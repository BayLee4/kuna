//! Byte-origin proof of register restoration across every normal return.
//! Raw proofs consume lifted p-code, not calling-convention promises. A separate
//! conditional pass accepts exact generated-family obligations. Only private
//! negative entry-stack slots retain saved values; unknown aliases discard proof.

use std::collections::{BTreeMap, BTreeSet};
use std::rc::Rc;
use kuna_base::address::Address;
use kuna_base::types::int4;
use kuna_num::opcodes::OpCode;
use crate::block::BlockKind;
use crate::context::{OpId, VarnodeId};
use crate::funcdata::Funcdata;
use super::kuna_physicalinputs::EntryRequirements;
use super::kuna_physicalinputs::ExecutionCallEffects;

type Byte = (int4, u64);
type Storage = (int4, u64, int4);

#[derive(Clone, Default, PartialEq, Eq)]
struct State {
    values: BTreeMap<Byte, Option<Byte>>,
    stack: BTreeMap<i64, Byte>,
    stored: BTreeSet<i64>,
    pointers: BTreeMap<Storage, i64>,
    saved_pointers: BTreeMap<(i64, int4), i64>,
    observed: BTreeSet<Byte>,
    escaped_stack: bool,
    used_private_frame: bool,
    private_frame_lost: bool,
}




fn storage(fd: &Funcdata, id: VarnodeId) -> Option<Storage> {
    let value = fd.vbank().get(id)?;
    if value.is_constant() { return None; }
    Some((value.get_space().get_index(), value.get_offset(), value.get_size()))
}

fn byte_key(fd: &Funcdata, id: VarnodeId, low_byte: int4) -> Option<Byte> {
    let value = fd.vbank().get(id)?;
    if value.is_constant() || low_byte < 0 || low_byte >= value.get_size() { return None; }
    let byte = if value.get_addr().is_big_endian() { value.get_size() - low_byte - 1 } else { low_byte };
    Some((value.get_space().get_index(), value.get_offset() + byte as u64))
}

fn entry_origin(fd: &Funcdata, byte: Byte) -> Option<Byte> {
    fd.get_arch().manage().get_space(byte.0)
        .filter(|space| space.get_name() == "register").map(|_| byte)
}

fn overlaps(left: Storage, right: Storage) -> bool {
    left.0 == right.0 && left.1 < right.1.saturating_add(right.2 as u64)
        && right.1 < left.1.saturating_add(left.2 as u64)
}

impl State {
    fn origin(&self, fd: &Funcdata, byte: Byte) -> Option<Byte> {
        self.values.get(&byte).copied().unwrap_or_else(|| entry_origin(fd, byte))
    }

    fn read(&self, fd: &Funcdata, id: VarnodeId, low_byte: int4) -> Option<Byte> {
        byte_key(fd, id, low_byte).and_then(|byte| self.origin(fd, byte))
    }

    fn observe_roots(&mut self, roots: &[Storage]) {
        for root in roots {
            for byte in 0..root.2 { self.observed.insert((root.0, root.1 + byte as u64)); }
        }
    }

    fn meet(&mut self, other: &Self, fd: &Funcdata, roots: &[Storage]) {
        self.observed.extend(other.observed.iter().copied());
        self.escaped_stack |= other.escaped_stack;
        self.used_private_frame |= other.used_private_frame;
        self.private_frame_lost |= other.private_frame_lost;
        for (byte, origin) in &mut self.values {
            let incoming = other.origin(fd, *byte);
            if *origin != incoming {
                self.observed.extend(origin.iter().copied());
                self.observed.extend(incoming);
                *origin = None;
            }
        }
        for (byte, origin) in &other.values {
            if !self.values.contains_key(byte) {
                let initial = entry_origin(fd, *byte);
                let agreed = if initial == *origin { initial } else {
                    self.observed.extend(initial);
                    self.observed.extend(origin.iter().copied());
                    None
                };
                self.values.insert(*byte, agreed);
            }
        }
        for (byte, origin) in self.stack.iter().chain(&other.stack) {
            if self.stack.get(byte) != other.stack.get(byte) { self.observed.insert(*origin); }
        }
        if self.pointers != other.pointers || self.saved_pointers != other.saved_pointers {
            self.observe_roots(roots);
            self.private_frame_lost = true;
        }
        self.stack.retain(|byte, origin| other.stack.get(byte) == Some(origin));
        self.stored.retain(|byte| other.stored.contains(byte));
        self.pointers.retain(|storage, offset| other.pointers.get(storage) == Some(offset));
        self.saved_pointers.retain(|storage, offset| other.saved_pointers.get(storage) == Some(offset));
    }

    fn invalidate(&mut self, range: Storage) {
        for byte in 0..range.2 { self.values.insert((range.0, range.1 + byte as u64), None); }
        self.pointers.retain(|storage, _| !overlaps(*storage, range));
    }

    fn clear_memory(&mut self, roots: &[Storage]) {
        // Losing identity is not evidence of independence: a later load can
        // still return an old saved byte if an unknown alias did not overwrite
        // that slot. Retain dependency conservatively before dropping proof.
        self.observed.extend(self.stack.values().copied());
        if !self.saved_pointers.is_empty() { self.observe_roots(roots); }
        self.stack.clear();
        self.stored.clear();
        self.saved_pointers.clear();
    }

    fn observe_range(&mut self, fd: &Funcdata, range: Storage, roots: &[Storage]) {
        for byte in 0..range.2 {
            if let Some(origin) = self.origin(fd, (range.0, range.1 + byte as u64)) {
                self.observed.insert(origin);
            }
        }
        if self.pointers.keys().any(|pointer| overlaps(*pointer, range)) {
            for root in roots {
                for byte in 0..root.2 { self.observed.insert((root.0, root.1 + byte as u64)); }
            }
        }
    }
}

fn covered(ranges: &[(Address, int4)], byte: Byte) -> bool {
    ranges.iter().any(|(address, size)| *size > 0
        && address.get_space().is_some_and(|space| space.get_index() == byte.0)
        && address.get_offset() <= byte.1 && byte.1 - address.get_offset() < *size as u64)
}

fn call_stack_interval(fd: &Funcdata, state: &State, address: &Address, size: int4) -> Option<(i64, i64)> {
    let space = address.get_space()?;
    let stack = fd.get_arch().manage().get_stack_space()?;
    if !Rc::ptr_eq(stack, space) || stack.num_spacebase() != 1 || size <= 0 { return None; }
    let root = stack.get_spacebase(0).ok()?;
    let root = (root.space.as_ref()?.get_index(), root.offset, root.size as int4);
    let base = *state.pointers.get(&root)?;
    let start = base.checked_add(i64::try_from(address.get_offset()).ok()?)?;
    let end = start.checked_add(i64::from(size))?;
    if start >= 0 || end > 0 || !(start..end).all(|byte| state.stored.contains(&byte)) { return None; }
    Some((start, end))
}

fn observe_call_input(fd: &Funcdata, state: &mut State, address: &Address, size: int4,
    roots: &[Storage]) -> bool
{
    let Some(space) = address.get_space() else { state.observe_roots(roots); return true };
    if space.get_type() != kuna_base::space::spacetype::IPTR_SPACEBASE {
        let range = (space.get_index(), address.get_offset(), size);
        let escapes = state.pointers.keys().any(|pointer| overlaps(*pointer, range));
        state.observe_range(fd, range, roots);
        return escapes;
    }
    let interval = call_stack_interval(fd, state, address, size);
    let Some((start, end)) = interval else { state.observe_roots(roots); return true };
    state.observed.extend(state.stack.range(start..end).map(|(_, origin)| *origin));
    let escapes = state.saved_pointers.keys().any(|(at, bytes)|
        *at < end && at.saturating_add(i64::from(*bytes)) > start);
    if escapes { state.observe_roots(roots); }
    escapes
}

fn declared_stack_input(fd: &Funcdata, offset: i64, size: int4) -> bool {
    let Some(stack) = fd.get_arch().manage().get_stack_space() else { return false };
    let proto = fd.get_func_proto();
    if !proto.has_store() || !proto.is_input_locked() { return false; }
    let Some(end) = offset.checked_add(size as i64).filter(|_| size > 0) else { return false };
    let mut cursor = offset;
    while cursor < end {
        let next = (0..proto.num_params()).filter_map(|slot| proto.source_param(slot)).filter_map(|parameter| {
            let address = parameter.get_address();
            if !parameter.is_type_locked() || address.get_space().is_none_or(|space| !Rc::ptr_eq(space, stack)) { return None; }
            let start = address.get_offset() as i64;
            (start <= cursor).then(|| start.checked_add(parameter.get_size() as i64)).flatten()
        }).max().unwrap_or(cursor);
        if next <= cursor { return false; }
        cursor = next.min(end);
    }
    true
}

fn signed_constant(fd: &Funcdata, id: VarnodeId) -> Option<i64> {
    let value = fd.vbank().get(id)?;
    if !value.is_constant() || !(1..=8).contains(&value.get_size()) { return None; }
    let shift = 64 - value.get_size() * 8;
    Some(((value.get_offset() << shift) as i64) >> shift)
}

/// Resolve only a literal or an actual earlier pure unique definition in this
/// instruction. No memory, tracked register, ABI or final-SSA premise enters.
fn instruction_constant(fd: &Funcdata, before: OpId, id: VarnodeId, remaining: &mut usize) -> Option<u64> {
    let value = fd.vbank().get(id)?;
    if !(1..=8).contains(&value.get_size()) { return None; }
    if value.is_constant() { return Some(value.get_offset()); }
    if value.get_space().get_type() != kuna_base::space::spacetype::IPTR_INTERNAL { return None; }
    let wanted = storage(fd, id)?;
    let consumer = fd.obank().get(before)?;
    let mut previous = consumer.basic_neighbours().0;
    while let Some(producer_id) = previous {
        *remaining = remaining.checked_sub(1)?;
        let producer = fd.obank().get(producer_id)?;
        if producer.get_addr() != consumer.get_addr() || producer.get_halt_type() != 0 { return None; }
        let behavior = fd.get_arch().op_behavior(producer.code())?;
        if behavior.is_special() { return None; }
        previous = producer.basic_neighbours().0;
        let output = producer.get_out().and_then(|id| storage(fd, id))?;
        if !overlaps(output, wanted) { continue; }
        // A partial overwrite is not a definition of the requested value.
        if output != wanted { return None; }
        let count = if behavior.is_unary() { 1 } else { 2 };
        if producer.num_input() != count { return None; }
        let first = producer.get_in(0)?;
        let first_size = fd.vbank().get(first)?.get_size();
        let first_value = instruction_constant(fd, producer_id, first, remaining)?;
        return if count == 1 {
            behavior.evaluate_unary(output.2, first_size, first_value).ok()
        } else {
            let second_value = instruction_constant(fd, producer_id, producer.get_in(1)?, remaining)?;
            behavior.evaluate_binary(output.2, first_size, first_value, second_value).ok()
        };
    }
    None
}

pub(super) fn signed_input_constant(fd: &Funcdata, op: OpId, slot: int4) -> Option<i64> {
    let input = fd.obank().get(op)?.get_in(slot)?;
    let size = fd.vbank().get(input)?.get_size();
    if !(1..=8).contains(&size) { return None; }
    let value = instruction_constant(fd, op, input, &mut 32)?;
    let shift = 64 - size * 8;
    Some(((value << shift) as i64) >> shift)
}

/// Share raw affine propagation without copying the restoration state model.
pub(super) fn affine_offset(fd: &Funcdata, op: OpId,
    read: impl Fn(VarnodeId) -> Option<(int4, i64)>) -> Option<i64>
{
    let operation = fd.obank().get(op)?;
    let output_size = fd.vbank().get(operation.get_out()?)?.get_size();
    let pointer = |slot| read(operation.get_in(slot)?).filter(|(size, _)| *size == output_size).map(|(_, offset)| offset);
    match operation.code() {
        OpCode::CPUI_COPY | OpCode::CPUI_CAST => pointer(0),
        OpCode::CPUI_INT_ADD => pointer(0).and_then(|base|
                signed_input_constant(fd, op, 1).and_then(|offset| base.checked_add(offset)))
            .or_else(|| pointer(1).and_then(|base|
                signed_input_constant(fd, op, 0).and_then(|offset| base.checked_add(offset)))),
        OpCode::CPUI_INT_SUB => pointer(0).and_then(|base|
            signed_input_constant(fd, op, 1).and_then(|offset| base.checked_sub(offset))),
        _ => None,
    }
}

/// Check raw future reads, not model-clobber liveness. A call never kills a
/// byte here; only an actual later p-code definition can retire that byte.
fn pointer_dead_after(fd: &Funcdata, call: OpId, range: Storage,
    callees: &BTreeMap<OpId, Rc<EntryRequirements>>,
    contracts: Option<&BTreeMap<OpId, &ExecutionCallEffects>>, return_outputs: &[Storage],
    flow: Option<&super::kuna_physicalinputs::ConditionalFlowView>) -> bool
{
    if !(1..=8).contains(&range.2) || range.1.checked_add(range.2 as u64).is_none() { return false; }
    let Some(operation) = fd.obank().get(call) else { return false };
    let Some(block) = operation.get_parent() else { return false };
    let valid = |range: Storage| range.2 > 0 && range.1.checked_add(range.2 as u64).is_some();
    let mask_for = |other: Storage| -> u16 {
        if !overlaps(range, other) { return 0; }
        let mut mask = 0;
        for byte in 0..range.2 {
            let offset = range.1 + byte as u64;
            if other.1 <= offset && offset - other.1 < other.2 as u64 { mask |= 1u16 << byte; }
        }
        mask
    };
    let mut work = vec![(block, operation.basic_neighbours().1, (1u16 << range.2) - 1)];
    let mut seen = BTreeMap::new();
    while let Some((block, first, mut remaining)) = work.pop() {
        let visited = seen.entry((block, first)).or_insert(0u16);
        remaining &= !*visited;
        if remaining == 0 { continue; }
        *visited |= remaining;
        let mut next = first;
        let mut returned = false;
        while let Some(id) = next {
            let Some(operation) = fd.obank().get(id) else { return false };
            if operation.get_halt_type() != 0 { return false; }
            for slot in 0..operation.num_input() {
                if operation.get_in(slot).and_then(|value| storage(fd, value))
                    .is_some_and(|input| !valid(input) || mask_for(input) & remaining != 0) {
                    return false;
                }
            }
            let code = operation.code();
            if matches!(code, OpCode::CPUI_CALL | OpCode::CPUI_CALLIND | OpCode::CPUI_CALLOTHER) {
                let contract = contracts.and_then(|contracts| contracts.get(&id));
                let callee = callees.get(&id);
                let refined_only = fd.refined_indirect_contracts().get(&id).is_some_and(|proof|
                    contract.is_some_and(|effects| std::ptr::eq(*effects, &proof.effects)));
                // A settled dynamic family has no original target-read set.
                // It cannot retire a hidden pointer through an unknown raw call.
                if (contract.is_none() || refined_only) && callee.is_none_or(|callee| !callee.is_complete()) {
                    return false;
                }
                // A declared argument is still an escape even if a known child
                // discards it and sink-observed demand did not retain its bytes.
                if let Some(index) = fd.get_call_specs_index(id) {
                    let proto = fd.get_call_specs(index).proto();
                    if proto.has_store() {
                        for slot in 0..proto.num_params() {
                            let Some(parameter) = proto.get_param(slot) else { return false };
                            let address = parameter.get_address();
                            let Some(space) = address.get_space() else { return false };
                            if !valid((space.get_index(), address.get_offset(), parameter.get_size()))
                                || space.get_type() == kuna_base::space::spacetype::IPTR_JOIN
                                || mask_for((space.get_index(), address.get_offset(), parameter.get_size())) & remaining != 0
                            {
                                return false;
                            }
                        }
                    }
                }
                if let Some(callee) = callee {
                    for (address, size) in &callee.reads {
                        let Some(space) = address.get_space() else { return false };
                        if !valid((space.get_index(), address.get_offset(), *size))
                            || mask_for((space.get_index(), address.get_offset(), *size)) & remaining != 0 {
                            return false;
                        }
                    }
                }
                // A generated indirect target still has its original positive
                // machine reads even when its C family does not expose them.
                for target in fd.generated_execution_contracts().get(&id).into_iter().flat_map(|contract| &contract.targets) {
                    for (address, size) in &target.raw.reads {
                        let Some(space) = address.get_space() else { return false; };
                        if !valid((space.get_index(), address.get_offset(), *size))
                            || space.get_type() == kuna_base::space::spacetype::IPTR_JOIN
                            || mask_for((space.get_index(), address.get_offset(), *size)) & remaining != 0 {
                            return false;
                        }
                    }
                }
                if let Some(contract) = contract {
                    for (address, size) in &contract.inputs {
                        let Some(space) = address.get_space() else { return false };
                        if !valid((space.get_index(), address.get_offset(), *size))
                            || mask_for((space.get_index(), address.get_offset(), *size)) & remaining != 0 {
                            return false;
                        }
                    }
                }
            } else if code == OpCode::CPUI_RETURN {
                if return_outputs.iter().any(|output| !valid(*output) || mask_for(*output) & remaining != 0) {
                    return false;
                }
                returned = true;
                break;
            } else if let Some(output) = operation.get_out().and_then(|value| storage(fd, value)) {
                if !valid(output) { return false; }
                remaining &= !mask_for(output);
                if remaining == 0 { break; }
            }
            next = operation.basic_neighbours().1;
        }
        if returned || remaining == 0 { continue; }
        let block_id = block;
        let block = fd.bblocks_ref().block(block);
        if block.size_out() == 0 { return false; }
        for edge in 0..block.size_out() {
            if flow.is_some_and(|view| !view.edge_allowed(block_id, edge)) { continue; }
            let target = block.get_out(edge);
            let first = match fd.bblocks_ref().block(target).kind() {
                BlockKind::Basic(data) => data.op_head,
                _ => return false,
            };
            work.push((target, first, remaining));
        }
    }
    true
}

/// Only the implicit logical result object gets a bounded destination. Existing
/// saved origins cannot be hidden inside its padding or overwritten footprint.
fn hidden_result_interval(fd: &Funcdata, state: &State, contract: &ExecutionCallEffects,
    roots: &[Storage]) -> Option<(Storage, i64, i64)>
{
    let result = contract.hidden_result.as_ref()?;
    if roots.len() != 1 || !(1..=8).contains(&result.pointer_size) || result.value_size <= 0 { return None; }
    let space = result.address.get_space()?;
    if space.get_name() != "register" { return None; }
    let role = (space.get_index(), result.address.get_offset(), result.pointer_size);
    if roots.contains(&role) || role.1.checked_add(role.2 as u64).is_none() { return None; }
    let start = *state.pointers.get(&role)?;
    let end = start.checked_add(i64::from(result.value_size))?;
    let (stack_address, stack_size, pop) = contract.stack_adjustment.as_ref()?;
    let stack_space = stack_address.get_space()?;
    if *pop < 0 || (stack_space.get_index(), stack_address.get_offset(), *stack_size) != roots[0] { return None; }
    let floor = state.pointers.get(&roots[0])?.checked_add(*pop)?;
    // A native callee owns space below its return-adjusted stack pointer; a
    // merely negative entry offset does not establish an allocated caller object.
    if start < floor || start >= 0 || end > 0 || state.stack.range(start..end).next().is_some()
        || state.saved_pointers.keys().any(|(at, size)| *at < end && at.saturating_add(i64::from(*size)) > start)
    { return None; }
    // Confirm this is the architecture's stack root, not an unrelated affine map.
    let stack = fd.get_arch().manage().get_stack_space()?;
    let base = stack.get_spacebase(0).ok()?;
    if stack.num_spacebase() != 1 || base.space.as_ref()?.get_index() != roots[0].0
        || base.offset != roots[0].1 || base.size as int4 != roots[0].2 { return None; }
    Some((role, start, end))
}

fn transfer(
    fd: &Funcdata, op: OpId, state: &mut State,
    callees: &BTreeMap<OpId, Rc<EntryRequirements>>, scratch: &mut Vec<Option<Byte>>,
    contracts: Option<&BTreeMap<OpId, &ExecutionCallEffects>>, registers: &[Byte], roots: &[Storage],
    direct: &BTreeMap<OpId, super::kuna_physicalinputs::DirectExecutionAssumption>,
    observable: bool, return_loads: &BTreeSet<OpId>,
    dead_after: &mut impl FnMut(OpId, Storage) -> bool,
) {
    let operation = fd.obank().get(op).expect("restoration operation");
    let code = operation.code();
    let input = |slot| operation.get_in(slot);
    let pointer = |state: &State, slot| input(slot).and_then(|vn| storage(fd, vn))
        .and_then(|storage| state.pointers.get(&storage).copied());
    let memory = if matches!(code, OpCode::CPUI_LOAD | OpCode::CPUI_STORE) {
        input(0).and_then(|vn| fd.vbank().get(vn)).filter(|value| value.is_constant())
            .and_then(|value| int4::try_from(value.get_offset()).ok())
            .and_then(|index| fd.get_arch().manage().get_space(index))
    } else { None };
    let stack_offset = pointer(state, 1);
    let stack_memory = memory.is_some_and(|space| fd.get_arch().manage().get_default_data_space()
        .is_some_and(|data| Rc::ptr_eq(space, data)));
    let private_store = code == OpCode::CPUI_STORE && stack_memory && !state.escaped_stack
        && stack_offset.zip(input(2).and_then(|vn| fd.vbank().get(vn).map(|value| value.get_size())))
            .is_some_and(|(offset, size)| offset < 0 && offset.checked_add(size as i64).is_some_and(|end| end <= 0));
    let affine = affine_offset(fd, op, |id| {
        let range = storage(fd, id)?;
        state.pointers.get(&range).map(|offset| (range.2, *offset))
    });
    let affine_operation = matches!(code, OpCode::CPUI_COPY | OpCode::CPUI_CAST) || affine.is_some();
    let local_load = code == OpCode::CPUI_LOAD && stack_memory && stack_offset.is_some_and(|offset| {
        operation.get_out().is_some_and(|output| fd.vbank().get(output).is_some_and(|value| {
            (0..value.get_size()).all(|byte| offset.checked_add(byte as i64).is_some_and(|at| state.stored.contains(&at)))
                || declared_stack_input(fd, offset, value.get_size())
                || return_loads.contains(&op)
        }))
    });
    // An arbitrary machine pointer can alias a saved slot even when its value
    // was not derived from SP in this body. Exact stack offsets are disjoint;
    // otherwise the load can observe any stored entry origin.
    if observable && code == OpCode::CPUI_LOAD && !(stack_memory && stack_offset.is_some()) {
        if contracts.is_some() && stack_memory && !state.escaped_stack && !state.private_frame_lost {
            state.used_private_frame |= !state.stored.is_empty();
        } else { state.observed.extend(state.stack.values().copied()); }
    }
    if observable && code == OpCode::CPUI_LOAD && stack_memory {
        if let Some((offset, size)) = stack_offset.zip(operation.get_out()
            .and_then(|vn| fd.vbank().get(vn).map(|value| value.get_size()))) {
            if !state.saved_pointers.contains_key(&(offset, size))
                && state.saved_pointers.keys().any(|(at, bytes)|
                    at.saturating_add(*bytes as i64) > offset && offset.saturating_add(size as i64) > *at)
            { state.observe_roots(roots); state.private_frame_lost = true; }
        }
    }
    for slot in 0..operation.num_input() {
        if !observable { break; }
        let Some(range) = input(slot).and_then(|vn| storage(fd, vn)) else { continue };
        let propagated = affine_operation
            || (private_store && matches!(slot, 1 | 2))
            || (local_load && slot == 1);
        if !propagated {
            state.observe_range(fd, range, roots);
            if state.pointers.keys().any(|pointer| overlaps(*pointer, range)) {
                state.escaped_stack = true;
            }
        }
    }
    if code == OpCode::CPUI_STORE {
        let stored = input(2).and_then(|vn| fd.vbank().get(vn).map(|value| (vn, value.get_size())));
        // Only an owning generated C body supplies this private-activation
        // premise. Raw machine pointers retain the conservative alias rule.
        if contracts.is_some() && stack_memory && stack_offset.is_none()
            && !state.escaped_stack && !state.private_frame_lost {
            state.used_private_frame |= !state.stored.is_empty();
            return;
        }
        if let (Some(space), Some(offset), Some((value, size))) = (memory, stack_offset, stored) {
            if !private_store { state.clear_memory(roots); return; }
            if state.saved_pointers.keys().any(|(at, bytes)|
                at.saturating_add(*bytes as i64) > offset && offset.saturating_add(size as i64) > *at)
            { state.observe_roots(roots); state.private_frame_lost = true; }
            state.saved_pointers.retain(|(at, bytes), _| {
                at.saturating_add(*bytes as i64) <= offset || offset.saturating_add(size as i64) <= *at
            });
            for byte in 0..size {
                let Some(at) = offset.checked_add(byte as i64) else { state.clear_memory(roots); return };
                state.stored.insert(at);
                let low = if space.is_big_endian() { size - byte - 1 } else { byte };
                if let Some(origin) = state.read(fd, value, low) { state.stack.insert(at, origin); }
                else { state.stack.remove(&at); }
            }
            if let Some(pointer) = storage(fd, value).and_then(|storage| state.pointers.get(&storage)).copied() {
                state.saved_pointers.insert((offset, size), pointer);
            }
        } else { state.clear_memory(roots); }
        return;
    }
    if matches!(code, OpCode::CPUI_CALL | OpCode::CPUI_CALLIND | OpCode::CPUI_CALLOTHER) {
        if let Some(contract) = contracts.and_then(|contracts| contracts.get(&op)) {
            let result = hidden_result_interval(fd, state, contract, roots);
            let mut aliases_stack = state.escaped_stack || state.private_frame_lost || !state.saved_pointers.is_empty();
            for (address, size) in &contract.inputs {
                let hidden = result.is_some_and(|(role, _, _)| address.get_space().is_some_and(|space|
                    (space.get_index(), address.get_offset(), *size) == role));
                if !hidden { aliases_stack |= observe_call_input(fd, state, address, *size, roots); }
            }
            if let Some((_, start, _)) = result {
                // A consumed implicit result pointer may remain in a clobbered
                // register. Retire it only if actual future raw reads cannot use
                // any surviving byte before an independent definition.
                state.pointers.retain(|pointer, offset| {
                    let temporary = fd.get_arch().manage().get_space(pointer.0).is_some_and(|space|
                        space.get_type() == kuna_base::space::spacetype::IPTR_INTERNAL);
                    let changes = !temporary && (0..pointer.2).any(|byte|
                        !covered(&contract.preserved, (pointer.0, pointer.1 + byte as u64)));
                    *offset != start || roots.contains(pointer) || !changes || !dead_after(op, *pointer)
                });
            }
            let loses_pointer = state.pointers.keys().any(|pointer| {
                // As in ProtoModel::lookup_effect, unique storage is local to
                // this function; absence from hardware ABI ranges cannot kill it.
                if fd.get_arch().manage().get_space(pointer.0).is_some_and(|space|
                    space.get_type() == kuna_base::space::spacetype::IPTR_INTERNAL) { return false; }
                let stack_delta = contract.stack_adjustment.as_ref().is_some_and(|(address, size, _)|
                    address.get_space().is_some_and(|space| space.get_index() == pointer.0)
                        && address.get_offset() == pointer.1 && *size == pointer.2);
                !stack_delta && (0..pointer.2).any(|byte|
                    !covered(&contract.preserved, (pointer.0, pointer.1 + byte as u64)))
                    && !(0..pointer.2).all(|byte|
                        covered(&contract.outputs, (pointer.0, pointer.1 + byte as u64)))
            });
            if loses_pointer {
                state.observe_roots(roots);
                state.private_frame_lost = true;
                aliases_stack = true;
            }
            for byte in registers {
                let stack_byte = contract.stack_adjustment.as_ref().is_some_and(|(address, size, _)| {
                    address.get_space().is_some_and(|space| space.get_index() == byte.0)
                        && address.get_offset() <= byte.1 && byte.1 - address.get_offset() < *size as u64
                });
                if stack_byte { state.values.insert(*byte, None); }
                else if !covered(&contract.preserved, *byte) {
                    if !covered(&contract.outputs, *byte) {
                        state.observe_range(fd, (byte.0, byte.1, 1), roots);
                    }
                    state.invalidate((byte.0, byte.1, 1));
                }
            }
            for (address, size) in &contract.outputs {
                if let Some(space) = address.get_space() { state.invalidate((space.get_index(), address.get_offset(), *size)); }
            }
            if let Some((address, size, delta)) = &contract.stack_adjustment {
                if let Some(space) = address.get_space() {
                    let storage = (space.get_index(), address.get_offset(), *size);
                    if let Some(offset) = state.pointers.get(&storage).and_then(|offset| offset.checked_add(*delta)) {
                        state.pointers.insert(storage, offset);
                    } else {
                        if state.pointers.remove(&storage).is_some() {
                            state.observe_roots(roots); state.private_frame_lost = true;
                        }
                        aliases_stack = true;
                    }
                }
            } else { aliases_stack = true; }
            // This private-frame claim is conditional on the generated family:
            // no saved-slot address has escaped or been passed to that C call.
            if aliases_stack {
                state.private_frame_lost = true;
                state.clear_memory(roots);
            } else {
                if let Some((_, start, end)) = result {
                    // The ABI result writes only this local object's footprint.
                    // Disjoint saved-state origins remain unchanged.
                    state.stored.extend(start..end);
                }
                state.used_private_frame |= !state.stored.is_empty();
            }
        } else if let Some(callee) = callees.get(&op).filter(|callee| callee.is_complete()) {
            let obligation = direct.get(&op);
            let mut aliases_stack = state.escaped_stack || state.private_frame_lost || !state.saved_pointers.is_empty();
            // Source arguments can escape even when sink demand trimmed their
            // physical reads. Escape is persistent, including before any save.
            let source_inputs = fd.get_call_specs_index(op).map(|index| fd.get_call_specs(index).proto())
                .filter(|proto| proto.has_store());
            let mut check_escape = |address: &Address, size: int4| {
                if let Some(space) = address.get_space() {
                    let range = (space.get_index(), address.get_offset(), size);
                    if state.pointers.keys().any(|pointer| overlaps(*pointer, range))
                        || space.get_type() == kuna_base::space::spacetype::IPTR_SPACEBASE {
                        aliases_stack = true;
                        state.private_frame_lost = true;
                    }
                } else { aliases_stack = true; state.private_frame_lost = true; }
            };
            for parameter in source_inputs.into_iter().flat_map(|proto| (0..proto.num_params())
                .filter_map(move |slot| proto.source_param(slot))) {
                check_escape(&parameter.get_address(), parameter.get_size());
            }
            for (address, size) in obligation.into_iter().flat_map(|contract| &contract.inputs) {
                check_escape(address, *size);
            }
            for (address, size) in &callee.reads {
                if callee.is_bookkeeping(address, *size) { continue; }
                if let Some(space) = address.get_space() {
                    let range = (space.get_index(), address.get_offset(), *size);
                    if state.pointers.keys().any(|pointer| overlaps(*pointer, range))
                        || space.get_type() == kuna_base::space::spacetype::IPTR_SPACEBASE {
                        aliases_stack = true;
                        state.private_frame_lost = true;
                    }
                    state.observe_range(fd, range, roots);
                }
            }
            let loses_pointer = state.pointers.keys().any(|pointer| {
                let stack_delta = callee.stack_adjustments.iter().any(|(address, size, _)|
                    address.get_space().is_some_and(|space| space.get_index() == pointer.0)
                        && address.get_offset() == pointer.1 && *size == pointer.2);
                !stack_delta && (0..pointer.2).any(|byte| {
                    let key = (pointer.0, pointer.1 + byte as u64);
                    covered(&callee.writes, key) && !covered(&callee.restored, key)
                }) && !(0..pointer.2).all(|byte|
                    covered(&callee.definite_writes, (pointer.0, pointer.1 + byte as u64)))
            });
            if loses_pointer {
                state.observe_roots(roots);
                state.private_frame_lost = true;
                aliases_stack = true;
            }
            let private_frame = obligation.is_some() && !aliases_stack;
            if private_frame {
                state.used_private_frame |= (callee.reads_memory || callee.writes_memory) && !state.stored.is_empty();
            } else if callee.reads_memory {
                state.observed.extend(state.stack.values().copied());
            }
            for (address, size) in &callee.writes {
                let Some(space) = address.get_space() else { continue };
                for byte in 0..*size {
                    let address = address + byte as i64;
                    if !callee.restores(&address, 1) {
                        let stack_adjustment = callee.stack_adjustments.iter().any(|(at, bytes, _)| {
                            at.get_space().is_some_and(|other| Rc::ptr_eq(space, other))
                                && at.get_offset() <= address.get_offset()
                                && address.get_offset() - at.get_offset() < *bytes as u64
                        });
                        if stack_adjustment {
                            state.values.insert((space.get_index(), address.get_offset()), None);
                        } else {
                            if !covered(&callee.definite_writes, (space.get_index(), address.get_offset())) {
                                state.observe_range(fd, (space.get_index(), address.get_offset(), 1), roots);
                            }
                            state.invalidate((space.get_index(), address.get_offset(), 1));
                        }
                    }
                }
            }
            for (address, size, delta) in &callee.stack_adjustments {
                let Some(space) = address.get_space() else { continue };
                let storage = (space.get_index(), address.get_offset(), *size);
                if let Some(offset) = state.pointers.get(&storage).and_then(|offset| offset.checked_add(*delta)) {
                    state.pointers.insert(storage, offset);
                } else if state.pointers.remove(&storage).is_some() {
                    state.observe_roots(roots); state.private_frame_lost = true;
                }
            }
            if callee.writes_memory && !private_frame { state.clear_memory(roots); }
        } else {
            // The caller only publishes proof for a complete closure. Preserve
            // no accidental state if this helper is reached on an unknown cut.
            state.private_frame_lost = true;
            state.values.clear();
            for id in fd.vbank().iter_loc() {
                if let Some(range) = storage(fd, id) { state.invalidate(range); }
            }
            if !state.pointers.is_empty() { state.observe_roots(roots); }
            state.pointers.clear();
            state.clear_memory(roots);
        }
    }
    let Some(output) = operation.get_out() else { return };
    let Some(out) = storage(fd, output) else { return };
    scratch.clear();
    scratch.resize(out.2.max(0) as usize, None);
    let first = input(0);
    match code {
        OpCode::CPUI_COPY | OpCode::CPUI_CAST | OpCode::CPUI_INT_ZEXT | OpCode::CPUI_INT_SEXT => {
            if let Some(first) = first {
                for byte in 0..out.2 { scratch[byte as usize] = state.read(fd, first, byte); }
            }
        }
        OpCode::CPUI_SUBPIECE => {
            if let Some((first, cut)) = first.zip(input(1).and_then(|vn| signed_constant(fd, vn))) {
                if let Ok(cut) = int4::try_from(cut) {
                    for byte in 0..out.2 {
                        scratch[byte as usize] = byte.checked_add(cut).and_then(|byte| state.read(fd, first, byte));
                    }
                }
            }
        }
        OpCode::CPUI_PIECE => {
            if let Some((high, low)) = first.zip(input(1)) {
                let low_size = fd.vbank().get(low).expect("piece input").get_size();
                for byte in 0..out.2 {
                    scratch[byte as usize] = if byte < low_size { state.read(fd, low, byte) }
                        else { state.read(fd, high, byte - low_size) };
                }
            }
        }
        OpCode::CPUI_LOAD => {
            if let (Some(space), Some(offset)) = (memory, stack_offset) {
                if stack_memory {
                    for byte in 0..out.2 {
                        let at = if space.is_big_endian() { out.2 - byte - 1 } else { byte };
                        scratch[byte as usize] = offset.checked_add(at as i64).and_then(|at| state.stack.get(&at).copied());
                    }
                }
            }
        }
        _ => {}
    }
    let affine = if code == OpCode::CPUI_LOAD && stack_memory {
        stack_offset.and_then(|offset| state.saved_pointers.get(&(offset, out.2)).copied())
    } else { affine };
    let loses_partial_pointer = state.pointers.keys().any(|pointer| overlaps(*pointer, out)
        && !(out.1 <= pointer.1 && out.1.saturating_add(out.2 as u64) >= pointer.1.saturating_add(pointer.2 as u64)));
    let loses_affine_input = observable && affine_operation && affine.is_none()
        && (0..operation.num_input()).any(|slot| input(slot).and_then(|vn| storage(fd, vn))
            .is_some_and(|input| state.pointers.keys().any(|pointer| overlaps(*pointer, input))));
    if loses_partial_pointer || loses_affine_input {
        state.observe_roots(roots); state.private_frame_lost = true;
    }
    state.invalidate(out);
    for byte in 0..out.2 {
        if let Some(key) = byte_key(fd, output, byte) { state.values.insert(key, scratch[byte as usize]); }
    }
    if let Some(offset) = affine { state.pointers.insert(out, offset); }
}

/// Whether each model-declared internal entry value can reach all of its raw
/// uses without an unproved call clobber. This is deliberately independent of
/// conditional reachability, native preservation promises, and final SSA.
pub(super) fn raw_internal_roles(fd: &Funcdata,
    callees: &BTreeMap<OpId, Rc<EntryRequirements>>,
    contracts: &BTreeMap<OpId, &ExecutionCallEffects>) -> (Vec<(Address, int4)>, Vec<super::kuna_physicalinputs::InheritedInternalRole>)
{
    let proto = fd.get_func_proto();
    if !proto.has_model() || fd.bblocks_get_size() == 0 { return (Vec::new(), Vec::new()); }
    let roles = proto.internal_list().iter().filter_map(|role| {
        let space = role.space.as_ref().filter(|space| space.get_name() == "register")?;
        let size = int4::try_from(role.size).ok().filter(|size| *size > 0)?;
        role.offset.checked_add(size as u64)?;
        Some((space.get_index(), role.offset, size))
    }).collect::<Vec<Storage>>();
    if roles.is_empty() { return (Vec::new(), Vec::new()); }
    let mut domain = roles.iter().flat_map(|role|
        (0..role.2).map(move |byte| (role.0, role.1 + byte as u64))).collect::<Vec<Byte>>();
    domain.sort_unstable();
    domain.dedup();
    fn observe(roles: &[Storage], domain: &[Byte], dirty: &[bool], rejected: &mut [bool], range: Storage) {
        let Some(end) = range.1.checked_add(range.2 as u64).filter(|_| range.2 > 0) else { rejected.fill(true); return; };
        for (index, role) in roles.iter().enumerate() {
            if !overlaps(*role, range) { continue; }
            let start = role.1.max(range.1);
            let end = (role.1 + role.2 as u64).min(end);
            if (start..end).any(|offset| domain.binary_search(&(role.0, offset)).is_ok_and(|index| dirty[index])) {
                rejected[index] = true;
            }
        }
    }
    fn observe_address(fd: &Funcdata, roles: &[Storage], domain: &[Byte], dirty: &[bool], rejected: &mut [bool],
        address: &Address, size: int4)
    {
        let Some(space) = address.get_space() else { rejected.fill(true); return };
        if space.get_type() == kuna_base::space::spacetype::IPTR_JOIN {
            let Ok(join) = fd.get_arch().manage().find_join(address.get_offset()) else { rejected.fill(true); return };
            for index in 0..join.num_pieces() {
                let piece = join.get_piece(index);
                let Some(space) = &piece.space else { rejected.fill(true); return };
                let Ok(size) = int4::try_from(piece.size) else { rejected.fill(true); return };
                observe(roles, domain, dirty, rejected, (space.get_index(), piece.offset, size));
            }
        } else { observe(roles, domain, dirty, rejected, (space.get_index(), address.get_offset(), size)); }
    }
    let blocks = (0..fd.bblocks_get_size()).map(|index| fd.bblocks_get_block(index)).collect::<Vec<_>>();
    let positions = blocks.iter().enumerate().map(|(index, block)| (*block, index)).collect::<BTreeMap<_, _>>();
    let mut reached = vec![false; blocks.len()];
    let mut dirty_out = vec![vec![false; domain.len()]; blocks.len()];
    let mut rejected_out = vec![vec![false; roles.len()]; blocks.len()];
    let mut dirty = vec![false; domain.len()];
    let mut rejected = vec![false; roles.len()];
    let mut has_return = false;
    loop {
        let mut changed = false;
        for (index, block_id) in blocks.iter().enumerate() {
            dirty.fill(false);
            rejected.fill(false);
            let mut reachable = index == 0;
            let block = fd.bblocks_ref().block(*block_id);
            for edge in 0..block.size_in() {
                let Some(&previous) = positions.get(&block.get_in(edge)).filter(|index| reached[**index]) else { continue };
                reachable = true;
                for (value, incoming) in dirty.iter_mut().zip(&dirty_out[previous]) { *value |= *incoming; }
                for (value, incoming) in rejected.iter_mut().zip(&rejected_out[previous]) { *value |= *incoming; }
            }
            if !reachable { continue; }
            if !reached[index] { reached[index] = true; changed = true; }
            let mut next = fd.bb_op_head(*block_id);
            while let Some(op) = next {
                let operation = fd.obank().get(op).expect("raw internal-role operation");
                next = operation.basic_neighbours().1;
                for slot in 0..operation.num_input() {
                    if let Some(value) = operation.get_in(slot).and_then(|id| fd.vbank().get(id)) {
                        observe_address(fd, &roles, &domain, &dirty, &mut rejected,
                            value.get_addr(), value.get_size());
                    }
                }
                if matches!(operation.code(), OpCode::CPUI_CALL | OpCode::CPUI_CALLIND | OpCode::CPUI_CALLOTHER) {
                    let raw = callees.get(&op);
                    // Formal arguments do not inventory implicit model storage.
                    // An unresolved callee may consume every applicable internal
                    // role before it clobbers them; a prior unknown call cannot
                    // silently forward a dirty GP to another implicit consumer.
                    if raw.is_none_or(|raw| !raw.is_complete()) {
                        for role in &roles {
                            observe(&roles, &domain, &dirty, &mut rejected, *role);
                        }
                    }
                    for (address, size) in raw.into_iter().flat_map(|raw| &raw.reads) {
                        observe_address(fd, &roles, &domain, &dirty, &mut rejected, address, *size);
                    }
                    // Additional ABI/source locations can establish a read, but
                    // none of these generated premises establishes raw preservation.
                    for (address, size) in contracts.get(&op).into_iter().flat_map(|effects| &effects.inputs)
                        .chain(fd.native_execution_contracts().get(&op).into_iter().flat_map(|contract| &contract.effects.inputs))
                        .chain(fd.generated_execution_contracts().get(&op).into_iter().flat_map(|contract| &contract.effects.inputs))
                        .chain(fd.deferred_execution_contracts().get(&op).into_iter().flat_map(|contract| &contract.effects.inputs)) {
                        observe_address(fd, &roles, &domain, &dirty, &mut rejected, address, *size);
                    }
                    if let Some(call) = fd.get_call_specs_index(op).map(|index| fd.get_call_specs(index)) {
                        let source = call.proto();
                        if source.has_store() {
                            for slot in 0..source.num_params() {
                                if let Some(parameter) = source.get_param(slot).filter(|parameter| parameter.get_size() > 0) {
                                    observe_address(fd, &roles, &domain, &dirty, &mut rejected,
                                        &parameter.get_address(), parameter.get_size());
                                }
                            }
                        }
                    }
                    for (index, byte) in domain.iter().enumerate() {
                        if raw.is_none_or(|raw| !raw.is_complete()
                            || (covered(&raw.writes, *byte) && !covered(&raw.restored, *byte))) {
                            dirty[index] = true;
                        }
                    }
                } else {
                    if operation.code() == OpCode::CPUI_RETURN && operation.get_halt_type() == 0 {
                        has_return = true;
                        if proto.has_store() && proto.is_output_locked() && proto.get_output().get_size() > 0 {
                            observe_address(fd, &roles, &domain, &dirty, &mut rejected,
                                &proto.get_output().get_address(), proto.get_output().get_size());
                        }
                    }
                    if let Some(output) = operation.get_out().and_then(|id| storage(fd, id)) {
                        let Some(end) = output.1.checked_add(output.2 as u64).filter(|_| output.2 > 0) else {
                            rejected.fill(true); continue;
                        };
                        // All reads above precede this actual independent definition;
                        // a partial write cannot clear surviving upper dirty bytes.
                        for (index, byte) in domain.iter().enumerate() {
                            if byte.0 == output.0 && output.1 <= byte.1 && byte.1 < end { dirty[index] = false; }
                        }
                    }
                }
            }
            if dirty_out[index] != dirty { dirty_out[index].clone_from(&dirty); changed = true; }
            if rejected_out[index] != rejected { rejected_out[index].clone_from(&rejected); changed = true; }
        }
        if !changed { break; }
    }
    if !has_return { return (Vec::new(), Vec::new()); }
    rejected.fill(false);
    for values in rejected_out { for (rejected, value) in rejected.iter_mut().zip(values) { *rejected |= value; } }
    let mut safe = roles.into_iter().enumerate().filter(|(index, _)| !rejected[*index]).filter_map(|(_, (space, offset, size))|
        fd.get_arch().manage().get_space(space).map(|space| (Address::new(space.clone(), offset), size))).collect::<Vec<_>>();
    safe.sort_unstable();
    safe.dedup();
    if safe.is_empty() { return (safe, Vec::new()); }
    let calls = || fd.obank().iter_all().filter_map(|(_, op)| {
        let operation = fd.obank().get(op)?;
        (matches!(operation.code(), OpCode::CPUI_CALL | OpCode::CPUI_CALLIND | OpCode::CPUI_CALLOTHER)
            && operation.get_parent().and_then(|block| positions.get(&block)).is_some_and(|index| reached[*index]))
            .then_some(op)
    });
    // A pending target-body receipt cannot close unknown original call effects.
    // This scan deliberately uses the same unpruned raw reachability as above.
    if calls().any(|op| callees.get(&op).is_none_or(|raw| !raw.is_complete())) {
        return (safe, Vec::new());
    }
    let mut inherited = Vec::new();
    for (address, size) in &safe {
        let space = address.get_space().expect("validated internal-role space");
        let mut writing_calls = Vec::new();
        for op in calls() {
            let raw = callees.get(&op).expect("complete original raw call");
            if (0..*size).any(|offset| {
                let byte = (space.get_index(), address.get_offset() + offset as u64);
                covered(&raw.writes, byte) && !covered(&raw.restored, byte)
            }) { writing_calls.push(op); }
        }
        if !writing_calls.is_empty() {
            inherited.push(super::kuna_physicalinputs::InheritedInternalRole {
                address: address.clone(), size: *size, calls: writing_calls,
            });
        }
    }
    (safe, inherited)
}

#[derive(Default)]
pub(super) struct Restoration {
    pub restored: Vec<(Address, int4)>,
    pub stack_adjustments: Vec<(Address, int4, i64)>,
    pub bookkeeping: Vec<(Address, int4)>,
    pub observed: Option<BTreeSet<Byte>>,
    pub requires_private_frame: bool,
    pub flow_returns: Vec<super::kuna_physicalinputs::FlowReturnAssumption>,
    pub memory_definitions: Vec<super::kuna_physicalinputs::ExecutionMemoryDefinition>,
    pub private_stores: Vec<super::kuna_physicalinputs::PrivateStoreObligation>,
}

pub(super) fn restored_registers(
    fd: &Funcdata, callees: &BTreeMap<OpId, Rc<EntryRequirements>>,
    raw_callees: &BTreeMap<OpId, Rc<EntryRequirements>>, writes: &[(Address, int4)],
    contracts: Option<&BTreeMap<OpId, &ExecutionCallEffects>>,
    direct: &BTreeMap<OpId, super::kuna_physicalinputs::DirectExecutionAssumption>,
    flow_returns: &BTreeMap<OpId, super::kuna_physicalinputs::FlowReturnAssumption>,
    flow: Option<&super::kuna_physicalinputs::ConditionalFlowView>,
) -> Restoration {
    let mut result = Restoration::default();
    let blocks: Vec<_> = (0..fd.bblocks_get_size()).map(|index| fd.bblocks_get_block(index)).collect();
    if blocks.is_empty() { return result; }
    let positions: BTreeMap<_, _> = blocks.iter().enumerate().map(|(index, block)| (*block, index)).collect();
    let operations: Vec<Vec<_>> = blocks.iter().map(|block| {
        let mut operations = Vec::new();
        if flow.is_some_and(|view| !view.block_reachable(*block)) { return operations; }
        let mut op = match fd.bblocks_ref().block(*block).kind() {
            BlockKind::Basic(data) => data.op_head, _ => None,
        };
        while let Some(id) = op {
            operations.push(id);
            op = fd.obank().get(id).expect("raw block operation").basic_neighbours().1;
        }
        operations
    }).collect();
    let mut entry = State::default();
    if let Some(stack) = fd.get_arch().manage().get_stack_space() {
        for index in 0..stack.num_spacebase() {
            if let Ok(pointer) = stack.get_spacebase(index) {
                if let Some(space) = pointer.space {
                    entry.pointers.insert((space.get_index(), pointer.offset, pointer.size as int4), 0);
                }
            }
        }
    }
    let mut outgoing: Vec<Option<State>> = vec![None; blocks.len()];
    let mut incoming = outgoing.clone();
    let mut scratch = Vec::new();
    let roots = entry.pointers.keys().copied().collect::<Vec<_>>();
    let mut registers = Vec::new();
    let reachable_values = flow.map(|_| operations.iter().flatten().flat_map(|op| {
        let operation = fd.obank().get(*op).expect("reachable raw operation");
        (0..operation.num_input()).filter_map(move |slot| operation.get_in(slot)).chain(operation.get_out())
    }).collect::<BTreeSet<_>>());
    let mut potential_outputs = Vec::new();
    let proto = fd.get_func_proto();
    let model = if proto.has_model() { Some(proto.model()) } else { fd.get_arch().default_fp() };
    for id in fd.vbank().iter_loc() {
        if reachable_values.as_ref().is_some_and(|values| !values.contains(&id)) { continue; }
        let value = fd.vbank().get(id).expect("raw register value");
        if value.get_space().get_name() != "register" { continue; }
        let range = (value.get_space().get_index(), value.get_offset(), value.get_size());
        for byte in 0..range.2 { registers.push((range.0, range.1 + byte as u64)); }
        if model.is_some_and(|model| model.possible_output_param(value.get_addr(), value.get_size())) {
            potential_outputs.push(range);
        }
    }
    if flow.is_some() {
        // Registers appearing only in an eliminated arm still belong to the
        // original preservation obligation. A live call can clobber them even
        // when no retained p-code operand mentions their storage.
        for (address, size) in writes {
            if let Some(space) = address.get_space().filter(|space| space.get_name() == "register") {
                for byte in 0..*size { registers.push((space.get_index(), address.get_offset() + byte as u64)); }
            }
        }
    }
    registers.sort_unstable();
    registers.dedup();
    potential_outputs.sort_unstable();
    potential_outputs.dedup();
    let return_outputs = if proto.has_store() && proto.is_output_locked() {
        let output = proto.get_output();
        let address = output.get_address();
        let mut outputs = Vec::new();
        if output.get_size() > 0 {
            if let Some(space) = address.get_space() {
                if space.get_type() == kuna_base::space::spacetype::IPTR_JOIN {
                    if let Ok(join) = fd.get_arch().manage().find_join(address.get_offset()) {
                        for index in 0..join.num_pieces() {
                            let piece = join.get_piece(index);
                            if let Some(space) = &piece.space { outputs.push((space.get_index(), piece.offset, piece.size as int4)); }
                        }
                    } else { return result; }
                } else { outputs.push((space.get_index(), address.get_offset(), output.get_size())); }
            }
        }
        outputs
    } else { potential_outputs };
    let mut retired_pointers = BTreeMap::new();
    let mut dead_after = |call, range| *retired_pointers.entry((call, range))
        .or_insert_with(|| pointer_dead_after(fd, call, range, raw_callees, contracts, &return_outputs, flow));
    let return_loads = operations.iter().flatten().filter_map(|op| {
        let operation = fd.obank().get(*op).expect("raw operation");
        (operation.code() == OpCode::CPUI_LOAD
            && operation.get_out().is_some_and(|output| super::kuna_physicalinputs::return_target_only(fd, output, raw_callees, contracts, flow)))
            .then_some(*op)
    }).collect::<BTreeSet<_>>();
    // Raw register/temporary liveness suppresses dead arithmetic observations
    // (notably stack-allocation flags). It does not reconstruct values or trust
    // final SSA after effect-related dead-code removal.
    let mut live_in = vec![BTreeSet::<Byte>::new(); blocks.len()];
    let mut live_operations = BTreeSet::new();
    loop {
        let mut changed = false;
        live_operations.clear();
        for index in (0..blocks.len()).rev() {
            if flow.is_some_and(|view| !view.block_reachable(blocks[index])) { continue; }
            let mut live = BTreeSet::new();
            let block = fd.bblocks_ref().block(blocks[index]);
            for edge in 0..block.size_out() {
                if flow.is_some_and(|view| !view.edge_allowed(blocks[index], edge)) { continue; }
                if let Some(next) = positions.get(&block.get_out(edge)) { live.extend(live_in[*next].iter().copied()); }
            }
            for op in operations[index].iter().rev() {
                let operation = fd.obank().get(*op).expect("liveness operation");
                let code = operation.code();
                if code == OpCode::CPUI_RETURN && operation.get_halt_type() == 0 {
                    for range in &return_outputs {
                        for byte in 0..range.2 { live.insert((range.0, range.1 + byte as u64)); }
                    }
                }
                let output = operation.get_out().and_then(|vn| storage(fd, vn));
                let used = matches!(code, OpCode::CPUI_STORE | OpCode::CPUI_CALL | OpCode::CPUI_CALLIND
                    | OpCode::CPUI_CALLOTHER | OpCode::CPUI_CBRANCH | OpCode::CPUI_BRANCHIND | OpCode::CPUI_RETURN)
                    || output.is_some_and(|range| (0..range.2).any(|byte| live.contains(&(range.0, range.1 + byte as u64))));
                if let Some(range) = output {
                    for byte in 0..range.2 { live.remove(&(range.0, range.1 + byte as u64)); }
                }
                if let Some(contract) = contracts.and_then(|contracts| contracts.get(op)) {
                    live.retain(|byte| !registers.binary_search(byte).is_ok() || covered(&contract.preserved, *byte));
                    for (address, size) in &contract.inputs {
                        if let Some(space) = address.get_space() {
                            for byte in 0..*size { live.insert((space.get_index(), address.get_offset() + byte as u64)); }
                        }
                    }
                } else if let Some(callee) = callees.get(op) {
                    for (address, size) in &callee.definite_writes {
                        if let Some(space) = address.get_space() {
                            for byte in 0..*size {
                                let at = address + byte as i64;
                                if !callee.restores(&at, 1) { live.remove(&(space.get_index(), at.get_offset())); }
                            }
                        }
                    }
                    for (address, size) in &callee.reads {
                        if let Some(space) = address.get_space() {
                            for byte in 0..*size { live.insert((space.get_index(), address.get_offset() + byte as u64)); }
                        }
                    }
                }
                if used {
                    live_operations.insert(*op);
                    for slot in 0..operation.num_input() {
                        if let Some(range) = operation.get_in(slot).and_then(|vn| storage(fd, vn)) {
                            for byte in 0..range.2 { live.insert((range.0, range.1 + byte as u64)); }
                        }
                    }
                }
            }
            if live != live_in[index] { live_in[index] = live; changed = true; }
        }
        if !changed { break; }
    }
    loop {
        let mut changed = false;
        for index in 0..blocks.len() {
            if flow.is_some_and(|view| !view.block_reachable(blocks[index])) { continue; }
            let mut state = if index == 0 { Some(entry.clone()) } else { None };
            let block = fd.bblocks_ref().block(blocks[index]);
            for edge in 0..block.size_in() {
                if flow.is_some_and(|view| !view.edge_allowed(block.get_in(edge), block.get_in_rev_index(edge))) { continue; }
                let Some(previous) = positions.get(&block.get_in(edge)).and_then(|index| outgoing[*index].as_ref()) else { continue };
                if let Some(state) = state.as_mut() { state.meet(previous, fd, &roots); }
                else { state = Some(previous.clone()); }
            }
            incoming[index].clone_from(&state);
            if let Some(state) = state.as_mut() {
                for op in &operations[index] {
                    transfer(fd, *op, state, callees, &mut scratch, contracts, &registers, &roots,
                        direct,
                        live_operations.contains(op), &return_loads, &mut dead_after);
                }
            }
            if outgoing[index] != state { outgoing[index] = state; changed = true; }
        }
        if !changed { break; }
    }
    let mut preserved: Vec<Vec<bool>> = writes.iter().map(|(_, size)| vec![true; *size as usize]).collect();
    let mut balanced = entry.pointers.keys().copied().collect::<BTreeSet<_>>();
    let mut stack_offsets: Option<BTreeMap<Storage, i64>> = None;
    let extra_pop = fd.get_func_proto().get_extra_pop();
    let mut has_return = false;
    let mut observed = BTreeSet::new();
    let mut escaped_stack = false;
    let mut used_private_frame = false;
    let mut isolated = contracts.is_some() && roots.len() == 1
        && proto.has_model() && !proto.internal_list().is_empty();
    let mut private_stores = Vec::new();
    let mut stack_reads = Vec::new();
    for (index, operations) in operations.iter().enumerate() {
        let Some(mut state) = incoming[index].take() else { continue };
        for op in operations {
            if isolated {
                let operation = fd.obank().get(*op).expect("private store operation");
                let code = operation.code();
                if matches!(code, OpCode::CPUI_LOAD | OpCode::CPUI_STORE) {
                    let memory = operation.get_in(0).and_then(|id| fd.vbank().get(id))
                        .filter(|value| value.is_constant())
                        .and_then(|value| int4::try_from(value.get_offset()).ok())
                        .and_then(|index| fd.get_arch().manage().get_space(index));
                    let stack_memory = memory.zip(fd.get_arch().manage().get_default_data_space())
                        .is_some_and(|(memory, data)| Rc::ptr_eq(memory, data));
                    if !stack_memory { isolated = false; }
                    if stack_memory {
                        let offset = operation.get_in(1).and_then(|id| storage(fd, id))
                            .and_then(|location| state.pointers.get(&location)).copied();
                        let size = if code == OpCode::CPUI_LOAD { operation.get_out() } else { operation.get_in(2) }
                            .and_then(|id| fd.vbank().get(id)).map(|value| value.get_size());
                        if let Some((start, size)) = offset.zip(size).filter(|(_, size)| *size > 0) {
                            if let Some(end) = start.checked_add(i64::from(size)) {
                                if code == OpCode::CPUI_LOAD { stack_reads.push((start, end)); }
                                else if start < 0 && end <= 0 {
                                    let root = roots[0];
                                    if let Some(space) = fd.get_arch().manage().get_space(root.0) {
                                        private_stores.push(super::kuna_physicalinputs::PrivateStoreObligation {
                                            op: *op, root: Address::new(space.clone(), root.1), root_size: root.2,
                                            offset: start, size,
                                        });
                                    } else { isolated = false; }
                                }
                            } else { isolated = false; }
                        } else if state.escaped_stack || state.private_frame_lost {
                            isolated = false;
                        }
                    }
                }
                if matches!(code, OpCode::CPUI_CALL | OpCode::CPUI_CALLIND | OpCode::CPUI_CALLOTHER) {
                    let call_effects = contracts.and_then(|contracts| contracts.get(op));
                    let call_inputs = call_effects.into_iter().flat_map(|effects| &effects.inputs)
                        .chain(direct.get(op).into_iter().flat_map(|proof| &proof.inputs));
                    for (address, size) in call_inputs {
                        // Contract producers flatten physical JOIN pieces. An
                        // unexpanded range is not evidence of disjointness.
                        if address.get_space().is_none_or(|space|
                            space.get_type() == kuna_base::space::spacetype::IPTR_JOIN) { isolated = false; }
                        if address.get_space().is_some_and(|space|
                            space.get_type() == kuna_base::space::spacetype::IPTR_SPACEBASE) {
                            if let Some(interval) = call_stack_interval(fd, &state, address, *size) {
                                stack_reads.push(interval);
                            } else { isolated = false; }
                        }
                    }
                    let body_contract = call_effects.is_some() || direct.contains_key(op);
                    let touches_memory = callees.get(op).is_none_or(|child|
                        !child.is_complete() || child.reads_memory || child.writes_memory);
                    if touches_memory && (!body_contract || state.escaped_stack
                        || state.private_frame_lost || !state.saved_pointers.is_empty()) { isolated = false; }
                }
            }
            let operation = fd.obank().get(*op).expect("return operation");
            let memory_definition = contracts.and_then(|effects| {
                if !matches!(operation.code(), OpCode::CPUI_CALL | OpCode::CPUI_CALLIND) { return None; }
                let effects = *effects.get(op)?;
                let native = fd.native_execution_contracts().get(op)
                    .filter(|contract| std::ptr::eq(effects, &contract.effects));
                let generated = fd.generated_execution_contracts().get(op)
                    .filter(|contract| std::ptr::eq(effects, &contract.effects));
                let (_, start, end) = hidden_result_interval(fd, &state, effects, &roots)?;
                let value_size = match (native, generated) {
                    (Some(contract), None) => super::kuna_callabletransport::native_hidden_value_size(contract),
                    (None, Some(contract)) => super::kuna_callabletransport::generated_hidden_value_size(contract),
                    _ => return None,
                };
                let Ok(Some(size)) = value_size else { return None; };
                if i64::from(size) != end.checked_sub(start)? { return None; }
                let stack = fd.get_arch().manage().get_stack_space().filter(|space| space.get_word_size() == 1)?;
                Some((native, generated, stack, start, size))
            });
            transfer(fd, *op, &mut state, callees, &mut scratch, contracts, &registers, &roots,
                direct,
                live_operations.contains(op), &return_loads, &mut dead_after);
            if !state.private_frame_lost && !state.escaped_stack {
                if let Some((native, generated, stack, start, size)) = memory_definition {
                    use super::kuna_physicalinputs::ExecutionMemoryProducer;
                    let producer = match (native, generated) {
                        (Some(contract), None) => ExecutionMemoryProducer::Native(Rc::clone(contract)),
                        (None, Some(contract)) => ExecutionMemoryProducer::Generated(Rc::clone(contract)),
                        _ => unreachable!("one authenticated result-memory producer"),
                    };
                    result.memory_definitions.push(super::kuna_physicalinputs::ExecutionMemoryDefinition {
                        op: *op, stack_address: Address::new(stack.clone(), stack.wrap_offset(start as u64)),
                        size, producer,
                    });
                }
            }
            if operation.code() != OpCode::CPUI_RETURN || operation.get_halt_type() != 0 { continue; }
            has_return = true;
            for range in &return_outputs {
                if state.pointers.keys().any(|pointer| overlaps(*pointer, *range)) { state.private_frame_lost = true; }
                state.observe_range(fd, *range, &roots);
            }
            // Only the exact source-authorized override return can unwind the
            // generated activation. Do not change raw origins or pointer state.
            let flow_return = if contracts.is_some() { flow_returns.get(op) } else { None };
            let flow_stack = if let Some(proof) = flow_return {
                let (address, size, expected) = &proof.stack;
                let Some(space) = address.get_space() else { return Restoration::default() };
                let storage = (space.get_index(), address.get_offset(), *size);
                let Some(observed) = state.pointers.get(&storage).copied()
                    .filter(|_| entry.pointers.contains_key(&storage)) else { return Restoration::default() };
                if proof.return_op != *op { return Restoration::default(); }
                let mut proof = proof.clone();
                proof.observed_delta = Some(observed);
                result.flow_returns.push(proof);
                Some((storage, *expected))
            } else { None };
            let effective_offset = |storage: &Storage| flow_stack.as_ref()
                .filter(|(root, _)| root == storage).map(|(_, delta)| *delta)
                .or_else(|| state.pointers.get(storage).copied());
            if let Some(offsets) = stack_offsets.as_mut() {
                offsets.retain(|storage, offset| effective_offset(storage) == Some(*offset));
            } else {
                stack_offsets = Some(state.pointers.iter().filter(|(storage, _)| entry.pointers.contains_key(storage))
                    .map(|(storage, _)| (*storage, effective_offset(storage).expect("known stack root"))).collect());
            }
            balanced.retain(|storage| extra_pop != crate::fspec::EXTRAPOP_UNKNOWN
                && effective_offset(storage) == Some(extra_pop as i64));
            for ((address, _), bytes) in writes.iter().zip(&mut preserved) {
                let Some(space) = address.get_space() else { bytes.fill(false); continue };
                for (byte, restored) in bytes.iter_mut().enumerate() {
                    let key = (space.get_index(), address.get_offset() + byte as u64);
                    *restored &= state.origin(fd, key) == Some(key);
                }
            }
        }
        observed.extend(state.observed);
        escaped_stack |= state.escaped_stack || state.private_frame_lost;
        used_private_frame |= state.used_private_frame;
    }
    if !has_return || (used_private_frame && escaped_stack) { return Restoration::default(); }
    if isolated && !escaped_stack {
        private_stores.retain(|store| !stack_reads.iter().any(|(start, end)|
            *start < store.offset.saturating_add(i64::from(store.size)) && store.offset < *end));
        result.private_stores = private_stores;
    }
    result.requires_private_frame = used_private_frame;
    for ((space, offset, size), delta) in stack_offsets.unwrap_or_default() {
        if let Some(space) = fd.get_arch().manage().get_space(space) {
            result.stack_adjustments.push((Address::new(Rc::clone(space), offset), size, delta));
        }
    }
    for ((address, _), bytes) in writes.iter().zip(preserved) {
        let mut start = None;
        for byte in 0..=bytes.len() {
            if byte < bytes.len() && bytes[byte] { start.get_or_insert(byte); }
            else if let Some(first) = start.take() { result.restored.push((address + first as i64, (byte - first) as int4)); }
        }
    }
    for (address, size) in &result.restored {
        let Some(space) = address.get_space() else { continue };
        let mut start = None;
        for byte in 0..=*size {
            if byte < *size && !observed.contains(&(space.get_index(), address.get_offset() + byte as u64)) { start.get_or_insert(byte); }
            else if let Some(first) = start.take() { result.bookkeeping.push((address + first as i64, byte - first)); }
        }
    }
    for (space, offset, size) in &balanced {
        if (0..*size).any(|byte| observed.contains(&(*space, offset + byte as u64))) { continue; }
        if let Some(space) = fd.get_arch().manage().get_space(*space) {
            result.bookkeeping.push((Address::new(Rc::clone(space), *offset), *size));
        }
    }
    result.observed = Some(observed);
    result
}
