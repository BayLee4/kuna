//! Target-owned proof that an implicit logical result is completely initialized.
//! Caller allocation/non-alias evidence is a separate authority.
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::rc::Rc;
use kuna_base::address::Address;
use kuna_base::error::KunaResult;
use kuna_base::space::spacetype;
use kuna_base::types::int4;
use kuna_num::opcodes::OpCode;
use crate::context::{OpId, VarnodeId};
use crate::dtype::{DatatypeKind, TypeRoot, type_metatype};
use crate::funcdata::Funcdata;
use super::kuna_callabletransport::{LogicalResultFamily, logical_result_family};
use super::kuna_registerrestore::affine_offset;

const MAX_RESULT_BYTES: usize = 256;
const MAX_BODY_OPS: usize = 1024;
const MAX_BLOCKS: usize = 64;
const MAX_LAYOUT_DEPTH: usize = 16;
const MAX_VALUE_DEPTH: usize = 128;
type Byte = (int4, u64);
type Storage = (int4, u64, int4);

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct LogicalResultFieldLayout {
    /// Exact C member designator, using the emitter's own identifier sanitizer.
    pub path: String,
    pub offset: u64,
    pub size: u64,
}
struct StoreSeed { op: OpId, address: Address, time: u32, offset: i64, size: int4 }
struct ReturnSeed { op: OpId, address: Address, time: u32 }
pub(crate) struct LogicalResultBodySeed {
    entry: Address,
    family: LogicalResultFamily,
    hidden_address: Address,
    pointer_size: int4,
    stores: Vec<StoreSeed>,
    returns: Vec<ReturnSeed>,
    layout: Vec<LogicalResultFieldLayout>,
}
impl LogicalResultBodySeed {
    pub(crate) fn result(&self) -> &TypeRoot { &self.family.result }
    pub(crate) fn layout(&self) -> &[LogicalResultFieldLayout] { &self.layout }
}

pub(crate) fn result_layout(root: &TypeRoot) -> KunaResult<Option<Vec<LogicalResultFieldLayout>>> {
    fn walk(ty: &TypeRoot, path: &str, base: u64, depth: usize,
        active: &mut Vec<TypeRoot>, out: &mut Vec<LogicalResultFieldLayout>) -> KunaResult<bool>
    {
        if depth > MAX_LAYOUT_DEPTH || active.contains(ty) || ty.is_incomplete() || ty.get_size() <= 0
            || out.len() >= MAX_RESULT_BYTES { return Ok(false); }
        active.push(ty.clone());
        let view = ty.read();
        if !view.layout_ready(ty.id())? { return Ok(false); }
        let value = view.get(ty.id())?.effective()?;
        let size = value.get_size() as u64;
        let valid = match &value.kind {
            DatatypeKind::Base => matches!(value.get_metatype(), type_metatype::TYPE_INT | type_metatype::TYPE_UINT)
                && matches!(size, 1 | 2 | 4 | 8),
            DatatypeKind::Struct { field, bitfield } => {
                if !bitfield.is_empty() || field.is_empty() { return Ok(false); }
                let mut cursor = 0u64;
                let mut names = BTreeSet::new();
                for field in field {
                    let child = ty.related(field.field_type)?;
                    if field.name.is_empty() || field.offset < 0 || field.offset as u64 != cursor
                        || child.get_size() <= 0 { return Ok(false); }
                    let name = crate::printc::sanitize_type_name(&field.name).into_owned();
                    if name.is_empty() || !names.insert(name.clone()) { return Ok(false); }
                    let member = if path.is_empty() { name } else { format!("{path}.{name}") };
                    let Some(offset) = base.checked_add(cursor) else { return Ok(false); };
                    out.push(LogicalResultFieldLayout { path: member.clone(), offset, size: child.get_size() as u64 });
                    if !walk(&child, &member, offset, depth + 1, active, out)? { return Ok(false); }
                    let Some(next) = cursor.checked_add(child.get_size() as u64) else { return Ok(false); };
                    cursor = next;
                }
                cursor == size
            }
            DatatypeKind::Array { arrayof, arraysize } => {
                let child = ty.related(*arrayof)?;
                if *arraysize <= 0 || child.get_size() <= 0
                    || (child.get_size() as u64).checked_mul(*arraysize as u64) != Some(size) { return Ok(false); }
                let member = format!("{path}[0]");
                out.push(LogicalResultFieldLayout { path: member.clone(), offset: base, size: child.get_size() as u64 });
                walk(&child, &member, base, depth + 1, active, out)?
            }
            _ => false,
        };
        active.pop();
        Ok(valid)
    }
    let size = root.get_size();
    if size <= 0 || size as usize > MAX_RESULT_BYTES { return Ok(None); }
    let mut result = Vec::new();
    if !walk(root, "", 0, 0, &mut Vec::new(), &mut result)? { return Ok(None); }
    Ok(Some(result))
}

fn storage(fd: &Funcdata, id: VarnodeId) -> Option<Storage> {
    let value = fd.vbank().get(id)?;
    if value.is_constant() || value.get_size() <= 0 { return None; }
    let space = value.get_space();
    if space.get_type() != spacetype::IPTR_INTERNAL && space.get_name() != "register" { return None; }
    value.get_offset().checked_add(value.get_size() as u64)?;
    Some((space.get_index(), value.get_offset(), value.get_size()))
}
fn overlaps(a: Storage, b: Storage) -> bool {
    a.0 == b.0 && a.1 < b.1.saturating_add(b.2 as u64) && b.1 < a.1.saturating_add(a.2 as u64)
}
fn bytes(range: Storage) -> impl Iterator<Item = Byte> { (0..range.2).map(move |byte| (range.0, range.1 + byte as u64)) }
fn register_ranges(fd: &Funcdata, address: &Address, size: int4) -> KunaResult<Option<Vec<Storage>>> {
    let Some(space) = address.get_space() else { return Ok(None); };
    if size <= 0 || size as usize > MAX_RESULT_BYTES { return Ok(None); }
    if space.get_type() == spacetype::IPTR_JOIN {
        let join = fd.get_arch().manage().find_join(address.get_offset())?;
        let mut ranges = Vec::new();
        let mut total = 0;
        for index in 0..join.num_pieces() {
            let piece = join.get_piece(index);
            let Some(space) = &piece.space else { return Ok(None); };
            let Ok(size) = int4::try_from(piece.size) else { return Ok(None); };
            if space.get_name() != "register" || size <= 0 || piece.offset.checked_add(size as u64).is_none() { return Ok(None); }
            total += size;
            ranges.push((space.get_index(), piece.offset, size));
        }
        return Ok((total == size).then_some(ranges));
    }
    if space.get_name() != "register" || address.get_offset().checked_add(size as u64).is_none() { return Ok(None); }
    Ok(Some(vec![(space.get_index(), address.get_offset(), size)]))
}
fn ordinary_inputs(fd: &Funcdata, family: &LogicalResultFamily, hidden: Storage) -> KunaResult<Option<BTreeSet<Byte>>> {
    let proto = fd.get_func_proto();
    let mut initialized = BTreeSet::new();
    for slot in 0..proto.num_params() {
        if slot == family.hidden_slot { continue; }
        let Some(parameter) = proto.source_param(slot) else { return Ok(None); };
        let Some(ranges) = register_ranges(fd, &parameter.get_address(), parameter.get_size())? else { return Ok(None); };
        for range in ranges {
            if overlaps(range, hidden) { return Ok(None); }
            initialized.extend(bytes(range));
        }
    }
    Ok(Some(initialized))
}

#[derive(Clone, PartialEq, Eq)]
struct State {
    initialized: BTreeSet<Byte>,
    tainted: BTreeSet<Byte>,
    pointers: BTreeMap<Storage, i64>,
    written: [u64; 4],
}
impl State {
    fn input_defined(&self, fd: &Funcdata, id: VarnodeId) -> bool {
        fd.vbank().get(id).is_some_and(|value| value.is_constant())
            || storage(fd, id).is_some_and(|range| bytes(range).all(|byte| self.initialized.contains(&byte)))
    }
    fn input_tainted(&self, fd: &Funcdata, id: VarnodeId) -> bool {
        storage(fd, id).is_some_and(|range| bytes(range).any(|byte| self.tainted.contains(&byte)))
    }
    fn meet(&mut self, other: &Self) {
        self.initialized.retain(|byte| other.initialized.contains(byte));
        self.tainted.extend(other.tainted.iter().copied());
        self.pointers.retain(|range, offset| other.pointers.get(range) == Some(offset));
        for (written, incoming) in self.written.iter_mut().zip(other.written) { *written &= incoming; }
    }
    fn complete(&self, size: int4) -> bool {
        (0..size as usize).all(|byte| self.written[byte / 64] & (1u64 << (byte % 64)) != 0)
    }
}
fn pure_scalar(code: OpCode) -> bool {
    matches!(code, OpCode::CPUI_COPY | OpCode::CPUI_CAST | OpCode::CPUI_INT_EQUAL | OpCode::CPUI_INT_NOTEQUAL
        | OpCode::CPUI_INT_SLESS | OpCode::CPUI_INT_SLESSEQUAL | OpCode::CPUI_INT_LESS | OpCode::CPUI_INT_LESSEQUAL
        | OpCode::CPUI_INT_ZEXT | OpCode::CPUI_INT_SEXT | OpCode::CPUI_INT_ADD | OpCode::CPUI_INT_SUB
        | OpCode::CPUI_INT_CARRY | OpCode::CPUI_INT_SCARRY | OpCode::CPUI_INT_SBORROW | OpCode::CPUI_INT_2COMP
        | OpCode::CPUI_INT_NEGATE | OpCode::CPUI_INT_XOR | OpCode::CPUI_INT_AND | OpCode::CPUI_INT_OR
        | OpCode::CPUI_INT_LEFT | OpCode::CPUI_INT_RIGHT | OpCode::CPUI_INT_SRIGHT | OpCode::CPUI_INT_MULT
        | OpCode::CPUI_INT_DIV | OpCode::CPUI_INT_SDIV | OpCode::CPUI_INT_REM | OpCode::CPUI_INT_SREM
        | OpCode::CPUI_BOOL_NEGATE | OpCode::CPUI_BOOL_XOR | OpCode::CPUI_BOOL_AND | OpCode::CPUI_BOOL_OR
        | OpCode::CPUI_PIECE | OpCode::CPUI_SUBPIECE | OpCode::CPUI_POPCOUNT | OpCode::CPUI_LZCOUNT)
}
fn data_memory(fd: &Funcdata, op: OpId) -> bool {
    let Some(operation) = fd.obank().get(op) else { return false; };
    let Some(value) = operation.get_in(0).and_then(|id| fd.vbank().get(id)) else { return false; };
    if !value.is_constant() { return false; }
    let Ok(index) = int4::try_from(value.get_offset()) else { return false; };
    fd.get_arch().manage().get_space(index).zip(fd.get_arch().manage().get_default_data_space())
        .is_some_and(|(space, data)| Rc::ptr_eq(space, data) && space.get_word_size() == 1)
}

fn transfer(fd: &Funcdata, op: OpId, state: &mut State, size: int4, hidden: Storage,
    stores: &mut BTreeMap<OpId, (i64, int4)>) -> bool
{
    let Some(operation) = fd.obank().get(op) else { return false; };
    let code = operation.code();
    if code == OpCode::CPUI_RETURN {
        let no_register_escape = state.tainted.iter().all(|&(space, offset)| {
            (space == hidden.0 && offset >= hidden.1 && offset - hidden.1 < hidden.2 as u64)
                || fd.get_arch().manage().get_space(space).is_some_and(|space| space.get_type() == spacetype::IPTR_INTERNAL)
        });
        return operation.get_halt_type() == 0 && operation.num_input() == 1 && state.complete(size)
            && no_register_escape && operation.get_in(0).is_some_and(|id| !state.input_tainted(fd, id));
    }
    if code == OpCode::CPUI_BRANCH { return operation.num_input() == 1; }
    if code == OpCode::CPUI_CBRANCH {
        return operation.num_input() == 2 && operation.get_in(1).is_some_and(|id|
            state.input_defined(fd, id) && !state.input_tainted(fd, id));
    }
    if code == OpCode::CPUI_STORE {
        if operation.num_input() != 3 || !data_memory(fd, op) { return false; }
        let Some(pointer) = operation.get_in(1).and_then(|id| storage(fd, id)) else { return false; };
        let Some(&offset) = state.pointers.get(&pointer) else { return false; };
        let Some(value) = operation.get_in(2) else { return false; };
        let Some(width) = fd.vbank().get(value).map(|v| v.get_size()) else { return false; };
        let Some(end) = offset.checked_add(width as i64) else { return false; };
        if width <= 0 || offset < 0 || end > size as i64 || !state.input_defined(fd, value)
            || state.input_tainted(fd, value) { return false; }
        if stores.get(&op).is_some_and(|old| *old != (offset, width)) { return false; }
        stores.insert(op, (offset, width));
        for byte in offset as usize..end as usize { state.written[byte / 64] |= 1u64 << (byte % 64); }
        return true;
    }
    if !pure_scalar(code) || operation.num_input() <= 0 || operation.num_input() > 3 { return false; }
    let Some(output) = operation.get_out().and_then(|id| storage(fd, id)) else { return false; };
    if output.2 > 16 { return false; }
    let mut tainted = false;
    let mut defined = true;
    for slot in 0..operation.num_input() {
        let Some(input) = operation.get_in(slot) else { return false; };
        defined &= state.input_defined(fd, input);
        tainted |= state.input_tainted(fd, input);
    }
    let pointer = affine_offset(fd, op, |id| {
        let range = storage(fd, id)?;
        state.pointers.get(&range).copied().map(|offset| (range.2, offset))
    });
    if tainted && pointer.is_none() { return false; }
    if pointer.is_some_and(|offset| offset < 0 || offset > size as i64 || output.2 != hidden.2) { return false; }
    state.pointers.retain(|range, _| !overlaps(*range, output));
    // Raw return plumbing can copy the link register without making it a
    // logical input. Only values consumed by a result store or condition need
    // initializedness here; ordinary entry/control authority is checked apart.
    for byte in bytes(output) {
        if defined { state.initialized.insert(byte); } else { state.initialized.remove(&byte); }
        state.tainted.remove(&byte);
    }
    if let Some(offset) = pointer {
        state.pointers.insert(output, offset);
        state.tainted.extend(bytes(output));
    }
    true
}

pub(crate) fn capture_logical_result_body(fd: &Funcdata) -> KunaResult<Option<LogicalResultBodySeed>> {
    // Capture runs before SSA projections. Ordinary functions must not clone
    // the source parameter store for a certificate they cannot produce.
    let raw = fd.get_func_proto();
    let trace = std::env::var_os("KUNA_LOGICAL_RESULT_TRACE").is_some();
    if trace {
        eprintln!("LOGICAL-SEED entry={}:{} gate store={} indirect={} origins={} logical={} inputlock={} outputlock={}",
            fd.get_address().get_space().map_or(-1, |space| space.get_index()), fd.get_address().get_offset(),
            raw.has_store(), raw.has_store() && raw.get_output().is_indirect_storage(), raw.callable_input_origins().len(),
            raw.logical_callable().is_some(), raw.has_store() && raw.is_input_locked(), raw.has_store() && raw.is_output_locked());
    }
    if !raw.has_store() || !raw.get_output().is_indirect_storage()
        || raw.callable_input_origins().iter()
            .filter(|origin| matches!(origin, crate::fspec::AbiInputOrigin::HiddenResult))
            .take(2).count() != 1 { return Ok(None); }
    let source = fd.get_func_proto().source_prototype();
    let Some(family) = logical_result_family(fd, &source)? else {
        if trace { eprintln!("LOGICAL-SEED rejected family entry={}", fd.get_address().get_offset()); }
        return Ok(None);
    };
    let Some(layout) = result_layout(&family.result)? else {
        if trace { eprintln!("LOGICAL-SEED rejected layout entry={} size={}", fd.get_address().get_offset(), family.result.get_size()); }
        return Ok(None);
    };
    if trace { eprintln!("LOGICAL-SEED family/layout entry={} size={} hidden={}", fd.get_address().get_offset(), family.result.get_size(), family.hidden_slot); }
    let Some(parameter) = source.get_param(family.hidden_slot) else { return Ok(None); };
    let hidden_address = parameter.get_address();
    let pointer_size = parameter.get_size();
    if !(1..=8).contains(&pointer_size) { return Ok(None); }
    let Some(hidden_ranges) = register_ranges(fd, &hidden_address, pointer_size)? else { return Ok(None); };
    if hidden_ranges.len() != 1 { return Ok(None); }
    let hidden = hidden_ranges[0];
    let Some(mut initialized) = ordinary_inputs(fd, &family, hidden)? else { return Ok(None); };
    initialized.extend(bytes(hidden));
    let entry = State { initialized, tainted: bytes(hidden).collect(),
        pointers: BTreeMap::from([(hidden, 0)]), written: [0; 4] };
    let count = fd.bblocks_get_size() as usize;
    if count == 0 || count > MAX_BLOCKS { return Ok(None); }
    let blocks: Vec<_> = (0..count).map(|index| fd.bblocks_get_block(index as int4)).collect();
    let indices: BTreeMap<_, _> = blocks.iter().enumerate().map(|(index, &block)| (block, index)).collect();
    let operations: Vec<_> = blocks.iter().map(|&block| fd.bb_ops(block)).collect();
    if operations.iter().map(Vec::len).sum::<usize>() > MAX_BODY_OPS { return Ok(None); }
    let mut incoming = vec![None; count];
    incoming[0] = Some(entry);
    let mut work = VecDeque::from([0]);
    let mut queued = vec![false; count];
    queued[0] = true;
    let mut stores = BTreeMap::new();
    let mut visits = 0;
    while let Some(index) = work.pop_front() {
        visits += 1;
        if visits > MAX_BODY_OPS * 4 { return Ok(None); }
        queued[index] = false;
        let mut state = incoming[index].as_ref().expect("reachable result-body block").clone();
        let Some(&last) = operations[index].last() else { return Ok(None); };
        let Some(last_op) = fd.obank().get(last) else { return Ok(None); };
        let edges = fd.bblocks_ref().block(blocks[index]).size_out();
        let valid_edges = match last_op.code() {
            OpCode::CPUI_RETURN => edges == 0,
            OpCode::CPUI_CBRANCH => edges == 2,
            OpCode::CPUI_BRANCH => edges == 1,
            _ => edges == 1,
        };
        if !valid_edges { return Ok(None); }
        for &op in &operations[index] {
            if !transfer(fd, op, &mut state, family.result.get_size(), hidden, &mut stores) {
                if trace {
                    let operation = fd.obank().get(op).expect("raw result operation");
                    let inputs = (0..operation.num_input()).map(|slot| operation.get_in(slot).map(|id| {
                        let node = fd.vbank().get(id).expect("raw input");
                        (storage(fd, id), node.is_constant(), node.get_offset(), node.get_size(),
                            state.input_defined(fd, id), state.input_tainted(fd, id),
                            storage(fd, id).and_then(|range| state.pointers.get(&range).copied()))
                    })).collect::<Vec<_>>();
                    eprintln!("LOGICAL-SEED rejected transfer entry={} at={} code={:?} output={:?} inputs={inputs:?} tainted={:?} pointers={:?} written={:?}",
                        fd.get_address().get_offset(), operation.get_addr().get_offset(), operation.code(),
                        operation.get_out().and_then(|id| storage(fd, id)), state.tainted, state.pointers, state.written);
                }
                return Ok(None);
            }
        }
        for edge in 0..edges {
            let target = fd.bblocks_ref().block(blocks[index]).get_out(edge);
            let Some(&next) = indices.get(&target) else { return Ok(None); };
            let changed = if let Some(previous) = &mut incoming[next] {
                let before = (previous.initialized.len(), previous.tainted.len(), previous.pointers.len(), previous.written);
                previous.meet(&state);
                before != (previous.initialized.len(), previous.tainted.len(), previous.pointers.len(), previous.written)
            } else {
                incoming[next] = Some(state.clone());
                true
            };
            if changed && !queued[next] { work.push_back(next); queued[next] = true; }
        }
    }
    let mut returns = Vec::new();
    for (index, ops) in operations.iter().enumerate() {
        if incoming[index].is_none() { continue; }
        for &op in ops {
            let operation = fd.obank().get(op).expect("captured raw result operation");
            if operation.code() == OpCode::CPUI_RETURN {
                returns.push(ReturnSeed { op, address: operation.get_addr().clone(), time: operation.get_time() });
            }
        }
    }
    if returns.is_empty() || stores.is_empty() { return Ok(None); }
    if trace { eprintln!("LOGICAL-SEED captured entry={} stores={} returns={}", fd.get_address().get_offset(), stores.len(), returns.len()); }
    let stores = stores.into_iter().map(|(op, (offset, size))| {
        let operation = fd.obank().get(op).expect("captured raw result store");
        StoreSeed { op, address: operation.get_addr().clone(), time: operation.get_time(), offset, size }
    }).collect();
    Ok(Some(LogicalResultBodySeed { entry: fd.get_address().clone(), family, hidden_address,
        pointer_size, stores, returns, layout }))
}

// Check the supported shape and bound before invoking the existing pointer
// analysis (whose upstream contract assumes a well-formed acyclic expression).
pub(crate) fn final_pointer(fd: &Funcdata, original: VarnodeId, width: int4) -> Option<(VarnodeId, u64)> {
    let mut value = original;
    let mut seen = [None; MAX_VALUE_DEPTH];
    let mut count = 0;
    loop {
        if count == MAX_VALUE_DEPTH || seen[..count].contains(&Some(value)) { return None; }
        seen[count] = Some(value);
        count += 1;
        let varnode = fd.vbank().get(value)?;
        if varnode.get_size() != width { return None; }
        let Some(definition) = varnode.get_def() else {
            if !varnode.is_input() { return None; }
            break;
        };
        let operation = fd.obank().get(definition)?;
        match operation.code() {
            OpCode::CPUI_COPY | OpCode::CPUI_CAST if operation.num_input() == 1 => {}
            OpCode::CPUI_PTRSUB | OpCode::CPUI_INT_ADD if operation.num_input() == 2 => {
                if !operation.get_in(1).and_then(|id| fd.vbank().get(id)).is_some_and(|v| v.is_constant()) { return None; }
            }
            _ => return None,
        }
        value = operation.get_in(0)?;
    }
    let mut cursor = original;
    let mut total = 0u64;
    for _ in 0..count {
        let mut offset = 0;
        let root = crate::expression::root_pointer(cursor, &mut offset, fd.vbank(), fd.obank());
        total = total.checked_add(offset)?;
        if root == value { return Some((root, total)); }
        let operation = fd.vbank().get(root)?.get_def().and_then(|op| fd.obank().get(op))?;
        if operation.code() != OpCode::CPUI_CAST { return None; }
        cursor = operation.get_in(0)?;
    }
    None
}

fn final_value_defined(fd: &Funcdata, id: VarnodeId, inputs: &BTreeSet<Byte>,
    cache: &mut BTreeMap<VarnodeId, bool>, active: &mut Vec<VarnodeId>) -> bool
{
    if let Some(&defined) = cache.get(&id) { return defined; }
    if active.len() >= MAX_VALUE_DEPTH || active.contains(&id) { return false; }
    let Some(value) = fd.vbank().get(id) else { return false; };
    if value.is_constant() { return true; }
    if value.is_input() {
        return storage(fd, id).is_some_and(|range| bytes(range).all(|byte| inputs.contains(&byte)));
    }
    let Some(operation) = value.get_def().and_then(|op| fd.obank().get(op)) else { return false; };
    if !pure_scalar(operation.code()) && operation.code() != OpCode::CPUI_MULTIEQUAL { return false; }
    if operation.num_input() <= 0 || operation.num_input() as usize > MAX_BLOCKS { return false; }
    active.push(id);
    let defined = (0..operation.num_input()).all(|slot| operation.get_in(slot)
        .is_some_and(|input| final_value_defined(fd, input, inputs, cache, active)));
    active.pop();
    cache.insert(id, defined);
    defined
}

fn hidden_uses_are_local(fd: &Funcdata, root: VarnodeId, seed: &LogicalResultBodySeed) -> bool {
    let mut seen = BTreeSet::new();
    let mut work = vec![root];
    while let Some(value) = work.pop() {
        if !seen.insert(value) { continue; }
        if seen.len() > MAX_BODY_OPS { return false; }
        let Some(varnode) = fd.vbank().get(value) else { return false; };
        for reader in varnode.descend_iter() {
            let Some(operation) = fd.obank().get(reader) else { return false; };
            if operation.is_dead() { continue; }
            if operation.code() == OpCode::CPUI_STORE {
                if !seed.stores.iter().any(|store| store.op == reader)
                    || operation.get_in(1) != Some(value)
                    || operation.get_in(0) == Some(value) || operation.get_in(2) == Some(value) { return false; }
                continue;
            }
            if !matches!(operation.code(), OpCode::CPUI_COPY | OpCode::CPUI_CAST
                | OpCode::CPUI_PTRSUB | OpCode::CPUI_INT_ADD) || operation.get_in(0) != Some(value)
                || (1..operation.num_input()).any(|slot| operation.get_in(slot) == Some(value)) { return false; }
            let Some(output) = operation.get_out() else { return false; };
            if !final_pointer(fd, output, seed.pointer_size).is_some_and(|(base, offset)|
                base == root && offset <= seed.family.result.get_size() as u64) { return false; }
            work.push(output);
        }
    }
    true
}

fn final_coverage(fd: &Funcdata, seed: &LogicalResultBodySeed) -> bool {
    let count = fd.bblocks_get_size() as usize;
    if count == 0 || count > MAX_BLOCKS { return false; }
    let blocks: Vec<_> = (0..count).map(|index| fd.bblocks_get_block(index as int4)).collect();
    let indices: BTreeMap<_, _> = blocks.iter().enumerate().map(|(index, &block)| (block, index)).collect();
    let operations: Vec<_> = blocks.iter().map(|&block| fd.bb_ops(block)).collect();
    if operations.iter().map(Vec::len).sum::<usize>() > MAX_BODY_OPS { return false; }
    let mut incoming = vec![None; count];
    incoming[0] = Some([0u64; 4]);
    let mut work = VecDeque::from([0]);
    let mut queued = vec![false; count];
    queued[0] = true;
    let mut visits = 0;
    let mut returns = 0;
    while let Some(index) = work.pop_front() {
        visits += 1;
        if visits > MAX_BODY_OPS * 4 { return false; }
        queued[index] = false;
        let mut written = incoming[index].expect("reachable final result block");
        let Some(&last) = operations[index].last() else { return false; };
        let Some(last_op) = fd.obank().get(last) else { return false; };
        let edges = fd.bblocks_ref().block(blocks[index]).size_out();
        let valid_edges = match last_op.code() {
            OpCode::CPUI_RETURN => edges == 0,
            OpCode::CPUI_CBRANCH => edges == 2,
            OpCode::CPUI_BRANCH => edges == 1,
            _ => edges == 1,
        };
        if !valid_edges { return false; }
        for &op in &operations[index] {
            let Some(operation) = fd.obank().get(op) else { return false; };
            if operation.code() == OpCode::CPUI_STORE {
                let Some(store) = seed.stores.iter().find(|store| store.op == op) else { return false; };
                for byte in store.offset as usize..(store.offset + store.size as i64) as usize {
                    written[byte / 64] |= 1u64 << (byte % 64);
                }
            } else if operation.code() == OpCode::CPUI_RETURN {
                if !(0..seed.family.result.get_size() as usize)
                    .all(|byte| written[byte / 64] & (1u64 << (byte % 64)) != 0) { return false; }
                returns += 1;
            }
        }
        for edge in 0..edges {
            let target = fd.bblocks_ref().block(blocks[index]).get_out(edge);
            let Some(&next) = indices.get(&target) else { return false; };
            let changed = if let Some(previous) = &mut incoming[next] {
                let before = *previous;
                for (byte, incoming) in previous.iter_mut().zip(written) { *byte &= incoming; }
                before != *previous
            } else {
                incoming[next] = Some(written);
                true
            };
            if changed && !queued[next] { work.push_back(next); queued[next] = true; }
        }
    }
    returns != 0
}

pub(crate) fn logical_result_body_matches(fd: &Funcdata, seed: &LogicalResultBodySeed) -> KunaResult<bool> {
    if *fd.get_address() != seed.entry { return Ok(false); }
    let source = fd.get_func_proto().source_prototype();
    let Some(family) = logical_result_family(fd, &source)? else { return Ok(false); };
    if family.code != seed.family.code || family.result != seed.family.result || family.hidden_slot != seed.family.hidden_slot
        || family.inputs != seed.family.inputs || family.origins != seed.family.origins
        || result_layout(&family.result)?.as_ref() != Some(&seed.layout) { return Ok(false); }
    let Some(parameter) = source.get_param(family.hidden_slot) else { return Ok(false); };
    if parameter.get_address() != seed.hidden_address || parameter.get_size() != seed.pointer_size { return Ok(false); }
    let Some(space) = seed.hidden_address.get_space() else { return Ok(false); };
    let hidden = (space.get_index(), seed.hidden_address.get_offset(), seed.pointer_size);
    let Some(inputs) = ordinary_inputs(fd, &family, hidden)? else { return Ok(false); };
    let mut hidden_input = None;
    for id in fd.vbank().iter_loc() {
        let value = fd.vbank().get(id).expect("live final input");
        if !value.is_input() { continue; }
        if storage(fd, id).is_some_and(|range| overlaps(range, hidden)) {
            if value.get_addr() != &seed.hidden_address || value.get_size() != seed.pointer_size
                || hidden_input.replace(id).is_some() { return Ok(false); }
        }
    }
    let Some(hidden_input) = hidden_input else { return Ok(false); };
    if !hidden_uses_are_local(fd, hidden_input, seed) { return Ok(false); }
    let mut seen_stores = BTreeSet::new();
    let mut seen_returns = BTreeSet::new();
    let mut values = BTreeMap::new();
    for op in fd.obank().iter_alive() {
        let operation = fd.obank().get(op).expect("live final result operation");
        match operation.code() {
            OpCode::CPUI_STORE => {
                let Some(expected) = seed.stores.iter().find(|store| store.op == op) else { return Ok(false); };
                if operation.get_addr() != &expected.address || operation.get_time() != expected.time
                    || operation.num_input() != 3 || !data_memory(fd, op) { return Ok(false); }
                let Some(pointer) = operation.get_in(1) else { return Ok(false); };
                if final_pointer(fd, pointer, seed.pointer_size) != Some((hidden_input, expected.offset as u64)) { return Ok(false); }
                let Some(value) = operation.get_in(2) else { return Ok(false); };
                if fd.vbank().get(value).is_none_or(|v| v.get_size() != expected.size)
                    || !final_value_defined(fd, value, &inputs, &mut values, &mut Vec::new()) { return Ok(false); }
                seen_stores.insert(op);
            }
            OpCode::CPUI_RETURN => {
                let Some(expected) = seed.returns.iter().find(|ret| ret.op == op) else { return Ok(false); };
                if operation.get_addr() != &expected.address || operation.get_time() != expected.time
                    || operation.get_halt_type() != 0 || operation.num_input() != 1 { return Ok(false); }
                seen_returns.insert(op);
            }
            OpCode::CPUI_LOAD | OpCode::CPUI_CALL | OpCode::CPUI_CALLIND | OpCode::CPUI_CALLOTHER
            | OpCode::CPUI_INDIRECT | OpCode::CPUI_BRANCHIND | OpCode::CPUI_CPOOLREF | OpCode::CPUI_NEW => return Ok(false),
            _ => {
                // Materialized memory COPY is still a read/write, not a scalar.
                if operation.get_out().is_some_and(|id| storage(fd, id).is_none())
                    || (0..operation.num_input()).any(|slot| operation.get_in(slot).is_some_and(|id|
                        fd.vbank().get(id).is_some_and(|v| !v.is_constant() && storage(fd, id).is_none())
                            && !(slot == 0 && matches!(operation.code(), OpCode::CPUI_BRANCH | OpCode::CPUI_CBRANCH)))) { return Ok(false); }
            }
        }
    }
    Ok(seen_stores.len() == seed.stores.len() && !seen_returns.is_empty() && final_coverage(fd, seed))
}
