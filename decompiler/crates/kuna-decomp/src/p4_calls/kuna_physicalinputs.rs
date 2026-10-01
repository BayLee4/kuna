//! Derived physical entry requirements. Source declarations are projections,
//! not proof that other observed incoming bits do not exist.

use std::collections::{BTreeMap, BTreeSet};
use std::ops::Range;
use std::rc::Rc;

use kuna_base::address::Address;
use kuna_base::error::KunaResult;
use kuna_base::types::int4;
use kuna_num::opcodes::OpCode;

use crate::block::BlockKind;
use crate::context::{OpId, VarnodeId};
use crate::dtype::{type_metatype, TypeFactory, TypeRoot};
use crate::fspec::{FuncProto, PhysicalCallInput};
use crate::funcdata::Funcdata;
use crate::varnode::varnode_flags;

/// Positive reads survive unresolved calls. An unresolved remainder is never
/// interpreted as an empty input interface.
#[derive(Default)]
pub struct RawFlowAnalysis {
    pub requirements: EntryRequirements,
    pub private_stores: Vec<PrivateStoreObligation>,
    pub safe_internal_roles: Vec<(Address, int4)>,
    pub inherited_internal_roles: Vec<InheritedInternalRole>,
}

#[derive(Clone, Debug)]
pub struct InheritedInternalRole {
    pub address: Address,
    pub size: int4,
    pub calls: Vec<OpId>,
}

#[derive(Clone, Debug)]
pub struct PrivateStoreObligation {
    pub op: OpId,
    pub root: Address,
    pub root_size: int4,
    pub offset: i64,
    pub size: int4,
}

#[derive(Clone, Debug)]
pub struct EntryRequirements {
    pub reads: Vec<(Address, int4)>,
    /// May-writes, including resolved callees. Absence proves preservation only
    /// when the whole dependency closure is complete.
    pub writes: Vec<(Address, int4)>,
    /// May-written bytes proved equal to their entry value at every return.
    pub restored: Vec<(Address, int4)>,
    pub reads_memory: bool,
    pub writes_memory: bool,
    /// Proven affine stack-base change at every return, not an ABI guess.
    pub stack_adjustments: Vec<(Address, int4, i64)>,
    /// Bytes definitely defined on every reachable normal return. Unlike
    /// may-writes, these can discharge a caller's later entry-state read.
    pub definite_writes: Vec<(Address, int4)>,
    /// Conditional C execution contract, never a machine preservation proof.
    pub execution: Option<Rc<ExecutionRequirements>>,
    pub bookkeeping: Vec<(Address, int4)>,
    pub unresolved: Vec<(Address, OpCode)>,
    pub incomplete_flow: bool,
}

impl Default for EntryRequirements {
    fn default() -> Self {
        Self { reads: Vec::new(), writes: Vec::new(), restored: Vec::new(), reads_memory: true, writes_memory: true,
            stack_adjustments: Vec::new(), definite_writes: Vec::new(), execution: None,
            bookkeeping: Vec::new(), unresolved: Vec::new(), incomplete_flow: true }
    }
}

impl EntryRequirements {
    pub fn is_complete(&self) -> bool {
        !self.incomplete_flow && self.unresolved.is_empty()
    }

    pub fn is_bookkeeping(&self, addr: &Address, size: int4) -> bool {
        size > 0 && self.bookkeeping.iter().any(|(at, bytes)| {
            at.get_space().zip(addr.get_space()).is_some_and(|(a, b)| Rc::ptr_eq(a, b))
                && at.get_offset() <= addr.get_offset()
                && at.get_offset().saturating_add(*bytes as u64) >= addr.get_offset().saturating_add(size as u64)
        })
    }

    pub fn preserves(&self, addr: &Address, size: int4) -> bool {
        self.is_complete() && size > 0 && !self.writes.iter().any(|(at, bytes)| {
            at.get_space().zip(addr.get_space()).is_some_and(|(a, b)| Rc::ptr_eq(a, b))
                && at.get_offset() < addr.get_offset().saturating_add(size as u64)
                && addr.get_offset() < at.get_offset().saturating_add(*bytes as u64)
                && {
                    let start = addr.get_offset().max(at.get_offset());
                    let end = addr.get_offset().saturating_add(size as u64)
                        .min(at.get_offset().saturating_add(*bytes as u64));
                    !self.restores(&Address::new(at.get_space().unwrap().clone(), start), (end - start) as int4)
                }
        })
    }

    pub fn restores(&self, addr: &Address, size: int4) -> bool {
        if !self.is_complete() || size <= 0 { return false; }
        let Some(end) = addr.get_offset().checked_add(size as u64) else { return false };
        let mut cursor = addr.get_offset();
        while cursor < end {
            let next = self.restored.iter().filter(|(at, bytes)| {
                *bytes > 0 && at.get_space().zip(addr.get_space()).is_some_and(|(a, b)| Rc::ptr_eq(a, b))
                    && at.get_offset() <= cursor
            }).map(|(at, bytes)| at.get_offset().saturating_add(*bytes as u64)).max().unwrap_or(cursor);
            if next <= cursor { return false; }
            cursor = next.min(end);
        }
        true
    }
}

/// Valid only for a generated callable boundary whose target-owned definition
/// proves these local value/family assumptions and closes every child adapter.
/// The original raw summary retains all unresolved calls and machine effects.
#[derive(Clone, Debug)]
pub struct ExecutionRequirements {
    pub reads: Vec<(Address, int4)>,
    pub definite_writes: Vec<(Address, int4)>,
    pub restored: Vec<(Address, int4)>,
    pub stack_adjustments: Vec<(Address, int4, i64)>,
    pub bookkeeping: Vec<(Address, int4)>,
    /// The owning generated C activation, not raw alias analysis, protects
    /// private saved slots. Requires the actual matching target definition.
    pub requires_private_frame: bool,
    pub memory_definitions: Vec<ExecutionMemoryDefinition>,
    pub complete: bool,
    pub execution_assumptions: Vec<(OpId, TypeRoot)>,
    pub direct_assumptions: Vec<DirectExecutionAssumption>,
    pub flow_returns: Vec<FlowReturnAssumption>,
    pub native_assumptions: Vec<NativeExecutionAssumption>,
    pub generated_assumptions: Vec<GeneratedExecutionAssumption>,
    pub deferred_assumptions: Vec<DeferredBodyAssumption>,
    pub conditional_flow: Option<Rc<ConditionalFlowView>>,
}

/// A current raw epoch's conditional CFG. Its constructor accepts only opaque
/// optimizer receipts replayed against this exact entry prefix; raw IR is never
/// edited and the original machine requirement analysis never receives this view.
#[derive(Debug)]
pub struct ConditionalFlowView {
    cuts: Vec<super::kuna_branchreachability::CertifiedEdgeCut>,
    excluded: Vec<(crate::context::BlockId, int4)>,
    reachable: BTreeSet<crate::context::BlockId>,
}

impl ConditionalFlowView {
    pub(crate) fn from_receipts(fd: &Funcdata) -> KunaResult<Option<Rc<Self>>> {
        use super::kuna_branchreachability::{certified_cuts, StableOpKey};
        use kuna_base::error::KunaError;
        let cuts = certified_cuts(fd);
        if cuts.is_empty() { return Ok(None); }
        let fail = || KunaError::lowlevel("Conditional flow certificate does not match raw CFG");
        if fd.bblocks_get_size() == 0 { return Err(fail()); }
        let mut excluded = Vec::with_capacity(cuts.len());
        for cut in cuts {
            let mut matching = fd.obank().iter_all().filter_map(|(_, id)|
                (StableOpKey::of(fd, id).as_ref() == Some(cut.branch())).then_some(id));
            let branch = matching.next().ok_or_else(fail)?;
            if matching.next().is_some() { return Err(fail()); }
            let operation = fd.obank().get(branch).ok_or_else(fail)?;
            let block = operation.get_parent().ok_or_else(fail)?;
            if operation.is_dead() || operation.code() != OpCode::CPUI_CBRANCH
                || fd.bb_op_tail(block) != Some(branch)
                || fd.bb_op_head(block).and_then(|op| StableOpKey::of(fd, op)).as_ref() != Some(cut.from_start()) {
                return Err(fail());
            }
            let edge = int4::try_from(cut.edge()).map_err(|_| fail())?;
            let source = fd.bblocks_ref().block(block);
            if edge < 0 || edge >= source.size_out() { return Err(fail()); }
            let target = source.get_out(edge);
            if fd.bb_op_head(target).and_then(|op| StableOpKey::of(fd, op)).as_ref() != Some(cut.to_start()) {
                return Err(fail());
            }
            if excluded.contains(&(block, edge)) { return Err(fail()); }
            excluded.push((block, edge));
        }
        let mut view = Self { cuts: cuts.to_vec(), excluded, reachable: BTreeSet::new() };
        let mut work = vec![fd.bblocks_get_block(0)];
        while let Some(block) = work.pop() {
            let index = fd.bblocks_ref().block(block).get_index();
            if index < 0 || index >= fd.bblocks_get_size() || fd.bblocks_get_block(index) != block {
                return Err(fail());
            }
            if !view.reachable.insert(block) { continue; }
            let node = fd.bblocks_ref().block(block);
            for edge in 0..node.size_out() {
                if view.edge_allowed(block, edge) { work.push(node.get_out(edge)); }
            }
        }
        Ok(Some(Rc::new(view)))
    }

    pub(crate) fn block_reachable(&self, block: crate::context::BlockId) -> bool {
        self.reachable.contains(&block)
    }

    pub(crate) fn edge_allowed(&self, block: crate::context::BlockId, edge: int4) -> bool {
        !self.excluded.contains(&(block, edge))
    }

    pub(crate) fn op_reachable(&self, fd: &Funcdata, op: OpId) -> bool {
        fd.obank().get(op).and_then(|op| op.get_parent()).is_some_and(|block| self.block_reachable(block))
    }
}

/// A pruned execution proof is usable only in its owning body's live replay.
pub(crate) fn validate_execution_flow(fd: &Funcdata, execution: &ExecutionRequirements) -> KunaResult<()> {
    if let Some(flow) = &execution.conditional_flow {
        if !execution.flow_returns.is_empty()
            || flow.cuts.as_slice() != super::kuna_branchreachability::certified_cuts(fd) {
            return Err(kuna_base::error::KunaError::lowlevel("Conditional flow proof lost its owning replay"));
        }
        super::kuna_branchreachability::validate_final(fd)?;
    }
    Ok(())
}

/// The logical C result object's implicit ABI destination, never a source pointer.
#[derive(Clone, Debug)]
pub struct ExecutionIndirectResult {
    pub address: Address,
    pub pointer_size: int4,
    pub value_size: int4,
}

#[derive(Clone, Debug)]
pub struct ExecutionCallEffects {
    pub inputs: Vec<(Address, int4)>,
    pub outputs: Vec<(Address, int4)>,
    pub preserved: Vec<(Address, int4)>,
    pub stack_adjustment: Option<(Address, int4, i64)>,
    pub hidden_result: Option<ExecutionIndirectResult>,
}

#[derive(Clone, Debug)]
pub struct NativeExecutionAssumption {
    pub op: OpId,
    pub contract: Rc<crate::p4_calls::kuna_callabletransport::NativeCallContract>,
}

#[derive(Clone, Debug)]
pub struct GeneratedExecutionAssumption {
    pub op: OpId,
    pub contract: Rc<super::kuna_callabletransport::GeneratedCallContract>,
}

/// Conditional value production by the implicit result object of one genuine
/// native or target-owned generated call. This never changes the original raw child memory/read summary.
#[derive(Clone, Debug)]
pub struct ExecutionMemoryDefinition {
    pub op: OpId,
    pub stack_address: Address,
    pub size: int4,
    pub producer: ExecutionMemoryProducer,
}

#[derive(Clone, Debug)]
pub enum ExecutionMemoryProducer {
    Native(Rc<super::kuna_callabletransport::NativeCallContract>),
    Generated(Rc<super::kuna_callabletransport::GeneratedCallContract>),
}

impl ExecutionMemoryProducer {
    fn effects(&self) -> &ExecutionCallEffects {
        match self { Self::Native(contract) => &contract.effects, Self::Generated(contract) => &contract.effects }
    }

    fn value_size(&self) -> KunaResult<Option<int4>> {
        match self {
            Self::Native(contract) => super::kuna_callabletransport::native_hidden_value_size(contract),
            Self::Generated(contract) => super::kuna_callabletransport::generated_hidden_value_size(contract),
        }
    }

    fn admitted(&self, fd: &Funcdata, execution: &ExecutionRequirements, op: OpId) -> bool {
        match self {
            Self::Native(contract) => fd.native_execution_contracts().get(&op)
                .is_some_and(|actual| Rc::ptr_eq(actual, contract))
                && execution.native_assumptions.iter().any(|assumption|
                    assumption.op == op && Rc::ptr_eq(&assumption.contract, contract)),
            Self::Generated(contract) => fd.generated_execution_contracts().get(&op)
                .is_some_and(|actual| Rc::ptr_eq(actual, contract))
                && execution.generated_assumptions.iter().any(|assumption|
                    assumption.op == op && Rc::ptr_eq(&assumption.contract, contract)),
        }
    }

    fn hidden_slot(&self) -> KunaResult<Option<int4>> {
        match self {
            Self::Generated(contract) => super::kuna_callabletransport::generated_hidden_argument_slot(contract),
            Self::Native(contract) => {
                let Some(result) = &contract.effects.hidden_result else { return Ok(None); };
                let mut arguments = contract.arguments.iter().enumerate().filter(|(_, argument)|
                    argument.address == result.address && argument.size == result.pointer_size);
                let Some((slot, _)) = arguments.next() else { return Ok(None); };
                if arguments.next().is_some() { return Ok(None); }
                Ok(int4::try_from(slot).ok().and_then(|slot| slot.checked_add(1)))
            }
        }
    }
}

/// Heritage has detached the call-spec vector. Use its explicit call and the
/// exact admitted receipt; final publication separately replays the destination.
pub(crate) fn execution_memory_definition_covers(fd: &Funcdata, call: &crate::fspec::FuncCallSpecs,
    address: &Address, size: int4) -> bool
{
    if !fd.get_arch().execution_callable_c || size <= 0 { return false; }
    let Some(stack) = fd.get_arch().manage().get_stack_space().filter(|space| space.get_word_size() == 1) else { return false; };
    if address.get_space().is_none_or(|space| !Rc::ptr_eq(space, stack)) { return false; }
    let Some(execution) = fd.entry_physical_requirements().and_then(|raw| raw.execution.as_ref())
        .filter(|execution| execution.complete) else { return false; };
    execution.memory_definitions.iter().any(|definition| {
        if definition.op != call.get_op() || definition.size <= 0
            || definition.stack_address.get_space().is_none_or(|space| !Rc::ptr_eq(space, stack))
            || !definition.producer.admitted(fd, execution, definition.op)
            || matches!(&definition.producer, ExecutionMemoryProducer::Native(contract)
                if !super::kuna_callabletransport::native_source_abi_equal(call.proto(), &contract.prototype)) {
            return false;
        }
        let delta = stack.wrap_offset(address.get_offset().wrapping_sub(definition.stack_address.get_offset()));
        delta <= definition.size as u64 && size as u64 <= definition.size as u64 - delta
    })
}

/// Called after final native and generated ABI/target replay by the owning-body exporter.
/// Provisional Heritage creation alone is never executable publication evidence.
pub(crate) fn validate_execution_memory_destinations(fd: &Funcdata, execution: &ExecutionRequirements) -> KunaResult<()> {
    use kuna_base::error::KunaError;
    for definition in &execution.memory_definitions {
        let fail = || KunaError::lowlevel("Conditional result memory definition lost its destination proof");
        if !definition.producer.admitted(fd, execution, definition.op)
            || definition.producer.value_size()? != Some(definition.size) { return Err(fail()); }
        let result = definition.producer.effects().hidden_result.as_ref().ok_or_else(fail)?;
        let slot = definition.producer.hidden_slot()?.ok_or_else(fail)?;
        let operation = fd.obank().get(definition.op).filter(|operation| !operation.is_dead()).ok_or_else(fail)?;
        let input = operation.get_in(slot).ok_or_else(fail)?;
        let (root, offset) = super::kuna_logicalresultbody::final_pointer(fd, input, result.pointer_size).ok_or_else(fail)?;
        let root = fd.vbank().get(root).ok_or_else(fail)?;
        let stack = fd.get_arch().manage().get_stack_space().filter(|space|
            space.get_word_size() == 1 && space.num_spacebase() == 1).ok_or_else(fail)?;
        let base = stack.get_spacebase(0).map_err(|_| fail())?;
        if !root.is_input() || root.get_size() != result.pointer_size || base.size as int4 != result.pointer_size
            || base.space.as_ref().is_none_or(|space| !Rc::ptr_eq(space, root.get_space()))
            || root.get_offset() != base.offset
            || definition.stack_address.get_space().is_none_or(|space| !Rc::ptr_eq(space, stack))
            || stack.wrap_offset(offset) != definition.stack_address.get_offset() {
            return Err(fail());
        }
    }
    Ok(())
}

/// Fresh successful target-own raw flow, not transitive execution completeness.
/// Constructed only by PhysicalInputDrive; never carries target-local operation IDs.
#[derive(Clone, Debug)]
pub struct MappedBodyWitness {
    entry: Address,
    raw: Rc<EntryRequirements>,
}

impl MappedBodyWitness {
    pub(crate) fn new(entry: Address, raw: Rc<EntryRequirements>) -> Self { Self { entry, raw } }
    pub(crate) fn entry(&self) -> &Address { &self.entry }
    pub(crate) fn raw(&self) -> &Rc<EntryRequirements> { &self.raw }
}

#[derive(Clone, Debug)]
pub struct DeferredBodyAssumption {
    pub op: OpId,
    pub contract: Rc<super::kuna_callabletransport::DeferredBodyContract>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum FlowReturnOrigin {
    LocalOverride,
    HostInstruction,
}

#[derive(Clone, Debug)]
pub struct FlowReturnAssumption {
    pub(crate) origin: FlowReturnOrigin,
    pub site: Address,
    pub call: OpId,
    pub return_op: OpId,
    pub source_model: Rc<crate::fspec::ProtoModel>,
    pub stack: (Address, int4, i64),
    pub observed_delta: Option<i64>,
    pub normal_returns: Rc<[OpId]>,
}

#[derive(Clone, Debug)]
pub struct DirectExecutionAssumption {
    pub op: OpId,
    pub entry: Address,
    pub family: TypeRoot,
    pub raw: Rc<EntryRequirements>,
    pub execution: Option<Rc<ExecutionRequirements>>,
    pub inputs: Vec<(Address, int4)>,
    pub output: Option<(Address, int4)>,
    pub effects: Vec<crate::fspec::EffectRecord>,
    pub extra_pop: int4,
    pub model: Rc<crate::fspec::ProtoModel>,
    pub internal_roles: Vec<(Address, int4)>,
}

#[derive(Clone)]
enum Access {
    Read(Range<usize>),
    Write(Range<usize>),
    Return,
}

/// Retain positive machine reads outside the C interface as actual CALL operands.
/// Such a call is explicitly raw: no declaration is widened to pretend these
/// extra state inputs are source parameters, and no detached Varnodes are cached.
pub fn capture_call_inputs(data: &mut Funcdata, index: int4) -> KunaResult<()> {
    let mut physical = data.get_call_specs(index).collect_physical_inputs(data)?;
    for input in data.get_call_specs(index).physical_inputs() {
        if !physical.iter().any(|current| current.operand_slot == input.operand_slot) {
            let operation = data.get_call_specs(index).get_op();
            let value = data.obank().get(operation).and_then(|op| op.get_in(input.operand_slot))
                .and_then(|id| data.vbank().get(id))
                .ok_or_else(|| kuna_base::error::KunaError::lowlevel("Missing captured raw call operand"))?;
            if value.get_size() != input.size {
                return Err(kuna_base::error::KunaError::lowlevel("Captured raw call operand has wrong width"));
            }
            physical.push(input.clone());
        }
    }
    let mut raw = data.get_call_specs(index).requires_raw_call()
        || physical.iter().any(|input| input.operand_slot > data.get_call_specs(index).proto().num_params());
    let requirements = data.get_call_specs(index).input_requirements().cloned();
    if data.get_call_specs(index).proto().is_input_locked() {
        if let Some(requirements) = requirements {
            let operation = data.get_call_specs(index).get_op();
            for (read, bytes) in &requirements.reads {
                let Some(space) = read.get_space() else { continue };
                let end = read.get_offset() + *bytes as u64;
                let mut cursor = read.get_offset();
                while cursor < end {
                    let mut covered_end = cursor;
                    let mut boundary = end;
                    let mut cover = |at: &Address, size: int4| {
                        if !at.get_space().is_some_and(|other| Rc::ptr_eq(space, other)) { return; }
                        let last = at.get_offset() + size as u64;
                        if at.get_offset() <= cursor && last > cursor { covered_end = covered_end.max(last); }
                        else if at.get_offset() > cursor { boundary = boundary.min(at.get_offset()); }
                    };
                    let prototype = data.get_call_specs(index).proto();
                    for slot in 0..prototype.num_params() {
                        let parameter = prototype.get_param(slot).expect("physical call parameter");
                        cover(&parameter.get_address(), parameter.get_size());
                    }
                    for (at, size) in &requirements.bookkeeping { cover(at, *size); }
                    for input in &physical {
                        if input.operand_slot > prototype.num_params() { cover(&input.address, input.size); }
                    }
                    if covered_end > cursor { cursor = covered_end.min(end); continue; }
                    if !raw {
                        data.get_call_specs_mut(index).set_physical_inputs(Vec::new(), true);
                        physical = data.get_call_specs(index).collect_physical_inputs(data)?;
                        raw = true;
                    }
                    let address = Address::new(space.clone(), cursor);
                    let size = (boundary - cursor) as int4;
                    let value = data.new_varnode(size, &address, None);
                    let slot = data.obank().get(operation).expect("physical call operation").num_input();
                    data.op_insert_input(operation, value, slot)?;
                    physical.push(PhysicalCallInput { operand_slot: slot, address, size });
                    cursor = boundary;
                }
            }
        }
    }
    data.get_call_specs_mut(index).set_physical_inputs(physical, raw);
    Ok(())
}

fn register_range(fd: &Funcdata, vn: VarnodeId) -> Option<(int4, u64, usize)> {
    let value = fd.vbank().get(vn)?;
    let space = value.get_addr().get_space()?;
    if space.get_name() != "register" || value.get_size() <= 0 { return None; }
    Some((space.get_index(), value.get_offset(), value.get_size() as usize))
}

fn coalesce_writes(writes: &mut Vec<(Address, int4)>) {
    writes.sort_unstable_by(|left, right| left.0.cmp(&right.0));
    let mut retained = 0;
    for index in 0..writes.len() {
        if retained > 0 {
            let previous = &writes[retained - 1];
            let current = &writes[index];
            let same_space = previous.0.get_space().zip(current.0.get_space())
                .is_some_and(|(left, right)| Rc::ptr_eq(left, right));
            if same_space && current.0.get_offset() <= previous.0.get_offset() + previous.1 as u64 {
                let end = (current.0.get_offset() + current.1 as u64)
                    .max(previous.0.get_offset() + previous.1 as u64);
                if let Ok(size) = int4::try_from(end - previous.0.get_offset()) {
                    writes[retained - 1].1 = size;
                    continue;
                }
            }
        }
        writes.swap(retained, index);
        retained += 1;
    }
    writes.truncate(retained);
}

/// Prove that a value reaches only normal RETURN targets through full COPYs.
/// Reused/overlapping storage and implicit callee reads are observations too;
/// uncertain aliases reject bookkeeping without deleting positive raw reads.
pub(super) fn return_target_only(fd: &Funcdata, initial: VarnodeId,
    callees: &BTreeMap<OpId, Rc<EntryRequirements>>,
    contracts: Option<&BTreeMap<OpId, &ExecutionCallEffects>>,
    flow: Option<&ConditionalFlowView>) -> bool
{
    let storage = |id| fd.vbank().get(id).and_then(|value| {
        value.get_addr().get_space().map(|space| (space.get_index(), value.get_offset(), value.get_size()))
    });
    let Some(initial) = storage(initial) else { return false };
    let mut values = BTreeSet::from([initial]);
    loop {
        let mut changed = false;
        for (_, id) in fd.obank().iter_all() {
            if flow.is_some_and(|view| !view.op_reachable(fd, id)) { continue; }
            let operation = fd.obank().get(id).expect("live raw operation");
            if matches!(operation.code(), OpCode::CPUI_CALL | OpCode::CPUI_CALLIND) {
                let intersects = |address: &Address, size: int4| size > 0
                    && address.get_space().is_some_and(|space| values.iter().any(|value|
                        value.0 == space.get_index() && value.2 > 0
                        && value.1 < address.get_offset().saturating_add(size as u64)
                        && address.get_offset() < value.1.saturating_add(value.2 as u64)));
                if let Some(contract) = contracts.and_then(|contracts| contracts.get(&id)) {
                    if contract.inputs.iter().any(|(address, size)| intersects(address, *size)) { return false; }
                } else if let Some(callee) = callees.get(&id).filter(|callee| callee.is_complete()) {
                    if callee.reads.iter().any(|(address, size)| intersects(address, *size)
                        && !callee.is_bookkeeping(address, *size)) { return false; }
                } else if values.iter().any(|value| fd.get_arch().manage().get_space(value.0)
                    .is_some_and(|space| space.get_name() == "register")) { return false; }
            }
            for slot in 0..operation.num_input() {
                let Some(value) = operation.get_in(slot).and_then(storage) else { continue };
                let overlaps = values.iter().any(|known| known.0 == value.0 && known.2 > 0 && value.2 > 0
                    && known.1 < value.1.saturating_add(value.2 as u64)
                    && value.1 < known.1.saturating_add(known.2 as u64));
                if !overlaps { continue; }
                if !values.contains(&value) { return false; }
                if operation.code() == OpCode::CPUI_RETURN && operation.get_halt_type() == 0 && slot == 0 { continue; }
                if operation.code() != OpCode::CPUI_COPY || operation.num_input() != 1 { return false; }
                let Some(output) = operation.get_out().and_then(storage) else { return false };
                if output.2 != value.2 { return false; }
                changed |= values.insert(output);
            }
        }
        if !changed { break; }
    }
    // Raw RETURN has no explicit result operands. A copy into a source/model
    // result register is an observable value, even if the only P-code read of
    // the original register is the return branch target.
    let proto = fd.get_func_proto();
    let model = if proto.has_model() { Some(proto.model()) } else { fd.get_arch().default_fp() };
    for (space_index, offset, bytes) in &values {
        let Some(space) = fd.get_arch().manage().get_space(*space_index) else { return false; };
        if space.get_name() != "register" { continue; }
        let address = Address::new(space.clone(), *offset);
        if model.is_some_and(|model| model.possible_output_param(&address, *bytes)) { return false; }
        if proto.has_store() && proto.is_output_locked() {
            let output = proto.get_output();
            let at = output.get_address();
            if at.get_space().is_some_and(|space| space.get_type() == kuna_base::space::spacetype::IPTR_JOIN) {
                let Ok(join) = fd.get_arch().manage().find_join(at.get_offset()) else { return false; };
                for index in 0..join.num_pieces() {
                    let piece = join.get_piece(index);
                    if piece.space.as_ref().is_some_and(|other| Rc::ptr_eq(other, space))
                        && piece.offset < offset.saturating_add(*bytes as u64)
                        && *offset < piece.offset.saturating_add(piece.size as u64) { return false; }
                }
            } else if at.get_space().is_some_and(|other| Rc::ptr_eq(other, space))
                && at.get_offset() < offset.saturating_add(*bytes as u64)
                && *offset < at.get_offset().saturating_add(output.get_size().max(0) as u64) { return false; }
        }
    }
    values.iter().all(|value| fd.obank().iter_all().any(|(_, id)| {
        if flow.is_some_and(|view| !view.op_reachable(fd, id)) { return false; }
        let operation = fd.obank().get(id).expect("live raw operation");
        (0..operation.num_input()).any(|slot| operation.get_in(slot).and_then(storage).as_ref() == Some(value))
    })) && fd.obank().iter_code(OpCode::CPUI_RETURN).any(|id| {
        if flow.is_some_and(|view| !view.op_reachable(fd, id)) { return false; }
        fd.obank().get(id).filter(|op| op.get_halt_type() == 0).and_then(|op| op.get_in(0)).and_then(storage)
            .is_some_and(|value| values.contains(&value))
    })
}

fn stack_address_only(
    fd: &Funcdata, addr: &Address, size: int4,
    callees: &BTreeMap<OpId, Rc<EntryRequirements>>,
    raw_callees: &BTreeMap<OpId, Rc<EntryRequirements>>, contracts: Option<&BTreeMap<OpId, &ExecutionCallEffects>>,
    flow: Option<&ConditionalFlowView>,
) -> bool {
    let Some(space) = addr.get_space() else { return false };
    let mut tainted = BTreeSet::from([(space.get_index(), addr.get_offset(), size)]);
    let intersects = |address: &Address, bytes: int4, tainted: &BTreeSet<(int4, u64, int4)>| {
        address.get_space().is_some_and(|space| tainted.iter().any(|(id, offset, size)| {
            *id == space.get_index() && *offset < address.get_offset().saturating_add(bytes as u64)
                && address.get_offset() < offset.saturating_add(*size as u64)
        }))
    };
    loop {
        let mut changed = false;
        for (_, id) in fd.obank().iter_all() {
            if flow.is_some_and(|view| !view.op_reachable(fd, id)) { continue; }
            let operation = fd.obank().get(id).expect("live raw operation");
            for slot in 0..operation.num_input() {
                let Some(value) = operation.get_in(slot).and_then(|id| fd.vbank().get(id)) else { continue };
                if !intersects(value.get_addr(), value.get_size(), &tainted) { continue; }
                if matches!(operation.code(), OpCode::CPUI_LOAD | OpCode::CPUI_STORE) && slot == 1 {
                    if operation.code() == OpCode::CPUI_LOAD
                        && !operation.get_out().is_some_and(|output| return_target_only(fd, output, raw_callees, contracts, flow))
                    { return false; }
                    continue;
                }
                let affine = operation.code() == OpCode::CPUI_COPY
                    || (matches!(operation.code(), OpCode::CPUI_INT_ADD | OpCode::CPUI_INT_SUB)
                        && (slot == 0 || operation.code() == OpCode::CPUI_INT_ADD)
                        && operation.get_in(1 - slot).and_then(|id| fd.vbank().get(id))
                            .is_some_and(|other| other.is_constant()));
                if !affine { return false; }
                let Some(output) = operation.get_out().and_then(|id| fd.vbank().get(id)) else { return false };
                let Some(output_space) = output.get_addr().get_space() else { return false };
                changed |= tainted.insert((output_space.get_index(), output.get_offset(), output.get_size()));
            }
        }
        if !changed { break; }
    }
    // Raw RETURN names only the branch target, not ABI result registers.
    // A stack pointer copied into a returned register is observable even when
    // there is no explicit subsequent P-code read of that register.
    let proto = fd.get_func_proto();
    let model = if proto.has_model() { Some(proto.model()) } else { fd.get_arch().default_fp() };
    for (space_index, offset, bytes) in &tainted {
        let Some(space) = fd.get_arch().manage().get_space(*space_index) else { return false };
        if space.get_name() != "register" { continue; }
        let location = Address::new(space.clone(), *offset);
        if model.is_some_and(|model| model.possible_output_param(&location, *bytes)) { return false; }
        if proto.has_store() && proto.is_output_locked() {
            let output = proto.get_output();
            let outaddr = output.get_address();
            if outaddr.get_space().is_some_and(|space| space.get_type() == kuna_base::space::spacetype::IPTR_JOIN) {
                return false;
            }
            if outaddr.get_space().is_some_and(|other| Rc::ptr_eq(space, other))
                && outaddr.get_offset() < offset.saturating_add(*bytes as u64)
                && *offset < outaddr.get_offset().saturating_add(output.get_size().max(0) as u64)
            { return false; }
        }
    }
    callees.values().all(|callee| callee.reads.iter().all(|(at, bytes)| {
        !intersects(at, *bytes, &tainted) || callee.is_bookkeeping(at, *bytes)
    }))
}

/// Conservative read-before-def requirements over the entire lifted CFG, not a
/// bounded entry prefix. Calls retain an unresolved effect while the walk
/// continues through their fallthrough, so reads after a call are not lost.
pub fn from_raw_flow(
    fd: &Funcdata, callees: &BTreeMap<OpId, Rc<EntryRequirements>>,
    flow: Option<Rc<ConditionalFlowView>>,
) -> RawFlowAnalysis {
    let (contracts, failed) = match crate::p4_calls::kuna_callabletransport::raw_indirect_contracts(fd, None) {
        Ok(contracts) => (contracts, false),
        Err(_) => (BTreeMap::new(), true),
    };
    let direct = BTreeMap::new();
    let mut effects = contracts.iter().map(|(op, contract)| (*op, &contract.effects)).collect::<BTreeMap<_, _>>();
    let mut raw = analyze_flow(fd, callees, callees, &effects, false, &direct, &BTreeMap::new(), None, None);
    let (safe_internal_roles, inherited_internal_roles) =
        super::kuna_registerrestore::raw_internal_roles(fd, callees, &effects);
    raw.safe_internal_roles = safe_internal_roles;
    raw.requirements.incomplete_flow |= failed;
    if failed { raw.requirements.execution = None; }
    if !fd.get_arch().execution_callable_c || (failed && flow.is_none()) { return raw; }
    let flow_returns = super::kuna_flowreturn::raw_contracts(fd);
    // Flow-return receipts authenticate the whole original normal-return set.
    // Do not silently weaken that independent obligation through an edge cut.
    if flow.is_some() && !flow_returns.is_empty() { raw.requirements.execution = None; return raw; }
    let replay_contracts = if let Some(view) = &flow {
        match crate::p4_calls::kuna_callabletransport::raw_indirect_contracts(fd, Some(view)) {
            Ok(contracts) => Some(contracts),
            Err(_) => { raw.requirements.execution = None; return raw; }
        }
    } else { None };
    if let Some(contracts) = &replay_contracts {
        effects.clear();
        effects.extend(contracts.iter().map(|(op, contract)| (*op, &contract.effects)));
    }
    let reachable = |op| flow.as_ref().is_none_or(|view| view.op_reachable(fd, op));
    let refined = fd.refined_indirect_contracts();
    let formal_contracts = replay_contracts.as_ref().unwrap_or(&contracts);
    for (op, contract) in refined.iter().filter(|(op, _)| reachable(**op)) {
        if formal_contracts.get(op).is_some_and(|formal| formal.family != contract.family) {
            raw.requirements.execution = None;
            return raw;
        }
        // Settled producer authority enters only the conditional solver. It is
        // never an original raw read/preservation fact or a finite target body.
        effects.entry(*op).or_insert(&contract.effects);
    }
    let native = fd.native_execution_contracts();
    let generated = fd.generated_execution_contracts();
    let deferred = fd.deferred_execution_contracts();
    let conditional_calls = flow.is_some() || !contracts.is_empty() || !native.is_empty()
        || !generated.is_empty() || !deferred.is_empty() || !refined.is_empty()
        || !inherited_internal_roles.is_empty()
        || callees.values().any(|child| child.execution.as_ref().is_some_and(|execution| execution.complete));
    let private_leaf = raw.requirements.is_complete() && callees.is_empty() && raw.requirements.writes_memory;
    if !conditional_calls && !private_leaf && flow_returns.is_empty() { return raw; }
    // These temporary views are used only by the conditional solver. They are
    // never installed on a call specification or exposed as raw effect facts.
    let mut direct = BTreeMap::new();
    for (op, child) in callees {
        if !reachable(*op) { continue; }
        let requested_roles = inherited_internal_roles.iter().filter(|role| role.calls.contains(op))
            .map(|role| (role.address.clone(), role.size)).collect::<Vec<_>>();
        match crate::p4_calls::kuna_callabletransport::raw_direct_contract(fd, *op, child, &requested_roles) {
            Ok(Some(obligation)) => { direct.insert(*op, obligation); }
            Ok(None) => {}
            Err(_) => {
                raw.requirements.incomplete_flow = true;
                raw.requirements.execution = None;
                return raw;
            }
        }
    }
    let execution_callees = callees.iter().filter(|(op, _)| reachable(**op)).map(|(op, child)| {
        let selected = if let Some(execution) = direct.get(op)
            .and_then(|obligation| obligation.execution.as_ref())
        {
            let mut selected = child.as_ref().clone();
            selected.reads.clone_from(&execution.reads);
            selected.definite_writes.clone_from(&execution.definite_writes);
            selected.restored.clone_from(&execution.restored);
            selected.stack_adjustments.clone_from(&execution.stack_adjustments);
            selected.bookkeeping.clone_from(&execution.bookkeeping);
            selected.incomplete_flow = !execution.complete;
            if execution.complete { selected.unresolved.clear(); }
            // This solver-only view retains its exact owning-body obligation.
            Rc::new(selected)
        } else { Rc::clone(child) };
        (*op, selected)
    }).collect();
    effects.extend(native.iter().filter(|(op, _)| reachable(**op)).map(|(op, contract)| (*op, &contract.effects)));
    effects.extend(generated.iter().filter(|(op, _)| reachable(**op)).map(|(op, contract)| (*op, &contract.effects)));
    effects.extend(deferred.iter().filter(|(op, _)| reachable(**op)).map(|(op, contract)| (*op, &contract.effects)));
    let RawFlowAnalysis { requirements: mut analyzed, private_stores, .. } = analyze_flow(fd, &execution_callees, callees, &effects, true, &direct, &flow_returns, flow.as_ref(), Some(&raw.requirements.writes));
    raw.private_stores = private_stores;
    let complete = analyzed.is_complete();
    if complete {
        raw.inherited_internal_roles = inherited_internal_roles.into_iter().filter(|role|
            role.calls.iter().all(|op| direct.get(op).is_some_and(|obligation|
                obligation.internal_roles.iter().any(|(address, size)|
                    address == &role.address && *size == role.size)))).collect();
    }
    let (reads, requires_private_frame, flow_returns, memory_definitions) = match analyzed.execution.take() {
        Some(execution) => {
            let execution = Rc::unwrap_or_clone(execution);
            (execution.reads, execution.requires_private_frame, execution.flow_returns, execution.memory_definitions)
        }
        None => (analyzed.reads, false, Vec::new(), Vec::new()),
    };
    if !conditional_calls && !requires_private_frame && flow_returns.is_empty() { return raw; }
    drop(effects);
    let admitted = replay_contracts.unwrap_or(contracts);
    let mut execution_assumptions = Vec::with_capacity(admitted.len() + refined.len());
    for (op, contract) in refined.iter().filter(|(op, _)| reachable(**op)) {
        if !admitted.contains_key(op) { execution_assumptions.push((*op, contract.family.clone())); }
    }
    execution_assumptions.extend(admitted.into_iter().map(|(op, contract)| (op, contract.family)));
    raw.requirements.execution = Some(Rc::new(ExecutionRequirements {
        reads, definite_writes: analyzed.definite_writes,
        restored: analyzed.restored, stack_adjustments: analyzed.stack_adjustments,
        bookkeeping: analyzed.bookkeeping,
        requires_private_frame, memory_definitions,
        complete, execution_assumptions, direct_assumptions: direct.into_values().collect(),
        native_assumptions: native.iter().filter(|(op, _)| reachable(**op)).map(|(op, contract)| NativeExecutionAssumption {
            op: *op, contract: Rc::clone(contract),
        }).collect(),
        generated_assumptions: generated.iter().filter(|(op, _)| reachable(**op)).map(|(op, contract)| GeneratedExecutionAssumption {
            op: *op, contract: Rc::clone(contract),
        }).collect(),
        deferred_assumptions: deferred.iter().filter(|(op, _)| reachable(**op)).map(|(op, contract)| DeferredBodyAssumption {
            op: *op, contract: Rc::clone(contract),
        }).collect(),
        flow_returns, conditional_flow: flow,
    }));
    raw
}

fn analyze_flow(
    fd: &Funcdata, callees: &BTreeMap<OpId, Rc<EntryRequirements>>,
    raw_callees: &BTreeMap<OpId, Rc<EntryRequirements>>,
    contracts: &BTreeMap<OpId, &ExecutionCallEffects>,
    conditional: bool, direct: &BTreeMap<OpId, DirectExecutionAssumption>,
    flow_returns: &BTreeMap<OpId, FlowReturnAssumption>,
    flow: Option<&Rc<ConditionalFlowView>>,
    restoration_writes: Option<&[(Address, int4)]>,
) -> RawFlowAnalysis {
    let count = fd.bblocks_get_size() as usize;
    let mut result = EntryRequirements::default();
    result.incomplete_flow = count == 0 || fd.has_unimplemented() || fd.has_bad_data();
    result.writes_memory = false;
    result.reads_memory = false;
    if count == 0 { return RawFlowAnalysis { requirements: result, ..Default::default() }; }
    // Raw RETURN exposes its branch target, not the function's declared result.
    // Treat result storage as a read at each return so must-written analysis
    // retains an incoming result register when some return path never defines it.
    let mut return_reads = Vec::new();
    let prototype = fd.get_func_proto();
    if prototype.has_store() && prototype.is_output_locked() {
        let output = prototype.get_output();
        if output.get_size() > 0 {
            let address = output.get_address();
            match address.get_space() {
                Some(space) if space.get_name() == "register" => {
                    return_reads.push((address.clone(), output.get_size()));
                }
                Some(space) if space.get_type() == kuna_base::space::spacetype::IPTR_JOIN => {
                    match fd.get_arch().manage().find_join(address.get_offset()) {
                        Ok(join) => {
                            for index in 0..join.num_pieces() {
                                let piece = join.get_piece(index);
                                if let Some(space) = piece.space.as_ref().filter(|space| space.get_name() == "register") {
                                    return_reads.push((Address::new(space.clone(), piece.offset), piece.size as int4));
                                } else { result.incomplete_flow = true; }
                            }
                        }
                        Err(_) => { result.incomplete_flow = true; }
                    }
                }
                _ => { result.incomplete_flow = true; }
            }
        }
    }
    let blocks: Vec<_> = (0..count).map(|i| fd.bblocks_get_block(i as int4)).collect();
    let positions: BTreeMap<_, _> = blocks.iter().enumerate().map(|(i, id)| (*id, i)).collect();
    let mut domain = Vec::new();
    for vn in fd.vbank().iter_loc() {
        if let Some((space, offset, size)) = register_range(fd, vn) {
            for byte in 0..size { domain.push((space, offset + byte as u64)); }
        }
    }
    for callee in callees.values() {
        for (address, size) in callee.reads.iter().chain(&callee.definite_writes) {
            let Some(space) = address.get_space() else { continue };
            for byte in 0..*size {
                domain.push((space.get_index(), address.get_offset() + byte as u64));
            }
        }
    }
    for (op, contract) in contracts {
        for (address, size) in &contract.inputs {
            let Some(space) = address.get_space() else { continue };
            // Conditional ABI stack arguments are callee-relative outgoing slots, not
            // newly observed incoming memory of this caller. Restoration reads
            // their actual caller-relative stored origins at the call state.
            if conditional && (fd.native_execution_contracts().contains_key(op)
                || fd.deferred_execution_contracts().contains_key(op))
                && space.get_type() == kuna_base::space::spacetype::IPTR_SPACEBASE { continue; }
            for byte in 0..*size {
                domain.push((space.get_index(), address.get_offset() + byte as u64));
            }
        }
    }
    for (address, size) in &return_reads {
        let space = address.get_space().expect("declared return register space");
        for byte in 0..*size { domain.push((space.get_index(), address.get_offset() + byte as u64)); }
    }
    if conditional {
        for contract in contracts.values() {
            for (address, size) in &contract.outputs {
                let Some(space) = address.get_space() else { continue };
                for byte in 0..*size { domain.push((space.get_index(), address.get_offset() + byte as u64)); }
            }
        }
    }
    domain.sort_unstable();
    domain.dedup();
    let width = domain.len();
    let mut events = Vec::with_capacity(count);
    for block in &blocks {
        let mut accesses = Vec::new();
        if flow.is_some_and(|view| !view.block_reachable(*block)) { events.push(accesses); continue; }
        let mut op = match fd.bblocks_ref().block(*block).kind() {
            BlockKind::Basic(data) => data.op_head,
            _ => None,
        };
        while let Some(id) = op {
            let operation = fd.obank().get(id).expect("live physical-input operation");
            op = operation.basic_neighbours().1;
            let code = operation.code();
            if code == OpCode::CPUI_STORE { result.writes_memory = true; }
            if code == OpCode::CPUI_LOAD { result.reads_memory = true; }
            if matches!(code, OpCode::CPUI_CALL | OpCode::CPUI_CALLIND | OpCode::CPUI_CALLOTHER)
                && !callees.contains_key(&id) { result.writes_memory = true; result.reads_memory = true; }
            if code == OpCode::CPUI_RETURN && operation.get_halt_type() == 0 {
                for (address, size) in &return_reads {
                    let space = address.get_space().expect("declared return register space");
                    let start = domain.binary_search(&(space.get_index(), address.get_offset())).unwrap();
                    accesses.push(Access::Read(start..start + *size as usize));
                }
            }
            if let Some(contract) = contracts.get(&id) {
                for (address, size) in &contract.inputs {
                    let Some(space) = address.get_space() else { continue };
                    if conditional && (fd.native_execution_contracts().contains_key(&id)
                        || fd.generated_execution_contracts().contains_key(&id)
                        || fd.deferred_execution_contracts().contains_key(&id))
                        && space.get_type() == kuna_base::space::spacetype::IPTR_SPACEBASE { continue; }
                    let start = domain.binary_search(&(space.get_index(), address.get_offset())).unwrap();
                    accesses.push(Access::Read(start..start + *size as usize));
                }
            }
            if matches!(code, OpCode::CPUI_LOAD | OpCode::CPUI_STORE) {
                let accessed = operation.get_in(0).and_then(|id| fd.vbank().get(id))
                    .filter(|value| value.is_constant())
                    .and_then(|value| int4::try_from(value.get_offset()).ok())
                    .and_then(|index| fd.get_arch().manage().get_space(index));
                if accessed.is_none_or(|space| space.get_name() == "register") {
                    result.incomplete_flow = true;
                }
            }
            if matches!(code, OpCode::CPUI_CALL | OpCode::CPUI_CALLIND | OpCode::CPUI_CALLOTHER
                | OpCode::CPUI_BRANCHIND)
            {
                if let Some(callee) = callees.get(&id) {
                    // Separate native or generated-body obligations close only
                    // their exact call cut in this conditional solver. Raw facts
                    // remain installed on the original summary unchanged.
                    let deferred_body = conditional && (fd.deferred_execution_contracts().contains_key(&id)
                        || fd.generated_execution_contracts().contains_key(&id));
                    if !deferred_body && (!conditional || !fd.native_execution_contracts().contains_key(&id)) {
                        result.incomplete_flow |= callee.incomplete_flow;
                        result.unresolved.extend(callee.unresolved.iter().cloned());
                    }
                    result.writes.extend(callee.writes.iter().cloned());
                    result.writes_memory |= callee.writes_memory;
                    result.reads_memory |= callee.reads_memory;
                    if !deferred_body {
                        for (address, size) in &callee.reads {
                            let Some(space) = address.get_space() else { continue };
                            let start = domain.binary_search(&(space.get_index(), address.get_offset())).unwrap();
                            accesses.push(Access::Read(start..start + *size as usize));
                        }
                    }
                } else if !conditional || !contracts.contains_key(&id) {
                    result.unresolved.push((operation.get_addr().clone(), code));
                }
            }
            if operation.get_halt_type() != 0 { result.incomplete_flow = true; }
            let zero_idiom = matches!(code, OpCode::CPUI_INT_XOR | OpCode::CPUI_INT_SUB)
                && operation.get_in(0).zip(operation.get_in(1)).is_some_and(|(left, right)| {
                    register_range(fd, left).is_some()
                        && register_range(fd, left) == register_range(fd, right)
                });
            if !zero_idiom {
                for slot in 0..operation.num_input() {
                    let Some(input) = operation.get_in(slot) else { continue };
                    let Some((space, mut offset, mut size)) = register_range(fd, input) else { continue };
                    if code == OpCode::CPUI_SUBPIECE && slot == 0 {
                        if let Some(cut) = operation.get_in(1).and_then(|id| fd.vbank().get(id)) {
                            if cut.is_constant() {
                                let output_size = operation.get_out().and_then(|id| fd.vbank().get(id))
                                    .map_or(size, |value| value.get_size() as usize);
                                let low = cut.get_offset() as usize;
                                if low + output_size <= size {
                                    offset += if fd.vbank().get(input).unwrap().get_addr().is_big_endian() {
                                        (size - low - output_size) as u64
                                    } else { low as u64 };
                                    size = output_size;
                                }
                            }
                        }
                    }
                    if code == OpCode::CPUI_INT_AND && size <= 8 {
                        let mask = operation.get_in(1 - slot).and_then(|id| fd.vbank().get(id))
                            .filter(|value| value.is_constant()).map(|value| value.get_offset());
                        if let Some(mask) = mask {
                            for byte in 0..size {
                                let shift = if fd.vbank().get(input).unwrap().get_addr().is_big_endian() {
                                    (size - 1 - byte) * 8
                                } else { byte * 8 };
                                if (mask >> shift) & 0xff != 0 {
                                    let index = domain.binary_search(&(space, offset + byte as u64)).unwrap();
                                    accesses.push(Access::Read(index..index + 1));
                                }
                            }
                            continue;
                        }
                    }
                    let start = domain.binary_search(&(space, offset)).unwrap();
                    accesses.push(Access::Read(start..start + size));
                }
            }
            // A known callee reads its incoming state before producing these
            // guaranteed definitions. May-writes alone are never a kill.
            if let Some(contract) = contracts.get(&id).filter(|_| conditional) {
                for (address, size) in &contract.outputs {
                    if let Some(space) = address.get_space() {
                        let start = domain.binary_search(&(space.get_index(), address.get_offset())).unwrap();
                        accesses.push(Access::Write(start..start + *size as usize));
                    }
                }
            }
            if let Some(callee) = callees.get(&id) {
                for (address, size) in &callee.definite_writes {
                    let Some(space) = address.get_space() else { continue };
                    let start = domain.binary_search(&(space.get_index(), address.get_offset())).unwrap();
                    accesses.push(Access::Write(start..start + *size as usize));
                }
            }
            if let Some((space, offset, size)) = operation.get_out().and_then(|id| register_range(fd, id)) {
                let start = domain.binary_search(&(space, offset)).unwrap();
                accesses.push(Access::Write(start..start + size));
                let address = fd.vbank().get(operation.get_out().unwrap()).unwrap().get_addr().clone();
                result.writes.push((address, size as int4));
            }
            if code == OpCode::CPUI_RETURN && operation.get_halt_type() == 0 { accesses.push(Access::Return); }
        }
        events.push(accesses);
    }
    let mut reachable = vec![false; count];
    let mut work = vec![0usize];
    while let Some(index) = work.pop() {
        if reachable[index] { continue; }
        reachable[index] = true;
        let block = fd.bblocks_ref().block(blocks[index]);
        for edge in 0..block.size_out() {
            if flow.is_some_and(|view| !view.edge_allowed(blocks[index], edge)) { continue; }
            if let Some(next) = positions.get(&block.get_out(edge)) { work.push(*next); }
        }
    }
    let mut written_out = vec![vec![false; width]; count];
    let mut written = vec![false; width];
    loop {
        let mut changed = false;
        for index in 0..count {
            if !reachable[index] { continue; }
            written.fill(false);
            if index != 0 {
                let block = fd.bblocks_ref().block(blocks[index]);
                let mut first = true;
                for edge in 0..block.size_in() {
                    if flow.is_some_and(|view| !view.edge_allowed(block.get_in(edge), block.get_in_rev_index(edge))) { continue; }
                    let Some(predecessor) = positions.get(&block.get_in(edge)).copied() else { continue };
                    if !reachable[predecessor] { continue; }
                    if first { written.clone_from(&written_out[predecessor]); first = false; }
                    else {
                        for (value, incoming) in written.iter_mut().zip(&written_out[predecessor]) {
                            *value &= *incoming;
                        }
                    }
                }
            }
            for event in &events[index] {
                if let Access::Write(range) = event { written[range.clone()].fill(true); }
            }
            if written_out[index] != written {
                written_out[index].clone_from(&written);
                changed = true;
            }
        }
        if !changed { break; }
    }
    let mut live = vec![false; width];
    let mut return_written = vec![true; width];
    let mut has_return = false;
    for index in 0..count {
        if !reachable[index] { continue; }
        written.fill(false);
        if index != 0 {
            let block = fd.bblocks_ref().block(blocks[index]);
            let mut first = true;
            for edge in 0..block.size_in() {
                if flow.is_some_and(|view| !view.edge_allowed(block.get_in(edge), block.get_in_rev_index(edge))) { continue; }
                let Some(predecessor) = positions.get(&block.get_in(edge)).copied() else { continue };
                if !reachable[predecessor] { continue; }
                if first { written.clone_from(&written_out[predecessor]); first = false; }
                else {
                    for (value, incoming) in written.iter_mut().zip(&written_out[predecessor]) {
                        *value &= *incoming;
                    }
                }
            }
        }
        for event in &events[index] {
            match event {
                Access::Write(range) => written[range.clone()].fill(true),
                Access::Read(range) => {
                    for byte in range.clone() { live[byte] |= !written[byte]; }
                }
                Access::Return => {
                    has_return = true;
                    for (guaranteed, current) in return_written.iter_mut().zip(&written) {
                        *guaranteed &= *current;
                    }
                }
            }
        }
    }
    // No vacuous guarantees for non-returning functions or a closure whose
    // unresolved control flow could return along an unobserved path.
    if !has_return || !result.is_complete() { return_written.fill(false); }
    for (mask, ranges) in [(&live, &mut result.reads), (&return_written, &mut result.definite_writes)] {
        let mut index = 0;
        while index < width {
            if !mask[index] { index += 1; continue; }
            let (space_index, offset) = domain[index];
            let start = index;
            index += 1;
            while index < width && mask[index] && domain[index] == (space_index, offset + (index - start) as u64) {
                index += 1;
            }
            if let Some(space) = fd.get_arch().manage().get_space(space_index) {
                ranges.push((Address::new(Rc::clone(space), offset), (index - start) as int4));
            }
        }
    }
    coalesce_writes(&mut result.writes);
    let restoration = if result.is_complete() {
        // A conditional cut removes effects, not the obligation to account for
        // the original machine may-write universe at every retained return.
        super::kuna_registerrestore::restored_registers(fd, callees, raw_callees,
            restoration_writes.unwrap_or(&result.writes),
            conditional.then_some(contracts), direct, flow_returns, flow.map(Rc::as_ref))
    } else { super::kuna_registerrestore::Restoration::default() };
    result.restored = restoration.restored;
    result.stack_adjustments = restoration.stack_adjustments;
    result.bookkeeping = restoration.bookkeeping;
    // Preserve positive raw reads; only classify exact registers whose actual
    // uses are full-width COPYs ending exclusively in normal RETURN targets.
    let storage = |id| fd.vbank().get(id).map(|node| (node.get_addr().clone(), node.get_size()));
    let mut return_candidates = BTreeMap::new();
    for id in fd.obank().iter_code(OpCode::CPUI_RETURN) {
        if flow.is_some_and(|view| !view.op_reachable(fd, id)) { continue; }
        let Some(value) = fd.obank().get(id).filter(|operation| operation.get_halt_type() == 0)
            .and_then(|operation| operation.get_in(0)) else { continue; };
        if let Some(storage) = storage(value) { return_candidates.insert(storage, value); }
    }
    loop {
        let mut changed = false;
        for (_, id) in fd.obank().iter_all() {
            if flow.is_some_and(|view| !view.op_reachable(fd, id)) { continue; }
            let operation = fd.obank().get(id).expect("raw COPY");
            if operation.code() != OpCode::CPUI_COPY || operation.num_input() != 1 { continue; }
            let Some(output) = operation.get_out().and_then(storage) else { continue; };
            if !return_candidates.contains_key(&output) { continue; }
            let Some(input) = operation.get_in(0) else { continue; };
            let Some(storage) = storage(input).filter(|storage| storage.1 == output.1) else { continue; };
            if let std::collections::btree_map::Entry::Vacant(entry) = return_candidates.entry(storage) {
                entry.insert(input);
                changed = true;
            }
        }
        if !changed { break; }
    }
    let return_model = if prototype.has_model() { Some(prototype.model()) } else { fd.get_arch().default_fp() };
    for ((address, size), value) in return_candidates {
        if size <= 0 || address.get_space().is_none_or(|space| space.get_name() != "register") { continue; }
        // The use proof must also start at an authentic incoming return-address
        // role, not an arbitrary parameter used by a nonstandard RETURN.
        if return_model.is_none_or(|model| model.effect_list().iter().all(|effect|
            effect.get_type() != crate::fspec::effect_type::RETURN_ADDRESS
                || effect.get_address() != address || effect.get_size() != size)) { continue; }
        let Some(end) = address.get_offset().checked_add(size as u64) else { continue; };
        if !result.reads.iter().any(|(at, bytes)| *bytes > 0
            && at.get_space().zip(address.get_space()).is_some_and(|(a, b)| Rc::ptr_eq(a, b))
            && at.get_offset() <= address.get_offset()
            && at.get_offset().checked_add(*bytes as u64).is_some_and(|limit| end <= limit)) { continue; }
        if return_target_only(fd, value, raw_callees, conditional.then_some(contracts), flow.map(Rc::as_ref)) {
            result.bookkeeping.push((address, size));
        }
    }
    let requires_private_frame = restoration.requires_private_frame;
    if let Some(stack) = fd.get_arch().manage().get_stack_space() {
        for index in 0..stack.num_spacebase() {
            if let Ok(storage) = stack.get_spacebase(index) {
                if let Some(space) = storage.space {
                    let addr = Address::new(space, storage.offset);
                    if stack_address_only(fd, &addr, storage.size as int4, callees, raw_callees, conditional.then_some(contracts), flow.map(Rc::as_ref)) {
                        result.bookkeeping.push((addr, storage.size as int4));
                    }
                }
            }
        }
    }
    coalesce_writes(&mut result.bookkeeping);
    // Positive machine reads stay above. Only a target-owned generated body
    // can use sink-observed demand to discharge a dead raw-state operand.
    if fd.get_arch().execution_callable_c {
        if let Some(observed) = restoration.observed {
            let mut reads = Vec::new();
            let mut trimmed = false;
            for (address, size) in &result.reads {
                let Some(space) = address.get_space() else { continue };
                let mut first = None;
                for byte in 0..=*size {
                    let used = byte < *size && observed.contains(&(space.get_index(), address.get_offset() + byte as u64));
                    if byte < *size && !used && !result.is_bookkeeping(&(address + byte as i64), 1) { trimmed = true; }
                    if used { first.get_or_insert(byte); }
                    else if let Some(start) = first.take() { reads.push((address + start as i64, byte - start)); }
                }
            }
            if trimmed || requires_private_frame || !restoration.flow_returns.is_empty() || !restoration.memory_definitions.is_empty() {
                result.execution = Some(Rc::new(ExecutionRequirements {
                    reads, definite_writes: result.definite_writes.clone(),
                    restored: result.restored.clone(), stack_adjustments: result.stack_adjustments.clone(),
                    bookkeeping: result.bookkeeping.clone(), complete: result.is_complete(),
                    requires_private_frame,
                    memory_definitions: restoration.memory_definitions,
                    execution_assumptions: Vec::new(),
                    direct_assumptions: Vec::new(),
                    native_assumptions: Vec::new(),
                    generated_assumptions: Vec::new(),
                    deferred_assumptions: Vec::new(),
                    conditional_flow: flow.cloned(),
                    flow_returns: restoration.flow_returns,
                }));
            }
        }
    }
    RawFlowAnalysis {
        requirements: result,
        private_stores: restoration.private_stores,
        safe_internal_roles: Vec::new(),
        inherited_internal_roles: Vec::new(),
    }
}

/// Actual demand after SSA/dead-code propagation. Ambient machine bookkeeping
/// is not promoted into source arguments.
pub fn from_ssa_inputs(fd: &Funcdata) -> EntryRequirements {
    collect_ssa_inputs(fd, false)
}

/// All consumed register and stack entry state, including bookkeeping
/// candidates. Executable export must explicitly cover or justify each range.
pub fn from_all_ssa_inputs(fd: &Funcdata) -> EntryRequirements {
    collect_ssa_inputs(fd, true)
}

fn collect_ssa_inputs(fd: &Funcdata, include_implicit: bool) -> EntryRequirements {
    let mut result = EntryRequirements::default();
    for id in fd.vbank().iter_def_flag(varnode_flags::input) {
        let value = fd.vbank().get(id).expect("live entry input");
        if !include_implicit && (value.is_unaffected() || value.is_spacebase() || value.is_indirect_only()) { continue; }
        if register_range(fd, id).is_none()
            && !(include_implicit && fd.get_arch().manage().get_stack_space()
                .is_some_and(|space| Rc::ptr_eq(space, value.get_space()))) { continue; }
        let size = value.get_size();
        let mut first = None;
        for byte in 0..=size {
            let demanded = if byte == size { false } else {
                let index = if value.get_addr().is_big_endian() { size - 1 - byte } else { byte };
                index >= 8 || (value.get_consume() >> (index * 8)) & 0xff != 0
            };
            if demanded { first.get_or_insert(byte); }
            else if let Some(start) = first.take() {
                result.reads.push((value.get_addr() + start as i64, byte - start));
            }
        }
    }
    result
}

pub fn has_narrow_source(proto: &FuncProto) -> bool {
    proto.has_store() && (0..proto.num_params()).any(|slot| {
        proto.source_param(slot).is_some_and(|parameter| {
            parameter.is_type_locked() && !parameter.is_hidden_return() && !parameter.is_indirect_storage()
                && parameter.get_size() < 8 && parameter.get_type().is_some_and(|ty|
                    matches!(ty.get_metatype(), type_metatype::TYPE_INT | type_metatype::TYPE_UINT
                        | type_metatype::TYPE_ENUM_INT | type_metatype::TYPE_ENUM_UINT | type_metatype::TYPE_BOOL))
        })
    })
}

/// Do not let a source `_Bool` seed erase noncanonical machine byte values
/// before consumed-bit analysis can see them. This changes no storage width and
/// promotes no undeclared input; the authentic boolean descriptor stays intact.
pub fn prepare_boolean_inputs(data: &mut Funcdata) -> KunaResult<()> {
    if !data.get_func_proto().has_store() { return Ok(()); }
    let Some(requirements) = data.entry_physical_requirements().cloned() else { return Ok(()) };
    let arch = data.get_arch().clone();
    let Some(factory) = arch.types() else { return Ok(()) };
    let count = data.get_func_proto().num_params();
    for slot in 0..count {
        let Some(source) = data.get_func_proto().source_param(slot) else { continue };
        if !source.is_type_locked() || !source.get_type().is_some_and(|ty| ty.get_metatype() == type_metatype::TYPE_BOOL) {
            continue;
        }
        let addr = source.get_address();
        let size = source.get_size();
        let observed = requirements.reads.iter().any(|(at, bytes)| {
            at.get_space().zip(addr.get_space()).is_some_and(|(a, b)| Rc::ptr_eq(a, b))
                && at.get_offset() < addr.get_offset() + size as u64
                && addr.get_offset() < at.get_offset() + *bytes as u64
        });
        if observed && data.get_func_proto().get_param(slot).is_some_and(|parameter| parameter.get_size() == size) {
            data.get_func_proto_mut().install_execution_input_type(slot, factory.get_base(size, type_metatype::TYPE_UINT)?)?;
        }
    }
    Ok(())
}

/// Choose a real register carrier only for observed bytes outside the source.
/// Other slots bound the carrier, even when one wider architectural read spans
/// both slots. No default ABI reallocation occurs.
pub fn apply_requirements(
    proto: &mut FuncProto, requirements: &EntryRequirements,
    manager: &kuna_base::space::AddrSpaceManager, factory: &dyn TypeFactory,
) -> KunaResult<bool> {
    if !proto.has_store() || !proto.is_input_locked() { return Ok(false); }
    let Some(registers) = manager.register_lookup() else { return Ok(false) };
    let mut changed = false;
    for slot in 0..proto.num_params() {
        let Some(source) = proto.source_param(slot) else { continue };
        let source_addr = source.get_address();
        let source_size = source.get_size();
        let Some(space) = source_addr.get_space() else { continue };
        let boolean_read = source.get_type().is_some_and(|ty| ty.get_metatype() == type_metatype::TYPE_BOOL)
            && requirements.reads.iter().any(|(at, bytes)| {
                at.get_space().is_some_and(|other| Rc::ptr_eq(space, other))
                    && at.get_offset() < source_addr.get_offset() + source_size as u64
                    && source_addr.get_offset() < at.get_offset() + *bytes as u64
            });
        if !source.is_type_locked() || source_size <= 0 || source_size >= 8
            || source.is_hidden_return() || source.is_indirect_storage()
            || !source.get_type().is_some_and(|ty| matches!(ty.get_metatype(),
                type_metatype::TYPE_INT | type_metatype::TYPE_UINT | type_metatype::TYPE_ENUM_INT
                | type_metatype::TYPE_ENUM_UINT | type_metatype::TYPE_BOOL))
        { continue; }
        let current = proto.get_param(slot).expect("existing physical slot");
        let mut selected = (current.get_address(), current.get_size());
        for (read, bytes) in &requirements.reads {
            if !read.get_space().is_some_and(|other| Rc::ptr_eq(space, other)) { continue; }
            let read_start = read.get_offset();
            let read_end = read_start + *bytes as u64;
            let mut boundaries = vec![read_start, read_end];
            for other in (0..proto.num_params()).filter(|other| *other != slot) {
                let parameter = proto.get_param(other).expect("existing physical slot");
                let at = parameter.get_address();
                if at.get_space().is_some_and(|other| Rc::ptr_eq(space, other)) {
                    boundaries.push(at.get_offset().clamp(read_start, read_end));
                    boundaries.push((at.get_offset() + parameter.get_size() as u64).clamp(read_start, read_end));
                }
            }
            boundaries.sort_unstable();
            boundaries.dedup();
            for piece in boundaries.windows(2) {
                let owned = (0..proto.num_params()).filter(|other| *other != slot).any(|other| {
                    let parameter = proto.get_param(other).expect("existing physical slot");
                    let at = parameter.get_address();
                    at.get_space().is_some_and(|other| Rc::ptr_eq(space, other))
                        && at.get_offset() <= piece[0]
                        && at.get_offset() + parameter.get_size() as u64 >= piece[1]
                });
                if owned { continue; }
                let start = selected.0.get_offset().min(piece[0]);
                let end = (selected.0.get_offset() + selected.1 as u64).max(piece[1]);
                if end - start > 8 { continue; }
                let name = registers.get_register_name(space, start, (end - start) as int4);
                if name.is_empty() { continue; }
                let storage = registers.get_register(&name)?;
                let Some(container_space) = storage.space else { continue };
                if !Rc::ptr_eq(space, &container_space) || storage.size > 8
                    || storage.offset > start || storage.offset + (storage.size as u64) < end
                { continue; }
                let container_end = storage.offset + storage.size as u64;
                let overlaps = (0..proto.num_params()).filter(|other| *other != slot).any(|other| {
                    let parameter = proto.get_param(other).expect("existing physical slot");
                    let at = parameter.get_address();
                    at.get_space().is_some_and(|other| Rc::ptr_eq(space, other))
                        && at.get_offset() < container_end
                        && storage.offset < at.get_offset() + parameter.get_size() as u64
                });
                if !overlaps {
                    selected = (Address::new(container_space, storage.offset), storage.size as int4);
                }
            }
        }
        if selected.1 > source_size {
            changed |= proto.install_input_carrier(slot, &selected.0, selected.1, factory)?;
        } else if boolean_read {
            changed |= proto.install_execution_input_type(slot, factory.get_base(source_size, type_metatype::TYPE_UINT)?)?;
        }
    }
    Ok(changed)
}

/// A complete observed body can have a finite execution interface even when
/// its source declaration is variadic. Unrepresented stack tails stay open.
pub fn close_finite_variadic_inputs(
    proto: &mut FuncProto, raw: &EntryRequirements,
    manager: &kuna_base::space::AddrSpaceManager,
) -> KunaResult<bool> {
    if !proto.has_store() || !proto.has_model() || !proto.is_input_locked()
        || !proto.is_dotdotdot() || !raw.is_complete() { return Ok(false); }
    let Some(registers) = manager.register_lookup() else { return Ok(false) };
    let Some(stack) = manager.get_stack_space() else { return Ok(false) };
    if stack.num_spacebase() == 0 { return Ok(false); }
    for (read, bytes) in &raw.reads {
        if *bytes <= 0 { return Ok(false); }
        if raw.is_bookkeeping(read, *bytes) { continue; }
        let Some(space) = read.get_space() else { return Ok(false) };
        let Some(end) = read.get_offset().checked_add(*bytes as u64) else { return Ok(false) };
        for index in 0..stack.num_spacebase() {
            let root = stack.get_spacebase(index)?;
            if root.space.as_ref().is_some_and(|base| Rc::ptr_eq(base, space))
                && root.offset < end && read.get_offset() < root.offset.saturating_add(root.size as u64) {
                return Ok(false);
            }
        }
        let covered = (0..proto.num_params()).filter_map(|slot| proto.source_param(slot)).any(|param| {
            let at = param.get_address();
            at.get_space().is_some_and(|other| Rc::ptr_eq(space, other))
                && at.get_offset() <= read.get_offset()
                && at.get_offset().saturating_add(param.get_size().max(0) as u64) >= end
        });
        if covered { continue; }
        if space.get_name() != "register" || *bytes > 8 { return Ok(false); }
        let name = registers.get_register_name(space, read.get_offset(), *bytes);
        if name.is_empty() { return Ok(false); }
        let storage = registers.get_register(&name)?;
        let Some(at) = storage.space else { return Ok(false) };
        if !Rc::ptr_eq(&at, space) || storage.size <= 0 || storage.size > 8
            || storage.offset > read.get_offset() || storage.offset.saturating_add(storage.size as u64) < end
            || !proto.model().possible_input_param(&Address::new(at, storage.offset), storage.size as int4) {
            return Ok(false);
        }
    }
    Ok(proto.close_execution_inputs())
}

/// Materialize finite model-valid execution inputs. Own entries use consumed SSA
/// demand; canonical call adapters may deliberately carry conservative raw reads
/// and discard unused inputs when adapting to the target's final SSA interface.
pub fn apply_ssa_requirements(
    proto: &mut FuncProto, requirements: &EntryRequirements,
    manager: &kuna_base::space::AddrSpaceManager, factory: &dyn TypeFactory,
) -> KunaResult<bool> {
    let mut changed = apply_requirements(proto, requirements, manager, factory)?;
    if !proto.has_store() || !proto.has_model() || !proto.is_input_locked() || proto.is_dotdotdot() {
        return Ok(changed);
    }
    let Some(registers) = manager.register_lookup() else { return Ok(changed) };
    for (read, bytes) in &requirements.reads {
        if *bytes <= 0 || *bytes > 8 { continue; }
        if requirements.is_bookkeeping(read, *bytes) { continue; }
        let Some(space) = read.get_space() else { continue };
        let read_end = read.get_offset() + *bytes as u64;
        let mut covered_end = read.get_offset();
        loop {
            let next = (0..proto.num_params()).filter_map(|slot| {
                let parameter = proto.get_param(slot).expect("existing input");
                let at = parameter.get_address();
                (at.get_space().is_some_and(|other| Rc::ptr_eq(space, other))
                    && at.get_offset() <= covered_end)
                    .then_some(at.get_offset() + parameter.get_size() as u64)
            }).max().unwrap_or(covered_end);
            if next <= covered_end || next >= read_end { covered_end = next; break; }
            covered_end = next;
        }
        if covered_end >= read_end { continue; }
        let name = registers.get_register_name(space, read.get_offset(), *bytes);
        if name.is_empty() { continue; }
        let storage = registers.get_register(&name)?;
        let Some(container_space) = storage.space else { continue };
        let address = Address::new(container_space, storage.offset);
        let size = storage.size as int4;
        if size <= 0 || size > 8 || !proto.model().possible_input_param(&address, size) { continue; }
        changed |= proto.install_physical_only_input(&address, size, factory)?;
    }
    Ok(changed)
}
