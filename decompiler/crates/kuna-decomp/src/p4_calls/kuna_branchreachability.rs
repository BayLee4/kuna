//! Candidate-private certificates for an optimizer-proved raw entry edge cut.
//! This module records existing successful rewrites; it never evaluates p-code.
use std::cell::RefCell;
use std::collections::BTreeMap;
use std::rc::Rc;

use kuna_base::address::Address;
use kuna_base::error::{KunaError, KunaResult};
use kuna_base::types::int4;
use kuna_num::opcodes::OpCode;
use crate::context::{BlockId, OpId, VarnodeId};
use crate::funcdata::Funcdata;
use crate::fspec::FuncProto;
use crate::varnode::varnode_flags;

#[cfg(feature = "test-support")]
#[path = "kuna_branchreachability/replay_tests.rs"]
pub(crate) mod replay_tests;

const MAX_PREFIX_OPS: usize = 128;
const MAX_INPUTS: usize = 4;
const MAX_FACTS: usize = 16;

// SeqNum::PartialEq compares time alone. Replay must also compare full Address.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct StableOpKey {
    pub(crate) address: Address,
    pub(crate) time: u32,
}
impl StableOpKey {
    pub(crate) fn of(fd: &Funcdata, op: OpId) -> Option<Self> {
        let op = fd.obank().get(op)?;
        Some(Self { address: op.get_addr().clone(), time: op.get_time() })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CertifiedEdgeCut {
    branch: StableOpKey,
    from_start: StableOpKey,
    edge: usize,
    to_start: StableOpKey,
}
impl CertifiedEdgeCut {
    pub(crate) fn branch(&self) -> &StableOpKey { &self.branch }
    pub(crate) fn from_start(&self) -> &StableOpKey { &self.from_start }
    pub(crate) fn edge(&self) -> usize { self.edge }
    pub(crate) fn to_start(&self) -> &StableOpKey { &self.to_start }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Storage {
    address: Address,
    size: int4,
    constant: bool,
}
impl Storage {
    fn of(fd: &Funcdata, id: VarnodeId) -> Option<Self> {
        let v = fd.vbank().get(id)?;
        Some(Self { address: v.get_addr().clone(), size: v.get_size(), constant: v.is_constant() })
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
struct Operand {
    id: VarnodeId,
    storage: Storage,
    definition: Option<OpId>,
}
impl Operand {
    fn of(fd: &Funcdata, id: VarnodeId) -> Option<Self> {
        Some(Self { id, storage: Storage::of(fd, id)?, definition: fd.vbank().get(id)?.get_def() })
    }
    // Only an admitted COPY transaction can use this for a canonical constant clone.
    fn same_value(&self, other: &Self) -> bool {
        self == other || (self.storage.constant && other.storage.constant && self.storage == other.storage)
    }
    fn matches(&self, fd: &Funcdata, id: VarnodeId) -> bool {
        id == self.id && fd.vbank().get(id).is_some_and(|value| {
            value.get_addr() == &self.storage.address && value.get_size() == self.storage.size
                && value.is_constant() == self.storage.constant && value.get_def() == self.definition
        })
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
struct Operation {
    key: StableOpKey,
    code: OpCode,
    inputs: Vec<Operand>,
    output: Option<Operand>,
    flip: bool,
    fallthrough_true: bool,
}
impl Operation {
    fn of(fd: &Funcdata, id: OpId) -> Option<Self> {
        let op = fd.obank().get(id)?;
        if op.num_input() < 0 || op.num_input() as usize > MAX_INPUTS { return None; }
        let inputs = (0..op.num_input()).map(|slot| Operand::of(fd, op.get_in(slot)?)).collect::<Option<Vec<_>>>()?;
        Some(Self {
            key: StableOpKey::of(fd, id)?, code: op.code(), inputs,
            output: match op.get_out() { None => None, Some(id) => Some(Operand::of(fd, id)?) },
            flip: op.is_boolean_flip(), fallthrough_true: op.is_fallthru_true(),
        })
    }
    fn same_identity(&self, other: &Self) -> bool {
        self.key == other.key && self.output == other.output
    }
    fn matches(&self, fd: &Funcdata, id: OpId) -> bool {
        let Some(op) = fd.obank().get(id) else { return false; };
        op.get_addr() == &self.key.address && op.get_time() == self.key.time && op.code() == self.code
            && op.is_boolean_flip() == self.flip && op.is_fallthru_true() == self.fallthrough_true
            && op.num_input() as usize == self.inputs.len()
            && self.inputs.iter().enumerate().all(|(slot, value)|
                op.get_in(slot as int4).is_some_and(|id| value.matches(fd, id)))
            && match (&self.output, op.get_out()) {
                (None, None) => true,
                (Some(value), Some(id)) => value.matches(fd, id),
                _ => false,
            }
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
struct RawOperation {
    key: StableOpKey,
    code: OpCode,
    inputs: Vec<Storage>,
    output: Option<Storage>,
    flip: bool,
    fallthrough_true: bool,
}
impl From<&Operation> for RawOperation {
    fn from(op: &Operation) -> Self {
        Self { key: op.key.clone(), code: op.code,
            inputs: op.inputs.iter().map(|v| v.storage.clone()).collect(),
            output: op.output.as_ref().map(|v| v.storage.clone()),
            flip: op.flip, fallthrough_true: op.fallthrough_true }
    }
}

struct SourceContext {
    prototype: FuncProto,
    overrides: BTreeMap<Address, PrefixOverride>,
}
struct PrefixOverride {
    flow: u32,
    indirect: Option<Address>,
    prototype: Option<FuncProto>,
    force_goto: Option<Address>,
    multistage: bool,
}
impl SourceContext {
    fn capture(fd: &Funcdata, prefix: &[RawOperation]) -> Self {
        let mut overrides = BTreeMap::new();
        for op in prefix {
            let address = &op.key.address;
            if overrides.contains_key(address) { continue; }
            let ov = fd.get_override();
            overrides.insert(address.clone(), PrefixOverride {
                flow: ov.get_flow_override(address),
                indirect: ov.find_indirect_override(address).cloned(),
                prototype: ov.find_proto_override(address).map(FuncProto::source_prototype),
                force_goto: ov.force_gotos().find(|(from, _)| *from == address).map(|(_, to)| to.clone()),
                multistage: ov.query_multistage_jumptable(address),
            });
        }
        Self { prototype: fd.get_func_proto().source_prototype(), overrides }
    }
    fn matches(&self, fd: &Funcdata) -> bool {
        let actual = fd.get_func_proto().source_prototype();
        let a = &self.prototype;
        let b = &actual;
        if a.has_model() != b.has_model() || a.logical_callable() != b.logical_callable()
            || a.is_input_locked() != b.is_input_locked() || a.is_output_locked() != b.is_output_locked()
            || a.is_model_locked() != b.is_model_locked() || a.is_override() != b.is_override()
            || a.has_custom_storage() != b.has_custom_storage() || a.get_inject_id() != b.get_inject_id()
            || a.is_inline() != b.is_inline() || a.is_no_return() != b.is_no_return()
            || (a.has_model() && !Rc::ptr_eq(a.model(), b.model())) { return false; }
        if a.is_input_locked() && (a.num_params() != b.num_params()
            || a.is_dotdotdot() != b.is_dotdotdot() || a.get_abi_first_vararg() != b.get_abi_first_vararg()
            || !(0..a.num_params()).all(|slot| a.source_param(slot).zip(b.source_param(slot))
                .is_some_and(|(a, b)| crate::fspec::proto_parameter_eq(a, b)
                    && a.get_size() == b.get_size() && a.get_flags() == b.get_flags()))) { return false; }
        if a.is_output_locked() && (!crate::fspec::proto_parameter_eq(a.source_output(), b.source_output())
            || a.source_output().get_flags() != b.source_output().get_flags()
            || a.source_output().get_size() != b.source_output().get_size()) { return false; }
        let ov = fd.get_override();
        self.overrides.iter().all(|(address, saved)| {
            saved.flow == ov.get_flow_override(address)
                && saved.indirect.as_ref() == ov.find_indirect_override(address)
                && saved.force_goto.as_ref() == ov.force_gotos().find(|(from, _)| *from == address).map(|(_, to)| to)
                && saved.multistage == ov.query_multistage_jumptable(address)
                && match (&saved.prototype, ov.find_proto_override(address)) {
                    (None, None) => true,
                    (Some(a), Some(b)) => crate::p4_calls::kuna_callabletransport::native_source_abi_equal(a, b),
                    _ => false,
                }
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct TrackedFact { storage: Storage, value: u64 }
impl TrackedFact {
    fn matches(&self, fd: &Funcdata) -> bool {
        let mut matches = fd.get_arch().get_tracked_set(fd.get_address()).iter().filter(|ctx| {
            ctx.loc.space.as_ref().is_some_and(|space| {
                self.storage.address == Address::new(space.clone(), ctx.loc.offset)
                    && self.storage.size == ctx.loc.size as int4
            })
        });
        matches.next().is_some_and(|ctx| ctx.val == self.value) && matches.next().is_none()
    }
}
struct ReadonlyFact {
    address: Address,
    size: int4,
    bytes: [u8; 8],
    endian: bool,
    policy: bool,
    dynreloc: bool,
    litpool: bool,
    properties: u32,
    loader: Rc<RefCell<Box<dyn kuna_sleigh::loadimage::LoadImage>>>,
}
impl ReadonlyFact {
    fn capture(fd: &Funcdata, memory: VarnodeId, bytes: &[u8]) -> Option<Self> {
        let value = fd.vbank().get(memory)?;
        let size = value.get_size();
        if !(1..=8).contains(&size) || bytes.len() != size as usize || !value.is_read_only()
            || value.is_volatile() || value.is_external_ref() || value.is_written() { return None; }
        let arch = fd.get_arch();
        let address = value.get_addr().clone();
        let policy = arch.readonly_propagate();
        let dynreloc = arch.dynreloc_const_contains(address.get_offset());
        let litpool = arch.litpool_const_contains(address.get_offset(), size as u32);
        if !policy && !dynreloc && !litpool { return None; }
        let properties = memory_properties(fd, &address, size);
        if properties & varnode_flags::readonly == 0
            || properties & (varnode_flags::volatil | varnode_flags::externref) != 0 { return None; }
        let mut stored = [0; 8];
        stored[..bytes.len()].copy_from_slice(bytes);
        Some(Self { address, size, bytes: stored, endian: value.get_space().is_big_endian(),
            policy, dynreloc, litpool, properties, loader: arch.loader.as_ref()?.clone() })
    }
    fn matches(&self, fd: &Funcdata) -> bool {
        let arch = fd.get_arch();
        if !arch.loader.as_ref().is_some_and(|loader| Rc::ptr_eq(loader, &self.loader))
            || arch.readonly_propagate() != self.policy
            || arch.dynreloc_const_contains(self.address.get_offset()) != self.dynreloc
            || arch.litpool_const_contains(self.address.get_offset(), self.size as u32) != self.litpool
            || self.address.get_space().is_none_or(|s| s.is_big_endian() != self.endian)
            || memory_properties(fd, &self.address, self.size) != self.properties { return false; }
        let mut bytes = [0; 8];
        arch.loader_fill(&mut bytes[..self.size as usize], &self.address).is_ok()
            && bytes[..self.size as usize] == self.bytes[..self.size as usize]
    }
}
fn memory_properties(fd: &Funcdata, address: &Address, size: int4) -> u32 {
    let point = Address::new_invalid();
    (fd.query_local_properties(address, size, &point)
        | fd.get_arch().query_global_properties(address, size, &point))
        & (varnode_flags::readonly | varnode_flags::volatil | varnode_flags::externref)
}

// Opaque and immutable: only finish_branch constructs this object.
pub(crate) struct BranchReplay {
    entry: Address,
    raw: Vec<RawOperation>,
    source: SourceContext,
    tracked: Vec<TrackedFact>,
    readonly: Vec<ReadonlyFact>,
    successors: [StableOpKey; 2],
    cut: CertifiedEdgeCut,
}
impl BranchReplay {
    fn facts_match(&self, fd: &Funcdata) -> bool {
        self.entry == *fd.get_address() && self.source.matches(fd)
            && self.tracked.iter().all(|fact| fact.matches(fd))
            && self.readonly.iter().all(|fact| fact.matches(fd))
    }
}

struct Candidate {
    branch: OpId,
    block: BlockId,
    raw: Vec<RawOperation>,
    source: SourceContext,
    expected: BTreeMap<OpId, Operation>,
    tracked: Vec<TrackedFact>,
    readonly: Vec<ReadonlyFact>,
    materialized: BTreeMap<VarnodeId, OpId>,
    successors: [StableOpKey; 2],
    successor_blocks: [BlockId; 2],
    edge_order: [usize; 2],
    bound: bool,
}
// Retain provisional obligations if a failed transaction drops the live candidate.
pub(crate) struct BranchFacts {
    candidate: Option<Box<Candidate>>,
    replayed: Option<Rc<BranchReplay>>,
    completed: Option<Rc<BranchReplay>>,
    cuts: Vec<CertifiedEdgeCut>,
}

fn block_start(fd: &Funcdata, block: BlockId) -> Option<StableOpKey> {
    StableOpKey::of(fd, *fd.bb_ops(block).first()?)
}
fn raw_candidate(fd: &Funcdata) -> Option<Box<Candidate>> {
    if fd.bblocks_get_size() == 0 { return None; }
    let block = fd.bblocks_get_block(0);
    if fd.bblocks_ref().block(block).size_out() != 2 { return None; }
    let branch = fd.bb_op_tail(block)?;
    if fd.obank().get(branch)?.code() != OpCode::CPUI_CBRANCH { return None; }
    let ops = fd.bb_ops(block);
    if ops.len() > MAX_PREFIX_OPS || ops.iter().any(|id| fd.obank().get(*id).is_none_or(|o|
        matches!(o.code(), OpCode::CPUI_CALL | OpCode::CPUI_CALLIND | OpCode::CPUI_CALLOTHER))) { return None; }
    let expected = ops.iter().map(|&id| Some((id, Operation::of(fd, id)?))).collect::<Option<BTreeMap<_, _>>>()?;
    // Some translators encode an absolute memory read as COPY from a real
    // data-space varnode, rather than LOAD(space, constant). Retain that exact
    // raw operand as already materialized; only the existing readonly setter
    // transaction can turn it into a loader/policy/property fact below.
    let mut materialized = BTreeMap::new();
    if let Some(data_space) = fd.get_arch().manage().get_default_data_space() {
        for (&id, operation) in &expected {
            if operation.code != OpCode::CPUI_COPY || operation.inputs.len() != 1 { continue; }
            let memory = &operation.inputs[0];
            if memory.storage.constant || memory.definition.is_some()
                || memory.storage.size <= 0 || memory.storage.size > 8
                || operation.output.as_ref().is_none_or(|output| output.storage.size != memory.storage.size)
                || !memory.storage.address.get_space().is_some_and(|space| Rc::ptr_eq(space, data_space))
            { continue; }
            if materialized.len() == MAX_FACTS || materialized.insert(memory.id, id).is_some() { return None; }
        }
    }
    if materialized.is_empty() && !expected.values().any(|operation| operation.code == OpCode::CPUI_LOAD) { return None; }
    let raw: Vec<_> = ops.iter().map(|id| RawOperation::from(&expected[id])).collect();
    let source = SourceContext::capture(fd, &raw);
    let successors = [block_start(fd, fd.bblocks_ref().block(block).get_out(0))?,
        block_start(fd, fd.bblocks_ref().block(block).get_out(1))?];
    let successor_blocks = [fd.bblocks_ref().block(block).get_out(0), fd.bblocks_ref().block(block).get_out(1)];
    Some(Box::new(Candidate { branch, block, raw, source, expected, tracked: Vec::new(), readonly: Vec::new(),
        materialized, successors, successor_blocks, edge_order: [0, 1], bound: false }))
}

pub(crate) fn seed_raw(fd: &mut Funcdata, replays: &[Rc<BranchReplay>]) -> KunaResult<()> {
    fd.branch_reachability = None;
    if replays.len() > 1 { return Err(KunaError::lowlevel("Multiple entry branch replay certificates")); }
    let Some(candidate) = raw_candidate(fd) else {
        return if replays.is_empty() { Ok(()) } else { Err(KunaError::lowlevel("Entry branch replay lost its raw prefix")) };
    };
    let mut cuts = Vec::new();
    let replayed = replays.first().cloned();
    if let Some(replay) = &replayed {
        if candidate.raw != replay.raw || candidate.successors != replay.successors || !replay.facts_match(fd)
            || StableOpKey::of(fd, candidate.branch).as_ref() != Some(&replay.cut.branch)
            || block_start(fd, candidate.block).as_ref() != Some(&replay.cut.from_start)
            || replay.cut.edge >= 2 || candidate.successors[replay.cut.edge] != replay.cut.to_start {
            return Err(KunaError::lowlevel("Entry branch replay premises changed"));
        }
        cuts.push(replay.cut.clone());
    }
    fd.branch_reachability = Some(Box::new(BranchFacts { candidate: Some(candidate), replayed, completed: None, cuts }));
    Ok(())
}
pub(crate) fn completed_replays(fd: &Funcdata) -> Vec<Rc<BranchReplay>> {
    fd.branch_reachability.as_ref().and_then(|s| s.completed.clone()).into_iter().collect()
}
pub(crate) fn certified_cuts(fd: &Funcdata) -> &[CertifiedEdgeCut] {
    fd.branch_reachability.as_ref().map_or(&[], |s| s.cuts.as_slice())
}
pub(crate) fn has_candidate(fd: &Funcdata) -> bool {
    fd.branch_reachability.as_ref().is_some_and(|s| s.candidate.is_some())
}
pub(crate) fn validate_final(fd: &Funcdata) -> KunaResult<()> {
    let Some(state) = &fd.branch_reachability else { return Ok(()); };
    if let Some(required) = &state.replayed {
        let Some(actual) = &state.completed else {
            return Err(KunaError::lowlevel("Replayed entry branch has no current optimizer decision"));
        };
        if required.cut != actual.cut || required.raw != actual.raw || !required.facts_match(fd) || !actual.facts_match(fd) {
            return Err(KunaError::lowlevel("Final entry branch replay premises changed"));
        }
    }
    Ok(())
}

impl Candidate {
    fn matches_op(&self, fd: &Funcdata, op: OpId) -> bool {
        self.expected.get(&op).is_some_and(|saved| saved.matches(fd, op))
    }
    fn edges_match(&self, fd: &Funcdata) -> bool {
        fd.obank().get(self.branch).and_then(|op| op.get_parent()) == Some(self.block)
            && fd.bb_op_tail(self.block) == Some(self.branch)
            && fd.bblocks_ref().block(self.block).size_out() == 2
            && (0..2).all(|edge| fd.bblocks_ref().block(self.block).get_out(edge as int4)
                == self.successor_blocks[self.edge_order[edge]])
    }
    // Follow actual Heritage bindings, never infer reaching definitions by storage.
    // This also detects unsupported mutations before an admitted transaction.
    fn bind_and_prune(&mut self, fd: &Funcdata) -> bool {
        let mut nodes = [None; MAX_PREFIX_OPS];
        nodes[0] = Some(self.branch);
        let (mut cursor, mut count) = (0, 1);
        while cursor < count {
            let id = nodes[cursor].expect("bounded branch queue");
            cursor += 1;
            if !self.matches_op(fd, id) { return false; }
            let op = &self.expected[&id];
            for (slot, input) in op.inputs.iter().enumerate() {
                if (id == self.branch && slot == 0) || input.storage.constant { continue; }
                if self.materialized.contains_key(&input.id) { continue; }
                let Some(definition) = input.definition else { return false; };
                if !self.expected.get(&definition).is_some_and(|def| def.output.as_ref() == Some(input)) {
                    return false;
                }
                if !nodes[..count].contains(&Some(definition)) {
                    if count == MAX_PREFIX_OPS { return false; }
                    nodes[count] = Some(definition);
                    count += 1;
                }
            }
        }
        self.expected.retain(|id, _| nodes[..count].contains(&Some(*id)));
        self.bound = true;
        true
    }
}

fn put(fd: &mut Funcdata, candidate: Box<Candidate>) {
    if let Some(state) = fd.branch_reachability.as_mut() { state.candidate = Some(candidate); }
}
fn take(fd: &mut Funcdata, root: OpId, bind: bool) -> Option<Box<Candidate>> {
    let mut candidate = fd.branch_reachability.as_mut()?.candidate.take()?;
    if bind && !candidate.bind_and_prune(fd) { return None; }
    if !candidate.expected.contains_key(&root) {
        put(fd, candidate);
        return None;
    }
    if !candidate.matches_op(fd, root) { return None; }
    Some(candidate)
}

pub(crate) fn record_track(fd: &mut Funcdata, op: OpId, address: &Address, size: int4, value: u64) {
    let Some(mut candidate) = fd.branch_reachability.as_mut().and_then(|s| s.candidate.take()) else { return; };
    let Some(actual) = Operation::of(fd, op) else { return; };
    let fact = TrackedFact { storage: Storage { address: address.clone(), size, constant: false }, value };
    if candidate.bound || candidate.expected.len() >= MAX_PREFIX_OPS || candidate.tracked.len() >= MAX_FACTS
        || actual.code != OpCode::CPUI_COPY || actual.inputs.len() != 1
        || !actual.inputs[0].storage.constant || actual.inputs[0].storage.size != size
        || actual.inputs[0].storage.address.get_offset() != value
        || actual.output.as_ref().is_none_or(|out| out.storage != fact.storage)
        || fd.obank().get(op).and_then(|o| o.get_parent()) != Some(candidate.block)
        || actual.key.address != candidate.raw[0].key.address || !fact.matches(fd) { return; }
    candidate.expected.insert(op, actual);
    candidate.tracked.push(fact);
    put(fd, candidate);
}

enum Rewrite {
    Heritage { slot: usize, new: Operand },
    Copy { slot: usize, source: Operand },
    Identity,
    Subtract,
    EqualZero { positive: Operand, unnegated: Operand },
    Shift { result: u64 },
    Collapse { result: u64 },
    Reassociate { source: OpId, result: u64 },
    Collect { slots: Vec<(OpId, usize)>, target: (OpId, usize), result: u64 },
    Load { memory: VarnodeId },
    Readonly { memory: VarnodeId, fact: ReadonlyFact, result: u64 },
    Invert,
    Normalize { condition: OpId },
}
// Taking the candidate starts the transaction. An early return/error drops it;
// provisional replay obligations remain in BranchFacts and fail final validation.
pub(crate) struct RewriteTxn { candidate: Box<Candidate>, root: OpId, rewrite: Rewrite }

pub(crate) fn begin_heritage(fd: &mut Funcdata, op: OpId, old: VarnodeId, new: VarnodeId, slot: int4) -> Option<RewriteTxn> {
    let candidate = take(fd, op, false)?;
    let slot = usize::try_from(slot).ok()?;
    if candidate.expected[&op].inputs.get(slot)?.id != old { return None; }
    let new = Operand::of(fd, new)?;
    if new.storage != candidate.expected[&op].inputs[slot].storage
        || new.definition.is_some_and(|definition| !candidate.expected.contains_key(&definition)) { return None; }
    Some(RewriteTxn { candidate, root: op, rewrite: Rewrite::Heritage { slot, new } })
}

pub(crate) fn begin_copy(fd: &mut Funcdata, op: OpId, slot: int4, source: OpId) -> Option<RewriteTxn> {
    let candidate = take(fd, op, true)?;
    let slot = usize::try_from(slot).ok()?;
    if !candidate.matches_op(fd, source) { return None; }
    let copy = &candidate.expected[&source];
    if copy.code != OpCode::CPUI_COPY || copy.inputs.len() != 1
        || candidate.expected[&op].inputs.get(slot) != copy.output.as_ref() { return None; }
    let source = copy.inputs[0].clone();
    Some(RewriteTxn { candidate, root: op, rewrite: Rewrite::Copy { slot, source } })
}

pub(crate) fn begin_identity(fd: &mut Funcdata, op: OpId) -> Option<RewriteTxn> {
    let candidate = take(fd, op, true)?;
    let old = &candidate.expected[&op];
    if old.inputs.len() != 2 || !old.inputs[1].storage.constant || old.inputs[1].storage.address.get_offset() != 0
        || !matches!(old.code, OpCode::CPUI_INT_ADD | OpCode::CPUI_INT_XOR | OpCode::CPUI_INT_OR
            | OpCode::CPUI_BOOL_XOR | OpCode::CPUI_BOOL_OR) { return None; }
    Some(RewriteTxn { candidate, root: op, rewrite: Rewrite::Identity })
}

pub(crate) fn begin_subtract(fd: &mut Funcdata, op: OpId) -> Option<RewriteTxn> {
    let candidate = take(fd, op, true)?;
    let old = &candidate.expected[&op];
    let size = old.output.as_ref()?.storage.size;
    if old.code != OpCode::CPUI_INT_SUB || old.inputs.len() != 2 || !(1..=8).contains(&size)
        || old.inputs.iter().any(|input| input.storage.size != size)
        || candidate.expected.len() == MAX_PREFIX_OPS { return None; }
    Some(RewriteTxn { candidate, root: op, rewrite: Rewrite::Subtract })
}

pub(crate) fn begin_equal_zero(fd: &mut Funcdata, op: OpId,
    positive: VarnodeId, unnegated: VarnodeId) -> Option<RewriteTxn>
{
    let candidate = take(fd, op, true)?;
    let old = &candidate.expected[&op];
    if !matches!(old.code, OpCode::CPUI_INT_EQUAL | OpCode::CPUI_INT_NOTEQUAL) || old.inputs.len() != 2 { return None; }
    let size = old.inputs[0].storage.size;
    if !(1..=8).contains(&size) || old.inputs[1].storage.size != size { return None; }
    let sum = if literal(&old.inputs[0], size, 0) { &old.inputs[1] }
        else if literal(&old.inputs[1], size, 0) { &old.inputs[0] } else { return None; };
    let addition = sum.definition?;
    if !candidate.matches_op(fd, addition) { return None; }
    let add = &candidate.expected[&addition];
    if add.code != OpCode::CPUI_INT_ADD || add.inputs.len() != 2 || add.output.as_ref() != Some(sum)
        || add.inputs.iter().any(|input| input.storage.size != size) { return None; }
    let positive = Operand::of(fd, positive)?;
    let unnegated = Operand::of(fd, unnegated)?;
    if add.inputs[1].storage.constant {
        // The existing rule supplies its computed negative constant; as with
        // collapse receipts, this module records it rather than evaluating it.
        if !positive.same_value(&add.inputs[0]) || !unnegated.storage.constant
            || unnegated.storage.size != size { return None; }
    } else {
        let negated_slot = if positive.same_value(&add.inputs[1]) { 0 }
            else if positive.same_value(&add.inputs[0]) { 1 } else { return None; };
        let negated = &add.inputs[negated_slot];
        let multiply = negated.definition?;
        if !candidate.matches_op(fd, multiply) { return None; }
        let multiply = &candidate.expected[&multiply];
        if multiply.code != OpCode::CPUI_INT_MULT || multiply.inputs.len() != 2
            || multiply.output.as_ref() != Some(negated) || multiply.inputs[0].storage.size != size
            || !literal(&multiply.inputs[1], size, kuna_base::address::calc_mask(size))
            || !unnegated.same_value(&multiply.inputs[0]) { return None; }
    }
    Some(RewriteTxn { candidate, root: op, rewrite: Rewrite::EqualZero { positive, unnegated } })
}

pub(crate) fn begin_shift(fd: &mut Funcdata, op: OpId, result: u64) -> Option<RewriteTxn> {
    let candidate = take(fd, op, true)?;
    let old = &candidate.expected[&op];
    if old.code != OpCode::CPUI_INT_LEFT || old.inputs.len() != 2 || !old.inputs[1].storage.constant { return None; }
    Some(RewriteTxn { candidate, root: op, rewrite: Rewrite::Shift { result } })
}

pub(crate) fn begin_collapse(fd: &mut Funcdata, op: OpId, result: u64) -> Option<RewriteTxn> {
    let candidate = take(fd, op, true)?;
    let old = &candidate.expected[&op];
    if old.inputs.is_empty() || !old.inputs.iter().all(|input| input.storage.constant)
        || !matches!(old.code, OpCode::CPUI_INT_ADD | OpCode::CPUI_INT_MULT | OpCode::CPUI_INT_LEFT
            | OpCode::CPUI_INT_EQUAL | OpCode::CPUI_INT_NOTEQUAL) { return None; }
    Some(RewriteTxn { candidate, root: op, rewrite: Rewrite::Collapse { result } })
}

pub(crate) fn begin_reassociate(fd: &mut Funcdata, op: OpId, source: OpId, result: u64) -> Option<RewriteTxn> {
    let candidate = take(fd, op, true)?;
    if !candidate.matches_op(fd, source) { return None; }
    let root = &candidate.expected[&op];
    let sub = &candidate.expected[&source];
    if !matches!(root.code, OpCode::CPUI_INT_ADD | OpCode::CPUI_INT_MULT) || root.code != sub.code
        || root.inputs.len() != 2 || sub.inputs.len() != 2 || !root.inputs[1].storage.constant
        || !sub.inputs[1].storage.constant || root.inputs.first() != sub.output.as_ref()
        || root.output.as_ref()?.storage.size != sub.output.as_ref()?.storage.size { return None; }
    Some(RewriteTxn { candidate, root: op, rewrite: Rewrite::Reassociate { source, result } })
}

// The caller supplies the existing TermOrder's non-multiplied constant edges.
// It allocates that list only when a candidate is present.
pub(crate) fn begin_collect(fd: &mut Funcdata, op: OpId, slots: Vec<(OpId, usize)>,
    target: (OpId, usize), result: u64) -> Option<RewriteTxn>
{
    let candidate = take(fd, op, true)?;
    if slots.len() < 2 || slots.len() > MAX_PREFIX_OPS || !slots.contains(&target) { return None; }
    let root = &candidate.expected[&op];
    if root.code != OpCode::CPUI_INT_ADD { return None; }
    let size = root.output.as_ref()?.storage.size;
    let mut group = [None; MAX_PREFIX_OPS];
    group[0] = Some(op);
    let (mut cursor, mut count) = (0, 1);
    while cursor < count {
        let id = group[cursor]?;
        cursor += 1;
        if !candidate.matches_op(fd, id) { return None; }
        let addition = &candidate.expected[&id];
        if addition.code != OpCode::CPUI_INT_ADD || addition.inputs.len() != 2
            || addition.output.as_ref()?.storage.size != size { return None; }
        for input in &addition.inputs {
            if let Some(def) = input.definition {
                if candidate.expected.get(&def).is_some_and(|o| o.code == OpCode::CPUI_INT_ADD)
                    && !group[..count].contains(&Some(def))
                {
                    if count == MAX_PREFIX_OPS { return None; }
                    group[count] = Some(def);
                    count += 1;
                }
            }
        }
    }
    for &(id, slot) in &slots {
        if !group[..count].contains(&Some(id)) { return None; }
        let input = candidate.expected[&id].inputs.get(slot)?;
        if !input.storage.constant || input.storage.size != size { return None; }
        // Changing an interior add cannot certify a value used outside this root.
        if id != op && fd.vbank().get(candidate.expected[&id].output.as_ref()?.id)?
            .descend_iter().any(|reader| !group[..count].contains(&Some(reader))) { return None; }
    }
    Some(RewriteTxn { candidate, root: op, rewrite: Rewrite::Collect { slots, target, result } })
}

pub(crate) fn begin_load(fd: &mut Funcdata, op: OpId, memory: VarnodeId) -> Option<RewriteTxn> {
    let candidate = take(fd, op, true)?;
    let root = &candidate.expected[&op];
    let value = Operand::of(fd, memory)?;
    if root.code != OpCode::CPUI_LOAD || root.inputs.len() != 2 || !root.inputs.iter().all(|v| v.storage.constant)
        || value.storage.constant || value.definition.is_some()
        || value.storage.size != root.output.as_ref()?.storage.size
        || candidate.materialized.len() >= MAX_FACTS { return None; }
    Some(RewriteTxn { candidate, root: op, rewrite: Rewrite::Load { memory } })
}

pub(crate) fn begin_readonly(fd: &mut Funcdata, op: OpId, memory: VarnodeId, bytes: &[u8], result: u64) -> Option<RewriteTxn> {
    // VarnodeProps can fold a genuine raw memory COPY before Heritage has
    // supplied the guard's reaching definitions. Authenticate this local
    // setter now, just like tracked-input binding; never infer those missing
    // definitions. The first bound transaction and begin_branch still require
    // the complete actual Heritage closure before any edge can be certified.
    let bind = fd.get_heritage_pass() != 0;
    let candidate = take(fd, op, bind)?;
    let root = &candidate.expected[&op];
    if root.code != OpCode::CPUI_COPY || root.inputs.len() != 1 || root.inputs[0].id != memory
        || candidate.materialized.get(&memory) != Some(&op) || candidate.readonly.len() >= MAX_FACTS { return None; }
    let fact = ReadonlyFact::capture(fd, memory, bytes)?;
    Some(RewriteTxn { candidate, root: op, rewrite: Rewrite::Readonly { memory, fact, result } })
}

pub(crate) fn begin_invert(fd: &mut Funcdata, block: BlockId) -> Option<RewriteTxn> {
    let root = fd.bb_op_tail(block)?;
    let candidate = take(fd, root, true)?;
    if block != candidate.block || root != candidate.branch || !candidate.edges_match(fd) { return None; }
    Some(RewriteTxn { candidate, root, rewrite: Rewrite::Invert })
}
pub(crate) fn begin_normalize(fd: &mut Funcdata, root: OpId) -> Option<RewriteTxn> {
    let candidate = take(fd, root, true)?;
    if root != candidate.branch || !candidate.edges_match(fd) { return None; }
    let branch = &candidate.expected[&root];
    let condition = branch.inputs.get(1)?.definition?;
    if !candidate.matches_op(fd, condition) || !branch.flip
        || !matches!(candidate.expected[&condition].code, OpCode::CPUI_INT_EQUAL | OpCode::CPUI_INT_NOTEQUAL) { return None; }
    Some(RewriteTxn { candidate, root, rewrite: Rewrite::Normalize { condition } })
}

fn literal(value: &Operand, size: int4, result: u64) -> bool {
    value.storage.constant && value.storage.size == size && value.storage.address.get_offset() == result
}
fn same_except_input(before: &Operation, after: &Operation, slot: usize) -> bool {
    before.same_identity(after) && before.code == after.code && before.flip == after.flip
        && before.fallthrough_true == after.fallthrough_true && before.inputs.len() == after.inputs.len()
        && before.inputs.iter().zip(&after.inputs).enumerate().all(|(i, (a, b))| i == slot || a == b)
}

pub(crate) fn finish(fd: &mut Funcdata, transaction: Option<RewriteTxn>) {
    let Some(RewriteTxn { mut candidate, root, rewrite }) = transaction else { return; };
    let Some(actual) = Operation::of(fd, root) else { return; };
    let old = &candidate.expected[&root];
    if !old.same_identity(&actual) { return; }
    let size = old.output.as_ref().map(|out| out.storage.size);
    let successful = match rewrite {
        Rewrite::Heritage { slot, new } => same_except_input(old, &actual, slot) && actual.inputs.get(slot) == Some(&new),
        Rewrite::Copy { slot, source } => same_except_input(old, &actual, slot)
            && actual.inputs.get(slot).is_some_and(|retained| source.same_value(retained)),
        Rewrite::Identity => actual.code == OpCode::CPUI_COPY && actual.inputs.as_slice() == &old.inputs[..1]
            && actual.flip == old.flip && actual.fallthrough_true == old.fallthrough_true,
        Rewrite::Subtract => {
            let Some(size) = size else { return; };
            if actual.code != OpCode::CPUI_INT_ADD || actual.inputs.len() != 2 || actual.inputs[0] != old.inputs[0]
                || actual.flip != old.flip || actual.fallthrough_true != old.fallthrough_true { return; }
            let Some(inserted) = actual.inputs[1].definition else { return; };
            if candidate.expected.contains_key(&inserted) { return; }
            let Some(multiply) = Operation::of(fd, inserted) else { return; };
            if multiply.code != OpCode::CPUI_INT_MULT || multiply.inputs.len() != 2
                || multiply.key.address != old.key.address || multiply.output.as_ref() != actual.inputs.get(1)
                || multiply.inputs[0] != old.inputs[1]
                || !literal(&multiply.inputs[1], size, kuna_base::address::calc_mask(size))
                || multiply.flip || multiply.fallthrough_true
                || fd.obank().get(inserted).is_none_or(|operation| operation.is_dead()
                    || operation.basic_neighbours().1 != Some(root)
                    || operation.get_parent() != fd.obank().get(root).and_then(|root| root.get_parent())) { return; }
            // Retain the actual inserted definition, not an evaluated negation.
            // Its later constant fold must pass the ordinary collapse receipt.
            candidate.expected.insert(inserted, multiply);
            true
        }
        Rewrite::EqualZero { positive, unnegated } => actual.code == old.code && actual.inputs.len() == 2
            && positive.same_value(&actual.inputs[0]) && unnegated.same_value(&actual.inputs[1])
            && actual.flip == old.flip && actual.fallthrough_true == old.fallthrough_true,
        Rewrite::Shift { result } => actual.code == OpCode::CPUI_INT_MULT && actual.inputs.len() == 2
            && actual.inputs[0] == old.inputs[0] && size.is_some_and(|size| literal(&actual.inputs[1], size, result))
            && actual.flip == old.flip && actual.fallthrough_true == old.fallthrough_true,
        Rewrite::Collapse { result } => actual.code == OpCode::CPUI_COPY && actual.inputs.len() == 1
            && size.is_some_and(|size| literal(&actual.inputs[0], size, result))
            && actual.flip == old.flip && actual.fallthrough_true == old.fallthrough_true,
        Rewrite::Reassociate { source, result } => {
            let sub = &candidate.expected[&source];
            actual.code == old.code && actual.inputs.len() == 2 && actual.inputs[0].same_value(&sub.inputs[0])
                && size.is_some_and(|size| literal(&actual.inputs[1], size, result))
                && actual.flip == old.flip && actual.fallthrough_true == old.fallthrough_true
                && candidate.matches_op(fd, source)
        }
        Rewrite::Collect { slots, target, result } => {
            let Some(size) = size else { return; };
            for (index, &(id, _)) in slots.iter().enumerate() {
                if slots[..index].iter().any(|&(prior, _)| prior == id) { continue; }
                let replacement = if id == root { None } else {
                    let Some(after) = Operation::of(fd, id) else { return; };
                    Some(after)
                };
                let after = replacement.as_ref().unwrap_or(&actual);
                let before = &candidate.expected[&id];
                if !before.same_identity(after) || before.code != after.code || before.inputs.len() != after.inputs.len()
                    || before.flip != after.flip || before.fallthrough_true != after.fallthrough_true { return; }
                for (slot, (before, after)) in before.inputs.iter().zip(&after.inputs).enumerate() {
                    if slots.contains(&(id, slot)) {
                        let wanted = if (id, slot) == target { result } else { 0 };
                        if !literal(after, size, wanted) { return; }
                    } else if before != after { return; }
                }
                if let Some(replacement) = replacement { candidate.expected.insert(id, replacement); }
            }
            true
        }
        Rewrite::Load { memory } => {
            if actual.code != OpCode::CPUI_COPY || actual.inputs.len() != 1 || actual.inputs[0].id != memory
                || actual.flip != old.flip || actual.fallthrough_true != old.fallthrough_true { return; }
            candidate.materialized.insert(memory, root);
            true
        }
        Rewrite::Readonly { memory, fact, result } => {
            if actual.code != OpCode::CPUI_COPY || actual.inputs.len() != 1
                || !literal(&actual.inputs[0], fact.size, result)
                || actual.flip != old.flip || actual.fallthrough_true != old.fallthrough_true { return; }
            candidate.materialized.remove(&memory);
            candidate.readonly.push(fact);
            true
        }
        Rewrite::Invert => {
            if actual.code != old.code || actual.inputs != old.inputs || actual.flip == old.flip
                || actual.fallthrough_true == old.fallthrough_true { return; }
            candidate.edge_order.swap(0, 1);
            candidate.edges_match(fd)
        }
        Rewrite::Normalize { condition } => {
            let Some(after_condition) = Operation::of(fd, condition) else { return; };
            let before_condition = &candidate.expected[&condition];
            let opposite = match before_condition.code {
                OpCode::CPUI_INT_EQUAL => OpCode::CPUI_INT_NOTEQUAL,
                OpCode::CPUI_INT_NOTEQUAL => OpCode::CPUI_INT_EQUAL,
                _ => return,
            };
            if actual.code != old.code || actual.inputs != old.inputs || actual.flip == old.flip
                || actual.fallthrough_true != old.fallthrough_true
                || !before_condition.same_identity(&after_condition) || after_condition.code != opposite
                || after_condition.inputs != before_condition.inputs
                || after_condition.flip != before_condition.flip
                || after_condition.fallthrough_true != before_condition.fallthrough_true
                || !candidate.edges_match(fd) { return; }
            candidate.expected.insert(condition, after_condition);
            true
        }
    };
    if !successful { return; }
    candidate.expected.insert(root, actual);
    if candidate.bound && !candidate.bind_and_prune(fd) { return; }
    put(fd, candidate);
}

pub(crate) struct BranchTxn { candidate: Box<Candidate>, cut: CertifiedEdgeCut }
pub(crate) fn begin_branch(fd: &mut Funcdata, branch: OpId, removed_edge: int4) -> Option<BranchTxn> {
    let candidate = take(fd, branch, true)?;
    if candidate.branch != branch || !candidate.edges_match(fd) || candidate.readonly.is_empty()
        || !candidate.source.matches(fd) || !candidate.tracked.iter().all(|fact| fact.matches(fd))
        || !candidate.readonly.iter().all(|fact| fact.matches(fd)) { return None; }
    let edge = usize::try_from(removed_edge).ok()?;
    let original_edge = *candidate.edge_order.get(edge)?;
    let root = &candidate.expected[&branch];
    if root.code != OpCode::CPUI_CBRANCH || root.inputs.len() != 2 || !root.inputs[1].storage.constant { return None; }
    // ActionDeterminedBranch supplies its actual selected edge; do not duplicate
    // its branch evaluation here. The literal/flag state above is authenticated.
    let cut = CertifiedEdgeCut { branch: root.key.clone(), from_start: candidate.raw.first()?.key.clone(),
        edge: original_edge, to_start: candidate.successors[original_edge].clone() };
    Some(BranchTxn { candidate, cut })
}
pub(crate) fn finish_branch(fd: &mut Funcdata, transaction: Option<BranchTxn>, success: bool) {
    let Some(BranchTxn { candidate, cut }) = transaction else { return; };
    if !success { return; }
    let replay = Rc::new(BranchReplay { entry: fd.get_address().clone(), raw: candidate.raw,
        source: candidate.source, tracked: candidate.tracked, readonly: candidate.readonly,
        successors: candidate.successors, cut });
    if let Some(state) = fd.branch_reachability.as_mut() { state.completed = Some(replay); }
}
