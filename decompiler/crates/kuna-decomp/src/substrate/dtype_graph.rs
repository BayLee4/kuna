//! Datatype-only generation storage. Internal edges never retain a generation.
use super::*;
use std::cell::Ref;
use std::collections::{HashMap, HashSet, VecDeque};
use std::hash::{Hash, Hasher};
use std::ops::Deref;
use std::sync::atomic::{AtomicU64, Ordering as AtomicOrdering};

static NEXT_GENERATION: AtomicU64 = AtomicU64::new(1);
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TypeId { generation: u64, slot: usize }
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TypeState { Opaque, Loading, Failed(String), Pending, Complete }
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum TypeInstance { Fixed, Sized(int4) }
impl TypeInstance {
    pub(super) fn of(data: &Datatype) -> Self {
        if data.is_variable_length() { Self::Sized(data.size) } else { Self::Fixed }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
enum NominalInstance { Unspecified, Target(TypeId), Known(TypeInstance) }
#[derive(Clone)]
pub struct TypeRoot { pub(super) generation: Rc<Generation>, pub(super) identity: TypeId }
impl std::fmt::Debug for TypeRoot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { f.debug_tuple("TypeRoot").field(&self.identity).finish() }
}
impl PartialEq for TypeRoot { fn eq(&self, rhs: &Self) -> bool { self.identity == rhs.identity } }
impl Eq for TypeRoot {}
impl PartialOrd for TypeRoot { fn partial_cmp(&self, rhs: &Self) -> Option<Ordering> { Some(self.cmp(rhs)) } }
impl Ord for TypeRoot { fn cmp(&self, rhs: &Self) -> Ordering { self.identity.cmp(&rhs.identity) } }
impl Hash for TypeRoot { fn hash<H: Hasher>(&self, state: &mut H) { self.identity.hash(state); } }
impl TypeRoot {
    pub fn id(&self) -> TypeId { self.identity }
    pub fn read(&self) -> ReadView<'_> { self.generation.read() }
    pub fn related(&self, id: TypeId) -> KunaResult<Self> { self.generation.root(id) }
    pub fn is_inferred(&self) -> bool { self.read().access().node(self.identity).is_ok_and(|n| n.inferred) }
}

/// Source ownership is an authenticated decode receipt, not a datatype property
/// inferred from names, source ids, shape, or absence of inference metadata.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HostTypeSourceKind { Program, Builtin, Transient }

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HostTypeSource {
    pub program: u64,
    pub revision: u64,
    pub id: u64,
    pub kind: HostTypeSourceKind,
    pub size: int4,
    pub scope: String,
    pub binding: String,
}

impl HostTypeSource {
    /// Core roots survive request flushes. Preserve their original revision;
    /// the Java consumer must replay this exact binding against today's source.
    pub(super) fn same_definition(&self, other: &Self) -> bool {
        self == other || (self.kind == HostTypeSourceKind::Builtin
            && other.kind == HostTypeSourceKind::Builtin
            && self.program == other.program && self.id == other.id && self.size == other.size
            && self.scope == other.scope && self.binding == other.binding)
    }
}

pub struct ReadView<'a> {
    owner: &'a Rc<Generation>,
    local: Ref<'a, Nodes>,
    core: Option<Ref<'a, Nodes>>,
}
#[derive(Clone, Copy)]
pub(super) struct GraphAccess<'a> {
    owner: &'a Rc<Generation>,
    local: &'a Nodes,
    core: Option<&'a Nodes>,
}
#[derive(Clone, Copy)]
pub struct TypeRef<'a> {
    pub(super) graph: GraphAccess<'a>,
    pub(super) id: TypeId,
    pub(super) data: &'a Datatype,
}
impl std::fmt::Debug for TypeRef<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { self.data.fmt(f) }
}
impl Deref for TypeRef<'_> { type Target = Datatype; fn deref(&self) -> &Datatype { self.data } }
impl<'a> TypeRef<'a> {
    pub fn id(&self) -> TypeId { self.id }
    pub fn effective(&self) -> KunaResult<Self> { self.graph.get(self.graph.resolve_alias(self.id)?) }
    pub fn root(&self) -> TypeRoot { self.graph.root(self.id).expect("validated borrowed datatype identity") }
    pub fn get_instance(&self) -> Option<TypeInstance> {
        match self.graph.node(self.id).expect("validated borrowed datatype identity").instance {
            NominalInstance::Known(instance) => Some(instance), _ => None,
        }
    }
}
impl ReadView<'_> {
    pub fn host_source(&self, id: TypeId) -> KunaResult<Option<&HostTypeSource>> {
        let graph = self.access();
        graph.node(id)?;
        let store = graph.store(id)?;
        if store.stale_host_sources.contains(&id) {
            return Err(graph_error("Host datatype source receipt was invalidated by a dependency mutation"));
        }
        Ok(store.host_sources.get(&id))
    }
}

impl GraphStore {
    pub(super) fn validate_host_source_binding(&self, root: &TypeRoot, source: &HostTypeSource) -> KunaResult<()> {
        self.check_owner(root)?;
        let view = root.read();
        let graph = view.access();
        let node = graph.node(root.id())?;
        if node.inferred || node.data.id != source.id || node.data.size != source.size
            || matches!(node.state, TypeState::Opaque | TypeState::Loading | TypeState::Failed(_)) {
            return Err(graph_error("Host source receipt changes datatype identity, instance or completed definition"));
        }
        let store = graph.store(root.id())?;
        if let Some(previous) = store.host_sources.get(&root.id()) {
            if !previous.same_definition(source) {
                return Err(graph_error("Conflicting host source datatype receipt"));
            }
            if !store.stale_host_sources.contains(&root.id()) { return Ok(()); }
        }
        drop(view);
        root.generation.writable()
    }

    pub(super) fn bind_host_source(&self, root: &TypeRoot, source: HostTypeSource) -> KunaResult<()> {
        self.validate_host_source_binding(root, &source)?;
        {
            let view = root.read();
            let store = view.access().store(root.id())?;
            if store.host_sources.contains_key(&root.id()) && !store.stale_host_sources.contains(&root.id()) {
                return Ok(());
            }
        }
        let mut nodes = root.generation.nodes.try_borrow_mut().map_err(|_| busy())?;
        // Preserve the original builtin revision. Only a freshly completed full
        // host decode reaches this binder; a typeref can never clear the tombstone.
        nodes.host_sources.entry(root.id()).or_insert(source);
        nodes.stale_host_sources.remove(&root.id());
        Ok(())
    }

    pub(super) fn host_source_stale(&self, root: &TypeRoot) -> KunaResult<bool> {
        self.check_owner(root)?;
        let view = root.read();
        Ok(view.access().store(root.id())?.stale_host_sources.contains(&root.id()))
    }

    fn host_source_dependents(&self, root: &TypeRoot) -> KunaResult<Vec<TypeId>> {
        let view = root.read();
        if view.access().store(root.id())?.host_sources.is_empty() { return Ok(Vec::new()); }
        dependent_closure(view.access(), std::iter::once(root.id()))
    }

    pub(super) fn host_mutation_epoch(&self) -> u64 { self.host_mutation_epoch.get() }

    fn advance_host_mutation_epoch(&self) {
        self.host_mutation_epoch.set(self.host_mutation_epoch.get().checked_add(1)
            .expect("host datatype mutation epoch exhausted"));
    }

}

impl ReadView<'_> {
    pub(super) fn access(&self) -> GraphAccess<'_> {
        GraphAccess { owner: self.owner, local: &self.local, core: self.core.as_deref() }
    }
    pub fn get(&self, id: TypeId) -> KunaResult<TypeRef<'_>> { self.access().get(id) }
    pub fn definition(&self, id: TypeId) -> KunaResult<&Datatype> { Ok(&self.access().node(id)?.data) }
    pub fn resolve_alias(&self, id: TypeId) -> KunaResult<TypeId> { self.access().resolve_alias(id) }
    pub fn state(&self, id: TypeId) -> KunaResult<&TypeState> { Ok(&self.access().node(id)?.state) }
    pub fn layout_ready(&self, id: TypeId) -> KunaResult<bool> {
        let graph = self.access();
        graph.value_ready(id, true, graph.len() + 1)
    }
    pub fn derived_ready(&self, id: TypeId) -> KunaResult<bool> { Ok(self.access().node(id)?.derived_ready) }
    /// Complete graph edge inventory, including callable, alias, auxiliary and
    /// identity-owned variant dependencies. No per-read allocation.
    pub fn dependencies(&self, id: TypeId) -> KunaResult<&[TypeId]> { Ok(&self.access().node(id)?.dependencies) }
    pub fn get_field(&self, id: TypeId, index: int4) -> KunaResult<Option<&TypeField>> {
        if index < 0 { return Ok(None); }
        let data = self.definition(self.resolve_alias(id)?)?;
        Ok(match &data.kind { DatatypeKind::Struct { field, .. } | DatatypeKind::Union { field } => field.get(index as usize), _ => None })
    }
    pub fn get_ptr_to(&self, id: TypeId) -> KunaResult<Option<TypeId>> {
        Ok(match &self.definition(self.resolve_alias(id)?)?.kind {
            DatatypeKind::Pointer { ptrto, .. } | DatatypeKind::PointerRel { ptrto, .. } => Some(*ptrto), _ => None,
        })
    }
    pub fn get_code_prototype(&self, id: TypeId) -> KunaResult<Option<&crate::fspec::LogicalCallable>> {
        Ok(match &self.definition(self.resolve_alias(id)?)?.kind { DatatypeKind::Code { proto } => proto.as_ref(), _ => None })
    }
    pub fn abi_ready(&self, id: TypeId) -> KunaResult<bool> {
        let proto = self.get_code_prototype(id)?.ok_or_else(|| graph_error("Datatype has no logical callable declaration"))?;
        let graph = self.access();
        let mut ready = graph.value_ready(proto.output, true, graph.len() + 1)?;
        for &input in &proto.inputs { ready &= graph.value_ready(input, false, graph.len() + 1)?; }
        Ok(ready)
    }
    pub fn variant_layout(&self, id: TypeId) -> Option<&crate::kuna_dwarfvariants::VariantLayout> {
        let store = self.access().store(id).ok()?;
        store.variants.get(&id)
    }
}
impl<'a> GraphAccess<'a> {
    fn len(self) -> usize { self.local.nodes.len() + self.core.map_or(0, |s| s.nodes.len()) }
    fn store(self, id: TypeId) -> KunaResult<&'a Nodes> {
        if id.generation == self.owner.id { Ok(self.local) }
        else if self.owner.core.as_ref().is_some_and(|c| c.id == id.generation) { self.core.ok_or_else(|| graph_error("Core datatype generation unavailable")) }
        else { Err(graph_error("Datatype identity belongs to a different generation")) }
    }
    fn node(self, id: TypeId) -> KunaResult<&'a Node> { self.store(id)?.nodes.get(id.slot).ok_or_else(|| graph_error("Unknown datatype identity")) }
    pub(super) fn get(self, id: TypeId) -> KunaResult<TypeRef<'a>> { Ok(TypeRef { graph: self, id, data: &self.node(id)?.data }) }
    pub(super) fn root(self, id: TypeId) -> KunaResult<TypeRoot> {
        self.node(id)?;
        let owner = if id.generation == self.owner.id { self.owner } else { self.owner.core.as_ref().ok_or_else(|| graph_error("Missing core owner"))? };
        Ok(TypeRoot { generation: Rc::clone(owner), identity: id })
    }
    fn resolve_alias(self, mut id: TypeId) -> KunaResult<TypeId> {
        for _ in 0..=self.len() {
            let node = self.node(id)?;
            if let TypeState::Failed(message) = &node.state { return Err(graph_error(message)); }
            if !matches!(node.data.kind, DatatypeKind::Alias) { return Ok(id); }
            id = node.data.typedef_imm.ok_or_else(|| graph_error("Alias declaration is incomplete"))?;
        }
        Err(graph_error("Cyclic typedef declaration"))
    }
    fn value_ready(self, id: TypeId, allow_void: bool, remaining: usize) -> KunaResult<bool> {
        if remaining == 0 { return Err(graph_error("Impossible by-value datatype cycle")); }
        let node = self.node(id)?;
        if let TypeState::Failed(message) = &node.state { return Err(graph_error(message)); }
        if matches!(node.state, TypeState::Opaque | TypeState::Loading) { return Ok(false); }
        match &node.data.kind {
            DatatypeKind::Alias => match node.data.typedef_imm { Some(base) => self.value_ready(base, allow_void, remaining - 1), None => Ok(false) },
            DatatypeKind::Void => if allow_void { Ok(true) } else { Err(graph_error("Void is not a callable input type")) },
            DatatypeKind::Code { .. } => Err(graph_error("Code is not a by-value callable type")),
            DatatypeKind::Struct { field, bitfield } if !node.layout_ready => {
                for field in field { self.value_ready(field.field_type, false, remaining - 1)?; }
                for field in bitfield { self.value_ready(field.field_type, false, remaining - 1)?; }
                Ok(false)
            }
            DatatypeKind::Union { field } if !node.layout_ready => {
                for field in field { self.value_ready(field.field_type, false, remaining - 1)?; }
                Ok(false)
            }
            DatatypeKind::Array { arrayof, .. } if !node.layout_ready => { self.value_ready(*arrayof, false, remaining - 1)?; Ok(false) }
            DatatypeKind::PartialStruct { container, .. } | DatatypeKind::PartialUnion { container, .. } if !node.layout_ready => {
                self.value_ready(*container, false, remaining - 1)?;
                Ok(false)
            }
            DatatypeKind::PartialEnum { parent, .. } if !node.layout_ready => {
                self.value_ready(*parent, false, remaining - 1)?;
                Ok(false)
            }
            _ => Ok(node.layout_ready),
        }
    }
}

fn graph_error(message: impl Into<String>) -> KunaError { KunaError::lowlevel(message) }
fn busy() -> KunaError { graph_error("Datatype graph is borrowed; release readers before publication") }
fn reservation_compatible(old: &Datatype, new: &Datatype) -> bool {
    if matches!(old.kind, DatatypeKind::Alias) { return matches!(new.kind, DatatypeKind::Alias); }
    if old.metatype != new.metatype || matches!(new.kind, DatatypeKind::Alias) { return false; }
    match &old.kind {
        DatatypeKind::Struct { .. } => matches!(new.kind, DatatypeKind::Struct { .. }),
        DatatypeKind::Union { .. } => matches!(new.kind, DatatypeKind::Union { .. }),
        DatatypeKind::Enum { .. } => matches!(new.kind, DatatypeKind::Enum { .. }),
        DatatypeKind::Code { .. } => matches!(new.kind, DatatypeKind::Code { .. }),
        _ => true,
    }
}
fn normalize_leaf_kind(data: &mut Datatype) {
    if matches!(data.kind, DatatypeKind::Base) {
        match data.metatype {
            type_metatype::TYPE_UNKNOWN => data.kind = DatatypeKind::Unknown,
            type_metatype::TYPE_VOID => data.kind = DatatypeKind::Void,
            type_metatype::TYPE_CODE => data.kind = DatatypeKind::Code { proto: None },
            _ => (),
        }
    }
}
#[derive(Clone, Copy)]
struct Intrinsic { size: int4, alignment: int4, metatype: type_metatype, flags: uint4, submeta: sub_metatype }
impl Intrinsic {
    fn of(d: &Datatype) -> Self {
        // Aggregate drafts may explicitly publish only a declared width, not a
        // complete body. Keep that source fact separate from incompleteness
        // derived later for aliases, arrays and by-value dependents.
        let derived = if matches!(d.kind, DatatypeKind::Struct { .. } | DatatypeKind::Union { .. }) {
            DERIVED_FLAGS & !flags::type_incomplete
        } else { DERIVED_FLAGS };
        Self { size: d.size, alignment: d.alignment, metatype: d.metatype, flags: d.flags & !derived, submeta: d.submeta }
    }
}
const DERIVED_FLAGS: uint4 = flags::type_incomplete | flags::needs_resolution | flags::has_bitfields | flags::pointer_to_array | flags::force_format | flags::warning_issued | flags::coretype;
struct Node {
    data: Datatype,
    intrinsic: Intrinsic,
    state: TypeState,
    layout_ready: bool,
    derived_ready: bool,
    inferred: bool,
    indexed: bool,
    dependencies: Vec<TypeId>,
    dependents: Vec<TypeId>,
    key: Option<u64>,
    instance: NominalInstance,
    instance_constraint: Option<TypeInstance>,
}
#[derive(Default)]
struct Nodes {
    nodes: Vec<Node>,
    named: BTreeMap<String, BTreeMap<(uint8, NominalInstance), TypeId>>,
    anonymous: HashMap<u64, Vec<TypeId>>,
    variants: BTreeMap<TypeId, crate::kuna_dwarfvariants::VariantLayout>,
    host_sources: BTreeMap<TypeId, HostTypeSource>,
    stale_host_sources: HashSet<TypeId>,
}
pub(super) struct Generation {
    id: u64,
    core: Option<Rc<Generation>>,
    frozen: Cell<bool>,
    model_context: Cell<Option<crate::fspec::ModelContextId>>,
    nodes: RefCell<Nodes>,
}
impl Generation {
    fn new(core: Option<Rc<Self>>) -> Rc<Self> {
        let id = NEXT_GENERATION.fetch_update(AtomicOrdering::Relaxed, AtomicOrdering::Relaxed, |id| id.checked_add(1))
            .expect("datatype generation identity space exhausted");
        Rc::new(Self { id, core, frozen: Cell::new(false), model_context: Cell::new(None), nodes: RefCell::new(Nodes::default()) })
    }
    fn read(self: &Rc<Self>) -> ReadView<'_> {
        // Only private, callback-free commit sections hold mutable guards.
        ReadView { owner: self, local: self.nodes.borrow(), core: self.core.as_ref().map(|c| c.nodes.borrow()) }
    }
    fn root(self: &Rc<Self>, id: TypeId) -> KunaResult<TypeRoot> { self.read().access().root(id) }
    fn writable(&self) -> KunaResult<()> {
        if self.frozen.get() { return Err(graph_error("Retired datatype generation is immutable")); }
        let _guard = self.nodes.try_borrow_mut().map_err(|_| busy())?;
        Ok(())
    }
}
pub(super) struct GraphStore { core: Rc<Generation>, active: RefCell<Rc<Generation>>, host_mutation_epoch: Cell<u64> }
impl GraphStore {
    pub(super) fn new() -> Self {
        let core = Generation::new(None);
        let active = Generation::new(Some(Rc::clone(&core)));
        Self { core, active: RefCell::new(active), host_mutation_epoch: Cell::new(0) }
    }
    pub(super) fn root(&self, id: TypeId) -> KunaResult<TypeRoot> { self.active.borrow().root(id) }
    fn check_owner(&self, root: &TypeRoot) -> KunaResult<()> {
        if root.id().generation != self.core.id && root.id().generation != self.active.borrow().id {
            return Err(graph_error("Datatype mutation requires this factory's current generation"));
        }
        if !root.read().access().node(root.id())?.indexed {
            return Err(graph_error("Retired datatype identity is immutable"));
        }
        Ok(())
    }
    pub(super) fn bind_model_context(&self, id: crate::fspec::ModelContextId) -> KunaResult<()> {
        let active = self.active.borrow();
        for owner in [&self.core, &*active] {
            if owner.model_context.get().is_some_and(|old| old != id) { return Err(graph_error("Datatype graph architecture/model context cannot be rebound")); }
        }
        self.core.model_context.set(Some(id));
        active.model_context.set(Some(id));
        Ok(())
    }
    pub(super) fn seal_core(&self) -> KunaResult<()> {
        if self.core.frozen.get() { return Ok(()); }
        let nodes = self.core.nodes.borrow();
        if nodes.nodes.iter().any(|n| n.state != TypeState::Complete || !n.derived_ready) { return Err(graph_error("Core datatype closure is incomplete")); }
        self.core.frozen.set(true);
        Ok(())
    }
    pub(super) fn flush(&self) -> KunaResult<()> {
        let mut active = self.active.try_borrow_mut().map_err(|_| busy())?;
        {
            let _active_nodes = active.nodes.try_borrow_mut().map_err(|_| busy())?;
            let _core_nodes = self.core.nodes.try_borrow_mut().map_err(|_| busy())?;
        }
        self.seal_core()?;
        active.frozen.set(true);
        let fresh = Generation::new(Some(Rc::clone(&self.core)));
        fresh.model_context.set(active.model_context.get());
        *active = fresh;
        Ok(())
    }
    pub(super) fn find_instance(&self, name: &str, host: uint8, instance: TypeInstance) -> Option<TypeRoot> {
        self.find_indexed(name, host, NominalInstance::Known(instance), false)
    }
    fn find_indexed(&self, name: &str, host: uint8, instance: NominalInstance, include_failed: bool) -> Option<TypeRoot> {
        let active = self.active.borrow();
        for owner in [&*active, &self.core] {
            let store = owner.nodes.borrow();
            let usable = |id: &TypeId| include_failed || !matches!(store.nodes[id.slot].state, TypeState::Failed(_));
            let found = store.named.get(name).and_then(|ids| ids.get(&(host, instance))).filter(|id| usable(id)).copied();
            if let Some(id) = found { return Some(TypeRoot { generation: Rc::clone(owner), identity: id }); }
        }
        None
    }
    pub(super) fn find_source(&self, name: &str, host: uint8, include_failed: bool) -> KunaResult<Option<TypeRoot>> {
        let active = self.active.borrow();
        let mut found = None;
        for owner in [&*active, &self.core] {
            let store = owner.nodes.borrow();
            if let Some(ids) = store.named.get(name) {
                for (_, &id) in ids.range((host, NominalInstance::Unspecified)..=(host, NominalInstance::Known(TypeInstance::Sized(int4::MAX)))) {
                    if !include_failed && matches!(store.nodes[id.slot].state, TypeState::Failed(_)) { continue; }
                    if found.is_some() { return Err(graph_error("Datatype source identity has multiple instances")); }
                    found = Some(TypeRoot { generation: Rc::clone(owner), identity: id });
                }
            }
        }
        Ok(found)
    }
    pub(super) fn find_by_name(&self, name: &str) -> Option<TypeRoot> {
        let active = self.active.borrow();
        for owner in [&*active, &self.core] {
            let store = owner.nodes.borrow();
            if let Some(id) = store.named.get(name).and_then(|ids| ids.values()
                .find(|id| !matches!(store.nodes[id.slot].state, TypeState::Failed(_)))).copied() {
                return Some(TypeRoot { generation: Rc::clone(owner), identity: id });
            }
        }
        None
    }
    pub(super) fn resolve_instance(&self, name: &str, host: uint8, instance: TypeInstance) -> KunaResult<Option<TypeRoot>> {
        if let Some(root) = self.find_instance(name, host, instance) { return Ok(Some(root)); }
        let Some(root) = self.find_provisional(name, host, false)? else { return Ok(None); };
        self.constrain_instance(&root, instance)?;
        Ok(Some(root))
    }
    fn find_provisional(&self, name: &str, host: uint8, include_failed: bool) -> KunaResult<Option<TypeRoot>> {
        let active = self.active.borrow();
        let mut found = None;
        for owner in [&*active, &self.core] {
            let store = owner.nodes.borrow();
            if let Some(ids) = store.named.get(name) {
                for (&(_, instance), &id) in ids.range((host, NominalInstance::Unspecified)..=(host, NominalInstance::Known(TypeInstance::Sized(int4::MAX)))) {
                    if matches!(instance, NominalInstance::Known(_)) { continue; }
                    if !include_failed && matches!(store.nodes[id.slot].state, TypeState::Failed(_)) { continue; }
                    if found.is_some() { return Err(graph_error("Datatype reference has multiple unresolved instances")); }
                    found = Some(TypeRoot { generation: Rc::clone(owner), identity: id });
                }
            }
        }
        Ok(found)
    }
    fn constrain_instance(&self, root: &TypeRoot, instance: TypeInstance) -> KunaResult<()> {
        self.check_owner(root)?;
        if self.instance_of(root) == Some(instance) { return Ok(()); }
        root.generation.writable()?;
        let affected = self.host_source_dependents(root)?;
        let mut nodes = root.generation.nodes.try_borrow_mut().map_err(|_| busy())?;
        let node = &nodes.nodes[root.id().slot];
        let old = node.instance;
        if old == NominalInstance::Known(instance) { return Ok(()); }
        if !matches!(old, NominalInstance::Unspecified | NominalInstance::Target(_)) {
            return Err(graph_error("Conflicting datatype instance constraint"));
        }
        let source = node.data.id;
        let name = node.data.name.clone();
        let new = NominalInstance::Known(instance);
        if let Some(ids) = nodes.named.get_mut(&name) {
            if ids.get(&(source, new)).is_some_and(|id| *id != root.id()) {
                return Err(graph_error("Conflicting datatype instance reservation"));
            }
            ids.remove(&(source, old));
            ids.insert((source, new), root.id());
        }
        let node = &mut nodes.nodes[root.id().slot];
        node.instance = new;
        node.instance_constraint = Some(instance);
        invalidate_host_sources(&mut nodes, affected.into_iter());
        Ok(())
    }
    pub(super) fn roots(&self) -> Vec<TypeRoot> {
        let active = self.active.borrow();
        let mut roots = Vec::new();
        for owner in [&self.core, &*active] {
            let store = owner.nodes.borrow();
            roots.extend(store.nodes.iter().enumerate().filter(|(_, n)| n.indexed)
                .map(|(slot, _)| TypeRoot { generation: Rc::clone(owner), identity: TypeId { generation: owner.id, slot } }));
        }
        roots
    }
    pub(super) fn core_roots(&self) -> Vec<TypeRoot> {
        self.core.nodes.borrow().nodes.iter().enumerate().filter(|(_, n)| n.indexed)
            .map(|(slot, _)| TypeRoot { generation: Rc::clone(&self.core), identity: TypeId { generation: self.core.id, slot } }).collect()
    }
    pub(super) fn reserve(&self, name: &str, host: uint8, meta: type_metatype, inferred: bool) -> KunaResult<TypeRoot> {
        let mut data = Datatype::new(0, meta);
        data.name = name.into(); data.display_name = name.into(); data.id = host;
        data.flags |= flags::type_incomplete;
        data.kind = match meta {
            type_metatype::TYPE_STRUCT => DatatypeKind::Struct { field: Vec::new(), bitfield: Vec::new() },
            type_metatype::TYPE_UNION => { data.flags |= flags::needs_resolution; DatatypeKind::Union { field: Vec::new() } },
            type_metatype::TYPE_CODE => DatatypeKind::Code { proto: None },
            type_metatype::TYPE_ENUM_INT | type_metatype::TYPE_ENUM_UINT => DatatypeKind::Enum { namemap: BTreeMap::new() },
            _ => DatatypeKind::Base,
        };
        self.reserve_data(data, inferred, false, NominalInstance::Unspecified, None)
    }
    pub(super) fn reserve_alias(&self, name: &str, host: uint8) -> KunaResult<TypeRoot> {
        self.reserve_alias_instance(name, host, None, None, false)
    }
    pub(super) fn reserve_alias_instance(&self, name: &str, host: uint8, instance: Option<TypeInstance>, target: Option<TypeId>, core: bool) -> KunaResult<TypeRoot> {
        let mut data = Datatype::new(0, type_metatype::TYPE_UNKNOWN);
        data.name = name.into(); data.display_name = name.into(); data.id = host;
        data.flags |= flags::type_incomplete; data.kind = DatatypeKind::Alias;
        let key = instance.map(NominalInstance::Known).or_else(|| target.map(NominalInstance::Target)).unwrap_or(NominalInstance::Unspecified);
        self.reserve_data(data, false, core, key, instance)
    }
    pub(super) fn instance_of(&self, root: &TypeRoot) -> Option<TypeInstance> {
        match root.read().access().node(root.id()).expect("valid type root").instance {
            NominalInstance::Known(instance) => Some(instance), _ => None,
        }
    }
    fn reserve_data(&self, mut data: Datatype, inferred: bool, core: bool, instance: NominalInstance, constraint: Option<TypeInstance>) -> KunaResult<TypeRoot> {
        let owner = if core { Rc::clone(&self.core) } else { Rc::clone(&self.active.borrow()) };
        owner.writable()?;
        if core { data.flags |= flags::coretype; }
        if inferred && (!data.name.is_empty() || data.id != 0) {
            if let Some(existing) = self.find_source(&data.name, data.id, true)? {
                if !existing.is_inferred() { return Err(graph_error("Inferred revision collides with an authoritative nominal identity")); }
            }
        }
        if !inferred && (!data.name.is_empty() || data.id != 0) {
            let exact = self.find_indexed(&data.name, data.id, instance, true);
            let existing = if exact.is_some() { exact }
                else if instance == NominalInstance::Unspecified { self.find_source(&data.name, data.id, true)? }
                else if matches!(instance, NominalInstance::Known(_)) { self.find_provisional(&data.name, data.id, true)? }
                else { self.find_indexed(&data.name, data.id, NominalInstance::Unspecified, true) };
            if let Some(existing) = existing {
                if core && existing.id().generation != self.core.id {
                    return Err(graph_error("Datatype reservation crosses core ownership"));
                }
                let view = existing.read(); let old = view.definition(existing.id())?;
                if !reservation_compatible(old, &data) {
                    return Err(graph_error("Conflicting datatype reservation kind"));
                }
                drop(view);
                if let Some(instance) = constraint { self.constrain_instance(&existing, instance)?; }
                return Ok(existing.clone());
            }
        }
        let intrinsic = Intrinsic::of(&data);
        let key = (data.name.clone(), (data.id, instance));
        let intrinsic_union = matches!(data.kind, DatatypeKind::Union { .. });
        if intrinsic_union { data.flags |= flags::needs_resolution; }
        let mut nodes = owner.nodes.try_borrow_mut().map_err(|_| busy())?;
        let id = TypeId { generation: owner.id, slot: nodes.nodes.len() };
        nodes.nodes.push(Node { data, intrinsic, state: TypeState::Opaque, layout_ready: false, derived_ready: intrinsic_union,
            inferred, indexed: true, dependencies: Vec::new(), dependents: Vec::new(), key: None, instance, instance_constraint: constraint });
        if !key.0.is_empty() || key.1.0 != 0 {
            if let Some(previous) = nodes.named.entry(key.0).or_default().insert(key.1, id) {
                nodes.nodes[previous.slot].indexed = false;
            }
        }
        drop(nodes);
        Ok(TypeRoot { generation: owner, identity: id })
    }
    pub(super) fn begin(&self, root: &TypeRoot) -> KunaResult<()> {
        self.check_owner(root)?;
        root.generation.writable()?;
        let mut nodes = root.generation.nodes.try_borrow_mut().map_err(|_| busy())?;
        let node = &mut nodes.nodes[root.id().slot];
        if !matches!(node.state, TypeState::Opaque | TypeState::Failed(_)) {
            return Err(graph_error("Datatype definition is already loading or published"));
        }
        if matches!(node.state, TypeState::Opaque | TypeState::Failed(_)) { node.state = TypeState::Loading; }
        Ok(())
    }
    pub(super) fn fail(&self, root: &TypeRoot, message: String) -> KunaResult<()> {
        self.check_owner(root)?;
        root.generation.writable()?;
        let affected = {
            let view = root.read();
            if matches!(view.state(root.id())?, TypeState::Complete | TypeState::Pending) {
                return Err(graph_error("Cannot discard a published datatype definition"));
            }
            if view.access().store(root.id())?.host_sources.is_empty() { Vec::new() }
            else { dependent_closure(view.access(), std::iter::once(root.id()))? }
        };
        let mut nodes = root.generation.nodes.try_borrow_mut().map_err(|_| busy())?;
        nodes.nodes[root.id().slot].state = TypeState::Failed(message);
        invalidate_host_sources(&mut nodes, affected.into_iter());
        self.advance_host_mutation_epoch();
        Ok(())
    }
    pub(super) fn state(&self, root: &TypeRoot) -> KunaResult<TypeState> { Ok(root.read().state(root.id())?.clone()) }
    pub(super) fn set_display_format(&self, root: &TypeRoot, format: uint4) -> KunaResult<TypeRoot> {
        self.check_owner(root)?;
        if format > 5 { return Err(graph_error("Unknown datatype integer display format")); }
        if root.generation.core.is_some() && root.generation.frozen.get() {
            return Err(graph_error("Retired datatype presentation is immutable"));
        }
        // The one presentation-only exception to frozen core definitions. No semantic
        // flags, edges, layout or interner key changes, and readers remain legally valid.
        root.read().definition(root.id())?.presentation_format.set(Some(format));
        Ok(root.clone())
    }

    pub(super) fn intern(&self, data: Datatype) -> KunaResult<TypeRoot> {
        self.intern_in(data, false)
    }
    pub(super) fn intern_core(&self, data: Datatype) -> KunaResult<TypeRoot> {
        self.intern_in(data, true)
    }
    fn intern_in(&self, mut data: Datatype, core: bool) -> KunaResult<TypeRoot> {
        normalize_leaf_kind(&mut data);
        let owner = if core { Rc::clone(&self.core) } else { Rc::clone(&self.active.borrow()) };
        if core { data.flags |= flags::coretype; }
        let declaration_only = data.is_incomplete() && match &data.kind {
            DatatypeKind::Pointer { .. } | DatatypeKind::PointerRel { .. } | DatatypeKind::Array { .. } => false,
            DatatypeKind::Alias => data.typedef_imm.is_none(),
            DatatypeKind::Code { proto } => proto.is_none(),
            _ => true,
        };
        if !data.name.is_empty() || data.id != 0 {
            let instance = if matches!(data.kind, DatatypeKind::Alias) {
                data.typedef_imm.and_then(|id| self.root(id).ok()).and_then(|root| self.instance_of(&root))
            } else { Some(TypeInstance::of(&data)) };
            let nominal = instance.map(NominalInstance::Known).or_else(|| data.typedef_imm.map(NominalInstance::Target)).unwrap_or(NominalInstance::Unspecified);
            let existing = self.find_indexed(&data.name, data.id, nominal, true)
                .or_else(|| self.find_indexed(&data.name, data.id, NominalInstance::Unspecified, true));
            if let Some(root) = existing {
                if core && root.id().generation != self.core.id { return Err(graph_error("Core definition collides with active nominal identity")); }
                if declaration_only {
                    if let Some(instance) = instance { self.constrain_instance(&root, instance)?; }
                }
                {
                    let view = root.read();
                    let node = view.access().node(root.id())?;
                    if declaration_only {
                        if !reservation_compatible(&node.data, &data) {
                            return Err(graph_error("Conflicting datatype reservation kind"));
                        }
                        let replace = matches!(node.state, TypeState::Opaque | TypeState::Failed(_));
                        drop(view);
                        if replace {
                            root.generation.writable()?;
                            let affected = self.host_source_dependents(&root)?;
                            let mut nodes = root.generation.nodes.try_borrow_mut().map_err(|_| busy())?;
                            let node = &mut nodes.nodes[root.id().slot];
                            node.intrinsic = Intrinsic::of(&data);
                            node.data = data;
                            invalidate_host_sources(&mut nodes, affected.into_iter());
                        }
                        return Ok(root.clone());
                    }
                    if matches!(node.state, TypeState::Complete | TypeState::Pending)
                        && shape_eq(&node.data, node.intrinsic, &data, Intrinsic::of(&data)) {
                        return Ok(root.clone());
                    }
                }
                self.complete(&root, data)?;
                return Ok(root);
            }
            if declaration_only { return self.reserve_data(data, false, core, nominal, instance); }
            // Reserve without duplicating a potentially large candidate body.
            let mut shell = Datatype::new_with_align(data.size, data.alignment, data.metatype);
            shell.name = data.name.clone(); shell.display_name = data.display_name.clone(); shell.id = data.id;
            shell.flags = data.flags | flags::type_incomplete;
            shell.kind = match data.kind {
                DatatypeKind::Alias => DatatypeKind::Alias,
                DatatypeKind::Struct { .. } => DatatypeKind::Struct { field: Vec::new(), bitfield: Vec::new() },
                DatatypeKind::Union { .. } => DatatypeKind::Union { field: Vec::new() },
                DatatypeKind::Code { .. } => DatatypeKind::Code { proto: None },
                DatatypeKind::Enum { .. } => DatatypeKind::Enum { namemap: BTreeMap::new() },
                _ => DatatypeKind::Base,
            };
            let root = self.reserve_data(shell, false, core, nominal, instance)?;
            self.complete(&root, data)?;
            return Ok(root);
        }
        if declaration_only {
            // An explicit unnamed binder has nominal identity even without a display
            // name. It is not an anonymous structural interning candidate.
            let instance = TypeInstance::of(&data);
            return self.reserve_data(data, false, core, NominalInstance::Known(instance), Some(instance));
        }
        let intrinsic = Intrinsic::of(&data);
        let key = shape_hash(&data, intrinsic);
        {
            let view = owner.read();
            if let Some(ids) = view.local.anonymous.get(&key) {
                for &id in ids {
                    let node = &view.local.nodes[id.slot];
                    if shape_eq(&node.data, node.intrinsic, &data, intrinsic) { return view.access().root(id); }
                }
            }
        }
        owner.writable()?;
        if !core { self.seal_core()?; }
        let id = TypeId { generation: owner.id, slot: owner.nodes.borrow().nodes.len() };
        let (staged, dependencies) = {
            let view = owner.read();
            Stage::build(view.access(), id, &data, intrinsic)?
        };
        if staged[&id].pending && !matches!(data.kind, DatatypeKind::Array { .. }) {
            return Err(graph_error("Anonymous aggregate layout is pending; reserve nominal dependencies first"));
        }
        let mut nodes = owner.nodes.try_borrow_mut().map_err(|_| busy())?;
        nodes.nodes.push(Node { data, intrinsic, state: TypeState::Complete, layout_ready: false,
            derived_ready: false, inferred: false, indexed: true, dependencies: Vec::new(),
            dependents: Vec::new(), key: Some(key), instance: NominalInstance::Unspecified, instance_constraint: None });
        update_reverse(&mut nodes, owner.id, id, &[], &dependencies);
        nodes.nodes[id.slot].dependencies = dependencies;
        apply_metadata(&mut nodes, owner.id, staged);
        nodes.anonymous.entry(key).or_default().push(id);
        drop(nodes);
        Ok(TypeRoot { generation: owner, identity: id })
    }
    pub(super) fn complete(&self, root: &TypeRoot, data: Datatype) -> KunaResult<()> {
        self.publish(root, data, false)
    }
    pub(super) fn correct_pending(&self, root: &TypeRoot, data: Datatype) -> KunaResult<()> {
        self.publish(root, data, true)
    }
    fn publish(&self, root: &TypeRoot, mut data: Datatype, correcting: bool) -> KunaResult<()> {
        normalize_leaf_kind(&mut data);
        self.check_owner(root)?;
        if root.id().generation == self.core.id {
            data.flags |= flags::coretype;
            if root.generation.frozen.get() && !correcting {
                let view = root.read();
                let node = view.access().node(root.id())?;
                if node.data.name == data.name && node.data.id == data.id
                    && shape_eq(&node.data, node.intrinsic, &data, Intrinsic::of(&data)) { return Ok(()); }
            }
        }
        root.generation.writable()?;
        if root.generation.core.is_some() { self.seal_core()?; }
        let intrinsic = Intrinsic::of(&data);
        let staged = {
            let view = root.read();
            let node = view.access().node(root.id())?;
            if correcting && (node.state != TypeState::Pending || node.key.is_some()) {
                return Err(graph_error("Only a provisional nominal aggregate can be corrected"));
            }
            if node.data.name != data.name || node.data.id != data.id {
                return Err(graph_error("Completion cannot replace nominal datatype identity"));
            }
            if matches!(node.state, TypeState::Complete | TypeState::Pending) && !correcting {
                if shape_eq(&node.data, node.intrinsic, &data, intrinsic) { return Ok(()); }
                return Err(graph_error("Conflicting completed datatype definition"));
            }
            if !reservation_compatible(&node.data, &data) {
                return Err(graph_error("Datatype completion changes reserved kind"));
            }
            Stage::build(view.access(), root.id(), &data, intrinsic)
        };
        let (staged, new_dependencies) = match staged {
            Ok(staged) => staged,
            Err(error) => {
                if !correcting && error.owner == root.id() {
                    let affected = self.host_source_dependents(root)?;
                    let mut nodes = root.generation.nodes.try_borrow_mut().map_err(|_| busy())?;
                    nodes.nodes[root.id().slot].state = TypeState::Failed(error.message.clone());
                    invalidate_host_sources(&mut nodes, affected.into_iter());
                    self.advance_host_mutation_epoch();
                }
                return Err(error.into());
            }
        };
        let mut nodes = root.generation.nodes.try_borrow_mut().map_err(|_| busy())?;
        let old_dependencies = std::mem::take(&mut nodes.nodes[root.id().slot].dependencies);
        update_reverse(&mut nodes, root.id().generation, root.id(), &old_dependencies, &new_dependencies);
        invalidate_host_sources(&mut nodes, staged.keys().copied());
        if correcting { self.advance_host_mutation_epoch(); }
        let node = &mut nodes.nodes[root.id().slot];
        node.dependencies = new_dependencies;
        let presentation = node.data.presentation_format.get();
        node.data = data; node.intrinsic = intrinsic; node.state = TypeState::Complete;
        if presentation.is_some() { node.data.presentation_format.set(presentation); }
        apply_metadata(&mut nodes, root.id().generation, staged);
        Ok(())
    }
    pub(super) fn retire_inferred(&self, roots: &[TypeRoot]) -> KunaResult<Vec<TypeId>> {
        let owner = Rc::clone(&self.active.borrow());
        owner.writable()?;
        let affected = {
            let view = owner.read();
            for root in roots {
                if root.id().generation != owner.id { return Err(graph_error("Only current noncore revisions can be retired")); }
                let node = view.access().node(root.id())?;
                if !node.inferred && (!node.data.name.is_empty() || node.data.id != 0) {
                    return Err(graph_error("Authoritative datatype definitions cannot be retired as inferred revisions"));
                }
            }
            let affected = dependent_closure(view.access(), roots.iter().map(TypeRoot::id))?;
            for &id in &affected {
                let node = view.access().node(id)?;
                if !node.inferred && (!node.data.name.is_empty() || node.data.id != 0) {
                    return Err(graph_error("An authoritative nominal definition retains this inferred revision"));
                }
            }
            affected
        };
        let mut store = owner.nodes.try_borrow_mut().map_err(|_| busy())?;
        invalidate_host_sources(&mut store, affected.iter().copied());
        if !affected.is_empty() { self.advance_host_mutation_epoch(); }
        for &id in &affected {
            let node = &mut store.nodes[id.slot];
            node.indexed = false;
            let name = (node.data.name.clone(), (node.data.id, node.instance));
            let key = node.key;
            if let Some(ids) = store.named.get_mut(&name.0) {
                if ids.get(&name.1) == Some(&id) { ids.remove(&name.1); }
                if ids.is_empty() { store.named.remove(&name.0); }
            }
            if let Some(key) = key {
                if let Some(ids) = store.anonymous.get_mut(&key) { ids.retain(|&existing| existing != id); }
            }
            // Bodies and identity-owned metadata remain readable through old roots.
        }
        Ok(affected)
    }
    pub(super) fn record_variant(&self, root: &TypeRoot, layout: crate::kuna_dwarfvariants::VariantLayout) -> KunaResult<()> {
        self.check_owner(root)?;
        if layout.type_id != root.id() { return Err(graph_error("Variant metadata owner identity mismatch")); }
        {
            let view = root.read();
            if let Some(existing) = view.variant_layout(root.id()) {
                return if existing == &layout { Ok(()) } else { Err(graph_error("Conflicting variant metadata for a published datatype identity")) };
            }
        }
        root.generation.writable()?;
        let mut edges = {
            let view = root.read();
            view.get(layout.union_type)?;
            for facet in &layout.variants {
                if let Some(payload) = facet.payload_type { view.get(payload)?; }
            }
            collect_edges(view.definition(root.id())?)
        };
        edges.push(layout.union_type);
        edges.extend(layout.variants.iter().filter_map(|facet| facet.payload_type));
        edges.sort_unstable(); edges.dedup();
        let affected = self.host_source_dependents(root)?;
        let mut store = root.generation.nodes.try_borrow_mut().map_err(|_| busy())?;
        invalidate_host_sources(&mut store, affected.into_iter());
        self.advance_host_mutation_epoch();
        let old = std::mem::take(&mut store.nodes[root.id().slot].dependencies);
        update_reverse(&mut store, root.id().generation, root.id(), &old, &edges);
        store.nodes[root.id().slot].dependencies = edges;
        store.variants.insert(root.id(), layout);
        Ok(())
    }
    pub(super) fn variant_types(&self) -> Vec<TypeRoot> {
        let active = self.active.borrow();
        [&self.core, &*active].into_iter().flat_map(|owner| {
            let store = owner.nodes.borrow();
            store.variants.keys().filter(|id| store.nodes[id.slot].indexed)
                .map(|&identity| TypeRoot { generation: Rc::clone(owner), identity }).collect::<Vec<_>>()
        }).collect()
    }
}

fn collect_edges(data: &Datatype) -> Vec<TypeId> {
    let mut edges = Vec::new();
    if let Some(id) = data.typedef_imm { edges.push(id); }
    match &data.kind {
        DatatypeKind::Pointer { ptrto, truncate, .. } => { edges.push(*ptrto); edges.extend(truncate); }
        DatatypeKind::PointerRel { ptrto, parent, stripped, .. } => { edges.extend([*ptrto, *parent]); edges.extend(stripped); }
        DatatypeKind::Array { arrayof, .. } => edges.push(*arrayof),
        DatatypeKind::Struct { field, bitfield } => {
            edges.extend(field.iter().map(|f| f.field_type));
            edges.extend(bitfield.iter().map(|f| f.field_type));
        }
        DatatypeKind::Union { field } => edges.extend(field.iter().map(|f| f.field_type)),
        DatatypeKind::PartialStruct { stripped, container, .. } | DatatypeKind::PartialUnion { stripped, container, .. } => edges.extend([*stripped, *container]),
        DatatypeKind::PartialEnum { stripped, parent, .. } => edges.extend([*stripped, *parent]),
        DatatypeKind::Code { proto: Some(proto) } => { edges.push(proto.output); edges.extend(&proto.inputs); }
        _ => (),
    }
    edges.sort_unstable(); edges.dedup();
    edges
}
fn update_reverse(nodes: &mut Nodes, generation: u64, owner: TypeId, old: &[TypeId], new: &[TypeId]) {
    for &id in old {
        if id.generation == generation && new.binary_search(&id).is_err() { nodes.nodes[id.slot].dependents.retain(|&parent| parent != owner); }
    }
    for &id in new {
        if id.generation == generation && old.binary_search(&id).is_err() {
            nodes.nodes[id.slot].dependents.push(owner);
        }
    }
}
fn invalidate_host_sources(nodes: &mut Nodes, affected: impl Iterator<Item = TypeId>) {
    for id in affected {
        if nodes.host_sources.contains_key(&id) { nodes.stale_host_sources.insert(id); }
    }
}

fn dependent_closure(graph: GraphAccess<'_>, roots: impl Iterator<Item = TypeId>) -> KunaResult<Vec<TypeId>> {
    let mut queue: VecDeque<TypeId> = roots.collect();
    let mut seen = HashSet::new();
    let mut affected = Vec::new();
    while let Some(id) = queue.pop_front() {
        if !seen.insert(id) { continue; }
        let node = graph.node(id)?;
        if !node.indexed { continue; }
        affected.push(id);
        queue.extend(node.dependents.iter().copied());
    }
    Ok(affected)
}

#[derive(Debug)]
struct StageError { owner: TypeId, message: String }
impl From<StageError> for KunaError {
    fn from(error: StageError) -> Self { graph_error(format!("Datatype {:?}: {}", error.owner, error.message)) }
}
type StageResult<T> = Result<T, StageError>;
#[derive(Clone, Copy)]
struct Metadata {
    size: int4, alignment: int4, align_size: int4,
    flags: uint4, submeta: sub_metatype, metatype: type_metatype,
    layout_ready: bool, derived_ready: bool, pending: bool,
    instance: NominalInstance,
}
impl Metadata {
    fn existing(node: &Node) -> Self {
        let d = &node.data;
        Self { size: d.size, alignment: d.alignment, align_size: d.align_size, flags: d.flags,
            submeta: d.submeta, metatype: d.metatype, layout_ready: node.layout_ready,
            derived_ready: node.derived_ready, pending: node.state == TypeState::Pending, instance: node.instance }
    }
}
struct Stage<'a> {
    graph: GraphAccess<'a>, candidate: TypeId, data: &'a Datatype, intrinsic: Intrinsic,
    affected: HashSet<TypeId>, metadata: HashMap<TypeId, Metadata>,
    layout_marks: HashSet<TypeId>, derived_marks: HashSet<TypeId>,
}
impl<'a> Stage<'a> {
    fn build(graph: GraphAccess<'a>, candidate: TypeId, data: &'a Datatype, intrinsic: Intrinsic) -> StageResult<(HashMap<TypeId, Metadata>, Vec<TypeId>)> {
        let mut affected = if candidate.slot < graph.local.nodes.len() {
            dependent_closure(graph, std::iter::once(candidate))
                .map_err(|e| StageError { owner: candidate, message: e.to_string() })?
        } else { vec![candidate] };
        let mut dependencies = collect_edges(data);
        if let Some(layout) = graph.local.variants.get(&candidate) {
            dependencies.push(layout.union_type);
            dependencies.extend(layout.variants.iter().filter_map(|facet| facet.payload_type));
            dependencies.sort_unstable(); dependencies.dedup();
        }
        for &id in &dependencies {
            graph.node(id).map_err(|e| StageError { owner: candidate, message: e.to_string() })?;
        }
        if let DatatypeKind::Code { proto: Some(proto) } = &data.kind {
            if graph.owner.model_context.get() != Some(proto.binding.context_id()) {
                return Err(StageError { owner: candidate, message: "Callable model belongs to another architecture context".into() });
            }
        }
        let mut stage = Self { graph, candidate, data, intrinsic, affected: affected.iter().copied().collect(),
            metadata: HashMap::with_capacity(affected.len()), layout_marks: HashSet::new(), derived_marks: HashSet::new() };
        // Only the changed reverse-dependency closure is visited. Body data stays borrowed.
        for &id in &affected { stage.layout(id, 0)?; }
        for &id in &affected { stage.derive(id, 0)?; }
        for id in affected.drain(..) { stage.derive_instance(id, 0)?; }
        stage.validate_instance_keys()?;
        Ok((stage.metadata, dependencies))
    }
    fn error(&self, id: TypeId, message: impl Into<String>) -> StageError { StageError { owner: id, message: message.into() } }
    fn data(&self, id: TypeId) -> StageResult<&'a Datatype> {
        if id == self.candidate { Ok(self.data) }
        else { Ok(&self.graph.node(id).map_err(|e| self.error(id, e.to_string()))?.data) }
    }
    fn intrinsic(&self, id: TypeId) -> StageResult<Intrinsic> {
        if id == self.candidate { Ok(self.intrinsic) }
        else { Ok(self.graph.node(id).map_err(|e| self.error(id, e.to_string()))?.intrinsic) }
    }
    fn defined(&self, id: TypeId) -> StageResult<bool> {
        if id == self.candidate { return Ok(true); }
        Ok(matches!(self.graph.node(id).map_err(|e| self.error(id, e.to_string()))?.state, TypeState::Complete | TypeState::Pending))
    }
    fn effective(&self, mut id: TypeId) -> StageResult<Option<TypeId>> {
        for _ in 0..=self.graph.len() + 1 {
            let d = self.data(id)?;
            if !matches!(d.kind, DatatypeKind::Alias) { return Ok(Some(id)); }
            match d.typedef_imm { Some(base) => id = base, None => return Ok(None) }
        }
        Err(self.error(self.candidate, "Impossible cyclic typedef"))
    }
    fn validate_callable_type(&self, owner: TypeId, mut id: TypeId, output: bool) -> StageResult<()> {
        for _ in 0..=self.graph.len() + 1 {
            if id != self.candidate {
                let node = self.graph.node(id).map_err(|e| self.error(owner, e.to_string()))?;
                if let TypeState::Failed(message) = &node.state { return Err(self.error(owner, message.clone())); }
            }
            let data = self.data(id)?;
            if matches!(data.kind, DatatypeKind::Alias) {
                match data.typedef_imm { Some(target) => { id = target; continue; }, None => return Ok(()) }
            }
            if matches!(data.kind, DatatypeKind::Code { .. }) || (!output && matches!(data.kind, DatatypeKind::Void)) {
                return Err(self.error(owner, "Invalid by-value callable type"));
            }
            return Ok(());
        }
        Err(self.error(owner, "Impossible cyclic typedef"))
    }
    fn derive_instance(&mut self, id: TypeId, depth: usize) -> StageResult<NominalInstance> {
        if !self.affected.contains(&id) {
            return Ok(self.graph.node(id).map_err(|e| self.error(id, e.to_string()))?.instance);
        }
        if depth > self.graph.len() + 1 { return Err(self.error(id, "Impossible cyclic typedef")); }
        let data = self.data(id)?;
        let node = if id.slot < self.graph.local.nodes.len() { Some(self.graph.node(id).map_err(|e| self.error(id, e.to_string()))?) } else { None };
        let constraint = node.and_then(|n| n.instance_constraint);
        let mut instance = if !self.defined(id)? {
            node.map_or(NominalInstance::Unspecified, |n| n.instance)
        } else if matches!(data.kind, DatatypeKind::Alias) {
            match data.typedef_imm {
                Some(target) => match self.derive_instance(target, depth + 1)? {
                    NominalInstance::Known(instance) => NominalInstance::Known(instance),
                    _ => NominalInstance::Target(target),
                },
                None => NominalInstance::Unspecified,
            }
        } else {
            let m = self.metadata[&id];
            NominalInstance::Known(if m.flags & flags::variable_length != 0 { TypeInstance::Sized(m.size) } else { TypeInstance::Fixed })
        };
        if let Some(expected) = constraint {
            if matches!(instance, NominalInstance::Known(actual) if actual != expected) {
                return Err(self.error(id, "Datatype definition violates its instance constraint"));
            }
            instance = NominalInstance::Known(expected);
        }
        self.metadata.get_mut(&id).expect("staged metadata").instance = instance;
        Ok(instance)
    }
    fn validate_instance_keys(&self) -> StageResult<()> {
        let mut proposed = HashMap::new();
        for (&id, m) in &self.metadata {
            let data = self.data(id)?;
            if data.name.is_empty() && data.id == 0 { continue; }
            if id.slot < self.graph.local.nodes.len() && !self.graph.node(id).map_err(|e| self.error(id, e.to_string()))?.indexed { continue; }
            let key = (data.name.as_str(), data.id, m.instance);
            if proposed.insert(key, id).is_some_and(|old| old != id) {
                return Err(self.error(self.candidate, "Conflicting datatype instance definitions"));
            }
            for store in std::iter::once(self.graph.local).chain(self.graph.core) {
                if let Some(&old) = store.named.get(&data.name).and_then(|ids| ids.get(&(data.id, m.instance))) {
                    if old != id && self.metadata.get(&old).is_none_or(|old_m| old_m.instance == m.instance) {
                        return Err(self.error(self.candidate, "Conflicting datatype instance definitions"));
                    }
                }
            }
        }
        Ok(())
    }
    fn layout(&mut self, id: TypeId, depth: usize) -> StageResult<Metadata> {
        if let Some(m) = self.metadata.get(&id) { return Ok(*m); }
        if !self.affected.contains(&id) {
            return Ok(Metadata::existing(self.graph.node(id).map_err(|e| self.error(id, e.to_string()))?));
        }
        if depth > 1024 { return Err(self.error(id, "Datatype nesting exceeds supported validation depth")); }
        if !self.layout_marks.insert(id) { return Err(self.error(self.candidate, "Impossible by-value datatype cycle")); }
        let d = self.data(id)?;
        let intrinsic = self.intrinsic(id)?;
        let defined = self.defined(id)?;
        let mut m = Metadata { size: intrinsic.size, alignment: intrinsic.alignment,
            align_size: intrinsic.size, flags: intrinsic.flags | (d.flags & (flags::force_format | flags::warning_issued | flags::coretype)),
            submeta: intrinsic.submeta, metatype: intrinsic.metatype,
            layout_ready: defined && intrinsic.flags & flags::type_incomplete == 0,
            derived_ready: false, pending: false, instance: NominalInstance::Unspecified };
        if !defined {
            m.flags |= flags::type_incomplete;
            if matches!(d.kind, DatatypeKind::Union { .. }) { m.flags |= flags::needs_resolution; }
            self.layout_marks.remove(&id);
            self.metadata.insert(id, m);
            return Ok(m);
        }
        match &d.kind {
            DatatypeKind::Alias => {
                let base = d.typedef_imm.ok_or_else(|| self.error(id, "Alias has no target"))?;
                let target = self.layout(base, depth + 1)?;
                m.size = target.size; m.alignment = target.alignment; m.align_size = target.align_size;
                m.metatype = target.metatype; m.submeta = target.submeta;
                m.layout_ready = target.layout_ready;
            }
            DatatypeKind::Void => { m.size = 0; m.alignment = 1; m.layout_ready = true; }
            DatatypeKind::Code { proto } => {
                m.layout_ready = false;
                if let Some(proto) = proto {
                    if proto.logical_first.is_some_and(|first| first < 0 || first as usize > proto.inputs.len()) {
                        return Err(self.error(id, "Invalid logical variadic boundary"));
                    }
                    for (ty, output) in std::iter::once((proto.output, true)).chain(proto.inputs.iter().map(|&ty| (ty, false))) {
                        self.validate_callable_type(id, ty, output)?;
                    }
                }
            }
            DatatypeKind::Array { arrayof, arraysize } => {
                if *arraysize < 0 { return Err(self.error(id, "Negative array length")); }
                let child = self.layout(*arrayof, depth + 1)?;
                m.layout_ready = child.layout_ready;
                if child.layout_ready {
                    m.size = child.align_size.checked_mul(*arraysize).ok_or_else(|| self.error(id, "Array layout overflow"))?;
                    m.alignment = child.alignment;
                }
                m.pending = !m.layout_ready;
            }
            DatatypeKind::Struct { field, bitfield } => {
                for f in field {
                    let child = self.layout(f.field_type, depth + 1)?;
                    self.validate_field(id, f.offset, child, intrinsic.size)?;
                    m.layout_ready &= child.layout_ready;
                    if self.effective(f.field_type)?.is_some_and(|ty| matches!(self.data(ty).map(|d| &d.kind), Ok(DatatypeKind::Void | DatatypeKind::Code { .. }))) {
                        return Err(self.error(id, "Unsized structure field"));
                    }
                }
                for b in bitfield {
                    let child = self.layout(b.field_type, depth + 1)?;
                    m.layout_ready &= child.layout_ready;
                    if b.byte_offset < 0 || b.byte_size < 0 || b.num_bits < 0 || b.least_sig_bit < 0
                        || b.byte_offset.checked_add(b.byte_size).is_none_or(|end| end > intrinsic.size)
                        || b.least_sig_bit.checked_add(b.num_bits).is_none_or(|end| i64::from(end) > i64::from(b.byte_size) * 8) {
                        return Err(self.error(id, "Invalid bitfield storage geometry"));
                    }
                    if child.layout_ready && (!matches!(child.metatype,
                        type_metatype::TYPE_INT | type_metatype::TYPE_UINT | type_metatype::TYPE_BOOL
                        | type_metatype::TYPE_ENUM_INT | type_metatype::TYPE_ENUM_UINT)
                        || i64::from(b.num_bits) > i64::from(child.size) * 8) {
                        return Err(self.error(id, "Bitfield width or underlying integer type is invalid"));
                    }
                }
                m.pending = !m.layout_ready;
            }
            DatatypeKind::Union { field } => {
                for f in field {
                    let child = self.layout(f.field_type, depth + 1)?;
                    if f.offset != 0 { return Err(self.error(id, "Union field has nonzero offset")); }
                    self.validate_field(id, 0, child, intrinsic.size)?;
                    m.layout_ready &= child.layout_ready;
                    if self.effective(f.field_type)?.is_some_and(|ty| matches!(self.data(ty).map(|d| &d.kind), Ok(DatatypeKind::Void | DatatypeKind::Code { .. }))) {
                        return Err(self.error(id, "Unsized union field"));
                    }
                }
                m.pending = !m.layout_ready;
            }
            DatatypeKind::Pointer { wordsize, .. } | DatatypeKind::PointerRel { wordsize, .. } => {
                if m.size <= 0 || *wordsize == 0 { return Err(self.error(id, "Invalid pointer layout")); }
            }
            DatatypeKind::PartialStruct { container, offset, .. } | DatatypeKind::PartialUnion { container, offset, .. } => {
                let parent = self.layout(*container, depth + 1)?;
                m.layout_ready &= parent.layout_ready;
                if *offset < 0 || (parent.layout_ready && offset.checked_add(m.size).is_none_or(|end| end > parent.size)) {
                    return Err(self.error(id, "Partial datatype exceeds containing layout"));
                }
                m.pending = !m.layout_ready;
            }
            DatatypeKind::PartialEnum { parent, offset, .. } => {
                let parent = self.layout(*parent, depth + 1)?;
                m.layout_ready &= parent.layout_ready;
                if *offset < 0 { return Err(self.error(id, "Negative partial enum offset")); }
            }
            _ => (),
        }
        if m.size < 0 { return Err(self.error(id, "Negative datatype size")); }
        if m.alignment <= 0 {
            if m.layout_ready && !matches!(d.kind, DatatypeKind::Code { .. }) { return Err(self.error(id, "Datatype alignment is not positive")); }
            m.alignment = 1;
        }
        m.align_size = m.size.checked_add(m.alignment - 1).map(|size| (size / m.alignment) * m.alignment)
            .ok_or_else(|| self.error(id, "Aligned datatype size overflow"))?;
        if !m.layout_ready && !matches!(d.kind, DatatypeKind::Code { .. }) { m.flags |= flags::type_incomplete; }
        self.layout_marks.remove(&id);
        self.metadata.insert(id, m);
        Ok(m)
    }
    fn validate_field(&self, id: TypeId, offset: int4, child: Metadata, size: int4) -> StageResult<()> {
        if offset < 0 || (child.layout_ready && offset.checked_add(child.size).is_none_or(|end| end > size)) {
            return Err(self.error(id, "Field lies outside its containing layout"));
        }
        Ok(())
    }
    fn derive(&mut self, id: TypeId, depth: usize) -> StageResult<Metadata> {
        if !self.affected.contains(&id) { return self.layout(id, depth); }
        let mut m = self.layout(id, depth)?;
        if m.derived_ready { return Ok(m); }
        if depth > 1024 { return Err(self.error(id, "Datatype nesting exceeds supported metadata depth")); }
        if !self.derived_marks.insert(id) { return Err(self.error(self.candidate, "Impossible by-value metadata cycle")); }
        let d = self.data(id)?;
        if !self.defined(id)? {
            m.derived_ready = matches!(d.kind, DatatypeKind::Union { .. });
        } else {
            m.derived_ready = true;
            match &d.kind {
                DatatypeKind::Alias => {
                    let target = self.derive(d.typedef_imm.ok_or_else(|| self.error(id, "Alias has no target"))?, depth + 1)?;
                    m.flags = (target.flags & !(flags::coretype | flags::force_format))
                        | (d.flags & (flags::coretype | flags::force_format));
                    m.submeta = target.submeta; m.metatype = target.metatype;
                    m.derived_ready = target.derived_ready;
                }
                DatatypeKind::Struct { field, bitfield } => {
                    m.flags &= !(flags::needs_resolution | flags::has_bitfields);
                    if !bitfield.is_empty() { m.flags |= flags::has_bitfields; }
                    for f in field {
                        let child = self.containment(f.field_type, depth + 1)?;
                        m.flags |= child.flags & flags::has_bitfields;
                        m.derived_ready &= child.derived_ready;
                    }
                    if field.len() == 1 && field[0].offset == 0 && self.layout(field[0].field_type, depth + 1)?.size == m.size {
                        m.flags |= flags::needs_resolution;
                    }
                    m.derived_ready &= m.layout_ready;
                }
                DatatypeKind::Union { field } => {
                    m.flags |= flags::needs_resolution;
                    for f in field { m.flags |= self.containment(f.field_type, depth + 1)?.flags & flags::has_bitfields; }
                    m.derived_ready &= m.layout_ready;
                }
                DatatypeKind::Array { arrayof, arraysize } => {
                    let child = self.containment(*arrayof, depth + 1)?;
                    m.flags |= child.flags & flags::has_bitfields;
                    if *arraysize == 1 { m.flags |= flags::needs_resolution; }
                    m.derived_ready = child.derived_ready && m.layout_ready;
                }
                DatatypeKind::Pointer { ptrto, .. } | DatatypeKind::PointerRel { ptrto, .. } => {
                    m.flags &= !(flags::needs_resolution | flags::pointer_to_array | flags::has_bitfields);
                    m.submeta = base2sub(m.metatype);
                    if let Some(target) = self.effective(*ptrto)? {
                        let target_data = self.data(target)?;
                        // Stop before core cached pointer metadata as well as local pointer metadata.
                        let pointer_target = matches!(target_data.kind, DatatypeKind::Pointer { .. } | DatatypeKind::PointerRel { .. });
                        let target_meta = if pointer_target { self.layout(target, depth + 1)? }
                            else { self.derive(target, depth + 1)? };
                        m.flags |= target_meta.flags & flags::warning_issued;
                        if !pointer_target && target_meta.flags & flags::needs_resolution != 0 { m.flags |= flags::needs_resolution; }
                        match target_meta.metatype {
                            type_metatype::TYPE_STRUCT => {
                                if target_meta.flags & flags::needs_resolution == 0 { m.submeta = sub_metatype::SUB_PTR_STRUCT; }
                            }
                            type_metatype::TYPE_UNION => m.submeta = sub_metatype::SUB_PTR_STRUCT,
                            type_metatype::TYPE_ARRAY => m.flags |= flags::pointer_to_array,
                            _ => (),
                        }
                        if let DatatypeKind::PointerRel { stripped, .. } = &d.kind {
                            m.submeta = if stripped.is_some() && target_meta.metatype == type_metatype::TYPE_UNKNOWN {
                                sub_metatype::SUB_PTRREL_UNK
                            } else { sub_metatype::SUB_PTRREL };
                        }
                        m.derived_ready = pointer_target || target_meta.derived_ready;
                    } else { m.derived_ready = false; }
                }
                DatatypeKind::PartialStruct { container, offset, .. } => {
                    if self.has_bits_in_range(*container, *offset, m.size, depth + 1)? { m.flags |= flags::has_bitfields; }
                    m.flags |= self.derive(*container, depth + 1)?.flags & flags::warning_issued;
                    m.derived_ready = m.layout_ready;
                }
                DatatypeKind::PartialUnion { container, .. } => {
                    m.flags |= flags::needs_resolution;
                    m.flags |= self.derive(*container, depth + 1)?.flags & flags::warning_issued;
                    m.derived_ready = m.layout_ready;
                }
                DatatypeKind::PartialEnum { parent, .. } => {
                    m.flags |= self.derive(*parent, depth + 1)?.flags & flags::warning_issued;
                    m.derived_ready = m.layout_ready;
                }
                _ => (),
            }
        }
        if !m.derived_ready && !matches!(d.kind, DatatypeKind::Code { .. }) { m.flags |= flags::type_incomplete; }
        self.derived_marks.remove(&id);
        self.metadata.insert(id, m);
        Ok(m)
    }
    fn containment(&mut self, id: TypeId, depth: usize) -> StageResult<Metadata> {
        if let Some(target) = self.effective(id)? {
            if matches!(self.data(target)?.kind, DatatypeKind::Pointer { .. } | DatatypeKind::PointerRel { .. } | DatatypeKind::Code { .. }) {
                let mut m = self.layout(id, depth)?;
                m.flags &= !(flags::has_bitfields | flags::needs_resolution);
                m.derived_ready = true;
                return Ok(m);
            }
        }
        self.derive(id, depth)
    }
    fn has_bits_in_range(&self, id: TypeId, offset: int4, size: int4, depth: usize) -> StageResult<bool> {
        if depth > 1024 { return Err(self.error(id, "Datatype nesting exceeds supported bitfield depth")); }
        let Some(id) = self.effective(id)? else { return Ok(false); };
        let end = i64::from(offset) + i64::from(size);
        match &self.data(id)?.kind {
            DatatypeKind::Struct { field, bitfield } => {
                if bitfield.iter().any(|b| i64::from(b.byte_offset) < end
                    && i64::from(b.byte_offset) + i64::from(b.byte_size) > i64::from(offset)) { return Ok(true); }
                for f in field {
                    if i64::from(f.offset) < end && self.has_bits_in_range(f.field_type, offset.saturating_sub(f.offset), size, depth + 1)? { return Ok(true); }
                }
                Ok(false)
            }
            DatatypeKind::Union { field } => {
                for f in field { if self.has_bits_in_range(f.field_type, offset, size, depth + 1)? { return Ok(true); } }
                Ok(false)
            }
            DatatypeKind::Array { arrayof, arraysize } => {
                let child = self.metadata.get(arrayof).copied().unwrap_or_else(|| Metadata::existing(self.graph.node(*arrayof).expect("validated array dependency")));
                if child.align_size <= 0 || *arraysize <= 0 { return Ok(false); }
                let first = (offset.max(0) / child.align_size).min(*arraysize);
                let last = ((end.max(0) + i64::from(child.align_size) - 1) / i64::from(child.align_size)).min(i64::from(*arraysize));
                for index in i64::from(first)..last {
                    let relative = i64::from(offset) - index * i64::from(child.align_size);
                    if let Ok(relative) = int4::try_from(relative) {
                        if self.has_bits_in_range(*arrayof, relative, size, depth + 1)? { return Ok(true); }
                    }
                }
                Ok(false)
            }
            DatatypeKind::PartialStruct { container, offset: part_offset, .. } => {
                let relative = offset.checked_add(*part_offset).ok_or_else(|| self.error(id, "Partial bitfield offset overflow"))?;
                self.has_bits_in_range(*container, relative, size, depth + 1)
            }
            _ => Ok(false),
        }
    }
}
fn apply_metadata(nodes: &mut Nodes, generation: u64, metadata: HashMap<TypeId, Metadata>) {
    for (&id, m) in &metadata {
        if id.generation != generation { continue; }
        let node = &nodes.nodes[id.slot];
        if node.indexed && node.instance != m.instance {
            if let Some(ids) = nodes.named.get_mut(&node.data.name) { ids.remove(&(node.data.id, node.instance)); }
        }
    }
    for (id, m) in metadata {
        if id.generation != generation { continue; }
        let node = &mut nodes.nodes[id.slot];
        if node.indexed && node.instance != m.instance && (!node.data.name.is_empty() || node.data.id != 0) {
            nodes.named.entry(node.data.name.clone()).or_default().insert((node.data.id, m.instance), id);
        }
        node.instance = m.instance;
        node.data.size = m.size; node.data.alignment = m.alignment; node.data.align_size = m.align_size;
        node.data.flags = m.flags; node.data.submeta = m.submeta; node.data.metatype = m.metatype;
        node.layout_ready = m.layout_ready; node.derived_ready = m.derived_ready;
        if matches!(node.state, TypeState::Complete | TypeState::Pending) {
            node.state = if m.pending { TypeState::Pending } else { TypeState::Complete };
        }
    }
}

fn intrinsic_key(data: &Datatype, intrinsic: Intrinsic) -> (int4, int4, type_metatype, uint4) {
    match data.kind {
        DatatypeKind::Array { .. } => (0, 0, type_metatype::TYPE_ARRAY, intrinsic.flags),
        DatatypeKind::Alias => (0, 0, type_metatype::TYPE_UNKNOWN, intrinsic.flags),
        _ => (intrinsic.size, intrinsic.alignment, intrinsic.metatype, intrinsic.flags),
    }
}
fn space_key(space: Option<&Rc<AddrSpace>>) -> Option<usize> { space.map(|space| Rc::as_ptr(space) as usize) }
fn field_key(field: &TypeField) -> (int4, int4, &str, TypeId) { (field.ident, field.offset, &field.name, field.field_type) }
fn bitfield_key(field: &TypeBitField) -> (int4, &str, TypeId, int4, int4, int4, int4, bool) {
    (field.ident, &field.name, field.field_type, field.byte_offset, field.byte_size, field.least_sig_bit, field.num_bits, field.is_big_endian)
}
fn shape_hash(data: &Datatype, intrinsic: Intrinsic) -> u64 {
    let mut h = std::collections::hash_map::DefaultHasher::new();
    intrinsic_key(data, intrinsic).hash(&mut h);
    std::mem::discriminant(&data.kind).hash(&mut h);
    data.typedef_imm.hash(&mut h);
    match &data.kind {
        DatatypeKind::Pointer { ptrto, spaceid, truncate, wordsize } => (ptrto, space_key(spaceid.as_ref()), truncate, wordsize).hash(&mut h),
        DatatypeKind::PointerRel { ptrto, spaceid, wordsize, stripped, parent, offset } => (ptrto, space_key(spaceid.as_ref()), wordsize, stripped, parent, offset).hash(&mut h),
        DatatypeKind::Array { arrayof, arraysize } => (arrayof, arraysize).hash(&mut h),
        DatatypeKind::Struct { field, bitfield } => {
            field.len().hash(&mut h); for f in field { field_key(f).hash(&mut h); }
            bitfield.len().hash(&mut h); for f in bitfield { bitfield_key(f).hash(&mut h); }
        }
        DatatypeKind::Union { field } => { field.len().hash(&mut h); for f in field { field_key(f).hash(&mut h); } }
        DatatypeKind::Enum { namemap } => namemap.hash(&mut h),
        DatatypeKind::Code { proto } => proto.hash(&mut h),
        DatatypeKind::Spacebase { spaceid, localframe } => (space_key(spaceid.as_ref()), space_key(localframe.get_space()), localframe.get_offset()).hash(&mut h),
        DatatypeKind::PartialStruct { stripped, container, offset } | DatatypeKind::PartialUnion { stripped, container, offset } => (stripped, container, offset).hash(&mut h),
        DatatypeKind::PartialEnum { stripped, parent, offset } => (stripped, parent, offset).hash(&mut h),
        _ => (),
    }
    h.finish()
}
fn shape_eq(a: &Datatype, ai: Intrinsic, b: &Datatype, bi: Intrinsic) -> bool {
    if intrinsic_key(a, ai) != intrinsic_key(b, bi) || a.typedef_imm != b.typedef_imm { return false; }
    match (&a.kind, &b.kind) {
        (DatatypeKind::Base, DatatypeKind::Base) | (DatatypeKind::Unknown, DatatypeKind::Unknown)
        | (DatatypeKind::Void, DatatypeKind::Void) | (DatatypeKind::Alias, DatatypeKind::Alias) => true,
        (DatatypeKind::Pointer { ptrto: a, spaceid: sa, truncate: ta, wordsize: wa },
         DatatypeKind::Pointer { ptrto: b, spaceid: sb, truncate: tb, wordsize: wb }) =>
            a == b && space_key(sa.as_ref()) == space_key(sb.as_ref()) && ta == tb && wa == wb,
        (DatatypeKind::PointerRel { ptrto: a, spaceid: spa, wordsize: wa, stripped: sa, parent: pa, offset: oa },
         DatatypeKind::PointerRel { ptrto: b, spaceid: spb, wordsize: wb, stripped: sb, parent: pb, offset: ob }) =>
            a == b && space_key(spa.as_ref()) == space_key(spb.as_ref()) && wa == wb && sa == sb && pa == pb && oa == ob,
        (DatatypeKind::Array { arrayof: a, arraysize: na }, DatatypeKind::Array { arrayof: b, arraysize: nb }) => a == b && na == nb,
        (DatatypeKind::Struct { field: a, bitfield: ba }, DatatypeKind::Struct { field: b, bitfield: bb }) =>
            a.iter().map(field_key).eq(b.iter().map(field_key)) && ba.iter().map(bitfield_key).eq(bb.iter().map(bitfield_key)),
        (DatatypeKind::Union { field: a }, DatatypeKind::Union { field: b }) => a.iter().map(field_key).eq(b.iter().map(field_key)),
        (DatatypeKind::Enum { namemap: a }, DatatypeKind::Enum { namemap: b }) => a == b,
        (DatatypeKind::Code { proto: a }, DatatypeKind::Code { proto: b }) => a == b,
        (DatatypeKind::Spacebase { spaceid: sa, localframe: a }, DatatypeKind::Spacebase { spaceid: sb, localframe: b }) =>
            space_key(sa.as_ref()) == space_key(sb.as_ref()) && a == b,
        (DatatypeKind::PartialStruct { stripped: a, container: ca, offset: oa }, DatatypeKind::PartialStruct { stripped: b, container: cb, offset: ob })
        | (DatatypeKind::PartialUnion { stripped: a, container: ca, offset: oa }, DatatypeKind::PartialUnion { stripped: b, container: cb, offset: ob }) =>
            a == b && ca == cb && oa == ob,
        (DatatypeKind::PartialEnum { stripped: a, parent: pa, offset: oa }, DatatypeKind::PartialEnum { stripped: b, parent: pb, offset: ob }) =>
            a == b && pa == pb && oa == ob,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn scalar(graph: &GraphStore) -> TypeRoot {
        graph.intern_core(Datatype::new_with_align(4, 4, type_metatype::TYPE_INT)).unwrap()
    }
    fn pointer(target: TypeId) -> Datatype {
        let mut d = Datatype::new_with_align(8, 8, type_metatype::TYPE_PTR);
        d.kind = DatatypeKind::Pointer { ptrto: target, spaceid: None, truncate: None, wordsize: 1 };
        d
    }
    fn record(root: &TypeRoot, size: int4, fields: Vec<TypeField>) -> Datatype {
        let view = root.read();
        let old = view.definition(root.id()).unwrap();
        let mut d = Datatype::new_with_align(size, 8, type_metatype::TYPE_STRUCT);
        d.name = old.name.clone(); d.display_name = old.display_name.clone(); d.id = old.id;
        d.kind = DatatypeKind::Struct { field: fields, bitfield: Vec::new() };
        d
    }
    fn alias(root: &TypeRoot, target: TypeId) -> Datatype {
        let view = root.read();
        let old = view.definition(root.id()).unwrap();
        let mut d = Datatype::new_with_align(0, 1, type_metatype::TYPE_UNKNOWN);
        d.name = old.name.clone(); d.display_name = old.display_name.clone(); d.id = old.id;
        d.kind = DatatypeKind::Alias; d.typedef_imm = Some(target);
        d
    }

    #[test]
    fn core_alias_instance_finalizes_before_seal_and_stays_readable_after_flush() {
        let graph = GraphStore::new();
        let mut code = Datatype::new_with_align(1, 1, type_metatype::TYPE_CODE);
        code.name = "CoreCallable".into(); code.display_name = code.name.clone(); code.id = 901;
        code.kind = DatatypeKind::Code { proto: None };
        code.flags = flags::type_incomplete | flags::variable_length;
        let root = graph.intern_core(code.clone()).unwrap();
        let alias_root = graph.reserve_alias_instance("CoreAlias", 902, Some(TypeInstance::Sized(1)), Some(root.id()), true).unwrap();
        graph.complete(&alias_root, alias(&alias_root, root.id())).unwrap();
        assert!(graph.seal_core().is_err());
        code.flags &= !flags::type_incomplete;
        code.flags |= flags::coretype;
        graph.complete(&root, code).unwrap();
        graph.seal_core().unwrap();
        graph.flush().unwrap();
        assert_eq!(graph.find_instance("CoreAlias", 902, TypeInstance::Sized(1)).unwrap().id(), alias_root.id());
        assert_eq!(alias_root.get_unsized_id().unwrap(), 902);
        assert!(graph.constrain_instance(&alias_root, TypeInstance::Sized(2)).is_err());
    }

    #[test]
    fn early_pointer_alias_and_field_tokens_observe_one_completion() {
        let graph = GraphStore::new();
        let int = scalar(&graph);
        let node = graph.reserve("Node", 101, type_metatype::TYPE_STRUCT, false).unwrap();
        let ptr = graph.intern(pointer(node.id())).unwrap();
        let named_alias = graph.reserve_alias("NodeAlias", 102).unwrap();
        graph.complete(&named_alias, alias(&named_alias, node.id())).unwrap();
        assert!(!node.read().layout_ready(node.id()).unwrap());
        assert!(ptr.read().layout_ready(ptr.id()).unwrap());
        assert!(!ptr.read().derived_ready(ptr.id()).unwrap());
        graph.complete(&node, record(&node, 16, vec![
            TypeField::new(71, 0, "next", ptr.id()),
            TypeField::new(-17, 8, "value", int.id()),
        ])).unwrap();
        let view = named_alias.read();
        let next = view.get_ptr_to(view.get_field(named_alias.id(), 0).unwrap().unwrap().field_type).unwrap().unwrap();
        let value = view.get_field(next, 1).unwrap().unwrap();
        assert_eq!((value.ident, value.offset, value.name.as_str()), (-17, 8, "value"));
        assert_eq!(view.definition(named_alias.id()).unwrap().name, "NodeAlias");
        assert_eq!(view.definition(named_alias.id()).unwrap().id, 102);
        assert_eq!(view.definition(named_alias.id()).unwrap().size, 16);
        assert!(view.derived_ready(ptr.id()).unwrap());
        assert_eq!(view.definition(ptr.id()).unwrap().submeta, sub_metatype::SUB_PTR_STRUCT);
        drop(view);
        assert_eq!(graph.intern(pointer(node.id())).unwrap(), ptr);
        assert_eq!(graph.find_instance("Node", 101, TypeInstance::Fixed).unwrap(), node);
    }

    #[test]
    fn pending_parent_correction_preserves_valid_child_in_both_orders() {
        for parent_first in [true, false] {
            let graph = GraphStore::new();
            let child = graph.reserve("Child", 201, type_metatype::TYPE_STRUCT, false).unwrap();
            let parent = graph.reserve("Parent", 202, type_metatype::TYPE_STRUCT, false).unwrap();
            let fields = || vec![TypeField::new(33, 0, "child", child.id())];
            if parent_first {
                graph.complete(&parent, record(&parent, 8, fields())).unwrap();
                assert_eq!(graph.state(&parent).unwrap(), TypeState::Pending);
                graph.begin(&child).unwrap();
                assert!(graph.complete(&child, record(&child, 16, vec![])).is_err());
                assert_eq!(graph.state(&child).unwrap(), TypeState::Loading);
                assert!(graph.correct_pending(&parent, record(&parent, -1, fields())).is_err());
                assert_eq!(parent.get_size(), 8);
                graph.correct_pending(&parent, record(&parent, 16, fields())).unwrap();
                graph.complete(&child, record(&child, 16, vec![])).unwrap();
            } else {
                graph.complete(&child, record(&child, 16, vec![])).unwrap();
                assert!(graph.complete(&parent, record(&parent, 8, fields())).is_err());
                graph.complete(&parent, record(&parent, 16, fields())).unwrap();
            }
            assert_eq!(parent.get_size(), 16);
            assert_eq!(child.get_size(), 16);
            assert_eq!(graph.state(&parent).unwrap(), TypeState::Complete);
            assert!(graph.correct_pending(&parent, record(&parent, 32, vec![])).is_err());
            assert_eq!(parent.read().get_field(parent.id(), 0).unwrap().unwrap().field_type, child.id());
        }
    }

    #[test]
    fn failed_bitfield_layout_propagates_through_pending_partial() {
        let graph = GraphStore::new();
        let stripped = scalar(&graph);
        let base = graph.reserve_alias("BitBase", 211).unwrap();
        let parent = graph.reserve("BitParent", 212, type_metatype::TYPE_STRUCT, false).unwrap();
        let mut draft = record(&parent, 8, vec![]);
        draft.kind = DatatypeKind::Struct {
            field: vec![],
            bitfield: vec![TypeBitField::new(-13, 3, false, "bits", base.id())],
        };
        graph.complete(&parent, draft).unwrap();
        let partial = graph.reserve("BitPartial", 213, type_metatype::TYPE_PARTIALSTRUCT, false).unwrap();
        let mut part = Datatype::new_with_align(4, 4, type_metatype::TYPE_PARTIALSTRUCT);
        part.name = "BitPartial".into();
        part.id = 213;
        part.kind = DatatypeKind::PartialStruct { stripped: stripped.id(), container: parent.id(), offset: 0 };
        graph.complete(&partial, part).unwrap();
        assert!(!partial.read().layout_ready(partial.id()).unwrap());
        graph.fail(&base, "Missing bitfield base".into()).unwrap();
        assert!(parent.read().layout_ready(parent.id()).is_err());
        assert!(partial.read().layout_ready(partial.id()).is_err());
    }

    #[test]
    fn core_pointer_boundary_and_opaque_union_alias_preserve_metadata() {
        let graph = GraphStore::new();
        let mut u = Datatype::new_with_align(8, 8, type_metatype::TYPE_UNION);
        u.name = "CoreUnion".into(); u.id = 301; u.kind = DatatypeKind::Union { field: vec![] };
        let core_union = graph.intern_core(u).unwrap();
        let core_pointer = graph.intern_core(pointer(core_union.id())).unwrap();
        let outer = graph.intern(pointer(core_pointer.id())).unwrap();
        assert!(!outer.needs_resolution());
        assert_eq!(outer.get_sub_meta(), sub_metatype::SUB_PTR);
        let opaque = graph.reserve("Union", 302, type_metatype::TYPE_UNION, false).unwrap();
        let aliased = graph.reserve_alias("UnionAlias", 303).unwrap();
        graph.complete(&aliased, alias(&aliased, opaque.id())).unwrap();
        let direct = graph.intern(pointer(opaque.id())).unwrap();
        let through_alias = graph.intern(pointer(aliased.id())).unwrap();
        for loading in [false, true] {
            if loading { graph.begin(&opaque).unwrap(); }
            assert!(direct.needs_resolution());
            assert!(through_alias.needs_resolution());
            assert_eq!(through_alias.get_sub_meta(), sub_metatype::SUB_PTR_STRUCT);
            assert!(through_alias.read().derived_ready(through_alias.id()).unwrap());
        }
    }

    #[test]
    fn cyclic_generation_reclaims_and_core_root_does_not_pin_it() {
        let graph = GraphStore::new();
        let int = scalar(&graph);
        let node = graph.reserve("Node", 401, type_metatype::TYPE_STRUCT, false).unwrap();
        let ptr = graph.intern(pointer(node.id())).unwrap();
        graph.complete(&node, record(&node, 8, vec![TypeField::new(0, 0, "next", ptr.id())])).unwrap();
        let old = Rc::downgrade(&node.generation);
        let retained_core = node.related(int.id()).unwrap();
        graph.flush().unwrap();
        let fresh = graph.reserve("Node", 401, type_metatype::TYPE_STRUCT, false).unwrap();
        graph.complete(&fresh, record(&fresh, 16, vec![])).unwrap();
        assert_ne!(node.id(), fresh.id());
        assert_eq!(node.get_size(), 8);
        assert_eq!(fresh.get_size(), 16);
        assert!(graph.intern(pointer(node.id())).is_err());
        assert!(graph.set_display_format(&node, 1).is_err());
        drop(node); drop(ptr);
        assert!(old.upgrade().is_none());
        assert_eq!(retained_core.get_size(), 4);
    }

    #[test]
    fn flush_rejects_live_views_without_retiring_the_current_generation() {
        let graph = GraphStore::new();
        let int = scalar(&graph);
        let node = graph.reserve("Retained", 402, type_metatype::TYPE_STRUCT, false).unwrap();
        let view = node.read();
        assert!(graph.flush().is_err());
        assert_eq!(view.get(node.id()).unwrap().get_name(), "Retained");
        assert_eq!(graph.find_by_name("Retained").unwrap(), node);
        drop(view);
        graph.complete(&node, record(&node, 8, vec![])).unwrap();
        graph.flush().unwrap();
        let fresh = graph.reserve("Retained", 402, type_metatype::TYPE_STRUCT, false).unwrap();
        assert_ne!(fresh.id(), node.id());
        let retired_view = node.read();
        assert!(graph.flush().is_err());
        assert_eq!(retired_view.get(node.id()).unwrap().get_size(), 8);
        drop(retired_view);
        let core_view = int.read();
        assert!(graph.flush().is_err());
        assert_eq!(graph.find_by_name("Retained").unwrap(), fresh);
        drop(core_view);
        graph.complete(&fresh, record(&fresh, 16, vec![])).unwrap();
        graph.flush().unwrap();
        assert_eq!(node.get_size(), 8);
        assert_eq!(fresh.get_size(), 16);
    }

    #[test]
    fn presentation_is_not_structural_identity_and_borrowed_writes_are_rejected() {
        let graph = GraphStore::new();
        let int = scalar(&graph);
        graph.seal_core().unwrap();
        let held = int.read();
        graph.set_display_format(&int, 1).unwrap();
        assert_eq!(held.definition(int.id()).unwrap().get_display_format(), 1);
        drop(held);
        let p = graph.intern(pointer(int.id())).unwrap();
        let view = p.read();
        let mut different = pointer(int.id()); different.size = 4; different.alignment = 4;
        assert!(graph.intern(different).is_err());
        drop(view);
        graph.set_display_format(&p, 2).unwrap();
        assert_eq!(graph.intern(pointer(int.id())).unwrap(), p);
        assert_eq!(p.get_display_format(), 2);
    }

    #[test]
    fn retired_pending_revision_rejects_correction_and_dependency_updates() {
        let graph = GraphStore::new();
        let child = graph.reserve("Child", 511, type_metatype::TYPE_STRUCT, false).unwrap();
        let old = graph.reserve("inferred", 512, type_metatype::TYPE_STRUCT, true).unwrap();
        graph.complete(&old, record(&old, 8, vec![TypeField::new(0, 0, "child", child.id())])).unwrap();
        assert_eq!(graph.state(&old).unwrap(), TypeState::Pending);
        graph.retire_inferred(std::slice::from_ref(&old)).unwrap();
        let replacement = graph.reserve("inferred", 512, type_metatype::TYPE_STRUCT, true).unwrap();
        assert_ne!(old.id(), replacement.id());
        assert!(graph.correct_pending(&old, record(&old, 16, vec![])).is_err());
        assert!(graph.complete(&old, record(&old, 8, vec![])).is_err());
        assert!(graph.set_display_format(&old, 1).is_err());
        graph.complete(&child, record(&child, 8, vec![])).unwrap();
        assert_eq!(old.get_size(), 8);
        assert_eq!(graph.state(&old).unwrap(), TypeState::Pending);
        assert!(!old.read().layout_ready(old.id()).unwrap());
        graph.complete(&replacement, record(&replacement, 16, vec![])).unwrap();
        assert_eq!(graph.find_instance("inferred", 512, TypeInstance::Fixed).unwrap(), replacement);
    }

    #[test]
    fn inferred_retirement_keeps_prior_revision_and_rebuilds_derived_index() {
        let graph = GraphStore::new();
        let old = graph.reserve("struct_1", 501, type_metatype::TYPE_STRUCT, true).unwrap();
        graph.complete(&old, record(&old, 8, vec![])).unwrap();
        let old_ptr = graph.intern(pointer(old.id())).unwrap();
        let affected = graph.retire_inferred(std::slice::from_ref(&old)).unwrap();
        assert!(affected.contains(&old.id()) && affected.contains(&old_ptr.id()));
        let new = graph.reserve("struct_1", 501, type_metatype::TYPE_STRUCT, true).unwrap();
        graph.complete(&new, record(&new, 16, vec![])).unwrap();
        assert_ne!(old.id(), new.id());
        assert_eq!(old.get_size(), 8);
        assert_eq!(new.get_size(), 16);
        assert_eq!(old_ptr.get_ptr_to().unwrap(), old);
        assert_ne!(graph.intern(pointer(new.id())).unwrap(), old_ptr);
    }
}
