//! Request-local, real-body callable publication for the host protocol.
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use kuna_base::address::Address;
use kuna_base::error::{KunaError, KunaResult};
use kuna_base::marshal::{AttributeId, ElementId, Encoder, ATTRIB_CONTENT};
use kuna_decomp::architecture::Architecture;
use kuna_decomp::dtype::{DatatypeKind, HostTypeSource, HostTypeSourceKind, TypeRoot};
use kuna_decomp::funcdata::Funcdata;
use kuna_decomp::kuna_callabletransport::{self as transport, CallableArtifact, CallableBody, CallableDefinition};
use kuna_decomp::decompile_drive::{self, GlobalInfo};

const SUPPORT: ElementId = ElementId::new("callable_support", 4030);
const BODY: ElementId = ElementId::new("callable_body", 4031);
const ARTIFACT: ElementId = ElementId::new("callable_artifact", 4032);
const DECLARATION: ElementId = ElementId::new("callable_declaration", 4033);
const DEFINITION: ElementId = ElementId::new("callable_definition", 4034);
const PRELUDE: ElementId = ElementId::new("callable_prelude", 4035);
const GLOBAL: ElementId = ElementId::new("callable_global", 4036);
const TYPE: ElementId = ElementId::new("callable_type", 4037);
const BODYTEXT: ElementId = ElementId::new("callable_bodytext", 4038);
const SOURCE: ElementId = ElementId::new("callable_source", 4039);
const VERSION: AttributeId = AttributeId::new("kuna_version", 4030);
const STATUS: AttributeId = AttributeId::new("kuna_status", 4031);
const REASON: AttributeId = AttributeId::new("kuna_reason", 4032);
const ADDRESS: AttributeId = AttributeId::new("kuna_address", 4033);
const CURRENT: AttributeId = AttributeId::new("kuna_current", 4034);
const COMPLETE: AttributeId = AttributeId::new("kuna_complete", 4035);
const REQUIRED: AttributeId = AttributeId::new("kuna_required", 4036);
const DEFERRED: AttributeId = AttributeId::new("kuna_deferred", 4037);
const KIND: AttributeId = AttributeId::new("kuna_definition_kind", 4038);
const KEY: AttributeId = AttributeId::new("kuna_key", 4039);
const SPACE: AttributeId = AttributeId::new("kuna_space", 4040);
const PROGRAM: AttributeId = AttributeId::new("kuna_source_program", 4041);
const REVISION: AttributeId = AttributeId::new("kuna_source_revision", 4042);
const SOURCE_ID: AttributeId = AttributeId::new("kuna_source_id", 4043);
const SOURCE_KIND: AttributeId = AttributeId::new("kuna_source_kind", 4044);
const SOURCE_SIZE: AttributeId = AttributeId::new("kuna_source_size", 4045);
const SOURCE_SCOPE: AttributeId = AttributeId::new("kuna_source_scope", 4046);
const SOURCE_BINDING: AttributeId = AttributeId::new("kuna_source_binding", 4047);
const PROVIDER: AttributeId = AttributeId::new("kuna_provider", 4048);

struct Text { kind: ElementId, key: String, text: String, sources: Vec<HostTypeSource> }
struct Body { space: i32, address: u64, declaration: String, text: String, artifacts: Vec<CallableArtifact> }
pub(crate) struct CallableSupport { records: Vec<Text>, bodies: Vec<Body>, error: Option<String> }

fn fail(message: impl Into<String>) -> KunaError { KunaError::lowlevel(message.into()) }
fn entry(key: &str) -> KunaResult<(i32, u64)> {
    key.strip_prefix("kuna_entry_").and_then(|rest| rest.split_once('_'))
        .and_then(|(space, rest)| rest.split_once('_').and_then(|(address, descriptor)| {
            if descriptor.is_empty() { return None; }
            Some((space.parse().ok()?, address.parse().ok()?))
        })).ok_or_else(|| fail("Callable request has an invalid full target identity"))
}

/// The source root's successful decode owns anonymous structural nodes only
/// while the graph's transitive source invalidation retains that receipt. Named
/// children retain independent source identity and cannot inherit a mismatched
/// program/revision. The authoritative edges include callable prototypes.
fn source_closure(root: &TypeRoot, owner: &HostTypeSource) -> KunaResult<()> {
    let view = root.read();
    let mut pending = vec![root.id()];
    let mut seen = BTreeSet::new();
    while let Some(id) = pending.pop() {
        if !seen.insert(id) { continue; }
        if seen.len() > 4096 { return Err(fail("Source datatype closure exceeds publication bound")); }
        let node = view.get(id)?.effective()?;
        if let Some(source) = view.host_source(id)? {
            if source.program != owner.program
                || (source.kind != HostTypeSourceKind::Builtin && source.revision != owner.revision) {
                return Err(fail("Source datatype dependency belongs to another program revision"));
            }
        } else {
            // The actual host encoder emits these inline without an ID. They
            // acquire no source ownership of their own, and never suppress a
            // Java root. A later child correction invalidates the owning root.
            let inline = matches!(&node.kind, DatatypeKind::Void)
                || (node.get_name().is_empty()
                    && matches!(&node.kind, DatatypeKind::Pointer { .. } | DatatypeKind::Array { .. }));
            if !inline { return Err(fail("Source datatype dependency lost its authenticated decode receipt")); }
        }
        pending.extend_from_slice(view.dependencies(id)?);
    }
    Ok(())
}
fn source_owner(root: &TypeRoot) -> KunaResult<Vec<HostTypeSource>> {
    let source = root.read().host_source(root.id())?.cloned();
    if let Some(source) = source {
        source_closure(root, &source)?;
        if source.size != root.get_size() { return Err(fail("Source datatype encoded size no longer matches its definition")); }
        Ok(vec![source])
    } else { Ok(Vec::new()) }
}

struct Inventory {
    types: BTreeMap<String, (TypeRoot, String, Vec<HostTypeSource>)>,
    type_order: Vec<String>,
    forwards: BTreeMap<String, String>,
    globals: BTreeMap<(i32, u64, String), Vec<GlobalInfo>>,
}
impl Inventory {
    fn capture(&mut self, arch: &Architecture, fd: &Funcdata) -> KunaResult<()> {
        let spelling = kuna_decomp::kuna_langtypes::SpellCtx::from_arch(arch, arch.print().out_lang(), arch.print().options.convention);
        for root in kuna_decomp::kuna_structdefs::referenced_types(fd) {
            let view = root.read();
            let node = view.get(root.id())?;
            let name = kuna_decomp::printc::sanitize_type_name(node.get_name()).into_owned();
            let definition = kuna_decomp::kuna_structdefs::definition_text(&root, spelling);
            if definition.is_empty() { return Err(fail("Referenced named type has no native definition")); }
            let source = source_owner(&root)?;
            if let Some((previous, text, owner)) = self.types.get(&name) {
                if previous != &root || text != &definition || owner != &source {
                    return Err(fail(format!("Conflicting native datatype ownership for {name}")));
                }
                continue;
            }
            if root.get_typedef().is_none() {
                let tag = match &node.kind {
                    DatatypeKind::Struct { .. } => Some("struct"),
                    DatatypeKind::Union { .. } => Some("union"),
                    _ => None,
                };
                if let Some(tag) = tag {
                    self.forwards.insert(name.clone(), format!("typedef {tag} {name} {name};\n"));
                }
            }
            drop(view);
            self.type_order.push(name.clone());
            self.types.insert(name, (root, definition, source));
        }
        for global in decompile_drive::extract_global_objects(arch) {
            let records = self.globals.entry((global.space_index, global.address, global.name.clone())).or_default();
            if !records.contains(&global) { records.push(global); }
        }
        Ok(())
    }
}

impl CallableSupport {
    pub(crate) fn collect(arch: &mut Architecture, current: &Funcdata) -> Self {
        match Self::collect_inner(arch, current) {
            Ok(result) => result,
            Err(error) => Self { records: Vec::new(), bodies: Vec::new(), error: Some(error.to_string()) },
        }
    }
    fn add_body(arch: &mut Architecture, fd: &Funcdata, result: &mut Self,
        inventory: &mut Inventory, queued: &mut BTreeSet<(i32, u64)>,
        work: &mut VecDeque<(i32, u64)>) -> KunaResult<()>
    {
        if fd.kuna_pipeline_failure().is_some() || fd.sblocks_get_size() == 0 {
            return Err(fail("Callable dependency has no successfully decompiled body"));
        }
        let Some(space) = fd.get_address().get_space() else { return Err(fail("Callable body has no address space")); };
        let identity = (space.get_index(), fd.get_address().get_offset());
        let artifacts = transport::export_artifacts(fd, arch, arch.print())?;
        let declaration = transport::body_declaration(fd, arch, arch.print())?;
        let mut printer = arch.take_print();
        let rendered = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| printer.doc_function_support(fd, arch)));
        arch.put_print(printer);
        let text = match rendered {
            Ok(text) => text?,
            Err(_) => return Err(fail("Callable dependency body rendering failed")),
        };
        if text.trim().is_empty() { return Err(fail("Callable dependency body rendering was empty")); }
        for artifact in &artifacts {
            if matches!(artifact.definition, Some(CallableDefinition::ExistingTarget { .. })) && artifact.declaration != declaration {
                return Err(fail("Callable existing provider declaration differs from its actual body"));
            }
            if artifact.required {
                let target = entry(&artifact.key)?;
                if target != identity && queued.insert(target) { work.push_back(target); }
            }
        }
        inventory.capture(arch, fd)?;
        result.bodies.push(Body { space: identity.0, address: identity.1, declaration, text, artifacts });
        Ok(())
    }
    fn collect_inner(arch: &mut Architecture, current: &Funcdata) -> KunaResult<Self> {
        if arch.print().out_lang() != kuna_decomp::kuna_lang::OutLang::C {
            return Err(fail("Callable C support requires the C emission surface"));
        }
        let mut result = Self { records: Vec::new(), bodies: Vec::new(), error: None };
        let mut inventory = Inventory { types: BTreeMap::new(), type_order: Vec::new(), forwards: BTreeMap::new(), globals: BTreeMap::new() };
        let mut queued = BTreeSet::new();
        let mut work = VecDeque::new();
        let Some(space) = current.get_address().get_space() else { return Err(fail("Current function has no address space")); };
        queued.insert((space.get_index(), current.get_address().get_offset()));
        Self::add_body(arch, current, &mut result, &mut inventory, &mut queued, &mut work)?;
        while let Some((space, offset)) = work.pop_front() {
            if result.bodies.len() >= 1024 { return Err(fail("Callable dependency closure exceeds publication bound")); }
            let space = arch.manage().get_space(space).cloned().ok_or_else(|| fail("Callable dependency address space is unavailable"))?;
            let address = Address::new(space, offset);
            let fd = crate::process::host_decompile_entry(arch, &address, || format!("FUN_{offset:08x}"))?;
            Self::add_body(arch, &fd, &mut result, &mut inventory, &mut queued, &mut work)?;
        }
        let bodies: Vec<_> = result.bodies.iter().map(|body| CallableBody {
            space: Some(body.space), byte_address: body.address, artifacts: &body.artifacts, failed: false, export_error: None,
        }).collect();
        let joined = transport::collect_callable_publication(&bodies).map_err(fail)?;
        transport::validate_callable_publication(&bodies, &joined, |_| true).map_err(fail)?;

        let mut core_roots = Vec::new();
        let prelude = decompile_drive::print_c_recompile_prelude_with_roots(arch, |root| core_roots.push(root.clone()));
        let mut sources = Vec::new();
        let mut core_names = BTreeMap::new();
        for root in core_roots {
            let view = root.read();
            let name = view.get(root.id())?.get_name().to_owned();
            if inventory.types.contains_key(&name) || core_names.get(&name).is_some_and(|old| old != &root) {
                return Err(fail(format!("Conflicting native core datatype ownership for {name}")));
            }
            drop(view);
            for source in source_owner(&root)? { if !sources.contains(&source) { sources.push(source); } }
            core_names.insert(name, root);
        }
        result.records.push(Text { kind: PRELUDE, key: "native-core-prelude".into(), text: prelude, sources });
        for (name, text) in inventory.forwards {
            result.records.push(Text { kind: PRELUDE, key: format!("forward:{name}"), text, sources: Vec::new() });
        }
        for name in inventory.type_order {
            let (_, text, sources) = inventory.types.remove(&name).expect("recorded type order");
            result.records.push(Text { kind: TYPE, key: format!("type:{name}"), text, sources });
        }
        for ((space, address, name), globals) in inventory.globals {
            let text = decompile_drive::global_declarations(globals.iter());
            result.records.push(Text { kind: GLOBAL, key: format!("global:{space}:{address}:{name}"), text, sources: Vec::new() });
        }
        Ok(result)
    }
    pub(crate) fn encode(&self, encoder: &mut dyn Encoder) {
        fn text(encoder: &mut dyn Encoder, element: &ElementId, text: &str) {
            encoder.open_element(element);
            encoder.write_string(&ATTRIB_CONTENT, text.as_bytes());
            encoder.close_element(element);
        }
        encoder.open_element(&SUPPORT);
        encoder.write_signed_integer(&VERSION, 2);
        encoder.write_string(&STATUS, if self.error.is_some() { b"refused" } else { b"complete" });
        encoder.write_string(&REASON, self.error.as_deref().unwrap_or("").as_bytes());
        for record in &self.records {
            encoder.open_element(&record.kind);
            encoder.write_string(&KEY, record.key.as_bytes());
            encoder.write_string(&ATTRIB_CONTENT, record.text.as_bytes());
            for source in &record.sources {
                encoder.open_element(&SOURCE);
                encoder.write_unsigned_integer(&PROGRAM, source.program);
                encoder.write_unsigned_integer(&REVISION, source.revision);
                encoder.write_unsigned_integer(&SOURCE_ID, source.id);
                encoder.write_string(&SOURCE_KIND, match source.kind { HostTypeSourceKind::Program => b"program", HostTypeSourceKind::Builtin => b"builtin", HostTypeSourceKind::Transient => b"transient" });
                encoder.write_signed_integer(&SOURCE_SIZE, source.size as i64);
                encoder.write_string(&SOURCE_SCOPE, source.scope.as_bytes());
                encoder.write_string(&SOURCE_BINDING, source.binding.as_bytes());
                encoder.close_element(&SOURCE);
            }
            encoder.close_element(&record.kind);
        }
        for (index, body) in self.bodies.iter().enumerate() {
            encoder.open_element(&BODY);
            encoder.write_signed_integer(&SPACE, body.space as i64);
            encoder.write_unsigned_integer(&ADDRESS, body.address);
            encoder.write_bool(&CURRENT, index == 0);
            encoder.write_bool(&COMPLETE, true);
            text(encoder, &DECLARATION, &body.declaration);
            text(encoder, &BODYTEXT, &body.text);
            for artifact in &body.artifacts {
                encoder.open_element(&ARTIFACT);
                encoder.write_string(&KEY, artifact.key.as_bytes());
                encoder.write_bool(&REQUIRED, artifact.required);
                encoder.write_bool(&DEFERRED, artifact.deferred);
                encoder.write_string(&KIND, match &artifact.definition { None => b"none", Some(CallableDefinition::Wrapper(_)) => b"wrapper", Some(CallableDefinition::ExistingTarget { .. }) => b"existing", Some(CallableDefinition::BodyProof { .. }) => b"bodyproof" });
                if let Some(CallableDefinition::BodyProof { provider }) = &artifact.definition { encoder.write_string(&PROVIDER, provider.as_bytes()); }
                text(encoder, &DECLARATION, &artifact.declaration);
                if let Some(CallableDefinition::Wrapper(definition)) = &artifact.definition { text(encoder, &DEFINITION, definition); }
                encoder.close_element(&ARTIFACT);
            }
            encoder.close_element(&BODY);
        }
        encoder.close_element(&SUPPORT);
    }
}
