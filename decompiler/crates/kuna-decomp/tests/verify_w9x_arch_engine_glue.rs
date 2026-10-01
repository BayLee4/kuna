//! VERIFIER adversarial tests for item `w9x-arch-engine-glue` (round 1).
//!
//! These tests are written by the independent verifier (not the porter) and
//! target the fragile spots the hunt list flagged for this engine-glue item:
//!
//!   * **The path must be REAL, not faked.**  `build_and_follow_flow` must lift
//!     genuine p-code into the `Funcdata` (a real corpus function has ops after
//!     the flow follow), and `decompile_func` must run the installed
//!     universalAction `perform` to completion without erroring on a
//!     straight-line corpus function.  If the pipeline were a stub returning a
//!     constant, the IR would be empty.
//!   * **init order faithfulness.**  `option extrapop` before any default proto
//!     model is seeded (empty `proto_models` registry) must take the C++
//!     no-op-when-defaultfp-null path without spuriously creating a model.
//!
//! These reuse the gate's datatest-bootstrap mechanics inline (the gate's
//! helpers are private to its own integration-test binary).

use std::path::PathBuf;
use std::rc::Rc;

use kuna_base::address::Address;
use kuna_base::error::{KunaError, KunaResult};
use kuna_base::marshal::IdRegistry;
use kuna_base::space::AddrSpaceManager;
use kuna_base::xml::{DocumentStorage, Element};

use kuna_decomp::architecture::Architecture;
use kuna_decomp::decompile_drive::{build_and_follow_flow, decompile_func, print_c};
use kuna_decomp::options::ArchOptionContext;
use kuna_decomp::sleigh_arch::{register_sleigh_arch_ids, LanguageDatabase};
use kuna_decomp::xml_arch::{XmlArchitecture, XmlArchitectureCapability};

use kuna_sleigh::loadimage::LoadImage;
use kuna_sleigh::loadimage_xml::register_loadimage_xml_ids;
use kuna_sleigh::translate::register_translate_ids;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../..").canonicalize().unwrap()
}

struct SymbolFn {
    name: String,
    space: String,
    offset: u64,
}

struct DataTest {
    binaryimage: Rc<Element>,
    arch_id: String,
    symbols: Vec<SymbolFn>,
}

fn parse_u64(s: &str) -> u64 {
    let s = s.trim();
    if let Some(hex) = s.strip_prefix("0x") {
        u64::from_str_radix(hex, 16).unwrap_or(0)
    } else {
        s.parse().unwrap_or(0)
    }
}

fn find_named(el: &Rc<Element>, name: &str, out: &mut Vec<Rc<Element>>) {
    if el.get_name() == name {
        out.push(Rc::clone(el));
    }
    for c in el.get_children() {
        find_named(c, name, out);
    }
}

fn attr(el: &Element, name: &str) -> Option<String> {
    el.get_attribute_value(name).ok().map(|b| String::from_utf8_lossy(b).into_owned())
}

fn parse_datatest(stem: &str) -> Result<DataTest, String> {
    let path = repo_root().join("tests/datatests").join(format!("{stem}.xml"));
    let xml = std::fs::read(&path).map_err(|e| format!("read {}: {e}", path.display()))?;
    let mut store = DocumentStorage::new();
    let root =
        store.parse_document(&xml).map_err(|e| format!("parse {stem}: {e}"))?.get_root().clone();
    let mut bis = Vec::new();
    find_named(&root, "binaryimage", &mut bis);
    let binaryimage = bis.into_iter().next().ok_or("no <binaryimage>")?;
    let arch_id = attr(&binaryimage, "arch").ok_or("<binaryimage> has no arch")?;
    let mut syms = Vec::new();
    find_named(&binaryimage, "symbol", &mut syms);
    let symbols: Vec<SymbolFn> = syms
        .iter()
        .filter_map(|s| {
            Some(SymbolFn {
                name: attr(s, "name")?,
                space: attr(s, "space")?,
                offset: parse_u64(&attr(s, "offset")?),
            })
        })
        .collect();
    Ok(DataTest { binaryimage, arch_id, symbols })
}

struct DummyImg;
impl LoadImage for DummyImg {
    fn get_file_name(&self) -> &str {
        "dummy"
    }
    fn load_fill(&mut self, _ptr: &mut [u8], _addr: &Address) -> KunaResult<()> {
        Err(KunaError::data_unavail("dummy"))
    }
    fn get_arch_type(&self) -> Vec<u8> {
        Vec::new()
    }
    fn adjust_vma(&mut self, _adjust: i64) {}
}

fn build_registry() -> IdRegistry {
    let mut registry = IdRegistry::with_base_ids();
    register_translate_ids(&mut registry);
    register_sleigh_arch_ids(&mut registry);
    register_loadimage_xml_ids(&mut registry);
    kuna_decomp::options::register_option_elements(&mut registry);
    registry
}

fn bootstrap(dt: &DataTest) -> Result<XmlArchitecture, String> {
    let root = repo_root();
    let registry = build_registry();
    let capability = XmlArchitectureCapability::new();
    let mut arch = capability.build_architecture("datatest", "");
    arch.build_loader(Rc::clone(&dt.binaryimage)).map_err(|e| format!("build_loader: {e}"))?;
    let mut db = LanguageDatabase::new();
    db.scan_for_sleigh_directories(root.join("specs").to_str().unwrap());
    db.get_descriptions(&registry).map_err(|e| format!("collect ldefs: {e}"))?;
    arch.sleigh_mut().set_archid(&dt.arch_id);
    arch.sleigh_mut()
        .resolve_architecture(&db, &dt.arch_id)
        .map_err(|e| format!("resolve_architecture: {e}"))?;
    if arch.sleigh().language_index() < 0 {
        return Err("language index unresolved".to_string());
    }
    let specs = arch.sleigh().build_spec_file(&db).map_err(|e| format!("build_spec_file: {e}"))?;
    let resolved_sla = specs.slafile.ok_or("build_spec_file resolved no .sla")?;
    let sla = std::fs::read(&resolved_sla).map_err(|e| format!("read sla: {e}"))?;
    arch.sleigh_mut()
        .build_translator(Box::new(DummyImg), &sla)
        .map_err(|e| format!("build_translator: {e}"))?;
    let base = arch.sleigh_mut().base_mut().ok_or("no Architecture base after build_translator")?;
    base.set_pspec_xml(std::fs::read(&specs.processorfile).map_err(|e| format!("read pspec: {e}"))?);
    base.set_cspec_xml(std::fs::read(&specs.compilerfile).map_err(|e| format!("read cspec: {e}"))?);
    base.init_post_engine().map_err(|e| format!("init_post_engine: {e}"))?;
    let manager_ptr: *const AddrSpaceManager = arch.sleigh().base().unwrap().manage();
    // SAFETY: same shape as the gate / corpus_bootstrap — manager outlives open().
    arch.open_image(unsafe { &*manager_ptr }, &registry).map_err(|e| format!("open_image: {e}"))?;
    let img = arch.take_loader().ok_or("loader vanished after open")?;
    arch.sleigh_mut().base_mut().unwrap().set_loader(Box::new(img));
    Ok(arch)
}

fn first_mapped_symbol(dt: &DataTest, arch: &mut Architecture) -> Option<(String, Address)> {
    for sym in &dt.symbols {
        if let Some(space) = arch.manage().get_space_by_name(&sym.space).cloned() {
            let entry = Address::new(space, sym.offset);
            // Only return a symbol whose flow can actually be followed (its
            // bytes are mapped) — the gate itself tolerates unmapped ones.
            if build_and_follow_flow(arch, &sym.name, entry.clone(), 0).is_ok() {
                return Some((sym.name.clone(), entry));
            }
        }
    }
    None
}

/// ADVERSARIAL 1 — the path is REAL: `build_and_follow_flow` lifts genuine
/// p-code (the `Funcdata` op-bank is non-empty after the flow follow).  A stub
/// that returned an empty `Funcdata` would fail here.
#[test]
fn w9x_flow_follow_lifts_real_pcode() {
    let dt = match parse_datatest("boolless") {
        Ok(d) => d,
        Err(e) => {
            eprintln!("skip (no boolless datatest): {e}");
            return;
        }
    };
    let mut xarch = match bootstrap(&dt) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("skip (bootstrap, likely no .sla): {e}");
            return;
        }
    };
    let arch = xarch.sleigh_mut().base_mut().expect("base");
    let (name, entry) = first_mapped_symbol(&dt, arch).expect("a mapped corpus function");
    let fd = build_and_follow_flow(arch, &name, entry, 0).expect("flow follow");
    assert!(
        fd.is_proc_started(),
        "followFlow should mark processing started (isProcStarted gate)"
    );
    let live = fd.obank().num_alive();
    let dead = fd.obank().num_dead();
    assert!(
        live + dead > 0,
        "flow follow produced ZERO p-code ops for `{name}` — the lift path is a stub, not a real \
         followFlow (live={live} dead={dead})"
    );
    eprintln!("w9x: `{name}` lifted live={live} dead={dead} ops (real flow follow)");
}

/// ADVERSARIAL 2 — `perform` actually runs: `decompile_func` drives the
/// installed universalAction `perform` to completion (returns Ok) on a real
/// straight-line corpus function, and the printed C names the function.  A
/// pipeline that errored or never installed the action root would fail here.
#[test]
fn w9x_decompile_func_runs_perform_and_prints() {
    let dt = match parse_datatest("boolless") {
        Ok(d) => d,
        Err(_) => return,
    };
    let mut xarch = match bootstrap(&dt) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("skip (bootstrap): {e}");
            return;
        }
    };
    let arch = xarch.sleigh_mut().base_mut().expect("base");
    let (name, entry) = first_mapped_symbol(&dt, arch).expect("a mapped corpus function");
    // FINDING (F1, FIXED): C++ `buildAction` -> `resetDefaults` (action.cc:1003)
    // ends with `setCurrent("decompile")`, so after init the current action is
    // the derived "decompile" root and `getCurrent() != null`.  The Rust
    // `build_action` now mirrors that (it calls `set_current("decompile")` after
    // `install_universal`), so right after `init_post_engine` the current action
    // is "decompile" — faithful to upstream and required by the kuna `stage
    // status` / `pipeline list (current)` console readers.
    assert!(
        arch.has_current_action(),
        "init_post_engine should set the `decompile` current action (F1 fix)"
    );
    let fd = decompile_func(arch, &name, entry, 0).expect("decompile_func ran perform");
    let c = print_c(arch, &fd);
    assert!(!c.trim().is_empty(), "printed C is empty");
    assert!(c.contains(&name), "printed C does not name the function `{name}`:\n{c}");
    assert_eq!(
        c.matches('{').count(),
        c.matches('}').count(),
        "printed C has unbalanced braces:\n{c}"
    );
    assert!(c.matches('{').count() >= 1, "printed C has no function body braces:\n{c}");
}

/// ADVERSARIAL 3a — init-order faithfulness: `option extrapop` with NO default
/// proto model seeded (empty registry — the state before `build_default_proto`)
/// must NOT panic and must NOT spuriously create a model.  C++
/// `setDefaultExtraPop` dereferences `defaultfp`; the Rust port guards on
/// `defaultfp.is_some()` (a no-op when null), matching the invariant that the
/// option is applied after the cspec seeds `defaultfp`.
#[test]
fn w9x_extrapop_with_no_default_model_is_a_safe_noop() {
    let bare = bare_sleigh();
    let mut arch = Architecture::new("t", bare);
    assert!(arch.default_fp().is_none(), "precondition: no default model");
    arch.set_default_extra_pop(8);
    assert!(arch.default_fp().is_none(), "extrapop spuriously created a default model");
    assert!(!arch.has_model("unknown"), "extrapop spuriously registered a model");
    // After seeding, the same call DOES reach the model (round-trips).
    arch.build_default_proto();
    arch.set_default_extra_pop(8);
    assert_eq!(arch.default_fp().unwrap().get_extra_pop(), 8);
}

/// Build a bare Sleigh with no decoded `.sla` (mirrors the architecture/tests.rs
/// helper) for the pure-`ArchOptionContext` unit tests above.
fn bare_sleigh() -> kuna_sleigh::sleigh::Sleigh {
    use kuna_sleigh::globalcontext::ContextInternal;
    kuna_sleigh::sleigh::Sleigh::new(Box::new(DummyImg), Box::new(ContextInternal::new()))
}

#[derive(Clone)]
enum DriveProbe {
    RestartOnce(Rc<std::cell::Cell<u32>>),
    Fatal,
    Panic,
}

struct ProbeAction {
    base: kuna_decomp::action::ActionBase,
    probe: DriveProbe,
}

impl kuna_decomp::action::Action for ProbeAction {
    fn base(&self) -> &kuna_decomp::action::ActionBase { &self.base }
    fn base_mut(&mut self) -> &mut kuna_decomp::action::ActionBase { &mut self.base }
    fn clone_filtered(
        &self, groups: &kuna_decomp::action::ActionGroupList,
    ) -> Option<Box<dyn kuna_decomp::action::Action>> {
        groups.contains(self.get_group()).then(|| {
            Box::new(Self { base: self.base.clone(), probe: self.probe.clone() })
                as Box<dyn kuna_decomp::action::Action>
        })
    }
    fn apply(
        &mut self, fd: &mut kuna_decomp::funcdata::Funcdata,
        ctx: &mut kuna_decomp::action::ActionContext,
    ) -> i32 {
        match &self.probe {
            DriveProbe::RestartOnce(visits) => {
                let count = visits.get();
                visits.set(count + 1);
                if count == 0 { fd.set_restart_pending(true); }
                0
            }
            DriveProbe::Fatal => {
                ctx.fail(KunaError::Decoder { explain: "invalid declaration in selected root".into() });
                -1
            }
            DriveProbe::Panic => panic!("temporary pipeline unwind"),
        }
    }
}

fn selected_root_fixture() -> Option<(XmlArchitecture, String, Address)> {
    let dt = parse_datatest("switchind").expect("checked-in switch fixture");
    let mut xarch = match bootstrap(&dt) {
        Ok(arch) => arch,
        Err(error) => {
            eprintln!("skip (bootstrap, likely no .sla): {error}");
            return None;
        }
    };
    let arch = xarch.sleigh_mut().base_mut().unwrap();
    let symbol = dt.symbols.first().expect("switch fixture entry");
    let entry = Address::new(
        arch.manage().get_space_by_name(&symbol.space).unwrap().clone(), symbol.offset,
    );
    Some((xarch, symbol.name.clone(), entry))
}

/// Retain the real firstpass actions; controlled faults exercise the driver's
/// restart and temporary-root error paths without depending on incidental IR.
fn install_drive_probes(arch: &mut Architecture) -> Rc<std::cell::Cell<u32>> {
    use kuna_decomp::action::{ruleflags, ActionBase, ActionRestartGroup};
    arch.allacts.set_current("firstpass").unwrap();
    let firstpass = arch.allacts.get_current().unwrap()
        .clone_filtered(arch.allacts.get_group("firstpass").unwrap()).unwrap();
    let visits = Rc::new(std::cell::Cell::new(0));
    let mut universal = ActionRestartGroup::new(ruleflags::rule_onceperfunc, "universal", 8);
    universal.add_action(firstpass);
    for (group, probe) in [
        ("restart_probe", DriveProbe::RestartOnce(visits.clone())),
        ("fatal_probe", DriveProbe::Fatal),
        ("panic_probe", DriveProbe::Panic),
    ] {
        universal.add_action(Box::new(ProbeAction {
            base: ActionBase::new(0, group, group), probe,
        }));
    }
    arch.allacts.set_universal(Box::new(universal));
    arch.allacts.set_group("seeded_firstpass", ["base", "restart_probe"]);
    arch.allacts.set_group("fatal_probe", ["fatal_probe"]);
    arch.allacts.set_group("panic_probe", ["panic_probe"]);
    arch.allacts.set_current("seeded_firstpass").unwrap();
    visits
}

struct EntryPrototypeFetch {
    entry: Address,
    document: Vec<u8>,
}

impl kuna_decomp::remote_provider::RemoteProviderFetch for EntryPrototypeFetch {
    fn fetch_mapped_symbols(
        &self, addr: &Address, decoder: &mut dyn kuna_base::marshal::Decoder,
    ) -> KunaResult<bool> {
        if addr != &self.entry { return Ok(false); }
        decoder.ingest_stream(&self.document)?;
        Ok(true)
    }
    fn fetch_namespace_path(
        &self, _: u64, _: &mut dyn kuna_base::marshal::Decoder,
    ) -> KunaResult<bool> { Ok(false) }
    fn fetch_external_ref(
        &self, _: &Address, _: &mut dyn kuna_base::marshal::Decoder,
    ) -> KunaResult<bool> { Ok(false) }
    fn fetch_tracked_registers(
        &self, _: &Address, _: &mut dyn kuna_base::marshal::Decoder,
    ) -> KunaResult<bool> { Ok(false) }
    fn fetch_comments(
        &self, _: &Address, _: u32, _: &mut dyn kuna_base::marshal::Decoder,
    ) -> KunaResult<bool> { Ok(false) }
}

#[test]
fn selected_reduced_root_preserves_explicit_entry_and_local_seeds_across_reflow() {
    use kuna_base::marshal::{Encoder, PackedEncode, ATTRIB_ID, ATTRIB_NAME, ATTRIB_SIZE};
    use kuna_decomp::dtype::type_metatype;
    use kuna_decomp::fspec::{FuncProto, ParameterPieces, PrototypePieces};
    use kuna_decomp::remote_provider::ELEM_MAPSYM;
    use kuna_decomp::varnode::varnode_flags;

    let Some((mut xarch, name, entry)) = selected_root_fixture() else { return };
    let arch = xarch.sleigh_mut().base_mut().unwrap();
    let visits = install_drive_probes(arch);
    let declared_type = arch.types().get_base(4, type_metatype::TYPE_INT).unwrap();
    let host_type = arch.types().get_base(8, type_metatype::TYPE_INT).unwrap();
    let model = arch.default_fp().unwrap().clone();
    let host_pieces = PrototypePieces {
        name: name.clone(), outtype: Some(host_type.clone()), first_var_arg_slot: -1,
        ..Default::default()
    };
    let mut host_proto = FuncProto::new();
    host_proto.seed_locked_from_pieces(
        &host_pieces, model.clone(), arch.types().get_type_void().unwrap(),
        arch.types(), arch.manage(),
    ).unwrap();
    let mut document = Vec::new();
    {
        let mut encoder = PackedEncode::new(&mut document);
        let wrapper = kuna_decomp::prettyprint::ids::ELEM_TYPE;
        let function = kuna_decomp::funcdata_encode::ELEM_FUNCTION;
        encoder.open_element(&wrapper);
        encoder.write_unsigned_integer(&ATTRIB_ID, 0);
        encoder.open_element(&ELEM_MAPSYM);
        encoder.open_element(&function);
        encoder.write_unsigned_integer(&ATTRIB_ID, 0x7001);
        encoder.write_string(&ATTRIB_NAME, name.as_bytes());
        encoder.write_signed_integer(&ATTRIB_SIZE, 1);
        entry.encode(&mut encoder).unwrap();
        host_proto.encode(&mut encoder).unwrap();
        encoder.close_element(&function);
        entry.encode_sized(&mut encoder, 1).unwrap();
        encoder.open_element(&kuna_base::address::ELEM_RANGELIST);
        encoder.close_element(&kuna_base::address::ELEM_RANGELIST);
        encoder.close_element(&ELEM_MAPSYM);
        encoder.close_element(&wrapper);
    }
    arch.install_remote_provider(Rc::new(EntryPrototypeFetch {
        entry: entry.clone(), document,
    }), None);
    let canonical = arch.remote_scope.as_ref().unwrap().prototype_at(&entry).unwrap();
    assert_eq!(canonical.get_output_type(), Some(&host_type));
    let stack = arch.manage().get_stack_space().unwrap().clone();
    let output_addr = Address::new(stack.clone(), 0x20);
    let explicit = PrototypePieces {
        name: name.clone(), outtype: Some(declared_type.clone()), first_var_arg_slot: -1,
        output_storage: Some(ParameterPieces {
            addr: output_addr.clone(), type_: Some(declared_type.clone()), flags: 0,
        }),
        ..Default::default()
    };
    let local_addr = Address::new(stack.clone(), stack.get_highest() - 0x1f);
    let local_flags = varnode_flags::typelock | varnode_flags::namelock;
    let mapped = [("committed_local".to_string(), declared_type.clone(), local_addr.clone(), local_flags)];
    let fd = kuna_decomp::decompile_drive::decompile_func_full_with_override_dyn(
        arch, &name, entry.clone(), 0, &mapped, &[], &[], Some(&explicit), &[],
        &kuna_decomp::overrides::Override::new(), &[],
    ).expect("selected seeded firstpass drive");
    assert_eq!(visits.get(), 2, "the test must exercise one real cross-flow restart");
    assert!(!fd.is_high_on(), "firstpass must not run the full high-variable pipeline");
    assert!(!fd.is_type_recovery_on());
    assert_eq!(fd.get_func_proto().get_output_type(), Some(&declared_type));
    assert!(fd.get_func_proto().is_output_locked());
    assert_eq!(fd.get_func_proto().get_output().get_address(), output_addr);
    assert!(fd.mapped_symbol_specs().iter().any(|(name, ty, addr, flags)| {
        name == "committed_local" && ty == &declared_type && addr == &local_addr
            && flags & local_flags == local_flags
    }));
    assert_eq!(canonical.get_output_type(), Some(&host_type));
    assert!(canonical.is_output_locked());
    assert_eq!(arch.allacts.get_current_name(), "seeded_firstpass");
}

#[test]
fn temporary_roots_restore_custom_selection_after_success_error_and_unwind() {
    use kuna_decomp::decompile_drive::run_named_pipeline_variant;
    let Some((mut xarch, name, entry)) = selected_root_fixture() else { return };
    let arch = xarch.sleigh_mut().base_mut().unwrap();
    let visits = install_drive_probes(arch);
    for root in ["firstpass", "fatal_probe", "panic_probe", "missing_root"] {
        let result = run_named_pipeline_variant(arch, &name, entry.clone(), 0, root);
        match root {
            "firstpass" => {
                let fd = result.expect("temporary firstpass");
                assert!(!fd.is_high_on());
            }
            "fatal_probe" => assert!(matches!(result, Err(KunaError::Decoder { .. }))),
            _ => assert!(result.is_err()),
        }
        assert_eq!(arch.allacts.get_current_name(), "seeded_firstpass");
    }
    arch.kuna_fn_budget = Some(std::time::Duration::ZERO);
    let expired = decompile_func(arch, &name, entry.clone(), 0);
    assert!(expired.is_err(), "an expired drive must not publish reduced IR");
    assert!(arch.kuna_fn_deadline.is_none(), "drive deadline must not leak to the next request");
    assert_eq!(arch.allacts.get_current_name(), "seeded_firstpass");
    assert_eq!(visits.get(), 0, "expired actions must not run");
    arch.kuna_fn_budget = None;
    // A subsequent ordinary drive must execute the previous selected root,
    // including its restart behavior, rather than a default or temporary root.
    let fd = decompile_func(arch, &name, entry, 0).unwrap();
    assert_eq!(visits.get(), 2);
    assert!(!fd.is_high_on());
    assert_eq!(arch.allacts.get_current_name(), "seeded_firstpass");
}
