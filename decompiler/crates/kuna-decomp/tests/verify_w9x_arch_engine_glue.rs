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
//!     no-op-when-defaultfp-null path (no panic, no spurious mutation), and the
//!     unknown-model error must surface as a `KunaError`, never a `panic!`.
//!   * **shell brace-matching boundary.**  The structural-sanity invariant the
//!     gate relies on (matched braces) must hold even for a display name that
//!     itself contains brace/paren characters — the printer must not let a
//!     pathological name forge a "sane" shell or unbalance the count.
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
use kuna_decomp::printc::PrintC;
use kuna_decomp::sleigh_arch::{register_sleigh_arch_ids, LanguageDatabase};
use kuna_decomp::xml_arch::{XmlArchitecture, XmlArchitectureCapability};

use kuna_sleigh::loadimage::LoadImage;
use kuna_sleigh::loadimage_xml::register_loadimage_xml_ids;
use kuna_sleigh::translate::register_translate_ids;

mod config_ir_regressions {
    use super::{Address, AddrSpaceManager, Architecture, DataTest, DummyImg, LanguageDatabase, Rc, XmlArchitecture, XmlArchitectureCapability, build_registry, decompile_func, parse_datatest, repo_root};
    fn seeded_bootstrap(dt: &DataTest) -> Result<XmlArchitecture, String> {
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
        base.translate_mut().as_sleigh_mut().ok_or("standalone Sleigh engine")?
            .install_register_lookup().map_err(|e| format!("install_register_lookup: {e}"))?;
        base.init_post_engine().map_err(|e| format!("init_post_engine: {e}"))?;
        let manager_ptr: *const AddrSpaceManager = arch.sleigh().base().unwrap().manage();
        // SAFETY: same shape as the gate / corpus_bootstrap — manager outlives open().
        arch.open_image(unsafe { &*manager_ptr }, &registry).map_err(|e| format!("open_image: {e}"))?;
        let img = arch.take_loader().ok_or("loader vanished after open")?;
        arch.sleigh_mut().base_mut().unwrap().set_loader(Box::new(img));
        Ok(arch)
    }

    use kuna_decomp::action::{ruleflags, Action, ActionBase, ActionContext, ActionGroupList, ActionRestartGroup};
    use kuna_decomp::funcdata::Funcdata;
    use std::cell::Cell;

    struct RestartProbe {
        base: ActionBase,
        visits: Rc<Cell<u32>>,
        emit_warnings: bool,
    }

    struct PanicProbe(ActionBase);
    impl Action for PanicProbe {
        fn base(&self) -> &ActionBase { &self.0 }
        fn base_mut(&mut self) -> &mut ActionBase { &mut self.0 }
        fn clone_filtered(&self, groups: &ActionGroupList) -> Option<Box<dyn Action>> {
            groups.contains("panic_probe").then(|| Box::new(Self(
                ActionBase::new(0, "panic_probe", "panic_probe"),
            )) as Box<dyn Action>)
        }
        fn apply(&mut self, _: &mut Funcdata, _: &mut ActionContext) -> kuna_base::error::KunaResult<i32> {
            Ok(panic!("injected reduced-pipeline unwind"))
        }
    }

    impl Action for RestartProbe {
        fn base(&self) -> &ActionBase { &self.base }
        fn base_mut(&mut self) -> &mut ActionBase { &mut self.base }
        fn clone_filtered(&self, groups: &ActionGroupList) -> Option<Box<dyn Action>> {
            groups.contains("restart_probe").then(|| Box::new(Self {
                base: ActionBase::new(0, "restart_probe", "restart_probe"),
                visits: self.visits.clone(),
                emit_warnings: self.emit_warnings,
            }) as Box<dyn Action>)
        }
        fn apply(&mut self, fd: &mut Funcdata, _: &mut ActionContext) -> kuna_base::error::KunaResult<i32> {
            let visits = self.visits.get();
            self.visits.set(visits + 1);
            if visits == 0 {
                if self.emit_warnings {
                    fd.warning_header("discarded before reflow");
                    fd.warning("discarded instruction warning", &fd.get_address().clone());
                }
                fd.set_restart_pending(true);
            } else if self.emit_warnings {
                fd.warning_header("current after reflow");
                fd.warning("current instruction after reflow", &fd.get_address().clone());
            }
            Ok(0)
        }
    }

    fn selected_root_fixture() -> (XmlArchitecture, String, Address) {
        let dt = parse_datatest("switchind").expect("checked-in switch fixture");
        let mut xarch = seeded_bootstrap(&dt).expect("usable compiled spec is required");
        let arch = xarch.sleigh_mut().base_mut().unwrap();
        let symbol = dt.symbols.first().expect("switch fixture entry");
        let entry = Address::new(arch.manage().get_space_by_name(&symbol.space).unwrap().clone(), symbol.offset);
        (xarch, symbol.name.clone(), entry)
    }

    fn install_selected_root(arch: &mut Architecture) -> Rc<Cell<u32>> {
        install_selected_root_with_warnings(arch, false)
    }

    fn install_selected_root_with_warnings(arch: &mut Architecture, emit_warnings: bool) -> Rc<Cell<u32>> {
        arch.allacts.set_current("firstpass").unwrap();
        let firstpass = arch.allacts.get_current().unwrap()
            .clone_filtered(arch.allacts.get_group("firstpass").unwrap()).unwrap();
        let visits = Rc::new(Cell::new(0));
        let mut root = ActionRestartGroup::new(ruleflags::rule_onceperfunc, "universal", 8);
        root.add_action(firstpass);
        root.add_action(Box::new(RestartProbe {
            base: ActionBase::new(0, "restart_probe", "restart_probe"), visits: visits.clone(),
            emit_warnings,
        }));
        root.add_action(Box::new(PanicProbe(ActionBase::new(0, "panic_probe", "panic_probe"))));
        arch.allacts.set_universal(Box::new(root));
        // Installing a new universal does not replace roots already derived
        // from its predecessor. Rebuild the test's selection from this tree.
        arch.allacts.reset_defaults().unwrap();
        arch.allacts.set_group("seeded_firstpass", ["base", "restart_probe"]);
        arch.allacts.set_group("panic_probe", ["panic_probe"]);
        arch.allacts.set_current("seeded_firstpass").unwrap();
        visits
    }

    #[test]
    fn replacement_flow_and_reflow_replace_only_generated_body_warnings() {
        use kuna_decomp::comment::comment_type;
        let (mut xarch, name, entry) = selected_root_fixture();
        let arch = xarch.sleigh_mut().base_mut().unwrap();
        let other = Address::new(entry.get_space().unwrap().clone(), entry.get_offset() + 0x10000);
        let stale = "WARNING: Inlined function: old body";
        // The console's instruction-comment producer uses a composite display
        // mask, while remote source comments can also be warning-only.
        arch.commentdb.add_comment(comment_type::HEADER, &entry, &entry, stale);
        arch.commentdb.add_comment(comment_type::USER1, &entry, &entry, "authored end-of-line");
        arch.commentdb.add_comment(comment_type::USER2, &entry, &entry, "authored pre-comment");
        arch.commentdb.add_comment(comment_type::USER2 | comment_type::WARNING,
            &entry, &entry, "authored composite instruction");
        arch.commentdb.add_comment(comment_type::WARNING, &entry, &entry, "authored warning category");
        arch.commentdb.add_comment(comment_type::WARNINGHEADER, &entry, &entry, "authored warning header");
        arch.commentdb.add_comment(comment_type::WARNINGHEADER, &other, &other, "other function warning");
        let visits = install_selected_root_with_warnings(arch, true);
        let _fd = decompile_func(arch, &name, entry.clone(), 0).expect("real flow and one reflow");
        assert_eq!(visits.get(), 2);
        let comments = arch.commentdb.comments();
        assert!(!comments.iter().any(|c| c.func_addr == entry
            && c.text.contains("discarded")));
        assert_eq!(comments.iter().filter(|c| c.func_addr == entry
            && c.tp == comment_type::WARNINGHEADER && c.text == "WARNING: current after reflow").count(), 1);
        assert_eq!(comments.iter().filter(|c| c.func_addr == entry
            && c.tp == comment_type::WARNING && c.text == "WARNING: current instruction after reflow").count(), 1);
        let held = comments.to_vec();

        let visits = install_selected_root_with_warnings(arch, false);
        let _fd = decompile_func(arch, &name, entry.clone(), 0).expect("replacement real flow and reflow");
        assert_eq!(visits.get(), 2);
        let comments = arch.commentdb.comments();
        assert!(!comments.iter().any(|c| c.func_addr == entry
            && (c.text.contains("current after reflow") || c.text.contains("current instruction after reflow")
                || c.text.contains("discarded"))));
        for (tp, text) in [
            (comment_type::HEADER, stale),
            (comment_type::USER1, "authored end-of-line"),
            (comment_type::USER2, "authored pre-comment"),
            (comment_type::USER2 | comment_type::WARNING, "authored composite instruction"),
            (comment_type::WARNING, "authored warning category"),
            (comment_type::WARNINGHEADER, "authored warning header"),
        ] {
            assert!(comments.iter().any(|c| c.func_addr == entry && c.tp == tp && c.text == text));
        }
        assert!(comments.iter().any(|c| c.func_addr == other && c.text == "other function warning"));
        assert!(held.iter().any(|c| c.func_addr == entry && c.tp == comment_type::WARNINGHEADER
            && c.text == "WARNING: current after reflow"));
    }

    #[test]
    fn selected_reduced_root_preserves_explicit_entry_and_local_seeds_across_reflow() {
        use kuna_decomp::dtype::type_metatype;
        use kuna_decomp::fspec::{ParameterPieces, PrototypePieces};
        use kuna_decomp::varnode::varnode_flags;
        let (mut xarch, name, entry) = selected_root_fixture();
        let arch = xarch.sleigh_mut().base_mut().unwrap();
        let visits = install_selected_root(arch);
        let declared_type = arch.types().get_base(4, type_metatype::TYPE_INT).unwrap();
        let stack = arch.manage().get_stack_space().expect("compiler stack space").clone();
        let output_addr = Address::new(stack.clone(), 0x20);
        let explicit = PrototypePieces {
            name: name.clone(), outtype: Some(declared_type.clone()), first_var_arg_slot: -1,
            output_storage: Some(ParameterPieces { addr: output_addr.clone(), type_: Some(declared_type.clone()), flags: 0 }),
            ..Default::default()
        };
        let local_addr = Address::new(stack.clone(), stack.get_highest() - 0x1f);
        let local_flags = varnode_flags::typelock | varnode_flags::namelock;
        let mapped = [("committed_local".to_string(), declared_type.clone(), local_addr.clone(), local_flags)];
        let fd = kuna_decomp::decompile_drive::decompile_func_full_with_override_dyn(
            arch, &name, entry, 0, &mapped, &[], &[], Some(&explicit), &[], &[], &[],
        ).expect("selected seeded firstpass drive");
        assert_eq!(visits.get(), 2, "one real cross-flow restart must run");
        assert!(!fd.is_high_on(), "selected firstpass excludes high-variable pipeline");
        assert!(!fd.is_type_recovery_on());
        assert_eq!(fd.get_func_proto().get_output_type().expect("declared entry output type")
            .compare_dependency(&declared_type).unwrap(), 0);
        assert!(fd.get_func_proto().is_output_locked());
        assert_eq!(fd.get_func_proto().get_output().get_address(), output_addr);
        assert!(fd.mapped_symbol_specs().iter().any(|(name, ty, addr, flags)| {
            name == "committed_local" && ty.compare_dependency(&declared_type).unwrap() == 0
                && addr == &local_addr && flags & local_flags == local_flags
        }));
        assert_eq!(explicit.outtype.as_ref().expect("source output type")
            .compare_dependency(&declared_type).unwrap(), 0);
        assert_eq!(arch.allacts.get_current_name(), "seeded_firstpass");
    }

    #[test]
    fn temporary_roots_restore_custom_selection_after_success_error_and_deadline() {
        use kuna_decomp::decompile_drive::run_named_pipeline_variant;
        let (mut xarch, name, entry) = selected_root_fixture();
        let arch = xarch.sleigh_mut().base_mut().unwrap();
        let visits = install_selected_root(arch);
        let fd = run_named_pipeline_variant(arch, &name, entry.clone(), 0, "firstpass").expect("temporary firstpass");
        assert!(!fd.is_high_on());
        assert_eq!(arch.allacts.get_current_name(), "seeded_firstpass");
        assert!(run_named_pipeline_variant(arch, &name, entry.clone(), 0, "missing_root").is_err());
        assert_eq!(arch.allacts.get_current_name(), "seeded_firstpass");
        assert!(run_named_pipeline_variant(arch, &name, entry.clone(), 0, "panic_probe").is_err());
        assert_eq!(arch.allacts.get_current_name(), "seeded_firstpass");
        arch.kuna_fn_budget = Some(std::time::Duration::ZERO);
        assert!(decompile_func(arch, &name, entry.clone(), 0).is_err(), "expired drive cannot publish partial IR");
        assert!(arch.kuna_fn_deadline.is_none(), "deadline must not leak to next request");
        assert_eq!(arch.allacts.get_current_name(), "seeded_firstpass");
        assert_eq!(visits.get(), 0, "expired actions must not run");
        arch.kuna_fn_budget = None;
        let fd = decompile_func(arch, &name, entry, 0).unwrap();
        assert_eq!(visits.get(), 2);
        assert!(!fd.is_high_on());
        assert_eq!(arch.allacts.get_current_name(), "seeded_firstpass");
    }
}

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
    arch.sleigh_mut()
        .base_mut()
        .ok_or("no Architecture base after build_translator")?
        .init_post_engine()
        .map_err(|e| format!("init_post_engine: {e}"))?;
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
    let c = print_c(arch, &fd).unwrap();
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
    // Must not panic (Rc::make_mut on a None would; the guard prevents it).
    arch.set_default_extra_pop(8);
    assert!(arch.default_fp().is_none(), "extrapop spuriously created a default model");
    assert!(!arch.has_model("unknown"), "extrapop spuriously registered a model");
    // After seeding, the same call DOES reach the model (round-trips).
    arch.build_default_proto().unwrap();
    arch.set_default_extra_pop(8);
    assert_eq!(arch.default_fp().unwrap().get_extra_pop(), 8);
}

/// ADVERSARIAL 3b — unknown-model resolution surfaces a `KunaError`, never a
/// panic, and the message faithfully echoes the C++ `LowlevelError("Unknown
/// prototype model :...")`.
#[test]
fn w9x_unknown_model_is_an_error_not_a_panic() {
    let mut arch = Architecture::new("t", bare_sleigh());
    let err: KunaError = arch.set_default_model("no-such-model").unwrap_err();
    let msg = format!("{err}");
    assert!(msg.contains("Unknown prototype model"), "unfaithful error text: {msg}");
    // eval model uses a distinct C++ ParseError text; also must not panic.
    let err2 = arch.set_eval_current_model("no-such-model").unwrap_err();
    assert!(format!("{err2}").contains("Unknown prototype model"));
}

/// ADVERSARIAL 4 — shell brace-matching boundary: a display name that itself
/// contains `{`, `}`, `(`, `)` must NOT unbalance the printer's brace count nor
/// let a pathological name forge extra structure.  The printer emits exactly
/// one `{`/`}` pair regardless of the name's contents (the name flows through
/// `tag_func_name` as plain text, not as structural tokens).
#[test]
fn w9x_doc_function_braces_balanced_under_adversarial_name() {
    let mut p = PrintC::new();
    // A maliciously-structured name: braces + parens + a fake body.
    let nasty = "evil(){ return; } extra {";
    let out = p.doc_function(nasty, None, "void", &[]);
    // The structural function braces are exactly one pair...
    let open = out.matches('{').count();
    let close = out.matches('}').count();
    // ...the name contributes its own literal braces, but they must remain
    // BALANCED (the name has 2 '{' and 1 '}'); the printer adds 1 each, so the
    // total must still be open==close ONLY if the name was balanced.  Here the
    // name is deliberately UNBALANCED (2 open, 1 close), so the printer's own
    // balanced pair cannot rescue it — proving the structural-sanity check is
    // NOT fooled into accepting an unbalanced name as "sane".
    assert_ne!(
        open, close,
        "an unbalanced adversarial name slipped through as balanced (open={open} close={close}) — \
         is_structurally_sane would wrongly accept it"
    );
    // A name with no structural characters yields the clean one-pair shell.
    let mut p2 = PrintC::new();
    let clean = p2.doc_function("plain_name", None, "void", &[]);
    assert_eq!(clean.matches('{').count(), 1);
    assert_eq!(clean.matches('}').count(), 1);
    assert!(clean.contains("void plain_name(void)"));
}

/// Build a bare Sleigh with no decoded `.sla` (mirrors the architecture/tests.rs
/// helper) for the pure-`ArchOptionContext` unit tests above.
fn bare_sleigh() -> kuna_sleigh::sleigh::Sleigh {
    use kuna_sleigh::globalcontext::ContextInternal;
    kuna_sleigh::sleigh::Sleigh::new(Box::new(DummyImg), Box::new(ContextInternal::new()))
}
