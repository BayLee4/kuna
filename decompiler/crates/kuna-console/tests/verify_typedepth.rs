//! End-to-end gate for full-depth DWARF type resolution (`--option typedepth`).
//!
//! The bug: the DIE→`Datatype` mapper reduced Ghidra's
//! `DWARFDataTypeImporter.trackRecursion` (a per-DIE-offset re-entry counter that
//! fires only on a genuine type cycle) to a flat three-hop budget counted over
//! EVERY link, transparent `typedef`/`const`/`volatile`/`restrict` included. Four
//! DIEs is an ordinary C declaration — `const char *const *`, `const size_t *`,
//! `char ***`, `state_t *` — so those chains ran out of budget and fell back to
//! `void`, and the stack locals, globals and deep-pointer parameters of a `-g`
//! binary rendered `void *`.
//!
//! The fixture `typedepth_x86_64` (source vendored alongside) is a `-g -O0` C
//! binary whose every function carries one of those shapes, plus the
//! self-referential and mutually recursive structs the budget claimed to be
//! guarding against. Each test is TWO-PASS: `typedepth off` reproduces the bug,
//! the default reproduces the fix.
//!
//! ## Why the gate is set through the environment, not `set_kuna_option`
//!
//! The types are baked into the analysis facts by `DwarfPass` during `load file`,
//! upstream of every `option` command, so the live gate is the process env var
//! (`kuna_typedepth::TYPEDEPTH_ENV`) that the CLI exports before the load. The
//! helper below therefore sets it BEFORE `bootstrap_from_object`, serialized by a
//! mutex because the environment is process-global and `cargo test` runs the
//! tests in this binary concurrently.

use std::path::PathBuf;
use std::sync::Mutex;

use kuna_console::engine::bootstrap_from_object;
use kuna_console::ifacedecomp::{execute, register_decomp_commands, IfaceDecompData, DECOMPILE_MODULE};
use kuna_console::ifaceterm::ConsoleCommands;
use kuna_decomp::kuna_dwarfstructs::DWARFSTRUCTS_ENV;
use kuna_decomp::kuna_typedepth::TYPEDEPTH_ENV;

/// Serializes the env-var flip + bootstrap across the concurrently-run tests.
static GATE: Mutex<()> = Mutex::new(());

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../..").canonicalize().unwrap()
}

/// Bootstrap the fixture with `typedepth` on/off, decompile each of `funcs` and return the
/// concatenated C.
fn decompile(funcs: &[&str], typedepth: bool) -> String {
    decompile_checking(funcs, typedepth, |_| {})
}

fn decompile_checking(
    funcs: &[&str],
    typedepth: bool,
    check: impl FnOnce(&kuna_console::engine::ConsoleProgram),
) -> String {
    let _guard = GATE.lock().unwrap_or_else(|e| e.into_inner());
    let root = repo_root();
    let specs = root.join("specs");
    let spec_roots = vec![specs.to_str().unwrap().to_string()];
    let path = root
        .join("decompiler/crates/kuna-analysis/tests/fixtures/typedepth_x86_64")
        .to_str().expect("UTF-8 fixture path")
        .to_string();

    std::env::set_var(TYPEDEPTH_ENV, if typedepth { "on" } else { "off" });
    // Pin the sibling `dwarfstructs` gate OFF so this file keeps measuring the
    // one axis it is about. That arm renames the anonymous fallback after the
    // shape it describes (`anon_struct_8_2`) and interns a name-colliding
    // aggregate under a size-suffixed name with its fields (`code_4 *base`, whose
    // members then resolve) instead of the shared anonymous fallback asserted
    // below — both strict improvements on what these assertions pin, and both
    // covered by `verify_dwarfstructs.rs`.
    std::env::set_var(DWARFSTRUCTS_ENV, "off");
    let prog = bootstrap_from_object(&path, "", &spec_roots);
    std::env::remove_var(TYPEDEPTH_ENV);
    std::env::remove_var(DWARFSTRUCTS_ENV);
    let mut prog = prog.expect("bootstrap fixture with built processor specs");
    prog.commit_pending_analysis().expect("analysis commit succeeds");
    check(&prog);

    let mut cmds: Vec<String> = Vec::new();
    for f in funcs {
        cmds.push(format!("load function {f}"));
        cmds.push("decompile".into());
        cmds.push("print C".into());
    }
    let count = cmds.len();
    let mut status = ConsoleCommands::into_status(cmds);
    register_decomp_commands(&mut status);
    {
        let data = status.get_data_mut(DECOMPILE_MODULE).unwrap();
        let dcp = data.as_any_mut().downcast_mut::<IfaceDecompData>().unwrap();
        dcp.conf = Some(prog);
    }
    for _ in 0..count {
        execute(&mut status);
    }
    status.optr.clone()
}

/// The headline plain-C case: a stack local declared `const char *const *`
/// (pointer → const → pointer → const → char) is five DIEs deep.
#[test]
fn stack_local_keeps_its_element_type() {
    let (off, on) =
        (decompile(&["count_authors"], false), decompile(&["count_authors"], true));
    assert!(off.contains("void * const *p"), "gate off should lose the pointee but retain the reached qualification, got:\n{off}");
    assert!(
        on.contains("const char * const *p")
            && !on.contains("void **p")
            && !on.contains("void * const *p"),
        "`const char *const *p` should keep its element type, got:\n{on}"
    );
}

/// Three POINTER hops (`char ***`) exhausted the budget even after `cppproto`
/// collapsed the qualifier hops — the case that arm left on the table.
#[test]
fn three_pointer_hops_resolve() {
    let (off, on) =
        (decompile(&["take_argvp"], false), decompile(&["take_argvp"], true));
    assert!(off.contains("void ***argvp"), "gate off should reproduce the bug, got:\n{off}");
    assert!(
        on.contains("char ***argvp"),
        "`char ***argvp` should resolve to its element type, got:\n{on}"
    );
}

/// An anonymous struct reached through its typedef is interned under the typedef
/// name, not the shared `anon_struct` (the `mbstate_t` shape).
#[test]
fn anonymous_aggregate_takes_its_typedef_name() {
    let (off, on) =
        (decompile(&["use_state"], false), decompile(&["use_state"], true));
    assert!(off.contains("anon_struct *cur"), "gate off should reproduce the bug, got:\n{off}");
    assert!(
        on.contains("state_t *cur"),
        "the local should take its typedef name, got:\n{on}"
    );
}

/// ...unless that typedef name is already a kuna core type (`code`, which zlib's
/// `inftrees.h` really does typedef an anonymous struct to). The factory refuses
/// the redefinition, and the aggregate must fall back to the anonymous name
/// instead of letting the pointer degrade to `void *`.
#[test]
fn colliding_typedef_name_falls_back_not_to_void() {
    let on = decompile(&["walk_codes"], true);
    assert!(
        !on.contains("void *base"),
        "a name collision must not degrade the pointer to void, got:\n{on}"
    );
    assert!(on.contains("anon_struct *base"), "expected the anonymous fallback, got:\n{on}");
}

fn check_authors_global(program: &kuna_console::engine::ConsoleProgram, typedepth: bool) {
    use kuna_decomp::{dtype::type_metatype, kuna_typequal::CONST};
    let database = &program.arch().symboltab;
    let scope = database.get_global_scope().unwrap();
    let ids = database.query_by_name(scope, "default_authors");
    assert_eq!(ids.len(), 1, "the original global has one mapped declaration");
    let symbol = database.symbol(ids[0]);
    let array = symbol.dtype.as_ref().unwrap();
    assert_eq!(array.get_size(), 24, "retain the original producer's object extent");
    assert_eq!(database.entry(symbol.scope, symbol.mapentry[0]).get_size(), 24);
    assert!(symbol.is_name_locked());
    assert_eq!(symbol.is_type_locked(), typedepth, "DWARF adds the declaration, not a guessed pointee");
    if typedepth {
        assert_eq!(array.num_elements(), Some(3));
        let pointer = array.get_array_base().expect("declared array element");
        assert_eq!((pointer.get_metatype(), pointer.get_size()), (type_metatype::TYPE_PTR, 8));
        assert_ne!(pointer.c_qualifiers() & CONST, 0);
        let character = pointer.get_ptr_to().expect("declared character pointee");
        assert_eq!((character.get_name(), character.get_size()), ("char", 1));
        assert_ne!(character.c_qualifiers() & CONST, 0);
    } else {
        assert!(!array.get_array_base().and_then(|element| element.get_ptr_to())
            .is_some_and(|pointee| pointee.get_name() == "char"),
            "the depth budget must still lose the declared character pointee");
    }
}

const DEGRADED_AUTHORS_CALL: &str =
    r"\bcount_authors\(\s*\(\s*void\s*\*\s*(?:const\s*)?\*\s*\)\s*default_authors\s*\)";
const TYPED_AUTHORS_CALL: &str =
    r"\bcount_authors\(\s*(?:\(\s*(?:const\s+)?char\s*\*\s*(?:const\s*)?\*\s*\)\s*)?default_authors\s*\)";

/// The loader retains the original 24-byte object even with the depth budget.
/// Full-depth DWARF additionally supplies its three qualified character pointers;
/// its compatible consumer need not cast the already-correct array.
#[test]
fn global_array_gets_its_real_extent() {
    let off = decompile_checking(&["main"], false, |program| check_authors_global(program, false));
    let on = decompile_checking(&["main"], true, |program| check_authors_global(program, true));
    assert!(
        regex::Regex::new(DEGRADED_AUTHORS_CALL).unwrap().is_match(&off),
        "gate off retains object extent but loses the qualified character pointee:\n{off}"
    );
    assert!(
        regex::Regex::new(TYPED_AUTHORS_CALL).unwrap().is_match(&on),
        "the declared array must decay at its actual consumer, without address-taking:\n{on}"
    );
}

/// Termination on the shapes the depth budget claimed to be protecting against: a
/// self-referential struct and a mutually recursive pair still decompile (the
/// cycle counter, not a hop budget, is what keeps the walk finite).
#[test]
fn recursive_struct_types_terminate() {
    let on = decompile(&["list_len", "ping", "pong"], true);
    assert!(on.contains("list_len"), "self-referential struct walk should decompile:\n{on}");
    assert!(on.contains("ping_s"), "mutually recursive struct should resolve:\n{on}");
    assert!(on.contains("pong_s"), "mutually recursive struct should resolve:\n{on}");
}
