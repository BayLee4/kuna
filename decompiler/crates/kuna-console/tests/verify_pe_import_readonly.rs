//! End-to-end regression gate for a PE Import Address Table inside executable
//! read-only memory. The Windows loader overwrites an IAT slot before execution,
//! so its on-disk hint/name RVA is not a constant even though the section is RX.

use std::path::PathBuf;

use kuna_console::engine::{bootstrap_from_object, ConsoleProgram};
use kuna_console::ifacedecomp::{
    execute, register_decomp_commands, IfaceDecompData, DECOMPILE_MODULE,
};
use kuna_console::ifaceterm::ConsoleCommands;

const FIXTURE: &str = "pe_iatincode_readonly_i386.exe";
const ENTRY: u64 = 0x401010;
// The imported Win32 declaration supplies four arguments, independently of the
// two values this fixture explicitly stages. Match their meaning and order,
// not local names, whitespace, null printing, or equivalent 32-bit casts.
fn named_call_matches(code: &str, library_source: bool) -> bool {
    let address = r"(?:\(\s*void\s*\*\s*\)\s*)?(?:0[xX]40|64)";
    let word = r"(?:\(\s*(?:uint4|uint32_t|unsigned(?:\s+int)?)\s*\)\s*)?";
    let zero = r"(?:\(\s*(?:(?:const\s+)?char|void)\s*\*\s*\)\s*)?(?:NULL|0[xX]0+|0)";
    let trailing = if library_source {
        r",\s*[A-Za-z_][A-Za-z_0-9]*\s*,\s*[A-Za-z_][A-Za-z_0-9]*\s*"
    } else {
        ""
    };
    regex::Regex::new(&format!(
        r"(?m)^\s*VirtualAlloc\s*\(\s*{address}\s*,\s*{word}GetModuleHandleA\s*\(\s*{zero}\s*\)\s*{trailing}\)\s*;\s*$"
    )).unwrap().is_match(code)
}
const RAW_CALL: &str = "(*(code *)0x10a0)(0x40,(*(code *)0x10b0)(0));";

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../..")
        .canonicalize()
        .unwrap()
}

fn load(options: &[(&str, &str)]) -> ConsoleProgram {
    let root = repo_root();
    let spec_roots = vec![root.join("specs").to_str().unwrap().to_string()];
    let bin = root
        .join("decompiler/crates/kuna-analysis/tests/fixtures")
        .join(FIXTURE);
    let mut prog =
        bootstrap_from_object(bin.to_str().unwrap(), "", &spec_roots).unwrap_or_else(|e| {
            panic!(
                "bootstrap {FIXTURE} (build `.sla` with `make specs`): {}",
                e.explain()
            )
        });
    for &(option, value) in options {
        if option == "readonly" {
            prog.arch_mut().readonlypropagate = value == "on";
        } else {
            prog.arch_mut()
                .set_kuna_option(option, value)
                .expect("test option flips");
        }
    }
    prog.commit_pending_analysis()
        .expect("analysis commit succeeds");
    prog
}

fn body(prog: ConsoleProgram) -> String {
    let cmds = vec![
        format!("load addr {ENTRY:#x}"),
        "decompile".into(),
        "print C".into(),
    ];
    let count = cmds.len();
    let mut status = ConsoleCommands::into_status(cmds);
    register_decomp_commands(&mut status);
    {
        let data = status.get_data_mut(DECOMPILE_MODULE).unwrap();
        data.as_any_mut()
            .downcast_mut::<IfaceDecompData>()
            .unwrap()
            .conf = Some(prog);
    }
    for _ in 0..count {
        execute(&mut status);
    }
    status.optr.clone()
}

#[test]
fn peimportcall_off_keeps_the_raw_hint_name_rvas() {
    let prog = load(&[("peimportcall", "off")]);
    let c = body(prog);
    assert!(
        c.contains(RAW_CALL),
        "the off arm must preserve the raw call exactly; got:\n{c}"
    );
    assert!(
        !c.contains("VirtualAlloc("),
        "the disabled analysis must not name imports; got:\n{c}"
    );
}

#[test]
fn default_and_explicit_on_keep_the_nested_calls_named() {
    for options in [&[][..], &[("peimportcall", "on")][..]] {
        let prog = load(options);
        let c = body(prog);
        assert!(
            named_call_matches(&c, true),
            "both import calls and their arguments must survive; got:\n{c}"
        );
        assert!(
            !c.contains("0x10a0"),
            "the IAT's on-disk RVA is not a run-time target; got:\n{c}"
        );
        assert!(
            !c.contains("0x10b0"),
            "the IAT's on-disk RVA is not a run-time target; got:\n{c}"
        );
    }
}

#[test]
fn readonly_on_still_preserves_external_reference_identity() {
    let prog = load(&[("peimportcall", "on"), ("readonly", "on")]);
    let c = body(prog);
    assert!(
        named_call_matches(&c, true),
        "program-wide read-only folding must not consume an external reference; got:\n{c}"
    );
    assert!(
        !c.contains("0x10a0"),
        "the outer call must retain its import identity; got:\n{c}"
    );
    assert!(
        !c.contains("0x10b0"),
        "the nested call must retain its import identity; got:\n{c}"
    );
}

#[test]
fn library_disabled_retains_the_original_two_staged_values() {
    for readonly in ["off", "on"] {
        let c = body(load(&[("peimportcall", "on"), ("win32sigs", "off"), ("readonly", readonly)]));
        assert!(named_call_matches(&c, false), "the original two staged values and nested order must survive; got:\n{c}");
        assert!(!named_call_matches(&c, true), "the disabled library must not add source positions; got:\n{c}");
        assert!(!c.contains("0x10a0"), "the outer IAT slot must retain import identity; got:\n{c}");
        assert!(!c.contains("0x10b0"), "the nested IAT slot must retain import identity; got:\n{c}");
    }
}
