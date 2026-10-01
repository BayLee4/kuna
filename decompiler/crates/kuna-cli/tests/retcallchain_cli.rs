//! End-to-end gate for the RET-call chain a `--assert flow <addr> call` extends
//! along — RE-need `flow-call-override-retain`.
//!
//! Fixture: `retcallchain_i386` (`retcallchain_i386.s` beside it is the source),
//! a 4.7 KiB ELF32 whose `chain_entry` is three `push <continuation>;
//! push <target>; ret` links — the idiom the round-9 crackme builds its whole
//! self-unpacking body out of, 22 links deep.
//!
//! This case is the promoted acceptance probe of that need (`tests/cli/`)
//! executed by `make rust-test`: the entry-chain detector recovers all three
//! calls by default, and overriding the FIRST link keeps #504's continuation
//! behavior intact.

use std::path::PathBuf;
use std::process::Command;

#[path = "../../kuna-console/tests/common/mod.rs"]
mod common;
#[path = "../../kuna-console/tests/common/raw_calls.rs"]
mod raw_calls;

/// The `ret` of each link in `chain_entry`, and the plain epilogue after them.
const FIRST_LINK_RET: &str = "0x8049019";
const EPILOGUE_RET: &str = "0x8049032";

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../..").canonicalize().unwrap()
}

fn fixture() -> String {
    repo_root()
        .join("decompiler/crates/kuna-analysis/tests/fixtures/retcallchain_i386")
        .to_string_lossy()
        .into_owned()
}

fn specs_missing(stderr: &str) -> bool {
    stderr.contains("could not build an architecture")
        || stderr.contains("SLEIGH")
        || stderr.contains("Could not discover")
        || stderr.contains(".sla")
}

/// Decompile `chain_entry`, optionally under a `flow` assertion.  `None` ⇒ the
/// `.sla` tree is not built (a visible skip, never a false green).
fn decompile(assertion: Option<&str>) -> Option<String> {
    decompile_output(assertion, false)
}

fn decompile_output(assertion: Option<&str>, raw: bool) -> Option<String> {
    let binary = fixture();
    let sleigh = repo_root().join("specs").to_string_lossy().into_owned();
    let mut args: Vec<&str> =
        vec!["decompile", &binary, "chain_entry", "--sleighpath", &sleigh];
    if let Some(spec) = assertion {
        args.push("--assert");
        args.push(spec);
    }
    if raw {
        args.push("--raw");
    }
    let out = Command::new(env!("CARGO_BIN_EXE_kuna")).args(&args).output().expect("spawn kuna");
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    if !out.status.success() {
        if specs_missing(&stderr) {
            eprintln!("skipping: specs not built ({stderr})");
            return None;
        }
        panic!("kuna decompile failed: {stderr}");
    }
    Some(stdout)
}

/// Unasserted entry chains are recovered by the same strict detector.
#[test]
fn the_default_recovers_the_whole_entry_chain() {
    let Some(code) = decompile(None) else { return };
    common::c_behavior::assert_three_call_chain("default-chain", &code, "chain_entry");
}

/// The need's own case: one override on the first link recovers all three calls.
#[test]
fn overriding_the_first_link_recovers_the_whole_chain() {
    let Some(code) = decompile(Some(&format!("flow {FIRST_LINK_RET} call"))) else { return };
    common::c_behavior::assert_three_call_chain("first-link-override", &code, "chain_entry");
}

/// A caller can still override the plain epilogue independently; it does not
/// disturb the automatically recovered links before it.
#[test]
fn overriding_the_plain_epilogue_extends_to_nothing() {
    let Some(code) = decompile_output(Some(&format!("flow {EPILOGUE_RET} call")), true) else { return };
    assert!(code.contains("funcboundflow:"), "the epilogue override did not stay local:\n{code}");

    // The explicit epilogue override deliberately calls an unresolved stack
    // target, so execute neither it nor a rewritten body. Trace actual CLI
    // SSA operands: the three original links remain ordered and only the
    // epilogue adds a call through the incoming return-address slot.
    assert_eq!(raw_calls::indirect_targets(&code), [
        (0x8049019, 'r', 0x804a000),
        (0x8049025, 'r', 0x804a004),
        (0x8049031, 'r', 0x804a008),
        (0x8049032, 's', 0),
    ]);
}
