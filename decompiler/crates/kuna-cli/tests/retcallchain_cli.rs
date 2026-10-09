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

mod common;
use common::{c_behavior, raw_calls, scratch_file};

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

/// Decompile `chain_entry`, optionally under a `flow` assertion.
fn decompile(assertion: Option<&str>) -> String {
    decompile_output(assertion, false)
}

fn decompile_output(assertion: Option<&str>, raw: bool) -> String {
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
        panic!("kuna decompile failed: {stderr}");
    }
    stdout
}

/// The three callees the chain reaches, by the global each `ret` pops.
const CALLS: [&str; 3] = ["(*dat_804a000)()", "(*dat_804a004)()", "(*dat_804a008)()"];

/// Unasserted entry chains are recovered by the same strict detector.
#[test]
fn the_default_recovers_the_whole_entry_chain() {
    let code = decompile(None);
    for call in CALLS {
        assert!(code.contains(call), "the default chain stopped before {call}:\n{code}");
    }
    c_behavior::assert_three_call_chain(
        &scratch_file("default-chain", "c"), &code, "chain_entry",
    );
    assert_eq!(raw_calls::indirect_targets(&decompile_output(None, true)), [
        (0x8049019, 'r', 0x804a000),
        (0x8049025, 'r', 0x804a004),
        (0x8049031, 'r', 0x804a008),
    ]);
}

/// The need's own case: one override on the first link recovers all three calls.
#[test]
fn overriding_the_first_link_recovers_the_whole_chain() {
    let code = decompile(Some(&format!("flow {FIRST_LINK_RET} call")));
    for call in CALLS {
        assert!(code.contains(call), "the chain stopped before {call}:\n{code}");
    }
    c_behavior::assert_three_call_chain(
        &scratch_file("first-link-override", "c"), &code, "chain_entry",
    );
    assert_eq!(raw_calls::indirect_targets(&decompile_output(
        Some(&format!("flow {FIRST_LINK_RET} call")), true,
    )), [
        (0x8049019, 'r', 0x804a000),
        (0x8049025, 'r', 0x804a004),
        (0x8049031, 'r', 0x804a008),
    ]);
}

/// A caller can still override the plain epilogue independently; it does not
/// disturb the automatically recovered links before it.
#[test]
fn overriding_the_plain_epilogue_extends_to_nothing() {
    let code = decompile(Some(&format!("flow {EPILOGUE_RET} call")));
    for call in CALLS {
        assert!(code.contains(call), "the default chain stopped before {call}:\n{code}");
    }
    assert!(code.contains("funcboundflow:"), "the epilogue override did not stay local:\n{code}");
    let raw = decompile_output(Some(&format!("flow {EPILOGUE_RET} call")), true);
    assert_eq!(raw_calls::indirect_targets(&raw), [
        (0x8049019, 'r', 0x804a000),
        (0x8049025, 'r', 0x804a004),
        (0x8049031, 'r', 0x804a008),
        (0x8049032, 's', 0),
    ]);
    let mut saw_block = false;
    for block in raw.lines().filter_map(|line| line.strip_prefix("Basic Block ")) {
        let extent = block.split_whitespace().last().expect("raw block extent");
        let (start, end) = extent.split_once('-').expect("raw block address range");
        let start = u64::from_str_radix(start.strip_prefix("0x").unwrap(), 16).unwrap();
        let end = u64::from_str_radix(end.strip_prefix("0x").unwrap(), 16).unwrap();
        assert!(start >= 0x804900e && end <= 0x8049032,
            "the epilogue override absorbed an adjacent function's instructions:\n{raw}");
        saw_block = true;
    }
    assert!(saw_block, "CLI must expose full instruction extents:\n{raw}");
}
