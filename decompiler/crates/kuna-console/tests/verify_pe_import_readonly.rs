//! End-to-end regression gate for a PE Import Address Table inside executable
//! read-only memory. The Windows loader overwrites an IAT slot before execution,
//! so its on-disk hint/name RVA is not a constant even though the section is RX.

use std::path::PathBuf;

#[path = "common/call_facts.rs"]
mod call_facts;

use kuna_decomp::funcdata::Funcdata;
use kuna_num::opcodes::OpCode;
use kuna_console::engine::{bootstrap_from_object, ConsoleProgram};
use kuna_console::ifacedecomp::{
    execute, register_decomp_commands, IfaceDecompData, DECOMPILE_MODULE,
};
use kuna_console::ifaceterm::ConsoleCommands;

const FIXTURE: &str = "pe_iatincode_readonly_i386.exe";
const ENTRY: u64 = 0x401010;

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

fn body(prog: ConsoleProgram) -> Funcdata {
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
    let data = status.get_data_mut(DECOMPILE_MODULE).unwrap().as_any_mut()
        .downcast_mut::<IfaceDecompData>().unwrap();
    let fd = data.fd.take().expect("decompiled function");
    assert!(fd.kuna_pipeline_failure().is_none());
    fd
}

fn assert_nested_calls(fd: &Funcdata, named: bool) {
    assert_eq!(fd.num_calls(), 2);
    let find = |name: &str, raw_target: u64| {
        (0..fd.num_calls()).find(|&index| {
            let call = fd.get_call_specs(index);
            let op = fd.obank().get(call.get_op()).unwrap();
            if named {
                call.get_name() == name && op.code() == OpCode::CPUI_CALL
            } else {
                call.get_entry_address().is_invalid() && call.get_name().is_empty()
                    && op.code() == OpCode::CPUI_CALLIND
                    && call_facts::constant(fd, op.get_in(0).unwrap()) == Some(raw_target)
            }
        }).unwrap_or_else(|| panic!("missing {} target {name} / {raw_target:#x}",
            if named { "bound import" } else { "raw hint/name RVA" }))
    };
    let inner = fd.obank().get(fd.get_call_specs(find("GetModuleHandleA", 0x10b0)).get_op()).unwrap();
    let outer = fd.obank().get(fd.get_call_specs(find("VirtualAlloc", 0x10a0)).get_op()).unwrap();
    assert_eq!(inner.num_input(), 2);
    assert_eq!(call_facts::constant(fd, inner.get_in(1).unwrap()), Some(0));
    assert_eq!(call_facts::constant(fd, outer.get_in(1).unwrap()), Some(0x40));
    assert_eq!(
        call_facts::without_value_casts(fd, outer.get_in(2).unwrap()),
        inner.get_out().expect("inner call's result must reach the outer call"),
    );
}

#[test]
fn peimportcall_off_keeps_the_raw_hint_name_rvas() {
    let prog = load(&[("peimportcall", "off")]);
    assert_nested_calls(&body(prog), false);
}

#[test]
fn default_and_explicit_on_keep_the_nested_calls_named() {
    for options in [&[][..], &[("peimportcall", "on")][..]] {
        let prog = load(options);
        assert_nested_calls(&body(prog), true);
    }
}

#[test]
fn readonly_on_still_preserves_external_reference_identity() {
    let prog = load(&[("peimportcall", "on"), ("readonly", "on")]);
    assert_nested_calls(&body(prog), true);
}
