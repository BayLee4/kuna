//! End-to-end coverage for direct calls through Mach-O import-pointer slots.

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

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../..")
        .canonicalize()
        .unwrap()
}

fn boot() -> Option<ConsoleProgram> {
    let root = repo_root();
    let specs = vec![root.join("specs").to_str().unwrap().to_string()];
    let fixture = root.join("decompiler/crates/kuna-analysis/tests/fixtures/macho_import_slots");
    match bootstrap_from_object(fixture.to_str().unwrap(), "", &specs) {
        Ok(program) => Some(program),
        Err(error) => {
            eprintln!(
                "verify_macho_import_slots: skipping (build `.sla` with `make specs`): {}",
                error.explain()
            );
            None
        }
    }
}

fn decompile(program: ConsoleProgram, setup: &[&str]) -> Funcdata {
    let commands: Vec<String> = setup.iter().map(|command| command.to_string()).collect();
    let count = commands.len();
    let mut status = ConsoleCommands::into_status(commands);
    register_decomp_commands(&mut status);
    {
        let data = status.get_data_mut(DECOMPILE_MODULE).unwrap();
        data.as_any_mut()
            .downcast_mut::<IfaceDecompData>()
            .unwrap()
            .conf = Some(program);
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

#[test]
fn peimportcall_binds_only_the_typed_macho_import_slot() {
    let Some(on_program) = boot() else { return };
    let on = decompile(
        on_program,
        &["load function _call_slots", "decompile", "print C"],
    );
    assert_eq!(on.num_calls(), 2);
    let mut bound = 0;
    let mut ordinary = 0;
    for index in 0..on.num_calls() {
        let call = on.get_call_specs(index);
        let op = on.obank().get(call.get_op()).unwrap();
        assert_eq!(op.num_input(), 1);
        if call.get_name() == "objc_msgSend" {
            assert_eq!(op.code(), OpCode::CPUI_CALL);
            bound += 1;
        } else {
            assert_eq!(op.code(), OpCode::CPUI_CALLIND);
            assert!(call.get_entry_address().is_invalid());
            assert!(call_facts::target_reads(&on, op.get_in(0).unwrap(), 0x100002000),
                "ordinary __objc_msgrefs must remain a read of its own data slot");
            ordinary += 1;
        }
    }
    assert_eq!((bound, ordinary), (1, 1));

    let Some(off_program) = boot() else { return };
    let off = decompile(
        off_program,
        &[
            "option peimportcall off",
            "load function _call_slots",
            "decompile",
            "print C",
        ],
    );
    assert_eq!(off.num_calls(), 2);
    for address in [0x100001000, 0x100002000] {
        let matches = (0..off.num_calls()).filter(|&index| {
            let call = off.get_call_specs(index);
            let op = off.obank().get(call.get_op()).unwrap();
            op.code() == OpCode::CPUI_CALLIND && op.num_input() == 1
                && call.get_entry_address().is_invalid()
                && call.get_name() != "objc_msgSend"
                && call_facts::target_reads(&off, op.get_in(0).unwrap(), address)
        }).count();
        assert_eq!(matches, 1, "disabled binding must retain each original slot independently");
    }
}
