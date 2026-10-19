//! Genuine MIPS raw and final consumers; build the original role fixtures first.

use std::path::PathBuf;
use std::rc::Rc;
use kuna_base::address::Address;
use kuna_console::engine::{bootstrap_from_object, ConsoleProgram};
use kuna_console::grammar::{parse_c, DataOrg};
use kuna_decomp::decompile_drive::{build_and_follow_flow, decompile_func_full, print_c};
use kuna_decomp::funcdata::Funcdata;
use kuna_num::opcodes::OpCode;

fn program(readonly: u8) -> ConsoleProgram {
    let fixtures = std::env::var_os("KUNA_MIPS_ROLE_FIXTURES").map(PathBuf::from)
        .expect("build_mips_roles.py must supply the genuine MIPS images");
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../..");
    let mut program = bootstrap_from_object(
        fixtures.join(format!("readonly{readonly}.elf")).to_str().unwrap(), "",
        &[root.join("specs").to_str().unwrap().to_owned()],
    ).expect("original MIPS images and built processor specifications");
    program.read_loader_symbols().unwrap();
    program.commit_pending_analysis().unwrap();
    program.arch_mut().readonlypropagate = true;
    program.arch_mut().set_print_language_checked("c-language").unwrap();
    program
}

fn entry(program: &ConsoleProgram, name: &str) -> Address {
    program.function_entries().find(|(symbol, _)| *symbol == name)
        .map(|(_, address)| address.clone()).expect("original function symbol")
}

fn register_access(fd: &Funcdata, address: &Address, size: i32) -> (usize, usize) {
    let matches = |id| fd.vbank().get(id).is_some_and(|vn|
        vn.get_addr() == address && vn.get_size() == size);
    let mut reads = 0;
    let mut writes = 0;
    for (_, id) in fd.obank().iter_all() {
        let op = fd.obank().get(id).unwrap();
        reads += (0..op.num_input()).filter_map(|slot| op.get_in(slot)).filter(|id| matches(*id)).count();
        writes += usize::from(op.get_out().is_some_and(matches));
    }
    (reads, writes)
}

fn opcode_count(fd: &Funcdata, code: OpCode) -> usize {
    fd.obank().iter_all().filter(|(_, id)| fd.obank().get(*id).unwrap().code() == code).count()
}

#[test]
#[ignore = "Requires genuine MIPS role fixtures and built processor specifications"]
fn original_loaded_calls_distinguish_dirty_full_and_partial_internal_role_definitions() {
    for readonly in [0, 1] {
        let mut program = program(readonly);
        let gp = program.arch().get_register_varnode(b"gp").unwrap();
        let address = Address::new(gp.space.clone().unwrap(), gp.offset);
        assert_eq!(gp.size, 4);
        assert!(program.arch().default_fp().expect("loaded MIPS default prototype")
            .internal_list().iter().any(|role|
                role.space.as_ref().zip(gp.space.as_ref()).is_some_and(|(a, b)| Rc::ptr_eq(a, b))
                    && role.offset == gp.offset && role.size == gp.size));
        for name in ["caller_dirty", "caller_full", "caller_partial", "caller_removed"] {
            let entry = entry(&program, name);
            let fd = build_and_follow_flow(program.arch_mut(), name, entry, 0).unwrap();
            assert_eq!(opcode_count(&fd, OpCode::CPUI_CALLIND), 2, "{name}/readonly{readonly}");
            let (reads, writes) = register_access(&fd, &address, 4);
            assert!(reads > 0 && writes > 0, "{name}: retain saved incoming GP and real definitions");
            if name == "caller_partial" {
                assert!(fd.obank().iter_all().any(|(_, id)| {
                    let op = fd.obank().get(id).unwrap();
                    op.get_out().is_some_and(|id| fd.vbank().get(id).unwrap().get_addr() == &address)
                        && (0..op.num_input()).filter_map(|slot| op.get_in(slot)).any(|id|
                            fd.vbank().get(id).unwrap().get_addr() == &address)
                }), "partial definition must still consume its incoming GP bytes");
            }
        }
    }
}

#[test]
#[ignore = "Requires genuine MIPS role fixtures and built processor specifications"]
fn natural_child_preserves_raw_gp_write_and_return_reads() {
    let mut program = program(0);
    let gp = program.arch().get_register_varnode(b"gp").unwrap();
    let ra = program.arch().get_register_varnode(b"ra").unwrap();
    let gp_address = Address::new(gp.space.unwrap(), gp.offset);
    let ra_address = Address::new(ra.space.unwrap(), ra.offset);
    let at = entry(&program, "dirty_gp_natural");
    let fd = build_and_follow_flow(program.arch_mut(), "dirty_gp_natural", at, 0).unwrap();
    assert!(register_access(&fd, &gp_address, 4).1 > 0);
    assert!(register_access(&fd, &ra_address, 4).0 > 0);
    assert_eq!(opcode_count(&fd, OpCode::CPUI_STORE), 0);
    assert_eq!(opcode_count(&fd, OpCode::CPUI_RETURN), 1);
}

#[test]
#[ignore = "Requires genuine MIPS role fixtures and built processor specifications"]
fn actual_private_spill_reload_and_escape_keep_raw_effects_and_source_formals() {
    for (name, declaration, stores, loads, expected_global) in [
        ("private_gp_spill", "extern int private_gp_spill(void);", 1, 0, None),
        ("private_gp_reload", "extern int private_gp_reload(void);", 1, 1, Some("alternate_value")),
        ("private_gp_escape", "extern void private_gp_escape(void);", 2, 0, Some("escaped_slot")),
        ("dirty_gp_natural", "extern void dirty_gp_natural(void);", 0, 0, None),
    ] {
        let mut program = program(0);
        let at = entry(&program, name);
        let raw = build_and_follow_flow(program.arch_mut(), name, at.clone(), 0).unwrap();
        assert_eq!(opcode_count(&raw, OpCode::CPUI_STORE), stores, "{name}");
        assert_eq!(opcode_count(&raw, OpCode::CPUI_LOAD), loads, "{name}");
        let arch = program.arch();
        let (addr_size, word_size) = arch.data_org();
        let models = arch.proto_model_names().collect::<Vec<_>>();
        let mut pieces = None;
        parse_c(declaration, arch.types(), DataOrg { addr_size, word_size }, &models,
            |parsed, _| { pieces = Some(parsed); Ok(()) }).unwrap();
        let fd = decompile_func_full(program.arch_mut(), name, at, 0, &[], pieces.as_ref()).unwrap();
        assert_eq!(fd.get_func_proto().num_params(), 0, "{name}: GP is not an invented source formal");
        let c = print_c(program.arch_mut(), &fd).unwrap();
        if let Some(global) = expected_global {
            assert!(c.contains(global), "{name}: lost authored global observation:\n{c}");
        }
    }
}

#[test]
#[ignore = "Requires genuine MIPS role fixtures and built processor specifications"]
fn actual_direct_child_preserves_a_later_implicit_raw_gp_read() {
    let mut program = program(0);
    let gp = program.arch().get_register_varnode(b"gp").unwrap();
    let address = Address::new(gp.space.unwrap(), gp.offset);
    for (name, observes_gp) in [("direct_gp_parent", false), ("direct_gp_read_parent", true)] {
        let at = entry(&program, name);
        let fd = build_and_follow_flow(program.arch_mut(), name, at, 0).unwrap();
        assert_eq!(fd.num_calls(), 1);
        assert_eq!(fd.get_call_specs(0).get_entry_address(), &entry(&program, "dirty_gp"));
        let reads = register_access(&fd, &address, 4).0;
        assert_eq!(reads > 0, observes_gp, "{name}: implicit GP load is independent of child source arity");
        assert_eq!(opcode_count(&fd, OpCode::CPUI_LOAD), if observes_gp { 2 } else { 1 });
    }
}
