//! Return-address bookkeeping over genuine RISC-V instructions and compiler
//! model facts. No synthetic IR, supplied complete summaries, or ABI read clears.
//! The compressed return is intentional: the ordinary RISC-V return masks a
//! tag bit, whereas this fixture isolates the existing full-COPY use proof.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::rc::Rc;
use kuna_base::address::Address;
use kuna_base::xml::DocumentStorage;
use kuna_console::engine::{bootstrap_program, ConsoleProgram};
use kuna_decomp::decompile_drive::build_and_follow_flow;
use kuna_decomp::funcdata::Funcdata;
use kuna_decomp::kuna_physicalinputs::{from_raw_flow, EntryRequirements};

fn program() -> ConsoleProgram {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../..").canonicalize().unwrap();
    let source = std::fs::read_to_string(root.join(
        "tests/ghidra/callable/fixtures/return_role_bookkeeping.xml")).unwrap();
    let mut documents = DocumentStorage::new();
    let image = documents.parse_document(source.as_bytes()).unwrap().get_root().clone();
    let mut program = bootstrap_program(image, "RISCV:LE:64:default:gcc",
        &[root.join("specs").to_str().unwrap().to_owned()])
        .expect("build the genuine RISC-V specification before running this raw-flow regression");
    program.arch_mut().set_print_language_checked("c-language").unwrap();
    let ra = program.arch().get_register_varnode(b"ra").unwrap();
    let address = Address::new(ra.space.unwrap(), ra.offset);
    assert!(program.arch().default_fp().unwrap().effect_list().iter().any(|effect|
        effect.get_type() == kuna_decomp::fspec::effect_type::RETURN_ADDRESS
            && effect.get_address() == address && effect.get_size() == ra.size as i32),
        "the real compiler model must declare the incoming return-address role");
    program
}

fn body(program: &mut ConsoleProgram, name: &str, offset: u64) -> Funcdata {
    let code = program.arch().manage().get_default_code_space().unwrap().clone();
    build_and_follow_flow(program.arch_mut(), name, Address::new(code, offset), 0)
        .expect("actual RISC-V instruction decoding and raw flow")
}

fn reads_range(raw: &EntryRequirements, address: &Address, size: i32) -> bool {
    raw.reads.iter().any(|(at, bytes)| *bytes > 0
        && at.get_space().zip(address.get_space()).is_some_and(|(a, b)| Rc::ptr_eq(a, b))
        && at.get_offset() <= address.get_offset()
        && at.get_offset().saturating_add(*bytes as u64)
            >= address.get_offset().saturating_add(size as u64))
}

#[test]
fn actual_full_width_return_copy_is_bookkeeping_but_its_machine_read_survives() {
    let mut program = program();
    let lr = program.arch().get_register_varnode(b"ra").unwrap();
    let address = Address::new(lr.space.unwrap(), lr.offset);
    let fd = body(&mut program, "return_copy", 0x1000);
    let raw = from_raw_flow(&fd, &BTreeMap::new(), None).requirements;
    assert!(raw.is_complete());
    assert!(reads_range(&raw, &address, lr.size as i32),
        "the real incoming link-register read cannot be deleted");
    assert!(raw.is_bookkeeping(&address, lr.size as i32),
        "full-width COPY provenance through the actual RETURN must represent the control target");
}

#[test]
fn observable_partial_reads_narrowed_targets_and_result_escape_are_not_bookkeeping() {
    for (name, offset, read_size) in [
        ("partial_read", 0x1100, 8),
        ("narrowed_target", 0x1200, 4),
        ("output_escape", 0x1300, 8),
    ] {
        let mut program = program();
        let lr = program.arch().get_register_varnode(b"ra").unwrap();
        let address = Address::new(lr.space.unwrap(), lr.offset);
        let fd = body(&mut program, name, offset);
        let raw = from_raw_flow(&fd, &BTreeMap::new(), None).requirements;
        assert!(raw.is_complete(), "{name}");
        assert!(reads_range(&raw, &address, read_size),
            "{name} retains its positive actual link-register read");
        assert!(!raw.is_bookkeeping(&address, read_size),
            "{name} must not hide observable data or truncate the machine return address");
    }
}

#[test]
fn implicit_actual_callee_read_prevents_a_return_address_argument_from_being_hidden() {
    let mut program = program();
    let lr = program.arch().get_register_varnode(b"ra").unwrap();
    let address = Address::new(lr.space.unwrap(), lr.offset);
    let argument = program.arch().get_register_varnode(b"a2").unwrap();
    let argument_address = Address::new(argument.space.unwrap(), argument.offset);
    let child = body(&mut program, "consume_a2", 0x1500);
    let child_raw = Rc::new(from_raw_flow(&child, &BTreeMap::new(), None).requirements);
    assert!(child_raw.is_complete());
    assert!(reads_range(&child_raw, &argument_address, argument.size as i32),
        "the actual STORE callee consumes its implicit A2 value");
    assert!(!child_raw.is_bookkeeping(&argument_address, argument.size as i32));
    let parent = body(&mut program, "implicit_parent", 0x1400);
    assert!(!parent.get_func_proto().model().possible_output_param(&argument_address, argument.size as i32),
        "this case must exercise an implicit child read, not the independent output-register guard");
    let call = (0..parent.num_calls()).map(|slot| parent.get_call_specs(slot))
        .find(|call| call.get_entry_address() == child.get_address())
        .expect("the actual JAL reaches the actual STORE body");
    let callees = BTreeMap::from([(call.get_op(), child_raw)]);
    let raw = from_raw_flow(&parent, &callees, None).requirements;
    assert!(raw.is_complete());
    assert!(reads_range(&raw, &address, lr.size as i32));
    assert!(!raw.is_bookkeeping(&address, lr.size as i32),
        "CALL has no explicit raw argument operand, but the actual child's positive read still observes RA through A2");
}
