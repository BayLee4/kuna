//! Return-target versus observable register uses over the original real instructions.
use std::path::PathBuf;
use kuna_base::address::Address;
use kuna_base::xml::DocumentStorage;
use kuna_console::engine::{bootstrap_program, ConsoleProgram};
use kuna_decomp::decompile_drive::build_and_follow_flow;
use kuna_decomp::funcdata::Funcdata;
use kuna_num::opcodes::OpCode;

fn roots() -> Vec<String> {
    vec![PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../specs").to_string_lossy().into_owned()]
}

fn program() -> ConsoleProgram {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../..");
    let source = std::fs::read_to_string(root.join("tests/ghidra/callable/fixtures/return_role_bookkeeping.xml")).unwrap();
    let mut documents = DocumentStorage::new();
    let image = documents.parse_document(source.as_bytes()).unwrap().get_root().clone();
    let mut program = bootstrap_program(image, "RISCV:LE:64:default:gcc", &roots())
        .expect("original RISC-V fixture and built specification");
    program.arch_mut().set_print_language_checked("c-language").unwrap();
    program
}

fn body(program: &mut ConsoleProgram, name: &str, offset: u64) -> Funcdata {
    let code = program.arch().manage().get_default_code_space().unwrap().clone();
    build_and_follow_flow(program.arch_mut(), name, Address::new(code, offset), 0).unwrap()
}

fn read_widths(fd: &Funcdata, address: &Address) -> Vec<i32> {
    fd.obank().iter_all().flat_map(|(_, id)| {
        let op = fd.obank().get(id).unwrap();
        (0..op.num_input()).filter_map(|slot| op.get_in(slot)).filter_map(|id| {
            let vn = fd.vbank().get(id).unwrap();
            (vn.get_addr() == address).then_some(vn.get_size())
        }).collect::<Vec<_>>()
    }).collect()
}

fn has_opcode(fd: &Funcdata, code: OpCode) -> bool {
    fd.obank().iter_all().any(|(_, id)| fd.obank().get(id).unwrap().code() == code)
}

fn low_bytes_from_register(
    fd: &Funcdata, mut value: kuna_decomp::context::VarnodeId, address: &Address, width: i32,
) -> bool {
    let required = fd.vbank().get(value).unwrap().get_size();
    for _ in 0..=fd.obank().iter_all().count() {
        let vn = fd.vbank().get(value).unwrap();
        if vn.get_addr() == address && (required..=width).contains(&vn.get_size()) {
            return true;
        }
        let Some(op) = vn.get_def().and_then(|id| fd.obank().get(id)) else {
            return false;
        };
        let Some(input) = op.get_in(0) else { return false };
        let input_size = fd.vbank().get(input).unwrap().get_size();
        match op.code() {
            OpCode::CPUI_COPY | OpCode::CPUI_CAST if input_size == vn.get_size() => {}
            OpCode::CPUI_SUBPIECE if input_size >= vn.get_size()
                && op.get_in(1).is_some_and(|id| {
                    let offset = fd.vbank().get(id).unwrap();
                    offset.is_constant() && offset.get_offset() == 0
                }) => {}
            _ => return false,
        }
        value = input;
    }
    false
}

#[test]
fn observable_partial_reads_narrowed_targets_and_result_escape_are_not_bookkeeping() {
    for (name, offset, width) in [("partial_read", 0x1100, 8), ("narrowed_target", 0x1200, 4)] {
        let mut program = program();
        let ra = program.arch().get_register_varnode(b"ra").unwrap();
        let address = Address::new(ra.space.unwrap(), ra.offset);
        let fd = body(&mut program, name, offset);
        assert!(read_widths(&fd, &address).iter().any(|size| *size >= width),
            "{name}: preserve the observed low register bytes");
        assert!(has_opcode(&fd, OpCode::CPUI_RETURN));
        if name == "partial_read" {
            assert!(fd.obank().iter_all().any(|(_, id)| {
                let op = fd.obank().get(id).unwrap();
                op.code() == OpCode::CPUI_STORE && op.get_in(2).is_some_and(|value|
                    fd.vbank().get(value).unwrap().get_size() == 4
                        && low_bytes_from_register(&fd, value, &address, ra.size as i32))
            }), "the four-byte store consumes the low bytes of the real link register");
        }
        if name == "narrowed_target" {
            let t1 = program.arch().get_register_varnode(b"t1").unwrap();
            let temporary = Address::new(t1.space.unwrap(), t1.offset);
            let sext = fd.obank().iter_all().find_map(|(_, id)| {
                let op = fd.obank().get(id).unwrap();
                (op.code() == OpCode::CPUI_INT_SEXT).then_some(op)
            }).expect("sext.w sign-extends the low word");
            let low = sext.get_in(0).unwrap();
            let low_vn = fd.vbank().get(low).unwrap();
            assert_eq!(low_vn.get_size(), 4);
            let widened = fd.vbank().get(sext.get_out().unwrap()).unwrap();
            assert_eq!(widened.get_size(), 8);
            assert_eq!(widened.get_addr(), &temporary);
            assert!(low_bytes_from_register(&fd, low, &address, ra.size as i32)
                || fd.obank().iter_all().any(|(_, id)| {
                    let slice = fd.obank().get(id).unwrap();
                    slice.code() == OpCode::CPUI_SUBPIECE && slice.get_time() < sext.get_time()
                        && slice.get_out().is_some_and(|id| {
                            let sliced = fd.vbank().get(id).unwrap();
                            sliced.get_addr() == low_vn.get_addr() && sliced.get_size() == 4
                        })
                        && slice.get_in(0).is_some_and(|id| {
                            let source = fd.vbank().get(id).unwrap();
                            source.get_addr() == &address && source.get_size() == ra.size as i32
                        })
                        && slice.get_in(1).is_some_and(|id| {
                            let offset = fd.vbank().get(id).unwrap();
                            offset.is_constant() && offset.get_offset() == 0
                        })
                }), "the sign extension consumes the actual low word of RA");
            let transfer = fd.obank().iter_all().find_map(|(_, id)| {
                let op = fd.obank().get(id).unwrap();
                (op.code() == OpCode::CPUI_COPY && op.get_time() > sext.get_time()
                    && op.get_in(0).is_some_and(|id| {
                        let vn = fd.vbank().get(id).unwrap();
                        vn.get_addr() == &temporary && vn.get_size() == 8
                    })
                    && op.get_out().is_some_and(|id| {
                        let vn = fd.vbank().get(id).unwrap();
                        vn.get_addr() == &address && vn.get_size() == 8
                    })).then_some(op)
            }).expect("the sign-extended temporary is transferred back to RA");
            assert!(fd.obank().iter_all().any(|(_, id)| {
                let op = fd.obank().get(id).unwrap();
                op.code() == OpCode::CPUI_RETURN && op.get_time() > transfer.get_time()
                    && op.get_in(0).is_some_and(|id| {
                        let target = fd.vbank().get(id).unwrap();
                        target.get_addr() == &address && target.get_size() == 8
                    })
            }), "compressed return consumes the sign-extended RV64 target");
        }
    }
}

#[test]
fn implicit_actual_callee_read_prevents_a_return_address_argument_from_being_hidden() {
    let mut program = program();
    let argument = program.arch().get_register_varnode(b"a2").unwrap();
    let ra = program.arch().get_register_varnode(b"ra").unwrap();
    let argument_address = Address::new(argument.space.unwrap(), argument.offset);
    let ra_address = Address::new(ra.space.unwrap(), ra.offset);
    let child = body(&mut program, "consume_a2", 0x1500);
    assert!(has_opcode(&child, OpCode::CPUI_STORE));
    assert!(read_widths(&child, &argument_address).contains(&(argument.size as i32)));
    let parent = body(&mut program, "implicit_parent", 0x1400);
    assert!(!program.arch().default_fp().expect("loaded RISC-V ABI")
        .possible_output_param(&argument_address, argument.size as i32));
    assert!(read_widths(&parent, &ra_address).contains(&(ra.size as i32)));
    assert!((0..parent.num_calls()).any(|slot| parent.get_call_specs(slot).get_entry_address() == child.get_address()));
    assert!(parent.obank().iter_all().any(|(_, id)| {
        let op = parent.obank().get(id).unwrap();
        op.code() == OpCode::CPUI_COPY
            && op.get_in(0).is_some_and(|id| parent.vbank().get(id).unwrap().get_addr() == &ra_address)
            && op.get_out().is_some_and(|id| parent.vbank().get(id).unwrap().get_addr() == &argument_address)
    }), "actual child STORE receives RA through A2 independently of explicit CALL operands");
}

#[test]
fn mips_tagged_returns_keep_control_bits_separate_from_observable_values() {
    let source = br#"<binaryimage arch="MIPS:LE:32:default:gcc">
<bytechunk space="ram" offset="0x1000" readonly="true">0800e00300000000</bytechunk>
<bytechunk space="ram" offset="0x1100" readonly="true">0100e2330800e00300000000</bytechunk>
<bytechunk space="ram" offset="0x1200" readonly="true">0100e833000088ac0800e00300000000</bytechunk>
<bytechunk space="ram" offset="0x1300" readonly="true">0800e00300009fac</bytechunk>
</binaryimage>"#;
    let mut documents = DocumentStorage::new();
    let image = documents.parse_document(source).unwrap().get_root().clone();
    let mut program = bootstrap_program(image, "MIPS:LE:32:default:gcc", &roots()).unwrap();
    let ra = program.arch().get_register_varnode(b"ra").unwrap();
    let address = Address::new(ra.space.unwrap(), ra.offset);
    for (name, offset, stores, data_mask) in [
        ("tagged_return", 0x1000, false, false), ("result_tag", 0x1100, false, true),
        ("stored_tag", 0x1200, true, true), ("return_delay_store", 0x1300, true, false),
    ] {
        let fd = body(&mut program, name, offset);
        assert!(read_widths(&fd, &address).contains(&4), "{name}");
        assert!(has_opcode(&fd, OpCode::CPUI_RETURN));
        assert_eq!(has_opcode(&fd, OpCode::CPUI_STORE), stores, "{name}");
        if data_mask { assert!(has_opcode(&fd, OpCode::CPUI_INT_AND), "{name}"); }
    }
}
