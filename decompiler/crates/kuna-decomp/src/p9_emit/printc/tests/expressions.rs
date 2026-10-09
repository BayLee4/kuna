use super::*;
use super::support::{assert_c_source, assert_rust_source, bare_arch, build_fd, build_manager,
    execution_printer, mk_op, name_call_local, ram};
use crate::context::{ArchContext as ContextArch, TypeOp};
use crate::dtype::{type_metatype, Datatype, TypeFactory, TypeFactoryImpl};
use crate::funcdata::Funcdata;
use kuna_base::address::Address;
use kuna_num::opcodes::OpCode;
use std::rc::Rc;

    fn named(nm: &str, size: int4, meta: type_metatype) -> Rc<Datatype> {
        let types = TypeFactoryImpl::new();
        types.setup_sizes(Some(4), 8, 8);
        types.set_max_basetype_size(16);
        types.get_base_named(size, meta, nm).unwrap()
    }

    fn execution_input(fd: &mut Funcdata, name: &str, ty: Rc<Datatype>)
        -> crate::context::VarnodeId
    {
        let vn = fd.new_unique(ty.get_size(), Some(ty));
        name_call_local(fd, vn, name);
        vn
    }

    fn execution_call(
        fd: &mut Funcdata, name: &str, ty: Rc<Datatype>, offset: u64,
    ) -> crate::context::VarnodeId {
        let op = mk_op(fd, 1, offset, OpCode::CPUI_CALL);
        fd.op_set_opcode(op, TypeOp::new(OpCode::CPUI_CALL, crate::op::pcodeop_flags::call, "CALL"));
        let target = Address::new(ram(fd), offset + 0x1000);
        let target_vn = fd.new_constant(8, target.get_offset());
        fd.op_set_input(op, target_vn, 0).unwrap();
        let out = fd.new_unique(ty.get_size(), Some(ty));
        fd.op_set_output(op, out).unwrap();
        fd.vbank_mut().get_mut(out).unwrap().set_implied();
        let mut specs = crate::fspec::FuncCallSpecs::new(op, target.clone());
        specs.set_funcdata(target, name).unwrap();
        fd.push_call_specs(specs);
        out
    }

    #[test]
    fn emitted_default_high_characters_match_declared_byte_values() {
        let fd = build_fd();
        let arch = bare_arch();
        let mut c = String::from("#include <assert.h>\nint main(void){\n");
        let mut rust = String::from("fn main(){\n");
        for signed in [false, true] {
            let types = TypeFactoryImpl::new();
            types.setup_sizes(Some(4), 8, 8);
            types.set_max_basetype_size(8);
            let ty = types.get_type_char_signed(
                if signed { "schar" } else { "uchar" },
                if signed { type_metatype::TYPE_INT } else { type_metatype::TYPE_UINT },
            ).unwrap();
            for value in [0, 0x41, 0x7f, 0x80, 0xfe, 0xff] {
                for is_rust in [false, true] {
                    let mut print = execution_printer(&arch, is_rust);
                    print.push_char_constant_ir(&fd, &ty, value, OpId::default(), VarnodeId::default());
                    let expression = print.emit_mut().output_str().to_string();
                    if is_rust {
                        let expected = if signed {
                            format!("{}i8", value as u8 as i8)
                        } else {
                            format!("{value}u8")
                        };
                        rust.push_str(&format!("assert_eq!({expression}, {expected});\n"));
                    } else {
                        let expected = if signed { value as u8 as i8 as i32 } else { value as i32 };
                        c.push_str(&format!("assert(({expression}) == {expected});\n"));
                    }
                }
            }
        }
        c.push_str("return 0;}\n");
        rust.push_str("}\n");
        assert_c_source(&c, "default-high-character");
        assert_rust_source(&rust, "default-high-character");
    }

    #[test]
    fn emitted_rust_nested_arithmetic_evaluates_calls_once() {
        let mut fd = build_fd();
        fd.set_high_level();
        let ty = named("u32", 4, type_metatype::TYPE_UINT);
        let first = execution_call(&mut fd, "next_value", ty.clone(), 0x1000);
        let second = execution_call(&mut fd, "next_value", ty.clone(), 0x1004);
        let mul = mk_op(&mut fd, 2, 0x1008, OpCode::CPUI_INT_MULT);
        fd.op_set_input(mul, first, 0).unwrap();
        fd.op_set_input(mul, second, 1).unwrap();
        let product = fd.new_unique(4, Some(ty.clone()));
        fd.op_set_output(mul, product).unwrap();
        fd.vbank_mut().get_mut(product).unwrap().set_implied();
        let add = mk_op(&mut fd, 2, 0x100c, OpCode::CPUI_INT_ADD);
        let literal = fd.new_constant(4, 0xffffffff);
        fd.op_set_input(add, product, 0).unwrap();
        fd.op_set_input(add, literal, 1).unwrap();
        let result = fd.new_unique(4, Some(ty));
        fd.op_set_output(add, result).unwrap();
        let arch = bare_arch();
        let mut print = execution_printer(&arch, true);
        print.op_push_ir(&fd, &arch, add, None);
        let emitted = print.emit_mut().output_str().to_string();
        let source = format!(r#"
use std::sync::atomic::{{AtomicU32, Ordering}};
static CALLS: AtomicU32 = AtomicU32::new(0);
fn next_value() -> u32 {{ CALLS.fetch_add(1, Ordering::SeqCst) + 1 }}
fn consumer() -> u32 {{ {emitted} }}
fn main() {{
    assert_eq!(consumer(), 1);
    assert_eq!(CALLS.load(Ordering::SeqCst), 2);
}}
"#);
        assert_rust_source(&source, "single-evaluation");
    }

    #[test]
    fn emitted_rust_u128_variable_addition_wraps() {
        let mut fd = build_fd();
        fd.set_high_level();
        let ty = named("u128", 16, type_metatype::TYPE_UINT);
        let a = execution_input(&mut fd, "a", ty.clone());
        let b = execution_input(&mut fd, "b", ty.clone());
        let add = mk_op(&mut fd, 2, 0x1000, OpCode::CPUI_INT_ADD);
        fd.op_set_input(add, a, 0).unwrap();
        fd.op_set_input(add, b, 1).unwrap();
        let result = fd.new_unique(16, Some(ty));
        fd.op_set_output(add, result).unwrap();
        let arch = bare_arch();
        let mut print = execution_printer(&arch, true);
        print.op_push_ir(&fd, &arch, add, None);
        let emitted = print.emit_mut().output_str().to_string();
        let source = format!(r#"
fn consumer(a: u128, b: u128) -> u128 {{ {emitted} }}
fn main() {{
    assert_eq!(consumer(u128::MAX, 2), 1);
    assert_eq!(consumer(1u128 << 127, 1u128 << 127), 0);
}}
"#);
        assert_rust_source(&source, "u128-variable");
    }

    #[test]
    fn emitted_rust_narrow_addition_wraps_before_widening() {
        let mut fd = build_fd();
        fd.set_high_level();
        let narrow = named("u8", 1, type_metatype::TYPE_UINT);
        let wide = named("u32", 4, type_metatype::TYPE_UINT);
        let a = execution_input(&mut fd, "a", narrow.clone());
        let b = execution_input(&mut fd, "b", narrow.clone());
        let add = mk_op(&mut fd, 2, 0x1000, OpCode::CPUI_INT_ADD);
        fd.op_set_input(add, a, 0).unwrap();
        fd.op_set_input(add, b, 1).unwrap();
        let sum = fd.new_unique(1, Some(narrow));
        fd.op_set_output(add, sum).unwrap();
        fd.vbank_mut().get_mut(sum).unwrap().set_implied();
        // Genuine p-code width transition, not an invalid merge of differently
        // sized High members manufactured to exercise declaration recovery.
        let extend = mk_op(&mut fd, 1, 0x1004, OpCode::CPUI_INT_ZEXT);
        fd.op_set_input(extend, sum, 0).unwrap();
        let result = fd.new_unique(4, Some(wide));
        fd.op_set_output(extend, result).unwrap();
        let arch = bare_arch();
        let mut print = execution_printer(&arch, true);
        print.op_push_ir(&fd, &arch, extend, None);
        let emitted = print.emit_mut().output_str().to_string();
        let source = format!(r#"
fn consumer(a: u8, b: u8) -> u32 {{ {emitted} }}
fn main() {{
    assert_eq!(consumer(255, 2), 1);
    assert_eq!(consumer(128, 128), 0);
    assert_eq!(consumer(200, 7), 207);
}}
"#);
        assert_rust_source(&source, "narrow-before-widening");
    }

    #[test]
    fn emitted_rust_pointer_stride_and_index_evaluation_are_preserved() {
        use crate::dtype::TypeFactory;
        if !cfg!(target_pointer_width = "64") {
            eprintln!("language stride execution: skipping (fixture requires a 64-bit host)");
            return;
        }
        let arch = bare_arch();
        let types = arch.types_rc();
        let cell = types.get_base(4, type_metatype::TYPE_UINT).unwrap();
        let pointer = types.get_type_pointer(8, cell, 1).unwrap();
        let index = types.get_base(8, type_metatype::TYPE_INT).unwrap();
        let manager = Rc::new(build_manager());
        let mut context = ContextArch::new_shared(manager.clone());
        context.types = Some(arch.types_rc());
        let mut fd = Funcdata::new("stride", "stride", Rc::new(context),
            Address::new(manager.get_space_by_name("ram").unwrap().clone(), 0x1000),
            0x1000_0000, 0x40).unwrap();
        fd.set_high_level();
        let root = fd.bblocks_root_pub();
        let block = fd.bblocks_mut().new_block_basic(root);
        let p = execution_input(&mut fd, "p", pointer.clone());
        let i = execution_call(&mut fd, "next_index", index, 0x1000);
        let index_call = fd.vbank().get(i).unwrap().get_def().unwrap();
        fd.op_insert_end(index_call, block);
        let add = mk_op(&mut fd, 3, 0x1004, OpCode::CPUI_PTRADD);
        let stride = fd.new_constant(8, 8); // deliberately not sizeof(u32)
        fd.op_set_input(add, p, 0).unwrap();
        fd.op_set_input(add, i, 1).unwrap();
        fd.op_set_input(add, stride, 2).unwrap();
        let result = fd.new_unique(8, Some(pointer));
        fd.op_set_output(add, result).unwrap();
        fd.op_insert_end(add, block);
        fd.action_set_casts();
        let mut print = execution_printer(&arch, true);
        print.op_push_ir(&fd, &arch, add, None);
        let emitted = print.emit_mut().output_str().to_string();
        let source = format!(r#"
use std::sync::atomic::{{AtomicU32, Ordering}};
static CALLS: AtomicU32 = AtomicU32::new(0);
fn next_index() -> i64 {{ CALLS.fetch_add(1, Ordering::SeqCst); -1 }}
unsafe fn consumer(p: *mut u32) -> *mut u32 {{ {emitted} }}
fn main() {{ unsafe {{
    let mut cells = [0x11223344u32, 11, 22, 33, 0xaabbccdd];
    let result = consumer(cells.as_mut_ptr().add(3));
    assert_eq!(result, cells.as_mut_ptr().add(1));
    assert_eq!(CALLS.load(Ordering::SeqCst), 1);
    *result = 77;
    assert_eq!(cells, [0x11223344, 77, 22, 33, 0xaabbccdd]);
}} }}
"#);
        assert_rust_source(&source, "stride-single-evaluation");
    }

    #[test]
    fn emitted_rust_pointer_at_host_address_width_preserves_cells() {
        use crate::dtype::TypeFactory;
        let target_size = std::mem::size_of::<usize>() as int4;
        let arch = bare_arch();
        let types = arch.types_rc();
        let cell = types.get_base(4, type_metatype::TYPE_UINT).unwrap();
        let pointer = types.get_type_pointer(target_size, cell, 1).unwrap();
        let index = types.get_base(target_size, type_metatype::TYPE_INT).unwrap();
        let mut fd = build_fd();
        fd.set_high_level();
        let p = execution_input(&mut fd, "p", pointer.clone());
        let i = execution_input(&mut fd, "i", index);
        let add = mk_op(&mut fd, 3, 0x1000, OpCode::CPUI_PTRADD);
        let stride = fd.new_constant(target_size, 4);
        fd.op_set_input(add, p, 0).unwrap();
        fd.op_set_input(add, i, 1).unwrap();
        fd.op_set_input(add, stride, 2).unwrap();
        let result = fd.new_unique(target_size, Some(pointer));
        fd.op_set_output(add, result).unwrap();
        let mut print = execution_printer(&arch, true);
        print.op_push_ir(&fd, &arch, add, None);
        let emitted = print.emit_mut().output_str().to_string();
        let bits = target_size * 8;
        let source = format!(
            "unsafe fn consumer(p: *mut u32, i: i{bits}) -> *mut u32 {{ {emitted} }}\n\
             fn main() {{ unsafe {{\n\
                 let mut cells = [11u32, 22, 33];\n\
                 let base = cells.as_mut_ptr();\n\
                 assert_eq!(consumer(base, 1), base.add(1));\n\
                 *consumer(base, 1) = 77;\n\
                 assert_eq!(cells, [11, 77, 33]);\n\
             }} }}\n"
        );
        assert_rust_source(&source, "host-width-pointer");
    }

    #[test]
    fn emitted_rust_actual_array_load_store_and_one_past_address_execute() {
        use crate::dtype::TypeFactory;
        if !cfg!(target_pointer_width = "64") {
            eprintln!("language array execution: skipping (fixture requires a 64-bit host)");
            return;
        }
        let arch = bare_arch();
        let types = arch.types_rc();
        let cell = types.get_base(4, type_metatype::TYPE_UINT).unwrap();
        let array = types.get_type_array(5, cell.clone()).unwrap();
        let array_pointer = types.get_type_pointer(8, array, 1).unwrap();
        let pointer = types.get_type_pointer(8, cell.clone(), 1).unwrap();
        let index = types.get_base(8, type_metatype::TYPE_INT).unwrap();
        let mut fd = build_fd();
        fd.set_high_level();
        let p = execution_input(&mut fd, "p", array_pointer);
        let i = execution_input(&mut fd, "i", index);
        // Array decay retains pointer-sized p-code storage. PTRSUB exposes
        // the pointed-to array expression; PTRADD indexes that expression.
        let decay = mk_op(&mut fd, 2, 0x0ffc, OpCode::CPUI_PTRSUB);
        let zero = fd.new_constant(8, 0);
        fd.op_set_input(decay, p, 0).unwrap();
        fd.op_set_input(decay, zero, 1).unwrap();
        let cells = fd.new_unique(8, Some(pointer.clone()));
        fd.op_set_output(decay, cells).unwrap();
        fd.vbank_mut().get_mut(cells).unwrap().set_implied();
        let add = mk_op(&mut fd, 3, 0x1000, OpCode::CPUI_PTRADD);
        let stride = fd.new_constant(8, 4);
        fd.op_set_input(add, cells, 0).unwrap();
        fd.op_set_input(add, i, 1).unwrap();
        fd.op_set_input(add, stride, 2).unwrap();
        let address = fd.new_unique(8, Some(pointer));
        fd.op_set_output(add, address).unwrap();
        fd.vbank_mut().get_mut(address).unwrap().set_implied();
        let mut print = execution_printer(&arch, true);
        print.op_push_ir(&fd, &arch, add, None);
        let address_text = print.emit_mut().output_str().to_string();
        let load = mk_op(&mut fd, 2, 0x1004, OpCode::CPUI_LOAD);
        let space = fd.new_constant(4, ram(&fd).get_index() as u64);
        fd.op_set_input(load, space, 0).unwrap();
        fd.op_set_input(load, address, 1).unwrap();
        let loaded = fd.new_unique(4, Some(cell.clone()));
        fd.op_set_output(load, loaded).unwrap();
        let mut print = execution_printer(&arch, true);
        print.op_push_ir(&fd, &arch, load, None);
        let load_text = print.emit_mut().output_str().to_string();
        let store = mk_op(&mut fd, 3, 0x1008, OpCode::CPUI_STORE);
        let value = execution_input(&mut fd, "value", cell);
        fd.op_set_input(store, space, 0).unwrap();
        fd.op_set_input(store, address, 1).unwrap();
        fd.op_set_input(store, value, 2).unwrap();
        let mut print = execution_printer(&arch, true);
        print.emit_statement(&fd, &arch, store);
        let store_text = print.emit_mut().output_str().to_string();
        let source = format!(r#"
fn main() {{ unsafe {{
    let mut cells = [0x11223344u32, 11, 22, 33, 0xaabbccdd];
    let p = &mut cells as *mut [u32; 5];
    for (i, expected) in [(1i64, 11u32), (2, 22), (3, 33)] {{
        let loaded = {load_text};
        assert_eq!(loaded, expected);
        let address = {address_text};
        assert_eq!(address, cells.as_mut_ptr().add(i as usize));
    }}
    let i = 5i64;
    let one_past = {address_text};
    assert_eq!(one_past, cells.as_mut_ptr().add(5));
    for (i, value) in [(1i64, 101u32), (3, 303)] {{
        {store_text}
    }}
    assert_eq!(cells, [0x11223344, 101, 22, 303, 0xaabbccdd]);
    // P-code computes a target-width byte offset, not an unbounded array
    // element index: ((2^62 + 1) * 4) mod 2^64 is four.
    let i = (1i64 << 62) + 1;
    let loaded = {load_text};
    assert_eq!(loaded, 101);
    let wrapped_address = {address_text};
    assert_eq!(wrapped_address, cells.as_mut_ptr().add(1));
    let value = 77u32;
    {store_text}
    assert_eq!(cells, [0x11223344, 77, 22, 303, 0xaabbccdd]);
}} }}
"#);
        assert_rust_source(&source, "actual-array");
    }

    #[test]
    fn emitted_integer_arithmetic_executes_at_its_pcode_width() {
        for rust in [true, false] {
            let mut source = if rust { String::new() } else {
                "#include <stdint.h>\n#include <assert.h>\n".to_string()
            };
            let mut checks = String::new();
            for size in [1, 2, 4, 8] {
                for signed in [false, true] {
                    let bits = size * 8;
                    let mask = (1u128 << bits) - 1;
                    let tyname = if rust {
                        format!("{}{bits}", if signed { "i" } else { "u" })
                    } else {
                        format!("{}int{bits}_t", if signed { "" } else { "u" })
                    };
                    for (opname, opcode) in [
                        ("add", OpCode::CPUI_INT_ADD),
                        ("sub", OpCode::CPUI_INT_SUB),
                        ("mul", OpCode::CPUI_INT_MULT),
                    ] {
                        for compound in [false, true] {
                            let name = format!("f_{bits}_{signed}_{opname}_{compound}");
                            let mut fd = build_fd();
                            fd.set_high_level();
                            let meta = if signed { type_metatype::TYPE_INT } else { type_metatype::TYPE_UINT };
                            let ty = named(&tyname, size, meta);
                            let a = execution_input(&mut fd, "a", ty.clone());
                            let b = execution_input(&mut fd, "b", ty.clone());
                            let op = mk_op(&mut fd, 2, 0x1000, opcode);
                            fd.op_set_input(op, a, 0).unwrap();
                            fd.op_set_input(op, b, 1).unwrap();
                            let out = fd.new_unique(size, Some(ty));
                            fd.op_set_output(op, out).unwrap();
                            name_call_local(&mut fd, out, "result");
                            if compound {
                                let high = fd.vbank().get(a).unwrap().get_high().unwrap();
                                let other = fd.vbank().get(out).unwrap().get_high().unwrap();
                                let mut writes = Vec::new();
                                fd.with_high_split(|bank, ctx| {
                                    bank.merge_internal(high, other, false, ctx, &mut |vn, high, group| {
                                        writes.push((vn, high, group));
                                    })
                                }).unwrap();
                                for (vn, high, group) in writes {
                                    fd.vbank_mut().get_mut(vn).unwrap().set_high(high, group);
                                }
                                fd.high_bank_mut().get_mut(high).unwrap().set_kuna_name("a");
                            }
                            let mut arch = bare_arch();
                            arch.ctypes = false;
                            arch.realtypes = false;
                            let mut print = execution_printer(&arch, rust);
                            if compound { print.emit_statement(&fd, &arch, op); }
                            else { print.op_push_ir(&fd, &arch, op, None); }
                            let emitted = print.emit_mut().output_str().to_string();
                            let body = if compound { format!("{emitted}\nreturn a;") }
                                else { format!("return {emitted};") };
                            if rust {
                                source.push_str(&format!("fn {name}(mut a: {tyname}, b: {tyname}) -> {tyname} {{ {body} }}\n"));
                            } else {
                                source.push_str(&format!("{tyname} {name}({tyname} a, {tyname} b) {{ {body} }}\n"));
                            }
                            // C signed overflow is not defined under ordinary
                            // flags. Its control arm uses only defined inputs;
                            // Rust must preserve p-code bits across overflow.
                            let cases: Vec<(u128, u128)> = if !rust && signed {
                                vec![(7, 3), (12, 2)]
                            } else if !rust && size < 4 && opname == "mul" {
                                // u16 promotes to int, but 65535*2 still fits
                                // int: the return must truncate to 65534.
                                if size == 2 { vec![(65535, 2)] }
                                else { vec![(127, 3), (17, 9)] }
                            } else {
                                vec![(mask, 2), (0, 1), (mask >> 1, 3), ((mask >> 1) + 1, mask)]
                            };
                            for (a, b) in cases {
                                let expected = match opname {
                                    "add" => (a + b) & mask,
                                    "sub" => (a + mask + 1 - b) & mask,
                                    _ => (a * b) & mask,
                                };
                                if rust {
                                    checks.push_str(&format!("assert_eq!(({name}({a}u64 as {tyname}, {b}u64 as {tyname}) as u64) & {mask}u64, {expected}u64);\n"));
                                } else {
                                    checks.push_str(&format!("assert((((uint64_t){name}(({tyname})UINT64_C({a}), ({tyname})UINT64_C({b}))) & UINT64_C({mask})) == UINT64_C({expected}));\n"));
                                }
                            }
                        }
                    }
                }
            }
            source.push_str(&if rust { format!("fn main() {{ {checks} }}") }
                else { format!("int main(void) {{ {checks} return 0; }}") });
            if rust { assert_rust_source(&source, "integers"); }
            else { assert_c_source(&source, "integers"); }
        }
    }

    #[test]
    fn emitted_pointer_offsets_preserve_cells_and_guards() {
        use crate::dtype::TypeFactory;
        if !cfg!(target_pointer_width = "64") {
            eprintln!("language pointer execution: skipping (fixture requires a 64-bit host)");
            return;
        }
        for rust in [true, false] {
            let mut arch = bare_arch();
            arch.ctypes = false;
            arch.realtypes = false;
            let types = arch.types_rc();
            let cell = types.get_base(4, type_metatype::TYPE_UINT).unwrap();
            let pointer = types.get_type_pointer(8, cell.clone(), 1).unwrap();
            let index = types.get_base(8, type_metatype::TYPE_INT).unwrap();
            let mut fd = build_fd();
            fd.set_high_level();
            let p = execution_input(&mut fd, "p", pointer.clone());
            let i = execution_input(&mut fd, "i", index);
            let add = mk_op(&mut fd, 3, 0x1000, OpCode::CPUI_PTRADD);
            let stride = fd.new_constant(8, 4);
            fd.op_set_input(add, p, 0).unwrap();
            fd.op_set_input(add, i, 1).unwrap();
            fd.op_set_input(add, stride, 2).unwrap();
            let address = fd.new_unique(8, Some(pointer));
            fd.op_set_output(add, address).unwrap();
            fd.vbank_mut().get_mut(address).unwrap().set_implied();
            let mut print = execution_printer(&arch, rust);
            print.op_push_ir(&fd, &arch, add, None);
            let address_text = print.emit_mut().output_str().to_string();
            let load = mk_op(&mut fd, 2, 0x1004, OpCode::CPUI_LOAD);
            let space = fd.new_constant(4, ram(&fd).get_index() as u64);
            fd.op_set_input(load, space, 0).unwrap();
            fd.op_set_input(load, address, 1).unwrap();
            let loaded = fd.new_unique(4, Some(cell.clone()));
            fd.op_set_output(load, loaded).unwrap();
            let mut print = execution_printer(&arch, rust);
            print.op_push_ir(&fd, &arch, load, None);
            let load_text = print.emit_mut().output_str().to_string();
            let store = mk_op(&mut fd, 3, 0x1008, OpCode::CPUI_STORE);
            let value = execution_input(&mut fd, "value", cell);
            fd.op_set_input(store, space, 0).unwrap();
            fd.op_set_input(store, address, 1).unwrap();
            fd.op_set_input(store, value, 2).unwrap();
            let mut print = execution_printer(&arch, rust);
            print.emit_statement(&fd, &arch, store);
            let store_text = print.emit_mut().output_str().to_string();
            let source = if rust {
                format!(r#"
unsafe fn address(p: *mut u32, i: i64) -> *mut u32 {{ {address_text} }}
unsafe fn load(p: *mut u32, i: i64) -> u32 {{ {load_text} }}
unsafe fn store(p: *mut u32, i: i64, value: u32) {{ {store_text} }}
fn main() {{ unsafe {{
    let mut cells = [0x11223344u32, 11, 22, 33, 0xaabbccdd];
    let p = cells.as_mut_ptr().add(2);
    for (i, want) in [(-1, 11), (0, 22), (1, 33)] {{
        assert_eq!(load(p, i), want);
        assert_eq!(address(p, i), p.offset(i as isize));
    }}
    assert_eq!(address(p, 3), cells.as_mut_ptr().add(5));
    store(p, -1, 101); store(p, 1, 303);
    assert_eq!(cells, [0x11223344, 101, 22, 303, 0xaabbccdd]);
}} }}
"#)
            } else {
                format!(r#"
#include <stdint.h>
#include <assert.h>
uint32_t *address(uint32_t *p, int64_t i) {{ return {address_text}; }}
uint32_t load(uint32_t *p, int64_t i) {{ return {load_text}; }}
void store(uint32_t *p, int64_t i, uint32_t value) {{ {store_text} }}
int main(void) {{
    uint32_t cells[] = {{0x11223344, 11, 22, 33, 0xaabbccdd}};
    uint32_t *p = cells + 2;
    for (int64_t i = -1; i <= 1; ++i) {{
        assert(load(p, i) == (uint32_t)(22 + i * 11));
        assert(address(p, i) == p + i);
    }}
    assert(address(p, 3) == cells + 5);
    store(p, -1, 101); store(p, 1, 303);
    assert(cells[0] == 0x11223344 && cells[1] == 101 && cells[2] == 22 &&
           cells[3] == 303 && cells[4] == 0xaabbccdd);
    return 0;
}}
"#)
            };
            if rust { assert_rust_source(&source, "pointers"); }
            else { assert_c_source(&source, "pointers"); }
        }
    }

    #[test]
    fn emitted_rust_fallback_pointer_load_and_store_keep_the_memory_access() {
        use crate::dtype::TypeFactory;
        use std::process::Command;
        let arch = bare_arch();
        let types = arch.types_rc();
        let cell = types.get_base(4, type_metatype::TYPE_UINT).unwrap();
        let pointer = types.get_type_pointer(8, cell.clone(), 1).unwrap();
        let mut fd = build_fd();
        fd.set_high_level();
        let p = execution_input(&mut fd, "p", pointer.clone());
        // construct_typed_pointer in constseq builds four-byte index/stride
        // constants independently of the target pointer's storage width.
        let i = fd.new_constant(4, 1);
        let add = mk_op(&mut fd, 3, 0x1000, OpCode::CPUI_PTRADD);
        let stride = fd.new_constant(4, 4);
        fd.op_set_input(add, p, 0).unwrap();
        fd.op_set_input(add, i, 1).unwrap();
        fd.op_set_input(add, stride, 2).unwrap();
        let address = fd.new_unique(8, Some(pointer));
        fd.op_set_output(add, address).unwrap();
        fd.vbank_mut().get_mut(address).unwrap().set_implied();
        let load = mk_op(&mut fd, 2, 0x1004, OpCode::CPUI_LOAD);
        let space = fd.new_constant(4, ram(&fd).get_index() as u64);
        fd.op_set_input(load, space, 0).unwrap();
        fd.op_set_input(load, address, 1).unwrap();
        let loaded = fd.new_unique(4, Some(cell.clone()));
        fd.op_set_output(load, loaded).unwrap();
        let mut print = execution_printer(&arch, true);
        print.op_push_ir(&fd, &arch, load, None);
        let load_text = print.emit_mut().output_str().to_string();
        let store = mk_op(&mut fd, 3, 0x1008, OpCode::CPUI_STORE);
        let value = execution_input(&mut fd, "value", cell);
        fd.op_set_input(store, space, 0).unwrap();
        fd.op_set_input(store, address, 1).unwrap();
        fd.op_set_input(store, value, 2).unwrap();
        let mut print = execution_printer(&arch, true);
        print.emit_statement(&fd, &arch, store);
        let store_text = print.emit_mut().output_str().to_string();
        let source = format!(r#"
extern "C" {{ fn PTRADD(p: *mut u32, index: i32, stride: i32) -> *mut u32; }}
pub unsafe fn load(p: *mut u32) -> u32 {{ {load_text} }}
pub unsafe fn store(p: *mut u32, value: u32) {{ {store_text} }}
"#);
        // Type/lvalue contract only: no invented PTRADD implementation, linking
        // or execution claim for this unsupported native lowering.
        let dir = std::env::temp_dir()
            .join(format!("kuna-language-fallback-metadata-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let input = dir.join("consumer.rs");
        std::fs::write(&input, &source).unwrap();
        let out = Command::new("rustc")
            .args(["--edition=2021", "--crate-type=lib", "--emit=metadata", "-A", "warnings"])
            .arg(&input).arg("-o").arg(dir.join("consumer.rmeta")).output()
            .expect("compile emitted Rust metadata with required rustc");
        assert!(out.status.success(), "fallback LOAD/STORE lost its value/lvalue contract:\n{}\n{source}",
            String::from_utf8_lossy(&out.stderr));
        std::fs::remove_dir_all(dir).unwrap();
    }

fn declared_code(types: &TypeFactoryImpl, fd: &Funcdata, output: Rc<Datatype>, inputs: Vec<Rc<Datatype>>, variadic: bool) -> Rc<Datatype> {
    use crate::dtype::type_class;
    use crate::fspec::{ParamEntry, PrototypePieces, ProtoModel};
    let mut manager = build_manager();
    manager.set_default_code_space(2).unwrap();
    manager.set_default_data_space(2).unwrap();
    let manager = Rc::new(manager);
    let mut model = ProtoModel::new(&manager);
    model.build_param_list("standard").unwrap();
    for slot in 0..inputs.len().max(1) {
        let input = model.input_mut();
        let entry = ParamEntry::seed(slot as int4, type_class::TYPECLASS_GENERAL,
            ram(fd), 0x100 + slot as u64 * 8, 8, 1, 0, 0, true, false,
            input.get_entry(), &manager).unwrap();
        input.push_entry(entry);
    }
    model.input_mut().finish_decode();
    model.output_mut().push_entry(ParamEntry::seed(0, type_class::TYPECLASS_GENERAL,
        ram(fd), 0x200, 8, 1, 0, 0, true, false, &[], &manager).unwrap());
    model.output_mut().finish_decode();
    types.set_proto_context(manager);
    let declaration = PrototypePieces {
        outtype: Some(output), innames: vec!["argument".into(); inputs.len()],
        first_var_arg_slot: if variadic { inputs.len() as int4 } else { -1 },
        intypes: inputs, ..PrototypePieces::default()
    };
    let code = types.get_type_code_proto_model(&declaration, Rc::new(model)).unwrap();
    let signature = code.get_code_prototype().unwrap();
    assert_eq!(signature.num_params(), declaration.intypes.len() as int4,
        "the real model must assign every authored formal");
    for (slot, expected) in declaration.intypes.iter().enumerate() {
        assert!(Rc::ptr_eq(signature.get_param(slot as int4).unwrap().get_type().unwrap(), expected));
    }
    code
}

fn callable_types() -> TypeFactoryImpl {
    let types = TypeFactoryImpl::new();
    types.setup_sizes(Some(4), 8, 8);
    types.set_max_basetype_size(8);
    for (name, size, meta) in [("void", 1, type_metatype::TYPE_VOID),
        ("code", 1, type_metatype::TYPE_CODE), ("int4", 4, type_metatype::TYPE_INT),
        ("uint8", 8, type_metatype::TYPE_UINT)] {
        types.set_core_type(name, size, meta, false).unwrap();
    }
    types.cache_core_types().unwrap();
    types
}

#[test]
fn callable_dialect_cast_preserves_explicit_semantic_declaration() {
    use crate::cast::{CastStrategy, CastStrategyC};
    for variadic in [false, true] {
        let manager = Rc::new(build_manager());
        let types = Rc::new(callable_types());
        let mut context = ContextArch::new_shared(manager.clone());
        context.types = Some(types.clone());
        let memory = manager.get_space_by_name("ram").unwrap().clone();
        let mut fd = Funcdata::new("convert", "convert", Rc::new(context),
            Address::new(memory.clone(), 0x1000), 0x1000_0000, 0x40).unwrap();
        fd.set_high_level();
        let void = types.get_type_void().unwrap();
        let int4_type = types.get_base(4, type_metatype::TYPE_INT).unwrap();
        let source_code = declared_code(&types, &fd, void.clone(), vec![], false);
        let destination_code = declared_code(&types, &fd, void, vec![int4_type], variadic);
        let source_type = types.get_type_pointer(8, source_code, 1).unwrap();
        let destination = types.get_type_pointer(8, destination_code, 1).unwrap();
        let strategy = CastStrategyC::new(types.clone());
        assert!(Rc::ptr_eq(&strategy.cast_standard(&destination, &source_type, false, true)
            .expect("distinct declared prototypes require a conversion"), &destination));
        let source = fd.new_varnode(8, &Address::new(memory, 0x400), Some(source_type.clone()));
        let source = fd.set_input_varnode(source).unwrap();
        name_call_local(&mut fd, source, "callback");
        let root = fd.bblocks_root_pub();
        let block = fd.bblocks_mut().new_block_basic(root);
        let copy = mk_op(&mut fd, 1, 0x1000, OpCode::CPUI_COPY);
        fd.op_set_input(copy, source, 0).unwrap();
        let converted = fd.new_unique_out(8, copy).unwrap();
        fd.vn_update_type(converted, destination.clone());
        name_call_local(&mut fd, converted, "converted");
        fd.op_insert_end(copy, block);
        fd.action_set_casts();
        let cast_output = fd.obank().get(copy).unwrap().get_in(0).unwrap();
        let cast = fd.vbank().get(cast_output).unwrap().get_def()
            .expect("real cast stage must insert the declared conversion");
        assert_eq!(fd.obank().get(cast).unwrap().code(), OpCode::CPUI_CAST);
        assert_eq!(fd.obank().get(cast).unwrap().get_in(0), Some(source));
        assert!(Rc::ptr_eq(fd.vbank().get(cast_output).unwrap().get_type(), &destination));
        for native in [false, true, false] {
            let mut arch = bare_arch();
            arch.ctypes = native;
            let mut print = execution_printer(&arch, false);
            print.op_type_cast_ir(&fd, &arch, cast);
            let emitted = print.emit_mut().output_str().to_string();
            assert!(emitted.contains(if native { "int" } else { "int4" })
                && emitted.contains("(*)"), "{emitted}");
            assert_eq!(emitted.contains("..."), variadic, "{emitted}");
            assert!(Rc::ptr_eq(fd.vbank().get(source).unwrap().get_type(), &source_type));
            let suffix = if variadic { ", ..." } else { "" };
            let consumer = format!(r#"
#include <assert.h>
#include <stdint.h>
typedef int32_t int4;
typedef void (*Origin)(void);
static unsigned calls;
static int effect;
void provider(int4 value{suffix}) {{
    assert(value == 7 && ++calls == 1);
    effect = value + 11;
}}
int main(void) {{
    Origin callback = (Origin)provider;
    ({emitted})(7);
    assert(calls == 1 && effect == 18);
    return 0;
}}
"#);
            assert_c_source(&consumer, &format!("declared-callable-{variadic}-{native}"));
        }
    }
}

#[test]
fn recovered_callable_projection_retains_cast_provenance_and_authority() {
    use crate::action::ActionContext;
    use crate::cast::CastStrategyC;
    use crate::dtype::type_class;
    use crate::fspec::{FuncCallSpecs, ParamEntry, ParameterPieces, ProtoModel};
    use crate::p5_types::kuna_calltargettype::ActionCallTargetType;
    use crate::p9_emit::coreaction_casts::get_input_cast;
    use crate::prettyprint::TokenKind;

    let mut manager = build_manager();
    manager.set_default_code_space(2).unwrap();
    manager.set_default_data_space(2).unwrap();
    let manager = Rc::new(manager);
    let types = Rc::new(callable_types());
    let int4_type = types.get_base(4, type_metatype::TYPE_INT).unwrap();
    let void = types.get_type_void().unwrap();
    let memory = manager.get_space_by_name("ram").unwrap().clone();
    let mut model = ProtoModel::new(&manager);
    model.build_param_list("standard").unwrap();
    model.set_name("recovered_abi");
    model.input_mut().push_entry(ParamEntry::seed(0, type_class::TYPECLASS_GENERAL,
        memory.clone(), 0x100, 8, 1, 0, 0, true, false, &[], &manager).unwrap());
    model.input_mut().finish_decode();
    model.output_mut().push_entry(ParamEntry::seed(0, type_class::TYPECLASS_GENERAL,
        memory.clone(), 0x200, 8, 1, 0, 0, true, false, &[], &manager).unwrap());
    model.output_mut().finish_decode();
    let model = Rc::new(model);
    types.set_proto_context(manager.clone());
    types.set_proto_models(Some(model.clone()), std::collections::BTreeMap::from([
        ("recovered_abi".to_string(), model.clone()),
    ]));
    let mut context = ContextArch::new_shared(manager);
    context.types = Some(types.clone());
    context.defaultfp = Some(model.clone());
    context.call_target_type = true;
    let mut fd = Funcdata::new("func", "func", Rc::new(context),
        Address::new(memory.clone(), 0x1000), 0x1000_0000, 0x40).unwrap();
    fd.get_func_proto_mut().set_internal(model.clone(), void.clone());
    let source_type = types.get_base(8, type_metatype::TYPE_UINT).unwrap();
    let address = Address::new(memory.clone(), 0x400);
    let source = fd.new_varnode(8, &address, Some(source_type.clone()));
    let source = fd.set_input_varnode(source).unwrap();
    fd.get_func_proto_mut().set_param(0, "target", &ParameterPieces {
        addr: address, type_: Some(source_type.clone()), flags: 0,
    });
    let root = fd.bblocks_root_pub();
    let block = fd.bblocks_mut().new_block_basic(root);
    let call = mk_op(&mut fd, 2, 0x1010, OpCode::CPUI_CALLIND);
    let argument = fd.new_constant(4, 7);
    fd.vn_update_type(argument, int4_type.clone());
    fd.op_set_input(call, source, 0).unwrap();
    fd.op_set_input(call, argument, 1).unwrap();
    let mut specs = FuncCallSpecs::new(call, Address::new_invalid());
    specs.proto_mut().set_internal(model, void);
    specs.set_final_input_storage(vec![(Address::new(memory, 0x100), 4)]);
    fd.push_call_specs(specs);
    fd.op_insert_end(call, block);
    fd.set_high_level();
    name_call_local(&mut fd, source, "target");
    ActionCallTargetType::boxed("analysis").apply(&mut fd, &mut ActionContext::new());
    let facing = fd.vn_high_type_read_facing(source, call);
    assert!(Rc::ptr_eq(&facing, &source_type));
    let authority = fd.kuna_call_target_type(call)
        .expect("ABI-compatible integer target must publish its per-call signature");
    let code = authority.get_ptr_to().unwrap();
    let signature = code.get_code_prototype().unwrap();
    assert_eq!(signature.num_params(), 1);
    assert_eq!(signature.get_param(0).unwrap().get_address().get_offset(), 0x100);
    assert!(Rc::ptr_eq(signature.get_param(0).unwrap().get_type().unwrap(), &int4_type));
    assert_eq!(signature.get_output_type().unwrap().get_metatype(), type_metatype::TYPE_VOID);
    assert!(!signature.is_dotdotdot());
    let strategy = CastStrategyC::new(types.clone());
    assert!(Rc::ptr_eq(&get_input_cast(&mut fd, &strategy, call, 0)
        .expect("published authority must reach the cast consumer"), &authority));
    fd.action_set_casts();
    let cast_output = fd.obank().get(call).unwrap().get_in(0).unwrap();
    let cast = fd.vbank().get(cast_output).unwrap().get_def()
        .expect("real cast owner must insert the numeric callable conversion");
    assert_eq!(fd.obank().get(cast).unwrap().code(), OpCode::CPUI_CAST);
    assert_eq!(fd.obank().get(cast).unwrap().get_in(0), Some(source));
    assert!(Rc::ptr_eq(fd.vbank().get(cast_output).unwrap().get_type(), &authority));
    let mut arch = bare_arch();
    arch.realtypes = false;
    for _ in 0..2 {
        assert!(get_input_cast(&mut fd, &strategy, call, 0).is_none());
        for native in [false, true] {
            arch.ctypes = native;
            let mut plain = execution_printer(&arch, false);
            plain.op_call_ir(&fd, &arch, call);
            plain.recurse();
            let text = plain.emit_mut().output_str().to_string();
            let mut print = execution_printer(&arch, false);
            print.set_markup(true);
            print.emit_mut().set_capture_tokens(true);
            print.op_call_ir(&fd, &arch, call);
            print.recurse();
            let tokens = print.emit_mut().take_markup_tokens();
            assert_eq!(tokens.iter().filter(|t| t.kind == TokenKind::Type).count(), 1,
                "{tokens:?}");
            assert!(Rc::ptr_eq(&fd.vn_high_type_read_facing(source, call), &facing));
            assert_eq!(fd.obank().get(call).unwrap().get_in(0), Some(cast_output));
            let consumer = format!(r#"
#include <assert.h>
#include <stdint.h>
typedef int32_t int4;
static unsigned calls;
static int effect;
void provider(int4 value) {{
    assert(value == 7 && ++calls == 1);
    effect = value + 11;
}}
int main(void) {{
    uintptr_t target = (uintptr_t)provider;
    assert((void (*)(int4))target == provider);
    {text};
    assert(calls == 1 && effect == 18);
    return 0;
}}
"#);
            assert_c_source(&consumer, &format!("recovered-call-expression-integer-{native}"));
        }
    }
}
