use super::*;
use super::support::{assert_c_source, bare_arch, build_manager, mk_op,
    name_call_local, named_call_input, ram};
use crate::context::{ArchContext as ContextArch, TypeOp};
use crate::dtype::{TypeFactory, TypeFactoryImpl, TypeField};
use crate::funcdata::Funcdata;
use kuna_base::address::Address;
use kuna_num::opcodes::OpCode;
use std::rc::Rc;

    #[derive(Clone, Copy)]
    enum LogicalInputs { Tag, MethodByValue, Variadic }

    #[derive(Clone, Copy)]
    enum LogicalResultUse { Discarded, ExplicitPointer, ImpliedPointer, NestedPointer }

    /// A real standard ABI: eight-byte resources force Big24 results through a
    /// hidden pointer, while pointermax lowers Big24 inputs to indirect storage.
    /// Every physical role comes from the current model storage assignment.
    fn render_logical_call(
        indirect: bool, inputs: LogicalInputs, result_use: LogicalResultUse, occupied_names: &[&str],
    ) -> String {
        use crate::dtype::{type_class, TypeFactory, TypeField};
        use crate::fspec::{FuncCallSpecs, PrototypePieces, ParamEntry, ProtoModel};

        let mut arch = bare_arch();
        arch.realtypes = false;
        arch.ctypes = false;
        arch.cast_implied = false;
        arch.cast_sign = false;
        arch.cast_ternary = false;
        let types = arch.types_rc();
        types.setup_sizes(Some(4), 8, 8);
        types.set_max_basetype_size(8);
        types.set_core_type("int4", 4, type_metatype::TYPE_INT, false).unwrap();
        types.set_core_type("int8", 8, type_metatype::TYPE_INT, false).unwrap();
        types.cache_core_types().unwrap();
        let int4 = types.get_base(4, type_metatype::TYPE_INT).unwrap();
        let int8 = types.get_base(8, type_metatype::TYPE_INT).unwrap();
        let void = types.get_type_void().unwrap();
        let void_ptr = types.get_type_pointer(8, void.clone(), 1).unwrap();
        let shell = types.get_type_struct("Big24").unwrap();
        let big = types.set_fields_struct_raw(&shell,
            (0..3).map(|i| TypeField::new(i, i * 8, format!("v{i}"), int8.clone())).collect(),
            vec![], 24, 8, 0).unwrap();
        let big_ptr = types.get_type_pointer(8, big.clone(), 1).unwrap();

        let mut manager = build_manager();
        manager.set_default_code_space(2).unwrap();
        manager.set_default_data_space(2).unwrap();
        let memory = manager.get_space_by_name("ram").unwrap().clone();
        manager.insert_space(Rc::new(kuna_base::space::SpacebaseSpace::new(
            "stack", 3, 8, &memory, 1, true, false,
        ))).unwrap();
        let manager = Rc::new(manager);
        let space = manager.get_space_by_name("ram").unwrap().clone();
        let mut model = ProtoModel::new(&manager);
        model.build_param_list("standard").unwrap();
        model.set_name("logical_call_test");
        model.set_has_this(matches!(inputs, LogicalInputs::MethodByValue));
        for group in 0..6 {
            let input = model.input_mut();
            let entry = ParamEntry::seed(group, type_class::TYPECLASS_GENERAL,
                space.clone(), 0x100 + group as u64 * 8, 8, 1, 0, 0, true,
                false, input.get_entry(), &manager).unwrap();
            input.push_entry(entry);
        }
        model.input_mut().push_pointermax_rule(8);
        model.input_mut().finish_decode();
        model.output_mut().push_entry(ParamEntry::seed(0, type_class::TYPECLASS_GENERAL,
            space.clone(), 0x200, 8, 1, 0, 0, true, false, &[], &manager).unwrap());
        model.output_mut().finish_decode();
        // This is the fixture's default ABI, not a source-level convention
        // keyword. Use the real publication owner so the architecture and type
        // factory share it and default declaration visibility is implicit.
        arch.set_default_model_rc(Rc::new(model));
        let model = arch.default_fp().unwrap().clone();
        assert!(!model.print_in_decl());
        types.set_proto_context(manager.clone());
        let declaration = PrototypePieces {
            outtype: Some(big.clone()),
            intypes: match inputs {
                LogicalInputs::MethodByValue => vec![void_ptr.clone(), big.clone(), int4.clone()],
                _ => vec![int4.clone()],
            },
            first_var_arg_slot: if matches!(inputs, LogicalInputs::Variadic) { 1 } else { -1 },
            ..PrototypePieces::default()
        };
        let code = types.get_type_code_proto(&declaration).unwrap();
        let abi = code.get_code_prototype().unwrap();
        assert!(abi.as_ref().get_output().is_indirect_storage());

        let mut context = ContextArch::new_shared(manager);
        context.types = Some(types.clone());
        let mut fd = Funcdata::new("driver", "driver", Rc::new(context),
            Address::new(space.clone(), 0x1000), 0x1000_0000, 0x40).unwrap();
        fd.get_func_proto_mut().set_internal(model.clone(), void.clone());
        fd.set_high_level();
        let occupied: Vec<_> = occupied_names.iter()
            .map(|name| named_call_input(&mut fd, name, int4.clone())).collect();
        let root = fd.bblocks_root_pub();
        let block = fd.bblocks_mut().new_block_basic(root);

        let destination = if matches!(result_use, LogicalResultUse::ImpliedPointer | LogicalResultUse::NestedPointer) {
            let next_code = types.get_type_code_proto(&PrototypePieces {
                outtype: Some(big_ptr.clone()), first_var_arg_slot: -1,
                ..PrototypePieces::default()
            }).unwrap();
            let next_abi = next_code.get_code_prototype().unwrap();
            let next = mk_op(&mut fd, 1, 0x1000, OpCode::CPUI_CALL);
            fd.op_set_opcode(next, TypeOp::new(OpCode::CPUI_CALL,
                crate::op::pcodeop_flags::call, "CALL"));
            let target = fd.new_constant(8, 0x3000);
            fd.op_set_input(next, target, 0).unwrap();
            let out = fd.new_unique_out(8, next).unwrap();
            fd.vn_update_type(out, big_ptr.clone());
            fd.vbank_mut().get_mut(out).unwrap().set_implied();
            fd.op_insert_end(next, block);
            let mut specs = FuncCallSpecs::new(next, Address::new(space.clone(), 0x3000));
            specs.set_funcdata(Address::new(space.clone(), 0x3000), "next_destination").unwrap();
            specs.proto_mut().copy(next_abi.as_ref());
            fd.push_call_specs(specs);
            out
        } else {
            named_call_input(&mut fd, "destination", big_ptr.clone())
        };
        let logical_args = match inputs {
            LogicalInputs::MethodByValue => vec![
                named_call_input(&mut fd, "object", void_ptr.clone()),
                named_call_input(&mut fd, "source_ptr", big_ptr.clone()),
                named_call_input(&mut fd, "tag", int4.clone()),
            ],
            _ => vec![named_call_input(&mut fd, "tag", int4.clone())],
        };
        let mut physical_args = Vec::new();
        let mut declared = 0;
        for slot in 0..abi.num_params() {
            let parameter = abi.get_param(slot).unwrap();
            physical_args.push(if parameter.is_hidden_return() {
                destination
            } else {
                if matches!(inputs, LogicalInputs::MethodByValue) && declared == 1 {
                    assert!(parameter.is_indirect_storage());
                }
                let value = logical_args[declared];
                declared += 1;
                value
            });
        }
        assert!(abi.get_param(0).unwrap().is_hidden_return());
        if matches!(inputs, LogicalInputs::MethodByValue) {
            assert!(abi.as_ref().get_param(1).unwrap().is_this_pointer());
        }
        if matches!(inputs, LogicalInputs::Variadic) {
            physical_args.push(named_call_input(&mut fd, "extra", int4.clone()));
        }
        let target = if indirect {
            named_call_input(&mut fd, "callback", void_ptr)
        } else { fd.new_constant(8, 0x4000) };
        let opcode = if indirect { OpCode::CPUI_CALLIND } else { OpCode::CPUI_CALL };
        let call = mk_op(&mut fd, physical_args.len() as int4 + 1, 0x1010, opcode);
        fd.op_set_opcode(call, TypeOp::new(opcode, crate::op::pcodeop_flags::call, "CALL"));
        fd.op_set_input(call, target, 0).unwrap();
        for (slot, vn) in physical_args.into_iter().enumerate() {
            fd.op_set_input(call, vn, slot as int4 + 1).unwrap();
        }
        let physical_output = if matches!(result_use, LogicalResultUse::Discarded) { None } else {
            let out = fd.new_unique_out(8, call).unwrap();
            fd.vn_update_type(out, big_ptr.clone());
            if matches!(result_use, LogicalResultUse::ImpliedPointer | LogicalResultUse::NestedPointer) {
                fd.vbank_mut().get_mut(out).unwrap().set_implied();
            } else { name_call_local(&mut fd, out, "returned"); }
            Some(out)
        };
        fd.op_insert_end(call, block);
        let mut specs = FuncCallSpecs::new(call, Address::new(space.clone(), 0x4000));
        if !indirect {
            specs.set_funcdata(Address::new(space, 0x4000), "make_big").unwrap();
        }
        specs.proto_mut().copy(abi.as_ref());
        specs.proto_mut().set_override(true); // source survives site pinning
        assert!(specs.proto().is_input_locked() && specs.proto().is_output_locked());
        assert!(crate::kuna_indirectargs::hidden_result(specs.proto()).is_some());
        assert!(!fd.get_override().is_authored_proto_override(fd.obank().get(call).unwrap().get_addr()),
            "the logical-result positive must not depend on an authored site override");
        fd.push_call_specs(specs);
        if indirect {
            fd.action_set_casts().unwrap();
        }
        let consumed_pointer = if let Some(out) = physical_output {
            if matches!(result_use, LogicalResultUse::NestedPointer) {
                out
            } else {
                let copy = mk_op(&mut fd, 1, 0x1020, OpCode::CPUI_COPY);
                fd.op_set_input(copy, out, 0).unwrap();
                let observed = fd.new_unique_out(8, copy).unwrap();
                fd.vn_update_type(observed, big_ptr.clone());
                name_call_local(&mut fd, observed, "observed");
                fd.op_insert_end(copy, block);
                observed
            }
        } else { destination };
        let consumer_code = types.get_type_code_proto(&PrototypePieces {
            outtype: Some(void.clone()), intypes: vec![big_ptr, int4.clone()],
            first_var_arg_slot: -1, ..PrototypePieces::default()
        }).unwrap();
        let consumer_abi = consumer_code.get_code_prototype().unwrap();
        let consumer = mk_op(&mut fd, 3, 0x1030, OpCode::CPUI_CALL);
        fd.op_set_opcode(consumer, TypeOp::new(OpCode::CPUI_CALL,
            crate::op::pcodeop_flags::call, "CALL"));
        let target = fd.new_constant(8, 0x5000);
        fd.op_set_input(consumer, target, 0).unwrap();
        fd.op_set_input(consumer, consumed_pointer, 1).unwrap();
        fd.op_set_input(consumer, *logical_args.last().unwrap(), 2).unwrap();
        fd.op_insert_end(consumer, block);
        let entry = Address::new(ram(&fd), 0x5000);
        let mut specs = FuncCallSpecs::new(consumer, entry.clone());
        specs.set_funcdata(entry, "consume_pointer").unwrap();
        specs.proto_mut().copy(consumer_abi.as_ref());
        fd.push_call_specs(specs);

        let name_code = types.get_type_code_proto(&PrototypePieces {
            outtype: Some(void), intypes: vec![int4.clone(), int4.clone()],
            first_var_arg_slot: -1, ..PrototypePieces::default()
        }).unwrap();
        let name_abi = name_code.get_code_prototype().unwrap();
        for (slot, value) in occupied.into_iter().enumerate() {
            let consumer = mk_op(&mut fd, 3, 0x1040 + slot as u64, OpCode::CPUI_CALL);
            fd.op_set_opcode(consumer, TypeOp::new(OpCode::CPUI_CALL,
                crate::op::pcodeop_flags::call, "CALL"));
            let target = fd.new_constant(8, 0x6000);
            let index = fd.new_constant(4, slot as u64);
            fd.vn_update_type(index, int4.clone());
            fd.op_set_input(consumer, target, 0).unwrap();
            fd.op_set_input(consumer, value, 1).unwrap();
            fd.op_set_input(consumer, index, 2).unwrap();
            fd.op_insert_end(consumer, block);
            let entry = Address::new(ram(&fd), 0x6000);
            let mut specs = FuncCallSpecs::new(consumer, entry.clone());
            specs.set_funcdata(entry, "consume_authored_name").unwrap();
            specs.proto_mut().copy(name_abi.as_ref());
            fd.push_call_specs(specs);
        }
        fd.get_func_proto_mut().set_input_lock(true);
        fd.seed_sblocks_copy();
        PrintC::new().doc_function_full(&fd, &arch).unwrap()
    }

    fn compact_c(text: &str) -> String {
        text.chars().filter(|c| !c.is_whitespace()).collect()
    }

    /// Compile the complete, unchanged document against source-level providers.
    /// Statement and expression lowerings have the same runtime obligations.
    fn execute_logical_call(
        indirect: bool, inputs: LogicalInputs, result_use: LogicalResultUse,
        occupied_names: &[&str], label: &str,
    ) {
        let emitted = render_logical_call(indirect, inputs, result_use, occupied_names);
        let readable = compact_c(&emitted);
        let arguments = match inputs {
            LogicalInputs::Tag => "tag",
            LogicalInputs::MethodByValue => "object,*source_ptr,tag",
            LogicalInputs::Variadic => "tag,extra",
        };
        if indirect {
            assert!(readable.contains(&format!("callback)({arguments})")),
                "the indirect source call must omit physical ABI arguments:\n{emitted}");
        } else {
            assert!(readable.contains(&format!("make_big({arguments})")),
                "the source call must retain logical operands:\n{emitted}");
        }
        if matches!(result_use, LogicalResultUse::ImpliedPointer | LogicalResultUse::NestedPointer) {
            assert_eq!(readable.matches("next_destination()").count(), 1,
                "the side-effectful destination must occur once:\n{emitted}");
        }
        let types = TypeFactoryImpl::new();
        types.setup_sizes(Some(4), 8, 8);
        types.set_max_basetype_size(8);
        let word = types.get_base_named(8, type_metatype::TYPE_INT, "int8").unwrap();
        let shell = types.get_type_struct("Big24").unwrap();
        let record = types.set_fields_struct_raw(&shell,
            (0..3).map(|i| TypeField::new(i, i * 8, format!("v{i}"), word.clone())).collect(),
            vec![], 24, 8, 0).unwrap();
        let declarations = render_type_definitions(&[record], &RealTypeCtx::OFF);
        let provider = match inputs {
            LogicalInputs::Tag => r#"
Big24 make_big(int4 tag) {
    assert(tag == 7 && ++producers == 1);
    Big24 value = {tag, tag + 1, tag + 2};
    return value;
}"#,
            LogicalInputs::MethodByValue => r#"
Big24 make_big(void *object, Big24 copy, int4 tag) {
    assert(object == &object_marker && tag == 7 && ++producers == 1);
    assert(copy.v0 == 31 && copy.v1 == 47 && copy.v2 == 59);
    Big24 value = {copy.v0 - 24, copy.v1 - 39, copy.v2 - 50};
    copy.v0 = -1;
    copy.v1 = -2;
    copy.v2 = -3;
    return value;
}"#,
            LogicalInputs::Variadic => r#"
Big24 make_big(int4 tag, ...) {
    assert(tag == 7 && ++producers == 1);
    va_list tail;
    va_start(tail, tag);
    int4 extra = va_arg(tail, int);
    va_end(tail);
    assert(extra == 23);
    Big24 value = {tag, extra - 15, extra - 14};
    return value;
}"#,
        };
        let side_effectful_destination = matches!(result_use,
            LogicalResultUse::ImpliedPointer | LogicalResultUse::NestedPointer);
        let mut arguments: Vec<_> = (0..occupied_names.len())
            .map(|slot| (101 + slot).to_string()).collect();
        if !side_effectful_destination { arguments.push("&destination_storage".to_owned()); }
        if matches!(inputs, LogicalInputs::MethodByValue) {
            arguments.push("&object_marker".to_owned());
            arguments.push("&source_storage".to_owned());
        }
        arguments.push("7".to_owned());
        if matches!(inputs, LogicalInputs::Variadic) { arguments.push("23".to_owned()); }
        if indirect { arguments.push("(void *)make_big".to_owned()); }
        let arguments = arguments.join(", ");
        let expected_destinations = u8::from(side_effectful_destination);
        let expected_names = occupied_names.len();
        let source = format!(r#"
#include <assert.h>
#include <stdint.h>
#include <stdarg.h>
typedef int32_t int4;
typedef int64_t int8;
typedef unsigned char undefined1;
{declarations}
static Big24 destination_storage;
static Big24 source_storage = {{31, 47, 59}};
static int object_marker;
static unsigned destinations, producers, consumers, authored_names;
Big24 *next_destination(void) {{
    assert(++destinations == 1);
    return &destination_storage;
}}
{provider}
void consume_pointer(Big24 *p, int4 tag) {{
    assert(++consumers == 1 && producers == 1);
    assert(destinations == {expected_destinations});
    assert(p == &destination_storage && tag == 7);
    assert(p->v0 == 7 && p->v1 == 8 && p->v2 == 9);
}}
void consume_authored_name(int4 value, int4 slot) {{
    assert(producers == 1 && consumers == 1);
    assert(slot == (int4)authored_names && value == 101 + slot);
    ++authored_names;
}}
{emitted}
int main(void) {{
    driver({arguments});
    assert(destinations == {expected_destinations} && producers == 1 && consumers == 1);
    assert(authored_names == {expected_names});
    assert(destination_storage.v0 == 7 && destination_storage.v1 == 8 && destination_storage.v2 == 9);
    assert(source_storage.v0 == 31 && source_storage.v1 == 47 && source_storage.v2 == 59);
    return 0;
}}
"#);
        assert_c_source(&source, label);
    }

    #[test]
    fn logical_hidden_result_omits_abi_argument_discarded_direct() {
        execute_logical_call(false, LogicalInputs::Tag, LogicalResultUse::Discarded,
            &[], "logical-result-discarded-direct");
    }

    #[test]
    fn logical_hidden_result_omits_abi_argument_discarded_indirect() {
        execute_logical_call(true, LogicalInputs::Tag, LogicalResultUse::Discarded,
            &[], "logical-result-discarded-indirect");
    }

    #[test]
    fn logical_hidden_result_omits_abi_argument_and_preserves_used_pointer() {
        execute_logical_call(false, LogicalInputs::Tag, LogicalResultUse::ExplicitPointer,
            &[], "logical-result-explicit-direct");
    }

    #[test]
    fn logical_hidden_result_omits_abi_argument_and_preserves_used_pointer_indirect() {
        execute_logical_call(true, LogicalInputs::Tag, LogicalResultUse::ExplicitPointer,
            &[], "logical-result-explicit-indirect");
    }

    #[test]
    fn implied_hidden_result_captures_side_effectful_destination_once() {
        execute_logical_call(false, LogicalInputs::Tag, LogicalResultUse::ImpliedPointer,
            &[], "logical-result-implied-direct");
    }

    #[test]
    fn implied_hidden_result_captures_side_effectful_destination_once_indirect() {
        execute_logical_call(true, LogicalInputs::Tag, LogicalResultUse::ImpliedPointer,
            &[], "logical-result-implied-indirect");
    }

    #[test]
    fn hidden_result_sequence_remains_one_nested_call_argument() {
        execute_logical_call(false, LogicalInputs::Tag, LogicalResultUse::NestedPointer,
            &[], "logical-result-nested-direct");
    }

    #[test]
    fn hidden_result_sequence_remains_one_nested_call_argument_indirect() {
        execute_logical_call(true, LogicalInputs::Tag, LogicalResultUse::NestedPointer,
            &[], "logical-result-nested-indirect");
    }

    #[test]
    fn logical_method_arguments_dereference_indirect_byvalue_storage() {
        execute_logical_call(false, LogicalInputs::MethodByValue, LogicalResultUse::Discarded,
            &[], "logical-result-method-by-value");
    }

    #[test]
    fn logical_variadic_call_preserves_operands_beyond_source_role_prefix() {
        execute_logical_call(false, LogicalInputs::Variadic, LogicalResultUse::Discarded,
            &[], "logical-result-variadic-tail");
    }

    const AUTHORED_RESULT_NAMES: &[&str] = &[
        "sret", "sret_1", "result_ptr", "result_ptr_1",
        "hidden_result", "hidden_result_1", "return_ptr", "return_ptr_1",
    ];

    #[test]
    fn logical_hidden_result_preserves_authored_parameter_values() {
        execute_logical_call(false, LogicalInputs::Tag, LogicalResultUse::ExplicitPointer,
            AUTHORED_RESULT_NAMES, "logical-result-authored-names-direct");
    }

    #[test]
    fn logical_hidden_result_preserves_authored_parameter_values_indirect() {
        execute_logical_call(true, LogicalInputs::Tag, LogicalResultUse::ExplicitPointer,
            AUTHORED_RESULT_NAMES, "logical-result-authored-names-indirect");
    }
