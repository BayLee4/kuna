use super::*;

#[test]
fn recovered_callable_projection_retains_cast_provenance_and_authority() {
    use crate::action::ActionContext;
    use crate::cast::CastStrategyC;
    use crate::dtype::type_class;
    use crate::fspec::{FuncCallSpecs, ParamEntry, ParameterPieces, ProtoModel};
    use crate::p5_types::kuna_calltargettype::ActionCallTargetType;
    use crate::p9_emit::coreaction_casts::get_input_cast;
    use crate::prettyprint::TokenKind;

    for source_kind in ["parameter", "mismatch", "locked_call", "declared", "generic", "integer"] {
        let mut manager = build_manager();
        manager.set_default_code_space(2).unwrap();
        manager.set_default_data_space(2).unwrap();
        let manager = Rc::new(manager);
        let types = Rc::new(callable_types());
        let int4 = types.get_base(4, type_metatype::TYPE_INT).unwrap();
        let void = types.get_type_void().unwrap();
        let ram = manager.get_space_by_name("ram").unwrap().clone();
        let mut model = ProtoModel::new(&manager);
        model.build_param_list("standard").unwrap();
        model.set_name("recovered_abi");
        model.input_mut().push_entry(ParamEntry::seed(
            0, type_class::TYPECLASS_GENERAL, ram.clone(), 0x100, 8, 1,
            0, 0, true, false, &[], &manager,
        ).unwrap());
        model.input_mut().finish_decode();
        model.output_mut().push_entry(ParamEntry::seed(
            0, type_class::TYPECLASS_GENERAL, ram.clone(), 0x200, 8, 1,
            0, 0, true, false, &[], &manager,
        ).unwrap());
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
            Address::new(ram.clone(), 0x1000), 0x1000_0000, 0x40).unwrap();
        fd.get_func_proto_mut().set_internal(model.clone(), void.clone());
        let source_type = match source_kind {
            "integer" => types.get_base(8, type_metatype::TYPE_UINT).unwrap(),
            "declared" => {
                let pieces = crate::fspec::PrototypePieces {
                    outtype: Some(int4.clone()), first_var_arg_slot: -1,
                    ..Default::default()
                };
                let code = types.get_type_code_proto_model(&pieces, model.clone()).unwrap();
                types.get_type_pointer(8, code, 1).unwrap()
            }
            _ => types.get_type_pointer(8, types.get_type_code().unwrap(), 1).unwrap(),
        };
        let root = fd.bblocks_root_pub();
        let block = fd.bblocks_mut().new_block_basic(root);
        let source = if matches!(source_kind, "integer" | "declared" | "parameter") {
            let address = Address::new(ram.clone(), 0x400);
            let source = fd.new_varnode(8, &address, Some(source_type.clone()));
            let source = fd.set_input_varnode(source).unwrap();
            fd.get_func_proto_mut().set_param(0, "target", &ParameterPieces {
                addr: address, type_: Some(source_type.clone()), flags: 0,
            });
            source
        } else {
            let copy = mk_op(&mut fd, 1, 0x1000, OpCode::CPUI_COPY);
            let zero = fd.new_constant(8, 0);
            fd.op_set_input(copy, zero, 0).unwrap();
            let source = fd.new_unique(8, Some(source_type.clone()));
            fd.op_set_output(copy, source).unwrap();
            fd.vbank_mut().get_mut(source).unwrap().set_explicit();
            fd.op_insert_end(copy, block);
            source
        };
        let call = mk_op(&mut fd, 2, 0x1010, OpCode::CPUI_CALLIND);
        let argument = fd.new_constant(4, 7);
        fd.vn_update_type(argument, int4.clone());
        fd.op_set_input(call, source, 0).unwrap();
        fd.op_set_input(call, argument, 1).unwrap();
        let mut specs = FuncCallSpecs::new(call, Address::new_invalid());
        specs.proto_mut().set_internal(model.clone(), void);
        if source_kind == "locked_call" {
            specs.proto_mut().set_param(0, "argument", &ParameterPieces {
                addr: Address::new(ram.clone(), 0x100), type_: Some(int4.clone()), flags: 0,
            });
            specs.proto_mut().set_input_lock(true);
        }
        specs.set_final_input_storage(vec![(Address::new(ram,
            if source_kind == "mismatch" { 0x180 } else { 0x100 }), 4)]);
        fd.push_call_specs(specs);
        fd.op_insert_end(call, block);
        fd.set_high_level();
        let high = fd.vbank().get(source).unwrap().get_high().unwrap();
        fd.high_bank_mut().get_mut(high).unwrap().set_kuna_name("target");
        ActionCallTargetType::boxed("analysis").apply(&mut fd, &mut ActionContext::new());

        let facing = fd.vn_high_type_read_facing(source, call);
        let published = fd.kuna_call_target_type(call);
        let authority = match source_kind {
            "generic" => {
                assert!(published.is_none());
                facing.clone()
            }
            "integer" => published.expect("producer must publish the ABI-compatible per-call signature"),
            _ => {
                assert!(published.is_none(), "{source_kind} must not acquire inferred authority");
                assert!(Rc::ptr_eq(&facing, &source_type), "{source_kind} source type changed");
                facing.clone()
            }
        };
        if matches!(source_kind, "generic" | "integer") {
            let code = authority.get_ptr_to().unwrap();
            let signature = code.get_code_prototype().expect("producer-published callable prototype");
            assert_eq!(signature.num_params(), 1);
            assert_eq!(signature.get_param(0).unwrap().get_address().get_offset(), 0x100);
            assert!(Rc::ptr_eq(signature.get_param(0).unwrap().get_type().unwrap(), &int4));
            assert_eq!(signature.get_output_type().unwrap().get_metatype(), type_metatype::TYPE_VOID);
            assert!(!signature.is_dotdotdot());
        }
        let strategy = CastStrategyC::new(types.clone());
        let destination = get_input_cast(&mut fd, &strategy, call, 0);
        let cast = destination.map(|destination| {
            assert_eq!(source_kind, "integer", "excluded/prototyped targets need no manufactured cast");
            assert!(Rc::ptr_eq(&destination, &authority));
            let cast = mk_op(&mut fd, 1, 0x1010, OpCode::CPUI_CAST);
            fd.op_set_input(cast, source, 0).unwrap();
            let output = fd.new_unique(8, Some(destination));
            fd.op_set_output(cast, output).unwrap();
            fd.vbank_mut().get_mut(output).unwrap().set_implied();
            fd.op_set_input(call, output, 0).unwrap();
            fd.op_insert_before(cast, call);
            cast
        });
        if source_kind == "integer" {
            assert!(cast.is_some(), "published integer authority must reach the cast consumer");
        }
        let mut arch = bare_arch();
        arch.realtypes = false;
        let mut observations = Vec::new();
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
                observations.push((native, text, tokens));
                assert!(Rc::ptr_eq(&fd.vn_high_type_read_facing(source, call), &facing));
            }
        }
        for (native, text, tokens) in observations {
            assert!(text.contains("target") && text.contains('7'), "{source_kind}: {text}");
            let presented: String = tokens.iter().flat_map(|token| token.text.chars())
                .filter(|character| !character.is_whitespace()).collect();
            let complete: String = text.chars().filter(|character| !character.is_whitespace()).collect();
            assert_eq!(presented, complete, "{source_kind}, ctypes={native}: {tokens:?}");
            if source_kind == "integer" {
                arch.ctypes = native;
                let target = fd.obank().get(call).unwrap().get_in(0).unwrap();
                let mut target_print = execution_printer(&arch, false);
                target_print.push_vn_ir(&fd, &arch, target, call);
                target_print.recurse();
                let target_expression = target_print.emit_mut().output_str().to_string();
                let signature_consumer = format!(r#"
#include <stdint.h>
typedef int32_t int4;
typedef void (*expected_callback)(int4);
static void verify_target(uintptr_t target) {{
    _Static_assert(_Generic(({target_expression}), expected_callback: 1, default: 0),
                   "the actual CALL target must retain its complete callable type");
}}
int main(void) {{ verify_target(0); return 0; }}
"#);
                assert_c_source_with_warnings(&signature_consumer,
                    &format!("recovered-call-target-type-{source_kind}-{native}"),
                    &["-Wall", "-Wextra", "-Werror=strict-prototypes"]);
            } else {
                // These exact expressions contain only the named target and
                // literal7: retain the original no-visible-conversion negative.
                assert!(!tokens.iter().any(|token| token.kind == TokenKind::Type),
                    "uncast target acquired a visible conversion: {tokens:?}");
            }
            if matches!(source_kind, "generic" | "integer") {
                let target = if source_kind == "integer" {
                    "uintptr_t target = (uintptr_t)provider;\n\
                     assert((void (*)(int4))target == provider);"
                } else {
                    "void (*target)(int4) = provider;"
                };
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
    {target}
    {text};
    assert(calls == 1 && effect == 18);
    return 0;
}}
"#);
                assert_c_source(&consumer,
                    &format!("recovered-call-expression-{source_kind}-{native}"));
            }
        }
    }
    // EC-0759's clone-local inferred receipt and override-specific dialect
    // projection are unrepresented: current authority is Funcdata/per-high,
    // and PrintC's CAST consumer has no inferred-target/override discriminator.
}
