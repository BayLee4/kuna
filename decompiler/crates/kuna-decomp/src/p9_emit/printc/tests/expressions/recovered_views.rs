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
        let mut arch = bare_arch();
        arch.realtypes = false;
        arch.set_default_model_rc(Rc::new(model));
        let model = arch.default_fp().unwrap().clone();
        types.set_proto_context(manager.clone());
        types.set_proto_models(Some(model.clone()), Rc::new(std::cell::RefCell::new(std::collections::BTreeMap::from([
            ("recovered_abi".to_string(), model.clone()),
        ]))));
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
            let source = fd.new_varnode(8, &address, Some(source_type.clone())).unwrap();
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
        ActionCallTargetType::boxed("analysis").apply(&mut fd, &mut ActionContext::new()).unwrap();

        let facing = fd.vn_high_type_read_facing(source, call).unwrap();
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
        let destination = get_input_cast(&mut fd, &strategy, call, 0).unwrap();
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
        let mut observations = Vec::new();
        for _ in 0..2 {
            assert!(get_input_cast(&mut fd, &strategy, call, 0).unwrap().is_none());
            for native in [false, true] {
                arch.ctypes = native;
                let mut plain = execution_printer(&arch, false);
                plain.op_call_ir(&fd, &arch, call).unwrap();
                plain.recurse();
                let text = plain.emit_mut().output_str().to_string();
                let mut print = execution_printer(&arch, false);
                print.set_markup(true);
                print.emit_mut().set_capture_tokens(true);
                print.op_call_ir(&fd, &arch, call).unwrap();
                print.recurse();
                let tokens = print.emit_mut().take_markup_tokens();
                observations.push((native, text, tokens));
                assert!(Rc::ptr_eq(&fd.vn_high_type_read_facing(source, call).unwrap(), &facing));
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
                target_print.push_vn_ir(&fd, &arch, target, call).unwrap();
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
}

fn per_call_pipeline_fixture(
    enabled: bool, source_core: bool, integer_target: bool, guard: &str,
) -> (Funcdata, crate::architecture::Architecture, crate::context::VarnodeId, crate::context::OpId, Rc<crate::dtype::Datatype>, Rc<crate::dtype::Datatype>) {
    use crate::dtype::{type_class, TypeFactory, TypeFactoryImpl};
    use crate::fspec::{FuncCallSpecs, ParamEntry, ParameterPieces, ProtoModel};
    use crate::kuna_calltargettype::CallTargetPublication;
    use kuna_base::marshal::{Decoder, IdRegistry, XmlDecode};

    let mut manager = build_manager();
    manager.insert_space(Rc::new(kuna_base::space::IopSpace::new(3))).unwrap();
    manager.set_default_code_space(2).unwrap();
    manager.set_default_data_space(2).unwrap();
    let manager = Rc::new(manager);
    let types = Rc::new(if source_core {
        let types = TypeFactoryImpl::new();
        types.setup_sizes(Some(4), 8, 8);
        types.set_max_basetype_size(8);
        // Actual source31 Java coretypes excerpt, through its real native
        // registration decoder. Do not mark native types host-owned by hand.
        let mut registry = IdRegistry::with_base_ids();
        crate::dtype::register_type_wire_ids(&mut registry);
        let mut decoder = XmlDecode::new(manager.as_ref(), &registry);
        decoder.ingest_stream(br#"<coretypes>
          <type name="void" size="0" metatype="void" id="0xc0000000000000c9"/>
          <type name="code" size="1" metatype="code" id="0xe000000000000001"/>
          <type name="int" size="4" metatype="int" id="0xc000000000000095"/>
          <type name="ulong" size="8" metatype="uint" id="0xc0000000000000c6"/>
        </coretypes>"#).unwrap();
        types.decode_core_types(&mut decoder).unwrap();
        types
    } else {
        callable_types()
    });
    let argument_type = types.get_base(4, type_metatype::TYPE_INT).unwrap();
    assert_eq!(argument_type.is_host_type(), source_core);
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
    let mut arch = bare_arch();
    arch.call_target_publication = CallTargetPublication::PerCallOnly;
    arch.call_target_type = enabled;
    arch.ctypes = true;
    arch.realtypes = true;
    arch.set_default_model_rc(Rc::new(model));
    let model = arch.default_fp().unwrap().clone();
    types.set_proto_context(manager.clone());
    types.set_proto_models(Some(model.clone()), Rc::new(std::cell::RefCell::new(std::collections::BTreeMap::from([
        ("recovered_abi".to_string(), model.clone()),
    ]))));
    let mut context = ContextArch::new_shared(manager);
    context.types = Some(types.clone());
    context.defaultfp = Some(model.clone());
    context.call_target_type = enabled;
    context.call_target_publication = CallTargetPublication::PerCallOnly;
    let mut fd = Funcdata::new("func", "func", Rc::new(context),
        Address::new(ram.clone(), 0x1000), 0x1000_0000, 0x40).unwrap();
    fd.get_func_proto_mut().set_internal(model.clone(), void.clone());
    let source_type = if integer_target {
        types.get_base(8, type_metatype::TYPE_UINT).unwrap()
    } else {
        types.get_type_pointer(8, types.get_type_code().unwrap(), 1).unwrap()
    };
    let source_address = Address::new(ram.clone(), 0x400);
    let source = fd.new_varnode(8, &source_address, Some(source_type.clone())).unwrap();
    let source = fd.set_input_varnode(source).unwrap();
    fd.get_func_proto_mut().set_param(0, "target", &ParameterPieces {
        addr: source_address, type_: Some(source_type.clone()), flags: 0,
    });
    let root = fd.bblocks_root_pub();
    let block = fd.bblocks_mut().new_block_basic(root);
    let call = mk_op(&mut fd, 2, 0x1010, OpCode::CPUI_CALLIND);
    let argument = fd.new_constant(4, 7);
    fd.vn_update_type(argument, argument_type.clone());
    fd.op_set_input(call, source, 0).unwrap();
    fd.op_set_input(call, argument, 1).unwrap();
    let mut specs = FuncCallSpecs::new(call, Address::new_invalid());
    specs.proto_mut().set_internal(model, void);
    specs.set_final_input_storage(vec![(Address::new(ram.clone(),
        if guard == "storage_mismatch" { 0x180 } else { 0x100 }), 4)]);
    fd.push_call_specs(specs);
    fd.op_insert_end(call, block);
    if guard.starts_with("clobber_") {
        let indirect = fd.new_indirect_creation(call, &Address::new(ram, 0x300), 8, true).unwrap();
        if guard == "clobber_read" {
            let value = fd.obank().get(indirect).unwrap().get_out().unwrap();
            let reader = mk_op(&mut fd, 1, 0x1011, OpCode::CPUI_COPY);
            fd.op_set_input(reader, value, 0).unwrap();
            let output = fd.new_unique(8, None);
            fd.op_set_output(reader, output).unwrap();
            fd.op_insert_after(reader, call);
            assert!(!fd.vbank().get(value).unwrap().has_no_descend());
        }
        // The actual producer guard runs while the clobber is adjacent.
        assert_eq!(fd.op_previous_op(call), Some(indirect));
        assert!(fd.obank().get(indirect).unwrap().is_indirect_creation());
    }
    fd.set_high_level();
    name_call_local(&mut fd, source, "target");
    (fd, arch, source, call, source_type, argument_type)
}

#[test]
fn ordinary_callable_pipeline_preserves_ir_and_only_spells_admitted_source_leaves() {
    use crate::action::ActionContext;
    use crate::kuna_calltargettype::ActionCallTargetType;
    use crate::prettyprint::TokenKind;
    use kuna_base::marshal::{Decoder, PackedDecode};

    fn wire_types(fd: &Funcdata, bytes: &[u8]) -> Vec<(String, Option<u64>)> {
        use crate::prettyprint::ids;
        let mut decoder = PackedDecode::new(fd.get_arch().manage());
        decoder.ingest_stream(bytes).unwrap();
        let root = decoder.open_element().unwrap();
        let mut types = Vec::new();
        while decoder.peek_element().unwrap() != 0 {
            let element = decoder.open_element().unwrap();
            if element == ids::ELEM_TYPE.get_id() {
                let mut name = String::new();
                let mut id = None;
                loop {
                    let attribute = decoder.get_next_attribute_id().unwrap();
                    if attribute == 0 { break; }
                    if attribute == ids::ATTRIB_CONTENT.get_id() {
                        name = String::from_utf8(decoder.read_string().unwrap()).unwrap();
                    } else if attribute == ids::ATTRIB_ID.get_id() {
                        id = Some(decoder.read_unsigned_integer().unwrap());
                    }
                }
                types.push((name, id));
            }
            decoder.close_element_skipping(element).unwrap();
        }
        decoder.close_element(root).unwrap();
        types
    }

    for (source_core, guards) in [
        (true, &["clean", "storage_mismatch", "clobber_unread", "clobber_read"][..]),
        (false, &["clean"][..]),
    ] {
        for integer_target in [false, true] {
            for guard in guards.iter().copied() {
                let mut observations = Vec::new();
                let mut disabled_type_tokens = None;
                for enabled in [false, true] {
                    let (mut fd, arch, source, call, source_type, argument_type) =
                        per_call_pipeline_fixture(enabled, source_core, integer_target, guard);
                    // Invoke the real producer at its original phase, before
                    // the real CAST owner, never post-drive reacquisition.
                    ActionCallTargetType::boxed("analysis").apply(&mut fd, &mut ActionContext::new()).unwrap();
                    fd.action_set_casts().unwrap();
                    assert!(Rc::ptr_eq(&fd.vn_high_type_read_facing(source, call).unwrap(), &source_type));
                    assert!(Rc::ptr_eq(fd.get_func_proto().get_param(0).unwrap().get_type().unwrap(), &source_type));
                    let ir: Vec<_> = fd.obank().iter_alive().map(|id| {
                        let operation = fd.obank().get(id).unwrap();
                        let value = |id| {
                            let value = fd.vbank().get(id).unwrap();
                            (value.get_create_index(), (value.get_addr().get_space().map(|space| space.get_index()),
                                value.get_addr().get_offset()), value.get_size(),
                                value.get_type().get_name().to_string(), value.get_type().get_id())
                        };
                        (operation.get_time(), operation.code(), (0..operation.num_input())
                            .map(|slot| value(operation.get_in(slot).unwrap())).collect::<Vec<_>>(),
                            operation.get_out().map(value))
                    }).collect();
                    let mut print = execution_printer(&arch, false);
                    print.set_markup(true);
                    print.emit_mut().set_capture_tokens(true);
                    let document = print.emit_mut().begin_document();
                    print.op_call_ir(&fd, &arch, call).unwrap();
                    print.recurse();
                    print.emit_mut().end_document(document);
                    let tokens = print.emit_mut().take_markup_tokens();
                    let type_tokens = wire_types(&fd, &print.emit_mut().take_markup_bytes());
                    let text: String = tokens.iter().map(|token| token.text.as_str()).collect();
                    let admitted = enabled && source_core && matches!(guard, "clean" | "clobber_unread");
                    if admitted {
                        let expected = (argument_type.get_name().to_string(), Some(argument_type.get_unsized_id().unwrap()));
                        assert!(type_tokens.contains(&expected), "source core identity missing: {type_tokens:?}");
                        let target = if integer_target {
                            "uintptr_t target = (uintptr_t)provider;"
                        } else {
                            "void *target = (void *)provider;"
                        };
                        let consumer = format!(r#"
#include <assert.h>
#include <stdint.h>
static unsigned calls;
static void provider(int value) {{ assert(value == 7 && ++calls == 1); }}
int main(void) {{
    {target}
    {text};
    assert(calls == 1);
    return 0;
}}
"#);
                        assert_c_source_with_warnings(&consumer,
                            &format!("ordinary-call-pipeline-{source_core}-{integer_target}-{guard}"),
                            &["-Wall", "-Wextra", "-Werror=strict-prototypes"]);
                    } else if integer_target {
                        // Standard CAST IR already converts an integer target
                        // to generic code*. Keep that preexisting token stream
                        // exactly; no inferred native leaf may be added.
                        if enabled {
                            assert_eq!(Some(&type_tokens), disabled_type_tokens.as_ref(),
                                "refusal added an inferred type token: {type_tokens:?}");
                        }
                    } else {
                        assert!(!tokens.iter().any(|token| token.kind == TokenKind::Type),
                            "refused bare call acquired a type token: {tokens:?}");
                        assert!(type_tokens.is_empty());
                    }
                    if !enabled { disabled_type_tokens = Some(type_tokens); }
                    observations.push(ir);
                }
                assert_eq!(observations[0], observations[1],
                    "inferred C spelling changed opcode/operand geometry/types/connectivity: core={source_core}, integer={integer_target}, {guard}");
            }
        }
    }
}
