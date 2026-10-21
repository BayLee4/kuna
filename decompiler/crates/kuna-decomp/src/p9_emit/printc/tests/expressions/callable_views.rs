use super::*;
use crate::dtype::DatatypeKind;

#[test]
fn callable_target_borrows_only_complete_authored_site_contracts() {
    use crate::fspec::FuncCallSpecs;

    for kind in ["authored", "inferred", "locked", "input_open", "output_open", "wrong_arity"] {
        for generic_code in [false, true] {
            let mut fd = build_fd();
            let types = callable_types();
            let integer = types.get_base(4, type_metatype::TYPE_INT).unwrap();
            let code = declared_code(&types, &fd, integer.clone(), vec![integer], false);
            let mut signature = code.get_code_prototype().unwrap().as_ref().clone();
            assert!(signature.logical_pieces().is_some(),
                "logical pieces also exist on inferred generated Code");
            let target_type = types.get_type_pointer(8, if generic_code {
                types.get_type_code().unwrap()
            } else { types.get_type_void().unwrap() }, 1).unwrap();
            fd.set_high_level();
            let target = execution_input(&mut fd, "callback", target_type.clone());
            let call = mk_op(&mut fd, if kind == "wrong_arity" { 1 } else { 2 }, 0x1000, OpCode::CPUI_CALLIND);
            fd.op_set_input(call, target, 0).unwrap();
            if kind != "wrong_arity" {
                let argument = fd.new_constant(4, 7);
                fd.op_set_input(call, argument, 1).unwrap();
            }
            let site = fd.obank().get(call).unwrap().get_addr().clone();
            if kind == "inferred" {
                fd.get_override_mut().insert_inferred_proto_override(site, 0, Box::new(signature.clone()));
                signature.set_override(true);
            } else if kind != "locked" {
                fd.get_override_mut().insert_proto_override(site, Box::new(signature.clone()));
                signature.set_override(true);
            }
            if kind == "input_open" { signature.set_input_lock(false); }
            if kind == "output_open" { signature.set_output_lock(false); }
            let mut specs = FuncCallSpecs::new(call, Address::new_invalid());
            specs.proto_mut().copy(&signature);
            fd.push_call_specs(specs);
            for native in [false, true, false] {
                let mut arch = bare_arch();
                arch.ctypes = native;
                let mut print = execution_printer(&arch, false);
                print.push_callable_target_ir(&fd, &arch, target, call, Some(fd.get_call_specs(0).proto()), None).unwrap();
                print.recurse();
                let text = print.emit_mut().output_str();
                let authored = !matches!(kind, "inferred" | "locked");
                assert_eq!(text.contains("(*)"), authored && (!generic_code || native),
                    "{kind}, generic_code={generic_code}, ctypes={native}: {text}");
                assert_eq!(fd.obank().get(call).unwrap().get_in(0), Some(target));
                assert!(Rc::ptr_eq(fd.vbank().get(target).unwrap().get_type(), &target_type));
            }
        }
    }
}

fn apply_display_authority(proto: &mut crate::fspec::FuncProto, fd: &Funcdata,
    types: &TypeFactoryImpl, ty: &Rc<Datatype>, authority: &str) {
    use crate::fspec::{parameter_pieces_flags as pf, ParameterPieces, PrototypePieces};
    match authority {
        "override" => proto.set_override(true),
        "output" => {
            proto.set_output_lock(true);
            proto.set_model_lock(false);
        }
        "model" => proto.set_model_lock(true),
        "custom" => {
            let pieces = PrototypePieces {
                outtype: proto.get_output_type().cloned(),
                intypes: vec![ty.clone()], innames: vec!["argument".into()],
                first_var_arg_slot: -1,
                input_storage: vec![(0, ParameterPieces {
                    addr: Address::new(ram(fd), 0x180), type_: Some(ty.clone()),
                    flags: pf::CUSTOM_STORAGE,
                })],
                ..PrototypePieces::default()
            };
            proto.set_pieces(&pieces, Some(proto.model().clone()), types, fd.get_arch().manage()).unwrap();
            proto.set_input_lock(false);
            proto.set_output_lock(false);
            proto.set_model_lock(false);
            assert!(proto.has_custom_storage());
        }
        "voidlock" => {
            proto.store_clear_all_inputs();
            proto.set_input_lock(true);
        }
        "input" | "later" | "later_name" | "later_size" => {
            let slot = int4::from(authority.starts_with("later"));
            let flags = match authority {
                "later_name" => pf::NAMELOCK,
                "later_size" => pf::SIZELOCK,
                _ => pf::TYPELOCK,
            };
            for index in 0..=slot {
                proto.set_param(index, "argument", &ParameterPieces {
                    addr: Address::new(ram(fd), 0x100 + index as u64 * 8),
                    type_: Some(ty.clone()), flags: if index == slot { flags } else { 0 },
                });
            }
            assert!(!proto.is_model_locked());
            if slot == 1 { assert!(!proto.is_input_locked()); }
        }
        _ => {}
    }
}

#[test]
fn callable_dialect_cast_preserves_explicit_semantic_declaration() {
    use crate::fspec::{parameter_pieces_flags, FuncCallSpecs, ParameterPieces, ProtoModel};
    for source_kind in ["generic", "declared", "void", "integer", "narrow", "word_addressed",
        "call_override", "call_input", "call_later", "call_output", "call_model", "call_custom",
        "call_later_name", "call_later_size", "scalar_constant", "scalar_unknown",
        "scalar_callother", "scalar_narrow", "second_use", "declared_void", "call_open", "view_open"] {
        for variadic in [false, true] {
            let mut fd = build_fd();
            let types = callable_types();
            let void = types.get_type_void().unwrap();
            let int4 = types.get_base(4, type_metatype::TYPE_INT).unwrap();
            let declared_variadic = match source_kind {
                "call_open" => false,
                "view_open" => true,
                _ => variadic,
            };
            let declared = declared_code(&types, &fd, void.clone(), vec![int4.clone()], declared_variadic);
            let destination = types.get_type_pointer(8, declared.clone(), 1).unwrap();
            let source_type = if source_kind == "integer" || source_kind.starts_with("scalar") {
                types.get_base(if source_kind == "scalar_narrow" { 4 } else { 8 },
                    if source_kind == "scalar_unknown" || source_kind == "scalar_callother" {
                        type_metatype::TYPE_UNKNOWN
                    } else { type_metatype::TYPE_UINT }).unwrap()
            } else {
                let base = match source_kind {
                    "void" => void.clone(),
                    "declared" => declared_code(&types, &fd, void.clone(), vec![], false),
                    _ => types.get_type_code().unwrap(),
                };
                types.get_type_pointer(if source_kind == "narrow" { 4 } else { 8 }, base,
                    if source_kind == "word_addressed" { 2 } else { 1 }).unwrap()
            };
            let source_address = Address::new(ram(&fd), 0x400);
            let source = if source_kind == "scalar_constant" {
                let value = fd.new_constant(8, 0x200000);
                fd.vn_update_type(value, source_type.clone());
                value
            } else if source_kind == "scalar_callother" {
                let producer = mk_op(&mut fd, 2, 0x0ffc, OpCode::CPUI_CALLOTHER);
                let userop = fd.new_constant(4, 0);
                let number = fd.new_constant(4, 0x29);
                fd.op_set_input(producer, userop, 0).unwrap();
                fd.op_set_input(producer, number, 1).unwrap();
                let value = fd.new_unique(8, Some(source_type.clone()));
                fd.op_set_output(producer, value).unwrap();
                fd.vbank_mut().get_mut(value).unwrap().set_implied();
                value
            } else {
                let value = fd.new_varnode(source_type.get_size(), &source_address, Some(source_type.clone())).unwrap();
                fd.set_input_varnode(value).unwrap()
            };
            let mut model = ProtoModel::new(fd.get_arch().manage());
            model.build_param_list("standard").unwrap();
            fd.get_func_proto_mut().set_internal(Rc::new(model), void);
            fd.get_func_proto_mut().set_param(0, "callback", &ParameterPieces {
                addr: source_address, type_: Some(if source_kind == "declared_void" {
                    types.get_type_pointer(8, types.get_type_void().unwrap(), 1).unwrap()
                } else { source_type.clone() }),
                flags: parameter_pieces_flags::NAMELOCK | parameter_pieces_flags::TYPELOCK,
            });
            let cast = mk_op(&mut fd, 1, 0x1000, OpCode::CPUI_CAST);
            fd.op_set_input(cast, source, 0).unwrap();
            let output = fd.new_unique(8, Some(destination.clone()));
            fd.op_set_output(cast, output).unwrap();
            let call = mk_op(&mut fd, 2, 0x1004, OpCode::CPUI_CALLIND);
            let argument = fd.new_constant(4, 7);
            fd.op_set_input(call, output, 0).unwrap();
            fd.op_set_input(call, argument, 1).unwrap();
            let mut specs = FuncCallSpecs::new(call, Address::new_invalid());
            specs.proto_mut().copy(declared.get_code_prototype().unwrap());
            specs.proto_mut().set_input_lock(false);
            specs.proto_mut().set_output_lock(false);
            specs.proto_mut().set_model_lock(false);
            specs.proto_mut().set_dotdotdot(match source_kind {
                "call_open" => true,
                "view_open" => false,
                _ => variadic,
            });
            if let Some(authority) = source_kind.strip_prefix("call_") {
                apply_display_authority(specs.proto_mut(), &fd, &types, &int4, authority);
            }
            fd.push_call_specs(specs);
            if source_kind == "second_use" {
                let copy = mk_op(&mut fd, 1, 0x1008, OpCode::CPUI_COPY);
                fd.op_set_input(copy, output, 0).unwrap();
            }
            fd.set_high_level();
            for native in [false, true, false] {
                let mut arch = bare_arch();
                arch.ctypes = native;
                arch.types_impl().setup_sizes(Some(4), 8, 8);
                let mut print = execution_printer(&arch, false);
                print.op_type_cast_ir(&fd, &arch, cast).unwrap();
                let text = print.emit_mut().output_str();
                assert!(text.contains(if native { "int" } else { "int4" }) && text.contains("(*)"),
                    "explicit signature erased for {source_kind}: {text}");
                assert_eq!(text.contains("..."), declared_variadic, "{text}");
                assert_eq!(fd.obank().get(call).unwrap().get_in(0), Some(output));
                assert_eq!(fd.obank().get(cast).unwrap().get_in(0), Some(source));
                assert_eq!(fd.obank().get(cast).unwrap().code(), OpCode::CPUI_CAST);
                assert!(Rc::ptr_eq(fd.vbank().get(source).unwrap().get_type(), &source_type));
                assert!(Rc::ptr_eq(fd.vbank().get(output).unwrap().get_type(), &destination));
                if source_kind == "declared_void" {
                    assert_eq!(fd.get_func_proto().get_param(0).unwrap().get_type().unwrap()
                        .get_ptr_to().unwrap().get_metatype(), type_metatype::TYPE_VOID);
                }
            }
        }
    }
}

#[test]
fn generic_numeric_transfer_keeps_code_identity_and_refuses_other_domains() {
    use crate::fspec::FuncProto;
    for kind in [
        "transfer", "inferred", "legacy", "nocasts", "zero", "nonconstant",
        "ordinary_reader", "argument", "arguments", "result", "width_mismatch",
        "explicit_space", "truncated", "word_addressed", "pointer_alias",
        "pointer_qualified", "code_alias", "code_qualified", "source_full", "authored",
    ] {
        let mut fd = build_fd();
        let types = callable_types();
        let code = types.get_type_code().unwrap();
        assert!(code.get_code_prototype().is_none());
        let pointee = match kind {
            "source_full" => declared_code(&types, &fd, types.get_type_void().unwrap(), vec![], false),
            "code_alias" => types.get_typedef(&code, "OpaqueCode", 0, 0).unwrap(),
            "code_qualified" => types.get_qualified_type(code.clone(), crate::kuna_typequal::CONST).unwrap(),
            _ => code.clone(),
        };
        let pointer = if kind == "explicit_space" {
            types.get_type_pointer_with_space(pointee, ram(&fd), "").unwrap()
        } else {
            types.get_type_pointer(8, pointee, 1).unwrap()
        };
        let pointer = match kind {
            "truncated" | "word_addressed" => {
                let mut supplied = (*pointer).clone();
                if let DatatypeKind::Pointer { truncate, wordsize, .. } = &mut supplied.kind {
                    if kind == "truncated" {
                        *truncate = Some(types.get_type_pointer(4, code.clone(), 1).unwrap());
                    } else {
                        *wordsize = 2;
                    }
                }
                Rc::new(supplied)
            }
            "pointer_alias" => types.get_typedef(&pointer, "OpaqueCallback", 0, 0).unwrap(),
            "pointer_qualified" => types.get_qualified_type(pointer, crate::kuna_typequal::CONST).unwrap(),
            _ => pointer,
        };
        let value = if kind == "nonconstant" {
            fd.new_unique(8, Some(pointer.clone()))
        } else {
            fd.new_constant(if kind == "width_mismatch" { 4 } else { 8 },
                if kind == "zero" { 0 } else { 0x200000 })
        };
        fd.vn_update_type(value, pointer.clone());
        let slot = int4::from(kind == "argument");
        let reader = mk_op(&mut fd, if slot == 1 || kind == "arguments" { 2 } else { 1 }, 0x1000,
            if kind == "ordinary_reader" { OpCode::CPUI_COPY } else { OpCode::CPUI_CALLIND });
        let other = fd.new_constant(8, 7);
        fd.op_set_input(reader, other, 0).unwrap();
        if slot == 1 || kind == "arguments" {
            fd.op_set_input(reader, other, 1).unwrap();
        }
        fd.op_set_input(reader, value, slot).unwrap();
        if kind == "result" {
            let result = fd.new_unique(4, Some(types.get_base(4, type_metatype::TYPE_INT).unwrap()));
            fd.op_set_output(reader, result).unwrap();
        }
        let site = fd.obank().get(reader).unwrap().get_addr().clone();
        if kind == "authored" {
            fd.get_override_mut().insert_proto_override(site, Box::new(FuncProto::new()));
        } else if kind == "inferred" {
            fd.get_override_mut().insert_inferred_proto_override(site, 0, Box::new(FuncProto::new()));
        }
        let mut arch = bare_arch();
        arch.ctypes = kind != "legacy";
        let mut print = execution_printer(&arch, false);
        print.set_no_cast_printing(kind == "nocasts");
        let spelling = print.generic_numeric_callable_type(&fd, value, reader, &pointer);
        if matches!(kind, "transfer" | "inferred") {
            let spelling = spelling.expect("generic zero-argument transfer needs one callable conversion");
            assert_eq!(format!("{}{}", spelling.front, spelling.back), "void (*)()");
            assert_eq!(spelling.front_types.len(), 1);
            assert!(Rc::ptr_eq(&spelling.front_types[0].datatype, &code));
            assert!(spelling.back_types.is_empty());
            print.push_vn_explicit_ir(&fd, &arch, value, reader).unwrap();
            print.recurse();
            let text = print.emit_mut().output_str();
            assert_eq!(text, "(void (*)())0x200000");
            assert_c_source(&format!(r#"
_Static_assert(_Generic({text}, void (*)(): 1, default: 0),
               "the numeric expression remains a callable C type");
int main(void) {{ return 0; }}
"#), &format!("generic-numeric-{kind}"));
        } else {
            assert!(spelling.is_none(), "generic numeric projection admitted {kind}");
        }
        assert!(Rc::ptr_eq(fd.vbank().get(value).unwrap().get_type(), &pointer));
        assert_eq!(fd.vbank().get(value).unwrap().get_def(), None);
        assert_eq!(fd.obank().get(reader).unwrap().get_in(slot), Some(value));
        assert_eq!(fd.vbank().get(value).unwrap().is_constant(), kind != "nonconstant");
    }
}

#[test]
fn numeric_callable_projection_preserves_non_target_abi_and_pointer_views() {
    use crate::fspec::{FuncCallSpecs, FuncProto, ParameterPieces, ProtoModel};
    for kind in ["callable", "void", "object", "null", "explicit_space", "truncated",
        "width_mismatch", "ordinary_reader", "argument", "view_open", "call_open",
        "call_override", "call_input", "call_later", "call_output", "call_model", "call_custom",
        "call_voidlock", "call_later_name", "call_later_size"] {
        let mut fd = build_fd();
        let types = callable_types();
        let void = types.get_type_void().unwrap();
        let base = match kind {
            "void" => void.clone(),
            "object" => types.get_base(4, type_metatype::TYPE_INT).unwrap(),
            _ => declared_code(&types, &fd, void.clone(), vec![], kind == "view_open"),
        };
        let pointer = if kind == "explicit_space" {
            types.get_type_pointer_with_space(base, ram(&fd), "").unwrap()
        } else {
            let pointer = types.get_type_pointer(8, base.clone(), 1).unwrap();
            if kind == "truncated" {
                // A bounded expression refusal consumes supplied pointer metadata,
                // not factory interning or a segmented-address producer.
                let mut supplied = (*pointer).clone();
                if let DatatypeKind::Pointer { truncate, .. } = &mut supplied.kind {
                    *truncate = Some(types.get_type_pointer(4, base, 1).unwrap());
                }
                Rc::new(supplied)
            } else { pointer }
        };
        let value = fd.new_constant(if kind == "width_mismatch" { 4 } else { 8 }, if kind == "null" { 0 } else { 0x200000 });
        fd.vn_update_type(value, pointer.clone());
        let int_type = types.get_base(4, type_metatype::TYPE_INT).unwrap();
        let mut model = ProtoModel::new(fd.get_arch().manage());
        model.build_param_list("standard").unwrap();
        let mut signature = FuncProto::new();
        signature.set_internal(Rc::new(model), void);
        if let Some(authority) = kind.strip_prefix("call_") {
            apply_display_authority(&mut signature, &fd, &types, &int_type, authority);
        }
        signature.set_dotdotdot(kind == "call_open");
        if kind == "argument" {
            signature.set_param(0, "callback", &ParameterPieces {
                addr: Address::new(ram(&fd), 0x100), type_: Some(pointer.clone()), flags: 0,
            });
        }
        let slot = int4::from(kind == "argument");
        let reader = mk_op(&mut fd, (signature.num_params() + 1).max(slot + 1), 0x1000,
            if kind == "ordinary_reader" { OpCode::CPUI_COPY } else { OpCode::CPUI_CALLIND });
        for index in 0..signature.num_params() + 1 {
            let argument = fd.new_constant(4, index as u64 + 7);
            fd.op_set_input(reader, argument, index).unwrap();
        }
        fd.op_set_input(reader, value, slot).unwrap();
        if kind != "ordinary_reader" {
            let mut specs = FuncCallSpecs::new(reader, Address::new_invalid());
            specs.proto_mut().copy(&signature);
            fd.push_call_specs(specs);
        }
        for native in [false, true] {
            let mut arch = bare_arch();
            arch.ctypes = native;
            let mut print = execution_printer(&arch, false);
            print.options.null = kind == "null";
            print.push_vn_explicit_ir(&fd, &arch, value, reader).unwrap();
            print.recurse();
            let text = print.emit_mut().output_str();
            if kind == "null" {
                assert_eq!(text, "NULL");
                // Java prints the language literal whatever the C `NULL` option says.
                let mut java = execution_printer(&arch, false);
                java.set_name(crate::kuna_lang::OutLang::Java.print_name());
                java.options.null = false;
                java.push_vn_explicit_ir(&fd, &arch, value, reader).unwrap();
                java.recurse();
                assert_eq!(java.emit_mut().output_str(), "null");
            }
            else if kind == "void" { assert!(text.contains("void *"), "{text}"); }
            else if kind == "object" { assert!(!text.contains("(*)"), "object pointer promoted: {text}"); }
            else { assert!(text.contains("(*)"), "callable declaration erased for {kind}: {text}"); }
            assert!(Rc::ptr_eq(fd.vbank().get(value).unwrap().get_type(), &pointer));
            assert!(fd.vbank().get(value).unwrap().is_constant());
            assert!(fd.vbank().get(value).unwrap().get_def().is_none());
            assert_eq!(fd.obank().get(reader).unwrap().get_in(slot), Some(value));
        }
    }
}

    #[test]
    fn loaded_callable_views_preserve_explicit_signature_despite_member_guesses() {
        use crate::dtype::{TypeFactory, TypeFactoryImpl};
        use crate::fspec::{parameter_pieces_flags, FuncCallSpecs, FuncProto, ParameterPieces, ProtoModel};
        use crate::prettyprint::TokenKind;

        for case in [
            "declared_code", "visible_cast", "declared_void", "named_cast",
            "wrong_load_width", "wrong_stride", "unresolved_unknown_load",
            "copy_loaded",
        ] {
            let mut fd = build_fd();
            let types = TypeFactoryImpl::new();
            types.setup_sizes(Some(4), 8, 8);
            types.set_max_basetype_size(8);
            for (name, size, meta) in [
                ("void", 1, type_metatype::TYPE_VOID),
                ("code", 1, type_metatype::TYPE_CODE),
                ("int4", 4, type_metatype::TYPE_INT),
            ] {
                types.set_core_type(name, size, meta, false).unwrap();
            }
            types.cache_core_types().unwrap();
            let void = types.get_type_void().unwrap();
            let code_ptr = types.get_type_pointer(8, types.get_type_code().unwrap(), 1).unwrap();
            let code_table = types.get_type_pointer(8, code_ptr.clone(), 1).unwrap();
            let void_ptr = types.get_type_pointer(8, void.clone(), 1).unwrap();
            let void_table = types.get_type_pointer(8, void_ptr.clone(), 1).unwrap();
            let declaration = if case == "visible_cast" {
                void_ptr
            } else if matches!(case, "declared_void" | "named_cast") {
                void_table
            } else {
                code_table.clone()
            };
            let address = Address::new(ram(&fd), 0x400);
            let table = fd.new_varnode(8, &address, Some(if case == "declared_void" {
                code_table.clone()
            } else { declaration.clone() })).unwrap();
            let table = fd.set_input_varnode(table).unwrap();
            let mut model = ProtoModel::new(fd.get_arch().manage());
            model.build_param_list("standard").unwrap();
            let model = Rc::new(model);
            
            fd.get_func_proto_mut().set_internal(Rc::clone(&model), void.clone());
            fd.get_func_proto_mut().set_param(0, "table", &ParameterPieces {
                addr: address, type_: Some(declaration.clone()),
                flags: parameter_pieces_flags::TYPELOCK | parameter_pieces_flags::NAMELOCK,
            });
            let pointer = if matches!(case, "visible_cast" | "named_cast") {
                let cast = mk_op(&mut fd, 1, 0x0ff0, OpCode::CPUI_CAST);
                fd.op_set_input(cast, table, 0).unwrap();
                let out = fd.new_unique(8, Some(code_table.clone()));
                fd.op_set_output(cast, out).unwrap();
                if case == "visible_cast" {
                    fd.vbank_mut().get_mut(out).unwrap().set_implied();
                }
                out
            } else if matches!(case, "wrong_stride" | "unresolved_unknown_load") {
                let add = mk_op(&mut fd, 3, 0x0ff0, OpCode::CPUI_PTRADD);
                let index = fd.new_constant(4, 1);
                let stride = fd.new_constant(4, 4); // elements actually occupy 8 bytes
                fd.op_set_input(add, table, 0).unwrap();
                fd.op_set_input(add, index, 1).unwrap();
                fd.op_set_input(add, stride, 2).unwrap();
                let out = fd.new_unique(8, Some(code_table.clone()));
                fd.op_set_output(add, out).unwrap();
                fd.vbank_mut().get_mut(out).unwrap().set_implied();
                out
            } else { table };
            let load = mk_op(&mut fd, 2, 0x0ff4, OpCode::CPUI_LOAD);
            let space = fd.new_constant(4, ram(&fd).get_index() as u64);
            fd.op_set_input(load, space, 0).unwrap();
            fd.op_set_input(load, pointer, 1).unwrap();
            // Deliberately stale member typing must not turn a short LOAD into
            // a proven full-width callable read from an eight-byte table.
            let loaded = fd.new_unique(
                if case == "wrong_load_width" { 4 } else { 8 },
                Some(if case == "unresolved_unknown_load" {
                    types.get_base(8, type_metatype::TYPE_UNKNOWN).unwrap()
                } else { code_ptr.clone() }),
            );
            fd.op_set_output(load, loaded).unwrap();
            fd.vbank_mut().get_mut(loaded).unwrap().set_implied();
            let source = if case == "copy_loaded" {
                let copy = mk_op(&mut fd, 1, 0x0ff8, OpCode::CPUI_COPY);
                fd.op_set_input(copy, loaded, 0).unwrap();
                let out = fd.new_unique(8, Some(code_ptr));
                fd.op_set_output(copy, out).unwrap();
                fd.vbank_mut().get_mut(out).unwrap().set_implied();
                out
            } else { loaded };
            let mut signature = FuncProto::new();
            signature.set_internal(model, void.clone());
            signature.set_param(0, "argument", &ParameterPieces {
                addr: Address::new(ram(&fd), 0x80),
                type_: Some(types.get_base(4, type_metatype::TYPE_INT).unwrap()),
                flags: 0,
            });
            let destination = types.get_type_pointer(8,
                declared_code(&types, &fd, void.clone(),
                    vec![types.get_base(4, type_metatype::TYPE_INT).unwrap()], false), 1).unwrap();
            let cast = mk_op(&mut fd, 1, 0x1000, OpCode::CPUI_CAST);
            fd.op_set_input(cast, source, 0).unwrap();
            let output = fd.new_unique(8, Some(destination));
            fd.op_set_output(cast, output).unwrap();
            let call = mk_op(&mut fd, 2, 0x1000, OpCode::CPUI_CALLIND);
            let argument = fd.new_constant(4, 7);
            fd.op_set_input(call, output, 0).unwrap();
            fd.op_set_input(call, argument, 1).unwrap();
            let mut specs = FuncCallSpecs::new(call, Address::new_invalid());
            specs.proto_mut().copy(&signature);
            fd.push_call_specs(specs);
            fd.set_high_level();
            if case == "named_cast" {
                // The CAST result is a member of the named input High. Reading
                // it prints the void** declaration, not its hidden code** CAST.
                let high = fd.vbank().get(table).unwrap().get_high().unwrap();
                let other = fd.vbank().get(pointer).unwrap().get_high().unwrap();
                let mut writes = Vec::new();
                fd.with_high_split(|bank, ctx| {
                    bank.merge_internal(high, other, false, ctx, &mut |vn, high, group| {
                        writes.push((vn, high, group));
                    })
                }).unwrap();
                for (vn, high, group) in writes {
                    fd.vbank_mut().get_mut(vn).unwrap().set_high(high, group);
                }
            }
            // Bind the existing source parameter's real High, not a fake C
            // variable for an otherwise unnamed physical input.
            name_call_local(&mut fd, table, "table");
            let mut arch = bare_arch();
            arch.types_impl().setup_sizes(Some(4), 8, 8);
            arch.types_impl().set_core_type("code", 1, type_metatype::TYPE_CODE, false).unwrap();
            arch.types_impl().cache_core_types().unwrap();
            for native in [false, true, false] {
                arch.ctypes = native;
                let mut plain = execution_printer(&arch, false);
                plain.op_type_cast_ir(&fd, &arch, cast).unwrap();
                let text = plain.emit_mut().output_str().to_string();
                let mut print = PrintC::new();
                print.rt_ctx = RealTypeCtx::from_arch(&arch, crate::kuna_lang::OutLang::C, print.options.convention);
                print.set_markup(true);
                print.emit_mut().set_capture_tokens(true);
                print.op_type_cast_ir(&fd, &arch, cast).unwrap();
                let tokens = print.emit_mut().take_markup_tokens();
                let presented: String = tokens.iter().flat_map(|token| token.text.chars())
                    .filter(|character| !character.is_whitespace()).collect();
                let complete: String = text.chars().filter(|character| !character.is_whitespace()).collect();
                assert_eq!(presented, complete, "{case}, ctypes={native}: {tokens:?}");
                if matches!(case, "visible_cast" | "named_cast") {
                    // Read the pointer exactly as the real LOAD renderer does,
                    // rather than directly forcing its defining CAST to print.
                    let mut plain_view = execution_printer(&arch, false);
                    plain_view.push_vn_ir(&fd, &arch, pointer, load).unwrap();
                    plain_view.recurse();
                    let view = plain_view.emit_mut().output_str().to_string();
                    let mut marked_view = execution_printer(&arch, false);
                    marked_view.set_markup(true);
                    marked_view.emit_mut().set_capture_tokens(true);
                    marked_view.push_vn_ir(&fd, &arch, pointer, load).unwrap();
                    marked_view.recurse();
                    let view_tokens = marked_view.emit_mut().take_markup_tokens();
                    let view_presentation: String = view_tokens.iter().flat_map(|token| token.text.chars())
                        .filter(|character| !character.is_whitespace()).collect();
                    let view_complete: String = view.chars().filter(|character| !character.is_whitespace()).collect();
                    assert_eq!(view_presentation, view_complete, "{case}, ctypes={native}: {view_tokens:?}");
                    if case == "named_cast" {
                        assert!(!view_tokens.iter().any(|token| token.kind == TokenKind::Type),
                            "the named High must not expose its hidden member CAST: {view_tokens:?}");
                    } else {
                        let parameter = crate::printc::declaration_text(
                            &declaration, "table", &RealTypeCtx::from_arch(&arch, crate::kuna_lang::OutLang::C, print.options.convention));
                        let expected_view = if native { "void **" } else { "code **" };
                        let consumer = format!(r#"
#include <stdint.h>
typedef int32_t int4; typedef uint32_t undefined4; typedef uint64_t undefined8;
typedef void code;
typedef {expected_view} expected_pointer;
static void verify_view({parameter}) {{
    _Static_assert(_Generic(({view}), expected_pointer: 1, default: 0),
                   "the actual LOAD operand must retain its usable pointer view");
}}
int main(void) {{ verify_view(0); return 0; }}
"#);
                        assert_c_source(&consumer, &format!("loaded-callable-pointer-view-{native}"));
                    }
                }
                assert_eq!(fd.obank().get(cast).unwrap().code(), OpCode::CPUI_CAST);
                assert_eq!(fd.obank().get(cast).unwrap().get_in(0), Some(source));
                assert_eq!(fd.obank().get(call).unwrap().get_in(0), Some(output));
                let parameter = crate::printc::declaration_text(
                    &declaration, "table", &RealTypeCtx::from_arch(&arch, crate::kuna_lang::OutLang::C, print.options.convention));
                let consumer = format!(r#"
#include <stdint.h>
typedef int32_t int4;
typedef uint32_t undefined4; typedef uint64_t undefined8;
typedef void code;
typedef void (*expected_callback)(int4);
static void verify_signature({parameter}) {{
    _Static_assert(_Generic(({text}), expected_callback: 1, default: 0),
                   "the complete produced expression must have the declared callable type");
}}
int main(void) {{ verify_signature(0); return 0; }}
"#);
                // _Generic does not evaluate its controlling expression.
                // Preserve wrong-stride/short-load inputs without performing
                // their unsupported memory access or calling a fabricated target.
                assert_c_source_with_warnings(&consumer,
                    &format!("loaded-callable-signature-{case}-{native}"),
                    &["-Wall", "-Wextra", "-Werror=strict-prototypes"]);
            }
        }
    }
