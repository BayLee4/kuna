use super::*;
use super::support::{assert_c_source, bare_arch, build_fd, build_manager, mk_op,
    name_call_local, named_call_input, ram};
use crate::context::ArchContext as ContextArch;
use crate::dtype::{type_metatype, Datatype, TypeFactory, TypeFactoryImpl};
use crate::funcdata::Funcdata;
use kuna_base::address::Address;
use kuna_base::space::{addrspace_flags, spacetype, AddrSpace};
use kuna_num::opcodes::OpCode;
use std::rc::Rc;

fn compact_c(text: &str) -> String {
    text.chars().filter(|c| !c.is_whitespace()).collect()
}

    fn decode_authored_record(types: &TypeFactoryImpl, record: &Datatype) -> Rc<Datatype> {
        use kuna_base::marshal::{Decoder, PackedDecode, PackedEncode};
        let mut bytes = Vec::new();
        record.encode(&mut PackedEncode::new(&mut bytes)).unwrap();
        let manager = build_manager();
        let mut decoder = PackedDecode::new(&manager);
        decoder.ingest_stream(&bytes).unwrap();
        types.decode_type(&mut decoder).unwrap()
    }

mod comment_consumers {
    use super::*;
    use crate::comment::comment_type as ct;
    use crate::context::ArchContext;
    use crate::dtype::{type_metatype, TypeFactory};
    use crate::fspec::ProtoModel;
    use kuna_base::address::Address;
    use kuna_base::error::{KunaError, KunaResult};
    use kuna_base::space::{
        addrspace_flags, spacetype, AddrSpace, AddrSpaceManager, ConstantSpace, UniqueSpace,
    };
    use kuna_sleigh::globalcontext::ContextInternal;
    use kuna_sleigh::loadimage::LoadImage;
    use kuna_sleigh::sleigh::Sleigh;
    use std::rc::Rc;

    struct Image;
    impl LoadImage for Image {
        fn get_file_name(&self) -> &str { "comments" }
        fn load_fill(&mut self, _: &mut [u8], _: &Address) -> KunaResult<()> {
            Err(KunaError::data_unavail("no instruction bytes needed"))
        }
        fn get_arch_type(&self) -> Vec<u8> { Vec::new() }
        fn adjust_vma(&mut self, _: i64) {}
    }

    fn fixture() -> (Funcdata, Architecture, Address) {
        let mut arch = Architecture::new("comments",
            Sleigh::new(Box::new(Image), Box::new(ContextInternal::new())));
        arch.realtypes = false;
        arch.ctypes = false;
        let types = arch.types_rc();
        types.setup_sizes(Some(4), 8, 8);
        types.set_max_basetype_size(8);
        let mut manager = AddrSpaceManager::new();
        manager.insert_space(Rc::new(ConstantSpace::new())).unwrap();
        manager.insert_space(Rc::new(UniqueSpace::new(1, 0, false))).unwrap();
        let ram = Rc::new(AddrSpace::new(spacetype::IPTR_PROCESSOR, "ram", false,
            8, 1, 2, addrspace_flags::hasphysical, 1, 1));
        manager.insert_space(ram.clone()).unwrap();
        manager.set_default_code_space(2).unwrap();
        manager.set_default_data_space(2).unwrap();
        let manager = Rc::new(manager);
        let mut model = ProtoModel::new(&manager);
        model.build_param_list("standard").unwrap();
        let mut context = ArchContext::new_shared(manager);
        context.types = Some(types.clone());
        context.global_query = Some(Rc::new(crate::context::GlobalQuery::default()));
        let mut fd = Funcdata::new("comments", "comments", Rc::new(context),
            Address::new(ram.clone(), 0x1000), 0x1000_0000, 0x40).unwrap();
        fd.get_func_proto_mut().set_internal(Rc::new(model), types.get_type_void().unwrap());
        fd.set_high_level();
        let root = fd.bblocks_root_pub();
        let block = fd.bblocks_mut().new_block_basic(root);
        let address = Address::new(ram, 0x1010);
        let op = fd.new_op(1, address.clone());
        fd.op_set_opcode(op, crate::context::TypeOp::new(OpCode::CPUI_COPY, 0, "COPY"));
        let input = fd.new_constant(4, 7);
        fd.op_set_input(op, input, 0).unwrap();
        let output = fd.new_unique_out(4, op).unwrap();
        fd.vn_update_type(output, types.get_base(4, type_metatype::TYPE_INT).unwrap());
        fd.vbank_mut().get_mut(output).unwrap().set_explicit();
        let high = fd.vbank().get(output).unwrap().get_high().unwrap();
        fd.high_bank_mut().get_mut(high).unwrap().set_kuna_name("value");
        fd.op_insert_end(op, block);
        fd.seed_sblocks_copy();
        (fd, arch, address)
    }

    #[test]
    fn named_calls_without_addresses_preserve_known_names_and_scope() {
        let (mut fd, arch, address) = fixture();
        fd.set_display_name("platform::comments");
        let anchor = fd.obank().iter_alive().next().unwrap();
        for name in ["builtin", "platform::intrinsic"] {
            let op = fd.new_op(1, address.clone());
            fd.op_set_opcode(op, crate::context::TypeOp::new(OpCode::CPUI_CALL, 0, "CALL"));
            let target = fd.new_constant(8, 0);
            fd.op_set_input(op, target, 0).unwrap();
            let mut call = crate::fspec::FuncCallSpecs::new(op, Address::new_invalid());
            call.set_funcdata(Address::new_invalid(), name).unwrap();
            call.proto_mut().copy(fd.get_func_proto());
            fd.push_call_specs(call);
            fd.op_insert_before(op, anchor);
        }
        let mut printer = PrintC::new();
        for (strategy, intrinsic) in [
            (NamespaceStrategy::Minimal, "platform::intrinsic"),
            (NamespaceStrategy::None, "intrinsic"),
            (NamespaceStrategy::All, "platform::intrinsic"),
        ] {
            printer.set_namespace_strategy(strategy);
            let text = printer.doc_function_full(&fd, &arch);
            assert!(text.contains("builtin();"), "{text}");
            assert!(text.contains(&format!("{intrinsic}();")), "{text}");
            assert!(!text.contains("::builtin"), "{text}");
        }
    }

    #[test]
    fn convention_policy_uses_the_committed_models_declaration_visibility() {
        let (mut fd, arch, _) = fixture();
        let mut model = ProtoModel::copy_named("__regparm3", fd.get_func_proto().model());
        fd.get_func_proto_mut().set_model(Some(Rc::new(model.clone())));
        let mut printer = PrintC::new();
        for enabled in [false, true, false] {
            printer.set_convention_printing(enabled);
            let text = printer.doc_function_full(&fd, &arch);
            let declaration = if enabled {
                "void __regparm3 comments(void)"
            } else {
                "void comments(void)"
            };
            assert!(text.contains(declaration), "{text}");
            assert_eq!(text.contains("__regparm3"), enabled, "{text}");
            assert!(text.contains("value = 7;"), "{text}");
        }
        // The architecture suppresses its default model independently of the
        // user's convention setting; enabling display cannot override that.
        model.set_print_in_decl(false);
        fd.get_func_proto_mut().set_model(Some(Rc::new(model)));
        printer.set_convention_printing(true);
        let text = printer.doc_function_full(&fd, &arch);
        assert!(text.contains("void comments(void)"), "{text}");
        assert!(!text.contains("__regparm3"), "{text}");
    }

    #[test]
    fn namespace_policy_changes_spelling_without_changing_global_binding() {
        use crate::action::ActionContext;
        use crate::context::{GlobalEntry, GlobalQuery};
        use crate::coreaction_cleanup::ActionNameVars;
        use crate::remote_provider::{RemoteProviderFetch, RemoteScope};
        use kuna_base::address::RangeList;
        use kuna_base::marshal::{Decoder, ElementId, Encoder, PackedEncode};
        use kuna_base::partmap::PartMap;

        struct NamespaceSource { function: Vec<u8>, namespace: Vec<u8> }
        impl RemoteProviderFetch for NamespaceSource {
            fn fetch_mapped_symbols(&self, addr: &Address, dec: &mut dyn Decoder) -> KunaResult<bool> {
                if addr.get_offset() != 0x1000 { return Ok(false); }
                dec.ingest_stream(&self.function)?;
                Ok(true)
            }
            fn fetch_namespace_path(&self, id: u64, dec: &mut dyn Decoder) -> KunaResult<bool> {
                if id != 10 { return Ok(false); }
                dec.ingest_stream(&self.namespace)?;
                Ok(true)
            }
            fn fetch_external_ref(&self, _: &Address, _: &mut dyn Decoder) -> KunaResult<bool> { Ok(false) }
            fn fetch_tracked_registers(&self, _: &Address, _: &mut dyn Decoder) -> KunaResult<bool> { Ok(false) }
            fn fetch_comments(&self, _: &Address, _: u32, _: &mut dyn Decoder) -> KunaResult<bool> { Ok(false) }
        }
        let (template, mut arch, address) = fixture();
        let manager = template.get_arch().manage.clone();
        let ram = manager.get_space_by_name("ram").unwrap().clone();
        let types = arch.types_rc();
        let int4 = types.get_base(4, type_metatype::TYPE_INT).unwrap();
        let global = Address::new(ram.clone(), 0x2000);
        let entry = Address::new(ram.clone(), 0x1000);
        let doc = ElementId::new("doc", 229);
        let mut function = Vec::new();
        {
            let mut enc = PackedEncode::new(&mut function);
            enc.open_element(&doc);
            enc.write_unsigned_integer(&kuna_base::marshal::ATTRIB_ID, 10);
            enc.open_element(&crate::remote_provider::ELEM_MAPSYM);
            enc.open_element(&crate::remote_provider::ELEM_FUNCTIONSHELL);
            enc.write_string(&kuna_base::marshal::ATTRIB_NAME, b"comments");
            enc.write_unsigned_integer(&kuna_base::marshal::ATTRIB_ID, 0x502);
            entry.encode(&mut enc).unwrap();
            enc.close_element(&crate::remote_provider::ELEM_FUNCTIONSHELL);
            entry.encode_sized(&mut enc, 1).unwrap();
            enc.open_element(&kuna_base::address::ELEM_RANGELIST);
            enc.close_element(&kuna_base::address::ELEM_RANGELIST);
            enc.close_element(&crate::remote_provider::ELEM_MAPSYM);
            enc.close_element(&doc);
        }
        let mut namespace = Vec::new();
        {
            let mut enc = PackedEncode::new(&mut namespace);
            enc.open_element(&crate::remote_provider::ELEM_PARENT);
            for (id, name) in [(0, ""), (10, "outer")] {
                enc.open_element(&kuna_base::marshal::ELEM_VAL);
                enc.write_unsigned_integer(&kuna_base::marshal::ATTRIB_ID, id);
                enc.write_string(&kuna_base::marshal::ATTRIB_CONTENT, name.as_bytes());
                enc.close_element(&kuna_base::marshal::ELEM_VAL);
            }
            enc.close_element(&crate::remote_provider::ELEM_PARENT);
        }
        let mut owned = RangeList::default();
        owned.insert_range(ram.clone(), 0, 0xffff);
        let query = GlobalQuery::new(vec![GlobalEntry {
            space_index: ram.get_index(), first: 0x2000, last: 0x2003, size: 4,
            all_flags: crate::varnode::varnode_flags::persist | crate::varnode::varnode_flags::addrtied,
            addrtied: true, uselimit: RangeList::default(),
            symbol_name: "kept_alias".into(), symbol_offset: 0, symbol_type: Some(int4.clone()),
            scope_path: vec!["inner".into(), "outer".into()], symbol_id: 0x501,
            is_function: false, func_inject_id: -1, func_no_return: false,
        }], owned, PartMap::default());
        let model = template.get_func_proto().model().clone();
        let scope = Rc::new(RemoteScope::new(
            Rc::new(NamespaceSource { function, namespace }), manager.clone(), types.clone(),
            std::collections::BTreeMap::new(), Some(model.clone()), query,
        ));
        let function_path = scope.function_at(&entry).unwrap().scope_path;
        assert_eq!(function_path, ["outer"]);
        let use_path: Vec<_> = function_path.iter().rev().cloned().collect();
        let mut context = ArchContext::new_shared(manager);
        context.types = Some(types.clone());
        context.remote_scope = Some(scope.clone());
        arch.remote_scope = Some(scope.clone());
        let mut fd = Funcdata::new("comments", "comments", Rc::new(context),
            entry, 0x1000_0000, 0x40).unwrap();
        fd.get_func_proto_mut().set_internal(model, types.get_type_void().unwrap());
        fd.set_high_level();
        let root = fd.bblocks_root_pub();
        let block = fd.bblocks_mut().new_block_basic(root);
        let op = fd.new_op(1, address);
        fd.op_set_opcode(op, crate::context::TypeOp::new(OpCode::CPUI_COPY, 0, "COPY"));
        let input = fd.new_constant(4, 7);
        fd.op_set_input(op, input, 0).unwrap();
        let output = fd.new_varnode(4, &global, Some(int4));
        fd.op_set_output(op, output).unwrap();
        fd.vbank_mut().get_mut(output).unwrap().set_explicit();
        fd.op_insert_end(op, block);
        ActionNameVars::boxed("analysis").apply(&mut fd, &mut ActionContext::new());
        fd.seed_sblocks_copy();
        let high = fd.vbank().get(output).unwrap().get_high().unwrap();
        let bound_name = fd.high_bank().get(high).unwrap().kuna_name().unwrap().to_string();
        let source_name = fd.get_arch().name_for_global_varnode_scoped(
            &global, 4, &Address::new_invalid()).unwrap();
        assert_eq!(source_name.0, "kept_alias");
        assert_eq!(source_name.3, ["inner", "outer"]);
        assert_eq!(scope.snapshot().entries_cloned().iter()
            .find(|e| e.first == 0x2000).unwrap().symbol_id, 0x501);
        let mut printer = PrintC::new();
        for (strategy, spelling, function) in [
            (NamespaceStrategy::Minimal, "inner::kept_alias", "outer::comments"),
            (NamespaceStrategy::None, "kept_alias", "comments"),
            (NamespaceStrategy::All, "outer::inner::kept_alias", "outer::comments"),
            (NamespaceStrategy::Minimal, "inner::kept_alias", "outer::comments"),
        ] {
            printer.set_namespace_strategy(strategy);
            let text = printer.doc_function_full(&fd, &arch);
            let prefix = crate::kuna_namespaces::scope_prefix(
                printer.context.namespace_strategy(), &source_name.0,
                &source_name.3, &use_path, &|_, _| false,
            );
            let source_spelling = prefix.into_iter().chain([source_name.0.clone()])
                .collect::<Vec<_>>().join("::");
            assert_eq!(source_spelling, spelling);
            assert!(text.contains(&format!("{function}(void)")), "{text}");
            assert!(text.lines().any(|line| line.trim() == format!("{bound_name} = 7;")), "{text}");
            assert_eq!(fd.vbank().get(output).unwrap().get_high(), Some(high));
            assert_eq!(fd.high_bank().get(high).unwrap().kuna_name(), Some(bound_name.as_str()));
            let preserved = fd.get_arch().name_for_global_varnode_scoped(
                &global, 4, &Address::new_invalid()).unwrap();
            assert_eq!(preserved.0, "kept_alias");
            assert_eq!(preserved.3, ["inner", "outer"]);
        }
        // EC-0750: GlobalQuery retains the bare alias and separate path, but
        // ActionNameVars publishes only qualified text to High, with no scope
        // receipt/symbol id. Bare-High alias and emitted global strategy clauses
        // are unrepresented; the source policy and function declaration are real.
    }

    #[test]
    fn user_visibility_masks_do_not_turn_ordinary_comments_into_warnings() {
        let (fd, mut arch, address) = fixture();
        let mut printer = PrintC::new();
        // IfcCommentInstr stores the current selection mask, not a single
        // category. Its ordinary comment must not become an inline warning.
        arch.commentdb.add_comment(printer.instruction_comment_flags(),
            fd.get_address(), &address, "instructionnote");
        arch.commentdb.add_comment(printer.header_comment_flags(),
            fd.get_address(), fd.get_address(), "headernote");
        arch.commentdb.add_comment(ct::WARNING,
            fd.get_address(), &address, "generated");
        let text = printer.doc_function_full(&fd, &arch);
        for note in ["instructionnote", "headernote"] {
            assert!(text.lines().any(|line| line.trim() == format!("/* {note} */")), "{text}");
            assert!(!text.contains(&format!("warn: {note}")), "{text}");
        }
        assert!(text.contains("value = 7; // warn: generated"), "{text}");
    }

    #[test]
    fn each_instruction_comment_category_obeys_its_mask_across_documents() {
        let (fd, mut arch, address) = fixture();
        let categories = [
            (ct::USER1, "userone"), (ct::USER2, "usertwo"), (ct::USER3, "userthree"),
            (ct::HEADER, "bodyheader"), (ct::WARNING, "bodywarning"),
            (ct::WARNINGHEADER, "bodywarningheader"),
        ];
        for (category, marker) in categories {
            arch.commentdb.add_comment(category, fd.get_address(), &address, marker);
        }
        let mut printer = PrintC::new();
        printer.options.set_warn_inline(false);
        printer.set_header_comment_flags(0);
        for selected in categories.iter().map(|(category, _)| *category).chain([0, ct::USER2]) {
            printer.set_instruction_comment_flags(selected);
            let text = printer.doc_function_full(&fd, &arch);
            for (category, marker) in categories {
                // Include delimiters so bodywarning cannot match bodywarningheader.
                assert_eq!(text.contains(&format!("/* {marker} */")), selected & category != 0,
                    "mask {selected}, category {category}:\n{text}");
            }
        }
    }

    #[test]
    fn header_masks_and_inline_warning_precedence_survive_style_changes() {
        let (fd, mut arch, address) = fixture();
        arch.commentdb.add_comment(ct::HEADER, fd.get_address(), fd.get_address(), "plate");
        arch.commentdb.add_comment(ct::WARNINGHEADER, fd.get_address(), fd.get_address(), "headeralert");
        arch.commentdb.add_comment(ct::USER2, fd.get_address(), &address, "instruction");
        arch.commentdb.add_comment(ct::WARNING, fd.get_address(), &address, "bodyalert");
        let mut printer = PrintC::new();
        for style in ["c", "cplusplus", "c"] {
            printer.set_comment_style(style);
            printer.set_header_comment_flags(ct::HEADER | ct::WARNINGHEADER);
            printer.set_instruction_comment_flags(ct::USER2 | ct::WARNING);
            let text = printer.doc_function_full(&fd, &arch);
            let prefix = if style == "c" { "/* " } else { "// " };
            assert!(text.contains(&format!("{prefix}plate")), "{text}");
            assert!(text.contains(&format!("{prefix}instruction")), "{text}");
            assert!(text.contains("// warn: headeralert"), "{text}");
            assert!(text.contains("// warn: bodyalert"), "{text}");
            printer.set_header_comment_flags(ct::HEADER);
            printer.set_instruction_comment_flags(ct::USER2);
            let masked = printer.doc_function_full(&fd, &arch);
            assert!(!masked.contains("headeralert") && !masked.contains("bodyalert"), "{masked}");
            printer.set_header_comment_flags(ct::WARNINGHEADER);
            let header_only = printer.doc_function_full(&fd, &arch);
            assert!(!header_only.contains("plate") && header_only.contains("headeralert"), "{header_only}");
        }
    }

    #[test]
    fn comment_style_escapes_multiline_text_and_resets_without_leaking_fill() {
        let (mut fd, mut arch, address) = fixture();
        let high = fd.high_bank().iter()
            .find(|(_, high)| high.kuna_name() == Some("value"))
            .map(|(id, _)| id).unwrap();
        let binding = fd.high_bank_mut().get_mut(high).unwrap();
        binding.set_kuna_name("sentinel");
        binding.set_kuna_global(true);
        arch.commentdb.add_comment(ct::USER2, fd.get_address(), &address,
            "first\nsecond */ escaped = 99; /*\nthird\\");
        let mut printer = PrintC::new();
        let baseline = printer.doc_function_full(&fd, &arch);
        for style in ["cplusplus", "c", "cplusplus"] {
            printer.set_line_comment_indent(6).unwrap();
            printer.set_comment_style(style);
            let text = printer.doc_function_full(&fd, &arch);
            let source = format!(
                "#include <assert.h>\n\
                 int sentinel = -1, escaped = 0;\n\
                 {text}\n\
                 int main(void) {{ comments(); assert(escaped == 0); assert(sentinel == 7); return 0; }}\n"
            );
            assert_c_source(&source, &format!("comment-containment-{style}"));
            let prefix = if style == "c" { "/*" } else { "//" };
            assert!(text.lines().any(|line|
                line.starts_with(&format!("      {prefix}")) && line.contains("first")), "{text}");
            for marker in ["first", "second", "third"] {
                assert!(text.contains(marker), "comment payload lost:\n{text}");
            }
            printer.set_comment_style("unknown");
            assert_eq!(printer.doc_function_full(&fd, &arch), text);
            printer.context.reset_defaults_internal();
            assert_eq!(printer.doc_function_full(&fd, &arch), baseline);
        }
    }
}

    mod host_layout {
        use super::*;
        use crate::dtype::TypeFactory;
        use crate::fspec::{ParameterPieces, ProtoModel};
        use crate::prettyprint::ids;
        use kuna_base::marshal::{Decoder, PackedDecode};

        fn fixture() -> (Funcdata, Architecture) {
            let mut arch = bare_arch();
            arch.realtypes = false;
            arch.ctypes = false;
            let types = arch.types_rc();
            types.setup_sizes(Some(4), 8, 8);
            types.set_max_basetype_size(8);
            types.set_core_type("int4", 4, type_metatype::TYPE_INT, false).unwrap();
            types.cache_core_types().unwrap();
            let integer = types.get_base(4, type_metatype::TYPE_INT).unwrap();
            let void = types.get_type_void().unwrap();
            // A real local scope requires a stack space. Without it,
            // link_proto_params is a no-op and named input highs are also
            // emitted as locals instead of FUNCTION_PARAMETER symbols.
            let mut manager = build_manager();
            let register = Rc::new(AddrSpace::new(
                spacetype::IPTR_PROCESSOR, "register", false, 8, 1, 3,
                addrspace_flags::hasphysical, 1, 1,
            ));
            manager.insert_space(register.clone()).unwrap();
            manager.insert_space(Rc::new(kuna_base::space::SpacebaseSpace::new(
                "stack", 4, 8, &register, 1, true, false,
            ))).unwrap();
            let manager = Rc::new(manager);
            let model = Rc::new(ProtoModel::new(&manager));
            let memory = manager.get_space_by_name("ram").unwrap().clone();
            let mut context = ContextArch::new_shared(manager);
            context.types = Some(types);
            let mut fd = Funcdata::new("compute", "compute", Rc::new(context),
                Address::new(memory.clone(), 0x1000), 0x1000_0000, 0x40).unwrap();
            assert!(fd.get_scope_local().is_some(), "host fixture needs parameter symbols");
            fd.get_func_proto_mut().set_internal(model, void);
            fd.get_func_proto_mut().set_output(&ParameterPieces {
                addr: Address::new(memory.clone(), 0x200),
                type_: Some(integer.clone()), flags: 0,
            });
            for (index, name) in ["alpha", "beta", "gamma", "delta"].iter().enumerate() {
                fd.get_func_proto_mut().set_param(index as int4, name, &ParameterPieces {
                    addr: Address::new(memory.clone(), 0x100 + index as u64 * 8),
                    type_: Some(integer.clone()), flags: 0,
                });
            }
            let root = fd.bblocks_root_pub();
            let block = fd.bblocks_mut().new_block_basic(root);
            let ret = mk_op(&mut fd, 2, 0x1000, OpCode::CPUI_RETURN);
            let address = fd.new_constant(8, 0);
            let value = fd.new_constant(4, 7);
            fd.op_set_input(ret, address, 0).unwrap();
            fd.op_set_input(ret, value, 1).unwrap();
            fd.op_insert_end(ret, block);
            fd.seed_sblocks_copy();
            (fd, arch)
        }

        type FieldMarkup = (Vec<u8>, u64, i64, u64);

        fn host_document(fd: &Funcdata, bytes: &[u8]) -> (String, Vec<FieldMarkup>) {
            fn element(decoder: &mut PackedDecode<'_>, text: &mut String, fields: &mut Vec<FieldMarkup>) {
                let id = decoder.open_element().unwrap();
                let mut content = None;
                let mut indent = 0;
                loop {
                    let attr = decoder.get_next_attribute_id().unwrap();
                    if attr == 0 { break; }
                    if attr == ids::ATTRIB_CONTENT.get_id() {
                        content = Some(decoder.read_string().unwrap());
                    } else if attr == ids::ATTRIB_INDENT.get_id() {
                        indent = decoder.read_signed_integer().unwrap();
                    }
                }
                if id == ids::ELEM_BREAK.get_id() {
                    text.push('\n');
                    text.extend(std::iter::repeat_n(' ', indent as usize));
                }
                if let Some(content) = content {
                    text.push_str(std::str::from_utf8(&content).unwrap());
                }
                if id == ids::ELEM_FIELD.get_id() {
                    fields.push((
                        decoder.read_string_id(&ids::ATTRIB_NAME).unwrap(),
                        decoder.read_unsigned_integer_id(&ids::ATTRIB_ID).unwrap(),
                        decoder.read_signed_integer_id(&ids::ATTRIB_OFF).unwrap(),
                        decoder.read_unsigned_integer_id(&ids::ATTRIB_OPREF).unwrap(),
                    ));
                }
                while decoder.peek_element().unwrap() != 0 { element(decoder, text, fields); }
                decoder.close_element(id).unwrap();
            }
            let mut decoder = PackedDecode::new(fd.get_arch().manage());
            decoder.ingest_stream(bytes).unwrap();
            let mut text = String::new();
            let mut fields = Vec::new();
            element(&mut decoder, &mut text, &mut fields);
            (text, fields)
        }

        fn host_text(fd: &Funcdata, bytes: &[u8]) -> String {
            host_document(fd, bytes).0
        }

        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        enum TypePosition { Other, Prototype, Return, Local, Statement }

        fn host_type_tokens(fd: &Funcdata, bytes: &[u8]) -> Vec<(TypePosition, String, Option<u64>)> {
            fn visit(
                decoder: &mut PackedDecode<'_>, position: TypePosition,
                tokens: &mut Vec<(TypePosition, String, Option<u64>)>,
            ) {
                let element = decoder.open_element().unwrap();
                let position = if element == ids::ELEM_FUNCPROTO.get_id() {
                    TypePosition::Prototype
                } else if element == ids::ELEM_RETURN_TYPE.get_id() {
                    TypePosition::Return
                } else if element == ids::ELEM_VARDECL.get_id() && position != TypePosition::Prototype {
                    TypePosition::Local
                } else if element == ids::ELEM_STATEMENT.get_id() {
                    TypePosition::Statement
                } else { position };
                let mut name = None;
                let mut type_id = None;
                loop {
                    let attr = decoder.get_next_attribute_id().unwrap();
                    if attr == 0 { break; }
                    if attr == ids::ATTRIB_CONTENT.get_id() {
                        name = Some(String::from_utf8(decoder.read_string().unwrap()).unwrap());
                    } else if attr == ids::ATTRIB_ID.get_id() {
                        type_id = Some(decoder.read_unsigned_integer().unwrap());
                    }
                }
                if element == ids::ELEM_TYPE.get_id() {
                    tokens.push((position, name.expect("type token content"), type_id));
                }
                while decoder.peek_element().unwrap() != 0 { visit(decoder, position, tokens); }
                decoder.close_element(element).unwrap();
            }
            let mut decoder = PackedDecode::new(fd.get_arch().manage());
            decoder.ingest_stream(bytes).unwrap();
            let mut tokens = Vec::new();
            visit(&mut decoder, TypePosition::Other, &mut tokens);
            tokens
        }

        fn nominal_node(types: &crate::dtype::TypeFactoryImpl) -> Rc<Datatype> {
            use crate::dtype::DatatypeKind;
            let mut node = Datatype::new_with_align(8, 8, type_metatype::TYPE_STRUCT);
            node.name = "Node".into();
            node.display_name = node.name.clone();
            node.id = 72_057_594_037_927_936;
            node.kind = DatatypeKind::Struct { field: vec![], bitfield: vec![] };
            decode_authored_record(types, &node)
        }

        #[test]
        fn host_pointer_prototype_and_cast_keep_pointee_type_identity() {
            for rust in [false, true] {
                let (mut fd, mut arch) = fixture();
                arch.cast_implied = false;
                let types = arch.types_rc();
                let node = nominal_node(&types);
                let pointer = types.get_type_pointer(8, node, 1).unwrap();
                fd.set_high_level();
                named_call_input(&mut fd, "typed_input", pointer.clone());
                let return_address = Address::new(ram(&fd), 0x200);
                fd.get_func_proto_mut().set_output(&ParameterPieces {
                    addr: return_address,
                    type_: Some(pointer.clone()), flags: 0,
                });
                let ret = fd.obank().iter_alive().next().unwrap();
                let cast = mk_op(&mut fd, 1, 0x1000, OpCode::CPUI_CAST);
                let input = fd.new_constant(8, 0x1234);
                fd.op_set_input(cast, input, 0).unwrap();
                let output = fd.new_unique(8, Some(pointer));
                fd.op_set_output(cast, output).unwrap();
                fd.vbank_mut().get_mut(output).unwrap().set_implied();
                fd.op_insert_before(cast, ret);
                fd.op_set_input(ret, output, 1).unwrap();
                let mut print = PrintC::new();
                if rust { print.set_name("rust-language"); }
                let bytes = print.doc_function_markup(&fd, &arch);
                let tokens = host_type_tokens(&fd, &bytes);
                // Check the consumer-visible binding at each semantic position,
                // independently of C/Rust's differing prototype token order.
                for position in [TypePosition::Return, TypePosition::Prototype, TypePosition::Statement] {
                    let ids: Vec<_> = tokens.iter()
                        .filter(|(at, name, _)| *at == position && name == "Node")
                        .map(|(_, _, id)| *id).collect();
                    assert_eq!(ids, vec![Some(72_057_594_037_927_936)],
                        "{position:?}: {}", host_text(&fd, &bytes));
                }
                assert!(!tokens.iter().any(|(at, name, _)|
                    *at == TypePosition::Local && name == "Node"),
                    "parameter must not also be declared as a local: {}", host_text(&fd, &bytes));
            }
        }

        #[test]
        fn host_callback_suffix_and_named_typedef_keep_independent_type_identities() {
            use crate::fspec::{PrototypePieces, ParamEntry};
            use crate::dtype::type_class;
            let (mut fd, arch) = fixture();
            let types = arch.types_rc();
            let node = nominal_node(&types);
            let input = types.get_typedef(&node, "Input alias (v2)", 72_057_594_037_927_937, 0).unwrap();
            let manager = Rc::new(build_manager());
            let space = manager.get_space_by_name("ram").unwrap().clone();
            let mut model = ProtoModel::new(&manager);
            model.build_param_list("standard").unwrap();
            for group in 0..6 {
                let input = model.input_mut();
                input.push_entry(ParamEntry::seed(group, type_class::TYPECLASS_GENERAL,
                    space.clone(), 0x100 + group as u64 * 8, 8, 1, 0, 0, true,
                    false, input.get_entry(), &manager).unwrap());
            }
            model.input_mut().finish_decode();
            model.output_mut().push_entry(ParamEntry::seed(0, type_class::TYPECLASS_GENERAL,
                space, 0x200, 8, 1, 0, 0, true, false, &[], &manager).unwrap());
            model.output_mut().finish_decode();
            types.set_proto_models(Some(Rc::new(model)), std::collections::BTreeMap::new());
            types.set_proto_context(manager);
            let callable = |output: &Rc<Datatype>, inputs: Vec<Rc<Datatype>>| {
                let code = types.get_type_code_proto(&PrototypePieces {
                    outtype: Some(output.clone()), intypes: inputs,
                    first_var_arg_slot: -1, ..PrototypePieces::default()
                }).unwrap();
                types.get_type_pointer(8, code, 1).unwrap()
            };
            let nested = callable(&input, vec![node.clone()]);
            let callback = callable(&node, vec![input, nested]);
            let alias = types.get_typedef(&callback, "Transform (next)", 72_057_594_037_927_938, 0).unwrap();
            fd.set_high_level();
            named_call_input(&mut fd, "callback", callback);
            named_call_input(&mut fd, "named_callback", alias);
            let bytes = PrintC::new().doc_function_markup(&fd, &arch);
            let tokens = host_type_tokens(&fd, &bytes);
            let nominal: Vec<_> = tokens.iter()
                .filter(|(at, name, _)| *at == TypePosition::Prototype
                    && matches!(name.as_str(), "Node" | "Input alias (v2)" | "Transform (next)"))
                .map(|(_, name, id)| (name.clone(), *id))
                .collect();
            assert_eq!(nominal, vec![
                ("Node".into(), Some(72_057_594_037_927_936)),
                ("Input alias (v2)".into(), Some(72_057_594_037_927_937)),
                ("Input alias (v2)".into(), Some(72_057_594_037_927_937)),
                ("Node".into(), Some(72_057_594_037_927_936)),
                ("Transform (next)".into(), Some(72_057_594_037_927_938)),
            ], "{}", host_text(&fd, &bytes));
            assert!(!tokens.iter().any(|(at, name, _)| *at == TypePosition::Local
                && matches!(name.as_str(), "Node" | "Input alias (v2)" | "Transform (next)")),
                "callback parameters must not also be declared as locals: {}", host_text(&fd, &bytes));
        }

        #[test]
        fn host_local_symbol_override_annotates_selected_composite_or_array_element() {
            for rust in [false, true] {
                for array in [false, true] {
                    let (mut fd, arch) = fixture();
                    let types = arch.types_rc();
                    let node = nominal_node(&types);
                    let symbol_type = if array {
                        types.get_type_array(2, node).unwrap()
                    } else { node };
                    let byte = types.get_base(1, type_metatype::TYPE_UINT).unwrap();
                    fd.set_high_level();
                    let ret = fd.obank().iter_alive().next().unwrap();
                    let copy = mk_op(&mut fd, 1, 0x1000, OpCode::CPUI_COPY);
                    let value = fd.new_constant(1, 0);
                    fd.op_set_input(copy, value, 0).unwrap();
                    let output = fd.new_unique(1, Some(byte.clone()));
                    fd.op_set_output(copy, output).unwrap();
                    name_call_local(&mut fd, output, "local");
                    let high = fd.vbank().get(output).unwrap().get_high().unwrap();
                    let high = fd.high_bank_mut().get_mut(high).unwrap();
                    high.set_symbol_type(symbol_type);
                    high.set_symbol_offset(0);
                    fd.op_insert_before(copy, ret);
                    // This is genuinely an override, not two names for the
                    // same datatype selected by the ordinary representative.
                    assert!(Rc::ptr_eq(fd.vbank().get(output).unwrap().get_type(), &byte));
                    let mut print = PrintC::new();
                    if rust { print.set_name("rust-language"); }
                    let bytes = print.doc_function_markup(&fd, &arch);
                    let nodes: Vec<_> = host_type_tokens(&fd, &bytes).into_iter()
                        .filter(|(at, name, _)| *at == TypePosition::Local && name == "Node")
                        .map(|(_, name, id)| (name, id)).collect();
                    assert_eq!(nodes, vec![("Node".into(), Some(72_057_594_037_927_936))],
                        "{}", host_text(&fd, &bytes));
                }
            }
        }

        #[test]
        fn rust_host_markup_uses_rust_grammar_and_exact_field_references() {
            use crate::dtype::{DatatypeKind, TypeField};
            let (mut fd, arch) = fixture();
            let types = arch.types_rc();
            let integer = types.get_base(4, type_metatype::TYPE_INT).unwrap();
            let first = types.get_base(8, type_metatype::TYPE_INT).unwrap();
            let mut node = Datatype::new_with_align(16, 8, type_metatype::TYPE_STRUCT);
            node.name = "Node".into();
            node.display_name = node.name.clone();
            node.id = 72_057_594_037_927_936;
            node.kind = DatatypeKind::Struct {
                field: vec![
                    TypeField::new(0, 0, "first", first.clone()),
                    TypeField::new(1, 8, "next", integer.clone()),
                ], bitfield: vec![],
            };
            let node = decode_authored_record(&types, &node);
            let pointer = types.get_type_pointer(8, node, 1).unwrap();
            let field_pointer = types.get_type_pointer(8, integer.clone(), 1).unwrap();
            fd.set_high_level();
            let base = named_call_input(&mut fd, "node", pointer);
            let ret = fd.obank().iter_alive().next().unwrap();
            let member = mk_op(&mut fd, 2, 0x1000, OpCode::CPUI_PTRSUB);
            let offset = fd.new_constant(8, 8);
            fd.op_set_input(member, base, 0).unwrap();
            fd.op_set_input(member, offset, 1).unwrap();
            let address = fd.new_unique(8, Some(field_pointer));
            fd.op_set_output(member, address).unwrap();
            fd.vbank_mut().get_mut(address).unwrap().set_implied();
            fd.op_insert_before(member, ret);
            let load = mk_op(&mut fd, 2, 0x1000, OpCode::CPUI_LOAD);
            let space = fd.new_constant(8, ram(&fd).get_index() as u64);
            fd.op_set_input(load, space, 0).unwrap();
            fd.op_set_input(load, address, 1).unwrap();
            let value = fd.new_unique(4, Some(integer));
            fd.op_set_output(load, value).unwrap();
            fd.vbank_mut().get_mut(value).unwrap().set_implied();
            fd.op_insert_before(load, ret);
            fd.op_set_input(ret, value, 1).unwrap();
            // The fixture already seeded this basic block's BlockCopy. Added
            // operations are visible through it; seeding again duplicates the
            // same block in the structured graph.
            let mut print = PrintC::new();
            print.set_name("rust-language");
            let bytes = print.doc_function_markup(&fd, &arch);
            let (text, fields) = host_document(&fd, &bytes);
            let compact = compact_c(&text);
            assert!(compact.contains("fncompute(") && compact.contains("node:*mutNode"), "{text}");
            assert!(compact.contains(")->i32") && compact.contains(".next"), "{text}");
            assert_eq!(fields, vec![(b"Node".to_vec(), 72_057_594_037_927_936, 8,
                fd.obank().get(member).unwrap().get_time() as u64)]);
            assert_eq!(print.get_name(), "rust-language");
        }

        #[test]
        fn queued_c_comments_and_inline_warnings_keep_their_own_continuations() {
            use crate::comment::comment_type as ct;
            let (fd, mut arch) = fixture();
            arch.commentdb.add_comment(ct::USER2, fd.get_address(), fd.get_address(),
                "ordinary first\nordinary second");
            arch.commentdb.add_comment(ct::WARNING, fd.get_address(), fd.get_address(),
                "warning alpha beta gamma delta epsilon");
            let mut print = PrintC::new();
            print.set_max_line_size(20).unwrap();
            print.set_line_comment_indent(2).unwrap();
            print.set_comment_style("c");
            print.set_header_comment_flags(0);
            print.set_instruction_comment_flags(ct::USER2 | ct::WARNING);
            print.options.set_warn_inline(true);
            let text = host_text(&fd, &print.doc_function_markup(&fd, &arch));
            let block = text.split("/*").skip(1)
                .filter_map(|block| block.split_once("*/").map(|(body, _)| body))
                .find(|body| body.contains("ordinary")).unwrap();
            assert!(block.contains("first") && block.contains("second") && !block.contains("//"), "{text}");
            let warning = &text[text.find("//").unwrap()..];
            let warning_lines: Vec<_> = warning.lines()
                .filter(|line| line.contains("alpha") || line.contains("beta")
                    || line.contains("gamma") || line.contains("delta") || line.contains("epsilon"))
                .collect();
            assert!(warning_lines.len() > 1, "{text}");
            assert!(warning_lines.iter().all(|line| line.trim_start().starts_with("//")), "{text}");
        }

        #[test]
        fn host_width_and_indent_survive_sinks_without_moving_raw_source_maps() {
            let (fd, arch) = fixture();
            let mut print = PrintC::new();
            let raw = print.doc_function_full(&fd, &arch);
            let tokens = print.doc_function_tokens(&fd, &arch);
            let wide = host_text(&fd, &print.doc_function_markup(&fd, &arch));
            assert_eq!(wide.split('{').next().unwrap().lines()
                .filter(|line| !line.is_empty()).count(), 1, "{wide}");

            print.set_max_line_size(20).unwrap();
            print.set_indent_increment(4);
            print.set_markup(true);
            print.set_markup(false);
            let narrow = host_text(&fd, &print.doc_function_markup(&fd, &arch));
            assert_eq!(compact_c(&narrow), compact_c(&wide));
            let signature = narrow.split('{').next().unwrap();
            assert!(signature.lines().filter(|line| !line.is_empty()).count() > 1, "{narrow}");
            assert!(narrow.contains("\n    return 7;"), "{narrow}");
            assert_eq!(print.doc_function_full(&fd, &arch).split('{').next(),
                raw.split('{').next(), "host wrapping must not reach raw C");
            print.set_indent_increment(2);
            assert_eq!(print.doc_function_tokens(&fd, &arch), tokens);
            assert_eq!(print.doc_function_full(&fd, &arch), raw);

            print.reset_wire_option_defaults();
            let reset = host_text(&fd, &print.doc_function_markup(&fd, &arch));
            assert_eq!(reset, wide);
            assert!(print.set_max_line_size(19).is_err());
            assert!(print.set_max_line_size(10001).is_err());
            assert_eq!(host_text(&fd, &print.doc_function_markup(&fd, &arch)), wide);
            print.set_max_line_size(20).unwrap();
            assert!(print.set_line_comment_indent(20).is_err());
            assert!(print.set_line_comment_indent(-1).is_err());
            print.set_line_comment_indent(19).unwrap();
        }

}

mod host_field_metadata {
    use super::*;
    use crate::dtype::{DatatypeKind, TypeFactoryImpl, TypeField};
    use crate::prettyprint::ids;
    use kuna_base::marshal::{Decoder, PackedDecode};

    #[test]
    fn recovered_member_keeps_nominal_host_parent_and_byte_offset() {
        let types = TypeFactoryImpl::new();
        types.setup_sizes(Some(4), 8, 8);
        types.set_max_basetype_size(8);
        let scalar = types.get_base(8, type_metatype::TYPE_INT).unwrap();
        let mut draft = Datatype::new_with_align(16, 8, type_metatype::TYPE_STRUCT);
        draft.name = "Node".into();
        draft.display_name = draft.name.clone();
        draft.id = 72_057_594_037_927_936;
        draft.kind = DatatypeKind::Struct {
            field: vec![
                TypeField::new(0, 0, "first", scalar.clone()),
                TypeField::new(1, 8, "next", scalar.clone()),
            ],
            bitfield: vec![],
        };
        let node = decode_authored_record(&types, &draft);
        let alias = types.get_typedef(&node, "NodeAlias", 72_057_594_037_927_937, 0).unwrap();
        for (parent, expected_name, expected_id) in [
            (node, "Node", 72_057_594_037_927_936),
            (alias, "NodeAlias", 72_057_594_037_927_937),
        ] {
            let mut fd = build_fd();
            let op = mk_op(&mut fd, 1, 0x1000, OpCode::CPUI_COPY);
            let vn = fd.new_varnode(16, &Address::new(ram(&fd), 0x200), Some(parent.clone()));
            fd.op_set_input(op, vn, 0).unwrap();
            let arch = bare_arch();
            let mut print = PrintC::new();
            print.set_markup(true);
            print.emit_fd = Some(&fd as *const Funcdata);
            let document = print.emit_mut().begin_function();
            assert!(print.push_partial_symbol_ir(
                &fd, &arch, "node", parent, 8, 8, vn, op, 0, false,
            ));
            print.recurse();
            print.emit_mut().end_function(document);
            let bytes = print.emit_mut().take_markup_bytes();
            let mut decoder = PackedDecode::new(fd.get_arch().manage());
            decoder.ingest_stream(&bytes).unwrap();
            let root = decoder.open_element_id(&ids::ELEM_FUNCTION).unwrap();
            let mut members = Vec::new();
            while decoder.peek_element().unwrap() != 0 {
                let element = decoder.open_element().unwrap();
                if element == ids::ELEM_FIELD.get_id() {
                    members.push((
                        decoder.read_string_id(&ids::ATTRIB_CONTENT).unwrap(),
                        decoder.read_string_id(&ids::ATTRIB_NAME).unwrap(),
                        decoder.read_unsigned_integer_id(&ids::ATTRIB_ID).unwrap(),
                        decoder.read_signed_integer_id(&ids::ATTRIB_OFF).unwrap(),
                        decoder.read_unsigned_integer_id(&ids::ATTRIB_OPREF).unwrap(),
                    ));
                }
                decoder.close_element_skipping(element).unwrap();
            }
            decoder.close_element(root).unwrap();
            assert_eq!(members, vec![(
                b"next".to_vec(), expected_name.as_bytes().to_vec(), expected_id,
                8, fd.obank().get(op).unwrap().get_time() as u64,
            )]);
        }
    }
}
