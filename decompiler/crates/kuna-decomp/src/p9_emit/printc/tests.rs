//! Tests for the `PrintC` c-language token data and the self-contained
//! constant/type formatters (`printc.rs`).
//!
//! These exercise the part of `PrintC` that is faithfully ported now and is
//! print-fidelity-critical: the operator-token precedence/associativity table
//! (which drives `parentheses`), the negate cross-links, the keyword constants,
//! the byte-for-byte integer / float / char token strings, the generic
//! name builders, and the opcode→token dispatch — plus the `resetDefaultsPrintC`
//! defaults including the kuna `arraynotation` default-on.  The RPN/`Emit`
//! driver bodies are the W9 stub (see the module docs) and are not testable
//! until `prettyprint` lands.

use super::*;
use crate::printlanguage::{parentheses, ReversePolish};

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
        let model = ProtoModel::copy_named("__regparm3", fd.get_func_proto().model());
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
        let (mut fd, arch, _) = fixture();
        fd.set_display_name("outer::comments");
        let high = fd.high_bank().iter()
            .find(|(_, high)| high.kuna_name() == Some("value"))
            .map(|(id, _)| id).unwrap();
        let binding = fd.high_bank_mut().get_mut(high).unwrap();
        binding.set_kuna_name("kept_alias");
        binding.set_kuna_symbol_scope(vec!["inner".into(), "outer".into()]);
        binding.set_kuna_global(true);
        let mut printer = PrintC::new();
        for (strategy, spelling, function) in [
            (NamespaceStrategy::Minimal, "inner::kept_alias", "outer::comments"),
            (NamespaceStrategy::None, "kept_alias", "comments"),
            (NamespaceStrategy::All, "outer::inner::kept_alias", "outer::comments"),
            (NamespaceStrategy::Minimal, "inner::kept_alias", "outer::comments"),
        ] {
            printer.set_namespace_strategy(strategy);
            let text = printer.doc_function_full(&fd, &arch);
            assert!(text.contains(&format!("{function}(void)")), "{text}");
            assert!(text.lines().any(|line| line.trim() == format!("{spelling} = 7;")), "{text}");
        }
        assert_eq!(fd.high_bank().get(high).unwrap().kuna_name(), Some("kept_alias"));
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
            printer.set_comment_style(style).unwrap();
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
        let (fd, mut arch, address) = fixture();
        arch.commentdb.add_comment(ct::USER2, fd.get_address(), &address,
            "first\nsecond */\nthird\\");
        let mut printer = PrintC::new();
        printer.set_line_comment_indent(6).unwrap();
        printer.set_comment_style("cplusplus").unwrap();
        let cpp = printer.doc_function_full(&fd, &arch);
        assert!(cpp.contains("\n      // first\n      // second */\n      // third\\ //"), "{cpp}");
        assert!(printer.set_comment_style("unknown").is_err());
        assert_eq!(printer.doc_function_full(&fd, &arch), cpp);
        printer.set_comment_style("/*").unwrap();
        let c = printer.doc_function_full(&fd, &arch);
        assert!(c.contains("\n      /* first\n         second * /\n         third\\ */"), "{c}");
        printer.context.reset_defaults_internal();
        printer.set_comment_style("//").unwrap();
        let reset = printer.doc_function_full(&fd, &arch);
        assert!(reset.contains(&format!("\n{}// first", " ".repeat(20))), "{reset}");
        printer.context.reset_defaults_internal();
        let default = printer.doc_function_full(&fd, &arch);
        assert!(default.contains(&format!("\n{}/* first", " ".repeat(20))), "{default}");
    }
}

#[test]
fn case_labels_without_ops_keep_their_numeric_value() {
    let mut print = PrintC::new();
    print.set_output_stream();

    print.emit_numeric_case_label(0xff, 1, false, None);
    print.emit_numeric_case_label(0xff, 1, true, None);

    let output = print.emit_mut().output_str();
    assert_eq!(output, "\ncase 0xff:\ncase -1:");
    assert!(!output.contains("case :"));
}

#[test]
fn ordinary_and_default_case_labels_are_unchanged() {
    let mut print = PrintC::new();
    print.set_output_stream();

    print.emit_numeric_case_label(0xff, 1, false, Some(OpId::default()));
    print.emit_default_case_label(0, &MarkupRef::none());

    assert_eq!(print.emit_mut().output_str(), "\ncase 0xff:\ndefault:");
}

/// `option indentincrement` lives on the emitter leaf, and a markup render
/// swaps the leaf twice: the setting must survive both swaps.
#[test]
fn switching_markup_keeps_the_indent_increment() {
    let mut print = PrintC::new();
    print.set_indent_increment(4);
    print.set_markup(true);
    assert_eq!(print.emit_mut().get_indent_increment(), 4);
    print.set_markup(false);
    assert_eq!(print.emit_mut().get_indent_increment(), 4);
}

#[test]
fn case_label_without_an_op_survives_markup_without_fabricated_provenance() {
    let mut print = PrintC::new();
    print.set_markup(true);

    print.emit_numeric_case_label(0xff, 1, false, None);

    let bytes = print.emit_mut().take_markup_bytes();
    for token in [b"case".as_slice(), b"0xff".as_slice(), b":".as_slice()] {
        assert!(bytes.windows(token.len()).any(|window| window == token));
    }
    assert!(print.emit_mut().take_markup_provenance().associations.is_empty());
}

mod stack_pointer_high_leaf {
    use super::*;
    use crate::context::ArchContext;
    use crate::dtype::{type_metatype, Datatype};
    use crate::funcdata::Funcdata;
    use kuna_base::address::Address;
    use kuna_base::error::{KunaError, KunaResult};
    use kuna_base::space::{
        addrspace_flags, spacetype, AddrSpace, AddrSpaceManager, ConstantSpace, UniqueSpace,
    };
    use kuna_sleigh::globalcontext::ContextInternal;
    use kuna_sleigh::loadimage::LoadImage;
    use kuna_sleigh::sleigh::Sleigh;
    use std::rc::Rc;

    struct DummyImg;
    impl LoadImage for DummyImg {
        fn get_file_name(&self) -> &str {
            "dummy"
        }
        fn load_fill(&mut self, _ptr: &mut [u8], _addr: &Address) -> KunaResult<()> {
            Err(KunaError::data_unavail("dummy"))
        }
        fn get_arch_type(&self) -> Vec<u8> {
            Vec::new()
        }
        fn adjust_vma(&mut self, _adjust: i64) {}
    }

    fn bare_arch() -> crate::architecture::Architecture {
        crate::architecture::Architecture::new(
            "t",
            Sleigh::new(Box::new(DummyImg), Box::new(ContextInternal::new())),
        )
    }

    fn build_fd() -> (Funcdata, Rc<AddrSpace>) {
        let mut manage = AddrSpaceManager::new();
        manage.insert_space(Rc::new(ConstantSpace::new())).unwrap();
        manage.insert_space(Rc::new(UniqueSpace::new(1, 0, false))).unwrap();
        let ram = Rc::new(AddrSpace::new(
            spacetype::IPTR_PROCESSOR,
            "ram",
            false,
            8,
            1,
            2,
            addrspace_flags::hasphysical,
            1,
            1,
        ));
        manage.insert_space(Rc::clone(&ram)).unwrap();
        let register = Rc::new(AddrSpace::new(
            spacetype::IPTR_PROCESSOR,
            "register",
            false,
            8,
            1,
            3,
            addrspace_flags::hasphysical,
            1,
            1,
        ));
        manage.insert_space(Rc::clone(&register)).unwrap();
        let glb = Rc::new(ArchContext::new(manage));
        let fd =
            Funcdata::new("f", "f", glb, Address::new(ram, 0x1000), 0x1000, 0x20).unwrap();
        (fd, register)
    }

    fn unknown8() -> crate::dtype::TypeRoot {
        use crate::dtype::TypeFactoryImpl;
        TypeFactoryImpl::new().intern(Datatype::new(8, type_metatype::TYPE_UNKNOWN)).unwrap()
    }

    fn merge_highs(fd: &mut Funcdata, first: VarnodeId, rest: &[VarnodeId]) {
        fd.set_high_level();
        let first_high = fd.vbank().get(first).unwrap().get_high().unwrap();
        for &vn in rest {
            let other = fd.vbank().get(vn).unwrap().get_high().unwrap();
            let mut writes = Vec::new();
            fd.with_high_split(|bank, ctx| {
                bank.merge_internal(first_high, other, false, ctx, &mut |vn, high, group| {
                    writes.push((vn, high, group));
                })
            })
            .unwrap();
            for (vn, high, group) in writes {
                fd.vbank_mut().get_mut(vn).unwrap().set_high(high, group);
            }
        }
    }

    fn render_leaf(fd: &Funcdata, vn: VarnodeId, op: OpId) -> String {
        let mut print = PrintC::new();
        print.set_output_stream();
        print.push_vn_explicit_ir(fd, &bare_arch(), vn, op);
        print.emit_mut().output_str().to_string()
    }

    #[test]
    fn direct_callee_name_is_reserved_before_local_suffix_allocation() {
        let (mut fd, register) = build_fd();
        let op = fd.new_op(1, Address::new(Rc::clone(&register), 0x1000));
        let entry = Address::new(register, 0x2000);
        let mut call = crate::fspec::FuncCallSpecs::new(op, entry.clone());
        call.set_funcdata(entry, "callee_1").unwrap();
        fd.push_call_specs(call);

        let occupied = declaration_occupied_names(&fd, vec!["param_1".to_string()]);
        assert!(occupied.iter().any(|name| name == "callee_1"));

        let mut allocator = crate::kuna_dedupvardecls::DeclNameUniquifier::new(
            ["callee", "callee"],
            occupied.iter().map(String::as_str),
        );
        assert_eq!(allocator.unique("callee"), "callee");
        assert_eq!(allocator.unique("callee"), "callee_2");
    }

    #[test]
    fn merged_unaffected_input_stack_pointer_canonicalizes_every_member() {
        let (mut fd, register) = build_fd();
        let sp = fd.new_varnode(8, &Address::new(Rc::clone(&register), 0), Some(unknown8()));
        let sp = fd.set_input_varnode(sp).unwrap();
        {
            let sp = fd.vbank_mut().get_mut(sp).unwrap();
            sp.set_spacebase();
            sp.set_unaffected();
        }
        let scratch_register = fd.new_varnode(
            8,
            &Address::new(Rc::clone(&register), 0x20),
            Some(unknown8()),
        );
        let scratch_unique = fd.new_unique(8, Some(unknown8()));
        merge_highs(&mut fd, sp, &[scratch_register, scratch_unique]);
        let high = fd.vbank().get(sp).unwrap().get_high();
        assert_eq!(fd.vbank().get(scratch_register).unwrap().get_high(), high);
        assert_eq!(fd.vbank().get(scratch_unique).unwrap().get_high(), high);
        let op = fd.new_op(0, Address::new(register, 0x1000));

        for vn in [sp, scratch_register, scratch_unique] {
            assert_eq!(render_leaf(&fd, vn, op), "Register0000000000000000");
        }
    }

    #[test]
    fn input_spacebase_without_unaffected_flag_does_not_canonicalize_high() {
        let (mut fd, register) = build_fd();
        let sp = fd.new_varnode(8, &Address::new(Rc::clone(&register), 0), Some(unknown8()));
        let sp = fd.set_input_varnode(sp).unwrap();
        fd.vbank_mut().get_mut(sp).unwrap().set_spacebase();
        let scratch_unique = fd.new_unique(8, Some(unknown8()));
        let unique_name = {
            let v = fd.vbank().get(scratch_unique).unwrap();
            kuna_storage_location_name(v.get_addr()).unwrap()
        };
        merge_highs(&mut fd, sp, &[scratch_unique]);
        assert_eq!(
            fd.vbank().get(sp).unwrap().get_high(),
            fd.vbank().get(scratch_unique).unwrap().get_high()
        );
        let op = fd.new_op(0, Address::new(register, 0x1000));

        assert_eq!(render_leaf(&fd, scratch_unique, op), unique_name);
        assert!(unique_name.starts_with("Unique"));
    }

    #[test]
    fn constant_symbol_reference_is_not_a_scalar_whole_storage_sibling() {
        let (mut fd, register) = build_fd();
        let partial = fd.new_varnode(
            4,
            &Address::new(Rc::clone(&register), 0x20),
            Some({
                use crate::dtype::TypeFactoryImpl;
                TypeFactoryImpl::new().intern(Datatype::new(4, type_metatype::TYPE_UNKNOWN)).unwrap()
            }),
        );
        let reference = fd.new_constant(8, 0xffff_ffff_ffff_fff0);
        let whole = fd.new_varnode(
            8,
            &Address::new(register, 0x28),
            Some(unknown8()),
        );
        fd.set_high_level();

        let partial_high = fd.vbank().get(partial).unwrap().get_high().unwrap();
        let reference_high = fd.vbank().get(reference).unwrap().get_high().unwrap();
        let whole_high = fd.vbank().get(whole).unwrap().get_high().unwrap();
        for high in [partial_high, reference_high] {
            let h = fd.high_bank_mut().get_mut(high).unwrap();
            h.set_kuna_name("local");
            h.set_symbol_type(unknown8());
            h.set_symbol_offset(0);
        }

        assert!(!high_name_has_scalar_whole_sibling(
            &fd,
            partial_high,
            "local"
        ));

        let h = fd.high_bank_mut().get_mut(whole_high).unwrap();
        h.set_kuna_name("local");
        h.set_symbol_type(unknown8());
        h.set_symbol_offset(0);
        assert!(high_name_has_scalar_whole_sibling(
            &fd,
            partial_high,
            "local"
        ));
    }
}

fn rpn(tok: &'static OpToken, visited: int4) -> ReversePolish {
    ReversePolish { tok, visited, paren: false, op: None, id: 0, id2: 0 }
}

// ===========================================================================
// VERIFIER (w10-input-prototype) adversarial tests for `declarator_parts`
// (the C-declarator builder transcribing buildTypeStack / pushTypeStart /
// pushTypeEnd). These probe the fragile pure logic: base/anonymous naming,
// pointer-front vs array-tail placement, and the ptr-inside-array
// parenthesisation the RPN ptr_expr/array_expr tokens encode.
// ===========================================================================
mod w10_input_prototype_declarator {
    use crate::dtype::{type_metatype, Datatype, DatatypeKind, TypeFactory, TypeFactoryImpl, TypeRoot};
    use crate::printc::declarator_parts;

    fn named(types: &TypeFactoryImpl, size: i32, m: type_metatype, nm: &str) -> TypeRoot {
        // C++ TypeBase sets displayName = name; mirror that (declarator_parts
        // reads get_display_name() for the base but get_name() for the
        // base-detection loop — both must be the identifier).
        let mut t = Datatype::new_with_align(size, -1, m);
        t.name = nm.to_string();
        t.display_name = nm.to_string();
        t.id = Datatype::hash_name(nm);
        types.intern(t).unwrap()
    }

    fn ptr_to(types: &TypeFactoryImpl, ptrto: TypeRoot) -> TypeRoot {
        let mut p = Datatype::new_with_align(8, -1, type_metatype::TYPE_PTR);
        p.kind = DatatypeKind::Pointer { ptrto: ptrto.id(), spaceid: None, truncate: None, wordsize: 1 };
        types.intern(p).unwrap()
    }

    fn array_of(types: &TypeFactoryImpl, arrayof: TypeRoot, n: i32) -> TypeRoot {
        let elt = arrayof.get_size().max(1);
        let mut a = Datatype::new_with_align(elt * n, -1, type_metatype::TYPE_ARRAY);
        a.kind = DatatypeKind::Array { arrayof: arrayof.id(), arraysize: n };
        types.intern(a).unwrap()
    }

    /// A bare named base type renders `("<name>", "")` with no trailing space
    /// (the caller adds the space before the identifier).  This is the
    /// `noident && typestack.size()==1` -> type_expr_nospace path.
    #[test]
    fn base_type_no_modifier() {
        let types = TypeFactoryImpl::new();
        let t = named(&types, 8, type_metatype::TYPE_INT, "int8");
        assert_eq!(
            declarator_parts(&t, crate::printc::RealTypeCtx::OFF),
            ("int8".to_string(), String::new())
        );
    }

    /// A pointer puts a `*` on the front glued to the base name with a single
    /// space: `("twostruct *", "")` -> `twostruct *ptr`.  The `want_space`
    /// caller suppresses a second space after `*`.
    #[test]
    fn pointer_front_star() {
        let types = TypeFactoryImpl::new();
        let base = types.reserve(
            "twostruct", Datatype::hash_name("twostruct"), type_metatype::TYPE_STRUCT,
        ).unwrap();
        let p = ptr_to(&types, base);
        assert_eq!(
            declarator_parts(&p, crate::printc::RealTypeCtx::OFF),
            ("twostruct *".to_string(), String::new())
        );
    }

    /// An array goes on the tail: `int4[4]` -> `("int4", "[4]")` -> `int4 a[4]`.
    /// No parenthesisation since there is no pending pointer.
    #[test]
    fn array_tail_no_paren() {
        let types = TypeFactoryImpl::new();
        let base = named(&types, 4, type_metatype::TYPE_INT, "int4");
        let a = array_of(&types, base, 4);
        assert_eq!(
            declarator_parts(&a, crate::printc::RealTypeCtx::OFF),
            ("int4".to_string(), "[4]".to_string())
        );
    }

    /// Pointer-to-array and array-of-pointer are mirror types in C: the former
    /// groups the pointer before applying the array suffix, while the latter
    /// lets `[]` bind directly to the identifier.  This reached ordinary cast
    /// output as invalid `*(char *[16])` for a pointer to a SIMD-sized array.
    #[test]
    fn pointer_to_array_parentheses_follow_c_precedence() {
        let types = TypeFactoryImpl::new();
        let base = named(&types, 4, type_metatype::TYPE_INT, "int4");
        // pointer-to-array int4 (*)[1]
        let pta = ptr_to(&types, array_of(&types, base.clone(), 1));
        assert_eq!(
            declarator_parts(&pta, crate::printc::RealTypeCtx::OFF),
            ("int4 (*".to_string(), ")[1]".to_string())
        );
        // array-of-pointer int4 *[1]
        let aop = array_of(&types, ptr_to(&types, base), 1);
        assert_eq!(
            declarator_parts(&aop, crate::printc::RealTypeCtx::OFF),
            ("int4 *".to_string(), "[1]".to_string())
        );
    }

    /// Alternating modifiers require grouping the entire declarator already
    /// accumulated, not just moving one close-parenthesis ahead of the first
    /// array suffix.  These are the two three-modifier mirror cases that a
    /// one-level pointer/array fix can accidentally corrupt.
    #[test]
    fn nested_pointer_array_parentheses_group_the_complete_declarator() {
        let types = TypeFactoryImpl::new();
        let base = named(&types, 4, type_metatype::TYPE_INT, "int4");

        // pointer to array[2] of pointer to int4: int4 *(*x)[2]
        let pointer_to_array_of_pointer = ptr_to(&types, array_of(&types, ptr_to(&types, base.clone()), 2));
        assert_eq!(
            declarator_parts(
                &pointer_to_array_of_pointer,
                crate::printc::RealTypeCtx::OFF
            ),
            ("int4 *(*".to_string(), ")[2]".to_string())
        );

        // array[2] of pointer to array[3] of int4: int4 (*x[2])[3]
        let array_of_pointer_to_array = array_of(&types, ptr_to(&types, array_of(&types, base, 3)), 2);
        assert_eq!(
            declarator_parts(&array_of_pointer_to_array, crate::printc::RealTypeCtx::OFF),
            ("int4 (*".to_string(), "[2])[3]".to_string())
        );
    }

    /// A declaration's type position (locals, array elements, return types) keeps
    /// the suffix a pointer to an array needs after the name. With only the front
    /// half, a local printed `int4 (*v1;` and a return type `int4 (* f(void)`.
    #[test]
    fn declaration_type_position_keeps_the_pointer_to_array_suffix() {
        use crate::printc::{array_decl_parts, type_name_for_decl, RealTypeCtx};

        let types = TypeFactoryImpl::new();
        let base = named(&types, 4, type_metatype::TYPE_INT, "int4");
        let rt = RealTypeCtx::OFF;
        let parts = |front: &str, back: &str| (front.to_string(), back.to_string());

        assert_eq!(
            type_name_for_decl(&ptr_to(&types, array_of(&types, base.clone(), 16)), rt),
            parts("int4 (*", ")[16]")
        );
        assert_eq!(
            type_name_for_decl(&ptr_to(&types, array_of(&types, ptr_to(&types, base.clone()), 3)), rt),
            parts("int4 *(*", ")[3]")
        );
        // array[2] of pointer to array[16]: `int4 (*x [2])[16]`
        assert_eq!(
            array_decl_parts(&array_of(&types, ptr_to(&types, array_of(&types, base.clone(), 16)), 2), rt, false)
                .map(|((front, back), count)| ((front.text, back.text), count)),
            Some((parts("int4 (*", ")[16]"), 2))
        );

        // Near-misses carry no suffix: a named base, a plain pointer, and an array
        // of pointers.
        assert_eq!(type_name_for_decl(&base, rt), parts("int4", ""));
        assert_eq!(type_name_for_decl(&ptr_to(&types, ptr_to(&types, base.clone())), rt), parts("int4 **", ""));
        assert_eq!(
            array_decl_parts(&array_of(&types, ptr_to(&types, base), 5), rt, false)
                .map(|((front, back), count)| ((front.text, back.text), count)),
            Some((parts("int4 *", ""), 5))
        );
    }

    /// Exact exported-type regressions found by the 253-binary differential.
    /// These are abstract declarators (`front + back`, with no identifier), so
    /// they exercise the same spelling consumed by JSON variable metadata.
    #[test]
    fn corpus_exported_type_strings_preserve_modifier_order() {
        fn abstract_spelling(dt: &TypeRoot) -> String {
            let (front, back) = declarator_parts(dt, crate::printc::RealTypeCtx::OFF);
            format!("{front}{back}")
        }

        let types = TypeFactoryImpl::new();
        let char_ty = named(&types, 1, type_metatype::TYPE_INT, "char");
        let uchar_ty = named(&types, 1, type_metatype::TYPE_UINT, "unsigned char");

        // arraycoverwidth_x86_64::vm v3: outer [2], inner [16].
        assert_eq!(
            abstract_spelling(&array_of(&types, array_of(&types, char_ty.clone(), 16), 2)),
            "char[2][16]"
        );
        // katavm_level1_x86_64::sub_12d0 v32 and ptx.o's v16 are
        // arrays of pointers, not pointers to arrays.
        assert_eq!(
            abstract_spelling(&array_of(&types, ptr_to(&types, uchar_ty), 2)),
            "unsigned char *[2]"
        );
        assert_eq!(
            abstract_spelling(&array_of(&types, ptr_to(&types, char_ty.clone()), 5)),
            "char *[5]"
        );
        // structreturn_x86_64::passthru param_1 is the mirror type.
        assert_eq!(
            abstract_spelling(&ptr_to(&types, array_of(&types, char_ty, 16))),
            "char (*)[16]"
        );
    }

    /// An anonymous base type with no name falls back to genericTypeName:
    /// TYPE_VOID -> "void", else "undefined<size>".  A pointer to an anonymous
    /// 4-byte type renders `undefined4 *`.
    #[test]
    fn anonymous_base_generic_name() {
        let types = TypeFactoryImpl::new();
        let anon = types.intern(Datatype::new_with_align(4, -1, type_metatype::TYPE_UNKNOWN)).unwrap();
        let p = ptr_to(&types, anon);
        assert_eq!(
            declarator_parts(&p, crate::printc::RealTypeCtx::OFF),
            ("undefined4 *".to_string(), String::new())
        );
        let v = types.intern(Datatype::new_with_align(0, 1, type_metatype::TYPE_VOID)).unwrap();
        assert_eq!(
            declarator_parts(&v, crate::printc::RealTypeCtx::OFF),
            ("void".to_string(), String::new())
        );
    }

    /// Pointer-to-pointer keeps both stars on the front, no parens:
    /// `char **` -> `("char **", "")`.
    #[test]
    fn pointer_to_pointer() {
        let types = TypeFactoryImpl::new();
        let base = named(&types, 1, type_metatype::TYPE_INT, "char");
        let pp = ptr_to(&types, ptr_to(&types, base));
        assert_eq!(
            declarator_parts(&pp, crate::printc::RealTypeCtx::OFF),
            ("char **".to_string(), String::new())
        );
    }

    /// (kuna DIV-6) With the `realtypes` context ON, a residual TYPE_UNKNOWN base
    /// is relabelled to a real C type by size, under a pointer as well as as a
    /// scalar, so the declared pointee keeps the width the index/cast expressions
    /// were built from.  Sizes with no natural single C type keep `undefined<N>`
    /// (and degrade to `void` only under a pointer).
    #[test]
    fn realtypes_relabels_unknown_bases() {
        let on = crate::printc::RealTypeCtx { enabled: true, long_is_8: true, ..crate::printc::RealTypeCtx::OFF };
        let types = TypeFactoryImpl::new();
        let unk = |sz: i32| types.intern(Datatype::new_with_align(sz, -1, type_metatype::TYPE_UNKNOWN)).unwrap();
        // Scalars: 1->char, 2->unsigned short, 4->unsigned int, 8->unsigned long.
        assert_eq!(declarator_parts(&unk(1), on).0, "char");
        assert_eq!(declarator_parts(&unk(2), on).0, "unsigned short");
        assert_eq!(declarator_parts(&unk(4), on).0, "unsigned int");
        assert_eq!(declarator_parts(&unk(8), on).0, "unsigned long");
        // LLP64: 8-byte unknown reads `unsigned long long` when long is 4 bytes.
        let llp64 = crate::printc::RealTypeCtx { enabled: true, long_is_8: false, ..crate::printc::RealTypeCtx::OFF };
        assert_eq!(declarator_parts(&unk(8), llp64).0, "unsigned long long");
        // Odd size keeps the placeholder.
        assert_eq!(declarator_parts(&unk(3), on).0, "undefined3");
        // Pointer-to-unknown relabels the pointee through the same size table, so
        // the declared stride matches the one `opLoad`/`opPtradd` index with.
        assert_eq!(
            declarator_parts(&ptr_to(&types, unk(8)), on),
            ("unsigned long *".to_string(), String::new())
        );
        assert_eq!(
            declarator_parts(&ptr_to(&types, unk(4)), on),
            ("unsigned int *".to_string(), String::new())
        );
        assert_eq!(
            declarator_parts(&ptr_to(&types, ptr_to(&types, unk(1))), on),
            ("char **".to_string(), String::new())
        );
        // Only a residual size with no natural C type degrades to `void` under a
        // pointer (as a scalar it still keeps the placeholder).
        assert_eq!(declarator_parts(&ptr_to(&types, unk(3)), on), ("void *".to_string(), String::new()));
        // Array of unknown -> `char [8]` (element relabelled, count preserved).
        assert_eq!(declarator_parts(&array_of(&types, unk(1), 8), on), ("char".to_string(), "[8]".to_string()));
        // Gate OFF leaves the placeholder untouched.
        assert_eq!(declarator_parts(&unk(4), crate::printc::RealTypeCtx::OFF).0, "undefined4");
    }

    /// (kuna DIV-6) A genuine `TYPE_VOID` pointee is not a residual unknown, so the
    /// relabel never sees it: `free(void *)` / `memcpy(void *, ...)` keep their
    /// opaque `void *` with the gate ON exactly as with it OFF.
    #[test]
    fn realtypes_keeps_genuine_void_pointers() {
        let on = crate::printc::RealTypeCtx { enabled: true, long_is_8: true, ..crate::printc::RealTypeCtx::OFF };
        let types = TypeFactoryImpl::new();
        let void = || types.intern(Datatype::new_with_align(0, 1, type_metatype::TYPE_VOID)).unwrap();
        for rt in [on, crate::printc::RealTypeCtx::OFF] {
            assert_eq!(declarator_parts(&void(), rt), ("void".to_string(), String::new()));
            assert_eq!(declarator_parts(&ptr_to(&types, void()), rt), ("void *".to_string(), String::new()));
            assert_eq!(
                declarator_parts(&ptr_to(&types, ptr_to(&types, void())), rt),
                ("void **".to_string(), String::new())
            );
        }
    }
}

// ===========================================================================
// (kuna decompile-project) `doc_type_definitions` pure renderers —
// `compose_type_body` / `compose_enum_body` / `render_type_definitions` /
// `sanitize_type_name` over hand-built Datatypes + `RealTypeCtx::OFF` (the
// same pattern as `w10_input_prototype_declarator` above).
// ===========================================================================
mod decompile_project_type_render {
    use crate::dtype::{flags, type_metatype, Datatype, DatatypeKind, TypeField, TypeFactory, TypeFactoryImpl, TypeRoot};
    use crate::printc::{
        compose_enum_body, compose_type_body, render_type_definitions, sanitize_type_name,
        RealTypeCtx,
    };
    fn named(types: &TypeFactoryImpl, size: i32, m: type_metatype, nm: &str) -> TypeRoot {
        let mut t = Datatype::new_with_align(size, -1, m);
        t.name = nm.to_string();
        t.display_name = nm.to_string();
        t.id = Datatype::hash_name(nm);
        types.intern(t).unwrap()
    }

    fn ptr_to(types: &TypeFactoryImpl, ptrto: TypeRoot) -> TypeRoot {
        let mut p = Datatype::new_with_align(8, -1, type_metatype::TYPE_PTR);
        p.kind = DatatypeKind::Pointer { ptrto: ptrto.id(), spaceid: None, truncate: None, wordsize: 1 };
        types.intern(p).unwrap()
    }

    fn array_of(types: &TypeFactoryImpl, arrayof: TypeRoot, n: i32) -> TypeRoot {
        let elt = arrayof.get_size().max(1);
        let mut a = Datatype::new_with_align(elt * n, -1, type_metatype::TYPE_ARRAY);
        a.kind = DatatypeKind::Array { arrayof: arrayof.id(), arraysize: n };
        types.intern(a).unwrap()
    }

    /// A complete named struct with the given (offset, name, type) fields and
    /// total size.
    fn struct_of(types: &TypeFactoryImpl, nm: &str, size: i32, fields: &[(i32, &str, TypeRoot)]) -> TypeRoot {
        let mut s = Datatype::new_with_align(size, -1, type_metatype::TYPE_STRUCT);
        s.name = nm.to_string();
        s.display_name = nm.to_string();
        s.id = Datatype::hash_name(nm);
        s.kind = DatatypeKind::Struct {
            field: fields
                .iter()
                .enumerate()
                .map(|(i, (off, fnm, ft))| TypeField::new(i as i32, *off, *fnm, ft.id()))
                .collect(),
            bitfield: vec![],
        };
        types.intern(s).unwrap()
    }

    fn make_enum(types: &TypeFactoryImpl, nm: &str, size: i32, m: type_metatype, entries: &[(u64, &str)]) -> TypeRoot {
        let mut dt = Datatype::new_with_align(size, size, m);
        dt.name = nm.to_string();
        dt.display_name = nm.to_string();
        dt.id = Datatype::hash_name(nm);
        dt.flags |= flags::enumtype;
        let mut namemap = std::collections::BTreeMap::new();
        for (v, n) in entries {
            namemap.insert(*v, (*n).to_string());
        }
        dt.kind = DatatypeKind::Enum { namemap };
        types.intern(dt).unwrap()
    }

    /// Struct body with a scalar, a pointer, an array, an interior padding gap
    /// AND trailing padding: every member/padding shape at once.
    #[test]
    fn struct_body_scalar_pointer_array_gap_trailing_pad() {
        let types = TypeFactoryImpl::new();
        let i4 = named(&types, 4, type_metatype::TYPE_INT, "int4");
        let ch = named(&types, 1, type_metatype::TYPE_INT, "char");
        // struct mystruct { int4 a@0; <gap 4>; char *p@8; int4 arr[4]@16;
        //                   <trailing pad 8> } size 40.
        let s = struct_of(
            &types,
            "mystruct",
            40,
            &[
                (0, "a", i4.clone()),
                (8, "p", ptr_to(&types, ch)),
                (16, "arr", array_of(&types, i4, 4)),
            ],
        );
        let body = compose_type_body(&s, "mystruct", RealTypeCtx::OFF);
        assert_eq!(
            body,
            "struct mystruct {\n\
             \x20   int4 a;\n\
             \x20   undefined1 _pad4[4];\n\
             \x20   char *p;\n\
             \x20   int4 arr[4];\n\
             \x20   undefined1 _pad20[8];\n\
             };\n",
            "struct body: scalar + gap pad + glued pointer + array tail + trailing pad"
        );
    }

    /// Union body: every field at offset 0, NO padding members.
    #[test]
    fn union_body_no_padding() {
        let types = TypeFactoryImpl::new();
        let i4 = named(&types, 4, type_metatype::TYPE_INT, "int4");
        let f8 = named(&types, 8, type_metatype::TYPE_FLOAT, "float8");
        let mut u = Datatype::new_with_align(8, -1, type_metatype::TYPE_UNION);
        u.name = "myunion".to_string();
        u.display_name = "myunion".to_string();
        u.id = Datatype::hash_name("myunion");
        u.kind = DatatypeKind::Union {
            field: vec![
                TypeField::new(0, 0, "as_int", i4.id()),
                TypeField::new(1, 0, "as_float", f8.id()),
            ],
        };
        let u = types.intern(u).unwrap();
        let body = compose_type_body(&u, "myunion", RealTypeCtx::OFF);
        assert_eq!(
            body,
            "union myunion {\n\
             \x20   int4 as_int;\n\
             \x20   float8 as_float;\n\
             };\n"
        );
        assert!(!body.contains("_pad"), "unions carry no padding members");
    }

    /// Enum values: the TYPE_INT (decode-time TYPE_ENUM_INT) form prints
    /// SIGNED decimal sign-extended by the enum size; the TYPE_UINT form hex.
    #[test]
    fn enum_signed_and_unsigned_value_forms() {
        let types = TypeFactoryImpl::new();
        // Signed 4-byte enum: 0xffffffff sign-extends to -1.
        let se = make_enum(
            &types,
            "serrs",
            4,
            type_metatype::TYPE_INT,
            &[(0, "OK"), (0xffff_ffff, "FAIL")],
        );
        let body = compose_enum_body(&se, "serrs");
        assert_eq!(
            body,
            "typedef enum serrs {\n\
             \x20   OK = 0,\n\
             \x20   FAIL = -1\n\
             } serrs;\n"
        );
        // Unsigned 4-byte enum: hex values.
        let ue = make_enum(
            &types,
            "uflags",
            4,
            type_metatype::TYPE_UINT,
            &[(0x1, "LO"), (0x80, "HI")],
        );
        let body = compose_enum_body(&ue, "uflags");
        assert_eq!(
            body,
            "typedef enum uflags {\n\
             \x20   LO = 0x1,\n\
             \x20   HI = 0x80\n\
             } uflags;\n"
        );
    }

    /// A typedef renders through the declarator builder; a plain scalar
    /// typedef and a pointer typedef both lay out correctly.
    #[test]
    fn typedef_renders_via_declarator() {
        let types = TypeFactoryImpl::new();
        let i4 = named(&types, 4, type_metatype::TYPE_INT, "int4");
        let td = {
            let mut t = Datatype::new_with_align(4, -1, type_metatype::TYPE_INT);
            t.kind = DatatypeKind::Alias;
            t.name = "myint".to_string();
            t.display_name = "myint".to_string();
            t.id = Datatype::hash_name("myint");
            t.typedef_imm = Some(i4.id());
            types.intern(t).unwrap()
        };
        let out = render_type_definitions(&[i4.clone(), td.clone()], RealTypeCtx::OFF);
        assert!(
            out.contains("typedef int4 myint;\n"),
            "scalar typedef line missing:\n{out}"
        );
        // Pointer typedef: `typedef char *mystr;` (the `*` glues to the name).
        let ch = named(&types, 1, type_metatype::TYPE_INT, "char");
        let pstr = ptr_to(&types, ch);
        let tdp = {
            let mut t = Datatype::new_with_align(8, -1, type_metatype::TYPE_PTR);
            t.kind = DatatypeKind::Alias;
            t.name = "mystr".to_string();
            t.display_name = "mystr".to_string();
            t.id = Datatype::hash_name("mystr");
            t.typedef_imm = Some(pstr.id());
            types.intern(t).unwrap()
        };
        let out = render_type_definitions(&[tdp], RealTypeCtx::OFF);
        assert!(
            out.contains("typedef char *mystr;\n"),
            "pointer typedef line missing:\n{out}"
        );
    }

    /// An INCOMPLETE struct emits ONLY the forward declaration, annotated
    /// `/* opaque */` — never a body.  A complete struct gets forward decl
    /// (un-annotated) FIRST, then its body.
    #[test]
    fn incomplete_struct_forward_decl_only() {
        let types = TypeFactoryImpl::new();
        let i4 = named(&types, 4, type_metatype::TYPE_INT, "int4");
        let complete = struct_of(&types, "solid", 4, &[(0, "a", i4)]);
        let opaque = types.reserve("mystery", Datatype::hash_name("mystery"), type_metatype::TYPE_STRUCT).unwrap();
        let out =
            render_type_definitions(&[opaque.clone(), complete.clone()], RealTypeCtx::OFF);
        assert!(
            out.contains("typedef struct mystery mystery; /* opaque */\n"),
            "opaque forward decl missing:\n{out}"
        );
        assert!(!out.contains("struct mystery {"), "opaque struct must have NO body:\n{out}");
        assert!(
            out.contains("typedef struct solid solid;\n"),
            "complete struct forward decl missing (and must not be /* opaque */):\n{out}"
        );
        assert!(out.contains("struct solid {"), "complete struct body missing:\n{out}");
        // Forward-decl block precedes ALL bodies (the self-reference guarantee).
        let fwd_pos = out.find("typedef struct solid").unwrap();
        let body_pos = out.find("struct solid {").unwrap();
        assert!(fwd_pos < body_pos, "forward declarations must precede bodies:\n{out}");
    }

    /// Name sanitisation: non-identifier characters become `_` (with the
    /// `/* renamed from … */` note); a digit-first name gains a `_` prefix.
    #[test]
    fn sanitize_type_names() {
        assert_eq!(sanitize_type_name("good_Name2"), "good_Name2");
        assert!(matches!(
            sanitize_type_name("good_Name2"),
            std::borrow::Cow::Borrowed(_)
        ));
        assert_eq!(sanitize_type_name("bad-name$1"), "bad_name_1");
        assert_eq!(sanitize_type_name("9lives"), "_9lives");
        assert_eq!(sanitize_type_name("std::vector<int>"), "std__vector_int_");

        let types = TypeFactoryImpl::new();
        let i4 = named(&types, 4, type_metatype::TYPE_INT, "int4");
        let s = struct_of(&types, "bad-name$1", 4, &[(0, "a", i4)]);
        let out = render_type_definitions(&[s], RealTypeCtx::OFF);
        assert!(
            out.contains(
                "typedef struct bad_name_1 bad_name_1; /* renamed from \"bad-name$1\" */"
            ),
            "renamed forward decl missing:\n{out}"
        );
        assert!(out.contains("struct bad_name_1 {"), "renamed body missing:\n{out}");
    }

    /// (GH-340) The `/* renamed from "…" */` note quotes the RAW type name, which
    /// is unvalidated binary data: a `*/` in it closed the comment early and a
    /// newline split it in two, re-opening in a comment exactly the hole
    /// `sanitize_type_name` closes in the identifier. The note escapes what it
    /// quotes, and nothing that could not break a comment is touched.
    #[test]
    fn renamed_from_note_cannot_be_escaped_by_the_raw_name() {
        let types = TypeFactoryImpl::new();
        let i4 = named(&types, 4, type_metatype::TYPE_INT, "int4");
        for raw in ["ev*/il", "ev\nil", "ev/*il"] {
            let out = render_type_definitions(
                &[struct_of(&types, raw, 4, &[(0, "a", i4.clone())])],
                RealTypeCtx::OFF,
            );
            for line in out.lines().filter(|l| l.contains("renamed from")) {
                let note = &line[line.find("/* renamed").unwrap() + 2..];
                assert_eq!(
                    note.matches("*/").count(),
                    1,
                    "the note must close exactly once, on its own terms:\n{out}"
                );
            }
            assert!(!out.contains("ev*/il") && !out.contains("ev/*il"), "{out}");
        }
        // A name with no comment delimiter and no control byte is quoted verbatim.
        let plain = render_type_definitions(
            &[struct_of(&types, "bad-name$1", 4, &[(0, "a", i4)])],
            RealTypeCtx::OFF,
        );
        assert!(plain.contains("/* renamed from \"bad-name$1\" */"), "{plain}");
    }

    /// Duplicate type names: the FIRST definition wins; a later same-named
    /// complete type emits only the `/* duplicate type name skipped */` note.
    #[test]
    fn duplicate_type_name_first_wins() {
        let types = TypeFactoryImpl::new();
        let other_types = TypeFactoryImpl::new();
        let i4 = named(&types, 4, type_metatype::TYPE_INT, "int4");
        let i8t = named(&other_types, 8, type_metatype::TYPE_INT, "int8");
        let first = struct_of(&types, "dup", 4, &[(0, "a", i4)]);
        let second = struct_of(&other_types, "dup", 8, &[(0, "b", i8t)]);
        let out = render_type_definitions(&[first, second], RealTypeCtx::OFF);
        assert_eq!(
            out.matches("typedef struct dup dup;").count(),
            1,
            "exactly one forward decl for the shared tag:\n{out}"
        );
        assert_eq!(
            out.matches("struct dup {").count(),
            1,
            "exactly one body for the shared tag:\n{out}"
        );
        assert!(out.contains("int4 a;"), "the FIRST definition's body wins:\n{out}");
        assert!(!out.contains("int8 b;"), "the second definition must be skipped:\n{out}");
        assert!(
            out.contains("/* duplicate type name skipped: dup */"),
            "duplicate note missing:\n{out}"
        );
    }

    /// Core types and unnamed types never render; an enum name colliding with
    /// a struct tag is skipped as a duplicate (the tag's forward typedef
    /// already claims the identifier).
    #[test]
    fn core_unnamed_and_cross_kind_collisions_skipped() {
        // A core type (flagged) is skipped even though it is a composite.
        let types = TypeFactoryImpl::new();
        let i4 = named(&types, 4, type_metatype::TYPE_INT, "int4");
        let core_struct = {
            let core_types = TypeFactoryImpl::new();
            core_types.setup_sizes(Some(4), 8, 8);
            core_types.set_core_type("int4", 4, type_metatype::TYPE_INT, false).unwrap();
            let core_i4 = core_types.find_by_name("int4").unwrap().unwrap();
            let mut c = Datatype::new_with_align(4, 4, type_metatype::TYPE_STRUCT);
            c.name = "sys".to_string();
            c.display_name = "sys".to_string();
            c.id = Datatype::hash_name("sys");
            c.kind = DatatypeKind::Struct {
                field: vec![TypeField::new(0, 0, "a", core_i4.id())],
                bitfield: vec![],
            };
            c.flags |= flags::coretype;
            let core_struct = core_types.intern(c).unwrap();
            core_types.cache_core_types().unwrap();
            core_struct
        };
        // An unnamed struct is skipped.
        let anon = {
            let mut s = Datatype::new_with_align(4, 4, type_metatype::TYPE_STRUCT);
            s.kind = DatatypeKind::Struct {
                field: vec![TypeField::new(0, 0, "a", i4.id())],
                bitfield: vec![],
            };
            types.intern(s).unwrap()
        };
        let named_struct = struct_of(&types, "tagged", 4, &[(0, "a", i4.clone())]);
        let colliding_enum = make_enum(&TypeFactoryImpl::new(), "tagged", 4, type_metatype::TYPE_UINT, &[(1, "ONE")]);
        let out = render_type_definitions(
            &[core_struct, anon, named_struct.clone(), colliding_enum],
            RealTypeCtx::OFF,
        );
        assert!(!out.contains("sys"), "core types must be skipped:\n{out}");
        assert!(out.contains("struct tagged {"), "named struct body missing:\n{out}");
        assert!(
            out.contains("/* duplicate type name skipped: tagged */"),
            "enum colliding with a struct tag must be skipped as a duplicate:\n{out}"
        );
        assert!(!out.contains("typedef enum tagged"), "colliding enum must not define:\n{out}");
    }
}

// ---------------------------------------------------------------------------
// Operator token table (printc.cc:24-78)
// ---------------------------------------------------------------------------

#[test]
fn token_table_precedence_and_type() {
    use tokens::*;
    // Spot-check the precedence ladder that defines C parenthesization
    // (printc.cc table).  Multiply/divide bind tighter than add/sub, which bind
    // tighter than shift, comparison, equality, bitwise, boolean, assignment,
    // comma.
    assert_eq!(MULTIPLY.precedence, 54);
    assert_eq!(BINARY_PLUS.precedence, 50);
    assert_eq!(SHIFT_LEFT.precedence, 46);
    assert_eq!(LESS_THAN.precedence, 42);
    assert_eq!(EQUAL.precedence, 38);
    assert_eq!(BITWISE_AND.precedence, 34);
    assert_eq!(BITWISE_XOR.precedence, 30);
    assert_eq!(BITWISE_OR.precedence, 26);
    assert_eq!(BOOLEAN_AND.precedence, 22);
    assert_eq!(BOOLEAN_OR.precedence, 18);
    assert_eq!(ASSIGNMENT.precedence, 14);
    assert_eq!(COMMA.precedence, 2);

    // Associativity flags (printc.cc).
    assert!(MULTIPLY.associative);
    assert!(!DIVIDE.associative);
    assert!(BINARY_PLUS.associative);
    assert!(!BINARY_MINUS.associative);
    assert!(BITWISE_AND.associative);
    assert!(!BOOLEAN_AND.associative);

    // Token types.
    assert_eq!(SUBSCRIPT.token_type, TokenType::Postsurround);
    assert_eq!(FUNCTION_CALL.token_type, TokenType::Postsurround);
    assert_eq!(TYPECAST.token_type, TokenType::Presurround);
    assert_eq!(DEREFERENCE.token_type, TokenType::UnaryPrefix);
    assert_eq!(HIDDEN.token_type, TokenType::HiddenFunction);
    assert_eq!(NEW_OP.token_type, TokenType::Space);

    // Printed characters.
    assert_eq!(SHIFT_LEFT.print1, "<<");
    assert_eq!(POINTER_MEMBER.print1, "->");
    assert_eq!(SUBSCRIPT.print1, "[");
    assert_eq!(SUBSCRIPT.print2, "]");
    assert_eq!(FUNCTION_CALL.bump, 10);
    assert_eq!(ASSIGNMENT.bump, 5);
}

#[test]
fn token_table_inplace_and_type_exprs() {
    use tokens::*;
    // In-place ops all bind at assignment precedence with bump 5 (printc.cc:62-71).
    for t in [
        &MULTEQUAL, &DIVEQUAL, &REMEQUAL, &PLUSEQUAL, &MINUSEQUAL, &LEFTEQUAL, &RIGHTEQUAL,
        &ANDEQUAL, &OREQUAL, &XOREQUAL,
    ] {
        assert_eq!(t.precedence, 14);
        assert_eq!(t.bump, 5);
        assert_eq!(t.token_type, TokenType::Binary);
    }
    assert_eq!(PLUSEQUAL.print1, "+=");
    assert_eq!(LEFTEQUAL.print1, "<<=");

    // Type-declaration tokens (printc.cc:74-78).
    assert_eq!(TYPE_EXPR_SPACE.spacing, 1);
    assert_eq!(TYPE_EXPR_NOSPACE.spacing, 0);
    assert_eq!(PTR_EXPR.print1, "*");
    assert_eq!(PTR_EXPR.token_type, TokenType::UnaryPrefix);
    assert_eq!(ARRAY_EXPR.token_type, TokenType::Postsurround);
    assert_eq!(ENUM_CAT.print1, "|");
}

#[test]
fn negate_cross_links() {
    use tokens::*;
    // printc.cc:130-135 — the six comparison flip pairs.
    assert!(std::ptr::eq(token_negate(&LESS_THAN).unwrap(), &GREATER_EQUAL));
    assert!(std::ptr::eq(token_negate(&LESS_EQUAL).unwrap(), &GREATER_THAN));
    assert!(std::ptr::eq(token_negate(&GREATER_THAN).unwrap(), &LESS_EQUAL));
    assert!(std::ptr::eq(token_negate(&GREATER_EQUAL).unwrap(), &LESS_THAN));
    assert!(std::ptr::eq(token_negate(&EQUAL).unwrap(), &NOT_EQUAL));
    assert!(std::ptr::eq(token_negate(&NOT_EQUAL).unwrap(), &EQUAL));
    // A token with no complement (C++ negate stays null).
    assert!(token_negate(&MULTIPLY).is_none());
    assert!(token_negate(&BINARY_PLUS).is_none());
    // The negate of a token's negate is itself (the pairs are symmetric).
    let n = token_negate(&LESS_THAN).unwrap();
    assert!(std::ptr::eq(token_negate(n).unwrap(), &LESS_THAN));
}

// ---------------------------------------------------------------------------
// parentheses driven by the real PrintC token table
// ---------------------------------------------------------------------------

#[test]
fn parentheses_uses_printc_token_precedence() {
    use tokens::*;
    // `a * (b + c)`: the `+` (op2, prec 50) feeds the `*` (top, prec 54).
    // top.precedence > op2.precedence -> parentheses required.
    let top = rpn(&MULTIPLY, 1);
    assert!(parentheses(&top, &BINARY_PLUS, None));

    // `a + b * c`: the `*` (op2, prec 54) feeds the `+` (top, prec 50).
    // top.precedence < op2.precedence -> no parentheses.
    let top = rpn(&BINARY_PLUS, 1);
    assert!(!parentheses(&top, &MULTIPLY, None));

    // Same associative token (`a * b * c` with `*` associative): no parens.
    let top = rpn(&MULTIPLY, 0);
    assert!(!parentheses(&top, &MULTIPLY, None));

    // Same precedence, NON-associative: `a - (b - c)` needs parens on the rhs.
    let top = rpn(&BINARY_MINUS, 1);
    assert!(parentheses(&top, &BINARY_MINUS, None));
}

/// The IEEE-754 pair is written out rather than derived from the integer one, so
/// EVERY field is compared here: a drifted precedence would change how float
/// arithmetic nests inside every other operator, and a drifted `bump` would wrap
/// the same `*` differently depending on the type of its operands.
#[test]
fn float_tokens_match_their_integer_twins_except_for_grouping() {
    use tokens::*;
    for (float_tok, int_tok) in [(&FLOAT_MULTIPLY, &MULTIPLY), (&FLOAT_PLUS, &BINARY_PLUS)] {
        assert_eq!(float_tok.print1, int_tok.print1);
        assert_eq!(float_tok.print2, int_tok.print2);
        assert_eq!(float_tok.precedence, int_tok.precedence);
        assert_eq!(float_tok.stage, int_tok.stage);
        assert_eq!(float_tok.spacing, int_tok.spacing);
        assert_eq!(float_tok.bump, int_tok.bump);
        assert_eq!(float_tok.token_type, int_tok.token_type);
        assert_eq!(float_tok.paren_before_angle, int_tok.paren_before_angle);
        assert!(float_tok.negate.is_none() && int_tok.negate.is_none());
        assert!(int_tok.associative && !int_tok.left_to_right_only);
        assert!(float_tok.left_to_right_only && !float_tok.associative);
    }
}

/// GH-641: `a * (b * c)` and `(a * b) * c` round differently, so the float
/// tokens parenthesize a same-token RIGHT operand and leave a left one bare.
#[test]
fn parentheses_keeps_float_grouping() {
    use tokens::*;
    for tok in [&FLOAT_MULTIPLY, &FLOAT_PLUS] {
        assert!(!parentheses(&rpn(tok, 0), tok, None), "a * b * c must stay flat");
        assert!(parentheses(&rpn(tok, 1), tok, None), "a * (b * c) must keep its parens");
    }
    // The integer twins are unchanged: associative on both sides.
    assert!(!parentheses(&rpn(&MULTIPLY, 1), &MULTIPLY, None));
    assert!(!parentheses(&rpn(&BINARY_PLUS, 1), &BINARY_PLUS, None));
}

/// End to end through the RPN engine, the shape the printer actually emits.
#[test]
fn rpn_float_chain_parenthesizes_only_the_right_operand() {
    let left = emit_expr(|p| {
        p.push_op(&tokens::FLOAT_MULTIPLY, None);
        p.push_op(&tokens::FLOAT_MULTIPLY, None);
        p.push_atom(&var_atom("a"));
        p.push_atom(&var_atom("b"));
        p.push_atom(&var_atom("c"));
    });
    assert_eq!(left, "a * b * c");

    let right = emit_expr(|p| {
        p.push_op(&tokens::FLOAT_MULTIPLY, None);
        p.push_atom(&var_atom("a"));
        p.push_op(&tokens::FLOAT_MULTIPLY, None);
        p.push_atom(&var_atom("b"));
        p.push_atom(&var_atom("c"));
    });
    assert_eq!(right, "a * (b * c)");
}

#[test]
fn parentheses_unary_adjacent_sign_kuna_fix() {
    use tokens::*;
    // (kuna) GH-2786: a unary minus feeding a unary minus would merge into `--`;
    // parentheses must intervene.  Both tokens are UNARY_MINUS (print1 "-").
    let top = rpn(&UNARY_MINUS, 0);
    assert!(parentheses(&top, &UNARY_MINUS, None));
    // A unary minus feeding a different unary prefix (bitwise not) does not.
    let top = rpn(&UNARY_MINUS, 0);
    assert!(!parentheses(&top, &BITWISE_NOT, None));
}

// ---------------------------------------------------------------------------
// Keyword / capability constants
// ---------------------------------------------------------------------------

#[test]
fn keyword_and_capability_constants() {
    use keywords::*;
    assert_eq!(KEYWORD_VOID, "void");
    assert_eq!(KEYWORD_IF, "if");
    assert_eq!(KEYWORD_ELSE, "else");
    assert_eq!(KEYWORD_RETURN, "return");
    assert_eq!(DOTDOTDOT, "...");
    assert_eq!(OPEN_CURLY, "{");
    assert_eq!(TYPE_POINTER_REL_TOKEN, "ADJ");
    assert_eq!(CAPABILITY_NAME, "c-language");
    // C++ `isdefault = true` (printc.cc:113).  Read through a runtime binding so
    // clippy doesn't treat it as an assert on a literal constant.
    let is_default = std::hint::black_box(CAPABILITY_IS_DEFAULT);
    assert!(is_default);
}

// ---------------------------------------------------------------------------
// PrintC option defaults (printc.cc:1649-1664)
// ---------------------------------------------------------------------------

#[test]
fn option_defaults_match_reset_defaults_printc() {
    let o = PrintCOptions::new();
    assert!(o.convention);
    assert!(o.hide_exts);
    // (kuna) DIV-36: `out OP= y` compound assignments render by default
    // (upstream ships the flag off and never consumed it; `option inplaceops
    // off` restores the `out = out OP y` form).
    assert!(o.inplace_ops);
    assert!(!o.nocasts);
    // (kuna) DIV-35: zero pointer constants render as NULL (upstream
    // option_NULL default off; `option nullprinting off` restores).
    assert!(o.null);
    assert!(!o.unplaced);
    // (kuna) DIV-2 default-on: &base[index] for standalone PTRADD (GH-558).
    assert!(o.array_notation);
    // (kuna) DIV-37: boolean-context zero comparisons render in truthy form
    // (`option truthycond off` restores the explicit comparisons).
    assert!(o.truthy_cond);
    // (kuna) DIV-38: single-statement if bodies drop their braces
    // (`option braceelide off` restores the braced form).
    assert!(o.brace_elide);
    // (kuna) DIV-39: warnings render as terse end-of-line slugs
    // (`option warnstyle banner` restores the WARNING banner lines).
    assert!(o.warn_inline);
    // (kuna) DIV-34: no blank line between the prototype and `{` (upstream
    // skip_line; `option braceformat function skip` restores it).
    assert_eq!(o.brace_func, BraceStyle::NextLine);
    assert_eq!(o.brace_ifelse, BraceStyle::SameLine);
    assert_eq!(o.brace_loop, BraceStyle::SameLine);
    assert_eq!(o.brace_switch, BraceStyle::SameLine);
}

#[test]
fn option_setters() {
    let mut o = PrintCOptions::new();
    o.set_null_printing(false);
    o.set_inplace_ops(false);
    o.set_no_cast_printing(true);
    o.set_array_notation(false);
    assert!(!o.null);
    assert!(!o.inplace_ops);
    assert!(o.nocasts);
    assert!(!o.array_notation());
    o.set_brace_format_function(BraceStyle::SkipLine);
    assert_eq!(o.brace_func, BraceStyle::SkipLine);
    o.set_truthy_cond(false);
    assert!(!o.truthy_cond());
    o.set_brace_elide(false);
    assert!(!o.brace_elide());
    o.set_warn_inline(false);
    assert!(!o.warn_inline());
}

// ---------------------------------------------------------------------------
// Integer constant formatting (printc.cc:1359-1436)
// ---------------------------------------------------------------------------

#[test]
fn format_integer_hex_dec_oct_bin() {
    // Hex: lowercase, 0x prefix.
    assert_eq!(
        format_integer_token(false, 0xdead_beef, display_format::FORCE_HEX, 4, false, false, false, ""),
        "0xdeadbeef"
    );
    // Decimal.
    assert_eq!(
        format_integer_token(false, 42, display_format::FORCE_DEC, 4, false, false, false, ""),
        "42"
    );
    // Octal: leading 0.
    assert_eq!(
        format_integer_token(false, 8, display_format::FORCE_OCT, 4, false, false, false, ""),
        "010"
    );
    // Binary: 0b prefix, padded to power-of-two width.
    assert_eq!(
        format_integer_token(false, 5, display_format::FORCE_BIN, 1, false, false, false, ""),
        "0b00000101"
    );
}

#[test]
fn format_integer_negative_unsigned_sized() {
    // Negative sign prefix.
    assert_eq!(
        format_integer_token(true, 5, display_format::FORCE_DEC, 4, false, false, false, ""),
        "-5"
    );
    // Force-unsigned 'U' suffix.
    assert_eq!(
        format_integer_token(false, 7, display_format::FORCE_DEC, 4, true, false, false, ""),
        "7U"
    );
    // Sized suffix.
    assert_eq!(
        format_integer_token(false, 7, display_format::FORCE_DEC, 8, false, true, false, "LL"),
        "7LL"
    );
}

/// The signed-integer format-resolution layer the Convert B1 substrate feeds: a
/// signed (`TYPE_INT` read-facing) equated constant must negate two's-complement
/// under the equate's forced display format.  C++ `pushConstant` passes
/// `sign=true` for `TYPE_INT` (`printc.cc:1818-1836`), so the equated `int4` value
/// `0xfffffe00` with a forced `dec` format renders `-512`, and the forced
/// `oct`/`bin` formats negate likewise (printc.cc:1381-1391).  This pins the
/// generic `resolve_integer_format`/`format_integer_token` free functions (NOT the
/// reserved `printc.rs` render dispatch — see the B3 stub in PROGRESS.md); generic
/// over the value/format, no convert-specific constants baked in.
#[test]
fn resolve_integer_signed_equate_negates_under_forced_format() {
    // 0xfffffe00 as int4 == -512: dec → (negsign, 512, FORCE_DEC).
    let (neg, val, fmt) =
        resolve_integer_format(0xffff_fe00, 4, true, display_format::FORCE_DEC, false, false);
    assert!(neg);
    assert_eq!(val, 512);
    assert_eq!(fmt, display_format::FORCE_DEC);
    assert_eq!(format_integer_token(neg, val, fmt, 4, false, false, false, ""), "-512");

    // Same value forced to octal: -0333 (512 == 0o1000... actually 512 dec, octal of
    // the magnitude).  The format is honored, the sign negated.
    let (neg, val, fmt) =
        resolve_integer_format(0xffff_fe00, 4, true, display_format::FORCE_OCT, false, false);
    assert!(neg);
    assert_eq!(format_integer_token(neg, val, fmt, 4, false, false, false, ""), "-01000");

    // An UNSIGNED (`TYPE_UINT`) read-facing constant does NOT negate: the same bits
    // print as the full unsigned value (4294966784).
    let (neg, val, fmt) =
        resolve_integer_format(0xffff_fe00, 4, false, display_format::FORCE_DEC, false, false);
    assert!(!neg);
    assert_eq!(val, 0xffff_fe00);
    assert_eq!(fmt, display_format::FORCE_DEC);

    // sign is suppressed for a `force_char` equate (printc.cc:1381): no negation.
    let (neg, _val, _fmt) =
        resolve_integer_format(0xffff_fe00, 4, true, display_format::FORCE_CHAR, false, false);
    assert!(!neg);
}

#[test]
fn format_integer_char() {
    // Plain printable char.
    assert_eq!(
        format_integer_token(false, b'A' as u64, display_format::FORCE_CHAR, 1, false, false, false, ""),
        "'A'"
    );
    // Escape char (newline).
    assert_eq!(
        format_integer_token(false, b'\n' as u64, display_format::FORCE_CHAR, 1, false, false, false, ""),
        "'\\n'"
    );
    // High byte (>= 0x80) with sz==1 uses the hex escape.
    assert_eq!(
        format_integer_token(false, 0x80, display_format::FORCE_CHAR, 1, false, false, false, ""),
        "'\\x80'"
    );
    // Wide-char prefix when sz > 1.
    assert_eq!(
        format_integer_token(false, b'A' as u64, display_format::FORCE_CHAR, 2, false, false, true, ""),
        "L'A'"
    );
}

#[test]
fn resolve_integer_format_sign_and_base() {
    // Signed value whose top bit is set, sz 1 (0xff = -1).
    let (neg, val, fmt) = resolve_integer_format(0xff, 1, true, 0, false, false);
    assert!(neg);
    assert_eq!(val, 1); // magnitude
    assert_eq!(fmt, display_format::FORCE_DEC); // val<=10

    // Small positive prints decimal regardless of natural base.
    let (neg, val, fmt) = resolve_integer_format(7, 4, false, 0, false, false);
    assert!(!neg);
    assert_eq!(val, 7);
    assert_eq!(fmt, display_format::FORCE_DEC);

    // force_hex mod wins.
    let (_, _, fmt) = resolve_integer_format(1000, 4, false, 0, true, false);
    assert_eq!(fmt, display_format::FORCE_HEX);

    // An explicit display-format override is preserved.
    let (_, _, fmt) =
        resolve_integer_format(1000, 4, false, display_format::FORCE_OCT, false, false);
    assert_eq!(fmt, display_format::FORCE_OCT);

    // 0xff with no force: most natural base of 255 is hex.
    let (_, _, fmt) = resolve_integer_format(0xff, 4, false, 0, false, false);
    assert_eq!(fmt, display_format::FORCE_HEX);
}

#[test]
fn resolve_then_format_full_path() {
    // The full push_integer path for a signed -1 (sz 4, 0xffffffff).
    let (neg, val, fmt) = resolve_integer_format(0xffff_ffff, 4, true, 0, false, false);
    let s = format_integer_token(neg, val, fmt, 4, false, false, false, "");
    assert_eq!(s, "-1");
}

// ---------------------------------------------------------------------------
// Char hex escape / unicode (printc.cc:1494-1591)
// ---------------------------------------------------------------------------

#[test]
fn char_hex_escape_widths() {
    let mut s = String::new();
    print_char_hex_escape(&mut s, 0x7);
    assert_eq!(s, "\\x07");
    let mut s = String::new();
    print_char_hex_escape(&mut s, 0x1ff);
    assert_eq!(s, "\\x01ff");
    let mut s = String::new();
    print_char_hex_escape(&mut s, 0x1_0000);
    assert_eq!(s, "\\x00010000");
}

#[test]
fn print_unicode_escapes_and_raw() {
    let mut s = String::new();
    print_unicode(&mut s, 0);
    assert_eq!(s, "\\0");
    let mut s = String::new();
    print_unicode(&mut s, 9);
    assert_eq!(s, "\\t");
    let mut s = String::new();
    print_unicode(&mut s, 92);
    assert_eq!(s, "\\\\");
    let mut s = String::new();
    print_unicode(&mut s, 0x22);
    assert_eq!(s, "\\\"");
    // A printable ASCII char passes through raw.
    let mut s = String::new();
    print_unicode(&mut s, b'A' as int4);
    assert_eq!(s, "A");
    // A printable non-ASCII codepoint passes through as UTF-8.
    let mut s = String::new();
    print_unicode(&mut s, 0x00e9); // é (A1-FF printable range)
    assert_eq!(s, "é");
}

// ---------------------------------------------------------------------------
// Float constant formatting (printc.cc:1448-1492)
// ---------------------------------------------------------------------------

#[test]
fn format_float_special_classes() {
    assert_eq!(format_float_token(FloatClass::Unknown, false, "", false), "FLOAT_UNKNOWN");
    assert_eq!(format_float_token(FloatClass::Infinity, false, "", false), "INFINITY");
    assert_eq!(format_float_token(FloatClass::Infinity, true, "", false), "-INFINITY");
    assert_eq!(format_float_token(FloatClass::Nan, false, "", false), "NAN");
    assert_eq!(format_float_token(FloatClass::Nan, true, "", false), "-NAN");
}

#[test]
fn format_float_normal_dot_zero_suffix() {
    // A decimal that already looks like a float is untouched.
    assert_eq!(format_float_token(FloatClass::Normal, false, "3.14159", false), "3.14159");
    assert_eq!(format_float_token(FloatClass::Normal, false, "1e+10", false), "1e+10");
    // A bare integer-looking decimal gets ".0" forced on (printc.cc:1485-1487).
    assert_eq!(format_float_token(FloatClass::Normal, false, "5", false), "5.0");
    assert_eq!(format_float_token(FloatClass::Normal, false, "0", false), "0.0");
    // Scientific (force_scinote): used verbatim, no .0 fix-up.
    assert_eq!(
        format_float_token(FloatClass::Normal, false, "5.00000e+00", true),
        "5.00000e+00"
    );
}

#[test]
fn format_float_consumes_floatformat_print_decimal() {
    // The real round-trip path: kuna-num FloatFormat::print_decimal -> the
    // token-string fix-up.  An IEEE-754 double-precision format.
    let fmt = kuna_num::float::FloatFormat::new(8);
    // 0.5 round-trips to "0.5", already float-looking.
    let dec = fmt.print_decimal(0.5, false);
    assert_eq!(format_float_token(FloatClass::Normal, false, &dec, false), "0.5");
    // 2.0 round-trips to "2"; push_float forces ".0".
    let dec = fmt.print_decimal(2.0, false);
    assert_eq!(format_float_token(FloatClass::Normal, false, &dec, false), "2.0");
}

// ---------------------------------------------------------------------------
// Generic names (printc.cc:3516-3558)
// ---------------------------------------------------------------------------

#[test]
fn generic_type_name_cases() {
    use type_metatype::*;
    assert_eq!(generic_type_name(TYPE_INT, 4), "unkint4");
    assert_eq!(generic_type_name(TYPE_UINT, 2), "unkuint2");
    assert_eq!(generic_type_name(TYPE_UNKNOWN, 1), "unkbyte1");
    assert_eq!(generic_type_name(TYPE_FLOAT, 8), "unkfloat8");
    assert_eq!(generic_type_name(TYPE_SPACEBASE, 4), "BADSPACEBASE");
    assert_eq!(generic_type_name(TYPE_STRUCT, 4), "BADTYPE");
}

#[test]
fn generic_function_name_invalid_addr() {
    // The non-kuna `func_<addr>` branch.  A null address renders the raw form
    // as "invalid_addr".
    let addr = kuna_base::address::Address::new_invalid();
    assert_eq!(generic_function_name(&addr).unwrap(), "func_invalid_addr");
}

// ---------------------------------------------------------------------------
// Opcode -> token dispatch (printc.hh:289-351)
// ---------------------------------------------------------------------------

#[test]
fn op_emit_kind_dispatch() {
    use kuna_num::opcodes::OpCode::*;
    use tokens::*;

    let kind = op_emit_kind(CPUI_INT_ADD);
    match kind {
        OpEmitKind::Binary(t) => assert!(std::ptr::eq(t, &BINARY_PLUS)),
        _ => panic!("INT_ADD should be Binary(BINARY_PLUS)"),
    }
    // Signed and unsigned div both map to '/'.
    for op in [CPUI_INT_DIV, CPUI_INT_SDIV] {
        match op_emit_kind(op) {
            OpEmitKind::Binary(t) => assert!(std::ptr::eq(t, &DIVIDE)),
            _ => panic!("div should be Binary(DIVIDE)"),
        }
    }
    // Signed/unsigned less both map to '<'.
    for op in [CPUI_INT_LESS, CPUI_INT_SLESS] {
        match op_emit_kind(op) {
            OpEmitKind::Binary(t) => assert!(std::ptr::eq(t, &LESS_THAN)),
            _ => panic!("less should be Binary(LESS_THAN)"),
        }
    }
    // 2COMP and NEGATE are unary.
    match op_emit_kind(CPUI_INT_2COMP) {
        OpEmitKind::Unary(t) => assert!(std::ptr::eq(t, &UNARY_MINUS)),
        _ => panic!("2COMP should be Unary(UNARY_MINUS)"),
    }
    match op_emit_kind(CPUI_INT_NEGATE) {
        OpEmitKind::Unary(t) => assert!(std::ptr::eq(t, &BITWISE_NOT)),
        _ => panic!("NEGATE should be Unary(BITWISE_NOT)"),
    }
    // CARRY/SCARRY/SBORROW and most float-only ops are functional.
    assert!(matches!(op_emit_kind(CPUI_INT_CARRY), OpEmitKind::Func));
    assert!(matches!(op_emit_kind(CPUI_FLOAT_NAN), OpEmitKind::Func));
    assert!(matches!(op_emit_kind(CPUI_FLOAT_SQRT), OpEmitKind::Func));
    assert!(matches!(op_emit_kind(CPUI_POPCOUNT), OpEmitKind::Func));
    assert!(matches!(op_emit_kind(CPUI_LZCOUNT), OpEmitKind::Func));
    assert!(matches!(op_emit_kind(CPUI_PIECE), OpEmitKind::Func));
    // CAST / FLOAT2FLOAT / FLOAT_TRUNC use type-cast syntax.
    assert!(matches!(op_emit_kind(CPUI_CAST), OpEmitKind::TypeCast));
    assert!(matches!(op_emit_kind(CPUI_FLOAT_FLOAT2FLOAT), OpEmitKind::TypeCast));
    assert!(matches!(op_emit_kind(CPUI_FLOAT_TRUNC), OpEmitKind::TypeCast));
    // FLOAT_INT2FLOAT has a hand-written override (PrintC::opFloatInt2Float,
    // printc.cc:850 — the `(floatN)input` cast with INT_ZEXT absorption), so it
    // is Custom and dispatched by the `op_float_int2float_ir` arm of op_push_ir.
    assert!(matches!(op_emit_kind(CPUI_FLOAT_INT2FLOAT), OpEmitKind::Custom));
    // Hand-written / no-op overrides are Custom.
    assert!(matches!(op_emit_kind(CPUI_LOAD), OpEmitKind::Custom));
    assert!(matches!(op_emit_kind(CPUI_STORE), OpEmitKind::Custom));
    assert!(matches!(op_emit_kind(CPUI_CALL), OpEmitKind::Custom));
    assert!(matches!(op_emit_kind(CPUI_MULTIEQUAL), OpEmitKind::Custom));
    assert!(matches!(op_emit_kind(CPUI_INDIRECT), OpEmitKind::Custom));
    assert!(matches!(op_emit_kind(CPUI_SUBPIECE), OpEmitKind::Custom));
    assert!(matches!(op_emit_kind(CPUI_PTRADD), OpEmitKind::Custom));
    assert!(matches!(op_emit_kind(CPUI_PTRSUB), OpEmitKind::Custom));
}

// ---------------------------------------------------------------------------
// PrintC::doc_function shell (w9x-arch-engine-glue): a real signature + matched
// braces driven through the Emit primitives.  The body is the W9-emit stub.
// ---------------------------------------------------------------------------

#[test]
fn doc_function_emits_a_structurally_sane_shell() {
    let mut p = PrintC::new();
    let out = p.doc_function("main", None, "void", &[]);
    // Signature: the name + a () param list.
    assert!(out.contains("main"), "missing function name: {out}");
    assert!(out.contains('(') && out.contains(')'), "missing param parens: {out}");
    assert!(out.contains("void"), "missing void return/params: {out}");
    // Matched braces.
    assert_eq!(out.matches('{').count(), 1, "want one open brace: {out}");
    assert_eq!(out.matches('}').count(), 1, "want one close brace: {out}");
    // void return + void params (no recovered prototype).
    assert!(out.contains("void main(void)"), "want `void main(void)`: {out}");
}

#[test]
fn doc_function_renders_a_real_prototype() {
    let mut p = PrintC::new();
    let params =
        vec![("int".to_string(), "a".to_string()), ("char".to_string(), "b".to_string())];
    let out = p.doc_function("foo", Some("__stdcall"), "int", &params);
    assert!(out.contains("int"), "{out}");
    assert!(out.contains("foo"), "{out}");
    assert!(out.contains('a') && out.contains('b'), "params missing: {out}");
    // The convention/model name is printed (option_convention default-on).
    assert!(out.contains("__stdcall"), "model name missing: {out}");
    assert_eq!(out.matches('{').count(), out.matches('}').count());
}

// ---------------------------------------------------------------------------
// The PrintLanguage RPN driver (push_op / push_atom / op_binary / op_unary /
// emit_op / emit_atom / parentheses), realized in printc.rs.  These drive the
// real `EmitNoMarkup` back-end and assert byte-faithful token emission against
// the C++ `emitOp`/`emitAtom`/`parentheses` logic (printlanguage.cc:129-580),
// independent of the stubbed IR.
// ---------------------------------------------------------------------------

use crate::printlanguage::{Atom as PlAtom, SyntaxHighlight as PlHl, TagType as PlTag};

/// A variable-name leaf atom.
fn var_atom(name: &str) -> PlAtom {
    PlAtom::syntax(name, PlTag::VarToken, PlHl::var_color)
}
/// A constant-syntax leaf atom (a literal already rendered to its string).
fn const_atom(name: &str) -> PlAtom {
    PlAtom::syntax(name, PlTag::Syntax, PlHl::const_color)
}

/// Drive `f` on a fresh PrintC and return the emitted text.
fn emit_expr<F: FnOnce(&mut PrintC)>(f: F) -> String {
    let mut p = PrintC::new();
    p.set_output_stream();
    f(&mut p);
    p.emit_mut().output_str().to_string()
}

#[test]
fn rpn_single_binary() {
    // a + b  -> "a + b" (binary spacing == 1 around the operator).
    let out = emit_expr(|p| {
        p.op_binary(&tokens::BINARY_PLUS, None, &var_atom("a"), &var_atom("b"));
    });
    assert_eq!(out, "a + b", "binary plus: {out:?}");
    // The stack must be fully drained.
}

#[test]
fn rpn_assignment_form() {
    // x = a  -> "x = a".
    let out = emit_expr(|p| {
        p.op_binary(&tokens::ASSIGNMENT, None, &var_atom("x"), &var_atom("a"));
    });
    assert_eq!(out, "x = a", "assignment: {out:?}");
}

#[test]
fn rpn_unary_prefix_no_space() {
    // -a  -> "-a" (unary minus spacing == 0).
    let out = emit_expr(|p| {
        p.op_unary(&tokens::UNARY_MINUS, None, &var_atom("a"));
    });
    assert_eq!(out, "-a", "unary minus: {out:?}");
    // ~a -> "~a".
    let out = emit_expr(|p| {
        p.op_unary(&tokens::BITWISE_NOT, None, &var_atom("a"));
    });
    assert_eq!(out, "~a", "bitwise not: {out:?}");
}

#[test]
fn rpn_precedence_forces_parens() {
    // a * (b + c): push MULTIPLY(a, <subexpr b+c>).  The lower-precedence '+'
    // as the right operand of '*' must be parenthesized.
    let out = emit_expr(|p| {
        // Build manually: push '*', push 'a', then a nested '+' subexpression.
        p.push_op(&tokens::MULTIPLY, None);
        p.push_atom(&var_atom("a"));
        // Now the right operand is a '+' expression; push it as a nested op.
        p.push_op(&tokens::BINARY_PLUS, None);
        p.push_atom(&var_atom("b"));
        p.push_atom(&var_atom("c"));
    });
    assert_eq!(out, "a * (b + c)", "precedence parens: {out:?}");
}

#[test]
fn rpn_no_parens_when_higher_precedence_nested() {
    // a + b * c: the higher-precedence '*' on the right needs no parens.
    let out = emit_expr(|p| {
        p.push_op(&tokens::BINARY_PLUS, None);
        p.push_atom(&var_atom("a"));
        p.push_op(&tokens::MULTIPLY, None);
        p.push_atom(&var_atom("b"));
        p.push_atom(&var_atom("c"));
    });
    assert_eq!(out, "a + b * c", "no parens for higher prec: {out:?}");
}

#[test]
fn rpn_associative_no_parens() {
    // a + b + c: '+' is associative; nesting the same token on the right
    // (top==op2 && associative) prints without parens.
    let out = emit_expr(|p| {
        p.push_op(&tokens::BINARY_PLUS, None);
        p.push_atom(&var_atom("a"));
        p.push_op(&tokens::BINARY_PLUS, None);
        p.push_atom(&var_atom("b"));
        p.push_atom(&var_atom("c"));
    });
    assert_eq!(out, "a + b + c", "associative: {out:?}");
}

#[test]
fn rpn_negate_token_flips_comparison() {
    // negatetoken modifier flips '<' to '>='.
    let out = emit_expr(|p| {
        p.context.set_mod(crate::printlanguage::modifiers::NEGATETOKEN);
        p.op_binary(&tokens::LESS_THAN, None, &var_atom("a"), &var_atom("b"));
    });
    assert_eq!(out, "a >= b", "negate flip: {out:?}");
}

#[test]
fn rpn_comparison_constant_operand() {
    // dat <= 10  (the boolless target shape) using a const-syntax operand.
    let out = emit_expr(|p| {
        p.op_binary(&tokens::LESS_EQUAL, None, &var_atom("dat_52"), &const_atom("10"));
    });
    assert_eq!(out, "dat_52 <= 10", "comparison: {out:?}");
}

#[test]
fn rpn_stack_drains_to_empty() {
    let mut p = PrintC::new();
    p.set_output_stream();
    p.op_binary(&tokens::BINARY_PLUS, None, &var_atom("a"), &var_atom("b"));
    assert!(p.is_stack_empty(), "RPN stack not drained after a complete expression");
}

// ---------------------------------------------------------------------------
// w10-enum-render VERIFIER adversarial tests.
//
// Target `PrintC::push_enum_constant_ir` — the enum arm of `pushConstant`
// transcribing C++ `PrintC::pushEnumConstant` (printc.cc:1735-1756).  These
// drive the REAL RPN/`EmitNoMarkup` back-end (`emit_expr`) so the assertion is
// the actual rendered C string, then re-derive the expectation from
// `Datatype::get_matches` + the C++ push order:
//   - flag-OR decomposition (`(A|B|C)`, MSB-first name order),
//   - a single matched flag (no `|`, no parens-from-cat),
//   - a value with a numeric remainder no flag covers (fall back to the raw
//     integer literal — `match_name` empty),
//   - bitwise-complement (`~`),
//   - GENERIC over an arbitrary namemap (no hardcoded flag names/values): the
//     same value through two unrelated enums renders each enum's own names.
//
// C++ oracle: `decompiler/cpp/printc.cc:1735-1756`, `type.cc:1537-1586`.
// ---------------------------------------------------------------------------
mod w10_enum_render {
    use super::*;
    use crate::dtype::{flags, type_metatype, Datatype, DatatypeKind};
    use crate::context::{OpId, VarnodeId};
    use std::collections::BTreeMap;

    /// Build an enum (value -> name) the way `TypeEnum` looks after decode:
    /// metatype TYPE_UINT plus the `enumtype` flag (dtype.rs:5244-5247).
    fn make_enum(size: i32, entries: &[(u64, &str)]) -> crate::dtype::TypeRoot {
        use crate::dtype::TypeFactoryImpl;
        let mut dt = Datatype::new_with_align(size, size, type_metatype::TYPE_UINT);
        dt.flags |= flags::enumtype;
        let mut namemap: BTreeMap<u64, String> = BTreeMap::new();
        for (v, n) in entries {
            namemap.insert(*v, (*n).to_string());
        }
        dt.kind = DatatypeKind::Enum { namemap };
        TypeFactoryImpl::new().intern(dt).unwrap()
    }

    /// Render a single enum constant through the live RPN/emit driver.
    fn render_enum(ct: &crate::dtype::TypeRoot, val: u64) -> String {
        emit_expr(|p| {
            p.push_enum_constant_ir(
                &crate::dtype::TypeFactoryImpl::new(), ct, val, OpId::default(), VarnodeId::default(),
                false,
            );
        })
    }

    /// Flag-OR: 0x2c = 0x20|0x8|0x4 over the enum.xml `flags`-style enum must
    /// render `(FLAG_20|FLAG_8|FLAG_4)` — the MSB-first OR the C++
    /// `pushEnumConstant` emits (one `enum_cat` `|` per gap, names in forward
    /// order, the whole thing parenthesised by the surrounding `&`/`==`).  We
    /// assert the bare expression here; the parens come from the parent op.
    #[test]
    fn flag_or_decomposition_msb_first() {
        let e = make_enum(
            8,
            &[(0x4, "FLAG_4"), (0x8, "FLAG_8"), (0x20, "FLAG_20"), (0x100, "FLAG_100")],
        );
        // Cross-check the data layer drives the render (no hardcoding).
        let rep = e.get_matches(0x2c).unwrap();
        assert_eq!(
            rep.match_name,
            vec!["FLAG_20".to_string(), "FLAG_8".to_string(), "FLAG_4".to_string()],
            "get_matches must yield MSB-first names"
        );
        assert!(!rep.complement && rep.shift_amount == 0);
        assert_eq!(render_enum(&e, 0x2c), "FLAG_20|FLAG_8|FLAG_4");
    }

    /// A single matched flag emits exactly one name — no `|`, no `enum_cat`.
    #[test]
    fn single_flag_no_cat() {
        let e = make_enum(4, &[(0x1, "A"), (0x2, "B"), (0x4, "C")]);
        let rep = e.get_matches(0x4).unwrap();
        assert_eq!(rep.match_name, vec!["C".to_string()]);
        assert_eq!(render_enum(&e, 0x4), "C");
    }

    /// A value with a bit no flag covers has NO representation (`match_name`
    /// empty) and falls back to the raw integer literal — NOT a partial
    /// "names + remainder" mix (C++ pushEnumConstant else-branch, printc.cc:1753).
    #[test]
    fn numeric_remainder_falls_back_to_raw_integer() {
        let e = make_enum(4, &[(0x1, "A"), (0x2, "B"), (0x4, "C")]);
        // 0x10 has no covering flag in {1,2,4} within the 4-byte mask.
        let rep = e.get_matches(0x10).unwrap();
        assert!(rep.match_name.is_empty(), "no representation -> empty match_name");
        // The render is the bare integer (default hex/dec format), no flag names.
        let out = render_enum(&e, 0x10);
        assert!(
            !out.contains('A') && !out.contains('B') && !out.contains('C') && !out.contains('|'),
            "remainder must render as a raw integer, got {out:?}"
        );
        assert_eq!(out, "0x10", "raw integer fallback: {out:?}");
    }

    /// NO SPECIAL-CASING: the arm is generic over the namemap.  The SAME value
    /// 0x5 through two unrelated enums renders each enum's own names — there is
    /// no hardcoded `FLAG_*`/value/function dependence anywhere in the arm.
    #[test]
    fn generic_over_namemap_no_hardcoding() {
        let red = make_enum(4, &[(0x1, "RED_LO"), (0x4, "RED_HI")]);
        let blue = make_enum(4, &[(0x1, "BLUE_BIT0"), (0x4, "BLUE_BIT2")]);
        // 0x5 = 0x4 | 0x1 in both, but the names differ entirely.
        assert_eq!(render_enum(&red, 0x5), "RED_HI|RED_LO");
        assert_eq!(render_enum(&blue, 0x5), "BLUE_BIT2|BLUE_BIT0");
    }
}

// ---------------------------------------------------------------------------
// w10-printc-body VERIFIER adversarial tests (round 1).
// Target the most fragile transcription points: the postsurround id2
// mirror-back across the two emit_op calls on one stack entry, deep
// non-associative right-nesting (parens at every level + stack drain order),
// and the op_binary negate-flip fallback divergence (C++ throws; Rust
// unwrap_or(tok)).  See docs/rust-port/reviews/w10-printc-body.md.
// ---------------------------------------------------------------------------

/// Postsurround (function-call `( )`) wrapping a lower-precedence binary
/// subexpression.  This is the only RPN path where one stack entry's `id2` is
/// SET by `emit_op` at `visited==1` (openParen) and then READ at `visited==2`
/// (closeParen).  The Rust port clones the entry for each `emit_op` and mirrors
/// `id2` back onto the live stack top; if that mirror is wrong the close paren
/// would be lost/mismatched.  C++ emitOp: postsurround visited==1 -> openParen,
/// visited==2 -> closeParen(print2,id2) (printlanguage.cc:347-357).
#[test]
fn w10_postsurround_call_id2_roundtrips() {
    // foo(a + b): push FUNCTION_CALL, the func-name leaf, then a nested '+'.
    let out = emit_expr(|p| {
        p.push_op(&tokens::FUNCTION_CALL, None);
        p.push_atom(&var_atom("foo"));
        p.push_op(&tokens::BINARY_PLUS, None);
        p.push_atom(&var_atom("a"));
        p.push_atom(&var_atom("b"));
    });
    assert_eq!(out, "foo(a + b)", "postsurround call: {out:?}");
}

/// Deep right-nested non-associative subtraction.  `BINARY_MINUS` is
/// non-associative (printc.cc:41), so each nested `-` on the right operand must
/// be parenthesized — exercising `parentheses` (equal-precedence,
/// non-associative -> true) at every level and the `push_atom` drain `do/while`
/// loop popping multiple completed entries when the final atom lands.
#[test]
fn w10_deep_nonassoc_right_nesting_parenthesizes_each_level() {
    // a - (b - (c - d))
    let out = emit_expr(|p| {
        p.push_op(&tokens::BINARY_MINUS, None);
        p.push_atom(&var_atom("a"));
        p.push_op(&tokens::BINARY_MINUS, None);
        p.push_atom(&var_atom("b"));
        p.push_op(&tokens::BINARY_MINUS, None);
        p.push_atom(&var_atom("c"));
        p.push_atom(&var_atom("d"));
    });
    assert_eq!(out, "a - (b - (c - d))", "deep nonassoc: {out:?}");
    // When the SAME non-assoc token is the nested operator while the outer
    // minus is still at its first stage (visited==0), C++ `parentheses`
    // (Binary arm: equal precedence + NON-associative -> return true,
    // printlanguage.cc:278-287) DOES parenthesize it.  So this push order
    // (outer minus, then inner minus as its left subexpression) prints
    // `(a - b) - c`, matching the C++ emitter.  (Associativity only suppresses
    // parens for an associative token feeding itself, e.g. `a + b + c`.)
    let out = emit_expr(|p| {
        p.push_op(&tokens::BINARY_MINUS, None);
        p.push_op(&tokens::BINARY_MINUS, None);
        p.push_atom(&var_atom("a"));
        p.push_atom(&var_atom("b"));
        p.push_atom(&var_atom("c"));
    });
    assert_eq!(out, "(a - b) - c", "nested non-assoc minus parenthesizes: {out:?}");
}

/// op_binary negate-flip on a token with NO complement.  C++ `opBinary`
/// (printlanguage.cc:556-561) throws `LowlevelError("Could not find fliptoken")`
/// when `tok->negate == 0` under `negatetoken`.  The Rust port uses
/// `token_negate(tok).unwrap_or(tok)` — it silently keeps the ORIGINAL token
/// (and clears the modifier) rather than aborting.  This test PINS the current
/// Rust behavior so a future restoration to the C++ throw is a visible change;
/// it is the divergence recorded as F1 in the verdict (latent: op_binary is not
/// yet IR-driven, so the path is unreachable in production today).
#[test]
fn w10_negate_flip_no_complement_keeps_token_does_not_panic() {
    use crate::printlanguage::modifiers::NEGATETOKEN;
    // BINARY_PLUS has no negate complement (token_negate -> None).
    assert!(crate::printc::token_negate(&tokens::BINARY_PLUS).is_none());
    let out = emit_expr(|p| {
        p.context.set_mod(NEGATETOKEN);
        // C++ would THROW here; Rust keeps '+' and clears the modifier.
        p.op_binary(&tokens::BINARY_PLUS, None, &var_atom("a"), &var_atom("b"));
    });
    assert_eq!(out, "a + b", "no-complement flip falls back to original token: {out:?}");
    // The modifier must be cleared regardless (matches C++ unsetMod ordering).
    let mut p = PrintC::new();
    p.set_output_stream();
    p.context.set_mod(NEGATETOKEN);
    p.op_binary(&tokens::BINARY_PLUS, None, &var_atom("a"), &var_atom("b"));
    assert!(!p.context.is_set(NEGATETOKEN), "negatetoken modifier not cleared");
}

// ===========================================================================
// VERIFIER tests for `rport/w10-float-family` (in-crate: these reach the
// PRIVATE ported logic `absorb_zext` / `op_float_int2float_ir` / the cast-type
// text, none of which is reachable from an integration test).
//
// Oracle: TypeOpFloatInt2Float::absorbZext (typeop.cc:1874) and
// PrintC::opFloatInt2Float (printc.cc:850).
//
//   const Varnode *vn0 = op->getIn(0);
//   if (vn0->isWritten() && vn0->isImplied()) {
//     const PcodeOp *zextOp = vn0->getDef();
//     if (zextOp->code() == CPUI_INT_ZEXT) return zextOp;
//   }
//   return 0;
//
// The hunt-list fragile spots for this item: (1) the AND of BOTH flags
// (isWritten && isImplied) — dropping either gates the wrong way; (2) the
// opcode equality (must be INT_ZEXT, not INT_SEXT or any other extension);
// (3) the def-null robustness (C++ derefs getDef() unguarded after isWritten,
// the Rust uses `?`); (4) the `(floatN)` cast text for a scalar float base.
// ===========================================================================
mod w10_float_family {
    use super::*;
    use crate::dtype::{type_metatype, Datatype};
    use crate::funcdata::Funcdata;
    use crate::printc::{absorb_zext, declarator_parts};
    use crate::context::{ArchContext, TypeOp};
    use kuna_base::address::Address;
    use kuna_base::space::{
        addrspace_flags, spacetype, AddrSpace, AddrSpaceManager, ConstantSpace, UniqueSpace,
    };
    use kuna_num::opcodes::OpCode;
    use std::rc::Rc;

    fn build_manager() -> AddrSpaceManager {
        let mut m = AddrSpaceManager::new();
        m.insert_space(Rc::new(ConstantSpace::new())).unwrap();
        m.insert_space(Rc::new(UniqueSpace::new(1, 0, false))).unwrap();
        m.insert_space(Rc::new(AddrSpace::new(
            spacetype::IPTR_PROCESSOR,
            "ram",
            false,
            8,
            1,
            2,
            addrspace_flags::hasphysical,
            1,
            1,
        )))
        .unwrap();
        m
    }

    fn build_fd() -> Funcdata {
        let manage = build_manager();
        let glb = Rc::new(ArchContext::new(manage));
        let ram = Rc::clone(glb.manage().get_space_by_name("ram").unwrap());
        let addr = Address::new(ram, 0x1000);
        Funcdata::new("func", "func", glb, addr, 0x1000_0000, 0x40).unwrap()
    }

    fn ram(fd: &Funcdata) -> Rc<AddrSpace> {
        Rc::clone(fd.get_arch().manage().get_space_by_name("ram").unwrap())
    }

    fn unk(size: int4) -> crate::dtype::TypeRoot {
        crate::dtype::TypeFactoryImpl::new().intern(Datatype::new(size, type_metatype::TYPE_UNKNOWN)).unwrap()
    }

    fn mk_op(fd: &mut Funcdata, inputs: int4, off: u64, opc: OpCode) -> super::super::OpId {
        let ram = ram(fd);
        let op = fd.new_op(inputs, Address::new(ram, off));
        fd.obank_mut().change_opcode(op, TypeOp::new(opc, 0, format!("{opc:?}")));
        op
    }

    /// Build a FLOAT_INT2FLOAT op whose in0 is the (written) output of a
    /// definer op with opcode `def_opc`; the produced varnode's implied flag is
    /// `implied`.  Returns the (i2f op, definer op).
    fn build_i2f_over(
        fd: &mut Funcdata,
        def_opc: OpCode,
        implied: bool,
    ) -> (super::super::OpId, super::super::OpId) {
        let r = ram(fd);
        // The definer op (e.g. INT_ZEXT) producing a written varnode.
        let defop = mk_op(fd, 1, 0x10, def_opc);
        let src = fd.new_varnode(4, &Address::new(Rc::clone(&r), 0x200), Some(unk(4)));
        fd.op_set_input(defop, src, 0).unwrap();
        let widened = fd.new_varnode(8, &Address::new(Rc::clone(&r), 0x300), Some(unk(8)));
        fd.op_set_output(defop, widened).unwrap();
        // op_set_output marks `widened` written; re-fetch its id (set_def may
        // remap) from the definer's output.
        let widened = fd.obank().get(defop).unwrap().get_out().unwrap();
        if implied {
            fd.vbank_mut().get_mut(widened).unwrap().set_implied();
        }
        // The FLOAT_INT2FLOAT reading `widened` in slot 0.
        let i2f = mk_op(fd, 1, 0x20, OpCode::CPUI_FLOAT_INT2FLOAT);
        fd.op_set_input(i2f, widened, 0).unwrap();
        let out = fd.new_varnode(8, &Address::new(r, 0x400), Some(unk(8)));
        fd.op_set_output(i2f, out).unwrap();
        (i2f, defop)
    }

    /// in0 is an implied, written INT_ZEXT output -> absorb (return the ZEXT).
    #[test]
    fn absorb_zext_positive_implied_written_intzext() {
        let mut fd = build_fd();
        let (i2f, zext) = build_i2f_over(&mut fd, OpCode::CPUI_INT_ZEXT, true);
        assert_eq!(
            absorb_zext(&fd, i2f),
            Some(zext),
            "implied+written INT_ZEXT must be absorbed"
        );
    }

    /// NOT implied (but written INT_ZEXT) -> NO absorption.  C++ requires BOTH
    /// isWritten() AND isImplied(); dropping the implied check is a finding.
    #[test]
    fn absorb_zext_negative_not_implied() {
        let mut fd = build_fd();
        let (i2f, _zext) = build_i2f_over(&mut fd, OpCode::CPUI_INT_ZEXT, false);
        assert_eq!(
            absorb_zext(&fd, i2f),
            None,
            "a written-but-not-implied INT_ZEXT must NOT be absorbed"
        );
    }

    /// Implied + written but the definer is INT_SEXT (sign-extend), not
    /// INT_ZEXT -> NO absorption.  The opcode equality must be exact: a
    /// sign-extension is a different conversion the cast cannot silently absorb.
    #[test]
    fn absorb_zext_negative_wrong_opcode_intsext() {
        let mut fd = build_fd();
        let (i2f, _def) = build_i2f_over(&mut fd, OpCode::CPUI_INT_SEXT, true);
        assert_eq!(
            absorb_zext(&fd, i2f),
            None,
            "an INT_SEXT (not INT_ZEXT) must NOT be absorbed"
        );
    }

    /// in0 is a free (un-written) input varnode -> NO absorption (isWritten()
    /// is false, so getDef() is never reached).  This is also the def-null
    /// robustness boundary: C++ would not deref getDef() here either.
    #[test]
    fn absorb_zext_negative_free_input() {
        let mut fd = build_fd();
        let r = ram(&fd);
        let i2f = mk_op(&mut fd, 1, 0x20, OpCode::CPUI_FLOAT_INT2FLOAT);
        let free_in = fd.new_varnode(8, &Address::new(Rc::clone(&r), 0x500), Some(unk(8)));
        // A free varnode marked implied (implied alone must not trigger absorb).
        fd.vbank_mut().get_mut(free_in).unwrap().set_implied();
        fd.op_set_input(i2f, free_in, 0).unwrap();
        let out = fd.new_varnode(8, &Address::new(r, 0x600), Some(unk(8)));
        fd.op_set_output(i2f, out).unwrap();
        assert_eq!(
            absorb_zext(&fd, i2f),
            None,
            "a free (un-written) input must NOT be absorbed even if implied"
        );
    }

    /// The cast-type text for a scalar `floatN` base is exactly its display
    /// name, no modifiers — `push_cast_type` builds `(front,back)` =
    /// `("float8","")` -> the `(float8)` half of the cast.  A trailing `*`/`[]`
    /// here would corrupt the rendered cast.
    #[test]
    fn cast_type_text_scalar_float_is_display_name() {
        let mut t = Datatype::new_with_align(8, -1, type_metatype::TYPE_FLOAT);
        t.name = "float8".to_string();
        t.display_name = "float8".to_string();
        t.id = Datatype::hash_name("float8");
        let types = crate::dtype::TypeFactoryImpl::new();
        let t = types.intern(t).unwrap();
        let (front, back) = declarator_parts(&t, crate::printc::RealTypeCtx::OFF);
        assert_eq!(front, "float8");
        assert_eq!(back, "");
        // float4 likewise (the conversion-source-width family).
        let mut t4 = Datatype::new_with_align(4, -1, type_metatype::TYPE_FLOAT);
        t4.name = "float4".to_string();
        t4.display_name = "float4".to_string();
        t4.id = Datatype::hash_name("float4");
        let (f4, b4) = declarator_parts(&types.intern(t4).unwrap(), crate::printc::RealTypeCtx::OFF);
        assert_eq!((f4.as_str(), b4.as_str()), ("float4", ""));
    }
}

// ===========================================================================
// VERIFIER adversarial tests for `rport/w10-printc-cast-render` (round 1).
//
// Oracle: PrintC::opTypeCast (printc.cc:468):
//
//   Datatype *dt = op->getOut()->getHighTypeDefFacing();
//   if (dt->isPointerToArray()) { ... addressof ... }      // STUB (not these)
//   if (!option_nocasts) { pushOp(&typecast,op); pushType(dt); }
//   pushVn(op->getIn(0),op,mods);
//
// shared by opCast / opFloatFloat2Float / opFloatTrunc (printc.hh:332-341).
//
// These tests reach the PRIVATE `op_type_cast_ir` end-to-end (build a real op
// with a typed output varnode, drive the routine, capture the emitted text) so
// they pin the THREE things the diff must get right and nothing else:
//   (1) FAITHFULNESS — the target type spelling comes from the OUTPUT varnode's
//       def-facing type (`op->getOut()->getHighTypeDefFacing()`), NOT a
//       hardcoded / opcode-keyed string: the SAME op renders a different cast
//       text when only its output type changes;
//   (2) PARENTHESIZATION / OPERAND RECURSION — the cast is a `presurround`
//       op-token (prec 2): a lower-precedence operand subexpression (`a + b`)
//       MUST be parenthesized `(T)(a + b)`, an atom MUST NOT (`(T)k`);
//   (3) the `!option_nocasts` gate — with nocasts the `(T)` is suppressed and
//       only the operand flows through.
// The fragile spot here is the type-name plumbing (a hardcode would pass a
// single fixture but fail test (1)'s two-type contrast) and the operand
// precedence (the cast is presurround, not a prefix unary).
// ===========================================================================
mod w10_printc_cast_render {
    use super::*;
    use crate::dtype::{type_metatype, Datatype};
    use crate::funcdata::Funcdata;
    use crate::context::{ArchContext as ContextArch, TypeOp};
    use kuna_base::address::Address;
    use kuna_base::error::{KunaError, KunaResult};
    use kuna_base::space::{
        addrspace_flags, spacetype, AddrSpace, AddrSpaceManager, ConstantSpace, UniqueSpace,
    };
    use kuna_num::opcodes::OpCode;
    use kuna_sleigh::globalcontext::ContextInternal;
    use kuna_sleigh::loadimage::LoadImage;
    use kuna_sleigh::sleigh::Sleigh;
    use std::rc::Rc;

    /// A minimal LoadImage so a bare `architecture::Architecture` can be built
    /// (the render `arch` arg is never dereferenced for a constant operand).
    struct DummyImg;
    impl LoadImage for DummyImg {
        fn get_file_name(&self) -> &str {
            "dummy"
        }
        fn load_fill(&mut self, _ptr: &mut [u8], _addr: &Address) -> KunaResult<()> {
            Err(KunaError::data_unavail("dummy"))
        }
        fn get_arch_type(&self) -> Vec<u8> {
            Vec::new()
        }
        fn adjust_vma(&mut self, _adjust: i64) {}
    }

    fn bare_arch() -> crate::architecture::Architecture {
        crate::architecture::Architecture::new(
            "t",
            Sleigh::new(Box::new(DummyImg), Box::new(ContextInternal::new())),
        )
    }

    fn build_manager() -> AddrSpaceManager {
        let mut m = AddrSpaceManager::new();
        m.insert_space(Rc::new(ConstantSpace::new())).unwrap();
        m.insert_space(Rc::new(UniqueSpace::new(1, 0, false))).unwrap();
        m.insert_space(Rc::new(AddrSpace::new(
            spacetype::IPTR_PROCESSOR,
            "ram",
            false,
            8,
            1,
            2,
            addrspace_flags::hasphysical,
            1,
            1,
        )))
        .unwrap();
        m
    }

    fn build_fd() -> Funcdata {
        let manage = build_manager();
        let glb = Rc::new(ContextArch::new(manage));
        let ram = Rc::clone(glb.manage().get_space_by_name("ram").unwrap());
        let addr = Address::new(ram, 0x1000);
        Funcdata::new("func", "func", glb, addr, 0x1000_0000, 0x40).unwrap()
    }

    fn ram(fd: &Funcdata) -> Rc<AddrSpace> {
        Rc::clone(fd.get_arch().manage().get_space_by_name("ram").unwrap())
    }

    /// A named base type whose `display_name` is `nm` (what `(nm)` must spell).
    fn named(nm: &str, size: int4, meta: type_metatype) -> crate::dtype::TypeRoot {
        let mut t = Datatype::new_with_align(size, -1, meta);
        t.name = nm.to_string();
        t.display_name = nm.to_string();
        t.id = Datatype::hash_name(nm);
        crate::dtype::TypeFactoryImpl::new().intern(t).unwrap()
    }

    fn mk_op(fd: &mut Funcdata, inputs: int4, off: u64, opc: OpCode) -> super::super::OpId {
        let r = ram(fd);
        let op = fd.new_op(inputs, Address::new(r, off));
        fd.obank_mut().change_opcode(op, TypeOp::new(opc, 0, format!("{opc:?}")));
        op
    }

    /// Build a 1-input cast op (`opc`) whose in0 is a constant `k` (renders as a
    /// literal, deterministic) and whose OUTPUT carries the data-type `out_ty`.
    fn build_cast_over_const(
        fd: &mut Funcdata,
        opc: OpCode,
        k: u64,
        out_ty: crate::dtype::TypeRoot,
    ) -> super::super::OpId {
        let r = ram(fd);
        let op = mk_op(fd, 1, 0x20, opc);
        let cst = fd.new_constant(8, k);
        fd.op_set_input(op, cst, 0).unwrap();
        let out = fd.new_varnode(out_ty.get_size(), &Address::new(r, 0x400), Some(out_ty));
        fd.op_set_output(op, out).unwrap();
        op
    }

    /// Drive the PRIVATE `op_type_cast_ir` on a fresh PrintC and return the text.
    /// The render `arch` is a throwaway bare `architecture::Architecture`: the
    /// constant-operand cast path never dereferences it (it only flows to
    /// `push_vn_explicit_ir`, whose constant arm ignores `arch`).
    fn render_cast(fd: &Funcdata, op: super::super::OpId, nocasts: bool) -> String {
        let arch = bare_arch();
        let mut p = PrintC::new();
        p.set_no_cast_printing(nocasts);
        p.set_output_stream();
        p.op_type_cast_ir(fd, &arch, op);
        p.emit_mut().output_str().to_string()
    }

    fn apply_callable_authority(
        proto: &mut crate::fspec::FuncProto, fd: &Funcdata,
        int_type: &crate::dtype::TypeRoot, authority: &str,
    ) {
        use crate::fspec::{parameter_pieces_flags, ParameterPieces};
        match authority {
            "override" => proto.set_override(true),
            "model" => proto.set_model_lock(true),
            "custom" => proto.set_custom_storage(true),
            "voidlock" => proto.set_void_input_lock(true),
            "output" => {
                proto.set_output_lock(true);
                // Isolate output authority from the setter's model-lock side effect.
                proto.set_model_lock(false);
            }
            "input" | "later" | "later_name" | "later_size" => {
                let locked_slot = int4::from(authority.starts_with("later"));
                let lock = match authority {
                    "later_name" => parameter_pieces_flags::NAMELOCK,
                    "later_size" => parameter_pieces_flags::SIZELOCK,
                    _ => parameter_pieces_flags::TYPELOCK,
                };
                for slot in 0..=locked_slot {
                    proto.set_param(slot, "argument", &ParameterPieces {
                        addr: Address::new(ram(fd), 0x80 + slot as u64 * 8),
                        type_: Some(int_type.clone()),
                        flags: if slot == locked_slot { lock } else { 0 },
                    });
                }
                assert!(!proto.is_model_locked(), "independent parameter lock witness");
                if locked_slot == 1 {
                    assert!(!proto.is_input_locked(), "aggregate first-input query misses this authority");
                }
            }
            _ => {}
        }
    }

    #[test]
    fn numeric_callable_projection_preserves_non_target_abi_and_pointer_views() {
        use crate::dtype::{DatatypeKind, TypeFactory, TypeFactoryImpl};
        use crate::fspec::{parameter_pieces_flags, FuncCallSpecs, FuncProto, ParameterPieces, ProtoModel};
        use crate::prettyprint::TokenKind;

        for case in [
            "plain", "call_abi", "view_abi", "call_open", "view_open",
            "argument", "ordinary_reader", "void_pointer", "object_pointer",
            "explicit_space", "truncated", "width_mismatch", "null",
            "call_override", "call_input", "call_later", "call_output",
            "call_model", "call_custom", "call_voidlock",
            "call_later_name", "call_later_size",
        ] {
            let mut fd = build_fd();
            let types = TypeFactoryImpl::new();
            types.setup_sizes(Some(4), 8, 8);
            for (name, size, meta) in [
                ("void", 1, type_metatype::TYPE_VOID),
                ("code", 1, type_metatype::TYPE_CODE),
                ("int4", 4, type_metatype::TYPE_INT),
            ] {
                types.set_core_type(name, size, meta, false).unwrap();
            }
            types.cache_core_types().unwrap();
            let void = types.get_type_void().unwrap();
            let mut model = ProtoModel::new(fd.get_arch().manage());
            model.build_param_list("standard").unwrap();
            let model = Rc::new(model);
            types.set_proto_context(Some(model.clone()), fd.get_arch().manage.clone()).unwrap();
            let mut signature = FuncProto::new();
            signature.set_internal(model, void.clone());
            let int_type = types.get_base(4, type_metatype::TYPE_INT).unwrap();
            if let Some(authority) = case.strip_prefix("call_") {
                apply_callable_authority(&mut signature, &fd, &int_type, authority);
            }
            if case == "call_abi" { signature.set_abi_first_vararg(Some(0)); }
            signature.set_dotdotdot(case == "call_open");
            let declaration = crate::fspec::LogicalCallable {
                binding: types.model_binding(None).unwrap(),
                output: void.id(),
                inputs: vec![],
                variadic: case == "view_open",
                input_closed: true,
                logical_first: (case == "view_abi").then_some(0),
                flags: 0,
            };
            let base = match case {
                "void_pointer" => void.clone(),
                "object_pointer" => types.get_base(4, type_metatype::TYPE_INT).unwrap(),
                _ => types.get_type_code_proto(&declaration).unwrap(),
            };
            let mut pointer = Datatype::new_with_align(8, -1, type_metatype::TYPE_PTR);
            pointer.kind = DatatypeKind::Pointer {
                ptrto: base.id(),
                spaceid: (case == "explicit_space").then(|| ram(&fd)),
                truncate: (case == "truncated").then(|| types.get_type_pointer(4, base, 1).unwrap().id()),
                wordsize: 1,
            };
            let pointer = types.intern(pointer).unwrap();
            if case == "argument" {
                signature.set_param(0, "callback", &ParameterPieces {
                    addr: Address::new(ram(&fd), 0x80),
                    type_: Some(pointer.clone()),
                    flags: parameter_pieces_flags::TYPELOCK,
                });
            }
            let value = fd.new_constant(
                if case == "width_mismatch" { 4 } else { 8 },
                if case == "null" { 0 } else { 0x200000 },
            );
            let reader = mk_op(&mut fd, signature.num_params() + 1, 0x1000,
                if case == "ordinary_reader" { OpCode::CPUI_COPY } else { OpCode::CPUI_CALLIND });
            let slot = if case == "argument" { 1 } else { 0 };
            if case == "argument" {
                let other_target = fd.new_constant(8, 0x100000);
                fd.op_set_input(reader, other_target, 0).unwrap();
            }
            fd.op_set_input(reader, value, slot).unwrap();
            if case != "argument" {
                for slot in 0..signature.num_params() {
                    let argument = fd.new_constant(4, slot as u64 + 7);
                    fd.op_set_input(reader, argument, slot + 1).unwrap();
                }
            }
            fd.vn_update_type(value, pointer.clone());
            if case != "ordinary_reader" {
                let mut specs = FuncCallSpecs::new(reader, Address::new_invalid());
                specs.proto_mut().copy(&signature);
                fd.push_call_specs(specs);
            }
            fd.set_high_level();
            let mut arch = bare_arch();
            arch.types_impl().setup_sizes(Some(4), 8, 8);
            arch.types_impl().set_core_type("code", 1, type_metatype::TYPE_CODE, false).unwrap();
            arch.types_impl().cache_core_types().unwrap();
            for native in [false, true, false] {
                arch.ctypes = native;
                let mut print = PrintC::new();
                print.rt_ctx = RealTypeCtx::from_arch(&arch, crate::kuna_lang::OutLang::C, print.options.convention);
                print.options.null = case == "null";
                print.set_markup(true);
                print.emit_mut().set_capture_tokens(true);
                print.push_vn_explicit_ir(&fd, &arch, value, reader);
                print.recurse();
                let tokens = print.emit_mut().take_markup_tokens();
                let conversions: Vec<_> = tokens.iter()
                    .filter(|token| token.kind == TokenKind::Type).collect();
                if case == "null" {
                    assert!(conversions.is_empty(), "NULL handling precedes callable projection");
                    assert!(tokens.iter().any(|token| token.text == "NULL"));
                } else {
                    assert_eq!(conversions.len(), 1, "{case}, ctypes={native}");
                    let spelling = &conversions[0].text;
                    match case {
                        "void_pointer" => assert_eq!(spelling, "void *"),
                        "object_pointer" => assert!(!spelling.contains("code") && !spelling.contains('('),
                            "object pointer must not become a callable view: {spelling}"),
                        _ => assert!(spelling.contains('('),
                            "{case}, ctypes={native}: concrete callable view was erased: {spelling}"),
                    }
                }
                let unchanged = fd.vbank().get(value).unwrap();
                assert!(unchanged.is_constant());
                assert!(unchanged.get_def().is_none());
                assert_eq!(unchanged.get_type(), &pointer,
                    "{case}: rendering must not replace the semantic constant datatype");
                assert_eq!(fd.obank().get(reader).unwrap().get_in(slot), Some(value));
            }
        }
    }

    #[test]
    fn recovered_callable_projection_retains_cast_provenance_and_authority() {
        use crate::cast::CastStrategyC;
        use crate::dtype::{TypeFactory, TypeFactoryImpl};
        use crate::fspec::{FuncCallSpecs, LogicalCallable, ParameterPieces, ProtoModel};
        use crate::p9_emit::coreaction_casts::get_input_cast;
        use crate::prettyprint::TokenKind;

        for source_kind in ["generic", "integer", "declared"] {
            let mut context = ContextArch::new(build_manager());
            let types = Rc::new(TypeFactoryImpl::new());
            types.setup_sizes(Some(4), 8, 8);
            for (name, size, meta) in [
                ("void", 1, type_metatype::TYPE_VOID),
                ("code", 1, type_metatype::TYPE_CODE),
                ("int4", 4, type_metatype::TYPE_INT),
                ("uint8", 8, type_metatype::TYPE_UINT),
            ] {
                types.set_core_type(name, size, meta, false).unwrap();
            }
            types.cache_core_types().unwrap();
            let mut model = ProtoModel::new(context.manage());
            model.build_param_list("standard").unwrap();
            let model = Rc::new(model);
            types.set_proto_context(Some(model.clone()), context.manage.clone()).unwrap();
            context.types = Some(types.clone());
            let entry = Address::new(context.manage().get_space_by_name("ram").unwrap().clone(), 0x1000);
            let mut fd = Funcdata::new("func", "func", Rc::new(context), entry, 0x1000_0000, 0x40).unwrap();
            let void = types.get_type_void().unwrap();
            let int4 = types.get_base(4, type_metatype::TYPE_INT).unwrap();
            let generic = types.get_type_pointer(8, types.get_type_code().unwrap(), 1).unwrap();
            let source_type = match source_kind {
                "integer" => types.get_base(8, type_metatype::TYPE_UINT).unwrap(),
                "declared" => {
                    let code = types.get_type_code_proto(&LogicalCallable {
                        binding: types.model_binding(None).unwrap(), output: int4.id(),
                        inputs: vec![], variadic: false, input_closed: true,
                        logical_first: None, flags: 0,
                    }).unwrap();
                    types.get_type_pointer(8, code, 1).unwrap()
                }
                _ => generic,
            };
            let address = Address::new(ram(&fd), 0x400);
            let source = fd.new_varnode(8, &address, Some(source_type.clone()));
            let source = fd.set_input_varnode(source).unwrap();
            fd.get_func_proto_mut().set_internal(model.clone(), void.clone());
            fd.get_func_proto_mut().set_param(0, "target", &ParameterPieces {
                addr: address, type_: Some(source_type), flags: 0,
            });
            let call = mk_op(&mut fd, 2, 0x1000, OpCode::CPUI_CALLIND);
            let argument = fd.new_constant(4, 7);
            fd.vn_update_type(argument, int4);
            fd.op_set_input(call, source, 0).unwrap();
            fd.op_set_input(call, argument, 1).unwrap();
            let mut specs = FuncCallSpecs::new(call, Address::new_invalid());
            specs.proto_mut().set_internal(model, void);
            let index = fd.num_calls();
            fd.push_call_specs(specs);
            fd.set_high_level();
            let strategy = CastStrategyC::new(types);
            let destination = get_input_cast(&mut fd, &strategy, call, 0).unwrap();
            let cast = mk_op(&mut fd, 1, 0x1000, OpCode::CPUI_CAST);
            fd.op_set_input(cast, source, 0).unwrap();
            let output = fd.new_unique(8, Some(destination.clone()));
            fd.op_set_output(cast, output).unwrap();
            fd.op_set_input(call, output, 0).unwrap();

            let mut arch = bare_arch();
            arch.types_impl().setup_sizes(Some(4), 8, 8);
            arch.types_impl().set_core_type("code", 1, type_metatype::TYPE_CODE, false).unwrap();
            arch.types_impl().cache_core_types().unwrap();
            for repeat in [false, true] {
                if repeat {
                    assert!(get_input_cast(&mut fd, &strategy, call, 0).is_none());
                }
                for native in [false, true] {
                    arch.ctypes = native;
                    let mut print = PrintC::new();
                    print.rt_ctx = RealTypeCtx::from_arch(&arch, crate::kuna_lang::OutLang::C, print.options.convention);
                    print.set_markup(true);
                    print.emit_mut().set_capture_tokens(true);
                    print.op_type_cast_ir(&fd, &arch, cast);
                    let tokens = print.emit_mut().take_markup_tokens();
                    let conversions: Vec<_> = tokens.iter().filter(|t| t.kind == TokenKind::Type).collect();
                    if !native && source_kind == "generic" {
                        assert!(conversions.is_empty(), "inferred generic target needs no visible conversion: {tokens:?}");
                    } else if !native && source_kind == "integer" {
                        assert_eq!(conversions.len(), 1);
                        assert_eq!(conversions[0].text, "code *");
                    } else {
                        assert_eq!(conversions.len(), 1);
                        assert!(conversions[0].text.contains('('), "concrete signature conversion lost: {tokens:?}");
                    }
                    assert_eq!(fd.vbank().get(output).unwrap().get_type(), &destination);
                }
            }
            assert!(fd.get_call_specs(index).clone_for_op(call).inferred_target_view().is_none());
            fd.get_call_specs_mut(index).proto_mut().set_override(true);
            arch.ctypes = false;
            let mut print = PrintC::new();
            print.rt_ctx = RealTypeCtx::from_arch(&arch, crate::kuna_lang::OutLang::C, print.options.convention);
            assert!(print.callable_dialect_code(&fd, &arch, call, output, &destination).is_none());
        }
    }

    #[test]
    fn callable_dialect_cast_preserves_explicit_semantic_declaration() {
        use crate::dtype::{TypeFactory, TypeFactoryImpl};
        use crate::fspec::{parameter_pieces_flags, FuncCallSpecs, FuncProto, ParameterPieces, ProtoModel};
        use crate::prettyprint::TokenKind;

        for case in [
            "plain", "second_use", "narrow_pointer", "word_addressed",
            "abi_boundary", "open_tail", "concrete_source", "declared_void",
            "call_abi", "view_abi", "call_open", "view_open",
            "scalar", "scalar_constant", "scalar_unknown", "scalar_callother",
            "scalar_narrow", "scalar_abi", "scalar_open",
            "call_override", "call_input", "call_later", "call_output",
            "call_model", "call_custom", "call_later_name", "call_later_size",
        ] {
            let scalar_source = case.starts_with("scalar");
            let mut fd = build_fd();
            let types = TypeFactoryImpl::new();
            types.setup_sizes(Some(4), 8, 8);
            for (name, size, meta) in [
                ("void", 1, type_metatype::TYPE_VOID),
                ("code", 1, type_metatype::TYPE_CODE),
                ("int4", 4, type_metatype::TYPE_INT),
                ("uint4", 4, type_metatype::TYPE_UINT),
                ("uint8", 8, type_metatype::TYPE_UINT),
                ("xunknown1", 1, type_metatype::TYPE_UNKNOWN),
                ("xunknown8", 8, type_metatype::TYPE_UNKNOWN),
            ] {
                types.set_core_type(name, size, meta, false).unwrap();
            }
            types.cache_core_types().unwrap();
            let void = types.get_type_void().unwrap();
            let int4 = types.get_base(4, type_metatype::TYPE_INT).unwrap();
            let mut model = ProtoModel::new(fd.get_arch().manage());
            model.build_param_list("standard").unwrap();
            let model = Rc::new(model);
            types.set_proto_context(Some(model.clone()), fd.get_arch().manage.clone()).unwrap();
            let mut signature = FuncProto::new();
            signature.set_internal(Rc::clone(&model), void.clone());
            signature.set_param(0, "argument", &ParameterPieces {
                addr: Address::new(ram(&fd), 0x80), type_: Some(int4.clone()),
                flags: 0,
            });
            if matches!(case, "abi_boundary" | "scalar_abi" | "call_abi") {
                signature.set_abi_first_vararg(Some(1));
            }
            signature.set_dotdotdot(matches!(case, "open_tail" | "scalar_open" | "call_open"));
            if let Some(authority) = case.strip_prefix("call_") {
                apply_callable_authority(&mut signature, &fd, &int4, authority);
            }
            let declaration = crate::fspec::LogicalCallable {
                binding: types.model_binding(None).unwrap(),
                output: void.id(),
                inputs: vec![int4.id()],
                variadic: matches!(case, "open_tail" | "scalar_open" | "view_open"),
                input_closed: true,
                logical_first: matches!(case, "abi_boundary" | "scalar_abi" | "view_abi").then_some(1),
                flags: 0,
            };
            let destination = types.get_type_pointer(
                8, types.get_type_code_proto(&declaration).unwrap(), 1).unwrap();
            let source_base = if case == "concrete_source" {
                let concrete = crate::fspec::LogicalCallable {
                    inputs: vec![], variadic: false, logical_first: None, ..declaration.clone()
                };
                types.get_type_code_proto(&concrete).unwrap()
            } else {
                types.get_type_code().unwrap()
            };
            let source_type = if scalar_source {
                types.get_base(
                    if case == "scalar_narrow" { 4 } else { 8 },
                    if case == "scalar_unknown" || case == "scalar_callother" {
                        type_metatype::TYPE_UNKNOWN
                    } else { type_metatype::TYPE_UINT },
                ).unwrap()
            } else {
                types.get_type_pointer(
                    if case == "narrow_pointer" { 4 } else { 8 },
                    source_base,
                    if case == "word_addressed" { 2 } else { 1 },
                ).unwrap()
            };
            let source_address = Address::new(ram(&fd), 0x400);
            let source = if case == "scalar_constant" {
                let value = fd.new_constant(8, 0x200000);
                fd.vn_update_type(value, source_type.clone());
                value
            } else if case == "scalar_callother" {
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
                let value = fd.new_varnode(
                    source_type.get_size(), &source_address, Some(source_type.clone()),
                );
                fd.set_input_varnode(value).unwrap()
            };
            fd.get_func_proto_mut().set_internal(Rc::clone(&model), void.clone());
            fd.get_func_proto_mut().set_param(0, "callback", &ParameterPieces {
                addr: source_address,
                type_: Some(if case == "declared_void" {
                    types.get_type_pointer(8, void, 1).unwrap()
                } else { source_type.clone() }),
                flags: parameter_pieces_flags::TYPELOCK | parameter_pieces_flags::NAMELOCK,
            });
            let cast = mk_op(&mut fd, 1, 0x1000, OpCode::CPUI_CAST);
            fd.op_set_input(cast, source, 0).unwrap();
            let output = fd.new_unique(8, Some(destination));
            fd.op_set_output(cast, output).unwrap();
            let call = mk_op(&mut fd, signature.num_params() + 1, 0x1000, OpCode::CPUI_CALLIND);
            fd.op_set_input(call, output, 0).unwrap();
            for slot in 0..signature.num_params() {
                let argument = fd.new_constant(4, slot as u64 + 7);
                fd.op_set_input(call, argument, slot + 1).unwrap();
            }
            let mut specs = FuncCallSpecs::new(call, Address::new_invalid());
            specs.proto_mut().copy(&signature);
            fd.push_call_specs(specs);
            if case == "second_use" {
                let another = mk_op(&mut fd, 1, 0x1004, OpCode::CPUI_COPY);
                fd.op_set_input(another, output, 0).unwrap();
            }
            fd.set_high_level();
            let mut arch = bare_arch();
            arch.types_impl().setup_sizes(Some(4), 8, 8);
            arch.types_impl().set_core_type("code", 1, type_metatype::TYPE_CODE, false).unwrap();
            arch.types_impl().cache_core_types().unwrap();
            for native in [false, true, false] {
                arch.ctypes = native;
                let mut print = PrintC::new();
                print.rt_ctx = RealTypeCtx::from_arch(&arch, crate::kuna_lang::OutLang::C, print.options.convention);
                print.set_markup(true);
                print.emit_mut().set_capture_tokens(true);
                print.op_type_cast_ir(&fd, &arch, cast);
                let tokens = print.emit_mut().take_markup_tokens();
                let casts = tokens.iter().filter(|token| token.kind == TokenKind::Type).count();
                assert_eq!(casts, 1, "{case}, ctypes={native}");
                let conversion = tokens.iter().find(|token| token.kind == TokenKind::Type).unwrap();
                assert!(conversion.text.contains('(') && conversion.text.contains(if native { "int" } else { "int4" }),
                    "explicit logical inputs must survive rendering: {case}: {conversion:?}");
                assert_eq!(fd.obank().get(call).unwrap().get_in(0), Some(output));
                assert_eq!(fd.obank().get(cast).unwrap().get_in(0), Some(source));
                assert_eq!(fd.obank().get(cast).unwrap().code(), OpCode::CPUI_CAST);
                if case == "declared_void" {
                    assert_eq!(fd.vbank().get(source).unwrap().get_type()
                        .get_ptr_to().unwrap().get_metatype(), type_metatype::TYPE_CODE);
                    assert_eq!(fd.get_func_proto().get_param(0).unwrap().get_type().unwrap()
                        .get_ptr_to().unwrap().get_metatype(), type_metatype::TYPE_VOID);
                }
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
            "copy_loaded", "abi_boundary",
        ] {
            let mut fd = build_fd();
            let types = TypeFactoryImpl::new();
            types.setup_sizes(Some(4), 8, 8);
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
            } else { declaration.clone() }));
            let table = fd.set_input_varnode(table).unwrap();
            let mut model = ProtoModel::new(fd.get_arch().manage());
            model.build_param_list("standard").unwrap();
            let model = Rc::new(model);
            types.set_proto_context(Some(model.clone()), fd.get_arch().manage.clone()).unwrap();
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
                    types.intern(Datatype::new(8, type_metatype::TYPE_UNKNOWN)).unwrap()
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
            if case == "abi_boundary" { signature.set_abi_first_vararg(Some(1)); }
            let declaration = crate::fspec::LogicalCallable {
                binding: types.model_binding(None).unwrap(),
                output: void.id(),
                inputs: vec![types.get_base(4, type_metatype::TYPE_INT).unwrap().id()],
                variadic: false,
                input_closed: true,
                logical_first: (case == "abi_boundary").then_some(1),
                flags: 0,
            };
            let destination = types.get_type_pointer(
                8, types.get_type_code_proto(&declaration).unwrap(), 1).unwrap();
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
            let mut arch = bare_arch();
            arch.types_impl().setup_sizes(Some(4), 8, 8);
            arch.types_impl().set_core_type("code", 1, type_metatype::TYPE_CODE, false).unwrap();
            arch.types_impl().cache_core_types().unwrap();
            for native in [false, true, false] {
                arch.ctypes = native;
                let mut print = PrintC::new();
                print.rt_ctx = RealTypeCtx::from_arch(&arch, crate::kuna_lang::OutLang::C, print.options.convention);
                print.set_markup(true);
                print.emit_mut().set_capture_tokens(true);
                print.op_type_cast_ir(&fd, &arch, cast);
                let tokens = print.emit_mut().take_markup_tokens();
                let conversions = tokens.iter().filter(|token| token.kind == TokenKind::Type).count();
                let inner = usize::from(case == "visible_cast");
                assert_eq!(conversions, inner + 1,
                    "{case}, ctypes={native}: {tokens:?}");
                let outer = tokens.iter().find(|token| token.kind == TokenKind::Type).unwrap();
                assert!(outer.text.contains('('),
                    "explicit signatures must survive loaded callable rendering: {case}: {tokens:?}");
                assert_eq!(fd.obank().get(cast).unwrap().code(), OpCode::CPUI_CAST);
                assert_eq!(fd.obank().get(cast).unwrap().get_in(0), Some(source));
                assert_eq!(fd.obank().get(call).unwrap().get_in(0), Some(output));
            }
        }
    }

    /// FAITHFULNESS (1a): a `CPUI_CAST` whose output is `int8` renders
    /// `(int8)<operand>` — the `(` `)` typecast token (printc.cc:36) wrapping the
    /// type name from the OUTPUT varnode and the in0 operand.
    #[test]
    fn cast_renders_output_type_int8() {
        let mut fd = build_fd();
        let op = build_cast_over_const(
            &mut fd,
            OpCode::CPUI_CAST,
            0x2a,
            named("int8", 8, type_metatype::TYPE_INT),
        );
        assert_eq!(render_cast(&fd, op, false), "(int8)0x2a", "CAST -> (int8)operand");
    }

    /// FAITHFULNESS (1b) — the ANTI-HARDCODE contrast: the SAME opcode and the
    /// SAME constant operand, but the OUTPUT varnode is `float4` instead of
    /// `int8`, must render `(float4)...`.  If the cast text were keyed on the
    /// opcode (or hardcoded), this would still say `(int8)` — it must not.  This
    /// is the test the `op->getOut()->getHighTypeDefFacing()` plumbing exists to
    /// pass and a special-case would fail.
    #[test]
    fn cast_text_follows_output_type_not_opcode() {
        let mut fd = build_fd();
        let op = build_cast_over_const(
            &mut fd,
            OpCode::CPUI_CAST,
            0x2a,
            named("float4", 4, type_metatype::TYPE_FLOAT),
        );
        let out = render_cast(&fd, op, false);
        assert_eq!(out, "(float4)0x2a", "cast text must come from the OUTPUT type");
        assert!(!out.contains("int8"), "cast text must NOT be a hardcoded/opcode-keyed name");
        // A second, exotic type-name proves it is the varnode display-name verbatim.
        let mut fd2 = build_fd();
        let op2 = build_cast_over_const(
            &mut fd2,
            OpCode::CPUI_CAST,
            0x7,
            named("MyWeirdType", 8, type_metatype::TYPE_UNKNOWN),
        );
        assert_eq!(render_cast(&fd2, op2, false), "(MyWeirdType)7");
    }

    /// FAITHFULNESS (2): all THREE opcodes that route through opTypeCast
    /// (CPUI_CAST / CPUI_FLOAT_FLOAT2FLOAT / CPUI_FLOAT_TRUNC, printc.hh:332-341)
    /// render the SAME cast-notation form `(T)operand` — none of them emits the
    /// functional `OPC(args)`.  (op_emit_kind routes them all to TypeCast; this
    /// confirms the rendered text, not just the table cell.)
    #[test]
    fn all_three_typecast_opcodes_render_cast_notation() {
        for opc in [
            OpCode::CPUI_CAST,
            OpCode::CPUI_FLOAT_FLOAT2FLOAT,
            OpCode::CPUI_FLOAT_TRUNC,
        ] {
            let mut fd = build_fd();
            let op = build_cast_over_const(
                &mut fd,
                opc,
                0x9,
                named("float8", 8, type_metatype::TYPE_FLOAT),
            );
            let out = render_cast(&fd, op, false);
            assert_eq!(out, "(float8)9", "{opc:?} must render (float8)operand");
            // The opcode name must NOT appear as a functional call `OPC(...)`.
            assert!(
                !out.contains("CAST") && !out.contains("FLOAT"),
                "{opc:?} must NOT render the functional OPC(args) form: {out}"
            );
        }
    }

    /// PARENTHESIZATION (3): the cast over a LOWER-precedence operand
    /// subexpression must parenthesize the operand.  `typecast` is a presurround
    /// op-token at precedence 2 (printc.cc:36); an `INT_ADD` (`+`, prec ~19,
    /// lower) operand pushed under it forces `(T)(a + b)`.  Here the operand is a
    /// nested implied INT_ADD whose two inputs are constants, so the operand
    /// renders `0x1 + 0x2`; the cast must wrap it in parentheses.
    #[test]
    fn cast_parenthesizes_lower_precedence_operand() {
        let mut fd = build_fd();
        let r = ram(&fd);
        // out = CAST( add ), add = INT_ADD(1, 2), `add`'s output is implied so
        // pushVn recurses into the INT_ADD (the binary `0x1 + 0x2`).
        let add = mk_op(&mut fd, 2, 0x10, OpCode::CPUI_INT_ADD);
        let c1 = fd.new_constant(8, 1);
        let c2 = fd.new_constant(8, 2);
        fd.op_set_input(add, c1, 0).unwrap();
        fd.op_set_input(add, c2, 1).unwrap();
        let mid = fd.new_varnode(8, &Address::new(Rc::clone(&r), 0x300), Some(named("int8", 8, type_metatype::TYPE_INT)));
        fd.op_set_output(add, mid).unwrap();
        let mid = fd.obank().get(add).unwrap().get_out().unwrap();
        fd.vbank_mut().get_mut(mid).unwrap().set_implied();
        let cast = mk_op(&mut fd, 1, 0x20, OpCode::CPUI_CAST);
        fd.op_set_input(cast, mid, 0).unwrap();
        let out = fd.new_varnode(8, &Address::new(r, 0x400), Some(named("float8", 8, type_metatype::TYPE_FLOAT)));
        fd.op_set_output(cast, out).unwrap();
        let rendered = render_cast(&fd, cast, false);
        assert_eq!(
            rendered, "(float8)(1 + 2)",
            "a lower-precedence operand must be parenthesized under the cast"
        );
    }

    /// `option_nocasts` GATE: with nocasts set, the `(T)` half is suppressed and
    /// ONLY the operand prints — the underlying value flows through (printc.cc:479
    /// `if (!option_nocasts)`).  This pins the gate so a port that always emitted
    /// the cast (or always dropped it) is caught.
    #[test]
    fn nocasts_suppresses_the_cast_keeps_operand() {
        let mut fd = build_fd();
        let op = build_cast_over_const(
            &mut fd,
            OpCode::CPUI_CAST,
            0x2a,
            named("int8", 8, type_metatype::TYPE_INT),
        );
        assert_eq!(render_cast(&fd, op, true), "0x2a", "nocasts: only the operand prints");
        // And with casts ON the SAME op DOES wear the cast (control).
        assert_eq!(render_cast(&fd, op, false), "(int8)0x2a");
    }


    #[derive(Clone, Copy)]
    enum LogicalInputs { Tag, MethodByValue, Variadic }

    #[derive(Clone, Copy)]
    enum LogicalResultUse { Discarded, ExplicitPointer, ImpliedPointer, NestedPointer }

    fn named_call_input(
        fd: &mut Funcdata, name: &str, ty: crate::dtype::TypeRoot,
    ) -> crate::context::VarnodeId {
        let slot = fd.get_func_proto().num_params();
        let addr = Address::new(ram(fd), 0x800 + slot as u64 * 0x20);
        fd.get_func_proto_mut().set_param(slot, name, &crate::fspec::ParameterPieces {
            addr: addr.clone(), type_: Some(ty.clone()),
            flags: crate::fspec::parameter_pieces_flags::TYPELOCK
                | crate::fspec::parameter_pieces_flags::NAMELOCK,
        });
        fd.link_proto_params();
        let vn = fd.new_varnode(ty.get_size(), &addr, Some(ty));
        let vn = fd.set_input_varnode(vn).unwrap();
        fd.vbank_mut().get_mut(vn).unwrap().set_explicit();
        let high = fd.vbank().get(vn).unwrap().get_high().unwrap();
        fd.high_bank_mut().get_mut(high).unwrap().set_kuna_name(name);
        vn
    }

    fn name_call_local(fd: &mut Funcdata, vn: crate::context::VarnodeId, name: &str) {
        fd.vbank_mut().get_mut(vn).unwrap().set_explicit();
        let high = fd.vbank().get(vn).unwrap().get_high().unwrap();
        fd.high_bank_mut().get_mut(high).unwrap().set_kuna_name(name);
    }

    // Execution tests live alongside the private IR fixtures: no textual repair
    // of a printed expression is permitted before it reaches the compiler.
    fn execute_language_source(language: &str, source: &str, label: &str) {
        use std::process::Command;
        let compiler = if language == "rust" { "rustc" } else { "cc" };
        match Command::new(compiler).arg("--version").output() {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                eprintln!("language execution {label}: skipping (missing `{compiler}`)");
                return;
            }
            Err(e) => panic!("starting {compiler}: {e}"),
            Ok(out) => assert!(out.status.success(), "{compiler} --version failed: {out:?}"),
        }
        let dir = std::env::temp_dir()
            .join(format!("kuna-language-{}-{label}-{language}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let input = dir.join(if language == "rust" { "consumer.rs" } else { "consumer.c" });
        std::fs::write(&input, source).unwrap();
        for optimization in ["0", "2"] {
            let exe = dir.join(format!("consumer-{optimization}"));
            let mut cmd = Command::new(compiler);
            if language == "rust" {
                cmd.args(["--edition=2021", "-A", "warnings", "-C"])
                    .arg(format!("opt-level={optimization}"));
                // Debug deliberately retains overflow checks; optimized matches
                // the compiler default, not an overflow-suppressing test flag.
            } else {
                cmd.args(["-std=c11", "-Wall", "-Wextra"]).arg(format!("-O{optimization}"));
            }
            let out = cmd.arg(&input).arg("-o").arg(&exe).output().unwrap();
            assert!(out.status.success(), "{label}/{language}/O{optimization}:\n{}\n{source}",
                String::from_utf8_lossy(&out.stderr));
            let out = Command::new(&exe).output().unwrap();
            assert!(out.status.success(), "{label}/{language}/O{optimization}:\n{}\n{source}",
                String::from_utf8_lossy(&out.stderr));
        }
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn emitted_enum_complements_preserve_width_sign_and_partial_parent() {
        use crate::dtype::{flags, DatatypeKind, TypeFactory, TypeFactoryImpl};
        use std::collections::BTreeMap;
        let arch = bare_arch();
        let types = TypeFactoryImpl::new();
        types.setup_sizes(Some(4), 8, 8);
        types.set_core_type("uint4", 4, type_metatype::TYPE_UINT, false).unwrap();
        types.set_core_type("uint8", 8, type_metatype::TYPE_UINT, false).unwrap();
        types.cache_core_types().unwrap();
        let mut c = String::from("#include <assert.h>\n#include <stdint.h>\n");
        let mut rust = String::new();
        let mut c_checks = String::new();
        let mut rust_checks = String::new();
        for size in [1, 2, 4, 8] {
            for signed in [false, true] {
                let bits = size * 8;
                let suffix = if signed { "s" } else { "u" };
                let name = format!("Flags{bits}{suffix}");
                let one = format!("{name}_ONE");
                let two = format!("{name}_TWO");
                let wide = format!("{name}_WIDE");
                let minimum = if signed { -(1i128 << (bits - 1)) } else { 0 };
                let maximum = if signed { (1u64 << (bits - 1)) - 1 }
                    else { kuna_base::address::calc_mask(size) };
                let min_c = if size == 8 && signed {
                    "(-9223372036854775807LL-1)".to_string()
                } else { minimum.to_string() };
                c.push_str(&format!(
                    "typedef enum __attribute__((packed)) {name} {{ {one}=1, {two}=2, {wide}={}, {name}_MIN={min_c}, {name}_MAX={maximum}ULL }} {name};\n_Static_assert(sizeof({name})=={size}, \"width\");\n_Static_assert((({name})-1<0)=={}, \"sign\");\n",
                    if size == 8 { "2147483648ULL" } else { "4" }, u8::from(signed),
                ));
                let scalar = format!("{}{bits}", if signed { 'i' } else { 'u' });
                rust.push_str(&format!(
                    "const {one}: {scalar}=1; const {two}: {scalar}=2; const {wide}: {scalar}={};\n",
                    if size == 8 { "2147483648" } else { "4" },
                ));
                let mut data = Datatype::new_with_align(size, size, if signed {
                    type_metatype::TYPE_INT
                } else { type_metatype::TYPE_UINT });
                data.name = name.clone();
                data.id = Datatype::hash_name(&name);
                data.display_name = name;
                data.flags |= flags::enumtype;
                data.kind = DatatypeKind::Enum { namemap: BTreeMap::from([
                    (1, one), (2, two), (if size == 8 { 0x8000_0000 } else { 4 }, wide),
                ]) };
                let ty = types.intern(data).unwrap();
                for flag in [1, 3, if size == 8 { 0x8000_0000 } else { 4 }] {
                    let value = kuna_base::address::calc_mask(size) ^ flag;
                    let expected = if signed {
                        (value as i128 - (1i128 << bits)).to_string()
                    } else { value.to_string() };
                    for is_rust in [false, true] {
                        let mut print = execution_printer(&arch, is_rust);
                        print.push_enum_constant_ir(&types, &ty, value, OpId::default(), VarnodeId::default(), false);
                        let expression = print.emit_mut().output_str().to_string();
                        if is_rust {
                            rust_checks.push_str(&format!("assert_eq!({expression}, {expected}{scalar});\n"));
                        } else {
                            c_checks.push_str(&format!("assert(({expression}) == ({expected}{}));\n",
                                if signed { "LL" } else { "ULL" }));
                        }
                    }
                }
            }
        }
        // Upper bytes cover complements, positive and negative named parents,
        // and a zero enumerator that still needs a width-valid shift.
        let mut data = Datatype::new_with_align(8, 8, type_metatype::TYPE_INT);
        data.name = "Parent".into();
        data.display_name = "Parent".into();
        data.id = Datatype::hash_name("Parent");
        data.flags |= flags::enumtype;
        data.kind = DatatypeKind::Enum { namemap: BTreeMap::from([
            (0, "PARENT_ZERO".into()),
            (0x1_ffff_ffff, "PARENT_LOW".into()),
            (0x300_0000_0000, "PARENT_HIGH".into()),
            (0x8000_0000_0000_0000, "PARENT_SIGN".into()),
        ]) };
        let parent = types.intern(data).unwrap();
        let partial = types.get_type_partial_enum(parent, 4, 4).unwrap();
        c.push_str("typedef unsigned int uint4;\ntypedef unsigned long long uint8;\nenum Parent { PARENT_ZERO=0, PARENT_LOW=8589934591LL, PARENT_HIGH=0x30000000000LL, PARENT_SIGN=(-9223372036854775807LL-1) };\n");
        rust.push_str("const PARENT_ZERO:i64=0; const PARENT_LOW:i64=8589934591; const PARENT_HIGH:i64=0x30000000000; const PARENT_SIGN:i64=i64::MIN;\n");
        for value in [0xffff_fffe, 0, 0x300, 0x8000_0000] {
            for is_rust in [false, true] {
                let mut print = execution_printer(&arch, is_rust);
                print.push_enum_constant_ir(&types, &partial, value, OpId::default(), VarnodeId::default(), false);
                let expression = print.emit_mut().output_str().to_string();
                if is_rust {
                    rust_checks.push_str(&format!("assert_eq!({expression}, {value}u32);\n"));
                } else {
                    c_checks.push_str(&format!(
                        "assert(({expression}) == {value}ULL);\nassert(!(({expression}) < (int64_t)-1));\n",
                    ));
                }
            }
        }
        c.push_str(&format!("int main(void){{ {c_checks} return 0; }}\n"));
        rust.push_str(&format!("fn main(){{ {rust_checks} }}\n"));
        execute_language_source("c", &c, "enum-complement-width");
        execute_language_source("rust", &rust, "enum-complement-width");
    }

    #[test]
    fn emitted_default_high_characters_match_declared_byte_values() {
        let fd = build_fd();
        let arch = bare_arch();
        let mut c = String::from("#include <assert.h>\nint main(void){\n");
        let mut rust = String::from("fn main(){\n");
        for signed in [false, true] {
            let mut data = Datatype::new_with_align(1, 1, if signed {
                type_metatype::TYPE_INT
            } else { type_metatype::TYPE_UINT });
            data.flags |= crate::dtype::flags::chartype;
            let ty = crate::dtype::TypeFactoryImpl::new().intern(data).unwrap();
            for value in [0, 0x41, 0x7f, 0x80, 0xfe, 0xff] {
                for is_rust in [false, true] {
                    let mut print = execution_printer(&arch, is_rust);
                    print.push_char_constant_ir(&fd, &ty, value, OpId::default(), VarnodeId::default());
                    let expression = print.emit_mut().output_str().to_string();
                    if is_rust {
                        rust.push_str(&format!("assert_eq!({expression}, {value}u8);\n"));
                    } else {
                        let expected = if signed { value as u8 as i8 as i32 } else { value as i32 };
                        c.push_str(&format!("assert(({expression}) == {expected});\n"));
                    }
                }
            }
        }
        c.push_str("return 0;}\n");
        rust.push_str("}\n");
        execute_language_source("c", &c, "default-high-character");
        execute_language_source("rust", &rust, "default-high-character");
    }

    fn execution_input(fd: &mut Funcdata, name: &str, ty: crate::dtype::TypeRoot)
        -> crate::context::VarnodeId
    {
        let vn = fd.new_unique(ty.get_size(), Some(ty));
        name_call_local(fd, vn, name);
        vn
    }

    fn execution_printer(arch: &crate::architecture::Architecture, rust: bool) -> PrintC {
        let lang = if rust { crate::kuna_lang::OutLang::Rust } else { crate::kuna_lang::OutLang::C };
        let mut print = PrintC::new();
        print.set_name(lang.print_name());
        print.rt_ctx = RealTypeCtx::from_arch(arch, lang, print.options.convention);
        print.set_output_stream();
        print
    }

    fn execution_call(
        fd: &mut Funcdata, name: &str, ty: crate::dtype::TypeRoot, offset: u64,
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
        execute_language_source("rust", &source, "single-evaluation");
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
        execute_language_source("rust", &source, "u128-variable");
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
        execute_language_source("rust", &source, "narrow-before-widening");
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
        let cell = types.intern(Datatype::new(4, type_metatype::TYPE_UINT)).unwrap();
        let pointer = types.get_type_pointer(8, cell, 1).unwrap();
        let index = types.intern(Datatype::new(8, type_metatype::TYPE_INT)).unwrap();
        let mut fd = build_fd();
        fd.set_high_level();
        let p = execution_input(&mut fd, "p", pointer.clone());
        let i = execution_call(&mut fd, "next_index", index, 0x1000);
        let add = mk_op(&mut fd, 3, 0x1004, OpCode::CPUI_PTRADD);
        let stride = fd.new_constant(8, 8); // deliberately not sizeof(u32)
        fd.op_set_input(add, p, 0).unwrap();
        fd.op_set_input(add, i, 1).unwrap();
        fd.op_set_input(add, stride, 2).unwrap();
        let result = fd.new_unique(8, Some(pointer));
        fd.op_set_output(add, result).unwrap();
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
        execute_language_source("rust", &source, "stride-single-evaluation");
    }

    #[test]
    fn emitted_rust_pointer_rejects_a_different_host_address_width() {
        use crate::dtype::TypeFactory;
        use std::process::Command;
        match Command::new("rustc").arg("--version").output() {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                eprintln!("language width rejection: skipping (missing `rustc`)");
                return;
            }
            Err(e) => panic!("starting rustc: {e}"),
            Ok(out) => assert!(out.status.success(), "rustc --version failed: {out:?}"),
        }
        let target_size = if cfg!(target_pointer_width = "64") { 4 } else { 8 };
        let arch = bare_arch();
        let types = arch.types_rc();
        let cell = types.intern(Datatype::new(4, type_metatype::TYPE_UINT)).unwrap();
        let pointer = types.get_type_pointer(target_size, cell, 1).unwrap();
        let index = types.intern(Datatype::new(target_size, type_metatype::TYPE_INT)).unwrap();
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
             fn main() {{ unsafe {{ let mut v = 7u32; let _ = consumer(&mut v, 0); }} }}\n"
        );
        let dir = std::env::temp_dir()
            .join(format!("kuna-language-width-rejection-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let input = dir.join("consumer.rs");
        std::fs::write(&input, &source).unwrap();
        let out = Command::new("rustc").args(["--edition=2021", "-A", "warnings"])
            .arg(&input).arg("-o").arg(dir.join("consumer")).output().unwrap();
        let diagnostic = String::from_utf8_lossy(&out.stderr);
        assert!(!out.status.success() && diagnostic.contains("E0080"),
            "a cross-width pointer must fail constant evaluation, not silently use host width:\n\
             {diagnostic}\n{source}");
        std::fs::remove_dir_all(dir).unwrap();
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
        let cell = types.intern(Datatype::new(4, type_metatype::TYPE_UINT)).unwrap();
        let array = types.get_type_array(5, cell.clone()).unwrap();
        let array_pointer = types.get_type_pointer(8, array, 1).unwrap();
        let pointer = types.get_type_pointer(8, cell.clone(), 1).unwrap();
        let index = types.intern(Datatype::new(8, type_metatype::TYPE_INT)).unwrap();
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
        execute_language_source("rust", &source, "actual-array");
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
            execute_language_source(if rust { "rust" } else { "c" }, &source, "integers");
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
            let cell = types.intern(Datatype::new(4, type_metatype::TYPE_UINT)).unwrap();
            let pointer = types.get_type_pointer(8, cell.clone(), 1).unwrap();
            let index = types.intern(Datatype::new(8, type_metatype::TYPE_INT)).unwrap();
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
            execute_language_source(if rust { "rust" } else { "c" }, &source, "pointers");
        }
    }

    #[test]
    fn emitted_rust_fallback_pointer_load_and_store_keep_the_memory_access() {
        use crate::dtype::TypeFactory;
        use std::process::Command;
        let arch = bare_arch();
        let types = arch.types_rc();
        let cell = types.intern(Datatype::new(4, type_metatype::TYPE_UINT)).unwrap();
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
        let output = Command::new("rustc")
            .args(["--edition=2021", "--crate-type=lib", "--emit=metadata", "-A", "warnings"])
            .arg(&input).arg("-o").arg(dir.join("consumer.rmeta")).output();
        let out = match output {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                eprintln!("language fallback metadata: skipping (missing `rustc`)");
                std::fs::remove_dir_all(dir).unwrap();
                return;
            }
            Err(e) => panic!("starting rustc: {e}"),
            Ok(out) => out,
        };
        assert!(out.status.success(), "fallback LOAD/STORE lost its value/lvalue contract:\n{}\n{source}",
            String::from_utf8_lossy(&out.stderr));
        std::fs::remove_dir_all(dir).unwrap();
    }

    /// A real standard ABI: eight-byte resources force Big24 results through a
    /// hidden pointer, while pointermax lowers Big24 inputs to indirect storage.
    /// Every role below comes from materialize_callable, never fixture flags.
    fn render_logical_call(
        indirect: bool, inputs: LogicalInputs, result_use: LogicalResultUse, occupied_name: Option<&str>,
    ) -> String {
        use crate::dtype::{type_class, DatatypeKind, TypeFactory, TypeField};
        use crate::fspec::{AbiInputOrigin, FuncCallSpecs, LogicalCallable, ParamEntry, ProtoModel};

        let mut arch = bare_arch();
        arch.realtypes = false;
        arch.ctypes = false;
        arch.cast_implied = false;
        arch.cast_sign = false;
        arch.cast_ternary = false;
        let types = arch.types_rc();
        types.setup_sizes(Some(4), 8, 8);
        types.set_core_type("int4", 4, type_metatype::TYPE_INT, false).unwrap();
        types.set_core_type("int8", 8, type_metatype::TYPE_INT, false).unwrap();
        types.cache_core_types().unwrap();
        let int4 = types.get_base(4, type_metatype::TYPE_INT).unwrap();
        let int8 = types.get_base(8, type_metatype::TYPE_INT).unwrap();
        let void = types.get_type_void().unwrap();
        let void_ptr = types.get_type_pointer(8, void.clone(), 1).unwrap();
        let mut draft = Datatype::new_with_align(24, 8, type_metatype::TYPE_STRUCT);
        draft.name = "Big24".to_owned();
        draft.display_name = draft.name.clone();
        draft.id = Datatype::hash_name(&draft.name);
        draft.kind = DatatypeKind::Struct {
            field: (0..3).map(|i| TypeField::new(i, i * 8, format!("v{i}"), int8.id())).collect(),
            bitfield: vec![],
        };
        let big = types.intern(draft).unwrap();
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
        let model = Rc::new(model);
        types.set_proto_context(Some(model.clone()), manager.clone()).unwrap();
        let declaration = LogicalCallable {
            binding: types.model_binding(None).unwrap(), output: big.id(),
            inputs: match inputs {
                LogicalInputs::MethodByValue => vec![void_ptr.id(), big.id(), int4.id()],
                _ => vec![int4.id()],
            },
            variadic: matches!(inputs, LogicalInputs::Variadic),
            input_closed: !matches!(inputs, LogicalInputs::Variadic),
            logical_first: matches!(inputs, LogicalInputs::Variadic).then_some(1),
            flags: if matches!(inputs, LogicalInputs::MethodByValue) {
                crate::fspec::func_proto_flags::HAS_THISPTR
            } else { 0 },
        };
        let code = types.get_type_code_proto(&declaration).unwrap();
        let abi = crate::fspec::materialize_callable(types.as_ref(), &code).unwrap().unwrap();
        assert!(abi.prototype().get_output().is_indirect_storage());
        assert_eq!(abi.prototype().logical_callable().unwrap().id(), code.id());

        let mut context = ContextArch::new_shared(manager);
        context.types = Some(types.clone());
        let mut fd = Funcdata::new("driver", "driver", Rc::new(context),
            Address::new(space.clone(), 0x1000), 0x1000_0000, 0x40).unwrap();
        fd.get_func_proto_mut().set_internal(model.clone(), void.clone());
        fd.set_high_level();
        if let Some(name) = occupied_name {
            named_call_input(&mut fd, name, int4.clone());
        }
        let root = fd.bblocks_root_pub();
        let block = fd.bblocks_mut().new_block_basic(root);

        let destination = if matches!(result_use, LogicalResultUse::ImpliedPointer | LogicalResultUse::NestedPointer) {
            let next_code = types.get_type_code_proto(&LogicalCallable {
                binding: declaration.binding.clone(), output: big_ptr.id(), inputs: vec![],
                variadic: false, input_closed: true, logical_first: None, flags: 0,
            }).unwrap();
            let next_abi = crate::fspec::materialize_callable(types.as_ref(), &next_code)
                .unwrap().unwrap();
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
            specs.proto_mut().copy(next_abi.prototype());
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
        for (slot, origin) in abi.prototype().callable_input_origins().iter().enumerate() {
            physical_args.push(match *origin {
                AbiInputOrigin::HiddenResult => destination,
                AbiInputOrigin::Declared(index) => {
                    if matches!(inputs, LogicalInputs::MethodByValue) && index == 1 {
                        assert!(abi.prototype().get_param(slot as int4).unwrap().is_indirect_storage());
                    }
                    logical_args[index]
                }
            });
        }
        assert_eq!(abi.prototype().callable_input_origins()[0], AbiInputOrigin::HiddenResult);
        if matches!(inputs, LogicalInputs::MethodByValue) {
            assert!(abi.prototype().get_param(1).unwrap().is_this_pointer());
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
        specs.proto_mut().copy(abi.prototype());
        specs.proto_mut().set_override(true); // source survives site pinning
        fd.push_call_specs(specs);
        if indirect {
            fd.action_set_casts();
            let cast_target = fd.obank().get(call).unwrap().get_in(0).unwrap();
            assert_eq!(fd.vbank().get(cast_target).unwrap().get_type().get_ptr_to().unwrap().id(), code.id());
        }
        if let Some(out) = physical_output {
            if matches!(result_use, LogicalResultUse::NestedPointer) {
                let consumer_code = types.get_type_code_proto(&LogicalCallable {
                    binding: declaration.binding.clone(), output: void.id(),
                    inputs: vec![big_ptr.id(), int4.id()], variadic: false,
                    input_closed: true, logical_first: None, flags: 0,
                }).unwrap();
                let consumer_abi = crate::fspec::materialize_callable(types.as_ref(), &consumer_code)
                    .unwrap().unwrap();
                let consumer = mk_op(&mut fd, 3, 0x1020, OpCode::CPUI_CALL);
                fd.op_set_opcode(consumer, TypeOp::new(OpCode::CPUI_CALL,
                    crate::op::pcodeop_flags::call, "CALL"));
                let target = fd.new_constant(8, 0x5000);
                fd.op_set_input(consumer, target, 0).unwrap();
                fd.op_set_input(consumer, out, 1).unwrap();
                fd.op_set_input(consumer, *logical_args.last().unwrap(), 2).unwrap();
                fd.op_insert_end(consumer, block);
                let entry = Address::new(ram(&fd), 0x5000);
                let mut specs = FuncCallSpecs::new(consumer, entry.clone());
                specs.set_funcdata(entry, "consume_pointer").unwrap();
                specs.proto_mut().copy(consumer_abi.prototype());
                fd.push_call_specs(specs);
            } else {
                let copy = mk_op(&mut fd, 1, 0x1020, OpCode::CPUI_COPY);
                fd.op_set_input(copy, out, 0).unwrap();
                let observed = fd.new_unique_out(8, copy).unwrap();
                fd.vn_update_type(observed, big_ptr);
                name_call_local(&mut fd, observed, "observed");
                fd.op_insert_end(copy, block);
            }
        }
        fd.get_func_proto_mut().set_input_lock(true);
        fd.seed_sblocks_copy();
        PrintC::new().doc_function_full(&fd, &arch)
    }

    fn compact_c(text: &str) -> String {
        text.chars().filter(|c| !c.is_whitespace()).collect()
    }

    /// Find the address captured immediately before the aggregate store. Other
    /// Big24 pointer locals and parameters are unrelated to this sequence.
    fn result_capture(text: &str) -> String {
        let c = compact_c(text);
        for (store, _) in c.match_indices(",*") {
            let Some((capture, _)) = c[..store].rsplit_once('=') else { continue };
            let start = capture.rfind(|ch: char| !ch.is_ascii_alphanumeric() && ch != '_')
                .map_or(0, |index| index + 1);
            let name = &capture[start..];
            if !name.is_empty() && c[store + 2..].starts_with(&format!("{name}=")) {
                return name.to_owned();
            }
        }
        panic!("missing captured-address aggregate store:\n{text}");
    }

    #[test]
    fn logical_hidden_result_omits_abi_argument_and_preserves_used_pointer() {
        for indirect in [false, true] {
            for result_use in [LogicalResultUse::Discarded, LogicalResultUse::ExplicitPointer] {
                let text = render_logical_call(indirect, LogicalInputs::Tag, result_use, None);
                let temp = result_capture(&text);
                let c = compact_c(&text);
                let callee = if indirect { "(*(Big24(*)(int4))callback)(tag)" } else { "make_big(tag)" };
                assert!(c.contains(&format!("{temp}=destination,*{temp}={callee}")), "{text}");
                if matches!(result_use, LogicalResultUse::ExplicitPointer) {
                    assert!(c.contains(&format!("returned=({temp}=destination,*{temp}={callee},{temp});")), "{text}");
                    assert!(c.contains("observed=returned;"), "{text}");
                }
            }
        }
    }

    #[test]
    fn implied_hidden_result_captures_side_effectful_destination_once() {
        for indirect in [false, true] {
            let text = render_logical_call(indirect, LogicalInputs::Tag, LogicalResultUse::ImpliedPointer, None);
            let temp = result_capture(&text);
            let c = compact_c(&text);
            let callee = if indirect { "(*(Big24(*)(int4))callback)(tag)" } else { "make_big(tag)" };
            assert!(c.contains(&format!("observed=({temp}=")), "{text}");
            assert!(c.contains(&format!(",*{temp}={callee},{temp});")), "{text}");
            assert_eq!(c.matches("next_destination()").count(), 1, "destination side effect runs once:\n{text}");
        }
    }

    #[test]
    fn logical_method_arguments_dereference_indirect_byvalue_storage() {
        let text = render_logical_call(false, LogicalInputs::MethodByValue, LogicalResultUse::Discarded, None);
        let temp = result_capture(&text);
        assert!(compact_c(&text).contains(&format!("*{temp}=make_big(object,*source_ptr,tag)")), "{text}");
    }

    #[test]
    fn logical_variadic_call_preserves_operands_beyond_source_role_prefix() {
        let text = render_logical_call(false, LogicalInputs::Variadic, LogicalResultUse::Discarded, None);
        let temp = result_capture(&text);
        assert!(compact_c(&text).contains(&format!("*{temp}=make_big(tag,extra)")), "{text}");
    }

    #[test]
    fn hidden_result_sequence_remains_one_nested_call_argument() {
        for indirect in [false, true] {
            let text = render_logical_call(indirect, LogicalInputs::Tag,
                LogicalResultUse::NestedPointer, None);
            let temp = result_capture(&text);
            let c = compact_c(&text);
            let callee = if indirect { "(*(Big24(*)(int4))callback)(tag)" } else { "make_big(tag)" };
            assert!(c.contains(&format!("consume_pointer(({temp}=")), "{text}");
            assert!(c.contains(&format!(",*{temp}={callee},{temp}),tag);")), "{text}");
            assert_eq!(c.matches("next_destination()").count(), 1, "{text}");
        }
    }

    #[test]
    fn hidden_result_capture_does_not_shadow_existing_parameter() {
        let original = render_logical_call(false, LogicalInputs::Tag,
            LogicalResultUse::ExplicitPointer, None);
        let occupied = result_capture(&original);
        let text = render_logical_call(false, LogicalInputs::Tag,
            LogicalResultUse::ExplicitPointer, Some(&occupied));
        let temp = result_capture(&text);
        let c = compact_c(&text);
        assert_ne!(temp, occupied, "the result capture must not shadow a parameter:\n{text}");
        assert!(c.contains(&format!("returned=({temp}=destination,*{temp}=make_big(tag),{temp});")), "{text}");
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

        fn nominal_node(types: &crate::dtype::TypeFactoryImpl) -> crate::dtype::TypeRoot {
            use crate::dtype::DatatypeKind;
            let mut node = Datatype::new_with_align(8, 8, type_metatype::TYPE_STRUCT);
            node.name = "Node".into();
            node.display_name = node.name.clone();
            node.id = 72_057_594_037_927_936;
            node.kind = DatatypeKind::Struct { field: vec![], bitfield: vec![] };
            types.intern(node).unwrap()
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
                let bytes = print.doc_function_markup(&fd, &arch).unwrap();
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
            use crate::fspec::LogicalCallable;
            let (mut fd, arch) = fixture();
            let types = arch.types_rc();
            let node = nominal_node(&types);
            let input = types.get_typedef(&node, "Input alias (v2)", 72_057_594_037_927_937, 0).unwrap();
            let manager = Rc::new(build_manager());
            let mut model = ProtoModel::new(&manager);
            model.build_param_list("standard").unwrap();
            types.set_proto_context(Some(Rc::new(model)), manager).unwrap();
            let binding = types.model_binding(None).unwrap();
            let callable = |output: &crate::dtype::TypeRoot, inputs: Vec<crate::dtype::TypeRoot>| {
                let code = types.get_type_code_proto(&LogicalCallable {
                    binding: binding.clone(), output: output.id(),
                    inputs: inputs.iter().map(crate::dtype::TypeRoot::id).collect(),
                    variadic: false, input_closed: true, logical_first: None, flags: 0,
                }).unwrap();
                types.get_type_pointer(8, code, 1).unwrap()
            };
            let nested = callable(&input, vec![node.clone()]);
            let callback = callable(&node, vec![input, nested]);
            let alias = types.get_typedef(&callback, "Transform (next)", 72_057_594_037_927_938, 0).unwrap();
            fd.set_high_level();
            named_call_input(&mut fd, "callback", callback);
            named_call_input(&mut fd, "named_callback", alias);
            let bytes = PrintC::new().doc_function_markup(&fd, &arch).unwrap();
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
                    assert_eq!(fd.vbank().get(output).unwrap().get_type(), &byte);
                    let mut print = PrintC::new();
                    if rust { print.set_name("rust-language"); }
                    let bytes = print.doc_function_markup(&fd, &arch).unwrap();
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
                    TypeField::new(0, 0, "first", first.id()),
                    TypeField::new(1, 8, "next", integer.id()),
                ], bitfield: vec![],
            };
            let node = types.intern(node).unwrap();
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
            let bytes = print.doc_function_markup(&fd, &arch).unwrap();
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
            print.set_comment_style("c").unwrap();
            print.set_header_comment_flags(0);
            print.set_instruction_comment_flags(ct::USER2 | ct::WARNING);
            print.options.set_warn_inline(true);
            let text = host_text(&fd, &print.doc_function_markup(&fd, &arch).unwrap());
            let block_start = text.find("/*").unwrap();
            let block_end = block_start + text[block_start..].find("*/").unwrap();
            let block = &text[block_start..block_end];
            assert!(block.contains("ordinary") && !block.contains("//"), "{text}");
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
            let wide = host_text(&fd, &print.doc_function_markup(&fd, &arch).unwrap());
            assert_eq!(wide.split('{').next().unwrap().lines()
                .filter(|line| !line.is_empty()).count(), 1, "{wide}");

            print.set_max_line_size(20).unwrap();
            print.set_indent_increment(4);
            print.set_markup(true);
            print.set_markup(false);
            let narrow = host_text(&fd, &print.doc_function_markup(&fd, &arch).unwrap());
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
            let reset = host_text(&fd, &print.doc_function_markup(&fd, &arch).unwrap());
            assert_eq!(reset, wide);
            assert!(print.set_max_line_size(19).is_err());
            assert!(print.set_max_line_size(10001).is_err());
            assert_eq!(host_text(&fd, &print.doc_function_markup(&fd, &arch).unwrap()), wide);
            print.set_max_line_size(20).unwrap();
            assert!(print.set_line_comment_indent(20).is_err());
            assert!(print.set_line_comment_indent(-1).is_err());
            print.set_line_comment_indent(19).unwrap();
        }

        #[test]
        fn host_sink_restores_after_queue_error_and_render_unwind() {
            let (fd, arch) = fixture();
            let mut print = PrintC::new();
            print.set_max_line_size(20).unwrap();
            print.set_indent_increment(4);
            print.emit.print("saved sink", SyntaxHighlight::NoColor);
            let failed: KunaResult<()> = print.with_document_sink(
                PrintEmit::Pretty(EmitPrettyPrint::new()), true, |print| {
                    print.emit.begin_function();
                    print.emit.flush()
                });
            assert!(failed.is_err());
            assert_eq!(print.emit.output_str(), "saved sink");
            assert!(!print.is_host_surface());
            let unwind = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let _: KunaResult<()> = print.with_document_sink(
                    PrintEmit::Pretty(EmitPrettyPrint::new()), true, |print| {
                        print.context.push_mod();
                        print.context.set_mod(modifiers::PRINT_LOAD_VALUE);
                        panic!("render interrupted");
                    });
            }));
            assert!(unwind.is_err());
            assert_eq!(print.emit.output_str(), "saved sink");
            assert_eq!(print.context.mods(), 0);
            assert!(print.emit_fd.is_none());
            let recovered = host_text(&fd, &print.doc_function_markup(&fd, &arch).unwrap());
            assert!(recovered.contains("\n    return 7;"), "{recovered}");
            assert!(!recovered.contains("saved sink"));
            assert_eq!(print.emit.output_str(), "saved sink");
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
            let scalar = types.intern(Datatype::new(8, type_metatype::TYPE_INT)).unwrap();
            let mut draft = Datatype::new_with_align(16, 8, type_metatype::TYPE_STRUCT);
            draft.name = "Node".into();
            draft.display_name = draft.name.clone();
            draft.id = 72_057_594_037_927_936;
            draft.kind = DatatypeKind::Struct {
                field: vec![
                    TypeField::new(0, 0, "first", scalar.id()),
                    TypeField::new(1, 8, "next", scalar.id()),
                ],
                bitfield: vec![],
            };
            let node = types.intern(draft).unwrap();
            let mut alias = Datatype::new_with_align(16, 8, type_metatype::TYPE_STRUCT);
            alias.name = "NodeAlias".into();
            alias.display_name = alias.name.clone();
            alias.id = 72_057_594_037_927_937;
            alias.kind = DatatypeKind::Alias;
            alias.typedef_imm = Some(node.id());
            let alias = types.intern(alias).unwrap();
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
}
