//! A declared variadic function's floating-point or aggregate return value, on
//! an ARM image that states the VFP procedure-call standard, comes back where
//! the base standard puts it: `r0:r1` for a `double`, `r0` for a four-byte float
//! aggregate.  A non-variadic callee keeps `d0`.  An image that states the base
//! standard with an FPU (`-mfloat-abi=softfp`), or no convention, keeps the
//! default layout, so its tail call to the variadic callee still returns it.
use crate::common;
use object::write::{Object, Relocation, Symbol, SymbolSection};
use object::{
    Architecture, BinaryFormat, Endianness, RelocationFlags, SectionKind, SymbolFlags, SymbolKind,
    SymbolScope,
};
use std::process::Command;

const ASSERTS: [&str; 8] = [
    "typedef struct f1 { float a; };",
    "prototype vr double vr(int n, ...)",
    "prototype vf1 struct f1 vf1(int n, ...)",
    "prototype g double g(int k)",
    "prototype w1 int w1(int k)",
    "prototype x1 float x1(int k)",
    "prototype n1 double n1(int k)",
    "prototype t1 double t1(int k)",
];

/// clang -O2 of
/// `int w1(int k) { return (int)vr(k, k + 1, (double)k); }`,
/// `float x1(int k) { struct f1 r = vf1(k, k + 1); return r.a; }`,
/// `double n1(int k) { return g(k) * 2.0; }` and
/// `double t1(int k) { return vr(k, 2); }`, with `vr`, `vf1` and `g` extern.
const ARM_HARD: [u32; 24] = [
    0xe92d4800, 0xee000a10, 0xe2801001, 0xeeb80bc0, 0xec532b10, 0xebfffffe, 0xec410b10, 0xeebd0bc0,
    0xee100a10, 0xe8bd8800, 0xe92d4800, 0xe2801001, 0xebfffffe, 0xee000a10, 0xe8bd8800, 0xe92d4800,
    0xebfffffe, 0xee300b00, 0xe8bd8800, 0xe92d4800, 0xe3a01002, 0xebfffffe, 0xec410b10, 0xe8bd8800,
];

/// The same four functions for Thumb-2 hard-float.
const THUMB_HARD: [u16; 37] = [
    0xb580, 0xee00, 0x0a10, 0x1c41, 0xeeb8, 0x0bc0, 0xec53, 0x2b10, 0xf7ff, 0xfffe, 0xec41, 0x0b10,
    0xeebd, 0x0bc0, 0xee10, 0x0a10, 0xbd80, 0xb580, 0x1c41, 0xf7ff, 0xfffe, 0xee00, 0x0a10, 0xbd80,
    0xb580, 0xf7ff, 0xfffe, 0xee30, 0x0b00, 0xbd80, 0xb580, 0x2102, 0xf7ff, 0xfffe, 0xec41, 0x0b10,
    0xbd80,
];

/// The same four functions for `-mfloat-abi=softfp -mfpu=vfpv3`; `t1` is a tail
/// call.
const ARM_SOFTFP: [u32; 22] = [
    0xe92d4800, 0xee000a10, 0xe2801001, 0xeef80bc0, 0xec532b30, 0xebfffffe, 0xec410b30, 0xeebd0be0,
    0xee100a10, 0xe8bd8800, 0xe92d4800, 0xe2801001, 0xebfffffe, 0xe8bd8800, 0xe92d4800, 0xebfffffe,
    0xec410b30, 0xee700ba0, 0xec510b30, 0xe8bd8800, 0xe3a01002, 0xeafffffe,
];

/// An `aeabi` attributes section with the given file-scope tag/value pairs.
fn attributes(tags: &[u8]) -> Vec<u8> {
    let mut data = vec![b'A'];
    data.extend(((4 + 6 + 5 + tags.len()) as u32).to_le_bytes());
    data.extend(b"aeabi\0");
    data.push(1);
    data.extend(((5 + tags.len()) as u32).to_le_bytes());
    data.extend(tags);
    data
}

fn image(
    code: &[u8],
    functions: &[(&str, u64, u64)],
    calls: &[(u64, &str, u32)],
    tags: Option<&[u8]>,
) -> Vec<u8> {
    let mut obj = Object::new(BinaryFormat::Elf, Architecture::Arm, Endianness::Little);
    let text = obj.add_section(Vec::new(), b".text".to_vec(), SectionKind::Text);
    obj.append_section_data(text, code, 4);
    for &(name, value, size) in functions {
        obj.add_symbol(Symbol {
            name: name.as_bytes().to_vec(),
            value,
            size,
            kind: SymbolKind::Text,
            scope: SymbolScope::Linkage,
            weak: false,
            section: SymbolSection::Section(text),
            flags: SymbolFlags::None,
        });
    }
    let mut externs = std::collections::HashMap::new();
    for &(offset, callee, r_type) in calls {
        let symbol = *externs.entry(callee).or_insert_with(|| {
            obj.add_symbol(Symbol {
                name: callee.as_bytes().to_vec(),
                value: 0,
                size: 0,
                kind: SymbolKind::Unknown,
                scope: SymbolScope::Linkage,
                weak: false,
                section: SymbolSection::Undefined,
                flags: SymbolFlags::None,
            })
        });
        obj.add_relocation(
            text,
            Relocation {
                offset,
                symbol,
                addend: 0,
                flags: RelocationFlags::Elf { r_type },
            },
        )
        .unwrap();
    }
    if let Some(tags) = tags {
        let section = obj.add_section(Vec::new(), b".ARM.attributes".to_vec(), SectionKind::Other);
        obj.append_section_data(section, &attributes(tags), 1);
    }
    obj.write().unwrap()
}

fn arm(words: &[u32]) -> Vec<u8> {
    words.iter().copied().flat_map(u32::to_le_bytes).collect()
}

fn decompile(stem: &str, bytes: Vec<u8>) -> String {
    let mut args = vec!["--assert-strict"];
    for assert in ASSERTS {
        args.extend(["--assert", assert]);
    }
    decompile_with(stem, bytes, &args)
}

fn decompile_with(stem: &str, bytes: Vec<u8>, args: &[&str]) -> String {
    let path = common::scratch_file(stem, "o");
    std::fs::write(&path, bytes).unwrap();
    let mut command = Command::new(env!("CARGO_BIN_EXE_kuna"));
    command
        .args(["decompile-all", path.to_str().unwrap()])
        .args(args);
    let result = command.output().unwrap();
    let code = String::from_utf8_lossy(&result.stdout).into_owned();
    assert!(
        result.status.success(),
        "{code}\n{}",
        String::from_utf8_lossy(&result.stderr)
    );
    code
}

fn body<'a>(code: &'a str, name: &str) -> &'a str {
    let start = code
        .find(&format!("// Function: {name} @"))
        .unwrap_or_else(|| panic!("no {name} in\n{code}"));
    let rest = &code[start..];
    let end = rest[1..].find("// Function:").map_or(rest.len(), |i| i + 1);
    &rest[..end]
}

fn assert_base_standard_returns(code: &str) {
    let w1 = body(code, "w1");
    assert!(w1.contains(" = vr(k,k + 1,"), "{w1}");
    assert!(!w1.contains("CONCAT44"), "{w1}");
    let x1 = body(code, "x1");
    assert!(x1.contains("return vf1(k,k + 1).a;"), "{x1}");
    let n1 = body(code, "n1");
    assert!(n1.contains(" = g(k);") && n1.contains("// d0"), "{n1}");
    let t1 = body(code, "t1");
    assert!(t1.contains(" = vr(k,2);"), "{t1}");
    assert!(!t1.contains("CONCAT44"), "{t1}");
}

const ARM_CALLS: [(u64, &str, u32); 4] = [
    (20, "vr", object::elf::R_ARM_CALL),
    (48, "vf1", object::elf::R_ARM_CALL),
    (64, "g", object::elf::R_ARM_CALL),
    (84, "vr", object::elf::R_ARM_CALL),
];

#[test]
fn hard_float_variadic_callees_return_in_core_registers() {
    let functions = [
        ("w1", 0, 40),
        ("x1", 40, 20),
        ("n1", 60, 16),
        ("t1", 76, 20),
    ];
    let code = decompile(
        "arm-variadic-returns",
        image(
            &arm(&ARM_HARD),
            &functions,
            &ARM_CALLS,
            Some(&[10, 4, 28, 1]),
        ),
    );
    assert_base_standard_returns(&code);
}

#[test]
fn thumb_hard_float_variadic_callees_return_in_core_registers() {
    let bytes: Vec<u8> = THUMB_HARD
        .iter()
        .copied()
        .flat_map(u16::to_le_bytes)
        .collect();
    let functions = [
        ("w1", 1, 34),
        ("x1", 35, 14),
        ("n1", 49, 12),
        ("t1", 61, 14),
    ];
    let calls = [
        (16, "vr", object::elf::R_ARM_THM_PC22),
        (38, "vf1", object::elf::R_ARM_THM_PC22),
        (50, "g", object::elf::R_ARM_THM_PC22),
        (64, "vr", object::elf::R_ARM_THM_PC22),
    ];
    let code = decompile(
        "thumb-variadic-returns",
        image(&bytes, &functions, &calls, Some(&[10, 4, 28, 1])),
    );
    assert_base_standard_returns(&code);
}

#[test]
fn base_standard_images_keep_the_default_layout() {
    let functions = [("w1", 0, 40), ("x1", 40, 16), ("n1", 56, 24), ("t1", 80, 8)];
    let calls = [
        (20, "vr", object::elf::R_ARM_CALL),
        (48, "vf1", object::elf::R_ARM_CALL),
        (60, "g", object::elf::R_ARM_CALL),
        (84, "vr", object::elf::R_ARM_JUMP24),
    ];
    let tags: [Option<&[u8]>; 2] = [Some(&[10, 4, 28, 0]), None];
    for tags in tags {
        let code = decompile(
            "softfp-variadic-returns",
            image(&arm(&ARM_SOFTFP), &functions, &calls, tags),
        );
        let t1 = body(&code, "t1");
        assert!(t1.contains("return vr(k,2);"), "{tags:?}: {t1}");
    }
}

/// clang -O2 of `float half(int x) { return x * 0.5f; }` and
/// `int user(int k) { return (int)half(k) + 1; }`.  `protoorder lock` parks the
/// recovered `half` with an open tail, which is a floor for argument recovery
/// and not a variadic signature, so `user` still reads the result from `s0`.
#[test]
fn a_parked_open_tail_keeps_its_float_return() {
    let words = [
        0xee010a10, 0xeeb60a00, 0xeeb81ac1, 0xee210a00, 0xe12fff1e, 0xe92d4800, 0xebfffff8,
        0xeebd0ac0, 0xee100a10, 0xe2800001, 0xe8bd8800,
    ];
    let functions = [("half", 0, 20), ("user", 20, 24)];
    let code = decompile_with(
        "lock-float-return",
        image(&arm(&words), &functions, &[], Some(&[10, 4, 28, 1])),
        &["--option", "protoorder", "lock"],
    );
    let user = body(&code, "user");
    assert!(user.contains("return (int)half(a0) + 1;"), "{user}");
}

#[test]
fn variadic_source_retains_the_effective_same_named_return_model() {
    use kuna_console::assertions::{self, Body, Directive};
    use kuna_console::engine::bootstrap_from_object;
    use kuna_decomp::database::SymbolKind as DecompSymbolKind;
    use kuna_decomp::fspec::PrototypePieces;
    use std::rc::Rc;

    let functions = [("w1", 0, 40), ("x1", 40, 20), ("n1", 60, 16), ("t1", 76, 20)];
    let bytes = image(&arm(&ARM_HARD), &functions, &ARM_CALLS, Some(&[10, 4, 28, 1]));
    let temporary = tempfile::tempdir().unwrap();
    let path = temporary.path().join("arm-variadic-source.o");
    std::fs::write(&path, bytes).unwrap();
    let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../..");
    let specs = vec![root.join("specs").to_str().unwrap().to_string()];
    let mut program = bootstrap_from_object(path.to_str().unwrap(), "", &specs).unwrap();
    program.commit_pending_analysis().unwrap();
    program.set_assertions(vec![Directive {
        raw: ASSERTS[1].to_owned(),
        body: Body::Prototype {
            func: "vr".to_owned(),
            decl: ASSERTS[1].strip_prefix("prototype vr ").unwrap().to_owned(),
        },
    }]);
    assertions::apply_program_scoped(&mut program);
    assert_eq!(program.assertion_outcomes()[0].status, "applied");
    let sid = program.arch().query_global_function("vr").unwrap();
    let source = match &program.arch().symboltab.symbol(sid).kind {
        DecompSymbolKind::Function { source_proto: Some(source), .. } => Rc::clone(source),
        _ => panic!("the original declaration must reach its canonical source owner"),
    };
    let default = Rc::clone(program.arch().default_fp().unwrap());
    let derived = kuna_decomp::kuna_vfpvariadic::declarations(program.arch()).unwrap();
    assert_eq!(derived.get_name(), default.get_name());
    assert!(!Rc::ptr_eq(&derived, &default));
    assert!(Rc::ptr_eq(source.model(), &derived));
    assert!(source.is_input_locked() && source.is_output_locked());
    assert!(!source.is_model_locked());
    let mut pieces = PrototypePieces::default();
    source.get_pieces(&mut pieces);
    assert_eq!(pieces.first_var_arg_slot, 1);
    assert_eq!(pieces.intypes.len(), 1);
    assert!(source.get_output().get_address().is_invalid());
    let source_output = Rc::clone(source.get_output_type().unwrap());
    assert_eq!(source_output.get_size(), 8);
    let working = program.arch().types_impl().acquire_working_proto(&source).unwrap();
    assert!(Rc::ptr_eq(working.model(), &derived));
    assert!(!working.is_model_locked());
    assert!(Rc::ptr_eq(working.get_output_type().unwrap(), &source_output));
    assert_eq!(working.get_output().get_size(), 8);
    let output = working.get_output().get_address();
    assert_eq!(output.get_space().unwrap().get_name(), "join");
    let join = program.arch().manage().find_join(output.get_offset()).unwrap();
    assert_eq!(join.num_pieces(), 2);
    for (index, name) in [b"r1", b"r0"].into_iter().enumerate() {
        let register = program.arch().get_register_varnode(name).unwrap();
        let piece = join.get_piece(index as i32);
        assert!(Rc::ptr_eq(piece.space.as_ref().unwrap(), register.space.as_ref().unwrap()));
        assert_eq!(piece.offset, register.offset);
        assert_eq!(piece.size, register.size);
    }
    assert!(source.get_output().get_address().is_invalid());
    assert!(Rc::ptr_eq(source.get_output_type().unwrap(), &source_output));

    // A complete declaration arrives after the pieces stream. Its
    // unassigned default model must not replace the effective same-named Rc.
    let entry = {
        let symbol = program.arch().symboltab.symbol(sid);
        program.arch().symboltab.entry(symbol.scope, symbol.mapentry[0]).get_addr().clone()
    };
    let mut incoming = kuna_decomp::fspec::FuncProto::new();
    incoming.copy(&source);
    incoming.set_model(Some(Rc::clone(&default)));
    incoming.set_input_lock(false);
    incoming.set_output_lock(true);
    incoming.set_model_lock(false);
    assert!(!incoming.is_input_locked() && incoming.is_output_locked() && !incoming.is_model_locked());
    incoming.set_extra_pop(12);
    // Only an authored wire attribute supplies independent extra-pop provenance.
    {
        use kuna_base::marshal::{Decoder, IdRegistry, XmlDecode, XmlEncode};
        use kuna_decomp::fspec::{PrototypeDecoding, PrototypeEncoding};
        let mut wire = Vec::new();
        incoming.encode_with_context(&mut XmlEncode::new(&mut wire), PrototypeEncoding::LogicalCallable).unwrap();
        let mut registry = IdRegistry::with_base_ids();
        kuna_decomp::remote_provider::register_remote_provider_ids(&mut registry);
        kuna_decomp::dtype::register_type_wire_ids(&mut registry);
        registry.register_element(&kuna_base::marshal::ElementId::new("param", 166));
        registry.register_element(&kuna_base::marshal::ElementId::new("retparam", 171));
        let mut decoder = XmlDecode::new(program.arch().manage(), &registry);
        decoder.ingest_stream(&wire).unwrap();
        incoming = program.arch().types_impl().decode_proto(&mut decoder, PrototypeDecoding::LogicalCallable).unwrap();
        incoming.set_model_lock(false);
        assert!(!incoming.is_input_locked() && incoming.is_output_locked() && !incoming.is_model_locked());
        assert_eq!(incoming.supplied_extra_pop(), Some(12));
    }
    incoming.set_no_return(true);
    incoming.set_inject_id(17);
    incoming.set_param_usepoint(0, entry.clone());
    let r4 = program.arch().get_register_varnode(b"r4").unwrap();
    incoming.push_effect_override(kuna_decomp::fspec::EffectRecord::from_varnode(
        r4, kuna_decomp::fspec::effect_type::UNAFFECTED,
    ));
    let incoming = Rc::new(incoming);
    program.arch_mut().set_function_source_proto_at(&entry, Rc::clone(&incoming));
    let published = Rc::clone(program.arch().symboltab.function_source_proto_across_scopes(&entry).unwrap());
    assert!(!Rc::ptr_eq(&published, &incoming));
    assert!(Rc::ptr_eq(published.model(), &derived));
    assert!(Rc::ptr_eq(incoming.model(), &default));
    assert!(!published.is_model_locked() && !published.is_input_locked());
    assert!(published.is_output_locked() && published.is_no_return());
    assert_eq!(published.supplied_extra_pop(), Some(12));
    assert_eq!(published.get_inject_id(), 17);
    assert_eq!(published.effect_list(), incoming.effect_list());
    assert_eq!(published.get_param(0).unwrap().get_usepoint(), incoming.get_param(0).unwrap().get_usepoint());
    assert_eq!(published.get_param(0).unwrap().get_flags(), incoming.get_param(0).unwrap().get_flags());
    assert_eq!(published.get_output().get_flags(), incoming.get_output().get_flags());
    assert!(published.get_output().get_address().is_invalid());
    assert!(Rc::ptr_eq(published.get_output_type().unwrap(), &source_output));
    program.arch_mut().set_function_source_proto_at(&entry, Rc::clone(&published));
    assert!(Rc::ptr_eq(
        program.arch().symboltab.function_source_proto_across_scopes(&entry).unwrap(), &published,
    ), "an unchanged effective model must not copy the complete source");

    // The wire child has no function name: resolve name-only model authority
    // through its actual Symbol owner, not the undeclared derived model.
    program.arch_mut().set_function_prototype_model("vr", Rc::clone(&default));
    program.arch_mut().set_function_source_proto_at(&entry, Rc::clone(&incoming));
    let named = program.arch().symboltab.function_source_proto_across_scopes(&entry).unwrap();
    assert!(!Rc::ptr_eq(named, &incoming));
    assert!(Rc::ptr_eq(named.model(), &default));
    assert!(named.is_model_locked());
    assert!(!named.is_input_locked() && named.is_output_locked());
    assert_eq!(named.supplied_extra_pop(), Some(12));
    assert_eq!(named.effect_list(), incoming.effect_list());
    assert!(!incoming.is_model_locked());
    assert!(Rc::ptr_eq(published.model(), &derived));

    // Supplied physical geometry and explicit convention authority are not
    // candidates for the unplaced-declaration reconciliation.
    let physical = Rc::new(program.arch().types_impl().acquire_working_proto(&source).unwrap());
    program.arch_mut().set_function_source_proto_at(&entry, Rc::clone(&physical));
    assert!(Rc::ptr_eq(
        program.arch().symboltab.function_source_proto_across_scopes(&entry).unwrap(), &physical,
    ));
    let mut locked = kuna_decomp::fspec::FuncProto::new();
    locked.copy(&incoming);
    locked.set_model_lock(true);
    let locked = Rc::new(locked);
    program.arch_mut().set_function_source_proto_at(&entry, Rc::clone(&locked));
    assert!(Rc::ptr_eq(
        program.arch().symboltab.function_source_proto_across_scopes(&entry).unwrap(), &locked,
    ));

    // Address authority beats the conflicting name selection.  Even when the
    // selected model Rc is unchanged, explicit authority adds its own lock.
    program.arch_mut().set_function_prototype_model("vr", Rc::clone(&derived));
    program.arch_mut().set_function_prototype_model_at(&entry, Rc::clone(&default));
    program.arch_mut().set_function_source_proto_at(&entry, Rc::clone(&incoming));
    let explicit_complete = program.arch().symboltab.function_source_proto_across_scopes(&entry).unwrap();
    assert!(!Rc::ptr_eq(explicit_complete, &incoming));
    assert!(Rc::ptr_eq(explicit_complete.model(), &default));
    assert!(explicit_complete.is_model_locked());
    assert!(!explicit_complete.is_input_locked() && explicit_complete.is_output_locked());
    assert_eq!(explicit_complete.supplied_extra_pop(), Some(12));
    assert_eq!(explicit_complete.effect_list(), incoming.effect_list());
    assert_eq!(explicit_complete.get_inject_id(), 17);

    program.arch_mut().set_function_prototype_model("vr", Rc::clone(&default));
    program.arch_mut().set_function_prototype_pieces("vr", pieces).unwrap();
    let explicit = match &program.arch().symboltab.symbol(sid).kind {
        DecompSymbolKind::Function { source_proto: Some(source), .. } => source,
        _ => panic!("the explicit convention must retain a complete source declaration"),
    };
    assert!(Rc::ptr_eq(explicit.model(), &default));
    assert!(explicit.is_model_locked());
    let working = program.arch().types_impl().acquire_working_proto(explicit).unwrap();
    assert!(Rc::ptr_eq(working.model(), &default));
    let d0 = program.arch().get_register_varnode(b"d0").unwrap();
    assert!(Rc::ptr_eq(working.get_output().get_address().get_space().unwrap(), d0.space.as_ref().unwrap()));
    assert_eq!(working.get_output().get_address().get_offset(), d0.offset);
    assert_eq!(working.get_output().get_size(), i32::try_from(d0.size).unwrap());
    assert!(explicit.get_output().get_address().is_invalid());
    assert!(Rc::ptr_eq(source.model(), &derived));
    assert!(source.get_output().get_address().is_invalid());
}
