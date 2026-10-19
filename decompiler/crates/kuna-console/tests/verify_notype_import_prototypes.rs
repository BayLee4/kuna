//! Undefined untyped call targets receive known library prototypes.
use crate::common;
use kuna_console::engine::{bootstrap_from_object, EntrySelector};
use kuna_console::project::decompile_targets;
use object::{
    write, Architecture, BinaryFormat, Endianness, RelocationFlags, SymbolFlags, SymbolKind,
    SymbolScope,
};

struct Scratch(std::path::PathBuf);
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

#[test]
fn notype_memset_call_types_pointer_parameter_and_return() {
    let sparc_words: [u32; 8] = [
        0x9de3bfa0, 0x90100018, 0x92102000, 0x941020a8, 0x40000000, 0x01000000, 0x81c7e008,
        0x91e80008,
    ];
    let sparc: Vec<_> = sparc_words.into_iter().flat_map(u32::to_be_bytes).collect();
    let x86 = vec![
        0x48, 0x83, 0xec, 8, 0x31, 0xf6, 0xba, 0xa8, 0, 0, 0, 0xe8, 0, 0, 0, 0, 0x48, 0x89, 0x04,
        0x24, 0x48, 0x8b, 0x04, 0x24, 0x48, 0x83, 0xc4, 8, 0xc3,
    ];
    for (architecture, endian, bytes, offset, addend, r_type) in [
        (
            Architecture::Sparc,
            Endianness::Big,
            sparc,
            16,
            0,
            object::elf::R_SPARC_WDISP30,
        ),
        (
            Architecture::X86_64,
            Endianness::Little,
            x86,
            12,
            -4,
            object::elf::R_X86_64_PLT32,
        ),
    ] {
        let mut object = write::Object::new(BinaryFormat::Elf, architecture, endian);
        let text = object.section_id(write::StandardSection::Text);
        object.append_section_data(text, &bytes, 4);
        object.add_symbol(write::Symbol {
            name: b"clear".to_vec(),
            value: 0,
            size: bytes.len() as u64,
            kind: SymbolKind::Text,
            scope: SymbolScope::Dynamic,
            weak: false,
            section: write::SymbolSection::Section(text),
            flags: SymbolFlags::None,
        });
        let target = object.add_symbol(write::Symbol {
            name: b"memset".to_vec(),
            value: 0,
            size: 0,
            kind: SymbolKind::Unknown,
            scope: SymbolScope::Dynamic,
            weak: false,
            section: write::SymbolSection::Undefined,
            flags: SymbolFlags::None,
        });
        object
            .add_relocation(
                text,
                write::Relocation {
                    offset,
                    symbol: target,
                    addend,
                    flags: RelocationFlags::Elf { r_type },
                },
            )
            .expect("call relocation");
        let path = Scratch(common::scratch_file("notype-memset", "o"));
        std::fs::write(&path.0, object.write().expect("synthetic ELF")).expect("write fixture");
        let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../..");
        let specs = vec![root.join("specs").to_str().unwrap().to_string()];
        let mut program =
            bootstrap_from_object(path.0.to_str().unwrap(), "", &specs).expect("bootstrap");
        program.commit_pending_analysis().expect("commit analysis");
        let entry = program
            .resolve_entry(&EntrySelector::Name("clear".into()))
            .expect("clear entry");
        let functions = decompile_targets(&mut program, vec![entry], false, false, false).unwrap();
        let code = functions[0].code.as_ref().expect("decompiled code");
        let signature = code
            .lines()
            .find(|line| line.contains("clear("))
            .expect("signature");
        assert!(
            regex::Regex::new(r"^void\s*\*\s*clear\(")
                .unwrap()
                .is_match(signature),
            "return type {architecture:?}: {code}"
        );
        assert!(
            regex::Regex::new(r"clear\(void\s*\*\s*\w+\)")
                .unwrap()
                .is_match(signature),
            "parameter type {architecture:?}: {code}"
        );
        assert!(
            regex::Regex::new(r"return\s+memset\([^,]+,\s*0,\s*0xa8\);")
                .unwrap()
                .is_match(code),
            "return call result {architecture:?}: {code}"
        );
    }
}

#[test]
fn crt_import_convention_reaches_both_iat_and_thunk_source_owners() {
    use kuna_base::address::Address;
    use kuna_decomp::database::SymbolKind as DecompSymbolKind;
    use kuna_decomp::dtype::type_metatype;
    use std::rc::Rc;

    let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../..");
    let specs = vec![root.join("specs").to_str().unwrap().to_string()];
    let image = root.join("decompiler/crates/kuna-analysis/tests/fixtures/calleepopframe_pe_i386.exe");
    let mut program = bootstrap_from_object(image.to_str().unwrap(), "", &specs).unwrap();
    program.commit_pending_analysis().unwrap();
    let arch = program.arch();
    let cdecl = arch.function_prototype_model("memset").unwrap();
    assert_eq!(cdecl.get_name(), "__cdecl");
    assert_eq!(cdecl.get_extra_pop(), 4);
    let iat_sid = arch.query_global_function("memset").unwrap();
    let iat = match &arch.symboltab.symbol(iat_sid).kind {
        DecompSymbolKind::Function { source_proto: Some(source), .. } => source,
        _ => panic!("the original IAT entry must retain its complete source declaration"),
    };
    let thunk_entry = Address::new(Rc::clone(arch.manage().get_default_code_space().unwrap()), 0x4010d0);
    let (thunk_sid, _) = arch.symboltab.find_function_across_scopes(&thunk_entry).unwrap();
    assert_ne!(iat_sid, thunk_sid, "the original fixture has distinct import-word and code-veneer owners");
    let thunk = arch.symboltab.function_source_proto_across_scopes(&thunk_entry).unwrap();
    assert!(!Rc::ptr_eq(iat, thunk));

    for source in [iat, thunk] {
        assert!(Rc::ptr_eq(source.model(), cdecl));
        assert_eq!(source.get_extra_pop(), 4);
        assert!(source.is_input_locked() && source.is_output_locked() && source.is_model_locked());
        assert_eq!(source.num_params(), 3);
        assert_eq!(source.get_output_type().unwrap().get_metatype(), type_metatype::TYPE_PTR);
        assert_eq!(source.get_param(0).unwrap().get_type().unwrap().get_metatype(), type_metatype::TYPE_PTR);
        assert_eq!(source.get_param(1).unwrap().get_type().unwrap().get_metatype(), type_metatype::TYPE_INT);
        assert_eq!(source.get_param(2).unwrap().get_type().unwrap().get_metatype(), type_metatype::TYPE_UINT);
        let mut working = arch.types_impl().acquire_working_proto(source).unwrap();
        assert!(Rc::ptr_eq(working.model(), cdecl));
        assert_eq!(working.get_extra_pop(), 4);
        assert!(working.is_input_locked() && working.is_output_locked() && working.is_model_locked());
        assert!(!working.has_input_errors() && !working.has_output_errors());
        assert_eq!(working.num_params(), 3);
        assert_eq!(working.effect_list(), source.effect_list());
        assert_eq!(working.get_output().get_flags(), source.get_output().get_flags());
        assert!(Rc::ptr_eq(working.get_output_type().unwrap(), source.get_output_type().unwrap()));
        for slot in 0..3 {
            let declared = source.get_param(slot).unwrap();
            let allocated = working.get_param(slot).unwrap();
            assert!(declared.get_address().is_invalid());
            assert_eq!(declared.get_name(), "");
            assert_eq!(allocated.get_name(), declared.get_name());
            assert_eq!(allocated.get_flags(), declared.get_flags());
            assert_eq!(allocated.get_usepoint(), declared.get_usepoint());
            assert!(Rc::ptr_eq(allocated.get_type().unwrap(), declared.get_type().unwrap()));
            assert_eq!(allocated.get_address().get_space().unwrap().get_name(), "stack");
            assert_eq!(allocated.get_address().get_offset(), 4 + slot as u64 * 4);
        }
        working.set_extra_pop(8);
        assert_eq!(source.get_extra_pop(), 4, "working cleanup edits must not alter the source owner");
    }
}
