use super::*;
use std::path::Path;
use kuna_harness::dwarf_fixture as producer;

fn callable_child(test: &str) -> bool {
    const CHILD: &str = "KUNA_ANALYSIS_DWARF_DECLARATION_CHILD";
    let (_, module) = module_path!().split_once("::").unwrap();
    let name = format!("{module}::{test}");
    if std::env::var(CHILD).ok().as_deref() == Some(name.as_str()) {
        assert!(kuna_decomp::kuna_calltargettype::dwarf_function_types(),
            "the isolated callable source consumer requires its named option");
        return true;
    }
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", &name, "--nocapture"])
        .env(CHILD, &name)
        .env(kuna_decomp::kuna_calltargettype::CALLTARGETTYPE_ENV, "on")
        .output().expect("run isolated callable source consumer");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stdout.contains("running 1 test") && output.status.success(),
        "{name}: isolated consumer {:?}\n{stdout}\n{stderr}", output.status.code());
    print!("{stdout}");
    eprint!("{stderr}");
    false
}

fn target_architecture(path: &Path, bytes: &[u8]) -> kuna_decomp::sleigh_arch::SleighArchitecture {
    use kuna_base::marshal::IdRegistry;
    use kuna_decomp::sleigh_arch::{register_sleigh_arch_ids, LanguageDatabase, SleighArchitecture};
    use kuna_sleigh::loadimage::LoadImage;
    use kuna_sleigh::translate::register_translate_ids;

    let filename = path.to_str().unwrap();
    let image = crate::loadimage_object::ObjectLoadImage::from_bytes(filename, bytes).unwrap();
    let target = String::from_utf8(image.get_arch_type()).unwrap();
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../..");
    let specs = std::env::var_os("KUNA_SPECS").map(std::path::PathBuf::from)
        .unwrap_or_else(|| root.join("specs"));
    let mut registry = IdRegistry::with_base_ids();
    register_translate_ids(&mut registry);
    register_sleigh_arch_ids(&mut registry);
    let mut database = LanguageDatabase::new();
    database.scan_for_sleigh_directories(specs.to_str().unwrap());
    database.get_descriptions(&registry).unwrap();
    let mut architecture = SleighArchitecture::new(filename, "");
    architecture.resolve_architecture(&database, &target).unwrap();
    if architecture.language_index() < 0 {
        if let Some(fallback) = image.fallback_arch_id() {
            let mut retry = SleighArchitecture::new(filename, "");
            retry.resolve_architecture(&database, std::str::from_utf8(fallback).unwrap()).unwrap();
            if retry.language_index() >= 0 {
                architecture = retry;
            }
        }
    }
    assert!(architecture.language_index() >= 0, "no built specification for actual producer {target}");
    let files = architecture.build_spec_file(&database).unwrap();
    let sla = std::fs::read(files.slafile.expect("actual target requires a built specification")).unwrap();
    architecture.build_translator(Box::new(image), &sla).unwrap();
    let index = architecture.language_index();
    let arch = architecture.base_mut().unwrap();
    database.modify_spaces(index, arch.manage()).unwrap();
    arch.set_cspec_xml(std::fs::read(files.compilerfile).unwrap());
    arch.set_pspec_xml(std::fs::read(files.processorfile).unwrap());
    arch.translate_mut().as_sleigh_mut().unwrap().install_register_lookup().unwrap();
    arch.init_post_engine().unwrap();
    architecture
}

fn with_declarations(source: &str, standard: &str, flags: &[&str], check: impl Fn(&BTreeMap<usize, DieSnap>, &Path, &[u8])) {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures").join(source);
    let fixture = producer::compile_dwarf(&path, standard, flags);
    let bytes = std::fs::read(&fixture.path).unwrap();
    let file = object::File::parse(bytes.as_slice()).unwrap();
    let endian = if file.is_little_endian() { gimli::RunTimeEndian::Little } else { gimli::RunTimeEndian::Big };
    let sections = gimli::DwarfSections::load(|id| -> Result<Vec<u8>, gimli::Error> {
        Ok(dwarf_section_data(&file, id).unwrap_or_default())
    }).unwrap();
    let dwarf = sections.borrow(|b| gimli::EndianSlice::new(b, endian));
    let mut units = dwarf.units();
    while let Some(header) = units.next().unwrap() {
        let unit = dwarf.unit(header).unwrap();
        let Some(name) = unit.name.as_ref().and_then(|name| std::str::from_utf8(name.slice()).ok()) else {
            continue;
        };
        let name = Path::new(name);
        let is_source = if name.is_absolute() {
            name == path
        } else {
            let Some(directory) = unit.comp_dir.as_ref()
                .and_then(|directory| std::str::from_utf8(directory.slice()).ok()) else {
                continue;
            };
            Path::new(directory).join(name) == path
        };
        if is_source {
            check(&snapshot_unit(&dwarf, &unit), &fixture.path, &bytes);
            return;
        }
    }
    panic!("compiler must supply the authored DWARF unit {}", path.display());
}

fn named<'a>(dies: &'a BTreeMap<usize, DieSnap>, tag: gimli::DwTag, name: &str) -> (usize, &'a DieSnap) {
    dies.iter().find(|(_, die)| die.tag == tag && die.name == name)
        .map(|(off, die)| (*off, die)).unwrap_or_else(|| panic!("producer omitted {tag:?} {name}"))
}

fn imported(dies: &BTreeMap<usize, DieSnap>, types: &dyn TypeFactory, off: usize) -> Rc<Datatype> {
    build_datatype(Some(off), dies, types, 1, &mut TypeWalk::with_gate(true), false)
        .expect("source declaration must import")
}

#[test]
fn dwarf_compiler_callbacks_import_as_code_not_void() {
    if !callable_child("dwarf_compiler_callbacks_import_as_code_not_void") {
        return;
    }
    for standard in ["c89", "c11"] {
        with_declarations("dwarf_callback_prototyped.c", standard, &[], |dies, path, bytes| {
            let architecture = target_architecture(path, bytes);
            let types = architecture.base().unwrap().types();
            for name in ["Open", "Closed", "Fixed", "Variadic"] {
                let (off, _) = named(dies, gimli::DW_TAG_typedef, name);
                let pointer = imported(dies, types, off);
                let code = pointer.get_ptr_to().expect("callback pointer");
                assert_eq!(code.get_metatype(), type_metatype::TYPE_CODE, "{standard} {name} must not become void*");
            }
        });
    }
}

#[test]
fn dwarf_callback_parameter_order_and_aliases_are_source_authored() {
    if !callable_child("dwarf_callback_parameter_order_and_aliases_are_source_authored") {
        return;
    }
    with_declarations("dwarf_declarations.c", "c11", &[], |dies, path, bytes| {
        let architecture = target_architecture(path, bytes);
        let types = architecture.base().unwrap().types();
        let (_, sub) = named(dies, gimli::DW_TAG_subprogram, "invoke_flags");
        let pieces = build_pieces("invoke_flags", sub, dies, types, 1).expect("retain known signature");
        assert_eq!(pieces.innames, ["value", "callback"]);
        assert_eq!(pieces.intypes[0].get_name(), "Flags");
        assert_eq!(pieces.intypes[0].get_metatype(), type_metatype::TYPE_UINT);
        assert_eq!(pieces.intypes[0].get_size(), 1);
        let code = pieces.intypes[1].get_ptr_to().unwrap();
        assert_eq!(code.get_metatype(), type_metatype::TYPE_CODE);
    });
}

#[test]
fn prototypes_preserve_character_input_and_return_signedness() {
    for flag in ["-fsigned-char", "-funsigned-char"] {
        with_declarations("dwarf_declarations.c", "c11", &[flag], |dies, _, _| {
            let types = factory();
            types.set_core_type("char", 1, type_metatype::TYPE_INT, true).unwrap();
            types.cache_core_types().unwrap();
            for (name, meta) in [
                ("unsigned_identity", Some(type_metatype::TYPE_UINT)),
                ("signed_identity", Some(type_metatype::TYPE_INT)),
                ("plain_identity", None),
            ] {
                let (_, sub) = named(dies, gimli::DW_TAG_subprogram, name);
                let resolved = kuna_cppproto::resolve_subprogram(sub, dies).unwrap();
                for pieces in [
                    build_pieces(name, sub, dies, &types, 1),
                    kuna_cppproto::build_pieces(&resolved, dies, &types, 1),
                ] {
                    let pieces = pieces.expect("known character declaration");
                    assert_eq!(pieces.innames, ["value"]);
                    for ty in [&pieces.intypes[0], pieces.outtype.as_ref().unwrap()] {
                        assert_eq!((ty.get_size(), ty.is_char_print()), (1, true), "{flag} {name}");
                        if let Some(meta) = meta {
                            assert_eq!(ty.get_metatype(), meta, "{flag} {name}");
                        } else {
                            assert_eq!(ty.get_name(), "char", "{flag} {name}");
                        }
                    }
                }
            }
        });
    }
}

#[test]
fn recursive_typedef_and_tag_share_completed_layout_in_both_query_orders() {
    if !callable_child("recursive_typedef_and_tag_share_completed_layout_in_both_query_orders") {
        return;
    }
    with_declarations("dwarf_declarations.c", "c11", &[], |dies, path, bytes| {
        let (alias_off, _) = named(dies, gimli::DW_TAG_typedef, "Node");
        let (node_off, node_die) = named(dies, gimli::DW_TAG_structure_type, "Node");
        for alias_first in [false, true] {
            let architecture = target_architecture(path, bytes);
            let types = architecture.base().unwrap().types();
            let early = alias_first.then(|| imported(dies, types, alias_off));
            let node = kuna_dwarfstructs::intern_aggregate(types, node_die, dies, None,
                "anon_struct", &mut TypeWalk::with_gate(true), 1, false, false).unwrap();
            let alias = imported(dies, types, alias_off);
            assert_eq!(alias.get_name(), "Node");
            assert_eq!(alias.get_size(), node_die.byte_size.unwrap() as i32);
            assert!(!alias.is_incomplete());
            let next = node.get_field(0).expect("recursive next field");
            assert_eq!((next.name.as_str(), next.offset), ("next", 0));
            let target = next.field_type.get_ptr_to().unwrap();
            assert_eq!(target.get_id(), node.get_id());
            assert_eq!(target.get_name(), "Node");
            assert_eq!(target.get_size(), node.get_size());
            assert!(!target.is_incomplete());
            assert_eq!(target.get_field(0).unwrap().name, "next");
            assert_eq!(alias.get_field(0).unwrap().name, "next");
            assert_eq!(alias.get_field(1).unwrap().name, "visit");
            assert!(Rc::ptr_eq(&imported(dies, types, node_off), &node));
            if let Some(early) = early {
                assert_eq!(early.get_id(), alias.get_id());
                assert_eq!(early.get_name(), alias.get_name());
                assert_eq!(early.get_size(), node.get_size());
                assert!(!early.is_incomplete());
                assert_eq!(early.get_field(0).unwrap().name, "next");
                assert_eq!(early.get_field(1).unwrap().name, "visit");
            }
            drop(architecture);
            assert_eq!(alias.get_field(0).unwrap().name, "next");
        }
    });
}

#[test]
fn dwarf_recursive_callable_keeps_node_parameter_identity() {
    if !callable_child("dwarf_recursive_callable_keeps_node_parameter_identity") {
        return;
    }
    with_declarations("dwarf_declarations.c", "c11", &[], |dies, path, bytes| {
        let architecture = target_architecture(path, bytes);
        let types = architecture.base().unwrap().types();
        let (_, node_die) = named(dies, gimli::DW_TAG_structure_type, "Node");
        let node = kuna_dwarfstructs::intern_aggregate(types, node_die, dies, None, "anon_struct", &mut TypeWalk::with_gate(true), 1, false, false).unwrap();
        let visit = node.get_field(1).expect("source callback field");
        assert_eq!(visit.name, "visit");
        let code = visit.field_type.get_ptr_to().unwrap();
        assert_eq!(code.get_metatype(), type_metatype::TYPE_CODE);
        let proto = code.get_code_prototype().expect("source callback signature");
        assert_eq!(proto.num_params(), 1);
        let parameter = proto.get_param(0).unwrap().get_type().unwrap().get_ptr_to().unwrap();
        assert_eq!(parameter.get_id(), node.get_id());
        assert_eq!(parameter.get_name(), "Node");
    });
}

#[test]
fn untyped_callable_formals_are_refused_without_invented_void() {
    if !callable_child("untyped_callable_formals_are_refused_without_invented_void") {
        return;
    }
    let types = factory();
    let mut dies = BTreeMap::new();
    let mut code = DieSnap::new(gimli::DW_TAG_subroutine_type, 1);
    code.children.push(2);
    dies.insert(1, code);
    dies.insert(2, DieSnap::new(gimli::DW_TAG_formal_parameter, 2));
    for _ in 0..3 {
        assert!(build_datatype(Some(1), &dies, &types, 1, &mut TypeWalk::with_gate(true), false).is_none());
    }
    with_declarations("dwarf_callback_prototyped.c", "c11", &[], |genuine, path, bytes| {
        let architecture = target_architecture(path, bytes);
        let types = architecture.base().unwrap().types();
        let (fixed, _) = named(genuine, gimli::DW_TAG_typedef, "Fixed");
        let code = imported(genuine, types, fixed).get_ptr_to().unwrap();
        assert_eq!(code.get_code_prototype().unwrap().num_params(), 1,
            "a genuine typed formal must be admitted before testing malformed-formal refusal");
        let mut malformed = dies.clone();
        malformed.get_mut(&1).unwrap().prototyped = true;
        for _ in 0..3 {
            assert!(build_datatype(Some(1), &malformed, types, 1, &mut TypeWalk::with_gate(true), false).is_none());
            assert_eq!(imported(genuine, types, fixed).get_ptr_to().unwrap()
                .get_code_prototype().unwrap().num_params(), 1);
        }
    });
}

#[test]
fn same_spelled_enum_typedef_preserves_nominal_name_and_enumerators() {
    with_declarations("dwarf_declarations.c", "c11", &[], |dies, _, _| {
        let types = factory();
        let (off, _) = named(dies, gimli::DW_TAG_typedef, "Mode");
        let alias = imported(dies, &types, off);
        assert_eq!((alias.get_name(), alias.get_size(), alias.is_enum_type()), ("Mode", 4, true));
        for (value, name) in [(7, "Seven"), (0xffff_ffff, "Negative")] {
            assert!(alias.has_named_value(value));
            let representation = alias.get_matches(value).unwrap();
            assert_eq!(representation.match_name, [name]);
            assert!(!representation.complement);
            assert_eq!(representation.shift_amount, 0);
        }
    });
}


#[test]
fn source_code_typedef_does_not_replace_core_callable_identity() {
    with_declarations("dwarf_declarations.c", "c11", &[], |dies, _, _| {
        let types = factory();
        types.set_core_type("code", 1, type_metatype::TYPE_CODE, false).unwrap();
        types.cache_core_types().unwrap();
        let core = types.get_type_code().unwrap();
        let (off, alias_die) = named(dies, gimli::DW_TAG_typedef, "code");
        let record_die = &dies[&alias_die.type_ref.unwrap()];
        let record = kuna_dwarfstructs::intern_aggregate(&types, record_die, dies, Some("code"), "anon_struct", &mut TypeWalk::with_gate(true), 1, false, false).unwrap();
        let alias = imported(dies, &types, off);
        assert_eq!((alias.get_metatype(), alias.get_size()), (type_metatype::TYPE_STRUCT, 4));
        assert_eq!(record.get_size(), alias.get_size());
        assert_ne!(alias.get_id(), core.get_id());
        let field = alias.get_field(1).unwrap();
        assert_eq!((field.name.as_str(), field.offset, field.field_type.get_size(), field.field_type.get_metatype()), ("val", 2, 2, type_metatype::TYPE_UINT));
        assert!(Rc::ptr_eq(&types.get_type_code().unwrap(), &core), "source spelling cannot replace builtin callable");
    });
}

#[test]
fn known_declaration_keeps_opaque_pointer_result_and_source_names() {
    with_declarations("dwarf_declarations.c", "c11", &[], |dies, _, _| {
        let types = factory();
        let (_, sub) = named(dies, gimli::DW_TAG_subprogram, "consume_forward");
        let pieces = build_pieces("consume_forward", sub, dies, &types, 1).unwrap();
        assert_eq!(pieces.innames, ["value", "count"]);
        assert_eq!(pieces.outtype.unwrap().get_metatype(), type_metatype::TYPE_INT);
        assert_eq!(pieces.intypes[1].get_size(), 4);
        let forward = pieces.intypes[0].get_ptr_to().unwrap();
        assert_eq!(forward.get_name(), "ForwardAlias");
        assert!(forward.is_incomplete(), "true forward declaration must not acquire guessed layout");
    });
}

#[test]
fn original_default_authors_retains_declared_three_element_extent() {
    let source = "typedepth_x86_64.c";
    with_declarations(source, "c11", &[], |dies, _, _| {
        let types = factory();
        types.set_core_type("char", 1, type_metatype::TYPE_INT, true).unwrap();
        types.cache_core_types().unwrap();
        let (_, variable) = named(dies, gimli::DW_TAG_variable, "default_authors");
        let ty = imported(dies, &types, variable.type_ref.unwrap());
        assert_eq!(ty.num_elements(), Some(3));
        assert_eq!(ty.get_size(), 3 * types.get_size_of_pointer());
        assert_eq!(ty.get_array_base().unwrap().get_ptr_to().unwrap().get_name(), "char");
    });
}
