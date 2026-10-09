use super::*;
use std::path::Path;
use kuna_harness::dwarf_fixture as producer;

fn with_declarations(source: &str, standard: &str, flags: &[&str], check: impl Fn(&BTreeMap<usize, DieSnap>)) {
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
    let unit = dwarf.unit(units.next().unwrap().expect("compiler must supply a DWARF unit")).unwrap();
    check(&snapshot_unit(&dwarf, &unit));
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
    for standard in ["c89", "c11"] {
        with_declarations("dwarf_callback_prototyped.c", standard, &[], |dies| {
            for name in ["Open", "Closed", "Fixed", "Variadic"] {
                let types = factory();
                let (off, _) = named(dies, gimli::DW_TAG_typedef, name);
                let pointer = imported(dies, &types, off);
                let code = pointer.get_ptr_to().expect("callback pointer");
                assert_eq!(code.get_metatype(), type_metatype::TYPE_CODE, "{standard} {name} must not become void*");
            }
        });
    }
}

#[test]
fn dwarf_callback_parameter_order_and_aliases_are_source_authored() {
    with_declarations("dwarf_declarations.c", "c11", &[], |dies| {
        let types = factory();
        let (_, sub) = named(dies, gimli::DW_TAG_subprogram, "invoke_flags");
        let pieces = build_pieces("invoke_flags", sub, dies, &types, 1).expect("retain known signature");
        assert_eq!(pieces.innames, ["value", "callback"]);
        assert_eq!(pieces.intypes[0].get_name(), "Flags");
        assert_eq!(pieces.intypes[0].get_metatype(), type_metatype::TYPE_UINT);
        assert_eq!(pieces.intypes[0].get_size(), 1);
        let code = pieces.intypes[1].get_ptr_to().unwrap();
        assert_eq!(code.get_metatype(), type_metatype::TYPE_CODE);
    });
}



#[test]
fn dwarf_recursive_callable_keeps_completed_node_parameter() {
    with_declarations("dwarf_declarations.c", "c11", &[], |dies| {
        let types = factory();
        let (_, node_die) = named(dies, gimli::DW_TAG_structure_type, "Node");
        let node = kuna_dwarfstructs::intern_aggregate(&types, node_die, dies, None, "anon_struct", &mut TypeWalk::with_gate(true), 1, false, false).unwrap();
        let visit = node.get_field(1).expect("source callback field");
        assert_eq!(visit.name, "visit");
        let code = visit.field_type.get_ptr_to().unwrap();
        assert_eq!(code.get_metatype(), type_metatype::TYPE_CODE);
    });
}

#[test]
fn untyped_callable_formals_are_refused_without_invented_void() {
    let types = factory();
    let mut dies = BTreeMap::new();
    let mut code = DieSnap::new(gimli::DW_TAG_subroutine_type, 1);
    code.children.push(2);
    dies.insert(1, code);
    dies.insert(2, DieSnap::new(gimli::DW_TAG_formal_parameter, 2));
    for _ in 0..3 {
        assert!(build_datatype(Some(1), &dies, &types, 1, &mut TypeWalk::with_gate(true), false).is_none());
    }
}

#[test]
fn same_spelled_enum_typedef_preserves_nominal_name_and_enumerators() {
    with_declarations("dwarf_declarations.c", "c11", &[], |dies| {
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
fn known_declaration_keeps_opaque_pointer_result_and_source_names() {
    with_declarations("dwarf_declarations.c", "c11", &[], |dies| {
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
    with_declarations(source, "c11", &[], |dies| {
        let types = factory();
        let (_, variable) = named(dies, gimli::DW_TAG_variable, "default_authors");
        let ty = imported(dies, &types, variable.type_ref.unwrap());
        assert_eq!(ty.num_elements(), Some(3));
        assert_eq!(ty.get_size(), 3 * types.get_size_of_pointer());
        assert_eq!(ty.get_array_base().unwrap().get_ptr_to().unwrap().get_name(), "char");
    });
}
