use super::*;
use crate::dtype::{type_metatype, TypeFactory, TypeFactoryImpl, TypeField};
use kuna_base::marshal::{Decoder, PackedDecode, XmlEncode};
use kuna_base::space::AddrSpaceManager;

fn factory() -> TypeFactoryImpl {
    let factory = TypeFactoryImpl::new();
    factory.setup_sizes(Some(4), 8, 8);
    factory.set_max_basetype_size(8);
    factory
}

#[test]
fn recursive_used_closure_reserves_before_descent_and_excludes_unreferenced_types() {
    let factory = factory();
    // A source declaration retains its recursive shell through completion.
    // Inferred records intentionally leave earlier pointers transient.
    let shell = factory.kuna_declare_record("Node", false).unwrap();
    let pointer = factory.get_type_pointer(8, Rc::clone(&shell), 1).unwrap();
    let integer = factory.get_base(4, type_metatype::TYPE_INT).unwrap();
    let record = factory.set_fields_struct_raw(&shell,
        vec![TypeField::new(23, 0, "next", Rc::clone(&pointer)),
            TypeField::new(71, 8, "value", integer)], vec![], 16, 8, 0).unwrap();
    let _unused = factory.get_type_struct("Unreachable").unwrap();
    let types = ResultTypeTable::shared();
    let mut body = Vec::new();
    pointer.encode_ref(&mut ResultTypeEncoder::new(&mut PackedEncode::new(&mut body), &types)).unwrap();
    assert!(types.borrow().entries.iter().any(|entry| entry.name == record.get_name()));
    assert!(!types.borrow().entries.iter().any(|entry| entry.name == "Unreachable"));
    let mut prelude = Vec::new();
    ResultTypeTable::encode_prelude_packed(&types, &mut prelude).unwrap();
    let manager = AddrSpaceManager::new();
    let mut decoder = PackedDecode::new(&manager);
    decoder.ingest_stream(&prelude).unwrap();
    let root = decoder.open_element_id(&ELEM_KUNA_RESULT).unwrap();
    assert_eq!(decoder.read_unsigned_integer_id(&ATTRIB_KUNA_RESULT_VERSION).unwrap(), 1);
    let mut reservations = Vec::new();
    let mut definitions = Vec::new();
    while decoder.peek_element().unwrap() != 0 {
        let element = decoder.open_element().unwrap();
        let handle = decoder.read_unsigned_integer_id(&ATTRIB_KUNA_LOCAL).unwrap();
        if element == ELEM_KUNA_TYPE.get_id() {
            assert!(definitions.is_empty());
            reservations.push(handle);
        } else {
            assert_eq!(element, ELEM_KUNA_DEFINITION.get_id());
            assert!(reservations.contains(&handle));
            definitions.push(handle);
        }
        decoder.close_element_skipping(element).unwrap();
    }
    decoder.close_element(root).unwrap();
    assert_eq!(reservations, definitions);
    assert_eq!(reservations.len(), 3);
}

#[test]
fn empty_result_still_acknowledges_and_ordinary_encoder_has_no_extension_grammar() {
    let types = ResultTypeTable::shared();
    let mut prelude = Vec::new();
    ResultTypeTable::encode_prelude_packed(&types, &mut prelude).unwrap();
    let manager = AddrSpaceManager::new();
    let mut decoder = PackedDecode::new(&manager);
    decoder.ingest_stream(&prelude).unwrap();
    let root = decoder.open_element_id(&ELEM_KUNA_RESULT).unwrap();
    assert_eq!(decoder.read_unsigned_integer_id(&ATTRIB_KUNA_RESULT_VERSION).unwrap(), 1);
    assert_eq!(decoder.peek_element().unwrap(), 0);
    decoder.close_element(root).unwrap();
    let factory = factory();
    let local = factory.get_type_struct("Local").unwrap();
    let mut ordinary = Vec::new();
    local.encode_ref(&mut XmlEncode::new(&mut ordinary)).unwrap();
    let ordinary = String::from_utf8(ordinary).unwrap();
    assert!(ordinary.contains("typeref"));
    assert!(!ordinary.contains("kuna_"));
}

#[test]
fn same_spelled_nominals_and_markup_only_dependencies_have_distinct_handles() {
    let first = factory();
    let second = factory();
    let a = first.get_type_struct("Local").unwrap();
    let b = second.get_type_struct("Local").unwrap();
    assert_eq!(a.get_id(), b.get_id());
    let types = ResultTypeTable::shared();
    let ah = types.borrow_mut().markup_handle(&a).unwrap();
    let bh = types.borrow_mut().markup_handle(&b).unwrap();
    assert_ne!(ah, bh);
    assert_eq!(types.borrow_mut().markup_handle(&a), Some(ah));
    let mut prelude = Vec::new();
    ResultTypeTable::encode_prelude_packed(&types, &mut prelude).unwrap();
    let entries = &types.borrow().entries;
    assert_eq!(entries.len(), 2);
    assert!(entries.iter().all(|entry| entry.definition.is_some()));
    assert!(entries.iter().all(|entry| entry.markup_root.is_none()));
}

#[test]
fn qualified_completion_keeps_one_envelope_identity_across_markup_and_encoding() {
    let factory = factory();
    let shell = factory.get_type_struct("QualifiedNode").unwrap();
    let qualified = factory.get_qualified_type(Rc::clone(&shell), crate::kuna_typequal::CONST).unwrap();
    let integer = factory.get_base(4, type_metatype::TYPE_INT).unwrap();
    let _complete = factory.set_fields_struct_raw(&shell,
        vec![TypeField::new(31, 0, "value", integer)], vec![], 4, 4, 0).unwrap();
    let types = ResultTypeTable::shared();
    let handle = types.borrow_mut().markup_handle(&qualified).unwrap();
    assert_eq!(types.borrow_mut().markup_handle(&qualified), Some(handle));
    let mut body = Vec::new();
    qualified.encode_ref(
        &mut ResultTypeEncoder::new(&mut PackedEncode::new(&mut body), &types)).unwrap();
    let mut prelude = Vec::new();
    ResultTypeTable::encode_prelude_packed(&types, &mut prelude).unwrap();
    let types = types.borrow();
    assert_eq!(types.keys.get(&(Rc::as_ptr(&qualified) as usize)), Some(&0));
    assert_eq!(types.entries.iter().filter(|entry| entry.name == "QualifiedNode").count(), 2);
    assert!(types.entries.iter().all(|entry| entry.definition.is_some()));
}
