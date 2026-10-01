use super::*;
use crate::dtype::{TypeFactory, TypeFactoryImpl};

fn factory() -> TypeFactoryImpl {
    let factory = TypeFactoryImpl::new();
    factory.set_default_alignment_map();
    factory.set_max_basetype_size(8);
    factory.set_core_type("undefined", 1, type_metatype::TYPE_UNKNOWN, false).unwrap();
    factory.cache_core_types().unwrap();
    factory
}

#[test]
fn code_pointee_is_blocked() {
    let factory = factory();
    let code = factory.get_type_code().unwrap();
    assert!(blocks_value_type(&code));
}

#[test]
fn ordinary_pointees_are_untouched() {
    let factory = factory();
    for meta in [
        type_metatype::TYPE_UNKNOWN,
        type_metatype::TYPE_INT,
        type_metatype::TYPE_UINT,
        type_metatype::TYPE_PTR,
        type_metatype::TYPE_STRUCT,
    ] {
        let t = match meta {
            type_metatype::TYPE_PTR => {
                let pointee = factory.get_base(1, type_metatype::TYPE_UNKNOWN).unwrap();
                factory.get_type_pointer(8, pointee, 1).unwrap()
            }
            type_metatype::TYPE_STRUCT => factory.get_type_struct("record").unwrap(),
            _ => factory.get_base(1, meta).unwrap(),
        };
        assert!(!blocks_value_type(&t), "{meta:?} must not be blocked");
    }
}
