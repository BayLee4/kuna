//! Unit tests for [`super`] — the by-value slot arithmetic.

use super::*;

#[test]
fn slots_are_four_byte_aligned() {
    assert_eq!(align4(1), 4);
    assert_eq!(align4(4), 4);
    assert_eq!(align4(5), 8);
    assert_eq!(align4(8), 8);
}

#[test]
fn a_range_inside_the_object_is_built_by_its_constructor() {
    assert!(within(0, 4, 4));
    assert!(within(4, 4, 8));
    assert!(within(0, 8, 8));
}

#[test]
fn a_range_reaching_past_the_object_is_not() {
    assert!(!within(4, 4, 4));
    assert!(!within(0, 8, 4));
    assert!(!within(u64::MAX - 1, 4, 8));
    assert!(!within(0, 0, 4));
}

#[test]
fn the_option_is_on_or_off() {
    assert!(OptionMsvcByval.apply("on").unwrap().0);
    assert!(!OptionMsvcByval.apply("off").unwrap().0);
    assert!(OptionMsvcByval.apply("maybe").is_err());
}

#[test]
fn generated_declaration_requires_the_same_live_source_owner() {
    let source = Rc::new(FuncProto::new());
    let mut declaration = ByvalDecl::new(PrototypePieces::default(), 0);
    assert!(!declaration.matches_generated_source(&source));
    declaration.bind_generated_source(&source);
    assert!(declaration.matches_generated_source(&source));
    let authored = Rc::new((*source).clone());
    assert_eq!(authored.get_comparable_flags(), source.get_comparable_flags());
    assert!(!declaration.matches_generated_source(&authored));
    let held = Rc::downgrade(&source);
    drop(source);
    assert!(held.upgrade().is_none(), "generated metadata must not retain the source owner");
}

#[test]
fn generated_input_extension_preserves_independent_working_facts() {
    use crate::fspec::{ParameterPieces, parameter_pieces_flags};
    let register = Rc::new(AddrSpace::new(
        spacetype::IPTR_PROCESSOR, "register", false, 4, 1, 1, 0, 1, 1,
    ));
    let input = ParameterPieces {
        addr: Address::new(Rc::clone(&register), 0x10),
        type_: Some(Rc::new(Datatype::new(4, type_metatype::TYPE_INT))),
        flags: parameter_pieces_flags::TYPELOCK | parameter_pieces_flags::NAMELOCK,
    };
    let output = ParameterPieces {
        addr: Address::new(Rc::clone(&register), 0),
        type_: Some(Rc::new(Datatype::new(1, type_metatype::TYPE_UINT))),
        flags: 0,
    };
    let mut source = FuncProto::new();
    source.attach_internal_store(Rc::new(Datatype::new(0, type_metatype::TYPE_VOID)));
    source.set_param(0, "authored_prefix", &input);
    source.set_param_usepoint(0, Address::new(Rc::clone(&register), 0x100));
    source.set_output(&output);
    source.set_dotdotdot(true);
    source.set_extra_pop(4);
    source.set_no_return(true);
    source.set_inject_id(7);
    let source = Rc::new(source);
    let mut allocated = (*source).clone();
    allocated.set_param(1, "generated_tail", &ParameterPieces {
        addr: Address::new(Rc::clone(&register), 0x20),
        ..input.clone()
    });
    allocated.set_output(&input);
    allocated.set_output_lock(true);
    allocated.set_extra_pop(12);
    allocated.set_no_return(false);
    allocated.cancel_inject_id();
    let mut working = (*source).clone();
    working.append_generated_inputs(&allocated);
    assert_eq!(working.num_params(), 2);
    assert_eq!(working.get_param(0).unwrap().get_name(), "authored_prefix");
    assert_eq!(working.get_param(0).unwrap().get_address(), input.addr);
    assert_eq!(working.get_param(0).unwrap().get_usepoint(),
        Address::new(Rc::clone(&register), 0x100));
    assert_eq!(working.get_param(0).unwrap().get_flags(), input.flags);
    assert_eq!(working.get_param(1).unwrap().get_name(), "generated_tail");
    assert_eq!(working.get_output().get_address(), output.addr);
    assert_eq!(working.get_output().get_size(), 1);
    assert!(!working.is_output_locked());
    assert_eq!(working.get_extra_pop(), 4);
    assert!(working.is_no_return() && working.is_inline());
    assert_eq!(working.get_inject_id(), 7);
    assert!(!working.is_dotdotdot());
    assert_eq!(source.num_params(), 1);
    assert!(source.is_dotdotdot());
}
