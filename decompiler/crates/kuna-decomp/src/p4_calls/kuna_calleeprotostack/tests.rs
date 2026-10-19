//! Unit tests for [`super`] — the declared-callee stack contract.

use std::rc::Rc;

use crate::dtype::{type_metatype, Datatype};

use super::*;

/// A prototype carrying the stand-alone store `FuncProto::set_input_lock` needs
/// to walk its parameter list.
///
/// Production never reaches the mutator this way — `resolve_declared_extra_pop`
/// runs on a prototype `seed_locked_from_pieces` has just given a store, and
/// `declared_caller_frame_floor` only ever READS one, through `is_input_locked`,
/// which reports a store-less prototype as unlocked rather than dereferencing a
/// null store (see [`store_less_prototype_declines`]).
fn void_store_proto() -> FuncProto {
    let mut fp = FuncProto::new();
    fp.attach_internal_store(Rc::new(Datatype::new(0, type_metatype::TYPE_VOID)));
    fp
}

#[test]
fn above_callee_frame_reads_the_offset_as_signed() {
    // A 32-bit stack space: 0xffffffec is -20, not 4294967276.
    assert!(!above_callee_frame(0xffffffec, 4, 4, 4));
    assert!(above_callee_frame(0x4, 4, 4, 4));
    assert!(above_callee_frame(0x14, 4, 4, 4));
}

#[test]
fn above_callee_frame_keeps_the_return_address_and_parameter_area() {
    // floor 20 == a four-parameter __stdcall: slots 0 (return address) through
    // 16 (the last parameter) stay guarded, 20 and up do not.
    assert!(!above_callee_frame(0x0, 4, 4, 20));
    assert!(!above_callee_frame(0x10, 4, 4, 20));
    assert!(above_callee_frame(0x14, 4, 4, 20));
}

#[test]
fn declared_caller_frame_floor_declines_without_evidence() {
    let mut fp = void_store_proto();
    // Unlocked, no model: no claim.
    assert_eq!(declared_caller_frame_floor(true, &fp), None);
    fp.set_extra_pop(20);
    // Still unlocked.
    assert_eq!(declared_caller_frame_floor(true, &fp), None);
    fp.set_input_lock(true);
    assert_eq!(declared_caller_frame_floor(true, &fp), Some(20));
    // The option is the outermost gate.
    assert_eq!(declared_caller_frame_floor(false, &fp), None);
    // A variadic callee reads above its declared parameters.
    fp.set_dotdotdot(true);
    assert_eq!(declared_caller_frame_floor(true, &fp), None);
}

#[test]
fn resolve_declared_extra_pop_leaves_a_model_that_states_its_own() {
    let mut fp = void_store_proto();
    fp.set_input_lock(true);
    fp.set_extra_pop(4); // as a __cdecl model would
    resolve_declared_extra_pop(true, &mut fp);
    assert_eq!(fp.get_extra_pop(), 4);
}

#[test]
fn resolve_declared_extra_pop_needs_the_lock() {
    let mut fp = FuncProto::new();
    fp.set_extra_pop(EXTRAPOP_UNKNOWN);
    resolve_declared_extra_pop(true, &mut fp);
    assert_eq!(fp.get_extra_pop(), EXTRAPOP_UNKNOWN);
}

#[test]
fn logical_cleanup_waits_for_assigned_working_input_storage() {
    use crate::dtype::{TypeFactory, TypeFactoryImpl, type_class};
    use crate::fspec::{ParamEntry, ProtoModel, PrototypePieces};
    use kuna_base::space::{AddrSpace, AddrSpaceManager, ConstantSpace, spacetype};
    let mut manager = AddrSpaceManager::new();
    manager.insert_space(Rc::new(ConstantSpace::new())).unwrap();
    let register = Rc::new(AddrSpace::new(
        spacetype::IPTR_PROCESSOR, "register", false, 4, 1, 1, 0, 1, 1,
    ));
    manager.insert_space(Rc::clone(&register)).unwrap();
    manager.set_default_code_space(1).unwrap();
    manager.set_default_data_space(1).unwrap();
    let stack = Rc::new(AddrSpace::new(
        spacetype::IPTR_SPACEBASE, "stack", false, 4, 1, 2, 0, 1, 1,
    ));
    manager.insert_space(Rc::clone(&stack)).unwrap();
    let manager = Rc::new(manager);
    let types = TypeFactoryImpl::new();
    types.set_default_alignment_map();
    types.setup_sizes(Some(4), 4, 4);
    types.set_proto_context(Rc::clone(&manager));
    let mut model = ProtoModel::new(&manager);
    model.build_param_list("standard").unwrap();
    model.set_extra_pop(EXTRAPOP_UNKNOWN);
    model.input_mut().push_entry(ParamEntry::seed(
        0, type_class::TYPECLASS_GENERAL, register, 0x4, 4, 1, 0,
        0, true, false, &[], &manager,
    ).unwrap());
    let input = model.input_mut();
    input.push_entry(ParamEntry::seed(
        1, type_class::TYPECLASS_GENERAL, stack, 4, 0x100, 1, 4,
        0, true, false, input.get_entry(), &manager,
    ).unwrap());
    input.finish_decode();
    let pointer = types.get_type_pointer(
        4, Rc::new(Datatype::new(4, type_metatype::TYPE_INT)), 1,
    ).unwrap();
    let pieces = PrototypePieces {
        outtype: Some(types.get_type_void().unwrap()),
        intypes: vec![pointer; 2],
        innames: vec!["self".into(), "other".into()],
        first_var_arg_slot: -1,
        ..Default::default()
    };
    let model = ProtoModel::copy_named("__thiscall", &model);
    let mut source = FuncProto::from_logical(&pieces, Rc::new(model), &types).unwrap();
    resolve_declared_extra_pop(true, &mut source);
    assert_eq!(source.get_extra_pop(), EXTRAPOP_UNKNOWN);
    let mut working = types.acquire_working_proto(&source).unwrap();
    resolve_declared_extra_pop(true, &mut working);
    assert_eq!(working.get_extra_pop(), 8);
    assert_eq!(working.get_param(1).unwrap().get_address().get_offset(), 4);
    assert_eq!(source.get_extra_pop(), EXTRAPOP_UNKNOWN);
    assert!(source.get_param(1).unwrap().get_address().is_invalid());
}

#[test]
fn store_less_prototype_declines() {
    // `Heritage::guardCalls` asks every call's prototype for a floor, including
    // one that never reached `setScope` and so carries no store.  Both entry
    // points read the lock through `FuncProto::is_input_locked`, which answers
    // "unlocked" for a store-less prototype, so neither claims anything.
    let mut fp = FuncProto::new();
    assert!(!fp.has_store());
    fp.set_extra_pop(20);
    assert_eq!(declared_caller_frame_floor(true, &fp), None);
    resolve_declared_extra_pop(true, &mut fp);
    assert_eq!(fp.get_extra_pop(), 20);
}

fn fixed_model_proto(pop: i32) -> FuncProto {
    let manager = kuna_base::space::AddrSpaceManager::new();
    let mut model = crate::fspec::ProtoModel::new(&manager);
    model.set_extra_pop(pop);
    let mut proto = void_store_proto();
    proto.set_model(Some(Rc::new(model)));
    proto.set_input_lock(true);
    proto
}

#[test]
fn fixed_model_pop_completes_only_the_unknown_working_copy() {
    // Known RISC/no-stack-return, x86-32 and x86-64 model facts must not be
    // replaced by the 32-bit unknown-model inference's four-byte default.
    for pop in [0, 4, 8] {
        let mut source = fixed_model_proto(pop);
        source.set_extra_pop(EXTRAPOP_UNKNOWN);
        let source = Rc::new(source);
        let held = Rc::clone(&source);
        let mut working = FuncProto::new();
        working.copy(&source);
        resolve_declared_extra_pop(true, &mut working);
        assert_eq!(working.get_extra_pop(), pop);
        assert_eq!(source.get_extra_pop(), EXTRAPOP_UNKNOWN);
        assert_eq!(held.get_extra_pop(), EXTRAPOP_UNKNOWN);
        assert!(Rc::ptr_eq(source.model(), working.model()));
    }
}

#[test]
fn fixed_model_resolution_preserves_numeric_site_and_custom_effect_facts() {
    use crate::dtype::{TypeFactory, TypeFactoryImpl};
    use crate::fspec::{effect_type, EffectRecord, ParameterPieces, PrototypePieces};
    use kuna_base::address::Address;
    use kuna_base::space::{spacetype, AddrSpace, AddrSpaceManager};
    use kuna_num::pcoderaw::VarnodeData;
    let register = Rc::new(AddrSpace::new(
        spacetype::IPTR_PROCESSOR, "register", false, 8, 1, 0, 0, 1, 1,
    ));
    let storage = Address::new(Rc::clone(&register), 0x20);
    let types = TypeFactoryImpl::new();
    let word = Rc::new(Datatype::new(4, type_metatype::TYPE_UINT));
    let mut model = crate::fspec::ProtoModel::new(&AddrSpaceManager::new());
    model.set_extra_pop(8);
    let pieces = PrototypePieces {
        outtype: Some(types.get_type_void().unwrap()),
        intypes: vec![Rc::clone(&word)],
        innames: vec!["authored".into()],
        input_storage: vec![(0, ParameterPieces {
            addr: storage.clone(), type_: Some(Rc::clone(&word)),
            flags: crate::fspec::parameter_pieces_flags::CUSTOM_STORAGE,
        })],
        first_var_arg_slot: -1,
        ..Default::default()
    };
    let mut proto = FuncProto::from_logical(&pieces, Rc::new(model), &types).unwrap();
    proto.set_extra_pop(12); // Explicit site evidence can disagree with the model.
    proto.set_no_return(true);
    proto.set_inline(true);
    proto.push_effect_override(EffectRecord::from_varnode(VarnodeData {
        space: Some(register), offset: 0x20, size: 4,
    }, effect_type::UNAFFECTED));
    resolve_declared_extra_pop(true, &mut proto);
    assert_eq!(proto.get_extra_pop(), 12);
    assert!(proto.has_custom_storage() && proto.is_model_locked());
    assert!(proto.is_no_return() && proto.is_inline() && proto.has_effect_override());
    assert_eq!(proto.has_effect(&storage, 4), effect_type::UNAFFECTED);
    let input = proto.get_param(0).unwrap();
    assert_eq!(input.get_name(), "authored");
    assert_eq!(input.get_address(), storage);
    assert!(Rc::ptr_eq(input.get_type().unwrap(), &word));
}

#[test]
fn fixed_model_resolution_keeps_option_and_lock_gates() {
    let mut proto = fixed_model_proto(8);
    proto.set_extra_pop(EXTRAPOP_UNKNOWN);
    resolve_declared_extra_pop(false, &mut proto);
    assert_eq!(proto.get_extra_pop(), EXTRAPOP_UNKNOWN);
    proto.set_input_lock(false);
    resolve_declared_extra_pop(true, &mut proto);
    assert_eq!(proto.get_extra_pop(), EXTRAPOP_UNKNOWN);
}

#[test]
fn fixed_model_fact_does_not_require_argument_storage_inference() {
    use crate::fspec::ParameterPieces;
    use kuna_base::address::Address;
    let word = Rc::new(Datatype::new(4, type_metatype::TYPE_UINT));
    for pop in [8, EXTRAPOP_UNKNOWN] {
        let mut proto = fixed_model_proto(pop);
        proto.set_param(0, "pending", &ParameterPieces {
            addr: Address::new_invalid(), type_: Some(Rc::clone(&word)), flags: 0,
        });
        proto.set_input_lock(true);
        proto.set_extra_pop(EXTRAPOP_UNKNOWN);
        resolve_declared_extra_pop(true, &mut proto);
        assert_eq!(proto.get_extra_pop(), pop);
        assert!(proto.get_param(0).unwrap().get_address().is_invalid());
    }
}
