//! Tests for the remaining coreaction classes (`coreaction_render.rs`).
//!
//! Three kinds of checks:
//!
//!   1. **Identity** — every ported action carries the exact `name()` /
//!      `getGroup()` / flags the C++ constructor set, and clones only when its
//!      group is in the [`ActionGroupList`].
//!   2. **Stateful behavior on owned fields** — the parts of each `apply`/`reset`
//!      that bind only to this file's own fields (the `localcount`/`numpass`/
//!      `analysis_finished` gating, the `reset` zeroing, the `propagateIndirect`/
//!      `stackspace` configuration) are exercised directly on the concrete
//!      structs.
//!   3. **Seam contract** — every seamed `apply` returns `0` and bumps no count
//!      on a hand-built [`Funcdata`] (the C++ "changes are signalled by count"
//!      contract: an unrealized body must report no change).

use std::rc::Rc;

use kuna_base::address::Address;
use kuna_base::space::{
    addrspace_flags, spacetype, AddrSpace, AddrSpaceManager, ConstantSpace, UniqueSpace,
};

use super::*;
use crate::action::ActionGroupList;
use crate::context::ArchContext;
use crate::dtype::{type_class, type_metatype, Datatype, TypeFactory, TypeFactoryImpl};
use crate::fspec::{FuncCallSpecs, ParamEntry, ProtoModel, PrototypePieces};
use crate::context::{OpId, TypeOp, VarnodeId};
use kuna_num::opcodes::OpCode;

mod config_ir_regressions {
    use super::{Address, Datatype, Funcdata, OpCode, Rc, VarnodeId, build_fd, ram_space, type_metatype};

    fn input(fd: &mut Funcdata, offset: u64, size: i32) -> VarnodeId {
        let vn = fd.new_varnode(
            size,
            &Address::new(ram_space(fd), offset),
            Some(Rc::new(Datatype::new(size, type_metatype::TYPE_UNKNOWN))),
        );
        fd.vbank_mut().set_input(vn, &mut |_, _, _| Ok(())).unwrap()
    }

    #[test]
    fn phi_sharing_respects_edge_copy_values_and_predecessor_order() {
            let mut fd = build_fd();
            let root = fd.bblocks_root_pub();
            let entry = fd.bblocks_mut().new_block_basic(root);
            let left = fd.bblocks_mut().new_block_basic(root);
            let right = fd.bblocks_mut().new_block_basic(root);
            let block = fd.bblocks_mut().new_block_basic(root);
            fd.bblocks_mut().add_edge(entry, left);
            fd.bblocks_mut().add_edge(entry, right);
            fd.bblocks_mut().add_edge(left, block);
            fd.bblocks_mut().add_edge(right, block);
            fd.bblocks_mut().set_start_block(root, entry);
            let address = Address::new(ram_space(&fd), 0x1000);
            let a = input(&mut fd, 0x40, 4);
            let b = input(&mut fd, 0x48, 4);
            let copy_a = fd.new_op(1, address.clone());
            fd.op_set_opcode_code(copy_a, OpCode::CPUI_COPY);
            let a_copy = fd.new_unique_out(4, copy_a).unwrap();
            fd.op_set_input(copy_a, a, 0).unwrap();
            fd.op_insert_end(copy_a, left);
            let phi = fd.new_op(2, address.clone());
            fd.op_set_opcode_code(phi, OpCode::CPUI_MULTIEQUAL);
            let machine = fd.new_unique_out(4, phi).unwrap();
            fd.op_set_input(phi, a_copy, 0).unwrap();
            fd.op_set_input(phi, b, 1).unwrap();
            fd.op_insert_begin(phi, block);
            let projection = fd.new_op(2, address.clone());
            fd.op_set_opcode_code(projection, OpCode::CPUI_MULTIEQUAL);
            let source = fd.new_unique_out(4, projection).unwrap();
            fd.op_set_input(projection, a, 0).unwrap();
            fd.op_set_input(projection, b, 1).unwrap();
            fd.op_insert_begin(projection, block);
            let swapped_phi = fd.new_op(2, address.clone());
            fd.op_set_opcode_code(swapped_phi, OpCode::CPUI_MULTIEQUAL);
            let swapped = fd.new_unique_out(4, swapped_phi).unwrap();
            fd.op_set_input(swapped_phi, b, 0).unwrap();
            fd.op_set_input(swapped_phi, a, 1).unwrap();
            fd.op_insert_begin(swapped_phi, block);
            let consumer = fd.new_op(4, address);
            fd.op_set_opcode_code(consumer, OpCode::CPUI_CALL);
            let target = fd.new_constant(8, 0x2000);
            fd.op_set_input(consumer, target, 0).unwrap();
            fd.op_set_input(consumer, machine, 1).unwrap();
            fd.op_set_input(consumer, source, 2).unwrap();
            fd.op_set_input(consumer, swapped, 3).unwrap();
            fd.op_insert_end(consumer, block);
            let mut action = crate::coreaction_render::ActionMultiCse::boxed("analysis");
            let mut context = crate::action::ActionContext::new();
            action.apply(&mut fd, &mut context);
            let use_op = fd.obank().get(consumer).unwrap();
            assert_eq!(use_op.get_in(1), use_op.get_in(2));
            assert_ne!(use_op.get_in(1), use_op.get_in(3), "predecessor permutation is not equivalent");
            assert_eq!(action.base().count, 1);
            action.apply(&mut fd, &mut context);
            assert_eq!(action.base().count, 1, "sharing reaches a fixed point");
        }
}

// -----------------------------------------------------------------------------
// Harness (mirrors coreaction_cleanup.rs / coreaction_protos.rs fixtures)
// -----------------------------------------------------------------------------

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
    Funcdata::new("func", "func", glb, addr, 0x10000000, 0x40).unwrap()
}

fn ram_space(fd: &Funcdata) -> Rc<AddrSpace> {
    Rc::clone(fd.get_arch().manage().get_space_by_name("ram").unwrap())
}

fn typed_call_fixture() -> (Funcdata, Rc<Datatype>, Rc<ProtoModel>) {
    typed_call_fixture_with_globals(|_, _| {})
}

fn typed_call_fixture_with_globals(
    configure: impl FnOnce(&mut ArchContext, &Rc<Datatype>),
) -> (Funcdata, Rc<Datatype>, Rc<ProtoModel>) {
    let mut manager = build_manager();
    let register = Rc::new(AddrSpace::new(
        spacetype::IPTR_PROCESSOR, "register", false, 8, 1, 3,
        addrspace_flags::hasphysical, 1, 1,
    ));
    manager.insert_space(register.clone()).unwrap();
    manager.insert_space(Rc::new(kuna_base::space::FspecSpace::new(4))).unwrap();
    let manager = Rc::new(manager);
    let mut model = ProtoModel::new(&manager);
    model.build_param_list("standard").unwrap();
    model.set_name("callback");
    for (input, offset) in [(true, 0x10), (false, 0x20)] {
        let entry = ParamEntry::seed(
            0, type_class::TYPECLASS_GENERAL, register.clone(), offset, 4, 1, 0,
            0, true, false, &[], &manager,
        ).unwrap();
        let list = if input { model.input_mut() } else { model.output_mut() };
        list.push_entry(entry);
        list.finish_decode();
    }
    let model = Rc::new(model);
    let factory = Rc::new(TypeFactoryImpl::new());
    factory.set_default_alignment_map();
    factory.set_max_basetype_size(8);
    factory.set_core_type("void", 0, type_metatype::TYPE_VOID, false).unwrap();
    factory.set_core_type("int4", 4, type_metatype::TYPE_INT, false).unwrap();
    factory.cache_core_types().unwrap();
    factory.set_proto_context(manager.clone());
    factory.set_proto_models(Some(model.clone()), Default::default());
    let int_type = factory.get_base(4, type_metatype::TYPE_INT).unwrap();
    let code = factory.get_type_code_proto(&PrototypePieces {
        outtype: Some(int_type.clone()),
        intypes: vec![int_type],
        innames: vec!["argument".to_owned()],
        first_var_arg_slot: -1,
        ..Default::default()
    }).unwrap();
    let mut arch = ArchContext::new_shared(manager);
    let address = Address::new(arch.manage().get_space_by_name("ram").unwrap().clone(), 0x1000);
    arch.types = Some(factory);
    arch.defaultfp = Some(model.clone());
    configure(&mut arch, &code);
    let mut fd = Funcdata::new("typed", "typed", Rc::new(arch), address, 0x10000000, 0x40).unwrap();
    fd.start_type_recovery();
    (fd, code, model)
}

fn add_typed_indirect_call(
    fd: &mut Funcdata, code: &Rc<Datatype>, model: Rc<ProtoModel>, offset: u64,
) -> (OpId, VarnodeId, VarnodeId) {
    let register = fd.get_arch().manage().get_space_by_name("register").unwrap().clone();
    let factory = fd.get_arch().types_rc().unwrap();
    let pointer = factory.get_type_pointer(8, code.clone(), 1).unwrap();
    let int_type = factory.get_base(4, type_metatype::TYPE_INT).unwrap();
    let call = fd.new_op(3, Address::new(ram_space(fd), offset));
    fd.op_set_opcode(call, TypeOp::new(
        OpCode::CPUI_CALLIND, crate::op::pcodeop_flags::call, "CALLIND",
    ));
    let target = fd.new_varnode(8, &Address::new(register.clone(), 0x80), Some(pointer));
    let discarded = fd.new_varnode(4, &Address::new(register.clone(), 0x30), Some(int_type.clone()));
    let argument = fd.new_varnode(4, &Address::new(register.clone(), 0x10), Some(int_type));
    fd.op_set_input(call, target, 0).unwrap();
    fd.op_set_input(call, discarded, 1).unwrap();
    fd.op_set_input(call, argument, 2).unwrap();
    let output = fd.new_varnode_out(4, &Address::new(register.clone(), 0x20), call).unwrap();
    let mut spec = FuncCallSpecs::new(call, Address::new_invalid());
    spec.proto_mut().set_internal(model, factory.get_type_void().unwrap());
    spec.get_active_input().register_trial(&Address::new(register.clone(), 0x30), 4);
    spec.get_active_input().register_trial(&Address::new(register, 0x10), 4);
    fd.push_call_specs(spec);
    (call, argument, output)
}

#[test]
fn typed_callind_commits_real_operands_and_preserves_shared_signature() {
    let (mut fd, code, model) = typed_call_fixture();
    let (call, argument, output) = add_typed_indirect_call(&mut fd, &code, model, 0x1010);
    let shared = code.get_code_prototype().unwrap().clone();
    ActionDeindirect::boxed("g").apply(&mut fd, &mut ActionContext::new());
    assert!(!fd.has_restart_pending());
    let op = fd.obank().get(call).unwrap();
    assert_eq!(op.code(), OpCode::CPUI_CALLIND);
    assert_eq!(op.num_input(), 2);
    assert_eq!(op.get_in(1), Some(argument));
    assert_eq!(op.get_out(), Some(output));
    let output_type = fd.get_call_specs(0).proto().get_output().get_type().unwrap();
    assert_eq!(output_type.get_metatype(), type_metatype::TYPE_INT);
    assert_eq!(output_type.get_size(), 4);
    assert!(fd.get_call_specs(0).proto().is_input_locked());
    let site = fd.obank().get(call).unwrap().get_addr();
    let stored = fd.get_override().find_proto_override(site).unwrap()
        .prototype().expect("recovered declaration persists through analysis restart");
    assert!(stored.is_override());
    assert_eq!(stored.num_params(), 1);
    assert_eq!(stored.get_param(0).unwrap().get_name(), "argument");
    assert_eq!(stored.get_param(0).unwrap().get_address().get_offset(), 0x10);
    assert_eq!(stored.get_output().get_address().get_offset(), 0x20);
    assert!(!shared.is_override());
    assert_eq!(shared.num_params(), 1);
    assert_eq!(shared.get_param(0).unwrap().get_name(), "argument");
    assert_eq!(shared.get_param(0).unwrap().get_address().get_offset(), 0x10);
    assert_eq!(shared.get_output().get_address().get_offset(), 0x20);
}

#[test]
fn typed_callind_preserves_unlocked_site_pin_while_restricting_other_site() {
    use crate::fspec::{parameter_pieces_flags, ParameterPieces};
    let (mut fd, code, model) = typed_call_fixture();
    let (first, _, _) = add_typed_indirect_call(&mut fd, &code, model.clone(), 0x1010);
    let (second, argument, _) = add_typed_indirect_call(&mut fd, &code, model.clone(), 0x1020);
    let register = fd.get_arch().manage().get_space_by_name("register").unwrap().clone();
    let factory = fd.get_arch().types_rc().unwrap();
    let manager = fd.get_arch().manage.clone();
    let custom = factory.get_base(2, type_metatype::TYPE_UINT).unwrap();
    let pinned_storage = ParameterPieces {
        addr: Address::new(register, 0x30), type_: Some(custom.clone()),
        flags: parameter_pieces_flags::NAMELOCK | parameter_pieces_flags::CUSTOM_STORAGE,
    };
    let proto = fd.get_call_specs_mut(0).proto_mut();
    // Host-declared storage enters through pieces, not a private flag setter.
    proto.set_pieces(&PrototypePieces {
        outtype: Some(factory.get_type_void().unwrap()),
        intypes: vec![custom],
        innames: vec!["pinned_name".to_owned()],
        input_storage: vec![(0, pinned_storage.clone())],
        first_var_arg_slot: -1,
        ..Default::default()
    }, Some(model), factory.as_ref(), manager.as_ref()).unwrap();
    // Keep the site pin authoritative even without the input type lock that
    // set_pieces normally installs; retain the original name-only lock.
    proto.set_input_lock(false);
    proto.set_output_lock(false);
    proto.set_model_lock(false);
    proto.set_param(0, "pinned_name", &pinned_storage);
    proto.set_override(true);
    assert!(proto.has_custom_storage());
    assert!(!proto.is_input_locked());
    ActionDeindirect::boxed("g").apply(&mut fd, &mut ActionContext::new());
    assert_eq!(fd.obank().get(first).unwrap().num_input(), 3);
    let pinned = fd.get_call_specs(0).proto();
    assert!(pinned.has_custom_storage());
    assert!(!pinned.is_input_locked());
    assert_eq!(pinned.get_param(0).unwrap().get_name(), "pinned_name");
    assert_eq!(pinned.get_param(0).unwrap().get_address().get_offset(), 0x30);
    assert_eq!(pinned.get_param(0).unwrap().get_type().unwrap().get_size(), 2);
    assert_eq!(pinned.get_param(0).unwrap().get_type().unwrap().get_metatype(), type_metatype::TYPE_UINT);
    assert_eq!(fd.obank().get(second).unwrap().num_input(), 2);
    assert_eq!(fd.obank().get(second).unwrap().get_in(1), Some(argument));
}

#[test]
fn typed_callind_failed_late_restriction_persists_only_in_same_analysis() {
    let (mut fd, code, model) = typed_call_fixture();
    let (call, _, _) = add_typed_indirect_call(&mut fd, &code, model, 0x1010);
    fd.get_call_specs_mut(0).get_active_input().clear();
    let site = fd.obank().get(call).unwrap().get_addr().clone();
    ActionDeindirect::boxed("g").apply(&mut fd, &mut ActionContext::new());
    assert!(fd.has_restart_pending());
    assert_eq!(fd.obank().get(call).unwrap().num_input(), 3);
    let stored = fd.get_override().find_proto_override(&site).unwrap()
        .prototype().expect("late restriction stores a recovered full prototype");
    assert_eq!(stored.num_params(), 1);
    assert_eq!(stored.get_param(0).unwrap().get_address().get_offset(), 0x10);
    assert_eq!(stored.get_output().get_address().get_offset(), 0x20);
    fd.clear();
    let retained = fd.get_override().find_proto_override(&site).unwrap()
        .prototype().expect("recovered prototype survives analysis clear");
    assert!(retained.is_override());
    assert_eq!(retained.num_params(), 1);
    assert_eq!(retained.get_param(0).unwrap().get_address().get_offset(), 0x10);
    assert_eq!(retained.get_output().get_address().get_offset(), 0x20);
    let fresh = Funcdata::new("fresh", "fresh", fd.get_arch().clone(), fd.get_address().clone(), 0x10000000, 0x40).unwrap();
    assert!(fresh.get_override().find_proto_override(&site).is_none());
}

#[test]
fn generic_code_pointer_does_not_invent_a_callable_declaration() {
    let (mut fd, _, model) = typed_call_fixture();
    let generic_code = fd.get_arch().types().unwrap().get_type_code().unwrap();
    let (call, _, output) = add_typed_indirect_call(&mut fd, &generic_code, model, 0x1010);
    ActionDeindirect::boxed("g").apply(&mut fd, &mut ActionContext::new());
    assert!(!fd.has_restart_pending());
    assert!(!fd.get_call_specs(0).proto().is_override());
    assert_eq!(fd.obank().get(call).unwrap().num_input(), 3);
    assert_eq!(fd.obank().get(call).unwrap().get_out(), Some(output));
}

#[test]
fn late_external_deindirection_preserves_resolved_function_authority() {
    use kuna_base::address::RangeList;
    use kuna_base::partmap::PartMap;
    use crate::context::{GlobalEntry, GlobalQuery};
    use crate::varnode::varnode_flags;
    for callable_data in [false, true] {
        let (mut fd, code, model) = typed_call_fixture_with_globals(|arch, code| {
            let factory = arch.types_rc().unwrap();
            let loader_code = if callable_data {
                factory.get_type_code_proto(&PrototypePieces {
                    outtype: Some(factory.get_base(4, type_metatype::TYPE_INT).unwrap()),
                    first_var_arg_slot: -1, ..Default::default()
                }).unwrap()
            } else { code.clone() };
            let data_type = if callable_data {
                factory.get_type_pointer(8, code.clone(), 1).unwrap()
            } else { factory.get_base(8, type_metatype::TYPE_INT).unwrap() };
            let entry = |name: &str, ty, is_function| GlobalEntry {
                space_index: arch.manage().get_space_by_name("ram").unwrap().get_index(),
                first: 0x3000, last: 0x3007, size: 8, all_flags: 0, addrtied: true,
                uselimit: RangeList::new(), symbol_name: name.to_owned(), symbol_offset: 0,
                symbol_type: Some(ty), scope_path: Vec::new(), is_function,
                func_inject_id: -1, func_no_return: false, symbol_id: 0,
            };
            arch.global_query = Some(Rc::new(GlobalQuery::new(
                vec![entry("import_name", loader_code, true), entry("slot", data_type, false)],
                RangeList::new(), PartMap::new(0),
            )));
        });
        let (call, _, _) = add_typed_indirect_call(&mut fd, &code, model, 0x1010);
        if !callable_data {
            fd.op_remove_input(call, 2);
            fd.op_remove_input(call, 1);
            fd.get_call_specs_mut(0).get_active_input().clear();
        }
        let slot = Address::new(ram_space(&fd), 0x3000);
        let target_type = if callable_data {
            fd.get_arch().types().unwrap().get_type_pointer(8, code.clone(), 1).unwrap()
        } else { fd.get_arch().types().unwrap().get_base(8, type_metatype::TYPE_INT).unwrap() };
        let target = fd.new_varnode(8, &slot, Some(target_type));
        fd.vbank_mut().get_mut(target).unwrap().set_flags_pub(varnode_flags::persist | varnode_flags::externref);
        fd.op_set_input(call, target, 0).unwrap();
        ActionDeindirect::boxed("g").apply(&mut fd, &mut ActionContext::new());
        assert_eq!(fd.get_call_specs(0).get_name(), "import_name");
        assert_eq!(fd.get_call_specs(0).get_entry_address(), &slot);
        assert_eq!(fd.obank().get(call).unwrap().code(), OpCode::CPUI_CALL);
        let site = fd.obank().get(call).unwrap().get_addr();
        assert_eq!(fd.get_override().find_indirect_override(site), Some(&slot));
        let (_, entry, direct) = fd.get_arch().query_function(&slot).unwrap();
        assert_eq!(entry, slot);
        assert_eq!(direct.num_params(), if callable_data { 0 } else { 1 });
        if !fd.has_restart_pending() {
            assert_eq!(fd.get_call_specs(0).proto().num_params(), direct.num_params());
        }
    }
}

// -----------------------------------------------------------------------------
// 1. Identity (name / group / flags)
// -----------------------------------------------------------------------------

/// Every render-group leaf carries the exact C++ `name()` string and group.
#[test]
fn names_and_groups_match_cpp() {
    let cases: Vec<(Box<dyn Action>, &str)> = vec![
        (ActionLaneDivide::boxed("g0"), "lanedivide"),
        (ActionSegmentize::boxed("g0"), "segmentize"),
        (ActionForceGoto::boxed("g0"), "forcegoto"),
        (ActionMultiCse::boxed("g0"), "multicse"),
        (ActionShadowVar::boxed("g0"), "shadowvar"),
        (ActionConstantPtr::boxed("g0"), "constantptr"),
        (ActionDeindirect::boxed("g0"), "deindirect"),
        (ActionLikelyTrash::boxed("g0"), "likelytrash"),
        (ActionRestructureVarnode::boxed("g0"), "restructure_varnode"),
        (ActionMappedLocalSync::boxed("g0"), "mapped_local_sync"),
        (ActionMapGlobals::boxed("g0"), "mapglobals"),
        (ActionDeadCode::boxed("g0"), "deadcode"),
        (ActionConditionalConst::boxed("g0"), "condconst"),
        (ActionSwitchNorm::boxed("g0"), "switchnorm"),
        (ActionUnjustifiedParams::boxed("g0"), "unjustparams"),
        (ActionDynamicMapping::boxed("g0"), "dynamicmapping"),
        (ActionDynamicSymbols::boxed("g0"), "dynamicsymbols"),
        (ActionInternalStorage::boxed("g0"), "internalstorage"),
        (ActionInferTypes::boxed("g0"), "infertypes"),
    ];
    for (act, expect) in &cases {
        assert_eq!(act.get_name(), *expect, "name mismatch");
        assert_eq!(act.get_group(), "g0", "group must be the ctor's `g`");
    }
    // Parameterized constructors keep the same name/group.
    let sp = ActionStackPtrFlow::boxed("g0", None);
    assert_eq!(sp.get_name(), "stackptrflow");
    assert_eq!(sp.get_group(), "g0");
    let dw = ActionDirectWrite::boxed("g0", true);
    assert_eq!(dw.get_name(), "directwrite");
    assert_eq!(dw.get_group(), "g0");
}

/// Flags match the C++ constructors: `rule_onceperfunc` for the once-per-function
/// actions, `0` for the repeatable ones.
#[test]
fn flags_match_cpp_constructors() {
    // rule_onceperfunc in the C++ ctor.
    for a in [
        ActionLaneDivide::boxed("g"),
        ActionMapGlobals::boxed("g"),
        ActionDynamicSymbols::boxed("g"),
        ActionInternalStorage::boxed("g"),
    ] {
        assert_eq!(
            a.base().flags,
            ruleflags::rule_onceperfunc,
            "{} must be rule_onceperfunc",
            a.get_name()
        );
    }
    // flags == 0 in the C++ ctor.
    for a in [
        ActionStackPtrFlow::boxed("g", None),
        ActionSegmentize::boxed("g"),
        ActionForceGoto::boxed("g"),
        ActionMultiCse::boxed("g"),
        ActionShadowVar::boxed("g"),
        ActionConstantPtr::boxed("g"),
        ActionDeindirect::boxed("g"),
        ActionDirectWrite::boxed("g", false),
        ActionLikelyTrash::boxed("g"),
        ActionRestructureVarnode::boxed("g"),
        ActionMappedLocalSync::boxed("g"),
        ActionDeadCode::boxed("g"),
        ActionConditionalConst::boxed("g"),
        ActionSwitchNorm::boxed("g"),
        ActionUnjustifiedParams::boxed("g"),
        ActionDynamicMapping::boxed("g"),
        ActionInferTypes::boxed("g"),
    ] {
        assert_eq!(a.base().flags, 0, "{} must have flags 0", a.get_name());
    }
}

/// `render_actions` enumerates the full set (21 classes) with the passed group.
#[test]
fn render_actions_enumerates_full_set() {
    let acts = render_actions("merge");
    assert_eq!(acts.len(), 21, "21 live render-group actions");
    for a in &acts {
        assert_eq!(a.get_group(), "merge");
    }
    // Names are exactly the C++ set (order matches the module table).
    let names: Vec<&str> = acts.iter().map(|a| a.get_name()).collect();
    assert_eq!(
        names,
        vec![
            "stackptrflow",
            "lanedivide",
            "segmentize",
            "forcegoto",
            "multicse",
            "shadowvar",
            "constantptr",
            "deindirect",
            "directwrite",
            "likelytrash",
            "restructure_varnode",
            "mapped_local_sync",
            "mapglobals",
            "deadcode",
            "condconst",
            "switchnorm",
            "unjustparams",
            "dynamicmapping",
            "dynamicsymbols",
            "internalstorage",
            "infertypes",
        ]
    );
}

// -----------------------------------------------------------------------------
// 2. clone_filtered (C++ clone(grouplist) group filter)
// -----------------------------------------------------------------------------

/// `clone_filtered` mirrors the C++ `clone(grouplist)` filter: present iff the
/// grouplist contains the action's group, else dropped.
#[test]
fn clone_filtered_obeys_grouplist() {
    let act = ActionDeadCode::boxed("deadcode");
    let yes = ActionGroupList::from_names(["deadcode", "analysis"]);
    let cl = act.clone_filtered(&yes).expect("present when grouplist contains group");
    assert_eq!(cl.get_name(), "deadcode");
    assert_eq!(cl.get_group(), "deadcode");
    let no = ActionGroupList::from_names(["merge"]);
    assert!(act.clone_filtered(&no).is_none(), "dropped when group absent");
}

/// The parameterized actions pass their configuration through `clone_filtered`
/// (C++ `clone` re-passes `stackspace` / `propagateIndirect`), and reset the
/// per-function `analysis_finished` latch to its fresh-function value.
#[test]
fn clone_filtered_preserves_parameterization() {
    let fd = build_fd();
    let ram = ram_space(&fd);
    let sp = ActionStackPtrFlow {
        base: ActionBase::new(0, "stackptrflow", "g"),
        stackspace: Some(Rc::clone(&ram)),
        analysis_finished: true, // already finished on the source
    };
    let list = ActionGroupList::from_names(["g"]);
    let cl = sp.clone_filtered(&list).expect("present");
    assert_eq!(cl.get_name(), "stackptrflow");
    // (the clone re-derives a fresh action; analysis_finished starts unset)

    // ActionDirectWrite carries propagateIndirect verbatim.
    let dw = ActionDirectWrite::boxed("g", false);
    let cl = dw.clone_filtered(&list).expect("present");
    assert_eq!(cl.get_name(), "directwrite");
}

// -----------------------------------------------------------------------------
// 3. Stateful behavior on owned fields
// -----------------------------------------------------------------------------

/// `ActionStackPtrFlow::reset` clears `analysis_finished`; with no stack space
/// `apply` immediately latches finished and returns 0 (the C++ "No stack" path).
#[test]
fn stackptrflow_no_stack_latches_finished() {
    let mut fd = build_fd();
    let mut ctx = ActionContext::new();
    let mut sp = ActionStackPtrFlow {
        base: ActionBase::new(0, "stackptrflow", "g"),
        stackspace: None,
        analysis_finished: false,
    };
    // No stack space => analysis_finished set, no change.
    assert_eq!(sp.apply(&mut fd, &mut ctx), 0);
    assert!(sp.analysis_finished, "no-stack path latches finished");
    assert_eq!(sp.base().count, 0);
    // Already-finished short-circuit.
    assert_eq!(sp.apply(&mut fd, &mut ctx), 0);
    // reset() clears the latch for a new function.
    sp.reset(&mut fd);
    assert!(!sp.analysis_finished, "reset clears analysis_finished");
}

/// `ActionStackPtrFlow` with a (here, spacebase-less) stack space runs the
/// realized body: `check_clog` finds no clog (the space has no base register, so
/// `getSpacebase` fails and the clog scan is empty) -> `numchange == 0` -> the
/// C++ `analyzeExtraPop` branch runs and latches `analysis_finished`.  No change
/// is applied (no spacebase refs to solve), so `count` stays 0.
#[test]
fn stackptrflow_with_stack_runs_and_latches() {
    let mut fd = build_fd();
    let ram = ram_space(&fd);
    let mut ctx = ActionContext::new();
    let mut sp = ActionStackPtrFlow {
        base: ActionBase::new(0, "stackptrflow", "g"),
        stackspace: Some(ram),
        analysis_finished: false,
    };
    assert_eq!(sp.apply(&mut fd, &mut ctx), 0);
    assert!(
        sp.analysis_finished,
        "no clog -> analyzeExtraPop runs and latches analysis_finished (C++ coreaction.cc:507)"
    );
    assert_eq!(sp.base().count, 0);
}

/// The `reset` overrides zero the per-function counters
/// (`localcount`/`numpass`).
#[test]
fn reset_zeroes_per_function_counters() {
    let mut fd = build_fd();

    let mut seg = ActionSegmentize { base: ActionBase::new(0, "segmentize", "g"), localcount: 5 };
    seg.reset(&mut fd);
    assert_eq!(seg.localcount, 0);

    let mut cp = ActionConstantPtr { base: ActionBase::new(0, "constantptr", "g"), localcount: 3 };
    cp.reset(&mut fd);
    assert_eq!(cp.localcount, 0);

    let mut rv = ActionRestructureVarnode {
        base: ActionBase::new(0, "restructure_varnode", "g"),
        numpass: 7,
    };
    rv.reset(&mut fd);
    assert_eq!(rv.numpass, 0);

    let mut it = ActionInferTypes { base: ActionBase::new(0, "infertypes", "g"), localcount: 6 };
    it.reset(&mut fd);
    assert_eq!(it.localcount, 0);
}

/// `ActionDirectWrite` stores the `propagateIndirect` config from the ctor.
#[test]
fn directwrite_stores_propagate_indirect() {
    let yes = ActionDirectWrite {
        base: ActionBase::new(0, "directwrite", "g"),
        propagate_indirect: true,
    };
    assert!(yes.propagate_indirect);
    let no = ActionDirectWrite {
        base: ActionBase::new(0, "directwrite", "g"),
        propagate_indirect: false,
    };
    assert!(!no.propagate_indirect);
}

// -----------------------------------------------------------------------------
// 4. Seam contract — every seamed apply reports no change
// -----------------------------------------------------------------------------

/// Every action's `apply` returns `0` and leaves `count == 0` on a fresh
/// `Funcdata` (the unrealized-body contract; the realized state-gating in the
/// stateful actions does not, on its own, report a data-flow change).
#[test]
fn all_applies_report_no_change_on_empty_fd() {
    let mut fd = build_fd();
    let mut ctx = ActionContext::new();
    for mut a in render_actions("g") {
        let r = a.apply(&mut fd, &mut ctx);
        assert_eq!(r, 0, "{} apply must return 0", a.get_name());
        assert_eq!(a.base().count, 0, "{} apply must report no change", a.get_name());
    }
}
