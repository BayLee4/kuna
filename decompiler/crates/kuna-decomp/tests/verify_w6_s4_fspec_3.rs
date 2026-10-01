//! Adversarial verification tests for item `w6-s4-fspec-3`
//! (`FuncCallSpecs` + the `FspecSpace` print/encode arms:
//! `decompiler/cpp/fspec.cc` 4854-5982 and `fspec.hh:1645-1742`).
//!
//! Written by the INDEPENDENT verifier.  These target the spots the hunt list
//! flagged as most fragile for the *ported* (non-seamed) surface of this item:
//!
//!   - **Width / signedness / monotone** in `setInputBytesConsumed`
//!     (`fspec.cc:5894`): the `while (inputConsume.size() <= slot)` grow loop
//!     (size_t vs int4) and the smallest-wins rule with the `0` sentinel
//!     (`oldVal == 0 || val < oldVal`) — including the *equal* and *larger*
//!     cases that must NOT change, and the out-of-range read returning 0.
//!   - **Off-by-one / index-math** in `ParamActive::getTrialForInputVarnode`
//!     (`fspec.hh:1749`): the `slot < stackplaceholder ? 1 : 2` boundary —
//!     specifically the `slot == stackplaceholder` case (subtract 2, NOT 1).
//!   - **Wrapping** in `resolveSpacebaseRelative` (`fspec.cc:4904-4905`): the
//!     `stackoffset -= addr.getOffset(); stackoffset = wrapOffset(stackoffset)`
//!     underflow on a `uintb` for a locked stack parameter — C++ wraps; the
//!     port uses `wsub` + `wrap_offset`.
//!   - **Address arithmetic / reuse-slot encoding** in
//!     `transferLockedInputParam` + `transferLockedInput` (`fspec.cc:5043`,
//!     `:5105`): the `startaddr + (sz-1)` / trial-end overlap test and the
//!     `reuse > 0 => op->getIn(reuse)` reuse path, driven through
//!     `lateRestriction` with an input-locked register-only prototype.

use std::rc::Rc;

use kuna_base::address::Address;
use kuna_base::error::KunaResult;
use kuna_base::space::{spacetype, AddrSpace, AddrSpaceManager};
use kuna_base::types::int4;

use kuna_decomp::dtype::{type_metatype, TypeFactory};
use kuna_decomp::fspec::{
    FuncCallSpecs, FuncProto, ParameterPieces, ProtoModel, OFFSET_UNKNOWN,
};
use kuna_decomp::funcdata::Funcdata;
use kuna_decomp::op::pcodeop_flags;
use kuna_decomp::context::{ArchContext, OpId, TypeOp, VarnodeId};
use kuna_decomp::varnode::DefOpInfo;
use kuna_num::opcodes::OpCode;

// --- shared builders (mirror the in-crate `fcs_*` harness) ------------------

fn fcs_manager() -> AddrSpaceManager {
    use kuna_base::space::{ConstantSpace, UniqueSpace};
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
        kuna_base::space::addrspace_flags::hasphysical,
        1,
        1,
    )))
    .unwrap();
    // A spacebase (stack) space at index 3.
    m.insert_space(Rc::new(AddrSpace::new(
        spacetype::IPTR_SPACEBASE,
        "stack",
        false,
        8,
        1,
        3,
        0,
        1,
        1,
    )))
    .unwrap();
    // A processor "register" space at index 4 for register-storage params.
    m.insert_space(Rc::new(AddrSpace::new(
        spacetype::IPTR_PROCESSOR,
        "register",
        false,
        4,
        1,
        4,
        0,
        0,
        0,
    )))
    .unwrap();
    m.set_default_code_space(2).unwrap();
    m
}

fn fcs_fd() -> Funcdata {
    let glb = Rc::new(ArchContext::new(fcs_manager()));
    let ram = Rc::clone(glb.manage().get_space_by_name("ram").unwrap());
    let entry = Address::new(ram, 0x1000);
    Funcdata::new("caller", "caller", glb, entry, 0x10000000, 0x40).unwrap()
}

fn fcs_ram(fd: &Funcdata) -> Rc<AddrSpace> {
    Rc::clone(fd.get_arch().manage().get_space_by_name("ram").unwrap())
}
fn fcs_stack(fd: &Funcdata) -> Rc<AddrSpace> {
    Rc::clone(fd.get_arch().manage().get_space_by_name("stack").unwrap())
}
fn fcs_reg(fd: &Funcdata) -> Rc<AddrSpace> {
    Rc::clone(fd.get_arch().manage().get_space_by_name("register").unwrap())
}

fn fcs_new_op(fd: &mut Funcdata, inputs: int4, off: u64, opc: OpCode) -> OpId {
    let ram = fcs_ram(fd);
    let op = fd.new_op(inputs, Address::new(ram, off));
    let flags = if opc == OpCode::CPUI_CALL || opc == OpCode::CPUI_CALLIND {
        pcodeop_flags::call
    } else {
        0
    };
    fd.obank_mut().change_opcode(op, TypeOp::new(opc, flags, format!("{opc:?}")));
    op
}

/// A varnode in `space` at `off`/`size` defined by `op` (sets `written`).
fn fcs_out(fd: &mut Funcdata, op: OpId, space: Rc<AddrSpace>, off: u64, size: int4) -> VarnodeId {
    let seq = fd.obank().get(op).unwrap().get_seq_num().clone();
    let def = DefOpInfo { id: op, seqnum: seq };
    let dtype = fd.get_arch().types().unwrap().get_base(size, type_metatype::TYPE_UNKNOWN).unwrap();
    let vn = {
        let mut noop = |_b: &mut kuna_decomp::varnode::VarnodeBank,
                        _o: VarnodeId,
                        _n: VarnodeId|
         -> KunaResult<()> { panic!("collision") };
        fd.vbank_mut()
            .create_def(
                size,
                Address::new(space, off),
                dtype,
                def,
                &mut noop,
            )
            .unwrap()
    };
    fd.obank_mut().get_mut(op).unwrap().set_output(Some(vn));
    vn
}

fn addr(spc: &Rc<AddrSpace>, off: u64) -> Address {
    Address::new(Rc::clone(spc), off)
}

fn std_model(mgr: &AddrSpaceManager) -> ProtoModel {
    let mut model = ProtoModel::new(mgr);
    model.build_param_list("standard").unwrap();
    model
}

fn fcs_with_std_model(fd: &Funcdata, call: OpId) -> FuncCallSpecs {
    let mut fc = FuncCallSpecs::new(call, Address::default());
    let voidt = fd.get_arch().types().unwrap().get_type_void().unwrap();
    let mut fp = FuncProto::new();
    fp.set_internal(Rc::new(std_model(fd.get_arch().manage())), voidt);
    fc.proto_mut().copy(&fp);
    fc
}

// ---------------------------------------------------------------------------
// F-A: setInputBytesConsumed monotone + sentinel-zero + out-of-range read
//   C++ fspec.cc:5877-5905.  `getInputBytesConsumed`: slot>=size -> 0.
//   `setInputBytesConsumed`: grow with 0, then change iff `oldVal==0 || val<oldVal`.
// ---------------------------------------------------------------------------

#[test]
fn fspec3_input_bytes_consumed_sentinel_and_monotone() {
    let mut fd = fcs_fd();
    let call = fcs_new_op(&mut fd, 1, 0x1010, OpCode::CPUI_CALLIND);
    let mut fc = fcs_with_std_model(&fd, call);

    // Empty vector: any read is the 0 default (slot >= size()).
    assert_eq!(fc.get_input_bytes_consumed(0), 0);
    assert_eq!(fc.get_input_bytes_consumed(7), 0);

    // First set at slot 3 grows the vector [0,0,0,?]; the stored slot is
    // changed off its 0 sentinel (oldVal == 0) => returns true.
    assert!(fc.set_input_bytes_consumed(3, 5));
    assert_eq!(fc.get_input_bytes_consumed(3), 5);
    // Slots 0..3 were grown to the 0 sentinel and read back as 0.
    assert_eq!(fc.get_input_bytes_consumed(0), 0);
    assert_eq!(fc.get_input_bytes_consumed(2), 0);

    // A LARGER value does NOT replace 5 (only smaller wins) => false, unchanged.
    assert!(!fc.set_input_bytes_consumed(3, 9));
    assert_eq!(fc.get_input_bytes_consumed(3), 5);

    // An EQUAL value does NOT replace (not strictly smaller) => false, unchanged.
    assert!(!fc.set_input_bytes_consumed(3, 5));
    assert_eq!(fc.get_input_bytes_consumed(3), 5);

    // A SMALLER value replaces => true.
    assert!(fc.set_input_bytes_consumed(3, 2));
    assert_eq!(fc.get_input_bytes_consumed(3), 2);

    // A slot whose stored value is the 0 sentinel: even val==0 keeps it 0 and,
    // since oldVal==0, the branch is taken and returns true (C++:
    // `oldVal == 0 || val < oldVal` short-circuits on oldVal==0).
    assert!(fc.set_input_bytes_consumed(1, 0));
    assert_eq!(fc.get_input_bytes_consumed(1), 0);

    // Out-of-range read past the grown vector is still the 0 default.
    assert_eq!(fc.get_input_bytes_consumed(100), 0);
}

// ---------------------------------------------------------------------------
// F-B: getTrialForInputVarnode placeholder boundary.
//   C++ fspec.hh:1752: slot -= ((sp<0)||(slot<sp)) ? 1 : 2;
//   The `slot == stackplaceholder` case takes the `else 2` branch — a classic
//   off-by-one trap.
// ---------------------------------------------------------------------------

#[test]
fn fspec3_trial_for_input_varnode_placeholder_equal_boundary() {
    let mut fd = fcs_fd();
    let call = fcs_new_op(&mut fd, 1, 0x1010, OpCode::CPUI_CALLIND);
    let mut fc = fcs_with_std_model(&fd, call);
    let stk = fcs_stack(&fd);

    // `ParamActive::slotbase` starts at 1 (C++ ctor), so four registrations get
    // slots 1,2,3,4 and vector indices 0,1,2,3 at offsets 0x0/0x8/0x10/0x18.
    let pa = fc.get_active_input();
    pa.register_trial(&addr(&stk, 0x0), 8); // slot 1, idx 0
    pa.register_trial(&addr(&stk, 0x8), 8); // slot 2, idx 1
    pa.register_trial(&addr(&stk, 0x10), 8); // slot 3, idx 2
    pa.register_trial(&addr(&stk, 0x18), 8); // slot 4, idx 3

    // No placeholder yet (stackplaceholder == -1): subtract 1 everywhere.
    assert_eq!(pa.get_trial_for_input_varnode(1).get_address().get_offset(), 0x0);
    assert_eq!(pa.get_trial_for_input_varnode(4).get_address().get_offset(), 0x18);

    // Establish the placeholder at slotbase (now 5 after four registrations).
    pa.set_placeholder_slot(); // stackplaceholder = 5
    // slot < placeholder(5): subtract 1.
    assert_eq!(pa.get_trial_for_input_varnode(3).get_address().get_offset(), 0x10); // idx 2
    assert_eq!(pa.get_trial_for_input_varnode(4).get_address().get_offset(), 0x18); // idx 3
    // slot == placeholder(5): the BOUNDARY — must take `else 2`, NOT `1`.
    //   5 - 2 = idx 3 (0x18).  A buggy `<=` (`slot <= sp ? 1 : 2`) would take
    //   `-1` here and read idx 4 (out of bounds / wrong), so the `<` boundary is
    //   load-bearing.  With the correct `<`, slot 5 == slot 4's value (0x18).
    assert_eq!(pa.get_trial_for_input_varnode(5).get_address().get_offset(), 0x18); // idx 3
}

// ---------------------------------------------------------------------------
// F-C: resolveSpacebaseRelative input-locked wrap underflow.
//   C++ fspec.cc:4904-4905: stackoffset -= addr.getOffset(); wrapOffset(...).
//   With refvn offset 0 and a locked stack param at offset 0x20, the subtract
//   underflows uintb and wraps (C++ silent wrap; port uses wsub + wrap_offset).
// ---------------------------------------------------------------------------

#[test]
fn fspec3_resolve_spacebase_relative_locked_wrap_underflow() {
    let mut fd = fcs_fd();
    let tf = fd.get_arch().types_rc().unwrap();
    let stk = fcs_stack(&fd);

    // CALLIND with 2 inputs: target (slot 0) + placeholder (slot 1).
    let call = fcs_new_op(&mut fd, 2, 0x1010, OpCode::CPUI_CALLIND);
    let ram = fcs_ram(&fd);
    let target = {
        let c = Rc::clone(fd.get_arch().manage().get_space(0).unwrap());
        fd.vbank_mut().create(
            8,
            Address::new(c, 0x2000),
            tf.get_base(8, type_metatype::TYPE_UNKNOWN).unwrap(),
        )
    };
    let _ = &ram;
    fd.op_set_input(call, target, 0).unwrap();

    // LOAD producing the placeholder; its input 0 (refvn) is a stack varnode
    // at offset 0 (so stackoffset is read as 0 before the subtract).
    let load = fcs_new_op(&mut fd, 1, 0x1008, OpCode::CPUI_LOAD);
    let refvn = fd.vbank_mut().create(
        8,
        Address::new(Rc::clone(&stk), 0x0),
        tf.get_base(8, type_metatype::TYPE_UNKNOWN).unwrap(),
    );
    fd.op_set_input(load, refvn, 0).unwrap();
    let uniq = Rc::clone(fd.get_arch().manage().get_space(1).unwrap());
    let phvn = fcs_out(&mut fd, load, uniq, 0x0, 8);
    fd.vbank_mut().get_mut(phvn).unwrap().set_spacebase_placeholder();
    fd.op_set_input(call, phvn, 1).unwrap();

    // fc: standard model, then a LOCKED input prototype with one stack param at
    // offset 0x20.  stack_placeholder_slot stays -1, so the abort short-circuit
    // is skipped and the input-locked branch runs.
    let mut fc = fcs_with_std_model(&fd, call);
    let stack_param_off: u64 = 0x20;
    let pieces = ParameterPieces {
        addr: Address::new(Rc::clone(&stk), stack_param_off),
        type_: Some(tf.get_base(8, type_metatype::TYPE_INT).unwrap()),
        flags: kuna_decomp::fspec::parameter_pieces_flags::TYPELOCK,
    };
    fc.proto_mut().set_param(0, "p0", &pieces);
    fc.proto_mut().set_input_lock(true);
    assert!(fc.proto().is_input_locked());

    // getSlot(phvn) finds phvn at slot 1; slot = 1 - 1 = 0 -> getParam(0) (the
    // stack param).  spacebase matches, so the wrap branch runs:
    //   stackoffset(0) - 0x20  ==  2^64 - 0x20  (wrapped), then wrapOffset.
    let r = fc.resolve_spacebase_relative(&mut fd, phvn);
    assert!(r.is_ok(), "input-locked stack param should resolve, got {r:?}");
    let expected = 0u64.wrapping_sub(stack_param_off); // wrap_offset on a 8-byte space is identity
    assert_eq!(
        fc.get_spacebase_offset(),
        expected,
        "stackoffset must wrap (uintb), not panic / saturate"
    );
    assert_ne!(fc.get_spacebase_offset(), OFFSET_UNKNOWN);
}

// ---------------------------------------------------------------------------
// F-D: compatible locked register input commits without copying or restarting.
// ---------------------------------------------------------------------------

#[test]
fn fspec3_force_set_locked_register_reuses_committed_operand() {
    let mut fd = fcs_fd();
    let tf = fd.get_arch().types_rc().unwrap();
    let reg = fcs_reg(&fd);

    // CALL with 2 inputs: dest (slot 0) + one register operand (slot 1).
    let call = fcs_new_op(&mut fd, 2, 0x1010, OpCode::CPUI_CALL);
    let dest = {
        let c = Rc::clone(fd.get_arch().manage().get_space(0).unwrap());
        fd.vbank_mut().create(
            8,
            Address::new(c, 0x2000),
            tf.get_base(8, type_metatype::TYPE_UNKNOWN).unwrap(),
        )
    };
    fd.op_set_input(call, dest, 0).unwrap();
    let regvn = fd.vbank_mut().create(
        4,
        Address::new(Rc::clone(&reg), 0x0),
        tf.get_base(4, type_metatype::TYPE_UNKNOWN).unwrap(),
    );
    fd.op_set_input(call, regvn, 1).unwrap();

    // Share ONE model so isCompatible(restricted) is true.
    let model = Rc::new(std_model(fd.get_arch().manage()));

    // fc: has the shared model (hasModel() true), one register trial at the
    // param address whose slot is 1 (the live CALL input).
    let mut fc = FuncCallSpecs::new(call, Address::default());
    let voidt = tf.get_type_void().unwrap();
    fc.proto_mut().set_internal(Rc::clone(&model), voidt.clone());
    {
        let pa = fc.get_active_input();
        pa.register_trial(&addr(&reg, 0x0), 4); // slotbase 0
        pa.get_trial(0); // ensure it exists
        pa.get_trial_mut(0).set_slot(1); // point at CALL input slot 1
    }

    // restricted: same model, input-locked, one register param matching the
    // trial address/size exactly.
    let mut restricted = FuncProto::new();
    restricted.set_internal(Rc::clone(&model), voidt.clone());
    let pieces = ParameterPieces {
        addr: Address::new(Rc::clone(&reg), 0x0),
        type_: Some(tf.get_base(4, type_metatype::TYPE_INT).unwrap()),
        flags: kuna_decomp::fspec::parameter_pieces_flags::TYPELOCK,
    };
    restricted.set_param(0, "a", &pieces);
    restricted.set_input_lock(true);
    assert!(restricted.is_input_locked());

    let mut log = kuna_decomp::kuna_restartlog::RestartLog::new();
    fc.force_set(&mut fd, &restricted, &mut log).unwrap();
    assert!(!fd.has_restart_pending());
    assert_eq!(fd.obank().get(call).unwrap().get_in(0), Some(dest));
    assert_eq!(fd.obank().get(call).unwrap().get_in(1), Some(regvn));
    assert!(fc.proto().is_input_locked());
    let site = fd.obank().get(call).unwrap().get_addr();
    let pinned = fd.get_override().find_proto_override(site).unwrap();
    assert_eq!(pinned.get_param(0).unwrap().get_address(), addr(&reg, 0));
    assert_eq!(pinned.get_param(0).unwrap().get_size(), 4);
}

#[test]
fn physical_carriers_preserve_independent_storage_until_authoritative_edit() {
    use kuna_decomp::fspec::parameter_pieces_flags as pf;
    let fd = fcs_fd();
    let tf = fd.get_arch().types().unwrap();
    let reg = fcs_reg(&fd);
    let mut proto = FuncProto::new();
    proto.set_internal(Rc::new(std_model(fd.get_arch().manage())), tf.get_type_void().unwrap());
    proto.set_param(0, "value", &ParameterPieces {
        addr: addr(&reg, 0), type_: Some(tf.get_base(1, type_metatype::TYPE_UINT).unwrap()),
        flags: pf::TYPELOCK | pf::NAMELOCK,
    });
    proto.set_param(1, "high", &ParameterPieces {
        addr: addr(&reg, 4), type_: Some(tf.get_base(4, type_metatype::TYPE_UINT).unwrap()),
        flags: pf::TYPELOCK | pf::NAMELOCK | pf::CUSTOM_STORAGE,
    });
    proto.set_custom_storage(true);

    assert!(proto.install_input_carrier(0, &addr(&reg, 0), 8, tf).is_err());
    assert_eq!(proto.get_param(0).unwrap().get_size(), 1);
    assert_eq!(proto.get_param(1).unwrap().get_address(), addr(&reg, 4));
    assert!(proto.install_input_carrier(0, &addr(&reg, 0), 4, tf).unwrap());
    assert_eq!(proto.source_param(0).unwrap().get_flags() & pf::CUSTOM_STORAGE, 0);
    assert_ne!(proto.source_param(1).unwrap().get_flags() & pf::CUSTOM_STORAGE, 0);

    // A host/source edit invalidates the old derived envelope before moving
    // another slot into it. Its exact committed storage wins, not the carrier.
    proto.set_param(1, "high", &ParameterPieces {
        addr: addr(&reg, 2), type_: Some(tf.get_base(2, type_metatype::TYPE_UINT).unwrap()),
        flags: pf::TYPELOCK | pf::NAMELOCK | pf::CUSTOM_STORAGE,
    });
    assert_eq!(proto.get_param(0).unwrap().get_size(), 1);
    assert_eq!(proto.get_param(1).unwrap().get_address(), addr(&reg, 2));
    assert!(proto.install_input_carrier(0, &addr(&reg, 0), 4, tf).is_err());
    assert_eq!(proto.source_param(0).unwrap().get_name(), "value");
    assert_eq!(proto.source_param(1).unwrap().get_size(), 2);
}

#[test]
fn physical_refinement_cannot_drop_previously_live_bytes_or_restore_cleared_slots() {
    use kuna_decomp::fspec::parameter_pieces_flags as pf;
    let fd = fcs_fd();
    let tf = fd.get_arch().types().unwrap();
    let reg = fcs_reg(&fd);
    let mut proto = FuncProto::new();
    proto.set_internal(Rc::new(std_model(fd.get_arch().manage())), tf.get_type_void().unwrap());
    proto.set_param(0, "value", &ParameterPieces {
        addr: addr(&reg, 3), type_: Some(tf.get_base(1, type_metatype::TYPE_UINT).unwrap()),
        flags: pf::TYPELOCK,
    });
    assert!(proto.install_input_carrier(0, &addr(&reg, 0), 4, tf).unwrap());
    assert_eq!(proto.input_projection(0).unwrap().byte_offset, 3);
    // [2,6) contains the source byte at 3 but drops the established [0,2).
    assert!(proto.install_input_carrier(0, &addr(&reg, 2), 4, tf).is_err());
    assert_eq!(proto.get_param(0).unwrap().get_address(), addr(&reg, 0));
    assert_eq!(proto.get_param(0).unwrap().get_size(), 4);
    assert!(proto.install_input_carrier(0, &addr(&reg, 0), 8, tf).unwrap());
    assert_eq!(proto.input_projection(0).unwrap().byte_offset, 3);
    assert_eq!(proto.source_param(0).unwrap().get_address(), addr(&reg, 3));
    proto.clear_input();
    proto.restore_source_inputs();
    assert_eq!(proto.num_params(), 0);
    assert!(proto.source_param(0).is_none());
}

#[test]
fn source_unlock_does_not_turn_a_derived_carrier_into_persistent_authority() {
    use kuna_decomp::fspec::parameter_pieces_flags as pf;
    let fd = fcs_fd();
    let tf = fd.get_arch().types().unwrap();
    let reg = fcs_reg(&fd);
    let mut proto = FuncProto::new();
    proto.set_internal(Rc::new(std_model(fd.get_arch().manage())), tf.get_type_void().unwrap());
    proto.set_param(0, "value", &ParameterPieces {
        addr: addr(&reg, 0), type_: Some(tf.get_base(1, type_metatype::TYPE_UINT).unwrap()),
        flags: 0,
    });
    assert!(proto.install_input_carrier(0, &addr(&reg, 0), 4, tf).is_err());
    assert!(!proto.is_input_locked());
    proto.set_input_lock(true);
    assert!(proto.install_input_carrier(0, &addr(&reg, 0), 4, tf).unwrap());
    proto.set_input_lock(false);
    assert_eq!(proto.get_param(0).unwrap().get_size(), 1);
    assert_eq!(proto.source_param(0).unwrap().get_flags() & pf::TYPELOCK, 0);
    proto.clear_unlocked_input();
    proto.restore_source_inputs();
    assert_eq!(proto.num_params(), 0);
}

#[test]
fn physical_only_inputs_do_not_replace_closed_source_arity_or_survive_boundary_edits() {
    let fd = fcs_fd();
    let tf = fd.get_arch().types().unwrap();
    let reg = fcs_reg(&fd);
    let mut proto = FuncProto::new();
    proto.set_internal(Rc::new(std_model(fd.get_arch().manage())), tf.get_type_void().unwrap());
    proto.set_input_lock(true);
    assert!(proto.install_physical_only_input(&addr(&reg, 0), 4, tf).unwrap());
    assert!(proto.source_param(0).is_none());
    // Clearing recovered execution slots preserves the original explicit void
    // source lock, unlike deliberately unlocking or replacing the declaration.
    proto.store_clear_all_inputs();
    assert_eq!(proto.num_params(), 0);
    assert!(proto.is_input_locked());
    assert!(proto.install_physical_only_input(&addr(&reg, 0), 4, tf).unwrap());
    proto.set_dotdotdot(true);
    assert_eq!(proto.num_params(), 0);
    assert!(proto.install_physical_only_input(&addr(&reg, 0), 4, tf).is_err());
    proto.set_dotdotdot(false);
    assert!(proto.install_physical_only_input(&addr(&reg, 0), 4, tf).unwrap());
    proto.set_void_input_lock(false);
    proto.restore_source_inputs();
    assert_eq!(proto.num_params(), 0);
    assert!(!proto.is_input_locked());
    assert!(proto.install_physical_only_input(&addr(&reg, 0), 4, tf).is_err());
}

#[test]
fn replacing_a_projection_cannot_steal_another_formals_high_identity() {
    use kuna_decomp::fspec::parameter_pieces_flags as pf;
    use kuna_decomp::merge::MergeContext;
    let mut fd = fcs_fd();
    let arch = fd.get_arch().clone();
    let tf = arch.types().unwrap();
    let reg = fcs_reg(&fd);
    let byte = tf.get_base(1, type_metatype::TYPE_UINT).unwrap();
    fd.get_func_proto_mut().set_internal(Rc::new(std_model(arch.manage())), tf.get_type_void().unwrap());
    for (slot, name, offset) in [(0, "first", 0), (1, "second", 8)] {
        fd.get_func_proto_mut().set_param(slot, name, &ParameterPieces {
            addr: addr(&reg, offset), type_: Some(byte.clone()), flags: pf::TYPELOCK | pf::NAMELOCK,
        });
    }
    for (slot, offset) in [(0, 0), (1, 8)] {
        fd.get_func_proto_mut().install_input_carrier(slot, &addr(&reg, offset), 4, tf).unwrap();
    }
    let pc = fd.get_address().clone();
    let mut projections = Vec::new();
    for offset in [0, 8] {
        let input = fd.new_varnode(4, &addr(&reg, offset), None);
        let input = fd.set_input_varnode(input).unwrap();
        let op = fcs_new_op(&mut fd, 2, pc.get_offset(), OpCode::CPUI_SUBPIECE);
        let zero = fd.new_constant(4, 0);
        fd.op_set_input(op, input, 0).unwrap();
        fd.op_set_input(op, zero, 1).unwrap();
        let output = fd.new_varnode_out(1, &addr(&reg, offset), op).unwrap();
        fd.vbank_mut().get_mut(output).unwrap().update_type_locked(byte.clone(), true, true);
        projections.push(output);
    }
    let copy = fcs_new_op(&mut fd, 1, pc.get_offset(), OpCode::CPUI_COPY);
    fd.op_set_input(copy, projections[1], 0).unwrap();
    let replacement = fd.new_varnode_out(1, &addr(&reg, 16), copy).unwrap();
    fd.vbank_mut().get_mut(replacement).unwrap().update_type_locked(byte, true, true);
    fd.set_high_level();
    fd.record_source_input_projection(0, projections[0]);
    fd.record_source_input_projection(1, projections[1]);
    let first_high = fd.vbank().get(projections[0]).unwrap().get_high().unwrap();
    let second_high = fd.vbank().get(projections[1]).unwrap().get_high().unwrap();
    let replacement_high = fd.vbank().get(replacement).unwrap().get_high().unwrap();
    let mut cache = kuna_decomp::variable::HighIntersectTest::new(
        kuna_decomp::cover::PcodeOpSet::new(Box::new(Vec::new), Box::new(|_, _| false)));
    MergeContext::bank_merge_highs(&mut fd, second_high, replacement_high, false, &mut cache).unwrap();
    assert_ne!(replacement, projections[1]);
    assert_eq!(fd.vbank().get(replacement).unwrap().get_high(), Some(second_high));
    // Replacement is a different SSA value but shares the second source's High.
    // Reattaching the first formal would make host edits target the wrong formal.
    fd.total_replace(projections[0], replacement).unwrap();
    assert_eq!(fd.source_projection_slot_for_high(second_high), Some(1));
    assert_eq!(fd.source_projection_slot_for_high(first_high), None);
    assert_eq!(fd.get_func_proto().source_param(0).unwrap().get_name(), "first");
    assert_eq!(fd.get_func_proto().source_param(1).unwrap().get_name(), "second");
}

#[test]
fn raw_call_state_survives_placeholder_abort_and_late_restriction() {
    use kuna_base::space::{SpacebaseSpace, VarnodeStorage};
    use kuna_decomp::kuna_physicalinputs::{capture_call_inputs, EntryRequirements};

    let mut manager = fcs_manager();
    let ram = Rc::clone(manager.get_space_by_name("ram").unwrap());
    let reg = Rc::clone(manager.get_space_by_name("register").unwrap());
    let stack = Rc::new(SpacebaseSpace::new("raw_stack", 5, 8, &ram, 1, false, false));
    manager.add_spacebase_pointer(&stack, &VarnodeStorage {
        space: Some(Rc::clone(&reg)), offset: 0x20, size: 8,
    }, 8, true).unwrap();
    manager.insert_space(Rc::clone(&stack)).unwrap();
    let mut fd = Funcdata::new("caller", "caller", Rc::new(ArchContext::new(manager)),
        Address::new(ram, 0x1000), 0x10000000, 0x40).unwrap();
    let tf = fd.get_arch().types_rc().unwrap();
    let model = Rc::new(std_model(fd.get_arch().manage()));
    let mut restricted = FuncProto::new();
    restricted.set_internal(Rc::clone(&model), tf.get_type_void().unwrap());
    restricted.set_param(0, "value", &ParameterPieces {
        addr: addr(&reg, 0x38),
        type_: Some(tf.get_base(4, type_metatype::TYPE_INT).unwrap()),
        flags: kuna_decomp::fspec::parameter_pieces_flags::TYPELOCK,
    });
    restricted.set_input_lock(true);

    let call = fcs_new_op(&mut fd, 2, 0x1010, OpCode::CPUI_CALL);
    let dest = fd.new_constant(8, 0x2000);
    let argument = fd.new_varnode(4, &addr(&reg, 0x38), None);
    fd.op_set_input(call, dest, 0).unwrap();
    fd.op_set_input(call, argument, 1).unwrap();
    let root = fd.bblocks_ref().root.unwrap();
    let block = fd.bblocks_mut().new_block_basic(root);
    fd.op_insert_end(call, block);
    let mut fc = FuncCallSpecs::new(call, Address::default());
    fc.proto_mut().copy(&restricted);
    fc.get_active_input().register_trial(&addr(&reg, 0x38), 4);
    fc.get_active_input().get_trial_mut(0).set_slot(1);
    fc.create_placeholder(&mut fd, &stack).unwrap();
    let placeholder = fd.obank().get(call).unwrap().get_in(2).unwrap();
    assert!(fd.vbank().get(placeholder).unwrap().is_spacebase_placeholder());
    let mut requirements = EntryRequirements::default();
    requirements.reads.push((addr(&reg, 0x18), 4)); // EBX, outside the source formal.
    fc.set_physical_requirements(Rc::new(requirements));
    let index = fd.push_call_specs(fc);
    capture_call_inputs(&mut fd, index).unwrap();
    let raw = fd.obank().get(call).unwrap().get_in(3).unwrap();
    assert_ne!(raw, argument);
    assert_eq!(fd.vbank().get(raw).unwrap().get_addr(), &addr(&reg, 0x18));
    assert_eq!(fd.vbank().get(raw).unwrap().get_size(), 4);
    assert!(fd.get_call_specs(index).physical_inputs().iter().any(|input|
        input.operand_slot == 3 && input.address == addr(&reg, 0x18) && input.size == 4));

    // These APIs normally detach the descriptor while mutating the CALL.
    // Metadata must follow the same value, not the placeholder's former slot.
    let mut fc = fd.replace_call_specs(index);
    fc.abort_spacebase_relative(&mut fd);
    assert_eq!(fd.obank().get(call).unwrap().num_input(), 3);
    assert_eq!(fd.obank().get(call).unwrap().get_in(2), Some(raw));
    assert!(fc.physical_inputs().iter().any(|input|
        input.operand_slot == 2 && input.address == addr(&reg, 0x18) && input.size == 4));
    let mut log = kuna_decomp::kuna_restartlog::RestartLog::new();
    fc.force_set(&mut fd, &restricted, &mut log).unwrap();
    assert!(!fd.has_restart_pending());
    assert_eq!(fd.obank().get(call).unwrap().num_input(), 3);
    assert_eq!(fd.obank().get(call).unwrap().get_in(0), Some(dest));
    assert_eq!(fd.obank().get(call).unwrap().get_in(1), Some(argument));
    assert_eq!(fd.obank().get(call).unwrap().get_in(2), Some(raw));
    assert!(fc.requires_raw_call());
    assert_eq!(fc.proto().num_params(), 1);
    assert_eq!(fc.proto().source_param(0).unwrap().get_name(), "value");
    assert!(fc.physical_inputs().iter().any(|input|
        input.operand_slot == 2 && input.address == addr(&reg, 0x18) && input.size == 4));
    fd.restore_call_specs_at(index, fc);
}

#[test]
fn call_result_entry_state_requires_a_definition_on_every_resolved_return() {
    use std::collections::BTreeMap;
    use kuna_decomp::kuna_physicalinputs::from_raw_flow;

    fn function(glb: Rc<ArchContext>, name: &str) -> Funcdata {
        let ram = Rc::clone(glb.manage().get_space_by_name("ram").unwrap());
        let reg = Rc::clone(glb.manage().get_space_by_name("register").unwrap());
        let mut fd = Funcdata::new(name, name, glb, Address::new(ram, 0x1000),
            0x10000000, 0x40).unwrap();
        let tf = fd.get_arch().types_rc().unwrap();
        let model = Rc::new(std_model(fd.get_arch().manage()));
        fd.get_func_proto_mut().set_internal(model, tf.get_type_void().unwrap());
        fd.get_func_proto_mut().set_output(&ParameterPieces {
            addr: addr(&reg, 0),
            type_: Some(tf.get_base(4, type_metatype::TYPE_INT).unwrap()),
            flags: kuna_decomp::fspec::parameter_pieces_flags::TYPELOCK,
        });
        fd.get_func_proto_mut().set_output_lock(true);
        fd
    }

    for (writes_both, returns, unknown_call) in [
        (false, true, false), // one return preserves the incoming result
        (true, true, false),  // every return defines the result
        (true, false, false), // an infinite loop proves no returning definition
        (true, true, true),   // unresolved control effects cannot prove a kill
    ] {
        let glb = Rc::new(ArchContext::new(fcs_manager()));
        let mut callee = function(Rc::clone(&glb), "callee");
        let reg = fcs_reg(&callee);
        let root = callee.bblocks_ref().root.unwrap();
        let entry = callee.bblocks_mut().new_block_basic(root);
        let left = callee.bblocks_mut().new_block_basic(root);
        let right = callee.bblocks_mut().new_block_basic(root);
        callee.bblocks_mut().add_edge(entry, left);
        callee.bblocks_mut().add_edge(entry, right);
        if unknown_call {
            let call = fcs_new_op(&mut callee, 1, 0x1000, OpCode::CPUI_CALL);
            let target = callee.new_constant(8, 0x3000);
            callee.op_set_input(call, target, 0).unwrap();
            callee.op_insert_end(call, entry);
        }
        for (index, block) in [left, right].into_iter().enumerate() {
            if index == 0 || writes_both {
                let copy = fcs_new_op(&mut callee, 1, 0x1010 + index as u64 * 0x10, OpCode::CPUI_COPY);
                let value = callee.new_constant(4, 7 + index as u64);
                callee.op_set_input(copy, value, 0).unwrap();
                fcs_out(&mut callee, copy, Rc::clone(&reg), 0, 4);
                callee.op_insert_end(copy, block);
            }
            if returns {
                let ret = fcs_new_op(&mut callee, 1, 0x1014 + index as u64 * 0x10, OpCode::CPUI_RETURN);
                let target = callee.new_constant(8, 0x4000);
                callee.op_set_input(ret, target, 0).unwrap();
                callee.op_insert_end(ret, block);
            } else {
                callee.bblocks_mut().add_edge(block, block);
            }
        }
        let summary = from_raw_flow(&callee, &BTreeMap::new(), None).requirements;
        let guaranteed = writes_both && returns && !unknown_call;
        assert_eq!(summary.definite_writes, if guaranteed { vec![(addr(&reg, 0), 4)] } else { Vec::new() });
        if !writes_both {
            assert_eq!(summary.reads, vec![(addr(&reg, 0), 4)]);
        }

        let mut caller = function(glb, "caller");
        let root = caller.bblocks_ref().root.unwrap();
        let block = caller.bblocks_mut().new_block_basic(root);
        let call = fcs_new_op(&mut caller, 1, 0x1000, OpCode::CPUI_CALL);
        let target = caller.new_constant(8, 0x2000);
        caller.op_set_input(call, target, 0).unwrap();
        caller.op_insert_end(call, block);
        let ret = fcs_new_op(&mut caller, 1, 0x1005, OpCode::CPUI_RETURN);
        let target = caller.new_constant(8, 0x4000);
        caller.op_set_input(ret, target, 0).unwrap();
        caller.op_insert_end(ret, block);
        let requirements = from_raw_flow(&caller, &BTreeMap::from([(call, Rc::new(summary))]), None).requirements;
        assert_eq!(requirements.reads, if guaranteed { Vec::new() } else { vec![(addr(&reg, 0), 4)] });
    }

    for halt in [pcodeop_flags::badinstruction, pcodeop_flags::noreturn, pcodeop_flags::missing] {
        for stores_entry_value in [false, true] {
            let glb = Rc::new(ArchContext::new(fcs_manager()));
            let mut fd = function(glb, "synthetic_halt");
            let reg = fcs_reg(&fd);
            let ram = fcs_ram(&fd);
            let root = fd.bblocks_ref().root.unwrap();
            let block = fd.bblocks_mut().new_block_basic(root);
            if stores_entry_value {
                // A real observable store before an unusual halt still consumes EDX.
                let store = fcs_new_op(&mut fd, 3, 0x1000, OpCode::CPUI_STORE);
                let space = fd.new_constant(4, ram.get_index() as u64);
                let destination = fd.new_constant(8, 0x6000);
                let value = fd.new_varnode(4, &addr(&reg, 0x10), None);
                fd.op_set_input(store, space, 0).unwrap();
                fd.op_set_input(store, destination, 1).unwrap();
                fd.op_set_input(store, value, 2).unwrap();
                fd.op_insert_end(store, block);
            }
            let copy = fcs_new_op(&mut fd, 1, 0x1002, OpCode::CPUI_COPY);
            let value = fd.new_constant(4, 7);
            fd.op_set_input(copy, value, 0).unwrap();
            fcs_out(&mut fd, copy, Rc::clone(&reg), 0x8, 4); // ECX, not the source EAX result.
            fd.op_insert_end(copy, block);
            let stop = fcs_new_op(&mut fd, 1, 0x1004, OpCode::CPUI_RETURN);
            let target = fd.new_constant(8, 1);
            fd.op_set_input(stop, target, 0).unwrap();
            fd.obank_mut().get_mut(stop).unwrap().set_flag(halt);
            fd.op_insert_end(stop, block);
            let summary = from_raw_flow(&fd, &BTreeMap::new(), None).requirements;
            assert_eq!(summary.reads, if stores_entry_value {
                vec![(addr(&reg, 0x10), 4)]
            } else { Vec::new() }, "a synthetic halt must not read its declared EAX result");
            assert!(summary.incomplete_flow);
            assert!(summary.writes.contains(&(addr(&reg, 0x8), 4)));
            assert!(summary.definite_writes.is_empty());
        }
    }
}

