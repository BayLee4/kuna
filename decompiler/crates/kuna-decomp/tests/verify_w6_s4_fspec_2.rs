//! Adversarial verification tests for item `w6-s4-fspec-2`
//! (the prototype-model layer: `decompiler/cpp/fspec.cc` ~2268-4928 —
//! `ProtoModel`, `ScoreProtoModel`, `ProtoModelMerged`, `ProtoParameter` /
//! `ProtoStore`, `FuncProto` core).
//!
//! Written by the INDEPENDENT verifier.  These target the spots the hunt list
//! flagged as most fragile for this item:
//!
//!   - **Exception -> Result partial-state parity.**  C++ `FuncProto::
//!     updateAllTypes` (fspec.cc:4225) and `ProtoModel::assignParameterStorage`
//!     (fspec.cc:2441) catch ONLY `ParamUnassignedError`; any other
//!     `LowlevelError` thrown from `assignMap` propagates.  The port routes
//!     every error through `unassigned_err` (built as a *Lowlevel* variant) and
//!     catches with a bare `Err(_)`, so a non-ParamUnassigned error (e.g. the
//!     missing-space hidden-return path) is SWALLOWED instead of propagating.  (F1)
//!   - **`ScoreProtoModel::doScore` arithmetic** (fspec.cc:2743): the slot
//!     comparator is slot-only (`sort_unstable_by_key`), the hole penalty table
//!     saturates past index 4 (`penaltyfinal`), and the duplication branch
//!     advances `nextfree` only when it would grow.  (F2)
//!   - **`setReturnBytesConsumed` smallest-wins monotone** (fspec.cc:3959) and
//!     **`resolveExtraPop` 4-byte alignment mask** `(cur+3)&0x0ffffffc`
//!     (fspec.cc:3992).  (F3)
//!   - **`ProtoModelMerged::selectModel` tie-break** (fspec.cc:2882): strictly
//!     `<` bestscore, first index wins ties, early-out at score 0.  (F4)
//!
//! Models are built through the real `build_param_list` + `ParamEntry::seed`
//! post-decode chain (matching the in-crate harness).

use std::rc::Rc;

use kuna_base::address::Address;
use kuna_base::error::KunaError;
use kuna_base::space::{spacetype, AddrSpace, AddrSpaceManager};
use kuna_base::types::int4;

use kuna_decomp::dtype::{type_class, type_metatype, Datatype, TypeFactory, TypeFactoryImpl, TypeRoot};
use kuna_decomp::fspec::{
    FuncProto, ParamActive, ParamEntry, ParameterPieces, ProtoModel,
    PrototypePieces, ScoreProtoModel,
};

// --- shared builders --------------------------------------------------------

fn reg_space_le() -> Rc<AddrSpace> {
    Rc::new(AddrSpace::new(
        spacetype::IPTR_PROCESSOR,
        "register",
        false,
        4,
        1,
        3,
        0,
        0,
        0,
    ))
}

fn addr(spc: &Rc<AddrSpace>, off: u64) -> Address {
    Address::new(Rc::clone(spc), off)
}

fn excl_entry(
    grp: int4,
    space: &Rc<AddrSpace>,
    base: u64,
    size: int4,
    prev: &[ParamEntry],
    mgr: &AddrSpaceManager,
) -> ParamEntry {
    ParamEntry::seed(
        grp,
        type_class::TYPECLASS_GENERAL,
        Rc::clone(space),
        base,
        size,
        1,
        0,
        0,
        true,
        false,
        prev,
        mgr,
    )
    .expect("seed exclusion entry")
}

/// A 4-byte general-purpose integer data-type.
fn int4_type(tf: &TypeFactoryImpl) -> TypeRoot {
    tf.intern(Datatype::new_with_align(4, 4, type_metatype::TYPE_INT))
        .unwrap()
}
/// An 8-byte general-purpose integer data-type (too big for a 4-byte out reg).
fn int8_type(tf: &TypeFactoryImpl) -> TypeRoot {
    tf.intern(Datatype::new_with_align(8, 8, type_metatype::TYPE_INT))
        .unwrap()
}
fn void_type(tf: &TypeFactoryImpl) -> TypeRoot {
    tf.get_type_void().unwrap()
}

/// Build a standard ProtoModel with two int register input entries (groups 0/1
/// at 0x10/0x20) and one 4-byte int register output at 0x10.
fn two_reg_proto_model(mgr: &AddrSpaceManager, reg: &Rc<AddrSpace>) -> ProtoModel {
    let mut model = ProtoModel::new(mgr);
    model.build_param_list("standard").unwrap();
    model.set_name("__cdecl");
    {
        let input = model.input_mut();
        input.push_entry(excl_entry(0, reg, 0x10, 4, &[], mgr));
        let e1 = excl_entry(1, reg, 0x20, 4, input.get_entry(), mgr);
        input.push_entry(e1);
        input.finish_decode();
    }
    {
        let output = model.output_mut();
        output.push_entry(excl_entry(0, reg, 0x10, 4, &[], mgr));
        output.finish_decode();
    }
    model
}

// ===========================================================================
// F1: Exception -> Result parity — the over-broad `Err(_)` catch swallows a
//     non-ParamUnassigned error that C++ would propagate.
// ===========================================================================

/// C++ `assignParameterStorage(..., ignoreOutputError=true)` (fspec.cc:2437)
/// catches ONLY `ParamUnassignedError`.  A return value too big for the output
/// register requires a hidden-return pointer.  This fixture intentionally has
/// neither a stack nor a default data space, so pointer synthesis returns a
/// *Lowlevel* error (NOT ParamUnassigned).
///
/// After the F1 repair the catch is `Err(KunaError::ParamUnassigned { .. })`
/// only, so a non-ParamUnassigned `LowlevelError` PROPAGATES rather than being
/// swallowed into a spurious void return — matching C++ control flow, where the
/// `catch(ParamUnassignedError&)` lets any other exception escape.
#[test]
fn assign_parameter_storage_ignore_output_propagates_nonparamunassigned_w6s4f2() {
    let mgr = AddrSpaceManager::new();
    let reg = reg_space_le();
    let model = two_reg_proto_model(&mgr, &reg);
    let tf = TypeFactoryImpl::new();
    // An 8-byte return needs a hidden pointer, but the manager intentionally
    // has no space from which to derive its size.
    let proto = PrototypePieces {
        name: "f".to_string(),
        outtype: Some(int8_type(&tf)),
        intypes: vec![int4_type(&tf)],
        innames: vec!["a".into()],
        first_var_arg_slot: -1,
        output_storage: None,
        input_storage: Vec::new(),
    };
    let mut res: Vec<ParameterPieces> = Vec::new();
    // ignore_output_error = true: C++ catches ParamUnassignedError only.  A
    // non-ParamUnassigned Lowlevel (missing-space) error must escape, NOT be swallowed.
    let r = model.assign_parameter_storage(&proto, &mut res, true, &tf, &mgr);
    assert!(
        matches!(r, Err(KunaError::Lowlevel { .. })),
        "the missing-space Lowlevel error must propagate past the ParamUnassigned-only \
         catch (got {:?})",
        r
    );
}

/// `FuncProto::updateAllTypes` (fspec.cc:4199) calls `assignParameterStorage`
/// with `ignoreOutputError=false`, so the missing-space hidden-return Lowlevel error
/// propagates INTO updateAllTypes' own `try`.  C++ catches ONLY
/// `ParamUnassignedError`; a `LowlevelError` escapes `updateAllTypes` entirely.
///
/// After the F1 repair the catch is `Err(KunaError::ParamUnassigned { .. })`
/// only, so the missing-space Lowlevel error PROPAGATES out of `update_all_types` rather
/// than being swallowed into `error_inputparam` — matching C++ control flow.
#[test]
fn update_all_types_propagates_missing_space_lowlevel_w6s4f1() {
    let mgr = AddrSpaceManager::new();
    let reg = reg_space_le();
    let model = Rc::new(two_reg_proto_model(&mgr, &reg));
    let tf = TypeFactoryImpl::new();

    let mut fp = FuncProto::new();
    fp.set_internal(Rc::clone(&model), void_type(&tf));

    // 8-byte return -> output assign hits the missing-space hidden-return Lowlevel error.
    let proto = PrototypePieces {
        name: "g".to_string(),
        outtype: Some(int8_type(&tf)),
        intypes: vec![int4_type(&tf)],
        innames: vec!["a".into()],
        first_var_arg_slot: -1,
        output_storage: None,
        input_storage: Vec::new(),
    };
    let r = fp.update_all_types(&proto, &tf, &mgr);
    // Repaired port behavior: the non-ParamUnassigned Lowlevel error escapes
    // (only a real ParamUnassignedError would set error_inputparam + return Ok).
    assert!(
        matches!(r, Err(KunaError::Lowlevel { .. })),
        "updateAllTypes must propagate the non-ParamUnassigned Lowlevel error \
         (got {:?})",
        r
    );
}

/// Control case proving the catch is genuinely too broad: a return value that
/// the model CAN assign (4-byte int into the 4-byte output reg) must succeed
/// with NO error flag and a real (non-void) output.  This isolates the F1
/// finding to the error path (vs. a model that always fails).
#[test]
fn update_all_types_happy_path_assigns_output_no_error_w6s4() {
    let mgr = AddrSpaceManager::new();
    let reg = reg_space_le();
    let model = Rc::new(two_reg_proto_model(&mgr, &reg));
    let tf = TypeFactoryImpl::new();

    let mut fp = FuncProto::new();
    fp.set_internal(Rc::clone(&model), void_type(&tf));

    let proto = PrototypePieces {
        name: "h".to_string(),
        outtype: Some(int4_type(&tf)),
        intypes: vec![int4_type(&tf), int4_type(&tf)],
        innames: vec!["a".into(), "b".into()],
        first_var_arg_slot: -1,
        output_storage: None,
        input_storage: Vec::new(),
    };
    fp.update_all_types(&proto, &tf, &mgr).unwrap();
    assert!(
        !fp.has_input_errors(),
        "happy path must not set error_inputparam"
    );
    // Output landed in the 4-byte output register at 0x10.
    let out = fp.get_output();
    assert_eq!(out.get_address().get_offset(), 0x10);
    assert_eq!(out.get_size(), 4);
    // Two inputs recovered at 0x10 / 0x20.
    assert_eq!(fp.num_params(), 2);
    assert_eq!(fp.get_param(0).unwrap().get_address().get_offset(), 0x10);
    assert_eq!(fp.get_param(1).unwrap().get_address().get_offset(), 0x20);
}

// ===========================================================================
// F2: ScoreProtoModel::doScore arithmetic (holes, duplication, penaltyfinal).
// ===========================================================================

/// `doScore` (fspec.cc:2758): a trial in slot 1 with slot 0 missing yields a
/// hole at slot 0 -> `penalty[0] == 16`.  A perfect 2-slot fit yields 0.  These
/// pin the hole-penalty table indexing.
#[test]
fn do_score_hole_at_slot0_costs_16_w6s4() {
    let mgr = AddrSpaceManager::new();
    let reg = reg_space_le();
    let model = two_reg_proto_model(&mgr, &reg);

    // Only the slot-1 (0x20) parameter present -> slot 0 hole -> 16.
    let mut score = ScoreProtoModel::new(true, 1);
    score.add_parameter(&model, &addr(&reg, 0x20), 4);
    score.do_score();
    assert_eq!(score.get_num_mismatch(), 0);
    assert_eq!(score.get_score(), 16);

    // Both slots present in REVERSE order -> still a perfect fit (sort by slot).
    let mut score2 = ScoreProtoModel::new(true, 2);
    score2.add_parameter(&model, &addr(&reg, 0x20), 4); // slot 1 first
    score2.add_parameter(&model, &addr(&reg, 0x10), 4); // slot 0 second
    score2.do_score();
    assert_eq!(score2.get_score(), 0, "doScore sorts by slot before scoring");
}

/// `doScore` duplication branch (fspec.cc:2770): two trials that map to the SAME
/// slot incur `mismatchpenalty == 20`; a trial whose address is NOT a possible
/// parameter is counted in `mismatch` and adds `mismatchpenalty * mismatch`.
#[test]
fn do_score_duplication_and_mismatch_penalties_w6s4() {
    let mgr = AddrSpaceManager::new();
    let reg = reg_space_le();
    let model = two_reg_proto_model(&mgr, &reg);

    // Two trials both at slot 0 (0x10): the second is a duplication -> +20.
    // (Both are possible params, so mismatch == 0.)
    let mut score = ScoreProtoModel::new(true, 2);
    score.add_parameter(&model, &addr(&reg, 0x10), 4);
    score.add_parameter(&model, &addr(&reg, 0x10), 4);
    score.do_score();
    assert_eq!(score.get_num_mismatch(), 0);
    assert_eq!(score.get_score(), 20, "slot duplication costs mismatchpenalty");

    // A trial at an address that is NOT a possible parameter (0x100) is a
    // mismatch: not added to `entry`, counted in `mismatch` -> 20 * 1.
    let mut score2 = ScoreProtoModel::new(true, 3);
    score2.add_parameter(&model, &addr(&reg, 0x10), 4); // slot 0
    score2.add_parameter(&model, &addr(&reg, 0x20), 4); // slot 1
    score2.add_parameter(&model, &addr(&reg, 0x100), 4); // not a param
    score2.do_score();
    assert_eq!(score2.get_num_mismatch(), 1);
    assert_eq!(
        score2.get_score(),
        20,
        "a non-parameter trial adds mismatchpenalty*mismatch to a perfect base"
    );
}

// ===========================================================================
// F3: setReturnBytesConsumed monotone + resolveExtraPop alignment mask.
// ===========================================================================

/// `setReturnBytesConsumed` (fspec.cc:3959): 0 is a no-op (returns false); the
/// first non-zero wins; a SMALLER value updates (returns true); a LARGER value
/// does not.  Pins the `returnBytesConsumed == 0 || val < returnBytesConsumed`
/// monotone-decreasing rule.
#[test]
fn set_return_bytes_consumed_is_monotone_decreasing_w6s4() {
    let mut fp = FuncProto::new();
    assert!(!fp.set_return_bytes_consumed(0), "0 is a no-op");
    assert_eq!(fp.get_return_bytes_consumed(), 0);

    assert!(fp.set_return_bytes_consumed(8), "first non-zero wins");
    assert_eq!(fp.get_return_bytes_consumed(), 8);

    assert!(!fp.set_return_bytes_consumed(12), "larger -> no change");
    assert_eq!(fp.get_return_bytes_consumed(), 8);

    assert!(fp.set_return_bytes_consumed(4), "smaller -> update");
    assert_eq!(fp.get_return_bytes_consumed(), 4);

    assert!(!fp.set_return_bytes_consumed(0), "0 still a no-op after set");
    assert_eq!(fp.get_return_bytes_consumed(), 4);
}

// ===========================================================================
// F4: ProtoModelMerged::selectModel tie-break + score-0 early-out.
// ===========================================================================

/// `selectModel` (fspec.cc:2882) iterates the constituent list, keeps the model
/// with the STRICTLY smallest score, breaks ties toward the FIRST index, and
/// early-outs the moment a model scores 0.  Build a merged model from two
/// constituents that score identically for a given trial set and assert the
/// first one is selected (tie -> first index).
#[test]
fn select_model_ties_break_to_first_index_w6s4() {
    let mgr = AddrSpaceManager::new();
    let reg = reg_space_le();

    // Two identical constituent models -> identical scores for any trial set.
    let m0 = Rc::new(two_reg_proto_model(&mgr, &reg));
    let m1 = Rc::new(two_reg_proto_model(&mgr, &reg));

    let mut merged = ProtoModel::new_merged(&mgr);
    merged.merged_push(Rc::clone(&m0)).unwrap();
    merged.merged_push(Rc::clone(&m1)).unwrap();
    merged.merged_finalize();

    // A trial set that perfectly fits both -> both score 0 -> the FIRST index
    // wins (and the score-0 early-out fires on the first model).
    let mut active = ParamActive::new(false);
    active.register_trial(&addr(&reg, 0x10), 4);
    active.register_trial(&addr(&reg, 0x20), 4);
    for i in 0..active.get_num_trials() {
        active.get_trial_mut(i).mark_active();
    }

    let chosen = merged.select_model(&active).expect("selectModel");
    // The chosen model must be the first constituent (m0), by Rc identity.
    assert!(
        Rc::ptr_eq(&chosen, &m0),
        "selectModel must break a score tie toward the first constituent"
    );
    assert!(!Rc::ptr_eq(&chosen, &m1));
}

/// `selectModel` with NO trials still scores every model (base score 0 each)
/// and returns the first.  And a merged model with a single constituent always
/// returns it.  Guards the `bestindex >= 0` final branch and the empty-trial
/// loop bound.
#[test]
fn select_model_empty_trials_returns_first_w6s4() {
    let mgr = AddrSpaceManager::new();
    let reg = reg_space_le();
    let m0 = Rc::new(two_reg_proto_model(&mgr, &reg));

    let mut merged = ProtoModel::new_merged(&mgr);
    merged.merged_push(Rc::clone(&m0)).unwrap();
    merged.merged_finalize();

    let active = ParamActive::new(false); // no trials
    let chosen = merged.select_model(&active).expect("selectModel no trials");
    assert!(Rc::ptr_eq(&chosen, &m0));
}
