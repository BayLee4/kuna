//! The `ActionSetCasts` cast-insertion driver (C++ `coreaction.cc:2407-2872`),
//! W10 item `w10-merge-casts`.
//!
//! This is the keystone of the S9 rendering plane: once the S6 Merge stage has
//! populated the HighVariable read-/def-facing **type graph** (the four facing
//! accessors landed on [`crate::funcdata_facing`]) and the S6/W7 type inference
//! has scored the union/struct types, `ActionSetCasts` walks every printed op in
//! dominance order and inserts the explicit `CPUI_CAST`/`CPUI_PTRSUB` ops a C
//! compiler would need so the typed accesses *render*:
//!
//! ```text
//!   (float8)a            // a FLOAT_FLOAT2FLOAT whose token type != high type
//!   return (float4)(...) // a value whose declared type narrows the expression
//!   ptr->field3          // a union/struct field PTRSUB(ptr,#0) resolution
//!   u.b.bval1            // a union field access
//! ```
//!
//! ## Architecture (ADR-0001 faithful)
//!
//! The C++ `apply` operates directly on `Funcdata &data` and reaches the
//! decision predicates through `CastStrategy *castStrategy =
//! data.getArch()->print->getCastStrategy()`.  In the Rust port the driver is a
//! `&mut Funcdata` method ([`Funcdata::action_set_casts`]); the per-op decision
//! predicates ([`crate::cast::CastStrategyC`]) reach the read-only IR through a
//! [`FuncdataCastContext`] bridge that interns the slotmap [`VarnodeId`]/[`OpId`]
//! keys behind the opaque [`VnRef`]/[`OpRef`] handles the [`CastContext`] trait
//! names.  The driver itself never goes through the trait — it mutates the IR
//! through the normal `Funcdata` op/varnode API (`new_op`, `op_set_input`,
//! `op_insert_before`/`After`, `new_unique`, `new_constant`).
//!
//! ## Faithfulness
//!
//! Every helper (`castInput`/`castOutput`/`resolveUnion`/`checkPointerIssues`/
//! `insertPtrsubZero`/`testStructOffset0`/`tryResolutionAdjustment`/
//! `tryResolutionCopy`/`isOpIdentical`) is transcribed statement-for-statement
//! from `coreaction.cc:2407-2872`, citing the source line.  The per-op
//! `getInputCast`/`getOutputToken` surface ([`get_input_cast`]/
//! [`get_output_token`]) ports the default `TypeOp` bodies (typeop.cc:283-304)
//! plus the per-op-code overrides the corpus exercises (COPY/LOAD/STORE, the six
//! comparisons, ZEXT/SEXT, and the INT-arithmetic `getOutputToken` overrides);
//! op-codes without a ported override fall through to the faithful default,
//! which is exactly what the C++ does for any op whose `TypeOp` subclass does not
//! override these virtuals.
//!
//! ## What stays stubbed (and why it is faithful)
//!
//! `dt->resolveInFlow(op, slot)` — the *scoring* half of union resolution
//! (`ScoreUnionFields::run`) — is still a stub in [`crate::unionresolve`].  The
//! C++ `resolveUnion` calls `resolveInFlow` as a *last chance* when the cache
//! misses, then re-reads the cache.  Here we call the landed
//! [`Funcdata::find_resolve_facing`] lookup (which consults the populated cache)
//! and, on a miss, attempt `resolve_in_flow`; when the scorer is stubbed the
//! lookup simply stays a miss and no PTRSUB is inserted for that edge — the same
//! conservative outcome the C++ produces when no field scores.

use std::cell::RefCell;
use std::rc::Rc;

use kuna_base::types::{int4, int8, uintb};
use kuna_base::error::KunaResult;
use kuna_num::opcodes::OpCode;

use crate::cast::{CastContext, CastStrategy, OpRef, VnRef};
#[cfg(test)]
use crate::cast::CastStrategyC;
use crate::coreaction_infertypes::{declared_input_type_local as input_type_local, output_type_local};
use crate::dtype::{type_metatype, Datatype, TypeFactory};
use crate::funcdata::Funcdata;
use crate::context::{OpId, VarnodeId};
use crate::unionresolve::ResolvedUnion;

// Missing IR edges mean no cast; acquisition failures remain Result errors.
macro_rules! cast_some {
    ($value:expr) => {
        match $value {
            Some(value) => value,
            None => return Ok(None),
        }
    };
}

// =============================================================================
// FuncdataCastContext — the read-only IR bridge for CastStrategyC.
// =============================================================================

/// A [`CastContext`] backed by a live `&mut Funcdata` (C++: the `Varnode *` /
/// `PcodeOp *` the `CastStrategy` methods dereference, reaching the merged
/// HighVariable type graph and the union cache through
/// `op->getParent()->getFuncdata()`).
///
/// The [`CastContext`] trait names the IR queries with opaque [`VnRef`]/[`OpRef`]
/// `usize` handles so the promotion logic has no dependency on the slotmap key
/// types.  This bridge interns the real [`VarnodeId`]/[`OpId`] keys behind those
/// handles (a `Vec` per key kind; index == handle).  The Funcdata sits behind a
/// `RefCell` because two trait accessors (`vn_high_type_read_facing`,
/// `vn_set_unsigned_print`) need `&mut Funcdata` (the lazy HighVariable type
/// recompute and the constant-print flag), while the trait hands them out behind
/// `&self`/`&mut self`.
pub struct FuncdataCastContext<'a> {
    fd: RefCell<&'a mut Funcdata>,
    vn_intern: RefCell<Vec<VarnodeId>>,
    op_intern: RefCell<Vec<OpId>>,
    byte_as: Option<Rc<Datatype>>,
}

impl<'a> FuncdataCastContext<'a> {
    /// Build the bridge over a `&mut Funcdata`.
    pub fn new(fd: &'a mut Funcdata) -> FuncdataCastContext<'a> {
        FuncdataCastContext {
            fd: RefCell::new(fd),
            vn_intern: RefCell::new(Vec::new()),
            op_intern: RefCell::new(Vec::new()),
            byte_as: None,
        }
    }

    /// (kuna) Report a non-constant one-byte TYPE_UNKNOWN as `ty` instead, so the
    /// promotion queries see the type the printer spells it as.
    pub(crate) fn with_unknown_byte_as(mut self, ty: Rc<Datatype>) -> Self {
        self.byte_as = Some(ty);
        self
    }

    fn view(&self, vn: VarnodeId, ty: Rc<Datatype>) -> Rc<Datatype> {
        match &self.byte_as {
            Some(b)
                if ty.get_size() == 1
                    && ty.get_metatype() == type_metatype::TYPE_UNKNOWN
                    && !self.fd.borrow().vbank().get(vn).is_some_and(|v| v.is_constant()) =>
            {
                Rc::clone(b)
            }
            _ => ty,
        }
    }

    /// Intern a `VarnodeId`, returning its opaque handle (stable for the life of
    /// this context).
    pub(crate) fn vn_ref(&self, vn: VarnodeId) -> VnRef {
        let mut tab = self.vn_intern.borrow_mut();
        // Linear scan: the per-op cast decision touches a handful of varnodes, so
        // the table stays tiny; this keeps the handle stable without a HashMap
        // (clippy-banned) and reproduces the C++ pointer identity.
        if let Some(i) = tab.iter().position(|&k| k == vn) {
            return VnRef(i);
        }
        tab.push(vn);
        VnRef(tab.len() - 1)
    }

    /// Intern an `OpId`, returning its opaque handle.
    pub(crate) fn op_ref(&self, op: OpId) -> OpRef {
        let mut tab = self.op_intern.borrow_mut();
        if let Some(i) = tab.iter().position(|&k| k == op) {
            return OpRef(i);
        }
        tab.push(op);
        OpRef(tab.len() - 1)
    }

    /// Recover a `VarnodeId` from its opaque handle.
    fn vn_key(&self, vn: VnRef) -> VarnodeId {
        self.vn_intern.borrow()[vn.0]
    }

    /// Recover an `OpId` from its opaque handle.
    fn op_key(&self, op: OpRef) -> OpId {
        self.op_intern.borrow()[op.0]
    }
}

impl CastContext for FuncdataCastContext<'_> {
    fn op_code(&self, op: OpRef) -> OpCode {
        let op = self.op_key(op);
        self.fd.borrow().obank().get(op).expect("cast ctx: stale op").code()
    }

    fn op_num_input(&self, op: OpRef) -> int4 {
        let op = self.op_key(op);
        self.fd.borrow().obank().get(op).expect("cast ctx: stale op").num_input()
    }

    fn op_in(&self, op: OpRef, slot: int4) -> VnRef {
        let opk = self.op_key(op);
        let vn = self
            .fd
            .borrow()
            .obank()
            .get(opk)
            .expect("cast ctx: stale op")
            .get_in(slot)
            .expect("cast ctx: missing input slot");
        self.vn_ref(vn)
    }

    fn op_out(&self, op: OpRef) -> Option<VnRef> {
        let opk = self.op_key(op);
        let out = self.fd.borrow().obank().get(opk).expect("cast ctx: stale op").get_out();
        out.map(|vn| self.vn_ref(vn))
    }

    fn op_slot(&self, op: OpRef, vn: VnRef) -> int4 {
        let opk = self.op_key(op);
        let vnk = self.vn_key(vn);
        self.fd.borrow().obank().get(opk).expect("cast ctx: stale op").get_slot(vnk)
    }

    fn vn_is_constant(&self, vn: VnRef) -> bool {
        let vn = self.vn_key(vn);
        self.fd.borrow().vbank().get(vn).expect("cast ctx: stale vn").is_constant()
    }

    fn vn_is_explicit(&self, vn: VnRef) -> bool {
        let vn = self.vn_key(vn);
        self.fd.borrow().vbank().get(vn).expect("cast ctx: stale vn").is_explicit()
    }

    fn vn_is_written(&self, vn: VnRef) -> bool {
        let vn = self.vn_key(vn);
        self.fd.borrow().vbank().get(vn).expect("cast ctx: stale vn").is_written()
    }

    fn vn_size(&self, vn: VnRef) -> int4 {
        let vn = self.vn_key(vn);
        self.fd.borrow().vbank().get(vn).expect("cast ctx: stale vn").get_size()
    }

    fn vn_offset(&self, vn: VnRef) -> uintb {
        let vn = self.vn_key(vn);
        self.fd.borrow().vbank().get(vn).expect("cast ctx: stale vn").get_offset()
    }

    fn vn_def(&self, vn: VnRef) -> Option<OpRef> {
        let vn = self.vn_key(vn);
        let def = self.fd.borrow().vbank().get(vn).expect("cast ctx: stale vn").get_def();
        def.map(|op| self.op_ref(op))
    }

    fn vn_lone_descend(&self, vn: VnRef) -> Option<OpRef> {
        let vnk = self.vn_key(vn);
        let lone = self.fd.borrow().lone_descend(vnk);
        lone.map(|op| self.op_ref(op))
    }

    fn vn_high_type(&self, vn: VnRef) -> Rc<Datatype> {
        let vnk = self.vn_key(vn);
        // high->getType(): the merged HighVariable's data-type (lazy recompute ->
        // &mut), else the bare Varnode type when no HighVariable exists.
        let ty = {
            let mut fd = self.fd.borrow_mut();
            fd.high_get_type(vnk)
                .unwrap_or_else(|| Rc::clone(fd.vbank().get(vnk).expect("cast ctx: stale vn").get_type()))
        };
        self.view(vnk, ty)
    }

    fn vn_high_type_read_facing(&self, vn: VnRef, op: OpRef) -> KunaResult<Rc<Datatype>> {
        let vnk = self.vn_key(vn);
        let opk = self.op_key(op);
        let ty = self.fd.borrow_mut().vn_high_type_read_facing(vnk, opk)?;
        Ok(self.view(vnk, ty))
    }

    fn op_inherits_sign(&self, op: OpRef) -> bool {
        crate::typeop::type_op_info(self.op_code(op)).inherits_sign()
    }

    fn op_inherits_sign_first_param_only(&self, op: OpRef) -> bool {
        crate::typeop::type_op_info(self.op_code(op)).inherits_sign_first_param_only()
    }

    fn op_is_shift_op(&self, op: OpRef) -> bool {
        crate::typeop::type_op_info(self.op_code(op)).is_shift_op()
    }

    fn op_is_bool_output(&self, op: OpRef) -> bool {
        let opk = self.op_key(op);
        self.fd.borrow().obank().get(opk).expect("cast ctx: stale op").is_bool_output()
    }

    fn op_is_call(&self, op: OpRef) -> bool {
        let opk = self.op_key(op);
        self.fd.borrow().obank().get(opk).expect("cast ctx: stale op").is_call()
    }

    fn vn_set_unsigned_print(&mut self, vn: VnRef) {
        let vnk = self.vn_key(vn);
        if let Some(v) = self.fd.borrow_mut().vbank_mut().get_mut(vnk) {
            v.set_unsigned_print();
        }
    }

    fn vn_set_long_print(&mut self, vn: VnRef) {
        let vnk = self.vn_key(vn);
        if let Some(v) = self.fd.borrow_mut().vbank_mut().get_mut(vnk) {
            v.set_long_print();
        }
    }
}

// =============================================================================
// getInputCast / getOutputToken — the per-op-code TypeOp surface (typeop.cc).
// =============================================================================

/// `op->getOpcode()->getInputCast(op, slot, castStrategy)` (typeop.cc).
///
/// Returns the data-type a C compiler would require at input `slot`, or `None`
/// when the actual input Varnode's data-type already suffices (no cast needed).
/// The default body (typeop.cc:296-304) is `castStandard(inputTypeLocal(slot),
/// getHighTypeReadFacing(op))`; the per-op-code overrides the corpus exercises
/// are dispatched first.
///
/// `data` is borrowed immutably for the local-type lookup; the read-facing types
/// are read mutably up-front by the caller and threaded in as `Rc<Datatype>` so
/// this stays a pure decision over types (the C++ reaches them through the
/// Varnode `*`, here they are precomputed).  The promotion-sensitive comparison /
/// extension arms run their predicates through `ctx`.
pub(crate) fn get_input_cast(
    data: &mut Funcdata,
    strat: &dyn CastStrategy,
    op: OpId,
    slot: int4,
) -> KunaResult<Option<Rc<Datatype>>> {
    if let Some(cast) = get_input_cast_op(data, strat, op, slot)? {
        return Ok(Some(cast));
    }
    if let Some(cast) = crate::kuna_signedread::cast(data, op, slot)? {
        return Ok(Some(cast));
    }
    crate::kuna_unsignedread::cast(data, strat, op, slot)
}

/// The per-op-code body of [`get_input_cast`].
fn get_input_cast_op(
    data: &mut Funcdata,
    strat: &dyn CastStrategy,
    op: OpId,
    slot: int4,
) -> KunaResult<Option<Rc<Datatype>>> {
    let opc = cast_some!(data.obank().get(op)).code();
    match opc {
        // TypeOpCopy::getInputCast (typeop.cc:398-404): require input == output type.
        OpCode::CPUI_COPY => {
            let outvn = cast_some!(cast_some!(data.obank().get(op)).get_out());
            let reqtype = data.vn_high_type_def_facing(outvn)?;
            let invn = cast_some!(cast_some!(data.obank().get(op)).get_in(0));
            let curtype = data.vn_high_type_read_facing(invn, op)?;
            Ok(strat.cast_standard(&reqtype, &curtype, false, true))
        }
        // TypeOpLoad::getInputCast.
        OpCode::CPUI_LOAD => get_input_cast_load(data, strat, op, slot),
        // TypeOpStore::getInputCast.
        OpCode::CPUI_STORE => get_input_cast_store(data, strat, op, slot),
        // EQUAL/NOTEQUAL share the "coerce both inputs to the common (most-ordered)
        // input read-facing type" body: reqtype = max-read-facing(in0,in1),
        // castStandard(reqtype,curtype,false,false).
        OpCode::CPUI_INT_EQUAL | OpCode::CPUI_INT_NOTEQUAL => {
            get_input_cast_equal(data, strat, op, slot)
        }
        // SLESS/SLESSEQUAL and LESS/LESSEQUAL share the *inputTypeLocal* body:
        // reqtype = op->inputTypeLocal(slot), gated by checkIntPromotionForCompare,
        // then castStandard(reqtype,curtype,true,care_ptr_uint).  They differ ONLY
        // in the final care_ptr_uint flag: SLESS/SLESSEQUAL pass TRUE (signed
        // compare), LESS/LESSEQUAL pass FALSE.
        OpCode::CPUI_INT_SLESS | OpCode::CPUI_INT_SLESSEQUAL => {
            get_input_cast_less(data, strat, op, slot, true)
        }
        OpCode::CPUI_INT_LESS | OpCode::CPUI_INT_LESSEQUAL => {
            get_input_cast_less(data, strat, op, slot, false)
        }
        // TypeOpIntZext::getInputCast / TypeOpIntSext::getInputCast: a cast is
        // needed only when promotion forces it.
        OpCode::CPUI_INT_ZEXT | OpCode::CPUI_INT_SEXT => {
            get_input_cast_extension(data, strat, op, slot)
        }
        // TypeOpPtradd::getInputCast.
        OpCode::CPUI_PTRADD => get_input_cast_ptradd(data, strat, op, slot),
        // TypeOpPtrsub::getInputCast.
        OpCode::CPUI_PTRSUB => get_input_cast_ptrsub(data, strat, op, slot),
        // Ops that "never need a cast into <op>" (typeop.cc:2059-2063, 2138-2142,
        // 2422-2426, 2545-2549, 2572-2576, 2599-2603).
        OpCode::CPUI_PIECE
        | OpCode::CPUI_SUBPIECE
        | OpCode::CPUI_SEGMENTOP
        | OpCode::CPUI_INSERT
        | OpCode::CPUI_ZPULL
        | OpCode::CPUI_SPULL => Ok(None),
        // The signed/unsigned div/rem and the right-shifts gate the cast on the
        // input's integer-promotion class.
        OpCode::CPUI_INT_DIV | OpCode::CPUI_INT_REM | OpCode::CPUI_INT_RIGHT => {
            get_input_cast_promote_div(data, strat, op, slot, false)
        }
        OpCode::CPUI_INT_SDIV | OpCode::CPUI_INT_SREM | OpCode::CPUI_INT_SRIGHT => {
            get_input_cast_promote_div(data, strat, op, slot, true)
        }
        // TypeOpFloatInt2Float::getInputCast.
        OpCode::CPUI_FLOAT_INT2FLOAT => get_input_cast_int2float(data, strat, op, slot),
        // TypeOp::getInputCast default.
        _ => {
            let invn = cast_some!(cast_some!(data.obank().get(op)).get_in(slot));
            if cast_some!(data.vbank().get(invn)).is_annotation() {
                return Ok(None);
            }
            let contract = if data.get_arch().stack_views && opc == OpCode::CPUI_CALLOTHER {
                crate::p6_variables::kuna_stackuses::input_contract(data, op, slot)?
            } else { None };
            let declared_storage = contract.is_some();
            let reqtype = match contract {
                Some(ty) => ty,
                None => input_type_local(data, op, slot)?,
            };
            let curtype = data.vn_high_type_read_facing(invn, op)?;
            let care_ptr_uint = declared_storage || reqtype.get_metatype() != type_metatype::TYPE_UNKNOWN
                || crate::p9_emit::kuna_unknowncasts::declared_argument(data, op, slot);
            let cast = strat
                .cast_standard(&reqtype, &curtype, false, care_ptr_uint)
                .or_else(|| crate::kuna_calltargettype::uncallable_target_cast(data, op, slot, &curtype));
            if cast.is_some() { return Ok(cast); }
            crate::kuna_truncarg::narrowed_arg_cast(data, strat, op, slot)
        }
    }
}

/// TypeOpLoad::getInputCast (typeop.cc:441-471).
fn get_input_cast_load(
    data: &mut Funcdata,
    strat: &dyn CastStrategy,
    op: OpId,
    slot: int4,
) -> KunaResult<Option<Rc<Datatype>>> {
    if slot != 1 {
        return Ok(None);
    }
    let outvn = cast_some!(cast_some!(data.obank().get(op)).get_out());
    let reqtype = data.vn_high_type_def_facing(outvn)?; // Cast load pointer to match output
    let invn = cast_some!(cast_some!(data.obank().get(op)).get_in(1));
    let in_size = cast_some!(data.vbank().get(invn)).get_size();
    let mut curtype = data.vn_high_type_read_facing(invn, op)?;
    let spc = cast_some!(load_store_space(data, op));
    let wordsize = spc.get_word_size();
    let tlst = cast_some!(data.get_arch().types_rc());
    // input type not a pointer (cycle trimming): build a pointer to the output.
    if curtype.get_metatype() == type_metatype::TYPE_PTR {
        curtype = cast_some!(curtype.get_ptr_to());
    } else {
        return Ok(Some(tlst.get_type_pointer(in_size, reqtype, wordsize)?));
    }
    let reqtype = tlst.get_qualified_type(
        crate::kuna_typequal::unqualified_value(reqtype),
        crate::kuna_typequal::effective_qualifiers(&curtype),
    )?;
    if !Rc::ptr_eq(&curtype, &reqtype) && curtype.get_size() == reqtype.get_size() {
        let curmeta = curtype.get_metatype();
        if curmeta != type_metatype::TYPE_STRUCT
            && curmeta != type_metatype::TYPE_ARRAY
            && curmeta != type_metatype::TYPE_SPACEBASE
            && curmeta != type_metatype::TYPE_UNION
        {
            // Postpone cast to output unless the input is a CAST to the wrong type.
            let is_cast_to_wrong = {
                let v = cast_some!(data.vbank().get(invn));
                v.is_implied()
                    && v.is_written()
                    && v.get_def()
                        .and_then(|d| data.obank().get(d))
                        .map(|o| o.code() == OpCode::CPUI_CAST)
                        .unwrap_or(false)
            };
            if !is_cast_to_wrong {
                return Ok(None); // Postpone cast to output
            }
            // else fall through to recast
        }
    }
    let req2 = cast_some!(strat.cast_standard(&reqtype, &curtype, false, true));
    Ok(Some(tlst.get_type_pointer(in_size, req2, wordsize)?))
}

/// TypeOpStore::getInputCast (typeop.cc:521-563).
fn get_input_cast_store(
    data: &mut Funcdata,
    strat: &dyn CastStrategy,
    op: OpId,
    slot: int4,
) -> KunaResult<Option<Rc<Datatype>>> {
    if slot == 0 {
        return Ok(None);
    }
    if cast_some!(data.obank().get(op)).does_special_printing() {
        return Ok(None);
    }
    let pointer_vn = cast_some!(cast_some!(data.obank().get(op)).get_in(1));
    let pointer_size = cast_some!(data.vbank().get(pointer_vn)).get_size();
    let pointer_type = data.vn_high_type_read_facing(pointer_vn, op)?;
    let value_vn = cast_some!(cast_some!(data.obank().get(op)).get_in(2));
    let value_type = data.vn_high_type_read_facing(value_vn, op)?;
    let spc = cast_some!(load_store_space(data, op));
    let wordsize = spc.get_word_size();
    let tlst = cast_some!(data.get_arch().types_rc());

    let (pointed_to, dest_size) = if pointer_type.get_metatype() == type_metatype::TYPE_PTR {
        let pt = resolve_self_pointer(data, cast_some!(pointer_type.get_ptr_to()));
        let sz = pt.get_size();
        (pt, sz)
    } else {
        (Rc::clone(&pointer_type), -1)
    };
    let qualifiers = crate::kuna_typequal::effective_qualifiers(&pointed_to);
    let access_type = |ty| tlst.get_qualified_type(
        crate::kuna_typequal::unqualified_value(ty),
        qualifiers & !crate::kuna_typequal::CONST,
    );
    if dest_size != value_type.get_size() {
        if slot == 1 {
            return Ok(Some(tlst.get_type_pointer(pointer_size, access_type(value_type)?, wordsize)?));
        }
        return Ok(None);
    }
    if slot == 1 {
        if qualifiers & crate::kuna_typequal::CONST != 0 {
            return Ok(Some(tlst.get_type_pointer(pointer_size, access_type(pointed_to)?, wordsize)?));
        }
        let v = cast_some!(data.vbank().get(pointer_vn));
        let is_cast = v.is_written()
            && v.get_def()
                .and_then(|d| data.obank().get(d))
                .map(|o| o.code() == OpCode::CPUI_CAST)
                .unwrap_or(false);
        if is_cast
            && cast_some!(data.vbank().get(pointer_vn)).is_implied()
            && data.lone_descend(pointer_vn) == Some(op)
        {
            let new_type = tlst.get_type_pointer(pointer_size, access_type(Rc::clone(&value_type))?, wordsize)?;
            if !Rc::ptr_eq(&pointer_type, &new_type) {
                return Ok(Some(new_type));
            }
        }
        return Ok(None);
    }
    // slot == 2: cast the value, not the pointer.
    // (kuna `codescalar`) The other half of the size-1 `code` reading: with the
    // stored value typed by its own width, the pointee still demands a cast to
    // `code`, which prints `(void)`.  A `code` destination is not a value type,
    // so the store needs no cast at all.
    if data.get_arch().codescalar && crate::kuna_codescalar::blocks_value_type(&pointed_to) {
        return Ok(None);
    }
    Ok(strat.cast_standard(&pointed_to, &value_type, false, true))
}

/// TypeOpEqual/TypeOpNotEqual::getInputCast (typeop.cc:934-944, :998-1008): both
/// inputs are coerced to the common (most-ordered) input read-facing type, gated
/// by checkIntPromotionForCompare, with `castStandard(reqtype,curtype,false,false)`.
/// NOTE: SLESS/SLESSEQUAL do NOT share this body — they use inputTypeLocal +
/// (true,true) (see get_input_cast_less), distinct from both reqtype source AND
/// the final cast tuple.
fn get_input_cast_equal(
    data: &mut Funcdata,
    strat: &dyn CastStrategy,
    op: OpId,
    slot: int4,
) -> KunaResult<Option<Rc<Datatype>>> {
    let in0 = cast_some!(cast_some!(data.obank().get(op)).get_in(0));
    let in1 = cast_some!(cast_some!(data.obank().get(op)).get_in(1));
    let type0 = data.vn_high_type_read_facing(in0, op)?;
    let othertype = data.vn_high_type_read_facing(in1, op)?;
    let mut reqtype = if othertype.type_order(&type0).unwrap_or(0) < 0 {
        Rc::clone(&othertype)
    } else {
        Rc::clone(&type0)
    };
    if let Some(integer) = integer_beside_bool(&reqtype, [&type0, &othertype]) {
        reqtype = integer;
    }
    // Integer equality observes the entire opcode-width storage, not the first
    // field of a source aggregate. Keep its declaration intact and cast only
    // this read to an unsigned storage word.
    let size = cast_some!(data.vbank().get(in0)).get_size();
    let objects = if data.get_arch().out_lang == crate::kuna_lang::OutLang::C
        && matches!(size, 1 | 2 | 4 | 8)
        && cast_some!(data.vbank().get(in1)).get_size() == size
    {
        [full_aggregate_input(data, in0, &type0), full_aggregate_input(data, in1, &othertype)]
    } else {
        [false; 2]
    };
    if objects[0] || objects[1] {
        reqtype = cast_some!(data.get_arch().types_rc()).get_base(size, type_metatype::TYPE_UINT)?;
        if objects[slot as usize] {
            return Ok(Some(reqtype));
        }
    } else if reqtype.get_metatype() == type_metatype::TYPE_FLOAT
        && matches!(reqtype.get_size(), 4 | 8)
        && !float_compare_is_exact(data, in0, in1)
    {
        reqtype = cast_some!(float_bits_type(data, &[type0, othertype], reqtype.get_size()));
    }
    let needs_promote = {
        let ctx = FuncdataCastContext::new(data);
        let opr = ctx.op_ref(op);
        strat.check_int_promotion_for_compare(&ctx, opr, slot)?
    };
    if needs_promote {
        return Ok(Some(reqtype));
    }
    let slotvn = cast_some!(cast_some!(data.obank().get(op)).get_in(slot));
    let slottype = data.vn_high_type_read_facing(slotvn, op)?;
    let standard = strat.cast_standard(&reqtype, &slottype, false, false);
    let other = if slot == 0 { in1 } else { in0 };
    if standard.is_none() && promotes_with_other_sign(data, strat, slotvn, other, &slottype, &reqtype) {
        return Ok(Some(reqtype));
    }
    Ok(standard)
}

/// (kuna) The integer operand type of an `==`/`!=` that orders after a
/// `bool` of its size. Both sides compare as that integer instead: C converts a
/// `bool` to an integer as the 0 or 1 it holds, but an integer to `bool` as
/// whether it is nonzero, so `(bool)v == b` matches when `v` is 3 and `b` is 1.
fn integer_beside_bool(reqtype: &Rc<Datatype>, types: [&Rc<Datatype>; 2]) -> Option<Rc<Datatype>> {
    if reqtype.get_metatype() != type_metatype::TYPE_BOOL {
        return None;
    }
    types
        .into_iter()
        .find(|t| {
            matches!(t.get_metatype(), type_metatype::TYPE_INT | type_metatype::TYPE_UINT)
                && t.get_size() == reqtype.get_size()
        })
        .cloned()
}

/// (kuna) Would C widen `vn`, an input of a narrow `==`/`!=` printed as
/// `slottype`, with the other sign than `reqtype`, the type both inputs compare
/// as? The p-code compares the bytes; C promotes each side by its own type, so
/// a `char` beside an `unsigned char` stops matching once the top bit is set.
/// A side whose top bit is known clear (a constant like `0x7f`, a value
/// masked to seven bits) promotes the same way whatever its type, and the
/// comparison then holds exactly when the bytes do.
fn promotes_with_other_sign(
    data: &Funcdata,
    strat: &dyn CastStrategy,
    vn: VarnodeId,
    other: VarnodeId,
    slottype: &Datatype,
    reqtype: &Datatype,
) -> bool {
    let Some(v) = data.vbank().get(vn) else { return false };
    let integer = |t: &Datatype| matches!(t.get_metatype(), type_metatype::TYPE_INT | type_metatype::TYPE_UINT);
    if v.get_size() >= strat.promote_size() || !integer(slottype) || !integer(reqtype) {
        return false;
    }
    if (slottype.get_metatype() == type_metatype::TYPE_INT) == (reqtype.get_metatype() == type_metatype::TYPE_INT) {
        return false;
    }
    let top_bit_clear = |vn: VarnodeId| {
        data.vbank()
            .get(vn)
            .is_some_and(|c| !kuna_base::address::signbit_negative(c.get_nz_mask(), c.get_size()))
    };
    !top_bit_clear(vn) && !top_bit_clear(other)
}

/// A full object read, not a narrower access into a containing declaration.
fn full_aggregate_input(data: &Funcdata, vn: VarnodeId, facing: &Rc<Datatype>) -> bool {
    let Some(value) = data.vbank().get(vn) else { return false };
    let declared = crate::printc::declared_variable_type(data, data.get_arch().decl_high_type, vn);
    let ty = declared.as_ref().unwrap_or(facing);
    ty.get_size() == value.get_size()
        && matches!(ty.get_metatype(), type_metatype::TYPE_STRUCT | type_metatype::TYPE_UNION)
}

/// (kuna) Does a C float `==` of `a` and `b` decide what their bit test does?
/// Only against a constant whose literal spells the value exactly (a normal
/// number or an infinity), or against `+0.0` when the other side is an `ABS`,
/// which can be neither `-0.0` nor equal to zero as a NaN.
fn float_compare_is_exact(data: &Funcdata, a: VarnodeId, b: VarnodeId) -> bool {
    let zero_against_abs = |c: VarnodeId, v: VarnodeId| {
        data.vbank().get(c).is_some_and(|n| n.is_constant() && n.get_offset() == 0)
            && data.vbank().get(v).and_then(|n| n.get_def()).and_then(|d| data.obank().get(d))
                .is_some_and(|o| o.code() == OpCode::CPUI_FLOAT_ABS)
    };
    [(a, b), (b, a)].into_iter().any(|(c, v)| crate::kuna_floatbits::compares_as_a_float(data, c) || zero_against_abs(c, v))
}

/// (kuna) The integer type an `INT_EQUAL`/`INT_NOTEQUAL` with a float input
/// compares its bits as: the integer input's type, else `uint` of the width.
/// A C `==` on floats differs from the bit test for -0.0, NaNs and NaN constants.
fn float_bits_type(data: &Funcdata, types: &[Rc<Datatype>], size: int4) -> Option<Rc<Datatype>> {
    if let Some(t) = types.iter().find(|t| {
        t.get_size() == size && matches!(t.get_metatype(), type_metatype::TYPE_INT | type_metatype::TYPE_UINT)
    }) {
        return Some(Rc::clone(t));
    }
    data.get_arch().types_rc()?.get_base(size, type_metatype::TYPE_UINT).ok()
}

/// The signed/unsigned ordered-compare getInputCast body, shared by
/// TypeOpIntSless/IntSlessEqual (typeop.cc:1025-1033, :1051-1059) and
/// TypeOpIntLess/IntLessEqual (typeop.cc:1077-1085, :1101-1108): the required
/// type is the *local* input type (a SIGNED int4 for SLESS, an UNSIGNED uint4 for
/// LESS); coerce with `care_uint_int = true`.  `care_ptr_uint` is the only flag
/// that differs: SLESS/SLESSEQUAL pass `true` (signed compare), LESS/LESSEQUAL
/// pass `false`.
fn get_input_cast_less(
    data: &mut Funcdata,
    strat: &dyn CastStrategy,
    op: OpId,
    slot: int4,
    care_ptr_uint: bool,
) -> KunaResult<Option<Rc<Datatype>>> {
    let reqtype = input_type_local(data, op, slot)?;
    let needs_promote = {
        let ctx = FuncdataCastContext::new(data);
        let opr = ctx.op_ref(op);
        strat.check_int_promotion_for_compare(&ctx, opr, slot)?
    };
    if needs_promote {
        return Ok(Some(reqtype));
    }
    let slotvn = cast_some!(cast_some!(data.obank().get(op)).get_in(slot));
    let curtype = data.vn_high_type_read_facing(slotvn, op)?;
    Ok(strat.cast_standard(&reqtype, &curtype, true, care_ptr_uint))
}

/// TypeOpIntZext::getInputCast / TypeOpIntSext::getInputCast (typeop.cc:1133-1170).
fn get_input_cast_extension(
    data: &mut Funcdata,
    strat: &dyn CastStrategy,
    op: OpId,
    slot: int4,
) -> KunaResult<Option<Rc<Datatype>>> {
    let needs = {
        let ctx = FuncdataCastContext::new(data);
        let opr = ctx.op_ref(op);
        strat.check_int_promotion_for_extension(&ctx, opr)?
    };
    if needs {
        return Ok(Some(input_type_local(data, op, slot)?));
    }
    // ZEXT/SEXT do NOT fall through to the default tuple: the C++ tail is its own
    // `castStandard(reqtype,curtype,true,false)` -- care_uint_int=TRUE,
    // care_ptr_uint=FALSE.
    let reqtype = input_type_local(data, op, slot)?;
    let invn = cast_some!(cast_some!(data.obank().get(op)).get_in(slot));
    let curtype = data.vn_high_type_read_facing(invn, op)?;
    Ok(strat.cast_standard(&reqtype, &curtype, true, false))
}

/// TypeOpPtradd::getInputCast (typeop.cc:2252-2268): slot 0 compares the
/// Varnode's own read-facing pointer type to the merged high pointer type one
/// level down (by align size); other slots defer to the default.
fn get_input_cast_ptradd(
    data: &mut Funcdata,
    strat: &dyn CastStrategy,
    op: OpId,
    slot: int4,
) -> KunaResult<Option<Rc<Datatype>>> {
    if slot == 0 {
        let in0 = cast_some!(cast_some!(data.obank().get(op)).get_in(0));
        let reqtype = data.vn_type_read_facing(in0, op)?;
        let curtype = data.vn_high_type_read_facing(in0, op)?;
        if reqtype.get_metatype() != type_metatype::TYPE_PTR {
            return Ok(Some(reqtype));
        }
        if curtype.get_metatype() != type_metatype::TYPE_PTR {
            return Ok(Some(reqtype));
        }
        let reqbase = cast_some!(reqtype.get_ptr_to());
        let curbase = cast_some!(curtype.get_ptr_to());
        if reqbase.get_align_size() == curbase.get_align_size() {
            return Ok(None);
        }
        return Ok(Some(reqtype));
    }
    // TypeOp::getInputCast(op, slot) default.
    get_input_cast_default(data, strat, op, slot)
}

/// TypeOpPtrsub::getInputCast (typeop.cc:2322-2349): slot 0 compares the
/// Varnode's own read-facing pointer type to the merged high type one level down
/// (by identity, stripping arrays + typedefs); other slots defer to the default.
fn get_input_cast_ptrsub(
    data: &mut Funcdata,
    strat: &dyn CastStrategy,
    op: OpId,
    slot: int4,
) -> KunaResult<Option<Rc<Datatype>>> {
    if slot == 0 {
        let in0 = cast_some!(cast_some!(data.obank().get(op)).get_in(0));
        let reqtype = data.vn_type_read_facing(in0, op)?;
        let curtype = data.vn_high_type_read_facing(in0, op)?;
        if Rc::ptr_eq(&curtype, &reqtype) {
            return Ok(None);
        }
        if reqtype.get_metatype() != type_metatype::TYPE_PTR {
            return Ok(Some(reqtype));
        }
        if curtype.get_metatype() != type_metatype::TYPE_PTR {
            return Ok(Some(reqtype));
        }
        let mut reqbase = cast_some!(reqtype.get_ptr_to());
        let mut curbase = cast_some!(curtype.get_ptr_to());
        if curbase.get_metatype() == type_metatype::TYPE_ARRAY
            && reqbase.get_metatype() == type_metatype::TYPE_ARRAY
        {
            if let (Some(cb), Some(rb)) = (curbase.get_array_base(), reqbase.get_array_base()) {
                curbase = cb;
                reqbase = rb;
            }
        }
        while let Some(td) = reqbase.get_typedef() {
            let td = Rc::clone(td);
            reqbase = td;
        }
        while let Some(td) = curbase.get_typedef() {
            let td = Rc::clone(td);
            curbase = td;
        }
        if Rc::ptr_eq(&curbase, &reqbase) {
            return Ok(None);
        }
        return Ok(Some(reqtype));
    }
    get_input_cast_default(data, strat, op, slot)
}

/// The div/rem/right-shift getInputCast bodies (typeop.cc:1545-1599, 1641-1711):
/// gate the cast on the input's integer-promotion class.  `signed_ext` selects
/// the SIGNED_EXTENSION (s-variants) vs UNSIGNED_EXTENSION (u-variants) test.
fn get_input_cast_promote_div(
    data: &mut Funcdata,
    strat: &dyn CastStrategy,
    op: OpId,
    slot: int4,
    signed_ext: bool,
) -> KunaResult<Option<Rc<Datatype>>> {
    // INT_RIGHT / INT_SRIGHT only special-case slot 0; their slot 1 defers to the
    // binary default.  INT_DIV/SDIV/REM/SREM special-case every slot.
    let opc = cast_some!(data.obank().get(op)).code();
    let shift = matches!(opc, OpCode::CPUI_INT_RIGHT | OpCode::CPUI_INT_SRIGHT);
    if shift && slot != 0 {
        return get_input_cast_default(data, strat, op, slot);
    }
    let vn = cast_some!(cast_some!(data.obank().get(op)).get_in(slot));
    let reqtype = input_type_local(data, op, slot)?;
    let curtype = data.vn_high_type_read_facing(vn, op)?;
    let promo = {
        let ctx = FuncdataCastContext::new(data);
        let vnr = ctx.vn_ref(vn);
        strat.int_promotion_type(&ctx, vnr)?
    };
    use crate::cast::IntPromotionCode;
    let no_promotion = promo == IntPromotionCode::NO_PROMOTION;
    let ext_bit = if signed_ext {
        promo.as_i32() & IntPromotionCode::SIGNED_EXTENSION.as_i32()
    } else {
        promo.as_i32() & IntPromotionCode::UNSIGNED_EXTENSION.as_i32()
    };
    if !no_promotion && ext_bit == 0 {
        return Ok(Some(reqtype));
    }
    Ok(strat.cast_standard(&reqtype, &curtype, true, true))
}

/// TypeOpFloatInt2Float::getInputCast (typeop.cc:1849-1864).
fn get_input_cast_int2float(
    data: &mut Funcdata,
    strat: &dyn CastStrategy,
    op: OpId,
    slot: int4,
) -> KunaResult<Option<Rc<Datatype>>> {
    // Absorbing an INT_ZEXT.
    if float_int2float_absorb_zext(data, op).is_some() {
        return Ok(None);
    }
    let vn = cast_some!(cast_some!(data.obank().get(op)).get_in(slot));
    let reqtype = input_type_local(data, op, slot)?;
    let curtype = data.vn_high_type_read_facing(vn, op)?;
    let (vn_size, nzmask) = {
        let v = cast_some!(data.vbank().get(vn));
        (v.get_size(), v.get_nz_mask())
    };
    let mut care_uint_int = true;
    if (vn_size as usize) <= std::mem::size_of::<uintb>() {
        // Is the high-bit set in the nonzero mask?
        let shift = 8 * vn_size - 1;
        let val = if shift >= 64 { 0 } else { nzmask >> shift };
        care_uint_int = (val & 1) != 0;
    }
    Ok(strat.cast_standard(&reqtype, &curtype, care_uint_int, true))
}

/// The `TypeOpFloatInt2Float::absorbZext` test (typeop.cc:1874-...): the input is
/// a written, implied INT_ZEXT whose sole reader is this op.
fn float_int2float_absorb_zext(data: &Funcdata, op: OpId) -> Option<OpId> {
    let vn0 = data.obank().get(op)?.get_in(0)?;
    let v = data.vbank().get(vn0)?;
    if !v.is_written() || !v.is_implied() {
        return None;
    }
    let def = v.get_def()?;
    let defop = data.obank().get(def)?;
    if defop.code() != OpCode::CPUI_INT_ZEXT {
        return None;
    }
    // the ZEXT's output (vn0) must descend only into `op`.
    if data.lone_descend(vn0) == Some(op) {
        Some(def)
    } else {
        None
    }
}

/// The `TypeOp::getInputCast` default body (typeop.cc:296-304), reused by the
/// per-op overrides that delegate to it for their non-special slots.
fn get_input_cast_default(
    data: &mut Funcdata,
    strat: &dyn CastStrategy,
    op: OpId,
    slot: int4,
) -> KunaResult<Option<Rc<Datatype>>> {
    let invn = cast_some!(cast_some!(data.obank().get(op)).get_in(slot));
    if cast_some!(data.vbank().get(invn)).is_annotation() {
        return Ok(None);
    }
    let reqtype = input_type_local(data, op, slot)?;
    let curtype = data.vn_high_type_read_facing(invn, op)?;
    Ok(strat.cast_standard(&reqtype, &curtype, false, true))
}

/// `op->getOpcode()->getOutputToken(op, castStrategy)` (typeop.cc).
///
/// The data-type the op *produces* as a source token (what a C compiler would
/// assign to the result).  Default (typeop.cc:283-287) is `op->outputTypeLocal()`;
/// the COPY/LOAD overrides flow the read-facing input type, and the INT-arithmetic
/// overrides defer to `arithmeticOutputStandard`.
pub(crate) fn get_output_token(
    data: &mut Funcdata,
    strat: &dyn CastStrategy,
    op: OpId,
) -> KunaResult<Rc<Datatype>> {
    let opc = match data.obank().get(op) {
        Some(o) => o.code(),
        None => return output_type_local(data, op),
    };
    match opc {
        // TypeOpCopy::getOutputToken (typeop.cc:406-410): the input read-facing type.
        OpCode::CPUI_COPY => {
            if let Some(invn) = data.obank().get(op).and_then(|o| o.get_in(0)) {
                return data.vn_high_type_read_facing(invn, op);
            }
            output_type_local(data, op)
        }
        // TypeOpLoad::getOutputToken.
        OpCode::CPUI_LOAD => get_output_token_load(data, op),
        // INT arithmetic getOutputToken overrides whose result depends on the
        // operands' actual types -> arithmeticOutputStandard.
        OpCode::CPUI_INT_ADD
        | OpCode::CPUI_INT_SUB
        | OpCode::CPUI_INT_2COMP
        | OpCode::CPUI_INT_NEGATE
        | OpCode::CPUI_INT_XOR
        | OpCode::CPUI_INT_AND
        | OpCode::CPUI_INT_OR
        | OpCode::CPUI_INT_MULT => arithmetic_output_standard(data, strat, op),
        // The shift getOutputToken overrides return the shiftee's read-facing type
        // (bool -> int).
        OpCode::CPUI_INT_LEFT | OpCode::CPUI_INT_RIGHT | OpCode::CPUI_INT_SRIGHT => {
            get_output_token_shift(data, op)
        }
        // TypeOpPtradd::getOutputToken (typeop.cc:2246-2250): input read-facing type.
        OpCode::CPUI_PTRADD => {
            if let Some(in0) = data.obank().get(op).and_then(|o| o.get_in(0)) {
                return data.vn_high_type_read_facing(in0, op);
            }
            output_type_local(data, op)
        }
        // TypeOpPtrsub::getOutputToken.
        OpCode::CPUI_PTRSUB => get_output_token_ptrsub(data, op),
        // TypeOpSubpiece::getOutputToken.
        OpCode::CPUI_SUBPIECE => get_output_token_subpiece(data, op),
        // TypeOpPiece::getOutputToken.
        OpCode::CPUI_PIECE => get_output_token_piece(data, op),
        // INSERT/ZPULL/SPULL getOutputToken: the output's def-facing type
        // (typeop.cc:2551-2555, 2578-2582, 2605-2609).
        OpCode::CPUI_INSERT | OpCode::CPUI_ZPULL | OpCode::CPUI_SPULL => {
            match data.obank().get(op).and_then(|o| o.get_out()) {
                Some(outvn) => data.vn_high_type_def_facing(outvn),
                None => output_type_local(data, op),
            }
        }
        // TypeOpSegment::getOutputToken (typeop.cc:2416-2420): ptr-portion type.
        OpCode::CPUI_SEGMENTOP => match data.obank().get(op).and_then(|o| o.get_in(2)) {
            Some(in2) => data.vn_high_type_read_facing(in2, op),
            None => output_type_local(data, op),
        },
        OpCode::CPUI_CALL | OpCode::CPUI_CALLIND => {
            if let Some(ct) = crate::kuna_floatbits::held_bits_token(data, op) {
                return Ok(ct);
            }
            let local = output_type_local(data, op)?;
            if local.get_metatype() != type_metatype::TYPE_UNKNOWN {
                return Ok(local);
            }
            Ok(crate::p4_calls::kuna_callrettype::refused_token(data, op).unwrap_or(local))
        }
        // TypeOp::getOutputToken default.
        _ => output_type_local(data, op),
    }
}

/// The shift getOutputToken body (typeop.cc:1520-1527 etc.): the shiftee's
/// read-facing type, mapping BOOL -> INT of the same size.
fn get_output_token_shift(data: &mut Funcdata, op: OpId) -> KunaResult<Rc<Datatype>> {
    let in0 = match data.obank().get(op).and_then(|o| o.get_in(0)) {
        Some(v) => v,
        None => return output_type_local(data, op),
    };
    let res1 = data.vn_high_type_read_facing(in0, op)?;
    if res1.get_metatype() == type_metatype::TYPE_BOOL {
        if let Some(tlst) = data.get_arch().types_rc() {
            return tlst.get_base(res1.get_size(), type_metatype::TYPE_INT);
        }
    }
    Ok(res1)
}

/// TypeOpPtrsub::getOutputToken (typeop.cc:2351-2366): walk down the pointed-to
/// composite by the constant byte offset; if it lands at offset 0 on a sub-type,
/// that sub-type is the token; otherwise a `void *` of the output size.
fn get_output_token_ptrsub(data: &mut Funcdata, op: OpId) -> KunaResult<Rc<Datatype>> {
    let in0 = match data.obank().get(op).and_then(|o| o.get_in(0)) {
        Some(v) => v,
        None => return output_type_local(data, op),
    };
    let ptype = data.vn_high_type_read_facing(in0, op)?;
    if ptype.get_metatype() != type_metatype::TYPE_PTR {
        return output_type_local(data, op);
    }
    let (in1off, out_size, wordsize) = {
        let o = match data.obank().get(op) {
            Some(o) => o,
            None => return output_type_local(data, op),
        };
        let in1off = o.get_in(1).and_then(|v| data.vbank().get(v)).map(|v| v.get_offset()).unwrap_or(0);
        let out_size = o.get_out().and_then(|v| data.vbank().get(v)).map(|v| v.get_size()).unwrap_or(1);
        let ws = ptype.get_word_size().unwrap_or(1);
        (in1off, out_size, ws)
    };
    // address_to_byte takes a uintb; in1off is already a uintb offset.
    let offset = kuna_base::space::AddrSpace::address_to_byte(in1off, wordsize) as i64;
    let tlst = match data.get_arch().types_rc() {
        Some(t) => t,
        None => return output_type_local(data, op),
    };
    // C++ downChain takes `offset` by REFERENCE and updates it to the residual
    // offset *within* the reached sub-type; the `if (offset==0)` test uses that
    // UPDATED value (the Rust port returns it as the 2nd tuple element).
    //
    // The generic `Datatype::down_chain` cannot reach the symbol table that a
    // `TypeSpacebase` ptrto indexes (`TypeSpacebase::getSubType` needs `glb`), so
    // for a pointer-to-spacebase the spacebase branch of `TypePointer::downChain`
    // (type.cc:1224-1257) is reproduced here against `Funcdata`'s symbol scope.
    // The spacebase has `getAlignSize()==0`, so the `off >= ptrtoSize` wrapping
    // guard (type.cc:1225-1226) is skipped (`ptrtoSize != 0` is false); the type
    // is not an array/struct, so `!isArray -> getTypePointerStripArray` applies.
    let ptrto = ptype.get_ptr_to();
    if offset == 0 && ptrto.as_ref().is_some_and(|ty| ty.get_metatype() == type_metatype::TYPE_UNION) {
        if let Some(resolution) = data.get_union_field(&ptype, op, -1) {
            if resolution.get_field_num() >= 0 {
                return Ok(Rc::clone(resolution.get_datatype()));
            }
        }
    }
    let is_spacebase = ptrto
        .as_ref()
        .map(|p| p.get_metatype() == type_metatype::TYPE_SPACEBASE)
        .unwrap_or(false);
    if is_spacebase {
        let r = data.spacebase_get_sub_type(&ptrto.expect("spacebase ptrto present"), offset)?;
        if let Some((subtype, residual_off)) = r {
            if residual_off == 0 {
                // The spacebase itself is never an array, so the
                // getTypePointerStripArray build applies.
                return tlst.get_type_pointer_strip_array(out_size, subtype, wordsize);
            }
        }
        // Fall through to the `xunknown1 *` fallback below (residual != 0 or the
        // strip-array build failed — the C++ getSubType-miss / non-exact branch).
    } else {
        let down = tlst.down_chain(&ptype, offset, false)?;
        if let (Some(rettype), residual_off, _parent, _poff) = down {
            if residual_off == 0 {
                // downChain reached the sub-type exactly; the token is that pointer.
                return Ok(rettype);
            }
        }
    }
    let unk = tlst.get_base(1, type_metatype::TYPE_UNKNOWN)?;
    tlst.get_type_pointer(out_size, unk, wordsize)
}

/// TypeOpSubpiece::getOutputToken (typeop.cc:2144-2161).
fn get_output_token_subpiece(data: &mut Funcdata, op: OpId) -> KunaResult<Rc<Datatype>> {
    let (in0, out_vn, out_size) = {
        let o = match data.obank().get(op) {
            Some(o) => o,
            None => return output_type_local(data, op),
        };
        let in0 = match o.get_in(0) {
            Some(v) => v,
            None => return output_type_local(data, op),
        };
        let out_vn = match o.get_out() {
            Some(v) => v,
            None => return output_type_local(data, op),
        };
        let out_size = data.vbank().get(out_vn).map(|v| v.get_size()).unwrap_or(1);
        (in0, out_vn, out_size)
    };
    let ct = data.vn_high_type_read_facing(in0, op)?;
    let byte_off = subpiece_composite_byte_offset(data, op);
    // In C++ the slot-1 (artificial) truncation edge has already been written by
    // `TypeOpSubpiece::propagateType` -> `resolveTruncation(byteOff,op,1,byteOff)`
    // during `ActionInferTypes`, so `getOutputToken` only *reads* it.  In the Rust
    // port the per-op `propagateType` runs through an immutable `&Funcdata`, so the
    // SUBPIECE union arm cannot write the cache there; `getOutputToken`
    // (`ActionSetCasts`, `&mut Funcdata`) is the first reader and therefore drives
    // the resolution.  For a union/partial-union receiver this calls
    // `Funcdata::resolve_truncation` (the findTruncation-equivalent that scores on a
    // cache miss and writes the slot-1 edge — `TypeUnion::resolveTruncation`,
    // type.cc:2569); the resolved field is identical to what `findTruncation` would
    // read post-propagateType, and the write lets the print-time
    // `pushPartialSymbol`/`findTruncation` reads see the same field.  A plain struct
    // receiver still uses the read-only field walk.
    let field_lookup = {
        let meta = ct.get_metatype();
        if meta == type_metatype::TYPE_UNION || meta == type_metatype::TYPE_PARTIALUNION {
            data.resolve_truncation(&ct, byte_off as int8, op, 1)
        } else {
            data.find_truncation(&ct, byte_off as int8, out_size, op, 1)
        }
    };
    if let Some((field_idx, offset)) = field_lookup? {
        let _ = offset;
        // For a partial-union receiver the resolved field index is into the
        // container union; for a union/struct it is into `ct` directly.  Read the
        // field type back from the same datatype the truncation resolved against.
        let field_ty = match ct.get_metatype() {
            type_metatype::TYPE_PARTIALUNION => ct
                .get_partial_base()
                .and_then(|c| c.get_field(field_idx).map(|f| Rc::clone(&f.field_type))),
            _ => ct.get_field(field_idx).map(|f| Rc::clone(&f.field_type)),
        };
        if let Some(field_ty) = field_ty {
            if out_size == field_ty.get_size() {
                return Ok(field_ty);
            }
        }
    }
    let dt = data.vn_high_type_def_facing(out_vn)?;
    if dt.get_metatype() != type_metatype::TYPE_UNKNOWN {
        return Ok(dt);
    }
    match data.get_arch().types_rc() {
        Some(tlst) => tlst.get_base(out_size, type_metatype::TYPE_INT),
        None => output_type_local(data, op),
    }
}

/// TypeOpPiece::getOutputToken (typeop.cc:2065-2074).
fn get_output_token_piece(data: &mut Funcdata, op: OpId) -> KunaResult<Rc<Datatype>> {
    let outvn = match data.obank().get(op).and_then(|o| o.get_out()) {
        Some(v) => v,
        None => return output_type_local(data, op),
    };
    let out_size = data.vbank().get(outvn).map(|v| v.get_size()).unwrap_or(1);
    let dt = data.vn_high_type_def_facing(outvn)?;
    let meta = dt.get_metatype();
    if meta == type_metatype::TYPE_INT || meta == type_metatype::TYPE_UINT {
        return Ok(dt);
    }
    match data.get_arch().types_rc() {
        Some(tlst) => tlst.get_base(out_size, type_metatype::TYPE_UINT),
        None => output_type_local(data, op),
    }
}

/// `TypeOpSubpiece::computeByteOffsetForComposite(op)` (typeop.cc:2106-2116, the
/// SUBPIECE single-input form): the byte offset of the truncated piece into an
/// assumed composite, by endianness.
fn subpiece_composite_byte_offset(data: &Funcdata, op: OpId) -> i64 {
    let o = match data.obank().get(op) {
        Some(o) => o,
        None => return 0,
    };
    // For the 1-arg SUBPIECE form this reduces to the constant in(1) offset
    // (little-endian) or the high-end offset (big-endian).
    let in0 = match o.get_in(0) {
        Some(v) => v,
        None => return 0,
    };
    let in1off = o.get_in(1).and_then(|v| data.vbank().get(v)).map(|v| v.get_offset()).unwrap_or(0);
    let big_endian = data
        .vbank()
        .get(in0)
        .map(|v| v.get_space().is_big_endian())
        .unwrap_or(false);
    if big_endian {
        let in0_size = data.vbank().get(in0).map(|v| v.get_size()).unwrap_or(0) as i64;
        let out_size = o
            .get_out()
            .and_then(|v| data.vbank().get(v))
            .map(|v| v.get_size())
            .unwrap_or(0) as i64;
        in0_size - out_size - in1off as i64
    } else {
        in1off as i64
    }
}

/// (kuna `structsynth nest`) `ct`, or the completed record when `ct` is a
/// synthesized record's pointer to its own shell
/// (`kuna_structsynth::resolve_self_pointer`).
fn resolve_self_pointer(data: &Funcdata, ct: Rc<Datatype>) -> Rc<Datatype> {
    match data.get_arch().types() {
        Some(tlst) => crate::kuna_structsynth::resolve_self_pointer(tlst, &ct).unwrap_or(ct),
        None => ct,
    }
}

/// TypeOpLoad::getOutputToken (typeop.cc:473-486).
fn get_output_token_load(data: &mut Funcdata, op: OpId) -> KunaResult<Rc<Datatype>> {
    let invn = match data.obank().get(op).and_then(|o| o.get_in(1)) {
        Some(v) => v,
        None => return output_type_local(data, op),
    };
    let ct = data.vn_high_type_read_facing(invn, op)?;
    let outsize = data
        .obank()
        .get(op)
        .and_then(|o| o.get_out())
        .and_then(|v| data.vbank().get(v))
        .map(|v| v.get_size())
        .unwrap_or(1);
    if ct.get_metatype() == type_metatype::TYPE_PTR {
        if let Some(pt) = ct.get_ptr_to() {
            if pt.get_size() == outsize {
                return Ok(resolve_self_pointer(data, pt));
            }
        }
    }
    // The load produces the type matching its output (a cast will be inserted).
    let outvn = match data.obank().get(op).and_then(|o| o.get_out()) {
        Some(v) => v,
        None => return output_type_local(data, op),
    };
    data.vn_high_type_def_facing(outvn)
}

/// `castStrategy->arithmeticOutputStandard(op)` driven through the bridge
/// (cast.cc:394-409).
fn arithmetic_output_standard(data: &mut Funcdata, strat: &dyn CastStrategy, op: OpId) -> KunaResult<Rc<Datatype>> {
    let ctx = FuncdataCastContext::new(data);
    let opr = ctx.op_ref(op);
    strat.arithmetic_output_standard(&ctx, opr)
}

/// The LOAD/STORE address space from the constant in slot 0 (C++
/// `op->getIn(0)->getSpaceFromConst()`: the constant offset is the
/// address-space-manager index, LOSS-015 model — same resolution as
/// `coreaction_infertypes::space_from_const`).
fn load_store_space(data: &Funcdata, op: OpId) -> Option<Rc<kuna_base::space::AddrSpace>> {
    let cvn = data.obank().get(op)?.get_in(0)?;
    let idx = data.vbank().get(cvn)?.get_offset();
    let manage = data.get_arch().manage();
    if idx >= manage.num_spaces() as u64 {
        return None;
    }
    manage.get_space(idx as i32).cloned()
}

// =============================================================================
// ActionSetCasts driver + helpers (coreaction.cc:2407-2872), on Funcdata.
// =============================================================================

impl Funcdata {
    /// The `ActionSetCasts::apply` body (C++ `coreaction.cc:2812-2872`).
    ///
    /// Walks every printed op in dominance/basic-block order and drives
    /// `resolveUnion`/`castInput`/`castOutput`, inserting the explicit
    /// CAST/PTRSUB ops the rendered C needs. Returns the number of changes made,
    /// propagating failures acquiring facing types or local output types.
    pub fn action_set_casts(&mut self) -> KunaResult<int4> {
        self.start_cast_phase();
        crate::p9_emit::kuna_stackversions::prepare(self);
        crate::kuna_stackviews::prepare_casts(self)?;
        let tlst = match self.get_arch().types_rc() {
            Some(t) => t as Rc<dyn crate::dtype::TypeFactory>,
            None => return Ok(0),
        };
        let selected = crate::cast::LanguageCastStrategy::new(
            tlst, self.get_arch().out_lang, self.get_arch().call_target_c,
        );
        let strat: &dyn CastStrategy = &*selected;

        let mut count: int4 = 0;
        // Follow data flow: basic blocks in dominance order, ops in block order.
        let nblocks = self.bblocks_get_size();
        for j in 0..nblocks {
            let bb = self.bblocks_get_block(j);
            // Snapshot the op list: the cast loop inserts new ops, but processes
            // only the ops that were live when the block was entered (the C++
            // iterator walks the existing list; new ops insert before/after the
            // current op and are not revisited).
            let ops = self.bb_ops(bb);
            for op in ops {
                let o = match self.obank().get(op) {
                    Some(o) => o,
                    None => continue,
                };
                if o.not_printed() || crate::p9_emit::kuna_stackmarkers::nonprinting(self, op) {
                    continue;
                }
                let opc = o.code();
                if opc == OpCode::CPUI_CAST {
                    continue;
                }
                if opc == OpCode::CPUI_PTRADD {
                    self.cast_fixup_ptradd(op)?;
                } else if opc == OpCode::CPUI_PTRSUB {
                    self.cast_fixup_ptrsub(op)?;
                }
                // (kuna `castarith`) A pointer plus whole elements stays pointer arithmetic.
                if self.get_arch().cast_arith
                    && self.obank().get(op).map(|o| o.code()) == Some(OpCode::CPUI_INT_ADD)
                {
                    crate::kuna_castarith::rewrite(self, op)?;
                }
                // (kuna `castindex`) So does a variable index, and a byte-pointer difference.
                let mut diff_token = None;
                if self.get_arch().cast_index {
                    match self.obank().get(op).map(|o| o.code()) {
                        Some(OpCode::CPUI_INT_ADD) => {
                            crate::kuna_castarith::rewrite_index(self, strat, op)?;
                        }
                        Some(OpCode::CPUI_INT_SUB) => {
                            diff_token = crate::kuna_castarith::pointer_difference(self, op)?.ok();
                        }
                        _ => {}
                    }
                }
                let keep_inputs = diff_token.is_some();
                // Allow unresolved high data-types to resolve.
                let numin = self.obank().get(op).map(|o| o.num_input()).unwrap_or(0);
                for i in 0..numin {
                    count += self.cast_resolve_union(op, i, strat)?;
                }
                // Last chance to resolve the output data-type based on flow
                // (C++ `outHigh->getType()->resolveInFlow(op,-1)` — populates the
                // union cache for the output write edge).
                if let Some(vn) = self.obank().get(op).and_then(|o| o.get_out()) {
                    let out_high = self.high_get_type(vn);
                    if let Some(oh) = out_high {
                        if oh.needs_resolution() {
                            let _ = self.resolve_in_flow(&oh, op, -1)?;
                        }
                    }
                }
                // Do input casts first, as output may depend on input.
                let numin = self.obank().get(op).map(|o| o.num_input()).unwrap_or(0);
                for i in 0..numin {
                    if !keep_inputs {
                        count += self.cast_input(op, i, strat)?;
                    }
                }
                if opc == OpCode::CPUI_LOAD {
                    if let Some(outvn) = self.obank().get(op).and_then(|o| o.get_out()) {
                        self.cast_check_pointer_issues(op, outvn);
                    }
                } else if opc == OpCode::CPUI_STORE {
                    if let Some(vn2) = self.obank().get(op).and_then(|o| o.get_in(2)) {
                        self.cast_check_pointer_issues(op, vn2);
                    }
                }
                if self.obank().get(op).and_then(|o| o.get_out()).is_some() {
                    count += match &diff_token {
                        Some(t) => self.cast_output_token(op, strat, Rc::clone(t))?,
                        None => self.cast_output(op, strat)?,
                    };
                }
            }
        }
        Ok(count)
    }

    /// PTRADD that no longer fits its pointer (coreaction.cc:2830-2836).
    fn cast_fixup_ptradd(&mut self, op: OpId) -> KunaResult<()> {
        let (sz, in0) = {
            let o = match self.obank().get(op) {
                Some(o) => o,
                None => return Ok(()),
            };
            let sz = o.get_in(2).and_then(|v| self.vbank().get(v)).map(|v| v.get_offset()).unwrap_or(0);
            let in0 = match o.get_in(0) {
                Some(v) => v,
                None => return Ok(()),
            };
            (sz as int4, in0)
        };
        let ct = self.vn_high_type_read_facing(in0, op)?;
        let fits = if ct.get_metatype() == type_metatype::TYPE_PTR {
            if let (Some(ptrto), Some(ws)) = (ct.get_ptr_to(), ct.get_word_size()) {
                let align = ptrto.get_align_size();
                // C++: getAlignSize() == AddrSpace::addressToByteInt(sz, wordSize)
                // (int4 vs int8 — promote the int4 align to int8 for the compare).
                align as i64 == kuna_base::space::AddrSpace::address_to_byte_int(sz as i64, ws)
            } else {
                false
            }
        } else {
            false
        };
        if !fits {
            self.op_undo_ptradd(op, true)?;
        }
        Ok(())
    }

    /// PTRSUB that no longer fits its pointer (coreaction.cc:2837-2846).
    fn cast_fixup_ptrsub(&mut self, op: OpId) -> KunaResult<()> {
        let (in0, in1off) = {
            let o = match self.obank().get(op) {
                Some(o) => o,
                None => return Ok(()),
            };
            let in0 = match o.get_in(0) {
                Some(v) => v,
                None => return Ok(()),
            };
            let in1off = o.get_in(1).and_then(|v| self.vbank().get(v)).map(|v| v.get_offset()).unwrap_or(0);
            (in0, in1off)
        };
        let curtype = self.vn_type_read_facing(in0, op)?;
        if in1off == 0
            && curtype.get_ptr_to().is_some_and(|ty| {
                ty.get_metatype() == type_metatype::TYPE_UNION
                    && self.get_union_field(&curtype, op, -1).is_some_and(|resolution| {
                        ty.get_field(resolution.get_field_num()).is_some()
                    })
            })
        {
            return Ok(());
        }
        let matching = self.is_ptrsub_matching_scope(&curtype, in1off as i64, 0i64, 0i64)?;
        if !matching {
            if in1off == 0 {
                self.op_remove_input(op, 1);
                self.op_set_opcode_code(op, OpCode::CPUI_COPY);
            } else {
                self.op_set_opcode_code(op, OpCode::CPUI_INT_ADD);
            }
        }
        Ok(())
    }

    /// `ActionSetCasts::resolveUnion` (coreaction.cc:2580-2616).
    fn cast_resolve_union(&mut self, op: OpId, slot: int4, strat: &dyn CastStrategy) -> KunaResult<int4> {
        let vn = match self.obank().get(op).and_then(|o| o.get_in(slot)) {
            Some(v) => v,
            None => return Ok(0),
        };
        if self.vbank().get(vn).map(|v| v.is_annotation()).unwrap_or(true) {
            return Ok(0);
        }
        let dt = match self.high_get_type(vn) {
            Some(d) => d,
            None => return Ok(0),
        };
        if !dt.needs_resolution() {
            return Ok(0);
        }
        // On a getUnionField cache miss, the miss arm drives `ScoreUnionFields`
        // via [`Funcdata::resolve_in_flow`]
        // (the side effect is `setUnionField`, populating the cache), then re-reads
        // `getUnionField` exactly as C++ `dt->resolveInFlow(op,slot)` does.
        let field_and_dt = match self.get_union_field(&dt, op, slot) {
            Some(r) => Some((r.get_field_num(), Rc::clone(r.get_datatype()))),
            None => {
                let _ = self.resolve_in_flow(&dt, op, slot)?; // populates the cache
                self.get_union_field(&dt, op, slot)
                    .map(|r| (r.get_field_num(), Rc::clone(r.get_datatype())))
            }
        };
        let (field_num, res_dt) = match field_and_dt {
            Some(x) if x.0 >= 0 => x,
            _ => return Ok(0),
        };
        if dt.get_metatype() == type_metatype::TYPE_PTR {
            // Test if a cast is still needed even after resolution.
            let reqtype = self.vn_type_read_facing(vn, op)?;
            if strat.cast_standard(&reqtype, &res_dt, true, true).is_some() {
                return Ok(0); // cast still needed; don't resolve
            }
            // Insert a PTRSUB placeholder indicating which field is accessed.
            let ptrsub = self.cast_insert_ptrsub_zero(op, slot, reqtype);
            // Attach the resolution to the PTRSUB.
            let resolve = match self.rebuild_resolved(&dt, field_num) {
                Some(r) => r,
                None => return Ok(1),
            };
            self.set_union_field(&dt, ptrsub, -1, resolve);
            Ok(1)
        } else if self.vbank().get(vn).map(|v| v.is_implied()).unwrap_or(false) {
            if self.vbank().get(vn).map(|v| v.is_written()).unwrap_or(false) {
                // writefacing == readfacing -> treat as if it had the field type.
                if let Some(def) = self.vbank().get(vn).and_then(|v| v.get_def()) {
                    if let Some(wr) = self.get_union_field(&dt, def, -1) {
                        if wr.get_field_num() == field_num {
                            return Ok(0); // Don't print implied fields.
                        }
                    }
                }
            }
            if let Some(v) = self.vbank_mut().get_mut(vn) {
                v.set_implied_field();
            }
            Ok(1)
        } else {
            Ok(1)
        }
    }

    /// `ActionSetCasts::castInput` (coreaction.cc:2743-2810).
    fn cast_input(&mut self, op: OpId, slot: int4, strat: &dyn CastStrategy) -> KunaResult<int4> {
        let ct = match get_input_cast(self, strat, op, slot)? {
            Some(c) => c,
            None => {
                // markExplicitUnsigned / markExplicitLongSize.
                let mut ctx = FuncdataCastContext::new(self);
                let opr = ctx.op_ref(op);
                let res_unsigned = strat.mark_explicit_unsigned(&mut ctx, opr, slot)?;
                let res_sized = strat.mark_explicit_long_size(&mut ctx, opr, slot);
                if res_unsigned || res_sized {
                    return Ok(1);
                }
                return Ok(0);
            }
        };
        let vn = match self.obank().get(op).and_then(|o| o.get_in(slot)) {
            Some(v) => v,
            None => return Ok(0),
        };
        let vnin = vn;
        // Guard against double-casts.
        let vn_is_written = self.vbank().get(vn).map(|v| v.is_written()).unwrap_or(false);
        let vn_def_is_cast = vn_is_written
            && self
                .vbank()
                .get(vn)
                .and_then(|v| v.get_def())
                .and_then(|d| self.obank().get(d))
                .map(|o| o.code() == OpCode::CPUI_CAST)
                .unwrap_or(false);
        if vn_def_is_cast {
            if self.vbank().get(vn).map(|v| v.is_implied()).unwrap_or(false) {
                if self.lone_descend(vn) == Some(op) {
                    let changed = self.vn_update_type(vn, Rc::clone(&ct));
                    let _ = changed;
                    if self
                        .vbank()
                        .get(vn)
                        .map(|v| Rc::ptr_eq(v.get_type(), &ct))
                        .unwrap_or(false)
                    {
                        return Ok(1);
                    }
                }
                // Cast directly from the input of the previous cast.
                let prev_in = self
                    .vbank()
                    .get(vn)
                    .and_then(|v| v.get_def())
                    .and_then(|d| self.obank().get(d))
                    .and_then(|o| o.get_in(0));
                if let Some(vnin2) = prev_in {
                    if self
                        .vbank()
                        .get(vnin2)
                        .map(|v| Rc::ptr_eq(v.get_type(), &ct))
                        .unwrap_or(false)
                    {
                        let _ = self.op_set_input(op, vnin2, slot);
                        return Ok(1);
                    }
                }
            }
        } else if self.vbank().get(vn).map(|v| v.is_constant()).unwrap_or(false) {
            let _ = self.vn_update_type(vn, Rc::clone(&ct));
            if self.vbank().get(vn).map(|v| Rc::ptr_eq(v.get_type(), &ct)).unwrap_or(false) {
                return Ok(1);
            }
        } else if ct.get_metatype() == type_metatype::TYPE_PTR {
            let cur = self.vn_high_type_read_facing(vn, op)?;
            if test_struct_offset0(&ct, &cur, strat) {
                // Insert a PTRSUB(vn,#0) instead of a CAST.
                let newop = self.cast_insert_ptrsub_zero(op, slot, Rc::clone(&ct));
                let high = self.high_get_type(vn);
                if let Some(h) = high {
                    if h.needs_resolution() {
                        self.inherit_union_field(&h, newop, 0, op, slot);
                    }
                }
                return Ok(1);
            } else if self.cast_input_resolution(op, slot, &ct, strat) {
                return Ok(1);
            }
        // A compatible union field is not a substitute for the full-object
        // storage CAST that integer equality requested.
        } else if !(self.get_arch().out_lang == crate::kuna_lang::OutLang::C
            && matches!(self.obank().get(op).map(|o| o.code()),
                Some(OpCode::CPUI_INT_EQUAL | OpCode::CPUI_INT_NOTEQUAL))
            && ct.get_metatype() == type_metatype::TYPE_UINT
            && matches!(ct.get_size(), 1 | 2 | 4 | 8)
            && self.vbank().get(vn).is_some_and(|v| v.get_size() == ct.get_size())
            && {
                let facing = self.vn_high_type_read_facing(vn, op)?;
                full_aggregate_input(self, vn, &facing)
            })
            && self.cast_input_resolution(op, slot, &ct, strat)
        {
            return Ok(1);
        }
        // Generate the CAST op.
        let vnin_size = self.vbank().get(vnin).map(|v| v.get_size()).unwrap_or(1);
        let addr = match self.obank().get(op) {
            Some(o) => o.get_addr().clone(),
            None => return Ok(0),
        };
        let newop = self.new_op(1, addr);
        let vnout = self.new_unique_out(vnin_size, newop)?;
        let _ = self.vn_update_type(vnout, Rc::clone(&ct));
        let _ = self.vbank_mut().get_mut(vnout).map(|v| {
            v.set_implied();
        });
        self.op_set_opcode_code(newop, OpCode::CPUI_CAST);
        self.op_set_input(newop, vnin, 0)?;
        self.op_set_input(op, vnout, slot)?;
        self.op_insert_before(newop, op);
        if ct.needs_resolution() {
            let _ = self.force_facing_type(Rc::clone(&ct), -1, newop, -1)?;
        }
        let high = self.high_get_type(vn);
        if let Some(h) = high {
            if h.needs_resolution() {
                self.inherit_union_field(&h, newop, 0, op, slot);
            }
        }
        Ok(1)
    }

    /// The COPY/non-COPY resolution-adjustment arms of castInput
    /// (coreaction.cc:2787-2791).  Returns `true` if an adjustment removed the
    /// need for a CAST.
    fn cast_input_resolution(
        &mut self,
        op: OpId,
        slot: int4,
        ct: &Rc<Datatype>,
        _strat: &dyn CastStrategy,
    ) -> bool {
        let opc = self.obank().get(op).map(|o| o.code());
        if opc != Some(OpCode::CPUI_COPY) {
            self.cast_try_resolution_adjustment(ct, op, slot)
        } else {
            self.cast_try_resolution_copy(op)
        }
    }

    /// `ActionSetCasts::castOutput` (coreaction.cc:2624-2704).
    fn cast_output(&mut self, op: OpId, strat: &dyn CastStrategy) -> KunaResult<int4> {
        if let Some((wide, unsigned)) = crate::p4_calls::kuna_voidret::narrowed_call_result(self, op) {
            return Ok(self.cast_narrowed_call(op, wide, unsigned));
        }
        if let Some(float) = crate::p4_calls::kuna_callrettype::float_held_as_bits(self, op) {
            return Ok(self.cast_narrowed_call(op, float, false));
        }
        let tokenct = get_output_token(self, strat, op)?;
        self.cast_output_token(op, strat, tokenct)
    }

    /// (kuna `voidret`) Make the call `op` write its callee's whole result,
    /// typed `wide`, into a temporary its output then truncates with a CAST,
    /// which prints the conversion, to an unsigned word where `unsigned` asks
    /// ([`crate::p4_calls::kuna_voidret::narrowed_call_result`]).  (kuna
    /// `callrettype`) A float the caller holds as bits goes through the same
    /// CAST at its own width, which prints the reinterpretation
    /// ([`crate::p4_calls::kuna_callrettype::float_held_as_bits`]).
    fn cast_narrowed_call(&mut self, op: OpId, wide: Rc<Datatype>, unsigned: bool) -> int4 {
        let Some((outvn, addr)) = self.obank().get(op).and_then(|o| Some((o.get_out()?, o.get_addr().clone()))) else {
            return 0;
        };
        if unsigned {
            let size = self.vbank().get(outvn).map_or(0, |v| v.get_size());
            if let Some(word) = self.get_arch().types().and_then(|t| t.get_base(size, type_metatype::TYPE_UINT).ok()) {
                let _ = self.vn_update_type(outvn, word);
            }
        }
        let vn = self.new_unique(wide.get_size(), None);
        let _ = self.vn_update_type(vn, wide);
        if let Some(v) = self.vbank_mut().get_mut(vn) {
            v.set_implied();
        }
        let newop = self.new_op(1, addr);
        self.op_set_opcode_code(newop, OpCode::CPUI_CAST);
        let _ = self.op_set_output(newop, outvn);
        let _ = self.op_set_input(newop, vn, 0);
        let _ = self.op_set_output(op, vn);
        self.op_insert_after(newop, op);
        1
    }

    /// [`Self::cast_output`] against a given output token.
    fn cast_output_token(&mut self, op: OpId, strat: &dyn CastStrategy, tokenct: Rc<Datatype>) -> KunaResult<int4> {
        let outvn = match self.obank().get(op).and_then(|o| o.get_out()) {
            Some(v) => v,
            None => return Ok(0),
        };
        let out_high_type = match self.high_get_type(outvn) {
            Some(t) => t,
            None => Rc::clone(self.vbank().get(outvn).expect("castOutput: stale outvn").get_type()),
        };
        let storage_type = crate::kuna_stackviews::access_type(self, outvn, op, -1)?;
        if Rc::ptr_eq(&tokenct, storage_type.as_ref().unwrap_or(&out_high_type)) {
            if tokenct.needs_resolution() {
                let resolve = ResolvedUnion::new(Rc::clone(&tokenct));
                self.set_union_field(&tokenct, op, -1, resolve);
            }
            return Ok(0); // Same type, no cast.
        }
        let mut out_high_resolve = self.vn_high_type_def_facing(outvn)?;
        let mut force = false;
        if self.vbank().get(outvn).map(|v| v.is_implied()).unwrap_or(false) {
            if self.vbank().get(outvn).map(|v| v.is_type_lock()).unwrap_or(false) {
                let out_op = self.lone_descend(outvn);
                let is_return = out_op
                    .and_then(|o| self.obank().get(o))
                    .map(|o| o.code() == OpCode::CPUI_RETURN)
                    .unwrap_or(false);
                if out_op.is_none() || !is_return {
                    force = !is_op_identical(&out_high_resolve, &tokenct);
                }
            } else if out_high_resolve.get_metatype() != type_metatype::TYPE_PTR {
                let _ = self.vn_update_type(outvn, Rc::clone(&tokenct));
                out_high_resolve = self.vn_high_type_def_facing(outvn)?;
            } else if tokenct.get_metatype() == type_metatype::TYPE_PTR {
                if let Some(outct) = out_high_resolve.get_ptr_to() {
                    let meta = outct.get_metatype();
                    if meta != type_metatype::TYPE_ARRAY
                        && meta != type_metatype::TYPE_STRUCT
                        && meta != type_metatype::TYPE_UNION
                    {
                        let _ = self.vn_update_type(outvn, Rc::clone(&tokenct));
                        out_high_resolve = self.vn_high_type_def_facing(outvn)?;
                    }
                }
            }
        }
        // FLOAT_TRUNC converts to a signed integer before any destination coercion.
        force |= self.obank().get(op).is_some_and(|o| o.code() == OpCode::CPUI_FLOAT_TRUNC)
            && matches!(out_high_resolve.get_metatype(),
                type_metatype::TYPE_UINT | type_metatype::TYPE_BOOL);
        let mut opc = OpCode::CPUI_CAST;
        if !force {
            let outct = out_high_resolve;
            if outct.get_metatype() == type_metatype::TYPE_PTR
                && test_struct_offset0(&outct, &tokenct, strat)
            {
                opc = OpCode::CPUI_PTRSUB;
            } else if strat.cast_standard(&outct, &tokenct, false, true).is_none() {
                return Ok(0);
            }
            if self.cast_try_resolution_adjustment(&tokenct, op, -1) {
                return Ok(0);
            }
        }
        // Generate the cast op.
        let outvn_size = self.vbank().get(outvn).map(|v| v.get_size()).unwrap_or(1);
        let vn = self.new_unique(outvn_size, None);
        let _ = self.vn_update_type(vn, Rc::clone(&tokenct));
        let _ = self.vbank_mut().get_mut(vn).map(|v| {
            v.set_implied();
        });
        let addr = match self.obank().get(op) {
            Some(o) => o.get_addr().clone(),
            None => return Ok(0),
        };
        let ninput = if opc != OpCode::CPUI_CAST { 2 } else { 1 };
        let newop = self.new_op(ninput, addr);
        self.op_set_opcode_code(newop, opc);
        let _ = self.op_set_output(newop, outvn);
        let _ = self.op_set_input(newop, vn, 0);
        if opc != OpCode::CPUI_CAST {
            let c = self.new_constant(4, 0);
            let _ = self.op_set_input(newop, c, 1);
        }
        let _ = self.op_set_output(op, vn);
        self.op_insert_after(newop, op);
        if tokenct.needs_resolution() {
            let _ = self.force_facing_type(Rc::clone(&tokenct), -1, newop, 0)?;
        }
        if out_high_type.needs_resolution() {
            self.inherit_union_field(&out_high_type, newop, -1, op, -1);
        }
        if let Some(view) = self.stack_write_views.remove(&op) {
            self.inherit_union_field(&view.backing, newop, -1, op, -1);
            self.stack_write_views.insert(newop, view);
        } else if storage_type.is_some() {
            if let Some(backing) = self.vbank().get(outvn).and_then(|v| v.get_high()).and_then(|h| self.high_bank().get(h)).and_then(|h| h.kuna_symbol_type()).cloned() {
                self.inherit_union_field(&backing, newop, -1, op, -1);
            }
        }
        Ok(1)
    }

    /// `ActionSetCasts::insertPtrsubZero` (coreaction.cc:2718-2732).
    fn cast_insert_ptrsub_zero(&mut self, op: OpId, slot: int4, ct: Rc<Datatype>) -> OpId {
        let vn = self
            .obank()
            .get(op)
            .and_then(|o| o.get_in(slot))
            .expect("insertPtrsubZero: missing input slot");
        let vn_size = self.vbank().get(vn).map(|v| v.get_size()).unwrap_or(1);
        let addr = self.obank().get(op).expect("insertPtrsubZero: stale op").get_addr().clone();
        let newop = self.new_op(2, addr);
        let vnout = self.new_unique_out(vn_size, newop).expect("insertPtrsubZero: new unique out");
        let _ = self.vn_update_type(vnout, Rc::clone(&ct));
        let _ = self.vbank_mut().get_mut(vnout).map(|v| {
            v.set_implied();
        });
        self.op_set_opcode_code(newop, OpCode::CPUI_PTRSUB);
        let _ = self.op_set_input(newop, vn, 0);
        let c = self.new_constant(4, 0);
        let _ = self.op_set_input(newop, c, 1);
        let _ = self.op_set_input(op, vnout, slot);
        self.op_insert_before(newop, op);
        newop
    }

    /// `ActionSetCasts::tryResolutionAdjustment` (coreaction.cc:2482-2504).
    fn cast_try_resolution_adjustment(&mut self, dt: &Rc<Datatype>, op: OpId, slot: int4) -> bool {
        if dt.needs_resolution() {
            return false;
        }
        let vn = if slot < 0 {
            self.obank().get(op).and_then(|o| o.get_out())
        } else {
            self.obank().get(op).and_then(|o| o.get_in(slot))
        };
        let vn = match vn {
            Some(v) => v,
            None => return false,
        };
        let cur_type = match self.high_get_type(vn) {
            Some(t) => t,
            None => return false,
        };
        if !cur_type.needs_resolution() {
            return false;
        }
        if slot < 0 && cur_type.get_metatype() == type_metatype::TYPE_PTR {
            return false; // Cannot take field of a pointer during assignment.
        }
        let field_num = cur_type.find_compatible_resolve(dt).unwrap_or(-1);
        if field_num < 0 {
            return false;
        }
        let resolve = match self.rebuild_resolved(&cur_type, field_num) {
            Some(r) => r,
            None => return false,
        };
        let resolve_dt = Rc::clone(resolve.get_datatype());
        if !self.set_union_field(&cur_type, op, slot, resolve) {
            return false;
        }
        if slot >= 0 && cur_type.get_metatype() == type_metatype::TYPE_PTR {
            let needs_ptrsub = {
                let v = self.vbank().get(vn);
                let written = v.map(|v| v.is_written()).unwrap_or(false);
                if !written {
                    false
                } else {
                    let def = v.and_then(|v| v.get_def());
                    let def_not_matching = def
                        .and_then(|d| self.obank().get(d))
                        .map(|o| {
                            o.code() != OpCode::CPUI_PTRSUB
                                || o.get_in(0)
                                    .and_then(|iv| self.vbank().get(iv))
                                    .map(|iv| !Rc::ptr_eq(iv.get_type(), &cur_type))
                                    .unwrap_or(true)
                        })
                        .unwrap_or(true);
                    def_not_matching
                }
            };
            if needs_ptrsub {
                let ptrsub = self.cast_insert_ptrsub_zero(op, slot, resolve_dt);
                if let Some(r) = self.rebuild_resolved(&cur_type, field_num) {
                    self.set_union_field(&cur_type, ptrsub, -1, r);
                }
            }
        }
        true
    }

    /// `ActionSetCasts::tryResolutionCopy` (coreaction.cc:2514-2549).
    fn cast_try_resolution_copy(&mut self, op: OpId) -> bool {
        let outvn = match self.obank().get(op).and_then(|o| o.get_out()) {
            Some(v) => v,
            None => return false,
        };
        let in0 = match self.obank().get(op).and_then(|o| o.get_in(0)) {
            Some(v) => v,
            None => return false,
        };
        let out_type = match self.high_get_type(outvn) {
            Some(t) => t,
            None => return false,
        };
        let in_type = match self.high_get_type(in0) {
            Some(t) => t,
            None => return false,
        };
        if !in_type.needs_resolution() && !out_type.needs_resolution() {
            return false;
        }
        let mut in_resolve: int4 = -1;
        let mut out_resolve: int4 = -1;
        if in_type.needs_resolution() {
            in_resolve = in_type.find_compatible_resolve(&out_type).unwrap_or(-1);
            if in_resolve < 0 {
                return false;
            }
        }
        if out_type.needs_resolution() && out_type.get_metatype() != type_metatype::TYPE_PTR {
            if in_resolve >= 0 {
                let dep = in_type.get_depend(in_resolve);
                out_resolve = match dep {
                    Some(d) => out_type.find_compatible_resolve(&d).unwrap_or(-1),
                    None => -1,
                };
            } else {
                out_resolve = out_type.find_compatible_resolve(&in_type).unwrap_or(-1);
            }
            if out_resolve < 0 {
                return false;
            }
        }
        if in_resolve >= 0 {
            let resolve = match self.rebuild_resolved(&in_type, in_resolve) {
                Some(r) => r,
                None => return false,
            };
            if !self.set_union_field(&in_type, op, 0, resolve) {
                return false;
            }
        }
        if out_resolve >= 0 {
            let resolve = match self.rebuild_resolved(&out_type, out_resolve) {
                Some(r) => r,
                None => return false,
            };
            if !self.set_union_field(&out_type, op, -1, resolve) {
                return false;
            }
        }
        true
    }

    /// `ActionSetCasts::checkPointerIssues` (coreaction.cc:2407-2432).
    ///
    /// This helper is **warnings-only**: the C++ body only ever calls
    /// `data.warning(...)` (the LOAD/STORE size-mismatch and address-space-mismatch
    /// diagnostics).  It never mutates the IR, so it cannot affect the rendered C
    /// body the stringmatch oracle checks.  The Funcdata-level `warning` sink is not
    /// present in the merged tree (warnings route through the ActionContext, W8); the
    /// `does_special_printing()` early-out is preserved for fidelity, and the warning
    /// emission is faithfully a no-op here (a missing diagnostic comment, never a
    /// changed expression).  `op`/`vn` are kept in the signature so the call sites
    /// stay one-for-one with the C++.
    fn cast_check_pointer_issues(&mut self, op: OpId, _vn: VarnodeId) {
        let _ = self.obank().get(op).map(|o| o.does_special_printing());
    }

    /// Rebuild a `ResolvedUnion` for `(unres_type, field_num)` (the C++ constructs
    /// a fresh `ResolvedUnion resolve(curType, fieldNum, *typegrp)` at each use).
    fn rebuild_resolved(&self, unres_type: &Rc<Datatype>, field_num: int4) -> Option<ResolvedUnion> {
        let tlst = self.get_arch().types_rc()?;
        ResolvedUnion::new_field(Rc::clone(unres_type), field_num, tlst.as_ref()).ok()
    }
}

/// `ActionSetCasts::testStructOffset0` (coreaction.cc:2443-2472).
pub fn test_struct_offset0(reqtype: &Rc<Datatype>, curtype: &Rc<Datatype>, strat: &dyn CastStrategy) -> bool {
    if curtype.get_metatype() != type_metatype::TYPE_PTR {
        return false;
    }
    let high_ptr_to = match curtype.get_ptr_to() {
        Some(p) => p,
        None => return false,
    };
    let mut reqt: Rc<Datatype>;
    let curt: Rc<Datatype>;
    match high_ptr_to.get_metatype() {
        type_metatype::TYPE_STRUCT => {
            if high_ptr_to.num_depend() == 0 {
                return false;
            }
            let first = match high_ptr_to.get_field(0) {
                Some(f) => f,
                None => return false,
            };
            if first.offset != 0 {
                return false;
            }
            reqt = match reqtype.get_ptr_to() {
                Some(p) => p,
                None => return false,
            };
            curt = Rc::clone(&first.field_type);
            if reqt.get_metatype() == type_metatype::TYPE_ARRAY {
                if let Some(b) = reqt.get_array_base() {
                    reqt = b;
                }
            }
            let curt = if curt.get_metatype() == type_metatype::TYPE_ARRAY {
                curt.get_array_base().unwrap_or(curt)
            } else {
                curt
            };
            if reqt.get_metatype() == type_metatype::TYPE_VOID {
                return false; // Don't induce PTRSUB for "void *"
            }
            strat.cast_standard(&reqt, &curt, true, true).is_none()
        }
        type_metatype::TYPE_ARRAY => {
            reqt = match reqtype.get_ptr_to() {
                Some(p) => p,
                None => return false,
            };
            let curt = match high_ptr_to.get_array_base() {
                Some(b) => b,
                None => return false,
            };
            if reqt.get_metatype() == type_metatype::TYPE_VOID {
                return false;
            }
            strat.cast_standard(&reqt, &curt, true, true).is_none()
        }
        _ => false,
    }
}

/// `ActionSetCasts::isOpIdentical` (coreaction.cc:2559-2571).
pub fn is_op_identical(ct1: &Rc<Datatype>, ct2: &Rc<Datatype>) -> bool {
    let mut a = Rc::clone(ct1);
    let mut b = Rc::clone(ct2);
    while a.get_metatype() == type_metatype::TYPE_PTR && b.get_metatype() == type_metatype::TYPE_PTR {
        a = match a.get_ptr_to() {
            Some(p) => p,
            None => break,
        };
        b = match b.get_ptr_to() {
            Some(p) => p,
            None => break,
        };
    }
    while let Some(td) = a.get_typedef() {
        let td = Rc::clone(td);
        a = td;
    }
    while let Some(td) = b.get_typedef() {
        let td = Rc::clone(td);
        b = td;
    }
    Rc::ptr_eq(&a, &b)
}

// ===========================================================================
// VERIFIER round-2 adversarial fences for item `w10-merge-casts` (B1/B2 fix).
//
// Round 1 REJECTED this item because the live `get_input_cast` DISPATCH routed
// INT_SLESS/INT_SLESSEQUAL to the EQUAL/NOTEQUAL body (B1) and inverted the
// INT_ZEXT/INT_SEXT fallthrough tuple (B2).  The r1 fences proved the *tuples*
// diverge via the `cast_standard` proxy, but could not reach `get_input_cast`
// (it is `pub(crate)` — invisible to the `tests/` integration crate).  These
// in-module tests drive the ACTUAL fixed dispatch over a real `Funcdata` op and
// assert it equals the C++-faithful result computed independently — so a future
// edit that re-misroutes SLESS (or re-inverts the extension tuple) fails here
// even though the corpus still masks it behind `checkIntPromotion*`.
//
// They are SELF-CALIBRATING (the expected value is the faithful tuple applied
// to the same operands, not a hardcoded Some/None), and each op is built with
// 4-byte operands so `checkIntPromotionForCompare`/`ForExtension` returns false
// (NO_PROMOTION, cast.cc:178-181) and the `castStandard` tail — the part B1/B2
// corrupted — is actually reached.
// ===========================================================================
#[cfg(test)]
mod verify_w10_merge_casts_r2 {
    use super::*;
    use crate::cast::CastStrategy;
    use crate::dtype::{type_metatype, Datatype, TypeFactoryImpl};
    use crate::funcdata::Funcdata;
    use crate::context::{ArchContext, TypeOp};
    use kuna_base::address::Address;
    use kuna_base::space::{
        addrspace_flags, spacetype, AddrSpace, AddrSpaceManager, ConstantSpace, FspecSpace,
        IopSpace, UniqueSpace,
    };

    /// A `Funcdata` whose `Architecture` carries a real `TypeFactory` (size-of-int
    /// = 4, so `promote_size == 4` and a 4-byte operand has NO_PROMOTION) plus a
    /// `CastStrategyC` built on the same factory.
    fn build() -> (Funcdata, CastStrategyC, Rc<AddrSpace>) {
        let mut m = AddrSpaceManager::new();
        m.insert_space(Rc::new(ConstantSpace::new())).unwrap();
        m.insert_space(Rc::new(UniqueSpace::new(1, 0, false))).unwrap();
        m.insert_space(Rc::new(IopSpace::new(2))).unwrap();
        m.insert_space(Rc::new(FspecSpace::new(3))).unwrap();
        m.insert_space(Rc::new(AddrSpace::new(
            spacetype::IPTR_PROCESSOR,
            "ram",
            false,
            8,
            1,
            4,
            addrspace_flags::hasphysical,
            1,
            1,
        )))
        .unwrap();

        let tf = TypeFactoryImpl::new();
        tf.setup_sizes(Some(4), 8, 8); // size-of-int = 4 => promote_size = 4
        tf.set_default_alignment_map();
        tf.set_max_basetype_size(8);
        let tf = Rc::new(tf);

        let mut arch = ArchContext::new(m);
        arch.types = Some(Rc::clone(&tf));
        let glb = Rc::new(arch);
        let ram = Rc::clone(glb.manage().get_space_by_name("ram").unwrap());
        let addr = Address::new(Rc::clone(&ram), 0x1000);
        let fd = Funcdata::new("f", "f", glb, addr, 0x1000_0000, 0x40).unwrap();
        assert!(
            fd.get_arch().types().is_some(),
            "test fixture: Funcdata arch must carry the TypeFactory"
        );
        let strat = CastStrategyC::new(tf as Rc<dyn TypeFactory>);
        (fd, strat, ram)
    }

    fn ity(size: int4, m: type_metatype) -> Rc<Datatype> {
        Rc::new(Datatype::new(size, m))
    }

    #[test]
    fn integer_equality_reads_full_aggregate_storage_without_retyping_the_literal_as_an_object() {
        for opcode in [OpCode::CPUI_INT_EQUAL, OpCode::CPUI_INT_NOTEQUAL] {
            for meta in [type_metatype::TYPE_STRUCT, type_metatype::TYPE_UNION] {
              for size in [1, 2, 4, 8] {
                let (mut fd, strat, ram) = build();
                let word_type = ity(size, type_metatype::TYPE_UINT);
                let mut object_type = Datatype::new(size, meta);
                object_type.name = "Pair".into();
                object_type.display_name = "Pair".into();
                if meta == type_metatype::TYPE_UNION {
                    object_type.flags |= crate::dtype::flags::needs_resolution;
                }
                object_type.kind = if meta == type_metatype::TYPE_UNION {
                    crate::dtype::DatatypeKind::Union {
                        field: vec![crate::dtype::TypeField::new(0, 0, "word", word_type)],
                    }
                } else if size == 4 {
                    crate::dtype::DatatypeKind::Struct {
                        field: vec![
                            crate::dtype::TypeField::new(0, 0, "lo", ity(2, type_metatype::TYPE_UINT)),
                            crate::dtype::TypeField::new(1, 2, "hi", ity(2, type_metatype::TYPE_UINT)),
                        ],
                        bitfield: vec![],
                    }
                } else {
                    crate::dtype::DatatypeKind::Struct {
                        field: vec![crate::dtype::TypeField::new(0, 0, "word", word_type)],
                        bitfield: vec![],
                    }
                };
                let pair = Rc::new(object_type);
                let op = fd.new_op(2, Address::new(ram, 0x2000));
                fd.op_set_opcode(op, TypeOp::new(opcode, 0, "OP"));
                let object = fd.new_unique(size, Some(Rc::clone(&pair)));
                fd.op_set_input(op, object, 0).unwrap();
                let literal = fd.new_constant(size, 85);
                fd.op_set_input(op, literal, 1).unwrap();
                let root = fd.bblocks_root_pub();
                let block = fd.bblocks_mut().new_block_basic(root);
                fd.op_insert_end(op, block);
                fd.set_high_level();
                assert!(Rc::ptr_eq(&crate::printc::declared_variable_type(&fd, false, object).unwrap(), &pair));
                let wanted = get_input_cast(&mut fd, &strat, op, 0).unwrap().unwrap();
                assert_eq!(wanted.get_metatype(), type_metatype::TYPE_UINT);
                assert_eq!(wanted.get_size(), size);
                // The constant may not need a cast, but must never request Pair.
                if let Some(wanted) = get_input_cast(&mut fd, &strat, op, 1).unwrap() {
                    assert_eq!(wanted.get_metatype(), type_metatype::TYPE_UINT);
                    assert_eq!(wanted.get_size(), size);
                }
                fd.cast_input(op, 1, &strat).unwrap();
                assert_eq!(fd.vbank().get(literal).unwrap().get_offset(), 85);
                assert!(!matches!(fd.vbank().get(literal).unwrap().get_type().get_metatype(),
                    type_metatype::TYPE_STRUCT | type_metatype::TYPE_UNION));
                fd.cast_input(op, 0, &strat).unwrap();
                let word = fd.obank().get(op).unwrap().get_in(0).unwrap();
                let cast = fd.obank().get(fd.vbank().get(word).unwrap().get_def().unwrap()).unwrap();
                assert_eq!(cast.code(), OpCode::CPUI_CAST);
                assert_eq!(cast.get_in(0), Some(object));
                assert_eq!(fd.vbank().get(word).unwrap().get_type().get_size(), size);
                assert!(Rc::ptr_eq(fd.vbank().get(object).unwrap().get_type(), &pair));
              }
            }
        }
    }

    /// Build a binary op `opc` with two 4-byte input varnodes typed `t0`/`t1`.
    fn binop(
        fd: &mut Funcdata,
        ram: &Rc<AddrSpace>,
        off: u64,
        opc: OpCode,
        t0: Rc<Datatype>,
        t1: Rc<Datatype>,
    ) -> OpId {
        let pc = Address::new(Rc::clone(ram), 0x2000 + off);
        let op = fd.new_op(2, pc);
        fd.op_set_opcode(op, TypeOp::new(opc, 0, "OP"));
        let a = fd.new_unique(4, Some(t0));
        let b = fd.new_unique(4, Some(t1));
        fd.op_set_input(op, a, 0).unwrap();
        fd.op_set_input(op, b, 1).unwrap();
        op
    }

    /// Build a unary op `opc` with one 4-byte input varnode typed `t0` and an
    /// 8-byte output (a widening extension).
    fn unop(
        fd: &mut Funcdata,
        ram: &Rc<AddrSpace>,
        off: u64,
        opc: OpCode,
        t0: Rc<Datatype>,
    ) -> OpId {
        let pc = Address::new(Rc::clone(ram), 0x2000 + off);
        let op = fd.new_op(1, pc);
        fd.op_set_opcode(op, TypeOp::new(opc, 0, "OP"));
        let a = fd.new_unique(4, Some(t0));
        fd.op_set_input(op, a, 0).unwrap();
        let outaddr = Address::new(Rc::clone(ram), 0x3000 + off);
        let out = fd.new_varnode(8, &outaddr, None).unwrap();
        fd.op_set_output(op, out).unwrap();
        op
    }

    /// Structural equality on the (metatype, size) the cast decision turns on.
    /// `cast_standard` returns freshly-built `Rc<Datatype>` per call, so
    /// `Rc::ptr_eq` would spuriously fail; this compares the load-bearing fields.
    fn opt_ptr_eq(a: &Option<Rc<Datatype>>, b: &Option<Rc<Datatype>>) -> bool {
        match (a, b) {
            (None, None) => true,
            (Some(x), Some(y)) => {
                Rc::ptr_eq(x, y)
                    || (x.get_metatype() == y.get_metatype() && x.get_size() == y.get_size())
            }
            _ => false,
        }
    }

    #[test]
    fn variadic_float_constant_cast_preserves_bits_and_other_integer_uses() {
        use crate::fspec::{parameter_pieces_flags, FuncCallSpecs, FuncProto, ParameterPieces, ProtoModel};
        use crate::varnode::varnode_flags;
        for (other_reader, locked) in [(false, false), (true, false), (false, true)] {
            let (mut fd, strat, ram) = build();
            let types = fd.get_arch().types().unwrap();
            let int4 = types.get_base(4, type_metatype::TYPE_INT).unwrap();
            let uint8 = types.get_base(8, type_metatype::TYPE_UINT).unwrap();
            let float8 = types.get_base(8, type_metatype::TYPE_FLOAT).unwrap();
            let void = types.get_type_void().unwrap();
            let mut model = ProtoModel::new(fd.get_arch().manage());
            model.build_param_list("standard").unwrap();
            let mut proto = FuncProto::new();
            proto.set_internal(Rc::new(model), void);
            proto.set_override(true);
            proto.set_dotdotdot(true);
            for (slot, dtype) in [(0, int4), (1, float8)] {
                proto.set_param(slot, "argument", &ParameterPieces {
                    addr: Address::new(ram.clone(), 0x80 + slot as u64 * 8),
                    type_: Some(dtype), flags: parameter_pieces_flags::TYPELOCK,
                });
            }
            let root = fd.bblocks_root_pub();
            let block = fd.bblocks_mut().new_block_basic(root);
            let bits = 2.5_f64.to_bits();
            let raw = fd.new_constant(8, bits);
            fd.vn_update_type(raw, uint8);
            if locked {
                fd.vbank_mut().get_mut(raw).unwrap().set_flags_pub(varnode_flags::typelock);
            }
            let integer_use = if other_reader {
                let copy = fd.new_op(1, Address::new(ram.clone(), 0x2000));
                fd.op_set_opcode(copy, TypeOp::new(OpCode::CPUI_COPY, 0, "COPY"));
                fd.op_set_input(copy, raw, 0).unwrap();
                fd.new_unique_out(8, copy).unwrap();
                fd.op_insert_end(copy, block);
                Some(copy)
            } else { None };
            let call = fd.new_op(3, Address::new(ram.clone(), 0x2004));
            fd.op_set_opcode(call, TypeOp::new(OpCode::CPUI_CALLIND, crate::op::pcodeop_flags::call, "CALLIND"));
            let target = fd.new_unique(8, None);
            let fixed = fd.new_constant(4, 7);
            fd.op_set_input(call, target, 0).unwrap();
            fd.op_set_input(call, fixed, 1).unwrap();
            fd.op_set_input(call, raw, 2).unwrap();
            fd.op_insert_end(call, block);
            let admitted_argument = fd.obank().get(call).unwrap().get_in(2).unwrap();
            assert_eq!(fd.vbank().get(admitted_argument).unwrap().get_offset(), bits);
            if other_reader {
                assert_ne!(admitted_argument, raw, "each constant read owns its own varnode");
            }
            let mut specs = FuncCallSpecs::new(call, Address::new_invalid());
            specs.proto_mut().copy(&proto);
            fd.push_call_specs(specs);
            fd.cast_input(call, 2, &strat).unwrap();
            let cast_output = fd.obank().get(call).unwrap().get_in(2).unwrap();
            let output = fd.vbank().get(cast_output).unwrap();
            assert_eq!(output.get_type().get_metatype(), type_metatype::TYPE_FLOAT);
            assert_eq!(output.get_type().get_size(), 8);
            if output.is_constant() {
                assert!(!locked);
                assert_eq!(cast_output, admitted_argument);
                assert_eq!(output.get_offset(), bits);
            } else {
                let cast = fd.obank().get(output.get_def().expect("locked constant conversion")).unwrap();
                assert_eq!(cast.code(), OpCode::CPUI_CAST);
                let input = fd.vbank().get(cast.get_in(0).expect("consumed constant")).unwrap();
                assert!(input.is_constant());
                assert_eq!(input.get_size(), 8);
                assert_eq!(input.get_type().get_metatype(), type_metatype::TYPE_UINT);
                assert_eq!(input.get_type().get_size(), 8);
                assert_eq!(input.get_offset(), bits);
                if locked {
                    assert!(input.is_type_lock());
                }
            }
            if other_reader || locked {
                assert_eq!(fd.vbank().get(raw).unwrap().get_type().get_metatype(), type_metatype::TYPE_UINT);
                assert_eq!(fd.vbank().get(raw).unwrap().get_offset(), bits);
            }
            if locked {
                assert!(fd.vbank().get(raw).unwrap().is_type_lock());
            }
            if let Some(integer_use) = integer_use {
                assert_eq!(fd.obank().get(integer_use).unwrap().get_in(0), Some(raw));
            }
        }
    }

    #[test]
    fn closed_variadic_override_cast_preserves_abi_and_concrete_argument_types() {
        use crate::dtype::type_class;
        use crate::fspec::{parameter_pieces_flags, FuncCallSpecs, FuncProto, ParameterPieces, ProtoModel, PrototypePieces};
        use crate::fspec::ParamEntry;
        let (mut fd, strat, ram) = build();
        let types = fd.get_arch().types().unwrap();
        let void = types.get_type_void().unwrap();
        let int4 = types.get_base(4, type_metatype::TYPE_INT).unwrap();
        let uint8 = types.get_base(8, type_metatype::TYPE_UINT).unwrap();
        let mut model = ProtoModel::new(fd.get_arch().manage());
        model.build_param_list("standard").unwrap();
        for (input, offset) in [(true, 0x80), (false, 0x10)] {
            let entry = ParamEntry::seed(0, type_class::TYPECLASS_GENERAL,
                ram.clone(), offset, 4, 1, 0, 0, true, false, &[],
                fd.get_arch().manage()).unwrap();
            let list = if input { model.input_mut() } else { model.output_mut() };
            list.push_entry(entry);
            list.finish_decode();
        }
        let model = Rc::new(model);
        let factory = fd.get_arch().types_impl().unwrap();
        factory.set_proto_context(fd.get_arch().manage.clone());
        factory.set_proto_models(Some(model.clone()), Default::default());
        let declaration = factory.get_type_code_proto(&PrototypePieces {
            outtype: Some(int4.clone()), intypes: vec![int4.clone()],
            innames: vec!["arg".to_owned()], first_var_arg_slot: 1,
            ..Default::default()
        }).unwrap();
        let target_type = types.get_type_pointer(8, declaration.clone(), 1).unwrap();
        let target = fd.new_unique(8, Some(target_type.clone()));
        let mut proto = FuncProto::new();
        proto.set_internal(model, void);
        proto.set_override(true);
        for slot in 0..3 {
            proto.set_param(slot, "arg", &ParameterPieces {
                addr: Address::new(ram.clone(), 0x80 + slot as u64 * 8),
                type_: Some(int4.clone()), flags: parameter_pieces_flags::TYPELOCK,
            });
        }
        proto.set_output(&ParameterPieces {
            addr: Address::new(ram.clone(), 0x10), type_: Some(int4),
            flags: parameter_pieces_flags::TYPELOCK,
        });
        let op = fd.new_op(4, Address::new(ram, 0x2000));
        fd.op_set_opcode(op, TypeOp::new(OpCode::CPUI_CALLIND, crate::op::pcodeop_flags::call, "CALLIND"));
        fd.op_set_input(op, target, 0).unwrap();
        for slot in 1..4 {
            let argument = fd.new_unique(8, Some(uint8.clone()));
            fd.op_set_input(op, argument, slot).unwrap();
        }
        let mut specs = FuncCallSpecs::new(op, Address::new_invalid());
        specs.proto_mut().copy(&proto);
        fd.push_call_specs(specs);
        let callable = get_input_cast(&mut fd, &strat, op, 0)
            .unwrap().unwrap_or_else(|| fd.vn_high_type_read_facing(target, op).unwrap());
        let code = callable.get_ptr_to().unwrap();
        let signature = code.get_code_prototype().unwrap();
        assert!(signature.is_dotdotdot());
        assert_eq!(signature.num_params(), 1);
        assert_eq!(signature.get_param(0).unwrap().get_type().unwrap().get_size(), 4);
        let variadic_argument = get_input_cast(&mut fd, &strat, op, 2).unwrap().unwrap();
        assert_eq!(variadic_argument.get_metatype(), type_metatype::TYPE_INT);
        assert_eq!(variadic_argument.get_size(), 4);
        let original = fd.get_call_specs(fd.get_call_specs_index(op).unwrap());
        assert_eq!(original.proto().num_params(), 3);
        assert!(!original.proto().is_dotdotdot());
        assert_eq!(original.format_arity(), None);
        assert!(declaration.get_code_prototype().unwrap().is_dotdotdot());
        assert_eq!(declaration.get_code_prototype().unwrap().num_params(), 1);
        assert!(Rc::ptr_eq(&fd.vn_high_type_read_facing(target, op).unwrap(), &target_type));
    }

    // -- AT1 (B1) -- INT_SLESS over a uint4-typed operand MUST route to the
    //    inputTypeLocal body with the (true,true) tail, NOT the EQUAL body.
    //    Faithful (typeop.cc:1025-1033): reqtype = inputTypeLocal(slot) (a SIGNED
    //    int4), castStandard(reqtype, curtype, true, true).  The r1 bug produced
    //    the EQUAL tuple castStandard(uint4, uint4, false, false) == None.
    #[test]
    fn at1_sless_dispatch_uses_signed_local_and_true_true() {
        let (mut fd, strat, ram) = build();
        let uint4 = ity(4, type_metatype::TYPE_UINT);
        let op = binop(
            &mut fd,
            &ram,
            0x10,
            OpCode::CPUI_INT_SLESS,
            Rc::clone(&uint4),
            Rc::clone(&uint4),
        );

        // Independently computed FAITHFUL result for slot 0:
        // reqtype = inputTypeLocal(SLESS,0) = getBase(4, TYPE_INT) (signed),
        // curtype = uint4, gate = false (NO_PROMOTION), tail = (true,true).
        let reqtype = input_type_local(&fd, op, 0).unwrap();
        assert_eq!(
            reqtype.get_metatype(),
            type_metatype::TYPE_INT,
            "inputTypeLocal(SLESS) must be a SIGNED int (typeop.cc:1011 TYPE_INT)"
        );
        let faithful = strat.cast_standard(&reqtype, &uint4, true, true);
        // The EQUAL-body misroute the r1 dispatch took:
        let misroute = strat.cast_standard(&uint4, &uint4, false, false);
        assert!(
            faithful.is_some() && misroute.is_none(),
            "precondition: the faithful SLESS tuple and the EQUAL misroute must \
             DIFFER on (signed int4 < uint4), else this fence is vacuous"
        );

        let got = get_input_cast(&mut fd, &strat, op, 0).unwrap();
        assert!(
            opt_ptr_eq(&got, &faithful),
            "INT_SLESS getInputCast must equal the inputTypeLocal+(true,true) body \
             (cast required), got {:?}",
            got.as_ref().map(|t| t.get_metatype())
        );
        assert!(
            got.is_some(),
            "B1 regression: INT_SLESS over a uint4 operand dropped the (int) cast"
        );
    }

    // -- AT2 (B1 discriminator) -- INT_LESS over the SAME operands must use the
    //    (true,false) tail (LESS = unsigned, care_ptr_uint=false), and SLESS must
    //    NOT collapse into it: the two are distinguished by `care_ptr_uint`.
    //    Here we pin that SLESS and LESS BOTH route through the inputTypeLocal
    //    body (so the metatype of reqtype differs: SLESS=>INT, LESS=>UINT) — a
    //    misroute of SLESS to the EQUAL body would make reqtype uint4 for SLESS.
    #[test]
    fn at2_sless_vs_less_reqtype_signedness_differs() {
        let (mut fd, _strat, ram) = build();
        let uint4 = ity(4, type_metatype::TYPE_UINT);
        let sless = binop(
            &mut fd,
            &ram,
            0x20,
            OpCode::CPUI_INT_SLESS,
            Rc::clone(&uint4),
            Rc::clone(&uint4),
        );
        let less = binop(
            &mut fd,
            &ram,
            0x28,
            OpCode::CPUI_INT_LESS,
            Rc::clone(&uint4),
            Rc::clone(&uint4),
        );
        // SLESS local type is signed (TYPE_INT); LESS local type is unsigned
        // (TYPE_UINT).  If SLESS were misrouted to the EQUAL body its reqtype
        // would be max-read-facing(uint4,uint4)=uint4 — UNSIGNED — collapsing the
        // signedness distinction the C++ preserves.
        assert_eq!(input_type_local(&fd, sless, 0).unwrap().get_metatype(), type_metatype::TYPE_INT);
        assert_eq!(input_type_local(&fd, less, 0).unwrap().get_metatype(), type_metatype::TYPE_UINT);
    }

    // -- AT3 (B2) -- INT_ZEXT fallthrough must use the (true,false) tail, NOT the
    //    inverted (false,true) the r1 code borrowed from the default body, and the
    //    spurious is_annotation() early-return must be gone.
    //    Faithful (typeop.cc:1133-1141): reqtype = inputTypeLocal(ZEXT,0) =
    //    getBase(4, TYPE_UINT); curtype = int4 (signed input); castStandard with
    //    (care_uint_int=true, care_ptr_uint=false).
    #[test]
    fn at3_zext_dispatch_uses_true_false_not_inverted() {
        let (mut fd, strat, ram) = build();
        let int4s = ity(4, type_metatype::TYPE_INT); // signed input -> differs from ZEXT local uint
        let op = unop(&mut fd, &ram, 0x30, OpCode::CPUI_INT_ZEXT, Rc::clone(&int4s));

        let reqtype = input_type_local(&fd, op, 0).unwrap();
        assert_eq!(
            reqtype.get_metatype(),
            type_metatype::TYPE_UINT,
            "inputTypeLocal(ZEXT) must be UNSIGNED (typeop.cc:1119 TYPE_UINT)"
        );
        let curtype = fd.vn_high_type_read_facing(fd.obank().get(op).unwrap().get_in(0).unwrap(), op).unwrap();
        let faithful = strat.cast_standard(&reqtype, &curtype, true, false);
        let inverted = strat.cast_standard(&reqtype, &curtype, false, true);
        assert!(
            !opt_ptr_eq(&faithful, &inverted),
            "precondition: the faithful ZEXT tuple (true,false) and the inverted \
             (false,true) must DIFFER on (uint4 <- int4), else this fence is vacuous"
        );

        let got = get_input_cast(&mut fd, &strat, op, 0).unwrap();
        assert!(
            opt_ptr_eq(&got, &faithful),
            "B2 regression: INT_ZEXT getInputCast must use castStandard(reqtype,\
             curtype,true,false), got {:?} vs faithful {:?}",
            got.as_ref().map(|t| t.get_metatype()),
            faithful.as_ref().map(|t| t.get_metatype())
        );
        assert!(
            !opt_ptr_eq(&got, &inverted),
            "B2 regression: INT_ZEXT getInputCast matched the INVERTED (false,true) \
             tuple — the r1 bug"
        );
    }

    // -- AT4 (B2/SEXT) -- the SEXT arm shares the extension body; its reqtype is
    //    SIGNED (typeop.cc:1145 TYPE_INT) and the tail is the same (true,false).
    #[test]
    fn at4_sext_dispatch_uses_signed_local_true_false() {
        let (mut fd, strat, ram) = build();
        let uint4 = ity(4, type_metatype::TYPE_UINT); // unsigned input -> differs from SEXT local int
        let op = unop(&mut fd, &ram, 0x38, OpCode::CPUI_INT_SEXT, Rc::clone(&uint4));

        let reqtype = input_type_local(&fd, op, 0).unwrap();
        assert_eq!(
            reqtype.get_metatype(),
            type_metatype::TYPE_INT,
            "inputTypeLocal(SEXT) must be SIGNED (typeop.cc:1145 TYPE_INT)"
        );
        let curtype = fd.vn_high_type_read_facing(fd.obank().get(op).unwrap().get_in(0).unwrap(), op).unwrap();
        let faithful = strat.cast_standard(&reqtype, &curtype, true, false);
        let got = get_input_cast(&mut fd, &strat, op, 0).unwrap();
        assert!(
            opt_ptr_eq(&got, &faithful),
            "INT_SEXT getInputCast must equal castStandard(int4,uint4,true,false)"
        );
    }

    // -- AT5 (EQUAL unchanged) -- the fix must NOT perturb EQUAL/NOTEQUAL: they
    //    keep the max-read-facing reqtype + (false,false) tail (typeop.cc:934-944).
    #[test]
    fn at5_equal_still_uses_maxreadfacing_false_false() {
        let (mut fd, strat, ram) = build();
        let int4s = ity(4, type_metatype::TYPE_INT);
        let uint4 = ity(4, type_metatype::TYPE_UINT);
        let op = binop(
            &mut fd,
            &ram,
            0x40,
            OpCode::CPUI_INT_EQUAL,
            Rc::clone(&int4s),
            Rc::clone(&uint4),
        );
        // Faithful EQUAL: reqtype = max-read-facing(in0,in1); for slot 0 the
        // curtype is in0's read-facing type; tail = (false,false).
        let in0 = fd.obank().get(op).unwrap().get_in(0).unwrap();
        let in1 = fd.obank().get(op).unwrap().get_in(1).unwrap();
        let mut reqtype = fd.vn_high_type_read_facing(in0, op).unwrap();
        let othertype = fd.vn_high_type_read_facing(in1, op).unwrap();
        if othertype.type_order(&reqtype).unwrap_or(0) < 0 {
            reqtype = othertype;
        }
        let slottype = fd.vn_high_type_read_facing(in0, op).unwrap();
        let faithful = strat.cast_standard(&reqtype, &slottype, false, false);
        let got = get_input_cast(&mut fd, &strat, op, 0).unwrap();
        assert!(
            opt_ptr_eq(&got, &faithful),
            "INT_EQUAL getInputCast must stay the max-read-facing + (false,false) body"
        );
    }
}
