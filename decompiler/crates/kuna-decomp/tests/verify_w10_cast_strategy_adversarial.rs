//! Boundary tests for the production extension-promotion predicates.
//!
//! A missing reader, an oversized constant, and a mismatched operand type
//! require an explicit extension rather than hiding it through promotion.

use std::rc::Rc;

use kuna_decomp::cast::{CastContext, CastStrategy, CastStrategyC, OpRef, VnRef};
use kuna_decomp::dtype::{type_metatype, Datatype, TypeRoot, TypeFactoryImpl};
use kuna_num::opcodes::OpCode;

#[allow(non_camel_case_types)]
type int4 = i32;
#[allow(non_camel_case_types)]
type uintb = u64;

// -- data-type builders (mirror cast/tests.rs) ------------------------------

fn base(f: &TypeFactoryImpl, size: int4, meta: type_metatype) -> TypeRoot {
    f.intern(Datatype::new(size, meta)).unwrap()
}
fn int_t(f: &TypeFactoryImpl, size: int4) -> TypeRoot {
    base(f, size, type_metatype::TYPE_INT)
}
fn uint_t(f: &TypeFactoryImpl, size: int4) -> TypeRoot {
    base(f, size, type_metatype::TYPE_UINT)
}

/// `CastStrategyC` with `promoteSize == 4` (the x86:LE:64 `int` size).
fn factory() -> Rc<TypeFactoryImpl> {
    let f = TypeFactoryImpl::new();
    f.set_default_alignment_map();
    f.set_max_basetype_size(8);
    f.setup_sizes(Some(4), 8, 8);
    Rc::new(f)
}

fn strategy_c(f: &Rc<TypeFactoryImpl>) -> CastStrategyC {
    CastStrategyC::new(f.clone())
}

// -- mock CastContext (mirrors cast/tests.rs MockCtx) -----------------------

struct MockVn {
    size: int4,
    offset: uintb,
    ty: TypeRoot,
    constant: bool,
    explicit: bool,
    written: bool,
    def: Option<OpRef>,
}
struct MockOp {
    code: OpCode,
    ins: Vec<VnRef>,
    out: Option<VnRef>,
}
struct MockCtx {
    vns: Vec<MockVn>,
    ops: Vec<MockOp>,
}
impl MockCtx {
    fn new() -> MockCtx {
        MockCtx { vns: Vec::new(), ops: Vec::new() }
    }
    fn add_var(&mut self, size: int4, ty: TypeRoot) -> VnRef {
        let id = self.vns.len();
        self.vns.push(MockVn {
            size,
            offset: 0,
            ty,
            constant: false,
            explicit: false,
            written: false,
            def: None,
        });
        VnRef(id)
    }
    fn add_const(&mut self, size: int4, offset: uintb, ty: TypeRoot) -> VnRef {
        let v = self.add_var(size, ty);
        self.vns[v.0].constant = true;
        self.vns[v.0].offset = offset;
        v
    }
    fn set_explicit(&mut self, v: VnRef, val: bool) {
        self.vns[v.0].explicit = val;
    }
    fn add_op(&mut self, code: OpCode, ins: Vec<VnRef>, out: Option<VnRef>) -> OpRef {
        let id = self.ops.len();
        let op = OpRef(id);
        if let Some(o) = out {
            self.vns[o.0].written = true;
            self.vns[o.0].def = Some(op);
        }
        self.ops.push(MockOp { code, ins, out });
        op
    }
}
impl CastContext for MockCtx {
    fn op_code(&self, op: OpRef) -> OpCode {
        self.ops[op.0].code
    }
    fn op_num_input(&self, op: OpRef) -> int4 {
        self.ops[op.0].ins.len() as int4
    }
    fn op_in(&self, op: OpRef, slot: int4) -> VnRef {
        self.ops[op.0].ins[slot as usize]
    }
    fn op_out(&self, op: OpRef) -> Option<VnRef> {
        self.ops[op.0].out
    }
    fn op_slot(&self, op: OpRef, vn: VnRef) -> int4 {
        self.ops[op.0].ins.iter().position(|v| *v == vn).unwrap() as int4
    }
    fn vn_is_constant(&self, vn: VnRef) -> bool {
        self.vns[vn.0].constant
    }
    fn vn_is_explicit(&self, vn: VnRef) -> bool {
        self.vns[vn.0].explicit
    }
    fn vn_is_written(&self, vn: VnRef) -> bool {
        self.vns[vn.0].written
    }
    fn vn_size(&self, vn: VnRef) -> int4 {
        self.vns[vn.0].size
    }
    fn vn_offset(&self, vn: VnRef) -> uintb {
        self.vns[vn.0].offset
    }
    fn vn_def(&self, vn: VnRef) -> Option<OpRef> {
        self.vns[vn.0].def
    }
    fn vn_lone_descend(&self, _vn: VnRef) -> Option<OpRef> {
        None
    }
    fn vn_high_type(&self, vn: VnRef) -> TypeRoot {
        Clone::clone(&self.vns[vn.0].ty)
    }
    fn vn_high_type_read_facing(&self, vn: VnRef, _op: OpRef) -> TypeRoot {
        Clone::clone(&self.vns[vn.0].ty)
    }
    fn op_inherits_sign(&self, op: OpRef) -> bool {
        kuna_decomp::typeop::type_op_info(self.ops[op.0].code).inherits_sign()
    }
    fn op_inherits_sign_first_param_only(&self, op: OpRef) -> bool {
        kuna_decomp::typeop::type_op_info(self.ops[op.0].code).inherits_sign_first_param_only()
    }
    fn op_is_shift_op(&self, op: OpRef) -> bool {
        kuna_decomp::typeop::type_op_info(self.ops[op.0].code).is_shift_op()
    }
    fn op_is_bool_output(&self, _op: OpRef) -> bool {
        false
    }
    fn op_is_call(&self, _op: OpRef) -> bool {
        false
    }
    fn vn_set_unsigned_print(&mut self, _vn: VnRef) {
        unreachable!("not used by isExtensionCastImplied");
    }
    fn vn_set_long_print(&mut self, _vn: VnRef) {
        unreachable!("not used by isExtensionCastImplied");
    }
}

/// Build a `out = ZEXT(in0)` op whose output is read by `read = readcode(out, other)`.
/// Returns (ctx, zext_op, read_op).  The ZEXT output is left non-explicit so the
/// "implied" arm is reachable; `other` is whatever the caller wired in.
fn zext_read_by(f: &TypeFactoryImpl, 
    out_ty: TypeRoot,
    in_ty: TypeRoot,
    in_size: int4,
    out_size: int4,
    readcode: OpCode,
    other: impl FnOnce(&mut MockCtx) -> VnRef,
) -> (MockCtx, OpRef, OpRef) {
    let mut ctx = MockCtx::new();
    let invn = ctx.add_var(in_size, in_ty);
    let outvn = ctx.add_var(out_size, out_ty);
    let zext = ctx.add_op(OpCode::CPUI_INT_ZEXT, vec![invn], Some(outvn));
    let othervn = other(&mut ctx);
    // out is read by `read = out <readcode> other`; result type matches `out`.
    let resty = uint_t(f, out_size);
    let resvn = ctx.add_var(out_size, resty);
    let read = ctx.add_op(readcode, vec![outvn, othervn], Some(resvn));
    (ctx, zext, read)
}

// ===========================================================================

/// (V2) readOp == null (top of statement): `isExtensionCastImplied` returns false
/// for a NON-explicit output when there is no reader (cast.cc:255).  So the
/// genuine zext-cast renders as the EXPLICIT `(uintN)` cast at statement top, and
/// is only ever hidden when threaded a real reader.  This pins the printc seam
/// that passes `None` at printc.cc:2579.
#[test]
fn w10_cast_strategy_null_readop_never_hidden() {
    let f = &factory();
    let strat = strategy_c(f);
    // out uint8, in uint4 -> isZextCast true.  Output NON-explicit.
    let mut ctx = MockCtx::new();
    let invn = ctx.add_var(4, uint_t(f, 4));
    let outvn = ctx.add_var(8, uint_t(f, 8));
    let zext = ctx.add_op(OpCode::CPUI_INT_ZEXT, vec![invn], Some(outvn));
    assert!(!ctx.vn_is_explicit(outvn), "precondition: output non-explicit");

    // There is no promotion context at the top of a statement.
    assert!(!strat.is_extension_cast_implied(&ctx, zext, None));
}

/// (V3) The big-constant boundary in `isExtensionCastImplied` (cast.cc:281-284):
/// when the extension's reader is an integer op whose OTHER operand is a CONSTANT,
/// the extension is implied (hidden) only if that constant is NOT bigger than the
/// promotion size.  At `size == promoteSize` it is still implied (hidden); at
/// `size == promoteSize + 1` (`> promoteSize`) it flips to NOT implied -> the
/// cast must be explicit.  This is the off-by-one the hunt list flags for the
/// `getSize() > promoteSize` compare (promoteSize == 4 here).
#[test]
fn w10_cast_strategy_big_constant_boundary_flips_implied() {
    let f = &factory();
    let strat = strategy_c(f);
    let promote = strat.promote_size();
    assert_eq!(promote, 4);

    // out=uint8 = ZEXT(uint4 in); read = out + const(size).  metatype(out)=UINT.
    // The other operand is a UINT constant so its metatype matches.
    let build = |const_size: int4| {
        zext_read_by(f, 
            uint_t(f, 8),
            uint_t(f, 4),
            4,
            8,
            OpCode::CPUI_INT_ADD,
            move |c| c.add_const(const_size, 7, uint_t(f, const_size)),
        )
    };

    // const size == promoteSize (4): NOT bigger -> implied -> Hidden (hide on).
    let (ctx_eq, zext_eq, read_eq) = build(promote);
    assert!(
        strat.is_extension_cast_implied(&ctx_eq, zext_eq, Some(read_eq)),
        "const at exactly promoteSize must be implied (boundary inclusive)"
    );

    // const size == promoteSize + 1 (5 > 4): bigger -> NOT implied -> Cast.
    let (ctx_gt, zext_gt, read_gt) = build(promote + 1);
    assert!(
        !strat.is_extension_cast_implied(&ctx_gt, zext_gt, Some(read_gt)),
        "const strictly bigger than promoteSize must NOT be implied"
    );
}

/// (V5, bonus) Metatype-mismatch reader: if the OTHER operand's metatype differs
/// from the extension output's metatype, the extension is NOT implied
/// (cast.cc:289-290) -> explicit cast.  Pins the "right integer type" check the
/// wiring relies on the unchanged predicate for.
#[test]
fn w10_cast_strategy_metatype_mismatch_not_implied() {
    let f = &factory();
    let strat = strategy_c(f);
    // out is UINT8; other operand is an explicit INT8 (signed) -> metatype differs.
    let (ctx, zext, read) = zext_read_by(f, 
        uint_t(f, 8),
        uint_t(f, 4),
        4,
        8,
        OpCode::CPUI_INT_ADD,
        |c| {
            let v = c.add_var(8, int_t(f, 8)); // signed, mismatched metatype
            c.set_explicit(v, true);
            v
        },
    );
    assert!(
        !strat.is_extension_cast_implied(&ctx, zext, Some(read)),
        "a mismatched-metatype other operand must defeat the implied test"
    );
}
