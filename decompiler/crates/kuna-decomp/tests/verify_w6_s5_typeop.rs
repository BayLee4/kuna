//! Adversarial verifier tests for item `w6-s5-typeop` (the canonical `TypeOp`
//! information table ported from `decompiler/cpp/typeop.{cc,hh}`).
//!
//! These tests exercise public behavior derived from the C++ semantics and
//! target the spots most likely to hide a faithful-port bug for this item:
//!
//!   * **Integer width sensitivity of `floatSignManipulation`.**  The sign mask is
//!     `calc_mask(size)`, so the recognized constant is width-specific; a size-4
//!     AND must match the 4-byte mask and must NOT match the 8-byte mask.  The
//!     porter's test only exercises size 8.  F-V2 pins the per-width boundary.
//!   * **`selectJavaOperators` blast radius.**  C++ touches exactly six op-codes
//!     (ZEXT, NEGATE, XOR, OR, AND, RIGHT).  A port that mutates one extra slot is
//!     silent corruption.  F-V3 snapshots the whole table and asserts only those
//!     six records differ.
//!   * **Per-op `getInputLocal`/`getOutputLocal` size-only overrides.**  F-V4
//!     checks the metatype each (opcode, slot) produces.
//!
//! C++ oracle anchors are cited inline.

use kuna_base::address::calc_mask;
use kuna_decomp::dtype::{type_metatype, TypeFactoryImpl};
use kuna_decomp::typeop::{
    float_sign_manipulation, register_instructions, select_java_operators, type_op_info,
    TypeOpInfo,
};
use kuna_num::opcodes::OpCode;
use type_metatype::*;

fn factory() -> TypeFactoryImpl {
    let f = TypeFactoryImpl::new();
    f.set_default_alignment_map();
    f.set_max_basetype_size(8);
    f
}

/// `floatSignManipulation` recognizes a width-specific constant.  Re-derive the
/// recognized offsets from `calc_mask(size)` for sizes 1,2,4,8 and assert the
/// match is exactly width-keyed: the right mask -> ABS/NEG, a different-width mask
/// -> CPUI_MAX.  cpp: decompiler/cpp/typeop.cc:154-177.
#[test]
fn v2_float_sign_manipulation_is_width_specific() {
    for &sz in &[1i32, 2, 4, 8] {
        let mask = calc_mask(sz);
        let abs_off = mask >> 1; // INT_AND sign-clear constant for this width
        let neg_off = mask ^ (mask >> 1); // INT_XOR sign-flip constant (== top bit)

        assert_eq!(
            float_sign_manipulation(OpCode::CPUI_INT_AND, Some((sz, abs_off))),
            OpCode::CPUI_FLOAT_ABS,
            "size {sz}: AND {abs_off:#x} should be FLOAT_ABS"
        );
        assert_eq!(
            float_sign_manipulation(OpCode::CPUI_INT_XOR, Some((sz, neg_off))),
            OpCode::CPUI_FLOAT_NEG,
            "size {sz}: XOR {neg_off:#x} should be FLOAT_NEG"
        );

        // A constant valid for a *different* width must not be recognized at this
        // width (unless the masks happen to coincide, which only the same size
        // does).  Use the size-8 sign constants against the smaller widths.
        if sz != 8 {
            let mask8 = calc_mask(8);
            let abs8 = mask8 >> 1; // 0x7fff_ffff_ffff_ffff
            let neg8 = mask8 ^ (mask8 >> 1); // 0x8000_0000_0000_0000
            assert_eq!(
                float_sign_manipulation(OpCode::CPUI_INT_AND, Some((sz, abs8))),
                OpCode::CPUI_MAX,
                "size {sz}: the 8-byte AND mask must not match"
            );
            assert_eq!(
                float_sign_manipulation(OpCode::CPUI_INT_XOR, Some((sz, neg8))),
                OpCode::CPUI_MAX,
                "size {sz}: the 8-byte XOR sign bit must not match"
            );
        }
    }
    // Cross-op confusion: the AND constant fed to XOR (and vice-versa) must not
    // accidentally match at size 8 (abs_off != neg_off there).
    let mask8 = calc_mask(8);
    assert_eq!(
        float_sign_manipulation(OpCode::CPUI_INT_XOR, Some((8, mask8 >> 1))),
        OpCode::CPUI_MAX
    );
    assert_eq!(
        float_sign_manipulation(OpCode::CPUI_INT_AND, Some((8, mask8 ^ (mask8 >> 1)))),
        OpCode::CPUI_MAX
    );
}

/// `selectJavaOperators` must mutate exactly the six op-codes the C++ touches and
/// leave every other record byte-identical.  Snapshot the full table, flip to
/// Java, and diff: only ZEXT/NEGATE/XOR/OR/AND/RIGHT may change.  Then flip back
/// and assert a full round-trip to the C state.
/// cpp: decompiler/cpp/typeop.cc:115-148.
#[test]
fn v3_select_java_operators_blast_radius() {
    fn key(r: &TypeOpInfo) -> (u32, type_metatype, type_metatype, &'static str) {
        (r.opcode as u32, r.metaout, r.metain, r.name)
    }
    let touched: [OpCode; 6] = [
        OpCode::CPUI_INT_ZEXT,
        OpCode::CPUI_INT_NEGATE,
        OpCode::CPUI_INT_XOR,
        OpCode::CPUI_INT_OR,
        OpCode::CPUI_INT_AND,
        OpCode::CPUI_INT_RIGHT,
    ];

    let before: Vec<Option<TypeOpInfo>> = register_instructions();
    let mut java = before.clone();
    select_java_operators(&mut java, true);

    for idx in 0..before.len() {
        match (before[idx], java[idx]) {
            (Some(b), Some(a)) => {
                let opc = b.opcode;
                if touched.contains(&opc) {
                    assert_ne!(
                        key(&b),
                        key(&a),
                        "{opc:?} is a Java-touched op but did not change"
                    );
                } else {
                    assert_eq!(key(&b), key(&a), "{opc:?} must be untouched by Java toggle");
                    // opflags/addlflags/class are never touched by the toggle.
                    assert_eq!(b.opflags, a.opflags);
                    assert_eq!(b.addlflags, a.addlflags);
                    assert_eq!(b.class, a.class);
                }
            }
            (None, None) => {}
            _ => panic!("slot {idx} changed null-ness across the Java toggle"),
        }
    }

    // Round-trip: flipping back to C restores every field exactly.
    select_java_operators(&mut java, false);
    for idx in 0..before.len() {
        match (before[idx], java[idx]) {
            (Some(b), Some(a)) => assert_eq!(
                key(&b),
                key(&a),
                "{:?} not restored after Java->C round-trip",
                b.opcode
            ),
            (None, None) => {}
            _ => panic!("slot {idx} null-ness diverged after round-trip"),
        }
    }
}

/// Re-derive the metatype each per-op `getInputLocal`/`getOutputLocal` override
/// produces straight from the C++ override bodies.
#[test]
fn v4_local_type_overrides_metatype_rederived() {
    let f = factory();
    let mout = |opc: OpCode, sz: i32| type_op_info(opc).get_output_local(&f, sz).unwrap().get_metatype();
    let min = |opc: OpCode, slot: i32, sz: i32| {
        type_op_info(opc).get_input_local(&f, slot, sz).unwrap().get_metatype()
    };

    // PTRADD/PTRSUB: both in and out forced to INT regardless of class (Base).
    // (typeop.cc:2234-2244, 2310-2320)
    assert_eq!(mout(OpCode::CPUI_PTRADD, 8), TYPE_INT);
    assert_eq!(min(OpCode::CPUI_PTRADD, 2, 8), TYPE_INT, "PTRADD slot 2 (the element-size operand) -> INT");
    assert_eq!(mout(OpCode::CPUI_PTRSUB, 8), TYPE_INT);
    assert_eq!(min(OpCode::CPUI_PTRSUB, 0, 8), TYPE_INT);

    // Shift slot 1 -> INT via getBaseNoChar; slot 0 -> the binary metain.
    // INT_LEFT metain INT, INT_RIGHT metain UINT, INT_SRIGHT metain INT.
    // (typeop.cc:1512-1518, 1537-1543, 1602-1608)
    assert_eq!(min(OpCode::CPUI_INT_LEFT, 1, 4), TYPE_INT);
    assert_eq!(min(OpCode::CPUI_INT_LEFT, 0, 4), TYPE_INT);
    assert_eq!(min(OpCode::CPUI_INT_RIGHT, 1, 4), TYPE_INT, "shift count is INT even though metain is UINT");
    assert_eq!(min(OpCode::CPUI_INT_RIGHT, 0, 4), TYPE_UINT);
    assert_eq!(min(OpCode::CPUI_INT_SRIGHT, 1, 4), TYPE_INT);
    assert_eq!(min(OpCode::CPUI_INT_SRIGHT, 0, 4), TYPE_INT);

    // CPOOLREF input -> INT (typeop.cc:2467-2471).
    assert_eq!(min(OpCode::CPUI_CPOOLREF, 0, 4), TYPE_INT);

    // CBRANCH slot 1 -> BOOL (typeop.cc:613-617).
    assert_eq!(min(OpCode::CPUI_CBRANCH, 1, 1), TYPE_BOOL);

    // INSERT slots <=1 -> UNKNOWN, slot 2 -> Func metain INT (typeop.cc:2537-2543).
    assert_eq!(min(OpCode::CPUI_INSERT, 0, 4), TYPE_UNKNOWN);
    assert_eq!(min(OpCode::CPUI_INSERT, 1, 4), TYPE_UNKNOWN);
    assert_eq!(min(OpCode::CPUI_INSERT, 2, 4), TYPE_INT);

    // ZPULL/SPULL slot 0 -> UNKNOWN, other slots -> Func metain.
    // ZPULL metain INT, SPULL metain INT (typeop.cc:2564-2569, 2591-2596).
    assert_eq!(min(OpCode::CPUI_ZPULL, 0, 4), TYPE_UNKNOWN);
    assert_eq!(min(OpCode::CPUI_ZPULL, 2, 4), TYPE_INT);
    assert_eq!(min(OpCode::CPUI_SPULL, 0, 4), TYPE_UNKNOWN);
    assert_eq!(min(OpCode::CPUI_SPULL, 1, 4), TYPE_INT);

    // A pure Func op with no override: POPCOUNT out INT, in UNKNOWN
    // (typeop.cc:2611-2616) — confirms the default Func arm path is reached.
    assert_eq!(mout(OpCode::CPUI_POPCOUNT, 4), TYPE_INT);
    assert_eq!(min(OpCode::CPUI_POPCOUNT, 0, 4), TYPE_UNKNOWN);
}

