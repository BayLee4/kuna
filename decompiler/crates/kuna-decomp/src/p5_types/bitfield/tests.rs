//! Tests for the bitfield placement/recovery machinery (item w6-s5-bitfield).
//!
//! The "extraction/placement matrix" is exercised against ground-truth values
//! generated from the C++ `BitRange` (address.cc:630-868) so the port is pinned
//! field-by-field. Graph-backed rule tests exercise registration filtering
//! alongside enabled insertion, extraction, and absorption transforms.

use super::*;
use crate::action::Rule;

// =============================================================================
// BitRange: extraction/placement matrix
// =============================================================================

#[test]
fn bitrange_byte_range_ctor() {
    let r = BitRange::byte_range(0, 8, false);
    assert_eq!(r.byte_offset, 0);
    assert_eq!(r.byte_size, 8);
    assert_eq!(r.least_sig_bit, 0);
    assert_eq!(r.num_bits, 64);
    assert!(!r.is_big_endian);
}

#[test]
fn bitrange_undefined_sentinel() {
    let r = BitRange::undefined();
    assert_eq!(r.byte_offset, -1);
    assert_eq!(r.byte_size, -1);
    assert_eq!(r.least_sig_bit, -1);
    assert_eq!(r.num_bits, -1);
    assert!(!r.is_big_endian);
}

#[test]
fn bitrange_empty() {
    assert!(BitRange::new(0, 8, 0, 0, false).empty());
    assert!(BitRange::new(0, 8, 0, -1, false).empty());
    assert!(!BitRange::new(0, 8, 0, 1, false).empty());
}

#[test]
fn bitrange_get_mask() {
    // address.cc:816-829 — oracle from /tmp/bitcheck.
    assert_eq!(BitRange::byte_range(0, 8, false).get_mask(), 0xffff_ffff_ffff_ffff);
    assert_eq!(BitRange::new(0, 8, 4, 5, false).get_mask(), 0x1f0);
    // numBits >= 64 => res starts at 0, then -1 (all ones), then << leastSigBit.
    assert_eq!(BitRange::new(0, 8, 0, 64, false).get_mask(), 0xffff_ffff_ffff_ffff);
    assert_eq!(BitRange::new(0, 8, 4, 64, false).get_mask(), 0xffff_ffff_ffff_fff0);
}

#[test]
fn bitrange_translate_lsb() {
    // address.cc:660-673 — oracle from /tmp/bitcheck.
    let le_cont = BitRange::byte_range(0, 8, false);
    let le_field = BitRange::new(2, 2, 0, 16, false);
    assert_eq!(le_cont.translate_lsb(&le_field), 16);

    let be_cont = BitRange::byte_range(0, 8, true);
    let be_field = BitRange::new(2, 2, 0, 16, true);
    assert_eq!(be_cont.translate_lsb(&be_field), 32);
}

#[test]
fn bitrange_in_container() {
    // address.cc:630-638 — oracle from /tmp/bitcheck2.
    let le_field = BitRange::new(2, 2, 0, 16, false);
    let le = BitRange::in_container(&le_field, 0, 8);
    assert_eq!((le.byte_offset, le.byte_size, le.least_sig_bit, le.num_bits), (0, 8, 16, 16));

    let be_field = BitRange::new(2, 2, 0, 16, true);
    let be = BitRange::in_container(&be_field, 0, 8);
    assert_eq!((be.byte_offset, be.byte_size, be.least_sig_bit, be.num_bits), (0, 8, 32, 16));
    assert!(be.is_big_endian);
}

#[test]
fn bitrange_overlap_test_little_endian() {
    // address.cc:685-704 — oracle from /tmp/bitcheck.
    let x = BitRange::new(0, 4, 0, 8, false); // bits [0,8)
    let y = BitRange::new(0, 4, 8, 8, false); // bits [8,16)
    assert_eq!(x.overlap_test(&x), 0); // identical
    assert_eq!(x.overlap_test(&y), -1); // x before y (LE)

    let z = BitRange::new(0, 4, 4, 8, false); // bits [4,12)
    assert_eq!(x.overlap_test(&z), 4); // partial
    assert_eq!(z.overlap_test(&x), 4); // partial

    let big = BitRange::new(0, 4, 0, 16, false);
    let small = BitRange::new(0, 4, 4, 4, false);
    assert_eq!(big.overlap_test(&small), 3); // small contained in big
    assert_eq!(small.overlap_test(&big), 2); // small contained in big
}

#[test]
fn bitrange_overlap_test_big_endian() {
    // address.cc:691-694 — oracle from /tmp/bitcheck.
    let be1 = BitRange::new(0, 4, 0, 8, true);
    let be2 = BitRange::new(0, 4, 8, 8, true);
    assert_eq!(be1.overlap_test(&be2), 1); // be1 after be2 (BE branch)
}

#[test]
fn bitrange_intersection() {
    // address.cc:709-726 — oracle from /tmp/bitcheck3.
    let mut a = BitRange::new(0, 8, 8, 16, false); // [8,24)
    a.intersection(&BitRange::new(0, 8, 12, 8, false)); // [12,20)
    assert_eq!((a.least_sig_bit, a.num_bits), (12, 8));

    let mut b = BitRange::new(0, 8, 0, 8, false); // [0,8)
    b.intersection(&BitRange::new(0, 8, 16, 8, false)); // [16,24) disjoint
    assert_eq!((b.least_sig_bit, b.num_bits), (0, 0));
}

#[test]
fn bitrange_intersect_mask() {
    // address.cc:731-750 — oracle from /tmp/bitcheck.
    let mut c = BitRange::new(0, 8, 0, 64, false);
    c.intersect_mask(0x00f0);
    assert_eq!((c.least_sig_bit, c.num_bits), (4, 4));

    let mut c2 = BitRange::new(0, 8, 0, 64, false);
    c2.intersect_mask(0x0);
    assert_eq!((c2.least_sig_bit, c2.num_bits), (0, 0));

    let mut c3 = BitRange::new(0, 8, 8, 16, false); // [8,24)
    c3.intersect_mask(0x00ff_0000); // bits [16,24)
    assert_eq!((c3.least_sig_bit, c3.num_bits), (16, 8));
}

#[test]
fn bitrange_shift() {
    // address.cc:754-770 — oracle from /tmp/bitcheck.
    let mut s1 = BitRange::new(0, 8, 0, 8, false);
    s1.shift(4);
    assert_eq!((s1.least_sig_bit, s1.num_bits), (4, 8));

    let mut s2 = BitRange::new(0, 8, 0, 8, false);
    s2.shift(-4);
    assert_eq!((s2.least_sig_bit, s2.num_bits), (0, 4));

    // shift past container end (1-byte container) clamps numBits.
    let mut s3 = BitRange::new(0, 1, 0, 8, false);
    s3.shift(4);
    assert_eq!((s3.least_sig_bit, s3.num_bits), (4, 4));
}

#[test]
fn bitrange_truncate_bytes() {
    // address.cc:774-802 — oracle from /tmp/bitcheck2.
    let mut tm = BitRange::new(0, 4, 8, 16, false);
    tm.truncate_most_sig_bytes(1);
    assert_eq!((tm.byte_offset, tm.byte_size, tm.least_sig_bit, tm.num_bits), (0, 3, 8, 16));

    let mut tl = BitRange::new(0, 4, 8, 16, false);
    tl.truncate_least_sig_bytes(1);
    assert_eq!((tl.byte_offset, tl.byte_size, tl.least_sig_bit, tl.num_bits), (1, 3, 0, 16));

    let mut tmb = BitRange::new(0, 4, 8, 16, true);
    tmb.truncate_most_sig_bytes(1);
    assert_eq!((tmb.byte_offset, tmb.byte_size, tmb.least_sig_bit, tmb.num_bits), (1, 3, 8, 16));

    let mut tlb = BitRange::new(0, 4, 8, 16, true);
    tlb.truncate_least_sig_bytes(1);
    assert_eq!((tlb.byte_offset, tlb.byte_size, tlb.least_sig_bit, tlb.num_bits), (0, 3, 0, 16));
}

#[test]
fn bitrange_extend_bytes() {
    // address.cc:806-812 — oracle from /tmp/bitcheck2.
    let mut e = BitRange::new(2, 2, 0, 16, false);
    e.extend_bytes(2);
    assert_eq!((e.byte_offset, e.byte_size), (2, 4));

    let mut eb = BitRange::new(2, 2, 0, 16, true);
    eb.extend_bytes(2);
    assert_eq!((eb.byte_offset, eb.byte_size), (0, 4));
}

#[test]
fn bitrange_is_byte_range() {
    // address.cc:832-838 — oracle from /tmp/bitcheck2.
    assert!(BitRange::new(0, 4, 8, 16, false).is_byte_range());
    assert!(!BitRange::new(0, 4, 4, 16, false).is_byte_range());
    assert!(!BitRange::new(0, 4, 8, 7, false).is_byte_range());
}

#[test]
fn bitrange_is_most_significant() {
    // address.cc:841-845 — oracle from /tmp/bitcheck2.
    assert!(BitRange::new(0, 4, 24, 8, false).is_most_significant());
    assert!(!BitRange::new(0, 4, 20, 8, false).is_most_significant());
}

#[test]
fn bitrange_minimize_container() {
    // address.cc:847-862 — oracle from /tmp/bitcheck.
    let mut m1 = BitRange::new(0, 8, 16, 8, false);
    m1.minimize_container();
    assert_eq!((m1.byte_offset, m1.byte_size, m1.least_sig_bit, m1.num_bits), (2, 1, 0, 8));

    let mut m2 = BitRange::new(0, 8, 20, 5, false);
    m2.minimize_container();
    assert_eq!((m2.byte_offset, m2.byte_size, m2.least_sig_bit, m2.num_bits), (2, 2, 4, 5));
}

#[test]
fn bitrange_expand_to_most() {
    // address.cc:864-868.
    let mut r = BitRange::new(0, 4, 8, 4, false);
    r.expand_to_most();
    // numBits = 8*4 - 8 = 24.
    assert_eq!(r.num_bits, 24);
}

#[test]
fn bitrange_compare_total_order() {
    // address.cc:643-655 — total order over (byteOffset, byteSize, leastSigBit,
    // numBits).  Each field is a strict tie-break in declaration order.
    let base = BitRange::new(1, 2, 3, 4, false);
    assert_eq!(base.compare(&base), 0);
    // byteOffset dominates.
    assert_eq!(base.compare(&BitRange::new(2, 0, 0, 0, false)), -1);
    assert_eq!(base.compare(&BitRange::new(0, 9, 9, 9, false)), 1);
    // byteSize tie-break.
    assert_eq!(base.compare(&BitRange::new(1, 3, 0, 0, false)), -1);
    assert_eq!(base.compare(&BitRange::new(1, 1, 9, 9, false)), 1);
    // leastSigBit tie-break.
    assert_eq!(base.compare(&BitRange::new(1, 2, 4, 0, false)), -1);
    assert_eq!(base.compare(&BitRange::new(1, 2, 2, 9, false)), 1);
    // numBits tie-break.
    assert_eq!(base.compare(&BitRange::new(1, 2, 3, 5, false)), -1);
    assert_eq!(base.compare(&BitRange::new(1, 2, 3, 3, false)), 1);
    // isBigEndian is NOT part of compare (matches C++).
    assert_eq!(base.compare(&BitRange::new(1, 2, 3, 4, true)), 0);
}

// =============================================================================
// BitFieldNodeState
// =============================================================================

/// A null `VarnodeId` handle — the `BitFieldNodeState` tests exercise only the
/// pure bit-range arithmetic, never dereferencing `node`.
fn vn() -> VarnodeId {
    VarnodeId::default()
}

/// Build a `TypeBitField` whose `bits()` matches `field_bits` and whose
/// underlying type has the given metatype.  The transforms only read
/// `field->type->getMetatype()` and `field->bits.numBits`/range off the field.
fn bf(field_bits: &BitRange, meta: type_metatype) -> (TypeBitField, TypeRoot) {
    use crate::dtype::TypeBitField as TBF;
    let types = TypeFactoryImpl::new();
    let owner = types.intern(Datatype::new(field_bits.byte_size.max(1), meta)).unwrap();
    let mut f = TBF::new(0, field_bits.num_bits, field_bits.is_big_endian, "f",
        owner.id());
    f.byte_offset = field_bits.byte_offset;
    f.byte_size = field_bits.byte_size;
    f.least_sig_bit = field_bits.least_sig_bit;
    (f, owner)
}

#[test]
fn node_state_follow_field() {
    // bitfield.cc:21-28.  used container (off0,sz8); field bits (off2,sz2,lsb0,nb16).
    // bitsField = BitRange(field.bits, 0, 8) => lsb 16, nb 16 (LE oracle).
    let used = BitRange::byte_range(0, 8, false);
    let field_bits = BitRange::new(2, 2, 0, 16, false);
    let (field, owner) = bf(&field_bits, type_metatype::TYPE_INT);
    let st = BitFieldNodeState::follow_field(&used, vn(), &field, &owner);
    assert_eq!((st.bits_field.least_sig_bit, st.bits_field.num_bits), (16, 16));
    assert_eq!(st.orig_least_sig_bit, 16);
    // isMostSignificant of bitsField (8*8=64 == 16+16=32?) -> false, so no sign ext.
    assert!(!st.is_sign_extended);
    assert_eq!(st.field_type().unwrap().get_metatype(), type_metatype::TYPE_INT);
    // does_sign_extension_match: is_sign_extended(false) == is_int(true) -> false.
    assert!(!st.does_sign_extension_match());
}

#[test]
fn node_state_follow_field_top_aligned_signext() {
    // A field occupying the top of the container with is_int -> sign-extended.
    let used = BitRange::byte_range(0, 8, false);
    // field bits that translate to bitsField lsb 48 nb 16 in an 8-byte container:
    // a field at byteOffset 6, byteSize 2 (LE) -> translateLSB = 8*(6-0)=48.
    let field_bits = BitRange::new(6, 2, 0, 16, false);
    let (field, owner) = bf(&field_bits, type_metatype::TYPE_INT);
    let st = BitFieldNodeState::follow_field(&used, vn(), &field, &owner);
    assert_eq!((st.bits_field.least_sig_bit, st.bits_field.num_bits), (48, 16));
    assert!(st.bits_field.is_most_significant()); // 8*8 == 48+16
    assert!(st.is_sign_extended);
    assert!(st.does_sign_extension_match());
}

#[test]
fn node_state_follow_field_unsigned_no_signext() {
    let used = BitRange::byte_range(0, 8, false);
    let field_bits = BitRange::new(6, 2, 0, 16, false);
    let (field, owner) = bf(&field_bits, type_metatype::TYPE_UINT);
    let st = BitFieldNodeState::follow_field(&used, vn(), &field, &owner);
    // is_int false -> never sign extended even if most significant.
    assert!(!st.is_sign_extended);
    assert_eq!(st.field_type().unwrap().get_metatype(), type_metatype::TYPE_UINT);
    // does_sign_extension_match: false == false -> true.
    assert!(st.does_sign_extension_match());
}

#[test]
fn node_state_hole() {
    // bitfield.cc:30-37.  used (off0,sz8,LE); hole at leastSig 12, numBits 4.
    let used = BitRange::byte_range(0, 8, false);
    let st = BitFieldNodeState::hole(&used, vn(), 12, 4);
    assert_eq!(
        (
            st.bits_field.byte_offset,
            st.bits_field.byte_size,
            st.bits_field.least_sig_bit,
            st.bits_field.num_bits
        ),
        (0, 8, 12, 4)
    );
    assert_eq!(st.orig_least_sig_bit, 12);
    assert!(!st.is_sign_extended);
    assert!(st.field.is_hole());
    // does_sign_extension_match defensively false on a hole.
    assert!(!st.does_sign_extension_match());
}

#[test]
fn node_state_with_new_field() {
    // bitfield.cc:44-51.  field/origLeastSigBit copied; bitsField/node/signExt replaced.
    let used = BitRange::byte_range(0, 8, false);
    let field_bits = BitRange::new(2, 2, 0, 16, false);
    let (field, owner) = bf(&field_bits, type_metatype::TYPE_INT);
    let base = BitFieldNodeState::follow_field(&used, vn(), &field, &owner);
    let new_field = BitRange::new(0, 8, 0, 8, false);
    let st = BitFieldNodeState::with_new_field(&base, &new_field, vn(), /*sgn_ext*/ true);
    assert_eq!(st.bits_field, new_field);
    // field is copied from base (both follow the same TypeBitField).
    assert_eq!(
        st.field_type().unwrap().get_metatype(),
        base.field_type().unwrap().get_metatype()
    );
    assert_eq!(st.orig_least_sig_bit, base.orig_least_sig_bit);
    assert!(st.is_sign_extended);
    assert_eq!(st.bits_used, base.bits_used);
}

#[test]
fn node_state_is_field_aligned() {
    // bitfield.hh:39 — bitsField.leastSigBit == 0 && bitsField.numBits == bitsUsed.numBits.
    let used = BitRange::byte_range(0, 1, false); // numBits 8
    // Aligned: bitsField lsb 0 nb 8.
    let aligned = BitFieldNodeState::hole(&used, vn(), 0, 8);
    assert!(aligned.is_field_aligned());
    // Not aligned (lsb != 0).
    let off = BitFieldNodeState::hole(&used, vn(), 2, 6);
    assert!(!off.is_field_aligned());
    // Not aligned (numBits mismatch).
    let short = BitFieldNodeState::hole(&used, vn(), 0, 4);
    assert!(!short.is_field_aligned());
}

// =============================================================================
// BitFieldTransform (base): constructor + establish_fields
// =============================================================================

use crate::dtype::{flags, type_metatype, Datatype, DatatypeKind, TypeBitField, TypeFactoryImpl, TypeRoot};

/// `myfoo`'s first byte (`bitfields.xml`): `uint4 field3:3` (lsb0,3b),
/// `int4 sfield4:4` (lsb3,4b), `bool fieldb:1` (lsb7,1b).  All little-endian,
/// byteOffset 0, byteSize 1.
fn myfoo_byte0_struct(types: &TypeFactoryImpl) -> TypeRoot {
    let mk = |id, lsb, nb, name: &str, meta| {
        let field_type = types.intern(Datatype::new(4, meta)).unwrap();
        let mut bf = TypeBitField::new(id, nb, false, name, field_type.id());
        bf.least_sig_bit = lsb;
        bf.byte_offset = 0;
        bf.byte_size = 1;
        bf
    };
    let bitfield = vec![
        mk(0, 0, 3, "field3", type_metatype::TYPE_UINT),
        mk(1, 3, 4, "sfield4", type_metatype::TYPE_INT),
        mk(2, 7, 1, "fieldb", type_metatype::TYPE_BOOL),
    ];
    let mut s = Datatype::new_with_align(1, 4, type_metatype::TYPE_STRUCT);
    s.flags |= flags::has_bitfields;
    s.kind = DatatypeKind::Struct { field: vec![], bitfield };
    types.intern(s).unwrap()
}

#[test]
fn transform_ctor_struct_sets_parent_and_offset() {
    let dt = myfoo_byte0_struct(&TypeFactoryImpl::new());
    let t = BitFieldTransform::new(&dt, 0, false);
    assert!(t.parent_struct.is_some());
    assert_eq!(t.initial_offset, 0);
    assert_eq!(t.container_size, -1);
    assert!(!t.is_big_endian);
}

#[test]
fn transform_ctor_non_struct_leaves_parent_null() {
    let types = TypeFactoryImpl::new();
    let dt = types.intern(Datatype::new(4, type_metatype::TYPE_INT)).unwrap();
    let t = BitFieldTransform::new(&dt, 0, false);
    assert!(t.parent_struct.is_none());
    assert_eq!(t.initial_offset, -1);
}

#[test]
fn establish_fields_one_byte_no_holes() {
    // A 1-byte Varnode fully covered by field3(3)+sfield4(4)+fieldb(1) = 8 bits.
    // With follow_holes=false, only the three field records appear.
    let dt = myfoo_byte0_struct(&TypeFactoryImpl::new());
    let mut t = BitFieldTransform::new(&dt, 0, false);
    t.establish_fields(vn(), /*vn_size*/ 1, /*follow_holes*/ false);
    // Three field records, each a FieldRef::Field, none a hole.
    assert_eq!(t.work_list.len(), 3);
    assert!(t.work_list.iter().all(|s| matches!(s.field, FieldRef::Field { .. })));
    // field3 occupies bits [0,3); least significant first.
    assert_eq!(t.work_list[0].bits_field.least_sig_bit, 0);
    assert_eq!(t.work_list[0].bits_field.num_bits, 3);
    // sfield4 [3,7).
    assert_eq!(t.work_list[1].bits_field.least_sig_bit, 3);
    assert_eq!(t.work_list[1].bits_field.num_bits, 4);
    // fieldb [7,8) — most significant, is_int? bool -> not TYPE_INT -> no signext.
    assert_eq!(t.work_list[2].bits_field.least_sig_bit, 7);
    assert_eq!(t.work_list[2].bits_field.num_bits, 1);
    // sfield4 is int4 -> FieldRef::Field { is_int: true }; its bits are not at the
    // top of the 1-byte container ([3,7) != most significant), so not sign ext.
    assert_eq!(t.work_list[1].field_type().unwrap().get_metatype(), type_metatype::TYPE_INT);
    assert!(!t.work_list[1].is_sign_extended);
}

#[test]
fn establish_fields_partial_coverage_emits_final_hole() {
    let types = TypeFactoryImpl::new();
    // Only field3(3 bits) present in a struct; a 1-byte Varnode leaves a 5-bit
    // final hole [3,8).  With follow_holes the hole record is emitted.
    let mut s = Datatype::new_with_align(1, 4, type_metatype::TYPE_STRUCT);
    s.flags |= flags::has_bitfields;
    let field_type = types.intern(Datatype::new(4, type_metatype::TYPE_UINT)).unwrap();
    let mut bf = TypeBitField::new(0, 3, false, "field3", field_type.id());
    bf.byte_offset = 0;
    bf.byte_size = 1;
    s.kind = DatatypeKind::Struct { field: vec![], bitfield: vec![bf] };
    let dt = types.intern(s).unwrap();

    let mut t = BitFieldTransform::new(&dt, 0, true);
    t.establish_fields(vn(), 1, /*follow_holes*/ true);
    // field3 record + the final hole [3,8).
    assert_eq!(t.work_list.len(), 2);
    assert!(matches!(t.work_list[0].field, FieldRef::Field { .. }));
    assert!(matches!(t.work_list[1].field, FieldRef::Hole));
    assert_eq!(t.work_list[1].bits_field.least_sig_bit, 3);
    assert_eq!(t.work_list[1].bits_field.num_bits, 5);

    // With follow_holes=false the hole is suppressed.
    let mut t2 = BitFieldTransform::new(&dt, 0, true);
    t2.establish_fields(vn(), 1, false);
    assert_eq!(t2.work_list.len(), 1);
    assert!(matches!(t2.work_list[0].field, FieldRef::Field { .. }));
}

#[test]
fn establish_fields_non_struct_parent_collects_nothing() {
    // C++ never calls establishFields with a null parentStruct (the rule guards
    // on dt->hasBitfields() first, which implies a struct).  The port guards the
    // collectBitFields call defensively, so no field records are produced — the
    // overlap loop runs zero times.  With follow_holes=true the trailing
    // whole-Varnode hole branch (bitfield.cc:88-90) still fires, exactly as it
    // would for an empty struct (no bitfields).
    let types = TypeFactoryImpl::new();
    let dt = types.intern(Datatype::new(4, type_metatype::TYPE_INT)).unwrap();
    let mut t = BitFieldTransform::new(&dt, 0, false);
    t.establish_fields(vn(), 4, false);
    // follow_holes=false: nothing at all.
    assert!(t.work_list.is_empty());

    let mut t2 = BitFieldTransform::new(&dt, 0, false);
    t2.establish_fields(vn(), 4, true);
    // follow_holes=true: a single whole-Varnode hole [0, 32).
    assert_eq!(t2.work_list.len(), 1);
    assert!(matches!(t2.work_list[0].field, FieldRef::Hole));
    assert_eq!(t2.work_list[0].bits_field.least_sig_bit, 0);
    assert_eq!(t2.work_list[0].bits_field.num_bits, 32);
}

// Graph-backed membership checks: a positive rewrite for every rule prevents
// an inactive fixture from making the restricted-pool checks vacuous.
use crate::action::{Action, ActionContext, ActionGroupList, ActionPool, RuleState};
use crate::context::{ArchContext, BlockId, OpId};
use crate::dtype::TypeFactory;
use kuna_base::address::Address;
use kuna_base::space::{addrspace_flags, spacetype, AddrSpace, AddrSpaceManager, ConstantSpace, UniqueSpace};
use std::rc::Rc;

fn rule_fixture() -> (Funcdata, BlockId) {
    let mut manager = AddrSpaceManager::new();
    manager.insert_space(Rc::new(ConstantSpace::new())).unwrap();
    manager.insert_space(Rc::new(UniqueSpace::new(1, 0, false))).unwrap();
    manager.insert_space(Rc::new(AddrSpace::new(
        spacetype::IPTR_PROCESSOR, "ram", false, 8, 1, 2,
        addrspace_flags::hasphysical, 1, 1,
    ))).unwrap();
    let arch = Rc::new(ArchContext::new(manager));
    let ram = arch.manage().get_space_by_name("ram").unwrap().clone();
    let mut fd = Funcdata::new("bitfields", "bitfields", arch, Address::new(ram, 0x1000), 0x10000000, 0x40).unwrap();
    let root = fd.bblocks_ref().root.unwrap();
    let block = fd.bblocks_mut().new_block_basic(root);
    (fd, block)
}

fn fixture_op(fd: &mut Funcdata, block: BlockId, code: OpCode, inputs: &[VarnodeId], size: i32) -> OpId {
    let ram = fd.get_arch().manage().get_space_by_name("ram").unwrap().clone();
    let op = fd.new_op(inputs.len() as i32, Address::new(ram, 0x1000));
    fd.op_set_opcode_code(op, code);
    for (slot, &input) in inputs.iter().enumerate() {
        fd.op_set_input(op, input, slot as i32).unwrap();
    }
    if size != 0 {
        fd.new_unique_out(size, op).unwrap();
    }
    fd.op_insert_end(op, block);
    op
}

fn fixture_out(fd: &Funcdata, op: OpId) -> VarnodeId {
    fd.obank().get(op).unwrap().get_out().unwrap()
}

fn fixture_input(fd: &mut Funcdata, size: i32, offset: u64, ty: Option<TypeRoot>) -> VarnodeId {
    let ram = fd.get_arch().manage().get_space_by_name("ram").unwrap().clone();
    let input = fd.new_varnode(size, &Address::new(ram, offset), ty);
    fd.set_input_varnode(input).unwrap()
}

#[test]
fn all_bitfield_rules_require_registered_group_for_real_rewrites() {
    for (index, name) in ["bitfield_store", "bitfield_out", "bitfield_load", "bitfield_in", "pull_absorb", "insert_absorb"].into_iter().enumerate() {
        let mut pool = ActionPool::new(0, "bitfields");
        pool.add_rule(RuleState::new("bitfields", 0, name), (specs()[index].ctor)());
        for enabled in [false, true] {
            let (mut fd, block) = rule_fixture();
            let mut groups = ActionGroupList::new();
            groups.insert("base");
            if enabled {
                groups.insert("bitfields");
            }
            let field_type = myfoo_byte0_struct(fd.get_arch().types_impl().unwrap());
            let value = fd.new_constant(1, 0x55);
            let mask = fd.new_constant(1, 7);
            let pos = fd.new_constant(4, 0);
            let width = fd.new_constant(4, 3);
            let input = fixture_input(&mut fd, 1, 0x2000, None);
            let (observe, original_code, expected_code, expected_input) = match index {
                0 | 2 => {
                    let pointer_type = fd.get_arch().types_impl().unwrap()
                        .get_type_pointer(8, field_type, 1).unwrap();
                    let pointer = fixture_input(&mut fd, 8, 0x2100, Some(pointer_type));
                    let space = fd.new_constant(8, 2);
                    if index == 0 {
                        let store = fixture_op(&mut fd, block, OpCode::CPUI_STORE, &[space, pointer, value], 0);
                        (store, OpCode::CPUI_STORE, OpCode::CPUI_STORE, None)
                    } else {
                        let load = fixture_op(&mut fd, block, OpCode::CPUI_LOAD, &[space, pointer], 1);
                        let loaded = fixture_out(&fd, load);
                        let and = fixture_op(&mut fd, block, OpCode::CPUI_INT_AND, &[loaded, mask], 1);
                        (and, OpCode::CPUI_INT_AND, OpCode::CPUI_ZPULL, None)
                    }
                }
                1 => {
                    let copy = fixture_op(&mut fd, block, OpCode::CPUI_COPY, &[value], 1);
                    let out = fixture_out(&fd, copy);
                    let vn = fd.vbank_mut().get_mut(out).unwrap();
                    vn.update_type(field_type);
                    vn.mark_mapped_addr_tied();
                    (copy, OpCode::CPUI_COPY, OpCode::CPUI_INSERT, None)
                }
                3 => {
                    fd.vbank_mut().get_mut(input).unwrap().update_type(field_type);
                    let and = fixture_op(&mut fd, block, OpCode::CPUI_INT_AND, &[input, mask], 1);
                    (and, OpCode::CPUI_INT_AND, OpCode::CPUI_ZPULL, None)
                }
                4 => {
                    let pull = fixture_op(&mut fd, block, OpCode::CPUI_SPULL, &[input, pos, width], 1);
                    let pulled = fixture_out(&fd, pull);
                    let ext = fixture_op(&mut fd, block, OpCode::CPUI_INT_SEXT, &[pulled], 4);
                    (ext, OpCode::CPUI_INT_SEXT, OpCode::CPUI_SPULL, None)
                }
                5 => {
                    let and = fixture_op(&mut fd, block, OpCode::CPUI_INT_AND, &[input, mask], 1);
                    let masked = fixture_out(&fd, and);
                    let insert = fixture_op(&mut fd, block, OpCode::CPUI_INSERT, &[value, masked, pos, width], 1);
                    (insert, OpCode::CPUI_INSERT, OpCode::CPUI_INSERT, Some((masked, input)))
                }
                _ => unreachable!(),
            };
            let mut filtered = pool.clone_filtered(&groups);
            if let Some(action) = filtered.as_mut() {
                action.reset(&mut fd);
                assert!(action.perform(&mut fd, &mut ActionContext::new()) >= 0, "{name}");
            }
            if !enabled {
                assert!(filtered.is_none(), "{name} escaped the base-only pool");
                assert_eq!(fd.obank().get(observe).unwrap().code(), original_code, "{name}");
            } else if index == 0 {
                let written = fd.obank().get(observe).unwrap().get_in(2).unwrap();
                let definition = fd.vbank().get(written).unwrap().get_def().unwrap();
                assert_eq!(fd.obank().get(definition).unwrap().code(), OpCode::CPUI_INSERT, "{name}");
            } else if index == 2 || index == 3 {
                assert!(fd.bb_ops(block).iter().any(|&op| fd.obank().get(op).unwrap().code() == expected_code), "{name} did not recover a pull");
            } else {
                assert_eq!(fd.obank().get(observe).unwrap().code(), expected_code, "{name}");
            }
            if let Some((before, after)) = expected_input {
                assert_eq!(fd.obank().get(observe).unwrap().get_in(1), Some(if enabled { after } else { before }), "{name}");
            }
        }
    }
}

#[test]
fn schedule_registration_controls_unconditional_analysis_clone() {
    use crate::universalaction::{universal_sched, ActionListFilter, RuleRow};
    // Architecture registration is authoritative, even when both the rule's
    // usual primary group and its name are absent from the filter.
    for (groups, enabled) in [
        (&["base"][..], false),
        (&["trivialarith"][..], false),
        (&["cpu_alias"][..], true),
        (&["cpu_primary"][..], true),
    ] {
        let (mut fd, block) = rule_fixture();
        let input = fixture_input(&mut fd, 4, 0x2000, None);
        let xor = fixture_op(&mut fd, block, OpCode::CPUI_INT_XOR, &[input, input], 4);
        let schedule = universal_sched(None, None, vec![RuleRow {
            name: "cpu_identity",
            group: "cpu_primary",
            aliases: &["cpu_alias"],
            ctor: || Box::new(crate::ruleaction_2::RuleTrivialArith),
        }]);
        let dump = schedule.list_action_dump(&ActionListFilter::from_names(groups.iter().copied()));
        assert_eq!(dump.contains("cpu_identity"), enabled);
        let universal = schedule.materialize();
        let mut filter = ActionGroupList::new();
        for &group in groups {
            filter.insert(group);
        }
        // Inspect the base-only clone but don't run unrelated base Actions on
        // the minimal IR fixture: the isolated pool below exercises execution.
        if groups != ["base"] {
            if let Some(mut root) = universal.clone_filtered(&filter) {
                root.reset(&mut fd);
                assert!(root.perform(&mut fd, &mut ActionContext::new()) >= 0);
            }
        } else {
            let mut pool = ActionPool::new(0, "analysis");
            pool.add_rule(RuleState::new("analysis", 0, "trivialarith"), Box::new(crate::ruleaction_2::RuleTrivialArith));
            let mut root = crate::action::ActionGroup::new(0, "restricted");
            root.add_action(Box::new(pool));
            assert!(root.clone_filtered(&filter).is_none());
        }
        assert_eq!(fd.obank().get(xor).unwrap().code(), if enabled { OpCode::CPUI_COPY } else { OpCode::CPUI_INT_XOR });
        if enabled {
            let zero = fd.obank().get(xor).unwrap().get_in(0).unwrap();
            assert!(fd.vbank().get(zero).unwrap().is_constant());
            assert_eq!(fd.vbank().get(zero).unwrap().get_offset(), 0);
        }
    }
}


