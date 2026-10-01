//! Adversarial verifier tests for item `w6-s5-type-3` (TypeFactory container +
//! the type-3 `TypePointerRel` overrides in `decompiler/cpp/type.cc`,
//! lines ~3072-3147 and the factory body 3565-end).
//!
//! The hunt list flagged these as the most fragile spots for this item:
//!
//!   * **Integer widths.** `TypePointerRel::isPtrsubMatching` (type.cc:3138-3147)
//!     stores its running offset in an `int4 iOff`, so the C++ truncates the
//!     `addressToByteInt`/`offset`/`extra` sum to 32 bits before the bound check.
//!     The port keeps the whole computation in `int8` and never truncates — a real
//!     (if only-at-pathological-inputs) divergence. F1 below pins the boundary.
//!   * **Formal and ephemeral relative pointers.** Their different PTRSUB
//!     behavior and distinct graph identities must survive interning.
//!   * **Wrapping / signedness.** `hashName`/`hashSize` (type.cc:693-720) are
//!     bit-exact u64 hashes; the `(uint8)nm[i]` of a *signed* `char` sign-extends
//!     in C++.  The port masks to a byte (ASCII-only) — documented divergence.
//!
//! C++ oracle anchors are cited inline.

use kuna_decomp::dtype::{flags, Datatype, DatatypeKind, sub_metatype, type_metatype, TypeFactory, TypeFactoryImpl, TypeRoot};

fn int4_t(types: &TypeFactoryImpl) -> TypeRoot {
    types.get_base(4, type_metatype::TYPE_INT).unwrap()
}

/// Build a plain `TypePointer(8, ptrto, ws)` value (the `stripped` payload a
/// markEphemeral relative pointer would carry).
fn plain_pointer(types: &TypeFactoryImpl, ptrto: TypeRoot, ws: u32) -> TypeRoot {
    types.get_type_pointer(8, ptrto, ws).unwrap()
}

fn factory() -> TypeFactoryImpl {
    let types = TypeFactoryImpl::new();
    types.set_default_alignment_map();
    types.set_max_basetype_size(8);
    types
}

fn parent_struct(types: &TypeFactoryImpl) -> TypeRoot {
    let mut parent = Datatype::new_with_align(16, 4, type_metatype::TYPE_STRUCT);
    parent.kind = DatatypeKind::Struct { field: vec![], bitfield: vec![] };
    types.intern(parent).unwrap()
}

/// Publish a relative pointer and its optional ephemeral stripped edge in the
/// same graph as its pointee and parent.
fn ptrrel(
    types: &TypeFactoryImpl,
    size: int4_alias,
    ptrto: TypeRoot,
    wordsize: u32,
    stripped: Option<TypeRoot>,
    parent: TypeRoot,
    offset: int4_alias,
) -> TypeRoot {
    let mut pr = Datatype::new_with_align(size, -1, type_metatype::TYPE_PTRREL);
    pr.submeta = sub_metatype::SUB_PTRREL;
    if stripped.is_some() {
        pr.flags |= flags::has_stripped;
    }
    pr.kind = DatatypeKind::PointerRel {
        ptrto: ptrto.id(), spaceid: None, wordsize, stripped: stripped.map(|root| root.id()),
        parent: parent.id(), offset,
    };
    types.intern(pr).unwrap()
}

#[allow(non_camel_case_types)]
type int4_alias = i32;

/// **F1 (the width divergence).** `TypePointerRel::isPtrsubMatching`
/// (type.cc:3143-3146) computes `int4 iOff = addressToByteInt(off,ws); extra =
/// addressToByteInt(extra,ws); iOff += offset + extra;` and returns
/// `0 <= iOff <= parent->getSize()`.  Because `iOff` is a **32-bit** `int4` the
/// C++ sum truncates to 32 bits before the comparison; the Rust port keeps the
/// computation in `int8`.
///
/// This test pins the *agreeing* domain (all realistic small offsets) so a future
/// regression in the bound arithmetic is caught, and documents the boundary
/// where the int4-truncation would diverge.  With `wordsize == 1`,
/// `addressToByteInt` is the identity, so `iOff = off + offset + extra`.
#[test]
fn f1_ptrrel_isptrsubmatching_bounds_realistic_domain() {
    let types = factory();
    let parent = parent_struct(&types);
    // formal relative pointer (stripped == None) at offset 4 into the parent.
    let pr = ptrrel(&types, 8, int4_t(&types), 1, None, parent.clone(), 4);

    // iOff = off(0) + offset(4) + extra(0) = 4 ; 0 <= 4 <= 16 -> true
    assert!(pr.is_ptrsub_matching(0, 0, 1).unwrap());
    // Upper boundary inclusive: iOff = 0 + 4 + 12 = 16 ; 16 <= 16 -> true
    assert!(pr.is_ptrsub_matching(0, 12, 1).unwrap());
    // One past the upper boundary: iOff = 17 -> false
    assert!(!pr.is_ptrsub_matching(0, 13, 1).unwrap());
    // Lower boundary: iOff = off(-5) + 4 + 0 = -1 -> false (negative)
    assert!(!pr.is_ptrsub_matching(-5, 0, 1).unwrap());
    // Exactly zero is in-bounds: iOff = off(-4) + 4 + 0 = 0 -> true
    assert!(pr.is_ptrsub_matching(-4, 0, 1).unwrap());

    // The stripped (ephemeral) form defers to the inherited TypePointer body
    // (type.cc:3141-3142); ptrto is a plain int (not STRUCT/ARRAY/UNION/SPACEBASE)
    // so TypePointer::isPtrsubMatching falls to the `else return false` arm.
    let strip = plain_pointer(&types, int4_t(&types), 1);
    let pr_eph = ptrrel(&types, 8, int4_t(&types), 1, Some(strip), parent.clone(), 4);
    assert_ne!(pr, pr_eph, "formal and ephemeral pointers retain distinct behavior");
    assert!(!pr_eph.is_ptrsub_matching(0, 0, 1).unwrap());
}

/// **F1 continued — the truncation boundary the port does NOT reproduce.**
/// In C++ `iOff` is `int4`; a sum of `0x1_0000_0004` truncates to `4`, so the
/// C++ would return `true` (4 in [0,16]) while the Rust int8 path sees
/// `0x1_0000_0004 = 4294967300 > 16` and returns `false`.  We assert the *Rust*
/// behaviour here and flag the divergence in the verdict (F1, minor — the input
/// is a 4 GiB pointer offset, outside the realistic PTRSUB domain where
/// `parent->getSize()` is an int4).
#[test]
fn f1_ptrrel_isptrsubmatching_int4_truncation_divergence_documented() {
    let types = factory();
    let parent = parent_struct(&types);
    let pr = ptrrel(&types, 8, int4_t(&types), 1, None, parent, 4);
    // off = 0x1_0000_0000 (2^32): C++ int4 iOff would wrap this contribution to 0,
    // giving iOff == 4 (in-bounds, true).  The port computes in int8: 0x1_0000_0004,
    // which exceeds 16 -> false.  Documented as F1.
    let off: i64 = 0x1_0000_0000;
    assert!(
        !pr.is_ptrsub_matching(off, 0, 1).unwrap(),
        "Rust int8 path: a 2^32 offset is out of bounds (C++ int4 would truncate to in-bounds)"
    );
}


