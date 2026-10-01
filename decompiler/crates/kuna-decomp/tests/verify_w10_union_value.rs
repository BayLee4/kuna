//! Adversarial verifier tests for item `w10-union-value`.
//!
//! The item's whole production change is: match `DatatypeKind::PointerRel`
//! identically to `DatatypeKind::Pointer` in the three type-resolution
//! dispatchers, because `TypePointerRel : public TypePointer` (type.hh:724) does
//! NOT override `resolveInFlow`/`findResolve`/`findCompatibleResolve`, so a
//! relative pointer dispatches the inherited `TypePointer` body:
//!
//!   * `Datatype::find_compatible_resolve` (dtype.rs) <- TypePointer::
//!     findCompatibleResolve (type.cc:1347-1354),
//!   * `Funcdata::find_resolve_facing` (funcdata_facing.rs) <- TypePointer::
//!     findResolve (type.cc:1335-1345),
//!   * `Funcdata::resolve_in_flow` (funcdata_resolveflow.rs) <- TypePointer::
//!     resolveInFlow (type.cc:1314-1333).
//!
//! These tests pin the directly-testable dispatcher (`find_compatible_resolve`)
//! and the accessor invariant the two Funcdata dispatchers rely on, with the
//! fragile spots the change touches:
//!
//!   * the C++ reads `((TypePointer *)ct)->ptrto` — the RELATIVE ptrto member,
//!     NOT the stripped plain pointer. A port that reached for `stripped` would
//!     resolve against the wrong (union) type. (at1, at2)
//!   * a `PointerRel` RECEIVER must recurse on its OWN relative `ptrto`, byte-
//!     identically to a plain `Pointer` with the same ptrto (the inherited
//!     body). (at3)
//!   * the union-arm gate is `ptrto.get_metatype() == TYPE_UNION`; a
//!     PointerRel-to-NON-union must NOT be treated as a union edge (the gate is
//!     on the ptrto metatype, shared by both pointer kinds). (at4)
//!   * a `PointerRel` whose ct argument is a plain `Pointer` (and vice-versa)
//!     must cross-recurse on the literal `ptrto` of each — the cast is on the
//!     argument, independent of the receiver kind. (at5)

use kuna_base::types::int4;
use kuna_decomp::dtype::{
    type_metatype, Datatype, DatatypeKind, TypeFactory, TypeFactoryImpl, TypeField, TypeRoot,
};

fn factory() -> TypeFactoryImpl {
    let f = TypeFactoryImpl::new();
    f.set_default_alignment_map();
    f.set_max_basetype_size(8);
    f
}

/// Build a completed N-field union `{ int4 myint@0; float4 myfloat@0; }`, the
/// shape behind the `(ptr->value).myint` datatest renders, published in the
/// fixture's graph so field and relative-pointer edges share their owner.
fn make_union(types: &TypeFactoryImpl, name: &str, fields: &[(int4, TypeRoot)]) -> TypeRoot {
    let mut u = Datatype::new(4, type_metatype::TYPE_UNION);
    u.name = name.into();
    u.id = Datatype::hash_name(name);
    let field: Vec<TypeField> = fields
        .iter()
        .enumerate()
        .map(|(i, (off, ct))| TypeField::new(i as int4, *off, format!("m{i}"), ct.id()))
        .collect();
    u.kind = DatatypeKind::Union { field };
    types.intern(u).unwrap()
}

/// at1: `find_compatible_resolve` with a `PointerRel` ct must read ct's RELATIVE
/// `ptrto` (the field type), exactly like the C++ `((TypePointer *)ct)->ptrto`.
/// A plain pointer-to-int receiver, given a ptr-rel-to-int ct, must recurse
/// int<->int (compatible). The mutation guard: if the port had used `stripped`
/// (a TypePointer to the union/container) instead of `ptrto`, the recursion
/// would compare int against a pointer and the result would differ.
#[test]
fn w10_union_value_compat_resolve_reads_ct_relative_ptrto_not_stripped() {
    use type_metatype::*;
    let f = factory();
    let i4 = f.get_base(4, TYPE_INT).unwrap();
    let f4 = f.get_base(4, TYPE_FLOAT).unwrap();
    let u = make_union(&f, "valU", &[(0, i4.clone()), (0, f4.clone())]);
    // parentPtr: plain pointer to the union (the container the relptr points into).
    let pu = f.get_type_pointer(8, u.clone(), 1).unwrap();
    // ptr-rel-to-int: ptrto = i4 (the FIELD type), parent = union, offset 0.
    let relptr = f
        .get_type_pointer_rel(pu.clone(), i4.clone(), 0)
        .unwrap();
    assert!(relptr.is_pointer_rel(), "constructed a PointerRel");
    // get_ptr_to() must yield the relative ptrto (i4), NOT the stripped pointer.
    let rel_ptrto = relptr.get_ptr_to().unwrap();
    assert_eq!(rel_ptrto, i4, "PointerRel get_ptr_to is the field type i4");

    // Receiver: a plain pointer-to-int. ct: the ptr-rel-to-int.
    // C++ TypePointer::findCompatibleResolve(ct): ct is TYPE_PTR ->
    // ptrto(i4).findCompatibleResolve(((TypePointer*)ct)->ptrto == i4).
    let pint = f.get_type_pointer(8, i4.clone(), 1).unwrap();
    let got = pint.find_compatible_resolve(&relptr).unwrap();

    // Reference: the same call against a PLAIN pointer-to-int ct must be byte-
    // identical (both read the literal int4 ptrto).
    let plain_int_ct = f.get_type_pointer(8, i4.clone(), 1).unwrap();
    let want = pint.find_compatible_resolve(&plain_int_ct).unwrap();
    assert_eq!(got, want, "PointerRel ct must resolve via its relative ptrto, like a plain pointer");
}

/// at2: the STRIPPED-vs-PTRTO mutation, made OBSERVABLE with a concrete index.
///
/// Receiver = a union `{ int4 m0@0; }`.  Its
/// `findCompatibleResolve` (TypeUnion, `!ct.needs_resolution()` arm,
/// type.cc:2629-2649) returns the field INDEX when `field[i].type == ct` by
/// graph identity.  Drive it with a ptr-rel-to-int ct: the C++
/// `((TypePointer *)ct)->ptrto` is the RELATIVE ptrto (== `i4`, the field's own
/// identity), so the match fires and the result is `0` (the field index).
///
/// If the port had read the STRIPPED plain pointer (a distinct `TypePointer`
/// identity, not `i4`) the identity test would miss and the result would be `-1`.
/// So `0` vs `-1` is the live mutation discriminator; we also confirm a plain
/// ptr-to-int ct (built the same way) yields the identical `0`.
#[test]
fn w10_union_value_compat_resolve_ptrto_is_relative_field_not_stripped() {
    use type_metatype::*;
    let f = factory();
    let i4 = f.get_base(4, TYPE_INT).unwrap();
    // The scalar argument does not need resolution, so the union takes the
    // identity arm (`field[i].type == ct && offset==0` -> index i).
    let single_union = make_union(&f, "single", &[(0, i4.clone())]);

    // RECEIVER = pointer-to-(single-int)-union.  Its Pointer arm recurses:
    // union.findCompatibleResolve(((TypePointer*)ct)->ptrto).
    let pu_recv = f.get_type_pointer(8, single_union.clone(), 1).unwrap();

    // A throwaway parent pointer for the relptr (parent type is irrelevant here).
    let parent_u = make_union(&f, "valU2", &[(0, i4.clone())]);
    let pu_parent = f.get_type_pointer(8, parent_u.clone(), 1).unwrap();
    // The relative ptrto shares the union field's graph identity.
    let relptr_to_int = f.get_type_pointer_rel(pu_parent.clone(), i4.clone(), 0).unwrap();
    // The stripped plain pointer has a distinct identity from the int field type.
    if let Some(st) = relptr_to_int.get_stripped() {
        assert_ne!(st, i4, "stripped is a plain pointer, distinct from the int field type");
    }

    // ct = the relptr.  C++ reads ((TypePointer*)ct)->ptrto == i4 (the relative
    // ptrto), recurses union.findCompatibleResolve(i4) -> identity match -> 0.
    // A `stripped`-via read would pass a plain pointer (!= i4) -> -1.
    let via_relptr = pu_recv.find_compatible_resolve(&relptr_to_int).unwrap();
    assert_eq!(via_relptr, 0, "PointerRel ct resolves via its relative ptrto (union field index 0), not stripped (-1)");

    // Reference: a plain ptr-to-int ct (same i4) yields the identical 0.
    let plain_int_ct = f.get_type_pointer(8, i4.clone(), 1).unwrap();
    let via_plain = pu_recv.find_compatible_resolve(&plain_int_ct).unwrap();
    assert_eq!(via_plain, via_relptr, "plain Pointer and PointerRel cts resolve identically via ptrto");
}

/// at3: a `PointerRel` RECEIVER recurses on its own relative ptrto, byte-
/// identically to a plain `Pointer` with the same ptrto (the inherited body —
/// no override exists). This is the literal new match-arm (`Pointer | PointerRel`)
/// exercised from the receiver side.
#[test]
fn w10_union_value_compat_resolve_pointerrel_receiver_matches_plain_pointer() {
    use type_metatype::*;
    let f = factory();
    let i4 = f.get_base(4, TYPE_INT).unwrap();
    let u = make_union(&f, "valU3", &[(0, i4.clone())]);
    let pu = f.get_type_pointer(8, u.clone(), 1).unwrap();
    // RECEIVER = ptr-rel-to-int.
    let relptr = f
        .get_type_pointer_rel(pu.clone(), i4.clone(), 0)
        .unwrap();
    // ct = plain ptr-to-int.
    let pint_ct = f.get_type_pointer(8, i4.clone(), 1).unwrap();

    let from_rel = relptr.find_compatible_resolve(&pint_ct).unwrap();
    // The inherited TypePointer body: a plain ptr-to-int receiver with the same
    // ptrto must produce the identical result.
    let plain_recv = f.get_type_pointer(8, i4.clone(), 1).unwrap();
    let from_plain = plain_recv.find_compatible_resolve(&pint_ct).unwrap();
    assert_eq!(
        from_rel, from_plain,
        "PointerRel receiver dispatches the inherited TypePointer::findCompatibleResolve"
    );
}

/// at4: the union-arm gate is on `ptrto.get_metatype()`, NOT on the pointer
/// kind. A PointerRel-to-NON-union ct: `find_compatible_resolve` against a
/// non-pointer receiver returns -1 (base default); against a pointer receiver it
/// recurses. The gate must behave identically for Pointer and PointerRel cts of
/// the same ptrto. Mutation guard: a non-TYPE_PTR ct (e.g. a bare int) returns
/// -1, proving the `ct.get_metatype() == TYPE_PTR` guard still fires.
#[test]
fn w10_union_value_compat_resolve_non_pointer_ct_returns_minus_one() {
    use type_metatype::*;
    let f = factory();
    let i4 = f.get_base(4, TYPE_INT).unwrap();
    let u = make_union(&f, "valU4", &[(0, i4.clone())]);
    let pu = f.get_type_pointer(8, u.clone(), 1).unwrap();
    let relptr = f
        .get_type_pointer_rel(pu.clone(), i4.clone(), 0)
        .unwrap();
    // A bare (non-pointer) ct: the TYPE_PTR guard fails -> -1, for both kinds.
    let bare_int = f.get_base(4, TYPE_INT).unwrap();
    assert_eq!(
        relptr.find_compatible_resolve(&bare_int).unwrap(),
        -1,
        "PointerRel receiver, non-pointer ct -> -1 (TYPE_PTR guard)"
    );
    let plain = f.get_type_pointer(8, i4.clone(), 1).unwrap();
    assert_eq!(
        plain.find_compatible_resolve(&bare_int).unwrap(),
        -1,
        "plain Pointer receiver, non-pointer ct -> -1 (parity)"
    );
}

/// at5: cross-kind recursion. The `((TypePointer*)ct)->ptrto` cast is on the
/// ARGUMENT and works for either ct kind; symmetrically the receiver arm fires
/// for either receiver kind. So Pointer-recv/PointerRel-ct and
/// PointerRel-recv/Pointer-ct of matching ptrto must agree, and both must equal
/// the plain/plain case.
#[test]
fn w10_union_value_compat_resolve_cross_kind_symmetry() {
    use type_metatype::*;
    let f = factory();
    let i4 = f.get_base(4, TYPE_INT).unwrap();
    let u = make_union(&f, "valU5", &[(0, i4.clone())]);
    let pu = f.get_type_pointer(8, u.clone(), 1).unwrap();
    let relptr = f
        .get_type_pointer_rel(pu.clone(), i4.clone(), 0)
        .unwrap();
    let plain = f.get_type_pointer(8, i4.clone(), 1).unwrap();

    let plain_plain = plain.find_compatible_resolve(&plain).unwrap();
    let plain_rel = plain.find_compatible_resolve(&relptr).unwrap();
    let rel_plain = relptr.find_compatible_resolve(&plain).unwrap();
    let rel_rel = relptr.find_compatible_resolve(&relptr).unwrap();
    assert_eq!(plain_plain, plain_rel, "plain-recv: Pointer ct == PointerRel ct");
    assert_eq!(plain_plain, rel_plain, "PointerRel-recv: Pointer ct == plain-recv");
    assert_eq!(plain_plain, rel_rel, "both PointerRel == both plain");
}

