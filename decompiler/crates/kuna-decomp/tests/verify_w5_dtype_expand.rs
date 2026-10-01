//! Adversarial verifier tests for item `w5-dtype-expand`.
//!
//! These target the spots the hunt list flagged as most fragile for the
//! `type.hh` `Datatype` interface port:
//!
//!   * comparator routing / totality (`Datatype::compare` /
//!     `compareDependency`), where a wrong subclass grouping silently corrupts
//!     ordering — the riskiest surface in this item;
//!   * `string2metatype` boundary inputs (empty string, known-first-char with a
//!     non-matching tail), which the C++ resolves via `metastring[0]` + fallthrough.
//!
//! C++ oracle: `decompiler/cpp/type.cc` (`Datatype::compare` 216-222,
//! `Datatype::compareDependency` 231-237, `TypeSpacebase::compare` 3498-3501,
//! `TypeSpacebase::compareDependency` 3504-3514, `string2metatype` 307-369) and
//! `decompiler/cpp/type.hh` (`TypeSpacebase` 799-824, declaring `compare`/
//! `compareDependency` as overrides).

use std::rc::Rc;

use kuna_base::address::Address;
use kuna_base::space::{AddrSpace, ConstantSpace};
use kuna_decomp::dtype::{
    metatype2string, string2metatype, type_metatype, Datatype, DatatypeKind,
    TypeFactoryImpl, TypeRoot,
};

fn const_space() -> Rc<AddrSpace> {
    Rc::new(ConstantSpace::new())
}

/// Build a `TYPE_SPACEBASE` Datatype with the given spaceid/localframe, mirroring
/// the C++ `TypeSpacebase(int4=0, align=1, TYPE_SPACEBASE)` shape (size 0).
fn spacebase(types: &TypeFactoryImpl, spaceid: Option<Rc<AddrSpace>>, localframe: Address) -> TypeRoot {
    let mut d = Datatype::new_with_align(0, 1, type_metatype::TYPE_SPACEBASE);
    d.kind = DatatypeKind::Spacebase {
        spaceid,
        localframe,
    };
    types.intern(d).unwrap()
}

/// `string2metatype` boundary inputs. C++ switches on `metastring[0]`
/// (type.cc:308); an empty string in C++11 reads the NUL terminator -> `default`
/// -> throw. The Rust port uses `.first()` -> `None` -> error. A known first
/// char with a non-matching full string falls through the inner ifs and still
/// throws (the C++ `break` then final `throw`).
#[test]
fn w5_dtype_string2metatype_boundary_and_fallthrough() {
    // Empty string: both C++ (NUL -> default -> throw) and Rust error.
    assert!(string2metatype("").is_err());
    // Known first char 'p', unknown tail -> falls through inner ifs -> error.
    assert!(string2metatype("ptrz").is_err());
    assert!(string2metatype("partbogus").is_err());
    // 's' has two distinct matches (struct/spacebase) via separate ifs in C++.
    assert_eq!(string2metatype("struct").unwrap(), type_metatype::TYPE_STRUCT);
    assert_eq!(
        string2metatype("spacebase").unwrap(),
        type_metatype::TYPE_SPACEBASE
    );
    // 'u' three-way (unknown/uint/union).
    assert_eq!(string2metatype("union").unwrap(), type_metatype::TYPE_UNION);
    // The documented upstream asymmetry: "partenum" is emitted but not decodable.
    assert_eq!(
        metatype2string(type_metatype::TYPE_PARTIALENUM).unwrap(),
        "partenum"
    );
    assert!(string2metatype("partenum").is_err());
}

// =============================================================================
// Round 2 verifier additions (independent re-derivation of the override routing)
// =============================================================================
//
// Round 1 REJECTed on F1: `DatatypeKind::Spacebase` was routed to the base
// `compare`/`compareDependency` body, silently returning Ok(0) for two distinct
// spacebases. These tests independently pin the *fixed* routing and the rest of
// the subclass-override partition, against type.hh's virtual-override map:
//
//   compare/compareDependency overriders : Pointer, Array, Struct, Union, Enum,
//       Code, PartialStruct, PartialUnion, PartialEnum, PointerRel, Spacebase
//   getSubType overriders                : Pointer, Array, Struct, Spacebase,
//       PartialStruct, Code  (Union's getSubType is commented out -> base/null;
//       Enum has none -> base/null)
//   findCompatibleResolve overriders     : Pointer, Array, Struct, Union,
//       PartialUnion  (type.hh:294/488/522/608/637/714)
//   isPtrsubMatching overriders          : Pointer, PointerRel
//   numDepend/getDepend for PointerRel inherit TypePointer's (1 / ptrto).

use kuna_decomp::dtype::TypeField;

/// F1 FIX CONFIRMATION (now flipped by w6-s5-type-2). The F1 fix demanded that
/// `Spacebase` must NOT use the *base* `compare` body (which would equate
/// distinct-localframe spacebases as `Ok(0)`). w6-s5-type-2 ports the real
/// `TypeSpacebase::compare`/`compareDependency` (type.cc:3498-3514), which
/// tie-breaks on spaceid then localframe — so distinct localframes now compare
/// non-equal, and identical ones compare equal.  The pin flips from "must Err"
/// to "must distinguish localframes" (the property the F1 fix actually protects).
#[test]
fn w5r2_spacebase_compare_distinguishes_localframe() {
    let types = TypeFactoryImpl::new();
    let spc = const_space();
    let a = spacebase(&types, Some(Rc::clone(&spc)), Address::new(Rc::clone(&spc), 0x1000));
    let b = spacebase(&types, Some(Rc::clone(&spc)), Address::new(Rc::clone(&spc), 0x2000));
    // Distinct localframes must NOT equate (the F1 invariant); 0x1000 < 0x2000.
    assert_eq!(a.compare(&b, 10).unwrap(), -1);
    assert_eq!(b.compare(&a, 10).unwrap(), 1);
    assert_eq!(a.compare_dependency(&b).unwrap(), -1);
    // A self-spacebase compares equal (same spaceid, same localframe).
    assert_eq!(a.compare(&a.clone(), 10).unwrap(), 0);
}

/// `find_compatible_resolve` partition (type.hh:294/488/522/608/637/714). Of the
/// FIVE overriders, Pointer/Array (w6-s5-type-1) and Struct/Union/PartialUnion
/// (w6-s5-type-2) are now implemented; every other kind returns the base default
/// -1 (type.cc:600-604). PointerRel, Code, Spacebase, PartialStruct,
/// PartialEnum are NOT overriders -> base -1.
#[test]
fn w5r2_find_compatible_resolve_override_partition() {
    let types = TypeFactoryImpl::new();
    let int_t = types.intern(Datatype::new(4, type_metatype::TYPE_INT)).unwrap();

    // Base default -1 for non-overriders.
    assert_eq!(int_t.find_compatible_resolve(&int_t).unwrap(), -1);
    let void = types.intern(Datatype::new(0, type_metatype::TYPE_VOID)).unwrap();
    assert_eq!(void.find_compatible_resolve(&int_t).unwrap(), -1);
    let mut code = Datatype::new_with_align(1, 1, type_metatype::TYPE_CODE);
    code.kind = DatatypeKind::Code { proto: None };
    let code = types.intern(code).unwrap();
    assert_eq!(code.find_compatible_resolve(&int_t).unwrap(), -1);
    let mut pe_parent = Datatype::new(4, type_metatype::TYPE_ENUM_INT);
    pe_parent.kind = DatatypeKind::Enum { namemap: std::collections::BTreeMap::new() };
    let pe_parent = types.intern(pe_parent).unwrap();
    let mut pe = Datatype::new_with_align(2, -1, type_metatype::TYPE_PARTIALENUM);
    pe.kind = DatatypeKind::PartialEnum {
        stripped: int_t.id(),
        parent: pe_parent.id(),
        offset: 0,
    };
    let pe = types.intern(pe).unwrap();
    assert_eq!(pe.find_compatible_resolve(&int_t).unwrap(), -1);

    // Struct/Union/PartialUnion are now implemented (w6-s5-type-2).
    // TypeStruct::findCompatibleResolve (type.cc:2300-2311): field[0].type == ct
    // (a struct that needs resolution has exactly one field) -> 0.
    let mut s = Datatype::new_with_align(4, -1, type_metatype::TYPE_STRUCT);
    s.kind = DatatypeKind::Struct {
        field: vec![TypeField::new(0, 0, "a", int_t.id())],
        bitfield: vec![],
    };
    let s = types.intern(s).unwrap();
    assert_eq!(s.find_compatible_resolve(&int_t).unwrap(), 0);
    // TypeUnion::findCompatibleResolve (type.cc:2629-2649): the field == ct at
    // offset 0 -> its index.
    let mut u = Datatype::new_with_align(4, -1, type_metatype::TYPE_UNION);
    u.kind = DatatypeKind::Union {
        field: vec![TypeField::new(0, 0, "a", int_t.id())],
    };
    let u = types.intern(u).unwrap();
    assert_eq!(u.find_compatible_resolve(&int_t).unwrap(), 0);

    // TypePointer::findCompatibleResolve (type.cc:1347-1354): ct is a plain int
    // (not TYPE_PTR), so the override returns -1.
    let mut p = Datatype::new_with_align(8, -1, type_metatype::TYPE_PTR);
    p.kind = DatatypeKind::Pointer {
        ptrto: int_t.id(),
        spaceid: None,
        truncate: None,
        wordsize: 1,
    };
    let p = types.intern(p).unwrap();
    assert_eq!(p.find_compatible_resolve(&int_t).unwrap(), -1);

    // TypeArray::findCompatibleResolve (type.cc:1480-1490): arrayof IS int_t
    // (same graph identity), and int has no needsResolution, so `arrayof == ct`
    // -> 0.
    let mut a = Datatype::new_with_align(8, -1, type_metatype::TYPE_ARRAY);
    a.kind = DatatypeKind::Array { arrayof: int_t.id(), arraysize: 2 };
    let a = types.intern(a).unwrap();
    assert_eq!(a.find_compatible_resolve(&int_t).unwrap(), 0);
}

/// `get_sub_type` partition: Union and Enum are NOT getSubType overriders
/// (Union's is commented out in type.hh:619; Enum has none), so they take the
/// base body -> (None, off). Array/Pointer ARE overriders, implemented in
/// w6-s5-type-1; Struct is a type-2 overrider, now implemented (w6-s5-type-2).
#[test]
fn w5r2_get_sub_type_union_enum_are_base_not_stub() {
    let types = TypeFactoryImpl::new();
    let mut u = Datatype::new_with_align(8, -1, type_metatype::TYPE_UNION);
    u.kind = DatatypeKind::Union { field: vec![] };
    let u = types.intern(u).unwrap();
    let (sub, newoff) = u.get_sub_type(5).unwrap();
    assert!(sub.is_none(), "TypeUnion::getSubType is base (null) — type.hh:619 commented out");
    assert_eq!(newoff, 5, "base getSubType passes offset through unchanged");

    let mut e = Datatype::new_with_align(4, -1, type_metatype::TYPE_ENUM_INT);
    e.kind = DatatypeKind::Enum { namemap: std::collections::BTreeMap::new() };
    let e = types.intern(e).unwrap();
    let (sub, newoff) = e.get_sub_type(3).unwrap();
    assert!(sub.is_none());
    assert_eq!(newoff, 3);

    // Struct DOES override (type-2, now implemented): off 0 lands in field "a"
    // (offset 0, an int4), passing back the field type with newoff 0.
    let int_t = types.intern(Datatype::new(4, type_metatype::TYPE_INT)).unwrap();
    let mut s = Datatype::new_with_align(8, -1, type_metatype::TYPE_STRUCT);
    s.kind = DatatypeKind::Struct {
        field: vec![TypeField::new(0, 0, "a", int_t.id())],
        bitfield: vec![],
    };
    let s = types.intern(s).unwrap();
    let (sub, newoff) = s.get_sub_type(0).unwrap();
    assert!(sub.is_some());
    assert_eq!(newoff, 0);
    // An offset past the single field's extent (off 4 >= field end) -> base body.
    let (sub_oob, newoff_oob) = s.get_sub_type(4).unwrap();
    assert!(sub_oob.is_none());
    assert_eq!(newoff_oob, 4);
}

/// `PointerRel` inherits `TypePointer::numDepend()==1` and `getDepend(0)==ptrto`
/// (it does NOT override them — type.hh:724-770). The port must report 1 / ptrto.
/// `is_ptrsub_matching` is implemented for PointerRel (w6-s5-type-3), and
/// `getPtrInto`'s relative offset math is now ported (rport/w10-rel-pointer):
/// a relptr into a non-STRUCT/UNION points `offset` into the parent.
#[test]
fn w5r2_pointer_rel_inherits_pointer_depend_and_ptrsub_stubs() {
    let types = TypeFactoryImpl::new();
    let ptrto = types.intern(Datatype::new(4, type_metatype::TYPE_INT)).unwrap();
    let mut parent = Datatype::new(16, type_metatype::TYPE_STRUCT);
    parent.kind = DatatypeKind::Struct { field: vec![], bitfield: vec![] };
    let parent = types.intern(parent).unwrap();
    let mut pr = Datatype::new_with_align(8, -1, type_metatype::TYPE_PTRREL);
    pr.kind = DatatypeKind::PointerRel {
        ptrto: ptrto.id(),
        spaceid: None,
        wordsize: 1,
        stripped: None,
        parent: parent.id(),
        offset: 4,
    };
    let pr = types.intern(pr).unwrap();
    assert_eq!(pr.num_depend(), 1, "PointerRel inherits TypePointer::numDepend()==1");
    assert_eq!(pr.get_depend(0).unwrap().get_size(), 4, "inherited getDepend(0)==ptrto");
    assert_eq!(pr.get_ptr_to().unwrap().get_size(), 4);
    assert_eq!(pr.get_byte_offset(), Some(4));
    assert_eq!(pr.get_rel_parent().unwrap().get_size(), 16);
    // TypePointerRel::isPtrsubMatching (type.cc:3138-3147), stripped==None branch:
    // iOff = 0 + offset(4) + extra(0) = 4; 4 >= 0 && 4 <= parent->getSize()(16).
    assert!(pr.is_ptrsub_matching(0, 0, 1).unwrap());
    // TypePointerRel::getPtrInto (type.cc:3060-3070): ptrto is TYPE_INT (not a
    // STRUCT/UNION), so the relptr points `offset` (4) into the parent (size 16).
    let (into, off) = pr.get_ptr_into().unwrap().unwrap();
    assert_eq!(off, 4, "non-composite ptrto: off = offset");
    assert_eq!(into.get_size(), 16, "non-composite ptrto: returns the parent");
    assert_eq!(into.id(), parent.id());
    // A relptr whose ptrto IS a STRUCT points directly at the composite (off = 0).
    let mut struct_to = Datatype::new(16, type_metatype::TYPE_STRUCT);
    struct_to.kind = DatatypeKind::Struct { field: vec![], bitfield: vec![] };
    let struct_to = types.intern(struct_to).unwrap();
    let mut pr_struct = Datatype::new_with_align(8, -1, type_metatype::TYPE_PTRREL);
    pr_struct.kind = DatatypeKind::PointerRel {
        ptrto: struct_to.id(),
        spaceid: None,
        wordsize: 1,
        stripped: None,
        parent: parent.id(),
        offset: 4,
    };
    let pr_struct = types.intern(pr_struct).unwrap();
    let (into_s, off_s) = pr_struct.get_ptr_into().unwrap().unwrap();
    assert_eq!(off_s, 0, "STRUCT ptrto: off = 0");
    assert_eq!(into_s.id(), struct_to.id(), "STRUCT ptrto: returns ptrto");
}

/// Flow resolution preserves the graph identity of a plain integer, whose type
/// has no union-dependent resolution.
#[test]
fn w5r2_resolve_in_flow_base_is_stubbed_loss_f2() {
    let types = TypeFactoryImpl::new();
    let int_t = types.intern(Datatype::new(4, type_metatype::TYPE_INT)).unwrap();
    // OpId is a slotmap key newtype; its default (null) key is a valid opaque handle
    // (the identity path never reads it).
    let op = kuna_decomp::context::OpId::default();
    let resolved = int_t.resolve_in_flow(op, 0).expect("base resolveInFlow returns `this`");
    assert_eq!(
        resolved.id(), int_t.id(),
        "base resolveInFlow returns the receiver unchanged (C++ `return this`)"
    );
    let found = int_t.find_resolve(op, -1).expect("base findResolve returns `this`");
    assert_eq!(
        found.id(), int_t.id(),
        "base findResolve returns the receiver unchanged (C++ `return this`)"
    );
}
