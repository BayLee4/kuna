//! Adversarial verifier tests for the W10 `rport/w10-typed-access` item.
//!
//! ## Context for the next porter
//!
//! At review time (round 1) the branch `rport/w10-typed-access` contained
//! **zero commits beyond its merge-base with `rust-port`** (reflog:
//! `branch: Created from rust-port`, no further entries) and an empty diff
//! against `rust-port`.  No seam was closed by this item; the typed-access
//! field-rendering / union-facet machinery these tests probe was already
//! landed and *verified* by the W6 items (`w6-s5-unionresolve`,
//! `w6-s5-type-2`, `w6-s5-bitfield`, `w6-s5-typeop`) and the W8 printc item.
//!
//! These tests therefore do **not** validate new work — there is none.  They
//! pin the C++ oracle semantics of the in-scope public union-truncation
//! scorer ([`score_truncation`]) and the locked-type scorer
//! ([`score_locked_type`]) so the eventual real typed-access port has a
//! standing parity fence it must not break.  Every asserted constant is taken
//! verbatim from `decompiler/cpp/unionresolve.cc:931-977`
//! (`ScoreUnionFields::scoreTruncation`) and `unionresolve.cc` /
//! `scoreLockedType`.
//!
//! Item id: w10-typed-access.

use kuna_base::types::int4;
use kuna_decomp::dtype::{type_metatype, Datatype, DatatypeKind, TypeFactory, TypeFactoryImpl, TypeField, TypeRoot};
use kuna_decomp::unionresolve::{score_locked_type, score_truncation};

// ---- type builders (mirror the in-module test helpers, public API only) ----

fn base(factory: &TypeFactoryImpl, size: int4, m: type_metatype) -> TypeRoot {
    factory.intern(Datatype::new(size, m)).unwrap()
}

/// Build a union of (offset, type) fields, exactly as the in-module
/// `make_union` helper does (C++ `TypeUnion`).
fn make_union(factory: &TypeFactoryImpl, name: &str, size: int4, fields: &[(int4, TypeRoot)]) -> TypeRoot {
    let mut u = Datatype::new(size, type_metatype::TYPE_UNION);
    u.name = name.to_string();
    u.id = Datatype::hash_name(name);
    let field: Vec<TypeField> = fields
        .iter()
        .enumerate()
        .map(|(i, (off, ct))| TypeField::new(i as int4, *off, format!("f{i}"), ct.id()))
        .collect();
    u.kind = DatatypeKind::Union { field };
    factory.intern(u).unwrap()
}

// ===========================================================================
// score_truncation — C++ unionresolve.cc:931-977
// ===========================================================================

/// UNION branch, size+offset match -> +10 (and ct returned as None: "Don't
/// recurse a data-type from truncation of a union").  cpp:935-948.
#[test]
fn w10_typed_access_union_field_size_match_scores_plus10() {
    let factory = TypeFactoryImpl::new();
    let int4t = base(&factory, 4, type_metatype::TYPE_INT);
    let u = make_union(&factory, "union_t", 8, &[(0, base(&factory, 8, type_metatype::TYPE_FLOAT)), (0, int4t)]);
    // vn_size 4 matches field f1 (offset 0, size 4).  result_base = None so the
    // `+5 if result.getBase()==unionDt` bonus does not apply.
    let (score, ct_out) = score_truncation(&u, 4, 0, None).unwrap();
    assert_eq!(score, 10, "union with a size/offset-matching field scores +10");
    assert!(ct_out.is_none(), "union truncation never recurses a member type (cpp:937)");
}

/// UNION branch, NO field matches the truncation size -> -10.  cpp:938.
#[test]
fn w10_typed_access_union_no_match_scores_minus10() {
    let factory = TypeFactoryImpl::new();
    // Only an 8-byte field; a 4-byte truncation at offset 0 matches nothing.
    let u = make_union(&factory, "union_t", 8, &[(0, base(&factory, 8, type_metatype::TYPE_FLOAT))]);
    let (score, ct_out) = score_truncation(&u, 4, 0, None).unwrap();
    assert_eq!(score, -10, "union with no size-matching field scores -10 (cpp:938)");
    assert!(ct_out.is_none());
}

/// UNION branch, matching field AND result base IS the union -> +10 +5 = +15.
/// cpp:944-945 (`if (result.getBase() == unionDt) score += 5;`).
#[test]
fn w10_typed_access_union_match_self_base_bonus_plus5() {
    let factory = TypeFactoryImpl::new();
    let int4t = base(&factory, 4, type_metatype::TYPE_INT);
    let u = make_union(&factory, "union_t", 4, &[(0, int4t.clone())]);
    // Pass the union itself as the result base -> the +5 self-base bonus fires.
    let (score, _ct) = score_truncation(&u, 4, 0, Some(&u)).unwrap();
    assert_eq!(score, 15, "matching field + base==union -> +10+5");
    // A *different* base must NOT get the bonus.
    let other = make_union(&factory, "other_union_t", 4, &[(0, int4t)]);
    let (score2, _) = score_truncation(&u, 4, 0, Some(&other)).unwrap();
    assert_eq!(score2, 10, "base != this union -> no +5 bonus");
}

/// SCALAR branch, exact size match at offset 0 -> loop never enters, +10, ct
/// preserved.  cpp:951-953 (`curOff==0 && size==vn->size` falsifies the guard).
#[test]
fn w10_typed_access_scalar_exact_match_scores_plus10() {
    let factory = TypeFactoryImpl::new();
    let int4t = base(&factory, 4, type_metatype::TYPE_INT);
    let (score, ct_out) = score_truncation(&int4t, 4, 0, None).unwrap();
    assert_eq!(score, 10, "exact scalar size/offset match scores +10");
    assert_eq!(ct_out, Some(int4t), "exact scalar truncation preserves its type");
}

/// SCALAR branch, an INT wider than the truncation that still covers it
/// (`size >= vn_size + curOff`) -> +1.  cpp:954-958.
#[test]
fn w10_typed_access_scalar_wider_int_covers_scores_plus1() {
    let factory = TypeFactoryImpl::new();
    // 8-byte int, truncate 4 bytes at offset 0: size(8) >= 4+0 -> score 1.
    let int8t = base(&factory, 8, type_metatype::TYPE_INT);
    let (score, _ct) = score_truncation(&int8t, 4, 0, None).unwrap();
    assert_eq!(score, 1, "wide INT covering the truncation scores +1 (cpp:956)");
}

/// SCALAR branch, a type that cannot be subdivided to reach the truncation
/// (here a bare 8-byte FLOAT, not INT/UINT/ARRAY/struct) -> getSubType yields
/// None, loop exits with ct==0 -> -10.  cpp:970-973.
#[test]
fn w10_typed_access_scalar_unreachable_scores_minus10() {
    let factory = TypeFactoryImpl::new();
    // 8-byte float, ask for a 4-byte truncation at a non-zero offset that no
    // sub-type can satisfy.  The while-guard stays true (curOff!=0), FLOAT is
    // neither INT/UINT nor ARRAY, getSubType(curOff) returns None -> ct==0.
    let f8 = base(&factory, 8, type_metatype::TYPE_FLOAT);
    let (score, ct_out) = score_truncation(&f8, 4, 2, None).unwrap();
    assert_eq!(score, -10, "no sub-type reaches the truncation -> -10 (cpp:973)");
    assert!(ct_out.is_none(), "ct==0 sentinel maps to None");
}

// ===========================================================================
// score_locked_type — pointer-chain stripping + metatype scoring
// ===========================================================================

/// Nominal-identity perfect match: lockType == ct -> +5 seed before
/// the pointer-strip loop even begins.  unionresolve.cc scoreLockedType head
/// (`if (lockType == ct) score += 5;`).
#[test]
fn w10_typed_access_locked_type_nominal_identity_seeds_plus5() {
    let factory = TypeFactoryImpl::new();
    let mut first = Datatype::new(4, type_metatype::TYPE_INT);
    first.name = "first_int".to_string();
    first.id = Datatype::hash_name(&first.name);
    let int4t = factory.intern(first).unwrap();
    // The same nominal type receives both identity and metatype contributions.
    let identical = score_locked_type(&int4t, &int4t);
    // A distinct nominal INT4 with the same layout does not receive the bonus.
    let mut second = Datatype::new(4, type_metatype::TYPE_INT);
    second.name = "second_int".to_string();
    second.id = Datatype::hash_name(&second.name);
    let other_int4 = factory.intern(second).unwrap();
    let distinct = score_locked_type(&int4t, &other_int4);
    assert_eq!(
        identical,
        distinct + 5,
        "nominal-identity match adds exactly +5 over a same-layout distinct type"
    );
}

/// Metatype mismatch (INT lock vs FLOAT ct, both non-pointer) is scored
/// strictly below a metatype match, and the function is total (never panics)
/// on mismatched leaf types.
#[test]
fn w10_typed_access_locked_type_metatype_mismatch_is_lower() {
    let factory = TypeFactoryImpl::new();
    let int4t = base(&factory, 4, type_metatype::TYPE_INT);
    let float4t = base(&factory, 4, type_metatype::TYPE_FLOAT);
    let matched = score_locked_type(&int4t, &int4t);
    let mismatched = score_locked_type(&float4t, &int4t);
    assert!(
        mismatched < matched,
        "metatype mismatch must score below an exact metatype match (matched={matched}, mismatched={mismatched})"
    );
}
