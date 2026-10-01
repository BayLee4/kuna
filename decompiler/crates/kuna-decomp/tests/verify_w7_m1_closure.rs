//! Enum matching boundary regressions over factory-owned datatype graphs.

use std::collections::BTreeMap;
use kuna_decomp::dtype::{flags, type_metatype, Datatype, DatatypeKind, TypeFactoryImpl, TypeRoot};

fn factory() -> TypeFactoryImpl {
    let types = TypeFactoryImpl::new();
    types.set_default_alignment_map();
    types.set_max_basetype_size(8);
    types
}

/// Same construction as testtypes.rs `make_enum` (an interned `TypeEnum` after
/// decode): a BTreeMap<u64,String> keyed by value, x86-64 default enum size 8.
fn make_enum(types: &TypeFactoryImpl, size: i32, entries: &[(u64, &str)]) -> TypeRoot {
    let mut dt = Datatype::new_with_align(size, size, type_metatype::TYPE_INT);
    dt.flags |= flags::enumtype;
    let mut namemap: BTreeMap<u64, String> = BTreeMap::new();
    for (v, n) in entries {
        namemap.insert(*v, (*n).to_string());
    }
    dt.kind = DatatypeKind::Enum { namemap };
    types.intern(dt).unwrap()
}

/// enum3 { ZERO=0, ONE=1, TWO=2, FOUR=4, EIGHT=8 } — the C++ enum_matching
/// fixture — probed at inputs the original TEST does NOT cover.  Each expected
/// value is hand-derived from TypeEnum::getMatches (type.cc:1537).
#[test]
fn w7_m1_closure_enum3_extra_boundary_inputs() {
    let types = factory();
    let enum3 = make_enum(
        &types,
        8,
        &[(0, "ZERO"), (1, "ONE"), (2, "TWO"), (4, "FOUR"), (8, "EIGHT")],
    );

    // 3 = 2 | 1  -> ["TWO","ONE"] (greedy MSB-first), not complement.
    let r = enum3.get_matches(3).unwrap();
    assert_eq!(r.match_name, vec!["TWO", "ONE"], "3 == TWO|ONE");
    assert!(!r.complement);

    // 15 = 8|4|2|1 -> ["EIGHT","FOUR","TWO","ONE"], not complement.
    let r = enum3.get_matches(15).unwrap();
    assert_eq!(
        r.match_name,
        vec!["EIGHT", "FOUR", "TWO", "ONE"],
        "15 == EIGHT|FOUR|TWO|ONE"
    );
    assert!(!r.complement);

    // 13 = 8|4|1 -> ["EIGHT","FOUR","ONE"].
    let r = enum3.get_matches(13).unwrap();
    assert_eq!(r.match_name, vec!["EIGHT", "FOUR", "ONE"], "13 == EIGHT|FOUR|ONE");
    assert!(!r.complement);

    // Complement path with size 8: ~8 = 0xfffffffffffffff7 is the original
    // TEST's complement row; verify the sibling ~1 = 0xfffffffffffffffe, which
    // complements to 1 -> ["ONE"], complement=true.
    let r = enum3.get_matches(0xfffffffffffffffe).unwrap();
    assert_eq!(r.match_name, vec!["ONE"], "~1 == complement of ONE");
    assert!(r.complement);

    // 6 = 4|2 (no SIX member here) -> ["FOUR","TWO"], not complement.
    let r = enum3.get_matches(6).unwrap();
    assert_eq!(r.match_name, vec!["FOUR", "TWO"], "6 == FOUR|TWO");
    assert!(!r.complement);
}

/// enum4 { ZERO,ONE,TWO,FOUR,SIX=6,EIGHT,ELEVEN=11 } — the enum_matching2
/// fixture — probed at extra inputs.  SIX=6 (a non-power-of-two member) and
/// ELEVEN=11 exercise the upper_bound/predecessor walk and the restricted
/// re-search branch (`target = curval & ~diff`).
#[test]
fn w7_m1_closure_enum4_extra_boundary_inputs() {
    let types = factory();
    let enum4 = make_enum(
        &types,
        8,
        &[
            (0, "ZERO"),
            (1, "ONE"),
            (2, "TWO"),
            (4, "FOUR"),
            (6, "SIX"),
            (8, "EIGHT"),
            (11, "ELEVEN"),
        ],
    );

    // 6 is an exact member -> ["SIX"] alone (single-name hit, not FOUR|TWO).
    let r = enum4.get_matches(6).unwrap();
    assert_eq!(r.match_name, vec!["SIX"], "6 is the exact member SIX");
    assert!(!r.complement);

    // 14 = 8 | 6 -> greedy picks EIGHT (msb), leftover 6 hits SIX exactly:
    // ["EIGHT","SIX"].
    let r = enum4.get_matches(14).unwrap();
    assert_eq!(r.match_name, vec!["EIGHT", "SIX"], "14 == EIGHT|SIX");
    assert!(!r.complement);

    // 11 is an exact member -> ["ELEVEN"] (the original TEST checks this row;
    // re-pinned here as the oracle for the predecessor walk landing on the
    // largest key).
    let r = enum4.get_matches(11).unwrap();
    assert_eq!(r.match_name, vec!["ELEVEN"], "11 is the exact member ELEVEN");
    assert!(!r.complement);

    // 16 = 0x10 has no representation (no member, and complement ~0x10 over
    // size 8 also cannot be ORed from {1,2,4,6,8,11}) -> empty, not complement.
    let r = enum4.get_matches(0x10).unwrap();
    assert!(r.match_name.is_empty(), "0x10 has no enum4 representation");
    assert!(!r.complement);
}


