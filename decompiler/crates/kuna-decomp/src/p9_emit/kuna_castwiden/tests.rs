//! Tests for the arithmetic `castwiden` rests on.
//!
//! Which cast a function prints needs a decompile and is covered end to end by
//! `tests/stages/kuna-castwiden.xml` (off, on, literal) and by the compiled round
//! trip in `kuna-cli/tests/decompile_all_cli.rs`
//! (`an_implied_widening_round_trips_through_the_printed_c`).  What is pinned here
//! is the rule every removal rests on: `fits` accepts a widening only where C's
//! usual arithmetic conversions give the same type and the same value without it.

use super::*;

use kuna_base::address::Address;
use kuna_base::error::KunaError;
use kuna_base::space::{addrspace_flags, spacetype, AddrSpace, AddrSpaceManager, ConstantSpace, UniqueSpace};

use crate::context::{ArchContext, HighVariableId};
use crate::dtype::TypeFactoryImpl;

/// A promoted C integer type as (bits, signed).
fn shape(t: u8) -> (u32, bool) {
    match t {
        INT => (32, true),
        UINT => (32, false),
        LONG => (64, true),
        _ => (64, false),
    }
}

/// C's conversion of the value `v` to the promoted type `t` (C11 6.3.1.3; gcc and
/// clang define the signed case modulo 2^N).
fn conv(v: i128, t: u8) -> i128 {
    let (bits, signed) = shape(t);
    let m = v.rem_euclid(1i128 << bits);
    if signed && m >= 1i128 << (bits - 1) {
        m - (1i128 << bits)
    } else {
        m
    }
}

/// `a op b` evaluated in the promoted type `t` (wrapping; the unsigned rule, and
/// what the binary computes).
fn eval(op: char, a: i128, b: i128, t: u8) -> Option<i128> {
    let (bits, signed) = shape(t);
    let r = match op {
        '+' => a + b,
        '-' => a - b,
        '*' => a.wrapping_mul(b),
        '&' => a.rem_euclid(1i128 << bits) & b.rem_euclid(1i128 << bits),
        '|' => a.rem_euclid(1i128 << bits) | b.rem_euclid(1i128 << bits),
        '^' => a.rem_euclid(1i128 << bits) ^ b.rem_euclid(1i128 << bits),
        '/' | '%' => {
            if b == 0 || (signed && b == -1) {
                return None;
            }
            let q = a / b;
            if op == '/' {
                q
            } else {
                a - q * b
            }
        }
        _ => unreachable!(),
    };
    Some(conv(r, t))
}

fn samples(t: u8) -> Vec<i128> {
    let (bits, signed) = shape(t);
    let (lo, hi) = if signed {
        (-(1i128 << (bits - 1)), (1i128 << (bits - 1)) - 1)
    } else {
        (0, (1i128 << bits) - 1)
    };
    let mut v = vec![lo, lo + 1, -7, -1, 0, 1, 3, 0x7fff_ffff, 0x8000_0000, 0xffff_ffff, 0x1_0000_0000, hi - 1, hi];
    v.retain(|x| (lo..=hi).contains(x));
    v
}

#[test]
fn fits_is_exactly_an_unchanged_type_and_value() {
    for to in [LONG, ULONG] {
        for from in [INT, UINT] {
            // The extension C performs on `from`: a value `from` keeps under `to`
            // unless `to` cannot hold its negative values.
            let keeps = !(from == INT && to == ULONG);
            let w = Widening { op: OpId::default(), to, from, keeps };
            for y in [INT, UINT, LONG, ULONG] {
                let with_t = usual(to, y);
                let bare_t = usual(from, y);
                let mut same = with_t == bare_t;
                for &x in &samples(from) {
                    for &b in &samples(y) {
                        for op in ['+', '-', '*', '&', '|', '^', '/', '%'] {
                            let with = eval(op, conv(conv(x, to), with_t), conv(b, with_t), with_t);
                            let bare = eval(op, conv(x, bare_t), conv(b, bare_t), bare_t);
                            if with != bare {
                                same = false;
                            }
                        }
                    }
                }
                assert_eq!(fits(&w, y), same, "to {to} from {from} other {y}");
            }
        }
    }
}

#[test]
fn of_several_possible_types_every_one_must_fit() {
    let w = Widening { op: OpId::default(), to: LONG, from: INT, keeps: true };
    assert!(fits(&w, LONG));
    assert!(fits(&w, ULONG));
    assert!(!fits(&w, LONG | INT));
    assert!(!fits(&w, 0));
}

#[test]
fn a_literal_is_typed_in_both_bases() {
    assert_eq!(token_types("8", 8), Some(INT));
    assert_eq!(token_types("0xc", 8), Some(INT));
    assert_eq!(token_types("8L", 8), Some(LONG));
    assert_eq!(token_types("0xcL", 8), Some(LONG));
    assert_eq!(token_types("-4UL", 8), Some(ULONG));
    assert_eq!(token_types("3UL", 8), Some(ULONG));
    // Printed in decimal `3000000000` is a `long`; in hex, `0xb2d05e00` is an
    // `unsigned int`.  The printer picks the base, so both are allowed for.
    assert_eq!(token_types("3000000000", 8), Some(LONG | UINT));
    assert_eq!(token_types("0xb2d05e00", 8), Some(LONG | UINT));
    assert_eq!(token_types("-0x80000000", 8), Some(LONG | UINT));
    assert_eq!(token_types("0x100000000", 8), Some(LONG));
    // Too wide for a decimal literal of any signed type: no C type at all.
    assert_eq!(token_types("18446744073709551615", 8), None);
    assert_eq!(token_types("0x100000000L", 8), Some(LONG));
    assert_eq!(token_types("'a'", 8), Some(INT));
}

#[test]
fn a_long_suffix_where_long_is_four_bytes_is_long_long() {
    assert_eq!(token_types("8LL", 4), Some(LONG));
    assert_eq!(token_types("8ULL", 4), Some(ULONG));
    assert_eq!(token_types("8L", 4), Some(INT));
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Query {
    ExtensionCast,
    ExtensionHidden,
    Truncation,
    Integer,
    Suffix,
}

struct Forms {
    fail: Option<Query>,
    token: Option<&'static str>,
    extension_cast: bool,
}

impl Forms {
    fn acquire<T>(&self, query: Query, value: T) -> KunaResult<T> {
        if self.fail == Some(query) {
            Err(KunaError::data_unavail("printed widening acquisition"))
        } else {
            Ok(value)
        }
    }
}

impl PrintedForms for Forms {
    fn spell(&self, ty: &Rc<Datatype>) -> String {
        ty.get_name().to_owned()
    }

    fn extension_is_cast(&self, _op: OpId) -> KunaResult<bool> {
        self.acquire(Query::ExtensionCast, self.extension_cast)
    }

    fn extension_hidden(&self, _op: OpId, _read_op: Option<OpId>) -> KunaResult<bool> {
        self.acquire(Query::ExtensionHidden, false)
    }

    fn sign_dropped(&self, _op: OpId) -> bool {
        false
    }

    fn truncation_is_cast(&self, _op: OpId) -> KunaResult<bool> {
        self.acquire(Query::Truncation, true)
    }

    fn high_name(&self, _high: HighVariableId) -> Option<String> {
        None
    }

    fn planned_decl_type(&self, _high: HighVariableId) -> Option<Rc<Datatype>> {
        None
    }

    fn is_statement(&self, _op: OpId) -> bool {
        false
    }

    fn literal_token(&self, vn: VarnodeId, op: OpId) -> KunaResult<Option<String>> {
        self.integer_token(vn, op, None)
    }

    fn long_size(&self) -> i32 {
        8
    }

    fn integer_token(&self, _vn: VarnodeId, _op: OpId, suffix: Option<bool>) -> KunaResult<Option<String>> {
        let query = if suffix.is_some() { Query::Suffix } else { Query::Integer };
        self.acquire(query, self.token.map(|token| match suffix {
            Some(true) => format!("{token}UL"),
            Some(false) => format!("{token}L"),
            None => token.to_owned(),
        }))
    }
}

fn query_fd() -> Funcdata {
    let mut manager = AddrSpaceManager::new();
    manager.insert_space(Rc::new(ConstantSpace::new())).unwrap();
    manager.insert_space(Rc::new(UniqueSpace::new(1, 0, false))).unwrap();
    let ram = Rc::new(AddrSpace::new(
        spacetype::IPTR_PROCESSOR, "ram", false, 8, 1, 2,
        addrspace_flags::hasphysical, 1, 1,
    ));
    manager.insert_space(ram.clone()).unwrap();
    let types = TypeFactoryImpl::new();
    types.setup_sizes(Some(4), 8, 8);
    types.set_default_alignment_map();
    types.set_max_basetype_size(8);
    let mut arch = ArchContext::new(manager);
    arch.types = Some(Rc::new(types));
    Funcdata::new("widen", "widen", Rc::new(arch), Address::new(ram, 0x1000), 0x1000_0000, 0x40).unwrap()
}

fn query_op(fd: &mut Funcdata, code: OpCode, inputs: &[VarnodeId], size: i32) -> (OpId, VarnodeId) {
    let op = fd.new_op(inputs.len() as i32, fd.get_address().clone());
    fd.op_set_opcode_code(op, code);
    for (slot, &input) in inputs.iter().enumerate() {
        fd.op_set_input(op, input, slot as i32).unwrap();
    }
    let out = fd.new_unique_out(size, op).unwrap();
    fd.vn_update_type(out, Rc::new(Datatype::new(size, type_metatype::TYPE_INT)));
    fd.vbank_mut().get_mut(out).unwrap().set_implied();
    (op, out)
}

#[test]
fn literal_acquisition_errors_are_not_semantic_absence() {
    let mut fd = query_fd();
    let literal = fd.new_constant(8, 8);
    let (reader, _) = query_op(&mut fd, OpCode::CPUI_COPY, &[literal], 8);
    let ic = ImpliedCasts::default();
    let w = Widening { op: reader, to: LONG, from: INT, keeps: true };
    let mut forms = Forms { fail: None, token: Some("8"), extension_cast: true };

    assert_eq!(operand_set(&ic, &forms, &fd, literal, reader, 0).unwrap(), Some(INT));
    assert_eq!(literal_suffix(&forms, &fd, literal, reader, &w).unwrap(), Some(false));
    forms.token = None;
    assert_eq!(operand_set(&ic, &forms, &fd, literal, reader, 0).unwrap(), None);
    assert_eq!(literal_suffix(&forms, &fd, literal, reader, &w).unwrap(), None);

    forms.token = Some("8");
    forms.fail = Some(Query::Integer);
    assert!(operand_set(&ic, &forms, &fd, literal, reader, 0).unwrap_err().to_string().contains("printed widening acquisition"));
    assert!(literal_suffix(&forms, &fd, literal, reader, &w).unwrap_err().to_string().contains("printed widening acquisition"));
    forms.fail = Some(Query::Suffix);
    assert!(literal_suffix(&forms, &fd, literal, reader, &w).unwrap_err().to_string().contains("printed widening acquisition"));
}

#[test]
fn widening_plan_propagates_extension_queries_without_changing_refusal() {
    let mut fd = query_fd();
    let input = fd.new_unique(4, Some(Rc::new(Datatype::new(4, type_metatype::TYPE_INT))));
    let (_, widened) = query_op(&mut fd, OpCode::CPUI_INT_SEXT, &[input], 8);
    let literal = fd.new_constant(8, 8);
    let (reader, _) = query_op(&mut fd, OpCode::CPUI_INT_ADD, &[literal, widened], 8);
    let ic = ImpliedCasts::default();
    let mut forms = Forms { fail: None, token: Some("8"), extension_cast: false };

    assert_eq!(plan(&ic, &forms, &fd, reader, 0).unwrap(), Plan::default());
    assert_eq!(operand_set(&ic, &forms, &fd, widened, reader, 0).unwrap(), None);
    forms.extension_cast = true;
    for query in [Query::ExtensionCast, Query::ExtensionHidden] {
        forms.fail = Some(query);
        assert!(plan(&ic, &forms, &fd, reader, 0).unwrap_err().to_string().contains("printed widening acquisition"));
        assert!(operand_set(&ic, &forms, &fd, widened, reader, 0).unwrap_err().to_string().contains("printed widening acquisition"));
    }
}

#[test]
fn truncation_query_errors_propagate_through_operand_types() {
    let mut fd = query_fd();
    let input = fd.new_constant(8, 8);
    let offset = fd.new_constant(4, 0);
    let (reader, truncated) = query_op(&mut fd, OpCode::CPUI_SUBPIECE, &[input, offset], 4);
    let ic = ImpliedCasts::default();
    let mut forms = Forms { fail: None, token: Some("8"), extension_cast: true };
    assert_eq!(operand_set(&ic, &forms, &fd, truncated, reader, 0).unwrap(), Some(INT));
    forms.fail = Some(Query::Truncation);
    assert!(operand_set(&ic, &forms, &fd, truncated, reader, 0).unwrap_err().to_string().contains("printed widening acquisition"));
}
