//! (kuna `castwiden`) A 64-bit widening C performs by itself keeps no cast.
//!
//! An `INT_SEXT`/`INT_ZEXT` to eight bytes prints as `(long)x` or
//! `(unsigned long)x` wherever `CastStrategyC::isExtensionCastImplied`
//! (cast.cc:249) declines it, and that predicate accepts only an arithmetic
//! reader whose other operand is an explicit variable of the same metatype.  So
//! kuna prints `v3 = (long)v8 * 0xc + (long)v9;`, `v1 + (long)i` where `v1` is a
//! `*(unsigned long *)` load, and `v = (unsigned long)i;` into an `unsigned long
//! v`, where C converts the operand to the very same type by itself.
//!
//! # Arithmetic operands
//!
//! For `+ - * / % & | ^` (the ten integer ops C prints with those operators) C
//! converts both operands to their common type, integer promotion first
//! (C11 6.3.1.1, 6.3.1.8).  The cast on operand `x` is left out when, for every
//! type the other operand `y` may have as printed:
//!
//! - the common type of `(T)x` and `y` is the common type of `x` and `y`, so the
//!   operation and its result have the type they had; and
//! - that common type is `T` itself, or the cast keeps every value of `x`, so C's
//!   conversion of `x` to the common type yields what the cast followed by that
//!   conversion yielded (an integer conversion depends only on the value it
//!   converts, 6.3.1.3).
//!
//! In practice the other operand is printed as exactly `T` (`v1 + i` for a
//! `long v1`), or as `unsigned long` beside a value-keeping `(long)`.  The
//! extension must be the one C performs on the operand's printed type: a
//! sign-extension of a signed operand, a zero-extension of an unsigned one; any
//! other pairing keeps its cast.  Comparisons, shifts, unary minus and every
//! other reader are left alone, and of two widened operands only one cast goes
//! (the right one), so the survivor still makes the operation 64-bit.  An op that
//! reads one widened value in both slots (`(long)i * (long)i`) keeps both: the
//! printer asks per reader, not per slot, so leaving one out would leave out
//! both.
//!
//! The operand keeps the parentheses the cast gave it: it prints as upstream's
//! hidden extension does, parenthesized whenever its operator binds no tighter
//! than the reader's, so `p + (long)(a + b)` prints `p + (a + b)` and never
//! `p + a + b`, which C would group as `(p + a) + b` and compute at 64 bits.
//! The printer also writes `x + (y + z)` as `x + y + z`, which C groups as
//! `(x + y) + z`; so the left operand of `+ * & | ^` whose right operand is such
//! a chain loses its cast only when the chain's first leaf, as printed, would let
//! it go too (`(long)i + ((long)j + v)` keeps a cast on `i` or `j`).
//!
//! With the value `literal`, an operand beside an integer literal is handled
//! too: the literal is an eight-byte constant in the IR, but C types `8` as
//! `int`, so today the cast is what makes `(long)i * 8` a 64-bit product.
//! Printing the literal with the suffix that gives it its IR width, `8L` (`8UL`
//! for an unsigned target), makes C convert `i` itself: `i * 8L`.  The literal
//! keeps its digits and value; a negated unsigned literal (`-0x80000000`, whose C
//! value is positive) is refused.
//!
//! # Destinations
//!
//! `castimplied` leaves out a value-keeping widening into a destination declared
//! with exactly the cast's spelling.  With this option on it also leaves out, of
//! a widening to eight bytes (a narrower one keeps what `castimplied` decides),
//!
//! - a widening that does not keep the value (`(unsigned long)i` of an `int`)
//!   into a destination of exactly that type: the assignment, argument or return
//!   conversion is then the very conversion the cast spelled (6.5.16.1p2,
//!   6.5.2.2p7, 6.8.6.4p3), provided the operand's printed type is a known
//!   integer and the extension is the one C performs on it;
//! - a value-keeping widening into a destination that is an integer of the
//!   cast's width with the other signedness (`(long)i` into an `unsigned long`);
//! - the same into a store through a pointer whose pointee is that type
//!   (`*p = i;`), a pointer that prints as a declared variable, a cast, a field
//!   or an element.
//!
//! The last two only for an operand that prints as a C integer (not `bool`)
//! which C extends the way the widening does.
//!
//! Only where `int` is 4 bytes, and only for output languages with C's integer
//! conversions.
//!
//! Query-backed printed forms are fallible throughout this helper graph.
//! `Ok(None)` and `Ok(false)` mean ordinary semantic refusal; acquisition
//! failures propagate to the printer without selecting a different cast plan.

use std::rc::Rc;

use kuna_base::error::KunaResult;
use kuna_num::opcodes::OpCode;

use crate::context::{OpId, VarnodeId};
use crate::dtype::{type_metatype, Datatype};
use crate::funcdata::Funcdata;
use crate::kuna_castimplied::{int_range, preserves, CType, ImpliedCasts, PrintedForms};
use crate::kuna_castternary::{literal_type, promote, usual, INT, LONG, UINT, ULONG};

/// The value of `castwiden`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CastWidenMode {
    /// Every widening upstream prints stays.
    #[default]
    Off,
    /// Widenings the other operand or the destination already converts go.
    On,
    /// `On`, and a literal operand is printed with its IR width's suffix.
    Literal,
}

impl CastWidenMode {
    pub fn as_str(self) -> &'static str {
        match self {
            CastWidenMode::Off => "off",
            CastWidenMode::On => "on",
            CastWidenMode::Literal => "literal",
        }
    }
}

/// The `castwiden` option parser.
pub struct OptionCastWiden;

impl OptionCastWiden {
    pub const NAME: &'static str = "castwiden";

    pub fn apply(&self, p1: &str) -> kuna_base::error::KunaResult<(CastWidenMode, String)> {
        let mode = match p1 {
            "off" => CastWidenMode::Off,
            "on" => CastWidenMode::On,
            "literal" => CastWidenMode::Literal,
            other => {
                return Err(kuna_base::error::KunaError::parse(format!(
                    "Unknown castwiden value: {other} (expected off|on|literal)"
                )))
            }
        };
        Ok((mode, format!("Implied 64-bit widening elision set to {}", mode.as_str())))
    }
}

/// What an arithmetic op prints differently.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct Plan {
    /// The widening one operand keeps no cast for.
    pub(crate) drop: Option<OpId>,
    /// The constant other operand, printed with the suffix that types it as the
    /// widening's target (`true`: `UL`, else `L`).
    pub(crate) suffix: Option<(VarnodeId, bool)>,
}

/// A widening an operand prints as a cast.
#[derive(Debug, Clone, Copy)]
struct Widening {
    op: OpId,
    /// The promoted type it converts to: `LONG` or `ULONG`.
    to: u8,
    /// The promoted type of its operand: `INT` or `UINT`.
    from: u8,
    /// Does the conversion keep every value of its operand?
    keeps: bool,
}

const DEPTH: u32 = 8;

fn is_arith(code: OpCode) -> bool {
    matches!(
        code,
        OpCode::CPUI_INT_ADD
            | OpCode::CPUI_INT_SUB
            | OpCode::CPUI_INT_MULT
            | OpCode::CPUI_INT_DIV
            | OpCode::CPUI_INT_SDIV
            | OpCode::CPUI_INT_REM
            | OpCode::CPUI_INT_SREM
            | OpCode::CPUI_INT_AND
            | OpCode::CPUI_INT_OR
            | OpCode::CPUI_INT_XOR
    )
}

/// An integer C converts arithmetically: not `bool`, not an enum.
pub(crate) fn plain_int(t: &Datatype) -> bool {
    matches!(t.get_metatype(), type_metatype::TYPE_INT | type_metatype::TYPE_UINT)
        && !t.is_enum_type()
        && matches!(t.get_size(), 1 | 2 | 4 | 8)
        && int_range(t).is_some()
}

/// What the arithmetic op `r` prints differently (uncached; see
/// [`ImpliedCasts::widen_plan`]).
pub(crate) fn plan(ic: &ImpliedCasts, p: &dyn PrintedForms, fd: &Funcdata, r: OpId, depth: u32) -> KunaResult<Plan> {
    let Some(o) = fd.obank().get(r) else { return Ok(Plan::default()) };
    if !is_arith(o.code()) || o.num_input() != 2 {
        return Ok(Plan::default());
    }
    let (Some(a), Some(b)) = (o.get_in(0), o.get_in(1)) else { return Ok(Plan::default()) };
    if a == b {
        return Ok(Plan::default());
    }
    let ins = [a, b];
    for slot in [1usize, 0] {
        let Some(w) = widening(ic, p, fd, ins[slot], r, depth)? else { continue };
        let other = ins[1 - slot];
        if slot == 0 && !first_leaf_fits(ic, p, fd, o.code(), other, &w, depth)? {
            continue;
        }
        if operand_set(ic, p, fd, other, r, depth)?.is_some_and(|y| fits(&w, y)) {
            return Ok(Plan { drop: Some(w.op), suffix: None });
        }
        if ic.widen_literal() {
            if let Some(unsigned) = literal_suffix(p, fd, other, r, &w)? {
                return Ok(Plan { drop: Some(w.op), suffix: Some((other, unsigned)) });
            }
        }
    }
    Ok(Plan::default())
}

/// Does leaving out `w`'s cast keep the value where C regroups?  The printer
/// writes `x + (y + z)` as `x + y + z` (the same associative operator on the
/// right takes no parentheses), which C reads as `(x + y) + z`: `x` meets `y`, the
/// first leaf of the chain `other`, not the chain.  That leaf, as printed, must
/// let the cast go too, or `x` and `y` would be added at 32 bits.
fn first_leaf_fits(ic: &ImpliedCasts, p: &dyn PrintedForms, fd: &Funcdata, code: OpCode, other: VarnodeId, w: &Widening, depth: u32) -> KunaResult<bool> {
    if !matches!(
        code,
        OpCode::CPUI_INT_ADD | OpCode::CPUI_INT_MULT | OpCode::CPUI_INT_AND | OpCode::CPUI_INT_OR | OpCode::CPUI_INT_XOR
    ) {
        return Ok(true);
    }
    let mut leaf = other;
    let mut reader = None;
    loop {
        let Some(v) = fd.vbank().get(leaf) else { return Ok(false) };
        if v.is_explicit() || v.is_constant() || v.is_annotation() {
            break;
        }
        let Some(d) = v.get_def() else { break };
        let Some(dop) = fd.obank().get(d) else { return Ok(false) };
        if dop.code() != code || dop.num_input() != 2 {
            break;
        }
        let Some(first) = dop.get_in(0) else { return Ok(false) };
        reader = Some(d);
        leaf = first;
    }
    let Some(rd) = reader else { return Ok(true) };
    if depth + 1 > DEPTH {
        return Ok(false);
    }
    let pl = ic.widen_plan(p, fd, rd, depth + 1)?;
    let y = if pl.drop.is_some() && fd.vbank().get(leaf).and_then(|v| v.get_def()) == pl.drop {
        widening(ic, p, fd, leaf, rd, depth + 1)?.map(|x| x.from)
    } else if let Some((_, unsigned)) = pl.suffix.filter(|&(c, _)| c == leaf) {
        Some(if unsigned { ULONG } else { LONG })
    } else {
        operand_set(ic, p, fd, leaf, rd, depth + 1)?
    };
    Ok(y.is_some_and(|y| fits(w, y)))
}

/// The promoted types the set `y` holds.
fn each(y: u8) -> impl Iterator<Item = u8> {
    [INT, UINT, LONG, ULONG].into_iter().filter(move |b| y & b != 0)
}

/// The C type of the integer literal `tok` in either base: the printer picks
/// decimal or hexadecimal by magnitude and context, and the two bases give a
/// literal between 2^31 and 2^64 different types, so both are allowed for.
fn token_types(tok: &str, long_size: i32) -> Option<u8> {
    let t = tok.strip_prefix('-').unwrap_or(tok).to_ascii_lowercase();
    if t.ends_with('\'') {
        return literal_type(tok, long_size);
    }
    let num = t.trim_end_matches(['u', 'l']);
    let suffix = &t[num.len()..];
    let value = if let Some(h) = num.strip_prefix("0x") {
        u128::from_str_radix(h, 16).ok()?
    } else if num.len() > 1 && num.starts_with('0') {
        u128::from_str_radix(&num[1..], 8).ok()?
    } else {
        num.parse::<u128>().ok()?
    };
    let dec = literal_type(&format!("{value}{suffix}"), long_size)?;
    let hex = literal_type(&format!("0x{value:x}{suffix}"), long_size)?;
    Some(dec | hex)
}

/// Does leaving out `w`'s cast keep the type and value of an operation whose
/// other operand may have any type in `y`?
fn fits(w: &Widening, y: u8) -> bool {
    y != 0
        && each(y).all(|b| {
            let with = usual(w.to, b);
            with == usual(w.from, b) && (with == w.to || w.keeps)
        })
}

/// The suffix (`true` for `UL`) that types the constant `vn` read by `r` as
/// `w`'s target, when the suffixed literal keeps its value and the operation its
/// type.
fn literal_suffix(p: &dyn PrintedForms, fd: &Funcdata, vn: VarnodeId, r: OpId, w: &Widening) -> KunaResult<Option<bool>> {
    let Some(v) = fd.vbank().get(vn) else { return Ok(None) };
    if !v.is_constant() || v.is_annotation() || v.get_size() != 8 || fd.vn_high_equate_symbol(vn).is_some() {
        return Ok(None);
    }
    let Some(today_tok) = p.integer_token(vn, r, None)? else { return Ok(None) };
    let Some(today) = token_types(&today_tok, p.long_size()) else { return Ok(None) };
    if today_tok.starts_with('-') && today & (UINT | ULONG) != 0 {
        return Ok(None);
    }
    let unsigned = w.to == ULONG;
    let Some(typed_tok) = p.integer_token(vn, r, Some(unsigned))? else { return Ok(None) };
    let Some(typed) = token_types(&typed_tok, p.long_size()) else { return Ok(None) };
    let with = each(today).map(|t| usual(w.to, t)).fold(0, |a, b| a | b);
    Ok((typed == w.to && with == w.to && usual(w.from, typed) == with).then_some(unsigned))
}

/// The widening the operand `vn` of `r` prints as a cast there, when C would
/// perform that same extension on the operand's printed type.
fn widening(ic: &ImpliedCasts, p: &dyn PrintedForms, fd: &Funcdata, vn: VarnodeId, r: OpId, depth: u32) -> KunaResult<Option<Widening>> {
    let Some(v) = fd.vbank().get(vn) else { return Ok(None) };
    if v.is_explicit() || v.is_annotation() || v.is_constant() {
        return Ok(None);
    }
    let Some(def) = v.get_def() else { return Ok(None) };
    let Some(d) = fd.obank().get(def) else { return Ok(None) };
    let target = v.get_type_def_facing().clone();
    if target.get_size() != 8 || !plain_int(&target) {
        return Ok(None);
    }
    let sext = match d.code() {
        OpCode::CPUI_INT_SEXT => Some(true),
        OpCode::CPUI_INT_ZEXT => Some(false),
        OpCode::CPUI_CAST => None,
        _ => return Ok(None),
    };
    match sext {
        Some(_) if !p.extension_is_cast(def)? || p.extension_hidden(def, Some(r))? => return Ok(None),
        None if p.sign_dropped(def) => return Ok(None),
        _ => {}
    }
    let Some(to) = promote(&target) else { return Ok(None) };
    let Some(inn) = d.get_in(0) else { return Ok(None) };
    let (from, keeps) = match ic.operand_type(p, fd, inn, def)? {
        CType::Known(s) => {
            if !plain_int(&s) || s.get_size() >= 8 {
                return Ok(None);
            }
            let Some((lo, _)) = int_range(&s) else { return Ok(None) };
            if sext.is_some_and(|x| (lo < 0) != x) {
                return Ok(None);
            }
            let Some(from) = promote(&s) else { return Ok(None) };
            (from, preserves(&s, &target))
        }
        CType::Unknown => match (operand_set(ic, p, fd, inn, def, depth + 1)?, sext) {
            (Some(INT), Some(true)) => (INT, to == LONG),
            (Some(UINT), Some(false)) => (UINT, true),
            _ => return Ok(None),
        },
        CType::Opaque => return Ok(None),
    };
    Ok(Some(Widening { op: def, to, from, keeps }))
}

/// The promoted types (a set of `INT`/`UINT`/`LONG`/`ULONG`) the operand `vn`
/// has in C as printed where `reader` reads it, when the text says.  A widening
/// read by `reader` is taken as printed with its cast.
pub(crate) fn operand_set(ic: &ImpliedCasts, p: &dyn PrintedForms, fd: &Funcdata, vn: VarnodeId, reader: OpId, depth: u32) -> KunaResult<Option<u8>> {
    if depth > DEPTH {
        return Ok(None);
    }
    let Some(v) = fd.vbank().get(vn) else { return Ok(None) };
    if v.is_annotation() {
        return Ok(None);
    }
    if v.is_constant() {
        if fd.vn_high_equate_symbol(vn).is_some() {
            return Ok(None);
        }
        let Some(token) = p.integer_token(vn, reader, None)? else { return Ok(None) };
        return Ok(token_types(&token, p.long_size()));
    }
    if v.is_explicit() {
        return Ok(match ic.explicit_type(p, fd, vn, reader) {
            CType::Known(t) if plain_int(&t) => promote(&t),
            _ => None,
        });
    }
    let Some(def) = v.get_def() else { return Ok(None) };
    let Some(d) = fd.obank().get(def) else { return Ok(None) };
    let t = v.get_type_def_facing().clone();
    let inner = |d2: &crate::op::PcodeOp| {
        let Some(i) = d2.get_in(0) else { return Ok(None) };
        operand_set(ic, p, fd, i, def, depth + 1)
    };
    Ok(match d.code() {
        OpCode::CPUI_INT_SEXT | OpCode::CPUI_INT_ZEXT => {
            if !p.extension_is_cast(def)? {
                return Ok(None);
            }
            if p.extension_hidden(def, Some(reader))? || ic.drops(p, fd, def, Some(reader))? {
                return inner(d);
            }
            plain_int(&t).then(|| promote(&t)).flatten()
        }
        OpCode::CPUI_CAST => {
            if !plain_int(&t) {
                return Ok(None);
            }
            if p.sign_dropped(def) || ic.drops(p, fd, def, Some(reader))? {
                return inner(d);
            }
            promote(&t)
        }
        OpCode::CPUI_SUBPIECE if plain_int(&t) && p.truncation_is_cast(def)? => promote(&t),
        OpCode::CPUI_COPY => inner(d)?,
        OpCode::CPUI_LOAD => match ic.def_type(p, fd, def, t.clone(), Some(reader))? {
            CType::Known(k) if plain_int(&k) => promote(&k),
            _ => load_type(ic, p, fd, def)?.filter(|k| plain_int(k) && k.get_size() == t.get_size()).and_then(|k| promote(&k)),
        },
        OpCode::CPUI_INT_2COMP | OpCode::CPUI_INT_NEGATE => inner(d)?,
        c if is_arith(c) => expr_set(ic, p, fd, def, depth + 1)?,
        _ => None,
    })
}

/// The promoted types of the arithmetic op `def` as printed: the common types
/// of its operands', after what [`plan`] prints differently there.
fn expr_set(ic: &ImpliedCasts, p: &dyn PrintedForms, fd: &Funcdata, def: OpId, depth: u32) -> KunaResult<Option<u8>> {
    if depth > DEPTH {
        return Ok(None);
    }
    let Some(d) = fd.obank().get(def) else { return Ok(None) };
    if d.num_input() != 2 {
        return Ok(None);
    }
    let pl = ic.widen_plan(p, fd, def, depth)?;
    let mut sets = [0u8; 2];
    for (slot, set) in sets.iter_mut().enumerate() {
        let Some(vn) = d.get_in(slot as i32) else { return Ok(None) };
        let dropped = pl.drop.is_some_and(|w| fd.vbank().get(vn).and_then(|v| v.get_def()) == Some(w));
        *set = if dropped {
            let Some(w) = widening(ic, p, fd, vn, def, depth)? else { return Ok(None) };
            w.from
        } else if let Some((_, unsigned)) = pl.suffix.filter(|&(c, _)| c == vn) {
            if unsigned { ULONG } else { LONG }
        } else {
            let Some(set) = operand_set(ic, p, fd, vn, def, depth)? else { return Ok(None) };
            set
        };
    }
    let mut out = 0u8;
    for a in [INT, UINT, LONG, ULONG].into_iter().filter(|a| sets[0] & a != 0) {
        for b in [INT, UINT, LONG, ULONG].into_iter().filter(|b| sets[1] & b != 0) {
            out |= usual(a, b);
        }
    }
    Ok((out != 0).then_some(out))
}

/// Does the widening `ext` extend an operand that prints as a C integer narrower
/// than its output, the way C extends that type (`castimplied`'s destinations
/// under `castwiden`)?
pub(crate) fn narrow_operand(ic: &ImpliedCasts, p: &dyn PrintedForms, fd: &Funcdata, ext: OpId) -> KunaResult<bool> {
    let Some(d) = fd.obank().get(ext) else { return Ok(false) };
    let sext = match d.code() {
        OpCode::CPUI_INT_SEXT => Some(true),
        OpCode::CPUI_INT_ZEXT => Some(false),
        OpCode::CPUI_CAST => None,
        _ => return Ok(false),
    };
    let (Some(inn), Some(out)) = (d.get_in(0), d.get_out().and_then(|o| fd.vbank().get(o))) else { return Ok(false) };
    let size = out.get_size();
    Ok(match ic.operand_type(p, fd, inn, ext)? {
        CType::Known(s) => {
            plain_int(&s)
                && s.get_size() < size
                && int_range(&s).is_some_and(|(lo, _)| sext.is_none_or(|x| (lo < 0) == x))
        }
        CType::Unknown => matches!(
            (operand_set(ic, p, fd, inn, ext, 1)?, sext),
            (Some(INT), Some(true) | None) | (Some(UINT), Some(false) | None)
        ),
        CType::Opaque => false,
    })
}

/// The type of the object a `STORE` writes, as its printed pointer states it.
pub(crate) fn store_pointee(ic: &ImpliedCasts, p: &dyn PrintedForms, fd: &Funcdata, store: OpId) -> KunaResult<Option<Rc<Datatype>>> {
    let Some(o) = fd.obank().get(store) else { return Ok(None) };
    if o.code() != OpCode::CPUI_STORE {
        return Ok(None);
    }
    let Some(ptr) = o.get_in(1) else { return Ok(None) };
    let Some(t) = pointee(ic, p, fd, ptr, store)? else { return Ok(None) };
    let Some(value) = o.get_in(2).and_then(|v| fd.vbank().get(v)) else { return Ok(None) };
    Ok((t.get_size() == value.get_size()).then_some(t))
}

/// The type of the object a `LOAD` reads, as its printed pointer states it.
fn load_type(ic: &ImpliedCasts, p: &dyn PrintedForms, fd: &Funcdata, load: OpId) -> KunaResult<Option<Rc<Datatype>>> {
    let Some(o) = fd.obank().get(load) else { return Ok(None) };
    if o.code() != OpCode::CPUI_LOAD {
        return Ok(None);
    }
    let Some(ptr) = o.get_in(1) else { return Ok(None) };
    let Some(t) = pointee(ic, p, fd, ptr, load)? else { return Ok(None) };
    let Some(out) = o.get_out().and_then(|v| fd.vbank().get(v)) else { return Ok(None) };
    Ok((t.get_size() == out.get_size()).then_some(t))
}

/// The type the pointer `ptr` read by `op` points at as printed: a variable
/// declared `T *`, a cast `(T *)`, a field `base->f` of a structure, or an element
/// `base[i]` of a base printed as one of the first two.
fn pointee(ic: &ImpliedCasts, p: &dyn PrintedForms, fd: &Funcdata, ptr: VarnodeId, op: OpId) -> KunaResult<Option<Rc<Datatype>>> {
    let Some(pv) = fd.vbank().get(ptr) else { return Ok(None) };
    if pv.is_constant() || pv.is_annotation() {
        return Ok(None);
    }
    if pv.is_explicit() {
        return Ok(declared_pointee(ic, p, fd, ptr, op));
    }
    let Some(def) = pv.get_def() else { return Ok(None) };
    let Some(d) = fd.obank().get(def) else { return Ok(None) };
    Ok(match d.code() {
        OpCode::CPUI_CAST => {
            let t = pv.get_type_def_facing().clone();
            (t.get_metatype() == type_metatype::TYPE_PTR).then(|| t.get_ptr_to()).flatten()
        }
        OpCode::CPUI_PTRSUB => field_type(fd, def)?,
        OpCode::CPUI_PTRADD => {
            let Some(base) = d.get_in(0) else { return Ok(None) };
            let Some(elem) = d.get_in(2).and_then(|v| fd.vbank().get(v)) else { return Ok(None) };
            let Some(bv) = fd.vbank().get(base) else { return Ok(None) };
            let t = if bv.is_explicit() {
                let Some(t) = declared_pointee(ic, p, fd, base, def) else { return Ok(None) };
                t
            } else {
                let Some(c) = bv.get_def().and_then(|d| fd.obank().get(d)) else { return Ok(None) };
                if c.code() != OpCode::CPUI_CAST {
                    return Ok(None);
                }
                let bt = bv.get_type_def_facing().clone();
                if bt.get_metatype() != type_metatype::TYPE_PTR {
                    return Ok(None);
                }
                let Some(t) = bt.get_ptr_to() else { return Ok(None) };
                t
            };
            (elem.is_constant() && elem.get_offset() == t.get_size() as u64).then_some(t)
        }
        _ => None,
    })
}

/// The pointee of the declaration an explicit pointer `vn` prints with.
fn declared_pointee(ic: &ImpliedCasts, p: &dyn PrintedForms, fd: &Funcdata, vn: VarnodeId, op: OpId) -> Option<Rc<Datatype>> {
    match ic.explicit_type(p, fd, vn, op) {
        CType::Known(t) if t.get_metatype() == type_metatype::TYPE_PTR => t.get_ptr_to(),
        _ => None,
    }
}

/// The type of the structure member the `PTRSUB` `op` prints as `base->f`, when
/// the member starts exactly at its offset and its type is the one the `PTRSUB`
/// points at.
fn field_type(fd: &Funcdata, op: OpId) -> KunaResult<Option<Rc<Datatype>>> {
    let Some(o) = fd.obank().get(op) else { return Ok(None) };
    let Some(base) = o.get_in(0).and_then(|v| fd.vbank().get(v)) else { return Ok(None) };
    let Some(off) = o.get_in(1).and_then(|v| fd.vbank().get(v)).filter(|c| c.is_constant()) else { return Ok(None) };
    let off = off.get_offset();
    let pt = base.get_type().clone();
    if pt.get_metatype() != type_metatype::TYPE_PTR || pt.is_formal_pointer_rel() || pt.get_word_size() != Some(1) {
        return Ok(None);
    }
    let Some(ct) = pt.get_ptr_to() else { return Ok(None) };
    if ct.get_metatype() != type_metatype::TYPE_STRUCT {
        return Ok(None);
    }
    let Some((idx, noff)) = ct.find_truncation(off as i64, 0, op, 0)? else { return Ok(None) };
    if noff != 0 {
        return Ok(None);
    }
    let Some(field) = ct.get_field(idx) else { return Ok(None) };
    let field = field.field_type.clone();
    let Some(out) = o.get_out().and_then(|v| fd.vbank().get(v)) else { return Ok(None) };
    let out = out.get_type_def_facing().clone();
    let Some(pointed) = out.get_ptr_to() else { return Ok(None) };
    Ok((p_same(&pointed, &field)).then_some(field))
}

fn p_same(a: &Datatype, b: &Datatype) -> bool {
    std::ptr::eq(a, b) || (a.get_size() == b.get_size() && a.get_metatype() == b.get_metatype() && a.get_name() == b.get_name())
}

#[cfg(test)]
#[path = "kuna_castwiden/tests.rs"]
mod tests;
