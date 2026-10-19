//! An unsigned read of an expression C evaluates as signed.
//!
//! C promotes an operand narrower than `int` to `int` before arithmetic, so
//! `(*a1 ^ 0x80) - 0x80` over an `unsigned short *a1` is an `int` in C, and so
//! is `(int)a0 + 1`. The Varnode such an expression computes can still be typed
//! `unsigned int`: `arithmeticOutputStandard` takes the most ordered operand
//! type and knows no promotion. A reader that treats its input as unsigned --
//! a zero extension, a logical right shift, an unsigned compare, divide or
//! remainder -- checks that unsigned type, finds nothing to cast, and the
//! printed C reads the value as signed: `(unsigned long)((*a1 ^ 0x80) - 0x80)`
//! sign-extends where the machine zero-extends. Such a read makes the
//! expression unsigned: a plain constant operand of its top operation takes
//! a `U` suffix (`v + 1U`), and otherwise the expression is cast to the
//! unsigned integer of its size. Neither happens when the value cannot be
//! negative (its nonzero-bit mask clears the top bit) or, for a compare,
//! divide or remainder, when the other operand already makes C convert it.
//!
//! The C type of the printed expression is computed bottom-up: a constant from
//! its literal, a variable, a cast or a load from the type the text states, an
//! extension from its input when C performs it implicitly, and arithmetic by
//! C's usual conversions over the promoted operands. Only expressions at least
//! as wide as `int` are considered; a narrower one is cast by the upstream
//! integer-promotion checks.

use std::rc::Rc;

use kuna_base::address::signbit_negative;
use kuna_base::error::KunaResult;
use kuna_base::types::int4;
use kuna_num::opcodes::OpCode;

use crate::cast::CastStrategy;
use crate::context::{OpId, VarnodeId};
use crate::coreaction_casts::FuncdataCastContext;
use crate::dtype::{type_metatype, Datatype, TypeFactory};
use crate::funcdata::Funcdata;

const DEPTH: u32 = 8;

/// A C integer type after promotion: `(unsigned, bytes)`.
pub(crate) type CInt = (bool, int4);

/// The unsigned type input `slot` of `op` must be cast to because the
/// expression there is a signed `int` or `long` in C, or `None`.
pub(crate) fn cast(data: &mut Funcdata, strat: &dyn CastStrategy, op: OpId, slot: int4) -> KunaResult<Option<Rc<Datatype>>> {
    if !data.get_arch().int_promotion || data.get_arch().out_lang == crate::kuna_lang::OutLang::Java {
        return Ok(None);
    }
    let Some(o) = data.obank().get(op) else { return Ok(None) };
    let binary = match o.code() {
        OpCode::CPUI_INT_ZEXT | OpCode::CPUI_INT_RIGHT if slot == 0 => false,
        OpCode::CPUI_INT_LESS | OpCode::CPUI_INT_LESSEQUAL | OpCode::CPUI_INT_DIV | OpCode::CPUI_INT_REM => true,
        _ => return Ok(None),
    };
    let Some(vn) = o.get_in(slot) else { return Ok(None) };
    let other = if binary { o.get_in(1 - slot) } else { None };
    let Some(v) = data.vbank().get(vn) else { return Ok(None) };
    if v.is_constant() || v.is_explicit() || !v.is_written() {
        return Ok(None);
    }
    let size = v.get_size();
    if size < strat.promote_size() || size > 8 || !signbit_negative(v.get_nz_mask(), size) {
        return Ok(None);
    }
    let ir = data.vn_type_read_facing(vn, op)?;
    if !matches!(ir.get_metatype(), type_metatype::TYPE_UINT | type_metatype::TYPE_UNKNOWN) {
        return Ok(None);
    }
    if c_int(data, strat, vn, op)? != Some((false, size)) {
        return Ok(None);
    }
    if let Some(other) = other {
        if c_int(data, strat, other, op)?.is_some_and(|(unsigned, width)| unsigned && width >= size) {
            return Ok(None);
        }
    }
    if let Some(c) = suffixable_literal(data, vn)? {
        if let Some(cv) = data.vbank_mut().get_mut(c) {
            cv.set_unsigned_print();
            if size > 4 {
                cv.set_long_print();
            }
            return Ok(None);
        }
    }
    let Some(types) = data.get_arch().types_rc() else { return Ok(None) };
    Ok(Some(types.get_base(size, type_metatype::TYPE_UINT)?))
}

/// A constant operand of the operation that computes the implied `vn` whose
/// `U` suffix makes the whole expression unsigned (`v + 1U`): an operand of
/// arithmetic whose result bits do not depend on the sign it computes with
/// (a division, a remainder or a shift would change meaning), printed as a
/// plain non-negative integer.
fn suffixable_literal(data: &Funcdata, vn: VarnodeId) -> KunaResult<Option<VarnodeId>> {
    let Some(def) = data.vbank().get(vn).and_then(|v| v.get_def()) else { return Ok(None) };
    let Some(d) = data.obank().get(def) else { return Ok(None) };
    if !matches!(
        d.code(),
        OpCode::CPUI_INT_ADD
            | OpCode::CPUI_INT_SUB
            | OpCode::CPUI_INT_MULT
            | OpCode::CPUI_INT_AND
            | OpCode::CPUI_INT_OR
            | OpCode::CPUI_INT_XOR
            | OpCode::CPUI_INT_NEGATE
            | OpCode::CPUI_INT_2COMP
    ) {
        return Ok(None);
    }
    for c in (0..d.num_input()).filter_map(|i| d.get_in(i)) {
        if data.vbank().get(c).is_some_and(|cv| cv.is_constant() && !cv.is_annotation()) {
            let t = data.vn_type_read_facing(c, def)?;
            if matches!(t.get_metatype(), type_metatype::TYPE_UINT | type_metatype::TYPE_UNKNOWN)
                && !t.is_char_print()
                && !t.is_enum_type()
                && data.vn_high_display_format(c) == 0
            {
                return Ok(Some(c));
            }
        }
    }
    Ok(None)
}

/// The promoted C type of `vn` as printed where `reader` reads it,
/// `(unsigned, bytes)`, or `None` when the text does not settle it.
pub(crate) fn c_int(data: &mut Funcdata, strat: &dyn CastStrategy, vn: VarnodeId, reader: OpId) -> KunaResult<Option<CInt>> {
    c_int_at(data, strat, vn, reader, DEPTH)
}

fn c_int_at(data: &mut Funcdata, strat: &dyn CastStrategy, vn: VarnodeId, reader: OpId, depth: u32) -> KunaResult<Option<CInt>> {
    let Some(v) = data.vbank().get(vn) else { return Ok(None) };
    if v.is_annotation() || depth == 0 {
        return Ok(None);
    }
    if v.is_constant() {
        return literal(data, vn, reader);
    }
    if v.is_explicit() || !v.is_written() {
        return Ok(declared(data.vn_type_read_facing(vn, reader)?.as_ref()));
    }
    let Some(def) = v.get_def() else { return Ok(None) };
    let Some(d) = data.obank().get(def) else { return Ok(None) };
    let code = d.code();
    let ins: Vec<VarnodeId> = (0..d.num_input()).filter_map(|i| d.get_in(i)).collect();
    let info = crate::typeop::type_op_info(code);
    match code {
        OpCode::CPUI_COPY => match ins.first() {
            Some(&input) => c_int_at(data, strat, input, def, depth - 1),
            None => Ok(None),
        },
        OpCode::CPUI_INT_ZEXT | OpCode::CPUI_INT_SEXT => {
            let Some(&input) = ins.first() else { return Ok(None) };
            let outtype = data.vn_type_def_facing(vn)?;
            let intype = data.vn_type_read_facing(input, def)?;
            let cast = if code == OpCode::CPUI_INT_ZEXT {
                strat.is_zext_cast(&outtype, &intype)
            } else {
                strat.is_sext_cast(&outtype, &intype)
            };
            if !cast {
                return Ok(None);
            }
            let hidden = {
                let ctx = FuncdataCastContext::new(data);
                let (d, r) = (ctx.op_ref(def), ctx.op_ref(reader));
                strat.is_extension_cast_implied(&ctx, d, Some(r))?
            };
            if hidden {
                c_int_at(data, strat, ins[0], def, depth - 1)
            } else {
                Ok(declared(&outtype))
            }
        }
        _ if d.is_bool_output() => Ok(Some((false, 4))),
        _ if info.inherits_sign() => {
            let n = if info.inherits_sign_first_param_only() { 1 } else { ins.len() };
            let mut acc: Option<CInt> = None;
            for &i in &ins[..n.min(ins.len())] {
                let Some((unsigned, width)) = c_int_at(data, strat, i, def, depth - 1)? else {
                    return Ok(None);
                };
                acc = Some(match acc {
                    None => (unsigned, width),
                    Some((au, aw)) if aw == width => (au || unsigned, width),
                    Some((au, aw)) if aw > width => (au, aw),
                    Some(_) => (unsigned, width),
                });
            }
            Ok(acc)
        }
        _ => Ok(declared(data.vn_type_def_facing(vn)?.as_ref())),
    }
}

/// The promoted C type of a value the text declares as `t`.
fn declared(t: &Datatype) -> Option<CInt> {
    if t.is_enum_type() {
        return None;
    }
    let size = t.get_size();
    match t.get_metatype() {
        type_metatype::TYPE_BOOL => Some((false, 4)),
        _ if size < 4 && size > 0 => {
            matches!(t.get_metatype(), type_metatype::TYPE_INT | type_metatype::TYPE_UINT | type_metatype::TYPE_UNKNOWN)
                .then_some((false, 4))
        }
        type_metatype::TYPE_INT if size == 4 || size == 8 => Some((false, size)),
        type_metatype::TYPE_UINT | type_metatype::TYPE_UNKNOWN if size == 4 || size == 8 => Some((true, size)),
        _ => None,
    }
}

/// The C type of the literal the constant `vn` prints as where `reader` reads
/// it: a `U` or `L` suffix says so, a character is an `int`, and a
/// hexadecimal magnitude takes the first of `int`, `unsigned int`, `long`,
/// `unsigned long` that holds it (a leading minus keeps that type).
fn literal(data: &Funcdata, vn: VarnodeId, reader: OpId) -> KunaResult<Option<CInt>> {
    let Some(v) = data.vbank().get(vn) else { return Ok(None) };
    let t = data.vn_type_read_facing(vn, reader)?;
    if t.is_enum_type() {
        return Ok(None);
    }
    let (size, off) = (v.get_size(), v.get_offset());
    let magnitude = match t.get_metatype() {
        type_metatype::TYPE_BOOL => return Ok(Some((false, 4))),
        _ if t.is_char_print() => return Ok(Some((false, 4))),
        type_metatype::TYPE_INT if signbit_negative(off, size) => kuna_base::address::uintb_negate(off, size),
        type_metatype::TYPE_INT | type_metatype::TYPE_UINT | type_metatype::TYPE_UNKNOWN => off,
        _ => return Ok(None),
    };
    let long = v.is_long_print() || magnitude > 0xffff_ffff;
    if v.is_unsigned_print() {
        return Ok(Some((true, if long { 8 } else { 4 })));
    }
    Ok(Some(match (long, magnitude) {
        (false, x) if x <= 0x7fff_ffff => (false, 4),
        (false, _) => (true, 4),
        (true, x) if x <= 0x7fff_ffff_ffff_ffff => (false, 8),
        (true, _) => (true, 8),
    }))
}
