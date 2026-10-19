//! A SUBPIECE into a float extracts storage bits rather than converting a number.

use crate::context::{OpId, VarnodeId};
use crate::dtype::{type_metatype, Datatype};
use crate::funcdata::Funcdata;
use kuna_base::error::KunaResult;
use kuna_num::opcodes::OpCode;
use std::rc::Rc;

pub(crate) struct Slice {
    pub input: VarnodeId,
    pub source_float: bool,
    pub source_word: Rc<Datatype>,
    pub target_word: Rc<Datatype>,
    pub shift: u64,
}

pub(crate) fn recognize(fd: &Funcdata, decl_high_type: bool, op: OpId) -> KunaResult<Option<Slice>> {
    let Some(operation) = fd.obank().get(op) else { return Ok(None) };
    if operation.code() != OpCode::CPUI_SUBPIECE {
        return Ok(None);
    }
    let Some(input) = operation.get_in(0) else { return Ok(None) };
    let Some(source) = fd.vbank().get(input) else { return Ok(None) };
    let Some(output) = operation.get_out() else { return Ok(None) };
    let Some(destination) = fd.vbank().get(output) else { return Ok(None) };
    let Some(offset_id) = operation.get_in(1) else { return Ok(None) };
    let Some(offset) = fd.vbank().get(offset_id) else { return Ok(None) };
    if source.get_size() != 8
        || destination.get_size() != 4
        || !offset.is_constant()
        || offset.get_offset() > 4
    {
        return Ok(None);
    }
    let target = match crate::kuna_stackviews::access_type(fd, output, op, -1)? {
        Some(target) => target,
        None => fd.vn_type_def_facing(output)?,
    };
    if target.get_size() != 4 || target.get_metatype() != type_metatype::TYPE_FLOAT {
        return Ok(None);
    }
    let from = match crate::kuna_stackviews::access_type(fd, input, op, operation.get_slot(input))?
        .or_else(|| crate::printc::declared_variable_type(fd, decl_high_type, input)) {
        Some(from) => from,
        None => fd.vn_type_read_facing(input, op)?,
    };
    let from = from.get_stripped().unwrap_or(from);
    if from.get_size() != 8
        || !matches!(
            from.get_metatype(),
            type_metatype::TYPE_INT
                | type_metatype::TYPE_UINT
                | type_metatype::TYPE_UNKNOWN
                | type_metatype::TYPE_FLOAT
        )
        || from.get_metatype() == type_metatype::TYPE_UNKNOWN
            && source.is_implied()
            && !crate::kuna_bitcast::reinterprets_to_float(fd, decl_high_type, input)
    {
        return Ok(None);
    }
    let Some(types) = fd.get_arch().types() else { return Ok(None) };
    if types.get_size_of_int() != 4
        || types.get_size_of_float() != 4
        || types.get_size_of_long_long() != 8
        || types.get_size_of_double() != 8
    {
        return Ok(None);
    }
    Ok(Some(Slice {
        input,
        source_float: from.get_metatype() == type_metatype::TYPE_FLOAT,
        source_word: types.get_base(8, type_metatype::TYPE_UINT)?,
        target_word: types.get_base(4, type_metatype::TYPE_UINT)?,
        shift: offset.get_offset() * 8,
    }))
}
