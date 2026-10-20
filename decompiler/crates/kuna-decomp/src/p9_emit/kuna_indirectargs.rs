//! Recover source-level arguments and results lowered indirectly by the ABI.

use crate::dtype::Datatype;
use crate::fspec::{FuncProto, ProtoParameter};
use crate::funcdata::Funcdata;
use std::rc::Rc;

pub(crate) struct HiddenResult {
    pub value_type: Rc<Datatype>,
    pub pointer_type: Rc<Datatype>,
    pub slot: i32,
}

/// A source result and the one extra occurrence introduced by ABI allocation.
pub(crate) fn hidden_result(proto: &FuncProto) -> Option<HiddenResult> {
    if !proto.has_store() || proto.has_custom_storage() || proto.get_inject_id() >= 0
        || proto.decoded_inject_name().is_some()
        || !proto.has_model() || proto.get_inject_upon_entry() >= 0
        || proto.get_inject_upon_return() >= 0 || !proto.get_output().is_indirect_storage()
    {
        return None;
    }
    let logical = proto.logical_pieces()?;
    if logical.output_storage.is_some() || !logical.input_storage.is_empty() {
        return None;
    }
    let value_type = Datatype::completed_record(logical.outtype.as_ref()?);
    if !matches!(value_type.get_metatype(),
        crate::dtype::type_metatype::TYPE_STRUCT | crate::dtype::type_metatype::TYPE_UNION)
        || value_type.get_size() <= 0
    {
        return None;
    }
    let mut hidden = (0..proto.num_params())
        .filter(|&slot| proto.get_param(slot).is_some_and(|p| p.is_hidden_return()));
    let slot = hidden.next()?;
    if hidden.next().is_some() { return None; }
    let param = proto.get_param(slot)?;
    let pointer_type = param.get_type()?.clone();
    let pointee = Datatype::completed_record(&pointer_type.get_ptr_to()?);
    if param.get_address().is_invalid() || !Rc::ptr_eq(&pointee, &value_type) {
        return None;
    }
    let output = proto.get_output_type()?;
    if output.get_metatype() != crate::dtype::type_metatype::TYPE_VOID {
        let returned = Datatype::completed_record(&output.get_ptr_to()?);
        if output.get_size() != pointer_type.get_size() || !Rc::ptr_eq(&returned, &value_type) {
            return None;
        }
    }
    Some(HiddenResult { value_type, pointer_type, slot })
}

pub(crate) fn callable_logical(proto: &FuncProto, enabled: bool, results: bool) -> Option<&crate::fspec::PrototypePieces> {
    let logical = proto.logical_pieces()?;
    // The off policy exposes allocated ABI inputs, not pending logical slots.
    let physical_indirect = !enabled && proto.has_store()
        && (0..proto.num_params()).any(|slot| proto.get_param(slot)
            .is_some_and(|param| param.is_indirect_storage()))
        && (0..proto.num_params()).all(|slot| proto.get_param(slot)
            .is_some_and(|param| !param.get_address().is_invalid()))
        && proto.get_output_type().is_some_and(|ty|
            ty.get_metatype() == crate::dtype::type_metatype::TYPE_VOID
                || !proto.get_output().get_address().is_invalid());
    if physical_indirect { return None; }
    let hidden = proto.has_store() && (0..proto.num_params())
        .any(|slot| proto.get_param(slot).is_some_and(|p| p.is_hidden_return()));
    if hidden && (!results || hidden_result(proto).is_none()) { return None; }
    Some(logical)
}

pub(crate) fn hidden_input_highs(data: &Funcdata, result: &HiddenResult) -> Vec<crate::context::HighVariableId> {
    let param = data.get_func_proto().get_param(result.slot).expect("hidden result parameter");
    let high = data.vbank().find_input(param.get_size(), &param.get_address())
        .and_then(|vn| data.vbank().get(vn)?.get_high());
    let symbol = high.and_then(|id| data.high_bank().get(id)?.kuna_link_symbol())
        .or_else(|| data.get_scope_local()?.parameter_symbol(result.slot));
    data.high_bank().iter().filter_map(|(id, variable)| {
        (Some(id) == high || symbol.is_some_and(|symbol| variable.kuna_link_symbol() == Some(symbol)))
            .then_some(id)
    }).collect()
}

pub(crate) fn indirect_pointee(
    proto: &FuncProto,
    param: &dyn ProtoParameter,
) -> Option<Rc<Datatype>> {
    if !proto.has_store()
        || !proto.is_input_locked()
        || !param.is_indirect_storage()
        || param.is_hidden_return()
    {
        return None;
    }
    let value = param.get_type()?.get_ptr_to()?;
    (value.get_metatype() != crate::dtype::type_metatype::TYPE_ARRAY).then_some(value)
}

pub(crate) fn is_indirect_value(proto: Option<&FuncProto>, slot: i32, size: i32) -> bool {
    let Some(proto) = proto.filter(|proto| proto.has_store()) else {
        return false;
    };
    if slot <= 0 {
        return false;
    }
    proto
        .get_param(slot - 1)
        .is_some_and(|param| param.get_size() == size && indirect_pointee(proto, param).is_some())
}

pub(crate) fn source_type(proto: &FuncProto, param: &dyn ProtoParameter) -> Option<Rc<Datatype>> {
    indirect_pointee(proto, param).or_else(|| param.get_type().cloned())
}

pub(crate) fn is_indirect_input(data: &Funcdata, vn: crate::context::VarnodeId) -> bool {
    let Some(value) = data.vbank().get(vn).filter(|value| value.is_input()) else {
        return false;
    };
    let proto = data.get_func_proto();
    if !proto.has_store() {
        return false;
    }
    (0..proto.num_params())
        .filter_map(|slot| proto.get_param(slot))
        .any(|param| {
            indirect_pointee(proto, param).is_some()
                && param.get_address() == *value.get_addr()
                && param.get_size() == value.get_size()
        })
}

pub(crate) struct MutableInput {
    pub highs: Vec<crate::context::HighVariableId>,
    pub slot: i32,
    pub pointer_type: Rc<Datatype>,
}

pub(crate) fn mutable_inputs(data: &Funcdata) -> Vec<MutableInput> {
    let proto = data.get_func_proto();
    if !proto.has_store() {
        return Vec::new();
    }
    let mut inputs = Vec::new();
    for slot in 0..proto.num_params() {
        let Some(param) = proto.get_param(slot) else {
            continue;
        };
        if indirect_pointee(proto, param).is_none() {
            continue;
        }
        let Some(ty) = param.get_type() else { continue };
        let high = data
            .vbank()
            .find_input(param.get_size(), &param.get_address())
            .and_then(|vn| data.vbank().get(vn)?.get_high());
        let symbol = high
            .and_then(|high| data.high_bank().get(high)?.kuna_link_symbol())
            .or_else(|| {
                let scope = data.get_scope_local()?;
                scope
                    .query_container_for_link_matching(
                        &param.get_address(),
                        param.get_size(),
                        &kuna_base::address::Address::new_invalid(),
                        |symbol| {
                            symbol.get_category()
                                == crate::database::symbol_category::FUNCTION_PARAMETER
                                && i32::from(symbol.get_category_index()) == slot
                        },
                    )
                    .map(|entry| entry.symbol)
            });
        let mut highs = Vec::new();
        if let Some(high) = high {
            highs.push(high);
        }
        if let Some(symbol) = symbol {
            highs.extend(data.high_bank().iter().filter_map(|(id, variable)| {
                (Some(id) != high && variable.kuna_link_symbol() == Some(symbol)).then_some(id)
            }));
        }
        let mutable = highs.len() > 1
            || highs.iter().any(|&high| {
                data.high_bank().get(high).is_some_and(|variable| {
                    (0..variable.num_instances()).any(|index| {
                        data.vbank()
                            .get(variable.get_instance(index))
                            .is_some_and(|value| value.is_written())
                    })
                })
            });
        if mutable {
            inputs.push(MutableInput {
                highs,
                slot,
                pointer_type: Rc::clone(ty),
            });
        }
    }
    inputs
}
