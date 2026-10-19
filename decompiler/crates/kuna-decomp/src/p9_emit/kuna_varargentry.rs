//! Recover one consumed first variadic value without creating a source formal.

use crate::architecture::Architecture;
use crate::context::{HighVariableId, VarnodeId};
use crate::dtype::type_metatype::TYPE_INT;
use crate::fspec::{parameter_pieces_flags, PrototypePieces};
use crate::funcdata::Funcdata;
use kuna_base::error::{KunaError, KunaResult};
use kuna_num::opcodes::OpCode;

#[derive(Clone, Copy)]
pub(super) struct EntryValue {
    pub high: HighVariableId,
    pub input: VarnodeId,
    pub last_fixed: i32,
    pub block_index: Option<i32>,
}

/// The model proves the position; signed-int recovery supplies the presentation,
/// not an authored optional-argument type or a proof about arbitrary callers.
pub(super) fn entry_value(data: &Funcdata, arch: &Architecture) -> KunaResult<Option<EntryValue>> {
    let proto = data.get_func_proto();
    if !arch.vararg_entry || !proto.has_store() || !proto.has_model()
        || !proto.is_dotdotdot() || !proto.is_model_locked() || proto.has_custom_storage()
        || proto.is_model_unknown() || proto.model().is_merged() || proto.model().input_opt().is_none()
        || proto.get_inject_id() >= 0 || proto.decoded_inject_name().is_some()
        || proto.get_inject_upon_entry() >= 0 || proto.get_inject_upon_return() >= 0
        || proto.num_params() == 0 || data.bblocks_get_size() == 0
    {
        return Ok(None);
    }
    let int_size = arch.types().get_size_of_int();
    let mut declaration = PrototypePieces::default();
    proto.get_pieces(&mut declaration);
    if declaration.first_var_arg_slot != proto.num_params()
        || declaration.intypes.len() != proto.num_params() as usize
    {
        return Ok(None);
    }
    for slot in 0..proto.num_params() {
        let Some(param) = proto.get_param(slot) else { return Ok(None) };
        if !param.is_type_locked() || param.is_indirect_storage() || param.is_hidden_return()
            || param.is_this_pointer()
        {
            return Ok(None);
        }
    }
    let last_fixed = proto.num_params() - 1;
    let last_type = &declaration.intypes[last_fixed as usize];
    if last_type.get_metatype() != TYPE_INT || last_type.get_size() != int_size {
        return Ok(None);
    }
    declaration.intypes.push(arch.types().get_base(int_size, TYPE_INT)?);
    let mut storage = Vec::with_capacity(declaration.intypes.len() + 1);
    match proto.model().assign_parameter_storage(
        &declaration, &mut storage, false, &*arch.types(), arch.manage(),
    ) {
        Ok(()) => {}
        Err(KunaError::ParamUnassigned { .. }) => return Ok(None),
        Err(error) => return Err(error),
    }
    if storage.len() != declaration.intypes.len() + 1 {
        return Ok(None);
    }
    let roles = parameter_pieces_flags::INDIRECTSTORAGE | parameter_pieces_flags::HIDDENRETPARM
        | parameter_pieces_flags::ISTHIS;
    for slot in 0..proto.num_params() {
        let param = proto.get_param(slot).unwrap();
        let piece = &storage[slot as usize + 1];
        if piece.flags & roles != 0 || piece.addr != param.get_address()
            || piece.type_.as_ref().map(|ty| ty.get_size()) != Some(param.get_size())
        {
            return Ok(None);
        }
    }
    let tail = storage.last().unwrap();
    if tail.flags & roles != 0 || tail.addr.is_invalid()
        || tail.type_.as_ref().is_none_or(|ty| ty.get_metatype() != TYPE_INT || ty.get_size() != int_size)
    {
        return Ok(None);
    }
    let Some(input) = data.vbank().find_input(int_size, &tail.addr) else { return Ok(None) };
    let value = data.vbank().get(input).unwrap();
    if value.get_type().get_metatype() != TYPE_INT || value.get_type().get_size() != int_size
        || value.is_unaffected() || value.is_spacebase() || value.is_persist()
        || !value.descend_iter().any(|op| data.obank().get(op).is_some_and(|op| !op.is_dead()))
    {
        return Ok(None);
    }
    let Some(high) = value.get_high() else { return Ok(None) };
    let Some(variable) = data.high_bank().get(high) else { return Ok(None) };
    let Some(name) = variable.kuna_name().filter(|name| !name.is_empty()) else { return Ok(None) };
    if variable.kuna_global()
        || variable.kuna_symbol_offset() > 0
        || variable.kuna_symbol_type().is_some_and(|ty| ty.get_metatype() != TYPE_INT || ty.get_size() != int_size)
        || data.high_bank().iter().any(|(other, variable)|
            other != high && variable.kuna_name() == Some(name))
        || variable.kuna_link_symbol().is_some_and(|symbol| data.get_scope_local().is_some_and(|scope|
            scope.symbol_category(symbol) == crate::database::symbol_category::FUNCTION_PARAMETER))
    {
        return Ok(None);
    }
    for vn in data.vbank().iter_loc() {
        let value = data.vbank().get(vn).unwrap();
        if !value.is_input() || value.is_spacebase() || value.is_unaffected()
            || !value.descend_iter().any(|op| data.obank().get(op).is_some_and(|op| !op.is_dead()))
        {
            continue;
        }
        let fixed = (0..proto.num_params()).any(|slot| {
            let param = proto.get_param(slot).unwrap();
            param.get_address() == *value.get_addr() && param.get_size() == value.get_size()
        });
        if fixed {
            if value.get_high() == Some(high) { return Ok(None); }
        } else if vn != input && (value.get_high() == Some(high)
            || proto.possible_input_param(value.get_addr(), value.get_size()))
        {
            return Ok(None);
        }
    }
    let entry = data.bblocks_get_block(0);
    if data.bblocks_block_start(entry) != *data.get_address() { return Ok(None); }
    let mut next = data.bb_op_head(entry);
    while let Some(op) = next {
        let operation = data.obank().get(op).unwrap();
        if !operation.is_dead() {
            if operation.code() == OpCode::CPUI_RETURN
                && (0..operation.num_input()).any(|slot| operation.get_in(slot) == Some(input))
            {
                return Ok(Some(EntryValue { high, input, last_fixed, block_index: None }));
            }
            if matches!(operation.code(), OpCode::CPUI_CALL | OpCode::CPUI_CALLIND
                | OpCode::CPUI_CALLOTHER | OpCode::CPUI_BRANCH | OpCode::CPUI_CBRANCH
                | OpCode::CPUI_BRANCHIND | OpCode::CPUI_RETURN)
            {
                break;
            }
            if (0..operation.num_input()).any(|slot| operation.get_in(slot) == Some(input)) {
                return Ok(Some(EntryValue { high, input, last_fixed, block_index: None }));
            }
        }
        next = data.bb_op_next(op);
    }
    Ok(conditional_read_block(data, input).map(|block_index|
        EntryValue { high, input, last_fixed, block_index: Some(block_index) }))
}

/// Capture inside a uniquely emitted terminal consuming leaf, after a pure
/// prefix, so non-consuming paths never fetch an absent optional argument.
fn conditional_read_block(data: &Funcdata, input: VarnodeId) -> Option<i32> {
    let mut readers = data.vbank().get(input)?.descend_iter()
        .filter_map(|op| data.obank().get(op)).filter(|op| !op.is_dead());
    let block = readers.next()?.get_parent()?;
    if block == data.bblocks_get_block(0)
        || readers.any(|op| op.get_parent() != Some(block))
        || data.bblocks_ref().block(block).size_out() != 0
        || data.obank().get(data.bb_op_tail(block)?)?.code() != OpCode::CPUI_RETURN
        || data.obank().get(data.bb_op_tail(block)?)?.get_halt_type() != 0
    {
        return None;
    }
    let graph = data.sblocks_ref();
    fn copies(graph: &crate::block::BlockGraph, node: crate::context::BlockId,
              basic: crate::context::BlockId) -> usize {
        let block = graph.block(node);
        usize::from(block.get_copy() == Some(basic))
            + block.get_list().iter().map(|child| copies(graph, *child, basic)).sum::<usize>()
    }
    if copies(graph, graph.root?, block) != 1 { return None; }
    let mut read = false;
    let mut next = data.bb_op_head(block);
    while let Some(op) = next {
        let operation = data.obank().get(op)?;
        next = data.bb_op_next(op);
        if operation.is_dead() { continue; }
        if operation.code() == OpCode::CPUI_MULTIEQUAL { return None; }
        if !read && matches!(operation.code(), OpCode::CPUI_LOAD | OpCode::CPUI_STORE
            | OpCode::CPUI_CALL | OpCode::CPUI_CALLIND | OpCode::CPUI_CALLOTHER
            | OpCode::CPUI_NEW | OpCode::CPUI_BRANCH | OpCode::CPUI_CBRANCH | OpCode::CPUI_BRANCHIND
            | OpCode::CPUI_INT_DIV | OpCode::CPUI_INT_SDIV | OpCode::CPUI_INT_REM | OpCode::CPUI_INT_SREM)
        {
            return None;
        }
        read |= (0..operation.num_input()).any(|slot| operation.get_in(slot) == Some(input));
    }
    read.then(|| data.bblocks_ref().block(block).get_index())
}
