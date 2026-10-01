//! Semantic target queries over the optimized IR used by call rendering tests.

#![allow(dead_code)] // Each integration test observes a different target shape.

use std::collections::HashSet;
use kuna_decomp::context::VarnodeId;
use kuna_decomp::funcdata::Funcdata;
use kuna_num::opcodes::OpCode;

pub fn without_value_casts(fd: &Funcdata, mut value: VarnodeId) -> VarnodeId {
    let mut visited = HashSet::new();
    while visited.insert(value) {
        let Some(op) = fd.vbank().get(value).unwrap().get_def()
            .and_then(|op| fd.obank().get(op)) else { break };
        if !matches!(op.code(), OpCode::CPUI_CAST | OpCode::CPUI_COPY) { break; }
        value = op.get_in(0).unwrap();
    }
    value
}

pub fn constant(fd: &Funcdata, value: VarnodeId) -> Option<u64> {
    let value = fd.vbank().get(without_value_casts(fd, value)).unwrap();
    value.is_constant().then(|| value.get_offset())
}

fn address_contains(fd: &Funcdata, value: VarnodeId, address: u64) -> bool {
    let mut pending = vec![value];
    let mut visited = HashSet::new();
    while let Some(value) = pending.pop() {
        if !visited.insert(value) { continue; }
        let value = fd.vbank().get(value).unwrap();
        if value.is_constant() && value.get_offset() == address { return true; }
        let Some(op) = value.get_def().and_then(|op| fd.obank().get(op)) else { continue };
        if matches!(op.code(), OpCode::CPUI_CAST | OpCode::CPUI_COPY
            | OpCode::CPUI_INT_ADD | OpCode::CPUI_PTRADD | OpCode::CPUI_PTRSUB) {
            pending.extend((0..op.num_input()).filter_map(|slot| op.get_in(slot)));
        }
    }
    false
}

/// A direct memory Varnode is a promoted load. Otherwise require a real LOAD
/// whose address expression includes the table base, not merely a matching
/// literal elsewhere in the function.
pub fn target_reads(fd: &Funcdata, target: VarnodeId, address: u64) -> bool {
    let target = fd.vbank().get(without_value_casts(fd, target)).unwrap();
    if !target.is_constant()
        && target.get_addr().get_space().is_some_and(|space| space.get_name() == "ram")
        && target.get_offset() == address
    {
        return true;
    }
    let Some(op) = target.get_def().and_then(|op| fd.obank().get(op)) else { return false };
    op.code() == OpCode::CPUI_LOAD
        && op.get_in(1).is_some_and(|pointer| address_contains(fd, pointer, address))
}
