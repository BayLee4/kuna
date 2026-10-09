//! Semantic target queries over the optimized IR used by call rendering tests.

use kuna_decomp::context::VarnodeId;
use kuna_decomp::funcdata::Funcdata;
use kuna_num::opcodes::OpCode;
use std::collections::HashSet;

pub fn without_value_casts(fd: &Funcdata, mut value: VarnodeId) -> VarnodeId {
    let mut visited = HashSet::new();
    while visited.insert(value) {
        let Some(op) = fd
            .vbank()
            .get(value)
            .unwrap()
            .get_def()
            .and_then(|op| fd.obank().get(op))
        else {
            break;
        };
        if !matches!(op.code(), OpCode::CPUI_CAST | OpCode::CPUI_COPY) {
            break;
        }
        let input = op.get_in(0).unwrap();
        if fd.vbank().get(input).unwrap().get_size() != fd.vbank().get(value).unwrap().get_size() {
            break;
        }
        value = input;
    }
    value
}


