//! Conditional activation unwinding for an explicit CALL_RETURN flow override.

use std::collections::BTreeMap;
use std::rc::Rc;

use kuna_base::address::Address;
use kuna_base::error::{KunaError, KunaResult};
use kuna_base::types::int4;
use kuna_num::opcodes::OpCode;

use crate::context::{OpId, VarnodeId};
use crate::funcdata::Funcdata;
use crate::overrides::flow_type;
use super::kuna_physicalinputs::{FlowReturnAssumption, FlowReturnOrigin};

fn stack_contract(fd: &Funcdata) -> Option<(Address, int4, i64)> {
    let proto = fd.get_func_proto();
    if !proto.has_model() || proto.get_extra_pop() == crate::fspec::EXTRAPOP_UNKNOWN { return None; }
    let stack = proto.get_spacebase()?;
    if stack.num_spacebase() != 1 { return None; }
    let storage = stack.get_spacebase(0).ok()?;
    Some((Address::new(storage.space?, storage.offset), storage.size as int4, i64::from(proto.get_extra_pop())))
}

fn normal_returns(fd: &Funcdata) -> impl Iterator<Item = OpId> + '_ {
    fd.obank().iter_alive().filter(|id| fd.obank().get(*id)
        .is_some_and(|op| op.code() == OpCode::CPUI_RETURN && op.get_halt_type() == 0))
}

fn origin_matches(fd: &Funcdata, proof: &FlowReturnAssumption) -> bool {
    fd.flow_return_origins().contains(&(proof.return_op, proof.call, proof.origin))
        && (proof.origin == FlowReturnOrigin::HostInstruction
            || fd.get_override().get_flow_override(&proof.site) == flow_type::CALL_RETURN)
        && fd.obank().get(proof.call).is_some_and(|call| !call.is_dead()
            && matches!(call.code(), OpCode::CPUI_CALL | OpCode::CPUI_CALLIND)
            && call.get_addr() == &proof.site)
        && fd.obank().get(proof.return_op).is_some_and(|ret| !ret.is_dead()
            && ret.code() == OpCode::CPUI_RETURN && ret.get_halt_type() == 0
            && ret.get_addr() == &proof.site
            && ret.get_in(0).and_then(|id| fd.vbank().get(id))
                .is_some_and(|target| target.is_constant() && target.get_offset() == 0))
}

pub(super) fn raw_contracts(fd: &Funcdata) -> BTreeMap<OpId, FlowReturnAssumption> {
    let mut result = BTreeMap::new();
    if fd.flow_return_origins().is_empty() { return result; }
    let Some(stack) = stack_contract(fd) else { return result };
    let returns: Rc<[OpId]> = normal_returns(fd).collect();
    for &(return_op, call, origin) in fd.flow_return_origins() {
        let Some(operation) = fd.obank().get(call) else { continue };
        let proof = FlowReturnAssumption {
            site: operation.get_addr().clone(), call, return_op, origin,
            source_model: fd.get_func_proto().model().clone(), stack: stack.clone(),
            observed_delta: None, normal_returns: returns.clone(),
        };
        if origin_matches(fd, &proof) { result.insert(return_op, proof); }
    }
    result
}

fn returned_call_value(fd: &Funcdata, mut value: VarnodeId, call: OpId) -> bool {
    for _ in 0..64 {
        let Some(node) = fd.vbank().get(value) else { return false };
        let Some(definition) = node.get_def() else { return false };
        if definition == call { return true; }
        let Some(op) = fd.obank().get(definition).filter(|op| !op.is_dead()) else { return false };
        if !matches!(op.code(), OpCode::CPUI_COPY | OpCode::CPUI_CAST | OpCode::CPUI_INT_SEXT
            | OpCode::CPUI_INT_ZEXT | OpCode::CPUI_SUBPIECE) { return false; }
        if op.code() == OpCode::CPUI_SUBPIECE && !op.get_in(1).and_then(|id| fd.vbank().get(id))
            .is_some_and(|cut| cut.is_constant() && cut.get_offset() == 0) { return false; }
        let Some(input) = op.get_in(0) else { return false };
        value = input;
    }
    false
}

pub(super) fn validate(fd: &Funcdata, proof: &FlowReturnAssumption) -> KunaResult<()> {
    let proto = fd.get_func_proto();
    if proof.observed_delta.is_none() || !origin_matches(fd, proof) || !proto.has_model()
        || !Rc::ptr_eq(proto.model(), &proof.source_model)
        || stack_contract(fd).as_ref() != Some(&proof.stack)
        || !normal_returns(fd).eq(proof.normal_returns.iter().copied())
        || super::kuna_callabletransport::raw_boundary(fd, proof.call)? {
        return Err(KunaError::lowlevel("Conditional flow return lost its source override contract"));
    }
    let ret = fd.obank().get(proof.return_op).expect("validated flow return");
    if proto.has_store() && proto.get_output().get_size() > 0 {
        if ret.num_input() != 2 || !ret.get_in(1).is_some_and(|value| returned_call_value(fd, value, proof.call)) {
            return Err(KunaError::lowlevel("Conditional flow return does not return the overridden call value"));
        }
    } else if ret.num_input() != 1 {
        return Err(KunaError::lowlevel("Conditional void flow return gained a value"));
    }
    Ok(())
}
