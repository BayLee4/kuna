//! Execution-only callable views and stable, target-owned entry adapters.
//!
//! A declaration's scalar width is not an instruction-defined extension. The
//! transport view carries the containing register; the final target adapter
//! projects only the bytes demanded by the target's analyzed execution entry.
use std::collections::{BTreeMap, BTreeSet};
use std::rc::Rc;

use kuna_base::address::Address;
use kuna_base::error::{KunaError, KunaResult};
use kuna_base::space::AddrSpaceManager;
use kuna_base::types::int4;
use kuna_num::opcodes::OpCode;

use crate::architecture::Architecture;
use crate::context::{OpId, VarnodeId};
use crate::dtype::{type_metatype, TypeFactory, TypeRoot};
use crate::fspec::{FuncProto, LogicalCallable, ProtoParameter};
use crate::funcdata::Funcdata;
use super::kuna_physicalinputs::{apply_requirements, apply_ssa_requirements, close_finite_variadic_inputs, EntryRequirements};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CallableDefinition {
    Wrapper(String),
    /// The actual validated target body supplies this unchanged execution ABI.
    ExistingTarget { space: int4, byte_address: u64 },
    /// A non-emitting stronger body receipt, grounded in this concrete family.
    BodyProof { provider: String },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CallableArtifact {
    pub key: String,
    pub declaration: String,
    pub definition: Option<CallableDefinition>,
    /// A producer requests a body; target definitions are only candidates.
    /// A nonrequired record without a definition is an authenticated native declaration.
    pub required: bool,
    /// This owner requests a mapped-body proof rather than a raw-complete target.
    pub deferred: bool,
}

/// One actual body owner in a publication attempt. A missing space is allowed
/// only for the console's canonical single-code-space byte inventory.
pub struct CallableBody<'a> {
    pub space: Option<int4>,
    pub byte_address: u64,
    pub artifacts: &'a [CallableArtifact],
    pub failed: bool,
    pub export_error: Option<&'a str>,
}

pub struct CallablePublication<'a> {
    pub declaration: &'a str,
    pub definition: Option<(&'a CallableDefinition, usize)>,
    pub required: bool,
}

/// Join exact family identities without asserting closure. Streamed headers may
/// use this while a requested target has not arrived; final publication must call
/// validate_callable_publication with actual successful body-write receipts.
pub fn collect_callable_publication<'a>(bodies: &[CallableBody<'a>])
    -> Result<BTreeMap<&'a str, CallablePublication<'a>>, String>
{
    let mut joined: BTreeMap<&str, CallablePublication<'_>> = BTreeMap::new();
    for (owner, body) in bodies.iter().enumerate() {
        if let Some(error) = body.export_error { return Err(error.into()); }
        for artifact in body.artifacts {
            if artifact.deferred && !artifact.required {
                return Err(format!("callable adapter {} has a deferred edge without a request", artifact.key));
            }
            if let Some(definition) = &artifact.definition {
                if body.failed {
                    return Err(format!("callable adapter {} has a failed target function", artifact.key));
                }
                let entry = artifact.key.strip_prefix("kuna_entry_")
                    .and_then(|key| key.split_once('_'))
                    .and_then(|(space, rest)| rest.split_once('_')
                        .and_then(|(address, _)| Some((space.parse::<int4>().ok()?, address.parse::<u64>().ok()?))));
                let Some((space, address)) = entry else {
                    return Err(format!("callable adapter {} has an invalid target identity", artifact.key));
                };
                if address != body.byte_address || body.space.is_some_and(|expected| expected != space)
                    || matches!(definition, CallableDefinition::ExistingTarget { space: expected, byte_address }
                        if *expected != space || *byte_address != address)
                {
                    return Err(format!("callable adapter {} has an inconsistent target owner", artifact.key));
                }
            }
            match joined.entry(&artifact.key) {
                std::collections::btree_map::Entry::Vacant(entry) => {
                    entry.insert(CallablePublication {
                        declaration: &artifact.declaration,
                        definition: artifact.definition.as_ref().map(|definition| (definition, owner)),
                        required: artifact.required,
                    });
                }
                std::collections::btree_map::Entry::Occupied(mut entry) => {
                    let previous = entry.get_mut();
                    if previous.declaration != artifact.declaration {
                        return Err(format!("conflicting callable adapter declaration: {}", artifact.key));
                    }
                    if let Some(definition) = artifact.definition.as_ref() {
                        if previous.definition.is_some_and(|(old, previous_owner)| old != definition || previous_owner != owner) {
                            return Err(format!("conflicting callable adapter definition: {}", artifact.key));
                        }
                        previous.definition = Some((definition, owner));
                    }
                    previous.required |= artifact.required;
                }
            }
        }
    }
    // Qualified receipts never stand in for C definitions. Their referenced
    // concrete family belongs to the same actual validated body and is retained
    // even when the stronger receipt is the only incoming request.
    let mut retain = Vec::new();
    for (key, artifact) in &joined {
        let Some((CallableDefinition::BodyProof { provider }, owner)) = artifact.definition else { continue; };
        let suffix = key.strip_prefix(provider.as_str()).and_then(|suffix| suffix.strip_prefix("_internal_"));
        let valid = suffix.is_some_and(|suffix| {
            let mut fields = suffix.split('_');
            let (Some(space), Some(byte), Some(size)) = (fields.next(), fields.next(), fields.next()) else { return false; };
            if fields.next().is_some() || [space, byte, size].iter().any(|field| field.is_empty()
                || field.len() > 1 && field.starts_with('0') || !field.bytes().all(|byte| byte.is_ascii_digit())) { return false; }
            matches!((space.parse::<int4>(), byte.parse::<u64>(), size.parse::<int4>()),
                (Ok(space), Ok(byte), Ok(size)) if space >= 0 && size > 0 && byte.checked_add(size as u64).is_some())
        });
        let concrete = joined.get(provider.as_str());
        if !valid || provider.contains("_internal_") || concrete.is_none_or(|concrete|
            concrete.declaration != artifact.declaration || concrete.definition.is_none_or(|(definition, actual)|
                actual != owner || matches!(definition, CallableDefinition::BodyProof { .. }))) {
            return Err(format!("callable body proof {key} has no exact concrete provider"));
        }
        if artifact.required { retain.push(provider.as_str()); }
    }
    for provider in retain {
        joined.get_mut(provider).expect("validated body proof provider").required = true;
    }
    Ok(joined)
}

/// Discharge actual body dependencies, retaining each requesting owner's edge
/// kind. Only cycles containing deferred proof edges are ungrounded: ordinary
/// raw-complete recursion remains valid. Iterative Kosaraju avoids host stack
/// depth limits and repeated per-deferred-edge graph traversals.
pub fn validate_callable_publication(bodies: &[CallableBody<'_>],
    joined: &BTreeMap<&str, CallablePublication<'_>>, body_written: impl Fn(usize) -> bool)
    -> Result<(), String>
{
    let has_deferred = bodies.iter().any(|body| body.artifacts.iter().any(|artifact| artifact.deferred));
    let mut edges = if has_deferred { vec![Vec::new(); bodies.len()] } else { Vec::new() };
    let mut reverse = if has_deferred { vec![Vec::new(); bodies.len()] } else { Vec::new() };
    let mut deferred = Vec::new();
    for (owner, body) in bodies.iter().enumerate() {
        for artifact in body.artifacts.iter().filter(|artifact| artifact.required) {
            let (definition, target) = joined.get(artifact.key.as_str()).and_then(|artifact| artifact.definition)
                .ok_or_else(|| format!("callable adapter {} requires its target function in this export", artifact.key))?;
            if matches!(definition, CallableDefinition::BodyProof { .. }) && !artifact.deferred {
                return Err(format!("callable body proof {} lacks its deferred dependency", artifact.key));
            }
            if !body_written(target) {
                return Err(format!("callable adapter {} requires its target body in this export", artifact.key));
            }
            if has_deferred {
                edges[owner].push(target);
                reverse[target].push(owner);
            }
            if artifact.deferred { deferred.push((owner, target, artifact.key.as_str())); }
        }
    }
    if deferred.is_empty() { return Ok(()); }
    let mut seen = vec![false; bodies.len()];
    let mut order = Vec::with_capacity(bodies.len());
    let mut work = Vec::new();
    for start in 0..bodies.len() {
        if seen[start] { continue; }
        seen[start] = true;
        work.push((start, 0));
        while let Some((node, next)) = work.last_mut() {
            if *next == edges[*node].len() {
                order.push(*node);
                work.pop();
                continue;
            }
            let target = edges[*node][*next];
            *next += 1;
            if !seen[target] {
                seen[target] = true;
                work.push((target, 0));
            }
        }
    }
    let mut components = vec![usize::MAX; bodies.len()];
    let mut members = Vec::new();
    for start in order.into_iter().rev() {
        if components[start] != usize::MAX { continue; }
        components[start] = start;
        members.push(start);
        while let Some(node) = members.pop() {
            for &target in &reverse[node] {
                if components[target] == usize::MAX {
                    components[target] = start;
                    members.push(target);
                }
            }
        }
    }
    if let Some((_, _, key)) = deferred.iter().find(|(owner, target, _)| components[*owner] == components[*target]) {
        return Err(format!("callable adapter {key} participates in an ungrounded deferred body cycle"));
    }
    Ok(())
}


fn scalar(ty: &TypeRoot) -> bool {
    matches!(ty.get_metatype(), type_metatype::TYPE_INT | type_metatype::TYPE_UINT
        | type_metatype::TYPE_ENUM_INT | type_metatype::TYPE_ENUM_UINT | type_metatype::TYPE_BOOL)
}

fn adapter_supported(proto: &FuncProto) -> bool {
    proto.has_store() && proto.has_model() && !proto.is_dotdotdot() && !proto.get_output().is_indirect_storage()
        && (0..proto.num_params()).all(|slot| proto.get_param(slot).is_some_and(|p|
            !p.is_hidden_return() && !p.is_indirect_storage()))
}

fn has_callable_projection(proto: &FuncProto) -> bool {
    proto.source_output().get_type() != proto.get_output_type()
        || proto.input_projections().iter().any(|projection|
            projection.source.get_type().and_then(TypeRoot::get_ptr_to)
                .is_some_and(|code| code.get_metatype() == type_metatype::TYPE_CODE))
}

/// Normalize callable-valued parameters/results without rewriting nominal types.
pub fn normalize_type(ty: &TypeRoot, manager: &AddrSpaceManager, types: &dyn TypeFactory)
    -> KunaResult<TypeRoot>
{
    normalize_type_depth(ty, manager, types, 0)
}

fn normalize_type_depth(ty: &TypeRoot, manager: &AddrSpaceManager, types: &dyn TypeFactory,
    depth: usize) -> KunaResult<TypeRoot>
{
    if depth >= 32 { return Err(KunaError::lowlevel("Recursive callable execution signature")); }
    let Some(code) = ty.get_ptr_to() else { return Ok(ty.clone()) };
    if code.get_metatype() != type_metatype::TYPE_CODE { return Ok(ty.clone()); }
    {
        let view = code.read();
        let id = view.resolve_alias(code.id())?;
        if view.get_code_prototype(id)?.is_none() { return Ok(ty.clone()); }
    }
    let Some(abi) = crate::fspec::materialize_callable(types, &code)? else { return Ok(ty.clone()) };
    if !adapter_supported(abi.prototype()) { return Ok(ty.clone()); }
    let mut proto = abi.prototype().source_prototype();
    let changed = normalize_values(&mut proto, manager, types, depth + 1)?
        | widen_scalar_inputs(&mut proto, manager, types)?;
    if !changed { return Ok(ty.clone()); }
    let execution = callable_type(&proto, types)?;
    if let Some(space) = ty.get_pointer_space() {
        types.get_type_pointer_with_space(ty.get_size(), execution, ty.get_word_size().unwrap_or(1), space, "")
    } else {
        types.get_type_pointer(ty.get_size(), execution, ty.get_word_size().unwrap_or(1))
    }
}

fn normalize_values(proto: &mut FuncProto, manager: &AddrSpaceManager,
    types: &dyn TypeFactory, depth: usize) -> KunaResult<bool>
{
    if !proto.has_store() { return Ok(false); }
    let mut changed = false;
    for slot in 0..proto.num_params() {
        let Some(ty) = proto.source_param(slot).and_then(|p| p.get_type()).cloned() else { continue };
        let execution = normalize_type_depth(&ty, manager, types, depth)?;
        if execution != ty { changed |= proto.install_execution_input_type(slot, execution)?; }
    }
    if let Some(ty) = proto.source_output().get_type().cloned() {
        let execution = normalize_type_depth(&ty, manager, types, depth)?;
        if execution != ty { changed |= proto.install_execution_output_type(execution)?; }
    }
    Ok(changed)
}

fn widen_scalar_inputs(proto: &mut FuncProto, manager: &AddrSpaceManager,
    types: &dyn TypeFactory) -> KunaResult<bool>
{
    if !proto.has_store() || !proto.has_model() || !proto.is_input_locked() { return Ok(false); }
    let Some(registers) = manager.register_lookup() else { return Ok(false) };
    let mut requirements = EntryRequirements::default();
    for slot in 0..proto.num_params() {
        let Some(parameter) = proto.source_param(slot).or_else(|| proto.get_param(slot)) else { continue };
        if parameter.is_hidden_return() || parameter.is_indirect_storage()
            || !parameter.get_type().is_some_and(scalar) { continue; }
        let addr = parameter.get_address();
        let Some(space) = addr.get_space() else { continue };
        if space.get_name() != "register" { continue; }
        let size = parameter.get_size();
        if size <= 0 || size >= 8 { continue; }
        // Ask the architecture, rather than guessing ABI sign/zero extension.
        for bytes in ((size + 1)..=8).rev() {
            let mut selected = None;
            for before in 0..=(bytes - size) {
                let Some(start) = addr.get_offset().checked_sub(before as u64) else { continue };
                let name = registers.get_register_name(space, start, bytes);
                if name.is_empty() { continue; }
                let storage = registers.get_register(&name)?;
                if storage.offset != start || storage.size as int4 != bytes { continue; }
                let overlaps = (0..proto.num_params()).filter(|other| *other != slot)
                    .filter_map(|other| proto.source_param(other).or_else(|| proto.get_param(other))).any(|other| {
                        let at = other.get_address();
                        at.get_space().is_some_and(|other| Rc::ptr_eq(space, other))
                            && at.get_offset() < start + bytes as u64
                            && start < at.get_offset() + other.get_size() as u64
                    });
                if !overlaps { selected = Some((Address::new(space.clone(), start), bytes)); break; }
            }
            if let Some(storage) = selected { requirements.reads.push(storage); break; }
        }
    }
    if proto.physical_only_inputs().is_empty() {
        apply_requirements(proto, &requirements, manager, types)
    } else {
        apply_ssa_requirements(proto, &requirements, manager, types)
    }
}

fn callable_type(proto: &FuncProto, types: &dyn TypeFactory) -> KunaResult<TypeRoot> {
    let output = proto.get_output_type().ok_or_else(|| KunaError::lowlevel("Missing callable result"))?;
    let inputs = (0..proto.num_params()).map(|slot| {
        proto.get_param(slot).and_then(|p| p.get_type()).map(TypeRoot::id)
            .ok_or_else(|| KunaError::lowlevel("Missing callable input"))
    }).collect::<KunaResult<Vec<_>>>()?;
    types.get_type_code_proto(&LogicalCallable {
        binding: types.model_binding_for(proto.model().clone())?, output: output.id(), inputs,
        variadic: proto.is_dotdotdot(), input_closed: proto.is_input_locked(),
        logical_first: proto.is_dotdotdot().then_some(proto.num_params()), flags: 0,
    })
}

pub fn normalize_entry(data: &mut Funcdata) -> KunaResult<()> {
    if !data.get_arch().execution_callable_c { return Ok(()); }
    let arch = data.get_arch().clone();
    let Some(types) = arch.types() else { return Ok(()) };
    if let Some(raw) = data.entry_physical_requirements().cloned() {
        if close_finite_variadic_inputs(data.get_func_proto_mut(), &raw, arch.manage())? {
            apply_ssa_requirements(data.get_func_proto_mut(), &raw, arch.manage(), types)?;
        }
    }
    normalize_values(data.get_func_proto_mut(), arch.manage(), types, 0)?;
    Ok(())
}

pub fn normalize_call(data: &mut Funcdata, index: int4) -> KunaResult<()> {
    if !data.get_arch().execution_callable_c { return Ok(()); }
    let arch = data.get_arch().clone();
    let Some(types) = arch.types() else { return Ok(()) };
    let op = data.get_call_specs(index).get_op();
    if let Some(contract) = data.generated_execution_contracts().get(&op).cloned() {
        if install_generated_family(data, index, &contract)? { return Ok(()); }
    }
    if let Some(contract) = data.deferred_execution_contracts().get(&op).cloned() {
        if install_deferred_family(data, index, &contract)? { return Ok(()); }
    }
    let indirect = data.obank().get(op).is_some_and(|op| op.code() == OpCode::CPUI_CALLIND);
    let raw_summary = data.get_call_specs(index).physical_requirements().cloned();
    if !indirect {
        if let Some(raw) = raw_summary.as_ref() {
            close_finite_variadic_inputs(data.get_call_specs_mut(index).proto_mut(), raw, arch.manage())?;
        }
    }
    let mut summary = raw_summary.clone();
    let conditional = !indirect && !data.get_call_specs(index).get_entry_address().is_invalid()
        && adapter_supported(data.get_call_specs(index).proto())
        && (summary.as_ref().is_some_and(|summary| summary.execution.as_ref().is_some_and(|execution| execution.complete))
            || has_internal_role_request(data, op));
    if conditional { summary = summary.as_ref().map(execution_summary); }
    let contract = if indirect && data.get_call_specs(index).proto().has_store()
        && data.get_call_specs(index).proto().is_input_locked() {
        data.entry_physical_requirements().and_then(|raw| raw.execution.as_ref())
            .and_then(|execution| execution.execution_assumptions.iter().find(|(site, _)| *site == op))
            .map(|(_, family)| family.clone())
    } else { None };
    let mapped_override = if !indirect && data.get_call_specs(index).proto().is_override()
        && adapter_supported(data.get_call_specs(index).proto()) {
        let entry = data.get_call_specs(index).get_entry_address();
        match (data.physical_target_requirements(entry), arch.query_function(entry)?) {
            (Some(raw), Some((_, actual, source))) if actual == *entry && execution_complete(raw)
                && adapter_supported(&source) =>
                !requirements_fit(&source.source_prototype(), raw, arch.manage()),
            _ => false,
        }
    } else { false };
    let call = data.get_call_specs_mut(index);
    let proto = call.proto_mut();
    if !proto.has_store() || !proto.has_model() { return Ok(()); }
    if let Some(contract) = contract {
        // Replay only a call-specific normalized producer contract. A native or
        // opaque source declaration alone does not request wider machine inputs.
        let family = if adapter_supported(proto) {
            family_proto(proto, None, arch.manage(), types)?
        } else { proto.source_prototype() };
        let mut requirements = canonical_requirements(&family, summary.as_deref());
        let abi = crate::fspec::materialize_callable(types, &contract)?
            .ok_or_else(|| KunaError::lowlevel("Proven callable family lost its physical assignment"))?;
        requirements.reads.extend((0..abi.prototype().num_params()).map(|slot| {
            let input = abi.prototype().get_param(slot).expect("proven family input");
            (input.get_address(), input.get_size())
        }));
        requirements.reads.sort_unstable();
        requirements.reads.dedup();
        if adapter_supported(&family) && callable_type(&family, types)? == contract
            && family.has_execution_signature() { proto.copy(&family); }
        call.set_physical_requirements(Rc::new(requirements));
        call.set_execution_callable(None);
        let inputs = call.physical_inputs().to_vec();
        call.set_physical_inputs(inputs, true);
        return Ok(());
    }
    // A native indirect declaration is not evidence for a generated execution
    // family. Core-installed positive machine requirements remain intact.
    if indirect { return Ok(()); }
    let physical = proto.has_execution_inputs();
    let callable_transport = normalize_values(proto, arch.manage(), types, 0)? || has_callable_projection(proto);
    if physical && !adapter_supported(proto) {
        widen_scalar_inputs(proto, arch.manage(), types)?;
        let requirements = canonical_requirements(proto, summary.as_deref());
        call.set_physical_requirements(Rc::new(requirements));
        let inputs = call.physical_inputs().to_vec();
        call.set_physical_inputs(inputs, true);
        return Ok(());
    }
    // Mapped overrides request their own execution family without replacing
    // either the site declaration or the target's source declaration.
    let output_transport = proto.source_output().get_type() != proto.get_output_type();
    let widened = if physical || callable_transport || output_transport || conditional || mapped_override {
        widen_scalar_inputs(proto, arch.manage(), types)?
    } else { false };
    let ambient = if let Some(summary) = summary.as_ref() {
        apply_ssa_requirements(proto, &summary, arch.manage(), types)?
    } else { false };
    if ambient { widen_scalar_inputs(proto, arch.manage(), types)?; }
    if !indirect && (widened || ambient || physical || callable_transport || output_transport || conditional || mapped_override) {
        let code = callable_type(proto, types)?;
        let requirements = Rc::new(canonical_requirements(proto, summary.as_deref()));
        if conditional {
            let raw = canonical_requirements(proto, raw_summary.as_deref());
            call.set_physical_requirements(Rc::new(raw));
            call.set_execution_requirements(requirements);
        } else { call.set_physical_requirements(requirements); }
        call.set_execution_callable(Some(code));
        if conditional && !call.execution_inputs_settled() {
            let inputs = call.physical_inputs().to_vec();
            call.set_physical_inputs(inputs, true);
        }
    }
    Ok(())
}

fn execution_complete(summary: &EntryRequirements) -> bool {
    summary.is_complete() || summary.execution.as_ref().is_some_and(|execution| execution.complete)
}

fn execution_reads(summary: &EntryRequirements) -> &[(Address, int4)] {
    summary.execution.as_ref().filter(|execution| execution.complete)
        .map_or(summary.reads.as_slice(), |execution| execution.reads.as_slice())
}

fn execution_summary(summary: &Rc<EntryRequirements>) -> Rc<EntryRequirements> {
    if summary.execution.as_ref().is_none_or(|execution| !execution.complete) { return summary.clone(); }
    let mut selected = summary.as_ref().clone();
    selected.reads = execution_reads(summary).to_vec();
    selected.bookkeeping.clone_from(&summary.execution.as_ref().expect("complete execution summary").bookkeeping);
    // Raw writes, unresolved effects and completeness stay authentic. This view
    // is usable only with a target-owned generated-execution dependency.
    Rc::new(selected)
}

fn canonical_requirements(proto: &FuncProto, existing: Option<&EntryRequirements>) -> EntryRequirements {
    let mut requirements = existing.cloned().unwrap_or_default();
    requirements.reads.extend((0..proto.num_params()).map(|slot| {
        let parameter = proto.get_param(slot).expect("canonical callable state");
        (parameter.get_address(), parameter.get_size())
    }));
    requirements.reads.sort_unstable();
    requirements.reads.dedup();
    requirements
}

/// The known-target branch of ActionDeindirect also needs nested callable
/// contracts before force_set. Missing scalar summaries remain missing so the
/// existing deindirect reflow protocol, not a fabricated extension, recovers them.
pub fn prepare_direct(data: &mut Funcdata, index: int4, entry: &Address, source: &FuncProto) -> KunaResult<()> {
    if !data.get_arch().execution_callable_c { return Ok(()); }
    let arch = data.get_arch().clone();
    let Some(types) = arch.types() else { return Ok(()) };
    let op = data.get_call_specs(index).get_op();
    if let Some(contract) = data.generated_execution_contracts().get(&op).cloned() {
        if contract.targets.len() == 1 && contract.targets[0].entry == *entry
            && native_source_abi_equal(&source.source_prototype(), &contract.targets[0].source)
            && install_generated_family(data, index, &contract)? { return Ok(()); }
    }
    if let Some(contract) = data.deferred_execution_contracts().get(&op).cloned() {
        if contract.entry == *entry && native_source_abi_equal(&source.source_prototype(), &contract.source)
            && install_deferred_family(data, index, &contract)? { return Ok(()); }
    }
    let same_target = data.get_call_specs(index).get_entry_address() == entry;
    let raw_summary = data.physical_target_requirements(entry).cloned()
        .or_else(|| same_target.then(|| data.get_call_specs(index).physical_requirements().cloned()).flatten());
    let mut summary = raw_summary.clone();
    let conditional = adapter_supported(source)
        && (summary.as_ref().is_some_and(|summary| summary.execution.as_ref().is_some_and(|execution| execution.complete))
            || has_internal_role_request(data, op));
    if conditional { summary = summary.as_ref().map(execution_summary); }
    if !same_target {
        let call = data.get_call_specs_mut(index);
        call.clear_physical_requirements();
        call.set_execution_callable(None);
        call.set_physical_inputs(Vec::new(), false);
    }
    let mut proto = source.source_prototype();
    if let Some(summary) = summary.as_ref() {
        if let Some(raw) = raw_summary.as_ref() {
            close_finite_variadic_inputs(&mut proto, raw, arch.manage())?;
        }
        apply_ssa_requirements(&mut proto, summary, arch.manage(), types)?;
    }
    let physical = proto.has_execution_inputs();
    let callable_transport = normalize_values(&mut proto, arch.manage(), types, 0)?;
    if !physical && !callable_transport && !conditional { return Ok(()); }
    widen_scalar_inputs(&mut proto, arch.manage(), types)?;
    if let Some(summary) = summary.as_ref() {
        let requirements = Rc::new(canonical_requirements(&proto, Some(summary)));
        let call = data.get_call_specs_mut(index);
        if conditional {
            call.set_physical_requirements(Rc::new(canonical_requirements(&proto, raw_summary.as_deref())));
            call.set_execution_requirements(requirements);
            if !call.execution_inputs_settled() {
                let inputs = call.physical_inputs().to_vec();
                call.set_physical_inputs(inputs, true);
            }
        } else { call.set_physical_requirements(requirements); }
    }
    if adapter_supported(&proto) {
        data.get_call_specs_mut(index).set_execution_callable(Some(callable_type(&proto, types)?));
    } else {
        let inputs = data.get_call_specs(index).physical_inputs().to_vec();
        data.get_call_specs_mut(index).set_physical_inputs(inputs, true);
    }
    Ok(())
}

/// Discharge a generated boundary only after SSA producer and effect
/// evidence exists. Until then the call keeps every raw fallback operand.
/// Retargeting/reflow rebuilds call specs rather than mutating a settled contract.
pub fn settle_execution_inputs(data: &mut Funcdata, index: int4) -> KunaResult<bool> {
    if !data.get_arch().execution_callable_c { return Ok(false); }
    let call = data.get_call_specs(index);
    if call.execution_inputs_settled() || call.execution_callable().is_none() { return Ok(false); }
    if let Some(contract) = data.generated_execution_contracts().get(&call.get_op()).cloned() {
        if !generated_inputs_proven(data, call.get_op(), &contract)? { return Ok(false); }
        let mut call = data.replace_call_specs(index);
        let result = call.discharge_generated_inputs(data, contract);
        data.restore_call_specs_at(index, call);
        return result;
    }
    if call.get_entry_address().is_invalid() { return Ok(false); }
    if let Some(contract) = data.deferred_execution_contracts().get(&call.get_op()).cloned() {
        if !deferred_inputs_proven(data, call.get_op(), &contract)? { return Ok(false); }
        let mut call = data.replace_call_specs(index);
        let result = call.discharge_deferred_inputs(data, contract);
        data.restore_call_specs_at(index, call);
        return result;
    }
    let Some(selected) = call.execution_requirements().cloned() else { return Ok(false) };
    let op = call.get_op();
    let operation = data.obank().get(op).expect("generated direct boundary");
    if operation.is_dead() || operation.code() != OpCode::CPUI_CALL || operation.num_input() < call.proto().num_params() + 1 {
        return Ok(false);
    }
    if consumes_unrepresented_call_state(data, op) { return Ok(false); }
    for slot in 0..call.proto().num_params() {
        let parameter = call.proto().get_param(slot).expect("canonical direct input");
        let Some(input) = operation.get_in(slot + 1) else { return Ok(false) };
        if data.vbank().get(input).is_none_or(|value| value.get_size() != parameter.get_size()) {
            return Ok(false);
        }
    }
    if !callback_arguments_proven(data, call, &mut Vec::new())? { return Ok(false); }
    let mut call = data.replace_call_specs(index);
    let result = call.discharge_execution_inputs(data, selected);
    data.restore_call_specs_at(index, call);
    result
}

/// Record the transport contract before force_set can trim the operation.
pub fn prepare_indirect(data: &mut Funcdata, index: int4, source: &FuncProto) -> KunaResult<()> {
    if !data.get_arch().execution_callable_c { return Ok(()); }
    let op = data.get_call_specs(index).get_op();
    if let Some(contract) = data.generated_execution_contracts().get(&op).cloned() {
        if install_generated_family(data, index, &contract)? { return Ok(()); }
    }
    let arch = data.get_arch().clone();
    let Some(types) = arch.types() else { return Ok(()) };
    let target = data.obank().get(data.get_call_specs(index).get_op()).and_then(|op| op.get_in(0));
    let Some(proven) = target.map(|target| normalized_family(data, target, &mut Vec::new())).transpose()?.flatten()
        else { return Ok(()) };
    let family = if adapter_supported(source) {
        family_proto(source, None, arch.manage(), types)?
    } else { source.source_prototype() };
    let compatible = adapter_supported(&family) && proven.family == family_identity(&family, types)?;
    let mut requirements = canonical_requirements(&family,
        data.get_call_specs(index).physical_requirements().map(|summary| summary.as_ref()));
    // An incompatible source override cannot erase the actual producer's known
    // machine inputs. Keep both interfaces as a genuine raw boundary.
    requirements.reads.extend(proven.family.storage);
    requirements.reads.sort_unstable();
    requirements.reads.dedup();
    data.get_call_specs_mut(index).set_physical_requirements(Rc::new(requirements));
    if compatible {
        let execution = callable_type(&family, types)?;
        data.get_call_specs_mut(index).set_execution_callable(Some(execution));
        let inputs = data.get_call_specs(index).physical_inputs().to_vec();
        data.get_call_specs_mut(index).set_physical_inputs(inputs, false);
    } else {
        data.get_call_specs_mut(index).set_execution_callable(None);
        let inputs = data.get_call_specs(index).physical_inputs().to_vec();
        data.get_call_specs_mut(index).set_physical_inputs(inputs, true);
    }
    Ok(())
}

/// A direct mapped value-result call needs the same target-owned logical
/// wrapper and memory-SSA proof as a finite indirect producer. Its source ABI,
/// not the current raw fallback operand list, identifies that result contract.
pub(crate) fn generated_direct_result_entry(fd: &Funcdata, op: OpId) -> KunaResult<Option<Address>> {
    if fd.obank().get(op).is_none_or(|operation| operation.is_dead()
        || operation.code() != OpCode::CPUI_CALL) { return Ok(None); }
    let Some(index) = fd.get_call_specs_index(op) else { return Ok(None); };
    let entry = fd.get_call_specs(index).get_entry_address();
    if entry.is_invalid() { return Ok(None); }
    let Some((_, actual, source)) = fd.get_arch().query_function(entry)? else { return Ok(None); };
    if actual != *entry || logical_result_family(fd, &source.source_prototype())?.is_none() { return Ok(None); }
    Ok(Some(entry.clone()))
}

/// Exact addresses produced by one settled SSA callable operand. This only
/// requests real target probes; it does not admit a boundary or replace raw facts.
fn generated_target_set(fd: &Funcdata, op: OpId) -> KunaResult<Option<BTreeSet<Address>>> {
    if let Some(entry) = generated_direct_result_entry(fd, op)? {
        return Ok(Some(BTreeSet::from([entry])));
    }
    fn walk(fd: &Funcdata, value: VarnodeId, space: &Rc<kuna_base::space::AddrSpace>,
        targets: &mut BTreeSet<Address>, active: &mut Vec<VarnodeId>, remaining: &mut usize) -> bool
    {
        if *remaining == 0 || active.len() >= 64 || active.contains(&value) { return false; }
        *remaining -= 1;
        let Some(node) = fd.vbank().get(value) else { return false; };
        if node.is_constant() {
            if node.get_offset() == 0 { return false; }
            let offset = kuna_base::space::AddrSpace::address_to_byte(node.get_offset(), space.get_word_size());
            targets.insert(Address::new(space.clone(), offset));
            return targets.len() <= 64;
        }
        if node.is_input() { return false; }
        let Some(operation) = node.get_def().and_then(|id| fd.obank().get(id)).filter(|op| !op.is_dead())
            else { return false; };
        active.push(value);
        let result = match operation.code() {
            OpCode::CPUI_COPY | OpCode::CPUI_CAST => operation.num_input() == 1
                && operation.get_in(0).is_some_and(|input| fd.vbank().get(input)
                    .is_some_and(|input| input.get_size() == node.get_size()))
                && operation.get_in(0).is_some_and(|input| walk(fd, input, space, targets, active, remaining)),
            OpCode::CPUI_PTRSUB => operation.num_input() == 2
                && operation.get_in(0).and_then(|input| fd.vbank().get(input))
                    .is_some_and(|base| base.is_constant() && base.get_offset() == 0)
                && operation.get_in(1).is_some_and(|input| walk(fd, input, space, targets, active, remaining)),
            OpCode::CPUI_MULTIEQUAL => operation.num_input() > 0 && (0..operation.num_input()).all(|slot|
                operation.get_in(slot).is_some_and(|input| fd.vbank().get(input)
                    .is_some_and(|input| input.get_size() == node.get_size()))
                && operation.get_in(slot).is_some_and(|input| walk(fd, input, space, targets, active, remaining))),
            _ => false,
        };
        active.pop();
        result
    }
    let Some(operation) = fd.obank().get(op).filter(|operation|
        !operation.is_dead() && operation.code() == OpCode::CPUI_CALLIND) else { return Ok(None); };
    let Some(input) = operation.get_in(0) else { return Ok(None); };
    let Some(value) = fd.vbank().get(input) else { return Ok(None); };
    let pointer = value.get_type_read_facing(op);
    if pointer.get_ptr_to().is_none_or(|code| code.get_metatype() != type_metatype::TYPE_CODE) {
        return Ok(None);
    }
    let space = pointer.get_pointer_space().or_else(|| fd.get_arch().manage().get_default_code_space().cloned());
    let Some(space) = space else { return Ok(None); };
    if u32::try_from(value.get_size()).ok() != Some(space.get_addr_size()) { return Ok(None); }
    let mut targets = BTreeSet::new();
    if !walk(fd, input, &space, &mut targets, &mut Vec::new(), &mut 512) || targets.is_empty() {
        return Ok(None);
    }
    Ok(Some(targets))
}

pub(crate) fn generated_target_requests(fd: &Funcdata) -> KunaResult<BTreeSet<Address>> {
    let mut result = BTreeSet::new();
    if !fd.get_arch().execution_callable_c { return Ok(result); }
    for index in 0..fd.num_calls() {
        if let Some(targets) = generated_target_set(fd, fd.get_call_specs(index).get_op())? {
            result.extend(targets);
        }
    }
    Ok(result)
}

#[derive(Clone, Debug)]
pub struct GeneratedBodyTarget {
    pub entry: Address,
    pub source: Rc<FuncProto>,
    pub raw: Rc<EntryRequirements>,
    pub witness: Option<Rc<super::kuna_physicalinputs::MappedBodyWitness>>,
}

#[derive(Clone, Debug)]
pub struct GeneratedCallContract {
    /// Source prototype recovered at the proved typed site, not a raw epoch's
    /// still-unresolved placeholder prototype.
    pub source: Rc<FuncProto>,
    /// Actual CALL input order, including assigned implicit result parameters.
    pub family: Rc<FuncProto>,
    /// Physical execution Code, or retained logical Code for a value-result
    /// family whose target publication requires a real logical-result wrapper.
    pub family_code: TypeRoot,
    pub effects: super::kuna_physicalinputs::ExecutionCallEffects,
    pub targets: Vec<Rc<GeneratedBodyTarget>>,
}

/// Return an actual CALL operand slot, never a source logical parameter index.
pub(crate) fn generated_hidden_argument_slot(expected: &GeneratedCallContract)
    -> KunaResult<Option<int4>>
{
    let Some(hidden) = &expected.effects.hidden_result else { return Ok(None); };
    let proto = &expected.family;
    if !proto.has_store() || !proto.get_output().is_indirect_storage()
        || proto.callable_input_origins().len() != proto.num_params() as usize {
        return Ok(None);
    }
    let mut result = None;
    for slot in 0..proto.num_params() {
        let parameter = proto.get_param(slot).expect("generated physical slot");
        let role = proto.callable_input_origins()[slot as usize];
        if matches!(role, crate::fspec::AbiInputOrigin::HiddenResult) {
            if result.is_some() || !parameter.is_hidden_return()
                || parameter.get_address() != hidden.address || parameter.get_size() != hidden.pointer_size {
                return Ok(None);
            }
            result = Some(slot + 1);
        } else if parameter.is_hidden_return() { return Ok(None); }
    }
    Ok(result)
}

/// Only actual mapped probes create target authority. Positive raw reads remain
/// attached even when the mapped body still owes nested publication receipts.
pub(crate) fn generated_body_target(fd: &Funcdata, entry: &Address,
    raw: Rc<EntryRequirements>, witness: Option<Rc<super::kuna_physicalinputs::MappedBodyWitness>>)
    -> KunaResult<Option<Rc<GeneratedBodyTarget>>>
{
    let Some((_, actual, declaration)) = fd.get_arch().query_function(entry)? else { return Ok(None); };
    if actual != *entry || !declaration.has_store() || !declaration.has_model()
        || !declaration.is_input_locked() || !declaration.is_output_locked()
        || declaration.is_dotdotdot() || declaration.is_inline() || declaration.is_no_return()
        || declaration.get_inject_id() >= 0 || declaration.has_input_errors() || declaration.has_output_errors()
        || witness.as_ref().is_some_and(|proof| proof.entry() != entry || !Rc::ptr_eq(proof.raw(), &raw))
        || (!execution_complete(&raw) && witness.is_none()) { return Ok(None); }
    let source = declaration.source_prototype();
    if !adapter_supported(&source) && logical_result_family(fd, &source)?.is_none() { return Ok(None); }
    Ok(Some(Rc::new(GeneratedBodyTarget { entry: entry.clone(), source: Rc::new(source), raw, witness })))
}

fn generated_target_key(fd: &Funcdata, target: &GeneratedBodyTarget, family: &FuncProto) -> KunaResult<String> {
    if let Some(logical) = logical_result_family(fd, family)? {
        Ok(logical_result_key(&target.entry, family, &logical))
    } else { Ok(adapter_key(&target.entry, family)) }
}

fn generated_pointer_request(fd: &Funcdata, entry: &Address) -> KunaResult<Option<(String, FuncProto)>> {
    for contract in fd.generated_execution_contracts().values() {
        if let Some(target) = contract.targets.iter().find(|target| target.entry == *entry) {
            let Some((_, actual, source)) = fd.get_arch().query_function(entry)? else { return Ok(None); };
            if actual != *entry || !native_source_abi_equal(&source.source_prototype(), &target.source) { return Ok(None); }
            let mut family = FuncProto::new();
            family.copy(&contract.family);
            return Ok(Some((generated_target_key(fd, target, &contract.family)?, family)));
        }
    }
    Ok(None)
}

fn generated_required_artifacts(fd: &Funcdata, arch: &Architecture, printer: &crate::printc::PrintC,
    artifacts: &mut BTreeMap<String, CallableArtifact>) -> KunaResult<()>
{
    for (op, contract) in fd.generated_execution_contracts() {
        if !generated_contract_matches(fd, *op, contract)? {
            return Err(KunaError::lowlevel("Generated target request lost its exact SSA producer set"));
        }
        for target in &contract.targets {
            let key = generated_target_key(fd, target, &contract.family)?;
            let logical = logical_result_family(fd, &contract.family)?;
            let name = if contract.family.has_execution_signature() { key.clone() } else {
                let Some((name, entry, _)) = fd.get_arch().query_function(&target.entry)? else {
                    return Err(KunaError::lowlevel("Generated target lost its actual source symbol"));
                };
                if entry != target.entry { return Err(KunaError::lowlevel("Generated target changed address")); }
                printer.emitted_function_name(fd, &name, &entry, true)
            };
            let declaration = if let Some(logical) = logical {
                format!("{};", logical_result_declaration(&logical, &name, arch, printer))
            } else { format!("{};", declaration_with_convention(&contract.family, &name, arch,
                !contract.family.has_execution_signature() && printer.options.convention, printer)?) };
            let deferred = !execution_complete(&target.raw);
            if let Some(previous) = artifacts.get_mut(&key) {
                if previous.declaration != declaration { return Err(KunaError::lowlevel("Generated target family declarations conflict")); }
                previous.required = true;
                previous.deferred |= deferred;
            } else { artifacts.insert(key.clone(), CallableArtifact { key, declaration, definition: None, required: true, deferred }); }
        }
    }
    Ok(())
}

fn generated_family(fd: &Funcdata, source: &FuncProto)
    -> KunaResult<Option<(FuncProto, TypeRoot, super::kuna_physicalinputs::ExecutionCallEffects)>>
{
    if !source.has_store() || !source.has_model() || !source.is_input_locked() || !source.is_output_locked()
        || source.is_dotdotdot() || source.is_inline() || source.is_no_return() || source.get_inject_id() >= 0
        || source.has_input_errors() || source.has_output_errors() { return Ok(None); }
    let Some(types) = fd.get_arch().types() else { return Ok(None); };
    let logical = logical_result_family(fd, source)?;
    let (family, code, hidden_result) = if let Some(logical) = logical {
        let parameter = source.get_param(logical.hidden_slot).expect("logical hidden slot");
        let hidden = super::kuna_physicalinputs::ExecutionIndirectResult {
            address: parameter.get_address(), pointer_size: parameter.get_size(), value_size: logical.result.get_size(),
        };
        (source.source_prototype(), logical.code, Some(hidden))
    } else {
        if !adapter_supported(source) { return Ok(None); }
        let family = family_proto(source, None, fd.get_arch().manage(), types)?;
        if !adapter_supported(&family) { return Ok(None); }
        let code = callable_type(&family, types)?;
        (family, code, None)
    };
    let mut inputs = Vec::new();
    for slot in 0..family.num_params() {
        let parameter = family.get_param(slot).expect("generated family parameter");
        if parameter.get_size() <= 0 || parameter.get_address().is_invalid() { return Ok(None); }
        append_effect_input(&mut inputs, parameter.get_address(), parameter.get_size(), fd.get_arch().manage())?;
    }
    let mut outputs = Vec::new();
    let output = family.get_output();
    if output.get_size() > 0 && output.get_type().is_some_and(|ty| ty.get_metatype() != type_metatype::TYPE_VOID) {
        if output.get_address().is_invalid() { return Ok(None); }
        append_effect_input(&mut outputs, output.get_address(), output.get_size(), fd.get_arch().manage())?;
    }
    if inputs.iter().chain(&outputs).any(|(address, size)| *size <= 0
        || address.get_offset().checked_add(*size as u64).is_none()
        || address.get_space().is_none_or(|space| space.get_name() != "register"
            && space.get_type() != kuna_base::space::spacetype::IPTR_SPACEBASE)) { return Ok(None); }
    let effects = super::kuna_physicalinputs::ExecutionCallEffects {
        inputs, outputs, hidden_result,
        preserved: family.effect_list().iter().filter(|effect| effect.get_type() == crate::fspec::effect_type::UNAFFECTED)
            .map(|effect| (effect.get_address(), effect.get_size())).collect(),
        stack_adjustment: stack_adjustment(&family, false),
    };
    if effects.stack_adjustment.is_none() { return Ok(None); }
    Ok(Some((family, code, effects)))
}

fn generated_contract_from_source(fd: &Funcdata, source: &FuncProto,
    entries: &BTreeSet<Address>, targets: &BTreeMap<Address, Rc<GeneratedBodyTarget>>)
    -> KunaResult<Option<GeneratedCallContract>>
{
    let Some((family, family_code, effects)) = generated_family(fd, source)? else { return Ok(None); };
    let Some(types) = fd.get_arch().types() else { return Ok(None); };
    let identity = family_identity(&family, types)?;
    let mut selected = Vec::with_capacity(entries.len());
    for entry in entries {
        let Some(target) = targets.get(entry) else {
            return Ok(None);
        };
        if target.entry != *entry { return Ok(None); }
        let Some((target_family, target_code, target_effects)) = generated_family(fd, &target.source)? else { return Ok(None); };
        if target_code != family_code || family_identity(&target_family, types)? != identity
            || !Rc::ptr_eq(target_family.model(), family.model()) || (target_effects.inputs != effects.inputs || target_effects.outputs != effects.outputs
                || target_effects.preserved != effects.preserved || target_effects.stack_adjustment != effects.stack_adjustment
                || target_effects.hidden_result.as_ref().map(|result| (&result.address, result.pointer_size, result.value_size))
                    != effects.hidden_result.as_ref().map(|result| (&result.address, result.pointer_size, result.value_size)))
            || !requirements_fit(&family, &target.raw, fd.get_arch().manage()) { return Ok(None); }
        // A raw-complete target is still a generated body, not a native waiver.
        // Incomplete mapped targets retain their exact body witness and owe a
        // deferred provider; neither case mutates raw preservation facts.
        if !execution_complete(&target.raw) && target.witness.as_ref().is_none_or(|witness|
            witness.entry() != entry || !Rc::ptr_eq(witness.raw(), &target.raw)) { return Ok(None); }
        selected.push(target.clone());
    }
    Ok(Some(GeneratedCallContract {
        source: Rc::new(source.source_prototype()), family: Rc::new(family), family_code, effects, targets: selected,
    }))
}

pub(crate) fn generated_call_contract(fd: &Funcdata, op: OpId,
    targets: &BTreeMap<Address, Rc<GeneratedBodyTarget>>) -> KunaResult<Option<GeneratedCallContract>>
{
    let Some(entries) = generated_target_set(fd, op)? else { return Ok(None); };
    let Some(index) = fd.get_call_specs_index(op) else { return Ok(None); };
    let call = fd.get_call_specs(index);
    generated_contract_from_source(fd, &call.proto().source_prototype(), &entries, targets)
}

/// Core separately authenticates the original raw site fingerprint. Its raw
/// unresolved prototype is deliberately not compared with the settled source.
pub(crate) fn rebind_generated_contract(fd: &Funcdata, _op: OpId, retained: &GeneratedCallContract,
    targets: &BTreeMap<Address, Rc<GeneratedBodyTarget>>) -> KunaResult<Option<GeneratedCallContract>>
{
    let entries = retained.targets.iter().map(|target| target.entry.clone()).collect();
    generated_contract_from_source(fd, &retained.source, &entries, targets)
}

pub(crate) fn generated_hidden_value_size(expected: &GeneratedCallContract) -> KunaResult<Option<int4>> {
    let Some(slot) = generated_hidden_argument_slot(expected)? else { return Ok(None); };
    let hidden = expected.effects.hidden_result.as_ref().expect("validated generated hidden slot");
    let parameter = expected.family.get_param(slot - 1).expect("validated physical slot");
    let Some(output) = parameter.get_type().and_then(|ty| ty.get_ptr_to()) else { return Ok(None); };
    let view = expected.family_code.read();
    let id = view.resolve_alias(expected.family_code.id())?;
    let Some(logical) = view.get_code_prototype(id)? else { return Ok(None); };
    if logical.output != output.id() || output.get_size() != hidden.value_size
        || super::kuna_logicalresultbody::result_layout(&output)?.is_none() { return Ok(None); }
    Ok(Some(hidden.value_size))
}

pub(crate) fn generated_family_matches(fd: &Funcdata, call: &crate::fspec::FuncCallSpecs, expected: &Rc<GeneratedCallContract>) -> KunaResult<bool> {
    let op = call.get_op();
    let Some(operation) = fd.obank().get(op).filter(|operation| !operation.is_dead()
        && matches!(operation.code(), OpCode::CPUI_CALL | OpCode::CPUI_CALLIND)) else { return Ok(false); };
    if fd.generated_execution_contracts().get(&op).is_none_or(|actual| !Rc::ptr_eq(actual, expected))
        || !native_source_abi_equal(&call.proto().source_prototype(), &expected.source)
        || call.execution_callable() != Some(&expected.family_code)
        || operation.num_input() < expected.family.num_params() + 1 { return Ok(false); }
    let Some(types) = fd.get_arch().types() else { return Ok(false); };
    if family_identity(call.proto(), types)? != family_identity(&expected.family, types)?
        || !Rc::ptr_eq(call.proto().model(), expected.family.model())
        || call.proto().effect_list() != expected.family.effect_list()
        || call.proto().trash_list() != expected.family.trash_list()
        || call.proto().internal_list() != expected.family.internal_list()
        || call.proto().get_extra_pop() != expected.family.get_extra_pop() { return Ok(false); }
    if operation.code() == OpCode::CPUI_CALL {
        if expected.targets.len() != 1 || call.get_entry_address() != &expected.targets[0].entry { return Ok(false); }
    } else {
        let Some(entries) = generated_target_set(fd, op)? else { return Ok(false); };
        if entries.len() != expected.targets.len() || expected.targets.iter().any(|target| !entries.contains(&target.entry)) {
            return Ok(false);
        }
    }
    for target in &expected.targets {
        let Some((_, entry, source)) = fd.get_arch().query_function(&target.entry)? else { return Ok(false); };
        if entry != target.entry || !native_source_abi_equal(&source.source_prototype(), &target.source)
            || target.witness.as_ref().is_some_and(|witness| witness.entry() != &entry
                || !Rc::ptr_eq(witness.raw(), &target.raw)) { return Ok(false); }
    }
    Ok(true)
}

pub(crate) fn generated_inputs_proven(fd: &Funcdata, op: OpId, expected: &Rc<GeneratedCallContract>) -> KunaResult<bool> {
    let Some(index) = fd.get_call_specs_index(op) else { return Ok(false); };
    let call = fd.get_call_specs(index);
    if !generated_family_matches(fd, call, expected)? || consumes_unrepresented_call_state(fd, op) { return Ok(false); }
    let operation = fd.obank().get(op).expect("replayed generated call");
    for slot in 0..expected.family.num_params() {
        let parameter = expected.family.get_param(slot).expect("generated physical input");
        if operation.get_in(slot + 1).and_then(|input| fd.vbank().get(input))
            .is_none_or(|value| value.get_size() != parameter.get_size()) { return Ok(false); }
    }
    callback_arguments_proven(fd, fd.get_call_specs(fd.get_call_specs_index(op).expect("generated call spec")), &mut Vec::new())
}

pub(crate) fn generated_contract_matches(fd: &Funcdata, op: OpId, expected: &Rc<GeneratedCallContract>) -> KunaResult<bool> {
    let proven = generated_inputs_proven(fd, op, expected)?;
    if !proven { return Ok(false); }
    let call = fd.get_call_specs(fd.get_call_specs_index(op).expect("replayed generated call"));
    let valid = call.execution_inputs_settled() && !call.requires_raw_call()
        && fd.obank().get(op).is_some_and(|operation| operation.num_input() == expected.family.num_params() + 1);
    Ok(valid)
}

fn install_generated_family(fd: &mut Funcdata, index: int4, expected: &Rc<GeneratedCallContract>) -> KunaResult<bool> {
    let call = fd.get_call_specs(index);
    if fd.generated_execution_contracts().get(&call.get_op()).is_none_or(|actual| !Rc::ptr_eq(actual, expected)) {
        return Ok(false);
    }
    // Source identity is authenticated by Core's original raw fingerprint;
    // source declarations are restored from the retained settled certificate.
    let call = fd.get_call_specs_mut(index);
    call.proto_mut().copy(&expected.family);
    call.set_execution_callable(Some(expected.family_code.clone()));
    if !call.execution_inputs_settled() {
        let inputs = call.physical_inputs().to_vec();
        call.set_physical_inputs(inputs, true);
    }
    Ok(true)
}

#[derive(Clone, Debug)]
pub struct DeferredBodyContract {
    pub entry: Address,
    pub source: Rc<FuncProto>,
    pub family: Rc<FuncProto>,
    pub family_code: TypeRoot,
    pub effects: super::kuna_physicalinputs::ExecutionCallEffects,
    pub raw: Rc<EntryRequirements>,
    pub witness: Rc<super::kuna_physicalinputs::MappedBodyWitness>,
}

/// A mapped body may owe nested call closure or target-owned conditional
/// preservation. Keep its raw facts and demand an actual target-owned
/// family/body receipt before this premise can be published.
pub(crate) fn raw_deferred_contract(fd: &Funcdata, op: OpId,
    raw: Rc<EntryRequirements>, witness: Rc<super::kuna_physicalinputs::MappedBodyWitness>)
    -> KunaResult<Option<DeferredBodyContract>>
{
    if !Rc::ptr_eq(&raw, witness.raw()) { return Ok(None); }
    if fd.obank().get(op).is_none_or(|operation| operation.is_dead()
        || operation.code() != OpCode::CPUI_CALL) { return Ok(None); }
    let Some(index) = fd.get_call_specs_index(op) else { return Ok(None) };
    let call = fd.get_call_specs(index);
    if call.get_entry_address().is_invalid() || call.get_entry_address() != witness.entry()
        || !call.proto().is_input_locked() || !call.proto().is_output_locked()
        || !adapter_supported(call.proto()) || call.proto().is_inline()
        || call.proto().is_no_return() || call.proto().get_inject_id() >= 0
        || call.proto().has_input_errors() || call.proto().has_output_errors()
    { return Ok(None); }
    let Some(types) = fd.get_arch().types() else { return Ok(None) };
    let source = call.proto().source_prototype();
    let Some((_, entry, declaration)) = fd.get_arch().query_function(call.get_entry_address())? else { return Ok(None) };
    if entry != *call.get_entry_address()
        || !native_source_abi_equal(&source, &declaration.source_prototype()) { return Ok(None); }
    let family = family_proto(&source, None, fd.get_arch().manage(), types)?;
    if !adapter_supported(&family) || family.get_extra_pop() == crate::fspec::EXTRAPOP_UNKNOWN {
        return Ok(None);
    }
    if execution_complete(&raw) {
        let conditional = raw.execution.as_deref().filter(|execution| execution.complete);
        if !requirements_fit(&family, &raw, fd.get_arch().manage())
            || preservation_fits(&family, &source, &raw, conditional, &[], false, fd.get_arch().manage()) {
            return Ok(None);
        }
        // An ordinary family receipt cannot discharge a stronger internal-role
        // obligation. Those calls still need the exact qualified role provider.
        for role in source.internal_list() {
            let Some(space) = &role.space else { return Ok(None); };
            let Some(end) = u64::try_from(role.size).ok().filter(|size| *size > 0)
                .and_then(|size| role.offset.checked_add(size)) else { return Ok(None); };
            for (address, size) in &raw.writes {
                if *size <= 0 || address.get_space().is_none_or(|other| !Rc::ptr_eq(space, other)) { continue; }
                let Some(limit) = address.get_offset().checked_add(*size as u64) else { return Ok(None); };
                let start = role.offset.max(address.get_offset());
                let limit = end.min(limit);
                if start < limit && !ranges_cover(raw.restored.iter()
                    .chain(conditional.into_iter().flat_map(|execution| &execution.restored)),
                    &Address::new(space.clone(), start), int4::try_from(limit - start).map_err(|_| KunaError::lowlevel("Internal role interval overflows"))?) {
                    return Ok(None);
                }
            }
        }
    }
    let family_code = callable_type(&family, types)?;
    let mut inputs = Vec::new();
    for slot in 0..family.num_params() {
        let parameter = family.get_param(slot).expect("deferred execution parameter");
        if parameter.get_size() <= 0 || parameter.get_address().is_invalid() { return Ok(None); }
        append_effect_input(&mut inputs, parameter.get_address(), parameter.get_size(), fd.get_arch().manage())?;
    }
    let mut outputs = Vec::new();
    let output = family.get_output();
    if output.get_size() > 0 && output.get_type().is_some_and(|ty| ty.get_metatype() != type_metatype::TYPE_VOID) {
        if output.get_address().is_invalid() { return Ok(None); }
        append_effect_input(&mut outputs, output.get_address(), output.get_size(), fd.get_arch().manage())?;
    }
    if inputs.iter().chain(&outputs).any(|(address, size)| *size <= 0
        || address.get_offset().checked_add(*size as u64).is_none()
        || address.get_space().is_none_or(|space| space.get_name() != "register"
            && space.get_type() != kuna_base::space::spacetype::IPTR_SPACEBASE)) { return Ok(None); }
    let effects = super::kuna_physicalinputs::ExecutionCallEffects {
        inputs, outputs, hidden_result: None,
        preserved: family.effect_list().iter().filter(|effect|
            effect.get_type() == crate::fspec::effect_type::UNAFFECTED)
            .map(|effect| (effect.get_address().clone(), effect.get_size() as int4)).collect(),
        stack_adjustment: stack_adjustment(&family, false),
    };
    if effects.stack_adjustment.is_none() { return Ok(None); }
    Ok(Some(DeferredBodyContract {
        entry: call.get_entry_address().clone(), source: Rc::new(source), family: Rc::new(family),
        family_code, effects, raw, witness,
    }))
}

/// Replay the exact request-local source and assigned execution family. This is
/// not body completeness: callers must retain the deferred publication edge.
pub(crate) fn deferred_family_matches(fd: &Funcdata, call: &crate::fspec::FuncCallSpecs, expected: &Rc<DeferredBodyContract>) -> KunaResult<bool> {
    let op = call.get_op();
    let Some(operation) = fd.obank().get(op).filter(|operation| !operation.is_dead()
        && operation.code() == OpCode::CPUI_CALL) else { return Ok(false) };
    if fd.deferred_execution_contracts().get(&op).is_none_or(|actual| !Rc::ptr_eq(actual, expected))
        || expected.entry != *expected.witness.entry() || !Rc::ptr_eq(&expected.raw, expected.witness.raw())
        || call.physical_requirements().is_none_or(|raw| !Rc::ptr_eq(raw, &expected.raw))
        || call.get_entry_address() != &expected.entry
        || !native_source_abi_equal(&call.proto().source_prototype(), &expected.source)
        || call.execution_callable() != Some(&expected.family_code)
    { return Ok(false); }
    let Some((_, entry, source)) = fd.get_arch().query_function(&expected.entry)? else { return Ok(false) };
    if entry != expected.entry || !native_source_abi_equal(&source.source_prototype(), &expected.source) { return Ok(false); }
    let Some(types) = fd.get_arch().types() else { return Ok(false) };
    if family_identity(call.proto(), types)? != family_identity(&expected.family, types)?
        || !Rc::ptr_eq(call.proto().model(), expected.family.model())
        || call.proto().effect_list() != expected.family.effect_list()
        || call.proto().trash_list() != expected.family.trash_list()
        || call.proto().internal_list() != expected.family.internal_list()
        || call.proto().get_extra_pop() != expected.family.get_extra_pop()
        || operation.num_input() < call.proto().num_params() + 1
    { return Ok(false); }
    Ok(true)
}

/// Only this admitted contract can discharge its original captured raw operand
/// tail. Every retained formal still denotes a real current SSA operand.
pub(crate) fn deferred_inputs_proven(fd: &Funcdata, op: OpId, expected: &Rc<DeferredBodyContract>) -> KunaResult<bool> {
    let Some(index) = fd.get_call_specs_index(op) else { return Ok(false) };
    let call = fd.get_call_specs(index);
    if !deferred_family_matches(fd, call, expected)? || consumes_unrepresented_call_state(fd, op) { return Ok(false); }
    let operation = fd.obank().get(op).expect("replayed deferred operation");
    for slot in 0..call.proto().num_params() {
        let parameter = call.proto().get_param(slot).expect("deferred family argument");
        if operation.get_in(slot + 1).and_then(|input| fd.vbank().get(input))
            .is_none_or(|value| value.get_size() != parameter.get_size()) { return Ok(false); }
    }
    callback_arguments_proven(fd, call, &mut Vec::new())
}

fn deferred_contract_matches(fd: &Funcdata, op: OpId, expected: &Rc<DeferredBodyContract>) -> KunaResult<bool> {
    if !deferred_inputs_proven(fd, op, expected)? { return Ok(false); }
    let call = fd.get_call_specs(fd.get_call_specs_index(op).expect("replayed deferred call"));
    Ok(call.execution_inputs_settled() && !call.requires_raw_call()
        && fd.obank().get(op).is_some_and(|operation| operation.num_input() == call.proto().num_params() + 1))
}

fn install_deferred_family(fd: &mut Funcdata, index: int4, expected: &Rc<DeferredBodyContract>) -> KunaResult<bool> {
    let call = fd.get_call_specs(index);
    if call.get_entry_address() != &expected.entry
        || !native_source_abi_equal(&call.proto().source_prototype(), &expected.source)
        || fd.deferred_execution_contracts().get(&call.get_op()).is_none_or(|actual| !Rc::ptr_eq(actual, expected))
    { return Ok(false); }
    let call = fd.get_call_specs_mut(index);
    call.proto_mut().copy(&expected.family);
    call.set_execution_callable(Some(expected.family_code.clone()));
    // Preserve the original raw summary. The separate explicit family premise
    // never manufactures a complete EntryRequirements or substitutes its reads.
    call.set_physical_requirements(expected.raw.clone());
    if !call.execution_inputs_settled() {
        let inputs = call.physical_inputs().to_vec();
        call.set_physical_inputs(inputs, true);
    }
    Ok(true)
}

/// The source logical value and its exact assigned hidden destination. This
/// describes a possible adapter family, not evidence that a body implements it.
#[derive(Clone, Debug)]
pub(crate) struct LogicalResultFamily {
    pub code: TypeRoot,
    pub result: TypeRoot,
    pub hidden_slot: int4,
    pub inputs: Vec<TypeRoot>,
    pub origins: Vec<crate::fspec::AbiInputOrigin>,
}

pub(crate) fn logical_result_family(fd: &Funcdata, proto: &FuncProto)
    -> KunaResult<Option<LogicalResultFamily>>
{
    if !native_default_model(proto, fd) || !proto.is_input_locked() || !proto.is_output_locked()
        || proto.is_dotdotdot() || !proto.get_output().is_indirect_storage()
        || proto.get_output_type().is_none_or(|output| output.get_metatype() != type_metatype::TYPE_VOID)
    { return Ok(None); }
    let Some(code) = proto.logical_callable() else { return Ok(None) };
    let logical = {
        let view = code.read();
        let id = view.resolve_alias(code.id())?;
        let Some(logical) = view.get_code_prototype(id)? else { return Ok(None) };
        logical.clone()
    };
    if logical.variadic || !logical.input_closed { return Ok(None); }
    let result = code.related(logical.output)?;
    if result.is_incomplete() || result.get_size() <= 0
        || matches!(result.get_metatype(), type_metatype::TYPE_VOID | type_metatype::TYPE_CODE
            | type_metatype::TYPE_ARRAY | type_metatype::TYPE_SPACEBASE) { return Ok(None); }
    let Some(types) = fd.get_arch().types() else { return Ok(None) };
    let Some(abi) = crate::fspec::materialize_callable(types, code)? else { return Ok(None) };
    if proto.callable_input_origins() != abi.input_origins()
        || proto.callable_input_origins().len() != proto.num_params() as usize { return Ok(None); }
    let mut hidden_slot = None;
    let mut arguments = Vec::with_capacity(proto.num_params() as usize);
    for slot in 0..proto.num_params() {
        let parameter = proto.get_param(slot).expect("logical result physical parameter");
        let Some(datatype) = parameter.get_type() else { return Ok(None) };
        match proto.callable_input_origins()[slot as usize] {
            crate::fspec::AbiInputOrigin::HiddenResult => {
                if hidden_slot.replace(slot).is_some() || !parameter.is_hidden_return()
                    || datatype.get_ptr_to().as_ref() != Some(&result) { return Ok(None); }
            }
            crate::fspec::AbiInputOrigin::Declared(logical_slot) => {
                if parameter.is_hidden_return() || parameter.is_indirect_storage()
                    || logical.inputs.get(logical_slot).copied() != Some(datatype.id()) { return Ok(None); }
            }
        }
        arguments.push(NativeCallArgument {
            address: parameter.get_address(), size: parameter.get_size(), datatype: datatype.clone(),
        });
    }
    let Some(hidden_slot) = hidden_slot else { return Ok(None) };
    if !native_layout_matches(fd, proto, proto, &arguments)? { return Ok(None); }
    Ok(Some(LogicalResultFamily {
        code: code.clone(), result,
        hidden_slot,
        inputs: logical.inputs.into_iter().map(|id| code.related(id)).collect::<KunaResult<Vec<_>>>()?,
        origins: proto.callable_input_origins().to_vec(),
    }))
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NativeCallArgument {
    pub address: Address,
    pub size: int4,
    pub datatype: TypeRoot,
}

#[derive(Clone, Debug)]
pub enum NativeTargetContract {
    Direct { entry: Address, declaration: Rc<FuncProto> },
    Indirect { pointer_code: TypeRoot },
}

#[derive(Clone, Debug)]
pub struct NativeCallContract {
    pub prototype: Rc<FuncProto>,
    pub target: NativeTargetContract,
    pub arguments: Vec<NativeCallArgument>,
    pub effects: super::kuna_physicalinputs::ExecutionCallEffects,
}

/// Do not use NZMask here: a locked source BOOL can itself force that mask to 1.
fn native_boolean_proven(fd: &Funcdata, vn: VarnodeId, active: &mut Vec<VarnodeId>, remaining: &mut usize) -> bool {
    if *remaining == 0 || active.len() >= 64 || active.contains(&vn) { return false; }
    *remaining -= 1;
    let Some(value) = fd.vbank().get(vn) else { return false };
    if value.is_constant() { return value.get_offset() <= 1; }
    let Some(operation) = value.get_def().and_then(|op| fd.obank().get(op)) else { return false };
    active.push(vn);
    let mut input = |slot| operation.get_in(slot)
        .is_some_and(|input| native_boolean_proven(fd, input, active, remaining));
    let result = match operation.code() {
        OpCode::CPUI_INT_EQUAL | OpCode::CPUI_INT_NOTEQUAL | OpCode::CPUI_INT_LESS
        | OpCode::CPUI_INT_LESSEQUAL | OpCode::CPUI_INT_SLESS | OpCode::CPUI_INT_SLESSEQUAL
        | OpCode::CPUI_INT_CARRY | OpCode::CPUI_INT_SCARRY | OpCode::CPUI_INT_SBORROW
        | OpCode::CPUI_FLOAT_EQUAL | OpCode::CPUI_FLOAT_NOTEQUAL | OpCode::CPUI_FLOAT_LESS
        | OpCode::CPUI_FLOAT_LESSEQUAL | OpCode::CPUI_FLOAT_NAN => true,
        OpCode::CPUI_COPY | OpCode::CPUI_CAST | OpCode::CPUI_INT_ZEXT | OpCode::CPUI_INT_SEXT
        | OpCode::CPUI_SUBPIECE | OpCode::CPUI_BOOL_NEGATE => input(0),
        OpCode::CPUI_INT_AND | OpCode::CPUI_BOOL_AND => input(0) || input(1),
        OpCode::CPUI_INT_OR | OpCode::CPUI_INT_XOR | OpCode::CPUI_BOOL_OR | OpCode::CPUI_BOOL_XOR =>
            input(0) && input(1),
        OpCode::CPUI_MULTIEQUAL => operation.num_input() > 0 && (0..operation.num_input()).all(&mut input),
        _ => false,
    };
    active.pop();
    result
}

/// A statically named/addressed target belongs to generated-body publication,
/// not the premise for an unresolved native pointer loaded at runtime.
fn native_target_has_static_address(fd: &Funcdata, vn: VarnodeId, active: &mut Vec<VarnodeId>, remaining: &mut usize) -> bool {
    if *remaining == 0 || active.len() >= 64 { return true; }
    *remaining -= 1;
    if active.contains(&vn) { return false; }
    let Some(value) = fd.vbank().get(vn) else { return true };
    if value.is_constant() { return true; }
    if value.get_high().and_then(|id| fd.high_bank().get(id)).and_then(|high| high.kuna_symbol_type())
        .is_some_and(|ty| ty.get_metatype() == type_metatype::TYPE_CODE) { return true; }
    let Some(operation) = value.get_def().and_then(|op| fd.obank().get(op)) else { return false };
    if matches!(operation.code(), OpCode::CPUI_LOAD | OpCode::CPUI_CALL | OpCode::CPUI_CALLIND | OpCode::CPUI_CALLOTHER) {
        return false;
    }
    active.push(vn);
    let inputs = if matches!(operation.code(), OpCode::CPUI_COPY | OpCode::CPUI_CAST
        | OpCode::CPUI_INT_ZEXT | OpCode::CPUI_INT_SEXT | OpCode::CPUI_SUBPIECE | OpCode::CPUI_INDIRECT) {
        1
    } else { operation.num_input() };
    let result = (0..inputs).any(|slot| operation.get_in(slot)
        .is_none_or(|input| native_target_has_static_address(fd, input, active, remaining)));
    active.pop();
    result
}

/// Exact request-local ABI identity; names are not ABI and inference is not authority.
pub(crate) fn native_source_abi_equal(left: &FuncProto, right: &FuncProto) -> bool {
    if left.has_store() != right.has_store() || left.has_model() != right.has_model()
        || left.is_input_locked() != right.is_input_locked()
        || left.is_output_locked() != right.is_output_locked()
        || left.is_model_locked() != right.is_model_locked()
        || left.is_override() != right.is_override()
        || left.has_custom_storage() != right.has_custom_storage()
        || left.is_dotdotdot() != right.is_dotdotdot()
        || left.get_abi_first_vararg() != right.get_abi_first_vararg()
        || left.logical_callable() != right.logical_callable()
        || left.callable_input_origins() != right.callable_input_origins()
        || left.get_extra_pop() != right.get_extra_pop()
        || left.is_inline() != right.is_inline() || left.is_no_return() != right.is_no_return()
        || left.get_inject_id() != right.get_inject_id()
        || left.has_this_pointer() != right.has_this_pointer()
        || left.is_constructor() != right.is_constructor() || left.is_destructor() != right.is_destructor()
        || left.has_input_errors() != right.has_input_errors() || left.has_output_errors() != right.has_output_errors()
        || left.effect_list() != right.effect_list()
        || left.has_execution_signature() || right.has_execution_signature() { return false; }
    if left.has_model() && (!Rc::ptr_eq(left.model(), right.model())
        || left.trash_list() != right.trash_list()
        || left.internal_list() != right.internal_list()) { return false; }
    fn equal(a: &dyn crate::fspec::ProtoParameter, b: &dyn crate::fspec::ProtoParameter) -> bool {
        crate::fspec::proto_parameter_eq(a, b) && a.get_size() == b.get_size() && a.get_flags() == b.get_flags()
    }
    if !left.has_store() { return true; }
    left.num_params() == right.num_params() && equal(left.get_output(), right.get_output())
        && (0..left.num_params()).all(|slot| left.get_param(slot).zip(right.get_param(slot))
            .is_some_and(|(a, b)| equal(a, b)))
}

fn native_inferred_inputs(proto: &FuncProto) -> bool {
    proto.logical_callable().is_none() && !proto.is_input_locked() && !proto.is_override()
}

fn native_arguments(fd: &Funcdata, call: &crate::fspec::FuncCallSpecs) -> Option<Vec<NativeCallArgument>> {
    let operation = fd.obank().get(call.get_op())?;
    let count = operation.num_input().checked_sub(1)?;
    let proto = call.proto();
    let inferred = native_inferred_inputs(proto);
    if !inferred && count < proto.num_params() { return None; }
    if let Some(code) = proto.logical_callable() {
        let view = code.read();
        let id = view.resolve_alias(code.id()).ok()?;
        let declaration = view.get_code_prototype(id).ok()??;
        if proto.callable_input_origins().len() != proto.num_params() as usize
            || (!declaration.variadic && declaration.input_closed && count != proto.num_params()) {
            return None;
        }
    } else if !inferred && count > proto.num_params() && !proto.is_dotdotdot() { return None; }
    let recovered = call.final_input_storage();
    let mut arguments = Vec::with_capacity(count as usize);
    for slot in 0..count {
        let input = operation.get_in(slot + 1).and_then(|input| fd.vbank().get(input))?;
        let (address, size, datatype) = if let Some(parameter) = proto.get_param(slot).filter(|_| !inferred) {
            (parameter.get_address(), parameter.get_size(), parameter.get_type()?.clone())
        } else {
            if recovered.len() != count as usize { return None; }
            let (address, size) = &recovered[slot as usize];
            (address.clone(), *size, input.get_type_read_facing(call.get_op()).clone())
        };
        if size <= 0 || input.get_size() != size || datatype.get_size() != size { return None; }
        if datatype.get_metatype() == type_metatype::TYPE_BOOL
            && !operation.get_in(slot + 1).is_some_and(|vn| native_boolean_proven(fd, vn, &mut Vec::new(), &mut 256)) {
            return None;
        }
        arguments.push(NativeCallArgument { address, size, datatype });
    }
    for physical in call.physical_inputs() {
        let slot = usize::try_from(physical.operand_slot.checked_sub(1)?).ok()?;
        let argument = arguments.get(slot)?;
        if physical.address != argument.address || physical.size != argument.size { return None; }
    }
    Some(arguments)
}

fn native_default_model(proto: &FuncProto, fd: &Funcdata) -> bool {
    proto.has_store() && proto.has_model() && !proto.has_execution_signature()
        && !proto.is_inline() && !proto.is_no_return() && proto.get_inject_id() < 0
        && !proto.has_input_errors() && !proto.has_output_errors()
        && fd.get_arch().default_fp().is_some_and(|model|
            (Rc::ptr_eq(proto.model(), model)
                || (proto.model().is_unknown() && !proto.model().print_in_decl()
                    && proto.model().is_compatible(model)))
            && proto.get_extra_pop() != crate::fspec::EXTRAPOP_UNKNOWN
            && proto.get_extra_pop() == model.get_extra_pop()
            && proto.effect_list() == model.effect_list()
            && proto.trash_list() == model.trash_list())
}

/// Compare concrete site slots against the native declaration's logical prefix
/// and actual variadic tail, assigning through the emitted default C ABI only.
fn native_layout_matches(fd: &Funcdata, site: &FuncProto, declaration: &FuncProto,
    arguments: &[NativeCallArgument]) -> KunaResult<bool>
{
    if !native_default_model(site, fd) || !native_default_model(declaration, fd) { return Ok(false); }
    let Some(types) = fd.get_arch().types() else { return Ok(false) };
    let prefix = declaration.num_params() as usize;
    let (output, mut inputs, first, open) = if let Some(code) = declaration.logical_callable() {
        let logical = {
            let view = code.read();
            let id = view.resolve_alias(code.id())?;
            let Some(logical) = view.get_code_prototype(id)? else { return Ok(false) };
            logical.clone()
        };
        (code.related(logical.output)?, logical.inputs.iter().map(|id| code.related(*id))
            .collect::<KunaResult<Vec<_>>>()?, logical.logical_first.unwrap_or(-1),
            logical.variadic || !logical.input_closed)
    } else {
        if declaration.get_output().is_indirect_storage()
            || (0..declaration.num_params()).any(|slot| declaration.get_param(slot)
                .is_none_or(|parameter| parameter.is_hidden_return() || parameter.is_indirect_storage())) {
            return Ok(false);
        }
        let Some(output) = declaration.get_output_type().cloned() else { return Ok(false) };
        let inputs = (0..declaration.num_params()).map(|slot| declaration.get_param(slot)
            .and_then(|parameter| parameter.get_type()).cloned())
            .collect::<Option<Vec<_>>>();
        let Some(inputs) = inputs else { return Ok(false) };
        (output, inputs, if declaration.is_dotdotdot() {
            declaration.get_abi_first_vararg().unwrap_or(declaration.num_params())
        } else { -1 }, declaration.is_dotdotdot())
    };
    if arguments.len() < prefix || (!open && arguments.len() != prefix) { return Ok(false); }
    for argument in &arguments[prefix..] {
        // The CALL must already contain C's concrete default promotions. A
        // nominal byte/float tail is not evidence for the promoted native bits.
        let kind = argument.datatype.get_metatype();
        if (scalar(&argument.datatype) && argument.size < 4)
            || (kind == type_metatype::TYPE_FLOAT && argument.size < 8) { return Ok(false); }
        inputs.push(argument.datatype.clone());
    }
    let pieces = crate::fspec::PrototypePieces {
        outtype: Some(output), intypes: inputs,
        first_var_arg_slot: if open && first < 0 { 0 } else { first },
        ..Default::default()
    };
    let mut assigned = Vec::new();
    let model = fd.get_arch().default_fp().expect("validated default model");
    model.assign_parameter_storage(&pieces, &mut assigned, false, types, fd.get_arch().manage())?;
    if assigned.len() != arguments.len() + 1 { return Ok(false); }
    let result = site.get_output();
    let output = &assigned[0];
    if result.get_address() != output.addr || result.get_type() != output.type_.as_ref()
        || result.is_indirect_storage()
            != (output.flags & crate::fspec::parameter_pieces_flags::INDIRECTSTORAGE != 0) { return Ok(false); }
    for (slot, (argument, expected)) in arguments.iter().zip(&assigned[1..]).enumerate() {
        if argument.address != expected.addr || expected.type_.as_ref() != Some(&argument.datatype) {
            return Ok(false);
        }
        if let Some(parameter) = site.get_param(slot as int4).filter(|_| !native_inferred_inputs(site)) {
            if parameter.is_hidden_return()
                != (expected.flags & crate::fspec::parameter_pieces_flags::HIDDENRETPARM != 0)
                || parameter.is_indirect_storage()
                    != (expected.flags & crate::fspec::parameter_pieces_flags::INDIRECTSTORAGE != 0) { return Ok(false); }
        }
    }
    Ok(true)
}

fn native_reads_fit(raw: &EntryRequirements, arguments: &[NativeCallArgument]) -> bool {
    raw.reads.iter().all(|(address, size)| {
        if *size <= 0 { return false; }
        let Some(end) = address.get_offset().checked_add(*size as u64) else { return false };
        let mut cursor = address.get_offset();
        while cursor < end {
            let mut covered = cursor;
            let mut cover = |at: &Address, bytes: int4| {
                if bytes > 0 && at.get_space().zip(address.get_space()).is_some_and(|(a, b)| Rc::ptr_eq(a, b))
                    && at.get_offset() <= cursor {
                    covered = covered.max(at.get_offset().saturating_add(bytes as u64));
                }
            };
            for argument in arguments { cover(&argument.address, argument.size); }
            for (address, size) in &raw.bookkeeping { cover(address, *size); }
            if covered <= cursor { return false; }
            cursor = covered.min(end);
        }
        true
    })
}

/// Execution effects use real storage, never the synthetic JOIN address. In
/// particular, frame escape observes each component of an aggregate argument.
fn append_effect_input(inputs: &mut Vec<(Address, int4)>, address: Address, size: int4,
    manager: &AddrSpaceManager) -> KunaResult<()>
{
    if address.get_space().is_some_and(|space| space.get_type() == kuna_base::space::spacetype::IPTR_JOIN) {
        let join = manager.find_join(address.get_offset())?;
        for index in 0..join.num_pieces() {
            let piece = join.get_piece(index);
            let space = piece.space.as_ref()
                .ok_or_else(|| KunaError::lowlevel("Execution argument JOIN has no physical space"))?;
            let size = int4::try_from(piece.size).ok().filter(|size| *size > 0)
                .ok_or_else(|| KunaError::lowlevel("Execution argument JOIN has invalid piece size"))?;
            if space.get_type() == kuna_base::space::spacetype::IPTR_JOIN {
                return Err(KunaError::lowlevel("Execution argument JOIN has synthetic piece storage"));
            }
            inputs.push((Address::new(space.clone(), piece.offset), size));
        }
    } else { inputs.push((address, size)); }
    Ok(())
}

/// `body_unavailable` is issued only by this drive's exact missing-image probe;
/// incomplete decode, recursion, or a budget cut cannot issue it.
pub(crate) fn native_call_contract(fd: &Funcdata, op: OpId, body_unavailable: bool)
    -> KunaResult<Option<NativeCallContract>>
{
    let Some(operation) = fd.obank().get(op).filter(|operation| !operation.is_dead()
        && matches!(operation.code(), OpCode::CPUI_CALL | OpCode::CPUI_CALLIND)) else { return Ok(None) };
    let Some(index) = fd.get_call_specs_index(op) else { return Ok(None) };
    let call = fd.get_call_specs(index);
    if call.execution_callable().is_some() { return Ok(None); }
    if !native_default_model(call.proto(), fd) { return Ok(None); }
    if raw_boundary(fd, op)? { return Ok(None); }
    let Some(arguments) = native_arguments(fd, call) else { return Ok(None) };
    if operation.code() == OpCode::CPUI_CALLIND
        && operation.get_in(0).is_none_or(|input| native_target_has_static_address(fd, input, &mut Vec::new(), &mut 256)) {
        return Ok(None);
    }
    for slot in 0..operation.num_input() {
        if operation.code() == OpCode::CPUI_CALL && slot == 0 { continue; }
        let Some(input) = operation.get_in(slot) else { return Ok(None) };
        if normalized_family(fd, input, &mut Vec::new())?.is_some_and(|proof| proof.transformed) { return Ok(None); }
    }
    let (target, declaration) = if operation.code() == OpCode::CPUI_CALL {
        if !body_unavailable || call.get_entry_address().is_invalid() { return Ok(None); }
        let Some((_, entry, declaration)) = fd.get_arch().query_function(call.get_entry_address())? else { return Ok(None) };
        if entry != *call.get_entry_address() { return Ok(None); }
        let declaration = Rc::new(declaration.source_prototype());
        (NativeTargetContract::Direct { entry, declaration: declaration.clone() }, declaration)
    } else {
        let Some(input) = operation.get_in(0).and_then(|input| fd.vbank().get(input)) else { return Ok(None) };
        let Some(code) = input.get_type_read_facing(op).get_ptr_to()
            .filter(|code| code.get_metatype() == type_metatype::TYPE_CODE) else { return Ok(None) };
        let Some(types) = fd.get_arch().types() else { return Ok(None) };
        let Some(abi) = crate::fspec::materialize_callable(types, &code)? else { return Ok(None) };
        (NativeTargetContract::Indirect { pointer_code: code }, abi.prototype().clone())
    };
    if !native_layout_matches(fd, call.proto(), &declaration, &arguments)? {
        return Ok(None);
    }
    // Only the assigned implicit ABI result pointer denotes a bounded return
    // object. An explicit source pointer remains an ordinary escaping argument.
    let mut hidden_result = None;
    for slot in 0..call.proto().num_params() {
        let parameter = call.proto().get_param(slot).expect("native source slot");
        if !parameter.is_hidden_return() { continue; }
        if hidden_result.is_some() || !call.proto().get_output().is_indirect_storage() { return Ok(None); }
        let Some(code) = call.proto().logical_callable() else { return Ok(None) };
        let output = {
            let view = code.read();
            let id = view.resolve_alias(code.id())?;
            let Some(logical) = view.get_code_prototype(id)? else { return Ok(None) };
            logical.output
        };
        let output = code.related(output)?;
        let Some(argument) = arguments.get(slot as usize) else { return Ok(None) };
        if output.get_size() <= 0 || argument.datatype.get_ptr_to().as_ref() != Some(&output) {
            return Ok(None);
        }
        hidden_result = Some(super::kuna_physicalinputs::ExecutionIndirectResult {
            address: argument.address.clone(), pointer_size: argument.size, value_size: output.get_size(),
        });
    }
    if let Some(raw) = call.physical_requirements() {
        if !native_reads_fit(raw, &arguments)
            || !preservation_fits(call.proto(), call.proto(), raw, None, &[], false, fd.get_arch().manage()) { return Ok(None); }
    }
    let mut outputs = Vec::new();
    let result = call.proto().get_output();
    if result.get_type().is_some_and(|ty| ty.get_metatype() != type_metatype::TYPE_VOID) {
        let address = result.get_address();
        if address.get_space().is_some_and(|space| space.get_type() == kuna_base::space::spacetype::IPTR_JOIN) {
            let join = fd.get_arch().manage().find_join(address.get_offset())?;
            for index in 0..join.num_pieces() {
                let piece = join.get_piece(index);
                let Some(space) = piece.space.as_ref() else { return Ok(None) };
                outputs.push((Address::new(space.clone(), piece.offset), piece.size as int4));
            }
        } else if result.get_size() > 0 { outputs.push((address, result.get_size())); }
    }
    let mut inputs = Vec::with_capacity(arguments.len());
    for argument in &arguments {
        append_effect_input(&mut inputs, argument.address.clone(), argument.size, fd.get_arch().manage())?;
    }
    let effects = super::kuna_physicalinputs::ExecutionCallEffects {
        inputs,
        outputs,
        hidden_result,
        preserved: call.proto().effect_list().iter()
            .filter(|effect| effect.get_type() == crate::fspec::effect_type::UNAFFECTED)
            .map(|effect| (effect.get_address().clone(), effect.get_size())).collect(),
        stack_adjustment: stack_adjustment(call.proto(), false),
    };
    Ok(Some(NativeCallContract {
        prototype: Rc::new(call.proto().source_prototype()), target, arguments, effects,
    }))
}

/// Semantic bytes written by a genuine native C value return. This is not a
/// source-pointer write promise: the caller must separately prove the assigned
/// implicit destination, private frame interval, and exact current call replay.
/// Padding and unmodeled value representations cannot define memory here.
pub(crate) fn native_hidden_value_size(expected: &NativeCallContract) -> KunaResult<Option<int4>> {
    let Some(hidden) = &expected.effects.hidden_result else { return Ok(None); };
    let proto = &expected.prototype;
    if !proto.has_store() || !proto.get_output().is_indirect_storage() { return Ok(None); }
    let Some(code) = proto.logical_callable() else { return Ok(None); };
    let output = {
        let view = code.read();
        let id = view.resolve_alias(code.id())?;
        let Some(logical) = view.get_code_prototype(id)? else { return Ok(None); };
        logical.output
    };
    let output = code.related(output)?;
    if output.get_size() != hidden.value_size { return Ok(None); }
    let mut slots = (0..proto.num_params()).filter(|slot| proto.get_param(*slot)
        .is_some_and(|parameter| parameter.is_hidden_return()));
    let Some(slot) = slots.next() else { return Ok(None); };
    if slots.next().is_some() { return Ok(None); }
    let parameter = proto.get_param(slot).expect("validated hidden result slot");
    let Some(argument) = expected.arguments.get(slot as usize) else { return Ok(None); };
    if parameter.get_address() != hidden.address || parameter.get_size() != hidden.pointer_size
        || argument.address != hidden.address || argument.size != hidden.pointer_size
        || parameter.get_type() != Some(&argument.datatype)
        || argument.datatype.get_ptr_to().as_ref() != Some(&output)
        || super::kuna_logicalresultbody::result_layout(&output)?.is_none() { return Ok(None); }
    Ok(Some(hidden.value_size))
}

pub(crate) fn native_contract_matches(fd: &Funcdata, op: OpId, expected: &NativeCallContract) -> KunaResult<bool> {
    let Some(operation) = fd.obank().get(op).filter(|operation| !operation.is_dead()) else { return Ok(false) };
    let Some(index) = fd.get_call_specs_index(op) else { return Ok(false) };
    let call = fd.get_call_specs(index);
    if call.execution_callable().is_some() || !native_default_model(call.proto(), fd)
        || !native_source_abi_equal(call.proto(), &expected.prototype)
        || operation.num_input() != expected.arguments.len() as int4 + 1
        || raw_boundary(fd, op)? { return Ok(false); }
    if let Some(result) = &expected.effects.hidden_result {
        let Some(code) = call.proto().logical_callable() else { return Ok(false) };
        let output = {
            let view = code.read();
            let id = view.resolve_alias(code.id())?;
            let Some(logical) = view.get_code_prototype(id)? else { return Ok(false) };
            logical.output
        };
        if code.related(output)?.get_size() != result.value_size { return Ok(false); }
    }
    for (slot, argument) in expected.arguments.iter().enumerate() {
        let Some(input) = operation.get_in(slot as int4 + 1).and_then(|input| fd.vbank().get(input)) else { return Ok(false) };
        if input.get_size() != argument.size
            || (argument.datatype.get_metatype() == type_metatype::TYPE_BOOL
                && !operation.get_in(slot as int4 + 1).is_some_and(|vn| native_boolean_proven(fd, vn, &mut Vec::new(), &mut 256))) {
            return Ok(false);
        }
        if let Some(parameter) = call.proto().get_param(slot as int4).filter(|_| !native_inferred_inputs(call.proto())) {
            if parameter.get_address() != argument.address || parameter.get_size() != argument.size
                || parameter.get_type() != Some(&argument.datatype) { return Ok(false); }
        } else {
            if call.final_input_storage().len() != expected.arguments.len()
                || call.final_input_storage().get(slot)
                    .is_none_or(|(address, size)| address != &argument.address || *size != argument.size)
                || input.get_type_read_facing(op) != &argument.datatype { return Ok(false); }
        }
    }
    for physical in call.physical_inputs() {
        let Some(argument) = physical.operand_slot.checked_sub(1).and_then(|slot| usize::try_from(slot).ok())
            .and_then(|slot| expected.arguments.get(slot)) else { return Ok(false) };
        if physical.address != argument.address || physical.size != argument.size { return Ok(false); }
    }
    for slot in 0..operation.num_input() {
        if operation.code() == OpCode::CPUI_CALL && slot == 0 { continue; }
        let Some(input) = operation.get_in(slot) else { return Ok(false) };
        if normalized_family(fd, input, &mut Vec::new())?.is_some_and(|proof| proof.transformed) { return Ok(false); }
    }
    if let Some(raw) = call.physical_requirements() {
        if !native_reads_fit(raw, &expected.arguments)
            || !preservation_fits(call.proto(), call.proto(), raw, None, &[], false, fd.get_arch().manage()) { return Ok(false); }
    }
    match &expected.target {
        NativeTargetContract::Direct { entry, declaration } => {
            if operation.code() != OpCode::CPUI_CALL || call.get_entry_address() != entry { return Ok(false); }
            let Some((_, actual_entry, actual)) = fd.get_arch().query_function(entry)? else { return Ok(false) };
            Ok(actual_entry == *entry && native_source_abi_equal(&actual, declaration))
        }
        NativeTargetContract::Indirect { pointer_code } => {
            if operation.code() != OpCode::CPUI_CALLIND { return Ok(false); }
            if operation.get_in(0).is_none_or(|input|
                native_target_has_static_address(fd, input, &mut Vec::new(), &mut 256)) { return Ok(false); }
            Ok(operation.get_in(0).and_then(|input| fd.vbank().get(input))
                .and_then(|input| input.get_type_read_facing(op).get_ptr_to()).as_ref() == Some(pointer_code))
        }
    }
}

/// A conditional generated-execution contract, never a raw-machine summary.
/// The final body must discharge each retained site against SSA producer proof.
#[derive(Clone)]
pub struct RawIndirectContract {
    pub effects: super::kuna_physicalinputs::ExecutionCallEffects,
    pub family: TypeRoot,
}

fn refined_family_contract(fd: &Funcdata, code: &TypeRoot) -> KunaResult<Option<RawIndirectContract>> {
    let Some(types) = fd.get_arch().types() else { return Ok(None); };
    let Some(abi) = crate::fspec::materialize_callable(types, code)? else { return Ok(None); };
    let family = abi.prototype();
    if !adapter_supported(family) || family.is_dotdotdot() || family.get_output().is_indirect_storage()
        || callable_type(family, types)? != *code { return Ok(None); }
    let mut inputs = Vec::with_capacity(family.num_params() as usize);
    for slot in 0..family.num_params() {
        let parameter = family.get_param(slot).expect("refined family input");
        if parameter.get_size() <= 0 || parameter.get_address().is_invalid() { return Ok(None); }
        append_effect_input(&mut inputs, parameter.get_address(), parameter.get_size(), fd.get_arch().manage())?;
    }
    let mut outputs = Vec::new();
    let output = family.get_output();
    if output.get_size() > 0 && output.get_type().is_some_and(|ty| ty.get_metatype() != type_metatype::TYPE_VOID) {
        append_effect_input(&mut outputs, output.get_address(), output.get_size(), fd.get_arch().manage())?;
    }
    let effects = super::kuna_physicalinputs::ExecutionCallEffects {
        inputs, outputs, hidden_result: None,
        preserved: family.effect_list().iter().filter(|effect| effect.get_type() == crate::fspec::effect_type::UNAFFECTED)
            .map(|effect| (effect.get_address(), effect.get_size())).collect(),
        stack_adjustment: stack_adjustment(family, fd.get_arch().callee_proto_stack),
    };
    if effects.stack_adjustment.is_none() { return Ok(None); }
    Ok(Some(RawIndirectContract { effects, family: code.clone() }))
}

/// Refine an actual representation producer, not a nominal callable type. This
/// has no finite target/raw-child set and cannot retire hidden destination aliases.
pub(crate) fn refined_indirect_contract(fd: &Funcdata, op: OpId) -> KunaResult<Option<RawIndirectContract>> {
    let Some(operation) = fd.obank().get(op).filter(|operation| !operation.is_dead()
        && operation.code() == OpCode::CPUI_CALLIND) else { return Ok(None); };
    let Some(input) = operation.get_in(0) else { return Ok(None); };
    let Some(proof) = normalized_family(fd, input, &mut Vec::new())? else { return Ok(None); };
    if !proof.transformed { return Ok(None); }
    let Some(index) = fd.get_call_specs_index(op) else { return Ok(None); };
    let call = fd.get_call_specs(index);
    let Some(types) = fd.get_arch().types() else { return Ok(None); };
    if !call.proto().has_store() || !call.proto().has_model() || !adapter_supported(call.proto())
        || family_identity(call.proto(), types)? != proof.family { return Ok(None); }
    refined_family_contract(fd, &proof.family.code)
}

/// Core has already authenticated the original raw fingerprint/source. Rebind
/// only the retained immutable family; final SSA must prove its producer again.
pub(crate) fn rebind_refined_indirect_contract(fd: &Funcdata, _op: OpId, retained: &RawIndirectContract)
    -> KunaResult<bool>
{
    fn storage_matches(fd: &Funcdata, actual: &Address, bytes: int4,
        expected: &[(Address, int4)], cursor: &mut usize) -> KunaResult<bool>
    {
        if bytes <= 0 || actual.is_invalid() { return Ok(false); }
        if actual.get_space().is_some_and(|space| space.get_type() == kuna_base::space::spacetype::IPTR_JOIN) {
            let join = fd.get_arch().manage().find_join(actual.get_offset())?;
            for index in 0..join.num_pieces() {
                let piece = join.get_piece(index);
                let Some(space) = piece.space.as_ref() else { return Ok(false); };
                let Some((at, size)) = expected.get(*cursor) else { return Ok(false); };
                if at.get_offset() != piece.offset || *size != piece.size as int4
                    || at.get_space().is_none_or(|other| !Rc::ptr_eq(space, other)) { return Ok(false); }
                *cursor += 1;
            }
        } else {
            if expected.get(*cursor).is_none_or(|(at, size)| at != actual || *size != bytes) { return Ok(false); }
            *cursor += 1;
        }
        Ok(true)
    }
    let Some(types) = fd.get_arch().types() else { return Ok(false); };
    let Some(abi) = crate::fspec::materialize_callable(types, &retained.family)? else { return Ok(false); };
    let family = abi.prototype();
    if !adapter_supported(family) || family.is_dotdotdot() || family.get_output().is_indirect_storage()
        || callable_type(family, types)? != retained.family || retained.effects.hidden_result.is_some()
        || stack_adjustment(family, fd.get_arch().callee_proto_stack) != retained.effects.stack_adjustment { return Ok(false); }
    let mut cursor = 0;
    for slot in 0..family.num_params() {
        let parameter = family.get_param(slot).expect("refined replay formal");
        if !storage_matches(fd, &parameter.get_address(), parameter.get_size(), &retained.effects.inputs, &mut cursor)? { return Ok(false); }
    }
    if cursor != retained.effects.inputs.len() { return Ok(false); }
    cursor = 0;
    let output = family.get_output();
    if output.get_size() > 0 && output.get_type().is_some_and(|ty| ty.get_metatype() != type_metatype::TYPE_VOID)
        && !storage_matches(fd, &output.get_address(), output.get_size(), &retained.effects.outputs, &mut cursor)? { return Ok(false); }
    if cursor != retained.effects.outputs.len() { return Ok(false); }
    let mut expected = retained.effects.preserved.iter();
    for effect in family.effect_list().iter().filter(|effect| effect.get_type() == crate::fspec::effect_type::UNAFFECTED) {
        if expected.next().is_none_or(|(at, size)| *at != effect.get_address() || *size != effect.get_size()) { return Ok(false); }
    }
    Ok(expected.next().is_none())
}

pub fn raw_indirect_contracts(
    fd: &Funcdata, flow: Option<&super::kuna_physicalinputs::ConditionalFlowView>,
) -> KunaResult<BTreeMap<OpId, RawIndirectContract>> {
    type Storage = (int4, u64, int4);
    type State = BTreeMap<Storage, usize>;
    fn storage(fd: &Funcdata, vn: VarnodeId) -> Option<Storage> {
        let value = fd.vbank().get(vn)?;
        if value.is_constant() { return None; }
        Some((value.get_addr().get_space()?.get_index(), value.get_offset(), value.get_size()))
    }
    fn transfer(fd: &Funcdata, op: OpId, state: &mut State) {
        let operation = fd.obank().get(op).expect("raw callable operation");
        let output = operation.get_out().and_then(|vn| storage(fd, vn));
        let copied = if matches!(operation.code(), OpCode::CPUI_COPY | OpCode::CPUI_CAST) {
            operation.get_in(0).and_then(|vn| storage(fd, vn)).filter(|input|
                output.is_some_and(|output| input.2 == output.2)).and_then(|input| state.get(&input).copied())
        } else { None };
        // Unknown machine calls may overwrite any retained carrier. Do not infer
        // a returned family from a nominal type or a caller-save convention.
        if matches!(operation.code(), OpCode::CPUI_CALL | OpCode::CPUI_CALLIND | OpCode::CPUI_CALLOTHER) {
            state.clear();
        }
        if operation.code() == OpCode::CPUI_STORE {
            let space = operation.get_in(0).and_then(|vn| fd.vbank().get(vn))
                .filter(|vn| vn.is_constant()).and_then(|vn| int4::try_from(vn.get_offset()).ok())
                .and_then(|index| fd.get_arch().manage().get_space(index));
            if space.is_none_or(|space| space.get_name() == "register") { state.clear(); }
        }
        if let Some(output) = output {
            state.retain(|input, _| input.0 != output.0
                || input.1.saturating_add(input.2 as u64) <= output.1
                || output.1.saturating_add(output.2 as u64) <= input.1);
            if let Some(family) = copied { state.insert(output, family); }
        }
    }
    let mut result = BTreeMap::new();
    if !fd.get_arch().execution_callable_c || !fd.get_func_proto().has_store() { return Ok(result); }
    if !fd.obank().iter_alive().any(|id| flow.is_none_or(|view| view.op_reachable(fd, id))
        && fd.obank().get(id).is_some_and(|op| op.code() == OpCode::CPUI_CALLIND)) { return Ok(result); }
    let Some(types) = fd.get_arch().types() else { return Ok(result) };
    let source = fd.get_func_proto().source_prototype();
    let mut seed = State::new();
    let mut contracts = Vec::new();
    for slot in 0..source.num_params() {
        let parameter = source.get_param(slot).expect("source formal");
        let Some(original) = parameter.get_type() else { continue };
        let normalized = normalize_type(original, fd.get_arch().manage(), types)?;
        if normalized == *original { continue; }
        let Some(code) = normalized.get_ptr_to().filter(|code| code.get_metatype() == type_metatype::TYPE_CODE) else { continue };
        let Some(abi) = crate::fspec::materialize_callable(types, &code)? else { continue };
        let family = abi.prototype();
        if !adapter_supported(family) { continue; }
        let address = parameter.get_address();
        let Some(space) = address.get_space().filter(|space| space.get_name() == "register") else { continue };
        let output = family.get_output();
        let output = if output.get_size() == 0
            || output.get_type().is_some_and(|ty| ty.get_metatype() == type_metatype::TYPE_VOID)
        { None } else {
            let address = output.get_address();
            if address.get_space().is_none_or(|space| space.get_name() != "register") { continue; }
            Some((address, output.get_size()))
        };
        let mut inputs = Vec::with_capacity(family.num_params() as usize);
        for slot in 0..family.num_params() {
            let input = family.get_param(slot).expect("family formal");
            append_effect_input(&mut inputs, input.get_address(), input.get_size(), fd.get_arch().manage())?;
        }
        seed.insert((space.get_index(), address.get_offset(), parameter.get_size()), contracts.len());
        contracts.push(RawIndirectContract {
            effects: super::kuna_physicalinputs::ExecutionCallEffects {
                inputs,
                outputs: output.into_iter().collect(),
                hidden_result: None,
                preserved: family.effect_list().iter().filter(|effect|
                    effect.get_type() == crate::fspec::effect_type::UNAFFECTED
                        && effect.get_address().get_space().is_some_and(|space| space.get_name() == "register"))
                    .map(|effect| (effect.get_address(), effect.get_size())).collect(),
                stack_adjustment: stack_adjustment(family, fd.get_arch().callee_proto_stack),
            },
            family: callable_type(family, types)?,
        });
    }
    if seed.is_empty() { return Ok(result); }
    let blocks: Vec<_> = (0..fd.bblocks_get_size()).map(|index| fd.bblocks_get_block(index)).collect();
    let positions: BTreeMap<_, _> = blocks.iter().enumerate().map(|(index, block)| (*block, index)).collect();
    if blocks.is_empty() { return Ok(result); }
    let mut reachable = vec![false; blocks.len()];
    let mut work = vec![0usize];
    while let Some(index) = work.pop() {
        if reachable[index] || flow.is_some_and(|view| !view.block_reachable(blocks[index])) { continue; }
        reachable[index] = true;
        let block = fd.bblocks_ref().block(blocks[index]);
        for edge in 0..block.size_out() {
            if flow.is_some_and(|view| !view.edge_allowed(blocks[index], edge)) { continue; }
            if let Some(next) = positions.get(&block.get_out(edge)) { work.push(*next); }
        }
    }
    let operations: Vec<Vec<_>> = blocks.iter().map(|block| {
        let mut ops = Vec::new();
        let mut op = match fd.bblocks_ref().block(*block).kind() {
            crate::block::BlockKind::Basic(data) => data.op_head,
            _ => None,
        };
        while let Some(id) = op {
            if flow.is_none_or(|view| view.op_reachable(fd, id)) { ops.push(id); }
            op = fd.obank().get(id).expect("raw block operation").basic_neighbours().1;
        }
        ops
    }).collect();
    let mut outgoing = vec![State::new(); blocks.len()];
    let mut incoming = vec![State::new(); blocks.len()];
    loop {
        let mut changed = false;
        for index in 0..blocks.len() {
            if !reachable[index] { continue; }
            let mut state = if index == 0 { seed.clone() } else { State::new() };
            {
                let block = fd.bblocks_ref().block(blocks[index]);
                let mut first = index != 0;
                for edge in 0..block.size_in() {
                    let Some(previous) = positions.get(&block.get_in(edge)).copied() else { continue };
                    if !reachable[previous] || flow.is_some_and(|view|
                        !view.edge_allowed(blocks[previous], block.get_in_rev_index(edge))) { continue; }
                    if first { state.clone_from(&outgoing[previous]); first = false; }
                    else { state.retain(|storage, family| outgoing[previous].get(storage) == Some(family)); }
                }
            }
            incoming[index].clone_from(&state);
            for op in &operations[index] { transfer(fd, *op, &mut state); }
            if outgoing[index] != state { outgoing[index] = state; changed = true; }
        }
        if !changed { break; }
    }
    for (index, ops) in operations.iter().enumerate() {
        if !reachable[index] { continue; }
        let state = &mut incoming[index];
        for op in ops {
            let operation = fd.obank().get(*op).expect("raw callable operation");
            if operation.code() == OpCode::CPUI_CALLIND {
                if let Some(family) = operation.get_in(0).and_then(|vn| storage(fd, vn))
                    .and_then(|storage| state.get(&storage)) {
                    result.insert(*op, contracts[*family].clone());
                }
            }
            transfer(fd, *op, state);
        }
    }
    Ok(result)
}

#[derive(Clone, PartialEq, Eq)]
struct CallableFamily {
    code: TypeRoot,
    storage: Vec<(Address, int4)>,
    output: Option<(Address, int4)>,
}

/// ABI identity and representation provenance are separate facts. An unchanged
/// real target symbol keeps its native identity; a generated adapter does not.
struct ProvenCallableFamily {
    family: CallableFamily,
    transformed: bool,
}

fn family_identity(proto: &FuncProto, types: &dyn TypeFactory) -> KunaResult<CallableFamily> {
    let output = proto.get_output();
    let output = if output.get_size() == 0
        || output.get_type().is_some_and(|ty| ty.get_metatype() == type_metatype::TYPE_VOID)
    { None } else { Some((output.get_address(), output.get_size())) };
    Ok(CallableFamily {
        code: callable_type(proto, types)?,
        storage: (0..proto.num_params()).map(|slot| {
            let parameter = proto.get_param(slot).expect("family slot");
            (parameter.get_address(), parameter.get_size())
        }).collect(),
        output,
    })
}

fn family_from_pointer(ty: &TypeRoot, fd: &Funcdata) -> KunaResult<Option<CallableFamily>> {
    let Some(code) = ty.get_ptr_to() else { return Ok(None) };
    if code.get_metatype() != type_metatype::TYPE_CODE { return Ok(None); }
    {
        let view = code.read();
        let id = view.resolve_alias(code.id())?;
        if view.get_code_prototype(id)?.is_none() { return Ok(None); }
    }
    let Some(types) = fd.get_arch().types() else { return Ok(None) };
    let Some(abi) = crate::fspec::materialize_callable(types, &code)? else { return Ok(None) };
    Ok(Some(family_identity(abi.prototype(), types)?))
}

/// Select a generated direct child only with a retained exact family obligation.
pub(super) fn raw_direct_contract(fd: &Funcdata, op: OpId, child: &Rc<EntryRequirements>,
    requested_roles: &[(Address, int4)])
    -> KunaResult<Option<super::kuna_physicalinputs::DirectExecutionAssumption>>
{
    if !execution_complete(child) { return Ok(None); }
    let execution = child.execution.as_ref().filter(|execution| execution.complete).cloned();
    if execution.is_none() && requested_roles.is_empty() { return Ok(None); }
    if fd.obank().get(op).is_none_or(|operation| operation.is_dead()
        || operation.code() != OpCode::CPUI_CALL) { return Ok(None); }
    let Some(index) = fd.get_call_specs_index(op) else { return Ok(None) };
    let call = fd.get_call_specs(index);
    if call.get_entry_address().is_invalid() || !call.proto().is_input_locked()
        || !adapter_supported(call.proto()) { return Ok(None); }
    let Some(types) = fd.get_arch().types() else { return Ok(None) };
    let family = family_proto(call.proto(), Some(child), fd.get_arch().manage(), types)?;
    if !adapter_supported(&family) || !requirements_fit(&family, child, fd.get_arch().manage()) { return Ok(None); }
    if !internal_roles_fit(fd, &call.proto().source_prototype(), &family, requested_roles)? { return Ok(None); }
    let identity = family_identity(&family, types)?;
    if identity.storage.iter().any(|(address, size)| *size <= 0 || *size > 8
        || address.get_space().is_none_or(|space| space.get_name() != "register")) { return Ok(None); }
    // Raw CALL has not been linked to SSA argument operands at this checkpoint.
    // Keep the complete family storage, including arguments the child discards.
    Ok(Some(super::kuna_physicalinputs::DirectExecutionAssumption {
        op, entry: call.get_entry_address().clone(), family: identity.code,
        inputs: identity.storage, output: identity.output, raw: child.clone(), execution,
        model: family.model().clone(), effects: family.effect_list().to_vec(),
        extra_pop: family.get_extra_pop(), internal_roles: requested_roles.to_vec(),
    }))
}

fn append_internal_role_providers(fd: &Funcdata, source: &FuncProto, family: &FuncProto,
    provider: &str, body_internal: &[(Address, int4)], artifacts: &mut BTreeMap<String, CallableArtifact>)
    -> KunaResult<()>
{
    let Some(raw) = fd.entry_physical_requirements() else { return Ok(()); };
    let conditional = raw.execution.as_deref().filter(|execution| execution.complete);

    for role in source.internal_list() {
        let Some(space) = role.space.as_ref() else { continue; };
        let Ok(size) = int4::try_from(role.size) else { continue; };
        let address = Address::new(space.clone(), role.offset);
        let Some(end) = u64::try_from(size).ok().filter(|size| *size > 0)
            .and_then(|size| address.get_offset().checked_add(size)) else { continue; };
        if !internal_roles_fit(fd, source, family, &[(address.clone(), size)])? { continue; }
        // Ordinary restoration proves untouched bytes vacuously. Bytes actually
        // written must be restored, or owned by the final representation proof.
        let proven = raw.writes.iter().filter(|(at, bytes)| *bytes > 0 && at.get_offset() < end
            && at.get_space().is_some_and(|other| Rc::ptr_eq(space, other)))
            .all(|(at, bytes)| {
                let Some(limit) = at.get_offset().checked_add(*bytes as u64) else { return false; };
                let start = address.get_offset().max(at.get_offset());
                let limit = end.min(limit);
                start >= limit || ranges_cover(raw.restored.iter().chain(conditional.into_iter().flat_map(|facts| &facts.restored))
                    .chain(body_internal), &Address::new(space.clone(), start), (limit - start) as int4)
            });
        if !proven { continue; }
        let Some(concrete) = artifacts.get(provider).filter(|artifact| artifact.definition.as_ref()
            .is_some_and(|definition| !matches!(definition, CallableDefinition::BodyProof { .. }))) else { continue; };
        let declaration = concrete.declaration.clone();
        let key = internal_role_key(provider, &address, size)?;
        artifacts.insert(key.clone(), CallableArtifact { key, declaration,
            definition: Some(CallableDefinition::BodyProof { provider: provider.into() }), required: false, deferred: false });
    }
    Ok(())
}

fn selected_execution_matches(raw: &EntryRequirements,
    selected: Option<&Rc<super::kuna_physicalinputs::ExecutionRequirements>>) -> bool
{
    match (raw.execution.as_ref().filter(|execution| execution.complete), selected) {
        (Some(actual), Some(expected)) => Rc::ptr_eq(actual, expected),
        (None, None) => raw.is_complete(),
        _ => false,
    }
}

fn has_internal_role_request(fd: &Funcdata, op: OpId) -> bool {
    fd.entry_physical_requirements().and_then(|raw| raw.execution.as_ref())
        .filter(|execution| execution.complete).is_some_and(|execution|
            execution.direct_assumptions.iter().any(|expected| expected.op == op && !expected.internal_roles.is_empty()))
}

fn internal_role_key(provider: &str, address: &Address, size: int4) -> KunaResult<String> {
    let space = address.get_space().filter(|space| space.get_index() >= 0)
        .ok_or_else(|| KunaError::lowlevel("Internal role has no canonical address space"))?;
    if size <= 0 || address.get_offset().checked_add(size as u64).is_none() {
        return Err(KunaError::lowlevel("Internal role has an invalid whole range"));
    }
    Ok(format!("{provider}_internal_{}_{}_{}", space.get_index(), address.get_offset(), size))
}

fn ranges_cover<'a>(ranges: impl Iterator<Item = &'a (Address, int4)> + Clone, address: &Address, size: int4) -> bool {
    let Some(end) = u64::try_from(size).ok().filter(|size| *size > 0)
        .and_then(|size| address.get_offset().checked_add(size)) else { return false; };
    let mut cursor = address.get_offset();
    while cursor < end {
        let next = ranges.clone().filter(|(at, bytes)| *bytes > 0 && at.get_offset() <= cursor
            && at.get_space().zip(address.get_space()).is_some_and(|(a, b)| Rc::ptr_eq(a, b)))
            .filter_map(|(at, bytes)| at.get_offset().checked_add(*bytes as u64)).max().unwrap_or(cursor);
        if next <= cursor { return false; }
        cursor = next.min(end);
    }
    true
}

/// This checks an obligation's admissibility, not target restoration. The
/// stronger qualified provider must still prove the requested whole role.
fn internal_roles_fit(fd: &Funcdata, source: &FuncProto, family: &FuncProto,
    roles: &[(Address, int4)]) -> KunaResult<bool>
{
    if roles.is_empty() { return Ok(true); }
    if !source.has_store() || !source.has_model() || !family.has_store() || !family.has_model() { return Ok(false); }
    let Some(types) = fd.get_arch().types() else { return Ok(false); };
    let code = callable_type(family, types)?;
    let Some(exposed) = crate::fspec::materialize_callable(types, &code)? else { return Ok(false); };
    if !exposed.prototype().has_store() || !exposed.prototype().has_model() { return Ok(false); }
    let preserved: Vec<_> = exposed.prototype().effect_list().iter()
        .filter(|effect| effect.get_type() == crate::fspec::effect_type::UNAFFECTED)
        .map(|effect| (effect.get_address(), effect.get_size())).collect();
    let mut occupied = Vec::new();
    for proto in [source, family, exposed.prototype().as_ref()] {
        for slot in 0..proto.num_params() {
            let parameter = proto.get_param(slot).expect("role-disjoint formal");
            append_effect_input(&mut occupied, parameter.get_address(), parameter.get_size(), fd.get_arch().manage())?;
        }
        for output in [proto.get_output(), proto.source_output()] {
            if output.get_size() > 0 && output.get_type().is_some_and(|ty| ty.get_metatype() != type_metatype::TYPE_VOID) {
                append_effect_input(&mut occupied, output.get_address(), output.get_size(), fd.get_arch().manage())?;
            }
        }
    }
    for (address, size) in roles {
        if !source.internal_list().iter().any(|role| role.space.as_ref().zip(address.get_space()).is_some_and(|(a, b)| Rc::ptr_eq(a, b))
            && role.offset == address.get_offset() && int4::try_from(role.size).ok() == Some(*size))
            || !ranges_cover(preserved.iter(), address, *size) { return Ok(false); }
        let Some(end) = address.get_offset().checked_add(*size as u64) else { return Ok(false); };
        if occupied.iter().any(|(at, bytes)| *bytes <= 0 || at.get_space().zip(address.get_space())
            .is_some_and(|(a, b)| Rc::ptr_eq(a, b)) && at.get_offset() < end
                && at.get_offset().checked_add(*bytes as u64).is_none_or(|limit| address.get_offset() < limit)) {
            return Ok(false);
        }
    }
    Ok(true)
}

/// Match the exact retained direct child obligation. Early SSA authenticates
/// source/family/raw identity; final SSA additionally discharges actual inputs.
pub(crate) fn internal_role_obligation_matches(fd: &Funcdata, op: OpId,
    address: &Address, size: int4, final_ssa: bool) -> KunaResult<bool>
{
    let Some(execution) = fd.entry_physical_requirements().and_then(|raw| raw.execution.as_ref())
        .filter(|execution| execution.complete) else { return Ok(false); };
    let Some(expected) = execution.direct_assumptions.iter().find(|expected| expected.op == op
        && expected.internal_roles.iter().any(|(at, bytes)| at == address && *bytes == size)) else { return Ok(false); };
    let Some(operation) = fd.obank().get(op).filter(|operation| !operation.is_dead()
        && operation.code() == OpCode::CPUI_CALL) else { return Ok(false); };
    let Some(index) = fd.get_call_specs_index(op) else { return Ok(false); };
    let call = fd.get_call_specs(index);
    if call.physical_requirements().is_none() { return Ok(false); }
    if call.get_entry_address() != &expected.entry
        || fd.physical_target_requirements(&expected.entry).is_none_or(|actual| !Rc::ptr_eq(actual, &expected.raw))
        || !selected_execution_matches(&expected.raw, expected.execution.as_ref()) { return Ok(false); }
    let Some((_, entry, declaration)) = fd.get_arch().query_function(&expected.entry)? else { return Ok(false); };
    let source = call.proto().source_prototype();
    if entry != expected.entry || !native_source_abi_equal(&source, &declaration.source_prototype()) { return Ok(false); }
    let Some(types) = fd.get_arch().types() else { return Ok(false); };
    let rebuilt;
    let family = if final_ssa { call.proto() } else {
        rebuilt = family_proto(&source, Some(&expected.raw), fd.get_arch().manage(), types)?;
        &rebuilt
    };
    let identity = family_identity(family, types)?;
    if identity.code != expected.family || identity.storage != expected.inputs || identity.output != expected.output
        || !Rc::ptr_eq(family.model(), &expected.model) || family.effect_list() != expected.effects
        || family.get_extra_pop() != expected.extra_pop
        || !internal_roles_fit(fd, &source, family, &expected.internal_roles)? { return Ok(false); }
    if !final_ssa { return Ok(true); }
    if call.execution_callable() != Some(&expected.family) || !call.execution_inputs_settled()
        || call.requires_raw_call() || operation.num_input() != family.num_params() + 1
        || consumes_unrepresented_call_state(fd, op) { return Ok(false); }
    for slot in 0..family.num_params() {
        if operation.get_in(slot + 1).and_then(|input| fd.vbank().get(input)).is_none_or(|input|
            input.get_size() != family.get_param(slot).expect("final role formal").get_size()) { return Ok(false); }
    }
    callback_arguments_proven(fd, call, &mut Vec::new())
}

fn callback_arguments_proven(fd: &Funcdata, call: &crate::fspec::FuncCallSpecs,
    active: &mut Vec<VarnodeId>) -> KunaResult<bool>
{
    let operation = fd.obank().get(call.get_op()).expect("callable argument consumer");
    for slot in 0..call.proto().num_params() {
        let Some(projection) = call.proto().input_projection(slot) else { continue };
        let Some(source) = projection.source.get_type() else { continue };
        let Some(execution) = call.proto().get_param(slot).and_then(|parameter| parameter.get_type()) else { continue };
        if source == execution { continue; }
        let Some(expected) = family_from_pointer(execution, fd)? else { continue };
        if call.execution_callable().is_none() { return Ok(false); }
        let Some(input) = operation.get_in(slot + 1) else { return Ok(false) };
        if fd.vbank().get(input).is_some_and(|value| value.is_constant() && value.get_offset() == 0) { continue; }
        if normalized_family(fd, input, active)?.as_ref().map(|proof| &proof.family) != Some(&expected) { return Ok(false); }
    }
    Ok(true)
}

/// A representation proof, not a nominal type or a points-to guess. Unknown
/// loads/native results never become normalized simply by acquiring a typedef.
fn normalized_family(fd: &Funcdata, vn: VarnodeId, active: &mut Vec<VarnodeId>)
    -> KunaResult<Option<ProvenCallableFamily>>
{
    if active.contains(&vn) { return Ok(None); }
    let Some(value) = fd.vbank().get(vn) else { return Ok(None) };
    if value.is_input() {
        for slot in 0..fd.get_func_proto().num_params() {
            let proto = fd.get_func_proto();
            let parameter = proto.get_param(slot).expect("entry slot");
            if parameter.get_address() == *value.get_addr() && parameter.get_size() == value.get_size()
                && proto.input_projection(slot).is_some()
            {
                if let Some(ty) = parameter.get_type() {
                    return Ok(family_from_pointer(ty, fd)?.map(|family| ProvenCallableFamily { family, transformed: true }));
                }
            }
        }
        return Ok(None);
    }
    if value.is_constant() {
        let typed = value.get_type().get_ptr_to().is_some_and(|code| code.get_metatype() == type_metatype::TYPE_CODE);
        let symbol = value.get_high().and_then(|id| fd.high_bank().get(id))
            .and_then(|high| high.kuna_symbol_type()).is_some_and(|ty| ty.get_metatype() == type_metatype::TYPE_CODE);
        let pointer_offset = value.descend_iter().any(|op| fd.obank().get(op).is_some_and(|op| {
            op.code() == OpCode::CPUI_PTRSUB && op.get_in(1) == Some(vn)
                && op.get_out().and_then(|vn| fd.vbank().get(vn))
                    .and_then(|vn| vn.get_type_def_facing().get_ptr_to())
                    .is_some_and(|code| code.get_metatype() == type_metatype::TYPE_CODE)
        }));
        if !typed && !symbol && !pointer_offset { return Ok(None); }
        if let Some(space) = fd.get_address().get_space() {
            let entry = Address::new(space.clone(), kuna_base::space::AddrSpace::address_to_byte(
                value.get_offset(), space.get_word_size()));
            if let Some((_, proto)) = pointer_adapter(fd, &entry)? {
                return family_identity(&proto, fd.get_arch().types().expect("adapter types"))
                    .map(|family| Some(ProvenCallableFamily { family, transformed: proto.has_execution_signature() }));
            }
        }
        return Ok(None);
    }
    let Some(def) = value.get_def().and_then(|op| fd.obank().get(op)) else { return Ok(None) };
    active.push(vn);
    let result = match def.code() {
        OpCode::CPUI_COPY | OpCode::CPUI_CAST =>
            match def.get_in(0) {
                Some(input) => normalized_family(fd, input, active)?,
                None => None,
            },
        OpCode::CPUI_PTRSUB => match def.get_in(1) {
            Some(input) => normalized_family(fd, input, active)?,
            None => None,
        },
        OpCode::CPUI_MULTIEQUAL => {
            let mut family: Option<ProvenCallableFamily> = None;
            let mut compatible = true;
            for slot in 0..def.num_input() {
                let Some(input) = def.get_in(slot) else { compatible = false; break };
                if fd.vbank().get(input).is_some_and(|v| v.is_constant() && v.get_offset() == 0) { continue; }
                let Some(candidate) = normalized_family(fd, input, active)? else { compatible = false; break };
                if let Some(current) = family.as_mut() {
                    if current.family != candidate.family { compatible = false; break; }
                    current.transformed |= candidate.transformed;
                } else { family = Some(candidate); }
            }
            if compatible { family } else { None }
        }
        OpCode::CPUI_CALL | OpCode::CPUI_CALLIND => {
            let call = value.get_def().and_then(|op| fd.get_call_specs_index(op)).map(|index| fd.get_call_specs(index));
            if let Some(call) = call.filter(|call| call.execution_callable().is_some()
                && !call.requires_raw_call() && def.num_input() == call.proto().num_params() + 1
                && (call.execution_requirements().is_none() || call.execution_inputs_settled())
                && !consumes_unrepresented_call_state(fd, call.get_op())) {
                let direct = def.code() == OpCode::CPUI_CALL && !call.get_entry_address().is_invalid()
                    && (call.physical_requirements().is_some_and(|summary| execution_complete(summary))
                        || (call.execution_inputs_settled() && fd.deferred_execution_contracts().get(&call.get_op())
                            .map(|contract| deferred_family_matches(fd, call, contract)).transpose()?.unwrap_or(false)));
                let generated = fd.generated_execution_contracts().get(&call.get_op())
                    .map(|contract| generated_family_matches(fd, call, contract)).transpose()?.unwrap_or(false);
                let indirect = if def.code() == OpCode::CPUI_CALLIND {
                    let retained = fd.entry_physical_requirements().and_then(|raw| raw.execution.as_ref())
                        .filter(|execution| execution.complete).is_some_and(|execution|
                            execution.execution_assumptions.iter().any(|(op, family)| *op == call.get_op()
                                && call.execution_callable() == Some(family)));
                    if retained {
                        let target = def.get_in(0).map(|input| normalized_family(fd, input, active)).transpose()?.flatten();
                        let Some(types) = fd.get_arch().types() else { active.pop(); return Ok(None); };
                        target.as_ref().filter(|proof| proof.transformed).map(|proof| &proof.family) == Some(&family_identity(call.proto(), types)?)
                    } else { false }
                } else { false };
                if (direct || indirect || generated) && callback_arguments_proven(fd, call, active)? {
                    match (call.proto().source_output().get_type(), call.proto().get_output_type()) {
                        (Some(source), Some(execution)) if indirect || generated || source != execution => family_from_pointer(execution, fd)?
                            .map(|family| ProvenCallableFamily { family, transformed: true }),
                        _ => None,
                    }
                } else { None }
            } else { None }
        }
        _ => None,
    };
    active.pop();
    Ok(result)
}

/// Reject address observations and escapes that cannot preserve the normalized
/// representation. This is checked before publishing an executable unit.
pub fn validate_representations(fd: &Funcdata) -> KunaResult<()> {
    let Some(types) = fd.get_arch().types() else { return Ok(()) };
    for id in fd.obank().iter_alive() {
        let op = fd.obank().get(id).expect("representation consumer");
        for slot in 0..op.num_input() {
            let Some(input) = op.get_in(slot) else { continue };
            let Some(proof) = normalized_family(fd, input, &mut Vec::new())? else { continue };
            if !proof.transformed { continue; }
            let family = proof.family;
            let preserved = match op.code() {
                OpCode::CPUI_COPY | OpCode::CPUI_MULTIEQUAL => {
                    let output = op.get_out().and_then(|vn| fd.vbank().get(vn));
                    let typed = output.map(|value| family_from_pointer(value.get_type_def_facing(), fd))
                        .transpose()?.flatten().as_ref() == Some(&family);
                    typed && op.get_out().map(|vn| normalized_family(fd, vn, &mut Vec::new()))
                        .transpose()?.flatten().as_ref().map(|proof| &proof.family) == Some(&family)
                },
                OpCode::CPUI_CAST => {
                    let out = op.get_out().and_then(|vn| fd.vbank().get(vn));
                    match out {
                        Some(out) => {
                            family_from_pointer(out.get_type_def_facing(), fd)?.as_ref() == Some(&family)
                        }
                        None => false,
                    }
                }
                OpCode::CPUI_PTRSUB => slot == 1
                    && op.get_out().and_then(|vn| fd.vbank().get(vn))
                        .map(|value| family_from_pointer(value.get_type_def_facing(), fd))
                        .transpose()?.flatten().as_ref() == Some(&family),
                OpCode::CPUI_RETURN =>
                    fd.get_func_proto().get_output_type().map(|ty| family_from_pointer(ty, fd))
                        .transpose()?.flatten().as_ref() == Some(&family),
                OpCode::CPUI_CALL | OpCode::CPUI_CALLIND => {
                    match fd.get_call_specs_index(id).map(|index| fd.get_call_specs(index)) {
                        Some(call) if slot == 0 => call.execution_callable().is_some()
                            && family_identity(call.proto(), types)? == family,
                        Some(call) => call.execution_callable().is_some()
                            && call.proto().get_param(slot - 1).and_then(|p| p.get_type())
                                .map(|ty| family_from_pointer(ty, fd)).transpose()?.flatten().as_ref() == Some(&family),
                        None => false,
                    }
                }
                OpCode::CPUI_INT_EQUAL | OpCode::CPUI_INT_NOTEQUAL => {
                    match op.get_in(1 - slot) {
                        Some(other) if fd.vbank().get(other).is_some_and(|v| v.is_constant() && v.get_offset() == 0) => true,
                        Some(other) => normalized_family(fd, other, &mut Vec::new())?.as_ref().map(|proof| &proof.family) == Some(&family),
                        None => false,
                    }
                }
                // Effect markers are not executed pointer observations. Their
                // outputs do not acquire representation provenance.
                OpCode::CPUI_INDIRECT => true,
                _ => false,
            };
            if !preserved {
                return Err(KunaError::lowlevel(format!(
                    "Callable address observation or native escape at {:?}", op.get_addr())));
            }
        }
    }
    Ok(())
}

/// A generated C call exposes only its declared result. A live INDIRECT value
/// from any other register is machine state, even when its target family is
/// proven. Preserve that boundary instead of turning it into an entry argument.
fn consumes_unrepresented_call_state(fd: &Funcdata, call: OpId) -> bool {
    let Some(index) = fd.get_call_specs_index(call) else { return true };
    let result = fd.get_call_specs(index).proto().get_output();
    let result_address = result.get_address();
    let mut chain = Vec::new();
    for id in fd.obank().iter_alive() {
        let operation = fd.obank().get(id).expect("call effect marker");
        if operation.code() != OpCode::CPUI_INDIRECT { continue; }
        if operation.is_dead() { continue; }
        let Some(output) = operation.get_out().and_then(|vn| fd.vbank().get(vn)) else { continue };
        if output.get_addr().get_space().is_none_or(|space| space.get_name() != "register") { continue; }
        if !output.descend_iter().any(|op| fd.obank().get(op).is_some_and(|op| !op.is_dead())) { continue; }
        let consume = if output.get_consume() == 0 { u64::MAX } else { output.get_consume() };
        chain.clear();
        let mut current = id;
        let affected = loop {
            if chain.contains(&current) { break true; }
            chain.push(current);
            let Some(indirect) = fd.obank().get(current) else { break true };
            if indirect.code() != OpCode::CPUI_INDIRECT { break false; }
            let Some(effect) = indirect.get_in(1).and_then(|vn| fd.vbank().get(vn)) else { break true };
            current = crate::funcdata_varnode::op_iop_decode(effect.get_offset());
            if current == call { break true; }
        };
        if !affected { continue; }
        if !operation.is_indirect_creation() && (fd.get_call_specs(index).physical_requirements().is_some_and(|summary|
            summary.preserves(output.get_addr(), output.get_size()))
            || provisional_execution_preserves(fd, fd.get_call_specs(index), output.get_addr(), output.get_size())) { continue; }
        // Map consumed bits to storage bytes, including big-endian registers.
        // Values wider than the consume mask cannot establish a supported scalar
        // result contract and are conservatively retained as machine state.
        if output.get_size() > 8 { return true; }
        for byte in 0..output.get_size() {
            let bit = if output.get_addr().is_big_endian() { output.get_size() - byte - 1 } else { byte };
            if (consume >> (bit * 8)) & 0xff == 0 { continue; }
            let offset = output.get_offset() + byte as u64;
            let same_space = output.get_addr().get_space().zip(result_address.get_space())
                .is_some_and(|(a, b)| Rc::ptr_eq(a, b));
            if !same_space || result.get_size() <= 0 || offset < result_address.get_offset()
                || offset - result_address.get_offset() >= result.get_size() as u64 {
                return true;
            }
        }
    }
    false
}

/// A source/native pointer cannot be passed into a normalized execution formal
/// by adding a C cast. Keep that operation as a machine boundary instead.
pub fn raw_boundary(fd: &Funcdata, op: OpId) -> KunaResult<bool> {
    let Some(index) = fd.get_call_specs_index(op) else { return Ok(false) };
    let call = fd.get_call_specs(index);
    if call.requires_raw_call() { return Ok(true); }
    if let Some(contract) = fd.generated_execution_contracts().get(&op) {
        return Ok(!generated_contract_matches(fd, op, contract)?);
    }
    let operation = fd.obank().get(op).expect("call operation");
    if consumes_unrepresented_call_state(fd, op) { return Ok(true); }
    if operation.code() == OpCode::CPUI_CALL && !call.get_entry_address().is_invalid() {
        if let Some(contract) = fd.deferred_execution_contracts().get(&op) {
            if !deferred_contract_matches(fd, op, contract)? { return Ok(true); }
        } else if let Some(summary) = call.physical_requirements() {
            let conditional = summary.execution.as_deref()
                .filter(|execution| call.execution_callable().is_some() && execution.complete);
            let roles = fd.entry_physical_requirements().and_then(|raw| raw.execution.as_ref())
                .filter(|execution| execution.complete).and_then(|execution|
                    execution.direct_assumptions.iter().find(|expected| expected.op == op))
                .map_or(&[][..], |expected| expected.internal_roles.as_slice());
            for (address, size) in roles {
                if !internal_role_obligation_matches(fd, op, address, *size, true)? { return Ok(true); }
            }
            if !preservation_fits(call.proto(), call.proto(), summary, conditional, roles, false, fd.get_arch().manage()) { return Ok(true); }
        }
    }
    if call.execution_callable().is_some() {
        if operation.num_input() != call.proto().num_params() + 1 { return Ok(true); }
        for slot in 0..call.proto().num_params() {
            let parameter = call.proto().get_param(slot).expect("execution call slot");
            if operation.get_in(slot + 1).and_then(|id| fd.vbank().get(id))
                .is_none_or(|value| value.get_size() != parameter.get_size()) { return Ok(true); }
        }
    }
    if operation.code() == OpCode::CPUI_CALLIND {
        let Some(target) = operation.get_in(0) else { return Ok(true); };
        let proven = normalized_family(fd, target, &mut Vec::new())?;
        if call.execution_callable().is_some() || call.proto().has_execution_signature() || proven.is_some() {
            let Some(types) = fd.get_arch().types() else { return Ok(true) };
            if proven.as_ref().map(|proof| &proof.family) != Some(&family_identity(call.proto(), types)?) { return Ok(true); }
        }
    }
    Ok(!callback_arguments_proven(fd, call, &mut Vec::new())?)
}

/// Deliberately a p-code statement, not a fabricated executable C helper.
pub fn raw_boundary_text(fd: &Funcdata, op: OpId) -> String {
    use std::fmt::Write as _;

    let operation = fd.obank().get(op).expect("raw machine operation");
    let call = fd.get_call_specs_index(op).map(|index| fd.get_call_specs(index));
    let site = operation.get_addr();
    let mut text = format!("{:?} [site=({},{:#x})", operation.code(),
        site.get_space().map_or("invalid", |space| space.get_name()), site.get_offset());
    for slot in 0..operation.num_input() {
        let Some(id) = operation.get_in(slot) else { continue };
        let value = fd.vbank().get(id).expect("live machine operand");
        let address = if slot == 0 {
            call.map(|call| call.get_entry_address()).filter(|entry| !entry.is_invalid())
                .unwrap_or(value.get_addr())
        } else { value.get_addr() };
        write!(text, ", input{slot}=({},{:#x},{})",
            address.get_space().map_or("invalid", |space| space.get_name()),
            address.get_offset(), value.get_size()).expect("writing to String");
    }
    text.push_str("] effects=");
    if let Some(call) = call {
        text.push('[');
        for (index, effect) in call.proto().effect_list().iter().enumerate() {
            if index != 0 { text.push_str(", "); }
            let address = effect.get_address();
            write!(text, "({},{:#x},{},{})",
                address.get_space().map_or("invalid", |space| space.get_name()),
                address.get_offset(), effect.get_size(), effect.get_type()).expect("writing to String");
        }
        text.push(']');
    } else { text.push_str("None"); }
    text
}

fn family_proto(source: &FuncProto, summary: Option<&EntryRequirements>, manager: &AddrSpaceManager,
    types: &dyn TypeFactory) -> KunaResult<FuncProto>
{
    let mut proto = source.source_prototype();
    if let Some(raw) = summary { close_finite_variadic_inputs(&mut proto, raw, manager)?; }
    normalize_values(&mut proto, manager, types, 0)?;
    widen_scalar_inputs(&mut proto, manager, types)?;
    if let Some(summary) = summary {
        if summary.execution.as_ref().is_some_and(|execution| execution.complete) {
            let mut selected = summary.clone();
            selected.reads = execution_reads(summary).to_vec();
            apply_ssa_requirements(&mut proto, &selected, manager, types)?;
        } else { apply_ssa_requirements(&mut proto, summary, manager, types)?; }
    }
    if !proto.physical_only_inputs().is_empty() { widen_scalar_inputs(&mut proto, manager, types)?; }
    Ok(proto)
}

/// The key contains storage, not arena TypeIds (which differ in workers).
fn adapter_key(entry: &Address, proto: &FuncProto) -> String {
    use std::fmt::Write;
    let mut key = format!("kuna_entry_{}_{}", entry.get_space().map_or(0, |s| s.get_index()), entry.get_offset());
    let mut descriptor = format!("{}:{}:{}:", proto.model().get_name(), proto.is_dotdotdot(), proto.num_params());
    let result = proto.get_output();
    let result_address = result.get_address();
    write!(&mut descriptor, "O{}:{}:{}:", result_address.get_space().map_or(-1, |s| s.get_index()),
        result_address.get_offset(), result.get_size()).expect("String write");
    for slot in 0..proto.num_params() {
        let parameter = proto.get_param(slot).expect("adapter parameter");
        let address = parameter.get_address();
        key.push_str(&format!("_{}_{}_{}", address.get_space().map_or(0, |s| s.get_index()),
            address.get_offset(), parameter.get_size()));
        if let Some(ty) = parameter.get_type() { type_identity(&ty.read(), ty.id(), &mut descriptor, &mut Vec::new()); }
    }
    if let Some(ty) = proto.get_output_type() { type_identity(&ty.read(), ty.id(), &mut descriptor, &mut Vec::new()); }
    key.push('_');
    // Injective encoding: unlike a truncated hash this cannot merge incompatible
    // callable overrides. Arena IDs and worker-local synthesized names are absent.
    for byte in descriptor.bytes() { write!(&mut key, "{byte:02x}").expect("String write"); }
    key
}

fn type_identity(view: &crate::dtype::ReadView<'_>, id: crate::dtype::TypeId,
    out: &mut String, active: &mut Vec<crate::dtype::TypeId>)
{
    use crate::dtype::DatatypeKind;
    use std::fmt::Write;
    if let Some(index) = active.iter().position(|seen| *seen == id) {
        write!(out, "R{index};").expect("String write");
        return;
    }
    active.push(id);
    let ty = view.get(id).expect("retained callable type");
    write!(out, "{:?}:{}:{}[", ty.get_metatype(), ty.get_size(), ty.is_char_print()).expect("String write");
    let effective = ty.effective().expect("callable type definition");
    let mut child = |id| type_identity(view, id, out, active);
    match &effective.kind {
        DatatypeKind::Pointer { ptrto, spaceid, truncate, wordsize } => {
            child(*ptrto);
            if let Some(truncate) = truncate { child(*truncate); }
            write!(out, "@{}:{wordsize}", spaceid.as_ref().map_or(-1, |s| s.get_index())).expect("String write");
        }
        DatatypeKind::Array { arrayof, arraysize } => {
            child(*arrayof);
            write!(out, "#{arraysize}").expect("String write");
        }
        DatatypeKind::Code { proto: Some(proto) } => {
            child(proto.output);
            for input in &proto.inputs { child(*input); }
            write!(out, "{}:{}:{}:{:?}:{}", proto.binding.model().get_name(), proto.variadic,
                proto.input_closed, proto.logical_first, proto.flags).expect("String write");
        }
        DatatypeKind::Struct { field, bitfield } => {
            for field in field {
                type_identity(view, field.field_type, out, active);
                write!(out, "@{};", field.offset).expect("String write");
            }
            for field in bitfield {
                type_identity(view, field.field_type, out, active);
                write!(out, "@{}:{}:{}:{}:{};", field.byte_offset, field.byte_size,
                    field.least_sig_bit, field.num_bits, field.is_big_endian).expect("String write");
            }
        }
        DatatypeKind::Union { field } => {
            for field in field { type_identity(view, field.field_type, out, active); }
        }
        DatatypeKind::PartialStruct { stripped, .. }
        | DatatypeKind::PartialUnion { stripped, .. }
        | DatatypeKind::PartialEnum { stripped, .. } => child(*stripped),
        DatatypeKind::PointerRel { ptrto, spaceid, wordsize, stripped, parent, offset } => {
            child(*ptrto);
            child(*parent);
            if let Some(stripped) = stripped { child(*stripped); }
            write!(out, "rel@{}:{wordsize}:{offset}:{}", spaceid.as_ref().map_or(-1, |s| s.get_index()),
                stripped.is_some()).expect("String write");
        }
        _ => {}
    }
    out.push(']');
    active.pop();
}

/// Address-producing operations are normalized to the same stable adapter as
/// direct requests. Merely sharing a nominal callable type is not a target.
/// The returned string is the dependency key. An unchanged family is supplied
/// by the actual target symbol, not by a function named after that key.
pub fn pointer_adapter(fd: &Funcdata, entry: &Address) -> KunaResult<Option<(String, FuncProto)>> {
    pointer_adapter_inner(fd, entry, false)
}

// Eligibility is needed during SSA analysis, while a known incompatible target
// is an executable-export error. Keep the diagnostic body available in between.
fn pointer_adapter_inner(fd: &Funcdata, entry: &Address, validate_boundary: bool)
    -> KunaResult<Option<(String, FuncProto)>>
{
    if let Some(request) = generated_pointer_request(fd, entry)? { return Ok(Some(request)); }
    let arch = fd.get_arch();
    let Some((_, entry, source)) = arch.query_function(entry)? else { return Ok(None) };
    let Some(types) = arch.types() else { return Ok(None) };
    let Some(summary) = fd.physical_target_requirements(&entry) else { return Ok(None); };
    if source.is_dotdotdot() {
        let mut candidate = source.source_prototype();
        if close_finite_variadic_inputs(&mut candidate, summary, arch.manage())? {
            return if validate_boundary {
                Err(KunaError::lowlevel("Variadic callable address requires an unrepresented execution interface"))
            } else { Ok(None) };
        }
    }
    if let Some(logical) = logical_result_family(fd, &source)? {
        let conditional = summary.execution.as_deref().filter(|execution| execution.complete);
        if execution_complete(summary) && requirements_fit(&source, summary, arch.manage())
            && preservation_fits(&source, &source, summary, conditional, &[], false, arch.manage()) {
            return Ok(Some((logical_result_key(&entry, &source, &logical), source.source_prototype())));
        }
    }
    if !adapter_supported(&source) {
        if !preservation_fits(&source, &source, summary, None, &[], false, arch.manage()) {
            return if validate_boundary { Err(KunaError::lowlevel("Executable C target does not preserve declared register state")) } else { Ok(None) };
        }
        if source.has_store() && source.has_model() {
            let code = callable_type(&source, types)?;
            if let Some(exposed) = crate::fspec::materialize_callable(types, &code)? {
                if !preservation_fits(exposed.prototype(), exposed.prototype(), summary, None, &[], arch.callee_proto_stack, arch.manage()) {
                    return if validate_boundary { Err(KunaError::lowlevel("Callable target violates its exposed register preservation contract")) } else { Ok(None) };
                }
            }
        }
        return Ok(None);
    }
    let family = family_proto(&source, None, arch.manage(), types)?;
    let conditional = summary.execution.as_deref()
        .filter(|execution| execution.complete);
    if !preservation_fits(&source, &source, summary, conditional, &[], false, arch.manage()) {
        return if validate_boundary { Err(KunaError::lowlevel("Executable C target does not preserve declared register state")) } else { Ok(None) };
    }
    let code = callable_type(&family, types)?;
    let exposed = crate::fspec::materialize_callable(types, &code)?
        .ok_or_else(|| KunaError::lowlevel("Callable family has no physical result contract"))?;
    // Native pointers expose only their declared ABI result. A generated
    // target-owned wrapper additionally transports the source's physical result.
    let result = if family.has_execution_signature() { &source } else { exposed.prototype().as_ref() };
    if !preservation_fits(exposed.prototype(), result, summary, conditional, &[], arch.callee_proto_stack, arch.manage()) {
        return if validate_boundary { Err(KunaError::lowlevel("Callable target violates its exposed register preservation contract")) } else { Ok(None) };
    }
    if !execution_complete(summary) || !requirements_fit(&family, summary, fd.get_arch().manage()) { return Ok(None); }
    Ok(Some((adapter_key(&entry, &family), family)))
}

/// Provisional generated-body preservation is an execution obligation, not a
/// replacement for the raw callee facts or an ordinary native ABI assumption.
pub fn provisional_execution_preserves(fd: &Funcdata, call: &crate::fspec::FuncCallSpecs,
    address: &Address, size: int4) -> bool
{
    if size <= 0 || call.get_entry_address().is_invalid()
        || fd.obank().get(call.get_op()).is_none_or(|op| op.code() != OpCode::CPUI_CALL) { return false; }
    let Some(code) = call.execution_callable() else { return false };
    if let Some(contract) = fd.deferred_execution_contracts().get(&call.get_op()) {
        if !deferred_family_matches(fd, call, contract).unwrap_or(false) { return false; }
        let Some(end) = address.get_offset().checked_add(size as u64) else { return false };
        let overlaps = |at: &Address, bytes: int4| bytes > 0
            && at.get_space().zip(address.get_space()).is_some_and(|(a, b)| Rc::ptr_eq(a, b))
            && at.get_offset() < end
            && at.get_offset().checked_add(bytes as u64).is_none_or(|limit| address.get_offset() < limit);
        if contract.effects.outputs.iter().any(|(at, bytes)| overlaps(at, *bytes))
            || contract.effects.stack_adjustment.as_ref().is_some_and(|(at, bytes, pop)| *pop != 0 && overlaps(at, *bytes))
        { return false; }
        let mut cursor = address.get_offset();
        while cursor < end {
            let next = contract.effects.preserved.iter().filter(|(at, bytes)| *bytes > 0
                && at.get_space().zip(address.get_space()).is_some_and(|(a, b)| Rc::ptr_eq(a, b))
                && at.get_offset() <= cursor)
                .filter_map(|(at, bytes)| at.get_offset().checked_add(*bytes as u64))
                .max().unwrap_or(cursor);
            if next <= cursor { return false; }
            cursor = next.min(end);
        }
        return true;
    }
    let Some(raw) = call.physical_requirements() else { return false };
    let Some(selected) = call.execution_requirements() else { return false };
    let Some(execution) = selected.execution.as_ref()
        .filter(|execution| execution.complete && execution.requires_private_frame) else { return false };
    if raw.execution.as_ref().is_none_or(|original| !Rc::ptr_eq(original, execution)) { return false; }
    let Some(types) = fd.get_arch().types() else { return false };
    if callable_type(call.proto(), types).as_ref().ok() != Some(code)
        || !requirements_fit(call.proto(), selected, fd.get_arch().manage()) { return false; }
    let Some(end) = address.get_offset().checked_add(size as u64) else { return false };
    let mut cursor = address.get_offset();
    while cursor < end {
        let next = execution.restored.iter().filter(|(at, bytes)| *bytes > 0
            && at.get_space().zip(address.get_space()).is_some_and(|(a, b)| Rc::ptr_eq(a, b))
            && at.get_offset() <= cursor)
            .map(|(at, bytes)| at.get_offset().saturating_add(*bytes as u64)).max().unwrap_or(cursor);
        if next <= cursor { return false; }
        cursor = next.min(end);
    }
    true
}

fn stack_adjustment(proto: &FuncProto, resolve_declaration: bool) -> Option<(Address, int4, i64)> {
    if !proto.has_model() { return None; }
    let extra_pop = if proto.get_extra_pop() == crate::fspec::EXTRAPOP_UNKNOWN {
        if !resolve_declaration { return None; }
        proto.declared_extra_pop()?
    } else { proto.get_extra_pop() };
    let stack = proto.get_spacebase()?;
    if stack.num_spacebase() != 1 { return None; }
    let storage = stack.get_spacebase(0).ok()?;
    Some((Address::new(storage.space?, storage.offset), storage.size as int4, i64::from(extra_pop)))
}

/// Facts are selected by the caller: conditional restoration requires a
/// generated target-owned definition, never an ordinary native pointer.
/// Internal coverage belongs only to the actual final body's representation;
/// it never changes raw preservation or licenses a native/caller boundary.
fn preservation_fits(effects: &FuncProto, proto: &FuncProto, summary: &EntryRequirements,
    conditional: Option<&super::kuna_physicalinputs::ExecutionRequirements>,
    body_internal: &[(Address, int4)], resolve_declaration: bool, manager: &AddrSpaceManager) -> bool
{
    let output = proto.has_store().then(|| proto.source_output());
    let output_address = output.map(|output| output.get_address());
    let output_size = output.filter(|output|
        output.get_type().is_none_or(|ty| ty.get_metatype() != type_metatype::TYPE_VOID))
        .map_or(0, |output| output.get_size());
    let output_join = output_address.as_ref().filter(|address|
        address.get_space().is_some_and(|space| space.get_type() == kuna_base::space::spacetype::IPTR_JOIN))
        .and_then(|address| manager.find_join(address.get_offset()).ok());
    let stack = stack_adjustment(effects, resolve_declaration).filter(|expected| {
        summary.stack_adjustments.iter().chain(conditional.into_iter().flat_map(|facts| &facts.stack_adjustments))
            .any(|actual| actual == expected)
    });
    for effect in effects.effect_list() {
        if effect.get_type() != crate::fspec::effect_type::UNAFFECTED { continue; }
        let at = effect.get_address();
        if at.get_space().is_none_or(|space| space.get_name() != "register") || effect.get_size() <= 0 { continue; }
        let end = at.get_offset().saturating_add(effect.get_size() as u64);
        for (write, bytes) in &summary.writes {
            if *bytes <= 0 || !write.get_space().zip(at.get_space()).is_some_and(|(a, b)| Rc::ptr_eq(a, b)) { continue; }
            let mut cursor = at.get_offset().max(write.get_offset());
            let end = end.min(write.get_offset().saturating_add(*bytes as u64));
            while cursor < end {
                let mut covered = cursor;
                let mut cover = |space: Option<&Rc<kuna_base::space::AddrSpace>>, offset: u64, size: int4| {
                    if size > 0 && space.zip(at.get_space()).is_some_and(|(a, b)| Rc::ptr_eq(a, b))
                        && offset <= cursor {
                        covered = covered.max(offset.saturating_add(size as u64));
                    }
                };
                for (address, size) in summary.restored.iter()
                    .chain(conditional.into_iter().flat_map(|facts| &facts.restored)).chain(body_internal) {
                    cover(address.get_space(), address.get_offset(), *size);
                }
                if output_size > 0 {
                    if let Some(join) = &output_join {
                        for index in 0..join.num_pieces() {
                            let piece = join.get_piece(index);
                            cover(piece.space.as_ref(), piece.offset, piece.size as int4);
                        }
                    } else if let Some(address) = &output_address {
                        cover(address.get_space(), address.get_offset(), output_size);
                    }
                }
                if let Some((address, size, _)) = &stack { cover(address.get_space(), address.get_offset(), *size); }
                if covered <= cursor { return false; }
                cursor = covered.min(end);
            }
        }
    }
    true
}

fn requirements_fit(family: &FuncProto, summary: &EntryRequirements, manager: &AddrSpaceManager) -> bool {
    execution_reads(summary).iter().all(|(address, size)| {
        if *size <= 0 { return false; }
        let Some(end) = address.get_offset().checked_add(*size as u64) else { return false };
        let mut cursor = address.get_offset();
        while cursor < end {
            let mut covered = cursor;
            let mut cover = |at: &Address, bytes: int4| {
                if bytes > 0 && at.get_space().zip(address.get_space()).is_some_and(|(a,b)| Rc::ptr_eq(a,b))
                    && at.get_offset() <= cursor
                {
                    covered = covered.max(at.get_offset().saturating_add(bytes as u64));
                }
            };
            for slot in 0..family.num_params() {
                let parameter = family.get_param(slot).expect("family input");
                let at = parameter.get_address();
                if at.get_space().is_some_and(|space| space.get_type() == kuna_base::space::spacetype::IPTR_JOIN) {
                    let Ok(join) = manager.find_join(at.get_offset()) else { return false };
                    for index in 0..join.num_pieces() {
                        let piece = join.get_piece(index);
                        let Some(space) = piece.space.as_ref() else { return false };
                        let Ok(size) = int4::try_from(piece.size) else { return false };
                        if size <= 0 || space.get_type() == kuna_base::space::spacetype::IPTR_JOIN { return false; }
                        cover(&Address::new(space.clone(), piece.offset), size);
                    }
                } else { cover(&at, parameter.get_size()); }
            }
            let bookkeeping = summary.execution.as_deref().filter(|execution| execution.complete)
                .map_or(summary.bookkeeping.as_slice(), |execution| execution.bookkeeping.as_slice());
            for (at, bytes) in bookkeeping { cover(at, *bytes); }
            if covered <= cursor { return false; }
            cursor = covered.min(end);
        }
        true
    })
}

fn declaration(proto: &FuncProto, name: &str, arch: &Architecture, printer: &crate::printc::PrintC) -> KunaResult<String> {
    declaration_with_convention(proto, name, arch, false, printer)
}

fn declaration_with_convention(proto: &FuncProto, name: &str, arch: &Architecture,
    convention: bool, printer: &crate::printc::PrintC) -> KunaResult<String>
{
    let context = crate::printc::RealTypeCtx::from_arch(arch, crate::kuna_lang::OutLang::C, printer.options.convention);
    let mut params = Vec::new();
    for slot in 0..proto.num_params() {
        let ty = proto.get_param(slot).and_then(|p| p.get_type())
            .ok_or_else(|| KunaError::lowlevel("Missing adapter input type"))?;
        params.push(crate::printc::declaration_text(ty, &format!("p{slot}"), context));
    }
    if proto.is_dotdotdot() { params.push("...".into()); }
    else if params.is_empty() { params.push("void".into()); }
    let model = crate::printc::emitted_model_name(proto, convention);
    let separator = if model.is_empty() { "" } else { " " };
    let result = proto.get_output_type().ok_or_else(|| KunaError::lowlevel("Missing adapter result type"))?;
    Ok(crate::printc::declaration_text(result, &format!("{model}{separator}{name}({})", params.join(", ")), context))
}

fn argument(final_parameter: &dyn ProtoParameter, family: &FuncProto, arch: &Architecture, printer: &crate::printc::PrintC) -> KunaResult<String> {
    let address = final_parameter.get_address();
    for slot in 0..family.num_params() {
        let parameter = family.get_param(slot).expect("adapter parameter");
        let at = parameter.get_address();
        if !at.get_space().zip(address.get_space()).is_some_and(|(a,b)| Rc::ptr_eq(a,b))
            || at.get_offset() > address.get_offset()
            || at.get_offset() + (parameter.get_size() as u64) < address.get_offset() + final_parameter.get_size() as u64
        { continue; }
        let mut value = format!("p{slot}");
        let byte_offset = if address.is_big_endian() {
            parameter.get_size() as u64 - final_parameter.get_size() as u64 - (address.get_offset() - at.get_offset())
        } else { address.get_offset() - at.get_offset() };
        if byte_offset != 0 {
            if !parameter.get_type().is_some_and(scalar) {
                return Err(KunaError::lowlevel("Callable adapter cannot slice a noninteger carrier"));
            }
            value = format!("({value} >> {})", byte_offset * 8);
        }
        let ty = final_parameter.get_type().ok_or_else(|| KunaError::lowlevel("Missing final adapter input"))?;
        if parameter.get_type() != Some(ty) {
            if !scalar(ty) || !parameter.get_type().is_some_and(scalar) {
                return Err(KunaError::lowlevel("Incompatible callable adapter storage"));
            }
            let context = crate::printc::RealTypeCtx::from_arch(arch, crate::kuna_lang::OutLang::C, printer.options.convention);
            let (front, back) = context.speller().type_name(&context, ty);
            value = format!("({front}{back}){value}");
        }
        return Ok(value);
    }
    Err(KunaError::lowlevel("Final target input is outside its adapter transport contract"))
}

fn return_address_only(fd: &Funcdata, input: VarnodeId) -> bool {
    let mut work = vec![input];
    let mut seen = Vec::new();
    let mut returned = false;
    while let Some(value) = work.pop() {
        if seen.contains(&value) { continue; }
        seen.push(value);
        let Some(node) = fd.vbank().get(value) else { return false };
        for consumer in node.descend_iter() {
            let Some(operation) = fd.obank().get(consumer).filter(|operation| !operation.is_dead()) else { continue };
            for slot in 0..operation.num_input() {
                if operation.get_in(slot) != Some(value) { continue; }
                if operation.code() == OpCode::CPUI_RETURN && slot == 0 { returned = true; continue; }
                if slot != 0 || !matches!(operation.code(), OpCode::CPUI_COPY | OpCode::CPUI_CAST) { return false; }
                let Some(output) = operation.get_out() else { return false };
                if fd.vbank().get(output).is_none_or(|output| output.get_size() != node.get_size()) { return false; }
                work.push(output);
            }
        }
    }
    returned
}

/// Only the C emission identity changes. Funcdata and host symbols continue
/// to identify the original source function and source parameter storage.
pub(crate) fn emitted_body_name(fd: &Funcdata, printer: &crate::printc::PrintC) -> String {
    if printer.out_lang() == crate::kuna_lang::OutLang::C && fd.logical_result_body_seed().is_some() {
        return format!("kuna_physical_entry_{}_{}",
            fd.get_address().get_space().map_or(0, |space| space.get_index()), fd.get_address().get_offset());
    }
    printer.emitted_function_name(fd, fd.get_display_name(), fd.get_address(), true)
}

fn logical_result_key(entry: &Address, proto: &FuncProto, family: &LogicalResultFamily) -> String {
    use std::fmt::Write;
    let mut key = adapter_key(entry, proto);
    key.push_str("_logical_");
    let mut descriptor = String::new();
    type_identity(&family.code.read(), family.code.id(), &mut descriptor, &mut Vec::new());
    for byte in descriptor.bytes() { write!(&mut key, "{byte:02x}").expect("String write"); }
    key
}

fn logical_result_declaration(family: &LogicalResultFamily, name: &str, arch: &Architecture,
    printer: &crate::printc::PrintC) -> String {
    let context = crate::printc::RealTypeCtx::from_arch(arch, crate::kuna_lang::OutLang::C, printer.options.convention);
    let mut inputs = family.inputs.iter().enumerate().map(|(slot, datatype)|
        crate::printc::declaration_text(datatype, &format!("p{slot}"), context)).collect::<Vec<_>>();
    if inputs.is_empty() { inputs.push("void".into()); }
    crate::printc::declaration_text(&family.result, &format!("{name}({})", inputs.join(", ")), context)
}

fn logical_result_artifact(fd: &Funcdata, printer: &crate::printc::PrintC,
    arch: &Architecture) -> KunaResult<Option<CallableArtifact>>
{
    use std::fmt::Write;
    let Some(seed) = fd.logical_result_body_seed() else { return Ok(None); };
    if !super::kuna_logicalresultbody::logical_result_body_matches(fd, seed)? {
        return Err(KunaError::lowlevel("Logical result body lost its complete value-write certificate"));
    }
    let family = logical_result_family(fd, fd.get_func_proto())?
        .ok_or_else(|| KunaError::lowlevel("Logical result body lost its assigned source family"))?;
    if seed.result() != &family.result {
        return Err(KunaError::lowlevel("Logical result body changed its source value root"));
    }
    let key = logical_result_key(fd.get_address(), fd.get_func_proto(), &family);
    let public = printer.emitted_function_name(fd, fd.get_display_name(), fd.get_address(), true);
    let target = emitted_body_name(fd, printer);
    let declaration = logical_result_declaration(&family, &public, arch, printer);
    let context = crate::printc::RealTypeCtx::from_arch(arch, crate::kuna_lang::OutLang::C, printer.options.convention);
    let (front, back) = context.speller().type_name(&context, &family.result);
    let result_type = format!("{front}{back}");
    let mut definition = format!("{declaration} {{\n");
    // Compile-time-only typedef assertions work in both C and C++ exports.
    writeln!(definition, "  typedef char kuna_result_size[(sizeof({result_type}) == {}) ? 1 : -1];", family.result.get_size()).expect("String write");
    for (index, field) in seed.layout().iter().enumerate() {
        writeln!(definition, "  typedef char kuna_result_offset_{index}[(offsetof({result_type}, {}) == {}) ? 1 : -1];", field.path, field.offset).expect("String write");
        writeln!(definition, "  typedef char kuna_result_field_{index}[(sizeof((({result_type} *)0)->{}) == {}) ? 1 : -1];", field.path, field.size).expect("String write");
    }
    writeln!(definition, "  {};", crate::printc::declaration_text(&family.result, "result", context)).expect("String write");
    let arguments = family.origins.iter().map(|origin| match origin {
        crate::fspec::AbiInputOrigin::HiddenResult => "&result".into(),
        crate::fspec::AbiInputOrigin::Declared(slot) => format!("p{slot}"),
    }).collect::<Vec<_>>();
    writeln!(definition, "  {target}({});\n  return result;\n}}", arguments.join(", ")).expect("String write");
    Ok(Some(CallableArtifact { key, declaration: format!("{declaration};"),
        definition: Some(CallableDefinition::Wrapper(definition)), required: true, deferred: false }))
}

pub fn export_artifacts(fd: &Funcdata, arch: &Architecture, printer: &crate::printc::PrintC) -> KunaResult<Vec<CallableArtifact>> {
    if printer.out_lang() != crate::kuna_lang::OutLang::C { return Ok(Vec::new()); }
    validate_representations(fd)?;
    if fd.entry_physical_requirements().is_none_or(|summary| !execution_complete(summary)) {
        return Err(KunaError::lowlevel("Executable C body has unresolved machine flow or effects"));
    }
    if let Some(execution) = fd.entry_physical_requirements().and_then(|summary| summary.execution.as_ref())
        .filter(|execution| execution.complete)
    {
        super::kuna_physicalinputs::validate_execution_flow(fd, execution)?;
        for expected in &execution.native_assumptions {
            if fd.native_execution_contracts().get(&expected.op)
                .is_none_or(|actual| !Rc::ptr_eq(actual, &expected.contract))
                || !native_contract_matches(fd, expected.op, &expected.contract)? {
                return Err(KunaError::lowlevel("Conditional native execution lacks final ABI proof"));
            }
        }
        for expected in &execution.generated_assumptions {
            if !generated_contract_matches(fd, expected.op, &expected.contract)? {
                return Err(KunaError::lowlevel("Generated indirect execution lacks exact final target proof"));
            }
        }
        super::kuna_physicalinputs::validate_execution_memory_destinations(fd, execution)?;
        for expected in &execution.deferred_assumptions {
            if !deferred_contract_matches(fd, expected.op, &expected.contract)? {
                return Err(KunaError::lowlevel("Deferred generated execution lacks final target proof"));
            }
        }
        for expected in &execution.direct_assumptions {
            let operation = fd.obank().get(expected.op).filter(|operation| !operation.is_dead()
                && operation.code() == OpCode::CPUI_CALL)
                .ok_or_else(|| KunaError::lowlevel("Conditional direct execution lost its call site"))?;
            let call = fd.get_call_specs_index(expected.op).map(|index| fd.get_call_specs(index))
                .ok_or_else(|| KunaError::lowlevel("Conditional direct execution lost its call contract"))?;
            let types = arch.types();
            let family = family_identity(call.proto(), types)?;
            if call.get_entry_address() != &expected.entry
                || fd.physical_target_requirements(&expected.entry).is_none_or(|actual| !Rc::ptr_eq(actual, &expected.raw))
                || !selected_execution_matches(&expected.raw, expected.execution.as_ref())
                || call.execution_callable() != Some(&expected.family)
                || family.code != expected.family || family.storage != expected.inputs
                || family.output != expected.output
                || !Rc::ptr_eq(call.proto().model(), &expected.model)
                || call.proto().effect_list() != expected.effects
                || call.proto().get_extra_pop() != expected.extra_pop
                || operation.num_input() != call.proto().num_params() + 1
                || raw_boundary(fd, expected.op)? {
                return Err(KunaError::lowlevel("Conditional direct execution lacks final target proof"));
            }
        }
        for proof in &execution.flow_returns {
            super::kuna_flowreturn::validate(fd, proof)?;
        }
        for (op, expected) in &execution.execution_assumptions {
            let operation = fd.obank().get(*op).filter(|operation| !operation.is_dead()
                && operation.code() == OpCode::CPUI_CALLIND)
                .ok_or_else(|| KunaError::lowlevel("Conditional execution family lost its call site"))?;
            let family = operation.get_in(0).map(|vn| normalized_family(fd, vn, &mut Vec::new()))
                .transpose()?.flatten();
            let call = fd.get_call_specs_index(*op).map(|index| fd.get_call_specs(index));
            let valid = family.as_ref().is_some_and(|proof| &proof.family.code == expected)
                && call.is_some_and(|call| call.execution_callable() == Some(expected))
                && !raw_boundary(fd, *op)?;
            if !valid {
                return Err(KunaError::lowlevel("Conditional execution family lacks final producer proof"));
            }
        }
    }
    let mut entry = super::kuna_physicalinputs::from_all_ssa_inputs(fd);
    if let Some(raw) = fd.entry_physical_requirements() {
        let conditional = raw.execution.as_deref().filter(|execution| execution.complete);
        entry.bookkeeping.clone_from(conditional.map_or(&raw.bookkeeping, |execution| &execution.bookkeeping));
    }
    for id in fd.vbank().iter_def_flag(crate::varnode::varnode_flags::input) {
        let input = fd.vbank().get(id).expect("entry value");
        if input.is_return_address() && return_address_only(fd, id) {
            entry.bookkeeping.push((input.get_addr().clone(), input.get_size()));
        }
    }
    if !requirements_fit(fd.get_func_proto(), &entry, arch.manage()) {
        return Err(KunaError::lowlevel("Executable C cannot represent consumed entry state"));
    }
    let context = fd.get_arch();
    let types = arch.types();
    let mut artifacts = BTreeMap::<String, CallableArtifact>::new();
    for index in 0..fd.num_calls() {
        let op = fd.get_call_specs(index).get_op();
        if raw_boundary(fd, op)? {
            return Err(KunaError::lowlevel(format!("Executable C cannot marshal machine boundary: {}",
                raw_boundary_text(fd, op))));
        }
    }
    if fd.get_func_proto().source_output().get_type() != fd.get_func_proto().get_output_type() {
        if let Some(expected) = fd.get_func_proto().get_output_type()
            .map(|ty| family_from_pointer(ty, fd)).transpose()?.flatten()
        {
            for op in fd.obank().iter_code(OpCode::CPUI_RETURN) {
                let operation = fd.obank().get(op).expect("return operation");
                if operation.is_dead() { continue; }
                let Some(value) = operation.get_in(1) else {
                    return Err(KunaError::lowlevel("Callable return has no machine value"));
                };
                if fd.vbank().get(value).is_some_and(|v| v.is_constant() && v.get_offset() == 0) { continue; }
                if normalized_family(fd, value, &mut Vec::new())?.as_ref().map(|proof| &proof.family) != Some(&expected) {
                    return Err(KunaError::lowlevel("Callable return crosses an unresolved machine boundary"));
                }
            }
        }
    }
    // Resolve actual address producers before consuming own-body-only coverage.
    // Required target definitions still discharge through publication; no raw or
    // native preservation gate receives these representation facts.
    let requests = required_artifacts(fd, arch, printer)?;
    let body_internal = fd.internal_constant_body_coverage()?;
    if let Some(raw) = fd.entry_physical_requirements() {
        let conditional = raw.execution.as_deref().filter(|execution| execution.complete);
        if !preservation_fits(fd.get_func_proto(), fd.get_func_proto(), raw, conditional, &body_internal, false, arch.manage()) {
            return Err(KunaError::lowlevel("Executable C body does not preserve declared register state"));
        }
    }
    let source = fd.get_func_proto().source_prototype();
    let families = [
        family_proto(&source, None, context.manage(), types),
        family_proto(&source, fd.entry_physical_requirements().map(|s| s.as_ref()), context.manage(), types),
    ];
    let mut target_name = None;
    // The already validated final body is also a provider for its exact plain
    // execution declaration, including genuinely recovered unchanged families.
    // No source prototype or raw summary is substituted for this real body.
    if !fd.get_func_proto().has_execution_signature() {
        let target = target_name.get_or_insert_with(||
            emitted_body_name(fd, printer));
        let key = adapter_key(fd.get_address(), fd.get_func_proto());
        let Some(space) = fd.get_address().get_space() else {
            return Err(KunaError::lowlevel("Callable body has no entry address space"));
        };
        artifacts.insert(key.clone(), CallableArtifact { key: key.clone(),
            declaration: format!("{};", declaration_with_convention(fd.get_func_proto(), target, arch, printer.options.convention, printer)?),
            definition: Some(CallableDefinition::ExistingTarget {
                space: space.get_index(), byte_address: fd.get_address().get_offset(),
            }), required: false, deferred: false });
        append_internal_role_providers(fd, &source, fd.get_func_proto(), &key,
            &body_internal, &mut artifacts)?;
    }
    for family in families {
        // A candidate is not an executable dependency until a real producer
        // requests it. Required-but-unavailable definitions fail unit linking.
        let Ok(family) = family else { continue };
        let conditional = fd.entry_physical_requirements()
            .is_some_and(|summary| summary.execution.as_ref().is_some_and(|execution| execution.complete));
        if (!family.has_execution_signature() && !conditional) || !adapter_supported(&family) { continue; }
        if let Some(summary) = fd.entry_physical_requirements() {
            let code = callable_type(&family, types)?;
            let exposed = crate::fspec::materialize_callable(types, &code)?
                .ok_or_else(|| KunaError::lowlevel("Callable family has no physical result contract"))?;
            let conditional = summary.execution.as_deref().filter(|execution| execution.complete);
            if !requirements_fit(&family, summary, arch.manage())
                || !preservation_fits(exposed.prototype(), fd.get_func_proto(), summary, conditional, &body_internal, arch.callee_proto_stack, arch.manage()) {
                continue;
            }
        }
        let key = adapter_key(fd.get_address(), &family);
        if artifacts.contains_key(&key) { continue; }
        if !family.has_execution_signature() {
            if family_identity(&family, types)? != family_identity(fd.get_func_proto(), types)? { continue; }
            let target = target_name.get_or_insert_with(||
                emitted_body_name(fd, printer));
            let declaration = format!("{};", declaration_with_convention(&family, target, arch, printer.options.convention, printer)?);
            let Some(space) = fd.get_address().get_space() else { continue };
            artifacts.insert(key.clone(), CallableArtifact { key: key.clone(), declaration,
                definition: Some(CallableDefinition::ExistingTarget {
                    space: space.get_index(), byte_address: fd.get_address().get_offset(),
                }), required: false, deferred: false });
            append_internal_role_providers(fd, &source, &family, &key,
                &body_internal, &mut artifacts)?;
            continue;
        }
        let declaration = declaration(&family, &key, arch, printer)?;
        let arguments = (0..fd.get_func_proto().num_params()).map(|slot|
            argument(fd.get_func_proto().get_param(slot).expect("final input"), &family, arch, printer))
            .collect::<KunaResult<Vec<_>>>();
        // A nominal family cannot absorb independent physical-only state. Its
        // producer proof rejects that family; only the wider direct transport
        // candidate below can represent such an entry.
        let Ok(arguments) = arguments else { continue };
        let returned = family.get_output_type().is_some_and(|ty| ty.get_metatype() != type_metatype::TYPE_VOID);
        let target = target_name.get_or_insert_with(||
            emitted_body_name(fd, printer));
        let definition = format!("{declaration} {{ {}{target}({}); }}", if returned { "return " } else { "" }, arguments.join(", "));
        artifacts.insert(key.clone(), CallableArtifact { key: key.clone(), declaration: format!("{declaration};"), definition: Some(CallableDefinition::Wrapper(definition)), required: false, deferred: false });
        append_internal_role_providers(fd, &source, &family, &key, &body_internal, &mut artifacts)?;
    }
    if let Some(wrapper) = logical_result_artifact(fd, printer, arch)? {
        artifacts.insert(wrapper.key.clone(), wrapper);
    }
    for request in requests {
        artifacts.entry(request.key.clone()).and_modify(|artifact| {
            artifact.required |= request.required;
            artifact.deferred |= request.deferred;
        }).or_insert(request);
    }
    Ok(artifacts.into_values().collect())
}

/// Canonical receipt for the actual emitted body; source parameter names stay
/// in the body/UI, while forward declarations use deterministic parameter names.
pub fn body_declaration(fd: &Funcdata, arch: &Architecture, printer: &crate::printc::PrintC)
    -> KunaResult<String>
{
    let name = emitted_body_name(fd, printer);
    Ok(format!("{};", declaration_with_convention(fd.get_func_proto(), &name, arch, printer.options.convention, printer)?))
}

fn native_declaration(proto: &FuncProto, name: &str, arch: &Architecture,
    printer: &crate::printc::PrintC) -> KunaResult<String>
{
    let Some(code) = proto.logical_callable() else {
        return declaration_with_convention(proto, name, arch, printer.options.convention, printer);
    };
    // Native C invokes the retained logical declaration, not the materialized
    // hidden-result pointer or other ABI-only carrier slots.
    let context = crate::printc::RealTypeCtx::from_arch(arch, crate::kuna_lang::OutLang::C, printer.options.convention);
    let view = code.read();
    let id = view.resolve_alias(code.id())?;
    let logical = view.get_code_prototype(id)?
        .ok_or_else(|| KunaError::lowlevel("Native declaration lost its logical prototype"))?;
    let mut params = Vec::with_capacity(logical.inputs.len() + usize::from(logical.variadic));
    for (slot, input) in logical.inputs.iter().enumerate() {
        params.push(crate::printc::declaration_text(&code.related(*input)?, &format!("p{slot}"), context));
    }
    if logical.variadic { params.push("...".into()); }
    else if params.is_empty() { params.push("void".into()); }
    let model = crate::printc::emitted_model_name(proto, printer.options.convention);
    let separator = if model.is_empty() { "" } else { " " };
    Ok(crate::printc::declaration_text(&code.related(logical.output)?,
        &format!("{model}{separator}{name}({})", params.join(", ")), context))
}

struct DirectSiteBridge {
    source: FuncProto,
    key: String,
    target_key: String,
}

fn direct_site_bridge(fd: &Funcdata, index: int4) -> KunaResult<Option<DirectSiteBridge>> {
    let call = fd.get_call_specs(index);
    let site = call.proto();
    if !site.is_override() || site.has_execution_signature() || call.execution_callable().is_some()
        || !adapter_supported(site) || call.get_entry_address().is_invalid()
        || fd.native_execution_contracts().contains_key(&call.get_op())
        || fd.obank().get(call.get_op()).is_none_or(|op| op.is_dead() || op.code() != OpCode::CPUI_CALL) {
        return Ok(None);
    }
    let Some(raw) = fd.physical_target_requirements(call.get_entry_address()) else { return Ok(None); };
    if !execution_complete(raw) { return Ok(None); }
    let Some((_, entry, source)) = fd.get_arch().query_function(call.get_entry_address())? else { return Ok(None); };
    if entry != *call.get_entry_address() { return Ok(None); }
    let source = source.source_prototype();
    if !adapter_supported(&source) || !requirements_fit(&source, raw, fd.get_arch().manage()) {
        return Ok(None);
    }
    let output = source.get_output();
    let site_output = site.get_output();
    if output.get_address() != site_output.get_address() || output.get_size() != site_output.get_size()
        || output.get_type() != site_output.get_type() { return Ok(None); }
    let unchanged = Rc::ptr_eq(source.model(), site.model()) && source.num_params() == site.num_params()
        && (0..source.num_params()).all(|slot| {
            let source = source.get_param(slot).expect("source formal");
            let site = site.get_param(slot).expect("site formal");
            source.get_address() == site.get_address() && source.get_size() == site.get_size()
                && source.get_type() == site.get_type()
        });
    if unchanged { return Ok(None); }
    if raw_boundary(fd, call.get_op())? {
        return Err(KunaError::lowlevel("Direct site adapter lacks its machine-boundary proof"));
    }
    let target_key = adapter_key(&entry, &source);
    let key = format!("{}_to_{target_key}", adapter_key(fd.get_address(), site));
    Ok(Some(DirectSiteBridge { source, key, target_key }))
}

fn original_parameter_unused(parameter: &dyn ProtoParameter, raw: &EntryRequirements) -> bool {
    if !raw.is_complete() || parameter.get_type().is_none_or(|ty| !scalar(ty)) { return false; }
    let address = parameter.get_address();
    let Some(space) = address.get_space().filter(|space| space.get_name() == "register") else { return false; };
    let Some(end) = u64::try_from(parameter.get_size()).ok().filter(|size| *size > 0)
        .and_then(|size| address.get_offset().checked_add(size)) else { return false; };
    raw.reads.iter().all(|(read, bytes)| {
        let Some(other) = read.get_space() else { return false; };
        if other.get_type() == kuna_base::space::spacetype::IPTR_JOIN { return false; }
        let Some(limit) = u64::try_from(*bytes).ok().filter(|size| *size > 0)
            .and_then(|size| read.get_offset().checked_add(size)) else { return false; };
        !Rc::ptr_eq(space, other) || read.get_offset() >= end || address.get_offset() >= limit
    })
}

fn direct_site_artifacts(fd: &Funcdata, index: int4, bridge: DirectSiteBridge,
    arch: &Architecture, printer: &crate::printc::PrintC) -> KunaResult<[CallableArtifact; 2]>
{
    let call = fd.get_call_specs(index);
    let raw = fd.physical_target_requirements(call.get_entry_address())
        .ok_or_else(|| KunaError::lowlevel("Direct site adapter lost its original target requirements"))?;
    let mut arguments = Vec::with_capacity(bridge.source.num_params() as usize);
    for slot in 0..bridge.source.num_params() {
        let parameter = bridge.source.get_param(slot).expect("source formal");
        let value = match argument(parameter, call.proto(), arch, printer) {
            Ok(value) => value,
            Err(_) if original_parameter_unused(parameter, raw) => "0".to_owned(),
            Err(error) => return Err(error),
        };
        arguments.push(value);
    }
    let Some((name, entry, _)) = fd.get_arch().query_function(call.get_entry_address())? else {
        return Err(KunaError::lowlevel("Direct site adapter lost its target symbol"));
    };
    let target = printer.emitted_function_name(fd, &name, &entry, true);
    let signature = declaration_with_convention(call.proto(), &bridge.key, arch, printer.options.convention, printer)?;
    let returned = bridge.source.get_output_type().is_some_and(|ty| ty.get_metatype() != type_metatype::TYPE_VOID);
    let definition = format!("{signature} {{ {}{target}({}); }}", if returned { "return " } else { "" }, arguments.join(", "));
    Ok([
        CallableArtifact { key: bridge.key, declaration: format!("{signature};"),
            definition: Some(CallableDefinition::Wrapper(definition)), required: true, deferred: false },
        CallableArtifact { key: bridge.target_key,
            declaration: format!("{};", declaration_with_convention(&bridge.source, &target, arch, printer.options.convention, printer)?),
            definition: None, required: true, deferred: false },
    ])
}

pub fn required_artifacts(fd: &Funcdata, arch: &Architecture, printer: &crate::printc::PrintC)
    -> KunaResult<Vec<CallableArtifact>>
{
    let mut artifacts = BTreeMap::<String, CallableArtifact>::new();
    generated_required_artifacts(fd, arch, printer, &mut artifacts)?;
    for index in 0..fd.num_calls() {
        let call = fd.get_call_specs(index);
        if call.get_entry_address().is_invalid() || fd.obank().get(call.get_op())
            .is_none_or(|op| op.is_dead() || op.code() != OpCode::CPUI_CALL) { continue; }
        if let Some(bridge) = direct_site_bridge(fd, index)? {
            for artifact in direct_site_artifacts(fd, index, bridge, arch, printer)? {
                artifacts.insert(artifact.key.clone(), artifact);
            }
            continue;
        }
        // A mapped machine body is never a native declaration waiver. Even an
        // unchanged direct family requires its real emitted provider receipt.
        if let Some(native) = fd.native_execution_contracts().get(&call.get_op()) {
            if let NativeTargetContract::Direct { entry, declaration: prototype } = &native.target {
                if !native_contract_matches(fd, call.get_op(), native)? {
                    return Err(KunaError::lowlevel("Native direct declaration lost its ABI proof"));
                }
                let name = if call.get_name().is_empty() {
                    call.fspec_printed_name(fd.get_arch().kuna_name_style())
                } else { call.get_name().to_string() };
                let name = printer.emitted_function_name(fd, &name, entry, true);
                let key = format!("native:{}", adapter_key(entry, prototype));
                let declaration = format!("{};", native_declaration(prototype, &name, arch, printer)?);
                if let Some(previous) = artifacts.get(&key) {
                    if previous.declaration != declaration {
                        return Err(KunaError::lowlevel("Conflicting authenticated native declarations"));
                    }
                } else {
                    artifacts.insert(key.clone(), CallableArtifact { key, declaration,
                        definition: None, required: false, deferred: false });
                }
                continue;
            }
        }
        if let Some(family) = logical_result_family(fd, call.proto())? {
            let name = if call.get_name().is_empty() {
                call.fspec_printed_name(fd.get_arch().kuna_name_style())
            } else { call.get_name().to_string() };
            let name = printer.emitted_function_name(fd, &name, call.get_entry_address(), true);
            let key = logical_result_key(call.get_entry_address(), call.proto(), &family);
            let declaration = format!("{};", logical_result_declaration(&family, &name, arch, printer));
            artifacts.insert(key.clone(), CallableArtifact { key, declaration,
                definition: None, required: true, deferred: false });
            continue;
        }
        let key = adapter_key(call.get_entry_address(), call.proto());
        let target = if call.proto().has_execution_signature() { key.clone() } else {
            let name = if call.get_name().is_empty() {
                call.fspec_printed_name(fd.get_arch().kuna_name_style())
            } else { call.get_name().to_string() };
            printer.emitted_function_name(fd, &name, call.get_entry_address(), true)
        };
        let declaration = format!("{};", declaration_with_convention(call.proto(), &target, arch,
            !call.proto().has_execution_signature() && printer.options.convention, printer)?);
        let deferred = fd.deferred_execution_contracts().get(&call.get_op());
        if let Some(contract) = deferred {
            if !deferred_contract_matches(fd, call.get_op(), contract)? {
                return Err(KunaError::lowlevel("Deferred callable request lacks final family proof"));
            }
        }
        if let Some(expected) = fd.entry_physical_requirements().and_then(|raw| raw.execution.as_ref())
            .filter(|execution| execution.complete).and_then(|execution|
                execution.direct_assumptions.iter().find(|expected| expected.op == call.get_op())) {
            for (address, size) in &expected.internal_roles {
                if !internal_role_obligation_matches(fd, call.get_op(), address, *size, true)? {
                    return Err(KunaError::lowlevel("Inherited role request lost its exact direct obligation"));
                }
                let qualified = internal_role_key(&key, address, *size)?;
                artifacts.insert(qualified.clone(), CallableArtifact { key: qualified,
                    declaration: declaration.clone(), definition: None, required: true, deferred: true });
            }
        }
        let deferred = deferred.is_some();
        artifacts.entry(key.clone()).and_modify(|artifact| {
            artifact.required = true;
            artifact.deferred |= deferred;
        }).or_insert(CallableArtifact { key, declaration, definition: None, required: true, deferred });
    }
    // Requests come from actual code-address producers, never from the order in
    // which target functions happen to be decompiled.
    for id in fd.obank().iter_alive() {
        let op = fd.obank().get(id).expect("live address producer");
        for slot in 0..op.num_input() {
            // Direct calls are checked by raw_boundary against their authentic
            // call prototype; indirect target constants are address producers.
            if op.code() == OpCode::CPUI_CALL && slot == 0 { continue; }
            let Some(vn) = op.get_in(slot) else { continue };
            let Some(value) = fd.vbank().get(vn) else { continue };
            if !value.is_constant() { continue; }
            let typed = value.get_type_read_facing(id).get_ptr_to()
                .is_some_and(|code| code.get_metatype() == type_metatype::TYPE_CODE)
                || value.get_type().get_ptr_to().is_some_and(|code| code.get_metatype() == type_metatype::TYPE_CODE);
            let named = value.get_high().and_then(|id| fd.high_bank().get(id))
                .and_then(|high| high.kuna_symbol_type()).is_some_and(|ty| ty.get_metatype() == type_metatype::TYPE_CODE);
            let symbol = value.descend_iter().any(|op| fd.obank().get(op).is_some_and(|op| {
                op.code() == OpCode::CPUI_PTRSUB && op.get_in(1) == Some(vn)
                    && op.get_out().and_then(|vn| fd.vbank().get(vn))
                        .and_then(|vn| vn.get_type_def_facing().get_ptr_to())
                        .is_some_and(|code| code.get_metatype() == type_metatype::TYPE_CODE)
            }));
            if !typed && !named && !symbol { continue; }
            let Some(space) = fd.get_address().get_space() else { continue };
            let entry = Address::new(space.clone(), kuna_base::space::AddrSpace::address_to_byte(
                value.get_offset(), space.get_word_size()));
            let Some((key, family)) = pointer_adapter_inner(fd, &entry, true)? else { continue };
            let target = if family.has_execution_signature() { key.clone() } else {
                let Some((name, target, _)) = fd.get_arch().query_function(&entry)? else {
                    return Err(KunaError::lowlevel("Proven callable target lost its symbol"));
                };
                printer.emitted_function_name(fd, &name, &target, true)
            };
            let declaration = if let Some(logical) = logical_result_family(fd, &family)? {
                format!("{};", logical_result_declaration(&logical, &target, arch, printer))
            } else { format!("{};", declaration_with_convention(&family, &target, arch,
                !family.has_execution_signature() && printer.options.convention, printer)?) };
            artifacts.entry(key.clone()).and_modify(|artifact| artifact.required = true)
                .or_insert(CallableArtifact { key, declaration, definition: None, required: true, deferred: false });
        }
    }
    Ok(artifacts.into_values().collect())
}

pub fn direct_adapter_name(fd: &Funcdata, index: int4) -> Option<String> {
    if let Ok(Some(bridge)) = direct_site_bridge(fd, index) { return Some(bridge.key); }
    let call = fd.get_call_specs(index);
    if call.execution_callable().is_none() || call.get_entry_address().is_invalid()
        || !call.proto().has_execution_signature() { return None; }
    Some(adapter_key(call.get_entry_address(), call.proto()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn body_proof_publication_rejects_wrapping_role_ranges() {
        let provider = "kuna_entry_3_4096_abi";
        let declaration = "int target(void);";
        for (byte, size, accepted) in [(u64::MAX - 1, 1, true), (u64::MAX, 1, false), (u64::MAX - 1, 2, false)] {
            let key = format!("{provider}_internal_4_{byte}_{size}");
            let request = [CallableArtifact { key: key.clone(), declaration: declaration.into(),
                definition: None, required: true, deferred: true }];
            let definitions = [
                CallableArtifact { key: provider.into(), declaration: declaration.into(),
                    definition: Some(CallableDefinition::ExistingTarget { space: 3, byte_address: 4096 }),
                    required: false, deferred: false },
                CallableArtifact { key: key.clone(), declaration: declaration.into(),
                    definition: Some(CallableDefinition::BodyProof { provider: provider.into() }),
                    required: false, deferred: false },
            ];
            let bodies = [
                CallableBody { space: Some(3), byte_address: 8192, artifacts: &request, failed: false, export_error: None },
                CallableBody { space: Some(3), byte_address: 4096, artifacts: &definitions, failed: false, export_error: None },
            ];
            let joined = collect_callable_publication(&bodies);
            assert_eq!(joined.is_ok(), accepted, "role {byte}/{size}");
            if let Ok(joined) = joined {
                assert!(joined[provider].required, "a body proof must retain its concrete provider");
                validate_callable_publication(&bodies, &joined, |_| true).unwrap();
            }
        }
    }
}
