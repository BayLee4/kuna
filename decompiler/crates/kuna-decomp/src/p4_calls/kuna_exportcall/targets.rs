//! Finite, positive callable-identity facts for one selected export invocation.
//!
//! This follows the value-carrying forms used by `kuna_callbacktype`'s
//! `code_address` / `carries_a_value`, not scalar evaluation or prototype
//! compatibility. Facts are membership observations, never a closed target
//! domain: a public callback input, load, or unrecorded callee remains unknown.
//! The retained graph contains only portable identities and integer node ids;
//! recording a body retains neither its Funcdata nor its architecture.

use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};

use kuna_base::address::Address;
use kuna_base::error::KunaResult;
use kuna_num::opcodes::OpCode;

use crate::funcdata::Funcdata;

use super::{ExportAddress, ExportCallKey, ExportEntry};

type Storage = (ExportAddress, i32);

struct DirectCall {
    target: ExportAddress,
    arguments: Vec<(Storage, usize)>,
    output: Option<usize>,
}

#[derive(Default)]
struct Body {
    widths: Vec<i32>,
    banks: Vec<Option<String>>,
    seeds: Vec<(usize, usize)>,
    edges: Vec<(usize, usize)>,
    // Only entry inputs matching exact formal source storage participate.
    inputs: BTreeMap<Storage, Vec<usize>>,
    returns: Vec<usize>,
    calls: Vec<DirectCall>,
    indirect: Vec<(ExportCallKey, usize)>,
}

/// Invocation-local positive provenance over the finite selected identities.
/// No fact in this summary rules out an unknown/public callback target.
pub(super) struct TargetFlow {
    selected: Vec<ExportAddress>,
    bodies: BTreeMap<ExportAddress, Body>,
}

impl TargetFlow {
    pub(super) fn new(selected: &[ExportEntry]) -> Self {
        let identities: BTreeSet<_> = selected.iter()
            .filter_map(|entry| portable(&entry.entry))
            .collect();
        Self {
            selected: identities.into_iter().collect(),
            bodies: BTreeMap::new(),
        }
    }

    /// Snapshot canonical/source value flow without changing source, callback
    /// locks, High variables, or the selected root set. Acquisition errors from
    /// the existing address resolver propagate before replacing a prior body.
    pub(super) fn record(&mut self, fd: &Funcdata) -> KunaResult<()> {
        let Some(entry) = portable(fd.get_address()) else { return Ok(()) };
        if self.selected.binary_search(&entry).is_err() {
            return Ok(());
        }
        let mut body = Body::default();
        let mut nodes = HashMap::new();
        for id in fd.obank().iter_alive() {
            let Some(op) = fd.obank().get(id) else { continue };
            for vn in (0..op.num_input()).filter_map(|slot| op.get_in(slot)).chain(op.get_out()) {
                if nodes.contains_key(&vn) {
                    continue;
                }
                let Some(value) = fd.vbank().get(vn) else { continue };
                let node = body.widths.len();
                nodes.insert(vn, node);
                body.widths.push(value.get_size());
                let pointer_space = value.get_type().get_pointer_space();
                let callable = value.get_type().get_ptr_to()
                    .is_some_and(|ty| ty.get_metatype() == crate::dtype::type_metatype::TYPE_CODE);
                body.banks.push(pointer_space.as_ref().or_else(|| {
                    callable.then(|| fd.get_arch().manage().get_default_code_space()).flatten()
                }).map(|space| space.get_name().to_owned()));
                let literal = if value.is_constant() { Some(value.get_offset()) }
                    else if callable { crate::kuna_callbacktype::code_address(fd,vn,0) }
                    else { None };
                if let Some(literal) = literal {
                    let space = pointer_space
                        .or_else(|| fd.get_arch().manage().get_default_code_space().cloned());
                    if let Some(space) = space {
                        let mut encoding = 0;
                        let address = fd.get_arch().resolve_constant(
                            &space, literal, value.get_size(),
                            op.get_addr(), &mut encoding,
                        )?;
                        seed(&self.selected, &mut body, node, &address);
                    }
                }
            }
        }

        let proto = fd.get_func_proto();
        let formals: BTreeSet<_> = (0..proto.num_params())
            .filter_map(|index| proto.get_param(index))
            .filter_map(|param| storage(&param.get_address(), param.get_size()))
            .collect();
        for (&vn, &node) in &nodes {
            let Some(value) = fd.vbank().get(vn) else { continue };
            if !value.is_input() {
                continue;
            }
            if let Some(home) = storage(value.get_addr(), value.get_size()) {
                if formals.contains(&home) {
                    body.inputs.entry(home).or_default().push(node);
                }
            }
            // Simplification can retain the original input home separately.
            // A write-qualified home is not evidence of an entry input.
            for source in fd.kuna_storage_sources(vn) {
                if source.write_address.is_some() || source.size != value.get_size() {
                    continue;
                }
                if let Some(home) = storage(&source.address, source.size) {
                    if formals.contains(&home) {
                        let inputs = body.inputs.entry(home).or_default();
                        if !inputs.contains(&node) {
                            inputs.push(node);
                        }
                    }
                }
            }
        }

        for id in fd.obank().iter_alive() {
            let Some(op) = fd.obank().get(id) else { continue };
            if op.code() == OpCode::CPUI_RETURN {
                for slot in 1..op.num_input() {
                    if let Some(node) = op.get_in(slot).and_then(|vn| nodes.get(&vn)) {
                        body.returns.push(*node);
                    }
                }
            }
            let Some(output) = op.get_out().and_then(|vn| nodes.get(&vn)).copied() else { continue };
            match op.code() {
                OpCode::CPUI_COPY | OpCode::CPUI_CAST | OpCode::CPUI_INT_ZEXT
                | OpCode::CPUI_INDIRECT => {
                    if op.code() == OpCode::CPUI_INDIRECT && op.is_indirect_creation() {
                        continue;
                    }
                    if let Some(input) = op.get_in(0).and_then(|vn| nodes.get(&vn)).copied() {
                        let widening = op.code() == OpCode::CPUI_INT_ZEXT;
                        if body.widths[input] == body.widths[output]
                            || (widening && body.widths[input] < body.widths[output])
                        {
                            body.edges.push((input, output));
                        }
                    }
                }
                OpCode::CPUI_MULTIEQUAL => {
                    for slot in 0..op.num_input() {
                        if let Some(input) = op.get_in(slot).and_then(|vn| nodes.get(&vn)).copied() {
                            if body.widths[input] == body.widths[output] {
                                body.edges.push((input, output));
                            }
                        }
                    }
                }
                OpCode::CPUI_PTRSUB => {
                    let Some(base_id) = op.get_in(0) else { continue };
                    let Some(base) = fd.vbank().get(base_id) else { continue };
                    let Some(offset) = op.get_in(1).and_then(|vn| fd.vbank().get(vn)) else { continue };
                    if !offset.is_constant() {
                        continue;
                    }
                    if base.is_constant() && base.get_offset() == 0 {
                        let base_type = base.get_type().get_ptr_to();
                        let spacebase = base_type.as_ref().and_then(|ty| ty.spacebase_parts());
                        // A local frame is not a global/function address, even
                        // if its offset happens to equal a selected entry.
                        if spacebase.as_ref().is_some_and(|(_, frame)| !frame.is_invalid()) {
                            continue;
                        }
                        let space = spacebase.and_then(|(space, _)| space)
                            .or_else(|| base.get_type().get_pointer_space())
                            .or_else(|| op.get_out().and_then(|vn| fd.vbank().get(vn))
                                .and_then(|value| value.get_type().get_pointer_space()));
                        let space = space.or_else(|| fd.get_arch().manage().get_default_code_space().cloned());
                        if let Some(space) = space {
                            let mut encoding = 0;
                            let address = fd.get_arch().resolve_constant(
                                &space, offset.get_offset(), -1, op.get_addr(), &mut encoding,
                            )?;
                            seed(&self.selected, &mut body, output, &address);
                        }
                    } else if offset.get_offset() == 0 {
                        if let Some(&input) = nodes.get(&base_id) {
                            if body.widths[input] == body.widths[output] {
                                body.edges.push((input, output));
                            }
                        }
                    }
                }
                _ => {}
            }
        }

        for (index,key) in super::call_keys(fd).into_iter().enumerate() {
            let index = index as i32;
            let call = fd.get_call_specs(index);
            let Some(op) = fd.obank().get(call.get_op()) else { continue };
            if op.is_dead() {
                continue;
            }
            if op.code() == OpCode::CPUI_CALLIND {
                if let Some(&node) = op.get_in(0).and_then(|vn| nodes.get(&vn)) {
                    body.indirect.push((key, node));
                }
                continue;
            }
            if op.code() != OpCode::CPUI_CALL {
                continue;
            }
            let Some(target) = portable(call.get_entry_address()) else { continue };
            if self.selected.binary_search(&target).is_err() {
                continue;
            }
            let finalized = call.final_input_storage();
            let aligned = finalized.len() + 1 == op.num_input() as usize;
            let mut arguments = Vec::new();
            for slot in 1..op.num_input() {
                let Some(&node) = op.get_in(slot).and_then(|vn| nodes.get(&vn)) else { continue };
                let home = if aligned {
                    finalized.get((slot - 1) as usize)
                        .and_then(|(address, size)| storage(address, *size))
                } else if call.get_paramshift() == 0 {
                    call.proto().get_param(slot - 1)
                        .and_then(|param| storage(&param.get_address(), param.get_size()))
                } else {
                    None
                };
                if let Some(home) = home.filter(|(_, width)| *width == body.widths[node]) {
                    arguments.push((home, node));
                }
            }
            body.calls.push(DirectCall {
                target, arguments,
                output: op.get_out().and_then(|vn| nodes.get(&vn)).copied(),
            });
        }
        self.bodies.insert(entry, body);
        Ok(())
    }

    /// Close only the observed positive facts. Empty or absent membership is
    /// not evidence that an indirect call has no other possible targets.
    pub(super) fn resolve(&self) -> BTreeMap<ExportCallKey, Vec<ExportAddress>> {
        let mut starts = BTreeMap::new();
        let mut count = 0;
        for (entry, body) in &self.bodies {
            starts.insert(entry, count);
            count += body.widths.len();
        }
        let mut edges = vec![Vec::new(); count];
        let mut facts = vec![BTreeSet::new(); count];
        let mut banks = vec![None; count];
        let mut work = VecDeque::new();
        for (entry, body) in &self.bodies {
            let start = starts[entry];
            banks[start..start+body.banks.len()].clone_from_slice(&body.banks);
            for &(from, to) in &body.edges {
                edges[start + from].push(start + to);
            }
            for &(node, target) in &body.seeds {
                if banks[start+node].as_ref().is_some_and(|bank| bank != &self.selected[target].space) {
                    continue;
                }
                if facts[start + node].insert(target) {
                    work.push_back((start + node, target));
                }
            }
            for call in &body.calls {
                let Some(callee) = self.bodies.get(&call.target) else { continue };
                let destination = starts[&call.target];
                for (storage, argument) in &call.arguments {
                    if let Some(inputs) = callee.inputs.get(storage) {
                        for &input in inputs {
                            edges[start + argument].push(destination + input);
                        }
                    }
                }
                if let Some(output) = call.output {
                    for &returned in &callee.returns {
                        if callee.widths[returned] == body.widths[output] {
                            edges[destination + returned].push(start + output);
                        }
                    }
                }
            }
        }
        // At most selected.len() facts can be added to each finite graph node;
        // recursion and phi cycles therefore need neither a depth cutoff nor
        // retained bodies to converge.
        while let Some((node, target)) = work.pop_front() {
            for &next in &edges[node] {
                if banks[next].as_ref().is_some_and(|bank| bank != &self.selected[target].space) {
                    continue;
                }
                if facts[next].insert(target) {
                    work.push_back((next, target));
                }
            }
        }
        let mut resolved = BTreeMap::new();
        for (entry, body) in &self.bodies {
            let start = starts[entry];
            for (key, node) in &body.indirect {
                let targets = facts[start + node].iter()
                    .map(|&target| self.selected[target].clone()).collect();
                resolved.insert(key.clone(), targets);
            }
        }
        resolved
    }
}

fn portable(address: &Address) -> Option<ExportAddress> {
    Some(ExportAddress {
        space: address.get_space()?.get_name().to_string(),
        offset: address.get_offset(),
    })
}

fn storage(address: &Address, width: i32) -> Option<Storage> {
    (width > 0).then(|| portable(address).map(|address| (address, width))).flatten()
}

fn seed(selected: &[ExportAddress], body: &mut Body, node: usize, address: &Address) {
    let Some(space) = address.get_space() else { return };
    if let Ok(target) = selected.binary_search_by(|candidate| {
        candidate.space.as_str().cmp(space.get_name())
            .then_with(|| candidate.offset.cmp(&address.get_offset()))
    }) {
        body.seeds.push((node, target));
    }
}
