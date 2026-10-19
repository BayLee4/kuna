//! Decode-time context runs for ARM corpus fingerprints. Rendering never changes live context.

use std::collections::HashSet;
use std::rc::Rc;

use kuna_base::address::Address;
use kuna_base::space::AddrSpace;
use kuna_decomp::architecture::Architecture;
use kuna_sleigh::translate::{AssemblyEmit, Translate};

use super::Listing;

#[derive(Default)]
pub(super) struct FingerprintContexts {
    runs: Vec<(usize, Vec<u32>)>,
}

impl FingerprintContexts {
    /// Record before translation can commit context changes. A failed decode
    /// leaves the partition index unchanged, so the next attempt replaces it.
    pub fn record(
        &mut self,
        index: usize,
        arch: &Architecture,
        addr: &Address,
        mode: Option<&super::kuna_walkcontext::InstructionMode<'_>>,
    ) {
        if self.runs.last().is_some_and(|(start, _)| *start == index) {
            self.runs.pop();
        }
        arch.with_context_db_mut(|db| {
            let words = db.get_context(addr);
            let effective = || {
                words
                    .iter()
                    .enumerate()
                    .map(|(word, &value)| mode.map_or(value, |mode| mode.context_word(word, value)))
            };
            if self
                .runs
                .last()
                .is_none_or(|(_, previous)| !effective().eq(previous.iter().copied()))
            {
                self.runs.push((index, effective().collect()));
            }
        });
    }

    /// Compact decode-time contexts alongside a partially rebuilt partition.
    pub fn retain(&mut self, keep: impl Iterator<Item = bool>) {
        let old = std::mem::take(&mut self.runs);
        let mut runs = old.iter().peekable();
        let mut words = &[][..];
        let mut next = 0;
        for (index, keep) in keep.enumerate() {
            while runs.peek().is_some_and(|(start, _)| *start <= index) {
                words = &runs.next().unwrap().1;
            }
            if keep {
                if self.runs.last().is_none_or(|(_, prior)| prior != words) {
                    self.runs.push((next, words.to_vec()));
                }
                next += 1;
            }
        }
    }

    /// Re-render only fingerprint instructions, including entries discovered
    /// after their instructions were already walked as part of another body.
    pub fn render(
        &self,
        listing: &mut Listing,
        partition: &[(u64, u32)],
        arch: &Architecture,
        translate: &dyn Translate,
        space: &Rc<AddrSpace>,
    ) {
        let Some(_context) = translate.context_scope() else {
            return;
        };
        let mut needed = HashSet::new();
        for (&entry, _) in listing.functions() {
            let mut at = entry;
            for _ in 0..2 {
                let Some(insn) = listing.instruction_at(at) else {
                    break;
                };
                needed.insert(at);
                at = at.wrapping_add(u64::from(insn.len));
            }
        }
        // Literal-pool admission consumes real operand facts, not just the
        // mnemonic fingerprints. The xrefs partition retains those read edges.
        for reference in listing.refs.edges() {
            if reference.kind == super::RefKind::Read && listing.in_exec(reference.to) {
                needed.insert(reference.from);
            }
        }
        let mut runs = self.runs.iter().peekable();
        let mut words = &[][..];
        let mut mnemonic = Mnemonic::default();
        for (index, &(at, len)) in partition.iter().enumerate() {
            while runs.peek().is_some_and(|(start, _)| *start <= index) {
                words = &runs.next().unwrap().1;
            }
            if !needed.remove(&at) {
                continue;
            }
            let addr = Address::new(Rc::clone(space), at);
            arch.with_context_db_mut(|db| {
                for (word, &value) in words.iter().enumerate() {
                    db.set_context_change_point(&addr, word as i32, u32::MAX, value);
                }
            });
            mnemonic.0.clear();
            mnemonic.1.clear();
            let rendered = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                translate.print_assembly(&mut mnemonic, &addr)
            }));
            if matches!(rendered, Ok(Ok(n)) if n > 0 && n as u32 == len) {
                // Resolve a PC-relative literal while its genuine decode context
                // is active. Later admission must not recompute it from a mode
                // that another decoded path has since repainted.
                if (mnemonic.0.starts_with("ldr") || mnemonic.0.starts_with("vldr"))
                    && mnemonic.1.contains("[pc")
                {
                    let delta = || arch.with_context_db_mut(|db|
                        db.get_variable_value(b"TMode", &addr)).ok()
                        .map(|mode| if mode == 1 { 4 } else { 8 });
                    if let Some(target) = crate::aif::kuna_poolentry::pcrel_literal_target(at, &mnemonic.1, delta) {
                        let start = mnemonic.1.find("[pc").unwrap();
                        let end = start + mnemonic.1[start..].find(']').unwrap() + 1;
                        mnemonic.1.replace_range(start..end, &format!("[0x{target:x}]"));
                    }
                }
                let interned = listing.insns.intern_mnemonic(&mnemonic.0);
                let insn = listing.insns.get_mut(&at).unwrap();
                insn.mnemonic = interned;
                insn.operands.clone_from(&mnemonic.1);
            }
        }
    }
}

#[derive(Default)]
struct Mnemonic(String, String);

impl AssemblyEmit for Mnemonic {
    fn dump(&mut self, _addr: &Address, mnemonic: &str, body: &str) {
        self.0.clear();
        self.0.push_str(mnemonic);
        self.1.clear();
        self.1.push_str(body);
    }
}
