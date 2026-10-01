//! The end-to-end decompilation orchestrator (item `w9x-arch-engine-glue`).
//!
//! Wires the merged subsystems — the [`Architecture`] god object, the
//! [`FlowInfo`] flow engine, the universalAction pipeline
//! ([`crate::universalaction`]), and the [`PrintC`] printer — into a single
//! function-decompilation path, mirroring `decompiler/cpp/ifacedecomp.cc`'s
//! `IfcDecompile` + `IfcPrintC`:
//!
//! ```text
//! IfcDecompile::execute (ifacedecomp.cc:889)
//!   fd->followFlow(...)                         -> generate_ops + generate_blocks
//!   allacts.getCurrent()->reset(*fd)
//!   res = allacts.getCurrent()->perform(*fd)    -> the restart loop
//! IfcPrintC::execute (ifacedecomp.cc:925)
//!   print->docFunction(fd)                      -> PrintC::doc_function shell
//! ```
//!
//! ## What runs end-to-end today (and what stubs out)
//!
//! * **Flow following is real.**  [`FlowInfo::generate_ops`] (C++
//!   `Funcdata::followFlow` -> `generateOps`) lifts and links every
//!   straight-line instruction's p-code into the `Funcdata`; CALL / jump-table
//!   sites hit the documented W4 `FlowInfo` stubs (FuncCallSpecs / JumpTable),
//!   which are no-ops here (faithful partial flow), so `generate_ops` returns
//!   the IR built up to those boundaries rather than erroring.
//! * **The universalAction perform loop is real.**  The 252-pass `decompile`
//!   root is installed and run; the *boot* passes (`ActionStart` -> the C++
//!   `Funcdata::startProcessing`) are W3/W4 stub no-ops in the merged tree
//!   (which is why the flow follow is driven explicitly here, outside the
//!   pipeline, exactly as the C++ `followFlow` runs before `perform`), so the
//!   pass scheduler/status state-machine executes without rebuilding the IR.
//! * **The printer body is the W9-emit stub.**  [`PrintC::doc_function`] emits a
//!   structurally-complete C function *shell* (real signature + matched braces)
//!   driving the real [`Emit`](crate::prettyprint::Emit) primitives; the
//!   per-statement RPN expression body is the `// STUB(W9-emit)` driver absent
//!   from the merged tree (see `printc.rs`).
//!
//! This proves the full path RUNS and emits plausible C — not byte-parity (the
//! W10 grind), which the e2e gate (`tests/decompile_e2e.rs`) asserts.

use std::collections::{BTreeMap, BTreeSet};
use std::rc::Rc;
use std::sync::Arc;

use kuna_base::address::Address;
use kuna_base::error::{KunaError, KunaResult};
use kuna_base::types::int4;

use kuna_num::opcodes::OpCode;

use crate::action::ActionContext;
use crate::architecture::Architecture;
use crate::flow::{FlowEnvironment, FlowInfo};
use crate::funcdata::{funcdata_flags, Funcdata};
use crate::context::{HighVariableId, TypeOp};

use kuna_sleigh::translate::Translate;
use kuna_sleigh::loadimage::ImageBytes;

/// A [`FlowEnvironment`] backed by a borrowed [`Architecture`] — the real
/// engine-backed shape the C++ `FlowInfo` uses (`glb->translate` for the
/// decoder, `glb->inst[opc]` for the op-property resolution).
///
/// The override / user-op tables default to "none" (the W4 surfaces the
/// `FlowInfo` trait already defaults); the architecture-owned `inst` table
/// drives `resolve_typeop` so the built ops carry the correct
/// branch/call/coderef/marker property flags.
struct ArchFlowEnv {
    mapped_image: Option<Arc<dyn ImageBytes>>,
    /// (kuna `calltrampoline` / `callpopret`) Memo of both return-address-
    /// discarding probes, keyed by direct-call target.  Both inspect the same
    /// bounded raw decode, so sharing the verdict also keeps the second option
    /// from doubling `getPcode` traffic in ghidra mode.
    return_discard_memo:
        std::cell::RefCell<std::collections::HashMap<(i32, u64), (bool, bool)>>,
    /// Raw pointer to the architecture (read-only use: `translate` / `resolve_
    /// typeop` / `query_call`).  A raw pointer (rather than `&Architecture`) lets
    /// the jump-table recovery hold `&mut Architecture` for the action sub-
    /// pipeline (`allacts`) concurrently: the env's reads (`translate`/`inst`/
    /// `symboltab`) never alias the `allacts` mutation, so the access is sound.
    arch: *const Architecture,
}

impl ArchFlowEnv {
    #[inline]
    fn arch(&self) -> &Architecture {
        // SAFETY: the pointer is created from a live `&mut Architecture` in
        // `build_and_follow_flow` and used only for non-aliasing read methods
        // (`translate`/`resolve_typeop`/`query_call`) for the duration of the
        // flow-follow; the architecture outlives the env.
        unsafe { &*self.arch }
    }
}

impl FlowEnvironment for ArchFlowEnv {
    fn mapped_flow_image(&self) -> Option<&dyn ImageBytes> {
        self.mapped_image.as_deref()
    }
    fn translate(&self) -> &dyn Translate {
        self.arch().translate()
    }
    fn resolve_typeop(&self, opc: OpCode) -> TypeOp {
        self.arch().resolve_typeop(opc)
    }
    /// (kuna) One-byte probe through the load image — the same question
    /// `ConsoleProgram::entry_bytes_mapped` asks, answered here for a branch
    /// target the walk is about to queue.  A loader already borrowed elsewhere
    /// reports `true` (queue it), which is the behaviour that predates the probe.
    fn code_bytes_mapped(&self, addr: &Address) -> bool {
        let loader_rc = self.arch().translate().loader_rc();
        let Ok(mut loader) = loader_rc.try_borrow_mut() else {
            return true;
        };
        let mut probe = [0u8; 1];
        loader.load_fill(&mut probe, addr).is_ok()
    }
    fn query_call(&self, entry: &Address) -> Option<String> {
        let arch = self.arch();
        // (kuna, Phase 3) ghidra-mode: the callee name comes from the host's
        // getMappedSymbols answer through the lazy RemoteScope (query-through);
        // the live symboltab is empty in that mode.  Standalone: no provider
        // installed, fall through to the symbol table unchanged.
        if let Some(remote) = &arch.remote_scope {
            if let Some(facts) = remote.function_at(entry) {
                // The DISPLAY form: callee tokens print the label when the host
                // sent one (the raw name is the Java-side identity only).
                return Some(facts.display_name);
            }
        }
        // C++ FlowInfo::queryCall -> getScopeLocal()->getParent()->queryFunction(entry):
        // resolve the callee's display name from the symbol table (populated by
        // readLoaderSymbols + the analysis passes at load).  Resolved across scopes
        // so a namespaced (demangled) callee like `foo::Bar::baz` renders its
        // qualified name instead of `sub_<addr>` (C++ queryFunction spans the
        // scope tree; kuna's per-scope maptable otherwise hides it).
        arch.symboltab.function_display_name_across_scopes(entry)
    }
    fn query_call_no_return(&self, entry: &Address) -> bool {
        // C++ `queryCall` copies the callee proto's `isNoReturn()` flow effect;
        // the flag is set by `option noreturn <name>` (OptionNoReturn) or the
        // no-return analysis pass on the resolved FunctionSymbol.
        let arch = self.arch();
        // (kuna, Phase 3) ghidra-mode: `Function.hasNoReturn()` rides the
        // `<function noreturn>` attribute of the getMappedSymbols answer —
        // upstream carries it on the queried callee's FuncProto the same way.
        if let Some(remote) = &arch.remote_scope {
            if let Some(facts) = remote.function_at(entry) {
                if facts.no_return {
                    return true;
                }
            }
        }
        if arch.symboltab.function_is_no_return_across_scopes(entry) {
            return true;
        }
        // (kuna, angr `test_decompiling_incorrect_duplication_chcon_main`) When
        // `option noreturn_externmatch on` (DIV-13 default-on), also report no-return
        // for a callee whose *name* matches the vendored ELF known-no-return list —
        // closing the ET_REL `.o` gap where the address-keyed `noreturn_known` scan
        // emitted no fact for an undefined extern (`__stack_chk_fail`), so flow stops
        // at the call instead of decoding the trailing alignment padding. A no-op on a
        // normal ELF (the proto flag above is already set). See
        // `kuna_noreturn_externmatch`.
        if arch.noreturn_extern_match {
            if let Some(name) = arch.symboltab.function_display_name_across_scopes(entry) {
                if crate::kuna_noreturn_externmatch::is_known_noreturn_name(&name) {
                    return true;
                }
            }
        }
        // (kuna `securitycheck`, DIV-82) The seven rustc security-check helpers are
        // all declared `-> !` in libcore, so a call to one diverges by definition.
        // kuna's address-keyed no-return discovery only proves that for the helper
        // bodies it can walk, and the ones it misses leave a *returning* panic block
        // that `ActionRemoveSecurityCheck`'s divergence guard then (correctly)
        // declines to remove.  Asserting the fact from the name here is the same
        // seam and the same shape as `noreturn_externmatch` above, on a list that
        // exists nowhere but Rust — so it is inert on a C binary.
        if arch.strip_security_check {
            if let Some(name) = arch.symboltab.function_display_name_across_scopes(entry) {
                if crate::kuna_securitycheck::is_security_check_name(&name) {
                    return true;
                }
            }
        }
        // (kuna) noreturn_extern: when the address-keyed flag is unset, fall back
        // to a name match against the known ELF no-return list.  This catches an
        // **undefined external** no-return (`__stack_chk_fail` in an ET_REL `.o`)
        // that the analysis-tier `noreturn_known` pass — which keys on a *defined*
        // FUNC symbol's address — never marks, so flow would otherwise run off the
        // function's end into the next one.  Default off (`option noreturn_extern`).
        if arch.noreturn_extern_calls {
            if let Some(name) = self.query_call(entry) {
                return crate::kuna_noreturnextern::matches_noreturn_extern_name(&name);
            }
        }
        false
    }
    fn funcbound_flow_enabled(&self) -> bool {
        // (kuna funcboundflow) the Architecture-owned gate (`option funcboundflow`).
        // When on, `flow.rs` truncates a fall-through that reaches a known function
        // entry (via `query_call`) so the next function is not decoded into this one.
        self.arch().funcbound_flow
    }
    fn funcbound_entry_is_unconditional_return(&self, entry: &Address) -> bool {
        // Decode exactly the candidate entry instruction out of band.  The
        // probe builds no Funcdata IR and a failure is conservative (the caller
        // keeps the boundary).  Match the flow follower's own fall-through
        // classification: the last p-code op must be RETURN and no other
        // control-transfer op may precede it.  BRANCH/BRANCHIND and conditional
        // returns are deliberately excluded because they can still reach more
        // code and consume a neighbouring function.
        decode_raw_run(self.arch(), entry, 1, usize::MAX)
            .map(|ops| {
                crate::kuna_funcboundflow::kuna_is_unconditional_return(
                    ops.into_iter().map(|op| op.code),
                )
            })
            .unwrap_or(false)
    }
    fn overlap_branch_enabled(&self) -> bool {
        // (kuna overlapbranch) the Architecture-owned gate (`option overlapbranch`).
        // When on, `flow.rs` truncates a conditional branch's fall-through whose
        // encoding swallows the branch's own target.
        self.arch().overlap_branch
    }
    fn decode_halt_reports(&self) -> bool {
        // (kuna decodehalt) the Architecture-owned gate (`option decodehalt`).
        // When on, a halt planted because the decode failed carries the upstream
        // truncation + header warnings.
        self.arch().decode_halt
    }
    fn query_call_inline(&self, entry: &Address) -> bool {
        // C++ `queryCall` copies the callee proto's `isInline()` flow effect; the
        // flag is set by `option inline <name>` (OptionInline) on the resolved
        // FunctionSymbol.
        if let Some(remote) = &self.arch().remote_scope {
            return remote.prototype_at(entry).is_some_and(|proto| proto.is_inline());
        }
        self.arch().symboltab.function_is_inline_across_scopes(entry)
    }
    fn query_call_inject_id(&self, entry: &Address) -> int4 {
        // The callee's parked inject id (IfcFixupApply); -1 for none.
        self.arch().symboltab.function_inject_id_across_scopes(entry)
    }
    fn build_inline_funcdata(&self, entry: &Address) -> KunaResult<Option<Funcdata>> {
        // C++ `Funcdata::inlineFlow` builds a fresh FlowInfo over the queried
        // callee Funcdata (after clearAnalysis).  Resolve the callee symbol's
        // name (the C++ `queryFunction(entry)` -> Funcdata), then build a fresh
        // Funcdata at that entry through the engine's `new_funcdata` factory.  No
        // callee symbol -> no inline (the C++ `fd == 0` short-circuit).
        let arch = self.arch();
        if let Some(remote) = &arch.remote_scope {
            return match remote.function_at(entry) {
                Some(facts) => {
                    let mut fd = arch.new_funcdata(&facts.name, entry.clone(), 0)?;
                    fd.set_display_name(&facts.display_name);
                    Ok(Some(fd))
                }
                None => Ok(None),
            };
        }
        let scope = match arch.symboltab.get_global_scope() {
            Some(s) => s,
            None => return Ok(None),
        };
        let sid = match arch.symboltab.find_function(scope, entry) {
            Some(s) => s,
            None => return Ok(None),
        };
        let name = arch.symboltab.symbol(sid).get_display_name().to_string();
        // size 0: unbounded natural extent — inlineFlow sets its own flow range
        // (the full entry-space) before generating ops.
        let fd = arch.new_funcdata(&name, entry.clone(), 0)?;
        Ok(Some(fd))
    }

    fn is_injected_userop(&self, userop_index: kuna_base::types::uintb) -> bool {
        // C++ `glb->userops.getOp(in0)->getType() == UserPcodeOp::injected`.
        //
        // (kuna `cortexmpriv`) The synthesized `isCurrentModePrivileged` fixup is
        // registered at architecture bootstrap, before any `option` line is
        // applied, so this — the only live per-CALLOTHER predicate that sees the
        // applied options — is where the flag gates it. Off, the CALLOTHER is left
        // alone and prints through the ordinary user-op path.
        let arch = self.arch();
        let op = match arch.userops.get_op(userop_index as kuna_base::types::uint4) {
            Some(op) => op,
            None => return false,
        };
        if op.get_type() != crate::userop::userop_type::injected {
            return false;
        }
        if !arch.cortexmpriv {
            if let Some(id) = op.get_inject_id() {
                if crate::kuna_cortexmpriv::is_our_fixup(arch.cortexmpriv_inject, id as int4) {
                    return false;
                }
            }
        }
        true
    }

    fn is_incidental_copy_userop(&self, userop_index: kuna_base::types::uintb) -> bool {
        // C++ `payload->isIncidentalCopy()` for the user-op's injection payload.
        let arch = self.arch();
        let injectid = match arch
            .userops
            .get_op(userop_index as kuna_base::types::uint4)
            .and_then(|op| op.get_inject_id())
        {
            Some(id) => id as int4,
            None => return false,
        };
        arch.pcodeinjectlib.get_payload(injectid).core().is_incidental_copy()
    }

    fn inject_userop(
        &self,
        userop_index: kuna_base::types::uintb,
        context: &mut crate::pcodeinject::InjectContext,
        emit: &mut dyn kuna_sleigh::translate::PcodeEmit,
    ) -> KunaResult<()> {
        // C++ `FlowInfo::injectUserOp`'s emit step.
        let arch = self.arch();
        let injectid = arch
            .userops
            .get_op(userop_index as kuna_base::types::uint4)
            .and_then(|op| op.get_inject_id())
            .ok_or_else(|| KunaError::lowlevel("inject_userop: user-op is not injected"))?
            as int4;
        emit_inject(arch, injectid, context, emit)
    }

    fn inject_call_fixup_payload(
        &self,
        inject_id: int4,
        context: &mut crate::pcodeinject::InjectContext,
        emit: &mut dyn kuna_sleigh::translate::PcodeEmit,
    ) -> KunaResult<()> {
        // C++ `FlowInfo::injectSubFunction`'s emit step.
        let arch = self.arch();
        emit_inject(arch, inject_id, context, emit)
    }

    fn is_incidental_copy_payload(&self, inject_id: int4) -> bool {
        let arch = self.arch();
        arch.pcodeinjectlib.get_payload(inject_id).core().is_incidental_copy()
    }

    fn call_fixup_param_shift(&self, inject_id: int4) -> int4 {
        let arch = self.arch();
        arch.pcodeinjectlib.get_payload(inject_id).core().get_param_shift()
    }

    fn call_fixup_name(&self, inject_id: int4) -> String {
        let arch = self.arch();
        String::from_utf8_lossy(&arch.pcodeinjectlib.base.get_call_fixup_name(inject_id)).into_owned()
    }


    fn is_v850_indirect_jmp(&self, fd: &Funcdata, op: crate::context::OpId) -> bool {
        // (kuna) GH-8817: wire the ported `kunaIsV850IndirectJmp` predicate.  The
        // gate is the architecture-owned `v850_indirect_branch` flag (`option
        // v850indirectbranch on|off`, default off / upstream byte-identical); the
        // register name is `glb->translate->getRegisterName(spc, off, size)` of
        // op's input-0 varnode (None == the C++ empty string, "not a named
        // register").
        let arch = self.arch();
        if !arch.v850_indirect_branch {
            // Fast-path the default-off gate without touching the IR (matches the
            // predicate's leading `if (!gate) return false`).
            return false;
        }
        // Resolve the input-0 register name for the predicate (the predicate
        // re-checks CALLIND / processor-space / null-input, so only the name
        // resolution lives here).
        let regname: Option<String> = (|| {
            let opref = fd.obank().get(op)?;
            let vn = opref.get_in(0)?;
            let vnref = fd.vbank().get(vn)?;
            let space = vnref.get_space();
            let off = vnref.get_offset();
            let size = vnref.get_size();
            let name = arch.translate().get_register_name(space, off, size);
            if name.is_empty() {
                None
            } else {
                Some(name)
            }
        })();
        crate::kuna_v850indbranch::kuna_is_v850_indirect_jmp(
            fd,
            op,
            arch.v850_indirect_branch,
            regname.as_deref(),
        )
    }

    fn is_sparc_struct_ret_trap(&self, fd: &Funcdata, op: crate::context::OpId) -> bool {
        // (kuna) GH-6882: wire the ported `kunaIsSparcStructRetTrap` predicate.
        // The gate is the architecture-owned `sparc_struct_return` flag (`option
        // sparcstructret on|off`, default off / upstream byte-identical); the
        // user-op name resolution is `glb->userops.getOp(id)->getName()` (None ==
        // the C++ null `UserPcodeOp *`).
        let arch = self.arch();
        if !arch.sparc_struct_return {
            // Fast-path the default-off gate without touching the IR (matches the
            // predicate's leading `if (!gate) return false`).
            return false;
        }
        crate::kuna_sparcstructret::kuna_is_sparc_struct_ret_trap(
            fd,
            op,
            arch.sparc_struct_return,
            |id| {
                arch.userops
                    .get_op(id)
                    .map(|uo| String::from_utf8_lossy(uo.get_name()).into_owned())
            },
        )
    }

    fn is_fastfail_callind(&self, fd: &Funcdata, op: crate::context::OpId) -> bool {
        // (kuna `fastfailnoreturn`) wire the `int 0x29` predicate.  The gate is the
        // architecture-owned `fastfail_noreturn` flag (`option fastfailnoreturn
        // on|off`, DIV default-on) plus the compiler-spec component of the resolved
        // language id — `int 0x29` is `__fastfail` by Windows convention alone.  The
        // user-op name resolution is `glb->userops.getOp(id)->getName()`.
        let arch = self.arch();
        if !arch.fastfail_noreturn
            || !crate::kuna_fastfailnoreturn::archid_is_windows(arch.get_description())
        {
            // Fast-path both gates without touching the IR.
            return false;
        }
        crate::kuna_fastfailnoreturn::is_fastfail_callind(fd, op, |id| {
            arch.userops.get_op(id).map(|uo| String::from_utf8_lossy(uo.get_name()).into_owned())
        })
    }

    fn int3_pad_site(
        &self,
        fd: &Funcdata,
        op: crate::context::OpId,
    ) -> Option<crate::kuna_int3pad::Int3PadSite> {
        // (kuna `int3pad`) wire the decoded-`int3` predicate.  The gate is the
        // architecture-owned `int3_pad` mode (`option int3pad off|warn|halt`,
        // default `warn`); the shape and user-op name resolution are
        // `fastfailnoreturn`'s, read for vector 3.  No language gate: the shape
        // itself is x86's, so no other processor reaches the match.
        let arch = self.arch();
        if !arch.int3_pad.warns() {
            // Fast-path the gate without touching the IR.
            return None;
        }
        if !crate::kuna_int3pad::is_int3_callind(fd, op, |id| {
            arch.userops.get_op(id).map(|uo| String::from_utf8_lossy(uo.get_name()).into_owned())
        }) {
            return None;
        }
        let addr = fd.obank().get(op)?.get_addr().clone();
        Some(crate::kuna_int3pad::Int3PadSite {
            run: crate::kuna_int3pad::pad_run_length(fd, &addr),
            halt: arch.int3_pad.halts(),
        })
    }

    fn is_tail_call_branch(
        &self,
        fd: &Funcdata,
        op: crate::context::OpId,
        dest: &Address,
    ) -> bool {
        // (kuna) tee-O2 tail-jump: wire the ported `kuna_is_tail_call_branch`
        // predicate.  The gate is the architecture-owned `tail_call_jumps` flag
        // (`option tailcalljump on|off`, default-off opt-in / default-pipeline
        // byte-identical — default-on regresses 2 datatests, Long double #1/#2).
        // The callee resolution is `query_call(dest).is_some()` (is `dest` a known
        // function entry, incl. a PLT thunk?) and the self-entry check is
        // `dest == fd.getAddress()`.
        let arch = self.arch();
        if !arch.tail_call_jumps {
            // Fast-path the default-off gate without touching the IR.
            return false;
        }
        let dest_is_known_function = self.query_call(dest).is_some();
        let dest_is_self = dest == fd.get_address();
        crate::kuna_tailcalljump::kuna_is_tail_call_branch(
            fd,
            op,
            arch.tail_call_jumps,
            dest_is_known_function,
            dest_is_self,
        )
    }

    fn is_return_discarding_trampoline(&self, dest: &Address) -> bool {
        // (kuna `calltrampoline`) Fast-path the gate: this runs at every direct
        // CALL site, and off it must not touch the decoder.
        if !self.arch().call_trampoline {
            return false;
        }
        self.return_discard_verdicts(dest).1
    }

    fn pops_return_address(&self, dest: &Address) -> bool {
        // (kuna `callpopret`) Fast-path the gate: this runs at every direct CALL
        // site, and off it must not touch the decoder.
        if !self.arch().call_pop_ret {
            return false;
        }
        self.return_discard_verdicts(dest).0
    }

    fn is_frame_teardown_tail_call(
        &self,
        fd: &Funcdata,
        op: crate::context::OpId,
        dest: &Address,
    ) -> bool {
        // (kuna `tailcallframe`) The gate is the architecture-owned
        // `tail_call_frame` flag; the predicate needs the stack-pointer register
        // location, which is the stack space's own base register
        // (`getStackSpace()->getSpacebaseFull(0)`).  A compiler spec with no
        // `<stackpointer>` has no stack space, and the rule declines.
        let arch = self.arch();
        if !arch.tail_call_frame {
            // Fast-path the gate without touching the IR.
            return false;
        }
        let sp = arch
            .manage()
            .get_stack_space()
            .and_then(|spc| spc.get_spacebase_full(0).ok());
        crate::kuna_tailcallframe::kuna_is_frame_teardown_tail_call(
            fd,
            op,
            arch.tail_call_frame,
            fd.get_address(),
            dest,
            sp.as_ref(),
            arch.tail_call_saved,
        )
    }
}

impl ArchFlowEnv {
    /// (kuna `calltrampoline` / `callpopret`) Classify both shapes from one
    /// bounded decode.  Tuple order is `(callpopret, calltrampoline)`.
    fn return_discard_verdicts(&self, dest: &Address) -> (bool, bool) {
        let key = dest.get_space().map(|sp| (sp.get_index(), dest.get_offset()));
        if let Some(k) = key {
            if let Some(hit) = self.return_discard_memo.borrow().get(&k) {
                return *hit;
            }
        }
        let arch = self.arch();
        let Some(sp) =
            arch.manage().get_stack_space().and_then(|spc| spc.get_spacebase_full(0).ok())
        else {
            return (false, false);
        };
        let Some(ops) = decode_raw_run(
            arch,
            dest,
            crate::kuna_calltrampoline::KUNA_TRAMPOLINE_MAX_INSTRS,
            crate::kuna_calltrampoline::KUNA_TRAMPOLINE_MAX_OPS,
        ) else {
            return (false, false);
        };
        let popret = arch.call_pop_ret
            && crate::kuna_callpopret::kuna_call_pops_return_address(&ops, &sp);
        let trampoline = if arch.call_trampoline {
            crate::kuna_calltrampoline::kuna_trampoline_branch_target(&ops, &sp)
                .and_then(|target| {
                    let space = target.space.as_ref()?;
                    let re_entry = Address::new(std::rc::Rc::clone(space), target.offset);
                    Some(self.query_call(&re_entry).is_none())
                })
                .unwrap_or(false)
        } else {
            false
        };
        let verdict = (popret, trampoline);
        if let Some(k) = key {
            self.return_discard_memo.borrow_mut().insert(k, verdict);
        }
        verdict
    }
}

/// Collects the raw p-code of an out-of-band decode into a flat list.
///
/// The [`FlowEmit`](crate::flow) emitter builds `Funcdata` IR; the trampoline
/// probe must not, because it runs *before* the flow follower has decided
/// whether the callee's bytes belong to the function at all.
struct RawOpCollector {
    ops: Vec<crate::kuna_calltrampoline::RawOp>,
    /// Set once a control-transfer op has been seen, so the caller stops
    /// decoding instead of walking on past the fragment's `jmp`.
    ended: bool,
}

impl kuna_sleigh::translate::PcodeEmit for RawOpCollector {
    fn dump(
        &mut self,
        _addr: &Address,
        opc: OpCode,
        outvar: Option<&kuna_num::pcoderaw::VarnodeData>,
        vars: &[kuna_num::pcoderaw::VarnodeData],
    ) {
        if matches!(
            opc,
            OpCode::CPUI_BRANCH
                | OpCode::CPUI_CBRANCH
                | OpCode::CPUI_BRANCHIND
                | OpCode::CPUI_CALL
                | OpCode::CPUI_CALLIND
                | OpCode::CPUI_CALLOTHER
                | OpCode::CPUI_RETURN
        ) {
            self.ended = true;
        }
        self.ops.push(crate::kuna_calltrampoline::RawOp {
            code: opc,
            out: outvar.cloned(),
            ins: vars.to_vec(),
        });
    }
}

/// (kuna `calltrampoline`) Decode the straight-line run starting at `entry`
/// into raw p-code, stopping at the first control-transfer op or at the module's
/// instruction/op budget.
///
/// A decode failure ends the run rather than propagating: this is a *probe* at
/// an address the flow follower has not committed to, and an address whose bytes
/// do not disassemble is simply not a trampoline.
fn decode_raw_run(
    arch: &Architecture,
    entry: &Address,
    max_instrs: usize,
    max_ops: usize,
) -> Option<Vec<crate::kuna_calltrampoline::RawOp>> {
    let translate = arch.translate();
    let mut collector = RawOpCollector { ops: Vec::new(), ended: false };
    let mut at = entry.clone();
    for _ in 0..max_instrs {
        let step = translate.one_instruction(&mut collector, &at).ok()?;
        if collector.ended || collector.ops.len() > max_ops {
            break;
        }
        if step <= 0 {
            return None;
        }
        at = &at + step as i64;
    }
    Some(collector.ops)
}

/// Build a [`Funcdata`] for the function `name` at `entry` and follow its flow,
/// returning the IR-populated `Funcdata` (C++ `Funcdata` construction +
/// `Funcdata::followFlow`).
///
/// The Funcdata is built through [`Architecture::new_funcdata`] (the W3 boot
/// boundary: it carries the IR-boundary address-space slice + the analysis
/// unique-start).  Flow following runs the real [`FlowInfo`] against an
/// [`ArchFlowEnv`]; on success the `processing_started` flag is set so the
/// printer's `isProcStarted` gate (and the pipeline's resume bookkeeping) see a
/// started function.
#[allow(clippy::mutable_key_type)]
pub fn build_and_follow_flow(
    arch: &mut Architecture,
    name: &str,
    entry: Address,
    size: int4,
) -> KunaResult<Funcdata> {
    build_and_follow_flow_with_override(arch, name, entry, size, &[])
}

/// Like [`build_and_follow_flow`], but seeds the fresh `Funcdata`'s per-function
/// flow-`Override` (C++ `data.getOverride()`) before flow follows — so the console
/// `override flow <addr> <type>` command (which sets the override on the function
/// before `decompile` rebuilds the IR) takes effect at flow time
/// (`FlowInfo::process` reads `hasFlowOverride`/`getFlowOverride` then
/// `Funcdata::overrideFlow`).
///
/// `flow_overrides` are the `(address, flow_type)` facts the console stashed; they
/// are re-inserted into the fresh Funcdata's `localoverride` (the C++ override is
/// kept on the reused Funcdata, but the kuna console rebuilds the IR — see the
/// `pending_prototypes`/`mapped_symbols` re-seed precedent).
///
/// Takes `&mut Architecture` because the jump-table recovery pipeline (below)
/// holds a `*mut Architecture` to drive the `allacts` sub-pipeline concurrently
/// with the env's read-only `*const Architecture` (see [`ArchFlowEnv`]).
#[allow(clippy::mutable_key_type)]
pub fn build_and_follow_flow_with_override(
    arch: &mut Architecture,
    name: &str,
    entry: Address,
    size: int4,
    flow_overrides: &[(Address, kuna_base::types::uint4)],
) -> KunaResult<Funcdata> {
    build_and_follow_flow_with_override_and_protos(
        arch, name, entry, size, flow_overrides, &crate::overrides::Override::new(),
    )
}

/// Like [`build_and_follow_flow_with_override`], but also re-seeds the
/// `override prototype <addr> <decl>` facts onto the fresh `Funcdata`'s
/// `localoverride` (the proto-override store) before flow follows, so
/// `FlowInfo::build_call_specs` applies them (`Override::applyPrototype`).  The
/// override survives the deindirect-driven `clear()` + re-flow, so a prototype
/// forced onto an injected CALLIND (the `injectoverride` corpus case) takes
/// effect on the restart re-flow.
#[allow(clippy::mutable_key_type)]
pub fn build_and_follow_flow_with_override_and_protos(
    arch: &mut Architecture,
    name: &str,
    entry: Address,
    size: int4,
    flow_overrides: &[(Address, kuna_base::types::uint4)],
    proto_overrides: &crate::overrides::Override,
) -> KunaResult<Funcdata> {
    let mut fd = arch.new_funcdata(name, entry, size)?;
    for (addr, ty) in flow_overrides {
        fd.get_override_mut().insert_flow_override(addr.clone(), *ty);
    }
    fd.get_override_mut().merge_proto_overrides(proto_overrides);
    follow_flow_on_fd(arch, fd)
}

/// Follow flow for an (already-constructed) `fd`, returning the IR-populated
/// `Funcdata`.  Shared by the fresh build ([`build_and_follow_flow_with_override`])
/// and the restart re-flow ([`refollow_flow`], C++ `ActionStart::startProcessing`
/// → `followFlow` after `clearAnalysis`): both run the same
/// `generateOps`/`generateBlocks`/`startProcessing` sequence; the only difference
/// is whether `fd` is brand-new or just `clear()`ed (its per-function `Override`
/// — including the indirect override a prior `deindirect` installed — survives the
/// clear, so the re-flow rebuilds the CALLIND straight as a direct CALL).
#[allow(clippy::mutable_key_type)]
fn follow_flow_on_fd(arch: &mut Architecture, mut fd: Funcdata) -> KunaResult<Funcdata> {
    fd.select_analysis_model();
    // C++ Funcdata::followFlow(baddr, eaddr): a function carrying a declared byte
    // extent restricts flow to it; size 0 keeps the unbounded default the whole
    // engine has used until now (`kuna_console::engine::UNBOUNDED_SIZE`), so this
    // is inert for every caller that does not declare one. `eaddr` is INCLUSIVE
    // (`FlowInfo::new_address` rejects `eaddr < to`), so the last in-body byte is
    // `entry + size - 1`.
    let range = (fd.get_size() > 0).then(|| fd.get_address().clone()).and_then(|start| {
        let last = start.get_offset().checked_add(fd.get_size() as u64 - 1)?;
        let space = Rc::clone(start.get_space()?);
        Some((start.clone(), Address::new(space, last)))
    });
    let env = ArchFlowEnv {
        mapped_image: if arch.mapped_flow_boundary && arch.mapped_flow_boundary_image {
            arch.translate().loader_rc().borrow().shared_bytes()
        } else {
            None
        },
        arch: arch as *const Architecture,
        return_discard_memo: Default::default(),
    };
    let mut flow = FlowInfo::new(fd, &env);
    if let Some((baddr, eaddr)) = range {
        flow.set_range(baddr, eaddr);
    }
    // C++ Funcdata::followFlow (decompiler/cpp/funcdata_op.cc:765): after the
    // FlowInfo is constructed (and its range set), followFlow applies the global
    // flow options and the instruction bound.
    // `flowoptions` defaults to `error_toomanyinstructions` and
    // `max_instructions` to 100000 (`resetDefaultsInternal`); the console
    // options `maxinstruction` / `errortoomanyinstructions` / `unimplemented` /
    // `jumpload` mutate them (options.cc ports in `p0_knowledge/options.rs`).
    flow.set_flags(arch.flowoptions);
    flow.set_maximum_instructions(arch.max_instructions);
    // C++ followFlow: generateOps() then generateBlocks().  The jump-table
    // recovery loop runs inside generateOps (via the action sub-pipeline).
    {
        let arch_ptr: *mut Architecture = arch;
        let mut run_jt_pipeline = |partial: &mut Funcdata,
                                   visited: &crate::flow::VisitedMap|
         -> Result<(), crate::flow::JtPipelineError> {
            // SAFETY: `arch_ptr` aliases the live `&mut Architecture`; the env's
            // reads (`translate`/`inst`/`symboltab`) are disjoint from the
            // `allacts` mutation here, and the `flow` borrow of `env`/`arch` does
            // not overlap this closure's run (it is only active between calls).
            let arch_mut: &mut Architecture = unsafe { &mut *arch_ptr };
            run_jumptable_pipeline(arch_mut, partial, visited)
        };
        flow.generate_ops_with_jumptables(&mut run_jt_pipeline)?;
    }
    flow.generate_blocks()?;
    // C++ followFlow: switchOverJumpTables(flow) — map each recovered table's
    // addresses to the basic-block out-edges (the `target` surface is
    // `FlowInfo::target`).  Drive it before the FlowInfo is consumed.
    let target_snapshot = flow.target_index_snapshot();
    let mut data = flow.data;
    data.switch_over_jump_tables(|fd, addr| {
        crate::flow::target_in(fd, &target_snapshot, addr)
    })?;
    // C++ `Funcdata::startProcessing` (funcdata.cc:150) runs after `followFlow`:
    // it calls `structureReset()` — which builds the basic-block reverse-post
    // ordering AND the forward dominator tree (`bblocks.calcForwardDominator`).
    // `ActionHeritage::buildADT` *requires* that dominator tree, so the reset is
    // part of the heritage-application prerequisite (the merged tree's
    // `ActionStart` is a stub, so it is driven here, exactly as the C++
    // `followFlow`→`startProcessing` order runs it before the action pipeline).
    data.structure_reset();
    // C++ startProcessing also calls sortCallSpecs() (dominance order for the
    // call-spec list); now that qlst exists, sort it.
    data.sort_call_specs();
    // startProcessing then sets the processing_started flag (so isProcStarted()
    // is true; the rest of startProcessing — sortCallSpecs / buildInfoList /
    // applyDeadCodeDelay — is a W4 stub or handled lazily in op_heritage).
    data.set_flag_raw(funcdata_flags::processing_started);
    // Publish buffered flow comments only after replacement construction succeeds.
    let func_addr = data.get_address().clone();
    if arch.mapped_flow_boundary_image {
        crate::kuna_mappedflowboundary::clear_stale_warnings(&mut arch.commentdb, &func_addr);
    }
    for (tp, ad, txt) in data.drain_pending_comments() {
        arch.commentdb.add_comment_no_duplicate(tp, &func_addr, &ad, &txt);
    }
    Ok(data)
}

/// Run the reduced "jumptable" universalAction on a partial-clone Funcdata (the
/// `partial.truncatedFlow` block-build + `allacts.setCurrent("jumptable")` +
/// reset + perform of C++ `Funcdata::stageJumpTable`, funcdata_block.cc:512).
///
/// The partial already has its ops + jump-tables cloned; this builds its basic
/// blocks (seeded with the source flow's `visited`), runs `structureReset` +
/// `sortCallSpecs` (the `startProcessing` prerequisites), then drives the
/// "jumptable" action set to simplify it so the BRANCHIND's switch calculation
/// becomes a straight-line index expression the recovery can emulate.
#[allow(clippy::mutable_key_type)]
fn run_jumptable_pipeline(
    arch: &mut Architecture,
    partial: &mut Funcdata,
    visited: &crate::flow::VisitedMap,
) -> Result<(), crate::flow::JtPipelineError> {
    // Build the partial's basic blocks (partialflow.generateBlocks).
    let env = ArchFlowEnv {
        mapped_image: None,
        arch: arch as *const Architecture,
        return_discard_memo: Default::default(),
    };
    crate::flow::build_partial_blocks(partial, &env, visited)?;
    // startProcessing prerequisites for heritage (forward dominators + RPO).
    partial.structure_reset();
    partial.sort_call_specs();
    partial.set_flag_raw(funcdata_flags::processing_started);
    // Run the reduced "jumptable" universalAction root over the partial.
    let saved = selected_action_name(arch)?;
    arch.allacts.set_current("jumptable")?;
    let mut ctx = ActionContext::new();
    // (kuna decompile-all watchdog) The jumptable sub-pipeline runs inside the
    // budgeted per-function drive (flow-follow), so it shares the same deadline;
    // `None` on every unbudgeted path (console/parity — structurally unchanged).
    ctx.deadline = arch.kuna_fn_deadline;
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let root = arch
            .allacts
            .get_current_mut()
            .ok_or_else(|| KunaError::lowlevel("no current jumptable action"))?;
        root.reset(partial);
        // catch_unwind so an un-ported pass stub in the sub-pipeline degrades to a
        // recoverable error (the recovery falls back to truncating the BRANCHIND),
        // never an abort — same policy as the main `decompile_func_full` drive.
        Ok::<_, KunaError>(root.perform(partial, &mut ctx))
    }));
    // Restore the previous action set regardless of outcome.
    arch.allacts.set_current(&saved).map_err(crate::flow::JtPipelineError::Fatal)?;
    if let Some(error) = ctx.take_error() {
        return Err(crate::flow::JtPipelineError::Fatal(error));
    }
    match result {
        Ok(Ok(r)) => {
            if r < 0 {
                return Err(KunaError::lowlevel("jumptable pipeline hit a breakpoint").into());
            }
            Ok(())
        }
        Ok(Err(error)) => Err(error.into()),
        Err(payload) => Err(KunaError::lowlevel(format!(
            "jumptable pipeline reached an un-ported seam: {}",
            panic_message(payload)
        )).into()),
    }
}

/// Run the selected universalAction root to completion against `fd` (C++
/// `IfcDecompile::execute`, ifacedecomp.cc:889 — `getCurrent()->reset(fd)` then
/// `getCurrent()->perform(fd)`).  Returns the perform result (`>=0` change
/// count, `<0` on a breakpoint).
///
/// The action root owns the restart loop (C++ non-virtual `Action::perform`,
/// already ported in `action.rs`); this drives it through the engine-side
/// [`ActionContext`] so the warning-emission points are observable.
/// Per-drive dependency closure: no inferred facts are persisted in Override or
/// the immutable declaration ABI cache. A cut is explicit, never an empty ABI.
#[derive(Clone, PartialEq, Eq)]
struct RawNativeFingerprint {
    opcode: kuna_num::opcodes::OpCode,
    entry: Address,
    inputs: Vec<(Address, int4)>,
    output: Option<(Address, int4)>,
    flow_override: kuna_base::types::uint4,
}

struct RawNativeSite {
    fingerprint: RawNativeFingerprint,
    authority: crate::fspec::FuncProto,
    body_unavailable: bool,
}

struct NativeReplay {
    original: RawNativeSite,
    contract: std::rc::Rc<crate::p4_calls::kuna_callabletransport::NativeCallContract>,
}

struct GeneratedReplay {
    original: RawNativeSite,
    contract: std::rc::Rc<crate::p4_calls::kuna_callabletransport::GeneratedCallContract>,
}

struct RefinedIndirectReplay {
    original: RawNativeSite,
    contract: std::rc::Rc<crate::p4_calls::kuna_callabletransport::RawIndirectContract>,
}

impl PhysicalInputDrive {
    fn native_site(&self, arch: &Architecture, data: &Funcdata, index: int4) -> KunaResult<Option<RawNativeSite>> {
        use kuna_num::opcodes::OpCode;
        let call = data.get_call_specs(index);
        let Some(operation) = data.obank().get(call.get_op()) else { return Ok(None) };
        if !matches!(operation.code(), OpCode::CPUI_CALL | OpCode::CPUI_CALLIND) { return Ok(None); }
        let direct = operation.code() == OpCode::CPUI_CALL;
        let body_unavailable = if direct {
            if call.get_entry_address().is_invalid() { return Ok(None); }
            let loader = arch.translate().loader_rc();
            let Ok(mut loader) = loader.try_borrow_mut() else { return Ok(None) };
            match loader.load_fill(&mut [0u8; 1], call.get_entry_address()) {
                Ok(()) => false,
                Err(KunaError::DataUnavail { .. }) => self.no_real_bodies.contains(call.get_entry_address()),
                Err(error) => return Err(error),
            }
        } else { false };
        if direct && !body_unavailable
            && crate::p4_calls::kuna_callabletransport::generated_direct_result_entry(data, call.get_op())?.is_none() {
            return Ok(None);
        }
        let storage = |id| data.vbank().get(id)
            .map(|value| (value.get_addr().clone(), value.get_size()));
        let mut inputs = Vec::with_capacity(operation.num_input().max(0) as usize);
        for slot in (if direct { 1 } else { 0 })..operation.num_input() {
            let Some(input) = operation.get_in(slot).and_then(storage) else { return Ok(None) };
            inputs.push(input);
        }
        Ok(Some(RawNativeSite {
            fingerprint: RawNativeFingerprint {
                opcode: operation.code(), entry: call.get_entry_address().clone(), inputs,
                output: operation.get_out().and_then(storage),
                flow_override: data.get_override().get_flow_override(operation.get_addr()),
            },
            authority: call.proto().source_prototype(), body_unavailable,
        }))
    }

    fn seed_native(&mut self, arch: &Architecture, data: &mut Funcdata) -> KunaResult<()> {
        use crate::p4_calls::kuna_callabletransport::native_source_abi_equal;
        self.native_sites.clear();
        let mut admitted = std::collections::BTreeMap::new();
        if data.get_arch().execution_callable_c {
            for index in 0..data.num_calls() {
                let Some(site) = self.native_site(arch, data, index)? else { continue };
                let call = data.get_call_specs(index);
                let sequence = data.obank().get(call.get_op()).expect("raw call").get_seq_num().clone();
                if let Some(replay) = self.native_replays.get(&sequence) {
                    if site.fingerprint == replay.original.fingerprint
                        && site.body_unavailable == replay.original.body_unavailable
                        && native_source_abi_equal(&site.authority, &replay.original.authority) {
                        admitted.insert(call.get_op(), replay.contract.clone());
                    }
                }
                self.native_sites.insert(sequence, site);
            }
        }
        // Replacing seed premises invalidates the preceding epoch's own proof.
        data.set_native_execution_contracts(admitted);
        Ok(())
    }

    fn generated_targets(&mut self, arch: &mut Architecture, data: &Funcdata)
        -> KunaResult<BTreeMap<Address, std::rc::Rc<crate::p4_calls::kuna_callabletransport::GeneratedBodyTarget>>>
    {
        let entries = std::mem::take(&mut self.generated_entries);
        let result = (|| {
            let mut targets = BTreeMap::new();
            for entry in &entries {
                let raw = self.summary(arch, entry)?;
                let witness = self.mapped_bodies.get(entry).cloned();
                if let Some(target) = crate::p4_calls::kuna_callabletransport::generated_body_target(
                    data, entry, raw, witness)? {
                    targets.insert(entry.clone(), target);
                }
            }
            Ok(targets)
        })();
        self.generated_entries = entries;
        result
    }

    fn seed_generated(&self, data: &mut Funcdata,
        targets: &BTreeMap<Address, std::rc::Rc<crate::p4_calls::kuna_callabletransport::GeneratedBodyTarget>>)
        -> KunaResult<()>
    {
        use crate::p4_calls::kuna_callabletransport::{native_source_abi_equal, rebind_generated_contract};
        let mut admitted = BTreeMap::new();
        if data.get_arch().execution_callable_c {
            for index in 0..data.num_calls() {
                let call = data.get_call_specs(index);
                let Some(operation) = data.obank().get(call.get_op()) else { continue; };
                let sequence = operation.get_seq_num();
                let Some(original) = self.native_sites.get(sequence) else { continue; };
                let Some(replay) = self.generated_replays.get(sequence) else { continue; };
                if original.fingerprint != replay.original.fingerprint
                    || original.body_unavailable != replay.original.body_unavailable
                    || !native_source_abi_equal(&original.authority, &replay.original.authority) { continue; }
                if let Some(contract) = rebind_generated_contract(data, call.get_op(), &replay.contract, targets)? {
                    admitted.insert(call.get_op(), std::rc::Rc::new(contract));
                }
            }
        }
        data.set_generated_execution_contracts(admitted);
        Ok(())
    }

    fn seed_refined_indirect(&self, data: &mut Funcdata) -> KunaResult<()> {
        use crate::p4_calls::kuna_callabletransport::{native_source_abi_equal, rebind_refined_indirect_contract};
        let mut admitted = BTreeMap::new();
        if data.get_arch().execution_callable_c {
            for index in 0..data.num_calls() {
                let call = data.get_call_specs(index);
                let Some(operation) = data.obank().get(call.get_op()) else { continue; };
                let sequence = operation.get_seq_num();
                let Some(original) = self.native_sites.get(sequence) else { continue; };
                let Some(replay) = self.refined_indirect_replays.get(sequence) else { continue; };
                if original.fingerprint != replay.original.fingerprint
                    || original.body_unavailable != replay.original.body_unavailable
                    || !native_source_abi_equal(&original.authority, &replay.original.authority) { continue; }
                if rebind_refined_indirect_contract(data, call.get_op(), &replay.contract)? {
                    admitted.insert(call.get_op(), std::rc::Rc::clone(&replay.contract));
                }
            }
        }
        data.set_refined_indirect_contracts(admitted);
        Ok(())
    }

    fn refine_execution(&mut self, arch: &mut Architecture, data: &Funcdata) -> KunaResult<bool> {
        use crate::p4_calls::kuna_callabletransport::{native_call_contract, generated_call_contract,
            generated_target_requests, refined_indirect_contract};
        if self.execution_refined || !data.get_arch().execution_callable_c { return Ok(false); }
        self.execution_refined = true;
        self.branch_replays = crate::p4_calls::kuna_branchreachability::completed_replays(data);
        self.generated_entries = generated_target_requests(data)?;
        self.active.insert(data.get_address().clone());
        let targets = self.generated_targets(arch, data);
        self.active.remove(data.get_address());
        let targets = targets?;
        for index in 0..data.num_calls() {
            let call = data.get_call_specs(index);
            let Some(operation) = data.obank().get(call.get_op()).filter(|operation| !operation.is_dead()) else { continue };
            let sequence = operation.get_seq_num();
            let Some(original) = self.native_sites.get(sequence) else { continue };
            if operation.code() != original.fingerprint.opcode
                || call.get_entry_address() != &original.fingerprint.entry
                || data.get_override().get_flow_override(operation.get_addr()) != original.fingerprint.flow_override {
                continue;
            }
            if let Some(contract) = generated_call_contract(data, call.get_op(), &targets)? {
                let original = self.native_sites.remove(sequence).expect("matched generated seed");
                self.generated_replays.insert(sequence.clone(), GeneratedReplay {
                    original, contract: std::rc::Rc::new(contract),
                });
                continue;
            }
            if let Some(contract) = refined_indirect_contract(data, call.get_op())? {
                let original = self.native_sites.remove(sequence).expect("matched refined indirect seed");
                self.refined_indirect_replays.insert(sequence.clone(), RefinedIndirectReplay {
                    original, contract: std::rc::Rc::new(contract),
                });
                continue;
            }
            let Some(contract) = native_call_contract(data, call.get_op(), original.body_unavailable)? else { continue };
            let original = self.native_sites.remove(sequence).expect("matched native seed");
            self.native_replays.insert(sequence.clone(), NativeReplay { original, contract: std::rc::Rc::new(contract) });
        }
        Ok(!self.native_replays.is_empty() || !self.generated_replays.is_empty()
            || !self.refined_indirect_replays.is_empty() || !self.branch_replays.is_empty())
    }
}

#[derive(Default)]
struct PhysicalInputDrive {
    summaries: std::collections::BTreeMap<Address, std::rc::Rc<crate::p4_calls::kuna_physicalinputs::EntryRequirements>>,
    active: std::collections::BTreeSet<Address>,
    decoded: usize,
    native_sites: BTreeMap<kuna_base::address::SeqNum, RawNativeSite>,
    native_replays: BTreeMap<kuna_base::address::SeqNum, NativeReplay>,
    generated_replays: BTreeMap<kuna_base::address::SeqNum, GeneratedReplay>,
    generated_entries: BTreeSet<Address>,
    refined_indirect_replays: BTreeMap<kuna_base::address::SeqNum, RefinedIndirectReplay>,
    execution_refined: bool,
    branch_replays: Vec<std::rc::Rc<crate::p4_calls::kuna_branchreachability::BranchReplay>>,
    no_real_bodies: BTreeSet<Address>,
    mapped_bodies: BTreeMap<Address, std::rc::Rc<crate::p4_calls::kuna_physicalinputs::MappedBodyWitness>>,
}

impl PhysicalInputDrive {
    fn summary(&mut self, arch: &mut Architecture, entry: &Address)
        -> KunaResult<std::rc::Rc<crate::p4_calls::kuna_physicalinputs::EntryRequirements>>
    {
        use crate::p4_calls::kuna_physicalinputs::{EntryRequirements, from_raw_flow};
        if arch.kuna_fn_deadline.is_some_and(|deadline| std::time::Instant::now() >= deadline) {
            return Err(KunaError::lowlevel("Physical call analysis exceeded function deadline"));
        }
        if let Some(summary) = self.summaries.get(entry) { return Ok(summary.clone()); }
        if self.decoded >= 32 || !self.active.insert(entry.clone()) {
            return Ok(std::rc::Rc::new(EntryRequirements::default()));
        }
        self.decoded += 1;
        let lifted = (|| {
            let mut probe = arch.new_funcdata("", entry.clone(), 0)?;
            if !probe.get_func_proto().has_store() {
                let context = probe.get_arch().clone();
                if let Some(pieces) = context.callee_proto_pieces(entry) {
                    probe.apply_locked_prototype_with_model(&pieces, context.callee_proto_model(entry))?;
                }
            }
            follow_flow_on_fd(arch, probe)
        })();
        let mut mapped = false;
        let summary = match lifted {
            Ok(probe) => {
                let no_real_body = probe.obank().iter_all().all(|(_, op)| {
                    let operation = probe.obank().get(op).expect("raw target operation");
                    operation.code() == OpCode::CPUI_RETURN && operation.get_halt_type() != 0
                        && operation.num_input() == 1 && operation.get_out().is_none()
                        && operation.get_in(0).and_then(|id| probe.vbank().get(id))
                            .is_some_and(|value| value.is_constant() && value.get_offset() == 1)
                });
                if no_real_body { self.no_real_bodies.insert(entry.clone()); }
                // This witnesses only a real, closed target-own CFG. Nested call
                // cuts remain in its raw requirements and need actual bodies.
                mapped = probe.get_arch().execution_callable_c && !no_real_body
                    && probe.bblocks_get_size() > 0 && !probe.has_bad_data() && !probe.has_unimplemented()
                    && probe.flags() & crate::funcdata::funcdata_flags::jumptablerecovery_on == 0
                    && probe.obank().iter_all().all(|(_, id)| probe.obank().get(id).is_some_and(|operation|
                        operation.get_halt_type() == 0 && (operation.code() != OpCode::CPUI_BRANCHIND
                            || probe.find_jump_table_index(id).is_some_and(|index|
                                probe.get_jump_table(index as int4).num_entries() != 0))));
                let mut callees = std::collections::BTreeMap::new();
                for index in 0..probe.num_calls() {
                    let call = probe.get_call_specs(index);
                    if !call.get_entry_address().is_invalid() {
                        let child = self.summary(arch, call.get_entry_address())?;
                        callees.insert(call.get_op(), child);
                    }
                }
                // Probe-local operation identities never enter cross-target caches.
                from_raw_flow(&probe, &callees, None).requirements
            }
            Err(_) => EntryRequirements { incomplete_flow: true, ..Default::default() },
        };
        self.active.remove(entry);
        let summary = std::rc::Rc::new(summary);
        if mapped {
            self.mapped_bodies.insert(entry.clone(), std::rc::Rc::new(
                crate::p4_calls::kuna_physicalinputs::MappedBodyWitness::new(entry.clone(), summary.clone())));
        }
        self.summaries.insert(entry.clone(), summary.clone());
        Ok(summary)
    }

    fn seed_deferred(&self, data: &mut Funcdata,
        callees: &BTreeMap<crate::context::OpId, std::rc::Rc<crate::p4_calls::kuna_physicalinputs::EntryRequirements>>)
        -> KunaResult<()>
    {
        let mut admitted = BTreeMap::new();
        if data.get_arch().execution_callable_c {
            for index in 0..data.num_calls() {
                let call = data.get_call_specs(index);
                let Some(raw) = callees.get(&call.get_op()) else { continue };
                let Some(witness) = self.mapped_bodies.get(call.get_entry_address()) else { continue };
                if !std::rc::Rc::ptr_eq(raw, witness.raw()) { continue; }
                if let Some(contract) = crate::p4_calls::kuna_callabletransport::raw_deferred_contract(
                    data, call.get_op(), raw.clone(), witness.clone())? {
                    admitted.insert(call.get_op(), std::rc::Rc::new(contract));
                }
            }
        }
        data.set_deferred_execution_contracts(admitted);
        Ok(())
    }

    fn seed(&mut self, arch: &mut Architecture, data: &mut Funcdata) -> KunaResult<()> {
        use crate::p4_calls::kuna_physicalinputs::{from_raw_flow, has_narrow_source};
        // Explicit/parked entry declarations are installed before this point.
        // Adopted raw IR also needs the same unlocked-model prerequisite before
        // source/branch/body facts are captured for this flow epoch.
        data.select_analysis_model();
        let proto = data.get_func_proto();
        let ambient = proto.has_store() && proto.is_input_locked() && !proto.is_dotdotdot()
            && proto.num_params() == 0;
        let context = data.get_arch();
        fn callable_value(ty: &crate::dtype::TypeRoot) -> bool {
            ty.get_ptr_to().is_some_and(|target| target.get_metatype() == crate::dtype::type_metatype::TYPE_CODE)
        }
        fn callable_source(proto: &crate::fspec::FuncProto) -> bool {
            proto.has_store() && (proto.source_output().get_type().is_some_and(callable_value)
                || (0..proto.num_params()).filter_map(|slot| proto.source_param(slot))
                    .any(|parameter| parameter.get_type().is_some_and(callable_value)))
        }
        let mut callable_boundary = callable_source(proto);
        let mut relevant = has_narrow_source(proto) || proto.has_execution_signature() || ambient;
        for index in 0..data.num_calls() {
            let entry = data.get_call_specs(index).get_entry_address();
            if let Some(proto) = context.remote_scope.as_ref().and_then(|remote| remote.prototype_at(entry)) {
                callable_boundary |= callable_source(&proto);
                relevant |= has_narrow_source(&proto) || proto.has_execution_signature()
                    || (proto.has_store() && proto.is_input_locked() && !proto.is_dotdotdot() && proto.num_params() == 0);
            } else if let Some(pieces) = context.callee_proto_pieces(entry) {
                callable_boundary |= pieces.outtype.as_ref().is_some_and(callable_value)
                    || pieces.intypes.iter().any(callable_value);
                relevant |= (pieces.intypes.is_empty() && pieces.outtype.is_some() && pieces.first_var_arg_slot < 0)
                    || pieces.intypes.iter().any(|ty| ty.get_size() < 8 && matches!(ty.get_metatype(),
                        crate::dtype::type_metatype::TYPE_INT | crate::dtype::type_metatype::TYPE_UINT
                        | crate::dtype::type_metatype::TYPE_ENUM_INT | crate::dtype::type_metatype::TYPE_ENUM_UINT
                        | crate::dtype::type_metatype::TYPE_BOOL));
            }
        }
        relevant |= callable_boundary;
        // Executable C needs raw effect evidence for ordinary full-width and
        // inferred entries too; declaration width cannot prove preservation.
        if !relevant && !context.execution_callable_c { return Ok(()); }
        // A reflow can install authoritative indirect/flow overrides. Summaries
        // belong to this flow epoch; never reuse a previous epoch's proof.
        self.summaries.clear();
        self.no_real_bodies.clear();
        self.mapped_bodies.clear();
        self.decoded = 0;
        self.active.insert(data.get_address().clone());
        if callable_boundary {
            let mut targets = std::collections::BTreeSet::new();
            if let Some(space) = data.get_address().get_space() {
                for id in data.vbank().iter_loc() {
                    let value = data.vbank().get(id).expect("live raw value");
                    if !value.is_constant() { continue; }
                    let candidate = Address::new(space.clone(), kuna_base::space::AddrSpace::address_to_byte(
                        value.get_offset(), space.get_word_size()));
                    if let Some((_, entry, _)) = data.get_arch().query_function(&candidate)? {
                        targets.insert(entry);
                    }
                }
            }
            for entry in targets {
                let summary = self.summary(arch, &entry)?;
                data.set_physical_target_requirements(entry, summary);
            }
        }
        let mut callees = std::collections::BTreeMap::new();
        for index in 0..data.num_calls() {
            let entry = data.get_call_specs(index).get_entry_address().clone();
            if entry.is_invalid() { continue; }
            let summary = self.summary(arch, &entry)?;
            callees.insert(data.get_call_specs(index).get_op(), summary.clone());
            data.set_physical_target_requirements(entry, summary.clone());
            data.get_call_specs_mut(index).set_physical_requirements(summary);
        }
        let generated = self.generated_targets(arch, data)?;
        self.active.remove(data.get_address());
        self.seed_native(arch, data)?;
        self.seed_generated(data, &generated)?;
        self.seed_refined_indirect(data)?;
        self.seed_deferred(data, &callees)?;
        if data.get_arch().execution_callable_c {
            crate::p4_calls::kuna_branchreachability::seed_raw(data, &self.branch_replays)?;
        }
        let flow = crate::p4_calls::kuna_physicalinputs::ConditionalFlowView::from_receipts(data)?;
        // Scan the caller's actual raw IR, including its request-local Override.
        // A recursive edge is an explicit incomplete cut, not a fresh unoverridden body.
        let own = from_raw_flow(data, &callees, flow);
        data.set_entry_physical_analysis(own);
        if data.get_arch().execution_callable_c {
            let seed = crate::p4_calls::kuna_logicalresultbody::capture_logical_result_body(data)?;
            data.set_logical_result_body_seed(seed.map(std::rc::Rc::new));
        }
        Ok(())
    }
}

fn run_pipeline(
    arch: &mut Architecture,
    fd: &mut Funcdata,
    entry_proto: Option<&crate::fspec::FuncProto>,
) -> KunaResult<int4> {
    // Selection belongs to the caller. Host requests may deliberately select
    // a reduced root while still needing this drive's complete seed/reflow path.
    arch.allacts.get_current().ok_or_else(|| KunaError::lowlevel("no current action"))?;
    // The action loop's in-loop restart cannot re-follow flow (no SLEIGH
    // translator inside `allacts`); it hands a pending restart up here via
    // `ctx.reflow_requested`.  This outer loop owns `&mut Architecture`, so it can
    // `clear()` + re-`followFlow` the IR (C++ `clearAnalysis` + `ActionStart` →
    // `startProcessing`) and re-perform the root — exactly the C++ restart
    // semantics, just relocated out of the borrow-restricted action loop.  Bound
    // the iterations defensively (the action layer's own `maxrestarts` already
    // caps in-loop restarts; this caps cross-flow restarts).
    const MAX_REFLOW: int4 = 8;
    let mut total: int4 = 0;
    let mut physical_inputs = PhysicalInputDrive::default();
    for _ in 0..=MAX_REFLOW {
        physical_inputs.seed(arch, fd)?;
        let res = {
            let deadline = arch.kuna_fn_deadline;
            let root = arch
                .allacts
                .get_current_mut()
                .ok_or_else(|| kuna_base::error::KunaError::lowlevel("no current action"))?;
            root.reset(fd);
            let mut ctx = ActionContext::new();
            // (kuna decompile-all watchdog) thread the per-function deadline
            // into the action loop (`None` = no budget, the parity default).
            ctx.deadline = deadline;
            let r = root.perform(fd, &mut ctx);
            if let Some(error) = ctx.take_error() {
                return Err(error);
            }
            (r, ctx.reflow_requested)
        };
        let (r, reflow_requested) = res;
        // (kuna decompile-all watchdog) A budgeted drive that ran past its
        // deadline unwound cooperatively (the action/heritage loops stop
        // scheduling work); surface it as the per-function error the batch
        // driver records, instead of printing a half-analyzed function.
        if let Some(deadline) = arch.kuna_fn_deadline {
            if std::time::Instant::now() >= deadline {
                let secs = arch.kuna_fn_budget.map(|b| b.as_secs()).unwrap_or(0);
                return Err(kuna_base::error::KunaError::lowlevel(format!(
                    "per-function decompile budget exceeded ({secs} s)"
                )));
            }
        }
        if r < 0 {
            return Ok(r); // breakpoint — propagate verbatim (no re-flow)
        }
        total += r;
        let flow_requested = reflow_requested && fd.has_restart_pending();
        let conditional_requested = !flow_requested && physical_inputs.refine_execution(arch, fd)?;
        if !flow_requested && !conditional_requested {
            crate::p4_calls::kuna_branchreachability::validate_final(fd)?;
            drain_pipeline_comments(arch, fd);
            return Ok(total);
        }
        // Re-follow flow against the same Funcdata (its Override — incl. the
        // deindirect's indirect override — survives `clear()`), then loop to
        // re-perform.  `clear()` resets the restart flag, so a fresh request must
        // come from the re-flowed pass to loop again.
        let execution_seed = if fd.get_func_proto().has_execution_signature() {
            let mut seed = crate::fspec::FuncProto::new();
            seed.copy(fd.get_func_proto());
            Some(seed)
        } else { None };
        refollow_flow(arch, fd, execution_seed.as_ref().or(entry_proto))?;
        // (kuna `rustabi`) The re-flow hands back a FRESH Funcdata, so the
        // callee-body evidence has to be taken again or the call-output seam
        // silently loses its veto on every restarted function.  Cached, so this
        // is a map lookup per call.
        crate::kuna_rustabi::seed_callee_return_writes(arch, fd);
        // (kuna `calleedeadarg`) Same story for the entry-liveness probe the
        // input-trial scoring seam consults.
        crate::p4_calls::kuna_calleedeadarg::seed_callee_entry_dead(arch, fd);
        // (kuna `protoorder types`) And for the parameter types earlier callees stated.
        crate::p4_calls::kuna_protoorder::seed_protoorder_types(arch, fd);
        crate::p4_calls::kuna_calleevote::seed(arch, fd);
        // (kuna `calleepreserves`) And for the call-guard seam's view of the
        // callee's writes; shares rustabi's cache, so this is a map lookup.
        crate::p4_calls::kuna_calleepreserves::seed_callee_preserves(arch, fd);
    }
    // The last iteration requested new physical input state but has not analyzed
    // its re-lifted IR. Publishing that shell would silently discard live bits.
    Err(KunaError::lowlevel("Cross-flow refinement did not converge"))
}

/// Flush any analysis comments the **action pipeline** buffered on the `Funcdata`
/// (e.g. the `branchflip:` warning that `ActionBranchFlip` records at S8) into the
/// comment database for emit.  The flow-time `Funcdata::warning`s are drained in
/// `follow_flow_on_fd` before the pipeline runs; warnings raised *inside* the
/// pipeline land here.  No-op when nothing was buffered.
fn drain_pipeline_comments(arch: &mut Architecture, fd: &mut Funcdata) {
    let func_addr = fd.get_address().clone();
    for (tp, ad, txt) in fd.drain_pending_comments() {
        arch.commentdb.add_comment_no_duplicate(tp, &func_addr, &ad, &txt);
    }
}

#[cfg(feature = "test-support")]
#[doc(hidden)]
pub fn test_readonly_receipt_replay(arch: &mut Architecture, fd: &mut Funcdata) -> KunaResult<()> {
    crate::p4_calls::kuna_branchreachability::replay_tests::run(arch, fd)
}

#[cfg(feature = "test-support")]
#[doc(hidden)]
pub fn test_internal_body_coverage(fd: &Funcdata) -> KunaResult<Vec<(Address, int4)>> {
    fd.internal_constant_body_coverage()
}

/// Re-follow flow on an existing, already-analyzed `fd` after a restart request
/// (C++ `ActionRestartGroup` → `clearAnalysis` + `ActionStart::startProcessing` →
/// `followFlow`).  Clears the analysis-derived IR (`Funcdata::clear`) while
/// preserving the per-function `Override`, then re-runs the flow follow in place.
#[allow(clippy::mutable_key_type)]
pub(crate) fn refollow_flow(
    arch: &mut Architecture,
    fd: &mut Funcdata,
    entry_proto: Option<&crate::fspec::FuncProto>,
) -> KunaResult<()> {
    // C++ `glb->clearAnalysis(&data)` == fd->clear() (the comment-DB clear is the
    // W4 stub) — drops ops/vbank/blocks/qlst/heritage but keeps `localoverride`.
    fd.clear();
    if let Some(seed) = entry_proto {
        fd.get_func_proto_mut().copy(seed);
    }
    // Move the cleared shell out so `follow_flow_on_fd` can re-flow it (it takes
    // `fd` by value, mirroring the fresh-build path), then put the re-flowed IR
    // back into the caller's slot.  The throwaway placeholder is a minimal valid
    // Funcdata at the same entry (so `new_funcdata`'s space lookup succeeds); it is
    // immediately overwritten by the re-flowed result.
    let entry = fd.get_address().clone();
    let placeholder = arch.new_funcdata("", entry, 0)?;
    let shell = std::mem::replace(fd, placeholder);
    *fd = follow_flow_on_fd(arch, shell)?;
    Ok(())
}

/// Decompile the function `name` at `funcaddr` to a ready-to-print
/// [`Funcdata`] (C++ `IfcDecompile`): build the IR (follow flow), then run the
/// selected universalAction root to completion.
///
/// `size` bounds the flow follow (0 = unbounded, the function's natural extent).
/// On success the returned `Funcdata` has its IR built and the pipeline run; it
/// is ready for the selected root's consumers. Full C output requires the
/// `decompile` root. The universalAction must already be installed on
/// the architecture (via [`Architecture::build_action`] / `init_post_engine`).
pub fn decompile_func(
    arch: &mut Architecture,
    name: &str,
    funcaddr: Address,
    size: int4,
) -> KunaResult<Funcdata> {
    decompile_func_with_symbols(arch, name, funcaddr, size, &[])
}

/// Like [`decompile_func`], but seeds the freshly-built `Funcdata`'s local scope
/// with console-mapped Symbol specs (`map addr`).  The kuna console rebuilds the
/// IR on `decompile` (C++ reuses the same `fd`); this carries the `map addr`
/// symbols across that rebuild so stack-variable promotion can name them.
pub fn decompile_func_with_symbols(
    arch: &mut Architecture,
    name: &str,
    funcaddr: Address,
    size: int4,
    mapped_symbols: &[(String, crate::dtype::TypeRoot, Address, kuna_base::types::uint4)],
) -> KunaResult<Funcdata> {
    decompile_func_full(arch, name, funcaddr, size, mapped_symbols, None)
}

/// The full decompile drive: like [`decompile_func_with_symbols`] but also
/// applies a parsed-and-locked input/output prototype (`parse line extern
/// <decl>`) to the fresh `Funcdata` before the pipeline runs (C++
/// `Architecture::setPrototype` on the queried `Funcdata`).
///
/// The console captures the [`PrototypePieces`](crate::fspec::PrototypePieces)
/// at `parse line` and stashes them by name; the decompile rebuilds the IR, so
/// the lock must be re-applied to the fresh `funcp` here — the seed that lets
/// `ActionPrototypeTypes` force the typed input/output Varnodes and the type
/// plane (`ActionInferTypes`) flow from them.
pub fn decompile_func_full(
    arch: &mut Architecture,
    name: &str,
    funcaddr: Address,
    size: int4,
    mapped_symbols: &[(String, crate::dtype::TypeRoot, Address, kuna_base::types::uint4)],
    pending_proto: Option<&crate::fspec::PrototypePieces>,
) -> KunaResult<Funcdata> {
    decompile_func_full_with_override(arch, name, funcaddr, size, mapped_symbols, pending_proto, &[])
}

/// Like [`decompile_func_full`], but also seeds the per-function flow `Override`
/// (`override flow <addr> <type>`) before flow follows — see
/// [`build_and_follow_flow_with_override`].
#[allow(clippy::too_many_arguments)]
pub fn decompile_func_full_with_override(
    arch: &mut Architecture,
    name: &str,
    funcaddr: Address,
    size: int4,
    mapped_symbols: &[(String, crate::dtype::TypeRoot, Address, kuna_base::types::uint4)],
    pending_proto: Option<&crate::fspec::PrototypePieces>,
    flow_overrides: &[(Address, kuna_base::types::uint4)],
) -> KunaResult<Funcdata> {
    decompile_func_full_with_override_dyn(
        arch,
        name,
        funcaddr,
        size,
        mapped_symbols,
        &[],
        &[],
        pending_proto,
        flow_overrides,
        &crate::overrides::Override::new(),
        &[],
    )
}

/// Like [`decompile_func_full_with_override`], but also re-seeds the console-added
/// dynamic (`map hash`) symbols (`(name, type, hashAddr, hash)`) into the rebuilt
/// local scope, so `ActionDynamicSymbols` can name the matched temporaries.
#[allow(clippy::too_many_arguments)]
pub fn decompile_func_full_with_override_dyn(
    arch: &mut Architecture,
    name: &str,
    funcaddr: Address,
    size: int4,
    mapped_symbols: &[(String, crate::dtype::TypeRoot, Address, kuna_base::types::uint4)],
    usepoint_symbols: &[(String, crate::dtype::TypeRoot, Address, kuna_base::types::uint4, Address, bool)],
    dynamic_symbols: &[crate::database::DynamicSymbolSpec],
    pending_proto: Option<&crate::fspec::PrototypePieces>,
    flow_overrides: &[(Address, kuna_base::types::uint4)],
    proto_overrides: &crate::overrides::Override,
    mapped_params: &[(int4, String, crate::fspec::ParameterPieces)],
) -> KunaResult<Funcdata> {
    decompile_func_full_with_override_dyn_prefollowed(
        arch,
        name,
        funcaddr,
        size,
        mapped_symbols,
        usepoint_symbols,
        dynamic_symbols,
        pending_proto,
        flow_overrides,
        proto_overrides,
        mapped_params,
        None,
    )
}

/// [`decompile_func_full_with_override_dyn`], but able to adopt a `Funcdata`
/// whose flow has **already been followed** instead of following it again.
///
/// The console runs `load function <name>` and then `decompile`, and each of
/// those followed the flow of the same function from scratch -- so a `kuna
/// decompile` paid the whole lift, including the per-jump-table
/// sub-decompilation, twice.  C++ has no such duplication: `IfcFuncload`
/// follows flow once and `IfcDecompile` re-runs the actions on *that*
/// `Funcdata` after `Architecture::clearAnalysis` (ifacedecomp.cc:889).
///
/// `prefollowed` is the caller's already-followed IR.  It is adopted verbatim,
/// so the caller is responsible for having followed flow with the SAME name,
/// entry, size, flow overrides and prototype overrides this call would have used
/// -- see `kuna_console::ifacedecomp` (`PristineFlow`), which only offers one
/// when every seed below is empty and nothing has run in between.  `None`
/// restores the build-and-follow behaviour every other caller has.
#[allow(clippy::too_many_arguments)]
#[allow(clippy::mutable_key_type)]
pub fn decompile_func_full_with_override_dyn_prefollowed(
    arch: &mut Architecture,
    name: &str,
    funcaddr: Address,
    size: int4,
    mapped_symbols: &[(String, crate::dtype::TypeRoot, Address, kuna_base::types::uint4)],
    usepoint_symbols: &[(String, crate::dtype::TypeRoot, Address, kuna_base::types::uint4, Address, bool)],
    dynamic_symbols: &[crate::database::DynamicSymbolSpec],
    pending_proto: Option<&crate::fspec::PrototypePieces>,
    flow_overrides: &[(Address, kuna_base::types::uint4)],
    proto_overrides: &crate::overrides::Override,
    mapped_params: &[(int4, String, crate::fspec::ParameterPieces)],
    prefollowed: Option<Funcdata>,
) -> KunaResult<Funcdata> {
    // (kuna decompile-all watchdog) Arm the per-function deadline from the
    // driver-set budget (`kuna decompile-all --max-fn-seconds N` sets
    // `kuna_fn_budget`; every other path leaves it `None`, so this is a `None`
    // assignment and the pipeline below is structurally unchanged).  The budget
    // covers the whole drive — flow-follow (incl. the jumptable sub-pipeline)
    // and the action pipeline — and is consulted cooperatively at the action /
    // rule-pool / heritage loop boundaries.
    arch.kuna_fn_deadline = arch.kuna_fn_budget.map(|b| std::time::Instant::now() + b);
    // (ghidra-mode, Phase 4) Take the staged name recommendations UP FRONT so
    // an early flow failure can never leak them into a later drive.
    let staged_name_recs = std::mem::take(&mut arch.kuna_pending_name_recs);
    let staged_dyn_recs = std::mem::take(&mut arch.kuna_pending_dyn_recs);
    let staged_proto_model = arch.kuna_pending_proto_model.take();
    let result = (|| {
        // Kept for the parked-prototype lookup below (the flow build consumes the
        // address).
        let entry_addr = funcaddr.clone();
        let mut fd = match prefollowed {
            Some(fd) => fd,
            None => build_and_follow_flow_with_override_and_protos(
                arch,
                name,
                funcaddr,
                size,
                flow_overrides,
                proto_overrides,
            )?,
        };
        // The prototype the function is decompiled *against*. Two sources, in
        // precedence order:
        //
        //  1. `pending_proto` — a prototype the operator declared for this run
        //     (`parse line extern ...`). An explicit declaration always wins.
        //  2. The prototype parked on this function's own global FunctionSymbol.
        //     That is where the DWARF pass's recovered `DW_TAG_subprogram`
        //     signature lands (`set_function_prototype_pieces`), and where the
        //     library-prototype table lands for a named libc function.
        //
        // Source 2 used to be read *only* by a CALLER — `ActionDefaultParams`
        // copies a callee's parked prototype into the call site, so `fmt(FILE*,
        // char const*)` typed its arguments correctly at every call — while the
        // function's own decompile ignored it and re-derived everything from data
        // flow. So `main`, fully described by `.debug_info` as
        // `int main(int argc, char **argv)`, rendered `undefined16 main(uint4
        // a0, void *a1)`: the recovered signature existed and was thrown away.
        //
        // Applying it locks the inputs and the output, which is also what
        // collapses the bogus wide return. With no locked output,
        // `ActionPrototypeTypes` turns on return recovery, `Heritage::guard_returns`
        // registers a trial per output register the model characterizes (x86-64
        // gcc: RAX *and* RDX), and the cspec's `join_dual_class` output rule
        // accepts the consecutive pair as one 16-byte return — materialized as
        // `PIECE(RDX,RAX)` and typed `undefined16`, with the never-written RDX half
        // picking up an uninitialized stack slot. A known `int` return skips that
        // machinery entirely.
        //
        // (kuna `cppproto`) Resolved across ALL scopes, not just the global one: a
        // demangled C++ function is filed under its namespace/class scope, so a
        // global-only lookup never finds the prototype the DWARF C++ arm parked on
        // `Account::deposit`. Inert for every prototype parked by NAME (that path
        // resolves through the global scope, so it can only reach global symbols).
        let recovered_proto = if pending_proto.is_none() {
            arch.symboltab.function_proto_pieces_across_scopes(&entry_addr).cloned()
        } else {
            None
        };
        // Apply the resolved prototype to the fresh funcp (the input-param
        // recovery SEED): after this the inputs/output are type-locked, so
        // ActionPrototypeTypes forces the typed Varnodes.
        if let Some(pieces) = pending_proto.or(recovered_proto.as_ref()) {
            // Declaration pieces retain their explicit model and all-locked
            // semantics. Host prototypes were copied by Funcdata::new without
            // passing through this declaration-only path.
            let declared_model = staged_proto_model
                .clone()
                .or_else(|| fd.get_arch().callee_proto_model(&entry_addr));
            fd.apply_locked_prototype_with_model(pieces, declared_model)?;
        }
        // Re-seed any console `map param <i> <addr> <typedecl>` storage locks (lost
        // when the IR is rebuilt, like `pending_proto`/`mapped_symbols`).  This makes
        // the rebuilt proto input-locked so `ActionPrototypeTypes` forces the typed
        // input Varnode (C++ `IfcMapParam` writes straight onto the live FuncProto).
        fd.apply_mapped_params(mapped_params);
        // Only explicit entry overrides need an extra seed: ordinary host
        // drives reuse RemoteScope's immutable canonical prototype on clear().
        let entry_seed = (pending_proto.is_some() || recovered_proto.is_some()
            || !mapped_params.is_empty()).then(|| {
                let mut seed = crate::fspec::FuncProto::new();
                seed.copy(fd.get_func_proto());
                seed
            });
        // Re-seed the console-mapped symbols (lost when the IR is rebuilt).
        fd.seed_mapped_symbols(mapped_symbols);
        // Re-seed the usepoint-scoped console symbols (the register-storage
        // `type varnode %REG(pc)` symbols, e.g. retstruct's `tmp`) WITH their use
        // address so `linkSymbol`'s usepoint query binds them at the scoped read.
        fd.seed_usepoint_symbols(usepoint_symbols);
        // Re-seed the console-added dynamic (`map hash`) symbols (likewise lost).
        fd.seed_dynamic_symbols(dynamic_symbols);
        // (ghidra-mode, Phase 4) Seed the staged name recommendations (the
        // host `<localdb>`'s rename-only locals — C++ `nameRecommend`
        // entries); empty everywhere outside ghidra mode.
        if !staged_name_recs.is_empty() {
            fd.seed_name_recommendations(&staged_name_recs);
        }
        if !staged_dyn_recs.is_empty() {
            fd.seed_dynamic_recommendations(&staged_dyn_recs);
        }
        // (kuna `rustabi`) Take the callee-body probe the call-output seam needs.
        // The per-function handle the pipeline runs against carries no
        // translator, so this is the last point the callee's instructions can be
        // read at all; inert unless `option rustabi` is live for this image.
        crate::kuna_rustabi::seed_callee_return_writes(arch, &mut fd);
        // (kuna `calleedeadarg`) Take the callee entry-liveness probe the
        // input-trial scoring seam consults, for the same reason and at the same
        // point; inert unless `option calleedeadarg` is live.
        crate::p4_calls::kuna_calleedeadarg::seed_callee_entry_dead(arch, &mut fd);
        // (kuna `protoorder types`) The parameter types callees decompiled earlier stated.
        crate::p4_calls::kuna_protoorder::seed_protoorder_types(arch, &mut fd);
        // (kuna `calleevote`) What every caller of this function passes.
        crate::p4_calls::kuna_calleevote::seed(arch, &mut fd);
        // (kuna `calleepreserves`) The call-guard seam's view of the same
        // decode: the registers the callee is proven NOT to write; inert unless
        // `option calleepreserves` is live.
        crate::p4_calls::kuna_calleepreserves::seed_callee_preserves(arch, &mut fd);
        // With the single-manager unification (LOSS-132) the universalAction passes
        // now reach the *real* lifted varnodes, so the pipeline genuinely executes
        // heritage / simplification / merge / … on live IR.  Some pass BODIES are
        // still un-ported stubs (LOSS-131, the M3 grind): a hand-built fixture never
        // reached them, but a real corpus function can hit, e.g.,
        // `Heritage::normalizeWriteSize`'s PIECE-concat path.  Those stubs abort via
        // `unimplemented_stub` (a deliberate `#[cold] panic!`).  Convert such a
        // stub-abort into a recoverable `Err` at this orchestration boundary so the
        // end-to-end harnesses degrade to the documented "honest partial parity"
        // (the pipeline ran; a body declined at a stub) instead of taking down the
        // whole run — exactly the graceful-degradation the LOSS-130/131 measurement
        // assumes.  `fd`/`arch` are discarded on the unwind, so no half-mutated
        // state escapes (`AssertUnwindSafe` is sound here for that reason).
        let res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            run_pipeline(arch, &mut fd, entry_seed.as_ref())
        }));
        match res {
            Ok(r) => {
                r?;
                Ok(fd)
            }
            Err(payload) => {
                let msg = panic_message(payload);
                Err(kuna_base::error::KunaError::lowlevel(format!(
                    "decompile pipeline reached an un-ported seam (LOSS-131): {msg}"
                )))
            }
        }
    })();
    // (kuna decompile-all watchdog) Disarm the deadline once the drive is over so
    // no later, non-drive pipeline run (console sub-queries) consults a stale one.
    arch.kuna_fn_deadline = None;
    result
}

/// (kuna) Build the IR for `name` and run a **named reduced pipeline** variant
/// over it as a sub-query (C++ `IfcKunaPipeline::execute`).
///
/// Temporarily installs the named action group
/// (`normalize`/`paramid`/`register`/`firstpass`/`jumptable`), follows flow and
/// runs it through the shared restart/error-aware drive, then restores the
/// previously selected root. The
/// resulting [`Funcdata`] holds whatever IR the reduced pipeline produced (for
/// `normalize`, no `sblocks` — `quality` then hits its `hasNoStructBlocks`
/// guard).  Stub aborts degrade to a recoverable `Err`, like the full drive.
pub fn run_named_pipeline_variant(
    arch: &mut Architecture,
    name: &str,
    funcaddr: Address,
    size: int4,
    variant: &str,
) -> KunaResult<Funcdata> {
    let saved = selected_action_name(arch)?;
    arch.allacts.set_current(variant)?;
    let res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let mut fd = build_and_follow_flow(arch, name, funcaddr, size)?;
        let r = run_pipeline(arch, &mut fd, None)?;
        if r < 0 {
            return Err(KunaError::lowlevel(format!(
                "{variant} pipeline hit a breakpoint"
            )));
        }
        Ok(fd)
    }));
    // Restore the root action regardless of outcome (C++ restores setCurrent).
    arch.allacts.set_current(&saved)?;
    match res {
        Ok(Ok(fd)) => Ok(fd),
        Ok(Err(e)) => Err(e),
        Err(payload) => Err(KunaError::lowlevel(format!(
            "{variant} pipeline reached an un-ported seam: {}",
            panic_message(payload)
        ))),
    }
}

/// Save only a usable root: restoring an empty or invalid selection would hide
/// the temporary pipeline's effect on later host requests.
fn selected_action_name(arch: &Architecture) -> KunaResult<String> {
    arch.allacts.get_current().ok_or_else(|| KunaError::lowlevel("no current action"))?;
    Ok(arch.allacts.get_current_name().to_string())
}

/// Best-effort extraction of a panic payload's message (the `panic!` string),
/// for surfacing an un-ported-stub abort as a recoverable [`KunaError`].
///
/// Takes the `catch_unwind` payload **by value**: a `&Box<dyn Any + Send>`
/// unsize-coerces to the *box itself* as the `Any`, so every `downcast` against
/// the payload types silently fails and the message is lost (the bug this
/// signature makes unwritable).
fn panic_message(payload: Box<dyn std::any::Any + Send>) -> String {
    match payload.downcast::<&'static str>() {
        Ok(s) => (*s).to_string(),
        Err(payload) => match payload.downcast::<String>() {
            Ok(s) => *s,
            Err(_) => "panic with non-string payload".to_string(),
        },
    }
}

/// Render `fd` to C text (C++ `IfcPrintC::execute` -> `print->docFunction(fd)`).
///
/// Drives [`PrintC::doc_function_full`] over the analyzed [`Funcdata`]: the
/// signature shell (recovered return type) plus the **structured-block body**
/// (the if/else hierarchy + per-statement RPN expressions) when `sblocks` is
/// present.
///
/// ## The W10 (`w10-structure-printbody`) closure
///
/// `ActionBlockStructure` now seeds `sblocks` (the cross-arena `build_copy` +
/// `CollapseStructure`), `ActionMarkExplicit`/`ActionMarkImplied` classify the
/// Varnodes, and the IR-coupled body driver
/// ([`PrintC::emit_function_body`](crate::printc::PrintC::emit_function_body))
/// walks the structured tree emitting real statements (`if (cond) { … }`,
/// assignments, `return`) through the ported RPN engine.  The remaining gap to
/// full byte-parity is the **next analysis layer**, not the printer:
///
///   * the recovered local **names** (`v1`) need Merge/HighVariable + the naming
///     pass (a Varnode with no bound Symbol falls back to its register / global
///     `dat_<addr>` name here — faithful `pushVnExplicit`);
///   * the **comparison/branch direction** (`dat_52 <= 10` vs the un-joined
///     `10 < dat_52`) needs `ActionNodeJoin`/`ConditionalJoin` + the
///     present-compare canonicalization to collapse the two-compare boolean
///     pattern into one `INT_LESSEQUAL`;
///   * the return-type / local-decl text needs the proto store + symbol scope.
///
/// The structure of the body — the if/else hierarchy, the statement sequence,
/// the operator expressions — is fully driven here and generalizes across the
/// corpus (real `if` statements now emit for boolless / ccmp / condconst /
/// condexesub / skipnext2 / promotecompare).
pub fn print_c(arch: &mut Architecture, fd: &Funcdata) -> String {
    let cookie_calls = exact_cookie_call_evidence(fd, arch);
    // Drive the IR-coupled body emitter (C++ `IfcPrintC::execute` ->
    // `print->docFunction(fd)`): the real signature (recovered return type) plus
    // the structured-block body (the if/else hierarchy + per-statement RPN
    // expressions) when `sblocks` is present.  `doc_function_full` needs both the
    // printer (`arch.print_mut()`) and the architecture (for register-name
    // resolution); split the borrows by moving the printer out, driving it, and
    // moving it back (the printer is owned by `arch`).
    let mut printer = arch.take_print();
    let out = if cookie_calls.is_empty() {
        printer.doc_function_full(fd, arch)
    } else {
        let (out, mut markup) =
            printer.doc_function_full_with_statement_provenance(fd, arch);
        rewrite_cookie_literal_returns(out, &cookie_calls, &mut markup)
    };
    arch.put_print(printer);
    out
}

/// Inline the caller's literal return assignment across a checker call only
/// when P7 recorded that exact call occurrence as an MSVC `/GS` cookie check.
/// Return-tail duplication can render one shared p-code tail in several
/// structured leaves; the tied return register then prints as
/// `v = K; checker(); return v;` even though the exact call proof already
/// established that the checker preserves ABI output storage. Keeping the line
/// slot blank preserves line numbering, while moving the assignment line's
/// markup associations onto the return line keeps the synthesized literal tied
/// to the instruction that produced it.
///
/// This is deliberately a final presentation rule: the three adjacent lines,
/// the same local on assignment and return, a literal 0/1, a complete standalone
/// call statement, and that line's exact marked call `opref` must all agree. A
/// same-named unmarked call, trailing expression/statement, intervening
/// statement, non-literal value, or absent P7 evidence leaves the text
/// byte-for-byte unchanged.
fn exact_cookie_call_evidence(
    fd: &Funcdata,
    arch: &Architecture,
) -> BTreeMap<u64, BTreeSet<String>> {
    let mut calls = BTreeMap::<u64, BTreeSet<String>>::new();
    for i in 0..fd.num_calls() {
        let call = fd.get_call_specs(i);
        let Some(op) = fd.obank().get(call.get_op()) else { continue };
        if !fd.get_override().is_msvc_cookie_call(op.get_addr()) {
            continue;
        }
        let names = calls.entry(op.get_time() as u64).or_default();
        if !call.get_name().is_empty() {
            names.insert(call.get_name().to_string());
        }
        let printed = call.fspec_printed_name(arch.kuna_name_style());
        if !printed.is_empty() {
            names.insert(printed);
        }
    }
    calls.retain(|_, names| !names.is_empty());
    calls
}

/// True only for one complete call expression statement. A trailing `//`
/// printer annotation is harmless, but any expression or second statement
/// after the matching close parenthesis is a refusal.
fn is_exact_call_statement(line: &str, callee: &str) -> bool {
    let trimmed = line.trim();
    let code = match trimmed.split_once("//") {
        Some((before, _)) => before.trim_end(),
        None => trimmed,
    };
    let Some(expression) = code.strip_suffix(';').map(str::trim_end) else {
        return false;
    };
    let Some(rest) = expression.strip_prefix(callee) else {
        return false;
    };
    if !rest.starts_with('(') {
        return false;
    }

    let mut depth = 0usize;
    for (index, ch) in rest.char_indices() {
        match ch {
            '(' => depth += 1,
            ')' => {
                let Some(next_depth) = depth.checked_sub(1) else {
                    return false;
                };
                depth = next_depth;
                if depth == 0 && index + ch.len_utf8() != rest.len() {
                    return false;
                }
            }
            // Quotes and statement delimiters need a C parser to interpret
            // safely. The `/GS` checker arguments do not need them, so decline.
            '\'' | '"' | ';' | '{' | '}' => return false,
            _ => {}
        }
    }
    depth == 0
}

fn rewrite_cookie_literal_returns(
    text: String,
    calls: &BTreeMap<u64, BTreeSet<String>>,
    markup: &mut crate::prettyprint::MarkupProvenance,
) -> String {
    rewrite_cookie_literal_returns_with_edits(text, calls, markup).0
}

/// [`rewrite_cookie_literal_returns`], also returning each line pair it
/// rewrote so a token stream of the same render can follow
/// ([`crate::kuna_srcmap::apply_cookie_rewrites`]).
fn rewrite_cookie_literal_returns_with_edits(
    text: String,
    calls: &BTreeMap<u64, BTreeSet<String>>,
    markup: &mut crate::prettyprint::MarkupProvenance,
) -> (String, Vec<crate::kuna_srcmap::CookieRewrite>) {
    let mut edits = Vec::new();
    if calls.is_empty() {
        return (text, edits);
    }

    let trailing_newline = text.ends_with('\n');
    let mut lines: Vec<String> = text.lines().map(str::to_string).collect();
    // The printer starts documents with `tag_line()`: the text sink contains
    // that initial newline, while both provenance emitters number the content
    // after it as line 1. Translate raw split positions back to emitter lines.
    let leading_sink_line = usize::from(text.starts_with('\n'));
    for i in 0..lines.len().saturating_sub(2) {
        let assignment = lines[i].trim();
        let Some((name, value)) = assignment.split_once(" = ") else { continue };
        if name.is_empty()
            || !name.bytes().all(|b| b == b'_' || b.is_ascii_alphanumeric())
            || !matches!(value, "0;" | "1;")
        {
            continue;
        }
        let call_line_number = i + 2 - leading_sink_line;
        let exact_marked_call = markup
            .associations
            .iter()
            .filter(|association| association.line_number == call_line_number)
            .filter_map(|association| association.opref)
            .filter_map(|opref| calls.get(&opref))
            .flatten()
            .any(|callee| is_exact_call_statement(&lines[i + 1], callee));
        if !exact_marked_call {
            continue;
        }
        if lines[i + 2].trim() != format!("return {name};") {
            continue;
        }
        let literal = value.as_bytes()[0] as char;
        let indent: String = lines[i].chars().take_while(|c| c.is_whitespace()).collect();
        lines[i] = indent.clone();
        lines[i + 2] = format!("{indent}return {literal};");
        let assignment_line_number = i + 1 - leading_sink_line;
        let return_line_number = i + 3 - leading_sink_line;
        for association in &mut markup.associations {
            if association.line_number == assignment_line_number {
                association.line_number = return_line_number;
            }
        }
        edits.push(crate::kuna_srcmap::CookieRewrite {
            assignment_line: assignment_line_number,
            return_line: return_line_number,
            indent: indent.encode_utf16().count(),
            literal,
        });
    }
    let mut out = lines.join("\n");
    if trailing_newline {
        out.push('\n');
    }
    (out, edits)
}

/// Render the ordinary C text and independently collect the markup references
/// needed to map its lines back to machine instructions.
pub fn print_c_with_provenance(
    arch: &mut Architecture,
    fd: &Funcdata,
) -> (String, CodeProvenance) {
    let cookie_calls = exact_cookie_call_evidence(fd, arch);
    let mut printer = arch.take_print();
    let out = printer.doc_function_full(fd, arch);
    let mut markup = printer.doc_function_provenance(fd, arch);
    arch.put_print(printer);
    let out = rewrite_cookie_literal_returns(out, &cookie_calls, &mut markup);
    align_markup_to_trimmed(&mut markup, &out);
    (
        out,
        resolve_markup_provenance(fd, &markup),
    )
}

/// Renumber markup lines to the text callers report, which is trimmed of its
/// leading breaks: the emitter counts from the first break, so a render that
/// opens with more than one (the Rust attribute line) numbers every line one
/// past the one it lands on. A line the trim removed maps to 0 (dropped).
fn align_markup_to_trimmed(markup: &mut crate::prettyprint::MarkupProvenance, untrimmed: &str) {
    let skip = untrimmed.len() - untrimmed.trim_start_matches('\n').len();
    if skip == 1 {
        return;
    }
    for association in &mut markup.associations {
        association.line_number = (association.line_number + 1).saturating_sub(skip);
    }
}

/// [`print_c_with_provenance`] whose markup pass also captures every token at
/// its place in the returned text ([`crate::kuna_srcmap`]). The text is the
/// plain render, byte for byte.
pub fn print_c_with_srcmap(
    arch: &mut Architecture,
    fd: &Funcdata,
) -> (String, CodeProvenance, Vec<crate::prettyprint::EmitToken>) {
    let cookie_calls = exact_cookie_call_evidence(fd, arch);
    let mut printer = arch.take_print();
    let out = printer.doc_function_full(fd, arch);
    let (mut markup, mut tokens) = printer.doc_function_tokens(fd, arch);
    arch.put_print(printer);
    let (out, edits) = rewrite_cookie_literal_returns_with_edits(out, &cookie_calls, &mut markup);
    crate::kuna_srcmap::apply_cookie_rewrites(&mut tokens, &edits);
    align_markup_to_trimmed(&mut markup, &out);
    (out, resolve_markup_provenance(fd, &markup), tokens)
}

/// (kuna) Render every user-defined data-type in the architecture's type
/// factory as C definitions (the `PrintC::docTypeDefinitions` port,
/// [`crate::printc::PrintC::doc_type_definitions`]) — the type-definition
/// block of the `kuna decompile-project` `.h` artifact.  Same
/// take/put split-borrow dance as [`print_c`] (the printer is owned by `arch`).
pub fn print_c_types(arch: &mut Architecture) -> String {
    let mut printer = arch.take_print();
    let out = printer.doc_type_definitions(arch);
    arch.put_print(printer);
    out
}

/// (kuna) Render ONLY the decompiled function's prototype declaration —
/// `<ret> <name>(<params>);` — via
/// [`crate::printc::PrintC::doc_prototype`]: the `.h`-prototype half of the
/// `kuna decompile-project` prototype == definition-line contract (the emitted
/// text minus the trailing `;` appears char-for-char inside [`print_c`]'s
/// render of the same `Funcdata`).  A function whose prototype was never
/// recovered (no proto store) renders as `void <name>(void);`.
pub fn print_c_prototype(arch: &mut Architecture, fd: &Funcdata) -> String {
    let mut printer = arch.take_print();
    let out = printer.doc_prototype(fd, arch);
    arch.put_print(printer);
    out
}

/// (kuna) The generated recompile prelude for a `kuna decompile-project` `.h`:
/// C typedefs for the architecture's interned **core** scalar types (`uint4`,
/// `int8`, `float8`, …, spelled per standard C — 8-byte integers always use
/// `long long` so the text is data-model independent) plus the fixed Ghidra
/// `undefined` family block (`undefined`, `undefined1..8` — 3/5/6/7 mapped to
/// the next larger unsigned integer with a sizeof note — and `undefined16/32`
/// as byte-array structs).  `bool` is covered by `#include <stdbool.h>`;
/// C scalar keywords and standard-header types are not redeclared.
pub fn print_c_recompile_prelude(arch: &Architecture) -> String {
    print_c_recompile_prelude_with_roots(arch, |_| {})
}

/// The same prelude, reporting the actual graph roots whose declarations or
/// layout checks it emits. Publication can authenticate source ownership without guessing by
/// name; fixed synthetic helper declarations do not acquire source ownership.
pub fn print_c_recompile_prelude_with_roots(
    arch: &Architecture, mut emitted: impl FnMut(&crate::dtype::TypeRoot),
) -> String {
    use crate::dtype::type_metatype::*;
    use std::fmt::Write as _;
    let mut out = String::new();
    out.push_str("/* kuna recompile prelude (generated): core scalar typedefs */\n");
    out.push_str("#include <stdbool.h>\n");
    out.push_str("#include <stdint.h>\n");
    out.push_str("#include <stddef.h>\n");
    // A recovered aggregate can hold target pointers, and a host that compiles
    // this header for a different data model sizes them differently and moves
    // every field after such a member -- which also moves what `p[1]` means in
    // the body.  Name the target's width, and the flag when it is not the
    // 64-bit host default.
    if let Some(bytes) = arch.manage().get_default_data_space().map(|s| s.get_addr_size()) {
        let flag = if bytes == 4 { " (`gcc -m32`)" } else { "" };
        out.push_str(&format!(
            "/* target pointers are {bytes} bytes: compile for that data model{flag}, or a\n   \
             `T *` member of a different width moves every field after it */\n"
        ));
    }
    out.push('\n');

    // Generated typedefs for the interned core types (dependent_order filtered
    // on is_core_type; sorted by name for a stable, readable block).
    let mut lines: Vec<String> = Vec::new();
    for ct in arch.types_impl().dependent_order() {
        if !ct.is_core_type() {
            continue;
        }
        let view = ct.read();
        let node = view.get(ct.id()).expect("retained datatype");
        let name = node.get_name();
        if name.is_empty() || name == "void" {
            continue;
        }
        let size = ct.get_size();
        if crate::kuna_ctypes::is_builtin_type_name(name) {
            lines.push(format!("typedef char kuna_core_size_{name}[(sizeof({name}) == {size}) ? 1 : -1];\n"));
            emitted(&ct);
            continue;
        }
        let (spelling, note): (&str, &str) = match ct.get_metatype() {
            TYPE_INT => match size {
                1 => ("signed char", ""),
                2 => ("short", ""),
                4 => ("int", ""),
                8 => ("long long", ""),
                _ => continue,
            },
            TYPE_UINT | TYPE_UNKNOWN => match size {
                1 => ("unsigned char", ""),
                2 => ("unsigned short", ""),
                4 => ("unsigned int", ""),
                8 => ("unsigned long long", ""),
                _ => continue,
            },
            TYPE_FLOAT => match size {
                4 => ("float", ""),
                8 => ("double", ""),
                10 | 16 => ("long double", " /* sizeof may differ */"),
                _ => continue,
            },
            // The pseudo "function body" type: only ever used as `code *`;
            // a 1-byte scalar keeps `sizeof(code)` meaningful too.
            TYPE_CODE => ("unsigned char", " /* pseudo (function body) type */"),
            _ => continue,
        };
        lines.push(format!("typedef {spelling} {name};{note}\n"));
        emitted(&ct);
    }
    lines.sort();
    lines.dedup();
    for l in &lines {
        out.push_str(l);
    }

    // The fixed Ghidra/kuna `undefined` family (the anonymous-unknown
    // rendering `undefined<N>`, printc.rs `declarator_parts`).
    out.push_str("\n/* the Ghidra/kuna `undefined` family */\n");
    out.push_str("typedef unsigned char undefined;\n");
    out.push_str("typedef unsigned char undefined1;\n");
    out.push_str("typedef unsigned short undefined2;\n");
    out.push_str("typedef unsigned int undefined3; /* 3 bytes in the decompiler; sizeof differs */\n");
    out.push_str("typedef unsigned int undefined4;\n");
    out.push_str("typedef unsigned long long undefined5; /* 5 bytes in the decompiler; sizeof differs */\n");
    out.push_str("typedef unsigned long long undefined6; /* 6 bytes in the decompiler; sizeof differs */\n");
    out.push_str("typedef unsigned long long undefined7; /* 7 bytes in the decompiler; sizeof differs */\n");
    out.push_str("typedef unsigned long long undefined8;\n");
    out.push_str("typedef struct { unsigned char b[16]; } undefined16;\n");
    out.push_str("typedef struct { unsigned char b[32]; } undefined32;\n");
    out.push_str("\n/* Scalar PIECE helpers: byte widths, high part first. */\n#ifndef KUNA_SCALAR_CONCAT_HELPERS\n#define KUNA_SCALAR_CONCAT_HELPERS\n");
    for high in 1..8 {
        for low in 1..=8 - high {
            let result = match high + low { 2 => "uint16_t", 3 | 4 => "uint32_t", _ => "uint64_t" };
            let high_mask = (1u64 << (8 * high)) - 1;
            let low_mask = (1u64 << (8 * low)) - 1;
            writeln!(out,
                "static inline {result} CONCAT{high}{low}(uint64_t high, uint64_t low) {{\n  return ({result})(((high & UINT64_C(0x{high_mask:x})) << {}) | (low & UINT64_C(0x{low_mask:x})));\n}}",
                8 * low).expect("writing to String");
        }
    }
    out.push_str("#endif /* KUNA_SCALAR_CONCAT_HELPERS */\n");
    out
}

/// A recovered variable surfaced for the machine-readable batch output
/// (`kuna decompile-all --json`) — the fields decbench's `type_match` metric
/// consumes from a decompiler's per-function variable list.
#[derive(Debug, Clone)]
pub struct VarInfo {
    /// Variable name as it appears in the decompiled C (`param_1`, `local_18`, a
    /// DWARF name on a `-g` binary, …).
    pub name: String,
    /// The C type string, rendered exactly as `print_c` would spell it
    /// (`int`, `char *`, `undefined8`, …) via [`crate::printc::type_to_c_string`].
    pub type_name: String,
    /// Signed frame-relative stack offset for a stack-resident variable; `None`
    /// for a register-resident parameter (ghidra `getStorage().getStackOffset()`).
    pub stack_offset: Option<i64>,
    /// Size in bytes (the variable's type size).
    pub size: i64,
    /// `true` for a formal parameter (`kind="arg"`), `false` for a local
    /// (`kind="stack"`).
    pub is_param: bool,
    /// ABI parameter index (dense, source order) for parameters; `None` for locals.
    pub arg_index: Option<usize>,
    /// 1-based pseudocode lines containing markup-backed references to this variable.
    pub line_numbers: Vec<usize>,
    /// Machine instruction addresses associated with those pseudocode lines.
    pub addresses: Vec<u64>,
}

/// A type definition surfaced for the machine-readable batch output
/// (`kuna decompile-all --json`'s per-function `types`) — the layout side of a
/// recovered function, so a consumer reads it without parsing C out of `code`.
///
/// Populated only under `option structdefs on`, whose preamble prints the same
/// set above the function; the key is always present (`[]` when off) so a
/// consumer can read it unconditionally.
#[derive(Debug, Clone)]
pub struct TypeInfo {
    /// The type's name as the factory holds it (`_IO_FILE`, `FILE`, `struct_0`).
    pub name: String,
    /// The definition text: the `struct <n> { … };` body for a complete
    /// composite, the enum block, the `typedef <base> <n>;` line, or the
    /// `typedef struct <n> <n>; /* opaque */` forward declaration for an
    /// incomplete one — the same line(s) the export's `.h` gives it.
    pub definition: String,
    /// The type's size in bytes as the factory holds it, which an incomplete
    /// (opaque) type also has: a `libctypes` shell is created at its ABI size
    /// and reports it (`FILE` is 216) even though no member is known, so a
    /// consumer testing for an opaque shell reads `definition` — the
    /// `/* opaque */` forward declaration — and never `size == 0`.
    pub size: i64,
}

/// The composite/enum/typedef definitions `fd`'s printed C names, in
/// definition-before-use order ([`crate::kuna_structdefs::referenced_types`]).
///
/// Empty unless `option structdefs on`: the JSON array and the printed preamble
/// are one decision, so a caller never sees a layout on one surface and not the
/// other.
pub fn extract_type_definitions(arch: &Architecture, fd: &Funcdata) -> Vec<TypeInfo> {
    if !arch.print().options.struct_defs() {
        return Vec::new();
    }
    // (kuna outlang) The definition text is C, and the printed preamble
    // declines for a non-C output language for that reason; the array and the
    // preamble are one decision, so it declines here too.
    if arch.print().out_lang() != crate::kuna_lang::OutLang::C {
        return Vec::new();
    }
    let rt = crate::printc::RealTypeCtx::from_arch(arch, arch.print().out_lang(), arch.print().options.convention);
    let types = crate::kuna_structdefs::referenced_types(fd);
    crate::kuna_structdefs::dedup_by_name(&types)
        .iter()
        .map(|ct| {
            let name = {
                let view = ct.read();
                view.get(ct.id()).expect("retained datatype").get_name().to_string()
            };
            TypeInfo {
                name,
                definition: crate::kuna_structdefs::definition_text(ct, rt),
                size: ct.get_size() as i64,
            }
        })
        .collect()
}

/// (kuna `globalref`) A global the printed C names: by address (`&dat_2b080`),
/// or, for the header to check its declaration against, directly (`dat_2b080`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GlobalInfo {
    /// The authenticated target data address-space index.
    pub space_index: i32,
    /// The byte address the name stands for.
    pub address: u64,
    /// The actual emitted symbol name, or the unnamed-data spelling.
    pub name: String,
    /// The C declaration without `extern` or `;` (`struct_2 dat_2b080`).
    pub declaration: String,
    /// The declared object's size in bytes.
    pub size: i64,
    /// True when the function only ever used the address through `void *`, so
    /// the declared type is the unknown byte.
    pub unknown: bool,
    /// True for a direct storage access or an authenticated named symbol.
    /// Its declaration governs that object, rather than tentatively choosing
    /// a type from an unnamed address-taking expression.
    pub direct: bool,
    /// True when the declared type is a record or union: a scalar read or write
    /// of the name does not compile against it. (An array decays to a pointer,
    /// so a scalar compare against one would compile to something else.)
    pub aggregate: bool,
}

/// The globals the C `print_c` just rendered for `fd` names
/// ([`crate::kuna_globalref`]): authenticated named symbols, every rewritten
/// address it takes, and unnamed program data it accesses directly. Read from
/// the printer, so it must follow the `print_c` of the same function. Named
/// symbol declarations do not depend on the optional global-address rewrite.
pub fn extract_global_objects(arch: &Architecture) -> Vec<GlobalInfo> {
    let Some(data_space) = arch.manage().get_default_data_space() else { return Vec::new(); };
    let print = arch.print();
    let plan = print.globalref_plan();
    let rt = crate::printc::RealTypeCtx::from_arch(arch, print.out_lang(), print.options.convention);
    let info = |address: u64, name: String, ty: &crate::dtype::TypeRoot, unknown: bool, direct: bool, volatile: bool| {
        use crate::dtype::type_metatype::{TYPE_STRUCT, TYPE_UNION};
        GlobalInfo {
            space_index: data_space.get_index(),
            address,
            declaration: if volatile {
                crate::printc::declaration_text(ty, &format!("volatile {name}"), rt)
            } else { crate::printc::declaration_text(ty, &name, rt) },
            size: i64::from(ty.get_size()),
            name,
            unknown,
            direct,
            aggregate: matches!(ty.get_metatype(), TYPE_STRUCT | TYPE_UNION),
        }
    };
    let mut out: Vec<GlobalInfo> =
        plan.minted.iter().map(|(&address, m)| info(address, crate::printc::global_data_name(arch, address),
            &m.decl_type, m.unknown, false, false)).collect();
    for (address, ty) in plan.direct_objects() {
        let g = info(address, crate::printc::global_data_name(arch, address), ty, false, true, false);
        if !out.contains(&g) {
            out.push(g);
        }
    }
    for (address, name, ty, volatile) in plan.named_objects() {
        out.push(info(address, name.to_string(), ty, false, true, volatile));
    }
    out
}

/// (kuna `globalref`) One `extern` line per referenced global symbol, in address/name order.
/// Shared by project exports and native callable support inventories.
///
/// Each function declares the object at the type IT uses it at, so two
/// functions can disagree, and a function that reads the same `dat_<addr>`
/// directly reads it at the type IT printed. The declaration is what every
/// direct read and write compiles against, so it must never be a scalar of
/// another type than theirs: that would silently change what they compute (a
/// signed compare turned unsigned, a store truncated), where a pointer of the
/// wrong type in an address-taking body is a diagnosed mismatch. The choice:
///
/// * a record or union some function takes the address of, the larger one
///   first: a scalar access of the name does not compile against it;
/// * otherwise the one type the direct accesses agree on;
/// * otherwise, with direct accesses at two types, nothing, and a comment says so;
/// * with no direct access, a type over the unknown byte a `void *` use stands
///   for, then the larger object, then the declaration more functions make,
///   then the earlier function.
///
/// Every other type is listed in a comment on the line.
pub fn global_declarations<'a>(globals: impl IntoIterator<Item = &'a GlobalInfo>) -> String {
    use std::fmt::Write as _;
    let mut by_addr: BTreeMap<(i32, u64, &str), (Vec<&GlobalInfo>, Vec<&GlobalInfo>)> = BTreeMap::new();
    for g in globals {
        let e = by_addr.entry((g.space_index, g.address, g.name.as_str())).or_default();
        if g.direct { e.1.push(g) } else { e.0.push(g) }
    }
    let quote = |d: &str| d.replace("/*", "/ *").replace("*/", "* /");
    let mut out = String::new();
    for (taken, direct) in by_addr.values() {
        let mut decls: Vec<(&GlobalInfo, usize)> = Vec::new();
        for g in taken.iter().chain(direct.iter()) {
            match decls.iter_mut().find(|(d, _)| d.declaration == g.declaration) {
                Some((_, n)) => *n += 1,
                None => decls.push((g, 1)),
            }
        }
        let best = |pool: &mut dyn Iterator<Item = &(&GlobalInfo, usize)>| -> Option<String> {
            pool.max_by(|(a, an), (b, bn)| (!a.unknown, a.size, *an).cmp(&(!b.unknown, b.size, *bn)).then(std::cmp::Ordering::Greater))
                .map(|(g, _)| g.declaration.clone())
        };
        let mut direct_decls: Vec<&str> = direct.iter().map(|g| g.declaration.as_str()).collect();
        direct_decls.sort_unstable();
        direct_decls.dedup();
        let record = best(&mut decls.iter().filter(|(g, _)| !g.direct && g.aggregate));
        let chosen = match (record, direct_decls.as_slice()) {
            (Some(r), _) => r,
            (None, [one]) => one.to_string(),
            (None, []) => best(&mut decls.iter()).unwrap_or_default(),
            (None, _) => {
                let all: Vec<String> = decls.iter().map(|(g, _)| quote(&g.declaration)).collect();
                let _ = writeln!(out, "/* {} is read at two types, so it is not declared: {} */", decls[0].0.name, all.join(", "));
                continue;
            }
        };
        let others: Vec<String> =
            decls.iter().filter(|(g, _)| g.declaration != chosen).map(|(g, _)| quote(&g.declaration)).collect();
        if others.is_empty() {
            let _ = writeln!(out, "extern {chosen};");
        } else {
            let _ = writeln!(out, "extern {chosen}; /* also used as: {} */", others.join(", "));
        }
    }
    out
}

/// One 1-based pseudocode line and its associated machine instruction addresses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LineMapping {
    pub line_number: usize,
    pub addresses: Vec<u64>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct VariableUseEvidence {
    line_numbers: Vec<usize>,
    addresses: Vec<u64>,
}

/// Provenance resolved from printer markup against a decompiled function's IR.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CodeProvenance {
    pub line_mappings: Vec<LineMapping>,
    variable_uses: BTreeMap<u64, VariableUseEvidence>,
}

impl CodeProvenance {
    /// Attach markup-backed use evidence to the corresponding reported variables.
    pub fn apply_to_variables(&self, fd: &Funcdata, variables: &mut [VarInfo]) {
        self.apply_to_variables_with_refs(fd, variables);
    }

    /// [`Self::apply_to_variables`], returning for each variable the varrefs
    /// its evidence came from (what a token map binds variable tokens by).
    pub fn apply_to_variables_with_refs(
        &self,
        fd: &Funcdata,
        variables: &mut [VarInfo],
    ) -> Vec<BTreeSet<u64>> {
        variables
            .iter_mut()
            .map(|variable| {
                let refs = self.variable_varrefs(fd, variable);
                let evidence = self.evidence_for_refs(&refs);
                variable.line_numbers = evidence.line_numbers;
                variable.addresses = evidence.addresses;
                refs
            })
            .collect()
    }

    /// The varrefs whose uses are `variable`'s evidence: its storage, else the
    /// highs carrying its name, else its `&parameter` references -- the first
    /// set the rendered markup actually used.
    fn variable_varrefs(&self, fd: &Funcdata, variable: &VarInfo) -> BTreeSet<u64> {
        let storage_refs = variable_storage_varrefs(fd, variable);
        if !self.evidence_for_refs(&storage_refs).line_numbers.is_empty() {
            return storage_refs;
        }
        let named_refs = named_high_varrefs(fd, variable);
        if !self.evidence_for_refs(&named_refs).line_numbers.is_empty() {
            return named_refs;
        }
        // (kuna `paramrefdecl`) An ADDRESS-TAKEN parameter has no Varnode at its
        // own storage and no high carrying its `param_N` JSON name -- its only
        // appearance is the `&a0` reference, a PTRSUB offset constant bound to
        // the parameter's Symbol.  Both queries above miss it, so the surface
        // reported a parameter with no uses while the C showed one.
        parameter_reference_varrefs(fd, variable)
    }

    fn evidence_for_refs(&self, varrefs: &BTreeSet<u64>) -> VariableUseEvidence {
        let mut line_numbers = BTreeSet::new();
        let mut addresses = BTreeSet::new();
        for evidence in varrefs.iter().filter_map(|varref| self.variable_uses.get(varref)) {
            line_numbers.extend(evidence.line_numbers.iter().copied());
            addresses.extend(evidence.addresses.iter().copied());
        }
        VariableUseEvidence {
            line_numbers: line_numbers.into_iter().collect(),
            addresses: addresses.into_iter().collect(),
        }
    }
}

fn extend_high_varrefs(fd: &Funcdata, high_id: HighVariableId, varrefs: &mut BTreeSet<u64>) {
    let Some(high) = fd.high_bank().get(high_id) else { return };
    for index in 0..high.num_instances() {
        let Some(varnode) = fd.vbank().get(high.get_instance(index)) else { continue };
        varrefs.insert(varnode.get_create_index() as u64);
    }
}

fn select_storage_varrefs(
    fd: &Funcdata,
    matches: &[(u64, Option<HighVariableId>)],
    variable_name: &str,
) -> BTreeSet<u64> {
    let highs: BTreeSet<HighVariableId> = matches.iter().filter_map(|(_, high)| *high).collect();
    let selected_high = if highs.len() == 1 {
        highs.iter().next().copied()
    } else {
        let named: Vec<HighVariableId> = highs
            .iter()
            .copied()
            .filter(|high_id| {
                fd.high_bank()
                    .get(*high_id)
                    .and_then(|high| high.kuna_name())
                    == Some(variable_name)
            })
            .collect();
        (named.len() == 1).then(|| named[0])
    };

    let mut varrefs = BTreeSet::new();
    if let Some(high_id) = selected_high {
        extend_high_varrefs(fd, high_id, &mut varrefs);
    } else if highs.is_empty() {
        varrefs.extend(matches.iter().map(|(varref, _)| *varref));
    }
    varrefs
}

fn parameter_storage(fd: &Funcdata, arg_index: usize) -> Option<(Address, i64)> {
    let proto = fd.get_func_proto();
    let mut source_index = 0usize;
    for index in 0..proto.num_params() {
        let Some(parameter) = proto.source_param(index) else { continue };
        if parameter.is_hidden_return() {
            continue;
        }
        if source_index == arg_index {
            return Some((parameter.get_address(), parameter.get_size() as i64));
        }
        source_index += 1;
    }
    None
}

fn variable_storage_varrefs(fd: &Funcdata, variable: &VarInfo) -> BTreeSet<u64> {
    let mut matches = Vec::new();
    if variable.is_param {
        let Some(arg_index) = variable.arg_index else { return BTreeSet::new() };
        let Some((address, size)) = parameter_storage(fd, arg_index) else {
            return BTreeSet::new();
        };
        for varnode_id in fd.vbank().iter_loc() {
            let Some(varnode) = fd.vbank().get(varnode_id) else { continue };
            if varnode.get_addr() == &address && varnode.get_size() as i64 == size {
                matches.push((
                    varnode.get_create_index() as u64,
                    varnode.get_high(),
                    varnode.is_input(),
                ));
            }
        }
        if matches.iter().any(|(_, _, is_input)| *is_input) {
            matches.retain(|(_, _, is_input)| *is_input);
        }
    } else if let (Some(stack_offset), Some(scope)) =
        (variable.stack_offset, fd.get_scope_local())
    {
        let stack_space = scope.get_space_id();
        for varnode_id in fd.vbank().iter_loc() {
            let Some(varnode) = fd.vbank().get(varnode_id) else { continue };
            let in_stack_space = varnode
                .get_addr()
                .get_space()
                .is_some_and(|space| space.get_index() == stack_space.get_index());
            if in_stack_space
                && signed_space_offset(stack_space, varnode.get_offset()) == stack_offset
                && varnode.get_size() as i64 == variable.size
            {
                matches.push((
                    varnode.get_create_index() as u64,
                    varnode.get_high(),
                    false,
                ));
            }
        }
    }

    let matches: Vec<(u64, Option<HighVariableId>)> = matches
        .into_iter()
        .map(|(varref, high, _)| (varref, high))
        .collect();
    select_storage_varrefs(fd, &matches, &variable.name)
}

/// The `&parameter` references of a reported parameter (`option paramrefdecl`):
/// the varrefs of every high bound to the `function_parameter` Symbol that owns
/// the parameter's storage.  Empty for a local, and for a parameter whose storage
/// no Symbol claims.
fn parameter_reference_varrefs(fd: &Funcdata, variable: &VarInfo) -> BTreeSet<u64> {
    if !variable.is_param || !fd.get_arch().param_ref_decl {
        return BTreeSet::new();
    }
    let Some(arg_index) = variable.arg_index else { return BTreeSet::new() };
    let Some((address, _size)) = parameter_storage(fd, arg_index) else {
        return BTreeSet::new();
    };
    crate::kuna_paramrefdecl::parameter_reference_varrefs(fd, &address)
}

fn high_matches_stack_variable(
    fd: &Funcdata,
    high_id: HighVariableId,
    variable: &VarInfo,
) -> bool {
    let (Some(stack_offset), Some(scope), Some(high)) = (
        variable.stack_offset,
        fd.get_scope_local(),
        fd.high_bank().get(high_id),
    ) else {
        return false;
    };
    let stack_space = scope.get_space_id();
    (0..high.num_instances()).any(|index| {
        let Some(varnode) = fd.vbank().get(high.get_instance(index)) else { return false };
        let Some(space) = varnode.get_addr().get_space() else { return false };
        let offset = signed_space_offset(stack_space, varnode.get_offset());
        // Constants represent `&aggregate`; their pointer width is not the
        // aggregate's width, so only the exact base address is meaningful.
        if space.get_type() == kuna_base::space::spacetype::IPTR_CONSTANT {
            return offset == stack_offset;
        }
        space.get_index() == stack_space.get_index()
            && stack_storage_contains(
                stack_offset,
                variable.size,
                offset,
                varnode.get_size() as i64,
            )
    })
}

fn stack_storage_contains(
    aggregate_offset: i64,
    aggregate_size: i64,
    piece_offset: i64,
    piece_size: i64,
) -> bool {
    // Element highs count as aggregate uses, but a partial overlap would
    // attribute a neighbouring frame object's evidence to this variable.
    if aggregate_size <= 0 || piece_size <= 0 || piece_offset < aggregate_offset {
        return false;
    }
    let (Some(aggregate_end), Some(piece_end)) = (
        aggregate_offset.checked_add(aggregate_size),
        piece_offset.checked_add(piece_size),
    ) else {
        return false;
    };
    piece_end <= aggregate_end
}

fn named_high_varrefs(fd: &Funcdata, variable: &VarInfo) -> BTreeSet<u64> {
    let named: Vec<HighVariableId> = fd
        .high_bank()
        .iter()
        .filter_map(|(high_id, high)| {
            (high.kuna_name() == Some(variable.name.as_str())).then_some(high_id)
        })
        .collect();
    let selected: Vec<HighVariableId> = if named.len() <= 1 {
        named
    } else {
        named
            .into_iter()
            .filter(|high_id| high_matches_stack_variable(fd, *high_id, variable))
            .collect()
    };
    let mut varrefs = BTreeSet::new();
    for high_id in selected {
        extend_high_varrefs(fd, high_id, &mut varrefs);
    }
    varrefs
}

fn resolve_markup_provenance(
    fd: &Funcdata,
    markup: &crate::prettyprint::MarkupProvenance,
) -> CodeProvenance {
    let op_addresses: BTreeMap<u64, u64> = fd
        .obank()
        .iter_all()
        .filter_map(|(_, op_id)| {
            let op = fd.obank().get(op_id)?;
            op.get_addr().get_space()?;
            Some((op.get_time() as u64, op.get_addr().get_offset()))
        })
        .collect();
    resolve_markup_provenance_with_addresses(markup, &op_addresses)
}

fn resolve_markup_provenance_with_addresses(
    markup: &crate::prettyprint::MarkupProvenance,
    op_addresses: &BTreeMap<u64, u64>,
) -> CodeProvenance {
    let mut line_addresses: BTreeMap<usize, BTreeSet<u64>> = BTreeMap::new();
    let mut variable_lines: BTreeMap<u64, BTreeSet<usize>> = BTreeMap::new();

    for association in &markup.associations {
        if association.line_number == 0 {
            continue;
        }
        if let Some(address) = association.opref.and_then(|opref| op_addresses.get(&opref)) {
            line_addresses.entry(association.line_number).or_default().insert(*address);
        }
        if let Some(varref) = association.varref {
            variable_lines.entry(varref).or_default().insert(association.line_number);
        }
    }

    let line_mappings: Vec<LineMapping> = line_addresses
        .iter()
        .map(|(&line_number, addresses)| LineMapping {
            line_number,
            addresses: addresses.iter().copied().collect(),
        })
        .collect();
    let variable_uses = variable_lines
        .into_iter()
        .map(|(varref, lines)| {
            let addresses = lines
                .iter()
                .flat_map(|line| line_addresses.get(line).into_iter().flatten().copied())
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect();
            (
                varref,
                VariableUseEvidence {
                    line_numbers: lines.into_iter().collect(),
                    addresses,
                },
            )
        })
        .collect();
    CodeProvenance { line_mappings, variable_uses }
}

/// Interpret a raw spacebase `off` as a signed frame offset for `space`
/// (negative locals wrap to the high end of the unsigned range): sign-extend from
/// the space's address bit-width via the codebase's canonical
/// [`kuna_base::address::sign_extend`] (the same idiom `varmap` uses, which also
/// masks off any bits above the sign bit).  Matches ghidra
/// `getStorage().getStackOffset()`, which the decbench `type_match` metric
/// calibrates per binary against DWARF.  Stack spaces are byte-addressed
/// (`word_size == 1`), so no `byte_to_address` scaling is needed.
fn signed_space_offset(space: &Rc<kuna_base::space::AddrSpace>, off: u64) -> i64 {
    kuna_base::address::sign_extend(off as i64, space.get_addr_size() as i32 * 8 - 1)
}

/// (kuna) Extract the recovered parameters + stack locals of a decompiled
/// [`Funcdata`] as a flat `Vec<VarInfo>` for the `kuna decompile-all --json`
/// surface (→ decbench `type_match`).
///
/// Mirrors how the decbench Ghidra backend reads the `HighFunction` local symbol
/// map: source parameters come from the `FuncProto` in ABI order (`arg_index` = dense
/// source position, a register-passed param has `stack_offset == None`); stack
/// locals come from the function's `ScopeLocal` stack space, keeping only
/// `NO_CATEGORY` symbols (a `FUNCTION_PARAMETER` symbol is already emitted as a
/// parameter, the `emitScopeVarDecls(no_category)` split).  Reads the
/// already-computed `Funcdata` — no decompile re-run.
pub fn extract_variables(arch: &Architecture, fd: &Funcdata) -> Vec<VarInfo> {
    let stack_index = arch.manage().get_stack_space().map(|s| s.get_index());
    let mut out: Vec<VarInfo> = Vec::new();

    // 1) Source parameters, in ABI order, excluding derived execution-only inputs.
    let proto = fd.get_func_proto();
    let nparams = proto.num_params();
    let mut arg_pos = 0usize;
    for i in 0..nparams {
        let Some(p) = proto.source_param(i) else { continue };
        // A hidden return-storage pointer is a synthetic ABI slot, not a
        // source-level parameter (no DWARF formal-parameter to match), so skip it.
        if p.is_hidden_return() {
            continue;
        }
        let raw_name = p.get_name();
        let name = if raw_name.is_empty() {
            format!("param_{}", arg_pos + 1)
        } else {
            raw_name.to_string()
        };
        let type_name = p
            .get_type()
            .map(|t| crate::kuna_bytehonest::exported_type_name(arch, t))
            .unwrap_or_default();
        let size = p.get_size() as i64;
        let addr = p.get_address();
        let stack_offset = match (stack_index, addr.get_space()) {
            (Some(si), Some(sp)) if sp.get_index() == si => {
                Some(signed_space_offset(sp, addr.get_offset()))
            }
            _ => None,
        };
        out.push(VarInfo {
            name,
            type_name,
            stack_offset,
            size,
            is_param: true,
            arg_index: Some(arg_pos),
            line_numbers: Vec::new(),
            addresses: Vec::new(),
        });
        arg_pos += 1;
    }

    // 2) Stack locals, off the ScopeLocal (NO_CATEGORY symbols only).
    if let Some(sl) = fd.get_scope_local() {
        let space = sl.get_space_id();
        let space_index = space.get_index() as usize;
        let specs = sl.database().scope_space_local_var_specs(sl.scope_id(), space_index);
        for (name, ct, addr, category) in specs {
            if category != crate::database::symbol_category::NO_CATEGORY {
                continue; // already emitted as a parameter above
            }
            let type_name = crate::kuna_bytehonest::exported_type_name(arch, &ct);
            out.push(VarInfo {
                name,
                type_name,
                stack_offset: Some(signed_space_offset(space, addr.get_offset())),
                size: ct.get_size() as i64,
                is_param: false,
                arg_index: None,
                line_numbers: Vec::new(),
                addresses: Vec::new(),
            });
        }
    }

/// (kuna `framelayout`) How an exported stack slot's data type is spelled.
///
/// A slot the type system never committed to is carried internally as
/// `xunknown1[N]` (Ghidra's `undefined1[N]`) or a bare `TYPE_UNKNOWN`, and
/// `type_to_c_string` renders the array form as `char[N]` -- which asserts an
/// element type the recovery never established.  Report those as the width-only
/// `undefined<N>`, the same spelling Ghidra uses for the same fact, and leave every
/// committed type exactly as the printer spells it.
fn frame_slot_type_name(arch: &Architecture, dt: &crate::dtype::TypeRoot) -> String {
    use crate::dtype::type_metatype;
    let n = dt.get_size();
    let uncommitted = match dt.get_metatype() {
        type_metatype::TYPE_UNKNOWN => true,
        type_metatype::TYPE_ARRAY => dt
            .get_array_base()
            .map(|e| e.get_metatype() == type_metatype::TYPE_UNKNOWN)
            .unwrap_or(false),
        _ => false,
    };
    if uncommitted && n > 0 {
        return format!("undefined{n}");
    }
    crate::printc::type_to_c_string(arch, dt)
}

    // 3) (kuna `framelayout`) The frame slots an EARLIER restructure pass recovered
    // and the final one no longer has, because the dataflow folded the spill away.
    // The emitted C is right to drop them; the recovered frame still contains them,
    // and `variables` reports the frame. Only offsets no parameter or surviving
    // local already covers are added, so this can never contradict section 1 or 2.
    if arch.framelayout {
        let covered: std::collections::BTreeSet<i64> =
            out.iter().filter_map(|v| v.stack_offset).collect();
        let first_slot = out.len();
        for (off, slot) in fd.frame_slots() {
            if covered.contains(&off) {
                continue;
            }
            // `$$undefNNNNNNNN` is Ghidra's internal placeholder for an unnamed
            // symbol and must not surface on a public interface; name the slot the
            // way Ghidra's stack view does.
            let name = if crate::kuna_undefname::is_undefined_name(&slot.name) {
                if off < 0 {
                    format!("local_{:x}", -off)
                } else {
                    format!("stack_{off:x}")
                }
            } else {
                slot.name
            };
            out.push(VarInfo {
                name,
                type_name: frame_slot_type_name(arch, &slot.dtype),
                stack_offset: Some(off),
                size: slot.size as i64,
                is_param: false,
                arg_index: None,
                line_numbers: Vec::new(),
                addresses: Vec::new(),
            });
        }
        if arch.slot_ptr {
            type_filler_slots_from_stores(arch, fd, &mut out, first_slot);
        }
    }
    out
}

/// (kuna `slotptr`) Re-spell each `framelayout` filler slot (the rows from
/// `first_slot` on) whose stores agree on one pointer type, as long as its byte
/// range overlaps no other exported variable.
fn type_filler_slots_from_stores(
    arch: &Architecture,
    fd: &Funcdata,
    out: &mut [VarInfo],
    first_slot: usize,
) {
    let ranges: Vec<(i64, i64)> = out
        .iter()
        .map(|v| v.stack_offset.map(|o| (o, o + v.size.max(1))).unwrap_or((0, 0)))
        .collect();
    for i in first_slot..out.len() {
        let (lo, hi) = ranges[i];
        if hi <= lo {
            continue;
        }
        let overlaps = ranges
            .iter()
            .enumerate()
            .any(|(j, &(a, b))| j != i && b > a && a < hi && lo < b);
        if overlaps {
            continue;
        }
        if let Ok(ty) = crate::kuna_slotptr::slot_pointer_type(fd, arch, lo, out[i].size as int4) {
            out[i].type_name = crate::printc::type_to_c_string(arch, &ty);
        }
    }
}

/// Emit an injection payload's p-code (C++ `InjectPayloadSleigh::inject` vs
/// `InjectPayloadGhidra::inject`): the locally compiled SLEIGH template when
/// the library has one, otherwise a back-end fetch through the translator
/// seam, which is where a ghidra-mode session — no local `.sla`, so no
/// compiled template ever — gets its answer.
fn emit_inject(
    arch: &Architecture,
    injectid: int4,
    context: &mut crate::pcodeinject::InjectContext,
    emit: &mut dyn kuna_sleigh::translate::PcodeEmit,
) -> KunaResult<()> {
    let payload = arch.pcodeinjectlib.get_payload(injectid);
    match arch.pcodeinjectlib.get_tpl(injectid) {
        Some(tpl) => {
            // SleighInjectEngine over the arch's const/unique/default-code spaces.
            let engine = crate::inject_sleigh::SleighInjectEngine::new(
                Rc::clone(arch.manage().get_constant_space().expect("no constant space")),
                Rc::clone(arch.manage().get_unique_space().expect("no unique space")),
                Rc::clone(arch.manage().get_default_code_space().expect("no default code space")),
            );
            engine.emit_payload(payload, tpl, context, emit)
        }
        None => arch.translate().fetch_inject_pcode(
            payload.core().get_name(),
            payload.core().get_type(),
            context,
            emit,
        ),
    }
}

#[cfg(test)]
mod tests;
