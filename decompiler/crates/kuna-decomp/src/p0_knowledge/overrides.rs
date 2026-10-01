//! Port of `decompiler/cpp/override.{cc,hh}` — the P0 override store.
//!
//! NAMING LOSS: the C++ class is `Override`, but `override` is a Rust reserved
//! keyword, so the module is named `overrides` and the type stays [`Override`]
//! (the type name is fine; only the *module path* is renamed).
//!
//! [`Override`] is a container of commands that override the decompiler's
//! default behavior for a single function:
//!
//!   - sub-functions: how they are called (`flowoverride`) and where they call
//!     to (`indirectover` direct-call redirect, `protoover` prototype replace);
//!   - jumptables: indirect jumps needing multistage analysis (`multistagejump`);
//!   - deadcode: per-address-space dead-code-elimination delay (`deadcodedelay`);
//!   - data-flow / control-flow: force a branch to be an unstructured goto
//!     (`forcegoto`).
//!
//! These commands live *independently* of the main data-flow / control-flow /
//! symbol structures and **survive a decompilation restart** — that is the whole
//! point of the P0 store (ADR 0007).  A few analyses, mid-transformation, insert
//! a new command to fix a problem discovered too late and then force a restart
//! via `Funcdata::setRestartPending()`.
//!
//! ### Dead-code-delay bump (how `heritage.cc` consumes it)
//!
//! `Heritage::bumpDeadcodeDelay(spc)` (heritage.cc:2572) is the auto-bump:
//!   1. it only fires for `IPTR_PROCESSOR` / `IPTR_SPACEBASE` spaces and only
//!      when `spc->getDelay() == spc->getDeadcodeDelay()` (no global delay yet);
//!   2. if [`Override::has_deadcode_delay`] already returns `true` for the space
//!      it returns without re-bumping (the delay is installed *once*);
//!   3. otherwise it calls
//!      `Override::insert_deadcode_delay(spc, spc->getDeadcodeDelay()+1)` and
//!      `setRestartPending(true)`.
//!
//! Because the [`Override`] is the P0 store, the bumped delay is read back on the
//! *next* decompilation pass (the restart) via [`Override::deadcode_delays`] →
//! `Funcdata::setDeadCodeDelay` → `Heritage::setDeadCodeDelay`.  The
//! [`Override::has_deadcode_delay`] guard — `val != spc->getDeadcodeDelay()` — is
//! what makes the bump idempotent across restarts: once installed, the stored
//! value differs from the space's static delay, so the predicate stays `true`
//! and the bump is never repeated.
//!
//! ### Boundaries
//!
//! - Prototype overrides own immutable completed `FuncProto` facts keyed by
//!   the caller's call instruction address, independently of callee prototypes.
//! - `applyPrototype`/`applyIndirect` copy into a `FuncCallSpecs` (W4) and
//!   `applyDeadCodeDelay`/`applyForceGoto` drive `Funcdata`/`Heritage`.  Those
//!   are exposed as query/iterator accessors here ([`Override::find_proto_override`],
//!   [`Override::find_indirect_override`], [`Override::deadcode_delays`],
//!   [`Override::force_gotos`]) so the apply logic can live at the W4/W5 call
//!   site without this module depending on the unported subsystems.  // STUB(W4)

use std::collections::{BTreeMap, BTreeSet};

use kuna_base::address::Address;
use kuna_base::error::{KunaError, KunaResult};
use kuna_base::marshal::{Decoder, ElementId, Encoder, IdRegistry, ATTRIB_SPACE, ATTRIB_TYPE};
use kuna_base::space::{AddrSpace, AddrSpaceManager, ATTRIB_DELAY};
use kuna_base::types::{int4, uint4};

// ---------------------------------------------------------------------------
// Marshaling ids (verbatim from override.cc:21-27)
// ---------------------------------------------------------------------------

/// Marshaling element `<deadcodedelay>` (`override.cc:21`).
pub const ELEM_DEADCODEDELAY: ElementId = ElementId::new("deadcodedelay", 218);
/// Marshaling element `<flow>` (`override.cc:22`).
pub const ELEM_FLOW: ElementId = ElementId::new("flow", 219);
/// Marshaling element `<forcegoto>` (`override.cc:23`).
pub const ELEM_FORCEGOTO: ElementId = ElementId::new("forcegoto", 220);
/// Marshaling element `<indirectoverride>` (`override.cc:24`).
pub const ELEM_INDIRECTOVERRIDE: ElementId = ElementId::new("indirectoverride", 221);
/// Marshaling element `<multistagejump>` (`override.cc:25`).
pub const ELEM_MULTISTAGEJUMP: ElementId = ElementId::new("multistagejump", 222);
/// Marshaling element `<override>` (`override.cc:26`).
pub const ELEM_OVERRIDE: ElementId = ElementId::new("override", 223);
/// Marshaling element `<protooverride>` (`override.cc:27`).
pub const ELEM_PROTOOVERRIDE: ElementId = ElementId::new("protooverride", 224);

/// Register every override marshaling id with an [`IdRegistry`] so a name-driven
/// `XmlDecode` resolves `<override>`/`<forcegoto>`/etc. (the C++ global
/// static-init side effect; the Rust registry is explicit).
pub fn register_ids(reg: &mut IdRegistry) {
    for e in [
        &ELEM_DEADCODEDELAY,
        &ELEM_FLOW,
        &ELEM_FORCEGOTO,
        &ELEM_INDIRECTOVERRIDE,
        &ELEM_MULTISTAGEJUMP,
        &ELEM_OVERRIDE,
        &ELEM_PROTOOVERRIDE,
    ] {
        reg.register_element(e);
    }
}

// ---------------------------------------------------------------------------
// Branch override types (override.hh:53-59)
// ---------------------------------------------------------------------------

/// Enumeration of possible branch overrides (C++ `Override` anonymous enum).
pub mod flow_type {
    use kuna_base::types::uint4;
    /// No override.
    pub const NONE: uint4 = 0;
    /// Replace primary CALL or RETURN with suitable BRANCH operation.
    pub const BRANCH: uint4 = 1;
    /// Replace primary BRANCH or RETURN with suitable CALL operation.
    pub const CALL: uint4 = 2;
    /// Replace primary BRANCH or RETURN with suitable CALL/RETURN operation.
    pub const CALL_RETURN: uint4 = 3;
    /// Replace primary BRANCH or CALL with a suitable RETURN operation.
    pub const RETURN: uint4 = 4;
}

// ---------------------------------------------------------------------------
// FuncProto boundary (override.hh: map<Address,FuncProto *> protoover)
// ---------------------------------------------------------------------------

/// Model-aware construction callback for the `<protooverride>` branch.
pub type ProtoDecoder<'a> =
    dyn FnMut(&mut dyn Decoder) -> KunaResult<crate::fspec::FuncProto> + 'a;

// ---------------------------------------------------------------------------
// Override (override.hh:50-92, override.cc:29-433)
// ---------------------------------------------------------------------------

/// \brief A container of commands that override the decompiler's default
/// behavior for a single function (C++ `Override`, the P0 store).
///
/// The C++ maps key on `Address` (`std::map`, ordered) — ported to `BTreeMap`
/// with the same [`Address`] ordering. Completed prototypes are immutable,
/// shared caller facts; call specs copy them into their own mutable state.
///
/// `Default` constructs the empty store (the C++ default-constructed `Override`).
#[derive(Clone, Default)]
pub struct Override {
    /// Force goto on jump at \b targetpc to \b destpc.
    forcegoto: BTreeMap<Address, Address>,
    /// Delay count indexed by address space (C++ `vector<int4>`; `-1` is "no
    /// override installed for this space").
    deadcodedelay: Vec<int4>,
    /// Override indirect at \b call-point into direct to \b addr.
    indirectover: BTreeMap<Address, Address>,
    /// Override prototype at \b call-point.
    protoover: BTreeMap<Address, std::rc::Rc<crate::fspec::FuncProto>>,
    /// Addresses of indirect jumps that need multistage recovery.
    multistagejump: Vec<Address>,
    /// Override the CALL <-> BRANCH interpretation of a branch instruction.
    flowoverride: BTreeMap<Address, uint4>,
    /// `/GS` checker call sites recognized after SSA and replayed on restart.
    msvc_cookie_calls: BTreeSet<Address>,
    /// (kuna `formatstring`) Call points whose prototype override is a resolved
    /// format string, installed with an open tail it sheds after P4.
    format_calls: BTreeSet<Address>,
}

impl Override {
    /// Construct the empty override store (C++ default constructor).
    pub fn new() -> Override {
        Override::default()
    }

    /// Clear the entire set of overrides (C++ `Override::clear`).
    ///
    /// Releases this store's references to the immutable prototypes.
    pub fn clear(&mut self) {
        self.forcegoto.clear();
        self.deadcodedelay.clear();
        self.indirectover.clear();
        self.protoover.clear();
        self.multistagejump.clear();
        self.flowoverride.clear();
        self.msvc_cookie_calls.clear();
        self.format_calls.clear();
    }

    /// Generate the \e warning message related to a dead-code delay
    /// (C++ `Override::generateDeadcodeDelayMessage`).
    ///
    /// \param index is the index of the address space
    /// \param glb is the Architecture's address-space manager
    fn generate_deadcode_delay_message(index: int4, glb: &AddrSpaceManager) -> String {
        let spc = glb.get_space(index).expect("generateDeadcodeDelayMessage: null space");
        format!("Restarted to delay deadcode elimination for space: {}", spc.get_name())
    }

    /// Force a specific branch instruction to be an unstructured \e goto
    /// (C++ `Override::insertForceGoto`).
    pub fn insert_force_goto(&mut self, targetpc: Address, destpc: Address) {
        self.forcegoto.insert(targetpc, destpc);
    }

    /// Override the number of passes executed before \e dead-code elimination
    /// starts, for a specific address space (C++ `Override::insertDeadcodeDelay`).
    ///
    /// The `deadcodedelay` vector is grown with `-1` placeholders up to the
    /// space's index — exactly the C++ `while (size <= index) push_back(-1)`.
    pub fn insert_deadcode_delay(&mut self, spc: &AddrSpace, delay: int4) {
        // C++ compares `size()` (a size_t) against `getIndex()` (an int4); the
        // index is always non-negative for a real space, so the comparison is
        // safe as `usize <= usize`.
        let index = spc.get_index();
        while (self.deadcodedelay.len() as i64) <= index as i64 {
            self.deadcodedelay.push(-1);
        }
        self.deadcodedelay[index as usize] = delay;
    }

    /// Check if a delay override is already installed for an address space
    /// (C++ `Override::hasDeadcodeDelay`).
    ///
    /// Returns `false` when no slot exists, when the slot is the `-1`
    /// placeholder, or when the stored value equals the space's static delay
    /// (`val != spc->getDeadcodeDelay()`).  This last check is what makes the
    /// heritage auto-bump idempotent across restarts (see module docs).
    pub fn has_deadcode_delay(&self, spc: &AddrSpace) -> bool {
        let index = spc.get_index();
        // C++ `if (index >= deadcodedelay.size())`: index (int4) vs size (size_t).
        if index as usize >= self.deadcodedelay.len() {
            return false;
        }
        let val = self.deadcodedelay[index as usize];
        if val == -1 {
            return false;
        }
        val != spc.get_deadcode_delay()
    }

    /// Override an indirect call, turning it into a direct call
    /// (C++ `Override::insertIndirectOverride`).
    pub fn insert_indirect_override(&mut self, callpoint: Address, directcall: Address) {
        self.indirectover.insert(callpoint, directcall);
    }

    /// Override the assumed function prototype at a specific call site
    /// (C++ `Override::insertProtoOverride`).
    ///
    /// The newest override at a call point wins, without mutating any other
    /// caller's seed or a callee-global prototype.
    pub fn insert_proto_override(&mut self, callpoint: Address, mut p: crate::fspec::FuncProto) {
        p.set_override(true);
        self.format_calls.remove(&callpoint);
        self.protoover.insert(callpoint, std::rc::Rc::new(p));
    }

    pub fn has_proto_overrides(&self) -> bool {
        !self.protoover.is_empty()
    }

    pub fn proto_overrides(&self) -> impl Iterator<Item = (&Address, &crate::fspec::FuncProto)> {
        self.protoover.iter().map(|(addr, proto)| (addr, proto.as_ref()))
    }

    /// Merge completed caller seeds, retaining each source's format marker.
    pub fn merge_proto_overrides(&mut self, source: &Override) {
        for (addr, proto) in &source.protoover {
            self.protoover.insert(addr.clone(), std::rc::Rc::clone(proto));
            if source.format_calls.contains(addr) {
                self.format_calls.insert(addr.clone());
            } else {
                self.format_calls.remove(addr);
            }
        }
    }

    pub fn remove_proto_override(&mut self, addr: &Address) {
        self.protoover.remove(addr);
        self.format_calls.remove(addr);
    }

    /// Flag an indirect jump for multistage analysis
    /// (C++ `Override::insertMultistageJump`).
    pub fn insert_multistage_jump(&mut self, addr: Address) {
        self.multistagejump.push(addr);
    }

    /// Mark a branch instruction with a different flow type
    /// (C++ `Override::insertFlowOverride`).
    pub fn insert_flow_override(&mut self, addr: Address, type_: uint4) {
        self.flowoverride.insert(addr, type_);
    }

    /// Record an exact `/GS` checker call site for the restart re-flow.
    pub fn insert_msvc_cookie_call(&mut self, addr: Address) {
        self.msvc_cookie_calls.insert(addr);
    }

    /// (kuna `formatstring`) Mark the prototype override at `addr` as one a
    /// resolved format string produced.
    pub fn insert_format_call(&mut self, addr: Address) {
        self.format_calls.insert(addr);
    }

    /// (kuna `formatstring`) Is the prototype override at `addr` a resolved
    /// format string's?
    pub fn is_format_call(&self, addr: &Address) -> bool {
        self.format_calls.contains(addr)
    }

    /// Has the late `/GS` recognizer seeded this exact call site?
    pub fn is_msvc_cookie_call(&self, addr: &Address) -> bool {
        self.msvc_cookie_calls.contains(addr)
    }

    /// Look up a function-prototype override at a call point (C++
    /// `Override::applyPrototype`'s map find).
    ///
    /// The call site copies this prototype before recovering mutable call state.
    pub fn find_proto_override(&self, callpoint: &Address) -> Option<&crate::fspec::FuncProto> {
        self.protoover.get(callpoint).map(|b| b.as_ref())
    }

    /// Look up a destination override for an indirect call (C++
    /// `Override::applyIndirect`'s map find).
    ///
    /// STUB(W4): the C++ then does `fspecs.setAddress(addr)`; the port returns
    /// the overriding direct-call target (or `None`).  Returns `None` when the
    /// store is empty (the C++ `if (!indirectover.empty())`).
    pub fn find_indirect_override(&self, callpoint: &Address) -> Option<&Address> {
        if self.indirectover.is_empty() {
            return None;
        }
        self.indirectover.get(callpoint)
    }

    /// Check for a multistage marker for a specific indirect jump
    /// (C++ `Override::queryMultistageJumptable`).
    ///
    /// Faithfully a linear scan in insertion order (the C++ `vector` walk), not
    /// a set lookup — a duplicate-insert stays a duplicate.
    pub fn query_multistage_jumptable(&self, addr: &Address) -> bool {
        for entry in &self.multistagejump {
            if entry == addr {
                return true;
            }
        }
        false
    }

    /// The force-goto overrides, in [`Address`] order (C++ `applyForceGoto`'s
    /// `forcegoto` walk feeding `data.forceGoto(target, dest)`).
    ///
    /// STUB(W5): the C++ `applyForceGoto` calls `Funcdata::forceGoto` for each
    /// entry; the port exposes the ordered `(target, dest)` pairs so the W5 call
    /// site drives the (already-ported) `Funcdata::force_goto`.
    pub fn force_gotos(&self) -> impl Iterator<Item = (&Address, &Address)> {
        self.forcegoto.iter()
    }

    /// The installed dead-code delays as `(space_index, delay)` pairs, skipping
    /// the `-1` placeholders (C++ `applyDeadCodeDelay`'s `deadcodedelay` walk).
    ///
    /// STUB(W5): the C++ `applyDeadCodeDelay` looks up `glb->getSpace(i)` and
    /// calls `data.setDeadCodeDelay(spc, delay)`; the port yields the
    /// `(index, delay)` pairs for the W5 call site to resolve and apply.
    pub fn deadcode_delays(&self) -> impl Iterator<Item = (int4, int4)> + '_ {
        self.deadcodedelay
            .iter()
            .enumerate()
            // i is a vector index (< len); int4 is i32, the C++ loop counter type.
            .filter(|(_, &delay)| delay >= 0)
            .map(|(i, &delay)| (i as int4, delay))
    }

    /// Return the particular flow override at a given address
    /// (C++ `Override::getFlowOverride`).  Returns [`flow_type::NONE`] when there
    /// is no override at the address.
    pub fn get_flow_override(&self, addr: &Address) -> uint4 {
        match self.flowoverride.get(addr) {
            None => flow_type::NONE,
            Some(&v) => v,
        }
    }

    /// Are there any flow overrides (C++ `Override::hasFlowOverride`).
    pub fn has_flow_override(&self) -> bool {
        !self.flowoverride.is_empty()
    }

    /// Dump a description of the overrides to a string, one per line
    /// (C++ `Override::printRaw`).
    ///
    /// \param s receives the debug text
    /// \param glb is the Architecture's address-space manager
    pub fn print_raw(&self, s: &mut String, glb: &AddrSpaceManager) {
        for (target, dest) in &self.forcegoto {
            let mut a = String::new();
            let mut b = String::new();
            // print_raw on a valid address cannot fail; an m_maximal sentinel
            // would be C++ UB and panics there too.
            target.print_raw(&mut a).expect("printRaw: forcegoto target");
            dest.print_raw(&mut b).expect("printRaw: forcegoto dest");
            s.push_str(&format!("force goto at {a} jumping to {b}\n"));
        }

        for (i, &delay) in self.deadcodedelay.iter().enumerate() {
            if delay < 0 {
                continue;
            }
            let spc = glb.get_space(i as int4).expect("printRaw: null deadcode space");
            s.push_str(&format!("dead code delay on {} set to {}\n", spc.get_name(), delay));
        }

        for (callpoint, directcall) in &self.indirectover {
            let mut a = String::new();
            let mut b = String::new();
            callpoint.print_raw(&mut a).expect("printRaw: indirect callpoint");
            directcall.print_raw(&mut b).expect("printRaw: indirect target");
            s.push_str(&format!("override indirect at {a} to call directly to {b}\n"));
        }

        for (callpoint, proto) in &self.protoover {
            let mut a = String::new();
            callpoint.print_raw(&mut a).expect("printRaw: proto callpoint");
            s.push_str(&format!("override prototype at {a} to "));
            proto.print_raw("func", s);
            s.push('\n');
        }
    }

    /// Create warning messages that describe current overrides
    /// (C++ `Override::generateOverrideMessages`).
    ///
    /// Messages are designed to be displayed in the function header comment.
    /// Only the dead-code delays generate messages.
    pub fn generate_override_messages(&self, glb: &AddrSpaceManager) -> Vec<String> {
        let mut messagelist = Vec::new();
        for (i, &delay) in self.deadcodedelay.iter().enumerate() {
            if delay >= 0 {
                messagelist.push(Override::generate_deadcode_delay_message(i as int4, glb));
            }
        }
        messagelist
    }

    /// Encode the override commands to a stream (C++ `Override::encode`).
    ///
    /// All commands are written as children of a root `<override>` element; the
    /// element is omitted entirely when every store is empty.
    ///
    /// \param encoder is the stream encoder
    /// \param glb is the Architecture's address-space manager
    pub fn encode(&self, encoder: &mut dyn Encoder, glb: &AddrSpaceManager) -> KunaResult<()> {
        if self.forcegoto.is_empty()
            && self.deadcodedelay.is_empty()
            && self.indirectover.is_empty()
            && self.protoover.is_empty()
            && self.multistagejump.is_empty()
            && self.flowoverride.is_empty()
        {
            return Ok(());
        }
        encoder.open_element(&ELEM_OVERRIDE);

        for (target, dest) in &self.forcegoto {
            encoder.open_element(&ELEM_FORCEGOTO);
            target.encode(encoder)?;
            dest.encode(encoder)?;
            encoder.close_element(&ELEM_FORCEGOTO);
        }

        for (i, &delay) in self.deadcodedelay.iter().enumerate() {
            if delay < 0 {
                continue;
            }
            let spc = glb.get_space(i as int4).expect("encode: null deadcode space");
            encoder.open_element(&ELEM_DEADCODEDELAY);
            encoder.write_space(&ATTRIB_SPACE, spc);
            encoder.write_signed_integer(&ATTRIB_DELAY, delay as i64);
            encoder.close_element(&ELEM_DEADCODEDELAY);
        }

        for (callpoint, directcall) in &self.indirectover {
            encoder.open_element(&ELEM_INDIRECTOVERRIDE);
            callpoint.encode(encoder)?;
            directcall.encode(encoder)?;
            encoder.close_element(&ELEM_INDIRECTOVERRIDE);
        }

        for (callpoint, proto) in &self.protoover {
            encoder.open_element(&ELEM_PROTOOVERRIDE);
            callpoint.encode(encoder)?;
            proto.encode_internal(encoder)?;
            encoder.close_element(&ELEM_PROTOOVERRIDE);
        }

        for addr in &self.multistagejump {
            encoder.open_element(&ELEM_MULTISTAGEJUMP);
            addr.encode(encoder)?;
            encoder.close_element(&ELEM_MULTISTAGEJUMP);
        }

        for (addr, &type_) in &self.flowoverride {
            encoder.open_element(&ELEM_FLOW);
            encoder.write_string(&ATTRIB_TYPE, Override::type_to_string(type_).as_bytes());
            addr.encode(encoder)?;
            encoder.close_element(&ELEM_FLOW);
        }
        encoder.close_element(&ELEM_OVERRIDE);
        Ok(())
    }

    /// Parse an `<override>` element containing override commands
    /// (C++ `Override::decode`).
    ///
    /// The callback resolves the model and materializes complete storage before
    /// insertion; no declaration pieces or flow-time ABI reassignment remain.
    pub fn decode(
        &mut self,
        decoder: &mut dyn Decoder,
        proto_decoder: &mut ProtoDecoder<'_>,
    ) -> KunaResult<()> {
        let elem_id = decoder.open_element_id(&ELEM_OVERRIDE)?;
        loop {
            let sub_id = decoder.open_element()?;
            if sub_id == 0 {
                break;
            }
            if sub_id == ELEM_INDIRECTOVERRIDE {
                let callpoint = Address::decode(decoder)?;
                let directcall = Address::decode(decoder)?;
                self.insert_indirect_override(callpoint, directcall);
            } else if sub_id == ELEM_PROTOOVERRIDE {
                let callpoint = Address::decode(decoder)?;
                let fp = proto_decoder(decoder)?;
                self.insert_proto_override(callpoint, fp);
            } else if sub_id == ELEM_FORCEGOTO {
                let targetpc = Address::decode(decoder)?;
                let destpc = Address::decode(decoder)?;
                self.insert_force_goto(targetpc, destpc);
            } else if sub_id == ELEM_DEADCODEDELAY {
                let delay = decoder.read_signed_integer_id(&ATTRIB_DELAY)?;
                let spc = decoder.read_space_id(&ATTRIB_SPACE)?;
                if delay < 0 {
                    return Err(KunaError::lowlevel("Bad deadcodedelay tag"));
                }
                // delay was just checked non-negative; it fits int4 as in the
                // C++ `readSignedInteger` -> int4 assignment.
                self.insert_deadcode_delay(&spc, delay as int4);
            } else if sub_id == ELEM_MULTISTAGEJUMP {
                let callpoint = Address::decode(decoder)?;
                self.insert_multistage_jump(callpoint);
            } else if sub_id == ELEM_FLOW {
                let type_ = Override::string_to_type(&decoder.read_string_id(&ATTRIB_TYPE)?);
                let addr = Address::decode(decoder)?;
                if type_ == flow_type::NONE || addr.is_invalid() {
                    return Err(KunaError::lowlevel("Bad flowoverride tag"));
                }
                self.insert_flow_override(addr, type_);
            }
            decoder.close_element(sub_id)?;
        }
        decoder.close_element(elem_id)?;
        Ok(())
    }

    /// Convert a flow override type to a string (C++ `Override::typeToString`).
    pub fn type_to_string(tp: uint4) -> &'static str {
        if tp == flow_type::BRANCH {
            return "branch";
        }
        if tp == flow_type::CALL {
            return "call";
        }
        if tp == flow_type::CALL_RETURN {
            return "callreturn";
        }
        if tp == flow_type::RETURN {
            return "return";
        }
        "none"
    }

    /// Convert a string to a flow override type (C++ `Override::stringToType`).
    pub fn string_to_type(nm: &[u8]) -> uint4 {
        if nm == b"branch" {
            flow_type::BRANCH
        } else if nm == b"call" {
            flow_type::CALL
        } else if nm == b"callreturn" {
            flow_type::CALL_RETURN
        } else if nm == b"return" {
            flow_type::RETURN
        } else {
            flow_type::NONE
        }
    }
}

#[cfg(test)]
mod tests;
