//! The ghidra-mode command loop — a port of `decompiler/cpp/ghidra_process.cc`
//! (`GhidraCapability::readCommand`, `GhidraCommand::doit`, and the seven
//! decomp-capability commands, ghidra_process.cc:86-506).
//!
//! Lifecycle per command (`doit`, ghidra_process.cc:125-160), preserved
//! exactly:
//!
//! ```text
//!   write {0,0,1,6}                        response OPEN — before any work
//!   loadParameters()                       archid as ASCII decimal in a
//!                                          string stream (every command
//!                                          except registerProgram), plus
//!                                          command-specific params
//!   expect burst 3 (command close)
//!   rawAction()
//!   catch DecoderError  -> "Marshaling error: ..."     (warning)
//!   catch JavaError     -> passJavaException, NO sendResult
//!   catch RecovError    -> "Recoverable Error: ..."    (warning)
//!   catch LowlevelError -> "Low-level Error: ..."      (warning)
//!   sendResult()                           optional payload, then ALWAYS
//!                                          the 16/17 warnings frame
//!                                          (possibly empty) — but only
//!                                          while a session is bound
//!   write {0,0,1,7}; flush
//! ```
//!
//! Because the response-open burst is written first, any queries a command
//! issues are nested inside the open command response (the phase-2 engine
//! bridge relies on this).
//!
//! Phase-2 step 6 (see `docs/rust-port/ghidra-phase2-plan.md`): registerProgram
//! builds a *live* [`Architecture`] over the query-backed [`GhidraTranslate`] —
//! its `init_post_engine` issues the getUserOpName probe loop as a real query
//! nested in the registerProgram response — and `decompileAt` now DRIVES that
//! engine: it names the function (getCodeLabel), runs [`decompile_func`] (whose
//! providers issue the getPcode/getBytes/… queries nested in the still-open
//! decompileAt response), and emits the `<doc>` response — `Funcdata::encode`'s
//! `<function>`/`<ast>` plus the Clang-markup `<function>` — the first real C
//! from kuna in ghidra mode. Acquisition, action and emission errors return
//! through the command error boundary before any result payload is opened;
//! recoverable errors use the native-message channel, while terminal transport
//! errors stop the connection. Native graph
//! and signature commands share the canonical engine codecs; body-derived
//! evidence is detached at host flush and eligible configuration changes.

use std::cell::RefCell;
use std::io::{Read, Write};
use std::rc::Rc;

use kuna_base::address::Address;
use kuna_base::error::{KunaError, KunaResult};
use kuna_base::marshal::{Decoder, Encoder, PackedDecode, PackedEncode};
use kuna_base::space::AddrSpaceManager;

use kuna_decomp::architecture::Architecture;
use kuna_decomp::funcdata::Funcdata;
use kuna_decomp::options::OptionDatabase;
use kuna_decomp::resulttypes::{ResultTypeTable, RESULT_VERSION};

use crate::client::GhidraClient;
use crate::provider::GhidraRemoteFetch;
use crate::ids::ELEM_DOC;
use crate::protocol::{
    pass_java_exception, read_string_stream, read_string_stream_optional, read_to_any_burst,
    write_burst, write_string_stream, WireError, WireResult, BURST_COMMAND_CLOSE,
    BURST_COMMAND_OPEN, BURST_MESSAGE_CLOSE, BURST_MESSAGE_OPEN, BURST_RESPONSE_CLOSE,
    BURST_RESPONSE_OPEN, BURST_STRING_CLOSE, BURST_STRING_OPEN,
};
use crate::provider::SharedClient;
use crate::translate::{build_registry, GhidraTranslate};

/// One registered program: the kuna analog of an `ArchitectureGhidra` slot
/// in the global `archlist` (ghidra_process.cc:76,176-201).
///
/// Phase-2 step 3 makes this a *live engine*: registerProgram builds a real
/// [`Architecture`] over the query-backed [`GhidraTranslate`] (the four wire
/// specs → `from_engine_translate` + the console frontend's cspec/pspec →
/// `init_post_engine` tail).  Its space manager decodes wire \<addr> elements
/// and its subsystems are exercised by `decompileAt` (the next step).
struct Session {
    /// The live decompiler engine built from the four registerProgram specs
    /// (C++ `ArchitectureGhidra`, the `archlist` slot's `Architecture`).
    /// `None` when engine construction failed — the failure is recorded on
    /// `warnings` (shipped on the 16/17 frame) so Java detects the
    /// registration failure (DecompInterface.java:291-294).
    architecture: Option<Architecture>,
    /// Accumulated warnings, shipped on the 16/17 channel by sendResult
    /// (C++ `ArchitectureGhidra::warnings`; `printMessage` appends
    /// `'\n' + message`, ghidra_arch.cc:898-902).
    warnings: String,
    /// setAction "tree"/"notree" (C++ `sendsyntaxtree`, default true).
    send_syntax_tree: bool,
    /// setAction "c"/"noc" (C++ `sendCcode`, default true).
    send_c_code: bool,
    /// setAction "parammeasures"/"noparammeasures" (default false).
    send_param_measures: bool,
}

impl Session {
    /// A fresh session shell (defaults only); the live [`Architecture`] is
    /// installed after construction by [`GhidraProcess::build_architecture`].
    fn new() -> Session {
        Session {
            architecture: None,
            warnings: String::new(),
            // ArchitectureGhidra constructor defaults (ghidra_arch.cc:912-926)
            send_syntax_tree: true,
            send_c_code: true,
            send_param_measures: false,
        }
    }

    /// The engine's space manager (for decoding wire \<addr> elements), or
    /// `None` when construction failed.
    fn manager(&self) -> Option<&AddrSpaceManager> {
        self.architecture.as_ref().map(|a| a.manage())
    }

    /// C++ `ArchitectureGhidra::printMessage` (ghidra_arch.cc:898-902).
    fn print_message(&mut self, message: &str) {
        self.warnings.push('\n');
        self.warnings.push_str(message);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CommandKind {
    RegisterProgram,
    DeregisterProgram,
    FlushNative,
    DecompileAt,
    SetAction,
    SetOptions,
    StructureGraph,
    GenerateSignatures,
    DebugSignatures,
    GetSignatureSettings,
    SetSignatureSettings,
    PrepareSelectedRoots,
}

/// Per-command scratch state (the C++ `GhidraCommand` subclass members).
struct CommandState {
    kind: CommandKind,
    /// The bound archlist slot (C++ `ghidra` member); `None` until
    /// loadParameters binds it, and unbound again by deregister (C++ nulls
    /// `ghidra` after delete, so its sendResult skips the 16/17 frame).
    slot: Option<usize>,
    /// 0 = keep looping, 1 = terminate (C++ `status`).
    status: i32,
    /// registerProgram result (C++ `RegisterProgram::archid`).
    archid: i32,
    /// deregisterProgram / flushNative result (C++ `res`).
    res: i32,
    /// setAction / setOptions result (C++ `res` bool).
    ok: bool,
    /// registerProgram params.
    specs: Option<[Vec<u8>; 4]>,
    /// setAction params.
    actionstring: Vec<u8>,
    printstring: Vec<u8>,
    /// decompileAt param: the decoded entry address (None if the engine is
    /// unavailable), driving the [`decompile_func`] build.
    addr: Option<Address>,
    /// setOptions param: the raw packed `<optionslist>` (applied in rawAction).
    optionslist: Option<Vec<u8>>,
}

impl CommandState {
    fn new(kind: CommandKind) -> CommandState {
        CommandState {
            kind,
            slot: None,
            status: 0,
            archid: -1,
            res: 0,
            ok: false,
            specs: None,
            actionstring: Vec::new(),
            printstring: Vec::new(),
            addr: None,
            optionslist: None,
        }
    }
}

/// The ghidra-mode process: the command loop over the two protocol streams
/// plus the architecture list (C++ `archlist` + `GhidraCapability::
/// readCommand`, ghidra_process.cc:76,464-486).
///
/// The process no longer owns `sin`/`sout` directly: it owns the
/// [`SharedClient`] (`Rc<RefCell<GhidraClient>>`) that every session's engine
/// providers (`GhidraTranslate`/`GhidraLoadImage`) hold `Rc::clone`s of.  The
/// command loop frames each response through a *short-lived*
/// `self.client.borrow_mut()` (via [`GhidraClient::sin_mut`]/
/// [`GhidraClient::sout_mut`]); mid-decompile the engine re-entrantly issues
/// callback queries through the same client on the same streams.
///
/// **The soundness invariant** (matching the C++ single-owner `glb` model): the
/// loop must NEVER hold a `client` borrow across [`raw_action`](GhidraProcess::raw_action),
/// where the engine re-entrantly calls providers that `borrow_mut()` the same
/// client.  Each framing read/write here borrows, acts, and drops before the
/// next statement, and the protocol is strictly synchronous (exactly one query
/// is ever in flight, completing before the engine regains control), so no two
/// borrows ever overlap.
pub struct GhidraProcess<R: Read + 'static, W: Write + 'static> {
    client: SharedClient<R, W>,
    archlist: Vec<Option<Session>>,
}

impl<R: Read + 'static, W: Write + 'static> GhidraProcess<R, W> {
    /// Construct over the two protocol streams (stdin/stdout in the real
    /// binary; in-memory buffers in tests), wrapping them in the
    /// [`SharedClient`] the loop and the engine providers share.
    pub fn new(sin: R, sout: W) -> Self {
        GhidraProcess {
            client: Rc::new(RefCell::new(GhidraClient::new(sin, sout))),
            archlist: Vec::new(),
        }
    }

    /// Tear down into the underlying streams (test access to the written
    /// response bytes).
    ///
    /// Drops every session first: each holds an [`Architecture`] whose ghidra
    /// translator carries an `Rc::clone` of the shared client, so the client is
    /// uniquely owned (and unwrappable) only once the archlist is gone.  In the
    /// real binary this is never called (the process runs to a terminating
    /// status); tests call it after deregistering / dropping all sessions.
    pub fn into_inner(self) -> (R, W) {
        let GhidraProcess { client, archlist } = self;
        drop(archlist);
        match Rc::try_unwrap(client) {
            Ok(cell) => cell.into_inner().into_inner(),
            Err(_) => panic!(
                "GhidraProcess::into_inner: the shared client is still referenced by a \
                 live session engine (deregister or drop all sessions first)"
            ),
        }
    }

    /// Apply a kuna-owned option to a live session for integration tests.
    ///
    /// Kuna options do not have upstream wire element ids, so the stock Java
    /// client cannot place one in its `<optionslist>`.  Tests use this seam to
    /// exercise option-gated engine paths through the real ghidra-mode process
    /// without changing the production wire protocol.
    #[doc(hidden)]
    pub fn set_kuna_option_for_test(
        &mut self,
        archid: usize,
        name: &str,
        value: &str,
    ) -> KunaResult<String> {
        let arch = self
            .archlist
            .get_mut(archid)
            .and_then(Option::as_mut)
            .and_then(|session| session.architecture.as_mut())
            .ok_or_else(|| KunaError::lowlevel(format!("no live architecture {archid}")))?;
        arch.set_kuna_option(name, value)
    }

    /// Run the process loop until a command terminates it (C++ `main`'s
    /// `while(status == 0) status = readCommand(...)`,
    /// ghidra_process.cc:532-535).  Returns the terminating status.
    pub fn run(&mut self) -> WireResult<i32> {
        loop {
            let status = self.read_command()?;
            if status != 0 {
                return Ok(status);
            }
        }
    }

    /// Read and execute one command (C++ `GhidraCapability::readCommand`,
    /// ghidra_process.cc:464-486).  Returns the command's meta-status
    /// (0 = continue, 1 = terminate).
    pub fn read_command(&mut self) -> WireResult<i32> {
        // Align ourselves: scan to the next command-open burst, skipping
        // anything else (including the dangling params + close burst of a
        // rejected command).
        loop {
            if read_to_any_burst(self.client.borrow_mut().sin_mut())? == BURST_COMMAND_OPEN {
                break;
            }
        }
        let name_bytes = read_string_stream(self.client.borrow_mut().sin_mut())?;
        let name = String::from_utf8_lossy(&name_bytes).into_owned();
        let kind = match name.as_str() {
            "registerProgram" => CommandKind::RegisterProgram,
            "deregisterProgram" => CommandKind::DeregisterProgram,
            "flushNative" => CommandKind::FlushNative,
            "decompileAt" => CommandKind::DecompileAt,
            "setAction" => CommandKind::SetAction,
            "setOptions" => CommandKind::SetOptions,
            "structureGraph" => CommandKind::StructureGraph,
            "generateSignatures" => CommandKind::GenerateSignatures,
            "debugSignatures" => CommandKind::DebugSignatures,
            "getSignatureSettings" => CommandKind::GetSignatureSettings,
            "setSignatureSettings" => CommandKind::SetSignatureSettings,
            "prepareSelectedRoots" => CommandKind::PrepareSelectedRoots,
            _ => {
                write_burst(self.client.borrow_mut().sout_mut(), BURST_RESPONSE_OPEN)?;
                write_burst(self.client.borrow_mut().sout_mut(), BURST_MESSAGE_OPEN)?;
                self.client
                    .borrow_mut()
                    .sout_mut()
                    .write_all(format!("Bad command: {name}").as_bytes())
                    .map_err(WireError::Io)?;
                write_burst(self.client.borrow_mut().sout_mut(), BURST_MESSAGE_CLOSE)?;
                write_burst(self.client.borrow_mut().sout_mut(), BURST_RESPONSE_CLOSE)?;
                self.client
                    .borrow_mut()
                    .sout_mut()
                    .flush()
                    .map_err(WireError::Io)?;
                return Ok(0);
            }
        };
        self.doit(kind)
    }

    /// The canonical command lifecycle (C++ `GhidraCommand::doit`,
    /// ghidra_process.cc:125-160).
    fn doit(&mut self, kind: CommandKind) -> WireResult<i32> {
        let mut cmd = CommandState::new(kind);
        // Command response header — BEFORE any work, so queries nest inside.
        // Borrow the client only for this framing write, then drop it: the
        // rawAction inside run_command re-borrows it per callback query, and the
        // loop must never hold a borrow across that re-entry (see the struct doc).
        write_burst(self.client.borrow_mut().sout_mut(), BURST_RESPONSE_OPEN)?;
        let result = self.run_command(&mut cmd);
        match result {
            Ok(()) => {}
            // Pipe/IO failures propagate to the process loop (C++ exit(1))
            Err(e @ (WireError::PipeClosed | WireError::Io(_))) => return Err(e),
            Err(WireError::Kuna(e @ KunaError::Transport { .. })) => return Err(e.into()),
            // catch(JavaError): pass the exception, abort sending results
            Err(WireError::Kuna(KunaError::Java { type_name, explain })) => {
                pass_java_exception(self.client.borrow_mut().sout_mut(), &type_name, &explain)?;
                // C++ relies on cin.tie(&cout) flushing before the next
                // blocking read; Rust must flush explicitly.
                self.client
                    .borrow_mut()
                    .sout_mut()
                    .flush()
                    .map_err(WireError::Io)?;
                return Ok(cmd.status);
            }
            // catch(DecoderError) / catch(RecovError) / catch(LowlevelError):
            // classify into a warning (KunaError::Decoder is the standalone
            // C++ DecoderError; Recov its subclass family; every other
            // variant derives LowlevelError — see kuna-base error.rs docs)
            Err(WireError::Kuna(err)) => {
                let errmsg = match &err {
                    KunaError::Decoder { .. } => format!("Marshaling error: {}", err.explain()),
                    KunaError::Recov { .. } => format!("Recoverable Error: {}", err.explain()),
                    _ => format!("Low-level Error: {}", err.explain()),
                };
                self.print_message(cmd.slot, &errmsg);
            }
        }
        self.send_result(&cmd)?;
        write_burst(self.client.borrow_mut().sout_mut(), BURST_RESPONSE_CLOSE)?;
        self.client
            .borrow_mut()
            .sout_mut()
            .flush()
            .map_err(WireError::Io)?;
        Ok(cmd.status)
    }

    /// loadParameters + the command-close burst + rawAction (the `try`
    /// body of doit).
    fn run_command(&mut self, cmd: &mut CommandState) -> WireResult<()> {
        self.load_parameters(cmd)?;
        let t = read_to_any_burst(self.client.borrow_mut().sin_mut())?;
        if t != BURST_COMMAND_CLOSE {
            return Err(WireError::Kuna(KunaError::java(
                "alignment",
                "Missing end of command",
            )));
        }
        self.raw_action(cmd)
    }

    // -- loadParameters -----------------------------------------------------

    /// The base `GhidraCommand::loadParameters` (ghidra_process.cc:86-103):
    /// the architecture id as ASCII decimal in a string stream, validated
    /// against the archlist, then `clearWarnings`.
    fn bind_session(&mut self, start_msg: &str, end_msg: &str) -> WireResult<usize> {
        let t = read_to_any_burst(self.client.borrow_mut().sin_mut())?;
        if t != BURST_STRING_OPEN {
            return Err(WireError::Kuna(KunaError::java("alignment", start_msg)));
        }
        let (payload, code) = crate::protocol::read_id_payload(self.client.borrow_mut().sin_mut())?;
        if code != BURST_STRING_CLOSE {
            return Err(WireError::Kuna(KunaError::java("alignment", end_msg)));
        }
        let id = parse_arch_id(&payload);
        if id >= 0 && (id as usize) < self.archlist.len() && self.archlist[id as usize].is_some() {
            let slot = id as usize;
            // ghidra->clearWarnings()
            if let Some(session) = self.archlist[slot].as_mut() {
                session.warnings.clear();
            }
            return Ok(slot);
        }
        Err(WireError::Kuna(KunaError::java(
            "decompiler",
            "No architecture registered with decompiler",
        )))
    }

    fn load_parameters(&mut self, cmd: &mut CommandState) -> WireResult<()> {
        match cmd.kind {
            // RegisterProgram::loadParameters (ghidra_process.cc:162-173):
            // four consecutive string streams, no arch id
            CommandKind::RegisterProgram => {
                let pspec = read_string_stream(self.client.borrow_mut().sin_mut())?;
                let cspec = read_string_stream(self.client.borrow_mut().sin_mut())?;
                let tspec = read_string_stream(self.client.borrow_mut().sin_mut())?;
                let corespec = read_string_stream(self.client.borrow_mut().sin_mut())?;
                cmd.specs = Some([pspec, cspec, tspec, corespec]);
                Ok(())
            }
            // DeregisterProgram::loadParameters (ghidra_process.cc:212-229)
            CommandKind::DeregisterProgram => {
                let slot = self.bind_session(
                    "Expecting deregister id start",
                    "Expecting deregister id end",
                )?;
                cmd.slot = Some(slot);
                Ok(())
            }
            CommandKind::FlushNative | CommandKind::GetSignatureSettings => {
                let slot = self.bind_session("Expecting arch id start", "Expecting arch id end")?;
                cmd.slot = Some(slot);
                Ok(())
            }
            // DecompileAt::loadParameters (ghidra_process.cc:284-291): base,
            // then the packed <addr> ingested and decoded
            CommandKind::DecompileAt | CommandKind::GenerateSignatures | CommandKind::DebugSignatures => {
                let slot = self.bind_session("Expecting arch id start", "Expecting arch id end")?;
                cmd.slot = Some(slot);
                let raw = read_string_stream_optional(self.client.borrow_mut().sin_mut())?;
                let session = self.archlist[slot].as_ref().expect("bound session");
                match (session.manager(), raw) {
                    (Some(manager), Some(bytes)) => {
                        let mut decoder = PackedDecode::new(manager);
                        decoder.ingest_stream(&bytes).map_err(WireError::Kuna)?;
                        let addr = Address::decode(&mut decoder).map_err(WireError::Kuna)?;
                        cmd.addr = Some(addr);
                    }
                    (None, Some(_bytes)) => {
                        // Engine construction failed: the <addr> was consumed
                        // but cannot be decoded (the session already carries the
                        // construction-failure warning on its 16/17 frame).
                        cmd.addr = None;
                    }
                    (_, None) => {
                        // Missing payload: C++ Address::decode on the empty
                        // decoder raises DecoderError -> "Marshaling error"
                        return Err(WireError::Kuna(KunaError::decoder(
                            "Expecting <addr> element",
                        )));
                    }
                }
                Ok(())
            }
            // SetAction::loadParameters (ghidra_process.cc:368-376)
            CommandKind::SetAction => {
                let slot = self.bind_session("Expecting arch id start", "Expecting arch id end")?;
                cmd.slot = Some(slot);
                cmd.actionstring = read_string_stream(self.client.borrow_mut().sin_mut())?;
                cmd.printstring = read_string_stream(self.client.borrow_mut().sin_mut())?;
                Ok(())
            }
            // SetOptions::loadParameters (ghidra_process.cc:418-426): base,
            // then the packed <optionslist> string stream
            CommandKind::SetOptions | CommandKind::StructureGraph | CommandKind::SetSignatureSettings
                | CommandKind::PrepareSelectedRoots => {
                let slot = self.bind_session("Expecting arch id start", "Expecting arch id end")?;
                cmd.slot = Some(slot);
                cmd.optionslist =
                    read_string_stream_optional(self.client.borrow_mut().sin_mut())?;
                Ok(())
            }
        }
    }

    // -- rawAction ------------------------------------------------------------

    fn raw_action(&mut self, cmd: &mut CommandState) -> WireResult<()> {
        match cmd.kind {
            // RegisterProgram::rawAction (ghidra_process.cc:176-201): find a
            // free slot (the C++ loop keeps the LAST open slot), install a
            // session shell, build the live engine, archid = slot index.
            CommandKind::RegisterProgram => {
                let [pspec, cspec, tspec, corespec] =
                    cmd.specs.take().expect("registerProgram params");
                require_result_version(&corespec)?;
                let mut open: Option<usize> = None;
                for (i, s) in self.archlist.iter().enumerate() {
                    if s.is_none() {
                        open = Some(i); // C++ keeps scanning: last open slot
                    }
                }
                let slot = match open {
                    Some(i) => {
                        self.archlist[i] = Some(Session::new());
                        i
                    }
                    None => {
                        self.archlist.push(Some(Session::new()));
                        self.archlist.len() - 1
                    }
                };
                cmd.slot = Some(slot);
                cmd.archid = slot as i32;
                // Build the live engine over the four wire specs.  This issues
                // the init-time queries (the getUserOpName probe loop, C++
                // `userops.initialize`) on the shared client — nested inside the
                // still-open registerProgram command response.  The slot (and so
                // the warning sink) is bound BEFORE this fallible build, so a
                // construction failure ships its error on the 16/17 warnings
                // frame and Java treats the non-empty nativeMessage as a
                // registration failure (DecompInterface.java:291-294; the C++
                // `RegisterProgram::rawAction` assigns `ghidra` before `init` for
                // exactly this reason, ghidra_process.cc:176-201).
                match self.build_architecture(cmd.archid, &pspec, &cspec, &tspec, &corespec) {
                    Ok(arch) => {
                        self.archlist[slot]
                            .as_mut()
                            .expect("bound session")
                            .architecture = Some(arch);
                    }
                    Err(e) => {
                        if matches!(e, KunaError::Transport { .. }) {
                            return Err(e.into());
                        }
                        self.print_message(
                            cmd.slot,
                            &format!(
                                "kuna ghidra-mode: could not build the decompiler engine from \
                                 the registerProgram specs ({}); this program will not decompile",
                                e.explain()
                            ),
                        );
                    }
                }
                Ok(())
            }
            // DeregisterProgram::rawAction (ghidra_process.cc:231-251):
            // free the slot, res=1, status=1 terminates the process loop.
            // C++ nulls `ghidra` after the delete, so the base sendResult's
            // 16/17 frame is skipped — mirror by unbinding the slot.
            CommandKind::DeregisterProgram => {
                if let Some(slot) = cmd.slot.take() {
                    cmd.res = 1;
                    self.archlist[slot] = None;
                    cmd.status = 1;
                } else {
                    cmd.res = 0;
                }
                Ok(())
            }
            // FlushNative::rawAction (ghidra_process.cc:262-273), Phase 3: clear
            // the per-function provider caches in the upstream order — the lazy
            // symbol cache (holes + entries + property-map rollback), the
            // non-core types, the comment database, the decoded strings
            // (`Architecture::flush_remote_caches`).
            CommandKind::FlushNative => {
                if let Some(slot) = cmd.slot {
                    if let Some(session) = self.archlist[slot].as_mut() {
                        if let Some(arch) = session.architecture.as_mut() {
                            arch.flush_remote_caches();
                        }
                    }
                }
                cmd.res = 0;
                Ok(())
            }
            // DecompileAt::rawAction (ghidra_process.cc:293-335): the live
            // engine bridge.  Establish the function name (getCodeLabel), drive
            // `decompile_func` to a ready-to-print `Funcdata` (its providers
            // issue the getPcode/getBytes/… queries nested inside this still-open
            // command response), then emit the `<doc>` between the 14/15 burst —
            // `fd.encode` (the `<function>`/`<ast>` syntax tree) plus, when C is
            // requested for the `decompile` action, the Clang-markup `<function>`
            // spliced into the SAME `<doc>` stream. Exceptions propagate before
            // the result stream opens, preserving their native diagnostic.
            CommandKind::DecompileAt | CommandKind::GenerateSignatures | CommandKind::DebugSignatures => {
                let slot = cmd.slot.expect("bound session");
                // A failed registration has no manager. Return through the
                // ordinary command error boundary without opening a result.
                let addr = match cmd.addr.clone() {
                    Some(a) => a,
                    None => {
                        return Err(KunaError::lowlevel(
                            "decompiler engine unavailable; function address could not be decoded",
                        ).into());
                    }
                };

                // (2) Establish the current-function identity.  Phase 3: query
                // getMappedSymbols FIRST through the lazy provider — the
                // `<mapsym><function>` answer carries Java's `Function.getName()`
                // (namespaced), which is what `HighFunction.decode`'s name-echo
                // check compares against, plus the locked prototype pieces that
                // seed the Funcdata.  `getCodeLabel` stays as the fallback for an
                // address the host answers nothing at, then the synthesized
                // `FUN_<addr>`.  All query borrows are short-lived (the
                // no-borrow-across-decompile invariant).
                let remote = self.archlist[slot]
                    .as_ref()
                    .and_then(|s| s.architecture.as_ref())
                    .and_then(|a| a.remote_scope.clone());
                let facts = match &remote {
                    Some(r) => r.function_at(&addr).map_err(WireError::from)?,
                    None => None,
                };
                // The RAW `Function.getName()` is the Funcdata identity (the
                // HighFunction.decode name echo compares against it); the
                // label, when the host sent one (TemplateSimplifier), is only
                // the display form the printed signature uses.
                let (
                    name,
                    display_name,
                ) = match facts {
                    Some(f) => (
                        f.name,
                        f.display_name,
                    ),
                    None => {
                        let label = self.client.borrow_mut().get_code_label(&addr);
                        let n = match label {
                            Ok(l) if !l.is_empty() => {
                                String::from_utf8_lossy(&l).into_owned()
                            }
                            Err(e) => return Err(e),
                            _ => format!("FUN_{:08x}", addr.get_offset()),
                        };
                        (n.clone(), n)
                    }
                };

                // (2b) The ghidra-mode banner (user-requested): a plate
                // comment at the top of EVERY decompiled function so it is
                // visible inside Ghidra that kuna is the active core.
                // Cache-only (never written back to the host, never on the
                // 16/17 frame); the version is baked at build time exactly
                // like the kuna CLI's (`KUNA_VERSION` from the release build
                // matrix, the workspace version on dev builds).  Then fill the
                // per-function comment cache from the host
                // (CommentDatabaseGhidra::fillCache semantics: once per flush
                // cycle, filtered by the printer's comment settings; an empty
                // filter issues no query).
                {
                    let session = self.archlist[slot].as_mut().expect("bound session");
                    if let Some(arch) = session.architecture.as_mut() {
                        arch.commentdb.add_comment_no_duplicate(
                            kuna_decomp::comment::comment_type::HEADER,
                            &addr,
                            &addr,
                            &kuna_banner_text(),
                        );
                        if let Some(remote) = &remote {
                            let filter = arch.printer_comment_filter();
                            let sink = &mut arch.commentdb;
                            remote.fill_comments(&addr, filter, sink).map_err(WireError::from)?;
                        }
                    }
                }

                // (2c) Per-entry host context: getTrackedRegisters (the
                // upstream ContextGhidra), merged OVER the pspec defaults —
                // wire values win per register, pspec fills the gaps — so
                // per-address host facts (MIPS gp, PPC TOC, a user 'Set
                // Register Value') reach ActionConstbase.  Cached in the
                // provider until flushNative.
                if let Some(remote) = &remote {
                    if let Some(wire_set) = remote.tracked_at(&addr).map_err(WireError::from)? {
                        // Write when the wire reports values OR a previous
                        // epoch merged here (the revert case: the host STOPPED
                        // reporting a value, so the pristine layer must be
                        // written back — upstream stores nothing and rebuilds
                        // per call; kuna's trackbase persists, hence the
                        // explicit pristine base).
                        if !wire_set.is_empty() || remote.has_pristine_tracked(&addr) {
                            let session =
                                self.archlist[slot].as_mut().expect("bound session");
                            if let Some(arch) = session.architecture.as_mut() {
                                let manager = arch.translate().manager_rc();
                                let spc = std::rc::Rc::clone(
                                    addr.get_space().expect("entry addr has a space"),
                                );
                                // Open upper bound via the Range helper (an
                                // entry at the very top of its space must not
                                // wrap the bound to 0).
                                let upper = kuna_base::address::Range::new(
                                    spc,
                                    addr.get_offset(),
                                    addr.get_offset(),
                                )
                                .get_last_addr_open(&manager);
                                arch.with_context_db_mut(|db| {
                                    // Merge wire-over-PRISTINE (captured on the
                                    // first merge at this address), never over
                                    // the previously-merged set.
                                    let current = db.get_tracked_set(&addr).clone();
                                    let mut merged =
                                        remote.pristine_tracked_for(&addr, current);
                                    for w in &wire_set {
                                        match merged.iter_mut().find(|t| t.loc == w.loc) {
                                            Some(t) => t.val = w.val,
                                            None => merged.push(w.clone()),
                                        }
                                    }
                                    *db.create_set(&addr, &upper) = merged;
                                });
                            }
                        }
                    }
                }

                // Snapshot the render flags before taking `&mut Architecture`.
                let (send_syntax_tree, send_c_code, send_param_measures) = {
                    let session = self.archlist[slot].as_ref().expect("bound session");
                    (
                        session.send_syntax_tree,
                        session.send_c_code,
                        session.send_param_measures,
                    )
                };

                // (3) Drive the decompile FULLY — releasing every provider query
                // borrow — BEFORE re-borrowing the client to write the `<doc>`.
                // `size = 0` = the flow-discovered natural extent (the console
                // decompile-all path's shape: build a `Funcdata` for the raw
                // entry, let flow-following via the getPcode/getBytes providers
                // discover the body).  Assemble the response document while the
                // `&mut Architecture` is in hand (the markup needs `&Architecture`).
                let doc: KunaResult<Vec<u8>> = {
                    let session = self.archlist[slot].as_mut().expect("bound session");
                    let arch = session
                        .architecture
                        .as_mut()
                        .expect("addr decoded ⇒ engine present");
                    let saved_root = arch.allacts.get_current_name().to_string();
                    let signature = matches!(cmd.kind, CommandKind::GenerateSignatures | CommandKind::DebugSignatures);
                    if signature {
                        arch.allacts.set_current("normalize").map_err(WireError::from)?;
                    }
                    let driven = kuna_decomp::decompile_drive::decompile_func_full(
                        arch, &name, addr.clone(), 0, &[], None,
                    );
                    if signature {
                        arch.allacts.set_current(&saved_root).map_err(WireError::from)?;
                    }
                    match driven {
                        Ok(mut fd) => {
                            // The printed signature/tokens use the display
                            // form; fd.encode's ATTRIB_NAME stays the RAW name
                            // (the Java-side identity echo).
                            if display_name != name {
                                fd.set_display_name(&display_name);
                            }
                            if signature {
                                let mut bytes = Vec::new();
                                let mut encoder = PackedEncode::new(&mut bytes);
                                if cmd.kind == CommandKind::DebugSignatures {
                                    kuna_decomp::signature::debug_signature(&fd, &mut encoder)?;
                                } else {
                                    kuna_decomp::signature::simple_signature(&fd, &mut encoder)?;
                                }
                                Ok(bytes)
                            } else {
                            let current_action = arch.allacts.get_current_name().to_string();
                            build_decompile_at_doc(
                                arch,
                                &mut fd,
                                send_syntax_tree,
                                send_c_code,
                                send_param_measures,
                                &current_action,
                            )
                            }
                        }
                        Err(e) => Err(e),
                    }
                };

                // C++ performs the action before writing burst 14. A thrown
                // error therefore sends only the command's diagnostic result,
                // not an empty packed document. Opening and closing an empty
                // PackedDecode buffer makes Java attempt <doc> decoding and
                // overwrite the real diagnostic with a decoding error.
                let bytes = doc.map_err(WireError::from)?;
                write_burst(self.client.borrow_mut().sout_mut(), BURST_STRING_OPEN)?;
                self.client
                    .borrow_mut()
                    .sout_mut()
                    .write_all(&bytes)
                    .map_err(WireError::Io)?;
                write_burst(self.client.borrow_mut().sout_mut(), BURST_STRING_CLOSE)?;
                Ok(())
            }
            // SetAction::rawAction (ghidra_process.cc:378-406)
            CommandKind::SetAction => {
                let slot = cmd.slot.expect("bound session");
                let actionstring = String::from_utf8_lossy(&cmd.actionstring).into_owned();
                let printstring = String::from_utf8_lossy(&cmd.printstring).into_owned();
                let session = self.archlist[slot].as_mut().expect("bound session");
                if !actionstring.is_empty() {
                    if let Some(arch) = session.architecture.as_mut() {
                        arch.allacts.set_current(&actionstring).map_err(WireError::from)?;
                        arch.print_mut().set_export_binding(None);
                    }
                }
                if !printstring.is_empty() {
                    match printstring.as_str() {
                        "tree" => session.send_syntax_tree = true,
                        "notree" => session.send_syntax_tree = false,
                        "c" => session.send_c_code = true,
                        "noc" => session.send_c_code = false,
                        "parammeasures" => session.send_param_measures = true,
                        "noparammeasures" => session.send_param_measures = false,
                        "jumpload" | "nojumpload" => {
                            if let Some(arch) = session.architecture.as_mut() {
                                arch.print_mut().set_export_binding(None);
                                if printstring == "jumpload" {
                                    arch.flowoptions |= kuna_decomp::flow::flow_flags::record_jumploads;
                                } else {
                                    arch.flowoptions &= !kuna_decomp::flow::flow_flags::record_jumploads;
                                }
                            }
                        }
                        _ => {
                            return Err(WireError::Kuna(KunaError::lowlevel(format!(
                                "Unknown print action: {printstring}"
                            ))))
                        }
                    }
                }
                cmd.ok = true;
                Ok(())
            }
            // SetOptions::rawAction (ghidra_process.cc:435-445), Phase 3: the
            // <optionslist> is DECODED AND APPLIED through the ported
            // OptionDatabase.  DELIBERATE DIVERGENCE (docs/ghidra-integration.md
            // §8, DIV row in docs/history.md): upstream throws on the first
            // unknown option element (-> response 'f' -> Java "Did not accept
            // decompiler options", killing the whole program open), so one
            // option from a newer Java vocabulary (12.2's `baddatacount`)
            // bricks the decompiler view. Unknown IDs are skipped per-element;
            // known option errors stop the list and answer 'f'. Skipped
            // elements are reported on the 16/17 frame with messages beginning
            // "Warning" — DecompInterface.isErrorMessage treats text containing
            // "warning" as non-fatal, so the note surfaces without failing the
            // program open.
            CommandKind::SetOptions => {
                let slot = cmd.slot.expect("bound session");
                let mut warnings: Vec<String> = Vec::new();
                if let Some(session) = self.archlist[slot].as_mut() {
                    if let Some(arch) = session.architecture.as_mut() {
                        // The upstream reset-then-apply contract
                        // (ghidra_process.cc:435-445): Java delta-encodes the
                        // list, so a previously-sent non-default option must
                        // REVERT when the user sets it back to default.  Reset
                        // to the registerProgram baseline (engine + printer
                        // defaults, then the DIV-77 ghidra-mode preset layer),
                        // then let the deltas land on it.
                        arch.reset_wire_defaults();
                        apply_ghidra_mode_defaults(arch);
                        let bytes = cmd.optionslist.take()
                            .ok_or_else(|| KunaError::decoder("missing <optionslist>"))?;
                        let manager = arch.translate().manager_rc();
                        let mut decoder = PackedDecode::new(&manager);
                        let outcome = decoder
                            .ingest_stream(&bytes)
                            .and_then(|_| OptionDatabase::new().decode_native(&mut decoder, arch));
                        match outcome {
                            Ok(w) => warnings = w,
                            Err(e) => return Err(e.into()),
                        }
                    }
                }
                for w in &warnings {
                    self.print_message(cmd.slot, w);
                }
                cmd.ok = true;
                Ok(())
            }
            CommandKind::PrepareSelectedRoots => {
                let slot = cmd.slot.expect("bound session");
                let session = self.archlist[slot].as_mut().expect("bound session");
                let arch = session.architecture.as_mut()
                    .ok_or_else(|| KunaError::lowlevel("decompiler engine unavailable"))?;
                // A failed replacement must not publish an older invocation's
                // decisions. The physical-publication owner alone holds roots
                // and computed bindings; command routing has no second cache.
                arch.print_mut().set_export_binding(None);
                let bytes = cmd.optionslist.take()
                    .ok_or_else(|| KunaError::decoder("missing selected-root address stream"))?;
                // Command-specific collection: canonical <addr/> and <string>
                // content siblings in ONE packed stream, no new envelope.
                // Strings reserve the invocation's existing output namespace;
                // they do not select additional roots. Decode the entire
                // packet before exposing the reservations to preparation.
                let mut roots = Vec::new();
                let mut reserved = std::collections::BTreeSet::new();
                if !bytes.is_empty() {
                    let manager = arch.translate().manager_rc();
                    let mut decoder = PackedDecode::new(&manager);
                    decoder.ingest_stream(&bytes)?;
                    loop {
                        let element = decoder.peek_element()?;
                        if element == 0 {
                            break;
                        }
                        if element == kuna_base::address::ELEM_ADDR.get_id() {
                            roots.push(Address::decode(&mut decoder)?);
                        } else if element == kuna_decomp::stringmanage::ELEM_STRING.get_id() {
                            let id = decoder.open_element_id(&kuna_decomp::stringmanage::ELEM_STRING)?;
                            let name = decoder.read_string_id(&kuna_base::marshal::ATTRIB_CONTENT)?;
                            decoder.close_element(id)?;
                            reserved.insert(String::from_utf8(name).map_err(|_| {
                                KunaError::decoder("invalid UTF-8 in selected-root reserved identifier")
                            })?);
                        } else {
                            return Err(KunaError::decoder("expected selected-root address or reserved identifier").into());
                        }
                    }
                }
                arch.print_mut().set_reserved_identifiers(Rc::new(reserved));
                let binding = kuna_decomp::kuna_exportcall::prepare_addresses(arch, &roots)?;
                arch.print_mut().set_export_binding(Some(Rc::new(binding)));
                arch.hidden_results = true;
                let mut acknowledgment = Vec::new();
                ResultTypeTable::encode_prelude_packed(
                    &ResultTypeTable::shared(), &mut acknowledgment,
                )?;
                write_string_stream(self.client.borrow_mut().sout_mut(), &acknowledgment)?;
                Ok(())
            }
            CommandKind::StructureGraph | CommandKind::GetSignatureSettings | CommandKind::SetSignatureSettings => {
                let slot = cmd.slot.expect("bound session");
                let session = self.archlist[slot].as_mut().expect("bound session");
                let arch = session.architecture.as_mut()
                    .ok_or_else(|| KunaError::lowlevel("decompiler engine unavailable"))?;
                if cmd.kind == CommandKind::SetSignatureSettings {
                    let raw = cmd.optionslist.take().ok_or_else(|| KunaError::decoder("missing signature settings"))?;
                    let settings = parse_signature_settings(&raw)?;
                    cmd.ok = kuna_decomp::signature::try_set_settings(settings);
                } else {
                    let mut bytes = Vec::new();
                    let mut encoder = PackedEncode::new(&mut bytes);
                    if cmd.kind == CommandKind::StructureGraph {
                        let raw = cmd.optionslist.take().ok_or_else(|| KunaError::decoder("missing graph"))?;
                        let mut decoder = PackedDecode::new(arch.manage());
                        decoder.ingest_stream(&raw)?;
                        kuna_decomp::blockaction::structure_graph(&mut decoder, &mut encoder)?;
                    } else {
                        kuna_decomp::signature::encode_settings(&mut encoder);
                    }
                    write_string_stream(self.client.borrow_mut().sout_mut(), &bytes)?;
                }
                Ok(())
            }
        }
    }

    /// Build the live ghidra-mode [`Architecture`] from the four registerProgram
    /// wire documents (C++ `ArchitectureGhidra::buildSpecFile` +
    /// `Architecture::init`/`restoreFromSpec`).
    ///
    /// - `buildTranslator` → a [`GhidraTranslate`] over a *clone* of the shared
    ///   client (the kuna analog of the C++ `glb` back-pointer every ghidra-mode
    ///   component holds).  The engine, mid-init and mid-decompile, issues
    ///   queries through this clone on the same streams the command loop frames.
    /// - `Architecture::from_engine_translate` builds the subsystems over the
    ///   query-backed engine, and the wire cspec/pspec feed the same setters the
    ///   console frontend uses (`build_engine_and_init`).
    /// - `init_post_engine` runs the shared restoreFromSpec tail
    ///   (typegrp / core types / default proto / actions / …) and — via
    ///   `userops.initialize` — issues the getUserOpName probe loop, a real
    ///   query nested inside the open registerProgram response.
    ///
    /// The wire corespec is the `<coretypes>` document; decoding it needs the
    /// (unported) TypeFactory type decoder, which arrives with TypeFactoryGhidra
    /// in Phase 3 (`docs/rust-port/ghidra-phase2-plan.md` §6).  For now
    /// `init_post_engine` builds the default core types — the same set the
    /// standalone engine uses, which the 675-datatest parity proves sufficient.
    fn build_architecture(
        &self,
        archid: i32,
        pspec: &[u8],
        cspec: &[u8],
        tspec: &[u8],
        corespec: &[u8],
    ) -> KunaResult<Architecture> {
        let registry = build_registry();
        let translate = GhidraTranslate::new(tspec, &registry, Rc::clone(&self.client))?;
        let mut arch =
            Architecture::from_engine_translate(&archid.to_string(), Box::new(translate));
        arch.set_cspec_xml(cspec.to_vec());
        arch.set_pspec_xml(pspec.to_vec());
        // Phase 3: decode the wire <coretypes> inside buildCoreTypes (the C++
        // `store.getTag("coretypes")` branch) so kuna's core-type IDS match the
        // host's and every later <typeref>/getDataType exchange resolves.
        arch.set_coretypes_xml(corespec.to_vec());
        arch.init_post_engine()?;
        // Native registration starts with the same sparse-wire printing
        // defaults that a subsequent fresh DecompileOptions list restores.
        // Standalone Architecture construction retains the CLI defaults.
        arch.print_mut().reset_wire_option_defaults();
        // Phase 3 (DIV: ghidra-mode defaults): Ghidra-convention fallback
        // naming (FUN_/DAT_/LAB_ for address-derived placeholder names — what
        // Java's isDynamicSymbolName expects, ghidra_arch.cc:928-947) plus the
        // CLI `aggressive` ENGINE-TIER preset, applied BEFORE Java's setOptions
        // replay lands on top.  The GUI has no --mode surface, and the CLI
        // resolves `auto` to `aggressive` for every binary under 500 KiB —
        // without the preset the GUI would show the one rendering no other kuna
        // surface defaults to.  `name_style_angr` stays ON (the shipped
        // default): it also gates kuna's LOCAL variable naming (`v2`/`a0` +
        // storage comments), the only ported local-naming pass — turning it off
        // leaves unnamed register highs rendering as raw `EAX`/`RBX`.
        // `kuna_name_style()` gives `Ghidra` precedence exactly at the
        // fallback-name sites.  Analysis/loader-tier preset members (listing,
        // fid, aif, ...) run over a real file in kuna-analysis and have no seam
        // here: their PRODUCTS are what the Phase-3 providers pull over the
        // wire instead.
        apply_ghidra_mode_defaults(&mut arch);
        // Phase 3: install the lazy wire-backed providers (ScopeGhidra /
        // TypeFactoryGhidra) — after init (cspec <global> ranges + pspec
        // property paints are in, the lockDefaultProperties point), before the
        // first decompile.
        let fetch = Rc::new(GhidraRemoteFetch::new(Rc::clone(&self.client)));
        arch.install_remote_provider(
            Rc::clone(&fetch) as Rc<dyn kuna_decomp::remote_provider::RemoteProviderFetch>,
            Some(fetch as Rc<dyn kuna_decomp::dtype::RemoteTypeFetch>),
        );
        Ok(arch)
    }

    // -- sendResult -----------------------------------------------------------

    /// The per-command payload plus the base `GhidraCommand::sendResult`
    /// warnings frame (ghidra_process.cc:108-116,203-210,253-260,275-282,
    /// 408-416,447-455).  The 16/17 frame is written only while a session
    /// is bound (the C++ `ghidra != nullptr` check).
    fn send_result(&mut self, cmd: &CommandState) -> WireResult<()> {
        match cmd.kind {
            CommandKind::RegisterProgram => {
                write_string_stream(
                    self.client.borrow_mut().sout_mut(),
                    cmd.archid.to_string().as_bytes(),
                )?;
            }
            CommandKind::DeregisterProgram | CommandKind::FlushNative => {
                write_string_stream(
                    self.client.borrow_mut().sout_mut(),
                    cmd.res.to_string().as_bytes(),
                )?;
            }
            CommandKind::SetAction | CommandKind::SetOptions | CommandKind::SetSignatureSettings => {
                write_string_stream(
                    self.client.borrow_mut().sout_mut(),
                    if cmd.ok { b"t" } else { b"f" },
                )?;
            }
            // DecompileAt writes its payload inside rawAction (or none at
            // all when rawAction was aborted) — nothing here
            CommandKind::DecompileAt | CommandKind::StructureGraph | CommandKind::GenerateSignatures
                | CommandKind::DebugSignatures | CommandKind::GetSignatureSettings
                | CommandKind::PrepareSelectedRoots => {}
        }
        if let Some(slot) = cmd.slot {
            if let Some(session) = self.archlist[slot].as_ref() {
                write_burst(self.client.borrow_mut().sout_mut(), BURST_MESSAGE_OPEN)?;
                self.client
                    .borrow_mut()
                    .sout_mut()
                    .write_all(session.warnings.as_bytes())
                    .map_err(WireError::Io)?;
                write_burst(self.client.borrow_mut().sout_mut(), BURST_MESSAGE_CLOSE)?;
            }
        }
        Ok(())
    }

    /// Route a message to the bound session's warning accumulator; without
    /// a bound session the message is dropped (the C++ base sendResult
    /// skips the 16/17 frame entirely when `ghidra` is null).
    ///
    /// C++ `RegisterProgram::rawAction` assigns `ghidra` to the freshly-`new`'d
    /// `ArchitectureGhidra` *before* `init`, so an `init` that throws on bad
    /// specs still ships its error on the 16/17 channel — and Java's
    /// registerProgram treats a non-empty nativeMessage as registration failure
    /// (`DecompInterface.java:291-294`).  kuna mirrors this: the slot is bound
    /// before the fallible `build_architecture`, so a construction failure
    /// routes here and ships on the 16/17 frame.
    fn print_message(&mut self, slot: Option<usize>, message: &str) {
        if let Some(slot) = slot {
            if let Some(session) = self.archlist[slot].as_mut() {
                session.print_message(message);
            }
        }
    }
}

/// The ghidra-mode banner comment (user-requested): rendered as the first
/// plate line of every decompiled function so the GUI makes it obvious kuna
/// is the active core.  The version bakes exactly like the kuna CLI's
/// (`kuna-cli/src/main.rs`): `KUNA_VERSION` from the release build matrix
/// (release.yml exports it job-wide), the workspace Cargo version on dev
/// builds.
pub fn kuna_banner_text() -> String {
    format!(
        "Kuna v{}",
        option_env!("KUNA_VERSION").unwrap_or(env!("CARGO_PKG_VERSION"))
    )
}

/// The DIV-77 ghidra-mode defaults layer (applied at registerProgram AND on
/// every setOptions after `reset_wire_defaults` — the reset-then-apply
/// contract): Ghidra-convention fallback naming plus the CLI `aggressive`
/// ENGINE-TIER preset.  See the build_architecture doc comment for why.
fn apply_ghidra_mode_defaults(arch: &mut Architecture) {
    arch.name_style_ghidra = true;
    arch.retain_physical_call_inputs = true;
    arch.vararg_entry = true;
    if let Some(overrides) = kuna_decomp::modes::mode_overrides("aggressive") {
        for (name, value) in overrides {
            if kuna_decomp::options::KUNA_OPTION_NAMES.contains(name) {
                // Engine-tier knob: apply.  Unknown/analysis-tier names have
                // no engine seam in ghidra mode and are skipped.
                let _ = arch.set_kuna_option(name, value);
            }
        }
    }
}

/// Parse the ASCII-decimal architecture id (C++ `sin >> dec >> id`,
/// ghidra_process.cc:92): skip whitespace, optional sign, decimal digits,
/// stopping at the first non-digit.
///
/// DELIBERATE DIVERGENCE: on extraction failure C++11 stores 0 AND sets
/// failbit, after which every read fails and the process exits.  kuna
/// returns -1, which the caller turns into the "No architecture registered
/// with decompiler" JavaError — the client sees a clean exception and the
/// process stays alive (docs/ghidra-integration.md).
fn parse_arch_id(payload: &[u8]) -> i32 {
    let mut i = 0usize;
    while i < payload.len() && (payload[i] as char).is_ascii_whitespace() {
        i += 1;
    }
    let mut negative = false;
    if i < payload.len() && (payload[i] == b'+' || payload[i] == b'-') {
        negative = payload[i] == b'-';
        i += 1;
    }
    let mut val: i64 = 0;
    let mut any = false;
    while i < payload.len() && payload[i].is_ascii_digit() {
        any = true;
        val = val
            .saturating_mul(10)
            .saturating_add((payload[i] - b'0') as i64);
        i += 1;
    }
    if !any {
        return -1;
    }
    if negative {
        val = -val;
    }
    val.clamp(i32::MIN as i64, i32::MAX as i64) as i32
}

/// The session requires the Kuna extension's Java: its `coretypes` offers the
/// result protocol version this native speaks.
fn require_result_version(corespec: &[u8]) -> KunaResult<()> {
    let mut store = kuna_base::xml::DocumentStorage::new();
    let doc = store.parse_document(corespec)?;
    let root = doc.get_root();
    match root.get_attribute_value("kuna_result_version") {
        Ok(value) if kuna_base::marshal::cxx_parse_unsigned(value) == u64::from(RESULT_VERSION) => Ok(()),
        _ => Err(KunaError::recov("registerProgram: coretypes does not offer the Kuna result protocol; the Kuna extension's Java classes are required")),
    }
}

/// C++ integer extraction with the base selected by the prefix. Invalid or
/// overflowing settings are a recoverable command error, never a stale value.
fn parse_signature_settings(raw: &[u8]) -> KunaResult<u32> {
    let value = std::str::from_utf8(raw)
        .map_err(|_| KunaError::parse("Invalid signature settings"))?.trim();
    let value = value.strip_prefix('+').unwrap_or(value);
    let (digits, radix) = if let Some(digits) = value.strip_prefix("0x").or_else(|| value.strip_prefix("0X")) {
        (digits, 16)
    } else if value.len() > 1 && value.starts_with('0') {
        (&value[1..], 8)
    } else {
        (value, 10)
    };
    u32::from_str_radix(digits, radix)
        .map_err(|_| KunaError::parse("Invalid signature settings"))
}

/// Assemble the decompileAt response document (C++ `DecompileAt::rawAction`
/// isProcComplete branch, `decompiler/cpp/ghidra_process.cc:293-335`):
///
/// ```text
///   encoder.openElement(ELEM_DOC);
///   if (getSendParamMeasures() && actionname == "paramid")
///     ParamIDAnalysis(fd,true).encode(encoder,true);      // the ONLY child
///   else {
///     if (getSendParamMeasures())
///       ParamIDAnalysis(fd,false).encode(encoder,true);
///     fd->encode(encoder,0,getSendSyntaxTree());          // <function>/<ast>
///     if (getSendCCode() && actionname == "decompile")
///       ghidra->print->docFunction(fd);                   // markup <function>
///   }
///   encoder.closeElement(ELEM_DOC);
/// ```
///
/// The dual `<function>` (the markup) is spliced AFTER the syntax tree and
/// BEFORE `</doc>`.  Its `opref`/`varref` tokens resolve to the SAME
/// `get_time()`/`get_create_index()` the `<ast>` emitted, so the
/// click-to-address contract holds by construction.  [`PackedEncode`] writes
/// its 0x00-free bytes straight to the buffer with no open-element stack, so
/// appending the markup bytes then writing `</doc>` from a fresh encoder is
/// byte-identical to C++ writing both to one `sout` — exactly the same splice.
///
/// The Phase-4 symbol-link pass (`kuna_link_high_symbols`) runs FIRST — before
/// the markup is printed — because the markup's `<vardecl symref>` must carry
/// the same LocalSymbolMap ids `<localdb>` encodes: Java resolves the
/// declaration line's HighSymbol exclusively through that attribute, so a
/// declaration printed before the symbols exist leaves rename/retype dead on
/// declaration tokens (and logs "Invalid symbol reference" once per
/// declaration per decompile).  The pass is idempotent and does not change the
/// printed C — it only attaches Symbols to highs the naming pass already
/// named, writing a field (`kuna_link_symbol`) nothing in the printer's text
/// path reads; the harness asserts the C text is byte-identical across the
/// reorder.  Both documents are then spliced in the upstream order
/// (`<function>` #1 first).
///
/// The selected root comes exclusively from ActionDatabase, including paramid.
fn build_decompile_at_doc(
    arch: &mut Architecture,
    fd: &mut Funcdata,
    send_syntax_tree: bool,
    send_c_code: bool,
    send_param_measures: bool,
    current_action: &str,
) -> KunaResult<Vec<u8>> {
    use kuna_decomp::resulttypes::ResultTypeEncoder;
    let types = ResultTypeTable::shared();
    let mut buf: Vec<u8> = Vec::new();
    // The symbol-link pass, ahead of everything that reads its results (the
    // markup's `<vardecl symref>` and the `<localdb>`/`<highlist>` encode).
    if send_syntax_tree {
        fd.kuna_link_high_symbols();
    }
    if send_param_measures && current_action == "paramid" {
        // The parammeasures-only doc (DecompilerParameterIdCmd /
        // ConventionAnalysisDecompileConfigurer).
        let analysis = kuna_decomp::paramid::ParamIDAnalysis::new(fd, true)?;
        let mut enc = PackedEncode::new(&mut buf);
        analysis.encode(&mut ResultTypeEncoder::new(&mut enc, &types), true)?;
    } else {
        if send_param_measures {
            let analysis = kuna_decomp::paramid::ParamIDAnalysis::new(fd, false)?;
            let mut enc = PackedEncode::new(&mut buf);
            analysis.encode(&mut ResultTypeEncoder::new(&mut enc, &types), true)?;
        }
        // The dual <function>: the Clang token-markup document, rendered first
        // (see above), spliced after the syntax tree.  `doc_function_markup`
        // needs `&mut PrintC` + `&Architecture`; move the printer out (the
        // `print_c` split-borrow precedent), render, put it back.
        let markup: Option<Vec<u8>> = if send_c_code && current_action == "decompile" {
            let mut printer = arch.take_print();
            // Markup and ordinary C/Java presentation use the same selected
            // language. Clang token identities do not require C spelling.
            let m = printer.doc_function_markup_result(fd, arch, Rc::clone(&types));
            arch.put_print(printer);
            Some(m?)
        } else {
            None
        };
        {
            let mut enc = PackedEncode::new(&mut buf);
            fd.encode(&mut ResultTypeEncoder::new(&mut enc, &types), 0, send_syntax_tree)?;
        }
        if let Some(m) = markup {
            if let Some(publication) = arch.print().export_publication() {
                publication.encode(&mut PackedEncode::new(&mut buf))?;
            }
            buf.extend_from_slice(&m);
        }
    }
    let mut doc = Vec::new();
    PackedEncode::new(&mut doc).open_element(&ELEM_DOC);
    ResultTypeTable::encode_prelude_packed(&types, &mut doc)?;
    doc.extend_from_slice(&buf);
    PackedEncode::new(&mut doc).close_element(&ELEM_DOC);
    Ok(doc)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signature_settings_parse_native_bases_without_stale_values() {
        for value in [b"73".as_slice(), b"0x49", b"0111", b" +73 "] {
            assert_eq!(parse_signature_settings(value).unwrap(), 73);
        }
        for value in [b"".as_slice(), b"garbage", b"-1", b"4294967296", b"0x"] {
            assert!(parse_signature_settings(value).is_err());
        }
    }

    #[test]
    fn registration_requires_the_supported_result_offer() {
        assert!(require_result_version(b"<coretypes/>").is_err());
        assert!(require_result_version(b"<coretypes kuna_result_version=\"1\"/>").is_ok());
        assert!(require_result_version(b"<coretypes kuna_result_version=\"0x1\"/>").is_ok());
        assert!(require_result_version(b"<coretypes kuna_result_version=\"2\"/>").is_err());
    }

    #[test]
    fn test_parse_arch_id() {
        assert_eq!(parse_arch_id(b"0"), 0);
        assert_eq!(parse_arch_id(b"17"), 17);
        assert_eq!(parse_arch_id(b" 3"), 3);
        assert_eq!(parse_arch_id(b"5xyz"), 5); // stops at first non-digit
        assert_eq!(parse_arch_id(b"-2"), -2);
        assert_eq!(parse_arch_id(b""), -1); // kuna divergence: -1, not 0
        assert_eq!(parse_arch_id(b"abc"), -1);
    }
}
