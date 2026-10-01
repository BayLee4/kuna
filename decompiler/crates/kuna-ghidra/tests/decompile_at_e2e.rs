//! The decompileAt end-to-end proof (phase-2 step 6): drive a FULL ghidra-mode
//! session — registerProgram → setAction("decompile","c") → decompileAt(entry)
//! — for a TINY canned function and prove C comes out.
//!
//! Unlike the pre-canned byte streams of `protocol_e2e.rs`, this drives the LIVE
//! decompiler: `decompileAt` runs `decompile_func`, whose flow-follow + pipeline
//! issue getPcode/getCodeLabel/getRegister/... queries whose exact sequence
//! depends on engine internals.  Pre-canning that sequence would be brittle, so
//! the MockJava here is the **interactive single-threaded loopback** shared
//! machinery in `tests/ghidra_sim/mod.rs` (extracted from this test): the
//! process writes queries into a shared buffer; the mock decodes each query's
//! command element id and generates a response on demand (empty getUserOpName
//! to end the probe, a name for getCodeLabel, a canned `<inst>` RETURN for
//! getPcode at the entry, safe minimal answers for everything else).
//!
//! The real-program twin of this test — the same machinery answering from
//! kuna's own analysis of a vendored ELF — is `ghidra_sim_e2e.rs`.
//!
//! ## What this covers
//!   * The whole wire lifecycle end to end over the real command loop.
//!   * `decompileAt` names the function from `getCodeLabel`, builds+decompiles a
//!     `Funcdata` for the raw entry (flow-discovered extent), and emits a
//!     well-formed `<doc>` containing the `Funcdata::encode` `<function>`/`<ast>`.
//!   * The dual `<function>` (the Clang markup) is present when C is requested,
//!     decodes, and its `opref`/`varref` tokens are a subset of the `<ast>`'s op
//!     times / varnode create-indices — the click-to-address contract, end to end.
//!
//! ## What this stubs / canned
//!   * The decompiled function is a synthetic single-instruction `RETURN #0x0`
//!     (the mock's getPcode answer for the entry; BadData elsewhere) — enough to
//!     produce a non-empty AST without needing a real processor `.sla`.
//!   * getRegister returns a fixed register storage, getRegisterName/getComments
//!     return empty, getBytes returns DataUnavail — defensive minimal answers so
//!     the decompile of this register-free function completes; the specs are the
//!     same four tiny valid documents `protocol_e2e.rs` proves build a live arch.
//!   * There is NO symbol scope (Phase 3): unresolved refs degrade to
//!     placeholders, which is the accepted phase-2 quality.

mod ghidra_sim;

use std::cell::RefCell;
use std::rc::Rc;

use kuna_base::address::Address;
use kuna_base::marshal::{Decoder, ElementId, Encoder, PackedDecode, PackedEncode, ATTRIB_SIZE};
use kuna_base::space::AddrSpaceManager;
use kuna_num::opcodes::{OpCode, OpcodeEncoder};
use kuna_sleigh::translate::{ATTRIB_CODE, ELEM_OP};

use kuna_ghidra::ids::{
    ELEM_COMMAND_GETBYTES, ELEM_COMMAND_GETCODELABEL, ELEM_COMMAND_GETPCODE,
    ELEM_COMMAND_GETREGISTER, ELEM_COMMAND_GETREGISTERNAME, ELEM_COMMAND_GETUSEROPNAME,
};
use kuna_ghidra::process::GhidraProcess;
use kuna_ghidra::translate::{build_registry, TspecModel};

use ghidra_sim::{
    cmd_decompile_at, cmd_register_program, cmd_set_action, parse_decompile_doc, resp_empty,
    resp_string, AnswerSource, MockReader, MockState, MockWriter,
};

// The four registerProgram documents — the same tiny valid specs
// `protocol_e2e.rs` proves build a live `Architecture` (single init query, empty
// warnings).  `<default_proto/>` is empty (no register storage in the model), so
// the register-free RETURN function needs no register recovery.
const TSPEC: &[u8] = b"<sleigh bigendian=\"false\" uniqbase=\"0x10000000\">\
<spaces defaultspace=\"ram\">\
<space_other name=\"OTHER\" index=\"1\" size=\"8\" bigendian=\"false\" delay=\"0\" physical=\"true\"/>\
<space_unique name=\"unique\" index=\"2\" size=\"4\" bigendian=\"false\" delay=\"0\" physical=\"true\"/>\
<space name=\"ram\" index=\"3\" size=\"8\" bigendian=\"false\" delay=\"1\" physical=\"true\"/>\
<space name=\"register\" index=\"4\" size=\"4\" bigendian=\"false\" delay=\"0\" physical=\"true\"/>\
</spaces></sleigh>";
const PSPEC: &[u8] = b"<processor_spec><programcounter register=\"PC\"/></processor_spec>";
const CSPEC: &[u8] = b"<compiler_spec><default_proto/></compiler_spec>";
// Phase 3 decodes the wire corespec for real (build_core_types): mirror the
// standalone default core-type set so engine init still finds char/bool/void.
const CORETYPES: &[u8] = b"<coretypes>\
<type name=\"void\" size=\"1\" metatype=\"void\"/>\
<type name=\"bool\" size=\"1\" metatype=\"bool\"/>\
<type name=\"uint1\" size=\"1\" metatype=\"uint\"/>\
<type name=\"uint2\" size=\"2\" metatype=\"uint\"/>\
<type name=\"uint4\" size=\"4\" metatype=\"uint\"/>\
<type name=\"uint8\" size=\"8\" metatype=\"uint\"/>\
<type name=\"int1\" size=\"1\" metatype=\"int\"/>\
<type name=\"int2\" size=\"2\" metatype=\"int\"/>\
<type name=\"int4\" size=\"4\" metatype=\"int\"/>\
<type name=\"int8\" size=\"8\" metatype=\"int\"/>\
<type name=\"float4\" size=\"4\" metatype=\"float\"/>\
<type name=\"float8\" size=\"8\" metatype=\"float\"/>\
<type name=\"float10\" size=\"10\" metatype=\"float\"/>\
<type name=\"float16\" size=\"16\" metatype=\"float\"/>\
<type name=\"xunknown1\" size=\"1\" metatype=\"unknown\"/>\
<type name=\"xunknown2\" size=\"2\" metatype=\"unknown\"/>\
<type name=\"xunknown4\" size=\"4\" metatype=\"unknown\"/>\
<type name=\"xunknown8\" size=\"8\" metatype=\"unknown\"/>\
<type name=\"code\" size=\"1\" metatype=\"code\"/>\
<type name=\"char\" size=\"1\" metatype=\"int\" char=\"true\"/>\
<type name=\"wchar2\" size=\"2\" metatype=\"int\" utf=\"true\"/>\
<type name=\"wchar4\" size=\"4\" metatype=\"int\" utf=\"true\"/>\
</coretypes>";

const ENTRY: u64 = 0x1000;
const FUNC_NAME: &[u8] = b"myfunc";

/// The canned answer source: fixed constants over the tiny inline tspec (the
/// original MockJava of this test, now behind the shared [`AnswerSource`]).
struct CannedSource {
    /// The tspec address-space manager (decodes the getPcode `<addr>`, encodes
    /// the canned `<inst>` / register responses).
    manager: Rc<AddrSpaceManager>,
    entry_nop: bool,
    first_pcode_response: Option<Vec<u8>>,
}

impl CannedSource {
    /// A one-byte RETURN, optionally preceded by a one-byte NOP at the entry.
    fn inst_doc(&self, offset: u64) -> Vec<u8> {
        let ram = Rc::clone(self.manager.get_space_by_name("ram").expect("ram"));
        let cst = Rc::clone(self.manager.get_constant_space().expect("constant"));
        let elem_inst = ElementId::new("inst", 98); // ELEM_INST (kuna-decomp)
        let mut doc = Vec::new();
        {
            let mut e = PackedEncode::new(&mut doc);
            e.open_element(&elem_inst);
            e.write_signed_integer(&kuna_base::marshal::ATTRIB_OFFSET, 1); // instr length
            Address::new(Rc::clone(&ram), offset).encode(&mut e).expect("pc addr");
            if self.entry_nop && offset == ENTRY {
                e.close_element(&elem_inst);
                return doc;
            }
            // <op>: RETURN, isize=1, void output, one constant input.
            e.open_element(&ELEM_OP);
            e.write_signed_integer(&ATTRIB_SIZE, 1); // isize = one input
            e.write_opcode(&ATTRIB_CODE, OpCode::CPUI_RETURN);
            e.open_element(&kuna_base::marshal::ELEM_VOID);
            e.close_element(&kuna_base::marshal::ELEM_VOID);
            Address::new(cst, 0).encode_sized(&mut e, 8).expect("const input");
            e.close_element(&ELEM_OP);
            e.close_element(&elem_inst);
        }
        doc
    }

    /// A fixed register storage `<addr space=register offset=0 size=8>` (the
    /// getRegister answer shape AddressXML.encode sends).
    fn register_addr_doc(&self) -> Vec<u8> {
        let reg = Rc::clone(self.manager.get_space_by_name("register").expect("register"));
        let mut doc = Vec::new();
        {
            let mut e = PackedEncode::new(&mut doc);
            Address::new(reg, 0).encode_sized(&mut e, 8).expect("register addr");
        }
        doc
    }
}

impl AnswerSource for CannedSource {
    /// Decode a query's command element id and produce its response bytes.
    fn respond(&mut self, doc: &[u8]) -> Vec<u8> {
        let mut dec = PackedDecode::new(&self.manager);
        dec.ingest_stream(doc).expect("query doc ingests");
        let el = dec.open_element().expect("query has a command element");
        if el == ELEM_COMMAND_GETUSEROPNAME.get_id() {
            // Empty name at index 0 terminates the init-time user-op probe.
            resp_string(b"")
        } else if el == ELEM_COMMAND_GETCODELABEL.get_id() {
            // The primary symbol name -> <function name>.
            resp_string(FUNC_NAME)
        } else if el == ELEM_COMMAND_GETPCODE.get_id() {
            if let Some(response) = self.first_pcode_response.take() {
                return response;
            }
            let addr = Address::decode(&mut dec).expect("getPcode carries an <addr>");
            if addr.get_offset() == ENTRY || (self.entry_nop && addr.get_offset() == ENTRY + 1) {
                resp_string(&self.inst_doc(addr.get_offset()))
            } else {
                resp_empty() // BadData: flow should not ask past the RETURN
            }
        } else if el == ELEM_COMMAND_GETREGISTER.get_id() {
            // A fixed valid register storage so a register lookup never errors
            // (the register-free RETURN function should not reach here).
            resp_string(&self.register_addr_doc())
        } else if el == ELEM_COMMAND_GETREGISTERNAME.get_id() {
            resp_string(b"") // no named register -> render by raw location
        } else if el == ELEM_COMMAND_GETBYTES.get_id() {
            resp_empty() // DataUnavail (no loadimage for a register/const-only fn)
        } else {
            // getComments / getMappedSymbols / getTrackedRegisters / getDataType
            // / ... : an empty response (the decompile of this function issues
            // none of them, but answer defensively so nothing desyncs).
            resp_empty()
        }
    }
}

#[test]
fn test_decompile_at_emits_c() {
    // The tspec manager the mock uses to decode/encode <addr> elements.
    let registry = build_registry();
    let model = TspecModel::decode(TSPEC, &registry).expect("tspec parses");
    let manager = Rc::new(model.manager);

    // The packed <addr> for the decompileAt entry (ram:ENTRY).
    let addr_packed = {
        let ram = Rc::clone(manager.get_space_by_name("ram").expect("ram"));
        let mut v = Vec::new();
        {
            let mut e = PackedEncode::new(&mut v);
            Address::new(ram, ENTRY).encode(&mut e).expect("entry addr");
        }
        v
    };

    // The proactive command stream: registerProgram + setAction + decompileAt.
    let mut commands = Vec::new();
    cmd_register_program(&mut commands, PSPEC, CSPEC, TSPEC, CORETYPES);
    cmd_set_action(&mut commands, "0", "decompile", "c");
    cmd_decompile_at(&mut commands, "0", &addr_packed);

    let shared = Rc::new(RefCell::new(MockState::new(
        commands,
        CannedSource {
            manager: Rc::clone(&manager),
            entry_nop: false,
            first_pcode_response: None,
        },
    )));

    let reader = MockReader { shared: Rc::clone(&shared) };
    let writer = MockWriter { shared: Rc::clone(&shared) };

    let mut process = GhidraProcess::new(reader, writer);
    // Drive the three commands (registerProgram, setAction, decompileAt).
    for cmd in ["registerProgram", "setAction", "decompileAt"] {
        assert_eq!(
            process.read_command().unwrap_or_else(|e| panic!("{cmd}: {e:?}")),
            0,
            "{cmd} should complete without terminating the loop"
        );
    }

    let out = shared.borrow().from_process.clone();
    // Drop the process (releases the session engine's client Rc clones) so the
    // shared state has no live borrower for the assertions below.
    let _ = process.into_inner();

    // Sanity: no engine-construction failure warning leaked into the stream.
    let text = String::from_utf8_lossy(&out);
    assert!(
        !text.contains("could not build the decompiler engine"),
        "engine construction failed: {text}"
    );
    // Extract the decompileAt <doc> payload (the last command response) and
    // decode it with the shared dual-<function> parser.
    let trace = ghidra_sim::trace_session(&out);
    let doc = trace
        .responses
        .last()
        .and_then(|r| r.payload.clone())
        .expect("decompileAt produced a response payload");
    assert!(!doc.is_empty(), "decompileAt emitted an EMPTY payload (no <doc>)");

    let parsed = parse_decompile_doc(&doc, &manager);

    assert_eq!(
        parsed.name.as_bytes(),
        FUNC_NAME,
        "<function name> must be the getCodeLabel name"
    );
    assert!(
        !parsed.ast_op_times.is_empty(),
        "the <ast> has no ops (empty function body) — expected the RETURN op"
    );
    assert!(
        parsed.has_markup,
        "the C-code markup <function> is missing (send_c_code + decompile action)"
    );

    // The click-to-address contract: every markup token ref resolves against the
    // AST it was emitted alongside.
    assert!(
        parsed.markup_oprefs.is_subset(&parsed.ast_op_times),
        "markup oprefs {:?} are not a subset of the AST op times {:?}",
        parsed.markup_oprefs,
        parsed.ast_op_times
    );
    assert!(
        parsed.markup_varrefs.is_subset(&parsed.ast_var_refs),
        "markup varrefs {:?} are not a subset of the AST varnode refs {:?}",
        parsed.markup_varrefs,
        parsed.ast_var_refs
    );
    // The markup must actually reference the syntax tree (a bare `return;` still
    // tags its statement/op), proving the two documents are cross-linked rather
    // than trivially both empty.
    assert!(
        !parsed.markup_oprefs.is_empty() || !parsed.markup_varrefs.is_empty(),
        "the markup carried NO opref/varref — the dual <function> is not cross-linked to the <ast>"
    );

    // The flattened markup IS the C the GUI renders: it must name the function
    // and carry a body.
    assert!(
        parsed.c_text.contains("myfunc"),
        "flattened markup C does not name the function:\n{}",
        parsed.c_text
    );
    assert!(
        parsed.c_text.contains('{') && parsed.c_text.contains('}'),
        "flattened markup C has no function body:\n{}",
        parsed.c_text
    );
}

#[test]
fn instruction_limit_preserves_error_and_session_recovers() {
    let registry = build_registry();
    let model = TspecModel::decode(TSPEC, &registry).expect("tspec parses");
    let manager = Rc::new(model.manager);
    let mut addr_packed = Vec::new();
    Address::new(Rc::clone(manager.get_space_by_name("ram").unwrap()), ENTRY)
        .encode(&mut PackedEncode::new(&mut addr_packed))
        .unwrap();

    let mut commands = Vec::new();
    cmd_register_program(&mut commands, PSPEC, CSPEC, TSPEC, CORETYPES);
    cmd_set_action(&mut commands, "0", "decompile", "c");
    for limit in [b"1".as_slice(), b"100".as_slice()] {
        let mut options = Vec::new();
        let mut enc = PackedEncode::new(&mut options);
        let optionslist = ElementId::new("optionslist", 201);
        let maxinstruction = kuna_decomp::options::ELEM_MAXINSTRUCTION;
        enc.open_element(&optionslist);
        enc.open_element(&maxinstruction);
        enc.write_string(&kuna_base::marshal::ATTRIB_CONTENT, limit);
        enc.close_element(&maxinstruction);
        enc.close_element(&optionslist);
        ghidra_sim::burst(&mut commands, 2);
        ghidra_sim::wire_string(&mut commands, b"setOptions");
        ghidra_sim::wire_string(&mut commands, b"0");
        ghidra_sim::wire_string(&mut commands, &options);
        ghidra_sim::burst(&mut commands, 3);
        cmd_decompile_at(&mut commands, "0", &addr_packed);
    }

    let shared = Rc::new(RefCell::new(MockState::new(
        commands,
        CannedSource {
            manager: Rc::clone(&manager),
            entry_nop: true,
            first_pcode_response: None,
        },
    )));
    let mut process = GhidraProcess::new(
        MockReader { shared: Rc::clone(&shared) },
        MockWriter { shared: Rc::clone(&shared) },
    );
    for _ in 0..6 {
        assert_eq!(process.read_command().unwrap(), 0);
    }
    let mut frames: Vec<Vec<u8>> = Vec::new();
    let mut in_query = false;
    for (code, _) in ghidra_sim::tokenize(&shared.borrow().from_process) {
        match code {
            4 => in_query = true,
            5 => in_query = false,
            6 => frames.push(vec![6]),
            _ if !in_query => frames.last_mut().unwrap().push(code),
            _ => {}
        }
    }
    assert_eq!(frames[3], [6, 16, 17, 7]);
    assert_eq!(frames[5], [6, 14, 15, 16, 17, 7]);
    let trace = ghidra_sim::trace_session(&shared.borrow().from_process);
    assert_eq!(trace.responses.len(), 6);
    for index in [2, 4] {
        assert_eq!(trace.responses[index].payload.as_deref(), Some(b"t".as_slice()));
    }
    let failed = &trace.responses[3];
    assert!(failed.payload.is_none(), "failed analysis must not open a document frame");
    assert!(
        failed.warnings.contains("Low-level Error: Flow exceeded maximum allowable instructions"),
        "native diagnostic was lost: {}",
        failed.warnings
    );
    let recovered = &trace.responses[5];
    assert!(recovered.warnings.is_empty(), "stale error: {}", recovered.warnings);
    let parsed = parse_decompile_doc(recovered.payload.as_ref().expect("recovered document"), &manager);
    assert_eq!(parsed.name.as_bytes(), FUNC_NAME);
    assert!(parsed.has_markup);
    assert!(parsed.markup_oprefs.is_subset(&parsed.ast_op_times));
    assert!(parsed.markup_varrefs.is_subset(&parsed.ast_var_refs));
    assert!(parsed.c_text.contains("return;"), "{}", parsed.c_text);
}

#[test]
fn trace_undefined_function_without_id_preserves_name_entry_and_return() {
    use kuna_base::marshal::{
        ATTRIB_EXTRAPOP, ATTRIB_ID, ATTRIB_MODEL, ATTRIB_NAME, ELEM_VOID,
    };
    use kuna_decomp::remote_provider::{
        ATTRIB_LOCK, ATTRIB_MAIN, ELEM_LOCALDB, ELEM_MAPSYM, ELEM_PARENT, ELEM_SCOPE,
        ELEM_SYMBOLLIST, ELEM_PROTOTYPE, ELEM_RETURNSYM,
    };
    use kuna_decomp::funcdata_encode::ELEM_FUNCTION;
    use kuna_base::address::ELEM_RANGELIST;
    use ghidra_sim::oracle::{generate_tspec, repo_root, SimOracle};

    // Captured from Ghidra 12.1.4 DBTrace.getFixedProgramView(0), bytes
    // b8 25 00 00 00 c3 at ram:1000, UndefinedFunction.findFunction:
    // <function name="UndefinedFunction_00001000" size="1"> (NO id)
    // <addr space="ram" offset="0x1000"/>
    // <localdb lock="false" main="stack"><scope name="UndefinedFunction_00001000">
    // <parent id="0x0"/><rangelist/><symbollist/></scope></localdb>
    // <prototype extrapop="8" model="unknown"><returnsym><addr/><void/>
    // </returnsym></prototype></function><addr space="ram" offset="0x1000"
    // size="1"/><rangelist/>
    const NAME: &[u8] = b"UndefinedFunction_00001000";
    struct TraceSource {
        registers: SimOracle,
        function: Vec<u8>,
        instructions: [Vec<u8>; 2],
    }
    impl AnswerSource for TraceSource {
        fn respond(&mut self, doc: &[u8]) -> Vec<u8> {
            let mut dec = PackedDecode::new(&self.registers.manager);
            dec.ingest_stream(doc).unwrap();
            let command = dec.open_element().unwrap();
            if command == kuna_ghidra::ids::ELEM_COMMAND_GETMAPPEDSYMBOLS.get_id() {
                let address = Address::decode(&mut dec).unwrap();
                return if address.get_offset() == ENTRY {
                    resp_string(&self.function)
                } else { resp_empty() };
            }
            if command == ELEM_COMMAND_GETPCODE.get_id() {
                return match Address::decode(&mut dec).unwrap().get_offset() {
                    ENTRY => resp_string(&self.instructions[0]),
                    offset if offset == ENTRY + 5 => resp_string(&self.instructions[1]),
                    _ => resp_empty(),
                };
            }
            if [ELEM_COMMAND_GETREGISTER.get_id(), ELEM_COMMAND_GETREGISTERNAME.get_id(),
                ELEM_COMMAND_GETUSEROPNAME.get_id()].contains(&command)
            {
                drop(dec);
                return self.registers.respond(doc);
            }
            // In particular getCodeLabel cannot supply the expected function name.
            resp_empty()
        }
    }
    let Some(oracle) = SimOracle::bootstrap(&repo_root().join("tests/bug-repro/faillog"))
        else { return };
    let manager = Rc::clone(&oracle.manager);
    let entry = Address::new(Rc::clone(manager.get_space_by_name("ram").unwrap()), ENTRY);
    let mut function = Vec::new();
    {
        let mut enc = PackedEncode::new(&mut function);
        enc.open_element(&kuna_ghidra::ids::ELEM_DOC);
        enc.write_unsigned_integer(&ATTRIB_ID, 0);
        enc.open_element(&ELEM_MAPSYM);
        enc.open_element(&ELEM_FUNCTION);
        enc.write_string(&ATTRIB_NAME, NAME);
        enc.write_signed_integer(&ATTRIB_SIZE, 1);
        entry.encode(&mut enc).unwrap();
        enc.open_element(&ELEM_LOCALDB);
        enc.write_bool(&ATTRIB_LOCK, false);
        enc.write_space(&ATTRIB_MAIN, manager.get_space_by_name("stack").unwrap());
        enc.open_element(&ELEM_SCOPE);
        enc.write_string(&ATTRIB_NAME, NAME);
        enc.open_element(&ELEM_PARENT);
        enc.write_unsigned_integer(&ATTRIB_ID, 0);
        enc.close_element(&ELEM_PARENT);
        for element in [ELEM_RANGELIST, ELEM_SYMBOLLIST] {
            enc.open_element(&element);
            enc.close_element(&element);
        }
        enc.close_element(&ELEM_SCOPE);
        enc.close_element(&ELEM_LOCALDB);
        enc.open_element(&ELEM_PROTOTYPE);
        enc.write_signed_integer(&ATTRIB_EXTRAPOP, 8);
        enc.write_string(&ATTRIB_MODEL, b"unknown");
        enc.open_element(&ELEM_RETURNSYM);
        Address::new_invalid().encode(&mut enc).unwrap();
        enc.open_element(&ELEM_VOID);
        enc.close_element(&ELEM_VOID);
        enc.close_element(&ELEM_RETURNSYM);
        enc.close_element(&ELEM_PROTOTYPE);
        enc.close_element(&ELEM_FUNCTION);
        entry.encode_sized(&mut enc, 1).unwrap();
        enc.open_element(&ELEM_RANGELIST);
        enc.close_element(&ELEM_RANGELIST);
        enc.close_element(&ELEM_MAPSYM);
        enc.close_element(&kuna_ghidra::ids::ELEM_DOC);
    }
    // Minimal p-code for mov eax,37 (zero-extends RAX) and ret. Real x86
    // register/model answers come from the existing oracle, not a second ABI.
    let instructions = [(ENTRY, 5, OpCode::CPUI_COPY), (ENTRY + 5, 1, OpCode::CPUI_RETURN)]
        .map(|(offset, length, code)| {
            let mut doc = Vec::new();
            let mut enc = PackedEncode::new(&mut doc);
            let inst = ElementId::new("inst", 98);
            enc.open_element(&inst);
            enc.write_signed_integer(&kuna_base::marshal::ATTRIB_OFFSET, length);
            Address::new(Rc::clone(entry.get_space().unwrap()), offset).encode(&mut enc).unwrap();
            enc.open_element(&ELEM_OP);
            enc.write_signed_integer(&ATTRIB_SIZE, 1);
            enc.write_opcode(&ATTRIB_CODE, code);
            if code == OpCode::CPUI_COPY {
                Address::new(Rc::clone(manager.get_space_by_name("register").unwrap()), 0)
                    .encode_sized(&mut enc, 8).unwrap();
            } else {
                enc.open_element(&ELEM_VOID);
                enc.close_element(&ELEM_VOID);
            }
            Address::new(Rc::clone(manager.get_constant_space().unwrap()),
                if code == OpCode::CPUI_COPY { 37 } else { 0 })
                .encode_sized(&mut enc, 8).unwrap();
            enc.close_element(&ELEM_OP);
            enc.close_element(&inst);
            doc
        });
    let languages = repo_root().join("specs/Ghidra/Processors/x86/data/languages");
    let tspec = generate_tspec(&manager, oracle.big_endian, oracle.unique_base);
    let mut commands = Vec::new();
    cmd_register_program(&mut commands, &std::fs::read(languages.join("x86-64.pspec")).unwrap(),
        &std::fs::read(languages.join("x86-64-gcc.cspec")).unwrap(), &tspec, CORETYPES);
    cmd_set_action(&mut commands, "0", "decompile", "c");
    let mut packed_entry = Vec::new();
    entry.encode(&mut PackedEncode::new(&mut packed_entry)).unwrap();
    cmd_decompile_at(&mut commands, "0", &packed_entry);
    let shared = Rc::new(RefCell::new(MockState::new(commands,
        TraceSource { registers: oracle, function, instructions })));
    let mut process = GhidraProcess::new(
        MockReader { shared: Rc::clone(&shared) }, MockWriter { shared: Rc::clone(&shared) });
    for _ in 0..3 { assert_eq!(process.read_command().unwrap(), 0); }
    let trace = ghidra_sim::trace_session(&shared.borrow().from_process);
    let response = &trace.responses[2];
    assert!(response.warnings.is_empty(), "{}", response.warnings);
    let parsed = parse_decompile_doc(response.payload.as_ref().expect("completed function"), &manager);
    assert_eq!(parsed.name.as_bytes(), NAME);
    assert_eq!(parsed.entry_space.as_deref(), Some("ram"));
    assert_eq!(parsed.entry_offset, Some(ENTRY));
    assert!(parsed.has_markup);
    assert!(parsed.markup_oprefs.is_subset(&parsed.ast_op_times));
    assert!(parsed.markup_varrefs.is_subset(&parsed.ast_var_refs));
    let returns: Vec<_> = parsed.ast_ops.values()
        .filter(|op| op.code == OpCode::CPUI_RETURN as i64).collect();
    assert_eq!(returns.len(), 1);
    assert_eq!(returns[0].inputs.len(), 2);
    let mut value = returns[0].inputs[1].expect("return value reference");
    // A recovered register return may retain its defining COPY in the AST.
    // Follow only value-preserving copies, not arbitrary output text or ops.
    let mut remaining = parsed.ast_ops.len();
    while !parsed.ast_constants.contains_key(&value) {
        assert!(remaining > 0, "cycle in returned value definitions");
        remaining -= 1;
        let definition = parsed.ast_ops.values().find(|op| op.output == Some(value))
            .expect("returned value must have a definition");
        assert_eq!(definition.code, OpCode::CPUI_COPY as i64);
        assert_eq!(definition.inputs.len(), 1);
        value = definition.inputs[0].expect("COPY input reference");
    }
    assert_eq!(parsed.ast_constants.get(&value), Some(&37));
}

#[test]
fn option_failures_and_future_elements_preserve_native_session_recovery() {
    use kuna_decomp::options::{
        ELEM_COMMENTINDENT, ELEM_COMMENTSTYLE, ELEM_INTEGERFORMAT, ELEM_MAXINSTRUCTION,
        ELEM_MAXLINEWIDTH, ELEM_OPTIONSLIST, ELEM_PROTOEVAL, ELEM_SETACTION, ELEM_SETLANGUAGE,
    };
    use kuna_base::marshal::ATTRIB_CONTENT;

    for case in [
        "negative_limit", "missing_model", "missing_action", "java", "shape", "truncated",
        "future", "rust", "line_width", "comment_indent", "comment_style", "integer_format",
    ] {
        let model = TspecModel::decode(TSPEC, &build_registry()).unwrap();
        let manager = Rc::new(model.manager);
        let mut addr = Vec::new();
        Address::new(Rc::clone(manager.get_space_by_name("ram").unwrap()), ENTRY)
            .encode(&mut PackedEncode::new(&mut addr)).unwrap();
        let mut options = Vec::new();
        {
            let mut enc = PackedEncode::new(&mut options);
            enc.open_element(&ELEM_OPTIONSLIST);
            let (element, value) = match case {
                "negative_limit" => (ELEM_MAXINSTRUCTION, "-1"),
                "missing_model" => (ELEM_PROTOEVAL, "missing_model"),
                "missing_action" => (ELEM_SETACTION, "missing_action"),
                "java" => (ELEM_SETLANGUAGE, "java-language"),
                "rust" => (ELEM_SETLANGUAGE, "rust-language"),
                "line_width" => (ELEM_MAXLINEWIDTH, "19"),
                "comment_indent" => (ELEM_COMMENTINDENT, "-2"),
                "comment_style" => (ELEM_COMMENTSTYLE, "invalid"),
                "integer_format" => (ELEM_INTEGERFORMAT, "invalid"),
                _ => (ELEM_MAXINSTRUCTION, "1"),
            };
            let future = ElementId::new("future_option", 4095);
            if case == "future" {
                enc.open_element(&future);
                enc.open_element(&ELEM_MAXINSTRUCTION);
                enc.write_string(&ATTRIB_CONTENT, b"-1");
                enc.close_element(&ELEM_MAXINSTRUCTION);
                enc.close_element(&future);
            }
            enc.open_element(&element);
            if case == "shape" { enc.open_element(&future); }
            enc.write_string(&ATTRIB_CONTENT, value.as_bytes());
            if case == "shape" { enc.close_element(&future); }
            enc.close_element(&element);
            enc.close_element(&ELEM_OPTIONSLIST);
        }
        if case == "truncated" { options.pop(); }
        let mut valid = Vec::new();
        {
            let mut enc = PackedEncode::new(&mut valid);
            enc.open_element(&ELEM_OPTIONSLIST);
            enc.open_element(&ELEM_SETLANGUAGE);
            enc.write_string(&ATTRIB_CONTENT, b"c-language");
            enc.close_element(&ELEM_SETLANGUAGE);
            enc.open_element(&ELEM_MAXINSTRUCTION);
            enc.write_string(&ATTRIB_CONTENT, b"100");
            enc.close_element(&ELEM_MAXINSTRUCTION);
            enc.open_element(&ELEM_PROTOEVAL);
            enc.write_string(&ATTRIB_CONTENT, b"default");
            enc.close_element(&ELEM_PROTOEVAL);
            enc.close_element(&ELEM_OPTIONSLIST);
        }
        let mut commands = Vec::new();
        cmd_register_program(&mut commands, PSPEC, CSPEC, TSPEC, CORETYPES);
        for payload in [&options, &valid] {
            ghidra_sim::burst(&mut commands, 2);
            ghidra_sim::wire_string(&mut commands, b"setOptions");
            ghidra_sim::wire_string(&mut commands, b"0");
            ghidra_sim::wire_string(&mut commands, payload);
            ghidra_sim::burst(&mut commands, 3);
            cmd_decompile_at(&mut commands, "0", &addr);
        }
        let shared = Rc::new(RefCell::new(MockState::new(commands, CannedSource {
            manager: Rc::clone(&manager), entry_nop: true, first_pcode_response: None,
        })));
        let mut process = GhidraProcess::new(
            MockReader { shared: Rc::clone(&shared) },
            MockWriter { shared: Rc::clone(&shared) },
        );
        for _ in 0..5 { assert_eq!(process.read_command().unwrap(), 0); }
        let trace = ghidra_sim::trace_session(&shared.borrow().from_process);
        let expected = if matches!(case, "future" | "rust") { b"t" } else { b"f" };
        assert_eq!(trace.responses[1].payload.as_deref(), Some(expected.as_slice()), "{case}");
        if case == "rust" {
            assert!(trace.responses[1].warnings.is_empty(), "{case}");
            let parsed = parse_decompile_doc(trace.responses[2].payload.as_ref().unwrap(), &manager);
            assert!(parsed.c_text.contains("fn myfunc("), "{}", parsed.c_text);
            assert!(parsed.markup_oprefs.is_subset(&parsed.ast_op_times));
            assert!(parsed.markup_varrefs.is_subset(&parsed.ast_var_refs));
        } else {
            assert!(!trace.responses[1].warnings.is_empty(), "{case}");
        }
        if case == "future" {
            assert!(trace.responses[1].warnings.contains("Warning"), "{case}");
            assert!(trace.responses[2].payload.is_none(), "known option after future subtree must apply");
            assert!(trace.responses[2].warnings.contains("maximum allowable instructions"));
        }
        assert_eq!(trace.responses[3].payload.as_deref(), Some(b"t".as_slice()), "{case}");
        assert!(trace.responses[3].warnings.is_empty(), "{case}");
        let recovered = &trace.responses[4];
        assert!(recovered.warnings.is_empty(), "{case}: {}", recovered.warnings);
        let parsed = parse_decompile_doc(recovered.payload.as_ref().unwrap(), &manager);
        assert_eq!(parsed.name.as_bytes(), FUNC_NAME);
        assert!(parsed.c_text.contains("return;"), "{case}: {}", parsed.c_text);
        assert!(parsed.markup_oprefs.is_subset(&parsed.ast_op_times), "{case}");
        assert!(parsed.markup_varrefs.is_subset(&parsed.ast_var_refs), "{case}");
    }
}

#[test]
fn pcode_errors_preserve_classification_and_session_recovers() {
    let mut malformed = Vec::new();
    {
        let inst = ElementId::new("inst", 98);
        let mut enc = PackedEncode::new(&mut malformed);
        enc.open_element(&inst);
        enc.write_signed_integer(&kuna_base::marshal::ATTRIB_OFFSET, 1);
        enc.close_element(&inst);
    }
    for (response, diagnostic) in [
        (resp_string(&malformed), "Marshaling error:"),
        (
            ghidra_sim::resp_exception("test", "host p-code failure"),
            "Low-level Error: Error generating pcode at address:",
        ),
    ] {
        let model = TspecModel::decode(TSPEC, &build_registry()).unwrap();
        let manager = Rc::new(model.manager);
        let mut addr_packed = Vec::new();
        Address::new(Rc::clone(manager.get_space_by_name("ram").unwrap()), ENTRY)
            .encode(&mut PackedEncode::new(&mut addr_packed))
            .unwrap();
        let mut commands = Vec::new();
        cmd_register_program(&mut commands, PSPEC, CSPEC, TSPEC, CORETYPES);
        cmd_set_action(&mut commands, "0", "decompile", "c");
        cmd_decompile_at(&mut commands, "0", &addr_packed);
        cmd_decompile_at(&mut commands, "0", &addr_packed);
        let shared = Rc::new(RefCell::new(MockState::new(
            commands,
            CannedSource {
                manager: Rc::clone(&manager),
                entry_nop: false,
                first_pcode_response: Some(response),
            },
        )));
        let mut process = GhidraProcess::new(
            MockReader { shared: Rc::clone(&shared) },
            MockWriter { shared: Rc::clone(&shared) },
        );
        for _ in 0..4 {
            assert_eq!(process.read_command().unwrap(), 0);
        }
        let trace = ghidra_sim::trace_session(&shared.borrow().from_process);
        assert_eq!(trace.responses.len(), 4);
        let failed = &trace.responses[2];
        assert!(failed.payload.is_none(), "{diagnostic}");
        assert!(failed.warnings.contains(diagnostic), "{}", failed.warnings);
        let recovered = &trace.responses[3];
        assert!(recovered.warnings.is_empty(), "{}", recovered.warnings);
        let parsed = parse_decompile_doc(recovered.payload.as_ref().unwrap(), &manager);
        assert_eq!(parsed.name.as_bytes(), FUNC_NAME);
        assert!(parsed.has_markup);
        assert!(parsed.c_text.contains("return;"), "{}", parsed.c_text);
    }
}
