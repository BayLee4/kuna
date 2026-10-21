//! Wire contracts of the extension's native commands, driven in-process like
//! `ghidra_sim_e2e.rs` (kuna's own loader answers the host queries): the
//! options list a Java `DecompileOptions` sends reaches the printer and is
//! replaced, not accumulated, by the next list; the BSim signature commands
//! answer on the wire.

#[path = "ghidra_sim/mod.rs"]
mod ghidra_sim;

use std::cell::RefCell;
use std::rc::Rc;

use kuna_base::marshal::{Encoder, PackedEncode, ATTRIB_CONTENT};
use kuna_decomp::options::{
    ELEM_BRACEFORMAT, ELEM_INPLACEOPS, ELEM_MAXLINEWIDTH, ELEM_NULLPRINTING, ELEM_OPTIONSLIST,
    ELEM_PARAM1, ELEM_PARAM2,
};
use kuna_base::marshal::ElementId;
use kuna_ghidra::process::GhidraProcess;

use ghidra_sim::oracle::{generate_tspec, repo_root, SimOracle};
use ghidra_sim::{
    burst, cmd_decompile_at, cmd_deregister_program, cmd_register_program, cmd_set_action,
    cmd_set_options, parse_decompile_doc, trace_session, wire_string, MockReader, MockState,
    MockWriter, ResponseTrace,
};

/// A packed `<optionslist>` of `(element, parameters)` entries, as Java's
/// `DecompileOptions.encode` writes them.
fn options(list: &[(&ElementId, &[&str])]) -> Vec<u8> {
    let mut bytes = Vec::new();
    let mut e = PackedEncode::new(&mut bytes);
    e.open_element(&ELEM_OPTIONSLIST);
    for (id, params) in list {
        e.open_element(id);
        for (param, text) in [&ELEM_PARAM1, &ELEM_PARAM2].into_iter().zip(params.iter()) {
            e.open_element(param);
            e.write_string(&ATTRIB_CONTENT, text.as_bytes());
            e.close_element(param);
        }
        e.close_element(id);
    }
    e.close_element(&ELEM_OPTIONSLIST);
    bytes
}

fn command(v: &mut Vec<u8>, name: &str, params: &[&[u8]]) {
    burst(v, 2);
    wire_string(v, name.as_bytes());
    for param in params {
        wire_string(v, param);
    }
    burst(v, 3);
}

/// Register the faillog program, run `script` against `sub_3ad0`'s packed
/// entry address, deregister, and return one response per script command
/// (registration and deregistration excluded) plus the oracle for decoding.
fn run_script(
    script: impl FnOnce(&mut Vec<u8>, &[u8]) -> usize,
) -> (SimOracle, Vec<ResponseTrace>) {
    let binary = repo_root().join("tests/bug-repro/faillog");
    let oracle = SimOracle::bootstrap(&binary);
    let entry = oracle.prog.find_entry_by_name("sub_3ad0").expect("sub_3ad0").addr;
    let mut packed_entry = Vec::new();
    entry.encode(&mut PackedEncode::new(&mut packed_entry)).expect("entry encodes");
    let lang_dir = repo_root().join("specs/Ghidra/Processors/x86/data/languages");
    let pspec = std::fs::read(lang_dir.join("x86-64.pspec")).expect("x86-64.pspec");
    let cspec = std::fs::read(lang_dir.join(&oracle.cspec)).expect("cspec");
    let tspec = generate_tspec(&oracle.manager, oracle.big_endian, oracle.unique_base);

    let mut commands = Vec::new();
    cmd_register_program(&mut commands, &pspec, &cspec, &tspec, ghidra_sim::DEFAULT_CORETYPES_XML);
    cmd_set_action(&mut commands, "0", "decompile", "c");
    let count = script(&mut commands, &packed_entry);
    cmd_deregister_program(&mut commands, "0");
    let total = 2 + count + 1;

    let shared = Rc::new(RefCell::new(MockState::new(commands, oracle)));
    let mut process = GhidraProcess::new(
        MockReader { shared: Rc::clone(&shared) },
        MockWriter { shared: Rc::clone(&shared) },
    );
    for i in 0..total {
        let status = process.read_command().unwrap_or_else(|e| panic!("command #{i}: {e:?}"));
        assert_eq!(status, i32::from(i == total - 1), "command #{i} loop status");
    }
    let _ = process.into_inner();
    let state = match Rc::try_unwrap(shared) {
        Ok(cell) => cell.into_inner(),
        Err(_) => panic!("mock state still shared"),
    };
    let mut responses = trace_session(&state.from_process).responses;
    assert_eq!(responses.len(), total, "one response per command");
    let tail = responses.split_off(2 + count);
    drop(tail);
    let script_responses = responses.split_off(2);
    (state.source, script_responses)
}

fn c_text(oracle: &SimOracle, response: &ResponseTrace) -> String {
    assert!(response.warnings.trim().is_empty(), "warnings: {}", response.warnings);
    let payload = response.payload.as_ref().expect("decompileAt payload");
    parse_decompile_doc(payload, &oracle.manager).c_text
}

/// The four options whose native defaults differ from Java's are sent on every
/// `setOptions`; each reaches the printer, and the next list replaces the last
/// one (Java encodes a list, not a delta from the previous call).
#[test]
fn ghidra_sim_options_reach_the_printer_and_the_next_list_replaces_them() {
    let changed = options(&[
        (&ELEM_INPLACEOPS, &["off"]),
        (&ELEM_NULLPRINTING, &["off"]),
        (&ELEM_BRACEFORMAT, &["function", "skip"]),
        (&ELEM_MAXLINEWIDTH, &["40"]),
    ]);
    let (oracle, responses) = run_script(|v, entry| {
        cmd_decompile_at(v, "0", entry);
        cmd_set_options(v, "0", &changed);
        cmd_decompile_at(v, "0", entry);
        cmd_set_options(v, "0", &options(&[]));
        cmd_decompile_at(v, "0", entry);
        5
    });
    let [default, with_options, replaced] =
        [0, 2, 4].map(|i| c_text(&oracle, &responses[i]));

    assert!(default.contains("v7 += 2;") && default.contains("NULL") && !default.contains("\n\n{"));
    assert!(!with_options.contains("+=") && !with_options.contains("NULL"), "{with_options}");
    assert!(with_options.contains("(char *)0x0") && with_options.contains("\n\n{"), "{with_options}");
    let widest = |c: &str| c.lines().filter(|l| !l.contains("//")).map(str::len).max().unwrap_or(0);
    assert!(widest(&default) > 50 && widest(&with_options) <= 50,
        "width {} -> {}", widest(&default), widest(&with_options));
    assert_eq!(replaced, default, "an empty list must restore every default");
}

/// The BSim signature-settings commands answer on the wire: a valid setting
/// changes the reported settings; an unsupported one is refused and leaves them.
#[test]
fn ghidra_sim_signature_settings_answer_on_the_wire() {
    let (_, responses) = run_script(|v, _| {
        command(v, "getSignatureSettings", &[b"0"]);
        command(v, "setSignatureSettings", &[b"0", b"461"]);
        command(v, "getSignatureSettings", &[b"0"]);
        command(v, "setSignatureSettings", &[b"0", b"2"]);
        command(v, "getSignatureSettings", &[b"0"]);
        5
    });
    let payload = |i: usize| responses[i].payload.clone().expect("payload");
    assert_ne!(payload(0), payload(2), "valid settings change the reported settings");
    assert_eq!(payload(1), b"t");
    assert_eq!(payload(3), b"f");
    assert_eq!(payload(2), payload(4), "a refused setting leaves the valid one");
}
