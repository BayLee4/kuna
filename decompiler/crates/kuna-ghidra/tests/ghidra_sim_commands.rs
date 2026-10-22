//! Wire contracts of the extension's native commands, driven in-process like
//! `ghidra_sim_e2e.rs` (kuna's own loader answers the host queries): the
//! options list a Java `DecompileOptions` sends reaches the printer and is
//! replaced, not accumulated, by the next list; the BSim signature commands and
//! `structureGraph` answer on the wire.

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
use kuna_base::marshal::{Decoder, PackedDecode, ATTRIB_INDEX, ATTRIB_TYPE, ELEM_TARGET};
use kuna_decomp::block::{
    BlockGraph, BlockKind, FlowBlock, ATTRIB_ALTINDEX, ATTRIB_END, ATTRIB_REV, ELEM_BHEAD, ELEM_BLOCK,
    ELEM_EDGE,
};
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

/// BSim signatures: `generateSignatures` and `debugSignatures` answer for a function
/// whose host supplied no prototype, deterministically, and a refused settings
/// change does not alter the next result.
#[test]
fn ghidra_sim_signature_commands_answer_deterministically() {
    let (_, responses) = run_script(|v, entry| {
        cmd_set_action(v, "0", "normalize", "");
        command(v, "generateSignatures", &[b"0", entry]);
        command(v, "generateSignatures", &[b"0", entry]);
        command(v, "debugSignatures", &[b"0", entry]);
        command(v, "setSignatureSettings", &[b"0", b"2"]);
        command(v, "generateSignatures", &[b"0", entry]);
        6
    });
    let payload = |i: usize| responses[i].payload.clone().expect("payload");
    for i in 0..6 {
        assert!(responses[i].warnings.trim().is_empty(), "#{i}: {}", responses[i].warnings);
    }
    assert!(payload(1).len() > 16, "an empty signature document");
    assert_eq!(payload(1), payload(2), "repeat generateSignatures differs");
    assert!(payload(3).len() > payload(1).len(), "debug signatures carry the simple features and more");
    assert_eq!(payload(1), payload(5), "a refused setting changed the next result");
}

/// One `<block>` of `structureGraph`'s answer: the canonical output grammar the
/// Java `BlockGraph` consumes (type, optional `altindex` of a copy, `<bhead>`
/// headers, child blocks, `<target>`s and `<edge>`s).
#[derive(Debug)]
struct Structured {
    kind: String,
    original: Option<i64>,
    children: Vec<Structured>,
    edges: Vec<(i64, i64)>,
}

fn read_block(decoder: &mut dyn Decoder, kind: String) -> Structured {
    let element = decoder.open_element_id(&ELEM_BLOCK).unwrap();
    decoder.read_signed_integer_id(&ATTRIB_INDEX).unwrap();
    let original = (kind == "copy").then(|| decoder.read_signed_integer_id(&ATTRIB_ALTINDEX).unwrap());
    let mut headers = Vec::new();
    while decoder.peek_element().unwrap() == ELEM_BHEAD.get_id() {
        let header = decoder.open_element_id(&ELEM_BHEAD).unwrap();
        decoder.read_signed_integer_id(&ATTRIB_INDEX).unwrap();
        headers.push(String::from_utf8(decoder.read_string_id(&ATTRIB_TYPE).unwrap()).unwrap());
        decoder.close_element(header).unwrap();
    }
    let children = headers.into_iter().map(|child_kind| read_block(decoder, child_kind)).collect();
    while decoder.peek_element().unwrap() == ELEM_TARGET.get_id() {
        decoder.skip_element().unwrap();
    }
    let mut edges = Vec::new();
    while decoder.peek_element().unwrap() == ELEM_EDGE.get_id() {
        let edge = decoder.open_element_id(&ELEM_EDGE).unwrap();
        edges.push((
            decoder.read_signed_integer_id(&ATTRIB_END).unwrap(),
            decoder.read_signed_integer_id(&ATTRIB_REV).unwrap(),
        ));
        decoder.close_element(edge).unwrap();
    }
    decoder.close_element(element).unwrap();
    Structured { kind, original, children, edges }
}

/// `structureGraph` structures a diamond for the GUI's graph consumers: one list
/// of an if/else (condition, true branch, false branch) and the join, where the
/// join is a copy naming its input block and carries the collapsed edge.
#[test]
fn ghidra_sim_structure_graph_structures_a_diamond() {
    let mut graph = BlockGraph::new();
    let top = graph.arena.insert(FlowBlock::new_kind(BlockKind::Graph));
    let blocks: Vec<_> = (0..4).map(|_| graph.new_block(top)).collect();
    for (index, &block) in blocks.iter().enumerate() {
        graph.block_mut(block).set_index(index as i32);
    }
    for (from, to) in [(0, 1), (0, 2), (1, 3), (2, 3)] {
        graph.add_edge(blocks[from], blocks[to]);
    }
    let mut packed = Vec::new();
    graph.encode(top, &mut PackedEncode::new(&mut packed));

    let (oracle, responses) = run_script(|v, _| {
        command(v, "structureGraph", &[b"0", &packed]);
        1
    });
    assert!(responses[0].warnings.trim().is_empty(), "warnings: {}", responses[0].warnings);
    let payload = responses[0].payload.as_ref().expect("structureGraph payload");
    let mut decoder = PackedDecode::new(&oracle.manager);
    decoder.ingest_stream(payload).expect("response stream");
    let result = read_block(&mut decoder, "graph".into());
    assert_eq!(decoder.peek_element().unwrap(), 0, "trailing elements");

    let [list] = &result.children[..] else { panic!("one top-level component: {result:?}") };
    assert_eq!(list.kind, "list");
    let [conditional, join] = &list.children[..] else { panic!("if/else then join: {list:?}") };
    assert_eq!(conditional.kind, "ifelse");
    assert_eq!(conditional.children.len(), 3);
    assert_eq!(
        conditional.children.iter().map(|c| c.original).collect::<Vec<_>>(),
        vec![Some(0), Some(2), Some(1)],
        "condition, true branch, false branch name their input blocks",
    );
    assert_eq!((join.kind.as_str(), join.original), ("copy", Some(3)));
    assert_eq!(join.edges.len(), 1, "the join keeps one collapsed incoming edge");
}
