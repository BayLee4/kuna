//! Production-script corpus coverage of Ghidra's AST and token-address contract.
//! The test-local reader follows PcodeSyntaxTree/PcodeOp/Varnode and the Clang
//! token consumers; it deliberately does not implement HighFunction's other
//! documents (symbols, prototypes, high variables, or jump tables).

use crate::common;
#[path = "common/corpus.rs"]
mod corpus;

use std::collections::{BTreeMap, BTreeSet};

use corpus::Corpus;
use kuna_base::address::{Address, RangeList, SeqNum, ELEM_ADDR};
use kuna_base::error::KunaResult;
use kuna_base::marshal::{
    Decoder, PackedDecode, PackedEncode, ATTRIB_CONTENT, ATTRIB_INDEX, ATTRIB_NAME,
    ATTRIB_REF, ATTRIB_SIZE, ATTRIB_SPACE, ATTRIB_VALUE, ELEM_VOID,
};
use kuna_base::space::{spacetype, AddrSpaceManager};
use kuna_decomp::block::{
    BlockKind, ATTRIB_END, ATTRIB_REV, ELEM_BLOCK, ELEM_BLOCKEDGE, ELEM_EDGE,
};
use kuna_decomp::context::VarnodeId;
use kuna_decomp::funcdata::Funcdata;
use kuna_decomp::funcdata_encode::{ELEM_AST, ELEM_FUNCTION, ELEM_IOP, ELEM_VARNODES};
use kuna_decomp::prettyprint::ids::{ATTRIB_OPREF, ATTRIB_VARREF, ELEM_VARIABLE};
use kuna_num::opcodes::OpCode;
use kuna_num::pcoderaw::{ATTRIB_CODE, ELEM_SPACEID};
use kuna_sleigh::translate::ELEM_OP;

#[derive(PartialEq, Eq)]
struct Storage {
    address: Address,
    size: i32,
}

impl std::fmt::Debug for Storage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{:#x}/{}", self.address.get_space().map_or("<invalid>", |s| s.get_name()),
            self.address.get_offset(), self.size)
    }
}

#[derive(Debug, PartialEq, Eq)]
enum Operand {
    Void,
    Ref(u64),
    Space(i32),
    Iop(u64),
}

#[derive(Debug, PartialEq, Eq)]
struct Instruction {
    code: i64,
    address: Address,
    output: Operand,
    inputs: Vec<Operand>,
}

#[derive(Debug, Default, PartialEq, Eq)]
struct Block {
    ranges: Vec<(i32, u64, u64)>,
    ops: Vec<u64>,
    // Incoming slot order, with the predecessor's outgoing slot.
    incoming: Vec<(i64, i64)>,
}

#[derive(Debug, Default)]
struct Ast {
    varnodes: BTreeMap<u64, Storage>,
    ops: BTreeMap<u64, Instruction>,
    blocks: BTreeMap<i64, Block>,
}

fn ranges(cover: &RangeList) -> Vec<(i32, u64, u64)> {
    cover.iter().map(|r| (r.get_space().get_index(), r.get_first(), r.get_last())).collect()
}

fn storage_attributes(dec: &mut PackedDecode) -> KunaResult<Storage> {
    let space = dec.read_space_id(&ATTRIB_SPACE)?;
    dec.rewind_attributes();
    let mut size = 0;
    let offset = space.decode_attributes(dec, &mut size)?;
    Ok(Storage { address: Address::new(space, offset), size: size as i32 })
}

fn operand(dec: &mut PackedDecode) -> KunaResult<Operand> {
    let id = dec.open_element()?;
    let result = if id == ELEM_VOID.get_id() {
        Operand::Void
    } else if id == ELEM_ADDR.get_id() {
        Operand::Ref(dec.read_unsigned_integer_id(&ATTRIB_REF)?)
    } else if id == ELEM_SPACEID.get_id() {
        Operand::Space(dec.read_space_id(&ATTRIB_NAME)?.get_index())
    } else {
        assert_eq!(id, ELEM_IOP.get_id(), "unexpected AST operand");
        Operand::Iop(dec.read_unsigned_integer_id(&ATTRIB_VALUE)?)
    };
    dec.close_element(id)?;
    Ok(result)
}

fn decode_ast(dec: &mut PackedDecode) -> KunaResult<Ast> {
    let mut ast = Ast::default();
    let root = dec.open_element_id(&ELEM_AST)?;
    let vars = dec.open_element_id(&ELEM_VARNODES)?;
    while dec.peek_element()? != 0 {
        let id = dec.open_element_id(&ELEM_ADDR)?;
        let reference = dec.read_unsigned_integer_id(&ATTRIB_REF)?;
        let storage = storage_attributes(dec)?;
        assert!(ast.varnodes.insert(reference, storage).is_none(),
            "duplicate varnode ref {reference}");
        dec.close_element(id)?;
    }
    dec.close_element(vars)?;
    while dec.peek_element()? == ELEM_BLOCK.get_id() {
        let id = dec.open_element_id(&ELEM_BLOCK)?;
        let index = dec.read_signed_integer_id(&ATTRIB_INDEX)?;
        let mut cover = RangeList::new();
        cover.decode(dec)?;
        let mut block = Block { ranges: ranges(&cover), ..Block::default() };
        while dec.peek_element()? != 0 {
            let id = dec.open_element_id(&ELEM_OP)?;
            let code = dec.read_signed_integer_id(&ATTRIB_CODE)?;
            let seq = SeqNum::decode(dec)?;
            let reference = u64::from(seq.get_time());
            let address = seq.get_addr().clone();
            let output = operand(dec)?;
            let mut inputs = Vec::new();
            while dec.peek_element()? != 0 {
                inputs.push(operand(dec)?);
            }
            let op = Instruction { code, address, output, inputs };
            assert!(ast.ops.insert(reference, op).is_none(), "duplicate op uniq {reference}");
            block.ops.push(reference);
            dec.close_element(id)?;
        }
        assert!(ast.blocks.insert(index, block).is_none(), "duplicate block index {index}");
        dec.close_element(id)?;
    }
    let mut edge_blocks = BTreeSet::new();
    while dec.peek_element()? != 0 {
        let id = dec.open_element_id(&ELEM_BLOCKEDGE)?;
        let index = dec.read_signed_integer_id(&ATTRIB_INDEX)?;
        assert!(edge_blocks.insert(index), "duplicate blockedge index {index}");
        let block = ast.blocks.get_mut(&index).expect("blockedge references missing block");
        while dec.peek_element()? != 0 {
            let edge = dec.open_element_id(&ELEM_EDGE)?;
            block.incoming.push((dec.read_signed_integer_id(&ATTRIB_END)?,
                                 dec.read_signed_integer_id(&ATTRIB_REV)?));
            dec.close_element(edge)?;
        }
        dec.close_element(id)?;
    }
    dec.close_element(root)?;
    Ok(ast)
}

fn decode_function(manage: &AddrSpaceManager, bytes: &[u8], fd: &Funcdata) -> KunaResult<Ast> {
    let mut dec = PackedDecode::new(manage);
    dec.ingest_stream(bytes)?;
    let root = dec.open_element_id(&ELEM_FUNCTION)?;
    assert_eq!(dec.read_string_id(&ATTRIB_NAME)?, fd.get_name().as_bytes());
    assert_eq!(dec.read_signed_integer_id(&ATTRIB_SIZE)?, i64::from(fd.get_size()));
    assert_eq!(dec.peek_element()?, ELEM_ADDR.get_id(), "missing function entry");
    assert_eq!(Address::decode(&mut dec)?, *fd.get_address(), "function entry address");
    let mut ast = None;
    while dec.peek_element()? != 0 {
        if dec.peek_element()? == ELEM_AST.get_id() {
            assert!(ast.is_none(), "duplicate AST");
            ast = Some(decode_ast(&mut dec)?);
        } else {
            // Other HighFunction documents have separate contract tests.
            dec.skip_element()?;
        }
    }
    dec.close_element(root)?;
    assert_eq!(dec.peek_element()?, 0, "trailing function document");
    Ok(ast.expect("missing AST"))
}

fn reference(fd: &Funcdata, vn: Option<VarnodeId>) -> Operand {
    vn.map_or(Operand::Void, |vn| Operand::Ref(u64::from(fd.vbank().get(vn).unwrap().get_create_index())))
}

fn verify_ast(fd: &Funcdata, ast: &Ast) {
    let expected_vars: BTreeMap<_, _> = fd.vbank().iter_loc().filter_map(|id| {
        let vn = fd.vbank().get(id).unwrap();
        // fspec is an internal call-spec handle, not Java storage. Its wire
        // address is the callee entry; derive that from the live call graph.
        let address = if vn.get_space().get_type() == spacetype::IPTR_FSPEC {
            (0..fd.num_calls()).find_map(|i| {
                let call = fd.get_call_specs(i);
                (fd.obank().get(call.get_op()).unwrap().get_in(0) == Some(id))
                    .then(|| call.get_entry_address().clone())
            }).expect("fspec varnode must identify a live call target")
        } else { vn.get_addr().clone() };
        (vn.get_space().get_type() != spacetype::IPTR_IOP).then(|| (
            u64::from(vn.get_create_index()), Storage { address, size: vn.get_size() },
        ))
    }).collect();
    assert_eq!(ast.varnodes.keys().collect::<Vec<_>>(), expected_vars.keys().collect::<Vec<_>>(),
        "serialized varnode references");
    for (reference, expected) in &expected_vars {
        assert_eq!(&ast.varnodes[reference], expected, "serialized varnode storage at ref {reference}");
    }
    let mut expected_ops = BTreeMap::new();
    let mut expected_blocks = BTreeMap::new();
    for i in 0..fd.bblocks_get_size() {
        let id = fd.bblocks_get_block(i);
        let live = fd.bblocks_ref().block(id);
        let BlockKind::Basic(basic) = live.kind() else { panic!("not a basic block") };
        let mut block = Block { ranges: ranges(&basic.cover), ..Block::default() };
        for slot in 0..live.size_in() {
            let pred = fd.bblocks_ref().block(live.get_in(slot));
            block.incoming.push((i64::from(pred.get_index()), i64::from(live.get_in_rev_index(slot))));
        }
        for id in fd.bb_ops(id) {
            let live = fd.obank().get(id).unwrap();
            let mut inputs = Vec::new();
            for slot in 0..live.num_input() {
                let input = live.get_in(slot);
                let value = if let Some(vn) = input {
                    let vn = fd.vbank().get(vn).unwrap();
                    if vn.get_space().get_type() == spacetype::IPTR_IOP {
                        if slot == 1 && live.code() == OpCode::CPUI_INDIRECT {
                            let target = kuna_decomp::merge::MergeContext::indirect_effect_op(fd, id);
                            Operand::Iop(u64::from(fd.obank().get(target).unwrap().get_time()))
                        } else { Operand::Void }
                    } else if slot == 0 && matches!(live.code(), OpCode::CPUI_LOAD | OpCode::CPUI_STORE) {
                        Operand::Space(vn.get_offset() as i32)
                    } else { reference(fd, input) }
                } else { Operand::Void };
                inputs.push(value);
            }
            let uniq = u64::from(live.get_time());
            block.ops.push(uniq);
            expected_ops.insert(uniq, Instruction {
                code: live.code() as i64,
                address: live.get_seq_num().get_addr().clone(),
                output: reference(fd, live.get_out()), inputs,
            });
        }
        expected_blocks.insert(i64::from(live.get_index()), block);
    }
    assert_eq!(ast.ops, expected_ops, "serialized opcode, seqnum address, or ordered operands");
    assert_eq!(ast.blocks, expected_blocks, "serialized block cover, op order, or incoming edges");

    // Java reconstructs outgoing edges from each incoming edge's reverse slot.
    let mut outgoing = BTreeMap::new();
    for (&target, block) in &ast.blocks {
        for (slot, &(pred, reverse)) in block.incoming.iter().enumerate() {
            assert!(ast.blocks.contains_key(&pred), "edge references missing predecessor");
            assert!(reverse >= 0, "negative outgoing edge slot");
            assert!(outgoing.insert((pred, reverse), (target, slot as i64)).is_none(),
                "duplicate outgoing edge slot");
        }
    }
    for i in 0..fd.bblocks_get_size() {
        let block = fd.bblocks_ref().block(fd.bblocks_get_block(i));
        for slot in 0..block.size_out() {
            let target = fd.bblocks_ref().block(block.get_out(slot));
            assert_eq!(outgoing.get(&(i64::from(block.get_index()), i64::from(slot))),
                Some(&(i64::from(target.get_index()), i64::from(block.get_out_rev_index(slot)))),
                "reconstructed outgoing edge");
        }
    }
    for op in ast.ops.values() {
        for value in std::iter::once(&op.output).chain(&op.inputs) {
            match value {
                Operand::Ref(id) => assert!(ast.varnodes.contains_key(id), "missing operand varnode {id}"),
                Operand::Iop(id) => assert!(ast.ops.contains_key(id), "missing INDIRECT target {id}"),
                Operand::Space(id) => assert!(fd.get_arch().manage().get_space(*id).is_some(), "missing LOAD/STORE space"),
                Operand::Void => (),
            }
        }
    }
}

#[derive(Debug)]
struct Token {
    element: u32,
    text: Vec<u8>,
    opref: Option<u64>,
    varref: Option<u64>,
}

fn walk_markup(dec: &mut PackedDecode, tokens: &mut Vec<Token>) -> KunaResult<()> {
    let element = dec.open_element()?;
    let mut token = Token { element, text: Vec::new(), opref: None, varref: None };
    loop {
        let attr = dec.get_next_attribute_id()?;
        if attr == 0 { break; }
        if attr == ATTRIB_OPREF.get_id() {
            assert!(token.opref.replace(dec.read_unsigned_integer()?).is_none(), "duplicate token opref");
        } else if attr == ATTRIB_VARREF.get_id() {
            assert!(token.varref.replace(dec.read_unsigned_integer()?).is_none(), "duplicate token varref");
        } else if attr == ATTRIB_CONTENT.get_id() {
            token.text = dec.read_string()?;
        }
    }
    tokens.push(token);
    while dec.peek_element()? != 0 { walk_markup(dec, tokens)?; }
    dec.close_element(element)?;
    Ok(())
}

fn verify_markup(ast: &Ast, manage: &AddrSpaceManager, bytes: &[u8], stem: &str) {
    let mut dec = PackedDecode::new(manage);
    dec.ingest_stream(bytes).expect("markup stream");
    assert_eq!(dec.peek_element().unwrap(), ELEM_FUNCTION.get_id());
    let mut tokens = Vec::new();
    walk_markup(&mut dec, &mut tokens).expect("markup document");
    for token in &tokens {
        if let Some(id) = token.opref {
            ast.ops.get(&id).unwrap_or_else(|| panic!("markup opref {id} has no serialized op: {token:?}"));
        }
        if let Some(id) = token.varref {
            ast.varnodes.get(&id).unwrap_or_else(|| panic!("markup varref {id} has no serialized storage: {token:?}"));
        }
    }
    if stem == "lzcount" {
        // The fixture ends with blr at ram:1002c. ClangOpToken.getMinAddress()
        // returns its resolved op's sequence address, not a varnode address.
        let token = tokens.iter().find(|t| t.element == ELEM_OP.get_id() && t.text == b"return")
            .expect("required return token");
        let op = &ast.ops[&token.opref.expect("return token lost instruction reference")];
        assert_eq!(op.code, OpCode::CPUI_RETURN as i64, "return token resolved wrong opcode");
        assert_eq!(op.address.get_space().unwrap().get_name(), "ram");
        assert_eq!(op.address.get_offset(), 0x1002c, "return token instruction address");

        let comparison = tokens.iter().find(|t| t.element == ELEM_OP.get_id() && t.text == b"==")
            .expect("required equality token, not a void shell");
        let comparison_id = comparison.opref.expect("equality token lost instruction reference");
        let op = &ast.ops[&comparison_id];
        assert_eq!(op.code, OpCode::CPUI_INT_EQUAL as i64, "equality token resolved wrong opcode");
        let variable = tokens.iter().find(|t| t.element == ELEM_VARIABLE.get_id()
            && t.opref == Some(comparison_id) && t.varref.is_some() && t.text != b"3")
            .expect("comparison variable must retain both Ghidra references");
        let id = variable.varref.unwrap();
        assert!(op.inputs.contains(&Operand::Ref(id)), "variable token resolves outside its instruction operands");
        assert_eq!(ast.varnodes[&id].size, 4, "PowerPC comparison variable storage width");
        assert_ne!(ast.varnodes[&id].address.get_space().unwrap().get_type(),
            spacetype::IPTR_CONSTANT, "parameter token resolved to constant storage");
        assert!(op.inputs.iter().any(|input| match input {
            Operand::Ref(id) => {
                let storage = &ast.varnodes[id];
                storage.address.get_space().unwrap().get_type() == spacetype::IPTR_CONSTANT
                    && storage.address.get_offset() == 3 && storage.size == 4
            }
            _ => false,
        }), "equality must compare against the fixture's constant 3");
    }
}

#[test]
fn scripted_functions_preserve_ghidra_ast_and_markup_relationships() {
    // Only scripted bodies are selected. External call targets remain symbols.
    for (stem, name, required_opcode) in [
        ("boolless", "boolless", OpCode::CPUI_CBRANCH),
        ("ccmp", "ccmp", OpCode::CPUI_CALL),
        ("gp", "test_gp", OpCode::CPUI_CALL),
        ("lzcount", "cntlzwtest", OpCode::CPUI_INT_EQUAL),
        ("condexesub", "func", OpCode::CPUI_CALL),
        ("condexesub", "iblockadd", OpCode::CPUI_STORE),
    ] {
        eprintln!("AST/markup contract: {stem}:{name}");
        let mut corpus = Corpus::load(stem);
        let data = corpus.run_to_function(name);
        let fd = data.fd.as_mut().expect("script must decompile required function");
        assert_eq!(fd.get_name(), name);
        let mut bytes = Vec::new();
        fd.encode(&mut PackedEncode::new(&mut bytes), 1, true).expect("encode required function");
        let ast = decode_function(fd.get_arch().manage(), &bytes, fd).expect("decode serialized AST");
        verify_ast(fd, &ast);
        // A recovered named call can retain CALLIND (notably MIPS jalr).
        // Call identity/arguments are corpus output contracts; here either
        // call form supplies the body guard, while verify_ast checks its
        // exact serialized opcode and operands against the analyzed function.
        assert!(ast.ops.values().any(|op| op.code == required_opcode as i64
            || (required_opcode == OpCode::CPUI_CALL && op.code == OpCode::CPUI_CALLIND as i64)),
            "{stem}:{name} lost its required semantic operation {required_opcode:?}");
        let arch = data.conf.as_mut().unwrap().arch_mut();
        let mut printer = arch.take_print();
        let markup = printer.doc_function_markup(fd, arch);
        arch.put_print(printer);
        verify_markup(&ast, fd.get_arch().manage(), &markup, stem);
    }
}
