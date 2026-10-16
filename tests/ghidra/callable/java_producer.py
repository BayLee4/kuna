#!/usr/bin/env python3
"""Consume actual CALL_RETURN, dynamic LOAD/CALLIND and unmarked source pcode."""
import json
import os
from pathlib import Path
import sys
import traceback

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from kuna_vs_stock import start_ghidra
from support import snapshot

output = Path(sys.argv[1] if len(sys.argv) > 1 else os.environ["KUNA_SMOKE_OUT"])
output.mkdir(parents=True, exist_ok=True)
report = {"installation": os.environ["GHIDRA_INSTALL_DIR"], "rows": []}
start_ghidra()
from jpype import JArray, JByte
from java.io import ByteArrayOutputStream
from java.lang import Object
from ghidra.app.decompiler import DecompInterface, DecompileOptions, DecompileProcessFactory
from ghidra.app.plugin.processors.sleigh import PcodeEmit, PcodeEmitPacked
from ghidra.program.database import ProgramDB
from ghidra.program.flatapi import FlatProgramAPI
from ghidra.program.model.data import IntegerDataType
from ghidra.program.model.lang import CompilerSpecID, LanguageID
from ghidra.program.model.listing import FlowOverride, Function, ParameterImpl, ReturnParameterImpl, Variable
from ghidra.program.model.pcode import ElementId, PackedDecode, PatchPackedEncode, PcodeOp
from ghidra.program.model.symbol import SourceType
from ghidra.program.util import DefaultLanguageService
from ghidra.util.task import ConsoleTaskMonitor

monitor = ConsoleTaskMonitor()
owner = Object()
language = DefaultLanguageService.getLanguageService().getLanguage(LanguageID("x86:LE:64:default"))
program = ProgramDB("authentic_producer_probe", language,
                    language.getCompilerSpecByID(CompilerSpecID("gcc")), owner)
api = FlatProgramAPI(program, monitor)
factory = DecompileProcessFactory.class_.getDeclaredField("exepath")
factory.setAccessible(True)
original_factory = factory.get(None)
callback_field = DecompInterface.class_.getDeclaredField("decompCallback")
callback_field.setAccessible(True)
interface = None


def address(offset):
    return program.getAddressFactory().getDefaultAddressSpace().getAddress(offset)


def memory(offset, code, name, executable=True):
    block = api.createMemoryBlock(name, address(offset), JArray(JByte)(code), False)
    block.setExecute(executable)


def create_function(offset, name):
    assert api.disassemble(address(offset)), name
    fn = api.createFunction(address(offset), name)
    assert fn is not None, name
    return fn


def capture(site, label):
    encoder = PatchPackedEncode()
    encoder.clear()
    callback_field.get(interface).getPcode(address(site), encoder)
    stream = ByteArrayOutputStream()
    encoder.writeTo(stream)
    payload = stream.toByteArray()
    (output / f"{label}-{site:x}.packed").write_bytes(bytes((int(b) & 255) for b in payload))
    decoder = PackedDecode(program.getAddressFactory())
    decoder.open(len(payload), label)
    decoder.ingestBytes(payload, 0, len(payload))
    decoder.endIngest()
    root = decoder.openElement(ElementId.ELEM_INST)
    addr_element = decoder.openElement(ElementId.ELEM_ADDR)
    decoder.closeElementSkipping(addr_element)
    operations = []
    while decoder.peekElement() != 0:
        op_element = decoder.openElement(ElementId.ELEM_OP)
        opcode = None
        while True:
            attribute = decoder.getNextAttributeId()
            if attribute == 0:
                break
            # Actual wire CODE id, not an inferred operation mnemonic.
            if attribute == 43:
                opcode = int(decoder.readSignedInteger())
        decoder.closeElementSkipping(op_element)
        assert opcode is not None, (label, site)
        operations.append({"opcode": opcode})
    decoder.closeElement(root)
    return operations


def assert_source_flow(operations, marked, needs_load=False):
    calls = [i for i, op in enumerate(operations)
             if op["opcode"] in (PcodeOp.CALL, PcodeOp.CALLIND)]
    returns = [i for i, op in enumerate(operations) if op["opcode"] == PcodeOp.RETURN]
    if marked:
        assert len(calls) == 1 and returns == [len(operations)-1] and calls[0] < returns[0], operations
    else:
        assert len(calls) == 1 and returns == [], operations
    if needs_load:
        assert operations[calls[0]]["opcode"] == PcodeOp.CALLIND, operations
        assert any(op["opcode"] == PcodeOp.LOAD for op in operations[:calls[0]]), operations


try:
    tx = program.startTransaction("authentic CALL_RETURN producer fixtures")
    try:
        # Branch 0: direct CALL at 1004. Branch 1: initialize RAX with the pointer
        # slot's address, then CALL [RAX] at 102a. Unlike a static RIP-relative
        # memory read (COPY from RAM), this requires a real dynamic-address LOAD.
        body = (bytes.fromhex("85ff741ce8f70f0000c3") + b"\x90" * 22 +
                bytes.fromhex("48b80030000000000000ff10c3"))
        memory(0x1000, body, "two_override_sites")
        memory(0x1100, bytes.fromhex("ccc3"), "authored_int3")
        memory(0x1200, bytes.fromhex("c3"), "ordinary_ret")
        memory(0x2000, bytes.fromhex("b807000000c3"), "real_target")
        memory(0x3000, (0x2000).to_bytes(8, "little"), "real_target_pointer", False)
        mixed = create_function(0x1000, "two_override_sites")
        trap = create_function(0x1100, "authored_int3")
        ordinary = create_function(0x1200, "ordinary_ret")
        target = create_function(0x2000, "real_target")
        mixed.updateFunction("__stdcall", ReturnParameterImpl(IntegerDataType.dataType, program),
                             Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS, False,
                             SourceType.USER_DEFINED,
                             JArray(Variable)([ParameterImpl("which", IntegerDataType.dataType, program)]))
    finally:
        program.endTransaction(tx, True)

    # Stock receives the actual installed producer's instruction overrides.
    source_before = snapshot({"mixed": mixed, "trap": trap, "ordinary": ordinary, "target": target})
    factory.set(None, None)
    interface = DecompInterface()
    assert interface.setOptions(DecompileOptions())
    assert interface.openProgram(program), str(interface.getLastMessage())
    report["interface_class"] = str(interface.getClass().getName())
    assert report["interface_class"] == "ghidra.app.decompiler.DecompInterface"
    for phase, override in (("baseline", FlowOverride.NONE),
                            ("active", FlowOverride.CALL_RETURN),
                            ("removed", FlowOverride.NONE)):
        tx = program.startTransaction(phase)
        try:
            for site in (0x1004, 0x102a):
                program.getListing().getInstructionAt(address(site)).setFlowOverride(override)
        finally:
            program.endTransaction(tx, True)
        interface.flushCache()
        row = {"phase": phase, "core": "stock", "instructions": {}}
        report["rows"].append(row)
        revision = int(program.getModificationNumber())
        result = interface.decompileFunction(mixed, 60, monitor)
        row["completed"] = bool(result.decompileCompleted())
        row["error"] = str(result.getErrorMessage())
        assert row["completed"], row
        assert result.getHighFunction() is not None and result.getCCodeMarkup() is not None
        assert snapshot({"mixed": mixed, "trap": trap, "ordinary": ordinary, "target": target}) == source_before
        row["c"] = str(result.getDecompiledFunction().getC())
        assert "two_override_sites" in row["c"]
        (output / f"{phase}-stock.c").write_text(row["c"])
        for site in (0x1004, 0x102a, 0x1100, 0x1200):
            ops = capture(site, phase)
            row["instructions"][f"{site:x}"] = ops
            if site in (0x1004, 0x102a):
                assert_source_flow(ops, phase == "active", needs_load=site == 0x102a)
            if site == 0x1100:
                assert program.getListing().getInstructionAt(address(site)).getFlowOverride() == FlowOverride.NONE
                assert any(op["opcode"] == PcodeOp.CALLOTHER for op in ops), ops
                assert any(op["opcode"] == PcodeOp.CALLIND for op in ops), ops
                assert any(op["opcode"] == PcodeOp.RETURN for op in ops), ops
            if site == 0x1200:
                assert program.getListing().getInstructionAt(address(site)).getFlowOverride() == FlowOverride.NONE
                assert any(op["opcode"] == PcodeOp.RETURN for op in ops), ops
        assert int(program.getModificationNumber()) == revision, "Acquisition edited source"
        row["source_unchanged"] = True
        row["passed"] = True
    report["passed"] = True
except BaseException:
    report["failure"] = traceback.format_exc()
    raise
finally:
    if interface is not None:
        interface.dispose()
    factory.set(None, original_factory)
    program.release(owner)
    (output / "report.json").write_text(json.dumps(report, indent=2))
