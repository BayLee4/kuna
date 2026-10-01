#!/usr/bin/env python3
"""Observe the real installed callback and stock-native ordinary DecompInterface.

Run in a fresh JVM with GHIDRA_INSTALL_DIR pointing at KunaIntegratedInstall output:
  <venv>/bin/python tests/ghidra/callable/java_producer.py <output-directory>
This exercises the actual integrated producer, not an alternative encoder or decoder.
"""
import json
import os
from pathlib import Path
import sys
import traceback

import pyghidra

output = Path(sys.argv[1] if len(sys.argv) > 1 else os.environ["KUNA_SMOKE_OUT"])
output.mkdir(parents=True, exist_ok=True)
report = {"installation": os.environ["GHIDRA_INSTALL_DIR"], "rows": []}
pyghidra.start()
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
        origin = None
        while True:
            attribute = decoder.getNextAttributeId()
            if attribute == 0:
                break
            # Actual wire CODE id, not an inferred operation mnemonic.
            if attribute == 43:
                opcode = int(decoder.readSignedInteger())
            elif attribute == 4002:
                origin = int(decoder.readUnsignedInteger())
        decoder.closeElementSkipping(op_element)
        assert opcode is not None, (label, site)
        operations.append({"opcode": opcode, "callreturn_origin": origin})
    decoder.closeElement(root)
    return operations


def assert_origin(operations, marked, needs_load=False):
    origins = [(i, op["callreturn_origin"]) for i, op in enumerate(operations)
               if op["callreturn_origin"] is not None]
    if not marked:
        assert origins == [], operations
        return
    assert len(origins) == 1, operations
    ret_index, call_index = origins[0]
    assert 0 <= call_index < ret_index, operations
    assert operations[ret_index]["opcode"] == PcodeOp.RETURN, operations
    assert operations[call_index]["opcode"] in (PcodeOp.CALL, PcodeOp.CALLIND), operations
    if needs_load:
        assert any(op["opcode"] == PcodeOp.LOAD for op in operations[:call_index]), operations


try:
    expected_jar = Path(report["installation"]).resolve() / "Ghidra/patch/kuna-ghidra-producer.jar"
    report["class_origins"] = {}
    for cls in (PcodeEmit, PcodeEmitPacked):
        origin = Path(str(cls.class_.getProtectionDomain().getCodeSource().getLocation().toURI().getPath())).resolve()
        report["class_origins"][str(cls.class_.getName())] = str(origin)
        assert origin == expected_jar, (origin, expected_jar)

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

    # Use the stock native binary through the unchanged, ordinary interface. The
    # installed producer still emits attributes; stock must ignore them successfully.
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
        result = interface.decompileFunction(mixed, 60, monitor)
        row["completed"] = bool(result.decompileCompleted())
        row["error"] = str(result.getErrorMessage())
        assert row["completed"], row
        row["c"] = str(result.getDecompiledFunction().getC())
        (output / f"{phase}-stock.c").write_text(row["c"])
        for site in (0x1004, 0x102a, 0x1100, 0x1200):
            ops = capture(site, phase)
            row["instructions"][f"{site:x}"] = ops
            assert_origin(ops, phase == "active" and site in (0x1004, 0x102a),
                          needs_load=site == 0x102a)
            if site == 0x1100:
                assert any(op["opcode"] == PcodeOp.CALLIND for op in ops), ops
                assert any(op["opcode"] == PcodeOp.RETURN for op in ops), ops
            if site == 0x1200:
                assert any(op["opcode"] == PcodeOp.RETURN for op in ops), ops
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
