#!/usr/bin/env python3
"""Actual public Node/union/aggregate/bitfield consumers and recursive source edits."""
import json
import os
from pathlib import Path
import subprocess
import sys
import traceback

root = Path(__file__).resolve().parent
sys.path.insert(0, str(root.parents[2] / "tests" / "ghidra"))
from whole_calls import Machine
from kuna_vs_stock import KUNA_GHIDRA, get_exepath_field, export_program, start_ghidra
output = Path(os.environ["KUNA_SMOKE_OUT"]).resolve()
output.mkdir(parents=True, exist_ok=True)
executable = Path(KUNA_GHIDRA).resolve()
report = {"passed": False, "scope": "actual union, partial aggregate and bitfield-alias source-edit public C/High/markup/export consumers", "native": str(executable)}
machine = None
field = None
original = None


def save():
    (output / "structural_publisher.json").write_text(json.dumps(report, indent=2) + "\n")


def mutation_matrix():
    """Consume actual host child edits through fresh public results and export."""
    from java.io import ByteArrayOutputStream, StringWriter
    from ghidra.program.model.data import (CategoryPath, DataTypeWriter, TypedefDataType, UnionDataType,
                                         UnsignedIntegerDataType, UnsignedLongLongDataType)
    from ghidra.program.model.pcode import PackedEncode, XmlEncode

    rows = report["mutations"] = []
    for kind, code in (("union", "8b4704c3"), ("partial", "4889f848c1e820c3"),
                       ("bitfield_alias", "8b07c1e80325ff000000c3")):
        code = bytes.fromhex(code)
        fixture = Machine(code, [("read_value", 0x1000, code, "unsigned read_value(void *value)")])
        program = fixture.program
        manager = program.getDataTypeManager()
        api = FlatProgramAPI(program, fixture.monitor)
        interface = DecompInterface()
        row = {"case": kind, "epochs": [{"epoch": epoch, "status": "unexecuted"}
               for epoch in ("initial", "edited_flush")]}
        rows.append(row)
        directory = output / kind
        directory.mkdir(exist_ok=True)
        try:
            tx = program.startTransaction("Managed aggregate and alias sources")
            try:
                word = manager.resolve(TypedefDataType(CategoryPath.ROOT, "WordAlias", UnsignedIntegerDataType.dataType,
                                                       manager), DataTypeConflictHandler.DEFAULT_HANDLER)
                record = StructureDataType("Record", 4 if kind == "bitfield_alias" else 8, manager)
                if kind == "bitfield_alias":
                    record.insertBitFieldAt(0, 4, 3, word, 8, "middle", None)
                else:
                    record.replaceAtOffset(0, word, 4, "low", None)
                    record.replaceAtOffset(4, word, 4, "high", None)
                record = manager.resolve(record, DataTypeConflictHandler.DEFAULT_HANDLER)
                if kind == "union":
                    aggregate = UnionDataType(CategoryPath.ROOT, "Choice", manager)
                    aggregate.add(record, "parts", None)
                    aggregate.add(UnsignedLongLongDataType.dataType, "whole", None)
                    aggregate = manager.resolve(aggregate, DataTypeConflictHandler.DEFAULT_HANDLER)
                else:
                    aggregate = record
                source = manager.resolve(TypedefDataType(CategoryPath.ROOT, "SourceAlias", aggregate, manager),
                                         DataTypeConflictHandler.DEFAULT_HANDLER)
                callback = FunctionDefinitionDataType("MutationCallback", manager)
                callback.setCallingConvention("__stdcall")
                callback.setReturnType(UnsignedIntegerDataType.dataType)
                callback.setArguments(JArray(ParameterDefinition)([
                    ParameterDefinitionImpl("value", source, None)]))
                callback = manager.resolve(callback, DataTypeConflictHandler.DEFAULT_HANDLER)
                parameter = source if kind == "partial" else PointerDataType(source, manager)
                function = api.createFunction(fixture.address(0x1000), "read_value")
                function.updateFunction("__stdcall", ReturnParameterImpl(UnsignedIntegerDataType.dataType, program),
                    Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS, False, SourceType.USER_DEFINED,
                    JArray(Variable)([ParameterImpl("value", parameter, program)]))
            finally:
                program.endTransaction(tx, True)
            ids = {name: int(manager.getID(ty)) for name, ty in
                   (("word", word), ("record", record), ("source", source))}
            def edit_source(edited):
                tx = program.startTransaction("Same-width nested source correction")
                try:
                    base = IntegerDataType.dataType if edited else UnsignedIntegerDataType.dataType
                    word.replaceWith(TypedefDataType(CategoryPath.ROOT, "WordAlias", base, manager))
                    if kind != "bitfield_alias":
                        record.getComponentAt(4).setFieldName("upper" if edited else "high")
                    if kind == "union":
                        aggregate.getComponent(1).setFieldName("signed_whole" if edited else "whole")
                finally:
                    program.endTransaction(tx, True)
                assert ids == {name: int(manager.getID(ty)) for name, ty in
                               (("word", word), ("record", record), ("source", source))}

            row["source_epochs"] = []
            for epoch in ("initial", "edited_flush"):
                if epoch == "edited_flush":
                    edit_source(True)
                identities = PcodeDataTypeManager(program, IllegalCharCppTransformer())
                for name, ty in (("word", word), ("record", record), ("aggregate", aggregate),
                                 ("source", source), ("callback", callback)):
                    wire = XmlEncode()
                    identities.encodeType(wire, ty, ty.getLength())
                    (directory / (epoch + "-" + name + ".xml")).write_text(str(wire))
                    packed = ByteArrayOutputStream()
                    identities.encodeType(PackedEncode(packed), ty, ty.getLength())
                    (directory / (epoch + "-" + name + ".packed")).write_bytes(
                        bytes((int(value) & 255) for value in packed.toByteArray()))
                row["source_epochs"].append({"epoch": epoch, "committed_source_ids": ids,
                                             "revision": int(program.getModificationNumber()),
                                             "produced": True})
                save()
            edit_source(False)
            row["machine"] = []
            for raw in (0, 0xffffffffffffffff, 0x80000000ffffffff, 0x7fffffff00000000,
                        0x12345678a5a5a5a5, 0x800, 0x7f8):
                emulator = fixture.EmulatorHelper(program)
                try:
                    emulator.writeMemory(fixture.address(0x7100), JArray(JByte)(raw.to_bytes(8, "little")))
                    emulator.writeMemory(fixture.address(0x7fd8), JArray(JByte)((0x7ff0).to_bytes(8, "little")))
                    emulator.writeRegister("RDI", BigInteger(str(raw if kind == "partial" else 0x7100)))
                    emulator.writeRegister("RSP", BigInteger(str(0x7fd8)))
                    emulator.setBreakpoint(fixture.address(0x7ff0))
                    assert emulator.run(fixture.address(0x1000), None, fixture.monitor), str(emulator.getLastError())
                    actual = int(str(emulator.readRegister("RAX"))) & 0xffffffff
                    expected = (raw >> 3) & 255 if kind == "bitfield_alias" else raw >> 32
                    assert actual == expected, (kind, raw, actual, expected)
                    assert emulator.getExecutionAddress() == fixture.address(0x7ff0)
                    row["machine"].append({"raw": raw, "result": actual})
                finally:
                    emulator.dispose()
            options = DecompileOptions()
            options.setBitfieldAccess(True)
            interface.setOptions(options)
            assert interface.openProgram(program), str(interface.getLastMessage())
            for epoch in ("initial", "edited_flush"):
                observed = next(phase for phase in row["epochs"] if phase["epoch"] == epoch)
                observed["status"] = "running"
                if epoch == "edited_flush":
                    edit_source(True)
                    interface.flushCache()
                result = interface.decompileFunction(function, 120, fixture.monitor)
                assert result.decompileCompleted(), str(result.getErrorMessage())
                assert result.getCCodeMarkup() is not None
                identities = PcodeDataTypeManager(program, IllegalCharCppTransformer())
                actual = result.getHighFunction().getFunctionPrototype().getParam(0).getDataType()
                referent = actual if kind == "partial" else actual.getDataType()
                assert int(manager.getID(referent)) == ids["source"]
                header_path = directory / (epoch + ".h")
                body_path = directory / (epoch + ".c")
                driver_path = directory / (epoch + "-driver.c")
                assert export_program(program, body_path, options=options)
                include = f'#include "{header_path.name}"\n'
                expression = "read_value(value)" if kind == "partial" else "read_value(&value)"
                expected = "((unsigned)(raw >> 3) & 255)" if kind == "bitfield_alias" else "(unsigned)(raw >> 32)"
                driver_path.write_text(include + "#include <string.h>\n" + f"""
int main(void) {{
    const unsigned long long inputs[] = {{0, 0xffffffffffffffffULL, 0x80000000ffffffffULL,
        0x7fffffff00000000ULL, 0x12345678a5a5a5a5ULL, 0x800, 0x7f8}};
    for (unsigned i=0; i<sizeof(inputs)/sizeof(inputs[0]); ++i) {{
        unsigned long long raw=inputs[i];
        SourceAlias value;
        memcpy(&value, &raw, sizeof(value));
        if ({expression} != {expected}) return 1;
    }}
    return 0;
}}
""")
                observed.update(source_ids=ids, execution=[])
                for optimization in ("-O0", "-O2"):
                    binary = directory / (epoch + optimization)
                    command = [os.environ.get("CC", "cc"), "-std=c11", "-Wall", "-Werror", optimization,
                               str(body_path), str(driver_path), "-o", str(binary)]
                    built = subprocess.run(command, capture_output=True, text=True, timeout=120)
                    assert built.returncode == 0, built.stderr
                    ran = subprocess.run([str(binary)], capture_output=True, text=True, timeout=30)
                    assert ran.returncode == 0, (kind, epoch, optimization, ran.stderr)
                    observed["execution"].append(optimization)
                observed["status"] = "passed"
                save()
            row["passed"] = True
            print("PASS source mutation: " + kind, flush=True)
        except Exception:
            row["passed"] = False
            row["failure"] = traceback.format_exc()
            for phase in row["epochs"]:
                if phase["status"] == "running":
                    phase.update(status="failed", failure=row["failure"])
            print("FAIL source mutation: " + kind + "\n" + row["failure"], flush=True)
        finally:
            interface.dispose()
            fixture.close()
            save()


try:
    start_ghidra()
    from jpype import JArray, JByte
    from java.math import BigInteger
    from ghidra.app.decompiler import DecompInterface, DecompileOptions
    from ghidra.program.flatapi import FlatProgramAPI
    from ghidra.program.model.data import DataTypeConflictHandler, FunctionDefinitionDataType, IntegerDataType, ParameterDefinition, ParameterDefinitionImpl, PointerDataType, StructureDataType
    from ghidra.program.model.listing import Function, ParameterImpl, ReturnParameterImpl, Variable
    from ghidra.program.model.pcode import PcodeDataTypeManager
    from ghidra.program.model.symbol import IllegalCharCppTransformer, SourceType
    from ghidra.util.task import ConsoleTaskMonitor

    field = get_exepath_field()
    original = field.get(None)
    field.set(None, str(executable))
    mutation_matrix()
    report["passed"] = all(row.get("passed") for row in report["mutations"])
    assert report["passed"], "Mutation consumers failed; source snapshots remain available"
except BaseException:
    report["failure"] = traceback.format_exc()
    raise
finally:
    if field is not None:
        field.set(None, original)
    if machine is not None:
        machine.close()
    save()
