#!/usr/bin/env python3
"""Actual public Node/union/aggregate/bitfield consumers and recursive source edits."""
import json
import os
from pathlib import Path
import re
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
report = {"passed": False, "scope": "actual Node, union, partial aggregate and bitfield-alias public C/High/markup/export consumers; fresh source edits across flush/reset/reopen and genuine packed source fixtures", "native": str(executable)}
values = [0, 85, 0x10055, -7, 0x7fffffff, -0x80000000]
machine = None
field = None
original = None


def save():
    (output / "structural_publisher.json").write_text(json.dumps(report, indent=2) + "\n")


def mutation_matrix():
    """Consume actual host child edits through fresh public results and export."""
    from java.io import ByteArrayOutputStream
    from ghidra.program.model.data import (CategoryPath, TypedefDataType, UnionDataType,
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
        retained = []
        row = {"case": kind, "epochs": [{"epoch": epoch, "status": "unexecuted"}
               for epoch in ("initial", "edited_flush", "reset", "reopen")]}
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
            for epoch in ("initial", "edited_flush", "reset", "reopen"):
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
                for name, ty in (("record", record), ("aggregate", aggregate)):
                    wire = XmlEncode()
                    identities.encodeCompositePlaceholder(wire, ty)
                    (directory / (epoch + "-" + name + "-placeholder.xml")).write_text(str(wire))
                    packed = ByteArrayOutputStream()
                    identities.encodeCompositePlaceholder(PackedEncode(packed), ty)
                    (directory / (epoch + "-" + name + "-placeholder.packed")).write_bytes(
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
            for epoch in ("initial", "edited_flush", "reset", "reopen"):
                observed = next(phase for phase in row["epochs"] if phase["epoch"] == epoch)
                observed["status"] = "running"
                if epoch == "edited_flush":
                    edit_source(True)
                    interface.flushCache()
                elif epoch == "reset":
                    interface.resetDecompiler()
                elif epoch == "reopen":
                    interface.closeProgram()
                    assert interface.openProgram(program), str(interface.getLastMessage())
                result = interface.decompileFunction(function, 120, fixture.monitor)
                assert result.decompileCompleted(), str(result.getErrorMessage())
                assert result.getCCodeMarkup() is not None
                retained.append((str(result.getDecompiledFunction().getC()), result))
                identities = PcodeDataTypeManager(program, IllegalCharCppTransformer())
                actual = result.getHighFunction().getFunctionPrototype().getParam(0).getDataType()
                referent = actual if kind == "partial" else actual.getDataType()
                assert int(manager.getID(referent)) == ids["source"]
                assert referent.isEquivalent(source)
                expected_field = "high" if epoch == "initial" else "upper"
                if kind != "bitfield_alias":
                    assert str(record.getComponentAt(4).getFieldName()) == expected_field
                assert word.getDataType().isSigned() == (epoch != "initial")
                header_path = directory / (epoch + ".h")
                body_path = directory / (epoch + ".c")
                driver_path = directory / (epoch + "-driver.c")
                assert export_program(program, body_path, options=options)
                header_text = header_path.read_text()
                assert "WordAlias" in header_text and "SourceAlias" in header_text
                word_declarations = re.findall(r'(?m)^typedef[^\n;]*\bWordAlias\s*;', header_text)
                assert len(word_declarations) == 1, word_declarations
                if epoch == "initial":
                    initial_word_declaration = word_declarations[0]
                else:
                    assert word_declarations[0] != initial_word_declaration, "Same-ID signedness edit lost from fresh H"
                if kind != "bitfield_alias":
                    assert expected_field in header_text
                    assert ("upper" if epoch == "initial" else "high") not in header_text
                if kind == "union":
                    assert ("whole" if epoch == "initial" else "signed_whole") in header_text
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
                # Retained Java results must remain readable after native reset.
                for old_c, old in retained:
                    assert old.getHighFunction() is not None
                    assert str(old.getDecompiledFunction().getC()) == old_c
                    assert old.getCCodeMarkup() is not None
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
    from java.io import File
    from java.math import BigInteger
    from ghidra.app.decompiler import DecompInterface, DecompileOptions
    from ghidra.app.util.exporter import CppExporter
    from ghidra.program.flatapi import FlatProgramAPI
    from ghidra.program.model.data import ArrayDataType, DataTypeConflictHandler, FunctionDefinitionDataType, IntegerDataType, LongLongDataType, ParameterDefinition, ParameterDefinitionImpl, PointerDataType, StructureDataType, VoidDataType
    from ghidra.program.model.listing import Function, ParameterImpl, ReturnParameterImpl, Variable
    from ghidra.program.model.pcode import PcodeDataTypeManager
    from ghidra.program.model.symbol import IllegalCharCppTransformer, SourceType
    from ghidra.util.task import ConsoleTaskMonitor

    field = get_exepath_field()
    original = field.get(None)
    field.set(None, str(executable))
    mutation_matrix()
    # mov rax,[rdi]; mov eax,[rax]; ret: exactly load the int addressed by node.p.
    code = bytes.fromhex("488b078b00c3")
    machine = Machine(code, [("load_node", 0x1000, code, "int load_node(Node *node)")])
    program = machine.program
    manager = program.getDataTypeManager()
    api = FlatProgramAPI(program, machine.monitor)
    convention = str(program.getCompilerSpec().getDefaultCallingConvention().getName())
    transaction = program.startTransaction("Actual source Node with inline structural descendants")
    try:
        callback = FunctionDefinitionDataType("NestedCallback", manager)
        callback.setCallingConvention(convention)
        callback.setReturnType(IntegerDataType.dataType)
        callback.setArguments(JArray(ParameterDefinition)([ParameterDefinitionImpl("value", IntegerDataType.dataType, None)]))
        node = StructureDataType("Node", 40, manager)
        node.replaceAtOffset(0, PointerDataType(IntegerDataType.dataType, manager), 8, "p", None)
        node.replaceAtOffset(8, ArrayDataType(IntegerDataType.dataType, 3, 4, manager), 12, "values", None)
        node.replaceAtOffset(24, PointerDataType(callback, manager), 8, "callback", None)
        node.replaceAtOffset(32, PointerDataType(VoidDataType.dataType, manager), 8, "opaque", None)
        node = manager.resolve(node, DataTypeConflictHandler.DEFAULT_HANDLER)
        callback = node.getComponentAt(24).getDataType().getDataType()
        assert int(callback.getReturnType().getLength()) == 4
        function = api.createFunction(machine.address(0x1000), "load_node")
        assert function is not None
        function.updateFunction(convention, ReturnParameterImpl(IntegerDataType.dataType, program), Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS, False, SourceType.USER_DEFINED, JArray(Variable)([ParameterImpl("node", PointerDataType(node, manager), program)]))
    finally:
        program.endTransaction(transaction, True)

    machine_rows = []
    report["machine"] = machine_rows
    for value in values:
        emulator = machine.EmulatorHelper(program)
        try:
            emulator.writeMemory(machine.address(0x7100), JArray(JByte)((0x7200).to_bytes(8, "little") + bytes(32)))
            emulator.writeMemory(machine.address(0x7200), JArray(JByte)((value & 0xffffffff).to_bytes(4, "little")))
            # SysV x86-64 entry: return address occupies eight bytes, RSP%16==8.
            emulator.writeMemory(machine.address(0x7fd8), JArray(JByte)((0x7ff0).to_bytes(8, "little")))
            emulator.writeRegister("RDI", BigInteger(str(0x7100)))
            emulator.writeRegister("RSP", BigInteger(str(0x7fd8)))
            emulator.setBreakpoint(machine.address(0x7ff0))
            assert emulator.run(machine.address(0x1000), None, machine.monitor), str(emulator.getLastError())
            actual = int(str(emulator.readRegister("RAX"))) & 0xffffffff
            assert actual == (value & 0xffffffff), (value, actual)
            assert emulator.getExecutionAddress() == machine.address(0x7ff0)
            assert int(str(emulator.readRegister("RSP"))) == 0x7fe0
            machine_rows.append({"input": value, "actual_u32": actual, "entry_rsp": 0x7fd8, "final_rsp": 0x7fe0})
        finally:
            emulator.dispose()
    save()

    options = DecompileOptions()
    interface = DecompInterface()
    try:
        interface.setOptions(options)
        assert interface.openProgram(program), str(interface.getLastMessage())
        result = interface.decompileFunction(function, 120, machine.monitor)
        assert result.decompileCompleted(), str(result.getErrorMessage())
        assert result.getHighFunction() is not None and result.getCCodeMarkup() is not None
        parameter = result.getHighFunction().getFunctionPrototype().getParam(0)
        assert parameter.getDataType().getDataType().isEquivalent(node)
        old_result = result
        old_code = str(result.getDecompiledFunction().getC())
    finally:
        interface.dispose()

    exporter = CppExporter(options, True, True, True, True, False, "")
    assert exporter.export(File(str(output / "node.c")), program, None, ConsoleTaskMonitor()), "Actual structural publication rejected"
    driver = output / "driver.c"
    driver_body = '''int main(void) {
    const int values[] = {0, 85, 0x10055, -7, 0x7fffffff, (-0x7fffffff - 1)};
    Node node = {0};
    for (unsigned int i = 0; i < sizeof(values)/sizeof(values[0]); ++i) {
        int value = values[i];
        node.p = &value;
        if (load_node(&node) != value) return 1;
    }
    return 0;
}
'''
    driver.write_text('#include "node.h"\n'
        '_Static_assert(_Generic(((Node *)0)->callback, int (*)(int): 1, default: 0), '
        '"Original callback is int(int)");\n' + driver_body)
    executions = []
    report["execution"] = executions
    for optimization in ("-O0", "-O2"):
        binary = output / ("node" + optimization)
        command = [os.environ.get("CC", "cc"), "-std=c11", "-Wall", "-Werror=uninitialized", "-Werror=incompatible-pointer-types", "-Werror=implicit-function-declaration", optimization, str(output / "node.c"), str(driver), "-o", str(binary)]
        built = subprocess.run(command, capture_output=True, text=True, timeout=120)
        row = {"optimization": optimization, "command": command, "compile_exit": built.returncode, "stdout": built.stdout, "stderr": built.stderr}
        executions.append(row)
        save()
        assert built.returncode == 0, row
        ran = subprocess.run([str(binary)], capture_output=True, text=True, timeout=30)
        row.update({"execution_exit": ran.returncode, "execution_stdout": ran.stdout, "execution_stderr": ran.stderr})
        save()
        assert ran.returncode == 0, row

    original_revision = int(program.getModificationNumber())
    original_signature = str(function.getSignature())
    transaction = program.startTransaction("Edit the actual nested callback child, retaining previous result")
    try:
        callback.setReturnType(LongLongDataType.dataType)
        assert int(node.getComponentAt(24).getDataType().getDataType().getReturnType().getLength()) == 8
    finally:
        program.endTransaction(transaction, True)
    assert int(program.getModificationNumber()) != original_revision
    assert str(function.getSignature()) == original_signature
    interface = DecompInterface()
    try:
        assert interface.openProgram(program), str(interface.getLastMessage())
        report["node_source_epochs"] = []
        for epoch in ("edited_flush", "reset", "reopen"):
            if epoch == "edited_flush":
                interface.flushCache()
            elif epoch == "reset":
                interface.resetDecompiler()
            else:
                interface.closeProgram()
                assert interface.openProgram(program), str(interface.getLastMessage())
            revision = int(program.getModificationNumber())
            fresh = interface.decompileFunction(function, 120, machine.monitor)
            assert fresh.decompileCompleted(), str(fresh.getErrorMessage())
            decoded_node = fresh.getHighFunction().getFunctionPrototype().getParam(0).getDataType().getDataType()
            assert decoded_node.getComponentAt(24).getDataType().getDataType().getReturnType().getLength() == 8
            assert fresh.getCCodeMarkup() is not None
            assert old_result.getHighFunction() is not None
            assert str(old_result.getDecompiledFunction().getC()) == old_code
            assert old_result.getCCodeMarkup() is not None
            destination = output / ("node-" + epoch + ".c")
            assert export_program(program, destination, options=options)
            header = destination.with_suffix(".h")
            assert header.read_text() != (output / "node.h").read_text(), "Nested callback edit lost from fresh source declarations"
            edited_driver = output / ("node-" + epoch + "-driver.c")
            edited_driver.write_text('#include "' + header.name + '"\n'
                '_Static_assert(_Generic(((Node *)0)->callback, longlong (*)(int): 1, default: 0), '
                '"Edited callback is longlong(int)");\n' + driver_body)
            for optimization in ("-O0", "-O2"):
                binary = output / ("node-" + epoch + optimization)
                built = subprocess.run([os.environ.get("CC", "cc"), "-std=c11", "-Wall",
                    "-Werror=incompatible-pointer-types", "-Werror=implicit-function-declaration",
                    optimization, str(destination), str(edited_driver), "-o", str(binary)],
                    capture_output=True, text=True, timeout=120)
                assert built.returncode == 0, built.stderr
                ran = subprocess.run([str(binary)], capture_output=True, text=True, timeout=30)
                assert ran.returncode == 0, ran.stderr
            assert int(program.getModificationNumber()) == revision
            assert str(function.getSignature()) == original_signature
            report["node_source_epochs"].append({"epoch": epoch, "callback_return_size": 8,
                                                 "old_result_readable": True, "source_unchanged": True})
    finally:
        interface.dispose()
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
