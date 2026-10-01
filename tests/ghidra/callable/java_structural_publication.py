#!/usr/bin/env python3
"""Actual markerless structural descendants under a genuine host Node receipt."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import traceback

root = Path(__file__).resolve().parent
sys.path.insert(0, str(root.parents[2] / "tests" / "ghidra"))
from whole_calls import Machine
from kuna_vs_stock import get_exepath_field
output = Path(os.environ["KUNA_SMOKE_OUT"]).resolve()
output.mkdir(parents=True, exist_ok=False)
executable = Path(os.environ["KUNA_GHIDRA_EXE"]).resolve()
report = {"passed": False, "scope": "actual native Node pointer/array/callback/void descendant publication, unchanged ordinary CppExporter output; Java retained-result stale revision rejection only, not native reverse-invalidation proof", "native": str(executable), "native_sha256": hashlib.sha256(executable.read_bytes()).hexdigest()}
values = [0, 85, 0x10055, -7, 0x7fffffff, -0x80000000]
machine = None
field = None
original = None
publication = None


def save():
    (output / "structural_publisher.json").write_text(json.dumps(report, indent=2) + "\n")


try:
    # mov rax,[rdi]; mov eax,[rax]; ret: exactly load the int addressed by node.p.
    code = bytes.fromhex("488b078b00c3")
    machine = Machine(code, [("load_node", 0x1000, code, "int load_node(Node *node)")])
    from jpype import JArray, JByte
    from java.io import File, IOException
    from java.math import BigInteger
    from ghidra.app.decompiler import CallableSupport, DecompInterface, DecompileOptions
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
        assert result.getCallableSupport().isPresent()
        support = result.getCallableSupport().get()
        report["support_status"] = str(support.getStatus())
        report["support_reason"] = str(support.getReason())
        save()
        assert str(support.getStatus()) == "COMPLETE", str(support.getReason())
        publication = CallableSupport.Publication()
        publication.add(support)
        publication.validate()
        publication.sourceOwnership(PcodeDataTypeManager(program, IllegalCharCppTransformer()))
    finally:
        interface.dispose()

    exporter = CppExporter(options, True, True, True, True, False, "")
    assert exporter.export(File(str(output / "node.c")), program, None, ConsoleTaskMonitor()), "Actual structural publication rejected"
    driver = output / "driver.c"
    driver.write_text('''#include "node.h"
int main(void) {
    const int values[] = {0, 85, 0x10055, -7, 0x7fffffff, (-0x7fffffff - 1)};
    Node node = {0};
    for (unsigned int i = 0; i < sizeof(values)/sizeof(values[0]); ++i) {
        int value = values[i];
        node.p = &value;
        if (load_node(&node) != value) return 1;
    }
    return 0;
}
''')
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
    rejection = None
    try:
        publication.sourceOwnership(PcodeDataTypeManager(program, IllegalCharCppTransformer()))
    except IOException as error:
        rejection = str(error)
    assert rejection is not None, "Retained genuine support must reject nested-child source edit"
    report["retained_support_child_edit"] = {"before_revision": original_revision, "after_revision": int(program.getModificationNumber()), "old_callback_return_size": 4, "new_callback_return_size": 8, "outer_function_signature_unchanged": True, "rejected": True, "diagnostic": rejection}
    report["passed"] = True
except BaseException:
    report["failure"] = traceback.format_exc()
    raise
finally:
    if publication is not None:
        publication.close()
    if field is not None:
        field.set(None, original)
    if machine is not None:
        machine.close()
    save()
