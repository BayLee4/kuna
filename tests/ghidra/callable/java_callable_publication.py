#!/usr/bin/env python3
"""Actual Kuna result/publication and ordinary CppExporter; unchanged emitted C."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import traceback

root = Path(__file__).resolve().parent
repo = root.parents[2]
sys.path.insert(0, str(repo / "tests" / "ghidra"))
from whole_calls import fixture, Machine
from kuna_vs_stock import KUNA_GHIDRA, get_exepath_field, export_program, start_ghidra

output = Path(os.environ["KUNA_SMOKE_OUT"]).resolve()
output.mkdir(parents=True, exist_ok=True)
executable = Path(KUNA_GHIDRA).resolve()
assert executable.is_file(), executable
report = {"passed": False, "scope": "unmodified Java C/High/markup, selected public export and ordinary CppExporter; unchanged emitted C/header execution", "native": str(executable), "native_sha256": hashlib.sha256(executable.read_bytes()).hexdigest(), "rows": []}


def save():
    (output / "native_publisher.json").write_text(json.dumps(report, indent=2) + "\n")


def compile_run(stem, whole):
    body = """
int main(void) {
    const unsigned long long uppers[] = {0, 0x10000ULL, 0x1234567800000000ULL};
    if (choose(0) != choose(0) || choose(1) != choose(1) || choose(0) == choose(1)) return 10;
    for (unsigned int u=0; u<3; ++u) for (unsigned int low=0; low<256; ++low) {
        unsigned long long raw = uppers[u] | low;
        for (unsigned int which=0; which<2; ++which) {
            int expected = which ? ((unsigned int)raw == 85) : ((raw & 255) == 85);
            if (carry_dispatch(raw, which) != expected) return 11;
            if (carry_invoke(raw, choose(which)) != expected) return 12;
            if (dispatch((Flags)low, which) != (low == 85)) return 18;
            if (invoke((Flags)low, choose(which)) != (low == 85)) return 19;
        }
    }
"""
    if whole:
        body += """
    if (direct_dirty()!=0 || direct_clean()!=1 || ambient_dirty()!=0 || ambient_clean()!=1) return 13;
    if (bool_byte(0)!=0 || bool_byte(1)!=0) return 20;
    for (unsigned int u=0; u<3; ++u) for (unsigned int low=0; low<256; ++low) {
        unsigned long long raw = uppers[u] | low;
        int expected = (unsigned int)raw == 85;
        if (carry_ambient(raw)!=expected || wide_ambient(raw)!=expected) return 14;
        if (carry_bool(raw)!=((raw & 255)==85)) return 15;
    }
    if (sizeof(UnrelatedOnly) != 4) return 16;
    int inferred_fields[2] = {5,6};
    if (sum_fields((void *)inferred_fields) != 11) return 17;
"""
    body += "    return 0;\n}\n"
    driver = output / (stem + "-driver.c")
    driver.write_text('#include "' + stem + '.h"\n' + body)
    rows = []
    for optimization in ("-O0", "-O2"):
        binary = output / (stem + optimization)
        command = [os.environ.get("CC", "cc"), "-std=c11", "-Wall",
                   "-Werror=uninitialized", "-Werror=incompatible-pointer-types",
                   "-Werror=implicit-function-declaration", optimization,
                   str(output / (stem + ".c")), str(driver), "-o", str(binary)]
        built = subprocess.run(command, capture_output=True, text=True, timeout=120)
        row = {"optimization": optimization, "command": command, "compile_exit": built.returncode, "stdout": built.stdout, "stderr": built.stderr}
        rows.append(row)
        report[stem + "_execution"] = rows
        save()
        assert built.returncode == 0, row
        ran = subprocess.run([str(binary)], capture_output=True, text=True, timeout=30)
        row.update({"execution_exit": ran.returncode, "execution_stdout": ran.stdout, "execution_stderr": ran.stderr})
        save()
        assert ran.returncode == 0, row
    return rows


machine = None
field = None
original = None
try:
    start_ghidra()
    image, entries = fixture()
    inferred_bytes = bytes.fromhex("8b070fb6570401d0c3")
    entries.append(("sum_fields", 0x11e0, inferred_bytes, "independently inferred source"))
    image = image[:0x1e0] + inferred_bytes + image[0x1e0 + len(inferred_bytes):]
    machine = Machine(image, entries)
    from jpype import JArray, JObject
    from java.io import File, StringWriter
    from ghidra.app.decompiler import (ClangVariableToken, DecompInterface,
                                      DecompileOptions, DecompileProcess)
    from ghidra.app.util.exporter import CppExporter
    from ghidra.program.flatapi import FlatProgramAPI
    from ghidra.program.model.data import BooleanDataType, CategoryPath, DataTypeConflictHandler, FunctionDefinitionDataType, IntegerDataType, ParameterDefinition, ParameterDefinitionImpl, Pointer, PointerDataType, Structure, TypedefDataType, UnsignedCharDataType, UnsignedIntegerDataType, UnsignedLongLongDataType
    from ghidra.program.model.listing import Function, ParameterImpl, ReturnParameterImpl, Variable
    from ghidra.program.model.pcode import VarnodeAST
    from ghidra.program.model.symbol import SourceType
    from ghidra.util.task import ConsoleTaskMonitor

    field = get_exepath_field()
    original = field.get(None)
    field.set(None, str(executable))
    program = machine.program
    manager = program.getDataTypeManager()
    api = FlatProgramAPI(program, machine.monitor)
    convention = str(program.getCompilerSpec().getDefaultCallingConvention().getName())
    functions = {}
    transaction = program.startTransaction("Real narrow source signatures and compatible callback family")
    try:
        flags = manager.resolve(TypedefDataType(CategoryPath.ROOT, "Flags", UnsignedCharDataType.dataType, manager), DataTypeConflictHandler.DEFAULT_HANDLER)
        definition = FunctionDefinitionDataType("CallbackFunction", manager)
        definition.setCallingConvention(convention)
        definition.setReturnType(IntegerDataType.dataType)
        definition.setArguments(JArray(ParameterDefinition)([ParameterDefinitionImpl("value", flags, None)]))
        callback = manager.resolve(TypedefDataType(CategoryPath.ROOT, "Callback", PointerDataType(definition, manager), manager), DataTypeConflictHandler.DEFAULT_HANDLER)
        manager.resolve(TypedefDataType(CategoryPath.ROOT, "UnrelatedOnly", UnsignedIntegerDataType.dataType, manager), DataTypeConflictHandler.DEFAULT_HANDLER)
        for name, pc, _, _ in entries:
            address = machine.address(pc)
            function = program.getFunctionManager().getFunctionAt(address)
            if function is None:
                function = api.createFunction(address, name)
            assert function is not None, name
            function.setName(name, SourceType.USER_DEFINED)
            if name == "sum_fields":
                functions[name] = function
                continue  # No authored model, parameters or result facts.
            result = IntegerDataType.dataType
            params = []
            if name == "choose":
                result = callback
                params = [("which", UnsignedIntegerDataType.dataType)]
            elif name in ("byte_target", "word_target"):
                params = [("value", flags)]
            elif name == "invoke":
                params = [("value", flags), ("callback", callback)]
            elif name == "dispatch":
                params = [("value", flags), ("which", UnsignedIntegerDataType.dataType)]
            elif name == "bool_byte":
                params = [("value", BooleanDataType.dataType)]
            elif name == "wide_ambient":
                params = [("bits", UnsignedLongLongDataType.dataType)]
            elif name == "carry_dispatch":
                params = [("bits", UnsignedLongLongDataType.dataType),
                          ("which", UnsignedIntegerDataType.dataType)]
            elif name == "carry_invoke":
                params = [("bits", UnsignedLongLongDataType.dataType), ("callback", callback)]
            elif name in ("carry_ambient", "carry_bool"):
                params = [("bits", UnsignedLongLongDataType.dataType)]
            variables = JArray(Variable)([ParameterImpl(n, t, program) for n, t in params])
            function.updateFunction(convention, ReturnParameterImpl(result, program), Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS, False, SourceType.USER_DEFINED, variables)
            functions[name] = function
    finally:
        program.endTransaction(transaction, True)

    def source_snapshot():
        return {name: {"signature": str(fn.getSignature()), "return_storage": str(fn.getReturn().getVariableStorage()), "parameters": [{"name": str(p.getName()), "type": str(p.getDataType().getPathName()), "size": int(p.getDataType().getLength()), "storage": str(p.getVariableStorage())} for p in fn.getParameters()]} for name, fn in functions.items()}

    before = source_snapshot()
    report["source_before"] = before
    before_revision = int(program.getModificationNumber())
    options = DecompileOptions()
    interface = DecompInterface()
    try:
        interface.setOptions(options)
        assert interface.openProgram(program), str(interface.getLastMessage())
        result = interface.decompileFunction(functions["dispatch"], 120, machine.monitor)
        assert result.decompileCompleted(), str(result.getErrorMessage())
        fragment = result.getDecompiledFunction()
        assert fragment is not None
        high = result.getHighFunction()
        assert high is not None and result.getCCodeMarkup() is not None
        diagnostic_text = str(fragment.getC())
        prototype = high.getFunctionPrototype()
        assert prototype.getNumParams() == 2
        assert str(prototype.getParam(0).getName()) == "value"
        assert prototype.getParam(0).getDataType().isEquivalent(flags)
        bindings = []
        def visit(token):
            if isinstance(token, ClangVariableToken):
                varnode = token.getVarnode()
                if varnode is not None:
                    varnode = JObject(varnode, VarnodeAST)
                    assert high.getRef(varnode.getUniqueId()) == varnode
                    bindings.append({"text": str(token.getText()),
                                     "size": int(varnode.getSize())})
            for child in range(token.numChildren()):
                visit(token.Child(child))
        visit(result.getCCodeMarkup())
        assert bindings, "Current C document lost its same-document High value bindings"
        report["source_high_bindings"] = bindings
        for name, expected_type in (("invoke", flags), ("byte_target", flags),
                                    ("word_target", flags), ("bool_byte", BooleanDataType.dataType)):
            source_result = interface.decompileFunction(functions[name], 120, machine.monitor)
            assert source_result.decompileCompleted(), str(source_result.getErrorMessage())
            assert source_result.getCCodeMarkup() is not None
            source_param = source_result.getHighFunction().getFunctionPrototype().getParam(0)
            assert source_param.getDataType().isEquivalent(expected_type), name
        ambient_result = interface.decompileFunction(functions["ambient"], 120, machine.monitor)
        assert ambient_result.decompileCompleted(), str(ambient_result.getErrorMessage())
        assert ambient_result.getHighFunction().getFunctionPrototype().getNumParams() == 0
        assert interface.toggleSyntaxTree(False)
        notree = interface.decompileFunction(functions["dispatch"], 120, machine.monitor)
        assert notree.getHighFunction() is not None
        assert list(notree.getHighFunction().getPcodeOps()) == []
        assert notree.getCCodeMarkup() is not None
        assert str(notree.getDecompiledFunction().getC()) == diagnostic_text
        assert interface.toggleSyntaxTree(True)
        (output / "current-fragment.c").write_text(diagnostic_text)
        from ghidra.program.model.address import AddressSet
        selection = AddressSet()
        for name in ("dispatch", "choose", "invoke", "byte_target", "word_target",
                     "carry_dispatch", "carry_invoke"):
            selection.add(functions[name].getBody())
        assert export_program(program, output / "direct.c", selection=selection)
        repeated = interface.decompileFunction(functions["dispatch"], 120, machine.monitor)
        assert repeated.decompileCompleted(), str(repeated.getErrorMessage())
        assert str(repeated.getDecompiledFunction().getC()) == diagnostic_text
        assert source_snapshot() == before, "Export acquisition changed source authority"
    finally:
        interface.dispose()
    compile_run("direct", False)
    report["rows"].append({"surface": "selected_public_export", "passed": True})
    save()

    # Native inferred record fields must not enter Program source lookup.
    from error_recovery import field as java_field
    inferred_interface = DecompInterface()
    try:
        inferred_interface.setOptions(options)
        assert inferred_interface.openProgram(program)

        def inferred_result():
            result = inferred_interface.decompileFunction(functions["sum_fields"], 120, machine.monitor)
            assert result.decompileCompleted(), str(result.getErrorMessage())
            assert result.getCCodeMarkup() is not None
            prototype = result.getHighFunction().getFunctionPrototype()
            assert prototype.getNumParams() == 1
            pointer = JObject(prototype.getParam(0).getDataType(), Pointer)
            target = pointer.getDataType()
            assert target is not None and isinstance(target, Structure), str(target)
            record = JObject(target, Structure)
            components = [(int(component.getOffset()), int(component.getLength()),
                           str(component.getDataType().getName()))
                          for component in record.getDefinedComponents()]
            assert (0, 4) in [component[:2] for component in components], components
            assert (4, 1) in [component[:2] for component in components], components
            assert manager.getDataType(record.getDataTypePath()) is None, "Inferred declarations cannot edit source types"
            row = {"record": str(record.getName()), "size": int(record.getLength()),
                   "components": components, "c": str(result.getDecompiledFunction().getC())}
            report.setdefault("inferred_record_lifecycle", []).append(row)
            return result, row

        inferred, initial = inferred_result()
        for _ in range(3):
            independent, row = inferred_result()
            assert row == initial
        inferred_interface.flushCache()
        flushed, row = inferred_result()
        assert row == initial
        process_field = java_field(DecompInterface, "decompProcess")
        native_field = java_field(DecompileProcess, "nativeProcess")
        old_pid = int(native_field.get(process_field.get(inferred_interface)).pid())
        inferred_interface.resetDecompiler()
        fresh, row = inferred_result()
        new_pid = int(native_field.get(process_field.get(inferred_interface)).pid())
        assert old_pid != new_pid
        assert row == initial
        assert inferred.getHighFunction() is not None
        assert str(inferred.getDecompiledFunction().getC()) == initial["c"]
        report["inferred_record_worker_pids"] = [old_pid, new_pid]
    finally:
        inferred_interface.dispose()

    exporter = CppExporter(options, True, True, True, True, False, "")
    assert exporter.export(File(str(output / "whole.c")), program, None, ConsoleTaskMonitor()), "Actual CppExporter rejected native closure"
    assert (output / "whole.h").is_file()
    compile_run("whole", True)
    report["rows"].append({"surface": "ordinary_cpp_exporter", "passed": True})
    after = source_snapshot()
    report["source_after"] = after
    assert after == before, "Public export must not edit source function signatures/storage"
    assert int(program.getModificationNumber()) == before_revision, "Decompilation/export edited persistent source"
    report["passed"] = True
except BaseException:
    report["failure"] = traceback.format_exc()
    raise
finally:
    if field is not None:
        field.set(None, original)
    if machine is not None:
        machine.close()
    save()
