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
from kuna_vs_stock import get_exepath_field

output = Path(os.environ["KUNA_SMOKE_OUT"]).resolve()
output.mkdir(parents=True, exist_ok=False)
executable = Path(os.environ["KUNA_GHIDRA_EXE"]).resolve()
assert executable.is_file(), executable
report = {"passed": False, "scope": "real native callable support, direct Java publication and ordinary CppExporter; unchanged emitted C/header execution", "native": str(executable), "native_sha256": hashlib.sha256(executable.read_bytes()).hexdigest(), "rows": []}


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
            if (dispatch(raw, which) != expected) return 11;
            if (invoke(raw, choose(which)) != expected) return 12;
        }
    }
"""
    if whole:
        body += """
    if (direct_dirty()!=0 || direct_clean()!=1 || ambient_dirty()!=0 || ambient_clean()!=1) return 13;
    for (unsigned int u=0; u<3; ++u) for (unsigned int low=0; low<256; ++low) {
        unsigned long long raw = uppers[u] | low;
        int expected = (unsigned int)raw == 85;
        if (ambient(raw)!=expected || wide_ambient(raw)!=expected) return 14;
        if (bool_byte(raw)!=((raw & 255)==85)) return 15;
    }
    if (sizeof(UnrelatedOnly) != 4) return 16;
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
    image, entries = fixture()
    machine = Machine(image, entries)
    from jpype import JArray
    from java.io import File, StringWriter
    from ghidra.app.decompiler import CallableSupport, DecompInterface, DecompileOptions
    from ghidra.app.util.exporter import CppExporter
    from ghidra.program.flatapi import FlatProgramAPI
    from ghidra.program.model.data import BooleanDataType, CategoryPath, DataTypeConflictHandler, FunctionDefinitionDataType, IntegerDataType, ParameterDefinition, ParameterDefinitionImpl, PointerDataType, TypedefDataType, UnsignedCharDataType, UnsignedIntegerDataType, UnsignedLongLongDataType
    from ghidra.program.model.listing import Function, ParameterImpl, ReturnParameterImpl, Variable
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
            variables = JArray(Variable)([ParameterImpl(n, t, program) for n, t in params])
            function.updateFunction(convention, ReturnParameterImpl(result, program), Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS, False, SourceType.USER_DEFINED, variables)
            functions[name] = function
    finally:
        program.endTransaction(transaction, True)

    def source_snapshot():
        return {name: {"signature": str(fn.getSignature()), "return_storage": str(fn.getReturn().getVariableStorage()), "parameters": [{"name": str(p.getName()), "type": str(p.getDataType().getPathName()), "size": int(p.getDataType().getLength()), "storage": str(p.getVariableStorage())} for p in fn.getParameters()]} for name, fn in functions.items()}

    before = source_snapshot()
    report["source_before"] = before
    options = DecompileOptions()
    interface = DecompInterface()
    try:
        interface.setOptions(options)
        assert interface.openProgram(program), str(interface.getLastMessage())
        result = interface.decompileFunction(functions["dispatch"], 120, machine.monitor)
        assert result.decompileCompleted(), str(result.getErrorMessage())
        fragment = result.getDecompiledFunction()
        assert fragment is not None
        support_optional = result.getCallableSupport()
        assert support_optional.isPresent(), "Kuna publisher must emit explicit callable support"
        support = support_optional.get()
        report["support_status"] = str(support.getStatus())
        report["support_reason"] = str(support.getReason())
        save()
        assert str(support.getStatus()) == "COMPLETE", str(support.getReason())
        assert fragment.getCallableSupport().isPresent()
        (output / "current-fragment.c").write_text(str(fragment.getC()))
        current = [b for b in support.getBodies() if b.current()]
        assert len(current) == 1
        assert int(current[0].id().space()) == int(functions["dispatch"].getEntryPoint().getAddressSpace().getUnique())
        assert int(current[0].id().byteAddress()) == int(functions["dispatch"].getEntryPoint().getOffset())
        report["actual_bodies"] = [{"space": int(b.id().space()), "address": int(b.id().byteAddress()), "current": bool(b.current()), "complete": bool(b.complete()), "declaration": str(b.declaration()), "artifacts": [{"key": str(a.key()), "required": bool(a.required()), "deferred": bool(a.deferred()), "kind": str(a.kind())} for a in b.artifacts()]} for b in support.getBodies()]
        publication = CallableSupport.Publication()
        try:
            publication.add(support)
            publication.validate()
            header = StringWriter()
            body = StringWriter()
            publication.writeTypes(header)
            publication.writeDeclarations(header, True)
            publication.writeBodies(body)
            (output / "direct.h").write_text(str(header.toString()))
            (output / "direct.c").write_text('#include "direct.h"\n' + str(body.toString()))
        finally:
            publication.close()
    finally:
        interface.dispose()
    compile_run("direct", False)
    report["rows"].append({"surface": "direct_result_publication", "passed": True})
    save()

    exporter = CppExporter(options, True, True, True, True, False, "")
    assert exporter.export(File(str(output / "whole.c")), program, None, ConsoleTaskMonitor()), "Actual CppExporter rejected native closure"
    assert (output / "whole.h").is_file()
    compile_run("whole", True)
    report["rows"].append({"surface": "ordinary_cpp_exporter", "passed": True})
    after = source_snapshot()
    report["source_after"] = after
    assert after == before, "Execution carrier publication must not edit source function signatures/storage"
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
