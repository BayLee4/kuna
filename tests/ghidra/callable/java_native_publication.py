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
from whole_calls import Machine
from kuna_vs_stock import KUNA_GHIDRA, get_exepath_field, export_program, start_ghidra

output = Path(os.environ["KUNA_SMOKE_OUT"]).resolve()
output.mkdir(parents=True, exist_ok=True)
executable = Path(KUNA_GHIDRA).resolve()
assert executable.is_file(), executable
report = {"passed": False, "scope": "Kuna inferred-only record C/High/markup, source separation across native restart, unchanged export execution", "native": str(executable), "native_sha256": hashlib.sha256(executable.read_bytes()).hexdigest(), "rows": []}


def save():
    (output / "native_publisher.json").write_text(json.dumps(report, indent=2) + "\n")


machine = None
field = None
original = None
try:
    start_ghidra()
    inferred_bytes = bytes.fromhex("8b070fb6570401d0c3")
    machine = Machine(inferred_bytes, [("sum_fields", 0x1000, inferred_bytes, "independently inferred source")])
    from jpype import JObject
    from java.io import File
    from ghidra.app.decompiler import DecompInterface, DecompileOptions
    from ghidra.app.util.exporter import CppExporter
    from ghidra.program.flatapi import FlatProgramAPI
    from ghidra.program.model.data import Pointer, Structure
    from ghidra.util.task import ConsoleTaskMonitor

    field = get_exepath_field()
    original = field.get(None)
    field.set(None, str(executable))
    program = machine.program
    manager = program.getDataTypeManager()
    api = FlatProgramAPI(program, machine.monitor)
    functions = {}
    transaction = program.startTransaction("Create function without authored datatype facts")
    try:
        function = api.createFunction(machine.address(0x1000), "sum_fields")
        assert function is not None
        functions["sum_fields"] = function
    finally:
        program.endTransaction(transaction, True)

    def source_snapshot():
        return {name: {"signature": str(fn.getSignature()), "return_storage": str(fn.getReturn().getVariableStorage()), "parameters": [{"name": str(p.getName()), "type": str(p.getDataType().getPathName()), "size": int(p.getDataType().getLength()), "storage": str(p.getVariableStorage())} for p in fn.getParameters()]} for name, fn in functions.items()}

    before = source_snapshot()
    before_revision = int(program.getModificationNumber())
    report["source_before"] = before
    options = DecompileOptions()
    # Native inferred record fields must not enter Program source lookup.
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
        for _ in range(1):
            independent, row = inferred_result()
            assert row == initial
        inferred_interface.flushCache()
        flushed, row = inferred_result()
        assert row == initial
        inferred_interface.resetDecompiler()
        fresh, row = inferred_result()
        assert row == initial
    finally:
        inferred_interface.dispose()

    exporter = CppExporter(options, True, True, True, True, False, "")
    assert exporter.export(File(str(output / "whole.c")), program, None, ConsoleTaskMonitor()), "Actual CppExporter rejected native closure"
    assert (output / "whole.h").is_file()
    driver = output / "inferred-driver.c"
    driver.write_text('#include "whole.h"\nint main(void) { int fields[2]={5,6}; return sum_fields((void *)fields)!=11; }\n')
    for optimization in ("-O0", "-O2"):
        binary = output / ("inferred" + optimization)
        command = [os.environ.get("CC", "cc"), "-std=c11", "-Wall", "-Werror=uninitialized",
                   "-Werror=incompatible-pointer-types", "-Werror=implicit-function-declaration",
                   optimization, str(output / "whole.c"), str(driver), "-o", str(binary)]
        built = subprocess.run(command, capture_output=True, text=True, timeout=120)
        assert built.returncode == 0, built.stderr
        ran = subprocess.run([str(binary)], capture_output=True, text=True, timeout=30)
        assert ran.returncode == 0, ran.stderr
        report["rows"].append({"surface": "inferred_record_export", "optimization": optimization, "passed": True})
    after = source_snapshot()
    report["source_after"] = after
    assert int(program.getModificationNumber()) == before_revision, "Decompilation/export edited persistent source"
    assert after == before, "Public export must not edit source function signatures/storage"
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
