#!/usr/bin/env python3
"""Verify native error preservation and same-process recovery with real Ghidra.

Uses GHIDRA_INSTALL_DIR, KUNA_GHIDRA_EXE and KUNA_SMOKE_OUT as documented in
README.md. Builds an in-memory x86 function; no input binary is required.
"""

import json
import os
import re
from pathlib import Path

import pyghidra

from kuna_vs_stock import KUNA_GHIDRA, get_exepath_field


def field(cls, name):
    result = cls.class_.getDeclaredField(name)
    result.setAccessible(True)
    return result


def main():
    pyghidra.start()
    from jpype import JArray, JByte
    from java.lang import Object
    from ghidra.app.decompiler import DecompInterface, DecompileOptions, DecompileProcess
    from ghidra.program.database import ProgramDB
    from ghidra.program.flatapi import FlatProgramAPI
    from ghidra.program.model.lang import CompilerSpecID, LanguageID
    from ghidra.program.util import DefaultLanguageService
    from ghidra.util.task import ConsoleTaskMonitor

    language = DefaultLanguageService.getLanguageService().getLanguage(LanguageID("x86:LE:64:default"))
    owner = Object()
    program = ProgramDB("error_recovery", language, language.getCompilerSpecByID(CompilerSpecID("gcc")), owner)
    monitor = ConsoleTaskMonitor()
    exepath = get_exepath_field()
    original_exepath = exepath.get(None)
    process_field = field(DecompInterface, "decompProcess")
    native_field = field(DecompileProcess, "nativeProcess")
    rows = {}
    try:
        tx = program.startTransaction("Create plus-seven fixture")
        try:
            api = FlatProgramAPI(program, monitor)
            entry = program.getAddressFactory().getDefaultAddressSpace().getAddress(0x1000)
            block = api.createMemoryBlock("code", entry, JArray(JByte)(bytes.fromhex("89f883c007c3")), False)
            block.setExecute(True)
            assert api.disassemble(entry), "fixture disassembly failed"
            function = api.createFunction(entry, "plus_seven")
            assert function is not None, "fixture function creation failed"
        finally:
            program.endTransaction(tx, True)

        for core in ("stock", "kuna"):
            exepath.set(None, KUNA_GHIDRA if core == "kuna" else None)
            interface = DecompInterface()
            options = DecompileOptions()
            options.setMaxInstructions(100)
            interface.setOptions(options)
            rows[core] = []
            try:
                assert interface.openProgram(program), str(interface.getLastMessage())
                native = native_field.get(process_field.get(interface))
                pid = int(native.pid())
                for limit in (100, 1, 100, 1, 100):
                    options.setMaxInstructions(limit)
                    assert interface.setOptions(options), str(interface.getLastMessage())
                    result = interface.decompileFunction(function, 30, monitor)
                    decompiled = result.getDecompiledFunction()
                    current_native = native_field.get(process_field.get(interface))
                    row = {
                        "limit": limit,
                        "pid": int(current_native.pid()),
                        "completed": bool(result.decompileCompleted()),
                        "error": str(result.getErrorMessage()),
                        "highfunction": result.getHighFunction() is not None,
                        "c": str(decompiled.getC()) if decompiled is not None else None,
                    }
                    rows[core].append(row)
                    assert row["pid"] == pid and current_native.isAlive(), row
                    if limit == 1:
                        assert not row["completed"] and not row["highfunction"] and row["c"] is None, row
                        assert "Flow exceeded maximum allowable instructions" in row["error"], row
                        assert "Decoding error" not in row["error"], row
                    else:
                        assert row["completed"] and row["highfunction"] and row["error"] == "", row
                        assert re.search(r"return\s+\w+\s*\+\s*7\s*;", row["c"] or ""), row
                print(f"PASS {core}: success/failure/recovery twice, unchanged native PID {pid}")
            finally:
                interface.dispose()
    finally:
        exepath.set(None, original_exepath)
        program.release(owner)
        out = Path(os.environ.get("KUNA_SMOKE_OUT", "live-smoke-out"))
        out.mkdir(parents=True, exist_ok=True)
        (out / "error_recovery.json").write_text(json.dumps(rows, indent=2) + "\n")


if __name__ == "__main__":
    main()
