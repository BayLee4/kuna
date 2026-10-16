#!/usr/bin/env python3
"""Verify qualified pointer references against real 8051 banks and native C objects."""

import json
import os
from pathlib import Path
import traceback


def run(output, report):
    import pyghidra
    from kuna_vs_stock import KUNA_GHIDRA, get_exepath_field, start_ghidra
    from prototype_facts import execute_c

    start_ghidra()
    from jpype import JArray, JByte
    from java.lang import Object
    from ghidra.app.decompiler import DecompInterface, DecompileOptions, ClangVariableToken
    from ghidra.app.emulator import EmulatorHelper
    from ghidra.program.database import ProgramDB
    from ghidra.program.database.data import PointerTypedefInspector
    from ghidra.program.flatapi import FlatProgramAPI
    from ghidra.program.model.data import (
        ByteDataType, PointerTypedef, TypedefDataType, CategoryPath, DataTypeConflictHandler,
    )
    from ghidra.program.model.lang import LanguageID, CompilerSpecID
    from ghidra.program.model.listing import Function, ReturnParameterImpl, Variable
    from ghidra.program.model.pcode import PcodeDataTypeManager, XmlEncode
    from ghidra.program.model.symbol import SourceType, IllegalCharCppTransformer
    from ghidra.program.util import DefaultLanguageService
    from ghidra.util.task import ConsoleTaskMonitor

    monitor = ConsoleTaskMonitor()
    language = DefaultLanguageService.getLanguageService().getLanguage(LanguageID("8051:BE:16:default"))
    field = get_exepath_field()
    original = field.get(None)
    try:
        for bank in ("INTMEM", "SFR"):
            for offset in (0x80, 0xa0, 0xff):
                for aliased in (False, True):
                    case = f"{bank.lower()}_{offset:x}_{'alias' if aliased else 'pointer'}"
                    owner = Object()
                    program = ProgramDB(case, language, language.getCompilerSpecByID(CompilerSpecID("default")), owner)
                    try:
                        api = FlatProgramAPI(program, monitor)
                        manager = program.getDataTypeManager()
                        spaces = program.getAddressFactory()
                        tx = program.startTransaction("Qualified pointer consumer")
                        try:
                            for name, value in (("INTMEM", 0x11), ("SFR", 0x22)):
                                location = spaces.getAddressSpace(name).getAddress(offset)
                                api.createMemoryBlock(name + "_data", location, JArray(JByte)(bytes([value])), False)
                                api.createData(location, ByteDataType.dataType)
                                api.createLabel(location, name.lower() + "_value", True)
                            target = spaces.getAddressSpace(bank)
                            pointer = manager.resolve(
                                PointerTypedef("BankPointer", ByteDataType.dataType, 1, manager, target),
                                DataTypeConflictHandler.DEFAULT_HANDLER,
                            )
                            returned = pointer
                            if aliased:
                                returned = manager.resolve(
                                    TypedefDataType(CategoryPath.ROOT, "PortAlias", pointer, manager),
                                    DataTypeConflictHandler.DEFAULT_HANDLER,
                                )
                            address = spaces.getAddressSpace("CODE").getAddress(0x100)
                            code = bytes([0x74, offset, 0x22])
                            block = api.createMemoryBlock("code", address, JArray(JByte)(code), False)
                            block.setExecute(True)
                            assert api.disassemble(address)
                            function = api.createFunction(address, "get_port")
                            function.updateFunction(
                                "__stdcall", ReturnParameterImpl(returned, program),
                                Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS, False,
                                SourceType.USER_DEFINED, JArray(Variable)([]),
                            )
                        finally:
                            program.endTransaction(tx, True)
                        assert PointerTypedefInspector.getPointerAddressSpace(pointer, spaces) == target
                        encoder = XmlEncode()
                        PcodeDataTypeManager(program, IllegalCharCppTransformer()).encodeType(encoder, pointer, 1)
                        wire = str(encoder)
                        assert f'space="{bank}"' in wire
                        emulator = EmulatorHelper(program)
                        try:
                            emulator.setBreakpoint(address.add(2))
                            assert emulator.run(address, None, monitor), str(emulator.getLastError())
                            actual = int(str(emulator.readRegister("ACC")))
                            assert actual == offset, (case, actual)
                        finally:
                            emulator.dispose()
                        for core, executable in (("stock", None), ("kuna", KUNA_GHIDRA)):
                            field.set(None, executable)
                            interface = DecompInterface()
                            row = {"case": case, "core": core, "bank": bank, "offset": offset,
                                   "wire": wire, "machine_return": actual}
                            report["rows"].append(row)
                            try:
                                interface.setOptions(DecompileOptions())
                                assert interface.openProgram(program), str(interface.getLastMessage())
                                result = interface.decompileFunction(function, 60, monitor)
                                assert result.decompileCompleted(), str(result.getErrorMessage())
                                assert result.getHighFunction().getFunctionPrototype().getReturnType().isEquivalent(returned)
                                row["c"] = str(result.getDecompiledFunction().getC())
                                names = []

                                def visit(token):
                                    if isinstance(token, ClangVariableToken):
                                        names.append(str(token.getText()))
                                    for index in range(token.numChildren()):
                                        visit(token.Child(index))

                                visit(result.getCCodeMarkup())
                                row["variable_tokens"] = names
                                expected = bank.lower() + "_value"
                                wrong = ("sfr" if bank == "INTMEM" else "intmem") + "_value"
                                assert expected in names and wrong not in names, names
                                preamble = (
                                    "typedef unsigned char *BankPointer; typedef BankPointer PortAlias;\n"
                                    "unsigned char intmem_value=0x11, sfr_value=0x22;\n"
                                )
                                driver = (
                                    "int main(void) { BankPointer p=get_port(); return "
                                    f"p != &{expected} || *p != {0x11 if bank == 'INTMEM' else 0x22}; }}\n"
                                )
                                row["execution"] = execute_c(row["c"], preamble, driver)
                                row["status"] = "passed"
                                print(f"PASS {core}: {case}", flush=True)
                            except BaseException:
                                row["status"] = "failed"
                                row["failure"] = traceback.format_exc()
                                print(f"FAIL {core}: {case}\n{row['failure']}", flush=True)
                            finally:
                                interface.dispose()
                                (output / "pointer_spaces.json").write_text(json.dumps(report, indent=2) + "\n")
                    finally:
                        program.release(owner)
        report["completed"] = True
        assert all(row["status"] == "passed" for row in report["rows"])
    finally:
        field.set(None, original)


def main():
    output = Path(os.environ.get("KUNA_SMOKE_OUT", "live-pointer-spaces-out")).resolve()
    output.mkdir(parents=True, exist_ok=True)
    report = {"completed": False, "status": "running", "rows": []}
    try:
        run(output, report)
        report["status"] = "passed"
    except BaseException:
        report["status"] = "failed"
        report["failure"] = traceback.format_exc()
        raise
    finally:
        (output / "pointer_spaces.json").write_text(json.dumps(report, indent=2) + "\n")


if __name__ == "__main__":
    main()
