#!/usr/bin/env python3
"""Source-owned same-spelled records, field bindings and source-edit lifetime."""
import json
import os
from pathlib import Path
import sys
import traceback

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from kuna_vs_stock import KUNA_GHIDRA, selected_core, start_ghidra


def main():
    output = Path(os.environ.get("KUNA_SMOKE_OUT", "java-source-identity-proof"))
    output.mkdir(parents=True, exist_ok=True)
    report = {"passed": False, "rows": []}
    program = None
    try:
        start_ghidra()
        from jpype import JArray, JByte
        from java.lang import Object
        from ghidra.app.decompiler import ClangFieldToken, DecompInterface
        from ghidra.program.database import ProgramDB
        from ghidra.program.flatapi import FlatProgramAPI
        from ghidra.program.model.data import (CategoryPath, StructureDataType, IntegerDataType,
            DataTypeConflictHandler, PointerDataType)
        from ghidra.program.model.lang import LanguageID, CompilerSpecID
        from ghidra.program.model.listing import Function, ParameterImpl, ReturnParameterImpl, Variable
        from ghidra.program.model.symbol import SourceType
        from ghidra.program.util import DefaultLanguageService
        from ghidra.util.task import ConsoleTaskMonitor
        owner = Object()
        language = DefaultLanguageService.getLanguageService().getLanguage(LanguageID("x86:LE:64:default"))
        program = ProgramDB("source-identity", language, language.getCompilerSpecByID(CompilerSpecID("gcc")), owner)
        monitor = ConsoleTaskMonitor()
        api = FlatProgramAPI(program, monitor)
        manager = program.getDataTypeManager()
        addr = program.getAddressFactory().getDefaultAddressSpace().getAddress
        tx = program.startTransaction("Distinct genuine source definitions")
        try:
            records = []
            functions = []
            for index, category in enumerate(("/first", "/second")):
                record = StructureDataType(CategoryPath(category), "Persisted", 4, manager)
                record.replaceAtOffset(0, IntegerDataType.dataType, 4, "authored_" + str(index), None)
                record = manager.resolve(record, DataTypeConflictHandler.DEFAULT_HANDLER)
                records.append(record)
                entry = addr(0x1000 + index * 0x100)
                block = api.createMemoryBlock("body" + str(index), entry,
                    JArray(JByte)(bytes.fromhex("8b07c3")), False)
                block.setExecute(True)
                assert api.disassemble(entry)
                fn = api.createFunction(entry, "read_" + str(index))
                fn.updateFunction("__stdcall", ReturnParameterImpl(IntegerDataType.dataType, program),
                    Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS, False, SourceType.USER_DEFINED,
                    JArray(Variable)([ParameterImpl("record", PointerDataType(record, manager), program)]))
                functions.append(fn)
        finally:
            program.endTransaction(tx, True)
        ids = [int(manager.getID(record)) for record in records]
        assert ids[0] != ids[1]
        for core, exe in (("kuna", KUNA_GHIDRA),):
            with selected_core(exe):
                interface = DecompInterface()
                retained = []
                try:
                    assert interface.openProgram(program), str(interface.getLastMessage())
                    for epoch in ("initial", "edited_flush"):
                        if epoch == "edited_flush":
                            tx = program.startTransaction("Explicit nested source edit")
                            try:
                                records[0].getComponentAt(0).setFieldName("edited_field")
                            finally:
                                program.endTransaction(tx, True)
                            interface.flushCache()
                        before = int(program.getModificationNumber())
                        for index, fn in enumerate(functions):
                            result = interface.decompileFunction(fn, 60, monitor)
                            assert result.decompileCompleted(), str(result.getErrorMessage())
                            high = result.getHighFunction()
                            actual = high.getFunctionPrototype().getParam(0).getDataType().getDataType()
                            assert int(manager.getID(actual)) == ids[index]
                            expected = "edited_field" if index == 0 and epoch == "edited_flush" else "authored_" + str(index)
                            bindings = []
                            def visit(token):
                                if isinstance(token, ClangFieldToken):
                                    datatype = token.getDataType()
                                    bindings.append((str(token.getText()), int(token.getOffset()), int(manager.getID(datatype))))
                                for child in range(token.numChildren()):
                                    visit(token.Child(child))
                            visit(result.getCCodeMarkup())
                            assert bindings == [(expected, 0, ids[index])], bindings
                            code = str(result.getDecompiledFunction().getC())
                            assert expected in code and str(fn.getName()) in code
                            retained.append((result, code))
                            assert int(program.getModificationNumber()) == before, "Decompilation edited source"
                            report["rows"].append({"core": core, "epoch": epoch, "entry": str(fn.getEntryPoint()),
                                                   "bindings": bindings, "source_unchanged": True})
                        for old, code in retained:
                            assert str(old.getDecompiledFunction().getC()) == code
                finally:
                    interface.dispose()
        report["passed"] = True
    except BaseException:
        report["failure"] = traceback.format_exc()
        raise
    finally:
        if program is not None:
            program.release(owner)
        (output / "source_identity.json").write_text(json.dumps(report, indent=2) + "\n")


if __name__ == "__main__":
    main()
