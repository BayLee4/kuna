#!/usr/bin/env python3
"""Check datatype identity, recursive loading and bitfields through real Ghidra.

Uses the suite environment from README.md. Signature commits run in rolled
back ProgramDB transactions; emitted memory reads also execute as native C.
"""

import json
import os
from pathlib import Path
import traceback


def main():
    output = Path(os.environ.get("KUNA_SMOKE_OUT", "live-type-boundaries-out")).resolve()
    output.mkdir(parents=True, exist_ok=True)
    report = {"completed": False, "status": "running", "rows": []}
    report_path = output / "type_boundaries.json"
    report_path.write_text(json.dumps(report, indent=2) + "\n")
    try:
        run(output, report)
        report["status"] = "passed"
    except BaseException:
        report["status"] = "failed" if report["completed"] else "aborted"
        report["failure"] = traceback.format_exc()
        raise
    finally:
        report_path.write_text(json.dumps(report, indent=2) + "\n")


def run(output, report):
    import pyghidra
    from kuna_vs_stock import KUNA_GHIDRA, get_exepath_field
    from prototype_facts import execute_c

    pyghidra.start()
    from jpype import JArray, JByte
    from java.lang import Object
    from ghidra.app.decompiler import DecompInterface, DecompileOptions, ClangTypeToken
    from ghidra.program.database import ProgramDB
    from ghidra.program.flatapi import FlatProgramAPI
    from ghidra.program.model.data import (
        CategoryPath, StructureDataType, TypedefDataType, IntegerDataType,
        UnsignedIntegerDataType, LongLongDataType, FunctionDefinitionDataType,
        PointerDataType, PointerTypedef, ParameterDefinition, ParameterDefinitionImpl,
        DataTypeConflictHandler,
    )
    from ghidra.program.model.lang import LanguageID, CompilerSpecID
    from ghidra.program.model.listing import Function, ParameterImpl, ReturnParameterImpl, Variable
    from ghidra.program.model.pcode import HighFunctionDBUtil
    from ghidra.program.model.symbol import SourceType, IllegalCharCppTransformer
    from ghidra.program.util import DefaultLanguageService
    from ghidra.util.task import ConsoleTaskMonitor

    field = get_exepath_field()
    original_exepath = field.get(None)
    monitor = ConsoleTaskMonitor()
    language = DefaultLanguageService.getLanguageService().getLanguage(LanguageID("x86:LE:64:default"))

    def type_info(datatype, manager):
        if datatype is None:
            return None
        return {"name": str(datatype.getName()), "id": int(manager.getID(datatype))}

    try:
        for case in ("callback", "callback_alias", "recursive_alias", "record", "bitfield",
                     "relative_named", "relative_auto"):
            owner = Object()
            program = ProgramDB(case, language, language.getCompilerSpecByID(CompilerSpecID("gcc")), owner)
            nominal_pointer = case == "callback_alias" or case.startswith("relative")
            try:
                api = FlatProgramAPI(program, monitor)
                manager = program.getDataTypeManager()
                tx = program.startTransaction("Datatype producer fixture")
                try:
                    if case.startswith("callback"):
                        target = FunctionDefinitionDataType("CallbackSig", manager)
                        target.setCallingConvention("__stdcall")
                        target.setReturnType(IntegerDataType.dataType)
                        target.setArguments(JArray(ParameterDefinition)([
                            ParameterDefinitionImpl("value", IntegerDataType.dataType, None)
                        ]))
                        target = manager.resolve(target, DataTypeConflictHandler.DEFAULT_HANDLER)
                        if case == "callback_alias":
                            target = manager.resolve(
                                TypedefDataType(CategoryPath.ROOT, "CallbackAlias",
                                                PointerDataType(target, manager), manager),
                                DataTypeConflictHandler.DEFAULT_HANDLER,
                            )
                        returned = target if case == "callback_alias" else PointerDataType(target, manager)
                        code = "4889f8c3"
                        preamble = driver = None
                    elif case.startswith("relative"):
                        node = StructureDataType("Node", 16, manager)
                        node.replaceAtOffset(0, LongLongDataType.dataType, 8, "first", None)
                        node.replaceAtOffset(8, LongLongDataType.dataType, 8, "second", None)
                        node = manager.resolve(node, DataTypeConflictHandler.DEFAULT_HANDLER)
                        name = "TailPointer" if case == "relative_named" else None
                        target = manager.resolve(PointerTypedef(name, node, 8, manager, 8),
                                                 DataTypeConflictHandler.DEFAULT_HANDLER)
                        export_name = str(IllegalCharCppTransformer().simplify(target.getName()))
                        returned = LongLongDataType.dataType
                        code = "488b47f8c3"
                        preamble = (
                            "typedef long long longlong;\n"
                            "typedef struct Node { longlong first, second; } Node;\n"
                            f"typedef Node *{export_name};\n"
                            "#define ADJ(p) (*(Node *)((unsigned char *)(p) - 8))\n"
                        )
                        driver = (
                            "int main(void) { Node values[] = {{-739,219},{0,17},"
                            "{9223372036854775807LL,-41},{(-9223372036854775807LL-1),1}};\n"
                            "for (unsigned i=0; i<4; ++i) { "
                            f"{export_name} p=({export_name})((unsigned char *)&values[i]+8); "
                            f"if (read_{case}(p)!=values[i].first) return 1; }} return 0; }}"
                        )
                    elif case == "bitfield":
                        target = StructureDataType("Bits", 4, manager)
                        target.insertBitFieldAt(0, 4, 3, UnsignedIntegerDataType.dataType, 8, "middle", None)
                        target = manager.resolve(target, DataTypeConflictHandler.DEFAULT_HANDLER)
                        returned = UnsignedIntegerDataType.dataType
                        code = "8b07c1e80325ff000000c3"
                        preamble = "typedef struct Bits { unsigned int low:3, middle:8, high:21; } Bits;"
                        driver = "int main(void) { Bits v = {7, 0xab, 0x12345}; return read_bitfield(&v) != 0xab; }"
                    else:
                        node = StructureDataType("Node", 16 if case == "recursive_alias" else 8, manager)
                        node.replaceAtOffset(0, LongLongDataType.dataType, 8, "value", None)
                        if case == "recursive_alias":
                            target = TypedefDataType(CategoryPath.ROOT, "NodeAlias", node, manager)
                            callback = FunctionDefinitionDataType("Callback", manager)
                            callback.setCallingConvention("__stdcall")
                            callback.setReturnType(target)
                            callback.setArguments(JArray(ParameterDefinition)([
                                ParameterDefinitionImpl("value", target, None)
                            ]))
                            node.replaceAtOffset(8, PointerDataType(callback, manager), 8, "next", None)
                            preamble = "typedef long long longlong; typedef struct Node Node; typedef Node NodeAlias; typedef NodeAlias Callback(NodeAlias); struct Node { longlong value; Callback *next; };"
                            driver = "int main(void) { NodeAlias v = {-739, 0}; return read_recursive_alias(&v) != -739; }"
                        else:
                            target = node
                            preamble = "typedef long long longlong; typedef struct Node { longlong value; } Node;"
                            driver = "int main(void) { Node v = {-739}; return read_record(&v) != -739; }"
                        target = manager.resolve(target, DataTypeConflictHandler.DEFAULT_HANDLER)
                        returned = LongLongDataType.dataType
                        code = "488b07c3"
                    pointer = target if nominal_pointer else PointerDataType(target, manager)
                    address = program.getAddressFactory().getDefaultAddressSpace().getAddress(0x1000)
                    block = api.createMemoryBlock("code", address, JArray(JByte)(bytes.fromhex(code)), False)
                    block.setExecute(True)
                    assert api.disassemble(address), case
                    function = api.createFunction(address, "read_" + case)
                    function.updateFunction("__stdcall", ReturnParameterImpl(returned, program),
                                            Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS, False,
                                            SourceType.USER_DEFINED,
                                            JArray(Variable)([ParameterImpl("typed_input", pointer, program)]))
                    expected_parameter = function.getParameter(0).getDataType()
                    expected_return = function.getReturnType()
                    expected_id = int(manager.getID(target))
                finally:
                    program.endTransaction(tx, True)

                def identity_type(datatype):
                    return datatype if nominal_pointer else datatype.getDataType()

                for core, executable in (("stock", None), ("kuna", KUNA_GHIDRA)):
                    field.set(None, executable)
                    interface = DecompInterface()
                    row = {"case": case, "core": core, "expected_target": type_info(target, manager)}
                    report["rows"].append(row)
                    try:
                        interface.setOptions(DecompileOptions())
                        assert interface.openProgram(program), str(interface.getLastMessage())
                        result = interface.decompileFunction(function, 60, monitor)
                        row["completed"] = bool(result.decompileCompleted())
                        row["error"] = str(result.getErrorMessage())
                        assert row["completed"] and not row["error"], row
                        high = result.getHighFunction()
                        prototype = high.getFunctionPrototype()
                        actual = prototype.getParam(0)
                        assert str(actual.getName()) == "typed_input", str(actual.getName())
                        assert actual.getDataType().isEquivalent(expected_parameter), str(actual.getDataType())
                        assert prototype.getReturnType().isEquivalent(expected_return), str(prototype.getReturnType())
                        referent = identity_type(actual.getDataType())
                        row["parameter_referent"] = type_info(referent, manager)
                        assert referent is not None and int(manager.getID(referent)) == expected_id, row
                        if case.startswith("callback"):
                            referent = identity_type(prototype.getReturnType())
                            row["return_referent"] = type_info(referent, manager)
                            assert referent is not None and int(manager.getID(referent)) == expected_id, row
                        row["tokens"] = []

                        def visit(token):
                            if isinstance(token, ClangTypeToken):
                                row["tokens"].append({"text": str(token.getText()),
                                                      "type": type_info(token.getDataType(), manager)})
                            for index in range(token.numChildren()):
                                visit(token.Child(index))

                        visit(result.getCCodeMarkup())
                        named = [token for token in row["tokens"] if token["text"] == str(target.getName())]
                        assert named and all(token["type"] is not None and token["type"]["id"] == expected_id
                                             for token in named), row["tokens"]
                        row["c"] = str(result.getDecompiledFunction().getC())
                        (output / f"{case}-{core}.c").write_text(row["c"])
                        tx = program.startTransaction("Commit recovered datatype identities")
                        try:
                            HighFunctionDBUtil.commitParamsToDatabase(
                                high, True, HighFunctionDBUtil.ReturnCommitOption.COMMIT, SourceType.USER_DEFINED)
                            committed = function.getParameter(0).getDataType()
                            assert committed.isEquivalent(expected_parameter), str(committed)
                            assert int(manager.getID(identity_type(committed))) == expected_id, str(committed)
                            assert function.getReturnType().isEquivalent(expected_return), str(function.getReturnType())
                            row["committed_referent"] = type_info(identity_type(committed), manager)
                            if case.startswith("callback"):
                                referent = identity_type(function.getReturnType())
                                row["committed_return_referent"] = type_info(referent, manager)
                                assert referent is not None and int(manager.getID(referent)) == expected_id, row
                        finally:
                            program.endTransaction(tx, False)
                        if driver is not None:
                            row["execution"] = execute_c(row["c"], preamble, driver)
                        row["status"] = "passed"
                        print(f"PASS {core}: {case}", flush=True)
                    except BaseException:
                        row["status"] = "failed"
                        row["failure"] = traceback.format_exc()
                        print(f"FAIL {core}: {case}\n{row['failure']}", flush=True)
                    finally:
                        interface.dispose()
            finally:
                program.release(owner)
        report["completed"] = True
        failures = [row for row in report["rows"] if row["status"] != "passed"]
        assert not failures, [(row["core"], row["case"]) for row in failures]
    finally:
        field.set(None, original_exepath)


if __name__ == "__main__":
    main()
