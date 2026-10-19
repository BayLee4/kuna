#!/usr/bin/env python3
"""Read actual native SDK/libc import provenance; never alter imported metadata."""
import hashlib
import json
import os
from pathlib import Path
import platform
import shlex
import subprocess
import tempfile

import sys
import traceback
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from kuna_vs_stock import export_program, start_ghidra, KUNA_GHIDRA, selected_core, test_cores
import pyghidra

SOURCE = r'''#include <stdio.h>
__attribute__((noinline)) int call_printf(void) {
    return printf("%d %lld", 65, 0x1122334455667788LL);
}
__attribute__((noinline)) int call_scanf(int *first, short *second) {
    return scanf("%d %hd", first, second);
}
int main(void) {
    int first = 0;
    short second = 0;
    if (call_printf() != 22) return 1;
    if (call_scanf(&first, &second) != 2 || first != 65 || second != -7) return 2;
    return fgetc(stdin) != '!' || fgetc(stdin) != EOF;
}
'''


def main():
    host = platform.system()
    assert host in ("Darwin", "Linux"), "This probe requires a native Darwin or Linux SDK/libc"
    output = Path(os.environ["KUNA_SMOKE_OUT"]).resolve()
    output.mkdir(parents=True, exist_ok=True)
    cores = test_cores()
    report = {"scope": "Actual SDK/libc imports, unchanged source metadata, selected-core C/High and genuine libc consumers",
              "group": "product" if "kuna" in cores else "stock-controls", "selected_cores": cores,
              "host": platform.platform(), "commands": []}

    def run(command, **kwargs):
        result = subprocess.run(command, text=True, capture_output=True, **kwargs)
        report["commands"].append({"argv": [str(arg) for arg in command],
                                   "returncode": result.returncode,
                                   "stdout": result.stdout, "stderr": result.stderr})
        result.check_returncode()
        return result.stdout

    def text(value):
        return None if value is None else str(value)

    def datatype(value):
        archive = value.getSourceArchive()
        return {"path": str(value.getPathName()), "size": int(value.getLength()),
                "class": str(value.getClass().getName()),
                "archive": None if archive is None else str(archive.getName()),
                "archive_id": None if archive is None else text(archive.getSourceArchiveID()),
                "universal_id": text(value.getUniversalID())}

    def function(value):
        if value is None:
            return None
        return {"name": str(value.getName()), "entry": str(value.getEntryPoint()),
                "external": bool(value.isExternal()), "thunk": bool(value.isThunk()),
                "signature_source": str(value.getSignatureSource()),
                "signature": str(value.getSignature()),
                "convention": text(value.getCallingConventionName()),
                "varargs": bool(value.hasVarArgs()), "custom_storage": bool(value.hasCustomVariableStorage()),
                "return": datatype(value.getReturnType()),
                "return_storage": str(value.getReturn().getVariableStorage()),
                "parameters": [{"name": str(p.getName()), "source": str(p.getSource()),
                                "storage": str(p.getVariableStorage()), "type": datatype(p.getDataType())}
                               for p in value.getParameters()]}

    try:
        source = output / "sdk_import.c"
        binary = output / "sdk_import"
        source.write_text(SOURCE)
        if host == "Darwin":
            report["sdk"] = run(["xcrun", "--show-sdk-path"]).strip()
        compiler = shlex.split(os.environ["CC"]) if "CC" in os.environ else (["xcrun", "clang"] if host == "Darwin" else ["cc"])
        run(compiler + ["-O0", "-g", "-fno-builtin", "-Wall", "-Werror",
                        str(source), "-o", str(binary)])
        report["binary_sha256"] = hashlib.sha256(binary.read_bytes()).hexdigest()
        report["linked_libraries"] = run(["xcrun", "otool", "-L", str(binary)] if host == "Darwin" else ["ldd", str(binary)])
        report["undefined_symbols"] = run(["xcrun", "nm", "-u", str(binary)] if host == "Darwin" else ["nm", "-u", str(binary)])
        observed = run([str(binary)], input="65 -7!")
        assert observed == "65 1234605616436508552", repr(observed)
        report["native_executed"] = True
        start_ghidra()
        with tempfile.TemporaryDirectory(prefix="sdk-import-project-", dir=output) as project:
            with pyghidra.open_program(binary, project_location=project,
                                      project_name="sdk_import", analyze=True) as api:
                program = api.getCurrentProgram()
                report["program"] = {"format": str(program.getExecutableFormat()),
                                     "language": str(program.getLanguageID()),
                                     "compiler": str(program.getCompilerSpec().getCompilerSpecID())}
                externals = program.getExternalManager()
                report["libraries"] = []
                report["external_locations"] = []
                for library in externals.getExternalLibraryNames():
                    report["libraries"].append({"name": str(library),
                                               "project_path": text(externals.getExternalLibraryPath(library))})
                    for location in externals.getExternalLocations(library):
                        symbol = location.getSymbol()
                        references = []
                        for reference in program.getReferenceManager().getReferencesTo(location.getExternalSpaceAddress()):
                            origin = reference.getFromAddress()
                            data = program.getListing().getDefinedDataAt(origin)
                            block = program.getMemory().getBlock(origin)
                            references.append({
                                "from": str(origin), "source": str(reference.getSource()),
                                "type": str(reference.getReferenceType()),
                                "external": bool(reference.isExternalReference()),
                                "initialized": block is not None and bool(block.isInitialized()),
                                "data_type": None if data is None else str(data.getDataType()),
                                "data_size": None if data is None else int(data.getLength()),
                            })
                        report["external_locations"].append({
                            "library": str(location.getLibraryName()),
                            "label": str(location.getLabel()),
                            "original_imported_name": text(location.getOriginalImportedName()),
                            "source": str(location.getSource()),
                            "symbol_id": None if symbol is None else int(symbol.getID()),
                            "external_address": text(location.getAddress()),
                            "external_space_address": str(location.getExternalSpaceAddress()),
                            "references": references,
                            "function": function(location.getFunction())})
                report["callers"] = []
                report["thunks"] = []
                for fn in program.getFunctionManager().getFunctions(True):
                    if fn.isThunk():
                        report["thunks"].append({"function": function(fn),
                                                 "target": function(fn.getThunkedFunction(True)),
                                                 "incoming_references": [{
                                                     "from": str(reference.getFromAddress()),
                                                     "source": str(reference.getSource()),
                                                     "type": str(reference.getReferenceType()),
                                                     "data_type": text(program.getListing().getDefinedDataAt(reference.getFromAddress())),
                                                 } for reference in program.getReferenceManager().getReferencesTo(fn.getEntryPoint())],
                                                 "instructions": [{
                                                     "address": str(instruction.getAddress()),
                                                     "instruction": str(instruction),
                                                     "pcode": [str(op) for op in instruction.getPcode()],
                                                     "references": [{
                                                         "to": str(reference.getToAddress()),
                                                         "source": str(reference.getSource()),
                                                         "type": str(reference.getReferenceType()),
                                                     } for reference in instruction.getReferencesFrom()],
                                                 } for instruction in program.getListing().getInstructions(fn.getBody(), True)]})
                    if str(fn.getName()) not in ("call_printf", "_call_printf", "call_scanf", "_call_scanf"):
                        continue
                    row = {"function": function(fn), "calls": []}
                    for instruction in program.getListing().getInstructions(fn.getBody(), True):
                        if instruction.getFlowType().isCall():
                            references = []
                            for ref in instruction.getReferencesFrom():
                                reference = {"to": str(ref.getToAddress()),
                                             "type": str(ref.getReferenceType())}
                                target = program.getFunctionManager().getFunctionAt(ref.getToAddress())
                                if target is not None and target.isThunk():
                                    target = target.getThunkedFunction(True)
                                if target is not None and target.isExternal():
                                    reference["external_symbol_id"] = int(target.getSymbol().getID())
                                references.append(reference)
                            row["calls"].append({"site": str(instruction.getAddress()),
                                                 "instruction": str(instruction),
                                                 "references": references})
                    report["callers"].append(row)
                assert len(report["callers"]) == 2, report["callers"]
                assert {row["function"]["name"].lstrip("_") for row in report["callers"]} == {
                    "call_printf", "call_scanf"}, report["callers"]
                report["metadata_captured"] = True
                before = {str(fn.getEntryPoint()): function(fn)
                          for fn in program.getFunctionManager().getFunctions(True)}
                from ghidra.app.decompiler import DecompInterface, DecompileOptions
                from ghidra.program.model.data import FunctionDefinition
                from ghidra.program.model.pcode import PcodeOp
                from ghidra.util.task import ConsoleTaskMonitor
                def function_data_types():
                    manager = program.getDataTypeManager()
                    return sorted([
                        {**datatype(value), "name": str(value.getName()),
                         "managed_id": int(manager.getID(value)),
                         "signature": str(value.getPrototypeString(True)),
                         "return": datatype(value.getReturnType()),
                         "parameters": [datatype(parameter.getDataType())
                                        for parameter in value.getArguments()],
                         "parents": sorted(str(parent.getPathName()) for parent in value.getParents())}
                        for value in manager.getAllDataTypes()
                        if isinstance(value, FunctionDefinition)
                    ], key=lambda value: (value["path"], value["managed_id"]))
                source_function_types = function_data_types()
                report["function_data_types_before"] = source_function_types
                monitor = ConsoleTaskMonitor()
                report["decompilations"] = []
                def consume_core(core, executable):
                    with selected_core(executable):
                        interface = DecompInterface()
                        try:
                            assert interface.openProgram(program), str(interface.getLastMessage())
                            fragments = []
                            enhanced_results = []
                            selected = {}
                            from ghidra.program.model.address import AddressSet
                            selection = AddressSet()
                            for fn in program.getFunctionManager().getFunctions(True):
                                if str(fn.getName()).lstrip("_") not in ("call_printf", "call_scanf"):
                                    continue
                                selected[str(fn.getName()).lstrip("_")] = str(fn.getName())
                                selection.add(fn.getBody())
                                result = interface.decompileFunction(fn, 120, monitor)
                                assert result.decompileCompleted(), str(result.getErrorMessage())
                                high = result.getHighFunction()
                                assert high is not None and result.getCCodeMarkup() is not None
                                enhanced_results.append(hasattr(result, "isEnhancedResult") and
                                                        bool(result.isEnhancedResult()))
                                calls = [op for op in high.getPcodeOps()
                                         if op.getOpcode() in (PcodeOp.CALL, PcodeOp.CALLIND)]
                                assert calls, "Imported source caller lost its call effect"
                                code = str(result.getDecompiledFunction().getC())
                                fragments.append(code)
                                report["decompilations"].append({"core": core,
                                    "name": str(fn.getName()), "c": code,
                                    "high_calls": [str(op) for op in calls]})
                            assert len(fragments) == 2
                            unit = output / (core + "-imports.c")
                            assert export_program(program, unit, monitor, selection=selection)
                            header = unit.with_suffix(".h")
                            assert header.is_file()
                            # The enhanced Java exporter has source import facts even when
                            # the selected native core returns no enhanced result metadata.
                            if all(enhanced_results) or hasattr(result, "getDataTypeManager"):
                                declarations = header.read_text()
                                locations = {location["symbol_id"]: location
                                             for location in report["external_locations"]}
                                for caller in report["callers"]:
                                    imported_ids = {
                                        reference["external_symbol_id"]
                                        for call in caller["calls"] for reference in call["references"]
                                        if "external_symbol_id" in reference}
                                    assert len(imported_ids) == 1, caller
                                    location = locations[next(iter(imported_ids))]
                                    assert location["function"] is not None, location
                                    identifier = location["function"]["name"]
                                    imported_name = location["original_imported_name"]
                                    if imported_name is None:
                                        assert location["source"] == "IMPORTED", location
                                        imported_name = location["label"]
                                    assert identifier and imported_name, location
                                    assert f"({identifier})(" in declarations, declarations
                                    assert f'__asm__("{imported_name}")' in declarations, declarations
                                report.setdefault("enhanced_external_declarations", []).append({
                                    "core": core, "source_identifiers_preserved": True,
                                    "actual_import_labels_bound": True,
                                    "selected_bodies": sorted(selected)})
                            driver = output / (core + "-import-driver.c")
                            stdio = output / (core + "-stdio-provider.c")
                            stdio.write_text('#include <stdio.h>\n'
                                "int check_input_terminator(void) {"
                                "return fgetc(stdin)!='!' || fgetc(stdin)!=EOF; }\n")
                            driver.write_text('#include "' + header.name + '"\n'
                                "int check_input_terminator(void);\n" +
                                "int main(void) { int first=0; short second=0;"
                                f"if ({selected['call_printf']}()!=22) return 1;"
                                f"if ({selected['call_scanf']}(&first,&second)!=2 || first!=65 || second!=-7) return 2;"
                                "return check_input_terminator(); }\n")
                            for optimization in ("-O0", "-O2"):
                                emitted = output / (core + optimization)
                                run(compiler + ["-std=c11", "-Wall", "-Werror=implicit-function-declaration",
                                    "-Werror=incompatible-pointer-types",
                                    optimization, str(unit), str(driver), str(stdio), "-o", str(emitted)])
                                stdout = run([str(emitted)], input="65 -7!")
                                assert stdout == "65 1234605616436508552", repr(stdout)
                        finally:
                            interface.dispose()
                report["core_failures"] = []
                report["core_source_checks"] = []
                for core in cores:
                    executable = KUNA_GHIDRA if core == "kuna" else None
                    try:
                        consume_core(core, executable)
                    except Exception:
                        report["core_failures"].append({
                            "core": core, "failure": traceback.format_exc()})
                    finally:
                        observed = {str(fn.getEntryPoint()): function(fn)
                                    for fn in program.getFunctionManager().getFunctions(True)}
                        observed_function_types = function_data_types()
                        report["core_source_checks"].append({
                            "core": core, "source_after": observed,
                            "unchanged": observed == before,
                            "function_data_types_after": observed_function_types,
                            "function_data_types_unchanged": observed_function_types == source_function_types})
                        try:
                            assert observed == before, "Decompilation altered imported source/types/storage"
                            assert observed_function_types == source_function_types, "Export altered managed callable source datatypes"
                        except AssertionError:
                            report["core_failures"].append({
                                "core": core, "failure": traceback.format_exc()})
                after = {str(fn.getEntryPoint()): function(fn)
                         for fn in program.getFunctionManager().getFunctions(True)}
                assert after == before, "Decompilation altered imported source/types/storage"
                report["source_unchanged"] = True
                assert not report["core_failures"], report["core_failures"]
        report["passed"] = True
    except BaseException:
        report["passed"] = False
        report["failure"] = traceback.format_exc()
        raise
    finally:
        (output / "canonical_native_import.json").write_text(json.dumps(report, indent=2) + "\n")


if __name__ == "__main__":
    main()
