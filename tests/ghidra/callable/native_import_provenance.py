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
    output.mkdir(parents=True, exist_ok=False)
    report = {"scope": "Actual SDK/libc-linked executable and unmodified host import metadata; not native callable-publication proof",
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
        pyghidra.start()
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
                        report["external_locations"].append({
                            "library": str(location.getLibraryName()),
                            "label": str(location.getLabel()),
                            "original_imported_name": text(location.getOriginalImportedName()),
                            "source": str(location.getSource()),
                            "symbol_id": None if symbol is None else int(symbol.getID()),
                            "external_address": text(location.getAddress()),
                            "external_space_address": str(location.getExternalSpaceAddress()),
                            "function": function(location.getFunction())})
                report["callers"] = []
                report["thunks"] = []
                for fn in program.getFunctionManager().getFunctions(True):
                    if fn.isThunk():
                        report["thunks"].append({"function": function(fn),
                                                 "target": function(fn.getThunkedFunction(True))})
                    if str(fn.getName()) not in ("call_printf", "_call_printf", "call_scanf", "_call_scanf"):
                        continue
                    row = {"function": function(fn), "calls": []}
                    for instruction in program.getListing().getInstructions(fn.getBody(), True):
                        if instruction.getFlowType().isCall():
                            row["calls"].append({"site": str(instruction.getAddress()),
                                                 "instruction": str(instruction),
                                                 "references": [{"to": str(ref.getToAddress()),
                                                                  "type": str(ref.getReferenceType())}
                                                                 for ref in instruction.getReferencesFrom()]})
                    report["callers"].append(row)
                assert len(report["callers"]) == 2, report["callers"]
                report["metadata_captured"] = True
                # Report UNKNOWN honestly: no library rename, manual prototype,
                # canonical receipt, or native decompiler output is manufactured.
    finally:
        (output / "canonical_native_import.json").write_text(json.dumps(report, indent=2) + "\n")


if __name__ == "__main__":
    main()
