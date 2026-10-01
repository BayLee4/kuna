#!/usr/bin/env python3
"""Real CppExporter stock success and faulted-real-native refusal/sentinel proof."""
import base64
import json
import os
from pathlib import Path
import shlex
import subprocess
import sys
import traceback

repo = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(repo / "tests" / "ghidra"))
output = Path(os.environ.get("KUNA_SMOKE_OUT", "java-cpp-exporter-proof")).resolve()
output.mkdir(parents=True, exist_ok=True)
report = {"passed": False, "scope": "actual ordinary CppExporter; real stock native with transport faults; no successful Kuna native support claim", "rows": []}
try:
    import pyghidra
    from kuna_vs_stock import get_exepath_field
    pyghidra.start()
    from jpype import JArray, JByte
    from java.io import ByteArrayOutputStream, File
    from java.lang import Object
    from ghidra.app.decompiler import DecompInterface, DecompileOptions, DecompileProcessFactory
    from ghidra.app.util.exporter import CppExporter
    from ghidra.program.database import ProgramDB
    from ghidra.program.flatapi import FlatProgramAPI
    from ghidra.program.model.data import IntegerDataType
    from ghidra.program.model.lang import LanguageID, CompilerSpecID
    from ghidra.program.model.listing import Function, ReturnParameterImpl, Variable
    from ghidra.program.model.pcode import PackedEncode, ElementId, AttributeId
    from ghidra.program.model.symbol import SourceType
    from ghidra.program.util import DefaultLanguageService
    from ghidra.util.task import ConsoleTaskMonitor

    field = get_exepath_field()
    original = field.get(None)
    field.set(None, None)
    lookup = DecompileProcessFactory.get()
    stock = str(field.get(None))
    DecompileProcessFactory.release(lookup)
    assert Path(stock).is_file(), stock
    report["stock_executable"] = stock
    language = DefaultLanguageService.getLanguageService().getLanguage(LanguageID("x86:LE:64:default"))
    owner = Object()
    program = ProgramDB("export-receipt-failure", language,
                        language.getCompilerSpecByID(CompilerSpecID("gcc")), owner)
    try:
        monitor = ConsoleTaskMonitor()
        api = FlatProgramAPI(program, monitor)
        transaction = program.startTransaction("Real constant-return function")
        try:
            address = program.getAddressFactory().getDefaultAddressSpace().getAddress(0x1000)
            block = api.createMemoryBlock("code", address,
                                          JArray(JByte)(bytes.fromhex("b82a000000c3")), False)
            block.setExecute(True)
            assert api.disassemble(address)
            function = api.createFunction(address, "wire_result")
            function.updateFunction("__stdcall", ReturnParameterImpl(IntegerDataType.dataType, program),
                                    Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS, False,
                                    SourceType.USER_DEFINED, JArray(Variable)([]))
        finally:
            program.endTransaction(transaction, True)
        options = DecompileOptions()
        def exporter():
            return CppExporter(options, True, True, True, True, False, "")
        modes = os.environ.get("KUNA_CPP_EXPORTER_MODES", "stock,malformed,crash,cancelled").split(",")
        assert modes and all(mode in ("stock", "malformed", "crash", "cancelled") for mode in modes)
        if "stock" in modes:
            field.set(None, stock)
            interface = DecompInterface()
            try:
                assert interface.openProgram(program), str(interface.getLastMessage())
                result = interface.decompileFunction(function, 30, monitor)
                assert result.decompileCompleted(), str(result.getErrorMessage())
                assert result.getCallableSupport().isEmpty()
                assert result.getDecompiledFunction().getCallableSupport().isEmpty()
                report["stock_absence"] = True
            finally:
                interface.dispose()
            stock_c = output / "stock.c"
            assert exporter().export(File(str(stock_c)), program, None, ConsoleTaskMonitor())
            stock_header = output / "stock.h"
            assert stock_header.is_file()
            driver = output / "driver.c"
            driver.write_text('#include "stock.h"\nint main(void) { return wire_result() != 42; }\n')
            executions = []
            for optimization in ("-O0", "-O2"):
                binary = output / ("stock" + optimization)
                command = [os.environ.get("CC", "cc"), "-std=c11", optimization,
                           str(stock_c), str(driver), "-o", str(binary)]
                built = subprocess.run(command, text=True, capture_output=True)
                assert built.returncode == 0, built.stderr
                ran = subprocess.run([str(binary)], text=True, capture_output=True)
                assert ran.returncode == 0, ran.stderr
                executions.append({"optimization": optimization, "exit": ran.returncode})
            report["rows"].append({"mode": "stock_success", "passed": True, "execution": executions})

        # Obtain fault bytes from the REAL target PackedEncode, not a custom codec.
        raw = ByteArrayOutputStream()
        encoder = PackedEncode(raw)
        encoder.openElement(ElementId.ELEM_DOC)
        encoder.closeElement(ElementId.ELEM_DOC)
        document = bytes(raw.toByteArray())
        assert len(document) % 2 == 0
        middle = len(document) // 2
        malformed = ByteArrayOutputStream()
        encoder = PackedEncode(malformed)
        support = ElementId("callable_support", 4030)
        encoder.openElement(support)
        encoder.writeSignedInteger(AttributeId("kuna_version", 4030), 999)
        encoder.closeElement(support)
        config = output / "fault-codec.json"
        config.write_text(json.dumps({"doc_open": base64.b64encode(document[:middle]).decode(),
                                      "doc_close": base64.b64encode(document[middle:]).decode(),
                                      "invalid_support": base64.b64encode(bytes(malformed.toByteArray())).decode()}))
        proxy = Path(__file__).with_name("native_response_fault_proxy.py")
        for mode in ("malformed", "crash", "cancelled"):
            if mode not in modes:
                continue
            c_file, h_file = output / (mode + ".c"), output / (mode + ".h")
            sentinels = {c_file: b"original C destination\x00" + mode.encode(),
                         h_file: b"original header destination\x00" + mode.encode()}
            for path, content in sentinels.items():
                path.write_bytes(content)
            task_monitor = ConsoleTaskMonitor()
            if mode == "cancelled":
                field.set(None, stock)
                task_monitor.setCancelEnabled(True)
                task_monitor.cancel()
                assert task_monitor.isCancelled(), "Cancellation must be active before export"
            else:
                log = output / (mode + "-native.jsonl")
                launcher = output / (mode + "-native.sh")
                argv = [sys.executable, str(proxy), stock, mode, str(config), str(log)]
                stderr = output / (mode + "-stderr.log")
                launcher.write_text("#!/bin/sh\nexec " + " ".join(shlex.quote(arg) for arg in argv) +
                                    " 2>" + shlex.quote(str(stderr)) + "\n")
                launcher.chmod(0o755)
                field.set(None, str(launcher))
            success = bool(exporter().export(File(str(c_file)), program, None, task_monitor))
            assert not success, mode
            for path, content in sentinels.items():
                assert path.read_bytes() == content, (mode, str(path))
            assert not list(output.glob("ghidra-cpp-*.tmp")), mode
            row = {"mode": mode, "export_result": success, "sentinels_unchanged": True,
                   "staging_removed": True}
            if mode != "cancelled":
                events = [json.loads(line) for line in log.read_text().splitlines()]
                faults = [event for event in events if event["phase"] == "fault"]
                assert faults and all(event["mode"] == mode and event["native_executable"] == stock for event in faults), events
                row["actual_native_response_faults"] = faults
            report["rows"].append(row)
        report["exporter_origin"] = str(exporter().getClass().getProtectionDomain().getCodeSource().getLocation())
        report["passed"] = True
    finally:
        program.release(owner)
        field.set(None, original)
except BaseException:
    report["failure"] = traceback.format_exc()
    raise
finally:
    (output / "cpp_exporter.json").write_text(json.dumps(report, indent=2) + "\n")
