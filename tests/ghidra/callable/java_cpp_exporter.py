#!/usr/bin/env python3
"""Real exporter observations; atomic failure is required only in the enhanced domain."""
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
report = {"passed": False, "scope": "actual selected-domain CppExporter with both cores; unchanged C/H/providers, real stock faults and recovery", "rows": [], "failures": []}
enhanced = os.environ.get("KUNA_CPP_EXPORTER_DOMAIN") == "enhanced"
report["domain"] = "enhanced" if enhanced else "stock"
report["enhanced_atomic_contract"] = {
    "status": "selected-unproven" if enhanced else "prerequisite-unrepresented",
    "requires": ["global failure on malformed/crash/cancelled",
                 "identical C and H destination sentinels", "no ghidra-cpp-*.tmp staging files"],
    "installation": "GHIDRA_INSTALL_DIR must select the enhanced receiving/exporter implementation; this selector installs nothing and negotiates no capability.",
}
try:
    from kuna_vs_stock import KUNA_GHIDRA, get_exepath_field, selected_core, start_ghidra
    if enhanced:
        import pyghidra
        pyghidra.start()
    else:
        start_ghidra()
    from jpype import JArray, JByte
    from java.io import ByteArrayOutputStream, File
    from java.lang import Object
    from ghidra.app.decompiler import DecompInterface, DecompileOptions, DecompileProcessFactory
    from ghidra.app.util.exporter import CppExporter
    from ghidra.program.database import ProgramDB
    from ghidra.program.flatapi import FlatProgramAPI
    from ghidra.program.model.data import (CategoryPath, DataTypeConflictHandler,
                                          IntegerDataType, TypedefDataType)
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
            other_address = program.getAddressFactory().getDefaultAddressSpace().getAddress(0x2000)
            other_block = api.createMemoryBlock("other_code", other_address,
                JArray(JByte)(bytes.fromhex("b82b000000c3")), False)
            other_block.setExecute(True)
            assert api.disassemble(other_address)
            other = api.createFunction(other_address, "wire_other")
            other.updateFunction("__stdcall", ReturnParameterImpl(IntegerDataType.dataType, program),
                Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS, False,
                SourceType.USER_DEFINED, JArray(Variable)([]))
            api.setPlateComment(address, "authored-export-comment")
            manager = program.getDataTypeManager()
            manager.resolve(TypedefDataType(CategoryPath.ROOT, "ExportSource",
                            IntegerDataType.dataType, manager), DataTypeConflictHandler.DEFAULT_HANDLER)
            for offset, name, code in (
                    (0x1100, "global_provider", "8b05fa000000c3"),
                    (0x1120, "global_consumer", "e8dbffffffc3")):
                entry = program.getAddressFactory().getDefaultAddressSpace().getAddress(offset)
                block = api.createMemoryBlock(name, entry, JArray(JByte)(bytes.fromhex(code)), False)
                block.setExecute(True)
                assert api.disassemble(entry)
                provider = api.createFunction(entry, name)
                assert provider is not None
                provider.updateFunction("__stdcall", ReturnParameterImpl(IntegerDataType.dataType, program),
                    Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS, False,
                    SourceType.USER_DEFINED, JArray(Variable)([]))
            global_address = program.getAddressFactory().getDefaultAddressSpace().getAddress(0x1200)
            global_block = api.createMemoryBlock("owned_global", global_address,
                                                JArray(JByte)((42).to_bytes(4, "little")), False)
            global_block.setWrite(True)
            api.createData(global_address, IntegerDataType.dataType)
            api.createLabel(global_address, "exported_word", True)
        finally:
            program.endTransaction(transaction, True)
        from support import snapshot as source_snapshot
        functions = {str(fn.getName()): fn for fn in program.getFunctionManager().getFunctions(True)}
        source_before = source_snapshot(functions)
        revision_before = int(program.getModificationNumber())
        options = DecompileOptions()
        def exporter(types=True, globals=True):
            return CppExporter(options, True, True, types, globals, False, "")
        modes = os.environ.get("KUNA_CPP_EXPORTER_MODES", "stock,kuna,malformed,crash,cancelled").split(",")
        assert modes and all(mode in ("stock", "kuna", "malformed", "crash", "cancelled") for mode in modes)
        if "stock" in modes:
            row = {"mode": "stock_success", "passed": False, "failures": [], "execution": []}
            report["rows"].append(row)
            try:
                field.set(None, stock)
                interface = DecompInterface()
                try:
                    assert interface.openProgram(program), str(interface.getLastMessage())
                    result = interface.decompileFunction(function, 30, monitor)
                    assert result.decompileCompleted(), str(result.getErrorMessage())
                    assert result.getHighFunction() is not None and result.getCCodeMarkup() is not None
                    assert str(result.getDecompiledFunction().getC()).count("wire_result") == 1
                finally:
                    interface.dispose()
            except Exception:
                row["failures"].append({"stage": "receiver", "failure": traceback.format_exc()})
            stock_c, stock_header = output / "stock.c", output / "stock.h"
            driver = output / "driver.c"
            try:
                driver.write_text('#include "stock.h"\nint main(void) { return wire_result() != 42 || wire_other() != 43; }\n')
                assert exporter().export(File(str(stock_c)), program, None, ConsoleTaskMonitor())
                assert stock_header.is_file()
            except Exception:
                row["failures"].append({"stage": "export", "failure": traceback.format_exc()})
            for optimization in ("-O0", "-O2"):
                try:
                    binary = output / ("stock" + optimization)
                    command = [os.environ.get("CC", "cc"), "-std=c11", optimization,
                               str(stock_c), str(driver), "-o", str(binary)]
                    built = subprocess.run(command, text=True, capture_output=True)
                    receipt = {"command": command, "status": built.returncode, "stdout": built.stdout, "stderr": built.stderr}
                    row["execution"].append(receipt)
                    assert built.returncode == 0, receipt
                    ran = subprocess.run([str(binary)], text=True, capture_output=True)
                    receipt = {"command": [str(binary)], "status": ran.returncode, "stdout": ran.stdout, "stderr": ran.stderr}
                    row["execution"].append(receipt)
                    assert ran.returncode == 0, receipt
                except Exception:
                    row["failures"].append({"stage": "unchanged-C" + optimization, "failure": traceback.format_exc()})
            row["passed"] = not row["failures"]

        for core, native in (("stock", stock), ("kuna", KUNA_GHIDRA)):
            if core not in modes:
                continue
            for comments in (True, False):
                for types in (True, False):
                    row = {"core": core, "comments": comments, "types": types,
                           "mode": "successful_public_export", "passed": False, "failures": [], "execution": []}
                    report["rows"].append(row)
                    destination = output / (core + "-comments" + str(int(comments)) + "-types" + str(int(types)) + ".c")
                    header = destination.with_suffix(".h")
                    driver = destination.with_name(destination.stem + "-driver.c")
                    try:
                        driver.write_text('#include "' + header.name + '"\nextern int exported_word;\n'
                            'int main(void) { if(wire_result()!=42||wire_other()!=43)return 1;'
                            'exported_word=42;if(global_provider()!=42||global_consumer()!=42)return 2;'
                            'exported_word=-7;return global_provider()!=-7||global_consumer()!=-7; }\n')
                        options.setWARNCommentIncluded(comments)
                        options.setPLATECommentIncluded(comments)
                        options.setHeadCommentIncluded(comments)
                        with selected_core(native):
                            row["export_result"] = bool(exporter(types).export(File(str(destination)), program, None, ConsoleTaskMonitor()))
                        row["c"] = destination.read_text() if destination.is_file() else None
                        row["h"] = header.read_text() if header.is_file() else None
                        assert row["export_result"], row
                        header = destination.with_suffix(".h")
                        assert header.is_file()
                        body = row["c"]
                        assert all(name in body and name in row["h"]
                                   for name in ("wire_result", "wire_other"))
                        assert ("authored-export-comment" in body) == comments, body
                        assert ("ExportSource" in row["h"]) == types, row["h"]
                        assert "global_provider" in body and "global_consumer" in body
                        assert "exported_word" in body
                    except Exception:
                        row["failures"].append({"stage": "export", "failure": traceback.format_exc()})
                    for optimization in ("-O0", "-O2"):
                        try:
                            binary = destination.with_name(destination.stem + optimization)
                            command = [os.environ.get("CC", "cc"), "-std=c11", optimization,
                                       str(destination), str(driver), "-o", str(binary)]
                            built = subprocess.run(command, text=True, capture_output=True,
                                                   timeout=120 if core == "kuna" else None)
                            receipt = {"command": command, "status": built.returncode, "stdout": built.stdout, "stderr": built.stderr}
                            row["execution"].append(receipt)
                            assert built.returncode == 0, receipt
                            ran = subprocess.run([str(binary)], text=True, capture_output=True,
                                                 timeout=30 if core == "kuna" else None)
                            receipt = {"command": [str(binary)], "status": ran.returncode, "stdout": ran.stdout, "stderr": ran.stderr}
                            row["execution"].append(receipt)
                            assert ran.returncode == 0, receipt
                        except Exception:
                            row["failures"].append({"stage": "unchanged-C" + optimization, "failure": traceback.format_exc()})
                    row["passed"] = not row["failures"]
        try:
            assert source_snapshot(functions) == source_before
            assert int(program.getModificationNumber()) == revision_before
        except Exception:
            report["failures"].append({"stage": "positive-source-preservation", "failure": traceback.format_exc()})
        options.setWARNCommentIncluded(True)

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
        empty_function = ByteArrayOutputStream()
        encoder = PackedEncode(empty_function)
        encoder.openElement(ElementId.ELEM_FUNCTION)
        encoder.closeElement(ElementId.ELEM_FUNCTION)
        original_config = output / "original-empty-function-codec.json"
        original_config.write_text(json.dumps({
            "doc_open": base64.b64encode(document[:middle]).decode(),
            "doc_close": base64.b64encode(document[middle:]).decode(),
            "invalid_support": base64.b64encode(bytes(empty_function.toByteArray())).decode(),
        }))
        report["fault_inputs"] = {
            "selected": {"kind": "unknown4030", "config": str(config)},
            "original_stock": {"kind": "empty-extra-function", "config": str(original_config)},
            "empty_function_contract": "Ordinary receiver/export outcomes are observations, not acceptance of silent body loss. The original enhanced malformed/global-failure, both-sentinel and staging obligations remain conditional on enhanced capability; empty replacement markup is not the unknown4030 decoder error.",
        }
        proxy = Path(__file__).with_name("native_response_fault_proxy.py")
        def snapshot(native, healthy=True):
            field.set(None, native)
            interface = DecompInterface()
            try:
                assert interface.openProgram(program), str(interface.getLastMessage())
                rows = []
                def markup_tree(token):
                    if token is None:
                        return None
                    return {"kind": str(token.getClass().getSimpleName()), "text": str(token),
                            "children": [markup_tree(token.Child(i)) for i in range(token.numChildren())]}
                for selected in (function, other):
                    result = interface.decompileFunction(selected, 30, monitor)
                    high, markup, decompiled = result.getHighFunction(), result.getCCodeMarkup(), result.getDecompiledFunction()
                    received = {"entry": str(selected.getEntryPoint()), "error": str(result.getErrorMessage()),
                                 "completed": bool(result.decompileCompleted()), "valid": bool(result.isValid()),
                                 "high": high is not None, "markup": markup_tree(markup),
                                 "c": None if decompiled is None else str(decompiled.getC()),
                                 "signature": None if decompiled is None else str(decompiled.getSignature()),
                                 "pcode": [{"opcode": int(op.getOpcode()),
                                            "output_size": int(op.getOutput().getSize()) if op.getOutput() else None,
                                            "inputs": [{"size": int(vn.getSize()),
                                                        "constant": int(vn.getOffset()) if vn.isConstant() else None}
                                                       for vn in op.getInputs()]}
                                           for op in high.getPcodeOps()] if high is not None else None,
                                 "return_type": None if high is None else str(high.getFunctionPrototype().getReturnType())}
                    rows.append(received)
                    if healthy:
                        assert received["completed"], received
                        assert high is not None and markup is not None, received
                return rows
            finally:
                interface.dispose()
        neutral_log = output / "neutral-native.jsonl"
        neutral_launcher = output / "neutral-native.sh"
        argv = [sys.executable, str(proxy), stock, "pass", str(config), str(neutral_log)]
        neutral_launcher.write_text("#!/bin/sh\nexec " + " ".join(shlex.quote(arg) for arg in argv) + "\n")
        neutral_launcher.chmod(0o755)
        report["neutral_observer"] = {"equivalent": False}
        for label, native in (("direct", stock), ("observed", str(neutral_launcher))):
            try:
                report["neutral_observer"][label] = snapshot(native)
            except Exception:
                report["failures"].append({"stage": "neutral-" + label, "failure": traceback.format_exc()})
        try:
            assert report["neutral_observer"]["direct"] == report["neutral_observer"]["observed"], report["neutral_observer"]
            witnesses = [json.loads(line) for line in neutral_log.read_text().splitlines()]
            assert len([event for event in witnesses if event["phase"] == "document"]) == 2, witnesses
            report["neutral_observer"].update(equivalent=True, actual_documents=2)
        except Exception:
            report["failures"].append({"stage": "neutral-equivalence", "failure": traceback.format_exc()})
        fault_cases = [("malformed", "unknown4030", config)]
        if not enhanced:
            fault_cases.append(("malformed", "empty-extra-function", original_config))
        fault_cases.extend((mode, mode, config) for mode in ("crash", "cancelled"))
        for mode, kind, selected_config, warnings in (
                (mode, kind, selected_config, warnings)
                for mode, kind, selected_config in fault_cases if mode in modes
                for warnings in (True, False)):
            row = {"mode": mode, "fault_input": kind, "domain": report["domain"], "warnings": warnings,
                   "config": str(selected_config), "failures": [], "export_result": None, "recovery_commands": []}
            report["rows"].append(row)
            stem = "malformed-empty-extra-function" if kind == "empty-extra-function" else mode
            if not warnings:
                stem += "-no-comments"
            c_file, h_file = output / (stem + ".c"), output / (stem + ".h")
            sentinels = {c_file: b"original C destination\x00" + mode.encode(),
                         h_file: b"original header destination\x00" + mode.encode()}
            ready = False
            log, launcher = None, None
            try:
                options.setWARNCommentIncluded(warnings)
                for path, content in sentinels.items():
                    path.write_bytes(content)
                task_monitor = ConsoleTaskMonitor()
                if mode == "cancelled":
                    field.set(None, stock)
                    task_monitor.setCancelEnabled(True)
                    task_monitor.cancel()
                    assert task_monitor.isCancelled(), "Cancellation must be active before export"
                else:
                    log = output / (stem + "-native.jsonl")
                    launcher = output / (stem + "-native.sh")
                    argv = [sys.executable, str(proxy), stock, mode, str(selected_config), str(log)]
                    stderr = output / (stem + "-stderr.log")
                    row["proxy_command"] = argv
                    launcher.write_text("#!/bin/sh\nexec " + " ".join(shlex.quote(arg) for arg in argv) +
                                        " 2>" + shlex.quote(str(stderr)) + "\n")
                    launcher.chmod(0o755)
                    field.set(None, str(launcher))
                ready = True
            except Exception:
                row["failures"].append({"stage": "fault-setup", "failure": traceback.format_exc()})
            if ready and mode != "cancelled":
                try:
                    row["receiver"] = snapshot(str(launcher), healthy=False)
                except Exception:
                    row["failures"].append({"stage": "fault-receiver", "failure": traceback.format_exc()})
            if ready:
                try:
                    row["export_result"] = bool(exporter().export(File(str(c_file)), program, None, task_monitor))
                except Exception:
                    row["failures"].append({"stage": "fault-export", "failure": traceback.format_exc()})
            try:
                row["outputs"] = {
                    path.suffix: {"exists": path.is_file(),
                                  "bytes_base64": base64.b64encode(path.read_bytes()).decode() if path.is_file() else None,
                                  "text": path.read_text(errors="replace") if path.is_file() else None,
                                  "sentinel_unchanged": path.read_bytes() == content if path.is_file() else False}
                    for path, content in sentinels.items()}
                row["staging"] = [str(path) for path in output.glob("ghidra-cpp-*.tmp")]
            except Exception:
                row["failures"].append({"stage": "fault-output-capture", "failure": traceback.format_exc()})
            if kind == "unknown4030" and not enhanced:
                try:
                    assert all(not received["valid"] and received["error"] == "Unknown decompiler tag"
                               for received in row["receiver"]) and len(row["receiver"]) == 2, row
                except Exception:
                    row["failures"].append({"stage": "unknown-tag-cause", "failure": traceback.format_exc()})
            if kind == "empty-extra-function":
                row["ordinary_observation_only"] = True
                row["acceptance_scope"] = "Fault observation/source preservation/recovery only; useful empty-markup C publication is not certified."
                row["conditional_requirement"] = report["enhanced_atomic_contract"]
            try:
                success = row["export_result"]
                if enhanced:
                    assert success is False, row
                else:
                    if mode == "cancelled":
                        assert success is False, row
                    elif kind != "empty-extra-function":
                        assert success is True, "Individual stock decompilation failures must not abort best-effort export"
            except Exception:
                row["failures"].append({"stage": "fault-export-status", "failure": traceback.format_exc()})
            try:
                assert len(row["outputs"]) == 2, row
                if enhanced:
                    assert all(observed["exists"] and observed["sentinel_unchanged"]
                               for observed in row["outputs"].values()), row
                    row["sentinels_unchanged"] = True
                else:
                    assert all(observed["exists"] and not observed["sentinel_unchanged"]
                               for observed in row["outputs"].values()), row
                    row["destination_replaced"] = True
            except Exception:
                row["failures"].append({"stage": "fault-destinations", "failure": traceback.format_exc()})
            if enhanced:
                try:
                    assert not row["staging"], row
                    row["staging_removed"] = True
                except Exception:
                    row["failures"].append({"stage": "fault-staging", "failure": traceback.format_exc()})
            if not enhanced and kind != "empty-extra-function":
                try:
                    generated = row["outputs"][".c"]["text"]
                    assert "wire_result(" not in generated and "wire_other(" not in generated, generated
                    if mode != "cancelled":
                        if warnings:
                            assert "Unable to decompile" in generated and "wire_result" in generated and "wire_other" in generated, generated
                        else:
                            assert "Unable to decompile" not in generated and "wire_result" not in generated and "wire_other" not in generated, generated
                    row["stock_skip_content"] = True
                except Exception:
                    row["failures"].append({"stage": "fault-export-content", "failure": traceback.format_exc()})
            if mode != "cancelled":
                try:
                    events = [json.loads(line) for line in log.read_text().splitlines()]
                    faults = [event for event in events if event["phase"] == "fault"]
                    row["actual_native_response_faults"] = faults
                    assert faults and all(event["mode"] == mode and event["native_executable"] == stock for event in faults), events
                except Exception:
                    row["failures"].append({"stage": "native-fault-receipts", "failure": traceback.format_exc()})
            recovered = output / (stem + "-recovered.c")
            recovered_header = recovered.with_suffix(".h")
            recovered_driver = output / (stem + "-recovered-driver.c")
            try:
                field.set(None, stock)
                row["recovery_export_result"] = bool(exporter().export(File(str(recovered)), program, None, ConsoleTaskMonitor()))
                row["recovered_c"] = recovered.read_text() if recovered.is_file() else None
                row["recovered_h"] = recovered_header.read_text() if recovered_header.is_file() else None
                recovered_driver.write_text('#include "' + recovered_header.name + '"\nextern int exported_word;\n'
                    'int main(void){exported_word=42;return wire_result()!=42||wire_other()!=43||global_provider()!=42||global_consumer()!=42;}\n')
                assert row["recovery_export_result"], row
            except Exception:
                row["failures"].append({"stage": "recovery-export", "failure": traceback.format_exc()})
            for optimization in ("-O0", "-O2"):
                try:
                    binary = output / (stem + "-recovered" + optimization)
                    command = [os.environ.get("CC", "cc"), "-std=c11", optimization,
                               str(recovered), str(recovered_driver), "-o", str(binary)]
                    built = subprocess.run(command, text=True, capture_output=True)
                    receipt = {"command": command, "status": built.returncode, "stdout": built.stdout, "stderr": built.stderr}
                    row["recovery_commands"].append(receipt)
                    assert built.returncode == 0, receipt
                    ran = subprocess.run([str(binary)], text=True, capture_output=True)
                    receipt = {"command": [str(binary)], "status": ran.returncode, "stdout": ran.stdout, "stderr": ran.stderr}
                    row["recovery_commands"].append(receipt)
                    assert ran.returncode == 0, receipt
                except Exception:
                    row["failures"].append({"stage": "recovery" + optimization, "failure": traceback.format_exc()})
            row["actual_stock_recovery"] = not any(failure["stage"].startswith("recovery") for failure in row["failures"])
            try:
                row["source_after"] = source_snapshot(functions)
                row["revision_after"] = int(program.getModificationNumber())
                assert row["source_after"] == source_before
                assert row["revision_after"] == revision_before
            except Exception:
                row["failures"].append({"stage": "source-preservation", "failure": traceback.format_exc()})
            row["passed"] = not row["failures"]
        try:
            assert source_snapshot(functions) == source_before
            assert int(program.getModificationNumber()) == revision_before
        except Exception:
            report["failures"].append({"stage": "final-source-preservation", "failure": traceback.format_exc()})
        report["exporter_origin"] = str(exporter().getClass().getProtectionDomain().getCodeSource().getLocation())
        report["passed"] = not report["failures"] and all(row["passed"] for row in report["rows"])
    finally:
        program.release(owner)
        field.set(None, original)
except BaseException:
    report["failure"] = traceback.format_exc()
    raise
finally:
    (output / "cpp_exporter.json").write_text(json.dumps(report, indent=2) + "\n")
if not report["passed"]:
    raise SystemExit(1)
