#!/usr/bin/env python3
"""Genuine JVM constant-pool consumers and executable Java null/default replay."""
import hashlib
import json
import os
import re
from pathlib import Path
import subprocess
import traceback

from kuna_vs_stock import KUNA_GHIDRA, selected_core, start_ghidra, test_cores


def assert_java_type_binding(result, source_type, spelling, count):
    from java.util import ArrayList
    from ghidra.app.decompiler import ClangTypeToken
    from ghidra.app.decompiler.component import DecompilerUtils
    from ghidra.program.model.data import Pointer

    while isinstance(source_type, Pointer):
        source_type = source_type.getDataType()
    flattened = ArrayList()
    result.getCCodeMarkup().flatten(flattened)
    tokens = [token for token in flattened
              if isinstance(token, ClangTypeToken) and str(token.getText()) == spelling]
    assert len(tokens) == count, (spelling, tokens)
    for token in tokens:
        assert token.getDataType() == source_type, (spelling, token.getDataType(), source_type)
        if DecompilerUtils.getVarnodeRef(token) is None:
            assert DecompilerUtils.getDataType(token) == source_type, spelling
    return {"spelling": spelling, "source_type": str(source_type.getPathName()),
            "tokens": count}


def execute_null_methods(output, row, code):
    """Consume the emitted bodies unchanged, including Java's boxing semantics."""
    directory = output / (row["core"] + "-null-" + row["phase"])
    directory.mkdir(parents=True, exist_ok=True)
    methods = []
    names = {}
    row["signature_accommodations"] = []
    for name, return_type, parameters in [
        ("nil", r"(?:java\.lang\.)?Object", r"(?P<void>void)?"),
        ("isNil", "boolean", r"(?:java\.lang\.)?Object\s+[A-Za-z_$][\w$]*"),
    ]:
        text = code[name]
        signature = re.search(
            r"(?m)^[ \t]*" + return_type +
            r"\s+(?P<name>[A-Za-z_$][\w$]*)\s*\(\s*" + parameters + r"\s*\)",
            text,
        )
        assert signature, (name, text)
        names[name] = signature.group("name")
        # Stock's inherited Java printer spells a zero-parameter method with
        # C's `(void)`. Java 21 needs `()`. Only this signature token changes;
        # the reference-valued return/comparison bodies must reach javac intact.
        if name == "nil" and signature.group("void") is not None:
            start, end = signature.span("void")
            row["signature_accommodations"].append({
                "method": name, "before": signature.group(),
                "after": text[signature.start():start] + text[end:signature.end()],
            })
            text = text[:start] + text[end:]
        methods.append(text)
    consumer = f"""
public static void main(String[] args) {{
    Object value = new Object();
    Object original = CpoolConsumers.nil();
    boolean originalNull = CpoolConsumers.isNil(null);
    boolean originalObject = CpoolConsumers.isNil(value);
    RecoveredNull recovered = new RecoveredNull();
    Object actual = recovered.{names["nil"]}();
    boolean actualNull = recovered.{names["isNil"]}(null);
    boolean actualObject = recovered.{names["isNil"]}(value);
    System.out.println("original_nil=" + (original == null));
    System.out.println("emitted_nil=" + (actual == null));
    System.out.println("original_isNil_null=" + originalNull);
    System.out.println("emitted_isNil_null=" + actualNull);
    System.out.println("original_isNil_object=" + originalObject);
    System.out.println("emitted_isNil_object=" + actualObject);
    if (original != null || !originalNull || originalObject)
        throw new AssertionError("original javac producer");
    if (actual != null || !actualNull || actualObject)
        throw new AssertionError("emitted reference-null semantics");
}}
"""
    source = directory / "RecoveredNull.java"
    source.write_text("public class RecoveredNull {\n" + "\n".join(methods) + consumer + "\n}\n")
    row["consumer_source_sha256"] = hashlib.sha256(source.read_bytes()).hexdigest()
    row["consumer_composition"] = (
        "Emitted methods enclosed in one class and called as instance methods; "
        "no static modifier or method-body changes. Only recorded nil(void) "
        "signature accommodation is permitted."
    )
    row["consumer_commands"] = []
    commands = [
        [os.environ.get("JAVAC", "javac"), "-cp", str(output.resolve()),
         "-d", str(directory), str(source)],
        [os.environ.get("JAVA", "java"), "-cp",
         os.pathsep.join([str(directory.resolve()), str(output.resolve())]), "RecoveredNull"],
    ]
    for command in commands:
        result = subprocess.run(command, capture_output=True, text=True, timeout=120)
        receipt = {"command": command, "exit": result.returncode,
                   "stdout": result.stdout, "stderr": result.stderr}
        row["consumer_commands"].append(receipt)
        assert result.returncode == 0, receipt


def main():
    output = Path(os.environ.get("KUNA_SMOKE_OUT", "live-cpool"))
    output.mkdir(parents=True, exist_ok=True)
    report = {"completed": False, "passed": False, "producer": {}, "rows": [],
              "later_clauses": ["native completion", "High return typing", "string rendering", "array class and length rendering"]}
    try:
        source = Path(__file__).with_name("callable") / "fixtures/CpoolConsumers.java"
        command = [os.environ.get("JAVAC", "javac"), "-g", "-d", str(output), str(source)]
        produced = subprocess.run(command, capture_output=True, text=True, timeout=120)
        report["producer"] = {"command": command, "exit": produced.returncode,
                              "stdout": produced.stdout, "stderr": produced.stderr}
        assert produced.returncode == 0, report["producer"]
        pyghidra = start_ghidra()
        from jpype import JArray, JByte, JLong
        from java.util import ArrayList
        from ghidra.app.decompiler import DecompInterface, DecompileOptions
        from ghidra.program.model.data import BooleanDataType, Pointer
        from ghidra.program.model.lang import InjectPayload
        from ghidra.program.model.lang import ConstantPool
        from ghidra.program.model.lang import DecompilerLanguage
        from ghidra.program.model.pcode import PcodeOp
        from ghidra.util.task import ConsoleTaskMonitor
        from ghidra.javaclass.format import ClassFileAnalysisState
        monitor = ConsoleTaskMonitor()
        with pyghidra.open_program(output / "CpoolConsumers.class", project_location=str(output / "project"),
                                  project_name="cpool", analyze=True) as api:
            program = api.getCurrentProgram()
            assert str(program.getLanguageID()).startswith("JVM:"), str(program.getLanguageID())
            state = ClassFileAnalysisState.getState(program)
            assert state.getClassFile() is not None
            library = program.getCompilerSpec().getPcodeInjectLibrary()
            pool = library.getConstantPool(program)
            assert pool is not None
            functions = {str(fn.getName()): fn for fn in program.getFunctionManager().getFunctions(True)}
            wanted = ("constant", "length", "array", "readField", "callMethod", "method")
            targets = {}
            for name in wanted:
                matches = [fn for key, fn in functions.items() if key == name or key.startswith(name + "_")]
                assert len(matches) == 1, (name, list(functions))
                targets[name] = matches[0]
            null_targets = {}
            for name in ("nil", "isNil"):
                matches = [fn for key, fn in functions.items() if key == name or key.startswith(name + "_")]
                assert len(matches) == 1, (name, list(functions))
                null_targets[name] = matches[0]
            assert isinstance(null_targets["nil"].getReturnType(), Pointer)
            assert isinstance(null_targets["isNil"].getReturnType(), BooleanDataType)
            assert null_targets["nil"].getParameterCount() == 0
            assert null_targets["isNil"].getParameterCount() == 1
            assert isinstance(null_targets["isNil"].getParameter(0).getDataType(), Pointer)
            null_source_before = {name: str(fn.getSignature()) for name, fn in null_targets.items()}
            setup = report["genuine_cpool_inputs"] = []
            for name, fn in targets.items():
                operations = []
                for instruction in program.getListing().getInstructions(fn.getBody(), True):
                    for op in instruction.getPcode():
                        if op.getOpcode() == PcodeOp.CALLOTHER:
                            userop = program.getLanguage().getUserDefinedOpName(int(op.getInput(0).getOffset()))
                            payload = library.getPayload(InjectPayload.CALLOTHERFIXUP_TYPE, userop)
                            assert payload is not None, userop
                            context = library.buildInjectContext()
                            context.baseAddr = instruction.getAddress()
                            context.nextAddr = instruction.getAddress().add(instruction.getLength())
                            context.callAddr = context.baseAddr
                            context.inputlist = ArrayList()
                            for index in range(1, op.getNumInputs()):
                                context.inputlist.add(op.getInput(index))
                            operations.extend(list(payload.getPcode(program, context)))
                        else:
                            operations.append(op)
                refs = []
                for op in operations:
                    if op.getOpcode() != PcodeOp.CPOOLREF:
                        continue
                    identity = [int(op.getInput(index).getOffset()) for index in range(1, op.getNumInputs())]
                    record = pool.getRecord(JArray(JLong)(identity))
                    assert record.type is not None
                    row = {"function": name, "refs": identity, "tag": int(record.tag),
                           "type": str(record.type), "token": str(record.token)}
                    if name == "constant":
                        assert bytes((int(value) & 255) for value in record.byteData) == b"kuna_cpool_token"
                    elif name == "length":
                        assert str(record.token) == "length" and record.type.getLength() == 4
                    elif name == "array":
                        assert str(record.token) == "Object"
                    elif name in ("readField", "method"):
                        assert record.tag == ConstantPool.POINTER_FIELD and str(record.token) == "field"
                        assert record.type.getDataType().getLength() == 4
                    elif name == "callMethod":
                        assert record.tag == ConstantPool.POINTER_METHOD and str(record.token) == "method"
                        declared = record.type.getDataType()
                        assert declared.getReturnType().getLength() == 4
                        assert len(declared.getArguments()) == 2
                        assert declared.getArguments()[1].getDataType().getLength() == 4
                    refs.append(row)
                assert refs, (name, "Authentic JVM producer did not supply CPOOLREF")
                setup.extend(refs)
            source_before = {name: str(fn.getSignature()) for name, fn in targets.items()}
            def assert_return_constraints(returned, source):
                if isinstance(source, Pointer) and source.getDataType() is None:
                    assert isinstance(returned, Pointer)
                    assert returned.getLength() == program.getDefaultPointerSize()
                else:
                    assert returned.isEquivalent(source), (returned, source)

            array_instruction = next(instruction for instruction in
                program.getListing().getInstructions(targets["array"].getBody(), True)
                if str(instruction.getMnemonicString()) == "anewarray")
            instruction_address = array_instruction.getAddress()
            original_instruction = bytes((int(value) & 255) for value in array_instruction.getBytes())
            assert len(original_instruction) == 3 and original_instruction[0] == 0xbd

            def replace_array_reference(data):
                tx = program.startTransaction("Explicit malformed/restore JVM constant-pool source reference")
                try:
                    program.getListing().clearCodeUnits(instruction_address, instruction_address.add(2), False)
                    program.getMemory().setBytes(instruction_address, JArray(JByte)(data))
                    assert api.disassemble(instruction_address)
                finally:
                    program.endTransaction(tx, True)

            for core in test_cores():
                with selected_core(KUNA_GHIDRA if core == "kuna" else None):
                    interface = DecompInterface()
                    try:
                        options = DecompileOptions()
                        options.grabFromProgram(program)
                        assert options.getDisplayLanguage() == DecompilerLanguage.JAVA_LANGUAGE
                        assert interface.setOptions(options)
                        assert interface.openProgram(program), str(interface.getLastMessage())
                        for name, fn in targets.items():
                            row = {"core": core, "function": name}
                            report["rows"].append(row)
                            try:
                                result = interface.decompileFunction(fn, 60, monitor)
                                row["error"] = str(result.getErrorMessage())
                                row["completed"] = bool(result.decompileCompleted())
                                assert row["completed"], row
                                high = result.getHighFunction()
                                assert high is not None and result.getCCodeMarkup() is not None
                                returned = high.getFunctionPrototype().getReturnType()
                                code = str(result.getDecompiledFunction().getC())
                                row["c"] = code
                                (output / (core + "-" + name + ".java")).write_text(code)
                                assert_return_constraints(returned, fn.getReturnType())
                                if name == "constant":
                                    assert '"kuna_cpool_token"' in code, code
                                elif name == "length":
                                    assert re.search(r"\.\s*length\b", code), code
                                    parameter = fn.getParameter(0).getDataType()
                                    assert_return_constraints(
                                        high.getFunctionPrototype().getParam(0).getDataType(),
                                        parameter)
                                    row["datatype_binding"] = assert_java_type_binding(
                                        result, parameter, "int", 2)
                                elif name == "array":
                                    assert re.search(r"\bnew\s+(?:java\.lang\.)?Object\s*\[", code), code
                                elif name in ("readField", "method"):
                                    assert re.search(r"\.\s*field\b", code), code
                                    assert returned.getLength() == 4
                                elif name == "callMethod":
                                    assert re.search(r"\.\s*method\s*\(", code), code
                                    assert returned.getLength() == 4
                                assert str(fn.getSignature()) == source_before[name]
                                row["passed"] = True
                            except Exception:
                                row["passed"] = False
                                row["failure"] = traceback.format_exc()
                        row = {"core": core, "function": "array", "case": "malformed_constant_pool_record_recovery",
                               "producer": "original analyzed anewarray with reserved invalid pool index zero"}
                        report["rows"].append(row)
                        try:
                            try:
                                replace_array_reference(bytes([0xbd, 0, 0]))
                                interface.flushCache()
                                result = interface.decompileFunction(targets["array"], 60, monitor)
                                row["error"] = str(result.getErrorMessage())
                                assert not result.decompileCompleted(), row
                                assert result.getHighFunction() is None and result.getDecompiledFunction() is None, row
                                assert result.getCCodeMarkup() is None, row
                                assert not result.isTimedOut() and not result.isCancelled(), row
                                row["failed_without_fabricated_products"] = True
                            except Exception:
                                row["negative_failure"] = traceback.format_exc()
                            finally:
                                replace_array_reference(original_instruction)
                                interface.flushCache()
                            recovered = interface.decompileFunction(targets["array"], 60, monitor)
                            assert recovered.decompileCompleted(), str(recovered.getErrorMessage())
                            assert recovered.getHighFunction() is not None and recovered.getCCodeMarkup() is not None
                            recovered_code = str(recovered.getDecompiledFunction().getC())
                            assert re.search(r"\bnew\s+(?:java\.lang\.)?Object\s*\[", recovered_code), recovered_code
                            assert_return_constraints(
                                recovered.getHighFunction().getFunctionPrototype().getReturnType(),
                                targets["array"].getReturnType())
                            assert str(targets["array"].getSignature()) == source_before["array"]
                            row["valid_followup"] = True
                            row["passed"] = "negative_failure" not in row
                        except Exception:
                            row["passed"] = False
                            row["failure"] = traceback.format_exc()
                        # Keep the original six CPOOLREF producers and malformed
                        # recovery above independent of this additional contract.
                        # Default false is omitted by Java's sparse options;
                        # replay must restore Java defaults, not C's numeric zero.
                        for phase, language, null_token in [
                            ("default_java", DecompilerLanguage.JAVA_LANGUAGE, False),
                            ("explicit_null_on", DecompilerLanguage.JAVA_LANGUAGE, True),
                            ("default_java_again", DecompilerLanguage.JAVA_LANGUAGE, False),
                            ("default_c", DecompilerLanguage.C_LANGUAGE, False),
                            ("java_after_c", DecompilerLanguage.JAVA_LANGUAGE, False),
                        ]:
                            row = {"core": core, "case": "reference_null_replay", "phase": phase,
                                   "language": str(language), "java_null_option": null_token}
                            report["rows"].append(row)
                            try:
                                if phase != "default_java":
                                    replay = DecompileOptions()
                                    replay.grabFromProgram(program)
                                    replay.setDisplayLanguage(language)
                                    replay.setNullToken(null_token)
                                    assert interface.setOptions(replay)
                                interface.flushCache()
                                code = row["c"] = {}
                                row["source_signatures"] = {}
                                row["high_returns"] = {}
                                for name, fn in null_targets.items():
                                    result = interface.decompileFunction(fn, 60, monitor)
                                    assert result.decompileCompleted(), str(result.getErrorMessage())
                                    high = result.getHighFunction()
                                    assert high is not None and result.getCCodeMarkup() is not None
                                    returned = high.getFunctionPrototype().getReturnType()
                                    assert_return_constraints(returned, fn.getReturnType())
                                    row["high_returns"][name] = str(returned)
                                    assert str(fn.getSignature()) == null_source_before[name]
                                    row["source_signatures"][name] = str(fn.getSignature())
                                    if name == "isNil":
                                        parameter = high.getFunctionPrototype().getParam(0).getDataType()
                                        assert_return_constraints(parameter, fn.getParameter(0).getDataType())
                                    if language == DecompilerLanguage.JAVA_LANGUAGE:
                                        source_type = (fn.getReturnType() if name == "nil"
                                                       else fn.getParameter(0).getDataType())
                                        row.setdefault("datatype_bindings", {})[name] = (
                                            assert_java_type_binding(result, source_type, "Object", 1))
                                    code[name] = str(result.getDecompiledFunction().getC())
                                    (output / (core + "-null-" + phase + "-" + name + ".txt")).write_text(code[name])
                                if language == DecompilerLanguage.C_LANGUAGE:
                                    assert re.search(r"\bObject\s*\*", code["nil"]), code["nil"]
                                    assert re.search(r"\breturn\s+\([^)]*\*\)\s*(?:0x0|0)\s*;",
                                                     code["nil"]), code["nil"]
                                else:
                                    execute_null_methods(output, row, code)
                                row["passed"] = True
                            except Exception:
                                row["passed"] = False
                                row["failure"] = traceback.format_exc()
                    finally:
                        interface.dispose()
        report["completed"] = True
        report["passed"] = all(row["passed"] for row in report["rows"])
        assert report["passed"], "CPOOLREF consumer failures; see cpool_consumers.json"
    except BaseException:
        report["failure"] = traceback.format_exc()
        raise
    finally:
        (output / "cpool_consumers.json").write_text(json.dumps(report, indent=2) + "\n")


if __name__ == "__main__":
    main()
