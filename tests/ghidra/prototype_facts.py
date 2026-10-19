#!/usr/bin/env python3
"""Exercise current/callee prototype facts through real Ghidra and compiled C.

Uses the live-smoke environment from README.md. Requires a native C11 compiler
(CC or cc). Stock and kuna must preserve custom storage, per-entry isolation,
and return recovery after importing a stock DecompileDebug capture.
"""

import contextlib
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import traceback
import xml.etree.ElementTree as ET

import pyghidra

from kuna_vs_stock import KUNA_GHIDRA, export_program, get_exepath_field, start_ghidra, test_cores


C_TYPES = """#include <stdint.h>
typedef unsigned char byte;
typedef unsigned int uint;
typedef unsigned long ulong;
typedef unsigned long long ulonglong;
typedef uint8_t undefined1;
typedef uint16_t undefined2;
typedef uint32_t undefined4;
typedef uint64_t undefined8;
"""

class CCompileError(AssertionError):
    def __init__(self, stderr, body):
        self.stderr = stderr
        super().__init__(f"emitted C did not compile:\n{stderr}\n{body}")


def execute_c(body, preamble, driver, *, input_text=None):
    with tempfile.TemporaryDirectory(prefix="kuna-prototype-c-") as directory:
        source = Path(directory) / "witness.c"
        executable = Path(directory) / "witness"
        source.write_text(C_TYPES + preamble + "\n" + body + "\n" + driver)
        outputs = []
        for optimization in ("-O0", "-O2"):
            built = subprocess.run(
                [os.environ.get("CC", "cc"), "-std=c11", optimization, "-Wall", "-Werror",
                 str(source), "-o", str(executable)], capture_output=True, text=True, timeout=30,
            )
            if built.returncode != 0:
                raise CCompileError(built.stderr, body)
            ran = subprocess.run([str(executable)], input=input_text, capture_output=True, text=True, timeout=5)
            assert ran.returncode == 0, f"emitted C changed behavior ({optimization}, {ran.returncode}):\n{ran.stderr}\n{body}"
            outputs.append(ran.stdout)
        assert outputs[0] == outputs[1], outputs
        return outputs[0]


def selected_results(interface, functions, monitor):
    """Read authentic selected entries without a private planning prerequisite."""
    results = [interface.decompileFunction(function, 60, monitor) for function in functions]
    for result in results:
        assert result.decompileCompleted(), str(result.getErrorMessage())
        assert result.getHighFunction() is not None
        assert result.getCCodeMarkup() is not None
    return results


def source_facts(function):
    """Read the exact stock callback source, before native recovery mutates its view."""
    from error_recovery import field
    from ghidra.program.model.pcode import FunctionPrototype, HighFunction, PcodeDataTypeManager
    from ghidra.program.model.symbol import IllegalCharCppTransformer

    program = function.getProgram()
    high = HighFunction(function, program.getLanguage(), program.getCompilerSpec(),
                        PcodeDataTypeManager(program, IllegalCharCppTransformer()))
    high.grabFromFunction(0, False, False)
    prototype = high.getFunctionPrototype()
    locks = {name: bool(field(FunctionPrototype, name).get(prototype))
             for name in ("modellock", "voidinputlock", "outputlock")}
    parameters = [(str(prototype.getParam(i).getName()),
                   prototype.getParam(i).getDataType(), prototype.getParam(i).getStorage(),
                   bool(prototype.getParam(i).isNameLocked()),
                   bool(prototype.getParam(i).isTypeLocked()))
                  for i in range(prototype.getNumParams())]
    return locks, parameters, prototype


def parameter_markup(result):
    """Require authored input declarations to link to their actual High symbols/types."""
    from ghidra.app.decompiler import ClangVariableDecl, ClangVariableToken

    high = result.getHighFunction()
    prototype = high.getFunctionPrototype()
    tree = result.getCCodeMarkup()
    assert tree is not None
    declarations = []
    variables = []
    pending = [tree]
    while pending:
        node = pending.pop()
        if isinstance(node, ClangVariableDecl):
            declarations.append(node)
        elif isinstance(node, ClangVariableToken):
            variables.append(node)
        pending.extend(node.Child(i) for i in range(node.numChildren()))
    for i in range(prototype.getNumParams()):
        parameter = prototype.getParam(i)
        if not parameter.isNameLocked():
            continue
        matches = [node for node in declarations
                   if node.getHighSymbol() is not None and node.getHighSymbol().getId() == parameter.getId()]
        assert matches, (str(parameter.getName()), "missing linked parameter declaration")
        assert all(node.getDataType().isEquivalent(parameter.getDataType()) for node in matches)
        assert any(str(node.getText()) == str(parameter.getName())
                   and node.getHighSymbol(high) is not None
                   and node.getHighSymbol(high).getId() == parameter.getId() for node in variables), str(parameter.getName())


def execute_export(program, results, driver, *, output, stem, input_text=None, functions=(),
                   direct_call=None, provider_sources=(), provider_headers=()):
    """Execute unmodified stock CppExporter output and genuine selected providers."""
    from ghidra.app.decompiler import DecompInterface, DecompileOptions
    from ghidra.program.model.address import AddressSet
    from ghidra.program.model.pcode import PcodeOp
    from ghidra.util.task import ConsoleTaskMonitor

    monitor = ConsoleTaskMonitor()
    selection = AddressSet()
    pending = list(results)
    seen = set()
    interface = DecompInterface()
    options = DecompileOptions()
    options.grabFromProgram(program)
    options.setNamespaceStrategy(DecompileOptions.NamespaceStrategy.Never)
    interface.setOptions(options)
    try:
        assert interface.openProgram(program), str(interface.getLastMessage())
        pending.extend(interface.decompileFunction(function, 60, monitor) for function in functions)
        while pending:
            result = pending.pop()
            assert result.decompileCompleted(), str(result.getErrorMessage())
            high = result.getHighFunction()
            assert high is not None and result.getCCodeMarkup() is not None
            function = high.getFunction()
            entry = str(function.getEntryPoint())
            if entry in seen:
                continue
            seen.add(entry)
            selection.add(function.getBody())
            for op in high.getPcodeOps():
                if op.getOpcode() == PcodeOp.CALL:
                    target = program.getFunctionManager().getFunctionAt(op.getInput(0).getAddress())
                    if target is not None and not target.isExternal() and not target.isThunk():
                        if str(target.getEntryPoint()) not in seen:
                            pending.append(interface.decompileFunction(target, 60, monitor))
    finally:
        interface.dispose()
    body_path = output / f"{stem}-export.c"
    header_path = body_path.with_suffix(".h")
    driver_path = output / f"{stem}-driver.c"
    assert export_program(program, body_path, monitor=monitor, selection=selection, options=options), stem
    driver_path.write_text(f'#include "{header_path.name}"\n' + driver)
    if str(program.getLanguageID()) == "x86:LE:32:default":
        sys.path.insert(0, str(Path(__file__).resolve().parent / "callable"))
        from support import execute_i386_publication

        directory = output / f"{stem}-i386"
        directory.mkdir(exist_ok=True)
        observations = {}
        try:
            default_stdcall = str(program.getCompilerSpec().getDefaultCallingConvention().getName()) == "__stdcall"
            execute_i386_publication(observations, directory, header_path, body_path, driver_path,
                                     default_stdcall, direct_call=direct_call)
        finally:
            (directory / "execution.json").write_text(json.dumps(observations, indent=2) + "\n")
        return ""
    with tempfile.TemporaryDirectory(prefix="kuna-export-c-") as directory:
        executable = Path(directory) / "witness"
        outputs = []
        provider_includes = [argument for header in provider_headers
                             for argument in ("-include", str(header))]
        for optimization in ("-O0", "-O2"):
            built = subprocess.run(
                [os.environ.get("CC", "cc"), "-std=c11", optimization, "-Wall", "-Werror",
                 *provider_includes,
                 str(body_path), str(driver_path), *map(str, provider_sources),
                 "-o", str(executable)],
                capture_output=True, text=True, timeout=30,
            )
            if built.returncode != 0:
                raise CCompileError(built.stderr, body_path.read_text())
            ran = subprocess.run([str(executable)], input=input_text, capture_output=True,
                                 text=True, timeout=5)
            assert ran.returncode == 0, f"exported C changed behavior ({optimization}, {ran.returncode}):\n{ran.stderr}"
            outputs.append(ran.stdout)
        assert outputs[0] == outputs[1], outputs
        return outputs[0]


def main():
    start_ghidra()
    from jpype import JArray, JByte
    from java.io import File
    from java.lang import Object
    from ghidra.app.decompiler import DecompInterface, DecompileOptions
    from ghidra.app.emulator import EmulatorHelper
    from ghidra.program.database import ProgramDB
    from ghidra.program.flatapi import FlatProgramAPI
    from ghidra.program.model.data import (
        AbstractIntegerDataType, DataType, DataTypeConflictHandler, IntegerDataType, StructureDataType,
        UnsignedIntegerDataType, UnsignedLongLongDataType, VoidDataType,
    )
    from ghidra.program.model.lang import CompilerSpecID, LanguageID
    from ghidra.program.model.listing import Function, ParameterImpl, ReturnParameterImpl, Variable, VariableStorage
    from ghidra.program.model.pcode import PcodeOp, Varnode
    from ghidra.program.model.symbol import SourceType
    from ghidra.program.util import DefaultLanguageService
    from ghidra.util.task import ConsoleTaskMonitor

    output = Path(os.environ.get("KUNA_SMOKE_OUT", "live-prototype-out")).resolve()
    output.mkdir(parents=True, exist_ok=True)
    field = get_exepath_field()
    original_exepath = field.get(None)
    monitor = ConsoleTaskMonitor()
    language = DefaultLanguageService.getLanguageService().getLanguage(LanguageID("x86:LE:64:default"))
    compiler = language.getCompilerSpecByID(CompilerSpecID("gcc"))
    integer = IntegerDataType.dataType
    user = SourceType.USER_DEFINED
    rows = []

    @contextlib.contextmanager
    def program(name, bits=64):
        owner = Object()
        selected_language = language if bits == 64 else DefaultLanguageService.getLanguageService().getLanguage(
            LanguageID("x86:LE:32:default"))
        selected_compiler = compiler if bits == 64 else selected_language.getCompilerSpecByID(CompilerSpecID("windows"))
        value = ProgramDB(name, selected_language, selected_compiler, owner)
        try:
            yield value, FlatProgramAPI(value, monitor)
        finally:
            value.release(owner)

    @contextlib.contextmanager
    def transaction(value):
        tx = value.startTransaction("prototype fact fixture")
        try:
            yield
        except BaseException:
            value.endTransaction(tx, False)
            raise
        else:
            value.endTransaction(tx, True)

    def address(value, offset):
        return value.getAddressFactory().getDefaultAddressSpace().getAddress(offset)

    def function(value, api, offset, code, name):
        entry = address(value, offset)
        block = api.createMemoryBlock(name, entry, JArray(JByte)(code), False)
        block.setExecute(True)
        assert api.disassemble(entry), name
        result = api.createFunction(entry, name)
        assert result is not None, name
        return result

    def signature(fn, input_register=None, output_register=None, empty=False, returns=None):
        value = fn.getProgram()
        returns = integer if returns is None else returns
        custom = input_register is not None or output_register is not None
        parameters = [] if empty else [
            ParameterImpl("value", integer, value.getRegister(input_register), value)
            if input_register else ParameterImpl("value", integer, value)
        ]
        result = (ReturnParameterImpl(returns, value.getRegister(output_register), value)
                  if output_register else ReturnParameterImpl(returns, value))
        mode = (Function.FunctionUpdateType.CUSTOM_STORAGE if custom
                else Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS)
        fn.updateFunction("__stdcall", result, mode, True, user, JArray(Variable)(parameters))

    @contextlib.contextmanager
    def interface(value, core):
        field.set(None, KUNA_GHIDRA if core == "kuna" else None)
        result = DecompInterface()
        result.setOptions(DecompileOptions())
        try:
            assert result.openProgram(value), str(result.getLastMessage())
            yield result
        finally:
            result.dispose()

    def observe(ifc, fn, label, core, preamble, driver, call_contract=None, expect_void=False,
                current_contract=False, physical_targets=(), callable_unit=False):
        row = {"case": label, "core": core}
        rows.append(row)
        try:
            result = ifc.decompileFunction(fn, 30, monitor)
            row["completed"] = bool(result.decompileCompleted())
            row["error"] = str(result.getErrorMessage())
            assert row["completed"], row
            assert result.getHighFunction() is not None, row
            assert result.getCCodeMarkup() is not None, row
            decompiled = result.getDecompiledFunction()
            assert decompiled is not None, row
            row["c"] = str(decompiled.getC())
            (output / f"{label}-{core}.c").write_text(row["c"])
            prototype = result.getHighFunction().getFunctionPrototype()
            returned_type = prototype.getReturnType()
            row["return_type"] = str(returned_type)
            assert bool(returned_type.isEquivalent(VoidDataType.dataType)) == expect_void, row
            if current_contract:
                parameter_markup(result)
                _, _, authored = source_facts(fn)
                assert prototype.hasThisPointer() == authored.hasThisPointer(), row
                parameters = list(fn.getParameters())
                assert prototype.getNumParams() == len(parameters), row
                row["parameters"] = [
                    {"name": str(prototype.getParam(i).getName()),
                     "storage": str(prototype.getParam(i).getStorage()),
                     "type_locked": bool(prototype.getParam(i).isTypeLocked()),
                     "name_locked": bool(prototype.getParam(i).isNameLocked())}
                    for i in range(prototype.getNumParams())
                ]
                for index, parameter in enumerate(parameters):
                    decoded = prototype.getParam(index)
                    assert decoded.isThisPointer() == authored.getParam(index).isThisPointer(), row
                    assert decoded.isHiddenReturn() == authored.getParam(index).isHiddenReturn(), row
                    assert decoded.getStorage() == parameter.getVariableStorage(), row
                    assert decoded.getCategoryIndex() == index, row
                    assert decoded.getDataType().isEquivalent(parameter.getDataType()), row
                    if not parameter.isAutoParameter():
                        assert str(decoded.getName()) == str(parameter.getName()), row
                        assert decoded.isTypeLocked() and decoded.isNameLocked(), row
                    for piece in parameter.getVariableStorage().getVarnodes():
                        for vn in result.getHighFunction().getVarnodes(piece.getSize(), piece.getAddress()):
                            if vn.isInput():
                                high = vn.getHigh()
                                assert high is not None and high.getSymbol() is not None, row
                                assert high.getSymbol().getId() == decoded.getId(), row
                storage = fn.getReturn().getVariableStorage()
                assert returned_type.isEquivalent(fn.getReturn().getDataType()), row
                if not storage.isUnassignedStorage():
                    # HighFunction returns use the lowered pointer type and
                    # physical storage, not FunctionDB's forced-indirect flag.
                    expected_pieces = [(v.getAddress(), v.getSize()) for v in storage.getVarnodes()]
                    actual_pieces = [(v.getAddress(), v.getSize())
                                     for v in prototype.getReturnStorage().getVarnodes()]
                    assert actual_pieces == expected_pieces, row
            if call_contract is not None:
                contracts = [call_contract] if isinstance(call_contract, tuple) else call_contract
                calls = [op for op in result.getHighFunction().getPcodeOps()
                         if op.getOpcode() == PcodeOp.CALL]
                row["calls"] = [str(op) for op in calls]
                assert len(calls) == len(contracts), row
                for call_op, (target, argument, output_register) in zip(calls, contracts):
                    assert call_op.getInput(0).getAddress() == address(fn.getProgram(), target), row
                    assert call_op.getNumInputs() == 2, row
                    actual = call_op.getInput(1)
                    assert actual.isConstant() and actual.getOffset() == argument, row
                    if target in physical_targets:
                        # The LEA reads RDI, while its declared argument is EDI.
                        # The unchanged target + caller TU below proves the chosen
                        # execution-family declaration and adapter are compatible.
                        assert actual.getSize() in (4, 8), row
                        datatype = actual.getHigh().getDataType()
                        assert datatype.getLength() == actual.getSize(), row
                        if actual.getSize() == 8:
                            assert isinstance(datatype, AbstractIntegerDataType), row
                        else:
                            assert datatype.isEquivalent(integer), row
                        # MOV EDI,imm32 defines the upper half as zero, not sign bits.
                        assert 0 <= int(actual.getOffset()) < (1 << 32), row
                    else:
                        assert actual.getSize() == 4, row
                    result_storage = call_op.getOutput()
                    assert result_storage is not None and result_storage.getSize() == 4, row
                    assert result_storage.getAddress() == fn.getProgram().getRegister(output_register).getAddress(), row
            if callable_unit:
                row["stdout"] = execute_export(fn.getProgram(), [result], driver,
                                                output=output, stem=f"{label}-{core}")
                row["c_executed"] = True
            else:
                row["stdout"] = execute_c(row["c"], preamble, driver)
                row["c_executed"] = True
            row["passed"] = True
            print(f"PASS {core}: {label}", flush=True)
        except Exception:
            row["passed"] = False
            row["failure"] = traceback.format_exc()
            print(f"FAIL {core}: {label}\n{row['failure']}", flush=True)

    def call(site, target):
        return b"\xe8" + struct.pack("<i", target - site - 5)

    def caller_driver(name, expected):
        return (f"int main(void) {{ int result = {name}(); "
                f"return result != {expected} || calls != 1 || argument != 5; }}\n")

    try:
        for core in test_cores():
            with program("independent_source_locks") as (value, api):
                with transaction(value):
                    cases = []
                    for index, (name, supplied, named, model, output_type) in enumerate([
                        ("absent_declaration", False, False, False, False),
                        ("name_only", False, True, False, False),
                        ("input_only", True, True, False, False),
                        ("output_only", False, False, False, True),
                        ("model_only", False, False, True, False),
                        ("full_declaration", True, True, True, True),
                    ]):
                        fn = function(value, api, 0x5000 + index * 0x100,
                                      bytes.fromhex("8d4701c3"), name)
                        if supplied or named:
                            fn.updateFunction(None, ReturnParameterImpl(DataType.DEFAULT, value),
                                              Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS,
                                              False, user if supplied else SourceType.DEFAULT,
                                              JArray(Variable)([ParameterImpl("value" if named else None,
                                                                            integer, value)]))
                        if model:
                            fn.setCallingConvention("__stdcall")
                        if output_type:
                            fn.setReturnType(integer, user)
                        cases.append(fn)
                with interface(value, core) as ifc:
                    for fn in cases:
                        row = {"case": str(fn.getName()), "core": core}
                        rows.append(row)
                        try:
                            from error_recovery import field as java_field
                            from ghidra.program.model.pcode import FunctionPrototype
                            before = str(fn.getSignature())
                            expected, parameters, authored = source_facts(fn)
                            result = selected_results(ifc, [fn], monitor)[0]
                            decoded = result.getHighFunction().getFunctionPrototype()
                            parameter_markup(result)
                            row["source_locks"] = expected
                            row["result_locks"] = {
                                name: bool(java_field(FunctionPrototype, name).get(decoded))
                                for name in expected
                            }
                            normalized = dict(expected)
                            normalized["modellock"] = bool(
                                expected["modellock"] or expected["voidinputlock"]
                                or expected["outputlock"]
                                or (parameters and parameters[0][4])
                            )
                            row["expected_result_locks"] = normalized
                            assert row["result_locks"] == normalized, row
                            if expected["voidinputlock"]:
                                assert decoded.getNumParams() == 0, row
                            if expected["outputlock"]:
                                assert decoded.getReturnType().isEquivalent(authored.getReturnType()), row
                            if expected["modellock"]:
                                assert str(decoded.getModelName()) == str(authored.getModelName()), row
                            for index, (name, dtype, storage, name_locked, type_locked) in enumerate(parameters):
                                parameter = decoded.getParam(index)
                                assert parameter is not None
                                assert bool(parameter.isNameLocked()) == name_locked, row
                                assert bool(parameter.isTypeLocked()) == type_locked, row
                                if name_locked:
                                    assert str(parameter.getName()) == name, row
                                if type_locked:
                                    assert parameter.getDataType().isEquivalent(dtype), row
                                    assert parameter.getStorage() == storage, row
                            assert source_facts(fn)[0] == expected, row
                            assert str(fn.getSignature()) == before, row
                            row["passed"] = True
                        except Exception:
                            row["passed"] = False
                            row["failure"] = traceback.format_exc()

        with program("method_this_storage", bits=32) as (value, api):
            with transaction(value):
                fn = function(value, api, 0x1000, bytes.fromhex("8b01c3"), "method_value")
                fn.updateFunction("__thiscall", ReturnParameterImpl(integer, value),
                                  Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS,
                                  False, user, JArray(Variable)([]))
                assert fn.getAutoParameterCount() == 1
                assert fn.getParameter(0).getVariableStorage().getVarnodes()[0].getAddress() == value.getRegister("ECX").getAddress()
            for core in test_cores():
                with interface(value, core) as ifc:
                    observe(ifc, fn, "method_this_storage", core, "#define __thiscall\n",
                            "int main(void) { int value=42; return method_value(&value) != 42; }\n",
                            current_contract=True)

        with program("equal_shape_entry_effects") as (value, api):
            with transaction(value):
                plain = function(value, api, 0x1000, bytes.fromhex("8d4701c3"), "plain_effect")
                inline = function(value, api, 0x1100, bytes.fromhex("8d4701c3"), "inline_effect")
                noreturn = function(value, api, 0x1200, bytes.fromhex("ebfe"), "noreturn_effect")
                for fn in (plain, inline, noreturn):
                    signature(fn)
                inline.setInline(True)
                noreturn.setNoReturn(True)
            for core in test_cores():
                with interface(value, core) as ifc:
                    for order in ((plain, inline, noreturn), (noreturn, inline, plain)):
                        for fn in order:
                            row = {"case": "entry_effect_" + str(fn.getName()), "core": core}
                            rows.append(row)
                            try:
                                before = (str(fn.getSignature()), bool(fn.isInline()), bool(fn.hasNoReturn()))
                                result = selected_results(ifc, [fn], monitor)[0]
                                prototype = result.getHighFunction().getFunctionPrototype()
                                assert bool(prototype.isInline()) == bool(fn.isInline()), row
                                assert bool(prototype.hasNoReturn()) == bool(fn.hasNoReturn()), row
                                assert prototype.getNumParams() == 1, row
                                assert str(prototype.getParam(0).getName()) == "value", row
                                assert prototype.getParam(0).isTypeLocked(), row
                                assert before == (str(fn.getSignature()), bool(fn.isInline()), bool(fn.hasNoReturn())), row
                                row["passed"] = True
                            except Exception:
                                row["passed"] = False
                                row["failure"] = traceback.format_exc()
                        ifc.flushCache()

        for kind, incoming, outgoing, code, prefix, suffix, expected in [
            ("input", "R10D", "EAX", "4489d0c3", "41ba05000000", "c3", 5),
            ("output", "EDI", "EDX", "89fac3", "bf05000000", "89d0c3", 5),
            ("both", "R10D", "EDX", "4489d283c209c3", "41ba05000000", "89d0c3", 14),
            ("deindirect", "R10D", "EDX", "4489d283c209c3", "41ba05000000b800200000", "89d0c3", 14),
            ("inline", "R10D", "EDX", "4489d283c209c3", "41ba05000000", "89d0c3", 14),
        ]:
            name = f"custom_{kind}_caller"
            target_name = f"custom_{kind}_target"
            with program(name) as (value, api):
                with transaction(value):
                    target = function(value, api, 0x2000, bytes.fromhex(code), target_name)
                    signature(target, incoming, outgoing)
                    if kind == "inline":
                        target.setInline(True)
                    setup = bytes.fromhex(prefix)
                    caller = function(value, api, 0x1000,
                                      setup + (bytes.fromhex("ffd0") if kind == "deindirect"
                                               else call(0x1000 + len(setup), 0x2000))
                                      + bytes.fromhex(suffix), name)
                    if kind != "both":
                        signature(caller, empty=True)
                for core in test_cores():
                    with interface(value, core) as ifc:
                        if kind == "inline":
                            observe(ifc, caller, kind, core, "",
                                    f"int main(void) {{ return {name}() != {expected}; }}\n", [],
                                    callable_unit=True)
                        else:
                            observe(ifc, caller, kind, core, "",
                                    f"int main(void) {{ return {name}() != {expected}; }}\n",
                                    (0x2000, 5, outgoing), callable_unit=True)
                            preamble = ("static int calls, argument;\n"
                                        f"int {target_name}(int value) {{ ++calls; argument = value; "
                                        f"return value + {expected - 5}; }}\n")
                            observe(ifc, caller, kind + "_caller_occurrences", core, preamble,
                                    caller_driver(name, expected), (0x2000, 5, outgoing))
                        if kind == "both":
                            observe(ifc, target, "current_custom", core, "",
                                    f"int main(void) {{ return {target_name}(-9) != 0 || "
                                    f"{target_name}(5) != 14; }}\n", current_contract=True)
        with program("callee_isolation") as (value, api):
            with transaction(value):
                ordinary = function(value, api, 0x3000, bytes.fromhex("8d4701c3"), "ordinary_target")
                custom = function(value, api, 0x2000, bytes.fromhex("4489d283c209c3"), "custom_target")
                alternate = function(value, api, 0x4000, bytes.fromhex("4489d983c109c3"), "alternate_target")
                signature(ordinary)
                signature(custom, "R10D", "EDX")
                signature(alternate, "R11D", "ECX")
                api.createMemoryBlock("isolation_stack", address(value, 0x7000),
                                      JArray(JByte)(bytes(0x1000)), False)
                ordinary_case = (0x3000, 11, "EAX", "bf0b000000", "44")
                custom_case = (0x2000, 5, "EDX", "41ba05000000", "54")
                alternate_case = (0x4000, 7, "ECX", "41bb07000000", "4c")
                isolation_cases = []
                for order, entries in enumerate([
                    [ordinary_case, custom_case, alternate_case],
                    [alternate_case, custom_case, ordinary_case],
                ]):
                    entry = 0x1000 + order * 0x100
                    code = bytes.fromhex("4883ec18")
                    for index, (target, _, _, setup, storage) in enumerate(entries):
                        code += bytes.fromhex(setup)
                        code += call(entry + len(code), target)
                        # Save the first result, then accumulate in a stack slot
                        # so later calls cannot clobber an earlier result.
                        code += bytes.fromhex(("89" if index == 0 else "01") + storage + "240c")
                    code += bytes.fromhex("8b44240c4883c418c3")
                    fn = function(value, api, entry, code, f"isolation_{order}")
                    signature(fn, empty=True)
                    isolation_cases.append((fn, [item[:3] for item in entries]))
            for core in test_cores():
                with interface(value, core) as ifc:
                    targets = []
                    for target, argument, expected in ((ordinary, 11, 12), (custom, 5, 14), (alternate, 7, 16)):
                        observe(ifc, target, str(target.getName()), core, "",
                                f"int main(void) {{ return {target.getName()}({argument}) != {expected}; }}\n",
                                current_contract=True)
                        assert rows[-1]["passed"], rows[-1]
                        if core == "stock":
                            targets.append(rows[-1]["c"])
                    # Stock controls use genuine target fragments; native uses CppExporter.
                    preamble = "\n".join(targets)
                    for fn, contracts in isolation_cases:
                        emulator = EmulatorHelper(value)
                        try:
                            emulator.writeRegister("RSP", 0x7fe0)
                            emulator.writeMemory(address(value, 0x7fe0), JArray(JByte)((0x7ff0).to_bytes(8, "little")))
                            emulator.setBreakpoint(address(value, 0x7ff0))
                            assert emulator.run(fn.getEntryPoint(), None, monitor), str(emulator.getLastError())
                            assert emulator.getExecutionAddress() == address(value, 0x7ff0)
                            machine_result = int(str(emulator.readRegister("RAX"))) & 0xffffffff
                            assert machine_result == 42
                        finally:
                            emulator.dispose()
                        observe(ifc, fn, str(fn.getName()), core, preamble,
                                f"int main(void) {{ return {fn.getName()}() != 42; }}\n", contracts,
                                physical_targets=(0x3000,) if core == "kuna" else (),
                                callable_unit=True)
                        rows[-1]["machine_result"] = machine_result

        for core in test_cores():
            with program("prototype_edit") as (value, api):
                with transaction(value):
                    target = function(value, api, 0x2000, bytes.fromhex("4489d283c209c3"), "edited_target")
                    signature(target, "R10D", "EDX")
                    caller = function(value, api, 0x1000,
                        bytes.fromhex("41ba0500000041bb07000000") + call(0x100c, 0x2000)
                        + bytes.fromhex("89d0c3"), "edited_caller")
                    signature(caller, empty=True)
                    live_named = function(value, api, 0x3000,
                                          bytes.fromhex("8d4709c3"), "live_named")
                    signature(live_named, "EDI", "EAX")
                with interface(value, core) as ifc:
                    for index, (register, instruction, argument) in enumerate([
                        ("R10D", "4489d2", 5), ("R11D", "4489da", 7), ("R10D", "4489d2", 5),
                    ]):
                        if index:
                            with transaction(value):
                                value.getListing().clearCodeUnits(address(value, 0x2000), address(value, 0x2002), False)
                                value.getMemory().setBytes(address(value, 0x2000), JArray(JByte)(bytes.fromhex(instruction)))
                                assert api.disassemble(address(value, 0x2000))
                                signature(target, register, "EDX")
                                target.getParameter(0).setName("edited_value", user)
                            ifc.flushCache()
                        observe(ifc, caller, f"edit_{index}", core,
                                "",
                                f"int main(void) {{ return edited_caller() != {argument + 9}; }}\n",
                                (0x2000, argument, "EDX"), callable_unit=True)
                    for lifecycle in ("rename_retype", "unlock", "reset", "reopen"):
                        if lifecycle == "rename_retype":
                            with transaction(value):
                                for fn in (target, live_named):
                                    fn.getParameter(0).setName("unsigned_value", user)
                                    fn.getParameter(0).setDataType(UnsignedIntegerDataType.dataType, user)
                            ifc.flushCache()
                        elif lifecycle == "unlock":
                            with transaction(value):
                                for fn in (target, live_named):
                                    fn.setSignatureSource(SourceType.DEFAULT)
                            ifc.flushCache()
                        elif lifecycle == "reset":
                            ifc.resetDecompiler()
                        else:
                            ifc.closeProgram()
                            assert ifc.openProgram(value), str(ifc.getLastMessage())
                        row = {"case": "source_edit_" + lifecycle, "core": core}
                        rows.append(row)
                        try:
                            before = str(target.getSignature())
                            expected, parameters, _ = source_facts(target)
                            assert len(parameters) == 1, row
                            name, _, storage, name_locked, type_locked = parameters[0]
                            assert name == "unsigned_value" and name_locked, row
                            assert bool(type_locked) == (lifecycle == "rename_retype"), row
                            result = selected_results(ifc, [target], monitor)[0]
                            high = result.getHighFunction()
                            prototype = high.getFunctionPrototype()
                            matches = [prototype.getParam(index)
                                       for index in range(prototype.getNumParams())
                                       if prototype.getParam(index).getStorage() == storage]
                            for vn in high.locRange():
                                if not vn.isInput() or not any(
                                        vn.getAddress() == entry.getAddress()
                                        and vn.getSize() == entry.getSize()
                                        for entry in storage.getVarnodes()):
                                    continue
                                variable = vn.getHigh()
                                assert variable is not None and variable.getSymbol() is not None, row
                                matches.append(variable.getSymbol())
                            matches = list({int(symbol.getId()): symbol for symbol in matches}.values())
                            if lifecycle == "rename_retype":
                                parameter_markup(result)
                                assert prototype.getNumParams() == 1 and matches, row
                            for decoded in matches:
                                assert str(decoded.getName()) == "unsigned_value", row
                                assert bool(decoded.isNameLocked()) == name_locked, row
                                assert bool(decoded.isTypeLocked()) == type_locked, row
                                if lifecycle == "rename_retype":
                                    assert decoded.getDataType().isEquivalent(UnsignedIntegerDataType.dataType), row
                            assert source_facts(target)[:2] == (expected, parameters), row
                            assert str(target.getSignature()) == before, row
                            assert str(target.getParameter(0).getName()) == "unsigned_value", row
                            row["source_locks"] = expected
                            row["matching_live_symbols"] = [
                                {"id": int(symbol.getId()), "name": str(symbol.getName()),
                                 "storage": str(symbol.getStorage())} for symbol in matches
                            ]
                            row["name_contract"] = "Preserve authored source and matching live High names; unlocked custom storage need not survive as a formal"
                            row["passed"] = True
                        except Exception:
                            row["passed"] = False
                            row["failure"] = traceback.format_exc()
                        row = {"case": "live_source_name_" + lifecycle, "core": core}
                        rows.append(row)
                        try:
                            before = str(live_named.getSignature())
                            _, parameters, _ = source_facts(live_named)
                            assert len(parameters) == 1, row
                            name, _, storage, name_locked, type_locked = parameters[0]
                            result = selected_results(ifc, [live_named], monitor)[0]
                            parameter_markup(result)
                            prototype = result.getHighFunction().getFunctionPrototype()
                            matches = [prototype.getParam(index)
                                       for index in range(prototype.getNumParams())
                                       if prototype.getParam(index).getStorage() == storage]
                            assert len(matches) == 1, row
                            decoded = matches[0]
                            assert str(decoded.getName()) == name == "unsigned_value", row
                            assert decoded.isNameLocked() and name_locked, row
                            assert bool(decoded.isTypeLocked()) == bool(type_locked), row
                            if lifecycle == "rename_retype":
                                assert decoded.getDataType().isEquivalent(UnsignedIntegerDataType.dataType), row
                            assert str(live_named.getSignature()) == before, row
                            row["passed"] = True
                        except Exception:
                            row["passed"] = False
                            row["failure"] = traceback.format_exc()

        with program("recursive_inline") as (value, api):
            fixture = Path(__file__).resolve().parents[2] / "tests/datatests/inline.xml"
            code = bytes.fromhex(ET.parse(fixture).getroot().find("binaryimage/bytechunk").text)
            with transaction(value):
                block = api.createMemoryBlock("collatz_code", address(value, 0x100000), JArray(JByte)(code), False)
                block.setExecute(True)
                functions = []
                for offset, name, names in [
                    (0x10004c, "collatz1", ("a", "b")), (0x10006d, "collatz", ("val",)),
                ]:
                    assert api.disassemble(address(value, offset))
                    fn = api.createFunction(address(value, offset), name)
                    assert fn is not None
                    parameters = [ParameterImpl(n, integer, value) for n in names]
                    fn.updateFunction("__stdcall", ReturnParameterImpl(integer, value),
                                      Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS,
                                      False, user, JArray(Variable)(parameters))
                    fn.setInline(True)
                    functions.append(fn)
            for core in test_cores():
                with interface(value, core) as ifc:
                    observe(ifc, functions[1], "recursive_inline", core, "",
                            "int main(void) { return collatz(1)!=1 || collatz(2)!=1 || "
                            "collatz(7)!=1 || collatz(27)!=1; }\n",
                            current_contract=True, callable_unit=True)

        with program("aggregate_storage") as (value, api):
            with transaction(value):
                wide = UnsignedLongLongDataType.dataType
                big = StructureDataType("Big24", 0, value.getDataTypeManager())
                for name in ("a", "b", "c"):
                    big.add(wide, 8, name, None)
                big = value.getDataTypeManager().resolve(big, DataTypeConflictHandler.DEFAULT_HANDLER)
                assert big.getLength() == 24
                assert [big.getComponent(i).getOffset() for i in range(3)] == [0, 8, 16]
                joined = VariableStorage(value, JArray(Varnode)([
                    Varnode(value.getRegister(name).getAddress(), 8) for name in ("RCX", "RDX", "RAX")
                ]))
                assert joined.isValid() and joined.size() == 24
                aggregate_cases = []
                for index, (name, code, custom, formal) in enumerate([
                    ("aggregate_auto", "4889f8488937488d560148895708488d560248895710c3", False, True),
                    ("aggregate_custom", "4c89d0498d5201498d4a02c3", True, True),
                    ("aggregate_empty", "b801000000ba02000000b903000000c3", True, False),
                ]):
                    fn = function(value, api, 0x1000 + index * 0x100, bytes.fromhex(code), name)
                    result = ReturnParameterImpl(big, joined, value) if custom else ReturnParameterImpl(big, value)
                    parameters = ([] if not formal else [
                        ParameterImpl("q", wide, value.getRegister("R10"), value) if custom
                        else ParameterImpl("q", wide, value)
                    ])
                    mode = (Function.FunctionUpdateType.CUSTOM_STORAGE if custom
                            else Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS)
                    fn.updateFunction("__stdcall", result, mode, False, user, JArray(Variable)(parameters))
                    assert fn.getAutoParameterCount() == (0 if custom else 1)
                    assert fn.getParameterCount() == (int(formal) if custom else 2)
                    assert bool(fn.getReturn().getVariableStorage().isForcedIndirect()) == (not custom)
                    aggregate_cases.append((fn, custom, formal))
            for core in test_cores():
                with interface(value, core) as ifc:
                    for fn, custom, formal in aggregate_cases:
                        if custom:
                            driver = (f"int main(void) {{ Big24 result = {fn.getName()}({'5' if formal else ''}); "
                                      f"return result.a != {5 if formal else 1} || result.b != {6 if formal else 2} "
                                      f"|| result.c != {7 if formal else 3}; }}\n")
                        else:
                            driver = (f"int main(void) {{ Big24 result; Big24 *returned = {fn.getName()}(&result, 5); "
                                      "return returned != &result || result.a != 5 || result.b != 6 || result.c != 7; }\n")
                        observe(ifc, fn, str(fn.getName()), core,
                                "typedef struct Big24 { ulonglong a, b, c; } Big24;\n",
                                driver, current_contract=True)

        if "kuna" in test_cores():
            with program("upper_register_transfer") as (value, api):
                with transaction(value):
                    unsigned = UnsignedIntegerDataType.dataType
                    wide = UnsignedLongLongDataType.dataType
                    upper_address = value.getRegister("RDI").getAddress().add(4)
                    upper_storage = VariableStorage(value, JArray(Varnode)([
                        Varnode(upper_address, 4)
                    ]))
                    functions = []
                    for name, offset, code in [
                        ("upper_register_target", 0x2000, "4889f848c1e820c3"),
                        ("upper_register_indirect", 0x1000, "4883ec08488d05f50f0000ffd04883c408c3"),
                        ("upper_register_direct", 0x1100, "4883ec08e8f70e00004883c408c3"),
                    ]:
                        fn = function(value, api, offset, bytes.fromhex(code), name)
                        parameter = (ParameterImpl("upper", unsigned, upper_storage, value)
                                     if offset == 0x2000 else
                                     ParameterImpl("value", wide, value.getRegister("RDI"), value))
                        fn.updateFunction("__stdcall",
                                          ReturnParameterImpl(unsigned, value.getRegister("EAX"), value),
                                          Function.FunctionUpdateType.CUSTOM_STORAGE, True, user,
                                          JArray(Variable)([parameter]))
                        functions.append(fn)
                    installed = functions[0].getParameter(0).getVariableStorage().getVarnodes()[0]
                    assert installed.getAddress() == upper_address and installed.getSize() == 4

                original_results = []
                for fn in functions:
                    emulator = EmulatorHelper(value)
                    try:
                        emulator.writeRegister("RDI", 0x123456789abcdef0)
                        emulator.writeRegister("RSP", 0x8000)
                        emulator.writeMemoryValue(address(value, 0x8000), 8, 0x3000)
                        emulator.setBreakpoint(address(value, 0x3000))
                        assert emulator.run(fn.getEntryPoint(), None, monitor), str(emulator.getLastError())
                        actual = int(str(emulator.readRegister("EAX")))
                        assert actual == 0x12345678, (str(fn.getName()), hex(actual))
                        original_results.append({"function": str(fn.getName()), "result": hex(actual)})
                    finally:
                        emulator.dispose()
                rows.append({"case": "upper_register_instructions", "core": "emulator",
                             "passed": True, "results": original_results})

                # Stock shares the indirect-call defect; instruction semantics, not
                # stock parity, are the acceptance criterion for this regression.
                with interface(value, "kuna") as ifc:
                    observe(ifc, functions[0], "upper_register_target", "kuna", "",
                            "int main(void) { unsigned values[]={0,0x12345678,0x80000000,0xffffffff}; "
                            "for(unsigned i=0;i<4;++i) if(upper_register_target(values[i])!=values[i]) "
                            "return 1; return 0; }\n", current_contract=True)
                    assert rows[-1]["passed"], rows[-1]
                    for fn in functions[1:]:
                        observe(ifc, fn, str(fn.getName()), "kuna", "",
                                "int main(void) { ulonglong values[]={0x123456789abcdef0ULL,"
                                "0xfedcba9876543210ULL,0x00000001ffffffffULL,0xffffffff00000000ULL}; "
                                "for(unsigned i=0;i<4;++i) { unsigned expected=(unsigned)(values[i]>>32); "
                                f"if({fn.getName()}(values[i])!=expected) return 1; "
                                "} return 0; }\n", current_contract=True, callable_unit=True)

        with program("output_lock_controls") as (value, api):
            with transaction(value):
                typed = function(value, api, 0x1000, bytes.fromhex("b807000000c3"), "typed_return")
                untyped = function(value, api, 0x1100, bytes.fromhex("b807000000c3"), "untyped_return")
                locked_void = function(value, api, 0x1200, bytes.fromhex("b807000000c3"), "locked_void")
                signature(typed, empty=True)
                signature(locked_void, empty=True, returns=VoidDataType.dataType)
            for core in test_cores():
                with interface(value, core) as ifc:
                    for fn in (typed, untyped):
                        observe(ifc, fn, str(fn.getName()), core, "",
                                f"int main(void) {{ return {fn.getName()}() != 7; }}\n")
                    observe(ifc, locked_void, "locked_void", core, "",
                            "int main(void) { locked_void(); return 0; }\n", expect_void=True)

        capture = output / "stock-prototype.xml"
        with program("replay_source") as (value, api):
            with transaction(value):
                fn = function(value, api, 0x1100, bytes.fromhex("8d8734120000c3"), "replay_value")
                signature(fn)
            with interface(value, "stock") as ifc:
                ifc.enableDebug(File(str(capture)))
                observe(ifc, fn, "replay_original", "stock", "",
                        "int main(void) { return replay_value(-4660) != 0 || replay_value(5) != 4665; }\n")
                rows[-1]["role"] = "stock-debug-input-producer"
                rows[-1]["input_for"] = [f"{core}:replay_imported" for core in test_cores()]
        field.set(None, None)
        with tempfile.TemporaryDirectory(prefix="kuna-prototype-replay-") as directory:
            with pyghidra.open_program(capture, project_location=directory, project_name="replay",
                    analyze=True, loader="ghidra.app.util.opinion.DecompileDebugXmlLoader") as api:
                value = api.getCurrentProgram()
                fn = value.getFunctionManager().getFunctionAt(address(value, 0x1100))
                assert fn is not None, "debug importer lost the function"
                assert fn.getReturn().getVariableStorage().isUnassignedStorage(), "replay must exercise unassigned output storage"
                for core in test_cores():
                    with interface(value, core) as ifc:
                        observe(ifc, fn, "replay_imported", core, "",
                                "int main(void) { return replay_value(-4660) != 0 || replay_value(5) != 4665; }\n",
                                current_contract=True)
    finally:
        field.set(None, original_exepath)
        (output / "prototype_facts.json").write_text(json.dumps(rows, indent=2) + "\n")
    failed = [f"{row['core']}:{row['case']}" for row in rows if not row.get("passed")]
    assert not failed, f"prototype behavior failures: {failed}"


if __name__ == "__main__":
    main()
