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
import tempfile
import traceback
import xml.etree.ElementTree as ET

import pyghidra

from kuna_vs_stock import KUNA_GHIDRA, get_exepath_field


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
        built = subprocess.run(
            [os.environ.get("CC", "cc"), "-std=c11", "-O2", "-Wall", "-Werror",
             str(source), "-o", str(executable)], capture_output=True, text=True, timeout=30,
        )
        if built.returncode != 0:
            raise CCompileError(built.stderr, body)
        ran = subprocess.run([str(executable)], input=input_text, capture_output=True, text=True, timeout=5)
        assert ran.returncode == 0, f"emitted C changed behavior ({ran.returncode}):\n{ran.stderr}\n{body}"
        return ran.stdout


def execute_callable(program, results, driver, *, output, stem, input_text=None):
    """Execute an actual native publication, never repaired getC fragments."""
    from java.io import StringWriter
    from ghidra.app.decompiler import CallableSupport
    from ghidra.program.model.pcode import PcodeDataTypeManager
    from ghidra.program.model.symbol import IllegalCharCppTransformer

    publication = CallableSupport.Publication()
    try:
        for result in results:
            assert result.decompileCompleted(), str(result.getErrorMessage())
            support = result.getCallableSupport()
            assert support.isPresent(), "Kuna callable execution requires native support"
            publication.add(support.get())
        publication.validate()
        publication.sourceOwnership(PcodeDataTypeManager(program, IllegalCharCppTransformer()))
        header = StringWriter()
        body = StringWriter()
        publication.writeTypes(header)
        publication.writeDeclarations(header, True)
        publication.writeBodies(body)
        header_path = output / f"{stem}-publication.h"
        body_path = output / f"{stem}-publication.c"
        driver_path = output / f"{stem}-driver.c"
        header_path.write_text(str(header.toString()))
        include = f'#include "{header_path.name}"\n'
        body_path.write_text(include + str(body.toString()))
        driver_path.write_text(include + driver)
    finally:
        publication.close()
    with tempfile.TemporaryDirectory(prefix="kuna-callable-c-") as directory:
        executable = Path(directory) / "witness"
        built = subprocess.run(
            [os.environ.get("CC", "cc"), "-std=c11", "-O2", "-Wall", "-Werror",
             str(body_path), str(driver_path), "-o", str(executable)],
            capture_output=True, text=True, timeout=30,
        )
        if built.returncode != 0:
            raise CCompileError(built.stderr, str(body.toString()))
        ran = subprocess.run([str(executable)], input=input_text, capture_output=True,
                             text=True, timeout=5)
        assert ran.returncode == 0, f"published C changed behavior ({ran.returncode}):\n{ran.stderr}"
        return ran.stdout


def main():
    pyghidra.start()
    from jpype import JArray, JByte
    from java.io import File
    from java.lang import Object
    from ghidra.app.decompiler import DecompInterface, DecompileOptions
    from ghidra.app.emulator import EmulatorHelper
    from ghidra.program.database import ProgramDB
    from ghidra.program.flatapi import FlatProgramAPI
    from ghidra.program.model.data import (
        AbstractIntegerDataType, DataTypeConflictHandler, IntegerDataType, StructureDataType,
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
    def program(name):
        owner = Object()
        value = ProgramDB(name, language, compiler, owner)
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
            decompiled = result.getDecompiledFunction()
            assert decompiled is not None, row
            row["c"] = str(decompiled.getC())
            (output / f"{label}-{core}.c").write_text(row["c"])
            prototype = result.getHighFunction().getFunctionPrototype()
            returned_type = prototype.getReturnType()
            row["return_type"] = str(returned_type)
            assert bool(returned_type.isEquivalent(VoidDataType.dataType)) == expect_void, row
            if current_contract:
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
                            assert isinstance(datatype, AbstractIntegerDataType) and not datatype.isSigned(), row
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
                row["stdout"] = execute_callable(fn.getProgram(), [result], driver,
                                                output=output, stem=f"{label}-{core}")
            else:
                row["stdout"] = execute_c(row["c"], preamble, driver)
            row["c_executed"] = True
            if core == "kuna" and row.get("c_executed"):
                row["callable_export_refused"] = "/* callable transport:" in row["c"]
                assert not row["callable_export_refused"], row
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
                preamble = ("static int calls, argument;\n"
                            f"int {target_name}(int value) {{ ++calls; argument = value; "
                            f"return value + {expected - 5}; }}\n")
                for core in ("stock", "kuna"):
                    with interface(value, core) as ifc:
                        if kind == "inline":
                            observe(ifc, caller, kind, core, "",
                                    f"int main(void) {{ return {name}() != {expected}; }}\n", [])
                        else:
                            observe(ifc, caller, kind, core, preamble, caller_driver(name, expected),
                                    (0x2000, 5, outgoing))
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
            for core in ("stock", "kuna"):
                with interface(value, core) as ifc:
                    targets = []
                    for target, argument, expected in ((ordinary, 11, 12), (custom, 5, 14), (alternate, 7, 16)):
                        observe(ifc, target, str(target.getName()), core, "",
                                f"int main(void) {{ return {target.getName()}({argument}) != {expected}; }}\n",
                                current_contract=True)
                        assert rows[-1]["passed"], rows[-1]
                        if core == "stock":
                            targets.append(rows[-1]["c"])
                    # Stock controls use the genuine target fragments. Kuna
                    # execution uses the actual native callable publication.
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
                                callable_unit=core == "kuna")
                        rows[-1]["machine_result"] = machine_result

        for core in ("stock", "kuna"):
            with program("prototype_edit") as (value, api):
                with transaction(value):
                    target = function(value, api, 0x2000, bytes.fromhex("4489d283c209c3"), "edited_target")
                    signature(target, "R10D", "EDX")
                    caller = function(value, api, 0x1000,
                        bytes.fromhex("41ba0500000041bb07000000") + call(0x100c, 0x2000)
                        + bytes.fromhex("89d0c3"), "edited_caller")
                    signature(caller, empty=True)
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
                            ifc.flushCache()
                        observe(ifc, caller, f"edit_{index}", core,
                                "int edited_target(int x) { return x + 9; }\n",
                                f"int main(void) {{ return edited_caller() != {argument + 9}; }}\n",
                                (0x2000, argument, "EDX"))

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
            for core in ("stock", "kuna"):
                with interface(value, core) as ifc:
                    observe(ifc, functions[1], "recursive_inline", core, "",
                            "int main(void) { return collatz(1)!=1 || collatz(2)!=1 || "
                            "collatz(7)!=1 || collatz(27)!=1; }\n",
                            current_contract=True, callable_unit=core == "kuna")

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
            for core in ("stock", "kuna"):
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
            for core in ("stock", "kuna"):
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
        field.set(None, None)
        with tempfile.TemporaryDirectory(prefix="kuna-prototype-replay-") as directory:
            with pyghidra.open_program(capture, project_location=directory, project_name="replay",
                    analyze=True, loader="ghidra.app.util.opinion.DecompileDebugXmlLoader") as api:
                value = api.getCurrentProgram()
                fn = value.getFunctionManager().getFunctionAt(address(value, 0x1100))
                assert fn is not None, "debug importer lost the function"
                assert fn.getReturn().getVariableStorage().isUnassignedStorage(), "replay must exercise unassigned output storage"
                for core in ("stock", "kuna"):
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
