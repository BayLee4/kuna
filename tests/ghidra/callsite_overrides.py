#!/usr/bin/env python3
"""Check caller-owned overrides with real Ghidra and unchanged emitted C.

Uses the suite environment in README.md. No input binary is required.
The genuine library consumers require a native C11 compiler and SDK/libc.
Darwin imports use the normal pyghidra host; Linux additionally requires ldd
and real shared libraries importable by Ghidra for its normal symbol resolver.
UNKNOWN/unmodeled providers retain actual source provenance, never a libc guess.
The installed stock FormatStringAnalyzer supplies the printf/scanf overrides.
Library consumers use genuine host imports; no stock-only synthetic analyzer matrix.
The selected test group controls independent native-core observations, not the
stock-native Java analyzer/import producers needed by the Kuna product cases.
Stock controls assert correct outcomes; their failures remain real failures.
"""

import contextlib
import json
import os
from pathlib import Path
import platform
import struct
import subprocess
import tempfile
import traceback
import xml.etree.ElementTree as ET

PREAMBLE = "typedef long long longlong;\n#define __cdecl\n#define __stdcall\n#define __fastcall\n"

# Vary one returned field at a time. The expected sums come from the original
# caller's three loads and additions, not from inspecting or changing emitted C.
AGGREGATE_RESULTS = (
    ((1, 7, 25), 33),
    ((12, 7, 25), 44),
    ((1, 32, 25), 58),
    ((1, 7, 93), 101),
)


def execute_native_caller(code, preamble, declaration, driver):
    """Link the actual caller instructions to the same genuine variadic witness."""
    from prototype_facts import C_TYPES

    with tempfile.TemporaryDirectory(prefix="kuna-callsite-native-") as directory:
        source = Path(directory) / "witness.c"
        assembly = Path(directory) / "caller.s"
        executable = Path(directory) / "witness"
        source.write_text(C_TYPES + PREAMBLE + preamble + "\n" + declaration + "\n" + driver)
        symbol = "_big_invoke" if platform.system() == "Darwin" else "big_invoke"
        assembly.write_text(
            f".text\n.globl {symbol}\n.p2align 2\n{symbol}:\n.byte "
            + ",".join(str(byte) for byte in code) + "\n"
        )
        built = subprocess.run(
            [os.environ.get("CC", "cc"), "-std=c11", "-O2", "-Wall", "-Werror",
             str(source), str(assembly), "-o", str(executable)],
            capture_output=True, text=True, timeout=30,
        )
        assert built.returncode == 0, f"original caller did not compile:\n{built.stderr}"
        ran = subprocess.run([str(executable)], capture_output=True, text=True, timeout=5)
        assert ran.returncode == 0, f"original caller violated native ABI ({ran.returncode}): {ran.stderr}"
        return ran.stdout


def run(output, report):
    import pyghidra

    from error_recovery import field as java_field
    from kuna_vs_stock import KUNA_GHIDRA, get_exepath_field, start_ghidra, test_cores
    from prototype_facts import execute_c, execute_export, parameter_markup, selected_results, source_facts

    cores = test_cores()
    report["test_group"] = "product" if cores == ("kuna",) else "stock-controls"
    report["selected_cores"] = list(cores)
    report["producer_scope"] = {
        "format_overrides": "Installed Java FormatStringAnalyzer with stock-native producer authority",
        "native_imports": "Genuine host imports analyzed with stock native before selected-core consumption",
    }
    start_ghidra()
    from jpype import JArray, JByte
    from java.io import File
    from java.lang import Object
    from ghidra.app.decompiler import DecompInterface, DecompileOptions, DecompileProcess
    from ghidra.app.emulator import EmulatorHelper
    from ghidra.app.plugin.core.string.variadic import FormatStringAnalyzer
    from ghidra.app.util.importer import MessageLog
    from ghidra.program.database import ProgramDB
    from ghidra.program.flatapi import FlatProgramAPI
    from ghidra.program.model.address import AddressSet
    from ghidra.program.model.data import (
        CharDataType, DataTypeConflictHandler, DoubleDataType, FloatDataType, FunctionDefinitionDataType,
        IntegerDataType, LongLongDataType, ParameterDefinition, ParameterDefinitionImpl,
        PointerDataType, ShortDataType, StructureDataType, UnsignedLongLongDataType, VoidDataType,
    )
    from ghidra.program.model.lang import CompilerSpecID, LanguageID
    from ghidra.program.model.listing import Function, ParameterImpl, ReturnParameterImpl, Variable
    from ghidra.program.model.listing import FlowOverride, Library
    from ghidra.program.model.mem import MemoryBlock
    from ghidra.program.model.pcode import HighFunction, HighFunctionDBUtil, PcodeOp
    from ghidra.program.model.symbol import RefType, SourceType
    from ghidra.program.util import DefaultLanguageService
    from ghidra.util.task import ConsoleTaskMonitor

    field = get_exepath_field()
    original = field.get(None)
    monitor = ConsoleTaskMonitor()
    integer, wide, short = IntegerDataType.dataType, LongLongDataType.dataType, ShortDataType.dataType
    user = SourceType.USER_DEFINED
    rows = report["rows"]

    @contextlib.contextmanager
    def program(name, bits=64, apple=False):
        language_id = "AARCH64:LE:64:AppleSilicon" if apple else f"x86:LE:{bits}:default"
        language = DefaultLanguageService.getLanguageService().getLanguage(LanguageID(language_id))
        compiler_id = "default" if apple else ("gcc" if bits == 64 else "windows")
        compiler = language.getCompilerSpecByID(CompilerSpecID(compiler_id))
        owner = Object()
        value = ProgramDB(name, language, compiler, owner)
        try:
            yield value, FlatProgramAPI(value, monitor)
        finally:
            value.release(owner)

    @contextlib.contextmanager
    def transaction(value):
        tx = value.startTransaction("callsite override fixture")
        try:
            yield
        except BaseException:
            value.endTransaction(tx, False)
            raise
        else:
            value.endTransaction(tx, True)

    def address(value, offset):
        return value.getAddressFactory().getDefaultAddressSpace().getAddress(offset)

    def memory(value, api, offset, data, name, executable=True):
        block = api.createMemoryBlock(name, address(value, offset), JArray(JByte)(data), False)
        block.setExecute(executable)
        return block

    def function(value, api, offset, code, name):
        memory(value, api, offset, code, name)
        assert api.disassemble(address(value, offset)), name
        fn = api.createFunction(address(value, offset), name)
        assert fn is not None, name
        return fn

    def signature(fn, parameters, result=integer, model="__stdcall", varargs=False):
        value = fn.getProgram()
        args = [ParameterImpl(name, dtype, value) for name, dtype in parameters]
        fn.updateFunction(model, ReturnParameterImpl(result, value),
                          Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS,
                          False, user, JArray(Variable)(args))
        fn.setVarArgs(varargs)

    def external_function(value, offset, name):
        # Match ElfProgramBuilder's absent-body external linkage: a RAM symbol
        # in an artificial, uninitialized EXTERNAL block delegates its source
        # declaration to a real external Function. No target instructions exist.
        entry = address(value, offset)
        block = value.getMemory().createUninitializedBlock(
            MemoryBlock.EXTERNAL_BLOCK_NAME, entry, 1, False)
        block.setArtificial(True)
        external = value.getExternalManager().addExtFunction(
            Library.UNKNOWN, name, None, SourceType.IMPORTED).getFunction()
        target = value.getFunctionManager().createFunction(
            None, entry, AddressSet(entry), SourceType.IMPORTED)
        target.setThunkedFunction(external)
        assert external.isExternal() and external.getEntryPoint().isExternalAddress()
        assert target.isThunk() and target.getThunkedFunction(True) == external
        assert not block.isInitialized() and not block.isExecute()
        assert value.getListing().getInstructionAt(entry) is None
        return target

    def fingerprint(fn):
        return (str(fn.getSignature()), str(fn.getReturn().getVariableStorage()),
                tuple((str(p.getName()), str(p.getDataType()), str(p.getVariableStorage()))
                      for p in fn.getParameters()), bool(fn.hasVarArgs()), bool(fn.hasNoReturn()))

    def override(fn, site, types, result=integer, model="__stdcall", varargs=False):
        definition = FunctionDefinitionDataType("site_signature", fn.getProgram().getDataTypeManager())
        definition.setCallingConvention(model)
        definition.setReturnType(result)
        definition.setArguments(JArray(ParameterDefinition)([
            ParameterDefinitionImpl(f"arg{i}", dtype, None) for i, dtype in enumerate(types)
        ]))
        definition.setVarArgs(varargs)
        namespace = HighFunction.findOverrideSpace(fn)
        prior = [] if namespace is None else [
            (symbol, HighFunctionDBUtil.readOverride(symbol))
            for symbol in fn.getProgram().getSymbolTable().getSymbols(namespace)
            if symbol.getAddress() == address(fn.getProgram(), site)
            and HighFunctionDBUtil.readOverride(symbol) is not None
        ]
        assert len(prior) <= 1, "expected at most one override to replace"
        if prior:
            prior[0][0].delete()
        HighFunctionDBUtil.writeOverride(fn, address(fn.getProgram(), site), definition)
        if prior:
            prior[0][1].cleanupUnusedOverride()

    def remove_override(fn, site):
        namespace = HighFunction.findOverrideSpace(fn)
        assert namespace is not None, "missing caller override namespace"
        matches = []
        for symbol in fn.getProgram().getSymbolTable().getSymbols(namespace):
            record = HighFunctionDBUtil.readOverride(symbol)
            if record is not None and symbol.getAddress() == address(fn.getProgram(), site):
                matches.append((symbol, record))
        assert len(matches) == 1, "expected exactly one override to remove"
        symbol, record = matches[0]
        symbol.delete()
        record.cleanupUnusedOverride()

    @contextlib.contextmanager
    def interface(value, core):
        field.set(None, KUNA_GHIDRA if core == "kuna" else None)
        ifc = DecompInterface()
        options = DecompileOptions()
        options.grabFromProgram(value)
        ifc.setOptions(options)
        try:
            assert ifc.openProgram(value), str(ifc.getLastMessage())
            yield ifc
        finally:
            ifc.dispose()

    def observe(ifc, fn, label, core, expected, preamble, driver, opcode=None,
                returns=None, committed_parameters=False,
                physical_input_size=None, input_text=None, callable_unit=False, functions=(),
                provider_sources=(), provider_headers=()):
        row = {"case": label, "core": core}
        rows.append(row)
        result = None
        try:
            result = ifc.decompileFunction(fn, 60, monitor)
            row["completed"] = bool(result.decompileCompleted())
            row["error"] = str(result.getErrorMessage())
            assert row["completed"], row
            high = result.getHighFunction()
            assert high is not None and result.getDecompiledFunction() is not None, row
            assert result.getCCodeMarkup() is not None, row
            if committed_parameters:
                parameter_markup(result)
                prototype = high.getFunctionPrototype()
                _, authored, _ = source_facts(fn)
                parameters = list(fn.getParameters())
                assert prototype.getNumParams() == len(parameters), row
                for i, parameter in enumerate(parameters):
                    decoded = prototype.getParam(i)
                    assert decoded.getDataType().isEquivalent(parameter.getDataType()), row
                    assert decoded.getStorage() == parameter.getVariableStorage(), row
                    assert decoded.getCategoryIndex() == i, row
                    assert bool(decoded.isNameLocked()) == authored[i][3], row
                    assert bool(decoded.isTypeLocked()) == authored[i][4], row
                    if authored[i][3]:
                        assert str(decoded.getName()) == authored[i][0], row
            row["c"] = str(result.getDecompiledFunction().getC())
            (output / f"{label}-{core}.c").write_text(row["c"])
            calls = [op for op in high.getPcodeOps() if op.getOpcode() in (PcodeOp.CALL, PcodeOp.CALLIND)]
            row["calls"] = [str(op) for op in calls]
            assert len(calls) == len(expected), row
            for op, (site, arguments) in zip(calls, expected):
                assert op.getSeqnum().getTarget() == address(fn.getProgram(), site), row
                if opcode is not None:
                    assert op.getOpcode() == opcode, row
                assert op.getNumInputs() == len(arguments) + 1, row
                if returns is not None and site in returns:
                    out = op.getOutput()
                    if returns[site].isEquivalent(VoidDataType.dataType):
                        assert out is None, row
                    else:
                        assert out is not None and out.getSize() == returns[site].getLength(), row
                        assert out.getHigh().getDataType().isEquivalent(returns[site]), row
                for index, (size, dtype, constant) in enumerate(arguments, 1):
                    vn = op.getInput(index)
                    if physical_input_size is not None:
                        assert vn.getSize() >= physical_input_size, row
                    if size is not None:
                        assert vn.getSize() == size, row
                    if dtype is not None:
                        assert vn.getHigh() is not None and vn.getHigh().getDataType().isEquivalent(dtype), row
                    if constant is not None:
                        assert constant_value(vn) == constant, row
            row["ir_passed"] = True
            if callable_unit:
                row["stdout"] = execute_export(fn.getProgram(), [result], driver,
                                                output=output, stem=f"{label}-{core}",
                                                input_text=input_text, functions=functions,
                                                provider_sources=provider_sources,
                                                provider_headers=provider_headers)
                row["c_executed"] = True
            else:
                row["stdout"] = execute_c(row["c"], PREAMBLE + preamble, driver, input_text=input_text)
                row["c_executed"] = True
            row["passed"] = True
            status = "PASS" if row["c_executed"] else "REFERENCE IR ONLY"
            print(f"{status} {core}: {label}", flush=True)
        except Exception:
            row["passed"] = False
            row["failure"] = traceback.format_exc()
            print(f"FAIL {core}: {label}\n{row['failure']}", flush=True)
        return result

    def constant_value(vn, depth=0):
        if vn.isConstant():
            return int(vn.getOffset()) & ((1 << (8 * vn.getSize())) - 1)
        assert depth < 12 and vn.getDef() is not None, f"not a constant address expression: {vn}"
        op = vn.getDef()
        values = [constant_value(v, depth + 1) for v in op.getInputs()]
        if op.getOpcode() in (PcodeOp.COPY, PcodeOp.CAST):
            result = values[0]
        elif op.getOpcode() in (PcodeOp.PTRSUB, PcodeOp.INT_ADD):
            result = values[0] + values[1]
        elif op.getOpcode() == PcodeOp.PTRADD:
            result = values[0] + values[1] * values[2]
        else:
            raise AssertionError(f"unexpected constant address operation: {op}")
        return result & ((1 << (8 * vn.getSize())) - 1)

    def machine_return(value, entry, inputs=(), *, extra_pop=None):
        emulator = EmulatorHelper(value)
        try:
            for register, value_in in inputs:
                emulator.writeRegister(register, value_in)
            size = 8 if value.getRegister("RSP") is not None else 4
            emulator.writeRegister("RSP" if size == 8 else "ESP", 0x7fe0)
            emulator.writeMemory(address(value, 0x7fe0), JArray(JByte)((0x7ff0).to_bytes(size, "little")))
            emulator.setBreakpoint(address(value, 0x7ff0))
            assert emulator.run(address(value, entry), None, monitor), str(emulator.getLastError())
            assert emulator.getExecutionAddress() == address(value, 0x7ff0)
            if extra_pop is not None:
                actual = int(str(emulator.readRegister("RSP" if size == 8 else "ESP")))
                assert actual == 0x7fe0 + extra_pop, actual
            return int(str(emulator.readRegister("RAX" if size == 8 else "EAX"))) & 0xffffffff
        finally:
            emulator.dispose()

    def call(site, target=0x2000):
        return b"\xe8" + struct.pack("<i", target - site - 5)

    def captured_overrides(capture):
        records = []
        for encoded in ET.parse(capture).getroot().findall(".//protooverride"):
            proto = encoded.find("prototype")
            internal = proto.find("internallist")
            records.append({"first": int(internal.get("first"), 0),
                            "inputs": len(internal.findall("param")),
                            "open": proto.get("dotdotdot", "false") == "true"})
        return records

    def direct_code(entry, first, second):
        return b"\xbf" + struct.pack("<I", first) + b"\xbe" + struct.pack("<I", second) + call(entry + 10) + b"\xc3"

    try:
        for core in cores:
            with program("direct_override") as (value, api):
                with transaction(value):
                    # One-input override/arity witness: the body ignores ESI in every phase.
                    target = function(value, api, 0x2000, bytes.fromhex("6bc70ac3"), "direct_target")
                    signature(target, [("first", integer)])
                    caller = function(value, api, 0x1000, direct_code(0x1000, 5, 6), "direct_caller")
                    other = function(value, api, 0x1100, direct_code(0x1100, 7, 8), "other_caller")
                    signature(caller, [])
                    signature(other, [])
                    memory(value, api, 0x7000, bytes(0x1000), "machine_stack", executable=False)
                unchanged = fingerprint(target)
                with interface(value, core) as ifc:
                    for phase in ("baseline", "override", "newest", "removed"):
                        if phase != "baseline":
                            with transaction(value):
                                if phase == "override":
                                    override(caller, 0x100a, [integer, integer])
                                elif phase == "newest":
                                    override(caller, 0x100a, [integer])
                                else:
                                    remove_override(caller, 0x100a)
                            ifc.flushCache()
                        two = phase == "override"
                        args = [(4, integer, 5)] + ([(4, integer, 6)] if two else [])
                        native = machine_return(value, 0x1000)
                        assert native == 50, native
                        observe(ifc, caller, "direct_" + phase, core, [(0x100a, args)], "",
                                "int main(void) { return direct_caller() != 50; }\n",
                                callable_unit=True)
                        rows[-1]["machine_result"] = native
                        if core == "stock":
                            preamble = ("static int calls;\nint direct_target(int x" + (", int y" if two else "")
                                        + ") { ++calls; " + ("(void)y; " if two else "") + "return x * 10; }\n")
                            observe(ifc, caller, "direct_occurrences_" + phase, core, [(0x100a, args)],
                                    preamble,
                                    "int main(void) { return direct_caller() != 50 || calls != 1; }\n")
                        native = machine_return(value, 0x1100)
                        assert native == 70, native
                        observe(ifc, other, "other_" + phase, core, [(0x110a, [(4, integer, 7)])],
                                "", "int main(void) { return other_caller() != 70; }\n",
                                callable_unit=True)
                        rows[-1]["machine_result"] = native
                        if core == "stock":
                            observe(ifc, other, "other_occurrences_" + phase, core,
                                    [(0x110a, [(4, integer, 7)])],
                                    "static int calls; int direct_target(int x) { ++calls; return x * 10; }\n",
                                    "int main(void) { return other_caller() != 70 || calls != 1; }\n")
                        assert fingerprint(target) == unchanged, "site override changed the global callee"

        # Preserve the original two-register body as a separate physical-state
        # witness. Its one-argument source declaration cannot erase the ESI read.
        if "kuna" in cores:
            with program("direct_physical_sum") as (value, api):
                with transaction(value):
                    target = function(value, api, 0x2000, bytes.fromhex("89f801f0c3"), "sum_target")
                    signature(target, [("first", integer)])
                    namespace = value.getSymbolTable().createNameSpace(value.getGlobalNamespace(), "Physical", user)
                    target.setParentNamespace(namespace)
                    caller = function(value, api, 0x1000, direct_code(0x1000, 5, 6), "sum_caller")
                    other = function(value, api, 0x1100, direct_code(0x1100, 7, 8), "sum_other")
                    signature(caller, [])
                    signature(other, [])
                    memory(value, api, 0x7000, bytes(0x1000), "machine_stack", executable=False)
                unchanged = fingerprint(target)
                with interface(value, "kuna") as ifc:
                    options = DecompileOptions()
                    options.setNamespaceStrategy(DecompileOptions.NamespaceStrategy.Never)
                    assert ifc.setOptions(options)
                    for phase in ("baseline", "override", "removed"):
                        if phase != "baseline":
                            with transaction(value):
                                if phase == "override":
                                    override(caller, 0x100a, [integer, integer])
                                else:
                                    remove_override(caller, 0x100a)
                            ifc.flushCache()
                        override_scope = HighFunction.findOverrideSpace(caller)
                        records = [] if override_scope is None else [
                            record for symbol in value.getSymbolTable().getSymbols(override_scope)
                            if (record := HighFunctionDBUtil.readOverride(symbol)) is not None
                            and record.getAddress() == address(value, 0x100a)
                        ]
                        assert len(records) == (1 if phase == "override" else 0), records
                        if records:
                            declared = records[0].getDataType()
                            assert not declared.hasVarArgs() and declared.getReturnType().isEquivalent(integer)
                            assert len(declared.getArguments()) == 2
                            assert all(arg.getDataType().isEquivalent(integer) for arg in declared.getArguments())
                        target_result = ifc.decompileFunction(target, 60, monitor)
                        assert target_result.decompileCompleted(), str(target_result.getErrorMessage())
                        source = target_result.getHighFunction().getFunctionPrototype()
                        assert source.getNumParams() == 1
                        first = source.getParam(0)
                        assert str(first.getName()) == "first"
                        assert first.isTypeLocked() and first.isNameLocked()
                        assert first.getDataType().getLength() == 4 and first.getDataType().isEquivalent(integer)
                        assert first.getStorage() == target.getParameter(0).getVariableStorage()
                        manager = value.getDataTypeManager()
                        assert manager.getID(first.getDataType()) == manager.getID(target.getParameter(0).getDataType())
                        assert target_result.getDecompiledFunction() is not None
                        target_c = str(target_result.getDecompiledFunction().getC())
                        (output / f"physical_sum_target_{phase}-kuna.c").write_text(target_c)
                        results = []
                        for fn, entry, inputs, expected in (
                            (caller, 0x1000, (5, 6), 11), (other, 0x1100, (7, 8), 15)
                        ):
                            native = machine_return(value, entry)
                            assert native == expected, (phase, entry, native)
                            args = [(None, None, constant) for constant in inputs]
                            # Export the actual target and callers; do not repair getC.
                            result = observe(ifc, fn, f"physical_{fn.getName()}_{phase}", "kuna",
                                    [(entry + 10, args)], "",
                                    f"int main(void) {{ return {fn.getName()}() != {expected}; }}\n",
                                    opcode=PcodeOp.CALL, committed_parameters=True,
                                    physical_input_size=4, callable_unit=True)
                            rows[-1]["machine_result"] = native
                            assert rows[-1]["passed"], rows[-1]
                            results.append(result)
                        results = selected_results(ifc, [caller, other], monitor)
                        rows[-1]["joint_stdout"] = execute_export(value, results,
                            "int main(void) { return sum_caller() != 11 || sum_other() != 15; }\n",
                            output=output, stem=f"physical_joint_{phase}-kuna")
                        rows[-1]["joint_c_executed"] = True
                        assert fingerprint(target) == unchanged, "physical transport changed source authority"

        for core in cores:
            with program("callfixup_precedence") as (value, api):
                with transaction(value):
                    target = function(value, api, 0x2000, b"\xc3", "fixup_target")
                    signature(target, [], result=VoidDataType.dataType)
                    target.setCallFixup("fentry")
                    prefix = bytes.fromhex("bf63000000")
                    site = 0x1000 + len(prefix)
                    caller = function(value, api, 0x1000,
                                      prefix + call(site) + bytes.fromhex("b807000000c3"), "fixup_caller")
                    signature(caller, [])
                    override(caller, site, [integer])
                with interface(value, core) as ifc:
                    for phase in ("injected", "removed", "restored"):
                        if phase != "injected":
                            with transaction(value):
                                target.setCallFixup(None if phase == "removed" else "fentry")
                            ifc.flushCache()
                        expected = [(site, [(4, integer, 99)])] if phase == "removed" else []
                        observe(ifc, caller, "fixup_" + phase, core, expected,
                                "",
                                "int main(void) { return fixup_caller() != 7; }\n",
                                callable_unit=True)
                        if phase == "removed":
                            assert target.getCallFixup() is None
                        else:
                            assert str(target.getCallFixup()) == "fentry"

        for core in cores:
            with program("indirect_override") as (value, api):
                with transaction(value):
                    caller = function(value, api, 0x1000, bytes.fromhex("4889f8bf05000000be06000000ffd0c3"), "indirect_caller")
                organization = value.getDataTypeManager().getDataOrganization()
                assert (organization.getPointerSize(), organization.getIntegerSize(),
                        organization.getLongSize(), organization.getLongLongSize()) == (8, 4, 8, 8)
                assert str(organization.getIntegerCTypeApproximation(8, False)) == "unsigned long"
                with interface(value, core) as ifc:
                    for phase in ("baseline", "override", "removed"):
                        if phase != "baseline":
                            with transaction(value):
                                if phase == "override":
                                    override(caller, 0x100d, [integer])
                                else:
                                    remove_override(caller, 0x100d)
                            ifc.flushCache()
                        one = phase == "override"
                        args = [(4, integer, 5)] if one else [(None, None, 5), (None, None, 6)]
                        preamble = ("typedef int code(int);\nstatic int calls, observed;\n"
                                    "int callback(int x) { ++calls; observed = x; return x + 10; }\n"
                                    if one else "#include <limits.h>\n"
                                    "_Static_assert(CHAR_BIT == 8 && sizeof(unsigned long) == 8 && sizeof(void *) == 8, "
                                    "\"x86-64 GCC fixture requires matching LP64 C provider\");\n"
                                    "typedef void code(unsigned long, unsigned long);\nstatic int calls, observed;\n"
                                    "void callback(unsigned long x, unsigned long y) { ++calls; observed = (int)(x * 10 + y); }\n")
                        observe(ifc, caller, "indirect_" + phase, core, [(0x100d, args)], preamble,
                                f"int main(void) {{ indirect_caller(callback); return observed != {5 if one else 56} || calls != 1; }}\n")

        for core in cores:
            with program("two_direct_sites") as (value, api):
                with transaction(value):
                    target = function(value, api, 0x2000,
                                      bytes.fromhex("89f883ff0574066bc00a01f0c383c00ac3"), "mode_target")
                    signature(target, [("mode", integer)], varargs=True)
                    code = bytes.fromhex("85ff7510bf05000000be06000000")
                    code += call(0x100e) + b"\xc3"
                    code += bytes.fromhex("bf07000000be08000000") + call(0x101e) + b"\xc3"
                    caller = function(value, api, 0x1000, code, "two_sites")
                    signature(caller, [("choice", integer)])
                    memory(value, api, 0x7000, bytes(0x1000), "two_sites_stack", executable=False)
                unchanged = fingerprint(target)
                driver = "int main(void) { return two_sites(0) != 15 || two_sites(1) != 78; }\n"
                with interface(value, core) as ifc:
                    for phase in ("override", "removed"):
                        with transaction(value):
                            if phase == "override":
                                override(caller, 0x100e, [integer])
                            else:
                                remove_override(caller, 0x100e)
                        ifc.flushCache()
                        target_result = ifc.decompileFunction(target, 60, monitor)
                        assert target_result.decompileCompleted(), str(target_result.getErrorMessage())
                        source = target_result.getHighFunction().getFunctionPrototype()
                        assert source.isVarArg() and source.getNumParams() == 1
                        formal = source.getParam(0)
                        assert str(formal.getName()) == "mode" and formal.getDataType().isEquivalent(integer)
                        assert formal.isTypeLocked() and formal.isNameLocked()
                        assert formal.getDataType().getLength() == 4
                        assert formal.getStorage() == target.getParameter(0).getVariableStorage()
                        pieces = formal.getStorage().getVarnodes()
                        assert len(pieces) == 1 and pieces[0].getSize() == 4
                        assert pieces[0].getAddress() == value.getRegister("EDI").getAddress()
                        target_c = str(target_result.getDecompiledFunction().getC())
                        (output / f"two_sites_target_{phase}-{core}.c").write_text(target_c)
                        machine = [machine_return(value, 0x1000, (("RDI", choice),)) for choice in (0, 1)]
                        assert machine == [15, 78]
                        capture = output / f"two_sites_{phase}-{core}.xml"
                        ifc.enableDebug(File(str(capture)))
                        first_args = ([(4, integer, 5)] if core == "stock" and phase == "override" else
                                      [(None, None, 5), (None, None, 6)])
                        observe(ifc, caller, "two_sites_" + phase, core,
                                [(0x100e, first_args), (0x101e, [(None, None, 7), (None, None, 8)])],
                                target_c if core == "stock" else "", driver,
                                opcode=PcodeOp.CALL, physical_input_size=4, callable_unit=True)
                        rows[-1]["machine_results"] = machine
                        rows[-1]["target_c"] = target_c
                        wire = ET.parse(capture).getroot().findall(".//protooverride")
                        if phase == "override":
                            assert wire
                            for encoded in wire:
                                assert int(encoded.find("addr").get("offset"), 0) == 0x100e
                                proto = encoded.find("prototype")
                                assert proto.get("dotdotdot", "false") == "false"
                                params = proto.findall("internallist/param")
                                assert len(params) == 1
                                datatype = params[0].find("type")
                                assert datatype.get("metatype") == "int" and int(datatype.get("size")) == 4
                        else:
                            assert not wire
                        rows[-1]["source_override_arity"] = 1 if phase == "override" else None
                        assert fingerprint(target) == unchanged

        for core in cores:
            with program("deindirect_override") as (value, api):
                with transaction(value):
                    target = function(value, api, 0x2000, bytes.fromhex("89f8c3"), "resolved_target")
                    signature(target, [("first", integer), ("second", integer)])
                    prefix = bytes.fromhex("b800200000bf05000000be06000000")
                    site = 0x1000 + len(prefix)
                    caller = function(value, api, 0x1000, prefix + bytes.fromhex("ffd0c3"), "resolved_caller")
                    signature(caller, [])
                    override(caller, site, [integer])
                unchanged = fingerprint(target)
                with interface(value, core) as ifc:
                    observe(ifc, caller, "resolved_indirect_override", core,
                            [(site, [(4, integer, 5)])],
                            "", "int main(void) { return resolved_caller() != 5; }\n",
                            opcode=PcodeOp.CALL, callable_unit=True)
                    if core == "stock":
                        observe(ifc, caller, "resolved_indirect_occurrences", core,
                                [(site, [(4, integer, 5)])],
                                "static int calls; int resolved_target(int value) { ++calls; return value; }\n",
                                "int main(void) { return resolved_caller() != 5 || calls != 1; }\n",
                                opcode=PcodeOp.CALL)
                assert fingerprint(target) == unchanged

        # Export-private input projection must retain all ordinary source argument effects.
        if "kuna" in cores:
            with program("projected_source_argument_effects") as (value,api):
                with transaction(value):
                    target=function(value,api,0x2000,bytes.fromhex("89f8c3"),"projected_target")
                    signature(target,[("first",integer),("second",integer)])
                    authored=function(value,api,0x1000,direct_code(0x1000,5,6),"projected_authored")
                    signature(authored,[])
                    override(authored,0x100a,[integer])
                    memory(value,api,0x5000,bytes(8),"counter_storage",False)
                    for offset,name in ((0x5000,"first_count"),(0x5004,"second_count")):
                        api.createData(address(value,offset),integer)
                        api.createLabel(address(value,offset),name,True)
                    for entry,offset,name,result in ((0x3000,0x5000,"first_value",7),(0x3100,0x5004,"second_value",8)):
                        code=b"\xff\x05"+struct.pack("<i",offset-entry-6)+b"\xb8"+struct.pack("<I",result)+b"\xc3"
                        provider=function(value,api,entry,code,name)
                        signature(provider,[])
                    code=b"\x53"
                    first_site=0x1100+len(code);code+=call(first_site,0x3000)+bytes.fromhex("89c3")
                    second_site=0x1100+len(code);code+=call(second_site,0x3100)+bytes.fromhex("89c689df")
                    target_site=0x1100+len(code);code+=call(target_site,0x2000)+bytes.fromhex("5bc3")
                    ordinary=function(value,api,0x1100,code,"projected_ordinary")
                    signature(ordinary,[])
                    memory(value,api,0x7000,bytes(0x1000),"machine_stack",False)
                target_facts=fingerprint(target)
                assert machine_return(value,0x1000)==5
                assert machine_return(value,0x1100)==7
                with interface(value,"kuna") as ifc:
                    target_result=ifc.decompileFunction(target,60,monitor)
                    assert target_result.decompileCompleted(),str(target_result.getErrorMessage())
                    assert target_result.getHighFunction().getFunctionPrototype().getNumParams()==2
                    first=observe(ifc,authored,"projected_authored","kuna",[(0x100a,[(4,integer,5)])],"",
                        "int main(void) { return projected_authored()!=5; }\n",opcode=PcodeOp.CALL,callable_unit=True)
                    second=observe(ifc,ordinary,"projected_ordinary","kuna",[(first_site,[]),(second_site,[]),(target_site,[(4,integer,None),(4,integer,None)])],"",
                        "extern int first_count,second_count; int main(void) { return projected_ordinary()!=7 || first_count!=1 || second_count!=1; }\n",
                        opcode=PcodeOp.CALL,callable_unit=True)
                    assert first is not None and second is not None
                    driver="extern int first_count,second_count; int main(void) { return projected_authored()!=5 || projected_ordinary()!=7 || first_count!=1 || second_count!=1 || projected_target(9,10)!=9; }\n"
                    rows[-1]["joint_stdout"]=execute_export(value,[first,second],driver,output=output,stem="projected_joint")
                    rows[-1]["joint_C_executed"]=True
                    assert fingerprint(target)==target_facts,"export projection changed canonical source"

        native_apple = platform.system() == "Darwin" and platform.machine().lower() in ("arm64", "aarch64")
        assert native_apple or platform.machine().lower() in ("x86_64", "amd64"), \
            "aggregate native witness requires Darwin arm64 or x86-64"
        aggregate_cases = [(False, "stock", False), (False, "kuna", False), (True, "kuna", False)]
        if native_apple:
            aggregate_cases.append((True, "kuna", True))
        for logical, core, apple in aggregate_cases:
            if core not in cores:
                continue
            native_caller = logical and (apple or not native_apple)
            label = ("aggregate_logical_native" if native_caller else "aggregate_logical_x86") \
                if logical else "aggregate_explicit_pointer"
            with program(label, apple=apple) as (value, api):
                with transaction(value):
                    big = StructureDataType("Big24", 0, value.getDataTypeManager())
                    for name in ("a", "b", "c"):
                        big.add(UnsignedLongLongDataType.dataType, 8, name, None)
                    big = value.getDataTypeManager().resolve(big, DataTypeConflictHandler.DEFAULT_HANDLER)
                    pointer = PointerDataType(big, value.getDataTypeManager())
                    model = "__cdecl" if apple else "__stdcall"
                    target = function(value, api, 0x2000,
                                      bytes.fromhex("c0035fd6") if apple else b"\xc3", "big_target")
                    signature(target, [("tag", integer)], big, model=model, varargs=True)
                    if apple:
                        # Frame: tail arguments at sp+0/+8, Big24 at sp+32, saved fp/lr at sp+64.
                        # x8 is the hidden result pointer; w0 is tag. No result pointer is returned.
                        code = bytes.fromhex(
                            "ff4301d1fd7b04a9fd030191e90300aae883009120008052ea008052"
                            "ea0300f90090601ee00700fd20013fd6e02340b9e12b40b90000010b"
                            "e13340b90000010bfd7b44a9ff430191c0035fd6")
                        site = 0x1028
                    else:
                        prefix = bytes.fromhex("4989fb4889f7be01000000ba0700000048b8")
                        prefix += struct.pack("<Q", 0x4004000000000000)
                        prefix += bytes.fromhex("66480f6ec0b8010000004883ec08")
                        site = 0x1000 + len(prefix)
                        code = prefix + bytes.fromhex("41ffd34883c4084889c18b01034108034110c3")
                    caller = function(value, api, 0x1000, code, "big_invoke")
                    parameters = [("callback", PointerDataType(VoidDataType.dataType, value.getDataTypeManager()))]
                    if not apple:
                        parameters.append(("storage", pointer))
                    signature(caller, parameters, model=model)
                    reference = value.getReferenceManager().addMemoryReference(
                        address(value, site), address(value, 0x2000), RefType.COMPUTED_CALL, user, 0)
                    value.getReferenceManager().setPrimary(reference, True)
                    arguments = [integer, integer, DoubleDataType.dataType]
                    if not logical:
                        arguments = [pointer] + arguments
                    override(caller, site, arguments, big if logical else pointer, model=model)
                assert target.getAutoParameterCount() == 1 and target.getParameterCount() == 2
                assert HighFunctionDBUtil.getFirstVarArg(value, address(value, site)) == 2
                if apple:
                    hidden = target.getParameter(0)
                    assert hidden.isAutoParameter()
                    assert hidden.getVariableStorage().getVarnodes()[0].getAddress() == value.getRegister("x8").getAddress()
                    assert target.getReturnType().isEquivalent(VoidDataType.dataType)
                unchanged = fingerprint(target), fingerprint(caller)
                preamble = r"""
#include <stdarg.h>
#include <stdio.h>
typedef struct { ulonglong a,b,c; } Big24;
static int calls, bad_arguments;
static volatile Big24 callback_result;
"""
                if logical:
                    preamble += r"""
__attribute__((noinline)) Big24 big_callback(int tag, ...) {
    va_list ap; va_start(ap,tag); int value = va_arg(ap,int);
    double number = va_arg(ap,double); va_end(ap); ++calls;
    Big24 result = {0,0,0};
    if (tag == 1 && value == 7 && number == 2.5) result = callback_result;
    else ++bad_arguments;
    return result;
}
"""
                else:
                    preamble += r"""
__attribute__((noinline)) Big24 *big_callback(Big24 *storage, int tag, ...) {
    va_list ap; va_start(ap,tag); int value = va_arg(ap,int);
    ++calls; storage->a = storage->b = storage->c = 0;
    if (value != 7) { ++bad_arguments; va_end(ap); return storage; }
    double number = va_arg(ap,double); va_end(ap);
    if (tag == 1 && number == 2.5) *storage = callback_result;
    else ++bad_arguments;
    return storage;
}
"""
                preamble += "static void *volatile runtime_callback;\n"
                cases = ",\n".join(
                    f"    {{{{{a},{b},{c}}},{expected}}}"
                    for (a, b, c), expected in AGGREGATE_RESULTS
                )
                driver = (
                    "int main(void) {\n"
                    "  const struct { Big24 fields; int expected; } cases[] = {\n"
                    + cases + "\n  };\n"
                    "  runtime_callback = (void *)big_callback;\n"
                    "  for (unsigned i = 0; i < sizeof(cases)/sizeof(cases[0]); ++i) {\n"
                    "    callback_result = cases[i].fields;\n"
                    "    calls = bad_arguments = 0;\n"
                )
                if apple:
                    driver += "    int result = big_invoke(runtime_callback);\n"
                    declaration = "extern int big_invoke(void *);"
                else:
                    driver += (
                        "    Big24 storage = {0,0,0};\n"
                        "    int result = big_invoke(runtime_callback, &storage);\n"
                        "    if (storage.a != cases[i].fields.a || storage.b != cases[i].fields.b\n"
                        "        || storage.c != cases[i].fields.c) return 1;\n"
                    )
                    declaration = "extern int big_invoke(void *, Big24 *);"
                driver += (
                    "    if (result != cases[i].expected || calls != 1 || bad_arguments) return 2;\n"
                    '    printf("%u:%d\\n", i, result);\n'
                    "  }\n"
                    "  return 0;\n"
                    "}\n"
                )
                native_stdout = execute_native_caller(code, preamble, declaration, driver) if native_caller else None
                with interface(value, core) as ifc:
                    capture = output / f"{label}-{core}.xml"
                    ifc.enableDebug(File(str(capture)))
                    observe(ifc, caller, label, core,
                            [(site, [(8, pointer, None), (4, integer, 1), (4, integer, 7),
                                     (8, DoubleDataType.dataType, 0x4004000000000000)])],
                            preamble, (
                                preamble.replace("typedef struct { ulonglong a,b,c; } Big24;\n", "") + driver
                                if logical and core == "kuna" else driver
                            ),
                            opcode=PcodeOp.CALLIND,
                            returns={site: VoidDataType.dataType if apple else pointer},
                            committed_parameters=True, callable_unit=logical and core == "kuna")
                    records = captured_overrides(capture)
                    expected_first = 1 if logical else 2
                    assert records and all(record == {"first": expected_first, "inputs": len(arguments), "open": False}
                                           for record in records), records
                    rows[-1]["supplied_declaration"] = {
                        "signature": "Big24(int,int,double)" if logical else "Big24*(Big24*,int,int,double)",
                        "global_auto_parameters": 1, "global_parameters": 2, "wire": records,
                        "language": str(value.getLanguageID()),
                        "execution_contract": "original aggregate-return ABI" if logical else "explicit pointer declaration",
                        "original_native_executed": native_caller, "original_native_stdout": native_stdout,
                        "result_cases": [
                            {"fields": dict(zip(("a", "b", "c"), fields)), "expected_sum": expected}
                            for fields, expected in AGGREGATE_RESULTS
                        ],
                    }
                assert (fingerprint(target), fingerprint(caller)) == unchanged, \
                    "callsite aggregate override changed current or callee facts"

        for core in cores:
            with program("override_convention", bits=32) as (value, api):
                with transaction(value):
                    target = function(value, api, 0x2000, bytes.fromhex("89c801d0c3"), "fast_target")
                    prefix = bytes.fromhex("b905000000ba060000006a63")
                    site = 0x1000 + len(prefix)
                    caller = function(value, api, 0x1000, prefix + call(site) + bytes.fromhex("83c404c3"), "fast_caller")
                    signature(caller, [], model="__cdecl")
                    override(caller, site, [integer, integer], model="__fastcall")
                    memory(value, api, 0x7000, bytes(0x1000), "machine_stack", executable=False)
                unchanged = fingerprint(target), fingerprint(caller)
                native = machine_return(value, 0x1000, extra_pop=4)
                assert native == 11, native
                with interface(value, core) as ifc:
                    observe(ifc, caller, "nondefault_fastcall", core,
                            [(site, [(4, integer, 5), (4, integer, 6)])],
                            "", "int main(void) { return fast_caller() != 11; }\n",
                            callable_unit=True)
                    rows[-1]["machine_result"] = native
                    if core == "stock":
                        observe(ifc, caller, "nondefault_fastcall_occurrences", core,
                                [(site, [(4, integer, 5), (4, integer, 6)])],
                                "static int calls; int fast_target(int a, int b) { ++calls; return a + b; }\n",
                                "int main(void) { return fast_caller() != 11 || calls != 1; }\n")
                assert (fingerprint(target), fingerprint(caller)) == unchanged, \
                    "independent convention recovery changed source authority"

                if core == "kuna":
                    row = {"case": "inferred_fastcall_lifecycle", "core": core, "machine_result": native}
                    rows.append(row)
                    try:
                        with interface(value, core) as ifc:
                            selected = [target, caller]
                            process_field = java_field(DecompInterface, "decompProcess")
                            native_field = java_field(DecompileProcess, "nativeProcess")
                            row["replay_lifecycles"] = []
                            for lifecycle in ("retained", "flush", "fresh_worker"):
                                previous_pid = int(native_field.get(process_field.get(ifc)).pid())
                                if lifecycle == "flush":
                                    ifc.flushCache()
                                elif lifecycle == "fresh_worker":
                                    ifc.resetDecompiler()
                                    assert int(native_field.get(process_field.get(ifc)).pid()) != previous_pid
                                planned = selected_results(ifc, selected, monitor)
                                prototype = planned[0].getHighFunction().getFunctionPrototype()
                                assert prototype.getNumParams() == 2
                                for index, register in enumerate(("ECX", "EDX")):
                                    storage = prototype.getParam(index).getStorage().getVarnodes()
                                    assert len(storage) == 1 and storage[0].getSize() == 4
                                    assert storage[0].getAddress() == value.getRegister(register).getAddress()
                                result_storage = prototype.getReturnStorage().getVarnodes()
                                assert len(result_storage) == 1 and result_storage[0].getSize() == 4
                                assert result_storage[0].getAddress() == value.getRegister("EAX").getAddress()
                                execute_export(value, planned,
                                                 "int main(void) { return fast_caller() != 11 || fast_target(5,6) != 11; }\n",
                                                 output=output, stem=f"inferred-fastcall-lifecycle-{lifecycle}")
                                assert (fingerprint(target), fingerprint(caller)) == unchanged, \
                                    "Exact replay changed canonical source authority"
                                row["replay_lifecycles"].append(lifecycle)
                            row["provider_and_caller_replayed"] = True
                            with transaction(value):
                                signature(target, [("a", integer), ("b", integer)],
                                          result=wide, model="__fastcall")
                            ifc.flushCache()
                            changed = selected_results(ifc, [target], monitor)[0]
                            assert changed.getHighFunction().getFunctionPrototype().getReturnType().isEquivalent(wide)
                            row["source_edit_return"] = str(changed.getHighFunction().getFunctionPrototype().getReturnType())
                        row["passed"] = True
                    except Exception:
                        row["passed"] = False
                        row["failure"] = traceback.format_exc()
                    print(f"{'PASS' if row['passed'] else 'FAIL'} kuna: inferred_fastcall_lifecycle", flush=True)

        for core in cores:
            with program("typed_indirect_fastcall", bits=32) as (value, api):
                with transaction(value):
                    callback = FunctionDefinitionDataType("FastCallback", value.getDataTypeManager())
                    callback.setCallingConvention("__fastcall")
                    callback.setReturnType(integer)
                    callback.setArguments(JArray(ParameterDefinition)([
                        ParameterDefinitionImpl("left", integer, None),
                        ParameterDefinitionImpl("right", integer, None),
                    ]))
                    target = function(value, api, 0x2000, bytes.fromhex("89c801d0c3"), "typed_fast_target")
                    signature(target, [("left", integer), ("right", integer)], model="__fastcall")
                    caller = function(value, api, 0x1000,
                                      bytes.fromhex("8b442404b905000000ba06000000ffd0c3"), "typed_fast_caller")
                    signature(caller, [("callback", PointerDataType(callback, value.getDataTypeManager()))],
                              model="__cdecl")
                    memory(value, api, 0x7000, bytes(0x1000), "typed_indirect_stack", executable=False)
                    value.getMemory().setBytes(address(value, 0x7fe4), JArray(JByte)((0x2000).to_bytes(4, "little")))
                unchanged = fingerprint(target), fingerprint(caller)
                assert machine_return(value, 0x1000, extra_pop=4) == 11
                with interface(value, core) as ifc:
                    for phase in ("declared", "override_result", "removed", "reset", "reopen"):
                        if phase in ("override_result", "removed"):
                            with transaction(value):
                                if phase == "override_result":
                                    override(caller, 0x100e, [integer, integer], short, model="__fastcall")
                                else:
                                    remove_override(caller, 0x100e)
                            ifc.flushCache()
                        elif phase == "reset":
                            ifc.resetDecompiler()
                        elif phase == "reopen":
                            ifc.closeProgram()
                            assert ifc.openProgram(value), str(ifc.getLastMessage())
                        result = observe(ifc, caller, "typed_fastcall_" + phase, core,
                                         [(0x100e, [(4, integer, 5), (4, integer, 6)])],
                                         "",
                                         "int main(void) { return typed_fast_caller(typed_fast_target) != 11; }\n",
                                         opcode=PcodeOp.CALLIND, committed_parameters=True,
                                         returns={0x100e: short if phase == "override_result" else integer},
                                         callable_unit=True, functions=(target,))
                        assert (fingerprint(target), fingerprint(caller)) == unchanged

        if "kuna" in cores:
            with program("typed_indirect_fastcall_upper_once", bits=32) as (value, api):
                with transaction(value):
                    callback = FunctionDefinitionDataType("FastCallback", value.getDataTypeManager())
                    callback.setCallingConvention("__fastcall")
                    callback.setReturnType(integer)
                    callback.setArguments(JArray(ParameterDefinition)([
                        ParameterDefinitionImpl("left", integer, None),
                        ParameterDefinitionImpl("right", integer, None),
                    ]))
                    target = function(value, api, 0x2000,
                                      bytes.fromhex("ff050030000089c801d00500003412c3"), "typed_fast_target")
                    signature(target, [("left", integer), ("right", integer)], model="__fastcall")
                    caller = function(value, api, 0x1000,
                                      bytes.fromhex("8b442404b905000000ba06000000ffd0c3"), "typed_fast_caller")
                    signature(caller, [("callback", PointerDataType(callback, value.getDataTypeManager()))],
                              model="__cdecl")
                    memory(value, api, 0x3000, bytes(4), "call_counter", executable=False)
                    api.createData(address(value, 0x3000), integer)
                    value.getSymbolTable().createLabel(address(value, 0x3000), "call_count", user)
                    memory(value, api, 0x7000, bytes(0x1000), "typed_indirect_stack", executable=False)
                    value.getMemory().setBytes(address(value, 0x7fe4), JArray(JByte)((0x2000).to_bytes(4, "little")))
                    override(caller, 0x100e, [integer, integer], short, model="__fastcall")
                unchanged = fingerprint(target), fingerprint(caller)
                emulator = EmulatorHelper(value)
                try:
                    emulator.writeRegister("ESP", 0x7fe0)
                    emulator.writeMemory(address(value, 0x7fe0), JArray(JByte)((0x7ff0).to_bytes(4, "little")))
                    emulator.setBreakpoint(address(value, 0x7ff0))
                    assert emulator.run(address(value, 0x1000), None, monitor), str(emulator.getLastError())
                    assert emulator.getExecutionAddress() == address(value, 0x7ff0)
                    native = int(str(emulator.readRegister("EAX"))) & 0xffffffff
                    final_esp = int(str(emulator.readRegister("ESP")))
                    calls = int.from_bytes(bytes(int(b) & 255 for b in
                        emulator.readMemory(address(value, 0x3000), 4)), "little")
                    assert (native, final_esp, calls) == (0x1234000b, 0x7fe4, 1)
                finally:
                    emulator.dispose()
                with interface(value, "kuna") as ifc:
                    observe(ifc, caller, "typed_fastcall_upper_result_once", "kuna",
                            [(0x100e, [(4, integer, 5), (4, integer, 6)])], "",
                            "extern int call_count;\n"
                            "int main(void) { call_count = 0; int result = typed_fast_caller(typed_fast_target); "
                            "return result != 0x1234000b || call_count != 1; }\n",
                            opcode=PcodeOp.CALLIND, committed_parameters=True,
                            returns={0x100e: short}, callable_unit=True, functions=(target,))
                    rows[-1]["machine"] = {"result": native, "final_esp": final_esp, "calls": calls}
                assert (fingerprint(target), fingerprint(caller)) == unchanged
                assert caller.getParameter(0).getDataType().getDataType().getReturnType().isEquivalent(integer)
                assert value.getListing().getDataAt(address(value, 0x3000)).getDataType().isEquivalent(integer)

        if "kuna" in cores:
            with program("inferred_fastcall_wrong_cleanup", bits=32) as (value, api):
                with transaction(value):
                    target = function(value, api, 0x2000, bytes.fromhex("89c801d0c20800"), "wrong_cleanup")
                    memory(value, api, 0x7000, bytes(0x1000), "machine_stack", executable=False)
                unchanged = fingerprint(target)
                native = machine_return(value, 0x2000, [("ECX", 5), ("EDX", 6)], extra_pop=12)
                assert native == 11, native
                row = {"case": "inferred_fastcall_wrong_cleanup", "core": "kuna", "machine_result": native}
                rows.append(row)
                try:
                    with interface(value, "kuna") as ifc:
                        result = ifc.decompileFunction(target, 60, monitor)
                        assert result.decompileCompleted(), str(result.getErrorMessage())
                        high = result.getHighFunction()
                        assert high is not None and result.getCCodeMarkup() is not None
                        row["stack_cleanup"] = int(high.getFunctionPrototype().getExtraPop())
                        assert row["stack_cleanup"] == 12, row
                        execute_export(value, [result], "int main(void) { return 0; }\n",
                                       output=output, stem="wrong-cleanup-kuna",
                                       direct_call={"function": "wrong_cleanup",
                                                    "registers": {"ECX": 5, "EDX": 6},
                                                    "initial_esp": 0x7fe0,
                                                    "expected_result": 11,
                                                    "expected_final_esp": 0x7fec})
                    assert fingerprint(target) == unchanged, "Cleanup verification changed source authority"
                    row["passed"] = True
                except Exception:
                    row["passed"] = False
                    row["failure"] = traceback.format_exc()
                print(f"{'PASS' if row['passed'] else 'FAIL'} kuna: inferred_fastcall_wrong_cleanup", flush=True)

        for core in cores:
            with program("override_flow_effect") as (value, api):
                with transaction(value):
                    target = function(value, api, 0x2000, bytes.fromhex("8d470ac3"), "flow_target")
                    signature(target, [("value", integer)])
                    caller = function(value, api, 0x1000,
                                      bytes.fromhex("bf05000000") + call(0x1005) + bytes.fromhex("83c001c3"), "flow_caller")
                    signature(caller, [])
                    target.setNoReturn(True)
                    override(caller, 0x1005, [integer])
                    memory(value, api, 0x7000, bytes(0x1000), "flow_stack", executable=False)
                unchanged = fingerprint(target)
                with interface(value, core) as ifc:
                    target_result = ifc.decompileFunction(target, 60, monitor)
                    assert target_result.decompileCompleted(), str(target_result.getErrorMessage())
                    source = target_result.getHighFunction().getFunctionPrototype()
                    assert source.getNumParams() == 1 and source.getReturnType().isEquivalent(integer)
                    parameter = source.getParam(0)
                    assert str(parameter.getName()) == "value"
                    assert parameter.getDataType().isEquivalent(integer) and parameter.getDataType().getLength() == 4
                    assert parameter.getStorage() == target.getParameter(0).getVariableStorage()
                    pieces = parameter.getStorage().getVarnodes()
                    assert len(pieces) == 1 and pieces[0].getSize() == 4
                    assert pieces[0].getAddress() == value.getRegister("EDI").getAddress()
                    target_c = str(target_result.getDecompiledFunction().getC())
                    (output / f"flow_target-{core}.c").write_text(target_c)
                    process_field = java_field(DecompInterface, "decompProcess")
                    native_field = java_field(DecompileProcess, "nativeProcess")
                    instruction = value.getListing().getInstructionAt(address(value, 0x1005))
                    for label, expected_result, explicit, lifecycle in (
                        ("returning_override_beats_global_noreturn", 16, False, "initial"),
                        ("explicit_flow_override_remains_authoritative", 15, True, "flush"),
                        ("explicit_flow_override_restart", 15, True, "reset"),
                        ("removed_flow_override_restores_original", 16, False, "flush"),
                        ("removed_flow_override_restart", 16, False, "reset"),
                        ("reapplied_flow_override_reopen", 15, True, "reopen"),
                        ("removed_flow_override_reopen", 16, False, "reopen"),
                    ):
                        selected = FlowOverride.CALL_RETURN if explicit else FlowOverride.NONE
                        if instruction.getFlowOverride() != selected:
                            with transaction(value):
                                instruction.setFlowOverride(selected)
                        previous_pid = int(native_field.get(process_field.get(ifc)).pid())
                        if lifecycle == "flush":
                            ifc.flushCache()
                        elif lifecycle == "reset":
                            ifc.resetDecompiler()
                            assert int(native_field.get(process_field.get(ifc)).pid()) != previous_pid
                        elif lifecycle == "reopen":
                            ifc.closeProgram()
                            assert ifc.openProgram(value), str(ifc.getLastMessage())
                        assert instruction.getFlowOverride() == selected
                        # EmulatorHelper executes the original instructions, not
                        # the user-requested CALL_RETURN semantic transformation.
                        native = machine_return(value, 0x1000)
                        assert native == 16
                        capture = output / f"{label}-{core}.xml"
                        ifc.enableDebug(File(str(capture)))
                        arguments = [(None, None, 5)] if core == "kuna" else [(4, integer, 5)]
                        result = observe(ifc, caller, label, core,
                            [(0x1005, arguments)], target_c if core == "stock" else "",
                            f"int main(void) {{ return flow_caller() != {expected_result}; }}\n",
                            opcode=PcodeOp.CALL, physical_input_size=4, callable_unit=True)
                        assert result is not None and rows[-1].get("completed") and rows[-1].get("ir_passed"), rows[-1]
                        if core == "kuna":
                            from ghidra.program.model.data import AbstractIntegerDataType
                            operations = [op for op in result.getHighFunction().getPcodeOps()
                                          if op.getOpcode() == PcodeOp.CALL]
                            assert len(operations) == 1
                            actual = operations[0].getInput(1)
                            datatype = actual.getHigh().getDataType()
                            rows[-1]["physical_call_input_type"] = {
                                "class": str(datatype.getClass().getName()),
                                "name": str(datatype.getName()),
                                "size": int(datatype.getLength()),
                                "signed": bool(datatype.isSigned()) if isinstance(datatype, AbstractIntegerDataType) else None,
                            }
                            assert actual.getSize() in (4, 8) and datatype.getLength() == actual.getSize()
                            if actual.getSize() == 8:
                                assert isinstance(datatype, AbstractIntegerDataType) and not datatype.isSigned()
                            else:
                                assert datatype.isEquivalent(integer)
                            # The actual eight-byte constant must contain the zero
                            # upper half defined by MOV EDI,5, never invented bits.
                            assert actual.isConstant() and int(actual.getOffset()) == 5
                        document = ET.parse(capture).getroot()
                        wire = document.findall(".//protooverride/prototype")
                        assert wire and all(proto.get("noreturn", "false") == "false" for proto in wire)
                        flow_wire = document.findall(".//flowoverridelist/flow")
                        for encoded in flow_wire:
                            assert encoded.get("type") == "callreturn"
                            addresses = encoded.findall("addr")
                            assert len(addresses) == 2 and all(at.get("space") == "ram" for at in addresses)
                            assert [int(at.get("offset"), 0) for at in addresses] == [0x1000, 0x1005]
                        rows[-1]["flow_override_wire"] = bool(flow_wire)
                        rows[-1]["lifecycle"] = lifecycle
                        rows[-1]["native_pid_before"] = previous_pid
                        rows[-1]["native_pid_after"] = int(native_field.get(process_field.get(ifc)).pid())
                        rows[-1]["original_machine_result"] = native
                        rows[-1]["effective_flow_result"] = expected_result
                        rows[-1]["explicit_call_return"] = explicit
                        assert fingerprint(target) == unchanged and target.hasNoReturn()
                    assert instruction.getFlowOverride() == FlowOverride.NONE
                assert target.hasNoReturn()

        for core in cores:
            with program("unmarked_trap_boundary") as (value, api):
                with transaction(value):
                    trap = function(value, api, 0x1000, bytes.fromhex("cc"), "unmarked_trap")
                    signature(trap, [])
                instruction = value.getListing().getInstructionAt(address(value, 0x1000))
                raw = list(instruction.getPcode(True))
                raw_opcodes = [int(op.getOpcode()) for op in raw]
                assert instruction.getFlowOverride() == FlowOverride.NONE
                assert PcodeOp.CALLOTHER in raw_opcodes and PcodeOp.CALLIND in raw_opcodes
                returns = [op for op in raw if op.getOpcode() == PcodeOp.RETURN]
                assert len(returns) == 1 and returns[0].getInput(0).isConstant()
                assert int(returns[0].getInput(0).getOffset()) == 0
                unchanged = fingerprint(trap)
                row = {"case": "unmarked_trap_boundary", "core": core,
                       "raw_opcodes": raw_opcodes, "flow_override": "NONE",
                       "c_executed": False,
                       "evidence_scope": "Actual INT3 diagnostic origin; kernel interrupt context is not supplied"}
                rows.append(row)
                try:
                    with interface(value, core) as ifc:
                        result = ifc.decompileFunction(trap, 60, monitor)
                        row["completed"] = bool(result.decompileCompleted())
                        row["error"] = str(result.getErrorMessage())
                        assert row["completed"], row
                        high = result.getHighFunction()
                        emitted = result.getDecompiledFunction()
                        assert high is not None and emitted is not None, row
                        row["high_opcodes"] = [int(op.getOpcode()) for op in high.getPcodeOps()]
                        assert PcodeOp.CALLOTHER in row["high_opcodes"], row
                        assert PcodeOp.CALLIND in row["high_opcodes"], row
                        row["c"] = str(emitted.getC())
                        (output / f"unmarked_trap_boundary-{core}.c").write_text(row["c"])
                        assert fingerprint(trap) == unchanged
                        assert instruction.getFlowOverride() == FlowOverride.NONE
                        row["passed"] = True
                except Exception:
                    row["passed"] = False
                    row["failure"] = traceback.format_exc()

        for core in cores:
            with program("shared_callback") as (value, api):
                pointer = PointerDataType(integer, value.getDataTypeManager())
                with transaction(value):
                    code = bytes.fromhex(
                        "4889f885f6750d"
                        "bf05000000be06000000ffd0c3"
                        "bf07000000be08000000ffd08b00c3")
                    caller = function(value, api, 0x1000, code, "branch_callback")
                    signature(caller, [("callback", PointerDataType(VoidDataType.dataType, value.getDataTypeManager())),
                                       ("choice", integer)])
                    override(caller, 0x1011, [integer])
                    override(caller, 0x101e, [integer, integer], pointer)
                unchanged = fingerprint(caller)
                preamble = r"""
static int calls_one, calls_two;
int callback_one(int value) { ++calls_one; return value + 10; }
int *callback_two(int first, int second) {
    static int result; ++calls_two; result = first * 10 + second; return &result;
}
static void *volatile runtime_callback;
"""
                driver = r"""
int main(void) {
    runtime_callback = (void *)callback_one;
    if (branch_callback(runtime_callback, 0) != 15) return 1;
    runtime_callback = (void *)callback_two;
    if (branch_callback(runtime_callback, 1) != 78) return 2;
    return calls_one != 1 || calls_two != 1;
}
"""
                with interface(value, core) as ifc:
                    observe(ifc, caller, "shared_callback_sites", core,
                            [(0x1011, [(4, integer, 5)]),
                             (0x101e, [(4, integer, 7), (4, integer, 8)])],
                            preamble, driver, opcode=PcodeOp.CALLIND,
                            returns={0x1011: integer, 0x101e: pointer}, committed_parameters=True)
                assert fingerprint(caller) == unchanged, "site casts changed the callback declaration"

        for name, text, first, second in ([
            ("printf", "%d %lld", 65, 0x1122334455667788),
            ("scanf", "%d %hd", 0x4000, 0x5000),
        ] if "stock" in cores else ()):
            with program("analyzed_" + name) as (value, api):
                charptr = PointerDataType(CharDataType.dataType, value.getDataTypeManager())
                with transaction(value):
                    target = external_function(value, 0x2000, name)
                    signature(target, [("format", charptr)], varargs=True)
                    memory(value, api, 0x3000, text.encode() + b"\0", "format_data", False)
                    api.createAsciiString(address(value, 0x3000))
                    api.createLabel(address(value, 0x3000), "format_text", True)
                    memory(value, api, 0x4000, bytes(8), "destination_one", False)
                    memory(value, api, 0x5000, bytes(8), "destination_two", False)
                    api.createLabel(address(value, 0x4000), "destination_one", True)
                    api.createLabel(address(value, 0x5000), "destination_two", True)
                    prefix = b"\xbf" + struct.pack("<I", 0x3000) + b"\x48\xbe" + struct.pack("<Q", first)
                    prefix += b"\x48\xba" + struct.pack("<Q", second) + bytes.fromhex("b96300000031c0")
                    site = 0x1000 + len(prefix)
                    caller = function(value, api, 0x1000, prefix + call(site) + b"\xc3", "call_" + name)
                    signature(caller, [])
                unchanged = fingerprint(target)
                field.set(None, None)
                with transaction(value):
                    log = MessageLog()
                    assert FormatStringAnalyzer().added(value, caller.getBody(), monitor, log), str(log)
                assert HighFunctionDBUtil.getFirstVarArg(value, address(value, site)) == 1
                namespace = HighFunction.findOverrideSpace(caller)
                definitions = [HighFunctionDBUtil.readOverride(s) for s in value.getSymbolTable().getSymbols(namespace)]
                definitions = [d.getDataType() for d in definitions if d is not None]
                assert len(definitions) == 1 and not definitions[0].hasVarArgs()
                expected_types = ([charptr, integer, wide] if name == "printf" else
                                  [charptr, PointerDataType(integer, value.getDataTypeManager()),
                                   PointerDataType(short, value.getDataTypeManager())])
                assert len(definitions[0].getArguments()) == 3
                assert all(p.getDataType().isEquivalent(t) for p, t in zip(definitions[0].getArguments(), expected_types))
                arguments = [(8, charptr, 0x3000),
                             (4 if name == "printf" else 8, expected_types[1], first),
                             (8, expected_types[2], second)]
                preamble = f'#include <stdio.h>\nchar format_text[] = "{text}";\n'
                input_text = None
                if name == "printf":
                    expected_stdout = "65 1234605616436508552"
                    driver = f"int main(void) {{ return call_printf() != {len(expected_stdout)}; }}\n"
                else:
                    preamble += ("union { int value; unsigned char bytes[8]; } destination_one;\n"
                                 "union { short value; unsigned char bytes[8]; } destination_two;\n")
                    expected_stdout = ""
                    input_text = "65 -7!"
                    driver = r"""
int main(void) {
    if (call_scanf() != 2 || destination_one.value != 65 || destination_two.value != -7) return 1;
    return fgetc(stdin) != '!' || fgetc(stdin) != EOF;
}
"""
                with interface(value, "stock") as ifc:
                    capture = output / f"analyzer_{name}-stock.xml"
                    ifc.enableDebug(File(str(capture)))
                    observe(ifc, caller, "analyzer_" + name, "stock", [(site, arguments)],
                            preamble, driver, input_text=input_text)
                    if rows[-1].get("c_executed"):
                        assert rows[-1]["stdout"] == expected_stdout, rows[-1]
                    records = captured_overrides(capture)
                    assert records and all(record == {"first": 1, "inputs": 3, "open": False}
                                           for record in records), records
                    rows[-1]["wire"] = records
                assert fingerprint(target) == unchanged, "analyzer override changed the global callee"

        host = platform.system()
        assert host in ("Darwin", "Linux"), f"genuine native-library fixture requires Darwin or Linux, got {host}"
        source = output / "sdk_import.c"
        binary = output / "sdk_import"
        source.write_text(r"""#include <stdio.h>
__attribute__((noinline)) int call_printf(void) {
    return printf("%d %lld", 65, 0x1122334455667788LL);
}
__attribute__((noinline)) int call_printf_repeated(void) {
    return printf("%d:%d:%d|", 5, 5, 7) + printf("%d:%d:%d", 7, 5, 5);
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
""")
        imported = report["native_library_import"] = {"host": host, "commands": [], "imports": []}

        def native_command(command, **kwargs):
            completed = subprocess.run(command, capture_output=True, text=True, timeout=60, **kwargs)
            imported["commands"].append({"argv": command, "returncode": completed.returncode,
                                         "stdout": completed.stdout, "stderr": completed.stderr})
            assert completed.returncode == 0, imported["commands"][-1]
            return completed.stdout

        compiler = ([os.environ["CC"]] if "CC" in os.environ else
                    (["xcrun", "clang"] if host == "Darwin" else ["cc"]))
        native_command(compiler + ["-std=c11", "-O0", "-g", "-fno-builtin", "-fno-stack-protector",
                                   "-Wall", "-Werror", str(source), "-o", str(binary)])
        imported["native_stdout"] = native_command([str(binary)], input="65 -7!")
        assert imported["native_stdout"] == "65 1234605616436508552", imported

        @contextlib.contextmanager
        def imported_program(directory):
            field.set(None, None)
            if host == "Darwin":
                with pyghidra.open_program(binary, project_location=directory,
                                          project_name="sdk_import", analyze=True) as api:
                    yield api.getCurrentProgram()
            else:
                # Import the real runtime dependency files into the same project.
                # Ghidra's loader and External Symbol Resolver own the bindings;
                # neither library assignments nor function signatures are fabricated.
                linked = native_command(["ldd", str(binary)])
                dependencies = []
                for line in linked.splitlines():
                    fields = line.split()
                    if len(fields) >= 3 and fields[1] == "=>":
                        assert fields[2].startswith("/"), f"unresolved host dependency: {line}"
                        dependencies.append((fields[0], fields[2]))
                assert dependencies, f"ldd did not expose real shared-library paths: {linked}"
                project = pyghidra.open_project(directory, "sdk_import", create=True)
                try:
                    for soname, filename in dependencies:
                        loaded = (pyghidra.program_loader().project(project)
                                  .source(filename).name(soname).load())
                        try:
                            loaded.save(monitor)
                        finally:
                            loaded.close()
                    loaded = pyghidra.program_loader().project(project).source(str(binary)).load()
                    try:
                        loaded.save(monitor)
                    finally:
                        loaded.close()
                    with pyghidra.program_context(project, "/" + binary.name) as value:
                        imported["analysis_log"] = str(pyghidra.analyze(value))
                        yield value
                finally:
                    project.close()

        with tempfile.TemporaryDirectory(prefix="kuna-native-libraries-", dir=output) as directory:
            with imported_program(directory) as value:
                from ghidra.program.model.pcode import HighParam

                imported["format"] = str(value.getExecutableFormat())
                imported["language"] = str(value.getLanguageID())
                imported["compiler"] = str(value.getCompilerSpec().getCompilerSpecID())
                assert imported["format"] == ("Mac OS X Mach-O" if host == "Darwin" else "Executable and Linking Format (ELF)"), imported
                functions = list(value.getFunctionManager().getFunctions(True))
                charptr = PointerDataType(CharDataType.dataType, value.getDataTypeManager())
                ptrsize = value.getDefaultPointerSize()
                assert ptrsize == 8, f"genuine library fixture requires supported 64-bit host: {imported}"
                repeated = [fn for fn in functions if str(fn.getName()) == "call_printf_repeated"]
                assert len(repeated) == 1, imported
                repeated = repeated[0]
                field.set(None, None)
                with transaction(value):
                    log = MessageLog()
                    assert FormatStringAnalyzer().added(value, repeated.getBody(), monitor, log), str(log)
                for core in cores:
                    with interface(value, core) as ifc:
                        discovered = ifc.decompileFunction(repeated, 60, monitor)
                        assert discovered.decompileCompleted(), str(discovered.getErrorMessage())
                        calls = [op for op in discovered.getHighFunction().getPcodeOps()
                                 if op.getOpcode() == PcodeOp.CALL]
                        assert len(calls) == 2
                        expected = [
                            (int(op.getSeqnum().getTarget().getOffset()),
                             [(ptrsize, None, None)] + [(4, integer, n) for n in values])
                            for op, values in zip(calls, ((5, 5, 7), (7, 5, 5)))
                        ]
                        observe(ifc, repeated, "printf_repeated_occurrences", core, expected,
                                "#include <stdio.h>\n",
                                "int main(void) { return call_printf_repeated() != 11; }\n",
                                opcode=PcodeOp.CALL, callable_unit=True)
                        if rows[-1].get("c_executed"):
                            assert rows[-1]["stdout"] == "5:5:7|7:5:5", rows[-1]
                for name, text in ((("printf", "%d %lld"), ("scanf", "%d %hd"))
                                   if "kuna" in cores else ()):
                    callers = [fn for fn in functions if str(fn.getName()) == "call_" + name]
                    assert len(callers) == 1, f"missing imported debug caller call_{name}: {imported}"
                    caller = callers[0]
                    assert not caller.isThunk() and not caller.isExternal()
                    calls = [ins for ins in value.getListing().getInstructions(caller.getBody(), True)
                             if ins.getFlowType().isCall()]
                    assert len(calls) == 1, [str(ins) for ins in calls]
                    instruction = calls[0]
                    destinations = [ref.getToAddress() for ref in instruction.getReferencesFrom()
                                    if ref.getReferenceType().isCall()]
                    assert len(destinations) == 1, [str(addr) for addr in destinations]
                    target = value.getFunctionManager().getFunctionAt(destinations[0])
                    assert target is not None
                    external = target.getThunkedFunction(True) if target.isThunk() else target
                    assert external is not None and external.isExternal(), str(target)
                    location = value.getExternalManager().getExternalLocation(external.getSymbol())
                    assert location is not None

                    def import_receipt():
                        original_name = location.getOriginalImportedName()
                        return {"library": str(location.getLibraryName()),
                                "label": str(location.getLabel()),
                                "original_name": None if original_name is None else str(original_name),
                                "source": str(location.getSource()),
                                "symbol_id": int(location.getSymbol().getID()),
                                "external_entry": str(external.getEntryPoint()),
                                "linkage_entry": str(target.getEntryPoint()),
                                "caller": str(caller.getEntryPoint()),
                                "callsite": str(instruction.getAddress())}

                    receipt = import_receipt()
                    imported["imports"].append(receipt)
                    raw_name = receipt["original_name"] or receipt["label"]
                    supported = ((host == "Darwin" and receipt["library"] == "/usr/lib/libSystem.B.dylib"
                                  and raw_name == "_" + name) or
                                 (host == "Linux" and receipt["library"] == "libc.so.6"
                                  and raw_name in (("printf",) if name == "printf" else ("scanf", "__isoc99_scanf"))))
                    assert supported, ("unsupported genuine import prerequisite; preserve this receipt, "
                                       "do not canonicalize UNKNOWN or infer a provider from its name", receipt)
                    assert external.hasVarArgs() and external.getParameterCount() == 1, receipt
                    assert external.getReturnType().isEquivalent(integer), receipt
                    assert external.getParameter(0).getDataType().isEquivalent(charptr), receipt
                    unchanged = (fingerprint(target), fingerprint(external), fingerprint(caller), receipt)
                    site = int(instruction.getAddress().getOffset())
                    formats = [data.getAddress() for data in value.getListing().getDefinedData(True)
                               if data.hasStringValue() and str(data.getValue()) == text]
                    assert len(formats) == 1, f"missing actual analyzed format string {text!r}: {formats}"
                    format_offset = int(formats[0].getOffset())
                    field.set(None, None)
                    with transaction(value):
                        log = MessageLog()
                        assert FormatStringAnalyzer().added(value, caller.getBody(), monitor, log), str(log)
                    assert HighFunctionDBUtil.getFirstVarArg(value, instruction.getAddress()) == 1
                    namespace = HighFunction.findOverrideSpace(caller)
                    assert namespace is not None
                    records = [HighFunctionDBUtil.readOverride(symbol)
                               for symbol in value.getSymbolTable().getSymbols(namespace)]
                    definitions = [record.getDataType() for record in records if record is not None]
                    assert len(definitions) == 1 and not definitions[0].hasVarArgs()
                    expected_types = ([charptr, integer, wide] if name == "printf" else
                                      [charptr, PointerDataType(integer, value.getDataTypeManager()),
                                       PointerDataType(short, value.getDataTypeManager())])
                    assert len(definitions[0].getArguments()) == 3
                    assert all(p.getDataType().isEquivalent(t)
                               for p, t in zip(definitions[0].getArguments(), expected_types))
                    arguments = ([(ptrsize, charptr, format_offset), (4, integer, 65),
                                  (8, wide, 0x1122334455667788)] if name == "printf" else
                                 [(ptrsize, charptr, format_offset),
                                  (ptrsize, expected_types[1], None), (ptrsize, expected_types[2], None)])
                    expected_stdout = "65 1234605616436508552" if name == "printf" else ""
                    input_text = None if name == "printf" else "65 -7!"
                    provider_sources = ()
                    if name == "scanf":
                        # Keep the real SDK and exported source datatype definitions in
                        # separate translation units, as in native_import_provenance.
                        stdio_provider = output / "analyzer_scanf-stdio-provider.c"
                        stdio_provider.write_text('#include <stdio.h>\n'
                            "int check_input_terminator(void) {"
                            "return fgetc(stdin) != '!' || fgetc(stdin) != EOF; }\n")
                        provider_sources = (stdio_provider,)
                    driver = ('int main(void) { return call_printf() != 22; }\n'
                              if name == "printf" else r"""int check_input_terminator(void);
int main(void) {
    int first = 0;
    short second = 0;
    if (call_scanf(&first, &second) != 2 || first != 65 || second != -7) return 1;
    return check_input_terminator();
}
""")
                    with interface(value, "kuna") as ifc:
                        capture = output / f"analyzer_{name}-kuna.xml"
                        ifc.enableDebug(File(str(capture)))
                        result = observe(ifc, caller, "analyzer_" + name, "kuna", [(site, arguments)],
                                         "#include <stdio.h>\n", driver, opcode=PcodeOp.CALL,
                                         returns={site: integer}, committed_parameters=True,
                                         input_text=input_text, callable_unit=True,
                                         provider_sources=provider_sources)
                        row = rows[-1]
                        assert row["passed"] and row.get("c_executed"), row
                        assert row["stdout"] == expected_stdout, row
                        row["passed"] = False
                        high_calls = [op for op in result.getHighFunction().getPcodeOps()
                                      if op.getOpcode() == PcodeOp.CALL]
                        assert len(high_calls) == 1
                        assert high_calls[0].getInput(0).getAddress() == target.getEntryPoint(), row
                        if name == "scanf":
                            # Assert actual destination parameter identity, not fabricated RAM values.
                            for index, slot in ((2, 0), (3, 1)):
                                vn = high_calls[0].getInput(index)
                                while not isinstance(vn.getHigh(), HighParam):
                                    defining = vn.getDef()
                                    assert defining is not None and defining.getOpcode() in (PcodeOp.COPY, PcodeOp.CAST), row
                                    vn = defining.getInput(0)
                                assert vn.getHigh().getSlot() == slot, row
                        wire = captured_overrides(capture)
                        assert wire and all(record == {"first": 1, "inputs": 3, "open": False}
                                            for record in wire), wire
                        row["wire"] = wire
                        row["import"] = receipt
                        # No emitted-C rewrite, data substitute, callee body, alias or cast.
                        # The genuine callers need only recovered string literals; scanf
                        # destinations belong to the real driver and are passed as parameters.
                        row["publication_stdout"] = row["stdout"]
                        assert row["publication_stdout"] == expected_stdout, row
                        row["publication_executed"] = True
                    assert (fingerprint(target), fingerprint(external), fingerprint(caller), import_receipt()) == unchanged, \
                        "analyzer/publication changed the imported source declaration or provenance"
                    row["passed"] = True
                    bindings = []
                    for reference in value.getReferenceManager().getReferencesTo(target.getEntryPoint()):
                        data = value.getListing().getDataAt(reference.getFromAddress())
                        if (reference.getReferenceType().isData()
                                and reference.getSource() in (SourceType.DEFAULT, SourceType.IMPORTED)
                                and data is not None and data.getLength() == ptrsize
                                and data.getValue() == target.getEntryPoint()):
                            bindings.append(data.getAddress())
                    assert bindings, ("actual loader pointer binding missing", receipt)
                    receipt["pointer_slots"] = [str(slot) for slot in bindings]
                    for mutation in ("source", "slot", "mapped_body", "thunk_target"):
                        negative = {"case": f"analyzer_{name}_{mutation}_edit", "core": "kuna",
                                    "passed": False,
                                    "evidence_scope": "Actual edited import/source/raw acquisition; "
                                                      "ordinary CppExporter has no retained-publication submission"}
                        rows.append(negative)
                        tx = value.startTransaction("native imported source edit")
                        try:
                            if mutation == "source":
                                external.setReturnType(wide, user)
                            elif mutation == "slot":
                                for slot in bindings:
                                    value.getMemory().setBytes(slot, JArray(JByte)(b"\0" * ptrsize))
                            elif mutation == "thunk_target":
                                alternate_names = (("_scanf", "scanf", "__isoc99_scanf") if name == "printf"
                                                   else ("_printf", "printf"))
                                alternatives = [location.getFunction() for location in
                                                value.getExternalManager().getExternalLocations(receipt["library"])
                                                if str(location.getLabel()) in alternate_names]
                                assert len(alternatives) == 1 and alternatives[0] is not None
                                target.setThunkedFunction(alternatives[0])
                            else:
                                start = target.getEntryPoint()
                                first = value.getListing().getInstructionAt(start)
                                assert first is not None
                                value.getListing().clearCodeUnits(start, first.getMaxAddress(), False)
                                replacement = bytes.fromhex("c0035fd6") if host == "Darwin" else b"\xc3"
                                value.getMemory().setBytes(start, JArray(JByte)(replacement))
                                assert FlatProgramAPI(value, monitor).disassemble(start)
                            with interface(value, "kuna") as ifc:
                                changed = ifc.decompileFunction(caller, 60, monitor)
                                assert changed.decompileCompleted(), str(changed.getErrorMessage())
                                assert changed.getHighFunction() is not None and changed.getCCodeMarkup() is not None
                                negative["c"] = str(changed.getDecompiledFunction().getC())
                                negative["source"] = fingerprint(external)
                                negative["import"] = import_receipt()
                                if mutation == "source":
                                    assert external.getReturnType().isEquivalent(wide)
                                    namespace = HighFunction.findOverrideSpace(caller)
                                    site_records = [HighFunctionDBUtil.readOverride(symbol)
                                                    for symbol in value.getSymbolTable().getSymbols(namespace)]
                                    site_records = [record for record in site_records
                                                    if record is not None and record.getAddress() == instruction.getAddress()]
                                    assert len(site_records) == 1
                                    site_return = site_records[0].getDataType().getReturnType()
                                    assert site_return.isEquivalent(integer)
                                    negative["site_return"] = str(site_return)
                                    calls = [op for op in changed.getHighFunction().getPcodeOps()
                                             if op.getOpcode() == PcodeOp.CALL]
                                    assert len(calls) == 1
                                    assert calls[0].getOutput() is not None
                                    assert calls[0].getOutput().getSize() == site_return.getLength()
                                elif mutation == "slot":
                                    assert all(value.getMemory().getLong(slot) == 0 for slot in bindings)
                                elif mutation == "thunk_target":
                                    assert target.getThunkedFunction(True) == alternatives[0]
                                else:
                                    raw = value.getListing().getInstructionAt(target.getEntryPoint()).getPcode()
                                    assert any(op.getOpcode() == PcodeOp.RETURN for op in raw)
                            negative["passed"] = True
                        finally:
                            value.endTransaction(tx, False)
                        print(f"PASS kuna: {negative['case']}", flush=True)

        for core in cores:
            with program("variadic_indirect") as (value, api):
                double = DoubleDataType.dataType
                callback_type = FunctionDefinitionDataType("variadic_callback", value.getDataTypeManager())
                callback_type.setCallingConvention("__stdcall")
                callback_type.setReturnType(integer)
                callback_type.setArguments(JArray(ParameterDefinition)([
                    ParameterDefinitionImpl("tag", integer, None)
                ]))
                callback_type.setVarArgs(True)
                with transaction(value):
                    target = external_function(value, 0x2000, "variadic_target")
                    signature(target, [("tag", integer)], varargs=True)
                    prefix = bytes.fromhex("4989fbbf01000000be0700000048b8")
                    prefix += struct.pack("<Q", 0x4004000000000000)
                    prefix += bytes.fromhex("66480f6ec0ba63000000b801000000")
                    site = 0x1000 + len(prefix)
                    caller = function(value, api, 0x1000, prefix + bytes.fromhex("41ffd3c3"), "invoke_variadic")
                    signature(caller, [("callback", PointerDataType(callback_type, value.getDataTypeManager()))])
                    reference = value.getReferenceManager().addMemoryReference(
                        address(value, site), address(value, 0x2000), RefType.COMPUTED_CALL, user, 0)
                    value.getReferenceManager().setPrimary(reference, True)
                    override(caller, site, [integer, integer, double])
                    opaque_site = 0x1100 + len(prefix)
                    opaque_caller = function(value, api, 0x1100, prefix + bytes.fromhex("41ffd3c3"),
                                             "invoke_variadic_opaque")
                    signature(opaque_caller, [("callback", PointerDataType(VoidDataType.dataType,
                                                                          value.getDataTypeManager()))])
                    opaque_ref = value.getReferenceManager().addMemoryReference(
                        address(value, opaque_site), address(value, 0x2000), RefType.COMPUTED_CALL, user, 0)
                    value.getReferenceManager().setPrimary(opaque_ref, True)
                    override(opaque_caller, opaque_site, [integer, integer, double])
                assert HighFunctionDBUtil.getFirstVarArg(value, address(value, site)) == 1
                assert HighFunctionDBUtil.getFirstVarArg(value, address(value, opaque_site)) == 1
                instruction = value.getListing().getInstructionAt(address(value, site))
                assert any(op.getOpcode() == PcodeOp.CALLIND for op in instruction.getPcode(True))
                witness = r"""
#include <stdarg.h>
static int calls;
static int check_values(int tag, va_list ap) {
    int value = va_arg(ap, int);
    double number = va_arg(ap, double);
    ++calls;
    return tag == 1 && value == 7 && number == 2.5 ? 42 : -1;
}
__attribute__((noinline)) int variadic_impl(int tag, ...) {
    va_list ap; va_start(ap, tag);
    int result = check_values(tag, ap); va_end(ap); return result;
}
int variadic_target(int tag, ...) {
    va_list ap; va_start(ap, tag);
    int result = check_values(tag, ap); va_end(ap); return result;
}
static int (*volatile runtime_callback)(int, ...);
"""
                preamble = "typedef int variadic_callback(int, ...);\ntypedef int code(int, ...);\n" + witness
                driver = ("int main(void) { runtime_callback = variadic_impl; "
                          "return invoke_variadic(runtime_callback) != 42 || calls != 1; }\n")
                consumer = witness
                args = [(4, integer, 1), (4, integer, 7), (8, double, 0x4004000000000000)]
                unchanged = fingerprint(target)
                with interface(value, core) as ifc:
                    observe(ifc, caller, "variadic_computed_call", core, [(site, args)], preamble,
                            consumer + driver, opcode=PcodeOp.CALLIND, callable_unit=True)
                    if core == "kuna":
                        negative = {"case": "variadic_unpromoted_tail", "core": core, "passed": False}
                        rows.append(negative)
                        tx = value.startTransaction("unpromoted native variadic tail")
                        try:
                            remove_override(caller, site)
                            override(caller, site, [integer, ShortDataType.dataType, FloatDataType.dataType])
                            ifc.flushCache()
                            changed = ifc.decompileFunction(caller, 60, monitor)
                            assert changed.decompileCompleted(), str(changed.getErrorMessage())
                            assert changed.getHighFunction() is not None and changed.getCCodeMarkup() is not None
                            namespace = HighFunction.findOverrideSpace(caller)
                            records = [HighFunctionDBUtil.readOverride(symbol)
                                       for symbol in value.getSymbolTable().getSymbols(namespace)]
                            records = [record for record in records if record is not None]
                            assert len(records) == 1
                            types = [argument.getDataType() for argument in records[0].getDataType().getArguments()]
                            assert types[1].isEquivalent(ShortDataType.dataType)
                            assert types[2].isEquivalent(FloatDataType.dataType)
                            negative["c"] = str(changed.getDecompiledFunction().getC())
                            negative["stdout"] = execute_c(negative["c"], PREAMBLE + preamble, driver)
                            negative["c_executed"] = True
                            negative["passed"] = True
                        except Exception:
                            negative["failure"] = traceback.format_exc()
                        finally:
                            value.endTransaction(tx, False)
                            ifc.flushCache()
                    capture = output / f"variadic_opaque_call-{core}.xml"
                    ifc.enableDebug(File(str(capture)))
                    observe(ifc, opaque_caller, "variadic_opaque_call", core, [(opaque_site, args)], preamble,
                            consumer + "int main(void) { runtime_callback = variadic_impl; "
                            "return invoke_variadic_opaque((void *)runtime_callback) != 42 || calls != 1; }\n",
                            opcode=PcodeOp.CALLIND, committed_parameters=True,
                            callable_unit=True)
                    records = captured_overrides(capture)
                    assert records and all(record == {"first": 1, "inputs": 3, "open": False}
                                           for record in records), records
                    rows[-1]["wire"] = records
                    with transaction(value):
                        value.getReferenceManager().delete(reference)
                        direct_ref = value.getReferenceManager().addMemoryReference(
                            address(value, site), address(value, 0x2000),
                            RefType.CALL_OVERRIDE_UNCONDITIONAL, user, 0)
                        value.getReferenceManager().setPrimary(direct_ref, True)
                    assert any(op.getOpcode() == PcodeOp.CALL for op in instruction.getPcode(True))
                    ifc.flushCache()
                    # Declare the separate real provider without changing exported C/H or import facts.
                    provider_header = output / f"variadic-original-provider-{core}.h"
                    provider_header.write_text("int variadic_target(int tag, ...);\n")
                    observe(ifc, caller, "explicit_call_reference", core, [(site, args)], preamble,
                            consumer + driver, opcode=PcodeOp.CALL, callable_unit=True,
                            provider_headers=(provider_header,))
                assert fingerprint(target) == unchanged
    finally:
        field.set(None, original)
    report["completed"] = True
    failed = [f"{r['core']}:{r['case']}" for r in rows if not r.get("passed")]
    assert not failed, failed


def main():
    output = Path(os.environ.get("KUNA_SMOKE_OUT", "live-callsite-out")).resolve()
    output.mkdir(parents=True, exist_ok=True)
    artifact = output / "callsite_overrides.json"
    report = {"completed": False, "status": "running", "rows": []}
    # Invalidate a previous successful artifact even if this run is interrupted
    # before PyGhidra starts or before the first case is created.
    artifact.write_text(json.dumps(report, indent=2) + "\n")
    try:
        run(output, report)
    except BaseException:
        report["status"] = "failed" if report["completed"] else "aborted"
        report["failure"] = traceback.format_exc()
        raise
    else:
        report["status"] = "passed"
    finally:
        artifact.write_text(json.dumps(report, indent=2) + "\n")


if __name__ == "__main__":
    main()
