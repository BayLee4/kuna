#!/usr/bin/env python3
"""Exercise real Java option snapshots, action roots, and native-session replay.

No input binary is required. The suite README describes the environment.
IR checks are used where reduced/raw C deliberately has no executable surface.
"""

import contextlib
import json
import os
from pathlib import Path
import re
import struct
import traceback

PREAMBLE = "#include <stdbool.h>\n#include <stddef.h>\n#define __cdecl\n#define __stdcall\n"


def main():
    output = Path(os.environ.get("KUNA_SMOKE_OUT", "live-settings-out")).resolve()
    output.mkdir(parents=True, exist_ok=True)
    report = {"completed": False, "status": "running", "rows": []}
    report_path = output / "settings_lifecycle.json"
    # Invalidate a prior successful artifact before optional imports or JVM setup.
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
    from error_recovery import field
    from kuna_vs_stock import KUNA_GHIDRA, get_exepath_field, start_ghidra
    from prototype_facts import execute_c, execute_export

    start_ghidra()
    from jpype import JArray, JByte
    from java.lang import Object
    from ghidra.app.decompiler import ClangFieldToken, ClangVariableToken, DecompInterface, DecompileOptions, DecompileProcess
    from ghidra.program.database import ProgramDB
    from ghidra.program.flatapi import FlatProgramAPI
    from ghidra.program.model.data import (
        DataTypeConflictHandler, FunctionDefinitionDataType, IntegerDataType,
        ParameterDefinition, ParameterDefinitionImpl, Pointer, PointerDataType, ShortDataType,
        StructureDataType, UnsignedIntegerDataType, UnsignedLongLongDataType, VoidDataType,
    )
    from ghidra.program.model.lang import CompilerSpecID, LanguageID
    from ghidra.program.model.listing import CodeUnit, Function, ParameterImpl, ReturnParameterImpl, Variable
    from ghidra.program.model.pcode import HighFunction, HighFunctionDBUtil, PcodeOp
    from ghidra.program.model.symbol import SourceType
    from ghidra.program.util import DefaultLanguageService
    from ghidra.util.task import ConsoleTaskMonitor

    exepath = get_exepath_field()
    original = exepath.get(None)
    process_field = field(DecompInterface, "decompProcess")
    native_field = field(DecompileProcess, "nativeProcess")
    monitor = ConsoleTaskMonitor()
    user = SourceType.USER_DEFINED
    integer = IntegerDataType.dataType
    unsigned = UnsignedIntegerDataType.dataType
    rows = report["rows"]

    @contextlib.contextmanager
    def program(name, bits=64):
        language = DefaultLanguageService.getLanguageService().getLanguage(LanguageID(f"x86:LE:{bits}:default"))
        compiler = language.getCompilerSpecByID(CompilerSpecID("gcc"))
        owner = Object()
        value = ProgramDB(name, language, compiler, owner)
        try:
            yield value, FlatProgramAPI(value, monitor)
        finally:
            value.release(owner)

    @contextlib.contextmanager
    def transaction(value):
        tx = value.startTransaction("settings/session fixture")
        try:
            yield
        except BaseException:
            value.endTransaction(tx, False)
            raise
        else:
            value.endTransaction(tx, True)

    def address(value, offset):
        return value.getAddressFactory().getDefaultAddressSpace().getAddress(offset)

    def function(value, api, offset, code, name, parameters, result=integer, locked=True):
        block = api.createMemoryBlock(name, address(value, offset), JArray(JByte)(bytes.fromhex(code)), False)
        block.setExecute(True)
        assert api.disassemble(address(value, offset)), name
        fn = api.createFunction(address(value, offset), name)
        assert fn is not None, name
        if locked:
            model = "__stdcall" if value.getDefaultPointerSize() == 8 else "__cdecl"
            fn.updateFunction(model, ReturnParameterImpl(result, value),
                              Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS, False, user,
                              JArray(Variable)([ParameterImpl(n, t, value) for n, t in parameters]))
        return fn

    @contextlib.contextmanager
    def interface(value, core):
        exepath.set(None, KUNA_GHIDRA if core == "kuna" else None)
        ifc = DecompInterface()
        assert ifc.setOptions(DecompileOptions())
        try:
            assert ifc.openProgram(value), str(ifc.getLastMessage())
            yield ifc
        finally:
            ifc.dispose()

    def pid(ifc):
        return int(native_field.get(process_field.get(ifc)).pid())

    def fingerprint(fn):
        return (str(fn.getSignature()), str(fn.getReturn().getVariableStorage()),
                tuple((str(p.getName()), str(p.getDataType()), str(p.getVariableStorage()))
                      for p in fn.getParameters()), bool(fn.hasVarArgs()), bool(fn.hasNoReturn()),
                bool(fn.hasCustomVariableStorage()), str(fn.getCallingConventionName()))

    def observe(ifc, fn, core, label, check, preamble=None, driver=None):
        row = {"core": core, "case": label, "pid": pid(ifc)}
        rows.append(row)
        try:
            result = ifc.decompileFunction(fn, 60, monitor)
            high = result.getHighFunction()
            measure = result.getHighParamID()
            decompiled = result.getDecompiledFunction()
            ops = list(high.getPcodeOps()) if high is not None else []
            row.update(completed=bool(result.decompileCompleted()), error=str(result.getErrorMessage()),
                       highfunction=high is not None, measures=measure is not None,
                       c=str(decompiled.getC()) if decompiled is not None else None,
                       ops=[{"opcode": str(op.getMnemonic()), "text": str(op),
                             "output_size": int(op.getOutput().getSize()) if op.getOutput() else None}
                            for op in ops])
            if row["c"] is not None:
                (output / f"{label}-{core}.c").write_text(row["c"])
            assert row["completed"], row
            check(result, ops, row)
            if driver is not None:
                assert row["c"] is not None, row
                row["stdout"] = execute_c(row["c"], PREAMBLE + (preamble or ""), driver)
                row["c_executed"] = True
            row["passed"] = True
            print(f"PASS {core}: {label}", flush=True)
        except Exception:
            row["passed"] = False
            row["failure"] = traceback.format_exc()
            print(f"FAIL {core}: {label}\n{row['failure']}", flush=True)
        return row

    def null_check(enabled):
        def check(result, ops, row):
            assert row["c"] is not None and (re.search(r"\bNULL\b", row["c"]) is not None) == enabled, row
        return check

    def check_unreachable(enabled):
        def check(result, ops, row):
            branches = [op for op in ops if op.getOpcode() == PcodeOp.CBRANCH]
            returns = [op for op in ops if op.getOpcode() == PcodeOp.RETURN]
            assert len(branches) == (0 if enabled else 1), row
            assert len(returns) == (1 if enabled else 2), row
            values = {int(vn.getOffset()) for op in ops for vn in op.getInputs() if vn.isConstant()}
            assert 7 in values and (9 in values) == (not enabled), row
        return check

    def check_split(enabled):
        def check(result, ops, row):
            stores = [op for op in ops if op.getOpcode() == PcodeOp.STORE]
            sizes = sorted(int(op.getInput(2).getSize()) for op in stores)
            assert sizes == ([2, 2, 4, 4] if enabled else [4, 8]), row
        return check

    def bitfield_check(enabled):
        def check(result, ops, row):
            if not enabled:
                assert all(str(op.getMnemonic()) not in ("INSERT", "ZPULL", "SPULL") for op in ops), row
                def source(vn):
                    while vn.getDef() is not None and vn.getDef().getOpcode() in (PcodeOp.COPY, PcodeOp.CAST):
                        vn = vn.getDef().getInput(0)
                    return vn
                returns = [op for op in ops if op.getOpcode() == PcodeOp.RETURN]
                assert len(returns) == 1 and returns[0].getNumInputs() == 2, row
                mask = source(returns[0].getInput(1)).getDef()
                assert mask is not None and mask.getOpcode() == PcodeOp.INT_AND, row
                assert mask.getInput(1).isConstant() and mask.getInput(1).getOffset() == 31, row
                shift = source(mask.getInput(0)).getDef()
                assert shift is not None and shift.getOpcode() == PcodeOp.INT_RIGHT, row
                assert shift.getInput(1).isConstant() and shift.getInput(1).getOffset() == 3, row
                load = source(shift.getInput(0)).getDef()
                assert load is not None and load.getOpcode() == PcodeOp.LOAD and load.getOutput().getSize() == 4, row
                pointer = source(load.getInput(1))
                while pointer.getDef() is not None:
                    definition = pointer.getDef()
                    if definition.getOpcode() in (PcodeOp.PTRSUB, PcodeOp.INT_ADD):
                        assert definition.getInput(1).isConstant() and definition.getInput(1).getOffset() == 0, row
                    elif definition.getOpcode() == PcodeOp.PTRADD:
                        assert definition.getInput(1).isConstant() and definition.getInput(1).getOffset() == 0, row
                    else:
                        raise AssertionError(f"bitfield LOAD does not address the input pointer: {definition}")
                    pointer = source(definition.getInput(0))
                parameter = result.getHighFunction().getFunctionPrototype().getParam(0)
                storage = parameter.getStorage().getVarnodes()
                assert len(storage) == 1 and pointer.isInput(), row
                assert pointer.getAddress() == storage[0].getAddress() and pointer.getSize() == storage[0].getSize(), row
                assert pointer.getHigh() is not None and pointer.getHigh().getSymbol() is not None, row
                assert pointer.getHigh().getSymbol().getId() == parameter.getId(), row
                row["load_source"] = {"parameter_id": int(parameter.getId()),
                                      "address": str(pointer.getAddress()), "offset": 0}
                row["c_executed"] = False
                row["evidence_scope"] = (
                    "IR-only: both cores emit a non-C aggregate-to-integer cast with bitfields disabled; "
                    "the returned value is checked as (load32(ptr + 0) >> 3) & 31."
                )
        return check

    def override(value, caller, nargs):
        site = address(value, 0x1507)
        namespace = HighFunction.findOverrideSpace(caller)
        previous = []
        if namespace is not None:
            for symbol in value.getSymbolTable().getSymbols(namespace):
                record = HighFunctionDBUtil.readOverride(symbol)
                if record is not None and symbol.getAddress() == site:
                    previous.append((symbol, record))
        assert len(previous) <= 1, "fixture contains competing callsite override records"
        # Match EditPrototypeOverrideAction: writeOverride alone does not replace
        # same-namespace marker symbols in the installed Ghidra producer.
        for symbol, _ in previous:
            symbol.delete()
        definition = FunctionDefinitionDataType("replay_site", value.getDataTypeManager())
        definition.setCallingConvention("__stdcall")
        definition.setReturnType(integer)
        definition.setArguments(JArray(ParameterDefinition)([
            ParameterDefinitionImpl(f"arg{i}", integer, None) for i in range(nargs)
        ]))
        HighFunctionDBUtil.writeOverride(caller, site, definition)
        for _, record in previous:
            record.cleanupUnusedOverride()
        namespace = HighFunction.findOverrideSpace(caller)
        stored = [HighFunctionDBUtil.readOverride(symbol)
                  for symbol in value.getSymbolTable().getSymbols(namespace) if symbol.getAddress() == site]
        stored = [record for record in stored if record is not None]
        assert len(stored) == 1 and len(stored[0].getDataType().getArguments()) == nargs, \
            "fixture did not persist one replacement override"

    try:
        for core in ("stock", "kuna"):
            with program("settings_session") as (value, api):
                with transaction(value):
                    null = function(value, api, 0x1000, "31c0c3", "return_null", [],
                                    PointerDataType(VoidDataType.dataType, value.getDataTypeManager()))
                    unreachable = function(value, api, 0x1100, "31c085c07506b807000000c3b809000000c3",
                                           "unreachable_branch", [])
                    arithmetic = function(value, api, 0x1200, "31c001f883c007c3", "plus_seven", [("value", integer)])
                    shape = StructureDataType("Fields", 0, value.getDataTypeManager())
                    for dtype, name in ((integer, "a"), (ShortDataType.dataType, "b"),
                                        (ShortDataType.dataType, "c"), (integer, "d")):
                        shape.add(dtype, name, None)
                    shape = value.getDataTypeManager().resolve(shape, DataTypeConflictHandler.DEFAULT_HANDLER)
                    split = function(value, api, 0x1300, "48b8000100000002ffffc7470800000000488907c3",
                                     "store_fields", [("ptr", PointerDataType(shape))], VoidDataType.dataType)
                    bits = StructureDataType("Bits", 4, value.getDataTypeManager())
                    bits.insertBitFieldAt(0, 4, 0, unsigned, 3, "low", None)
                    bits.insertBitFieldAt(0, 4, 3, unsigned, 5, "middle", None)
                    bits.insertBitFieldAt(0, 4, 8, unsigned, 24, "high", None)
                    bits = value.getDataTypeManager().resolve(bits, DataTypeConflictHandler.DEFAULT_HANDLER)
                    bitfield = function(value, api, 0x1400, "8b07c1e80383e01fc3", "extract_middle",
                                        [("ptr", PointerDataType(bits))], unsigned)
                    record = StructureDataType("SessionRecord", 0, value.getDataTypeManager())
                    record.add(integer, "before", None)
                    record = value.getDataTypeManager().resolve(record, DataTypeConflictHandler.DEFAULT_HANDLER)
                    caller = function(value, api, 0x1500, "8b3fbe07000000e8f40a0000c3", "replay_call",
                                      [("ptr", PointerDataType(record))])
                    target = function(value, api, 0x2000, "89f801f0c3", "session_target",
                                      [("x", integer), ("y", integer)])
                    api.createMemoryBlock("session_record", address(value, 0x6000),
                                          JArray(JByte)((35).to_bytes(4, "little")), False)
                    api.createData(address(value, 0x6000), record)
                    api.createMemoryBlock("session_stack", address(value, 0x7000),
                                          JArray(JByte)(bytes(0x1000)), False)
                    override(value, caller, 1)
                    literal = function(value, api, 0x1600, "b82a000000c3", "literal_value", [])
                    wrapping = function(value, api, 0x1700, "89f801f001d001c801f8c3", "wrap_sum",
                                        [(name, integer) for name in ("aa", "bb", "cc", "dd")])
                    value.getListing().setComment(address(value, 0x1200), CodeUnit.PLATE_COMMENT, "SESSION_HEADER")
                    value.getListing().setComment(address(value, 0x1202), CodeUnit.PRE_COMMENT, "SESSION_PRE")
                    value.getListing().setComment(address(value, 0x1202), CodeUnit.EOL_COMMENT, "SESSION_EOL")
                    value.getListing().setComment(address(value, 0x1202), CodeUnit.POST_COMMENT, "SESSION_POST")
                    outer = value.getSymbolTable().createNameSpace(value.getGlobalNamespace(), "Outer", user)
                    scopes = [value.getSymbolTable().createNameSpace(outer, name, user) for name in ("One", "Two")]
                    for index, scope in enumerate(scopes):
                        callee = function(value, api, 0x2100 + index * 0x100, "89f8c3",
                                          "namespace_target_" + str(index), [("x", integer)])
                        callee.setParentNamespace(scope)
                        callee.setName("shared", user)
                    ns_code = bytes.fromhex("53bf01000000")
                    ns_code += b"\xe8" + struct.pack("<i", 0x2100 - (0x1800 + len(ns_code) + 5))
                    ns_code += bytes.fromhex("89c3bf02000000")
                    ns_code += b"\xe8" + struct.pack("<i", 0x2200 - (0x1800 + len(ns_code) + 5))
                    ns_code += bytes.fromhex("01d85bc3")
                    namespaced = function(value, api, 0x1800, ns_code.hex(), "call_namespaces", [])
                    namespaced.setParentNamespace(outer)
                    inplace = function(value, api, 0x1900, "31c085ff7e0701f883ef0175f9c3", "sum_down",
                                       [("counter", integer)])
                with interface(value, core) as ifc:
                    opts = DecompileOptions()
                    for index, enabled in enumerate((False, True, False)):
                        opts.setNullToken(enabled)
                        assert ifc.setOptions(opts), str(ifc.getLastMessage())
                        observe(ifc, null, core, f"null_{index}", null_check(enabled),
                                driver="int main(void) { return return_null() != NULL; }\n")
                    opts.setNullToken(True)
                    assert ifc.setOptions(opts)
                    before = pid(ifc)
                    ifc.resetDecompiler()
                    assert pid(ifc) != before, "reset did not replace native process"
                    observe(ifc, null, core, "null_reset_replay", null_check(True),
                            driver="int main(void) { return return_null() != NULL; }\n")
                    ifc.closeProgram()
                    assert ifc.openProgram(value), str(ifc.getLastMessage())
                    observe(ifc, null, core, "null_reopen_replay", null_check(True),
                            driver="int main(void) { return return_null() != NULL; }\n")
                    assert ifc.setOptions(DecompileOptions())
                    observe(ifc, null, core, "null_fresh_options", null_check(False),
                            driver="int main(void) { return return_null() != NULL; }\n")
                    opts = DecompileOptions()
                    opts.setAnalyzeForLoops(False)
                    for index, enabled in enumerate((False, True, False)):
                        opts.setInplaceTokens(enabled)
                        opts.setFunctionBraceFormat(
                            DecompileOptions.BraceStyle.Same if enabled else DecompileOptions.BraceStyle.Skip)
                        assert ifc.setOptions(opts)
                        def inplace_check(result, ops, row, enabled=enabled):
                            assert ("+=" in row["c"]) == enabled, row
                            if enabled:
                                assert re.search(r"\bsum_down\s*\([^)]*\)[ \t]*\{", row["c"]), row
                            else:
                                assert re.search(r"\bsum_down\s*\([^)]*\)[ \t]*\n[ \t]*\n[ \t]*\{", row["c"]), row
                        observe(ifc, inplace, core, f"inplace_brace_{index}", inplace_check,
                                driver="int main(void) { return sum_down(7)!=28 || sum_down(0)!=0 || sum_down(-1)!=0; }\n")

                    for index, width in enumerate((20, 100, 20)):
                        opts = DecompileOptions()
                        opts.setMaxWidth(width)
                        assert ifc.setOptions(opts)
                        def width_check(result, ops, row, width=width):
                            lines = [line for line in row["c"].splitlines()
                                     if line.strip() and not line.lstrip().startswith(("/*", "*", "//"))]
                            # A margin cannot split one C identifier. Generated support
                            # names may exceed it, but must occupy their own line.
                            for line in lines:
                                if len(line) > width:
                                    token = line.strip()
                                    indent = len(line) - len(line.lstrip())
                                    assert re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", token), row
                                    assert len(token) > width - indent, row
                            row["line_widths"] = [len(line) for line in lines]
                            if width == 100:
                                # Test the requested function, not its support adapters.
                                body = re.search(r"\bwrap_sum\s*\([^)]*\)\s*\{[^{}]*\}", row["c"])
                                assert body is not None, row
                                assert any(len(line) > 20 for line in body.group().splitlines()), "wide layout remained narrow"
                        width_row = observe(ifc, wrapping, core, f"width_{index}_{width}", width_check,
                                            driver="int main(void) { return wrap_sum(1,2,3,4)!=11; }\n")
                        if width == 100:
                            wide_layout = width_row.get("line_widths")
                    assert ifc.setOptions(DecompileOptions())
                    def fresh_width(result, ops, row):
                        width_check(result, ops, row, width=100)
                        assert row["line_widths"] == wide_layout, row
                    observe(ifc, wrapping, core, "width_fresh_options", fresh_width,
                            driver="int main(void) { return wrap_sum(1,2,3,4)!=11; }\n")
                    for name, form, indent in (("hex", DecompileOptions.IntegerFormatEnum.Hexadecimal, 2),
                                               ("decimal", DecompileOptions.IntegerFormatEnum.Decimal, 6)):
                        opts = DecompileOptions()
                        opts.setIntegerFormat(form)
                        opts.setIndentWidth(indent)
                        assert ifc.setOptions(opts)
                        def number_check(result, ops, row, name=name, indent=indent):
                            token = "0x2a" if name == "hex" else "42"
                            match = re.search(r"(?m)^( +)return\s+" + token + r"\s*;", row["c"])
                            assert match is not None and len(match.group(1)) == indent, row
                        observe(ifc, literal, core, f"integer_indent_{name}", number_check,
                                driver="int main(void) { return literal_value()!=42; }\n")
                    assert ifc.setOptions(DecompileOptions())
                    def default_indent(result, ops, row):
                        match = re.search(r"(?m)^( +)return\b", row["c"])
                        assert match is not None and len(match.group(1)) == 2, row
                    observe(ifc, literal, core, "indent_fresh_options", default_indent,
                            driver="int main(void) { return literal_value()!=42; }\n")
                    for name, strategy in (("all", DecompileOptions.NamespaceStrategy.All),
                                           ("none", DecompileOptions.NamespaceStrategy.Never),
                                           ("minimal", DecompileOptions.NamespaceStrategy.Minimal)):
                        opts = DecompileOptions()
                        opts.setNamespaceStrategy(strategy)
                        assert ifc.setOptions(opts)
                        def namespace_check(result, ops, row, name=name):
                            targets = [int(op.getInput(0).getOffset()) for op in ops if op.getOpcode() == PcodeOp.CALL]
                            assert targets == [0x2100, 0x2200], row
                            separator = "::"
                            for scope in ("One", "Two"):
                                full = separator.join(("Outer", scope, "shared"))
                                short = separator.join((scope, "shared"))
                                if name == "all":
                                    assert full in row["c"], row
                                elif name == "minimal":
                                    assert short in row["c"] and full not in row["c"], row
                                else:
                                    assert short not in row["c"], row
                        observe(ifc, namespaced, core, "namespace_" + name, namespace_check)
                    for phase in ("none", "selected_cpp", "fresh"):
                        opts = DecompileOptions()
                        if phase != "fresh":
                            for category in ("PRE", "EOL", "POST", "PLATE", "Head"):
                                getattr(opts, "set" + category + "CommentIncluded")(
                                    phase == "selected_cpp" and category in ("PRE", "EOL"))
                            opts.setCommentStyle(DecompileOptions.CommentStyleEnum.CPPStyle)
                        assert ifc.setOptions(opts)
                        expected = {
                            "SESSION_PRE": bool(opts.isPRECommentIncluded()),
                            "SESSION_EOL": bool(opts.isEOLCommentIncluded()),
                            "SESSION_POST": bool(opts.isPOSTCommentIncluded()),
                            "SESSION_HEADER": bool(opts.isHeadCommentIncluded()),
                        }
                        def comment_check(result, ops, row, expected=expected, phase=phase):
                            for marker, included in expected.items():
                                assert (marker in row["c"]) == included, row
                                if included:
                                    if phase == "selected_cpp":
                                        assert re.search(r"//[^\n]*" + marker, row["c"]), row
                                    else:
                                        assert re.search(r"/\*(?:(?!\*/).)*" + marker, row["c"], re.S), row
                        observe(ifc, arithmetic, core, "comments_" + phase, comment_check,
                                driver="int main(void) { return plus_seven(35)!=42; }\n")

                    for name, fn, setter, checker, preamble, driver in (
                        ("unreachable", unreachable, "setEliminateUnreachable", check_unreachable, "",
                         "int main(void) { return unreachable_branch()!=7; }\n"),
                        ("split_pointer", split, "setSplitPointers", check_split,
                         "typedef struct { int a; short b,c; int d; } Fields;\n",
                         "int main(void) { Fields f={0,0,0,9}; store_fields(&f); return f.a!=256 || f.b!=512 || f.c!=-1 || f.d!=0; }\n"),
                        ("bitfields", bitfield, "setBitfieldAccess", bitfield_check,
                         "typedef struct { unsigned low:3,middle:5,high:24; } Bits;\n",
                         "int main(void) { Bits b={5,19,123}; return extract_middle(&b)!=19 || b.low!=5 || b.high!=123; }\n"),
                    ):
                        opts = DecompileOptions()
                        for index, enabled in enumerate((False, True, False)):
                            getattr(opts, setter)(enabled)
                            assert ifc.setOptions(opts), str(ifc.getLastMessage())
                            c_driver = None if name == "bitfields" and not enabled else driver
                            observe(ifc, fn, core, f"{name}_{index}", checker(enabled), preamble, c_driver)
                        assert ifc.setOptions(DecompileOptions())
                        observe(ifc, fn, core, f"{name}_fresh_options", checker(True), preamble, driver)

                    # A cached Java style is not an implicit native replay on SetOptions.
                    assert ifc.setSimplificationStyle("firstpass")
                    default_opts = DecompileOptions()
                    assert ifc.setOptions(default_opts)
                    def full_arithmetic(result, ops, row):
                        assert row["c"] is not None, row
                        assert all(op.getOpcode() != PcodeOp.INT_XOR for op in ops), row
                    observe(ifc, arithmetic, core, "style_snapshot_resets_root", full_arithmetic,
                            driver="int main(void) { return plus_seven(35)!=42; }\n")
                    default_opts.setPredicate(False)
                    assert ifc.setOptions(default_opts)
                    observe(ifc, arithmetic, core, "style_predicate_targets_reset_root", full_arithmetic,
                            driver="int main(void) { return plus_seven(35)!=42; }\n")
                    default_opts.setEliminateUnreachable(False)
                    assert ifc.setOptions(default_opts)
                    def firstpass_arithmetic(result, ops, row):
                        assert row["c"] is None and any(op.getOpcode() == PcodeOp.INT_XOR for op in ops), row
                    observe(ifc, arithmetic, core, "style_named_delta_selects_root", firstpass_arithmetic)
                    assert ifc.setOptions(DecompileOptions())
                    before = pid(ifc)
                    ifc.resetDecompiler()
                    assert pid(ifc) != before
                    observe(ifc, arithmetic, core, "style_reset_replays_cached_root", firstpass_arithmetic)

                    for style, modes in (("decompile", (False, True)),
                                         ("paramid", (True,)), ("firstpass", (False,))):
                        assert ifc.setSimplificationStyle(style), style
                        for measures in modes:
                            tree = not measures
                            ccode = not measures
                            assert ifc.toggleSyntaxTree(tree)
                            assert ifc.toggleCCode(ccode)
                            assert ifc.toggleParamMeasures(measures)
                            def envelope(result, ops, row, style=style, measures=measures, tree=tree, ccode=ccode):
                                measure_only = style == "paramid" and measures
                                assert row["measures"] == measures, row
                                assert row["highfunction"] == (not measure_only), row
                                assert (row["c"] is not None) == (style == "decompile" and ccode and not measure_only), row
                                if not tree:
                                    assert not ops, row
                                elif style == "firstpass":
                                    assert any(op.getOpcode() == PcodeOp.INT_XOR for op in ops), row
                                elif style == "decompile":
                                    assert all(op.getOpcode() != PcodeOp.INT_XOR for op in ops), row
                                if measures:
                                    info = result.getHighParamID()
                                    assert info.getFunctionAddress() == arithmetic.getEntryPoint(), row
                                    if style == "paramid":
                                        assert info.getNumInputs() == 1 and info.getNumOutputs() == 1, row
                                        assert info.getInput(0).getVarnode().getSize() == 4, row
                                        assert info.getOutput(0).getVarnode().getSize() == 4, row
                            observe(ifc, arithmetic, core, f"envelope_{style}_{int(measures)}_{len(rows)}", envelope)
                    assert ifc.setSimplificationStyle("decompile")
                    assert ifc.toggleParamMeasures(False)
                    assert ifc.toggleSyntaxTree(False)
                    assert ifc.toggleCCode(True)
                    def c_without_tree(result, ops, row):
                        assert row["highfunction"] and not ops and row["c"] is not None, row
                    observe(ifc, arithmetic, core, "c_without_tree", c_without_tree,
                            driver="int main(void) { return plus_seven(35)!=42; }\n")
                    assert ifc.toggleSyntaxTree(True)

                    # Rejected Java requests remain cached; repair them before reset/reopen.
                    invalid = DecompileOptions()
                    invalid.setMaxInstructions(-1)
                    assert not ifc.setOptions(invalid), "negative known instruction option accepted"
                    assert ifc.setOptions(DecompileOptions()), str(ifc.getLastMessage())
                    assert not ifc.setSimplificationStyle("future_missing_root"), "unknown root accepted"
                    assert ifc.setSimplificationStyle("decompile"), str(ifc.getLastMessage())
                    observe(ifc, arithmetic, core, "known_error_recovery", full_arithmetic,
                            driver="int main(void) { return plus_seven(35)!=42; }\n")
                    from java.io import File
                    from ghidra.app.emulator import EmulatorHelper
                    import xml.etree.ElementTree as ET

                    target_facts = fingerprint(target)
                    record_id = int(value.getDataTypeManager().getID(record))
                    for phase, nargs, fieldname in (("initial", 1, "before"), ("edited_flush", 2, "after"),
                                                    ("reset", 2, "after"), ("reopen", 1, "before")):
                        if phase in ("edited_flush", "reopen"):
                            with transaction(value):
                                record.getComponent(0).setFieldName(fieldname)
                                override(value, caller, nargs)
                        assert int(value.getDataTypeManager().getID(record)) == record_id
                        assert str(record.getComponent(0).getFieldName()) == fieldname
                        if phase == "edited_flush":
                            ifc.flushCache()
                        elif phase == "reset":
                            before = pid(ifc)
                            ifc.resetDecompiler()
                            assert pid(ifc) != before
                        elif phase == "reopen":
                            ifc.closeProgram()
                            assert ifc.openProgram(value), str(ifc.getLastMessage())

                        # Source metadata remains authoritative even when the
                        # execution call must preserve an additional live input.
                        namespace = HighFunction.findOverrideSpace(caller)
                        assert namespace is not None
                        stored = [HighFunctionDBUtil.readOverride(symbol)
                                  for symbol in value.getSymbolTable().getSymbols(namespace)
                                  if symbol.getAddress() == address(value, 0x1507)]
                        stored = [entry for entry in stored if entry is not None]
                        assert len(stored) == 1
                        declared = stored[0].getDataType()
                        assert str(declared.getCallingConventionName()) == "__stdcall"
                        assert not declared.hasVarArgs() and declared.getReturnType().isEquivalent(integer)
                        assert declared.getReturnType().getLength() == 4
                        assert len(declared.getArguments()) == nargs
                        for index, argument in enumerate(declared.getArguments()):
                            assert str(argument.getName()) == f"arg{index}"
                            assert argument.getDataType().isEquivalent(integer)
                            assert argument.getDataType().getLength() == 4

                        target_result = ifc.decompileFunction(target, 60, monitor)
                        assert target_result.decompileCompleted(), str(target_result.getErrorMessage())
                        source = target_result.getHighFunction().getFunctionPrototype()
                        assert source.getNumParams() == target.getParameterCount() == 2
                        assert source.getReturnType().isEquivalent(integer)
                        for index, (name, register) in enumerate((("x", "EDI"), ("y", "ESI"))):
                            host = target.getParameter(index)
                            decoded = source.getParam(index)
                            assert str(host.getName()) == str(decoded.getName()) == name
                            assert host.getDataType().isEquivalent(integer)
                            assert decoded.getDataType().isEquivalent(integer)
                            assert host.getDataType().getLength() == decoded.getDataType().getLength() == 4
                            assert decoded.getStorage() == host.getVariableStorage()
                            storage = decoded.getStorage().getVarnodes()
                            assert len(storage) == 1 and storage[0].getSize() == 4
                            assert storage[0].getAddress() == value.getRegister(register).getAddress()
                        assert target_result.getDecompiledFunction() is not None
                        target_c = str(target_result.getDecompiledFunction().getC())
                        (output / f"metadata_target_{phase}-{core}.c").write_text(target_c)
                        capture = output / f"metadata_{phase}-{core}.xml"
                        ifc.enableDebug(File(str(capture)))

                        def site_check(result, ops, row, nargs=nargs, fieldname=fieldname):
                            # This is the host declaration supplied during this
                            # actual decompile request, not a setter read-back.
                            # Java skips returned <override> records, so the wire
                            # evidence is not a claim about native source arity.
                            wire = []
                            for encoded in ET.parse(capture).getroot().findall(".//protooverride"):
                                site = encoded.find("addr")
                                assert site is not None and site.get("space") == "ram", row
                                assert int(site.get("offset"), 0) == 0x1507, row
                                proto = encoded.find("prototype")
                                assert proto is not None and proto.get("model") == "__stdcall", row
                                assert proto.get("modellock") == "true", row
                                assert proto.get("dotdotdot", "false") == "false", row
                                returned = proto.find("returnsym")
                                assert returned is not None and returned.get("typelock") == "true", row
                                return_type = returned.find("type")
                                assert return_type is not None, row
                                assert return_type.get("metatype") == "int" and int(return_type.get("size")) == 4, row
                                internal = proto.find("internallist")
                                assert internal is not None, row
                                arguments = internal.findall("param")
                                assert len(arguments) == nargs, row
                                for index, argument in enumerate(arguments):
                                    assert argument.get("name") == f"arg{index}", row
                                    assert argument.get("typelock") == "true", row
                                    datatype = argument.find("type")
                                    assert datatype is not None, row
                                    assert datatype.get("metatype") == "int" and int(datatype.get("size")) == 4, row
                                wire.append({"site": 0x1507, "source_arity": len(arguments),
                                             "input_sizes": [4] * len(arguments), "return_size": 4})
                            assert wire, row
                            row["source_override_wire"] = wire

                            calls = [op for op in ops if op.getOpcode() in (PcodeOp.CALL, PcodeOp.CALLIND)]
                            assert len(calls) == 1, row
                            call = calls[0]
                            assert call.getOpcode() == PcodeOp.CALL, row
                            assert call.getNumInputs() == (3 if core == "kuna" else nargs + 1), row
                            assert call.getSeqnum().getTarget() == address(value, 0x1507), row
                            assert call.getInput(0).getAddress() == target.getEntryPoint(), row
                            assert call.getOutput() is not None and call.getOutput().getSize() == 4, row
                            # Check the source load, not a blanket width change:
                            # MOV EDI,[RDI] reads four bytes; any widened carrier
                            # must derive from that value through zero extension.
                            loaded = call.getInput(1)
                            while loaded.getDef() is not None and loaded.getDef().getOpcode() in (
                                    PcodeOp.COPY, PcodeOp.CAST, PcodeOp.INT_ZEXT):
                                definition = loaded.getDef()
                                operand = definition.getInput(0)
                                if definition.getOpcode() == PcodeOp.INT_ZEXT:
                                    assert operand.getSize() == 4 and loaded.getSize() == 8, row
                                else:
                                    assert operand.getSize() == loaded.getSize(), row
                                loaded = operand
                            load = loaded.getDef()
                            assert load is not None and load.getOpcode() == PcodeOp.LOAD, row
                            assert loaded.getSize() == 4, row
                            if call.getNumInputs() == 3:
                                second = call.getInput(2)
                                assert second.isConstant() and second.getOffset() == 7, row
                                assert second.getSize() == call.getInput(1).getSize(), row
                            row["execution_input_sizes"] = [int(vn.getSize()) for vn in list(call.getInputs())[1:]]
                            parameter = result.getHighFunction().getFunctionPrototype().getParam(0)
                            assert parameter.getStorage() == caller.getParameter(0).getVariableStorage(), row
                            pointer = load.getInput(1)
                            while pointer.getDef() is not None:
                                definition = pointer.getDef()
                                assert definition.getOpcode() in (PcodeOp.COPY, PcodeOp.CAST, PcodeOp.PTRSUB), row
                                if definition.getOpcode() == PcodeOp.PTRSUB:
                                    assert definition.getInput(1).isConstant() and definition.getInput(1).getOffset() == 0, row
                                pointer = definition.getInput(0)
                            pointer_storage = parameter.getStorage().getVarnodes()
                            assert len(pointer_storage) == 1 and pointer.isInput(), row
                            assert pointer.getAddress() == pointer_storage[0].getAddress(), row
                            assert pointer.getSize() == pointer_storage[0].getSize(), row
                            pointer_type = parameter.getDataType()
                            assert isinstance(pointer_type, Pointer), row
                            decoded_record = pointer_type.getDataType()
                            manager = value.getDataTypeManager()
                            assert int(manager.getID(decoded_record)) == record_id, row
                            component = decoded_record.getComponentAt(0)
                            assert component is not None and component.getOffset() == 0, row
                            assert str(component.getFieldName()) == fieldname, row
                            assert component.getDataType().isEquivalent(integer) and component.getLength() == 4, row
                            field_tokens = []
                            def visit(node):
                                if isinstance(node, ClangFieldToken):
                                    datatype = node.getDataType()
                                    assert datatype is not None, row
                                    field_tokens.append({
                                        "datatype_id": int(manager.getID(datatype)),
                                        "offset": int(node.getOffset()), "name": str(node.getText()),
                                    })
                                for index in range(node.numChildren()):
                                    visit(node.Child(index))
                            visit(result.getCCodeMarkup())
                            assert field_tokens == [{"datatype_id": record_id, "offset": 0, "name": fieldname}], row
                            row["returned_field_tokens"] = field_tokens

                            emu = EmulatorHelper(value)
                            try:
                                emu.writeRegister("RDI", 0x6000)
                                emu.writeRegister("RSP", 0x7fe0)
                                emu.writeMemory(address(value, 0x7fe0), JArray(JByte)((0x7ff0).to_bytes(8, "little")))
                                emu.setBreakpoint(address(value, 0x7ff0))
                                assert emu.run(caller.getEntryPoint(), None, monitor), str(emu.getLastError())
                                assert emu.getExecutionAddress() == address(value, 0x7ff0), row
                                row["machine_result"] = int(str(emu.readRegister("RAX"))) & 0xffffffff
                                assert row["machine_result"] == 42, row
                            finally:
                                emu.dispose()

                            driver = "int main(void) { SessionRecord r={35}; return replay_call(&r)!=42; }\n"
                            if core == "kuna":
                                row["stdout"] = execute_export(value, [result], driver,
                                    output=output, stem=f"metadata_unit_{phase}-{core}")
                                row["c_executed"] = True
                            elif nargs == 1:
                                # Stock omits the live ESI input under the source
                                # override. The real two-input target exposes this
                                # incompatibility; a handwritten x-only stub hid it.
                                row["c_executed"] = False
                                row["evidence_scope"] = "Stock source-only call omits live ESI; unchanged target+caller is not executable C."
                            else:
                                unit = target_c + "\n" + row["c"]
                                (output / f"metadata_unit_{phase}-{core}.c").write_text(unit)
                                preamble = PREAMBLE + f"typedef struct {{ int {fieldname}; }} SessionRecord;\n"
                                row["stdout"] = execute_c(unit, preamble, driver)
                                row["c_executed"] = True
                        observe(ifc, caller, core, "metadata_" + phase, site_check)
                        assert fingerprint(target) == target_facts, "site facts changed callee"

            with program("doubleprecision_session", bits=32) as (value, api):
                with transaction(value):
                    wide = UnsignedLongLongDataType.dataType
                    fn = function(value, api, 0x1000, "8b4424048b5424080344240c13542410c3", "wide_add",
                                  [("x", wide), ("y", wide)], wide)
                    inferred = function(value, api, 0x1100, "01d001c8c3", "infer_register_args", [], locked=False)
                with interface(value, core) as ifc:
                    opts = DecompileOptions()
                    for index, enabled in enumerate((False, True, False)):
                        opts.setSimplifyDoublePrecision(enabled)
                        assert ifc.setOptions(opts)
                        def wide_check(result, ops, row, enabled=enabled):
                            carry = any(op.getOpcode() == PcodeOp.INT_CARRY for op in ops)
                            wide_add = any(op.getOpcode() == PcodeOp.INT_ADD and op.getOutput().getSize() == 8 for op in ops)
                            assert carry == (not enabled) and wide_add == enabled, row
                        observe(ifc, fn, core, f"doubleprecision_{index}", wide_check,
                                driver="int main(void) { return wide_add(0xffffffffULL,2)!=0x100000001ULL; }\n" if enabled else None)
                    unchanged = str(inferred.getSignature()), str(inferred.getSignatureSource())
                    for phase, model in (("named", "__regparm3"), ("default", "default"),
                                         ("named_again", "__regparm3"), ("reset", "__regparm3"),
                                         ("fresh_default", "default"), ("reopen", "default")):
                        opts = DecompileOptions()
                        opts.setProtoEvalModel(model)
                        assert ifc.setOptions(opts), str(ifc.getLastMessage())
                        if phase == "reset":
                            before = pid(ifc)
                            ifc.resetDecompiler()
                            assert pid(ifc) != before
                        elif phase == "reopen":
                            ifc.closeProgram()
                            assert ifc.openProgram(value), str(ifc.getLastMessage())
                        def inferred_check(result, ops, row, model=model):
                            proto = result.getHighFunction().getFunctionPrototype()
                            named = model == "__regparm3"
                            assert proto.getNumParams() == (3 if named else 0), row
                            if named:
                                for index, register in enumerate(("EAX", "EDX", "ECX")):
                                    storage = proto.getParam(index).getStorage()
                                    assert storage.size() == 4, row
                                    assert storage.getVarnodes()[0].getAddress() == value.getRegister(register).getAddress(), row
                        observe(ifc, inferred, core, "protoeval_" + phase, inferred_check,
                                preamble="#define __regparm3\n",
                                driver="int main(void) { return infer_register_args(20,15,7)!=42; }\n"
                                if model == "__regparm3" else None)
                        assert (str(inferred.getSignature()), str(inferred.getSignatureSource())) == unchanged, \
                            "evaluation policy changed ProgramDB signature facts"
                    opts = DecompileOptions()
                    opts.setProtoEvalModel("__regparm3")
                    for index, enabled in enumerate((False, True, False)):
                        opts.setConventionPrint(enabled)
                        assert ifc.setOptions(opts)
                        def convention_check(result, ops, row, enabled=enabled):
                            proto = result.getHighFunction().getFunctionPrototype()
                            assert proto.getNumParams() == 3, row
                            signature = str(result.getDecompiledFunction().getSignature())
                            assert ("__regparm3" in signature) == enabled, row
                        observe(ifc, inferred, core, f"convention_{index}", convention_check,
                                preamble="#define __regparm3\n",
                                driver="int main(void) { return infer_register_args(20,15,7)!=42; }\n")
    finally:
        exepath.set(None, original)
    report["completed"] = True
    failed = [f"{row['core']}:{row['case']}" for row in rows if not row.get("passed")]
    assert not failed, failed


if __name__ == "__main__":
    main()
