#!/usr/bin/env python3
"""Selected native positives and real Java exporter fault/recovery observations.

KUNA_CPP_EXPORTER_POLICY selects best-effort (default) or opt-in atomic
assertions, not installed Java. Full-Java positive coverage follows the actual
receiver capability independently of this stronger, unimplemented atomic policy.
"""
import base64
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import sys
import traceback

repo = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(repo / "tests" / "ghidra"))
output = Path(os.environ.get("KUNA_SMOKE_OUT", "java-cpp-exporter-proof")).resolve()
output.mkdir(parents=True, exist_ok=True)
report = {"passed": False, "scope": "selected-native CppExporter positives; unchanged C/H/providers, Java faults and recovery using genuine stock responses", "rows": [], "failures": []}
policy = os.environ.get("KUNA_CPP_EXPORTER_POLICY", "best-effort")
atomic_policy = policy == "atomic"
report["assertion_policy"] = policy
report["stock_native_roles"] = {
    "neutral_observer": "Verify the fault proxy preserves genuine stock result documents before mutation",
    "faults": "Test the installed Java receiver/exporter with genuine malformed/crash/cancelled input",
    "recovery": "Verify the installed Java exporter recovers with unchanged C/H/provider execution",
}
report["atomic_contract"] = {
    "status": "selected-unimplemented" if atomic_policy else "inactive-unimplemented",
    "requires": ["global failure on malformed/crash/cancelled",
                 "identical C and H destination sentinels", "no ghidra-cpp-*.tmp staging files"],
    "selection": "KUNA_CPP_EXPORTER_POLICY=atomic selects stronger assertions only; full Java does not imply atomic export and this selector installs nothing.",
}
try:
    if policy not in ("best-effort", "atomic"):
        raise ValueError("KUNA_CPP_EXPORTER_POLICY must be best-effort or atomic: " + policy)
    from kuna_vs_stock import KUNA_GHIDRA, get_exepath_field, selected_core, start_ghidra, test_cores
    cores = test_cores()
    report["group"] = "product" if "kuna" in cores else "stock-controls"
    report["selected_cores"] = cores
    start_ghidra()
    from jpype import JArray, JByte, JProxy
    from java.io import ByteArrayOutputStream, File
    from java.lang import Object
    from java.util import ArrayList, IdentityHashMap
    from ghidra.app.decompiler import (ClangFuncProto, ClangTypeToken, DecompInterface,
                                       DecompileOptions, DecompileProcessFactory, DecompileResults)
    from ghidra.app.util.exporter import CppExporter
    from ghidra.program.database import ProgramDB
    from ghidra.program.flatapi import FlatProgramAPI
    from ghidra.program.model.data import (BuiltInDataType, CategoryPath, DataTypeConflictHandler, EnumDataType,
                                          FunctionDefinitionDataType, IntegerDataType, PointerDataType,
                                          StructureDataType, TypedefDataType, UnsignedCharDataType,
                                          UnsignedLongLongDataType)
    from ghidra.program.model.lang import LanguageID, CompilerSpecID
    from ghidra.program.model.listing import Function, ParameterImpl, ReturnParameterImpl, Variable
    from ghidra.program.model.pcode import PackedEncode, ElementId, AttributeId
    from ghidra.program.model.symbol import SourceType
    from ghidra.program.util import DefaultLanguageService
    from ghidra.util.task import ConsoleTaskMonitor

    receiver_methods = {str(method.getName()) for method in DecompileResults.class_.getMethods()}
    full_java_methods = {"isEnhancedResult", "getDataTypeManager", "hasCurrentSourceAuthority"}
    full_java = full_java_methods <= receiver_methods
    report["installed_java"] = {
        "full_java": full_java,
        "required_result_methods": sorted(full_java_methods),
        "decompiler_origin": str(DecompInterface.class_.getProtectionDomain().getCodeSource().getLocation()),
        "exporter_origin": str(CppExporter.class_.getProtectionDomain().getCodeSource().getLocation()),
        "selection": "Discovered JVM classes; neither the group nor assertion policy installs Java",
    }
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
            if full_java:
                # Match imported image-offset typedefs with an untyped pointer base.
                # The source remains a null-target pointer, not an invented C alias.
                manager.resolve(TypedefDataType(CategoryPath.ROOT, "ExportOpaquePointer",
                                PointerDataType(None, 8, manager), manager),
                                DataTypeConflictHandler.DEFAULT_HANDLER)
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
        modes_override = os.environ.get("KUNA_CPP_EXPORTER_MODES")
        modes = (modes_override.split(",") if modes_override is not None
                 else [*cores, "malformed", "crash", "cancelled"])
        assert modes and all(mode in ("stock", "kuna", "malformed", "crash", "cancelled") for mode in modes)
        report["selected_modes"] = modes
        report["modes_override"] = modes_override
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
                        if full_java and types:
                            assert "typedef void *ExportOpaquePointer;" in row["h"], row["h"]
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

        for core, native in (("stock", stock), ("kuna", KUNA_GHIDRA)):
            if core not in modes:
                continue
            row = {"mode": "source_callable_presentation", "core": core,
                   "passed": False, "failures": [], "execution": []}
            report["rows"].append(row)
            consumer = Object()
            value = ProgramDB("source-callable-presentation", language,
                              language.getCompilerSpecByID(CompilerSpecID("gcc")), consumer)
            try:
                flat = FlatProgramAPI(value, monitor)
                manager = value.getDataTypeManager()
                # The first two are introduced-regression witnesses. Templates and keywords
                # exercise the fixed legal stem, rather than the C++ symbol transformer.
                specs = [
                    ("/Functions", "Callback", "Callback", 7),
                    ("/Functions", "Callback Type", "SpaceCallback", 11),
                    ("/Functions", "Callback<int>", "TemplateCallback", 13),
                    ("/Functions", "switch", "KeywordCallback", 17),
                    ("/First", "SharedCallable", "FirstShared", 19),
                    ("/Second", "SharedCallable", "SecondShared", 23),
                    ("/Functions", "code", "CodeCallback", 37),
                    ("/Functions", "ExportEquate", "EquateCallback", 43),
                    ("/Functions", "ExportEnum", "EnumCallback", 53),
                    ("/Functions", "PRecordForCallback", "CompositeCallback", 59),
                    ("/Functions", "undefined", "DefaultCallback", 67),
                    ("/Functions", "uchar", "BuiltinCallback", 71),
                    ("/Functions", "undefined8", "LateBuiltinCallback", 73),
                    ("/Functions", "ΔCallback", "UnicodeCallback", 31),
                    ("/Functions", "PlainCallable", "PlainCallback", 29),
                ]
                source_types = []
                tx = value.startTransaction("Author distinct callable source identities")
                try:
                    entry = value.getAddressFactory().getDefaultAddressSpace().getAddress(0x1000)
                    memory = flat.createMemoryBlock("code", entry,
                        JArray(JByte)(bytes.fromhex("b82a000000c3")), False)
                    memory.setExecute(True)
                    assert flat.disassemble(entry)
                    answer = flat.createFunction(entry, "get_answer")
                    answer.updateFunction("__stdcall", ReturnParameterImpl(IntegerDataType.dataType, value),
                        Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS, False,
                        SourceType.USER_DEFINED, JArray(Variable)([]))
                    convention = str(value.getCompilerSpec().getDefaultCallingConvention().getName())
                    for category, name, alias_name, expected in specs:
                        definition = FunctionDefinitionDataType(CategoryPath(category), name, manager)
                        definition.setCallingConvention(convention)
                        definition.setReturnType(IntegerDataType.dataType)
                        definition = manager.resolve(definition, DataTypeConflictHandler.DEFAULT_HANDLER)
                        alias = manager.resolve(TypedefDataType(alias_name,
                            PointerDataType(definition, manager)), DataTypeConflictHandler.DEFAULT_HANDLER)
                        source_types.append((definition, alias))
                    # An authored typedef already occupies the space-bearing type's transformed name.
                    manager.resolve(TypedefDataType("Callback_Type", IntegerDataType.dataType),
                                    DataTypeConflictHandler.DEFAULT_HANDLER)
                    value.getEquateTable().createEquate("ExportEquate", 41)
                    enum = EnumDataType(CategoryPath.ROOT, "define_ExportEnum", 4, manager)
                    enum.add("only", 47)
                    manager.resolve(enum, DataTypeConflictHandler.DEFAULT_HANDLER)
                    record = StructureDataType("RecordForCallback", 0, manager)
                    record.add(IntegerDataType.dataType, "value", None)
                    record.add(UnsignedCharDataType.dataType, "byte", None)
                    manager.resolve(record, DataTypeConflictHandler.DEFAULT_HANDLER)
                    transported_functions = {}
                    if full_java:
                        # Use the original named function leaf, not SpaceCallback: its typedef
                        # would hide the callable spelling from the formal and CAST tokens.
                        callable_pointer = PointerDataType(source_types[1][0], manager)
                        for offset, name, code, returned, parameters in (
                                (0x1100, "invoke_space_callback", "ffe7",
                                 IntegerDataType.dataType, [("callback", callable_pointer)]),
                                (0x1120, "space_callback_from_bits", "4889f8c3",
                                 callable_pointer, [("bits", UnsignedLongLongDataType.dataType)])):
                            entry = value.getAddressFactory().getDefaultAddressSpace().getAddress(offset)
                            memory = flat.createMemoryBlock(name, entry,
                                JArray(JByte)(bytes.fromhex(code)), False)
                            memory.setExecute(True)
                            assert flat.disassemble(entry)
                            transported = flat.createFunction(entry, name)
                            assert transported is not None
                            transported.updateFunction("__stdcall", ReturnParameterImpl(returned, value),
                                Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS, False,
                                SourceType.USER_DEFINED, JArray(Variable)([
                                    ParameterImpl(parameter, datatype, value)
                                    for parameter, datatype in parameters]))
                            transported_functions[name] = transported
                    if core == "kuna":
                        copy_entry = value.getAddressFactory().getDefaultAddressSpace().getAddress(0x2000)
                        memory = flat.createMemoryBlock("copy_code", copy_entry,
                            JArray(JByte)(bytes.fromhex("488b0748894708c3")), False)
                        memory.setExecute(True)
                        assert flat.disassemble(copy_entry)
                        copy_words = flat.createFunction(copy_entry, "copy_words")
                        assert copy_words is not None
                finally:
                    value.endTransaction(tx, True)
                assert not any(isinstance(data_type, BuiltInDataType) and
                               str(data_type.getName()) == "undefined8"
                               for data_type in manager.getAllDataTypes())
                def callable_sources():
                    return [{"path": str(definition.getPathName()), "id": int(manager.getID(definition)),
                             "alias_path": str(alias.getPathName()), "alias_id": int(manager.getID(alias)),
                             "target_id": int(manager.getID(alias.getDataType().getDataType()))}
                            for definition, alias in source_types]
                before = callable_sources()
                assert all(item["id"] == item["target_id"] for item in before), before
                assert len({item["id"] for item in before}) == len(specs), before
                revision = int(value.getModificationNumber())
                source_functions = {"answer": answer}
                source_functions.update(transported_functions)
                if core == "kuna":
                    source_functions["copy_words"] = copy_words
                before_functions = source_snapshot(source_functions)
                if full_java:
                    callable_definition = source_types[1][0]
                    callable_identity = IdentityHashMap()
                    callable_identity.put(callable_definition, True)
                    callable_id = int(manager.getID(callable_definition))
                    row["transported_callable_bindings"] = []
                    with selected_core(native):
                        interface = DecompInterface()
                        try:
                            assert interface.setOptions(DecompileOptions())
                            assert interface.openProgram(value), str(interface.getLastMessage())
                            for name, transported in transported_functions.items():
                                result = interface.decompileFunction(transported, 60, monitor)
                                assert result.decompileCompleted(), str(result.getErrorMessage())
                                high = result.getHighFunction()
                                assert high is not None and result.getCCodeMarkup() is not None
                                prototype = high.getFunctionPrototype()
                                assert prototype.getNumParams() == 1
                                expected_parameter = transported.getParameter(0).getDataType()
                                expected_return = transported.getReturnType()
                                assert prototype.getParam(0).getDataType().isEquivalent(expected_parameter)
                                assert prototype.getReturnType().isEquivalent(expected_return)
                                pointer = (prototype.getParam(0).getDataType()
                                           if name == "invoke_space_callback"
                                           else prototype.getReturnType())
                                assert callable_identity.containsKey(pointer.getDataType())
                                assert int(manager.getID(pointer.getDataType())) == callable_id
                                bindings = []
                                def callable_tokens(token, in_prototype=False):
                                    in_prototype = in_prototype or isinstance(token, ClangFuncProto)
                                    if isinstance(token, ClangTypeToken):
                                        datatype = token.getDataType()
                                        if (datatype is not None and
                                                str(datatype.getName()) == str(callable_definition.getName())):
                                            assert callable_identity.containsKey(datatype)
                                            assert int(manager.getID(datatype)) == callable_id
                                            bindings.append(in_prototype)
                                    for child in range(token.numChildren()):
                                        callable_tokens(token.Child(child), in_prototype)
                                callable_tokens(result.getCCodeMarkup())
                                assert bindings == ([True] if name == "invoke_space_callback"
                                                    else [True, False]), (name, bindings)
                                row["transported_callable_bindings"].append({
                                    "function": name, "source_id": callable_id,
                                    "prototype_leaves": bindings.count(True),
                                    "body_cast_leaves": bindings.count(False)})
                        finally:
                            interface.dispose()
                destination = output / ("source-callables-" + core + ".c")
                with selected_core(native):
                    assert CppExporter(DecompileOptions(), True, True, True, True, False, "").export(
                        File(str(destination)), value, None, ConsoleTaskMonitor())
                header = destination.with_suffix(".h")
                row["c"], row["h"] = destination.read_text(), header.read_text()
                nominal_names = []
                if full_java:
                    for _, _, alias_name, _ in specs:
                        match = re.search(r"(?m)^typedef (\w+) \*" +
                                          re.escape(alias_name) + r";$", row["h"])
                        assert match, (alias_name, row["h"])
                        nominal = match.group(1)
                        assert re.search(r"(?m)^typedef int \(" + re.escape(nominal) +
                                         r"\)\(void\);$", row["h"]), (nominal, row["h"])
                        nominal_names.append(nominal)
                    assert len(set(nominal_names)) == len(specs), nominal_names
                    assert nominal_names[-2] == "ΔCallback", nominal_names
                    assert nominal_names[-1] == "PlainCallable", nominal_names
                driver = destination.with_name(destination.stem + "-driver.c")
                providers = [f"static int provider{i}(void) {{ return {expected}; }}"
                             for i, (_, _, _, expected) in enumerate(specs)]
                checks = []
                for i, (_, _, alias_name, expected) in enumerate(specs):
                    checks.append(f"{alias_name} callback{i} = provider{i};"
                                  f"if (callback{i}() != {expected}) return {i + 1};")
                    if full_java:
                        checks.append(f"{nominal_names[i]} *nominal{i} = provider{i};"
                                      f"if (nominal{i}() != {expected}) return {i + 11};")
                if full_java:
                    for index in (1, 2):
                        checks.append(
                            f"if(invoke_space_callback(provider{index})!={specs[index][3]})return 40;"
                            f"SpaceCallback recovered{index}=space_callback_from_bits((uintptr_t)provider{index});"
                            f"if(recovered{index}!=provider{index}||recovered{index}()!={specs[index][3]})return 41;")
                    checks.append("if(recovered1==recovered2)return 42;")
                late_values = (
                    "const uint64_t values[]={0,1,255,UINT64_C(0x1234567887654321),UINT64_MAX};"
                    "for(unsigned i=0;i<5;++i){uint64_t words[2]={values[i],7};"
                    "copy_words((void*)words);"
                    "if(words[0]!=values[i]||words[1]!=values[i])return 31;}"
                    if core == "kuna" else "")
                driver.write_text('#include <stdint.h>\n#include "' + header.name + '"\n' + "\n".join(providers) +
                    "\nint main(void) { Callback_Type reserved = 31;"
                    "RecordForCallback record = {61, 5}; PRecordForCallback pointer = &record;"
                    "undefined byte = 5; uchar builtin = 71; code *opaque = 0;"
                    "if (reserved != 31 || get_answer() != 42 || ExportEquate != 41 || ExportEnum != 47"
                    " || pointer->value != 61 || pointer->byte != byte || builtin != 71 || opaque) return 30;" +
                    "".join(checks) + late_values + "return 0; }\n")
                for optimization in ("-O0", "-O2"):
                    binary = destination.with_name(destination.stem + optimization)
                    command = [os.environ.get("CC", "cc"), "-std=c11",
                               "-Werror=implicit-function-declaration",
                               "-Werror=incompatible-pointer-types", optimization,
                               str(destination), str(driver), "-o", str(binary)]
                    built = subprocess.run(command, text=True, capture_output=True, timeout=120)
                    receipt = {"command": command, "status": built.returncode,
                               "stdout": built.stdout, "stderr": built.stderr}
                    row["execution"].append(receipt)
                    assert built.returncode == 0, receipt
                    ran = subprocess.run([str(binary)], text=True, capture_output=True, timeout=30)
                    receipt = {"command": [str(binary)], "status": ran.returncode,
                               "stdout": ran.stdout, "stderr": ran.stderr}
                    row["execution"].append(receipt)
                    assert ran.returncode == 0, receipt
                assert callable_sources() == before
                assert source_snapshot(source_functions) == before_functions
                assert int(value.getModificationNumber()) == revision
                row.update(passed=True, source_types=before, source_unchanged=True,
                           nominal_names=nominal_names)
            except Exception:
                row["failures"].append({"stage": "source-callable-presentation",
                                        "failure": traceback.format_exc()})
            finally:
                value.release(consumer)

        if full_java and "kuna" in cores and "kuna" in modes:
            from ghidra.app.decompiler.parallel import DecompileConfigurer
            from ghidra.program.model.address import AddressSet
            row = {"mode": "configured_export_consumers", "passed": False,
                   "failures": [], "phases": []}
            report["rows"].append(row)
            consumer = Object()
            value = ProgramDB("configured-export-consumers", language,
                              language.getCompilerSpecByID(CompilerSpecID("gcc")), consumer)
            try:
                flat = FlatProgramAPI(value, monitor)
                configured_functions = {}
                tx = value.startTransaction("Original non-inline caller and constant-return provider")
                try:
                    convention = str(value.getCompilerSpec().getDefaultCallingConvention().getName())
                    for offset, name, code in (
                            (0x1000, "caller", "e8fb0f0000c3"),
                            (0x2000, "callee", "b82a000000c3")):
                        entry = value.getAddressFactory().getDefaultAddressSpace().getAddress(offset)
                        memory = flat.createMemoryBlock(name, entry,
                            JArray(JByte)(bytes.fromhex(code)), False)
                        memory.setExecute(True)
                        assert flat.disassemble(entry)
                        configured_function = flat.createFunction(entry, name)
                        assert configured_function is not None
                        configured_function.updateFunction(convention,
                            ReturnParameterImpl(IntegerDataType.dataType, value),
                            Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS, False,
                            SourceType.USER_DEFINED, JArray(Variable)([]))
                        assert not configured_function.isInline()
                        configured_functions[name] = configured_function
                finally:
                    value.endTransaction(tx, True)
                configured_before = source_snapshot(configured_functions)
                configured_revision = int(value.getModificationNumber())
                roots = ArrayList()
                roots.add(configured_functions["caller"])
                selection = AddressSet(configured_functions["caller"].getBody())
                for enabled in (False, True):
                    # Equal constructor/callback options would pass even if either factory
                    # lost its configurer. Each real consumer must observe the override.
                    defaults = DecompileOptions()
                    defaults.setExportInline(not enabled)
                    configured_options = DecompileOptions()
                    configured_options.setExportInline(enabled)
                    configured_interfaces = []
                    def configure(interface):
                        assert interface.setOptions(configured_options)
                        configured_interfaces.append(True)
                    configurer = JProxy(DecompileConfigurer, dict(configure=configure))
                    configured_exporter = CppExporter(defaults, True, True, True, True, False, "")
                    configured_exporter.setConfigurer(configurer)
                    directory = output / ("configured-export-" + ("on" if enabled else "off"))
                    directory.mkdir(exist_ok=True)
                    phase = {"enabled": enabled, "constructor_enabled": not enabled,
                             "surfaces": []}
                    row["phases"].append(phase)
                    destination = directory / "unit.c"
                    with selected_core(KUNA_GHIDRA):
                        prepared = configured_exporter.prepareSelectedRoots(value, roots, monitor)
                        assert len(prepared) == 1
                        prepared_result = prepared[0]
                        assert prepared_result.decompileCompleted(), str(prepared_result.getErrorMessage())
                        assert prepared_result.isEnhancedResult()
                        assert prepared_result.getHighFunction() is not None
                        assert prepared_result.getCCodeMarkup() is not None
                        prepared_function = prepared_result.getDecompiledFunction()
                        assert prepared_function is not None
                        prepared_source = directory / "prepared.c"
                        prepared_source.write_text(str(prepared_function.getC()))
                        assert configured_exporter.export(
                            File(str(destination)), value, selection, monitor)
                    phase["configured_interfaces"] = len(configured_interfaces)
                    provider = directory / "provider.c"
                    provider.write_text("int callee(void) { return 42; }\n")
                    provider_header = directory / "provider.h"
                    provider_header.write_text("int callee(void);\n")
                    for surface, source in (("prepared", prepared_source), ("exported", destination)):
                        observation = {"surface": surface, "c": source.read_text(), "execution": []}
                        phase["surfaces"].append(observation)
                        if surface == "exported":
                            observation["h"] = destination.with_suffix(".h").read_text()
                        driver = directory / (surface + "-driver.c")
                        declaration = (str(prepared_function.getSignature()) + "\n"
                                       if surface == "prepared" else '#include "unit.h"\n')
                        driver.write_text(declaration + "int main(void) { return caller()!=42; }\n")
                        for optimization in ("-O0", "-O2"):
                            binary = directory / (surface + optimization)
                            command = shlex.split(os.environ.get("CC", "cc")) + [
                                "-std=c11", "-Werror=implicit-function-declaration", optimization,
                                "-include", str(provider_header), str(source), str(driver)]
                            if not enabled:
                                # Prove a real dependency, not merely the presence of call text.
                                missing = subprocess.run(command + ["-o", str(binary)],
                                    text=True, capture_output=True, timeout=120)
                                receipt = {"command": command + ["-o", str(binary)],
                                           "expected": "missing callee provider", "status": missing.returncode,
                                           "stdout": missing.stdout, "stderr": missing.stderr}
                                observation["execution"].append(receipt)
                                assert missing.returncode != 0 and "callee" in missing.stderr, receipt
                                command.append(str(provider))
                            command += ["-o", str(binary)]
                            built = subprocess.run(command, text=True, capture_output=True, timeout=120)
                            receipt = {"command": command, "status": built.returncode,
                                       "stdout": built.stdout, "stderr": built.stderr}
                            observation["execution"].append(receipt)
                            assert built.returncode == 0, receipt
                            ran = subprocess.run([str(binary)], text=True, capture_output=True, timeout=30)
                            receipt = {"command": [str(binary)], "status": ran.returncode,
                                       "stdout": ran.stdout, "stderr": ran.stderr}
                            observation["execution"].append(receipt)
                            assert ran.returncode == 0, receipt
                    assert source_snapshot(configured_functions) == configured_before
                    assert all(not fn.isInline() for fn in configured_functions.values())
                    assert int(value.getModificationNumber()) == configured_revision
                    phase["source_unchanged"] = True
                row.update(passed=True, source_before=configured_before, source_unchanged=True)
            except Exception:
                row["failures"].append({"stage": "configured-export-consumers",
                                        "failure": traceback.format_exc()})
            finally:
                value.release(consumer)

            from ghidra.program.model.data import ParameterDefinition, ParameterDefinitionImpl
            from support import execute_i386_publication
            row = {"mode": "configured_export_convention", "passed": False,
                   "constructor_convention_print": False, "effective_convention_print": True,
                   "failures": []}
            report["rows"].append(row)
            consumer = Object()
            windows32 = DefaultLanguageService.getLanguageService().getLanguage(
                LanguageID("x86:LE:32:default"))
            value = ProgramDB("configured-export-convention", windows32,
                              windows32.getCompilerSpecByID(CompilerSpecID("windows")), consumer)
            try:
                flat = FlatProgramAPI(value, monitor)
                manager = value.getDataTypeManager()
                tx = value.startTransaction("Explicit cdecl callback under Windows stdcall default")
                try:
                    entry = value.getAddressFactory().getDefaultAddressSpace().getAddress(0x1000)
                    memory = flat.createMemoryBlock("code", entry,
                        JArray(JByte)(bytes.fromhex("8b442404ff742408ffd083c404c3")), False)
                    memory.setExecute(True)
                    assert flat.disassemble(entry)
                    invoke = flat.createFunction(entry, "invoke")
                    assert invoke is not None
                    callback = FunctionDefinitionDataType("CallbackFunction", manager)
                    callback.setReturnType(IntegerDataType.dataType)
                    callback.setCallingConvention("__cdecl")
                    callback.setArguments(JArray(ParameterDefinition)([
                        ParameterDefinitionImpl("x", IntegerDataType.dataType, None)]))
                    callback = manager.resolve(callback, DataTypeConflictHandler.DEFAULT_HANDLER)
                    alias = manager.resolve(TypedefDataType("Callback", PointerDataType(callback, manager)),
                                            DataTypeConflictHandler.DEFAULT_HANDLER)
                    invoke.updateFunction("__cdecl", ReturnParameterImpl(IntegerDataType.dataType, value),
                        Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS, False,
                        SourceType.USER_DEFINED, JArray(Variable)([
                            ParameterImpl("callback", alias, value),
                            ParameterImpl("x", IntegerDataType.dataType, value)]))
                finally:
                    value.endTransaction(tx, True)
                assert str(value.getCompilerSpec().getDefaultCallingConvention().getName()) == "__stdcall"
                assert str(callback.getCallingConventionName()) == "__cdecl"
                assert str(invoke.getCallingConventionName()) == "__cdecl"
                def convention_sources():
                    return {"functions": source_snapshot({"invoke": invoke}),
                            "invoke_convention": str(invoke.getCallingConventionName()),
                            "callback_path": str(callback.getPathName()),
                            "callback_id": int(manager.getID(callback)),
                            "callback_prototype": str(callback.getPrototypeString(True)),
                            "callback_convention": str(callback.getCallingConventionName()),
                            "alias_path": str(alias.getPathName()),
                            "alias_id": int(manager.getID(alias)),
                            "alias_target_id": int(manager.getID(alias.getDataType().getDataType())),
                            "revision": int(value.getModificationNumber())}
                before = convention_sources()
                defaults = DecompileOptions()
                defaults.setConventionPrint(False)
                effective = DecompileOptions()
                effective.setConventionPrint(True)
                configured_interfaces = []
                def configure_convention(interface):
                    assert interface.setOptions(effective)
                    configured_interfaces.append(True)
                configured_exporter = CppExporter(defaults, True, True, True, True, False, "")
                configured_exporter.setConfigurer(
                    JProxy(DecompileConfigurer, dict(configure=configure_convention)))
                directory = output / "configured-export-convention"
                directory.mkdir(exist_ok=True)
                destination = directory / "unit.c"
                with selected_core(KUNA_GHIDRA):
                    assert configured_exporter.export(File(str(destination)), value, None, monitor)
                assert configured_interfaces
                header = destination.with_suffix(".h")
                row.update(c=destination.read_text(), h=header.read_text(),
                           configured_interfaces=len(configured_interfaces), source_before=before)
                driver = directory / "driver.c"
                driver.write_text('#include "unit.h"\n'
                    'static int __cdecl provider(int x) { return x+3; }\n'
                    'int main(void) { return invoke(provider,4)!=7; }\n')
                # The compiler's stdcall default makes an omitted callback convention
                # incompatible with this genuine cdecl provider, not just different text.
                execute_i386_publication(row, directory, header, destination, driver, True)
                row["source_after"] = convention_sources()
                assert row["source_after"] == before
                row.update(passed=True, source_unchanged=True)
            except Exception:
                row["failures"].append({"stage": "configured-export-convention",
                                        "failure": traceback.format_exc()})
            finally:
                value.release(consumer)

        if full_java and "kuna" in cores and "kuna" in modes:
            from ghidra.app.util.opinion import ElfLoader
            from ghidra.program.model.address import AddressSet
            from ghidra.program.model.listing import Library
            from ghidra.program.model.pcode import PcodeOp
            for case in ("raw_import", "user_external", "custom_external"):
                row = {"mode": "optional_external_binding_compatibility", "case": case,
                       "passed": False, "failures": []}
                report["rows"].append(row)
                consumer = Object()
                value = ProgramDB(case, language,
                                  language.getCompilerSpecByID(CompilerSpecID("gcc")), consumer)
                try:
                    flat = FlatProgramAPI(value, monitor)
                    tx = value.startTransaction("Actual optional external binding edge")
                    try:
                        if case != "raw_import":
                            value.setExecutableFormat(ElfLoader.ELF_NAME)
                        source = SourceType.USER_DEFINED if case == "user_external" else SourceType.IMPORTED
                        location = value.getExternalManager().addExtFunction(
                            Library.UNKNOWN, "compat_external", None, source)
                        external = location.getFunction()
                        external.updateFunction("__stdcall", ReturnParameterImpl(IntegerDataType.dataType, value),
                            Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS, False,
                            source, JArray(Variable)([]))
                        if case == "custom_external":
                            external.setCustomVariableStorage(True)
                        space = value.getAddressFactory().getDefaultAddressSpace()
                        caller_entry, thunk_entry = space.getAddress(0x1000), space.getAddress(0x2000)
                        for entry, name, code in (
                                (caller_entry, "compat_caller", "e8fb0f0000c3"),
                                (thunk_entry, "compat_thunk", "c3")):
                            memory = flat.createMemoryBlock(name, entry, JArray(JByte)(bytes.fromhex(code)), False)
                            memory.setExecute(True)
                            assert flat.disassemble(entry)
                        caller = flat.createFunction(caller_entry, "compat_caller")
                        thunk = flat.createFunction(thunk_entry, "compat_thunk")
                        assert caller is not None and thunk is not None
                        caller.updateFunction("__stdcall", ReturnParameterImpl(IntegerDataType.dataType, value),
                            Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS, False,
                            SourceType.USER_DEFINED, JArray(Variable)([]))
                        thunk.setThunkedFunction(external)
                        assert thunk.isThunk() and thunk.getThunkedFunction(True) == external
                    finally:
                        value.endTransaction(tx, True)
                    sources = {"caller": caller, "external": external}
                    before = source_snapshot(sources)
                    revision = int(value.getModificationNumber())
                    with selected_core(KUNA_GHIDRA):
                        interface = DecompInterface()
                        try:
                            assert interface.openProgram(value), str(interface.getLastMessage())
                            result = interface.decompileFunction(caller, 60, monitor)
                            assert result.decompileCompleted(), str(result.getErrorMessage())
                            assert result.isEnhancedResult() and result.hasCurrentSourceAuthority()
                            calls = [op for op in result.getHighFunction().getPcodeOps()
                                     if op.getOpcode() == PcodeOp.CALL]
                            assert calls, "Compatibility control must exercise an actual external CALL"
                            assert any(value.getFunctionManager().getFunctionAt(op.getInput(0).getAddress()) in
                                       (thunk, external) for op in calls)
                            original_c = str(result.getDecompiledFunction().getC())
                            callee_names = [str(target.getName()) for target in (thunk, external)
                                            if str(target.getName()) + "(" in original_c]
                            assert callee_names, original_c
                        finally:
                            interface.dispose()
                        destination = output / ("optional-external-" + case + ".c")
                        edge_options = DecompileOptions()
                        edge_exporter = CppExporter(edge_options, True, True, True, True, False, "")
                        assert edge_exporter.export(File(str(destination)), value,
                                                    AddressSet(caller.getBody()), ConsoleTaskMonitor())
                    emitted, declarations = destination.read_text(), destination.with_suffix(".h").read_text()
                    assert "compat_caller" in emitted, emitted
                    assert all(name + "(" in emitted for name in callee_names), emitted
                    assert "__asm__(" not in declarations, declarations
                    assert source_snapshot(sources) == before
                    assert int(value.getModificationNumber()) == revision
                    row.update(passed=True, completed=True, actual_enhanced_call=True,
                               decompiled_c=original_c, emitted_c=emitted,
                               optional_binding_added=False, source_unchanged=True)
                except Exception:
                    row["failures"].append({"stage": "actual-external-compatibility",
                                            "failure": traceback.format_exc()})
                finally:
                    value.release(consumer)

            row = {"mode": "source_callable_late_class_alias", "core": "kuna",
                   "passed": False, "failures": [], "execution": []}
            report["rows"].append(row)
            consumer = Object()
            class_language = DefaultLanguageService.getLanguageService().getLanguage(
                LanguageID("x86:LE:32:default"))
            value = ProgramDB("late-class-alias", class_language,
                class_language.getCompilerSpecByID(CompilerSpecID("gcc")), consumer)
            try:
                flat = FlatProgramAPI(value, monitor)
                manager = value.getDataTypeManager()
                tx = value.startTransaction("Author a class method and global caller")
                try:
                    klass = value.getSymbolTable().createClass(None, "LateClass", SourceType.USER_DEFINED)
                    sources = {}
                    for name, offset, code in (
                            ("call_method", 0x1000, "6a00e8f90f000083c404c3"),
                            ("read_value", 0x2000, "b82a000000c3")):
                        entry = value.getAddressFactory().getDefaultAddressSpace().getAddress(offset)
                        memory = flat.createMemoryBlock(name, entry,
                            JArray(JByte)(bytes.fromhex(code)), False)
                        memory.setExecute(True)
                        assert flat.disassemble(entry)
                        sources[name] = flat.createFunction(entry, name)
                        assert sources[name] is not None
                    caller, method = sources["call_method"], sources["read_value"]
                    method.setParentNamespace(klass)
                    for class_function, convention in (
                            (method, "__thiscall"),
                            (caller, str(value.getCompilerSpec().getDefaultCallingConvention().getName()))):
                        class_function.updateFunction(convention,
                            ReturnParameterImpl(IntegerDataType.dataType, value),
                            Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS, False,
                            SourceType.USER_DEFINED, JArray(Variable)([]))
                    definition = FunctionDefinitionDataType(CategoryPath("/Callbacks"), "PLateClass", manager)
                    definition.setCallingConvention(
                        str(value.getCompilerSpec().getDefaultCallingConvention().getName()))
                    definition.setReturnType(IntegerDataType.dataType)
                    definition = manager.resolve(definition, DataTypeConflictHandler.DEFAULT_HANDLER)
                    alias = manager.resolve(TypedefDataType("Callback", PointerDataType(definition, manager)),
                                            DataTypeConflictHandler.DEFAULT_HANDLER)
                finally:
                    value.endTransaction(tx, True)
                tx = value.startTransaction("User deletes the automatically created class datatype")
                try:
                    managed = manager.getDataType(CategoryPath.ROOT, "LateClass")
                    assert managed is not None
                    assert manager.remove(managed)
                finally:
                    value.endTransaction(tx, True)
                assert manager.getDataType(CategoryPath.ROOT, "LateClass") is None
                assert method.getAutoParameterCount() == 1
                placeholder = method.getParameter(0).getDataType().getDataType()
                assert str(placeholder.getName()) == "LateClass" and manager.getID(placeholder) < 0
                def class_sources():
                    return {"revision": int(value.getModificationNumber()),
                            "class_id": int(klass.getSymbol().getID()), "functions": source_snapshot(sources),
                            "source_path": str(definition.getPathName()), "source_id": int(manager.getID(definition)),
                            "alias_id": int(manager.getID(alias)),
                            "alias_target_id": int(manager.getID(alias.getDataType().getDataType())),
                            "inventory": sorted((str(dt.getPathName()), int(manager.getID(dt)))
                                                for dt in manager.getAllDataTypes())}
                before = class_sources()
                assert before["source_id"] == before["alias_target_id"]
                with selected_core(KUNA_GHIDRA):
                    interface = DecompInterface()
                    try:
                        assert interface.openProgram(value), str(interface.getLastMessage())
                        result = interface.decompileFunction(caller, 60, monitor)
                        assert result.decompileCompleted(), str(result.getErrorMessage())
                        assert result.isEnhancedResult()
                        assert result.getHighFunction() is not None and result.getCCodeMarkup() is not None
                        assert any(op.getOpcode() == PcodeOp.CALL and
                                   op.getInput(0).getAddress() == method.getEntryPoint()
                                   for op in result.getHighFunction().getPcodeOps())
                        assert any(str(dt.getName()) == "LateClass" and manager.getID(dt) < 0
                                   for dt in result.getDataTypeManager().getRetainedSourceDataTypes())
                    finally:
                        interface.dispose()
                    destination = output / "late-class-alias.c"
                    assert CppExporter(DecompileOptions(), True, False, True, True, False, "").export(
                        File(str(destination)), value, AddressSet(caller.getBody()), ConsoleTaskMonitor())
                assert not destination.exists()
                header = destination.with_suffix(".h")
                row["h"] = header.read_text()
                driver = output / "late-class-alias-driver.c"
                driver.write_text('#include "' + header.name + '"\n'
                    'static int provider(void) { return 7; }\n'
                    'int main(void) { Callback callback = provider; LateClass *object = 0;'
                    'PLateClass object_alias = object; return callback() != 7 || object_alias != 0; }\n')
                for optimization in ("-O0", "-O2"):
                    binary = output / ("late-class-alias" + optimization)
                    for command in ([os.environ.get("CC", "cc"), "-std=c11", "-Wall",
                                     "-Werror=incompatible-pointer-types", optimization,
                                     str(driver), "-o", str(binary)], [str(binary)]):
                        ran = subprocess.run(command, text=True, capture_output=True, timeout=120)
                        receipt = {"command": command, "status": ran.returncode,
                                   "stdout": ran.stdout, "stderr": ran.stderr}
                        row["execution"].append(receipt)
                        assert ran.returncode == 0, receipt
                assert class_sources() == before
                assert manager.getDataType(CategoryPath.ROOT, "LateClass") is None
                row.update(passed=True, source_unchanged=True, retained_nondb_class=True)
            except Exception:
                row["failures"].append({"stage": "late-class-alias", "failure": traceback.format_exc()})
            finally:
                value.release(consumer)

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
            "empty_function_contract": "Best-effort receiver/export outcomes are observations, not acceptance of silent body loss. The original malformed/global-failure, both-sentinel and staging obligations remain conditional on explicit atomic assertion policy, not full-Java capability; empty replacement markup is not the unknown4030 decoder error.",
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
                                 "timed_out": bool(result.isTimedOut()),
                                 "cancelled": bool(result.isCancelled()),
                                 "failed_to_start": bool(result.failedToStart()),
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
        if not atomic_policy:
            fault_cases.append(("malformed", "empty-extra-function", original_config))
        fault_cases.extend((mode, mode, config) for mode in ("crash", "cancelled"))
        for mode, kind, selected_config, warnings in (
                (mode, kind, selected_config, warnings)
                for mode, kind, selected_config in fault_cases if mode in modes
                for warnings in (True, False)):
            row = {"mode": mode, "fault_input": kind, "assertion_policy": policy, "warnings": warnings,
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
                    row["receiver_native_response_faults"] = [
                        event for event in (json.loads(line) for line in log.read_text().splitlines())
                        if event["phase"] == "fault"]
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
            if kind == "unknown4030" and not atomic_policy:
                try:
                    # The real document fault and failed result tuple identify this edge;
                    # decoder diagnostic wording is not a protocol status.
                    faults = row["receiver_native_response_faults"]
                    assert len(faults) == 2 and [event["document"] for event in faults] == [1, 2], row
                    assert all(event["mode"] == "malformed" and event["native_executable"] == stock
                               and event["native_doc_bytes"] > 0 and len(event["native_doc_sha256"]) == 64
                               for event in faults), row
                    assert len(row["receiver"]) == 2 and all(
                        not received["valid"] and not received["completed"] and received["error"]
                        and not received["timed_out"] and not received["cancelled"]
                        and not received["failed_to_start"] and not received["high"]
                        and received["markup"] is None and received["c"] is None
                        and received["signature"] is None and received["pcode"] is None
                        for received in row["receiver"]), row
                except Exception:
                    row["failures"].append({"stage": "unknown-tag-cause", "failure": traceback.format_exc()})
            if kind == "empty-extra-function":
                row["ordinary_observation_only"] = True
                row["acceptance_scope"] = "Fault observation/source preservation/recovery only; useful empty-markup C publication is not certified."
                row["conditional_requirement"] = report["atomic_contract"]
            try:
                success = row["export_result"]
                if atomic_policy:
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
                if atomic_policy:
                    assert all(observed["exists"] and observed["sentinel_unchanged"]
                               for observed in row["outputs"].values()), row
                    row["sentinels_unchanged"] = True
                else:
                    assert all(observed["exists"] and not observed["sentinel_unchanged"]
                               for observed in row["outputs"].values()), row
                    row["destination_replaced"] = True
            except Exception:
                row["failures"].append({"stage": "fault-destinations", "failure": traceback.format_exc()})
            if atomic_policy:
                try:
                    assert not row["staging"], row
                    row["staging_removed"] = True
                except Exception:
                    row["failures"].append({"stage": "fault-staging", "failure": traceback.format_exc()})
            if not atomic_policy and kind != "empty-extra-function":
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
