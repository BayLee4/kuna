#!/usr/bin/env python3
"""Packed result lifetime and actual private-export public-consumer contracts."""
import base64
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import sys
import time
import xml.etree.ElementTree as ET

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from kuna_vs_stock import KUNA_GHIDRA, selected_core, start_ghidra
from whole_calls import Machine


def acquisition_authority_consumer(output):
    """A complete old native document cannot certify a concurrent public source edit."""
    from concurrent.futures import ThreadPoolExecutor
    from java.io import ByteArrayOutputStream
    from jpype import JArray
    from ghidra.app.decompiler import DecompInterface
    from ghidra.program.flatapi import FlatProgramAPI
    from ghidra.program.model.data import (
        CategoryPath, DataTypeConflictHandler, IntegerDataType, TypedefDataType,
        UnsignedCharDataType,
    )
    from ghidra.program.model.listing import Function, ParameterImpl, ReturnParameterImpl, Variable
    from ghidra.program.model.pcode import ElementId as E, HighFunctionDBUtil, PackedEncode
    from ghidra.program.model.symbol import SourceType
    from ghidra.util.exception import InvalidInputException
    from whole_calls import fixture

    directory = output / "acquisition-authority"
    directory.mkdir(parents=True, exist_ok=True)
    ready, release = directory / "ready", directory / "release"
    ready.unlink(missing_ok=True)
    release.unlink(missing_ok=True)
    image, entries = fixture()
    machine = Machine(image, [entry for entry in entries if entry[0] == "word_target"])
    program = machine.program
    interfaces = []
    executor = ThreadPoolExecutor(max_workers=1)
    try:
        manager = program.getDataTypeManager()
        tx = program.startTransaction("Original word provider and source signature")
        try:
            flags = manager.resolve(TypedefDataType(CategoryPath.ROOT, "Flags",
                UnsignedCharDataType.dataType, manager), DataTypeConflictHandler.DEFAULT_HANDLER)
            function = FlatProgramAPI(program, machine.monitor).createFunction(
                machine.address(0x1060), "word_target")
            function.updateFunction(
                str(program.getCompilerSpec().getDefaultCallingConvention().getName()),
                ReturnParameterImpl(IntegerDataType.dataType, program),
                Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS, False,
                SourceType.USER_DEFINED,
                JArray(Variable)([ParameterImpl("value", flags, program)]))
        finally:
            program.endTransaction(tx, True)
        wire = ByteArrayOutputStream()
        encoder = PackedEncode(wire)
        encoder.openElement(E.ELEM_DOC)
        encoder.closeElement(E.ELEM_DOC)
        payload = bytes(wire.toByteArray())
        midpoint = len(payload) // 2
        config, log = directory / "codec.json", directory / "native.jsonl"
        log.unlink(missing_ok=True)
        config.write_text(json.dumps({
            "doc_open": base64.b64encode(payload[:midpoint]).decode(),
            "doc_close": base64.b64encode(payload[midpoint:]).decode(),
            "invalid_support": "", "hold_ready": str(ready.resolve()),
            "hold_release": str(release.resolve()),
        }))
        launcher = directory / "native.sh"
        command = [sys.executable, str(Path(__file__).with_name(
            "native_response_fault_proxy.py").resolve()), str(Path(KUNA_GHIDRA).resolve()),
            "pass", str(config.resolve()), str(log.resolve())]
        launcher.write_text("#!/bin/sh\nexec " +
                            " ".join(shlex.quote(arg) for arg in command) + "\n")
        launcher.chmod(0o755)
        author = DecompInterface()
        interfaces.append(author)
        assert author.openProgram(program), str(author.getLastMessage())
        before = author.decompileFunction(function, 60, machine.monitor)
        assert before.decompileCompleted() and before.hasCurrentSourceAuthority()
        receiver = DecompInterface()
        interfaces.append(receiver)
        with selected_core(launcher):
            assert receiver.openProgram(program), str(receiver.getLastMessage())
        revision = int(program.getModificationNumber())
        pending = executor.submit(receiver.decompileFunction, function, 60, machine.monitor)
        deadline = time.monotonic() + 30
        while not ready.exists():
            assert not pending.done(), "Native request returned before the delivery barrier"
            assert time.monotonic() < deadline, "Native result never reached the delivery barrier"
            time.sleep(0.01)
        assert not program.isLocked(), "Acquisition unexpectedly locked public source editing"
        tx = program.startTransaction("Public source correction during native result delivery")
        try:
            HighFunctionDBUtil.updateDBVariable(
                before.getHighFunction().getFunctionPrototype().getParam(0),
                "current_value", None, SourceType.USER_DEFINED)
        finally:
            program.endTransaction(tx, True)
        assert int(program.getModificationNumber()) > revision
        release.write_text("Deliver the unchanged complete native document\n")
        held = pending.result(timeout=30)
        assert held.decompileCompleted(), str(held.getErrorMessage())
        assert held.isEnhancedResult() and not held.isExportResult()
        assert not held.hasCurrentSourceAuthority()
        parameter = held.getHighFunction().getFunctionPrototype().getParam(0)
        assert str(parameter.getName()) == "value"
        old_c = str(held.getDecompiledFunction().getC())
        revision = int(program.getModificationNumber())
        try:
            HighFunctionDBUtil.updateDBVariable(
                parameter, "forbidden_stale_overwrite", None, SourceType.USER_DEFINED)
            raise AssertionError("Acquisition-overlapped source change retained public edit authority")
        except InvalidInputException:
            pass
        assert str(function.getParameter(0).getName()) == "current_value"
        assert int(program.getModificationNumber()) == revision
        current = receiver.decompileFunction(function, 60, machine.monitor)
        assert current.decompileCompleted() and current.hasCurrentSourceAuthority()
        assert str(current.getHighFunction().getFunctionPrototype().getParam(0).getName()) == "current_value"
        assert not held.hasCurrentSourceAuthority()
        assert str(held.getDecompiledFunction().getC()) == old_c
        assert held.getHighFunction() is not None and held.getCCodeMarkup() is not None
        events = [json.loads(line) for line in log.read_text().splitlines()]
        documents = [event for event in events if event["phase"] == "document"]
        releases = [event for event in events if event["phase"] == "released_unchanged"]
        assert len(releases) == 1
        assert releases[0]["native_doc_sha256"] == documents[0]["native_doc_sha256"]
        return {"passed": True, "stale_public_edit_refused": True,
                "held_readable": True, "following_current_authority": True,
                "observer": str(log), "held_c": old_c}
    finally:
        release.write_text("Release any pending native document\n")
        executor.shutdown(wait=True)
        for interface in interfaces:
            interface.dispose()
        machine.close()


def export_scope_consumers(output):
    """Keep canonical authoring separate from real prepared working documents."""
    from java.io import ByteArrayOutputStream, File
    from java.util import ArrayList, HashSet, IdentityHashMap
    from jpype import JArray, JByte, JObject
    from ghidra.app.decompiler import ClangVariableToken, DecompInterface, DecompileOptions
    from ghidra.app.util.exporter import CppExporter
    from ghidra.program.flatapi import FlatProgramAPI
    from ghidra.program.model.address import AddressSet
    from ghidra.program.model.data import (
        CategoryPath, DataTypeConflictHandler, Enum as GhidraEnum,
        FunctionDefinitionDataType, IntegerDataType,
        ParameterDefinition, ParameterDefinitionImpl, PointerDataType, SignedCharDataType, StructureDataType,
        TypedefDataType, UnsignedCharDataType, UnsignedIntegerDataType,
    )
    from ghidra.program.model.listing import Function, ParameterImpl, ReturnParameterImpl, Variable
    from ghidra.program.model.pcode import (
        AttributeId as A, ElementId as E, HighFunctionDBUtil, PackedEncode, PcodeOp, VarnodeAST, XmlEncode,
    )
    from ghidra.program.model.symbol import IllegalCharCppTransformer, SourceType
    from ghidra.util.exception import InvalidInputException
    from ghidra.util.task import ConsoleTaskMonitor
    from support import snapshot
    from whole_calls import fixture

    def same(left, right):
        identities = IdentityHashMap()
        identities.put(left, True)
        return bool(identities.containsKey(right))

    image, entries = fixture()
    names = {"choose", "byte_target", "word_target", "invoke", "dispatch"}
    fixture_machine = Machine(image, [entry for entry in entries if entry[0] in names])
    program = fixture_machine.program
    manager = program.getDataTypeManager()
    functions = {}
    interfaces = []
    observations = {"held": [], "mutations": [], "failures": []}
    directory = output / "export-scope"
    directory.mkdir(parents=True, exist_ok=True)
    try:
        convention = str(program.getCompilerSpec().getDefaultCallingConvention().getName())
        tx = program.startTransaction("Original narrow source signatures and callback providers")
        try:
            flags = manager.resolve(TypedefDataType(CategoryPath.ROOT, "Flags",
                UnsignedCharDataType.dataType, manager), DataTypeConflictHandler.DEFAULT_HANDLER)
            definition = FunctionDefinitionDataType("CallbackFunction", manager)
            definition.setCallingConvention(convention)
            definition.setReturnType(IntegerDataType.dataType)
            definition.setArguments(JArray(ParameterDefinition)([
                ParameterDefinitionImpl("value", flags, None)]))
            callback = manager.resolve(TypedefDataType(CategoryPath.ROOT, "Callback",
                PointerDataType(definition, manager), manager), DataTypeConflictHandler.DEFAULT_HANDLER)
            parameters = {
                "choose": [("which", UnsignedIntegerDataType.dataType)],
                "byte_target": [("value", flags)], "word_target": [("value", flags)],
                "invoke": [("value", flags), ("callback", callback)],
                "dispatch": [("value", flags), ("which", UnsignedIntegerDataType.dataType)],
            }
            api = FlatProgramAPI(program, fixture_machine.monitor)
            for name, pc, _, _ in entries:
                if name not in names:
                    continue
                fn = api.createFunction(fixture_machine.address(pc), name)
                assert fn is not None, name
                fn.updateFunction(convention,
                    ReturnParameterImpl(callback if name == "choose" else IntegerDataType.dataType, program),
                    Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS, False, SourceType.USER_DEFINED,
                    JArray(Variable)([ParameterImpl(n, ty, program) for n, ty in parameters[name]]))
                functions[name] = fn
            functions["word_target"].setComment("scope-source-comment")
        finally:
            program.endTransaction(tx, True)

        # These are the original providers, not rewritten or emulated C replacements.
        assert fixture_machine.call(0x1060, 85) == 1
        assert fixture_machine.call(0x1060, 0x10055) == 0
        assert fixture_machine.call(0x10a0, 0x10055, 0) == 1
        assert fixture_machine.call(0x10a0, 0x10055, 1) == 0
        roots = ArrayList()
        for name in sorted(functions):
            roots.add(functions[name])

        def create_scope(selected_roots):
            reserved = HashSet()
            transformer = IllegalCharCppTransformer()
            def reserve(name):
                for spelling in (str(name), str(transformer.simplify(name))):
                    reserved.add(spelling)
                    reserved.add("P" + spelling)
            for symbol in program.getSymbolTable().getAllSymbols(False):
                reserve(symbol.getName())
            types = manager.getAllDataTypes()
            while types.hasNext():
                datatype = types.next()
                reserve(datatype.getName())
                reserve(datatype.getDisplayName())
                if isinstance(datatype, GhidraEnum):
                    for name in datatype.getNames():
                        reserve(name)
            return DecompInterface.createExportScope(program, selected_roots, reserved)

        wire = ByteArrayOutputStream()
        encoder = PackedEncode(wire)
        encoder.openElement(E.ELEM_DOC)
        encoder.closeElement(E.ELEM_DOC)
        empty_doc = bytes(wire.toByteArray())
        midpoint = len(empty_doc) // 2
        bad = ByteArrayOutputStream()
        encoder = PackedEncode(bad)
        unknown = E("callable_support", 4030)
        encoder.openElement(unknown)
        encoder.writeSignedInteger(A("kuna_version", 4030), 999)
        encoder.closeElement(unknown)
        proxy = Path(__file__).with_name("native_response_fault_proxy.py")

        def configured(label, mode="pass", after=0):
            config = directory / (label + "-codec.json")
            config.write_text(json.dumps({
                "doc_open": base64.b64encode(empty_doc[:midpoint]).decode(),
                "doc_close": base64.b64encode(empty_doc[midpoint:]).decode(),
                "invalid_support": base64.b64encode(bytes(bad.toByteArray())).decode(),
                "fault_after_documents": after,
            }))
            log = directory / (label + "-native.jsonl")
            launcher = directory / (label + "-native.sh")
            command = [sys.executable, str(proxy.resolve()), str(Path(KUNA_GHIDRA).resolve()),
                       mode, str(config.resolve()), str(log.resolve())]
            launcher.write_text("#!/bin/sh\nexec " + " ".join(shlex.quote(arg) for arg in command) + "\n")
            launcher.chmod(0o755)
            interface = DecompInterface()
            interfaces.append(interface)
            options = DecompileOptions()
            options.setPLATECommentIncluded(False)
            options.setWARNCommentIncluded(False)
            assert interface.setOptions(options)
            assert interface.toggleSyntaxTree(True)
            assert interface.toggleCCode(True)
            with selected_core(launcher):
                assert interface.openProgram(program), str(interface.getLastMessage())
            return interface, options, log

        def completed(result, export):
            assert result.decompileCompleted(), str(result.getErrorMessage())
            assert result.isExportResult() == export
            assert result.isEnhancedResult()
            high, markup = result.getHighFunction(), result.getCCodeMarkup()
            assert high is not None and markup is not None
            assert result.getDecompiledFunction() is not None
            bindings = []
            nodes = IdentityHashMap()
            identifiers = set()
            def visit(token):
                nodes.put(token, True)
                if token.numChildren() == 0:
                    identifiers.add(str(token))
                if isinstance(token, ClangVariableToken) and token.getVarnode() is not None:
                    varnode = JObject(token.getVarnode(), VarnodeAST)
                    assert same(high.getRef(varnode.getUniqueId()), varnode)
                    bindings.append((str(token.getText()), int(varnode.getSize())))
                for index in range(token.numChildren()):
                    visit(token.Child(index))
            visit(markup)
            assert bindings, "Actual markup must retain its own High varnode bindings"
            binding = result.getExportBinding()
            if export:
                assert binding is not None
                public_prototype = binding.getPublicPrototype()
                assert public_prototype is not None
                assert nodes.containsKey(public_prototype), "Public prototype must be actual received markup"
                declarations = [str(name) for name in binding.getDeclarationNames()]
                assert declarations and all(name in identifiers for name in declarations), declarations
            else:
                assert binding is None
            assert result.hasCurrentExportAuthority() if export else result.hasCurrentSourceAuthority()
            return str(result.getDecompiledFunction().getC()), bindings

        def failed(result):
            assert not result.decompileCompleted()
            assert not result.isValid()
            assert result.getHighFunction() is None
            assert result.getCCodeMarkup() is None
            assert result.getDecompiledFunction() is None
            assert result.getExportBinding() is None
            assert not result.hasCurrentExportAuthority()

        def dispose(interface):
            interface.dispose()
            interfaces.remove(interface)

        canonical, _, _ = configured("canonical")
        ordinary = canonical.decompileFunction(functions["word_target"], 60, fixture_machine.monitor)
        completed(ordinary, False)
        assert ordinary.getHighFunction().getFunctionPrototype().getParam(0).getDataType().isEquivalent(flags)
        tx = program.startTransaction("Public ordinary High authoring remains enabled")
        try:
            HighFunctionDBUtil.updateDBVariable(
                ordinary.getHighFunction().getFunctionPrototype().getParam(0),
                "canonical_value", None, SourceType.USER_DEFINED)
        finally:
            program.endTransaction(tx, True)
        assert str(functions["word_target"].getParameter(0).getName()) == "canonical_value"
        dispose(canonical)
        before, revision = snapshot(functions), int(program.getModificationNumber())
        scope = create_scope(roots)
        working, _, working_log = configured("working")
        working.setExportScope(scope)
        initial = working.decompileFunctionForExport(
            functions["word_target"], 60, fixture_machine.monitor)
        initial_text, initial_bindings = completed(initial, True)
        identities = working.getDataTypeManager()
        temporary = StructureDataType("ScopeTemporary", 4, manager)
        temporary.replaceAtOffset(0, IntegerDataType.dataType, 4, "retained", None)
        assert manager.getID(temporary) <= 0
        encoded = XmlEncode()
        identities.encodeType(encoded, temporary, 4)
        unsigned_id = int(ET.fromstring(str(encoded)).get("id"), 0)
        temporary_id = unsigned_id - (1 << 64) if unsigned_id >= (1 << 63) else unsigned_id
        assert same(identities.findBaseType("ScopeTemporary", temporary_id), temporary)
        held = [(initial, initial_text, initial_bindings)]
        for name in ("word_target", "dispatch", "invoke", "word_target"):
            result = working.decompileFunctionForExport(functions[name], 60, fixture_machine.monitor)
            text, bindings = completed(result, True)
            assert not result.hasCurrentSourceAuthority()
            assert not result.getHighFunction().hasCurrentSourceAuthority()
            assert same(identities.findBaseType("ScopeTemporary", temporary_id), temporary), (
                "Working requests after preparation must preserve the private NONDB namespace")
            parameter = result.getHighFunction().getFunctionPrototype().getParam(0)
            assert parameter.getDataType().getLength() == 4, (name, text)
            assert any(size == 4 for _, size in bindings), bindings
            try:
                HighFunctionDBUtil.updateDBVariable(parameter, "forbidden_private_write",
                                                   None, SourceType.USER_DEFINED)
                raise AssertionError("Working High accepted public source editing")
            except InvalidInputException:
                pass
            assert snapshot(functions) == before and int(program.getModificationNumber()) == revision
            held.append((result, text, bindings))
        next_temporary = StructureDataType("ScopeNextTemporary", 8, manager)
        next_encoded = XmlEncode()
        identities.encodeType(next_encoded, next_temporary, 8)
        assert int(ET.fromstring(str(next_encoded)).get("id"), 0) != unsigned_id
        assert same(identities.findBaseType("ScopeTemporary", temporary_id), temporary)
        working.endExportScope()
        assert identities.findBaseType("ScopeTemporary", temporary_id) is None
        working.resetDecompiler()
        for result, text, bindings in held:
            assert str(result.getDecompiledFunction().getC()) == text
            assert result.getHighFunction() is not None and result.getCCodeMarkup() is not None
            assert result.hasCurrentExportAuthority() and not result.hasCurrentSourceAuthority()
            observations["held"].append({"c": text, "bindings": bindings})
        ordinary = working.decompileFunction(functions["word_target"], 60, fixture_machine.monitor)
        completed(ordinary, False)
        assert ordinary.getHighFunction().getFunctionPrototype().getParam(0).getDataType().isEquivalent(flags)
        assert str(ordinary.getHighFunction().getFunctionPrototype().getParam(0).getName()) == "canonical_value"

        # The same immutable descriptor is usable by fresh pooled receivers with the same config.
        for index in range(2):
            pooled, _, _ = configured("pooled-" + str(index))
            pooled.setExportScope(scope)
            result = pooled.decompileFunctionForExport(functions["word_target"], 60, fixture_machine.monitor)
            text, _ = completed(result, True)
            assert text == held[0][1]
            pooled.endExportScope()
            dispose(pooled)
        assert snapshot(functions) == before and int(program.getModificationNumber()) == revision

        # This authored typedef occupies the same C namespace as a generated function.
        # Keep the real provider and exporter output unchanged: allocation, not rewriting,
        # must avoid the native implementation's first-choice name.
        collision_name = "kuna_impl_word_target"
        tx = program.startTransaction("Authored typedef collides with native implementation candidate")
        try:
            authored_collision = manager.resolve(TypedefDataType(CategoryPath.ROOT, collision_name,
                IntegerDataType.dataType, manager), DataTypeConflictHandler.DEFAULT_HANDLER)
        finally:
            program.endTransaction(tx, True)
        collision_id = int(manager.getID(authored_collision))
        collision_before = snapshot(functions)
        collision_revision = int(program.getModificationNumber())
        collision_roots = ArrayList()
        collision_roots.add(functions["word_target"])
        collision_scope = create_scope(collision_roots)
        collision_interface, collision_options, _ = configured("authored-name-collision")
        collision_interface.setExportScope(collision_scope)
        collision_result = collision_interface.decompileFunctionForExport(
            functions["word_target"], 60, fixture_machine.monitor)
        completed(collision_result, True)
        collision_binding = collision_result.getExportBinding()
        implementation_name = str(collision_binding.getImplementationName())
        assert str(collision_binding.getSourceName()) == "word_target"
        assert collision_binding.isPrivateImplementation()
        assert implementation_name != collision_name
        assert implementation_name.startswith(collision_name + "_"), implementation_name
        collision_interface.endExportScope()
        dispose(collision_interface)

        selected = AddressSet()
        selected.add(functions["word_target"].getBody())
        c_file = directory / "authored-name-collision.c"
        header = c_file.with_suffix(".h")
        cpp_exporter = CppExporter(collision_options, True, True, True, True, False, "")
        assert cpp_exporter.export(File(str(c_file)), program, selected, fixture_machine.monitor)
        assert c_file.is_file() and header.is_file()
        body = c_file.read_text()
        for provider in ("word_target", implementation_name):
            assert re.search(r"\b" + re.escape(provider) + r"\s*\([^;]*\)\s*\{", body), (
                "Actual exporter lost a public/private provider body", provider, body)
        driver = directory / "authored-name-collision-driver.c"
        driver.write_text(
            '#include "authored-name-collision.h"\n'
            'int main(void) {\n'
            '  kuna_impl_word_target authored_value = 17;\n'
            '  if (sizeof(authored_value) != sizeof(int) || authored_value != 17) return 1;\n'
            '  if (word_target((Flags)85) != 1) return 2;\n'
            '  if (word_target((Flags)84) != 0 || word_target((Flags)255) != 0) return 3;\n'
            '  return word_target((Flags)0x10055) != 1;\n'
            '}\n')
        collision_observation = observations["authored_name_collision"] = {
            "source_typedef": collision_name, "source_type_id": collision_id,
            "implementation": implementation_name, "execution": [],
        }
        for optimization in ("-O0", "-O2"):
            binary = directory / ("authored-name-collision" + optimization)
            command = [os.environ.get("CC", "cc"), "-std=c11", "-Wall",
                       "-Werror=implicit-function-declaration", "-Werror=incompatible-pointer-types",
                       optimization, str(c_file), str(driver), "-o", str(binary)]
            built = subprocess.run(command, text=True, capture_output=True, timeout=120)
            receipt = {"command": command, "status": built.returncode,
                       "stdout": built.stdout, "stderr": built.stderr}
            collision_observation["execution"].append(receipt)
            assert built.returncode == 0, receipt
            ran = subprocess.run([str(binary)], text=True, capture_output=True, timeout=30)
            receipt = {"command": [str(binary)], "status": ran.returncode,
                       "stdout": ran.stdout, "stderr": ran.stderr}
            collision_observation["execution"].append(receipt)
            assert ran.returncode == 0, receipt
        assert snapshot(functions) == collision_before
        assert int(program.getModificationNumber()) == collision_revision
        assert int(manager.getID(authored_collision)) == collision_id
        assert str(authored_collision.getName()) == collision_name
        assert same(manager.getDataType(authored_collision.getDataTypePath()), authored_collision)
        collision_observation["passed"] = True

        # Fresh source/type/value consumption after termination must not reuse prepared bodies.
        tx = program.startTransaction("Change real source alias and provider comparison")
        try:
            fresh_source = manager.resolve(TypedefDataType(CategoryPath.ROOT, "FreshScopeWord",
                SignedCharDataType.dataType, manager), DataTypeConflictHandler.DEFAULT_HANDLER)
            functions["word_target"].updateFunction(convention,
                ReturnParameterImpl(IntegerDataType.dataType, program),
                Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS, False, SourceType.USER_DEFINED,
                JArray(Variable)([ParameterImpl("canonical_value", fresh_source, program)]))
            immediate = fixture_machine.address(0x1064)
            program.getListing().clearCodeUnits(fixture_machine.address(0x1062), immediate, False)
            program.getMemory().setByte(immediate, JByte(86))
            assert api.disassemble(fixture_machine.address(0x1062))
        finally:
            program.endTransaction(tx, True)
        assert fixture_machine.call(0x1060, 85) == 0
        assert fixture_machine.call(0x1060, 86) == 1
        refreshed = working.decompileFunction(functions["word_target"], 60, fixture_machine.monitor)
        completed(refreshed, False)
        fresh_parameter = refreshed.getHighFunction().getFunctionPrototype().getParam(0)
        assert fresh_parameter.getDataType().isEquivalent(fresh_source)
        assert manager.getID(fresh_parameter.getDataType()) == manager.getID(fresh_source)
        assert fresh_parameter.getDataType().getLength() == 1
        assert fresh_parameter.getDataType().getDataType().isSigned()
        comparisons = [op for op in refreshed.getHighFunction().getPcodeOps()
                       if op.getOpcode() in (PcodeOp.INT_EQUAL, PcodeOp.INT_NOTEQUAL)]
        assert any(vn.isConstant() and vn.getOffset() == 86
                   for op in comparisons for vn in op.getInputs())
        assert not any(vn.isConstant() and vn.getOffset() == 85
                       for op in comparisons for vn in op.getInputs())
        assert not held[0][0].hasCurrentExportAuthority()
        assert str(held[0][0].getDecompiledFunction().getC()) == held[0][1]
        observations["fresh_source_type_and_provider_value"] = True
        dispose(working)

        organization = manager.getDataOrganization()
        original_sign = organization.isSignedChar()
        for mutation in ("source", "core", "options", "output", "style"):
            for acquisition in ("before", "after"):
                candidate_scope = create_scope(roots)
                interface, options, _ = configured(mutation + "-" + acquisition)
                interface.setExportScope(candidate_scope)
                captured = None
                if acquisition == "after":
                    captured = interface.decompileFunctionForExport(
                        functions["word_target"], 60, fixture_machine.monitor)
                    completed(captured, True)
                if mutation == "source":
                    tx = program.startTransaction("Expire private Program basis")
                    try:
                        functions["word_target"].setComment("changed-" + acquisition)
                    finally:
                        program.endTransaction(tx, True)
                elif mutation == "core":
                    revision_before = int(program.getModificationNumber())
                    organization.setCharIsSigned(not original_sign)
                    assert int(program.getModificationNumber()) == revision_before
                elif mutation == "options":
                    options.setPLATECommentIncluded(True)
                elif mutation == "style":
                    assert interface.setSimplificationStyle("normalize")
                else:
                    assert interface.toggleCCode(False)
                try:
                    if captured is not None:
                        assert not captured.hasCurrentExportAuthority()
                        try:
                            captured.requireCurrentExportAuthority()
                            raise AssertionError("Changed basis retained current export authority")
                        except Exception as error:
                            assert not isinstance(error, AssertionError)
                        assert captured.getHighFunction() is not None
                        assert captured.getDecompiledFunction() is not None
                    revision_before = int(program.getModificationNumber())
                    failed(interface.decompileFunctionForExport(
                        functions["word_target"], 60, fixture_machine.monitor))
                    assert int(program.getModificationNumber()) == revision_before
                    if mutation in ("source", "core"):
                        try:
                            interface.setExportScope(candidate_scope)
                            raise AssertionError("Stale immutable scope was accepted")
                        except Exception as error:
                            assert not isinstance(error, AssertionError)
                    observations["mutations"].append({"kind": mutation, "acquisition": acquisition})
                finally:
                    organization.setCharIsSigned(original_sign)
                    interface.endExportScope()
                    dispose(interface)

        # Cancellation must reject the whole result and terminate this physical scope.
        for failure in ("cancelled", "decode"):
            single_root = ArrayList()
            single_root.add(functions["word_target"])
            fresh_scope = create_scope(single_root)
            interface, _, log = configured(failure, "malformed" if failure == "decode" else "pass",
                                           after=2)
            interface.setExportScope(fresh_scope)
            monitor = ConsoleTaskMonitor()
            retained = interface.decompileFunctionForExport(functions["word_target"], 60, monitor)
            retained_text, _ = completed(retained, True)
            failure_ids = interface.getDataTypeManager()
            marker = XmlEncode()
            failure_ids.encodeType(marker, temporary, 4)
            marker_unsigned = int(ET.fromstring(str(marker)).get("id"), 0)
            marker_id = marker_unsigned - (1 << 64) if marker_unsigned >= (1 << 63) else marker_unsigned
            if failure == "cancelled":
                monitor.setCancelEnabled(True)
                monitor.cancel()
            started = time.monotonic()
            rejected = interface.decompileFunctionForExport(functions["word_target"], 60, monitor)
            if failure == "cancelled":
                assert time.monotonic() - started < 10, "Precancelled acquisition blocked on native work"
            assert failure_ids.findBaseType("ScopeTemporary", marker_id) is None
            failed(rejected)
            if failure == "decode":
                faults = [event for event in map(json.loads, log.read_text().splitlines())
                          if event["phase"] == "fault"]
                assert len(faults) == 1 and faults[0]["mode"] == "malformed"
                assert faults[0]["document"] == 3 and faults[0]["native_doc_bytes"] > 0
                assert not rejected.isTimedOut()
                assert not rejected.isCancelled()
                assert not rejected.failedToStart()
            else:
                assert rejected.isCancelled()
            assert retained.hasCurrentExportAuthority() and not retained.hasCurrentSourceAuthority()
            assert str(retained.getDecompiledFunction().getC()) == retained_text
            assert retained.getHighFunction() is not None and retained.getCCodeMarkup() is not None
            failed(interface.decompileFunctionForExport(
                functions["word_target"], 60, fixture_machine.monitor))
            tx = program.startTransaction("Fresh source after failed physical scope")
            try:
                functions["word_target"].getParameter(0).setName(
                    "fresh_" + failure, SourceType.USER_DEFINED)
            finally:
                program.endTransaction(tx, True)
            # Normal public decompilation must recover canonical source, not stale working High.
            with selected_core(KUNA_GHIDRA):
                interface.resetDecompiler()
                recovered = interface.decompileFunction(
                    functions["word_target"], 60, fixture_machine.monitor)
            completed(recovered, False)
            assert recovered.getHighFunction().getFunctionPrototype().getParam(0).getDataType().isEquivalent(fresh_source)
            assert str(recovered.getHighFunction().getFunctionPrototype().getParam(0).getName()) == "fresh_" + failure
            observations["failures"].append({"kind": failure, "error": str(rejected.getErrorMessage()),
                                              "observer": str(log)})
            dispose(interface)
        observations["raw_declaration_names"] = []
        for raw_name in ("templated<int>", "operator+", "méthode", "clone.part.1"):
            tx = program.startTransaction("Supported raw function-name presentation")
            try:
                functions["word_target"].setName(raw_name, SourceType.USER_DEFINED)
            finally:
                program.endTransaction(tx, True)
            raw_scope = create_scope(roots)
            interface, _, _ = configured("raw-name-" + str(len(observations["raw_declaration_names"])))
            canonical_name = interface.decompileFunction(
                functions["word_target"], 60, fixture_machine.monitor)
            completed(canonical_name, False)
            interface.setExportScope(raw_scope)
            result = interface.decompileFunctionForExport(
                functions["word_target"], 60, fixture_machine.monitor)
            completed(result, True)
            binding = result.getExportBinding()
            assert str(binding.getSourceName()) == raw_name
            assert raw_name in [str(name) for name in binding.getDeclarationNames()]
            assert binding.getPublicPrototype() is not None
            assert str(functions["word_target"].getName()) == raw_name
            observations["raw_declaration_names"].append(raw_name)
            interface.endExportScope()
            dispose(interface)
        observations["native_observer"] = str(working_log)
        observations["passed"] = True
        return observations
    finally:
        for interface in interfaces:
            interface.dispose()
        fixture_machine.close()


def commit_consumers():
    """Public commits of ordinary results match stock, also after sibling commits."""
    from ghidra.app.decompiler import DecompInterface
    from ghidra.program.flatapi import FlatProgramAPI
    from ghidra.program.model.pcode import HighFunctionDBUtil
    from ghidra.program.model.symbol import SourceType
    code = {"load_first": (0x1000, "0fb607c3"), "load_second": (0x1010, "0fb64701c3"),
            "sum_fields": (0x1020, "488b0f31c031d24885c97e0c48034708" "48ffc24839ca75f4" "48034710c3")}
    image = bytearray(0x40)
    for pc, raw in code.values():
        image[pc - 0x1000:pc - 0x1000 + len(raw) // 2] = bytes.fromhex(raw)
    machine = Machine(bytes(image), [(name, pc, None, None) for name, (pc, _) in code.items()])
    program = machine.program
    interface = DecompInterface()
    try:
        tx = program.startTransaction("Ordinary pointer functions")
        try:
            functions = [FlatProgramAPI(program, machine.monitor).createFunction(
                machine.address(pc), name) for name, (pc, _) in code.items()]
        finally:
            program.endTransaction(tx, True)
        assert interface.openProgram(program), str(interface.getLastMessage())
        # The stock batch pattern: every result exists before the first commit advances the Program.
        results = [interface.decompileFunction(function, 60, machine.monitor) for function in functions]
        assert all(result.decompileCompleted() and result.isEnhancedResult() for result in results)
        expected = []
        for result in results:
            high = result.getHighFunction()
            manager = high.getDataTypeManager()
            pointer = high.getFunctionPrototype().getParam(0).getDataType()
            assert manager.isResultLocal(pointer) and not manager.isResultLocal(pointer.getDataType())
            expected.append(str(pointer.getName()))
        for function, result in zip(functions, results):
            tx = program.startTransaction("Commit " + str(function.getName()))
            try:
                HighFunctionDBUtil.commitParamsToDatabase(result.getHighFunction(), True,
                    HighFunctionDBUtil.ReturnCommitOption.COMMIT, SourceType.USER_DEFINED)
            finally:
                program.endTransaction(tx, True)
        assert [str(function.getParameter(0).getDataType().getName()) for function in functions] == expected
    finally:
        interface.dispose()
        machine.close()


def main():
    start_ghidra()
    from java.io import ByteArrayOutputStream
    from java.util import IdentityHashMap
    from jpype import JArray
    from ghidra.app.decompiler import DecompInterface, DecompileResults, DecompileProcess
    from ghidra.app.plugin.core.decompile.actions import RenameStructFieldTask
    from ghidra.program.flatapi import FlatProgramAPI
    from ghidra.program.model.data import (
        DataTypeConflictHandler, FunctionDefinition, IntegerDataType, PointerDataType, StructureDataType,
    )
    from ghidra.program.model.listing import Function, ParameterImpl, ReturnParameterImpl, Variable
    from ghidra.program.model.pcode import (
        AttributeId as A, ElementId as E, HighFunction, HighFunctionDBUtil, PackedDecode, PackedEncode,
        PcodeDataTypeManager, XmlEncode,
    )
    from ghidra.program.model.symbol import IllegalCharCppTransformer, SourceType
    from ghidra.util.exception import InvalidInputException

    def same(left, right):
        identities = IdentityHashMap()
        identities.put(left, True)
        return bool(identities.containsKey(right))

    machine = Machine(bytes.fromhex('8b07c3'), [('read_value', 0x1000, bytes.fromhex('8b07c3'), '')])
    try:
        program = machine.program
        manager = program.getDataTypeManager()
        transaction = program.startTransaction('Result view test function')
        try:
            function = FlatProgramAPI(program, machine.monitor).createFunction(machine.address(0x1000), 'read_value')
            assert function is not None
            managed = StructureDataType('ManagedRecord', 4, manager)
            managed.replaceAtOffset(0, IntegerDataType(manager), 4, 'authored_field', None)
            managed = manager.resolve(managed, DataTypeConflictHandler.DEFAULT_HANDLER)
            function.updateFunction('__stdcall', ReturnParameterImpl(IntegerDataType(manager), program),
                Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS, False, SourceType.USER_DEFINED,
                JArray(Variable)([ParameterImpl('value', PointerDataType(managed, manager), program)]))
        finally:
            program.endTransaction(transaction, True)
        source = PcodeDataTypeManager(program, IllegalCharCppTransformer())
        integer = IntegerDataType(manager)
        high = HighFunction(function, program.getLanguage(), program.getCompilerSpec(), source)
        high.grabFromFunction(0, False, False)
        oversized_pointer_size = int(PointerDataType.MAX_POINTER_SIZE_BYTES) + 1
        reservations = [
            (1, 'Node', 16, 'struct'), (2, 'NodeAlias', 16, 'struct'),
            (3, '', 8, 'ptr'), (4, '', 32, 'array'), (5, 'Callback', 1, 'code'),
            (6, 'Choice', 32, 'union'), (7, 'Color', 4, 'int'),
            (8, 'Bits', 4, 'struct'), (9, '', 8, 'ptr'),
            (10, '', 4, 'partstruct'), (11, '', 1, 'uint'), (12, '', 1, 'code'),
            (13, '', 4, 'ptr'), (14, '', oversized_pointer_size, 'ptr'),
        ]

        def reference(encoder, handle):
            encoder.openElement(E.ELEM_TYPEREF)
            encoder.writeUnsignedInteger(PcodeDataTypeManager.ATTRIB_KUNA_LOCAL, handle)
            encoder.writeString(A.ATTRIB_NAME, '')
            encoder.writeUnsignedInteger(A.ATTRIB_ID, 200 + handle)
            encoder.closeElement(E.ELEM_TYPEREF)

        def type_header(encoder, name, size, meta):
            encoder.openElement(E.ELEM_TYPE)
            encoder.writeString(A.ATTRIB_NAME, name)
            encoder.writeSignedInteger(A.ATTRIB_SIZE, size)
            encoder.writeString(A.ATTRIB_METATYPE, meta)

        def field(encoder, name, offset, handle=None):
            encoder.openElement(E.ELEM_FIELD)
            encoder.writeString(A.ATTRIB_NAME, name)
            encoder.writeSignedInteger(A.ATTRIB_OFFSET, offset)
            if handle is None:
                source.encodeTypeRef(encoder, integer, 4)
            else:
                reference(encoder, handle)
            encoder.closeElement(E.ELEM_FIELD)

        def body(encoder, handle):
            if handle == 1:
                type_header(encoder, 'Node', 16, 'struct')
                field(encoder, 'value', 0)
                field(encoder, 'next', 8, 3)
                encoder.closeElement(E.ELEM_TYPE)
            elif handle == 2:
                encoder.openElement(E.ELEM_DEF)
                encoder.writeString(A.ATTRIB_NAME, 'NodeAlias')
                reference(encoder, 1)
                encoder.closeElement(E.ELEM_DEF)
            elif handle == 3:
                type_header(encoder, '', 8, 'ptr')
                reference(encoder, 2)
                encoder.closeElement(E.ELEM_TYPE)
            elif handle == 4:
                type_header(encoder, '', 32, 'array')
                encoder.writeSignedInteger(A.ATTRIB_ARRAYSIZE, 2)
                reference(encoder, 2)
                encoder.closeElement(E.ELEM_TYPE)
            elif handle == 5:
                type_header(encoder, 'Callback', 1, 'code')
                encoder.openElement(E.ELEM_PROTOTYPE)
                encoder.writeString(A.ATTRIB_MODEL, 'default')
                encoder.writeBool(A.ATTRIB_DOTDOTDOT, True)
                encoder.openElement(E.ELEM_RETURNSYM)
                encoder.openElement(E.ELEM_ADDR)
                encoder.closeElement(E.ELEM_ADDR)
                reference(encoder, 2)
                encoder.closeElement(E.ELEM_RETURNSYM)
                encoder.openElement(E.ELEM_INTERNALLIST)
                for element in (E.ELEM_RETPARAM, E.ELEM_PARAM):
                    encoder.openElement(element)
                    encoder.writeString(A.ATTRIB_NAME, 'value')
                    encoder.openElement(E.ELEM_ADDR)
                    encoder.closeElement(E.ELEM_ADDR)
                    reference(encoder, 2)
                    encoder.closeElement(element)
                encoder.closeElement(E.ELEM_INTERNALLIST)
                encoder.closeElement(E.ELEM_PROTOTYPE)
                encoder.closeElement(E.ELEM_TYPE)
            elif handle == 6:
                type_header(encoder, 'Choice', 32, 'union')
                field(encoder, 'node', 0, 2)
                field(encoder, 'nodes', 0, 4)
                encoder.closeElement(E.ELEM_TYPE)
            elif handle == 7:
                type_header(encoder, 'Color', 4, 'enum_int')
                for name, value in [('negative', -1), ('positive', 2)]:
                    encoder.openElement(E.ELEM_VAL)
                    encoder.writeString(A.ATTRIB_NAME, name)
                    encoder.writeSignedInteger(A.ATTRIB_VALUE, value)
                    encoder.closeElement(E.ELEM_VAL)
                encoder.closeElement(E.ELEM_TYPE)
            elif handle == 8:
                type_header(encoder, 'Bits', 4, 'struct')
                encoder.openElement(E.ELEM_BITFIELD)
                encoder.writeString(A.ATTRIB_NAME, 'middle')
                encoder.writeSignedInteger(A.ATTRIB_OFFSET, 0)
                encoder.writeSignedInteger(A.ATTRIB_FIRST, 3)
                encoder.writeSignedInteger(A.ATTRIB_SIZE, 8)
                source.encodeTypeRef(encoder, integer, 4)
                encoder.closeElement(E.ELEM_BITFIELD)
                encoder.closeElement(E.ELEM_TYPE)
            elif handle == 9:
                encoder.openElement(PcodeDataTypeManager.ELEM_QUALIFIED)
                encoder.writeUnsignedInteger(A.ATTRIB_VALUE, 4)
                reference(encoder, 3)
                encoder.closeElement(PcodeDataTypeManager.ELEM_QUALIFIED)
            elif handle in (10, 11):
                type_header(encoder, '', 4 if handle == 10 else 1,
                            'partstruct' if handle == 10 else 'partenum')
                encoder.writeSignedInteger(A.ATTRIB_OFFSET, 4 if handle == 10 else 1)
                reference(encoder, 1 if handle == 10 else 7)
                encoder.closeElement(E.ELEM_TYPE)
            elif handle in (13, 14):
                type_header(encoder, '', 4 if handle == 13 else oversized_pointer_size, 'ptr')
                source.encodeTypeRef(encoder, managed, 4)
                encoder.closeElement(E.ELEM_TYPE)
            else:
                type_header(encoder, '', 1, 'code')
                encoder.closeElement(E.ELEM_TYPE)

        def prelude(encoder, populated):
            encoder.openElement(PcodeDataTypeManager.ELEM_KUNA_RESULT)
            encoder.writeUnsignedInteger(PcodeDataTypeManager.ATTRIB_KUNA_RESULT_VERSION, 1)
            if populated:
                for handle, name, size, meta in reservations:
                    encoder.openElement(PcodeDataTypeManager.ELEM_KUNA_TYPE)
                    encoder.writeUnsignedInteger(PcodeDataTypeManager.ATTRIB_KUNA_LOCAL, handle)
                    encoder.writeString(A.ATTRIB_NAME, name)
                    encoder.writeUnsignedInteger(A.ATTRIB_ID, 200 + handle)
                    encoder.writeSignedInteger(A.ATTRIB_SIZE, size)
                    encoder.writeString(A.ATTRIB_METATYPE, meta)
                    encoder.closeElement(PcodeDataTypeManager.ELEM_KUNA_TYPE)
                for handle, _, _, _ in reservations:
                    encoder.openElement(PcodeDataTypeManager.ELEM_KUNA_DEFINITION)
                    encoder.writeUnsignedInteger(PcodeDataTypeManager.ATTRIB_KUNA_LOCAL, handle)
                    body(encoder, handle)
                    encoder.closeElement(PcodeDataTypeManager.ELEM_KUNA_DEFINITION)
            encoder.closeElement(PcodeDataTypeManager.ELEM_KUNA_RESULT)

        temporary = StructureDataType('Temporary', 4, manager)
        temporary.replaceAtOffset(0, integer, 4, 'first', None)
        encoded = XmlEncode()
        source.encodeType(encoded, temporary, 4)
        unsigned_id = int(ET.fromstring(str(encoded)).get('id'), 0)
        temporary_id = unsigned_id - (1 << 64) if unsigned_id >= (1 << 63) else unsigned_id

        def document(admission):
            stream = ByteArrayOutputStream()
            encoder = PackedEncode(stream)
            encoder.openElement(E.ELEM_DOC)
            if admission is not None:
                prelude(encoder, admission)
            high.encode(encoder, high.getID(), function.getParentNamespace(), function.getEntryPoint(), 0)
            encoder.openElement(E.ELEM_FUNCTION)
            # A host temporary referenced ONLY by C markup must still be retained.
            encoder.openElement(E.ELEM_TYPE)
            encoder.writeUnsignedInteger(A.ATTRIB_ID, temporary_id)
            encoder.writeString(A.ATTRIB_CONTENT, 'Temporary')
            encoder.closeElement(E.ELEM_TYPE)
            if admission:
                encoder.openElement(E.ELEM_FIELD)
                encoder.writeUnsignedInteger(PcodeDataTypeManager.ATTRIB_KUNA_LOCAL, 1)
                encoder.writeString(A.ATTRIB_NAME, 'Node')
                encoder.writeSignedInteger(A.ATTRIB_OFF, 8)
                encoder.writeString(A.ATTRIB_CONTENT, 'next')
                encoder.closeElement(E.ELEM_FIELD)
                encoder.openElement(E.ELEM_FIELD)
                encoder.writeUnsignedInteger(A.ATTRIB_ID, manager.getID(managed))
                encoder.writeString(A.ATTRIB_NAME, 'ManagedRecord')
                encoder.writeSignedInteger(A.ATTRIB_OFF, 0)
                encoder.writeString(A.ATTRIB_CONTENT, 'authored_field')
                encoder.closeElement(E.ELEM_FIELD)
            encoder.closeElement(E.ELEM_FUNCTION)
            encoder.closeElement(E.ELEM_DOC)
            payload = stream.toByteArray()
            decoder = PackedDecode(program.getAddressFactory())
            decoder.open(len(payload), 'result-view-semantic-test')
            decoder.ingestBytes(payload, 0, len(payload))
            decoder.endIngest()
            return DecompileResults(function, program.getLanguage(), program.getCompilerSpec(), source,
                                    '', decoder, DecompileProcess.DisposeState.NOT_DISPOSED)

        result, empty, ordinary = document(True), document(False), document(None)
        for value in (result, empty, ordinary):
            assert value.decompileCompleted(), str(value.getErrorMessage())
            assert same(value.getDataTypeManager().getProgram(), program)
            assert same(value.getCCodeMarkup().Child(0).getDataType(), temporary)
        assert result.isEnhancedResult() and empty.isEnhancedResult()
        assert len(empty.getResultDataTypes()) == 0
        assert not ordinary.isEnhancedResult() and len(ordinary.getResultDataTypes()) == 0
        view = result.getDataTypeManager()
        local = lambda handle: view.findResultType('', 200 + handle, handle)
        node, alias, pointer, array, callback = [local(i) for i in range(1, 6)]
        assert len(result.getResultDataTypes()) == len(reservations)
        assert same(node.getComponentAt(8).getDataType(), pointer)
        assert same(pointer.getDataType(), alias) and same(alias.getDataType(), node)
        assert pointer.hasLanguageDependantLength()
        assert pointer.isEquivalent(PointerDataType(alias, manager))
        narrow_pointer, oversized_pointer = local(13), local(14)
        assert same(narrow_pointer.getDataType(), managed)
        assert same(oversized_pointer.getDataType(), managed)
        assert narrow_pointer.getLength() == 4 and not narrow_pointer.hasLanguageDependantLength()
        assert narrow_pointer.isEquivalent(PointerDataType(managed, 4, manager))
        assert oversized_pointer.getLength() == manager.getDataOrganization().getPointerSize()
        assert oversized_pointer.hasLanguageDependantLength()
        assert oversized_pointer.isEquivalent(PointerDataType(managed, manager))
        assert same(array.getDataType(), alias) and array.getNumElements() == 2
        assert same(callback.getReturnType(), alias)
        assert len(callback.getArguments()) == 1 and same(callback.getArguments()[0].getDataType(), alias)
        assert callback.hasVarArgs()
        assert local(6).getLength() == 32 and local(7).getValue('negative') == -1
        bitfield = next(component for component in local(8).getDefinedComponents() if component.isBitFieldComponent())
        assert bitfield.getDataType().getBitOffset() == 3 and bitfield.getDataType().getBitSize() == 8
        assert local(9).getQualifiers() == 4 and same(local(9).getDataType(), pointer)
        for handle, parent, offset, size in [(10, node, 4, 4), (11, local(7), 1, 1)]:
            partial = local(handle)
            assert same(partial.getParentDataType(), parent)
            assert partial.getOffset() == offset and partial.getLength() == size
            assert partial.getStrippedDataType().getLength() == size
        assert local(12).getLength() == 1 and not isinstance(local(12), FunctionDefinition)
        token = result.getCCodeMarkup().Child(1)
        assert token.getOffset() == 8 and same(token.getDataType(), node)
        revision = program.getModificationNumber()
        local_rename = RenameStructFieldTask(None, program, None, token, node, token.getOffset())
        assert local_rename.isValid('renamed_local')
        try:
            local_rename.commit()
            raise AssertionError('Public field task implicitly authored a result-local type')
        except InvalidInputException:
            pass
        assert str(node.getComponentAt(8).getFieldName()) == 'next'
        assert program.getModificationNumber() == revision and manager.getID(node) <= 0
        assert same(result.getCCodeMarkup().Child(2).getDataType(), managed)
        assert all(view.isResultLocal(datatype) for datatype in result.getResultDataTypes())
        assert not view.isResultLocal(integer) and not view.isResultLocal(temporary)
        assert any(same(datatype, temporary) for datatype in view.getRetainedSourceDataTypes())
        assert all(not view.isResultLocal(datatype) for datatype in view.getRetainedSourceDataTypes())
        source.clearTemporaryIds()
        replacement = StructureDataType('Temporary', 8, manager)
        source.encodeType(XmlEncode(), replacement, 8)
        assert same(source.findBaseType('Temporary', temporary_id), replacement)
        assert same(view.findBaseType('Temporary', temporary_id), temporary)
        reverse = XmlEncode()
        view.encodeTypeRef(reverse, temporary, 4)
        assert int(ET.fromstring(str(reverse)).get('id'), 0) == unsigned_id
        source.clearTemporaryIds()
        assert same(view.findBaseType('Temporary', temporary_id), temporary)
        independent = StructureDataType('Independent', 4, manager)
        independent_wire = XmlEncode()
        view.encodeType(independent_wire, independent, 4)
        independent_unsigned_id = int(ET.fromstring(str(independent_wire)).get('id'), 0)
        independent_id = independent_unsigned_id - (1 << 64) if independent_unsigned_id >= (1 << 63) else independent_unsigned_id
        assert independent_unsigned_id != unsigned_id
        assert same(view.findBaseType('Independent', independent_id), independent)
        assert source.findBaseType('Independent', independent_id) is None
        assert not any(same(datatype, independent) for datatype in view.getRetainedSourceDataTypes())
        local_wire = XmlEncode()
        view.encodeTypeRef(local_wire, pointer, 8)
        local_element = ET.fromstring(str(local_wire))
        assert int(local_element.get('id'), 0) == 203 and int(local_element.get('kuna_local'), 0) == 3
        assert result.hasCurrentSourceAuthority()
        transaction = program.startTransaction('Expire enhanced source edit authority')
        try:
            function.setComment('Changed after result capture')
        finally:
            program.endTransaction(transaction, True)
        assert not result.hasCurrentSourceAuthority() and ordinary.hasCurrentSourceAuthority()
        try:
            result.requireCurrentSourceAuthority()
            raise AssertionError('Stale enhanced authority was accepted')
        except Exception as error:
            assert 'stale' in str(error).lower()
        stale_symbol = result.getHighFunction().getFunctionPrototype().getParam(0)
        assert stale_symbol is not None
        revision = program.getModificationNumber()
        try:
            HighFunctionDBUtil.updateDBVariable(stale_symbol, 'renamed_value', None, SourceType.USER_DEFINED)
            raise AssertionError('Public High edit accepted stale result authority')
        except InvalidInputException:
            pass
        assert str(function.getParameter(0).getName()) == 'value'
        assert program.getModificationNumber() == revision
        assert same(view.findBaseType('Temporary', temporary_id), temporary)
        assert result.getHighFunction() is not None and result.getCCodeMarkup() is not None
        source.encodeType(XmlEncode(), temporary, 4)
        managed_result = document(True)
        assert managed_result.decompileCompleted(), str(managed_result.getErrorMessage())
        managed_token = managed_result.getCCodeMarkup().Child(2)
        assert same(managed_token.getDataType(), managed)
        managed_rename = RenameStructFieldTask(None, program, None, managed_token, managed, 0)
        assert managed_rename.isValid('renamed_source')
        transaction = program.startTransaction('Public managed source field rename')
        try:
            managed_rename.commit()
        finally:
            program.endTransaction(transaction, True)
        assert str(managed.getComponentAt(0).getFieldName()) == 'renamed_source'
        organization = manager.getDataOrganization()
        original_sign = organization.isSignedChar()
        with selected_core(KUNA_GHIDRA):
            interface = DecompInterface()
            try:
                assert interface.openProgram(program), str(interface.getLastMessage())
                registered = interface.decompileFunction(function, 60, machine.monitor)
                assert registered.decompileCompleted(), str(registered.getErrorMessage())
                assert registered.isEnhancedResult() and registered.hasCurrentSourceAuthority()
                registered_code = str(registered.getDecompiledFunction().getC())
                revision = program.getModificationNumber()
                organization.setCharIsSigned(not original_sign)
                assert program.getModificationNumber() == revision
                assert not registered.hasCurrentSourceAuthority()
                try:
                    registered.requireCurrentSourceAuthority()
                    raise AssertionError('Changed registration basis retained edit authority')
                except Exception as error:
                    assert 'stale' in str(error).lower()
                registered_symbol = registered.getHighFunction().getFunctionPrototype().getParam(0)
                assert registered_symbol is not None
                try:
                    HighFunctionDBUtil.updateDBVariable(registered_symbol, 'context_stale_value',
                                                       None, SourceType.USER_DEFINED)
                    raise AssertionError('Public High edit accepted changed registration basis')
                except InvalidInputException:
                    pass
                assert program.getModificationNumber() == revision
                assert str(function.getParameter(0).getName()) == 'value'
                assert str(registered.getDecompiledFunction().getC()) == registered_code
                assert registered.getHighFunction() is not None
                interface.flushCache()
                current = interface.decompileFunction(function, 60, machine.monitor)
                assert current.decompileCompleted(), str(current.getErrorMessage())
                assert current.isEnhancedResult() and current.hasCurrentSourceAuthority()
                assert not registered.hasCurrentSourceAuthority()
            finally:
                organization.setCharIsSigned(original_sign)
                interface.dispose()
        output = Path(os.environ.get('KUNA_SMOKE_OUT', 'java-result-view-proof'))
        output.mkdir(parents=True, exist_ok=True)
        with selected_core(KUNA_GHIDRA):
            acquisition = acquisition_authority_consumer(output)
            scoped = export_scope_consumers(output)
            commit_consumers()
        (output / 'result_view.json').write_text(json.dumps({'passed': True, 'local_types': len(reservations),
            'markup_only_temporary_retained': True, 'explicit_empty_acknowledgment': True,
            'ordinary_authority_unchanged': True, 'stale_enhanced_edit_refused': True,
            'public_local_field_edit_refused': True, 'public_stale_high_edit_refused': True,
            'public_managed_field_edit_succeeded': True,
            'acquisition_authority': acquisition,
            'zero_event_registration_change_refused': True, 'export_scope': scoped}, indent=2) + '\n')
    finally:
        machine.close()


if __name__ == '__main__':
    main()
