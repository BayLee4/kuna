#!/usr/bin/env python3
"""Actual Ghidra packed-codec/result decoder smoke, not native decompilation evidence."""
import json
import os
from pathlib import Path
import traceback

output = Path(os.environ.get("KUNA_SMOKE_OUT", "java-callable-wire-proof")).resolve()
output.mkdir(parents=True, exist_ok=True)
report = {"passed": False, "scope": "real target Java codec/result decoder/bodyproof publication contract; synthetic frames, no successful native body claims"}
try:
    import pyghidra
    pyghidra.start()
    from jpype import JArray, JByte
    from java.io import ByteArrayInputStream, ByteArrayOutputStream, IOException, StringWriter
    from java.lang import Object
    from ghidra.app.decompiler import DecompileResults, DecompileProcess, CallableSupport
    from ghidra.program.database import ProgramDB
    from ghidra.program.flatapi import FlatProgramAPI
    from ghidra.program.model.lang import LanguageID, CompilerSpecID
    from ghidra.program.model.pcode import PackedEncode, PackedDecode, ElementId, AttributeId, PcodeDataTypeManager
    from ghidra.program.model.symbol import IllegalCharCppTransformer
    from ghidra.program.util import DefaultLanguageService
    from ghidra.util.task import ConsoleTaskMonitor

    # Every allocated element/attribute is decoded as itself, not its old 12-bit alias.
    raw = ByteArrayOutputStream()
    encoder = PackedEncode(raw)
    encoder.openElement(ElementId.ELEM_DOC)
    for tag in range(4030, 4040):
        element = ElementId("probe_" + str(tag), tag)
        encoder.openElement(element)
        for attribute in range(4030, 4049):
            encoder.writeString(AttributeId("probe_" + str(attribute), attribute),
                                f"element={tag};attribute={attribute};nonascii=\u03bb")
        encoder.closeElement(element)
    encoder.closeElement(ElementId.ELEM_DOC)
    decoder = PackedDecode(ByteArrayInputStream(raw.toByteArray()), "actual packed ID roundtrip")
    document = decoder.openElement(ElementId.ELEM_DOC)
    observed = []
    for tag in range(4030, 4040):
        assert decoder.peekElement() == tag
        element = decoder.openElement()
        attributes = []
        for attribute in range(4030, 4049):
            assert decoder.getNextAttributeId() == attribute
            assert str(decoder.readString()) == f"element={tag};attribute={attribute};nonascii=\u03bb"
            attributes.append(attribute)
        assert decoder.getNextAttributeId() == 0
        decoder.closeElement(element)
        observed.append({"element": tag, "attributes": attributes})
    decoder.closeElement(document)
    report["roundtrip"] = observed

    language = DefaultLanguageService.getLanguageService().getLanguage(LanguageID("x86:LE:64:default"))
    owner = Object()
    program = ProgramDB("wire-consumer", language,
                        language.getCompilerSpecByID(CompilerSpecID("gcc")), owner)
    try:
        monitor = ConsoleTaskMonitor()
        api = FlatProgramAPI(program, monitor)
        transaction = program.startTransaction("Real result function")
        try:
            address = program.getAddressFactory().getDefaultAddressSpace().getAddress(0x1000)
            block = api.createMemoryBlock("code", address, JArray(JByte)(bytes.fromhex("c3")), False)
            block.setExecute(True)
            assert api.disassemble(address)
            function = api.createFunction(address, "wire_result")
        finally:
            program.endTransaction(transaction, True)
        manager = PcodeDataTypeManager(program, IllegalCharCppTransformer())
        def result(status, duplicate=False):
            bytes_out = ByteArrayOutputStream()
            encoded = PackedEncode(bytes_out)
            encoded.openElement(ElementId.ELEM_DOC)
            for _ in range(2 if duplicate else 1):
                support = ElementId("callable_support", 4030)
                encoded.openElement(support)
                encoded.writeSignedInteger(AttributeId("kuna_version", 4030), 2)
                encoded.writeString(AttributeId("kuna_status", 4031), status)
                encoded.writeString(AttributeId("kuna_reason", 4032), "wire refusal probe")
                encoded.closeElement(support)
            encoded.closeElement(ElementId.ELEM_DOC)
            decoded = PackedDecode(ByteArrayInputStream(bytes_out.toByteArray()), "result sibling decode")
            return DecompileResults(function, language, program.getCompilerSpec(), manager, "", decoded,
                                    DecompileProcess.DisposeState.NOT_DISPOSED)
        refused = result("refused")
        assert refused.getCallableSupport().isPresent(), str(refused.getErrorMessage())
        assert refused.getCallableSupport().get().getStatus() == CallableSupport.Status.REFUSED
        assert str(refused.getCallableSupport().get().getReason()) == "wire refusal probe"
        assert not refused.decompileCompleted() and refused.getDecompiledFunction() is None
        for malformed in (result("refused", duplicate=True), result("complete")):
            assert malformed.getCallableSupport().isEmpty()
            assert malformed.getDecompiledFunction() is None and not malformed.decompileCompleted()
            assert str(malformed.getErrorMessage())
        report["consumer_refusal"] = str(refused.getCallableSupport().get().getStatus())
        report["decode_failure_clears_support"] = True
        report["consumer_origin"] = str(refused.getClass().getProtectionDomain().getCodeSource().getLocation())
        # Synthetic protocol frames test joins only. They are not native body receipts
        # and never substitute for the actual inherited-role native execution probes.
        space = int(address.getAddressSpace().getUnique())
        caller_key = f"kuna_entry_{space}_4096_callerfamily"
        generic_key = f"kuna_entry_{space}_8192_targetfamily"
        qualified_key = generic_key + "_internal_1_24_8"
        target_declaration = "int target(void);"

        def artifact(key, kind="none", declaration=target_declaration, required=False,
                     deferred=False, provider=None, definition=None):
            return dict(key=key, kind=kind, declaration=declaration, required=required,
                        deferred=deferred, provider=provider, definition=definition)

        def body(entry, declaration, artifacts, current=False):
            return dict(entry=entry, declaration=declaration, artifacts=artifacts,
                        current=current, text=declaration[:-1] + " { return 7; }")

        def frame(bodies, version=2):
            raw = ByteArrayOutputStream()
            encoded = PackedEncode(raw)
            def element(name, number):
                return ElementId(name, number)
            def attribute(name, number):
                return AttributeId(name, number)
            def text(name, number, value):
                tag = element(name, number)
                encoded.openElement(tag)
                encoded.writeString(AttributeId.ATTRIB_CONTENT, value)
                encoded.closeElement(tag)
            encoded.openElement(ElementId.ELEM_DOC)
            support = element("callable_support", 4030)
            encoded.openElement(support)
            encoded.writeSignedInteger(attribute("kuna_version", 4030), version)
            encoded.writeString(attribute("kuna_status", 4031), "complete")
            encoded.writeString(attribute("kuna_reason", 4032), "synthetic protocol join fixture")
            for value in bodies:
                tag = element("callable_body", 4031)
                encoded.openElement(tag)
                encoded.writeSignedInteger(attribute("kuna_space", 4040), space)
                encoded.writeUnsignedInteger(attribute("kuna_address", 4033), value["entry"])
                encoded.writeBool(attribute("kuna_current", 4034), value["current"])
                encoded.writeBool(attribute("kuna_complete", 4035), True)
                text("callable_declaration", 4033, value["declaration"])
                text("callable_bodytext", 4038, value["text"])
                for item in value["artifacts"]:
                    tag_artifact = element("callable_artifact", 4032)
                    encoded.openElement(tag_artifact)
                    encoded.writeString(attribute("kuna_key", 4039), item["key"])
                    encoded.writeString(attribute("kuna_definition_kind", 4038), item["kind"])
                    encoded.writeBool(attribute("kuna_required", 4036), item["required"])
                    encoded.writeBool(attribute("kuna_deferred", 4037), item["deferred"])
                    if item["provider"] is not None:
                        encoded.writeString(attribute("kuna_provider", 4048), item["provider"])
                    text("callable_declaration", 4033, item["declaration"])
                    if item["definition"] is not None:
                        text("callable_definition", 4034, item["definition"])
                    encoded.closeElement(tag_artifact)
                encoded.closeElement(tag)
            encoded.closeElement(support)
            encoded.closeElement(ElementId.ELEM_DOC)
            decoded = PackedDecode(ByteArrayInputStream(raw.toByteArray()), "bodyproof protocol join")
            return DecompileResults(function, language, program.getCompilerSpec(), manager, "", decoded,
                                    DecompileProcess.DisposeState.NOT_DISPOSED)

        def proof_bodies(concrete="existing", role="_internal_1_24_8", provider=generic_key,
                         proof_declaration=target_declaration, deferred=True, cycle=False):
            qualified = generic_key + role
            caller_artifacts = [artifact(qualified, required=True, deferred=deferred)]
            if cycle:
                caller_artifacts.append(artifact(caller_key, "existing", "int caller(void);"))
            target_artifacts = []
            target_decl = target_declaration
            if concrete is not None:
                definition = None
                if concrete == "wrapper":
                    target_decl = "int target_body(void);"
                    definition = "int target(void) { return target_body(); }"
                target_artifacts.append(artifact(generic_key, concrete, definition=definition))
            target_artifacts.append(artifact(qualified, "bodyproof", proof_declaration, provider=provider))
            if cycle:
                target_artifacts.append(artifact(caller_key, declaration="int caller(void);", required=True))
            return [body(4096, "int caller(void);", caller_artifacts, True),
                    body(8192, target_decl, target_artifacts)]

        checks = []
        report["bodyproof_protocol"] = checks
        def check_join(name, bodies, accepted, *, version=2):
            result = frame(bodies, version)
            optional = result.getCallableSupport()
            if optional.isEmpty():
                assert not accepted, str(result.getErrorMessage())
                checks.append({"case": name, "accepted": False, "stage": "decode",
                               "diagnostic": str(result.getErrorMessage())})
                return
            publication = CallableSupport.Publication()
            try:
                publication.add(optional.get())
                try:
                    publication.validate()
                except IOException as error:
                    assert not accepted, str(error)
                    checks.append({"case": name, "accepted": False, "stage": "publication",
                                   "diagnostic": str(error)})
                    return
                assert accepted, "Invalid bodyproof publication accepted: " + name
                declarations = StringWriter()
                definitions = StringWriter()
                publication.writeDeclarations(declarations, True)
                publication.writeBodies(definitions)
                header, source = str(declarations.toString()), str(definitions.toString())
                assert header.count(target_declaration) == 1, header
                assert "_internal_" not in header and "_internal_" not in source
                if name == "wrapper_retained_only_through_proof":
                    assert source.count("int target(void) { return target_body(); }") == 1, source
                checks.append({"case": name, "accepted": True, "stage": "publication"})
            finally:
                publication.close()

        check_join("existing_target_proof", proof_bodies(), True)
        check_join("wrapper_retained_only_through_proof", proof_bodies(concrete="wrapper"), True)
        raw_cycle = proof_bodies(cycle=True, deferred=False)
        raw_cycle[0]["artifacts"][0]["key"] = generic_key
        raw_cycle[1]["artifacts"] = [
            item for item in raw_cycle[1]["artifacts"] if item["kind"] != "bodyproof"
        ]
        check_join("raw_complete_cycle", raw_cycle, True)
        check_join("required_proof_cannot_drop_deferred_assumption",
                   proof_bodies(deferred=False), False)
        for concrete in ("existing", "wrapper"):
            for name, byte, size, accepted in (
                ("last_nonoverflowing_byte", 18446744073709551614, 1, True),
                ("last_byte_overflows", 18446744073709551615, 1, False),
                ("last_two_bytes_overflow", 18446744073709551614, 2, False),
            ):
                check_join(f"{concrete}_{name}",
                           proof_bodies(concrete=concrete, role=f"_internal_1_{byte}_{size}"), accepted)
        check_join("missing_concrete", proof_bodies(concrete=None), False)
        check_join("declaration_only_not_provider", proof_bodies(concrete="none"), False)
        declaration_conflict = proof_bodies(proof_declaration="long target(void);")
        declaration_conflict[0]["artifacts"][0]["declaration"] = "long target(void);"
        check_join("proof_declaration_conflict", declaration_conflict, False)
        check_join("missing_provider_attribute", proof_bodies(provider=None), False)
        check_join("empty_provider_attribute", proof_bodies(provider=""), False)
        check_join("self_reference", proof_bodies(provider=qualified_key), False)
        check_join("deferred_proof_cycle", proof_bodies(deferred=True, cycle=True), False)
        check_join("old_schema", proof_bodies(), False, version=1)
        for suffix in ("_internal_-1_24_8", "_internal_01_24_8", "_internal_1_024_8",
                       "_internal_1_24_0", "_internal_1_24_08", "_internal_1_24_-8",
                       "_internal_1_18446744073709551616_8", "_internal_1_24_8_1"):
            check_join("noncanonical_role" + suffix, proof_bodies(role=suffix), False)
        wrong_family = proof_bodies()
        wrong_family[1]["artifacts"][-1]["provider"] = generic_key + "other"
        wrong_family[1]["artifacts"].append(artifact(generic_key + "other", "existing"))
        check_join("wrong_family", wrong_family, False)
        wrong_owner = proof_bodies()
        other_key = f"kuna_entry_{space}_12288_targetfamily"
        wrong_owner[1]["artifacts"][-1]["provider"] = other_key
        wrong_owner.append(body(12288, target_declaration, [artifact(other_key, "existing")]))
        check_join("wrong_owner", wrong_owner, False)
        chain = proof_bodies()
        second_key = generic_key + "_internal_1_32_8"
        chain[1]["artifacts"].append(artifact(second_key, "bodyproof", provider=qualified_key))
        check_join("proof_chain", chain, False)
        unexpected = proof_bodies()
        unexpected[1]["artifacts"][0]["provider"] = generic_key
        check_join("provider_attribute_on_existing", unexpected, False)
        duplicate = proof_bodies()
        duplicate[1]["artifacts"].append(duplicate[1]["artifacts"][-1].copy())
        check_join("duplicate_owner_proof", duplicate, False)
        extra_definition = proof_bodies()
        extra_definition[1]["artifacts"][-1]["definition"] = "int invented(void) { return 0; }"
        check_join("nonemitting_proof_rejects_definition", extra_definition, False)
        missing_body = proof_bodies()
        missing_body[1]["text"] = ""
        check_join("proof_cannot_replace_actual_body_receipt", missing_body, False)
    finally:
        program.release(owner)
    report["passed"] = True
except BaseException:
    report["failure"] = traceback.format_exc()
    raise
finally:
    (output / "callable_wire.json").write_text(json.dumps(report, indent=2) + "\n")
