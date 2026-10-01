#!/usr/bin/env python3
"""Real target-Java identity epochs and source-edit invalidation."""
import json
import os
from pathlib import Path
import traceback

out = Path(os.environ.get("KUNA_SMOKE_OUT", "java-source-identity-proof")).resolve()
out.mkdir(parents=True, exist_ok=True)
report = {"passed": False}
try:
    import pyghidra
    pyghidra.start()
    from java.lang import Object
    from java.io import ByteArrayInputStream, ByteArrayOutputStream
    from ghidra.program.database import ProgramDB
    from ghidra.program.model.data import (
        StructureDataType, IntegerDataType, CharDataType, StringDataType, DataTypeConflictHandler
    )
    from ghidra.program.model.lang import LanguageID, CompilerSpecID
    from ghidra.program.model.pcode import PcodeDataTypeManager, PackedEncode, PackedDecode, AttributeId
    from ghidra.program.model.symbol import IllegalCharCppTransformer
    from ghidra.program.util import DefaultLanguageService
    language = DefaultLanguageService.getLanguageService().getLanguage(LanguageID("x86:LE:64:default"))
    owner = Object()
    program = ProgramDB("source-identity-epochs", language,
                        language.getCompilerSpecByID(CompilerSpecID("gcc")), owner)
    try:
        tx = program.startTransaction("Resolve authentic source root")
        try:
            root = program.getDataTypeManager().resolve(StructureDataType("Persisted", 4),
                                                       DataTypeConflictHandler.DEFAULT_HANDLER)
        finally:
            program.endTransaction(tx, True)
        manager = PcodeDataTypeManager(program, IllegalCharCppTransformer())
        revision = int(program.getModificationNumber())
        persisted = manager.getSourceIdentity(root)
        builtin = manager.getSourceIdentity(IntegerDataType.dataType)
        first = manager.getSourceIdentity(StructureDataType("A", 4))
        manager.clearTemporaryIds()
        second = manager.getSourceIdentity(StructureDataType("B", 4))
        assert int(program.getModificationNumber()) == revision
        assert first.program() == second.program() and first.revision() == second.revision()
        assert first.id() != second.id() and first.size() == second.size()
        assert str(first.kind()) == str(second.kind()) == "transient"
        assert str(first.scope()) != str(second.scope()) and not first.equals(second)
        assert persisted.equals(manager.getSourceIdentity(root))
        assert builtin.equals(manager.getSourceIdentity(IntegerDataType.dataType))
        assert str(persisted.kind()) == "program" and str(builtin.kind()) == "builtin"
        assert str(persisted.scope()) == str(builtin.scope()) == ""
        tx = program.startTransaction("Unrelated Program revision")
        try:
            program.setName("source-identity-renamed")
        finally:
            program.endTransaction(tx, True)
        after_edit = manager.getSourceIdentity(IntegerDataType.dataType)
        assert after_edit.revision() != builtin.revision()
        assert after_edit.program() == builtin.program() and after_edit.id() == builtin.id()
        assert after_edit.size() == builtin.size() and str(after_edit.binding()) == str(builtin.binding())
        assert not persisted.equals(manager.getSourceIdentity(root))
        char_before = manager.getSourceIdentity(CharDataType.dataType)
        organization = program.getDataTypeManager().getDataOrganization()
        signed = bool(organization.isSignedChar())
        try:
            organization.setCharIsSigned(not signed)
            char_changed = manager.getSourceIdentity(CharDataType.dataType)
            assert char_before.id() == char_changed.id() and char_before.size() == char_changed.size()
            assert str(char_before.binding()) != str(char_changed.binding())
        finally:
            organization.setCharIsSigned(signed)
        sized4 = manager.getSourceIdentity(StringDataType.dataType, 4)
        sized8 = manager.getSourceIdentity(StringDataType.dataType, 8)
        assert sized4.id() == sized8.id() and sized4.size() == 4 and sized8.size() == 8
        assert str(sized4.binding()) != str(sized8.binding())
        wire = ByteArrayOutputStream()
        manager.encodeCoreTypes(PackedEncode(wire))
        decoder = PackedDecode(ByteArrayInputStream(wire.toByteArray()), "real core producer")
        core_element = decoder.openElement()
        core_sources = {}
        while decoder.peekElement() != 0:
            element = decoder.openElement()
            identity = int(decoder.readUnsignedInteger(AttributeId.ATTRIB_ID)) & ((1 << 64) - 1)
            markers = []
            decoder.rewindAttributes()
            while True:
                attribute = int(decoder.getNextAttributeId())
                if attribute == 0:
                    break
                if attribute in (4041, 4042, 4044, 4045, 4046, 4047):
                    markers.append(attribute)
            core_sources[identity] = markers
            decoder.closeElementSkipping(element)
        decoder.closeElement(core_element)
        assert core_sources[0xE000000000000001] == [], core_sources
        assert core_sources[int(builtin.id()) & ((1 << 64) - 1)] == [4041, 4042, 4044, 4045, 4046, 4047]
        report.update(passed=True, revision=revision, transient_first=str(first),
                      transient_second=str(second), persisted=str(persisted), builtin=str(builtin),
                      builtin_after_edit=str(after_edit), changed_char=str(char_changed),
                      contextual4=str(sized4), contextual8=str(sized8), core_source_markers=core_sources,
                      producer_origin=str(manager.getClass().getProtectionDomain().getCodeSource().getLocation()))
    finally:
        program.release(owner)
except BaseException:
    report["failure"] = traceback.format_exc()
    raise
finally:
    (out / "source_identity.json").write_text(json.dumps(report, indent=2) + "\n")
