#!/usr/bin/env python3
"""Source-owned same-spelled records, field bindings and source-edit lifetime."""
import json
import os
from pathlib import Path
import sys
import traceback

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from kuna_vs_stock import KUNA_GHIDRA, selected_core, start_ghidra, test_cores


def contextual_source_cases(output):
    import shlex
    import struct
    import subprocess
    import xml.etree.ElementTree as ET
    from jpype import JArray
    from java.io import ByteArrayOutputStream
    from java.lang import System
    from ghidra.app.decompiler import DecompInterface
    from ghidra.program.flatapi import FlatProgramAPI
    from ghidra.program.model.data import CharDataType, StringDataType, IntegerDataType, PointerDataType
    from ghidra.program.model.listing import Function, ParameterImpl, ReturnParameterImpl, Variable
    from ghidra.program.model.pcode import PcodeDataTypeManager, XmlEncode, PackedEncode, PackedDecode, PcodeOp
    from ghidra.program.model.symbol import IllegalCharCppTransformer, SourceType
    from integer_boundaries import ALIASES
    from whole_calls import Machine

    output.mkdir(parents=True, exist_ok=True)
    entries = [('read_char', 0x1000, bytes.fromhex('0fbe07c3'), '')]
    image = bytearray(0x2020)
    for pc, address, size in [(0x1100, 0x3000, 4), (0x1200, 0x3010, 8)]:
        entries.append(('read_string' + str(size), pc,
                        bytes.fromhex('0fb605') + struct.pack('<i', address + size - 1 - (pc + 7)) + b'\xc3', ''))
    for _, pc, code, _ in entries:
        image[pc - 0x1000:pc - 0x1000 + len(code)] = code
    image[0x2000:0x2004], image[0x2010:0x2018] = b'abcd', b'abcdefgh'
    (output / 'primitive-aliases.h').write_text(ALIASES)
    rows, failures = [], []

    def attempt(label, action):
        try:
            action()
        except BaseException:
            failures.append({'stage': label, 'failure': traceback.format_exc()})

    machine = Machine(image, entries)
    program = machine.program
    manager = program.getDataTypeManager()
    organization = manager.getDataOrganization()
    original_sign = bool(organization.isSignedChar())
    functions = {}

    def snapshot():
        return (bool(organization.isSignedChar()), [(name, str(fn.getSignature()), str(fn.getReturn().getVariableStorage()),
                 [(str(p.getName()), int(manager.getID(p.getDataType())), str(p.getVariableStorage()))
                  for p in fn.getParameters()]) for name, fn in functions.items()])

    try:
        api = FlatProgramAPI(program, machine.monitor)
        tx = program.startTransaction('Original contextual char and String clauses')
        try:
            char_type, string_type = CharDataType(manager), StringDataType(manager)
            for name, pc, _, _ in entries:
                fn = api.createFunction(machine.address(pc), name)
                assert fn is not None
                parameters = ([ParameterImpl('value', PointerDataType(char_type, manager), program)]
                              if name == 'read_char' else [])
                fn.updateFunction('__stdcall', ReturnParameterImpl(IntegerDataType.dataType, program),
                                  Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS, False,
                                  SourceType.USER_DEFINED, JArray(Variable)(parameters))
                functions[name] = fn
            char_type = functions['read_char'].getParameter(0).getDataType().getDataType()
            program.getMemory().getBlock(machine.address(0x3000)).setWrite(True)
            for address, size in [(0x3000, 4), (0x3010, 8)]:
                program.getListing().createData(machine.address(address), string_type, size)
                api.createLabel(machine.address(address), 'context_string' + str(size), True)
        finally:
            program.endTransaction(tx, True)
        source_objects = [int(System.identityHashCode(ty)) for ty in (char_type, string_type)]
        retained = PcodeDataTypeManager(program, IllegalCharCppTransformer())
        for epoch, signed in [('initial', original_sign), ('edited', not original_sign), ('restored', original_sign)]:
            organization.setCharIsSigned(signed)
            assert source_objects == [int(System.identityHashCode(ty)) for ty in (char_type, string_type)]
            assert bool(char_type.isSigned()) == signed
            for boundary, producer in [('retained', retained), ('fresh', PcodeDataTypeManager(program, IllegalCharCppTransformer()))]:
                for ty, size in [(char_type, 1), (string_type, 4), (string_type, 8)]:
                    def packet():
                        xml, packed = XmlEncode(), ByteArrayOutputStream()
                        producer.encodeType(xml, ty, size)
                        producer.encodeType(PackedEncode(packed), ty, size)
                        payload = packed.toByteArray()
                        decoder = PackedDecode(program.getAddressFactory())
                        decoder.open(len(payload), epoch + boundary)
                        decoder.ingestBytes(payload, 0, len(payload))
                        decoder.endIngest()
                        decoded = producer.decodeDataType(decoder)
                        element = ET.fromstring(str(xml))
                        rows.append({'packet': epoch + '-' + boundary, 'size': size, 'xml': str(xml),
                                     'source_id': int(manager.getID(ty)), 'source_object': int(System.identityHashCode(ty)),
                                     'decoded_length': int(decoded.getLength())})
                        if size == 1:
                            assert element.get('metatype') == ('int' if signed else 'uint')
                            assert bool(decoded.isSigned()) == signed
                        else:
                            assert element.get('metatype') == 'array'
                            assert int(element.get('size')) == int(element.get('arraysize')) == size
                            assert int(decoded.getLength()) == int(decoded.getNumElements()) == size
                    attempt(epoch + '-' + boundary + '-packet-' + str(size), packet)

        def acquire(interface, core, epoch):
            before, revision = snapshot(), int(program.getModificationNumber())
            try:
                for name, fn in functions.items():
                    def consume():
                        result = interface.decompileFunction(fn, 60, machine.monitor)
                        row = {'core': core, 'epoch': epoch, 'function': name,
                               'completed': bool(result.decompileCompleted()), 'error': str(result.getErrorMessage())}
                        rows.append(row)
                        if (name == 'read_char' and epoch in ('edited-flush', 'edited-reset')
                                and not result.decompileCompleted()
                                and "Trying to alter definition of type: char" in row['error']):
                            row['classification'] = 'known core-type redefinition refused; fail-closed, not refresh success'
                        assert result.decompileCompleted(), row
                        code = str(result.getDecompiledFunction().getC())
                        source = output / (core + '-' + epoch + '-' + name + '.c')
                        source.write_text(code)
                        if name != 'read_char':
                            high = result.getHighFunction()
                            assert high is not None and result.getCCodeMarkup() is not None
                            size, address = (4, 0x3000) if name.endswith('4') else (8, 0x3010)
                            source_data = program.getListing().getDefinedDataAt(machine.address(address))
                            symbols = [s for s in high.getGlobalSymbolMap().getSymbols()
                                       if str(s.getName()) == 'context_string' + str(size)]
                            assert len(symbols) == 1
                            symbol = symbols[0]
                            row['instance_size'] = int(symbol.getSize())
                            row['storage_size'] = int(symbol.getStorage().size())
                            row['source_length'] = int(source_data.getLength())
                            row['source_id'] = int(manager.getID(source_data.getDataType()))
                            assert row['instance_size'] == row['storage_size'] == row['source_length'] == size
                            assert int(manager.getID(symbol.getDataType())) == row['source_id'] == int(manager.getID(string_type))
                            assert [(str(v.getAddress().getAddressSpace().getName()), int(v.getAddress().getOffset()), int(v.getSize()))
                                    for v in symbol.getStorage().getVarnodes()] == [('ram', address, size)]
                            pending = [op.getInput(i) for op in high.getPcodeOps()
                                       if op.getOpcode() == PcodeOp.RETURN for i in range(1, op.getNumInputs())]
                            seen, returned_ram = set(), set()
                            while pending:
                                value = pending.pop()
                                identity = int(System.identityHashCode(value))
                                if identity in seen:
                                    continue
                                seen.add(identity)
                                location = value.getAddress()
                                if str(location.getAddressSpace().getName()) == 'ram' and value.getSize() == 1:
                                    returned_ram.add(int(location.getOffset()))
                                definition = value.getDef()
                                if definition is not None:
                                    pending.extend(definition.getInput(i) for i in range(definition.getNumInputs()))
                            row['returned_byte_ram_uses'] = sorted(returned_ram)
                            assert address + size - 1 in returned_ram, row
                            return
                        def source_high():
                            high = result.getHighFunction()
                            assert high is not None and result.getCCodeMarkup() is not None
                            prototype = high.getFunctionPrototype()
                            assert prototype.getNumParams() == 1
                            pointed = prototype.getParam(0).getDataType().getDataType()
                            assert bool(pointed.isSigned()) == bool(char_type.isSigned())
                        attempt(core + '-' + epoch + '-char-high', source_high)
                        driver = output / (core + '-' + epoch + '-driver.c')
                        driver.write_text('#include <string.h>\n' + str(result.getDecompiledFunction().getSignature()).rstrip('; \n') + ';\n'
                            'int main(void){for(unsigned i=0;i<256;++i){unsigned char bits=(unsigned char)i;'
                            'char value;memcpy(&value,&bits,1);int expected=i<128?(int)i:(int)i-256;'
                            'if(read_char(&value)!=expected)return 1;}return 0;}\n')
                        for optimization in ['-O0', '-O2']:
                            def execute():
                                binary = output / (core + '-' + epoch + optimization)
                                flags = ['-std=c11', '-Wall', '-Werror=implicit-function-declaration',
                                         '-Werror=incompatible-pointer-types', optimization,
                                         '-fsigned-char' if char_type.isSigned() else '-funsigned-char',
                                         '-include', str(output / 'primitive-aliases.h')]
                                for command in [shlex.split(os.environ.get('CC', 'cc')) + flags + [str(source), str(driver), '-o', str(binary)], [str(binary)]]:
                                    proc = subprocess.run(command, capture_output=True, text=True, timeout=120)
                                    rows.append({'core': core, 'epoch': epoch, 'command': command,
                                                 'status': proc.returncode, 'stdout': proc.stdout, 'stderr': proc.stderr})
                                    assert proc.returncode == 0
                            attempt(core + '-' + epoch + optimization, execute)
                    attempt(core + '-' + epoch + '-' + name, consume)
            finally:
                assert snapshot() == before and int(program.getModificationNumber()) == revision, 'Consumer edited source'

        for core in test_cores():
            executable = KUNA_GHIDRA if core == 'kuna' else None
            organization.setCharIsSigned(original_sign)
            with selected_core(executable):
                interface = DecompInterface()
                try:
                    assert interface.openProgram(program), str(interface.getLastMessage())
                    acquire(interface, core, 'initial')
                    organization.setCharIsSigned(not original_sign)
                    interface.flushCache()
                    acquire(interface, core, 'edited-flush')
                    interface.resetDecompiler()
                    acquire(interface, core, 'edited-reset')
                    interface.closeProgram()
                    assert interface.openProgram(program), str(interface.getLastMessage())
                    acquire(interface, core, 'edited-reopen')
                except BaseException:
                    failures.append({'stage': core + '-interface', 'failure': traceback.format_exc()})
                finally:
                    interface.dispose()
                fresh = DecompInterface()
                try:
                    assert fresh.openProgram(program), str(fresh.getLastMessage())
                    acquire(fresh, core, 'edited-fresh')
                except BaseException:
                    failures.append({'stage': core + '-fresh-interface', 'failure': traceback.format_exc()})
                finally:
                    fresh.dispose()
    except BaseException:
        failures.append({'stage': 'contextual-setup', 'failure': traceback.format_exc()})
    finally:
        organization.setCharIsSigned(original_sign)
        machine.close()
    return {'passed': not failures, 'rows': rows, 'failures': failures}


def main():
    output = Path(os.environ.get("KUNA_SMOKE_OUT", "java-source-identity-proof"))
    output.mkdir(parents=True, exist_ok=True)
    cores = test_cores()
    report = {"passed": False, "group": "product" if "kuna" in cores else "stock-controls",
              "selected_cores": cores, "rows": []}
    program = None
    try:
        start_ghidra()
        from jpype import JArray, JByte
        from java.lang import Object
        from ghidra.app.decompiler import ClangFieldToken, DecompInterface
        from ghidra.program.database import ProgramDB
        from ghidra.program.flatapi import FlatProgramAPI
        from ghidra.program.model.data import (CategoryPath, StructureDataType, IntegerDataType,
            DataTypeConflictHandler, PointerDataType)
        from ghidra.program.model.lang import LanguageID, CompilerSpecID
        from ghidra.program.model.listing import Function, ParameterImpl, ReturnParameterImpl, Variable
        from ghidra.program.model.symbol import SourceType
        from ghidra.program.util import DefaultLanguageService
        from ghidra.util.task import ConsoleTaskMonitor
        owner = Object()
        language = DefaultLanguageService.getLanguageService().getLanguage(LanguageID("x86:LE:64:default"))
        program = ProgramDB("source-identity", language, language.getCompilerSpecByID(CompilerSpecID("gcc")), owner)
        monitor = ConsoleTaskMonitor()
        api = FlatProgramAPI(program, monitor)
        manager = program.getDataTypeManager()
        addr = program.getAddressFactory().getDefaultAddressSpace().getAddress
        tx = program.startTransaction("Distinct genuine source definitions")
        try:
            records = []
            functions = []
            for index, category in enumerate(("/first", "/second")):
                record = StructureDataType(CategoryPath(category), "Persisted", 4, manager)
                record.replaceAtOffset(0, IntegerDataType.dataType, 4, "authored_" + str(index), None)
                record = manager.resolve(record, DataTypeConflictHandler.DEFAULT_HANDLER)
                records.append(record)
                entry = addr(0x1000 + index * 0x100)
                block = api.createMemoryBlock("body" + str(index), entry,
                    JArray(JByte)(bytes.fromhex("8b07c3")), False)
                block.setExecute(True)
                assert api.disassemble(entry)
                fn = api.createFunction(entry, "read_" + str(index))
                fn.updateFunction("__stdcall", ReturnParameterImpl(IntegerDataType.dataType, program),
                    Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS, False, SourceType.USER_DEFINED,
                    JArray(Variable)([ParameterImpl("record", PointerDataType(record, manager), program)]))
                functions.append(fn)
        finally:
            program.endTransaction(tx, True)
        ids = [int(manager.getID(record)) for record in records]
        assert ids[0] != ids[1]
        for core in cores:
            exe = KUNA_GHIDRA if core == "kuna" else None
            tx = program.startTransaction("Restore independent core baseline")
            try:
                records[0].getComponentAt(0).setFieldName("authored_0")
            finally:
                program.endTransaction(tx, True)
            with selected_core(exe):
                interface = DecompInterface()
                retained = []
                try:
                    assert interface.openProgram(program), str(interface.getLastMessage())
                    for epoch in ("initial", "edited_flush", "reset", "reopen"):
                        if epoch == "edited_flush":
                            tx = program.startTransaction("Explicit nested source edit")
                            try:
                                records[0].getComponentAt(0).setFieldName("edited_field")
                            finally:
                                program.endTransaction(tx, True)
                            interface.flushCache()
                        elif epoch == "reset":
                            interface.resetDecompiler()
                        elif epoch == "reopen":
                            interface.closeProgram()
                            assert interface.openProgram(program), str(interface.getLastMessage())
                        before = int(program.getModificationNumber())
                        for index, fn in enumerate(functions):
                            result = interface.decompileFunction(fn, 60, monitor)
                            assert result.decompileCompleted(), str(result.getErrorMessage())
                            high = result.getHighFunction()
                            actual = high.getFunctionPrototype().getParam(0).getDataType().getDataType()
                            assert int(manager.getID(actual)) == ids[index]
                            expected = ("edited_field" if index == 0 and epoch != "initial"
                                        else "authored_" + str(index))
                            assert str(records[index].getComponentAt(0).getFieldName()) == expected
                            bindings = []
                            def visit(token):
                                if isinstance(token, ClangFieldToken):
                                    datatype = token.getDataType()
                                    bindings.append((str(token.getText()), int(token.getOffset()), int(manager.getID(datatype))))
                                for child in range(token.numChildren()):
                                    visit(token.Child(child))
                            visit(result.getCCodeMarkup())
                            assert bindings == [(expected, 0, ids[index])], bindings
                            code = str(result.getDecompiledFunction().getC())
                            assert expected in code and str(fn.getName()) in code
                            retained.append((result, code))
                            assert int(program.getModificationNumber()) == before, "Decompilation edited source"
                            report["rows"].append({"core": core, "epoch": epoch, "entry": str(fn.getEntryPoint()),
                                                   "bindings": bindings, "source_unchanged": True})
                        for old, code in retained:
                            assert str(old.getDecompiledFunction().getC()) == code
                finally:
                    interface.dispose()
        report["passed"] = True
    except BaseException:
        report["failure"] = traceback.format_exc()
        raise
    finally:
        if program is not None:
            program.release(owner)
        try:
            contextual = contextual_source_cases(output / "contextual")
        except BaseException:
            contextual = {"passed": False, "failure": traceback.format_exc()}
        report["contextual"] = contextual
        report["passed"] = report["passed"] and contextual["passed"]
        (output / "source_identity.json").write_text(json.dumps(report, indent=2) + "\n")
        if not contextual["passed"] and "failure" not in report:
            raise AssertionError("Contextual source clauses failed; see source_identity.json")


if __name__ == "__main__":
    main()
