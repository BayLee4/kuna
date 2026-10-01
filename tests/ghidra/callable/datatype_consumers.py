#!/usr/bin/env python3
"""Actual Java datatype consumers; all selected cases are mandatory requirements."""
import json
import os
from pathlib import Path
import re
import struct
import subprocess
import sys
import traceback

from support import host, output, sha256, tool
from whole_calls import Machine

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

BITFIELDS = ((4, 13, 12, True), (4, 23, 7, False), (0, 0, 31, True),
             (4, 7, 25, False), (4, 9, 7, True), (8, 5, 19, False))


def execute(out, row, driver):
    """Consume the publication's untouched C/H, never a replacement provider."""
    (out / 'driver.c').write_text('#include "unit.h"\n#include <stdint.h>\n#include <string.h>\n' + driver)
    row['execution'] = []
    for optimization in ('-O0', '-O2'):
        binary = out / ('consumer' + optimization)
        commands = [[tool('cc'), '-std=c11', '-Wall', '-Werror=uninitialized',
                     '-Werror=incompatible-pointer-types', '-Werror=implicit-function-declaration',
                     optimization, str(out / 'unit.c'), str(out / 'driver.c'), '-o', str(binary)],
                    [str(binary)]]
        for command in commands:
            result = subprocess.run(command, capture_output=True, text=True, timeout=120)
            observation = dict(command=command, status=result.returncode,
                               stdout=result.stdout, stderr=result.stderr)
            row['execution'].append(observation)
            assert result.returncode == 0, observation


def snapshot(functions):
    return {name: {'signature': str(fn.getSignature()),
                   'return_storage': str(fn.getReturn().getVariableStorage()),
                   'parameters': [{'name': str(p.getName()), 'type': str(p.getDataType()),
                                   'storage': str(p.getVariableStorage())}
                                  for p in fn.getParameters()]}
            for name, fn in functions.items()}


def publish(machine, functions, out, row, inspect=None, refuse=False):
    from java.io import File, IOException
    from ghidra.app.decompiler import CallableSupport, DecompInterface, DecompileOptions
    from ghidra.app.util.exporter import CppExporter
    from ghidra.program.model.pcode import PcodeDataTypeManager
    from ghidra.program.model.symbol import IllegalCharCppTransformer
    from kuna_vs_stock import get_exepath_field

    field = get_exepath_field()
    previous = field.get(None)
    interface = DecompInterface()
    publication = CallableSupport.Publication()
    before = snapshot(functions)
    row['source_before'] = before
    row['decompilations'] = []
    try:
        field.set(None, str(host()))
        options = DecompileOptions()
        options.setBitfieldAccess(True)
        options.setNamespaceStrategy(DecompileOptions.NamespaceStrategy.Never)
        interface.setOptions(options)
        assert interface.openProgram(machine.program), str(interface.getLastMessage())
        supports = []
        for name, function in functions.items():
            result = interface.decompileFunction(function, 120, machine.monitor)
            observed = {'name': name, 'completed': bool(result.decompileCompleted()),
                        'error': str(result.getErrorMessage())}
            row['decompilations'].append(observed)
            assert observed['completed'], observed
            fragment = result.getDecompiledFunction()
            assert fragment is not None, observed
            (out / (name + '-fragment.c')).write_text(str(fragment.getC()))
            optional = result.getCallableSupport()
            assert optional.isPresent(), 'Actual producer must return explicit CallableSupport'
            support = optional.get()
            observed.update(status=str(support.getStatus()), reason=str(support.getReason()))
            observed['bodies'] = [
                {'space': int(body.id().space()), 'address': int(body.id().byteAddress()),
                 'current': bool(body.current()), 'complete': bool(body.complete()),
                 'declaration': str(body.declaration())}
                for body in support.getBodies()]
            if not refuse:
                current = [body for body in observed['bodies'] if body['current']]
                assert len(current) == 1, observed
                assert current[0]['address'] == int(function.getEntryPoint().getOffset()), observed
                assert current[0]['space'] == int(function.getEntryPoint().getAddressSpace().getUnique()), observed
            supports.append(support)
            if inspect is not None:
                inspect(result)
        # No comment/error wording admission: use the real Publication contract.
        try:
            for support in supports:
                publication.add(support)
            publication.validate()
            publication.sourceOwnership(PcodeDataTypeManager(machine.program, IllegalCharCppTransformer()))
        except IOException as error:
            if not refuse:
                raise
            row['publication_refusal'] = str(error)
        else:
            assert not refuse, 'Malformed ordinary RET 8 must not publish as a normal callable'
            assert all(str(s.getStatus()) == 'COMPLETE' for s in supports)
            # The ordinary exporter owns source datatype declarations as well as
            # callable artifacts. Do not handwrite a Bits/PairArray declaration.
            exporter = CppExporter(options, True, True, True, True, False, "")
            assert exporter.export(File(str(out / 'unit.c')), machine.program, None,
                                   machine.monitor), 'Actual source publication rejected'
            row['publication_sha256'] = {name: sha256(out / name) for name in ('unit.c', 'unit.h')}
        row['source_after'] = snapshot(functions)
        assert row['source_after'] == before, 'Publication must not mutate source identity/storage'
    finally:
        publication.close()
        interface.dispose()
        field.set(None, previous)


def install(machine, name, pc, result_type, parameters):
    from jpype import JArray
    from ghidra.program.flatapi import FlatProgramAPI
    from ghidra.program.model.listing import Function, ParameterImpl, ReturnParameterImpl, Variable
    from ghidra.program.model.symbol import SourceType
    program = machine.program
    function = FlatProgramAPI(program, machine.monitor).createFunction(machine.address(pc), name)
    assert function is not None, name
    function.updateFunction('__stdcall', ReturnParameterImpl(result_type, program),
                            Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS, False,
                            SourceType.USER_DEFINED,
                            JArray(Variable)([ParameterImpl(n, t, program) for n, t in parameters]))
    return function


def emulate(machine, pc, registers, memory=(), size=0):
    from jpype import JArray, JByte
    from java.math import BigInteger
    emulator = machine.EmulatorHelper(machine.program)
    try:
        for register, value in registers:
            emulator.writeRegister(register, BigInteger(str(value)))
        for address, data in memory:
            emulator.writeMemory(machine.address(address), JArray(JByte)(data))
        emulator.writeRegister('RSP', 0x7fe0)
        emulator.writeMemory(machine.address(0x7fe0), JArray(JByte)((0x7ff0).to_bytes(8, 'little')))
        emulator.setBreakpoint(machine.address(0x7ff0))
        assert emulator.run(machine.address(pc), None, machine.monitor), str(emulator.getLastError())
        assert emulator.getExecutionAddress() == machine.address(0x7ff0)
        observed = {'rax': int(str(emulator.readRegister('RAX'))) & ((1 << 64) - 1),
                    'stack_delta': int(str(emulator.readRegister('RSP'))) - 0x7fe0}
        if size:
            observed['memory'] = bytes(int(b) & 255 for b in emulator.readMemory(machine.address(0x7100), size)).hex()
        return observed
    finally:
        emulator.dispose()


def bitfield(out, row, off, first, width, signed, writing):
    from ghidra.app.decompiler import ClangBitFieldToken
    from ghidra.program.model.data import (StructureDataType, IntegerDataType,
        UnsignedIntegerDataType, PointerDataType, DataTypeConflictHandler, VoidDataType)
    integer = IntegerDataType.dataType if signed else UnsignedIntegerDataType.dataType
    mask = ((1 << width) - 1) << first
    code = bytes.fromhex('8b07') if off == 0 else bytes([0x8b, 0x47, off])
    if writing:
        code += b'\x25' + struct.pack('<I', (~mask) & 0xffffffff)
        code += b'\x89\xf1\x81\xe1' + struct.pack('<I', (1 << width) - 1)
        if first:
            code += bytes([0xc1, 0xe1, first])
        code += b'\x09\xc8'
        code += bytes.fromhex('8907') if off == 0 else bytes([0x89, 0x47, off])
    elif signed:
        left = 32 - first - width
        if left:
            code += bytes([0xc1, 0xe0, left])
        code += bytes([0xc1, 0xf8, 32 - width])
    else:
        if first:
            code += bytes([0xc1, 0xe8, first])
        code += b'\x25' + struct.pack('<I', (1 << width) - 1)
    code += b'\xc3'
    row['instructions'] = code.hex()
    machine = Machine(code, [('extract', 0x1000, code, '')])
    try:
        program = machine.program
        manager = program.getDataTypeManager()
        tx = program.startTransaction('Original signed bitfield source and storage')
        try:
            record = StructureDataType('Bits', off + 4, manager)
            for pad in range(0, off, 4):
                record.replaceAtOffset(pad, UnsignedIntegerDataType.dataType, 4, f'pad{pad}', None)
            record.insertBitFieldAt(off, 4, first, integer, width, 'middle', None)
            record = manager.resolve(record, DataTypeConflictHandler.DEFAULT_HANDLER)
            parameters = [('bits', PointerDataType(record, manager))]
            if writing:
                parameters.append(('value', UnsignedIntegerDataType.dataType))
            function = install(machine, 'extract', 0x1000,
                               VoidDataType.dataType if writing else integer, parameters)
        finally:
            program.endTransaction(tx, True)
        row['record_id'] = int(manager.getID(record))
        row['machine'] = []
        for i in range(256):
            raw = (i * 0x9e3779b9) & 0xffffffff
            value = ((~raw) * 3) & 0xffffffff
            memory = bytearray(b'\xa5' * (off + 4))
            memory[off:off + 4] = raw.to_bytes(4, 'little')
            wanted = bytearray(memory)
            expected = (raw >> first) & ((1 << width) - 1)
            if signed and expected & (1 << (width - 1)):
                expected -= 1 << width
            if writing:
                wanted[off:off + 4] = ((raw & ~mask) | ((value << first) & mask)).to_bytes(4, 'little')
            actual = emulate(machine, 0x1000, [('RDI', 0x7100), ('RSI', value)],
                             [(0x7100, memory)], len(memory))
            assert actual['stack_delta'] == 8, actual
            assert actual['memory'] == wanted.hex(), (i, actual, wanted.hex())
            if not writing:
                assert actual['rax'] & 0xffffffff == expected & 0xffffffff, (i, actual, expected)
            row['machine'].append(dict(vector=i, raw=raw, value=value, **actual))
        row['bitfield_tokens'] = []

        def inspect(result):
            def visit(token):
                if isinstance(token, ClangBitFieldToken):
                    component, parent = token.getComponent(), token.getDataType()
                    assert component is not None and parent is not None
                    item = {'text': str(token.getText()), 'component': str(component.getFieldName()),
                            'parent_id': int(manager.getID(parent))}
                    row['bitfield_tokens'].append(item)
                    assert item['component'] == item['text'] == 'middle', item
                    assert item['parent_id'] == row['record_id'], item
                for index in range(token.numChildren()):
                    visit(token.Child(index))
            visit(result.getCCodeMarkup())
            assert row['bitfield_tokens'], 'Bitfield-ON must retain actual component tokens'

        publish(machine, {'extract': function}, out, row, inspect)
        expected_c = f'long long expected=(raw>>{first})&{(1 << width) - 1}u;'
        if signed:
            expected_c += f'if(expected&{1 << (width - 1)}LL)expected-={1 << width}LL;'
        if writing:
            check = (f'unsigned value=~raw*3u; unsigned char wanted[sizeof(b)]; memcpy(wanted,&b,sizeof(b));'
                     f'unsigned expected=(raw&{(~mask) & 0xffffffff}u)|((value<<{first})&{mask}u);'
                     f'memcpy(wanted+{off},&expected,4); extract(&b,value);'
                     'if(memcmp(&b,wanted,sizeof(b)))return 2;')
        else:
            check = expected_c + 'if((long long)extract(&b)!=expected)return 3;'
        driver = (f'int main(void){{if(sizeof(Bits)!={off + 4})return 1;'
                  'for(unsigned i=0;i<256;i++){unsigned raw=i*0x9e3779b9u;Bits b;'
                  f'memset(&b,0xa5,sizeof(b));memcpy((unsigned char*)&b+{off},&raw,4);'
                  + check + '}return 0;}\n')
        execute(out, row, driver)
    finally:
        machine.close()


def array_pointer(out, row, typedef):
    from ghidra.program.model.data import (ArrayDataType, LongLongDataType, PointerDataType,
        TypedefDataType, CategoryPath, DataTypeConflictHandler)
    code = bytes.fromhex('488b4718c3')
    machine = Machine(code, [('read_value', 0x1000, code, '')])
    row['instructions'] = code.hex()
    try:
        program = machine.program
        manager = program.getDataTypeManager()
        tx = program.startTransaction('Original pointer to two-element array source')
        try:
            array = ArrayDataType(LongLongDataType.dataType, 2, 8, manager)
            if typedef:
                array = manager.resolve(TypedefDataType(CategoryPath.ROOT, 'PairArray', array, manager),
                                        DataTypeConflictHandler.DEFAULT_HANDLER)
            function = install(machine, 'read_value', 0x1000, LongLongDataType.dataType,
                               [('typed_input', PointerDataType(array, manager))])
            parameter = function.getParameter(0).getDataType()
        finally:
            program.endTransaction(tx, True)
        data = struct.pack('<qqqq', -739, 219, 831, -415)
        actual = emulate(machine, 0x1000, [('RDI', 0x7100)], [(0x7100, data)], len(data))
        assert actual['rax'] == (-415 & ((1 << 64) - 1)) and actual['stack_delta'] == 8, actual
        assert actual['memory'] == data.hex(), actual
        row['machine'] = actual

        def inspect(result):
            high = result.getHighFunction().getFunctionPrototype().getParam(0).getDataType()
            row['parameter_id'] = int(manager.getID(parameter))
            row['high_parameter'] = str(high)
            assert high.isEquivalent(parameter), (str(high), str(parameter))

        publish(machine, {'read_value': function}, out, row, inspect)
        declaration = 'PairArray rows[2]' if typedef else 'longlong rows[2][2]'
        execute(out, row, 'int main(void){' + declaration + '={{-739,219},{831,-415}};'
                'return read_value(rows)!=rows[1][1] || read_value(rows)!=-415;}\n')
    finally:
        machine.close()


def mixed_flow(out, row, malformed):
    from jpype import JArray
    from ghidra.app.plugin.processors.sleigh import PcodeEmitPacked
    from ghidra.program.flatapi import FlatProgramAPI
    from ghidra.program.model.data import (IntegerDataType, UnsignedIntegerDataType,
        FunctionDefinitionDataType, ParameterDefinition, ParameterDefinitionImpl, PointerDataType)
    from ghidra.program.model.listing import FlowOverride
    from ghidra.program.model.pcode import PcodeOp
    code = bytes.fromhex('85ff741983ff01740889f7e8f0000000c389f7488d15e6030000ff12c389f083c003')
    code += bytes.fromhex('c20800' if malformed else 'c3')
    entries = [('subject', 0x1000, code, ''),
               ('target_a', 0x1100, bytes.fromhex('89f883c00ac3'), ''),
               ('target_b', 0x1200, bytes.fromhex('89f883c014c3'), '')]
    image = bytearray(0x408)
    for name, pc, body, _ in entries:
        image[pc - 0x1000:pc - 0x1000 + len(body)] = body
    image[0x400:0x408] = (0x1200).to_bytes(8, 'little')
    machine = Machine(image, entries)
    row['instructions'] = [{'name': n, 'address': pc, 'bytes': b.hex()} for n, pc, b, _ in entries]
    try:
        program = machine.program
        api = FlatProgramAPI(program, machine.monitor)
        integer, unsigned = IntegerDataType.dataType, UnsignedIntegerDataType.dataType
        functions = {}
        tx = program.startTransaction('Original two marked calls and ordinary exit source')
        try:
            definition = FunctionDefinitionDataType('Callback', program.getDataTypeManager())
            definition.setCallingConvention('__stdcall')
            definition.setReturnType(integer)
            definition.setArguments(JArray(ParameterDefinition)([ParameterDefinitionImpl('value', integer, None)]))
            for name, pc, body, _ in entries:
                parameters = [('choice', unsigned), ('value', integer)] if name == 'subject' else [('value', integer)]
                functions[name] = install(machine, name, pc, integer, parameters)
                assert int(functions[name].getBody().getMaxAddress().getOffset()) < pc + len(body)
            api.createData(machine.address(0x1400), PointerDataType(definition, program.getDataTypeManager()))
            api.createLabel(machine.address(0x1400), 'callback_slot', True)
            program.getMemory().getBlock(machine.address(0x1400)).setWrite(True)
            row['marked_sites'] = []
            for pc in (0x100b, 0x101a):
                instruction = program.getListing().getInstructionAt(machine.address(pc))
                assert str(instruction.getMnemonicString()).upper() == 'CALL'
                phases = {}
                for phase in ('original', 'overridden'):
                    if phase == 'overridden':
                        instruction.setFlowOverride(FlowOverride.CALL_RETURN)
                    operations = list(instruction.getPcode(phase == 'overridden'))
                    calls = [i for i, op in enumerate(operations) if op.getOpcode() in (PcodeOp.CALL, PcodeOp.CALLIND)]
                    assert len(calls) == 1
                    if pc == 0x101a:
                        assert operations[calls[0]].getOpcode() == PcodeOp.CALLIND
                        assert any(op.getOpcode() == PcodeOp.LOAD for op in operations[:calls[0]])
                    phases[phase] = [str(op) for op in operations]
                row['marked_sites'].append(dict(address=pc, **phases))
        finally:
            program.endTransaction(tx, True)
        origin = Path(str(PcodeEmitPacked.class_.getProtectionDomain().getCodeSource().getLocation().toURI().getPath())).resolve()
        expected = Path(os.environ['GHIDRA_INSTALL_DIR']).resolve() / 'Ghidra/patch/kuna-ghidra-producer.jar'
        row['producer_origin'] = str(origin)
        assert origin == expected, (origin, expected)
        row['machine'] = []
        for choice in (0, 1, 0xffffffff):
            for value in (-7, 0, 5, 1234):
                actual = emulate(machine, 0x1000, [('RDI', choice), ('RSI', value & 0xffffffff)])
                wanted = (value + (3 if choice == 0 else 20 if choice == 1 else 10)) & 0xffffffff
                assert actual['rax'] & 0xffffffff == wanted, actual
                assert actual['stack_delta'] == (16 if malformed and choice == 0 else 8), actual
                row['machine'].append(dict(choice=choice, value=value, **actual))
        publish(machine, functions, out, row, refuse=malformed)
        if not malformed:
            # Integrated Publication writes extern global declarations, not
            # object initializers. Supply only the genuine fixture data using
            # that exact emitted type; the target body remains the real export.
            declarations = re.findall(r'(?m)^\s*extern\s+([^;]*\bcallback_slot\b[^;]*);',
                                      (out / 'unit.h').read_text())
            assert len(declarations) == 1, 'Expected one externally owned callback slot'
            definition = declarations[0].strip() + '=target_b;\n'
            row['global_ownership'] = {
                'owner': 'consumer fixture data', 'source_address': 0x1400,
                'original_pointer': 0x1200, 'emitted_target': 'target_b',
                'definition': definition}
            execute(out, row, definition +
                    'int main(void){const unsigned choices[]={0,1,UINT32_MAX};'
                    'const int values[]={-7,0,5,1234};'
                    'for(unsigned i=0;i<3;i++)for(unsigned j=0;j<4;j++){'
                    'int want=values[j]+(choices[i]==0?3:choices[i]==1?20:10);'
                    'if(subject(choices[i],values[j])!=want)return 1;}return 0;}\n')
    finally:
        machine.close()


def custom_return(out, row, label, offset, size, signed, load, tail):
    from jpype import JArray
    from ghidra.program.flatapi import FlatProgramAPI
    from ghidra.program.model.data import (UnsignedIntegerDataType, UnsignedLongLongDataType,
        ShortDataType, SignedByteDataType, IntegerDataType)
    from ghidra.program.model.listing import (Function, ParameterImpl, ReturnParameterImpl,
        Variable, VariableStorage)
    from ghidra.program.model.pcode import Varnode
    from ghidra.program.model.symbol import SourceType
    datatype = (UnsignedIntegerDataType.dataType if not signed else
                ShortDataType.dataType if size == 2 else SignedByteDataType.dataType)
    target = bytes.fromhex(load) + bytes([0x48, 0xc1, 0xe0, offset * 8]) + b'\xc3'
    extraction = bytes([0x48, 0xc1, 0xf8 if signed and size == 1 else 0xe8,
                        offset * 8]) + bytes.fromhex(tail)
    entries = [
        ('target', 0x2000, target, ''),
        ('indirect', 0x1000, bytes.fromhex('4883ec08488d05f50f0000ffd0') +
         extraction + bytes.fromhex('4883c408c3'), ''),
        ('direct', 0x1100, bytes.fromhex('4883ec08e8f70e0000') +
         extraction + bytes.fromhex('4883c408c3'), ''),
    ]
    image = bytearray(0x1000 + len(target))
    for _, pc, code, _ in entries:
        image[pc - 0x1000:pc - 0x1000 + len(code)] = code
    row['instructions'] = [{'name': n, 'address': pc, 'bytes': b.hex()} for n, pc, b, _ in entries]
    values = [0x123456789abcdef0, 0xfedcba9876543210,
              0x00000001ffffff80, 0xffffffff00007fff]
    machine = Machine(image, entries)
    try:
        program = machine.program
        functions = {}
        api = FlatProgramAPI(program, machine.monitor)
        tx = program.startTransaction('Original exact custom return slices')
        try:
            address = program.getRegister('RAX').getAddress().add(offset)
            storage = VariableStorage(program, JArray(Varnode)([Varnode(address, size)]))
            for name, pc, _, _ in entries:
                function = api.createFunction(machine.address(pc), name)
                assert function is not None, name
                result = (ReturnParameterImpl(datatype, storage, program) if name == 'target' else
                          ReturnParameterImpl(IntegerDataType.dataType if signed else
                                              UnsignedIntegerDataType.dataType,
                                              program.getRegister('EAX'), program))
                parameter = ParameterImpl('value', UnsignedLongLongDataType.dataType,
                                          program.getRegister('RDI'), program)
                function.updateFunction('__stdcall', result, Function.FunctionUpdateType.CUSTOM_STORAGE,
                                        True, SourceType.USER_DEFINED, JArray(Variable)([parameter]))
                functions[name] = function
            installed = functions['target'].getReturn().getVariableStorage().getVarnodes()
            assert len(installed) == 1
            assert installed[0].getAddress() == address and installed[0].getSize() == size
            row['custom_result'] = {'register': 'RAX', 'byte_offset': offset, 'size': size,
                                    'signed': signed, 'storage': str(storage)}
        finally:
            program.endTransaction(tx, True)
        row['machine'] = []
        mask = (1 << (size * 8)) - 1
        for name, pc in (('indirect', 0x1000), ('direct', 0x1100)):
            for value in values:
                expected = value & mask
                if signed and expected & (1 << (size * 8 - 1)):
                    expected -= 1 << (size * 8)
                actual = emulate(machine, pc, [('RDI', value)])
                assert actual['rax'] & 0xffffffff == expected & 0xffffffff, actual
                assert actual['stack_delta'] == 8, actual
                row['machine'].append(dict(function=name, input=hex(value), expected=expected, **actual))
        # Includes the real shifted target, not the historical handwritten cast.
        publish(machine, functions, out, row)
        expected_c = f'unsigned long long raw=values[i]&{mask}ULL;long long expected=(long long)raw;'
        if signed:
            expected_c += f'if(raw&{1 << (size * 8 - 1)}ULL)expected-={1 << (size * 8)}LL;'
        driver = ('int main(void){const unsigned long long values[]={' +
                  ','.join(hex(value) + 'ULL' for value in values) +
                  '};for(unsigned i=0;i<4;i++){' + expected_c +
                  'if((long long)direct(values[i])!=expected)return 1;'
                  'if((long long)indirect(values[i])!=expected)return 2;}return 0;}\n')
        execute(out, row, driver)
    finally:
        machine.close()


def main():
    out = output('datatype-consumers')
    cases = []
    for off, first, width, signed in BITFIELDS:
        for writing in (False, True):
            cases.append((f'bitfield_{off}_{first}_{width}_{int(signed)}_{"write" if writing else "read"}',
                          bitfield, (off, first, width, signed, writing)))
    cases.extend([('array_pointer', array_pointer, (False,)),
                  ('array_typedef_pointer', array_pointer, (True,)),
                  ('mixed_two_marked', mixed_flow, (False,)),
                  ('mixed_bad_ret8', mixed_flow, (True,))])
    for case in (('upper_uint', 4, 4, False, '89f8', ''),
                 ('middle_short', 3, 2, True, '480fbfc7', '0fbfc0'),
                 ('upper_byte', 7, 1, True, '480fbec7', '')):
        cases.append(('custom_return_' + case[0], custom_return, case))
    report = {'completed': False, 'cases': [], 'output': str(out)}
    try:
        import pyghidra
        pyghidra.start()
        report['native'] = str(host())
        report['native_sha256'] = sha256(host())
        tool('cc')
        prerequisite = None
    except Exception:
        prerequisite = traceback.format_exc()
    for name, function, arguments in cases:
        directory = out / name
        directory.mkdir()
        row = {'case': name, 'completed': False}
        report['cases'].append(row)
        try:
            if prerequisite:
                raise RuntimeError(prerequisite)
            function(directory, row, *arguments)
            row['completed'] = True
        except Exception:
            row['failure'] = traceback.format_exc()
        finally:
            (directory / 'report.json').write_text(json.dumps(row, indent=2) + '\n')
            print(json.dumps({'case': name, 'completed': row['completed'], 'failure': row.get('failure')}), flush=True)
    report['completed'] = all(row['completed'] for row in report['cases'])
    (out / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
    print(out, flush=True)
    return 0 if report['completed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
