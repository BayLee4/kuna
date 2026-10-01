#!/usr/bin/env python3
"""Raw BOOL byte is physical state, not a native C _Bool range proof."""
import argparse
import hashlib
import json
from pathlib import Path
from support import ROOT, cli as default_cli, output, tool
import subprocess
import traceback
from whole_calls import Machine, rel

parser = argparse.ArgumentParser()
parser.add_argument('--out', type=Path)
parser.add_argument('--cli', type=Path)
parser.add_argument('--machine-only', action='store_true')
args = parser.parse_args()
args.cli = args.cli.resolve() if args.cli else None if args.machine_only else default_cli()
args.out = (args.out or output("native_bool_boundary")/"run").resolve()
args.out.mkdir(parents=True, exist_ok=False)
entries = [
    ('dispatch', 0x1000, rel(0xe8, 0x1000, 0x1100) + bytes.fromhex('c3'), 'int dispatch(unsigned char raw)'),
    ('invoke', 0x1100, bytes.fromhex('488b35f9010000ffd6c3'), 'int invoke(bool value)'),
    ('native_target', 0x1200, bytes.fromhex('400fb6c7c3'), 'int native_target(bool value)'),
]
image = bytearray(0x308)
for _, pc, code, _ in entries:
    image[pc-0x1000:pc-0x1000+len(code)] = code
image[0x300:0x308] = (0x1200).to_bytes(8, 'little')
binary = args.out/'native_bool_boundary'
binary.write_bytes(image)
report = {
    'scope': 'Source BOOL must not canonicalize arbitrary incoming low byte at an unresolved native callback edge. Real MOVZX target, no replacement callee or patched emitted C.',
    'machine_only': args.machine_only,
    'completed': False,
    'image_sha256': hashlib.sha256(image).hexdigest(),
    'fixture': [{'name': n, 'address': a, 'bytes': c.hex(), 'source_prototype': p} for n, a, c, p in entries],
    'commands': [],
}
def invoke(command):
    command = list(map(str, command))
    process = subprocess.run(command, cwd='/tmp', capture_output=True, text=True, timeout=240)
    row = {'command': command, 'status': process.returncode, 'stdout': process.stdout, 'stderr': process.stderr}
    report['commands'].append(row)
    return row
try:
    machine = Machine(image, entries)
    try:
        from jpype import JArray, JByte
        from ghidra.program.flatapi import FlatProgramAPI
        from ghidra.program.model.data import BooleanDataType, UnsignedCharDataType, IntegerDataType, FunctionDefinitionDataType, ParameterDefinition, ParameterDefinitionImpl, PointerDataType
        from ghidra.program.model.listing import Function, ParameterImpl, ReturnParameterImpl, Variable
        from ghidra.program.model.symbol import SourceType
        program = machine.program
        api = FlatProgramAPI(program, machine.monitor)
        integer, boolean, byte = IntegerDataType.dataType, BooleanDataType.dataType, UnsignedCharDataType.dataType
        callback = FunctionDefinitionDataType('Callback', program.getDataTypeManager())
        callback.setCallingConvention('__stdcall')
        callback.setReturnType(integer)
        callback.setArguments(JArray(ParameterDefinition)([ParameterDefinitionImpl('value', boolean, None)]))
        pointer = PointerDataType(callback, program.getDataTypeManager())
        report['source'] = []
        tx = program.startTransaction('genuine BOOL callback source declarations')
        try:
            for name, pc, _, _ in entries:
                fn = api.createFunction(machine.address(pc), name)
                assert fn is not None
                parameters = [ParameterImpl('raw', byte, program)] if name == 'dispatch' else [ParameterImpl('value', boolean, program)]
                fn.updateFunction('__stdcall', ReturnParameterImpl(integer, program), Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS, False, SourceType.USER_DEFINED, JArray(Variable)(parameters))
                actual = [(str(p.getName()), str(p.getDataType()), int(p.getDataType().getLength()), str(p.getVariableStorage())) for p in fn.getParameters()]
                assert actual[0][2:] == (1, 'DIL:1'), actual
                if name != 'dispatch':
                    assert isinstance(fn.getParameter(0).getDataType(), BooleanDataType)
                report['source'].append({'name': name, 'signature': str(fn.getSignature()), 'parameters': actual})
            api.createData(machine.address(0x1300), pointer)
            assert isinstance(callback.getArguments()[0].getDataType(), BooleanDataType)
        finally:
            program.endTransaction(tx, True)
        report['machine'] = []
        for upper in [0, 0x1234567800000000]:
            for low in [0, 1, 0xff]:
                raw = upper | low
                for name, pc, _, _ in entries:
                    emulator = machine.EmulatorHelper(program)
                    try:
                        for register, value in [('RDI', raw), ('RSI', 0x1200), ('RAX', 0x88776655), ('RSP', 0x7fe0)]:
                            emulator.writeRegister(register, value)
                        emulator.writeMemory(machine.address(0x7fe0), JArray(JByte)((0x7ff0).to_bytes(8, 'little')))
                        emulator.setBreakpoint(machine.address(0x7ff0))
                        assert emulator.run(machine.address(pc), None, machine.monitor), str(emulator.getLastError())
                        assert emulator.getExecutionAddress() == machine.address(0x7ff0)
                        actual = int(str(emulator.readRegister('RAX'))) & ((1 << 64)-1)
                        assert actual == low, (name, raw, actual, low)
                        report['machine'].append({'entry': name, 'raw_RDI': raw, 'low_byte': low, 'result': actual})
                    finally:
                        emulator.dispose()
    finally:
        machine.close()
    if not args.machine_only:
        report['cli_sha256'] = hashlib.sha256(args.cli.read_bytes()).hexdigest()
        common = ['--raw-image', '--target', 'x86:LE:64:default:gcc', '--base', '0x1000', '--sleighpath', ROOT/'specs', '--assert-strict', '--assert', 'typedef typedef int (*Callback)(bool value);', '--assert', 'data 0x1300 Callback callback_slot']
        for name, pc, code, prototype in entries:
            common += ['--addr', hex(pc), '--define-function', f'{pc:#x}-{pc+len(code):#x}={name}', '--assert', 'prototype '+name+' '+prototype]
        meta = invoke([args.cli, 'decompile-all', binary, '--json', *common])
        assert meta['status'] == 0, meta
        metadata = json.loads(meta['stdout'])
        (args.out/'metadata.json').write_text(json.dumps(metadata, indent=2)+'\n')
        byname = {f['name']: f for f in metadata['functions']}
        assert all(f.get('error') is None and f.get('code') for f in byname.values()), metadata
        for name, wanted in [('dispatch', [('raw', 1, 0)]), ('invoke', [('value', 1, 0)]), ('native_target', [('value', 1, 0)])]:
            parameters = sorted((v for v in byname[name]['variables'] if v['kind'] == 'arg'), key=lambda v: v['arg_index'])
            assert [(p['name'], p['size'], p['arg_index']) for p in parameters] == wanted, parameters
        assert byname['invoke'].get('callable_export_error'), byname['invoke']
        project = invoke([args.cli, 'decompile-project', binary, '-o', args.out/'project', *common])
        assert project['status'] == 1, project
        report['boundary'] = {'diagnostic_bodies_retained': True, 'invoke_explicit_export_error': True, 'project_rejected': True}
    report['completed'] = True
except BaseException:
    report['failure'] = traceback.format_exc()
    raise
finally:
    (args.out/'report.json').write_text(json.dumps(report, indent=2)+'\n')
    print(json.dumps(report, indent=2))
