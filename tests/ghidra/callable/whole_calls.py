#!/usr/bin/env python3
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import traceback

BASE = 0x1000

def rel(opcode, pc, target):
    return bytes([opcode]) + int(target - (pc + 5)).to_bytes(4, 'little', signed=True)

def fixture():
    choose = bytes.fromhex('85ff488d0537000000488d0d50000000480f45c1c3')
    dispatch = bytes.fromhex('534889fb89f7')
    dispatch += rel(0xe8, 0x10a0 + len(dispatch), 0x1000)
    dispatch += bytes.fromhex('4889c64889df5b')
    dispatch += rel(0xe9, 0x10a0 + len(dispatch), 0x1080)
    entries = [
        ('choose', 0x1000, choose, 'Callback choose(unsigned int which)'),
        ('byte_target', 0x1040, bytes.fromhex('31c04080ff550f94c0c3'), 'int byte_target(Flags value)'),
        ('word_target', 0x1060, bytes.fromhex('31c083ff550f94c0c3'), 'int word_target(Flags value)'),
        ('invoke', 0x1080, bytes.fromhex('ffd6c3'), 'int invoke(Flags value,Callback callback)'),
        ('dispatch', 0x10a0, dispatch, 'int dispatch(Flags value,unsigned int which)'),
    ]
    for name, pc, raw in [('direct_dirty', 0x1100, 0x10055), ('direct_clean', 0x1120, 85)]:
        code = bytes([0xbf]) + raw.to_bytes(4, 'little')
        code += rel(0xe8, pc + len(code), 0x1060) + bytes([0xc3])
        entries.append((name, pc, code, 'int ' + name + '(void)'))
    entries.append(('ambient', 0x1140, rel(0xe8, 0x1140, 0x1060) + bytes([0xc3]), 'int ambient(void)'))
    for name, pc, raw in [('ambient_dirty', 0x1160, 0x10055), ('ambient_clean', 0x1180, 85)]:
        code = bytes([0xbf]) + raw.to_bytes(4, 'little')
        code += rel(0xe8, pc + len(code), 0x1140) + bytes([0xc3])
        entries.append((name, pc, code, 'int ' + name + '(void)'))
    entries.append(('bool_byte', 0x11a0, bytes.fromhex('31c04080ff550f94c0c3'), 'int bool_byte(bool value)'))
    entries.append(('wide_ambient', 0x11c0, rel(0xe8, 0x11c0, 0x1140) + bytes([0xc3]), 'int wide_ambient(unsigned long long bits)'))
    image = bytearray(0x1e0)
    for _, pc, code, _ in entries:
        image[pc-BASE:pc-BASE+len(code)] = code
    return bytes(image), entries

class Machine:
    def __init__(self, image, entries):
        import pyghidra
        pyghidra.start()
        from jpype import JArray, JByte
        from java.lang import Object
        from ghidra.app.emulator import EmulatorHelper
        from ghidra.program.database import ProgramDB
        from ghidra.program.flatapi import FlatProgramAPI
        from ghidra.program.model.lang import LanguageID, CompilerSpecID
        from ghidra.program.util import DefaultLanguageService
        from ghidra.util.task import ConsoleTaskMonitor
        self.EmulatorHelper = EmulatorHelper
        self.monitor = ConsoleTaskMonitor()
        language = DefaultLanguageService.getLanguageService().getLanguage(LanguageID('x86:LE:64:default'))
        self.owner = Object()
        self.program = ProgramDB('actual-whole-calls', language, language.getCompilerSpecByID(CompilerSpecID('gcc')), self.owner)
        api = FlatProgramAPI(self.program, self.monitor)
        self.address = self.program.getAddressFactory().getDefaultAddressSpace().getAddress
        tx = self.program.startTransaction('whole unit')
        try:
            block = api.createMemoryBlock('code', self.address(BASE), JArray(JByte)(image), False)
            block.setExecute(True)
            api.createMemoryBlock('stack', self.address(0x7000), JArray(JByte)(bytes(0x1000)), False)
            for _, pc, _, _ in entries:
                assert api.disassemble(self.address(pc))
        finally:
            self.program.endTransaction(tx, True)
    def call(self, pc, rdi=0, rsi=0):
        from jpype import JArray, JByte
        emu = self.EmulatorHelper(self.program)
        try:
            emu.writeRegister('RDI', rdi)
            emu.writeRegister('RSI', rsi)
            emu.writeRegister('RSP', 0x7fe0)
            emu.writeMemory(self.address(0x7fe0), JArray(JByte)((0x7ff0).to_bytes(8, 'little')))
            emu.setBreakpoint(self.address(0x7ff0))
            assert emu.run(self.address(pc), None, self.monitor), str(emu.getLastError())
            return int(str(emu.readRegister('RAX'))) & ((1 << 64)-1)
        finally:
            emu.dispose()
    def close(self):
        self.program.release(self.owner)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--cli', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--mode', choices=('serial',), default='serial')
    parser.add_argument('--specs', type=Path, default=Path(__file__).resolve().parents[3]/'specs')
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=False)
    report = {'scope': 'new actual emitted whole-unit acceptance, no handwritten adapter or body repair',
              'cli': str(args.cli), 'cli_sha256': hashlib.sha256(args.cli.read_bytes()).hexdigest(),
              'mode': args.mode, 'commands': [], 'completed': False}
    def invoke(command, expected=0):
        run = subprocess.run(list(map(str, command)), cwd='/tmp', capture_output=True, text=True, timeout=240)
        row = {'command': list(map(str, command)), 'status': run.returncode, 'stdout': run.stdout, 'stderr': run.stderr}
        report['commands'].append(row)
        (args.out/'report.json').write_text(json.dumps(report, indent=2)+'\n')
        assert (run.returncode != 0 if expected == 'nonzero' else run.returncode == expected), row
        return row
    try:
        image, entries = fixture()
        binary = args.out/'whole_calls'
        binary.write_bytes(image)
        report['fixture'] = [{'name': n, 'address': a, 'bytes': c.hex(), 'source_prototype': p} for n,a,c,p in entries]
        machine = Machine(image, entries)
        machine_rows = []
        try:
            for which, target in [(0, 0x1040), (1, 0x1060)]:
                assert machine.call(0x1000, which) == target
                assert machine.call(0x1000, which) == target
            assert machine.call(0x1100) == 0
            assert machine.call(0x1120) == 1
            assert machine.call(0x1160) == 0
            assert machine.call(0x1180) == 1
            for upper in (0, 0x10000, 0x1234567800000000):
                for low in range(256):
                    raw = upper | low
                    assert machine.call(0x1140, raw) == int((raw & 0xffffffff) == 85)
                    assert machine.call(0x11a0, raw) == int((raw & 0xff) == 85)
                    assert machine.call(0x11c0, raw) == int((raw & 0xffffffff) == 85)
                    for which in (0,1):
                        expected = int((raw & (0xffffffff if which else 0xff)) == 85)
                        actual = machine.call(0x10a0, raw, which)
                        assert actual == expected, (raw, which, actual, expected)
                        machine_rows.append({'raw': raw, 'which': which, 'actual': actual, 'expected': expected})
        finally:
            machine.close()
        (args.out/'machine.json').write_text(json.dumps(machine_rows, indent=2)+'\n')
        report['machine'] = {'cases':len(machine_rows), 'ambient_cases':768, 'bool_byte_cases':768, 'wide_ambient_cases':768, 'direct_dirty':0, 'direct_clean':1, 'ambient_dirty':0, 'ambient_clean':1, 'pointer_selection_identity':'passed'}
        project = args.out/'project'
        command = [args.cli, 'decompile-project', binary, '-o', project, '--raw-image', '--target', 'x86:LE:64:default:gcc', '--base', hex(BASE), '--sleighpath', args.specs, '--assert-strict',
                   '--assert', 'typedef typedef unsigned char Flags;', '--assert', 'typedef typedef int (*Callback)(Flags);']
        for name, pc, code, prototype in entries:
            command += ['--addr', hex(pc), '--define-function', f'{pc:#x}-{pc+len(code):#x}={name}', '--assert', 'prototype '+name+' '+prototype]
        metadata_command = [args.cli, 'decompile-all', binary, '--json', *command[5:]]
        invoke(command)
        metadata_run = invoke(metadata_command)
        metadata = json.loads(metadata_run['stdout'])
        (args.out/'source-metadata.json').write_text(json.dumps(metadata, indent=2)+'\n')
        expected_source = {
            'choose': [('which', 4)], 'byte_target': [('value', 1)],
            'word_target': [('value', 1)], 'invoke': [('value', 1), ('callback', 8)],
            'dispatch': [('value', 1), ('which', 4)], 'direct_dirty': [],
            'direct_clean': [], 'ambient': [], 'ambient_dirty': [], 'ambient_clean': [],
            'bool_byte': [('value', 1)], 'wide_ambient': [('bits', 8)],
        }
        actual_source = {}
        for function in metadata['functions']:
            assert function.get('error') is None, function
            assert function.get('callable_export_error') is None, function
            name = function['name']
            if name not in expected_source:
                continue
            params = sorted((v for v in function['variables'] if v['kind'] == 'arg'), key=lambda v:v['arg_index'])
            assert [v['arg_index'] for v in params] == list(range(len(expected_source[name]))), function
            actual = [(v['name'], v['size']) for v in params]
            assert actual == expected_source[name], (name, actual, expected_source[name])
            actual_source[name] = actual
        assert actual_source == expected_source, actual_source
        report['source_metadata'] = actual_source
        emitted_c = project/'whole_calls.c'
        emitted_h = project/'whole_calls.h'
        assert emitted_c.is_file() and emitted_h.is_file()
        report['emitted_sha256'] = {p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in (emitted_c,emitted_h)}
        driver = args.out/'consumer.c'
        driver.write_text('#include <stdint.h>\n#include <stdio.h>\n#include "whole_calls.h"\n'
            'int main(void) {\n'
            ' if (choose(0)!=choose(0) || choose(1)!=choose(1) || choose(0)==choose(1)) return 11;\n'
            ' if (direct_dirty()!=0 || direct_clean()!=1) return 12;\n'
            ' if (ambient_dirty()!=0 || ambient_clean()!=1) return 15;\n'
            ' const uint64_t upper[]={0,UINT64_C(0x10000),UINT64_C(0x1234567800000000)};\n'
            ' unsigned checked=0;\n'
            ' for(unsigned p=0;p<3;++p) for(unsigned low=0;low<256;++low) for(unsigned which=0;which<2;++which) {\n'
            '  uint64_t raw=upper[p]|low; int want=which ? (uint32_t)raw==85 : (uint8_t)raw==85;\n'
            '  if(which==0 && ambient(raw)!=((uint32_t)raw==85)) return 14;\n'
            '  if(which==0 && bool_byte(raw)!=((uint8_t)raw==85)) return 16;\n'
            '  if(which==0 && wide_ambient(raw)!=((uint32_t)raw==85)) return 17;\n'
            '  int got=dispatch(raw,which); int via_pointer=invoke(raw,choose(which));\n'
            '  if(got!=want || via_pointer!=want) { fprintf(stderr,"raw=%llx target=%u got=%d indirect=%d want=%d\\n",(unsigned long long)raw,which,got,via_pointer,want); return 13; }\n'
            '  ++checked;\n }\n printf("checked=%u direct-calls=passed pointer-identity=passed\\n",checked); return 0;\n}\n')
        for opt in ('O0','O2'):
            for char_mode in ('-fsigned-char', '-funsigned-char'):
                exe = args.out/('consumer-'+opt+char_mode)
                invoke(['cc','-std=c11','-Wall','-Wextra','-Werror=uninitialized','-Werror=incompatible-pointer-types','-Werror=implicit-function-declaration','-'+opt,char_mode,'-I',project,emitted_c,driver,'-o',exe])
                invoke([exe])
        native_image = bytearray(0x180)
        native_entries = [
            ('forward', 0x1000, rel(0xe8, 0x1000, 0x1100) + bytes([0xc3]), 'int forward(Callback callback)'),
            ('native_register_callback', 0x1100, bytes.fromhex('4889f8bf55000100ffd0c3'), 'int native_register_callback(Callback callback)'),
            ('native_byte_target', 0x1140, bytes.fromhex('31c04080ff550f94c0c3'), 'int native_byte_target(Flags value)'),
            ('native_word_target', 0x1160, bytes.fromhex('31c083ff550f94c0c3'), 'int native_word_target(Flags value)'),
        ]
        for _, pc, code, _ in native_entries:
            native_image[pc-BASE:pc-BASE+len(code)] = code
        native_machine = Machine(bytes(native_image), native_entries)
        try:
            assert native_machine.call(0x1000, 0x1140) == 1
            assert native_machine.call(0x1000, 0x1160) == 0
        finally:
            native_machine.close()
        native_binary = args.out/'native_boundary'
        native_binary.write_bytes(native_image)
        native_common = ['--raw-image', '--target', 'x86:LE:64:default:gcc', '--base', hex(BASE), '--sleighpath', args.specs,
                         '--addr', '0x1000', '--assert-strict',
                         '--assert', 'typedef typedef unsigned char Flags;',
                         '--assert', 'typedef typedef int (*Callback)(Flags);']
        for name, pc, code, prototype in native_entries:
            native_common += ['--define-function', f'{pc:#x}-{pc+len(code):#x}={name}',
                              '--assert', 'prototype '+name+' '+prototype]
        native_metadata_command = [args.cli, 'decompile-all', native_binary, '--json', *native_common]
        native_project_command = [args.cli, 'decompile-project', native_binary, '-o', args.out/'native-project', *native_common]
        native_metadata = json.loads(invoke(native_metadata_command)['stdout'])
        native_forward = next(function for function in native_metadata['functions'] if function['name'] == 'forward')
        assert native_forward.get('error') is None, native_forward
        assert native_forward.get('code'), native_forward
        native_params = [(value['name'], value['size']) for value in native_forward['variables'] if value['kind'] == 'arg']
        assert native_params == [('callback', 8)], native_forward
        assert any(artifact['required'] and artifact['definition'] is None
                   for artifact in native_forward.get('callable_artifacts', [])), native_forward
        invoke(native_project_command, expected=1)
        report['native_boundary'] = {'original_machine_byte_target':1, 'original_machine_word_target':0,
                                     'diagnostic_body_retained':True, 'unavailable_adapter_dependency_retained':True,
                                     'executable_export_rejected':True}
        report['completed'] = True
    except BaseException:
        report['failure'] = traceback.format_exc()
        raise
    finally:
        (args.out/'report.json').write_text(json.dumps(report, indent=2)+'\n')
        print(json.dumps(report, indent=2))

if __name__ == '__main__':
    main()
