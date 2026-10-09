#!/usr/bin/env python3
"""Compare the direct private-spill aggregate provider with its original machine body."""
import argparse
import json
from pathlib import Path
import subprocess

from support import ROOT, tool, require_provider_body
from whole_calls_workers import ElfMachine, elf_symbols


CASES = [('spill_direct', 'make_big_spill')]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--cli', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=False)
    report = {'completed': False, 'machine': [], 'commands': []}
    symbols = elf_symbols(args.binary)
    common = ['--language', 'c', '--option', 'structdefs', 'on', '--assert-strict',
              '--assert', 'typedef typedef struct Big24 { unsigned long long a; unsigned long long b; unsigned long long c; } Big24;']
    for caller, target in CASES:
        common += ['--assert', f'prototype {target} Big24 {target}(int tag)',
                   '--assert', f'prototype {caller} long long {caller}(int tag)']

    def invoke(command, success=True):
        command = list(map(str, command))
        result = subprocess.run(command, cwd=ROOT, text=True, capture_output=True, timeout=240)
        row = {'command': command, 'status': result.returncode,
               'stdout': result.stdout, 'stderr': result.stderr}
        report['commands'].append(row)
        if success:
            assert result.returncode == 0, row
        return result

    try:
        machine = ElfMachine(args.binary, args.out)
        try:
            from java.math import BigInteger
            from jpype import JArray, JByte
            mask = (1 << 64) - 1
            for _, target in CASES:
                for tag in [-20, 0, 5, 19]:
                    emulator = machine.EmulatorHelper(machine.program)
                    try:
                        for name, value in [('X0', tag & mask), ('X8', 0x7800), ('X19', 0x12345678),
                                            ('X29', 0x1122334455667788), ('X30', 0x7ff0), ('sp', 0x7fc0)]:
                            emulator.writeRegister(name, BigInteger(str(value)))
                        emulator.writeMemory(machine.address(0x7fbc), JArray(JByte)((0x12345678).to_bytes(4, 'little')))
                        emulator.setBreakpoint(machine.address(0x7ff0))
                        assert emulator.run(machine.address(symbols[target]), None, machine.monitor), str(emulator.getLastError())
                        assert emulator.getExecutionAddress() == machine.address(0x7ff0)
                        data = bytes(int(value) & 255 for value in emulator.readMemory(machine.address(0x7800), 24))
                        fields = [int.from_bytes(data[offset:offset + 8], 'little') for offset in (0, 8, 16)]
                        third = (0x12340000 | (tag & 0xffff)) if target.endswith('_partial') else (
                            0x12345678 if target.endswith('_uninitialized') else tag & mask)
                        assert fields == [0x7fb0 if target.endswith('_escape') else 10, 100, third], (target, tag, fields)
                        final_sp = int(str(emulator.readRegister('sp')))
                        assert final_sp == (0x7fb0 if target.endswith('_unbalanced') else 0x7fc0)
                        assert int(str(emulator.readRegister('X19'))) == 0x12345678
                        assert int(str(emulator.readRegister('X29'))) == 0x1122334455667788
                        report['machine'].append({'target': target, 'tag': tag, 'fields': fields, 'SP': final_sp})
                    finally:
                        emulator.dispose()
        finally:
            machine.close()

        for caller, target in CASES:
            owners = caller + ',' + target
            metadata = json.loads(invoke([args.cli, 'decompile-all', args.binary, '--functions', owners,
                                          '--json', *common]).stdout)
            (args.out / (caller + '.json')).write_text(json.dumps(metadata, indent=2) + '\n')
            assert {fn['name'] for fn in metadata['functions']} == {caller, target}, metadata
            assert all(not fn.get('error') for fn in metadata['functions']), metadata
            project = args.out / caller
            exported = invoke([args.cli, 'decompile-project', args.binary, '--functions', owners,
                               '-o', project, *common])
            assert exported.returncode == 0, exported.stderr
            for name in (caller, target):
                require_provider_body(project / (args.binary.name + '.c'), name)
            driver = args.out / 'consumer.c'
            driver.write_text('#include "' + args.binary.name + '.h"\n'
                              'int main(void){for(int tag=-20;tag<=20;++tag){Big24 v=make_big_spill(tag);'
                              'if(v.a!=10||v.b!=100||v.c!=(unsigned long long)tag)return 1;'
                              'if(spill_direct(tag)!=tag)return 2;}return 0;}\n')
            for opt in ['-O0', '-O2']:
                executable = args.out / ('consumer' + opt)
                invoke([tool('cc'), '-std=c11', '-Wall', '-Wextra', '-Werror=uninitialized',
                        '-Werror=incompatible-pointer-types', '-Werror=implicit-function-declaration',
                        opt, '-I', project, project / (args.binary.name + '.c'), driver, '-o', executable])
                invoke([executable])
        report['behavioral_checks_completed'] = True
        report['completed'] = True
    finally:
        (args.out / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({'private_spill_result': report['completed']}), flush=True)
    if not report['completed']:
        raise SystemExit(1)


if __name__ == '__main__':
    main()
