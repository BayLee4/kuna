#!/usr/bin/env python3
"""Consume an actual mutable aggregate callback through its real invocation body."""
import argparse
import json
from pathlib import Path
import re
import subprocess
import traceback

from support import ROOT, tool, require_provider_body
from whole_calls_workers import ElfMachine, elf_symbols


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--cli', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=False)
    report = {'completed': False, 'machine': [], 'commands': []}
    symbols = elf_symbols(args.binary)
    symbol_listing = subprocess.run([tool('llvm-nm'), '--defined-only', str(args.binary)],
                                    check=True, capture_output=True, text=True).stdout
    for line in symbol_listing.splitlines():
        parts = line.split()
        if len(parts) == 3 and parts[2] in ['big_slot', 'big_wrong_slot', 'escaped_big_slot']:
            symbols[parts[2]] = int(parts[0], 16)

    def invoke(command, success=True):
        command = list(map(str, command))
        result = subprocess.run(command, cwd=ROOT, text=True, capture_output=True, timeout=240)
        row = {'command': command, 'status': result.returncode,
               'stdout': result.stdout, 'stderr': result.stderr}
        report['commands'].append(row)
        if success:
            assert result.returncode == 0, row
        return result

    declarations = [
        'typedef typedef struct Big24 { unsigned long long a; unsigned long long b; unsigned long long c; } Big24;',
        'typedef typedef Big24 (*BigFn)(int);',
        'prototype hidden_local unsigned long long hidden_local(BigFn callback,int tag)',
        'prototype mutable_big unsigned long long mutable_big(int tag)',
        'prototype mutable_big_wrong unsigned long long mutable_big_wrong(int tag)',
        'prototype make_big Big24 make_big(int tag)',
        'prototype make_big_other Big24 make_big_other(int tag)',
        'prototype make_big_wrong Big24 make_big_wrong(int tag)',
        f'data {symbols["big_slot"]:#x} BigFn big_slot',
        f'data {symbols["big_wrong_slot"]:#x} BigFn big_wrong_slot',
        f'data {symbols["escaped_big_slot"]:#x} BigFn escaped_big_slot',
    ]
    for subject, consumer in [('mutable_big_escape', 'hidden_callback_escape'),
                              ('mutable_big_reuse', 'hidden_callback_reuse')]:
        declarations.extend([f'prototype {subject} unsigned long long {subject}(int tag)',
                             f'prototype {consumer} unsigned long long {consumer}(BigFn callback,int tag)'])
    common = ['--language', 'c', '--option', 'structdefs', 'on', '--assert-strict']
    for declaration in declarations:
        common.extend(['--assert', declaration])
    try:
        machine = ElfMachine(args.binary, args.out)
        try:
            from java.math import BigInteger
            from jpype import JArray, JByte
            assert int(machine.program.getMemory().getLong(machine.address(symbols['big_slot']))) == symbols['make_big']
            machine_cases = [(subject, 'make_big') for subject in
                             ['mutable_big', 'mutable_big_wrong', 'mutable_big_escape', 'mutable_big_reuse']]
            machine_cases.append(('mutable_big', 'make_big_other'))
            for subject, target in machine_cases:
                for tag in [-20, 0, 5, 19]:
                    emulator = machine.EmulatorHelper(machine.program)
                    try:
                        initial = {'X0': tag & ((1 << 64) - 1), 'X19': 0x7fd0,
                                   'X29': 0x1122334455667788, 'X30': 0x7ff0, 'sp': 0x7fc0}
                        for name, value in initial.items():
                            emulator.writeRegister(name, BigInteger(str(value)))
                        if target != 'make_big':
                            pointer = symbols[target].to_bytes(8, 'little')
                            emulator.writeMemory(machine.address(symbols['big_slot']), JArray(JByte)(pointer))
                        stop = 0x7fd0 if subject == 'mutable_big_wrong' else 0x7ff0
                        emulator.setBreakpoint(machine.address(stop))
                        assert emulator.run(machine.address(symbols[subject]), None, machine.monitor), str(emulator.getLastError())
                        assert emulator.getExecutionAddress() == machine.address(stop)
                        result = int(str(emulator.readRegister('X0'))) & ((1 << 64) - 1)
                        if subject != 'mutable_big_wrong':
                            delta = 9 if target == 'make_big_other' else 3
                            assert result == (2 * tag + delta) & ((1 << 64) - 1), (subject, tag, result)
                            for name in ['X19', 'X29', 'sp']:
                                assert int(str(emulator.readRegister(name))) == initial[name], name
                        report['machine'].append({'subject': subject, 'target': target, 'tag': tag,
                                                  'stop': stop, 'result': result})
                    finally:
                        emulator.dispose()
        finally:
            machine.close()

        report['diagnostic_cases'] = []
        for subject, consumer, target in [
            ('mutable_big_wrong', 'hidden_local', 'make_big_wrong'),
            ('mutable_big_escape', 'hidden_callback_escape', 'make_big'),
            ('mutable_big_reuse', 'hidden_callback_reuse', 'make_big'),
        ]:
            row = {'subject': subject, 'completed': False}
            report['diagnostic_cases'].append(row)
            try:
                owners = ','.join([subject, consumer, target])
                bad = json.loads(invoke([args.cli, 'decompile-all', args.binary, '--functions',
                                         owners, '--json', *common]).stdout)
                assert len(bad['functions']) == 3 and {fn['name'] for fn in bad['functions']} == set(owners.split(',')), bad
                wrong = next(fn for fn in bad['functions'] if fn['name'] == subject)
                assert wrong.get('code'), wrong
                row['completed'] = True
            except Exception:
                row['failure'] = traceback.format_exc()

        owners = 'mutable_big,hidden_local,make_big,make_big_other'
        metadata = json.loads(invoke([args.cli, 'decompile-all', args.binary, '--functions', owners,
                                      '--json', *common]).stdout)
        (args.out / 'metadata.json').write_text(json.dumps(metadata, indent=2) + '\n')
        assert len(metadata['functions']) == len(owners.split(',')) and {fn['name'] for fn in metadata['functions']} == set(owners.split(',')), metadata
        for function in metadata['functions']:
            assert function.get('code') and not function.get('error'), function
        project = args.out / 'project'
        invoke([args.cli, 'decompile-project', args.binary, '--functions', owners, '-o', project, *common])
        for name in owners.split(','):
            require_provider_body(project / (args.binary.name + '.c'), name)
        header = (project / (args.binary.name + '.h')).read_text()
        assert re.search(r'\bextern\s+BigFn\s+big_slot\s*;', header), header
        driver = args.out / 'consumer.c'
        driver.write_text('#include "' + args.binary.name + '.h"\n'
                          'BigFn big_slot=make_big;\n'
                          'int main(void){if(big_slot!=make_big)return 1;'
                          'for(int tag=-20;tag<=20;++tag){'
                          'if(mutable_big(tag)!=(unsigned long long)(2*tag+3))return 2;'
                          'Big24 v=big_slot(tag);if(v.a!=(unsigned long long)tag||v.b!=7||'
                          'v.c!=(unsigned long long)(tag+3))return 3;}'
                          'big_slot=make_big_other;for(int tag=-20;tag<=20;++tag)'
                          'if(mutable_big(tag)!=(unsigned long long)(2*tag+9))return 4;return 0;}\n')
        for opt in ['-O0', '-O2']:
            executable = args.out / ('consumer' + opt)
            invoke([tool('cc'), '-std=c11', '-Wall', '-Wextra', '-Werror=uninitialized',
                    '-Werror=incompatible-pointer-types', '-Werror=implicit-function-declaration',
                    opt, '-I', project, project / (args.binary.name + '.c'), driver, '-o', executable])
            invoke([executable])

        report['behavioral_checks_completed'] = True
        report['completed'] = all(row['completed'] for row in report['diagnostic_cases'])
    finally:
        (args.out / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({'mutable_hidden_callback': report['completed']}), flush=True)
    if not report['completed']:
        raise SystemExit(1)


if __name__ == '__main__':
    main()
