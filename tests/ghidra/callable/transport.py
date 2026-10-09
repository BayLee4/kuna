#!/usr/bin/env python3
"""Build authentic fixtures and exercise public callable transport, types and ABI."""
import json
import subprocess
import traceback
from support import cli, host, output, run_script, sha256, tool


def main():
    root = output('transport')
    native = cli()
    ghidra = host()
    report = {'completed': False, 'cases': [], 'output': str(root)}

    def case(name, action):
        row = {'name': name, 'completed': False}
        report['cases'].append(row)
        try:
            action()
            row['completed'] = True
        except Exception:
            row['failure'] = traceback.format_exc()
        (root / 'report.json').write_text(json.dumps(report, indent=2) + '\n')

    deferred = root / 'deferred-fixture'
    finite = root / 'finite-fixture'
    conventions = root / 'conventions-fixture'
    recursive = root / 'recursive-fixture'
    queries = root / 'query-fixture'
    whole = root / 'whole-fixture'
    case('build-whole', lambda: run_script('build_whole_calls_formals.py', '--out', whole,
                                          '--cc', tool('clang'), '--ld', tool('ld.lld')))
    case('build-deferred', lambda: run_script('build_deferred_boundaries.py', '--out', deferred))
    case('build-finite', lambda: run_script('build_finite_big_results.py', '--out', finite))
    case('build-conventions', lambda: run_script('build_nondefault_direct.py', '--out', conventions))
    case('build-recursive', lambda: run_script('build_recursive_reference.py', '--out', recursive))
    case('build-query-helpers', lambda: run_script('build_recursive_query_roots.py', '--out', queries))
    case('whole-direct', lambda: run_script('whole_calls.py', '--cli', native, '--out', root / 'whole-direct'))
    for mode in ['serial', 'stream', 'jobs2']:
        case('whole-' + mode, lambda mode=mode: run_script(
            'whole_calls_workers.py', '--cli', native, '--binary', whole / 'whole_calls_formals.elf',
            '--mode', mode, '--out', root / ('whole-' + mode)))

    def deferred_publication():
        binary = deferred / 'deferred.elf'
        symbols = subprocess.run([tool('llvm-nm'), '--defined-only', str(binary)],
                                 check=True, capture_output=True, text=True).stdout
        slots = [int(line.split()[0], 16) for line in symbols.splitlines()
                 if len(line.split()) == 3 and line.split()[2] == 'scalar_slot']
        assert len(slots) == 1, symbols
        run_script('deferred_publication.py', '--binary', binary, '--cli', native,
                   '--sha256', sha256(native), '--slot-address', hex(slots[0]),
                   '--out', root / 'deferred-publication')

    case('deferred-machine', lambda: run_script('deferred_machine.py', '--binary', deferred / 'deferred.elf',
                                               '--scope', 'entry', '--out', root / 'deferred-machine'))
    case('deferred-publication', deferred_publication)
    case('finite-machine', lambda: run_script('finite_big_machine.py', '--binary', finite / 'finite-big.elf',
                                             '--out', root / 'finite-machine'))
    case('finite-publication', lambda: run_script('finite_big_acceptance.py', '--binary', finite / 'finite-big.elf',
                                                 '--cli', native, '--sha256', sha256(native),
                                                 '--out', root / 'finite-publication'))
    for name in ['nondefault_direct_machine', 'nested_cc_machine']:
        case(name, lambda name=name: run_script(name + '.py', '--binary', conventions / 'conventions.elf',
                                               '--out', root / name))
    for phase in ['cli', 'host']:
        selected = native if phase == 'cli' else ghidra
        case('conventions-' + phase, lambda phase=phase, selected=selected: run_script(
            'nondefault_direct_acceptance.py', '--phase', phase, '--binary', conventions / 'conventions.elf',
            '--native', selected, '--sha256', sha256(selected), '--out', root / ('conventions-' + phase)))
    case('nested-conventions', lambda: run_script(
        'nondefault_direct_acceptance.py', '--phase', 'cli', '--nested', '--binary', conventions / 'conventions.elf',
        '--native', native, '--sha256', sha256(native), '--out', root / 'nested-conventions'))
    case('recursive-graphs', lambda: run_script(
        'recursive_mixed_returns.py', '--fixtures', recursive, '--query-helpers', queries,
        '--cli', native, '--cli-sha256', sha256(native), '--ghidra-exe', ghidra,
        '--ghidra-sha256', sha256(ghidra), '--out', root / 'recursive-graphs'))
    report['completed'] = all(row['completed'] for row in report['cases'])
    (root / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report, indent=2))
    return 0 if report['completed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
