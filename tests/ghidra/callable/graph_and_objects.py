#!/usr/bin/env python3
"""Build authentic fixtures and run their public machine/object/export consumers."""
import json
import subprocess
import traceback
from support import cli, output, run_script, sha256, tool


def main():
    root = output('graph-and-objects')
    report = {'completed': False, 'output': str(root), 'cases': []}

    def case(name, action):
        row = {'name': name, 'completed': False}
        report['cases'].append(row)
        try:
            action()
            row['completed'] = True
        except Exception:
            row['failure'] = traceback.format_exc()
        (root / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
        print(json.dumps(row), flush=True)

    nested = root / 'nested-fixture'
    hidden = root / 'hidden-fixture'
    named = root / 'named-fixture'
    private = root / 'private-fixture'
    for name, builder, destination in [
        ('nested', 'build_nested_default_binding.py', nested),
        ('hidden', 'build_hidden_boundaries.py', hidden),
        ('named', 'build_named_global_control.py', named),
        ('private', 'build_private_leaf_formals.py', private),
    ]:
        case('build-' + name, lambda builder=builder, destination=destination:
             run_script(builder, '--out', destination))

    case('nested-original-machine', lambda: run_script(
        'nested_default_binding.py', '--binary', nested / 'nested.elf',
        '--out', root / 'nested-machine'))

    case('hidden-machine-and-emitted-provider', lambda: run_script(
        'hidden_boundaries.py', '--binary', hidden / 'hidden.elf', '--cli', cli(),
        '--sha256', sha256(cli()), '--out', root / 'hidden-boundaries'))

    case('mutable-hidden-callback', lambda: run_script(
        'mutable_hidden_callback.py', '--binary', hidden / 'hidden.elf', '--cli', cli(),
        '--out', root / 'mutable-hidden-callback'))

    case('private-spill-result', lambda: run_script(
        'private_spill_result.py', '--binary', hidden / 'hidden.elf', '--cli', cli(),
        '--out', root / 'private-spill-result'))

    case('selected-child-pointer-provider', lambda: run_script(
        'hidden_selected_child.py', '--binary', hidden / 'hidden.elf', '--cli', cli(),
        '--sha256', sha256(cli()), '--out', root / 'selected-child-record'))

    def named_phase(phase):
        binary = named / 'named.elf'
        symbols = subprocess.run([tool('llvm-nm'), '--defined-only', str(binary)],
                                 capture_output=True, text=True, check=True).stdout
        addresses = [int(parts[0], 16) for line in symbols.splitlines()
                     if len(parts := line.split()) == 3 and parts[2] == 'state']
        assert len(addresses) == 1, symbols
        native_args = [] if phase == 'machine' else ['--cli', cli(), '--sha256', sha256(cli())]
        run_script('named_global_acceptance.py', '--binary', binary,
                   '--state-address', hex(addresses[0]), '--phase', phase,
                   '--out', root / ('named-' + phase), *native_args)

    for phase in ['machine', 'export']:
        case('named-' + phase, lambda phase=phase: named_phase(phase))

    case('private-leaf-machine-and-three-publication-modes', lambda: run_script(
        'private_leaf_identity.py', '--binary', private / 'private_leaf_formals.elf',
        '--cli', cli(), '--out', root / 'private-leaf'))
    report['completed'] = all(row['completed'] for row in report['cases'])
    (root / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report, indent=2))
    return 0 if report['completed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
