#!/usr/bin/env python3
"""Run every preserved restoration boundary; a failure never hides later cases."""
import argparse
import json
from pathlib import Path
import subprocess
import sys
import traceback

from support import HERE, ROOT, cli, output


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--cli', type=Path)
    parser.add_argument('--out', type=Path)
    args = parser.parse_args()
    out = args.out.resolve() if args.out else output('restoration-boundaries')
    out.mkdir(parents=True, exist_ok=True)
    cases = [
        ('private_frame_aliases', ['--case', case])
        for case in ('branch_alias', 'partial_saved_pointer', 'partial_pointer_write',
                     'callee_partial_pointer_write', 'passed_frame', 'callback_frame',
                     'delayed_frame_escape')
    ]
    cases += [('aggregate_frame_escape', [])]
    cases += [('restoration_edges', ['--case', case])
              for case in ('saved_slot', 'branch_copy', 'custom_rbx', 'join_return')]
    cases += [('preserved_register_effect', ['--scenario', case])
              for case in ('clobbered', 'restored')]
    cases += [(name, []) for name in ('native_bool_boundary', 'mixed_flow_return')]
    report = {'completed': False, 'cases': []}
    for script, options in cases:
        name = script + ('-' + options[-1] if options else '')
        row = {'case': name, 'completed': False}
        report['cases'].append(row)
        try:
            executable = args.cli.resolve() if args.cli else cli()
            command = [sys.executable, '-u', str(HERE / (script + '.py')),
                       '--cli', str(executable), '--out', str(out / name), *options]
            row['command'] = command
            result = subprocess.run(command, cwd=ROOT, capture_output=True, text=True,
                                    timeout=2400)
            row.update(status=result.returncode, stdout=result.stdout, stderr=result.stderr)
            child = out / name / 'report.json'
            if child.is_file():
                row['report'] = json.loads(child.read_text())
            row['completed'] = result.returncode == 0 and row.get('report', {}).get('completed') is True
        except Exception:
            row['failure'] = traceback.format_exc()
        (out / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
        print(json.dumps({'case': name, 'completed': row['completed'],
                          'report': str(out / name / 'report.json')}), flush=True)
    report['completed'] = all(row['completed'] for row in report['cases'])
    (out / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({'completed': report['completed'], 'report': str(out / 'report.json')}))
    return 0 if report['completed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
