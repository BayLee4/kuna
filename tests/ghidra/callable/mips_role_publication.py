#!/usr/bin/env python3
"""Actual CLI export providers and unchanged C for authentic MIPS fixtures."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import traceback

from support import tool, require_provider_body

p = argparse.ArgumentParser()
p.add_argument('--cli', type=Path, required=True)
p.add_argument('--sha256', required=True)
p.add_argument('--binary', type=Path, required=True)
p.add_argument('--binary-sha256', required=True)
p.add_argument('--out', type=Path, required=True)
p.add_argument('--subjects', help='Comma-separated subset; default is all three public consumers')
a = p.parse_args()
cases = [('dirty_gp', [], True), ('private_gp_spill', [], True),
         ('direct_gp_parent', ['dirty_gp'], True)]
selected = a.subjects.split(',') if a.subjects is not None else [case[0] for case in cases]
unknown = set(selected) - {case[0] for case in cases}
if unknown:
    p.error('Unknown subjects: ' + ','.join(sorted(unknown)))
a.cli = a.cli.resolve()
a.binary = a.binary.resolve()
a.out = a.out.resolve()
a.out.mkdir(parents=True, exist_ok=False)
sha = lambda path: hashlib.sha256(path.read_bytes()).hexdigest()
report = {'completed': False, 'cli_sha256': sha(a.cli), 'binary_sha256': sha(a.binary), 'cases': [],
          'selected_subjects': selected,
          'boundary': 'Three genuine machine scopes are separate from export execution. Raw/final GP effects are checked by verify_mips_internal_roles, not inferred from publication. Negative private-role observations remain genuine machine and Engine guards, not project-refusal probes.'}
assert report['cli_sha256'] == a.sha256
assert report['binary_sha256'] == a.binary_sha256
assertion_names = set(selected)
for subject, providers, _ in cases:
    if subject in assertion_names:
        assertion_names.update(providers)
assertions = ['--assert-strict']
assertion_count = 0
for declaration in ['void dirty_gp(void)', 'int direct_gp_parent(void)', 'int direct_gp_read_parent(void)',
                    'int private_gp_spill(void)']:
    name = declaration.split('(')[0].split()[-1]
    if name in assertion_names:
        assertions += ['--assert', 'prototype ' + name + ' ' + declaration]
        assertion_count += 1
compiler = tool('cc')

for subject, providers, positive in cases:
    if subject not in selected:
        continue
    directory = a.out / subject
    directory.mkdir()
    row = {'subject': subject, 'positive_internal_body': positive, 'completed': False, 'commands': []}
    report['cases'].append(row)

    def invoke(command):
        command = list(map(str, command))
        process = subprocess.run(command, cwd=directory, capture_output=True, text=True, timeout=240)
        result = {'command': command, 'status': process.returncode, 'stdout': process.stdout, 'stderr': process.stderr}
        row['commands'].append(result)
        return result

    try:
        names = [subject] + providers
        label = 'full'
        common = ['--functions', ','.join(names), '--language', 'c', '--option', 'structdefs', 'on', *assertions]
        result = invoke([a.cli, 'decompile-all', a.binary, '--json', *common])
        assert result['status'] == 0, result
        metadata = json.loads(result['stdout'])
        (directory / (label + '-metadata.json')).write_text(json.dumps(metadata, indent=2) + '\n')
        source_assertions = [item for item in metadata.get('assertions', [])
                             if item.get('directive', '').startswith('prototype ')]
        assert len(source_assertions) == assertion_count and all(item.get('status') == 'applied'
                                                                 for item in source_assertions), metadata.get('assertions')
        functions = metadata['functions']
        assert {f['name'] for f in functions} == set(names), metadata
        subject_function = next(f for f in functions if f['name'] == subject)
        assert subject_function.get('error') is None, subject_function
        project = directory / label
        result = invoke([a.cli, 'decompile-project', a.binary, '-o', project, *common])
        assert result['status'] == 0, result
        stem = a.binary.name
        header = project / (stem + '.h')
        body = project / (stem + '.c')
        for name in names:
            require_provider_body(body, name)
        row['emitted_sha256'] = {path.name: sha(path) for path in [header, body]}
        check = subject + '(); return 0;' if subject == 'dirty_gp' else 'return ' + subject + '() != 11;'
        consumer = directory / 'consumer.c'
        consumer.write_text('#include "' + stem + '.h"\nint main(void) { ' + check + ' }\n')
        for optimization in ['-O0', '-O2']:
            executable = directory / ('consumer' + optimization)
            result = invoke([compiler, '-std=c11', '-Wall', '-Wextra', '-Werror=uninitialized',
                             '-Werror=incompatible-pointer-types', '-Werror=implicit-function-declaration',
                             optimization, '-I', project, body, consumer, '-o', executable])
            assert result['status'] == 0, result
            result = invoke([executable])
            assert result['status'] == 0, result
        row['unchanged_C_passed'] = True
        row['behavioral_checks_completed'] = True
        row['completed'] = True
    except BaseException:
        row['failure'] = traceback.format_exc()
    finally:
        (directory / 'report.json').write_text(json.dumps(row, indent=2) + '\n')
        print(json.dumps({'subject': subject, 'completed': row['completed'], 'failure': row.get('failure')}), flush=True)
report['completed'] = all(row['completed'] for row in report['cases'])
(a.out / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
if not report['completed']:
    raise SystemExit(1)
