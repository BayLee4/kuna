#!/usr/bin/env python3
"""Real CLI publication and unchanged-C checks for the authentic MIPS fixtures.

Raw/final private-role negative proofs are checked by the paired opted-in Rust
matrix, not by pinning temporary engine diagnostic strings.
"""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import traceback

from support import tool

p = argparse.ArgumentParser()
p.add_argument('--cli', type=Path, required=True)
p.add_argument('--sha256', required=True)
p.add_argument('--binary', type=Path, required=True)
p.add_argument('--binary-sha256', required=True)
p.add_argument('--out', type=Path, required=True)
p.add_argument('--subjects', help='Comma-separated subset; default is all eight v4 cases')
a = p.parse_args()
cases = [('dirty_gp', [], True), ('private_gp_spill', [], True),
         ('direct_gp_parent', ['dirty_gp'], True), ('direct_gp_read_parent', ['dirty_gp'], False),
         ('private_gp_reload', [], False), ('private_gp_escape', [], False),
         ('dirty_gp_natural', [], True), ('direct_gp_natural_parent', ['dirty_gp_natural'], True)]
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
          'boundary': 'Machine behavior must be paired with the separately recorded ProtoFacts oracle for this exact binary SHA. Raw/final role evidence is checked by the paired opted-in Rust matrix. Original conditional and separately named natural children are distinct cases. Negative certificate absence does not imply whole-export refusal.'}
assert report['cli_sha256'] == a.sha256
assert report['binary_sha256'] == a.binary_sha256
assertion_names = set(selected)
for subject, providers, _ in cases:
    if subject in assertion_names:
        assertion_names.update(providers)
assertions = ['--assert-strict']
assertion_count = 0
for declaration in ['void dirty_gp(void)', 'int direct_gp_parent(void)', 'int direct_gp_read_parent(void)',
                    'int private_gp_spill(void)', 'int private_gp_reload(void)', 'void private_gp_escape(void)',
                    'void dirty_gp_natural(void)', 'int direct_gp_natural_parent(void)']:
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
        for omit in ([True, False] if positive and providers else [False]):
            label = 'omitted' if omit else 'full'
            names = [subject] + ([] if omit else providers)
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
            assert len(functions) == len(names), metadata
            subject_function = next(f for f in functions if f['name'] == subject)
            assert subject_function.get('error') is None and subject_function.get('code'), subject_function
            row[label + '_export_error'] = subject_function.get('callable_export_error')
            artifacts = [artifact for f in functions for artifact in f.get('callable_artifacts', [])]
            required = {artifact['key'] for artifact in artifacts if artifact.get('required')}
            owned = {artifact['key'] for artifact in artifacts if artifact.get('definition') is not None}
            qualified_required = {key for key in required if '_internal_' in key}
            qualified_owned = {artifact['key'] for artifact in subject_function.get('callable_artifacts', [])
                               if '_internal_' in artifact['key']
                               and (artifact.get('definition') or {}).get('kind') == 'body_proof'}
            row[label + '_qualified_owned'] = sorted(qualified_owned)
            row[label + '_qualified_required'] = sorted(qualified_required)
            project = directory / label
            result = invoke([a.cli, 'decompile-project', a.binary, '-o', project, *common])
            row[label + '_project_status'] = result['status']
            if not positive:
                # The paired real-Funcdata Rust matrix checks final GP coverage
                # and dirty-child use. Standalone leaves need not publish a
                # qualified provider, so absence alone is not a negative proof.
                row['negative_boundary'] = {
                    'whole_export_refused': result['status'] != 0,
                    'callable_export_error': subject_function.get('callable_export_error'),
                    'proof_test': ('actual_direct_child_role_cannot_hide_a_later_implicit_gp_read'
                                   if subject == 'direct_gp_read_parent' else
                                   'actual_private_spill_proof_rejects_reload_and_pointer_escape'),
                }
                continue
            assert all(f.get('error') is None and f.get('callable_export_error') is None for f in functions), metadata
            if omit:
                assert qualified_required and qualified_required - owned and result['status'] != 0, result
                row['omitted_provider_refused'] = {'missing': providers, 'unowned_qualified_keys': sorted(qualified_required - owned)}
                continue
            assert result['status'] == 0, result
            if providers:
                provider = next(f for f in functions if f['name'] == providers[0])
                receipts = [artifact for artifact in provider.get('callable_artifacts', [])
                            if artifact['key'] in qualified_required
                            and (artifact.get('definition') or {}).get('kind') == 'body_proof']
                assert qualified_required and receipts and qualified_required <= owned, metadata
                row['actual_child_qualified_receipts'] = receipts
            stem = a.binary.name
            header = project / (stem + '.h')
            body = project / (stem + '.c')
            row['emitted_sha256'] = {path.name: sha(path) for path in [header, body]}
            check = subject + '(); return 0;' if subject in {'dirty_gp', 'dirty_gp_natural'} else 'return ' + subject + '() != 11;'
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
