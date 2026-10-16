#!/usr/bin/env python3
"""Meet ordinary stack-pop and explicit FlowReturn exits independently."""
import argparse
import hashlib
import json
from pathlib import Path
from support import ROOT, cli as default_cli, output, tool, require_provider_body
import subprocess
import traceback
from whole_calls import Machine

parser = argparse.ArgumentParser()
parser.add_argument('--out', type=Path)
parser.add_argument('--cli', type=Path)
args = parser.parse_args()
args.cli = (args.cli or default_cli()).resolve(); args.out = (args.out or output("mixed_flow_return")/"run").resolve()
args.out.mkdir(parents=True, exist_ok=False)
report = {'cli_sha256': hashlib.sha256(args.cli.read_bytes()).hexdigest(), 'completed': False, 'cases': [], 'scope': 'Genuine conditional ordinary RET and explicit CALL_RETURN, with malformed ordinary RET8 negative. Actual original machine and unchanged generated whole-project C/H only.'}
for case in ['balanced', 'malformed_ordinary_pop']:
    out = args.out/case
    out.mkdir()
    subject = bytes.fromhex('85ff740889f7e8f5000000c38d4603' + ('c3' if case == 'balanced' else 'c20800'))
    target = bytes.fromhex('8d470ac3')
    entries = [('subject', 0x1000, subject, 'int subject(unsigned int choice,int value)'), ('target', 0x1100, target, 'int target(int value)')]
    image = bytearray(0x104)
    image[:len(subject)] = subject
    image[0x100:] = target
    binary = out/'mixed_flow_return'
    binary.write_bytes(image)
    row = {'case': case, 'completed': False, 'subject_bytes': subject.hex(), 'target_bytes': target.hex(), 'override': {'address': 0x1006, 'kind': 'CALL_RETURN'}, 'commands': []}
    report['cases'].append(row)
    def invoke(command):
        command = list(map(str, command))
        p = subprocess.run(command, cwd='/tmp', capture_output=True, text=True, timeout=240)
        result = {'command': command, 'status': p.returncode, 'stdout': p.stdout, 'stderr': p.stderr}
        row['commands'].append(result)
        return result
    try:
        machine = Machine(image, entries)
        try:
            from jpype import JArray, JByte
            from ghidra.program.flatapi import FlatProgramAPI
            from ghidra.program.model.data import IntegerDataType, UnsignedIntegerDataType
            from ghidra.program.model.listing import Function, ParameterImpl, ReturnParameterImpl, Variable, FlowOverride
            from ghidra.program.model.symbol import SourceType
            program = machine.program
            api = FlatProgramAPI(program, machine.monitor)
            integer, unsigned = IntegerDataType.dataType, UnsignedIntegerDataType.dataType
            row['source'] = []
            tx = program.startTransaction('genuine source declarations and explicit call-return override')
            try:
                for name, pc, _, _ in entries:
                    fn = api.createFunction(machine.address(pc), name)
                    assert fn is not None
                    params = [ParameterImpl('choice', unsigned, program), ParameterImpl('value', integer, program)] if name == 'subject' else [ParameterImpl('value', integer, program)]
                    fn.updateFunction('__stdcall', ReturnParameterImpl(integer, program), Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS, False, SourceType.USER_DEFINED, JArray(Variable)(params))
                    assert [str(p.getVariableStorage()) for p in fn.getParameters()] == (['EDI:4', 'ESI:4'] if name == 'subject' else ['EDI:4'])
                    row['source'].append({'name': name, 'signature': str(fn.getSignature()), 'source_stack_pop': int(fn.getStackPurgeSize()), 'parameters': [(str(p.getName()), str(p.getVariableStorage())) for p in fn.getParameters()]})
                instruction = program.getListing().getInstructionAt(machine.address(0x1006))
                assert str(instruction.getMnemonicString()).upper() == 'CALL'
                instruction.setFlowOverride(FlowOverride.CALL_RETURN)
            finally:
                program.endTransaction(tx, True)
            row['original_machine'] = []
            for choice in [0, 1, 0xffffffff]:
                for value in [-7, 0, 5, 1234]:
                    emulator = machine.EmulatorHelper(program)
                    try:
                        for register, val in [('RDI', choice), ('RSI', value & 0xffffffff), ('RSP', 0x7fe0)]:
                            emulator.writeRegister(register, val)
                        emulator.writeMemory(machine.address(0x7fe0), JArray(JByte)((0x7ff0).to_bytes(8, 'little')))
                        emulator.setBreakpoint(machine.address(0x7ff0))
                        assert emulator.run(machine.address(0x1000), None, machine.monitor), str(emulator.getLastError())
                        assert emulator.getExecutionAddress() == machine.address(0x7ff0)
                        actual = int(str(emulator.readRegister('RAX'))) & 0xffffffff
                        wanted = (value + (3 if choice == 0 else 10)) & 0xffffffff
                        delta = int(str(emulator.readRegister('RSP'))) - 0x7fe0
                        expected_delta = 16 if case == 'malformed_ordinary_pop' and choice == 0 else 8
                        assert actual == wanted and delta == expected_delta, (choice, value, actual, wanted, delta, expected_delta)
                        row['original_machine'].append({'choice': choice, 'value': value, 'result_u32': actual, 'final_stack_delta': delta})
                    finally:
                        emulator.dispose()
        finally:
            machine.close()
        row['oracle_note'] = 'Ghidra emulator runs original CALL/RET instructions even with source FlowOverride. Here CALL_RETURN only removes a following plain RET, so results match authorized transformed C. Final machine SP is observed, not substituted from source prototype.'
        common = ['--raw-image', '--target', 'x86:LE:64:default:gcc', '--base', '0x1000', '--sleighpath', ROOT/'specs', '--assert-strict', '--assert', 'flow subject::0x1006 callreturn']
        for name, pc, code, prototype in entries:
            common += ['--addr', hex(pc), '--define-function', f'{pc:#x}-{pc+len(code):#x}={name}', '--assert', 'prototype '+name+' '+prototype]
        meta = invoke([args.cli, 'decompile-all', binary, '--json', *common])
        assert meta['status'] == 0, meta
        metadata = json.loads(meta['stdout'])
        (out/'metadata.json').write_text(json.dumps(metadata, indent=2)+'\n')
        byname = {f['name']: f for f in metadata['functions']}
        assert len(metadata['functions']) == len(entries) and set(byname) == {entry[0] for entry in entries}, metadata
        assert all(f.get('error') is None and f.get('code') for f in byname.values()), metadata
        for name, wanted in [('subject', [('choice', 4, 0), ('value', 4, 1)]), ('target', [('value', 4, 0)])]:
            params = sorted((v for v in byname[name]['variables'] if v['kind'] == 'arg'), key=lambda p: p['arg_index'])
            assert [(p['name'], p['size'], p['arg_index']) for p in params] == wanted, params
        project = out/'project'
        export = invoke([args.cli, 'decompile-project', binary, '-o', project, *common])
        if case == 'malformed_ordinary_pop':
            row['executable_extension_contract'] = 'EX10/EX12 historical refusal remains prerequisite-unrepresented; ordinary export status is not executable certification'
            row['behavioral_checks_completed'] = True
            row['completed'] = True
            continue
        assert export['status'] == 0, export
        for provider, _, _, _ in entries:
            require_provider_body(project/'mixed_flow_return.c', provider)
        row['emitted_sha256'] = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in [project/'mixed_flow_return.c', project/'mixed_flow_return.h']}
        consumer = out/'consumer.c'
        consumer.write_text('#include "mixed_flow_return.h"\n#include <stdint.h>\nint main(void){const unsigned choices[]={0,1,UINT32_MAX};const int values[]={-7,0,5,1234};for(unsigned i=0;i<3;++i)for(unsigned j=0;j<4;++j){int want=values[j]+(choices[i]?10:3);if(subject(choices[i],values[j])!=want)return 1;}return 0;}\n')
        for opt in ['-O0', '-O2']:
            executable = out/('consumer'+opt)
            built = invoke([tool('cc'), '-std=c11', '-Wall', '-Wextra', '-Werror=uninitialized', '-Werror=incompatible-pointer-types', '-Werror=implicit-function-declaration', opt, '-I', project, project/'mixed_flow_return.c', consumer, '-o', executable])
            assert built['status'] == 0, built
            ran = invoke([executable])
            assert ran['status'] == 0, ran
        row['behavioral_checks_completed'] = True
        row['completed'] = True
    except BaseException:
        row['failure'] = traceback.format_exc()
    finally:
        (out/'report.json').write_text(json.dumps(row, indent=2)+'\n')
        print(json.dumps({'case': case, 'completed': row['completed'], 'failure': row.get('failure')}), flush=True)
report['completed'] = all(row['completed'] for row in report['cases'])
(args.out/'report.json').write_text(json.dumps(report, indent=2)+'\n')
if not report['completed']:
    raise SystemExit(1)
