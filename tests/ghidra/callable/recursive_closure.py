#!/usr/bin/env python3
"""Real recursive machine bodies, source controls, and unchanged emitted C."""
import json
import subprocess
import sys
import traceback
import xml.etree.ElementTree as ET

from support import (ROOT, cli, host, output, tool,
                     require_provider_body, require_absent_provider_body, snapshot)
from whole_calls import Machine, rel

sys.path.insert(0, str(ROOT / 'tests/ghidra'))
from kuna_vs_stock import export_program, selected_core


def recursive_body(pc, target, base):
    # test edi,edi; je base; sub edi,1; sub rsp,8; call target;
    # add rsp,8; ret; base: mov eax,base; ret
    prefix = bytes.fromhex('85ff741183ef014883ec08')
    return (prefix + rel(0xe8, pc + len(prefix), target)
            + bytes.fromhex('4883c408c3b8') + base.to_bytes(4, 'little') + b'\xc3')


def fixtures():
    entries = [
        ('even', 0x1000, recursive_body(0x1000, 0x1040, 1)),
        ('odd', 0x1040, recursive_body(0x1040, 0x1000, 0)),
    ]
    prefix = bytes.fromhex('85ff741383ef014883ec08')
    unknown = (prefix + rel(0xe8, 0x1100 + len(prefix), 0x1100)
               + bytes.fromhex('ffd04883c408c331c0c3'))
    entries.append(('unknown_cycle', 0x1100, unknown))
    prefix = bytes.fromhex('4883ec08')
    entries.append(('ungrounded', 0x1180, prefix + rel(0xe8, 0x1184, 0x1180)
                    + bytes.fromhex('4883c408c3')))
    prefix = bytes.fromhex('85ff741183ef014883ec08')
    blocked = (prefix + rel(0xe8, 0x1200 + len(prefix), 0x1200)
               + bytes.fromhex('4883c408c34883ec08'))
    blocked += rel(0xe8, 0x1200 + len(blocked), 0x1280)
    blocked += bytes.fromhex('4883c408b801000000c3')
    entries.extend([('blocked_cycle', 0x1200, blocked), ('never_returns', 0x1280, bytes.fromhex('ebfe'))])
    prefix = bytes.fromhex('85ff741183ef014883ec08')
    observed = (prefix + rel(0xe8, 0x1300 + len(prefix), 0x1300)
                + bytes.fromhex('4883c408c389e0c3'))
    entries.append(('stack_observed', 0x1300, observed))
    entries.append(('ordered_base', 0x1340, recursive_body(0x1340, 0x1380, 1)))
    ordered = bytes.fromhex('4883ec08') + rel(0xe8, 0x1384, 0x1380)
    ordered += bytes.fromhex('89c7') + rel(0xe8, 0x138b, 0x1340)
    entries.append(('ordered_blocked', 0x1380, ordered + bytes.fromhex('4883c408c3')))
    for name, pc, target in [('native_even', 0x1400, 0x1440), ('native_odd', 0x1440, 0x1400)]:
        prefix = bytes.fromhex('85ff741183ef014883ec08')
        code = prefix + rel(0xe8, pc + len(prefix), target) + bytes.fromhex('4883c408c3')
        code += bytes.fromhex('4889f0bf050000004883ec08ffd04883c408c3')
        entries.append((name, pc, code))
    entries.append(('native_leaf', 0x1480, bytes.fromhex('8d443f01c3')))
    image = bytearray(0x500)
    for _, pc, code in entries:
        image[pc - 0x1000:pc - 0x1000 + len(code)] = code
    return bytes(image), entries


def main():
    out = output('recursive-closure')
    report = {'completed': False, 'cases': []}
    image, entries = fixtures()
    machine = Machine(image, [(name, pc, code, '') for name, pc, code in entries])
    from jpype import JArray, JByte
    from ghidra.app.decompiler import DecompInterface, DecompileOptions
    from ghidra.program.model.address import AddressSet
    from ghidra.program.flatapi import FlatProgramAPI
    from ghidra.program.model.data import (IntegerDataType, FunctionDefinitionDataType,
                                          ParameterDefinitionImpl, PointerDataType)
    from ghidra.program.model.listing import Function, ParameterImpl, ReturnParameterImpl, Variable
    from ghidra.program.model.pcode import PcodeOp
    from ghidra.program.model.symbol import SourceType

    program = machine.program
    api = FlatProgramAPI(program, machine.monitor)
    functions = {}
    tx = program.startTransaction('actual recursive functions and source declarations')
    try:
        integer = IntegerDataType.dataType
        callback = FunctionDefinitionDataType('RecursiveCallback')
        callback.setReturnType(integer)
        callback.setArguments([ParameterDefinitionImpl('value', integer, '')])
        callback = PointerDataType(callback)
        for name, pc, _ in entries:
            fn = api.createFunction(machine.address(pc), name)
            assert fn is not None, name
            parameters = [ParameterImpl('n', integer, program)]
            if name in ('native_even', 'native_odd'):
                parameters.append(ParameterImpl('callback', callback, program))
            fn.updateFunction('__stdcall', ReturnParameterImpl(integer, program),
                              Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS, False,
                              SourceType.USER_DEFINED,
                              JArray(Variable)(parameters))
            fn.setNoReturn(False)
            functions[name] = fn
        original = ROOT / 'tests/datatests/inline.xml'
        code = bytes.fromhex(ET.parse(original).getroot().find('binaryimage/bytechunk').text)
        block = api.createMemoryBlock('collatz_code', machine.address(0x100000), JArray(JByte)(code), False)
        block.setExecute(True)
        # Preserve the existing fixture's exact bytes, declarations, and inline flags.
        for pc, name, parameters in [(0x10004c, 'collatz1', ('a', 'b')),
                                     (0x10006d, 'collatz', ('val',))]:
            assert api.disassemble(machine.address(pc))
            fn = api.createFunction(machine.address(pc), name)
            assert fn is not None
            fn.updateFunction('__stdcall', ReturnParameterImpl(integer, program),
                              Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS, False,
                              SourceType.USER_DEFINED,
                              JArray(Variable)([ParameterImpl(p, integer, program) for p in parameters]))
            fn.setInline(True)
            functions[name] = fn
    finally:
        program.endTransaction(tx, True)
    binary = out / 'recursive-machine'
    binary.write_bytes(image)
    common = ['--raw-image', '--target', 'x86:LE:64:default:gcc',
              '--base', '0x1000', '--sleighpath', ROOT / 'specs', '--assert-strict',
              '--assert', 'typedef typedef int (*RecursiveCallback)(int value);']
    for name, pc, code in entries:
        parameters = 'int n,RecursiveCallback callback' if name in ('native_even', 'native_odd') else 'int n'
        common += ['--define-function', f'{pc:#x}-{pc+len(code):#x}={name}',
                   '--assert', f'prototype {name} int __stdcall {name}({parameters})']

    def observe_project_boundary(row, label, names, omitted=None):
        selection = []
        for name in names:
            selection += ['--addr', hex(int(functions[name].getEntryPoint().getOffset()))]
        diagnostic_command = [cli(), 'decompile-all', binary, '--json', *common, *selection]
        diagnostic = subprocess.run(list(map(str, diagnostic_command)), capture_output=True,
                                    text=True, timeout=240)
        assert diagnostic.returncode == 0, diagnostic.stderr
        metadata = json.loads(diagnostic.stdout)
        assert len(metadata['functions']) == len(names)
        assert {function['name'] for function in metadata['functions']} == set(names), metadata
        (out / (label + '-metadata.json')).write_text(json.dumps(metadata, indent=2) + '\n')
        command = [cli(), 'decompile-project', binary, '-o', out / (label + '-project'),
                   *common, *selection]
        result = subprocess.run(list(map(str, command)), capture_output=True, text=True, timeout=240)
        observation = {'command': list(map(str, command)), 'status': result.returncode,
                       'stdout': result.stdout, 'stderr': result.stderr,
                       'diagnostic_command': list(map(str, diagnostic_command)),
                       'diagnostic_status': diagnostic.returncode}
        row.setdefault('projects', []).append(observation)
        assert result.returncode == 0, observation
        body = out / (label + '-project') / (binary.name + '.c')
        for name in names:
            require_provider_body(body, name)
        if omitted is not None:
            require_absent_provider_body(body, omitted)

    core = selected_core(host())
    core.__enter__()
    interface = DecompInterface()
    interface.setOptions(DecompileOptions())
    try:
        assert interface.openProgram(program), str(interface.getLastMessage())

        def decompile(name):
            result = interface.decompileFunction(functions[name], 30, machine.monitor)
            assert result.decompileCompleted(), (name, str(result.getErrorMessage()))
            return result

        def positive(label, names, vectors, driver, callback=None):
            row = {'case': label, 'passed': False, 'failures': []}
            report['cases'].append(row)
            try:
                before = snapshot({name: functions[name] for name in names})
                row['machine'] = []
                for name, argument, expected in vectors:
                    callback_entry = int(functions[callback].getEntryPoint().getOffset()) if callback else 0
                    actual = machine.call(int(functions[name].getEntryPoint().getOffset()), argument, callback_entry)
                    assert actual == expected, (name, argument, actual, expected)
                    row['machine'].append({'function': name, 'input': argument, 'result': actual})
                for name in names:
                    try:
                        result = decompile(name)
                        calls = [op for op in result.getHighFunction().getPcodeOps()
                                 if op.getOpcode() == PcodeOp.CALL]
                        targets = {int(op.getInput(0).getAddress().getOffset()) for op in calls}
                        expected = {int(functions[n].getEntryPoint().getOffset()) for n in names}
                        if name != callback:
                            assert targets & expected, (name, 'actual recursive CALL must survive', targets)
                    except Exception:
                        row['failures'].append({'stage': 'recursive-call', 'function': name,
                                                'failure': traceback.format_exc()})
                if len(names) > 1:
                    row['omitted_provider_entry'] = int(functions[names[1]].getEntryPoint().getOffset())
                    try:
                        observe_project_boundary(row, label + '-omitted', [names[0], *names[2:]], names[1])
                    except Exception:
                        row['failures'].append({'stage': 'partial-selection',
                                                'failure': traceback.format_exc()})
                selection = AddressSet()
                for name in names:
                    selection.add(functions[name].getBody())
                body = out / (label + '.c')
                header = body.with_suffix('.h')
                assert export_program(program, body, machine.monitor, selection), label
                for name in names:
                    require_provider_body(body, name)
                consumer = out / (label + '-driver.c')
                consumer.write_text('#include "' + header.name + '"\n' + driver)
                row['commands'] = []
                for optimization in ('-O0', '-O2'):
                    executable = out / (label + optimization)
                    command = [tool('cc'), '-std=c11', optimization, '-Wall',
                               '-Werror=uninitialized', '-Werror=incompatible-pointer-types',
                               '-Werror=implicit-function-declaration',
                               body, consumer, '-o', executable]
                    try:
                        for invocation in (command, [executable]):
                            ran = subprocess.run(list(map(str, invocation)), capture_output=True,
                                                 text=True, timeout=240)
                            observation = {'command': list(map(str, invocation)),
                                           'status': ran.returncode, 'stdout': ran.stdout,
                                           'stderr': ran.stderr}
                            row['commands'].append(observation)
                            assert ran.returncode == 0, observation
                    except Exception:
                        row['failures'].append({'stage': 'unchanged-C' + optimization,
                                                'failure': traceback.format_exc()})
                row['unchanged_C_O0_O2'] = not any(
                    failure['stage'].startswith('unchanged-C') for failure in row['failures'])
                assert snapshot({name: functions[name] for name in names}) == before
                row['behavioral_checks_completed'] = True
                row['passed'] = not row['failures']
            except Exception:
                row['failure'] = traceback.format_exc()
            print(json.dumps(row), flush=True)

        positive('collatz', ['collatz'], [('collatz', n, 1) for n in (1, 2, 7, 27)],
                 'int main(void){return collatz(1)!=1 || collatz(2)!=1 || collatz(7)!=1 || collatz(27)!=1;}\n')
        positive('mutual', ['even', 'odd'],
                 [(name, n, int(n % 2 == parity)) for n in (0, 1, 2, 7, 20)
                  for name, parity in [('even', 0), ('odd', 1)]],
                 'int main(void){for(int n=0;n<21;++n)if(even(n)!=(n%2==0)||odd(n)!=(n%2==1))return 1;return 0;}\n')
        positive('conditional_mutual', ['native_even', 'native_odd', 'native_leaf'],
                 [(name, n, 11) for n in (0, 1, 2, 7, 20) for name in ('native_even', 'native_odd')],
                 'int main(void){for(int n=0;n<21;++n)if(native_even(n,native_leaf)!=11||native_odd(n,native_leaf)!=11)return 1;return 0;}\n',
                 callback='native_leaf')
        for name in ('unknown_cycle', 'ungrounded', 'blocked_cycle', 'stack_observed', 'ordered_base'):
            row = {'case': name, 'passed': False}
            report['cases'].append(row)
            try:
                observe_project_boundary(row, name, [name])
            except Exception:
                row['negative_project_failure'] = traceback.format_exc()
            try:
                before = snapshot({name: functions[name]})
                if name == 'stack_observed':
                    assert machine.call(0x1300, 0) == 0x7fe0
                    row['observed_machine_stack'] = 0x7fe0
                if name == 'ordered_base':
                    assert machine.call(0x1340, 0) == 1
                    row['grounded_member_base_result'] = 1
                if name == 'unknown_cycle':
                    instructions = program.getListing().getInstructions(functions[name].getBody(), True)
                    assert any(op.getOpcode() == PcodeOp.CALLIND
                               for instruction in instructions for op in instruction.getPcode()), \
                        'the actual unknown member CALLIND must remain in the fixture'
                result = decompile(name)
                high = result.getHighFunction()
                assert high is not None and result.getCCodeMarkup() is not None
                assert result.getDecompiledFunction() is not None
                prototype = high.getFunctionPrototype()
                function = functions[name]
                assert prototype.getNumParams() == function.getParameterCount()
                assert prototype.getReturnType().isEquivalent(function.getReturnType())
                for index, parameter in enumerate(function.getParameters()):
                    recovered = prototype.getParam(index)
                    assert recovered.getName() == parameter.getName()
                    assert recovered.getDataType().isEquivalent(parameter.getDataType())
                    assert recovered.getStorage() == parameter.getVariableStorage()
                target_name = 'ordered_blocked' if name == 'ordered_base' else name
                calls = [operation for operation in high.getPcodeOps()
                         if operation.getOpcode() == PcodeOp.CALL]
                assert any(operation.getInput(0).getAddress() == functions[target_name].getEntryPoint()
                           for operation in calls), (name, [str(operation) for operation in calls])
                if name == 'blocked_cycle':
                    assert any(operation.getInput(0).getAddress() == functions['never_returns'].getEntryPoint()
                               for operation in calls), [str(operation) for operation in calls]
                row['c'] = str(result.getDecompiledFunction().getC())
                row['high'] = str(high)
                row['source'] = snapshot({name: functions[name]})
                assert row['source'] == before
                (out / (name + '-diagnostic.c')).write_text(row['c'])
                row['consumer'] = 'Ordinary source/High/markup and original raw/machine boundary; not complete-unit certification'
                row['passed'] = 'negative_project_failure' not in row
            except Exception:
                row['failure'] = traceback.format_exc()
            print(json.dumps(row), flush=True)
        report['completed'] = all(row['passed'] for row in report['cases'])
    finally:
        interface.dispose()
        core.__exit__(None, None, None)
        machine.close()
        (out / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
        print(out / 'report.json', flush=True)
    if not report['completed']:
        raise SystemExit(1)


if __name__ == '__main__':
    main()
