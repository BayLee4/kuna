#!/usr/bin/env python3
"""Real recursive machine bodies, source controls, and unchanged emitted C."""
import json
import subprocess
import sys
import traceback
import xml.etree.ElementTree as ET

from support import (ROOT, host, output, tool,
                     require_provider_body)
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
            row = {'case': label, 'passed': False}
            report['cases'].append(row)
            try:
                row['machine'] = []
                for name, argument, expected in vectors:
                    callback_entry = int(functions[callback].getEntryPoint().getOffset()) if callback else 0
                    actual = machine.call(int(functions[name].getEntryPoint().getOffset()), argument, callback_entry)
                    assert actual == expected, (name, argument, actual, expected)
                    row['machine'].append({'function': name, 'input': argument, 'result': actual})
                for name in names:
                    result = decompile(name)
                    calls = [op for op in result.getHighFunction().getPcodeOps()
                             if op.getOpcode() == PcodeOp.CALL]
                    targets = {int(op.getInput(0).getAddress().getOffset()) for op in calls}
                    expected = {int(functions[n].getEntryPoint().getOffset()) for n in names}
                    if name != callback:
                        assert targets & expected, (name, 'actual recursive CALL must survive', targets)
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
                    for invocation in (command, [executable]):
                        ran = subprocess.run(list(map(str, invocation)), capture_output=True,
                                             text=True, timeout=240)
                        observation = {'command': list(map(str, invocation)),
                                       'status': ran.returncode, 'stdout': ran.stdout,
                                       'stderr': ran.stderr}
                        row['commands'].append(observation)
                        assert ran.returncode == 0, observation
                row['unchanged_C_O0_O2'] = True
                row['behavioral_checks_completed'] = True
                row['passed'] = True
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
