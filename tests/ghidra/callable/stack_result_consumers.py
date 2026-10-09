#!/usr/bin/env python3
"""Genuine custom-stack scalar results: original machine and unchanged exported C."""
import json
import traceback

from support import emulate, execute, host, output, publish, sha256, start_ghidra
from whole_calls import Machine


def consume(out, row, kind):
    from jpype import JArray
    from ghidra.program.flatapi import FlatProgramAPI
    from ghidra.program.model.data import UnsignedLongLongDataType
    from ghidra.program.model.listing import (Function, ParameterImpl, ReturnParameterImpl,
                                            Variable, VariableStorage)
    from ghidra.program.model.pcode import Varnode
    from ghidra.program.model.symbol import SourceType

    bodies = {'complete': '48897c2410c3', 'partial': '897c2410c3',
              'unwritten': 'c3', 'wrong_offset': '48897c2418c3',
              'branch_partial': '4885ff740548897c2410c3',
              'split': '897c24104889f848c1e82089442414c3'}
    complete = kind in ('complete', 'split')
    target = bytes.fromhex(bodies[kind])
    # EntrySP+0x10 in the callee equals the caller's allocated SP+8.
    setup = bytes.fromhex('4883ec1848c744240878563412')
    finish = bytes.fromhex('488b4424084883c418c3')
    direct_call = b'\xe8' + (0x2000 - (0x1000 + len(setup) + 5)).to_bytes(4, 'little', signed=True)
    indirect_call = bytes.fromhex('488d05') + (0x2000 - (0x1100 + len(setup) + 7)).to_bytes(4, 'little', signed=True) + bytes.fromhex('ffd0')
    entries = [('target', 0x2000, target, ''),
               ('direct', 0x1000, setup + direct_call + finish, ''),
               ('indirect', 0x1100, setup + indirect_call + finish, '')]
    image = bytearray(0x1000 + len(target))
    for _, pc, code, _ in entries:
        image[pc - 0x1000:pc - 0x1000 + len(code)] = code
    row['instructions'] = [{'name': name, 'address': pc, 'bytes': code.hex()}
                           for name, pc, code, _ in entries]
    machine = Machine(image, entries)
    try:
        program = machine.program
        functions = {}
        api = FlatProgramAPI(program, machine.monitor)
        tx = program.startTransaction('Original custom stack result declaration')
        try:
            stack = program.getAddressFactory().getStackSpace()
            address = stack.getAddress(0x10)
            storage = VariableStorage(program, JArray(Varnode)([Varnode(address, 8)]))
            for name, pc, _, _ in entries:
                function = api.createFunction(machine.address(pc), name)
                assert function is not None, name
                result = ReturnParameterImpl(UnsignedLongLongDataType.dataType,
                                             storage if name == 'target' else program.getRegister('RAX'), program)
                parameter = ParameterImpl('value', UnsignedLongLongDataType.dataType,
                                          program.getRegister('RDI'), program)
                function.updateFunction('__stdcall', result, Function.FunctionUpdateType.CUSTOM_STORAGE,
                                        True, SourceType.USER_DEFINED, JArray(Variable)([parameter]))
                functions[name] = function
            installed = functions['target'].getReturn().getVariableStorage().getVarnodes()
            assert len(installed) == 1 and installed[0].getAddress() == address and installed[0].getSize() == 8
            row['custom_result'] = {'entry_stack_offset': 0x10, 'size': 8, 'storage': str(storage)}
        finally:
            program.endTransaction(tx, True)
        values = [0, 0x123456789abcdef0, 0xfedcba9876543210, 0xffffffffffffffff]
        row['machine'] = []
        for name, pc in [('direct', 0x1000), ('indirect', 0x1100)]:
            for value in values:
                actual = emulate(machine, pc, [('RDI', value)])
                expected = (value if complete or kind == 'branch_partial' and value != 0 else
                            value & 0xffffffff if kind == 'partial' else 0x12345678)
                assert actual['rax'] == expected and actual['stack_delta'] == 8, (kind, value, actual)
                row['machine'].append({'caller': name, 'value': value, 'expected': expected, **actual})
        publish(machine, functions, out, row)
        if complete:
            execute(out, row, 'int main(void){const unsigned long long values[]={0,0x123456789abcdef0ULL,0xfedcba9876543210ULL,~0ULL};'
                    'for(unsigned i=0;i<4;++i){if(target(values[i])!=values[i])return 1;'
                    'if(direct(values[i])!=values[i])return 2;if(indirect(values[i])!=values[i])return 3;}return 0;}\n')
    finally:
        machine.close()


def main():
    start_ghidra()
    from kuna_vs_stock import stock_executable
    out = output('stack-result-consumers')
    report = {'completed': False, 'native': str(host()), 'native_sha256': sha256(host()),
              'stock_native': stock_executable(), 'cases': []}
    for kind in ['complete', 'split', 'partial', 'unwritten', 'wrong_offset', 'branch_partial']:
        directory = out / kind
        directory.mkdir()
        row = {'case': kind, 'completed': False}
        report['cases'].append(row)
        try:
            consume(directory, row, kind)
            row['behavioral_checks_completed'] = True
            row['completed'] = True
        except Exception:
            row['failure'] = traceback.format_exc()
        finally:
            (directory / 'report.json').write_text(json.dumps(row, indent=2) + '\n')
            print(json.dumps({'case': kind, 'completed': row['completed'],
                              'failure': row.get('failure')}), flush=True)
    report['completed'] = all(row['completed'] for row in report['cases'])
    (out / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
    print(out, flush=True)
    return 0 if report['completed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
