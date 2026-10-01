#!/usr/bin/env python3
"""Build a typed-DWARF donor and inject the unchanged acceptance machine logic.

Only fixture input bytes change. No emitted C/header, oracle, or production code
is repaired. Review this script and whole_calls_formals.c before executing it.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import subprocess

from whole_calls import rel


def sha(data):
    return hashlib.sha256(data).hexdigest()


def symbols_and_sections(image):
    assert image[:6] == b'\x7fELF\x02\x01', 'expected ELF64 little-endian'
    assert struct.unpack_from('<H', image, 18)[0] == 62, 'expected x86-64'
    shoff = struct.unpack_from('<Q', image, 40)[0]
    stride, count, strings_index = struct.unpack_from('<HHH', image, 58)
    sections = [struct.unpack_from('<IIQQQQIIQQ', image, shoff + i * stride) for i in range(count)]
    strings = sections[strings_index]
    names = image[strings[4]:strings[4] + strings[5]]
    section_names = [names[s[0]:names.index(0, s[0])].decode() for s in sections]
    symbols = {}
    for table in sections:
        if table[1] != 2:
            continue
        strings = sections[table[6]]
        names = image[strings[4]:strings[4] + strings[5]]
        for pos in range(table[4], table[4] + table[5], table[9]):
            name, info, _, index, address, size = struct.unpack_from('<IBBHQQ', image, pos)
            if info & 15 != 2 or not size:
                continue
            section = sections[index]
            assert section[1] == 1 and section[2] & 4, 'function must occupy executable PROGBITS'
            offset = section[4] + address - section[3]
            assert section[4] <= offset and offset + size <= section[4] + section[5]
            spelling = names[name:names.index(0, name)].decode()
            assert spelling not in symbols
            symbols[spelling] = {'address': address, 'size': size, 'offset': offset}
    return symbols, dict(zip(section_names, sections))


def machine_bodies(symbols):
    addr = {name: data['address'] for name, data in symbols.items()}
    bodies = {}
    bodies['byte_target'] = bytes.fromhex('31c04080ff550f94c0c3')
    bodies['word_target'] = bytes.fromhex('31c083ff550f94c0c3')
    choose = bytearray.fromhex('85ff')
    for opcode, name in [('488d05', 'byte_target'), ('488d0d', 'word_target')]:
        next_pc = addr['choose'] + len(choose) + 7
        choose += bytes.fromhex(opcode) + (addr[name] - next_pc).to_bytes(4, 'little', signed=True)
    choose += bytes.fromhex('480f45c1c3')
    bodies['choose'] = bytes(choose)
    bodies['invoke'] = bytes.fromhex('ffd6c3')
    dispatch = bytes.fromhex('534889fb89f7')
    dispatch += rel(0xe8, addr['dispatch'] + len(dispatch), addr['choose'])
    dispatch += bytes.fromhex('4889c64889df5b')
    dispatch += rel(0xe9, addr['dispatch'] + len(dispatch), addr['invoke'])
    bodies['dispatch'] = dispatch
    for name, target, raw in [('direct_dirty', 'word_target', 0x10055),
                              ('direct_clean', 'word_target', 85),
                              ('ambient_dirty', 'ambient', 0x10055),
                              ('ambient_clean', 'ambient', 85)]:
        code = bytes([0xbf]) + raw.to_bytes(4, 'little')
        code += rel(0xe8, addr[name] + len(code), addr[target]) + bytes([0xc3])
        bodies[name] = code
    for name, target in [('ambient', 'word_target'), ('wide_ambient', 'ambient'),
                         ('forward', 'native_register_callback')]:
        bodies[name] = rel(0xe8, addr[name], addr[target]) + bytes([0xc3])
    bodies['bool_byte'] = bytes.fromhex('31c04080ff550f94c0c3')
    bodies['native_register_callback'] = bytes.fromhex('4889f8bf55000100ffd0c3')
    return bodies


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--cc', default='clang')
    parser.add_argument('--ld', default='ld.lld')
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=False)
    source = Path(__file__).with_name('whole_calls_formals.c').resolve()
    obj = args.out / 'whole_calls_formals.o'
    donor = args.out / 'whole_calls_formals.donor.elf'
    binary = args.out / 'whole_calls_formals.elf'
    commands = [
        [args.cc, '--target=x86_64-unknown-linux-gnu', '-O2', '-gdwarf-4',
         '-ffreestanding', '-fno-builtin', '-fno-stack-protector', '-fno-pic',
         '-fno-pie', '-c', str(source), '-o', str(obj)],
        [args.ld, '-m', 'elf_x86_64', '--image-base=0', '-Ttext=0x1000', '-e', 'choose',
         '--build-id=none', str(obj), '-o', str(donor)],
    ]
    report = {'source_sha256': sha(source.read_bytes()),
              'builder_sha256': sha(Path(__file__).read_bytes()), 'commands': []}
    for command in commands:
        result = subprocess.run(command, capture_output=True, text=True)
        report['commands'].append({'command': command, 'status': result.returncode,
                                   'stdout': result.stdout, 'stderr': result.stderr})
        assert result.returncode == 0, report['commands'][-1]
    original = donor.read_bytes()
    symbols, sections = symbols_and_sections(original)
    bodies = machine_bodies(symbols)
    assert set(symbols) == set(bodies), (set(symbols), set(bodies))
    patched = bytearray(original)
    rows = []
    for name, code in bodies.items():
        symbol = symbols[name]
        offset, size = symbol['offset'], symbol['size']
        assert len(code) <= 64 <= size
        assert bytes([0x90]) * 64 in original[offset:offset + size], name
        assert symbol['address'] + size <= 0x7000, 'fixture code must not overlap oracle stack'
        patched[offset:offset + len(code)] = code
        rows.append({'name': name, **symbol, 'machine_bytes': code.hex(),
                     'replaced_bytes': original[offset:offset + len(code)].hex()})
    for name, section in sections.items():
        if name.startswith('.debug_'):
            start, size = section[4], section[5]
            assert original[start:start + size] == patched[start:start + size], name
    binary.write_bytes(patched)
    report.update({'donor_sha256': sha(original), 'elf_sha256': sha(patched),
                   'binary': str(binary), 'functions': rows,
                   'debug_sections_byte_identical': True,
                   'limits': 'Machine behavior and source-formal import require independent validation.'})
    (args.out / 'construction.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
