#!/usr/bin/env python3
"""Build the original i386 stdcall/fastcall fixture, without running production builds."""
import argparse
import json
import subprocess
from pathlib import Path
from support import tool, sha256


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=False)
    source = Path(__file__).parent / 'fixtures/nested_default_binding.s'
    obj = args.out / 'nested.o'
    binary = args.out / 'nested.elf'
    report = {'completed': False, 'source_sha256': sha256(source), 'commands': []}
    try:
        for command in [
            [tool('clang'), '--target=i386-unknown-linux-gnu', '-c', str(source), '-o', str(obj)],
            [tool('ld.lld'), '-m', 'elf_i386', '--image-base=0', '-Ttext=0x1000',
             '-e', 'call_old', '--build-id=none', str(obj), '-o', str(binary)],
        ]:
            result = subprocess.run(command, capture_output=True, text=True, timeout=120)
            row = {'command': command, 'status': result.returncode,
                   'stdout': result.stdout, 'stderr': result.stderr}
            report['commands'].append(row)
            assert result.returncode == 0, row
        report['binary_sha256'] = sha256(binary)
        report['completed'] = True
    finally:
        (args.out / 'construction.json').write_text(json.dumps(report, indent=2) + '\n')


if __name__ == '__main__':
    main()
