#!/usr/bin/env python3
"""Build the checked-in, unmodified MIPS32 role fixtures with LLVM."""
import argparse
import json
from pathlib import Path
import subprocess

from support import HERE, sha256, tool


def build(destination):
    destination = Path(destination).resolve()
    destination.mkdir(parents=True, exist_ok=False)
    source = HERE / "fixtures" / "mips_role_boundaries.S"
    report = {"completed": False, "source": str(source), "source_sha256": sha256(source), "cases": []}
    try:
        clang, linker, objdump = tool("clang"), tool("ld.lld"), tool("llvm-objdump")
        for value in (0, 1):
            label = f"readonly{value}"
            obj, binary = destination / (label + ".o"), destination / (label + ".elf")
            row = {"label": label, "readonly_value": value, "commands": []}
            report["cases"].append(row)
            commands = [
                [clang, "--target=mipsel-unknown-linux-gnu", "-march=mips32", "-mabi=32",
                 "-mno-abicalls", "-fno-pic", f"-DREADONLY_VALUE={value}", "-c", source, "-o", obj],
                [linker, "-m", "elf32ltsmip", "--image-base=0", "-Ttext=0x1000",
                 "-e", "caller_dirty", "--build-id=none", obj, "-o", binary],
                [objdump, "-d", "-t", binary],
            ]
            for command in commands:
                command = list(map(str, command))
                result = subprocess.run(command, cwd=destination, capture_output=True, text=True, timeout=120)
                observation = {"command": command, "status": result.returncode,
                               "stdout": result.stdout, "stderr": result.stderr}
                row["commands"].append(observation)
                if result.returncode:
                    raise RuntimeError(json.dumps(observation))
            row.update(binary=str(binary), binary_sha256=sha256(binary))
        report["completed"] = True
        return destination / "construction.json"
    finally:
        (destination / "construction.json").write_text(json.dumps(report, indent=2) + "\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    print(build(parser.parse_args().out))
