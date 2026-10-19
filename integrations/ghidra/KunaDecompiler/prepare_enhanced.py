#!/usr/bin/env python3
"""Apply bounded patches to the matching installed Ghidra source members.

Requires the standard GNU/BSD patch utility. Batch/forward/fuzz-zero application
must complete successfully without offset, fuzz, reverse, skip, or reject output.
Only complete temporary staging is published as generated Java sources.
"""

import argparse
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import subprocess
import tempfile
import zipfile


SOURCE_ARCHIVES = {
    "Decompiler": "Ghidra/Features/Decompiler/lib/Decompiler-src.zip",
    "SoftwareModeling": "Ghidra/Framework/SoftwareModeling/lib/SoftwareModeling-src.zip",
    "Base": "Ghidra/Features/Base/lib/Base-src.zip",
}
NONEXACT_PATCH = re.compile(
    r"\b(?:offset|fuzz|reversed|previously\s+applied|skip\w*|ignor\w*|reject\w*|failed|malformed)\b",
    re.IGNORECASE,
)


def apply_owner_patch(stage, patch, member, executable):
    headers = patch.read_text(encoding="utf-8").splitlines()[:2]
    if headers != [f"--- a/{member}", f"+++ b/{member}"]:
        raise ValueError(f"Invalid bounded owner patch header: {member}")
    command = [executable, "-t", "-N", "-F", "0", "-p", "1", "-V", "none", "-i", str(patch)]
    result = subprocess.run(command, cwd=stage, text=True, capture_output=True, check=False)
    diagnostic = result.stdout + result.stderr
    if result.returncode != 0 or NONEXACT_PATCH.search(diagnostic):
        raise ValueError(f"Strict Ghidra source patch failed for {member}: "
                         f"{command!r} exited {result.returncode}\n{diagnostic}")


def prepare(installation, patches, new_sources, output, version, patch_executable="patch"):
    installation, patches = installation.resolve(), patches.resolve()
    new_sources, output = new_sources.resolve(), output.resolve()
    if output.exists():
        raise ValueError("Generated source destination must be clean")
    for source in (installation, patches, new_sources):
        if source == output or source in output.parents or output in source.parents:
            raise ValueError("Generated sources must be disjoint from installation and maintained inputs")
    properties = (installation / "Ghidra/application.properties").read_text(encoding="utf-8")
    actual_version = next((line.split("=", 1)[1].strip() for line in properties.splitlines()
                           if line.startswith("application.version=")), None)
    if actual_version != version:
        raise ValueError(f"Enhanced Java requires Ghidra {version}, found {actual_version}")
    patch_files = sorted(patches.rglob("*.patch"))
    if not patch_files:
        raise ValueError("No enhanced owner patches found")
    prepared, owner_patches = {}, []
    for patch in patch_files:
        relative = patch.relative_to(patches)
        if len(relative.parts) < 2 or relative.parts[0] not in SOURCE_ARCHIVES:
            raise ValueError(f"Unknown owning source archive for {relative}")
        module = relative.parts[0]
        member = PurePosixPath(*relative.parts[1:]).as_posix().removesuffix(".patch")
        if not member.endswith(".java") or ".." in PurePosixPath(member).parts:
            raise ValueError(f"Invalid owner source member {member}")
        archive = installation / SOURCE_ARCHIVES[module]
        with zipfile.ZipFile(archive) as sources:
            original = sources.read(member).decode("utf-8")
        if member in prepared:
            raise ValueError(f"Duplicate patched owner {member}")
        prepared[member] = original
        owner_patches.append((patch, member))
    for helper in sorted(new_sources.rglob("*.java")):
        member = helper.relative_to(new_sources).as_posix()
        if member in prepared:
            raise ValueError(f"New helper duplicates an existing patched owner: {member}")
        prepared[member] = helper.read_text(encoding="utf-8")
    output.parent.mkdir(parents=True, exist_ok=True)
    stage = Path(tempfile.mkdtemp(prefix=".kuna-enhanced-sources-", dir=output.parent))
    try:
        for member, content in prepared.items():
            target = stage / member
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(content, encoding="utf-8")
        for patch, member in owner_patches:
            apply_owner_patch(stage, patch, member, patch_executable)
        os.rename(stage, output)
    finally:
        if stage.exists():
            shutil.rmtree(stage)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ghidra-install", type=Path, required=True)
    parser.add_argument("--patches", type=Path, required=True)
    parser.add_argument("--new-sources", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--patch-executable", default=os.environ.get("PATCH", "patch"))
    args = parser.parse_args()
    prepare(args.ghidra_install, args.patches, args.new_sources, args.output, args.version,
            args.patch_executable)


if __name__ == "__main__":
    main()
