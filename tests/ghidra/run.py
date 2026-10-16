#!/usr/bin/env python3
"""Run the real-Ghidra integration suite; make test-ghidra-live is the entry point."""

import argparse
from dataclasses import dataclass
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]


@dataclass(frozen=True)
class Suite:
    script: str
    description: str
    filters: bool = False


SUITES = {
    "recovery": Suite("error_recovery.py", "Instruction-limit failure and process recovery"),
    "prototypes": Suite("prototype_facts.py", "Parameter, return, custom-storage and callable facts"),
    "types": Suite("type_boundaries.py", "Datatype identity, aliases, bitfields and C declarations"),
    "pointers": Suite("pointer_spaces.py", "Address-space qualifiers and named memory-bank references"),
    "integers": Suite("integer_boundaries.py", "CLI/Ghidra integer and enum consumer boundary matrix", filters=True),
    "settings": Suite("settings_lifecycle.py", "Options, action roots, flush and reopen lifecycle"),
    "symbols": Suite("symbol_replay.py", "Dynamic symbol identity and committed rename replay"),
    "callsites": Suite("callsite_overrides.py", "Callsite overrides and executable ABI consumers"),
    "callable-consumers": Suite("callable/consumers.py", "Kuna source identity and nested aggregate source edits"),
    "callable-transport": Suite("callable/transport.py", "CLI/host callback families, worker publication, conventions and recursive graphs"),
    "callable-readonly": Suite("callable/readonly_preservation.py", "Readonly and mutable machine controls with unchanged C consumers"),
    "callable-recursion": Suite("callable/recursive_closure.py", "Actual self/mutual recursion and grounded unchanged C consumers"),
    "callable-internal-roles": Suite("callable/mips_internal_roles.py", "MIPS raw roles, private spills, inherited effects and executable publication"),
    "callable-restoration": Suite("callable/restoration_boundaries.py", "Private frames, register restoration, native bool and mixed-flow consumers"),
    "callable-graph-objects": Suite("callable/graph_and_objects.py", "Nested bindings, hidden results, named objects and private-leaf identities"),
    "callable-datatypes": Suite("callable/datatype_consumers.py", "Bitfields, pointer arrays, mixed returns and custom register slices"),
    "callable-stack-results": Suite("callable/stack_result_consumers.py", "Custom stack results and exact stored bytes"),
    "native-features": Suite("native_features.py", "Kuna FunctionGraph and raw/debug BSim hash/settings consumers"),
    "cpool": Suite("cpool_consumers.py", "Genuine analyzed JVM CPOOLREF injection, typing and Java rendering"),
}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--suite", action="append", choices=SUITES, help="select a suite; repeat to combine")
    parser.add_argument("--list", action="store_true", help="list suites without starting Ghidra")
    parser.add_argument("--out", type=Path, default=Path(os.environ.get(
        "KUNA_SMOKE_OUT", ROOT / "decompiler/target/ghidra-live")))
    parser.add_argument("probe_args", nargs=argparse.REMAINDER, help="arguments after -- go to one selected suite")
    args = parser.parse_args(argv)
    if args.list:
        for name, suite in SUITES.items():
            print(f"{name:12} {suite.description}")
        return 0
    if sys.flags.optimize:
        parser.error("Python assertions must be enabled; remove -O/PYTHONOPTIMIZE")
    selected = list(dict.fromkeys(args.suite or SUITES))
    probe_args = args.probe_args[1:] if args.probe_args[:1] == ["--"] else args.probe_args
    if probe_args and len(selected) != 1:
        parser.error("probe arguments require exactly one --suite")
    if probe_args and not SUITES[selected[0]].filters:
        parser.error("probe arguments are supported only by --suite integers")
    output = args.out.resolve()
    output.mkdir(parents=True, exist_ok=True)
    run_root = Path(tempfile.mkdtemp(prefix="run-", dir=output))
    report = {"completed": False, "status": "running", "run_directory": str(run_root), "suites": []}
    report_path = run_root / "report.json"
    latest = output / "report.json"

    def save():
        text = json.dumps(report, indent=2) + "\n"
        report_path.write_text(text)
        latest.write_text(text)

    save()
    try:
        for name in selected:
            suite = SUITES[name]
            directory = run_root / name
            directory.mkdir()
            environment = os.environ.copy()
            environment["KUNA_SMOKE_OUT"] = str(directory)
            environment["PYTHONOPTIMIZE"] = "0"
            command = [sys.executable, "-u", str(HERE / suite.script), *probe_args]
            row = {"suite": name, "status": "running", "artifacts": str(directory), "command": command}
            report["suites"].append(row)
            save()
            print(f"RUN  {name}", flush=True)
            started = time.monotonic()
            with (directory / "output.log").open("w") as log:
                result = subprocess.run(command, cwd=ROOT, env=environment, stdout=log, stderr=subprocess.STDOUT)
            row["exit_code"] = result.returncode
            row["seconds"] = round(time.monotonic() - started, 3)
            row["status"] = "passed" if result.returncode == 0 else "failed"
            save()
            print(f"{row['status'].upper():10} {name} ({row['seconds']}s) — {directory / 'output.log'}", flush=True)
        report["completed"] = True
        failed = sum(row["status"] == "failed" for row in report["suites"])
        report["status"] = "failed" if failed else "passed"
        print(f"ghidra-live: {len(selected) - failed}/{len(selected)} suites completed successfully; {report_path}")
        return 1 if failed else 0
    except KeyboardInterrupt:
        report["status"] = "interrupted"
        return 130
    except OSError as error:
        report["status"] = "failed"
        report["error"] = str(error)
        return 1
    finally:
        save()


if __name__ == "__main__":
    sys.exit(main())
