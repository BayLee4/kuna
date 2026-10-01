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
    binary: bool = False
    diagnostic: bool = False
    filters: bool = False


SUITES = {
    "recovery": Suite("error_recovery.py", "Instruction-limit failure and process recovery"),
    "prototypes": Suite("prototype_facts.py", "Parameter, return, custom-storage and callable facts"),
    "types": Suite("type_boundaries.py", "Datatype identity, aliases, bitfields and C declarations"),
    "pointers": Suite("pointer_spaces.py", "Address-space qualifiers and named memory-bank references"),
    "integers": Suite("integer_boundaries.py", "CLI/Ghidra integer and enum consumer boundary matrix", filters=True),
    "settings": Suite("settings_lifecycle.py", "Options, action roots, flush and reopen lifecycle"),
    "symbols": Suite("symbol_replay.py", "Symbol identity and persistent renames"),
    "callsites": Suite("callsite_overrides.py", "Callsite overrides and executable ABI consumers"),
    "callable-consumers": Suite("callable/consumers.py", "Java callable publication, source edits, fault recovery and import provenance"),
    "callable-transport": Suite("callable/transport.py", "CLI/host callback families, worker publication, conventions and recursive graphs"),
    "callable-readonly": Suite("callable/readonly_preservation.py", "Readonly branch receipts, unchanged C and missing-provider refusal"),
    "callable-internal-roles": Suite("callable/mips_internal_roles.py", "MIPS raw roles, private spills, inherited effects and executable publication"),
    "callable-restoration": Suite("callable/restoration_boundaries.py", "Private frames, register restoration, native bool, variadic and mixed-flow boundaries"),
    "callable-graph-objects": Suite("callable/graph_and_objects.py", "Nested bindings, hidden results, named objects and private-leaf identities"),
    "callable-datatypes": Suite("callable/datatype_consumers.py", "Bitfields, pointer-to-array, mixed returns and custom result storage"),
    "features": Suite("phase4_features.py", "Host feature interactions on a supplied binary", binary=True),
    "comparison": Suite("kuna_vs_stock.py", "Diagnostic stock/Kuna output comparison", binary=True, diagnostic=True),
}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--suite", action="append", choices=SUITES, help="select a suite; repeat to combine")
    parser.add_argument("--list", action="store_true", help="list suites without starting Ghidra")
    parser.add_argument("--out", type=Path, default=Path(os.environ.get(
        "KUNA_SMOKE_OUT", ROOT / "decompiler/target/ghidra-live")))
    parser.add_argument("--binary", type=Path, help="input for the optional features/comparison suites")
    parser.add_argument("--function", action="append", help="function selection for features/comparison")
    parser.add_argument("probe_args", nargs=argparse.REMAINDER, help="arguments after -- go to one selected suite")
    args = parser.parse_args(argv)
    if args.list:
        for name, suite in SUITES.items():
            suffix = " (opt-in, requires --binary)" if suite.binary else ""
            print(f"{name:12} {suite.description}{suffix}")
        return 0
    if sys.flags.optimize:
        parser.error("Python assertions must be enabled; remove -O/PYTHONOPTIMIZE")
    selected = list(dict.fromkeys(args.suite or [name for name, suite in SUITES.items() if not suite.binary]))
    probe_args = args.probe_args[1:] if args.probe_args[:1] == ["--"] else args.probe_args
    if probe_args and len(selected) != 1:
        parser.error("probe arguments require exactly one --suite")
    if probe_args and not SUITES[selected[0]].filters:
        parser.error("probe arguments are supported only by --suite integers")
    binary = args.binary or (Path(os.environ["KUNA_SMOKE_BINARY"]) if os.environ.get("KUNA_SMOKE_BINARY") else None)
    if any(SUITES[name].binary for name in selected) and (binary is None or not binary.is_file()):
        parser.error("features/comparison require an existing --binary (or KUNA_SMOKE_BINARY)")
    if "features" in selected and args.function and len(args.function) != 1:
        parser.error("features accepts one --function")
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
            if binary is not None:
                environment["KUNA_SMOKE_BINARY"] = str(binary.resolve())
            if args.function:
                environment["KUNA_SMOKE_FUNCTIONS"] = ",".join(args.function)
                environment["KUNA_SMOKE_FUNCTION"] = args.function[0]
            command = [sys.executable, "-u", str(HERE / suite.script), *probe_args]
            row = {"suite": name, "status": "running", "diagnostic": suite.diagnostic,
                   "artifacts": str(directory), "command": command}
            report["suites"].append(row)
            save()
            print(f"RUN  {name}", flush=True)
            started = time.monotonic()
            with (directory / "output.log").open("w") as log:
                result = subprocess.run(command, cwd=ROOT, env=environment, stdout=log, stderr=subprocess.STDOUT)
            row["exit_code"] = result.returncode
            row["seconds"] = round(time.monotonic() - started, 3)
            row["status"] = ("diagnostic" if suite.diagnostic else "passed") if result.returncode == 0 else "failed"
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
