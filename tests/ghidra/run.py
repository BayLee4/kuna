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
    stock_control: str | None = None


SUITES = {
    "recovery": Suite("error_recovery.py", "Instruction-limit failure and process recovery",
                      stock_control="DecompInterface/process failure and recovery; compare unchanged stock native across Java receivers"),
    "prototypes": Suite("prototype_facts.py", "Parameter, return, custom-storage and callable facts",
                        stock_control="Java source locks/storage and debug replay; native prototype recovery is a reference, not Kuna's oracle"),
    "types": Suite("type_boundaries.py", "Datatype identity, aliases, bitfields and C declarations",
                   stock_control="PcodeDataTypeManager/High decoding, token identity and emitted source declarations"),
    "pointers": Suite("pointer_spaces.py", "Address-space qualifiers and named memory-bank references",
                      stock_control="Java address-space/type decoding and native pointer rendering"),
    "integers": Suite("integer_boundaries.py", "CLI/Ghidra integer and enum consumer boundary matrix", filters=True,
                      stock_control="Native numeric rendering versus real C consumers; stock improvement alone does not replace Kuna's printer"),
    "settings": Suite("settings_lifecycle.py", "Options, action roots, flush and reopen lifecycle",
                      stock_control="DecompileOptions/DecompInterface context and native option lifecycle"),
    "symbols": Suite("symbol_replay.py", "Dynamic symbol identity and committed rename replay",
                     stock_control="Java callback/High symbol identity, committed edits and debug replay"),
    "callsites": Suite("callsite_overrides.py", "Callsite overrides and executable ABI consumers",
                       stock_control="Java override/injection source authority plus native callsite/ABI/export reference behavior"),
    "callable-consumers": Suite("callable/consumers.py", "Kuna source identity and nested aggregate source edits",
                                stock_control="Java callback/type/source identity and CppExporter faults/recovery; SDK native semantics remain a reference"),
    "result-views": Suite("callable/java_result_view.py", "Full Java result-local identity, source authority and export-scope lifecycle"),
    "callable-transport": Suite("callable/transport.py", "CLI/host callback families, worker publication, conventions and recursive graphs"),
    "callable-readonly": Suite("callable/readonly_preservation.py", "Readonly and mutable machine controls with unchanged C consumers"),
    "callable-recursion": Suite("callable/recursive_closure.py", "Actual self/mutual recursion and grounded unchanged C consumers"),
    "callable-internal-roles": Suite("callable/mips_internal_roles.py", "MIPS raw roles, private spills, inherited effects and executable publication"),
    "callable-restoration": Suite("callable/restoration_boundaries.py", "Private frames, register restoration, native bool and mixed-flow consumers"),
    "callable-graph-objects": Suite("callable/graph_and_objects.py", "Nested bindings, hidden results, named objects and private-leaf identities"),
    "callable-datatypes": Suite("callable/datatype_consumers.py", "Bitfields, pointer arrays, mixed returns and custom register slices"),
    "callable-stack-results": Suite("callable/stack_result_consumers.py", "Custom stack results and exact stored bytes"),
    "native-features": Suite("native_features.py", "Kuna FunctionGraph and raw/debug BSim hash/settings consumers",
                             stock_control="Java graph/signature decoding and BSim consumers; product also requires genuine cross-core reference inputs"),
    "cpool": Suite("cpool_consumers.py", "Genuine analyzed JVM CPOOLREF injection, typing and Java rendering",
                   stock_control="Java JVM loader/analyzer/injection source facts versus native constant-pool rendering"),
}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--group", choices=("product", "stock-controls"), default="product",
                        help="product: Kuna + full Java; stock-controls: independent stock regression observations")
    parser.add_argument("--suite", action="append", choices=SUITES, help="select a suite; repeat to combine")
    parser.add_argument("--list", action="store_true", help="list suites without starting Ghidra")
    parser.add_argument("--extension", type=Path, default=os.environ.get("KUNA_GHIDRA_EXTENSION_ZIP"),
                        help="install this normal extension ZIP into an isolated profile, restart, and test its bundled backend")
    parser.add_argument("--out", type=Path, default=Path(os.environ.get(
        "KUNA_SMOKE_OUT", ROOT / "decompiler/target/ghidra-live")))
    parser.add_argument("probe_args", nargs=argparse.REMAINDER, help="arguments after -- go to one selected suite")
    args = parser.parse_args(argv)
    available = {name: suite for name, suite in SUITES.items()
                 if args.group == "product" or suite.stock_control}
    if args.list:
        print(f"Group: {args.group}")
        for name, suite in available.items():
            print(f"{name:12} {suite.description if args.group == 'product' else suite.stock_control}")
        return 0
    if sys.flags.optimize:
        parser.error("Python assertions must be enabled; remove -O/PYTHONOPTIMIZE")
    selected = list(dict.fromkeys(args.suite or available))
    unavailable = set(selected) - available.keys()
    if unavailable:
        parser.error("suites have no independent stock-control cases: " + ", ".join(sorted(unavailable)))
    if "callable-consumers" in selected:
        overrides = [name for name in ("KUNA_CPP_EXPORTER_MODES", "KUNA_CPP_EXPORTER_POLICY")
                     if name in os.environ]
        if overrides:
            parser.error("complete groups require default exporter coverage; unset " +
                         ", ".join(overrides) + " or run java_cpp_exporter.py directly for focused diagnostics")
    probe_args = args.probe_args[1:] if args.probe_args[:1] == ["--"] else args.probe_args
    if probe_args and len(selected) != 1:
        parser.error("probe arguments require exactly one --suite")
    if probe_args and not SUITES[selected[0]].filters:
        parser.error("probe arguments are supported only by --suite integers")
    output = args.out.resolve() / args.group
    output.mkdir(parents=True, exist_ok=True)
    run_root = Path(tempfile.mkdtemp(prefix="run-", dir=output))
    report = {"completed": False, "status": "running", "group": args.group,
              "interpretation": "Kuna + full Java product acceptance" if args.group == "product" else
                  "Raw correct-behavior observations: compare the same stock native/input under unmodified and full Java. "
                  "Inherited failures are not product defects; new Java regressions remain defects. "
                  "A later stock pass is success and triggers review of related patches, not automatic removal.",
              "selection": {"full_roster": selected == list(available) and not probe_args,
                            "suites": selected, "probe_args": probe_args},
              "run_directory": str(run_root), "suites": []}
    report_path = run_root / "report.json"
    latest = output / "report.json"

    def save():
        text = json.dumps(report, indent=2) + "\n"
        report_path.write_text(text)
        latest.write_text(text)

    save()
    try:
        environment = os.environ.copy()
        if args.extension:
            from installed_product import install_extension
            environment, report["installation"] = install_extension(
                args.extension, run_root / "installation")
            save()
        for name in selected:
            suite = SUITES[name]
            directory = run_root / name
            directory.mkdir()
            environment["KUNA_SMOKE_OUT"] = str(directory)
            environment["PYTHONOPTIMIZE"] = "0"
            # The CLI producers compared with the host keep DWARF typedef names (default off).
            environment.setdefault("KUNA_DWARFTYPEDEFS", "1")
            environment["KUNA_GHIDRA_TEST_GROUP"] = args.group
            command = [sys.executable, "-u", str(HERE / suite.script), *probe_args]
            row = {"suite": name, "status": "running", "artifacts": str(directory), "command": command,
                   "purpose": suite.description if args.group == "product" else suite.stock_control}
            report["suites"].append(row)
            save()
            print(f"RUN  {args.group}: {name}", flush=True)
            started = time.monotonic()
            with (directory / "output.log").open("w") as log:
                result = subprocess.run(command, cwd=ROOT, env=environment, stdout=log, stderr=subprocess.STDOUT)
            row["exit_code"] = result.returncode
            row["seconds"] = round(time.monotonic() - started, 3)
            row["status"] = "passed" if result.returncode == 0 else "failed"
            save()
            print(f"{row['status'].upper():10} {args.group}: {name} ({row['seconds']}s) — {directory / 'output.log'}", flush=True)
        report["completed"] = True
        failed = sum(row["status"] == "failed" for row in report["suites"])
        report["status"] = "failed" if failed else "passed"
        label = "Kuna + full Java product" if args.group == "product" else "Stock-control observations (not product acceptance)"
        print(f"{label}: {len(selected) - failed}/{len(selected)} suites passed; {report_path}")
        return 1 if failed else 0
    except KeyboardInterrupt:
        report["status"] = "interrupted"
        return 130
    except (OSError, RuntimeError) as error:
        report["status"] = "failed"
        report["error"] = str(error)
        return 1
    finally:
        save()


if __name__ == "__main__":
    sys.exit(main())
