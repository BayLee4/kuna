#!/usr/bin/env python3
"""Run real Java publication, source-edit, fault, and import-provenance regressions."""
import json
import os
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parent
from support import host


SCRIPTS = (
    "java_producer.py",
    "java_source_identity.py",
    "java_bodyproof_wire.py",
    "java_native_publication.py",
    "java_structural_publication.py",
    "java_cpp_exporter.py",
    "native_import_provenance.py",
)


def main():
    output = Path(os.environ["KUNA_SMOKE_OUT"]).resolve()
    output.mkdir(parents=True, exist_ok=True)
    report = {"passed": False, "scope": "Java producer/consumer, source-edit lifecycle, and genuine import provenance; not completion of the callable architecture cutover", "rows": []}
    try:
        assert os.environ.get("GHIDRA_INSTALL_DIR"), "GHIDRA_INSTALL_DIR must select the isolated integrated Ghidra installation"
        native = host()
        for script in SCRIPTS:
            destination = output / Path(script).stem
            env = dict(os.environ, KUNA_SMOKE_OUT=str(destination), KUNA_GHIDRA_EXE=str(native))
            command = [sys.executable, str(ROOT / script)]
            # A fresh process/JVM owns each Program, selected core, and exporter.
            result = subprocess.run(command, env=env, text=True, capture_output=True)
            log = output / (Path(script).stem + ".log")
            log.write_text(result.stdout + result.stderr)
            row = {"script": script, "command": command, "returncode": result.returncode,
                   "passed": result.returncode == 0, "output": str(destination), "log": str(log)}
            report["rows"].append(row)
            (output / "consumers.json").write_text(json.dumps(report, indent=2) + "\n")
            print(f"{'PASS' if row['passed'] else 'FAIL'} callable consumer: {script}", flush=True)
        report["passed"] = all(row["passed"] for row in report["rows"])
        assert report["passed"], "Callable consumer failures; see consumers.json and per-script logs"
    finally:
        (output / "consumers.json").write_text(json.dumps(report, indent=2) + "\n")


if __name__ == "__main__":
    main()
