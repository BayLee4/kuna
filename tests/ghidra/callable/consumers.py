#!/usr/bin/env python3
"""Run product consumers or explicit stock-native regression controls."""
import json
import os
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT.parent))
from kuna_vs_stock import test_cores
from support import host


# The producer's stock native process consumes our Java callback output; it is
# not an independent stock semantic-positive matrix.
CHILDREN = {
    "java_producer.py": {
        "groups": ("product", "stock-controls"),
        "purpose": "Java callback/source authority using a genuine stock-native consumer",
    },
    "java_native_publication.py": {
        "groups": ("product",),
        "purpose": "Kuna inferred result publication and unchanged export execution",
    },
    "java_callable_publication.py": {
        "groups": ("product",),
        "purpose": "Kuna callable publication and unchanged C/H/provider execution",
    },
    "java_source_identity.py": {
        "groups": ("product", "stock-controls"),
        "purpose": "Selected native core's source identity, field bindings and edit lifetime",
    },
    "java_structural_publication.py": {
        "groups": ("product",),
        "purpose": "Kuna structural publication and recursive source-edit consumers",
    },
    "java_cpp_exporter.py": {
        "groups": ("product", "stock-controls"),
        "purpose": "Selected native positives plus Java malformed/crash/cancel/recovery using genuine stock responses",
    },
    "native_import_provenance.py": {
        "groups": ("product", "stock-controls"),
        "purpose": "Selected native core's real SDK/libc import and source-preservation consumers",
    },
}


def main():
    cores = test_cores()
    group = "product" if "kuna" in cores else "stock-controls"
    scripts = [script for script, child in CHILDREN.items() if group in child["groups"]]
    output = Path(os.environ["KUNA_SMOKE_OUT"]).resolve()
    output.mkdir(parents=True, exist_ok=True)
    report = {"passed": False,
              "scope": "Selected callable consumers; original child failure and exit semantics",
              "group": group, "selected_cores": cores,
              "selected_children": [{"script": script, "purpose": CHILDREN[script]["purpose"]}
                                    for script in scripts],
              "rows": []}
    try:
        assert os.environ.get("GHIDRA_INSTALL_DIR"), "GHIDRA_INSTALL_DIR must select stock Ghidra; isolated per-user extension settings select ordinary or matching 12.1.4 enhanced Java"
        assert scripts, "Selected group has no callable consumers"
        native = host() if "kuna" in cores else None
        for script in scripts:
            destination = output / Path(script).stem
            env = dict(os.environ, KUNA_SMOKE_OUT=str(destination), KUNA_GHIDRA_TEST_GROUP=group)
            if native is not None:
                env["KUNA_GHIDRA_EXE"] = str(native)
            command = [sys.executable, str(ROOT / script)]
            # A fresh process/JVM owns each Program, selected core, and exporter.
            result = subprocess.run(command, env=env, text=True, capture_output=True)
            log = output / (Path(script).stem + ".log")
            log.write_text(result.stdout + result.stderr)
            row = {"script": script, "purpose": CHILDREN[script]["purpose"],
                   "command": command, "returncode": result.returncode,
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
