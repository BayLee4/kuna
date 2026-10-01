#!/usr/bin/env python3
"""Authentic MIPS role proofs, machine oracle, publication, and unchanged C."""
import json
import os
from pathlib import Path
import subprocess

from build_mips_roles import build
from support import ROOT, cli, output, run_script, sha256, tool


def main():
    directory = output("mips-internal-roles")
    report = {"completed": False, "stages": [], "output": str(directory)}

    def attempt(name, action):
        row = {"name": name, "passed": False}
        report["stages"].append(row)
        try:
            action()
            row["passed"] = True
        except Exception as error:
            row["error"] = str(error)
        finally:
            (directory / "report.json").write_text(json.dumps(report, indent=2) + "\n")

    try:
        construction = build(directory / "fixtures")
        manifest = json.loads(construction.read_text())
        assert manifest["completed"]
        binary = Path(next(row["binary"] for row in manifest["cases"] if row["readonly_value"] == 0))
        executable = cli()
        report.update(cli=str(executable), cli_sha256=sha256(executable),
                      construction=str(construction), binary_sha256=sha256(binary))

        def raw_proofs():
            environment = dict(os.environ, KUNA_MIPS_ROLE_FIXTURES=str(construction.parent))
            command = [tool("cargo"), "test", "--release", "-p", "kuna-console",
                       "--features", "test-support", "--test", "verify_mips_internal_roles", "--", "--nocapture"]
            result = subprocess.run(command, cwd=ROOT / "decompiler", env=environment,
                                    capture_output=True, text=True, timeout=1800)
            observation = {"command": command, "status": result.returncode,
                           "stdout": result.stdout, "stderr": result.stderr}
            (directory / "raw-proof-command.json").write_text(json.dumps(observation, indent=2) + "\n")
            if result.returncode:
                raise RuntimeError(f"actual raw/SSA proof matrix failed: {directory / 'raw-proof-command.json'}")

        attempt("actual_raw_and_final_proofs", raw_proofs)
        for scope in ("roles", "inherited", "private", "natural"):
            attempt("machine_" + scope, lambda scope=scope: run_script(
                "mips_role_machine.py", "--construction", construction,
                "--scope", scope, "--out", directory / ("machine-" + scope)))
        attempt("publication_and_unchanged_C", lambda: run_script(
            "mips_role_publication.py", "--cli", executable, "--sha256", sha256(executable),
            "--binary", binary, "--binary-sha256", sha256(binary),
            "--out", directory / "publication"))
        report["completed"] = all(row["passed"] for row in report["stages"])
    except Exception as error:
        report["error"] = str(error)
    finally:
        (directory / "report.json").write_text(json.dumps(report, indent=2) + "\n")
        print(json.dumps({"completed": report["completed"], "report": str(directory / "report.json")}))
    return 0 if report["completed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
