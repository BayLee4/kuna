#!/usr/bin/env python3
"""Authentic readonly branch preservation, provider ownership and unchanged C.

No mandatory arguments. The shared runner supplies KUNA_SMOKE_OUT/KUNA_CLI and
Ghidra prerequisites. The supported readonly positive executes unchanged providers;
machine-negative controls remain separate from ordinary project export.
"""
import json
import os
import subprocess
import traceback

from support import HERE, ROOT, cli, output, sha256, tool, require_provider_body, require_absent_provider_body
from whole_calls_workers import ElfMachine, elf_symbols


def invoke(row, command):
    command = list(map(str, command))
    process = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, timeout=240)
    result = {"command": command, "status": process.returncode,
              "stdout": process.stdout, "stderr": process.stderr}
    row.setdefault("commands", []).append(result)
    return result


def checked(row, command):
    result = invoke(row, command)
    assert result["status"] == 0, result
    return result


def machine_case(binary, directory, value, mutable):
    directory.mkdir()
    symbols = elf_symbols(binary)
    machine = ElfMachine(binary, directory)
    result = {"binary_sha256": sha256(binary), "executions": []}
    try:
        from jpype import JArray, JByte
        from java.math import BigInteger

        flags = [symbol for symbol in machine.program.getSymbolTable().getAllSymbols(True)
                 if str(symbol.getName()) == "flag"]
        assert len(flags) == 1
        flag = flags[0].getAddress()
        block = machine.program.getMemory().getBlock(flag)
        assert bool(block.isRead()) and bool(block.isWrite()) == mutable
        assert int(machine.program.getMemory().getByte(flag)) & 255 == value
        result["original_guard"] = {"address": int(flag.getOffset()), "value": value,
                                    "writable": bool(block.isWrite())}
        for entry in ("subject", "outer"):
            emulator = machine.EmulatorHelper(machine.program)
            try:
                for register, initial in (("RBX", 42), ("RBP", 0x1122334455667788), ("RSP", 0x7FD8)):
                    emulator.writeRegister(register, BigInteger(str(initial)))
                emulator.writeMemory(machine.address(0x7FD8), JArray(JByte)((0x7FF0).to_bytes(8, "little")))
                emulator.setBreakpoint(machine.address(0x7FF0))
                assert emulator.run(machine.address(symbols[entry]), None, machine.monitor), str(emulator.getLastError())
                assert emulator.getExecutionAddress() == machine.address(0x7FF0)
                returned = int(str(emulator.readRegister("RAX")))
                rbx = int(str(emulator.readRegister("RBX")))
                child_rbx = 7 if value else 42
                assert returned == (11 if entry == "subject" else child_rbx)
                assert rbx == (child_rbx if entry == "subject" else 42)
                assert int(str(emulator.readRegister("RSP"))) == 0x7FE0
                assert int(str(emulator.readRegister("RBP"))) == 0x1122334455667788
                result["executions"].append({"entry": entry, "return": returned, "RBX": rbx, "RSP": 0x7FE0})
            finally:
                emulator.dispose()
    finally:
        machine.close()
    return result


def common(functions, readonly):
    return ["--functions", functions, "--language", "c", "--option", "readonly", readonly,
            "--option", "structdefs", "on", "--assert-strict",
            "--assert", "prototype subject int subject(void)",
            "--assert", "prototype outer unsigned long long outer(void)"]


def omitted_provider(row, kuna, binary, directory):
    metadata = checked(row, [kuna, "decompile-all", binary, "--json", *common("outer", "on")])
    data = json.loads(metadata["stdout"])
    assert len(data["functions"]) == 1 and data["functions"][0]["name"] == "outer", data
    function = data["functions"][0]
    assert function.get("error") is None and "subject(" in function["code"], function
    exported = invoke(row, [kuna, "decompile-project", binary, "-o", directory / "omitted-project",
                           *common("outer", "on")])
    assert exported["status"] == 0, exported
    body = directory / "omitted-project" / (binary.name + ".c")
    require_provider_body(body, "outer")
    require_absent_provider_body(body, "subject")
    row["omitted_provider"] = {
        "selected_body": "outer", "omitted": "subject",
        "project_status": exported["status"],
    }


def main():
    directory = output("readonly-preservation")
    kuna = cli()
    source = HERE / "fixtures/readonly_cut.S"
    compiler, linker = tool("clang"), tool("ld.lld")
    native_cc = os.environ.get("CC") or tool("cc")
    report = {"completed": False, "cli_sha256": sha256(kuna), "source_sha256": sha256(source),
              "construction": [], "cases": []}
    fixtures = directory / "fixtures"
    fixtures.mkdir()
    try:
        for name, value, mutable in (("readonly_zero", 0, False), ("readonly_one", 1, False), ("mutable_zero", 0, True)):
            row = {"name": name}
            report["construction"].append(row)
            obj, binary = fixtures / (name + ".o"), fixtures / (name + ".elf")
            checked(row, [compiler, "--target=x86_64-unknown-linux-gnu", "-DFLAG_VALUE=" + str(value),
                          *(["-DMUTABLE_FLAG"] if mutable else []), "-c", source, "-o", obj])
            checked(row, [linker, "-m", "elf_x86_64", "--image-base=0", "-Ttext=0x1000", "-e", "outer",
                          "--build-id=none", obj, "-o", binary])
            checked(row, [tool("llvm-objdump"), "-d", "-s", binary])
            checked(row, [tool("llvm-readelf"), "-l", "-S", "-s", binary])
            row["machine"] = machine_case(binary, directory / (name + "-machine"), value, mutable)

        for name, readonly, admit in (("readonly_zero", "on", True), ("readonly_one", "on", False),
                                     ("mutable_zero", "on", False), ("readonly_zero", "off", False)):
            case = directory / (name + "-" + readonly)
            case.mkdir()
            binary = fixtures / (name + ".elf")
            row = {"name": name, "readonly": readonly, "unchanged_C_required": admit,
                   "binary_sha256": sha256(binary), "completed": False}
            report["cases"].append(row)
            try:
                args = common("subject,outer", readonly)
                metadata = checked(row, [kuna, "decompile-all", binary, "--json", *args])
                data = json.loads(metadata["stdout"])
                (case / "metadata.json").write_text(json.dumps(data, indent=2) + "\n")
                assert len(data["functions"]) == 2 and {function["name"] for function in data["functions"]} == {"subject", "outer"}
                assert all(function.get("error") is None and function.get("code") for function in data["functions"]), data
                assertions = [item for item in data.get("assertions", [])
                              if item.get("directive", "").startswith("prototype ")]
                assert len(assertions) == 2 and all(item.get("status") == "applied" for item in assertions), data
                project = case / "project"
                exported = invoke(row, [kuna, "decompile-project", binary, "-o", project, *args])
                assert exported["status"] == 0, exported
                stem = binary.name
                for provider in ("subject", "outer"):
                    require_provider_body(project / (stem + ".c"), provider)
                if not admit:
                    row["completed"] = True
                    continue
                try:
                    omitted_provider(row, kuna, binary, case)
                except Exception:
                    row["partial_selection_failure"] = traceback.format_exc()
                consumer = case / "consumer.c"
                consumer.write_text('#include "' + stem + '.h"\nint main(void) { return subject()!=11 || outer()!=42; }\n')
                row["emitted_sha256"] = {path.name: sha256(path) for path in (project / (stem + ".c"), project / (stem + ".h"))}
                row["consumer_failures"] = []
                for optimization in ("-O0", "-O2"):
                    try:
                        executable = case / ("consumer" + optimization)
                        checked(row, [native_cc, "-std=c11", "-Wall", "-Wextra", "-Werror=uninitialized",
                                      "-Werror=incompatible-pointer-types", "-Werror=implicit-function-declaration",
                                      optimization, "-I", project, project / (stem + ".c"), consumer, "-o", executable])
                        checked(row, [executable])
                    except Exception:
                        row["consumer_failures"].append({"optimization": optimization,
                                                        "failure": traceback.format_exc()})
                row["unchanged_C_passed"] = not row["consumer_failures"]
                row["behavioral_checks_completed"] = True
                row["completed"] = row["unchanged_C_passed"] and "partial_selection_failure" not in row
            except Exception:
                row["failure"] = traceback.format_exc()
            finally:
                (case / "report.json").write_text(json.dumps(row, indent=2) + "\n")
                print(json.dumps({"case": name + "-" + readonly, "completed": row["completed"],
                                  "failure": row.get("failure")}), flush=True)
        report["completed"] = all(row["completed"] for row in report["cases"])
    except Exception:
        report["failure"] = traceback.format_exc()
    finally:
        (directory / "report.json").write_text(json.dumps(report, indent=2) + "\n")
        print(json.dumps({"report": str(directory / "report.json"), "completed": report["completed"]}), flush=True)
    if not report["completed"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
