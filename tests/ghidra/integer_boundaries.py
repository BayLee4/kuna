#!/usr/bin/env python3
"""Execute unchanged CLI/Ghidra C across a bounded integer-boundary matrix.

Run in the live-smoke PyGhidra environment. --producer cli needs only Python,
clang, a native C compiler, and the release CLI. Each case groups seven equality
predicates, not a combinatorial product of independent expression generators.
Original Ghidra instructions and separately compiled source check the bitvector
oracle; stock output is a separate regression/reference control, never the oracle.
"""

import argparse
from dataclasses import dataclass
import json
import os
from pathlib import Path
import shlex
import subprocess
import traceback

ROOT = Path(__file__).resolve().parents[2]
ALIASES = """#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <limits.h>
typedef unsigned char byte, uchar;
typedef signed char sbyte, schar;
typedef unsigned short ushort;
typedef unsigned int uint;
typedef long long longlong;
typedef unsigned long long ulonglong;
"""


@dataclass(frozen=True)
class Case:
    kind: str
    width: int
    signed: bool

    @property
    def name(self):
        return f"{self.kind}{self.width}"

    @property
    def mask(self):
        return (1 << (8 * self.width)) - 1

    @property
    def ctype(self):
        if self.kind.endswith("enum"):
            return "Flags"
        if self.kind == "char":
            return "char"
        return {1: ("signed char", "unsigned char"),
                2: ("short", "unsigned short"),
                4: ("int", "unsigned int")}[self.width][not self.signed]

    @property
    def targets(self):
        if self.width == 8 and self.signed:
            # A 32-bit enumerator inside a signed 64-bit enum has different
            # C promotion rules from the enum's declared underlying width.
            return [self.mask ^ 0x80000000]
        sign = 1 << (8 * self.width - 1)
        return sorted({0, 1, sign - 1, sign, self.mask ^ 3, self.mask - 1, self.mask})

    @property
    def witnesses(self):
        values = {0, 1, 2, 4, self.mask}
        for target in self.targets:
            values.update(value for value in (target - 1, target, target + 1)
                          if 0 <= value <= self.mask)
        return sorted(values)

    @property
    def inputs(self):
        return list(range(256)) if self.width == 1 else self.witnesses

    def constant(self, bits):
        if self.signed and bits > self.mask // 2:
            value = bits - self.mask - 1
            if value == -(1 << 63):
                return "(-9223372036854775807LL-1)"
            return f"({value}{'LL' if self.width == 8 else ''})"
        return f"0x{bits:x}{'ULL' if self.width == 8 else 'U'}"

    @property
    def enum_values(self):
        if not self.kind.endswith("enum"):
            return {}
        values = {"FLAG_A": 0x80000000} if self.width == 8 and self.signed else {
            "FLAG_A": 1, "FLAG_B": 2, "FLAG_C": 4,
        }
        if self.signed:
            values.update(FLAG_MIN=-(1 << (8 * self.width - 1)), FLAG_MAX=self.mask // 2)
        else:
            values["FLAG_HIGH"] = 1 << (8 * self.width - 1)
        return values

    def definitions(self):
        if not self.enum_values:
            return ""
        values = [f"{name}={enum_literal(value)}" for name, value in self.enum_values.items()]
        return "typedef enum __attribute__((packed)) Flags {" + ",".join(values) + "} Flags;\n"

    def assertion(self):
        values = [f"{name}={hex(value) if value >= 0 else value}" for name, value in self.enum_values.items()]
        return "typedef typedef enum Flags {" + ",".join(values) + "} Flags;"

    def type_assertions(self):
        assertions = f'_Static_assert(sizeof({self.ctype})=={self.width}, "producer width");\n'
        if self.kind != "char":
            relation = "<" if self.signed else ">"
            assertions += f'_Static_assert(({self.ctype})-1 {relation} 0, "producer signedness");\n'
        else:
            assertions += '_Static_assert(CHAR_MIN<0, "x86 gcc char is signed");\n'
        return assertions

    def source(self):
        return self.definitions() + "\n".join(
            f"__attribute__((noinline)) int boundary_{index}({self.ctype} value) "
            f"{{ return value == {self.constant(target)}; }}"
            for index, target in enumerate(self.targets)
        ) + "\n"

    def driver(self):
        argument = "bits"
        if self.signed:
            argument = (f"(bits <= {self.mask // 2}ULL ? (int64_t)bits : "
                        f"-1 - (int64_t)({self.mask}ULL - bits))")
        return self.type_assertions() + f"""
int main(void) {{
  int (*subjects[])({self.ctype}) = {{{','.join('boundary_' + str(i) for i in range(len(self.targets)))}}};
  uint64_t targets[] = {{{','.join(str(v) + 'ULL' for v in self.targets)}}};
  uint64_t values[] = {{{','.join(str(v) + 'ULL' for v in self.inputs)}}};
  for (unsigned fn=0; fn<sizeof(subjects)/sizeof(subjects[0]); ++fn)
    for (unsigned i=0; i<sizeof(values)/sizeof(values[0]); ++i) {{
      uint64_t bits=values[i];
      int got=subjects[fn](({self.ctype}){argument});
      int expected=bits==targets[fn];
      if (got!=expected) {{
        printf("function=%u bits=%llu got=%d expected=%d\\n",fn,(unsigned long long)bits,got,expected);
        return 91;
      }}
    }}
  return 0;
}}
"""


def cases():
    result = [Case(kind, width, signed) for width in (1, 2, 4)
              for kind, signed in (("unsigned", False), ("signed", True),
                                   ("unsigned_enum", False), ("signed_enum", True))]
    return result + [Case("char", 1, True), Case("signed_enum", 8, True)]


def enum_literal(value):
    # Preserve normal C enumerator operand promotions independently of the
    # enum's storage width (notably FLAG_A's unsigned32 type in signed_enum8).
    if value == -(1 << 63):
        return "(-9223372036854775807LL-1)"
    if value < 0:
        return f"({value}{'LL' if value < -(1 << 31) else ''})"
    if value <= (1 << 31) - 1:
        return str(value)
    return f"0x{value:x}{'U' if value <= 0xffffffff else 'ULL'}"


def instructions(width, target):
    prefix = {1: b"\x40\x80\xff", 2: b"\x66\x81\xff", 4: b"\x81\xff"}
    comparison = (prefix[width] + target.to_bytes(width, "little") if width != 8 else
                  b"\x48\xb8" + target.to_bytes(8, "little") + b"\x48\x39\xc7")
    return comparison + bytes.fromhex("0f94c00fb6c0c3")


def command(path, arguments):
    completed = subprocess.run([str(arg) for arg in arguments], text=True, capture_output=True, timeout=120)
    result = {"command": [str(arg) for arg in arguments], "exit": completed.returncode,
              "stdout": completed.stdout, "stderr": completed.stderr}
    path.write_text(json.dumps(result, indent=2) + "\n")
    assert completed.returncode == 0, result
    return result


def execute_consumer(directory, case, emitted, label, warnings_as_errors=True):
    # The emitted function bodies are concatenated verbatim. Only externally
    # declared types and a driver are supplied; no cast/literal rewriting.
    source = directory / f"{label}-consumer.c"
    source.write_text(ALIASES + case.definitions() + emitted + case.driver())
    results = []
    for optimization in (0, 2):
        # Plain char follows the producer ABI. Explicitly signed/unsigned types
        # (including unsigned char) must survive either host plain-char mode.
        for char_mode in (("signed",) if case.kind == "char" else ("signed", "unsigned")):
            suffix = f"{label}-O{optimization}-{char_mode}-char"
            binary = directory / suffix
            build = command(directory / f"{suffix}-build.json", [
                *shlex.split(os.environ.get("CC", "cc")), "-std=c11", f"-O{optimization}",
                f"-f{char_mode}-char", "-Wall", *(["-Werror"] if warnings_as_errors else []),
                source, "-o", binary,
            ])
            run = command(directory / f"{suffix}-run.json", [binary])
            results.append({"optimization": optimization, "char_mode": char_mode,
                            "build": build, "run": run})
    return results


def check_source(directory, case):
    source = case.source()
    # Source already includes enum definitions; the consumer preamble supplies
    # them once and must not edit the function bodies.
    bodies = source[len(case.definitions()):]
    return execute_consumer(directory, case, bodies, "source-control")


def cli_default_enum(directory, row):
    """Require the x86 gcc compiler specification's four-byte enum layout."""
    cli = Path(os.environ.get("KUNA_CLI", ROOT / "decompiler/target/release/kuna")).resolve()
    raw = directory / "default-width.bin"
    machine = instructions(8, 0)
    raw.write_bytes(machine)
    result = command(directory / "default-width-cli.json", [
        cli, "decompile", raw, "0x1000", "--json", "--raw-image", "--target",
        "x86:LE:64:default:gcc", "--base", "0x1000", "--define-function",
        f"0x1000-0x{0x1000 + len(machine):x}=default_width", "--assert-strict",
        "--assert", Case("unsigned_enum", 4, False).assertion(),
        "--assert", "prototype default_width int default_width(Flags value)",
    ])
    payload = json.loads(result["stdout"])
    assert payload.get("error") is None, payload
    function, = payload["functions"]
    assert function.get("error") is None, function
    assert all(item["status"] == "applied" for item in payload["assertions"]), payload
    parameter, = [v for v in function["variables"] if v.get("kind") == "arg" and v.get("arg_index") == 0]
    assert parameter["size"] == 4, parameter
    row["default_enum_probe"] = {"parameter": parameter, "assertions": payload["assertions"]}
    row["effective_case"] = "unsigned_enum4"
    row["native_enum_model"] = "x86 gcc int and enum width is four bytes"
    return Case("unsigned_enum", 4, False)


def run_cli(directory, case, row, assertion_enum=False):
    cli = Path(os.environ.get("KUNA_CLI", ROOT / "decompiler/target/release/kuna")).resolve()
    row["producer"] = "cli-assertions" if not case.kind.endswith("enum") or assertion_enum else "cli-dwarf"
    bodies = []
    row["functions"] = []
    object_file = None
    if row["producer"] == "cli-dwarf":
        source = directory / "producer.c"
        source.write_text(case.source())
        object_file = directory / "producer.o"
        # O0 retains explicit narrow loads instead of the unrelated narrow-ABI
        # extension recovery path exercised by optimized EDI comparisons.
        row["producer_build"] = command(directory / "producer-build.json", [
            *shlex.split(os.environ.get("KUNA_MATRIX_CROSS_CC", "clang")),
            "-target", "x86_64-linux-gnu", "-g", "-O0", "-c", source, "-o", object_file,
        ])
    for index, target in enumerate(case.targets):
        name = f"boundary_{index}"
        if object_file is not None:
            args = [cli, "decompile", object_file, name, "--json"]
        else:
            machine = instructions(case.width, target)
            raw = directory / f"{name}.bin"
            raw.write_bytes(machine)
            args = [cli, "decompile", raw, "0x1000", "--json", "--raw-image", "--target",
                    "x86:LE:64:default:gcc", "--base", "0x1000", "--define-function",
                    f"0x1000-0x{0x1000 + len(machine):x}={name}", "--assert-strict"]
            if assertion_enum:
                args += ["--assert", case.assertion()]
            args += ["--assert", f"prototype {name} int {name}({case.ctype} value)"]
        result = command(directory / f"{name}-cli.json", args)
        payload = json.loads(result["stdout"])
        assert payload.get("error") is None, payload
        function, = payload["functions"]
        assert function.get("error") is None, function
        parameter, = [v for v in function["variables"] if v.get("kind") == "arg" and v.get("arg_index") == 0]
        assert parameter["size"] == case.width, parameter
        if object_file is None:
            assert all(a["status"] == "applied" for a in payload["assertions"]), payload["assertions"]
        row["functions"].append({"target_bits": target, "parameter": parameter, "assertions": payload["assertions"]})
        bodies.append(function["code"])
    emitted = "\n\n".join(bodies) + "\n"
    (directory / "emitted.c").write_text(emitted)
    row["execution"] = execute_consumer(directory, case, emitted, "cli")


def run_ghidra(directory, case, row, stock=False):
    from jpype import JArray, JByte
    from java.lang import Object
    from ghidra.app.decompiler import DecompInterface, DecompileOptions
    from ghidra.app.emulator import EmulatorHelper
    from ghidra.program.database import ProgramDB
    from ghidra.program.flatapi import FlatProgramAPI
    from ghidra.program.model.data import (
        CategoryPath, EnumDataType, CharDataType, SignedCharDataType, UnsignedCharDataType,
        ShortDataType, UnsignedShortDataType, IntegerDataType, UnsignedIntegerDataType,
        DataTypeConflictHandler,
    )
    from ghidra.program.model.lang import LanguageID, CompilerSpecID
    from ghidra.program.model.listing import Function, ParameterImpl, ReturnParameterImpl, Variable
    from ghidra.program.model.symbol import SourceType
    from ghidra.program.util import DefaultLanguageService
    from ghidra.util.task import ConsoleTaskMonitor
    from kuna_vs_stock import KUNA_GHIDRA, get_exepath_field

    monitor = ConsoleTaskMonitor()
    language = DefaultLanguageService.getLanguageService().getLanguage(LanguageID("x86:LE:64:default"))
    owner = Object()
    program = ProgramDB(case.name, language, language.getCompilerSpecByID(CompilerSpecID("gcc")), owner)
    field = get_exepath_field()
    previous = field.get(None)
    interface = DecompInterface()
    row["producer"] = "ghidra-stock" if stock else "ghidra-kuna"
    try:
        api = FlatProgramAPI(program, monitor)
        manager = program.getDataTypeManager()
        tx = program.startTransaction("Width and signedness boundary fixture")
        try:
            if case.kind.endswith("enum"):
                dtype = EnumDataType(CategoryPath.ROOT, "Flags", case.width, manager)
                for name, value in case.enum_values.items():
                    dtype.add(name, value)
                dtype = manager.resolve(dtype, DataTypeConflictHandler.DEFAULT_HANDLER)
                assert bool(dtype.isSigned()) == case.signed, str(dtype)
            elif case.kind == "char":
                dtype = CharDataType.dataType
            else:
                dtype = {(1, True): SignedCharDataType, (1, False): UnsignedCharDataType,
                         (2, True): ShortDataType, (2, False): UnsignedShortDataType,
                         (4, True): IntegerDataType, (4, False): UnsignedIntegerDataType}[(case.width, case.signed)].dataType
            assert int(dtype.getLength()) == case.width, str(dtype)
            row["producer_type"] = {"name": str(dtype.getName()), "width": int(dtype.getLength()), "signed": case.signed}
            functions = []
            for index, target in enumerate(case.targets):
                machine = instructions(case.width, target)
                address = program.getAddressFactory().getDefaultAddressSpace().getAddress(0x1000 + index * 0x100)
                block = api.createMemoryBlock(f"code_{index}", address, JArray(JByte)(machine), False)
                block.setExecute(True)
                assert api.disassemble(address), case.name
                function = api.createFunction(address, f"boundary_{index}")
                function.updateFunction("__stdcall", ReturnParameterImpl(IntegerDataType.dataType, program),
                                        Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS, False,
                                        SourceType.USER_DEFINED, JArray(Variable)([ParameterImpl("value", dtype, program)]))
                functions.append((function, target, address.add(len(machine) - 1)))
        finally:
            program.endTransaction(tx, True)
        row["original_execution"] = []
        for function, target, end in functions:
            for value in case.witnesses:
                emulator = EmulatorHelper(program)
                try:
                    emulator.writeRegister("RDI", value if value < (1 << 63) else value - (1 << 64))
                    emulator.setBreakpoint(end)
                    assert emulator.run(function.getEntryPoint(), None, monitor), str(emulator.getLastError())
                    actual = int(str(emulator.readRegister("EAX")))
                    assert actual == int(value == target), (value, target, actual)
                    row["original_execution"].append({"input_bits": value, "target_bits": target, "result": actual})
                finally:
                    emulator.dispose()
        field.set(None, None if stock else KUNA_GHIDRA)
        interface.setOptions(DecompileOptions())
        assert interface.openProgram(program), str(interface.getLastMessage())
        bodies = []
        row["functions"] = []
        for function, target, _ in functions:
            result = interface.decompileFunction(function, 60, monitor)
            assert result.decompileCompleted() and not str(result.getErrorMessage()), str(result.getErrorMessage())
            parameter = result.getHighFunction().getFunctionPrototype().getParam(0)
            assert parameter.getDataType().isEquivalent(dtype), str(parameter.getDataType())
            assert int(parameter.getDataType().getLength()) == case.width
            assert str(parameter.getName()) == "value"
            row["functions"].append({"target_bits": target, "parameter_type": str(parameter.getDataType()),
                                     "storage": str(parameter.getStorage())})
            bodies.append(str(result.getDecompiledFunction().getC()))
        emitted = "\n\n".join(bodies) + "\n"
        (directory / "emitted.c").write_text(emitted)
        row["execution"] = execute_consumer(
            directory, case, emitted, row["producer"], warnings_as_errors=not stock,
        )
    finally:
        interface.dispose()
        field.set(None, previous)
        program.release(owner)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--producer", choices=("both", "cli", "ghidra"), default="both")
    parser.add_argument("--case", action="append", help="select a case, e.g. unsigned1 or signed_enum2")
    parser.add_argument("--surface", action="append", choices=("cli", "cli-default-enum", "ghidra", "stock"),
                        help="select a producer surface within the case filter")
    parser.add_argument("--stock", action="store_true",
                        help="retain additive diagnostic stock comparisons in product runs; stock-controls selects stock directly")
    args = parser.parse_args()
    from kuna_vs_stock import test_cores
    product = "kuna" in test_cores()
    selected = [case for case in cases() if not args.case or case.name in args.case]
    assert selected and (not args.case or set(args.case) <= {case.name for case in selected}), args.case
    output = Path(os.environ.get("KUNA_SMOKE_OUT", "live-integer-boundaries-out")).resolve()
    output.mkdir(parents=True, exist_ok=True)
    report = {"completed": False, "status": "running", "rows": [],
              "method": {"widths": [1, 2, 4], "target_rules": "zero, one, sign boundary, complement one, complement OR, maximum",
                         "byte_input_domain": "all 256 bit patterns", "wider_input_domain": "target +/- 1 and flag/control values",
                         "focused_extra": "signed enum64 complement of a 32-bit enumerator",
                         "cli_enum_producer": "DWARF packed enums; default-width enum uses source assertions",
                         "plain_char_mode": "signed to match x86 gcc producer; explicit signed/unsigned types run both host modes"}}
    path = output / "integer_boundaries.json"
    try:
        if args.producer != "cli":
            import pyghidra
            from kuna_vs_stock import start_ghidra
            start_ghidra()
        for case in selected:
            variants = []
            if product and args.producer != "ghidra":
                variants.append("cli")
                if case.name == "unsigned_enum4":
                    variants.append("cli-default-enum")
            if args.producer != "cli":
                if product:
                    variants.append("ghidra")
                if not product or args.stock:
                    variants.append("stock")
            if args.surface:
                variants = [variant for variant in variants if variant in args.surface]
            for variant in variants:
                row = {"case": case.name, "producer": variant, "status": "running",
                       "diagnostic_only": product and variant == "stock",
                       "role": "stock-control" if variant == "stock" else "product"}
                report["rows"].append(row)
                directory = output / f"{case.name}-{variant}"
                directory.mkdir(parents=True, exist_ok=True)
                try:
                    effective_case = cli_default_enum(directory, row) if variant == "cli-default-enum" else case
                    row["source_control"] = check_source(directory, effective_case)
                    if variant.startswith("cli"):
                        run_cli(directory, effective_case, row, variant == "cli-default-enum")
                    else:
                        run_ghidra(directory, case, row, variant == "stock")
                    row["status"] = "passed"
                except BaseException:
                    row["status"] = "failed"
                    row["failure"] = traceback.format_exc()
                print(f"{row['status'].upper()} {variant}: {case.name}", flush=True)
                path.write_text(json.dumps(report, indent=2) + "\n")
        report["completed"] = True
        report["status"] = "failed"
        semantic_rows = [row for row in report["rows"] if not row["diagnostic_only"]]
        assert semantic_rows, (
            "filters selected no Kuna scenarios; stock is an additive diagnostic only"
            if product else "filters selected no stock-control scenarios"
        )
        failures = [row for row in semantic_rows if row["status"] != "passed"]
        report["status"] = "failed" if failures else "passed"
        assert not failures, [(row["producer"], row["case"], row.get("failure")) for row in failures]
    finally:
        path.write_text(json.dumps(report, indent=2) + "\n")


if __name__ == "__main__":
    main()
