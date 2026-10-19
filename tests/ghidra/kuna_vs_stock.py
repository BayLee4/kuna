#!/usr/bin/env python3
"""Shared real-Ghidra startup, native selection and unchanged CppExporter helpers."""
import json
import os
import sys
from contextlib import contextmanager
from pathlib import Path

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
KUNA_GHIDRA = os.environ.get(
    "KUNA_GHIDRA_EXE",
    os.path.join(REPO, "decompiler", "target", "release", "kuna_ghidra"),
)


def test_cores():
    """Select independent product cases or stock regression observations."""
    group = os.environ.get("KUNA_GHIDRA_TEST_GROUP", "product")
    if group == "product":
        return ("kuna",)
    if group == "stock-controls":
        return ("stock",)
    raise ValueError("KUNA_GHIDRA_TEST_GROUP must be product or stock-controls: " + group)


def get_exepath_field():
    from ghidra.app.decompiler import DecompileProcessFactory
    cls = DecompileProcessFactory.class_
    try:
        f = cls.getDeclaredField("exepath")
        f.setAccessible(True)
        return f
    except Exception as e:
        print(f"FATAL: DecompileProcessFactory has no 'exepath' field here: {e}")
        print("Declared fields:")
        for fld in cls.getDeclaredFields():
            print(f"  {fld}")
        sys.exit(2)


def start_ghidra():
    """Start the real receiver; product checks require the complete Java integration."""
    cores = test_cores()
    import pyghidra
    pyghidra.start()
    from ghidra.app.decompiler import DecompileResults
    methods = {str(method.getName()) for method in DecompileResults.class_.getMethods()}
    if "getCallableSupport" in methods or "getDiagnosticCallView" in methods:
        raise RuntimeError("Legacy patched Ghidra Java with retired consumer APIs is unsupported; "
                           "use stock GHIDRA_INSTALL_DIR and an isolated normal-extension settings profile")
    required = {"isEnhancedResult", "getDataTypeManager", "hasCurrentSourceAuthority"}
    full_java = required <= methods
    if cores == ("kuna",) and not full_java:
        raise RuntimeError("Product tests require the full Kuna Java extension installed before JVM startup; "
                           "stock-controls may use unmodified Java for baseline comparison")
    if output := os.environ.get("KUNA_SMOKE_OUT"):
        from ghidra.framework import Application
        from ghidra.app.util.exporter import CppExporter
        receiver = {
            "group": os.environ.get("KUNA_GHIDRA_TEST_GROUP", "product"),
            "full_java": full_java,
            "ghidra_version": str(Application.getApplicationVersion()),
            "results_origin": str(DecompileResults.class_.getProtectionDomain().getCodeSource().getLocation()),
            "exporter_origin": str(CppExporter.class_.getProtectionDomain().getCodeSource().getLocation()),
        }
        directory = Path(output)
        directory.mkdir(parents=True, exist_ok=True)
        (directory / "receiver.json").write_text(json.dumps(receiver, indent=2) + "\n")
    return pyghidra


def stock_executable():
    from ghidra.app.decompiler import DecompileProcessFactory
    field = get_exepath_field()
    previous = field.get(None)
    try:
        field.set(None, None)
        process = DecompileProcessFactory.get()
        try:
            executable = str(field.get(None))
            if not Path(executable).is_file():
                raise RuntimeError("Stock native executable unavailable: " + executable)
            return executable
        finally:
            DecompileProcessFactory.release(process)
    finally:
        field.set(None, previous)


@contextmanager
def selected_core(executable=None):
    field = get_exepath_field()
    previous = field.get(None)
    if executable is not None and not Path(executable).is_file():
        raise FileNotFoundError("Native executable unavailable: " + str(executable))
    try:
        field.set(None, None if executable is None else str(executable))
        yield
    finally:
        field.set(None, previous)


def export_program(program, output_c, monitor=None, selection=None, comments=True, options=None):
    """Export genuine C/H/types/globals, without rewriting generated providers."""
    from java.io import File
    from ghidra.app.decompiler import DecompileOptions
    from ghidra.app.util.exporter import CppExporter
    from ghidra.util.task import ConsoleTaskMonitor
    if options is None:
        options = DecompileOptions()
    options.setWARNCommentIncluded(comments)
    exporter = CppExporter(options, True, True, True, True, False, "")
    return bool(exporter.export(File(str(output_c)), program, selection,
                                monitor if monitor is not None else ConsoleTaskMonitor()))


