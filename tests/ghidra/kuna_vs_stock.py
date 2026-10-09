#!/usr/bin/env python3
"""Shared real-Ghidra startup, native selection and unchanged CppExporter helpers."""
import os
import sys
from contextlib import contextmanager
from pathlib import Path

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
KUNA_GHIDRA = os.environ.get(
    "KUNA_GHIDRA_EXE",
    os.path.join(REPO, "decompiler", "target", "release", "kuna_ghidra"),
)
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
    """Start the real JVM; reject a patched consumer in the ordinary stock lane."""
    import pyghidra
    pyghidra.start()
    from ghidra.app.decompiler import DecompileResults
    methods = {str(method.getName()) for method in DecompileResults.class_.getMethods()}
    if "getCallableSupport" in methods or "getDiagnosticCallView" in methods:
        raise RuntimeError("Stock regression requires unmodified Ghidra Java; "
                           "GHIDRA_INSTALL_DIR selects an enhanced consumer")
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


