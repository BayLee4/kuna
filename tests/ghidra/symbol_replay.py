#!/usr/bin/env python3
"""Resolve declarations and dynamic symbol identities with Ghidra's Java consumer.

Uses the suite environment from README.md and the repository's faillog
fixture. Also commits and replays a rename for a colliding dynamic symbol.
"""

import json
import os
from pathlib import Path
import tempfile

import pyghidra

from kuna_vs_stock import KUNA_GHIDRA, REPO, get_exepath_field


def main():
    pyghidra.start()
    from ghidra.app.decompiler import ClangVariableDecl, DecompInterface, DecompileOptions
    from ghidra.program.model.pcode import DynamicHash, HighFunctionDBUtil
    from ghidra.program.model.symbol import SourceType
    from ghidra.util.task import ConsoleTaskMonitor

    output = Path(os.environ.get("KUNA_SMOKE_OUT", "live-symbol-replay-out")).resolve()
    output.mkdir(parents=True, exist_ok=True)
    fixture = Path(REPO) / "tests/bug-repro/faillog"
    field = get_exepath_field()
    original = field.get(None)
    monitor = ConsoleTaskMonitor()
    rows = []
    renamed = False

    def decompile(interface, function):
        result = interface.decompileFunction(function, 120, monitor)
        assert result.decompileCompleted(), str(result.getErrorMessage())
        assert result.getHighFunction() is not None
        assert result.getDecompiledFunction() is not None
        return result

    def replay(high, symbol):
        storage = symbol.getStorage()
        code = storage.getMinAddress().getOffset()
        found = DynamicHash.findVarnode(high, symbol.getPCAddress(), code)
        resolved = found.getHigh().getSymbol() if found is not None and found.getHigh() is not None else None
        row = {"name": str(symbol.getName()), "hash": int(code), "pc": str(symbol.getPCAddress()),
               "pc_space": str(symbol.getPCAddress().getAddressSpace().getName()),
               "resolved": resolved is not None and resolved.getId() == symbol.getId()}
        assert row["resolved"], row
        row["target"] = {"space": str(found.getAddress().getAddressSpace().getName()),
                         "offset": int(found.getAddress().getOffset()), "size": int(found.getSize())}
        return row

    try:
        with tempfile.TemporaryDirectory(prefix="ghidra-symbols-", dir=output) as directory:
            with pyghidra.open_program(fixture, project_location=directory,
                    project_name="symbols", analyze=True) as api:
                program = api.getCurrentProgram()
                for core in ("stock", "kuna"):
                    field.set(None, KUNA_GHIDRA if core == "kuna" else None)
                    interface = DecompInterface()
                    interface.setOptions(DecompileOptions())
                    try:
                        assert interface.openProgram(program), str(interface.getLastMessage())
                        for offset in (0x2620, 0x3320, 0x3ad0):
                            function = program.getFunctionManager().getFunctionAt(program.getImageBase().add(offset))
                            assert function is not None, f"missing fixture function at offset {offset:x}"
                            result = decompile(interface, function)
                            high = result.getHighFunction()
                            row = {"core": core, "entry": str(function.getEntryPoint()),
                                   "declarations": [], "dynamic": []}
                            rows.append(row)

                            def declarations(node):
                                if isinstance(node, ClangVariableDecl):
                                    symbol = node.getHighSymbol()
                                    row["declarations"].append({"text": str(node), "resolved": symbol is not None})
                                    assert symbol is not None, row["declarations"][-1]
                                for i in range(node.numChildren()):
                                    declarations(node.Child(i))

                            declarations(result.getCCodeMarkup())
                            candidate = None
                            for symbol in high.getLocalSymbolMap().getSymbols():
                                if not symbol.getStorage().isHashStorage():
                                    continue
                                identity = replay(high, symbol)
                                row["dynamic"].append(identity)
                                code = symbol.getStorage().getMinAddress().getOffset()
                                if DynamicHash.getTotalFromHash(code) > 1:
                                    candidate = (symbol, identity)
                            if core == "kuna" and candidate is not None and not renamed:
                                symbol, identity = candidate
                                new_name = "kuna_hash_replay_probe"
                                tx = program.startTransaction("Rename a colliding dynamic local")
                                try:
                                    HighFunctionDBUtil.updateDBVariable(symbol, new_name, None, SourceType.USER_DEFINED)
                                except BaseException:
                                    program.endTransaction(tx, False)
                                    raise
                                else:
                                    program.endTransaction(tx, True)
                                interface.flushCache()
                                updated = decompile(interface, function)
                                matches = [s for s in updated.getHighFunction().getLocalSymbolMap().getSymbols()
                                           if str(s.getName()) == new_name]
                                assert len(matches) == 1, "committed dynamic rename did not return on re-decompile"
                                assert new_name in str(updated.getDecompiledFunction().getC())
                                assert matches[0].getStorage().isHashStorage(), "rename lost its dynamic mapping"
                                row["renamed"] = replay(updated.getHighFunction(), matches[0])
                                for key in ("hash", "pc", "pc_space", "target"):
                                    assert row["renamed"][key] == identity[key], f"rename changed target {key}: {row}"
                                renamed = True
                            print(f"PASS {core} {row['entry']}: {len(row['declarations'])} declarations, "
                                  f"{len(row['dynamic'])} dynamic identities", flush=True)
                    finally:
                        interface.dispose()
        assert renamed, "fixture no longer exercises a colliding dynamic-symbol rename"
    finally:
        field.set(None, original)
        (output / "symbol_replay.json").write_text(json.dumps(rows, indent=2) + "\n")


if __name__ == "__main__":
    main()
