#!/usr/bin/env python3
"""Consume real declarations, collision descriptors and committed dynamic renames."""

import json
import os
from pathlib import Path
import tempfile
import traceback

import pyghidra

from kuna_vs_stock import KUNA_GHIDRA, REPO, get_exepath_field, start_ghidra, test_cores


def main():
    start_ghidra()
    from java.util import IdentityHashMap
    from ghidra.app.decompiler import ClangVariableDecl, DecompInterface, DecompileOptions
    from ghidra.program.model.address import AddressSpace
    from ghidra.program.model.listing import LocalVariableImpl, VariableStorage
    from ghidra.program.model.pcode import DynamicEntry, DynamicHash, HighFunctionDBUtil
    from ghidra.program.model.symbol import SourceType
    from ghidra.util.task import ConsoleTaskMonitor

    output = Path(os.environ.get("KUNA_SMOKE_OUT", "live-symbol-replay-out")).resolve()
    output.mkdir(parents=True, exist_ok=True)
    field = get_exepath_field()
    original = field.get(None)
    monitor = ConsoleTaskMonitor()
    rows = []

    def decompile(interface, function):
        result = interface.decompileFunction(function, 120, monitor)
        assert result.decompileCompleted(), str(result.getErrorMessage())
        assert result.getHighFunction() is not None
        assert result.getDecompiledFunction() is not None
        assert result.getCCodeMarkup() is not None
        return result

    def target(vn):
        return {"space": str(vn.getAddress().getAddressSpace().getName()),
                "offset": int(vn.getOffset()), "size": int(vn.getSize())}

    def replay(high, symbol):
        code = symbol.getStorage().getMinAddress().getOffset()
        found = DynamicHash.findVarnode(high, symbol.getPCAddress(), code)
        resolved = found.getHigh().getSymbol() if found is not None and found.getHigh() is not None else None
        row = {"name": str(symbol.getName()), "hash": int(code), "pc": str(symbol.getPCAddress()),
               "pc_space": str(symbol.getPCAddress().getAddressSpace().getName()),
               "resolved": resolved is not None and resolved.getId() == symbol.getId()}
        assert row["resolved"], row
        row["target"] = target(found)
        return row

    try:
        with tempfile.TemporaryDirectory(prefix="ghidra-symbols-", dir=output) as directory:
            with pyghidra.open_program(Path(REPO) / "tests/bug-repro/faillog", project_location=directory,
                                      project_name="symbols", analyze=True) as api:
                program = api.getCurrentProgram()
                for core in test_cores():
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
                            row = {"case": "declarations", "core": core,
                                   "entry": str(function.getEntryPoint()), "declarations": [], "dynamic": []}
                            rows.append(row)
                            try:
                                def declarations(node):
                                    if isinstance(node, ClangVariableDecl):
                                        symbol = node.getHighSymbol()
                                        row["declarations"].append({"text": str(node), "resolved": symbol is not None})
                                        assert symbol is not None, row["declarations"][-1]
                                    for i in range(node.numChildren()):
                                        declarations(node.Child(i))
                                declarations(result.getCCodeMarkup())
                                for symbol in high.getLocalSymbolMap().getSymbols():
                                    if symbol.getStorage().isHashStorage():
                                        row["dynamic"].append(replay(high, symbol))
                                row["passed"] = True
                            except Exception:
                                row["failure"] = traceback.format_exc()
                                row["passed"] = False

                            if core == "kuna" and offset == 0x2620:
                                collision = {"case": "committed_colliding_dynamic_rename",
                                             "core": core, "passed": False}
                                rows.append(collision)
                                committed = None
                                try:
                                    candidates = []
                                    for root in high.locRange():
                                        variable = root.getHigh()
                                        if root.isConstant() or variable is None or variable.getSymbol() is None:
                                            continue
                                        symbol = variable.getSymbol()
                                        if (symbol.isGlobal() or symbol.isParameter()
                                                or variable.getDataType().getLength() != root.getSize()):
                                            continue
                                        descriptor = DynamicHash(root, high)
                                        code, pc = descriptor.getHash(), descriptor.getAddress()
                                        if not code or DynamicHash.getTotalFromHash(code) <= 1:
                                            continue
                                        found = DynamicHash.findVarnode(high, pc, code)
                                        identity = IdentityHashMap()
                                        identity.put(root, True)
                                        if found is not None and identity.containsKey(found):
                                            candidates.append((root, variable, code, pc))
                                            break
                                    assert candidates, "original High graph has no verified colliding local source"
                                    root, variable, code, pc = candidates[0]
                                    before = {"hash": int(code), "pc": str(pc),
                                              "pc_space": str(pc.getAddressSpace().getName()), "target": target(root)}
                                    collision["before"] = before
                                    collision["total"] = int(DynamicHash.getTotalFromHash(code))
                                    source = str(function.getSignature())
                                    tx = program.startTransaction("Author a verified colliding hash local")
                                    try:
                                        storage = VariableStorage(program, AddressSpace.HASH_SPACE.getAddress(code),
                                                                  root.getSize())
                                        local = LocalVariableImpl("kuna_collision_source",
                                                                  int(pc.subtract(function.getEntryPoint())),
                                                                  variable.getDataType(), storage, program)
                                        committed = function.addLocalVariable(local, SourceType.USER_DEFINED)
                                    except BaseException:
                                        program.endTransaction(tx, False)
                                        raise
                                    else:
                                        program.endTransaction(tx, True)
                                    db_id = int(committed.getSymbol().getID())
                                    assert committed.getVariableStorage().isHashStorage()
                                    assert int(committed.getVariableStorage().getMinAddress().getOffset()) == int(code)
                                    assert committed.getLength() == root.getSize()
                                    assert committed.getDataType().isEquivalent(variable.getDataType())
                                    assert committed.getFirstUseOffset() == int(pc.subtract(function.getEntryPoint()))
                                    assert committed.getSource() == SourceType.USER_DEFINED
                                    interface.flushCache()
                                    imported = decompile(interface, function)
                                    matches = [item for item in imported.getHighFunction().getLocalSymbolMap().getSymbols()
                                               if int(item.getId()) == db_id]
                                    assert len(matches) == 1, "committed colliding source was not imported exactly once"
                                    imported_identity = replay(imported.getHighFunction(), matches[0])
                                    for key in ("hash", "pc", "pc_space", "target"):
                                        assert imported_identity[key] == before[key], collision
                                    tx = program.startTransaction("Rename the imported colliding dynamic local")
                                    try:
                                        HighFunctionDBUtil.updateDBVariable(matches[0], "kuna_hash_replay_probe",
                                                                           None, SourceType.USER_DEFINED)
                                    except BaseException:
                                        program.endTransaction(tx, False)
                                        raise
                                    else:
                                        program.endTransaction(tx, True)
                                    assert int(committed.getSymbol().getID()) == db_id
                                    interface.flushCache()
                                    updated = decompile(interface, function)
                                    matches = [item for item in updated.getHighFunction().getLocalSymbolMap().getSymbols()
                                               if str(item.getName()) == "kuna_hash_replay_probe"]
                                    assert len(matches) == 1, "committed colliding rename did not return exactly once"
                                    assert int(matches[0].getId()) == db_id
                                    assert "kuna_hash_replay_probe" in str(updated.getDecompiledFunction().getC())
                                    assert matches[0].getStorage().isHashStorage()
                                    collision["after"] = replay(updated.getHighFunction(), matches[0])
                                    for key in ("hash", "pc", "pc_space", "target"):
                                        assert collision["after"][key] == before[key], collision
                                    assert str(function.getSignature()) == source
                                    collision["passed"] = True
                                except Exception:
                                    collision["failure"] = traceback.format_exc()
                                finally:
                                    if committed is not None:
                                        tx = program.startTransaction("Remove collision source fixture")
                                        try:
                                            function.removeVariable(committed)
                                        finally:
                                            program.endTransaction(tx, True)

                                rename = {"case": "committed_dynamic_rename", "core": core, "passed": False}
                                rows.append(rename)
                                try:
                                    interface.flushCache()
                                    high = decompile(interface, function).getHighFunction()
                                    symbols = [symbol for symbol in high.getLocalSymbolMap().getSymbols()
                                               if str(symbol.getName()) == "v1"]
                                    assert len(symbols) == 1, symbols
                                    symbol = symbols[0]
                                    variable = symbol.getHighVariable()
                                    root = variable.getRepresentative()
                                    assert not symbol.isGlobal() and not symbol.isParameter()
                                    assert variable.requiresDynamicStorage() and root.isUnique()
                                    entry = DynamicEntry.build(root)
                                    code, pc = entry.getHash(), entry.getPCAdress()
                                    found = DynamicHash.findVarnode(high, pc, code)
                                    identity = IdentityHashMap()
                                    identity.put(root, True)
                                    assert code and found is not None and identity.containsKey(found)
                                    before = {"hash": int(code), "pc": str(pc),
                                              "pc_space": str(pc.getAddressSpace().getName()), "target": target(root)}
                                    rename["before"] = before
                                    source = str(function.getSignature())
                                    new_name = "kuna_hash_replay_probe"
                                    tx = program.startTransaction("Rename an actual dynamic local")
                                    try:
                                        HighFunctionDBUtil.updateDBVariable(symbol, new_name, None, SourceType.USER_DEFINED)
                                    except BaseException:
                                        program.endTransaction(tx, False)
                                        raise
                                    else:
                                        program.endTransaction(tx, True)
                                    committed = [local for local in function.getLocalVariables()
                                                 if str(local.getName()) == new_name]
                                    assert len(committed) == 1 and committed[0].getVariableStorage().isHashStorage()
                                    assert int(committed[0].getVariableStorage().getMinAddress().getOffset()) == before["hash"]
                                    interface.flushCache()
                                    updated = decompile(interface, function)
                                    matches = [item for item in updated.getHighFunction().getLocalSymbolMap().getSymbols()
                                               if str(item.getName()) == new_name]
                                    assert len(matches) == 1, "committed dynamic rename did not return exactly once"
                                    assert new_name in str(updated.getDecompiledFunction().getC())
                                    assert matches[0].getStorage().isHashStorage()
                                    rename["after"] = replay(updated.getHighFunction(), matches[0])
                                    for key in ("hash", "pc", "pc_space", "target"):
                                        assert rename["after"][key] == before[key], rename
                                    assert str(function.getSignature()) == source
                                    rename["passed"] = True
                                except Exception:
                                    rename["failure"] = traceback.format_exc()
                                finally:
                                    tx = program.startTransaction("Remove dynamic rename fixture")
                                    try:
                                        for local in function.getLocalVariables():
                                            if str(local.getName()) == "kuna_hash_replay_probe":
                                                function.removeVariable(local)
                                    finally:
                                        program.endTransaction(tx, True)
                    finally:
                        interface.dispose()
        assert all(row.get("passed") for row in rows), [row for row in rows if not row.get("passed")]
    finally:
        field.set(None, original)
        (output / "symbol_replay.json").write_text(json.dumps(rows, indent=2) + "\n")


if __name__ == "__main__":
    main()
