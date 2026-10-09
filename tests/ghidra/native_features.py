#!/usr/bin/env python3
"""Actual FunctionGraph and BSim consumers on identical stock/Kuna ProgramDB inputs."""
from collections import Counter
import json
import os
from pathlib import Path
import traceback

from kuna_vs_stock import KUNA_GHIDRA, selected_core, start_ghidra


def main():
    output = Path(os.environ.get("KUNA_SMOKE_OUT", "live-native-features"))
    output.mkdir(parents=True, exist_ok=True)
    report = {"completed": False, "passed": False, "rows": []}
    program = None
    try:
        start_ghidra()
        from jpype import JArray, JByte, JInt
        from java.io import File
        from java.lang import Object, StringBuffer
        from java.util import IdentityHashMap
        from ghidra.app.decompiler import DecompInterface, DecompileOptions
        from ghidra.app.decompiler.signature import VarnodeSignature, BlockSignature
        from ghidra.program.database import ProgramDB
        from ghidra.program.flatapi import FlatProgramAPI
        from ghidra.program.model.data import IntegerDataType
        from ghidra.program.model.lang import LanguageID, CompilerSpecID
        from ghidra.program.model.listing import Function, ParameterImpl, ReturnParameterImpl, Variable
        from ghidra.program.model.pcode import BlockGraph, BlockCopy, PcodeBlock
        from ghidra.program.model.symbol import SourceType
        from ghidra.program.util import DefaultLanguageService
        from ghidra.util.task import ConsoleTaskMonitor
        from generic.lsh.vector import WeightedLSHCosineVectorFactory
        from ghidra.xml import XmlPullParserFactory
        owner = Object()
        monitor = ConsoleTaskMonitor()
        language = DefaultLanguageService.getLanguageService().getLanguage(LanguageID("x86:LE:64:default"))
        program = ProgramDB("native-features", language, language.getCompilerSpecByID(CompilerSpecID("gcc")), owner)
        api = FlatProgramAPI(program, monitor)
        address = program.getAddressFactory().getDefaultAddressSpace().getAddress
        tx = program.startTransaction("Proven add-three source fixture")
        try:
            block = api.createMemoryBlock("subject", address(0x1000), JArray(JByte)(bytes.fromhex("89f883c003c3")), False)
            block.setExecute(True)
            assert api.disassemble(address(0x1000))
            function = api.createFunction(address(0x1000), "add_three")
            function.updateFunction("__stdcall", ReturnParameterImpl(IntegerDataType.dataType, program),
                Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS, False, SourceType.USER_DEFINED,
                JArray(Variable)([ParameterImpl("value", IntegerDataType.dataType, program)]))
        finally:
            program.endTransaction(tx, True)
        weights = Path(os.environ.get("KUNA_BSIM_WEIGHTS", Path(os.environ["GHIDRA_INSTALL_DIR"]) /
                       "Ghidra/Features/BSim/data/lshweights_64.xml"))
        if not weights.is_file():
            raise FileNotFoundError("Real BSim database weights required: " + str(weights))
        factory = WeightedLSHCosineVectorFactory()
        parser = XmlPullParserFactory.create(File(str(weights)), None, False)
        try:
            factory.readWeights(parser)
        finally:
            parser.dispose()
        assert int(factory.getSettings()) == 73
        stock = {}
        for core, exe in (("stock", None), ("kuna", KUNA_GHIDRA)):
            with selected_core(exe):
                interface = DecompInterface()
                try:
                    assert interface.setOptions(DecompileOptions())
                    assert interface.openProgram(program), str(interface.getLastMessage())
                    def check(name, invoke):
                        row = {"core": core, "case": name}
                        report["rows"].append(row)
                        try:
                            row["value"] = invoke()
                            row["passed"] = True
                        except Exception:
                            row["passed"] = False
                            row["failure"] = traceback.format_exc()
                        row["last_message"] = str(interface.getLastMessage())
                        (output / "native_features.json").write_text(json.dumps(report, indent=2) + "\n")
                    def structure():
                        graph = BlockGraph()
                        refs = [Object() for _ in range(4)]
                        leaves = [BlockCopy(refs[i], address(0x1000+i)) for i in range(4)]
                        for leaf in leaves:
                            graph.addBlock(leaf)
                        graph.setIndices()
                        for a, b in ((0, 1), (0, 2), (1, 3), (2, 3)):
                            graph.addEdge(leaves[a], leaves[b])
                        assert leaves[0].getFalseOut() == leaves[1] and leaves[0].getTrueOut() == leaves[2]
                        result = interface.structureGraph(graph, 30, monitor)
                        assert result is not None, str(interface.getLastMessage())
                        found = []
                        types = []
                        seen = IdentityHashMap()
                        def leaf_ids(node):
                            if isinstance(node, BlockCopy):
                                return [int(node.getAltIndex())]
                            return sorted(index for child in range(node.getSize())
                                          for index in leaf_ids(node.getBlock(child)))
                        def walk(node):
                            types.append(int(node.getType()))
                            if isinstance(node, BlockCopy):
                                index = int(node.getAltIndex())
                                assert 0 <= index < 4
                                identity = IdentityHashMap()
                                identity.put(refs[index], True)
                                assert identity.containsKey(node.getRef()), index
                                assert node.getStart() == address(0x1000+index)
                                assert node.getStop() == node.getStart()
                                assert not seen.containsKey(node.getRef()), index
                                seen.put(node.getRef(), True)
                                found.append(index)
                                children = []
                            else:
                                assert isinstance(node, BlockGraph)
                                children = [walk(node.getBlock(index)) for index in range(node.getSize())]
                            return {"type": int(node.getType()), "leaves": leaf_ids(node),
                                    "children": children,
                                    "out": [leaf_ids(node.getOut(index)) for index in range(node.getOutSize())],
                                    "in": [leaf_ids(node.getIn(index)) for index in range(node.getInSize())]}
                        topology = walk(result)
                        assert sorted(found) == [0, 1, 2, 3], found
                        assert PcodeBlock.IFELSE in types, types
                        if core == "stock":
                            stock["topology"] = topology
                        else:
                            assert topology == stock["topology"], (topology, stock["topology"])
                        return {"leaf_indices": found, "types": types, "topology": topology,
                                "objects_addresses_branch_polarity_and_join_preserved": True}
                    def settings():
                        assert interface.setSignatureSettings(73), str(interface.getLastMessage())
                        version = [int(interface.getMajorVersion()), int(interface.getMinorVersion())]
                        assert version[0] > 0 and int(interface.getSignatureSettings()) == 73
                        return {"version": version, "settings": 73}
                    def signatures():
                        raw = interface.generateSignatures(function, True, 30, monitor)
                        assert raw is not None, str(interface.getLastMessage())
                        features = [int(value) for value in raw.features]
                        assert features and not raw.hasunimplemented and not raw.hasbaddata
                        assert list(raw.calllist) == [], list(raw.calllist)
                        debug = interface.debugSignatures(function, 30, monitor)
                        assert debug is not None, str(interface.getLastMessage())
                        hashes = [int(item.hash) for item in debug]
                        assert Counter(features) == Counter(hashes), (features, hashes)
                        origins = []
                        for item in debug:
                            buffer = StringBuffer()
                            item.printRaw(language, buffer)
                            binding = {"hash": int(item.hash), "kind": str(item.getClass().getSimpleName())}
                            if isinstance(item, VarnodeSignature):
                                assert item.vn.getSize() > 0
                                space = item.vn.getAddress().getAddressSpace()
                                binding.update(size=int(item.vn.getSize()), space=str(space.getName()),
                                               offset=None if space.isUniqueSpace() else int(item.vn.getOffset()),
                                               opcode=str(item.opcode) if item.opcode is not None else None,
                                               instruction=str(item.seqNum.getTarget()) if item.seqNum is not None else None)
                                if item.seqNum is not None:
                                    assert function.getBody().contains(item.seqNum.getTarget())
                            elif isinstance(item, BlockSignature):
                                assert function.getBody().contains(item.blockSeq)
                                binding.update(block=str(item.blockSeq),
                                               opcode=str(item.opcode) if item.opcode is not None else None,
                                               instruction=str(item.opSeq.getTarget()) if item.opSeq is not None else None,
                                               previous_opcode=str(item.previousOpcode) if item.previousOpcode is not None else None,
                                               previous_instruction=str(item.previousOpSeq.getTarget())
                                               if item.previousOpSeq is not None else None)
                            origins.append({"binding": binding, "origin": str(buffer)})
                        bound_origins = Counter(json.dumps(row["binding"], sort_keys=True) for row in origins)
                        if core == "stock":
                            stock["origins"] = bound_origins
                        else:
                            assert bound_origins == stock["origins"], (bound_origins, stock["origins"])
                        if core == "stock":
                            stock["features"] = Counter(features)
                        else:
                            assert Counter(features) == stock["features"], (features, stock)
                        vector = factory.buildVector(JArray(JInt)(sorted(features)))
                        assert vector.getEntries(), "Kuna/stock raw features did not yield a consumable BSim vector"
                        return {"hashes": features, "debug": origins,
                                "vector_entries": len(vector.getEntries()),
                                "vector_settings": int(factory.getSettings())}
                    check("structureGraph", structure)
                    check("get_set_signature_settings", settings)
                    check("generate_debug_signatures_and_vector", signatures)
                    def invalid_settings():
                        assert not interface.setSignatureSettings(0)
                        assert interface.setSignatureSettings(73)
                        return {"invalid_zero_rejected": True, "valid_73_recovered": True}
                    check("invalid_settings_recovery", invalid_settings)
                finally:
                    interface.dispose()
        report["completed"] = True
        report["passed"] = all(row["passed"] for row in report["rows"])
        assert report["passed"], "Native feature consumer failures; see native_features.json"
    except BaseException:
        report["failure"] = traceback.format_exc()
        raise
    finally:
        if program is not None:
            program.release(owner)
        (output / "native_features.json").write_text(json.dumps(report, indent=2) + "\n")


if __name__ == "__main__":
    main()
