# Restoration and native-boundary preservation

Entrypoint (no mandatory arguments):

```sh
python3 tests/ghidra/callable/restoration_boundaries.py
```

Use the Python environment containing PyGhidra/JPype and a configured Ghidra installation. Set `KUNA_CLI` to the current production CLI; `KUNA_SMOKE_OUT` selects the parent of unique output directories. Native raw-image probes do not invoke `kuna_ghidra`, so `KUNA_GHIDRA_EXE` is not required by this slice. C compilers are resolved by `support.tool('cc')`, including `KUNA_CC`. Explicit `--cli` and `--out` overrides are supported. Reusing an existing child output fails rather than consuming stale results.

All fixture instructions and initial data are embedded in the maintained Python sources. They are preserved from the round-6 ProtoFacts probes, not read from ignored output. The x86-64 probes reuse maintained `whole_calls.Machine` and `rel`; the restoration-edge probe retains its original direct ProgramDB emulator setup because its matrix also includes x86-32. Current metadata, generated C/H, compiler output, machine observations, and result reports are written into the selected output directory. No historical binaries, reports, or generated bodies are inputs.

## Exact matrix

- `private_frame_aliases.py`: branch alias (0, 1, MAX), partially saved pointer, partial local pointer write, AL-only child write, passed frame, callback frame, delayed escape before saving RBP, and disjoint memory. Saved-frame hazards may explicitly refuse publication or execute behaviorally correct unchanged C. The disjoint store must publish and run at O0/O2, return 42, store 7, and preserve the outer RBP in the original machine.
- `aggregate_frame_escape.py`: authentic JOIN `Pair{pointer,tag}` callback argument, including exact RDI/RSI storage pieces. Saved-frame alias requires explicit refusal; disjoint memory requires unchanged C/H execution at O0/O2. Original-machine observations include outer RBP and callback memory effects. The consumer supplies external fixture data `Writer callback_slot=writer` in a separate translation unit, matching the emitted header's extern declaration and the authenticated original eight-byte slot at 0x1300 pointing to writer at 0x1200. No target function or emitted body is replaced.
- `restoration_edges.py`: saved stack slot with preserved EBX, conditional copying with conditions 0/1/UINT32_MAX and wide values, custom RBX output, and JOIN EDX:EAX output. Saved-slot behavior may refuse or execute correctly. The other three are strict publication and O0/O2 positives.
- `preserved_register_effect.py`: genuine child RBX clobber returns 7; genuine save/restore returns 42. Only the clobber case may refuse. The aggregator isolates these scenarios so one failure does not hide the other.
- `native_bool_boundary.py`: real MOVZX body sees byte 0/1/255 with clean and dirty upper RDI bits. Authentic BOOL parameters occupy DIL:1. The unresolved callback must explicitly refuse export; this is not a native `_Bool` canonical-range proof or an emitted-C positive.
- `finite_variadic_boundaries.py`: incoming stack tail at RSP+8 and typed variadic-pointer escape retain source arity/varargs and require explicit refusal. The finite register target is independently executed on the original machine and required to have no callable-export error. As in the original probe, this target is not separately exported/executed in C: the whole unit contains a refusing pointer provider. This is a remaining C-consumer proof limitation, not an O0/O2 success claim.
- `callback_effects.py`: loaded-global native callback only. The actual RET target preserves incoming RAX=85; the diagnostic raw CALL operand must retain that state and publication must explicitly refuse. Generic ECX and standalone RET modes are excluded because maintained Rust tests already cover them.
- `mixed_flow_return.py`: one function combines ordinary RET and marked CALL_RETURN. Balanced flow is a strict whole-project C/H O0/O2 positive. Malformed ordinary RET 8 must refuse. Original machine conditions 0/1/MAX observe stack delta 16 only on the malformed ordinary path, versus 8 elsewhere.

## Admission and limitations

Refusals require real `callable_export_error` metadata and a failed project publication, not diagnostic-comment wording. Every strict positive remains a positive: current production admission failures, malformed C, compiler failures, and wrong results fail the suite. No blanket guard waiver, repaired emitted C, handwritten target body, or synthetic summary is used. Consumers link the unchanged emitted project with an external observation-only driver.

Each multi-case probe records individual failures; the aggregator continues through every child and exits nonzero if any child fails or lacks a completed report. Missing prerequisites fail, never skip.

The aggregate fixture passes with its genuine external callback-slot definition. The restored-register positive returns 42 on the original machine but production refuses publication for a callable address escape at 0x100c. That remains a failure, not an expected refusal.
