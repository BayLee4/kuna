# Real-Ghidra integration suite

```bash
make test-ghidra-live
```

The repository's real Java/CLI consumer checks live in `tests/ghidra/`. This complements
`make test-ghidra`, which exercises the native protocol simulator without a
Ghidra installation. The individual Python files are isolated suite modules,
not separate tools to learn. Each runs in its own process because JVM startup,
Ghidra projects, and the native-core selection are process-global.

## Setup

Use Ghidra 12.x and its supported JDK. Activate a Python environment containing
`pyghidra`; Ghidra ships wheels for offline installation:

```bash
export GHIDRA_INSTALL_DIR=/path/to/ghidra
python3 -m venv .venv-ghidra
source .venv-ghidra/bin/activate
pip install --no-index --find-links \
  "$GHIDRA_INSTALL_DIR/Ghidra/Features/PyGhidra/pypkg/dist" pyghidra
make binaries
(cd decompiler && cargo build --release -p kuna-ghidra)
make test-ghidra-live
```

The suite also needs built SLEIGH specs, a native C11 compiler (`CC`, default
`cc`), and `clang` capable of producing x86-64 ELF objects for the CLI/DWARF
integer cases (`KUNA_MATRIX_CROSS_CC` overrides it). The callsite suite supports
Darwin arm64 and x86-64. Missing prerequisites fail rather than silently skip.
`PYTHON=/path/to/venv/bin/python` selects the interpreter without activation.
`KUNA_GHIDRA_EXE` and `KUNA_CLI` can select non-default release binaries.

## Selection and results

```bash
make test-ghidra-live LIVE_ARGS='--list'
make test-ghidra-live LIVE_ARGS='--suite types --suite pointers'
```

The default runs every self-contained regression suite below. A selected run
has the same failure semantics as the full run: a failed or aborted probe makes
the command fail. Python assertions must remain enabled.

Artifacts default to `decompiler/target/ghidra-live/`; `KUNA_SMOKE_OUT` or
`--out` changes that root. Each invocation gets a fresh `run-*` directory,
containing one directory and `output.log` per suite plus an aggregate
`report.json`. The root's `report.json` points to the latest invocation and is
invalidated before probes start, so stale success artifacts cannot pass a run.
Probe-specific JSON, emitted C, compiler output, and execution evidence remain
inside the corresponding suite directory.

| Suite | Consumer contract |
|---|---|
| `recovery` | Instruction-limit failure, recovery, and native-process reuse. |
| `prototypes` | Host parameter/return facts, custom storage, direct/indirect calls, aggregate roles, and executable C. |
| `types` | Callback and recursive aliases, host datatype IDs, signature commits, bitfields, atomic nominal names, and relative-pointer C export. |
| `pointers` | 8051 INTMEM/SFR qualifiers, alias preservation, same-offset named globals, original-instruction execution, and native object-reference checks. |
| `integers` | CLI and Ghidra integer/enum output compared with independent bitvector/source oracles. |
| `settings` | Options, action roots, flush/reopen lifecycle, and host edits. |
| `symbols` | Decoded symbol identities and persistent dynamic-symbol renames. |
| `callsites` | Caller-owned overrides, format analysis, and executable native ABI consumers. |
| `callable-consumers` | Integrated Java publication, source edits, exporter failures, and genuine native-import provenance; requires the isolated integrated installation described below. |
| `callable-transport` | Authentic mixed-width and returned callbacks, serial/stream/worker publication, finite aggregate targets, nondefault conventions and recursive datatype graphs. |
| `callable-readonly` | Original-machine readonly/mutable controls, branch-receipt publication, missing-provider refusal and unchanged emitted C. |
| `callable-internal-roles` | Actual MIPS role reads/restoration, private spill/reload/escape, inherited effects and unchanged-C publication. |
| `callable-restoration` | Actual private-frame aliases, aggregate escape, saved-register/slot restoration, native bool bytes, variadic and mixed-return boundaries. |
| `callable-graph-objects` | Source-built nested bindings, hidden aggregate results, named mutable objects and private-leaf provider identities. Historical Apple replay and selected-child proof limits are documented in `callable/fixtures/graph_and_objects.md`. |
| `callable-datatypes` | Actual Java publication and unchanged C consumers for signed/cross-boundary bitfields, pointer-to-array aliases, mixed direct/indirect returns and custom register-slice results. |

Arguments after `--` are supported only by the `integers` suite. A focused
integer investigation can select `--suite integers -- --producer cli --case
unsigned_enum1`. This is a diagnostic filter, not a different runner.
An integer run must include a Kuna scenario; `--stock` adds diagnostic controls
and cannot substitute for those scenarios.

## Proof standard

Stock comparison uses the actual Ghidra integration: reflection selects
`DecompileProcessFactory.exepath`, then the same Java producer drives stock or
`kuna_ghidra`. No extension installation is needed. **Stock is a control, not an
oracle.** Inherited wrong output is still a defect; agreement cannot establish
correctness. Cases stock cannot represent correctly are explicitly identified,
not accepted as expected Kuna failures.

The integer suite also invokes the real `kuna` CLI. Primitive declarations come
from CLI assertions; packed enums come from real DWARF, avoiding unsupported
assertion syntax. A shared enum-value map feeds all producer and consumer
representations. The deterministic matrix crosses widths 1/2/4 and signedness
with zero, one, sign boundaries, complements, and maxima; byte consumers execute
all 256 bit patterns, wider consumers boundary neighbors. A focused 64-bit case
checks a narrower C enumerator. Unchanged emitted C executes at `-O0`/`-O2` with
plain-char modes appropriate to the declared input. Exact width/sign assertions,
original-instruction emulation, and independent source controls separate fixture
errors from backend defects. This is bounded semantic probing, not exhaustive
fuzzing.

The pointer suite checks address-bank selection through Ghidra's explicit
qualifier API. High-level CLI declaration assertions do not expose that API;
a standalone console typed-pointer check is not equivalent to a CLI bank-name
recovery test.

These checks exercise Java APIs and exported C, not GUI dialogs.
`getDecompiledFunction().getC()` sanitizes identifiers through Java's
`IllegalCharCppTransformer`; raw panel tokens are a separate surface. Symbol
identity, C compilation, and behavior are checked independently where applicable.
Ghidra 12 also erases a pointer-to-typedef-of-function before either backend
receives it; the supported callback smoke uses a typedef of the callback pointer.

## Callable consumer and import regressions

The integrated callable cutover still has failing positive cases. Consult the
[durable cutover status](../../docs/datatype-callable-cutover-status.md) and the
[native-import evidence and unapplied drafts](../../docs/features/native-import-declarations/README.md);
preserved tests are not a claim that every architecture gate passes.

Run the consumer slice in a Python environment containing `pyghidra`, with
`GHIDRA_INSTALL_DIR` pointing to the **isolated integrated Ghidra installation**
created by `kuna.KunaIntegratedInstall`, not an unpatched stock installation:

```bash
export GHIDRA_INSTALL_DIR=/path/to/isolated-integrated-ghidra
export JAVA_HOME=/path/to/ghidra-supported-jdk
export KUNA_SMOKE_OUT=/path/to/fresh/callable-consumers
python tests/ghidra/callable/consumers.py
```

If the platform's default Java user home is not writable, explicitly select a
writable isolated home before launching the tests:

```bash
mkdir -p /path/to/writable-ghidra-home
export JAVA_TOOL_OPTIONS="-Duser.home=/path/to/writable-ghidra-home"
```

Retain any other Java options your environment requires. This is a test
environment prerequisite, not a production fallback; startup failures remain
nonzero.

The entrypoint takes no positional arguments, uses the usual
`KUNA_GHIDRA_EXE` release-binary default, and starts a separate process/JVM for
each check. A missing prerequisite or failed assertion fails the slice;
`consumers.json` and one log/output directory per check retain the evidence.
Fresh output directories prevent stale successful results from being reused.
The shared `whole_calls.py` helper lives beside the tests, not in build output.
It is also registered with the maintained runner:

```bash
make test-ghidra-live LIVE_ARGS='--suite callable-consumers'
```

The slice covers the actual packed producer, source-identity/edit lifecycle,
protocol-2 Java decoding/publication, direct and whole-unit native publication,
structural child-type edits, and ordinary CppExporter success/failure handling.
The decoder's synthetic protocol frames are explicitly separate from native
body evidence. The fault proxy modifies or terminates **real** native responses;
it never supplies a fabricated successful function.

Individual regressions can also be invoked directly with the same environment:

```bash
KUNA_SMOKE_OUT=/path/to/fresh/direct-publication \
  python tests/ghidra/callable/java_native_publication.py
KUNA_SMOKE_OUT=/path/to/fresh/structural-edit \
  python tests/ghidra/callable/java_structural_publication.py
KUNA_SMOKE_OUT=/path/to/fresh/export-failures \
  python tests/ghidra/callable/java_cpp_exporter.py
KUNA_SMOKE_OUT=/path/to/fresh/import-provenance \
  python tests/ghidra/callable/native_import_provenance.py
```

The import-provenance regression builds a genuine native executable from C
source against the host SDK/libc and records the unmodified Ghidra import
metadata. Darwin needs `xcrun`, Clang, `otool`, and `nm`; Linux needs a native C
compiler, `ldd`, and `nm`. `CC` overrides the compiler. Its original-machine
checks cover printf output/return and scanf values/return/remaining input.
It does **not** claim that canonical native declarations or publication of real
mapped import thunks are implemented. UNKNOWN library provenance is reported
honestly, never converted to libc by a name heuristic. Darwin import evidence
has been observed; the newly preserved Linux generation branch still needs a
run on Linux.

## Callable fixture matrices

The maintained callable fixture matrices build their inputs from checked-in
source, not historical files in `decompiler/target/`:

```bash
make test-ghidra-live LIVE_ARGS='--suite callable-transport --suite callable-readonly'
make test-ghidra-live LIVE_ARGS='--suite callable-internal-roles'
make test-ghidra-live LIVE_ARGS='--suite callable-restoration'
```

They require cross-target Clang, `ld.lld`, `llvm-objdump`, `llvm-dwarfdump`,
PyGhidra and native C compilation. `LLVM_BIN` or tool-specific variables such as
`KUNA_CLANG`, `KUNA_LD_LLD` and `KUNA_LLVM_DWARFDUMP` select those tools.
Missing tools fail rather than silently skip. Original machine execution and
unchanged emitted C at `-O0`/`-O2` are separate checks. Failed positive cases
remain failures; see the [cutover checkpoint](../../docs/datatype-callable-cutover-status.md)
for currently observed blockers, including callback target identity and
body-grounded recursive publication. A failed streaming export may leave an
incomplete output file; its existence is not successful publication.

The internal-role runner also invokes the opt-in Rust test
`verify_mips_internal_roles` with the console `test-support` feature and the
freshly built fixture directory. Ordinary workspace tests do not require this
cross-toolchain fixture; the opted-in test fails on missing fixtures. The feature
exposes only narrow test access to actual final proof coverage and is absent
from normal production builds.

## Optional supplied-binary investigations

The same runner exposes `features` (host interactions) and `comparison`
(side-by-side C and scanner counts). They are opt-in because they need a binary:

```bash
make test-ghidra-live LIVE_ARGS='--suite comparison --binary ./a.out --function main'
```

`features` accepts one function; `comparison` accepts repeated `--function`
selections. Comparison completion is labelled `diagnostic`, not a semantic
pass. Scanner counts and line differences help locate candidates; only producer
facts and demonstrated consumer harm turn them into findings.
