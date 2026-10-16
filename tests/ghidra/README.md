# Real-Ghidra integration regressions

Run `python tests/ghidra/run.py` or `make test-ghidra-live`. Each selected suite
owns a separate process/JVM. Use `--list` for the current roster and repeat
`--suite` to select independent consumer boundaries.

The default roster is the original seventeen suites plus `native-features`
and `cpool`: `recovery`, `prototypes`, `types`, `pointers`, `integers`,
`settings`, `symbols`, `callsites`, `callable-consumers`, `callable-transport`,
`callable-readonly`, `callable-recursion`, `callable-internal-roles`,
`callable-restoration`, `callable-graph-objects`, `callable-datatypes` and
`callable-stack-results`. A filtered run does not replace this roster.

## Prerequisites

Use an unmodified Ghidra Java installation and supported JDK, with `pyghidra`
installed. Reviewed source contracts use Ghidra revision
`8b6bbb857accdfa20dc5b2f5dea471178c2e9fbc`. Select actual Kuna executables:

```sh
export GHIDRA_INSTALL_DIR=/path/to/stock-ghidra
export JAVA_HOME=/path/to/supported-jdk
export KUNA_GHIDRA_EXE=/path/to/kuna_ghidra
export KUNA_CLI=/path/to/kuna
export XDG_CONFIG_HOME=/path/to/writable/ghidra-config
export XDG_CACHE_HOME=/path/to/writable/ghidra-cache
python tests/ghidra/run.py --list
python tests/ghidra/run.py --suite integers -- --producer cli --case unsigned_enum1
```

Python optimization must be disabled. Setup failures and unmet real producer
prerequisites are failures, not silent skips. CLI integer fixtures require a
clang capable of x86-64 ELF (`KUNA_MATRIX_CROSS_CC`). Source-built i386/AArch64
fixtures also require clang, lld and LLVM inspection tools (`LLVM_BIN` or
helper-specific `KUNA_*` overrides). Exported C/H remains unchanged; missing
types, providers or wrong results fail instead of being repaired in the probe.

Target-i386 consumers compile with the target data model and execute through
the actual Ghidra emulator. Host C execution separately tests the exported
language-level computation; it does not demonstrate target stack cleanup or
register preservation.

`cpool` requires javac (`JAVAC`) and Ghidra's real JVM loader/analyzer/injection
module. It compiles `callable/fixtures/CpoolConsumers.java` and consumes genuine
constant-pool records and native rendering. Synthetic malformed record bodies
and private decoder protocols are not substituted for an actual producer.

`native-features` requires the genuine BSim module/weights, defaulting to
`$GHIDRA_INSTALL_DIR/Ghidra/Features/BSim/data/lshweights_64.xml`
(`KUNA_BSIM_WEIGHTS`). It consumes Kuna graph structure and raw/debug signature
hashes/settings through real Java clients; stock-only database policy is not a
Kuna regression oracle.

## Consumer scope

The retained suites exercise real source declarations, High/markup, named
memory spaces, source-edit freshness, machine values, finite call targets,
calling conventions and unchanged export execution. Source-edit tests retain
same-ID nested alias/field changes and exact nominal field-token bindings after
flush, reset and reopen, separately from readability of held C/High/markup.
Before/after ordinary requests on the same interface guard restoration after
native graph/signature failures; standalone smoke does not replace them.

The integer matrix retains all fourteen CLI cases, default-width enums,
primitive assertion admission, authentic DWARF enums and plain-char modes.
The pointer matrix crosses two banks, offsets `0x80`, `0xa0` and `0xff`,
and direct/alias pointers. Source identities, token bindings and unchanged
value consumers remain independent from metadata acquisition. The datatype
suite retains all twenty bitfield, pointer-array, mixed-return and custom
storage cases.

`callable/support.py` owns the shared source-signature/storage snapshots, actual
Kuna High/source checks, unchanged C/H publication/execution and machine helpers
used by stack-result and recursive consumers. These helpers do not depend on a
test suite's source module or implement executable-admission certification.

CLI `decompile-project` and stock `CppExporter` are diagnostic/recompilation
exports, not universal all-machine-state certification APIs. The original
mandatory frame positives still require successful unchanged C/H/value/effect
consumption. Their exit status reports analysis/artifact completion, not finite
recursion, preservation of ambient machine state, or a closed executable unit.
Partial selections retain their selected definitions and omit unselected ones.
Physical-state negatives retain their original source, raw, CFG and machine
observations. Historical refusal-or-correct-execution requirements for a stronger
physical-C interface remain conditional investigation evidence; an ordinary
successful export neither satisfies that interface nor proves its C correct.

Stock `CppExporter` takes the current Program and selected functions, not a
retained result. It has warning/skip/cancellation behavior rather than atomic
two-file replacement or historical retained-publication validation. Tests
retain actual malformed/cancel/recovery inputs, fresh edited declarations and
selected successful providers without inventing those contracts. Historical
enhanced receipts and their explicitly conditional product requirements remain
in the investigation evidence; they are not a second supported runtime domain.
Direct emitted i386 targets are exercised separately when cleanup or register
storage must match the original machine; a compiler-generated caller adapting
an incompatible declaration is insufficient.

## Artifacts

`KUNA_SMOKE_OUT` or `--out` chooses the artifact root. The default is
`decompiler/target/ghidra-live`; executables default to release binaries under
`decompiler/target/release`. Each invocation creates a fresh `run-*` directory
with logs and `report.json`. Failed children do not stop independent suites.
Individual reports distinguish setup, source/machine production, native
responses, compilation and execution. Completion counts do not prove a test's
necessity or correctness. No runtime acceptance is implied by source admission
of a retained test.

Integer arguments after `--` require exactly one `--suite integers`. A filtered
run is narrower scope, not full-suite acceptance. Stock controls may provide
interoperability comparisons but cannot substitute for the Kuna producer.
