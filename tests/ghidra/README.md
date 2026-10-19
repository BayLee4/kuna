# Real-Ghidra integration regressions

Run `python tests/ghidra/run.py` or `make test-ghidra-live` for **product
acceptance: Kuna native plus the complete Kuna Java integration**. Each selected
suite owns a separate process/JVM. The product roster includes the original
nineteen suites and the existing `result-views` authority/lifetime consumer.
Use `--list` for the current roster and repeat `--suite` to select boundaries.
A filtered run does not replace the full roster.

For packaged-product acceptance, pass `--extension /path/to/KunaDecompiler.zip`
or set `KUNA_GHIDRA_EXTENSION_ZIP` before `make test-ghidra-live`. The runner
installs that ZIP through Ghidra's `ExtensionUtils` into a fresh isolated profile,
restarts the JVM, checks the loaded Java owners and uses the installed bundled
native backend for the existing consumers. It records installation/restart logs,
class origins and the resolved executable alongside the suite report. It neither
modifies the SDK nor injects replacement JARs into the classpath.

CI runs this full product roster on macOS ARM64 with Ghidra 12.1.4 and Java 21
on main, manual/nightly runs, fork PRs and internal PRs labelled `full-ci`.
The Rust simulated-Java tests and ZIP byte-closure checks remain separate gates:
neither executes these Java semantics. Before merging an integration change,
run the installed-product gate locally as well, including on internal PRs.

`--group stock-controls` runs retained stock-native observations separately.
Its report is not a second product qualification and never contributes failures
to the product report. Both groups preserve their real assertions, failures,
unreached clauses and exit status. They do not encode expected failures.

## Prerequisites

Install `pyghidra`, Java 21 and actual Kuna executables. Product tests require
the complete version-qualified extension described in
`integrations/ghidra/KunaDecompiler/README.md`, installed before JVM startup.
Use the unmodified **Ghidra 12.1.4** installation as `GHIDRA_INSTALL_DIR`.
The reference checkout is not an installation target. Shared startup rejects
product runs without the full receiver APIs and records actual Java class origins.

```sh
export GHIDRA_INSTALL_DIR=/path/to/stock-ghidra-12.1.4
export JAVA_HOME=/path/to/supported-jdk
export KUNA_GHIDRA_EXE=/path/to/kuna_ghidra
export KUNA_CLI=/path/to/kuna
export XDG_CONFIG_HOME=/path/to/writable/full-integration-config
export XDG_CACHE_HOME=/path/to/writable/full-integration-cache
python tests/ghidra/run.py --list
python tests/ghidra/run.py --out /path/to/evidence/full
python tests/ghidra/run.py --suite integers -- --producer cli --case unsigned_enum1
```

Launch Ghidra with those same environment settings, install
`ghidra_12.1.4_PUBLIC_<date>_KunaDecompiler.zip` via
**File → Install Extensions… → `+`**, and restart before running consumers.
Build the ZIP with `build.sh`, or use `gradle buildExtension`
after freshly staging a compatible native backend from the same source.

Resolve the effective versioned settings directory through Ghidra's
`ApplicationLayout`, not a guessed `ghidra_<user>` or other user-prefix path.
For example, in a profile's initialized PyGhidra JVM:

```python
from ghidra.framework import Application
layout = Application.getApplicationLayout()
print(layout.getUserSettingsDir())
for directory in layout.getExtensionInstallationDirs():
    print(directory)
```

`XDG_CONFIG_HOME` is a root, not necessarily the effective settings directory:
Ghidra derives application/version and user-specific components. Use the layout's
returned extension locations when inspecting discovery. Keep only one active
`KunaDecompiler` extension per profile; uninstall through
**File → Install Extensions…** and restart before replacing it, then restart
again to load the replacement.

The GUI **KunaDecompilerPlugin** still activates the native backend through
**File → Configure → Miscellaneous**. Its **Use Kuna Core** toggle, like the
tests' native-core controls, does not unload enhanced Java. Removing the enhanced
receiver requires extension uninstall and restart, not switching to stock native.

## Stock controls: purpose and interpretation

Run `python tests/ghidra/run.py --group stock-controls --out /path/to/evidence/full`
with the installed full-Java profile. Repeat that command in a fresh process
with a separate settings/extension profile containing **no Kuna Java classes**,
using `/path/to/evidence/stock` as output. Preserve the same Ghidra version,
stock executable, fixture bytes, providers, options and toolchains.
`GHIDRA_INSTALL_DIR` remains the same. `receiver.json` records which Java actually
loaded; selecting a test group does not install or unload Java.

These controls answer whether our Java changes introduced a regression and
provide upgrade evidence. Compare actual case/lifecycle coverage, source/High,
declarations, compilation, execution and the first failed stage—not just equal
suite exit codes. An unmodified-Java compile failure and a full-Java runtime
failure are different observations. Original failed results stay failed:

|Observation|Interpretation|
|---|---|
|Baseline passes, full Java fails|Regression candidate; diagnose and fix an introduced defect|
|Both fail|Establish whether the first violated invariant is inherited; matching exit codes are insufficient|
|Baseline fails, full Java passes|Improvement; retain the independent regression assertions|
|Stock passes after an upgrade|Normal success; review whether related Kuna work is now obsolete|

|Retained family|Reason and relevant owner|
|---|---|
|Recovery, settings, source identity, symbols|`DecompInterface`, `DecompileOptions`, `PcodeDataTypeManager` and High/source-edit bindings must preserve receiver/context/lifetime behavior|
|Types and pointers|Managed type/field identity and Java decoding versus native C/type rendering; compare the first loss before attributing it|
|Prototypes and callsites|Java-authored source locks, storage, overrides, injection and analyzer facts versus native ABI recovery/printing|
|Callable exporter and SDK imports|`CppExporter`/`DataTypeWriter` declarations, source preservation and Java fault/recovery; real native variadic semantics remain reference observations|
|Integer and constant-pool consumers|Native rendering against real value consumers, with genuine Java JVM loader/analyzer/injection facts|
|Graph and BSim|Java graph/signature decoding and declared cross-core database compatibility|

Stock is also a necessary **input producer** in some product tests: the Java
callback producer, debug-replay capture, exporter fault proxy and cross-core
BSim/graph comparisons. Those test our Java or Kuna interoperability; they are
not unrelated stock semantic positives. Their real failures still fail product
acceptance. Report metadata identifies those roles.

A later stock pass is never an “unexpected success” failure. Review the matching
upstream owner and related maintained Java patch/native implementation against
the same fixtures and all independent contracts. Remove a patch only after that
evidence proves it unnecessary and the unpatched replacement passes product
consumers. A C++ recovery/printing fix alone does not replace Java result-local
namespaces, source authority, held views or exporter ownership. Preserve a useful
correct-behavior regression even when its former implementation becomes obsolete.
There is no persistent list that blesses particular stock failures.

Complete group runs reject `KUNA_CPP_EXPORTER_MODES` and
`KUNA_CPP_EXPORTER_POLICY` overrides: focused mode selection could omit required
positive cases. Use the exporter script directly for those diagnostics. The
default product run selects all implemented full-Java pointer/declaration and
optional external-binding compatibility checks. Only the separate, unimplemented
atomic-destination policy remains opt-in; selecting it does not enable a capability.

The product `result-views` suite exercises the enhanced decoder, held
temporary/local bindings, public edit authority and zero-event
registration-context changes. It can also run directly with
`python tests/ghidra/callable/java_result_view.py` in the same full-Java profile.

Python optimization must be disabled. Setup failures and unmet real producer
prerequisites are failures, not silent skips. CLI integer fixtures require a
clang capable of x86-64 ELF (`KUNA_MATRIX_CROSS_CC`). Source-built i386/AArch64
fixtures also require clang, lld and LLVM inspection tools (`LLVM_BIN` or
helper-specific `KUNA_*` overrides). Exported C/H remains unchanged; missing
types, providers or wrong results fail instead of being repaired in the probe.

The synthetic UNKNOWN-format explicit-call-reference consumer supplies its existing
external provider's C declaration to the caller translation unit. Its exported
C/H and real provider body remain unchanged; this prerequisite does not assert
automatic external declaration closure for unmodeled executable formats.

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
Settings lifecycle distinguishes unknown-language rejection from supported Java
selection using an explicitly enabled `return null;` token, then restores C and
executes the original arithmetic recovery consumer on the same native process.

The typed-fastcall result regression retains a short callsite High result and
the genuine int callback source while executing nonzero upper result bits and
an actual once-only provider counter through unchanged i386 C/H at O0/O2.

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
in the investigation evidence; they do not establish the current versioned
enhanced implementation's acceptance or add universal executable certification.
Direct emitted i386 targets are exercised separately when cleanup or register
storage must match the original machine; a compiler-generated caller adapting
an incompatible declaration is insufficient.

## Artifacts

`KUNA_SMOKE_OUT` or `--out` chooses the artifact root. The default is
`decompiler/target/ghidra-live`; executables default to release binaries under
`decompiler/target/release`. Each invocation creates a fresh
`product/run-*` or `stock-controls/run-*` directory with logs and `report.json`;
each group has its own latest `report.json`. Reports include the group and
each suite's purpose. The console names the group instead of mixing stock
observations into a product pass fraction. Failed children do not stop independent suites.
Individual reports distinguish setup, source/machine production, native
responses, compilation and execution. Completion counts do not prove a test's
necessity or correctness. No runtime acceptance is implied by source admission
of a retained test.

Integer arguments after `--` require exactly one `--suite integers`. A filtered
run is narrower scope, not full-suite acceptance. Stock controls may provide
interoperability comparisons but cannot substitute for the Kuna producer.
