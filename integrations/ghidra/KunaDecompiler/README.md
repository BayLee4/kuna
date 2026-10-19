# KunaDecompiler — the kuna core inside the stock Ghidra GUI

A standard Ghidra extension that makes the **stock Ghidra GUI** spawn **kuna** (the Rust
port of the Ghidra decompiler, this repository) as its native decompiler backend, in
place of the stock C++ `decompile` binary. The normal Ghidra GUI (Decompiler
window, analyzers, scripts) runs on the kuna engine, with bounded, versioned Java
owner patches for result-local types, source-edit authority and export configuration.
There is one full extension product, not a separate native-only installation.

The `kuna_ghidra` binary speaks the Ghidra⇄decompiler wire protocol and drives kuna's
engine, including lazy source-symbol/type queries and HighFunction/token markup.
The Decompiler window shows **C produced by kuna**, with click-to-address and
source-edit bindings. Unsupported engine paths remain per-function failures; these
integration capabilities do not promise correct decompilation of every input. See
[`docs/ghidra-integration.md`](../../../docs/ghidra-integration.md) for the design and
protocol contracts. The extension is strictly qualified for **Ghidra 12.1.4 with
Java 21**, identified in the release ZIP filename.

## Install from a GitHub Release (recommended; works airgapped)

Every kuna release ships a ready-to-install extension zip —
`kuna-v<ver>-KunaDecompiler-ghidra_12.1.4.zip` on the
[releases tab](https://github.com/Noelo-Lab/kuna/releases) — with prebuilt `kuna_ghidra`
backends for **all platforms** already inside: Linux x86_64 and arm64, macOS x86_64 and
arm64, Windows x86_64 (`kuna_ghidra.exe`). Ghidra picks the right one at runtime, and
its built-in arm→x86 fallbacks cover the rest (Windows-on-ARM runs the x86_64 binary
under emulation; an Apple-Silicon install missing `mac_arm_64` would fall back to
`mac_x86_64` under Rosetta). No cargo, no network, no separate specs download —
`kuna_ghidra` receives everything over the wire. An airgapped machine needs the
extension ZIP, the matching Ghidra installation and Java 21, but no Rust toolchain.

1. Download the `…KunaDecompiler-ghidra_12.1.4.zip` asset from the kuna releases tab.
2. In Ghidra's project window: **File → Install Extensions… → `+` → select the zip**,
   then restart Ghidra when prompted.
3. Enable the plugin: open a program in the CodeBrowser, then **File → Configure →
   Miscellaneous** and check **KunaDecompilerPlugin**.

The zip is built against — and version-stamped with — the Ghidra version in its
filename. Ghidra warns on a version mismatch; that is not compatibility proof.
Use exactly **Ghidra 12.1.4 with Java 21**. **Install Anyway** is not a
compatibility path. Retargeting requires matching owner patches and qualification,
not merely changing a version string.

The sections below are the from-source paths: building the backend and the zip yourself.

## Build the full extension from source (Ghidra 12.1.4)

Use an unmodified Ghidra **12.1.4** installation, Java 21, the Gradle version
required by `application.gradle.min` in its `Ghidra/application.properties`,
Rust, Python 3 and the standard GNU/BSD `patch` utility. Build the native backend
and full normal extension ZIP from the same source:

```bash
cd integrations/ghidra/KunaDecompiler
GHIDRA_INSTALL_DIR=/abs/stock-ghidra-12.1.4 ./build.sh
# -> dist/ghidra_12.1.4_PUBLIC_<date>_KunaDecompiler.zip

# If a compatible native backend is freshly built and staged in os/<platform>/:
gradle -PGHIDRA_INSTALL_DIR=/abs/stock-ghidra-12.1.4 buildExtension
```

To produce the extension ZIP, the driver requires `GHIDRA_INSTALL_DIR` and checks
its exact version before native compilation. Without it, the driver only builds
and stages a development native backend. It selects Rust's host target and reads Cargo's artifact
report, so a configured cross target or nondefault `CARGO_TARGET_DIR` cannot
mislabel the packaged host backend. A source build packages only that host;
release CI stages all five platforms. Direct Gradle packaging requires a matching
native backend already staged in `os/<platform>/`; use `-PkunaPlatform=<platform>`
to select just that platform.

Install that ZIP through **File → Install Extensions… → `+`**, then restart Ghidra.
The package keeps the `KunaDecompiler` module name, existing plugin JAR in `lib/`
and native assets in `os/`. Its complete freshly compiled enhanced owner/helper
closure is in `KunaDecompiler/bin/main/`: normal extension discovery places those
classes before the original module JARs in the same `GhidraClassLoader`. There is
no separate Java artifact to install and no modification of Ghidra's module JARs.
Enable **KunaDecompilerPlugin** through **File → Configure → Miscellaneous** to
activate the native backend. Ghidra's stock `buildExtension` still owns the plugin
JAR, embedded `zipSource` source archive, module metadata and license rules.
The existing `prepareEnhancedIntegrationSources` / `compileEnhancedIntegration`
tasks prepare and compile the Java closure; these are internal protocol-owner
names, not separate distribution choices.

Uninstall the previous `KunaDecompiler` through **File → Install Extensions…** and
restart before installing its replacement; restart again to load the replacement.
The native **Use Kuna Core** toggle does not unload enhanced Java classes. To remove
those classes, uninstall the extension and restart. An untouched-Java
control uses the same stock installation with a separate per-user settings profile
that has no extension. Use Ghidra's `ApplicationLayout` to resolve that
profile's settings and extension directories, rather than guessing user-prefix
paths; see [the test setup](../../../tests/ghidra/README.md).
The repository's reference checkout is not an installation target.

The build requires the unmodified installation source/JAR pair, including
`Decompiler-src.zip` and `SoftwareModeling-src.zip`. Bounded
maintained diffs in `patches/ghidra-12.1.4` apply strictly to those source members
in clean build staging using the standard GNU/BSD `patch` executable (`PATCH`
can select its path). Batch/forward/fuzz-zero flags are required; any nonzero
status or offset/fuzz/reverse/skip/reject diagnostic is a failure. Existing
Ghidra class bodies are not duplicated in the repository. Only new helper classes
are kept whole under `src/enhanced/java`.

Enhanced managers offer result protocol version 1 in `coretypes`; a supporting
native result acknowledges it even when no local definitions are needed. Old peers
without that acknowledgment retain ordinary grammar and do not gain enhanced
authority. Inferred types stay result-local, managed source/core identities are
shared, and held results retain used temporary bindings. Current enhanced source
edits require the captured Program revision and registered-context snapshot to
remain current; readability is retained. Export publication checks its separate
invocation authority rather than granting working export results source-edit authority.

For invocation-owned selected-root preparation, use
`CppExporter.setConfigurer(DecompileConfigurer)` and
`prepareSelectedRoots(program, explicitFunctions, monitor)` before provider
discovery. Configure `DecompileOptions.setExportInline(true)` through that same
configurer for preparation and every fresh exporter interface. This is opt-in;
ordinary exports and normal decompile requests retain their existing defaults.
Preparation uses ordinary canonical decompilation. The exporter inventories actual
functions once using the existing listing selection and function-tag filter, then
captures one immutable `DecompInterface.ExportScope` for that entire inventory.
The same datatype-name owner first reserves program source names and supplies an
immutable identifier snapshot to `createExportScope(program, functions,
reservedIdentifiers)`, so private native identifiers avoid the writer's existing
source-name namespace, including its C identifier transformations.
The same inventory drives chunking; selected membership is neither queried again
nor widened to include additional bodies. Every fresh private interface installs
the same scope after its options, configurer, program registration and toggles,
and scoped callbacks use `decompileFunctionForExport`. Pool disposal closes the
scope before disposing each interface. Before each scoped acquisition, callbacks
reinstall the same immutable scope: this is idempotent while active and allows the
next independent target to recover after a target-local failure closes its scope.
A backend without enhanced acknowledgment
retains ordinary canonical requests and receives no export-only commands.
Preparation and working requests retain one NONDB temporary-ID epoch; only
working requests omit automatic clearing and body flushing. Explicit flush,
scope close, cancellation, decode failure and acquisition errors still flush and
clear that private epoch. Captured result bindings stay readable independently.
Revision, registered-core and effective option/action/output snapshots are checked
before acquisition and after complete decoding. Working results never authorize
source edits; their export-authority snapshot retains no live interface/process.
Physical export metadata selects the actual typed public prototype in the result's
markup; the mapped printer renders that group with the invocation's datatype names.
An implementation-only result contributes no public header declaration. Descriptor
identifiers are reserved before local datatype names are assigned, and native markup
retains ownership of helper and dependency declaration ordering. Headers are not
inferred from the first implementation signature or rewritten as text.
Descriptor identities match raw received function-name tokens; supported template,
operator, Unicode and suffix spellings retain the existing renderer's name policy.

See [the integration contract](../../../docs/ghidra-integration.md)
for protocol IDs, lifetime and typed-name behavior.

The bounded exporter keeps ordinary per-function failure behavior: diagnostic
comments are optional, skipped results do not make a successful batch fail, and
chunks still stream in address order. Cancellation and output-stream errors
remain failures. The ordinary untouched-Java profile does not load these owner
patches. The datatype writer renders a source pointer with no referent as `void *`,
including inside typedefs; its internal display name (`pointer64`, for example)
is not a C type declaration. Neither behavior changes imported source metadata.

The enhanced Java exporter additionally retains referenced external function declarations
through actual High CALL targets and source thunk associations. Only declarations
are added, not unselected bodies. Their source prototypes, varargs and type closure
use the invocation's existing writer/name authority. Mach-O and ELF exports target
the GCC/Clang dialect: `__asm__` binds the unchanged source C identifier to the real
retained imported label, including Mach-O's leading underscore. Renamed imports use
their original imported name; an unchanged label is authoritative only when its
source is `IMPORTED`. Missing or non-printable labels, other object formats,
custom parameter/return storage and non-default calling conventions are
ineligible for the optional added declaration/binding, not newly refused exports.
Their existing declaration/body behavior remains unchanged.
The typed writer emits genuine named callable datatypes as function-type typedefs,
while preserving pointers and real aliases as separate layers. Anonymous callable
types stay structural; an internal result placeholder does not authorize a name.
All exporter-owned declaration writers receive the invocation's actual compiler
specification and the effective pooled interface's calling-convention display
option, including a configurer's replacement options. Each callable layer retains
its resolved nondefault convention; actual default models and convention-OFF
output remain unannotated. Other, unconfigured datatype writers retain their
ordinary behavior. A model named `__stdcall` is not itself evidence of a Windows
ABI: the x86-64 GCC specification uses that name for its System V default.
Synthetic external declaration roots are structural and cannot introduce a typedef
that conflicts with the imported function identifier.

## How it works

Every decompiler consumer in Ghidra funnels process creation through one static
factory, `ghidra.app.decompiler.DecompileProcessFactory`, which resolves the executable
once and caches it in a `private static String exepath` field. There is no property,
env var, or ExtensionPoint to substitute it — so at plugin load,
`KunaDecompilerPlugin` resolves the `kuna_ghidra` binary shipped in this extension's
`os/<platform>/` directory (or the `-Dkuna.decompiler.exe` override) and writes that
field by reflection, before the lazily-spawned first decompiler process exists. A
Tools-menu checkbox toggles between the kuna core and the stock one at runtime.

## Run the kuna backend in a real Ghidra instance

1. **Build the full extension** as described above against Ghidra 12.1.4 and Java 21.
2. **Install the extension:** in Ghidra's project window, **File → Install Extensions… →
   `+` → select `dist/…_KunaDecompiler.zip`**, then restart Ghidra when prompted.
3. **Enable the plugin:** open a program in the CodeBrowser, then **File → Configure →
   Miscellaneous** and check **KunaDecompilerPlugin**. On load it swaps the decompiler
   core and logs `Decompiler core is now KUNA: <path>`.
4. **Decompile:** open a function — the Decompiler window now shows kuna's C.
   Unsupported engine paths produce a per-function error rather than guaranteeing
   output for every function.
5. **Toggle / revert** at runtime with **Tools → Kuna Decompiler → Use Kuna Core** (see
   *Revert* below).

### Development native override (full extension already installed)

For native iteration, keep the full Java extension installed in the selected
Ghidra 12.1.4 profile and start a fresh JVM with
`-Dkuna.decompiler.exe=/abs/path/to/kuna_ghidra` pointing to a matching native build:
```bash
cd decompiler
cargo build --release -p kuna-ghidra
```

This selects only the native executable; it neither installs Java classes nor
replaces normal extension installation. For manual native staging and platform
directory names, see [`os/linux_x86_64/README.md`](os/linux_x86_64/README.md).

## Enable the plugin

Open a program in the CodeBrowser, then **File → Configure → Miscellaneous** (the
gear/"Configure All Plugins" view) and check **KunaDecompilerPlugin**. On load it
performs the swap and logs `Decompiler core is now KUNA: <path>` to the application
log; if the binary is missing it shows an error dialog with the build/copy commands and
leaves the stock core active.

## Verify

- Run the bundled script `KunaCoreStatus.java` (Script Manager, category *Kuna*): it
  prints the executable path currently installed in `DecompileProcessFactory` and
  whether the next decompiler process is the kuna or stock core.
- Decompile a small, self-contained function: the Decompiler window shows kuna's C, and
  clicking a token navigates to its address — proof that the stock GUI is running on the
  kuna engine. If a function can't be decompiled yet (an un-supported engine path), the
  window shows a clean per-function message instead of hanging.
- Sanity check that it's really kuna and not the stock core: the two decompilers produce
  cosmetically different C, and `KunaCoreStatus.java` reports the `kuna_ghidra` path.

## Revert

- **Runtime:** uncheck **Tools → Kuna Decompiler → Use Kuna Core** — future decompiler
  spawns use the stock binary again. Programs with an already-running decompiler
  process keep it until that process restarts (reopen the program, or the process is
  reset after an error/timeout); reopening the program is the reliable nudge.
- **Plugin off:** un-check the plugin in File → Configure (its dispose restores the
  stock core). This changes native selection, not already loaded enhanced Java.
- **Uninstall:** **File → Install Extensions…**, uncheck KunaDecompiler, then
  restart Ghidra. Enhanced Java remains loaded until restart. Uninstall/restart
  before installing a replacement; restart again to load the replacement.

## Use with PyGhidra (headless / scripting)

Install the full extension above into the selected per-user profile, install
PyGhidra (`pip install "$GHIDRA_INSTALL_DIR"/Ghidra/Features/PyGhidra/pypkg/dist/pyghidra-*.whl`,
or `pip install pyghidra`), and set `GHIDRA_INSTALL_DIR` to the matching Ghidra 12.1.4
installation. Start a fresh JVM under Java 21. The installed `KunaCoreSwap` API
resolves the extension's matching platform executable; for native development
only, set `-Dkuna.decompiler.exe=/abs/path/to/kuna_ghidra` before JVM startup.

### In-script native selection (no installation file changes)

The GUI plugin can't load headless, but the installed `kuna.KunaCoreSwap` owner
exposes the same native-selection seam. It sets `DecompileProcessFactory`'s cached
`exepath` by reflection, with **no file surgery**. Selection takes effect on the
next decompiler-process spawn:

```python
import pyghidra
pyghidra.start()
from jpype import JClass
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor

KunaCoreSwap = JClass("kuna.KunaCoreSwap")

with pyghidra.open_program("a.out") as flat:        # analyze=True by default
    program = flat.getCurrentProgram()
    previous = KunaCoreSwap.getInstalledExePath()
    KunaCoreSwap.setInstalledExePath(KunaCoreSwap.findKunaBinary().getAbsolutePath())
    ifc = DecompInterface()
    try:
        if not ifc.openProgram(program):
            raise RuntimeError(str(ifc.getLastMessage()))
        for func in program.getFunctionManager().getFunctions(True):
            result = ifc.decompileFunction(func, 60, ConsoleTaskMonitor())
            print(result.getDecompiledFunction().getC()
                  if result.decompileCompleted() else result.getErrorMessage())
    finally:
        try:
            ifc.dispose()
        finally:
            KunaCoreSwap.setInstalledExePath(previous)
```

`KunaCoreSwap.swapToKuna(originator)` / `restoreStock(originator)` expose the
GUI checkbox's selection and diagnostic behavior. `getInstalledExePath()` /
`setInstalledExePath(path)` let a script capture and restore its exact prior
selection as above. An already-open `DecompInterface` keeps its current core until it respawns, so
toggle *before* constructing the one you want to run. These controls select only
the native core. Enhanced Java must already be installed as the normal extension
in the selected per-user profile before starting PyGhidra; use a fresh JVM after
installation, replacement or uninstall.

For `analyzeHeadless`, select the same native backend in a Java Ghidra script
before opening its `DecompInterface`, using that same installed owner:

```java
String previous = kuna.KunaCoreSwap.getInstalledExePath();
kuna.KunaCoreSwap.setInstalledExePath(
    kuna.KunaCoreSwap.findKunaBinary().getAbsolutePath());
ghidra.app.decompiler.DecompInterface ifc = new ghidra.app.decompiler.DecompInterface();
try {
    if (!ifc.openProgram(currentProgram)) {
        throw new IllegalStateException(ifc.getLastMessage());
    }
    for (ghidra.program.model.listing.Function function :
            currentProgram.getFunctionManager().getFunctions(true)) {
        ghidra.app.decompiler.DecompileResults result =
            ifc.decompileFunction(function, 60, monitor);
        if (result.decompileCompleted()) {
            println(result.getDecompiledFunction().getC());
        }
        else {
            printerr(result.getErrorMessage());
        }
    }
}
finally {
    try {
        ifc.dispose();
    }
    finally {
        kuna.KunaCoreSwap.setInstalledExePath(previous);
    }
}
```

This selection presumes the full extension is installed in the launch profile.
It does not overwrite the stock binary or install the Java closure.
