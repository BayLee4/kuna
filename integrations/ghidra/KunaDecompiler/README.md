# KunaDecompiler — the kuna core inside the stock Ghidra GUI

A standard Ghidra extension that makes the **stock Ghidra GUI** spawn **kuna** (the Rust
port of the Ghidra decompiler, this repository) as its native decompiler backend, in
place of the stock C++ `decompile` binary. The existing GUI, analyzers, scripts and
`DecompInterface` remain the consumers. The integrated distribution also carries a
version-bound Java producer and consumer extension: it preserves the explicit origin
of a user `CALL_RETURN` override, carries source-type identity, and consumes native
callable-support records without reconstructing their ABI from printed text.

The `kuna_ghidra` backend obtains instruction p-code, symbols, types, comments and
callsite overrides from Ghidra, then returns a `HighFunction` and linked markup
for the stock Decompiler window. Host edits are loaded through the native cache
flush/replay lifecycle. See
[`docs/ghidra-integration.md`](../../../docs/ghidra-integration.md) for the
architecture and unsupported paths. The extension relies on the private
`DecompileProcessFactory` seam described below; release zips are built for the
Ghidra version named in the asset.

## Install from a GitHub Release (recommended; works airgapped)

Every kuna release ships a ready-to-install extension zip —
`kuna-v<ver>-KunaDecompiler-ghidra_<ghidra-version>.zip` on the
[releases tab](https://github.com/Noelo-Lab/kuna/releases) — with prebuilt `kuna_ghidra`
backends for **all platforms** already inside: Linux x86_64 and arm64, macOS x86_64 and
arm64, Windows x86_64 (`kuna_ghidra.exe`). Ghidra picks the right one at runtime, and
its built-in arm→x86 fallbacks cover the rest (Windows-on-ARM runs the x86_64 binary
under emulation; an Apple-Silicon install missing `mac_arm_64` would fall back to
`mac_x86_64` under Rosetta). No cargo, no network, no separate specs download —
`kuna_ghidra` receives everything over the wire, so the zip plus a Ghidra release
install are the only two files an airgapped machine needs.

1. Download and extract the `…KunaDecompiler-ghidra_<version>.zip` asset. It contains
   `KunaDecompiler/lib/KunaDecompiler.jar`, the native backends, and
   `KunaDecompiler/producer/kuna-ghidra-producer.jar`.
2. With Ghidra's supported Java on `PATH`, create a **new isolated installation**:

   ```sh
   java -cp /path/to/KunaDecompiler/lib/KunaDecompiler.jar kuna.KunaIntegratedInstall \
       /path/to/stock-ghidra /path/to/new-kuna-ghidra
   ```

   The output's parent must exist. The installer refuses an existing output, checks
   the source distribution against the producer's build hashes, copies the complete
   distribution, and installs the extension and producer into that copy. It never
   modifies the original installation. Allow disk space for a full Ghidra copy.
3. Launch the copy's `ghidraRun` (`ghidraRun.bat` on Windows). Open a program in the
   CodeBrowser, then **File → Configure → Miscellaneous** and check
   **KunaDecompilerPlugin**. Use this copy for GUI, headless and PyGhidra work.

The bootstrap JAR is bound to the exact `application.properties`,
`SoftwareModeling.jar`, `Decompiler.jar`, and both modules' source archives used to
build it, as well as the callable-support protocol revision. **Install Anyway is not a supported
way to cross that boundary**: rebuild the extension against the intended distribution.
The usual Ghidra extension installer alone changes only the native executable; it does
not install the producer on Ghidra's bootstrap patch path. A native-only installation
can still decompile, but cannot certify missing override-origin information or
provide the additional Java callable-support consumer API.

The sections below are the from-source paths: building the backend and the zip yourself.

## How it works

Every decompiler consumer in Ghidra funnels process creation through one static
factory, `ghidra.app.decompiler.DecompileProcessFactory`, which resolves the executable
once and caches it in a `private static String exepath` field. There is no property,
env var, or ExtensionPoint to substitute it — so at plugin load,
`KunaDecompilerPlugin` resolves the `kuna_ghidra` binary shipped in this extension's
`os/<platform>/` directory (or the `-Dkuna.decompiler.exe` override) and writes that
field by reflection, before the lazily-spawned first decompiler process exists. A
Tools-menu checkbox toggles between the kuna core and the stock one at runtime.

The producer JAR is loaded through Ghidra's supported `Ghidra/patch` path, before
module JARs. The maintained `producer/call-return-origin.patch` changes `PcodeEmit`
and `PcodeEmitPacked`, built from the target installation's own sources. Only the
RETURN synthesized by `FlowOverride.CALL_RETURN` receives the optional per-op
`kuna_callreturn` attribute (ID 4002), whose unsigned value names the actual paired
CALL/CALLIND ordinal in that instruction. Normal RETURNs, including authored trap
p-code with a zero return target, are not marked. The stock native decoder skips this
unknown attribute; Kuna consumes its provenance without applying the override again.
Missing metadata is not interpreted as a proven source override.

`producer/callable-support.patch` extends `PcodeDataTypeManager` with exact source-type
identity, `DataTypeWriter` with identity-based external-definition ownership, and
`DecompileResults`, `DecompiledFunction`, and `CppExporter` with a shared immutable
`CallableSupport` value. `getCallableSupport()` returns an `Optional`; genuine absence
retains stock-core behavior. `getC()` and `getSignature()` remain the current function
fragment, not a self-contained compilation unit. A complete support record supplies
its native declarations, types, globals, adapters, and function bodies separately.

The ordinary C/C++ exporter collects callable support across all chunks, validates
providers and source ownership, then publishes staged C/header files. A refused,
malformed, or incomplete support record, failed decompilation, or cancellation fails
the export without replacing existing output files. Legacy stock fragments are not
accepted as native callable providers. Publication is not an atomic two-file
filesystem transaction.

## Run the kuna backend in a real Ghidra instance

The whole flow, against a **Ghidra release install** — build the backend, package the
extension, install it, enable the plugin, decompile:

```bash
# 1. Build the kuna_ghidra backend and package the extension in one step.
#    build.sh compiles the release binary, stages it into os/<platform>/, and
#    (because GHIDRA_INSTALL_DIR is set) builds the installable zip.
cd integrations/ghidra/KunaDecompiler
GHIDRA_INSTALL_DIR=/abs/path/to/ghidra_release ./build.sh
#    -> dist/ghidra_<version>_..._KunaDecompiler.zip
```

2. **Create the integrated installation:** extract `dist/…_KunaDecompiler.zip` and run
   `KunaIntegratedInstall` as above, using the same Ghidra distribution as the build.
   Launch the new copy, not the original installation.
3. **Enable the plugin:** open a program in the CodeBrowser, then **File → Configure →
   Miscellaneous** and check **KunaDecompilerPlugin**. On load it swaps the decompiler
   core and logs `Decompiler core is now KUNA: <path>`.
4. **Decompile:** open a function — the Decompiler window now shows kuna's C.
5. **Toggle / revert** at runtime with **Tools → Kuna Decompiler → Use Kuna Core** (see
   *Revert* below).

Manual equivalents and the dev-checkout path are in the sections below.

### Just the binary (manual)

`build.sh` with no `GHIDRA_INSTALL_DIR` builds + stages the binary only; the equivalent
by hand, from the repo root:

```bash
cd decompiler
cargo build --release -p kuna-ghidra
cp target/release/kuna_ghidra ../integrations/ghidra/KunaDecompiler/os/linux_x86_64/
```

The binary is a gitignored build artifact; it must be present under
`os/<platform>/` **before** building the extension zip so it gets packaged (`build.sh`
picks the right `os/<platform>/` dir for your host; for other platforms see
`os/linux_x86_64/README.md`).

## Build & install the extension

### Against a Ghidra release install

Use the Gradle version named by `application.gradle.min` in
`<GHIDRA_INSTALL_DIR>/Ghidra/application.properties`, with Git available to apply the
maintained source patches. The target installation must include both
`Ghidra/Framework/SoftwareModeling/lib/SoftwareModeling-src.zip` and
`Ghidra/Features/Decompiler/lib/Decompiler-src.zip`:

```bash
cd integrations/ghidra/KunaDecompiler
gradle -PGHIDRA_INSTALL_DIR=<Absolute path to Ghidra> buildExtension
# -> dist/ghidra_<version>_<release>_<date>_KunaDecompiler.zip
```

Extract the zip and run `KunaIntegratedInstall` as described above. The Gradle build
fails if either maintained source patch no longer matches the target sources; review
the upstream change rather than bypassing that failure. `gradle producerJar` builds
just the producer artifact under `build/producer/` for integration development.

### Against a Ghidra source (dev) checkout

No zip needed — inject this directory as an external module when launching Ghidra
(this is the seam GhidraDev/VSCode dev launches use,
`GhidraApplicationLayout.java:174-181`):

```
-Dghidra.external.modules=/abs/path/to/kuna/integrations/ghidra/KunaDecompiler
```

added to the launcher's VM args (e.g. the Eclipse/VSCode launch configuration created
by `gradle prepDev` / the VSCode integration), with the extension's Java compiled into
the project. During development you can skip copying the binary and instead pass
`-Dkuna.decompiler.exe=/abs/path/to/kuna/decompiler/target/release/kuna_ghidra`.

This external-module seam switches the native core only. A Ghidra source build must
also incorporate both maintained source patches in its SoftwareModeling and
Decompiler sources; release-mode `Ghidra/patch` loading is not used in development mode.

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
  stock core), or **File → Install Extensions…** and uncheck KunaDecompiler, then
  restart Ghidra.

The selection is JVM-wide. If several tools have the plugin enabled, disabling
or closing one does not restore stock until the last enabled owner leaves. The
producer remains loaded for that JVM and is compatible with the stock native decoder.
To return to the completely unmodified Java distribution, launch the original Ghidra
installation; no restoration of its files is necessary.

## Alternative: the no-code file-drop seam

You can run kuna under Ghidra without this extension at all: copy the kuna binary
**named `decompile`** to

```
<GHIDRA_INSTALL_DIR>/Ghidra/Features/Decompiler/build/os/<platform>/decompile
```

`Application.getModuleOSFile` searches a module's `build/os/<platform>/` *before*
`os/<platform>/`, so this shadows the stock binary without overwriting it (delete the
`build/os` copy to revert). Tradeoffs versus the extension:

- applies **unconditionally** to that install — every project, every tool, no toggle,
  no logging of which core is active;
- invisible: nothing in the GUI indicates the core was swapped (use
  `KunaCoreStatus.java`'s output path, or the phase-1 message, to tell);
- survives extension uninstalls but may be wiped by Ghidra upgrades/rebuilds;
- per-install file surgery rather than a distributable artifact.

The extension is the recommended path; the file drop is handy for quick experiments on
a release install.

## Use with PyGhidra (headless / scripting)

Build the backend once (`cd decompiler && cargo build --release -p kuna-ghidra`), install
pyghidra (`pip install "$GHIDRA_INSTALL_DIR"/Ghidra/Features/PyGhidra/pypkg/dist/pyghidra-*.whl`,
or `pip install pyghidra`), and set `GHIDRA_INSTALL_DIR`. Then pick one of two ways to make
Ghidra use kuna. For complete override provenance, set `GHIDRA_INSTALL_DIR` to the
isolated installation created above before Python starts the JVM. Ordinary
`DecompInterface` instances then use the same producer as the GUI; no subclass or
extra Python classpath injection is needed.

### In-script toggle — recommended (no file changes)

The GUI plugin can't load headless, but you can do exactly what it does — set
`DecompileProcessFactory`'s cached `exepath` by reflection — straight from Python. This
flips the core on and off at runtime with **no file surgery**; it takes effect on the next
decompiler-process spawn (a freshly constructed `DecompInterface`):

```python
import os, pyghidra
pyghidra.start()
from ghidra.app.decompiler import DecompileProcessFactory, DecompInterface
from ghidra.util.task import ConsoleTaskMonitor

def _exepath():
    f = DecompileProcessFactory.class_.getDeclaredField("exepath")
    f.setAccessible(True)
    return f
def enable_kuna(exe):  _exepath().set(None, exe)    # kuna ON  (abs path to kuna_ghidra)
def disable_kuna():    _exepath().set(None, None)   # back to the stock decompiler
def active_core():     return _exepath().get(None)  # what Ghidra will spawn next

with pyghidra.open_program("a.out") as flat:        # analyze=True by default
    program = flat.getCurrentProgram()
    enable_kuna(os.environ["KUNA_GHIDRA_EXE"])       # target/release/kuna_ghidra
    ifc = DecompInterface(); ifc.openProgram(program)
    for func in program.getFunctionManager().getFunctions(True):
        print(ifc.decompileFunction(func, 60, ConsoleTaskMonitor()).getDecompiledFunction().getC())
    ifc.dispose()
    disable_kuna()                                   # later DecompInterfaces use stock again
```

`enable_kuna`/`disable_kuna` are the headless equivalent of the extension's
**Tools → Kuna Decompiler → Use Kuna Core** checkbox (which already toggles the GUI at
runtime). An already-open `DecompInterface` keeps its current core until it respawns, so
toggle *before* constructing the one you want to run.

### Persistent swap — the file-drop seam

When you can't inject Python (e.g. `analyzeHeadless`) or want *every* Ghidra invocation to
use kuna, drop the binary named `decompile` into the module's `build/os/<platform>/` (Ghidra
searches it before `os/<platform>/`, so it shadows the stock binary without overwriting it —
delete the copy to revert):

```bash
PLAT=mac_arm_64   # or linux_x86_64 | mac_x86_64 | linux_arm_64 (see build.sh)
DROP="$GHIDRA_INSTALL_DIR/Ghidra/Features/Decompiler/build/os/$PLAT"
mkdir -p "$DROP" && cp decompiler/target/release/kuna_ghidra "$DROP/decompile"
```
