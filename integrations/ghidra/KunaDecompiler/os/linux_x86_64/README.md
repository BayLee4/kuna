# os/linux_x86_64/ — the kuna native binary goes here

This directory holds the Linux x86-64 `kuna_ghidra` binary that the extension makes
Ghidra spawn as its decompiler process. It is a **build artifact** (gitignored): copy it
here before building the extension zip, so `gradle buildExtension` packages it into the
zip's `KunaDecompiler/os/linux_x86_64/` and `Application.getOSFile("KunaDecompiler",
"kuna_ghidra")` can resolve it at runtime.

From the kuna repo root:

```bash
cd decompiler
cargo build --release -p kuna-ghidra
cp target/release/kuna_ghidra ../integrations/ghidra/KunaDecompiler/os/linux_x86_64/
chmod +x ../integrations/ghidra/KunaDecompiler/os/linux_x86_64/kuna_ghidra
```

The full extension build requires a staged matching native backend and compiles the
Java owner/helper closure against the unmodified Ghidra 12.1.4 installation under
Java 21. Prefer `GHIDRA_INSTALL_DIR=/abs/ghidra_12.1.4_PUBLIC ./build.sh` from the
extension directory; it builds and stages the host binary before packaging.
For manual packaging, run `gradle buildExtension` with that installation configured.
Native staging is not a complete installation by itself: install the full ZIP
through Ghidra's normal extension installer and restart.

During native development only, the
`-Dkuna.decompiler.exe=/abs/path/to/kuna_ghidra` JVM property may point at a matching
build while the full Java extension is already installed in the launch profile.

## Other platforms

Ghidra resolves native binaries per platform from sibling directories named after the
platform. To ship kuna for another OS/arch, cross-build (or build natively) and drop the
binary, with the same name, into the matching directory before zipping:

| Platform | Directory | Binary name |
|---|---|---|
| Linux x86-64 | `os/linux_x86_64/` | `kuna_ghidra` |
| Linux AArch64 | `os/linux_arm_64/` | `kuna_ghidra` |
| macOS x86-64 | `os/mac_x86_64/` | `kuna_ghidra` |
| macOS AArch64 | `os/mac_arm_64/` | `kuna_ghidra` |
| Windows x86-64 | `os/win_x86_64/` | `kuna_ghidra.exe` |

Directory names are Ghidra's `Platform` enum names (`Ghidra/Framework/Generic/src/main/java/ghidra/framework/Platform.java`) — note the underscore before `64` on the arm variants (`linux_arm_64`, `mac_arm_64`).

A local `build.sh` run only stages the host's platform; the other directories may
simply not exist. Release CI (the `ghidra-ext` job in
`.github/workflows/release.yml`) stages all five before zipping, so the published
extension zip works on every platform.
