#!/usr/bin/env bash
#
# One-command build + package for the KunaDecompiler Ghidra extension: compiles the
# `kuna_ghidra` backend binary, stages it into this extension's `os/<platform>/`
# directory (a gitignored build artifact), and — if GHIDRA_INSTALL_DIR is set —
# packages the installable extension zip.
#
#   ./build.sh                          # build + stage the development binary
#   GHIDRA_INSTALL_DIR=/path ./build.sh  # complete extension zip (Ghidra 12.1.4, Java 21)
#
# This script builds a HOST-ONLY zip from source. Release CI (the ghidra-ext job
# in .github/workflows/release.yml) builds the multi-platform zip with prebuilt
# binaries for all platforms -- grab that from the GitHub releases tab if you
# just want to install (works airgapped, and it is the only Windows path).
#
# Python 3 reads Cargo's reported executable path, honoring its output-directory configuration.
# See README.md for the normal extension installation and restart lifecycle.
set -euo pipefail

if [ "$#" -ne 0 ]; then
	echo "error: unexpected argument: $1" >&2
	echo "usage: $0" >&2
	exit 1
fi

# Resolve paths relative to this script (integrations/ghidra/KunaDecompiler/).
EXT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$EXT_DIR/../../.." && pwd)"

if [ -n "${GHIDRA_INSTALL_DIR:-}" ]; then
	( cd "$EXT_DIR" && gradle -PGHIDRA_INSTALL_DIR="$GHIDRA_INSTALL_DIR" checkEnhancedGhidraVersion )
fi

# Map the Rust compiler's host to Ghidra's `Platform` enum directory name
# (Ghidra/Framework/Generic/.../Platform.java — note the underscore before 64 on arm).
HOST_TARGET="$("${RUSTC:-rustc}" --print host-tuple)"
case "$HOST_TARGET" in
	x86_64-*-linux-*)     PLATFORM=linux_x86_64; EXE=kuna_ghidra ;;
	aarch64-*-linux-*)    PLATFORM=linux_arm_64; EXE=kuna_ghidra ;;
	x86_64-apple-darwin)  PLATFORM=mac_x86_64;   EXE=kuna_ghidra ;;
	aarch64-apple-darwin) PLATFORM=mac_arm_64;   EXE=kuna_ghidra ;;
	*)
		echo "error: unsupported Rust host '$HOST_TARGET' (Windows and anything else non-Linux/mac)." >&2
		echo "       Use the prebuilt extension zip from the kuna GitHub releases tab instead:" >&2
		echo "       kuna-v<ver>-KunaDecompiler-ghidra_<version>.zip ships ready-to-install" >&2
		echo "       binaries for all platforms (including win_x86_64/kuna_ghidra.exe)." >&2
		echo "       Or build manually: (cd decompiler && cargo build --release -p kuna-ghidra)" >&2
		echo "       and copy the binary into os/<ghidra-platform-dir>/ yourself." >&2
		exit 1 ;;
esac

echo ">> building the kuna_ghidra backend (release, $HOST_TARGET)"
NATIVE_BINARY="$(
	cd "$REPO_ROOT/decompiler"
	cargo build --release --target "$HOST_TARGET" -p kuna-ghidra --message-format=json-render-diagnostics |
		"${PYTHON:-python3}" -c '
import json
import sys

executables = set()
for line in sys.stdin:
    message = json.loads(line)
    if (message.get("reason") == "compiler-artifact"
            and message["target"]["name"] == "kuna_ghidra"
            and message.get("executable")):
        executables.add(message["executable"])
if len(executables) != 1:
    sys.exit("error: Cargo must report exactly one kuna_ghidra executable")
print(executables.pop())
'
)"

echo ">> staging $EXE into os/$PLATFORM/"
mkdir -p "$EXT_DIR/os/$PLATFORM"
cp "$NATIVE_BINARY" "$EXT_DIR/os/$PLATFORM/$EXE"
chmod +x "$EXT_DIR/os/$PLATFORM/$EXE"

if [ -n "${GHIDRA_INSTALL_DIR:-}" ]; then
	echo ">> packaging the extension against $GHIDRA_INSTALL_DIR"
	( cd "$EXT_DIR" && gradle -PGHIDRA_INSTALL_DIR="$GHIDRA_INSTALL_DIR" \
		-PkunaPlatform="$PLATFORM" buildExtension )
	echo ">> done. Install the zip in $EXT_DIR/dist/ via Ghidra: File -> Install Extensions..."
else
	echo ">> binary staged at os/$PLATFORM/$EXE."
	echo "   Set GHIDRA_INSTALL_DIR to Ghidra 12.1.4 and re-run with Java 21 to build"
	echo "   the complete installable extension zip via buildExtension."
fi
