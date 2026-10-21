"""Install the KunaDecompiler extension ZIP into an isolated Ghidra profile, and
check from a running JVM that the extension's Java is the one loaded.

kuna_ghidra speaks the extension's result protocol, so the smoke scripts only
run in a JVM that loaded the extension (stock Java is refused at registration).

  python3 extension.py KunaDecompiler.zip PROFILE_DIR

installs the ZIP, restarts Ghidra once to resolve it, and prints the `export`
lines that select the profile for the smoke scripts.
"""

import json
import os
from pathlib import Path
import subprocess
import sys


def profile_environment(directory):
    home = directory / "home"
    properties = {"user.home": home, "application.settingsdir": home / "settings",
                  "application.cachedir": home / "cache", "application.tempdir": home / "tmp"}
    for path in properties.values():
        path.mkdir(parents=True, exist_ok=True)
    options = " ".join(f'"-D{key}={value}"' for key, value in properties.items())
    return {"JAVA_TOOL_OPTIONS": options, "GHIDRA_HEADLESS_JAVA_OPTIONS": options,
            "XDG_CONFIG_HOME": str(home / "config"), "XDG_CACHE_HOME": str(home / "cache")}


def install(archive, directory):
    """Install normally, then resolve in a fresh JVM; return (environment, native path)."""
    directory.mkdir(parents=True)
    environment = {**os.environ, **profile_environment(directory)}
    for phase in ("install", "resolve"):
        log = directory / f"{phase}.log"
        with log.open("w") as output:
            result = subprocess.run(
                [sys.executable, "-u", str(Path(__file__).resolve()), phase, str(archive.resolve()),
                 str(directory.resolve())],
                env=environment, stdout=output, stderr=subprocess.STDOUT)
        if result.returncode:
            raise RuntimeError(f"extension {phase} failed ({result.returncode}); see {log}")
    native = json.loads((directory / "resolve.json").read_text())["native"]
    return environment, native


def require():
    """Fail unless the running JVM loaded the extension's Java."""
    from ghidra.app.decompiler import DecompileResults
    methods = {str(method.getName()) for method in DecompileResults.class_.getMethods()}
    if "isEnhancedResult" not in methods:
        raise RuntimeError("the KunaDecompiler extension's Java is not loaded; install the "
                           "ZIP with extension.py and run in that profile")


def _phase(phase, archive, directory):
    import pyghidra
    from jpype import JClass
    pyghidra.start()
    directory = Path(directory)
    from ghidra.framework import Application
    from ghidra.util.extensions import ExtensionUtils
    from ghidra.util.task import TaskMonitor
    from java.io import File

    ExtensionUtils.initializeExtensions()
    if phase == "install":
        details = ExtensionUtils.getExtension(File(archive), False)
        if details is None or str(details.getName()) != "KunaDecompiler":
            raise RuntimeError("the ZIP is not the KunaDecompiler extension")
        if not ExtensionUtils.install(details, File(archive), TaskMonitor.DUMMY):
            raise RuntimeError("Ghidra extension installation failed")
        receipt = {"archive": archive}
    else:
        found = [e for e in ExtensionUtils.getActiveInstalledExtensions()
                 if str(e.getName()) == "KunaDecompiler"]
        if len(found) != 1:
            raise RuntimeError("restart did not discover exactly one KunaDecompiler extension")
        native = Path(str(JClass("kuna.KunaCoreSwap").findKunaBinary())).resolve()
        if not native.is_relative_to(Path(str(found[0].getInstallDir())).resolve()):
            raise RuntimeError(f"resolved backend is not the installed executable: {native}")
        require()
        receipt = {"ghidra": str(Application.getApplicationVersion()), "native": str(native)}
    (directory / f"{phase}.json").write_text(json.dumps(receipt, indent=2) + "\n")


if __name__ == "__main__":
    if len(sys.argv) == 3:
        env, native = install(Path(sys.argv[1]), Path(sys.argv[2]))
        for key in ("JAVA_TOOL_OPTIONS", "GHIDRA_HEADLESS_JAVA_OPTIONS", "XDG_CONFIG_HOME",
                    "XDG_CACHE_HOME"):
            print(f"export {key}='{env[key]}'")
        print(f"export KUNA_GHIDRA_EXE='{native}'")
    else:
        _phase(*sys.argv[1:])
