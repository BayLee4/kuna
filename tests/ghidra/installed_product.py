"""Install the supplied product ZIP normally, then resolve it in a fresh JVM."""

import json
import os
from pathlib import Path
import subprocess
import sys


def install_extension(archive, directory):
    directory.mkdir()
    home = directory / "home"
    home.mkdir()
    environment = os.environ.copy()
    properties = {"user.home": home, "application.settingsdir": home / "settings",
                  "application.cachedir": home / "cache", "application.tempdir": home / "tmp"}
    for path in properties.values():
        path.mkdir(exist_ok=True)
    options = " ".join(f'"-D{key}={value}"' for key, value in properties.items())
    environment["JAVA_TOOL_OPTIONS"] = environment.get("JAVA_TOOL_OPTIONS", "") + " " + options
    environment["GHIDRA_HEADLESS_JAVA_OPTIONS"] = options
    environment["XDG_CONFIG_HOME"] = str(home / "config")
    environment["XDG_CACHE_HOME"] = str(home / "cache")
    for phase in ("install", "resolve"):
        command = [sys.executable, "-u", str(Path(__file__).resolve()), phase,
                   str(archive.resolve()), str(directory.resolve())]
        log = directory / f"{phase}.log"
        with log.open("w") as output:
            result = subprocess.run(command, env=environment, stdout=output,
                                    stderr=subprocess.STDOUT)
        if result.returncode:
            raise RuntimeError(f"Normal extension {phase} failed ({result.returncode}); see {log}")
    receipt = json.loads((directory / "resolve.json").read_text())
    environment["KUNA_GHIDRA_EXE"] = receipt["native"]
    return environment, receipt


def main():
    import pyghidra
    from jpype import JClass

    phase, archive, directory = sys.argv[1:]
    directory = Path(directory)
    pyghidra.start()
    from ghidra.framework import Application
    from ghidra.util.extensions import ExtensionUtils
    from ghidra.util.task import TaskMonitor
    from java.io import File

    ExtensionUtils.initializeExtensions()
    if phase == "install":
        details = ExtensionUtils.getExtension(File(archive), False)
        if (details is None or str(details.getName()) != "KunaDecompiler"
                or str(details.getVersion()) != str(Application.getApplicationVersion())):
            raise RuntimeError("ZIP must be KunaDecompiler for the running Ghidra version")
        if not ExtensionUtils.getAllInstalledExtensions().getMatchingExtensions(details).isEmpty():
            raise RuntimeError("Isolated profile already contains KunaDecompiler")
        root = Application.getApplicationLayout().getExtensionInstallationDirs().get(0)
        if not (root.exists() or root.mkdir()) or not root.canWrite():
            raise RuntimeError(f"Extension directory is not writable: {root}")
        if not ExtensionUtils.install(details, File(archive), TaskMonitor.DUMMY):
            raise RuntimeError("Ghidra extension installation failed")
        receipt = {"archive": archive, "module": str(details.getInstallDir())}
    else:
        extensions = [extension for extension in ExtensionUtils.getActiveInstalledExtensions()
                      if str(extension.getName()) == "KunaDecompiler"]
        if len(extensions) != 1:
            raise RuntimeError("Restart did not discover exactly one KunaDecompiler extension")
        module = Path(str(extensions[0].getInstallDir())).resolve()
        swap = JClass("kuna.KunaCoreSwap")
        native = Path(str(swap.findKunaBinary())).resolve()
        if not native.is_relative_to(module) or not os.access(native, os.X_OK):
            raise RuntimeError(f"Resolved backend is not the installed executable: {native}")
        origins = {}
        for name in ("kuna.KunaCoreSwap", "ghidra.app.decompiler.DecompInterface",
                     "ghidra.app.decompiler.PrettyPrinter", "ghidra.app.util.exporter.CppExporter",
                     "ghidra.program.model.data.DataTypeWriter"):
            origin = Path(str(JClass(name).class_.getProtectionDomain().getCodeSource()
                              .getLocation().toURI().getPath())).resolve()
            if not origin.is_relative_to(module):
                raise RuntimeError(f"{name} loaded outside installed extension: {origin}")
            origins[name] = str(origin)
        receipt = {"archive": archive, "ghidra": str(Application.getApplicationVersion()),
                   "module": str(module), "native": str(native), "origins": origins}
    (directory / f"{phase}.json").write_text(json.dumps(receipt, indent=2) + "\n")
    print(json.dumps(receipt, indent=2), flush=True)


if __name__ == "__main__":
    main()
