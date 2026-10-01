"""Shared prerequisites for authentic callable integration regressions."""
import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]


def tool(name):
    override = os.environ.get('KUNA_' + name.upper().replace('-', '_').replace('.', '_'))
    if override:
        found = shutil.which(override)
        if found:
            return found
        raise FileNotFoundError(f'Configured {name} does not exist: {override}')
    candidates = []
    if os.environ.get('LLVM_BIN'):
        candidates.append(str(Path(os.environ['LLVM_BIN']) / name))
    candidates.extend([name, f'/opt/homebrew/opt/llvm/bin/{name}',
                       f'/opt/homebrew/opt/lld/bin/{name}', f'/usr/local/opt/llvm/bin/{name}'])
    for candidate in candidates:
        found = shutil.which(candidate)
        if found:
            return found
    raise FileNotFoundError(f'{name} is required; put it on PATH or set LLVM_BIN/KUNA_{name.upper().replace("-", "_").replace(".", "_")}')


def _binary(variable, name):
    path = Path(os.environ.get(variable, ROOT / 'decompiler/target/release' / name)).resolve()
    if not path.is_file() or not os.access(path, os.X_OK):
        raise FileNotFoundError(f'{variable} must name an executable: {path}')
    return path


def cli():
    return _binary('KUNA_CLI', 'kuna')


def host():
    return _binary('KUNA_GHIDRA_EXE', 'kuna_ghidra')


def output(slice_name):
    root = Path(os.environ.get('KUNA_SMOKE_OUT', ROOT / 'decompiler/target/ghidra-live')).resolve()
    root.mkdir(parents=True, exist_ok=True)
    return Path(tempfile.mkdtemp(prefix=slice_name + '-', dir=root))


def sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def run_script(name, *args):
    return subprocess.run([sys.executable, '-u', str(HERE / name), *map(str, args)],
                          cwd=ROOT, check=True)
