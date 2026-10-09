"""Shared prerequisites and genuine publication/machine consumers for callable tests."""
import hashlib
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]


def start_ghidra():
    """Use the stock host prerequisite and model-initialization owner."""
    if str(HERE.parent) not in sys.path:
        sys.path.insert(0, str(HERE.parent))
    from kuna_vs_stock import start_ghidra as start
    return start()


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


def require_provider_body(path, name):
    """Require the selected real provider definition in unchanged exporter output."""
    body = Path(path).read_text()
    tokens = re.sub(
        r'//[^\n]*|/\*.*?\*/|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'',
        ' ', body, flags=re.DOTALL,
    )
    assert re.search(r'\b' + re.escape(name) + r'\s*\([^;{}]*\)\s*\{', tokens), (name, path, body)


def execute_i386_publication(row, directory, header, body, driver, default_stdcall):
    """Compile untouched publication bytes and execute their actual i386 ABI."""
    from whole_calls_workers import ElfMachine
    from java.math import BigInteger
    from jpype import JArray, JByte

    def invoke(command):
        command = list(map(str, command))
        result = subprocess.run(command, cwd='/tmp', capture_output=True, text=True, timeout=240)
        observation = dict(command=command, status=result.returncode,
                           stdout=result.stdout, stderr=result.stderr)
        row.setdefault('commands', []).append(observation)
        assert result.returncode == 0, observation

    row['emitted_sha256'] = {path.name: sha256(path) for path in (header, body)}
    for optimization in ('-O0', '-O2'):
        case = directory / optimization[1:]
        case.mkdir()
        objects = []
        for source in (body, driver):
            obj = case / (source.stem + '.o')
            objects.append(obj)
            command = [tool('clang'), '--target=i386-unknown-linux-gnu', '-std=c11',
                       '-ffreestanding', '-fms-extensions', '-fno-builtin', '-fno-stack-protector',
                       '-fno-pic', '-fno-pie', '-Wall', '-Werror=uninitialized',
                       '-Werror=ignored-attributes', '-Werror=incompatible-pointer-types',
                       '-Werror=implicit-function-declaration', optimization, '-I', header.parent]
            if default_stdcall:
                command += ['-mrtd', '-fshort-wchar']
            invoke([*command, '-c', source, '-o', obj])
        image = case / 'consumer.elf'
        invoke([tool('ld.lld'), '-m', 'elf_i386', '--image-base=0', '-Ttext=0x1000',
                '-e', 'main', '--build-id=none', *objects, '-o', image])
        invoke([tool('llvm-objdump'), '-d', image])
        machine = ElfMachine(image, case)
        try:
            assert str(machine.program.getLanguageID()) == 'x86:LE:32:default'
            symbols = list(machine.program.getSymbolTable().getSymbols('main'))
            assert len(symbols) == 1, symbols
            emulator = machine.EmulatorHelper(machine.program)
            try:
                preserved = [('EBP', 0x11223344), ('EBX', 42), ('ESI', 0x12345678), ('EDI', 0x23456789)]
                for register, value in [('ESP', 0x7fdc), *preserved]:
                    emulator.writeRegister(register, BigInteger(str(value)))
                emulator.writeMemory(machine.address(0x7fdc), JArray(JByte)((0x7ff0).to_bytes(4, 'little')))
                emulator.setBreakpoint(machine.address(0x7ff0))
                assert emulator.run(symbols[0].getAddress(), None, machine.monitor), str(emulator.getLastError())
                assert emulator.getExecutionAddress() == machine.address(0x7ff0)
                actual = int(str(emulator.readRegister('EAX'))) & 0xffffffff
                assert actual == 0, actual
                assert int(str(emulator.readRegister('ESP'))) == 0x7fe0
                for register, value in preserved:
                    assert int(str(emulator.readRegister(register))) == value
                row.setdefault('execution', []).append({
                    'optimization': optimization, 'target': 'i386-unknown-linux-gnu',
                    'default': 'stdcall (-mrtd)' if default_stdcall else 'cdecl',
                    'actual_main_EAX': actual, 'final_ESP': 0x7fe0, 'binary_sha256': sha256(image)})
            finally:
                emulator.dispose()
        finally:
            machine.close()
    assert row['emitted_sha256'] == {path.name: sha256(path) for path in (header, body)}


def execute(out, row, driver, flags=()):
    """Consume the publication's untouched C/H, never a replacement provider."""
    (out / 'driver.c').write_text('#include "unit.h"\n#include <stdint.h>\n#include <string.h>\n' + driver)
    row['execution'] = []
    for optimization in ('-O0', '-O2'):
        binary = out / ('consumer' + optimization)
        commands = [[tool('cc'), '-std=c11', '-Wall', '-Werror=uninitialized',
                     '-Werror=incompatible-pointer-types', '-Werror=implicit-function-declaration',
                     optimization, *flags, str(out / 'unit.c'), str(out / 'driver.c'), '-o', str(binary)],
                    [str(binary)]]
        for command in commands:
            result = subprocess.run(command, capture_output=True, text=True, timeout=120)
            observation = dict(command=command, status=result.returncode,
                               stdout=result.stdout, stderr=result.stderr)
            row['execution'].append(observation)
            assert result.returncode == 0, observation


def snapshot(functions):
    return {name: {'signature': str(fn.getSignature()),
                   'return_storage': str(fn.getReturn().getVariableStorage()),
                   'parameters': [{'name': str(p.getName()), 'type': str(p.getDataType()),
                                   'storage': str(p.getVariableStorage())}
                                  for p in fn.getParameters()]}
            for name, fn in functions.items()}


def publish(machine, functions, out, row, inspect=None):
    from ghidra.app.decompiler import DecompInterface, DecompileOptions
    from kuna_vs_stock import export_program, selected_core

    interface = DecompInterface()
    before = snapshot(functions)
    row['source_before'] = before
    row['decompilations'] = []
    try:
        with selected_core(host()):
            options = DecompileOptions()
            options.grabFromProgram(machine.program)
            options.setBitfieldAccess(True)
            options.setNamespaceStrategy(DecompileOptions.NamespaceStrategy.Never)
            interface.setOptions(options)
            assert interface.openProgram(machine.program), str(interface.getLastMessage())
            for name, function in functions.items():
                result = interface.decompileFunction(function, 120, machine.monitor)
                observed = {'name': name, 'completed': bool(result.decompileCompleted()),
                            'error': str(result.getErrorMessage())}
                row['decompilations'].append(observed)
                assert observed['completed'], observed
                fragment, high = result.getDecompiledFunction(), result.getHighFunction()
                assert fragment is not None and high is not None, observed
                (out / (name + '-fragment.c')).write_text(str(fragment.getC()))
                prototype = high.getFunctionPrototype()
                assert prototype.getNumParams() == function.getParameterCount(), observed
                assert prototype.getReturnType().isEquivalent(function.getReturnType()), observed
                assert prototype.getReturnStorage() == function.getReturn().getVariableStorage(), observed
                for index, parameter in enumerate(function.getParameters()):
                    recovered = prototype.getParam(index)
                    assert recovered.getName() == parameter.getName(), observed
                    assert recovered.getDataType().isEquivalent(parameter.getDataType()), observed
                    assert recovered.getStorage() == parameter.getVariableStorage(), observed
                if inspect is not None:
                    inspect(result)
            exported = export_program(machine.program, out / 'unit.c', machine.monitor,
                                      options=options)
            row['stock_exported'] = exported
            assert exported, 'Actual stock CppExporter rejected source export'
            for name in functions:
                require_provider_body(out / 'unit.c', name)
            row['publication_sha256'] = {name: sha256(out / name) for name in ('unit.c', 'unit.h')}
    finally:
        interface.dispose()
        row['source_after'] = snapshot(functions)
        assert row['source_after'] == before, 'Export must not mutate source identity/storage'


def emulate(machine, pc, registers, memory=(), size=0):
    from jpype import JArray, JByte
    from java.math import BigInteger
    emulator = machine.EmulatorHelper(machine.program)
    try:
        for register, value in registers:
            emulator.writeRegister(register, BigInteger(str(value)))
        for address, data in memory:
            emulator.writeMemory(machine.address(address), JArray(JByte)(data))
        emulator.writeRegister('RSP', 0x7fe0)
        emulator.writeMemory(machine.address(0x7fe0), JArray(JByte)((0x7ff0).to_bytes(8, 'little')))
        emulator.setBreakpoint(machine.address(0x7ff0))
        assert emulator.run(machine.address(pc), None, machine.monitor), str(emulator.getLastError())
        assert emulator.getExecutionAddress() == machine.address(0x7ff0)
        observed = {'rax': int(str(emulator.readRegister('RAX'))) & ((1 << 64) - 1),
                    'stack_delta': int(str(emulator.readRegister('RSP'))) - 0x7fe0}
        if size:
            observed['memory'] = bytes(int(b) & 255 for b in emulator.readMemory(machine.address(0x7100), size)).hex()
        return observed
    finally:
        emulator.dispose()


def run_script(name, *args):
    return subprocess.run([sys.executable, '-u', str(HERE / name), *map(str, args)],
                          cwd=ROOT, check=True)
