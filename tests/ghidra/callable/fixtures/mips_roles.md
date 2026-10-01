# Authentic MIPS internal-role matrix

`mips_role_boundaries.S` is the original version-4 assembly used by the live
machine probes. The original conditional `dirty_gp` and the separately named
`dirty_gp_natural` are distinct bodies; neither substitutes for the other.
`dirty_gp` writes V0 in the JR delay slot. The natural child writes V0 before JR.
Both really overwrite GP. The parent bodies do not write GP themselves.

The fixture also contains two calls through mutable data slots, full and partial
GP redefinitions, a readonly branch, and isolated spill/reload/escape controls.
The partial case is a genuine lone `LWR gp,3(base)`: it reads old GP and merges a
new low byte, not a fabricated byte-sized register definition.

## Run the complete maintained slice

```sh
KUNA_SMOKE_OUT=/tmp/kuna-mips-live \
  python3 tests/ghidra/callable/mips_internal_roles.py
```

The shared live-test support creates a unique output directory. `KUNA_CLI`
selects the real CLI; its default is the repository release binary. The normal
live-test `GHIDRA_INSTALL_DIR`, `JAVA_HOME`, and PyGhidra prerequisites apply.
Build the real MIPS specifications before running. LLVM must support
`mipsel-unknown-linux-gnu`; `clang`, `ld.lld`, `llvm-objdump`, a host C compiler,
and Cargo must be available through the shared tool discovery (`LLVM_BIN`, PATH,
or explicit `KUNA_CLANG`, `KUNA_LD_LLD`, `KUNA_LLVM_OBJDUMP`, `KUNA_CC`, and
`KUNA_CARGO`). Missing prerequisites fail; there is no successful skip.

The entrypoint builds both readonly values from this checked-in source, records
compiler/linker/disassembly output and source/binary hashes, runs the opted-in
Rust raw/final-proof matrix, executes all four genuine Ghidra machine-oracle
scopes, and checks actual CLI publication plus unchanged emitted C at `-O0` and
`-O2`. Provider-omission runs remove the actual required child from the export,
not its declaration or machine body. Diagnostics are retained as observations;
temporary engine trace wording is not a test contract.

## Regenerate only the linked fixtures

```sh
python3 tests/ghidra/callable/build_mips_roles.py --out /tmp/new-mips-fixtures
KUNA_MIPS_ROLE_FIXTURES=/tmp/new-mips-fixtures \
  cargo test --manifest-path decompiler/Cargo.toml --release -p kuna-console \
  --features test-support --test verify_mips_internal_roles -- --nocapture
```

The output directory must not already exist. The builder uses real assembly and
linking, not encoded replacement bytes or patched ELF bodies. Machine-oracle
symbol addresses come from the newly linked image.

The optional `test-support` matrix is not part of the default workspace test
proof. It requires the generated fixtures and fails if their environment path is
missing. It checks that safe internal representation never creates raw GP
preservation, that a later implicit GP read rejects inheritance, and that final
private-spill coverage rejects reload and pointer escape. The natural child must
remain genuinely raw-complete with no manufactured conditional execution view.

All positive admission and return-bookkeeping expectations remain enabled even
when the current implementation fails them. A failing inherited publication or
raw return-target proof is an unresolved product regression, not an accepted
negative control. The runner reports a nonzero exit status for any failed stage.
