# Datatype and callable cutover status

The production changes and regression fixtures are in the working tree. This is
an unfinished cutover, not a release-ready change. Remaining architecture work
is paused; no commit has been made.

## Implemented

- Retained source datatype roots and storage volatility through DWARF data-object
  facts, including volatile callback globals.
- Separated physical entry requirements, restoration and conditional execution
  evidence. Readonly admission uses optimizer receipts without deleting raw reads.
- Added caller-owned direct-site adapters, generated logical-result providers and
  internal-role obligations to callable publication. Missing providers refuse export.
- Added Ghidra structural body proofs and actual flow-override provenance to the
  Java/native protocol, with source-edit and publication tests.
- Made C printing use retained SSA types instead of independently widening callable
  types. Representation validation checks COPY/PHI/CAST/PTRSUB families.
- Corrected return-role COPY traversal to scan actual operations; the opcode bank
  does not index COPY. Tagged return-address arithmetic still needs a separate proof.

Algorithm contracts are in `spec/03-ssa-and-simplification.md`,
`spec/04-calls-and-prototypes.md`, `spec/05-types.md` and `spec/09-emission.md`.

## Verification

The release build and `make check-spec` passed. Actual unchanged C/header consumers
passed at `-O0` and `-O2` for volatile scalar callbacks in serial/stream/two-worker
exports, nested i386 conventions, recursive datatype query orders, readonly
publication, named mutable objects, private-leaf providers, local hidden results,
aggregate disjoint storage and pointer-to-array declarations. The completed-root
ABI binding test, corrected MIPS raw-role test and all three RV64 return-role
tests also passed.

The full gates are not green:

| Command | Observed result |
|---|---|
| `make test` | 662/674; 12 baseline regressions |
| `make test-stages` | 1215/1390; 184 baseline regressions and 8 newly passing assertions |
| `cargo test --release --workspace --no-fail-fast` | 47 failed test targets |

The workspace run used the release profile, not `make rust-test`'s default profile.
These full runs preceded the final diagnostic cleanup and focused fixture checks;
they are not final-tree parity claims. Baselines were not changed.
The [failure inventory](features/callable-cutover-checkpoint/verification.json)
retains exact failing targets and stage assertions.

## Remaining failures

- **Callable families:** mixed-width and returned callbacks, finite aggregate
  targets and native Java publication still refuse valid positive cases. Global
  scalar publication is fixed, not the entire producer-driven projection design.
  Returning an adapter instead of the original target would violate pointer identity.
- **Recursive and internal-role proofs:** grounded recursive publication and MIPS
  inherited parents remain incomplete. MIPS return lowering masks RA into ISA-mode
  and PC paths; a COPY-only proof cannot certify it. A complete raw summary does
  not by itself establish a finite normal return.
- **Restoration:** the restored-register fixture returns 42 on the original
  machine but refuses callable publication at `0x100c`.
- **Bitfield layout:** ten nonzero-offset read/write cases fail emitted-C execution
  because the exported structure omits leading bit padding. Original-machine and
  token-identity checks pass; the offset-zero signed case passes.
- **Custom results:** all three register-slice targets complete, but their indirect
  callers refuse unresolved machine effects. Custom stack outputs need a memory
  result proof; clearing incompleteness would discard that obligation.
- **Native imports:** emitted `printf`/`scanf` declarations conflict with SDK
  `const char *` declarations. Provider metadata is available, but mapped import
  stubs still need authentic linkage proof, not a name-based exemption.
- **Hidden-result panic:** `verify_flowreuse::dwarf_locals_are_a_flow_time_seed_that_forces_the_rebuild`
  reaches a CALL containing only its fspec target although source roles require
  `[HiddenResult, Declared(0)]`. There is no execution prototype and the raw boundary
  is false. The proposed shared selector still selects this call and is not a fix.
- **Acceptance gaps:** host union/partial/bitfield-alias mutation and complete
  integrated revision-lifetime coverage remain outstanding. Earlier focused
  lifecycle passes do not establish the whole cutover or its performance budget.

The datatest regressions are Deindirect Output #1, Inlining #4, Long double
#8/#9/#10, Mixed float/int #7, Return Value Input Register #6/#7, Stack Return
#1/#3/#5 and Union #26. They have distinct causes: retained call-clobbered state,
extra physical operands, mapped native targets, return-role coverage, stack result
obligations and emitted casts. Restoring old wording is not a general fix.

## Reproducing and continuing

See [the live-test setup](../tests/ghidra/README.md) for Ghidra, PyGhidra, JDK and
cross-toolchain prerequisites. All active fixtures live under maintained source;
none imports old investigation scripts or reports from build output.

```sh
make test-ghidra-live LIVE_ARGS='--suite callable-consumers --suite callable-transport --suite callable-readonly --suite callable-internal-roles --suite callable-restoration --suite callable-graph-objects --suite callable-datatypes'
cargo test --manifest-path decompiler/Cargo.toml --release -p kuna-console --test verify_nested_callable_binding --test verify_return_role_bookkeeping
cargo test --manifest-path decompiler/Cargo.toml --release -p kuna-console --test verify_flowreuse dwarf_locals_are_a_flow_time_seed_that_forces_the_rebuild
```

The [coverage map](callable-regression-preservation-gaps.md) records fixture locations
and proof limits. Positive failures remain mandatory assertions, not expected
refusals. Temporary diagnostics have been removed.

Unapplied work is preserved separately: [recursive closure](features/raw-recursive-closure/README.md),
[native import declarations](features/native-import-declarations/README.md), and
[callable projection design](callable-projection-design.md). These are designs and
patch drafts, not production implementations.
