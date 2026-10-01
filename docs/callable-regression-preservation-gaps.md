# Callable regression coverage

All active probes use maintained fixture sources and shared helpers under
`tests/ghidra/callable/`. Run them through `tests/ghidra/run.py`; setup is in
[tests/ghidra/README.md](../tests/ghidra/README.md). Passing requirements and known
failures are distinguished in [the cutover status](datatype-callable-cutover-status.md).

## Maintained suites

| Suite | Coverage |
|---|---|
| `callable-consumers` | Java producer, datatype/source edits, body-proof decoding, real Publication, exporter failure recovery and native-import provenance |
| `callable-transport` | Mixed-width direct/indirect calls; volatile and returned callbacks; serial/stream/two-worker export; finite aggregate targets; nested conventions; recursive datatype query orders |
| `callable-readonly` | Original-machine readonly/mutable controls, branch receipts, unchanged C and missing-provider refusal |
| `callable-internal-roles` | MIPS raw roles, private spills/reloads/escape, implicit callee reads and inherited effects |
| `callable-restoration` | Private-frame aliases, aggregate escape, saved-slot/register restoration, native bool bytes, variadic boundaries and mixed returns |
| `callable-graph-objects` | Nested binding fixture, hidden-result provider, named mutable object/layout/address identity and private-leaf provider closure |
| `callable-datatypes` | Six signed/cross-boundary bitfield tuples in read/write modes; pointer-to-array and typedef-array consumers; combined Java CALL_RETURN/ordinary exits; three custom register-slice results |

Consumers compile unchanged emitted C/headers at O0/O2, using actual emitted
providers rather than handwritten replacement functions. Fixture data definitions
supply original external storage only. Positive admission or execution failures
remain nonzero failures.

## Rust and existing host coverage

- `kuna-console/tests/verify_nested_callable_binding.rs`: completed roots retain
  identity and ABI binding across a default switch; future roots acquire the new
  default, including nested/explicit variadic contracts.
- `kuna-console/tests/verify_return_role_bookkeeping.rs`: authentic RV64 return
  role, COPY uses, partial reads, width changes, result escapes and implicit
  callee reads. It does not cover tagged returns or reverse-COPY candidate discovery.
- `kuna-console/tests/verify_mips_internal_roles.rs`: opt-in actual loaded/lifted
  MIPS and final internal-body proofs; the Python suite builds its fixtures.
- `kuna-console/src/readonly_replay_tests.rs`: same-owner receipt premise changes
  invalidate conditional publication.
- `kuna-decomp/src/substrate/dtype_graph.rs` and `dtype_factory.rs`: recursive
  completion, reverse invalidation, stale typerefs and retired inferred roots.
- `kuna-analysis/src/dwarf/`: recursive aliases, source identities and variant layouts.
- Existing `tests/ghidra/{settings_lifecycle,type_boundaries,prototype_facts,callsite_overrides,integer_boundaries,pointer_spaces}.py`
  cover host edits/reopen, source/site precedence, scalar and address-bank consumers.

Crate paths above are relative to `decompiler/crates/`.

## Explicit limits

- The historical Apple hidden-result replay retains original Mach-O bytes, but
  its donor source and reproducible builder are missing. It is excluded from the
  active source-built graph suite; do not count it as a rebuilt fixture.
- `hidden_selected_child.py` asserts parent refusal and records child admission.
  It does not prove raw-versus-selected-map divergence.
- The finite variadic register-target control checks machine behavior and metadata,
  not a separate emitted-C consumer.
- No standalone probe was found for an ungrounded returned-family cycle or the
  full host union/partial-aggregate/bitfield-alias ownership matrix across mutation.
- Bitfield-OFF behavior and custom stack-return support are not added by the
  preserved datatype suite.
