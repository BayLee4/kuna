# Callable graph and object preservation

This slice promotes the round-6 ProtoFacts probes into maintained sources. It is
preservation, not a release-readiness claim. The integrated graph/object suite
and nested-binding Rust test passed at the checkpoint recorded in
[`docs/datatype-callable-cutover-status.md`](../../../../docs/datatype-callable-cutover-status.md).
Positive export or consumer failures remain failures, not expected refusals.

## Entry points

From the repository root, with the current native CLI and built specifications:

```sh
KUNA_CLI=/absolute/path/to/kuna python3 tests/ghidra/callable/graph_and_objects.py
cargo test --manifest-path decompiler/Cargo.toml -p kuna-console --test verify_nested_callable_binding
```

The Python aggregator takes no mandatory arguments, builds fresh fixtures, reports
every active case, and exits nonzero if any case fails. It does not run Cargo;
the Rust command is a separate mandatory semantic check. Missing prerequisites
fail rather than skip. `KUNA_SMOKE_OUT` selects the parent of unique output
directories; `KUNA_CLI` selects the tested CLI. Builders and C consumers resolve
tools through `support.tool` (`LLVM_BIN` and tool-specific `KUNA_*` overrides).
Clang cross targets, LLD, llvm-nm/objdump/readelf, a native C compiler, Python with
PyGhidra, and its configured Ghidra installation are required. These cases use
PyGhidra for original-machine execution, not the `kuna_ghidra` host executable;
`KUNA_GHIDRA_EXE` remains the shared harness setting for host-consuming slices.
The Rust test also needs `python3`; `KUNA_SPECS` overrides the repository specs.
No old report, binary, or module under ignored build output is imported.

## Active contracts

- **Nested defaults:** `verify_nested_callable_binding.rs` uses one real
  `IfaceStatus` and architecture loaded from the authentic i386 fixture. Old
  and Nested retain the exact completed root identities and stdcall bindings;
  Explicit retains its fastcall binding, variadic/input-closure/logical-first
  facts, and nested inner identity. Switching the default changes Future only:
  its binding equals Explicit rather than Old. Materialized slots are stack+4
  for stdcall and exact ECX space/offset/size for fastcall. No emitted-C spelling
  equality or ellipsis substring is substituted for these facts. The former
  private Cargo project is replaced by this normal integration test. The
  original `nested_default_binding.s` and the machine portion of its Python
  wrapper remain maintained: real stdcall/fastcall callbacks return input+1
  and preserve EBP with the expected ESP.
- **Named object:** original C and its DWARF builder preserve nominal State.
  Original-machine checks include readback 20 and 93 after changing count/delta,
  state address equality, and stack restoration. Global-reference on/off
  consumers use unchanged generated C/H at O0/O2, require the actual whole-object
  extern, assert its 16-byte layout and field offsets/sizes, mutate count/delta,
  and check exact `state_address() == &state`. The consumer supplies the original
  data definition only; it does not repair missing declarations or target code.
- **Private leaf:** original source and builder retain authentic entry declaration
  DWARF and explicitly install the original reviewed dispatch/subject machine
  bytes. Post-entry donor location lists are not execution truth. Machine checks
  require stored value 7, result 42, and saved RBP for zero/all-ones initial data.
  Serial, stream, and jobs2 publication require the exact existing-target provider
  identity at the discovered subject address, original pointer formal identity,
  actual whole emitted C/H O0/O2 execution, and refusal when the subject provider
  is omitted. Refusal is nonzero, with no incidental error wording pinned.
- **AArch64 hidden result:** original assembly and builder retain local, overlap,
  below-SP, live-X12 alias, explicit-argument alias, raw-child, and explicit-pointer
  boundaries. Original-machine results and X19/SP/X29 observations are separate
  from metadata admission. The positive `hidden_local` case now additionally
  requests the full emitted `make_big` provider and consumes both unmodified
  generated functions at O0/O2 for tags -20 through 20. There is no handwritten
  target, emitted-C repair, or fabricated physical summary. This exact consumer
  passed in the integrated checkpoint run; historical probes before promotion
  established machine behavior and admission only.

## Conversion records and remaining proof gaps

`hidden_selected_child.py` and the selected-child portion of
`hidden_boundaries.s` preserve the actual two machine cases returning 13 with
SP/X19/X29 restored. The aggregator labels this a limited record: parent refusal
is asserted, but child admission is only observed. Neither a true nor false
`child_admitted` value proves selected-map versus original-raw divergence. No
internal proof receipt exists here; this is not a production bug regression or
an end-to-end generated-provider consumer.

`hidden_result_apple.py` is an optional historical replay, excluded from the active
source-built aggregator. `hidden_result_apple_record.json` embeds the **complete,
exact original Mach-O bytes**, compressed/base64 encoded with size and SHA-256.
The replay reconstructs and checks those bytes in its fresh output directory, so
it has no dependency on the old production-smoke path. Original fixed entry,
callsite, and provider addresses remain deliberately historical. It retains the
AppleSilicon machine assertions (X8 at SP+8, disjoint 24-byte result before saved
X29/X30, original words/results for -20..20) and unchanged emitted caller/provider
O0/O2 requirements. None has been rerun during this promotion. The original donor
source containing `make_big` and a reproducible source builder with discovered
symbols are still missing; the maintained `reference_abi.c` is not that donor.
Do not relabel embedded-byte replay as source-built fixture proof.

Optional replay (OUT must not already exist; SHA is the current CLI hash):

```sh
python3 tests/ghidra/callable/hidden_result_apple.py --cli /absolute/path/to/kuna --sha256 SHA --out OUT
```

All generated metadata and reports come from the supplied current executable.
The historical private Cargo manifest had only kuna-console/kuna-decomp path
dependencies and introduced no additional implementation; those dependencies
already belong to the maintained kuna-console integration-test environment.
