# Datatype consumer preservation

Entrypoint (no mandatory arguments):

```sh
python tests/ghidra/callable/datatype_consumers.py
```

Use a Python environment with `pyghidra`, and `GHIDRA_INSTALL_DIR` pointing at the
current integrated Ghidra installation. `KUNA_GHIDRA_EXE` selects the actual native
producer; absent that override, the maintained support helper selects the release
binary. `KUNA_SMOKE_OUT` selects the parent of a unique `datatype-consumers-*`
output directory. A C compiler is required (`support.tool('cc')`, optionally
`KUNA_CC`). This Java surface does not invoke the CLI, so it does not require or
replace `KUNA_CLI`. Missing prerequisites fail every affected row; they are not
skips. Run the entrypoint after integration/build, not against a stale executable.

## Active requirements

All 19 cases run independently and record per-case and aggregate JSON. Every
positive failure makes the process exit nonzero; a refused positive is not a
passing negative. Artifacts include original instruction bytes, original-machine
observations, actual support status/reason/body identities, source storage before
and after publication, and compiler/execution output. Each positive requires the
ordinary exporter C/H to compile and execute unchanged at both O0 and O2. The
only added C is a consumer driver; it does not define replacement function bodies
or repair declarations, expressions, or emitted memory operations.

Source construction is embedded in the maintained script. It does not import
ignored probes, old reports, or ignored fixture binaries. The native executable
is the explicit production prerequisite, not a historical fixture dependency.

### Signed and write bitfields (12 cases)

Promoted from `decompiler/target/round2-review/bitfields/probe.py`, with the exact
six `(byte offset, first bit, width, signed)` tuples:

- `(4,13,12,true)`
- `(4,23,7,false)`
- `(0,0,31,true)`
- `(4,7,25,false)`
- `(4,9,7,true)`
- `(8,5,19,false)`

Each tuple runs read and write variants. The original x86 load, shift,
sign-extension, mask, read/modify/write, and RET bytes are constructed by the same
recipe as the earlier probe. Each original machine body runs all 256 vectors
`raw = i * 0x9e3779b9 (mod 2^32)`; writes use `value = ~raw * 3 (mod 2^32)`.
Reads use an independent extraction/sign-extension oracle. Writes compare the
entire object with an independently masked expected byte array, retaining `0xa5`
neighbor/padding bytes, not merely the named field. The C write oracle similarly
copies the complete object to a byte array before modifying only the expected
four-byte storage unit. Original reads also verify unchanged object memory.

Bitfield simplification is explicitly ON. Every actual `ClangBitFieldToken`
requires component name `middle` and the exact managed parent datatype ID.
Source declarations are emitted by the actual exporter; no handwritten `Bits`
definition substitutes for the source owner. Known unsupported bitfield-OFF
aggregate C is intentionally excluded, not fixed or represented as supported.

### Pointer to array (2 cases)

Promoted from `decompiler/target/round2-review/emitters/probe.py`:
`array_pointer` is a pointer to `Array(LongLong,2)`;
`array_typedef_pointer` is a pointer to the genuine managed typedef `PairArray`.
Both retain the exact `48 8b 47 18 c3` load at +24. Original machine memory and
actual C consume `{{-739,219},{831,-415}}` and must return `rows[1][1] == -415`.
The high parameter must remain equivalent to the actual installed datatype.
Unlike the old report-only execution failures, both cases are mandatory.

### Combined Java CALL_RETURN (2 cases)

Promoted from
`decompiler/target/round6-physical-inputs/ProtoFacts/java_callreturn_acceptance.py`.
The subject has an ordinary exit plus direct and memory-indirect CALL_RETURN
sites at `0x100b` and `0x101a`. Both actual instruction routes are inspected before
and after the real `FlowOverride`; the indirect route must retain LOAD before
CALLIND. The installed `PcodeEmitPacked` origin must be the integrated producer
JAR. Actual targets at `0x1100`/`0x1200` add 10/20. The callback slot at `0x1400`
contains the actual target_b address. The C driver initializes the corresponding
mutable global to the emitted `target_b`, not a replacement callback. The
integrated exporter delegates globals to Publication's declarations writer; the
native global emitter supplies `extern` declarations. The driver requires that
actual external declaration and uses its exact type for the sole fixture-data
definition and original initializer. The emitted C/H remains unchanged, with no
duplicate tentative/weak/common definition workaround. The report records this
ownership and the original slot/target addresses.

For choices `0,1,UINT32_MAX` and values `-7,0,5,1234`, original-machine execution
checks values and stack deltas. The positive requires ordinary stack delta 8
and complete actual caller-plus-target publication/execution. The malformed
ordinary `RET 8` variant has delta 16 only on the ordinary branch. Its actual
`CallableSupport.Publication` must refuse. No old transport-comment spelling or
incidental diagnostic text decides admission. The overlapping standalone INT3
case is not promoted here.

### Custom subregister returned values (3 cases)

Promoted from `decompiler/target/round3-review/returns/probe.py`, replacing its
handwritten C `target(value) { return (type)value; }` with the **actual emitted
machine provider**. These are active positive requirements, not dormant passing
claims or expected refusals. The real target and both real callers are added to
Publication, validated, and exported together. No separate dormant old consumer
is retained because its handwritten provider is superseded by this active
machine/provider construction.

Exact target contracts and bytes:

| Case | Source return storage | Target bytes |
| --- | --- | --- |
| upper_uint | RAX+4, 4-byte unsigned int | `89f848c1e020c3` |
| middle_short | RAX+3, 2-byte signed short | `480fbfc748c1e018c3` |
| upper_byte | RAX+7, 1-byte signed char | `480fbec748c1e038c3` |

The target remains at `0x2000`; the indirect caller at `0x1000` begins
`4883ec08488d05f50f0000ffd0`, and the direct caller at `0x1100` begins
`4883ec08e8f70e0000`. Each then applies the original extraction
(`48c1e820`, `48c1e8180fbfc0`, or `48c1f838`, respectively) and ends
`4883c408c3`. The maintained source asserts the precise installed return varnode
address and size. All functions retain explicit custom RDI input storage; callers
retain EAX output storage. Before/after source snapshots prevent publication
from silently rewriting these source contracts.

Both original callers and both emitted callers consume all original vectors:
`0x123456789abcdef0`, `0xfedcba9876543210`, `0x00000001ffffff80`, and
`0xffffffff00007fff`. The independent oracle masks to the logical result width
and sign-extends only signed cases. The actual-provider integration was not
assumed unsupported: a failure to admit/emit this contract is now an ordinary
nonzero positive failure, not a claimed pass or an invented limitation.

## Verification status and limits

This preservation change does not change production code and does not establish
release readiness. The integration owner's initial run reported 5 passing and 14
failing cases: the zero-offset bitfield read/write, typedef-array, and two combined
flow cases passed. Examination of the generated artifacts distinguished:

- Ten nonzero-bit-offset bitfield cases: original machine and token identities
  passed, but the exported `Bits` definition omitted the leading bitfield padding.
  For example the `(4,13,12,true)` header placed `int middle : 12` immediately after
  `pad0`, so the emitted read consumed bits 0–11 rather than 13–24. The actual O0
  consumer returned failure. This is an emitted-layout positive failure, not a
  driver fix opportunity; the headers and assertions remain unchanged.
- Plain pointer-to-array: the driver used C `long long` while the emitted
  `longlong` typedef mapped to host `long`. The driver now uses the genuine
  emitted `longlong` type, matching the source contract without altering C/H.
  This was a consumer-type error. The corrected case subsequently passed actual
  Java Publication and unchanged C at O0/O2 against the cleaned native core;
  the full 19-case matrix was not rerun.
- All three custom-return cases: original direct/indirect machine vectors passed;
  the actual target was COMPLETE, but the indirect caller returned REFUSED for
  unresolved machine flow or effects. No handwritten provider or expected-refusal
  conversion is introduced. These positive publication failures remain nonzero.

The executable assertions above describe required proof, not universal observed
passing results. In particular,
admission/source-owner/global publication defects must remain visible rather than
be papered over in drivers.
The existing known positive failures elsewhere in callable publication remain
independent release blockers. This slice does not add bitfield-OFF support,
custom stack-return support, synthetic wire summaries, or source-body adapters.
