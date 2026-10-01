# Using kuna as Ghidra's decompiler core

How kuna replaces the native `decompile` process behind Ghidra's stock GUI — the
architecture, the wire protocol, what kuna already has, what each phase adds, and the
response contracts that make the GUI actually work. Audience: kuna developers
implementing Phases 2–4 (Phase 1 — the protocol-complete, engine-stubbed binary plus the
extension that spawns it — is on branch `feat/ghidra-mode`).

**Citation convention.** Ghidra sources are cited as `file:line` against the Ghidra
12.2-DEV checkout at commit `f9e13846` (2026-06-16). Java paths are under
`Ghidra/Features/Decompiler/src/main/java/ghidra/app/decompiler/` unless otherwise
noted; C++ paths under `Ghidra/Features/Decompiler/src/decompile/cpp/`. kuna's own
pinned port anchor is `GHIDRA_REV` `cef869af` (2026-06-01, `docs/history.md`); the one
protocol-relevant delta between the two revisions is called out in §8. kuna paths are
relative to `decompiler/crates/`.

---

## 1. The decision: reimplement the native side, leave Ghidra alone

Ghidra's Java GUI talks to its decompiler through a **child process** named `decompile`,
spawned lazily on the first decompile request (`DecompInterface.java:267`) and driven
over stdin/stdout with a burst-framed binary protocol (`DecompileProcess.java:54-63`).
Upstream, that process is the C++ `ghidra_opt` build — the same DECCORE engine kuna
ported, linked against a `GHIDRA` glue group (`ghidra_process.cc`, `ghidra_arch.cc`,
`ghidra_translate.cc`, …) that kuna deliberately excluded from the port (LOSS-002,
see `docs/history.md`).

**kuna reimplements exactly that glue group**: a new **`kuna-ghidra`** crate producing a
binary that speaks the full decompiler-process protocol, backed by kuna's engine. The
stock Ghidra GUI, analyzers, scripts and `DecompInterface` remain the consumers.
The extension (`integrations/ghidra/KunaDecompiler/`, §7) points the spawn at our
binary and packages narrow Java producer and consumer deltas built against the target Ghidra
release. Its installer creates a separate complete Ghidra distribution, loading the
producer through the supported `Ghidra/patch` bootstrap path; the original installation
is never modified. This avoids both a forked callback chain and missing authoritative
metadata in otherwise ordinary consumers.

Java lowers an explicit `FlowOverride.CALL_RETURN` before returning instruction
p-code. The maintained `PcodeEmit`/`PcodeEmitPacked` delta marks only its synthesized
RETURN with unsigned per-op attribute `kuna_callreturn` (ID 4002), naming the exact
paired CALL/CALLIND ordinal in the same instruction. Ordinary RETURNs and authored
trap CALL/RETURN-zero sequences are unmarked. Kuna validates and consumes that origin
without applying the override twice. An unextended producer supplies no such evidence;
compilable C or operation adjacency cannot waive a callable-transport refusal. The
stock native decoder skips the optional attribute. The packaged producer is bound to
the exact application properties, SoftwareModeling and Decompiler JARs and source
archives, and the callable-support protocol revision; rebuild against another
distribution rather than using an extension-version override.

The second maintained delta, `producer/callable-support.patch`, carries source-type
identity from `PcodeDataTypeManager` and decodes the native `callable_support` sibling
into an immutable value exposed by `DecompileResults.getCallableSupport()` and
`DecompiledFunction.getCallableSupport()`. Genuine stock absence is `Optional.empty()`;
explicit refusal is not absence. Malformed or duplicate records fail decoding and
clear the result rather than falling back to a legacy fragment. Existing `getC()`
and `getSignature()` remain the current function fragment with linked markup intact;
they do not silently append wrappers or claim a complete compilation unit.

The ordinary `CppExporter` collects all chunks into one invocation-local publication.
It validates exact declarations, actual body receipts, provider dependencies, and
source ownership before publishing staged C/header files. Native-owned type
definitions suppress only matching source identities in `DataTypeWriter`, not
same-named or structurally equivalent host types; unrelated Program definitions
remain available. Source declarations and editing semantics are retained. Failed
decompilation, refusal, malformed support, missing providers, stale source identity,
or cancellation fails the export without replacing its existing destinations.
Successful stock exports retain the legacy path, but their fragments cannot satisfy
native callable-provider dependencies. The two final file moves are not an atomic
filesystem transaction.

Rejected alternatives, for the record:

- **Fork `DecompInterface`/the Java chain.** The GUI chain is hardcoded `new` at every
  link (`DecompilePlugin.java:93` → … → `Decompiler.java:75` → `DecompInterface.java:267`)
  with ~28 `new DecompInterface()` call sites across the tree and no injection seam.
  A fork covers only the call sites you rewrite, breaks the "normal Ghidra GUI" goal,
  and is unmaintainable against upstream.
- **A shim process wrapping kuna's existing CLI.** The protocol is not
  request/response: the native side issues **callback queries mid-decompile**
  (per-instruction p-code, symbols at an address, bytes, types — §4) that a
  `kuna decompile-all` wrapper cannot answer; and the response is not C text but a
  typed dual-document (`HighFunction` + token markup with cross-referenced ids, §6)
  over live program state. There is no shim-shaped solution.

### Shared engine, frontend adapters

CLI declarations and Ghidra signatures/overrides are producers of the same core
feature. Type completion, model resolution, ABI assignment, callsite precedence
and rendering authority belong in the shared engine. Adapters translate syntax,
wire records and lifecycle; they must not implement competing analysis semantics.
Host storage and independent locks remain authoritative facts, not differences
to erase in pursuit of byte-identical output or identical interfaces.

Intentional Kuna defaults should remain reasonably aligned across frontends,
while explicit supported choices must work. Java's sparse option packet means
"omitted = Java default", not "unchanged" or "Kuna default". The adapter
overlays the known sparse-baseline differences through
shared setters: NULL and inplace printing off, function braces on the next line.
It retains Kuna's engine presets and naming policy instead of replacing all
core defaults with stock defaults. Omission cannot distinguish an untouched
preference from a deliberately selected Java default.

The development host does not select supported target architectures. Keep
Linux and other target/compiler coverage when developing on macOS/AppleSilicon:
decoding and ABI-model checks are cross-target. Gate only target-code execution
that actually needs a compatible host or emulator, and report unexecuted ABI
witnesses rather than dropping those targets.

## 2. Architecture and session lifecycle

```
Ghidra GUI (untouched)                          kuna-ghidra binary
──────────────────────                          ─────────────────────
DecompilerProvider/Controller/Manager           main loop: readCommand()
  → DecompInterface                               ├─ registerProgram  → ArchitectureGhidra-equiv
    → DecompileProcessFactory.get()               ├─ setOptions/setAction (replayed state)
      → spawn kuna_ghidra  ◄──── extension        ├─ decompileAt ──┐
        (stdin/stdout bursts)                     │   queries back ─┘ getPcode/getBytes/…
                                                  ├─ flushNative   (after every function)
                                                  └─ deregisterProgram → exit
```

- **Spawn**: lazy, on first decompile; `runtime.exec(exepath)` with **no arguments and
  no environment changes** (`DecompileProcess.java:151`); Java waits 200 ms, checks
  `isAlive()`, and reads stderr into an error dialog if the process died
  (`DecompileProcess.java:154-192`). There is **no startup handshake** — the process
  silently waits for the first command.
- **Session**: `registerProgram` (four XML spec documents → a new engine session,
  answered with a decimal *archid*) → replayed session state (`setOptions`, `setAction`,
  print toggles, signature settings — `DecompInterface.java:262-352`) → any number of
  `decompileAt` + `flushNative` pairs (Java flushes the native caches after **every**
  decompiled function, `DecompInterface.java:826-832`) → `deregisterProgram`, which
  answers and then **terminates the process** (C++ sets `status=1`, ending the main
  loop, `ghidra_process.cc:242-248,533-535`; Java never reuses a deregistered process,
  `DecompileProcess.java:501-522`).
- **Timeout is process murder**: on decompile timeout Java disposes the process from a
  timer thread so the blocked read throws (`DecompileProcess.java:100-106,564-595`).
  The native side never sees a cancel message — it sees EOF, on which it must `exit(1)`
  (`ghidra_arch.cc:95-96`).
- **Respawn + replay**: any IOException marks the process bad; the next request
  respawns, re-registers the program, and replays options/action/toggles
  (`DecompInterface.java:354-361,262-352`). The native side needs no persistence — a
  fresh process must simply reach the same state from the replay.

## 3. The wire protocol, condensed

The byte-level ground truth is the upstream implementation (`DecompileProcess.java`,
`ghidra_arch.cc`). Summary:

**Burst framing** (`DecompileProcess.java:54-63`; `ghidra_arch.cc:50-77`): every marker
is written as `{0x00,0x00,0x01,code}` and read tolerantly (skip garbage, one-or-more
`0x00`, expect `0x01`, then the code byte — `readToAnyBurst`, `ghidra_arch.cc:79-98`).
Even codes open, odd codes close.

| pair | meaning | direction |
|---|---|---|
| 2 / 3 | command | Java → native |
| 4 / 5 | callback query | native → Java |
| 6 / 7 | command response | native → Java |
| 8 / 9 | query response | Java → native |
| 10 / 11 | exception | both |
| 12 / 13 | byte-stream payload | both |
| 14 / 15 | string-stream payload | both |
| 16 / 17 | native message (warnings) | native → Java |

String streams (14/15) carry either raw ASCII (command names, decimal archids, the
`t`/`f` answers) or a **packed** binary document (kuna's bit-exact
`kuna-base/src/marshal.rs` `PackedEncode`/`PackedDecode`) — every packed byte is
nonzero, so the closing burst's leading `0x00` terminates ingestion. The only XML on
the wire is the four `registerProgram` spec strings.

**Commands** (dispatch `ghidra_process.cc:464-486`; every command's first parameter
after the name is the decimal archid in a string burst, *except* `registerProgram`):

| command | parameters after archid | response payload | queries legal during? |
|---|---|---|---|
| `registerProgram` | *(no archid)* pspec, cspec, tspec, coretypes — 4 XML string bursts (`ghidra_process.cc:162-173`) | new archid, ASCII decimal | **yes** |
| `deregisterProgram` | — | `1`/`0` decimal; then process exit | no |
| `flushNative` | — | `0` decimal | no |
| `decompileAt` | packed `<addr>` of the entry | packed `<doc>` (§6); no document frame on analysis failure | **yes** |
| `structureGraph` | packed block graph | packed restructured block graph | **yes** |
| `setAction` | actionstring, printstring (2 string bursts) | `t`/`f` | no |
| `setOptions` | packed `<optionslist>` | `t`/`f` | no |
| `generateSignatures` | packed `<addr>` | packed `<signatures>` | **yes** |
| `debugSignatures` | packed `<addr>` | packed debug-sig doc | **yes** |
| `getSignatureSettings` | — | packed `<sigsettings>` | no |
| `setSignatureSettings` | decimal settings string | `t`/`f` | no |

Choreography invariant: the response-open burst 6 is written **before** parameters are
read (`GhidraCommand::doit`, `ghidra_process.cc:125-135`), so callback queries nest
inside the open response; the result payload is followed by the 16/17 warnings frame
(always present, possibly empty — `ghidra_process.cc:108-116`), then 7, then flush.
The "queries legal" column is a **hard constraint**: Java nulls its callback
decoder/encoder for all other commands (`DecompileProcess.java:512-513,536-537,618-619,
657-658,686-687` vs `:472-473,571-572`) — a query issued during `setOptions` desyncs
the protocol.

Analysis errors propagate through `GhidraCommand::doit` before the result's 14/15
frame opens, matching stock `DecompileAt::rawAction`. Low-level errors use the
16/17 native-message frame and the normal response closer; Java exceptions use
the existing exception frame instead. An opened-but-empty document is not equivalent
to an absent document: Java attempts to decode it and replaces the native diagnostic
with a packed-decoder error. Stock's separate, nonthrowing `!isProcComplete` path
can emit an empty frame; it is not the contract for an analysis exception.

**The 19 callback queries** (native → Java; element ids `ghidra_arch.cc:30-48` =
`ElementId.java:371-427`; framing: `4, 14 <packed command element> 15, 5, flush`, then
read `8 payload 9`, or `10 type msg 11` = a Java exception rethrown into the decompile):

| query | id | request params | response transport |
|---|---|---|---|
| `isNameUsed` | 239 | name, first (scope id), last | bool: raw `t`/`f` in 14/15 |
| `getBytes` | 240 | `<addr>` + size | byte burst 12/13, nibble-doubled (`'A'+hi,'A'+lo`); empty ⇒ DataUnavail |
| `getCallFixup` | 241 | name + `<context>` | packed `<inst>` of ops |
| `getCallMech` | 242 | name + `<context>` | packed `<inst>` |
| `getCallOtherFixup` | 243 | name + `<context>` | packed `<inst>` |
| `getCodeLabel` | 244 | `<addr>` | plain string (label, "" = none) |
| `getComments` | 245 | type-flag mask + `<addr>` | packed `<commentdb>` — **always written**, possibly empty |
| `getCPoolRef` | 246 | size n + n×`<value>` | packed cpool record |
| `getDataType` | 247 | name + id (signed) | packed `<type>`, or empty = not found |
| `getExternalRef` | 248 | `<addr>` | packed `<doc><mapsym>`, or empty |
| `getMappedSymbols` | 249 | `<addr>` | packed `<doc><mapsym>` / `<hole>`, or empty |
| `getNamespacePath` | 250 | id (unsigned) | packed `<parent>` with `<val>` per level |
| `getPcode` | 251 | `<addr>` | packed `<inst offset><addr/><op>…` or `<unimpl offset>`; empty ⇒ BadDataError, decompile **continues** |
| `getPcodeExecutable` | 252 | name + `<context>` | packed `<inst>` |
| `getRegister` | 253 | name | packed `<addr space offset size>` |
| `getRegisterName` | 254 | `<addr>` + size | plain string ("" = none) |
| `getStringData` | 255 | maxsize, type name, id + `<addr>` | byte burst: 2-byte biased length of len+1, raw trunc flag, nibble-doubled UTF-8 + doubled NUL |
| `getTrackedRegisters` | 256 | `<addr>` | packed `<tracked_pointset>` — **always written** |
| `getUserOpName` | 257 | index (signed) | plain string ("" = end of table) |

Registration-time traffic the client expects: the `getUserOpName` probe loop (index
0,1,2,… until "") fires during `registerProgram` init (`ghidra_translate.cc:107-117`),
establishing the CALLOTHER index table.

## 4. P-code comes from Java, per instruction (decided)

kuna ships a full SLEIGH engine and vendors every upstream spec, so the tempting
shortcut is to disassemble locally and use the wire only for bytes/symbols. **Rejected**
— Phase 2 ports `GhidraTranslate` faithfully (`ghidra_translate.cc:120-156`: one
`getPcode` query per instruction, register-name caches, no p-code cache), because:

1. **There is no wire query for low-level disassembly context.** The upstream
   `ContextGhidra` throws on every context-variable method
   (`ghidra_context.hh:36-47,60-74`) — disassembly context (ARM/Thumb, MIPS16,
   context-register state per address) lives only in Java's program database. A local
   SLEIGH engine would disassemble Thumb code as ARM with no way to know better.
2. **Listing parity.** What Java disassembled — including user overrides, manual
   context, length-override instructions — is exactly what gets decompiled. That
   invariant is the point of the product: the decompiler view always matches the
   listing view.
3. **It is what the wire contract assumes.** The spawn passes no arguments to identify
   a language; the tspec carries only address spaces + endianness + uniqbase, not a
   language id (`SleighLanguage.encodeTranslator`); and `flushNative`'s cache semantics
   (Java flushes after every function) are designed around Java being the source of
   truth for all program facts. A local-SLEIGH kuna would need out-of-band language
   resolution the protocol simply does not carry.

Consequence for kuna: `Architecture.translate` is today a **concrete `Sleigh`** field
(`kuna-decomp/src/infra/architecture.rs:836`). Phase 2 introduces a `Translate` seam on
`Architecture` — an **enum over `{Sleigh, GhidraTranslate}`**, not a `Box<dyn>`, to keep
`manage()` (the space-manager accessor) concrete and the standalone path untouched. The
lift stage is already trait-typed at the consumption point
(`FlowEnvironment::translate() -> &dyn Translate`, called at
`kuna-decomp/src/s2_lift/flow.rs:1321`), and the trait itself
(`kuna-sleigh/src/translate.rs:386`) is a faithful port of the C++ virtual. The
space-manager-without-`.sla` problem is already solved: `insert_space`
supports the sparse tspec indices (`kuna-base/src/space.rs:2545-2566`) and a unit test
builds a manager purely from decoded `<space>` elements
(`kuna-sleigh/src/translate.rs:1086-1124`). Phase 1 already ships the
`GhidraTranslate::decode` equivalent — `kuna-ghidra/src/translate.rs` parses the tspec
`<sleigh>` element (endianness, `uniqbase`, the `<space>`/`<space_unique>`/`<space_other>`/
`<space_overlay>` list, `<truncate_space>`) into a real `AddrSpaceManager`, which is why
`decompileAt` already decodes real `<addr>` parameters (`ghidra_translate.cc:161-176`).
Phase 2 only wires that manager into an `Architecture`.

## 5. Symbols, types, comments, strings, injects: pull-only ⇒ lazy caches (decided)

The wire has **no enumerate-the-program query**. Symbols arrive one address at a time
(`getMappedSymbols`), types one id at a time (`getDataType`), comments per function
(`getComments`), strings per address (`getStringData`), inject bodies per call site
(`getPcodeInject` family). Eager pre-population — the pattern kuna's analysis tier uses
(`ConsoleProgram::commit_pending_analysis`) — is therefore **impossible**, not merely
inferior: there is nothing to enumerate. kuna needs the upstream lazy model:

- **`ScopeGhidra`** (`database_ghidra.cc`): every lookup checks a local cache, then
  queries, then materializes the answer — including negative answers as `<hole>` ranges
  so the same miss is never re-queried, readonly/volatile flags folded into the
  property map with dirty-tracking, and namespaces rebuilt on demand via
  `getNamespacePath`.
- **`TypeFactoryGhidra`** (`typegrp_ghidra.cc:20-36`): one override — `findById` miss →
  `getDataType` → decode into the local factory.
- **`CommentDatabaseGhidra`** (`comment_ghidra.cc:30-49`): fill-once-per-function from
  `getComments`, filtered by the printer's current comment settings.
- All of it flushed by `flushNative` after every function
  (`ghidra_process.cc:262-273`): global scope, sub-scopes, non-core types, comments,
  string decodings, cpool.

The C++ virtuals these classes override were deliberately collapsed in the port (the
`Scope`/`ScopeInternal` merge, `kuna-decomp/src/p0_knowledge/database.rs`), so Phase 3
relocated the lazy model to the seams the kuna pipeline actually reads
(**shipped** — `kuna-decomp/src/infra/remote_provider.rs`):

- **`RemoteScope`** (the `ScopeGhidra` port at the GlobalQuery boundary): installed on
  `Architecture` at registerProgram and threaded into every per-function `ArchContext`
  by `build_arch_handle`; every global-scope read (`query_global_properties`,
  `name_for_global_varnode*`, `query_container_global`, `query_callee_proto`,
  `query_function`) and the flow environment's callee
  name/no-return queries resolve through `effective_global_query`/`function_at` —
  query-through with `<hole>` negative caching, decoded-entry positive caching,
  readonly/volatile property paints over a `lockDefaultProperties` snapshot, and
  namespace paths via getNamespacePath.  The wire is reached through the
  `RemoteProviderFetch` trait (implemented in `kuna-ghidra/src/provider.rs` over the
  shared client); the standalone path installs nothing and stays byte-identical.
  Function-specific prototypes live in entry-address-keyed `RemoteFunctionFacts`,
  not structurally interned callable types. Current functions, callees and resolved
  function-backed slots copy exact committed storage and independent locks from
  these facts; ordinary local symbols remain a separate channel. The same facts
  preserve the host's inline designation and supply its body to the inline path.
  A wider physical execution input does not replace the host formal: the encoded
  prototype and category-zero symbols retain its original name, type and storage.
  A live source projection may be a `HighParam`; its raw execution carrier is
  not, and carrier tokens carry neither varnode nor operation edit references.
  Printed C, including Java's `getC()`, uses the physical execution header rather
  than a source-only header over a body that needs additional bits. Rename,
  retype and flush/reopen rebuild the derived view from the host facts.
  This source edit authority is unchanged by generated callback execution views;
  those views and their export dependencies are derived, not new host declarations.
  Named source callback types replaced in the execution header remain navigable
  through explicit source-type comments. Their type tokens retain the original
  host datatype IDs without assigning those IDs or editable variable references
  to execution carriers.
  Host C documents include required callable declarations and, where a validated
  generated adapter is needed, the target-owned definition. These support
  declarations use the active namespace spelling and the same queued layout as
  the function; line width is a soft margin at indivisible identifiers, not
  permission to emit an entire support definition as one token.
  Successful compilation of the rendered body does not waive a callable-transport
  refusal: the diagnostic still marks unfulfilled execution/export obligations.
  Host consumers check this separately from actual C behavior.
- **`TypeFactoryGhidra`**: the wire `<coretypes>` decode replaces the default core
  types at registerProgram (so kuna's type ids match the host's), and
  `TypeFactoryImpl::find_by_id_or_remote` fetches unknown types with getDataType
  through the `RemoteTypeFetch` trait (`substrate/dtype.rs` `decode_type`/
  `decode_type_no_ref`/`decode_core_types`); `clear_noncore` evicts on flush.
- **`CommentDatabaseGhidra`**: `RemoteScope::fill_comments` fills the comment
  database once per flush cycle from getComments, filtered by the printer's comment
  settings (empty filter ⇒ no query).
- **External references** resolve through the upstream two-step
  (`resolveExternalRefFunction`): an `<externrefsymbol>` answer keeps its resolve
  address and fires getExternalRef at the POINTER address; the returned function
  materializes at its own entry (name/prototype/noreturn), and the pointer symbol
  itself types as pointer-to-code.
- **Tracked registers**: the pspec `<tracked_set>` decodes as the static default,
  and `ContextGhidra` is wired for real — decompileAt issues getTrackedRegisters
  at the entry (cached until flushNative) and merges the host's values OVER the
  pspec defaults, so per-address host context (MIPS `gp`, PPC TOC, a user 'Set
  Register Value') reaches `ActionConstbase`.
- **setOptions** follows the upstream reset-then-apply contract: Java
  delta-encodes its option list, so every `setOptions` first restores the
  registerProgram baseline (`Architecture::reset_wire_defaults` + the DIV-77
  ghidra-mode preset layer) and then applies the deltas — a previously-sent
  non-default option reverts when the user sets it back to default.
  This also discards derived action trees and custom groups and selects
  `decompile`; subsequent `setAction` requests select the executable root,
  not just the response envelope. Java replays its cached style after options
  on process initialization, not after every options packet. Program facts
  and immutable host prototypes are not option state and are retained.
- **Action selection and toggles** share `ActionDatabase` with CLI/console.
  Group edits invalidate affected derived roots; temporary jumptable/named
  drives restore the prior root on success, error, or unwind. The seeded host
  drive executes the selected root; the console's full-decompile boundary
  explicitly selects `decompile`.
  With bitfield simplification disabled, retained load/shift/mask operations
  can render an invalid aggregate-to-integer C cast.
- **The `Kuna v…` banner**: ghidra-mode prints a one-line plate comment
  (`/* Kuna v<MAJOR.MINOR> */`, the release `KUNA_VERSION` bake) at the top of
  every decompiled function so it is visible in the GUI that kuna is the active
  core.  Cache-only (never written back to the host); standalone output has no
  banner.
- **flushNative** clears everything in the upstream order
  (`Architecture::flush_remote_caches`): the lazy symbol cache + property rollback
  + the per-address tracked-register cache, the non-core types, the comment
  database, the decoded strings.

### Caller-owned callsite overrides

Function answers retain `<override><protooverride>` signatures by callpoint,
inside that caller's facts. They are materialized once as complete prototypes
and installed before flow; neither a global callee prototype nor a shared
function-pointer datatype is rewritten. Clearing/restarting analysis preserves
the caller's live override store, while a host edit followed by `flushNative`
loads a fresh seed.

The internal-list `first` value controls ABI assignment, not open-ended arity.
A closed three-argument `printf`/`scanf` override remains three arguments even
when `first=1`. The completed physical boundary is retained separately so a
CALLIND's C callable view can use the fixed prefix plus ellipsis without
reopening argument recovery. Variadic argument casts preserve the supplied
types and floating literal bits.

Supplied signatures remain visible in callable conversions, even in the
legacy `code *` vocabulary. Only genuinely inferred, uncommitted interfaces
may use generic callable spelling. The shared rendering policy is documented in
[the emission specification](spec/09-emission.md).

### Shared datatype graph and callable declarations

CLI declarations and host `TYPE_CODE` decoding use the same production datatype
graph. `substrate/dtype_graph.rs` owns generation-local `TypeId` edges;
`TypeRoot` retains the generation for scopes, varnodes and frontend results.
Pointers, arrays, aliases, fields, bitfields, partial/relative types and logical
callable signatures contain IDs, not owning links back into the generation.
Core roots retain only the target's core store. Retaining a non-core root retains
its whole generation; dropping the last owner reclaims recursive cycles.

`root.read()` borrows a `ReadView`; field and signature references cannot escape
that guard. Readers do not clone datatype bodies. Classifiers release guards
before interning effective pointers or other ABI-generated types.
`dtype_factory.rs` reads alias/terminal headers and reserves their identities
before descending into recursive bodies; `dtype_ops.rs` implements guarded
traversal and comparison. The raw host token is immutable and separate from both
the graph ID and the fixed/sized instance key. Callback-derived variable-length
metadata and later alias completion therefore cannot alter the ID echoed to
Java. Graph IDs are never serialized as host datatype or field identities.

Publication stages only the reverse-dependency closure affected by a definition.
Layout and derived pointer/union/bitfield metadata are distinct from immutable
shape keys. A provisional nominal body may remain `Pending` and be corrected
explicitly; finalized definitions cannot be replaced. An array's element/count
shape can be interned before element layout completes, allowing pointer-broken
recursive arrays. Failed dependencies produce errors, not indefinite waits.
An unresolved callable slot may wait on a live unbound alias without suppressing
validation of the other slots. Later completion revalidates affected callables;
logical completion never substitutes for ready by-value ABI layout.
Public lookup hides failed declarations while an explicit retry can reuse their
reservation. Inferred refinement creates a new revision; retired revisions no
longer accept corrections or dependency-driven updates. Variant metadata is
owned by its type generation, including payload IDs.

`LogicalCallable` retains declared result/input IDs, variadic and closed-arity
facts, boundary and semantic flags. Its `ModelBinding` captures the actual
architecture context and model at declaration time. Later default-model changes
affect new declarations only. CLI nested callback conventions and ellipses are
retained; explicit CLI `(void)` remains distinct from an intentionally open
empty host FunctionDefinition.

`fspec::materialize_callable` uses the real graph in the existing ABI classifiers.
Required by-value layouts must be ready; pointer layout does not wait for a
pointee's body. Successful ordinary declarations are cached as immutable
`AbiView`s outside the generation, with exact effective types, ordered storage
pieces and source roles. A cache hit does not reassign the prototype. Supplied
lists and committed entry/site facts bypass this cache. Flush validates core
completion, releases cached views and freezes the old non-core generation;
retained results remain readable.

`ActionDefaultParams` and `ActionDeindirect` consume these declarations through
the shared engine. Exact function-entry facts take precedence over a structural
Code declaration even through an indirect function-symbol slot. Existing
site-pinned facts win independently of the first parameter's lock. `force_set`
commits compatible operands/results, or persists the complete site fact before
requesting restart. Those analysis-local pins survive `Funcdata::clear`, not a
fresh frontend analysis. A required ABI still waiting at setup produces an
action error before `FuncLink`, rather than a fabricated default prototype.
The original error crosses ordinary and jump-table action pipelines unchanged.

When a late-resolved custom parameter occupies only part of an existing
argument trial, transfer preserves its endian-correct physical slice through
commit. It does not truncate every reused SSA value to its low bytes. The
direct and indirect forms of the same custom-register call therefore select
the same argument bits, including upper-register storage supplied by Java.

C rendering retains the logical declaration instead of inventing a signature
from physical slots. It omits hidden-result operands, dereferences indirect
by-value arguments and orders declared arguments by their source roles.
A hidden aggregate result captures its destination once, assigns the returned
aggregate through that pointer, and yields the physical pointer only where an
IR consumer requires it. This works inside nested expressions without
duplicating destination side effects. Existing C/Rust spellers share graph
access; unsupported Rust callable forms remain opaque, without invented ABI or
borrowing claims.

### Aggregate override contract

The supplied datatype list is a declaration to lower, not a request to recover
an earlier signature. Explicit pointer parameters stay explicit. No Java fork,
signature-basis metadata, or migration by parameter names/counts is needed.

Two source contracts differ at the host boundary. `HighFunctionDBUtil.getFirstVarArg`
returns the referenced variadic callee's `Function.getParameterCount()`, which
includes automatic parameters. `FunctionPrototype.encodePrototype` sends that
index beside the override's types with blank storage. Native model rules,
however, classify variadic arguments by their index in the supplied declaration.
Kuna marks this known host-override boundary as effective-coordinate; ordinary
CLI/declaration boundaries retain their declared-coordinate meaning.

Shared ABI assignment lowers the result first, translates the boundary using
the generated hidden-result position, then assigns inputs once. This accounts
for this-before-return markup without subtracting an explicit `this` argument
or an indirect-by-value parameter. For a variadic target with one fixed `int`:

| Supplied override | Wire `first` / input count | Declared fixed prefix | Completed inputs / physical boundary |
|---|---|---|---|
| `Big24(tag, value, number)` | 2 / 3 | 1 | 4 / 2 |
| `Big24 *(retptr, tag, value, number)` | 2 / 4 | 2 | 4 / 2 |

AppleSilicon has a second important case: the aggregate result uses hidden
`x8` storage and a **void physical output**, with no result-register address.
That is successful lowering, not an unassigned result. Its result lock and
hidden-input lock must survive; losing slot zero's lock previously caused
the entire override argument list to be discarded.

Fully locked, known declarations retain their semantic types and generated
input roles separately from committed site storage, names, effects and locks.
A closed expanded list remains closed for analysis, while its callable C view
uses the variadic fixed prefix. Emission omits the hidden result argument,
assigns the returned aggregate into its destination, and preserves any used
physical result pointer. Internal replay preserves existing explicit
`hiddenretparm`/`indirectstorage` role attributes, including result
`indirectstorage`; coherent, fully locked role metadata can restore the semantic
view without reassigning committed storage. Untagged or incomplete facts are
not treated as evidence of a missing declaration.

This does not recover intent that the producer discarded. On AArch64, a
literal `void(Big24 *, int)` declaration assigns `x0/w1`, not hidden `x8/w0`.
Likewise, `FunctionDefinitionDataType(fn, false)` can retain the formal
aggregate return while including an automatic pointer input; that mixed list
is indistinguishable from an intentional additional pointer parameter.
Java's formal-list wrapper also injects `this`, whereas native assignment marks
an existing input. None of these cases authorizes deleting or inventing inputs.
An independently pinned variadic boundary or preserved custom storage would
require an explicit producer contract; they are not prerequisites for this fix.
The existing boundary remains derived from the current callee/reference.

## 6. Response contracts that make the GUI work

Printing correct C is not enough. The `decompileAt` response is a packed `<doc>`
(ELEM_DOC=229) whose Java consumption (`DecompileResults.java:215-264`) imposes:

- **Dual `<function>` elements, order load-bearing**: the *first* decodes as the
  `HighFunction` (prototype, `<localdb>` symbols, `<ast>` varnodes+ops, `<highlist>`,
  `<jumptablelist>`), the *second* is the Clang token markup — an explicitly-commented
  "ugly kludge" around duplicate tag names. The GUI renders only if **both** decode
  (`DecompileData.java:56`); headless consumers survive on the first alone.
- **Name + entry echo**: `HighFunction.decode` throws on a function-name or
  entry-address mismatch with the Java-side `Function`
  (`Framework/SoftwareModeling/.../pcode/HighFunction.java:245-293`).
- **ast ↔ markup refid consistency**: markup tokens carry `ATTRIB_VARREF`/`ATTRIB_OPREF`
  that Java resolves *against the first `<function>`'s decoded `<ast>`*
  (`ClangVariableToken.java:147-163`, `PcodeSyntaxTree.java:309,365`). Click-to-address,
  hover, highlight, and rename-target resolution all ride on these ids — kuna's
  `EmitMarkup` `MarkupRef` fields (op time / varnode create-index) must match what
  `Funcdata::encode` emits into the `<ast>`.
- **DB symbol-id echo**: `<mapsym>` symbols must carry the *real Ghidra database symbol
  ids* they were delivered with; ids in the internal `0x4000000000000000` range are
  never round-tripped (`HighSymbol.java:39,386-387`). Rename/retype is a DB write keyed
  by that id followed by an event-driven re-decompile
  (`RenameVariableTask.java:51-57`, `DecompilerProgramListener.java:60,82`) — a wrong id
  silently breaks rename.
- **`<jumptablelist>`** feeds the switch analyzer (`DecompilerSwitchAnalysisCmd.java:100`,
  configured with C-code *off* and jumpload *on* — the list must be emitted even when
  the markup isn't).
- **`<parammeasures>`** (action `paramid` + the parammeasures toggle) feeds the
  Decompiler Parameter ID and calling-convention analyzers
  (`DecompilerParameterIdCmd.java:325-345`).

### Native callable-support publication

Alongside the current function's analysis and markup, Kuna emits a
`callable_support` sibling. Protocol **2** uses element IDs 4030–4039 and attribute
IDs 4030–4048; the bootstrap JAR and isolated installer bind this revision as
`2-e4030-4039-a4030-4048`. The override-origin attribute 4002 is unchanged. An
unsupported support version fails decoding; there is no protocol-1 compatibility
fallback. A stock native process genuinely omits the sibling and retains its
ordinary legacy path.

`DecompileResults` and `DecompiledFunction` expose an immutable
`Optional<CallableSupport>`. `complete` and `refused` are explicit native statuses,
not inferred from whether the fragment compiles. A complete result has exactly
one current receipt bound to the requested native space index and **byte** entry
offset. Every included body, including the current one, has its actual native
plain rendering and canonical declaration. The current linked markup remains
separate: `getC()` and `getSignature()` neither append adapters nor promise a
self-contained translation unit. A callable refusal can therefore preserve
useful analysis and source-editing metadata without certifying executable C.

A `CallableSupport.Publication` joins the exact body and artifact observations.
It requires matching declarations and actual owning bodies, rejects conflicting
receipts and missing providers, and checks the full required dependency graph.
A strongly connected component with an internal deferred assumption is refused;
a complete cycle without a deferred assumption is not. Protocol-2 `bodyproof`
artifacts carry `kuna_provider` (4048), naming their concrete wrapper or
existing-target provider. Their canonical single-role key extends that exact
family with `_internal_<space>_<byte>_<size>`. The provider must belong to the
same body and have the same declaration; proof chains are forbidden. Required
proof edges must remain deferred. These records emit no extra C declaration or
definition, and retaining a qualified proof also retains its concrete provider.
The Java checks enforce these protocol joins, not the native instruction proof
that authorizes the qualified receipt.

Native type ownership is a complete source dependency closure, not a list of
names to suppress. Receipts retain the Program identity, original revision,
source kind and ID, and the actual encoded instance size. Transient identities
are request-scoped and cannot suppress persisted Program roots. Builtins require
an exact producer witness; ordinary pointer/array shapes and bare void nodes do
not acquire invented source IDs. Inline shapes are accepted only through their
actual decode provenance, with independent child receipts still checked and
ancestor authority invalidated by dependency mutation. Callable inputs/results
and relative-pointer parents are part of that graph. This preserves host source
identity even when the execution view uses a different ABI carrier.

The ordinary `CppExporter` spools all chunks into one publication, authenticates
source ownership, then emits the native prelude and type closure before the
remaining Program datatypes. Unrelated host definitions remain available; a
same-named or structurally equivalent datatype is not an ownership substitute.
The native global inventory includes named and unnamed referenced globals.
Declarations for genuine external native functions remain separate from the
option controlling referenced object globals. Analysis failure, cancellation,
malformed support, unresolved obligations, or stale source ownership prevents
publication of the staged C/header pair. Stock fragments cannot discharge native
provider obligations. The final two file moves are not a filesystem-wide atomic
transaction.

Real integrated consumer scenarios exercise direct result publication and the
ordinary exporter by compiling and executing their unchanged native C/header
output, while preserving source signatures/storage and rejecting retained
support after a nested source-type edit. Synthetic packed-codec scenarios test
malformed records and dependency joins separately; they do not establish native
body or internal-role preservation.

## 7. The extension seam (decided)

Primary mechanism — **reflection swap of `DecompileProcessFactory.exepath` from a
plugin**. The factory caches the resolved path in a private static with an early-return
(`DecompileProcessFactory.java:28,52-55`); the native process spawns lazily on the first
decompile (`DecompInterface.java:267`), so any plugin constructor in the tool runs
inside the pre-spawn window. Ghidra's flat classpath (all classes in the unnamed module,
`GhidraClassLoader.java:34`) means `setAccessible(true)` works with no `--add-opens`.
The extension (`integrations/ghidra/KunaDecompiler/`) resolves the binary in two steps:
first the `-Dkuna.decompiler.exe=<path>` dev override (a JVM system property, for
pointing at a fresh `cargo build` without reinstalling the extension), then — the normal
path — the kuna binary shipped in the extension's **own** module `os/` dir under the
**distinct name `kuna_ghidra`**, resolved with the two-arg
`Application.getOSFile(moduleName, filename)` (`Application.java:1000-1003`). Naming it
`decompile` could never work, because the single-arg lookup searches the *calling*
class's module first and `DecompileProcessFactory` lives in the Decompiler module,
which ships its own (`Application.java:1013-1026`).

For native selection without the plugin, **build/os file-drop** remains available:
a binary at `<install>/Ghidra/Features/Decompiler/build/os/<platform>/decompile`
shadows the stock `os/` copy because `getModuleOSFile` checks `build/os/` first.
Native selection does not itself supply additional Java provenance. The integrated
installer separately places the version-bound producer JAR on **Ghidra/patch**,
which precedes module JARs in release mode (`GhidraLauncher.java:182-183`). Both
ordinary Java launchers and PyGhidra use that bootstrap path. Development-mode
Ghidra builds must incorporate both maintained source patches in SoftwareModeling
and Decompiler instead.

## 8. Version policy (decided)

The release workflow pins the Ghidra distribution used to build the integration;
its asset filename identifies that version. Local builds use `GHIDRA_INSTALL_DIR`
and bind the bootstrap producer/consumer JAR to that distribution's application
properties, both module JARs and source-archive hashes, and the callable-support
protocol revision. Historical source
citations in this document are not a declaration of the installed runtime version.
There is no protocol handshake — the interface version (major=6/minor=1,
`cpp/architecture.cc:35-36`) is exposed only through `getSignatureSettings` and only
BSim reads it. The real skew risk is **option drift**, already live between kuna's
`GHIDRA_REV` (`cef869af`) and the 12.2-DEV head (`f9e13846`): upstream added a
`baddatacount` option (ELEM_BADDATACOUNT=290, moving ELEM_UNKNOWN to 291,
`ElementId.java:293,464`), and an older core receiving that unknown `<optionslist>`
element throws `ParseError` → `setOptions` answers `f` → Java fails the whole
program-open with "Did not accept decompiler options" (`DecompInterface.java:301-303`).
kuna therefore **deliberately diverges from upstream: unknown option elements are
skipped with a warning instead of failing the command** — one stale option must not
brick the decompiler view. This is output-invariant for known options; it shipped
with Phase 3 (`OptionDatabase::decode_lenient` behind the real `setOptions`) and is
recorded as **DIV-76** in `docs/history.md`.

Only unknown option elements receive that compatibility treatment, including
their entire nested subtree. Malformed known options, unsupported languages,
unknown roots/models, and rejected values return `f` with a diagnostic. Options
apply in wire order: a later failure does not roll back earlier entries.
A valid replacement snapshot recovers the session. `protoeval=default`
selects the compiler specification's default model.

A second, smaller **deliberate divergence** hardens the process against a malformed
archid. Upstream reads the id with `sin >> dec >> id` (`ghidra_process.cc:89-96`); on a
non-numeric or overflowing payload C++11 leaves the stream in a failed state, and the
next `readToAnyBurst` sees the failbit and `exit(1)`s the whole process
(`ghidra_arch.cc:95-96`) — one bad command kills the session. kuna's `parse_arch_id`
instead returns `-1`, which the caller turns into the ordinary "No architecture
registered with decompiler" `JavaError`: the client sees a clean exception on that one
command and the process stays alive for the next.

## 9. What kuna already has vs. the seam inventory

Already in the tree (verified):

| asset | where | state |
|---|---|---|
| Packed marshaling, bit-exact | `kuna-base/src/marshal.rs` (`PackedDecode` :1424, `PackedEncode` :2008) | done — the payload codec is the ported one |
| `KunaError::Java` | `kuna-base/src/error.rs:145-153` | done — the C++ `JavaError` carrier |
| Token-markup emitter | `kuna-decomp/src/s9_emit/prettyprint.rs:719` (`EmitMarkup`, packed clang doc) | ported, **unreachable** — PrintC hardwires `EmitNoMarkup` (`printc.rs:1015`) |
| Signature engine | `kuna-decomp/src/infra/signature.rs` + `analyzesigs.rs` | ported; the four signature commands are wire-glue, not engine work |
| Signature element ids | `signature.rs:73-87` — 258, 259, 260, 263, 265, 266, 267, 269, upstream-numbered | done; the gaps 261/262/264/268 are ours to add |
| tspec-driven space manager, no `.sla` | `kuna-base/src/space.rs:2545-2566`; `kuna-ghidra/src/translate.rs` (`GhidraTranslate::decode`) | **done in kuna-ghidra** — the tspec `<sleigh>` parse builds a real `AddrSpaceManager`; Phase 2 wires it into an `Architecture` |
| `LoadImage` trait | `kuna-sleigh/src/loadimage.rs:101`, consumed as `Box<dyn>` everywhere | ready |
| `ContextDatabase` trait | `kuna-sleigh/src/globalcontext.rs:340` | ready |
| `Translate` trait + trait-typed lift | `kuna-sleigh/src/translate.rs:386`; `flow.rs:1321` | ready at the consumer; owner is concrete |

Protocol element ids to add (upstream numbers, wire compat — kuna's own 4000+ range is
for kuna-invented ids only, and none of these are taken): **229** (`doc`), **239–257**
(the query commands, §3 — note 241=`getcallfixup`, 242=`getcallmech`,
243=`getcallotherfixup`, verified against `ghidra_arch.cc:30-48` and
`ElementId.java:377-385`), **261/262/264/268** (`major`/`minor`/`settings`/`sigsettings`).

The engine-seam inventory, with honest difficulty:

| seam | kuna today | work | phase |
|---|---|---|---|
| `LoadImage` | trait ready | **trivial** — `GhidraLoadImage::load_fill` = `getBytes` | 2 |
| `ContextDatabase` | trait ready | **trivial** — `ContextGhidra` implements `getTrackedSet` only (upstream throws on the rest, `ghidra_context.hh:36-47`) | 2 |
| `Translate` | trait exists; `Architecture.translate: Sleigh` concrete (`architecture.rs:836`) | **enum seam** `{Sleigh, GhidraTranslate}` + the Sleigh-only call surface audit | 2 |
| `Funcdata::encode` | **DONE (Phase 4)** — the FULL `<function>` in upstream child order: `<addr>` + `<localdb>` + `<ast>` + `<highlist>` + `<jumptablelist>` + `<prototype>` (`substrate/funcdata_encode.rs`), over the `Datatype::encodeRef` / `FuncProto::encode` / `Symbol`/`SymbolEntry`/scope encode ports and the encode-time symbol-link pass | `<override>`/child-`<scope>` statics deferred (Java skips both) | 4 ✔ |
| PrintC → host markup | `doc_function_markup` uses the queued pretty-printer with persistent width/indent settings and token references; plain CLI/provenance output retains its unwrapped sink | C and existing Rust grammar work through packed markup; no Java renderer | ✔ |
| Scope / symbol table | **DONE (Phase 3)** — `RemoteScope` (`infra/remote_provider.rs`): query-through + `<hole>` negatives + property paints + namespace paths, at the GlobalQuery/flow seams; **Phase 4** echoes the delivered DB symbol ids back (`GlobalEntry::symbol_id` → `<high symref>`) | — | 3 ✔ / 4 ✔ |
| `TypeFactory` | Wire core/nominal types and recursive callable declarations use the shared generation graph (`substrate/dtype_factory.rs`, `substrate/dtype_graph.rs`); ordinary ABI views are materialized after required layouts complete | Aggregate overrides follow the explicit source/committed contract above; untagged physical pointers are not guessed into source roles | 3 ✔ / 4 ✔ |
| `CommentDatabase` | **DONE (Phase 3)** — `RemoteScope::fill_comments` (getComments, printer-filtered, fill-once-per-flush) into the `Architecture.commentdb` sink | the printer renders PRE/warning + header comments; EOL/POST placement is a printer gap, not a wire gap | 3 ✔ |
| `ParamIDAnalysis` | **DONE (Phase 4)** — `<parammeasures>` encode + the paramid-action doc shape (`infra/paramid.rs`; the justproto constructor reads the real recovered `FuncProto`) | — | 4 ✔ |
| `StringManager` | concrete, no trait (`stringmanage.rs:83`); cleared by flushNative | one-method extraction for Java-side charset-faithful decode | deferred |
| Inject library | **DONE** — payloads register from the wire-fed cspec, but nothing compiles them without a local `.sla`, so each injection fetches already-lifted p-code for that call site via getPcodeInject (`EngineTranslate::fetch_inject_pcode`, `kuna-ghidra/src/translate.rs`); never cached, since the answer is bound to the site | `CALLMECHANISM`/`EXECUTABLEPCODE` payloads are unreachable from the live engine and stay unwired. The call-fixup arm is wired but also unreachable: `remote_provider.rs` decodes every remote function with `func_inject_id: -1` and the remote `<prototype>` has no `<inject>` arm, so a Ghidra-side `setCallFixup` never arrives | ✔ |
| `ConstantPool` | trait ready (`infra/cpool.rs:470`) but **unwired** into `Architecture` | wiring + `CPOOLREF` path; JVM/Dalvik only | deferred |
| ArchSeam snapshot | **DONE (Phase 3)** — global reads and canonical callee prototypes use live seams when a `RemoteScope` is installed (`ArchContext::effective_global_query`/`query_callee_proto`; tracked sets decode from the wire pspec `<tracked_set>`) | — | 3 ✔ |

## 10. Graceful degradation

What breaks when a partial core omits pieces — all failure modes are clean:

| omitted | Java-side behavior | blast radius |
|---|---|---|
| signature commands | answered "Bad command" (the `6, 16 "Bad command: <name>" 17, 7` pattern, `ghidra_process.cc:476-484`); Java shows "not built with signature module" (`DecompInterface.java:341-347`) | **BSim only** — GUI unaffected |
| `structureGraph` | same "Bad command" path | FunctionGraph **nested-layout** view only |
| absent `decompileAt` document after a low-level failure | `decompileCompleted()` false; no HighFunction or C; the native diagnostic remains the error message | that one function; later requests can use the same process |
| second `<function>` (markup) | HighFunction decodes; GUI panel refuses to render (`DecompileData.java:56`) | GUI blank for that function; analyzers/scripts on HighFunction still work |
| `<parammeasures>` | param-ID / convention analyzers get nothing | those analyzers no-op |
| `<jumptablelist>` | switch analyzer finds no tables | unrecovered switches in the listing |

**Load-time analysis facts are the other half of this.** A wire session never loads
the image on kuna's side — the program database is Ghidra's — so every kuna analysis
pass that reads the file itself contributes nothing to the GUI path. The CLI's
`formatstring static` resolver and Ghidra's `FormatStringAnalyzer` are separate
producers: host analyzer-created callsite overrides now cross the wire into the
shared callsite contract. The live override smoke exercises actual printf/scanf
analyzer production and unchanged emitted-C behavior. The ghidra-sim oracle is not
that analyzer; its CLI comparison disables `formatstring` to reduce producer
differences. Its text-diff metrics are diagnostic, not correctness gates.

## 11. Testing strategy

- **In-crate mock-Java e2e (Phase 1, shipped).** A `MockJava` test double owns the
  other end of the pipe: sends command bursts, answers queries from canned tables,
  asserts the byte-exact response framing (including the response-open-before-params
  ordering, the always-present 16/17 frame, and the self-alignment/exception paths) —
  `kuna-ghidra/tests/protocol_e2e.rs` (canned streams) and `tests/decompile_at_e2e.rs`
  (the interactive loopback, one canned RETURN function). This is the same
  differential discipline as the port — the upstream implementation
  (`DecompileProcess.java`, `ghidra_arch.cc`) is the oracle.
- **ghidra-sim: the real-program differential harness (shipped with Phase 2).**
  `kuna-ghidra/tests/ghidra_sim_e2e.rs` + the shared machinery in
  `tests/ghidra_sim/` drive the FULL wire lifecycle in-process (registerProgram →
  setAction → decompileAt×N → flushNative → deregister) against vendored ELFs
  (`tests/bug-repro/faillog` fast; `sort`/`grep` breadth), with the mock-Java end
  answered from **kuna's own analysis** (`ghidra_sim/oracle.rs`:
  `bootstrap_from_object` for bytes/labels, the real Sleigh re-encoded as wire
  `<inst>` documents for getPcode, a tspec *generated* from the Sleigh's space
  manager so packed space indices agree by construction; mapped-symbol answers
  come from the oracle's committed program facts). It asserts the §6 response contracts (dual
  `<function>` decode, name/entry echo, markup opref/varref ⊆ ast, the 19-query
  legality and query-legal-command placement), flattens the Clang markup to C with
  Java's `getC()` token cleaning applied (`IllegalCharCppTransformer` — the reason
  over-wide type tokens read back as `unsigned_long__a1`), and checks
  raw-register identifier leaks, `Unique<hex>` tokens,
  `sub_`/`dat_` placeholder rate vs what the loader knows, `getC()`-mangled token
  counts, and query traffic. Typed markup checks retain token hierarchy, layout,
  engine references, and matched delimiter topology. Unchanged-host flush checks
  compare decoded consumer facts rather than raw bytes: document-local delimiter
  IDs need not repeat across documents. Changed-host checks require fresh symbol
  names after cache invalidation. Line counts and normalized CLI/host text-diff
  ratios remain informational, not thresholds to re-pin when presentation changes.
  Run: `make test-ghidra` (release; also part of the CI `gates` job on
  every PR, which matters because the workspace suite is skipped on internal PRs).
- **Error recovery:** `kuna-ghidra/tests/decompile_at_e2e.rs` exercises an actual
  instruction-limit failure followed by successful decompilation in the same
  session, asserting exact outer framing and preserved native diagnostics. It also
  covers malformed p-code and host p-code exceptions; `inject_e2e.rs` checks failed
  injection responses and subsequent-function recovery.
  `tests/ghidra/error_recovery.py` checks the corresponding real
  Java results against stock and kuna, including repeated recovery without PID
  changes.
- **Phase 3+: DecompileDebug captures as fixtures.** Ghidra's "Debug Function
  Decompilation" action (`DecompInterface.enableDebug`, `DebugDecompilerAction.java:38-73`)
  records every callback answer into an `<xml_savefile>` — exactly the document kuna's
  datatest corpus already consumes. Captures give us *recorded Java-side query answers*
  to replay against `kuna-ghidra` without a live Ghidra (de-risking the sim's
  synthesized `<mapsym>` shapes), and `DecompileDebugXmlLoader` (Features/Base) can
  import them as Programs for the reverse direction.
- **Real-Ghidra consumer suite** (manual): `make test-ghidra-live`, with setup
  and suite selection in `tests/ghidra/README.md`. One runner
  isolates JVM-backed probes, aggregates their exit status and preserves their
  consumer artifacts. It covers host facts, lifecycle, names, address spaces,
  and unchanged emitted-C execution; integer boundary cases exercise the CLI
  independently as well. Stock is diagnostic control, not a correctness oracle.
  Supplied-binary comparison is an opt-in suite. For the full integration path: build
  the extension against the intended release and run its `KunaIntegratedInstall`
  installer to create a separate distribution. Launch that copy, enable the plugin,
  verify the p-code/source-identity producers and result/export consumers load from
  its `Ghidra/patch` JAR and the spawned PID is `kuna_ghidra`, and exercise C,
  callable-support export, click-to-address, and rename round-trips. A development
  checkout must build both source deltas as well as the extension.
- **Regression floors**: the standing gates (`make test`, `make test-stages`,
  `make rust-test`, now plus the `gates`-job ghidra-sim step) must stay green —
  `kuna-ghidra` is additive and must not perturb the standalone engine.

## 12. Phase breakdown

**Phase 1 — wire-protocol-complete, engine-stubbed (this branch).**
- [x] `kuna-ghidra` crate: burst framer, command registry + `doit()` lifecycle,
      archlist session model, the 19 typed query clients, exception channels — engine
      calls stubbed.
- [x] Protocol element ids 229, 239–257, 261, 262, 264, 268 (upstream numbers).
- [x] tspec `<sleigh>` parse → real `AddrSpaceManager` (`GhidraTranslate::decode`), so
      `decompileAt` decodes real `<addr>` parameters.
- [x] Ghidra extension (`integrations/ghidra/KunaDecompiler/`): plugin + reflection
      exepath swap, binary shipped as `os/<platform>/kuna_ghidra`.
- [x] These two documents.

**Phase 2 — engine bridge (first real C in the GUI). DONE** (PR #135, branch
`feat/ghidra-mode-phase2`). Full plan + risk assessment + sequencing: the retired
`docs/rust-port/ghidra-phase2-plan.md` (git history). Each step landed as its own commit
keeping `make test` at 675/675 PARITY OK. One design refinement vs the plan: the
translator seam is a `Box<dyn EngineTranslate>` **trait**, not an enum — an enum
variant naming `kuna-ghidra`'s `GhidraTranslate` would be a `kuna-decomp`↔`kuna-ghidra`
dependency cycle; a trait object owned in `kuna-decomp` is not.
- [x] `SharedClient` design (the re-entrant provider→query pattern) +
      `GhidraLoadImage` (`load_fill` = `getBytes`) — `kuna-ghidra/src/provider.rs`.
- [x] `EngineTranslate` trait seam on `Architecture` (`translate: Box<dyn EngineTranslate>`,
      `infra/engine_translate.rs`) — behavior-preserving; only `Sleigh` implements it today.
- [x] `GhidraTranslate` port (getPcode per instruction, register caches, user-op probe
      loop) — `kuna-ghidra/src/translate.rs`. `ContextGhidra` is a `ContextInternal`
      stub (empty tracked sets; the query-backed `getTrackedRegisters` is Phase 3).
- [x] `Architecture::from_engine_translate` construction path: `registerProgram` builds
      a live engine from the wire specs (tspec→manager, cspec/pspec via
      `set_cspec_xml`/`set_pspec_xml`, `init_post_engine`; wire `<coretypes>` decode
      deferred — uses the default `build_core_types`, Phase 3).
- [x] `Funcdata::encode` — minimal `<function>`/`<ast>` (name/addr + ast;
      `<prototype>`/`<localdb>`/`<highlist>`/`<jumptablelist>` deferred).
- [x] PrintC → `EmitMarkup` wiring (`PrintEmit` enum, `doc_function_markup`, `MarkupRef`
      population); the dual-`<function>` `decompileAt` response, driven by `decompile_func`
      (name from `getCodeLabel`, flow-discovered extent). Proven end to end
      (`kuna-ghidra/tests/decompile_at_e2e.rs`: the response decodes to a `<function>`
      + a markup `<function>` whose refs resolve against the `<ast>`).

**Phase-2 scope boundary (historical):** Phase 2's `decompileAt` ran against an
*empty* `ScopeInternal` global scope — placeholders (`sub_ADDR`/`DAT_ADDR`/default
types) everywhere, no `getMappedSymbols` traffic. Phase 3 (below) replaced that with
the lazy providers; the ghidra-sim harness pinned the Phase-2 gap numerically and its
pins now hold the Phase-3 level.

**Phase 3 — lazy providers (correct symbols/types at scale). DONE** (branch
`feat/ghidra-phase3-providers`; DIV-76/DIV-77 in `docs/history.md`).
- [x] `ScopeGhidra`-equivalent lazy symbol cache (`RemoteScope`,
      `kuna-decomp/src/infra/remote_provider.rs`): getMappedSymbols query-through at
      the GlobalQuery + flow seams, the `<mapsym>`/`<hole>`/symbol-family decoder,
      `<hole>` negative caching, readonly/volatile property paints over the
      `lockDefaultProperties` snapshot, namespace paths via getNamespacePath, and
      wire symbol-id capture (`RemoteSymbolRecord::symbol_id`, the Phase-4 echo seed).
      decompileAt resolves the current function's identity and canonical prototype
      through it, getCodeLabel demoted to fallback.
- [x] `TypeFactory` wire decode + lazy `findById`
      (`decode_core_types`/`decode_type`/`find_by_id_or_remote` + `RemoteTypeFetch`,
      `clear_noncore`); comments rewiring (`fill_comments`, printer-filtered);
      tracked registers from the wire pspec `<tracked_set>` (the `DF = 0` seed).
      Injects via the wire-fed cspec snippets shipped with Phase 2.
- [x] ArchSeam snapshot rework (the frozen tables read through the live provider
      when installed); `flushNative` clearing end-to-end in the upstream order
      (`Architecture::flush_remote_caches`), proven by the ghidra-sim
      label-override cache-clearing test.
- [x] ghidra-mode defaults: the `aggressive` engine-tier preset at registerProgram +
      `FUN_`/`DAT_`/`LAB_` fallback naming (DIV-77); `setOptions` decodes and applies
      for real with per-element skip-unknown (DIV-76).

**Phase 4 — the full response encode (branch `feat/ghidra-phase4-encode`).**
- [x] `Datatype::encodeRef` port (`substrate/dtype.rs` `encode_ref`/`encode`/
      `encode_basic`/`encode_typedef` + `TypeField`/`TypeBitField` encode) —
      the cross-cutting type marshal-out every other element needed.
- [x] `<prototype>` (`FuncProto::encode`, `p4_calls/fspec.rs`): model +
      extrapop (+"unknown"), the boolean flags, `<returnsym>` (sized storage +
      type), effect/likely-trash model-diffs.  Input params travel as localdb
      cat-0 symbols (the upstream symbol-backed store shape).
- [x] `<localdb>` (`ScopeLocal::encode`, `varmap.rs` →
      `Database::encode_scope`/`Symbol::encode`/`SymbolEntry::encode`,
      `p0_knowledge/database.rs`): nonzero ids everywhere, ≥1 entry per
      mapsym, positional `<parent>`+`<rangelist>`, params cat=0+index+exact
      storage.
- [x] `<highlist>` (`Funcdata::encode_high`, `substrate/funcdata_encode.rs`)
      + the encode-time symbol-link pass (`kuna_link_high_symbols` — the
      C++ `ActionNameVars::linkSymbols` stand-in) attaching/creating localmap
      symbols for named highs so `<high symref>` resolves in the just-encoded
      `<localdb>`; global `<high>`s echo the REAL host DB id
      (`GlobalEntry::symbol_id` from the getMappedSymbols record) and omit
      `symref` rather than fabricate one.
- [x] `<jumptablelist>` (the ported `JumpTable::encode` wired into
      `Funcdata::encode`, emitted independently of savetree) + the jumpload
      toggle plumbed to `FlowInfo::record_jumploads` per decompile — the
      switch-analyzer contract (noc+notree+jumpload), loadtables included.
- [x] `<parammeasures>` (`ParamIDAnalysis::encode`, `infra/paramid.rs`,
      `<rank>` always on) + the `paramid`-action doc shape (parammeasures is
      the ONLY doc child) — the param-ID / convention analyzers.
- [x] Markup type-token fidelity: `EmitMarkup::tag_type` splits a rendered
      declarator into base-word `<type>` tokens + `<syntax>` separators, so
      Java's `getC()` (`IllegalCharCppTransformer`) no longer mangles
      `unsigned long *` to `unsigned_long__` (ghidra-sim mangled pins → 0).
      Composite declarators carry the source IDs of their nominal leaves,
      including pointees, named typedefs and nested callback slots. Original
      non-core nominal C names remain atomic even when they contain spaces or
      punctuation, so Java sanitizes a generated relative-pointer typedef name
      as one identifier. This is distinct from splitting composed type spelling.
      Raw token capture keeps its original text/kind/positions instead of recording the
      internal packed-token split.
- [x] The rename/retype PERSISTENCE loop: the function `<localdb>` answer's
      non-parameter locals (what Java sends after
      `HighFunctionDBUtil.updateDBVariable` committed a user edit) seed the
      fresh Funcdata — typelocked locals as mapped/usepoint symbols, plain
      renames (typelock=false) as `ScopeLocal::nameRecommend` records (the
      C++ mechanism; applied by the `ActionNameVars` port) — so a GUI
      rename/retype SURVIVES the event-driven re-decompile.
- [x] Every `<vardecl symref>` in the corpus resolves against its own
      `<localdb>` — `PIN_FAILLOG_VARDECL_UNRESOLVED = [0,0,0]`, plus a
      per-target 0 on the sort/grep breadth fixtures, so declaration-line
      rename/retype is live everywhere.  The last residue was a stack aggregate
      reached only through `&sym`, whose whole HighVariable is the constant
      `PTRSUB` operand: `link_symbol_reference` now records the referenced
      Symbol's identity (C++ `Varnode::setSymbolReference`).
- [x] Harness: the ghidra-sim decode now validates every Java hard-throw trap
      (r5 §3 — nonzero symbol ids, entry pairs, positional scope children,
      localdb/ast-before-highlist order, symref/repref resolution, prototype
      completeness, `<rank>` presence) plus switch-analyzer- and
      paramid-shaped configuration tests.

**Phase-4 deferred (follow-ups, graceful degradation per §10):**
- [ ] `structureGraph` (FunctionGraph nested layout only).
- [ ] The four signature commands (engine already ported) for BSim.
- [ ] Broader overlay and live-debugger lifecycle coverage; native wire fixtures
      do not test Java event delivery or target breakpoint installation.
- [ ] `getStringData` charset fidelity (Java-side decode instead of
      `GhidraLoadImage` bytes).
- [ ] `<override>` / child-`<scope>` statics (Java skips both); the C++
      `collectNameRecs` harvest (standalone symbols → recommendations).
- [ ] `kuna_apply_dynamic_recommendations` runs BEFORE the naming walk rather
      than after linking (kuna fuses the two upstream stages into one pass), so
      it creates a dynamic Symbol where upstream renames an existing one.  The
      upstream guards are reproduced against the scope instead of the high —
      see `docs/spec/06-variables-and-merge.md` §6.4.
