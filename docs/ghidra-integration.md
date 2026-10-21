# Using kuna as Ghidra's decompiler core

How kuna replaces the native `decompile` process behind Ghidra's stock GUI — the
architecture, the wire protocol, what kuna already has, what each phase adds, and the
response contracts that make the GUI actually work. Audience: kuna developers
maintaining the full extension's native integration and enhanced Java owners.
The phase breakdown below records the integration's development history.

**Citation convention.** Ghidra sources are cited as `file:line` against the Ghidra
12.2-DEV checkout at commit `f9e13846` (2026-06-16). Java paths are under
`Ghidra/Features/Decompiler/src/main/java/ghidra/app/decompiler/` unless otherwise
noted; C++ paths under `Ghidra/Features/Decompiler/src/decompile/cpp/`. kuna's own
pinned port anchor is `GHIDRA_REV` `cef869af` (2026-06-01, `docs/history.md`); the one
protocol-relevant delta between the two revisions is called out in §8. kuna paths are
relative to `decompiler/crates/`.

---

## 1. The full Java and native extension

Ghidra's Java GUI talks to its decompiler through a **child process** named `decompile`,
spawned lazily on the first decompile request (`DecompInterface.java:267`) and driven
over stdin/stdout with a burst-framed binary protocol (`DecompileProcess.java:54-63`).
Upstream, that process is the C++ `ghidra_opt` build — the same DECCORE engine kuna
ported, linked against a `GHIDRA` glue group (`ghidra_process.cc`, `ghidra_arch.cc`,
`ghidra_translate.cc`, …) that kuna deliberately excluded from the port (LOSS-002,
see `docs/history.md`).

**kuna reimplements exactly that glue group**: a new **`kuna-ghidra`** crate producing a
binary that speaks the full decompiler-process protocol, backed by kuna's engine.
The normal Ghidra extension (`integrations/ghidra/KunaDecompiler/`, §7)
selects that binary and supplies bounded Java owner patches for result-local
types, source-edit authority and export configuration. There is one installed
product, qualified for **Ghidra 12.1.4 with Java 21**; stock decoding without
enhanced acknowledgment remains a runtime peer contract, not another package.

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

### Enhanced result admission (version 1)

The extension patches bounded existing Java owners, not a
second controller or ProgramDB. Its maintained diffs are in
`integrations/ghidra/KunaDecompiler/patches/ghidra-12.1.4/`; only new helper
classes live in `src/enhanced/java`. Existing owner bodies are extracted from the
unmodified installation's `Decompiler-src.zip` and `SoftwareModeling-src.zip`,
then patched in clean staging by the standard GNU/BSD `patch`
utility in batch/forward/fuzz-zero mode. Nonzero status and any offset, fuzz,
reversed, skipped or rejected application fail preparation. The reference checkout
under `ghidra/Ghidra` is not an installation target. The build is pinned
to the unmodified **Ghidra 12.1.4** installation source/JAR pair.
`GHIDRA_INSTALL_DIR=/abs/stock-ghidra-12.1.4 ./build.sh` builds and stages the native backend before packaging;
`gradle -PGHIDRA_INSTALL_DIR=/abs/stock-ghidra-12.1.4 buildExtension`
packages an already freshly staged compatible native backend. Its sole deployment
artifact is `dist/ghidra_12.1.4_PUBLIC_<date>_KunaDecompiler.zip`.
Install through **File → Install Extensions… → `+`** in matching Ghidra 12.1.4
and restart. There is no standalone Java deployment artifact or installation copy.

The normal extension retains the `KunaDecompiler` module name, plugin JAR in
`lib/` and native assets in `os/`. The complete freshly compiled enhanced
owner/helper closure lives in `KunaDecompiler/bin/main/`, loaded through the same
`GhidraClassLoader` before the original module JARs by the launcher's existing
module-bin lookup. No original installation JAR is rewritten. Enable the existing
**KunaDecompilerPlugin** through **File → Configure → Miscellaneous** to activate
the native core. The **Tools → Kuna Decompiler → Use Kuna Core** checkbox changes
native selection, not the lifetime of enhanced Java already loaded in the JVM.

Uninstall the previous `KunaDecompiler` using **File → Install Extensions…** and restart
before installing its replacement; restart again to load the replacement.
Uninstalling enhanced Java also requires restart. For testing, use the same stock
`GHIDRA_INSTALL_DIR` with isolated per-user settings/extension profiles, not separate
Ghidra copies. Derive the effective settings and extension locations from Ghidra's
`ApplicationLayout`; do not construct guessed user-prefix paths. A profile without
the extension preserves the ordinary untouched-Java control. See
[`tests/ghidra/README.md`](../tests/ghidra/README.md) for setup.

An enhanced manager offers `kuna_result_version="1"` on registration's `coretypes`.
Only a supporting native session sends a first-child `kuna_result` DOC prelude
with that same version, including when its definition set is empty. No prelude
means ordinary decoding, **not** assumed enhanced support. Version 1 uses element
IDs 4000 (`kuna_result`), 4003 (`kuna_type`), 4002 (`kuna_definition`), version attribute
4003, and explicit `kuna_local` handle attribute 4004. Reservations precede
definitions; result-local reference handles are distinct from host datatype IDs.
Packed element and attribute IDs have separate namespaces and a 12-bit limit.
This unreleased coherent version-1 boundary also includes exporter-private
selected-root preparation and the export-only working-result role. It does not
claim compatibility with an earlier partial version-1 implementation.
Callable inference uses that same session negotiation to derive one native
publication policy. CLI architectures default to `Full`; an enhanced session
retains normal anonymous callable High/result types, while an ordinary session
uses `PerCallOnly`. Both use the existing aggressive `calltargettype` preset;
the catalog default and named ON/OFF controls are unchanged. An ordinary C
request may spell an ABI-admitted per-call signature without retyping its High,
public input, source prototype, record field, or CAST IR. The structural cast
binds actual source/core datatype leaves only; an anonymous native Code, minted
record, or other receiver-unresolvable leaf is not published to stock Java.
A plain `void` keyword needs no invented datatype identity. This is not an
external callback declaration: unknown-width inference cannot recover a missing
nominal integer rank, and C providers must match the selected target's data
organization and actual signature.

An authored managed `FunctionDefinition` is separate from native callable
inference. In ordinary C markup, its bare name expands to its source function
declarator because the untouched Java header writer omits standalone function
definitions. Actual typedef aliases retain their names. Enhanced result
admission retains the named Code leaf for Java's declaration/naming owner; CLI
publication is unchanged. This presentation choice is invocation-local and
preserves source objects, IDs, High types and physical storage.
Visible scalar type tokens bind their scalar owners; the parameter declaration's
HighSymbol retains the complete callback pointer for source edits.

The policy is derived only from `Session.result_version` during registration
and after `reset_wire_defaults`, before normal Java option deltas. Each
`ArchContext` receives that projection at construction. Ordinary no-C,
no-casts, non-C-language, and non-decompile requests skip receipt acquisition;
the request scope restores the stored feature option on success or failure.
No additional user option, capability version, or result cache is introduced.

Only actually referenced syntax-tree, measurement, token and transitive datatype
dependencies are described, including recursive records and callable types.
Typed declarator leaves retain their individual datatype bindings. C and Rust
return, formal, cast and local type leaves use their actual rendered datatype
owners, including recursively selected pointees and array elements; temporary
leaves enter the same result-local closure. Record field tokens carry the actual
parent and byte offset; union and bitfield tokens retain
their existing component-identifier coordinates. In particular, Java's union
rename/retype recipients consume component ordinals, not a blanket byte-offset
projection.
The declaration record retains the whole array datatype and its full storage
size for JSON register-local rows; only the declarator's type leaves select the
element, with the extent emitted once on the identifier. Storage-home acquisition,
signed-read cast decisions and narrow-input rewrites propagate typed failures
through their existing printing or action owners rather than omitting rows,
casts or failed rewrites.
Exact nominal source names remain single type tokens, including automatic
relative-pointer names containing punctuation; declarator operators and scalar
keyword spellings remain separate syntax/keyword leaves.

`DecompileResults` owns a datatype view sharing the request's managed source/core
objects and retaining temporary bindings used through the complete document.
Result-local absolute pointers use ordinary Java decoding's language-dependent
length for default-sized or oversized pointers and retain explicit supported
nondefault widths, without replacing managed references or relative-pointer rules.
Held results remain readable after later requests and interface resets. Enhanced
source/edit/export authority additionally requires the captured source revision
and registered-context snapshot to remain current. Ordinary requests capture that
revision before native acquisition, so a source edit during result delivery revokes
edit authority without discarding the readable old result. Transient inferred types are
not implicitly authored by source-edit transactions. Relevant registered core-context changes rebuild the
matching manager/callback/native registration at the existing headless request,
flush and reset boundaries. Ordinary body-only flushing does not rebuild it.

The existing `CppExporter` retains typed results through its collector, choosing
identity-based output names once per invocation before flattening bodies,
signatures, globals and definitions. Source names and objects remain unchanged.
Exact used host temporary roots participate in authored-name reservations.
The native CLI collector likewise chooses source-global output names before
rendering, using the existing invocation identifier reservation and suffix owner.
Its original global-name acquisition retains the actual nonzero source Symbol
id alongside the High's name/type/offset, including width-sensitive aliases and
SPACEBASE references. Rebinding a name clears that receipt.
Bodies, typed global declarations and global High wire references use the held
identity, while source names, Symbols and types remain unchanged. Only a missing
receipt uses the existing source-declaration query path; it does not reconstruct
the lost identity, and id zero never authorizes a shared presentation name.
Workers reserve transported canonical names and aliases independently of additive
symbol replay, then rebind the same source-global decisions to their local ids.
Genuinely named callable datatypes receive function-type typedef definitions,
not invented pointer aliases; pointers retain their separate declarator layer.
When a managed or NONDB function datatype's name needs a C presentation spelling
(for example spaces, templates or a C keyword), or collides with an exported
function, datatype typedef, enum constant or another source callable, only its C
presentation acquires an invocation-local nonconflicting alias. Source datatype
categories do not create separate C
identifier namespaces. Callable names outside the reserved export vocabulary retain their spelling;
aliases reuse the symbol transformer and suffix allocator, with a fixed legal
stem when the C++-permissive transformer still produces a non-C identifier.
The spelling check retains the transformer's existing letter acceptance, including
Unicode letters; it is not ASCII normalization or a general Unicode identifier validator.
The original datatype name, identity and dependencies remain unchanged, and
declarations, globals and typed body leaves use that same alias. Genuine
function-type typedefs are not discarded to avoid the collision.
The actual output paths also reserve emitted fake-type macros, equates, the
implicit default datatype and single-entry `define_` enum projections before
callable aliases and native export identifiers are assigned. Fake-type generation
reports its existing declaration identifiers once and retains the same text for
later output; enum macro naming is shared with `DataTypeWriter`. Disabled output
paths do not contribute these generated identifiers.
Datatype-definition export also reserves declaration-capable names from Ghidra's
existing shared builtin registry, using the Program's data organization. Inferred
dependencies can require these builtins only after initial callable definitions
have been written. Reserving their vocabulary up front keeps ordinary export's
bounded chunk lifetime: an otherwise unused builtin spelling can therefore
cause a callable presentation alias. This reservation emits no additional types
and changes no source datatype.
Class symbols likewise reserve the writer's `P<ClassName>` pointer alias even
when no managed class datatype exists. Ghidra can supply that class later as an
automatic-`this` NONDB placeholder after a user deletes its managed structure.
An unused class pointer-alias spelling can therefore also cause a presentation
alias; export neither recreates the managed type nor changes source state.
Anonymous callable definitions remain structural. Local callable naming consults
the retained wire reservation, not the decoder's generated Java placeholder name.
Synthesized external-function declaration roots are not nominal datatype roots;
only their genuine return and parameter dependencies enter this naming closure.
Enhanced result views remain retained until all invocation names are known, then
the existing bounded writing chunks release their High/markup references.
Ordinary-only export retains its existing chunked acquisition/writing behavior.
Requested C/header writers open before cancellable selection and naming
preparation, preserving the ordinary exporter's non-atomic destination policy
on pre-cancellation. Individual failures retain its existing best-effort
warning-comment/null-result behavior for both native peers. Enhanced result
admission does not make whole-export replacement atomic.
Its invocation-owned `setConfigurer(DecompileConfigurer)` hook configures every
fresh pooled interface; `prepareSelectedRoots` uses the same factory and returns
the explicit prepared roots before a caller discovers providers. The default-off
`exportinline` option is explicit and retains the ordinary `decompile` action,
selection, declaration, mixed-success, cancellation and writer policies.
Before native preparation, each private interface must observe the actual version-1
DOC acknowledgment through an ordinary request; registration's offer and numeric
architecture ID alone are not proof. Stock peers therefore receive only existing
commands. A fresh registration must acknowledge and prepare again, resolving the
invocation's full addresses in its own address-space manager.

The enhanced Java exporter also collects external declarations from actual High `CALL`
targets and their source thunk associations, without selecting additional bodies.
This source-only collection also applies to ordinary native results received by
the explicitly enhanced Java exporter; it does not require enhanced result metadata.
Declarations are emitted once through the existing chunked writing boundary.
The source formal prototype, varargs and recursive type dependencies participate
before invocation presentation names are assigned. External symbol identity
deduplicates declarations. For Mach-O and ELF, the supported GCC/Clang C dialect
uses an explicit `__asm__` link label from the retained original import name, or
the unchanged `IMPORTED` label when no rename was recorded. This preserves source
C identifiers without guessing platform decoration or rewriting libc names.
Other object formats, custom parameter/return storage, non-default calling
conventions, non-printable link labels and missing import-label authority are
ineligible for this optional added binding. They retain the exporter's existing
declaration/body policy rather than gaining a new refusal. Source metadata is
never changed to make a declaration fit.

The native `decompile-project` header also retains source global declarations
from the function's live High/source-symbol roots, including the whole source
object when a body accesses only one member. Volatile read/write annotations
have no HighVariable: the existing document global plan retains their source
binding once at the userop's actual access width, before type preambles, and the
body uses that same binding. Only emitted annotation bindings contribute global
declarations and result type roots. Raw source name, type, Symbol id and address
space remain unchanged; an actual volatile whole-object access can qualify its
declaration view, but a partial access never promotes volatility to its parent.
Whole-object qualifier evidence takes precedence when the same source object
also has partial accesses, independently of occurrence order.
Qualified type views do not compete with their source base for a nominal name.
These declarations do not depend on
`globalref`: that option controls synthesized names for otherwise unnamed
addresses, not whether an existing named global needs an `extern`. Callable
typedef ordering follows the retained source return and formal types, on both
the whole-factory header and the per-function `structdefs` surface. The recompile
printer emits scalar PIECEs through eight-byte results as unsigned C casts,
masks, shifts and ORs, without reserving source identifiers for helpers. Each
operand is evaluated once and masked to its p-code width. These expressions
do not initialize an unknown physical input or certify an executable
body: original provider, value and runtime assertions remain independent.

An inferred sixteen-byte SIMD local selected for the scalar C view uses that
same `unsigned __int128` view in casts to the local. Its unbound cast spelling
uses declarator syntax, not a fabricated datatype token. This does not change
the High datatype or authorize an array cast. Explicitly typed arrays, ordinary
loaded arrays and the `partialaccess off` representation remain unchanged.

### Native normalization lifecycle

The normalization setup clears all working input parameters, including locked
ones, and unlocks the working prototype model and return type without clearing
the return storage. Each function reset restores the action's once-per-function
scheduling state, so reusing the action for a second function repeats this setup.
Normalization of independently copied working prototypes leaves the source seed's
parameters, locks and return geometry unchanged. These operations follow
`coreaction.cc:4618-4629`, `fspec.cc:4016-4021` and the inherited
`Action::reset` in `action.cc:99-105`.

### Invocation-local physical callable publication

Export preparation binds the actual selected address-space-qualified entries
before serial, append-only stream, or worker rendering. The binding retains
canonical source prototypes separately from fresh working entry and call
geometry. Raw entry-read evidence and its unwritten direct-transfer cuts seed
ordinary scalar carriers; actual working SSA input consumption refines those
ranges using the model's storage justification. Callable membership comes from
selected function-address values, actual argument/formal transfers and returned
values, not from scanning functions with compatible signatures. These are
positive known-target facts: public callback inputs remain open domains.
Refinement uses affected-caller work, not repeated whole-selection rounds:
shrinking a callee's finite carrier domain requeues only actual dependent
occurrences and their callers, including cycles.

Physical formals are not evidence that their incoming bytes were declared by
source. Variadic input proofs reacquire the retained logical source prototype
once per active-parameter action and share its original ABI geometry across
their byte walks. Synthetic carriers and unknown upper bytes gain no source
authority. Source-piece queries likewise retain an absent logical return type:
the working store's default `void` does not declare an Itanium-demangled
function to return nothing or justify discarding its recovered return body.

An unchanged source input remains the dependency of a wider entry read when
the existing `narrowext`/prototype-model extension produces the entire demanded
storage range. The ordinary entry SSA action still supplies that exact signed
or zero extension, including the compiler spec's answer under `narrowext off`;
publication does not replace it with a source-to-carrier cast. Raw probe ranges
remain unchanged. A partial word extension cannot supply unknown upper bytes,
and an absent or already widened source occurrence does not regain source
geometry. Boolean raw-byte carriers remain unsigned bytes: a modeled extension
does not establish Boolean normalization or erase noncanonical-byte consumers.

A fresh Varnode of a host session queries its local scope with an invalid use point,
as upstream's `newVarnode` does, so the host's name-locked parameter Symbols do not
reach later Varnodes of the same register; a standalone decompile queries at the
function's entry use point.

A locked source declaration with fewer formals than the body consumes does not erase
the physical reads the entry probe proved: in a host session (the ghidra-mode
registerProgram sets `ArchContext::retain_physical_call_inputs`) the call keeps those
register reads as physical call operands next to the source formals. A standalone
decompile binds the source formals alone.

Standalone preparation acquires the existing authored `FunctionSeed` once
before binding. The normal source initializer applies pending declarations,
retained source facts or recovered pieces under their existing model precedence,
then source-slot parameter mappings, before the independent physical overlay.
The binding retains the effective invocation declaration separately from the
canonical source object, and workers rebind it through the same initializer.
Body retries do not replay source slots onto reordered physical carriers.
Private jump-table partial functions explicitly acquire the physical entry
prototype and fresh local mappings; ordinary partial construction is unchanged.
Fresh calls may still have logical parameters with unassigned storage when
the prepared binding is installed. Only an exact prevalidated binding can
supply that working geometry; completed source acquisition still rejects
unassigned storage. Recovered function-pointer restrictions retain the
engine's mechanical override/restart behavior, but their existing override
records distinguish inferred exact call occurrences from authored site
overrides. An authored replacement removes that inferred permission.
The source snapshot is an entry-application result, not physical proof.
Explicit input/output diagnostic flags keep a selected root on its existing
ordinary analysis/body path, with the actual diagnostics, rather than turning
it into an absent root or a blanket export failure. Only nondiagnostic
snapshots enter strict physical acquisition; replayed prepared bindings reject
diagnostic snapshots instead of reclassifying them as valid geometry.
For private implementations with symbol-scoped directives, a bounded
pre-publication pass uses the existing parameter directive owner to capture
successful edits against exact working slots and storage. Full edited datatype
references are frozen before declarations or bodies are streamed. Workers
rebind those same successful original directive indexes through the existing
declaration parser, rather than reducing a type edit to width or signedness.
Only consumed parameter directives are skipped during later local replay, and
the final emitted implementation signature still receives the original
directive checks. Canonical source and callback identities remain separate from
these private implementation edits.

Typed PrintC emission names selected direct implementations before flattening.
An indirect helper evaluates the source-compatible callee once, compares only
known selected identities, and otherwise performs the actual ordinary source
call. Constructible source wrappers preserve canonical returned/address function
identities. A zero-formal source declaration cannot supply an ambient incoming
register: such a selected body retains a private physical implementation, no
invented zero-argument wrapper, and no executable public declaration. Escaping
that unconstructible source callable identity is an explicit error. Source
prototypes, raw facts and ordinary editable High results are not widened.
Per-function type definitions and retained result type bindings also walk the
actual export signatures: source wrappers, physical implementation/dependency
declarations and callback helper conversions. A source enum used only by its
wrapper remains a typed definition even when the private body consumes an
unsigned integer carrier; no source identity is invented for an unavailable
wrapper.
Authored direct sites retain their independent source override during export.
Publication compares completed slot-aligned physical operands against both the
canonical target and that site declaration; this does not authorize inferred
reseeding of an authored site. Exact storage-matched ordinary scalar inputs can
use the existing direct emission path even when the authored spelling omits a
live carrier. When the implementation uses fewer inputs, an invocation-private
helper accepts and evaluates every supplied expression once, then projects only
exact storage occurrences. Source declarations, public wrappers and headers
retain the canonical formals. A demanded missing canonical formal can leave only
the private implementation after a complete existing untouched-return proof,
completed zero input consumption, and disjoint genuine output storage. Absence
from a positive read set alone is not such a proof. Unsupported storage/model
and injection/hidden/custom/variadic cases retain their existing owners.
Loader function symbols may retain generic `Code` without a prototype after a
source declaration arrives. Such a shell is not a callable helper signature.
Preparation reuses only complete compatible Code with the actual source type
references; otherwise the existing datatype/model factory constructs the
canonical source-compatible pointer. The loader symbol and its datatype remain
unchanged.
Ordinary indirect C rendering may borrow an actual authored site prototype, or
the logical signature of an actual hidden-result projection, when the live
dialect presents its callee as `void *` (or as a generic code pointer spelled
`void *`). The existing Override record distinguishes authored authority from
inferred restart geometry. This conversion retains source datatype leaves
without acquiring ABI storage or mutating the analyzed target. Default call
shells do not supply callable contracts: inferred typing and physical-ABI
refusals remain owned by `calltargettype`, including its option-off controls.
Reprinting an authorized signature with a changed `ctypes` setting does not
depend on the earlier analysis setting.
The enhanced HighFunction override encoder translates an effective variadic
boundary into logical signature slots only when the primary referenced function
has one hidden result pointer and the selected signature reproduces its model,
formal result, fixed types and exact allocated storage. A logical aggregate
result therefore excludes that auto parameter from its fixed count; an explicit
result-pointer argument remains counted. Unmatched references retain the public
`HighFunctionDBUtil.getFirstVarArg` answer. Finite supplied inputs stay closed,
and neither source declaration is changed.
A finite authored logical override with an effective variadic boundary and no
supplied physical/custom storage receives default argument promotions only in
its independent working allocation: narrow integer tails use target `int`, and
the actual core C `float` (including its aliases) uses target C `double`.
Fixed short/float formals, physical entries and the original authored override
types remain unchanged. Promotion precedes storage selection, so double bits
are not first truncated to a float-sized register input.
Nested function-type declarators also present each actual Code layer's held
calling convention through the same current-registry visibility policy as
ordinary function declarations. The active printer's convention option applies
to both; disabling it retains the existing unannotated-C policy, not the original
nondefault machine ABI. Declarator helpers borrow one invocation presentation
context rather than cloning registry handles for each type.
An empty model name emits no convention token or separator. A subsequently
supplied explicit convention locks that source-model choice without changing
the source declaration's parameter placements or separately supplied extrapop.
A nonzero numeric generic-Code target with no actual arguments or result uses
one native C `void (*)()` conversion, retaining the actual Code leaf identity.
The empty parameter list is unspecified, not an invented source prototype.
This bounded literal presentation does not borrow default call specifications
or change full source callables, authored sites, hidden-result calls, special
pointer metadata, or the inference-off table/float-ABI domains.
Console source declarations and mapped-parameter edits refresh the current
source parameter scope immediately, so the next rename/retype sees the new
slot before an explicit re-decompile. Parameter name/type directives update
that same current declaration projection before fresh working ABI/type
acquisition, without mutating held/global canonical source. Analyzed High
state still follows normal re-decompilation; synthetic working-carrier
reconstruction is not a source-edit operation. Matching geometry keeps its symbol;
changed geometry or omitted slots retire their actual analyzed symbol links
before replacement. A full declaration supersedes older parameter overlays,
while a single mapped slot preserves unrelated sibling edits and locals.
Custom/JOIN/hidden/injection and authored-site handling remain at their existing
owners; ineligibility for the scalar adapter is not a new export refusal.
An authored direct call excluded from inferred prototype seeding still receives
a typed forward declaration for its actual selected private definition. This
declaration closure preserves the authored call operands/prototype and does not
certify compatibility with that definition or expose an unavailable public
source wrapper.
Ordinary `decompile-all` does not acquire this private binding: its code,
variables and provenance all describe its actual ordinary Funcdata. Project
publication can explicitly report retained source parameters alongside its
private working body; generic variable extraction never substitutes a printer-
owned source snapshot.
Ordinary direct C calls may present a locked, nonvariadic source-formal prefix
only when the independently named target declaration has that same formal
boundary. Its acquired working prototype must satisfy existing prototype
compatibility plus exact typed input/output carriers and roles. Finalized
operand storage must also prove each formal at the same justified origin,
with remaining operands retained as physical dependencies. A shorter callsite
override alone does not shorten a named target's different declaration.
Missing target source keeps all operands; source-query and working-acquisition
errors propagate through the existing printing result instead of becoming
absence or partial output. Existing bounded assignment refusals produce an
error-marked working prototype, which cannot authorize shortening.
Interior source slices
without an expression projection do not take this presentation path. All operands
and trials remain in the IR and High;
an authored `helper(void)` still prints `helper()`. Diagnostic, custom,
injected, shifted, hidden/indirect/JOIN, variadic and unlocked domains retain
their existing presentation paths. Prepared physical calls bypass this source
projection and publish every bound machine input. Source-shaped C alone is not
a certificate of executable physical equivalence.

The private enhanced export scope receives a matching working High and typed
markup, without source-edit authority. A completed working result requires its
version acknowledgment and `kuna_export` descriptor
(element 4005, declaration child 4006; private/public attributes 4007–4008),
which identifies actual typed `ClangFuncProto` groups by preorder ordinal. The public
group is distinct from the first physical implementation signature; a negative
public ordinal means there is no executable public declaration. Source-only
selected results also carry their ordinary public group. Declaration names
match raw function-name tokens exactly; the existing presentation transformer,
not an additional ASCII-identifier grammar, handles templates, operators, Unicode
and preserved suffixes. Both raw and transformed spellings
participate in invocation reservations before local datatype naming. Workers
receive the parent's frozen full-space membership, carriers and implementation/
helper names through the existing session specification, then rebind source
types and models through their own loaded owners.

Preparation does not select additional provider bodies, change the default-off
`exportinline` option, certify unknown native callback/variadic domains, or
replace ordinary mixed-success diagnostics. Recoverable acquisition failures
remain per-entry outcomes; a terminal host transport failure stops acquisition.
The immutable binding contains no retained `Funcdata` or architecture back-edge.
Its selected source/working analyses are invocation preparation, not a
per-render replay after each body-cache flush; explicit scope invalidation and
source/core-context freshness remain owned by the enhanced request lifecycle.
The request scope captures Program revision and registered-core values before
acquisition and validates them again after complete decoding. Effective encoded
options, action, output settings and fresh-interface profile equality belong to
that same scope. Held export authority captures only this basis and its options
owner, never a live interface or native process.

The canonical capability probe, preparation callbacks and all working documents
share one Java NONDB temporary-ID epoch. Working requests omit only the ordinary
automatic temporary-map reset and post-result native flush. Scope close, explicit
flush, cancellation, failed decoding and acquisition errors genuinely flush and
clear that private namespace; captured used bindings in held result views remain
readable. Ordinary requests retain their per-request clearing and flushing.
Configuration setters revoke the active invocation; mutable option values are
compared through the same option encoder, without constructing another interface.

## 2. Architecture and session lifecycle

Call-fixup prototypes retain the shared live injection library together with the
assigned payload id. Full prototype copies and flow-effect copies preserve this
pair, including when the architecture owner is released; cancellation drops both.
Nested source-prototype encoding resolves the name through that originating
library before recursively encoding types. Decoded source names remain available
when no registered payload is known, while remote name resolution uses the same
live library rather than a separate name-to-id snapshot.

Compiler-model `uponentry` and `uponreturn` payloads use that same library and
the common local-template/host-query emitter. `ActionConstbase` inserts entry
operations at the beginning of the entry block and then applies tracked constants;
`ActionDefaultParams` inserts return operations immediately after each call.
Live insertion preserves the full ordered operations, including memory stores,
and rejects call/branch payloads. Existing once-per-function action scheduling
prevents duplicate insertion during continuation; reflow rebuilds raw IR before
those actions run again. Injection errors remain fallible action failures.

Compiler prototype decoding registers each authentic entry/return `<pcode>`
as `CALLMECHANISM_TYPE` in that same library, using the model name and the
existing `@@inject_uponentry`/`@@inject_uponreturn` identity. Defaults and named
models share this decoder; aliases retain the original ids, and repeated model
decoding reuses the existing registration only when the decoded source, body,
flags and parameter metadata match exactly. Conflicting same-name mechanisms
retain the library's duplicate-registration error without changing the live
payload or template. Payload decode/registration and local
compilation failures propagate through architecture initialization; the older
ABI-only model fallback does not swallow required payload failures.
Local snippet compilation runs after
prototype registration with the selected language/compiler pairing, so PPC
return stores and the named HCS12X `__asm_xgate` entry copy have real templates.
Dynamic Dalvik entry bodies remain template-less for host generation.

`inject_sleigh::emit_payload_shared` is the common emission boundary for
call/callother fixups, model entry/return mechanisms and executable-helper
construction. It resolves borrowed local templates using the canonical space
manager, then releases the library before replaying every operation. Missing
templates use the existing Weak host resolver with the original payload name,
kind and live site context; callback errors retain their typed identity.
Site-bound bodies are not cached. The executable cache and canonical loader
ownership remain unchanged.

Java output uses the existing `OutLang`/`PrintC` language plane, not a second
printer. `ArchContext` retains the selected language for analysis, including
stack-owned Java cast strategy selection and the same effective type-operation
metadata used by the instruction table. Printer passes use their own retained
language while the architecture's printer is temporarily detached. Java object
references, primitive/object arrays, null, scope, unsigned shifts, receiver calls,
allocation and constant-pool forms follow Ghidra's `PrintJava`; record acquisition
uses the shared architecture constant pool and propagates provider errors.
Java type leaves bind the final base datatype after pointer unwrapping; array
brackets remain syntax rather than part of the datatype token.
The original six genuine JVM consumers in `tests/ghidra/cpool_consumers.py`
remain the semantic acceptance tests.

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
| `decompileAt` | packed `<addr>` of the entry | packed `<doc>` (§6); empty 14/15 if incomplete | **yes** |
| `structureGraph` | packed block graph | packed restructured block graph | **yes** |
| `setAction` | actionstring, printstring (2 string bursts) | `t`/`f` | no |
| `setOptions` | packed `<optionslist>` | `t`/`f` | no |
| `generateSignatures` | packed `<addr>` | packed `<signatures>` | **yes** |
| `debugSignatures` | packed `<addr>` | packed debug-sig doc | **yes** |
| `getSignatureSettings` | — | packed `<sigsettings>` | no |
| `setSignatureSettings` | decimal settings string | `t`/`f` | no |
| `prepareSelectedRoots` *(acknowledged version-1 exporter only)* | one packed stream of canonical `<addr/>` roots and `<string>` content reservations in any order, no envelope; empty stream means empty selection | packed empty `kuna_result` acknowledgment with the central result version | **yes** |

`prepareSelectedRoots` routes full `Address` values to the physical-publication
preparation owner; command routing does not maintain a second root inventory.
Its owner supplies deterministic selection order/deduplication and uses the
same invocation-owned raw/transformed source-name reservation set as
Java's exporter. Canonical `string` element84/content attribute1 entries reserve
names only, never implicitly select providers or functions. The entire packet is
decoded before that set reaches implementation/helper name allocation.
Decode/preparation failure answers through the existing error categories and cannot silently retain
an older invocation's prepared decisions. Success uses the existing packed
`kuna_result` encoder with no definitions; it acknowledges preparation only, not
a function body or a second capability. This lets the existing callback-enabled
packed-command transport serve the request without another Java process owner.
Working acquisition remains ordinary
`decompileAt` with the matched DOC decoder, not a second result codec or command.
The explicit private acquisition scope avoids only its automatic post-result
body flush; closing it performs a genuine flush. Explicit native flush, options
reset, source/model publication, context-policy edits, language/root changes and
analysis publication discard the installed binding. Internal body-cache refresh
and same-function reflow retain its frozen entry/call decisions; the generic body
cache invalidator is deliberately not an invocation invalidation boundary.

Choreography invariant: the response-open burst 6 is written **before** parameters are
read (`GhidraCommand::doit`, `ghidra_process.cc:125-135`), so callback queries nest
inside the open response; the result payload is followed by the 16/17 warnings frame
(always present, possibly empty — `ghidra_process.cc:108-116`), then 7, then flush.
The "queries legal" column is a **hard constraint**: Java nulls its callback
decoder/encoder for all other commands (`DecompileProcess.java:512-513,536-537,618-619,
657-658,686-687` vs `:472-473,571-572`) — a query issued during `setOptions` desyncs
the protocol.

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
The terminating empty name is still a complete string stream (`8/14/15/9`),
as stock Java writes it. A bare absent response (`8/9`) is an alignment error,
not an enumeration terminator, and must not publish a partial user-op table.

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
  Authored console/remote records remain authored even when their display mask
  includes `warning`; only comments published from a function's pending analysis
  diagnostics are removed when its body is replaced or reflowed. Address/text
  deduplication preserves authored ownership in either arrival order. This keeps
  loop-condition comments on separate lines and preserves comments that prevent
  an `else` body from collapsing into `else if`.
  `ActionPrototypeWarnings` consumes the working prototype's input/output-error
  flags through this same generated-comment channel. Original override headers,
  unknown-convention visibility/locked-storage notes and per-call assignment
  warnings retain their own header or callee-entry placement. This consumer does
  not alter source prototypes or catch unrelated acquisition/transport errors.
- All of it flushed by `flushNative` after every function
  (`ghidra_process.cc:262-273`): global scope, sub-scopes, non-core types, comments,
  string decodings, cpool.

For four-byte character literals, a recovered integer-element pointer is not the
only authority: the existing mapped, type-locked `wchar4[N]` source array can
independently establish the literal. `PrintC` requires a same-width scalar use,
an element-aligned offset including the mapped piece's symbol offset, and the
complete remaining range in that same mapping. The shared `StringManager` must
then supply a complete, nontruncated string whose terminator ends that exact
remaining array extent. Readonly acquisition and independent index bounds still
apply. An integer array, a table continuing beyond its first zero, an opaque or
misaligned source, and host refusal gain no exception; ordinary element-pointer
refusal and unrelated successful string acquisition retain their existing paths.
The source pointer constructor also preserves an aligned character-array offcut
directly as a typed constant; rebuilding a base-plus-residual expression and then
folding it must not discard that source character type. The replacement inherits
the mapped array's type lock, so later local type reconstruction cannot replace
that established pointer with the integer requirement of address arithmetic.
This authority comes from the actual locked mapping, whether authored or installed
by the existing string analysis; it does not require or fabricate a DWARF type.
Its actual mapped-element
query precedes graph mutation, and acquisition errors propagate through
`ActionConstantPtr`. Integer-array interiors keep their ordinary numeric path.
Standalone two-byte inference with `widestrings` off cannot acquire a literal from
an inferred callee pointer alone; an existing source character array or the live
host string service remains independently authoritative.

The existing simulator's string callback follows Java's charset boundary:
declared string metadata and byte offcuts take precedence over the requested
datatype, source UTF-16/UTF-32 units use target endianness, and the reply contains
UTF-8. Undeclared raw strings must first fit the requested source-byte limit,
including the terminator; declared Listing-string truncation separately counts
Java UTF-16 code units. This keeps its original PE-wide
literal consumer meaningful when native acquisition uses the host service,
instead of accepting a provider's one-byte NUL scan of UTF-16 as translated text.

The C++ virtuals these classes override were deliberately collapsed in the port (the
`Scope`/`ScopeInternal` merge, `kuna-decomp/src/p0_knowledge/database.rs`), so Phase 3
relocated the lazy model to the seams the kuna pipeline actually reads
(**shipped** — `kuna-decomp/src/infra/remote_provider.rs`):

- **`RemoteScope`** (the `ScopeGhidra` port at the GlobalQuery boundary): installed on
  `Architecture` at registerProgram and threaded into every per-function `ArchContext`
  by `build_arch_handle`; every global-scope read (`query_global_properties`,
  `name_for_global_varnode*`, `query_container_global`, `query_callee_proto`,
  `query_function`, `callee_proto_pieces`) and the flow environment's callee
  name/no-return queries resolve through `effective_global_query`/`function_at` —
  query-through with `<hole>` negative caching, decoded-entry positive caching,
  readonly/volatile property paints over a `lockDefaultProperties` snapshot, and
  namespace paths via getNamespacePath.  The wire is reached through the
  `RemoteProviderFetch` trait (implemented in `kuna-ghidra/src/provider.rs` over the
  shared client); the standalone path installs nothing and stays byte-identical.
  Query-bearing acquisitions return `KunaResult` through namespace, tracked
  register, symbol/property, callee and naming consumers. A failed host query or
  decoder is not a missing symbol: it returns before hole/empty-cache admission,
  follow-up queries or warning conversion. Genuine empty replies and `<hole>`
  answers retain their absence semantics. Cache-only snapshots and static
  tracked-register reads remain infallible.
  Full local source records enter the fresh function's existing local scope
  through the same importer as supplied parameter mappings. Database IDs,
  mappings and use ranges are not flattened by command dispatch. Name-only
  locals become the scope's existing name recommendations; recovery restores
  their source ID without adding a type lock. Dynamic recovery remaps the
  matched variable using the original full hash and PC, including collision
  position/total bits, rather than rehashing its representative.
  Native-generated dynamic identities keep the winning collision descriptor
  and its anchor together; wire publication retains that anchor across CASTs
  instead of substituting the representative's definition address.
  Free Varnode construction queries properties without a usepoint; only
  established inputs and definitions use their entry or instruction usepoint.
  This keeps restricted parameter mappings off future register definitions
  while preserving whole-scope properties and later input/output binding.
- **`TypeFactoryGhidra`**: the wire `<coretypes>` decode replaces the default core
  types at registerProgram (so kuna's type ids match the host's), and
  `TypeFactoryImpl::find_by_id_or_remote` fetches unknown types with getDataType
  through the `RemoteTypeFetch` trait (`substrate/dtype.rs` `decode_type`/
  `decode_type_no_ref`/`decode_core_types`); `clear_noncore` evicts on flush.
  Exact `(name,id)` records and callable definitions reserve an immutable shell
  before recursive decoding. Weak completion links keep raw-shell contracts;
  independent semantic prototype readers retain only resolved reachable
  dependencies. Logical callable storage is acquired after by-value types are
  complete, and pending acquisition remains an error that can be retried.
  Struct synthesis reserves a fresh shell through
  `TypeFactory::kuna_synthesized_record`, rejecting an already-held name and
  stamping process-local ownership before interning or recursive pointers.
  Completion and replay preserve that nonwire provenance. Ledger admission
  and retirement require it, not merely `struct_N` spelling or field layout;
  qualifier-only views consult their base, while typedef aliases remain
  separate source identities. Ordinary raw getters and declared-record
  lookup retain their existing behavior, including held revision readability.
  Ordinary logical entry application alone retains the original bounded
  `ParamUnassigned` diagnostic state; physical callable/storage acquisition
  remains strict, and diagnostic snapshots cannot establish physical bindings.
  Complete supplied entry prototypes stay on their exact entry owner, not an
  interned `TypeCode`; working prototypes and overrides are independent copies.
  Explicit pending declarations retain their original logical signature after
  successful working seeding. Whole-signature replacement clears stale logical
  provenance; inferred replacement alone does not establish an authored source.
  Authored mapped inputs retain their exact physical slot, including sparse
  slots beyond the model-assigned formals; holes do not become logical formals.
  Callee queries compose independent symbol flow facts with the complete
  prototype without changing its source owner. Missing call-fixup and gated
  import no-return facts require an independent copy; otherwise reader identity
  remains unchanged.
  Flow applies site prototypes before callee queries: a modeled site retains
  its own no-return effect unless the callee is inline. The flow checker reads
  that effective call specification, while an explicit instruction
  `CALL_RETURN` still terminates flow independently of the site prototype.
  The shared codec emits internal inputs for callable/site definitions and uses
  localdb-backed input publication only for full function results. Source
  presence, locks, roles, storage, effects, trash, injection and convention
  remain independent.
  Independently retained source prototypes own their finite completion
  dependencies; canonical recursive callable types keep weak completion links
  so the type graph does not retain itself. Raw borrowed getters remain raw.
  Supplied unknown conventions are registered once as named
  unknown models with the default model's behavior, while an arbitrary parser
  convention typo remains an error. Architecture, source decoding and new
  acquisitions share the same effective model registry.
  A non-placeholder convention name supplied by the callable wire prototype
  remains explicit authority when it still names the effective model, even if
  that model is also the default. Internal/default selection alone and stale
  declared names do not grant that authority. Existing narrow-return,
  variadic JOIN/float eligibility and unspecified-model image-evidence rules
  remain in force; no platform evidence is inferred from a hosted session id.
- **`CommentDatabaseGhidra`**: `RemoteScope::fill_comments` fills the comment
  database once per flush cycle from getComments, filtered by the printer's comment
  settings (empty filter ⇒ no query).
- **External references** resolve through the upstream two-step
  (`resolveExternalRefFunction`): an `<externrefsymbol>` answer keeps its resolve
  address and fires getExternalRef at the POINTER address; the returned function
  materializes at its own entry (name/prototype/noreturn), and the pointer symbol
  itself types as pointer-to-code. Java maps the slot with one byte of storage;
  kuna maps the whole pointer and flags it `externref`, as upstream does, so a
  call through a PE import slot prints as the import.
- **String literals**: Ghidra defines a string as a read-only `char[N]` or
  `wchar_t[N]` under a label (`s_…`, `u_…`). The printer's read-only check asks
  the remote scope (`Architecture::is_global_read_only`), as upstream's
  `ScopeGhidra::isReadOnly` does, so the reference prints as the literal.
- **C++ namespaces** print as the native decompiler prints them: calls carry the
  scopes the Display Namespaces option needs (Minimal by default), declarations
  their full path, one token per scope.
- **Call-fixups** arrive as the `<inject>` of a function's `<prototype>` (the
  Call-Fixup Installer's tag on `__chkstk`, `_guard_dispatch_icall_nop`,
  `__security_check_cookie`, the x86 EH/SEH prolog helpers). kuna resolves the
  name against the cspec call-fixups and injects the getCallFixup payload at
  each call, so those helpers vanish from the C as they do in stock Ghidra.
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
  Java's `DecompileOptions.encode` omits an option equal to Java's default, and
  the engine's defaults (`NULL` on, in-place operators on, function brace on the
  next line) differ from Java's for four options. The extension patch therefore
  sends `nullprinting`, `inplaceops`, the function `braceformat` and
  `maxlinewidth` on every `setOptions`; the session keeps the engine's own
  defaults. Java output always prints `null` for a null pointer: the literal is
  part of the language, and `nullprinting` selects only C's `NULL`.
  Calling-convention printing is enabled by Java's sparse default, but the
  architecture's default model is implicit (`printInDecl=false`). Changing the
  default republishes the former model as explicit and the new default as
  implicit, including live registry/evaluation acquisitions; held prototype
  snapshots remain independent. Actual declarations use one architecture
  visibility lookup by registered model name, with the held model's policy as
  fallback for unregistered models; this lookup never changes prototype ABI,
  locks or layout. Explicit non-default model display still obeys
  the convention-printing toggle.
  Native host documents use the existing `EmitPrettyPrint` queue for linewidth,
  optional parameter/expression breaks and comment continuation. Width survives
  fresh document sinks and resets to 100 with fresh options. Standalone C and
  its raw token/provenance maps keep their original unwrapped emission path.
  Bitfield access follows this same action policy: Java sends
  `currentaction(bitfields,off)` only for the non-default disabled state.
  Derived pools filter the registered `RuleState` group before cloning a rule,
  including stateless rules whose concrete clone is unconditional. Thus off/on/off
  rebuilds the selected root without/with/without all six bitfield rules; disabled
  extraction retains its actual mask/shift IR instead of emitting `INSERT`,
  `ZPULL` or `SPULL`. The enabled sparse default is restored by the ordinary reset,
  not by a printer-side suppression or a separate bitfield setting.
- **The `Kuna v…` banner**: ghidra-mode prints a one-line plate comment
  (`/* Kuna v<MAJOR.MINOR> */`, the release `KUNA_VERSION` bake) at the top of
  every decompiled function so it is visible in the GUI that kuna is the active
  core.  Cache-only (never written back to the host); standalone output has no
  banner.
- **flushNative** clears everything in the upstream order
  (`Architecture::flush_remote_caches`): the lazy symbol cache + property rollback
  + the per-address tracked-register cache, the non-core types, the comment
  database, the decoded strings.

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
  `<seqnum>` carries its address and unique id as attributes on that same element;
  native sequence decoding reads those attributes without opening a nested address,
  preserving adjacent operands and markup operation identity.
- **Syntax-pair identity**: queued RPN calls, subscripts and casts retain the
  opening emitter id on the live expression stack until the matching close.
  Java's `ClangSyntaxToken` uses the encoded `open`/`close` ids to pair tokens;
  an earlier RPN snapshot must not overwrite the id returned by the emitter.
  The pretty-printer's process-wide allocation counter is not a stable
  cross-document identity.
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

Source emission also retains machine value contracts independently of the
receiving compiler's defaults. With an attached Ghidra host, C `INT_SEXT` from a
text byte explicitly converts through `signed char`, without changing the source
`char` declaration; the standalone CLI keeps the upstream spelling. That sign pin
is independent of the outer widening: `castimplied`, `castternary`, ordinary
promotion hiding and widening policies still decide whether C performs the outer
conversion without an explicit cast.
Phi commoning keeps distinct address-tied storage locations separate even when
their incoming values match. In particular, a global-state phi is not replaced
by a local pointer phi: its later aliasing-store marker must retain the global's
identity rather than requiring a synthetic write back to that global.
With `indirectargs` off, anonymous callable declarators use existing, fully
allocated indirect ABI storage rather than the retained logical value signature;
pending logical declarations are not treated as allocated storage.
C declaration assertions accept a typedef with the same name as its struct,
union or enum tag; the existing tag is retained rather than creating a
conflicting factory typedef identity.
Cast insertion
transfers the original read before attaching its replacement CAST input, keeping
free values single-reader without dropping operands when already-analyzed IR is
Generated C
narrow unsigned enum complements are truncated after C integer promotion.
An authored typedef exposing an anonymous DWARF enum retains the enum's own
identity, unnamed source spelling, members, width and sign separately from the
typedef's identity. Native headers define that enum under its genuine typedef name; other aliases
of the same enum reuse the first emitted genuine alias while retaining their own
declaration identities.
Bare `decompile-all` output still omits type definitions by default. Consumers
combining selected bodies can use the actual `decompile-project` header once
instead of reconstructing missing source enums or repeating per-body definitions.
Ordinary Ghidra output leaves the native `structdefs` preamble disabled;
`CppExporter` uses Java's `DataTypeWriter`.
An authored `FunctionDefinition` name identifies its callable datatype, not a
C pointer typedef. Named Code keeps its source spelling and managed type-token
binding; anonymous Code retains its structural declarator. CLI headers and the
authorized enhanced Java datatype writer emit a canonical function-type typedef,
such as `typedef int CallbackSig(int);`, for the named callable. Pointer(Code)
therefore remains `CallbackSig *`, and actual pointer typedefs remain distinct.
Only the outer callable name is expanded while defining it; its logical source
signature, nested named types, and source identity remain unchanged. Composite
forward names and necessary aliases precede callable definitions; callable
definitions precede record bodies that use them. The unmodified stock Java
datatype writer still omits direct FunctionDefinition definitions. Its ordinary
closed-C export limitation remains visible and is not a certificate of supported
export or grounds for erasing ordinary native source names.
No global-name query was added for that unselected native preamble: lazy native
acquisition only knows acquired definitions, and the host's namespace
`isNameUsed` query excludes global symbols.
Explicit source integer ranks are not replaced by equal-width ranks. The
console declaration parser retains validated `short`, `int`, `long` and
`long long` signed/unsigned combinations as canonical named atomic types,
using the target's existing widths. Equivalent keyword orders and optional
`signed`/`int` tokens share that rank identity; LP64 `long` and `long long`
remain distinct despite equal sizes. Single-keyword host lookup, character,
floating, Boolean and wide-character resolution retain their existing paths,
as do missing-width and invalid-combination errors. Inferred width-only types
continue to use the ordinary size/metatype allocation and spelling policy.
Placed bitfields decode their byte extent from
`first + size`, reject parent-boundary overflow, and mark direct and nested
bitfield-containing records for the ordinary load/store recovery rules. They
render interleaved ordinary fields and bit padding with packed allocation.
These declarations require the existing GCC/Clang packed-attribute dialect.
The maintained Java datatype writer uses the same placed-bit geometry for source
record declarations, including leading/trailing bit padding and source alignment.

Comment visibility uses the shared comment-category bits and the selected
header/instruction masks. The `c` and `cplusplus` styles apply to actual comment
tokens, including every physical line of multiline text. Payload delimiters
cannot terminate a generated block comment, and trailing backslashes cannot
splice a line comment into the following statement. Reset restores the default
style as well as the masks and indent.
Host markup retains one queued comment group across payload line breaks, with
the original source-address bindings and per-line safety escaping. Continuation
text belongs to the queued group, including overflow, rather than whichever
comment style was most recently selected. Plain output and its raw source-map
spelling retain their existing per-line emission path.

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

The development native override requires the full Java extension already installed
in the selected profile. It is not an installation alternative. Headless consumers
must select the native process explicitly before opening their interface because
they do not load the CodeBrowser plugin; see the extension README's
`KunaCoreSwap` examples. Neither native selection nor the diagnostic stock-core toggle unloads
Java classes. No stock binary or installation JAR is overwritten.

## 8. Version policy (decided)

The full extension targets exactly **Ghidra 12.1.4 with Java 21**. Do not bypass
a version mismatch with **Install Anyway**. The ordinary native
protocol has no general compatibility handshake — the interface version (major=6/minor=1,
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
with Phase 3 and is recorded as **DIV-76** in `docs/history.md`. Native sessions
now use `OptionDatabase::decode_native`: malformed known options stop the list,
answer `f`, and preserve successfully applied earlier options. A new request
resets engine, printer and derived action-group policy before applying deltas.
CLI lenient decoding is unchanged.

`ActionDatabase` alone owns the selected root. Reduced roots use the same
source/local preparation, deadline and reflow driver as decompile; temporary
jump-table and signature normalization roots restore the previous selection on
success and failure.
Model/default changes publish through the existing type and remote-scope
resolvers without modifying held immutable source prototypes.
Architecture and TypeFactory share one named-model registry, so a
source-supplied unknown convention retained by the physical decoder is visible
to subsequent model lookups. Declaration parsing still requires a registered
convention rather than inventing an arbitrary unknown name.

FunctionSymbol prototype snapshots project retained logical source declarations
before legacy parked pieces, keeping authored result types and formal names
available to existing providers without reconstructing them from working storage.
Remote entry declarations retain the full localdb parameter list and independent
source locks without relabeling supplied physical roles as logical declarations.
Missing non-custom placements are completed on the independent working prototype
with physical slot order intact. Raw source mappings, roles and missing addresses
stay unchanged, and custom storage does not acquire synthesized hidden inputs.

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
| Signature engine | `kuna-decomp/src/infra/signature.rs` + `analyzesigs.rs` | native simple/debug commands use the canonical algorithm and origin codecs |
| Signature element ids | `signature.rs` — canonical IDs 258–269 | settings include version 6.1 and the current validated global mask |
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
| PrintC → `EmitMarkup` | back-end ported, front-end hardwired (`printc.rs:1015`) | generalize PrintC's `emit` field; wire `doc_function` (`printc.rs:1102`) to the markup path | 2 |
| Scope / symbol table | **DONE (Phase 3)** — `RemoteScope` (`infra/remote_provider.rs`): query-through + `<hole>` negatives + property paints + namespace paths, at the GlobalQuery/flow seams; **Phase 4** echoes the delivered DB symbol ids back (`GlobalEntry::symbol_id` → `<high symref>`) | — | 3 ✔ / 4 ✔ |
| `TypeFactory` | Wire core/source decode, lazy exact-ID acquisition, nominal reservation/completion and marshal-out (`substrate/dtype.rs`); embedded Code prototypes use the complete contextual FuncProto codec | Raw immutable shells remain distinct from resolved semantic readers | implemented; integrated consumers required |
| `CommentDatabase` | **DONE (Phase 3)** — `RemoteScope::fill_comments` (getComments, printer-filtered, fill-once-per-flush) into the `Architecture.commentdb` sink | the printer renders PRE/warning + header comments; EOL/POST placement is a printer gap, not a wire gap | 3 ✔ |
| `ParamIDAnalysis` | **DONE (Phase 4)** — `<parammeasures>` encode + the paramid-action doc shape (`infra/paramid.rs`; the justproto constructor reads the real recovered `FuncProto`) | — | 4 ✔ |
| `StringManager` | shared by cleanup and printing; host misses use `getStringData` UTF-8 directly, including refusal and truncation; cache discriminates character width, opacity, host type identity and request limit; flushNative clears facts | standalone Unicode decoding and internal strings remain native | implemented; integrated consumers required |
| Inject library | One shared live `Rc<RefCell<PcodeInjectLibrarySleigh>>` owns payloads, templates and IDs. Userop names initialize before processor jump-assist decoding; compiler fixup compilation stays later. Site-bound call/callother injections are fetched without retaining a library borrow and are not cached. | Executable helpers compile/fetch once per payload and run through `EmulateSnippet`; reentrant frames share emitted code, not temporary state. Loader/resolver backedges are `Weak`, LOAD uses the canonical live image, and flushNative retains compiled code. Natural `JumpAssisted` consumes size/address/case/default helpers. | implemented; integrated semantic consumers required |
| `ConstantPool` | one architecture/analysis/printing cache; host misses use `getCPoolRef`, decoded through the shared type factory; `RuleTransformCpool` handles primitive replacement, boolean marking and tag annotation | flushNative clears pool facts; query/type errors propagate rather than becoming missing records | implemented; genuine JVM consumers required |
| ArchSeam snapshot | **DONE (Phase 3)** — the three frozen tables read through live seams when a `RemoteScope` is installed (`ArchContext::effective_global_query`/`callee_proto_pieces`; tracked sets decode from the wire pspec `<tracked_set>`) | — | 3 ✔ |

## 10. Graceful degradation

What breaks when a partial core omits pieces — all failure modes are clean:

The transformation scheduler keeps its integer status convention inside a typed
result: `Action::apply` and `Action::perform` return `KunaResult<ApplyResult>`,
where `ApplyResult` remains `int4`, and `Rule::apply_op` returns
`KunaResult<int4>`. `Ok(-1)` still means a resumable breakpoint, not an error.
An error stops the current rule pool, action group and restart schedule
immediately, preserving the original error category and changes already counted.
The driver restores a detached action owner before propagating the failure.
Constant-pointer spacebase conversion also propagates its typed failure; it is
not treated as an unsuccessful pointer candidate after conversion has begun.
Caller-pointer string proofs and character-table refusal guards propagate
resolver and source-query failures through their typed vote boundaries.
Caller evidence is acquired before replacing the recorded call-site facts, so a
failed acquisition does not publish a partial replacement ledger.

Rendering uses the same typed boundary: full C, statement provenance, token
markup, provenance, captured tokens and prototype roots return `KunaResult`.
String, resolver, register, facing-type, storage and namespace acquisitions
propagate at the actual recursive print call; genuine optional absence retains
its `false`/`None` meaning and pure token formatting remains infallible. A failed render
discards its incomplete document, RPN stack and per-document bindings, restores
the scoped function pointer and context, and restores any temporarily selected
backend, capture mode or language. The architecture always regains its taken
printer before the error escapes. Native documents and console/project result
tuples are published only after their required rendering succeeds; an acquisition
error is not a successful partial C/prototype/provenance result.

Recoverable acquisition/action/emission errors return through
`GhidraCommand::doit` before opening the main result string (burst 14). Only
the native diagnostic (bursts 16/17) and response close are sent. This matches
the original native action-before-output ordering: an empty opened packed
response would cause Java to attempt `<doc>` decoding and replace the genuine
instruction-limit or acquisition message with a decoding error. Subsequent
commands continue in the same process; transport errors still terminate the
connection without a completed response.

Successful replacement flow clears only that function's generated
`warning`/`warningheader` comments before publishing its new diagnostics.
Reflow keeps the warnings its abandoned pass buffered and publishes them with
the replacement flow's.
Authored header/instruction comments, other functions' diagnostics and held
encoded results are preserved; a stored inline annotation cannot outlive the
body that produced it after a policy transition.

Dead host EOF and stream I/O failures carry the distinct engine
`KunaError::Transport` category through provider, flow, transformation and
printing queries, then convert back to the connection owner's terminal wire
error. They do not become ordinary missing symbols, negative cache entries,
warnings or a completed command response. Received Java exceptions and ordinary
engine errors remain recoverable. Query-bearing register names and user-op
enumeration return typed results; unsuccessful enumeration does not publish a
partial name table. Scope-aware free-varnode construction is fallible, whereas
constant, unique and space-annotation constructors remain query-free.
Constructor, facing-type and storage-preservation failures propagate through
heritage, split-flow and call-recovery helpers to their Action/Rule result roots.
Call recovery restores detached call specifications and active-output ownership
before returning an acquisition failure; it does not turn that failure into a
rejected trial, an absent split or a successful partial argument list.

Flow callee/no-return probes and analysis helper caches retain typed acquisition
errors rather than caching a refused query as ordinary negative evidence.
Entry-liveness acquisition carries terminal errors through prototype-order,
callback and caller-return consumers before publishing recovered facts.
Ordinary unavailable or recoverably undecodable bodies retain their conservative
unknown-summary behavior; cached summary predicates remain infallible.
Project entry, pulled-batch, target and export-target APIs and their convergence
sweeps retain typed acquisition failures rather than returning a successful
partial batch. CLI commands and the WASM request boundary convert those errors
to their existing user-facing error strings; streaming exports close the result
channel and join the artifact writer before reporting a producer failure.
Detached heritage/action owners are restored before failures return. Jump-table
recovery keeps its ordinary recovery modes in a separate inner result; terminal
transport bypasses recovery, and failed trial tables are discarded.
The compact-selector immutable-map proof likewise propagates terminal transport;
an ordinary failed proof leaves the conservative selector domain unchanged.

Late variable and emission preparation preserves the same distinction: global
storage contracts, scope-backed spacebase subtypes, imported-callee stack-pop
inference and indirect-call resolution return query failures to their action
root. Global-reference and signed-shift rendering helpers likewise propagate
failures to the printer; only a successful query with no matching symbol may
select an unnamed-global, non-pointer or absent-contract path.

| omitted | Java-side behavior | blast radius |
|---|---|---|
| signature commands | supported canonical settings, simple features and debug origins; function analysis uses a scoped normalize root | BSim |
| `structureGraph` | supported canonical graph decode/structure/encode | FunctionGraph nested-layout view |
| empty `decompileAt` payload (function failed) | `decompileCompleted()` false; the 16/17 warnings text becomes the error message | that one function — clean GUI error |
| second `<function>` (markup) | HighFunction decodes; GUI panel refuses to render (`DecompileData.java:56`) | GUI blank for that function; analyzers/scripts on HighFunction still work |
| `<parammeasures>` | param-ID / convention analyzers get nothing | those analyzers no-op |
| `<jumptablelist>` | switch analyzer finds no tables | unrecovered switches in the listing |

**Load-time analysis facts are the other half of this.** A wire session never loads
the image on kuna's side — the program database is Ghidra's — so every kuna analysis
pass that reads the file itself contributes nothing to the GUI path. The largest one
today is `formatstring static`, the load-time printf/scanf format resolver: through
the CLI a `printf("%s %d", …)` call has its variadic arguments typed from the format
constant read out of `.rodata`, and through the wire it does not. Ghidra ships its own
`FormatStringAnalyzer` for this, so the fact is available on the host side; carrying it
across the wire (or having kuna open the file alongside the session) is future work.
The ghidra-sim differential in §11 therefore runs its CLI arm with `formatstring off`,
so the pinned line-diff band measures markup fidelity rather than this known gap.

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
  manager so packed space indices agree by construction; getMappedSymbols answers
  empty — the Phase-2 reality). It asserts the §6 response contracts (dual
  `<function>` decode, name/entry echo, markup opref/varref ⊆ ast, the 19-query
  legality and query-legal-command placement), flattens the Clang markup to C with
  Java's `getC()` token cleaning applied (`IllegalCharCppTransformer` — the reason
  over-wide type tokens read back as `unsigned_long__a1`), and **pins today's
  GUI-path quality numbers**: raw-register identifier leaks, `Unique<hex>` tokens,
  `sub_`/`dat_` placeholder rate vs what the loader knows, `getC()`-mangled token
  counts, query traffic (getPcode totals, getMappedSymbols == 0), and the
  normalized line-diff ratio against the SAME functions through the in-process CLI
  path. The pins are inline consts in `ghidra_sim_e2e.rs`; they move only with the
  provider/emitter change that earns the move — Phase 3/4 land by flipping them
  downward. Run: `make test-ghidra` (release; also part of the CI `gates` job on
  every PR, which matters because the workspace suite is skipped on internal PRs).
- **Phase 3+: DecompileDebug captures as fixtures.** Ghidra's "Debug Function
  Decompilation" action (`DecompInterface.enableDebug`, `DebugDecompilerAction.java:38-73`)
  records every callback answer into an `<xml_savefile>` — exactly the document kuna's
  datatest corpus already consumes. Captures give us *recorded Java-side query answers*
  to replay against `kuna-ghidra` without a live Ghidra (de-risking the sim's
  synthesized `<mapsym>` shapes), and `DecompileDebugXmlLoader` (Features/Base) can
  import them as Programs for the reverse direction.
- **Installed-product acceptance:** `make test-ghidra-live` runs the existing
  twenty real-Ghidra suites. Set `KUNA_GHIDRA_EXTENSION_ZIP` to the freshly built
  normal ZIP: the runner installs through `ExtensionUtils` in an isolated profile,
  restarts, verifies Java origins and selects that installation's bundled native
  executable. CI runs this gate on qualified macOS ARM64/Ghidra 12.1.4/Java 21
  for main, manual/nightly runs, fork PRs and internal PRs with `full-ci`.
  Run it locally before merging integration changes; Rust protocol simulation
  and package compilation alone do not cover Java result/export semantics.
  See `tests/ghidra/README.md` for prerequisites and raw stock-control comparison.
- **Focused live smoke:** `integrations/ghidra/live-smoke/` — a
  pyghidra rig that swaps `DecompileProcessFactory.exepath` to `kuna_ghidra` inside
  a real Ghidra, decompiles the same functions with both cores, and writes a
  side-by-side report with the same scanner counts the sim pins (see its README
  for the offline-pyghidra setup). For the full extension path: build the
  normal extension ZIP, install into its matching Ghidra release and restart,
  enable the plugin, verify the spawned PID is `kuna_ghidra` and that the C,
  click-to-address, and rename round-trip behave. Product testing requires the
  full 12.1.4 ZIP in an isolated per-user settings profile on the same stock
  installation. Untouched-Java controls use a separate profile without the
  extension; they are not another distribution.
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
      decompileAt resolves the current function's identity (name + locked prototype
      pieces) through it, getCodeLabel demoted to fallback.
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
      for real with per-element skip-unknown (DIV-76). `calltargettype` is left
      out: Java decodes its anonymous function-pointer types as `undefined1`.

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
- [x] Markup type-token fidelity: the existing C declarator builder optionally
      retains exact datatype-bound base spans, including nested callable returns
      and formals. Declaration and cast emission gives each base leaf its own
      native owner; qualifiers, pointer/array operators and grouping are syntax.
      `EmitMarkup::tag_type` may split a multiword scalar into words sharing that
      scalar owner, preserving Java's `IllegalCharCppTransformer` behavior.
      Invocation-local presentation names are keyed by native identity and never
      rename source types or mutate the factory; ordinary unmapped spelling keeps
      the existing allocation-free span path and unchanged C bytes.
- [x] The rename/retype PERSISTENCE loop: the function `<localdb>` answer's
      non-parameter locals (what Java sends after
      `HighFunctionDBUtil.updateDBVariable` committed a user edit) seed the
      fresh Funcdata — typelocked locals as mapped/usepoint symbols, plain
      renames (typelock=false) as `ScopeLocal::nameRecommend` records (the
      C++ mechanism; applied by the `ActionNameVars` port) — so a GUI
      rename/retype SURVIVES the event-driven re-decompile.
      Fresh physical-entry parameter symbols use the materializer's compact source
      slot and the existing ABI allocator's source-to-working correspondence, so
      generated hidden inputs never take an authored parameter's identity. Local
      categories follow the working carriers even when supplied physical mappings
      stay unchanged. Only missing physical mappings take the working datatype,
      roles, storage and ordinary parameter usepoint policy. Host symbol IDs and
      raw source categories/records remain retained; dynamic locals and logical
      callable allocation are not rewritten.
- [x] Every `<vardecl symref>` in the corpus resolves against its own
      `<localdb>` — `PIN_FAILLOG_VARDECL_UNRESOLVED = [0,0,0]`, plus a
      per-target 0 on the sort/grep breadth fixtures, so declaration-line
      rename/retype is live everywhere.  The last residue was a stack aggregate
      reached only through `&sym`, whose whole HighVariable is the constant
      `PTRSUB` operand: `link_symbol_reference` now records the referenced
      Symbol's identity (C++ `Varnode::setSymbolReference`).
      Named explicit values in a spacebase register also require local symbols:
      the spacebase flag does not exclude them from the existing storage/usepoint
      mapping. This is distinct from linking the referenced symbol of a `PTRSUB`
      offset, matching `ActionNameVars::linkSymbols`' two independent steps.
- [x] Harness: the ghidra-sim decode now validates every Java hard-throw trap
      (r5 §3 — nonzero symbol ids, entry pairs, positional scope children,
      localdb/ast-before-highlist order, symref/repref resolution, prototype
      completeness, `<rank>` presence) plus switch-analyzer- and
      paramid-shaped configuration tests.

The `structureGraph` codec is owned by
`kuna-decomp::blockaction::structure_graph`: it decodes the canonical input
`BlockGraph`, copies it, labels loops and forward dominators, collapses structures,
orders the result, and encodes the canonical block tree. Copy `altindex` values
retain the original component indexes used by Java's `transferObjectRef`; block
types, reverse edge slots, condition opcodes, and goto target indexes/depths use
the existing block codec. Independent graph switches have no function jump-table
association; function-IR switches still require their recovered table. The actual
Java consumer is `tests/ghidra/native_features.py` (including stock topology,
branch-polarity, object-reference and address comparisons).

**Phase-4 deferred (follow-ups, graceful degradation per §10):**
- [x] The four signature commands, including canonical settings and debug origins, for BSim.
- [ ] Overlay spaces (Java swaps in overlay codecs transparently —
      `DecompInterface.java:84-127,896-909`); `getStringData` charset fidelity
      (Java-side decode instead of `GhidraLoadImage` bytes).
- [ ] `<override>` / child-`<scope>` statics (Java skips both); the C++
      `collectNameRecs` harvest (standalone symbols → recommendations).
- [ ] `kuna_apply_dynamic_recommendations` runs BEFORE the naming walk rather
      than after linking (kuna fuses the two upstream stages into one pass), so
      it creates a dynamic Symbol where upstream renames an existing one.  The
      upstream guards are reproduced against the scope instead of the high —
      see `docs/spec/06-variables-and-merge.md` §6.4.
