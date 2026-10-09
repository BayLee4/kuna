> Historical investigation record. The earlier HFA and DWARF guard conclusions are corrected below after source comparison and independent critique. The user's standard is unchanged: each assertion must test the contract it claims to guard. Historical dispositions are evidence, not approval to change tests.

# Clean reimplementation requirements and test-port scope

User decision: restart from updated upstream Kuna, preserve the abandoned branch and investigation, port methodology without reducing corpus counts. Decide requirement/test scope first. The previous three-defect list was illustrative, not complete. This document is a concrete requirement proposal, not approval of discarded implementation or a claim of final acceptance. Updated upstream applicability is checked after the preservation step and fast-forward.

The corrected effective scope was accepted by the engine and surface critiques. Their original objections and separate informed follow-ups remain in `Restart{Engine,Surface}Critique-{report,findings,followup-report,followup-findings}` artifacts in the evidence archive. This closes scope conflicts only; implementation choices, updated-upstream runtime applicability and final product acceptance remain open.

## Admission rule

Carry consumer-visible requirements and original inputs/oracles, not cutover mechanisms. A passing added branch test proves its branch implements an expectation; it does not establish that the expectation is necessary. Preserve original baselines/readable-C/type/name/source-edit contracts and meaningful additive machine/provider coverage. Adapt genuine behavioral tests through existing public owners. Retain graph-lock/key/count/wire-revision/receipt/family-plan/source-text/wiring tests in the evidence branch when their only consumer is the discarded architecture. Exact type/ABI/storage/value/effect identity remains required where the actual consumer relies on it; arbitrary internal allocation IDs and wording do not.

Before changing an assertion, establish whether it tests the contract it claims to guard. Passing counts, equivalent replacement coverage or an "incidental" label do not establish that the original guard is wrong. Preserve source-authored names/types and meaningful C/High/markup/value/ABI/precedence/lifetime behavior. The original exact DWARF names and suffixes guard the documented deterministic collision policy and name-keyed layout lookup; keep them. Keep raw-shell and resolved-layout contracts distinct: a new completion assumption does not invalidate an existing shell guard. The original HFA no-dedup negative is valid: it isolates the filter's pointer-identity prerequisite, matching Kuna's `Rc::ptr_eq` and Ghidra's `Datatype*` comparison. It does not claim that normally interned equal float fields should fail ABI classification, nor independently verify factory canonicalization. The exact maps preserve historical text and decisions; evaluate each disposition against the same unchanged assertion-integrity standard.

All original gates and consumer phases remain obligations. Tests blocked by earlier assertions remain unexecuted, not waived. A cutover-only regression is a constraint on the new implementation, not proof that pristine upstream needs the same repair. A source-confirmed gap is distinguished from a runtime-demonstrated defect. Future fixes are admitted only after their requirement is independently challenged, reproduced on updated main, and assigned to the correct existing owner.

## Proven or established requirement families

1. **Stock native feature surface.** All11 actual stock commands, callback-backed pcode/bytes/symbol/type/comment/register/injection/cpool queries, compatible response framing and error classes. Five absent commands in0096e984/current: structureGraph, generateSignatures, debugSignatures, getSignatureSettings, setSignatureSettings. Main's genuine same-ProgramDB stock-versus-baseline witness now demonstrates FunctionGraph diamond structuring and valid BSim settings73/generation/debug features in stock versus Bad command/no usable result in baseline; ordinary decompilation still recovers in both. Evidence: stock-feature-gap-valid/report.json. Separate invalid-settings0 control is retained in stock-feature-gap/report.json. Acceptance also requires preserved FunctionGraph leaves/control-flow/object/address mapping and stock-comparable BSim feature hashes/multiplicities with truthful version/settings, raw/debug correspondence and actual database/LSH interoperability; parser acceptance/nonempty output is insufficient. Those broader runtime phases remain unexecuted. CPOOLREF has transport but unresolved engine owner, a source-confirmed gap whose actual bytecode consumer remains unexercised. Existing successful scalar decompile does not cover these features.
2. **Ordinary stock Java usability.** Actual unmodified DecompInterface must receive readable C, linked token markup and HighFunction without requiring private4070/4030/4081/4082 grammar. Independent tree/C toggles, notree, selected roots, measurements/jump loads and plain native replacement remain valid. Current unknown-tag loss is demonstrated; baseline compatibility is representative, not full acceptance. Exact native executable/core switching and process recovery remain obligations.
3. **Authentic function facts.** Per-entry source names, independent parameter/input/output/model/name/type locks, explicit storage, hidden/this/indirect flags, no-return/inline/injection/effect/trash/vararg boundaries and omitted-vs-supplied facts survive decoding and analysis. Authentic source seed is distinct from mutable recovery. Baseline host parameter-lock loss is demonstrated. Current store-null/captured-recovery failures constrain new source handling rather than justify another immutable whole-prototype authority.
4. **Callsite authority and ABI meaning.** Overrides are site-local, newest-site changes/removal win at that site without changing other callers or independent callee source locks; declared convention/custom/JOIN/hidden result cleanup and source formals/results remain truthful. Typed CALLIND declarations obey independent lock precedence and model binding; effect/no-return/fixup/injection/flow override precedence is preserved. Current exact printf occurrence permutation and InjectOverride failure are constraints; further baseline defects require their own updated-main witness.
5. **Source-edit and lifetime authority.** Genuine ProgramDB edits, parameter rename/retype/storage/unlock, symbol collision commit, usepoint/reused storage, recursive child mutation, flush/reset/reopen/respawn produce fresh truthful C/High/markup while Program source is changed only by explicit source edits. Absent/partial/full prototypes and output-only/void declarations remain usable. A free Varnode has no invented entry usepoint. Current graph borrow and stale projection records are implementation failures, not reasons to port those maps.
6. **Stable recursive datatype completion.** Early pointers/aliases/fields see later completion of the same factory-owned definition; true unresolved forward declarations remain incomplete; recursive sharing is finite and source identity is not name/shape inference. Baseline incomplete-pointer defect is directly demonstrated. Preserve nominal aliases, distinct same-spelled declarations, layout/extent/alignment, pointer banks/wordsize/relative pointers, bitfield byte geometry and effect-free display-format edits. Broad graph generation/reader/cache/transaction policies are not implied.
7. **Source versus inferred datatype provenance.** Source-owned same-shaped/named records stay authored; inferred records remain truthful transient inference, with exact per-document token/field/callable bindings and coherent lifetime. Native inference must not modify Program source datatypes or suppress same-name unrelated host definitions. Cross-worker portable source closure is required only by actual supported consumer; no blanket second datatype codec is admitted.
8. **Real source-language import.** DWARF typedef/callback formal/result/order/open-vs-closed/vararg/no-return/convention facts, signed/unsigned char, incomplete by-value layout, typed global extent and top-level volatility are preserved without fabricating storage/default ABI. Explicit convention absence and DW_AT_prototyped absence cannot be converted to invented declarations. Real retained C89/C11 clang and C11 GCC objects carry actual DWARF: baseline callbacks become void*, while current preserves named declarations but drops the observed Open callback argument. Unchanged emitted target/caller bodies with original typedef declarations fail baseline compilation for all four callback kinds; current Closed/Fixed/Variadic execute correctly atO0/O2, Open executes incorrectly at both. Evidence: al10-observations/callback-execution.json and per-object dumps. The first linked Mach-O binaries have no DIEs in the input and are not declaration-loss witnesses; their current four-wrapper panics are separate raw-input observations. Actual C++ COFF convention/absent-prototyped facts provide a separate source witness. Exact first importer/call-coordinate losses remain investigation obligations. C/C++/target ABI coverage remains cross-platform even when native execution is unavailable.
9. **Physical/source independence and readable calls.** Raw register/memory/result observations, independent upper bits and finite vararg occurrences survive; source params/types/names/arity and aggregate field/call meaning remain useful. Extra machine operands are not source parameters. Every rewrite retains occurrence/trial/placeholder/storage/use synchronization. Meaningful raw checks add to original readable-C clauses. No mandatory whole-program executable certification before ordinary output. Original concat/piecestruct/Bitfields/high-byte callers and all old call/result readable clauses remain acceptance.
10. **Import and data/body identity.** Exact loader/host data/slot/function-entry/thunk ownership prevents decoding import pointers as machine bodies; names alone never prove implementations/effects. Retain typed/volatile/global extents and full address-space identity in CLI/host/export/worker paths. The Format slot-as-PUSHAD defect is demonstrated in current code; clean baseline already preserves the original Format behavior. Optional receipt registries/veneer interpreters require separate necessity proof.
11. **Actual field/type/variable/constant consumers.** Genuine stock field OFF is byte offset; nominal leaves bind to their true datatypes; source/physical headers stay coherent; generated definitions retain exact width/sign/layout/convention, bitfield padding and union/array ownership. High-byte numeric defaults, explicit formatting, IEEE constants, rank-sensitive long versus long long, wide extraction, comments and RPN delimiter identity retain actual semantics. Handwritten packed enums/min-max anchors/no-bitfield replacement tests do not prove generated layout. Local source findings require an actual original consumer regression before clean production change.
12. **Action/configuration/error lifecycle.** Selected stock root executes, malformed known options fail meaningfully, sparse Java defaults/reset are respected, reflow stops obsolete work, fatal versus recoverable errors remain classified, subsequent valid requests recover. Existing engine default/option/group decisions and their original output remain intact. New alias/group-cache broadening, NaN first-operand policy and purpose-specific optimizer vetoes are unapproved optional behavior, not datatype migration prerequisites.
13. **Executable export correctness where supported.** Preserve original public CLI project/graph/serial/stream/worker contracts, real provider bodies, selected/analyzed-root completeness, declaration/type/global/ABI identity, meaningful omitted-provider/stale-source/refusal boundaries, source snapshots and genuine host CppExporter behavior. Original append-only immutable offsets/open reader contract remains. Never report successful incomplete selected export or replace prior destinations on enhanced failure. Stock legacy fragment warning/skip semantics remain distinct. Current replay support omission demonstrably loses roots under success; clean existing ordinary exporter requires preservation, not mandatory transport plans.
14. **Machine/value/effect execution regression families.** Keep actual source-built machine vectors and unmodified emitted providers atO0/O2: narrow/BOOL/upper/custom inputs, nondefault and nested callbacks, hidden/register/stack/aggregate results, readonly/mutable branches, control-only versus observable return roles, restored versus clobbered state, private-frame aliasing, native and finite vararg boundaries, genuine grounded recursion versus unresolved/nonreturning cuts, internal MIPS spill/reload/escape, pointer-array/bitfield/union/mixed-return/custom-result providers. Preserve allowed refusalORcorrect-execution alternatives exactly; a mandatory positive cannot become refusal. Raw facts and conditional executable assumptions stay distinct. No requirement implies current certificate species or repeated family replay.
15. **Verification and performance.** Original XML675 occurrence contracts (including duplicate Partial splitting#9), original stages1397 identities plus meaningful additions, CLI244, full enabled workspace plus explicitly required ignored/feature fixtures, simulator include-ignored/breadth/no-missing-spec shortcuts, all17 genuine suites and their later phases, actual stock/native integration and target data-model/provider execution, spec/catalog freshness and representative speed. Historical133 failures/1280 no-result cases and current30 datatest failures/31 Bitfields unreached remain recorded with provenance. Small scalar timings are not representative performance acceptance. Upstream additions/counts may change the future roster; preserve original lost identities separately and use actual updated corpus.

## First-port policy

The full acceptance roster also includes `.github/workflows/tests.yml:120-223`: `make test-cli`, catalog validation and generated options freshness, shared counters/ElementId uniqueness, release simulator include-ignored with missing-spec canary, browser study render/session/bytes/learn/groups modules, real WASM assembly, Worker/error/dev-viz/study-worker checks and available Chrome browser smoke. Recursive generated-provider O2 remains unexecuted despite the old comment. The original finite stack_tail/typed_address project failures and later mode_target O0/O2 success remain separate outcomes. Original default_authors input is retained for import/extent semantics; its undefined unterminated-array execution is not a portable oracle. A separately named well-defined driver supplies execution coverage.

Port original fixtures/oracles and requirement regressions before implementation, with compile/setup adaptations grounded in the existing baseline APIs. Keep stock/pure-baseline controls. Added tests depending on a discarded public extension are redesigned around the proven consumer requirement before import; their original form remains archived. New permanent tests cover plausible observable bugs, boundaries, precedence, lifetime or positive/negative transitions. Throwaway probes and observers remain evidence, not production instrumentation. A test requiring a newly invented product cannot silently enlarge or replace stock parity; any unresolved requirement is recorded explicitly pending proof.

Exact per-case test selections and requirement-to-audit-decision coverage are supplied by the engine, host and export mappings. Independent challenge evaluates this proposal and those exact selections together. No clean implementation or ported-test acceptance is claimed here.

## Recovery and provenance

The abandoned branch is `fix/shared-cli-ghidra-contracts`, preserved at `11a5f39a5530fa632c96ea729b9287a563331cc4`. `main` was fast-forwarded136 commits from `0096e984d74846e45f42c1dbe1fb95252083dda2` to upstream `c4f735f903026ec486a47f395e0e9944069e95e5`. The new branch is `fix/ghidra-clean-reimplementation`. The complete operation record is `kuna-reimplementation-evidence/20261006/restart-provenance.json` outside this checkout. The exact historical case index is preserved byte-for-byte at `/Users/leo/Downloads/ETH_Node/kuna-reimplementation-evidence/20261007-reassessment/clean-reimplementation-test-ports-20261006.json`. It is navigation and pre-review policy evidence, not current approval or a substitute for the original clause/helper/input evidence.

Updated upstream changed1647 paths, including DWARF builders, remote-provider and native process owners. Old0096e984 runtime findings remain historical evidence, not proof that c4f735f9 has the same defect. Reproduce each admitted defect against a freshly built updated baseline before selecting production changes. Existing `decompiler/target/` executables belong to prior builds, not this updated baseline; `make test` must not accidentally reuse them. The current upstream675 assertion count and all upstream guidance remain unchanged. Upstream also requires `make test-tools`, `make lint`, usable specs without false-green skips, and memory use below90%; retain these additions alongside the full live CI roster.

Durable local evidence: `/Users/leo/Downloads/ETH_Node/kuna-reimplementation-evidence/20261006/`. `raw-inputs.tar.gz` preserves historical source snapshots, actual witness executables, raw logs, genuine host/type/callmap probes, clean Ghidra12.1.4 source and JVM crash evidence. `audit-and-decisions.tar.gz` preserves the complete justification inventory, all owner reports/coverage, exact three requirement/clause maps, independent first critiques and distinct follow-ups, and Main's new runtime sources/commands/outputs. `cutover.bundle` preserves the Git source refs. Archive policy lists excluded regenerable build caches and genuinely missing historical indices/reports. These are local durable copies, not remote backup. The old `/tmp/kuna-owner-recovery-plan-20261006.md` is preserved as superseded evidence, not a live repair plan.

This restart carries methodology and requirement/evidence navigation only. Production implementations and tests are selected and adapted requirement-first; no wholesale cutover cherry-pick is authorized by this scope. The preservation snapshot is known broken, not a product milestone or passing-gate claim. Historical mixed-tree verification remains evidence only.

## Updated-upstream reassessment and regression ports

The approved work is steps1 and2, followed by a complete failure overview. Production repairs are a subsequent phase. The fresh comparison is pristine `c4f735f9`, built separately from the stale default release directory, with all149 processor specifications rebuilt. Current evidence lives in `/Users/leo/Downloads/ETH_Node/kuna-reimplementation-evidence/20261007-reassessment/`; `runtime-environment.json` records the actual executables, toolchains, specifications and supported writable Ghidra XDG paths.

| Original defect group | Fresh updated-baseline observation | Evidence |
|---|---|---|
| Ordinary recursive completion | Completed Node has size8, but its earlier pointer still sees size0/incomplete. | `recursive-completion-guard/` |
| Authored host parameter locks | Stock retains locks in all8 original lifecycle phases; Kuna loses them. Ordinary source/C/High/markup and14 O0/O2 scalar executions remain usable. | `host-scalar-{stock,updated}/` |
| Compiler-authored callbacks | All12 retained producer/callback pairs fail unchanged target/caller compilation at both O0 and O2 against original typedefs. | `dwarf-callback-replay/report.json` |
| Stock native graph/signature features | The same ProgramDB succeeds with stock FunctionGraph/BSim settings73; Kuna supplies no usable graph/signature result. Ordinary requests recover. Java guards the setter when native version is0, so actual setter execution remains unproved. | `native-feature-replay/report.json` |

Upstream improvements are bounded rather than family acceptance. `78212ad3` preserves explicit signed/unsigned char identity: original high-byte consumers pass with Clang21 and GCC16 at O0/O2 (`fresh-char-replay/report.json`); the broader plain-char prototype consumer remains independent. `30616a8e` repairs explicitly declared recursive records, not the ordinary earlier-pointer defect above. `24317760` adds callback-slot inference: the original qsort comparator now has the correct int return and two pointer formals, including the original calleevote-off command. The three original commands and their fields/types relationships are retained; generated names, register-comment spelling and the obsolete bool predicate were removed. A real int callback consumer compares all49 signed source-value pairs at O0/O2 without replacing emitted code (`focused-original-comparator/`).

The engine index accounts for1240 historical rows and242 selected behavioral/adaptation rows through current owners: DWARF10, datatype/source facts53, call state69, emission75 and configuration/IR35. These are scope counts, not passing executable-test counts. Current CLI inputs include the244 original cases and the three additional original-command controls. The real host harness registers all17 original suites plus genuine native-feature and JVM constant-pool consumers. Detailed original clauses, current targets, source evidence and unrepresented domains remain in each `*Ports-disposition.json`; source-only worker reports are not runtime verdicts.

Exact remaining obligations are retained rather than marked port-complete:

- Call-state EC0312/0321/0341/0368–0371/0903/1149/1151/1224 and the documented partial MIPS, return-role, carrier-edit and halt domains; EC0161 still lacks its genuine physical-input C consumer, while authored ordinal/name/type/storage and independent raw inputs remain tested.
- Authenticated executable-refusal counterparts of EC0156–0159; their ordinary diagnostic positives remain mandatory. Generic setup/pipeline errors do not satisfy those refusals.
- Physical vararg boundaries, genuine unwind/style inputs, typed fatal Action/jump-table channels and independent CALLOTHER effects where current consumers are absent.
- Broader/malformed FunctionGraph, additional BSim functions/settings/copy-debug origins, malformed constant-pool wire records and genuine getPcodeExecutable/all19 callback execution. The actual JVM invalid-reference/recovery consumer is narrower than malformed-wire coverage.
- Enhanced atomic selected-root/export omission, cleanup, trap, body/slot/thunk and vararg refusal domains require a genuine enhanced installation. Stock CppExporter fragment/warning behavior is a separate contract.
- The original Apple donor producer is missing. Both installed Clang21 and GCC16 omit DW_AT_noreturn on the actual NoReturn callback type; compiler dumps remain in `declaration-producer-evidence/`. These are producer prerequisites, not importer passes or proved importer failures.

Initial runtime exposed additional test-port setup and oracle mistakes. Independent critique distinguished missing spaces/factory/model configuration from product failure, restored original void/storage/lock controls, and removed assertions contradicted by actual Ghidra action selection or compressed RISC-V return semantics. Earlier interrupted or mixed-tree overview logs remain diagnostic evidence only; completion requires the entire final-tree roster after these corrections, with product failures and later unreached clauses recorded separately.

The executable-selector correction is test-only. Five remaining Rust harness helpers now honor the existing `KUNA_DECOMP_TEST_RUST` override; `KUNA_RUST_DECOMP_TEST` remains the other existing Rust-only selector. `KUNA_DECOMP_TEST` is reserved for a genuine C++ oracle and is unset here. Fresh debug siblings are built before the workspace run. The earlier Rust-as-C++ comparisons and stale fallback executions are invalid comparison evidence; optional C++ branches remain unexecuted when that oracle is absent.

Actual RV64 lifting contradicted a source-only return-role review: the low-word SUBPIECE output and later SEXT input are distinct varnodes at the same temporary address. The corrected ordered width/storage witness retains the full-width control and partial-read negative; all four return-role tests pass in `focused-return-role-supported/`. Publication completeness and independent inactive-clone clauses remain separate obligations.

The retained critique also identified nullable-cast, hidden-result sequence-shape and source-producer fixture mistakes. EC0619 now follows the real cast consumer: `None` retains the already-sufficient facing type rather than requiring a redundant cast. Hidden-result tests compile unchanged documents against real aggregate-returning, method-by-value and variadic providers, then check values, pointer identity and evaluation counts rather than capture spelling or comma-expression shape. Compilation failure leaves later runtime clauses unexecuted.

EC0731's cross-host-width refusal remains unrepresented. The preserved cross-width body fails on invalid raw-pointer indexing, not an authenticated width refusal; its exact input and diagnostic remain in `cross-width-original-consumer.rs` and `focused-owner-proofs-public-import/emit-consumers/stderr.txt`. The independent same-width positive uses unchanged emission and real pointer/cell checks at O0/O2. Neither an arbitrary compiler error nor that positive proves the original negative. Comment containment likewise uses real compiled following code; configured indentation and reset restoration remain, while sanitizer/filler spelling and default20 pins are removed.

Source-producer corrections retain bounded contracts without inventing publication paths. EC0194 tests held declarations, storage and locks in one actual RemoteScope; changing the live default for later declarations remains unrepresented because Architecture updates TypeFactory, not that scope's captured default. EC0750 publishes the bare alias, namespace and symbol ID through GlobalQuery and real remote function namespaces; source namespace policy and function declarations are exercised, while separate High provenance and mapped-global strategy emission remain unrepresented. EC0759 invokes the real enabled ActionCallTargetType producer with model resources and final ABI storage, retaining its protected-declaration/storage exclusions. Clone-local receipts, override-specific projection and conflicting-declaration replacement are not claimed.

EC0736's authored-name consumers preserve eight distinct parameter values after the aggregate call, but do not force collision with an actual generated capture: current emission has no such capture producer. That exact collision clause remains unrepresented. The retained reviewer approved these bounded adaptations and explicit gaps (`EnginePortCritique-integrated-source-resolution.json`); its verdict is source integrity, not execution or complete family acceptance.

The subsequent integrated smoke passed EC0619 and the bounded default/namespace consumers. It demonstrated executable comment injection, same-width invalid Rust pointer syntax and wrong direct aggregate-call ABI. Indirect cases now reach the unchanged C compiler instead of an intermediate target-type pin; they emit calls through `void *`. Runtime also exposed another fixture API error missed by source review: the markup sink's `output_str()` intentionally returns empty text. EC0759 now renders plain text and captured markup tokens separately through their actual sinks. Earlier source approval and failed flush-only hypothesis remain distinct diagnostic evidence, not acceptance.

The first complete overview finished in49m24s, without a memory-limit stop. It is
diagnostic: later review found simulator-canary, model/bootstrap and consumer
oracle defects, so its counts are not final-tree acceptance. The corrected
simulator gate exercises61 real tests successfully; the HFA and23 configured
nominal-access/modelrules/union consumers pass. The settings consumer now reaches
the real negative instruction-limit option instead of a missing executor import.

Three separately named datatype regressions restore original wire inputs:
INTMEM/SFR ptr/ptrrel banks, void() callback source-ID/instance extent, and
nested full alias headers without an invented varlength attribute. Actual
execution reaches lost bank distinction, missing encoded extent and rejected
Callback redefinition, respectively; later clauses remain unreached. The actual
same-tag grammar consumer retains source identity but observes a held size0
alias after size8 completion. An explicit host alias independently retains its
supplied ID and original layout.

EC0805's unsupported implicit constructor defaults are investigation-only.
`EC-0805-original-constructor-diagnostic.rs` and its first-primitive failure
remain unchanged external evidence. A separately named supported configured
maximum10/16 test passes scalar4/at-limit, array-at-limit+1, extent and unknown1
element/lookup controls. This does not make the historical diagnostic pass.
At that stage, the independent-allocation HFA guard was incorrectly removed.
It tests the filter's pointer-identity prerequisite, not factory deduplication;
the original negative and shared-identity positive are now restored.

The retained reviewer challenged every ordinary project-refusal assertion.
Current serial/stream/worker project output has no explicit executable-admission
owner; status1 alone can be an unrelated failure, and status0 is not certification.
All original negative commands, inputs and mandatory refusal obligations remain,
now recorded as prerequisite-unrepresented separately from completed behavioral
checks. Full selected-provider and unchanged execution positives remain strict,
and later cases run. The mixed callback-slot consumer now follows stock `.c`
global ownership; its actual compiler reaches the missing Callback declaration.
Complete/split stack-result consumers compile but exit2 at the direct-call value
check; the four incomplete-write negatives retain machine/source observations
and explicitly unresolved admission. The three-suite corrective smoke is
diagnostic because the final direct-predicate migration overlapped its first
suite; the complete frozen-tree run remains required.

The next51-gate run reached the full roster in49m57s, but is diagnostic:
the newly enabled MIPS gate used a working prototype before its model-binding
phase and pinned decimal `return 11;` against the equivalent `return 0xb;`.
Both are independently challenged test defects, not product failures. The
minimal correction queries the loaded architecture ABI before raw flow and
removes decimal/own-name/assignment-spelling pins while retaining original
raw counts, partial-byte dependency, source declarations and zero-formal
controls. All four genuine feature-enabled tests now pass. The actual unchanged
spill provider separately compiles and executes atO0/O2 with value11.

Enabling that gate without a focused preflight caused an avoidable full-run
repeat. Focused execution of all four consumers and the actual publication
consumer now precedes the new frozen run. A subsequently discovered publication
report reference still used the old overclaiming test name; the newly started
run was cancelled early, the reference migrated and the real publication
consumer exercised. Its negative private-role rows are observations, not
executable admission. The cancelled run has no completion claim; its active
guard completion record is unavailable. Native `ps` is permission-blocked;
the retained Darwin process-API observer found no older matching supervisors
and only the current run's workspace guard. This does not reconstruct the
missing older group-cleanup record. Historical EC0135/0137 coverage, preservation/completeness,
safe-internal-role classification and pointer lifetime remain unrepresented.

## Historical pre-review failure overview

The frozen final run is `final-overview-mips-final/`:24m04s,51 scheduled gates
accounted for,39 passed,6 failed,2 prerequisite-blocked and4 skipped.
This completes the approved reassessment/overview, not product acceptance or
every original port clause. Production remains at `c4f735f9`; no repairs,
commit or publication were made. All56 accepted requirements are classified:
16 have bounded admitted counterexamples;40 remain unresolved. None has
complete-family acceptance.

| Gate | Actual result |
|---|---|
| Original datatests | 675/675; PARITY OK |
| Current stages | 2208/2208; PARITY OK |
| Original CLI consumers through real GNU time | 280 passed,0 failed; includes all244 originals |
| Full Cargo workspace, non-failfast | 8268 passed,168 failed,40 ignored;20 failing targets; all10 crate doctests reached |
| Genuine feature-enabled MIPS | 4 passed,0 failed |
| Ghidra simulator with actual canary | 61 passed,0 failed |
| GCC16 DWARF import | 1 passed,9 failed |
| GCC16 unchanged-provider consumers | 1 passed,10 failed,1 ignored |
| Authentic held host datatype | 0 passed,1 failed at initial authored callback; later edits unreached |
| Real Ghidra suites | All19 attempted; all19 unsuccessful, including missing-consumer obligations |
| Python tooling | 39 passed,3 failed under Bash3.2 |
| Web/actual WASM consumers | All22 non-browser checks passed; assembly passed;4 browser checks skipped |

Isolated native builds, lint, spec anchors, catalog validation/freshness and
shared counters pass. All three observer-off/on comparisons are exactly equal;
every completed guarded gate records its child group absent. Peak guarded
anonymous/wired/compressed memory is87.04%, below90%.

The six failed gates are workspace, Python tooling, GCC import, GCC consumers,
real Ghidra and held host datatypes. Failures are test outcomes, not168
independently established production defects. The retained critique and exact
dispositions distinguish actual early-pointer completion, authored locks,
DWARF callable loss, pointer-bank/instance metadata, selected-root restoration,
aggregate ABI, executable comment injection, invalid Rust pointer syntax,
stack-result values and missing native graph/signature/JVM semantics from
setup/oracle, stock exporter and missing-consumer findings.

The original Darwin `/usr/bin/time` CI wrapper remains prerequisite-blocked;
the same original corpus through the separately verified GNU wrapper is not
a pass of that wrapper. Both actual Clang21/GCC16 NoReturn callback producers
omit `DW_AT_noreturn`; no importer verdict follows. Chrome discovery found
no usable executable and browser scripts explicitly skipped. The genuine C++
oracle is absent; optional C++ branches, ignored cases and assertions after
first failures remain unexecuted.

The final reports contain51 distinct observed unmet executable-admission
records with original commands and ordinary status0. They are missing-owner
obligations, not51 certified product failures or successful refusals. Additional
unreached/unrepresented source/physical, malformed-wire, enhanced-installation,
provider and performance clauses remain in the exact owner dispositions.
Stock callback export's missing declaration is a stock-exporter limitation,
not evidence of a Kuna engine regression.

Evidence owners: `failure-overview.json` holds all51 gate results, raw paths,
failed test names and admission record locations; `requirement-dispositions.json`
holds every56 classification and bounded witness; the existing port index
links original clauses, current targets and explicit gaps. Historical worker
source-only/pending fields remain historical; Main's final execution is their
current runtime authority.

Next production phase begins with one proven counterexample and causal
closure, preferably the ordinary retained-pointer completion failure. Reuse
the existing TypeFactory owner and retained reviewer; architecture and repairs
remain unselected pending that investigation and authorization.

## Historical whole-diff review and assertion corrections

The review snapshot contains72 tracked files (+5143/-244 lines) and144
untracked entries. Regression sources, real fixtures and harnesses account
for most code additions; a26,116-line generated evidence index accounts for
most untracked text volume. That index is now retained externally, unchanged.
The local Ghidra checkout, LSP configuration, historical JVM crash and
user-owned methodology are distinct from proposed product changes.

All216 entries are accounted for in the disjoint review manifests under
`kuna-reimplementation-evidence/20261007-reassessment/current-diff-review-20261009-091228/`.
One independent critique challenged the owner investigations. Its original
findings and subsequent informed resolutions remain separate evidence;
source review is not runtime acceptance.

All40 original DWARF variant tests pass on pristine `c4f735f9`, including
every removed assertion. The removals were policy-driven, not responses to
variant failures. That conclusion was wrong: the exact suffixes in these
fixtures test the documented deterministic collision policy and name-keyed
layout lookup. Restore the original assertions themselves, not replacements
that merely check distinct names. The later assertion-level audit preserves
the original guards; the user's standard has not changed.

Other restorations preserve canonical pointer/cast/scalar identity,
nonnull/null ExtraPop signals, source type spelling, compiled padding
geometry, full epilogue instruction extents and specific instruction-budget
error causes. Incorrect new premises are corrected separately: same-spelled
typedefs need no extra wrapper, signed Rust bytes retain signed values,
unlocked empty nonvariadic callbacks are closed, unregistered wire IDs are
absent, and mapped non-address-tied retyping preserves width or refuses.
Missing required compilers now fail explicitly instead of returning green.

Focused execution retains genuine failures rather than weakening oracles:
early held-pointer completion, source callback/type import, strict malformed
option parsing, logical aggregate-call operands and unchanged Rust pointer
emission. Actual unmodified Java/native comparison additionally demonstrates
Kuna accepting the known invalid negative instruction limit and returning a
decoding error instead of the instruction-budget cause. These are bounded
observations, not complete transport or family root-cause closure.

The source-carrier discriminator locates the width projection before edits:
machine-only EDI/ESI inputs are4 bytes; initial1-byte source declarations
split them into independent1-byte low and3-byte upper inputs, reconstructed
by ordered PIECE operations. Rename and same-width retype preserve that raw
information. The former monolithic-input assertion incorrectly rejected
this representation; its replacement checks original operand provenance,
including complete byte coverage and significance order. The first edit
case passes; the next original map-then-rename sequence fails because
`fresh` is absent from the selected local scope. Its command sequence remains
unchanged. Readable C still declares uninitialized upper-byte locals, and
the original256-vector dirty-upper-byte O0/O2 consumer remains unrepresented.
Raw provenance is not readable/executable acceptance.

The historical no-layout small-struct-return witness remains paired with
correct layout-enabled arithmetic. The contradictory new off-mode success
oracle is retained in review evidence, with its exact applicability unresolved;
neither a generic port classification nor one passing case approves it.
Original refusal alternatives, authenticated export boundaries, wider
producer/namespace/collision/ABI domains and representative performance
remain explicit in the owner evidence rather than being claimed complete.

The character audit also distinguishes a wrong setup from a valid failure.
`set_core_type("char", 1, TYPE_UINT, true)` does not configure unsigned core
char, so that setup cannot prove loss of unsigned compiler-authored values.
The genuine replacement consumes unchanged C with exact character signatures,
both compiler char modes and both prototype-publication routes. On native
Mach-O, `cppproto off` leaves the loader's underscored FunctionSymbols without
parked source prototypes; the bare-name binder misses them. The address-keyed
on route parks the correct declarations. The off-route signature failures are
retained, not weakened. The exact boundary observation and consumer logs are
in `necessity-review-20261009-154337/character-publication-boundary/` and
`character-consumers-both-routes/` within the reassessment evidence.

## Reviewed-tree failure overview

The fresh complete run is
`current-diff-review-20261009-091228/final-overview-complete/`:23m24s,
52 gates,40 passed,6 failed,2 prerequisite-blocked and4 browser skips.
The extra gate verifies the actual Python CLI-corpus wrapper with its
representative original callback fixture; all four observer-off/on
comparisons are equal. The previous cancelled run and the run whose CLI
helper failed to import `scripts` remain diagnostic evidence only. That
external helper now imports from the explicitly recorded repository path,
and its preflight succeeds with `PYTHONPATH` unset.

| Gate | Final execution |
|---|---|
| Original datatests | 675/675; PARITY OK |
| Current stages | 2208/2208; PARITY OK |
| Original CLI consumers through real GNU time | 280 passed,0 failed, including all244 originals |
| Full Cargo workspace, non-failfast | 8275 passed,161 failed,40 ignored;18 failing targets; all10 crate doctest targets reached |
| Feature-enabled MIPS | 4 passed,0 failed |
| Ghidra simulator with actual canary | 61 passed,0 failed |
| GCC16 DWARF import | 2 passed,8 failed |
| GCC16 unchanged-provider consumers | 1 passed,10 failed,1 ignored |
| Authentic held host datatype | 0 passed,1 failed at initial authored callback; later edits unreached |
| Real Ghidra suites | All19 attempted;0 completed successfully |
| Python tooling | 39 passed,3 failed under Bash3.2 |
| Web/actual WASM consumers | All22 non-browser checks passed;assembly passed;4 browser checks skipped |

Builds, lint, spec anchors, catalog validation/freshness and shared counters
pass. Peak guarded anonymous/wired/compressed RAM is87.18%; every completed
guarded child group is absent. The six failed gates are workspace, Python
tooling, GCC import, GCC consumers, real Ghidra and held host datatypes.
Test failures are not161 independently established production defects.

The original Darwin CI time wrapper remains blocked by its GNU-specific
arguments; the verified GNU-wrapper corpus pass does not pass that original
wrapper. Both installed NoReturn callback producers omit `DW_AT_noreturn`.
Chrome and the genuine C++ oracle are absent. Ignored/skipped/optional
branches and assertions after first failures remain unexecuted.

The51 observed unrepresented admission records remain missing-consumer
obligations, not authenticated refusals or certified defects. Original raw
export boundaries, forbidden carrier edits, dirty-upper-byte execution,
genuine unwind, broader producer/namespace/collision/ABI contracts and
representative performance remain explicit gaps. This completes the
requested diff review and failure overview, not the reimplementation or
test-port acceptance.

`Main-findings.json` in the review directory accounts for all19 independent
critique findings and their corrections, bounded execution or unresolved
consumer extent. The original critique and informed follow-ups remain
separate. `final-overview-complete/failure-overview.json` retains every gate,
failed test name, raw stream and admission-record location. Production
repairs remain deferred; no baseline was re-pinned to absorb a failure.

## Necessity-review corrections

The original HFA identity and deterministic DWARF suffix guards are valid and
restored. The note's deletion and those earlier guard-removal conclusions were
wrong; the user's criterion never changed. The necessity review preserves the
original note and inputs externally, with current per-case decisions and the
single retained critique in `necessity-review-20261009-154337/verdict-navigation.json`.

Runtime exposed test-port prerequisites missed by source review: missing local
space initialization, a moved whitespace helper, deleted-module imports and an
FspecSpace required by deindirection. Their repairs preserve the guards. The
provider-definition recognizer also wrongly rejected legal emitted header
comments and accepted names occurring only in comments or strings; its matching
view now excludes those tokens without changing emitted bytes. Actual unchanged
C consumers then reach compilation or value failures, not that parser refusal.
Correct failing guards remain for the integration work; suite counts are a
failure overview, not justification or product acceptance.

The final assembled-patch review found three further test defects. One added
test assigned call-trial remapping to generic operand mutators instead of the
actual call-finalization owner; its replacement drives `build_input_from_trials`
and checks repeated arguments, operand compaction and distinct physical storage.
Three added carrier tests never invoked transfer, analysis or a source consumer
and were removed. The Rust metadata-compilation test now requires `rustc`; a
missing compiler previously reported success without checking emitted code.
No original assertion was removed. The full critique and subsequent verification
remain separate from the earlier run tables in the existing evidence directory.
