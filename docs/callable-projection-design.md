# Proof-driven callable projection: reviewed design direction

This document preserves the pending callable-body projection design. It is **not an implemented API or production patch approval**. Current observed behavior and blockers are tracked in [the cutover status](datatype-callable-cutover-status.md). Source declarations remain authoritative; execution projections require actual machine/SSA proof and real provider bodies.

## Review gates

The source-relative design direction is agreed, but the exact structural source receipt/fingerprint and canonical recursive graph traversal remain unresolved. Before implementation:

- Canonicalize equivalent projection DAGs independently of node enumeration; raw JSON ordering is not type identity.
- Reject unreachable nodes and duplicate conflicting source paths. Match custom model, exact storage, effects, source ownership and nested callable bindings against the authentic source graph.
- Reuse existing graph traversal, source provenance and invalidation; transport no process-local type/operation/varnode IDs.
- Keep demanded variants separate from verified completed providers. Neither raw recursive reachability nor provisional return-family claims can ground an unresolved result-family cycle.
- Preserve full source/host editing semantics and perform actual per-contract body analysis. Do not replace incompatible invocations with casts, canonical-name aliases, fake wrappers, or declaration shells.

The following proposal snapshots retain the concrete interfaces and tradeoffs reviewed during integration. Names are proposed interfaces, not existing exported contracts. Their remaining design gates override any earlier tentative field choice.

## Durable acceptance

`tests/ghidra/callable/transport.py` builds source fixtures and runs authentic machine checks plus unchanged emitted C at `-O0` and `-O2`. It covers direct/whole-unit mixed-width callbacks in serial/stream/jobs2, volatile native callback globals, returned-pointer identity, finite Big24 direct/PHI providers and omissions, nondefault/nested conventions, and recursive datatype graphs on x86-64/AArch64/Apple targets. Missing dependencies fail; known production failures remain positive assertions, not expected-error repins.

Complete scalar recursion with genuine base cases is a positive executable case (depth 0 through 8). Missing provider publication is a separate negative. No authentic purely ungrounded result-family-cycle fixture has yet been established; ordinary machine recursion must not be mislabeled as that control.

Provider omission requires unsuccessful export and an unavailable required owner. Streaming export may leave incomplete output files on refusal; the tests never consume those files as a successful unit and do not promise atomic filesystem publication. The Apple recursive query-order fixture intentionally has no DWARF so assertions create its authoritative source graph; the ELF source fixtures retain genuine DWARF as separate controls.

The linked mixed-width fixture intentionally replaces donor function bytes while preserving authentic compiler-emitted source DWARF, records every replacement, and separately executes the machine oracle. Other callable fixtures compile their maintained source directly. Neither method changes exported C or supplies handwritten replacement callbacks.

## Rationale and value proofs

```text
PROOF-DRIVEN CALLABLE PROJECTION — DESIGN FOR REVIEW, NOT PATCH APPROVAL

Observed contradiction
normalize_type_depth and family_proto(None) widen every scalar in every callable type without a producer/demand proof. actual_leaf's authentic int(int) body reads only declared int, yet returned_scalar_child returns an int(ulong) adapter. Renaming that adapter actual_leaf fixes one comparison but makes genuine Fn volatile scalar_slot=actual_leaf incompatible. One C function address cannot be called compatibly as both int(int) and int(ulong). Native source identity and genuine transformed-family identity therefore must be separate semantic families, not solved by renaming.

Required invariant
Source Code/FuncProto remains authoritative for editing and native invocation. An execution Code is selected only for a particular actual value/entry contract with a retained proof. Exact unchanged source families preserve the actual source symbol. A transformed generated family has its existing stable target/family symbol and cannot cross a native source family or address-observation boundary. Within each admitted family, every occurrence of an actual target selects the same symbol.

Proposed value proof interface
CallableValueProof { source: TypeRoot, execution: TypeRoot, origin: CallableOrigin, obligations: Vec<BodyObligation> }
CallableOrigin alternatives:
  NativeSource: exact locked source/global/formal declaration used only under native ABI proof; execution==source.
  MappedTarget: exact entry, source Rc<FuncProto>, original raw Rc<EntryRequirements>, optional mapped witness, and exact requested family.
  Formal: owning entry/source generation, source slot, and the owning body's explicit execution contract (never merely inferred Code typedef).
  CallResult: exact producing call sequence and retained callee/indirect-family result contract.
  Merge: same source/execution family and union of genuine producer obligations; no arbitrary Code merging/casting.
COPY and width-preserving CAST carry the proof; finite PHI requires one compatible family. Unsupported loads/arithmetic/escapes remain unproved. Source-typed global loads may be native source values but not generated-family claims.

Owning body projection interface
CallableProjectionPlan { source: Rc<FuncProto>, inputs: Vec<(source_slot, execution_pointer_type)>, output: Option<execution_pointer_type>, obligations: Vec<BodyObligation> }
Only differing entries install existing FuncProto execution input/output projections. The source descriptor, source category-0 storage, source name/type/lock, globals, and host editor remain unchanged. Capture source slot numbering before implicit physical ABI arguments. Plans authenticate full source generation and original raw site inventory. Reflow rebinds exact source/raw premises; source edit, target override, flow change or graph generation change invalidates the plan. No detached Varnode cache; first-epoch SSA values are represented by owning slot or exact call sequence and replayed against actual new SSA.

Producer selection
1. An actual mapped target whose unchanged source prototype covers original positive machine reads, return representation, and preservation may expose that unchanged family and symbol. This is the actual_leaf/native-global case, not an arbitrary native waiver.
2. A genuine positive machine deficit selects an execution family using existing source projection + apply_requirements/SSA requirements. No register-wide requirement is invented merely because an integer is narrow.
3. Finite target PHIs join actual physical family requirements and require every target's real provider for that one compatible family. Source-compatible targets may need a family adapter in a PHI containing a truly wide target; the same source target outside that transformed family remains its native symbol.
4. Returned pointer source/exec family is proved by actual RETURN SSA producers. Direct callers consume a target-owned return-family contract; they do not normalize a return solely because the source result is a function pointer.
5. Factory CALLIND output is derived from its authenticated execution Code and actual factory producer proof. Mere nominal acquisition is insufficient.

Important interprocedural consequence
A function with a callable formal may genuinely be used under both native Fn(int) and a transformed generated Fn(ulong), or a nested Chooser returning either family. One emitted body cannot invoke that formal using both incompatible C pointer types. Such contexts require distinct target-owned execution body contracts, not a type-global choice based on whichever caller decompiles first. A body contract/variant is a real reanalysis of the same mapped machine entry under explicit execution-only callable projections; not a handwritten callee, incompatible cast, native bridge or placeholder. Original source/default body remains native-compatible when that path is representable. Stable family/body ownership keys distinguish the generated contract. Actual direct/callable producers require that contract's provider. A target variant is independently source/raw/SSA validated before publication.

Proposed driver/publication demand seam
BodyObligation needs actual entry + authoritative source identity + structural execution-family descriptors, not only an opaque key. The shared unit/host closure schedules the same real target body with that execution projection plan. Worker transport serializes type graphs using existing authenticated source/projection graph mechanisms; no process-local TypeId or OpId crosses workers. Returned-family receipts travel with the real body contract and remain provisional/deferred until final provider validation. Existing SCC rule remains: ungrounded deferred cycles cannot prove themselves. Unchanged raw-complete cycles remain allowed. Source-independent root-only decompilation may report required generated dependencies; it must not invent provider bodies.

Implementation boundaries
Funcdata retains immutable projection plans and invalidates them with raw/source generations.
Callable transport owns SSA value-family proofs, compatible adapter rendering and body obligations.
Publication schedules real per-contract target bodies across direct/project/stream/jobs/host closure.
No blanket fallback family normalizer remains after cutover; PrintC renders the actual retained execution type, not independently normalizing typedefs again.

Required acceptance (not yet exercised)
- Same genuine Fn volatile scalar_slot image, unchanged header/source declaration and actual source identity, returned_scalar_root(x)==actual_leaf; strict C -O0/-O2 serial/stream/jobs2.
- returned formal Chooser/Fn native-compatible family remains source-compatible; same actual factory/leaf identity.
- Mixed byte/word target PHI, direct and whole-unit invoke/dispatch/choose retain positive upper input bits, stable identity inside transformed family.
- Same target passed through unchanged/native and truly transformed contexts uses separate explicitly compatible family contracts; native escape of a transformed pointer remains refused.
- Actual finite scalar-root PHI with no callable parameters/direct calls uses retained generated target raw authority.
- Big direct/deindirected/finite-PHI retains real hidden memory SSA and actual target providers.
- Source-incomplete physical-only roots and direct site overrides retain machine values; no nominal provider demanded if it cannot cover original positive reads.
- Host rename/retype/flush/reopen invalidates derived plans; source signatures and global object declarations stay exact.
```

## Source-relative contract interfaces

```text
CONCRETE CALLABLE PROJECTION INTERFACES — REVIEW REQUEST

Scope
Contract/value-proof code belongs alongside kuna_callabletransport, with Funcdata lifecycle hooks. Raw SCC/inherited analysis stays separate: no EntryRequirements field receives callable return facts. Publication owns per-contract body scheduling and job transport. Demand materialization uses the existing datatype graph, not a second alias graph/cache.

Transport choice: source-relative projection instructions, not a second type codec
Existing TypeRoot/TypeRef encode emits semantic get_unsized_id/get_id references, but a worker does not already receive the sender's full graph or alias reservation sequence. Replaying arbitrary references into another arena is not justified. Every new execution type needed here is either an unchanged authoritative source root, a source scalar storage carrier created by existing install_input_carrier/physical_only APIs, or a function-pointer type whose nested callable inputs/results are themselves such projections. Therefore transport a finite source-relative projection DAG, not copied datatype definitions or process TypeIds. The receiver first loads the same actual target's authoritative source using its existing loader/host graph decoder, checks the source receipt, and applies the descriptor with existing TypeFactory/FuncProto projection APIs. Struct/union/array/enum/typedef/pointer-space/layout/Code model identities stay in that authenticated source graph. There is no type-name lookup fallback.

Plain wire/in-memory descriptor (all fields immutable after validation)
SourceRootSelector = Prototype | Input(u32) | Output
TypePathStep = Pointee | CodeInput(u32) | CodeOutput
SourceTypePath { root: SourceRootSelector, steps: Vec<TypePathStep> }
- Input/Output at the outer target are declared source coordinates, not physical CALL operand indexes.
- Alias traversal uses the existing graph's resolve_alias without dropping the original alias root.
- Prototype selects the actual source FuncProto including custom storage/model/effects, not a guessed default ABI.
- Nested Code paths select a concrete source pointer/Code graph node in that same declaration.

StoragePiece { space_index: i32, byte_offset: u64, byte_size: i32 }
- Receiver resolves space_index in the current authenticated architecture and checks space kind/address width/range; JOIN descriptions are expanded to real pieces for identity and must re-materialize through the existing manager.
ScalarCarrier { declared_slot: u32, storage: StoragePiece }
PhysicalOnlyCarrier { storage: StoragePiece }
CallableInputProjection { declared_slot: u32, family_node: u32 }
CallableProjectionNode {
  source: SourceTypePath,
  scalar_inputs: Vec<ScalarCarrier>,
  physical_only: Vec<PhysicalOnlyCarrier>,
  callable_inputs: Vec<CallableInputProjection>,
  callable_output: Option<u32>
}
CallableBodyDemand {
  entry: Address-on-wire(full space/index + byte offset),
  source_receipt: SourceCallableReceipt,
  nodes: Vec<CallableProjectionNode>,
  root_node: u32
}
- Node indexes are dense message-local DAG references only, never arena TypeIds/model IDs/OpIds/VarnodeIds.
- Empty root projection denotes the unchanged source callable contract; scalar entry carriers still derive independently from original machine requirements in the body analysis.
- A requested projection is a demand, not a proof: no raw complete/restored/reads/effects flags are transported as authority. Receiver re-probes/reanalyzes actual mapped bytes.
- Scalar carrier shape has no arbitrary new type metadata: existing unsigned execution carrier construction supplies the type. Source values are recovered using exact source descriptor and byte projection. Nested callables are recreated through existing callable materialization/model binding.
- Hidden result origins remain assigned from the source ABI; cannot be invented by a descriptor. Logical result family uses its existing owned layout/memory proof.

SourceCallableReceipt
Reuse request/source provenance rather than invent global mutable generations:
  authoritative entry + existing worker TargetSpec provenance/binding or authenticated host function source identity;
  exact source FuncProto ABI/effect/storage snapshot fingerprint;
  retained source graph roots and existing host source program/revision/scope/binding receipts locally.
For wire equality the source fingerprint must include complete structural shape, exact storage/order/flags/model semantics, aliases/source identities and nested Code binding, not process-local indexes. Source names alone never resolve a demand. Host mutation invalidates the existing source receipts/dependency tombstones; fresh source decode is mandatory. CLI workers independently load the same image/debug/override context and compare the descriptor with that authoritative source. A demand carrying an unavailable/stale/mismatched source fails, it is not reconstructed from type names.

Locally retained verified contract
CallableBodyContract {
  demand: Rc<CallableBodyDemand>,
  source: Rc<FuncProto>,
  execution: Rc<FuncProto>,
  source_roots: Vec<TypeRoot>,
  execution_roots: Vec<TypeRoot>
}
Only `materialize_body_contract(fd_or_context, demand)` constructs this after source receipt validation and materializing the projection DAG. The existing graph owns roots/lifetimes and derived AbiView invalidation. No second alias store.

Actual proof/certificate, distinct from demand and original raw requirements
CallableBodyProof {
  contract: Rc<CallableBodyContract>,
  original_raw: Rc<EntryRequirements>,
  mapped: Rc<MappedBodyWitness>,
  returned: Option<CallableValueContract>,
  dependencies: Vec<CallableBodyDemand>,
  final_source_receipt: SourceCallableReceipt
}
CallableValueContract includes source root, execution root, complete physical family identity/model/storage/result and one of:
  unchanged source/native ABI;
  exact mapped target/body-demand set;
  exact owning formal source slot + owning body contract;
  exact producing CALL/CALLIND sequence + producer body/result contract;
  finite compatible merge of the foregoing.
A returned contract is captured from all actual reachable RETURN SSA value producers, not type equality alone. Final provider replays actual same-family producers and source/raw identity. A provisional returned contract is an explicit body obligation and cannot ground its own deferred SCC.

Funcdata state/hooks (CallableTransport edits disjoint field/accessor/clear blocks)
  callable_body_contract: Option<Rc<CallableBodyContract>>
  callable_body_proof: Option<Rc<CallableBodyProof>>
  callable_value_contracts: BTreeMap<OpId, Rc<CallableValueContract>> (only current-IR producers)
  callable_body_demands: Vec<Rc<CallableBodyDemand>>
  callable_body_contract()/set_callable_body_contract(...)
  callable_body_proof()/set_callable_body_proof(...)
  callable_body_demands()
clear_source_input_projections clears every current-IR proof/demand and contract just like native/generated/deferred maps. The driver retains the immutable requested demand separately across a reflow, then materializes/rebinds it against fresh source/raw facts. Source editing/host request reset drops that driver seed. No cached VarnodeIds cross epochs.

Driver hooks
1. Existing decompile drive entry request gains `Option<Rc<CallableBodyDemand>>` as execution-only context, separate from pending source prototypes and call-site Overrides. The scheduler routes default root demand None and explicit derived body demands without changing authoritative declarations.
2. After authoritative source and raw CFG capture, `bind_body_contract(fd, demand)` checks source receipt and installs only approved execution input/output projections through existing FuncProto APIs before heritage. Raw requirements are unchanged.
3. Existing refine_execution checkpoint runs `infer_callable_contracts(fd)` on actual first-epoch SSA. It records exact call sequence/own source-slot descriptors, body demands and returned proofs. Pure source/native values retain source types; generated decisions require actual producer/demand proofs.
4. Reflow rebinds these records using existing RawNativeSite/raw fingerprint/source equality machinery, no new function-global alias table. Only changed execution projections trigger reanalysis. Bounded unresolved cycles remain explicit refusal, not a guessed type.
5. Final `validate_callable_body(fd)` replays every execution contract against final actual SSA and produces CallableBodyProof. Export artifacts reference actual body contract owners and required dependency demands. The default native body and a requested generated body are distinct genuine analyses when necessary.

Publication/scheduler interface
Decompile result contains `callable_demands: Vec<CallableBodyDemand>` and optional `callable_body_contract_key`, alongside existing artifacts/body error.
The scheduler resolves each demand to its actual target entry and runs the same full body driver under that execution-only demand. Dedup key is source receipt + canonical projection DAG, not entry alone; requested-but-unavailable variants cause publication error. A generated provider is a real decompiled body (or existing validated compatible adapter), never a declaration shell. Current source function's host signature/localdb remains source-owned; only execution variants contribute C publication definitions.
Existing shared publication SCC rules apply to contract keys. Concrete raw-complete owned bodies may anchor valid cycles; a cycle made solely of deferred variant/result requests cannot discharge itself. Worker jobs carry the small projection descriptor in target specifications and results; decode/materialization still uses the real target source graph. Host closure schedules the same demands request-locally through its existing complete-source/decompile helper.

Cutover consumers
normalize_entry/normalize_call/prepare_direct/prepare_indirect install explicit contract projections only; delete blanket callable scalar widening from normalize_type_depth. Keep scalar physical input proof mechanism unchanged. normalized_family becomes proof-driven value-family query covering unchanged native/source producers too. Pointer naming uses actual source symbol only for unchanged source family, stable generated family key otherwise. PrintC renders actual retained execution SSA types and never runs an independent nominal normalizer. Required/provider wrappers and body ownership use the exact requested family/body contract. Native imports/global objects retain their source ABI/qualifiers.

Remaining exact design gate
DAG recursion and source receipt structural fingerprint must reuse existing graph traversal/source ownership checks; the descriptor cannot claim a source anchor not present in the authentic target's source graph. All imported custom ABI, default/nondefault CC, aliases, hidden origins and nested callback cases must round-trip before production application. Descriptor/source-receipt fields remain unresolved.
```

## Body scheduling seam

```text
CALLABLE BODY CONTRACT SCHEDULING SEAM — REVIEW ADDENDUM

A returned-family certificate is needed while analyzing its caller, not merely when concatenating C. Current raw summary() only follows the target's raw CFG; it cannot invent a final SSA result-family certificate. Do not add that certificate to EntryRequirements or infer it from the declared output TypeRoot.

Use explicit dependency/worklist outcomes rather than recursively re-entering the global action loop or fabricating provisional code:

CallableBodyRequest {
  entry + authenticated existing source context,
  projection: Option<CallableBodyDemand>
}
- None means infer the default executable body from authentic source + actual machine/SSA proofs. It does NOT mean blindly normalize callable types.
- Some(empty projection node) explicitly demands the unchanged source callable context. It fails if the actual machine body cannot represent that context.
- Some(nonempty projection DAG) demands the corresponding generated callable context; scalar physical input coverage remains proved from actual raw facts.

CallableBodyAnalysisOutcome =
  Complete { real decompile result, verified CallableBodyProof }
  NeedsBodies { dependencies: Vec<CallableBodyRequest> }
  Refused { exact semantic/source/provenance failure }

NeedsBodies is internal orchestration, never successful public C and never a stub/provider. The scheduler obtains actual bodies through the same complete target-source setup and full decompile driver already used by each frontend, then reruns the waiting body with those verified facts. Source declarations/overrides/comments/locals/tracked state must all use the existing real source helper, especially host requests. No nested borrowing of a running global action root or mutable resolver callback is required.

Request-local CallableBodyFacts is keyed by source receipt + execution projection DAG. It holds only verified complete body/result contracts and original source/raw identity, not mutable type aliases. Each worker invocation receives the exact resolved dependency contract descriptors/receipts it needs and authenticates them against the same source context. Receiving a demand is not receiving a proof; a worker still requires the actual target's completed provider from the scheduler before caller publication. The host scheduler stays request-local and source edit/flush drops this facts set together with existing graph/source receipts.

The caller's default analysis may discover a new returned projection (e.g. choose returning one of real byte/word targets needs a generated common family). That verified output projection becomes part of the inferred body's contract key and its returned receipt. A default native-compatible factory returning actual_leaf retains Fn(int), original symbol identity and source global compatibility. Explicit generated factory variants can have another output family only when their actual producer set/body proof realizes it; never cast a native result into that family.

Cyclic dependencies
Use the existing shared deferred SCC/body-obligation rules and the newly reviewed recursive raw summary machinery. A request for the same unresolved contract may retain an explicit deferred obligation but is not accepted as a completed result-family proof. A source/raw-complete unchanged recursive group may be closed jointly by the existing grounded solver. A group whose callable-result/family claims depend solely on itself remains refused. Do not mark a body complete just to make this worklist progress.

State ownership
Funcdata retains only the current body's execution-only contract/proofs. The scheduler owns dependency outcomes and job transport; it does not mutate authoritative prototype caches. Original raw facts and conditional analysis remain separate from callable projection proofs.
```
