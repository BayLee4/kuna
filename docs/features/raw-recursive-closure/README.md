# Raw recursive closure draft

These patches are **unapplied and untested**. Recursive callable publication
remains unresolved.

`solver.patch` implements component analysis; `driver.patch` integrates discovery
and installation. `solver-copy-scan-followup.patch` corrects the solver's COPY
iteration and must accompany it.

`interface.txt` preserves the original design discussion. The final reviewed
solver adds explicit, transitively grounded `has_normal_return` evidence:
completeness alone is not a finite-return witness. A complete external child
without a grounded normal return stops its continuation; it does not become an
empty returning function. Default and unresolved summaries have no such witness.

## Integration contract

The driver calls:

```rust
pub(crate) fn analyze_raw_recursive_component(
    members: &[&Funcdata],
    external: &BTreeMap<Address, Rc<EntryRequirements>>,
) -> KunaResult<Option<Vec<EntryRequirements>>>
```

Members are genuine lifted bodies,
and returned summaries have exactly the member order. `None` leaves the
original cuts unresolved. Only final complete, grounded raw summaries leave the
solver; private iteration snapshots never become provisional complete
`EntryRequirements` or generated/deferred execution assumptions.

The owner is its actual raw `Funcdata`, including request-local overrides.
Settled SSA is never substituted for raw input. Discovery retains only genuine
mapped incomplete probes implicated by an active recursion cut, within the
existing probe limit. Components close leaves-first; affected acyclic ancestors
are recomputed afterward. Exact raw `Rc` values and mapped witnesses are staged
before installation, and callsites are bound after closure. Each reflow clears
all component evidence. No new publication wire category or deferred-cycle
exception is introduced.

The solver reuses raw byte-access and restoration transfers. Memory effects stay
conservative: recursion does not grant a private-frame premise or an invented
saved-stack footprint. Final bookkeeping uses actual closed child reads, not a
temporary empty demand set.

## Prerequisites before application

1. Triage the existing production parity failures without repinning baselines.
2. Reconcile these exact patches with any intervening return-bookkeeping helper
   changes. The solver was reviewed against the installed COPY-only return
   bookkeeping helper; later MIPS tagged-return work is not included here.
   The separate `solver-copy-scan-followup.patch` is required: `iter_code(COPY)`
   has no dedicated opcode list and yields no operations. The correction uses
   the actual operation bank with an explicit COPY guard.
   Diagnostic removal also changes surrounding source contexts; rebase and
   review the pair before application instead of blindly applying stale hunks.
3. Apply the solver and driver together. The driver requires the new solver API
   and `has_normal_return` field; neither patch is a standalone production fix.
4. Build and execute the acceptance paths below. Record actual outputs rather
   than treating successful source review or historical raw-C execution as proof.

## Required acceptance

- Existing `tests/datatests/inline.xml` bytes, original `collatz`/`collatz1`
  declarations and inline settings: actual residual self-CALL, complete grounded
  raw closure, successful native callable publication, and unchanged generated C
  executed at `-O0` and `-O2` for the existing inputs. Preserve owner overrides.
- Genuine mutually recursive bodies with real base-return paths, not merely a
  self-only special case. Include their actual generated providers in export.
- Unknown external/member calls, unimplemented or artificial-halt flow, absent
  grounded normal returns, and missing required providers must not gain a fake
  complete body or an export waiver.
- A complete non-returning external child followed syntactically by RETURN must
  not seed a returning component through that unreachable continuation.
- Preserve acyclic raw effects, readonly conditional receipts, internal-role
  inheritance, native/generated families, and same-process reflow invalidation.

Fixture sources and maintained live regressions belong under
`tests/ghidra/callable/`; generated binaries and execution reports belong in the
runner's unique output directory. No production or test source may include a
file from an ignored `target/` path.
