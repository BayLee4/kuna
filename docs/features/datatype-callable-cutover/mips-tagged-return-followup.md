# MIPS tagged return bookkeeping: unresolved

This is an unimplemented design direction, not a verified extension.

## Observed production failure

The authentic version-4 MIPS machine fixtures execute correctly in all four
maintained oracle scopes. The natural `dirty_gp_natural` body is raw-complete,
has `execution=None`, and its owning GP representation proof and unchanged
emitted C at `-O0`/`-O2` pass. Its real GP write is not raw restoration.

Both `direct_gp_parent` and `direct_gp_natural_parent` remain blocked. The actual
engine diagnostic captured before cleanup shows the GP inheritance inventory
present at the genuine call, followed by `raw_direct_contract` rejecting
`family-read-coverage`. Child raw bookkeeping contains SP but not RA. The
positive RA machine read remains present. The original child additionally has
the genuine incidental V0 read produced by the installed ISA-mode fixup; the
natural child does not need a conditional execution view.

The relevant actual JR p-code is not a full-width COPY chain:

- `RA & 1` feeds `INT_NOTEQUAL` and the `ISAModeSwitch` register.
- A real constant `-2` is ANDed with RA, then copied to PC.
- The actual `RETURN` names PC.

These operations come from `JXWritePC` in
`specs/Ghidra/Processors/MIPS/data/languages/mips.sinc` and the installed
`setISAMode` callother fixup. The complete raw dump was captured during the live
investigation; the checked-in assembly and maintained real-machine oracle are
under `tests/ghidra/callable/`.

## Distinct corrected COPY issue

The earlier return-candidate scan used `PcodeOpBank::iter_code(COPY)`, but COPY
has no dedicated opcode list. The production checkpoint now scans actual
operations and explicitly selects COPY. This is a separate mechanical correction;
it does not prove the MIPS AND/tag path. The RV64 regression fixture exercises
COPY-use safety with an authentic compressed return. It does not regress reverse
COPY candidate discovery or tagged-return masking.

## Possible extension, not source-approved

The actual MIPS compiler specification declares `<funcptr align="2"/>`.
`ArchContext::funcptr_align` therefore supplies one authoritative low pointer-tag
bit. A future proof could distinguish canonical return-address projection from
low-tag calculations:

- Permit only the declared low-bit canonicalizing mask on the actual return
  target chain. Arbitrary RA arithmetic or clearing higher address bits must
  remain refused.
- Any tag-only calculation would need a genuine closed-use proof. An unused
  temporary or processor-state result cannot be assumed harmless merely from
  its register name. Source/model result aliases, preserved or global state,
  STOREs, branches, implicit callee reads, partial aliases and escaped values
  remain observable boundaries.
- Retain the positive raw RA read and exact target-owned body obligations. Do
  not turn `execution=None` into a manufactured complete conditional summary.

This direction needs source review and new genuine boundary controls before any
implementation. The existing live parent admission expectations remain positive
requirements and fail until the actual gap is solved. They are not marked as
expected failures or converted into successful negative controls.
