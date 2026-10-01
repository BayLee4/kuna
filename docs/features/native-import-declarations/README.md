# Native import declaration drafts

These patches are **unapplied and untested**. They address source-C declarations
for genuine imported functions; they do not yet solve mapped linkage proof.

## Problem

Ghidra retains `int _printf(char *, ...)` and `int _scanf(char *, ...)`, while
Darwin's SDK requires `const char *`. Literal emission conflicts with the real
headers. Native import provenance alone cannot certify mapped stub instructions
or make incompatible function-pointer types interchangeable.

`tests/ghidra/callable/native_import_provenance.py` builds and executes a real
SDK/libc caller, then records normal Ghidra import metadata. The Darwin run found
`/usr/lib/libSystem.B.dylib`, imported `_printf`/`_scanf`, format storage `x0:8`,
result `w0:4`, and caller branches to initialized RAM linkage thunks. The linked
program's printf/scanf behavior passed. The Linux importer path is unverified.
No provider was assigned manually.

See [the live-test setup](../../../tests/ghidra/README.md#callable-consumer-and-import-regressions)
and [overall cutover failures](../../datatype-callable-cutover-status.md).

## Drafts and dependencies

- `canonical-native-import-design-v1.txt`: authority and declaration design.
- `canonical-native-import-core-v2.patch`: immutable import receipts and canonical
  C descriptors without changing source Function/HighFunction types.
- `canonical-native-import-producer-v1.patch`: actual host ExternalLocation facts
  transmitted through attributes 4050–4053.
- `canonical-native-import-cli-loader-v1.patch`: Mach-O ordinals, PE descriptor
  identities and ELF symbol-version provider requirements. DT_NEEDED alone is not
  enough to bind an individual import.
- `native-library-fixture-v1.patch`: replaces synthetic UNKNOWN-library consumers
  with genuine imported SDK/libc callers, using actual exported providers.

The core and loader share `NativeImportIdentity` and address-keyed receipt maps.
Apply them only as a coherent change after rebasing and resolving the requirements
below. No current production code depends on these patches.

## Unresolved requirements

1. A canonical declaration requires exact provider/symbol/ABI evidence. Names alone
   are insufficient; Mach-O underscore removal must follow an authenticated binding.
2. Real stub targets require linkage proof or a closed emitted provider. An
   ExternalLocation or thunk flag must not waive arbitrary mapped-body effects.
3. `int(const char *, ...)` must not escape as `int(char *, ...)` through a cast
   or fabricated adapter. The draft refuses such values without a valid projection.
4. Direct and whole-unit publication must compile unchanged against actual SDK/libc
   headers and execute the original call behavior. Cover edits, renamed/unknown/
   retargeted imports and pointer escapes.
5. Linux must establish actual resolved provider metadata through Ghidra's loader
   and resolver. Unknown providers and missing prerequisites fail rather than skip.
6. The fixture must use emitted string/data ownership; injecting replacement globals
   would hide a separate publication defect.
