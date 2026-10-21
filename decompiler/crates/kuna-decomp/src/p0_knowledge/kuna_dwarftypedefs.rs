//! (kuna `dwarftypedefs`) Keep the source names of a DWARF declaration's types.
//!
//! The DWARF type mapper looks straight through `DW_TAG_typedef` and the
//! `const`/`volatile`/`restrict` qualifiers, so a prototype that the program
//! source writes `int handle(Flags value)` is recovered as
//! `int handle(unsigned char value)`, and a global the source writes
//! `extern volatile Fn slot` as an untyped data symbol. A consumer compiled
//! against the emitted header then names a type the header never declares, or
//! redeclares the global with a spelling that conflicts with it.
//!
//! With the option on, the mapper keeps the typedef name and the qualifiers on
//! the types of prototype parameters and results, of parameters that carry a
//! frame location, and of top-level data objects (the declaration boundary). Types of
//! locals are unchanged. A data object then reaches the symbol table as a typed
//! symbol instead of a sized, untyped one.
//!
//! ## Why this is an env-var bridge, not an `Architecture` flag
//!
//! The types are baked into the analysis facts by `DwarfPass` at `load file`,
//! which runs **upstream of every `option` command**, so the gate is a process
//! environment variable ([`DWARFTYPEDEFS_ENV`]) the CLI exports ahead of the
//! load, exactly as `calltargettype` does. The companion
//! `Architecture::dwarf_typedefs` bool keeps the option catalog-visible.
//!
//! Default **off** in the catalog (the datatest corpus and the original CLI
//! fixtures pin the looked-through spellings); the Ghidra product gate
//! (`tests/ghidra/run.py`) turns it on for its CLI producers.

/// Environment variable that gates source-name retention in the DWARF type
/// mapper. Absent or any off-token => disabled (the default).
pub const DWARFTYPEDEFS_ENV: &str = "KUNA_DWARFTYPEDEFS";

/// Whether the DWARF mapper keeps typedef names and qualifiers at the
/// declaration boundary for this process.
pub fn dwarf_typedefs_enabled() -> bool {
    crate::options::env_toggle(DWARFTYPEDEFS_ENV, false)
}
