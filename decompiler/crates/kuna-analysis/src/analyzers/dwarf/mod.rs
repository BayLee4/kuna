//! DWARF debug-info names + types — the kuna analog of Ghidra's `DWARFAnalyzer`
//! ("DWARF").
//!
//! When a binary carries `.debug_*` sections, the compiler has already recorded
//! the source-level function names, parameter names, and *types*. Ghidra's
//! `DWARFAnalyzer` reads them and installs them onto the program, so a stripped
//! (no `.symtab`) but `-g` binary still decompiles to `add_values(int a,int b)`
//! instead of `FUN_00401136(undefined8,undefined8)`, and a typed parameter like
//! `char *binary` renders instead of `undefined8`/`long`.
//!
//! This pass reproduces the same two recoveries against kuna's symbol + type
//! tables:
//!   * **subtask 1 (names + globals)** — each *defined* `DW_TAG_subprogram`
//!     (one with `DW_AT_low_pc`) emits a [`SymFact`]`{Function}` at its entry
//!     VMA; each top-level `DW_TAG_variable` with a `DW_OP_addr` location emits
//!     a [`SymFact`]`{Data}`.
//!   * **subtask 2 (typed signatures)** — each defined subprogram also emits a
//!     [`PrototypePieces`] built from its return-type DIE + `DW_TAG_formal_parameter`
//!     children, mapping each DWARF type DIE to a kuna [`Datatype`] via the
//!     architecture's [`TypeFactory`].
//!   * **subtask 3 (named, typed stack locals)** — each defined subprogram's
//!     direct `DW_TAG_variable`/`DW_TAG_formal_parameter` children that carry a
//!     single `DW_OP_fbreg` (frame-base-relative) stack location emit a
//!     [`crate::pass::LocalFact`] at stack offset `call_frame_cfa + fbreg`, typed
//!     by the same DIE→[`Datatype`] mapper. The commit re-seeds each into the
//!     function's `ScopeLocal` (the `map addr`/`seed_mapped_symbols` path) so the
//!     decompiler renders `FILE *file` instead of `local_18`.
//!
//! ## Origin (upstream Ghidra, the tree kuna was ported from)
//!
//! - Driver: `Ghidra/Features/Base/.../analysis/DWARFAnalyzer.java` (`added()`,
//!   builds DWARFProgram + runs `DWARFImporter.performImport`).
//! - `DWARFFunctionImporter.java` — the DIE iteration + commit loop:
//!   `importFunctions()` (switches on DIE tag), `processSubprogram()`
//!   (fn name/addr/params), `outputGlobal()` (global vars).
//! - `DWARFFunction.java` — `read(DIEAggregate)`: name, body ranges (the
//!   `getFuncBodyRanges` non-empty guard => skip declaration-only),
//!   `DW_AT_external`/`DW_AT_noreturn`, retval (`getDataTypeForVariable`), and
//!   the `getFunctionParamList()` loop building param `DWARFVariable`s. `address`
//!   = `getCodeAddress(dwarfBody.getFirstAddress())` (the entry VMA).
//! - `DWARFDataTypeImporter.java` — `getDataType(DIEAggregate)`, the recursive
//!   tag switch ([`build_datatype`] reproduces it): `makeDataTypeForPointer`,
//!   base_type, struct/union/array/typedef/const/volatile, plus the
//!   `trackRecursion` cycle guard ([`kuna_typedepth`]) that survives type cycles.
//!
//! ## Dependency-substitution LOSS
//!
//! Ghidra hand-rolls a complete DWARF reader in `ghidra.app.util.bin.format.dwarf.*`
//! (DWARFProgram, DebugInfoEntry, DIEAggregate, DWARFAbbreviation, StringTable).
//! kuna substitutes [`gimli`], the de-facto Rust DWARF reader, for that parser
//! *wholesale* — the same dependency-substitution LOSS as BFD -> `object` (see
//! `loadimage_object.rs` / docs/rust-port/losses.md). We use gimli's high-level
//! `Dwarf::attr_string` / `attr_address` accessors (NOT raw form decode), so the
//! DWARF-5 `strx`/`addrx`/`.debug_str_offsets` indirections resolve correctly.
//!
//! ## Scope / faithful losses (DOC)
//!
//! - **subtask 3 (stack-local `ScopeLocal` map) is now DONE.** Each defined
//!   subprogram's direct `DW_OP_fbreg` `DW_TAG_variable`/`DW_TAG_formal_parameter`
//!   children emit a [`crate::pass::LocalFact`]; the commit re-seeds each as a
//!   typelock|namelock stack symbol in the function's `ScopeLocal` (the proven
//!   `map addr`/`seed_mapped_symbols` path — no shared-engine-path change). The
//!   `DW_OP_fbreg`→stack-offset conversion applies the per-arch `call_frame_cfa`
//!   constant ([`call_frame_cfa`], faithful to Ghidra's per-language `.dwarf`
//!   `<call_frame_cfa>`). LOSS: only **direct** children (a lexical-block- or
//!   inlined-subroutine-nested local is skipped, the same listing-cosmetic scope as
//!   the labels/call-sites below), and only the **single-`DW_OP_fbreg`** location
//!   form (a composite/register/multi-op location is left to the engine).
//! - We skip `DW_TAG_label`, `DW_TAG_call_site`, inlined-subroutine, lexical-block
//!   comments, and source-info/plate comments — all listing cosmetics with zero
//!   decompiler-output payoff (the same scope as the strings/demangle losses).
//! - **Aggregate layout is now imported** (`dwarfstructs`, [`kuna_dwarfstructs`]):
//!   a `DW_TAG_structure_type`/`union_type`/`class_type` carries its
//!   `DW_AT_byte_size` and its `DW_TAG_member` children (offsets verbatim,
//!   bitfields included) onto the interned type. With the gate OFF it maps to a
//!   *named opaque* struct (enough to render `struct foo *`) exactly as before.
//! - **Discriminated unions are now imported too** (`dwarfvariants`,
//!   [`kuna_dwarfvariants`]): a `DW_TAG_structure_type` carrying a
//!   `DW_TAG_variant_part` — a Rust tagged enum, which has no `DW_TAG_member` of
//!   its own — recovers its `DW_AT_discr` discriminant, each `DW_TAG_variant`'s
//!   `DW_AT_discr_value`, and each variant's payload. LOSS: the overlay is a
//!   UNION, whose members select themselves by offset with no reference to the
//!   discriminant, so a variant NAME is installed only where exactly one variant
//!   claims those bytes (`Option`'s `Some`); where two do — every `Result` — the
//!   payload is spelled `field_0x<offset>`, the same rendering the gate off
//!   gives. The arm EXTENDS
//!   `dwarfstructs` and is gated on it as well as on its own flag; with either
//!   off a Rust enum recovers its width and no fields. Needs FULL debug info
//!   (`-C debuginfo=2`): a binary whose DWARF carries no type DIEs gains nothing.
//!
//! ## PIE / load-bias limitation
//!
//! kuna's loader treats a DWARF `DW_AT_low_pc` as the runtime VMA verbatim (true
//! for the vendored PIE `cet_pie_x86_64`: its DWARF low_pc 0x1357 equals the
//! `.symtab` address). A target with a nonzero load bias would need a base
//! adjustment (Ghidra's `DWARFProgram.getCodeAddress` applies the program
//! image-base); that is a known limitation, asserted against the fixture below.
//!
//! ## Precedence vs `protos` (libproto)
//!
//! cet_pie's DWARF also *declares* external fns (`fprintf`/`fopen`/`malloc`,
//! declaration-only, no low_pc) — this pass SKIPS those so it never fights
//! libproto for the same imports. The pass is registered AFTER `LibProtoPass` in
//! `passes.rs::default_passes()` so that for any name both emit, the DWARF
//! (real source) prototype wins (last-write in `set_function_prototype_pieces`).

use std::collections::BTreeMap;

use object::{Object, ObjectSection};

use kuna_base::types::uint4;
use kuna_decomp::dtype::{type_metatype, Datatype, DatatypeKind, TypeFactory, TypeRoot};
use kuna_decomp::fspec::{func_proto_flags, LogicalCallable, PrototypePieces};

use crate::pass::{AnalysisCtx, AnalysisOutput, AnalysisPass, Phase, SymFact, SymKind};

/// The `.debug_line` source-line side of the DWARF analyzer (`DwarfLinesPass`,
/// the kuna analog of `DWARFLineInfoCommentScript`). Separate pass + gate
/// (`dwarf_lines`, default-off) from the names/types pass below.
mod lines;
pub use lines::DwarfLinesPass;

/// (kuna `cppproto`) The C++ arm — `DW_AT_specification`/`DW_AT_abstract_origin`
/// resolution, namespace/class name qualification, and address-keyed prototype
/// binding. See [`kuna_cppproto`].
mod kuna_cppproto;

/// (kuna `typedepth`) The type mapper's recursion guard — upstream's per-DIE
/// cycle counter in place of a fixed hop budget. See [`kuna_typedepth`].
mod kuna_typedepth;
use kuna_typedepth::TypeWalk;

/// (kuna `dwarfstructs`) The aggregate-LAYOUT arm — `DW_AT_byte_size` plus the
/// `DW_TAG_member` children, installed on the interned struct/union instead of
/// leaving it a zero-size shell. See [`kuna_dwarfstructs`].
mod kuna_dwarfstructs;

/// (kuna `dwarfvariants`) The DISCRIMINATED-UNION arm — `DW_TAG_variant_part` /
/// `DW_AT_discr` / `DW_TAG_variant`, i.e. the layout a Rust tagged enum keeps
/// there instead of in `DW_TAG_member` children. See [`kuna_dwarfvariants`].
mod kuna_dwarfvariants;

/// gimli's section reader: a byte slice tagged with the run-time endianness.
type Reader<'a> = gimli::EndianSlice<'a, gimli::RunTimeEndian>;

/// Resolve a gimli [`SectionId`](gimli::SectionId) to its (uncompressed) bytes in
/// `file`, picking the right section name **per object format** — the one piece of
/// container coupling in this otherwise format-neutral pass.
///
/// gimli ids are ELF-flavoured (`SectionId::name()` → `.debug_info`). `object`'s
/// `section_by_name` already maps that to each format's real name (documented in
/// `object::read::traits` — ELF `.debug_info`, Mach-O `__debug_info` in the
/// `__DWARF` segment, with `.debug_str_offsets`→`__debug_str_offs`; PE/COFF keep
/// the `.debug_*` names that MinGW emits), so a single `section_by_name(id.name())`
/// covers ELF, Mach-O **and** MinGW-PE. We add an explicit Mach-O `__`-prefixed
/// fallback (`.debug_info`→`__debug_info`) purely as a belt-and-suspenders guard
/// for any `object` version whose auto-mapping misses an id — it is a no-op when
/// the primary lookup already hit. `None` => the format has no such section.
fn dwarf_section_data(file: &object::File, id: gimli::SectionId) -> Option<Vec<u8>> {
    if let Some(sec) = file.section_by_name(id.name()) {
        return sec.uncompressed_data().map(|d| d.into_owned()).ok();
    }
    // Mach-O `__DWARF` segment short-names: `.debug_info` → `__debug_info`.
    if file.format() == object::BinaryFormat::MachO {
        let macho_name = format!("__{}", id.name().trim_start_matches('.'));
        if let Some(sec) = file.section_by_name(&macho_name) {
            return sec.uncompressed_data().map(|d| d.into_owned()).ok();
        }
    }
    None
}

/// The per-architecture **static `call_frame_cfa` offset** — the constant that
/// turns a `DW_AT_frame_base = DW_OP_call_frame_cfa` expression into a concrete
/// stack offset (`DWARFExpressionEvaluator` pushes a stack varnode at this value
/// for `DW_OP_call_frame_cfa`, then `DW_OP_fbreg` adds the per-variable offset, so
/// `stack_offset = call_frame_cfa + fbreg`). Ghidra reads it per-language from the
/// processor's `<arch>.dwarf` `<call_frame_cfa value="N"/>` element
/// (`DWARFRegisterMappings.getCallFrameCFA`); this is the faithful subset for the
/// ELF architectures kuna can produce here, transcribed from those files:
///
/// - x86-64 (`x86-64.dwarf`): 8 — push of return addr below the entry-SP CFA.
/// - x86 32-bit (`x86.dwarf`): 4.
/// - AArch64/ARM/SPARC/PowerPC: 0 — frame-base already at the CFA, no SP-adjust.
/// - RISC-V 64 (`riscv64.dwarf`): 8.
///
/// `None` for any architecture whose constant kuna does not vend; the DWARF
/// stack-local recovery then SKIPS `DW_OP_fbreg` locals for that target (additive,
/// faithful — we never guess a frame offset we can't ground in upstream's table).
fn call_frame_cfa(arch: object::Architecture) -> Option<i64> {
    use object::Architecture as A;
    match arch {
        A::X86_64 | A::X86_64_X32 => Some(8),
        A::I386 => Some(4),
        A::Aarch64 | A::Arm | A::Sparc64 | A::PowerPc | A::PowerPc64 => Some(0),
        A::Riscv64 => Some(8),
        _ => None,
    }
}

/// Port of `DWARFAnalyzer`: install DWARF function/global names and typed
/// function signatures from the program's `.debug_*` sections.
pub struct DwarfPass;

/// A flattened snapshot of one DIE's attributes (the subset this pass reads).
///
/// We snapshot the whole compilation unit into an offset-keyed map up front
/// because the type mapper resolves arbitrary `DW_AT_type` references by offset
/// while a separate DFS pass walks subprograms — gimli's cursor only streams
/// forward, so a snapshot is the clean way to random-access type DIEs.
#[derive(Clone)]
struct DieSnap {
    /// The DIE tag (`DW_TAG_*`).
    tag: gimli::DwTag,
    /// Absolute `.debug_info` offset, including the compilation unit's offset.
    /// Synthetic test trees use their unit-local map key instead.
    source_id: Option<u64>,
    /// `DW_AT_name`, resolved through `.debug_str`/`.debug_line_str` (may be empty).
    name: String,
    /// `DW_AT_low_pc` resolved to a VMA, if present (marks a *defined* function).
    low_pc: Option<u64>,
    /// `DW_AT_type` reference (the offset of the referenced type DIE in this unit).
    type_ref: Option<usize>,
    /// `DW_AT_byte_size` (base_type/pointer/struct sizing; on a `DW_TAG_member`
    /// it is the DWARF 2/3 bitfield CONTAINER width).
    byte_size: Option<u64>,
    /// (kuna `dwarfstructs`) `DW_AT_data_member_location` — a `DW_TAG_member`'s
    /// byte offset within its aggregate, taken verbatim. `None` for a member with
    /// no location (a C++ `static` data member, which is not part of the layout).
    data_member_location: Option<i64>,
    /// (kuna `dwarfstructs`) `DW_AT_bit_size` — a bitfield member's width in bits.
    bit_size: Option<u64>,
    /// (kuna `dwarfstructs`) `DW_AT_bit_offset` — the DWARF 2/3 bitfield spelling:
    /// bits from the MOST significant bit of the container named by
    /// `DW_AT_byte_size`.
    bit_offset: Option<u64>,
    /// (kuna `dwarfstructs`) `DW_AT_data_bit_offset` — the DWARF 4/5 bitfield
    /// spelling: bits from the start of the aggregate.
    data_bit_offset: Option<u64>,
    /// (kuna `dwarfstructs`) `DW_AT_alignment`, when the producer states it.
    alignment: Option<u64>,
    /// (kuna `dwarfvariants`) `DW_AT_discr` on a `DW_TAG_variant_part` — the
    /// unit offset of the `DW_TAG_member` that IS the discriminant.
    discr_ref: Option<usize>,
    /// (kuna `dwarfvariants`) `DW_AT_discr_value` on a `DW_TAG_variant` — the
    /// discriminant value that selects it. `None` on a variant that carries none
    /// marks the DEFAULT (niche / untagged) variant, which is a fact, not a gap.
    discr_value: Option<i64>,
    /// `DW_AT_encoding` (`DW_ATE_*`) for `DW_TAG_base_type`.
    encoding: Option<gimli::DwAte>,
    /// `DW_AT_count`/`DW_AT_upper_bound` (array subrange length).
    array_count: Option<u64>,
    /// `DW_AT_const_value` of a `DW_TAG_enumerator` — the enum member's value.
    /// Read as signed and masked to the enum's width when the map is built, so a
    /// negative member of a small enum lands on the same key the decompiler will
    /// look up. `None` for every other tag.
    const_value: Option<i64>,
    /// True if `DW_AT_declaration` is set (a declaration-only DIE — skip).
    declaration: bool,
    /// `DW_AT_noreturn` on a callable declaration.
    noreturn: bool,
    /// An explicit non-default calling convention must not be guessed.
    calling_convention: Option<gimli::DwCc>,
    /// Presence matters for C prototype-versus-nonprototype declarations.
    prototyped: Option<bool>,
    /// Compilation-unit language, not the C++ feature gate.
    language: Option<gimli::DwLang>,
    /// True if the DIE carries a `DW_AT_location` (a global var has a real address).
    has_location: bool,
    /// `DW_OP_addr` operand of a simple `DW_AT_location`, if that is its form.
    addr_location: Option<u64>,
    /// The signed `DW_OP_fbreg <off>` operand of a single-op `DW_AT_location`, if
    /// that is its form (a frame-base-relative stack local — subtask 3). `None`
    /// for any other location form (`DW_OP_addr`, register, multi-op).
    fbreg_location: Option<i64>,
    /// Depth in the DIE tree (root unit DIE = 0).
    depth: isize,
    /// Offsets of this DIE's direct children, in order.
    children: Vec<usize>,
    /// (kuna `cppproto`) `DW_AT_specification` or `DW_AT_abstract_origin` — the
    /// one-hop link from an out-of-line DEFINITION to the DECLARATION that carries
    /// its name, return type and (for an abstract instance) its parameter names.
    origin_ref: Option<usize>,
    /// (kuna `cppproto`) True when [`Self::origin_ref`] came from
    /// `DW_AT_specification` (a definition/declaration pair) rather than
    /// `DW_AT_abstract_origin` (a concrete instance of an abstract one). Only the
    /// former is followed for a subprogram — see `kuna_cppproto`'s clone note.
    origin_is_spec: bool,
    /// (kuna `cppproto`) This DIE's parent offset, so the namespace/class ancestry
    /// of a declaration can be walked into a qualified name.
    parent: Option<usize>,
}

impl DieSnap {
    /// An empty snapshot for the given tag/depth (gimli's `DwTag` has no
    /// `Default`, so we cannot derive it).
    fn new(tag: gimli::DwTag, depth: isize) -> Self {
        DieSnap {
            tag,
            source_id: None,
            name: String::new(),
            low_pc: None,
            type_ref: None,
            byte_size: None,
            data_member_location: None,
            bit_size: None,
            bit_offset: None,
            data_bit_offset: None,
            alignment: None,
            discr_ref: None,
            discr_value: None,
            encoding: None,
            array_count: None,
            const_value: None,
            declaration: false,
            noreturn: false,
            calling_convention: None,
            prototyped: None,
            language: None,
            has_location: false,
            addr_location: None,
            fbreg_location: None,
            depth,
            children: Vec::new(),
            origin_ref: None,
            origin_is_spec: false,
            parent: None,
        }
    }
}

/// Snapshot every DIE in `unit` into an offset-keyed map (plus the ordered
/// top-level offsets). Mirrors building Ghidra's `DebugInfoEntry` tree before
/// `DWARFFunctionImporter.importFunctions()` walks it.
fn snapshot_unit(
    dwarf: &gimli::Dwarf<Reader<'_>>,
    unit: &gimli::Unit<Reader<'_>>,
) -> BTreeMap<usize, DieSnap> {
    let mut map: BTreeMap<usize, DieSnap> = BTreeMap::new();
    // Parent stack of (offset, depth) to attach children to their parent.
    let mut stack: Vec<(usize, isize)> = Vec::new();

    let mut language = None;
    let mut cursor = unit.entries();
    while let Ok(Some(entry)) = cursor.next_dfs() {
        let off = entry.offset().0;
        let depth = entry.depth();

        // Pop the parent stack back to this DIE's parent level.
        while let Some(&(_, d)) = stack.last() {
            if d >= depth {
                stack.pop();
            } else {
                break;
            }
        }
        let parent_off = stack.last().map(|&(p, _)| p);
        if let Some(parent_off) = parent_off {
            if let Some(p) = map.get_mut(&parent_off) {
                p.children.push(off);
            }
        }

        if let Some(gimli::AttributeValue::Language(value)) = entry.attr_value(gimli::DW_AT_language) {
            language = Some(value);
        }
        let mut snap = DieSnap::new(entry.tag(), depth);
        snap.language = language;
        if let Some(gimli::AttributeValue::Flag(value)) = entry.attr_value(gimli::DW_AT_prototyped) {
            snap.prototyped = Some(value);
        }
        snap.source_id = entry.offset().to_debug_info_offset(&unit.header).map(|off| off.0 as u64);
        snap.parent = parent_off;
        // (kuna `cppproto`) The one-hop definition->declaration link. gcc/clang put
        // an out-of-line member or namespace definition at CU top level with only
        // `DW_AT_specification`, and a concrete out-of-line instance of an inlined
        // function with only `DW_AT_abstract_origin`; both leave the DIE with no
        // `DW_AT_name`/`DW_AT_type` of its own.
        for (attr, is_spec) in
            [(gimli::DW_AT_specification, true), (gimli::DW_AT_abstract_origin, false)]
        {
            if let Some(gimli::AttributeValue::UnitRef(o)) = entry.attr_value(attr) {
                snap.origin_ref = Some(o.0);
                snap.origin_is_spec = is_spec;
                break;
            }
        }

        if let Some(val) = entry.attr_value(gimli::DW_AT_name) {
            if let Ok(s) = dwarf.attr_string(unit, val) {
                if let Ok(s) = std::str::from_utf8(s.slice()) {
                    snap.name = s.to_string();
                }
            }
        }
        if let Some(val) = entry.attr_value(gimli::DW_AT_low_pc) {
            if let Ok(Some(a)) = dwarf.attr_address(unit, val) {
                snap.low_pc = Some(a);
            }
        }
        if let Some(gimli::AttributeValue::UnitRef(o)) = entry.attr_value(gimli::DW_AT_type) {
            snap.type_ref = Some(o.0);
        }
        if let Some(v) = entry.attr_value(gimli::DW_AT_byte_size) {
            snap.byte_size = v.udata_value();
        }
        // (kuna `dwarfstructs`) The aggregate-layout attributes. gcc spells a
        // member's offset as a plain constant; a `DW_AT_data_member_location` that
        // is a location EXPRESSION (the C++ virtual-base form) has no udata value
        // and reads as `None`, which skips that member rather than misplacing it.
        if let Some(v) = entry.attr_value(gimli::DW_AT_data_member_location) {
            snap.data_member_location =
                v.sdata_value().or_else(|| v.udata_value().map(|u| u as i64));
        }
        if let Some(v) = entry.attr_value(gimli::DW_AT_bit_size) {
            snap.bit_size = v.udata_value();
        }
        if let Some(v) = entry.attr_value(gimli::DW_AT_bit_offset) {
            snap.bit_offset = v.udata_value();
        }
        if let Some(v) = entry.attr_value(gimli::DW_AT_data_bit_offset) {
            snap.data_bit_offset = v.udata_value();
        }
        if let Some(v) = entry.attr_value(gimli::DW_AT_alignment) {
            snap.alignment = v.udata_value();
        }
        // (kuna `dwarfvariants`) The discriminated-union attributes. `DW_AT_discr`
        // is a reference to the artificial tag member; `DW_AT_discr_value` is a
        // constant whose signedness follows the discriminant type, so it is read
        // signed-first exactly like `DW_AT_const_value` above.
        if let Some(gimli::AttributeValue::UnitRef(o)) = entry.attr_value(gimli::DW_AT_discr) {
            snap.discr_ref = Some(o.0);
        }
        if let Some(v) = entry.attr_value(gimli::DW_AT_discr_value) {
            snap.discr_value = v.sdata_value().or_else(|| v.udata_value().map(|u| u as i64));
        }
        if let Some(gimli::AttributeValue::Encoding(e)) = entry.attr_value(gimli::DW_AT_encoding) {
            snap.encoding = Some(e);
        }
        // Array length: prefer DW_AT_count; else DW_AT_upper_bound + 1. The
        // subrange child of a DW_TAG_array_type carries it.
        if let Some(c) = entry.attr_value(gimli::DW_AT_count).and_then(|v| v.udata_value()) {
            snap.array_count = Some(c);
        } else if let Some(ub) =
            entry.attr_value(gimli::DW_AT_upper_bound).and_then(|v| v.udata_value())
        {
            snap.array_count = Some(ub + 1);
        }
        // Enumerator member value. gcc/clang emit it as `sdata` for a signed
        // underlying type and `data<N>`/`udata` otherwise, so try signed first and
        // fall back to unsigned (`udata_value` covers the `data<N>` forms gimli
        // does not report as `sdata`).
        if let Some(v) = entry.attr_value(gimli::DW_AT_const_value) {
            snap.const_value = v.sdata_value().or_else(|| v.udata_value().map(|u| u as i64));
        }
        if matches!(entry.attr_value(gimli::DW_AT_declaration), Some(gimli::AttributeValue::Flag(true)))
        {
            snap.declaration = true;
        }
        snap.noreturn = matches!(entry.attr_value(gimli::DW_AT_noreturn), Some(gimli::AttributeValue::Flag(true)));
        if let Some(gimli::AttributeValue::CallingConvention(cc)) = entry.attr_value(gimli::DW_AT_calling_convention) {
            snap.calling_convention = Some(cc);
        }
        if let Some(loc) = entry.attr_value(gimli::DW_AT_location) {
            snap.has_location = true;
            snap.addr_location = simple_addr_location(&loc);
            snap.fbreg_location = simple_fbreg_location(&loc);
        }

        map.insert(off, snap);
        if entry.has_children() {
            stack.push((off, depth));
        }
    }
    map
}

/// Decode a `DW_AT_location` that is a single `DW_OP_addr <vma>` expression (the
/// only global-variable location form this pass handles), returning the VMA.
/// Anything else (`DW_OP_fbreg`, register, multi-op) returns `None` — a
/// `DW_OP_fbreg` stack local is handled separately by [`simple_fbreg_location`]
/// (subtask 3); a register/multi-op location has no static address.
fn simple_addr_location(loc: &gimli::AttributeValue<Reader<'_>>) -> Option<u64> {
    let expr = match loc {
        gimli::AttributeValue::Exprloc(e) => e.clone(),
        gimli::AttributeValue::Block(b) => gimli::Expression(b.clone()),
        _ => return None,
    };
    // A DW_OP_addr expression is the opcode 0x03 followed by an address-sized
    // operand. Parse it with a temporary 64-bit encoding (address_size only
    // affects DW_OP_addr operand width); we only accept the single-op case.
    let bytes = expr.0.slice();
    if bytes.first() != Some(&0x03) {
        return None;
    }
    match bytes.len() {
        5 => Some(u32::from_le_bytes([bytes[1], bytes[2], bytes[3], bytes[4]]) as u64),
        9 => Some(u64::from_le_bytes([
            bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7], bytes[8],
        ])),
        _ => None,
    }
}

/// Decode a `DW_AT_location` that is a single `DW_OP_fbreg <sleb128>` expression
/// (the frame-base-relative stack-local form — subtask 3), returning the SIGNED
/// frame-base offset. Anything else (`DW_OP_addr`, register, multi-op) returns
/// `None`. The whole expression must be exactly the one opcode + its SLEB128
/// operand (we deliberately do NOT handle composite/piece locations — a single
/// `DW_OP_fbreg` is what `-O0`/`-g` emits for a plain stack slot, and is what
/// Ghidra's `DWARFExpressionEvaluator` resolves to a stack varnode via the frame
/// base set to the CFA, `DWARFExpressionEvaluator.java:403`).
fn simple_fbreg_location(loc: &gimli::AttributeValue<Reader<'_>>) -> Option<i64> {
    let expr = match loc {
        gimli::AttributeValue::Exprloc(e) => e.clone(),
        gimli::AttributeValue::Block(b) => gimli::Expression(b.clone()),
        _ => return None,
    };
    let bytes = expr.0.slice();
    // DW_OP_fbreg == 0x91, followed by a single SLEB128 operand.
    if bytes.first() != Some(&0x91) {
        return None;
    }
    let (off, consumed) = read_sleb128(&bytes[1..])?;
    // Reject any trailing opcodes (a composite/multi-op location is not a plain
    // stack slot — leave it to the engine, faithful to the single-op case only).
    if 1 + consumed != bytes.len() {
        return None;
    }
    Some(off)
}

/// Decode a little-endian SLEB128 (DWARF signed LEB128) from `buf`, returning the
/// value and the number of bytes consumed. `None` if `buf` is truncated. A tiny
/// self-contained reader (gimli exposes SLEB128 only on its streaming cursor, not
/// on a raw `&[u8]`), faithful to the DWARF spec's sign-extension rule.
fn read_sleb128(buf: &[u8]) -> Option<(i64, usize)> {
    let mut result: i64 = 0;
    let mut shift: u32 = 0;
    let mut i = 0;
    loop {
        let byte = *buf.get(i)?;
        i += 1;
        result |= ((byte & 0x7f) as i64) << shift;
        shift += 7;
        if byte & 0x80 == 0 {
            // Sign-extend if the sign bit of the final group is set and we have
            // not filled all 64 bits.
            if shift < 64 && (byte & 0x40) != 0 {
                result |= -1i64 << shift;
            }
            return Some((result, i));
        }
        if shift >= 64 {
            // Malformed (overlong); refuse rather than overflow.
            return None;
        }
    }
}

/// Storage volatility follows aliases/qualifiers only; a pointer stops the
/// walk so a pointer-to-volatile object does not become a volatile pointer.
fn object_is_volatile(mut off: Option<usize>, dies: &BTreeMap<usize, DieSnap>) -> bool {
    for _ in 0..MAX_QUALIFIER_HOPS {
        let Some(die) = off.and_then(|off| dies.get(&off)) else { return false; };
        match die.tag {
            gimli::DW_TAG_volatile_type => return true,
            gimli::DW_TAG_typedef | gimli::DW_TAG_const_type | gimli::DW_TAG_restrict_type => off = die.type_ref,
            _ => return false,
        }
    }
    false
}

/// Build the kuna [`Datatype`] for the type DIE at `off`, recursing through the
/// DWARF type chain (faithful reduction of `DWARFDataTypeImporter.getDataType`'s
/// tag switch). `None` for a missing/unbuildable type; the caller skips that one
/// piece rather than failing the analysis. `walk` is the recursion guard
/// ([`kuna_typedepth::TypeWalk`]) and is the whole of the termination argument.
///
/// `cpp` adds the C++-only tag arms (`--option cppproto`, see
/// [`kuna_cppproto`]): a `DW_TAG_class_type` maps like a structure and a
/// `DW_TAG_reference_type`/`DW_TAG_rvalue_reference_type` like a pointer. With
/// `cpp` false and the guard in its budget mode (`--option typedepth off`) the
/// switch is byte-identical to the pre-`cppproto` mapper.
fn build_datatype(
    off: Option<usize>,
    dies: &BTreeMap<usize, DieSnap>,
    types: &dyn TypeFactory,
    word_size: uint4,
    walk: &mut TypeWalk,
    cpp: bool,
) -> Option<TypeRoot> {
    // A null DW_AT_type means `void` (the C++ getDataTypeForVariable null case).
    let Some(off) = off else {
        return types.get_type_void().ok();
    };
    if let Some(root) = walk.reserved(off) {
        return Some(root);
    }
    if !walk.enter(off) {
        // Refused (a type cycle, or a bound): void keeps the chain finite while a
        // pointer to it still renders as a pointer.
        return types.get_type_void().ok();
    }
    let built = build_datatype_at(off, dies, types, word_size, walk, cpp);
    walk.leave(off);
    built
}

/// The tag switch itself, entered with `off` already admitted by the guard.
fn build_datatype_at(
    off: usize,
    dies: &BTreeMap<usize, DieSnap>,
    types: &dyn TypeFactory,
    word_size: uint4,
    walk: &mut TypeWalk,
    cpp: bool,
) -> Option<TypeRoot> {
    let mut off = off;
    let mut die = dies.get(&off)?;
    if cpp || walk.collapse_qualifiers() {
        for _ in 0..MAX_QUALIFIER_HOPS {
            if !matches!(die.tag,
                gimli::DW_TAG_const_type | gimli::DW_TAG_volatile_type | gimli::DW_TAG_restrict_type
            ) {
                break;
            }
            let Some(next) = die.type_ref else { break };
            let Some(target) = dies.get(&next) else { break };
            off = next;
            die = target;
        }
        if let Some(root) = walk.reserved(off) {
            return Some(root);
        }
    }
    // Typedefs are nominal nodes, reserved before descending into their target.
    // A recursive member retains this identity when the alias is completed.
    if die.tag == gimli::DW_TAG_typedef && !die.name.is_empty() {
        let name = kuna_dwarfstructs::qualified_name(die, dies, None, "", None);
        // C's typedef and tag namespaces can contain the same spelling. The
        // alias's source DIE identity is independent of its display name.
        let host_id = die.source_id.unwrap_or(off as u64);
        let alias = types.reserve_alias(&name, host_id).ok()?;
        walk.reserve(off, alias.clone());
        if alias.get_typedef().is_some() {
            return Some(alias);
        }
        let mut target_off = die.type_ref;
        for _ in 0..MAX_QUALIFIER_HOPS {
            let Some(o) = target_off else { break };
            let Some(target) = dies.get(&o) else { break };
            if matches!(target.tag, gimli::DW_TAG_const_type | gimli::DW_TAG_volatile_type | gimli::DW_TAG_restrict_type) {
                target_off = target.type_ref;
                continue;
            }
            if target.name.is_empty() && matches!(target.tag,
                gimli::DW_TAG_structure_type | gimli::DW_TAG_class_type | gimli::DW_TAG_union_type
            ) {
                walk.name_anonymous(o, name.clone());
            }
            break;
        }
        let target = build_datatype(die.type_ref, dies, types, word_size, walk, cpp);
        let Some(target) = target else {
            let _ = types.fail(&alias, "Unbuildable DWARF typedef target".into());
            walk.forget(off);
            return None;
        };
        let mut draft = Datatype::new_with_align(
            target.get_size(), target.get_alignment(), target.get_metatype(),
        );
        draft.name = name.clone();
        draft.display_name = name;
        draft.id = alias.get_id();
        draft.kind = DatatypeKind::Alias;
        draft.typedef_imm = Some(target.id());
        if types.complete(&alias, draft).is_err() {
            walk.forget(off);
            return None;
        }
        return Some(alias);
    }
    let aggregate_alias = walk.anonymous_name(off);
    let alias = aggregate_alias.as_deref();
    let ptr = types.get_size_of_pointer();
    match die.tag {
        gimli::DW_TAG_base_type => {
            let size = die.byte_size.unwrap_or(0) as i32;
            if size <= 0 {
                return None;
            }
            match die.encoding {
                Some(gimli::DW_ATE_signed_char) if die.name == "char" => {
                    types.get_type_char(size).ok()
                }
                Some(gimli::DW_ATE_signed_char) => {
                    types.get_base_no_char(size, type_metatype::TYPE_INT).ok()
                }
                Some(gimli::DW_ATE_unsigned_char) => {
                    types.get_base(size, type_metatype::TYPE_UINT).ok()
                }
                Some(gimli::DW_ATE_boolean) => types.get_base(size, type_metatype::TYPE_BOOL).ok(),
                Some(gimli::DW_ATE_float) => types.get_base(size, type_metatype::TYPE_FLOAT).ok(),
                Some(gimli::DW_ATE_unsigned) => types.get_base(size, type_metatype::TYPE_UINT).ok(),
                // DW_ATE_signed (and anything else) -> signed int.
                _ => types.get_base(size, type_metatype::TYPE_INT).ok(),
            }
        }
        // A C++ reference is a pointer at the ABI level (`DWARFDataTypeImporter`
        // maps both through `makeDataTypeForPointer`), so it shares this arm.
        gimli::DW_TAG_pointer_type => {
            // makeDataTypeForPointer: pointer to the (possibly null=void) pointee.
            let pointee = build_datatype(die.type_ref, dies, types, word_size, walk, cpp)
                .or_else(|| types.get_type_void().ok())?;
            let psize = die.byte_size.map(|b| b as i32).unwrap_or(ptr);
            types.get_type_pointer(psize, pointee, word_size).ok()
        }
        gimli::DW_TAG_reference_type | gimli::DW_TAG_rvalue_reference_type if cpp => {
            let pointee = build_datatype(die.type_ref, dies, types, word_size, walk, cpp)
                .or_else(|| types.get_type_void().ok())?;
            let psize = die.byte_size.map(|b| b as i32).unwrap_or(ptr);
            types.get_type_pointer(psize, pointee, word_size).ok()
        }
        // Unnamed typedefs and transparent qualifiers pass through to their
        // underlying DW_AT_type (a null underlying => void).
        gimli::DW_TAG_typedef
        | gimli::DW_TAG_const_type
        | gimli::DW_TAG_volatile_type
        | gimli::DW_TAG_restrict_type => {
            build_datatype(die.type_ref, dies, types, word_size, walk, cpp)
        }
        gimli::DW_TAG_array_type => {
            let elem = build_datatype(die.type_ref, dies, types, word_size, walk, cpp)?;
            // The length lives on a DW_TAG_subrange_type child (DW_AT_count or
            // upper_bound+1); fall back to 1 for a flexible/unknown array.
            let count = die
                .children
                .iter()
                .filter_map(|c| dies.get(c))
                .find(|c| c.tag == gimli::DW_TAG_subrange_type)
                .and_then(|c| c.array_count)
                .or(die.array_count)
                .unwrap_or(1) as i32;
            types.get_type_array(count.max(1), elem).ok()
        }
        // A `DW_TAG_class_type` is a structure with a default access specifier —
        // Ghidra's importer maps both through the same `makeDataTypeForStruct`
        // arm. Without it every `Foo *this` degraded to `void *`.
        gimli::DW_TAG_structure_type => {
            intern_aggregate(types, die, dies, alias, "anon_struct", walk, word_size, cpp, false)
        }
        gimli::DW_TAG_class_type if cpp => {
            intern_aggregate(types, die, dies, alias, "anon_class", walk, word_size, cpp, false)
        }
        gimli::DW_TAG_union_type => {
            intern_aggregate(types, die, dies, alias, "anon_union", walk, word_size, cpp, true)
        }
        gimli::DW_TAG_enumeration_type => {
            let size = die.byte_size.map(|b| b as i32).unwrap_or(4).max(1);
            build_enum(die, dies, types, size)
                // Anonymous, memberless, or the wrong width for the factory's
                // enum size: fall back to the plain underlying integer, which is
                // what this arm always used to produce.
                .or_else(|| types.get_base(size, type_metatype::TYPE_INT).ok())
        }
        gimli::DW_TAG_subroutine_type => {
            build_callable(off, die, dies, types, word_size, walk, cpp)
        }
        // Any other tag -> give up on this type cleanly.
        _ => None,
    }
}

/// Import a declaration, not an ABI slot list. Reserve the source identity before
/// descending so recursive callback edges refer to this same completed Code node.
#[allow(clippy::too_many_arguments)]
fn build_callable(
    off: usize,
    die: &DieSnap,
    dies: &BTreeMap<usize, DieSnap>,
    types: &dyn TypeFactory,
    word_size: uint4,
    walk: &mut TypeWalk,
    cpp: bool,
) -> Option<TypeRoot> {
    if die.calling_convention.is_some_and(|cc| cc != gimli::DW_CC_normal) {
        return None;
    }
    let host_id = die.source_id.unwrap_or(off as u64);
    let code = types.reserve(&die.name, host_id, type_metatype::TYPE_CODE).ok()?;
    if code.read().get_code_prototype(code.id()).ok()?.is_some() {
        return Some(code);
    }
    walk.reserve(off, code.clone());
    let built = (|| {
        // Capture the selected model before any recursive declaration is visited.
        let binding = types.model_binding(None).ok()?;
        types.begin(&code).ok()?;
        let outtype = build_datatype(die.type_ref, dies, types, word_size, walk, cpp)?;
        let mut intypes = Vec::new();
        let mut innames = Vec::new();
        let mut first_var_arg_slot = -1;
        for &child_off in &die.children {
            let child = dies.get(&child_off)?;
            match child.tag {
                gimli::DW_TAG_formal_parameter => {
                    // A missing formal type is not an invented void parameter.
                    let ty = build_datatype(Some(child.type_ref?), dies, types, word_size, walk, cpp)?;
                    if ty.get_metatype() == type_metatype::TYPE_VOID {
                        return None;
                    }
                    intypes.push(ty);
                    innames.push(child.name.clone());
                }
                gimli::DW_TAG_unspecified_parameters => {
                    first_var_arg_slot = intypes.len() as i32;
                }
                _ => {}
            }
        }
        // DW_AT_prototyped distinguishes C's int() from int(void). Its absence
        // in other languages does not make their fixed signatures open.
        let c_nonprototype = matches!(die.language,
            Some(gimli::DW_LANG_C | gimli::DW_LANG_C89 | gimli::DW_LANG_C99
                | gimli::DW_LANG_C11 | gimli::DW_LANG_C17 | gimli::DW_LANG_ObjC))
            && die.prototyped != Some(true);
        let variadic = first_var_arg_slot >= 0 && !c_nonprototype;
        if c_nonprototype {
            first_var_arg_slot = -1;
        }
        let pieces = PrototypePieces {
            name: die.name.clone(), outtype: Some(outtype), intypes, innames,
            first_var_arg_slot, output_storage: None, input_storage: Vec::new(),
        };
        let flags = if die.noreturn { func_proto_flags::NO_RETURN } else { 0 };
        let logical = LogicalCallable::from_declaration(binding, &pieces, variadic, !variadic && !c_nonprototype, flags).ok()?;
        let mut draft = Datatype::new_with_align(1, 1, type_metatype::TYPE_CODE);
        draft.name = die.name.clone();
        draft.display_name = die.name.clone();
        draft.id = host_id;
        draft.flags |= kuna_decomp::dtype::flags::variable_length;
        draft.kind = DatatypeKind::Code { proto: Some(logical) };
        types.complete(&code, draft).ok()?;
        Some(code.clone())
    })();
    if built.is_none() {
        let _ = types.fail(&code, "Unbuildable DWARF callable declaration".into());
        walk.forget(off);
    }
    built
}

/// Intern the aggregate for `die`: its `DW_AT_byte_size` + `DW_TAG_member`
/// layout under `--option dwarfstructs on` ([`kuna_dwarfstructs`]), else a named
/// opaque declaration. Typedefs retain their own source identity even when the
/// aggregate must use an anonymous fallback because a core type owns its name.
#[allow(clippy::too_many_arguments)]
fn intern_aggregate(
    types: &dyn TypeFactory,
    die: &DieSnap,
    dies: &BTreeMap<usize, DieSnap>,
    alias: Option<&str>,
    fallback: &str,
    walk: &mut TypeWalk,
    word_size: uint4,
    cpp: bool,
    union: bool,
) -> Option<TypeRoot> {
    // (kuna `dwarfvariants`) A `DW_TAG_variant_part` child means the aggregate is
    // a discriminated union, whose layout the member walk below cannot see (there
    // are no `DW_TAG_member` children to walk). `None` here means the arm REFUSED
    // this DIE -- it fell short of one of its guards -- and the ordinary paths
    // still get their turn. It is an EXTENSION of `dwarfstructs` and requires it:
    // with the aggregate-layout gate off, `dwarfstructs off` stays exactly the
    // pre-DIV-86 name-only mapping, which is what its own catalog row promises.
    if !union && kuna_dwarfstructs::enabled() && kuna_dwarfvariants::enabled() {
        if let Some(t) = kuna_dwarfvariants::intern_variant_aggregate(
            types, die, dies, alias, fallback, walk, word_size, cpp,
        ) {
            return Some(t);
        }
    }
    if kuna_dwarfstructs::enabled() {
        return kuna_dwarfstructs::intern_aggregate(
            types, die, dies, alias, fallback, walk, word_size, cpp, union,
        );
    }
    let want =
        if union { type_metatype::TYPE_UNION } else { type_metatype::TYPE_STRUCT };
    let intern = |n: &str| {
        let built = if union { types.get_type_union(n) } else { types.get_type_struct(n) };
        built.ok().filter(|t| t.get_metatype() == want)
    };
    let name = aggregate_name(die, alias, fallback);
    if let Some(t) = intern(name) {
        return Some(t);
    }
    if walk.collapse_qualifiers() && die.name.is_empty() && name != fallback {
        return intern(fallback);
    }
    None
}

/// (kuna `cppproto`) Follow typedefs and qualifiers only to inspect a source
/// storage width when a parameter cannot be built. Nominal construction does
/// not use this helper: typedefs remain separate graph identities.
///
/// Bounded by [`MAX_QUALIFIER_HOPS`]; a chain that ends in a null `DW_AT_type` (a
/// qualified `void`) or exceeds the bound is returned as-is, so the caller's own
/// arms still handle it.
fn strip_qualifiers<'a>(
    mut die: &'a DieSnap,
    dies: &'a BTreeMap<usize, DieSnap>,
) -> &'a DieSnap {
    for _ in 0..MAX_QUALIFIER_HOPS {
        if !matches!(
            die.tag,
            gimli::DW_TAG_typedef
                | gimli::DW_TAG_const_type
                | gimli::DW_TAG_volatile_type
                | gimli::DW_TAG_restrict_type
        ) {
            break;
        }
        match die.type_ref.and_then(|t| dies.get(&t)) {
            Some(next) => die = next,
            None => break,
        }
    }
    die
}

/// Bound on the [`strip_qualifiers`] walk (a real qualifier chain is 1-3 hops).
const MAX_QUALIFIER_HOPS: u32 = 16;

/// The interned name for an aggregate DIE: its own `DW_AT_name`, else the typedef
/// it was reached through, else `fallback`.
fn aggregate_name<'a>(die: &'a DieSnap, alias: Option<&'a str>, fallback: &'a str) -> &'a str {
    if !die.name.is_empty() {
        &die.name
    } else {
        alias.unwrap_or(fallback)
    }
}

/// Build a real kuna enum `Datatype` from a `DW_TAG_enumeration_type` DIE and its
/// `DW_TAG_enumerator` children (`DWARFDataTypeImporter.makeDataTypeForEnum`).
///
/// The decompiler already renders an enum-typed constant by member name; what was
/// missing was the type. This arm used to flatten every enum to its underlying
/// integer, so `quotearg_style(shell_escape_always_quoting_style, ...)` printed
/// `quotearg_style(4, ...)`.
///
/// `None` (and the caller falls back to the plain integer) when the enum is
/// anonymous, has no usable members, or is not the width the type factory builds
/// enums at — a size mismatch would misdescribe the storage, and a wrong size is
/// worse than a missing name.
///
/// Member values are masked to the enum's width, matching how the printer looks a
/// constant up: a `-1` member of a 4-byte enum is keyed `0xffffffff`, the value
/// the constant Varnode actually carries.
fn build_enum(
    die: &DieSnap,
    dies: &BTreeMap<usize, DieSnap>,
    types: &dyn TypeFactory,
    size: i32,
) -> Option<TypeRoot> {
    if die.name.is_empty() {
        return None;
    }
    let mask: u64 = if size >= 8 { u64::MAX } else { (1u64 << (size * 8)) - 1 };
    let mut nmap: std::collections::BTreeMap<u64, String> = std::collections::BTreeMap::new();
    for &coff in &die.children {
        let Some(child) = dies.get(&coff) else { continue };
        if child.tag != gimli::DW_TAG_enumerator || child.name.is_empty() {
            continue;
        }
        let Some(v) = child.const_value else { continue };
        // First member at a value wins; a duplicate value is an alias the printer
        // could not disambiguate anyway.
        nmap.entry((v as u64) & mask).or_insert_with(|| child.name.clone());
    }
    if nmap.is_empty() {
        return None;
    }
    // Signedness from `DW_AT_encoding` (gcc emits `DW_ATE_unsigned` for an enum
    // whose members are all non-negative, `DW_ATE_signed` otherwise). The width
    // is the DIE's own `DW_AT_byte_size`, not the factory's architecture default
    // (8 on x86-64) -- a C enum is normally int-sized, and a type that misstates
    // its storage width will not bind to the 4-byte constant it describes.
    let meta = match die.encoding {
        Some(gimli::DW_ATE_signed) | Some(gimli::DW_ATE_signed_char) => {
            type_metatype::TYPE_ENUM_INT
        }
        _ => type_metatype::TYPE_ENUM_UINT,
    };
    // The type factory interns by name, and a real program repeats the same enum
    // definition in every compilation unit that includes its header. Constructing
    // it a second time is an ERROR, not a no-op — the fresh (memberless) shell no
    // longer matches the filled definition already installed — so look first and
    // reuse. Guarded on shape: a same-named type that is not an enum of this width
    // owns the name, and we do not fight it.
    if let Some(existing) = types.find_by_source_id(&die.name, Datatype::hash_name(&die.name)).ok()? {
        return (existing.is_enum_type() && existing.get_size() == size).then_some(existing);
    }
    let ct = types.get_type_enum_sized(&die.name, size, meta).ok()?;
    types.set_enum_values(&ct, nmap).ok()
}

/// Build [`PrototypePieces`] for a defined subprogram DIE (`DWARFFunction.read` +
/// `getFunctionParamList`): return type from `DW_AT_type`, parameter types/names
/// from `DW_TAG_formal_parameter` children, `first_var_arg_slot` from a trailing
/// `DW_TAG_unspecified_parameters`. Returns `None` if any required type can't be
/// built with the layout required for ABI assignment (the whole prototype is
/// then skipped, leaving native recovery in place). Pointers to opaque types
/// remain admissible; a missing by-value layout is never replaced by a guessed
/// scalar width or hidden return parameter.
fn build_pieces(
    name: &str,
    sub: &DieSnap,
    dies: &BTreeMap<usize, DieSnap>,
    types: &dyn TypeFactory,
    word_size: uint4,
) -> Option<PrototypePieces> {
    // Return type: a null DW_AT_type is `void` (build_datatype handles None).
    let mut walk = TypeWalk::new();
    let outtype = build_datatype(sub.type_ref, dies, types, word_size, &mut walk, false)?;
    if !outtype.read().layout_ready(outtype.id()).ok()? {
        return None;
    }

    let mut intypes = Vec::new();
    let mut innames = Vec::new();
    let mut first_var_arg_slot: i32 = -1;

    for &coff in &sub.children {
        let Some(child) = dies.get(&coff) else { continue };
        match child.tag {
            gimli::DW_TAG_formal_parameter => {
                let ty = build_datatype(child.type_ref, dies, types, word_size, &mut walk, false)?;
                if !ty.read().layout_ready(ty.id()).ok()? {
                    return None;
                }
                intypes.push(ty);
                innames.push(child.name.clone());
            }
            gimli::DW_TAG_unspecified_parameters => {
                // `...` — variadic from the current fixed-parameter count.
                first_var_arg_slot = intypes.len() as i32;
            }
            _ => {}
        }
    }

    Some(PrototypePieces {
        name: name.to_string(),
        outtype: Some(outtype),
        intypes,
        innames,
        first_var_arg_slot,
        output_storage: None,
        input_storage: Vec::new(),
    })
}

/// Collect the named, typed stack LOCALS of a defined subprogram (subtask 3): each
/// direct `DW_TAG_variable` / `DW_TAG_formal_parameter` child carrying a single
/// `DW_OP_fbreg <off>` location becomes a [`LocalFact`] at stack offset
/// `cfa + off`, with its type mapped from `DW_AT_type` by [`build_datatype`].
///
/// Faithful reduction of `DWARFFunctionImporter.processSubprogram` →
/// `DWARFFunction.getLocalVarStorage` (the loop over `dfunc.localVarErrors` and the
/// parameter list) + `DWARFVariable.readLocalVariableStorage` (the
/// `DW_OP_fbreg`→stack-varnode resolution). A child we cannot fully ground (no
/// fbreg location, no `DW_AT_type`, an unbuildable type, an empty name) is SKIPPED
/// — never a failure (the names+types of subtasks 1+2 are unaffected).
///
/// We restrict to **direct** children of the subprogram DIE: a lexical-block- or
/// inlined-subroutine-nested local is a documented loss (the same listing-cosmetic
/// scope as the skipped `DW_TAG_label`/`DW_TAG_call_site`), and a plain `-O0`/`-g`
/// function carries its locals as direct children.
fn collect_fbreg_locals(
    func_addr: u64,
    sub: &DieSnap,
    dies: &BTreeMap<usize, DieSnap>,
    types: &dyn TypeFactory,
    word_size: uint4,
    cfa: i64,
    out: &mut Vec<crate::pass::LocalFact>,
) {
    let mut walk = TypeWalk::new();
    for &coff in &sub.children {
        let Some(child) = dies.get(&coff) else { continue };
        if !matches!(child.tag, gimli::DW_TAG_variable | gimli::DW_TAG_formal_parameter) {
            continue;
        }
        if child.name.is_empty() {
            continue;
        }
        let Some(fbreg) = child.fbreg_location else { continue };
        let Some(ty) =
            build_datatype(child.type_ref, dies, types, word_size, &mut walk, false)
        else {
            continue;
        };
        out.push(crate::pass::LocalFact {
            func_addr,
            name: child.name.clone(),
            type_: ty,
            // stack_offset = call_frame_cfa + fbreg (DWARFExpressionEvaluator).
            stack_offset: cfa.wrapping_add(fbreg),
        });
    }
}

impl AnalysisPass for DwarfPass {
    fn phase(&self) -> Phase {
        Phase::P1
    }

    fn id(&self) -> &'static str {
        "dwarf"
    }

    fn run(&self, ctx: &AnalysisCtx) -> AnalysisOutput {
        let mut out = AnalysisOutput::default();
        // gimli is **format-neutral** — it parses the DWARF byte stream, not the
        // container. The only container coupling is the *section-name lookup*, and
        // that is delegated to `object`'s format-aware `section_by_name`
        // ([`dwarf_section_data`]), which already maps gimli's ELF-style ids to
        // each format's real debug-section name: ELF `.debug_info` (verbatim),
        // **Mach-O `__DWARF,__debug_info`** (the `__debug_*` short names in the
        // `__DWARF` segment — `object` translates `.debug_info`→`__debug_info` and
        // `.debug_str_offsets`→`__debug_str_offs` per its documented Mach-O rule),
        // and **MinGW-PE `.debug_info`** (MinGW emits the standard `.debug_*`
        // names verbatim). So the ELF gate is dropped: any ELF/Mach-O/PE/COFF
        // object that carries `.debug_info` is read. (PE-MSVC carries PDB, not
        // DWARF — no `.debug_info` section — so it falls out here cleanly; PDB is
        // separate future work, not DWARF.)
        //
        // DWARFProgram.isDWARF: no `.debug_info` => not a DWARF program, empty out.
        if dwarf_section_data(ctx.file, gimli::SectionId::DebugInfo).is_none() {
            return out;
        }

        let endian = if ctx.file.is_little_endian() {
            gimli::RunTimeEndian::Little
        } else {
            gimli::RunTimeEndian::Big
        };

        // Own every section's bytes so the gimli readers can borrow them. A
        // missing section reads as empty (gimli treats that as "section absent").
        // [`dwarf_section_data`] does the per-format section-name resolution.
        let load = |id: gimli::SectionId| -> Result<Vec<u8>, gimli::Error> {
            Ok(dwarf_section_data(ctx.file, id).unwrap_or_default())
        };
        let Ok(sections) = gimli::DwarfSections::load(load) else {
            return out;
        };
        let dwarf = sections.borrow(|bytes| gimli::EndianSlice::new(bytes, endian));

        let types = ctx.arch.types();
        let (_addr_size, word_size) = ctx.arch.data_org();
        // subtask 3: the per-arch static CFA constant that turns a `DW_OP_fbreg`
        // frame-base offset into a kuna stack-space offset (`stack = cfa + fbreg`).
        // `None` => this target's CFA is not in kuna's table; skip fbreg locals
        // (additive — the names+types from subtasks 1+2 still apply).
        let cfa = call_frame_cfa(ctx.file.architecture());

        let mut units = dwarf.units();
        while let Ok(Some(header)) = units.next() {
            let Ok(unit) = dwarf.unit(header) else { continue };
            let dies = snapshot_unit(&dwarf, &unit);

            for snap in dies.values() {
                match snap.tag {
                    gimli::DW_TAG_subprogram => {
                        // Defined function only: DW_AT_low_pc present and not a
                        // declaration-only DIE (DWARFFunction.read body-ranges guard).
                        let Some(low_pc) = snap.low_pc else { continue };
                        if snap.declaration {
                            continue;
                        }
                        if !snap.name.is_empty() {
                            out.symbols.push(SymFact {
                                addr: low_pc,
                                name: snap.name.clone(),
                                kind: SymKind::Function,
                            });
                            // subtask 2: typed signature. A prototype that can't be
                            // fully typed is skipped (never fails the analysis).
                            if let Some(pieces) =
                                build_pieces(&snap.name, snap, &dies, types, word_size)
                            {
                                out.prototypes.push(pieces);
                            }
                            // subtask 3: named, typed stack LOCALS. Each direct
                            // `DW_TAG_variable`/`DW_TAG_formal_parameter` child with a
                            // single `DW_OP_fbreg` location (a plain stack slot) maps to
                            // a `LocalFact` at `cfa + fbreg`. Mirrors
                            // `DWARFFunctionImporter.processSubprogram`'s commit of
                            // `dfunc.localVarErrors`/params via
                            // `DWARFVariable.readLocalVariableStorage` -> stack varnode.
                            // Only when the arch's CFA constant is known.
                            if let Some(cfa) = cfa {
                                collect_fbreg_locals(low_pc, snap, &dies, types, word_size, cfa, &mut out.locals);
                            }
                        }
                        // (kuna `cppproto`) The C++ arm: fuse the definition with the
                        // declaration it links to, qualify the name by its
                        // namespace/class ancestry, and key the prototype by entry
                        // address. Emitted into a SEPARATE fact set so the commit
                        // boundary can drop it under `--option cppproto off` — the
                        // pass runs at load, upstream of the `option` commands.
                        let Some(res) = kuna_cppproto::resolve_subprogram(snap, &dies) else {
                            continue;
                        };
                        // Only a name the arm above could not produce is new; a
                        // definition that already carried its own unqualified name is
                        // installed once, by that arm.
                        if res.chased || res.name != snap.name {
                            out.cpp_dwarf.symbols.push(SymFact {
                                addr: low_pc,
                                name: res.name.clone(),
                                kind: SymKind::Function,
                            });
                        }
                        if let Some(pieces) =
                            kuna_cppproto::build_pieces(&res, &dies, types, word_size)
                        {
                            out.cpp_dwarf.prototypes.push((low_pc, pieces));
                        }
                        if res.chased {
                            if let Some(cfa) = cfa {
                                kuna_cppproto::collect_fbreg_locals(
                                    low_pc,
                                    snap,
                                    &dies,
                                    types,
                                    word_size,
                                    cfa,
                                    &mut out.cpp_dwarf.locals,
                                );
                            }
                        }
                    }
                    gimli::DW_TAG_variable => {
                        // A CU top-level global with a DW_OP_addr location
                        // (DWARFFunctionImporter.outputGlobal). depth==1 == direct
                        // child of the CU root DIE (no subprogram ancestor).
                        if snap.depth != 1 || snap.name.is_empty() {
                            continue;
                        }
                        if let Some(addr) = snap.addr_location {
                            // Preserve the same source graph root used by signatures,
                            // including nominal callback/record aliases. Volatility
                            // belongs to this storage, not the pointee's type.
                            let type_ = build_datatype(
                                snap.type_ref, &dies, types, word_size,
                                &mut TypeWalk::new(), false,
                            ).filter(|type_| type_.get_size() >= 1);
                            let size = type_.as_ref().map_or(1, |type_| type_.get_size()) as u32;
                            out.data_objects.push(crate::pass::DataObjectFact {
                                addr,
                                name: snap.name.clone(),
                                size,
                                type_,
                                volatile: object_is_volatile(snap.type_ref, &dies),
                            });
                        }
                    }
                    _ => {}
                }
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kuna_decomp::dtype::TypeFactoryImpl;
    use std::rc::Rc;

    /// A configured [`TypeFactory`] for the mapper unit tests (the dtype-test
    /// recipe: default alignment map, max base size 8, 64-bit sizes, core-type
    /// cache so `get_type_void`/`get_type_char`/`get_type_pointer` resolve).
    fn factory() -> TypeFactoryImpl {
        let f = TypeFactoryImpl::new();
        f.set_default_alignment_map();
        f.set_max_basetype_size(8);
        f.setup_sizes(Some(8), 8, 4);
        let _ = f.cache_core_types();
        f
    }

    fn callable_factory() -> TypeFactoryImpl {
        let types = factory();
        let manager = Rc::new(kuna_base::space::AddrSpaceManager::new());
        let model = Rc::new(kuna_decomp::fspec::ProtoModel::new(&manager));
        types.set_proto_context(Some(model), manager).unwrap();
        types
    }

    #[test]
    fn dwarf_callback_declarations_keep_logical_formals_and_variadic_boundary() {
        for variadic in [false, true] {
            let types = callable_factory();
            let mut dies = BTreeMap::new();
            let mut byte = DieSnap::new(gimli::DW_TAG_base_type, 1);
            byte.name = "unsigned char".into();
            byte.encoding = Some(gimli::DW_ATE_unsigned_char);
            byte.byte_size = Some(1);
            dies.insert(1, byte);
            let mut flags = DieSnap::new(gimli::DW_TAG_typedef, 1);
            flags.name = "Flags".into();
            flags.type_ref = Some(1);
            dies.insert(2, flags);
            let mut integer = DieSnap::new(gimli::DW_TAG_base_type, 1);
            integer.encoding = Some(gimli::DW_ATE_signed);
            integer.byte_size = Some(4);
            dies.insert(3, integer);
            let mut code = DieSnap::new(gimli::DW_TAG_subroutine_type, 1);
            code.source_id = Some(0xabc);
            code.type_ref = Some(3);
            code.noreturn = true;
            code.children.push(5);
            if variadic {
                code.children.push(6);
                dies.insert(6, DieSnap::new(gimli::DW_TAG_unspecified_parameters, 2));
            }
            dies.insert(4, code);
            let mut parameter = DieSnap::new(gimli::DW_TAG_formal_parameter, 2);
            parameter.type_ref = Some(2);
            dies.insert(5, parameter);
            let mut pointer = DieSnap::new(gimli::DW_TAG_pointer_type, 1);
            pointer.type_ref = Some(4);
            dies.insert(7, pointer);
            let mut callback = DieSnap::new(gimli::DW_TAG_typedef, 1);
            callback.name = "Callback".into();
            callback.type_ref = Some(7);
            dies.insert(8, callback);
            let mut value = DieSnap::new(gimli::DW_TAG_formal_parameter, 2);
            value.name = "value".into();
            value.type_ref = Some(2);
            dies.insert(10, value);
            let mut callback = DieSnap::new(gimli::DW_TAG_formal_parameter, 2);
            callback.name = "callback".into();
            callback.type_ref = Some(8);
            dies.insert(11, callback);
            let mut invoke = DieSnap::new(gimli::DW_TAG_subprogram, 1);
            invoke.type_ref = Some(3);
            invoke.children = vec![10, 11];
            let pieces = build_pieces("invoke", &invoke, &dies, &types, 1).unwrap();
            assert_eq!(pieces.innames, ["value", "callback"]);
            let code = pieces.intypes[1].get_ptr_to().unwrap();
            let view = code.read();
            let logical = view.get_code_prototype(code.id()).unwrap().unwrap();
            assert_eq!(logical.inputs, vec![pieces.intypes[0].id()]);
            assert_eq!(view.get(logical.output).unwrap().get_size(), 4);
            assert_eq!(logical.binding, types.model_binding(None).unwrap());
            assert_eq!(logical.variadic, variadic);
            assert_eq!(logical.input_closed, !variadic);
            assert_eq!(logical.logical_first, variadic.then_some(1));
            assert_ne!(logical.flags & func_proto_flags::NO_RETURN, 0);
        }
    }

    #[test]
    fn dwarf_c_unprototyped_closed_and_variadic_callables_stay_distinct() {
        for (prototyped, fixed, unspecified, expected) in [
            (None, false, true, (false, false, None)),
            (Some(true), false, false, (false, true, None)),
            (Some(true), true, true, (true, false, Some(1))),
        ] {
            let types = callable_factory();
            let mut dies = BTreeMap::new();
            let mut integer = DieSnap::new(gimli::DW_TAG_base_type, 1);
            integer.byte_size = Some(4);
            integer.encoding = Some(gimli::DW_ATE_signed);
            dies.insert(1, integer);
            let mut code = DieSnap::new(gimli::DW_TAG_subroutine_type, 1);
            code.type_ref = Some(1);
            code.language = Some(gimli::DW_LANG_C11);
            code.prototyped = prototyped;
            if fixed {
                let mut parameter = DieSnap::new(gimli::DW_TAG_formal_parameter, 2);
                parameter.type_ref = Some(1);
                dies.insert(3, parameter);
                code.children.push(3);
            }
            if unspecified {
                dies.insert(4, DieSnap::new(gimli::DW_TAG_unspecified_parameters, 2));
                code.children.push(4);
            }
            dies.insert(2, code);
            let code = build_datatype(Some(2), &dies, &types, 1, &mut TypeWalk::with_gate(true), false).unwrap();
            let view = code.read();
            let logical = view.get_code_prototype(code.id()).unwrap().unwrap();
            assert_eq!((logical.variadic, logical.input_closed, logical.logical_first), expected);
            assert_eq!(logical.inputs.len(), usize::from(fixed));
        }
    }

    #[test]
    fn dwarf_recursive_callable_reserves_identity_and_rejects_untyped_formals() {
        let types = callable_factory();
        let mut dies = BTreeMap::new();
        let mut code = DieSnap::new(gimli::DW_TAG_subroutine_type, 1);
        code.children.push(2);
        dies.insert(1, code);
        let mut parameter = DieSnap::new(gimli::DW_TAG_formal_parameter, 2);
        parameter.type_ref = Some(3);
        dies.insert(2, parameter);
        let mut pointer = DieSnap::new(gimli::DW_TAG_pointer_type, 1);
        pointer.type_ref = Some(1);
        dies.insert(3, pointer);
        let code = build_datatype(Some(1), &dies, &types, 1, &mut TypeWalk::with_gate(true), false).unwrap();
        {
            let view = code.read();
            let logical = view.get_code_prototype(code.id()).unwrap().unwrap();
            assert_eq!(view.get(logical.output).unwrap().get_metatype(), type_metatype::TYPE_VOID);
            let input = code.related(logical.inputs[0]).unwrap();
            assert_eq!(input.get_ptr_to().unwrap().id(), code.id());
        }
        let again = build_datatype(Some(1), &dies, &types, 1, &mut TypeWalk::with_gate(true), false).unwrap();
        assert_eq!(again.id(), code.id());
        let mut invalid = DieSnap::new(gimli::DW_TAG_subroutine_type, 1);
        invalid.children.push(5);
        dies.insert(4, invalid);
        dies.insert(5, DieSnap::new(gimli::DW_TAG_formal_parameter, 2));
        let mut walk = TypeWalk::with_gate(true);
        for _ in 0..3 {
            assert!(build_datatype(Some(4), &dies, &types, 1, &mut walk, false).is_none());
        }
    }

    #[test]
    fn prototypes_preserve_character_input_and_return_signedness() {
        let types = TypeFactoryImpl::new();
        types.set_default_alignment_map();
        types.set_max_basetype_size(8);
        types.setup_sizes(Some(8), 8, 4);
        types.set_core_type("int1", 1, type_metatype::TYPE_INT, false).unwrap();
        types.set_core_type("char", 1, type_metatype::TYPE_INT, true).unwrap();
        types.cache_core_types().unwrap();
        for (name, encoding, expected, text) in [
            ("unsigned char", gimli::DW_ATE_unsigned_char, type_metatype::TYPE_UINT, false),
            ("signed char", gimli::DW_ATE_signed_char, type_metatype::TYPE_INT, false),
            ("char", gimli::DW_ATE_signed_char, type_metatype::TYPE_INT, true),
            ("char", gimli::DW_ATE_unsigned_char, type_metatype::TYPE_UINT, false),
        ] {
            let mut dies = BTreeMap::new();
            let mut scalar = DieSnap::new(gimli::DW_TAG_base_type, 1);
            scalar.name = name.into();
            scalar.encoding = Some(encoding);
            scalar.byte_size = Some(1);
            dies.insert(1, scalar);
            let mut parameter = DieSnap::new(gimli::DW_TAG_formal_parameter, 1);
            parameter.name = "value".into();
            parameter.type_ref = Some(1);
            dies.insert(2, parameter);
            let mut sub = DieSnap::new(gimli::DW_TAG_subprogram, 1);
            sub.name = "character_identity".into();
            sub.type_ref = Some(1);
            sub.children.push(2);

            let resolved = kuna_cppproto::resolve_subprogram(&sub, &dies).unwrap();
            for pieces in [
                build_pieces(&sub.name, &sub, &dies, &types, 1),
                kuna_cppproto::build_pieces(&resolved, &dies, &types, 1),
            ] {
                let pieces = pieces.unwrap();
                let output = pieces.outtype.unwrap();
                assert_eq!(output.get_metatype(), expected, "return: {name}");
                assert_eq!(output.get_size(), 1);
                assert_eq!(output.is_ascii(), text, "return: {name}");
                assert_eq!(pieces.intypes[0].get_metatype(), expected, "input: {name}");
                assert_eq!(pieces.intypes[0].get_size(), 1);
                assert_eq!(pieces.intypes[0].is_ascii(), text, "input: {name}");
            }
        }
    }

    #[test]
    fn prototypes_omit_unavailable_value_layout_but_keep_opaque_pointers() {
        let types = factory();
        let mut dies = BTreeMap::new();
        let mut opaque = DieSnap::new(gimli::DW_TAG_structure_type, 1);
        opaque.name = "Forward".into();
        opaque.declaration = true;
        dies.insert(1, opaque);
        let mut alias = DieSnap::new(gimli::DW_TAG_typedef, 1);
        alias.name = "ForwardAlias".into();
        alias.type_ref = Some(1);
        dies.insert(2, alias);
        let mut pointer = DieSnap::new(gimli::DW_TAG_pointer_type, 1);
        pointer.type_ref = Some(2);
        dies.insert(3, pointer);
        let mut parameter = DieSnap::new(gimli::DW_TAG_formal_parameter, 1);
        parameter.name = "value".into();
        dies.insert(4, parameter);
        let mut sub = DieSnap::new(gimli::DW_TAG_subprogram, 1);
        sub.name = "consume".into();
        sub.children.push(4);

        for (output, input, ready) in [
            (Some(1), Some(3), false),
            (Some(2), Some(3), false),
            (None, Some(1), false),
            (None, Some(2), false),
            (Some(3), Some(3), true),
            (None, Some(3), true),
        ] {
            sub.type_ref = output;
            dies.get_mut(&4).unwrap().type_ref = input;
            let resolved = kuna_cppproto::resolve_subprogram(&sub, &dies).unwrap();
            for pieces in [
                build_pieces(&sub.name, &sub, &dies, &types, 1),
                kuna_cppproto::build_pieces(&resolved, &dies, &types, 1),
            ] {
                assert_eq!(pieces.is_some(), ready, "output={output:?}, input={input:?}");
                if let Some(pieces) = pieces {
                    let pointee = pieces.intypes[0].get_ptr_to().unwrap();
                    assert_eq!(pointee.read().get(pointee.id()).unwrap().get_name(), "ForwardAlias");
                    assert!(!pointee.read().layout_ready(pointee.id()).unwrap());
                }
            }
        }
    }

    #[test]
    fn source_code_typedef_does_not_replace_core_callable_identity() {
        let types = TypeFactoryImpl::new();
        types.set_default_alignment_map();
        types.set_max_basetype_size(8);
        types.setup_sizes(Some(8), 8, 4);
        types.set_core_type("code", 1, type_metatype::TYPE_CODE, false).unwrap();
        types.cache_core_types().unwrap();
        let core = types.get_type_code().unwrap();
        let mut dies = BTreeMap::new();
        let mut alias = DieSnap::new(gimli::DW_TAG_typedef, 1);
        alias.name = "code".into();
        alias.source_id = Some(0x1001);
        alias.type_ref = Some(2);
        dies.insert(1, alias);
        let mut record = DieSnap::new(gimli::DW_TAG_structure_type, 1);
        record.byte_size = Some(4);
        record.children.push(4);
        dies.insert(2, record);
        let mut pointer = DieSnap::new(gimli::DW_TAG_pointer_type, 1);
        pointer.type_ref = Some(1);
        dies.insert(3, pointer);
        let mut field = DieSnap::new(gimli::DW_TAG_member, 2);
        field.name = "val".into();
        field.type_ref = Some(5);
        field.data_member_location = Some(2);
        dies.insert(4, field);
        let mut scalar = DieSnap::new(gimli::DW_TAG_base_type, 1);
        scalar.name = "unsigned short".into();
        scalar.encoding = Some(gimli::DW_ATE_unsigned);
        scalar.byte_size = Some(2);
        dies.insert(5, scalar);
        let mut walk = TypeWalk::with_gate(true);
        // Install the actual member layout independently of the global gate.
        let record = kuna_dwarfstructs::intern_aggregate(
            &types, &dies[&2], &dies, Some("code"), "anon_struct",
            &mut walk, 1, false, false,
        ).unwrap();
        walk.reserve(2, record.clone());
        let pointer = build_datatype(Some(3), &dies, &types, 1, &mut walk, false).unwrap();
        let alias = pointer.get_ptr_to().unwrap();
        assert_eq!(alias.read().get(alias.id()).unwrap().get_name(), "code");
        assert_eq!(alias.get_id(), 0x1001);
        assert_eq!(alias.get_metatype(), type_metatype::TYPE_STRUCT);
        assert_ne!(alias.id(), core.id());
        assert_eq!(alias.get_typedef().unwrap().id(), record.id());
        assert_eq!(alias.get_size(), 4);
        let view = alias.read();
        let field = view.get_field(alias.id(), 0).unwrap().unwrap();
        assert_eq!(field.name, "val");
        assert_eq!(field.offset, 2);
        let scalar = view.get(field.field_type).unwrap();
        assert_eq!(scalar.get_metatype(), type_metatype::TYPE_UINT);
        assert_eq!(scalar.get_size(), 2);
        drop(view);
        assert_eq!(types.get_type_code().unwrap().id(), core.id());
        assert_eq!(
            types.find_by_source_id("code", core.get_id()).unwrap().unwrap().id(),
            core.id(),
        );
    }

    #[test]
    fn recursive_typedef_and_tag_share_completed_layout_in_both_query_orders() {
        for alias_first in [false, true] {
            let types = factory();
            let mut dies = BTreeMap::new();
            let mut alias = DieSnap::new(gimli::DW_TAG_typedef, 1);
            alias.name = "Node".into();
            alias.source_id = Some(0x1001);
            alias.type_ref = Some(2);
            dies.insert(1, alias);
            let mut node = DieSnap::new(gimli::DW_TAG_structure_type, 1);
            node.name = "Node".into();
            node.byte_size = Some(8);
            node.children.push(3);
            dies.insert(2, node);
            let mut next = DieSnap::new(gimli::DW_TAG_member, 2);
            next.name = "next".into();
            next.type_ref = Some(4);
            next.data_member_location = Some(0);
            dies.insert(3, next);
            let mut pointer = DieSnap::new(gimli::DW_TAG_pointer_type, 1);
            pointer.byte_size = Some(8);
            pointer.type_ref = Some(1);
            dies.insert(4, pointer);

            let mut walk = TypeWalk::with_gate(true);
            let early_alias = alias_first.then(|| {
                build_datatype(Some(1), &dies, &types, 1, &mut walk, false).unwrap()
            });
            // Invoke the layout arm directly so the test is independent of the
            // process-wide dwarfstructs gate.
            let node = kuna_dwarfstructs::intern_aggregate(
                &types, &dies[&2], &dies, None, "anon_struct", &mut walk, 1, false, false,
            ).unwrap();
            let alias = build_datatype(Some(1), &dies, &types, 1, &mut walk, false).unwrap();
            if let Some(early_alias) = early_alias {
                assert_eq!(early_alias.id(), alias.id());
            }
            assert_ne!(alias.id(), node.id());
            assert_eq!(alias.get_id(), 0x1001);
            assert_eq!(alias.get_typedef().unwrap().id(), node.id());
            assert_eq!(alias.get_size(), 8);
            assert!(!alias.is_incomplete());
            let mut revisit = TypeWalk::with_gate(true);
            assert_eq!(
                build_datatype(Some(1), &dies, &types, 1, &mut revisit, false).unwrap().id(),
                alias.id(),
            );
            let pointer_id = node.read().get_field(node.id(), 0).unwrap().unwrap().field_type;
            let pointer = node.related(pointer_id).unwrap();
            assert_eq!(pointer.get_ptr_to().unwrap().id(), alias.id());

            drop(types);
            let view = alias.read();
            assert_eq!(view.get(alias.id()).unwrap().get_name(), "Node");
            assert_eq!(view.get(node.id()).unwrap().get_name(), "Node");
            assert_eq!(view.get_field(node.id(), 0).unwrap().unwrap().name, "next");
            assert_eq!(view.resolve_alias(alias.id()).unwrap(), node.id());
        }
    }

    #[test]
    fn same_spelled_enum_typedef_preserves_nominal_name_and_enumerators() {
        let types = factory();
        let mut dies = BTreeMap::new();
        let mut alias = DieSnap::new(gimli::DW_TAG_typedef, 1);
        alias.name = "Mode".into();
        alias.type_ref = Some(2);
        dies.insert(1, alias);
        let mut enumeration = DieSnap::new(gimli::DW_TAG_enumeration_type, 1);
        enumeration.name = "Mode".into();
        enumeration.byte_size = Some(4);
        enumeration.children.push(3);
        dies.insert(2, enumeration);
        let mut enumerator = DieSnap::new(gimli::DW_TAG_enumerator, 2);
        enumerator.name = "Seven".into();
        enumerator.const_value = Some(7);
        dies.insert(3, enumerator);
        let mut walk = TypeWalk::with_gate(true);
        let alias = build_datatype(Some(1), &dies, &types, 1, &mut walk, false).unwrap();
        let enumeration = alias.get_typedef().unwrap();
        assert_ne!(alias.id(), enumeration.id());
        assert!(alias.is_enum_type());
        assert_eq!(alias.get_size(), 4);
        let view = alias.read();
        assert_eq!(view.get(alias.id()).unwrap().get_name(), "Mode");
        let enum_ref = view.get(enumeration.id()).unwrap();
        let DatatypeKind::Enum { namemap } = &enum_ref.kind else {
            panic!("typedef must preserve its nominal enum target");
        };
        assert_eq!(namemap.get(&7).map(String::as_str), Some("Seven"));
    }

    /// A FORGED `.debug_info` whose type chain closes on itself must terminate.
    ///
    /// This is what the recursion guard is for, and what the pre-fix depth budget
    /// conflated with "deep": a `DW_TAG_pointer_type` pointing at itself, a
    /// `typedef`/`const` pair pointing at each other, an array whose element type
    /// is the array. None is reachable from a real compiler and all are reachable
    /// from a corrupt or hostile file. The assertion is that the call RETURNS (a
    /// hang or a stack overflow is the failure).
    #[test]
    fn forged_type_cycles_terminate() {
        let types = factory();
        let mut dies: BTreeMap<usize, DieSnap> = BTreeMap::new();

        // 1: a pointer whose pointee is itself.
        let mut selfptr = DieSnap::new(gimli::DW_TAG_pointer_type, 1);
        selfptr.type_ref = Some(1);
        selfptr.byte_size = Some(8);
        dies.insert(1, selfptr);

        // 2 <-> 3: a typedef and a const pointing at each other (the qualifier
        // chain the collapse walks), reached through pointer 4.
        let mut td = DieSnap::new(gimli::DW_TAG_typedef, 1);
        td.name = "loop_t".into();
        td.type_ref = Some(3);
        dies.insert(2, td);
        let mut cst = DieSnap::new(gimli::DW_TAG_const_type, 1);
        cst.type_ref = Some(2);
        dies.insert(3, cst);
        let mut ptr = DieSnap::new(gimli::DW_TAG_pointer_type, 1);
        ptr.type_ref = Some(2);
        ptr.byte_size = Some(8);
        dies.insert(4, ptr);

        // 5: an array whose element type is the array itself.
        let mut arr = DieSnap::new(gimli::DW_TAG_array_type, 1);
        arr.type_ref = Some(5);
        arr.array_count = Some(4);
        dies.insert(5, arr);

        for cpp in [false, true] {
            for off in [1usize, 2, 4, 5] {
                let mut walk = TypeWalk::with_gate(true);
                let built = build_datatype(Some(off), &dies, &types, 1, &mut walk, cpp);
                if off == 1 || off == 4 {
                    assert!(built.is_some(), "a cyclic pointer should still build (off={off})");
                }
            }
        }
    }

    /// The same forged input under the pre-fix budget (`--option typedepth off`)
    /// also terminates — the off arm must stay safe, not just reproducible.
    #[test]
    fn forged_type_cycles_terminate_with_the_budget() {
        let types = factory();
        let mut dies: BTreeMap<usize, DieSnap> = BTreeMap::new();
        let mut selfptr = DieSnap::new(gimli::DW_TAG_pointer_type, 1);
        selfptr.type_ref = Some(1);
        selfptr.byte_size = Some(8);
        dies.insert(1, selfptr);
        let mut walk = TypeWalk::with_gate(false);
        assert!(build_datatype(Some(1), &dies, &types, 1, &mut walk, false).is_some());
    }

    /// An ordinary four-DIE C declaration (`const int *const *`) resolves under
    /// the cycle guard and truncates under the budget — the defect in one test.
    #[test]
    fn ordinary_declaration_survives_only_the_cycle_guard() {
        let types = factory();
        let mut dies: BTreeMap<usize, DieSnap> = BTreeMap::new();
        let mut leaf = DieSnap::new(gimli::DW_TAG_base_type, 1);
        leaf.name = "int".into();
        leaf.byte_size = Some(4);
        leaf.encoding = Some(gimli::DW_ATE_signed);
        dies.insert(10, leaf);
        let mut c1 = DieSnap::new(gimli::DW_TAG_const_type, 1);
        c1.type_ref = Some(10);
        dies.insert(11, c1);
        let mut p1 = DieSnap::new(gimli::DW_TAG_pointer_type, 1);
        p1.type_ref = Some(11);
        p1.byte_size = Some(8);
        dies.insert(12, p1);
        let mut c2 = DieSnap::new(gimli::DW_TAG_const_type, 1);
        c2.type_ref = Some(12);
        dies.insert(13, c2);
        let mut p2 = DieSnap::new(gimli::DW_TAG_pointer_type, 1);
        p2.type_ref = Some(13);
        p2.byte_size = Some(8);
        dies.insert(14, p2);

        let mut budget = TypeWalk::with_gate(false);
        let old = build_datatype(Some(14), &dies, &types, 1, &mut budget, false)
            .expect("a pointer always builds");
        let mut guard = TypeWalk::with_gate(true);
        let new = build_datatype(Some(14), &dies, &types, 1, &mut guard, false)
            .expect("a pointer always builds");
        let inner = |t: &TypeRoot| -> i32 {
            let one = t.get_ptr_to().expect("pointer");
            let two = one.get_ptr_to().expect("pointer to pointer");
            two.get_size()
        };
        assert_eq!(inner(&old), 0, "the budget truncates the element type to void");
        assert_eq!(inner(&new), 4, "the cycle guard keeps the 4-byte int");
    }


    /// Parse the DWARF snapshot of a fixture and return the subprogram DIEs that
    /// are *defined* (low_pc + not a declaration), as (name, low_pc).
    fn defined_subprograms(path: &str) -> Vec<(String, u64)> {
        let bytes = std::fs::read(path).expect("read dwarf fixture");
        let file = object::File::parse(bytes.as_slice()).expect("parse fixture");
        let endian = if file.is_little_endian() {
            gimli::RunTimeEndian::Little
        } else {
            gimli::RunTimeEndian::Big
        };
        let load = |id: gimli::SectionId| -> Result<Vec<u8>, gimli::Error> {
            Ok(file
                .section_by_name(id.name())
                .and_then(|s| s.uncompressed_data().ok())
                .map(|d| d.into_owned())
                .unwrap_or_default())
        };
        let sections = gimli::DwarfSections::load(load).expect("load dwarf");
        let dwarf = sections.borrow(|b| gimli::EndianSlice::new(b, endian));
        let mut found = Vec::new();
        let mut units = dwarf.units();
        while let Ok(Some(header)) = units.next() {
            let unit = dwarf.unit(header).expect("unit");
            let dies = snapshot_unit(&dwarf, &unit);
            for snap in dies.values() {
                if snap.tag == gimli::DW_TAG_subprogram
                    && !snap.declaration
                    && !snap.name.is_empty()
                {
                    if let Some(low_pc) = snap.low_pc {
                        found.push((snap.name.clone(), low_pc));
                    }
                }
            }
        }
        found
    }

    #[test]
    fn dwarf_stripped_recovers_function_names_and_addrs() {
        // dwarf_stripped_x86_64 has FUNC names ONLY in DWARF (.symtab stripped):
        // add_values@0x401136, compute@0x401153, main@0x401198. `printf` is
        // declaration-only (no low_pc) and must NOT appear.
        let path =
            concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/dwarf_stripped_x86_64");
        let defined = defined_subprograms(path);
        let by_name: BTreeMap<_, _> = defined.iter().cloned().collect();
        assert_eq!(by_name.get("add_values"), Some(&0x401136), "add_values low_pc");
        assert_eq!(by_name.get("compute"), Some(&0x401153), "compute low_pc");
        assert_eq!(by_name.get("main"), Some(&0x401198), "main low_pc");
        assert!(
            !by_name.contains_key("printf"),
            "declaration-only `printf` must be skipped, got: {defined:?}"
        );
    }

    #[test]
    fn cet_pie_recovers_elaborate_debug_symbol() {
        // cet_pie_x86_64 (not stripped, DWARF 5): elaborate_debug_symbol @ 0x1357
        // is a defined subprogram. (Names already come from .symtab here; the DWARF
        // value is the TYPED signature, asserted end-to-end in verify_s1_dwarf.rs.)
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/cet_pie_x86_64");
        let defined = defined_subprograms(path);
        let by_name: BTreeMap<_, _> = defined.iter().cloned().collect();
        assert_eq!(
            by_name.get("elaborate_debug_symbol"),
            Some(&0x1357),
            "elaborate_debug_symbol low_pc (PIE: DWARF low_pc == runtime VMA)"
        );
        // Confirm the headline param type chain resolves to a char pointer
        // structurally (the engine-level render is the e2e test). We re-snapshot
        // and walk the formal_parameter -> pointer -> const -> char(signed_char).
        let bytes = std::fs::read(path).unwrap();
        let file = object::File::parse(bytes.as_slice()).unwrap();
        let endian = gimli::RunTimeEndian::Little;
        let load = |id: gimli::SectionId| -> Result<Vec<u8>, gimli::Error> {
            Ok(file
                .section_by_name(id.name())
                .and_then(|s| s.uncompressed_data().ok())
                .map(|d| d.into_owned())
                .unwrap_or_default())
        };
        let sections = gimli::DwarfSections::load(load).unwrap();
        let dwarf = sections.borrow(|b| gimli::EndianSlice::new(b, endian));
        let mut units = dwarf.units();
        let mut found_charptr = false;
        while let Ok(Some(header)) = units.next() {
            let unit = dwarf.unit(header).unwrap();
            let dies = snapshot_unit(&dwarf, &unit);
            for snap in dies.values() {
                if snap.tag == gimli::DW_TAG_subprogram && snap.name == "elaborate_debug_symbol" {
                    // First formal parameter -> follow type to a base char.
                    let pcoff = snap
                        .children
                        .iter()
                        .find(|c| dies.get(c).map(|d| d.tag) == Some(gimli::DW_TAG_formal_parameter))
                        .copied();
                    if let Some(pcoff) = pcoff {
                        let p = &dies[&pcoff];
                        // pointer
                        let pt = dies.get(&p.type_ref.unwrap()).unwrap();
                        assert_eq!(pt.tag, gimli::DW_TAG_pointer_type, "param is a pointer");
                        // -> const -> char base_type
                        let ct = dies.get(&pt.type_ref.unwrap()).unwrap();
                        let base = dies.get(&ct.type_ref.unwrap()).unwrap();
                        assert_eq!(base.tag, gimli::DW_TAG_base_type);
                        assert_eq!(base.name, "char");
                        found_charptr = true;
                    }
                }
            }
        }
        assert!(found_charptr, "elaborate_debug_symbol's first param should be char *");
    }

    #[test]
    fn sleb128_decodes_signed_values() {
        // DWARF SLEB128 (the DW_OP_fbreg operand encoding). cet_pie's locals use
        // 0x58 = -40, 0x60 = -32, 0x68 = -24 (single-byte negatives).
        assert_eq!(read_sleb128(&[0x58]), Some((-40, 1)));
        assert_eq!(read_sleb128(&[0x60]), Some((-32, 1)));
        assert_eq!(read_sleb128(&[0x68]), Some((-24, 1)));
        // Positive and zero.
        assert_eq!(read_sleb128(&[0x00]), Some((0, 1)));
        assert_eq!(read_sleb128(&[0x02]), Some((2, 1)));
        // Multi-byte: -129 = 0xFF 0x7E, 127 = 0xFF 0x00.
        assert_eq!(read_sleb128(&[0xFF, 0x7E]), Some((-129, 2)));
        assert_eq!(read_sleb128(&[0xFF, 0x00]), Some((127, 2)));
        // Truncated -> None (never panics).
        assert_eq!(read_sleb128(&[0x80]), None);
        assert_eq!(read_sleb128(&[]), None);
    }

    /// Snapshot-parse cet_pie and confirm `elaborate_debug_symbol`'s three
    /// `DW_OP_fbreg` locals decode to the expected frame-base offsets, and that
    /// applying the x86-64 CFA constant (8) lands each at the kuna stack offset that
    /// the disassembly confirms (`-0x18`/`-0x10`/`-0x8` off `%rbp`, i.e. CFA-relative
    /// -32/-24/-16). This is the offset math the commit then wraps onto the stack
    /// space; the full name+type install render is the e2e `verify_s1_dwarf.rs` gate.
    #[test]
    fn cet_pie_fbreg_locals_and_cfa_offsets() {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/cet_pie_x86_64");
        let bytes = std::fs::read(path).unwrap();
        let file = object::File::parse(bytes.as_slice()).unwrap();
        // The fixture is x86-64 ⇒ static CFA = 8 (x86-64.dwarf `<call_frame_cfa>`).
        assert_eq!(call_frame_cfa(file.architecture()), Some(8), "x86-64 CFA == 8");
        let cfa = 8i64;

        let endian = gimli::RunTimeEndian::Little;
        let load = |id: gimli::SectionId| -> Result<Vec<u8>, gimli::Error> {
            Ok(file
                .section_by_name(id.name())
                .and_then(|s| s.uncompressed_data().ok())
                .map(|d| d.into_owned())
                .unwrap_or_default())
        };
        let sections = gimli::DwarfSections::load(load).unwrap();
        let dwarf = sections.borrow(|b| gimli::EndianSlice::new(b, endian));
        let mut units = dwarf.units();
        // (name, raw fbreg, cfa-adjusted stack offset).
        let mut found: Vec<(String, i64, i64)> = Vec::new();
        while let Ok(Some(header)) = units.next() {
            let unit = dwarf.unit(header).unwrap();
            let dies = snapshot_unit(&dwarf, &unit);
            for snap in dies.values() {
                if snap.tag == gimli::DW_TAG_subprogram && snap.name == "elaborate_debug_symbol" {
                    for &coff in &snap.children {
                        let c = &dies[&coff];
                        if matches!(c.tag, gimli::DW_TAG_variable | gimli::DW_TAG_formal_parameter) {
                            if let Some(fb) = c.fbreg_location {
                                found.push((c.name.clone(), fb, cfa.wrapping_add(fb)));
                            }
                        }
                    }
                }
            }
        }
        let by_name: BTreeMap<_, _> =
            found.iter().map(|(n, fb, off)| (n.clone(), (*fb, *off))).collect();
        // binary: fbreg -40 -> stack -32; file: -32 -> -24; elf_header: -24 -> -16.
        assert_eq!(by_name.get("binary"), Some(&(-40, -32)), "binary fbreg/offset");
        assert_eq!(by_name.get("file"), Some(&(-32, -24)), "file fbreg/offset");
        assert_eq!(by_name.get("elf_header"), Some(&(-24, -16)), "elf_header fbreg/offset");
    }
}
