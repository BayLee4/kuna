//! The ghidra-mode lazy symbol provider — kuna's port of `ScopeGhidra`
//! (`decompiler/cpp/database_ghidra.{hh,cc}`) relocated to the seam the kuna
//! engine actually reads.
//!
//! Upstream `ScopeGhidra` overrides the `Scope` virtuals; kuna deliberately
//! collapsed that polymorphism (the `Scope`/`ScopeInternal` merge,
//! `p0_knowledge/database.rs`), and the per-function pipeline reads program
//! facts through two seams instead:
//!
//!   * the frozen [`GlobalQuery`](crate::context::GlobalQuery) snapshot on the
//!     per-function [`ArchContext`](crate::context::ArchContext) (symbol
//!     names/types/properties, callee prototypes, deindirect resolution), and
//!   * the live `Architecture::symboltab` reads of the flow environment
//!     (callee display name, no-return, inline).
//!
//! [`RemoteScope`] backs BOTH with the upstream lazy query-through model: every
//! lookup consults a local cache, then — for an address inside a cspec
//! `<global>` range that has not been answered before — issues one
//! getMappedSymbols query, decodes the `<doc><mapsym>` / `<hole>` answer
//! ([`decode_mapped_answer`]), and materializes it as
//! [`GlobalEntry`](crate::context::GlobalEntry) records merged over the (empty
//! in ghidra mode) Database snapshot.  Negative answers land in a `<hole>`
//! range list so a miss is never re-queried; readonly/volatile facts fold into
//! a local property map seeded from the locked post-spec default
//! (`lockDefaultProperties`) and rolled back on [`RemoteScope::clear`] (the
//! flushNative reset).
//!
//! The wire itself is reached through the [`RemoteProviderFetch`] trait —
//! implemented in `kuna-ghidra` over the shared query client; `kuna-decomp`
//! cannot name that crate (the same dependency direction that makes
//! `EngineTranslate` a trait).  The standalone path never installs a
//! `RemoteScope`, so every seam below degrades to the frozen-snapshot behavior
//! byte-for-byte.

use std::cell::RefCell;
use std::rc::Rc;

use kuna_base::address::{Address, Range, RangeList};
use kuna_base::error::{KunaError, KunaResult};
use kuna_base::marshal::{
    AttributeId, Decoder, ElementId, IdRegistry, PackedDecode, ATTRIB_CONTENT, ATTRIB_ID,
    ATTRIB_INDEX, ATTRIB_NAME, ATTRIB_NAMELOCK, ATTRIB_READONLY, ATTRIB_SIZE,
    ATTRIB_TYPELOCK, ATTRIB_VAL, ELEM_SYMBOL,
};
use kuna_base::partmap::PartMap;
use kuna_base::space::AddrSpaceManager;
use kuna_base::types::{int4, uint4};

use crate::context::{GlobalEntry, GlobalQuery};
use crate::dtype::{Datatype, TypeFactory, TypeFactoryImpl};
use crate::funcdata_encode::ATTRIB_VOLATILE;
use crate::fspec::{ProtoModel, PrototypePieces};
use crate::varnode::varnode_flags;

// ---------------------------------------------------------------------------
// The symbol-family marshaling ids (upstream numbers, database.cc:29-43,
// fspec.cc, varmap.cc — wire-compat, NOT the kuna 4000+ range)
// ---------------------------------------------------------------------------

/// Marshaling element \<equatesymbol> (C++ `ELEM_EQUATESYMBOL`, database.cc:31).
pub const ELEM_EQUATESYMBOL: ElementId = ElementId::new("equatesymbol", 69);
/// Marshaling element \<externrefsymbol> (C++ `ELEM_EXTERNREFSYMBOL`, database.cc:32).
pub const ELEM_EXTERNREFSYMBOL: ElementId = ElementId::new("externrefsymbol", 70);
/// Marshaling element \<facetsymbol> (C++ `ELEM_FACETSYMBOL`, database.cc:33).
pub const ELEM_FACETSYMBOL: ElementId = ElementId::new("facetsymbol", 71);
/// Marshaling element \<functionshell> (C++ `ELEM_FUNCTIONSHELL`, database.cc:34).
pub const ELEM_FUNCTIONSHELL: ElementId = ElementId::new("functionshell", 72);
/// Marshaling element \<hash> (C++ `ELEM_HASH`, database.cc:35).
pub const ELEM_HASH: ElementId = ElementId::new("hash", 73);
/// Marshaling element \<hole> (C++ `ELEM_HOLE`, database.cc:36).
pub const ELEM_HOLE: ElementId = ElementId::new("hole", 74);
/// Marshaling element \<labelsym> (C++ `ELEM_LABELSYM`, database.cc:37).
pub const ELEM_LABELSYM: ElementId = ElementId::new("labelsym", 75);
/// Marshaling element \<mapsym> (C++ `ELEM_MAPSYM`, database.cc:38).
pub const ELEM_MAPSYM: ElementId = ElementId::new("mapsym", 76);
/// Marshaling element \<parent> (C++ `ELEM_PARENT`, database.cc:39).
pub const ELEM_PARENT: ElementId = ElementId::new("parent", 77);
/// Marshaling element \<scope> (C++ `ELEM_SCOPE`, database.cc:42).
pub const ELEM_SCOPE: ElementId = ElementId::new("scope", 80);
/// Marshaling element \<symbollist> (C++ `ELEM_SYMBOLLIST`, database.cc:43).
pub const ELEM_SYMBOLLIST: ElementId = ElementId::new("symbollist", 81);
/// Marshaling element \<internallist> (C++ `ELEM_INTERNALLIST`, fspec.cc:39).
pub const ELEM_INTERNALLIST: ElementId = ElementId::new("internallist", 161);
/// Marshaling element \<prototype> (C++ `ELEM_PROTOTYPE`, fspec.cc:47).
pub const ELEM_PROTOTYPE: ElementId = ElementId::new("prototype", 169);
/// Marshaling element \<returnsym> (C++ `ELEM_RETURNSYM`, fspec.cc:50).
pub const ELEM_RETURNSYM: ElementId = ElementId::new("returnsym", 172);
/// Marshaling element \<localdb> (C++ `ELEM_LOCALDB`, varmap.cc:24).
pub const ELEM_LOCALDB: ElementId = ElementId::new("localdb", 228);

/// Marshaling attribute "cat" (C++ `ATTRIB_CAT`, database.cc:23).
pub const ATTRIB_CAT: AttributeId = AttributeId::new("cat", 61);
/// Marshaling attribute "merge" (C++ `ATTRIB_MERGE`, database.cc:25).
pub const ATTRIB_MERGE: AttributeId = AttributeId::new("merge", 63);
/// Marshaling attribute "custom" (C++ `ATTRIB_CUSTOM`, fspec.cc:21).
pub const ATTRIB_CUSTOM: AttributeId = AttributeId::new("custom", 114);
/// Marshaling attribute "dotdotdot" (C++ `ATTRIB_DOTDOTDOT`, fspec.cc:22).
pub const ATTRIB_DOTDOTDOT: AttributeId = AttributeId::new("dotdotdot", 115);
/// Marshaling attribute "inline" (C++ `ATTRIB_INLINE`, fspec.cc:25).
pub const ATTRIB_INLINE: AttributeId = AttributeId::new("inline", 118);
/// Marshaling attribute "modellock" (C++ `ATTRIB_MODELLOCK`, fspec.cc:29).
pub const ATTRIB_MODELLOCK: AttributeId = AttributeId::new("modellock", 122);
/// Marshaling attribute "noreturn" (C++ `ATTRIB_NORETURN`, fspec.cc:30).
pub const ATTRIB_NORETURN: AttributeId = AttributeId::new("noreturn", 123);
/// Marshaling attribute "voidlock" (C++ `ATTRIB_VOIDLOCK`, fspec.cc:36).
pub const ATTRIB_VOIDLOCK: AttributeId = AttributeId::new("voidlock", 129);
/// Marshaling attribute "lock" (C++ `ATTRIB_LOCK`, varmap.cc:21).
pub const ATTRIB_LOCK: AttributeId = AttributeId::new("lock", 133);
/// Marshaling attribute "main" (C++ `ATTRIB_MAIN`, varmap.cc:22).
pub const ATTRIB_MAIN: AttributeId = AttributeId::new("main", 134);
/// Marshaling attribute "extrapop" (C++ `ATTRIB_EXTRAPOP`, fspec.cc — id 6;
/// the value is either a signed integer or the string "unknown").
pub const ATTRIB_EXTRAPOP: AttributeId = AttributeId::new("extrapop", 6);

/// Register the symbol-family wire ids (XML-form documents only; the packed
/// wire form matches by number).
pub fn register_remote_provider_ids(reg: &mut IdRegistry) {
    for e in [
        &ELEM_EQUATESYMBOL,
        &ELEM_EXTERNREFSYMBOL,
        &ELEM_FACETSYMBOL,
        &ELEM_FUNCTIONSHELL,
        &ELEM_HASH,
        &ELEM_HOLE,
        &ELEM_LABELSYM,
        &ELEM_MAPSYM,
        &ELEM_PARENT,
        &ELEM_SCOPE,
        &ELEM_SYMBOLLIST,
        &ELEM_INTERNALLIST,
        &ELEM_PROTOTYPE,
        &ELEM_RETURNSYM,
        &ELEM_LOCALDB,
    ] {
        reg.register_element(e);
    }
    for a in [
        &ATTRIB_CAT,
        &ATTRIB_MERGE,
        &ATTRIB_CUSTOM,
        &ATTRIB_DOTDOTDOT,
        &ATTRIB_INLINE,
        &ATTRIB_MODELLOCK,
        &ATTRIB_NORETURN,
        &ATTRIB_VOIDLOCK,
        &ATTRIB_LOCK,
        &ATTRIB_MAIN,
        &ATTRIB_EXTRAPOP,
    ] {
        reg.register_attribute(a);
    }
}

// ---------------------------------------------------------------------------
// The wire-fetch seam (implemented in kuna-ghidra over the shared client)
// ---------------------------------------------------------------------------

/// The remote query surface a [`RemoteScope`] pulls program facts through —
/// one method per wire query, each ingesting the packed response into a
/// caller-supplied decoder (matching the `GhidraClient` signatures).
pub trait RemoteProviderFetch {
    /// Constant-pool acquisition. An empty host answer is authoritative.
    fn fetch_cpool_ref(&self, _refs: &[u64], _decoder: &mut dyn Decoder) -> KunaResult<bool> {
        Ok(false)
    }
    /// Host-translated UTF-8, including its terminator, and truncation status.
    /// Empty data is an authoritative refusal, not permission to read raw bytes.
    fn fetch_string_data(
        &self,
        _addr: &Address,
        _max_bytes: int4,
        _datatype: &Datatype,
    ) -> KunaResult<(Vec<u8>, bool)> {
        Ok((Vec::new(), false))
    }
    /// getMappedSymbols(addr): `Ok(false)` = empty response (no answer at all).
    fn fetch_mapped_symbols(
        &self,
        addr: &Address,
        decoder: &mut dyn Decoder,
    ) -> KunaResult<bool>;
    /// getNamespacePath(id): the `<parent>` document for a scope id.
    fn fetch_namespace_path(&self, id: u64, decoder: &mut dyn Decoder) -> KunaResult<bool>;
    /// getExternalRef(addr): the resolved `<doc><mapsym>` for an external
    /// reference's POINTER address; `Ok(false)` = unresolvable.
    fn fetch_external_ref(&self, addr: &Address, decoder: &mut dyn Decoder) -> KunaResult<bool>;
    /// getTrackedRegisters(addr): the `<tracked_pointset>` for an address
    /// (always written by the host, possibly empty).
    fn fetch_tracked_registers(
        &self,
        addr: &Address,
        decoder: &mut dyn Decoder,
    ) -> KunaResult<bool>;
    /// getComments(addr, flags): the `<commentdb>` for a function.
    fn fetch_comments(
        &self,
        fad: &Address,
        flags: u32,
        decoder: &mut dyn Decoder,
    ) -> KunaResult<bool>;
    /// isNameUsed(name, start, stop): is `name` a symbol in the host namespace
    /// `start` or one of its parents below `stop` (0 = up to global)?
    fn fetch_is_name_used(&self, _name: &str, _start: u64, _stop: u64) -> KunaResult<bool> {
        Ok(false)
    }
}

// ---------------------------------------------------------------------------
// Decoded answer shapes
// ---------------------------------------------------------------------------

/// One decoded getMappedSymbols answer.
pub enum RemoteMapAnswer {
    /// `<hole>`: no symbol over the covering range; flags are the
    /// readonly/volatile property paint.
    Hole {
        /// The covering range.
        range: Range,
        /// `varnode_flags::readonly | varnode_flags::volatil` subset.
        flags: uint4,
    },
    /// A `<doc id=…><mapsym>` symbol answer.
    Symbol(Box<RemoteSymbolRecord>),
}

/// One mapped storage of a decoded symbol.
#[derive(Clone)]
pub struct RemoteEntry {
    /// Starting address of the storage; invalid for a DYNAMIC (`<hash>`)
    /// entry, whose identity is [`Self::hash`] plus the uselimit's first-use
    /// address.
    pub addr: Address,
    /// Byte size of the storage.
    pub size: int4,
    /// The data-flow hash of a DYNAMIC entry (C++ `DynamicEntry::hash`), 0 for
    /// ordinary mapped storage.
    pub hash: u64,
    /// Code-address ranges where the storage is in use (empty = address-tied).
    pub uselimit: RangeList,
}

/// A decoded `<mapsym>` symbol (the fields the kuna seams consume; everything
/// else is skipped with `close_element_skipping` semantics).
#[derive(Clone)]
pub struct RemoteSymbolRecord {
    /// The `<doc>` wrapper's namespace/scope id (0 = global).
    pub scope_id: u64,
    /// The real host database symbol id (0 = none delivered).
    pub symbol_id: u64,
    /// Symbol name.
    pub name: String,
    /// Display name (`label` when the host sent a simplified form).
    pub display_name: String,
    /// `varnode_flags` subset: typelock/namelock/readonly/volatil/externref.
    pub flags: uint4,
    /// Symbol category (-1 none, 0 = function parameter).
    pub category: i64,
    /// Category index (parameter slot) when `category == 0`.
    pub cat_index: u64,
    /// Whether this is the host's AUTO hidden-return storage parameter.
    pub hidden_return: bool,
    pub(crate) parameter_flags: uint4,
    /// The decoded data-type (data symbols; `None` for label/function shells).
    pub dtype: Option<Rc<Datatype>>,
    /// The mapped storage entries.
    pub entries: Vec<RemoteEntry>,
    /// Present when the symbol is a function (`<function>`/`<functionshell>`).
    pub func: Option<RemoteFunction>,
    /// `<externrefsymbol>`: the address the external reference resolves to
    /// (the callee body); the mapping entries are the POINTER's storage.
    pub extern_ref: Option<Address>,
}

/// A decoded `<function>` answer (C++ `FunctionSymbol::decode` →
/// `Funcdata::decode`, reduced to the facts the Phase-3 seams consume).
#[derive(Clone)]
pub struct RemoteFunction {
    /// Function name (the Java `Function.getName()` — the decompileAt echo name).
    pub name: String,
    /// Display name (`label` fallback to name).
    pub display_name: String,
    /// The host database function/symbol id.
    pub id: u64,
    /// Entry address.
    pub entry: Address,
    /// The `size` attribute (`diff+1` for interior queries; NOT the body size).
    pub size: i64,
    /// `Function.hasNoReturn()` — the flow-truncation fact.
    pub no_return: bool,
    /// `Function.isInline()`.
    pub inline: bool,
    /// The decoded `<prototype>` (+ `<localdb>` cat-0 params), when present.
    pub proto: Option<RemoteProto>,
    /// Complete non-parameter `<localdb>` symbols supplied by the host.
    pub locals: Vec<Rc<RemoteSymbolRecord>>,
    pub overrides: Rc<crate::overrides::Override>,
}

/// A decoded `<prototype>` plus the `<localdb>` category-0 parameters.
#[derive(Clone)]
pub struct RemoteProto {
    complete: Rc<crate::fspec::FuncProto>,
    /// Prototype model name.
    pub model: String,
    /// `extrapop`; `None` = the wire string "unknown".
    pub extrapop: Option<i64>,
    /// Varargs marker.
    pub dotdotdot: bool,
    /// Void-input lock (a locked `void` parameter list).
    pub voidlock: bool,
    /// Prototype-level no-return.
    pub no_return: bool,
    /// Return-type lock.
    pub out_lock: bool,
    /// The decoded return type.
    pub out_type: Option<Rc<Datatype>>,
    /// Exact return storage from the host's `<returnsym><addr>`.
    pub out_storage: Address,
    /// Whether Ghidra declared custom variable storage for this prototype.
    pub custom: bool,
    /// Parameters from the `<localdb>` cat-0 symbols, sorted by slot index.
    pub params: Vec<RemoteParam>,
    /// Whether every parameter carried `typelock` (a locked signature).
    pub params_locked: bool,
    /// The call-fixup the host attached to the function (`<inject>`), which
    /// replaces every call to it.
    pub inject: Option<String>,
}

/// One category-0 (parameter) symbol.
#[derive(Clone)]
pub struct RemoteParam {
    /// Parameter slot (`index` attribute).
    pub index: u64,
    /// Parameter name.
    pub name: String,
    /// Parameter data-type.
    pub dtype: Option<Rc<Datatype>>,
    /// The symbol's typelock bit.
    pub typelock: bool,
    /// The parameter's EXACT committed storage (the cat-0 mapsym's `<addr>`).
    /// Java's `checkFullCommit` compares kuna's echoed storage against the
    /// database's; re-deriving it from a default model instead (the Phase-4
    /// behavior before this) makes every rename of a nonstandard-convention
    /// function force-commit a kuna-rederived signature over the user's.
    /// Invalid when the host sent a dynamic/hash entry.
    pub storage: Address,
    /// The host's AUTO hidden-return parameter, re-derived by the prototype model.
    pub hidden: bool,
    pub flags: uint4,
    pub usepoint: Address,
    pub symbol: Option<Rc<RemoteSymbolRecord>>,
}

impl RemoteProto {
    /// Whether this prototype is locked enough to seed call-site/param
    /// recovery (the `parse line extern` analogue): a locked-void input list,
    /// or a non-empty all-typelocked parameter list.
    pub fn is_input_locked(&self) -> bool {
        self.voidlock || (!self.params.is_empty() && self.params_locked)
    }

    /// Flatten to the [`PrototypePieces`] the kuna callee-prototype seams
    /// consume (`ActionDefaultParams` / `query_callee_proto`'s `TypeCode`).
    pub fn to_pieces(&self, name: &str) -> PrototypePieces {
        let mut pieces = PrototypePieces {
            name: name.to_string(),
            outtype: self.out_type.clone(),
            intypes: Vec::new(),
            innames: Vec::new(),
            first_var_arg_slot: if self.dotdotdot {
                self.params
                    .iter()
                    .filter(|p| !p.hidden && p.dtype.is_some())
                    .count() as int4
            } else {
                -1
            },
            output_storage: None,
            input_storage: Vec::new(),
            kuna_library_names: None,
        };
        if self.custom {
            pieces.output_storage = self.out_type.as_ref().map(|ct| {
                crate::fspec::ParameterPieces {
                    addr: self.out_storage.clone(),
                    type_: Some(Rc::clone(ct)),
                    flags: crate::fspec::parameter_pieces_flags::TYPELOCK
                        | crate::fspec::parameter_pieces_flags::CUSTOM_STORAGE,
                }
            });
        }
        for p in &self.params {
            if p.hidden {
                continue;
            }
            if let Some(ct) = &p.dtype {
                pieces.intypes.push(Rc::clone(ct));
                pieces.innames.push(p.name.clone());
                if self.custom && !p.storage.is_invalid() {
                    let slot = (pieces.intypes.len() - 1) as int4;
                    pieces.input_storage.push((
                        slot,
                        crate::fspec::ParameterPieces {
                            addr: p.storage.clone(),
                            type_: Some(Rc::clone(ct)),
                            flags: crate::fspec::parameter_pieces_flags::TYPELOCK
                                | crate::fspec::parameter_pieces_flags::NAMELOCK
                                | crate::fspec::parameter_pieces_flags::CUSTOM_STORAGE,
                        },
                    ));
                }
            }
        }
        pieces
    }
}

// ---------------------------------------------------------------------------
// The <doc>/<mapsym>/<hole> decoder (database.cc Scope::addMapSym family)
// ---------------------------------------------------------------------------

/// Decode one getMappedSymbols/getExternalRef response: a bare `<hole>` or a
/// `<doc id=…>` wrapping one `<mapsym>` (C++ `ScopeGhidra::dump2Cache`,
/// database_ghidra.cc:101-173).
pub fn decode_mapped_answer(
    decoder: &mut dyn Decoder,
    types: &TypeFactoryImpl,
) -> KunaResult<RemoteMapAnswer> {
    if decoder.peek_element()? == ELEM_HOLE.get_id() {
        return decode_hole(decoder);
    }
    // The <doc> wrapper: upstream does not validate its element id, only the
    // namespace id attribute.
    let doc_id = decoder.open_element()?;
    let scope_id = decoder.read_unsigned_integer_id(&ATTRIB_ID).unwrap_or(0);
    let rec = decode_mapsym(decoder, types, scope_id)?;
    decoder.close_element_skipping(doc_id)?;
    Ok(RemoteMapAnswer::Symbol(Box::new(rec)))
}

/// Decode a `<hole>` (C++ `ScopeGhidra::decodeHole`, database_ghidra.cc:72-94):
/// the covering range from `Range::decodeFromAttributes`, then a rewound scan
/// for the readonly/volatile paint.
fn decode_hole(decoder: &mut dyn Decoder) -> KunaResult<RemoteMapAnswer> {
    let elem_id = decoder.open_element()?;
    let range = Range::decode_from_attributes(decoder)?;
    let mut flags: uint4 = 0;
    decoder.rewind_attributes();
    loop {
        let aid = decoder.get_next_attribute_id()?;
        if aid == 0 {
            break;
        }
        if aid == ATTRIB_READONLY.get_id() && decoder.read_bool()? {
            flags |= varnode_flags::readonly;
        } else if aid == ATTRIB_VOLATILE.get_id() && decoder.read_bool()? {
            flags |= varnode_flags::volatil;
        }
    }
    decoder.close_element(elem_id)?;
    Ok(RemoteMapAnswer::Hole { range, flags })
}

/// Decode one `<mapsym>`: the symbol element (dispatch on the first child id,
/// C++ `Scope::addMapSym`, database.cc:1568-1610) followed by the SymbolEntry
/// list.
pub fn decode_mapsym(
    decoder: &mut dyn Decoder,
    types: &TypeFactoryImpl,
    scope_id: u64,
) -> KunaResult<RemoteSymbolRecord> {
    let elem_id = decoder.open_element_id(&ELEM_MAPSYM)?;
    let sub = decoder.peek_element()?;
    let mut rec = if sub == ELEM_SYMBOL.get_id() || sub == ELEM_FACETSYMBOL.get_id() {
        // <symbol>: header attributes + one type child.  A <facetsymbol> is the
        // same shape plus a union-facet field attribute the scan skips.
        let sid = decoder.open_element()?;
        let mut rec = decode_symbol_header(decoder, scope_id)?;
        rec.dtype = Some(types.decode_type(decoder)?);
        decoder.close_element_skipping(sid)?;
        rec
    } else if sub == ELEM_EQUATESYMBOL.get_id() {
        // <equatesymbol>: header + <value>; renders as a named constant.  The
        // kuna equate surface is out of Phase-3 scope, so only the name/flags
        // survive (the mapping entry still marks the range answered).
        let sid = decoder.open_element()?;
        let rec = decode_symbol_header(decoder, scope_id)?;
        decoder.close_element_skipping(sid)?;
        rec
    } else if sub == ELEM_LABELSYM.get_id() {
        let sid = decoder.open_element()?;
        let rec = decode_symbol_header(decoder, scope_id)?;
        decoder.close_element_skipping(sid)?;
        rec
    } else if sub == ELEM_EXTERNREFSYMBOL.get_id() {
        // <externrefsymbol name?> + <addr> (the resolve address).  The name is
        // what a deindirected read of the pointer prints (C++ buildNameType).
        let sid = decoder.open_element()?;
        let mut name = String::new();
        loop {
            let aid = decoder.get_next_attribute_id()?;
            if aid == 0 {
                break;
            }
            if aid == ATTRIB_NAME.get_id() {
                name = String::from_utf8_lossy(&decoder.read_string()?).into_owned();
            }
        }
        let refaddr = Address::decode(decoder)?;
        decoder.close_element_skipping(sid)?;
        RemoteSymbolRecord {
            scope_id,
            symbol_id: 0,
            display_name: name.clone(),
            name,
            // ExternRefSymbol::buildNameType: the externref flag is what lets
            // ActionDeindirect resolve a call through the pointer.
            flags: varnode_flags::externref | varnode_flags::typelock,
            category: -1,
            cat_index: 0,
            hidden_return: false,
            parameter_flags: 0,
            // C++ ExternRefSymbol::buildNameType: the pointer's type is
            // pointer-to-code (glb->types->getTypePointer(...getTypeCode())).
            dtype: types
                .get_type_code()
                .and_then(|code| {
                    let sz = refaddr
                        .get_space()
                        .map(|s| s.get_addr_size() as i32)
                        .unwrap_or(8);
                    types.get_type_pointer(sz, code, 1)
                })
                .ok(),
            entries: Vec::new(),
            func: None,
            extern_ref: Some(refaddr),
        }
    } else if sub == crate::funcdata_encode::ELEM_FUNCTION.get_id()
        || sub == ELEM_FUNCTIONSHELL.get_id()
    {
        let func = decode_wire_function(decoder, types)?;
        RemoteSymbolRecord {
            scope_id,
            symbol_id: func.id,
            name: func.name.clone(),
            display_name: func.display_name.clone(),
            // FunctionSymbol::buildType: namelock|typelock (database.cc).
            flags: varnode_flags::namelock | varnode_flags::typelock,
            category: -1,
            cat_index: 0,
            hidden_return: false,
            parameter_flags: 0,
            dtype: None,
            entries: Vec::new(),
            func: Some(func),
            extern_ref: None,
        }
    } else {
        return Err(KunaError::lowlevel("Unknown symbol type"));
    };
    // The SymbolEntry list: <hash val=…>|<addr…> then a <rangelist> each
    // (SymbolEntry::decode, database.cc:206-221).
    while decoder.peek_element()? != 0 {
        // A DYNAMIC entry carries the data-flow hash INSTEAD of an address
        // (`DynamicEntry::decode`, database.cc:69-74); keeping it is what lets
        // a rename of a unique-space / split-merge-group variable round-trip.
        let (addr, size, hash) = if decoder.peek_element()? == ELEM_HASH.get_id() {
            let hid = decoder.open_element()?;
            let hash = decoder.read_unsigned_integer_id(&ATTRIB_VAL)?;
            decoder.close_element(hid)?;
            (Address::new_invalid(), 0, hash)
        } else {
            let (a, sz) = Address::decode_sized(decoder)?;
            (a, sz, 0)
        };
        let mut uselimit = RangeList::default();
        uselimit.decode(decoder)?;
        rec.entries.push(RemoteEntry {
            addr,
            size: size as int4,
            hash,
            uselimit,
        });
    }
    decoder.close_element(elem_id)?;
    // Scope::addMap sizes an entry by the symbol's bytes consumed, not by the
    // wire storage: Java maps an import slot as one byte, yet it is read as a
    // whole pointer.
    if rec.extern_ref.is_some() {
        if let Some(size) = rec.dtype.as_ref().map(|t| t.get_size()) {
            for e in rec.entries.iter_mut().filter(|e| !e.addr.is_invalid()) {
                e.size = size;
            }
        }
    }
    Ok(rec)
}

/// Decode the shared symbol-header attributes (C++ `Symbol::decodeHeader`,
/// database.cc:394-471) of an already-opened symbol element.
fn decode_symbol_header(
    decoder: &mut dyn Decoder,
    scope_id: u64,
) -> KunaResult<RemoteSymbolRecord> {
    let mut rec = RemoteSymbolRecord {
        scope_id,
        symbol_id: 0,
        name: String::new(),
        display_name: String::new(),
        flags: 0,
        category: -1,
        cat_index: 0,
        hidden_return: false,
        parameter_flags: 0,
        dtype: None,
        entries: Vec::new(),
        func: None,
        extern_ref: None,
    };
    loop {
        let aid = decoder.get_next_attribute_id()?;
        if aid == 0 {
            break;
        }
        if aid == ATTRIB_NAME.get_id() {
            rec.name = String::from_utf8_lossy(&decoder.read_string()?).into_owned();
        } else if aid == crate::jumptable::ATTRIB_LABEL.get_id() {
            rec.display_name = String::from_utf8_lossy(&decoder.read_string()?).into_owned();
        } else if aid == ATTRIB_ID.get_id() {
            let id = decoder.read_unsigned_integer()?;
            // Ids in the decompiler-internal 0x4000… range are never real
            // database ids (HighSymbol.ID_BASE); zero them like upstream.
            rec.symbol_id = if (id >> 56) == 0x40 { 0 } else { id };
        } else if aid == ATTRIB_TYPELOCK.get_id() {
            if decoder.read_bool()? {
                rec.flags |= varnode_flags::typelock;
            }
        } else if aid == ATTRIB_NAMELOCK.get_id() {
            if decoder.read_bool()? {
                rec.flags |= varnode_flags::namelock;
            }
        } else if aid == ATTRIB_READONLY.get_id() {
            if decoder.read_bool()? {
                rec.flags |= varnode_flags::readonly;
            }
        } else if aid == ATTRIB_VOLATILE.get_id() {
            if decoder.read_bool()? {
                rec.flags |= varnode_flags::volatil;
            }
        } else if aid == ATTRIB_CAT.get_id() {
            rec.category = decoder.read_signed_integer()?;
        } else if aid == ATTRIB_INDEX.get_id() {
            rec.cat_index = decoder.read_unsigned_integer()?;
        } else if aid == kuna_base::marshal::ATTRIB_HIDDENRETPARM.get_id() {
            rec.hidden_return = decoder.read_bool()?;
        } else if aid == kuna_base::marshal::ATTRIB_THISPTR.get_id() {
            if decoder.read_bool()? { rec.parameter_flags |= crate::fspec::parameter_pieces_flags::ISTHIS; }
        } else if aid == kuna_base::marshal::ATTRIB_INDIRECTSTORAGE.get_id() {
            if decoder.read_bool()? { rec.parameter_flags |= crate::fspec::parameter_pieces_flags::INDIRECTSTORAGE; }
        }
        // merge/thisptr/format/indirectstorage: skipped (the
        // Phase-3 seams do not consume them).
    }
    if rec.display_name.is_empty() {
        rec.display_name = rec.name.clone();
    }
    Ok(rec)
}

/// Decode a `<function>`/`<functionshell>` answer (C++ `FunctionSymbol::decode`
/// → `Funcdata::decode`, funcdata.cc:764-835, reduced): the header attributes,
/// the entry `<addr>`, the `<localdb>` cat-0 parameters, and the `<prototype>`.
/// Everything else (`<jumptablelist>`, `<override>`, unknown children) is
/// skipped whole.
fn decode_wire_function(
    decoder: &mut dyn Decoder,
    types: &TypeFactoryImpl,
) -> KunaResult<RemoteFunction> {
    let elem_id = decoder.open_element()?;
    let mut func = RemoteFunction {
        name: String::new(),
        display_name: String::new(),
        id: 0,
        entry: Address::new_invalid(),
        size: 1,
        no_return: false,
        inline: false,
        proto: None,
        locals: Vec::new(),
        overrides: Rc::new(crate::overrides::Override::new()),
    };
    loop {
        let aid = decoder.get_next_attribute_id()?;
        if aid == 0 {
            break;
        }
        if aid == ATTRIB_NAME.get_id() {
            func.name = String::from_utf8_lossy(&decoder.read_string()?).into_owned();
        } else if aid == crate::jumptable::ATTRIB_LABEL.get_id() {
            func.display_name = String::from_utf8_lossy(&decoder.read_string()?).into_owned();
        } else if aid == ATTRIB_ID.get_id() {
            func.id = decoder.read_unsigned_integer()?;
        } else if aid == ATTRIB_SIZE.get_id() {
            func.size = decoder.read_signed_integer()?;
        } else if aid == ATTRIB_NORETURN.get_id() {
            func.no_return = decoder.read_bool()?;
        } else if aid == ATTRIB_INLINE.get_id() {
            func.inline = decoder.read_bool()?;
        }
    }
    if func.display_name.is_empty() {
        func.display_name = func.name.clone();
    }
    // First child: the entry <addr> (possibly attribute-less for a shell).
    if decoder.peek_element()? != 0 {
        func.entry = Address::decode(decoder)?;
    }
    let mut params: Vec<RemoteParam> = Vec::new();
    let mut params_locked = true;
    let mut proto: Option<RemoteProto> = None;
    while decoder.peek_element()? != 0 {
        let sub = decoder.peek_element()?;
        if sub == ELEM_LOCALDB.get_id() {
            decode_localdb_params(
                decoder,
                types,
                &mut params,
                &mut params_locked,
                &mut func.locals,
            )?;
        } else if sub == ELEM_PROTOTYPE.get_id() {
            proto = Some(decode_prototype(decoder, types)?);
        } else if sub == crate::overrides::ELEM_OVERRIDE.get_id() {
            let mut overrides = crate::overrides::Override::new();
            overrides.decode(decoder, &mut |decoder| {
                Ok(Box::new(types.decode_proto(decoder, crate::fspec::PrototypeDecoding::LogicalCallable)?))
            })?;
            func.overrides = Rc::new(overrides);
        } else {
            let sid = decoder.open_element()?;
            decoder.close_element_skipping(sid)?;
        }
    }
    decoder.close_element(elem_id)?;
    if let Some(mut p) = proto {
        params.sort_by_key(|p| p.index);
        if !params.is_empty() {
            p.params = params;
            p.params_locked = params_locked;
        }
        func.proto = Some(p);
    }
    Ok(func)
}

/// Walk `<localdb><scope>…<symbollist>` collecting the category-0 (parameter)
/// symbols (Java `LocalSymbolMap.encodeLocalDb`; C++ params come from the
/// scope's category vector, database.cc:1831-1840) plus the non-parameter
/// locals, retaining their source identity and complete mappings.
fn decode_localdb_params(
    decoder: &mut dyn Decoder,
    types: &TypeFactoryImpl,
    params: &mut Vec<RemoteParam>,
    params_locked: &mut bool,
    locals: &mut Vec<Rc<RemoteSymbolRecord>>,
) -> KunaResult<()> {
    let localdb_id = decoder.open_element_id(&ELEM_LOCALDB)?;
    // lock/main attributes: not consumed.
    while decoder.peek_element()? != 0 {
        let sub = decoder.peek_element()?;
        if sub != ELEM_SCOPE.get_id() {
            let sid = decoder.open_element()?;
            decoder.close_element_skipping(sid)?;
            continue;
        }
        let scope_el = decoder.open_element()?;
        while decoder.peek_element()? != 0 {
            let inner = decoder.peek_element()?;
            if inner == ELEM_SYMBOLLIST.get_id() {
                let list_el = decoder.open_element()?;
                while decoder.peek_element()? != 0 {
                    if decoder.peek_element()? != ELEM_MAPSYM.get_id() {
                        let sid = decoder.open_element()?;
                        decoder.close_element_skipping(sid)?;
                        continue;
                    }
                    let rec = decode_mapsym(decoder, types, 0)?;
                    if rec.category == 0 {
                            let symbol = Rc::new(rec.clone());
                        if (rec.flags & varnode_flags::typelock) == 0 {
                            *params_locked = false;
                        }
                        let storage = rec
                            .entries
                            .iter()
                            .find(|e| !e.addr.is_invalid())
                            .map(|e| e.addr.clone())
                            .unwrap_or_else(Address::new_invalid);
                        params.push(RemoteParam {
                            index: rec.cat_index,
                            name: rec.display_name,
                            dtype: rec.dtype,
                            typelock: (rec.flags & varnode_flags::typelock) != 0,
                            storage,
                            hidden: rec.hidden_return,
                            flags: rec.parameter_flags | (if rec.flags & varnode_flags::typelock != 0 { crate::fspec::parameter_pieces_flags::TYPELOCK } else { 0 })
                                | (if rec.flags & varnode_flags::namelock != 0 { crate::fspec::parameter_pieces_flags::NAMELOCK } else { 0 })
                                | (if rec.hidden_return { crate::fspec::parameter_pieces_flags::HIDDENRETPARM } else { 0 }),
                            usepoint: rec.entries.iter().flat_map(|e| e.uselimit.iter()).next()
                                .map(|r| Address::new(r.get_space().clone(), r.get_first()))
                                .unwrap_or_else(Address::new_invalid),
                            symbol: Some(symbol),
                        });
                    } else if rec.category < 0 {
                        locals.push(Rc::new(rec));
                    }
                }
                decoder.close_element(list_el)?;
            } else {
                // <parent>/<rangelist>: structurally consumed.
                let sid = decoder.open_element()?;
                decoder.close_element_skipping(sid)?;
            }
        }
        decoder.close_element(scope_el)?;
    }
    decoder.close_element(localdb_id)?;
    Ok(())
}

/// Decode a `<prototype>` (C++ `FuncProto::decode`, fspec.cc:4675-4840,
/// reduced to model/extrapop/flags + the `<returnsym>` type).
fn decode_prototype(
    decoder: &mut dyn Decoder,
    types: &TypeFactoryImpl,
) -> KunaResult<RemoteProto> {
    let complete = Rc::new(types.decode_proto(decoder, crate::fspec::PrototypeDecoding::PhysicalEntry)?);
    let params: Vec<_> = (0..complete.num_params()).filter_map(|i| complete.get_param(i).map(|p| RemoteParam {
        index: i as u64, name: p.get_name().to_owned(), dtype: p.get_type().cloned(),
        typelock: p.is_type_locked(), storage: p.get_address(), hidden: p.is_hidden_return(),
        flags: p.get_flags(), usepoint: Address::new_invalid(),
        symbol: None,
    })).collect();
    Ok(RemoteProto {
        model: complete.declared_model_name().to_owned(),
        extrapop: if complete.get_extra_pop() == crate::fspec::EXTRAPOP_UNKNOWN { None } else { Some(complete.get_extra_pop() as i64) },
        dotdotdot: complete.is_dotdotdot(), voidlock: complete.is_input_locked() && params.is_empty(),
        no_return: complete.is_no_return(), out_lock: complete.is_output_locked(),
        out_type: complete.get_output_type().cloned(), out_storage: complete.get_output().get_address(),
        custom: complete.has_custom_storage(), params_locked: params.iter().all(|p| p.typelock),
        params, inject: complete.injection_name()?, complete,
    })
}

/// Decode a `<parent>` namespace-path answer (C++ `Database::decodeScopePath`,
/// database.cc:3399-3429): the first `<val>` is the (skipped) root scope; each
/// further `<val id=… [label=…]>name</val>` is one nesting level, outermost
/// first.  Returns the display names, INNERMOST FIRST (the
/// `GlobalEntry::scope_path` convention), global excluded.
pub fn decode_namespace_path(decoder: &mut dyn Decoder) -> KunaResult<Vec<String>> {
    Ok(decode_namespace_levels(decoder)?.into_iter().map(|(name, _)| name).collect())
}

/// [`decode_namespace_path`] keeping each level's host namespace id, the
/// handle isNameUsed takes.
pub fn decode_namespace_levels(decoder: &mut dyn Decoder) -> KunaResult<Vec<(String, u64)>> {
    let elem_id = decoder.open_element_id(&ELEM_PARENT)?;
    let mut levels: Vec<(String, u64)> = Vec::new();
    let mut first = true;
    while decoder.peek_element()? != 0 {
        let vid = decoder.open_element()?;
        let mut label: Option<String> = None;
        let mut id = 0;
        loop {
            let aid = decoder.get_next_attribute_id()?;
            if aid == 0 {
                break;
            }
            if aid == crate::jumptable::ATTRIB_LABEL.get_id() {
                label = Some(String::from_utf8_lossy(&decoder.read_string()?).into_owned());
            } else if aid == ATTRIB_ID.get_id() {
                id = decoder.read_unsigned_integer()?;
            }
        }
        if !first {
            let name = match label {
                Some(label) => label,
                None => String::from_utf8_lossy(&decoder.read_string_id(&ATTRIB_CONTENT)?).into_owned(),
            };
            levels.push((name, id));
        }
        first = false;
        decoder.close_element_skipping(vid)?;
    }
    decoder.close_element(elem_id)?;
    levels.reverse(); // outermost-first on the wire -> innermost-first
    Ok(levels)
}

/// C++ `ArchitectureGhidra::isDynamicSymbolName`: a Ghidra default name,
/// `FUN_`/`DAT_` followed by at least four hex digits.
fn is_dynamic_symbol_name(name: &str) -> bool {
    let b = name.as_bytes();
    b.len() >= 8
        && (b.starts_with(b"FUN_") || b.starts_with(b"DAT_"))
        && b[b.len() - 4..].iter().all(|c| matches!(c, b'0'..=b'9' | b'a'..=b'f'))
}

// ---------------------------------------------------------------------------
// RemoteScope: the lazy cache at the GlobalQuery boundary
// ---------------------------------------------------------------------------

/// The per-function-resettable cache state (C++ ScopeGhidra's `mutable`
/// members).
struct RemoteScopeState {
    /// Negative cache: ranges answered `<hole>` (never re-queried).
    holes: RangeList,
    /// Positive cache: ranges covered by a decoded symbol entry (a query
    /// inside one is answered from `entries`).
    answered: RangeList,
    /// The materialized [`GlobalEntry`] records for every decoded symbol.
    entries: Vec<GlobalEntry>,
    /// Function facts by (space_index, offset) for the flow-time seams.
    functions: std::collections::BTreeMap<(int4, u64), RemoteFunctionFacts>,
    /// Per-entry getTrackedRegisters answers (cached until flush; an empty
    /// answer caches too so an address is asked once per flush epoch).
    tracked: std::collections::BTreeMap<(int4, u64), kuna_sleigh::globalcontext::TrackedSet>,
    /// Live property map: the locked default plus hole/symbol paints.
    flagbase: PartMap<Address, uint4>,
    /// Namespace-path cache by scope id.
    namespaces: std::collections::BTreeMap<u64, Vec<(String, u64)>>,
    /// The merged snapshot handed to readers; rebuilt when `dirty`.
    snapshot: Rc<GlobalQuery>,
    dirty: bool,
}

/// The flow-time function facts of a decoded FunctionSymbol.
#[derive(Clone)]
pub struct RemoteFunctionFacts {
    /// The RAW `Function.getName()` — the identity Java's
    /// `HighFunction.decode` name-echo compares against.  NEVER the label.
    pub name: String,
    /// The display form (`label` when the host sent a template-simplified
    /// name, else the raw name) — what callee tokens and the signature print
    /// (the upstream `Funcdata` name/displayName split).
    pub display_name: String,
    /// `Function.hasNoReturn()` (or the prototype's noreturn).
    pub no_return: bool,
    /// Complete supplied declaration, absent independently of function existence.
    pub source_proto: Option<Rc<crate::fspec::FuncProto>>,
    /// Supplied category-0 symbols retain all mappings, sizes, ids and use ranges.
    pub parameter_symbols: Vec<Rc<RemoteSymbolRecord>>,
    pub overrides: Rc<crate::overrides::Override>,
    pub inline: bool,
    /// Complete supplied locals, imported by the fresh function's local scope.
    pub locals: Vec<Rc<RemoteSymbolRecord>>,
    /// The namespaces enclosing the function, innermost first, global
    /// excluded (`["Gui", "Utils"]` for `Utils::Gui::smallIconSize`).
    pub scope_path: Vec<String>,
    /// The host namespace id of each `scope_path` level, same order.
    pub scope_ids: Vec<u64>,
    /// The call-fixup payload id that replaces every call to the function, or
    /// -1 (the host's `<inject>` resolved against the cspec call-fixups).
    pub inject_id: int4,
}

/// The ghidra-mode lazy symbol provider (see the module docs).  Installed on
/// `Architecture` as `Option<Rc<RemoteScope>>` and threaded into every
/// per-function `ArchContext`; interior-mutable because queries fire from
/// `&self` readers mid-decompile (the C++ `mutable` members).
pub struct RemoteScope {
    /// The wire fetcher (kuna-ghidra's `SharedClient` adapter).
    fetch: Rc<dyn RemoteProviderFetch>,
    /// The engine's space manager (decoders resolve spaces against it).
    manager: Rc<AddrSpaceManager>,
    /// The shared type factory (mapsym type decode + `get_type_code_proto`).
    types: Rc<TypeFactoryImpl>,
    /// Live call-fixup authority shared with the architecture and held prototypes.
    injection_library: Option<Rc<RefCell<crate::inject_sleigh::PcodeInjectLibrarySleigh>>>,
    /// Per-space "has a cspec `<global>` range" gate (C++ `spacerange`):
    /// spaces outside it are never queried.
    spacerange: Vec<bool>,
    /// The base Database snapshot (owned ranges + entries — empty of symbols
    /// in ghidra mode) taken at install time.
    base: GlobalQuery,
    /// The locked post-spec property map (C++ `flagbaseDefault`,
    /// `lockDefaultProperties`): the rollback target for `clear`.
    flagbase_default: PartMap<Address, uint4>,
    /// The PRISTINE (pre-any-wire-merge) tracked set per entry address — the
    /// pspec-static layer captured the FIRST time the driver merges wire
    /// context at an address.  Deliberately OUTSIDE the flush-cleared state:
    /// it is session-stable ENGINE truth, and it is what lets a later epoch's
    /// merge REVERT a value the host stopped reporting (upstream ContextGhidra
    /// stores nothing and rebuilds from the wire per call; kuna's per-function
    /// trackbase snapshot needs the explicit pristine layer to merge over).
    pristine_tracked:
        RefCell<std::collections::BTreeMap<(int4, u64), kuna_sleigh::globalcontext::TrackedSet>>,
    state: RefCell<RemoteScopeState>,
}

impl RemoteFunctionFacts {
    /// Inspect supplied placements without keeping a second source representation.
    pub fn param_storage(&self) -> Vec<(int4, String, crate::fspec::ParameterPieces)> {
        self.source_proto.as_ref().map(|p| (0..p.num_params()).filter_map(|i| p.get_param(i).map(|param| (
            i, param.get_name().to_owned(), crate::fspec::ParameterPieces {
                addr: param.get_address(), type_: param.get_type().cloned(), flags: param.get_flags(),
            },
        ))).collect()).unwrap_or_default()
    }
}

impl RemoteScope {
    /// Build the provider over the wire fetcher and the engine's shared parts.
    /// `base` is the Database global snapshot at install time (its `owned`
    /// ranges gate which spaces are queried and paint the no-symbol
    /// discovery properties); its `flagbase` is the locked default property
    /// map (C++ `lockDefaultProperties` at `postSpecFile`).
    pub fn new(
        fetch: Rc<dyn RemoteProviderFetch>,
        manager: Rc<AddrSpaceManager>,
        types: Rc<TypeFactoryImpl>,
        models: Rc<RefCell<std::collections::BTreeMap<String, Rc<ProtoModel>>>>,
        defaultfp: Option<Rc<ProtoModel>>,
        base: GlobalQuery,
    ) -> RemoteScope {
        // A space participates iff the global scope owns any range in it
        // (C++ `ScopeGhidra::addRange` growing `spacerange`).
        let mut spacerange = vec![false; manager.num_spaces() as usize];
        for r in base.owned.iter() {
            let idx = r.get_space().get_index() as usize;
            if idx < spacerange.len() {
                spacerange[idx] = true;
            }
        }
        let flagbase_default = base.flagbase.clone();
        let snapshot = Rc::new(GlobalQuery::default());
        types.set_proto_models(defaultfp, models);
        RemoteScope {
            fetch,
            manager,
            types,
            injection_library: None,
            spacerange,
            flagbase_default: flagbase_default.clone(),
            pristine_tracked: RefCell::new(std::collections::BTreeMap::new()),
            state: RefCell::new(RemoteScopeState {
                holes: RangeList::default(),
                answered: RangeList::default(),
                entries: Vec::new(),
                functions: std::collections::BTreeMap::new(),
                tracked: std::collections::BTreeMap::new(),
                flagbase: flagbase_default,
                namespaces: std::collections::BTreeMap::new(),
                snapshot,
                dirty: true,
            }),
            base,
        }
    }

    /// Install the live library used to resolve host `<inject>` names.
    pub fn set_injection_library(
        &mut self,
        library: Rc<RefCell<crate::inject_sleigh::PcodeInjectLibrarySleigh>>,
    ) {
        self.types.set_injection_library(Rc::clone(&library));
        self.injection_library = Some(library);
    }

    /// The prototype model registry lookup (C++ `Architecture::getModel`).
    fn model_by_name(&self, nm: &str) -> Option<Rc<ProtoModel>> {
        self.types.resolve_proto_model(nm).ok()
    }

    /// C++ `ScopeGhidra::clear()` (database_ghidra.cc:222-231) — the
    /// flushNative step 1: drop every cached answer and roll the property map
    /// back to the locked default.
    pub fn clear(&self) {
        let mut st = self.state.borrow_mut();
        st.holes = RangeList::default();
        st.answered = RangeList::default();
        st.entries.clear();
        st.functions.clear();
        st.tracked.clear();
        st.namespaces.clear();
        st.flagbase = self.flagbase_default.clone();
        st.dirty = true;
    }

    /// The gatekeeper (C++ `ScopeGhidra::removeQuery`, database_ghidra.cc:181-210):
    /// should `addr` be sent to the host at all?  Fires (at most) one
    /// getMappedSymbols query and materializes the answer.
    pub fn ensure_queried(&self, addr: &Address) -> KunaResult<()> {
        let Some(spc) = addr.get_space() else { return Ok(()) };
        let idx = spc.get_index() as usize;
        if idx >= self.spacerange.len() || !self.spacerange[idx] {
            return Ok(()); // space has no global range: never query
        }
        {
            let st = self.state.borrow();
            if st.holes.in_range(addr, 1) || st.answered.in_range(addr, 1) {
                return Ok(()); // already answered (positively or negatively)
            }
        }
        // Only actual answers may populate the cache. A failed acquisition
        // returns before any follow-up query or false negative-cache entry.
        let mut dec = PackedDecode::new(&self.manager);
        let got = self.fetch.fetch_mapped_symbols(addr, &mut dec)?;
        if !got {
            return Ok(()); // empty response: no symbol, not even a hole (upstream parity)
        }
        match decode_mapped_answer(&mut dec, &self.types)? {
            RemoteMapAnswer::Hole { range, flags } => self.record_hole(range, flags),
            RemoteMapAnswer::Symbol(rec) => {
                let rec = *rec;
                // An <externrefsymbol> resolves through a second query AT THE
                // POINTER address (C++ ScopeGhidra::resolveExternalRefFunction,
                // database_ghidra.cc:327-353): the answer is the resolved
                // function (or a shell), materialized at ITS OWN entry so
                // calls through the import slot pick up name/proto/noreturn.
                if rec.extern_ref.is_some() {
                    self.resolve_external_ref(addr)?;
                }
                self.materialize(rec)?;
            }
        }
        Ok(())
    }

    /// The two-step external-reference resolution (C++
    /// `ScopeGhidra::resolveExternalRefFunction`, database_ghidra.cc:327-353):
    /// getExternalRef at the POINTER address; the `<doc><mapsym>` answer (a
    /// full function or a functionshell) materializes at the function's own
    /// entry.
    fn resolve_external_ref(&self, pointer: &Address) -> KunaResult<()> {
        let mut dec = PackedDecode::new(&self.manager);
        if self.fetch.fetch_external_ref(pointer, &mut dec)? {
            match decode_mapped_answer(&mut dec, &self.types)? {
                RemoteMapAnswer::Symbol(rec) if rec.func.is_some() => {
                    self.materialize(*rec)?;
                }
                _ => {}
            }
        }
        Ok(())
    }

    /// The host's tracked-register set for one address (C++
    /// `ContextGhidra::getTrackedSet` — a getTrackedRegisters query), cached
    /// per address until flush.  `None` only for a space-less address; an
    /// EMPTY host answer caches as an empty set.
    pub fn tracked_at(
        &self,
        addr: &Address,
    ) -> KunaResult<Option<kuna_sleigh::globalcontext::TrackedSet>> {
        let Some(spc) = addr.get_space() else { return Ok(None) };
        let key = (spc.get_index(), addr.get_offset());
        if let Some(set) = self.state.borrow().tracked.get(&key) {
            return Ok(Some(set.clone()));
        }
        let mut dec = PackedDecode::new(&self.manager);
        let mut set = kuna_sleigh::globalcontext::TrackedSet::new();
        if self.fetch.fetch_tracked_registers(addr, &mut dec)? {
            let el = dec.open_element()?;
            kuna_sleigh::globalcontext::decode_tracked(&mut dec, &mut set)?;
            dec.close_element(el)?;
        }
        self.state.borrow_mut().tracked.insert(key, set.clone());
        Ok(Some(set))
    }

    /// The pristine (pre-merge) tracked set for an entry address: captured
    /// from `current` on the FIRST call, returned verbatim afterwards — the
    /// stable base every epoch's wire merge is applied over, so a value the
    /// host STOPS reporting reverts after flushNative (see `pristine_tracked`).
    pub fn pristine_tracked_for(
        &self,
        addr: &Address,
        current: kuna_sleigh::globalcontext::TrackedSet,
    ) -> kuna_sleigh::globalcontext::TrackedSet {
        let Some(spc) = addr.get_space() else { return current };
        let key = (spc.get_index(), addr.get_offset());
        self.pristine_tracked
            .borrow_mut()
            .entry(key)
            .or_insert(current)
            .clone()
    }

    /// Whether a pristine tracked set was ever captured at `addr` (i.e. a wire
    /// merge previously wrote the context DB there and a revert-write may be
    /// needed even for an empty wire answer).
    pub fn has_pristine_tracked(&self, addr: &Address) -> bool {
        match addr.get_space() {
            Some(spc) => self
                .pristine_tracked
                .borrow()
                .contains_key(&(spc.get_index(), addr.get_offset())),
            None => false,
        }
    }

    fn record_hole(&self, range: Range, flags: uint4) {
        let mut st = self.state.borrow_mut();
        st.holes.insert_range(
            Rc::clone(range.get_space()),
            range.get_first(),
            range.get_last(),
        );
        if flags != 0 {
            let first = range.get_first_addr();
            let last = range.get_last_addr_open(&self.manager);
            Self::paint_property(&mut st.flagbase, flags, &first, &last);
            st.dirty = true;
        }
    }

    /// `Database::set_property_range` semantics over the local property map.
    fn paint_property(map: &mut PartMap<Address, uint4>, flags: uint4, a1: &Address, a2: &Address) {
        map.split(a1);
        if !a2.is_invalid() {
            map.split(a2);
        }
        for (k, v) in map.iter_from_mut(a1) {
            if !a2.is_invalid() && k >= a2 {
                break;
            }
            *v |= flags;
        }
    }

    /// Materialize one decoded symbol into the cache (the kuna analog of C++
    /// `dump2Cache`'s post-processing, database_ghidra.cc:143-171).
    fn materialize(&self, rec: RemoteSymbolRecord) -> KunaResult<()> {
        // Resolve the namespace path once per scope id.
        let scope_levels = if rec.scope_id != 0 {
            self.namespace_levels(rec.scope_id)?
        } else {
            Vec::new()
        };
        let scope_path: Vec<String> = scope_levels.iter().map(|(name, _)| name.clone()).collect();
        let scope_ids: Vec<u64> = scope_levels.iter().map(|&(_, id)| id).collect();
        let mut st = self.state.borrow_mut();
        let display = if rec.display_name.is_empty() {
            rec.name.clone()
        } else {
            rec.display_name.clone()
        };
        // Function facts + parked prototype for the callee seams.
        let mut symbol_type: Option<Rc<Datatype>> = rec.dtype.clone();
        let mut func_no_return = false;
        let is_function = rec.func.is_some();
        // FuncProto::decode: `<inject>` names the call-fixup that replaces
        // every call to the function.
        let func_inject_id = rec
            .func
            .as_ref()
            .and_then(|f| f.proto.as_ref())
            .and_then(|p| p.inject.as_ref())
            .and_then(|name| {
                self.injection_library.as_ref().map(|library| {
                    library.borrow().base.get_payload_id(crate::pcodeinject::CALLFIXUP_TYPE, name.as_bytes())
                })
            })
            .unwrap_or(-1);
        if let Some(func) = &rec.func {
            func_no_return =
                func.no_return || func.proto.as_ref().map(|p| p.no_return).unwrap_or(false);
            // The upstream Funcdata name/displayName split: the RAW name is the
            // Java-side identity (the HighFunction.decode echo); the label is
            // only ever a display form.
            let raw_name = func.name.clone();
            let fname = if func.display_name.is_empty() {
                func.name.clone()
            } else {
                func.display_name.clone()
            };
            if !func.entry.is_invalid() {
                if let Some(spc) = func.entry.get_space() {
                    let key = (spc.get_index(), func.entry.get_offset());
                    let source_proto = func.proto.as_ref().map(|p| -> KunaResult<Rc<crate::fspec::FuncProto>> {
                        let mut source = crate::fspec::FuncProto::new();
                        source.copy(&p.complete);
                        let extrapop = source.supplied_extra_pop();
                        source.set_model(Some(self.types.resolve_supplied_proto_model(&p.model)?));
                        if let Some(extrapop) = extrapop { source.set_extra_pop(extrapop); }
                        source.store_clear_all_inputs();
                        for (slot, param) in p.params.iter().enumerate() {
                            if let Some(ty) = &param.dtype {
                                source.set_param(slot as int4, &param.name, &crate::fspec::ParameterPieces {
                                    addr: param.storage.clone(), type_: Some(Rc::clone(ty)), flags: param.flags,
                                });
                                source.set_param_usepoint(slot as int4, param.usepoint.clone());
                            }
                        }
                        source.set_output(&crate::fspec::ParameterPieces {
                            addr: p.out_storage.clone(), type_: p.out_type.clone(),
                            flags: p.complete.get_output().get_flags(),
                        });
                        source.set_output_lock(p.out_lock);
                        if source.is_input_locked() || source.is_output_locked() { source.set_model_lock(true); }
                        source.set_inline(func.inline || p.complete.is_inline());
                        source.set_no_return(func_no_return);
                        source.complete_decoded_effects()?;
                        self.types.bind_prototype_injection(&mut source)?;
                        Ok(self.types.retain_source_proto(Rc::new(source)))
                    }).transpose()?;
                    st.functions.insert(
                        key,
                        RemoteFunctionFacts {
                            name: raw_name,
                            display_name: fname,
                            no_return: func_no_return,
                            source_proto,
                            parameter_symbols: func.proto.as_ref().map(|p| p.params.iter().filter_map(|p| p.symbol.clone()).collect()).unwrap_or_default(),
                            overrides: Rc::clone(&func.overrides),
                            inline: func.inline || func.proto.as_ref().is_some_and(|p| p.complete.is_inline()),
                            locals: func.locals.clone(),
                            scope_path: scope_path.clone(),
                            scope_ids: scope_ids.clone(),
                            inject_id: func_inject_id,
                        },
                    );
                }
            }
            // FunctionSymbol::buildType: a function without a declared prototype
            // is still typed as code, which is what a constant pointer to it binds
            // to (ActionConstantPtr -> spacebaseConstant).
            if symbol_type.is_none() {
                symbol_type = self.types.get_type_code().ok();
            }
        }
        // Materialize the mapped entries as GlobalEntry records.
        for e in &rec.entries {
            if e.addr.is_invalid() {
                continue; // dynamic (<hash>) entries have no static range
            }
            let Some(spc) = e.addr.get_space() else { continue };
            let size = if e.size <= 0 { 1 } else { e.size };
            let first = e.addr.get_offset();
            let last = first.wrapping_add(size as u64).wrapping_sub(1);
            let addr_tied = e.uselimit.empty();
            let mut all_flags = rec.flags | varnode_flags::mapped;
            if addr_tied {
                all_flags |= varnode_flags::addrtied | varnode_flags::persist;
            }
            st.entries.push(GlobalEntry {
                space_index: spc.get_index(),
                first,
                last,
                size,
                all_flags,
                addrtied: addr_tied,
                uselimit: e.uselimit.clone(),
                symbol_name: display.clone(),
                symbol_offset: 0,
                symbol_type: symbol_type.clone(),
                symbol_id: rec.symbol_id,
                scope_path: scope_path.clone(),
                is_function,
                func_inject_id,
                func_no_return,
            });
            // Mark the range answered so no interior address re-queries.
            st.answered.insert_range(Rc::clone(spc), first, last);
            // Property side effect (readonly/volatile symbols paint the map).
            let props = rec.flags & (varnode_flags::readonly | varnode_flags::volatil);
            if props != 0 {
                let a1 = Address::new(Rc::clone(spc), first);
                // Open upper bound via the Range helper: a symbol ending at
                // the very top of its space paints to the space end (an
                // invalid/next-space open end) instead of wrapping to 0 and
                // painting nothing.
                let a2 = Range::new(Rc::clone(spc), first, last)
                    .get_last_addr_open(&self.manager);
                Self::paint_property(&mut st.flagbase, props, &a1, &a2);
            }
        }
        if rec.entries.is_empty() {
            // A symbol with no static mapping (extern shell): remember only
            // the function facts; nothing to range-mark.
        }
        st.dirty = true;
        Ok(())
    }

    /// The namespace levels `(display name, host id)` for a host scope id,
    /// innermost first (cached; C++ `ScopeGhidra::reresolveScope` +
    /// `decodeScopePath`).
    fn namespace_levels(&self, id: u64) -> KunaResult<Vec<(String, u64)>> {
        if let Some(p) = self.state.borrow().namespaces.get(&id) {
            return Ok(p.clone());
        }
        let mut dec = PackedDecode::new(&self.manager);
        let path = if self.fetch.fetch_namespace_path(id, &mut dec)? {
            decode_namespace_levels(&mut dec)?
        } else {
            Vec::new()
        };
        self.state
            .borrow_mut()
            .namespaces
            .insert(id, path.clone());
        Ok(path)
    }

    /// C++ `ScopeGhidraNamespace::isNameUsed`: ask the host whether `name` is a
    /// symbol in namespace `start` or a parent below `stop`.  A default
    /// `FUN_`/`DAT_` name is assumed not to collide, as upstream does, and a
    /// failed query propagates without reporting a false absence.
    pub fn is_name_used(&self, name: &str, start: u64, stop: u64) -> KunaResult<bool> {
        if is_dynamic_symbol_name(name) {
            return Ok(false);
        }
        self.fetch.fetch_is_name_used(name, start, stop)
    }

    /// The merged read snapshot: the base Database snapshot's owned ranges,
    /// the live property map, and every materialized entry.  Rebuilt lazily.
    pub fn snapshot(&self) -> Rc<GlobalQuery> {
        let mut st = self.state.borrow_mut();
        if st.dirty {
            let mut entries = self.base.entries_cloned();
            entries.retain(|entry| !st.entries.iter().any(|host| {
                host.space_index == entry.space_index && host.first == entry.first
                    && host.last == entry.last && host.size == entry.size
            }));
            entries.extend(st.entries.iter().cloned());
            st.snapshot = Rc::new(GlobalQuery::new(
                entries,
                self.base.owned.clone(),
                st.flagbase.clone(),
            ));
            st.dirty = false;
        }
        Rc::clone(&st.snapshot)
    }

    /// Query-through + snapshot in one step (the ArchContext read seam).
    pub fn query_snapshot(&self, addr: &Address) -> KunaResult<Rc<GlobalQuery>> {
        self.ensure_queried(addr)?;
        Ok(self.snapshot())
    }

    /// The flow-time function facts at an entry address (queries through).
    pub fn function_at(&self, entry: &Address) -> KunaResult<Option<RemoteFunctionFacts>> {
        self.ensure_queried(entry)?;
        let Some(spc) = entry.get_space() else { return Ok(None) };
        Ok(self.state
            .borrow()
            .functions
            .get(&(spc.get_index(), entry.get_offset()))
            .cloned())
    }

    /// Fill the (stand-in) comment database once per function from the host's
    /// getComments answer, filtered by the printer's comment settings (C++
    /// `CommentDatabaseGhidra::fillCache`, comment_ghidra.cc:30-49): an empty
    /// filter issues no query.  The decoded `<commentdb>` is drained into
    /// `sink` through the trait the printer rebuilds from.
    pub fn fill_comments(
        &self,
        fad: &Address,
        filter: u32,
        sink: &mut crate::architecture::CommentDatabase,
    ) -> KunaResult<()> {
        if filter == 0 {
            return Ok(());
        }
        let mut dec = PackedDecode::new(&self.manager);
        if !self.fetch.fetch_comments(fad, filter, &mut dec)? {
            return Ok(());
        }
        let mut db = crate::comment::CommentDatabaseInternal::new();
        crate::comment::CommentDatabase::decode(&mut db, &mut dec)?;
        for c in crate::comment::CommentDatabase::comments_for(&db, fad) {
            sink.add_comment_no_duplicate(
                c.get_type(),
                c.get_func_addr(),
                c.get_addr(),
                &String::from_utf8_lossy(c.get_text()),
            );
        }
        Ok(())
    }

    /// The proto model resolved for a decoded prototype (kept for Phase-4
    /// prototype seeding; currently the pieces flow is model-agnostic).
    pub fn resolve_model(&self, nm: &str) -> Option<Rc<ProtoModel>> {
        self.model_by_name(nm)
    }
}

#[cfg(test)]
mod tests;
