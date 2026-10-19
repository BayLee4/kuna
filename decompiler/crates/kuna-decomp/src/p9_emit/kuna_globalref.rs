//! (kuna `globalref`) A constant address used as a pointer prints as the global
//! it names.
//!
//! `PrintC::pushConstant`'s pointer arm renders a pointer-typed constant as a
//! forced-hex integer behind a typecast, `sub_e4ca((struct_2 *)0x2b080)`.
//! Upstream reaches a symbol only through `ActionConstantPtr`, which links a
//! constant to a global Symbol that already exists; a stripped image carries none
//! for most of its data, so every address a callee's recovered pointer type
//! reaches keeps the cast. The type campaign made that more common, not less:
//! the more parameters are typed as pointers, the more constant arguments are
//! typed as pointers too.
//!
//! When on, such a constant prints as `&dat_<addr>` -- the name kuna already
//! gives an unnamed global it reads directly -- and the function records the
//! global as an object of the pointed-to type, which the `decompile-project`
//! header declares. The expression has exactly the constant's pointer type, so
//! the cast is gone because the object is declared at that type, and its value
//! is the address it replaces wherever `dat_<addr>` is placed at `<addr>`.
//!
//! The rewrite is refused where the name would claim something the function
//! does not show: an address outside every section the loader classifies as
//! holding program data (code, TLS templates, the run-time loader's tables, or
//! no section at all); an address a global Symbol already covers; a value the
//! same function also reads as a number (an ordering compare, a multiply, a
//! divide, a shift on a non-pointer); an object this function also reads or
//! writes directly at another width or type; a pointer to code; and, when the
//! pointed-to type is `void`, any reader for which C's implicit conversion from
//! the declared object's pointer is not exactly the conversion the cast
//! performed.

use std::collections::{BTreeMap, HashSet};
use std::rc::Rc;

use kuna_base::address::Address;
use kuna_base::error::KunaResult;
use kuna_base::types::uintb;
use kuna_num::opcodes::OpCode;

use crate::architecture::Architecture;
use crate::context::{OpId, VarnodeId};
use crate::dtype::{type_metatype, Datatype, TypeFactory};
use crate::funcdata::Funcdata;
use crate::kuna_elemptr::{GlobalVerdict, Obj};
use crate::options::on_or_off;

/// `globalref on|off`.
#[derive(Debug, Clone, Copy, Default)]
pub struct OptionGlobalRef;

impl OptionGlobalRef {
    /// The option name.
    pub const NAME: &'static str = "globalref";

    /// Parse + validate the `on`/`off` value; the caller performs the printer
    /// write ([`crate::printc::PrintCOptions::set_global_ref`]).
    pub fn apply(&self, p1: &str) -> KunaResult<(bool, String)> {
        let val = on_or_off(p1)?;
        let prop = if val { "on" } else { "off" };
        Ok((val, format!("Constant-address global references turned {prop}")))
    }
}

/// One global a function's C names by address.
#[derive(Debug, Clone)]
pub struct Minted {
    /// The type the function uses the object at.
    pub decl_type: Rc<Datatype>,
    /// True when `decl_type` is the unknown byte: the function only ever used
    /// the address through `void *` and never reads the storage there directly.
    pub unknown: bool,
    /// (kuna `elemptr`) True when the function indexes the address with a value
    /// it computes: the global is an array of `decl_type`, named without `&`
    /// (`dat_4020[v1]`), and declared `T dat_4020[]`.
    pub array: bool,
}

/// A direct access this function makes to global storage.
#[derive(Debug, Clone)]
struct Direct {
    start: u64,
    size: u64,
    ty: Rc<Datatype>,
    /// No global Symbol covers it, so the body prints it as `dat_<start>`.
    unnamed: bool,
    /// (kuna `elemptr`) The rule typed it an element pointer: the header
    /// declares it, since a subscript of it reads the declared element.
    elem: bool,
}

/// What one function reads an address at.
#[derive(Debug, Clone)]
enum Seen {
    /// Only ever through `void *`.
    Void(Rc<Datatype>),
    /// One pointed-to type other than `void`, perhaps also through `void *`.
    One(Rc<Datatype>),
    /// Two different pointed-to types other than `void`.
    Conflict,
}

impl Seen {
    /// `sized` (kuna `elemptr`): an unknown pointee wider than a byte is the
    /// same object as an unsigned one of its size, as [`same_object`] reads a
    /// direct access -- the undefined words a copy reads where a callee's
    /// parameter reads the elements `elemptr` gave it -- and the typed one names it.
    fn merge(prev: Option<Seen>, to: Rc<Datatype>, sized: bool) -> Seen {
        let is_void = to.get_metatype() == type_metatype::TYPE_VOID;
        let unknown_of = |a: &Datatype, b: &Datatype| {
            sized
                && a.get_metatype() == type_metatype::TYPE_UNKNOWN
                && b.get_metatype() == type_metatype::TYPE_UINT
                && a.get_size() == b.get_size()
                && a.get_size() > 1
        };
        match prev {
            None | Some(Seen::Void(_)) if is_void => Seen::Void(to),
            None | Some(Seen::Void(_)) => Seen::One(to),
            Some(Seen::One(t)) if is_void || same_type(&t, &to) || unknown_of(&to, &t) => Seen::One(t),
            Some(Seen::One(t)) if unknown_of(&t, &to) => Seen::One(to),
            _ => Seen::Conflict,
        }
    }

    fn object(&self) -> Option<Rc<Datatype>> {
        match self {
            Seen::Void(t) | Seen::One(t) => Some(Rc::clone(t)),
            Seen::Conflict => None,
        }
    }
}

/// The source Symbol selected for one exact-width annotation occurrence.
#[derive(Debug, Clone)]
pub(crate) struct AnnotationSymbol {
    pub name: String,
    pub offset: i32,
    pub ty: Option<Rc<Datatype>>,
    pub id: u64,
}

/// A volatile annotation is an address, not a value with a HighVariable. Keep
/// its existing source acquisition on the document plan instead of losing the
/// declaration and type roots when its variable token is flattened.
#[derive(Debug, Clone)]
pub(crate) struct Annotation {
    pub address: Address,
    pub size: i32,
    pub symbol: Option<AnnotationSymbol>,
    pub volatile: bool,
    pub emitted: bool,
}

impl Annotation {
    pub fn whole_object_volatile(&self) -> bool {
        self.volatile && self.symbol.as_ref().is_some_and(|symbol| {
            symbol.offset == 0 && symbol.ty.as_ref().is_some_and(|ty| ty.get_size() == self.size)
        })
    }

    /// Storage volatility can qualify a declaration only when the actual
    /// annotation covers that whole object, never a volatile member's parent.
    /// The acquired source datatype remains unchanged.
    pub fn declaration_type(&self) -> Option<Rc<Datatype>> {
        let symbol = self.symbol.as_ref()?;
        let ty = symbol.ty.as_ref()?;
        Some(if self.whole_object_volatile() && !crate::kuna_typequal::is_volatile(ty)
        {
            crate::kuna_typequal::qualified_type(Rc::clone(ty), crate::kuna_typequal::VOLATILE)
        } else {
            Rc::clone(ty)
        })
    }
}

/// The existing pushAnnotation acquisition, shared with document preparation.
/// The annotation's one-byte address carrier does not determine the access width.
pub(crate) fn acquire_annotation(
    fd: &Funcdata, arch: &Architecture, vn: VarnodeId, op: OpId,
) -> KunaResult<Annotation> {
    let value = fd.vbank().get(vn).expect("annotation operand");
    let operation = fd.obank().get(op).expect("annotation operation");
    let mut size = 0;
    if operation.code() == OpCode::CPUI_CALLOTHER {
        let index = operation.get_in(0).and_then(|id| fd.vbank().get(id))
            .map_or(0, |value| value.get_offset());
        if let Some(userop) = arch.userops.get_op(index as u32) {
            let output = operation.get_out().and_then(|id| fd.vbank().get(id))
                .map(|value| value.get_size());
            let input = if operation.num_input() > 2 {
                operation.get_in(2).and_then(|id| fd.vbank().get(id))
                    .map(|value| value.get_size())
            } else {
                None
            };
            size = userop.extract_annotation_size(output, input);
        }
    }
    let symbol = fd.get_arch().name_for_global_varnode(
        value.get_addr(), if size != 0 { size } else { 1 }, operation.get_addr(),
    )?.map(|(name, offset, ty, id)| AnnotationSymbol { name, offset, ty, id });
    Ok(Annotation {
        address: value.get_addr().clone(),
        size: if size != 0 { size } else { value.get_size() },
        symbol, volatile: value.is_volatile(), emitted: false,
    })
}

/// The per-function state: the facts every decision reads, computed once when
/// the function's document starts, and the globals it has named so far.
#[derive(Debug, Default)]
pub struct Plan {
    annotations: BTreeMap<(OpId, VarnodeId), Annotation>,
    on: bool,
    trace: bool,
    numeric: HashSet<uintb>,
    direct: Vec<Direct>,
    /// The pointed-to types each in-range constant address is read at.
    pointees: BTreeMap<u64, Seen>,
    /// (kuna `elemptr`) The addresses this function indexes with a computed
    /// value: a constant that is the base of a `PTRADD` whose index is not.
    indexed: HashSet<u64>,
    /// Every global this function's C names, by address.
    pub minted: BTreeMap<u64, Minted>,
}

/// Build the plan for `fd`. Source annotation bindings do not depend on the
/// synthesized-address option, data-section inventory, or output language.
pub fn plan(fd: &Funcdata, arch: &Architecture, on: bool, is_c: bool) -> KunaResult<Plan> {
    let mut annotations = BTreeMap::new();
    for op in fd.obank().iter_alive() {
        let operation = fd.obank().get(op).expect("live annotation operation");
        if operation.code() != OpCode::CPUI_CALLOTHER { continue; }
        let Some(index) = operation.get_in(0).and_then(|id| fd.vbank().get(id)) else { continue };
        let Some(userop) = arch.userops.get_op(index.get_offset() as u32) else { continue };
        if !matches!(userop.get_type(),
            crate::userop::userop_type::volatile_read | crate::userop::userop_type::volatile_write)
        {
            continue;
        }
        let Some(vn) = operation.get_in(1)
            .filter(|id| fd.vbank().get(*id).is_some_and(|value| value.is_annotation())) else { continue };
        annotations.insert((op, vn), acquire_annotation(fd, arch, vn, op)?);
    }
    if !on || !is_c || arch.globalref_ranges.is_empty() {
        return Ok(Plan { annotations, ..Plan::default() });
    }
    let data_space = arch.manage().get_default_data_space().map(|s| s.get_index());
    let mut numeric = HashSet::new();
    let mut direct = Vec::new();
    let mut pointees: BTreeMap<u64, Seen> = BTreeMap::new();
    let mut indexed = HashSet::new();
    let elem_held = if arch.elem_ptr { fd.kuna_elemptr_verdicts() } else { BTreeMap::new() };
    for vn in fd.vbank().iter_loc() {
        let Some(v) = fd.vbank().get(vn) else { continue };
        if v.is_constant() {
            let off = v.get_offset();
            for op in v.descend_iter() {
                let Some(code) = fd.obank().get(op).map(|o| o.code()) else { continue };
                let ct = v.get_type_read_facing(op);
                if ct.get_metatype() != type_metatype::TYPE_PTR {
                    if reads_as_number(code) {
                        numeric.insert(off);
                    }
                    continue;
                }
                if !in_ranges(&arch.globalref_ranges, off) {
                    continue;
                }
                let Some(to) = ct.get_ptr_to() else { continue };
                if arch.elem_ptr && fd.kuna_elemptr_objects() && is_indexed_base(fd, op, vn) {
                    indexed.insert(off);
                }
                let seen = pointees.remove(&off);
                pointees.insert(off, Seen::merge(seen, to, arch.elem_ptr));
            }
        } else if data_space.is_some() && v.get_addr().get_space().map(|s| s.get_index()) == data_space {
            let unnamed = in_ranges(&arch.globalref_ranges, v.get_offset())
                && fd.get_arch().query_container_global(v.get_addr(), v.get_size(), &Address::new_invalid())?.is_none();
            // (kuna `elemptr`) A global the rule typed, or whose fold names its
            // pointee and which nothing uses as a number, is used only as that
            // pointer: one of another type (its value before a call, which
            // nothing prints) is not a read of it at that type.
            let elem = arch.elem_ptr
                && matches!(
                    elem_held.get(&Obj::Held(v.get_offset())),
                    Some(GlobalVerdict::Typed { .. } | GlobalVerdict::Claimed { .. })
                );
            if elem && v.get_type().get_metatype() != type_metatype::TYPE_PTR {
                continue;
            }
            direct.push(Direct {
                start: v.get_offset(),
                size: v.get_size().max(1) as u64,
                ty: Rc::clone(v.get_type()),
                unnamed,
                elem,
            });
        }
    }
    let trace = std::env::var_os("KUNA_GLOBALREF_TRACE").is_some();
    Ok(Plan { annotations, on: true, trace, numeric, direct, pointees, indexed, minted: BTreeMap::new() })
}

/// (kuna `elemptr`) Is `vn` the base of the `PTRADD` `op`, indexed by a value
/// the program computes?
fn is_indexed_base(fd: &Funcdata, op: OpId, vn: VarnodeId) -> bool {
    fd.obank().get(op).is_some_and(|o| {
        o.code() == OpCode::CPUI_PTRADD
            && o.get_in(0) == Some(vn)
            && o.get_in(1).and_then(|i| fd.vbank().get(i)).is_some_and(|i| !i.is_constant())
    })
}

/// Does `opcode` read its operand as a number rather than as an address?
fn reads_as_number(opcode: OpCode) -> bool {
    crate::kuna_inferfuncentry::reads_as_integer(opcode)
}

impl Plan {
    pub(crate) fn use_annotation(&mut self, op: OpId, vn: VarnodeId) -> Option<&Annotation> {
        let annotation = self.annotations.get_mut(&(op, vn))?;
        annotation.emitted = true;
        Some(annotation)
    }

    pub(crate) fn annotations(&self) -> impl Iterator<Item = &Annotation> {
        self.annotations.values()
    }

    pub(crate) fn annotation_types(&self, emitted_only: bool) -> impl Iterator<Item = &Rc<Datatype>> {
        self.annotations.values().filter(move |annotation| !emitted_only || annotation.emitted)
            .filter_map(|annotation| annotation.symbol.as_ref()?.ty.as_ref())
    }

    /// Decide whether the pointer-typed constant `vn` (value `off`, read by
    /// `op` at type `ct`) names a global, and record it. Returns the address to
    /// name, or `None` to keep the upstream cast.
    pub fn decide(
        &mut self,
        fd: &Funcdata,
        arch: &Architecture,
        vn: VarnodeId,
        op: OpId,
        off: uintb,
        ct: &Rc<Datatype>,
    ) -> KunaResult<Option<u64>> {
        if !self.on {
            return Ok(None);
        }
        let verdict = self.judge(fd, arch, vn, op, off, ct)?;
        if self.trace {
            eprintln!(
                "[globalref] {} 0x{off:x} {} {}",
                fd.get_name(),
                ct.get_name(),
                match &verdict {
                    Ok(()) => "named",
                    Err(why) => why.as_str(),
                }
            );
        }
        Ok(verdict.ok().map(|()| off))
    }

    // Refusals are successful decisions to keep the original expression;
    // acquisition failures belong to the outer result and must stop printing.
    fn judge(
        &mut self,
        fd: &Funcdata,
        arch: &Architecture,
        vn: VarnodeId,
        op: OpId,
        off: uintb,
        ct: &Rc<Datatype>,
    ) -> KunaResult<Result<(), Refusal>> {
        if off == 0 || ct.get_metatype() != type_metatype::TYPE_PTR || ct.get_word_size().unwrap_or(1) != 1 {
            return Ok(Err(Refusal::NotAPointer));
        }
        if fd.vbank().get(vn).map(|v| v.get_size()) != Some(ct.get_size()) {
            return Ok(Err(Refusal::NotAPointer));
        }
        let Some(pointee) = ct.get_ptr_to() else { return Ok(Err(Refusal::NotAPointer)) };
        if matches!(pointee.get_metatype(), type_metatype::TYPE_CODE | type_metatype::TYPE_SPACEBASE) {
            return Ok(Err(Refusal::Code));
        }
        if !in_ranges(&arch.globalref_ranges, off) {
            return Ok(Err(Refusal::OutsideData));
        }
        if self.numeric.contains(&off) {
            return Ok(Err(Refusal::Numeric));
        }
        let Some(seen) = self.pointees.get(&off) else { return Ok(Err(Refusal::NotAPointer)) };
        let Some(object) = seen.object() else { return Ok(Err(Refusal::TwoTypes)) };
        if matches!(object.get_metatype(), type_metatype::TYPE_CODE | type_metatype::TYPE_SPACEBASE) {
            return Ok(Err(Refusal::Code));
        }
        let unknown = object.get_metatype() == type_metatype::TYPE_VOID;
        if pointee.get_metatype() == type_metatype::TYPE_VOID && !void_reader_converts(fd, op, vn) {
            return Ok(Err(Refusal::VoidReader));
        }
        let Some(space) = arch.manage().get_default_data_space() else { return Ok(Err(Refusal::OutsideData)) };
        let space = Rc::clone(space);
        let addr = Address::new(space, off);
        let invalid = Address::new_invalid();
        if fd.get_arch().query_container_global(&addr, 1, &invalid)?.is_some() {
            return Ok(Err(Refusal::Symbol));
        }
        let (decl_type, unknown) = if !unknown {
            (object, false)
        } else if let Some(read) = self.direct_type_at(off) {
            (read, false)
        } else {
            let byte = arch.types_impl().get_base(1, type_metatype::TYPE_UNKNOWN)?;
            (byte, true)
        };
        let size = decl_type.get_size().max(1) as u64;
        // (kuna `elemptr`) An indexed address is an array only where the function
        // does not also read or write its first element by name: that name would
        // be the array. It is then the scalar's address, `(&dat_5c000)[i]`.
        let array = self.indexed.contains(&off) && !unknown && !self.direct.iter().any(|d| overlaps(d, off, size));
        if let Some(d) = self.direct.iter().find(|d| overlaps(d, off, size) && !same_object(d, off, size, &decl_type)) {
            if self.trace {
                eprintln!(
                    "[globalref-direct] {} 0x{off:x} decl={}:{} direct=0x{:x}:{}:{}",
                    fd.get_name(),
                    decl_type.get_name(),
                    size,
                    d.start,
                    d.size,
                    d.ty.get_name()
                );
            }
            return Ok(Err(Refusal::DirectAccess));
        }
        self.minted.entry(off).or_insert(Minted { decl_type, unknown, array });
        Ok(Ok(()))
    }

    /// (kuna `elemptr`) Is the global this function names at `addr` an array,
    /// printed by its name alone?
    pub fn is_array(&self, addr: u64) -> bool {
        self.minted.get(&addr).is_some_and(|m| m.array)
    }
}

impl Plan {
    /// The unnamed program data this function reads or writes directly, by
    /// start and type: the `dat_<addr>` it prints that are not addresses taken.
    pub fn direct_objects(&self) -> impl Iterator<Item = (u64, &Rc<Datatype>, bool)> + '_ {
        self.direct.iter().filter(|d| d.unnamed).map(|d| (d.start, &d.ty, d.elem))
    }

    /// (kuna `elemptr`) The type a project header declares the global at `off`
    /// as, when no symbol names it and the rule typed it an element pointer:
    /// the one type this function reads and writes it at.
    pub fn declared_type(&self, off: u64) -> Option<Rc<Datatype>> {
        if !self.direct.iter().filter(|d| overlaps(d, off, 1)).all(|d| d.unnamed && d.elem) {
            return None;
        }
        self.direct_type_at(off)
    }

    /// The one type this function reads or writes the storage at `off` at,
    /// when every direct access that touches it starts there at that type.
    fn direct_type_at(&self, off: u64) -> Option<Rc<Datatype>> {
        let mut found: Option<&Direct> = None;
        for d in self.direct.iter().filter(|d| overlaps(d, off, 1)) {
            match found {
                None if d.start == off => found = Some(d),
                Some(f) if d.start == off && d.size == f.size && same_type(&d.ty, &f.ty) => {}
                _ => return None,
            }
        }
        found.map(|d| Rc::clone(&d.ty))
    }
}

/// Why a pointer-typed constant keeps its cast.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    /// Not a byte-addressed data pointer the size of the constant.
    NotAPointer,
    /// A pointer to code.
    Code,
    /// No section the loader classifies as program data holds the address.
    OutsideData,
    /// The function also reads the value as a number.
    Numeric,
    /// The function uses the address at two different pointed-to types.
    TwoTypes,
    /// A `void *` reader for which the declared object's pointer does not convert.
    VoidReader,
    /// A global Symbol already covers the address.
    Symbol,
    /// The function reads or writes the storage directly at another width or type.
    DirectAccess,
}

impl Refusal {
    /// The trace spelling.
    pub fn as_str(self) -> &'static str {
        match self {
            Refusal::NotAPointer => "not-a-pointer",
            Refusal::Code => "code",
            Refusal::OutsideData => "outside-data",
            Refusal::Numeric => "numeric",
            Refusal::TwoTypes => "two-types",
            Refusal::VoidReader => "void-reader",
            Refusal::Symbol => "symbol",
            Refusal::DirectAccess => "direct-access",
        }
    }
}

/// Is `off` inside one of the sorted, inclusive `ranges`?
pub fn in_ranges(ranges: &[(u64, u64)], off: u64) -> bool {
    let idx = ranges.partition_point(|&(lo, _)| lo <= off);
    idx > 0 && ranges[idx - 1].1 >= off
}

fn overlaps(d: &Direct, off: u64, size: u64) -> bool {
    d.start < off.saturating_add(size) && off < d.start.saturating_add(d.size)
}

/// Is the direct access `d` a read or write of exactly the object `off` names,
/// at a type that spells the same C type as `ty`? A wider unknown is the
/// unsigned integer of its size on every surface; a one-byte unknown is `char`
/// on one and `unsigned char` on another, so it matches only itself.
fn same_object(d: &Direct, off: u64, size: u64, ty: &Rc<Datatype>) -> bool {
    if d.start != off || d.size != size {
        return false;
    }
    same_type(&d.ty, ty)
        || (d.ty.get_metatype() == type_metatype::TYPE_UNKNOWN
            && ty.get_metatype() == type_metatype::TYPE_UINT
            && ty.get_size() == d.ty.get_size()
            && ty.get_size() > 1)
}

fn same_type(a: &Rc<Datatype>, b: &Rc<Datatype>) -> bool {
    Rc::ptr_eq(a, b) || a.type_order(b).map(|o| o == 0).unwrap_or(false)
}

/// Is `ct` a pointer to `void`?
fn is_void_pointer(ct: &Datatype) -> bool {
    ct.get_metatype() == type_metatype::TYPE_PTR
        && ct.get_ptr_to().is_some_and(|p| p.get_metatype() == type_metatype::TYPE_VOID)
}

/// For a `void *` constant: does the reader convert any object pointer to
/// `void *` exactly as the cast did? An argument, a returned value, a value
/// stored or copied into `void *` storage, and an equality test against another
/// `void *` do; anything else keeps the cast.
fn void_reader_converts(fd: &Funcdata, op: OpId, vn: VarnodeId) -> bool {
    let Some(o) = fd.obank().get(op) else { return false };
    let slot = o.get_slot(vn);
    let ty_of = |v: Option<VarnodeId>| v.and_then(|v| fd.vbank().get(v)).map(|v| Rc::clone(v.get_type()));
    match o.code() {
        OpCode::CPUI_CALL | OpCode::CPUI_CALLIND | OpCode::CPUI_RETURN => slot >= 1,
        OpCode::CPUI_COPY => ty_of(o.get_out()).is_some_and(|t| is_void_pointer(&t)),
        OpCode::CPUI_STORE => {
            slot == 2
                && ty_of(o.get_in(1)).is_some_and(|t| {
                    t.get_metatype() == type_metatype::TYPE_PTR
                        && t.get_ptr_to().is_some_and(|p| is_void_pointer(&p))
                })
        }
        OpCode::CPUI_INT_EQUAL | OpCode::CPUI_INT_NOTEQUAL => {
            let other = o.get_in(1 - slot);
            other
                .and_then(|v| fd.vbank().get(v))
                .is_some_and(|v| is_void_pointer(v.get_type_read_facing(op)))
        }
        _ => false,
    }
}

#[cfg(test)]
#[path = "kuna_globalref/tests.rs"]
mod tests;
