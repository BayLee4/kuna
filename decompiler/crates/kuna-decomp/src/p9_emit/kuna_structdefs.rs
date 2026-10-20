//! (kuna) The per-function type-definition preamble — no upstream Ghidra
//! equivalent, and the one half of `docTypeDefinitions` that never had a caller
//! outside `kuna decompile-project`.
//!
//! A decompiled body that reads `*(int *)(a0 + 8)` and one that reads
//! `f->_flags` are the same recovery; only the second one tells the reader what
//! the argument IS.  kuna already knows: the type factory holds the composite,
//! and `kuna decompile-project` writes every one of them into the export's
//! `.h`.  A single function printed to a terminal got none of it — the struct
//! name appeared in the signature (`int get_prefix(FILE *f)`) and nothing said
//! what a `FILE` was, so the layout the decompiler recovered stayed invisible to
//! the one surface agents actually read.
//!
//! angr prints its typedefs above the function for exactly this reason, and
//! that is what `option structdefs on` does here: the composite, enum, callable and
//! typedef definitions the function's own C names, in dependency order, above
//! the body.
//!
//! ## Which types
//!
//! The roots are the function's semantic type surface — its prototype's return
//! and parameter types, every Varnode's data-type, and every mapped Symbol type
//! behind a HighVariable, plus retained source types of volatile annotations
//! (which have no HighVariable). That is a SUPERSET of the type names the printer can
//! spell: every type name in the emitted C is read off one of those roots
//! (declarations from the highs and their symbols, the signature from the
//! prototype, a cast from the Varnode type it casts to), so the preamble cannot
//! miss a definition the body refers to.  Collecting from the token stream
//! instead would be exact, but it would also miss the struct behind
//! `p->field_0x8`, whose tag name is never printed at all.
//!
//! From those roots the walk descends through typedef bases and component
//! types ([`Datatype::get_depend`]) — a pointer's pointee, an array's element,
//! a struct's fields — so a struct whose field is another struct pulls in both,
//! and the postorder push is definition-before-use by construction (the same
//! order [`TypeFactoryImpl::dependent_order`](crate::dtype::TypeFactoryImpl::dependent_order)
//! produces, computed over the
//! referenced subset rather than the whole factory, which is what keeps a
//! whole-binary run linear in the types a function actually touches).
//!
//! ## One rendering, two surfaces
//!
//! The text is `printc::render_type_definitions`, the same renderer
//! that builds `kuna decompile-project`'s `.h` type block, over the subset:
//! the forward-declaration block, then bodies, with an incomplete struct
//! printing as `typedef struct FILE FILE; /* opaque */`.  So a preamble line and
//! the header line for the same type are the same line, and a project export's
//! `.c` bodies deliberately DO NOT carry the preamble — they include the header
//! that already holds it.
//!
//! Enum bodies retain the recovered storage width and signedness with packed
//! declarations and explicit range endpoints; a small set of positive flag
//! names must not silently turn a signed 64-bit producer type into C's
//! default-width unsigned enum. The recovered names and values are unchanged.

use std::collections::HashSet;
use std::rc::Rc;

use kuna_base::error::KunaResult;
use kuna_base::marshal::ElementId;

use crate::dtype::{Datatype, DatatypeKind};
use crate::funcdata::Funcdata;
use crate::kuna_langtypes::SpellCtx;
use crate::options::on_or_off;
use crate::printc::{
    compose_enum_body, compose_type_body, compose_typedef_line, sanitize_type_name,
};

/// Marshaling element `<structdefs>` (kuna 4000+ range; 4173 = the previous
/// highest kuna id).
pub const ELEM_STRUCTDEFS: ElementId = ElementId::new("structdefs", 4174);

/// (kuna) Toggle the per-function type-definition preamble: `structdefs on|off`.
///
/// "off" (the default) keeps the bare function document; "on" prints the
/// definitions of the composite/enum/typedef types the function's C names above
/// it.
#[derive(Debug, Clone, Copy, Default)]
pub struct OptionStructDefs;

impl OptionStructDefs {
    /// The option name.
    pub const NAME: &'static str = "structdefs";

    /// Parse + validate the `on`/`off` value; the caller performs the printer
    /// write ([`crate::printc::PrintCOptions::set_struct_defs`]).
    pub fn apply(&self, p1: &str) -> KunaResult<(bool, String)> {
        let val = on_or_off(p1)?;
        let prop = if val { "on" } else { "off" };
        Ok((val, format!("Per-function type definitions turned {prop}")))
    }
}

/// Is `ct` a type this preamble defines?
///
/// The predicate `render_type_definitions` applies to the `.h`: a user-defined
/// (non-core), named, non-partial typedef / struct / union / enum / callable. Core types
/// (`int4`, `undefined8`, `char`) are never defined — they are the language's,
/// and the project export declares them once in its recompile prelude.
pub fn is_definable(ct: &Rc<Datatype>) -> bool {
    let composite = matches!(
        &ct.kind,
        DatatypeKind::Struct { .. } | DatatypeKind::Union { .. }
    );
    !ct.is_core_type()
        && !ct.get_name().is_empty()
        && !ct.has_stripped()
        && (ct.get_typedef().is_some() || composite || ct.is_enum_type()
            || ct.get_code_prototype().is_some_and(|proto| proto.has_store()))
}

/// The definable types `fd`'s printed C can name, in definition-before-use
/// order (see the module header for the roots and why they are a superset of
/// what the printer spells).
pub fn referenced_types<'a>(
    fd: &Funcdata, additional_roots: impl IntoIterator<Item = &'a Rc<Datatype>>,
) -> Vec<Rc<Datatype>> {
    let mut order: Vec<Rc<Datatype>> = Vec::new();
    let mut seen: HashSet<*const Datatype> = HashSet::new();

    let proto = fd.get_func_proto();
    if proto.has_store() {
        if let Some(ty) = proto.get_output_type() {
            visit(ty, &mut seen, &mut order);
        }
        for i in 0..proto.num_params() {
            if let Some(ty) = proto.get_param(i).and_then(|p| p.get_type()) {
                visit(ty, &mut seen, &mut order);
            }
        }
    }
    for id in fd.vbank().iter_loc() {
        let Some(vn) = fd.vbank().get(id) else { continue };
        visit(vn.get_type(), &mut seen, &mut order);
        if let Some(sym) = vn
            .get_high()
            .and_then(|h| fd.high_bank().get(h))
            .and_then(|h| h.kuna_symbol_type())
        {
            visit(sym, &mut seen, &mut order);
        }
    }
    for root in additional_roots {
        visit(root, &mut seen, &mut order);
    }
    order
}

/// Postorder DFS over one type's dependency cone (C++
/// `TypeFactory::orderRecurse`, type.cc, restricted to a root set): the typedef
/// base and every component sub-type first, then the type itself if it is one
/// the preamble defines.  The mark set keys on `Rc` object identity, so a
/// pointer cycle (`struct A { struct B *b; }; struct B { struct A *a; };`)
/// terminates with each data-type visited once.
fn visit(ct: &Rc<Datatype>, seen: &mut HashSet<*const Datatype>, order: &mut Vec<Rc<Datatype>>) {
    if !seen.insert(Rc::as_ptr(ct)) {
        return;
    }
    if let Some(base) = ct.qualified_base() {
        // A qualified view names the underlying source type, not a new
        // typedef/record declaration of its own.
        visit(base, seen, order);
        return;
    }
    if let Some(base) = ct.get_typedef() {
        let base = Rc::clone(base);
        visit(&base, seen, order);
    }
    // A callback typedef names its source signature's types even though the
    // upstream TypeCode component API does not enumerate them.
    if let Some(proto) = ct.get_code_prototype() {
        if let Some(source) = proto.logical_pieces() {
            if let Some(output) = source.outtype.as_ref()
                .or_else(|| source.output_storage.as_ref().and_then(|p| p.type_.as_ref()))
            {
                visit(output, seen, order);
            }
            for input in &source.intypes {
                visit(input, seen, order);
            }
        }
        if proto.has_store() && (proto.logical_pieces().is_none()
            || (0..proto.num_params()).any(|slot|
                proto.get_param(slot).is_some_and(|param| param.is_hidden_return())))
        {
            if let Some(output) = proto.get_output_type() {
                visit(output, seen, order);
            }
            for slot in 0..proto.num_params() {
                if let Some(input) = proto.get_param(slot).and_then(|p| p.get_type()) {
                    visit(input, seen, order);
                }
            }
        }
    }
    for i in 0..ct.num_depend() {
        if let Some(dep) = ct.get_depend(i) {
            visit(&dep, seen, order);
        }
    }
    if is_definable(ct) {
        order.push(Rc::clone(ct));
    }
}

/// One record per NAME, for the machine-readable surface.
///
/// The factory can hold two data-types under one name — a DWARF image carries
/// both the forward-declared `struct _IO_FILE` and the defined one — and the
/// rendered text already resolves that (`render_type_definitions` prints one
/// forward declaration and one body, and drops the `/* opaque */` note when a
/// complete definition exists somewhere).  A JSON consumer has no such rule to
/// apply, and one name carrying both a laid-out body and an opaque forward
/// declaration is a contradiction, so the complete definition wins and a repeat
/// of an already-reported name is dropped.  Order is otherwise preserved.
///
/// Completeness, not size, is the test: an incomplete type still reports the
/// size it was created at (a `libctypes` `FILE` shell is 216 bytes with no
/// member known), so the two records would agree on `size` and disagree on
/// everything else.
pub fn dedup_by_name(types: &[Rc<Datatype>]) -> Vec<Rc<Datatype>> {
    let complete: HashSet<&str> = types
        .iter()
        .filter(|ct| !ct.is_incomplete())
        .map(|ct| ct.get_name())
        .collect();
    let mut taken: HashSet<String> = HashSet::new();
    types
        .iter()
        .filter(|ct| !(ct.is_incomplete() && complete.contains(ct.get_name())))
        .filter(|ct| taken.insert(ct.get_name().to_string()))
        .map(Rc::clone)
        .collect()
}

/// The presentation path distinguishes same-named producer nominals. A
/// declaration/completion pair shares its explicit factory identity; neither
/// size nor layout establishes equivalence.
pub fn dedup_by_identity(types: &[Rc<Datatype>]) -> Vec<Rc<Datatype>> {
    let complete: HashSet<(&str, u64)> = types.iter()
        .filter(|ct| !ct.is_incomplete())
        .map(|ct| (ct.get_name(), ct.get_id()))
        .collect();
    let mut taken = HashSet::new();
    types.iter()
        .filter(|ct| !(ct.is_incomplete() && complete.contains(&(ct.get_name(), ct.get_id()))))
        .filter(|ct| taken.insert((ct.get_name(), ct.get_id())))
        .map(Rc::clone)
        .collect()
}

/// ONE type's definition text, the line(s) `render_type_definitions` would give
/// it in the `.h`: the body for a complete struct/union, the enum block, the
/// `typedef <base> <name>;` line, and the forward declaration alone for an
/// incomplete (opaque) composite.
///
/// The machine-readable half of the preamble (`kuna decompile-all --json`'s
/// per-function `types` array), so a consumer reads the recovered layout
/// without parsing C out of the body.  Returns `""` for a type the preamble does
/// not define.
pub fn definition_text(ct: &Rc<Datatype>, rt: &SpellCtx) -> String {
    definition_text_with_names(ct, rt, None)
}

/// Render a retained nominal through the invocation's identity-bound spelling.
pub fn definition_text_with_names(
    ct: &Rc<Datatype>,
    rt: &SpellCtx,
    names: Option<&std::collections::BTreeMap<usize, String>>,
) -> String {
    let raw = ct.get_name();
    let name = names
        .and_then(|names| names.get(&(Rc::as_ptr(ct) as usize)))
        .map(|name| std::borrow::Cow::Borrowed(name.as_str()))
        .unwrap_or_else(|| sanitize_type_name(raw));
    if let Some(base) = ct.get_typedef() {
        if base.get_name().is_empty() && base.is_enum_type() {
            return compose_enum_body(base, &name);
        }
        if names.is_some() {
            return format!("typedef {};\n", crate::printc::declaration_text_with_names(base, &name, rt, names));
        }
        return compose_typedef_line(base, &name, rt);
    }
    match &ct.kind {
        DatatypeKind::Struct { .. } | DatatypeKind::Union { .. } => {
            let kw = if matches!(&ct.kind, DatatypeKind::Union { .. }) { "union" } else { "struct" };
            if ct.is_incomplete() {
                format!("typedef {kw} {name} {name}; /* opaque */\n")
            } else {
                if names.is_some() {
                    crate::printc::compose_type_body_with_names(ct, &name, rt, names)
                } else {
                    compose_type_body(ct, &name, rt)
                }
            }
        }
        _ if ct.is_enum_type() => compose_enum_body(ct, &name),
        DatatypeKind::Code { proto: Some(proto) } if proto.has_store() =>
            crate::printc::compose_callable_definition(ct, &name, rt, names),
        _ => String::new(),
    }
}

#[cfg(test)]
#[path = "kuna_structdefs/tests.rs"]
mod tests;
