//! (kuna) The type-spelling seam: how a recovered [`Datatype`] is *named* in the
//! output language.
//!
//! # Recovery is language-independent; only spelling is not
//!
//! P5 recovers a `Datatype`; this module decides whether that shows up as
//! `uint4`, `unsigned int`, or `u32`. Spelling deliberately lives in the printer
//! rather than in the type factory, for the reason `kuna_ctypes.rs` already
//! records: [`Datatype::hash_name`] makes the registered name determine the type
//! id, identifier generation derives from the first character of the type name
//! (`float8` → `fVar1`), and the console's C-type parser resolves base types by
//! `TypeFactory::find_by_name` — so renaming the interned core types would break
//! the Ghidra wire protocol.
//!
//! # Why the language rides on [`SpellCtx`]
//!
//! `SpellCtx` (the former `printc::RealTypeCtx`) is borrowed through every
//! declarator chokepoint. Carrying [`OutLang`] on it means
//! the free-function declarator family learns the language with no new threading
//! and no new parameter: `rt.speller()` is available wherever `rt` already was.
//!
//! # The C declarator's `(front, back)` is a C-ism
//!
//! C declarators wrap the identifier (`int4 (*a)[1]`), so the C speller returns a
//! front/back pair. Rust's `[T; N]` and Go's `[N]T` are prefixes and would have
//! to fake the split, which is why [`TypeSpeller::declarator`] is documented in
//! terms of `<front><name><back>` rather than promising a meaningful `back`.
//!
//! [`Datatype`]: crate::dtype::Datatype
//! [`Datatype::hash_name`]: crate::dtype::Datatype

use std::borrow::Cow;
use std::rc::Rc;

use kuna_base::types::int4;

use crate::dtype::Datatype;
use crate::kuna_lang::OutLang;

/// A base-type leaf in the spelling, bound to its actual native owner.
pub struct DeclaratorTypeSpan {
    pub range: std::ops::Range<usize>,
    pub datatype: Rc<Datatype>,
}

/// The ordinary declarator bytes, optionally accompanied by typed base leaves.
/// Empty vectors cost no allocation on the ordinary spelling path.
#[derive(Default)]
pub struct TypedDeclarator {
    pub front: String,
    pub back: String,
    pub front_types: Vec<DeclaratorTypeSpan>,
    pub back_types: Vec<DeclaratorTypeSpan>,
}

impl TypedDeclarator {
    fn leaf((front, back): (String, String), datatype: &Rc<Datatype>) -> Self {
        let front_types = vec![DeclaratorTypeSpan {
            range: 0..front.len(), datatype: Rc::clone(datatype),
        }];
        Self { front, back, front_types, back_types: Vec::new() }
    }
}

/// The per-document type-rendering context (C++ has no analogue: the `realtypes`
/// and `ctypes` gates are kuna divergences).
///
/// The registry handle is acquired once per document; declarators borrow this
/// context rather than cloning the registry or repainting held source models.
#[derive(Clone)]
pub struct SpellCtx {
    /// The output language, which selects the [`TypeSpeller`].
    pub(crate) lang: OutLang,
    /// (kuna `realtypes`) Relabel residual `TYPE_UNKNOWN` bases as real types.
    pub(crate) enabled: bool,
    /// The data-model fact that `long` is 8 bytes, so an 8-byte unknown reads
    /// `unsigned long` on LP64 and `unsigned long long` on LLP64.
    pub(crate) long_is_8: bool,
    /// (kuna `ctypes`) Spell the NAMED core types (`int4`/`uint1`/`float8`/`code`)
    /// as the target's own type names too, not just the residual unknowns.
    pub(crate) ctypes: bool,
    /// (kuna `ctypes`) The target's declared C scalar widths, which is what makes
    /// the spelling per-architecture rather than a guess.
    pub(crate) model: crate::kuna_ctypes::CDataModel,
    /// (kuna `indirectargs`) Spell an indirectly passed parameter at its value type.
    pub(crate) indirect_args: bool,
    /// The active printer's convention option, independent of model visibility.
    pub(crate) convention: bool,
    /// The architecture's existing live registry, not a model snapshot.
    pub(crate) model_visibility: Option<crate::architecture::ModelVisibility>,
    /// Ordinary host headers do not declare bare FunctionDefinition names.
    pub(crate) inline_host_callables: bool,
}

impl SpellCtx {
    /// The disabled context — never relabels (preserves the upstream
    /// `xunknownN`/`undefined<N>` rendering).
    pub const OFF: SpellCtx = SpellCtx {
        lang: OutLang::C,
        enabled: false,
        long_is_8: true,
        ctypes: false,
        model: crate::kuna_ctypes::CDataModel::LP64,
        indirect_args: false,
        convention: false,
        model_visibility: None,
        inline_host_callables: false,
    };

    /// The speller for this context's output language.
    #[inline]
    pub fn speller(&self) -> &'static dyn TypeSpeller {
        self.lang.speller()
    }

    /// Exact held prototype spelling, subject only to current presentation
    /// visibility and this document's option/language gates.
    pub(crate) fn convention_name<'a>(&self, proto: &'a crate::fspec::FuncProto) -> Option<&'a str> {
        (self.convention && self.lang == OutLang::C
            && crate::architecture::model_print_in_decl(self.model_visibility.as_ref(), proto))
            .then(|| proto.get_model_name())
    }
}

/// Per-language spelling of a recovered type.
///
/// Implementations are zero-sized policy objects reached through
/// [`OutLang::speller`]; the C one delegates to the ported declarator algorithm
/// with one shared traversal for ordinary and identity-bound typed spelling.
pub trait TypeSpeller {
    /// The base-type name to use for `dt`, or `None` to keep the type's own
    /// declared name. `under_pointer` is true when a pointer modifier sits
    /// between `dt` and the declared object, which C uses to decide whether a
    /// width-less residual size may degrade to `void`.
    fn relabel(
        &self,
        cx: &SpellCtx,
        dt: &Rc<Datatype>,
        under_pointer: bool,
    ) -> Option<Cow<'static, str>>;

    /// The name for an anonymous (unnamed) base type — C's `undefined<N>`/`void`
    /// fallback.
    fn anonymous(&self, dt: &Rc<Datatype>) -> String;

    /// `(front, back)` such that `<front><name><back>` declares an object named
    /// `name` of type `ct`. A language whose types are pure prefixes returns an
    /// empty `back`.
    fn declarator(&self, cx: &SpellCtx, ct: &Rc<Datatype>) -> (String, String);

    fn typed_declarator(&self, cx: &SpellCtx, ct: &Rc<Datatype>) -> TypedDeclarator {
        TypedDeclarator::leaf(self.declarator(cx, ct), ct)
    }

    /// `(front, back)` for a declaration's type position: the identifier and any
    /// `[count]` adornment go between them. Unlike [`TypeSpeller::declarator`], an
    /// anonymous non-pointer type keeps its whole-object name. `back` is non-empty
    /// only for a C pointer whose declarator needs a suffix (`char (*p)[16]`).
    fn type_name(&self, cx: &SpellCtx, t: &Rc<Datatype>) -> (String, String);

    fn typed_type_name(&self, cx: &SpellCtx, t: &Rc<Datatype>) -> TypedDeclarator {
        TypedDeclarator::leaf(self.type_name(cx, t), t)
    }

    /// Real name for a residual unknown of `size` bytes, or `None` when the
    /// language has no natural single type of that width.
    fn unknown_base(&self, size: int4, under_pointer: bool, long_is_8: bool)
        -> Option<Cow<'static, str>>;
}

/// Java encodes both object references and arrays as p-code pointers.
pub(crate) fn java_array_type(dt: &Datatype) -> bool {
    use crate::dtype::type_metatype::*;
    let Some(base) = dt.get_ptr_to() else { return false };
    match base.get_metatype() {
        TYPE_UINT => base.is_char_print(),
        TYPE_INT | TYPE_BOOL | TYPE_FLOAT | TYPE_PTR => true,
        _ => false,
    }
}

pub struct JavaSpeller;
pub static JAVA_SPELLER: JavaSpeller = JavaSpeller;

impl JavaSpeller {
    fn spelling(&self, dt: &Rc<Datatype>) -> (String, Rc<Datatype>, usize) {
        let mut base = Rc::clone(dt);
        let mut arrays = 0;
        let mut object = false;
        while let Some(next) = base.get_ptr_to() {
            object = !java_array_type(&base);
            arrays += usize::from(java_array_type(&base));
            base = next;
        }
        // JVM object placeholders have a declared class name; primitives are
        // spelled from their semantic metatype rather than C's uintN aliases.
        let mut name = if !base.get_name().is_empty()
            && (object || !matches!(base.get_metatype(), crate::dtype::type_metatype::TYPE_INT
                | crate::dtype::type_metatype::TYPE_UINT
                | crate::dtype::type_metatype::TYPE_FLOAT
                | crate::dtype::type_metatype::TYPE_BOOL
                | crate::dtype::type_metatype::TYPE_UNKNOWN))
        {
            base.get_display_name().replace("::", ".")
        } else if base.is_char_print() && base.get_size() == 2 {
            "char".into()
        } else {
            use crate::dtype::type_metatype::*;
            match (base.get_metatype(), base.get_size()) {
                (TYPE_VOID, _) => "void".into(),
                (TYPE_BOOL, _) => "boolean".into(),
                (TYPE_FLOAT, 4) => "float".into(),
                (TYPE_FLOAT, 8) => "double".into(),
                (TYPE_INT | TYPE_UINT | TYPE_UNKNOWN, 1) => "byte".into(),
                (TYPE_INT | TYPE_UINT | TYPE_UNKNOWN, 2) => "short".into(),
                (TYPE_INT | TYPE_UINT | TYPE_UNKNOWN, 4) => "int".into(),
                (TYPE_INT | TYPE_UINT | TYPE_UNKNOWN, 8) => "long".into(),
                _ if !base.get_name().is_empty() => base.get_display_name().replace("::", "."),
                _ => "void".into(),
            }
        };
        let base_end = name.len();
        for _ in 0..arrays { name.push_str("[]"); }
        (name, base, base_end)
    }
}

impl TypeSpeller for JavaSpeller {
    fn relabel(&self, _cx: &SpellCtx, dt: &Rc<Datatype>, _under_pointer: bool) -> Option<Cow<'static, str>> {
        Some(Cow::Owned(self.spelling(dt).0))
    }
    fn anonymous(&self, dt: &Rc<Datatype>) -> String { self.spelling(dt).0 }
    fn declarator(&self, _cx: &SpellCtx, dt: &Rc<Datatype>) -> (String, String) {
        (self.spelling(dt).0, String::new())
    }
    fn typed_declarator(&self, _cx: &SpellCtx, dt: &Rc<Datatype>) -> TypedDeclarator {
        let (front, datatype, end) = self.spelling(dt);
        TypedDeclarator {
            front, front_types: vec![DeclaratorTypeSpan { range: 0..end, datatype }],
            ..Default::default()
        }
    }
    fn type_name(&self, cx: &SpellCtx, dt: &Rc<Datatype>) -> (String, String) {
        self.declarator(cx, dt)
    }
    fn typed_type_name(&self, cx: &SpellCtx, dt: &Rc<Datatype>) -> TypedDeclarator {
        self.typed_declarator(cx, dt)
    }
    fn unknown_base(&self, size: int4, _under_pointer: bool, _long_is_8: bool) -> Option<Cow<'static, str>> {
        Some(Cow::Borrowed(match size { 1 => "byte", 2 => "short", 4 => "int", 8 => "long", _ => return None }))
    }
}
