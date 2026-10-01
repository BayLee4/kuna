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
//! `SpellCtx` (the former `printc::RealTypeCtx`) is `Copy` and is already
//! threaded through every declarator chokepoint. Carrying [`OutLang`] on it means
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

use kuna_base::types::{int4, uintb};

use crate::kuna_lang::OutLang;

/// Whether the spelling denotes one original name or language type grammar.
/// A host exporter must transform a nominal name as a whole, even when its
/// characters resemble pointer modifiers, keywords, or numeric literals.
#[derive(Clone, Copy, Debug)]
pub enum TypeTokenPolicy {
    NominalName,
    SpelledWords,
}

/// A nominal datatype leaf in one rendered fragment. Offsets are UTF-8 bytes,
/// relative to that fragment, not display columns or positions in a declaration.
#[derive(Clone, Debug)]
pub struct TypeSpan {
    pub start: usize,
    pub end: usize,
    pub id: uintb,
    pub policy: TypeTokenPolicy,
}

/// Spelling and optional host identity from the same type traversal.
///
/// Empty spans allocate nothing. Equality is deliberately not implemented:
/// declaration arbitration must compare spelling, never provenance.
#[derive(Clone, Debug, Default)]
pub struct TypeText {
    pub text: String,
    pub spans: Vec<TypeSpan>,
}

impl TypeText {
    pub fn plain(text: impl Into<String>) -> Self {
        Self { text: text.into(), spans: Vec::new() }
    }

    pub fn leaf(
        text: impl Into<String>, root: &crate::dtype::TypeRoot, annotate: bool,
        policy: TypeTokenPolicy,
    ) -> Self {
        let mut result = Self::plain(text);
        if annotate && !result.text.is_empty() {
            let id = root.get_unsized_id().expect("nominal datatype host ID");
            // Token boundaries remain authoritative even without a wire ID.
            result.spans.push(TypeSpan { start: 0, end: result.text.len(), id, policy });
        }
        result
    }

    pub fn push_str(&mut self, text: &str) {
        self.text.push_str(text);
    }

    pub fn prefix(&mut self, text: &str) {
        self.text.insert_str(0, text);
        for span in &mut self.spans {
            span.start += text.len();
            span.end += text.len();
        }
    }

    pub fn append(&mut self, mut other: Self) {
        if self.text.is_empty() {
            *self = other;
            return;
        }
        let offset = self.text.len();
        self.text.push_str(&other.text);
        for span in &mut other.spans {
            span.start += offset;
            span.end += offset;
        }
        if self.spans.is_empty() {
            self.spans = other.spans;
        } else {
            self.spans.append(&mut other.spans);
        }
    }

    /// Validate and freeze at the host queue boundary; plain text performs no
    /// span walk or allocation. Queued tokens may share these immutable IDs.
    pub fn into_parts(self) -> (String, Option<std::rc::Rc<[TypeSpan]>>) {
        if self.spans.is_empty() {
            return (self.text, None);
        }
        let mut previous_end = 0;
        for span in &self.spans {
            assert!(previous_end <= span.start && span.start < span.end
                && span.end <= self.text.len()
                && self.text.is_char_boundary(span.start)
                && self.text.is_char_boundary(span.end),
                "invalid datatype spelling span");
            previous_end = span.end;
        }
        (self.text, Some(self.spans.into()))
    }
}

/// The per-document type-rendering context (C++ has no analogue: the `realtypes`
/// and `ctypes` gates are kuna divergences).
///
/// `Copy`, so it threads cheaply through the declarator chokepoints.
#[derive(Clone, Copy)]
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
    pub(crate) conventions: bool,
    /// (kuna `ctypes`) The target's declared C scalar widths, which is what makes
    /// the spelling per-architecture rather than a guess.
    pub(crate) model: crate::kuna_ctypes::CDataModel,
}

impl SpellCtx {
    /// The disabled context — never relabels (preserves the upstream
    /// `xunknownN`/`undefined<N>` rendering).
    pub const OFF: SpellCtx = SpellCtx {
        lang: OutLang::C,
        enabled: false,
        long_is_8: true,
        ctypes: false,
        conventions: false,
        model: crate::kuna_ctypes::CDataModel::LP64,
    };

    /// The speller for this context's output language.
    #[inline]
    pub fn speller(&self) -> &'static dyn TypeSpeller {
        self.lang.speller()
    }
}

/// Per-language spelling of a recovered type.
///
/// Implementations are zero-sized policy objects reached through
/// [`OutLang::speller`]; the C one delegates to the ported declarator algorithm
/// verbatim, so routing through this trait is byte-identical for C.
pub trait TypeSpeller {
    /// Whether this document preserves a generic code base as the dialect's
    /// callable pseudotype, rather than spelling it as an object type.
    fn is_generic_callable(&self, _cx: &SpellCtx, _dt: &crate::dtype::TypeRoot) -> bool {
        false
    }

    /// The base-type name to use for `dt`, or `None` to keep the type's own
    /// declared name. `under_pointer` is true when a pointer modifier sits
    /// between `dt` and the declared object, which C uses to decide whether a
    /// width-less residual size may degrade to `void`.
    fn relabel(
        &self,
        cx: &SpellCtx,
        dt: &crate::dtype::TypeRoot,
        under_pointer: bool,
    ) -> Option<Cow<'static, str>>;

    /// The name for an anonymous (unnamed) base type — C's `undefined<N>`/`void`
    /// fallback.
    fn anonymous(&self, dt: &crate::dtype::TypeRoot) -> String;

    /// `(front, back)` such that `<front><name><back>` declares an object named
    /// `name` of type `ct`. A language whose types are pure prefixes returns an
    /// empty `back`.
    fn declarator(&self, cx: &SpellCtx, ct: &crate::dtype::TypeRoot) -> (String, String) {
        let (front, back) = self.declarator_annotated(cx, ct, false);
        (front.text, back.text)
    }

    fn declarator_annotated(
        &self, cx: &SpellCtx, ct: &crate::dtype::TypeRoot, annotate: bool,
    ) -> (TypeText, TypeText);

    /// `(front, back)` for a declaration's type position: the identifier and any
    /// `[count]` adornment go between them. Unlike [`TypeSpeller::declarator`], an
    /// anonymous non-pointer type keeps its whole-object name. `back` is non-empty
    /// only for a C pointer whose declarator needs a suffix (`char (*p)[16]`).
    fn type_name(&self, cx: &SpellCtx, t: &crate::dtype::TypeRoot) -> (String, String) {
        let (front, back) = self.type_name_annotated(cx, t, false);
        (front.text, back.text)
    }

    fn type_name_annotated(
        &self, cx: &SpellCtx, t: &crate::dtype::TypeRoot, annotate: bool,
    ) -> (TypeText, TypeText);

    /// Real name for a residual unknown of `size` bytes, or `None` when the
    /// language has no natural single type of that width.
    fn unknown_base(&self, size: int4, under_pointer: bool, long_is_8: bool)
        -> Option<Cow<'static, str>>;
}
