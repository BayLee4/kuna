//! (kuna) The c-language policy objects: the concrete half of the output-language
//! seam for C.
//!
//! [`CSpeller`] carries the declarator algorithm transcribed from
//! `PrintC::pushTypeStart` / `pushTypeEnd` (printc.cc:265/314) plus
//! `buildTypeStack` (printc.cc:143), together with the kuna `realtypes`/`ctypes`
//! relabelling (DIV-5/DIV-6). The declarator algorithm lives here;
//! `printc.rs` keeps thin dispatchers borrowing the document's spelling context.
//!
//! Callable convention publication uses the same current registry visibility
//! as ordinary function declarations and the active printer's convention option.
//! Each Code modifier contributes its own exact model spelling before pointer
//! grouping. Ordinary host documents expand bare managed callables lacking C
//! typedef declarations; other named Code references and true aliases stay
//! nominal. Presentation never changes a held model or physical ABI storage.

use std::borrow::Cow;
use std::rc::Rc;

use kuna_base::types::int4;

use crate::dtype::{type_metatype, Datatype};
use crate::kuna_langtypes::{DeclaratorTypeSpan, SpellCtx, TypedDeclarator, TypeSpeller};

/// The c-language type speller.
pub struct CSpeller;

/// The singleton reached through `OutLang::C.speller()`.
pub static C_SPELLER: CSpeller = CSpeller;

/// The part of a C declarator that surrounds its identifier.
///
/// C's prefix (`*`) and postfix (`[]`/`()`) operators have opposite binding
/// directions.  Keeping the two halves explicit lets us add modifiers from the
/// outside of the type toward its base without losing that precedence.  In
/// particular, a postfix applied after an ungrouped pointer must wrap the WHOLE
/// declarator accumulated so far: `*a` + `[4]` becomes `(*a)[4]`, while
/// `a[4]` + `*` becomes `*a[4]`.
#[derive(Default)]
struct CDeclarator {
    front: String,
    back: String,
    back_types: Vec<DeclaratorTypeSpan>,
    /// A pointer prefix has been added since the last postfix grouped it.
    ungrouped_pointer: bool,
}

impl CDeclarator {
    fn pointer(&mut self) {
        self.front.insert(0, '*');
        self.ungrouped_pointer = true;
    }

    fn qualified_pointer(&mut self, qualifiers: u8) {
        // We are walking from the outer type toward the base.  A newly reached
        // pointer belongs nearest the base type, so it prefixes the complete
        // declarator already accumulated around the identifier.
        if qualifiers == 0 {
            self.pointer();
            return;
        }
        let text = crate::kuna_typequal::spelling(qualifiers);
        let gap = if self.front.is_empty() { "" } else { " " };
        self.front.insert_str(0, &format!("* {text}{gap}"));
        self.ungrouped_pointer = true;
    }

    fn postfix(&mut self, suffix: &str) {
        if self.ungrouped_pointer {
            // Group the complete current declarator, including any postfixes
            // already accumulated.  Closing before `self.back` would turn
            // `*a[2]` + `[3]` into `(*a)[2][3]` instead of `(*a[2])[3]`.
            self.front.insert(0, '(');
            self.back.push(')');
            self.ungrouped_pointer = false;
        }
        self.back.push_str(suffix);
    }

    fn callable_postfix(&mut self, suffix: &str, convention: Option<&str>) {
        // Bind the keyword to THIS Code modifier before pointer grouping.
        // A factory's convention must not migrate to its returned callback.
        if let Some(convention) = convention {
            if !self.front.is_empty() {
                self.front.insert(0, ' ');
            }
            self.front.insert_str(0, convention);
        }
        self.postfix(suffix);
    }
}

impl TypeSpeller for CSpeller {
    /// Real C name for a residual `TYPE_UNKNOWN` base, or `None` when the gate is
    /// off / the type is not unknown. Conservative on sign (multi-byte unknowns
    /// are unsigned, since the real sign is genuinely unknown); a pointer-to-
    /// unknown base relabels through the same size table as a scalar, so the
    /// pointee keeps its width and `void` is only the residual fallback.
    fn relabel(
        &self,
        cx: &SpellCtx,
        dt: &Rc<Datatype>,
        under_pointer: bool,
    ) -> Option<Cow<'static, str>> {
        if dt.get_metatype() == type_metatype::TYPE_UNKNOWN {
            if !cx.enabled {
                return None;
            }
            return self.unknown_base(dt.get_size(), under_pointer, cx.long_is_8);
        }
        // (kuna `ctypes`) Every OTHER core type -- the named `int4`/`uint1`/
        // `float8`/`code` vocabulary -- spells as the target's own C type.
        // Restricted to core types so a user-defined or DWARF-recovered type keeps
        // the name it was declared with; that name is already C.
        if !cx.ctypes || !dt.is_core_type() {
            return None;
        }
        // A source-provided C scalar already carries a rank, not just a
        // width. On LP64 `long long` and `long` are both eight bytes but are
        // different C types (_Generic and pointer compatibility observe it).
        // Only internal width vocabulary should use the size approximation.
        let source_spelling = match (dt.get_metatype(), dt.get_name()) {
            (type_metatype::TYPE_INT, "signed char") => Some("signed char"),
            (type_metatype::TYPE_INT, "short") => Some("short"),
            (type_metatype::TYPE_INT, "int") => Some("int"),
            (type_metatype::TYPE_INT, "long") => Some("long"),
            (type_metatype::TYPE_INT, "long long") => Some("long long"),
            (type_metatype::TYPE_UINT, "unsigned char") => Some("unsigned char"),
            (type_metatype::TYPE_UINT, "unsigned short") => Some("unsigned short"),
            (type_metatype::TYPE_UINT, "unsigned int") => Some("unsigned int"),
            (type_metatype::TYPE_UINT, "unsigned long") => Some("unsigned long"),
            (type_metatype::TYPE_UINT, "unsigned long long") => Some("unsigned long long"),
            _ => None,
        };
        if let Some(spelling) = source_spelling {
            return Some(Cow::Borrowed(spelling));
        }
        crate::kuna_ctypes::core_type_spelling(
            &cx.model,
            dt.get_metatype(),
            dt.get_size(),
            dt.is_char_print(),
        )
        .map(Cow::Borrowed)
    }

    fn anonymous(&self, dt: &Rc<Datatype>) -> String {
        match dt.get_metatype() {
            type_metatype::TYPE_VOID => "void".to_string(),
            _ => format!("undefined{}", dt.get_size()),
        }
    }

    /// The stack is built base-up exactly as `buildTypeStack`; pointer modifiers
    /// go on the front (`*`), array modifiers on the tail (`[N]`), and a `*`
    /// front nested inside an array tail is parenthesised -- the precedence the
    /// RPN `ptr_expr`/`array_expr` tokens encode. Stored code prototypes supply
    /// function suffixes through the same `CDeclarator::postfix` grouping rule.
    fn declarator(&self, cx: &SpellCtx, ct: &Rc<Datatype>) -> (String, String) {
        let spelling = self.build_declarator(cx, ct, false, false);
        (spelling.front, spelling.back)
    }

    fn typed_declarator(&self, cx: &SpellCtx, ct: &Rc<Datatype>) -> TypedDeclarator {
        self.build_declarator(cx, ct, true, false)
    }

    fn typed_type_name(&self, cx: &SpellCtx, t: &Rc<Datatype>) -> TypedDeclarator {
        if t.qualified_base().is_some()
            || self.inline_host_callable(cx, t)
            || (t.get_name().is_empty()
                && matches!(t.get_metatype(), type_metatype::TYPE_PTR | type_metatype::TYPE_CODE))
        {
            return self.build_declarator(cx, t, true, false);
        }
        let (front, back) = self.type_name(cx, t);
        let end = front.len();
        TypedDeclarator {
            front, back,
            front_types: vec![DeclaratorTypeSpan { range: 0..end, datatype: Rc::clone(t) }],
            back_types: Vec::new(),
        }
    }

    fn type_name(&self, cx: &SpellCtx, t: &Rc<Datatype>) -> (String, String) {
        self.spell_type_name(cx, t)
    }

    fn unknown_base(
        &self,
        size: int4,
        under_pointer: bool,
        long_is_8: bool,
    ) -> Option<Cow<'static, str>> {
        self.spell_unknown_base(size, under_pointer, long_is_8)
    }
}

impl CSpeller {
    /// Define a function type, expanding its outer Code name. Nested callables
    /// follow the host declaration policy; actual aliases remain nominal.
    pub(crate) fn callable_definition(&self, cx: &SpellCtx, ct: &Rc<Datatype>) -> TypedDeclarator {
        self.build_declarator(cx, ct, true, true)
    }

    /// Borrow a call site's declaration without allocating a Code type or
    /// acquiring physical ABI storage. All type leaves keep their source owners.
    pub(crate) fn callable_pointer(&self, cx: &SpellCtx, proto: &crate::fspec::FuncProto) -> Option<TypedDeclarator> {
        let logical = crate::kuna_indirectargs::callable_logical(proto,cx.indirect_args,cx.hidden_results);
        let output = logical.and_then(|pieces| pieces.outtype.as_ref()
            .or_else(|| pieces.output_storage.as_ref().and_then(|piece| piece.type_.as_ref())))
            .or_else(|| proto.has_store().then(|| proto.get_output_type()).flatten())?;
        if logical.is_none() && (!proto.has_store() || (0..proto.num_params()).any(|slot|
            proto.get_param(slot).and_then(|param| param.get_type()).is_none()))
        {
            return None;
        }
        let mut decl = CDeclarator::default();
        decl.pointer();
        let mut active = Vec::new();
        self.callable_suffix(cx,proto,true,false,&mut decl,&mut active);
        Some(self.build_declarator_with_prefix(cx,output,true,false,decl,&mut active))
    }

    /// A generic Code leaf has no source prototype. For a result-discarding,
    /// zero-argument numeric transfer, C11's unspecified-parameter function
    /// spelling preserves callability without manufacturing a FuncProto.
    pub(crate) fn generic_callable_pointer(&self, cx: &SpellCtx, code: &Rc<Datatype>) -> Option<TypedDeclarator> {
        if cx.lang != crate::kuna_lang::OutLang::C || !cx.ctypes
            || !code.is_core_type() || code.get_metatype() != type_metatype::TYPE_CODE
            || code.get_code_prototype().is_some() || code.get_typedef().is_some()
            || code.qualified_base().is_some() || code.c_qualifiers() != 0
        {
            return None;
        }
        let mut decl = CDeclarator::default();
        decl.pointer();
        decl.callable_postfix("()", None);
        Some(self.build_declarator_with_prefix(cx,code,true,false,decl,&mut Vec::new()))
    }

    fn build_declarator(&self, cx: &SpellCtx, ct: &Rc<Datatype>, typed: bool, define_callable: bool) -> TypedDeclarator {
        self.build_declarator_with_prefix(cx,ct,typed,define_callable,CDeclarator::default(),&mut Vec::new())
    }

    fn inline_host_callable(&self, cx: &SpellCtx, ct: &Datatype) -> bool {
        cx.inline_host_callables && ct.is_host_type() && !ct.get_name().is_empty()
            && ct.get_metatype() == type_metatype::TYPE_CODE
            && ct.get_typedef().is_none() && ct.get_code_prototype().is_some()
    }

    fn build_declarator_with_prefix(
        &self, cx: &SpellCtx, ct: &Rc<Datatype>, typed: bool, define_callable: bool, mut decl: CDeclarator,
        active: &mut Vec<*const Datatype>,
    ) -> TypedDeclarator {
        let inherited = active.len();
        // buildTypeStack: walk to the base (named) type, recording the modifiers.
        let mut stack: Vec<(Rc<Datatype>, u8)> = Vec::new();
        let mut cur = Rc::clone(ct);
        loop {
            let qualifiers = cur.c_qualifiers();
            if let Some(base) = cur.qualified_base() {
                cur = Rc::clone(base);
            }
            stack.push((Rc::clone(&cur), qualifiers));
            let definition_root = define_callable && stack.len() == 1
                && cur.get_metatype() == type_metatype::TYPE_CODE
                && cur.get_typedef().is_none();
            let inline_callable = self.inline_host_callable(cx, &cur)
                && !active.contains(&Rc::as_ptr(&cur))
                && !stack[..stack.len() - 1].iter().any(|(ancestor, _)| Rc::ptr_eq(ancestor, &cur));
            if !cur.get_name().is_empty() && !definition_root && !inline_callable {
                break; // base type
            }
            let next = match cur.get_metatype() {
                type_metatype::TYPE_PTR => cur.get_ptr_to(),
                type_metatype::TYPE_ARRAY => cur.get_array_base(),
                type_metatype::TYPE_CODE => cur
                    .get_code_prototype()
                    .and_then(|proto| (if define_callable || inline_callable { proto.logical_pieces() }
                        else { crate::kuna_indirectargs::callable_logical(proto, cx.indirect_args, cx.hidden_results) })
                        .and_then(|pieces| pieces.outtype.as_ref()
                            .or_else(|| pieces.output_storage.as_ref().and_then(|piece| piece.type_.as_ref())))
                        .or_else(|| proto.has_store().then(|| proto.get_output_type()).flatten()).cloned()),
                _ => None, // other anonymous type: stop
            };
            match next {
                Some(n) => cur = n,
                None => break,
            }
        }
        // The base type's display name (anonymous -> `undefined<N>` / `void`).
        let (base, qualifiers) = stack.last().expect("declarator: non-empty stack");
        // (kuna) realtypes: relabel a residual TYPE_UNKNOWN base as a real C type
        // by size. Under a pointer modifier the same size table applies, so the
        // pointee width survives into the declaration; only a residual size with
        // no natural C type degrades to `void` there (the `*` chain is laid out by
        // the walk below).
        let under_pointer = stack[..stack.len() - 1]
            .iter()
            .rev()
            .map(|(m, _)| m)
            .take_while(|m| m.get_metatype() != type_metatype::TYPE_CODE)
            .any(|m| matches!(m.get_metatype(), type_metatype::TYPE_PTR));
        let base_name = if let Some(n) = self.relabel(cx, base, under_pointer) {
            n.into_owned()
        } else if base.get_name().is_empty() {
            self.anonymous(base)
        } else {
            base.get_display_name().to_string()
        };

        let base_name_len = base_name.len();
        let qualifier_text = crate::kuna_typequal::spelling(*qualifiers);
        let base_name_start = if qualifier_text.is_empty() { 0 } else { qualifier_text.len() + 1 };
        let base_name = if qualifier_text.is_empty() {
            base_name
        } else {
            format!("{qualifier_text} {base_name}")
        };

        // Walk modifiers OUTERMOST-to-base (`stack[0]..stack[len-2]`).  This is
        // the order in which a C declarator is built around its identifier.  A
        // pointer followed inward by an array postfix must be grouped;
        // the mirror ordering is an array of pointers and must not be grouped.
        for (ct_mod, qualifiers) in stack.iter().take(stack.len() - 1) {
            match ct_mod.get_metatype() {
                type_metatype::TYPE_PTR => decl.qualified_pointer(*qualifiers),
                type_metatype::TYPE_ARRAY => {
                    let n = ct_mod.num_elements().unwrap_or_else(|| {
                        let base = ct_mod
                            .get_array_base()
                            .map(|b| b.get_size())
                            .unwrap_or(1)
                            .max(1);
                        ct_mod.get_size() / base
                    });
                    decl.postfix(&format!("[{n}]"));
                }
                type_metatype::TYPE_CODE => {
                    let proto = ct_mod
                        .get_code_prototype()
                        .expect("code modifier prototype");
                    let inline_callable = self.inline_host_callable(cx, ct_mod);
                    if inline_callable {
                        active.push(Rc::as_ptr(ct_mod));
                    }
                    self.callable_suffix(cx,proto,typed,define_callable || inline_callable,&mut decl,active);
                }
                _ => {}
            }
        }
        // `<base> <front>` with a single separating space before any `*` modifiers
        // (the `type_expr_space` token); a bare base type has no trailing space
        // here (the caller adds the space before the identifier).
        let front_full = if decl.front.is_empty() {
            base_name
        } else {
            format!("{base_name} {}", decl.front)
        };
        let spelling = TypedDeclarator {
            front: front_full, back: decl.back,
            front_types: if typed {
                vec![DeclaratorTypeSpan {
                    range: base_name_start..base_name_start + base_name_len,
                    datatype: Rc::clone(base),
                }]
            } else { Vec::new() },
            back_types: decl.back_types,
        };
        active.truncate(inherited);
        spelling
    }

    fn callable_suffix(
        &self, cx: &SpellCtx, proto: &crate::fspec::FuncProto, typed: bool,
        define_callable: bool, decl: &mut CDeclarator,
        active: &mut Vec<*const Datatype>,
    ) {
        let mut params = Vec::new();
        let mut param_types = Vec::new();
        let mut param_offset = 1; // opening parenthesis
        let logical = if define_callable { proto.logical_pieces() }
            else { crate::kuna_indirectargs::callable_logical(proto, cx.indirect_args, cx.hidden_results) };
        let count = logical.map_or_else(|| proto.num_params() as usize, |pieces| {
            match usize::try_from(pieces.first_var_arg_slot) {
                Ok(first) if first > 0 && first <= pieces.intypes.len() => first,
                _ => pieces.intypes.len(),
            }
        });
        for i in 0..count {
            let ty = if let Some(pieces) = logical {
                pieces.intypes.get(i).cloned()
            } else {
                proto.get_param(i as int4).and_then(|param| {
                    if cx.indirect_args {
                        crate::kuna_indirectargs::source_type(proto, param)
                    } else {
                        param.get_type().cloned()
                    }
                })
            };
            let text = ty
                .map(|ty| {
                    let mut spelling = self.build_declarator_with_prefix(
                        cx, &ty, typed, false, CDeclarator::default(), active);
                    if typed {
                        for mut span in spelling.front_types {
                            span.range = span.range.start + param_offset..span.range.end + param_offset;
                            param_types.push(span);
                        }
                        for mut span in spelling.back_types {
                            let offset = param_offset + spelling.front.len();
                            span.range = span.range.start + offset..span.range.end + offset;
                            param_types.push(span);
                        }
                    }
                    spelling.front.push_str(&spelling.back);
                    spelling.front
                })
                .unwrap_or_else(|| "undefined1".to_string());
            param_offset += text.len() + 1; // comma
            params.push(text);
        }
        if logical.map_or_else(|| proto.is_dotdotdot(), |pieces| pieces.first_var_arg_slot >= 0) {
            params.push("...".to_string());
        } else if params.is_empty()
            && (proto.logical_pieces().is_none() || proto.is_input_locked())
        {
            params.push("void".to_string());
        }
        decl.callable_postfix(&format!("({})", params.join(",")), cx.convention_name(proto));
        if typed {
            let offset = decl.back.len() - (params.iter().map(String::len).sum::<usize>()
                + params.len().saturating_sub(1) + 2);
            for mut span in param_types {
                span.range = span.range.start + offset..span.range.end + offset;
                decl.back_types.push(span);
            }
        }
    }

    fn spell_type_name(&self, cx: &SpellCtx, t: &Rc<Datatype>) -> (String, String) {
        if t.qualified_base().is_some() || self.inline_host_callable(cx, t) {
            return self.declarator(cx, t);
        }
        // (kuna) realtypes: a scalar residual TYPE_UNKNOWN (the named `xunknownN`
        // core type or an anonymous `undefined<N>`) becomes its real C type by size.
        if let Some(n) = self.relabel(cx, t, false) {
            return (n.into_owned(), String::new());
        }
        let name = t.get_name();
        if !name.is_empty() {
            return (name.to_string(), String::new());
        }
        match t.get_metatype() {
            // An anonymous pointer renders as `<pointee> *` (recursively), exactly
            // as `push_cast_type` does for a `(char *)` cast. `declarator` walks
            // the modifier chain to the named base and lays out both halves; a
            // pointer to an array keeps its `)[N]` suffix for after the name.
            type_metatype::TYPE_PTR | type_metatype::TYPE_CODE => self.declarator(cx, t),
            _ => (self.anonymous(t), String::new()),
        }
    }

    /// Size -> standard-C name for an unknown value. `None` for sizes with no
    /// natural single C type (3/5/6/7/10/16...), which keep the `undefined<N>`
    /// form; under a pointer those residual sizes fall back to `void` (the
    /// modifier walk adds the `*` chain), since `void *` is the only spelling that
    /// carries no width claim. A pointee whose size *does* have a natural type
    /// keeps it, so the declaration agrees with the stride the index/cast
    /// expressions were built from.
    fn spell_unknown_base(
        &self,
        size: int4,
        under_pointer: bool,
        long_is_8: bool,
    ) -> Option<Cow<'static, str>> {
        Some(Cow::Borrowed(match size {
            1 => "char",
            2 => "unsigned short",
            4 => "unsigned int",
            8 => {
                if long_is_8 {
                    "unsigned long"
                } else {
                    "unsigned long long"
                }
            }
            _ => {
                return if under_pointer {
                    Some(Cow::Borrowed("void"))
                } else {
                    None
                };
            }
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::CDeclarator;

    #[test]
    fn core_source_integer_rank_is_not_replaced_by_equal_width() {
        use crate::dtype::{type_metatype::*, TypeFactory, TypeFactoryImpl};
        use crate::kuna_langtypes::{SpellCtx, TypeSpeller};
        let types = TypeFactoryImpl::new();
        types.set_default_alignment_map();
        let cx = SpellCtx { ctypes: true, ..SpellCtx::OFF };
        for (name, meta) in [
            ("long", TYPE_INT), ("long long", TYPE_INT),
            ("unsigned long", TYPE_UINT), ("unsigned long long", TYPE_UINT),
        ] {
            types.set_core_type(name, 8, meta, false).unwrap();
            let scalar = types.get_base_named(8, meta, name).unwrap();
            assert_eq!(super::C_SPELLER.type_name(&cx, &scalar).0, name);
            assert_eq!(super::C_SPELLER.declarator(&cx, &scalar).0, name);
        }
        types.set_core_type("uint8", 8, TYPE_UINT, false).unwrap();
        let width_only = types.get_base_named(8, TYPE_UINT, "uint8").unwrap();
        assert_eq!(super::C_SPELLER.type_name(&cx, &width_only).0, "unsigned long");
    }

    #[derive(Clone, Copy)]
    enum Modifier {
        Pointer,
        Array(usize),
        SyntheticPostfix(&'static str),
    }

    #[test]
    fn named_function_definition_keeps_source_name_and_canonical_definition() {
        use std::rc::Rc;
        use crate::dtype::{type_metatype::*, Datatype, DatatypeKind, TypeFactory, TypeFactoryImpl};
        use crate::fspec::{FuncProto, ParameterPieces};
        use crate::kuna_langtypes::{SpellCtx, TypeSpeller};

        let types = TypeFactoryImpl::new();
        types.set_default_alignment_map();
        types.setup_sizes(Some(8), 8, 8);
        let mut integer = Datatype::new(4, TYPE_INT);
        integer.name = "int".into();
        integer.display_name = "int".into();
        let integer = Rc::new(integer);
        let mut proto = FuncProto::new();
        proto.attach_internal_store(Rc::new(Datatype::new(0, TYPE_VOID)));
        proto.set_output(&ParameterPieces {
            type_: Some(Rc::clone(&integer)), ..Default::default()
        });
        proto.store_set_input(0, "value", &ParameterPieces {
            type_: Some(Rc::clone(&integer)), ..Default::default()
        });
        let mut code = Datatype::new(1, TYPE_CODE);
        code.id = 73;
        code.name = "RecursiveCallback".into();
        code.display_name = "RecursiveCallback".into();
        code.kind = DatatypeKind::Code { proto: Some(Rc::new(proto)) };
        let code = Rc::new(code);
        let pointer = types.get_type_pointer(8, Rc::clone(&code), 1).unwrap();
        let plain = super::C_SPELLER.declarator(&SpellCtx::OFF, &pointer);
        assert_eq!(format!("{}callback{}", plain.0, plain.1), "RecursiveCallback *callback");
        assert_eq!(format!("{}callback_slot{};", plain.0, plain.1),
            "RecursiveCallback *callback_slot;");
        let typed = super::C_SPELLER.typed_declarator(&SpellCtx::OFF, &pointer);
        assert_eq!((&typed.front, &typed.back), (&plain.0, &plain.1));
        assert!(Rc::ptr_eq(&typed.front_types[0].datatype, &code));
        assert!(typed.back_types.is_empty());
        assert_eq!(super::C_SPELLER.type_name(&SpellCtx::OFF, &code),
            ("RecursiveCallback".into(), String::new()));
        let typed_code = super::C_SPELLER.typed_type_name(&SpellCtx::OFF, &code);
        assert_eq!((typed_code.front, typed_code.back), ("RecursiveCallback".into(), String::new()));
        assert!(Rc::ptr_eq(&typed_code.front_types[0].datatype, &code));
        let definition = super::C_SPELLER.callable_definition(&SpellCtx::OFF, &code);
        assert_eq!((definition.front.as_str(), definition.back.as_str()), ("int", "(int)"));
        assert!(Rc::ptr_eq(&definition.front_types[0].datatype, &integer));
        assert!(Rc::ptr_eq(&definition.back_types[0].datatype, &integer));
        assert_eq!(code.get_name(), "RecursiveCallback");
        assert_eq!(code.id, 73);

        let alias = types.get_typedef(&code, "Callback", 74, 0).unwrap();
        let alias_pointer = types.get_type_pointer(8, alias, 1).unwrap();
        assert_eq!(super::C_SPELLER.declarator(&SpellCtx::OFF, &alias_pointer),
            ("Callback *".into(), String::new()));
        let pointer_alias = types.get_typedef(&pointer, "CallbackPointer", 75, 0).unwrap();
        assert_eq!(super::C_SPELLER.declarator(&SpellCtx::OFF, &pointer_alias),
            ("CallbackPointer".into(), String::new()));
    }

    #[test]
    fn ordinary_host_callables_expand_nested_signatures_without_erasing_aliases() {
        use std::cell::RefCell;
        use std::collections::BTreeMap;
        use std::rc::Rc;
        use crate::dtype::{type_class, TypeFactory, TypeFactoryImpl};
        use crate::fspec::{ParamEntry, ProtoModel};
        use crate::kuna_langtypes::{SpellCtx, TypeSpeller};
        use kuna_base::marshal::{ElementId, IdRegistry, XmlDecode};
        use kuna_base::space::{spacetype, AddrSpace, AddrSpaceManager, ConstantSpace};

        let types = TypeFactoryImpl::new();
        types.set_default_alignment_map();
        types.setup_sizes(Some(4), 8, 8);
        let mut manager = AddrSpaceManager::new();
        manager.insert_space(Rc::new(ConstantSpace::new())).unwrap();
        let register = Rc::new(AddrSpace::new(
            spacetype::IPTR_PROCESSOR, "register", false, 8, 1, 1, 0, 1, 1));
        manager.insert_space(Rc::clone(&register)).unwrap();
        manager.set_default_code_space(1).unwrap();
        manager.set_default_data_space(1).unwrap();
        let manager = Rc::new(manager);
        let mut model = ProtoModel::new(&manager);
        model.build_param_list("standard").unwrap();
        model.set_name("__cdecl");
        for slot in 0..3 {
            model.input_mut().push_entry(ParamEntry::seed(slot, type_class::TYPECLASS_GENERAL,
                Rc::clone(&register), 0x10 + slot as u64 * 8, 8, 1, 0, 0,
                true, false, &[], &manager).unwrap());
        }
        model.input_mut().finish_decode();
        model.output_mut().push_entry(ParamEntry::seed(0, type_class::TYPECLASS_GENERAL,
            register, 0, 8, 1, 0, 0, true, false, &[], &manager).unwrap());
        model.output_mut().finish_decode();
        let model = Rc::new(model);
        types.set_proto_context(Rc::clone(&manager));
        types.set_proto_models(Some(Rc::clone(&model)),
            Rc::new(RefCell::new(BTreeMap::from([("__cdecl".into(), model)]))));
        let mut registry = IdRegistry::with_base_ids();
        crate::dtype::register_type_wire_ids(&mut registry);
        crate::infra::remote_provider::register_remote_provider_ids(&mut registry);
        registry.register_element(&ElementId::new("param", 166));
        let decode = |text: &str| {
            let document = kuna_base::xml::xml_tree(text.as_bytes()).unwrap();
            let root = document.get_root().clone();
            let mut decoder = XmlDecode::new_with_root(&manager, &registry, &root, 0);
            types.decode_type(&mut decoder).unwrap()
        };
        let callback = decode(r#"<type name="HostCallback" id="73" metatype="code" size="1"><prototype><returnsym><addr/><type name="int" id="1" size="4" metatype="int"/></returnsym><internallist><param name="value"><addr/><typeref name="int" id="1"/></param></internallist></prototype></type>"#);
        assert!(callback.is_host_type());
        let pointer = types.get_type_pointer(8, Rc::clone(&callback), 1).unwrap();
        let cx = SpellCtx { inline_host_callables: true, ..SpellCtx::OFF };
        assert_eq!(super::C_SPELLER.declarator(&cx, &pointer),
            ("int (*".into(), ")(int)".into()));
        assert_eq!(super::C_SPELLER.declarator(&SpellCtx::OFF, &pointer),
            ("HostCallback *".into(), String::new()));
        assert_eq!(super::C_SPELLER.type_name(&cx, &callback),
            ("int".into(), "(int)".into()));
        let leaf = r#"<type name="" metatype="ptr" size="8"><typeref name="HostCallback" id="73" size="1"/></type>"#;
        let chooser = decode(&format!(r#"<type name="HostChooser" id="74" metatype="code" size="1"><prototype><returnsym><addr/>{leaf}</returnsym><internallist><param name="left"><addr/>{leaf}</param><param name="right"><addr/>{leaf}</param></internallist></prototype></type>"#));
        let chooser_pointer = types.get_type_pointer(8, chooser, 1).unwrap();
        let spelling = super::C_SPELLER.typed_declarator(&cx, &chooser_pointer);
        assert_eq!(format!("{}chooser{}", spelling.front, spelling.back),
            "int (*(*chooser)(int (*)(int),int (*)(int)))(int)");
        let integer = types.find_by_name("int").unwrap().unwrap();
        assert_eq!(spelling.front_types.len(), 1);
        assert_eq!(spelling.back_types.len(), 5);
        for (text, spans) in [(&spelling.front, &spelling.front_types),
            (&spelling.back, &spelling.back_types)]
        {
            for span in spans {
                assert_eq!(&text[span.range.clone()], "int");
                assert!(Rc::ptr_eq(&span.datatype, &integer));
            }
        }
        let alias = types.get_typedef(&callback, "Callback", 76, 0).unwrap();
        let alias_pointer = types.get_type_pointer(8, alias, 1).unwrap();
        assert_eq!(super::C_SPELLER.declarator(&cx, &alias_pointer),
            ("Callback *".into(), String::new()));
        let pointer_alias = types.get_typedef(&pointer, "CallbackPointer", 77, 0).unwrap();
        assert_eq!(super::C_SPELLER.declarator(&cx, &pointer_alias),
            ("CallbackPointer".into(), String::new()));
        let cycle = decode(r#"<type name="HostCycle" id="75" metatype="code" size="1"><prototype><returnsym><addr/><typeref name="int" id="1"/></returnsym><internallist><param name="next"><addr/><type name="" metatype="ptr" size="8"><typeref name="HostCycle" id="75" size="1"/></type></param></internallist></prototype></type>"#);
        let cycle_pointer = types.get_type_pointer(8, cycle, 1).unwrap();
        assert_eq!(super::C_SPELLER.declarator(&cx, &cycle_pointer),
            ("int (*".into(), ")(HostCycle *)".into()));
        assert_eq!((callback.get_name(), callback.get_unsized_id().unwrap()), ("HostCallback", 73));
    }

    #[test]
    fn borrowed_callable_declarations_need_no_model_or_physical_store() {
        use std::rc::Rc;
        use crate::dtype::{type_metatype::*, Datatype, DatatypeKind, TypeFactory, TypeFactoryImpl};
        use crate::fspec::{FuncProto,PrototypePieces};
        use crate::kuna_langtypes::SpellCtx;
        let types = TypeFactoryImpl::new();
        types.setup_sizes(Some(8),8,8);
        let integer = types.get_base_named(4,TYPE_INT,"int").unwrap();
        let pointer = types.get_type_pointer(8,Rc::clone(&integer),1).unwrap();
        let mut array = Datatype::new(12,TYPE_ARRAY);
        array.kind = DatatypeKind::Array { arrayof:Rc::clone(&integer),arraysize:3 };
        let array_pointer = types.get_type_pointer(8,Rc::new(array),1).unwrap();
        let mut returned_proto = FuncProto::new();
        returned_proto.retain_logical_declaration(&PrototypePieces {
            outtype:Some(Rc::clone(&integer)),intypes:vec![Rc::clone(&integer)],
            first_var_arg_slot:-1,..Default::default()
        });
        let mut returned_code = Datatype::new(1,TYPE_CODE);
        returned_code.kind = DatatypeKind::Code { proto:Some(Rc::new(returned_proto)) };
        let returned_callback = types.get_type_pointer(8,Rc::new(returned_code),1).unwrap();
        for (output,expected) in [
            (Rc::clone(&integer),"int (*)(int)"),
            (pointer,"int *(*)(int)"),
            (array_pointer,"int (*(*)(int))[3]"),
            (returned_callback,"int (*(*)(int))(int)"),
        ] {
            let mut proto = FuncProto::new();
            assert!(super::C_SPELLER.callable_pointer(&SpellCtx::OFF,&proto).is_none());
            proto.retain_logical_declaration(&PrototypePieces {
                outtype:Some(Rc::clone(&output)),intypes:vec![Rc::clone(&integer)],
                first_var_arg_slot:-1,..Default::default()
            });
            let spelling = super::C_SPELLER.callable_pointer(&SpellCtx::OFF,&proto).unwrap();
            assert_eq!(format!("{}{}",spelling.front,spelling.back),expected);
            assert!(Rc::ptr_eq(&spelling.front_types[0].datatype,&integer));
            assert!(spelling.back_types.iter().any(|span| Rc::ptr_eq(&span.datatype,&integer)));
            assert!(!proto.has_model());
            assert!(!proto.has_store());
            assert!(Rc::ptr_eq(proto.logical_pieces().unwrap().outtype.as_ref().unwrap(),&output));
            let mut code = Datatype::new(1,TYPE_CODE);
            code.kind = DatatypeKind::Code { proto:Some(Rc::new(proto)) };
            let definition = super::C_SPELLER.callable_definition(&SpellCtx::OFF,&Rc::new(code));
            assert!(Rc::ptr_eq(&definition.front_types[0].datatype,&integer));
        }
    }

    #[test]
    fn finite_variadic_callable_declarations_preserve_the_fixed_prefix() {
        use std::rc::Rc;
        use crate::dtype::{type_metatype::*, TypeFactory, TypeFactoryImpl};
        use crate::fspec::{FuncProto, PrototypePieces};
        use crate::kuna_langtypes::SpellCtx;

        let types = TypeFactoryImpl::new();
        types.setup_sizes(Some(8), 8, 8);
        let integer = types.get_base_named(4, TYPE_INT, "int").unwrap();
        let pointer = types.get_type_pointer(8, Rc::clone(&integer), 1).unwrap();
        let real = types.get_base_named(8, TYPE_FLOAT, "double").unwrap();
        for (fixed, intypes, expected) in [
            (1, vec![Rc::clone(&integer), Rc::clone(&integer), Rc::clone(&real)],
                "int (*)(int,...)"),
            (2, vec![Rc::clone(&pointer), Rc::clone(&integer),
                Rc::clone(&integer), Rc::clone(&real)],
                "int (*)(int *,int,...)"),
        ] {
            let mut proto = FuncProto::new();
            proto.retain_logical_declaration(&PrototypePieces {
                outtype: Some(Rc::clone(&integer)), intypes,
                first_var_arg_slot: fixed, ..Default::default()
            });
            proto.set_dotdotdot(false);
            let before = proto.logical_pieces().unwrap().intypes.clone();
            let spelling = super::C_SPELLER.callable_pointer(&SpellCtx::OFF, &proto).unwrap();
            assert_eq!(format!("{}{}", spelling.front, spelling.back), expected);
            assert!(!spelling.back_types.iter()
                .any(|span| Rc::ptr_eq(&span.datatype, &real)));
            let after = &proto.logical_pieces().unwrap().intypes;
            assert_eq!(before.len(), after.len());
            assert!(before.iter().zip(after).all(|(before, after)| Rc::ptr_eq(before, after)));
            assert_eq!(proto.logical_pieces().unwrap().first_var_arg_slot, fixed);
            assert!(!proto.is_dotdotdot());
        }
    }

    #[test]
    fn callable_conventions_bind_each_code_layer_without_replacing_nominal_leaves() {
        use std::cell::RefCell;
        use std::collections::BTreeMap;
        use std::rc::Rc;
        use crate::dtype::{type_metatype::*, Datatype, DatatypeKind, TypeFactory, TypeFactoryImpl};
        use crate::fspec::{FuncProto, ProtoModel, PrototypePieces};
        use crate::kuna_langtypes::SpellCtx;

        let types = TypeFactoryImpl::new();
        types.set_default_alignment_map();
        types.setup_sizes(Some(4), 4, 4);
        let integer = types.get_base_named(4, TYPE_INT, "int").unwrap();
        let manager = kuna_base::space::AddrSpaceManager::new();
        let base_model = ProtoModel::new(&manager);
        let cdecl = Rc::new(ProtoModel::copy_named("__cdecl", &base_model));
        let standard = Rc::new(ProtoModel::copy_named("__stdcall", &base_model));
        let fast = Rc::new(ProtoModel::copy_named("__fastcall", &base_model));
        let mut implicit = (*cdecl).clone();
        implicit.set_print_in_decl(false);
        let registry = Rc::new(RefCell::new(BTreeMap::from([
            ("__cdecl".into(), Rc::new(implicit)),
            ("__stdcall".into(), Rc::clone(&standard)),
            ("__fastcall".into(), Rc::clone(&fast)),
        ])));
        let mut cx = SpellCtx {
            convention: true, model_visibility: Some(Rc::clone(&registry)), ..SpellCtx::OFF
        };
        let code = |name: &str, output: Rc<Datatype>, inputs: Vec<Rc<Datatype>>, model: &Rc<ProtoModel>| {
            let mut proto = FuncProto::new();
            proto.set_model(Some(Rc::clone(model)));
            proto.retain_logical_declaration(&PrototypePieces {
                outtype: Some(output), intypes: inputs, first_var_arg_slot: -1, ..Default::default()
            });
            let mut ty = Datatype::new(1, TYPE_CODE);
            ty.name = name.into();
            ty.display_name = name.into();
            ty.id = Datatype::hash_name(name);
            ty.kind = DatatypeKind::Code { proto: Some(Rc::new(proto)) };
            Rc::new(ty)
        };
        let pointer = |ty| types.get_type_pointer(4, ty, 1).unwrap();
        let std_code = code("StdCode", Rc::clone(&integer), vec![Rc::clone(&integer)], &standard);
        let fast_code = code("FastCode", Rc::clone(&integer), vec![Rc::clone(&integer)], &fast);
        let std_pointer = pointer(Rc::clone(&std_code));
        let fast_pointer = pointer(Rc::clone(&fast_code));
        let std_fn = types.get_typedef(&std_pointer, "StdFn", 101, 0).unwrap();
        let fast_fn = types.get_typedef(&fast_pointer, "FastFn", 102, 0).unwrap();
        let chooser = code("ChooserCode", Rc::clone(&std_fn), vec![Rc::clone(&fast_fn)], &fast);
        let chooser_fn = types.get_typedef(&pointer(Rc::clone(&chooser)), "ChooserFn", 103, 0).unwrap();
        let identity = code("", Rc::clone(&chooser_fn), vec![Rc::clone(&chooser_fn)], &cdecl);
        let definition = |ty, name, cx: &SpellCtx| crate::printc::compose_callable_definition(ty, name, cx, None);
        assert_eq!(definition(&std_code, "StdCode", &cx), "typedef int __stdcall StdCode(int);\n");
        assert_eq!(definition(&fast_code, "FastCode", &cx), "typedef int __fastcall FastCode(int);\n");
        assert_eq!(definition(&chooser, "ChooserCode", &cx), "typedef StdFn __fastcall ChooserCode(FastFn);\n");
        assert_eq!(definition(&identity, "identity", &cx), "typedef ChooserFn identity(ChooserFn);\n");
        assert_eq!(crate::printc::declaration_text(&std_pointer, "standard", &cx), "StdCode *standard");
        let named = super::C_SPELLER.callable_definition(&cx, &chooser);
        assert!(Rc::ptr_eq(&named.front_types[0].datatype, &std_fn));
        assert!(Rc::ptr_eq(&named.back_types[0].datatype, &fast_fn));

        let anonymous_std = pointer(code("", Rc::clone(&integer), vec![Rc::clone(&integer)], &standard));
        let anonymous_fast = pointer(code("", Rc::clone(&integer), vec![Rc::clone(&integer)], &fast));
        let factory = code("", anonymous_std, vec![anonymous_fast], &fast);
        let typed = super::C_SPELLER.callable_definition(&cx, &factory);
        assert_eq!(format!("{} x{}", typed.front, typed.back),
            "int (__stdcall *__fastcall x(int (__fastcall *)(int)))(int)");
        assert_eq!(typed.back_types.len(), 3);
        for span in &typed.back_types {
            assert_eq!(&typed.back[span.range.clone()], "int");
            assert!(Rc::ptr_eq(&span.datatype, &integer));
        }
        let pointer_spelling = super::C_SPELLER.callable_pointer(
            &cx, factory.get_code_prototype().unwrap(),
        ).unwrap();
        assert_eq!(format!("{}x{}", pointer_spelling.front, pointer_spelling.back),
            "int (__stdcall *(__fastcall *x)(int (__fastcall *)(int)))(int)");
        let held = std_code.get_code_prototype().unwrap().model();
        assert!(Rc::ptr_eq(held, &standard));
        cx.convention = false;
        assert_eq!(definition(&std_code, "StdCode", &cx), "typedef int StdCode(int);\n");
        assert_eq!(definition(&chooser, "ChooserCode", &cx), "typedef StdFn ChooserCode(FastFn);\n");
        cx.convention = true;
        cx.lang = crate::kuna_lang::OutLang::Java;
        assert_eq!(definition(&std_code, "StdCode", &cx), "typedef int StdCode(int);\n");
        assert!(Rc::ptr_eq(std_code.get_code_prototype().unwrap().model(), &standard));
        cx.lang = crate::kuna_lang::OutLang::C;
        let mut printer = crate::printc::PrintC::new();
        printer.rt_ctx = cx;
        printer.set_convention_printing(false);
        assert_eq!(definition(&std_code, "StdCode", &printer.rt_ctx), "typedef int StdCode(int);\n");
        printer.set_convention_printing(true);
        assert_eq!(definition(&std_code, "StdCode", &printer.rt_ctx), "typedef int __stdcall StdCode(int);\n");
        printer.set_convention_printing(false);
        printer.reset_wire_option_defaults();
        assert_eq!(definition(&std_code, "StdCode", &printer.rt_ctx), "typedef int __stdcall StdCode(int);\n");
    }

    #[test]
    fn callable_definition_uses_logical_signature_not_lowered_store() {
        use std::rc::Rc;
        use crate::dtype::{type_metatype::*, Datatype, DatatypeKind, TypeFactory, TypeFactoryImpl};
        use crate::fspec::{FuncProto, ParameterPieces, ProtoModel, PrototypePieces};
        use crate::kuna_langtypes::SpellCtx;
        let types = TypeFactoryImpl::new();
        types.set_default_alignment_map();
        types.setup_sizes(Some(8), 8, 8);
        let integer = types.get_base_named(4, TYPE_INT, "int").unwrap();
        let pointer = types.get_type_pointer(8, Rc::clone(&integer), 1).unwrap();
        let logical = PrototypePieces {
            outtype: Some(Rc::clone(&integer)), intypes: vec![Rc::clone(&integer)],
            innames: vec!["value".into()], first_var_arg_slot: 1, ..Default::default()
        };
        let manager = kuna_base::space::AddrSpaceManager::new();
        let model = Rc::new(ProtoModel::new(&manager));
        let mut proto = FuncProto::from_logical(&logical, model, &types).unwrap();
        proto.set_output(&ParameterPieces { type_: Some(Rc::clone(&pointer)), ..Default::default() });
        proto.store_clear_all_inputs();
        for i in 0..2 {
            proto.store_set_input(i, "lowered", &ParameterPieces {
                type_: Some(Rc::clone(&pointer)), ..Default::default()
            });
        }
        proto.set_dotdotdot(false);
        assert_eq!(proto.num_params(), 2);
        assert!(Rc::ptr_eq(proto.get_output_type().unwrap(), &pointer));
        let mut code = Datatype::new(1, TYPE_CODE);
        code.name = "LogicalCallback".into();
        code.display_name = code.name.clone();
        code.kind = DatatypeKind::Code { proto: Some(Rc::new(proto)) };
        let code = Rc::new(code);
        let definition = super::C_SPELLER.callable_definition(&SpellCtx::OFF, &code);
        assert_eq!((definition.front, definition.back), ("int".into(), "(int,...)".into()));
        assert_eq!(code.get_code_prototype().unwrap().num_params(), 2);
    }

    #[test]
    fn callable_leaves_retain_distinct_same_named_owners_and_syntax() {
        use std::rc::Rc;
        use crate::dtype::{type_metatype::*, Datatype, DatatypeKind, TypeFactory, TypeFactoryImpl};
        use crate::fspec::{FuncProto, ParameterPieces};
        use crate::kuna_langtypes::{SpellCtx, TypeSpeller};
        use crate::prettyprint::Emit;

        let named = |id| {
            let mut ty = Datatype::new(4, TYPE_STRUCT);
            ty.id = id;
            ty.name = "Shared".into();
            ty.display_name = "Shared".into();
            Rc::new(ty)
        };
        let result = named(41);
        let formal = named(42);
        let types = TypeFactoryImpl::new();
        types.setup_sizes(Some(8), 8, 8);
        let pointer = |ty| types.get_type_pointer(8, ty, 1).unwrap();
        let callback = |output, input| {
            let mut proto = FuncProto::new();
            proto.attach_internal_store(Rc::new(Datatype::new(0, TYPE_VOID)));
            proto.set_output(&ParameterPieces { type_: Some(output), ..Default::default() });
            proto.store_set_input(0, "", &ParameterPieces {
                type_: Some(input), ..Default::default()
            });
            let mut code = Datatype::new(1, TYPE_CODE);
            code.kind = DatatypeKind::Code { proto: Some(Rc::new(proto)) };
            pointer(Rc::new(code))
        };
        let qualified = types.get_qualified_type(Rc::clone(&formal), crate::kuna_typequal::CONST).unwrap();
        let inner = callback(Rc::clone(&formal), pointer(qualified));
        let outer = callback(pointer(Rc::clone(&result)), inner);
        let typed = super::C_SPELLER.typed_declarator(&SpellCtx::OFF, &outer);
        let plain = super::C_SPELLER.declarator(&SpellCtx::OFF, &outer);
        assert_eq!((&typed.front, &typed.back), (&plain.0, &plain.1));
        assert_eq!(format!("{}x{}", typed.front, typed.back),
            "Shared *(*x)(Shared (*)(const Shared *))");
        assert_eq!(typed.front_types.len(), 1);
        assert!(Rc::ptr_eq(&typed.front_types[0].datatype, &result));
        assert_eq!(&typed.front[typed.front_types[0].range.clone()], "Shared");
        assert_eq!(typed.back_types.len(), 2);
        for span in &typed.back_types {
            assert!(Rc::ptr_eq(&span.datatype, &formal));
            assert_eq!(&typed.back[span.range.clone()], "Shared");
        }

        // Mapping is per identity, not a replacement of the common source name.
        let mut print = crate::printc::PrintC::new();
        print.set_output_stream();
        print.set_type_names(Some(Rc::new(std::collections::BTreeMap::from([
            (Rc::as_ptr(&result) as usize, "Result".into()),
            (Rc::as_ptr(&formal) as usize, "Input".into()),
        ]))));
        let markup = crate::prettyprint::MarkupRef::none();
        print.emit_typed_declarator_part(&typed.front, &typed.front_types, &markup);
        print.emit_mut().print("x", crate::prettyprint::SyntaxHighlight::NoColor);
        print.emit_typed_declarator_part(&typed.back, &typed.back_types, &markup);
        assert_eq!(print.emit_mut().output_str(),
            "Result *(*x)(Input (*)(const Input *))");
        assert_eq!(result.get_name(), "Shared");
        assert_eq!(formal.get_name(), "Shared");

        // A typedef is itself the rendered nominal leaf, not its target graph.
        let alias = types.get_typedef(&outer, "Callback", 43, 0).unwrap();
        let alias_spelling = super::C_SPELLER.typed_declarator(&SpellCtx::OFF, &alias);
        assert_eq!(alias_spelling.front, "Callback");
        assert!(alias_spelling.back_types.is_empty());
        assert!(Rc::ptr_eq(&alias_spelling.front_types[0].datatype, &alias));

        // Scalar relabelling may introduce multiple words, but it must still
        // bind to the width-bearing scalar rather than the enclosing pointer.
        let scalar = Rc::new(Datatype::new(8, TYPE_UNKNOWN));
        let scalar_pointer = pointer(Rc::clone(&scalar));
        let relabelled = super::C_SPELLER.typed_declarator(
            &SpellCtx { enabled: true, ..SpellCtx::OFF }, &scalar_pointer,
        );
        assert_eq!(relabelled.front, "unsigned long *");
        assert_eq!(relabelled.front_types.len(), 1);
        assert_eq!(&relabelled.front[relabelled.front_types[0].range.clone()], "unsigned long");
        assert!(Rc::ptr_eq(&relabelled.front_types[0].datatype, &scalar));
    }

    fn spell(modifiers_outer_to_inner: &[Modifier]) -> String {
        let mut decl = CDeclarator::default();
        for modifier in modifiers_outer_to_inner {
            match modifier {
                Modifier::Pointer => decl.pointer(),
                Modifier::Array(n) => decl.postfix(&format!("[{n}]")),
                Modifier::SyntheticPostfix(suffix) => decl.postfix(suffix),
            }
        }
        format!("int {}x{}", decl.front, decl.back)
    }

    /// The generic helper must distinguish every adjacent pointer/postfix
    /// ordering. Synthetic function suffixes here fence the helper's grouping rule
    /// independently of prototype storage. The
    /// right-hand strings are declarations accepted by a C compiler.
    #[test]
    fn pointer_array_and_function_precedence_table() {
        use Modifier::{Array as A, Pointer as P, SyntheticPostfix as S};

        let cases: &[(&[Modifier], &str)] = &[
            (&[P], "int *x"),
            (&[A(2)], "int x[2]"),
            (&[P, A(2)], "int (*x)[2]"),
            (&[A(2), P], "int *x[2]"),
            (&[P, S("(void)")], "int (*x)(void)"),
            (&[S("(void)"), P], "int *x(void)"),
            (&[P, P, A(2)], "int (**x)[2]"),
            (&[P, A(2), P], "int *(*x)[2]"),
            (&[A(2), P, A(3)], "int (*x[2])[3]"),
            (&[A(2), P, S("(void)")], "int (*x[2])(void)"),
            (&[P, S("(void)"), P], "int *(*x)(void)"),
            (&[P, S("(void)"), P, A(3)], "int (*(*x)(void))[3]"),
        ];

        for (mods, expected) in cases {
            assert_eq!(spell(mods), *expected);
        }
    }

    #[test]
    fn callback_pointer_does_not_erase_an_unknown_return_width() {
        use std::rc::Rc;

        use crate::dtype::{type_metatype, Datatype, DatatypeKind};
        use crate::fspec::{FuncProto, ParameterPieces};
        use crate::kuna_langtypes::{SpellCtx, TypeSpeller};

        let pointer = |to| {
            let mut ty = Datatype::new(8, type_metatype::TYPE_PTR);
            ty.kind = DatatypeKind::Pointer {
                ptrto: to,
                spaceid: None,
                truncate: None,
                wordsize: 1,
            };
            Rc::new(ty)
        };
        let callback = |output| {
            let mut proto = FuncProto::new();
            proto.attach_internal_store(Rc::new(Datatype::new(0, type_metatype::TYPE_VOID)));
            proto.set_output(&ParameterPieces { type_: Some(output), ..Default::default() });
            let mut code = Datatype::new(1, type_metatype::TYPE_CODE);
            code.kind = DatatypeKind::Code { proto: Some(Rc::new(proto)) };
            pointer(Rc::new(code))
        };
        let cx = SpellCtx { enabled: true, ..SpellCtx::OFF };
        for size in [3, 10, 16] {
            let unknown = Rc::new(Datatype::new(size, type_metatype::TYPE_UNKNOWN));
            assert_eq!(
                super::C_SPELLER.declarator(&cx, &callback(Rc::clone(&unknown))),
                (format!("undefined{size} (*"), ")(void)".into()),
            );
            assert_eq!(
                super::C_SPELLER.declarator(&cx, &callback(pointer(Rc::clone(&unknown)))),
                ("void *(*".into(), ")(void)".into()),
            );
            assert_eq!(
                super::C_SPELLER.declarator(&cx, &pointer(unknown)),
                ("void *".into(), "".into()),
            );
        }
    }

    #[test]
    fn completed_callable_types_preserve_nested_parameter_and_return_declarators() {
        use std::rc::Rc;
        use crate::dtype::{type_metatype, Datatype, DatatypeKind, TypeFactory, TypeFactoryImpl, TypeField};
        use crate::fspec::{FuncProto, ParameterPieces};
        use crate::kuna_langtypes::{SpellCtx, TypeSpeller};

        let types = TypeFactoryImpl::new();
        types.setup_sizes(Some(8), 8, 8);
        types.set_core_type("int", 4, type_metatype::TYPE_INT, false).unwrap();
        types.set_core_type("void", 1, type_metatype::TYPE_VOID, false).unwrap();
        types.cache_core_types().unwrap();
        let integer = types.get_base(4, type_metatype::TYPE_INT).unwrap();
        let callable = |output: Rc<Datatype>, inputs: Vec<Rc<Datatype>>, variadic: bool, closed: bool| {
            let mut proto = FuncProto::new();
            proto.attach_internal_store(Rc::new(Datatype::new(0, type_metatype::TYPE_VOID)));
            proto.set_output(&ParameterPieces { type_: Some(output), ..Default::default() });
            for (i, ty) in inputs.into_iter().enumerate() {
                proto.store_set_input(i as i32, "", &ParameterPieces {
                    type_: Some(ty), ..Default::default()
                });
            }
            proto.set_input_lock(closed);
            proto.set_dotdotdot(variadic);
            let mut code = Datatype::new(1, type_metatype::TYPE_CODE);
            code.kind = DatatypeKind::Code { proto: Some(Rc::new(proto)) };
            types.get_type_pointer(8, Rc::new(code), 1).unwrap()
        };
        let declaration = |ty: &Rc<Datatype>| {
            let (front, back) = super::C_SPELLER.declarator(&SpellCtx::OFF, ty);
            format!("{front}x{back}")
        };
        let callback = callable(Rc::clone(&integer), vec![Rc::clone(&integer)], false, true);
        assert_eq!(
            super::C_SPELLER.type_name(&SpellCtx::OFF, &callback.get_ptr_to().unwrap()),
            ("int".to_string(), "(int)".to_string()),
        );
        let nested = callable(
            types.get_type_pointer(8, Rc::clone(&integer), 1).unwrap(),
            vec![Rc::clone(&integer), callback], true, true,
        );
        assert_eq!(declaration(&nested), "int *(*x)(int,int (*)(int),...)");
        let unlocked = callable(Rc::clone(&integer), vec![], false, false);
        assert_eq!(declaration(&unlocked), "int (*x)(void)");
        let fixed_variadic = callable(Rc::clone(&integer), vec![Rc::clone(&integer)], true, true);
        assert_eq!(declaration(&fixed_variadic), "int (*x)(int,...)");
        let array = types.get_type_array(3, Rc::clone(&integer)).unwrap();
        let nested_return = callable(types.get_type_pointer(8, array, 1).unwrap(), vec![], false, true);
        assert_eq!(declaration(&nested_return), "int (*(*x)(void))[3]");

        let node = types.get_type_struct("Node").unwrap();
        let callback = callable(Rc::clone(&node), vec![Rc::clone(&node)], false, true);
        let completed = types.set_fields_struct_raw(
            &node, vec![TypeField::new(0, 0, "next", Rc::clone(&callback))],
            vec![], 8, 8, 0,
        ).unwrap();
        assert_eq!(declaration(&callback), "Node (*x)(Node)");
        assert_eq!(
            crate::kuna_structdefs::definition_text(&completed, &SpellCtx::OFF),
            "struct Node {\n    Node (*next)(Node);\n};\n",
        );
        let input = types.get_typedef(&node, "Input", 0x1234, 0).unwrap();
        let nested = callable(Rc::clone(&input), vec![Rc::clone(&node)], false, true);
        let outer = callable(node, vec![input, nested], false, true);
        assert_eq!(declaration(&outer), "Node (*x)(Input,Input (*)(Node))");
        let alias = types.get_typedef(&outer, "Transform", 0x5678, 0).unwrap();
        assert_eq!(super::C_SPELLER.type_name(&SpellCtx::OFF, &alias), ("Transform".into(), "".into()));
    }
}
