//! (kuna) The c-language policy objects: the concrete half of the output-language
//! seam for C.
//!
//! [`CSpeller`] carries the declarator algorithm transcribed from
//! `PrintC::pushTypeStart` / `pushTypeEnd` (printc.cc:265/314) plus
//! `buildTypeStack` (printc.cc:143), together with the kuna `realtypes`/`ctypes`
//! relabelling (DIV-5/DIV-6). The bodies are moved verbatim out of `printc.rs`,
//! which now keeps only thin dispatchers so its existing free-function callers
//! and their tests are unchanged.

use std::borrow::Cow;

use kuna_base::types::int4;

use crate::dtype::type_metatype;
use crate::kuna_langtypes::{SpellCtx, TypeSpeller, TypeText, TypeTokenPolicy};

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
    front: TypeText,
    back: TypeText,
    /// A pointer prefix has been added since the last postfix grouped it.
    ungrouped_pointer: bool,
}

impl CDeclarator {
    fn pointer(&mut self) {
        // We are walking from the outer type toward the base.  A newly reached
        // pointer belongs nearest the base type, so it prefixes the complete
        // declarator already accumulated around the identifier.
        self.front.prefix("*");
        self.ungrouped_pointer = true;
    }

    fn postfix(&mut self, suffix: TypeText) {
        if self.ungrouped_pointer {
            // Group the complete current declarator, including any postfixes
            // already accumulated.  Closing before `self.back` would turn
            // `*a[2]` + `[3]` into `(*a)[2][3]` instead of `(*a[2])[3]`.
            self.front.prefix("(");
            self.back.push_str(")");
            self.ungrouped_pointer = false;
        }
        self.back.append(suffix);
    }
}

impl TypeSpeller for CSpeller {
    fn is_generic_callable(&self, cx: &SpellCtx, dt: &crate::dtype::TypeRoot) -> bool {
        let view = dt.read();
        let node = view.get(dt.id()).expect("retained datatype");
        dt.get_metatype() == type_metatype::TYPE_CODE
            && view.get_code_prototype(dt.id()).expect("retained datatype").is_none()
            && dt.is_core_type()
            && !node.get_name().is_empty()
            && self.relabel(cx, dt, true).is_none()
    }

    /// Real C name for a residual `TYPE_UNKNOWN` base, or `None` when the gate is
    /// off / the type is not unknown. Conservative on sign (multi-byte unknowns
    /// are unsigned, since the real sign is genuinely unknown); a pointer-to-
    /// unknown base relabels through the same size table as a scalar, so the
    /// pointee keeps its width and `void` is only the residual fallback.
    fn relabel(
        &self,
        cx: &SpellCtx,
        dt: &crate::dtype::TypeRoot,
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
        crate::kuna_ctypes::core_type_spelling(
            &cx.model,
            dt.get_metatype(),
            dt.get_size(),
            dt.is_char_print(),
        )
        .map(Cow::Borrowed)
    }

    fn anonymous(&self, dt: &crate::dtype::TypeRoot) -> String {
        match dt.get_metatype() {
            type_metatype::TYPE_VOID => "void".to_string(),
            _ => format!("undefined{}", dt.get_size()),
        }
    }

    /// The stack is built base-up exactly as `buildTypeStack`; pointer modifiers
    /// go on the front (`*`), array modifiers on the tail (`[N]`), and a `*`
    /// front nested inside an array tail is parenthesised -- the precedence the
    /// RPN `ptr_expr`/`array_expr` tokens encode. Completed callable types add a
    /// function postfix and continue through their return datatype.
    fn declarator_annotated(
        &self, cx: &SpellCtx, ct: &crate::dtype::TypeRoot, annotate: bool,
    ) -> (TypeText, TypeText) {
        // buildTypeStack: walk to the base (named) type, recording the modifiers.
        let mut stack: Vec<crate::dtype::TypeRoot> = Vec::new();
        let mut cur = ct.clone();
        loop {
            stack.push(cur.clone());
            let view = cur.read();
            if !view.get(cur.id()).expect("retained datatype").get_name().is_empty() {
                break; // base type
            }
            let next = match cur.get_metatype() {
                type_metatype::TYPE_PTR => cur.get_ptr_to(),
                type_metatype::TYPE_ARRAY => cur.get_array_base(),
                type_metatype::TYPE_CODE => view.get_code_prototype(cur.id())
                    .expect("retained datatype")
                    .map(|proto| cur.related(proto.output).expect("callable output edge")),
                _ => None, // other anonymous type: stop
            };
            drop(view);
            match next {
                Some(n) => cur = n,
                None => break,
            }
        }
        // The base type's display name (anonymous -> `undefined<N>` / `void`).
        let base = stack.last().expect("declarator: non-empty stack");
        let base_view = base.read();
        let base_node = base_view.get(base.id()).expect("retained datatype");
        // (kuna) realtypes: relabel a residual TYPE_UNKNOWN base as a real C type
        // by size. Under a pointer modifier the same size table applies, so the
        // pointee width survives into the declaration; only a residual size with
        // no natural C type degrades to `void` there (the `*` chain is laid out by
        // the walk below).
        let under_pointer = stack[..stack.len() - 1]
            .iter()
            .any(|m| matches!(m.get_metatype(), type_metatype::TYPE_PTR));
        let (base_name, policy) = if let Some(n) = self.relabel(cx, base, under_pointer) {
            (n.into_owned(), TypeTokenPolicy::SpelledWords)
        } else if base_node.get_name().is_empty() {
            (self.anonymous(base), TypeTokenPolicy::SpelledWords)
        } else {
            let policy = if annotate && !base_node.is_core_type() {
                TypeTokenPolicy::NominalName
            } else {
                TypeTokenPolicy::SpelledWords
            };
            (base_node.get_display_name().to_string(), policy)
        };

        // Walk modifiers OUTERMOST-to-base (`stack[0]..stack[len-2]`).  This is
        // the order in which a C declarator is built around its identifier.  A
        // pointer followed inward by an array postfix must be grouped;
        // the mirror ordering is an array of pointers and must not be grouped.
        let mut decl = CDeclarator::default();
        for ct_mod in stack.iter().take(stack.len() - 1) {
            match ct_mod.get_metatype() {
                type_metatype::TYPE_PTR => decl.pointer(),
                type_metatype::TYPE_ARRAY => {
                    let n = ct_mod.num_elements().unwrap_or_else(|| {
                        let base = ct_mod
                            .get_array_base()
                            .map(|b| b.get_size())
                            .unwrap_or(1)
                            .max(1);
                        ct_mod.get_size() / base
                    });
                    decl.postfix(TypeText::plain(format!("[{n}]")));
                }
                type_metatype::TYPE_CODE => {
                    let view = ct_mod.read();
                    if let Some(proto) = view.get_code_prototype(ct_mod.id()).expect("retained datatype") {
                        let convention = crate::printc::emitted_bound_model_name(proto.binding.model(), cx.conventions);
                        if !convention.is_empty() {
                            decl.front.prefix(" ");
                            decl.front.prefix(convention);
                        }
                    }
                    decl.postfix(self.callable_suffix(cx, ct_mod, annotate));
                }
                _ => {}
            }
        }
        // `<base> <front>` with a single separating space before any `*` modifiers
        // (the `type_expr_space` token); a bare base type has no trailing space
        // here (the caller adds the space before the identifier).
        let mut front_full = TypeText::leaf(base_name, base, annotate, policy);
        if !decl.front.text.is_empty() {
            front_full.text.reserve(1 + decl.front.text.len());
            front_full.push_str(" ");
            front_full.append(decl.front);
        }
        (front_full, decl.back)
    }

    fn type_name_annotated(
        &self, cx: &SpellCtx, t: &crate::dtype::TypeRoot, annotate: bool,
    ) -> (TypeText, TypeText) {
        // (kuna) realtypes: a scalar residual TYPE_UNKNOWN (the named `xunknownN`
        // core type or an anonymous `undefined<N>`) becomes its real C type by size.
        if let Some(n) = self.relabel(cx, t, false) {
            return (TypeText::leaf(n.into_owned(), t, annotate, TypeTokenPolicy::SpelledWords),
                TypeText::default());
        }
        let view = t.read();
        let node = view.get(t.id()).expect("retained datatype");
        let name = node.get_name();
        if !name.is_empty() {
            let policy = if annotate && !node.is_core_type() {
                TypeTokenPolicy::NominalName
            } else {
                TypeTokenPolicy::SpelledWords
            };
            return (TypeText::leaf(name.to_string(), t, annotate, policy), TypeText::default());
        }
        match t.get_metatype() {
            // An anonymous pointer renders as `<pointee> *` (recursively), exactly
            // as `push_cast_type` does for a `(char *)` cast. `declarator` walks
            // the modifier chain to the named base and lays out both halves; a
            // pointer to an array keeps its `)[N]` suffix for after the name.
            type_metatype::TYPE_PTR | type_metatype::TYPE_CODE =>
                self.declarator_annotated(cx, t, annotate),
            _ => (TypeText::leaf(self.anonymous(t), t, annotate, TypeTokenPolicy::SpelledWords),
                TypeText::default()),
        }
    }

    /// Size -> standard-C name for an unknown value. `None` for sizes with no
    /// natural single C type (3/5/6/7/10/16...), which keep the `undefined<N>`
    /// form; under a pointer those residual sizes fall back to `void` (the
    /// modifier walk adds the `*` chain), since `void *` is the only spelling that
    /// carries no width claim. A pointee whose size *does* have a natural type
    /// keeps it, so the declaration agrees with the stride the index/cast
    /// expressions were built from.
    fn unknown_base(
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

impl CSpeller {
    fn callable_suffix(&self, cx: &SpellCtx, code: &crate::dtype::TypeRoot, annotate: bool) -> TypeText {
        let view = code.read();
        let Some(proto) = view.get_code_prototype(code.id()).expect("retained datatype") else {
            return TypeText::default();
        };
        let mut suffix = TypeText::plain("(");
        let fixed = if proto.variadic {
            proto.logical_first.map(|slot| slot as usize).unwrap_or(proto.inputs.len())
        } else {
            proto.inputs.len()
        };
        for (slot, &input) in proto.inputs[..fixed].iter().enumerate() {
            if slot != 0 { suffix.push_str(", "); }
            let dtype = code.related(input).expect("callable input edge");
            let (front, back) = self.type_name_annotated(cx, &dtype, annotate);
            suffix.append(front);
            suffix.append(back);
        }
        if proto.variadic {
            if fixed != 0 { suffix.push_str(", ..."); }
        } else if fixed == 0 && proto.input_closed {
            suffix.push_str("void");
        }
        suffix.push_str(")");
        suffix
    }

    pub(crate) fn callable_typedef(&self, cx: &SpellCtx, code: &crate::dtype::TypeRoot, name: &str) -> String {
        let view = code.read();
        let Some(proto) = view.get_code_prototype(code.id()).expect("retained datatype") else {
            return String::new();
        };
        let output = code.related(proto.output).expect("callable output edge");
        let (front, back) = self.declarator(cx, &output);
        let separator = if front.ends_with('*') { "" } else { " " };
        let suffix = self.callable_suffix(cx, code, false);
        let convention = crate::printc::emitted_bound_model_name(proto.binding.model(), cx.conventions);
        let convention_separator = if convention.is_empty() { "" } else { " " };
        format!("typedef {front}{separator}{convention}{convention_separator}{name}{}{back};\n", suffix.text)
    }
}

#[cfg(test)]
mod tests {
    use super::CDeclarator;

    #[derive(Clone, Copy)]
    enum Modifier {
        Pointer,
        Array(usize),
        SyntheticPostfix(&'static str),
    }

    fn spell(modifiers_outer_to_inner: &[Modifier]) -> String {
        let mut decl = CDeclarator::default();
        for modifier in modifiers_outer_to_inner {
            match modifier {
                Modifier::Pointer => decl.pointer(),
                Modifier::Array(n) => decl.postfix(super::TypeText::plain(format!("[{n}]"))),
                Modifier::SyntheticPostfix(suffix) => decl.postfix(super::TypeText::plain(*suffix)),
            }
        }
        format!("int {}x{}", decl.front.text, decl.back.text)
    }

    /// The generic helper must distinguish every adjacent pointer/postfix
    /// ordering, including function suffixes and nested array returns.
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
    fn completed_callable_types_preserve_nested_parameter_and_return_declarators() {
        use std::rc::Rc;
        use kuna_base::space::AddrSpaceManager;
        use crate::dtype::{type_metatype, Datatype, DatatypeKind, TypeFactory, TypeFactoryImpl, TypeField, TypeRoot};
        use crate::fspec::{LogicalCallable, ProtoModel};
        use crate::kuna_langtypes::{SpellCtx, TypeSpeller};

        let types = TypeFactoryImpl::new();
        types.setup_sizes(Some(8), 8, 8);
        types.set_core_type("int", 4, type_metatype::TYPE_INT, false).unwrap();
        types.set_core_type("void", 1, type_metatype::TYPE_VOID, false).unwrap();
        types.cache_core_types().unwrap();
        let integer = types.get_base(4, type_metatype::TYPE_INT).unwrap();
        let manager = Rc::new(AddrSpaceManager::new());
        let mut model = ProtoModel::new(&manager);
        model.build_param_list("standard").unwrap();
        let model = Rc::new(model);
        types.set_proto_context(Some(model), manager).unwrap();
        let binding = types.model_binding(None).unwrap();
        let callable = |output: TypeRoot, inputs: Vec<TypeRoot>, variadic: bool, input_closed: bool| {
            let proto = LogicalCallable {
                binding: binding.clone(),
                output: output.id(),
                logical_first: variadic.then_some(inputs.len() as i32),
                inputs: inputs.iter().map(TypeRoot::id).collect(),
                variadic,
                input_closed,
                flags: 0,
            };
            let code = types.get_type_code_proto(&proto).unwrap();
            types.get_type_pointer(8, code, 1).unwrap()
        };
        let callback = callable(integer.clone(), vec![integer.clone()], false, true);
        let callback_code = callback.get_ptr_to().unwrap();
        assert_eq!(super::C_SPELLER.type_name(&SpellCtx::OFF, &callback_code),
            ("int".to_string(), "(int)".to_string()));
        let int_pointer = types.get_type_pointer(8, integer.clone(), 1).unwrap();
        let nested = callable(int_pointer, vec![integer.clone(), callback], true, true);
        let (front, back) = super::C_SPELLER.declarator(&SpellCtx::OFF, &nested);
        // The semantic declaration never acquires an ABI hidden-result slot.
        assert_eq!(format!("{front}x{back}"), "int *(*x)(int, int (*)(int), ...)");

        let open = callable(integer.clone(), Vec::new(), false, false);
        let (front, back) = super::C_SPELLER.declarator(&SpellCtx::OFF, &open);
        assert_eq!(format!("{front}x{back}"), "int (*x)()");

        let expanded = LogicalCallable {
            binding: binding.clone(),
            output: integer.id(),
            inputs: vec![integer.id(), integer.id(), types.get_base(8, type_metatype::TYPE_FLOAT).unwrap().id()],
            variadic: true,
            input_closed: true,
            logical_first: Some(1),
            flags: 0,
        };
        let code = types.get_type_code_proto(&expanded).unwrap();
        let pointer = types.get_type_pointer(8, code, 1).unwrap();
        let (front, back) = super::C_SPELLER.declarator(&SpellCtx::OFF, &pointer);
        assert_eq!(format!("{front}x{back}"), "int (*x)(int, ...)");

        let array = types.get_type_array(3, integer).unwrap();
        let array_pointer = types.get_type_pointer(8, array, 1).unwrap();
        let nested_return = callable(array_pointer, Vec::new(), false, true);
        let (front, back) = super::C_SPELLER.declarator(&SpellCtx::OFF, &nested_return);
        assert_eq!(format!("{front}x{back}"), "int (*(*x)(void))[3]");

        let node = types.reserve("Node", Datatype::hash_name("Node"), type_metatype::TYPE_STRUCT).unwrap();
        let callback = callable(node.clone(), vec![node.clone()], false, true);
        let mut body = Datatype::new_with_align(8, 8, type_metatype::TYPE_STRUCT);
        body.name = "Node".into();
        body.display_name = "Node".into();
        body.id = Datatype::hash_name("Node");
        body.kind = DatatypeKind::Struct {
            field: vec![TypeField::new(0, 0, "next", callback.id())],
            bitfield: vec![],
        };
        types.complete(&node, body).unwrap();
        let (front, back) = super::C_SPELLER.declarator(&SpellCtx::OFF, &callback);
        assert_eq!(format!("{front}x{back}"), "Node (*x)(Node)");
        assert_eq!(crate::kuna_structdefs::definition_text(&node, SpellCtx::OFF),
            "struct Node {\n    Node (*next)(Node);\n};\n");

        // A callback suffix contains independent nominal leaves. Its identity
        // cannot be copied from the enclosing pointer or outer return type.
        let input = types.get_typedef(&node, "Input", 0x1234, 0).unwrap();
        let nested = callable(input.clone(), vec![node.clone()], false, true);
        let outer = callable(node.clone(), vec![input.clone(), nested], false, true);
        let (front, back) = super::C_SPELLER.declarator_annotated(&SpellCtx::OFF, &outer, true);
        assert_eq!(format!("{}x{}", front.text, back.text),
            "Node (*x)(Input, Input (*)(Node))");
        let leaves = |text: &super::TypeText| text.spans.iter().map(|span|
            (text.text[span.start..span.end].to_string(), span.id)
        ).collect::<Vec<_>>();
        let node_id = node.get_unsized_id().unwrap();
        assert_eq!(leaves(&front), vec![("Node".into(), node_id)]);
        assert_eq!(leaves(&back), vec![
            ("Input".into(), 0x1234), ("Input".into(), 0x1234), ("Node".into(), node_id),
        ]);
        let (plain_front, plain_back) =
            super::C_SPELLER.declarator_annotated(&SpellCtx::OFF, &outer, false);
        assert_eq!((&plain_front.text, &plain_back.text), (&front.text, &back.text));
        assert!(plain_front.spans.is_empty() && plain_back.spans.is_empty());
        front.into_parts();
        back.into_parts();

        // Naming the whole callable stops the traversal at the typedef itself.
        let alias = types.get_typedef(&outer, "Transform", 0x5678, 0).unwrap();
        let (front, back) = super::C_SPELLER.declarator_annotated(&SpellCtx::OFF, &alias, true);
        assert_eq!(leaves(&front), vec![("Transform".into(), 0x5678)]);
        assert!(back.text.is_empty() && back.spans.is_empty());
    }
}
