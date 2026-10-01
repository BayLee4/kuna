//! (kuna `dwarfvariants`) The DWARF **discriminated-union** gate, plus the
//! recovered-layout side table it fills.
//!
//! `dwarfstructs` (DIV-86) reads a `DW_TAG_structure_type`'s `DW_AT_byte_size`
//! and its `DW_TAG_member` children and deliberately stops there: a Rust enum
//! carries no `DW_TAG_member` at all, so it recovers its width and **no fields**.
//! Its whole layout lives under a `DW_TAG_variant_part`, which states three
//! things codegen cannot:
//!
//! * `DW_AT_discr` — WHICH member is the discriminant (offset, width, type);
//! * `DW_AT_discr_value` on each `DW_TAG_variant` — which value selects it;
//! * the variant's `DW_TAG_member` — the variant's NAME (`Ok`, `Err`, `Some`,
//!   `None`) and the payload struct describing its fields.
//!
//! A `DW_TAG_variant` with **no** `DW_AT_discr_value` is the default (niche /
//! untagged) variant: "any discriminant value the other variants did not claim".
//!
//! ## Scope, stated up front
//!
//! This needs **full debug info** (`-C debuginfo=2`, cargo `debug = true`). A
//! release Rust binary built without it carries no type DIEs, and this feature
//! then does exactly nothing — it is not "degraded", it is inert. That is a
//! deliberate limit: the alternative is inferring an enum from codegen shape,
//! and shape does not distinguish a `Result` from a `#[repr(C)]` struct, a
//! `(u64,u64)` tuple or a `&'static str` fat pointer.
//!
//! ## What is NOT recovered: which variant an access belongs to
//!
//! The recovered type overlays the variants as a **union**, and a union member
//! selects itself by OFFSET — the discriminant is never consulted. In a tagged
//! enum every payload variant starts immediately after the tag, so `Ok` and
//! `Err` sit at the same offset and the field the union scorer picks is not
//! evidence of anything. A variant name is therefore printed only where exactly
//! one variant claims the bytes being accessed (`Option<T>`, whose only
//! payload-carrying variant is `Some`); where two or more claim them, the
//! installed member name is an offset-derived `field_0x…` and nothing in the
//! emitted C names a variant. See [`VariantFacet::label`]. Choosing the facet
//! from the discriminant needs a dominating-guard analysis and belongs to a
//! `match` renderer, which is what the side table below exists for.
//!
//! ## The side table
//!
//! The recovered geometry is recorded in [`VariantLayout`], keyed by its owning
//! graph identity and revision, in the datatype generation
//! ([`crate::dtype::TypeFactory::kuna_record_variant_layout`]). It is the
//! `kuna_wire_symbols` arrangement: a table that **never enters the analysis
//! scope** and is read by nothing in this change, so it cannot perturb emitted C.
//! It exists so a later pass can render `match` / `if let` / `Ok(v)` from the
//! compiler's own answer instead of re-deriving it.

use crate::dtype::TypeId;

/// Environment variable that gates DWARF variant-part import (read by
/// `kuna-analysis::analyzers::dwarf::kuna_dwarfvariants`). Absent or any value
/// other than the off-tokens ⇒ **enabled**; set to `off`/`0`/`false` ⇒ disabled.
///
/// An env var rather than an [`crate::architecture::Architecture`] bool for the
/// same reason as the sibling `dwarfstructs`/`typedepth` gates: the types are
/// baked into the analysis facts inside `load file`, which runs upstream of every
/// `option` command.
pub const DWARFVARIANTS_ENV: &str = "KUNA_DWARFVARIANTS";

/// Whether DWARF variant-part import is enabled for this process.
/// Default **on**: only an explicit off-token in [`DWARFVARIANTS_ENV`] disables it.
pub fn dwarfvariants_enabled() -> bool {
    match std::env::var(DWARFVARIANTS_ENV) {
        Ok(v) => !matches!(v.trim().to_ascii_lowercase().as_str(), "off" | "0" | "false"),
        Err(_) => true, // unset => default-on
    }
}

/// Bridge a `set_kuna_option("dwarfvariants", val)` toggle to
/// [`DWARFVARIANTS_ENV`] so a later `load file` in the *same* process sees the
/// choice (the interactive `option dwarfvariants ...` before `load file` path;
/// the CLI sets the env var on the subprocess directly).
pub fn set_dwarfvariants_env(on: bool) {
    std::env::set_var(DWARFVARIANTS_ENV, if on { "on" } else { "off" });
}

/// One variant of a recovered discriminated union.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VariantFacet {
    /// The variant's source name, verbatim from its `DW_TAG_member`
    /// (`Ok`, `Err`, `Some`, `None`, `Cons`, …).
    pub name: String,
    /// `DW_AT_discr_value`, masked to the discriminant's width. `None` marks the
    /// DEFAULT variant — the one DWARF gives no value, selected by every
    /// discriminant the other variants did not claim (Rust's niche encoding).
    pub discr: Option<u64>,
    /// The union-member spelling actually INSTALLED on the recovered type, which
    /// is [`Self::name`] only when no other variant claims a byte this one
    /// claims. Where two variants overlay the same bytes — every `Result<T,E>`,
    /// and any enum with two or more payload-carrying variants — the union member
    /// selects itself by offset and the discriminant is never consulted, so a
    /// variant name on such an access would be a coin flip; the label is then an
    /// offset-derived `field_0x…` and no emitted field path claims a variant.
    /// **Empty for a FIELDLESS variant**, which gets no union member at all.
    pub label: String,
    /// The graph identity of the payload struct built for this facet, i.e. the
    /// type of the union member [`Self::label`] names. **None for a FIELDLESS
    /// variant** (`None`, `Nil`, a unit variant), which overlays nothing and
    /// therefore gets no union member — see the importer's note on
    /// `ScoreUnionFields`. Its name and its discriminant value still live here,
    /// which is what a `match` renderer needs.
    pub payload_type: Option<TypeId>,
    /// The variant's fields as `(name, offset within the ENUM)` — absolute, not
    /// relative to the payload struct, so a consumer never has to re-add
    /// [`VariantLayout::payload_offset`].
    pub fields: Vec<(String, i32)>,
}

/// The recovered geometry of one DWARF `DW_TAG_variant_part`.
///
/// Written once per interned enum type by the DWARF importer; read by nothing in
/// the change that introduced it (see the module header).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VariantLayout {
    /// Owning graph identity. The generation retains this metadata with
    /// non-owning edges, so metadata never retains a retired generation.
    pub type_id: TypeId,
    /// Display name only, never a metadata lookup key.
    pub type_name: String,
    /// `DW_AT_byte_size` of the enum.
    pub size: i32,
    /// Byte offset of the discriminant member (`DW_AT_discr` →
    /// `DW_AT_data_member_location`).
    pub tag_offset: i32,
    /// Width in bytes of the discriminant member's type.
    pub tag_size: i32,
    /// Byte offset of the overlay union WITHIN the recovered type — the lowest
    /// offset any variant places a field at, and 0 for a niche (where the overlay
    /// is the whole type). [`VariantFacet::fields`] offsets are absolute within
    /// the enum either way, so a consumer never has to add this back.
    pub payload_offset: i32,
    /// True when the discriminant's bytes and the payload OVERLAP, i.e. Rust read
    /// the tag out of a niche inside the payload rather than from a field of its
    /// own. The recovered type is then the overlay union ALONE (no enclosing
    /// struct and no `tag` field), because a tag field would have to sit at an
    /// offset a variant already owns.
    pub niche: bool,
    /// The graph identity of the union that overlays the variants. Equal to
    /// [`Self::type_id`] for a niche, where the union is the whole type.
    pub union_type: TypeId,
    /// The variants, in `DW_TAG_variant` order.
    pub variants: Vec<VariantFacet>,
}

impl VariantLayout {
    /// The variant a concrete discriminant value selects: the facet whose
    /// [`VariantFacet::discr`] matches, else the DEFAULT facet (the one DWARF
    /// gave no `DW_AT_discr_value`), else `None`.
    pub fn facet_for_discr(&self, value: u64) -> Option<&VariantFacet> {
        self.variants
            .iter()
            .find(|v| v.discr == Some(value))
            .or_else(|| self.variants.iter().find(|v| v.discr.is_none()))
    }

    /// The facet with the given source name.
    pub fn facet_named(&self, name: &str) -> Option<&VariantFacet> {
        self.variants.iter().find(|v| v.name == name)
    }

    /// Whether any emitted field path can name a variant of this enum, i.e.
    /// whether at least one payload-carrying variant kept its source name. False
    /// for every enum with two or more variants overlaying the same bytes — the
    /// suppression rule in [`VariantFacet::label`].
    pub fn names_any_variant(&self) -> bool {
        self.variants.iter().any(|v| !v.label.is_empty() && v.label == v.name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dtype::{TypeFactory, TypeFactoryImpl, TypeField, TypeRoot};

    /// The gate defaults on (unset env) and only the off-tokens disable it.
    /// Serialized by being a single test (env is process-global).
    #[test]
    fn dwarfvariants_env_gate() {
        std::env::remove_var(DWARFVARIANTS_ENV);
        assert!(dwarfvariants_enabled(), "unset => default-on");
        for off in ["off", "0", "false", "OFF", " off "] {
            std::env::set_var(DWARFVARIANTS_ENV, off);
            assert!(!dwarfvariants_enabled(), "`{off}` should disable");
        }
        for on in ["on", "1", "true", "anything"] {
            std::env::set_var(DWARFVARIANTS_ENV, on);
            assert!(dwarfvariants_enabled(), "`{on}` should enable");
        }
        set_dwarfvariants_env(false);
        assert!(!dwarfvariants_enabled());
        set_dwarfvariants_env(true);
        assert!(dwarfvariants_enabled());
        std::env::remove_var(DWARFVARIANTS_ENV);
    }

    fn layout() -> (TypeRoot, VariantLayout) {
        let factory = TypeFactoryImpl::new();
        layout_in(&factory)
    }

    fn layout_in(factory: &TypeFactoryImpl) -> (TypeRoot, VariantLayout) {
        let owner = factory.get_type_union("Option<&u32>").unwrap();
        let payload = factory.get_type_struct("Option<&u32>::Some").unwrap();
        factory.set_fields_struct_raw(&payload, Vec::new(), Vec::new(), 8, 1, 0).unwrap();
        factory
            .set_fields_union_raw(
                &owner,
                vec![TypeField::new(0, 0, "Some", payload.id())],
                8,
                1,
            )
            .unwrap();
        let layout = VariantLayout {
            type_id: owner.id(),
            type_name: "Option<&u32>".into(),
            size: 8,
            tag_offset: 0,
            tag_size: 8,
            payload_offset: 0,
            niche: true,
            union_type: owner.id(),
            variants: vec![
                VariantFacet {
                    name: "None".into(),
                    discr: Some(0),
                    label: String::new(),
                    payload_type: None,
                    fields: vec![],
                },
                VariantFacet {
                    name: "Some".into(),
                    discr: None,
                    label: "Some".into(),
                    payload_type: Some(payload.id()),
                    fields: vec![("__0".into(), 0)],
                },
            ],
        };
        (owner, layout)
    }

    #[test]
    fn retained_variant_graph_does_not_alias_a_reused_name_after_flush() {
        let factory = TypeFactoryImpl::new();
        let (old, layout) = layout_in(&factory);
        let payload = layout.variants[1].payload_type.unwrap();
        factory.kuna_record_variant_layout(&old, layout).unwrap();
        factory.clear_noncore().unwrap();

        let (fresh, mut fresh_layout) = layout_in(&factory);
        assert_ne!(old.id(), fresh.id());
        assert!(fresh.read().variant_layout(fresh.id()).is_none());
        fresh_layout.variants[1].discr = Some(1);
        factory.kuna_record_variant_layout(&fresh, fresh_layout).unwrap();

        let old_view = old.read();
        let retained = old_view.variant_layout(old.id()).unwrap();
        assert_eq!(retained.union_type, old.id());
        assert_eq!(retained.variants[1].payload_type, Some(payload));
        assert_eq!(old_view.get(payload).unwrap().get_size(), 8);
        assert_eq!(retained.facet_for_discr(7).unwrap().name, "Some");
        assert!(fresh.read().variant_layout(fresh.id()).unwrap().facet_for_discr(7).is_none());
    }

    /// A value a variant claims picks that variant; every other value falls to
    /// the DEFAULT variant, which is the whole point of the niche encoding.
    #[test]
    fn facet_for_discr_prefers_exact_then_default() {
        let (_owner, l) = layout();
        assert_eq!(l.facet_for_discr(0).unwrap().name, "None");
        assert_eq!(l.facet_for_discr(1).unwrap().name, "Some");
        assert_eq!(l.facet_for_discr(0xdeadbeef).unwrap().name, "Some");
        assert_eq!(l.facet_named("Some").unwrap().fields, vec![("__0".to_string(), 0)]);
        assert!(l.facet_named("Err").is_none());
    }

    /// A single payload-carrying variant keeps its name; two that overlay the
    /// same bytes do not, and `names_any_variant` is what says which happened.
    #[test]
    fn names_any_variant_tracks_the_suppression() {
        let (_owner, l) = layout();
        assert!(l.names_any_variant(), "`Some` is the only payload variant here");

        let (_result_owner, mut r) = layout();
        r.type_name = "Result<u64, u64>".into();
        r.variants[0] = VariantFacet {
            name: "Ok".into(),
            discr: Some(0),
            label: "field_0x8".into(),
            payload_type: r.variants[1].payload_type,
            fields: vec![("__0".into(), 8)],
        };
        r.variants[1] = VariantFacet {
            name: "Err".into(),
            discr: Some(1),
            label: "field_0x8".into(),
            payload_type: r.variants[0].payload_type,
            fields: vec![("__0".into(), 8)],
        };
        assert!(!r.names_any_variant(), "two variants at one offset name neither");
        // The SOURCE names are still on the table -- suppression is a rendering
        // decision, not a loss of what DWARF said.
        assert_eq!(r.facet_for_discr(1).unwrap().name, "Err");
    }

    /// With no default variant an unclaimed value selects nothing -- the lookup
    /// must not fall back to "the first one".
    #[test]
    fn facet_for_discr_without_default_refuses_unclaimed() {
        let (_owner, mut l) = layout();
        l.niche = false;
        l.variants[1].discr = Some(1);
        assert_eq!(l.facet_for_discr(1).unwrap().name, "Some");
        assert!(l.facet_for_discr(7).is_none(), "no default variant => no answer");
    }
}
