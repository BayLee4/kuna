//! Porter in-module tests for `architecture.rs`.
//!
//! Two strands:
//!   1. **Defaults + flags + naming**: a minimal `Architecture` over a fresh
//!      (uninitialized) Sleigh — exercises the verbatim `resetDefaultsInternal`
//!      transcription, the kuna anchor flags, `nameFunction`, and the warning
//!      sink without needing a built `.sla`.
//!   2. **Real-`.sla` bootstrap**: builds an `Architecture` over a Sleigh with a
//!      decoded `.sla` (skips gracefully when specs are unbuilt), then lifts a
//!      `Funcdata` through it (the W3 boot seam).

use std::path::PathBuf;
use std::rc::Rc;

use kuna_base::address::Address;
use kuna_base::error::{KunaError, KunaResult};
use kuna_sleigh::globalcontext::ContextInternal;
use kuna_sleigh::loadimage::LoadImage;
use kuna_sleigh::sleigh::Sleigh;
use kuna_sleigh::translate::{Translate, UniqueLayout};

use super::*;
use crate::flow::flow_flags;
use crate::options::split_datatype;

struct DummyImg;
impl LoadImage for DummyImg {
    fn get_file_name(&self) -> &str {
        "dummy"
    }
    fn load_fill(&mut self, _ptr: &mut [u8], _addr: &Address) -> KunaResult<()> {
        Err(KunaError::data_unavail("dummy"))
    }
    fn get_arch_type(&self) -> Vec<u8> {
        Vec::new()
    }
    fn adjust_vma(&mut self, _adjust: i64) {}
}

/// A bare (uninitialized) Sleigh — enough to construct an `Architecture` and
/// read its defaults; it has no spaces (no `.sla`), so it cannot lift.
fn bare_sleigh() -> Sleigh {
    Sleigh::new(Box::new(DummyImg), Box::new(ContextInternal::new()))
}

#[test]
fn sparse_data_organization_uses_source_defaults_and_explicit_abi_overrides() {
    let mut arch = Architecture::new("test:LE:32", bare_sleigh());
    arch.set_cspec_xml(br#"<compiler_spec><data_organization><pointer_size value="4"/></data_organization></compiler_spec>"#.to_vec());
    arch.decode_data_organization().unwrap();
    let types = arch.types();
    assert_eq!(types.get_size_of_int(), 4);
    assert_eq!(types.get_size_of_long(), 4);
    assert_eq!(types.get_size_of_long_long(), 8);
    assert_eq!(types.get_size_of_short(), 2);
    assert_eq!(types.get_size_of_char(), 1);
    assert_eq!(types.get_size_of_wchar(), 2);
    assert_eq!(types.get_size_of_pointer(), 4);
    assert_eq!(types.get_alignment(8).unwrap(), 8);
    arch.reset_defaults();
    assert_eq!(arch.types().get_size_of_long(), 4, "option reset does not change registered source organization");

    arch.set_cspec_xml(br#"<compiler_spec><data_organization><pointer_size value="8"/><long_size value="8"/><long_double_size value="10"/><size_alignment_map><entry size="16" alignment="16"/></size_alignment_map></data_organization></compiler_spec>"#.to_vec());
    arch.decode_data_organization().unwrap();
    assert_eq!(arch.types().get_size_of_pointer(), 8);
    assert_eq!(arch.types().get_size_of_long(), 8);
    assert_eq!(arch.types().get_size_of_long_double(), 10);
    assert_eq!(arch.types().get_alignment(4).unwrap(), 4);
    assert_eq!(arch.types().get_alignment(8).unwrap(), 8);
    assert_eq!(arch.types().get_alignment(16).unwrap(), 16);
}

#[test]
fn default_model_visibility_is_live_while_held_prototypes_keep_their_models() {
    let mut arch = Architecture::new("test", bare_sleigh());
    arch.set_cspec_xml(br#"<compiler_spec>
        <default_proto><prototype name="__stdcall" extrapop="0"/></default_proto>
        <prototype name="__regparm3" extrapop="0"/>
        </compiler_spec>"#.to_vec());
    arch.build_default_proto().unwrap();
    let held_default = arch.get_model("__stdcall").unwrap();
    let held_named = arch.get_model("__regparm3").unwrap();
    let mut source_default = crate::fspec::FuncProto::new();
    source_default.set_model(Some(Rc::clone(&held_default)));
    let mut source_named = crate::fspec::FuncProto::new();
    source_named.set_model(Some(Rc::clone(&held_named)));
    assert!(!held_default.print_in_decl(), "the source default is implicit");
    assert!(held_named.print_in_decl(), "a distinct named convention is explicit");
    assert!(!arch.model_print_in_decl(&source_default));
    assert!(arch.model_print_in_decl(&source_named));
    assert!(arch.print().options.convention, "visibility is not a printer-option override");
    let spelling = crate::printc::RealTypeCtx::from_arch(&arch, crate::kuna_lang::OutLang::C, true);
    assert_eq!(spelling.convention_name(&source_default), None);
    assert_eq!(spelling.convention_name(&source_named), Some("__regparm3"));
    let mut unnamed = crate::fspec::FuncProto::new();
    unnamed.set_model(Some(Rc::new(ProtoModel::copy_named("", &held_named))));
    assert!(!arch.model_print_in_decl(&unnamed));
    assert_eq!(spelling.convention_name(&unnamed), None,
        "an empty visible model name is not a calling-convention token");
    let mut unregistered = crate::fspec::FuncProto::new();
    unregistered.set_model(Some(Rc::new(ProtoModel::copy_named("__source_only", &held_named))));
    assert_eq!(spelling.convention_name(&unregistered), Some("__source_only"),
        "an unregistered source spelling uses its held model visibility");
    let mut implicit_unregistered = ProtoModel::copy_named("__source_implicit", &held_named);
    implicit_unregistered.set_print_in_decl(false);
    unregistered.set_model(Some(Rc::new(implicit_unregistered)));
    assert_eq!(spelling.convention_name(&unregistered), None);
    assert_eq!(spelling.convention_name(&crate::fspec::FuncProto::new()), None);
    arch.set_eval_current_model("__stdcall").unwrap();

    arch.set_default_model("__regparm3").unwrap();
    assert_eq!(arch.default_fp().unwrap().get_name(), "__regparm3");
    assert!(!arch.default_fp().unwrap().print_in_decl());
    assert!(!arch.get_model("__regparm3").unwrap().print_in_decl());
    assert!(arch.get_model("__stdcall").unwrap().print_in_decl());
    assert!(arch.evalfp_current.as_ref().unwrap().print_in_decl());
    assert!(!held_default.print_in_decl(), "held snapshots are not repainted");
    assert!(held_named.print_in_decl(), "held named snapshots remain independent");
    assert!(arch.model_print_in_decl(&source_default),
        "current presentation sees the former default as explicit");
    assert!(!arch.model_print_in_decl(&source_named),
        "current presentation hides the selected default without changing its ABI");
    assert_eq!(spelling.convention_name(&source_default), Some("__stdcall"),
        "a held spelling context shares live visibility, not a registry snapshot");
    assert_eq!(spelling.convention_name(&source_named), None);
    let hidden = crate::printc::RealTypeCtx::from_arch(&arch, crate::kuna_lang::OutLang::C, false);
    assert_eq!(hidden.convention_name(&source_default), None,
        "the active printer option is independent of registered visibility");

    arch.set_default_model("__stdcall").unwrap();
    assert!(!arch.get_model("__stdcall").unwrap().print_in_decl());
    assert!(arch.get_model("__regparm3").unwrap().print_in_decl());
    assert!(!arch.evalfp_current.as_ref().unwrap().print_in_decl());
    assert!(!arch.model_print_in_decl(&source_default));
    assert!(arch.model_print_in_decl(&source_named));
    assert_eq!(spelling.convention_name(&source_default), None);
    assert_eq!(spelling.convention_name(&source_named), Some("__regparm3"));
    arch.reset_wire_defaults();
    assert!(!arch.get_model("__stdcall").unwrap().print_in_decl());
    assert!(arch.print().options.convention);
}

#[test]
fn frozen_export_binding_survives_body_reflow_but_not_explicit_mutations() {
    let mut arch = Architecture::new("test", bare_sleigh());
    let held = Rc::new(crate::kuna_exportcall::ExportBinding::default());
    let install = |arch: &mut Architecture| {
        arch.print_mut().set_export_binding(Some(Rc::clone(&held)));
    };
    install(&mut arch);
    arch.invalidate_body_caches();
    assert!(Rc::ptr_eq(arch.print().export_binding().unwrap(), &held),
        "derived body refresh is not an invocation configuration change");

    arch.context_allow_set(false);
    assert!(arch.print().export_binding().is_none());
    install(&mut arch);
    arch.set_kuna_option("exportinline", "on").unwrap();
    assert!(arch.print().export_binding().is_none());
    install(&mut arch);
    arch.set_flow_options(0);
    assert!(arch.print().export_binding().is_none());
    install(&mut arch);
    arch.set_print_language_checked("c-language").unwrap();
    assert!(arch.print().export_binding().is_none());
    install(&mut arch);
    arch.print_mut().reset_wire_option_defaults();
    assert!(arch.print().export_binding().is_none());
    install(&mut arch);
    arch.flush_remote_caches();
    assert!(arch.print().export_binding().is_none());
    assert!(held.spec().functions.is_empty(), "detached immutable bindings remain readable");
}

#[test]
fn body_authority_is_exact_shared_and_published_before_cached_probes() {
    struct ImportImage { space: Rc<kuna_base::space::AddrSpace> }
    impl LoadImage for ImportImage {
        fn is_import_slot(&self, at: &Address) -> bool {
            at.get_space().is_some_and(|space| Rc::ptr_eq(space, &self.space))
                && (0x1000..0x1008).contains(&at.get_offset())
        }
        fn get_file_name(&self) -> &str { "import-word" }
        fn load_fill(&mut self, _: &mut [u8], _: &Address) -> KunaResult<()> {
            Err(KunaError::data_unavail("import-word"))
        }
        fn get_arch_type(&self) -> Vec<u8> { Vec::new() }
        fn adjust_vma(&mut self, _: i64) {}
    }
    let (mut arch, entry, queries) = crate::engine_translate::test_support::failure_arch(true);
    let space = Rc::clone(entry.get_space().unwrap());
    assert!(arch.is_body_entry(&entry), "images without negative loader evidence retain real bodies");
    arch.set_loader(Box::new(ImportImage { space: Rc::clone(&space) }));
    let key = (space.get_index(), entry.get_offset());
    let summary = Rc::new(crate::kuna_calleedeadarg::CalleeEntryDead::from_parts(
        2, vec![(2, 0x18, 8)], vec![], true));
    arch.kuna_callee_dead_cache.insert(key, Rc::clone(&summary));
    assert!(!arch.is_body_entry(&entry));
    assert!(crate::kuna_calleedeadarg::probe_cached(&mut arch, &entry, 2).unwrap().is_none(),
        "known bodyless addresses are declined before cached evidence or decode");
    assert_eq!(queries.get(), 0);

    let held = Rc::new(crate::kuna_exportcall::ExportBinding::default());
    arch.print_mut().set_export_binding(Some(Rc::clone(&held)));
    arch.declare_body_entry(&entry).unwrap();
    assert!(arch.is_declared_body_entry(&entry));
    assert!(arch.is_body_entry(&entry));
    assert!(arch.kuna_callee_dead_cache.is_empty());
    assert!(arch.print().export_binding().is_none());
    assert!(matches!(crate::kuna_calleedeadarg::probe_cached(&mut arch, &entry, 2),
        Err(KunaError::Transport { .. })), "real declared body errors still propagate");
    assert_eq!(queries.get(), 1);

    arch.kuna_callee_dead_cache.insert(key, Rc::clone(&summary));
    arch.print_mut().set_export_binding(Some(Rc::clone(&held)));
    arch.declare_body_entry(&entry).unwrap();
    assert!(Rc::ptr_eq(arch.kuna_callee_dead_cache.get(&key).unwrap(), &summary));
    assert!(Rc::ptr_eq(arch.print().export_binding().unwrap(), &held),
        "an identical declaration does not mutate invocation authority");
    arch.set_loader(Box::new(ImportImage { space: Rc::clone(&space) }));
    assert!(arch.is_declared_body_entry(&entry), "same-manager wrapper replacement keeps assertions");
    assert!(arch.is_body_entry(&entry));

    let (other, foreign, _) = crate::engine_translate::test_support::failure_arch(true);
    assert_eq!(foreign.get_space().unwrap().get_index(), space.get_index());
    assert!(!arch.is_declared_body_entry(&foreign));
    assert!(!arch.is_body_entry(&foreign));
    assert!(arch.declare_body_entry(&foreign).is_err());
    assert!(!other.is_declared_body_entry(&foreign), "fresh architectures inherit no assertions");
    arch.declared_body_entries.replace(foreign);
    assert!(!arch.is_declared_body_entry(&entry),
        "canonical request identity alone cannot authorize a stale stored bank");
    assert!(!arch.is_body_entry(&entry));
    arch.print_mut().set_export_binding(Some(Rc::clone(&held)));
    arch.kuna_callee_dead_cache.insert(key, summary);
    arch.declare_body_entry(&entry).unwrap();
    assert!(arch.is_declared_body_entry(&entry), "a new assertion replaces the stale binding");
    assert!(arch.kuna_callee_dead_cache.is_empty());
    assert!(arch.print().export_binding().is_none());
    assert!(!arch.is_body_entry(&Address::default()));
    for index in [-1, i32::MAX] {
        let unmanaged = Address::new(Rc::new(kuna_base::space::AddrSpace::new(
            kuna_base::space::spacetype::IPTR_PROCESSOR, "ram", false, 8, 1, index, 0, 1, 1,
        )), 0x1000);
        assert!(!arch.is_body_entry(&unmanaged));
        assert!(arch.declare_body_entry(&unmanaged).is_err(),
            "invalid indices are rejected before indexing the manager");
    }
}

#[test]
fn decode_recipe_requires_both_bootstrap_inputs() {
    let mut arch = Architecture::new("test:LE:32", bare_sleigh());
    assert!(
        arch.decode_recipe().is_none(),
        "a bare engine has no recipe"
    );

    arch.set_decode_sla(std::sync::Arc::from(&b"sla"[..]));
    assert!(
        arch.decode_recipe().is_none(),
        "the .sla alone omits the language's active space truncations"
    );

    arch.set_decode_truncations(Vec::new());
    let recipe = arch
        .decode_recipe()
        .expect("both bootstrap inputs complete the recipe");
    assert_eq!(&*recipe.sla, b"sla");
    assert!(recipe.truncations.is_empty());
}

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../..").canonicalize().unwrap()
}

// --- Strand 1: defaults + flags + naming -----------------------------------

#[test]
fn reset_defaults_internal_matches_cpp() {
    let arch = Architecture::new("test:LE:32", bare_sleigh());
    // Verbatim from architecture.cc:1420 (kuna DIV-2/DIV-3 defaults).
    assert_eq!(arch.trim_recurse_max, 5);
    assert_eq!(arch.max_implied_ref, 2);
    assert_eq!(arch.max_term_duplication, 2);
    assert_eq!(arch.max_basetype_size, 10);
    assert_eq!(arch.flowoptions, flow_flags::error_toomanyinstructions);
    assert_eq!(arch.max_instructions, 100000);
    assert_eq!(arch.max_jumptable_size, 1024);
    assert_eq!(arch.alias_block_level, 2);
    assert_eq!(
        arch.split_datatype_config,
        split_datatype::OPTION_STRUCT | split_datatype::OPTION_ARRAY | split_datatype::OPTION_POINTER
    );
    // ctor one-offs.
    assert_eq!(arch.min_funcsymbol_size, 1);
    assert!(!arch.aggressive_ext_trim);
    assert_eq!(arch.funcptr_align, 0);
    // plain bools.
    assert!(arch.infer_pointers);
    assert!(!arch.readonlypropagate);
    assert!(arch.analyze_for_loops);
    assert!(!arch.nan_ignore_all);
    assert!(arch.nan_ignore_compare);
    assert!(!arch.loadersymbols_parsed);
}

#[test]
fn kuna_anchor_flags_default_to_div_values() {
    let arch = Architecture::new("test:LE:32", bare_sleigh());
    // DIV-2/DIV-3 default-on (architecture.cc:1430-1451).
    assert!(arch.infer_funcentry);
    assert!(arch.memset_recover);
    assert!(arch.ov_less_simplify);
    assert!(arch.fold_boolean_mask);
    assert!(arch.input_varnode_adjust);
    assert!(arch.dynamic_hash_maxdup_high);
    assert!(arch.fold_flag_compare);
    assert!(arch.recover_array_stride);
    assert!(arch.recover_lowered_switch);
    assert!(arch.lowered_switch_labels);
    assert!(arch.lowered_switch_value_check);
    assert!(arch.lowered_switch_exact);
    assert!(arch.lowered_switch_every_head);
    assert!(arch.name_style_angr);
    assert!(arch.condexe_block_placement);
    assert!(arch.add_carry_chain);
    assert!(arch.model_stack_probe_loop);
    assert!(arch.present_lessequal);
    assert!(arch.preserve_thumb_funcptr);
    // (kuna) signedness ships `auto` -- a declaration is re-signed when every
    // signedness-sensitive reader of the value agrees.
    assert_eq!(arch.signedness, crate::kuna_typeround::SignPolicy::Auto);
    // (kuna) DIV-13 default-on sweep: the 10 angr structuring/switch flags are now
    // default-on (per-test opt-out keeps the datatest/stage corpora at parity).
    assert!(arch.tail_call_jumps);
    assert!(arch.tail_call_tables);
    assert!(arch.switch_multi_pred);
    assert!(arch.region_loop_refine);
    assert!(arch.reduce_return_gotos);
    assert!(arch.flatten_ifelse);
    assert!(arch.revert_cross_jumps);
    assert!(arch.dup_return_call_tails);
    assert!(arch.dedup_ite_tail);
    assert!(arch.fold_call_returns);
    // (kuna) foldcallretphi default-on (docs/features/foldcallretphi/flip.md).
    assert!(arch.fold_call_ret_phi);
    assert!(arch.branch_flip);
    // (kuna) DIV-14 default-on sweep: 4 more flags default-on (3 of them REMOVE
    // CODE — stackguard/noreturn_extern/noreturn_propagate). Per-test opt-out
    // (stackguard on the 2 Partial-splitting datatests) keeps the corpora at
    // parity; noreturn_propagate is Listing-gated so it is inert on every gate.
    assert!(arch.strip_stack_guard); // stackguard (REMOVES CODE)
    assert!(arch.noreturn_extern_calls); // noreturn_extern (REMOVES CODE)
    assert!(arch.analysis_noreturn_propagate); // noreturn_propagate (REMOVES CODE, Listing-gated)
    assert!(arch.switch_shared_case); // switchsharedcase
    // default-off (upstream byte-identical).
    assert!(!arch.return_single);
    assert!(!arch.v850_indirect_branch);
    assert!(!arch.sparc_struct_return);
    assert!(!arch.switch_modulo_bound);
    assert!(!arch.unrolled_guard);
    assert!(!arch.stack_alias_deadstore);
}

#[test]
fn reset_defaults_is_idempotent_after_mutation() {
    let mut arch = Architecture::new("t", bare_sleigh());
    arch.infer_funcentry = false;
    arch.max_instructions = 7;
    arch.signedness = crate::kuna_typeround::SignPolicy::Upstream;
    arch.reset_defaults();
    assert!(arch.infer_funcentry);
    assert_eq!(arch.max_instructions, 100000);
    // (kuna) `signedness` ships `auto`: the struct literal holds the inert
    // `Upstream` arm, so only reset_defaults puts the shipped value in place.
    assert_eq!(arch.signedness, crate::kuna_typeround::SignPolicy::Auto);
}

#[test]
fn apply_mode_aggressive_flips_offdefault_flags_but_not_v850_or_dwarf_lines() {
    let mut arch = Architecture::new("test:LE:32", bare_sleigh());
    // Off-by-default under the shipped defaults.
    assert!(!arch.analysis_listing);
    assert!(!arch.analysis_aif);
    assert!(!arch.analysis_fast_funcdisc);
    assert!(!arch.switch_guard_bound);
    assert!(!arch.sparc_struct_return);
    assert!(!arch.v850_indirect_branch);
    assert!(!arch.analysis_dwarf_lines);

    arch.apply_mode("aggressive").expect("aggressive mode applies");

    // Representative aggressive members turned on.
    assert!(arch.analysis_listing);
    assert!(arch.analysis_aif);
    assert!(arch.analysis_fast_funcdisc);
    assert!(arch.switch_guard_bound);
    // Listed by the preset even though DIV-54 makes it a shipped default, so the
    // preset re-enables it after an earlier `--option returndup off`.
    assert!(arch.duplicate_shared_returns);
    assert!(arch.sparc_struct_return); // SPARC-idiom-gated, safe to enable
    // Exclusion 1: reclassifies register-indirect calls on non-V850 targets.
    assert!(!arch.v850_indirect_branch);
    // Exclusion 2: annotates every statement of a `-g` binary with a
    // `/* src.c:NNN */` comment — noise, not recovery.
    assert!(!arch.analysis_dwarf_lines);
}

#[test]
fn apply_mode_reliable_is_a_no_op() {
    let mut arch = Architecture::new("test:LE:32", bare_sleigh());
    arch.apply_mode("reliable").expect("reliable mode applies");
    // reliable == shipped defaults: nothing off-default gets flipped, and nothing
    // on-default gets cleared.
    assert!(!arch.analysis_listing);
    assert!(!arch.analysis_aif);
    assert!(arch.duplicate_shared_returns); // DIV-54 shipped default survives
}

#[test]
fn apply_mode_fast_replaces_exhaustive_with_bounded_discovery() {
    let mut arch = Architecture::new("test:LE:32", bare_sleigh());
    arch.analysis_listing = true;
    arch.analysis_funcstart_patterns = true;
    arch.analysis_aif = true;

    arch.apply_mode("fast").expect("fast mode applies");

    assert!(!arch.analysis_listing);
    assert!(!arch.analysis_funcstart_patterns);
    assert!(!arch.analysis_aif);
    assert!(arch.analysis_fast_funcdisc);
    assert!(arch.infer_funcentry);
    assert!(arch.analysis_noreturn_propagate);
    assert!(!arch.switch_guard_bound);
}

#[test]
fn apply_mode_unknown_errors() {
    let mut arch = Architecture::new("test:LE:32", bare_sleigh());
    assert!(arch.apply_mode("turbo").is_err());
}

#[test]
fn apply_mode_auto_requires_frontend_binary_metadata() {
    let mut arch = Architecture::new("test:LE:32", bare_sleigh());
    let err = arch
        .apply_mode("auto")
        .expect_err("Architecture cannot resolve auto");
    assert!(err.explain().contains("requires input binary size"));
}

#[test]
fn name_function_angr_vs_upstream() {
    let mut arch = Architecture::new("t", bare_sleigh());
    // Need a space to make an address; use a constant-space address (any space
    // suffices for the textual default name).
    let ram = kuna_base::space::AddrSpace::new(
        kuna_base::space::spacetype::IPTR_PROCESSOR,
        "ram",
        false,
        4,
        1,
        7,
        kuna_base::space::addrspace_flags::hasphysical,
        1,
        1,
    );
    let addr = Address::new(Rc::new(ram), 0x401000);

    // angr-style on by default: sub_<addr> (kuna_function_name).
    assert!(arch.name_style_angr);
    let n_angr = arch.name_function(&addr);
    assert!(n_angr.starts_with("sub_"), "angr name was {n_angr}");

    // upstream style: func_<raw-addr>, where raw-addr is C++ Address::printRaw
    // (AddrSpace::printRaw): zero-padded to the address width (4 bytes -> 8 hex
    // digits), no space-name prefix, word-size division (wordsize 1 here).
    arch.name_style_angr = false;
    let n_up = arch.name_function(&addr);
    assert_eq!(n_up, "func_0x00401000", "upstream name was {n_up}");
}

#[test]
fn comment_database_dedups_matching_text() {
    let mut db = CommentDatabase::new();
    let ram = Rc::new(kuna_base::space::AddrSpace::new(
        kuna_base::space::spacetype::IPTR_PROCESSOR,
        "ram",
        false,
        4,
        1,
        7,
        kuna_base::space::addrspace_flags::hasphysical,
        1,
        1,
    ));
    let fad = Address::new(Rc::clone(&ram), 0x1000);
    let ad = Address::new(Rc::clone(&ram), 0x1004);
    assert!(db.add_comment_no_duplicate(comment_type::warning, &fad, &ad, "WARNING: x"));
    // Identical (fad,ad,text) is dropped (returns false).
    assert!(!db.add_comment_no_duplicate(comment_type::warning, &fad, &ad, "WARNING: x"));
    // Different text at the same address is stored.
    assert!(db.add_comment_no_duplicate(comment_type::warning, &fad, &ad, "WARNING: y"));
    assert_eq!(db.comments().len(), 2);

    db.clear();
    assert!(db.add_generated_comment_no_duplicate(comment_type::warning, &fad, &ad, "same text"));
    assert!(!db.add_comment_no_duplicate(crate::comment::comment_type::USER2, &fad, &ad, "same text"));
    db.clear_generated(&fad);
    assert_eq!(db.comments().len(), 1, "authored duplicate takes ownership without reinserting");
    assert!(!db.add_generated_comment_no_duplicate(comment_type::warning, &fad, &ad, "same text"));
    assert!(db.add_generated_comment_no_duplicate(comment_type::warningheader, &fad, &ad, "generated only"));
    db.clear_generated(&fad);
    assert_eq!(db.comments().len(), 1, "generated duplicates cannot take ownership from source");
    assert_eq!(db.comments()[0].text, "same text");
}

#[test]
fn version_constants_via_capability() {
    // The architecture's capability version constants are the decompiler
    // version (architecture.cc:36-37).
    assert_eq!(crate::capability::get_major_version(), 6);
    assert_eq!(crate::capability::get_minor_version(), 1);
}

#[test]
fn inject_tempbase_comes_from_unique_start() {
    // The injection library's tempbase is translate->getUniqueStart(INJECT)
    // (PcodeInjectLibrarySleigh ctor).  With a fresh engine the unique base is
    // 0, so getUniqueStart(INJECT) == 0x300 (the INJECT offset over base 0).
    let sleigh = bare_sleigh();
    let expected = sleigh.get_unique_start(UniqueLayout::INJECT);
    let arch = Architecture::new("t", sleigh);
    assert_eq!(arch.pcodeinjectlib.borrow().base.tempbase, expected);
}

// --- Strand 2: real-`.sla` bootstrap + Funcdata lift -----------------------

fn build_arch_from_sla(sla_rel: &str) -> Option<Architecture> {
    let root = repo_root();
    let sla_path = root.join("specs").join(sla_rel);
    if !sla_path.is_file() {
        eprintln!("SKIP: {} not built (run `make specs`)", sla_path.display());
        return None;
    }
    let sla = std::fs::read(&sla_path).expect("read .sla");
    let mut sleigh = Sleigh::new(Box::new(DummyImg), Box::new(ContextInternal::new()));
    sleigh.initialize_from_sla(&sla).expect("initialize from sla");
    Some(Architecture::new("ARM:LE:32:v7", sleigh))
}

#[test]
fn real_sla_bootstraps_subsystems_and_global_scope() {
    let Some(arch) = build_arch_from_sla("Ghidra/Processors/ARM/data/languages/ARM7_le.sla") else {
        return;
    };
    // The manager has real spaces from the .sla (ram, register, unique, ...).
    assert!(arch.manage().num_spaces() > 2, "decoded .sla yields multiple spaces");
    assert!(arch.manage().get_constant_space().is_some());
    assert!(arch.manage().get_unique_space().is_some());
    // The symbol table has a global scope attached (buildDatabase).
    assert!(arch.symboltab.get_global_scope().is_some());
}

#[test]
fn real_sla_creates_funcdata_at_entry() {
    let Some(mut arch) = build_arch_from_sla("Ghidra/Processors/ARM/data/languages/ARM7_le.sla")
    else {
        return;
    };
    // C++ `restoreFromSpec` inserts the fspec/iop/join spaces into the single
    // engine manager (LOSS-132); `init_post_engine` is that step in the Rust
    // port.  The funcdata's `glb` then shares that one manager, so it carries
    // const/unique/iop/fspec exactly as the lift+analyze path sees them.
    arch.init_post_engine().expect("init_post_engine");
    // Pick the default code space for the function entry.
    let code = Rc::clone(arch.manage().get_default_code_space().expect("default code space"));
    let entry = Address::new(code, 0x8000);
    let fd = arch.new_funcdata("main", entry.clone(), 0x40).expect("create funcdata");
    assert_eq!(fd.get_name(), "main");
    assert_eq!(fd.get_address(), &entry);
    assert_eq!(fd.get_size(), 0x40);
    // The funcdata's IR-boundary glb carries const/unique/iop/fspec spaces.
    assert!(fd.get_arch().manage().get_constant_space().is_some());
    assert!(fd.get_arch().manage().get_iop_space().is_some());
    assert!(fd.get_arch().manage().get_fspec_space().is_some());
    // uniq_start was the analysis unique-start (an absolute high offset).
    let analysis_start = arch.translate().get_unique_start(UniqueLayout::ANALYSIS);
    assert!(analysis_start >= 0x1000_0000);
}

// ===========================================================================
// w9x-arch-engine-glue: owned-subsystem accessors + ArchOptionContext.
// ===========================================================================

use crate::options::{ArchOptionContext, BraceCategory, BraceStyle, NamespaceStrategy};

#[test]
fn owned_subsystems_are_constructed_and_accessible() {
    let mut arch = Architecture::new("t", bare_sleigh());
    // The type factory + printer exist immediately (empty, as the C++ ctor
    // leaves them null until init; the Rust port default-constructs them).
    assert_eq!(arch.print().get_name(), "c-language");
    // The proto registry starts empty (no cspec parsed).
    assert!(arch.default_fp().is_none());
    assert!(!arch.has_model("unknown"));
    // build_default_proto seeds an `unknown` default model.
    arch.build_default_proto().unwrap();
    assert!(arch.has_model("unknown"));
    assert!(arch.default_fp().is_some());
    assert_eq!(arch.get_model("unknown").unwrap().get_name(), "unknown");
    // The full type-factory finish (`finish_typegrp` -> `get_default_size`)
    // needs a decoded `.sla`'s default code space; the e2e gate exercises that
    // real path.  Here (a bare Sleigh, no spaces) the factory is the empty
    // container `build_typegrp` produces.
    arch.build_typegrp();
}

#[test]
fn malformed_model_payloads_propagate_without_abi_fallback() {
    for (default_body, named_body, expected_name) in [
        (r#"<pcode inject="uponentry"/>"#, "", "default"),
        ("", r#"<prototype name="named" extrapop="0"><pcode inject="uponreturn"/></prototype>"#, "named"),
    ] {
        let mut arch = Architecture::new("test", bare_sleigh());
        arch.set_cspec_xml(format!(
            r#"<compiler_spec><default_proto><prototype name="default" extrapop="0">{default_body}</prototype></default_proto>{named_body}</compiler_spec>"#
        ).into_bytes());
        let error = arch.build_default_proto().expect_err("required payload errors must propagate");
        assert!(matches!(error, KunaError::Lowlevel { ref explain }
            if explain == &format!("Missing <body> subtag in <pcode>: Protomodel : {expected_name}")));
        assert!(!arch.has_model("unknown"), "an injection failure is not a default-model fallback");
        assert!(!arch.has_model("named"), "a named model with a malformed body is not admitted");
    }
}

#[test]
fn model_snippet_compile_failure_reaches_architecture_initialization() {
    let Some(mut arch) = build_arch_from_sla("Ghidra/Processors/ARM/data/languages/ARM7_le.sla")
    else {
        return;
    };
    arch.set_cspec_xml(br#"<compiler_spec><default_proto><prototype name="broken" extrapop="0">
        <pcode inject="uponreturn"><body>local value:4 = ;</body></pcode>
        </prototype></default_proto></compiler_spec>"#.to_vec());
    assert!(arch.init_post_engine().is_err(), "a model body compile failure must abort initialization");
    let model = arch.default_fp().expect("model registration precedes compilation");
    assert_eq!(model.get_name(), "broken", "the compiler error is not an ABI decode fallback");
    let id = model.get_inject_upon_return();
    assert!(id >= 0);
    assert!(arch.pcodeinjectlib.borrow().get_tpl(id).is_none());
}

#[test]
fn repeated_model_decode_reuses_both_role_ids_and_aliases() {
    let mut arch = Architecture::new("test", bare_sleigh());
    let spec = br#"<compiler_spec><default_proto><prototype name="default" extrapop="0">
        <pcode inject="uponentry" dynamic="true"/>
        <pcode inject="uponreturn"><body>local value:4 = 1;</body></pcode>
        </prototype></default_proto><modelalias name="alias" parent="default"/></compiler_spec>"#;
    let library = Rc::clone(&arch.pcodeinjectlib);
    for _ in 0..2 {
        arch.set_cspec_xml(spec.to_vec());
        arch.build_default_proto().unwrap();
        let model = arch.default_fp().unwrap();
        assert_eq!(model.get_inject_upon_entry(), 0);
        assert_eq!(model.get_inject_upon_return(), 1);
        let alias = arch.get_model("alias").unwrap();
        assert_eq!(alias.get_inject_upon_entry(), 0);
        assert_eq!(alias.get_inject_upon_return(), 1);
        assert!(Rc::ptr_eq(&arch.pcodeinjectlib, &library));
        assert_eq!(library.borrow().injection.len(), 2, "no duplicate or orphan registration");
        assert!(library.borrow().get_payload(0).core().is_dynamic());
        assert!(!library.borrow().get_payload(1).core().is_dynamic());
    }
}

#[test]
fn conflicting_model_redecode_preserves_the_original_live_payload() {
    let mut arch = Architecture::new("test", bare_sleigh());
    arch.set_cspec_xml(br#"<compiler_spec><default_proto><prototype name="default" extrapop="0">
        <pcode inject="uponentry" dynamic="true"/>
        </prototype></default_proto></compiler_spec>"#.to_vec());
    arch.build_default_proto().unwrap();
    let id = arch.default_fp().unwrap().get_inject_upon_entry();
    for replacement in [
        r#"<pcode inject="uponentry"><body>local value:4 = 1;</body></pcode>"#,
        r#"<pcode inject="uponentry" dynamic="true" incidentalcopy="true"/>"#,
        r#"<pcode inject="uponentry" dynamic="true"><input name="changed" size="4"/></pcode>"#,
        r#"<pcode inject="uponentry" dynamic="true"><output name="changed" size="4"/></pcode>"#,
    ] {
        arch.set_cspec_xml(format!(
            r#"<compiler_spec><default_proto><prototype name="default" extrapop="0">{replacement}</prototype></default_proto></compiler_spec>"#
        ).into_bytes());
        assert_eq!(arch.build_default_proto(), Err(KunaError::lowlevel(
            "Duplicate <callmechanism>: default@@inject_uponentry"
        )));
        let library = arch.pcodeinjectlib.borrow();
        assert_eq!(library.injection.len(), 1, "conflict never allocates a second live payload");
        assert!(library.get_payload(id).core().is_dynamic());
        assert!(!library.get_payload(id).core().is_incidental_copy());
        assert_eq!(library.get_payload(id).core().size_input(), 0);
        assert_eq!(library.get_payload(id).core().size_output(), 0);
    }
}

#[test]
fn build_instructions_populates_the_inst_table() {
    use kuna_num::opcodes::OpCode;
    use crate::op::pcodeop_flags;
    let mut arch = Architecture::new("t", bare_sleigh());
    arch.build_instructions();
    // A BRANCH resolves to a TypeOp carrying the branch + coderef flags.
    let to = arch.resolve_typeop(OpCode::CPUI_BRANCH);
    assert_eq!(to.get_opcode(), OpCode::CPUI_BRANCH);
    assert!(to.get_flags() & pcodeop_flags::branch != 0);
    assert!(to.get_flags() & pcodeop_flags::coderef != 0);
}

#[test]
fn arch_option_context_mutates_config_fields() {
    let mut arch = Architecture::new("t", bare_sleigh());
    // Plain config fields round-trip through the trait.
    arch.set_readonly_propagate(true);
    assert!(arch.readonlypropagate);
    arch.set_infer_pointers(false);
    assert!(!arch.infer_pointers);
    arch.set_max_jumptable_size(64);
    assert_eq!(arch.max_jumptable_size, 64);
    arch.set_alias_block_level(1);
    assert_eq!(ArchOptionContext::alias_block_level(&arch), 1);
    arch.set_nan_ignore_all(true);
    assert!(arch.nan_ignore_all());
}

#[test]
fn arch_option_context_drives_the_printer() {
    let mut arch = Architecture::new("t", bare_sleigh());
    assert!(arch.print_is_c_language());
    // (kuna) DIV-34: NULL printing is default-on; the option still drives it.
    assert!(arch.print().options.null);
    arch.set_null_printing(false);
    assert!(!arch.print().options.null);
    arch.set_null_printing(true);
    assert!(arch.print().options.null);
    arch.set_convention_printing(false);
    assert!(!arch.print().options.convention);
    arch.set_brace_format(BraceCategory::Function, BraceStyle::SameLine);
    assert_eq!(arch.print().options.brace_func, BraceStyle::SameLine);
    arch.set_namespace_strategy(NamespaceStrategy::None);
    arch.set_integer_format("hex");
    // Switching the print language flips print_is_c_language.
    arch.set_print_language("not-c");
    assert!(!arch.print_is_c_language());
}

#[test]
fn arch_option_context_proto_model_registry() {
    let mut arch = Architecture::new("t", bare_sleigh());
    arch.build_default_proto().unwrap();
    // set_default_extra_pop mutates the shared default model.
    arch.set_default_extra_pop(8);
    assert_eq!(arch.default_fp().unwrap().get_extra_pop(), 8);
    // set_default_model resolves a registered model and errors on unknown.
    assert!(arch.set_default_model("unknown").is_ok());
    let err = arch.set_default_model("no-such-model").unwrap_err();
    assert!(format!("{err}").contains("Unknown prototype model"));
    // Unknown function (no symbol table function) errors faithfully.
    let err = arch.set_function_extra_pop("nofunc", 4).unwrap_err();
    assert!(format!("{err}").contains("Unknown function name"));
}

/// (kuna) `loopcounterstore` (DIV-146): the shipped default is ON, the option
/// name toggles it, and a bogus value is refused.  The brake is read through
/// the ArchSeam copy in `build_arch_handle`, so a field that is declared and
/// never copied is silently inert -- `reset_defaults` is the only place the
/// shipped default exists.
#[test]
fn loopcounterstore_defaults_on_and_toggles() {
    let mut arch = Architecture::new("t", bare_sleigh());
    arch.reset_defaults_internal();
    assert!(arch.loop_counter_store, "loopcounterstore ships default-ON (DIV-146)");
    arch.set_kuna_option("loopcounterstore", "off").unwrap();
    assert!(!arch.loop_counter_store);
    arch.set_kuna_option("loopcounterstore", "on").unwrap();
    assert!(arch.loop_counter_store);
    assert!(arch.set_kuna_option("loopcounterstore", "maybe").is_err());
}

/// (kuna) `tiedphitrim` (DIV-182): ships default-ON, toggles by name and
/// refuses a bogus value.
#[test]
fn tiedphitrim_defaults_on_and_toggles() {
    let mut arch = Architecture::new("t", bare_sleigh());
    arch.reset_defaults_internal();
    assert!(arch.tied_phi_trim, "tiedphitrim ships default-ON (DIV-182)");
    arch.set_kuna_option("tiedphitrim", "off").unwrap();
    assert!(!arch.tied_phi_trim);
    arch.set_kuna_option("tiedphitrim", "on").unwrap();
    assert!(arch.tied_phi_trim);
    assert!(arch.set_kuna_option("tiedphitrim", "maybe").is_err());
}

/// (kuna) `jumptablemax`: ships at upstream's 1024, takes a positive decimal
/// count, and refuses anything else rather than reading a prefix of it.
#[test]
fn jumptablemax_defaults_to_1024_and_parses_strictly() {
    let mut arch = Architecture::new("t", bare_sleigh());
    arch.reset_defaults_internal();
    assert_eq!(arch.max_jumptable_size, 1024);
    arch.set_kuna_option("jumptablemax", "100000").unwrap();
    assert_eq!(arch.max_jumptable_size, 100000);
    for bad in ["", "0", "wide", "12abc", "1.5", "-5", "+5", "0x10", "4294967296"] {
        assert!(arch.set_kuna_option("jumptablemax", bad).is_err(), "{bad:?} was accepted");
    }
    assert_eq!(arch.max_jumptable_size, 100000);
}
