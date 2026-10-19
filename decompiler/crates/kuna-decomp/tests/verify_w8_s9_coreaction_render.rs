//! Scheduling, reset and clone-state contracts for the 21 render actions in
//! `decompiler/crates/kuna-decomp/src/p9_emit/coreaction_render.rs`.
//!
//! The scheduling contracts are:
//!
//!   (a) the exact name+flags partition vs the C++ ctors (a typo'd name or a
//!       wrong `rule_onceperfunc` flag is silent scheduling corruption);
//!   (b) the `reset` NON-chaining semantics — C++ `ActionGroup::reset` calls
//!       the *virtual* `reset`, so a stateful subclass whose override is
//!       `{ localcount = 0; }` does NOT run `Action::reset` (status/flags are
//!       left as-is), whereas a non-overriding leaf DOES reset its base;
//!   (c) repeated application on empty IR reports no changes;
//!   (d) `clone_filtered` group selection and independent action counters.
//!
//! Original references: coreaction.hh@bc278439 / coreaction.cc@28f6157.

use std::rc::Rc;

use kuna_base::address::Address;
use kuna_base::space::{
    addrspace_flags, spacetype, AddrSpace, AddrSpaceManager, ConstantSpace, UniqueSpace,
};

use kuna_decomp::action::{ruleflags, statusflags, ActionContext, ActionGroupList};
use kuna_decomp::coreaction_render::{
    render_actions, ActionConstantPtr, ActionDirectWrite, ActionInferTypes,
    ActionRestructureVarnode, ActionSegmentize, ActionStackPtrFlow,
};
use kuna_decomp::funcdata::Funcdata;
use kuna_decomp::context::ArchContext;

fn build_manager() -> AddrSpaceManager {
    let mut m = AddrSpaceManager::new();
    m.insert_space(Rc::new(ConstantSpace::new())).unwrap();
    m.insert_space(Rc::new(UniqueSpace::new(1, 0, false))).unwrap();
    m.insert_space(Rc::new(AddrSpace::new(
        spacetype::IPTR_PROCESSOR,
        "ram",
        false,
        8,
        1,
        2,
        addrspace_flags::hasphysical,
        1,
        1,
    )))
    .unwrap();
    m
}

fn build_fd() -> Funcdata {
    let manage = build_manager();
    let glb = Rc::new(ArchContext::new(manage));
    let ram = Rc::clone(glb.manage().get_space_by_name("ram").unwrap());
    let addr = Address::new(ram, 0x1000);
    Funcdata::new("func", "func", glb, addr, 0x10000000, 0x40).unwrap()
}

/// The full (name, flags) partition for every one of the 21 ported classes,
/// in `render_actions` order, re-derived from the C++ constructors.  `0` =
/// `Action(0,...)`; `1` = `Action(rule_onceperfunc,...)`.
const EXPECTED: &[(&str, u32)] = &[
    ("stackptrflow", 0),
    ("lanedivide", ruleflags::rule_onceperfunc),
    ("segmentize", 0),
    ("forcegoto", 0),
    ("multicse", 0),
    ("shadowvar", 0),
    ("constantptr", 0),
    ("deindirect", 0),
    ("directwrite", 0),
    ("likelytrash", 0),
    ("restructure_varnode", 0),
    ("mapped_local_sync", 0),
    ("mapglobals", ruleflags::rule_onceperfunc),
    ("deadcode", 0),
    ("condconst", 0),
    ("switchnorm", 0),
    ("unjustparams", 0),
    ("dynamicmapping", 0),
    ("dynamicsymbols", ruleflags::rule_onceperfunc),
    ("internalstorage", ruleflags::rule_onceperfunc),
    ("infertypes", 0),
];

/// (a) Every ported leaf carries the EXACT C++ `name()` and `flags`, and the
/// group is the ctor's `g` (fed here as a token that is NOT any action name,
/// to prove the group is plumbed through, not a hard-coded schedule literal).
#[test]
fn w8_render_ctor_facts_match_cpp_partition() {
    let token = "ZZ-not-a-schedule-group";
    let acts = render_actions(token);
    assert_eq!(acts.len(), EXPECTED.len(), "21 live render-residue classes");
    for (act, (name, flags)) in acts.iter().zip(EXPECTED.iter()) {
        assert_eq!(act.get_name(), *name, "name mismatch vs C++ ctor");
        assert_eq!(act.base().flags, *flags, "{}: flags must match C++ ctor", name);
        assert_eq!(act.get_group(), token, "{}: group must be the ctor's g", name);
        // Fresh action starts at status_start (C++ Action::Action base ctor).
        assert_eq!(act.get_status(), statusflags::status_start, "{}: fresh status", name);
    }
    // Exactly the four rule_onceperfunc actions, by name (no more, no fewer).
    let once: Vec<&str> = EXPECTED
        .iter()
        .filter(|(_, f)| *f == ruleflags::rule_onceperfunc)
        .map(|(n, _)| *n)
        .collect();
    assert_eq!(once, vec!["lanedivide", "mapglobals", "dynamicsymbols", "internalstorage"]);
}

/// (b) `reset` NON-chaining: a stateful subclass override is `{ counter = 0; }`
/// only — it must NOT also run the base `Action::reset` (which would reset
/// `status` to status_start and clear `rule_warnings_given`).  We pre-dirty the
/// base, call `reset`, and require the counter zeroed but the base untouched.
/// A non-overriding leaf (`render_actions` includes many) must, by contrast,
/// run the default `reset` and DO reset the base.  This pins the exact C++
/// virtual-dispatch behavior of `ActionGroup::reset` -> `(*iter)->reset`.
#[test]
fn w8_reset_overrides_do_not_chain_to_base() {
    let mut fd = build_fd();

    // --- stateful overrides: counter zeroed, base left dirty (non-chaining) ---
    let mut seg = ActionSegmentize::boxed("g");
    seg.base_mut().status = statusflags::status_end; // dirty
    seg.base_mut().flags |= ruleflags::rule_warnings_given;
    seg.base_mut().count = 9;
    seg.reset(&mut fd);
    assert_eq!(
        seg.get_status(),
        statusflags::status_end,
        "ActionSegmentize::reset must NOT chain to Action::reset (status preserved)"
    );
    assert_ne!(
        seg.base().flags & ruleflags::rule_warnings_given,
        0,
        "warnings_given must NOT be cleared by the non-chaining override"
    );

    for mut a in [
        ActionConstantPtr::boxed("g"),
        ActionRestructureVarnode::boxed("g"),
        ActionInferTypes::boxed("g"),
        ActionStackPtrFlow::boxed("g", None),
    ] {
        a.base_mut().status = statusflags::status_mid;
        a.reset(&mut fd);
        assert_eq!(
            a.get_status(),
            statusflags::status_mid,
            "{}: stateful reset override must not touch base status",
            a.get_name()
        );
    }

    // --- a non-overriding leaf DOES run the default reset (base reset) ---
    // `deadcode` has no reset override in C++ (and none in Rust), so the default
    // trait reset (reset_base) applies.
    let mut acts = render_actions("g");
    let dead = acts
        .iter_mut()
        .find(|a| a.get_name() == "deadcode")
        .expect("deadcode present");
    dead.base_mut().status = statusflags::status_end;
    dead.base_mut().flags |= ruleflags::rule_warnings_given;
    dead.reset(&mut fd);
    assert_eq!(
        dead.get_status(),
        statusflags::status_start,
        "a non-overriding leaf's default reset resets base status to start"
    );
    assert_eq!(
        dead.base().flags & ruleflags::rule_warnings_given,
        0,
        "default reset clears rule_warnings_given"
    );
}

/// Empty IR stays unchanged across repeated application of every render action.
#[test]
fn w8_empty_actions_report_no_change_under_repetition() {
    let mut fd = build_fd();
    let mut ctx = ActionContext::new();
    for mut action in render_actions("g") {
        for _ in 0..16 {
            assert_eq!(action.apply(&mut fd, &mut ctx).unwrap(), 0, "{}", action.get_name());
            assert_eq!(action.base().count, 0, "{} reports no change", action.get_name());
        }
    }

    let mut no_stack = ActionStackPtrFlow::boxed("g", None);
    assert_eq!(no_stack.apply(&mut fd, &mut ctx).unwrap(), 0);
    assert_eq!(no_stack.apply(&mut fd, &mut ctx).unwrap(), 0);
    assert_eq!(no_stack.base().count, 0, "no-stack latch reports no change");
}

/// Group selection and independent action counters across cloned actions.
#[test]
fn w8_clone_filters_groups_and_keeps_independent_state() {
    let yes = ActionGroupList::from_names(["g"]);
    let no = ActionGroupList::from_names(["other"]);

    let src = ActionStackPtrFlow::boxed("g", None);
    assert!(src.clone_filtered(&no).is_none(), "filtered out when group absent");
    let cl = src.clone_filtered(&yes).expect("present when group present");
    assert_eq!(cl.get_name(), "stackptrflow");
    assert_eq!(cl.get_group(), "g");

    for prop in [true, false] {
        let dw = ActionDirectWrite::boxed("g", prop);
        let cl = dw.clone_filtered(&yes).expect("present");
        assert_eq!(cl.get_name(), "directwrite");
    }

    // Independence: mutating the clone's base counter must not touch the source.
    let seg = ActionSegmentize::boxed("g");
    let mut cl = seg.clone_filtered(&yes).expect("present");
    cl.base_mut().count = 42;
    assert_eq!(seg.base().count, 0, "clone is an independent object");
    assert_eq!(cl.base().count, 42);
}
