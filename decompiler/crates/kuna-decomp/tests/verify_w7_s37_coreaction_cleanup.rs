//! High-variable activation and cleanup-action filtering regressions.

use std::rc::Rc;

use kuna_base::address::Address;
use kuna_base::space::{
    addrspace_flags, spacetype, AddrSpace, AddrSpaceManager, ConstantSpace, UniqueSpace,
};

use kuna_decomp::action::{ActionContext, ActionGroupList};
use kuna_decomp::coreaction_cleanup::{
    ActionAssignHigh, ActionMergeRequired, ActionSetCasts,
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
    let types = Rc::new(kuna_decomp::dtype::TypeFactoryImpl::new());
    types.set_default_alignment_map();
    types.set_max_basetype_size(8);
    let mut arch = ArchContext::new(manage);
    arch.types = Some(types);
    let glb = Rc::new(arch);
    let ram = Rc::clone(glb.manage().get_space_by_name("ram").unwrap());
    let addr = Address::new(ram, 0x1000);
    Funcdata::new("func", "func", glb, addr, 0x10000000, 0x40).unwrap()
}

/// Activating high variables is idempotent and does not signal an IR rewrite.
#[test]
fn w7_s37_assign_high_is_idempotent() {
    let mut fd = build_fd();
    let mut ctx = ActionContext::new();

    let mut assign = ActionAssignHigh::boxed("merge");
    assert!(!fd.is_high_on());
    assert_eq!(assign.apply(&mut fd, &mut ctx), 0);
    assert_eq!(assign.base().count, 0, "setHighLevel signals no change (C++ return 0)");
    assert!(fd.is_high_on(), "high layer on after assignhigh");
    // Idempotent: re-apply changes nothing and never signals.
    assert_eq!(assign.apply(&mut fd, &mut ctx), 0);
    assert_eq!(assign.base().count, 0);
    assert!(fd.is_high_on());

}

/// (d) `clone_filtered` is the C++ `clone(grouplist)` group filter: present iff
/// the grouplist contains the leaf's group, dropped (the C++ `(Action *)0`)
/// otherwise — AND the clone is independent (mutating the clone's count does
/// not touch the original, and the clone is born with the original's group).
/// A `casts`-group leaf must survive a {casts} list but be dropped by a {merge}
/// list, and vice-versa, exercising the per-leaf group string (not a shared
/// literal).
#[test]
fn w7_s37_clone_filtered_group_filter_and_independence() {
    let only_merge = ActionGroupList::from_names(["merge"]);
    let only_casts = ActionGroupList::from_names(["casts"]);
    let both = ActionGroupList::from_names(["merge", "casts"]);
    let neither = ActionGroupList::from_names(["analysis"]);

    // A "merge"-group leaf: kept by {merge} and {merge,casts}, dropped by
    // {casts} and {analysis}.
    let mr = ActionMergeRequired::boxed("merge");
    assert!(mr.clone_filtered(&only_merge).is_some());
    assert!(mr.clone_filtered(&both).is_some());
    assert!(mr.clone_filtered(&only_casts).is_none(), "merge leaf dropped by casts-only list");
    assert!(mr.clone_filtered(&neither).is_none());

    // The lone "casts"-group leaf: the mirror image.
    let sc = ActionSetCasts::boxed("casts");
    assert!(sc.clone_filtered(&only_casts).is_some());
    assert!(sc.clone_filtered(&both).is_some());
    assert!(sc.clone_filtered(&only_merge).is_none(), "casts leaf dropped by merge-only list");

    // Independence: the clone carries the original's name+group, and bumping the
    // clone's counter (via apply on the realized action) leaves the original at 0.
    let orig = ActionAssignHigh::boxed("merge");
    let mut cl = orig.clone_filtered(&only_merge).expect("kept");
    assert_eq!(cl.get_name(), "assignhigh");
    assert_eq!(cl.get_group(), "merge");
    let mut fd = build_fd();
    let mut ctx = ActionContext::new();
    let _ = cl.apply(&mut fd, &mut ctx); // assignhigh signals 0 anyway, but mutate the clone path
    cl.base_mut().count += 7; // forcibly diverge the clone's state
    assert_eq!(cl.base().count, 7);
    assert_eq!(orig.base().count, 0, "clone state must not leak back to the original");
}
