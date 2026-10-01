//! Prototype recovery initialization with an unlocked result and no returns.

use std::rc::Rc;

use kuna_base::address::Address;
use kuna_base::space::{
    addrspace_flags, spacetype, AddrSpace, AddrSpaceManager, ConstantSpace, UniqueSpace,
};
use kuna_decomp::action::ActionContext;
use kuna_decomp::context::ArchContext;
use kuna_decomp::coreaction_protos::ActionPrototypeTypes;
use kuna_decomp::funcdata::Funcdata;

fn build_fd() -> Funcdata {
    let mut manage = AddrSpaceManager::new();
    manage.insert_space(Rc::new(ConstantSpace::new())).unwrap();
    manage.insert_space(Rc::new(UniqueSpace::new(1, 0, false))).unwrap();
    manage.insert_space(Rc::new(AddrSpace::new(
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
    let glb = Rc::new(ArchContext::new(manage));
    let ram = Rc::clone(glb.manage().get_space_by_name("ram").unwrap());
    let addr = Address::new(ram, 0x1000);
    Funcdata::new("func", "func", glb, addr, 0x1000_0000, 0x40).unwrap()
}

#[test]
fn prototype_initialization_opens_unlocked_result_recovery() {
    let mut data = build_fd();
    let mut ctx = ActionContext::new();
    let mut action = ActionPrototypeTypes::boxed("protorecovery");
    assert!(data.get_active_output().is_none());
    action.apply(&mut data, &mut ctx);
    assert!(data.get_active_output().is_some());
}
