//! Genuine same-owner receipt mutation regressions, enabled only by test-support.
use super::*;
use crate::architecture::Architecture;
use crate::context::GlobalQuery;

#[derive(Clone, Copy, Debug)]
enum Premise { LoaderByte, ReadonlyPolicy, VolatileProperty, TrackedValue }

enum Undo {
    LoaderByte { address: Address, bytes: Vec<u8> },
    ReadonlyPolicy(bool),
    VolatileProperty(Rc<GlobalQuery>),
    TrackedValue { entry: Address, index: usize, value: u64 },
}

fn mutate(fd: &mut Funcdata, replay: &BranchReplay, premise: Premise) -> KunaResult<Undo> {
    match premise {
        Premise::LoaderByte => {
            let fact = replay.readonly.first().expect("actual readonly fact");
            let original = fact.bytes[..fact.size as usize].to_vec();
            let mut changed = original.clone();
            changed[0] ^= 1;
            let loader = fd.get_arch().loader.as_ref().expect("real selected loader");
            assert!(Rc::ptr_eq(loader, &fact.loader), "do not replace loader identity");
            loader.borrow_mut().kuna_overlay_bytes(&fact.address, &changed)?;
            let mut observed = vec![0; fact.size as usize];
            fd.get_arch().loader_fill(&mut observed, &fact.address)?;
            assert_eq!(observed, changed, "the real loader must expose the mutation");
            Ok(Undo::LoaderByte { address: fact.address.clone(), bytes: original })
        }
        Premise::ReadonlyPolicy => {
            let context = fd.readonly_replay_probe_context();
            let previous = context.readonlypropagate;
            context.readonlypropagate = !previous;
            Ok(Undo::ReadonlyPolicy(previous))
        }
        Premise::VolatileProperty => {
            let fact = replay.readonly.first().expect("actual readonly fact");
            let before = memory_properties(fd, &fact.address, fact.size);
            assert_eq!(before & varnode_flags::volatil, 0);
            let context = fd.readonly_replay_probe_context();
            assert!(context.remote_scope.is_none(), "standalone real image fixture");
            let previous = context.global_query.as_ref().expect("real global snapshot").clone();
            context.global_query = Some(Rc::new(previous.readonly_replay_probe_volatile(&fact.address, fact.size)));
            assert_eq!(memory_properties(fd, &fact.address, fact.size), before | varnode_flags::volatil,
                "exactly the volatile property changes");
            Ok(Undo::VolatileProperty(previous))
        }
        Premise::TrackedValue => {
            let fact = replay.tracked.first().expect("actual guard-relevant tracked fact");
            let entry = fd.get_address().clone();
            let set = fd.readonly_replay_probe_context().tracked_sets.get_value_mut(&entry);
            let matches: Vec<_> = set.iter().enumerate().filter_map(|(index, tracked)| {
                (tracked.loc.space.as_ref().is_some_and(|space|
                    fact.storage.address == Address::new(space.clone(), tracked.loc.offset))
                    && tracked.loc.size as int4 == fact.storage.size).then_some(index)
            }).collect();
            assert_eq!(matches.len(), 1, "mutate the exact receipt's unique tracked storage");
            let index = matches[0];
            let value = set[index].val;
            assert_eq!(value, fact.value);
            set[index].val ^= 1;
            Ok(Undo::TrackedValue { entry, index, value })
        }
    }
}

fn restore(fd: &mut Funcdata, undo: Undo) -> KunaResult<()> {
    match undo {
        Undo::LoaderByte { address, bytes } => fd.get_arch().loader.as_ref().expect("real loader")
            .borrow_mut().kuna_overlay_bytes(&address, &bytes)?,
        Undo::ReadonlyPolicy(previous) => fd.readonly_replay_probe_context().readonlypropagate = previous,
        Undo::VolatileProperty(previous) => fd.readonly_replay_probe_context().global_query = Some(previous),
        Undo::TrackedValue { entry, index, value } =>
            fd.readonly_replay_probe_context().tracked_sets.get_value_mut(&entry)[index].val = value,
    }
    Ok(())
}

fn exact_required_receipt(fd: &Funcdata, expected: &Rc<BranchReplay>) {
    let state = fd.branch_reachability.as_ref().expect("actual branch state");
    assert!(Rc::ptr_eq(state.replayed.as_ref().expect("actual cross-flow replay"), expected),
        "the same immutable receipt, not a replacement decompile's receipt");
    assert_eq!(certified_cuts(fd).len(), 1);
}

pub(crate) fn run(arch: &mut Architecture, fd: &mut Funcdata) -> KunaResult<()> {
    let completed = completed_replays(fd);
    assert_eq!(completed.len(), 1, "real optimizer must produce a receipt before mutation");
    let actual = &completed[0];
    let state = fd.branch_reachability.as_ref().expect("actual branch state");
    let replay = state.replayed.as_ref().expect("real pipeline must consume its receipt").clone();
    assert_eq!(actual.cut, replay.cut);
    assert_eq!(actual.raw, replay.raw);
    assert!(!replay.readonly.is_empty());
    assert!(!replay.tracked.is_empty(), "use the real MIPS guard with relevant tracked input");
    assert!(replay.readonly.iter().all(|fact| fact.bytes[..fact.size as usize].iter().all(|&byte| byte == 0)),
        "the authentic initial guard reads zero");
    exact_required_receipt(fd, &replay);
    validate_final(fd)?;

    let owner = fd.get_arch().as_ref() as *const crate::context::ArchContext;
    let premises = [Premise::LoaderByte, Premise::ReadonlyPolicy, Premise::VolatileProperty, Premise::TrackedValue];
    for premise in premises {
        let undo = mutate(fd, &replay, premise)?;
        exact_required_receipt(fd, &replay);
        let result = validate_final(fd);
        restore(fd, undo)?;
        let _ = result.expect_err("changed premise must invalidate the existing final receipt");
        validate_final(fd)?;
    }

    // Re-follow the same Funcdata in the same Architecture using the real flow
    // driver. Keep the old opaque receipt, rather than decompiling a replacement.
    let source = fd.get_func_proto().source_prototype();
    crate::decompile_drive::refollow_flow(arch, fd, Some(&source))?;
    assert_eq!(fd.get_arch().as_ref() as *const crate::context::ArchContext, owner);
    seed_raw(fd, std::slice::from_ref(&replay))?;
    exact_required_receipt(fd, &replay);
    for premise in premises {
        let undo = mutate(fd, &replay, premise)?;
        let result = seed_raw(fd, std::slice::from_ref(&replay));
        restore(fd, undo)?;
        let _ = result.expect_err("changed premise must reject the old receipt at raw admission");
        assert!(certified_cuts(fd).is_empty(), "failed admission must expose no cut");
        seed_raw(fd, std::slice::from_ref(&replay))?;
        exact_required_receipt(fd, &replay);
    }
    Ok(())
}
