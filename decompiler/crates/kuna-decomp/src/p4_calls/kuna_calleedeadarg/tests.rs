//! Unit tests for the `calleedeadarg` callee entry-liveness probe.

use super::*;
use crate::p0_knowledge::options::KUNA_OPTION_NAMES;

#[test]
fn option_parses_on_and_off() {
    assert!(OptionCalleeDeadArg.apply("on").unwrap().0);
    assert!(!OptionCalleeDeadArg.apply("off").unwrap().0);
    assert!(OptionCalleeDeadArg.apply("maybe").is_err());
}

#[test]
fn option_is_registered() {
    assert!(KUNA_OPTION_NAMES.contains(&OptionCalleeDeadArg::NAME));
}

#[test]
fn incomplete_summary_proves_nothing() {
    let d = CalleeEntryDead::default();
    assert!(!d.is_complete());
}

#[test]
fn summary_with_no_terminator_proves_nothing() {
    // A walk whose every path closes back onto an already-visited address ends
    // complete, with no reads and no cuts.  The cut test is a conjunction, so
    // over an empty list it holds for every register at once.
    let reg = Rc::new(kuna_base::space::AddrSpace::new(
        spacetype::IPTR_PROCESSOR,
        "register",
        false,
        8,
        1,
        3,
        kuna_base::space::addrspace_flags::hasphysical,
        1,
        1,
    ));
    let complete_no_cuts =
        CalleeEntryDead::from_parts(3, Vec::new(), Vec::new(), true);
    assert!(complete_no_cuts.is_complete());
    assert!(!complete_no_cuts.proves_dead(&Address::new(Rc::clone(&reg), 8), 8));

    // The same summary with one terminator that wrote RCX still proves it dead.
    let mut cut = ByteSet::new();
    for b in 8u64..16 {
        cut.insert((3, b));
    }
    let one_cut =
        CalleeEntryDead::from_parts(3, Vec::new(), vec![cut.into_iter().collect()], true);
    assert!(one_cut.proves_dead(&Address::new(reg, 8), 8));
}

/// A callee that leaves for a target nothing accounts for can still be carrying
/// the caller's value out with it, unless it wrote the register first.
/// `argclobber` reads exactly this before deleting a trailing argument, and the
/// direct-call arm is what the reviewer's two-frame counterexamples land on: a
/// NAMED target is not an accounted-for one.
#[test]
fn an_unaccounted_transfer_keeps_the_register_unproven() {
    let reg = Rc::new(kuna_base::space::AddrSpace::new(
        spacetype::IPTR_PROCESSOR,
        "register",
        false,
        8,
        1,
        3,
        kuna_base::space::addrspace_flags::hasphysical,
        1,
        1,
    ));
    let rdx = Address::new(Rc::clone(&reg), 8);
    let target = Address::new(Rc::clone(&reg), 0x1000);
    let rdx_bytes: Vec<(int4, u64)> = (8u64..16).map(|b| (3, b)).collect();
    let cut: Vec<(int4, u64)> = rdx_bytes.clone();
    let base = || CalleeEntryDead::from_parts(3, Vec::new(), vec![cut.clone()], true);
    let free = |d: &CalleeEntryDead, a: TargetAnswer| {
        let mut once = Some(a);
        fold_node(d, 3, move |_| once.take().unwrap_or(TargetAnswer::Unaccounted))
            .transfer_free(&rdx, 8)
    };

    // No transfer at all: nothing can leave, so the register is free.
    assert!(free(&base(), TargetAnswer::Unaccounted));

    // A tail call through a pointer, reached without writing rdx.
    assert!(!free(&base().with_opaque_cut(Vec::new()), TargetAnswer::Unaccounted));

    // The same transfer, with rdx written on the way to it.
    assert!(free(&base().with_opaque_cut(rdx_bytes.clone()), TargetAnswer::Unaccounted));

    // A DIRECT call whose target nothing accounts for -- an import with no
    // signature -- is the same hole, and the one the recovered prototype cannot
    // see: the callee renders with two parameters either way.
    let forwards = base().with_named_cut(target.clone(), Vec::new());
    assert!(!free(&forwards, TargetAnswer::Unaccounted));

    // Declared, so the recovery was typed against it.
    assert!(free(&forwards, TargetAnswer::Accounted));

    // Recovered, so the question is asked of the target in turn -- and its own
    // answer carries: a target that forwards to a hole is one too.
    let denied = fold_node(
        &CalleeEntryDead::from_parts(3, Vec::new(), vec![cut.clone()], true)
            .with_opaque_cut(Vec::new()),
        3,
        |_| TargetAnswer::Unaccounted,
    );
    assert!(!free(&forwards, TargetAnswer::Through(denied)));
    let clean = fold_node(&base(), 3, |_| TargetAnswer::Unaccounted);
    assert!(free(&forwards, TargetAnswer::Through(clean)));

    // ... unless the register was written before the forwarding call.
    let written_first = base().with_named_cut(target, rdx_bytes);
    let denied2 = fold_node(
        &CalleeEntryDead::from_parts(3, Vec::new(), vec![cut.clone()], true)
            .with_opaque_cut(Vec::new()),
        3,
        |_| TargetAnswer::Unaccounted,
    );
    assert!(free(&written_first, TargetAnswer::Through(denied2)));

    // An incomplete walk says nothing, in this direction too.
    let incomplete = CalleeEntryDead::from_parts(3, Vec::new(), Vec::new(), false);
    assert!(!free(&incomplete, TargetAnswer::Unaccounted));
}

/// A forwarder that calls its target reads what the target takes, for the
/// bytes it has not written by the call; `passthrough` reads this, and only
/// `proves_input` answers differently for it.
#[test]
fn a_call_forwards_what_its_target_takes() {
    let reg = Rc::new(kuna_base::space::AddrSpace::new(
        spacetype::IPTR_PROCESSOR,
        "register",
        false,
        8,
        1,
        3,
        kuna_base::space::addrspace_flags::hasphysical,
        1,
        1,
    ));
    let (rdi, rsi) = (Address::new(Rc::clone(&reg), 0x38), Address::new(Rc::clone(&reg), 0x30));
    let target = Address::new(Rc::clone(&reg), 0x1000);
    let narrow = Rc::new(vec![(3, 0x38, 8), (3, 0x30, 8)]);
    let rsi_bytes: Vec<(int4, u64)> = (0x30u64..0x38).map(|b| (3, b)).collect();
    let forwarder = |written: Vec<(int4, u64)>| {
        CalleeEntryDead::from_parts(3, Vec::new(), vec![written.clone()], true).with_named_cut(target.clone(), written)
    };
    let through = |d: &CalleeEntryDead, t: Option<Rc<Vec<RegRead>>>| match add_reads_through(d, |_| Ok(t.clone())).unwrap() {
        Some(reads_live) => CalleeEntryDead { reads_live, ..d.clone() },
        None => d.clone(),
    };

    let fwd = forwarder(Vec::new());
    assert!(!fwd.proves_input(&rdi, 8));
    let t = through(&fwd, Some(Rc::clone(&narrow)));
    assert!(t.proves_input(&rdi, 8) && t.proves_input(&rsi, 8));
    assert_eq!(t.live_input_width(&rdi, 8), Some(8));
    assert!(!t.proves_read(&rdi, 8));

    // A byte written before the call is the forwarder's own value.
    let t = through(&forwarder(rsi_bytes), Some(Rc::clone(&narrow)));
    assert!(t.proves_input(&rdi, 8) && !t.proves_input(&rsi, 8));

    // A register the forwarder reads itself keeps the width it reads it at: the
    // target's wider read of it adds nothing, while `rdi` still comes through.
    let reads_esi = CalleeEntryDead::from_parts(3, vec![(3, 0x30, 4)], vec![Vec::new()], true)
        .with_named_cut(target.clone(), Vec::new());
    assert_eq!(reads_esi.live_input_width(&rsi, 8), Some(4));
    let t = through(&reads_esi, Some(Rc::clone(&narrow)));
    assert!(t.proves_input(&rdi, 8));
    assert_eq!(t.live_input_width(&rsi, 8), Some(4));

    // A target that takes nothing, or an indirect call, adds nothing.
    assert!(add_reads_through(&fwd, |_| Ok(Some(Rc::new(Vec::new())))).unwrap().is_none());
    let opaque = CalleeEntryDead::from_parts(3, Vec::new(), vec![Vec::new()], true).with_opaque_cut(Vec::new());
    assert!(add_reads_through(&opaque, |_| Ok(Some(Rc::clone(&narrow)))).unwrap().is_none());

    // An incomplete forwarder proves nothing whatever its targets take.
    let mut broken = forwarder(Vec::new());
    broken.complete = false;
    assert!(add_reads_through(&broken, |_| Ok(Some(Rc::clone(&narrow)))).unwrap().is_none());
}

/// A target's read counts only for a parameter its own statement takes: a
/// variadic's register-save prologue reads every argument register, and the
/// ones past its named parameters are nothing a forwarder hands it.
#[test]
fn a_target_takes_only_what_it_stated() {
    let reg = Rc::new(kuna_base::space::AddrSpace::new(
        spacetype::IPTR_PROCESSOR,
        "register",
        false,
        8,
        1,
        3,
        kuna_base::space::addrspace_flags::hasphysical,
        1,
        1,
    ));
    let long = Rc::new(crate::dtype::Datatype::new(8, crate::dtype::type_metatype::TYPE_INT));
    let (rdi, rsi) = (Address::new(Rc::clone(&reg), 0x38), Address::new(Rc::clone(&reg), 0x30));
    let stated = crate::kuna_protoorder::RecoveredTypes {
        inputs: vec![(rdi.clone(), 8, Rc::clone(&long)), (rsi.clone(), 8, long)],
        arity_sound: true,
        output: None,
        result: None,
        vararg_tail: vec![rsi],
    };
    // `edi` is a read of the stated `rdi`.
    assert!(takes(&stated, &(3, 0x38, 4)));
    // `rsi` is stated only as a variadic tail, `rcx` not at all.
    assert!(!takes(&stated, &(3, 0x30, 8)));
    assert!(!takes(&stated, &(3, 0x08, 8)));
    // Another space's bytes are not the register.
    assert!(!takes(&stated, &(4, 0x38, 8)));
}

/// `xor ecx,ecx`, `and edx,0` and `or rdx,-1` all write a CONSTANT into the
/// register they read, and their p-code reads it.  The read is formal — the
/// result does not depend on it — so it is kept out of the
/// [`CalleeEntryDead::proves_input`] set, while [`CalleeEntryDead::proves_read`]
/// still counts it: dropping a read can only make `proves_dead` answer `true`
/// more often, and that direction deletes arguments.
#[test]
fn a_constant_writing_idiom_is_not_a_live_read() {
    let reg = Rc::new(kuna_base::space::AddrSpace::new(
        spacetype::IPTR_PROCESSOR,
        "register",
        false,
        8,
        1,
        3,
        kuna_base::space::addrspace_flags::hasphysical,
        1,
        1,
    ));
    let vd = |off: u64, sz: u32| VarnodeData {
        space: Some(Rc::clone(&reg)),
        offset: off,
        size: sz,
    };
    let cspace = Rc::new(kuna_base::space::AddrSpace::new(
        spacetype::IPTR_CONSTANT,
        "const",
        false,
        8,
        1,
        0,
        0,
        0,
        0,
    ));
    let selfop = |opc: OpCode| RawOp {
        opc,
        out: Some(vd(8, 4)),
        ins: vec![vd(8, 4), vd(8, 4)],
    };
    assert!(is_value_erasing(&selfop(OpCode::CPUI_INT_XOR)));
    assert!(is_value_erasing(&selfop(OpCode::CPUI_INT_SUB)));
    // Two different registers is an ordinary read of both.
    assert!(!is_value_erasing(&RawOp {
        opc: OpCode::CPUI_INT_XOR,
        out: Some(vd(8, 4)),
        ins: vec![vd(8, 4), vd(0x10, 4)],
    }));
    // `x & x` and `x | x` return x, so the self form of those is a real read.
    assert!(!is_value_erasing(&selfop(OpCode::CPUI_INT_AND)));
    assert!(!is_value_erasing(&selfop(OpCode::CPUI_INT_OR)));

    let konst = |k: u64, sz: u32| VarnodeData {
        space: Some(Rc::clone(&cspace)),
        offset: k,
        size: sz,
    };
    let with = |opc: OpCode, k: VarnodeData| RawOp {
        opc,
        out: Some(vd(0x10, 8)),
        ins: vec![vd(0x10, 8), k],
    };
    // `and rdx,0` is zero and `or rdx,-1` is all ones, whatever rdx held.
    assert!(is_value_erasing(&with(OpCode::CPUI_INT_AND, konst(0, 8))));
    assert!(is_value_erasing(&with(OpCode::CPUI_INT_OR, konst(u64::MAX, 8))));
    // ...but `and rdx,0xff` and `or rdx,1` both keep bits of rdx.
    assert!(!is_value_erasing(&with(OpCode::CPUI_INT_AND, konst(0xff, 8))));
    assert!(!is_value_erasing(&with(OpCode::CPUI_INT_OR, konst(1, 8))));
    // The all-ones mask is per operand width: 0xffffffff fills a 4-byte
    // constant and leaves the top half of an 8-byte one alone.
    assert!(is_value_erasing(&RawOp {
        opc: OpCode::CPUI_INT_OR,
        out: Some(vd(0x10, 4)),
        ins: vec![vd(0x10, 4), konst(0xffff_ffff, 4)],
    }));
    assert!(!is_value_erasing(&with(OpCode::CPUI_INT_OR, konst(0xffff_ffff, 8))));
}

/// [`CalleeEntryDead::low_read_width`] measures a read from the register's
/// least significant end: `mov %eax,%esi` reads four bytes of `rax`, `test
/// %al,%al` one, and a read of `ah` alone does not read the low byte at all.
/// On a big-endian register file the low end is the last byte.
#[test]
fn a_read_is_measured_from_the_low_end() {
    let space = |big: bool| {
        Rc::new(kuna_base::space::AddrSpace::new(
            spacetype::IPTR_PROCESSOR,
            "register",
            big,
            8,
            1,
            3,
            kuna_base::space::addrspace_flags::hasphysical,
            1,
            1,
        ))
    };
    let summary = |off: u64, sz: int4| CalleeEntryDead {
        reg_idx: 3,
        reads_live: vec![(3, off, sz)],
        live_read_bytes: (off..off + sz as u64).map(|b| (3, b)).collect(),
        complete: true,
        ..CalleeEntryDead::default()
    };
    let le = Address::new(space(false), 0);
    assert_eq!(summary(0, 4).low_read_width(&le, 8), Some(4));
    assert_eq!(summary(0, 1).low_read_width(&le, 8), Some(1));
    assert_eq!(summary(0, 8).low_read_width(&le, 8), Some(8));
    assert_eq!(summary(1, 1).low_read_width(&le, 8), None);
    let be = Address::new(space(true), 0x18);
    assert_eq!(summary(0x1c, 4).low_read_width(&be, 8), Some(4));
    assert_eq!(summary(0x18, 4).low_read_width(&be, 8), None);
}

#[test]
fn saved_cell_reload_does_not_let_padding_evidence_authorize_store_only_arguments() {
    let reg = Rc::new(kuna_base::space::AddrSpace::new(
        spacetype::IPTR_PROCESSOR, "register", false, 8, 1, 3, 0, 1, 1,
    ));
    let address = Address::new(Rc::clone(&reg), 0x18);
    let mut summary = CalleeEntryDead::from_parts(3, vec![(3, 0x18, 8)], vec![], true);
    for byte in 0x18..0x20 {
        summary = summary.with_stored_byte(byte);
    }
    summary.consumed_read_bytes.clear();
    let mut saved = Pushed {
        memory_layout: Some((1, false)),
        slots: vec![(-8, 8, (0x18..0x20).map(|byte| (3, byte)).collect())],
        ..Default::default()
    };
    let destination = VarnodeData { space: Some(Rc::clone(&reg)), offset: 0x10, size: 4 };
    assert!(!saved.read_back(&mut summary, -8, 4, Some(&destination)));
    assert!(summary.unpadded_read_bytes.contains(&(3, 0x18)),
        "a partial saved-cell reload supplies padding provenance, not non-store authority");
    for pads in [false, true] {
        assert!(!summary.reads_low_byte(&address, 8, false, pads),
            "padding policy must not broaden the convention's store-only domain");
        assert!(summary.reads_low_byte(&address, 8, true, pads),
            "conventions admitting stores keep the same evidence");
    }
    assert!(summary.consumed_read_bytes.contains(&(3, 0x18)));
    assert!(summary.consumed_read_bytes.contains(&(3, 0x1b)));
    assert!(!summary.consumed_read_bytes.contains(&(3, 0x1c)),
        "the partial physical dependency remains distinct from argument-extension policy");
    assert!(!summary.live_read_bytes.contains(&(3, 0x18)));
}

#[test]
fn local_projection_retains_exact_physical_demand_without_source_width_coercion() {
    use crate::dtype::{type_class, type_metatype, Datatype};
    use crate::fspec::{FuncCallSpecs, FuncProto, ParamEntry, ParameterPieces, ProtoModel};
    for big in [false, true] {
        let space = |kind, name, index| Rc::new(kuna_base::space::AddrSpace::new(
            kind, name, big, 8, 1, index, 0, 1, 1,
        ));
        let reg = space(spacetype::IPTR_PROCESSOR, "register", 3);
        let ram = space(spacetype::IPTR_PROCESSOR, "ram", 1);
        let unique = space(spacetype::IPTR_INTERNAL, "unique", 2);
        let constant = space(spacetype::IPTR_CONSTANT, "const", 0);
        let v = |space: &Rc<kuna_base::space::AddrSpace>, offset, size| VarnodeData {
            space: Some(Rc::clone(space)), offset, size,
        };
        let op = |opc, out, ins| RawOp { opc, out, ins };
        for shape in ["lea", "subtract", "multiply", "scaled_lea", "multiply_whole",
            "multiply_flags", "multiply_store", "multiply_userop",
            "copy", "copy_source", "userop", "negative_constant", "whole", "flags", "store",
            "address", "unsupported", "overlap", "redefined", "missing", "internal", "wide",
            "high_half", "local_bound", "input_bound"] {
            let source_width = if shape == "wide" { 16 } else { 8 };
            let mut ops = vec![op(
                if shape == "unsupported" { OpCode::CPUI_INT_OR }
                else if shape.starts_with("multiply") || shape == "scaled_lea" { OpCode::CPUI_INT_MULT }
                else if shape == "subtract" { OpCode::CPUI_INT_SUB } else { OpCode::CPUI_INT_ADD },
                Some(v(&unique, 0, source_width)),
                vec![v(&reg, 0x10, source_width),
                    v(&constant, if shape == "negative_constant" { (-3i64) as u64 }
                        else if shape.starts_with("multiply") || shape == "scaled_lea" { 1 }
                        else { 3 }, source_width)],
            )];
            if shape == "scaled_lea" {
                ops.push(op(OpCode::CPUI_INT_ADD, Some(v(&unique, 8, 8)),
                    vec![v(&reg, 0x28, 8), v(&unique, 0, 8)]));
            }
            if matches!(shape, "copy_source" | "userop") {
                ops[0] = op(OpCode::CPUI_COPY, Some(v(&unique, 0, 8)), vec![v(&reg, 0x10, 8)]);
            }
            if shape == "copy" {
                ops.push(op(OpCode::CPUI_COPY, Some(v(&unique, 8, 8)), vec![v(&unique, 0, 8)]));
            }
            if matches!(shape, "overlap" | "redefined") {
                let width = if shape == "redefined" { 8 } else { 4 };
                ops.push(op(OpCode::CPUI_COPY,
                    Some(v(&unique, if shape == "overlap" { 4 } else { 0 }, width)),
                    vec![v(&constant, 0, width)]));
            }
            ops.push(op(OpCode::CPUI_SUBPIECE, Some(v(&reg, 0, 4)), vec![
                v(&unique, if shape == "missing" { 16 }
                    else if matches!(shape, "copy" | "scaled_lea") { 8 } else { 0 }, source_width),
                v(&constant, if shape == "high_half" { 4 } else { 0 }, 4),
            ]));
            if shape == "local_bound" {
                for i in 0..16 {
                    ops.push(op(OpCode::CPUI_COPY, Some(v(&unique, 0x100 + i * 8, 8)),
                        vec![v(&constant, 0, 8)]));
                }
            } else if shape == "input_bound" {
                for i in 0..8 {
                    let temporary = v(&unique, 0x100 + i * 8, 8);
                    ops.push(op(OpCode::CPUI_INT_ADD, Some(temporary.clone()),
                        vec![v(&reg, 0x10, 8), v(&constant, 3, 8)]));
                    ops.push(op(OpCode::CPUI_SUBPIECE, Some(v(&reg, 0x80 + i * 8, 4)),
                        vec![temporary, v(&constant, 0, 4)]));
                }
            }
            match shape {
                "whole" | "multiply_whole" => ops.push(op(OpCode::CPUI_COPY, Some(v(&reg, 0x40, 8)),
                    vec![v(&unique, 0, 8)])),
                "flags" | "multiply_flags" => ops.push(op(OpCode::CPUI_INT_EQUAL, Some(v(&reg, 0x90, 1)),
                    vec![v(&unique, 0, 8), v(&constant, 0, 8)])),
                "store" | "multiply_store" => ops.push(op(OpCode::CPUI_STORE, None,
                    vec![v(&constant, 1, 4), v(&constant, 0x4000, 8), v(&unique, 0, 8)])),
                "address" => ops.push(op(OpCode::CPUI_LOAD, Some(v(&unique, 24, 4)),
                    vec![v(&constant, 1, 4), v(&unique, 0, 8)])),
                "userop" | "multiply_userop" => ops.push(op(OpCode::CPUI_CALLOTHER, Some(v(&unique, 16, 8)),
                    vec![v(&constant, 0, 4), v(&unique, 0, 8)])),
                _ => (),
            }
            ops.push(op(OpCode::CPUI_COPY, Some(v(&reg, 0x10, source_width)),
                vec![v(&constant, 0, source_width)]));
            ops.push(op(OpCode::CPUI_RETURN, None, vec![v(&constant, 0, 8)]));
            let mut summary = CalleeEntryDead { reg_idx: 3, complete: true, ..Default::default() };
            step_instruction(&mut summary, &EntryEmit { ops, internal_flow: shape == "internal" },
                ByteSet::new(), Pushed::default(), &Address::new(Rc::clone(&ram), 0),
                1, None, &[], &Default::default()).unwrap();
            let narrowed = matches!(shape, "lea" | "subtract" | "multiply" | "scaled_lea"
                | "copy" | "copy_source" | "negative_constant");
            let width = if narrowed { 4 } else { source_width };
            let offset = if big { 0x10 + u64::from(source_width - width) } else { 0x10 };
            let physical: Vec<_> = summary.consumed_input_ranges().collect();
            assert!(physical.contains(&(3, offset, width as int4)), "{shape}, BE={big}: {physical:?}");
            if shape == "scaled_lea" {
                assert!(physical.contains(&(3, if big { 0x2c } else { 0x28 }, 4)),
                    "both actual scaled-index LEA operands require low four bytes: {physical:?}");
            }
            if narrowed {
                assert!(!physical.contains(&(3, 0x10, 8)), "the required four-byte range is projected, not lost");
                assert!(summary.input_type_hints(&Address::new(Rc::clone(&reg), 0x10), 8).next().is_none(),
                    "a partial operand does not establish a whole eight-byte integer kind");
            } else if shape == "whole" {
                assert!(summary.input_type_hints(&Address::new(Rc::clone(&reg), 0x10), 8).next().is_some(),
                    "a genuine whole-width integer operand retains its kind evidence");
            }
            let raw_address = Address::new(Rc::clone(&reg), 0x10);
            assert!(summary.proves_read(&raw_address, source_width as int4), "raw read evidence is unchanged");
            assert_eq!(summary.live_input_width(&raw_address, source_width as int4), Some(source_width as int4),
                "raw range/width policies do not inherit the physical demand projection");
            assert!(!summary.proves_dead(&raw_address, source_width as int4),
                "the original read still vetoes dead-entry proof despite a later complete overwrite");
            if !matches!(shape, "lea" | "scaled_lea" | "whole") {
                continue;
            }
            // Exercise the actual early physical-binding consumer, with the
            // same one-byte source formal for both the four- and eight-byte body.
            let mut manager = kuna_base::space::AddrSpaceManager::new();
            for space in [&constant, &ram, &unique, &reg] {
                manager.insert_space(Rc::clone(space)).unwrap();
            }
            manager.set_default_code_space(1).unwrap();
            manager.set_default_data_space(1).unwrap();
            let arch = Rc::new(crate::context::ArchContext::new(manager));
            arch.retain_physical_call_inputs.set(true);
            let mut data = crate::funcdata::Funcdata::new("caller", "caller", arch,
                Address::new(Rc::clone(&ram), 0x1000), 0x1000_0000, 0x40).unwrap();
            let target = data.new_constant(8, 0x2000);
            let call_op = data.new_op(1, data.get_address().clone());
            data.op_set_opcode_code(call_op, OpCode::CPUI_CALL);
            data.op_set_input(call_op, target, 0).unwrap();
            let mut model = ProtoModel::new(data.get_arch().manage());
            model.build_param_list("standard").unwrap();
            model.input_mut().push_entry(ParamEntry::seed(0,
                type_class::TYPECLASS_GENERAL, Rc::clone(&reg), 0x10, 8, 1, 0, 0,
                true, false, &[], data.get_arch().manage()).unwrap());
            model.input_mut().finish_decode();
            model.output_mut().finish_decode();
            let source_address = Address::new(Rc::clone(&reg), if big { 0x17 } else { 0x10 });
            let mut proto = FuncProto::new();
            proto.set_internal(Rc::new(model), Rc::new(Datatype::new(0, type_metatype::TYPE_VOID)));
            proto.set_param(0, "flags", &ParameterPieces {
                addr: source_address.clone(),
                type_: Some(Rc::new(Datatype::new(1, type_metatype::TYPE_BOOL))), flags: 0,
            });
            proto.set_input_lock(true);
            proto.set_output_lock(true);
            let entry = Address::new(Rc::clone(&ram), 0x2000);
            let mut call = FuncCallSpecs::new(call_op, entry.clone());
            call.proto_mut().copy(&proto);
            data.push_call_specs(call);
            data.kuna_set_callee_entry_dead(&entry, Rc::new(summary));
            crate::coreaction_protos::ActionFuncLink::boxed("g")
                .apply(&mut data, &mut crate::action::ActionContext::new()).unwrap();
            let call = data.get_call_specs(0);
            assert_eq!(data.obank().get(call_op).unwrap().num_input(), 2);
            assert_eq!(call.active_input().get_num_trials(), 1, "one carrier, not a duplicated source slice");
            assert_eq!(call.final_input_storage(), &[(Address::new(Rc::clone(&reg), offset), width as int4)]);
            let param = call.proto().get_param(0).unwrap();
            assert_eq!(call.proto().num_params(), 1);
            assert_eq!(param.get_name(), "flags");
            assert_eq!(param.get_size(), 1);
            assert_eq!(param.get_address(), source_address);
            assert_eq!(param.get_type().unwrap().get_metatype(), type_metatype::TYPE_BOOL);
        }
    }
}

#[test]
fn integer_input_hints_require_one_wholly_incoming_operand() {
    let space = |kind, name, index| Rc::new(kuna_base::space::AddrSpace::new(
        kind, name, false, 8, 1, index, 0, 1, 1,
    ));
    let reg = space(spacetype::IPTR_PROCESSOR, "register", 3);
    let ram = space(spacetype::IPTR_PROCESSOR, "ram", 1);
    let unique = space(spacetype::IPTR_INTERNAL, "unique", 2);
    let constant = space(spacetype::IPTR_CONSTANT, "const", 0);
    let v = |space: &Rc<kuna_base::space::AddrSpace>, offset, size| VarnodeData {
        space: Some(Rc::clone(space)), offset, size,
    };
    for shape in ["whole", "union", "internal"] {
        let mut summary = CalleeEntryDead { reg_idx: 3, complete: true, ..Default::default() };
        let mut ops = Vec::new();
        if shape == "union" {
            ops.push(RawOp { opc: OpCode::CPUI_INT_ADD, out: Some(v(&unique, 0, 4)),
                ins: vec![v(&reg, 0x10, 4), v(&constant, 1, 4)] });
            ops.push(RawOp { opc: OpCode::CPUI_COPY, out: Some(v(&reg, 0x10, 4)),
                ins: vec![v(&constant, 0, 4)] });
        }
        ops.push(RawOp { opc: OpCode::CPUI_INT_ADD, out: Some(v(&unique, 8, 8)),
            ins: vec![v(&reg, 0x10, 8), v(&constant, 1, 8)] });
        step_instruction(&mut summary, &EntryEmit { ops, internal_flow: shape == "internal" },
            ByteSet::new(), Pushed::default(), &Address::new(Rc::clone(&ram), 0),
            1, None, &[], &Default::default()).unwrap();
        let address = Address::new(Rc::clone(&reg), 0x10);
        assert_eq!(summary.input_type_hints(&address, 8).collect::<Vec<_>>(),
            if shape == "whole" { vec![(OpCode::CPUI_INT_ADD, 0)] } else { vec![] });
        assert!(summary.input_type_hints(&address, 4).next().is_some() == (shape == "union"));
        assert!(summary.consumed_input_ranges().any(|range| range == (3, 0x10, 8)),
            "all bytes consumed across different reads do not prove a whole operand kind");
        assert!(summary.input_type_hints(&Address::new(Rc::clone(&reg), 0x11), 8).next().is_none());
        summary.complete = false;
        assert!(summary.input_type_hints(&address, 8).next().is_none());
    }
}

#[test]
fn recognized_pushes_keep_padding_policy_separate_from_ordinary_store_evidence() {
    let space = |kind, name, index| Rc::new(kuna_base::space::AddrSpace::new(
        kind, name, false, 8, 1, index, 0, 1, 1,
    ));
    let reg = space(spacetype::IPTR_PROCESSOR, "register", 3);
    let ram = space(spacetype::IPTR_PROCESSOR, "ram", 1);
    let unique = space(spacetype::IPTR_INTERNAL, "unique", 2);
    let constant = space(spacetype::IPTR_CONSTANT, "const", 0);
    let v = |space: &Rc<kuna_base::space::AddrSpace>, offset, size| VarnodeData {
        space: Some(Rc::clone(space)), offset, size,
    };
    let op = |opc, out, ins| RawOp { opc, out, ins };
    let address = Address::new(Rc::clone(&reg), 0x18);
    for count in [Some(0), Some(1), None] {
        let mut summary = CalleeEntryDead { reg_idx: 3, complete: true, ..Default::default() };
        let push = EntryEmit { internal_flow: false, ops: vec![
            op(OpCode::CPUI_COPY, Some(v(&unique, 0, 8)), vec![v(&reg, 0x18, 8)]),
            op(OpCode::CPUI_INT_SUB, Some(v(&reg, 0x20, 8)),
                vec![v(&reg, 0x20, 8), v(&constant, 8, 8)]),
            op(OpCode::CPUI_STORE, None,
                vec![v(&constant, 1, 4), v(&reg, 0x20, 8), v(&unique, 0, 8)]),
        ] };
        let mut frames = step_instruction(&mut summary, &push, ByteSet::new(), Pushed {
            sp: Some((0x20, 8)), entry_offset: Some(0), memory_layout: Some((1, false)),
            ..Default::default()
        }, &Address::new(Rc::clone(&ram), 0), 1, None, &[], &Default::default()).unwrap();
        let frame = frames.pop().unwrap();
        let counts = count.map(|n| std::collections::BTreeMap::from([(1, n)])).unwrap_or_default();
        step_instruction(&mut summary, &EntryEmit { internal_flow: false, ops: vec![
            op(OpCode::CPUI_CALL, None, vec![v(&ram, 0x2000, 8)]),
        ] }, frame.written, frame.pushed, &frame.at, 1, None, &[], &counts).unwrap();
        assert!(!summary.stored_read_bytes.contains(&(3, 0x18)),
            "a recognized push is not duplicated as unconditional store evidence");
        for stores in [false, true] {
            assert!(summary.reads_low_byte(&address, 8, stores, false));
            assert_eq!(summary.reads_low_byte(&address, 8, stores, true), count != Some(0),
                "only a positively identified format padding slot is excluded");
        }
        assert_eq!(summary.consumed_input_ranges().any(|range| range == (3, 0x18, 8)),
            count == Some(1), "a proven forwarded stack argument retains physical consumption");
    }
    for copied in [false, true] {
        let mut summary = CalleeEntryDead { reg_idx: 3, complete: true, ..Default::default() };
        let mut ops = Vec::new();
        if copied {
            ops.push(op(OpCode::CPUI_COPY, Some(v(&unique, 0, 8)), vec![v(&reg, 0x18, 8)]));
        }
        ops.push(op(OpCode::CPUI_STORE, None, vec![v(&constant, 1, 4),
            v(&constant, 0x4000, 8), if copied { v(&unique, 0, 8) } else { v(&reg, 0x18, 8) }]));
        step_instruction(&mut summary, &EntryEmit { ops, internal_flow: false },
            ByteSet::new(), Pushed::default(), &Address::new(Rc::clone(&ram), 0),
            1, None, &[], &Default::default()).unwrap();
        for pads in [false, true] {
            assert!(!summary.reads_low_byte(&address, 8, false, pads));
            assert!(summary.reads_low_byte(&address, 8, true, pads),
                "ordinary STORE evidence remains admitted by the same conventions");
        }
        assert!(summary.consumed_input_ranges().any(|range| range == (3, 0x18, 8)),
            "an external store remains an actual physical dependency");
    }
}

#[test]
fn physical_reads_distinguish_preservation_from_external_consumption() {
    let space = |kind, name, index| Rc::new(kuna_base::space::AddrSpace::new(
        kind, name, false, 8, 1, index, 0, 1, 1,
    ));
    let reg = space(spacetype::IPTR_PROCESSOR, "register", 3);
    let ram = space(spacetype::IPTR_PROCESSOR, "ram", 1);
    let unique = space(spacetype::IPTR_INTERNAL, "unique", 2);
    let constant = space(spacetype::IPTR_CONSTANT, "const", 0);
    let v = |space: &Rc<kuna_base::space::AddrSpace>, offset, size| VarnodeData {
        space: Some(Rc::clone(space)), offset, size,
    };
    let op = |opc, out, ins| RawOp { opc, out, ins };
    for scenario in ["restore", "external_store", "external_copy", "address", "arithmetic",
        "reload_elsewhere", "stack_forward", "unknown_forward", "partial",
        "private_store", "private_copy", "private_arithmetic", "private_external", "private_reloaded_after_restore"] {
        let mut summary = CalleeEntryDead { reg_idx: 3, complete: true, ..Default::default() };
        let private = scenario.starts_with("private_");
        let mut instructions = vec![vec![
            op(OpCode::CPUI_COPY, Some(v(&unique, 0, 8)), vec![v(&reg, 0x18, 8)]),
            op(OpCode::CPUI_INT_SUB, Some(v(&reg, 0x20, 8)), vec![v(&reg, 0x20, 8), v(&constant, 8, 8)]),
            op(OpCode::CPUI_STORE, None, vec![v(&constant, 1, 4), v(&reg, 0x20, 8), v(&unique, 0, 8)]),
        ]];
        if private {
            let mut save = vec![op(OpCode::CPUI_INT_ADD, Some(v(&unique, 32, 8)),
                vec![v(&reg, 0x20, 8), v(&constant, (-8i64) as u64, 8)])];
            let saved = if scenario == "private_copy" {
                save.push(op(OpCode::CPUI_COPY, Some(v(&unique, 0, 8)), vec![v(&reg, 0x18, 8)]));
                v(&unique, 0, 8)
            } else { v(&reg, 0x18, 8) };
            save.push(op(OpCode::CPUI_STORE, None, vec![v(&constant, 1, 4), v(&unique, 32, 8), saved]));
            instructions = vec![save];
        }
        if matches!(scenario, "stack_forward" | "unknown_forward") {
            instructions.push(vec![op(OpCode::CPUI_CALL, None, vec![v(&ram, 0x2000, 8)])]);
        } else {
            let width = if scenario == "partial" { 4 } else { 8 };
            let destination = if scenario == "reload_elsewhere" { 0x10 } else { 0x18 };
            let restore = vec![
                op(OpCode::CPUI_LOAD, Some(v(&unique, 8, width)), vec![v(&constant, 1, 4), v(&reg, 0x20, 8)]),
                op(OpCode::CPUI_COPY, Some(v(&reg, destination, width)), vec![v(&unique, 8, width)]),
                op(OpCode::CPUI_INT_ADD, Some(v(&reg, 0x20, 8)), vec![v(&reg, 0x20, 8), v(&constant, 8, 8)]),
            ];
            if private {
                instructions.push(vec![
                    op(OpCode::CPUI_INT_ADD, Some(v(&unique, 32, 8)),
                        vec![v(&reg, 0x20, 8), v(&constant, (-8i64) as u64, 8)]),
                    op(OpCode::CPUI_LOAD, Some(v(&unique, 8, 8)),
                        vec![v(&constant, 1, 4), v(&unique, 32, 8)]),
                    op(OpCode::CPUI_COPY, Some(v(&reg, 0x18, 8)), vec![v(&unique, 8, 8)]),
                ]);
            } else { instructions.push(restore); }
            let use_op = match scenario {
                "external_store" | "private_external" => Some(op(OpCode::CPUI_STORE, None,
                    vec![v(&constant, 1, 4), v(&constant, 0x4000, 8), v(&reg, 0x18, 8)])),
                "address" => Some(op(OpCode::CPUI_LOAD, Some(v(&unique, 16, 8)),
                    vec![v(&constant, 1, 4), v(&reg, 0x18, 8)])),
                "arithmetic" | "private_arithmetic" => Some(op(OpCode::CPUI_INT_ADD, Some(v(&reg, 0, 8)),
                    vec![v(&reg, 0x18, 8), v(&constant, 5, 8)])),
                _ => None,
            };
            if let Some(use_op) = use_op { instructions.push(vec![use_op]); }
            if scenario == "external_copy" {
                instructions.push(vec![
                    op(OpCode::CPUI_COPY, Some(v(&unique, 24, 8)), vec![v(&reg, 0x18, 8)]),
                    op(OpCode::CPUI_STORE, None,
                        vec![v(&constant, 1, 4), v(&constant, 0x4000, 8), v(&unique, 24, 8)]),
                ]);
            }
            if scenario == "private_reloaded_after_restore" {
                instructions.push(vec![op(OpCode::CPUI_COPY, Some(v(&reg, 0x18, 4)), vec![v(&constant, 0, 4)])]);
                instructions.push(vec![
                    op(OpCode::CPUI_INT_ADD, Some(v(&unique, 32, 8)),
                        vec![v(&reg, 0x20, 8), v(&constant, (-8i64) as u64, 8)]),
                    op(OpCode::CPUI_LOAD, Some(v(&unique, 16, 8)),
                        vec![v(&constant, 1, 4), v(&unique, 32, 8)]),
                    op(OpCode::CPUI_COPY, Some(v(&reg, 0, 8)), vec![v(&unique, 16, 8)]),
                ]);
            }
            instructions.push(vec![op(OpCode::CPUI_RETURN, None, vec![v(&reg, 0x80, 8)])]);
        }
        let stack_args = if scenario == "stack_forward" {
            std::collections::BTreeMap::from([(1, 1)])
        } else {
            Default::default()
        };
        let mut frames = vec![Frame { at: Address::new(Rc::clone(&ram), 0), written: ByteSet::new(),
            pushed: Pushed { sp: Some((0x20, 8)), entry_offset: Some(0),
                memory_layout: Some((1, false)), ..Default::default() } }];
        for ops in instructions {
            let frame = frames.pop().unwrap();
            frames = step_instruction(&mut summary, &EntryEmit { ops, internal_flow: false },
                frame.written, frame.pushed, &frame.at, 1, None, &[], &stack_args).unwrap();
        }
        let physical: Vec<_> = summary.consumed_input_ranges().collect();
        assert_eq!(physical.contains(&(3, 0x18, 8)),
            !matches!(scenario, "restore" | "partial" | "unknown_forward" | "private_store" | "private_copy"),
            "{scenario}: {physical:?}");
        if scenario == "partial" {
            assert!(physical.contains(&(3, 0x18, 4)), "{physical:?}");
        }
        if matches!(scenario, "external_store" | "external_copy" | "private_store" | "private_copy") {
            let address = Address::new(Rc::clone(&reg), 0x18);
            let pushed_then_reloaded = matches!(scenario, "external_store" | "external_copy");
            assert_eq!(summary.reads_low_byte(&address, 8, false, false), pushed_then_reloaded,
                "{scenario}: a recognized push/reload is distinct from an ordinary store-only read");
            assert_eq!(summary.reads_low_byte(&address, 8, false, true), pushed_then_reloaded,
                "{scenario}: a reloaded push is not an unused alignment pad");
            assert!(summary.reads_low_byte(&address, 8, true, false),
                "{scenario}: conventions that admit store evidence retain it");
            assert!(summary.reads_low_byte(&address, 8, true, true),
                "{scenario}: the padding option does not change store authority");
        }
        if matches!(scenario, "arithmetic" | "private_arithmetic") {
            assert!(summary.reads_low_byte(&Address::new(Rc::clone(&reg), 0x18), 8, false, false),
                "a saved value subsequently used in arithmetic is not store-only");
            assert!(summary.reads_low_byte(&Address::new(Rc::clone(&reg), 0x18), 8, false, true),
                "padding exclusion preserves actual arithmetic consumption");
        }
    }
}

#[test]
fn acquisition_propagates_transport_before_caching_but_retains_recoverable_unknown() {
    use crate::engine_translate::test_support::failure_arch;
    let (mut arch, entry, queries) = failure_arch(true);
    for expected in 1..=2 {
        assert!(matches!(probe_cached(&mut arch, &entry, 2),
            Err(kuna_base::error::KunaError::Transport { .. })));
        assert!(arch.kuna_callee_dead_cache.is_empty());
        assert_eq!(queries.get(), expected);
    }
    let (mut arch, entry, queries) = failure_arch(false);
    arch.remote_scope = Some(crate::remote_provider::empty_host_scope(&arch.translate().manager_rc()));
    let summary = probe_cached(&mut arch, &entry, 2).unwrap().unwrap();
    let register = Address::new(
        Rc::clone(arch.manage().get_space_by_name("register").unwrap()), 0x18);
    assert!(!summary.is_complete());
    assert!(!summary.walked_every_path());
    assert!(summary.consumed_input_ranges().next().is_none());
    assert!(!summary.proves_input(&register, 8));
    assert!(!summary.proves_read(&register, 8));
    assert!(!summary.proves_dead(&register, 8));
    assert!(!summary.never_takes(&register, 8));
    assert!(!summary.returns_untouched(&register, 8));
    assert!(probe_cached(&mut arch, &entry, 2).unwrap().is_some());
    assert_eq!(queries.get(), 1, "ordinary unknown remains a reusable body summary");
}

#[test]
fn logical_site_arity_does_not_disable_required_physical_acquisition() {
    use crate::dtype::{type_class, type_metatype, Datatype};
    use crate::engine_translate::test_support::failure_arch;
    use crate::fspec::{FuncCallSpecs, FuncProto, ParamEntry, ParameterPieces, ProtoModel};
    let (mut arch, entry, queries) = failure_arch(true);
    arch.callee_dead_arg = false;
    arch.callee_arity = false;
    arch.arg_clobber = false;
    arch.pass_through = false;
    arch.hidden_ret_arg = false;
    arch.callee_read_arg = false;
    arch.arm_float_args = false;
    let reg = Rc::clone(arch.manage().get_space_by_name("register").unwrap());
    let mut model = ProtoModel::new(arch.manage());
    model.build_param_list("standard").unwrap();
    for (group, offset) in [(0, 0x10), (1, 0x18)] {
        model.input_mut().push_entry(ParamEntry::seed(group, type_class::TYPECLASS_GENERAL,
            Rc::clone(&reg), offset, 8, 1, 0, 0, true, false, &[], arch.manage()).unwrap());
    }
    model.input_mut().finish_decode();
    model.output_mut().finish_decode();
    let mut proto = FuncProto::new();
    proto.set_internal(Rc::new(model), Rc::new(Datatype::new(0, type_metatype::TYPE_VOID)));
    proto.set_param(0, "arg0", &ParameterPieces {
        addr: Address::new(reg, 0x10), type_: Some(Rc::new(Datatype::new(4, type_metatype::TYPE_INT))),
        flags: 0,
    });
    proto.set_input_lock(true);
    proto.set_override(true);
    let mut data = arch.new_funcdata("caller", entry.clone(), 0).unwrap();
    let op = data.new_op(1, entry.clone());
    data.op_set_opcode_code(op, OpCode::CPUI_CALL);
    let target = data.new_constant(8, entry.get_offset());
    data.op_set_input(op, target, 0).unwrap();
    let mut call = FuncCallSpecs::new(op, entry);
    call.proto_mut().copy(&proto);
    data.push_call_specs(call);
    assert!(matches!(seed_callee_entry_dead(&mut arch, &mut data),
        Err(kuna_base::error::KunaError::Transport { .. })));
    assert_eq!(queries.get(), 1);
    assert!(arch.kuna_callee_dead_cache.is_empty());
    assert!(data.get_call_specs(0).proto().is_override());
    assert_eq!(data.get_call_specs(0).proto().num_params(), 1);
}

#[test]
fn partial_saved_reloads_use_actual_memory_byte_order_at_both_ends() {
    use crate::dtype::type_class;
    use crate::fspec::ParamEntry;
    use kuna_base::space::AddrSpaceManager;
    for register_big in [false, true] {
        for memory_big in [false, true] {
            for displacement in [0, 4] {
                let space = |kind, name, index, big| Rc::new(kuna_base::space::AddrSpace::new(
                    kind, name, big, 8, 1, index, 0, 1, 1,
                ));
                let reg = space(spacetype::IPTR_PROCESSOR, "register", 3, register_big);
                let ram = space(spacetype::IPTR_PROCESSOR, "ram", 1, memory_big);
                let unique = space(spacetype::IPTR_INTERNAL, "unique", 2, false);
                let constant = space(spacetype::IPTR_CONSTANT, "const", 0, false);
                let v = |space: &Rc<kuna_base::space::AddrSpace>, offset, size| VarnodeData {
                    space: Some(Rc::clone(space)), offset, size,
                };
                let op = |opc, out, ins| RawOp { opc, out, ins };
                let instructions = vec![
                    vec![
                        op(OpCode::CPUI_INT_ADD, Some(v(&unique, 0, 8)),
                            vec![v(&reg, 0x20, 8), v(&constant, (-8i64) as u64, 8)]),
                        op(OpCode::CPUI_STORE, None,
                            vec![v(&constant, 1, 4), v(&unique, 0, 8), v(&reg, 0x10, 8)]),
                    ],
                    vec![
                        op(OpCode::CPUI_INT_ADD, Some(v(&unique, 0, 8)),
                            vec![v(&reg, 0x20, 8), v(&constant, (-8i64 + displacement) as u64, 8)]),
                        op(OpCode::CPUI_LOAD, Some(v(&unique, 8, 4)),
                            vec![v(&constant, 1, 4), v(&unique, 0, 8)]),
                        op(OpCode::CPUI_COPY, Some(v(&reg, 0, 4)), vec![v(&unique, 8, 4)]),
                        op(OpCode::CPUI_RETURN, None, vec![v(&reg, 0x80, 8)]),
                    ],
                ];
                let mut summary = CalleeEntryDead { reg_idx: 3, complete: true, ..Default::default() };
                let mut frames = vec![Frame {
                    at: Address::new(Rc::clone(&ram), 0), written: ByteSet::new(),
                    pushed: Pushed { sp: Some((0x20, 8)), entry_offset: Some(0),
                        memory_layout: Some((1, memory_big)), ..Default::default() },
                }];
                for ops in instructions {
                    let frame = frames.pop().unwrap();
                    frames = step_instruction(&mut summary, &EntryEmit { ops, internal_flow: false },
                        frame.written, frame.pushed, &frame.at, 1, None, &[], &Default::default()).unwrap();
                }
                let offset = if register_big == memory_big { displacement } else { 4 - displacement };
                let wanted = (3, 0x10 + offset as u64, 4);
                let other = (3, 0x10 + (4 - offset) as u64, 4);
                let reads: Vec<_> = summary.consumed_input_ranges().collect();
                assert!(reads.contains(&wanted), "registerBE={register_big}, memoryBE={memory_big}, at={displacement}: {reads:?}");
                assert!(!reads.contains(&other));
                assert!(!reads.contains(&(3, 0x10, 8)));
                let entry = ParamEntry::seed(0, type_class::TYPECLASS_GENERAL, Rc::clone(&reg),
                    0x10, 8, 1, 0, 0, true, false, &[], &AddrSpaceManager::new()).unwrap();
                assert_eq!(entry.justified_contain(&Address::new(reg, wanted.1), 4),
                    if register_big { 4 - offset as int4 } else { offset as int4 });
            }
        }
    }
}

#[test]
fn an_unknown_stack_assignment_cannot_regain_private_frame_authority() {
    let space = |kind, name, index| Rc::new(kuna_base::space::AddrSpace::new(
        kind, name, false, 8, 1, index, 0, 1, 1,
    ));
    let reg = space(spacetype::IPTR_PROCESSOR, "register", 3);
    let ram = space(spacetype::IPTR_PROCESSOR, "ram", 1);
    let unique = space(spacetype::IPTR_INTERNAL, "unique", 2);
    let constant = space(spacetype::IPTR_CONSTANT, "const", 0);
    let v = |space: &Rc<kuna_base::space::AddrSpace>, offset, size| VarnodeData {
        space: Some(Rc::clone(space)), offset, size,
    };
    let op = |opc, out, ins| RawOp { opc, out, ins };
    let instructions = vec![
        vec![op(OpCode::CPUI_COPY, Some(v(&reg, 0x28, 8)), vec![v(&reg, 0x20, 8)])],
        vec![op(OpCode::CPUI_COPY, Some(v(&reg, 0x20, 8)), vec![v(&reg, 0x10, 8)])],
        // A later known displacement preserves Unknown, not entry-relative Frame.
        vec![op(OpCode::CPUI_INT_ADD, Some(v(&reg, 0x20, 8)),
            vec![v(&reg, 0x20, 8), v(&constant, 16, 8)])],
        vec![
            op(OpCode::CPUI_INT_ADD, Some(v(&unique, 0, 8)),
                vec![v(&reg, 0x20, 8), v(&constant, (-8i64) as u64, 8)]),
            op(OpCode::CPUI_STORE, None,
                vec![v(&constant, 1, 4), v(&unique, 0, 8), v(&reg, 0x18, 8)]),
        ],
        vec![op(OpCode::CPUI_COPY, Some(v(&reg, 0x20, 8)), vec![v(&reg, 0x28, 8)])],
        vec![op(OpCode::CPUI_RETURN, None, vec![v(&reg, 0x80, 8)])],
    ];
    let mut summary = CalleeEntryDead { reg_idx: 3, complete: true, ..Default::default() };
    let mut frames = vec![Frame {
        at: Address::new(ram, 0), written: ByteSet::new(),
        pushed: Pushed { sp: Some((0x20, 8)), entry_offset: Some(0),
            memory_layout: Some((1, false)), ..Default::default() },
    }];
    for ops in instructions {
        let frame = frames.pop().unwrap();
        frames = step_instruction(&mut summary, &EntryEmit { ops, internal_flow: false },
            frame.written, frame.pushed, &frame.at, 1, None, &[], &Default::default()).unwrap();
    }
    let reads: Vec<_> = summary.consumed_input_ranges().collect();
    assert!(reads.contains(&(3, 0x10, 8)), "the incoming pointer is consumed");
    assert!(reads.contains(&(3, 0x18, 8)), "the independent externally stored value must survive");
}
