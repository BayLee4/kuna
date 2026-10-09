// Tests for the `dynamic` port (DynamicHash / ToOpEdge), included into
// `mod tests` in dynamic.rs.
//
// Covered:
//   - the hash field encoding round-trips: getSlotFromHash / getMethodFromHash /
//     getOpCodeFromHash / getPositionFromHash / getTotalFromHash /
//     getIsNotAttached / clearTotalPosition / getComparable against the exact
//     bit layout `pieceTogetherHash` packs.
//   - TRANSTABLE lumping invariants (NOT_EQUAL hashes as EQUAL, SUB as ADD,
//     PTRADD/PTRSUB as INT_ADD, CAST skipped).
//   - calcHash determinism: hashing the same Varnode twice gives the same hash
//     and address; a different root gives a different hash.
//   - calcHash invariance under an interposed CAST (skip op).
//   - uniqueHash on a distinguishable Varnode yields a nonzero hash whose
//     encoded method/total/position are consistent, and findVarnode round-trips
//     it back to the same Varnode.
//   - the max-dup cap: the wider (16) budget admits a unique hash where the
//     narrow (per-method overflow) path would not change the encoding here, and
//     getTotalFromHash never exceeds the budget ceiling.

use super::*;

use std::rc::Rc;

use kuna_base::address::Address;
use kuna_base::space::{
    addrspace_flags, spacetype, AddrSpace, AddrSpaceManager, ConstantSpace, UniqueSpace,
};
use kuna_base::types::{int4, uint8};
use kuna_num::opcodes::OpCode;

use crate::dtype::{type_metatype, Datatype};
use crate::funcdata::Funcdata;
use crate::context::{ArchContext, BlockId, OpId, TypeOp, VarnodeId};

fn build_manager(big: bool) -> AddrSpaceManager {
    let mut m = AddrSpaceManager::new();
    m.insert_space(Rc::new(ConstantSpace::new())).unwrap();
    m.insert_space(Rc::new(UniqueSpace::new(1, 0, false))).unwrap();
    m.insert_space(Rc::new(AddrSpace::new(
        spacetype::IPTR_PROCESSOR,
        "ram",
        big,
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
    let manage = build_manager(false);
    let glb = Rc::new(ArchContext::new(manage));
    let ram = Rc::clone(glb.manage().get_space_by_name("ram").unwrap());
    let addr = Address::new(ram, 0x1000);
    Funcdata::new("func", "func", glb, addr, 0x1000_0000, 0x40).unwrap()
}

fn ram(fd: &Funcdata) -> Rc<AddrSpace> {
    Rc::clone(fd.get_arch().manage().get_space_by_name("ram").unwrap())
}

fn unk(size: int4) -> Rc<Datatype> {
    Rc::new(Datatype::new(size, type_metatype::TYPE_UNKNOWN))
}

fn mk_op(fd: &mut Funcdata, inputs: int4, off: u64, opc: OpCode) -> OpId {
    let r = ram(fd);
    let op = fd.new_op(inputs, Address::new(r, off));
    fd.obank_mut().change_opcode(op, TypeOp::new(opc, 0, format!("{opc:?}")));
    op
}

fn mk_vn(fd: &mut Funcdata, off: u64, size: int4) -> VarnodeId {
    let r = ram(fd);
    fd.vbank_mut().create(size, Address::new(r, off), unk(size))
}

fn mk_block(fd: &mut Funcdata) -> BlockId {
    let root = fd.bblocks_ref().root.expect("bblocks root");
    fd.bblocks_mut().new_block_basic(root)
}

/// `out = BINOP(a, b)` at `out_off`, placed in `bl`.  Returns the output vn.
#[allow(clippy::too_many_arguments)] // test graph-builder: explicit offsets/sizes aid readability
fn binop(
    fd: &mut Funcdata,
    bl: BlockId,
    off: u64,
    opc: OpCode,
    a: VarnodeId,
    b: VarnodeId,
    out_off: u64,
    out_size: int4,
) -> VarnodeId {
    let op = mk_op(fd, 2, off, opc);
    fd.op_set_input(op, a, 0).unwrap();
    fd.op_set_input(op, b, 1).unwrap();
    let out = mk_vn(fd, out_off, out_size);
    fd.op_set_output(op, out).unwrap();
    fd.op_insert_end(op, bl);
    out
}

/// `out = COPY(a)` (used to make a written input that may have many readers).
fn copy(fd: &mut Funcdata, bl: BlockId, off: u64, a: VarnodeId, out_off: u64, size: int4) -> VarnodeId {
    let op = mk_op(fd, 1, off, OpCode::CPUI_COPY);
    fd.op_set_input(op, a, 0).unwrap();
    let out = mk_vn(fd, out_off, size);
    fd.op_set_output(op, out).unwrap();
    fd.op_insert_end(op, bl);
    out
}

// =============================================================================
// Hash field encoding
// =============================================================================

#[test]
fn transtable_lumps_variants() {
    // NOT_EQUAL hashes same as EQUAL.
    assert_eq!(
        TRANSTABLE[OpCode::CPUI_INT_NOTEQUAL as usize],
        TRANSTABLE[OpCode::CPUI_INT_EQUAL as usize]
    );
    // SUB hashes same as ADD.
    assert_eq!(
        TRANSTABLE[OpCode::CPUI_INT_SUB as usize],
        TRANSTABLE[OpCode::CPUI_INT_ADD as usize]
    );
    // PTRADD / PTRSUB hash same as INT_ADD.
    assert_eq!(
        TRANSTABLE[OpCode::CPUI_PTRADD as usize],
        TRANSTABLE[OpCode::CPUI_INT_ADD as usize]
    );
    assert_eq!(
        TRANSTABLE[OpCode::CPUI_PTRSUB as usize],
        TRANSTABLE[OpCode::CPUI_INT_ADD as usize]
    );
    // CAST is skipped (0).
    assert_eq!(TRANSTABLE[OpCode::CPUI_CAST as usize], 0);
    // SLESSEQUAL hashes as SLESS, LESSEQUAL as LESS, INT_LEFT as INT_MULT.
    assert_eq!(
        TRANSTABLE[OpCode::CPUI_INT_SLESSEQUAL as usize],
        TRANSTABLE[OpCode::CPUI_INT_SLESS as usize]
    );
    assert_eq!(
        TRANSTABLE[OpCode::CPUI_INT_LESSEQUAL as usize],
        TRANSTABLE[OpCode::CPUI_INT_LESS as usize]
    );
    assert_eq!(
        TRANSTABLE[OpCode::CPUI_INT_LEFT as usize],
        TRANSTABLE[OpCode::CPUI_INT_MULT as usize]
    );
    // The table has exactly CPUI_MAX (75) entries (index 0..=74).
    assert_eq!(TRANSTABLE.len(), OpCode::CPUI_MAX as usize);
}

#[test]
fn hash_field_accessors_roundtrip() {
    // Manually pack a hash the way pieceTogetherHash does and read every field.
    // attachedop=false (=> isNotAttached true), method=2, opcode=INT_ADD,
    // slot=1, neighborhood reg = 0xdead_beef.
    let method: u64 = 2;
    let opc: u64 = TRANSTABLE[OpCode::CPUI_INT_ADD as usize] as u64;
    let slot: u64 = 1;
    let reg: u64 = 0xdead_beef;
    let mut h: u64 = 1; // attachedop ? 0 : 1  -> not attached
    h <<= 4;
    h |= method;
    h <<= 7;
    h |= opc;
    h <<= 5;
    h |= slot & 0x1f;
    h <<= 32;
    h |= reg;

    assert_eq!(DynamicHash::get_method_from_hash(h), 2);
    assert_eq!(DynamicHash::get_op_code_from_hash(h), opc as u32);
    assert_eq!(DynamicHash::get_slot_from_hash(h), 1);
    assert!(DynamicHash::get_is_not_attached(h));
    assert_eq!(DynamicHash::get_comparable(h), reg as u32);
}

#[test]
fn slot_31_decodes_as_minus_one() {
    // A slot field of 0x1f (31) is the output marker -> -1.
    let h: u64 = (31u64) << 32;
    assert_eq!(DynamicHash::get_slot_from_hash(h), -1);
}

#[test]
fn total_and_position_pack_and_clear() {
    // total field stores (count-1); getTotalFromHash adds 1 back.
    // Build hash with pos=3, total-field=5 (=> 6 collisions).
    let base: u64 = 0x1234_5678;
    let pos: u64 = 3;
    let totalfield: u64 = 5;
    let h = base | (pos << 49) | (totalfield << 52);
    assert_eq!(DynamicHash::get_position_from_hash(h), 3);
    assert_eq!(DynamicHash::get_total_from_hash(h), 6);
    // clearTotalPosition wipes bits 49..=54 (the 6-bit total+position field).
    let mut h2 = h;
    DynamicHash::clear_total_position(&mut h2);
    assert_eq!(DynamicHash::get_position_from_hash(h2), 0);
    // total-field now 0 -> getTotalFromHash returns 1.
    assert_eq!(DynamicHash::get_total_from_hash(h2), 1);
    // The low bits below 49 are preserved.
    assert_eq!(h2 & 0x1_ffff_ffff_ffff, base & 0x1_ffff_ffff_ffff);
}

// =============================================================================
// calcHash determinism / invariance
// =============================================================================

/// Build `c = a + b` with `a`,`b` distinct ram inputs; return (fd, bl, a, b, c).
fn build_add_graph() -> (Funcdata, BlockId, VarnodeId, VarnodeId, VarnodeId) {
    let mut fd = build_fd();
    let bl = mk_block(&mut fd);
    // a,b are written (COPY of a constant) so c is a normal data-flow node.
    let ca = fd.new_constant(8, 0x11);
    let a = copy(&mut fd, bl, 0x10, ca, 0x100, 8);
    let cb = fd.new_constant(8, 0x22);
    let b = copy(&mut fd, bl, 0x14, cb, 0x108, 8);
    let c = binop(&mut fd, bl, 0x18, OpCode::CPUI_INT_ADD, a, b, 0x110, 8);
    (fd, bl, a, b, c)
}

#[test]
fn calc_hash_is_deterministic() {
    let (mut fd, _bl, _a, _b, c) = build_add_graph();
    let mut dh1 = DynamicHash::new();
    dh1.calc_hash(c, 0, &mut fd);
    let h1 = dh1.get_hash();
    let addr1 = dh1.get_address().clone();

    let mut dh2 = DynamicHash::new();
    dh2.calc_hash(c, 0, &mut fd);
    let h2 = dh2.get_hash();
    let addr2 = dh2.get_address().clone();

    assert_eq!(h1, h2, "same varnode + method => same hash");
    assert_eq!(addr1, addr2);
    assert_ne!(h1, 0, "a well-formed root yields a nonzero hash");
}

#[test]
fn calc_hash_distinguishes_distinct_roots() {
    let (mut fd, _bl, a, _b, c) = build_add_graph();
    let mut dh = DynamicHash::new();
    dh.calc_hash(c, 0, &mut fd);
    let hc = dh.get_hash();
    dh.clear();
    dh.calc_hash(a, 0, &mut fd);
    let ha = dh.get_hash();
    assert_ne!(hc, ha, "distinct roots in distinct positions hash differently");
}

#[test]
fn calc_hash_marks_are_cleared_after() {
    // pieceTogetherHash must clear every scratch mark; a second hash of the same
    // node must therefore reproduce the first exactly (no leftover marks skew
    // the sub-graph walk).
    let (mut fd, _bl, _a, _b, c) = build_add_graph();
    let mut dh = DynamicHash::new();
    dh.calc_hash(c, 1, &mut fd); // method 1 grows the sub-graph (more marks)
    let first = dh.get_hash();
    dh.clear();
    dh.calc_hash(c, 1, &mut fd);
    let second = dh.get_hash();
    assert_eq!(first, second);
}

#[test]
fn calc_hash_invariant_under_interposed_cast() {
    // Two graphs that differ only by a CAST on the path to the root hash the
    // same, because TRANSTABLE skips CAST (buildVnUp/buildVnDown peel it).
    // Graph 1: c = a + b ; root = the value read by a downstream COPY of c.
    let (mut fd, bl, _a, _b, c) = build_add_graph();
    let _d = copy(&mut fd, bl, 0x20, c, 0x118, 8); // c has a reader
    let mut dh = DynamicHash::new();
    dh.calc_hash(c, 0, &mut fd);
    let no_cast = dh.get_hash();

    // Graph 2: identical but with a CAST interposed between c and its reader.
    let mut fd2 = build_fd();
    let bl2 = mk_block(&mut fd2);
    let ca = fd2.new_constant(8, 0x11);
    let a2 = copy(&mut fd2, bl2, 0x10, ca, 0x100, 8);
    let cb = fd2.new_constant(8, 0x22);
    let b2 = copy(&mut fd2, bl2, 0x14, cb, 0x108, 8);
    let c2 = binop(&mut fd2, bl2, 0x18, OpCode::CPUI_INT_ADD, a2, b2, 0x110, 8);
    // CAST(c2) -> cast_out, then COPY(cast_out)
    let cast = mk_op(&mut fd2, 1, 0x1c, OpCode::CPUI_CAST);
    fd2.op_set_input(cast, c2, 0).unwrap();
    let cast_out = mk_vn(&mut fd2, 0x130, 8);
    fd2.op_set_output(cast, cast_out).unwrap();
    fd2.op_insert_end(cast, bl2);
    let _d2 = copy(&mut fd2, bl2, 0x20, cast_out, 0x118, 8);

    let mut dh2 = DynamicHash::new();
    dh2.calc_hash(c2, 0, &mut fd2);
    let with_cast = dh2.get_hash();

    assert_eq!(no_cast, with_cast, "CAST on the read path is invisible to the hash");
}

// =============================================================================
// uniqueHash + findVarnode round-trip
// =============================================================================

#[test]
fn unique_hash_then_find_roundtrips() {
    let (mut fd, _bl, _a, _b, c) = build_add_graph();
    let mut dh = DynamicHash::new();
    // narrow (default) budget 8.
    dh.unique_hash(c, 8, &mut fd);
    let h = dh.get_hash();
    let addr = dh.get_address().clone();
    assert_ne!(h, 0, "a distinguishable varnode gets a unique hash");

    // The encoded method/total/position are within range.
    let method = DynamicHash::get_method_from_hash(h);
    assert!(method < 4, "varnode hashes use methods 0..3");
    let total = DynamicHash::get_total_from_hash(h);
    assert!((1..=8).contains(&total), "collision total within the budget");

    // findVarnode must recover exactly `c`.
    let mut finder = DynamicHash::new();
    let found = finder.find_varnode(&mut fd, &addr, h);
    assert_eq!(found, Some(c), "findVarnode round-trips the unique hash");
}

#[test]
fn unique_hash_position_zero_for_singleton() {
    // `c` is the only INT_ADD output at its address, so the collision list has
    // size 1: total field encodes 0 (getTotalFromHash == 1) and position 0.
    let (mut fd, _bl, _a, _b, c) = build_add_graph();
    let mut dh = DynamicHash::new();
    dh.unique_hash(c, 8, &mut fd);
    let h = dh.get_hash();
    assert_ne!(h, 0);
    assert_eq!(DynamicHash::get_total_from_hash(h), 1, "singleton => total 1");
    assert_eq!(DynamicHash::get_position_from_hash(h), 0, "singleton => pos 0");
}

#[test]
fn wide_budget_matches_narrow_when_no_overflow() {
    // With no real >8 collision, the 16-budget and 8-budget hashes are identical
    // (the cap only matters when a collision list overflows the narrow budget).
    let (mut fd, _bl, _a, _b, c) = build_add_graph();
    let mut narrow = DynamicHash::new();
    narrow.unique_hash(c, 8, &mut fd);
    let hn = narrow.get_hash();
    let mut wide = DynamicHash::new();
    wide.unique_hash(c, 16, &mut fd);
    let hw = wide.get_hash();
    assert_eq!(hn, hw, "no overflow => budget choice is invisible");
}

// =============================================================================
// Collision handling (multiple identical-shape roots at one address)
// =============================================================================

/// Build N INT_ADD ops at the SAME address, each `out_i = a + b` over shared
/// written inputs, producing N structurally-identical outputs that collide.
fn build_collision_graph(n: usize) -> (Funcdata, Vec<VarnodeId>) {
    let mut fd = build_fd();
    let bl = mk_block(&mut fd);
    let ca = fd.new_constant(8, 0x11);
    let a = copy(&mut fd, bl, 0x10, ca, 0x100, 8);
    let cb = fd.new_constant(8, 0x22);
    let b = copy(&mut fd, bl, 0x14, cb, 0x108, 8);
    let mut outs = Vec::new();
    // All ADDs share the SAME instruction address (0x18) but distinct unique
    // outputs, so they collide on address+shape.
    for i in 0..n {
        let op = mk_op(&mut fd, 2, 0x18, OpCode::CPUI_INT_ADD);
        fd.op_set_input(op, a, 0).unwrap();
        fd.op_set_input(op, b, 1).unwrap();
        let out = mk_vn(&mut fd, 0x200 + (i as u64) * 8, 8);
        fd.op_set_output(op, out).unwrap();
        fd.op_insert_end(op, bl);
        outs.push(out);
    }
    (fd, outs)
}

#[test]
fn colliding_roots_get_distinct_positions() {
    // Three identical-shape ADD outputs at one address: uniqueHash must encode a
    // collision list (total >= the count) and assign each a distinct position;
    // findVarnode recovers each by its position.
    let (mut fd, outs) = build_collision_graph(3);
    let mut hashes = Vec::new();
    for &vn in &outs {
        let mut dh = DynamicHash::new();
        dh.unique_hash(vn, 8, &mut fd);
        let h = dh.get_hash();
        assert_ne!(h, 0, "each colliding root still gets a hash within budget");
        hashes.push((vn, h, dh.get_address().clone()));
    }
    // The formal (comparable) hashes collide, but position fields differ.
    let positions: Vec<u32> =
        hashes.iter().map(|(_, h, _)| DynamicHash::get_position_from_hash(*h)).collect();
    let mut sorted = positions.clone();
    sorted.sort_unstable();
    sorted.dedup();
    assert_eq!(sorted.len(), positions.len(), "distinct positions per colliding root");
    // total reflects the collision-list size (3).
    for (_, h, _) in &hashes {
        assert_eq!(DynamicHash::get_total_from_hash(*h), 3);
    }
    // findVarnode round-trips each.
    for (vn, h, addr) in &hashes {
        let mut finder = DynamicHash::new();
        assert_eq!(finder.find_varnode(&mut fd, addr, *h), Some(*vn));
    }
}

#[test]
fn budget_cap_bounds_total_field() {
    // The collision total is encoded in 3 bits (+1) => max representable 8.  Even
    // under the wide budget the position/total fields stay within their bit
    // widths; here we assert getTotalFromHash never exceeds the chosen budget.
    let (mut fd, outs) = build_collision_graph(4);
    for &vn in &outs {
        let mut dh = DynamicHash::new();
        dh.unique_hash(vn, 8, &mut fd);
        let h = dh.get_hash();
        if h != 0 {
            assert!(DynamicHash::get_total_from_hash(h) <= 8);
        }
    }
}

// =============================================================================
// ToOpEdge ordering
// =============================================================================

#[test]
fn toopedge_orders_by_seqnum_then_slot() {
    // Two edges at different op addresses: the lower address sorts first.
    let (mut fd, bl, a, b, _c) = build_add_graph();
    // op at 0x30 reading a, op at 0x40 reading b.
    let op_lo = mk_op(&mut fd, 1, 0x30, OpCode::CPUI_COPY);
    fd.op_set_input(op_lo, a, 0).unwrap();
    let out_lo = mk_vn(&mut fd, 0x310, 8);
    fd.op_set_output(op_lo, out_lo).unwrap();
    fd.op_insert_end(op_lo, bl);

    let op_hi = mk_op(&mut fd, 1, 0x40, OpCode::CPUI_COPY);
    fd.op_set_input(op_hi, b, 0).unwrap();
    let out_hi = mk_vn(&mut fd, 0x318, 8);
    fd.op_set_output(op_hi, out_hi).unwrap();
    fd.op_insert_end(op_hi, bl);

    let e_lo = ToOpEdge::new(op_lo, 0);
    let e_hi = ToOpEdge::new(op_hi, 0);
    assert!(e_lo.less_than(&e_hi, &fd), "lower op address sorts first");
    assert!(!e_hi.less_than(&e_lo, &fd));

    // Same op, different slot: smaller slot sorts first.
    let e0 = ToOpEdge::new(op_lo, -1);
    let e1 = ToOpEdge::new(op_lo, 0);
    assert!(e0.less_than(&e1, &fd), "slot -1 < slot 0 at the same op");
}

#[test]
fn empty_subgraph_hashes_to_zero() {
    // calcHash on a free, undescended varnode produces no edges => hash 0.
    let mut fd = build_fd();
    let _bl = mk_block(&mut fd);
    let lone = mk_vn(&mut fd, 0x500, 8); // free, no def, no readers
    let mut dh = DynamicHash::new();
    dh.calc_hash(lone, 0, &mut fd);
    assert_eq!(dh.get_hash(), 0u64, "no edges => zero hash");
    let zero: uint8 = 0;
    assert_eq!(dh.get_hash(), zero);
}

#[test]
fn unique_hash_preserves_the_descriptor_of_the_best_collision_method() {
    let mut manager = build_manager(false);
    manager.insert_space(Rc::new(kuna_base::space::IopSpace::new(3))).unwrap();
    let mut context = ArchContext::new(manager);
    let types = crate::dtype::TypeFactoryImpl::new();
    types.set_default_alignment_map();
    types.set_max_basetype_size(8);
    context.types = Some(Rc::new(types));
    let arch = Rc::new(context);
    let memory = Rc::clone(arch.manage().get_space_by_name("ram").unwrap());
    let mut fd = Funcdata::new(
        "collision_methods", "collision_methods", arch,
        Address::new(memory, 0x1000), 0x10000000, 0x40,
    ).unwrap();
    let block = mk_block(&mut fd);
    let target = mk_op(&mut fd, 1, 0x80, OpCode::CPUI_CALL);
    let destination = fd.new_constant(8, 0x2000);
    fd.op_set_input(target, destination, 0).unwrap();
    fd.op_insert_end(target, block);
    let mut roots = Vec::new();
    for i in 0..9 {
        let root = mk_vn(&mut fd, 0x100 + i * 8, 8);
        let root = fd.set_input_varnode(root).unwrap();
        roots.push(root);
        let op = mk_op(&mut fd, 2, 0x10, OpCode::CPUI_INDIRECT);
        fd.op_set_input(op, root, 0).unwrap();
        let reference = fd.new_varnode_iop(target);
        fd.op_set_input(op, reference, 1).unwrap();
        let output = mk_vn(&mut fd, 0x200 + i * 8, 8);
        fd.op_set_output(op, output).unwrap();
        fd.op_insert_end(op, block);
        let consumer_pc = if i < 8 { 0x20 } else { 0x30 };
        copy(&mut fd, block, consumer_pc, output, 0x300 + i * 8, 8);
    }
    let mut collisions = Vec::new();
    for method in 0..4 {
        let mut probe = DynamicHash::new();
        probe.calc_hash(roots[0], method, &mut fd);
        let comparable = DynamicHash::get_comparable(probe.get_hash());
        let mut candidates = Vec::new();
        DynamicHash::gather_first_level_vars(
            &mut candidates, &mut fd, probe.get_address(), probe.get_hash(),
        );
        let count = candidates.into_iter().filter(|candidate| {
            let mut candidate_hash = DynamicHash::new();
            candidate_hash.calc_hash(*candidate, method, &mut fd);
            DynamicHash::get_comparable(candidate_hash.get_hash()) == comparable
        }).count();
        collisions.push(count);
    }
    assert!(collisions[2] > 1 && collisions[2] < collisions[3],
        "fixture must select an earlier non-singleton neighborhood: {collisions:?}");
    for root in roots {
        let mut hash = DynamicHash::new();
        hash.unique_hash(root, 8, &mut fd);
        let address = hash.get_address().clone();
        assert_eq!(
            DynamicHash::new().find_varnode(&mut fd, &address, hash.get_hash()),
            Some(root),
            "the chosen method/address/CRC and collision position must describe the same neighborhood",
        );
    }
}

#[test]
fn unique_operation_hash_recovers_the_operation_and_operand_slot() {
    let (mut fd, _, _, _, result) = build_add_graph();
    let operation = fd.vbank().get(result).unwrap().get_def().unwrap();
    for slot in [-1, 0, 1] {
        let mut hash = DynamicHash::new();
        hash.unique_hash_op(operation, slot, 8, &mut fd);
        let address = hash.get_address().clone();
        assert_eq!(DynamicHash::new().find_op(&mut fd, &address, hash.get_hash()), Some(operation));
        assert_eq!(DynamicHash::get_slot_from_hash(hash.get_hash()), slot,
            "recovering an operation must not redirect an input annotation to another operand");
    }
}

#[test]
fn unique_operation_hash_retains_an_earlier_collision_winner() {
    let mut fd = build_fd();
    let block = mk_block(&mut fd);
    let constant = fd.new_constant(8, 0x11);
    let other_constant = fd.new_constant(8, 0x22);
    let other = copy(&mut fd, block, 0x08, other_constant, 0x80, 8);
    let mut operations = Vec::new();
    for i in 0..9 {
        let input_pc = if i < 8 { 0x10 } else { 0x14 };
        let input = copy(&mut fd, block, input_pc, constant, 0x100 + i * 8, 8);
        let result = binop(
            &mut fd, block, 0x20, OpCode::CPUI_INT_ADD,
            input, other, 0x200 + i * 8, 8,
        );
        operations.push(fd.vbank().get(result).unwrap().get_def().unwrap());
    }
    let mut collisions = Vec::new();
    for method in 4..7 {
        let mut root_hash = DynamicHash::new();
        root_hash.calc_hash_op(operations[0], -1, method, &mut fd);
        let comparable = DynamicHash::get_comparable(root_hash.get_hash());
        let count = operations.iter().filter(|operation| {
            let mut candidate = DynamicHash::new();
            candidate.calc_hash_op(**operation, -1, method, &mut fd);
            DynamicHash::get_comparable(candidate.get_hash()) == comparable
        }).count();
        collisions.push(count);
    }
    assert!(collisions[1] > 1 && collisions[1] < collisions[2],
        "fixture must select method5 before method6: {collisions:?}");
    for operation in operations {
        let mut hash = DynamicHash::new();
        hash.unique_hash_op(operation, -1, 8, &mut fd);
        let address = hash.get_address().clone();
        assert_eq!(
            DynamicHash::new().find_op(&mut fd, &address, hash.get_hash()), Some(operation),
            "the selected neighborhood and collision position must identify this exact operation",
        );
        assert_eq!(DynamicHash::get_slot_from_hash(hash.get_hash()), -1);
    }
}

#[test]
fn wide_collision_budget_allows_rendering_without_rebinding_oversized_lists() {
    for count in [9, 16] {
        let (mut fd, roots) = build_collision_graph(count);
        for root in roots {
            let mut narrow = DynamicHash::new();
            narrow.unique_hash(root, 8, &mut fd);
            assert_eq!(narrow.get_hash(), 0,
                "the Java-compatible budget must refuse all {count} equivalent roots");
            let mut wide = DynamicHash::new();
            wide.unique_hash(root, 16, &mut fd);
            assert_ne!(wide.get_hash(), 0,
                "the opt-in wider budget must let build_dynamic_symbol continue rendering");
            let address = wide.get_address().clone();
            assert_eq!(
                DynamicHash::new().find_varnode(&mut fd, &address, wide.get_hash()),
                None,
                "an oversized {count}-root descriptor must remain unbound, not choose another root",
            );
        }
    }
}
