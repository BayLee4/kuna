//! W10 (`w10-union-scoring`) — parity fences for the `ScoreUnionFields` **driver**
//! and the `Funcdata::resolve_in_flow` cache-population path
//! (`decompiler/cpp/unionresolve.cc:135-1223`, `type.cc:1314-2557`).
//!
//! The leaf scoring functions are fenced by `verify_w6_s5_unionresolve.rs`; these
//! tests pin the *driver* that walks a live `Funcdata` graph and writes the winning
//! field into the `unionMap` cache via `resolveInFlow`:
//!
//!   * a union read \e down into a `FLOAT_ADD` resolves to the float field (the
//!     `scoreTrialDown` FLOAT_ADD arm scores `TYPE_FLOAT` = 10, everything else
//!     -10), and the resolution is cached on the read edge;
//!   * a union read \e down into an `INT_ADD` resolves to the int field;
//!   * `resolve_in_flow` on a non-union (plain int) returns the type itself and
//!     writes nothing (the C++ base-body `return this`).

use std::rc::Rc;

use kuna_base::address::Address;
use kuna_base::space::{
    addrspace_flags, spacetype, AddrSpace, AddrSpaceManager, ConstantSpace, FspecSpace, IopSpace,
    UniqueSpace,
};
use kuna_base::types::int4;
use kuna_num::opcodes::OpCode;

use kuna_decomp::dtype::{type_metatype, TypeFactoryImpl, TypeField, TypeRoot};
use kuna_decomp::funcdata::Funcdata;
use kuna_decomp::context::{ArchContext, OpId, TypeOp, VarnodeId};

fn build_manager() -> AddrSpaceManager {
    let mut m = AddrSpaceManager::new();
    m.insert_space(Rc::new(ConstantSpace::new())).unwrap();
    m.insert_space(Rc::new(UniqueSpace::new(1, 0, false))).unwrap();
    m.insert_space(Rc::new(IopSpace::new(2))).unwrap();
    m.insert_space(Rc::new(FspecSpace::new(3))).unwrap();
    m.insert_space(Rc::new(AddrSpace::new(
        spacetype::IPTR_PROCESSOR,
        "ram",
        false,
        8,
        1,
        4,
        addrspace_flags::hasphysical,
        1,
        1,
    )))
    .unwrap();
    m
}

fn build_fd() -> Funcdata {
    let manage = build_manager();
    let mut arch = ArchContext::new(manage);
    let types = TypeFactoryImpl::new();
    types.set_default_alignment_map();
    types.set_max_basetype_size(8);
    arch.types = Some(Rc::new(types));
    let glb = Rc::new(arch);
    let ram = Rc::clone(glb.manage().get_space_by_name("ram").unwrap());
    let addr = Address::new(ram, 0x1000);
    Funcdata::new("func", "func", glb, addr, 0x10000000, 0x40).unwrap()
}

fn ram(fd: &Funcdata) -> Rc<AddrSpace> {
    Rc::clone(fd.get_arch().manage().get_space_by_name("ram").unwrap())
}

fn base(fd: &Funcdata, size: int4, m: type_metatype) -> TypeRoot {
    fd.get_arch().types().unwrap().get_base(size, m).unwrap()
}

/// Publish the union in the same graph as its fields and the function.
fn make_union(fd: &Funcdata, size: int4, fields: &[(int4, TypeRoot)]) -> TypeRoot {
    let types = fd.get_arch().types().unwrap();
    let union = types.get_type_union("scored_union").unwrap();
    let field: Vec<TypeField> = fields
        .iter()
        .enumerate()
        .map(|(i, (off, ct))| TypeField::new(i as int4, *off, format!("f{i}"), ct.id()))
        .collect();
    types.set_fields_union_raw(&union, field, size, 1).unwrap()
}

fn new_op_code(fd: &mut Funcdata, inputs: int4, opc: OpCode, name: &str) -> OpId {
    let pc = Address::new(ram(fd), 0x2000);
    let op = fd.new_op(inputs, pc);
    fd.op_set_opcode(op, TypeOp::new(opc, 0, name));
    op
}

/// Build a Varnode at `ram:off` of `size` bytes (typed `ty`) and wire it as input
/// slot `slot` of `op`.
fn wire_input(fd: &mut Funcdata, op: OpId, slot: int4, off: u64, size: int4, ty: TypeRoot) -> VarnodeId {
    let r = ram(fd);
    let m = Address::new(r, off);
    let vn = fd.new_varnode(size, &m, Some(ty));
    fd.op_set_input(op, vn, slot).unwrap();
    vn
}

// ===========================================================================
// resolve_in_flow on a non-union: base body `return this`, no cache write.
// ===========================================================================

#[test]
fn w10_resolve_in_flow_non_union_is_identity() {
    let mut fd = build_fd();
    let int4t = base(&fd, 4, type_metatype::TYPE_INT);
    let op = new_op_code(&mut fd, 1, OpCode::CPUI_COPY, "COPY");
    let _vn = wire_input(&mut fd, op, 0, 0x100, 4, int4t.clone());
    let r = fd.resolve_in_flow(&int4t, op, 0).unwrap();
    // Base body returns the type itself.
    assert_eq!(r, int4t);
    // Nothing was cached (int4 does not need resolution).
    assert!(fd.get_union_field(&int4t, op, 0).is_none());
}

// ===========================================================================
// A union read down into FLOAT_ADD resolves to the float field & is cached.
// ===========================================================================

#[test]
fn w10_union_resolves_float_field_into_float_add() {
    let mut fd = build_fd();
    let int4t = base(&fd, 4, type_metatype::TYPE_INT);
    let float4t = base(&fd, 4, type_metatype::TYPE_FLOAT);
    // union { int4 f0; float4 f1; } — both at offset 0, size 4.
    let u = make_union(&fd, 4, &[(0, int4t.clone()), (0, float4t.clone())]);

    // FLOAT_ADD reads the union value at slot 0 (down trial -> float scores 10).
    let op = new_op_code(&mut fd, 2, OpCode::CPUI_FLOAT_ADD, "FLOAT_ADD");
    let _u_vn = wire_input(&mut fd, op, 0, 0x200, 4, u.clone());
    let _other = wire_input(&mut fd, op, 1, 0x208, 4, float4t.clone());

    let resolved = fd.resolve_in_flow(&u, op, 0).unwrap();
    // The float field (index 1) wins; resolve dt is the float4 field type.
    assert_eq!(resolved.get_metatype(), type_metatype::TYPE_FLOAT);
    // The resolution is cached on the read edge with field index 1.
    let cached = fd.get_union_field(&u, op, 0).expect("resolution cached on edge");
    assert_eq!(cached.get_field_num(), 1, "FLOAT_ADD resolves to the float field");
    assert_eq!(cached.get_datatype().get_metatype(), type_metatype::TYPE_FLOAT);
}

// ===========================================================================
// The same union read down into INT_ADD resolves to the int field.
// ===========================================================================

#[test]
fn w10_union_resolves_int_field_into_int_add() {
    let mut fd = build_fd();
    let int4t = base(&fd, 4, type_metatype::TYPE_INT);
    let float4t = base(&fd, 4, type_metatype::TYPE_FLOAT);
    let u = make_union(&fd, 4, &[(0, int4t.clone()), (0, float4t.clone())]);

    // INT_ADD reads the union value at slot 0 (the int field scores best; the
    // float field scores -5 in the INT_ADD down arm).
    let op = new_op_code(&mut fd, 2, OpCode::CPUI_INT_ADD, "INT_ADD");
    let _u_vn = wire_input(&mut fd, op, 0, 0x300, 4, u.clone());
    let _other = wire_input(&mut fd, op, 1, 0x308, 4, int4t.clone());

    let resolved = fd.resolve_in_flow(&u, op, 0).unwrap();
    assert_eq!(resolved.get_metatype(), type_metatype::TYPE_INT);
    let cached = fd.get_union_field(&u, op, 0).expect("resolution cached on edge");
    assert_eq!(cached.get_field_num(), 0, "INT_ADD resolves to the int field");
}
