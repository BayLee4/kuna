//! (kuna `structdefs`) Type-walk and definition-text tests over factory-owned graphs.

use super::*;
use crate::dtype::{flags, type_metatype, Datatype, TypeFactory, TypeFactoryImpl, TypeField};

fn core(types: &TypeFactoryImpl, size: i32, m: type_metatype, nm: &str) -> TypeRoot {
    let mut t = Datatype::new_with_align(size, -1, m);
    t.name = nm.to_string();
    t.display_name = nm.to_string();
    t.id = Datatype::hash_name(nm);
    t.flags |= flags::coretype;
    types.intern(t).unwrap()
}

fn ptr_to(types: &TypeFactoryImpl, ptrto: TypeRoot) -> TypeRoot {
    let mut p = Datatype::new_with_align(8, -1, type_metatype::TYPE_PTR);
    p.kind = DatatypeKind::Pointer { ptrto: ptrto.id(), spaceid: None, truncate: None, wordsize: 1 };
    types.intern(p).unwrap()
}

fn struct_draft(nm: &str, size: i32, fields: &[(i32, &str, TypeRoot)]) -> Datatype {
    let alignment = fields.iter().map(|(_, _, ty)| ty.get_alignment()).max().unwrap_or(1);
    let mut s = Datatype::new_with_align(size, alignment, type_metatype::TYPE_STRUCT);
    s.align_size = Datatype::calc_align_size(size, alignment);
    s.name = nm.to_string();
    s.display_name = nm.to_string();
    s.id = Datatype::hash_name(nm);
    s.kind = DatatypeKind::Struct {
        field: fields.iter().enumerate()
            .map(|(i, (off, fnm, ft))| TypeField::new(i as i32, *off, *fnm, ft.id()))
            .collect(),
        bitfield: vec![],
    };
    s
}

fn struct_of(types: &TypeFactoryImpl, nm: &str, size: i32, fields: &[(i32, &str, TypeRoot)]) -> TypeRoot {
    types.intern(struct_draft(nm, size, fields)).unwrap()
}

fn opaque(types: &TypeFactoryImpl, nm: &str) -> TypeRoot {
    types.reserve(nm, Datatype::hash_name(nm), type_metatype::TYPE_STRUCT).unwrap()
}

fn walk(roots: &[TypeRoot]) -> Vec<String> {
    let mut seen = HashSet::new();
    let mut order = Vec::new();
    for r in roots {
        visit(r, &mut seen, &mut order);
    }
    order.iter().map(|t| {
        let view = t.read();
        view.get(t.id()).unwrap().get_name().to_string()
    }).collect()
}

/// A pointer parameter reaches the definition of its pointee.
#[test]
fn a_pointer_parameter_pulls_in_its_pointee_struct() {
    let types = TypeFactoryImpl::new();
    let i4 = core(&types, 4, type_metatype::TYPE_INT, "int4");
    let s = struct_of(&types, "struct_0", 16, &[(0, "field_0x0", i4)]);
    assert_eq!(walk(&[ptr_to(&types, s)]), vec!["struct_0".to_string()]);
}

#[test]
fn a_nested_struct_is_ordered_before_the_struct_that_holds_it() {
    let types = TypeFactoryImpl::new();
    let i4 = core(&types, 4, type_metatype::TYPE_INT, "int4");
    let inner = struct_of(&types, "inner", 4, &[(0, "a", i4)]);
    let outer = struct_of(&types, "outer", 16, &[(0, "in", inner.clone()), (8, "p", ptr_to(&types, inner))]);
    assert_eq!(walk(&[outer]), vec!["inner".to_string(), "outer".to_string()]);
}

/// The pointer is published before completion and retains the same nominal node.
#[test]
fn a_pointer_cycle_terminates_with_one_entry_per_type() {
    let types = TypeFactoryImpl::new();
    let node = opaque(&types, "node");
    let selfptr = ptr_to(&types, node.clone());
    types.complete(&node, struct_draft("node", 8, &[(0, "next", selfptr.clone())])).unwrap();
    assert_eq!(selfptr.get_ptr_to().unwrap(), node);
    assert_eq!(walk(&[selfptr]), vec!["node".to_string()]);
}

#[test]
fn callback_only_dependencies_include_inputs_and_recursive_results() {
    use std::rc::Rc;
    use kuna_base::space::AddrSpaceManager;
    use crate::fspec::{LogicalCallable, ProtoModel};

    let types = TypeFactoryImpl::new();
    let integer = core(&types, 4, type_metatype::TYPE_INT, "int4");
    let input = struct_of(&types, "Argument", 4, &[(0, "value", integer)]);
    let result = opaque(&types, "Result");
    let manager = Rc::new(AddrSpaceManager::new());
    let mut model = ProtoModel::new(&manager);
    model.build_param_list("standard").unwrap();
    types.set_proto_context(Some(Rc::new(model)), manager).unwrap();
    let code = types.get_type_code_proto(&LogicalCallable {
        binding: types.model_binding(None).unwrap(),
        output: result.id(),
        inputs: vec![input.id()],
        variadic: false,
        input_closed: true,
        logical_first: None,
        flags: 0,
    }).unwrap();
    let callback = ptr_to(&types, code);
    types.complete(&result, struct_draft("Result", 8, &[(0, "next", callback.clone())])).unwrap();
    let holder = struct_of(&types, "Holder", 8, &[(0, "callback", callback)]);
    let definitions = walk(&[holder]);
    assert_eq!(definitions.last().map(String::as_str), Some("Holder"));
    assert_eq!(definitions.len(), 3);
    assert_eq!(definitions.iter().map(String::as_str).collect::<HashSet<_>>(),
        HashSet::from(["Argument", "Result", "Holder"]));
}

/// Independent retained generations may name the same type. The machine-readable
/// surface reports the complete definition once, without mutating either graph.
#[test]
fn the_complete_definition_wins_one_record_per_name() {
    let earlier = TypeFactoryImpl::new();
    let types = TypeFactoryImpl::new();
    let i4 = core(&types, 4, type_metatype::TYPE_INT, "int4");
    let fwd = opaque(&earlier, "_IO_FILE");
    let full = struct_of(&types, "_IO_FILE", 216, &[(0, "_flags", i4)]);
    let other = opaque(&types, "_IO_marker");
    let out = dedup_by_name(&[fwd, other.clone(), full]);
    let names: Vec<String> = out.iter().map(|t| {
        let view = t.read();
        view.get(t.id()).unwrap().get_name().to_string()
    }).collect();
    assert_eq!(names, vec!["_IO_marker", "_IO_FILE"]);
    assert_eq!(out[1].get_size(), 216);
    assert_eq!(dedup_by_name(&[other.clone()]), vec![other]);
}
