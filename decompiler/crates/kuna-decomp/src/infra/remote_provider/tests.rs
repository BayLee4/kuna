//! Porter in-module tests for `remote_provider.rs`: the `<mapsym>`/`<hole>`
//! decoder against hand-built packed documents (the Java `DecompileCallback`
//! answer shapes), and the wire `<coretypes>` decode equivalence.

use std::rc::Rc;

use kuna_base::address::{Address, ELEM_RANGELIST};
use kuna_base::marshal::{
    Encoder, IdRegistry, PackedEncode, XmlDecode, ATTRIB_CONTENT, ATTRIB_ID, ATTRIB_INDEX,
    ATTRIB_METATYPE, ATTRIB_MODEL, ATTRIB_NAME, ATTRIB_NAMELOCK, ATTRIB_READONLY, ATTRIB_SIZE,
    ATTRIB_TYPELOCK, ELEM_SYMBOL, ELEM_VOID,
};
use kuna_base::space::{addrspace_flags, spacetype, AddrSpace, AddrSpaceManager};

use super::*;
use crate::dtype::type_metatype;
use crate::fspec::{AbiInputOrigin, FirstVarArgCoordinate};

fn manager() -> Rc<AddrSpaceManager> {
    let mut m = AddrSpaceManager::new();
    m.insert_space(Rc::new(AddrSpace::new(
        spacetype::IPTR_PROCESSOR,
        "ram",
        false,
        8,
        1,
        1,
        addrspace_flags::hasphysical,
        1,
        1,
    )))
    .unwrap();
    Rc::new(m)
}

fn types_with_core() -> Rc<TypeFactoryImpl> {
    let t = TypeFactoryImpl::new();
    t.setup_sizes(Some(8), 8, 8);
    t.set_core_type("void", 1, type_metatype::TYPE_VOID, false).unwrap();
    t.set_core_type("int4", 4, type_metatype::TYPE_INT, false).unwrap();
    t.set_core_type("uint8", 8, type_metatype::TYPE_UINT, false).unwrap();
    t.set_core_type("char", 1, type_metatype::TYPE_INT, true).unwrap();
    t.cache_core_types().unwrap();
    Rc::new(t)
}

fn ram(m: &AddrSpaceManager) -> Rc<AddrSpace> {
    Rc::clone(m.get_space_by_name("ram").unwrap())
}

/// `<hole readonly=true space=ram first last/>` decodes to a readonly hole.
#[test]
fn hole_decodes_with_mutability() {
    let m = manager();
    let types = types_with_core();
    let mut doc = Vec::new();
    {
        let mut e = PackedEncode::new(&mut doc);
        e.open_element(&ELEM_HOLE);
        e.write_bool(&ATTRIB_READONLY, true);
        e.write_space(&kuna_base::marshal::ATTRIB_SPACE, &ram(&m));
        e.write_unsigned_integer(&kuna_base::address::ATTRIB_FIRST, 0x1000);
        e.write_unsigned_integer(&kuna_base::address::ATTRIB_LAST, 0x1fff);
        e.close_element(&ELEM_HOLE);
    }
    let mut dec = PackedDecode::new(&m);
    dec.ingest_stream(&doc).unwrap();
    match decode_mapped_answer(&mut dec, &types).unwrap() {
        RemoteMapAnswer::Hole { range, flags } => {
            assert_eq!(range.get_first(), 0x1000);
            assert_eq!(range.get_last(), 0x1fff);
            assert_eq!(flags, varnode_flags::readonly);
        }
        _ => panic!("expected a hole"),
    }
}

/// A data-symbol answer: `<doc id=0><mapsym><symbol …><typeref int4/></symbol>
/// <addr size=4/><rangelist/></mapsym></doc>`.
#[test]
fn data_symbol_mapsym_decodes() {
    let m = manager();
    let types = types_with_core();
    let int4 = crate::dtype::TypeFactory::find_by_name(&*types, "int4")
        .unwrap()
        .unwrap();
    let mut doc = Vec::new();
    {
        let mut e = PackedEncode::new(&mut doc);
        e.open_element(&crate::prettyprint::ids::ELEM_TYPE); // any wrapper id (upstream <doc>)
        e.write_unsigned_integer(&ATTRIB_ID, 0);
        e.open_element(&ELEM_MAPSYM);
        e.open_element(&ELEM_SYMBOL);
        e.write_unsigned_integer(&ATTRIB_ID, 0x1234);
        e.write_string(&ATTRIB_NAME, b"my_global");
        e.write_bool(&ATTRIB_TYPELOCK, true);
        e.write_bool(&ATTRIB_NAMELOCK, true);
        e.write_bool(&ATTRIB_READONLY, true);
        e.write_signed_integer(&ATTRIB_CAT, -1);
        e.open_element(&crate::dtype::ELEM_TYPEREF);
        e.write_string(&ATTRIB_NAME, b"int4");
        e.write_unsigned_integer(&ATTRIB_ID, int4.get_id());
        e.close_element(&crate::dtype::ELEM_TYPEREF);
        e.close_element(&ELEM_SYMBOL);
        Address::new(ram(&m), 0x2000).encode_sized(&mut e, 4).unwrap();
        e.open_element(&ELEM_RANGELIST);
        e.close_element(&ELEM_RANGELIST);
        e.close_element(&ELEM_MAPSYM);
        e.close_element(&crate::prettyprint::ids::ELEM_TYPE);
    }
    let mut dec = PackedDecode::new(&m);
    dec.ingest_stream(&doc).unwrap();
    let rec = match decode_mapped_answer(&mut dec, &types).unwrap() {
        RemoteMapAnswer::Symbol(rec) => rec,
        _ => panic!("expected a symbol"),
    };
    assert_eq!(rec.name, "my_global");
    assert_eq!(rec.symbol_id, 0x1234);
    assert_eq!(
        rec.flags,
        varnode_flags::typelock | varnode_flags::namelock | varnode_flags::readonly
    );
    assert_eq!(rec.dtype.as_ref().unwrap(), &int4);
    assert_eq!(rec.entries.len(), 1);
    assert_eq!(rec.entries[0].addr.get_offset(), 0x2000);
    assert_eq!(rec.entries[0].size, 4);
    assert!(rec.entries[0].uselimit.empty());
    assert!(rec.func.is_none());
}

/// A function answer with `<localdb>` cat-0 params and a `<prototype>`:
/// the noreturn flag and sorted parameters with independent metadata.
#[test]
fn function_mapsym_decodes_prototype_and_params() {
    let m = manager();
    let types = types_with_core();
    let int4 = crate::dtype::TypeFactory::find_by_name(&*types, "int4")
        .unwrap()
        .unwrap();
    let mut doc = Vec::new();
    {
        let mut e = PackedEncode::new(&mut doc);
        e.open_element(&crate::prettyprint::ids::ELEM_TYPE); // the <doc> wrapper
        e.write_unsigned_integer(&ATTRIB_ID, 0);
        e.open_element(&ELEM_MAPSYM);
        e.open_element(&crate::funcdata_encode::ELEM_FUNCTION);
        e.write_unsigned_integer(&ATTRIB_ID, 0x77);
        e.write_string(&ATTRIB_NAME, b"my_exit");
        e.write_signed_integer(&ATTRIB_SIZE, 1);
        e.write_bool(&ATTRIB_NORETURN, true);
        Address::new(ram(&m), 0x3000).encode(&mut e).unwrap();
        // <localdb lock=false main=ram><scope><parent id=0/><rangelist/>
        //   <symbollist> params (index 1 encoded FIRST — the decoder sorts)
        e.open_element(&ELEM_LOCALDB);
        e.write_bool(&ATTRIB_LOCK, false);
        e.write_space(&ATTRIB_MAIN, &ram(&m));
        e.open_element(&ELEM_SCOPE);
        e.write_string(&ATTRIB_NAME, b"my_exit");
        e.open_element(&ELEM_PARENT);
        e.write_unsigned_integer(&ATTRIB_ID, 0);
        e.close_element(&ELEM_PARENT);
        e.open_element(&ELEM_RANGELIST);
        e.close_element(&ELEM_RANGELIST);
        e.open_element(&ELEM_SYMBOLLIST);
        for (idx, pname) in [(1u64, "second"), (0u64, "first")] {
            e.open_element(&ELEM_MAPSYM);
            e.open_element(&ELEM_SYMBOL);
            e.write_string(&ATTRIB_NAME, pname.as_bytes());
            e.write_bool(&ATTRIB_TYPELOCK, true);
            e.write_bool(&ATTRIB_NAMELOCK, true);
            e.write_signed_integer(&ATTRIB_CAT, 0);
            e.write_unsigned_integer(&ATTRIB_INDEX, idx);
            if idx == 0 {
                e.write_bool(&kuna_base::marshal::ATTRIB_HIDDENRETPARM, true);
            }
            e.open_element(&crate::dtype::ELEM_TYPEREF);
            e.write_string(&ATTRIB_NAME, b"int4");
            e.write_unsigned_integer(&ATTRIB_ID, int4.get_id());
            e.close_element(&crate::dtype::ELEM_TYPEREF);
            e.close_element(&ELEM_SYMBOL);
            e.open_element(&ELEM_HASH);
            e.write_unsigned_integer(&kuna_base::marshal::ATTRIB_VAL, 1);
            e.close_element(&ELEM_HASH);
            e.open_element(&ELEM_RANGELIST);
            e.close_element(&ELEM_RANGELIST);
            e.close_element(&ELEM_MAPSYM);
        }
        e.close_element(&ELEM_SYMBOLLIST);
        e.close_element(&ELEM_SCOPE);
        e.close_element(&ELEM_LOCALDB);
        // <prototype extrapop="unknown" model="default"><returnsym><addr/><void/>
        e.open_element(&ELEM_PROTOTYPE);
        e.write_string(&ATTRIB_EXTRAPOP, b"unknown");
        e.write_string(&ATTRIB_MODEL, b"default");
        e.write_bool(&ATTRIB_CUSTOM, true);
        e.open_element(&ELEM_RETURNSYM);
        e.write_bool(&ATTRIB_TYPELOCK, true);
        Address::new(ram(&m), 0x88).encode_sized(&mut e, 1).unwrap();
        e.open_element(&ELEM_VOID);
        e.close_element(&ELEM_VOID);
        e.close_element(&ELEM_RETURNSYM);
        e.close_element(&ELEM_PROTOTYPE);
        e.close_element(&crate::funcdata_encode::ELEM_FUNCTION);
        // The mapping SymbolEntry.
        Address::new(ram(&m), 0x3000).encode_sized(&mut e, 1).unwrap();
        e.open_element(&ELEM_RANGELIST);
        e.close_element(&ELEM_RANGELIST);
        e.close_element(&ELEM_MAPSYM);
        e.close_element(&crate::prettyprint::ids::ELEM_TYPE);
    }
    let mut dec = PackedDecode::new(&m);
    dec.ingest_stream(&doc).unwrap();
    let rec = match decode_mapped_answer(&mut dec, &types).unwrap() {
        RemoteMapAnswer::Symbol(rec) => rec,
        _ => panic!("expected a symbol"),
    };
    let func = rec.func.as_ref().expect("function record");
    assert_eq!(func.name, "my_exit");
    assert!(func.no_return);
    assert_eq!(func.entry.get_offset(), 0x3000);
    let proto = func.proto.as_ref().expect("prototype decoded");
    assert_eq!(proto.model, "default");
    assert_eq!(proto.extrapop, None); // the "unknown" string form
    assert!(proto.custom);
    assert_eq!(proto.out_storage.get_offset(), 0x88);
    assert!(proto.out_lock);
    assert!(proto.out_type.as_ref().unwrap().get_metatype() == type_metatype::TYPE_VOID);
    assert!(proto.is_input_locked());
    // Sorted by slot index despite reversed wire order.
    assert_eq!(proto.params.len(), 2);
    assert_eq!(proto.params[0].name, "first");
    assert_ne!(proto.params[0].flags & parameter_pieces_flags::HIDDENRETPARM, 0);
    assert_eq!(proto.params[1].name, "second");
    assert_eq!(proto.params[1].flags & parameter_pieces_flags::HIDDENRETPARM, 0);
}

/// `<parent>` namespace-path decode: root skipped, innermost-first order.
#[test]
fn namespace_path_decodes_innermost_first() {
    let m = manager();
    let mut doc = Vec::new();
    {
        let mut e = PackedEncode::new(&mut doc);
        e.open_element(&ELEM_PARENT);
        for (id, nm) in [(0u64, ""), (10, "outer"), (11, "inner")] {
            e.open_element(&kuna_base::marshal::ELEM_VAL);
            e.write_unsigned_integer(&ATTRIB_ID, id);
            e.write_string(&ATTRIB_CONTENT, nm.as_bytes());
            e.close_element(&kuna_base::marshal::ELEM_VAL);
        }
        e.close_element(&ELEM_PARENT);
    }
    let mut dec = PackedDecode::new(&m);
    dec.ingest_stream(&doc).unwrap();
    let path = decode_namespace_path(&mut dec).unwrap();
    assert_eq!(path, vec!["inner".to_string(), "outer".to_string()]);
}

/// The wire `<coretypes>` XML mirror of the default core-type list decodes to
/// the SAME (name, id, size, metatype) set `set_core_type` builds — the
/// invariant that makes sim-side `<typeref>` name+id resolution agree.
#[test]
fn coretypes_xml_mirror_matches_default_build() {
    const DEFAULTS: &[(&str, i32, type_metatype, bool)] = &[
        ("void", 1, type_metatype::TYPE_VOID, false),
        ("bool", 1, type_metatype::TYPE_BOOL, false),
        ("uint1", 1, type_metatype::TYPE_UINT, false),
        ("uint2", 2, type_metatype::TYPE_UINT, false),
        ("uint4", 4, type_metatype::TYPE_UINT, false),
        ("uint8", 8, type_metatype::TYPE_UINT, false),
        ("int1", 1, type_metatype::TYPE_INT, false),
        ("int2", 2, type_metatype::TYPE_INT, false),
        ("int4", 4, type_metatype::TYPE_INT, false),
        ("int8", 8, type_metatype::TYPE_INT, false),
        ("float4", 4, type_metatype::TYPE_FLOAT, false),
        ("float8", 8, type_metatype::TYPE_FLOAT, false),
        ("float10", 10, type_metatype::TYPE_FLOAT, false),
        ("float16", 16, type_metatype::TYPE_FLOAT, false),
        ("xunknown1", 1, type_metatype::TYPE_UNKNOWN, false),
        ("xunknown2", 2, type_metatype::TYPE_UNKNOWN, false),
        ("xunknown4", 4, type_metatype::TYPE_UNKNOWN, false),
        ("xunknown8", 8, type_metatype::TYPE_UNKNOWN, false),
        ("code", 1, type_metatype::TYPE_CODE, false),
        ("char", 1, type_metatype::TYPE_INT, true),
        ("wchar2", 2, type_metatype::TYPE_INT, true),
        ("wchar4", 4, type_metatype::TYPE_INT, true),
    ];
    // The XML mirror (no id attributes -> hash_name ids, like set_core_type).
    let mut xml = String::from("<coretypes>");
    for (name, size, meta, chartp) in DEFAULTS {
        let ms = crate::dtype::metatype2string(if *chartp {
            type_metatype::TYPE_INT
        } else {
            *meta
        })
        .unwrap();
        xml.push_str(&format!("<type name=\"{name}\" size=\"{size}\" metatype=\"{ms}\""));
        if *chartp && *size == 1 {
            xml.push_str(" char=\"true\"");
        } else if *chartp {
            xml.push_str(" utf=\"true\"");
        }
        xml.push_str("/>");
    }
    xml.push_str("</coretypes>");

    let reference = TypeFactoryImpl::new();
    reference.setup_sizes(Some(8), 8, 8);
    for (name, size, meta, chartp) in DEFAULTS {
        reference.set_core_type(name, *size, *meta, *chartp).unwrap();
    }
    reference.cache_core_types().unwrap();

    let decoded = TypeFactoryImpl::new();
    decoded.setup_sizes(Some(8), 8, 8);
    let m = manager();
    let mut registry = IdRegistry::with_base_ids();
    crate::dtype::register_type_wire_ids(&mut registry);
    let store = kuna_base::xml::xml_tree(xml.as_bytes()).unwrap();
    let root = store.get_root().clone();
    let mut decoder = XmlDecode::new_with_root(&m, &registry, &root, 0);
    decoded.decode_core_types(&mut decoder).unwrap();

    for (name, size, _meta, _chartp) in DEFAULTS {
        let a = crate::dtype::TypeFactory::find_by_name(&reference, name)
            .unwrap()
            .unwrap_or_else(|| panic!("reference missing {name}"));
        let b = crate::dtype::TypeFactory::find_by_name(&decoded, name)
            .unwrap()
            .unwrap_or_else(|| panic!("decoded missing {name}"));
        assert_eq!(a.get_id(), b.get_id(), "{name}: id mismatch");
        // (void's interned size is the TypeVoid-internal 0 on both sides, so
        // compare a-vs-b rather than against the table.)
        assert_eq!(a.get_size(), b.get_size(), "{name}: size mismatch");
        assert_eq!(a.get_metatype(), b.get_metatype(), "{name}: metatype mismatch");
        assert!(b.is_core_type(), "{name}: decoded type not core");
        let _ = size;
    }
}

/// A REAL Java-side getMappedSymbols function answer, captured from stock
/// Ghidra 12.1.2 via DecompInterface.enableDebug on `fmt`'s `main`
/// (tests/ghidra rig; the `<xml_savefile>` records the
/// actual DecompileCallback encode).  Trimmed verbatim except for the added
/// `<doc id="0x0">` wrapper (the savefile stores answers unwrapped).  This is
/// the ground-truth shape check for the decoder: hex-form attribute values,
/// integer-form extrapop, register-storage entries with first-use rangelists,
/// inline nested pointer types with builtin 0xC… ids.
const CAPTURED_MAIN_MAPSYM: &str = r#"<doc id="0x0"><mapsym>
  <function id="0x18b" name="main" size="1">
    <addr space="ram" offset="0x101900"/>
    <localdb lock="false" main="stack">
      <scope name="main">
        <parent id="0x0"/>
        <rangelist/>
        <symbollist>
          <mapsym>
            <symbol id="0x1e0" name="argc" typelock="true" namelock="true" merge="false" cat="0" index="0x0">
              <type name="int" id="0xc000000000000095" metatype="int" size="4"/>
            </symbol>
            <addr space="register" offset="0x38" size="4"/>
            <rangelist>
              <range space="ram" first="0x1018ff" last="0x1018ff"/>
            </rangelist>
          </mapsym>
          <mapsym>
            <symbol id="0x1e1" name="argv" typelock="true" namelock="true" merge="false" cat="0" index="0x1">
              <type name="" metatype="ptr" size="8">
                <type name="" metatype="ptr" size="8">
                  <type name="char" id="0xc00000000000007b" metatype="int" size="1" char="true"/>
                </type>
              </type>
            </symbol>
            <addr space="register" offset="0x30" size="8"/>
            <rangelist>
              <range space="ram" first="0x1018ff" last="0x1018ff"/>
            </rangelist>
          </mapsym>
        </symbollist>
      </scope>
    </localdb>
    <prototype extrapop="8" model="__stdcall" modellock="true">
      <returnsym typelock="true">
        <addr space="register" offset="0x0" size="4"/>
        <type name="int" id="0xc000000000000095" metatype="int" size="4"/>
      </returnsym>
    </prototype>
  </function>
  <addr space="ram" offset="0x101900" size="1"/>
  <rangelist/>
</mapsym></doc>"#;

/// The capture's parameters carry `register` storage, so its manager needs the
/// space the plain [`manager`] omits.
fn manager_with_registers() -> Rc<AddrSpaceManager> {
    let mut m = AddrSpaceManager::new();
    m.insert_space(Rc::new(AddrSpace::new(
        spacetype::IPTR_PROCESSOR,
        "ram",
        false,
        8,
        1,
        1,
        addrspace_flags::hasphysical,
        1,
        1,
    )))
    .unwrap();
    m.insert_space(Rc::new(AddrSpace::new(
        spacetype::IPTR_PROCESSOR,
        "register",
        false,
        4,
        1,
        2,
        addrspace_flags::hasphysical,
        0,
        0,
    )))
    .unwrap();
    Rc::new(m)
}

fn decode_function_xml(
    m: &Rc<AddrSpaceManager>,
    types: &TypeFactoryImpl,
    xml: &str,
) -> Box<RemoteSymbolRecord> {
    let mut registry = IdRegistry::with_base_ids();
    register_remote_provider_ids(&mut registry);
    crate::dtype::register_type_wire_ids(&mut registry);
    registry.register_element(&crate::funcdata_encode::ELEM_FUNCTION);
    registry.register_element(&crate::prettyprint::ids::ELEM_TYPE);
    registry.register_attribute(&crate::jumptable::ATTRIB_LABEL);

    let store = kuna_base::xml::xml_tree(xml.as_bytes()).unwrap();
    let root = store.get_root().clone();
    let mut dec = XmlDecode::new_with_root(m, &registry, &root, 0);
    match decode_mapped_answer(&mut dec, types).unwrap() {
        RemoteMapAnswer::Symbol(rec) => rec,
        _ => panic!("expected a symbol"),
    }
}

/// Decode the vendored REAL Java answer (XML form; the packed wire form
/// differs only in the marshaling layer behind `dyn Decoder`).
#[test]
fn captured_java_function_mapsym_decodes() {
    let m = manager_with_registers();
    let types = types_with_core();
    let rec = decode_function_xml(&m, &types, CAPTURED_MAIN_MAPSYM);
    assert_eq!(rec.symbol_id, 0x18b);
    let func = rec.func.as_ref().expect("function record");
    assert_eq!(func.name, "main");
    assert_eq!(func.entry.get_offset(), 0x101900);
    assert!(!func.no_return);
    let proto = func.proto.as_ref().expect("prototype");
    assert_eq!(proto.model, "__stdcall");
    assert_eq!(proto.extrapop, Some(8)); // the integer form
    assert!(proto.out_lock);
    // The capture's builtin "int" carries Java's 0xC… id, interned as its own
    // instance beside any locally-hashed "int" — compare by shape, not identity.
    let out = proto.out_type.as_ref().unwrap();
    assert_eq!(out.read().get(out.id()).unwrap().get_name(), "int");
    assert_eq!(out.get_size(), 4);
    assert_eq!(out.get_metatype(), type_metatype::TYPE_INT);
    assert_eq!(out.get_id(), 0xc000000000000095);
    assert!(proto.is_input_locked());
    assert_eq!(proto.params.len(), 2);
    assert_eq!(proto.params[0].name, "argc");
    let argc_ty = proto.params[0].dtype.as_ref().unwrap();
    assert_eq!(argc_ty, out, "both int refs intern to one graph node");
    assert_eq!(proto.params[1].name, "argv");
    let argv_ty = proto.params[1].dtype.as_ref().unwrap();
    assert_eq!(argv_ty.get_metatype(), type_metatype::TYPE_PTR);
    // The mapping entry (the outer <addr size=1> at the function entry).
    assert_eq!(rec.entries.len(), 1);
    assert_eq!(rec.entries[0].addr.get_offset(), 0x101900);
}

/// Parameter and output storage must reach callers without acquiring or losing
/// locks through declaration assignment or the datatype interner.
#[test]
fn captured_java_params_materialize_with_exact_storage_and_locks() {
    let m = manager_with_registers();
    let types = types_with_core();
    let scope = scope_over(&m, Rc::clone(&types), MockFetch::default());
    scope.materialize(*decode_function_xml(&m, &types, CAPTURED_MAIN_MAPSYM)).unwrap();
    let proto = scope.prototype_at(&Address::new(ram(&m), 0x101900)).unwrap();
    assert!(proto.is_input_locked());
    assert!(proto.is_output_locked());
    assert_eq!(proto.get_output().get_address().get_offset(), 0);
    assert_eq!(proto.get_output().get_size(), 4);
    for (slot, name, offset) in [(0, "argc", 0x38), (1, "argv", 0x30)] {
        let param = proto.get_param(slot).unwrap();
        assert_eq!(param.get_name(), name);
        assert_eq!(param.get_address().get_offset(), offset);
        assert!(param.is_type_locked());
        assert!(param.is_name_locked());
    }
}

#[test]
fn new_host_declarations_use_current_default_without_rebinding_existing_facts() {
    let m = manager_with_registers();
    let types = types_with_core();
    let scope = scope_over(&m, Rc::clone(&types), MockFetch::default());
    let original_model = scope.model_by_name("default").unwrap();
    let original_xml = CAPTURED_MAIN_MAPSYM.replace("__stdcall", "default");
    scope.materialize(*decode_function_xml(&m, &types, &original_xml)).unwrap();
    let original_entry = Address::new(ram(&m), 0x101900);
    let original = scope.prototype_at(&original_entry).unwrap();
    assert!(original.has_matching_model(&original_model));

    let mut replacement = ProtoModel::new(&m);
    replacement.build_param_list("").unwrap();
    replacement.set_name("new_default");
    let replacement = Rc::new(replacement);
    types.set_proto_context(Some(Rc::clone(&replacement)), Rc::clone(&m)).unwrap();
    let next_xml = original_xml.replace("0x101900", "0x101a00");
    scope.materialize(*decode_function_xml(&m, &types, &next_xml)).unwrap();

    let next = scope.prototype_at(&Address::new(ram(&m), 0x101a00)).unwrap();
    assert!(next.has_matching_model(&replacement));
    assert!(scope.prototype_at(&original_entry).unwrap().has_matching_model(&original_model));
    assert!(original.has_matching_model(&original_model));
    for prototype in [&original, &next] {
        assert_eq!(prototype.get_param(0).unwrap().get_address().get_offset(), 0x38);
        assert_eq!(prototype.get_output().get_address().get_offset(), 0);
        assert!(prototype.is_input_locked() && prototype.is_output_locked());
    }
}

/// Same structural signatures must not share function-specific storage, in
/// either fetch order and before any cache flush.
#[test]
fn same_epoch_callees_keep_distinct_storage_in_both_orders() {
    for reverse in [false, true] {
        let m = manager_with_registers();
        let types = types_with_core();
        let scope = Rc::new(scope_over(&m, Rc::clone(&types), MockFetch::default()));
        let custom = |entry: &str, input: &str, output: &str| {
            CAPTURED_MAIN_MAPSYM
                .replace("0x101900", entry)
                .replace("modellock=\"true\"", "modellock=\"true\" custom=\"true\"")
                .replace("offset=\"0x38\"", &format!("offset=\"{input}\""))
                .replace("offset=\"0x0\" size=\"4\"", &format!("offset=\"{output}\" size=\"4\""))
        };
        let mut records = vec![
            (CAPTURED_MAIN_MAPSYM.to_string(), 0x101900, 0x38, 0x00, false),
            (custom("0x101a00", "0x90", "0x10"), 0x101a00, 0x90, 0x10, true),
            (custom("0x101b00", "0x98", "0x08"), 0x101b00, 0x98, 0x08, true),
        ];
        if reverse {
            records.reverse();
        }
        for (xml, ..) in &records {
            scope.materialize(*decode_function_xml(&m, &types, xml)).unwrap();
        }
        let mut ctx = crate::context::ArchContext::new_shared(Rc::clone(&m));
        ctx.remote_scope = Some(Rc::clone(&scope));
        let shared_type = ctx.query_callee_proto(&Address::new(ram(&m), 0x101900))
            .unwrap().unwrap().get_param(0).unwrap().get_type().unwrap().clone();
        for (_, entry, input, output, custom) in &records {
            let entry = Address::new(ram(&m), *entry);
            let direct = ctx.query_callee_proto(&entry).unwrap().unwrap();
            let (_, _, deindirect) = ctx.query_function(&entry).unwrap().unwrap();
            let slot = match ctx.query_indirect_slot_type(&entry, 8, &entry).unwrap().unwrap() {
                crate::context::IndirectSlotType::Prototype(proto) => proto,
                _ => panic!("function slot lost its authoritative prototype"),
            };
            for proto in [direct, deindirect, slot] {
                let param = proto.get_param(0).unwrap();
                assert_eq!(param.get_type().unwrap(), &shared_type);
                assert_eq!(param.get_address().get_space().unwrap().get_name(), "register");
                assert_eq!(param.get_address().get_offset(), *input);
                assert_eq!(param.get_size(), 4);
                assert_eq!(proto.get_output().get_address().get_offset(), *output);
                assert_eq!(proto.get_output().get_size(), 4);
                assert_eq!(proto.has_custom_storage(), *custom);
                let mut recovered = crate::fspec::FuncProto::new();
                recovered.copy(&proto);
                recovered.set_param(0, "recovered", &crate::fspec::ParameterPieces {
                    addr: Address::new(Rc::clone(m.get_space_by_name("register").unwrap()), 0xa0),
                    type_: param.get_type().cloned(),
                    flags: 0,
                });
                recovered.set_output_lock(false);
                let fresh = ctx.query_callee_proto(&entry).unwrap().unwrap();
                assert_eq!(fresh.get_param(0).unwrap().get_name(), "argc");
                assert_eq!(fresh.get_param(0).unwrap().get_address().get_offset(), *input);
                assert!(fresh.get_param(0).unwrap().is_type_locked());
                assert!(fresh.is_output_locked());
            }
            for wrong_width in [4, 16] {
                assert!(matches!(
                    ctx.query_indirect_slot_type(&entry, wrong_width, &entry).unwrap(),
                    Some(crate::context::IndirectSlotType::Untyped)
                ));
            }
        }
        scope.clear();
        let updated = custom("0x101900", "0x90", "0x10");
        scope.materialize(*decode_function_xml(&m, &types, &updated)).unwrap();
        let proto = ctx.query_callee_proto(&Address::new(ram(&m), 0x101900)).unwrap().unwrap();
        assert_eq!(proto.get_param(0).unwrap().get_address().get_offset(), 0x90);
        assert_eq!(proto.get_output().get_address().get_offset(), 0x10);
    }
}

/// Locked inputs must not convert the replay callback state (unlocked void)
/// into locked void. Output-only and genuine locked-void facts are distinct.
#[test]
fn host_input_and_output_locks_remain_independent() {
    let m = manager_with_registers();
    let types = types_with_core();
    let scope = scope_over(&m, Rc::clone(&types), MockFetch::default());
    for (input_lock, output_lock) in [(true, false), (false, true), (true, true), (false, false)] {
        scope.clear();
        let mut rec = *decode_function_xml(&m, &types, CAPTURED_MAIN_MAPSYM);
        let proto = rec.func.as_mut().unwrap().proto.as_mut().unwrap();
        proto.custom = true;
        proto.model_lock = false;
        for param in &mut proto.params {
            param.flags &= !(parameter_pieces_flags::TYPELOCK | parameter_pieces_flags::NAMELOCK);
            if input_lock {
                param.flags |= parameter_pieces_flags::TYPELOCK;
            }
        }
        proto.out_type = Some(types.get_type_void().unwrap());
        proto.out_storage = Address::new_invalid();
        proto.out_lock = output_lock;
        scope.materialize(rec).unwrap();
        let proto = scope.prototype_at(&Address::new(ram(&m), 0x101900)).unwrap();
        assert_eq!(proto.is_input_locked(), input_lock);
        assert_eq!(proto.is_output_locked(), output_lock);
        assert_eq!(proto.is_model_locked(), input_lock || output_lock);
        assert!(!proto.get_param(0).unwrap().is_name_locked());
        assert_eq!(proto.get_param(0).unwrap().get_address().get_offset(), 0x38);
        assert!(proto.get_output().get_address().is_invalid());
        assert_eq!(proto.get_output_type().unwrap().get_metatype(), type_metatype::TYPE_VOID);
    }
}

fn scope_with_override_register_model(
    m: &Rc<AddrSpaceManager>,
    types: Rc<TypeFactoryImpl>,
) -> RemoteScope {
    scope_with_override_result_model(m, types, false)
}

fn scope_with_override_result_model(
    m: &Rc<AddrSpaceManager>,
    types: Rc<TypeFactoryImpl>,
    void_indirect_result: bool,
) -> RemoteScope {
    let registers = Rc::clone(m.get_space_by_name("register").unwrap());
    let mut model = ProtoModel::new(m);
    model.build_param_list("standard").unwrap();
    model.set_name("site_registers");
    model.set_extra_pop(8);
    if void_indirect_result {
        model.input_mut().push_entry(crate::fspec::ParamEntry::seed(
            0, crate::dtype::type_class::TYPECLASS_HIDDENRET,
            Rc::clone(&registers), 0x80, 8, 1, 0, 0, true, false,
            &[], m,
        ).unwrap());
    }
    for (slot, offset) in [0x38, 0x30, 0x10, 0x08].into_iter().enumerate() {
        let entry = crate::fspec::ParamEntry::seed(
            slot as i32 + i32::from(void_indirect_result), crate::dtype::type_class::TYPECLASS_GENERAL,
            Rc::clone(&registers), offset, 8, 1, 0, 0, true, false,
            model.input().get_entry(), m,
        ).unwrap();
        model.input_mut().push_entry(entry);
    }
    model.input_mut().finish_decode();
    let mut registry = IdRegistry::with_base_ids();
    crate::modelrules::register_ids(&mut registry);
    let mut decoder = XmlDecode::new(m, &registry);
    decoder.ingest_stream(
        br#"<rule><datatype name="struct"/><varargs first="0"/><convert_to_ptr/></rule>"#,
    ).unwrap();
    let rule = crate::modelrules::ModelRule::decode(&mut decoder, model.input()).unwrap();
    model.input_mut().push_model_rule(rule);
    model.output_mut().push_entry(crate::fspec::ParamEntry::seed(
        0, crate::dtype::type_class::TYPECLASS_GENERAL,
        registers, 0, 8, 1, 0, 0, true, false, &[], m,
    ).unwrap());
    model.output_mut().finish_decode();
    if void_indirect_result {
        model.output_mut().push_model_rule(crate::modelrules::ModelRule::from_components(
            crate::modelrules::DatatypeFilter::SizeRestricted(
                crate::modelrules::SizeRestriction::new(9, 0),
            ),
            crate::modelrules::AssignAction::HiddenReturnAssign {
                ret_code: crate::fspec::AssignActionResponse::hiddenret_specialreg_void,
            },
        ));
    }
    let model = Rc::new(model);
    types.set_proto_context(Some(Rc::clone(&model)), Rc::clone(m)).unwrap();
    let mut owned = kuna_base::address::RangeList::default();
    owned.insert_range(ram(m), 0, u64::MAX >> 8);
    RemoteScope::new(
        Rc::new(MockFetch::default()), Rc::clone(m), types,
        GlobalQuery::new(Vec::new(), owned, PartMap::default()),
    )
}

#[test]
fn host_closed_internal_override_assigns_three_arguments_without_becoming_variadic() {
    let m = manager_with_registers();
    let types = types_with_core();
    let scope = scope_with_override_register_model(&m, Rc::clone(&types));
    // FunctionPrototype's first boundary is ABI-assignment metadata. The
    // FormatStringAnalyzer closes this signature despite first=1.
    let override_xml = r#"<override><protooverride>
      <addr space="ram" offset="0x101920"/>
      <prototype extrapop="8" model="site_registers" modellock="true">
        <returnsym typelock="true"><addr/><type name="" metatype="int" size="4"/></returnsym>
        <internallist first="1">
          <param name="format" typelock="true" namelock="true"><addr space="register" offset="0x90" size="8"/>
            <type name="" metatype="ptr" size="8"><type name="char" metatype="int" size="1" char="true"/></type>
          </param>
          <param name="count" typelock="true" namelock="false"><addr/>
            <type name="" metatype="int" size="4"/>
          </param>
          <param name="wide" typelock="true" namelock="true"><addr space="register" offset="0x98" size="8"/>
            <type name="" metatype="int" size="8"/>
          </param>
        </internallist>
      </prototype>
    </protooverride></override>"#;
    let xml = CAPTURED_MAIN_MAPSYM.replace("</function>", &format!("{override_xml}</function>"));
    scope.materialize(*decode_function_xml(&m, &types, &xml)).unwrap();
    let facts = scope.function_at(&Address::new(ram(&m), 0x101900)).unwrap();
    let site = Address::new(ram(&m), 0x101920);
    let proto = facts.overrides.find_proto_override(&site).unwrap();
    assert_eq!(proto.get_model_name(), "site_registers");
    assert!(!proto.is_dotdotdot());
    assert_eq!(proto.get_abi_first_vararg(), Some(1));
    assert!(!facts.overrides.is_format_call(&site),
        "host first=1 must not become the standalone analyzer's format-arity marker");
    assert_eq!(proto.num_params(), 3);
    // One unassigned parameter requires ABI assignment of the whole signature,
    // including the two explicitly supplied but non-ABI input locations.
    for (slot, offset, size) in [(0, 0x38, 8), (1, 0x30, 4), (2, 0x10, 8)] {
        let param = proto.get_param(slot).unwrap();
        assert_eq!(param.get_address(), Address::new(
            Rc::clone(m.get_space_by_name("register").unwrap()), offset,
        ));
        assert_eq!(param.get_size(), size);
        assert!(param.is_type_locked());
    }
    assert!(!proto.get_param(1).unwrap().is_name_locked());
    assert!(proto.is_output_locked());
    assert_eq!(proto.get_output().get_address().get_offset(), 0);
    assert_eq!(proto.get_output().get_size(), 4);

    let mut bytes = Vec::new();
    facts.overrides.encode(&mut PackedEncode::new(&mut bytes), &m).unwrap();
    let mut decoder = PackedDecode::new(&m);
    decoder.ingest_stream(&bytes).unwrap();
    let mut restored = crate::overrides::Override::new();
    restored.decode(&mut decoder, &mut |decoder| {
        let decoded = decode_prototype(decoder, &types)?;
        assert_eq!(decoded.internal_first, Some(1),
            "the variadic ABI boundary survives independently of closed recovery arity");
        assert!(!decoded.dotdotdot);
        decoded.to_func_proto(
            scope.model_by_name(&decoded.model).unwrap(), &types, &m,
            FirstVarArgCoordinate::Declared,
        )
    }).unwrap();
    let roundtrip = restored.find_proto_override(&site).unwrap();
    assert_eq!(roundtrip.num_params(), 3);
    assert_eq!(roundtrip.get_abi_first_vararg(), Some(1));
    assert!(!roundtrip.is_dotdotdot());
    assert!(!restored.is_format_call(&site));

    // An explicit open-arity bit, not first, is what permits additional args.
    scope.clear();
    let open = xml.replace(
        "model=\"site_registers\" modellock=\"true\"",
        "model=\"site_registers\" modellock=\"true\" dotdotdot=\"true\"",
    );
    scope.materialize(*decode_function_xml(&m, &types, &open)).unwrap();
    let open_facts = scope.function_at(&Address::new(ram(&m), 0x101900)).unwrap();
    assert!(open_facts.overrides.find_proto_override(&site).unwrap().is_dotdotdot());
    assert!(!proto.is_dotdotdot(), "flush must not mutate the previous immutable caller seed");
}

#[test]
fn closed_internal_abi_boundary_tracks_hidden_return_and_this_inputs() {
    for supplied_hidden in [false, true] {
        let mut m = manager_with_registers();
        Rc::get_mut(&mut m).unwrap().set_default_code_space(1).unwrap();
        let types = types_with_core();
        let scope = scope_with_override_register_model(&m, Rc::clone(&types));
        let hidden = if supplied_hidden {
            r#"<param name="host_return" typelock="true" hiddenretparm="true">
              <addr/><type name="" metatype="ptr" size="8"><type name="void" metatype="void" size="0"/></type>
            </param>"#
        } else { "" };
        // Host boundaries count effective inputs, even if the supplied list
        // omits the automatic result pointer.
        let first = 3;
        let override_xml = format!(r#"<override><protooverride>
          <addr space="ram" offset="0x101920"/>
          <prototype extrapop="8" model="site_registers">
            <returnsym typelock="true"><addr/>
              <type name="Pair" metatype="struct" size="16">
                <field name="left" offset="0"><type name="" metatype="int" size="8"/></field>
                <field name="right" offset="8"><type name="" metatype="int" size="8"/></field>
              </type>
            </returnsym>
            <internallist first="{first}">{hidden}
              <param name="self" typelock="true" thisptr="true"><addr/>
                <type name="" metatype="ptr" size="8"><type name="void" metatype="void" size="0"/></type>
              </param>
              <param name="format" typelock="true"><addr/>
                <type name="" metatype="ptr" size="8"><type name="char" metatype="int" size="1" char="true"/></type>
              </param>
              <param name="value" typelock="true"><addr/><type name="" metatype="int" size="4"/></param>
            </internallist>
          </prototype>
        </protooverride></override>"#);
        let xml = CAPTURED_MAIN_MAPSYM.replace("</function>", &format!("{override_xml}</function>"));
        scope.materialize(*decode_function_xml(&m, &types, &xml)).unwrap();
        let facts = scope.function_at(&Address::new(ram(&m), 0x101900)).unwrap();
        let site = Address::new(ram(&m), 0x101920);
        let mut bytes = Vec::new();
        facts.overrides.encode(&mut PackedEncode::new(&mut bytes), &m).unwrap();
        let mut decoder = PackedDecode::new(&m);
        decoder.ingest_stream(&bytes).unwrap();
        let mut restored = crate::overrides::Override::new();
        restored.decode(&mut decoder, &mut |decoder| {
            let decoded = decode_prototype(decoder, &types)?;
            assert_eq!(decoded.internal_first, Some(3));
            decoded.to_func_proto(
                scope.model_by_name(&decoded.model).unwrap(), &types, &m,
                FirstVarArgCoordinate::Declared,
            )
        }).unwrap();
        for overrides in [&facts.overrides, &restored] {
            let proto = overrides.find_proto_override(&site).unwrap();
            assert_eq!(proto.get_abi_first_vararg(), Some(3));
            assert_eq!(proto.num_params(), 4);
            assert!(!proto.is_dotdotdot());
            assert!(!overrides.is_format_call(&site));
            assert!(proto.get_param(0).unwrap().is_hidden_return());
            assert!(proto.get_param(1).unwrap().is_this_pointer());
            assert_eq!(proto.get_param(1).unwrap().get_name(), "self");
            assert_eq!(proto.get_param(2).unwrap().get_name(), "format");
            assert_eq!(proto.get_param(3).unwrap().get_name(), "value");
            let root = proto.logical_callable().expect("locked aggregate source survives replay");
            let view = root.read();
            let logical = view.get_code_prototype(root.id()).unwrap().unwrap();
            assert_eq!(view.get(logical.output).unwrap().get_metatype(), type_metatype::TYPE_STRUCT);
            assert_eq!(logical.inputs.len(), 3);
            assert_eq!(logical.logical_first, Some(2));
            assert!(logical.variadic && logical.input_closed);
            assert_eq!(proto.callable_input_origins(), &[
                AbiInputOrigin::HiddenResult, AbiInputOrigin::Declared(0),
                AbiInputOrigin::Declared(1), AbiInputOrigin::Declared(2),
            ]);
            for slot in 1..4 {
                assert!(!proto.get_param(slot).unwrap().is_hidden_return());
            }
            let mut copy = crate::fspec::FuncProto::new();
            copy.copy(proto);
            assert_eq!(copy.logical_callable(), proto.logical_callable());
            assert_eq!(copy.callable_input_origins(), proto.callable_input_origins());
            assert_eq!(copy.get_abi_first_vararg(), Some(3));
            copy.set_abi_first_vararg(Some(1));
            assert_eq!(proto.get_abi_first_vararg(), Some(3));
        }
    }
}

const CLOSED_AGGREGATE_OVERRIDE: &str = r#"<override><protooverride>
  <addr space="ram" offset="0x101920"/>
  <prototype extrapop="8" model="site_registers">
    <returnsym typelock="true"><addr/>
      <type name="SiteResult" metatype="struct" size="16">
        <field name="left" offset="0"><type name="" metatype="int" size="8"/></field>
        <field name="right" offset="8"><type name="" metatype="int" size="8"/></field>
      </type>
    </returnsym>
    <internallist first="2">
      <param name="rethidden" typelock="true" namelock="true"><addr/>
        <type name="" metatype="int" size="4"/>
      </param>
      <param name="self" typelock="true" namelock="false"><addr/>
        <type name="SitePayload" metatype="struct" size="16">
          <field name="head" offset="0"><type name="" metatype="int" size="8"/></field>
          <field name="tail" offset="8"><type name="" metatype="int" size="8"/></field>
        </type>
      </param>
    </internallist>
  </prototype>
</protooverride></override>"#;

#[test]
fn special_void_result_preserves_whole_override_input_lock_and_source_on_replay() {
    let mut m = manager_with_registers();
    Rc::get_mut(&mut m).unwrap().set_default_code_space(1).unwrap();
    Rc::get_mut(&mut m).unwrap().set_default_data_space(1).unwrap();
    let types = types_with_core();
    let scope = scope_with_override_result_model(&m, Rc::clone(&types), true);
    let xml = CAPTURED_MAIN_MAPSYM.replace(
        "</function>", &format!("{CLOSED_AGGREGATE_OVERRIDE}</function>"),
    );
    scope.materialize(*decode_function_xml(&m, &types, &xml)).unwrap();
    let facts = scope.function_at(&Address::new(ram(&m), 0x101900)).unwrap();
    let imported = facts.overrides.find_proto_override(&Address::new(ram(&m), 0x101920)).unwrap();
    let source = imported.logical_callable().unwrap().clone();
    let mut bytes = Vec::new();
    imported.encode_internal(&mut PackedEncode::new(&mut bytes)).unwrap();
    let mut decoder = PackedDecode::new(&m);
    decoder.ingest_stream(&bytes).unwrap();
    let decoded = decode_prototype(&mut decoder, &types).unwrap();
    let replay = decoded.to_func_proto(
        scope.model_by_name(&decoded.model).unwrap(), &types, &m,
        FirstVarArgCoordinate::Declared,
    ).unwrap();
    for proto in [imported, &replay] {
        assert!(proto.get_output().get_address().is_invalid());
        assert_eq!(proto.get_output_type().unwrap().get_metatype(), type_metatype::TYPE_VOID);
        assert!(proto.is_output_locked() && proto.get_output().is_indirect_storage());
        assert!(proto.is_input_locked(), "slot-zero hidden result must not unlock the whole call");
        assert_eq!(proto.num_params(), 3);
        assert_eq!(proto.get_abi_first_vararg(), Some(2));
        assert_eq!(proto.logical_callable(), Some(&source));
        assert_eq!(proto.callable_input_origins(), &[
            AbiInputOrigin::HiddenResult, AbiInputOrigin::Declared(0), AbiInputOrigin::Declared(1),
        ]);
        for (slot, offset) in [(0, 0x80), (1, 0x38), (2, 0x30)] {
            let param = proto.get_param(slot).unwrap();
            assert!(param.is_type_locked());
            assert_eq!(param.get_address().get_offset(), offset);
        }
        assert!(proto.get_param(0).unwrap().is_hidden_return());
        assert!(proto.get_param(2).unwrap().is_indirect_storage());
    }
}

#[test]
fn host_closed_aggregate_override_retains_expanded_source_through_abi_and_replay() {
    let mut m = manager_with_registers();
    Rc::get_mut(&mut m).unwrap().set_default_code_space(1).unwrap();
    Rc::get_mut(&mut m).unwrap().set_default_data_space(1).unwrap();
    let types = types_with_core();
    let scope = scope_with_override_register_model(&m, Rc::clone(&types));
    let xml = CAPTURED_MAIN_MAPSYM.replace(
        "</function>", &format!("{CLOSED_AGGREGATE_OVERRIDE}</function>"),
    );
    let mut rec = *decode_function_xml(&m, &types, &xml);
    let supplied = &mut rec.func.as_mut().unwrap().proto_overrides[0].1;
    let payload = supplied.params[1].dtype.clone().unwrap();
    let alias = types.get_typedef(&payload, "SitePayloadAlias", 0, 0).unwrap();
    supplied.params[1].dtype = Some(alias.clone());
    scope.materialize(rec).unwrap();
    let facts = scope.function_at(&Address::new(ram(&m), 0x101900)).unwrap();
    let site = Address::new(ram(&m), 0x101920);
    let imported = facts.overrides.find_proto_override(&site).unwrap();
    let source = imported.logical_callable().expect("fully locked supplied source").clone();
    let mut bytes = Vec::new();
    imported.encode_internal(&mut PackedEncode::new(&mut bytes)).unwrap();
    let mut decoder = PackedDecode::new(&m);
    decoder.ingest_stream(&bytes).unwrap();
    let decoded = decode_prototype(&mut decoder, &types).unwrap();
    let replay = decoded.to_func_proto(
        scope.model_by_name(&decoded.model).unwrap(), &types, &m,
        FirstVarArgCoordinate::Declared,
    ).unwrap();
    for proto in [imported, &replay] {
        assert_eq!(proto.num_params(), 3);
        assert_eq!(proto.get_abi_first_vararg(), Some(2));
        assert!(!proto.is_dotdotdot());
        assert!(proto.is_input_locked() && proto.is_output_locked());
        assert_eq!(proto.logical_callable(), Some(&source));
        assert_eq!(proto.callable_input_origins(), &[
            AbiInputOrigin::HiddenResult, AbiInputOrigin::Declared(0), AbiInputOrigin::Declared(1),
        ]);
        let view = source.read();
        let logical = view.get_code_prototype(source.id()).unwrap().unwrap();
        assert_eq!(logical.logical_first, Some(1));
        assert!(logical.variadic && logical.input_closed);
        assert_eq!(logical.inputs.len(), 2, "retain the expanded optional argument");
        assert_eq!(view.get(logical.output).unwrap().get_name(), "SiteResult");
        assert_eq!(view.get(logical.inputs[0]).unwrap().get_metatype(), type_metatype::TYPE_INT);
        assert_eq!(logical.inputs[1], alias.id());
        assert_eq!(view.get(logical.inputs[1]).unwrap().get_name(), "SitePayloadAlias");
        assert_eq!(alias.get_typedef(), Some(payload.clone()));
        assert_eq!(view.get(logical.inputs[1]).unwrap().get_metatype(), type_metatype::TYPE_STRUCT);
        let hidden = proto.get_param(0).unwrap();
        assert!(hidden.is_hidden_return() && hidden.is_type_locked());
        assert_eq!(hidden.get_type().unwrap().get_ptr_to().unwrap().id(), logical.output);
        let fixed = proto.get_param(1).unwrap();
        assert_eq!(fixed.get_name(), "rethidden");
        assert!(fixed.is_name_locked());
        assert!(!fixed.is_hidden_return(), "names do not declare automatic roles");
        assert_eq!(fixed.get_type().unwrap().id(), logical.inputs[0]);
        let expanded = proto.get_param(2).unwrap();
        assert_eq!(expanded.get_name(), "self");
        assert!(!expanded.is_name_locked() && !expanded.is_this_pointer());
        assert!(expanded.is_indirect_storage(),
            "effective first=2 must become declared first=1 before the varargs rule");
        assert_eq!(expanded.get_type().unwrap().get_ptr_to().unwrap().id(), logical.inputs[1]);
        for (slot, offset, size) in [(0, 0x38, 8), (1, 0x30, 4), (2, 0x10, 8)] {
            let param = proto.get_param(slot).unwrap();
            assert_eq!(param.get_address(), Address::new(
                Rc::clone(m.get_space_by_name("register").unwrap()), offset,
            ));
            assert_eq!(param.get_size(), size);
        }
        assert!(proto.get_output().is_indirect_storage());
        assert_eq!(proto.get_output().get_address().get_offset(), 0);
        assert_eq!(proto.get_output().get_type().unwrap().get_ptr_to().unwrap().id(), logical.output);
    }
    assert!(!facts.overrides.is_format_call(&site));

    // A malformed role cannot turn committed storage into a guessed source.
    let mut incomplete = decoded;
    incomplete.params[0].dtype = Some(types.get_base(8, type_metatype::TYPE_INT).unwrap());
    let incomplete = incomplete.to_func_proto(
        scope.model_by_name(&incomplete.model).unwrap(), &types, &m,
        FirstVarArgCoordinate::Declared,
    ).unwrap();
    assert!(incomplete.logical_callable().is_none());
    assert!(incomplete.callable_input_origins().is_empty());
    assert_eq!(incomplete.num_params(), 3);
    assert_eq!(incomplete.get_param(0).unwrap().get_type().unwrap().get_metatype(), type_metatype::TYPE_INT);
    assert_eq!(incomplete.get_param(0).unwrap().get_address(), imported.get_param(0).unwrap().get_address());
}

#[test]
fn host_unlocked_or_unknown_supplied_aggregate_keeps_facts_without_inventing_source() {
    for (input_lock, output_lock, unknown_input, unknown_output) in [
        (false, true, false, false),
        (true, false, false, false),
        (true, true, true, false),
        (true, true, false, true),
    ] {
        let mut m = manager_with_registers();
        Rc::get_mut(&mut m).unwrap().set_default_code_space(1).unwrap();
        Rc::get_mut(&mut m).unwrap().set_default_data_space(1).unwrap();
        let types = types_with_core();
        let scope = scope_with_override_register_model(&m, Rc::clone(&types));
        let xml = CAPTURED_MAIN_MAPSYM.replace(
            "</function>", &format!("{CLOSED_AGGREGATE_OVERRIDE}</function>"),
        );
        let mut rec = *decode_function_xml(&m, &types, &xml);
        let supplied = &mut rec.func.as_mut().unwrap().proto_overrides[0].1;
        supplied.out_lock = output_lock;
        if !input_lock {
            supplied.params[0].flags &= !parameter_pieces_flags::TYPELOCK;
        }
        if unknown_input {
            supplied.params[0].dtype = Some(types.get_base(4, type_metatype::TYPE_UNKNOWN).unwrap());
        }
        if unknown_output {
            supplied.out_type = Some(types.get_base(16, type_metatype::TYPE_UNKNOWN).unwrap());
        }
        scope.materialize(rec).unwrap();
        let facts = scope.function_at(&Address::new(ram(&m), 0x101900)).unwrap();
        let proto = facts.overrides.find_proto_override(&Address::new(ram(&m), 0x101920)).unwrap();
        assert!(proto.logical_callable().is_none());
        assert!(proto.callable_input_origins().is_empty());
        assert_eq!(proto.num_params(), 3);
        assert_eq!(proto.get_abi_first_vararg(), Some(2));
        assert!(!proto.is_dotdotdot());
        assert_eq!(proto.is_output_locked(), output_lock);
        let fixed = proto.get_param(1).unwrap();
        assert_eq!(fixed.is_type_locked(), input_lock);
        assert_eq!(fixed.get_type().unwrap().get_metatype(), if unknown_input {
            type_metatype::TYPE_UNKNOWN
        } else {
            type_metatype::TYPE_INT
        });
        assert!(proto.get_param(2).unwrap().is_indirect_storage());
        assert_eq!(proto.get_param(2).unwrap().get_address().get_offset(), 0x10);
    }
}

#[test]
fn host_committed_custom_aggregate_preserves_exact_types_storage_and_roles() {
    let m = manager_with_registers();
    let types = types_with_core();
    let scope = scope_with_override_register_model(&m, Rc::clone(&types));
    let xml = CAPTURED_MAIN_MAPSYM.replace(
        "</function>", &format!("{CLOSED_AGGREGATE_OVERRIDE}</function>"),
    );
    let mut rec = *decode_function_xml(&m, &types, &xml);
    let supplied = &mut rec.func.as_mut().unwrap().proto_overrides[0].1;
    supplied.custom = true;
    let register = Rc::clone(m.get_space_by_name("register").unwrap());
    supplied.out_storage = Address::new(Rc::clone(&register), 0x70);
    supplied.params[0].storage = Address::new(Rc::clone(&register), 0x90);
    supplied.params[1].storage = Address::new(Rc::clone(&register), 0x98);
    supplied.params[1].flags |= parameter_pieces_flags::ISTHIS;
    let output_type = supplied.out_type.clone().unwrap();
    let input_types: Vec<_> = supplied.params.iter().map(|p| p.dtype.clone().unwrap()).collect();
    scope.materialize(rec).unwrap();
    let facts = scope.function_at(&Address::new(ram(&m), 0x101900)).unwrap();
    let proto = facts.overrides.find_proto_override(&Address::new(ram(&m), 0x101920)).unwrap();
    assert!(proto.has_custom_storage());
    assert_eq!(proto.num_params(), 2, "committed aggregate result must not add a hidden input");
    assert_eq!(proto.get_abi_first_vararg(), Some(2));
    assert!(!proto.is_dotdotdot());
    assert!(proto.logical_callable().is_none());
    assert!(proto.callable_input_origins().is_empty());
    assert_eq!(proto.get_output().get_type(), Some(&output_type));
    assert_eq!(proto.get_output().get_address(), Address::new(Rc::clone(&register), 0x70));
    assert_eq!(proto.get_output().get_size(), 16);
    assert!(proto.is_output_locked());
    assert!(!proto.get_output().is_indirect_storage());
    for (slot, offset, size, name) in [(0, 0x90, 4, "rethidden"), (1, 0x98, 16, "self")] {
        let param = proto.get_param(slot).unwrap();
        assert_eq!(param.get_type(), Some(&input_types[slot as usize]));
        assert_eq!(param.get_address(), Address::new(Rc::clone(&register), offset));
        assert_eq!(param.get_size(), size);
        assert_eq!(param.get_name(), name);
        assert!(param.is_type_locked());
        assert_eq!(param.is_name_locked(), slot == 0);
        assert_eq!(param.is_this_pointer(), slot == 1);
        assert!(!param.is_hidden_return() && !param.is_indirect_storage());
    }
}

#[test]
fn legacy_internal_return_parameter_is_output_not_an_extra_argument() {
    let m = manager_with_registers();
    let types = types_with_core();
    let scope = scope_with_override_register_model(&m, Rc::clone(&types));
    let override_xml = r#"<override><protooverride>
      <addr space="ram" offset="0x101920"/>
      <prototype extrapop="8" model="site_registers" custom="true">
        <returnsym typelock="false"><addr space="register" offset="0x10" size="4"/>
          <type name="" metatype="int" size="4"/>
        </returnsym>
        <internallist>
          <retparam typelock="true"><addr space="register" offset="0x18" size="8"/>
            <type name="" metatype="int" size="8"/>
          </retparam>
          <param name="argument" typelock="true" namelock="true">
            <addr space="register" offset="0x90" size="4"/>
            <type name="" metatype="int" size="4"/>
          </param>
        </internallist>
      </prototype>
    </protooverride></override>"#;
    let xml = CAPTURED_MAIN_MAPSYM.replace("</function>", &format!("{override_xml}</function>"));
    scope.materialize(*decode_function_xml(&m, &types, &xml)).unwrap();
    let facts = scope.function_at(&Address::new(ram(&m), 0x101900)).unwrap();
    let proto = facts.overrides.find_proto_override(&Address::new(ram(&m), 0x101920)).unwrap();
    assert_eq!(proto.num_params(), 1);
    assert_eq!(proto.get_param(0).unwrap().get_name(), "argument");
    assert_eq!(proto.get_param(0).unwrap().get_address().get_offset(), 0x90);
    assert_eq!(proto.get_output().get_address().get_offset(), 0x18);
    assert_eq!(proto.get_output().get_size(), 8);
    assert!(proto.is_output_locked());
}

#[test]
fn caller_override_roundtrip_preserves_custom_storage_and_flush_ownership() {
    let mut m = manager_with_registers();
    Rc::get_mut(&mut m).unwrap().insert_space(
        Rc::new(kuna_base::space::ConstantSpace::new()),
    ).unwrap();
    Rc::get_mut(&mut m).unwrap().insert_space(
        Rc::new(kuna_base::space::UniqueSpace::new(3, 0, false)),
    ).unwrap();
    let types = types_with_core();
    let scope = Rc::new(scope_with_override_register_model(&m, Rc::clone(&types)));
    let override_xml = r#"<override><protooverride>
      <addr space="ram" offset="0x101920"/>
      <prototype extrapop="8" model="site_registers" custom="true">
        <returnsym typelock="false"><addr space="register" offset="0x10" size="4"/>
          <type name="" metatype="int" size="4"/>
        </returnsym>
        <internallist>
          <param name="custom_arg" typelock="true" namelock="false">
            <addr space="register" offset="0x90" size="4"/>
            <type name="" metatype="int" size="4"/>
          </param>
        </internallist>
      </prototype>
    </protooverride></override>"#;
    let xml = CAPTURED_MAIN_MAPSYM.replace("</function>", &format!("{override_xml}</function>"));
    scope.materialize(*decode_function_xml(&m, &types, &xml)).unwrap();
    let other_xml = CAPTURED_MAIN_MAPSYM.replace("0x101900", "0x101a00");
    scope.materialize(*decode_function_xml(&m, &types, &other_xml)).unwrap();
    let caller = Address::new(ram(&m), 0x101900);
    let site = Address::new(ram(&m), 0x101920);
    let facts = scope.function_at(&caller).unwrap();
    assert!(scope.function_at(&Address::new(ram(&m), 0x101a00)).unwrap()
        .overrides.find_proto_override(&site).is_none());
    assert!(facts.overrides.find_proto_override(&Address::new(ram(&m), 0x101924)).is_none());

    let mut bytes = Vec::new();
    facts.overrides.encode(&mut PackedEncode::new(&mut bytes), &m).unwrap();
    let mut decoder = PackedDecode::new(&m);
    decoder.ingest_stream(&bytes).unwrap();
    let mut restored = crate::overrides::Override::new();
    restored.decode(&mut decoder, &mut |decoder| {
        let decoded = decode_prototype(decoder, &types)?;
        decoded.to_func_proto(
            scope.model_by_name(&decoded.model).unwrap(), &types, &m,
            FirstVarArgCoordinate::Declared,
        )
    }).unwrap();
    for overrides in [&facts.overrides, &restored] {
        let proto = overrides.find_proto_override(&site).unwrap();
        assert_eq!(proto.get_model_name(), "site_registers");
        assert!(proto.is_override() && proto.has_custom_storage());
        assert_eq!(proto.num_params(), 1);
        let param = proto.get_param(0).unwrap();
        assert_eq!(param.get_name(), "custom_arg");
        assert_eq!(param.get_address().get_offset(), 0x90);
        assert_eq!(param.get_size(), 4);
        assert!(param.is_type_locked() && !param.is_name_locked());
        assert_eq!(proto.get_output().get_address().get_offset(), 0x10);
        assert_eq!(proto.get_output().get_size(), 4);
        assert!(!proto.is_output_locked());
        assert!(proto.logical_callable().is_none());
        assert!(proto.callable_input_origins().is_empty());
    }
    let mut ctx = crate::context::ArchContext::new_shared(Rc::clone(&m));
    ctx.remote_scope = Some(Rc::clone(&scope));
    let ctx = Rc::new(ctx);
    let fresh = || crate::funcdata::Funcdata::new(
        "caller", "caller", Rc::clone(&ctx), caller.clone(), 0x10000000, 0,
    ).unwrap();
    let mut analysis = fresh();
    analysis.clear();
    assert_eq!(analysis.get_override().find_proto_override(&site).unwrap()
        .get_param(0).unwrap().get_address().get_offset(), 0x90);
    analysis.get_override_mut().remove_proto_override(&site);
    assert!(analysis.get_override().find_proto_override(&site).is_none());
    assert!(fresh().get_override().find_proto_override(&site).is_some(),
        "analysis-local override removal must not mutate the canonical host seed");
    scope.clear();
    scope.materialize(*decode_function_xml(&m, &types, CAPTURED_MAIN_MAPSYM)).unwrap();
    assert!(scope.function_at(&caller).unwrap().overrides.find_proto_override(&site).is_none());
    assert!(fresh().get_override().find_proto_override(&site).is_none());
    assert!(facts.overrides.find_proto_override(&site).is_some());
}

#[test]
fn completed_void_internal_roundtrip_keeps_custom_inputs_and_hidden_return() {
    for hidden_return in [false, true] {
        let m = manager_with_registers();
        let types = types_with_core();
        let scope = scope_with_override_register_model(&m, Rc::clone(&types));
        let mut proto = crate::fspec::FuncProto::new();
        proto.set_internal(
            scope.model_by_name("site_registers").unwrap(), types.get_type_void().unwrap(),
        );
        proto.set_custom_storage(true);
        proto.set_abi_first_vararg(Some(1));
        let register = Rc::clone(m.get_space_by_name("register").unwrap());
        if hidden_return {
            proto.set_param(0, "return_storage", &crate::fspec::ParameterPieces {
                addr: Address::new(Rc::clone(&register), 0x90),
                type_: Some(types.get_type_pointer(8, types.get_base(4, type_metatype::TYPE_INT).unwrap(), 1).unwrap()),
                flags: parameter_pieces_flags::HIDDENRETPARM | parameter_pieces_flags::TYPELOCK,
            });
        }
        let slot = if hidden_return { 1 } else { 0 };
        proto.set_param(slot, "custom_argument", &crate::fspec::ParameterPieces {
            addr: Address::new(Rc::clone(&register), 0x98),
            type_: Some(types.get_base(4, type_metatype::TYPE_INT).unwrap()),
            flags: parameter_pieces_flags::TYPELOCK | parameter_pieces_flags::NAMELOCK,
        });
        let mut bytes = Vec::new();
        proto.encode_internal(&mut PackedEncode::new(&mut bytes)).unwrap();
        let mut decoder = PackedDecode::new(&m);
        decoder.ingest_stream(&bytes).unwrap();
        let decoded = decode_prototype(&mut decoder, &types).unwrap();
        let roundtrip = decoded.to_func_proto(
            scope.model_by_name(&decoded.model).unwrap(), &types, &m,
            FirstVarArgCoordinate::Declared,
        ).unwrap();
        assert_eq!(roundtrip.get_output().get_type().unwrap().get_metatype(), type_metatype::TYPE_VOID);
        assert!(roundtrip.get_output().get_address().is_invalid());
        assert!(!roundtrip.is_output_locked());
        assert_eq!(roundtrip.get_abi_first_vararg(), Some(1));
        assert_eq!(roundtrip.num_params(), slot + 1);
        assert!(!roundtrip.is_dotdotdot());
        let argument = roundtrip.get_param(slot).unwrap();
        assert_eq!(argument.get_name(), "custom_argument");
        assert_eq!(argument.get_address(), Address::new(Rc::clone(&register), 0x98));
        assert_eq!(argument.get_size(), 4);
        assert!(argument.is_type_locked() && argument.is_name_locked());
        if hidden_return {
            let hidden = roundtrip.get_param(0).unwrap();
            assert!(hidden.is_hidden_return() && hidden.is_type_locked());
            assert_eq!(hidden.get_address(), Address::new(register, 0x90));
            assert_eq!(hidden.get_size(), 8);
        }
    }
}

#[test]
fn same_signature_effects_and_locks_do_not_alias_or_mutate_cached_seed() {
    let m = manager_with_registers();
    let types = types_with_core();
    let scope = Rc::new(scope_over(&m, Rc::clone(&types), MockFetch::default()));
    let unlocked = CAPTURED_MAIN_MAPSYM
        .replace("0x101900", "0x101a00")
        .replace("typelock=\"true\"", "typelock=\"false\"")
        .replace("namelock=\"true\"", "namelock=\"false\"")
        .replace("modellock=\"true\"", "modellock=\"false\" inline=\"true\"")
        .replace("</prototype>", "<unaffected><addr space=\"register\" offset=\"0x90\" size=\"4\"/></unaffected></prototype>");
    let locked = CAPTURED_MAIN_MAPSYM.replace(
        "</prototype>",
        "<killedbycall><addr space=\"register\" offset=\"0x90\" size=\"4\"/></killedbycall></prototype>",
    );
    for xml in [&locked, &unlocked] {
        scope.materialize(*decode_function_xml(&m, &types, xml)).unwrap();
    }
    let mut ctx = crate::context::ArchContext::new_shared(Rc::clone(&m));
    ctx.remote_scope = Some(Rc::clone(&scope));
    let effect_addr = Address::new(Rc::clone(m.get_space_by_name("register").unwrap()), 0x90);
    for (entry, locked, effect) in [
        (0x101900, true, crate::fspec::effect_type::KILLEDBYCALL),
        (0x101a00, false, crate::fspec::effect_type::UNAFFECTED),
    ] {
        let entry = Address::new(ram(&m), entry);
        let (_, _, canonical) = ctx.query_function(&entry).unwrap().unwrap();
        assert_eq!(canonical.is_input_locked(), locked);
        assert_eq!(canonical.is_output_locked(), locked);
        assert_eq!(canonical.is_inline(), !locked);
        assert_eq!(canonical.has_effect(&effect_addr, 4), effect);
        assert_eq!(canonical.get_param(0).unwrap().is_name_locked(), locked);

        // Calls/reflows use mutable copies. Callsite specialization must not
        // contaminate subsequent consumers of the same per-entry host seed.
        let mut analysis = crate::fspec::FuncProto::new();
        analysis.copy(&canonical);
        analysis.set_output_lock(!locked);
        analysis.set_inline(locked);
        analysis.set_param(0, "analysis_only", &crate::fspec::ParameterPieces {
            addr: effect_addr.clone(),
            type_: canonical.get_param(0).unwrap().get_type().cloned(),
            flags: 0,
        });
        let fresh = ctx.query_callee_proto(&entry).unwrap().unwrap();
        assert_eq!(fresh.is_output_locked(), locked);
        assert_eq!(fresh.is_inline(), !locked);
        assert_eq!(fresh.get_param(0).unwrap().get_name(), "argc");
        assert_eq!(fresh.get_param(0).unwrap().get_address().get_offset(), 0x38);
        assert_eq!(fresh.has_effect(&effect_addr, 4), effect);
    }
}

#[test]
fn parameter_symbol_metadata_survives_creation_and_exact_storage_reuse() {
    let m = manager_with_registers();
    let types = types_with_core();
    let int4_t = types.get_base(4, type_metatype::TYPE_INT).unwrap();
    let reg = Rc::clone(m.get_space_by_name("register").unwrap());
    let address = Address::new(Rc::clone(&reg), 0x90);
    let usepoint = Address::new(ram(&m), 0x100f);
    for reuse in [false, true] {
        for flags in [
            parameter_pieces_flags::TYPELOCK | parameter_pieces_flags::NAMELOCK
                | parameter_pieces_flags::HIDDENRETPARM | parameter_pieces_flags::INDIRECTSTORAGE,
            parameter_pieces_flags::NAMELOCK,
            parameter_pieces_flags::TYPELOCK,
            0,
        ] {
            let mut scope = crate::varmap::ScopeLocal::new(
                0x1234, ram(&m), "metadata", m.num_spaces(),
            ).unwrap();
            if reuse {
                scope.add_symbol("host_local", int4_t.clone(), &address, &usepoint).unwrap();
            }
            scope.add_param_symbol(0, "arg", int4_t.clone(), &address, &usepoint, flags).unwrap();
            let mut doc = Vec::new();
            scope.encode(&mut PackedEncode::new(&mut doc)).unwrap();
            let mut decoder = PackedDecode::new(&m);
            decoder.ingest_stream(&doc).unwrap();
            let mut params = Vec::new();
            let mut locals = Vec::new();
            decode_localdb_params(&mut decoder, &types, &mut params, &mut locals).unwrap();
            assert_eq!(params.len(), 1, "exact storage must reuse the same parameter");
            assert!(locals.is_empty());
            assert_eq!(params[0].storage, address);
            assert_eq!(params[0].flags, flags, "new host metadata must retain its independent locks");
        }
    }

    for locks in [
        parameter_pieces_flags::TYPELOCK | parameter_pieces_flags::NAMELOCK,
        parameter_pieces_flags::NAMELOCK,
        parameter_pieces_flags::TYPELOCK,
    ] {
        for existing_parameter in [false, true] {
            let mut scope = crate::varmap::ScopeLocal::new(
                0x1234, ram(&m), "committed", m.num_spaces(),
            ).unwrap();
            if existing_parameter {
                scope.add_param_symbol(0, "committed", int4_t.clone(), &address, &usepoint, locks).unwrap();
            } else {
                let sid = scope.add_symbol("committed", int4_t.clone(), &address, &usepoint).unwrap();
                let mut attrs = 0;
                if locks & parameter_pieces_flags::TYPELOCK != 0 {
                    attrs |= varnode_flags::typelock;
                }
                if locks & parameter_pieces_flags::NAMELOCK != 0 {
                    attrs |= varnode_flags::namelock;
                }
                scope.set_attribute(sid, attrs);
            }
            scope.add_param_symbol(0, "recovered", int4_t.clone(), &address, &usepoint, 0).unwrap();
            let mut doc = Vec::new();
            scope.encode(&mut PackedEncode::new(&mut doc)).unwrap();
            let mut decoder = PackedDecode::new(&m);
            decoder.ingest_stream(&doc).unwrap();
            let mut params = Vec::new();
            let mut locals = Vec::new();
            decode_localdb_params(&mut decoder, &types, &mut params, &mut locals).unwrap();
            assert_eq!(params.len(), 1);
            assert_eq!(params[0].name, "committed");
            assert_eq!(params[0].flags, locks, "recovery must not clear committed user locks");
        }
    }

    // A differently sized overlapping local is not a parameter; its category
    // and user locks must not be rewritten when the input is linked.
    let mut scope = crate::varmap::ScopeLocal::new(
        0x1235, ram(&m), "overlap", m.num_spaces(),
    ).unwrap();
    let wide = types.get_base(8, type_metatype::TYPE_UINT).unwrap();
    scope.add_symbol("wide_local", wide, &address, &usepoint).unwrap();
    scope.add_param_symbol(
        0, "arg", int4_t, &address, &usepoint,
        parameter_pieces_flags::TYPELOCK | parameter_pieces_flags::NAMELOCK,
    ).unwrap();
    let mut doc = Vec::new();
    scope.encode(&mut PackedEncode::new(&mut doc)).unwrap();
    let mut decoder = PackedDecode::new(&m);
    decoder.ingest_stream(&doc).unwrap();
    let mut params = Vec::new();
    let mut locals = Vec::new();
    decode_localdb_params(&mut decoder, &types, &mut params, &mut locals).unwrap();
    assert!(params.is_empty());
    assert_eq!(locals.len(), 1);
    assert_eq!(locals[0].name, "wide_local");
    assert_eq!(locals[0].dtype.get_size(), 8);
    assert_eq!(locals[0].flags & (varnode_flags::typelock | varnode_flags::namelock), 0);
}

// ---------------------------------------------------------------------------
// RemoteScope behavior over a canned wire fetcher
// ---------------------------------------------------------------------------

/// A canned [`RemoteProviderFetch`]: per-query response maps keyed by offset,
/// plus call counters (the negative-caching asserts).
#[derive(Default)]
struct MockFetch {
    mapped: std::collections::BTreeMap<u64, Vec<u8>>,
    external: std::collections::BTreeMap<u64, Vec<u8>>,
    tracked: std::collections::BTreeMap<u64, Vec<u8>>,
    /// Offsets whose getMappedSymbols FAILS (a wire/JavaError).
    fail_mapped: std::collections::BTreeSet<u64>,
    calls: std::cell::RefCell<std::collections::BTreeMap<&'static str, usize>>,
}

impl MockFetch {
    fn count(&self, what: &'static str) -> usize {
        *self.calls.borrow().get(what).unwrap_or(&0)
    }
    fn bump(&self, what: &'static str) {
        *self.calls.borrow_mut().entry(what).or_insert(0) += 1;
    }
    fn serve(
        map: &std::collections::BTreeMap<u64, Vec<u8>>,
        off: u64,
        decoder: &mut dyn Decoder,
    ) -> KunaResult<bool> {
        match map.get(&off) {
            Some(doc) => {
                decoder.ingest_stream(doc)?;
                Ok(true)
            }
            None => Ok(false),
        }
    }
}

impl RemoteProviderFetch for MockFetch {
    fn fetch_mapped_symbols(
        &self,
        addr: &Address,
        decoder: &mut dyn Decoder,
    ) -> KunaResult<bool> {
        self.bump("mapped");
        if self.fail_mapped.contains(&addr.get_offset()) {
            return Err(kuna_base::error::KunaError::lowlevel("mock wire failure"));
        }
        Self::serve(&self.mapped, addr.get_offset(), decoder)
    }
    fn fetch_namespace_path(&self, _id: u64, _decoder: &mut dyn Decoder) -> KunaResult<bool> {
        self.bump("namespace");
        Ok(false)
    }
    fn fetch_external_ref(&self, addr: &Address, decoder: &mut dyn Decoder) -> KunaResult<bool> {
        self.bump("external");
        Self::serve(&self.external, addr.get_offset(), decoder)
    }
    fn fetch_tracked_registers(
        &self,
        addr: &Address,
        decoder: &mut dyn Decoder,
    ) -> KunaResult<bool> {
        self.bump("tracked");
        Self::serve(&self.tracked, addr.get_offset(), decoder)
    }
    fn fetch_comments(
        &self,
        _fad: &Address,
        _flags: u32,
        _decoder: &mut dyn Decoder,
    ) -> KunaResult<bool> {
        Ok(false)
    }
}

fn scope_over(m: &Rc<AddrSpaceManager>, types: Rc<TypeFactoryImpl>, fetch: MockFetch) -> RemoteScope {
    let mut owned = kuna_base::address::RangeList::default();
    owned.insert_range(ram(m), 0, u64::MAX >> 8);
    let base = GlobalQuery::new(Vec::new(), owned, PartMap::default());
    let mut model = ProtoModel::new(m);
    model.build_param_list("").unwrap();
    types.set_proto_context(Some(Rc::new(model)), Rc::clone(m)).unwrap();
    RemoteScope::new(
        Rc::new(fetch),
        Rc::clone(m),
        types,
        base,
    )
}

#[test]
fn host_names_override_equal_extent_defaults_without_hiding_unmapped_defaults() {
    let manager = manager();
    let types = types_with_core();
    let defaults = scope_over(&manager, Rc::clone(&types), MockFetch::default());
    let record = |name: &str, offset: u64, id: u64| {
        decode_function_xml(&manager, &types, &format!(
            r#"<doc><mapsym><symbol name="{name}" id="{id}" typelock="true" namelock="true" cat="-1">
              <type name="" metatype="uint" size="1"/></symbol>
              <addr space="ram" offset="{offset}" size="1"/><rangelist/></mapsym></doc>"#
        ))
    };
    defaults.materialize(*record("P2", 0xa0, 0x100)).unwrap();
    defaults.materialize(*record("HIE", 0xa1, 0x101)).unwrap();
    let scope = RemoteScope::new(
        Rc::new(MockFetch::default()), Rc::clone(&manager), Rc::clone(&types),
        defaults.snapshot().as_ref().clone(),
    );
    let address = Address::new(ram(&manager), 0xa0);
    let neighbor = Address::new(ram(&manager), 0xa1);
    let name = |query: &GlobalQuery, address: &Address| {
        query.name_for_varnode(address, 1, &Address::new_invalid()).unwrap().0
    };
    assert_eq!(name(&scope.query_snapshot(&address), &address), "P2");
    scope.materialize(*record("motor_control", 0xa0, 0x200)).unwrap();
    assert_eq!(name(&scope.query_snapshot(&address), &address), "motor_control");
    assert_eq!(name(&scope.query_snapshot(&neighbor), &neighbor), "HIE");
    scope.clear();
    assert_eq!(name(&scope.query_snapshot(&address), &address), "P2");
    scope.materialize(*record("renamed_control", 0xa0, 0x201)).unwrap();
    assert_eq!(name(&scope.query_snapshot(&address), &address), "renamed_control");
}

/// A packed `<doc><mapsym><externrefsymbol …>` answer at the pointer, whose
/// getExternalRef resolves to a function carrying BOTH a raw name and a
/// display label: the two-step resolution runs, the facts split name/label
/// (the HighFunction name-echo contract), and the pointer symbol survives.
#[test]
fn extern_ref_resolves_and_splits_name_from_label() {
    let m = manager();
    let types = types_with_core();
    // Pointer symbol at ram:0x5000 -> resolve address ram:0x7000 (the
    // refaddr <addr> is a CHILD of <externrefsymbol>, as upstream encodes).
    let mut ptr_doc = Vec::new();
    {
        let mut e = PackedEncode::new(&mut ptr_doc);
        e.open_element(&crate::prettyprint::ids::ELEM_TYPE);
        e.write_unsigned_integer(&ATTRIB_ID, 0);
        e.open_element(&ELEM_MAPSYM);
        e.open_element(&ELEM_EXTERNREFSYMBOL);
        e.write_string(&ATTRIB_NAME, b"imp_templated");
        Address::new(ram(&m), 0x7000).encode(&mut e).unwrap();
        e.close_element(&ELEM_EXTERNREFSYMBOL);
        Address::new(ram(&m), 0x5000).encode_sized(&mut e, 8).unwrap();
        e.open_element(&ELEM_RANGELIST);
        e.close_element(&ELEM_RANGELIST);
        e.close_element(&ELEM_MAPSYM);
        e.close_element(&crate::prettyprint::ids::ELEM_TYPE);
    }
    // The resolved function: raw name != label (the TemplateSimplifier case).
    let mut fn_doc = Vec::new();
    {
        let mut e = PackedEncode::new(&mut fn_doc);
        e.open_element(&crate::prettyprint::ids::ELEM_TYPE);
        e.write_unsigned_integer(&ATTRIB_ID, 0);
        e.open_element(&ELEM_MAPSYM);
        e.open_element(&crate::funcdata_encode::ELEM_FUNCTION);
        e.write_unsigned_integer(&ATTRIB_ID, 0x99);
        e.write_string(&ATTRIB_NAME, b"foo<int,long>");
        e.write_string(&crate::jumptable::ATTRIB_LABEL, b"foo");
        e.write_signed_integer(&ATTRIB_SIZE, 1);
        e.write_bool(&ATTRIB_NORETURN, true);
        Address::new(ram(&m), 0x7000).encode(&mut e).unwrap();
        e.close_element(&crate::funcdata_encode::ELEM_FUNCTION);
        Address::new(ram(&m), 0x7000).encode_sized(&mut e, 1).unwrap();
        e.open_element(&ELEM_RANGELIST);
        e.close_element(&ELEM_RANGELIST);
        e.close_element(&ELEM_MAPSYM);
        e.close_element(&crate::prettyprint::ids::ELEM_TYPE);
    }
    let mut fetch = MockFetch::default();
    fetch.mapped.insert(0x5000, ptr_doc);
    fetch.external.insert(0x5000, fn_doc);
    let scope = scope_over(&m, types, fetch);

    let probe = Address::new(ram(&m), 0x5000);
    scope.ensure_queried(&probe);
    // The two-step resolution materialized the FUNCTION at its own entry.
    let facts = scope
        .function_at(&Address::new(ram(&m), 0x7000))
        .expect("external function resolved");
    assert_eq!(facts.name, "foo<int,long>", "raw name is the Java identity");
    assert_eq!(facts.display_name, "foo", "label is only the display form");
    assert!(facts.no_return);
    // The pointer's own symbol landed too (pointer-to-code typed).
    let snap = scope.snapshot();
    let (nm, _, ty) = snap
        .name_for_varnode(&probe, 8, &Address::new_invalid())
        .expect("pointer symbol materialized");
    assert_eq!(nm, "imp_templated");
    assert_eq!(
        ty.expect("pointer type").get_metatype(),
        type_metatype::TYPE_PTR
    );
}

/// getTrackedRegisters answers cache per address until `clear()` (one wire
/// ask per flush epoch), and decode failures negative-cache with ONE warning.
#[test]
fn tracked_caches_and_failures_negative_cache() {
    let m = manager();
    let types = types_with_core();
    // A tracked answer for ram:0x1000: one register value.
    let reg_loc = kuna_num::pcoderaw::VarnodeData {
        space: Some(ram(&m)),
        offset: 0x30,
        size: 8,
    };
    let mut tr_doc = Vec::new();
    {
        let mut e = PackedEncode::new(&mut tr_doc);
        let set = vec![kuna_sleigh::globalcontext::TrackedContext {
            loc: reg_loc.clone(),
            val: 0x1234,
        }];
        kuna_sleigh::globalcontext::encode_tracked(
            &mut e,
            &Address::new(ram(&m), 0x1000),
            &set,
        )
        .unwrap();
    }
    let mut fetch = MockFetch::default();
    fetch.tracked.insert(0x1000, tr_doc);
    fetch.fail_mapped.insert(0x4444);
    let scope = scope_over(&m, types, fetch);

    let at = Address::new(ram(&m), 0x1000);
    let set = scope.tracked_at(&at).expect("tracked set");
    assert_eq!(set.len(), 1);
    assert_eq!(set[0].val, 0x1234);
    let set2 = scope.tracked_at(&at).expect("tracked set cached");
    assert_eq!(set2.len(), 1);

    // A FAILING getMappedSymbols address: asked once, negative-cached, one
    // drained warning; clear() re-opens both caches.
    let bad = Address::new(ram(&m), 0x4444);
    scope.ensure_queried(&bad);
    scope.ensure_queried(&bad);
    let warnings = scope.drain_warnings();
    assert_eq!(warnings.len(), 1, "{warnings:?}");
    assert!(warnings[0].starts_with("Warning:"));
    assert!(scope.drain_warnings().is_empty());
    scope.clear();
    scope.ensure_queried(&bad);
    let _ = scope.tracked_at(&at);
    // counts: mapped fired twice total (once per epoch), tracked twice.
    // (Read back through the fetch — the scope owns it, so assert indirectly:
    // a second same-epoch ensure_queried did NOT re-fire, proven by the single
    // warning above; the post-clear re-fire is proven by a fresh warning.)
    let warnings = scope.drain_warnings();
    assert_eq!(warnings.len(), 1, "post-clear re-query fired again");
}

/// Phase-4 differential: the `ScopeLocal::encode` `<localdb>` document decodes
/// through the SAME decoder Java shapes decode through (`decode_localdb_params`
/// / `decode_mapsym`): the cat-0 parameter round-trips with its slot index and
/// typelock, the plain local does not become a parameter, and every `<symbol>`
/// carries a NONZERO internal-range id (`HighSymbol.decodeHeader` throws
/// "missing unique symbol id" on 0 — the r5 §3 trap).
#[test]
fn phase4_localdb_encode_decodes_as_params() {
    let m = manager();
    let types = types_with_core();
    let int4_t = crate::dtype::TypeFactory::find_by_name(types.as_ref(), "int4")
        .unwrap()
        .unwrap();
    let mut lm =
        crate::varmap::ScopeLocal::new(0x1234, ram(&m), "testfn", m.num_spaces()).unwrap();
    // A register-style cat-0 parameter (exact storage + slot index 0).
    let param_addr = Address::new(ram(&m), 0x38);
    let usepoint = Address::new(ram(&m), 0x100f);
    let sid = lm
        .add_param_symbol(
            0, "argc", int4_t.clone(), &param_addr, &usepoint,
            parameter_pieces_flags::TYPELOCK | parameter_pieces_flags::NAMELOCK,
        )
        .unwrap()
        .expect("param created");
    let _ = sid;
    // A plain mapped local (no category).
    lm.add_symbol("local_10", int4_t.clone(), &Address::new(ram(&m), 0x2000), &Address::new_invalid())
        .unwrap();

    let mut doc = Vec::new();
    {
        let mut e = PackedEncode::new(&mut doc);
        lm.encode(&mut e).unwrap();
    }

    // Decode through the wire-shape consumer.
    let mut dec = kuna_base::marshal::PackedDecode::new(&m);
    kuna_base::marshal::Decoder::ingest_stream(&mut dec, &doc).unwrap();
    let mut params: Vec<RemoteParam> = Vec::new();
    let mut locals: Vec<RemoteLocalVar> = Vec::new();
    decode_localdb_params(&mut dec, types.as_ref(), &mut params, &mut locals)
        .unwrap();
    assert_eq!(params.len(), 1, "exactly the cat-0 symbol is a parameter");
    assert_eq!(params[0].index, 0);
    assert_eq!(params[0].name, "argc");
    assert_eq!(
        params[0].flags & (parameter_pieces_flags::TYPELOCK | parameter_pieces_flags::NAMELOCK),
        parameter_pieces_flags::TYPELOCK | parameter_pieces_flags::NAMELOCK,
    );
    assert!(params[0].dtype.as_ref().is_some_and(|t| t.get_size() == 4));
    // The non-parameter local rides the Phase-4 seeding channel: name + first
    // mapped entry + (empty uselimit ⇒ invalid) usepoint.
    assert_eq!(locals.len(), 1, "the plain local is captured for seeding");
    assert_eq!(locals[0].name, "local_10");
    assert_eq!(locals[0].addr.get_offset(), 0x2000);
    assert!(locals[0].usepoint.is_invalid(), "empty uselimit ⇒ addr-tied seed");

    // Structural walk: every <symbol> has a nonzero internal-range id, and every
    // <mapsym> carries at least one entry (addr|hash) + rangelist pair.
    let mut dec = kuna_base::marshal::PackedDecode::new(&m);
    kuna_base::marshal::Decoder::ingest_stream(&mut dec, &doc).unwrap();
    let localdb = dec.open_element().unwrap();
    assert_eq!(localdb, ELEM_LOCALDB.get_id());
    let scope_el = dec.open_element().unwrap();
    assert_eq!(scope_el, ELEM_SCOPE.get_id());
    // Positional contract: <parent> then <rangelist> BEFORE <symbollist>
    // (LocalSymbolMap.decodeScope skips the first two children blind).
    let parent_el = dec.open_element().unwrap();
    assert_eq!(parent_el, ELEM_PARENT.get_id(), "first scope child must be <parent>");
    dec.close_element_skipping(parent_el).unwrap();
    let rl_el = dec.open_element().unwrap();
    assert_eq!(rl_el, ELEM_RANGELIST.get_id(), "second scope child must be <rangelist>");
    dec.close_element_skipping(rl_el).unwrap();
    let list_el = dec.open_element().unwrap();
    assert_eq!(list_el, ELEM_SYMBOLLIST.get_id());
    let mut mapsym_count = 0;
    while dec.peek_element().unwrap() != 0 {
        let ms = dec.open_element().unwrap();
        assert_eq!(ms, ELEM_MAPSYM.get_id());
        mapsym_count += 1;
        // <symbol id=NONZERO ...>
        let sym_el = dec.open_element().unwrap();
        assert_eq!(sym_el, ELEM_SYMBOL.get_id());
        let id = kuna_base::marshal::Decoder::read_unsigned_integer_id(&mut dec, &ATTRIB_ID)
            .unwrap();
        assert_ne!(id, 0, "symbol id must be nonzero (Java hard-throw)");
        assert_eq!(id >> 56, 0x40, "invented symbols carry internal-range ids");
        dec.close_element_skipping(sym_el).unwrap();
        // >=1 SymbolEntry: (addr|hash) + rangelist.
        let entry_el = dec.open_element().unwrap();
        assert!(
            entry_el == kuna_base::address::ELEM_ADDR.get_id()
                || entry_el == ELEM_HASH.get_id(),
            "mapsym entry must open with <addr> or <hash>"
        );
        dec.close_element_skipping(entry_el).unwrap();
        let ul_el = dec.open_element().unwrap();
        assert_eq!(ul_el, ELEM_RANGELIST.get_id(), "entry uselimit rangelist required");
        dec.close_element_skipping(ul_el).unwrap();
        dec.close_element_skipping(ms).unwrap();
    }
    assert_eq!(mapsym_count, 2);
    dec.close_element(list_el).unwrap();
    dec.close_element(scope_el).unwrap();
    dec.close_element(localdb).unwrap();
}
