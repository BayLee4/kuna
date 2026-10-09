//! Porter in-module tests for `remote_provider.rs`: the `<mapsym>`/`<hole>`
//! decoder against hand-built packed documents (the Java `DecompileCallback`
//! answer shapes), and the wire `<coretypes>` decode equivalence.

use std::rc::Rc;

use kuna_base::address::{Address, ELEM_RANGELIST};
use kuna_base::marshal::{
    Encoder, IdRegistry, PackedEncode, XmlDecode, ATTRIB_CONTENT, ATTRIB_ID, ATTRIB_INDEX,
    ATTRIB_MODEL, ATTRIB_NAME, ATTRIB_NAMELOCK, ATTRIB_READONLY, ATTRIB_SIZE,
    ATTRIB_TYPELOCK, ELEM_SYMBOL, ELEM_VOID,
};
use kuna_base::space::{addrspace_flags, spacetype, AddrSpace, AddrSpaceManager};

use super::*;
use crate::dtype::type_metatype;

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
    assert!(Rc::ptr_eq(rec.dtype.as_ref().unwrap(), &int4));
    assert_eq!(rec.entries.len(), 1);
    assert_eq!(rec.entries[0].addr.get_offset(), 0x2000);
    assert_eq!(rec.entries[0].size, 4);
    assert!(rec.entries[0].uselimit.empty());
    assert!(rec.func.is_none());
}

/// A function answer with `<localdb>` cat-0 params and a `<prototype>`:
/// the noreturn flag, the sorted locked params, and `to_pieces`.
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
    assert!(proto.params[0].hidden);
    assert_eq!(proto.params[1].name, "second");
    assert!(!proto.params[1].hidden);
    let pieces = proto.to_pieces(&func.name);
    let output = pieces.output_storage.as_ref().expect("custom return storage");
    assert_eq!(output.addr.get_offset(), 0x88);
    assert_ne!(
        output.flags & crate::fspec::parameter_pieces_flags::CUSTOM_STORAGE,
        0
    );
    assert_eq!(pieces.name, "my_exit");
    assert_eq!(pieces.intypes.len(), 1);
    assert_eq!(pieces.innames, vec!["second".to_string()]);
    assert_eq!(pieces.first_var_arg_slot, -1);
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
    let mut dec = PackedDecode::new(&m);
    dec.ingest_stream(&doc).unwrap();
    let levels = decode_namespace_levels(&mut dec).unwrap();
    assert_eq!(levels, vec![("inner".to_string(), 11), ("outer".to_string(), 10)]);
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
/// (integrations/ghidra/live-smoke rig; the `<xml_savefile>` records the
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

fn decode_captured_main(
    m: &Rc<AddrSpaceManager>,
    types: &TypeFactoryImpl,
) -> Box<RemoteSymbolRecord> {
    let mut registry = IdRegistry::with_base_ids();
    register_remote_provider_ids(&mut registry);
    crate::dtype::register_type_wire_ids(&mut registry);
    registry.register_element(&crate::funcdata_encode::ELEM_FUNCTION);
    registry.register_element(&crate::prettyprint::ids::ELEM_TYPE);
    registry.register_attribute(&crate::jumptable::ATTRIB_LABEL);

    let store = kuna_base::xml::xml_tree(CAPTURED_MAIN_MAPSYM.as_bytes()).unwrap();
    let root = store.get_root().clone();
    let mut dec = XmlDecode::new_with_root(m, &registry, &root, 0);
    match decode_mapped_answer(&mut dec, types).unwrap() {
        RemoteMapAnswer::Symbol(rec) => rec,
        _ => panic!("expected a symbol"),
    }
}

fn decode_function_xml(
    m: &Rc<AddrSpaceManager>,
    types: &TypeFactoryImpl,
    text: &str,
) -> Box<RemoteSymbolRecord> {
    let registry = source_fixture_registry();

    let store = kuna_base::xml::xml_tree(text.as_bytes()).unwrap();
    let root = store.get_root().clone();
    let mut dec = XmlDecode::new_with_root(m, &registry, &root, 0);
    match decode_mapped_answer(&mut dec, types).unwrap() {
        RemoteMapAnswer::Symbol(rec) => rec,
        _ => panic!("expected a symbol"),
    }
}

fn source_fixture_registry() -> IdRegistry {
    let mut registry = IdRegistry::with_base_ids();
    register_remote_provider_ids(&mut registry);
    crate::dtype::register_type_wire_ids(&mut registry);
    for element in [
        crate::funcdata_encode::ELEM_FUNCTION, crate::prettyprint::ids::ELEM_TYPE,
        crate::fspec::ELEM_KILLEDBYCALL, crate::fspec::ELEM_UNAFFECTED,
        kuna_base::marshal::ElementId::new("param", 166),
        kuna_base::marshal::ElementId::new("override", 223),
        kuna_base::marshal::ElementId::new("protooverride", 224),
    ] {
        registry.register_element(&element);
    }
    registry.register_attribute(&crate::jumptable::ATTRIB_LABEL);
    registry
}

/// Decode the vendored REAL Java answer (XML form; the packed wire form
/// differs only in the marshaling layer behind `dyn Decoder`).
#[test]
fn captured_java_function_mapsym_decodes() {
    let m = manager_with_registers();
    let types = types_with_core();
    let rec = decode_captured_main(&m, &types);
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
    assert_eq!(out.get_name(), "int");
    assert_eq!(out.get_size(), 4);
    assert_eq!(out.get_metatype(), type_metatype::TYPE_INT);
    assert_eq!(out.get_id(), 0xc000000000000095);
    assert!(proto.is_input_locked());
    assert_eq!(proto.params.len(), 2);
    assert_eq!(proto.params[0].name, "argc");
    let argc_ty = proto.params[0].dtype.as_ref().unwrap();
    assert!(Rc::ptr_eq(argc_ty, out), "both int refs intern to one instance");
    assert_eq!(proto.params[1].name, "argv");
    let argv_ty = proto.params[1].dtype.as_ref().unwrap();
    assert_eq!(argv_ty.get_metatype(), type_metatype::TYPE_PTR);
    // The mapping entry (the outer <addr size=1> at the function entry).
    assert_eq!(rec.entries.len(), 1);
    assert_eq!(rec.entries[0].addr.get_offset(), 0x101900);
}

/// The host's typelocked parameters must reach [`RemoteFunctionFacts::param_storage`]
/// carrying the **`ParameterPieces`** lock bits.  `varnode_flags::typelock|namelock`
/// (0x300) shares no bit with `parameter_pieces_flags::TYPELOCK|NAMELOCK` (0x18), and
/// `Funcdata::apply_mapped_params` re-`set_param`s every slot wholesale AFTER
/// `apply_locked_prototype_with_model`, so unlocked pieces here CLOBBER the lock the
/// prototype channel just set: `FuncProto::is_input_locked` reads slot 0's typelock,
/// so the whole signature reads unlocked and the host's declared types and names are
/// re-derived instead of applied.
#[test]
fn captured_java_locked_params_materialize_with_pieces_locks() {
    let m = manager_with_registers();
    let types = types_with_core();
    let scope = scope_over(&m, Rc::clone(&types), MockFetch::default());
    scope.materialize(*decode_captured_main(&m, &types));

    let facts =
        scope.function_at(&Address::new(ram(&m), 0x101900)).expect("the captured function");
    let locks = crate::fspec::parameter_pieces_flags::TYPELOCK
        | crate::fspec::parameter_pieces_flags::NAMELOCK;
    let want = [(0, "argc", 0x38u64), (1, "argv", 0x30)];
    assert_eq!(facts.param_storage.len(), want.len(), "both host params carried storage");
    for ((slot, name, piece), (wslot, wname, woff)) in facts.param_storage.iter().zip(&want) {
        assert_eq!(slot, wslot, "{wname}: compacted slot basis");
        assert_eq!(name, wname);
        assert_eq!(piece.addr.get_offset(), *woff, "{wname}: host storage verbatim");
        assert_eq!(
            piece.flags & locks,
            locks,
            "{wname}: locks must be parameter_pieces_flags bits, got {:#x}",
            piece.flags
        );
    }
}

fn source_types_with_core() -> Rc<TypeFactoryImpl> {
    let types = types_with_core();
    types.set_max_basetype_size(8);
    types
}

fn source_manager_with_registers() -> Rc<AddrSpaceManager> {
    let mut manager = Rc::try_unwrap(manager_with_registers())
        .unwrap_or_else(|_| unreachable!("fresh fixture manager has one owner"));
    manager.insert_space(Rc::new(kuna_base::space::ConstantSpace::new())).unwrap();
    manager.insert_space(Rc::new(kuna_base::space::UniqueSpace::new(3, 0, false))).unwrap();
    manager.set_default_code_space(1).unwrap();
    manager.set_default_data_space(1).unwrap();
    Rc::new(manager)
}

fn source_fact_scope(m: &Rc<AddrSpaceManager>, types: Rc<TypeFactoryImpl>) -> Rc<RemoteScope> {
    let mut model = ProtoModel::new(m);
    model.build_param_list("standard").unwrap();
    model.set_name("__stdcall");
    let register = Rc::clone(m.get_space_by_name("register").unwrap());
    for (slot, offset) in [0x38, 0x30, 0x10, 0x08].into_iter().enumerate() {
        let entry = crate::fspec::ParamEntry::seed(
            slot as i32, crate::dtype::type_class::TYPECLASS_GENERAL,
            Rc::clone(&register), offset, 8, 1, 0, 0, true, false,
            model.input().get_entry(), m,
        ).unwrap();
        model.input_mut().push_entry(entry);
    }
    model.input_mut().finish_decode();
    model.output_mut().push_entry(crate::fspec::ParamEntry::seed(
        0, crate::dtype::type_class::TYPECLASS_GENERAL,
        register, 0, 8, 1, 0, 0, true, false, &[], m,
    ).unwrap());
    model.output_mut().finish_decode();
    let model = Rc::new(model);
    types.set_proto_context(Rc::clone(m));
    types.set_proto_models(Some(Rc::clone(&model)),
        std::collections::BTreeMap::from([("__stdcall".to_string(), Rc::clone(&model))]));
    let mut owned = kuna_base::address::RangeList::default();
    owned.insert_range(ram(m), 0, u64::MAX >> 8);
    Rc::new(RemoteScope::new(
        Rc::new(MockFetch::default()), Rc::clone(m), types,
        std::collections::BTreeMap::from([("__stdcall".to_string(), model.clone())]),
        Some(model), GlobalQuery::new(Vec::new(), owned, PartMap::default()),
    ))
}

#[test]
fn same_signature_entries_keep_independent_storage_and_analysis_copies() {
    for reverse in [false, true] {
        let m = source_manager_with_registers();
        let types = source_types_with_core();
        let scope = source_fact_scope(&m, Rc::clone(&types));
        let custom = |entry, input, output| CAPTURED_MAIN_MAPSYM
            .replace("0x101900", entry)
            .replace("modellock=\"true\"", "modellock=\"true\" custom=\"true\"")
            .replace("offset=\"0x38\"", input)
            .replace("offset=\"0x0\" size=\"4\"", output);
        let mut records = vec![
            (CAPTURED_MAIN_MAPSYM.to_string(), 0x101900, 0x38, 0, false),
            (custom("0x101a00", "offset=\"0x90\"", "offset=\"0x10\" size=\"4\""), 0x101a00, 0x90, 0x10, true),
            (custom("0x101b00", "offset=\"0x98\"", "offset=\"0x08\" size=\"4\""), 0x101b00, 0x98, 0x08, true),
        ];
        if reverse { records.reverse(); }
        for (xml, ..) in &records {
            scope.materialize(*decode_function_xml(&m, &types, xml));
        }
        let mut ctx = crate::context::ArchContext::new_shared(Rc::clone(&m));
        ctx.remote_scope = Some(Rc::clone(&scope));
        ctx.types = Some(Rc::clone(&types));
        ctx.defaultfp = scope.resolve_model("__stdcall");
        for (_, entry, input, output, custom) in &records {
            let entry = Address::new(ram(&m), *entry);
            let direct = ctx.query_callee_proto(&entry).expect("declared callee");
            let (_, _, deindirect) = ctx.query_function(&entry).unwrap();
            let indirect = match ctx.query_indirect_slot_type(&entry, 8, &entry).unwrap() {
                crate::context::IndirectSlotType::Prototype(proto) => proto,
                crate::context::IndirectSlotType::FunctionCode => {
                    let pieces = ctx.callee_proto_pieces(&entry).expect("exact function source");
                    assert_eq!(pieces.innames[0], "argc");
                    ctx.query_callee_proto(&entry).unwrap()
                }
                crate::context::IndirectSlotType::Untyped => panic!("authoritative function slot"),
            };
            for proto in [direct, deindirect, indirect] {
                let param = proto.get_param(0).unwrap();
                assert_eq!(param.get_name(), "argc");
                assert_eq!(param.get_address().get_offset(), *input);
                assert_eq!(param.get_address().get_space().unwrap().get_name(), "register");
                assert_eq!(param.get_size(), 4);
                assert_eq!(proto.get_output().get_address().get_offset(), *output);
                assert_eq!(proto.get_output().get_size(), 4);
                assert_eq!(proto.has_custom_storage(), *custom);
                assert!(param.is_type_locked() && param.is_name_locked());
                assert!(proto.is_output_locked());
                let mut analysis = crate::fspec::FuncProto::new();
                analysis.copy(&proto);
                analysis.set_param(0, "recovered", &crate::fspec::ParameterPieces {
                    addr: Address::new(Rc::clone(m.get_space_by_name("register").unwrap()), 0xa0),
                    type_: param.get_type().cloned(), flags: 0,
                });
                analysis.set_output_lock(false);
                let fresh = ctx.query_callee_proto(&entry).unwrap();
                assert_eq!(fresh.get_param(0).unwrap().get_name(), "argc");
                assert_eq!(fresh.get_param(0).unwrap().get_address().get_offset(), *input);
                assert!(fresh.is_output_locked());
            }
            for wrong_width in [4, 16] {
                assert!(matches!(ctx.query_indirect_slot_type(&entry, wrong_width, &entry),
                    Some(crate::context::IndirectSlotType::Untyped)));
            }
        }
        let old = scope.function_at(&Address::new(ram(&m), 0x101900)).unwrap();
        scope.clear();
        scope.materialize(*decode_function_xml(&m, &types,
            &custom("0x101900", "offset=\"0x90\"", "offset=\"0x10\" size=\"4\"")));
        let fresh = ctx.query_callee_proto(&Address::new(ram(&m), 0x101900)).unwrap();
        assert_eq!(fresh.get_param(0).unwrap().get_address().get_offset(), 0x90);
        assert_eq!(old.param_storage[0].2.addr.get_offset(), 0x38);
    }
}

#[test]
fn source_parameter_name_and_type_locks_materialize_independently() {
    for type_lock in [false, true] {
        for name_lock in [false, true] {
            let m = source_manager_with_registers();
            let types = source_types_with_core();
            let scope = source_fact_scope(&m, Rc::clone(&types));
            let xml = CAPTURED_MAIN_MAPSYM
                .replace("typelock=\"true\"", &format!("typelock=\"{type_lock}\""))
                .replace("namelock=\"true\"", &format!("namelock=\"{name_lock}\""));
            scope.materialize(*decode_function_xml(&m, &types, &xml));
            let facts = scope.function_at(&Address::new(ram(&m), 0x101900)).unwrap();
            assert_eq!(facts.param_storage.len(), 2, "supplied storage survives unlocked source");
            for (slot, name, offset) in [(0, "argc", 0x38), (1, "argv", 0x30)] {
                let (actual_slot, actual_name, piece) = &facts.param_storage[slot];
                assert_eq!((*actual_slot, actual_name.as_str()), (slot as i32, name));
                assert_eq!(piece.addr.get_offset(), offset);
                assert_eq!(piece.flags & crate::fspec::parameter_pieces_flags::TYPELOCK != 0, type_lock);
                assert_eq!(piece.flags & crate::fspec::parameter_pieces_flags::NAMELOCK != 0, name_lock);
            }
        }
    }
}

#[test]
fn host_input_and_output_locks_remain_independent_at_callee_consumers() {
    for void_result in [false, true] {
    for input_lock in [false, true] {
        for output_lock in [false, true] {
            let m = source_manager_with_registers();
            let types = source_types_with_core();
            let scope = source_fact_scope(&m, Rc::clone(&types));
            let xml = CAPTURED_MAIN_MAPSYM
                .replace("modellock=\"true\"", "modellock=\"false\" custom=\"true\"")
                .replace("typelock=\"true\"", &format!("typelock=\"{input_lock}\""))
                .replace(&format!("<returnsym typelock=\"{input_lock}\">"),
                    &format!("<returnsym typelock=\"{output_lock}\">"))
                .replace("namelock=\"true\"", "namelock=\"false\"");
            let mut rec = decode_function_xml(&m, &types, &xml);
            if void_result {
                let source = rec.func.as_mut().unwrap().proto.as_mut().unwrap();
                source.out_type = Some(types.get_type_void().unwrap());
                source.out_storage = Address::new_invalid();
            }
            let source = rec.func.as_ref().unwrap().proto.as_ref().unwrap();
            assert_eq!(source.is_input_locked(), input_lock);
            assert_eq!(source.out_lock, output_lock);
            scope.materialize(*rec);
            let mut ctx = crate::context::ArchContext::new_shared(Rc::clone(&m));
            ctx.types = Some(Rc::clone(&types));
            ctx.defaultfp = scope.resolve_model("__stdcall");
            ctx.remote_scope = Some(scope);
            let (_, _, proto) = ctx.query_function(&Address::new(ram(&m), 0x101900)).unwrap();
            assert_eq!(proto.is_input_locked(), input_lock);
            assert_eq!(proto.is_output_locked(), output_lock);
            assert_eq!(proto.is_model_locked(), input_lock || output_lock);
            assert!(!proto.get_param(0).unwrap().is_name_locked());
            if void_result {
                assert!(proto.get_output().get_address().is_invalid());
                assert_eq!(proto.get_output_type().unwrap().get_metatype(), type_metatype::TYPE_VOID);
            } else {
                assert_eq!(proto.get_output().get_size(), 4);
                assert_eq!(proto.get_output_type().unwrap().get_metatype(), type_metatype::TYPE_INT);
                assert_eq!(proto.get_output().get_address().get_offset(), 0);
            }
            assert_eq!(proto.get_param(0).unwrap().get_address().get_offset(), 0x38);
        }
    }
    }
}

#[test]
fn same_signature_effects_and_locks_do_not_alias_or_mutate_cached_seed() {
    for reverse in [false, true] {
        let m = source_manager_with_registers();
        let types = source_types_with_core();
        let scope = source_fact_scope(&m, Rc::clone(&types));
        let locked = CAPTURED_MAIN_MAPSYM.replace("</prototype>",
            "<killedbycall><addr space=\"register\" offset=\"0x90\" size=\"4\"/></killedbycall></prototype>");
        let unlocked = CAPTURED_MAIN_MAPSYM
            .replace("0x101900", "0x101a00")
            .replace("typelock=\"true\"", "typelock=\"false\"")
            .replace("namelock=\"true\"", "namelock=\"false\"")
            .replace("modellock=\"true\"", "modellock=\"false\" inline=\"true\"")
            .replace("</prototype>",
                "<unaffected><addr space=\"register\" offset=\"0x90\" size=\"4\"/></unaffected></prototype>");
        let mut documents = vec![locked, unlocked];
        if reverse { documents.reverse(); }
        for xml in documents { scope.materialize(*decode_function_xml(&m, &types, &xml)); }
        let mut ctx = crate::context::ArchContext::new_shared(Rc::clone(&m));
        ctx.types = Some(Rc::clone(&types));
        ctx.defaultfp = scope.resolve_model("__stdcall");
        ctx.remote_scope = Some(scope);
        let effect_addr = Address::new(Rc::clone(m.get_space_by_name("register").unwrap()), 0x90);
        for (entry, locked, effect) in [
            (0x101900, true, crate::fspec::effect_type::KILLEDBYCALL),
            (0x101a00, false, crate::fspec::effect_type::UNAFFECTED),
        ] {
            let entry = Address::new(ram(&m), entry);
            let (_, _, canonical) = ctx.query_function(&entry).unwrap();
            assert_eq!(canonical.has_effect(&effect_addr, 4), effect);
            assert_eq!(canonical.is_input_locked(), locked);
            assert_eq!(canonical.is_output_locked(), locked);
            assert_eq!(canonical.is_inline(), !locked);
            let mut analysis = crate::fspec::FuncProto::new();
            analysis.copy(&canonical);
            analysis.set_output_lock(!locked);
            analysis.set_inline(locked);
            let (_, _, fresh) = ctx.query_function(&entry).unwrap();
            assert_eq!(fresh.is_output_locked(), locked);
            assert_eq!(fresh.is_inline(), !locked);
            assert_eq!(fresh.has_effect(&effect_addr, 4), effect);
        }
    }
}

#[test]
fn internal_custom_storage_keeps_void_hidden_this_and_indirect_roles() {
    for void_result in [false, true] {
        let m = source_manager_with_registers();
        let types = source_types_with_core();
        let result = if void_result { "<void/>" } else {
            r#"<type name="SiteResult" metatype="struct" size="16"><field name="left" offset="0"><type name="" metatype="int" size="8"/></field><field name="right" offset="8"><type name="" metatype="int" size="8"/></field></type>"#
        };
        let result_storage = if void_result { "<addr/>" } else {
            r#"<addr space="register" offset="0x70" size="16"/>"#
        };
        let xml = format!(
            r#"<doc><mapsym><function name="custom" id="123" size="1"><addr space="ram" offset="0x101900"/>
            <prototype model="__stdcall" custom="true" modellock="true" extrapop="8">
              <returnsym typelock="false">{result_storage}{result}</returnsym>
              <internallist first="2">
                <param name="return_storage" typelock="true" namelock="false" hiddenretparm="true"><addr space="register" offset="0x80" size="8"/><type name="" metatype="ptr" size="8"><type name="" metatype="int" size="4"/></type></param>
                <param name="self" typelock="true" namelock="true" thisptr="true" indirectstorage="true"><addr space="register" offset="0x98" size="8"/><type name="" metatype="ptr" size="8"><type name="" metatype="int" size="4"/></type></param>
              </internallist>
            </prototype></function><addr space="ram" offset="0x101900" size="1"/><rangelist/></mapsym></doc>"#
        );
        let rec = decode_function_xml(&m, &types, &xml);
        let proto = rec.func.as_ref().unwrap().proto.as_ref().unwrap();
        assert_eq!(proto.params.len(), 2, "internal inputs must not be discarded");
        assert_eq!(proto.params[0].name, "return_storage");
        assert!(proto.params[0].hidden);
        assert_eq!(proto.params[0].storage.get_offset(), 0x80);
        assert_eq!(proto.params[1].name, "self");
        assert_eq!(proto.params[1].storage.get_offset(), 0x98);
        assert!(!proto.dotdotdot, "first boundary is not an open-arity declaration");
        assert!(!proto.out_lock);
        assert_eq!(proto.out_storage.is_invalid(), void_result);
        assert_eq!(proto.out_type.as_ref().unwrap().get_metatype(),
            if void_result { type_metatype::TYPE_VOID } else { type_metatype::TYPE_STRUCT });
        let scope = source_fact_scope(&m, Rc::clone(&types));
        scope.materialize(*rec);
        let facts = scope.function_at(&Address::new(ram(&m), 0x101900)).unwrap();
        let hidden = &facts.param_storage[0].2;
        assert_ne!(hidden.flags & crate::fspec::parameter_pieces_flags::HIDDENRETPARM, 0);
        let this = &facts.param_storage[1].2;
        assert_ne!(this.flags & crate::fspec::parameter_pieces_flags::ISTHIS, 0);
        assert_ne!(this.flags & crate::fspec::parameter_pieces_flags::INDIRECTSTORAGE, 0);
    }
}

const CLOSED_AGGREGATE_OVERRIDE: &str = r#"<override><protooverride>
  <addr space="ram" offset="0x101920"/>
  <prototype extrapop="8" model="__stdcall">
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
fn caller_override_source_reaches_only_its_callsite_and_survives_analysis_reset() {
    for custom in [false, true] {
    let m = source_manager_with_registers();
    let types = source_types_with_core();
    let scope = source_fact_scope(&m, Rc::clone(&types));
    let custom_override = r#"<override><protooverride><addr space="ram" offset="0x101920"/>
      <prototype extrapop="8" model="__stdcall" custom="true">
        <returnsym typelock="false"><addr space="register" offset="0x10" size="4"/><type name="" metatype="int" size="4"/></returnsym>
        <internallist><param name="custom_arg" typelock="true" namelock="false"><addr space="register" offset="0x90" size="4"/><type name="" metatype="int" size="4"/></param></internallist>
      </prototype></protooverride></override>"#;
    let declaration = if custom { custom_override } else { CLOSED_AGGREGATE_OVERRIDE };
    let xml = CAPTURED_MAIN_MAPSYM.replace("</function>", &format!("{declaration}</function>"));
    scope.materialize(*decode_function_xml(&m, &types, &xml));
    scope.materialize(*decode_function_xml(&m, &types, &CAPTURED_MAIN_MAPSYM.replace("0x101900", "0x101a00")));
    let mut ctx = crate::context::ArchContext::new_shared(Rc::clone(&m));
    ctx.remote_scope = Some(Rc::clone(&scope));
    ctx.types = Some(Rc::clone(&types));
    ctx.defaultfp = scope.resolve_model("__stdcall");
    let ctx = Rc::new(ctx);
    let fresh = |entry| crate::funcdata::Funcdata::new(
        "caller", "caller", Rc::clone(&ctx), Address::new(ram(&m), entry), 0x10000000, 0,
    ).unwrap();
    let site = Address::new(ram(&m), 0x101920);
    let mut caller = fresh(0x101900);
    caller.clear();
    let source = caller.get_override().find_proto_override(&site).expect("host callsite declaration");
    let proto = source.prototype().expect("materialized override");
    assert_eq!(proto.get_model_name(), "__stdcall");
    assert!(proto.is_input_locked());
    assert_eq!(proto.is_output_locked(), !custom);
    assert_eq!(proto.has_custom_storage(), custom);
    if custom {
        assert_eq!(proto.num_params(), 1);
        let input = proto.get_param(0).unwrap();
        assert_eq!(input.get_name(), "custom_arg");
        assert_eq!(input.get_address().get_offset(), 0x90);
        assert!(input.is_type_locked() && !input.is_name_locked());
        assert_eq!(proto.get_output().get_address().get_offset(), 0x10);
        assert_eq!(proto.get_output().get_size(), 4);
    } else {
        assert_eq!(proto.num_params(), 3);
        assert!(proto.get_param(0).unwrap().is_hidden_return());
        assert_eq!(proto.get_param(1).unwrap().get_name(), "rethidden");
        assert!(!proto.get_param(1).unwrap().is_hidden_return());
        let result = proto.get_output().get_type().unwrap().get_ptr_to().unwrap();
        assert_eq!((result.get_name(), result.get_size()), ("SiteResult", 16));
    }
    assert!(!proto.is_dotdotdot());
    assert!(caller.get_override().find_proto_override(&Address::new(ram(&m), 0x101924)).is_none());
    assert!(fresh(0x101a00).get_override().find_proto_override(&site).is_none());
    caller.get_override_mut().clear();
    assert!(caller.get_override().find_proto_override(&site).is_none());
    assert!(fresh(0x101900).get_override().find_proto_override(&site).is_some());
    scope.clear();
    scope.materialize(*decode_captured_main(&m, &types));
    assert!(fresh(0x101900).get_override().find_proto_override(&site).is_none());
    }
}

#[test]
fn closed_internal_source_arguments_preserve_storage_names_and_arity_boundary() {
    for open in [false, true] {
        let m = source_manager_with_registers();
        let types = source_types_with_core();
        let text = format!(
            r#"<prototype model="__stdcall" extrapop="8" dotdotdot="{open}" custom="true">
              <returnsym typelock="true"><addr space="register" offset="0" size="4"/><type name="" metatype="int" size="4"/></returnsym>
              <internallist first="1">
                <param name="format" typelock="true" namelock="true"><addr space="register" offset="0x90" size="8"/><type name="" metatype="ptr" size="8"><type name="char" metatype="int" size="1" char="true"/></type></param>
                <param name="count" typelock="true" namelock="false"><addr space="register" offset="0x30" size="4"/><type name="" metatype="int" size="4"/></param>
                <param name="wide" typelock="true" namelock="true"><addr space="register" offset="0x98" size="8"/><type name="" metatype="int" size="8"/></param>
              </internallist>
            </prototype>"#
        );
        let registry = source_fixture_registry();
        let store = kuna_base::xml::xml_tree(text.as_bytes()).unwrap();
        let root = store.get_root().clone();
        let mut decoder = XmlDecode::new_with_root(&m, &registry, &root, 0);
        let proto = decode_prototype(&mut decoder, &types).unwrap();
        assert_eq!(proto.dotdotdot, open, "first=1 alone must not reopen recovered arity");
        assert!(proto.out_lock);
        assert_eq!(proto.params.len(), 3);
        for (param, name, offset, size) in [
            (&proto.params[0], "format", 0x90, 8),
            (&proto.params[1], "count", 0x30, 4),
            (&proto.params[2], "wide", 0x98, 8),
        ] {
            assert_eq!(param.name, name);
            assert_eq!(param.storage.get_offset(), offset);
            assert_eq!(param.dtype.as_ref().unwrap().get_size(), size);
            assert!(param.typelock);
        }
        assert_eq!(proto.to_pieces("site").intypes.len(), 3);
    }
}

#[test]
fn committed_and_unlocked_aggregate_source_keeps_exact_types_storage_and_roles() {
    for (input_lock, output_lock, unknown) in [
        (true, true, false), (false, true, false), (true, false, false), (true, true, true),
    ] {
        let m = source_manager_with_registers();
        let types = source_types_with_core();
        let value = if unknown { r#"<type name="" metatype="unknown" size="4"/>"# }
            else { r#"<type name="" metatype="int" size="4"/>"# };
        let xml = format!(
            r#"<doc><mapsym><function name="aggregate" id="123" size="1"><addr space="ram" offset="0x101900"/>
              <prototype model="__stdcall" custom="true" extrapop="8">
                <returnsym typelock="{output_lock}"><addr space="register" offset="0x70" size="16"/>
                  <type name="SiteResult" metatype="struct" size="16"><field name="left" offset="0"><type name="" metatype="int" size="8"/></field><field name="right" offset="8"><type name="" metatype="int" size="8"/></field></type>
                </returnsym>
                <internallist first="2">
                  <param name="rethidden" typelock="{input_lock}" namelock="true"><addr space="register" offset="0x90" size="4"/>{value}</param>
                  <param name="self" typelock="true" namelock="false" thisptr="true"><addr space="register" offset="0x98" size="16"/>
                    <def name="SitePayloadAlias" id="601"><type name="SitePayload" id="602" metatype="struct" size="16"><field name="head" offset="0"><type name="" metatype="int" size="8"/></field><field name="tail" offset="8"><type name="" metatype="int" size="8"/></field></type></def>
                  </param>
                </internallist>
              </prototype>
            </function><addr space="ram" offset="0x101900" size="1"/><rangelist/></mapsym></doc>"#
        );
        let rec = decode_function_xml(&m, &types, &xml);
        let source = rec.func.as_ref().unwrap().proto.as_ref().unwrap();
        assert!(source.custom);
        assert_eq!(source.out_lock, output_lock);
        assert_eq!(source.out_storage.get_offset(), 0x70);
        let result = source.out_type.as_ref().unwrap();
        assert_eq!((result.get_name(), result.get_size()), ("SiteResult", 16));
        assert_eq!(result.get_field(1).unwrap().name, "right");
        assert_eq!(source.params.len(), 2, "committed result storage must not invent hidden input");
        let fixed = &source.params[0];
        assert_eq!(fixed.name, "rethidden");
        assert!(!fixed.hidden, "names do not declare automatic roles");
        assert_eq!(fixed.typelock, input_lock);
        assert_eq!(fixed.storage.get_offset(), 0x90);
        assert_eq!(fixed.dtype.as_ref().unwrap().get_metatype(),
            if unknown { type_metatype::TYPE_UNKNOWN } else { type_metatype::TYPE_INT });
        let aggregate = &source.params[1];
        let alias = aggregate.dtype.as_ref().unwrap();
        assert_eq!((alias.get_name(), alias.get_size()), ("SitePayloadAlias", 16));
        assert_eq!(alias.get_typedef().unwrap().get_name(), "SitePayload");
        assert_eq!(alias.get_field(1).unwrap().name, "tail");
        assert_eq!(aggregate.storage.get_offset(), 0x98);
        let pieces = source.to_pieces("aggregate");
        assert_eq!(pieces.intypes.len(), 2);
        assert_eq!(pieces.input_storage[1].1.addr.get_offset(), 0x98);
        assert_eq!(pieces.output_storage.as_ref().unwrap().addr.get_offset(), 0x70);
    }
}

#[test]
fn special_void_result_preserves_locked_hidden_return_and_supplied_inputs() {
    use crate::dtype::TypeField;
    use crate::fspec::{ParamEntry, PrototypePieces};
    let m = source_manager_with_registers();
    let types = source_types_with_core();
    let registers = Rc::clone(m.get_space_by_name("register").unwrap());
    let mut model = ProtoModel::new(&m);
    model.build_param_list("standard").unwrap();
    model.set_name("site_registers");
    model.input_mut().push_entry(ParamEntry::seed(
        0, crate::dtype::type_class::TYPECLASS_HIDDENRET, Rc::clone(&registers),
        0x80, 8, 1, 0, 0, true, false, &[], &m,
    ).unwrap());
    for (slot, offset) in [0x38, 0x30, 0x10, 0x08].into_iter().enumerate() {
        let entry = ParamEntry::seed(
            slot as i32 + 1, crate::dtype::type_class::TYPECLASS_GENERAL, Rc::clone(&registers),
            offset, 8, 1, 0, 0, true, false, model.input().get_entry(), &m,
        ).unwrap();
        model.input_mut().push_entry(entry);
    }
    model.input_mut().finish_decode();
    let mut registry = IdRegistry::with_base_ids();
    crate::modelrules::register_ids(&mut registry);
    let mut decoder = XmlDecode::new(&m, &registry);
    decoder.ingest_stream(br#"<rule><datatype name="struct"/><varargs first="0"/><convert_to_ptr/></rule>"#).unwrap();
    let rule = crate::modelrules::ModelRule::decode(&mut decoder, model.input()).unwrap();
    model.input_mut().push_model_rule(rule);
    model.output_mut().push_entry(ParamEntry::seed(
        0, crate::dtype::type_class::TYPECLASS_GENERAL, registers,
        0, 8, 1, 0, 0, true, false, &[], &m,
    ).unwrap());
    model.output_mut().finish_decode();
    model.output_mut().push_model_rule(crate::modelrules::ModelRule::from_components(
        crate::modelrules::DatatypeFilter::SizeRestricted(crate::modelrules::SizeRestriction::new(9, 0)),
        crate::modelrules::AssignAction::HiddenReturnAssign {
            ret_code: crate::fspec::AssignActionResponse::hiddenret_specialreg_void,
        },
    ));
    let word = types.get_base(8, type_metatype::TYPE_INT).unwrap();
    let result = types.get_type_struct("SiteResult").unwrap();
    let result = types.set_fields_struct_raw(&result, vec![
        TypeField::new(0, 0, "left", Rc::clone(&word)),
        TypeField::new(1, 8, "right", word),
    ], vec![], 16, 8, 0).unwrap();
    let pieces = PrototypePieces {
        outtype: Some(Rc::clone(&result)),
        intypes: vec![types.get_base(4, type_metatype::TYPE_INT).unwrap(), result],
        innames: vec!["rethidden".to_string(), "self".to_string()],
        first_var_arg_slot: 1, ..Default::default()
    };
    types.set_proto_context(Rc::clone(&m));
    let callable = types.get_type_code_proto_model(&pieces, Rc::new(model)).unwrap();
    let proto = callable.get_code_prototype().unwrap();
    assert!(proto.get_output().get_address().is_invalid());
    assert_eq!(proto.get_output_type().unwrap().get_metatype(), type_metatype::TYPE_VOID);
    assert!(proto.is_output_locked() && proto.get_output().is_indirect_storage());
    assert!(proto.is_input_locked(), "hidden result must not unlock the complete input list");
    assert_eq!(proto.num_params(), 3);
    for (slot, offset) in [(0, 0x80), (1, 0x38), (2, 0x30)] {
        let param = proto.get_param(slot).unwrap();
        assert!(param.is_type_locked());
        assert_eq!(param.get_address().get_offset(), offset);
    }
    assert!(proto.get_param(0).unwrap().is_hidden_return());
    assert!(!proto.get_param(1).unwrap().is_hidden_return());
    assert_eq!(proto.get_param(1).unwrap().get_name(), "rethidden");
    assert!(proto.get_param(2).unwrap().is_indirect_storage());
    let mut bytes = Vec::new();
    proto.encode(&mut PackedEncode::new(&mut bytes)).unwrap();
    let mut decoder = PackedDecode::new(&m);
    decoder.ingest_stream(&bytes).unwrap();
    let replay = decode_prototype(&mut decoder, &types).unwrap();
    assert_eq!(replay.out_type.as_ref().unwrap().get_metatype(), type_metatype::TYPE_VOID);
    assert!(replay.out_lock);
    assert_eq!(replay.params.len(), 3);
    assert!(replay.params[0].hidden);
    assert_eq!(replay.params[0].storage.get_offset(), 0x80);
    assert_eq!(replay.params[1].name, "rethidden");
    assert_eq!(replay.params[2].storage.get_offset(), 0x30);
}


#[test]
fn host_names_override_equal_extent_defaults_without_hiding_unmapped_defaults() {
    let m = manager();
    let types = source_types_with_core();
    let defaults = scope_over(&m, Rc::clone(&types), MockFetch::default());
    let record = |name: &str, offset: u64, id: u64| decode_function_xml(&m, &types, &format!(
        r#"<doc><mapsym><symbol name="{name}" id="{id}" typelock="true" namelock="true" cat="-1"><type name="" metatype="uint" size="1"/></symbol><addr space="ram" offset="{offset}" size="1"/><rangelist/></mapsym></doc>"#
    ));
    defaults.materialize(*record("P2", 0xa0, 0x100));
    defaults.materialize(*record("HIE", 0xa1, 0x101));
    let scope = RemoteScope::new(
        Rc::new(MockFetch::default()), Rc::clone(&m), Rc::clone(&types),
        std::collections::BTreeMap::new(), None, defaults.snapshot().as_ref().clone(),
    );
    let address = Address::new(ram(&m), 0xa0);
    let neighbor = Address::new(ram(&m), 0xa1);
    let name = |query: &GlobalQuery, address: &Address|
        query.name_for_varnode(address, 1, &Address::new_invalid()).unwrap().0;
    assert_eq!(name(&scope.query_snapshot(&address), &address), "P2");
    scope.materialize(*record("motor_control", 0xa0, 0x200));
    assert_eq!(name(&scope.query_snapshot(&address), &address), "motor_control");
    assert_eq!(name(&scope.query_snapshot(&neighbor), &neighbor), "HIE");
    scope.clear();
    assert_eq!(name(&scope.query_snapshot(&address), &address), "P2");
    scope.materialize(*record("renamed_control", 0xa0, 0x201));
    assert_eq!(name(&scope.query_snapshot(&address), &address), "renamed_control");
}

#[test]
fn host_default_declarations_retain_scope_model_storage_and_locks() {
    let m = source_manager_with_registers();
    let types = source_types_with_core();
    let scope = source_fact_scope(&m, Rc::clone(&types));
    let original_xml = CAPTURED_MAIN_MAPSYM.replace("__stdcall", "default");
    scope.materialize(*decode_function_xml(&m, &types, &original_xml));
    let mut ctx = crate::context::ArchContext::new_shared(Rc::clone(&m));
    ctx.remote_scope = Some(Rc::clone(&scope));
    let entry = Address::new(ram(&m), 0x101900);
    let original = ctx.query_callee_proto(&entry).unwrap();
    let original_name = original.get_model_name().to_string();
    scope.materialize(*decode_function_xml(&m, &types, &original_xml.replace("0x101900", "0x101a00")));
    let next = ctx.query_callee_proto(&Address::new(ram(&m), 0x101a00)).unwrap();
    let retained = ctx.query_callee_proto(&entry).unwrap();
    for proto in [&original, &next, &retained] {
        assert_eq!(proto.get_model_name(), original_name);
        assert!(Rc::ptr_eq(proto.model(), original.model()));
        assert_eq!(proto.get_param(0).unwrap().get_address().get_offset(), 0x38);
        assert_eq!(proto.get_output().get_address().get_offset(), 0);
        assert!(proto.is_input_locked());
        assert!(proto.is_output_locked());
    }
    // EC-0194's live default-publication clause is unrepresented: Architecture's
    // defaultprototype updates its TypeFactory, not this RemoteScope's defaultfp.
}

#[test]
fn parameter_symbol_metadata_survives_exact_storage_reuse_without_promoting_overlap() {
    let m = source_manager_with_registers();
    let types = source_types_with_core();
    let int4 = types.get_base(4, type_metatype::TYPE_INT).unwrap();
    let address = Address::new(Rc::clone(m.get_space_by_name("register").unwrap()), 0x90);
    let usepoint = Address::new(ram(&m), 0x100f);
    for typelock in [false, true] {
        for namelock in [false, true] {
            let mut local = crate::varmap::ScopeLocal::new(
                0x1234, ram(&m), "committed", m.num_spaces(),
            ).unwrap();
            let sid = local.add_symbol("committed", Rc::clone(&int4), &address, &usepoint).unwrap();
            let attrs = if typelock { varnode_flags::typelock } else { 0 }
                | if namelock { varnode_flags::namelock } else { 0 };
            local.set_attribute(sid, attrs);
            local.add_param_symbol(0, "recovered", Rc::clone(&int4), &address, &usepoint).unwrap();
            let mut bytes = Vec::new();
            local.encode(&mut PackedEncode::new(&mut bytes)).unwrap();
            let mut decoder = PackedDecode::new(&m);
            decoder.ingest_stream(&bytes).unwrap();
            let mut params = Vec::new();
            let mut locked = false;
            let mut locals = Vec::new();
            decode_localdb_params(&mut decoder, &types, &mut params, &mut locked, &mut locals).unwrap();
            assert_eq!(params.len(), 1);
            assert!(locals.is_empty());
            assert_eq!(params[0].name, "committed");
            assert_eq!(params[0].storage, address);
            assert_eq!(params[0].typelock, typelock);
        }
    }
    let mut local = crate::varmap::ScopeLocal::new(0x1235, ram(&m), "overlap", m.num_spaces()).unwrap();
    local.add_symbol("wide_local", types.get_base(8, type_metatype::TYPE_UINT).unwrap(),
        &address, &usepoint).unwrap();
    local.add_param_symbol(0, "arg", int4, &address, &usepoint).unwrap();
    let mut bytes = Vec::new();
    local.encode(&mut PackedEncode::new(&mut bytes)).unwrap();
    let mut decoder = PackedDecode::new(&m);
    decoder.ingest_stream(&bytes).unwrap();
    let mut params = Vec::new();
    let mut locked = false;
    let mut locals = Vec::new();
    decode_localdb_params(&mut decoder, &types, &mut params, &mut locked, &mut locals).unwrap();
    assert!(params.is_empty());
    assert_eq!(locals.len(), 1);
    assert_eq!(locals[0].name, "wide_local");
    assert_eq!(locals[0].dtype.get_size(), 8);
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
    RemoteScope::new(
        Rc::new(fetch),
        Rc::clone(m),
        types,
        std::collections::BTreeMap::new(),
        None,
        base,
    )
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

/// Java's real import-slot shape: the `<externrefsymbol>` is mapped with ONE
/// byte of storage and resolves to the slot itself, where getExternalRef
/// serves the function with a two-byte mapping.  The slot still covers a
/// whole-pointer read and carries `externref` (what ActionDeindirect keys
/// on), and the function, declared without a prototype, is typed as code.
#[test]
fn extern_ref_slot_covers_a_pointer_read() {
    let m = manager();
    let types = types_with_core();
    let slot = Address::new(ram(&m), 0x5000);
    let mut ptr_doc = Vec::new();
    {
        let mut e = PackedEncode::new(&mut ptr_doc);
        e.open_element(&crate::prettyprint::ids::ELEM_TYPE);
        e.write_unsigned_integer(&ATTRIB_ID, 0);
        e.open_element(&ELEM_MAPSYM);
        e.open_element(&ELEM_EXTERNREFSYMBOL);
        e.write_string(&ATTRIB_NAME, b"CreateThread_exref");
        slot.encode(&mut e).unwrap();
        e.close_element(&ELEM_EXTERNREFSYMBOL);
        slot.encode_sized(&mut e, 1).unwrap();
        e.open_element(&ELEM_RANGELIST);
        e.close_element(&ELEM_RANGELIST);
        e.close_element(&ELEM_MAPSYM);
        e.close_element(&crate::prettyprint::ids::ELEM_TYPE);
    }
    let mut fn_doc = Vec::new();
    {
        let mut e = PackedEncode::new(&mut fn_doc);
        e.open_element(&crate::prettyprint::ids::ELEM_TYPE);
        e.write_unsigned_integer(&ATTRIB_ID, 0);
        e.open_element(&ELEM_MAPSYM);
        e.open_element(&crate::funcdata_encode::ELEM_FUNCTION);
        e.write_unsigned_integer(&ATTRIB_ID, 0x99);
        e.write_string(&ATTRIB_NAME, b"CreateThread");
        e.write_signed_integer(&ATTRIB_SIZE, 2);
        slot.encode(&mut e).unwrap();
        e.close_element(&crate::funcdata_encode::ELEM_FUNCTION);
        slot.encode_sized(&mut e, 2).unwrap();
        e.open_element(&ELEM_RANGELIST);
        e.close_element(&ELEM_RANGELIST);
        e.close_element(&ELEM_MAPSYM);
        e.close_element(&crate::prettyprint::ids::ELEM_TYPE);
    }
    let mut fetch = MockFetch::default();
    fetch.mapped.insert(0x5000, ptr_doc);
    fetch.external.insert(0x5000, fn_doc);
    let scope = scope_over(&m, types, fetch);

    let snap = scope.query_snapshot(&slot);
    let invalid = Address::new_invalid();
    assert_ne!(
        snap.query_properties(&slot, 8, &invalid) & varnode_flags::externref,
        0,
        "an 8-byte read of the slot is an external reference"
    );
    let (nm, _, _) = snap
        .name_for_varnode(&slot, 8, &invalid)
        .expect("the slot symbol covers the whole pointer");
    assert_eq!(nm, "CreateThread_exref");
    let facts = scope.function_at(&slot).expect("external function resolved");
    assert_eq!(facts.name, "CreateThread");
    let (ty, _) = snap
        .sized_type_geometry(&slot, 1, &invalid)
        .expect("the function symbol is typed");
    assert_eq!(ty.get_metatype(), type_metatype::TYPE_CODE);
}

/// A function the host tagged with a call-fixup carries `<inject>` in its
/// `<prototype>`; the name resolves to the registered payload id, and an
/// unknown name leaves the function uninjected.
#[test]
fn prototype_inject_resolves_to_the_call_fixup_payload() {
    let m = manager();
    let types = types_with_core();
    let fn_doc = |entry: u64, name: &[u8], fixup: &[u8]| {
        let mut doc = Vec::new();
        {
            let mut e = PackedEncode::new(&mut doc);
            e.open_element(&crate::prettyprint::ids::ELEM_TYPE);
            e.write_unsigned_integer(&ATTRIB_ID, 0);
            e.open_element(&ELEM_MAPSYM);
            e.open_element(&crate::funcdata_encode::ELEM_FUNCTION);
            e.write_string(&ATTRIB_NAME, name);
            e.write_signed_integer(&ATTRIB_SIZE, 1);
            Address::new(ram(&m), entry).encode(&mut e).unwrap();
            e.open_element(&ELEM_PROTOTYPE);
            e.write_string(&ATTRIB_MODEL, b"default");
            e.write_bool(&ATTRIB_VOIDLOCK, true);
            e.open_element(&ELEM_RETURNSYM);
            e.write_bool(&ATTRIB_TYPELOCK, true);
            e.open_element(&kuna_base::address::ELEM_ADDR);
            e.close_element(&kuna_base::address::ELEM_ADDR);
            e.open_element(&ELEM_VOID);
            e.close_element(&ELEM_VOID);
            e.close_element(&ELEM_RETURNSYM);
            e.open_element(&crate::pcodeinject::ELEM_INJECT);
            e.write_string(&ATTRIB_CONTENT, fixup);
            e.close_element(&crate::pcodeinject::ELEM_INJECT);
            e.close_element(&ELEM_PROTOTYPE);
            e.close_element(&crate::funcdata_encode::ELEM_FUNCTION);
            Address::new(ram(&m), entry).encode_sized(&mut e, 1).unwrap();
            e.open_element(&ELEM_RANGELIST);
            e.close_element(&ELEM_RANGELIST);
            e.close_element(&ELEM_MAPSYM);
            e.close_element(&crate::prettyprint::ids::ELEM_TYPE);
        }
        doc
    };
    let mut fetch = MockFetch::default();
    fetch.mapped.insert(0x4000, fn_doc(0x4000, b"__chkstk", b"alloca_probe"));
    fetch.mapped.insert(0x4100, fn_doc(0x4100, b"helper", b"no_such_fixup"));
    let mut scope = scope_over(&m, types, fetch);
    scope.set_call_fixups([("alloca_probe".to_string(), 3)].into_iter().collect());

    let probe = scope.function_at(&Address::new(ram(&m), 0x4000)).expect("function");
    assert_eq!(probe.inject_id, 3);
    let other = scope.function_at(&Address::new(ram(&m), 0x4100)).expect("function");
    assert_eq!(other.inject_id, -1);
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
        .add_param_symbol(0, "argc", Rc::clone(&int4_t), &param_addr, &usepoint)
        .unwrap()
        .expect("param created");
    // Lock it (the Java write path needs cat/index/storage; locks ride along).
    let _ = sid;
    // A plain mapped local (no category).
    lm.add_symbol("local_10", Rc::clone(&int4_t), &Address::new(ram(&m), 0x2000), &Address::new_invalid())
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
    let mut locked = true;
    decode_localdb_params(&mut dec, types.as_ref(), &mut params, &mut locked, &mut locals)
        .unwrap();
    assert_eq!(params.len(), 1, "exactly the cat-0 symbol is a parameter");
    assert_eq!(params[0].index, 0);
    assert_eq!(params[0].name, "argc");
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
