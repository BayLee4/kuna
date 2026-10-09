//! GATE for `cspecprotos`: the compiler spec's NAMED prototype models are
//! registered, so the model registry can hold more than one calling convention.
//!
//! Before this, `Architecture::build_default_proto` read only
//! `<default_proto><prototype>`, so `protoModels` held exactly one entry and
//! `getModel("__thiscall")` — the lookup behind `option defaultprototype` and
//! behind every `hasThisPointer` consumer — could never resolve.
//!
//! These assertions run against the *real* vendored cspecs (x86win, x86-64-win,
//! x86gcc, x86-64-gcc), decoded through the same `init_post_engine` path the CLI
//! uses.  They are the sharp form of the end-to-end witness in
//! `tests/stages/ghdec-cspecprotos.xml`: a registry query, not a rendering.

use std::path::PathBuf;
use std::rc::Rc;

use kuna_base::error::{KunaError, KunaResult};
use kuna_base::marshal::IdRegistry;
use kuna_base::xml::{DocumentStorage, Element};

use kuna_decomp::architecture::Architecture;
use kuna_decomp::sleigh_arch::{register_sleigh_arch_ids, LanguageDatabase};
use kuna_decomp::xml_arch::{XmlArchitecture, XmlArchitectureCapability};

use kuna_base::address::Address;
use kuna_sleigh::loadimage::LoadImage;
use kuna_sleigh::loadimage_xml::register_loadimage_xml_ids;
use kuna_sleigh::translate::register_translate_ids;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../..").canonicalize().unwrap()
}

struct DummyImg;
impl LoadImage for DummyImg {
    fn get_file_name(&self) -> &str {
        "dummy"
    }
    fn load_fill(&mut self, _ptr: &mut [u8], _addr: &Address) -> KunaResult<()> {
        Err(KunaError::data_unavail("dummy"))
    }
    fn get_arch_type(&self) -> Vec<u8> {
        Vec::new()
    }
    fn adjust_vma(&mut self, _adjust: i64) {}
}

fn build_registry() -> IdRegistry {
    let mut registry = IdRegistry::with_base_ids();
    register_translate_ids(&mut registry);
    register_sleigh_arch_ids(&mut registry);
    register_loadimage_xml_ids(&mut registry);
    registry
}

/// Bootstrap an architecture for `arch_id` over the vendored specs, running the
/// cspec decode (`init_post_engine` -> `build_default_proto`) but not opening an
/// image: the prototype-model registry is fully populated at that point.
fn bootstrap(arch_id: &str) -> Result<XmlArchitecture, String> {
    let root = repo_root();
    let registry = build_registry();
    let mut store = DocumentStorage::new();
    let img_xml = format!(
        r#"<binaryimage arch="{arch_id}"><bytechunk space="ram" offset="0x1000">c3</bytechunk></binaryimage>"#
    );
    let binaryimage: Rc<Element> = store
        .parse_document(img_xml.as_bytes())
        .map_err(|e| format!("parse image: {e}"))?
        .get_root()
        .clone();

    let capability = XmlArchitectureCapability::new();
    let mut arch = capability.build_architecture("cspecprotos", "");
    arch.build_loader(binaryimage).map_err(|e| format!("build_loader: {e}"))?;
    let mut db = LanguageDatabase::new();
    db.scan_for_sleigh_directories(root.join("specs").to_str().unwrap());
    db.get_descriptions(&registry).map_err(|e| format!("collect ldefs: {e}"))?;
    arch.sleigh_mut().set_archid(arch_id);
    arch.sleigh_mut()
        .resolve_architecture(&db, arch_id)
        .map_err(|e| format!("resolve_architecture: {e}"))?;
    let specs = arch.sleigh().build_spec_file(&db).map_err(|e| format!("build_spec_file: {e}"))?;
    let resolved_sla = specs.slafile.ok_or("build_spec_file resolved no .sla")?;
    let sla = std::fs::read(&resolved_sla).map_err(|e| format!("read sla: {e}"))?;
    arch.sleigh_mut()
        .build_translator(Box::new(DummyImg), &sla)
        .map_err(|e| format!("build_translator: {e}"))?;
    let cspec = std::fs::read(&specs.compilerfile)
        .map_err(|e| format!("read cspec {}: {e}", specs.compilerfile))?;
    arch.sleigh_mut().base_mut().ok_or("no Architecture base")?.set_cspec_xml(cspec);
    arch.sleigh_mut()
        .base_mut()
        .ok_or("no Architecture base")?
        .init_post_engine()
        .map_err(|e| format!("init_post_engine: {e}"))?;
    Ok(arch)
}

fn arch_of(x: &XmlArchitecture) -> &Architecture {
    x.sleigh().base().expect("Architecture base")
}

const RECURSIVE_NODE_HOST_ID: u64 = 0x71000001;
const RECURSIVE_FN_HOST_ID: u64 = 0x71000002;
const RECURSIVE_ALIAS_HOST_ID: u64 = 0x71000003;

struct RecursiveCallableReplies {
    node: Vec<u8>,
    function: Vec<u8>,
    alias: Vec<u8>,
}

impl kuna_decomp::dtype::RemoteTypeFetch for RecursiveCallableReplies {
    fn fetch_data_type(
        &self, name: &str, id: u64, decoder: &mut dyn kuna_base::marshal::Decoder,
    ) -> KunaResult<bool> {
        let bytes = match (name, id) {
            ("RecursiveNode", RECURSIVE_NODE_HOST_ID) => &self.node,
            ("RecursiveFn", RECURSIVE_FN_HOST_ID) => &self.function,
            ("RecursiveAlias", RECURSIVE_ALIAS_HOST_ID) => &self.alias,
            _ => return Ok(false),
        };
        decoder.ingest_stream(bytes)?;
        Ok(true)
    }
}

fn encode_recursive_typeref(
    encoder: &mut dyn kuna_base::marshal::Encoder, name: &str, id: u64, size: Option<i32>,
) {
    use kuna_base::marshal::{ATTRIB_ID, ATTRIB_NAME, ATTRIB_SIZE};
    use kuna_decomp::dtype::ELEM_TYPEREF;
    encoder.open_element(&ELEM_TYPEREF);
    encoder.write_string(&ATTRIB_NAME, name.as_bytes());
    encoder.write_unsigned_integer(&ATTRIB_ID, id);
    if let Some(size) = size { encoder.write_signed_integer(&ATTRIB_SIZE, i64::from(size)); }
    encoder.close_element(&ELEM_TYPEREF);
}

fn recursive_callable_replies(model: &str, with_alias: bool) -> RecursiveCallableReplies {
    use kuna_base::address::ATTRIB_FIRST;
    use kuna_base::marshal::{
        Encoder, PackedEncode, ATTRIB_ID, ATTRIB_METATYPE, ATTRIB_MODEL, ATTRIB_NAME,
        ATTRIB_OFFSET, ATTRIB_SIZE,
    };
    use kuna_decomp::dtype::{ATTRIB_ALIGNMENT, ELEM_DEF};
    use kuna_decomp::prettyprint::ids::{ELEM_FIELD, ELEM_TYPE};
    use kuna_decomp::remote_provider::{
        ATTRIB_DOTDOTDOT, ELEM_INTERNALLIST, ELEM_PROTOTYPE, ELEM_RETURNSYM,
    };
    let parameter = kuna_base::marshal::ElementId::new("param", 166);
    let mut node = Vec::new();
    {
        let mut e = PackedEncode::new(&mut node);
        e.open_element(&ELEM_TYPE);
        e.write_string(&ATTRIB_NAME, b"RecursiveNode");
        e.write_unsigned_integer(&ATTRIB_ID, RECURSIVE_NODE_HOST_ID);
        e.write_string(&ATTRIB_METATYPE, b"struct");
        e.write_signed_integer(&ATTRIB_SIZE, 16);
        e.write_signed_integer(&ATTRIB_ALIGNMENT, 8);
        e.open_element(&ELEM_FIELD);
        e.write_string(&ATTRIB_NAME, b"d");
        e.write_signed_integer(&ATTRIB_ID, 101);
        e.write_signed_integer(&ATTRIB_OFFSET, 0);
        e.open_element(&ELEM_TYPE);
        e.write_string(&ATTRIB_NAME, b"");
        e.write_string(&ATTRIB_METATYPE, b"float");
        e.write_signed_integer(&ATTRIB_SIZE, 8);
        e.close_element(&ELEM_TYPE);
        e.close_element(&ELEM_FIELD);
        e.open_element(&ELEM_FIELD);
        e.write_string(&ATTRIB_NAME, b"next");
        e.write_signed_integer(&ATTRIB_ID, 203);
        e.write_signed_integer(&ATTRIB_OFFSET, 8);
        e.open_element(&ELEM_TYPE);
        e.write_string(&ATTRIB_NAME, b"");
        e.write_string(&ATTRIB_METATYPE, b"ptr");
        e.write_signed_integer(&ATTRIB_SIZE, 8);
        encode_recursive_typeref(&mut e, "RecursiveFn", RECURSIVE_FN_HOST_ID, Some(1));
        e.close_element(&ELEM_TYPE);
        e.close_element(&ELEM_FIELD);
        e.close_element(&ELEM_TYPE);
    }
    let mut alias = Vec::new();
    {
        let mut e = PackedEncode::new(&mut alias);
        e.open_element(&ELEM_DEF);
        e.write_string(&ATTRIB_NAME, b"RecursiveAlias");
        e.write_unsigned_integer(&ATTRIB_ID, RECURSIVE_ALIAS_HOST_ID);
        encode_recursive_typeref(&mut e, "RecursiveNode", RECURSIVE_NODE_HOST_ID, None);
        e.close_element(&ELEM_DEF);
    }
    let (name, id) = if with_alias {
        ("RecursiveAlias", RECURSIVE_ALIAS_HOST_ID)
    } else { ("RecursiveNode", RECURSIVE_NODE_HOST_ID) };
    let mut function = Vec::new();
    {
        let mut e = PackedEncode::new(&mut function);
        e.open_element(&ELEM_TYPE);
        e.write_string(&ATTRIB_NAME, b"RecursiveFn");
        e.write_unsigned_integer(&ATTRIB_ID, RECURSIVE_FN_HOST_ID);
        e.write_string(&ATTRIB_METATYPE, b"code");
        e.write_signed_integer(&ATTRIB_SIZE, 1);
        e.open_element(&ELEM_PROTOTYPE);
        e.write_string(&ATTRIB_MODEL, model.as_bytes());
        e.write_bool(&ATTRIB_DOTDOTDOT, false);
        e.open_element(&ELEM_RETURNSYM);
        Address::new_invalid().encode(&mut e).unwrap();
        encode_recursive_typeref(&mut e, name, id, None);
        e.close_element(&ELEM_RETURNSYM);
        e.open_element(&ELEM_INTERNALLIST);
        e.write_signed_integer(&ATTRIB_FIRST, -1);
        e.open_element(&parameter);
        e.write_string(&ATTRIB_NAME, b"node");
        Address::new_invalid().encode(&mut e).unwrap();
        encode_recursive_typeref(&mut e, name, id, None);
        e.close_element(&parameter);
        e.close_element(&ELEM_INTERNALLIST);
        e.close_element(&ELEM_PROTOTYPE);
        e.close_element(&ELEM_TYPE);
    }
    RecursiveCallableReplies { node, function, alias }
}

fn decode_recursive_typeref(
    arch: &Architecture, name: &str, id: u64, size: Option<i32>,
) -> KunaResult<Rc<kuna_decomp::dtype::Datatype>> {
    use kuna_base::marshal::{Decoder, PackedDecode, PackedEncode};
    let mut bytes = Vec::new();
    encode_recursive_typeref(&mut PackedEncode::new(&mut bytes), name, id, size);
    let mut decoder = PackedDecode::new(arch.manage());
    decoder.ingest_stream(&bytes)?;
    arch.types_impl().decode_type(&mut decoder)
}

fn assert_recursive_join(arch: &Architecture, address: &Address, registers: [&str; 2]) {
    assert_eq!(address.get_space().unwrap().get_type(), kuna_base::space::spacetype::IPTR_JOIN);
    let join = arch.manage().find_join(address.get_offset()).unwrap();
    assert_eq!(join.get_unified().size, 16);
    assert_eq!(join.num_pieces(), 2);
    for (index, register) in registers.into_iter().enumerate() {
        let expected = arch.translate().get_register_varnode(register.as_bytes()).unwrap();
        let actual = join.get_piece(index as i32);
        assert_eq!(actual.space.as_ref().unwrap().get_name(), expected.space.as_ref().unwrap().get_name());
        assert_eq!((actual.offset, actual.size), (expected.offset, 8), "{register}");
    }
}

#[test]
fn recursive_host_callable_decodes_and_assigns_real_target_abis_in_both_query_orders() {
    use kuna_decomp::dtype::type_metatype;
    for (target, inputs, output) in [
        ("x86:LE:64:default:gcc", ["RDI", "XMM0"], ["RAX", "XMM0"]),
        ("AARCH64:LE:64:v8A:default", ["x1", "x0"], ["x1", "x0"]),
        ("AARCH64:LE:64:AppleSilicon:default", ["x1", "x0"], ["x1", "x0"]),
    ] {
        for with_alias in [false, true] {
            for callback_first in [false, true] {
                let architecture = bootstrap(target).unwrap_or_else(|e| panic!("{target}: {e}"));
                let arch = arch_of(&architecture);
                let factory = arch.types_impl();
                let model = arch.default_fp().unwrap();
                factory.set_remote_type_fetch(Some(Rc::new(recursive_callable_replies(model.get_name(), with_alias))));
                if callback_first {
                    decode_recursive_typeref(arch, "RecursiveFn", RECURSIVE_FN_HOST_ID, Some(1)).unwrap();
                } else {
                    decode_recursive_typeref(arch, "RecursiveNode", RECURSIVE_NODE_HOST_ID, None).unwrap();
                }
                let node = decode_recursive_typeref(arch, "RecursiveNode", RECURSIVE_NODE_HOST_ID, None).unwrap();
                let function = decode_recursive_typeref(arch, "RecursiveFn", RECURSIVE_FN_HOST_ID, Some(1)).unwrap();
                let declared = if with_alias {
                    decode_recursive_typeref(arch, "RecursiveAlias", RECURSIVE_ALIAS_HOST_ID, None).unwrap()
                } else { Rc::clone(&node) };
                assert_eq!((node.get_size(), node.get_alignment(), node.is_incomplete()), (16, 8, false));
                let value = node.get_field(0).unwrap();
                assert_eq!((value.name.as_str(), value.ident, value.offset), ("d", 101, 0));
                assert_eq!(value.field_type.get_metatype(), type_metatype::TYPE_FLOAT);
                let next = node.get_field(1).unwrap();
                assert_eq!((next.name.as_str(), next.ident, next.offset), ("next", 203, 8));
                let callback = next.field_type.get_ptr_to().unwrap();
                let proto = function.get_code_prototype().expect("host callback declaration must survive decoding");
                assert!(callback.get_code_prototype().is_some(), "early recursive callback reference");
                assert_eq!(proto.get_model_name(), model.get_name());
                assert_eq!(proto.num_params(), 1);
                assert!(!proto.is_dotdotdot());
                let input = proto.get_param(0).unwrap();
                assert_eq!(input.get_type().unwrap().get_id(), declared.get_id());
                assert_eq!(proto.get_output().get_type().unwrap().get_id(), declared.get_id());
                assert!(!input.is_hidden_return() && !input.is_indirect_storage());
                assert_recursive_join(arch, &input.get_address(), inputs);
                assert_recursive_join(arch, &proto.get_output().get_address(), output);
            }
        }
    }
}

#[test]
fn recursive_alias_callable_waits_for_layout_before_assigning_aggregate_storage() {
    use kuna_decomp::dtype::{type_metatype, TypeFactory, TypeField};
    use kuna_decomp::fspec::PrototypePieces;
    let architecture = bootstrap("x86:LE:64:default:gcc").unwrap();
    let arch = arch_of(&architecture);
    let factory = arch.types_impl();
    let node = factory.kuna_declare_record("PendingNode", false).unwrap();
    let alias = factory.get_typedef(&node, "PendingNodeAlias", RECURSIVE_ALIAS_HOST_ID, 0).unwrap();
    let pieces = |value: Rc<kuna_decomp::dtype::Datatype>| PrototypePieces {
        name: "callback".to_string(), outtype: Some(Rc::clone(&value)),
        intypes: vec![value], innames: vec!["node".to_string()],
        first_var_arg_slot: -1, ..Default::default()
    };
    assert!(factory.get_type_code_proto(&pieces(alias)).is_err(),
        "an unresolved by-value layout cannot publish assigned storage");
    let callback_pointer = factory.get_type_pointer(8, factory.get_type_code().unwrap(), 1).unwrap();
    factory.set_fields_struct_raw(&node, vec![
        TypeField::new(101, 0, "d", factory.get_base(8, type_metatype::TYPE_FLOAT).unwrap()),
        TypeField::new(203, 8, "next", callback_pointer),
    ], vec![], 16, 8, 0).unwrap();
    let ready = factory.find_by_name("PendingNodeAlias").unwrap().unwrap();
    let callback = factory.get_type_code_proto(&pieces(ready)).unwrap();
    let proto = callback.get_code_prototype().unwrap();
    assert_eq!(proto.num_params(), 1);
    assert_recursive_join(arch, &proto.get_param(0).unwrap().get_address(), ["RDI", "XMM0"]);
    assert_recursive_join(arch, &proto.get_output().get_address(), ["RAX", "XMM0"]);
}


#[test]
fn failed_callable_alias_is_an_error_before_and_after_declaration() {
    use kuna_decomp::dtype::TypeFactory;
    let architecture = bootstrap("x86:LE:64:default:gcc").unwrap();
    let arch = arch_of(&architecture);
    let factory = arch.types_impl();
    for callback_first in [false, true] {
        factory.clear_noncore();
        let mut replies = recursive_callable_replies(arch.default_fp().unwrap().get_name(), true);
        replies.alias.clear();
        factory.set_remote_type_fetch(Some(Rc::new(replies)));
        if !callback_first {
            assert!(decode_recursive_typeref(arch, "RecursiveAlias", RECURSIVE_ALIAS_HOST_ID, None).is_err());
        }
        assert!(decode_recursive_typeref(arch, "RecursiveFn", RECURSIVE_FN_HOST_ID, Some(1)).is_err(),
            "an unavailable by-value source must not become a generic unprototyped callback");
        assert!(decode_recursive_typeref(arch, "RecursiveAlias", RECURSIVE_ALIAS_HOST_ID, None).is_err());
    }
}


#[test]
fn deferred_callable_rejects_invalid_alias_targets_without_poisoning_valid_retry() {
    use kuna_decomp::dtype::{type_metatype, TypeFactory};
    use kuna_decomp::fspec::PrototypePieces;
    let architecture = bootstrap("x86:LE:64:default:gcc").unwrap();
    let arch = arch_of(&architecture);
    let factory = arch.types_impl();
    for invalid in [factory.get_type_void().unwrap(), factory.get_type_code().unwrap()] {
        let alias = factory.get_typedef(&invalid, "InvalidValue", 0, 0).unwrap();
        let pieces = PrototypePieces {
            outtype: Some(Rc::clone(&alias)), intypes: vec![alias],
            innames: vec!["invalid".to_string()], first_var_arg_slot: -1, ..Default::default()
        };
        assert!(factory.get_type_code_proto(&pieces).is_err());
        factory.clear_noncore();
        let valid = factory.get_typedef(
            &factory.get_base(8, type_metatype::TYPE_INT).unwrap(), "ValidValue", 0, 0,
        ).unwrap();
        let pieces = PrototypePieces {
            outtype: Some(Rc::clone(&valid)), intypes: vec![Rc::clone(&valid)],
            innames: vec!["value".to_string()], first_var_arg_slot: -1, ..Default::default()
        };
        let callable = factory.get_type_code_proto(&pieces).unwrap();
        let proto = callable.get_code_prototype().unwrap();
        for (param, name) in [(proto.get_param(0).unwrap(), "RDI"), (proto.get_output(), "RAX")] {
            let register = arch.translate().get_register_varnode(name.as_bytes()).unwrap();
            assert_eq!(param.get_address().get_offset(), register.offset);
            assert_eq!(param.get_type().unwrap().get_id(), valid.get_id());
        }
    }
}

/// The x86 Windows spec declares four models plus a merged resolver; every one
/// of them must resolve by name, and `__thiscall` must carry `hasThisPointer`.
#[test]
fn x86win_registers_every_named_model() {
    let x = bootstrap("x86:LE:32:default:windows").expect("bootstrap x86win");
    let arch = arch_of(&x);
    // The whole point: the registry used to hold exactly one model.
    assert!(
        arch.num_proto_models() > 1,
        "registry holds {} model(s): {:?}",
        arch.num_proto_models(),
        arch.proto_model_names().collect::<Vec<_>>()
    );
    assert_eq!(arch.default_fp().unwrap().get_name(), "__stdcall");
    for nm in ["__stdcall", "__cdecl", "__fastcall", "__thiscall"] {
        assert!(arch.has_model(nm), "x86win cspec model {nm} is not registered");
    }
    let thiscall = arch.get_model("__thiscall").unwrap();
    assert!(thiscall.has_this_pointer(), "__thiscall must set hasThisPointer");
    assert!(!arch.get_model("__stdcall").unwrap().has_this_pointer());
    // The merged <resolveprototype> folds its three constituents in.
    let merged = arch
        .get_model("__fastcall/__thiscall/__stdcall")
        .expect("x86win <resolveprototype> is not registered");
    assert!(merged.is_merged());
    assert_eq!(merged.num_models(), 3);
}

/// `__thiscall`'s first `<pentry>` is ECX, which is what makes the model worth
/// registering: the default `__stdcall` list has no register entry at all.
#[test]
fn x86win_thiscall_passes_the_first_parameter_in_ecx() {
    let x = bootstrap("x86:LE:32:default:windows").expect("bootstrap x86win");
    let arch = arch_of(&x);
    let ecx = arch.translate().get_register_varnode(b"ECX").expect("ECX register");
    let thiscall = arch.get_model("__thiscall").unwrap();
    let addr = Address::new(Rc::clone(ecx.space.as_ref().unwrap()), ecx.offset);
    assert!(
        thiscall.possible_input_param(&addr, ecx.size as i32),
        "__thiscall must accept ECX as an input parameter"
    );
    let stdcall = arch.get_model("__stdcall").unwrap();
    assert!(
        !stdcall.possible_input_param(&addr, ecx.size as i32),
        "__stdcall must not accept ECX as an input parameter"
    );
}

/// x86-64 Windows declares `__thiscall` plus two `<modelalias>` copies of the
/// default; the aliases are named copies, not the parent object.
#[test]
fn x86_64_win_registers_thiscall_and_the_model_aliases() {
    let x = bootstrap("x86:LE:64:default:windows").expect("bootstrap x86-64-win");
    let arch = arch_of(&x);
    assert_eq!(arch.default_fp().unwrap().get_name(), "__fastcall");
    for nm in ["__fastcall", "__thiscall", "__cdecl", "__stdcall"] {
        assert!(arch.has_model(nm), "x86-64-win cspec model {nm} is not registered");
    }
    assert!(arch.get_model("__thiscall").unwrap().has_this_pointer());
    // <modelalias name="__cdecl" parent="__fastcall"/>: a compatible named copy.
    let alias = arch.get_model("__cdecl").unwrap();
    let parent = arch.get_model("__fastcall").unwrap();
    assert_eq!(alias.get_name(), "__cdecl");
    assert!(alias.is_compatible(parent), "a <modelalias> must stay compatible with its parent");
}

/// The ELF specs register their own named models, and the 32-bit gcc spec has a
/// `__thiscall` too — so this is not a PE-only capability.
#[test]
fn elf_specs_register_their_named_models() {
    let x = bootstrap("x86:LE:32:default:gcc").expect("bootstrap x86gcc");
    let arch = arch_of(&x);
    assert_eq!(arch.default_fp().unwrap().get_name(), "__cdecl");
    for nm in ["__cdecl", "__thiscall", "__regparm1", "__regparm2", "__regparm3", "syscall"] {
        assert!(arch.has_model(nm), "x86gcc cspec model {nm} is not registered");
    }
    assert!(arch.get_model("__thiscall").unwrap().has_this_pointer());
    assert!(arch.get_model("__cdecl/__regparm").unwrap().is_merged());

    let x = bootstrap("x86:LE:64:default:gcc").expect("bootstrap x86-64-gcc");
    let arch = arch_of(&x);
    assert_eq!(arch.default_fp().unwrap().get_name(), "__stdcall");
    for nm in ["__stdcall", "MSABI", "syscall", "processEntry"] {
        assert!(arch.has_model(nm), "x86-64-gcc cspec model {nm} is not registered");
    }
}

/// C++ `parseCompilerConfig` guarantees a `__thiscall` model on every language,
/// cloning it off the default when the spec declares none (architecture.cc:1342).
#[test]
fn every_language_has_a_thiscall_model() {
    // x86-64-gcc and AARCH64 gcc declare no <prototype name="__thiscall">.
    for id in ["x86:LE:64:default:gcc", "AARCH64:LE:64:v8A", "ARM:LE:32:v7"] {
        let x = bootstrap(id).unwrap_or_else(|e| panic!("bootstrap {id}: {e}"));
        let arch = arch_of(&x);
        let m = arch
            .get_model("__thiscall")
            .unwrap_or_else(|| panic!("{id} has no __thiscall model"));
        assert!(m.has_this_pointer(), "{id}: the cloned __thiscall must set hasThisPointer");
        // Cloned off the default, so it is a compatible named copy of it.
        assert!(m.is_compatible(arch.default_fp().unwrap()));
    }
}

/// Registration must not disturb the default model: it is still the object
/// `defaultfp` points at, with the same storage the `<default_proto>` decode
/// produced before named models were read.
#[test]
fn the_default_model_is_untouched_by_the_named_models() {
    let x = bootstrap("x86:LE:32:default:windows").expect("bootstrap x86win");
    let arch = arch_of(&x);
    let defaultfp = arch.default_fp().unwrap();
    assert!(Rc::ptr_eq(defaultfp, arch.get_model("__stdcall").unwrap()));
    // The x86win <default_proto> is `extrapop="unknown"` with an ESP/EBP/...
    // <unaffected> block; those are what proto recovery reads.
    assert_eq!(defaultfp.get_extra_pop(), kuna_decomp::fspec::EXTRAPOP_UNKNOWN);
    assert!(!defaultfp.effect_list().is_empty());
    assert!(!defaultfp.has_this_pointer());
}
