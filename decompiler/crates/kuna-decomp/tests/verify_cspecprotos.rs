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

const RECURSIVE_NODE_HOST_ID: u64 = 0x71000001;
const RECURSIVE_FN_HOST_ID: u64 = 0x71000002;
const RECURSIVE_ALIAS_HOST_ID: u64 = 0x71000003;

/// Actual getDataType reply documents. The production factory follows their
/// typerefs, including the back-edge into a definition still being decoded.
struct RecursiveCallableReplies {
    node: Vec<u8>,
    function: Vec<u8>,
    alias: Vec<u8>,
}

impl kuna_decomp::dtype::RemoteTypeFetch for RecursiveCallableReplies {
    fn fetch_data_type(
        &self,
        name: &str,
        id: u64,
        decoder: &mut dyn kuna_base::marshal::Decoder,
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
    encoder: &mut dyn kuna_base::marshal::Encoder,
    name: &str,
    id: u64,
    size: Option<i32>,
) {
    use kuna_base::marshal::{ATTRIB_ID, ATTRIB_NAME, ATTRIB_SIZE};
    use kuna_decomp::dtype::ELEM_TYPEREF;

    encoder.open_element(&ELEM_TYPEREF);
    encoder.write_string(&ATTRIB_NAME, name.as_bytes());
    encoder.write_unsigned_integer(&ATTRIB_ID, id);
    if let Some(size) = size {
        encoder.write_signed_integer(&ATTRIB_SIZE, i64::from(size));
    }
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
        ATTRIB_DOTDOTDOT, ELEM_INTERNALLIST, ELEM_PARAM, ELEM_PROTOTYPE, ELEM_RETURNSYM,
    };

    let mut node = Vec::new();
    {
        let mut encoder = PackedEncode::new(&mut node);
        encoder.open_element(&ELEM_TYPE);
        encoder.write_string(&ATTRIB_NAME, b"RecursiveNode");
        encoder.write_unsigned_integer(&ATTRIB_ID, RECURSIVE_NODE_HOST_ID);
        encoder.write_string(&ATTRIB_METATYPE, b"struct");
        encoder.write_signed_integer(&ATTRIB_SIZE, 16);
        encoder.write_signed_integer(&ATTRIB_ALIGNMENT, 8);
        encoder.open_element(&ELEM_FIELD);
        encoder.write_string(&ATTRIB_NAME, b"d");
        encoder.write_signed_integer(&ATTRIB_ID, 101);
        encoder.write_signed_integer(&ATTRIB_OFFSET, 0);
        encoder.open_element(&ELEM_TYPE);
        encoder.write_string(&ATTRIB_NAME, b"");
        encoder.write_string(&ATTRIB_METATYPE, b"float");
        encoder.write_signed_integer(&ATTRIB_SIZE, 8);
        encoder.close_element(&ELEM_TYPE);
        encoder.close_element(&ELEM_FIELD);
        encoder.open_element(&ELEM_FIELD);
        encoder.write_string(&ATTRIB_NAME, b"next");
        encoder.write_signed_integer(&ATTRIB_ID, 203);
        encoder.write_signed_integer(&ATTRIB_OFFSET, 8);
        encoder.open_element(&ELEM_TYPE);
        encoder.write_string(&ATTRIB_NAME, b"");
        encoder.write_string(&ATTRIB_METATYPE, b"ptr");
        encoder.write_signed_integer(&ATTRIB_SIZE, 8);
        // Java includes an instance width on FunctionDefinition references.
        encode_recursive_typeref(&mut encoder, "RecursiveFn", RECURSIVE_FN_HOST_ID, Some(1));
        encoder.close_element(&ELEM_TYPE);
        encoder.close_element(&ELEM_FIELD);
        encoder.close_element(&ELEM_TYPE);
    }
    let mut alias = Vec::new();
    {
        let mut encoder = PackedEncode::new(&mut alias);
        encoder.open_element(&ELEM_DEF);
        encoder.write_string(&ATTRIB_NAME, b"RecursiveAlias");
        encoder.write_unsigned_integer(&ATTRIB_ID, RECURSIVE_ALIAS_HOST_ID);
        encode_recursive_typeref(&mut encoder, "RecursiveNode", RECURSIVE_NODE_HOST_ID, None);
        encoder.close_element(&ELEM_DEF);
    }
    let (value_name, value_id) = if with_alias {
        ("RecursiveAlias", RECURSIVE_ALIAS_HOST_ID)
    } else {
        ("RecursiveNode", RECURSIVE_NODE_HOST_ID)
    };
    let mut function = Vec::new();
    {
        let mut encoder = PackedEncode::new(&mut function);
        encoder.open_element(&ELEM_TYPE);
        encoder.write_string(&ATTRIB_NAME, b"RecursiveFn");
        encoder.write_unsigned_integer(&ATTRIB_ID, RECURSIVE_FN_HOST_ID);
        encoder.write_string(&ATTRIB_METATYPE, b"code");
        encoder.write_signed_integer(&ATTRIB_SIZE, 1);
        encoder.open_element(&ELEM_PROTOTYPE);
        encoder.write_string(&ATTRIB_MODEL, model.as_bytes());
        encoder.write_bool(&ATTRIB_DOTDOTDOT, false);
        encoder.open_element(&ELEM_RETURNSYM);
        Address::new_invalid().encode(&mut encoder).unwrap();
        encode_recursive_typeref(&mut encoder, value_name, value_id, None);
        encoder.close_element(&ELEM_RETURNSYM);
        encoder.open_element(&ELEM_INTERNALLIST);
        // Java FunctionDefinition encoding uses first=-1 for this closed list.
        encoder.write_signed_integer(&ATTRIB_FIRST, -1);
        encoder.open_element(&ELEM_PARAM);
        encoder.write_string(&ATTRIB_NAME, b"node");
        Address::new_invalid().encode(&mut encoder).unwrap();
        encode_recursive_typeref(&mut encoder, value_name, value_id, None);
        encoder.close_element(&ELEM_PARAM);
        encoder.close_element(&ELEM_INTERNALLIST);
        encoder.close_element(&ELEM_PROTOTYPE);
        encoder.close_element(&ELEM_TYPE);
    }
    RecursiveCallableReplies { node, function, alias }
}

fn decode_recursive_typeref(
    arch: &Architecture,
    name: &str,
    id: u64,
    size: Option<i32>,
) -> kuna_decomp::dtype::TypeRoot {
    use kuna_base::marshal::{Decoder, PackedDecode, PackedEncode};

    let mut bytes = Vec::new();
    encode_recursive_typeref(&mut PackedEncode::new(&mut bytes), name, id, size);
    let mut decoder = PackedDecode::new(arch.manage());
    decoder.ingest_stream(&bytes).unwrap();
    arch.types().decode_type(&mut decoder).unwrap()
}

/// Join pieces are ordered most-significant first, not by register number.
/// Checking exact storage also catches accidental aggregate-to-pointer ABI
/// assignment while the recursive record is only partially decoded.
fn assert_recursive_join(
    arch: &Architecture,
    address: &Address,
    expected_registers: [&str; 2],
) {
    use kuna_base::space::spacetype;

    assert_eq!(address.get_space().unwrap().get_type(), spacetype::IPTR_JOIN);
    let join = arch.manage().find_join(address.get_offset()).unwrap();
    assert_eq!(join.get_unified().size, 16);
    assert_eq!(join.num_pieces(), 2);
    for (index, register) in expected_registers.iter().enumerate() {
        let expected = arch.translate().get_register_varnode(register.as_bytes()).unwrap();
        let actual = join.get_piece(index as i32);
        assert!(Rc::ptr_eq(actual.space.as_ref().unwrap(), expected.space.as_ref().unwrap()));
        assert_eq!(actual.offset, expected.offset, "{register}");
        assert_eq!(actual.size, 8, "{register}");
    }
}

#[test]
fn recursive_host_callable_decodes_and_assigns_real_target_abis_in_both_query_orders() {
    use kuna_decomp::dtype::{type_metatype, TypeFactory, TypeState};
    use kuna_decomp::fspec::{materialize_callable, AbiInputOrigin};

    // These are model/decoder checks, not target instruction execution. Every
    // target runs on every host, including the two distinct AArch64 cspecs.
    for (target, inputs, output) in [
        ("x86:LE:64:default:gcc", ["RDI", "XMM0"], ["RAX", "XMM0"]),
        ("AARCH64:LE:64:v8A:default", ["x1", "x0"], ["x1", "x0"]),
        ("AARCH64:LE:64:AppleSilicon:default", ["x1", "x0"], ["x1", "x0"]),
    ] {
        let architecture = bootstrap(target).unwrap_or_else(|error| panic!("{target}: {error}"));
        let arch = arch_of(&architecture);
        let factory = arch.types_rc();
        let model = arch.default_fp().unwrap();
        for (with_alias, first_name, first_id, first_size) in [
            (false, "RecursiveNode", RECURSIVE_NODE_HOST_ID, None),
            (false, "RecursiveFn", RECURSIVE_FN_HOST_ID, Some(1)),
            (true, "RecursiveNode", RECURSIVE_NODE_HOST_ID, None),
            (true, "RecursiveAlias", RECURSIVE_ALIAS_HOST_ID, None),
        ] {
            factory.clear_noncore().unwrap();
            factory.set_remote_type_fetch(Some(Rc::new(recursive_callable_replies(model.get_name(), with_alias))));
            let first = decode_recursive_typeref(arch, first_name, first_id, first_size);
            let node = decode_recursive_typeref(arch, "RecursiveNode", RECURSIVE_NODE_HOST_ID, None);
            let function = decode_recursive_typeref(arch, "RecursiveFn", RECURSIVE_FN_HOST_ID, Some(1));
            let declared = if with_alias {
                decode_recursive_typeref(arch, "RecursiveAlias", RECURSIVE_ALIAS_HOST_ID, None)
            } else {
                node.clone()
            };
            assert_eq!(first, match first_id {
                RECURSIVE_FN_HOST_ID => function.clone(),
                RECURSIVE_ALIAS_HOST_ID => declared.clone(),
                _ => node.clone(),
            });
            assert_eq!(node.get_id(), RECURSIVE_NODE_HOST_ID);
            assert_eq!(function.get_id(), RECURSIVE_FN_HOST_ID);
            assert_eq!(factory.state(&node).unwrap(), TypeState::Complete);
            assert_eq!(factory.state(&function).unwrap(), TypeState::Complete);
            assert_eq!(node.get_size(), 16);
            assert_eq!(declared.read().resolve_alias(declared.id()).unwrap(), node.id());
            {
                let view = node.read();
                let value = view.get_field(node.id(), 0).unwrap().unwrap();
                assert_eq!((value.name.as_str(), value.ident, value.offset), ("d", 101, 0));
                assert_eq!(view.get(value.field_type).unwrap().get_metatype(), type_metatype::TYPE_FLOAT);
                let next = view.get_field(node.id(), 1).unwrap().unwrap();
                assert_eq!((next.name.as_str(), next.ident, next.offset), ("next", 203, 8));
                assert_eq!(view.get_ptr_to(next.field_type).unwrap(), Some(function.id()));
                let signature = view.get_code_prototype(function.id()).unwrap().unwrap();
                assert_eq!(signature.output, declared.id());
                assert_eq!(signature.inputs, vec![declared.id()]);
                assert!(signature.input_closed);
                assert!(!signature.variadic);
                assert_eq!(signature.logical_first, None);
                assert!(Rc::ptr_eq(signature.binding.model(), model));
                assert!(view.abi_ready(function.id()).unwrap());
            }
            let abi = materialize_callable(&*factory, &function).unwrap().expect("complete recursive layout");
            assert_eq!(abi.root(), &function);
            assert_eq!(abi.logical.output, declared.id());
            assert_eq!(abi.logical.inputs, vec![declared.id()]);
            assert_eq!(abi.input_origins(), &[AbiInputOrigin::Declared(0)]);
            let prototype = abi.prototype();
            assert_eq!(prototype.num_params(), 1);
            assert_eq!(prototype.get_param(0).unwrap().get_type().unwrap(), &declared);
            assert_eq!(prototype.get_output().get_type().unwrap(), &declared);
            let input = prototype.get_param(0).unwrap();
            assert!(!input.is_hidden_return());
            assert!(!input.is_indirect_storage());
            assert_recursive_join(arch, &input.get_address(), inputs);
            assert_recursive_join(arch, &prototype.get_output().get_address(), output);
            assert!(Rc::ptr_eq(&abi, &materialize_callable(&*factory, &function).unwrap().unwrap()));
        }
    }
}

fn recursive_alias_draft(
    alias: &kuna_decomp::dtype::TypeRoot,
    target: &kuna_decomp::dtype::TypeRoot,
) -> kuna_decomp::dtype::Datatype {
    use kuna_decomp::dtype::{Datatype, DatatypeKind};

    let view = alias.read();
    let source = view.definition(alias.id()).unwrap();
    let mut draft = Datatype::new_with_align(target.get_size(), target.get_alignment(), target.get_metatype());
    draft.name = source.name.clone();
    draft.display_name = source.display_name.clone();
    draft.id = source.id;
    draft.kind = DatatypeKind::Alias;
    draft.typedef_imm = Some(target.id());
    draft
}

fn declare_recursive_callback(
    factory: &dyn kuna_decomp::dtype::TypeFactory,
    output: &kuna_decomp::dtype::TypeRoot,
    inputs: Vec<kuna_decomp::dtype::TypeId>,
) -> KunaResult<kuna_decomp::dtype::TypeRoot> {
    factory.get_type_code_proto(&kuna_decomp::fspec::LogicalCallable {
        binding: factory.model_binding(None)?,
        output: output.id(),
        inputs,
        variadic: false,
        input_closed: true,
        logical_first: None,
        flags: 0,
    })
}

#[test]
fn recursive_alias_callable_waits_for_layout_before_assigning_aggregate_storage() {
    use kuna_decomp::dtype::{type_metatype, TypeFactory, TypeField, TypeState};
    use kuna_decomp::fspec::materialize_callable;

    let architecture = bootstrap("x86:LE:64:default:gcc").unwrap();
    let arch = arch_of(&architecture);
    let factory = arch.types_rc();
    let alias = factory.reserve_alias("PendingNodeAlias", RECURSIVE_ALIAS_HOST_ID).unwrap();
    factory.begin(&alias).unwrap();
    let callback = declare_recursive_callback(&*factory, &alias, vec![alias.id()]).unwrap();
    assert_eq!(factory.state(&callback).unwrap(), TypeState::Complete);
    assert!(materialize_callable(&*factory, &callback).unwrap().is_none());

    let node = factory.reserve("PendingNode", RECURSIVE_NODE_HOST_ID, type_metatype::TYPE_STRUCT).unwrap();
    let float = factory.get_base(8, type_metatype::TYPE_FLOAT).unwrap();
    let pointer = factory.get_type_pointer(8, callback.clone(), 1).unwrap();
    factory.set_fields_struct_raw(&node, vec![
        TypeField::new(101, 0, "d", float.id()),
        TypeField::new(203, 8, "next", pointer.id()),
    ], vec![], 16, 8, 0).unwrap();
    assert!(materialize_callable(&*factory, &callback).unwrap().is_none());
    factory.complete(&alias, recursive_alias_draft(&alias, &node)).unwrap();

    let abi = materialize_callable(&*factory, &callback).unwrap().unwrap();
    let prototype = abi.prototype();
    let input = prototype.get_param(0).unwrap();
    assert_eq!(input.get_type().unwrap(), &alias);
    assert_eq!(prototype.get_output().get_type().unwrap(), &alias);
    assert!(!input.is_indirect_storage());
    assert!(!input.is_hidden_return());
    assert_recursive_join(arch, &input.get_address(), ["RDI", "XMM0"]);
    assert_recursive_join(arch, &prototype.get_output().get_address(), ["RAX", "XMM0"]);
    assert!(Rc::ptr_eq(&abi, &materialize_callable(&*factory, &callback).unwrap().unwrap()));
}

#[test]
fn unresolved_callable_slots_do_not_hide_known_invalid_inputs() {
    use kuna_decomp::dtype::{TypeFactory, TypeState};

    let architecture = bootstrap("x86:LE:64:default:gcc").unwrap();
    let factory = arch_of(&architecture).types_rc();
    let alias = factory.reserve_alias("UnresolvedValue", RECURSIVE_ALIAS_HOST_ID).unwrap();
    factory.begin(&alias).unwrap();
    for invalid in [factory.get_type_void().unwrap(), factory.get_type_code().unwrap()] {
        assert!(declare_recursive_callback(&*factory, &alias, vec![alias.id(), invalid.id()]).is_err());
        assert_eq!(factory.state(&alias).unwrap(), TypeState::Loading);
    }
}

#[test]
fn deferred_callable_rejects_invalid_alias_targets_without_poisoning_valid_retry() {
    use kuna_decomp::dtype::{type_metatype, TypeFactory, TypeState};
    use kuna_decomp::fspec::materialize_callable;

    let architecture = bootstrap("x86:LE:64:default:gcc").unwrap();
    let arch = arch_of(&architecture);
    let factory = arch.types_rc();
    for code_target in [false, true] {
        factory.clear_noncore().unwrap();
        let alias = factory.reserve_alias("DeferredValue", RECURSIVE_ALIAS_HOST_ID).unwrap();
        factory.begin(&alias).unwrap();
        let callback = declare_recursive_callback(&*factory, &alias, vec![alias.id()]).unwrap();
        let invalid = if code_target { factory.get_type_code().unwrap() } else { factory.get_type_void().unwrap() };
        assert!(factory.complete(&alias, recursive_alias_draft(&alias, &invalid)).is_err());
        assert_eq!(factory.state(&alias).unwrap(), TypeState::Loading);
        assert!(materialize_callable(&*factory, &callback).unwrap().is_none());

        let valid = factory.get_base(8, type_metatype::TYPE_INT).unwrap();
        factory.complete(&alias, recursive_alias_draft(&alias, &valid)).unwrap();
        let abi = materialize_callable(&*factory, &callback).unwrap().unwrap();
        let prototype = abi.prototype();
        let input = prototype.get_param(0).unwrap();
        assert_eq!(input.get_type().unwrap(), &alias);
        assert_eq!(prototype.get_output().get_type().unwrap(), &alias);
        let input_register = arch.translate().get_register_varnode(b"RDI").unwrap();
        let output_register = arch.translate().get_register_varnode(b"RAX").unwrap();
        assert_eq!(input.get_address(), Address::new(Rc::clone(input_register.space.as_ref().unwrap()), input_register.offset));
        assert_eq!(prototype.get_output().get_address(), Address::new(Rc::clone(output_register.space.as_ref().unwrap()), output_register.offset));
    }
}

#[test]
fn failed_callable_alias_is_an_error_before_and_after_declaration() {
    use kuna_decomp::dtype::TypeFactory;
    use kuna_decomp::fspec::materialize_callable;

    let architecture = bootstrap("x86:LE:64:default:gcc").unwrap();
    let factory = arch_of(&architecture).types_rc();
    for fail_first in [false, true] {
        factory.clear_noncore().unwrap();
        let alias = factory.reserve_alias("FailedValue", RECURSIVE_ALIAS_HOST_ID).unwrap();
        factory.begin(&alias).unwrap();
        if fail_first {
            factory.fail(&alias, "Producer cannot supply the declaration".into()).unwrap();
            assert!(declare_recursive_callback(&*factory, &alias, vec![alias.id()]).is_err());
        } else {
            let callback = declare_recursive_callback(&*factory, &alias, vec![alias.id()]).unwrap();
            assert!(materialize_callable(&*factory, &callback).unwrap().is_none());
            factory.fail(&alias, "Producer cannot supply the declaration".into()).unwrap();
            assert!(materialize_callable(&*factory, &callback).is_err());
        }
    }
}

#[test]
fn deferred_callable_does_not_legitimize_a_by_value_alias_cycle() {
    use kuna_decomp::dtype::{type_metatype, TypeFactory, TypeField};
    use kuna_decomp::fspec::materialize_callable;

    let architecture = bootstrap("x86:LE:64:default:gcc").unwrap();
    let factory = arch_of(&architecture).types_rc();
    let alias = factory.reserve_alias("CyclicValue", RECURSIVE_ALIAS_HOST_ID).unwrap();
    factory.begin(&alias).unwrap();
    let callback = declare_recursive_callback(&*factory, &alias, vec![alias.id()]).unwrap();
    let node = factory.reserve("CyclicNode", RECURSIVE_NODE_HOST_ID, type_metatype::TYPE_STRUCT).unwrap();
    factory.set_fields_struct_raw(&node, vec![
        TypeField::new(0, 0, "self_by_value", alias.id()),
    ], vec![], 16, 8, 0).unwrap();
    assert!(factory.complete(&alias, recursive_alias_draft(&alias, &node)).is_err());
    assert!(materialize_callable(&*factory, &callback).is_err());
}
