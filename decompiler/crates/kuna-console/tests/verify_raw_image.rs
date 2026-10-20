//! Headerless raw-image bootstrap and address-translation regressions.

use crate::common;

use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};

use kuna_base::address::Address;
use kuna_base::marshal::Decoder;
use kuna_console::assertions::{self, Body, Directive};
use kuna_console::engine::{bootstrap_from_raw, ArmIsa};
use kuna_console::project::decompile_targets;
use kuna_decomp::varnode::varnode_flags;

struct RawFixture(PathBuf);

impl RawFixture {
    fn thumb_return_7() -> Self {
        Self::new("raw-thumb", &[0x07, 0x20, 0x70, 0x47])
    }

    fn new(stem: &str, bytes: &[u8]) -> Self {
        let path = common::scratch_file(stem, "bin");
        std::fs::write(&path, bytes).unwrap();
        Self(path)
    }

    fn thumb_return_7_with_spaces() -> Self {
        let path = common::scratch_file("raw thumb image", "bin");
        std::fs::write(&path, [0x07, 0x20, 0x70, 0x47]).unwrap();
        Self(path)
    }
}

impl Drop for RawFixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../..")
        .canonicalize()
        .unwrap()
}

fn specs() -> Vec<String> {
    vec![std::env::var("KUNA_SPECS")
        .unwrap_or_else(|_| repo_root().join("specs").to_string_lossy().into_owned())]
}

fn source_state_program(fixture: &RawFixture, entries: &[u64]) -> kuna_console::engine::ConsoleProgram {
    let mut program = bootstrap_from_raw(fixture.0.to_str().unwrap(),
        "x86:LE:64:default:gcc", 0x1000, entries, None, &specs())
        .expect("real x86 fixture and built specification");
    program.commit_pending_analysis().unwrap();
    program
}

#[test]
fn global_presentation_keeps_alias_identity_and_body_header_values() {
    use std::rc::Rc;
    use kuna_console::project::{build_header, prepare_type_names, render_c};
    use kuna_decomp::decompile_drive::{print_c_recompile_prelude, print_c_types};
    use kuna_decomp::dtype::{type_metatype, TypeFactory};

    // mov eax,[0x1040]; movzx ecx,byte [0x1052]; add eax,ecx; add eax,edi; ret
    let mut image = vec![0; 0xc0];
    image[..18].copy_from_slice(&[
        0x8b, 0x05, 0x3a, 0, 0, 0, 0x0f, 0xb6, 0x0d, 0x45, 0, 0, 0,
        0x01, 0xc8, 0x01, 0xf8, 0xc3,
    ]);
    image[0x40..0x44].copy_from_slice(&7u32.to_le_bytes());
    image[0x52] = 5;
    let fixture = RawFixture::new("global-presentation-values", &image);
    let mut program = source_state_program(&fixture, &[0x1000]);
    let entry = program.find_entry_at(0x1000).unwrap();
    let function = entry.name.clone();
    program.set_assertions(vec![Directive {
        raw: "source parameter spelling reservation".into(),
        body: Body::Prototype {
            func: function.clone(),
            decl: format!("uint4 {function}(uint4 completed_0__kuna_2)"),
        },
    }]);
    assertions::apply_program_scoped(&mut program);
    let integer = program.arch().types().get_base(4, type_metatype::TYPE_INT).unwrap();
    let character = program.arch().types().get_type_char(1).unwrap();
    let array = program.arch().types().get_type_array(32, character).unwrap();
    let global = program.arch().symboltab.get_global_scope().unwrap();
    let data_space = program.arch().manage().get_default_data_space().unwrap().clone();
    let spaces = program.arch().manage().num_spaces();
    let namespace = program.arch_mut().symboltab
        .find_create_scope(0x7799, "other", Some(global), spaces).unwrap();
    let mut sources = Vec::new();
    for (scope, name, address, datatype) in [
        (global, "completed.0", 0x1040, integer.clone()),
        (global, "b.1", 0x1050, array.clone()),
        (global, "b+1", 0x1050, array.clone()),
        (global, "b_1", 0x1080, integer.clone()),
        (global, "b_1__kuna_2", 0x1088, integer),
        (namespace, "b.1", 0x10a0, array),
    ] {
        let (id, _) = program.arch_mut().symboltab.add_symbol_mapped(
            scope, name, datatype.clone(), &Address::new(data_space.clone(), address),
            &Address::new_invalid(),
        ).unwrap();
        let symbol = program.arch().symboltab.symbol(id);
        sources.push((id, symbol.get_id(), name.to_owned(), datatype));
    }

    prepare_type_names(&mut program);
    let results = decompile_targets(&mut program, vec![entry], false, true, false).unwrap();
    let result = &results[0];
    assert!(result.error.is_none(), "{:?}", result.error);
    let body = result.code.as_deref().unwrap();
    let scalar = result.globals.iter().find(|g| g.address == 0x1040 && g.source_symbol.is_some()).unwrap();
    let bytes = result.globals.iter().find(|g| g.address == 0x1050 && g.source_symbol.is_some()).unwrap();
    assert_eq!(scalar.name, "completed.0");
    assert!(["b.1", "b+1"].contains(&bytes.name.as_str()));
    assert_eq!((scalar.size, bytes.size), (4, 32));
    let print = program.arch().print();
    let scalar_name = print.global_presentation_name(scalar.source_symbol.unwrap(), &scalar.name);
    let array_name = print.global_presentation_name(bytes.source_symbol.unwrap(), &bytes.name);
    assert_ne!(scalar_name, scalar.name);
    assert_ne!(scalar_name, "completed_0__kuna_2", "source parameter owns its spelling");
    assert_ne!(array_name, "b_1");
    assert_ne!(array_name, "b_1__kuna_2", "unreferenced source global still reserves its spelling");
    assert!(body.contains(scalar_name) && body.contains(array_name), "{body}");
    assert!(scalar.declaration.contains(scalar_name), "{scalar:?}");
    assert!(bytes.declaration.contains(array_name) && bytes.declaration.ends_with("[32]"), "{bytes:?}");
    let selected: std::collections::BTreeSet<_> = sources.iter()
        .filter(|(_, _, name, _)| name == "b.1" || name == "b+1")
        .map(|(_, id, name, _)| print.global_presentation_name(*id, name).to_owned())
        .collect();
    assert_eq!(selected.len(), 3, "same-storage aliases and namespace peers keep separate identities");
    let scalar_name = scalar_name.to_owned();
    let array_name = array_name.to_owned();
    for (id, source_id, name, datatype) in &sources {
        let symbol = program.arch().symboltab.symbol(*id);
        assert_eq!((symbol.get_id(), symbol.get_name()), (*source_id, name.as_str()));
        assert!(Rc::ptr_eq(symbol.dtype.as_ref().unwrap(), datatype));
    }
    assert_eq!(program.arch().symboltab.get_full_name(namespace), "other");

    let prelude = print_c_recompile_prelude(program.arch());
    let types = print_c_types(program.arch_mut());
    let header = build_header("globals", &prelude, &types, &results);
    let header_path = common::scratch_file("global-presentation-values", "h");
    let source_path = common::scratch_file("global-presentation-values", "c");
    let executable = common::scratch_file("global-presentation-values", "exe");
    std::fs::write(&header_path, &header).unwrap();
    std::fs::write(&source_path, format!(
        "#include \"{}\"\n{}\nint {scalar_name}=7;\nchar {array_name}[32]={{0,0,5}};\n\
         int main(void){{if({function}(3)!=15)return 1;\
         {scalar_name}=37;{array_name}[2]=13;return {function}(9)!=59;}}\n",
        header_path.display(), render_c(&results),
    )).unwrap();
    for optimization in ["-O0", "-O2"] {
        let compiled = Command::new("cc").args(["-std=c11", optimization])
            .arg(&source_path).arg("-o").arg(&executable).output().expect("C compiler prerequisite");
        assert!(compiled.status.success(), "{optimization}:\n{}\n{header}\n{body}",
            String::from_utf8_lossy(&compiled.stderr));
        let observed = Command::new(&executable).output().expect("execute generated global-value consumer");
        assert!(observed.status.success(), "{optimization}: {observed:?}");
    }
    for path in [&header_path, &source_path, &executable] {
        std::fs::remove_file(path).unwrap();
    }
}

#[test]
fn supplied_default_callable_model_remains_explicit_for_mixed_join_storage() {
    use std::rc::Rc;
    use kuna_base::marshal::{PackedDecode, PackedEncode};
    use kuna_decomp::dtype::{type_metatype, TypeFactory, TypeField};
    use kuna_decomp::fspec::{FuncCallSpecs, FuncProto, ProtoModel, PrototypeDecoding,
        PrototypeEncoding, PrototypePieces};
    use kuna_decomp::funcdata::Funcdata;
    use kuna_num::opcodes::OpCode;

    let fixture = RawFixture::new("supplied-default-callable", &[0xc3]);
    let program = source_state_program(&fixture, &[0x1000]);
    let types = program.arch().types_impl();
    let shell = types.kuna_declare_record("MixedNode", false).unwrap();
    let floating = types.get_base(8, type_metatype::TYPE_FLOAT).unwrap();
    let code = types.get_type_code().unwrap();
    let pointer = types.get_type_pointer(8, code, 1).unwrap();
    let node = types.set_fields_struct_raw(&shell, vec![
        TypeField::new(0, 0, "d", floating), TypeField::new(1, 8, "next", pointer),
    ], vec![], 16, 8, 0).unwrap();
    let model = program.arch().default_fp().unwrap().clone();
    let logical = FuncProto::from_logical(&PrototypePieces {
        outtype: Some(node.clone()), intypes: vec![node.clone()], innames: vec!["node".into()],
        first_var_arg_slot: -1,
        ..PrototypePieces::default()
    }, model.clone(), types).unwrap();
    let inferred_default = Rc::new(types.acquire_working_proto(&logical).unwrap());
    let mut bytes = Vec::new();
    logical.encode_with_context(&mut PackedEncode::new(&mut bytes),
        PrototypeEncoding::LogicalCallable).unwrap();
    let mut decoder = PackedDecode::new(program.arch().manage());
    decoder.ingest_stream(&bytes).unwrap();
    let supplied = types.decode_proto(&mut decoder, PrototypeDecoding::LogicalCallable).unwrap();
    let supplied = Rc::new(types.acquire_working_proto(&supplied).unwrap());
    assert_eq!(supplied.get_model_name(), model.get_name());
    assert!(supplied.is_input_locked() && supplied.is_output_locked());
    assert_eq!(supplied.num_params(), 1);
    assert_eq!((supplied.get_param(0).unwrap().get_size(), supplied.get_output().get_size()), (16, 16));
    assert!(supplied.get_param(0).unwrap().get_address().is_join());
    assert!(supplied.get_output().get_address().is_join());

    let call_context = |default: Rc<ProtoModel>| {
        let mut context = Rc::try_unwrap(program.arch().build_arch_handle())
            .unwrap_or_else(|_| panic!("fresh call context must be uniquely owned"));
        // Hosted architectures have specifications but no standalone image ABI evidence.
        context.float_arg_registers = None;
        context.defaultfp = Some(default);
        let address = program.find_entry_at(0x1000).unwrap().addr;
        let mut data = Funcdata::new("subject", "subject", Rc::new(context),
            address.clone(), 0x1000_0000, 1).unwrap();
        let call = data.new_op(1, address);
        data.op_set_opcode(call, kuna_decomp::typeop::type_op_for(OpCode::CPUI_CALLIND));
        let target = data.new_constant(8, 0x2000);
        data.op_set_input(call, target, 0).unwrap();
        data.new_unique_out(16, call).unwrap();
        (data, FuncCallSpecs::new(call, Address::new_invalid()))
    };
    let (data, call) = call_context(model.clone());
    assert!(kuna_decomp::kuna_typedcallabi::admit(&data, &call, inferred_default).is_none(),
        "internal default selection is not supplied convention authority");
    let admitted = kuna_decomp::kuna_typedcallabi::admit(&data, &call, supplied.clone()).unwrap();
    assert!(Rc::ptr_eq(&admitted, &supplied));
    let mut variadic = FuncProto::new();
    variadic.copy(&supplied);
    variadic.set_dotdotdot(true);
    assert!(kuna_decomp::kuna_typedcallabi::admit(&data, &call, Rc::new(variadic)).is_none(),
        "supplied convention must not bypass variadic JOIN/float eligibility");

    let changed_model = Rc::new(ProtoModel::copy_named("current_default", &model));
    let mut changed = FuncProto::new();
    changed.copy(&supplied);
    changed.set_model(Some(changed_model.clone()));
    let (data, call) = call_context(changed_model);
    assert!(kuna_decomp::kuna_typedcallabi::admit(&data, &call, Rc::new(changed)).is_none(),
        "historical declared name cannot authorize a different effective model");
}

#[test]
fn live_source_parameter_replacement_retires_analyzed_symbol_links_before_printing() {
    use kuna_console::ifacedecomp::{register_decomp_commands, IfaceDecompData, DECOMPILE_MODULE};
    use kuna_console::ifaceterm::ConsoleCommands;
    let fixture = RawFixture::new("live-source-parameter-links", &[0x89, 0xf8, 0x01, 0xf0, 0xc3]);
    for edit in [
        "map param subject::0 [register,0x8,2] uint2 fresh",
        "parse line extern uint4 subject(uint1 fresh,uint1 other);",
        "parse line extern uint4 subject(void);",
    ] {
        let program = source_state_program(&fixture, &[0x1000]);
        let script: Vec<String> = [
            "map function [ram,0x1000] subject", "load function subject",
            "parse line extern uint4 subject(uint1 value,uint1 other);", "decompile",
            "rename value prior", edit, "print C",
        ].into_iter().map(str::to_owned).collect();
        let commands = script.clone();
        let mut status = ConsoleCommands::into_status(script);
        register_decomp_commands(&mut status);
        status.get_data_mut(DECOMPILE_MODULE).unwrap().as_any_mut()
            .downcast_mut::<IfaceDecompData>().unwrap().conf = Some(program);
        for command in commands {
            status.run_command().unwrap_or_else(|error| panic!("{command}: {error}"));
        }
        assert!(!status.optr.contains("prior"),
            "analyzed body kept a superseded source identifier after {edit}: {}", status.optr);
        let data = status.get_data_mut(DECOMPILE_MODULE).unwrap().as_any_mut()
            .downcast_mut::<IfaceDecompData>().unwrap();
        let fd = data.fd.as_ref().unwrap();
        let scope = fd.get_scope_local().unwrap();
        assert!(scope.query_by_name("prior").is_empty(), "superseded source symbol survives: {edit}");
        assert!(fd.kuna_directive_symbols().is_empty(), "superseded parameter directive survives: {edit}");
        assert!(data.pending_local_checks.is_empty(), "superseded parameter check survives: {edit}");
        assert_eq!(fd.get_func_proto().num_params(), if edit.contains("(void)") { 0 } else { 2 });
    }
}

#[test]
fn physical_source_console_edits_replay_without_resurrecting_old_slots() {
    use kuna_console::ifacedecomp::{register_decomp_commands, IfaceDecompData, DECOMPILE_MODULE};
    use kuna_console::ifaceterm::ConsoleCommands;
    let fixture = RawFixture::new("physical-source-edits", &[0x89, 0xf8, 0x01, 0xf0, 0xc3]);
    let cases: &[(&[&str], [(&str, i32, u64); 2])] = &[
        (&["rename value renamed", "decompile", "retype other int1 changed", "decompile"],
            [("renamed", 1, 0x38), ("changed", 1, 0x30)]),
        (&["rename other sibling", "map param subject::0 [register,0x8,2] uint2 fresh",
            "rename fresh newest", "decompile"],
            [("newest", 2, 0x08), ("sibling", 1, 0x30)]),
        (&["rename value old_rename", "parse line extern uint4 subject(uint2 fresh, uint1 other);",
            "rename fresh newest", "decompile"],
            [("newest", 2, 0x38), ("other", 1, 0x30)]),
        (&["retype other uint2 changed", "decompile"],
            [("value", 1, 0x38), ("other", 1, 0x30)]),
    ];
    for &(commands, expected) in cases {
        let program = source_state_program(&fixture, &[0x1000]);
        let mut script: Vec<String> = [
            "map function [ram,0x1000] subject", "load function subject",
            "parse line extern uint4 subject(uint1 value,uint1 other);", "decompile",
        ].into_iter().map(str::to_owned).collect();
        script.extend(commands.iter().map(|command| command.to_string()));
        let executed_commands = script.clone();
        let mut status = ConsoleCommands::into_status(script);
        register_decomp_commands(&mut status);
        status.get_data_mut(DECOMPILE_MODULE).unwrap().as_any_mut()
            .downcast_mut::<IfaceDecompData>().unwrap().conf = Some(program);
        for command in executed_commands {
            let result = status.run_command();
            if command == "retype other uint2 changed" {
                assert!(result.unwrap_err().is_execution(),
                    "a mapped non-address-tied register symbol cannot change width");
            } else {
                result.unwrap_or_else(|error| panic!("{command}: {error}"));
            }
        }
        let transcript = status.optr.clone();
        let data = status.get_data_mut(DECOMPILE_MODULE).unwrap().as_any_mut()
            .downcast_mut::<IfaceDecompData>().unwrap();
        let fd = data.fd.as_ref().unwrap_or_else(|| panic!("{transcript}"));
        let scope = fd.get_scope_local().expect("source symbols remain available after replay");
        let mut encoded_scope = Vec::new();
        scope.encode(&mut kuna_base::marshal::XmlEncode::new(&mut encoded_scope)).unwrap();
        let mut documents = kuna_base::xml::DocumentStorage::new();
        let document = documents.parse_document(&encoded_scope).unwrap();
        fn parameter_roster(element: &kuna_base::xml::Element, roster: &mut Vec<(u16, String)>) {
            if element.get_name() == "symbol" && element.get_attribute_value("cat").unwrap() == b"0" {
                let index = std::str::from_utf8(element.get_attribute_value("index").unwrap()).unwrap();
                let ordinal = u16::from_str_radix(index.strip_prefix("0x").unwrap(), 16).unwrap();
                let name = std::str::from_utf8(element.get_attribute_value("name").unwrap())
                    .unwrap().to_owned();
                roster.push((ordinal, name));
            }
            for child in element.get_children() {
                parameter_roster(child, roster);
            }
        }
        let mut roster = Vec::new();
        parameter_roster(document.get_root(), &mut roster);
        roster.sort();
        assert_eq!(roster, expected.iter().enumerate()
            .map(|(ordinal, &(name, _, _))| (ordinal as u16, name.to_owned())).collect::<Vec<_>>(),
            "complete authored parameter roster must survive replay: {transcript}");
        for (ordinal, &(name, size, offset)) in expected.iter().enumerate() {
            let symbols = scope.query_by_name(name);
            assert_eq!(symbols.len(), 1, "authored source name must have one live symbol: {transcript}");
            let symbol = symbols[0];
            assert_eq!(scope.symbol_category(symbol), kuna_decomp::database::symbol_category::FUNCTION_PARAMETER);
            assert_eq!(scope.database().symbol(symbol).get_category_index(), ordinal as u16);
            assert_eq!(scope.database().symbol(symbol).dtype.as_ref().unwrap().get_size(), size);
            let meta = if name == "changed" {
                kuna_decomp::dtype::type_metatype::TYPE_INT
            } else {
                kuna_decomp::dtype::type_metatype::TYPE_UINT
            };
            assert_eq!(scope.database().symbol(symbol).dtype.as_ref().unwrap().get_metatype(), meta);
            assert!(scope.symbol_storage(symbol).iter().any(|(address, width)|
                address.get_space().unwrap().get_name() == "register"
                    && address.get_offset() == offset && *width == size),
                "source storage is independent of execution inputs: {name}/{offset:#x}");
        }
        fn original_input(
            fd: &kuna_decomp::funcdata::Funcdata,
            id: kuna_decomp::context::VarnodeId,
            offset: u64,
            size: i32,
        ) -> bool {
            use kuna_num::opcodes::OpCode;
            let input = fd.vbank().get(id).unwrap();
            let address = input.get_addr();
            if input.get_size() != size
                || address.get_space().unwrap().get_name() != "register"
                || address.get_offset() != offset
            {
                return false;
            }
            if input.is_input() {
                return true;
            }
            let Some(definition) = input.get_def().and_then(|id| fd.obank().get(id)) else {
                return false;
            };
            if definition.is_dead() || definition.code() != OpCode::CPUI_PIECE {
                return false;
            }
            let high = definition.get_in(0).unwrap();
            let low = definition.get_in(1).unwrap();
            let low_size = fd.vbank().get(low).unwrap().get_size();
            low_size > 0 && low_size < size
                && original_input(fd, low, offset, low_size)
                && original_input(fd, high, offset + low_size as u64, size - low_size)
        }
        // Independent input pieces may reconstruct EDI/ESI; source formals
        // and an ECX mapping cannot replace their live four-byte provenance.
        for offset in [0x38, 0x30] {
            assert!(fd.obank().iter_all().any(|(_, id)| {
                let op = fd.obank().get(id).unwrap();
                !op.is_dead()
                    && op.code() == kuna_num::opcodes::OpCode::CPUI_INT_ADD
                    && op.get_addr().get_offset() == 0x1002
                    && (0..op.num_input()).filter_map(|slot| op.get_in(slot))
                        .any(|id| original_input(fd, id, offset, 4))
            }), "original four-byte machine input provenance at {offset:#x} must survive source replay");
        }
        let c = kuna_decomp::decompile_drive::print_c(data.conf.as_mut().unwrap().arch_mut(), fd).unwrap();
        for &(name, _, _) in &expected {
            assert!(c.contains(name), "source-authored name missing from readable C:\n{c}");
        }
        assert!(!c.contains("old_rename"), "obsolete source edit resurrected:\n{c}");
    }
}

#[test]
fn physical_source_assertion_batch_replays_the_authored_parameter_roster() {
    let fixture = RawFixture::new("physical-source-batch", &[0x89, 0xf8, 0x01, 0xf0, 0xc3]);
    let mut program = source_state_program(&fixture, &[0x1000]);
    let entry = program.find_entry_at(0x1000).unwrap();
    let function = entry.name.clone();
    program.set_assertions(vec![
        Directive { raw: "source prototype".into(), body: Body::Prototype {
            func: function.clone(), decl: format!("uint4 {function}(uint1 value,uint1 other)"),
        }},
        Directive { raw: "source rename".into(), body: Body::Name {
            func: Some(function), symbol: "value".into(), newname: "renamed".into(),
        }},
    ]);
    assertions::apply_program_scoped(&mut program);
    let results = decompile_targets(&mut program, vec![entry], false, false, false).unwrap();
    let result = &results[0];
    assert!(result.error.is_none(), "{:?}", result.error);
    let formals: Vec<_> = result.variables.iter().filter(|variable| variable.is_param)
        .map(|variable| (variable.name.as_str(), variable.size)).collect();
    assert_eq!(formals, [("renamed", 1), ("other", 1)]);
    let c = result.code.as_ref().unwrap();
    assert!(c.contains("renamed") && c.contains("other"), "{c}");
}




#[test]
fn link_register_bodies_preserve_declared_zero_arity_and_plain_return_export() {
    let mut image = vec![0u8; 0x24];
    image[..8].copy_from_slice(&[0xe0, 0x03, 0x1e, 0xaa, 0xc0, 0x03, 0x5f, 0xd6]);
    image[0x20..].copy_from_slice(&[0xc0, 0x03, 0x5f, 0xd6]);
    let fixture = RawFixture::new("link-register-entry-state", &image);
    let mut program = bootstrap_from_raw(fixture.0.to_str().unwrap(),
        "AARCH64:LE:64:v8A:default", 0x1000, &[0x1000, 0x1020], None, &specs())
        .expect("actual AArch64 fixture and built specification");
    program.commit_pending_analysis().unwrap();
    let escape = program.find_entry_at(0x1000).unwrap();
    let plain = program.find_entry_at(0x1020).unwrap();
    program.set_assertions(vec![
        Directive { raw: "observable return".into(), body: Body::Prototype {
            func: escape.name.clone(), decl: format!("unsigned long long {}(void)", escape.name),
        }},
        Directive { raw: "control-only return".into(), body: Body::Prototype {
            func: plain.name.clone(), decl: format!("void {}(void)", plain.name),
        }},
    ]);
    assertions::apply_program_scoped(&mut program);
    assert!(program.assertion_outcomes().iter().all(|outcome| outcome.status == "applied"));
    let ordinary = decompile_targets(&mut program, vec![escape, plain.clone()], false, false, false).unwrap();
    for result in &ordinary {
        assert!(result.error.is_none(), "{:?}", result.error);
        assert!(result.variables.iter().all(|variable| !variable.is_param),
            "control or observable entry X30 is not an invented source formal");
        assert!(result.code.as_deref().unwrap().contains("return"), "ordinary return body remains readable");
    }
    let plain_export = kuna_console::project::decompile_export_targets(&mut program, vec![plain]).unwrap();
    assert!(plain_export[0].error.is_none(), "plain RET export must remain supported");
    assert!(plain_export[0].code.as_deref().unwrap().contains("return"), "plain void return must remain readable");
}

fn run_console(script: &str, isa: Option<&str>) -> std::process::Output {
    let roots = specs();
    let mut command = Command::new(env!("CARGO_BIN_EXE_decomp_dbg"));
    command
        .args(["-sleighpath", &roots[0]])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    match isa {
        Some(isa) => {
            command.env(kuna_console::engine::ARM_ISA_ENV, isa);
        }
        None => {
            command.env_remove(kuna_console::engine::ARM_ISA_ENV);
        }
    }
    let mut child = command.spawn().expect("spawn decomp_dbg");
    child
        .stdin
        .as_mut()
        .expect("console stdin")
        .write_all(script.as_bytes())
        .expect("write console commands");
    child.wait_with_output().expect("wait for decomp_dbg")
}

#[test]
fn raw_thumb_maps_base_zero_and_nonzero() {
    let fixture = RawFixture::thumb_return_7();
    let path = fixture.0.to_string_lossy();
    for (base, selected) in [(0, 0), (0x4000, 0x4001)] {
        let mut program = bootstrap_from_raw(
            &path,
            "ARM:LE:32:v4t:default",
            base,
            &[base, selected],
            Some(ArmIsa::Thumb),
            &specs(),
        ).expect("bootstrap raw ARM fixture with built specs");
        program.commit_pending_analysis().unwrap();
        assert_eq!(program.sections(), vec![(base, 4, 4)]);
        assert_eq!(program.num_symbols(), 1);
        let entry = program
            .find_entry_at(selected)
            .expect("seeded raw entry must resolve");
        assert_eq!(entry.addr.get_offset(), base);
        assert!(program.entry_bytes_mapped(&entry.addr));

        let results = decompile_targets(&mut program, vec![entry], true, false, false).unwrap();
        assert_eq!(results.len(), 1);
        assert!(results[0].error.is_none(), "{:?}", results[0].error);
        let code = results[0].code.as_deref().unwrap();
        assert!(
            code.contains("return 7;"),
            "unexpected raw Thumb body:\n{code}"
        );
    }
}

#[test]
fn raw_arm_data_addresses_preserve_their_low_bit() {
    let fixture = RawFixture::thumb_return_7();
    let path = fixture.0.to_string_lossy();
    let mut program = bootstrap_from_raw(
        &path,
        "ARM:LE:32:v4t:default",
        0x4000,
        &[0x4001],
        Some(ArmIsa::Thumb),
        &specs(),
    ).expect("bootstrap raw ARM fixture with built specs");
    program.commit_pending_analysis().unwrap();
    assert_eq!(program.input_address_offset(0x4001).unwrap(), 0x4001);
    assert_eq!(program.input_code_offset(0x4001).unwrap(), 0x4000);
    program.set_assertions(vec![
        Directive {
            raw: "data 0x4001 char odd_data".into(),
            body: Body::Data { addr: 0x4001, decl: "char odd_data".into() },
        },
        Directive {
            raw: "volatile 0x4001+1".into(),
            body: Body::Volatile { addr: 0x4001, size: 1 },
        },
    ]);
    assertions::apply_program_scoped(&mut program);
    assert!(program.assertion_outcomes().iter().all(|outcome| outcome.status == "applied"));
    let (_, address, _) = program
        .global_data_symbol_addresses()
        .into_iter()
        .find(|(name, _, _)| name == "odd_data")
        .expect("odd-address data symbol");
    assert_eq!(address.get_offset(), 0x4001);
    let code = program.arch().manage().get_default_code_space().unwrap();
    let odd = Address::new(std::rc::Rc::clone(code), 0x4001);
    let even = Address::new(std::rc::Rc::clone(code), 0x4000);
    assert_ne!(program.arch().symboltab.get_property(&odd) & varnode_flags::volatil, 0);
    assert_eq!(program.arch().symboltab.get_property(&even) & varnode_flags::volatil, 0);
}

#[test]
fn word_addressed_targets_scale_base_and_entries_to_byte_offsets() {
    let fixture = RawFixture::new("raw-avr-nops", &[0, 0, 0, 0]);
    let path = fixture.0.to_string_lossy();

    let mut at_nonzero_base =
        bootstrap_from_raw(&path, "avr8:LE:16:default", 0x100, &[0x100], None, &specs())
            .expect("bootstrap raw AVR fixture with built specs");
    at_nonzero_base.commit_pending_analysis().unwrap();
    assert_eq!(at_nonzero_base.sections(), vec![(0x200, 4, 4)]);
    let entry = at_nonzero_base
        .find_entry_at(0x200)
        .expect("word-addressed base must become a byte VMA");
    assert!(at_nonzero_base.entry_bytes_mapped(&entry.addr));
    assert_eq!(at_nonzero_base.output_code_offset(entry.addr.get_offset()), 0x100);
    assert_eq!(at_nonzero_base.output_code_end_offset(0x201), 0x101);

    let mut at_second_word = bootstrap_from_raw(&path, "avr8:LE:16:default", 0, &[1], None, &specs())
        .expect("same built AVR8 specification");
    at_second_word.commit_pending_analysis().unwrap();
    let entry = at_second_word
        .find_entry_at(2)
        .expect("entry word 1 must select file byte offset 2");
    assert_eq!(entry.addr.get_offset(), 2);
    assert_eq!(at_second_word.output_code_offset(entry.addr.get_offset()), 1);
    assert!(at_second_word.entry_bytes_mapped(&entry.addr));
}

#[test]
fn raw_console_reports_word_addresses_in_target_units() {
    let fixture = RawFixture::new("raw-word-report", &[0, 0, 0x08, 0x95]);
    let roots = specs();
    assert!(PathBuf::from(&roots[0])
        .join("Ghidra/Processors/Atmel/data/languages/avr8.sla")
        .exists(), "required processor specs must be available");
    let script = format!(
        "load raw avr8:LE:16:default 0x100 0x101 \"{}\"\n\
         read symbols\n\
         functions\n\
         load addr 0x101\n\
         decompile\n\
         region blocks\n\
         region tree\n\
         region walk\n\
         quit\n",
        fixture.0.display()
    );
    let output = run_console(&script, None);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(), "{stdout}\n{stderr}");
    for expected in ["0x101 sub_101", "[0x101]", "region head=0x101", "walk 0x101"] {
        assert!(stdout.contains(expected), "missing {expected:?}:\n{stdout}\n{stderr}");
    }
    for byte_address in ["0x202 sub_101", "[0x202]", "region head=0x202", "walk 0x202"] {
        assert!(
            !stdout.contains(byte_address),
            "leaked byte address {byte_address:?}:\n{stdout}\n{stderr}"
        );
    }
}

#[test]
fn raw_map_function_normalizes_an_odd_thumb_pointer() {
    let fixture = RawFixture::thumb_return_7();
    let roots = specs();
    assert!(PathBuf::from(&roots[0])
        .join("Ghidra/Processors/ARM/data/languages/ARM8_le.sla")
        .exists(), "required processor specs must be available");
    let script = format!(
        "load raw ARM:LE:32:v4t:default 0x4000 0x4000 \"{}\"\n\
         map function 0x4001 mapped_thumb\n\
         decompile\n\
         print C\n\
         quit\n",
        fixture.0.display()
    );
    let output = run_console(&script, Some("thumb"));
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(), "{stdout}\n{stderr}");
    assert!(stdout.contains("mapped_thumb"), "{stdout}\n{stderr}");
    assert!(stdout.contains("return 7;"), "{stdout}\n{stderr}");
}

#[test]
fn raw_map_address_preserves_an_odd_arm_data_address() {
    let fixture = RawFixture::new(
        "raw-thumb-odd-data",
        &[0x01, 0x48, 0x00, 0x78, 0x70, 0x47, 0, 0, 0x01, 0x40, 0, 0],
    );
    let roots = specs();
    assert!(PathBuf::from(&roots[0])
        .join("Ghidra/Processors/ARM/data/languages/ARM8_le.sla")
        .exists(), "required processor specs must be available");
    let script = format!(
        "load raw ARM:LE:32:v4t:default 0x4000 0x4001 \"{}\"\n\
         map address 0x4001 char odd_data\n\
         readonly 0x4008 4\n\
         option readonly on\n\
         read symbols\n\
         load addr 0x4001\n\
         decompile\n\
         print C\n\
         quit\n",
        fixture.0.display()
    );
    let output = run_console(&script, Some("thumb"));
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(), "{stdout}\n{stderr}");
    assert!(stdout.contains("return odd_data;"), "{stdout}\n{stderr}");
    assert!(!stdout.contains("return dat_4001;"), "{stdout}\n{stderr}");
}

#[test]
fn console_load_raw_preserves_whitespace_in_final_filename() {
    let fixture = RawFixture::thumb_return_7_with_spaces();
    let roots = specs();
    assert!(PathBuf::from(&roots[0])
        .join("Ghidra/Processors/ARM/data/languages/ARM8_le.sla")
        .exists(), "required processor specs must be available");
    let mut child = Command::new(env!("CARGO_BIN_EXE_decomp_dbg"))
        .args(["-sleighpath", &roots[0]])
        .env(kuna_console::engine::ARM_ISA_ENV, "thumb")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn decomp_dbg");
    writeln!(
        child.stdin.as_mut().expect("console stdin"),
        "load raw ARM:LE:32:v4t:default 0x4000 0x4001 \"{}\"\nquit",
        fixture.0.display()
    )
    .expect("write console commands");
    let output = child.wait_with_output().expect("wait for decomp_dbg");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(), "{stdout}\n{stderr}");
    assert!(stdout.contains("successfully loaded"), "{stdout}\n{stderr}");
}

#[test]
fn raw_input_rejects_missing_metadata_and_unmapped_entries() {
    let fixture = RawFixture::thumb_return_7();
    let path = fixture.0.to_string_lossy();

    let missing_target = bootstrap_from_raw(&path, "", 0, &[0], None, &specs())
        .err()
        .expect("missing target must fail")
        .explain()
        .to_string();
    assert!(missing_target.contains("requires --target"));

    let error = match bootstrap_from_raw(
        &path,
        "ARM:LE:32:v4t:default",
        0x4000,
        &[0x4000],
        None,
        &specs(),
    ) {
        Ok(_) => panic!("raw ARM input without --isa unexpectedly loaded"),
        Err(error) => error.explain().to_string(),
    };
    assert!(
        error.contains("requires --isa"),
        "unexpected error: {error}"
    );
}

#[test]
fn raw_input_rejects_entry_at_end_of_mapping() {
    let fixture = RawFixture::thumb_return_7();
    let path = fixture.0.to_string_lossy();
    let error = match bootstrap_from_raw(
        &path,
        "ARM:LE:32:v4t:default",
        0x4000,
        &[0x4004],
        Some(ArmIsa::Thumb),
        &specs(),
    ) {
        Ok(_) => panic!("out-of-range raw entry unexpectedly loaded"),
        Err(error) => error.explain().to_string(),
    };
    assert!(
        error.contains("outside mapped range"),
        "unexpected error: {error}"
    );
}

#[test]
fn word_addressed_mapping_errors_report_target_units() {
    let fixture = RawFixture::new("raw-word-bounds", &[0, 0, 0, 0]);
    let path = fixture.0.to_string_lossy();
    let error = match bootstrap_from_raw(
        &path,
        "avr8:LE:16:default",
        0x100,
        &[0x103],
        None,
        &specs(),
    ) {
        Ok(_) => panic!("out-of-range word-addressed entry unexpectedly loaded"),
        Err(error) => error.explain().to_string(),
    };
    assert!(
        error.contains("raw entry 0x103 is outside mapped range 0x100..0x102"),
        "unexpected error: {error}"
    );
    assert!(!error.contains("0x200..0x204"), "byte bounds leaked: {error}");
}

#[test]
fn raw_input_rejects_empty_images() {
    let fixture = RawFixture::new("raw-empty", &[]);
    let path = fixture.0.to_string_lossy();
    let error = match bootstrap_from_raw(
        &path,
        "ARM:LE:32:v4t:default",
        0,
        &[0],
        Some(ArmIsa::Thumb),
        &specs(),
    ) {
        Ok(_) => panic!("empty raw image unexpectedly loaded"),
        Err(error) => error.explain().to_string(),
    };
    assert!(
        error.contains("raw image is empty"),
        "unexpected error: {error}"
    );
}

#[test]
fn raw_input_rejects_mapping_overflow() {
    let fixture = RawFixture::thumb_return_7();
    let path = fixture.0.to_string_lossy();
    let error = match bootstrap_from_raw(
        &path,
        "ARM:LE:32:v4t:default",
        u64::MAX,
        &[u64::MAX],
        Some(ArmIsa::Thumb),
        &specs(),
    ) {
        Ok(_) => panic!("overflowing raw mapping unexpectedly loaded"),
        Err(error) => error.explain().to_string(),
    };
    assert!(error.contains("overflows"), "unexpected error: {error}");
}
