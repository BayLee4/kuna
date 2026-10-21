//! Compiler-built DWARF declarations through the ordinary loader, source owner and C consumer.
use std::path::{Path, PathBuf};
use std::process::Command;
use kuna_console::engine::{bootstrap_from_object, ConsoleProgram};
use kuna_console::ifacedecomp::{execute, register_decomp_commands, IfaceDecompData, DECOMPILE_MODULE};
use kuna_console::ifaceterm::ConsoleCommands;
use kuna_decomp::dtype::type_metatype;
use kuna_decomp::fspec::PrototypePieces;
use kuna_decomp::varnode::varnode_flags;
use kuna_harness::dwarf_fixture as producer;

fn callable_child(name: &str) -> bool {
    const CHILD: &str = "KUNA_CONSOLE_DWARF_DECLARATION_CHILD";
    if std::env::var(CHILD).as_deref() == Ok(name) {
        assert!(kuna_decomp::kuna_calltargettype::dwarf_function_types());
        return true;
    }
    let output = Command::new(std::env::current_exe().expect("current declaration test executable"))
        .args(["--exact", name, "--nocapture", "--include-ignored"])
        .env(CHILD, name)
        .env(kuna_decomp::kuna_calltargettype::CALLTARGETTYPE_ENV, "on")
        .env(kuna_decomp::kuna_dwarftypedefs::DWARFTYPEDEFS_ENV, "on")
        .output()
        .expect("isolated declaration test child");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stdout.contains("running 1 test") && output.status.success(),
        "{name} child must execute its original source assertions: {:?}\n{stdout}\n{stderr}",
        output.status);
    print!("{stdout}");
    eprint!("{stderr}");
    false
}

fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../kuna-analysis/tests/fixtures")
}

fn boot(path: &Path) -> ConsoleProgram {
    boot_with_cppproto(path, true)
}

fn boot_with_cppproto(path: &Path, cppproto: bool) -> ConsoleProgram {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../..");
    let specs = vec![root.join("specs").to_str().unwrap().to_string()];
    let mut program = bootstrap_from_object(path.to_str().unwrap(), "", &specs)
        .expect("actual loader requires usable processor specs and a real compiler-built image");
    program.arch_mut().analysis_cppproto = cppproto;
    program.commit_pending_analysis().unwrap();
    program
}

fn pieces<'a>(program: &'a ConsoleProgram, name: &str) -> &'a PrototypePieces {
    let (_, address) = program.function_entries().find(|(entry, _)| *entry == name)
        .unwrap_or_else(|| panic!("missing genuine function {name}"));
    program.arch().symboltab.function_proto_pieces_across_scopes(address)
        .unwrap_or_else(|| panic!("known source declaration was discarded: {name}"))
}

fn require_declared_noreturn(path: &Path, callback: &str) {
    use std::collections::{BTreeMap, BTreeSet};
    let dumper = std::env::var_os("KUNA_DWARF_DUMP").unwrap_or_else(|| "llvm-dwarfdump".into());
    let output = Command::new(&dumper).arg("--debug-info").arg(path).output()
        .expect("noreturn producer prerequisite requires llvm-dwarfdump or KUNA_DWARF_DUMP");
    assert!(output.status.success(), "DWARF fact dumper {dumper:?} failed:\n{}",
        String::from_utf8_lossy(&output.stderr));
    let text = String::from_utf8(output.stdout).expect("DWARF fact dump must be UTF-8");
    let mut dies = BTreeMap::<u64, (&str, Vec<&str>)>::new();
    let mut current = None;
    for line in text.lines().map(str::trim) {
        if let Some((offset, tag)) = line.split_once(':') {
            if let Some(hex) = offset.strip_prefix("0x") {
                let offset = u64::from_str_radix(hex, 16).expect("DWARF DIE offset");
                dies.insert(offset, (tag.trim(), Vec::new()));
                current = Some(offset);
                continue;
            }
        }
        if line.starts_with("DW_AT_") {
            if let Some(offset) = current {
                dies.get_mut(&offset).unwrap().1.push(line);
            }
        }
    }
    let authored_name = format!("(\"{callback}\")");
    let mut offset = *dies.iter().find(|(_, (tag, attributes))| {
        *tag == "DW_TAG_typedef" && attributes.iter().any(|attribute| {
            attribute.starts_with("DW_AT_name") && attribute.ends_with(&authored_name)
        })
    }).expect("producer omitted authored callback typedef").0;
    let gnu_c = dies.range(..=offset).rev()
        .find(|(_, (tag, _))| *tag == "DW_TAG_compile_unit")
        .is_some_and(|(_, (_, attributes))| {
            attributes.iter().any(|attribute| attribute.starts_with("DW_AT_producer")
                && attribute.contains("(\"GNU C"))
                && attributes.iter().any(|attribute| attribute.starts_with("DW_AT_language")
                    && ["(DW_LANG_C)", "(DW_LANG_C89)", "(DW_LANG_C99)", "(DW_LANG_C11)"]
                        .iter().any(|language| attribute.ends_with(language)))
        });
    let mut function_volatile = false;
    let mut seen = BTreeSet::new();
    loop {
        assert!(seen.insert(offset), "producer callback DIE chain cycles");
        let (tag, attributes) = dies.get(&offset).expect("producer callback reference is absent");
        if *tag == "DW_TAG_subroutine_type" {
            let declared = attributes.iter().any(|attribute| {
                attribute.starts_with("DW_AT_noreturn") && attribute.ends_with("(true)")
            }) || (gnu_c && function_volatile);
            assert!(declared, "producer-missing: actual {callback} subroutine DIE {offset:#x} supplies neither a true DW_AT_noreturn nor GNU C volatile-function no-return; no importer verdict");
            return;
        }
        assert!(matches!(*tag, "DW_TAG_typedef" | "DW_TAG_pointer_type" |
            "DW_TAG_const_type" | "DW_TAG_volatile_type" | "DW_TAG_restrict_type"),
            "producer callback chain reached unexpected {tag}");
        if *tag == "DW_TAG_pointer_type" {
            function_volatile = false;
        } else if *tag == "DW_TAG_volatile_type" {
            function_volatile = true;
        }
        let reference = attributes.iter().find(|attribute| attribute.starts_with("DW_AT_type"))
            .expect("producer callback DIE has no type reference");
        let hex = reference.split_once("(0x").expect("DWARF type reference offset").1
            .split(|character: char| !character.is_ascii_hexdigit()).next().unwrap();
        offset = u64::from_str_radix(hex, 16).expect("DWARF callback type offset");
    }
}

fn emitted(program: ConsoleProgram, name: &str) -> String {
    let commands = vec![format!("load function {name}"), "decompile".into(), "print C".into()];
    let mut status = ConsoleCommands::into_status(commands);
    register_decomp_commands(&mut status);
    status.get_data_mut(DECOMPILE_MODULE).unwrap().as_any_mut()
        .downcast_mut::<IfaceDecompData>().unwrap().conf = Some(program);
    for _ in 0..3 { execute(&mut status); }
    let text = &status.optr;
    assert!(!text.contains("Execution error"), "decompile {name}:\n{text}");
    let signature = text.find(&format!("{name}(")).unwrap_or_else(|| panic!("no C definition for {name}:\n{text}"));
    let start = text[..signature].rfind('\n').map_or(0, |i| i + 1);
    let brace = text[signature..].find('{').map(|i| i + signature).expect("C body");
    let mut depth = 0;
    for (i, byte) in text.as_bytes().iter().enumerate().skip(brace) {
        if *byte == b'{' { depth += 1; }
        if *byte == b'}' {
            depth -= 1;
            if depth == 0 { return text[start..=i].to_string(); }
        }
    }
    panic!("unterminated C body for {name}");
}

fn execute_c(directory: &Path, body: &str, source: &Path, name: &str, driver: &str, flags: &[&str]) {
    let compiler = std::env::var_os("KUNA_DWARF_CC").unwrap_or_else(|| "clang".into());
    let consumer = directory.join(format!("{name}-consumer.c"));
    let text = format!(
        "#include <stdint.h>\ntypedef int8_t int1; typedef uint8_t uint1; typedef int16_t int2; typedef uint16_t uint2; typedef int32_t int4; typedef uint32_t uint4; typedef int64_t int8; typedef uint64_t uint8;\n#define main retained_source_main\n#define {name} retained_source_{name}\n#include \"{}\"\n#undef {name}\n#undef main\n{body}\n{driver}\n", source.canonicalize().unwrap().display()
    );
    std::fs::write(&consumer, text).unwrap();
    for optimization in ["-O0", "-O2"] {
        let executable = directory.join(format!("{name}-{}", &optimization[1..]));
        let result = Command::new(&compiler).args(["-std=c11", optimization]).args(flags)
            .arg(&consumer).arg("-o").arg(&executable).output().expect("execution compiler");
        assert!(result.status.success(), "unchanged emitted {name} must compile at {optimization}:\n{}\n{body}", String::from_utf8_lossy(&result.stderr));
        let result = Command::new(&executable).output().expect("run unchanged emitted consumer");
        assert!(result.status.success(), "{name} value/ABI mismatch at {optimization}: {:?}\n{body}", result.status);
    }
}

#[test]
fn dwarf_c_open_closed_fixed_and_variadic_source_facts_stay_distinct() {
    if !callable_child("dwarf_c_open_closed_fixed_and_variadic_source_facts_stay_distinct") { return; }
    for standard in ["c89", "c11"] {
        let fixture = producer::compile_dwarf(&fixtures().join("dwarf_callback_prototyped.c"), standard, &[]);
        let program = boot(&fixture.path);
        for (name, formal_count, callback_count, variadic, closed) in [
            ("invoke_open", 2, 0, false, false), ("invoke_closed", 1, 0, false, true),
            ("invoke_fixed", 2, 1, false, true), ("invoke_variadic", 2, 1, true, false),
        ] {
            let source = pieces(&program, name);
            assert_eq!(source.intypes.len(), formal_count);
            assert_eq!(source.outtype.as_ref().unwrap().get_metatype(), type_metatype::TYPE_INT);
            assert_eq!(source.innames[0], "callback");
            if formal_count == 2 { assert_eq!(source.innames[1], "value"); }
            let code = source.intypes[0].get_ptr_to().unwrap();
            let proto = code.get_code_prototype().expect("supplied callback must not be void* or anonymous code");
            assert_eq!(proto.num_params(), callback_count, "{standard} {name}");
            assert_eq!(proto.is_dotdotdot(), variadic, "{standard} {name}");
            assert_eq!(proto.is_input_locked() && !proto.is_dotdotdot(), closed, "{standard} {name}: unknown physical inputs are not a closed empty signature");
            assert_eq!(proto.get_output_type().unwrap().get_size(), 4);
        }
    }
}

macro_rules! callback_execution {
    ($test:ident, $name:literal, $driver:literal) => {
        #[test]
        fn $test() {
            if !callable_child(stringify!($test)) { return; }
            for standard in ["c89", "c11"] {
                let source = fixtures().join("dwarf_callback_prototyped.c");
                let fixture = producer::compile_dwarf(&source, standard, &[]);
                let body = emitted(boot(&fixture.path), $name);
                execute_c(fixture.path.parent().unwrap(), &body, &source, $name, $driver, &[]);
            }
        }
    };
}
callback_execution!(closed_callback_stays_closed_at_o0_o2, "invoke_closed", "int main(void) { return invoke_closed(target_closed) != 7; }");
callback_execution!(fixed_callback_preserves_argument_at_o0_o2, "invoke_fixed", "int main(void) { return invoke_fixed(target_fixed, 41) != 43 || invoke_fixed(target_fixed, 99) != 101; }");
callback_execution!(variadic_callback_preserves_tail_at_o0_o2, "invoke_variadic", "int tail_provider(int x, ...) { __builtin_va_list ap; int tail; __builtin_va_start(ap,x); tail = __builtin_va_arg(ap,int); __builtin_va_end(ap); return x + tail; } int main(void) { return invoke_variadic(target_variadic, 41) != 44 || invoke_variadic(target_variadic, 99) != 102 || invoke_variadic(tail_provider, 41) != 44 || invoke_variadic(tail_provider, 99) != 102; }");

#[test]
fn old_style_definition_keeps_known_formals_and_values() {
    let source = fixtures().join("dwarf_declarations.c");
    for standard in ["c89", "c11"] {
        let fixture = producer::compile_dwarf(&source, standard, &[]);
        for cppproto in [false, true] {
            let program = boot_with_cppproto(&fixture.path, cppproto);
            let entry = program.function_entries_canonical().into_iter()
                .find(|entry| entry.name == "target_open").unwrap();
            let prototype = program.arch().symboltab
                .function_source_proto_across_scopes(&entry.addr).unwrap();
            assert!(prototype.is_input_locked(), "the actual definition owns its formals");
            let parameter = prototype.get_param(0).unwrap();
            assert_eq!(parameter.get_name(), "x");
            assert_eq!(parameter.get_type().unwrap().get_size(), 4);
            let body = emitted(program, "target_open");
            kuna_harness::c_behavior::assert_c_parameters(
                &body, "target_open", &["x"], "int (*)(int)",
            );
            execute_c(fixture.path.parent().unwrap(), &body, &source, "target_open", r#"
#include <limits.h>
int main(void) {
    const int values[] = { INT_MIN, -99, -1, 0, 1, 41, 99, INT_MAX - 1 };
    for (unsigned i = 0; i < sizeof(values) / sizeof(values[0]); ++i)
        if (target_open(values[i]) != retained_source_target_open(values[i]))
            return 1;
    return 0;
}
"#, &[]);
        }
    }
}

#[test]
fn cpp_absent_prototyped_is_closed_and_declared_conventions_survive() {
    if !callable_child("cpp_absent_prototyped_is_closed_and_declared_conventions_survive") { return; }
    let fixture = producer::compile_dwarf(&fixtures().join("dwarf_callback_conventions.cpp"), "c++11", &["--target=i686-w64-windows-gnu"]);
    let program = boot(&fixture.path);
    for (name, model, count) in [("invoke_empty", None, 0), ("invoke_stdcall", Some("__stdcall"), 1), ("invoke_fastcall", Some("__fastcall"), 1), ("invoke_thiscall", Some("__thiscall"), 2)] {
        let source = pieces(&program, name);
        let code = source.intypes[0].get_ptr_to().unwrap();
        let proto = code.get_code_prototype().expect("actual COFF DWARF callback declaration");
        assert_eq!(proto.num_params(), count, "{name}");
        assert!(proto.is_input_locked(), "C++ absence is not C nonprototype evidence: {name}");
        assert!(!proto.is_dotdotdot());
        if let Some(model) = model { assert_eq!(proto.get_model_name(), model, "explicit nondefault convention"); }
    }
}

#[test]
fn supplied_callback_order_and_alias_survive_loader() {
    if !callable_child("supplied_callback_order_and_alias_survive_loader") { return; }
    let fixture = producer::compile_dwarf(&fixtures().join("dwarf_declarations.c"), "c11", &[]);
    let program = boot(&fixture.path);
    let source = pieces(&program, "invoke_flags");
    assert_eq!(source.innames, ["value", "callback"]);
    assert_eq!(source.intypes[0].get_name(), "Flags");
    let code = source.intypes[1].get_ptr_to().unwrap();
    let proto = code.get_code_prototype().expect("supplied callback facts");
    assert_eq!(proto.num_params(), 2);
    for (index, meta, name) in [(0, type_metatype::TYPE_UINT, "Flags"), (1, type_metatype::TYPE_INT, "signed char")] {
        let ty = proto.get_param(index).unwrap().get_type().unwrap();
        assert_eq!((ty.get_size(), ty.get_metatype(), ty.get_name()), (1, meta, name));
    }
}

#[test]
#[ignore = "producer-dependent: requires callback no-return encoded in actual DWARF"]
fn supplied_noreturn_callback_effect_survives_loader() {
    if !callable_child("supplied_noreturn_callback_effect_survives_loader") { return; }
    let fixture = producer::compile_dwarf(&fixtures().join("dwarf_declarations.c"), "c11", &[]);
    require_declared_noreturn(&fixture.path, "NoReturn");
    let program = boot(&fixture.path);
    let source = pieces(&program, "invoke_noreturn");
    let code = source.intypes[0].get_ptr_to().unwrap();
    assert!(code.get_code_prototype().expect("declared noreturn callback").is_no_return());
}

#[test]
fn explicit_character_types_execute_under_both_plain_char_modes() {
    for mode in ["-fsigned-char", "-funsigned-char"] {
        let source = fixtures().join("dwarf_declarations.c");
        let fixture = producer::compile_dwarf(&source, "c11", &[mode]);
        for (name, driver) in [
            ("unsigned_identity", "_Static_assert(_Generic(&unsigned_identity, unsigned char (*)(unsigned char): 1, default: 0), \"explicit unsigned char signature\"); int main(void) { return unsigned_identity(0x80) != 128 || unsigned_identity(0xff) != 255; }"),
            ("signed_identity", "_Static_assert(_Generic(&signed_identity, signed char (*)(signed char): 1, default: 0), \"explicit signed char signature\"); int main(void) { return signed_identity(-128) != -128 || signed_identity(-1) != -1; }"),
        ] {
            for cppproto in [false, true] {
                let body = emitted(boot_with_cppproto(&fixture.path, cppproto), name);
                execute_c(fixture.path.parent().unwrap(), &body, &source, name, driver, &[mode]);
            }
        }
    }
}

#[test]
fn plain_character_signature_and_values_follow_the_producer_mode() {
    let source = fixtures().join("dwarf_declarations.c");
    for mode in ["-fsigned-char", "-funsigned-char"] {
        let fixture = producer::compile_dwarf(&source, "c11", &[mode]);
        let driver = r#"
#include <string.h>
_Static_assert(_Generic(&plain_identity, char (*)(char): 1, default: 0),
               "plain char input and return must retain their source type");
int main(void) {
    for (unsigned bits = 0; bits < 256; ++bits) {
        unsigned char raw = (unsigned char)bits;
        char value;
        memcpy(&value, &raw, sizeof(value));
        if ((int)plain_identity(value) != (int)retained_source_plain_identity(value))
            return 1;
    }
    return 0;
}
"#;
        for cppproto in [false, true] {
            let body = emitted(boot_with_cppproto(&fixture.path, cppproto), "plain_identity");
            execute_c(fixture.path.parent().unwrap(), &body, &source, "plain_identity", driver, &[mode]);
        }
    }
}

#[test]
fn recursive_callback_and_alias_use_completed_layout() {
    if !callable_child("recursive_callback_and_alias_use_completed_layout") { return; }
    let fixture = producer::compile_dwarf(&fixtures().join("dwarf_declarations.c"), "c11", &[]);
    let program = boot(&fixture.path);
    let source = pieces(&program, "node_identity");
    assert_eq!(source.innames, ["value"]);
    let node = source.intypes[0].get_ptr_to().unwrap();
    assert_eq!(node.get_name(), "Node");
    assert!(!node.is_incomplete());
    let next = node.get_field(0).unwrap();
    let retained = next.field_type.get_ptr_to().unwrap();
    assert_eq!((retained.get_id(), retained.get_name()), (node.get_id(), node.get_name()));
    assert_eq!(retained.get_size(), node.get_size());
    assert_eq!(retained.get_field(0).unwrap().name, "next");
    let code = node.get_field(1).unwrap().field_type.get_ptr_to().unwrap();
    let proto = code.get_code_prototype().expect("source recursive callback");
    assert_eq!(proto.get_output_type().unwrap().get_metatype(), type_metatype::TYPE_VOID);
    assert_eq!(proto.num_params(), 1);
    let parameter = proto.get_param(0).unwrap().get_type().unwrap().get_ptr_to().unwrap();
    assert_eq!((parameter.get_id(), parameter.get_name()), (node.get_id(), node.get_name()));
    assert_eq!(parameter.get_size(), node.get_size());
    assert_eq!(parameter.get_field(1).unwrap().name, "visit");
    let (field_pointer, offset, _, _) = program.arch().types_impl()
        .down_chain(&next.field_type, 8, false).unwrap();
    let field_pointer = field_pointer.expect("held next pointer must resolve the visit field");
    assert_eq!(offset, 0);
    let field = field_pointer.get_ptr_to().unwrap();
    assert_eq!(field.get_metatype(), type_metatype::TYPE_PTR);
    let resolved_code = field.get_ptr_to().unwrap();
    assert_eq!(resolved_code.get_metatype(), type_metatype::TYPE_CODE);
    let resolved = resolved_code.get_code_prototype().unwrap();
    assert_eq!(resolved.get_output_type().unwrap().get_metatype(), type_metatype::TYPE_VOID);
    assert_eq!(resolved.num_params(), 1);
    let resolved_node = resolved.get_param(0).unwrap().get_type().unwrap().get_ptr_to().unwrap();
    assert_eq!(resolved_node.get_id(), node.get_id());
}

#[test]
fn typed_globals_keep_callback_array_extent_and_top_level_volatility() {
    if !callable_child("typed_globals_keep_callback_array_extent_and_top_level_volatility") { return; }
    let fixture = producer::compile_dwarf(&fixtures().join("dwarf_declarations.c"), "c11", &[]);
    let program = boot(&fixture.path);
    let database = &program.arch().symboltab;
    let global = database.get_global_scope().unwrap();
    for (name, volatile) in [("object_volatile", true), ("pointer_volatile", true), ("pointee_volatile", false)] {
        let ids = database.query_by_name(global, name);
        assert_eq!(ids.len(), 1, "genuine global {name}");
        let symbol = database.symbol(ids[0]);
        assert_ne!(symbol.flags & varnode_flags::typelock, 0, "source global is declared, not inferred: {name}");
        let storage = database.entry(symbol.scope, symbol.mapentry[0]);
        let effective = symbol.flags | storage.extraflags | database.get_property(&storage.addr);
        assert_eq!(effective & varnode_flags::volatil != 0, volatile, "top-level qualifier only: {name}");
    }
    let ids = database.query_by_name(global, "default_authors");
    let array = database.symbol(ids[0]).dtype.as_ref().unwrap();
    assert_eq!(array.num_elements(), Some(3));
    assert_eq!(array.get_array_base().unwrap().get_ptr_to().unwrap().get_name(), "char");
    let ids = database.query_by_name(global, "callback_global");
    let callback = database.symbol(ids[0]).dtype.as_ref().unwrap();
    assert_eq!(callback.get_name(), "Fixed");
    assert_eq!(callback.get_ptr_to().unwrap().get_metatype(), type_metatype::TYPE_CODE);
}

#[test]
fn dwarf_data_authority_is_independent_of_datasyms_and_preserves_user_mappings() {
    if !callable_child("dwarf_data_authority_is_independent_of_datasyms_and_preserves_user_mappings") {
        return;
    }
    let fixture = producer::compile_dwarf(&fixtures().join("dwarf_declarations.c"), "c11", &[]);
    let source = boot(&fixture.path);
    let database = &source.arch().symboltab;
    let global = database.get_global_scope().unwrap();
    let symbol = database.symbol(database.query_by_name(global, "callback_global")[0]);
    let storage = database.entry(symbol.scope, symbol.mapentry[0]);
    let offset = storage.addr.get_offset();
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../..");
    let specs = vec![root.join("specs").to_str().unwrap().to_string()];
    for dwarf in [false, true] {
        for datasyms in [false, true] {
            let mut program = bootstrap_from_object(fixture.path.to_str().unwrap(), "", &specs).unwrap();
            program.arch_mut().analysis_dwarf = dwarf;
            program.arch_mut().analysis_datasyms = datasyms;
            program.commit_pending_analysis().unwrap();
            let arch = program.arch();
            let address = kuna_base::address::Address::new(
                arch.manage().get_default_data_space().unwrap().clone(), offset,
            );
            let global = arch.symboltab.get_global_scope().unwrap();
            let mapped = arch.symboltab.find_container(
                global, &address, 1, &kuna_base::address::Address::new_invalid(),
            );
            assert_eq!(mapped.is_some(), dwarf || datasyms, "dwarf={dwarf} datasyms={datasyms}");
            let declarations = arch.symboltab.query_by_name(global, "callback_global");
            if dwarf {
                assert_eq!(declarations.len(), 1);
                let declared = arch.symboltab.symbol(declarations[0]);
                assert_ne!(declared.flags & varnode_flags::typelock, 0);
                let callback = declared.dtype.as_ref().unwrap();
                assert_eq!(callback.get_name(), "Fixed");
                assert_eq!(callback.get_ptr_to().unwrap().get_metatype(), type_metatype::TYPE_CODE);
            }
        }
    }
    let mut program = bootstrap_from_object(fixture.path.to_str().unwrap(), "", &specs).unwrap();
    let address = kuna_base::address::Address::new(
        program.arch().manage().get_default_data_space().unwrap().clone(), offset + 1,
    );
    let user_type = program.arch().types().get_base(1, type_metatype::TYPE_UINT).unwrap();
    let global = program.arch().symboltab.get_global_scope().unwrap();
    let (sid, _) = program.arch_mut().symboltab.add_symbol_mapped(
        global, "analyst_object", user_type.clone(), &address,
        &kuna_base::address::Address::new_invalid(),
    ).unwrap();
    program.arch_mut().symboltab.set_attribute(sid, varnode_flags::typelock | varnode_flags::namelock);
    program.commit_pending_analysis().unwrap();
    let database = &program.arch().symboltab;
    assert_eq!(database.query_by_name(global, "analyst_object"), [sid]);
    assert!(std::rc::Rc::ptr_eq(database.symbol(sid).dtype.as_ref().unwrap(), &user_type));
    assert!(database.query_by_name(global, "callback_global").is_empty(),
        "a debug declaration must not overlap an analyst mapping inside its extent");
}

#[test]
fn well_defined_count_authors_execution_driver() {
    let source = fixtures().join("typedepth_x86_64.c");
    let fixture = producer::compile_dwarf(&source, "c11", &[]);
    let body = emitted(boot(&fixture.path), "count_authors");
    let driver = format!("#define KUNA_EMITTED_DRIVER\n#include \"{}\"", fixtures().join("typedepth_execution_driver.c").canonicalize().unwrap().display());
    execute_c(fixture.path.parent().unwrap(), &body, &source, "count_authors", &driver, &[]);
}
