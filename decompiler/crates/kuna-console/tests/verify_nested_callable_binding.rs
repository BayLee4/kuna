//! Completed source callback declarations keep their ABI after the default changes.
use crate::common;
use std::rc::Rc;
use kuna_console::engine::ConsoleProgram;
use kuna_console::ifacedecomp::{register_console_commands, register_decomp_commands, IfaceDecompData, DECOMPILE_MODULE};
use kuna_console::ifaceterm::ConsoleCommands;
use kuna_console::interface::IfaceStatus;
use kuna_decomp::dtype::Datatype;

fn program(status: &mut IfaceStatus) -> &ConsoleProgram {
    status.get_data_mut(DECOMPILE_MODULE).unwrap().as_any_mut()
        .downcast_mut::<IfaceDecompData>().unwrap().conf.as_ref().unwrap()
}
fn run(status: &mut IfaceStatus, count: usize) {
    for _ in 0..count { assert!(status.run_command().unwrap()); }
}
fn code(program: &ConsoleProgram, name: &str) -> Rc<Datatype> {
    program.arch().types().find_by_name(name).unwrap().unwrap().get_ptr_to().unwrap()
}
fn verify(program: &ConsoleProgram, code: &Datatype, model: &str, variadic: bool, stack: bool) {
    let prototype = code.get_code_prototype().expect("actual source callable prototype");
    assert_eq!(prototype.model().get_name(), model);
    assert_eq!(prototype.num_params(), 1);
    assert_eq!(prototype.is_dotdotdot(), variadic);
    let parameter = prototype.get_param(0).unwrap();
    let address = parameter.get_address();
    assert_eq!(parameter.get_size(), 4);
    if stack {
        assert_eq!(address.get_space().unwrap().get_name(), "stack");
        assert_eq!(address.get_offset(), 4);
    } else {
        let ecx = program.arch().get_register_varnode(b"ECX").unwrap();
        assert!(Rc::ptr_eq(address.get_space().unwrap(), ecx.space.as_ref().unwrap()));
        assert_eq!(address.get_offset(), ecx.offset);
    }
}

#[test]
fn completed_nested_roots_keep_identity_and_abi_after_default_switch() {
    let repo = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../..").canonicalize().unwrap();
    let fixture = Fixture(common::scratch_file("nested-callable-binding", "fixture"));
    let result = std::process::Command::new("python3")
        .arg(repo.join("tests/ghidra/callable/build_nested_default_binding.py"))
        .arg("--out").arg(&fixture.0).output().expect("original fixture builder requires python3");
    assert!(result.status.success(), "fixture construction failed: {}\n{}",
        String::from_utf8_lossy(&result.stdout), String::from_utf8_lossy(&result.stderr));
    let before = vec![
        format!("load file x86:LE:32:default:windows {}", fixture.0.join("nested.elf").display()),
        "read symbols".into(), "option defaultprototype __stdcall".into(),
        "parse line typedef int (*Old)(int);".into(),
        "parse line typedef int (__fastcall *Explicit)(int,...);".into(),
        "parse line typedef Explicit (*Nested)(int);".into(),
        "parse line extern int __cdecl call_old(Old callback,int value);".into(),
        "parse line extern Nested __cdecl nested_identity(Nested value);".into(),
        "load function call_old".into(), "decompile".into(),
    ];
    let after: Vec<String> = [
        "option defaultprototype __fastcall", "parse line typedef int (*Future)(int);",
        "parse line extern int __cdecl call_future(Future callback,int value);",
        "load function call_old", "decompile", "load function call_future", "decompile",
        "load function nested_identity", "decompile",
    ].into_iter().map(str::to_owned).collect();
    let mut commands = before.clone(); commands.extend(after.clone());
    let mut status = ConsoleCommands::into_status(commands);
    register_decomp_commands(&mut status); register_console_commands(&mut status);
    status.get_data_mut(DECOMPILE_MODULE).unwrap().as_any_mut().downcast_mut::<IfaceDecompData>().unwrap()
        .spec_roots = vec![std::env::var("KUNA_SPECS").unwrap_or_else(|_| repo.join("specs").to_string_lossy().into_owned())];
    run(&mut status, before.len());
    let p = program(&mut status);
    let old = code(p, "Old"); let nested = code(p, "Nested"); let explicit = code(p, "Explicit");
    verify(p, &old, "__stdcall", false, true);
    verify(p, &nested, "__stdcall", false, true);
    verify(p, &explicit, "__fastcall", true, false);
    let returned = nested.get_code_prototype().unwrap().get_output().get_type().unwrap().get_ptr_to().unwrap();
    verify(p, &returned, "__fastcall", true, false);
    run(&mut status, after.len());
    let p = program(&mut status);
    for (name, held) in [("Old", &old), ("Nested", &nested), ("Explicit", &explicit)] {
        let current = code(p, name);
        assert_eq!(current.get_id(), held.get_id(), "{name}: source nominal identity changed");
        assert!(Rc::ptr_eq(&current, held), "{name}: default change replaced a completed callable");
    }
    for (name, model, variadic, stack) in [
        ("Old", "__stdcall", false, true), ("Nested", "__stdcall", false, true),
        ("Explicit", "__fastcall", true, false), ("Future", "__fastcall", false, false),
    ] { verify(p, &code(p, name), model, variadic, stack); }
    verify(p, &old, "__stdcall", false, true);
    verify(p, &nested, "__stdcall", false, true);
    verify(p, &explicit, "__fastcall", true, false);
    let returned = code(p, "Nested").get_code_prototype().unwrap().get_output().get_type().unwrap().get_ptr_to().unwrap();
    verify(p, &returned, "__fastcall", true, false);
}
struct Fixture(std::path::PathBuf);
impl Drop for Fixture {
    fn drop(&mut self) { let _ = std::fs::remove_dir_all(&self.0); }
}
