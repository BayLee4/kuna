//! Completed callable roots retain their binding when the live architecture default changes.
mod common;

use kuna_console::engine::ConsoleProgram;
use kuna_console::ifacedecomp::{register_console_commands, register_decomp_commands, IfaceDecompData, DECOMPILE_MODULE};
use kuna_console::ifaceterm::ConsoleCommands;
use kuna_console::interface::IfaceStatus;
use kuna_decomp::dtype::TypeRoot;
use kuna_decomp::fspec::{materialize_callable, LogicalCallable};

fn program(status: &mut IfaceStatus) -> &ConsoleProgram {
    status.get_data_mut(DECOMPILE_MODULE).unwrap().as_any_mut()
        .downcast_mut::<IfaceDecompData>().unwrap().conf.as_ref().unwrap()
}
fn run(status: &mut IfaceStatus, count: usize) {
    for _ in 0..count { assert!(status.run_command().unwrap()); }
}
fn code(program: &ConsoleProgram, name: &str) -> TypeRoot {
    program.arch().types().find_by_name(name).unwrap().unwrap().get_ptr_to().unwrap()
}
fn logical(code: &TypeRoot) -> LogicalCallable {
    code.read().get_code_prototype(code.id()).unwrap().unwrap().clone()
}
fn verify(program: &ConsoleProgram, root: &TypeRoot, name: &str, model: &str, variadic: bool, first: Option<i32>, stack: bool) {
    let declaration = logical(root);
    assert_eq!(declaration.binding.model().get_name(), model);
    assert_eq!(declaration.inputs.len(), 1);
    assert_eq!(declaration.variadic, variadic);
    assert_eq!(declaration.logical_first, first);
    assert_eq!(declaration.input_closed, !variadic);
    let abi = materialize_callable(program.arch().types(), root).unwrap().unwrap();
    let parameter = abi.prototype().get_param(0).unwrap();
    let address = parameter.get_address();
    if stack {
        assert_eq!(address.get_space().unwrap().get_name(), "stack");
        assert_eq!(address.get_offset(), 4);
        assert_eq!(parameter.get_size(), 4);
    } else {
        let ecx = program.arch().get_register_varnode(b"ECX").unwrap();
        assert!(std::rc::Rc::ptr_eq(address.get_space().unwrap(), ecx.space.as_ref().unwrap()));
        assert_eq!(address.get_offset(), ecx.offset);
        assert_eq!(parameter.get_size(), i32::try_from(ecx.size).unwrap());
    }
    assert_eq!(abi.prototype().is_dotdotdot(), variadic);
    assert_eq!(abi.prototype().get_abi_first_vararg(), first);
    println!("{name}: root={:?} context={:?} binding={:?} model={} variadic={} logical_first={:?} input={}:0x{:x}/{}", root.id(), declaration.binding.context_id(), declaration.binding.id(), model, variadic, first, address.get_space().unwrap().get_name(), address.get_offset(), parameter.get_size());
}
#[test]
fn completed_nested_roots_keep_identity_and_abi_after_default_switch() {
    let repo = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../..").canonicalize().unwrap();
    let fixture = Fixture(common::scratch_file("nested-callable-binding", "fixture"));
    let result = std::process::Command::new("python3")
        .arg(repo.join("tests/ghidra/callable/build_nested_default_binding.py"))
        .arg("--out").arg(&fixture.0).output().expect("fixture builder requires python3");
    assert!(result.status.success(), "fixture construction failed: {}\n{}",
        String::from_utf8_lossy(&result.stdout), String::from_utf8_lossy(&result.stderr));
    let binary = fixture.0.join("nested.elf");
    let specs = std::env::var("KUNA_SPECS")
        .unwrap_or_else(|_| repo.join("specs").to_string_lossy().into_owned());
    let before = vec![
        format!("load file x86:LE:32:default:windows {}", binary.display()),
        "read symbols".into(),
        "option defaultprototype __stdcall".into(),
        "parse line typedef int (*Old)(int);".into(),
        "parse line typedef int (__fastcall *Explicit)(int,...);".into(),
        "parse line typedef Explicit (*Nested)(int);".into(),
        "parse line extern int __cdecl call_old(Old callback,int value);".into(),
        "parse line extern Nested __cdecl nested_identity(Nested value);".into(),
        "load function call_old".into(),
        "decompile".into(),
    ];
    let after = vec![
        "option defaultprototype __fastcall".into(),
        "parse line typedef int (*Future)(int);".into(),
        "parse line extern int __cdecl call_future(Future callback,int value);".into(),
        "load function call_old".into(), "decompile".into(),
        "load function call_future".into(), "decompile".into(),
        "load function nested_identity".into(), "decompile".into(),
    ];
    let mut commands = before.clone(); commands.extend(after.clone());
    let mut status = ConsoleCommands::into_status(commands);
    register_decomp_commands(&mut status); register_console_commands(&mut status);
    status.get_data_mut(DECOMPILE_MODULE).unwrap().as_any_mut()
        .downcast_mut::<IfaceDecompData>().unwrap().spec_roots = vec![specs];
    run(&mut status, before.len());
    let p = program(&mut status);
    let old = code(p, "Old"); let nested = code(p, "Nested"); let explicit = code(p, "Explicit");
    let old_before = logical(&old); let nested_before = logical(&nested); let explicit_before = logical(&explicit);
    verify(p, &old, "Old before", "__stdcall", false, None, true);
    verify(p, &nested, "Nested before", "__stdcall", false, None, true);
    verify(p, &explicit, "Explicit before", "__fastcall", true, Some(1), false);
    assert_eq!(nested.related(nested_before.output).unwrap().get_ptr_to().unwrap().id(), explicit.id());
    run(&mut status, after.len());
    let p = program(&mut status);
    for (name, retained, binding) in [("Old", &old, &old_before.binding), ("Nested", &nested, &nested_before.binding), ("Explicit", &explicit, &explicit_before.binding)] {
        let current = code(p, name);
        assert_eq!(retained.id(), current.id(), "persistent source root identity changed");
        assert_eq!(&logical(&current).binding, binding, "completed declaration rebound after default switch");
    }
    let future = code(p, "Future");
    assert_ne!(logical(&future).binding, old_before.binding);
    assert_eq!(logical(&future).binding, explicit_before.binding);
    verify(p, &old, "Old after", "__stdcall", false, None, true);
    verify(p, &nested, "Nested after", "__stdcall", false, None, true);
    verify(p, &explicit, "Explicit after", "__fastcall", true, Some(1), false);
    verify(p, &future, "Future after", "__fastcall", false, None, false);
    let inner = nested.related(logical(&nested).output).unwrap().get_ptr_to().unwrap();
    assert_eq!(inner.id(), explicit.id());
    assert_eq!(logical(&inner).binding, explicit_before.binding);
    assert_eq!(logical(&inner).logical_first, Some(1));
    assert!(logical(&inner).variadic);
    println!("PASS: one actual IfaceStatus/Architecture, immutable completed roots, default binds future only, exact ABI slots, recursive nested explicit variadic boundary retained");
}

struct Fixture(std::path::PathBuf);
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
