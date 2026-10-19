//! Compile unchanged emitted C and check its observable behavior.

use std::path::Path;
use std::process::Command;

pub fn assert_c_behavior(source: &Path, preamble: &str, body: &str, driver: &str, warnings: &[&str]) {
    let executable = source.with_extension("exe");
    std::fs::write(&source, format!("{preamble}\n{body}\n{driver}\n"))
        .expect("write emitted-C witness");
    let compiler = std::env::var_os("CC").unwrap_or_else(|| "cc".into());
    for optimization in ["-O0", "-O2"] {
        let built = Command::new(&compiler)
            .args(["-std=c11", optimization])
            .args(warnings)
            .arg(&source)
            .arg("-o")
            .arg(&executable)
            .output()
            .unwrap_or_else(|e| panic!("required C compiler {compiler:?}: {e}"));
        assert!(
            built.status.success(),
            "emitted C did not compile ({}):\n{}\n{}\n{body}",
            source.display(),
            String::from_utf8_lossy(&built.stdout),
            String::from_utf8_lossy(&built.stderr)
        );
        let ran = Command::new(&executable)
            .output()
            .expect("execute emitted-C witness");
        assert!(
            ran.status.success(),
            "emitted C changed observable behavior ({}):\n{}\n{}\n{body}",
            source.display(),
            String::from_utf8_lossy(&ran.stdout),
            String::from_utf8_lossy(&ran.stderr)
        );
        std::fs::remove_file(&executable).expect("remove witness executable");
    }
    std::fs::remove_file(&source).expect("remove witness source");
}

/// Check an emitted declaration with the C compiler, not a width-alias spelling.
/// The exact emitted declaration and requested storage home remain independent.
pub fn assert_c_declaration(code: &str, name: &str, expected: &str, home: &str) {
    assert_c_type(c_declaration(code, name, home), name, expected);
}

/// A width-only inferred baseline need not select one of C's equal-width ranks.
pub fn assert_c_signed_integer_declaration(code: &str, name: &str, bytes: usize, home: &str) {
    let condition = format!("sizeof({name}) == {bytes} && _Generic(({name}), signed char: 1, short: 1, int: 1, long: 1, long long: 1, default: 0)");
    assert_c_condition(c_declaration(code, name, home), &condition);
}

/// Keep unsigned inferred widths independent of C's equal-width integer ranks.
pub fn assert_c_unsigned_integer_declaration(code: &str, name: &str, bytes: usize, home: &str) {
    let condition = format!("sizeof({name}) == {bytes} && _Generic(({name}), unsigned char: 1, unsigned short: 1, unsigned int: 1, unsigned long: 1, unsigned long long: 1, default: 0)");
    assert_c_condition(c_declaration(code, name, home), &condition);
}

fn c_declaration<'a>(code: &'a str, name: &str, home: &str) -> &'a str {
    code.lines().find_map(|line| {
        let (declaration, sources) = line.trim().split_once(" // ")?;
        if !sources.split(" | ").any(|source| source == home) { return None; }
        let identifier = declaration.strip_suffix(';')?.split_whitespace().last()?.trim_start_matches('*');
        (identifier == name).then_some(declaration)
    }).unwrap_or_else(|| panic!("no declaration for {name} at {home}:\n{code}"))
}

/// Keep formal order/name assertions separate from prototype type compatibility.
pub fn assert_c_parameters(code: &str, function: &str, names: &[&str], expected: &str) {
    let (signature, open) = c_function_signature(code, function);
    let inputs = signature[open + 1..].split(')').next().unwrap();
    let actual: Vec<_> = inputs.split(',').map(|input|
        input.split_whitespace().last().unwrap().rsplit('*').next().unwrap()).collect();
    assert_eq!(actual, names, "parameter slots changed:\n{code}");
    assert_c_function_type(signature, function, expected);
}

/// Check the complete emitted prototype, including nested callable parameters.
pub fn assert_c_function_declaration<'a>(code: &'a str, function: &str, expected: &str) -> &'a str {
    let (signature, _) = c_function_signature(code, function);
    assert_c_function_type(signature, function, expected);
    signature
}

fn c_function_signature<'a>(code: &'a str, function: &str) -> (&'a str, usize) {
    // Reuse assertions::signature_declaration's exact function identity rule;
    // private implementations and forward declarations may precede the body.
    let parameter_open = |signature: &str| {
        signature.match_indices(function).find_map(|(start, _)| {
            let before = &signature[..start];
            let after = &signature[start + function.len()..];
            let parameters = after.trim_start();
            (!before.chars().last().is_some_and(|c| c.is_ascii_alphanumeric() || c == '_')
                && parameters.starts_with('('))
                .then_some(start + function.len() + after.len() - parameters.len())
        })
    };
    code.lines().zip(code.lines().skip(1))
        .filter(|(_, brace)| brace.trim() == "{")
        .find_map(|(signature, _)| parameter_open(signature).map(|open| (signature, open)))
        .or_else(|| code.lines().flat_map(|line| line.split(';'))
            .find_map(|signature| parameter_open(signature).map(|open| (signature, open))))
        .unwrap_or_else(|| panic!("no signature for {function}:\n{code}"))
}

fn assert_c_function_type(signature: &str, function: &str, expected: &str) {
    let declaration = format!("{};", signature.split(" // ").next().unwrap());
    assert_c_type(&declaration, &format!("&{function}"), expected);
}

fn assert_c_type(declaration: &str, expression: &str, expected: &str) {
    assert_c_condition(declaration, &format!("_Generic(({expression}), {expected}: 1, default: 0)"));
}

fn assert_c_condition(declaration: &str, condition: &str) {
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let source = std::env::temp_dir().join(format!("kuna-declaration-{}-{}.c", std::process::id(), NEXT.fetch_add(1, Ordering::Relaxed)));
    std::fs::write(&source, format!("#include <stdint.h>\n#include <stdbool.h>\ntypedef int8_t int1; typedef int16_t int2; typedef int32_t int4; typedef int64_t int8;\ntypedef uint8_t uint1; typedef uint16_t uint2; typedef uint32_t uint4; typedef uint64_t uint8;\n#define MSABI __attribute__((ms_abi))\nvoid check(void) {{\n{declaration}\n_Static_assert({condition}, \"emitted declaration type changed\");\n}}\n")).expect("write declaration witness");
    let compiler = std::env::var_os("CC").unwrap_or_else(|| "cc".into());
    let built = Command::new(&compiler).args(["-std=c11", "-fsyntax-only", "-Werror=strict-prototypes"])
        .arg(&source).output().unwrap_or_else(|error| panic!("required C compiler {compiler:?}: {error}"));
    std::fs::remove_file(&source).expect("remove declaration witness");
    assert!(built.status.success(), "emitted declaration failed {condition}:\n{}\n{declaration}", String::from_utf8_lossy(&built.stderr));
}
