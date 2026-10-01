//! Compile unchanged emitted C and check its observable behavior.

use std::process::Command;

pub fn assert_c_behavior(stem: &str, preamble: &str, body: &str, driver: &str) {
    let source = super::scratch_file(stem, "c");
    let executable = source.with_extension("exe");
    std::fs::write(&source, format!("{preamble}\n{body}\n{driver}\n"))
        .expect("write emitted-C witness");
    let compiler = std::env::var_os("CC").unwrap_or_else(|| "cc".into());
    let built = Command::new(&compiler)
        .args(["-std=c11", "-O2", "-Wall", "-Werror"])
        .arg(&source)
        .arg("-o")
        .arg(&executable)
        .output()
        .unwrap_or_else(|e| panic!("required C compiler {compiler:?}: {e}"));
    assert!(
        built.status.success(),
        "{stem}: emitted C did not compile ({}):\n{}\n{}\n{body}",
        source.display(),
        String::from_utf8_lossy(&built.stdout),
        String::from_utf8_lossy(&built.stderr)
    );
    let ran = Command::new(&executable).output().expect("execute emitted-C witness");
    assert!(
        ran.status.success(),
        "{stem}: emitted C changed observable behavior ({}):\n{}\n{}\n{body}",
        source.display(),
        String::from_utf8_lossy(&ran.stdout),
        String::from_utf8_lossy(&ran.stderr)
    );
    std::fs::remove_file(&executable).expect("remove witness executable");
    std::fs::remove_file(&source).expect("remove witness source");
}

pub fn assert_three_call_chain(stem: &str, body: &str, function: &str) {
    let preamble = r#"
static unsigned order[4], count;
static void record(unsigned id) {
    if (count < 4) order[count] = id;
    ++count;
}
static void first(void) { record(1); }
static void second(void) { record(2); }
static void third(void) { record(3); }
void (*dat_804a000)(void) = first;
void (*dat_804a004)(void) = second;
void (*dat_804a008)(void) = third;
"#;
    let driver = format!(r#"
int main(void) {{
    for (unsigned run = 0; run < 2; ++run) {{
        count = 0;
        {function}();
        if (count != 3 || order[0] != 1 || order[1] != 2 || order[2] != 3) return 1;
    }}
    return 0;
}}
"#);
    assert_c_behavior(stem, preamble, body, &driver);
}
