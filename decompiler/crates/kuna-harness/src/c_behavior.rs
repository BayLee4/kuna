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
