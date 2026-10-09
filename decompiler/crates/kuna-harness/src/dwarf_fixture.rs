use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT_DWARF_FIXTURE: AtomicU64 = AtomicU64::new(0);

pub struct CompiledDwarf {
    pub path: PathBuf,
    directory: PathBuf,
}

impl Drop for CompiledDwarf {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.directory);
    }
}

pub fn compile_dwarf(source: &Path, standard: &str, flags: &[&str]) -> CompiledDwarf {
    let cross = flags.iter().any(|f| f.starts_with("--target="));
    let compiler = std::env::var_os(if cross { "KUNA_DWARF_CLANG" } else { "KUNA_DWARF_CC" })
        .unwrap_or_else(|| "clang".into());
    let directory = std::env::temp_dir().join(format!(
        "kuna-dwarf-{}-{}", std::process::id(), NEXT_DWARF_FIXTURE.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir(&directory).expect("create isolated DWARF fixture directory");
    let path = directory.join("declarations");
    let fixture = CompiledDwarf { path, directory };
    let mut command = Command::new(&compiler);
    command.arg(format!("-std={standard}")).args(["-g", "-gdwarf-4", "-O0", "-fno-inline"]);
    if cfg!(target_os = "macos") || cross {
        command.arg("-c");
    } else {
        command.arg("-no-pie");
    }
    let output = command.args(flags).arg(source).arg("-o").arg(&fixture.path)
        .output().expect("DWARF producer missing: install clang or set KUNA_DWARF_CC to a real compiler");
    assert!(output.status.success(), "DWARF producer {compiler:?} failed:\n{}",
        String::from_utf8_lossy(&output.stderr));
    fixture
}
