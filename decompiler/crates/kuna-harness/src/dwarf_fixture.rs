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
    let macho = cfg!(target_os = "macos") && !cross;
    if cross || macho {
        command.arg("-c");
    } else {
        command.arg("-no-pie");
    }
    let object = fixture.path.with_extension("o");
    let target = if macho { &object } else { &fixture.path };
    let output = command.args(flags).arg(source).arg("-o").arg(target)
        .output().expect("DWARF producer missing: install clang or set KUNA_DWARF_CC to a real compiler");
    assert!(output.status.success(), "DWARF producer {compiler:?} failed:\n{}",
        String::from_utf8_lossy(&output.stderr));
    if macho {
        // A Mach-O object keeps its relocations unapplied and a linked image keeps its DWARF in
        // the object files, so link the kept object and extract a dSYM beside the image.
        for (tool, args) in [
            (&compiler, vec![object.as_os_str(), "-o".as_ref(), fixture.path.as_os_str()]),
            (&"dsymutil".into(), vec![fixture.path.as_os_str()]),
        ] {
            let output = Command::new(tool).args(args).output().expect("Mach-O link and dSYM tools");
            assert!(output.status.success(), "{tool:?} failed:\n{}", String::from_utf8_lossy(&output.stderr));
        }
    }
    fixture
}
