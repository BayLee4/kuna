//! Corpus scripts executed through the production XML loader and console.

#![allow(dead_code)] // Each integration test uses only part of this shared helper.

use std::path::PathBuf;
use std::rc::Rc;

use kuna_base::xml::DocumentStorage;
use kuna_console::engine::{bootstrap_from_root, ConsoleProgram};
use kuna_console::ifacedecomp::{
    register_console_commands, register_decomp_commands, IfaceDecompData, DECOMPILE_MODULE,
};
use kuna_console::ifaceterm::IfaceTerm;
use kuna_console::interface::{IfaceError, IfaceResult, IfaceStatus};
use kuna_console::kuna_console::register_kuna_commands;
use kuna_decomp::funcdata::Funcdata;

pub const C_TYPES: &str = "#include <stdint.h>\n#include <stdbool.h>\n#include <limits.h>\n\
    typedef uint8_t uint1; typedef uint16_t uint2; typedef uint32_t uint4; typedef uint64_t uint8;\n\
    typedef int8_t int1; typedef int16_t int2; typedef int32_t int4; typedef int64_t int8;\n";

pub use crate::common::c_behavior::assert_c_behavior;

pub fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../..")
        .canonicalize()
        .expect("repository root")
}

fn is_decompile(command: &str) -> bool {
    let token = command.split_whitespace().next().unwrap_or("");
    token.len() >= 3 && "decompile".starts_with(token)
}

pub struct Corpus {
    stem: String,
    commands: Vec<String>,
    next: usize,
    status: IfaceStatus,
}

impl Corpus {
    pub fn load(stem: &str) -> Self {
        let root = repo_root();
        let path = root.join("tests/datatests").join(format!("{stem}.xml"));
        let xml = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("{}: {e}", path.display()));
        Self::from_xml(stem, &xml)
    }

    pub fn from_xml(stem: &str, xml: &str) -> Self {
        let mut documents = DocumentStorage::new();
        let document = documents.parse_document(xml.as_bytes()).expect("valid corpus XML");
        let root_element = Rc::clone(document.get_root());
        let script = root_element
            .get_children()
            .iter()
            .find(|element| element.get_name() == "script")
            .unwrap_or_else(|| panic!("{stem}: missing script"));
        // This only extracts the command feed. XML parsing, option dispatch,
        // type declarations, symbol mapping and processor setup are production APIs.
        let commands = script
            .get_children()
            .iter()
            .filter(|element| element.get_name() == "com")
            .map(|element| {
                std::str::from_utf8(element.get_content())
                    .expect("UTF-8 corpus command")
                    .replace('\r', "")
                    .replace('\n', " ")
            })
            .collect();
        let specs = std::env::var_os("KUNA_SPECS")
            .map(PathBuf::from)
            .unwrap_or_else(|| repo_root().join("specs"));
        let program = bootstrap_from_root(&root_element, &[specs.to_string_lossy().into_owned()])
            .unwrap_or_else(|e| panic!("{stem}: production bootstrap failed: {e}"));
        let mut status = IfaceTerm::into_status("> ", b"");
        register_decomp_commands(&mut status);
        register_console_commands(&mut status);
        register_kuna_commands(&mut status);
        let mut corpus = Self { stem: stem.into(), commands, next: 0, status };
        corpus.data().conf = Some(program);
        corpus
    }

    pub fn data(&mut self) -> &mut IfaceDecompData {
        self.status
            .get_data_mut(DECOMPILE_MODULE)
            .expect("registered decompile module")
            .as_any_mut()
            .downcast_mut::<IfaceDecompData>()
            .expect("decompile state")
    }

    pub fn render_c(&mut self) -> String {
        let data = self.data();
        kuna_decomp::decompile_drive::print_c(
            data.conf.as_mut().expect("loaded program").arch_mut(),
            data.fd.as_ref().expect("decompiled function"),
        )
    }

    /// Dispatch one additional command without replacing the program or the
    /// command sequence counter (which controls the pristine-flow cache).
    pub fn command(&mut self, command: &str) -> IfaceResult<()> {
        self.status.push_script_lines(vec![command.into()], "> ");
        let output_start = self.status.optr.len();
        let result = self.status.run_command();
        self.status.pop_script();
        match result {
            Ok(true) if is_decompile(command) => {
                let data = self.data();
                let fd = data.fd.as_ref()
                    .ok_or_else(|| IfaceError::execution("decompile left no function"))?;
                if let Some(reason) = fd.kuna_pipeline_failure() {
                    return Err(IfaceError::execution(reason));
                }
                // Funcdata::processing_complete is not maintained by this
                // console path: ActionStop does not call stopProcessing.
                // The once-per-function action root records real completion;
                // a breakpoint/partial pipeline leaves it at a non-end status.
                let action = data.conf.as_ref()
                    .ok_or_else(|| IfaceError::execution("decompile left no program"))?
                    .arch().allacts.get_current()
                    .ok_or_else(|| IfaceError::execution("decompile left no current action"))?;
                if action.get_status() != kuna_decomp::action::statusflags::status_end {
                    return Err(IfaceError::execution("decompile action did not finish"));
                }
                Ok(())
            }
            Ok(true) => Ok(()),
            Ok(false) => Err(IfaceError::parse(format!(
                "{}: command `{command}` did not execute: {}",
                self.stem,
                &self.status.optr[output_start..]
            ))),
            Err(error) => Err(error),
        }
    }

    fn next_command(&mut self) -> Option<bool> {
        let command = self.commands.get(self.next)?.clone();
        self.next += 1;
        assert!(!self.status.done, "{}: script continued after quit", self.stem);
        self.command(&command)
            .unwrap_or_else(|e| panic!("{}: command `{command}` failed: {e}", self.stem));
        Some(is_decompile(&command))
    }

    /// Execute every preceding setup command and decompilation, stopping at
    /// the requested script-selected body. Never substitute a loader symbol.
    pub fn run_to_function(&mut self, name: &str) -> &mut IfaceDecompData {
        while let Some(decompiled) = self.next_command() {
            if decompiled && self.data().fd.as_ref().expect("decompiled body").get_name() == name {
                return self.data();
            }
        }
        panic!("{}: script did not decompile required function {name}", self.stem);
    }

    pub fn run_all(
        &mut self,
        expected: &[&str],
        mut visit: impl FnMut(&mut ConsoleProgram, &Funcdata),
    ) {
        let mut names = Vec::new();
        while let Some(decompiled) = self.next_command() {
            if decompiled {
                let data = self.data();
                let fd = data.fd.as_ref().expect("successful decompile leaves a body");
                names.push(fd.get_name().to_string());
                visit(data.conf.as_mut().expect("loaded program"), fd);
            }
        }
        assert_eq!(names, expected, "{}: required scripted functions changed", self.stem);
    }
}
