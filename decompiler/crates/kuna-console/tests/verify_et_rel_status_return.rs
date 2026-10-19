//! Cross-architecture ET_REL proof for instruction relocations and conservative
//! status-return recovery across a terminal no-return error path.
//!
//! Both synthetic objects define `guarded_status`, which leaves a status in the
//! ABI return/first-argument register. The normal path returns it; a separate
//! guard-failure path passes the same value to an undefined no-return function.
//! `status_caller` consumes the result through a relocated direct call.
//!
//! With library prototypes disabled, the status-return half is the two-pass gate for `option noreturnretuse`: OFF
//! is the upstream behaviour, where the failure call's use of the same register
//! vetoes the return trial and the helper recovers as `void`.

#[path = "common/corpus.rs"]
mod corpus;

use std::path::PathBuf;

use kuna_console::engine::bootstrap_from_object;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../..")
        .canonicalize()
        .unwrap()
}

fn fixture(name: &str) -> PathBuf {
    repo_root()
        .join("decompiler/crates/kuna-analysis/tests/fixtures")
        .join(name)
}

fn decompile_pair(name: &str, noreturn_ret_use: bool, library_prototypes: bool) -> (String, String) {
    let path = fixture(name);
    assert!(path.is_file(), "missing fixture {path:?}");
    let specs = repo_root().join("specs");
    let roots = vec![specs.to_string_lossy().into_owned()];
    let mut program = bootstrap_from_object(path.to_str().unwrap(), "", &roots)
        .unwrap_or_else(|error| panic!("{name}: bootstrap failed: {}", error.explain()));
    program.arch_mut().analysis_libproto = library_prototypes;
    program.arch_mut().analysis_libcsigs = library_prototypes;
    program.commit_pending_analysis().expect("analysis commit");
    program.arch_mut().noreturn_ret_use = noreturn_ret_use;
    let entries = program
        .function_entries_canonical()
        .into_iter()
        .filter(|entry| matches!(entry.name.as_str(), "guarded_status" | "status_caller"))
        .collect::<Vec<_>>();
    assert_eq!(entries.len(), 2, "{name}: missing synthetic functions");
    let output = kuna_console::project::decompile_targets(
        &mut program,
        entries,
        /* no_vars= */ false,
        /* want_proto= */ false,
        /* want_provenance= */ false,
    ).unwrap();
    let code_for = |function: &str| {
        output
            .iter()
            .find(|item| item.name == function)
            .and_then(|item| item.code.clone())
            .unwrap_or_else(|| panic!("{name}: no decompile for {function}"))
    };
    (code_for("guarded_status"), code_for("status_caller"))
}

#[test]
fn arm_and_aarch64_status_helpers_keep_their_return_values() {
    let specs = repo_root().join("specs/Ghidra/Processors");
    assert!(specs.join("ARM/data/languages/ARM8_le.sla").is_file()
        && specs.join("AARCH64/data/languages/AARCH64.sla").is_file(), "required processor specs must be available");

    for name in ["et_rel_status_arm.o", "et_rel_status_aarch64.o"] {
        let (helper, caller) = decompile_pair(name, true, false);
        assert!(
            !helper.starts_with("void guarded_status"),
            "{name}: helper was forced to void:\n{helper}"
        );
        assert!(
            helper.contains("return "),
            "{name}: helper has no value-bearing return:\n{helper}"
        );
        assert!(
            helper.contains("__stack_chk_fail("),
            "{name}: terminal no-return control was not retained:\n{helper}"
        );
        assert!(
            caller.contains("guarded_status(") && caller.contains("return "),
            "{name}: caller did not consume the named relocated result:\n{caller}"
        );
        assert!(
            !caller.contains("sub_"),
            "{name}: relocated call lost callee identity:\n{caller}"
        );

        let (upstream, _) = decompile_pair(name, false, false);
        assert!(
            upstream.starts_with("void guarded_status"),
            "{name}: `noreturnretuse off` must restore the upstream void recovery:\n{upstream}"
        );
    }
}

#[test]
fn a_known_zero_argument_failure_does_not_consume_the_status_return() {
    for name in ["et_rel_status_arm.o", "et_rel_status_aarch64.o"] {
        let (helper, caller) = decompile_pair(name, false, true);
        assert!(!helper.starts_with("void guarded_status"), "{name}: {helper}");
        assert!(helper.contains("return "), "{name}: {helper}");
        assert!(helper.contains("__stack_chk_fail();"), "{name}: {helper}");
        assert!(caller.contains("guarded_status(") && caller.contains("return "), "{name}: {caller}");
    }
}

#[test]
fn declared_canary_signature_keeps_independent_noreturn_and_integer_bits() {
    use kuna_decomp::dtype::type_metatype;
    let path = fixture("floatparam_x86_64_O0.o");
    let roots = vec![repo_root().join("specs").to_string_lossy().into_owned()];
    let mut program = bootstrap_from_object(path.to_str().unwrap(), "", &roots).unwrap();
    program.commit_pending_analysis().unwrap();
    let mut corpus = corpus::Corpus::from_program("declared-canary-bits", program, Vec::new());
    corpus.command("load function bits").unwrap();
    let (callee, source) = {
        let data = corpus.data();
        let fd = data.fd.as_ref().unwrap();
        let arch = data.conf.as_ref().unwrap().arch();
        assert!(!fd.get_func_proto().is_input_locked());
        assert!(!fd.get_func_proto().is_output_locked());
        assert!(data.pending_prototypes.get("bits").is_none());
        assert!(arch.symboltab.function_source_proto_across_scopes(fd.get_address()).is_none());
        let call = (0..fd.num_calls()).map(|i| fd.get_call_specs(i))
            .find(|call| call.get_name() == "__stack_chk_fail").unwrap();
        let entry = call.get_entry_address().clone();
        let source = arch.symboltab.function_source_proto_across_scopes(&entry).unwrap().clone();
        assert!(!source.is_no_return(), "the type source does not supply this flow fact");
        assert!(source.is_output_locked());
        assert!(arch.noreturn_extern_match && arch.noreturn_extern_calls);
        assert!(call.proto().is_no_return(), "callee type acquisition erased the effective flow fact");
        (entry, source)
    };
    corpus.command("decompile").unwrap();
    {
        let data = corpus.data();
        let fd = data.fd.as_ref().unwrap();
        let output = fd.get_func_proto().get_output_type().unwrap();
        assert_eq!(output.get_size(), 8);
        assert!(matches!(output.get_metatype(), type_metatype::TYPE_INT
            | type_metatype::TYPE_UINT | type_metatype::TYPE_UNKNOWN));
        let retained = data.conf.as_ref().unwrap().arch().symboltab
            .function_source_proto_across_scopes(&callee).unwrap();
        assert!(std::rc::Rc::ptr_eq(&source, retained));
        assert!(!retained.is_no_return(), "working flow must not rewrite the type source");
    }
    let code = corpus.render_c();
    assert!(code.contains("return a0;"), "{code}");
}
