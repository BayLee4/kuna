//! Real-image readonly receipt regressions; requires the built MIPS specification.
#[test]
fn actual_mips_readonly_receipt_replays_reject_changed_premises() {
    use std::path::PathBuf;
    use kuna_base::address::Address;
    use crate::decompile_step::{decompile_one, DecompileSeed};
    use crate::engine::bootstrap_from_object;

    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../..").canonicalize().unwrap();
    let specs = vec![root.join("specs").to_str().unwrap().to_string()];
    let fixture = root.join("decompiler/crates/kuna-analysis/tests/fixtures/protoorder_floatgpr_mipsel");
    let mut program = bootstrap_from_object(fixture.to_str().unwrap(), "", &specs)
        .expect("the actual MIPS image and built processor specifications are required");
    program.read_loader_symbols().expect("real loader symbols");
    program.commit_pending_analysis().expect("real analysis facts");
    assert_eq!(program.arch().print().out_lang(), kuna_decomp::kuna_lang::OutLang::C);
    program.arch_mut().readonlypropagate = true;
    let space = program.arch().manage().get_default_code_space().unwrap().clone();
    let entry = Address::new(space, 0x400528);
    let step = decompile_one(program.arch_mut(), "_init", entry, 0,
        &DecompileSeed::plain(&[], &[]), &kuna_decomp::overrides::Override::new());
    let mut fd = step.result.expect("real _init optimizer pipeline must complete");
    kuna_decomp::decompile_drive::test_readonly_receipt_replay(program.arch_mut(), &mut fd)
        .expect("the exact old receipt must pass controls and reject each changed premise");
}
