//! Opt-in real MIPS32 fixture matrix (`--features test-support`).
//! `tests/ghidra/callable/mips_internal_roles.py` builds the checked-in assembly
//! and supplies KUNA_MIPS_ROLE_FIXTURES. Missing live-test prerequisites fail.
#![cfg(feature = "test-support")]

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::rc::Rc;
use kuna_base::address::Address;
use kuna_console::engine::bootstrap_from_object;
use kuna_decomp::decompile_drive::build_and_follow_flow;
use kuna_decomp::kuna_physicalinputs::from_raw_flow;
use kuna_num::opcodes::OpCode;

fn fixture_root() -> PathBuf {
    std::env::var_os("KUNA_MIPS_ROLE_FIXTURES").map(PathBuf::from)
        .expect("run the callable/mips_internal_roles.py fixture builder before this opted-in matrix")
}

fn spec_roots() -> Vec<String> {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../..").canonicalize().unwrap();
    vec![root.join("specs").to_str().unwrap().to_owned()]
}

#[test]
fn original_loaded_calls_distinguish_dirty_full_and_partial_internal_role_definitions() {
    for readonly_value in [0, 1] {
        let image = fixture_root().join(format!("readonly{readonly_value}.elf"));
        let mut program = bootstrap_from_object(image.to_str().unwrap(), "", &spec_roots())
            .expect("actual original MIPS image and built specifications");
        program.read_loader_symbols().unwrap();
        program.commit_pending_analysis().unwrap();
        program.arch_mut().readonlypropagate = true;
        program.arch_mut().set_print_language_checked("c-language").unwrap();
        let gp = program.arch().get_register_varnode(b"gp").unwrap();
        let gp_address = Address::new(gp.space.clone().unwrap(), gp.offset);
        let gp_size = i32::try_from(gp.size).unwrap();
        assert_eq!(gp_size, 4);
        for (name, wanted_safe) in [
            ("caller_dirty", false), ("caller_full", true),
            ("caller_partial", false), ("caller_removed", false),
        ] {
            let entry = program.function_entries().find(|(symbol, _)| *symbol == name)
                .map(|(_, address)| address.clone()).expect("original function symbol");
            let fd = build_and_follow_flow(program.arch_mut(), name, entry, 0).unwrap();
            assert!(fd.get_func_proto().has_model());
            assert!(fd.get_func_proto().internal_list().iter().any(|role|
                role.space.as_ref().zip(gp.space.as_ref()).is_some_and(|(a, b)| Rc::ptr_eq(a, b))
                    && role.offset == gp.offset && role.size == gp.size));
            // An empty map represents the actual unresolved indirect targets.
            // No ABI promise or invented child summary enters this raw proof.
            let analysis = from_raw_flow(&fd, &BTreeMap::new(), None);
            assert!(analysis.requirements.unresolved.iter().any(|(_, opcode)|
                *opcode == OpCode::CPUI_CALLIND), "actual mutable-slot target effects remain unresolved");
            let safe_gp = analysis.safe_internal_roles.iter()
                .any(|(address, size)| address == &gp_address && *size == gp_size);
            assert_eq!(safe_gp, wanted_safe, "{name}/readonly{readonly_value}");
            assert!(!analysis.requirements.preserves(&gp_address, gp_size),
                "internal-role representation cannot mint raw preservation");
            assert!(!analysis.requirements.is_complete(), "original unresolved calls stay unresolved");
        }
    }
}

#[test]
fn genuine_natural_child_needs_no_conditional_summary_to_represent_its_internal_role() {
    let image = fixture_root().join("readonly0.elf");
    let mut program = bootstrap_from_object(image.to_str().unwrap(), "", &spec_roots()).unwrap();
    program.read_loader_symbols().unwrap();
    program.commit_pending_analysis().unwrap();
    program.arch_mut().set_print_language_checked("c-language").unwrap();
    let entry = program.function_entries().find(|(name, _)| *name == "dirty_gp_natural")
        .map(|(_, address)| address.clone()).expect("genuine natural child symbol");
    let gp = program.arch().get_register_varnode(b"gp").unwrap();
    let ra = program.arch().get_register_varnode(b"ra").unwrap();
    let gp_address = Address::new(gp.space.unwrap(), gp.offset);
    let ra_address = Address::new(ra.space.unwrap(), ra.offset);
    let fd = build_and_follow_flow(program.arch_mut(), "dirty_gp_natural", entry, 0).unwrap();
    let analysis = from_raw_flow(&fd, &BTreeMap::new(), None);
    let raw = &analysis.requirements;
    assert!(raw.is_complete());
    assert!(raw.execution.is_none(), "the actual natural body must not receive a fabricated execution view");
    assert!(analysis.safe_internal_roles.iter().any(|(address, size)|
        address == &gp_address && *size == gp.size as i32));
    assert!(!raw.preserves(&gp_address, gp.size as i32));
    assert!(!raw.restores(&gp_address, gp.size as i32));
    assert!(raw.reads.iter().any(|(address, size)| address == &ra_address && *size == ra.size as i32),
        "return bookkeeping must retain the positive machine read");
    assert!(raw.is_bookkeeping(&ra_address, ra.size as i32),
        "actual return-only provenance, not an ABI register-name waiver, represents the return target");
}

#[test]
fn actual_private_spill_proof_rejects_reload_and_pointer_escape() {
    use kuna_console::grammar::{parse_c, DataOrg};
    use kuna_decomp::decompile_drive::{decompile_func_full, test_internal_body_coverage};

    for (name, declaration, covered) in [
        ("private_gp_spill", "extern int private_gp_spill(void);", true),
        ("private_gp_reload", "extern int private_gp_reload(void);", false),
        ("private_gp_escape", "extern void private_gp_escape(void);", false),
        ("dirty_gp_natural", "extern void dirty_gp_natural(void);", true),
    ] {
        let image = fixture_root().join("readonly0.elf");
        let mut program = bootstrap_from_object(image.to_str().unwrap(), "", &spec_roots()).unwrap();
        program.read_loader_symbols().unwrap();
        program.commit_pending_analysis().unwrap();
        program.arch_mut().set_print_language_checked("c-language").unwrap();
        let entry = program.function_entries().find(|(symbol, _)| *symbol == name)
            .map(|(_, address)| address.clone()).expect("actual private-frame function symbol");
        let arch = program.arch();
        let (addr_size, word_size) = arch.data_org();
        let models = arch.proto_model_names().map(str::to_owned).collect::<Vec<_>>();
        let mut parsed = None;
        parse_c(declaration, arch.types(), DataOrg { addr_size, word_size }, &models, |pieces, _| {
            parsed = Some(pieces);
            Ok(())
        }).unwrap();
        let pieces = parsed.expect("actual locked source declaration");
        let gp = arch.get_register_varnode(b"gp").unwrap();
        let gp_address = Address::new(gp.space.unwrap(), gp.offset);
        let fd = decompile_func_full(program.arch_mut(), name, entry, 0, &[], Some(&pieces))
            .expect("full genuine raw/SSA decompile pipeline");
        let coverage = test_internal_body_coverage(&fd).expect("final actual body proof replay");
        assert_eq!(coverage.iter().any(|(address, size)|
            address == &gp_address && *size == gp.size as i32), covered, "{name}");
        let raw = fd.entry_physical_requirements().expect("original machine effects retained");
        assert!(!raw.restores(&gp_address, gp.size as i32),
            "an internal representation proof is not raw GP restoration");
        if name == "dirty_gp_natural" {
            assert!(raw.is_complete());
            assert!(raw.execution.is_none());
        }
    }
}

#[test]
fn actual_direct_child_role_cannot_hide_a_later_implicit_gp_read() {
    let image = fixture_root().join("readonly0.elf");
    let mut program = bootstrap_from_object(image.to_str().unwrap(), "", &spec_roots()).unwrap();
    program.read_loader_symbols().unwrap();
    program.commit_pending_analysis().unwrap();
    program.arch_mut().set_print_language_checked("c-language").unwrap();
    let child_entry = program.function_entries().find(|(name, _)| *name == "dirty_gp")
        .map(|(_, address)| address.clone()).unwrap();
    let child = build_and_follow_flow(program.arch_mut(), "dirty_gp", child_entry.clone(), 0).unwrap();
    let child_raw = Rc::new(from_raw_flow(&child, &BTreeMap::new(), None).requirements);
    assert!(child_raw.is_complete());
    let gp = program.arch().get_register_varnode(b"gp").unwrap();
    let gp_address = Address::new(gp.space.unwrap(), gp.offset);
    for (name, safe) in [("direct_gp_parent", true), ("direct_gp_read_parent", false)] {
        let entry = program.function_entries().find(|(symbol, _)| *symbol == name)
            .map(|(_, address)| address.clone()).unwrap();
        let parent = build_and_follow_flow(program.arch_mut(), name, entry, 0).unwrap();
        let calls = (0..parent.num_calls()).map(|slot| parent.get_call_specs(slot)).collect::<Vec<_>>();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].get_entry_address(), &child_entry);
        let callees = BTreeMap::from([(calls[0].get_op(), child_raw.clone())]);
        let analysis = from_raw_flow(&parent, &callees, None);
        assert_eq!(analysis.safe_internal_roles.iter().any(|(address, size)|
            address == &gp_address && *size == gp.size as i32), safe, "{name}");
        assert!(!analysis.requirements.restores(&gp_address, gp.size as i32));
    }
}
