//! Headerless raw-image bootstrap and address-translation regressions.

mod common;

use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};

use kuna_base::address::Address;
use kuna_console::assertions::{self, Body, Directive};
use kuna_console::engine::{bootstrap_from_raw, ArmIsa};
use kuna_console::project::decompile_targets;
use kuna_decomp::varnode::varnode_flags;

struct RawFixture(PathBuf);

impl RawFixture {
    fn thumb_return_7() -> Self {
        Self::new("raw-thumb", &[0x07, 0x20, 0x70, 0x47])
    }

    fn new(stem: &str, bytes: &[u8]) -> Self {
        let path = common::scratch_file(stem, "bin");
        std::fs::write(&path, bytes).unwrap();
        Self(path)
    }

    fn thumb_return_7_with_spaces() -> Self {
        let path = common::scratch_file("raw thumb image", "bin");
        std::fs::write(&path, [0x07, 0x20, 0x70, 0x47]).unwrap();
        Self(path)
    }
}

impl Drop for RawFixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../..")
        .canonicalize()
        .unwrap()
}

/// A missing `.sla` is a visible skip; any other bootstrap failure is the test
/// failing, so a regression can never present as a green skip.
fn skip_or_fail(reason: &str, spec: &str) {
    assert!(reason.contains("No sleigh specification"), "raw bootstrap failed: {reason}");
    eprintln!("verify_raw_image: skipping (build the {spec} `.sla`): {reason}");
}

fn specs() -> Vec<String> {
    vec![std::env::var("KUNA_SPECS")
        .unwrap_or_else(|_| repo_root().join("specs").to_string_lossy().into_owned())]
}

fn run_console(script: &str, isa: Option<&str>) -> std::process::Output {
    let roots = specs();
    let mut command = Command::new(env!("CARGO_BIN_EXE_decomp_dbg"));
    command
        .args(["-sleighpath", &roots[0]])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    match isa {
        Some(isa) => {
            command.env(kuna_console::engine::ARM_ISA_ENV, isa);
        }
        None => {
            command.env_remove(kuna_console::engine::ARM_ISA_ENV);
        }
    }
    let mut child = command.spawn().expect("spawn decomp_dbg");
    child
        .stdin
        .as_mut()
        .expect("console stdin")
        .write_all(script.as_bytes())
        .expect("write console commands");
    child.wait_with_output().expect("wait for decomp_dbg")
}

#[test]
fn raw_thumb_maps_base_zero_and_nonzero() {
    let fixture = RawFixture::thumb_return_7();
    let path = fixture.0.to_string_lossy();
    for (base, selected) in [(0, 0), (0x4000, 0x4001)] {
        let mut program = match bootstrap_from_raw(
            &path,
            "ARM:LE:32:v4t:default",
            base,
            &[base, selected],
            Some(ArmIsa::Thumb),
            &specs(),
        ) {
            Ok(program) => program,
            Err(error) => {
                skip_or_fail(&error.explain().to_string(), "ARM");
                return;
            }
        };
        program.commit_pending_analysis().unwrap();
        assert_eq!(program.sections(), vec![(base, 4, 4)]);
        assert_eq!(program.num_symbols(), 1);
        let entry = program
            .find_entry_at(selected)
            .expect("seeded raw entry must resolve");
        assert_eq!(entry.addr.get_offset(), base);
        assert!(program.entry_bytes_mapped(&entry.addr));

        let results = decompile_targets(&mut program, vec![entry], true, false, false);
        assert_eq!(results.len(), 1);
        assert!(results[0].error.is_none(), "{:?}", results[0].error);
        let code = results[0].code.as_deref().unwrap();
        assert!(
            code.contains("return 7;"),
            "unexpected raw Thumb body:\n{code}"
        );
    }
}

#[test]
fn raw_arm_data_addresses_preserve_their_low_bit() {
    let fixture = RawFixture::thumb_return_7();
    let path = fixture.0.to_string_lossy();
    let mut program = match bootstrap_from_raw(
        &path,
        "ARM:LE:32:v4t:default",
        0x4000,
        &[0x4001],
        Some(ArmIsa::Thumb),
        &specs(),
    ) {
        Ok(program) => program,
        Err(error) => {
            skip_or_fail(&error.explain().to_string(), "ARM");
            return;
        }
    };
    program.commit_pending_analysis().unwrap();
    assert_eq!(program.input_address_offset(0x4001).unwrap(), 0x4001);
    assert_eq!(program.input_code_offset(0x4001).unwrap(), 0x4000);
    program.set_assertions(vec![
        Directive {
            raw: "data 0x4001 char odd_data".into(),
            body: Body::Data { addr: 0x4001, decl: "char odd_data".into() },
        },
        Directive {
            raw: "volatile 0x4001+1".into(),
            body: Body::Volatile { addr: 0x4001, size: 1 },
        },
    ]);
    assertions::apply_program_scoped(&mut program);
    assert!(program.assertion_outcomes().iter().all(|outcome| outcome.status == "applied"));
    let (_, address, _) = program
        .global_data_symbol_addresses()
        .into_iter()
        .find(|(name, _, _)| name == "odd_data")
        .expect("odd-address data symbol");
    assert_eq!(address.get_offset(), 0x4001);
    let code = program.arch().manage().get_default_code_space().unwrap();
    let odd = Address::new(std::rc::Rc::clone(code), 0x4001);
    let even = Address::new(std::rc::Rc::clone(code), 0x4000);
    assert_ne!(program.arch().symboltab.get_property(&odd) & varnode_flags::volatil, 0);
    assert_eq!(program.arch().symboltab.get_property(&even) & varnode_flags::volatil, 0);
}

#[test]
fn word_addressed_targets_scale_base_and_entries_to_byte_offsets() {
    let fixture = RawFixture::new("raw-avr-nops", &[0, 0, 0, 0]);
    let path = fixture.0.to_string_lossy();

    let mut at_nonzero_base =
        match bootstrap_from_raw(&path, "avr8:LE:16:default", 0x100, &[0x100], None, &specs()) {
            Ok(program) => program,
            Err(error) => {
                skip_or_fail(&error.explain().to_string(), "AVR8");
                return;
            }
        };
    at_nonzero_base.commit_pending_analysis().unwrap();
    assert_eq!(at_nonzero_base.sections(), vec![(0x200, 4, 4)]);
    let entry = at_nonzero_base
        .find_entry_at(0x200)
        .expect("word-addressed base must become a byte VMA");
    assert!(at_nonzero_base.entry_bytes_mapped(&entry.addr));
    assert_eq!(at_nonzero_base.output_code_offset(entry.addr.get_offset()), 0x100);
    assert_eq!(at_nonzero_base.output_code_end_offset(0x201), 0x101);

    let mut at_second_word = bootstrap_from_raw(&path, "avr8:LE:16:default", 0, &[1], None, &specs())
        .expect("same built AVR8 specification");
    at_second_word.commit_pending_analysis().unwrap();
    let entry = at_second_word
        .find_entry_at(2)
        .expect("entry word 1 must select file byte offset 2");
    assert_eq!(entry.addr.get_offset(), 2);
    assert_eq!(at_second_word.output_code_offset(entry.addr.get_offset()), 1);
    assert!(at_second_word.entry_bytes_mapped(&entry.addr));
}

#[test]
fn raw_console_reports_word_addresses_in_target_units() {
    let fixture = RawFixture::new("raw-word-report", &[0, 0, 0x08, 0x95]);
    let roots = specs();
    if !PathBuf::from(&roots[0])
        .join("Ghidra/Processors/Atmel/data/languages/avr8.sla")
        .exists()
    {
        eprintln!("verify_raw_image: skipping console report test (no AVR8 `.sla`)");
        return;
    }
    let script = format!(
        "load raw avr8:LE:16:default 0x100 0x101 \"{}\"\n\
         read symbols\n\
         functions\n\
         load addr 0x101\n\
         decompile\n\
         region blocks\n\
         region tree\n\
         region walk\n\
         quit\n",
        fixture.0.display()
    );
    let output = run_console(&script, None);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(), "{stdout}\n{stderr}");
    for expected in ["0x101 sub_101", "[0x101]", "region head=0x101", "walk 0x101"] {
        assert!(stdout.contains(expected), "missing {expected:?}:\n{stdout}\n{stderr}");
    }
    for byte_address in ["0x202 sub_101", "[0x202]", "region head=0x202", "walk 0x202"] {
        assert!(
            !stdout.contains(byte_address),
            "leaked byte address {byte_address:?}:\n{stdout}\n{stderr}"
        );
    }
}

#[test]
fn raw_map_function_normalizes_an_odd_thumb_pointer() {
    let fixture = RawFixture::thumb_return_7();
    let roots = specs();
    if !PathBuf::from(&roots[0])
        .join("Ghidra/Processors/ARM/data/languages/ARM8_le.sla")
        .exists()
    {
        eprintln!("verify_raw_image: skipping map function test (no ARM `.sla`)");
        return;
    }
    let script = format!(
        "load raw ARM:LE:32:v4t:default 0x4000 0x4000 \"{}\"\n\
         map function 0x4001 mapped_thumb\n\
         decompile\n\
         print C\n\
         quit\n",
        fixture.0.display()
    );
    let output = run_console(&script, Some("thumb"));
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(), "{stdout}\n{stderr}");
    assert!(stdout.contains("mapped_thumb"), "{stdout}\n{stderr}");
    assert!(stdout.contains("return 7;"), "{stdout}\n{stderr}");
}

#[test]
fn raw_map_address_preserves_an_odd_arm_data_address() {
    let fixture = RawFixture::new(
        "raw-thumb-odd-data",
        &[0x01, 0x48, 0x00, 0x78, 0x70, 0x47, 0, 0, 0x01, 0x40, 0, 0],
    );
    let roots = specs();
    if !PathBuf::from(&roots[0])
        .join("Ghidra/Processors/ARM/data/languages/ARM8_le.sla")
        .exists()
    {
        eprintln!("verify_raw_image: skipping map address test (no ARM `.sla`)");
        return;
    }
    let script = format!(
        "load raw ARM:LE:32:v4t:default 0x4000 0x4001 \"{}\"\n\
         map address 0x4001 char odd_data\n\
         readonly 0x4008 4\n\
         option readonly on\n\
         read symbols\n\
         load addr 0x4001\n\
         decompile\n\
         print C\n\
         quit\n",
        fixture.0.display()
    );
    let output = run_console(&script, Some("thumb"));
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(), "{stdout}\n{stderr}");
    assert!(stdout.contains("return odd_data;"), "{stdout}\n{stderr}");
    assert!(!stdout.contains("return dat_4001;"), "{stdout}\n{stderr}");
}

#[test]
fn console_load_raw_preserves_whitespace_in_final_filename() {
    let fixture = RawFixture::thumb_return_7_with_spaces();
    let roots = specs();
    if !PathBuf::from(&roots[0])
        .join("Ghidra/Processors/ARM/data/languages/ARM8_le.sla")
        .exists()
    {
        eprintln!("verify_raw_image: skipping whitespace path test (no ARM `.sla`)");
        return;
    }
    let mut child = Command::new(env!("CARGO_BIN_EXE_decomp_dbg"))
        .args(["-sleighpath", &roots[0]])
        .env(kuna_console::engine::ARM_ISA_ENV, "thumb")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn decomp_dbg");
    writeln!(
        child.stdin.as_mut().expect("console stdin"),
        "load raw ARM:LE:32:v4t:default 0x4000 0x4001 \"{}\"\nquit",
        fixture.0.display()
    )
    .expect("write console commands");
    let output = child.wait_with_output().expect("wait for decomp_dbg");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(), "{stdout}\n{stderr}");
    assert!(stdout.contains("successfully loaded"), "{stdout}\n{stderr}");
}

#[test]
fn raw_input_rejects_missing_metadata_and_unmapped_entries() {
    let fixture = RawFixture::thumb_return_7();
    let path = fixture.0.to_string_lossy();

    let missing_target = bootstrap_from_raw(&path, "", 0, &[0], None, &specs())
        .err()
        .expect("missing target must fail")
        .explain()
        .to_string();
    assert!(missing_target.contains("requires --target"));

    let error = match bootstrap_from_raw(
        &path,
        "ARM:LE:32:v4t:default",
        0x4000,
        &[0x4000],
        None,
        &specs(),
    ) {
        Ok(_) => panic!("raw ARM input without --isa unexpectedly loaded"),
        Err(error) => error.explain().to_string(),
    };
    if error.contains("No sleigh specification") {
        eprintln!("verify_raw_image: skipping (build the ARM `.sla`): {error}");
        return;
    }
    assert!(
        error.contains("requires --isa"),
        "unexpected error: {error}"
    );
}

#[test]
fn raw_input_rejects_entry_at_end_of_mapping() {
    let fixture = RawFixture::thumb_return_7();
    let path = fixture.0.to_string_lossy();
    let error = match bootstrap_from_raw(
        &path,
        "ARM:LE:32:v4t:default",
        0x4000,
        &[0x4004],
        Some(ArmIsa::Thumb),
        &specs(),
    ) {
        Ok(_) => panic!("out-of-range raw entry unexpectedly loaded"),
        Err(error) => error.explain().to_string(),
    };
    if error.contains("No sleigh specification") {
        eprintln!("verify_raw_image: skipping (build the ARM `.sla`): {error}");
        return;
    }
    assert!(
        error.contains("outside mapped range"),
        "unexpected error: {error}"
    );
}

#[test]
fn word_addressed_mapping_errors_report_target_units() {
    let fixture = RawFixture::new("raw-word-bounds", &[0, 0, 0, 0]);
    let path = fixture.0.to_string_lossy();
    let error = match bootstrap_from_raw(
        &path,
        "avr8:LE:16:default",
        0x100,
        &[0x103],
        None,
        &specs(),
    ) {
        Ok(_) => panic!("out-of-range word-addressed entry unexpectedly loaded"),
        Err(error) => error.explain().to_string(),
    };
    if error.contains("No sleigh specification") {
        eprintln!("verify_raw_image: skipping target-unit bounds test (no AVR8 `.sla`): {error}");
        return;
    }
    assert!(
        error.contains("raw entry 0x103 is outside mapped range 0x100..0x102"),
        "unexpected error: {error}"
    );
    assert!(!error.contains("0x200..0x204"), "byte bounds leaked: {error}");
}

#[test]
fn raw_input_rejects_empty_images() {
    let fixture = RawFixture::new("raw-empty", &[]);
    let path = fixture.0.to_string_lossy();
    let error = match bootstrap_from_raw(
        &path,
        "ARM:LE:32:v4t:default",
        0,
        &[0],
        Some(ArmIsa::Thumb),
        &specs(),
    ) {
        Ok(_) => panic!("empty raw image unexpectedly loaded"),
        Err(error) => error.explain().to_string(),
    };
    if error.contains("No sleigh specification") {
        eprintln!("verify_raw_image: skipping (build the ARM `.sla`): {error}");
        return;
    }
    assert!(
        error.contains("raw image is empty"),
        "unexpected error: {error}"
    );
}

#[test]
fn raw_input_rejects_mapping_overflow() {
    let fixture = RawFixture::thumb_return_7();
    let path = fixture.0.to_string_lossy();
    let error = match bootstrap_from_raw(
        &path,
        "ARM:LE:32:v4t:default",
        u64::MAX,
        &[u64::MAX],
        Some(ArmIsa::Thumb),
        &specs(),
    ) {
        Ok(_) => panic!("overflowing raw mapping unexpectedly loaded"),
        Err(error) => error.explain().to_string(),
    };
    if error.contains("No sleigh specification") {
        eprintln!("verify_raw_image: skipping (build the ARM `.sla`): {error}");
        return;
    }
    assert!(error.contains("overflows"), "unexpected error: {error}");
}


fn physical_source_program(fixture: &RawFixture) -> Option<kuna_console::engine::ConsoleProgram> {
    match bootstrap_from_raw(fixture.0.to_str().unwrap(), "x86:LE:64:default:gcc",
        0x1000, &[0x1000], None, &specs())
    {
        Ok(mut program) => {
            program.commit_pending_analysis().unwrap();
            Some(program)
        }
        Err(error) => {
            skip_or_fail(&error.explain().to_string(), "x86");
            None
        }
    }
}

#[test]
fn physical_source_console_edits_replay_without_resurrecting_old_slots() {
    use kuna_console::ifacedecomp::{execute, register_decomp_commands, IfaceDecompData, DECOMPILE_MODULE};
    use kuna_console::ifaceterm::ConsoleCommands;
    let fixture = RawFixture::new("physical-source-edits", &[0x89, 0xf8, 0x01, 0xf0, 0xc3]);
    let cases: &[(&[&str], [(&str, i32, u64); 2])] = &[
        (&["rename value renamed", "decompile", "retype other uint2 changed", "decompile"],
            [("renamed", 1, 0x38), ("changed", 2, 0x30)]),
        (&["rename other sibling", "map param subject::0 [register,0x8,2] uint2 fresh",
           "rename fresh newest", "decompile"],
            [("newest", 2, 0x08), ("sibling", 1, 0x30)]),
        (&["rename value old_rename", "parse line extern uint4 subject(uint2 fresh, uint1 other);",
           "rename fresh newest", "decompile"],
            [("newest", 2, 0x38), ("other", 1, 0x30)]),
    ];
    for &(commands, expected) in cases {
        let Some(program) = physical_source_program(&fixture) else { return };
        let mut script: Vec<String> = [
            "map function [ram,0x1000] subject",
            "load function subject",
            "parse line extern uint4 subject(uint1 value,uint1 other);",
            "decompile",
        ].into_iter().map(str::to_string).collect();
        script.extend(commands.iter().map(|command| command.to_string()));
        let count = script.len();
        let mut status = ConsoleCommands::into_status(script);
        register_decomp_commands(&mut status);
        let data = status.get_data_mut(DECOMPILE_MODULE).unwrap();
        data.as_any_mut().downcast_mut::<IfaceDecompData>().unwrap().conf = Some(program);
        for _ in 0..count { execute(&mut status); }
        let transcript = status.optr.clone();
        let data = status.get_data_mut(DECOMPILE_MODULE).unwrap();
        let dcp = data.as_any_mut().downcast_mut::<IfaceDecompData>().unwrap();
        let fd = dcp.fd.as_ref().expect("edited function remains selected");
        let proto = fd.get_func_proto();
        let actual: Vec<_> = (0..proto.num_params()).filter_map(|slot| proto.source_param(slot))
            .map(|parameter| (parameter.get_name(), parameter.get_size(), parameter.get_address().get_offset()))
            .collect();
        assert_eq!(actual, expected, "source edits lost or stale carrier authority replayed: {transcript}");
        assert!(proto.has_execution_inputs(), "wide machine reads must retain real carriers");
        let scope = fd.get_scope_local().unwrap();
        for (slot, &(name, size, offset)) in expected.iter().enumerate() {
            let id = scope.parameter_symbol_for_slot(slot as i32).expect("source category0 symbol");
            let symbol = scope.database().symbol(id);
            assert_eq!(symbol.get_name(), name);
            assert_eq!(symbol.dtype.as_ref().unwrap().get_size(), size);
            assert!(symbol.mapentry.iter().any(|&entry| {
                // Each source symbol's original storage survives independently.
                let entry = scope.database().entry(symbol.scope, entry);
                entry.get_addr().get_offset() == offset && entry.get_size() == size
            }));
        }
        let args = (0..proto.num_params()).map(|slot| {
            let param = proto.get_param(slot).unwrap();
            match param.get_address().get_offset() {
                0x38 => "left",
                0x30 => "right",
                0x08 => "0xaabbU",
                other => panic!("unexpected execution parameter storage: {other:#x}"),
            }
        }).collect::<Vec<_>>().join(",");
        let body = kuna_decomp::decompile_drive::print_c(dcp.conf.as_mut().unwrap().arch_mut(), fd);
        let preamble = "#include <stdint.h>\n#include <stdbool.h>\n\
            typedef uint8_t uint1; typedef uint16_t uint2; typedef uint32_t uint4; typedef uint64_t uint8;\n";
        let driver = format!("int main(void) {{ for(unsigned v=0;v<256;v++) {{ \
            uint32_t left=0x10000U|v,right=0x20000U|(v^0x5aU); \
            if((uint32_t)subject({args})!=left+right)return 1; }} return 0; }}");
        common::c_behavior::assert_c_behavior("source-formal-replay", preamble, &body, &driver);
    }
}

#[test]
fn physical_source_assertion_batch_keeps_carriers_read_only_until_replay() {
    let fixture = RawFixture::new("physical-source-batch", &[0x89, 0xf8, 0x01, 0xf0, 0xc3]);
    let Some(mut program) = physical_source_program(&fixture) else { return };
    let entry = program.find_entry_at(0x1000).expect("raw entry");
    let function = entry.name.clone();
    let prototype = Body::Prototype { func: function.clone(), decl: format!("uint4 {function}(uint1 value,uint1 other)") };
    program.set_assertions(vec![Directive { raw: "physical source prototype".into(), body: prototype.clone() }]);
    assertions::apply_program_scoped(&mut program);
    let seed = assertions::function_seed(&mut program, &function, &entry.addr, false);
    let fd = kuna_console::decompile_step::decompile_one(program.arch_mut(), &function,
        entry.addr.clone(), 0, &kuna_console::decompile_step::DecompileSeed {
            mapped_symbols: &[], usepoint_symbols: &[], dynamic_symbols: &[],
            pending_proto: seed.pending_proto.as_ref(), flow_overrides: &[], mapped_params: &seed.mapped_params,
        }, &kuna_decomp::overrides::Override::new()).result.expect("initial physical drive");
    let carrier = fd.get_func_proto().get_param(0).unwrap();
    assert!(fd.get_func_proto().is_execution_input(0));
    let source = fd.get_func_proto().source_param(0).unwrap();
    assert_eq!(source.get_size(), 1, "authentic source declaration stays a byte");
    let edi = Address::new(source.get_address().get_space().unwrap().clone(), 0x38);
    assert!(carrier.get_address().justified_contain(carrier.get_size(), &edi, 4, false) >= 0,
        "carrier must preserve every bit read from EDI");
    let input = fd.find_varnode_input(carrier.get_size(), &carrier.get_address()).expect("real carrier SSA input");
    let high = fd.vbank().get(input).unwrap().get_high().unwrap();
    assert_eq!(fd.execution_input_slot_for_high(high), Some(0));
    let raw_name = fd.high_bank().get(high).unwrap().kuna_name().unwrap().to_string();
    let specifications = [
        prototype,
        Body::Name { func: Some(function.clone()), symbol: "value".into(), newname: "renamed".into() },
        Body::Name { func: Some(function), symbol: raw_name, newname: "forbidden".into() },
    ];
    program.set_assertions(specifications.into_iter().enumerate().map(|(index, body)| Directive {
        raw: format!("source-batch-{index}"), body,
    }).collect());
    assertions::apply_program_scoped(&mut program);
    let results = decompile_targets(&mut program, vec![entry], false, false, false);
    let result = &results[0];
    assert!(result.error.is_none(), "{:?}", result.error);
    let report = program.assertion_outcomes();
    assert_eq!(report[1].status, "applied");
    assert_eq!(report[2].status, "rejected");
    let formals: Vec<_> = result.variables.iter().filter(|variable| variable.is_param)
        .map(|variable| (variable.name.as_str(), variable.size)).collect();
    assert_eq!(formals, [("renamed", 1), ("other", 1)]);
}

#[test]
fn normalized_callback_input_requires_the_receivers_execution_body() {
    let mut image = vec![0u8; 0x120];
    image[..6].copy_from_slice(&[0xe8, 0xfb, 0, 0, 0, 0xc3]);
    // The receiver calls its incoming code pointer with dirty EDI=0x10055.
    image[0x100..0x10b].copy_from_slice(&[0x48, 0x89, 0xf8, 0xbf, 0x55, 0, 1, 0, 0xff, 0xd0, 0xc3]);
    let fixture = RawFixture::new("native-callback-boundary", &image);
    let mut program = match bootstrap_from_raw(fixture.0.to_str().unwrap(), "x86:LE:64:default:gcc",
        0x1000, &[0x1000, 0x1100], None, &specs())
    {
        Ok(program) => program,
        Err(error) => { skip_or_fail(&error.explain().to_string(), "x86"); return; }
    };
    program.commit_pending_analysis().unwrap();
    let forward = program.find_entry_at(0x1000).expect("forward entry");
    let receiver = program.find_entry_at(0x1100).expect("receiver entry");
    let prototypes = [&forward, &receiver].into_iter().map(|entry| Directive {
        raw: format!("prototype {}", entry.name),
        body: Body::Prototype { func: entry.name.clone(),
            decl: format!("int {}(int (*callback)(unsigned char))", entry.name) },
    }).collect();
    program.set_assertions(prototypes);
    assertions::apply_program_scoped(&mut program);
    assert!(program.assertion_outcomes().iter().all(|outcome| outcome.status == "applied"));
    // Deliberately omit the receiver from the exported unit: a source callback
    // declaration alone cannot authorize passing a normalized adapter to it.
    let results = decompile_targets(&mut program, vec![forward], false, false, false);
    let result = &results[0];
    assert!(result.error.is_none(), "{:?}", result.error);
    assert!(result.code.is_some(), "diagnostic body must remain available");
    let formals: Vec<_> = result.variables.iter().filter(|variable| variable.is_param)
        .map(|variable| (variable.name.as_str(), variable.size)).collect();
    assert_eq!(formals, [("callback", 8)]);
    assert!(result.callable_artifacts.iter().any(|artifact| artifact.required && artifact.definition.is_none()),
        "callback normalization must require the omitted receiver, not just alter its formal datatype");
    assert!(kuna_console::project::render_c(&results).is_err(),
        "an unresolved native callback dependency cannot be published as executable C");
}

#[test]
fn callback_nonresult_register_effects_are_not_published_as_ordinary_c() {
    let mut image = vec![0u8; 0x120];
    // CALL RDI; MOV EAX,ECX; RET observes a caller-saved register, not the C result.
    image[..5].copy_from_slice(&[0xff, 0xd7, 0x89, 0xc8, 0xc3]);
    // A valid machine callback returns EAX=3 while the caller observes ECX=7.
    image[0x100..0x10b].copy_from_slice(&[0xb9, 7, 0, 0, 0, 0xb8, 3, 0, 0, 0, 0xc3]);
    let fixture = RawFixture::new("callback-nonresult-effect", &image);
    let mut program = match bootstrap_from_raw(fixture.0.to_str().unwrap(), "x86:LE:64:default:gcc",
        0x1000, &[0x1000, 0x1100], None, &specs())
    {
        Ok(program) => program,
        Err(error) => { skip_or_fail(&error.explain().to_string(), "x86"); return; }
    };
    program.commit_pending_analysis().unwrap();
    let caller = program.find_entry_at(0x1000).expect("caller entry");
    let target = program.find_entry_at(0x1100).expect("callback entry");
    program.set_assertions(vec![
        Directive { raw: format!("prototype {}", caller.name), body: Body::Prototype {
            func: caller.name.clone(), decl: format!("int {}(int (*callback)(void))", caller.name),
        } },
        Directive { raw: format!("prototype {}", target.name), body: Body::Prototype {
            func: target.name.clone(), decl: format!("int {}(void)", target.name),
        } },
    ]);
    assertions::apply_program_scoped(&mut program);
    assert!(program.assertion_outcomes().iter().all(|outcome| outcome.status == "applied"));
    let results = decompile_targets(&mut program, vec![caller, target], false, false, false);
    let result = &results[0];
    assert!(result.error.is_none(), "{:?}", result.error);
    assert!(result.code.is_some(), "the machine diagnostic body must remain available");
    let formals: Vec<_> = result.variables.iter().filter(|variable| variable.is_param)
        .map(|variable| (variable.name.as_str(), variable.size)).collect();
    assert_eq!(formals, [("callback", 8)]);
    assert!(result.callable_export_error.is_some());
    assert!(kuna_console::project::render_c(&results).is_err(),
        "a C callback result cannot substitute for its separately observed ECX effect");
}

#[test]
fn an_unrepresented_return_register_remains_an_explicit_execution_boundary() {
    let fixture = RawFixture::new("return-entry-state", &[0xc3]);
    let mut program = match bootstrap_from_raw(fixture.0.to_str().unwrap(), "x86:LE:64:default:gcc",
        0x1000, &[0x1000], None, &specs())
    {
        Ok(program) => program,
        Err(error) => { skip_or_fail(&error.explain().to_string(), "x86"); return; }
    };
    program.commit_pending_analysis().unwrap();
    let target = program.find_entry_at(0x1000).unwrap();
    program.set_assertions(vec![Directive {
        raw: format!("prototype {}", target.name),
        body: Body::Prototype { func: target.name.clone(),
            decl: format!("int {}(unsigned char value)", target.name) },
    }]);
    assertions::apply_program_scoped(&mut program);
    assert!(program.assertion_outcomes().iter().all(|outcome| outcome.status == "applied"));
    let results = decompile_targets(&mut program, vec![target], false, false, false);
    let target = &results[0];
    assert!(target.error.is_none(), "{:?}", target.error);
    assert!(target.code.is_some());
    let formals: Vec<_> = target.variables.iter().filter(|variable| variable.is_param)
        .map(|variable| (variable.name.as_str(), variable.size)).collect();
    assert_eq!(formals, [("value", 1)]);
    assert!(target.callable_export_error.is_some());
    assert!(kuna_console::project::render_c(&results).is_err(),
        "RET observes incoming EAX; an uninitialized C local cannot represent it");
}

#[test]
fn observable_link_register_state_is_not_return_target_bookkeeping() {
    let mut image = vec![0u8; 0x24];
    image[..8].copy_from_slice(&[0xe0, 0x03, 0x1e, 0xaa, 0xc0, 0x03, 0x5f, 0xd6]); // MOV X0,X30; RET
    image[0x20..].copy_from_slice(&[0xc0, 0x03, 0x5f, 0xd6]); // RET only
    let fixture = RawFixture::new("link-register-entry-state", &image);
    let mut program = match bootstrap_from_raw(fixture.0.to_str().unwrap(), "AARCH64:LE:64:v8A:default",
        0x1000, &[0x1000, 0x1020], None, &specs())
    {
        Ok(program) => program,
        Err(error) => { skip_or_fail(&error.explain().to_string(), "AARCH64"); return; }
    };
    program.commit_pending_analysis().unwrap();
    let escape = program.find_entry_at(0x1000).unwrap();
    let plain = program.find_entry_at(0x1020).unwrap();
    program.set_assertions(vec![
        Directive { raw: format!("prototype {}", escape.name), body: Body::Prototype {
            func: escape.name.clone(), decl: format!("unsigned long long {}(void)", escape.name),
        } },
        Directive { raw: format!("prototype {}", plain.name), body: Body::Prototype {
            func: plain.name.clone(), decl: format!("void {}(void)", plain.name),
        } },
    ]);
    assertions::apply_program_scoped(&mut program);
    assert!(program.assertion_outcomes().iter().all(|outcome| outcome.status == "applied"));
    let results = decompile_targets(&mut program, vec![escape, plain], false, false, false);
    assert!(results.iter().all(|result| result.error.is_none() && result.code.is_some()));
    assert!(results.iter().all(|result| result.variables.iter().all(|variable| !variable.is_param)));
    assert!(results[0].callable_export_error.is_some());
    assert!(kuna_console::project::render_c(&results[..1]).is_err());
    assert!(results[1].callable_export_error.is_none());
    assert!(kuna_console::project::render_c(&results[1..]).is_ok(),
        "a link register used only as the RETURN target is legitimate bookkeeping");
}
