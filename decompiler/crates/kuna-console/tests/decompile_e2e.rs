//! Original console corpus scripts retain required functions and observable effects.

use crate::common;
#[path = "common/corpus.rs"]
mod corpus;
#[path = "common/call_facts.rs"]
mod call_facts;

use corpus::{assert_c_behavior, repo_root, Corpus, C_TYPES};
use kuna_decomp::decompile_drive::print_c;

#[test]
fn original_callback_leaves_keep_physical_return_values_and_source_formals() {
    use kuna_console::engine::bootstrap_from_raw;
    use kuna_decomp::dtype::type_metatype;
    use kuna_decomp::kuna_emulatefunction::EmulateFunction;
    use kuna_num::opcodes::OpCode;

    for boolean in [false, true] {
        let (entries, declarations, typedef): (&[(&str, u64, &[u8])], &[&str], &str) = if boolean {
            (&[("dispatch", 0x1000, &[0xe8, 0xfb, 0, 0, 0, 0xc3]),
               ("invoke", 0x1100, &[0x48, 0x8b, 0x35, 0xf9, 0x01, 0, 0, 0xff, 0xd6, 0xc3]),
               ("native_target", 0x1200, &[0x40, 0x0f, 0xb6, 0xc7, 0xc3])],
             &["map prototype dispatch int dispatch(unsigned char raw);",
               "map prototype invoke int invoke(bool value);",
               "map prototype native_target int native_target(bool value);"],
             "parse line typedef int (*Callback)(bool value);")
        } else {
            (&[("native_dispatch", 0x1000, &[0x48, 0x8b, 0x35, 0xf9, 0x02, 0, 0, 0xbf, 0x55, 0, 0, 0, 0xb8, 0x55, 0, 0, 0, 0xe8, 0xea, 0, 0, 0, 0xc3]),
               ("invoke", 0x1100, &[0xff, 0xd6, 0xc3]),
               ("native_target", 0x1200, &[0xc3])],
             &["map prototype native_dispatch int native_dispatch(void);",
               "map prototype invoke int invoke(unsigned char value,Callback callback);",
               "map prototype native_target int native_target(unsigned char value);"],
             "parse line typedef int (*Callback)(unsigned char);")
        };
        let path = common::scratch_file(if boolean { "original-bool-return" } else { "original-ret-return" }, "bin");
        let mut image = vec![0u8; 0x308];
        for (_, at, bytes) in entries {
            let offset = (*at - 0x1000) as usize;
            image[offset..offset + bytes.len()].copy_from_slice(bytes);
        }
        image[0x300..0x308].copy_from_slice(&0x1200u64.to_le_bytes());
        std::fs::write(&path, image).unwrap();
        let specs = [repo_root().join("specs").to_string_lossy().into_owned()];
        let program = bootstrap_from_raw(path.to_str().unwrap(), "x86:LE:64:default:gcc",
            0x1000, &[0x1200], None, &specs).unwrap();
        let mut corpus = Corpus::from_program("original-callback-physical-return", program, Vec::new());
        corpus.command("read symbols").unwrap();
        for (name, at, bytes) in entries {
            corpus.command(&format!("function bounds {at:#x} {:#x} as {name}", at + bytes.len() as u64)).unwrap();
        }
        corpus.command(typedef).unwrap();
        for declaration in declarations { corpus.command(declaration).unwrap(); }
        corpus.command("map address 0x1300 Callback callback_slot").unwrap();
        corpus.command("load addr 0x1200").unwrap();
        let source_before = {
            let source = &corpus.data().pending_prototypes["native_target"];
            (source.name.clone(), source.innames.clone(), source.intypes.iter()
                .map(|ty| (ty.get_id(), ty.get_size(), ty.get_metatype())).collect::<Vec<_>>())
        };
        corpus.command("decompile").unwrap();
        let data = corpus.data();
        let source = &data.pending_prototypes["native_target"];
        assert_eq!((source.name.clone(), source.innames.clone(), source.intypes.iter()
            .map(|ty| (ty.get_id(), ty.get_size(), ty.get_metatype())).collect::<Vec<_>>()), source_before);
        assert_eq!(source.innames, ["value"]);
        assert_eq!(source.intypes.len(), 1);
        assert_eq!(source.outtype.as_ref().unwrap().get_metatype(), type_metatype::TYPE_INT);
        assert_eq!(source.outtype.as_ref().unwrap().get_size(), 4);
        let expected_meta = if boolean { type_metatype::TYPE_BOOL } else { type_metatype::TYPE_UINT };
        assert_eq!(source.intypes[0].get_metatype(), expected_meta);
        assert_eq!(source.intypes[0].get_size(), 1);
        let fd = data.fd.as_ref().unwrap();
        let arch = data.conf.as_ref().unwrap().arch();
        let dil = arch.get_register_varnode(b"DIL").unwrap();
        let eax = arch.get_register_varnode(b"EAX").unwrap();
        let proto = fd.get_func_proto();
        assert!(proto.has_store(), "authored source formal store must survive");
        assert_eq!(proto.num_params(), 1);
        let parameter = proto.get_param(0).unwrap();
        assert_eq!(parameter.get_name(), "value");
        assert_eq!(parameter.get_size(), 1);
        assert_eq!(parameter.get_type().unwrap().get_metatype(), expected_meta);
        assert_eq!(parameter.get_address().get_offset(), dil.offset);
        assert!(parameter.get_address().get_space().zip(dil.space.as_ref())
            .is_some_and(|(a, b)| std::rc::Rc::ptr_eq(a, b)));
        assert_eq!(proto.get_output().get_size(), 4);
        assert_eq!(proto.get_output().get_address().get_offset(), eax.offset);
        let returns = fd.obank().iter_alive().filter_map(|id| {
            let op = fd.obank().get(id).unwrap();
            (op.code() == OpCode::CPUI_RETURN).then(|| op.get_in(1).unwrap())
        }).collect::<Vec<_>>();
        assert_eq!(returns.len(), 1);
        let returned = call_facts::without_value_casts(fd, returns[0]);
        let register = if boolean { &dil } else { &eax };
        let mut physical_input = None;
        for id in fd.obank().iter_alive() {
            let op = fd.obank().get(id).unwrap();
            for slot in 0..op.num_input() {
                let Some(id) = op.get_in(slot) else { continue };
                let vn = fd.vbank().get(id).unwrap();
                if vn.is_input() && vn.get_size() == register.size as i32 && vn.get_offset() == register.offset
                    && vn.get_addr().get_space().zip(register.space.as_ref()).is_some_and(|(a, b)| std::rc::Rc::ptr_eq(a, b)) {
                    if let Some(previous) = physical_input { assert_eq!(previous, id); }
                    physical_input = Some(id);
                }
            }
        }
        let physical_input = physical_input.expect("actual live incoming physical value");
        if !boolean { assert_eq!(returned, physical_input, "RET returns incoming EAX, not its unrelated source formal"); }
        for bits in if boolean { &[0u64, 1, 0xff][..] } else { &[85u64][..] } {
            let mut emulator = EmulateFunction::new(fd);
            emulator.seed_varnode_value(physical_input, *bits);
            assert_eq!(emulator.evaluate_held(returns[0], 32), Some(*bits),
                "actual optimized return expression must preserve this original physical value");
        }
        std::fs::remove_file(path).unwrap();
    }
}

// Own-body values below are distinct from cross-CALL ambient-state transfer.
type PhysicalStorage = (i32, u64, i32);
const ORIGINAL_PHYSICAL_WORDS: [u64; 8] = [
    0x0123456789abcdef, 0xfedcba9876543210, 0x0123456700000000, 0x89abcdef,
    0xffffffff00000000, 0xffffffff, 0, u64::MAX,
];

fn physical_storage(fd: &kuna_decomp::funcdata::Funcdata, id: kuna_decomp::context::VarnodeId)
    -> PhysicalStorage
{
    let value = fd.vbank().get(id).unwrap();
    (value.get_space().get_index(), value.get_offset(), value.get_size())
}

fn own_return_values(fd: &kuna_decomp::funcdata::Funcdata, pc: Option<u64>)
    -> Vec<kuna_decomp::context::VarnodeId>
{
    use kuna_num::opcodes::OpCode;
    let mut values = Vec::new();
    for id in fd.obank().iter_alive() {
        let op = fd.obank().get(id).unwrap();
        if op.code() == OpCode::CPUI_RETURN && pc.is_none_or(|pc| op.get_addr().get_offset() == pc) {
            values.extend((1..op.num_input()).filter_map(|slot| op.get_in(slot)));
        }
    }
    assert!(!values.is_empty(), "required physical RETURN value is missing");
    values
}

fn physical_input(fd: &kuna_decomp::funcdata::Funcdata, storage: PhysicalStorage)
    -> kuna_decomp::context::VarnodeId
{
    let mut found = None;
    for id in fd.obank().iter_alive() {
        let op = fd.obank().get(id).unwrap();
        for slot in 0..op.num_input() {
            let Some(id) = op.get_in(slot) else { continue; };
            if fd.vbank().get(id).unwrap().is_input() && physical_storage(fd, id) == storage {
                if let Some(previous) = found { assert_eq!(previous, id); }
                found = Some(id);
            }
        }
    }
    found.expect("required genuine live physical input")
}

fn assert_own_return_value(fd: &kuna_decomp::funcdata::Funcdata,
    seeds: &[(PhysicalStorage, u64)], expected: u64)
{
    for returned in own_return_values(fd, None) {
        assert_eq!(fd.vbank().get(returned).unwrap().get_size(), 8);
        let mut expected_inputs: Vec<_> = seeds.iter().map(|(storage, _)| *storage).collect();
        expected_inputs.sort_unstable();
        assert_eq!(own_value_input_storage(fd, vec![returned], false), expected_inputs);
        // A fresh evaluator for each vector/RETURN prevents cached intermediate
        // values from hiding an input-half or arithmetic dependency.
        let mut evaluator = kuna_decomp::kuna_emulatefunction::EmulateFunction::new(fd);
        for &(storage, value) in seeds {
            evaluator.seed_varnode_value(physical_input(fd, storage), value);
        }
        assert_eq!(evaluator.evaluate_held(returned, 64), Some(expected));
    }
}

fn own_value_input_storage(fd: &kuna_decomp::funcdata::Funcdata,
    mut pending: Vec<kuna_decomp::context::VarnodeId>, allow_merge: bool) -> Vec<PhysicalStorage>
{
    use kuna_num::opcodes::OpCode;
    let mut seen = Vec::new();
    let mut inputs = Vec::new();
    while let Some(id) = pending.pop() {
        if seen.contains(&id) { continue; }
        seen.push(id);
        let value = fd.vbank().get(id).unwrap();
        if value.is_constant() { continue; }
        if value.is_input() { inputs.push(physical_storage(fd, id)); continue; }
        let op = fd.obank().get(value.get_def().expect("unresolved physical value")).unwrap();
        assert!(!matches!(op.code(), OpCode::CPUI_CALL | OpCode::CPUI_CALLIND
            | OpCode::CPUI_LOAD | OpCode::CPUI_INDIRECT), "value barrier: {:?}", op.code());
        assert!((allow_merge && op.code() == OpCode::CPUI_MULTIEQUAL)
            || kuna_decomp::kuna_emulatefunction::EmulateFunction::is_pure(op.code()),
            "unsupported value ancestry: {:?}", op.code());
        pending.extend((0..op.num_input()).filter_map(|slot| op.get_in(slot)));
    }
    inputs.sort_unstable();
    inputs.dedup();
    inputs
}

// Dependency-only observations for a conditional merge or selected recursive
// base RETURN. This does not evaluate PHI/control-flow selection or any CALL.
fn assert_return_dependencies(fd: &kuna_decomp::funcdata::Funcdata, pc: Option<u64>,
    expected: &[PhysicalStorage])
{
    let inputs = own_value_input_storage(fd, own_return_values(fd, pc), true);
    let mut expected = expected.to_vec();
    expected.sort_unstable();
    assert_eq!(inputs, expected);
}

#[test]
fn seventh_stack_formal_keeps_its_declared_width() {
    for (formal, size) in [("int8", 8), ("int4", 4)] {
        let xml = format!(r#"<decompilertest>
          <binaryimage arch="x86:LE:64:default:gcc">
            <bytechunk space="ram" offset="0x1000" readonly="true">4883ec2848b8efcdab896745230148890424e8e90f00004883c428c3</bytechunk>
            <bytechunk space="ram" offset="0x2000" readonly="true">488b442408c3</bytechunk>
            <symbol space="ram" offset="0x1000" name="caller"/>
            <symbol space="ram" offset="0x2000" name="target"/>
          </binaryimage>
          <script>
            <com>parse line extern int8 caller(int8 a,int8 b,int8 c,int8 d,int8 e,int8 f);</com>
            <com>parse line extern int8 target(int8 a,int8 b,int8 c,int8 d,int8 e,int8 f,{formal} g);</com>
            <com>lo fu caller</com><com>decompile</com><com>print C</com><com>print raw</com>
            <com>lo fu target</com><com>decompile</com><com>print C</com><com>print raw</com><com>quit</com>
          </script>
        </decompilertest>"#);
        Corpus::from_xml("seventh-stack-formal", &xml).run_all(&["caller", "target"], |program, fd| {
            if fd.get_name() == "target" {
                let stack = program.arch().manage().get_space_by_name("stack").unwrap().get_index();
                for value in ORIGINAL_PHYSICAL_WORDS {
                    let seeds = if size == 8 { vec![((stack, 8, 8), value)] }
                        else { vec![((stack, 8, 4), value & 0xffffffff),
                                    ((stack, 12, 4), value >> 32)] };
                    assert_own_return_value(fd, &seeds, value);
                }
                return;
            }
            let call = fd.get_call_specs(0);
            assert_eq!(call.proto().num_params(), 7);
            let operation = fd.obank().get(call.get_op()).unwrap();
            let source = fd.vbank().get(operation.get_in(7).unwrap()).unwrap();
            assert_eq!(source.get_size(), size, "{formal}");
        });
    }
}

fn assert_original_call_shape(
    image: &str, commands: &[&str], calls: Option<i32>, formals: Option<i32>,
) -> Corpus {
    let xml = format!("<decompilertest>{image}<script><com>quit</com></script></decompilertest>");
    let mut corpus = Corpus::from_xml("original-call-source-shape", &xml);
    for command in commands {
        corpus.command(command).unwrap();
    }
    let fd = corpus.data().fd.as_ref().unwrap();
    if let Some(calls) = calls {
        assert_eq!(fd.num_calls(), calls);
    }
    if let Some(formals) = formals {
        assert_eq!(fd.get_call_specs(0).proto().num_params(), formals);
    }
    corpus
}

#[test]
fn entry_result_paths_preserve_the_declared_target_formal() {
    for target in [
        "85ff7406b807000000c3c3",
        "85ff7406b807000000c3b809000000c3",
        "e8fb0f000085ff7406b807000000c3b809000000c3",
    ] {
        let image = format!(r#"<binaryimage arch="x86:LE:64:default:gcc">
          <bytechunk space="ram" offset="0x1000" readonly="true">b878563412e8f60f0000c3</bytechunk>
          <bytechunk space="ram" offset="0x2000" readonly="true">{target}</bytechunk>
          <symbol space="ram" offset="0x1000" name="caller"/>
          <symbol space="ram" offset="0x2000" name="target"/>
          <symbol space="ram" offset="0x3000" name="unresolved"/>
        </binaryimage>"#);
        assert_original_call_shape(&image, &[
            "parse line extern uint4 caller(int4 flag);",
            "parse line extern uint4 target(int4 flag);", "lo fu caller", "decompile",
            "print C", "print raw",
        ], Some(1), Some(1));
    }
}

#[test]
fn original_return_paths_keep_physical_eax_value_dependencies() {
    use kuna_decomp::context::VarnodeId;
    use kuna_num::opcodes::OpCode;

    for (target, incoming_value) in [
        ("85ff7406b807000000c3c3", true),
        ("85ff7406b807000000c3b809000000c3", false),
        ("e8fb0f000085ff7406b807000000c3b809000000c3", false),
    ] {
        let xml = format!(r#"<decompilertest>
          <binaryimage arch="x86:LE:64:default:gcc">
            <bytechunk space="ram" offset="0x1000" readonly="true">b878563412e8f60f0000c3</bytechunk>
            <bytechunk space="ram" offset="0x2000" readonly="true">{target}</bytechunk>
            <symbol space="ram" offset="0x1000" name="caller"/>
            <symbol space="ram" offset="0x2000" name="target"/>
            <symbol space="ram" offset="0x3000" name="unresolved"/>
          </binaryimage>
          <script>
            <com>parse line extern uint4 caller(int4 flag);</com>
            <com>parse line extern uint4 target(int4 flag);</com>
            <com>lo fu caller</com><com>decompile</com><com>print C</com><com>print raw</com>
            <com>lo fu target</com><com>decompile</com><com>print C</com><com>print raw</com>
          </script>
        </decompilertest>"#);
        Corpus::from_xml("original-return-value-dependencies", &xml).run_all(
            &["caller", "target"], |program, fd| {
                if fd.get_name() == "caller" {
                    assert_eq!(fd.num_calls(), 1);
                    assert_eq!(fd.get_call_specs(0).proto().num_params(), 1);
                    return;
                }
                let eax = program.arch().get_register_varnode(b"EAX").unwrap();
                let space = eax.space.unwrap();
                let mut pending: Vec<VarnodeId> = Vec::new();
                let mut returns = 0;
                for (_, id) in fd.obank().iter_all() {
                    let op = fd.obank().get(id).unwrap();
                    if !op.is_dead() && op.code() == OpCode::CPUI_RETURN {
                        returns += 1;
                        for slot in 1..op.num_input() {
                            pending.extend(op.get_in(slot));
                        }
                    }
                }
                assert!(returns > 0, "the original target must retain its return paths");
                assert!(!pending.is_empty(), "uint4 target must return a physical value");
                let mut seen = Vec::new();
                let mut reads_eax = false;
                let mut unresolved_value_edge = false;
                while let Some(id) = pending.pop() {
                    if seen.contains(&id) { continue; }
                    seen.push(id);
                    let value = fd.vbank().get(id).unwrap();
                    if value.is_constant() { continue; }
                    if value.is_input() {
                        reads_eax |= value.get_space().get_index() == space.get_index()
                            && value.get_offset() == eax.offset
                            && value.get_size() >= 4;
                        continue;
                    }
                    let Some(op) = value.get_def().and_then(|op| fd.obank().get(op)) else {
                        unresolved_value_edge = true;
                        continue;
                    };
                    if matches!(op.code(), OpCode::CPUI_CALL | OpCode::CPUI_CALLIND
                        | OpCode::CPUI_LOAD | OpCode::CPUI_INDIRECT) {
                        unresolved_value_edge = true;
                        continue;
                    }
                    for slot in 0..op.num_input() {
                        pending.extend(op.get_in(slot));
                    }
                }
                assert!(!unresolved_value_edge,
                    "these original return paths must have concrete value ancestry: {target}");
                assert_eq!(reads_eax, incoming_value, "{target}");
            },
        );
    }
}

#[test]
fn incoming_stack_result_images_keep_their_call() {
    for (callee, observe_result, indirect) in [
        ("", true, false), ("c3", true, false), ("c3", true, true),
        ("897c2410c3", true, false), ("4885ff740548897c2410c3", true, false),
        ("488b44241048897c2410c3", false, false), ("48897c2410c3", true, false),
    ] {
        let finish = if observe_result { "488b442408" } else { "b807000000" };
        let call = if indirect { "488d05e60f0000ffd0" } else { "e8e80f0000" };
        let body = if callee.is_empty() { String::new() } else {
            format!(r#"<bytechunk space="ram" offset="0x2000" readonly="true">{callee}</bytechunk>"#)
        };
        let image = format!(r#"<binaryimage arch="x86:LE:64:default:gcc">
          <bytechunk space="ram" offset="0x1000" readonly="true">4883ec1848b8efcdab89674523014889442408{call}{finish}4883c418c3</bytechunk>
          {body}
          <symbol space="ram" offset="0x1000" name="caller"/>
          <symbol space="ram" offset="0x2000" name="target"/>
        </binaryimage>"#);
        let mut corpus = assert_original_call_shape(&image, &[
            "parse line extern int8 caller(int8 value);",
            "map return target::s0x10 int8", "lo fu caller", "decompile",
        ], Some(1), None);
        if callee.is_empty() { continue; } // Original unavailable body remains unavailable.
        corpus.command("lo fu target").unwrap();
        corpus.command("decompile").unwrap();
        let data = corpus.data();
        let program = data.conf.as_mut().unwrap();
        let stack = program.arch().manage().get_space_by_name("stack").unwrap().get_index();
        let rdi = program.arch().get_register_varnode(b"RDI").unwrap();
        let register = rdi.space.unwrap().get_index();
        let fd = data.fd.as_ref().unwrap();
        if callee == "4885ff740548897c2410c3" {
            // Conditional merge: dependency only, not PHI/branch evaluation.
            assert_return_dependencies(fd, None, &[(register, rdi.offset, 8), (stack, 0x10, 8)]);
        } else if callee == "897c2410c3" {
            for (incoming, value) in [
                (0x0123456789abcdefu64, 0x1122334455667788u64),
                (0xfedcba9876543210, 0x8877665544332211),
                (0x1234567800000000, 0), (0, 0x89abcdef),
                (0, u64::MAX), (u64::MAX, 0), (0, 0), (u64::MAX, u64::MAX),
            ] {
                assert_own_return_value(fd, &[
                    ((stack, 0x14, 4), incoming >> 32),
                    ((register, rdi.offset, 4), value & 0xffffffff),
                ], (incoming & 0xffffffff00000000) | (value & 0xffffffff));
            }
        } else {
            let input = if callee == "c3" { (stack, 0x10, 8) } else { (register, rdi.offset, 8) };
            for value in ORIGINAL_PHYSICAL_WORDS { assert_own_return_value(fd, &[(input, value)], value); }
        }
        // Original read-before-overwrite/raw memory effects stay at their raw
        // owner; evaluating this optimized own RETURN does not restore a dead read
        // or prove caller-to-callee transport through the opaque CALL result.
    }
}

#[test]
fn unresolved_children_and_alias_reads_preserve_closed_source_arity() {
    for target in ["488b442418e8f61f0000c3", "488b442418488b0ec3"] {
        let image = format!(r#"<binaryimage arch="x86:LE:64:default:gcc">
          <bytechunk space="ram" offset="0x1000" readonly="true">4883ec2848b8efcdab89674523014889442410e8e80f00004883c428c3</bytechunk>
          <bytechunk space="ram" offset="0x2000" readonly="true">{target}</bytechunk>
          <symbol space="ram" offset="0x1000" name="caller"/>
          <symbol space="ram" offset="0x2000" name="target"/>
          <symbol space="ram" offset="0x4000" name="unresolved"/>
        </binaryimage>"#);
        let mut corpus = assert_original_call_shape(&image, &[
            "parse line extern int8 caller(void);", "parse line extern int8 target(void);",
            "lo fu caller", "decompile", "print C", "print raw",
        ], None, Some(0));
        corpus.command("lo fu target").unwrap();
        corpus.command("decompile").unwrap();
        let data = corpus.data();
        let program = data.conf.as_mut().unwrap();
        let fd = data.fd.as_ref().unwrap();
        if target == "488b442418488b0ec3" {
            let stack = program.arch().manage().get_space_by_name("stack").unwrap().get_index();
            for value in ORIGINAL_PHYSICAL_WORDS {
                assert_own_return_value(fd, &[((stack, 0x18, 8), value)], value);
            }
        } else {
            assert_eq!(fd.num_calls(), 1);
            assert_eq!(fd.get_call_specs(0).get_entry_address().get_offset(), 0x4000);
            // Unknown-child return/effects remain a CALL barrier, not a known value.
        }
    }
}

#[test]
fn register_return_wrappers_preserve_closed_source_arity() {
    for (target, child, grandchild) in [
        ("488b4424184889442410c3", "", ""),
        ("488b442418c3", "", ""),
        ("4883ec18e8f70f00004883c418c3", "488b442438c3", ""),
        ("4883ec18e8f70f00004883c418c3", "4883ec18e8f70f00004883c418c3", "488b442458c3"),
        ("4883ec1848c744243055000000e8ee0f00004883c418c3", "488b442438c3", ""),
    ] {
        let mapped = target == "488b4424184889442410c3";
        let finish = if mapped { "488b442408" } else { "" };
        let image = format!(r#"<binaryimage arch="x86:LE:64:default:gcc">
          <bytechunk space="ram" offset="0x1000" readonly="true">4883ec2848b8efcdab89674523014889442410e8e80f0000{finish}4883c428c3</bytechunk>
          <bytechunk space="ram" offset="0x2000" readonly="true">{target}</bytechunk>
          <bytechunk space="ram" offset="0x3000" readonly="true">{child}</bytechunk>
          <bytechunk space="ram" offset="0x4000" readonly="true">{grandchild}</bytechunk>
          <symbol space="ram" offset="0x1000" name="caller"/>
          <symbol space="ram" offset="0x2000" name="target"/>
          <symbol space="ram" offset="0x3000" name="child"/>
          <symbol space="ram" offset="0x4000" name="grandchild"/>
        </binaryimage>"#);
        let target_declaration = if mapped { "map return target::s0x10 int8" }
            else { "parse line extern int8 target(void);" };
        let mut corpus = assert_original_call_shape(&image, &[
            "parse line extern int8 caller(void);", "parse line extern int8 child(void);",
            "parse line extern int8 grandchild(void);", target_declaration,
            "lo fu caller", "decompile", "print C", "print raw",
        ], None, Some(0));
        let (leaf, offset) = if !grandchild.is_empty() { ("grandchild", 0x58) }
            else if !child.is_empty() { ("child", 0x38) } else { ("target", 0x18) };
        corpus.command(&format!("lo fu {leaf}")).unwrap();
        corpus.command("decompile").unwrap();
        let data = corpus.data();
        let stack = data.conf.as_ref().unwrap().arch().manage()
            .get_space_by_name("stack").unwrap().get_index();
        for value in ORIGINAL_PHYSICAL_WORDS {
            assert_own_return_value(data.fd.as_ref().unwrap(), &[((stack, offset, 8), value)], value);
        }
        // Original local0x55 STORE and cross-wrapper frontier effects remain
        // at the raw/machine owner; this is only the selected leaf's own value.
    }
}

#[test]
fn recursive_stack_frontiers_preserve_the_locked_depth_formal() {
    for locked in [false, true] {
      for (store, load) in [("10", "38"), ("c8", "f0")] {
        let image = format!(r#"<binaryimage arch="x86:LE:64:default:gcc">
          <bytechunk space="ram" offset="0x1000" readonly="true">4883ec2848b8efcdab896745230148894424{store}bf01000000e8e30f00004883c428c3</bytechunk>
          <bytechunk space="ram" offset="0x2000" readonly="true">85ff74104883ec18ffcfe8f10f00004883c418c331c0c3</bytechunk>
          <bytechunk space="ram" offset="0x3000" readonly="true">85ff74104883ec18ffcfe8f1efffff4883c418c3488b4424{load}c3</bytechunk>
          <symbol space="ram" offset="0x1000" name="probe"/>
          <symbol space="ram" offset="0x2000" name="left"/>
          <symbol space="ram" offset="0x3000" name="right"/>
        </binaryimage>"#);
        let mut commands = vec!["parse line extern int8 probe(void);"];
        if locked {
            commands.extend(["parse line extern int8 left(int4 depth);",
                "parse line extern int8 right(int4 depth);"]);
        }
        commands.extend(["lo fu probe", "decompile", "print C", "print raw"]);
        let mut corpus = assert_original_call_shape(&image, &commands, None,
            if locked { Some(1) } else { None });
        corpus.command("lo fu right").unwrap();
        corpus.command("decompile").unwrap();
        let data = corpus.data();
        let stack = data.conf.as_ref().unwrap().arch().manage()
            .get_space_by_name("stack").unwrap().get_index();
        let offset = if load == "38" { 0x38 } else { u64::MAX - 15 };
        assert_return_dependencies(data.fd.as_ref().unwrap(), Some(0x3019), &[(stack, offset, 8)]);
        // The recursive branch still contains a CALL value barrier; only the
        // own base-return input is proved here, independently in both modes.
      }
    }
}

#[test]
fn original_x87_target_store_keeps_its_incoming_physical_value() {
    use kuna_num::opcodes::OpCode;
    let xml = r#"<decompilertest>
      <binaryimage arch="x86:LE:64:default:gcc">
        <bytechunk space="ram" offset="0x1000" readonly="true">db6c2408d9e8dec1e8f30f0000c3</bytechunk>
        <bytechunk space="ram" offset="0x2000" readonly="true">db3fc3</bytechunk>
        <symbol space="ram" offset="0x1000" name="probe"/>
        <symbol space="ram" offset="0x2000" name="target"/>
      </binaryimage>
      <script>
        <com>parse line extern void probe(float10 *dest,float10 value);</com>
        <com>parse line extern void target(float10 *dest);</com>
        <com>lo fu probe</com><com>decompile</com><com>print C</com><com>print raw</com>
        <com>lo fu target</com><com>decompile</com><com>print C</com><com>print raw</com>
      </script>
    </decompilertest>"#;
    Corpus::from_xml("original-x87-physical-store", xml).run_all(
        &["probe", "target"], |program, fd| {
            if fd.get_name() == "probe" {
                assert_eq!(fd.get_func_proto().num_params(), 2);
                assert_eq!(fd.num_calls(), 1);
                assert_eq!(fd.get_call_specs(0).get_entry_address().get_offset(), 0x2000);
                assert_eq!(fd.get_call_specs(0).proto().num_params(), 1);
                return;
            }
            assert_eq!(fd.get_func_proto().num_params(), 1);
            let stores: Vec<_> = fd.obank().iter_alive().map(|id| fd.obank().get(id).unwrap())
                .filter(|op| op.code() == OpCode::CPUI_STORE).collect();
            assert_eq!(stores.len(), 1);
            let st0 = program.arch().get_register_varnode(b"ST0").unwrap();
            let value = stores[0].get_in(2).unwrap();
            assert_eq!(physical_storage(fd, value),
                (st0.space.unwrap().get_index(), st0.offset, st0.size as i32));
            let value = fd.vbank().get(value).unwrap();
            assert!(value.is_input(), "STORE consumes actual incoming physical ST0");
            assert_eq!(value.get_type().get_metatype(), kuna_decomp::dtype::type_metatype::TYPE_FLOAT);
            assert_eq!(value.get_size(), 10);
            assert_eq!(value.get_type().get_size(), 10);
            let rdi = program.arch().get_register_varnode(b"RDI").unwrap();
            let destination = stores[0].get_in(1).unwrap();
            assert_eq!(physical_storage(fd, destination),
                (rdi.space.unwrap().get_index(), rdi.offset, rdi.size as i32));
            assert!(fd.vbank().get(destination).unwrap().is_input());
            // Original raw FLOAT_ADD80 chain and vanished caller arithmetic stay
            // externally observed. Explicit materialization is a separate raw-
            // consumer obligation, not an arbitrary input flag or new ST0 formal.
        },
    );
}

#[test]
fn original_memory_only_initializers_keep_their_call_occurrences() {
    for (initialize, call, expression) in [
        ("488d4701", "e8ee0f0000", None),
        ("e8f71f0000", "e8ed0f0000", Some("initialize(value)")),
    ] {
        let xml = format!(r#"<decompilertest>
          <binaryimage arch="x86:LE:64:default:gcc">
            <bytechunk space="ram" offset="0x1000" readonly="true">4883ec18{initialize}4889442408{call}488b4424084883c418c3</bytechunk>
            <bytechunk space="ram" offset="0x2000" readonly="true">c3</bytechunk>
            <bytechunk space="ram" offset="0x3000" readonly="true">488d4701c3</bytechunk>
            <symbol space="ram" offset="0x1000" name="caller"/>
            <symbol space="ram" offset="0x2000" name="target"/>
            <symbol space="ram" offset="0x3000" name="initialize"/>
          </binaryimage>
          <script>
            <com>parse line extern int8 caller(int8 value);</com>
            <com>parse line extern int8 initialize(int8 value);</com>
            <com>map return target::s0x10 int8</com>
            <com>lo fu caller</com><com>decompile</com><com>print C</com>
          </script>
        </decompilertest>"#);
        Corpus::from_xml("original-memory-only-initializers", &xml).run_all(
            &["caller"], |program, fd| {
                let body = print_c(program.arch_mut(), fd);
                assert_eq!(fd.num_calls(), if expression.is_some() { 2 } else { 1 }, "{body}");
                let targets: Vec<_> = (0..fd.num_calls())
                    .map(|index| fd.get_call_specs(index).get_entry_address().get_offset())
                    .collect();
                assert_eq!(targets.iter().filter(|&&entry| entry == 0x2000).count(), 1, "{body}");
                if let Some(expression) = expression {
                    assert_eq!(targets.iter().filter(|&&entry| entry == 0x3000).count(), 1, "{body}");
                    assert_eq!(body.matches(expression).count(), 1, "{body}");
                }
            },
        );
    }
}

#[test]
fn corpus_rejects_partial_action_as_required_function() {
    let mut corpus = Corpus::load("boolless");
    corpus.command("load function boolless").expect("load byte-backed function");
    let action = corpus.data().conf.as_mut().unwrap().arch_mut()
        .allacts.get_current_mut().expect("decompile action");
    assert!(action.set_break_point(kuna_decomp::action::breakflags::break_start, "heritage"));
    let error = corpus.command("decompile")
        .expect_err("a breakpoint must not be counted as a completed function");
    assert!(error.is_execution(), "{error}");
    let data = corpus.data();
    let fd = data.fd.as_ref().expect("the supported partial action retains its function");
    assert!(fd.kuna_pipeline_failure().is_none(), "a pipeline error is not a supported breakpoint");
    let action = data.conf.as_ref().unwrap().arch().allacts.get_current().unwrap();
    assert_ne!(action.get_status(), kuna_decomp::action::statusflags::status_end);
}

#[test]
fn completed_recursive_callback_uses_the_original_callable_for_real_calls() {
    use kuna_console::grammar::{parse_c, DataOrg};
    use kuna_decomp::dtype::TypeFactory;
    for use_node_typedef in [false, true] {
        for observe_before_layout in [false, true] {
            let xml = r#"<decompilertest>
              <binaryimage arch="x86:LE:64:default:gcc">
                <bytechunk space="ram" offset="0x1000" readonly="true">50ffd659c3</bytechunk>
                <symbol space="ram" offset="0x1000" name="invoke"/>
              </binaryimage>
              <script><com>load function invoke</com><com>decompile</com><com>quit</com></script>
            </decompilertest>"#;
            let mut corpus = Corpus::from_xml("completed-recursive-callback", xml);
            let callback = {
                let factory = corpus.data().conf.as_ref().unwrap().arch().types_impl();
                let organization = DataOrg { addr_size: 8, word_size: 1 };
                let declare = |source| parse_c(source, factory, organization, &[], |_, _| unreachable!()).unwrap();
                if use_node_typedef {
                    declare("typedef struct Node Node;");
                    declare("typedef Node (*Fn)(Node);");
                    declare("typedef struct Node OtherNode;");
                } else {
                    declare("struct Node;");
                    declare("typedef struct Node (*Fn)(struct Node);");
                }
                let callback = factory.find_by_name("Fn").unwrap().unwrap();
                if observe_before_layout {
                    let mut pieces = kuna_decomp::fspec::PrototypePieces::default();
                    callback.get_ptr_to().unwrap().get_code_prototype().unwrap().get_pieces(&mut pieces);
                }
                declare("struct Node { float8 d; Fn next; };");
                callback
            };
            corpus.command("parse line extern struct Node invoke(struct Node node, Fn callback);").unwrap();
            corpus.data().pending_prototypes.get_mut("invoke").unwrap().intypes[1] =
                std::rc::Rc::clone(&callback);
            corpus.run_all(&["invoke"], |program, fd| {
                assert_eq!(fd.num_calls(), 1);
                program.arch_mut().ctypes = true;
                let body = print_c(program.arch_mut(), fd);
                assert_c_behavior(
                    &common::scratch_file("completed-recursive-callback", "c"),
                    r#"#include <stddef.h>
struct Node;
typedef struct Node (*Fn)(struct Node);
typedef struct Node Node;
struct Node { double d; Fn next; };
_Static_assert(sizeof(Node) == 16, "original target layout");
_Static_assert(offsetof(Node, d) == 0 && offsetof(Node, next) == 8, "original field geometry");
static Node provider(Node node) { node.d += 3.0; return node; }
static int calls;
static Node counted(Node node) { ++calls; return provider(node); }"#,
                    &body,
                    r#"int main(void) {
    Fn targets[2] = {provider, counted};
    double values[] = {-7.5, -1.0, 0.0, 2.25, 100.5};
    for (int i = 0; i < 5; ++i) for (int j = 0; j < 2; ++j) {
        Node input = {values[i], counted};
        Node result = invoke(input, targets[j]);
        if (result.d != input.d + 3.0 || result.next != counted) return 1;
    }
    return calls != 5;
}"#,
                );
            });
        }
    }
}

#[test]
fn callable_cast_rendering_uses_live_dialect_without_mutating_analysis() {
    for (target_type, table) in [
        ("code *", false), ("void *", false),
        ("code **", true), ("void **", true),
    ] {
        let (bytes, callpoint) = if table {
            ("488b410889d1ffd0c3", 0x1006)
        } else {
            ("4889c889d1ffd0c3", 0x1005)
        };
        let xml = format!(r#"<decompilertest>
          <binaryimage arch="x86:LE:64:default:windows">
            <bytechunk space="ram" offset="0x1000" readonly="true">{bytes}</bytechunk>
            <symbol space="ram" offset="0x1000" name="invoke"/>
          </binaryimage>
          <script>
            <com>parse line extern int4 invoke({target_type} target,int4 value);</com>
            <com>lo fu invoke</com>
            <com>override proto r0x{callpoint:x} int4 callback(int4);</com>
            <com>decompile</com>
            <com>print C</com>
            <com>quit</com>
          </script>
        </decompilertest>"#);
        Corpus::from_xml("callable-dialect", &xml).run_all(&["invoke"], |program, fd| {
            assert_eq!(fd.num_calls(), 1);
            let call = fd.get_call_specs(0).get_op();
            let operands: Vec<_> = (0..fd.obank().get(call).unwrap().num_input())
                .map(|slot| fd.obank().get(call).unwrap().get_in(slot).unwrap()).collect();
            let target_value = fd.vbank().get(operands[0]).unwrap();
            let analyzed_type = target_value.get_type().clone();
            let definition = target_value.get_def();
            let definition_state = || definition.map(|id| {
                let op = fd.obank().get(id).unwrap();
                let inputs: Vec<_> = (0..op.num_input()).map(|slot| op.get_in(slot)).collect();
                (op.code(), inputs, op.get_out())
            });
            let original_definition = definition_state();
            for native in [false, true, false] {
                program.arch_mut().ctypes = native;
                let body = print_c(program.arch_mut(), fd);
                let object_pointer = native || target_type.starts_with("void");
                let target_value = fd.vbank().get(operands[0]).unwrap();
                assert_eq!(target_value.get_def(), definition);
                assert_eq!(definition_state(), original_definition);
                assert!(std::rc::Rc::ptr_eq(target_value.get_type(), &analyzed_type));
                let current: Vec<_> = (0..fd.obank().get(call).unwrap().num_input())
                    .map(|slot| fd.obank().get(call).unwrap().get_in(slot).unwrap()).collect();
                assert_eq!(current, operands, "rendering must not change target or ordered arguments");
                let (setup, callback) = if table && object_pointer {
                    ("void *callbacks[2] = {(void *)decoy, (void *)plus};", "callbacks")
                } else if table {
                    ("code *callbacks[2] = {decoy, plus};", "callbacks")
                } else if object_pointer {
                    ("", "(void *)plus")
                } else {
                    ("", "plus")
                };
                let driver = format!(r#"
int main(void) {{
    {setup}
    for (int value = -20; value <= 20; ++value)
        if (invoke({callback}, value) != value * 3 + 7) return 1;
    return 0;
}}
"#);
                assert_c_behavior(
                    &common::scratch_file("live-callable-dialect", "c"),
                    &format!("{C_TYPES}\ntypedef int code(int);\nstatic int plus(int value) {{ return value * 3 + 7; }}\n{}",
                        if table { "static int decoy(int value) { return value - 100; }" } else { "" }),
                    &body, &driver,
                );
            }
        });
    }
}

#[test]
fn visible_indexed_code_cast_remains_callable_without_mutating_dispatch() {
    let xml = std::fs::read_to_string(repo_root().join("tests/stages/ghdec-funcptralign.xml"))
        .expect("checked-in function-pointer alignment witness");
    Corpus::from_xml("funcptralign-callable", &xml).run_all(
        &["dispatch", "dispatch"], |program, fd| {
            assert_eq!(fd.num_calls(), 1);
            let call = fd.get_call_specs(0).get_op();
            let operands: Vec<_> = (0..fd.obank().get(call).unwrap().num_input())
                .map(|slot| fd.obank().get(call).unwrap().get_in(slot).unwrap()).collect();
            assert_eq!(operands.len(), 2);
            let target_value = fd.vbank().get(operands[0]).unwrap();
            let analyzed_type = target_value.get_type().clone();
            let definition = target_value.get_def();
            let definition_state = || definition.map(|id| {
                let op = fd.obank().get(id).unwrap();
                let inputs: Vec<_> = (0..op.num_input()).map(|slot| op.get_in(slot)).collect();
                (op.code(), inputs, op.get_out())
            });
            let original_definition = definition_state();
            for native in [false, true, false] {
                program.arch_mut().ctypes = native;
                let body = print_c(program.arch_mut(), fd);
                let target_value = fd.vbank().get(operands[0]).unwrap();
                assert_eq!(target_value.get_def(), definition);
                assert_eq!(definition_state(), original_definition);
                assert!(std::rc::Rc::ptr_eq(target_value.get_type(), &analyzed_type));
                let current: Vec<_> = (0..fd.obank().get(call).unwrap().num_input())
                    .map(|slot| fd.obank().get(call).unwrap().get_in(slot).unwrap()).collect();
                assert_eq!(current, operands);
                let table = if native {
                    "void *callbacks[2] = {(void *)decoy, (void *)handler};"
                } else {
                    "code *callbacks[2] = {decoy, handler};"
                };
                assert_c_behavior(&common::scratch_file("indexed-callable-dialect", "c"), &format!(r#"{C_TYPES}
#include <stddef.h>
typedef void code(void *);
static void *expected;
static unsigned calls, wrong;
static void handler(void *context) {{ ++calls; if (context != expected) ++wrong; }}
static void decoy(void *context) {{ (void)context; wrong += 100; }}
"#), &body, &format!(r#"
int main(void) {{
    {table}
    expected = callbacks;
    dispatch(callbacks);
    if (calls != 1 || wrong != 0) return 1;
    callbacks[1] = 0;
    dispatch(callbacks);
    return calls != 1 || wrong != 0;
}}
"#));
            }
        },
    );
}

#[test]
fn immediate_tail_transfer_keeps_numeric_target_explicitly_callable() {
    use kuna_decomp::prettyprint::TokenKind;
    use kuna_decomp::printc::PrintC;
    use kuna_num::opcodes::OpCode;

    let xml = std::fs::read_to_string(repo_root().join("tests/stages/kuna-pushimmediateret.xml"))
        .expect("checked-in unmapped immediate tail-transfer witness");
    let mut pass = 0;
    Corpus::from_xml("immediate-callable-dialect", &xml).run_all(
        &["push_immediate_ret", "push_immediate_ret"], |program, fd| {
            pass += 1;
            let indirect: Vec<_> = (0..fd.num_calls())
                .map(|index| fd.get_call_specs(index).get_op())
                .filter(|op| fd.obank().get(*op).unwrap().code() == OpCode::CPUI_CALLIND)
                .collect();
            assert_eq!(indirect.len(), usize::from(pass == 2),
                "only enabled push-immediate recovery may create the indirect transfer");
            let unpacker: Vec<_> = (0..fd.num_calls())
                .filter(|index| fd.get_call_specs(*index).get_name() == "unpacker")
                .collect();
            assert_eq!(unpacker.len(), 1, "recovery must preserve the preceding unpacker call");
            if pass == 1 {
                return;
            }
            let call = indirect[0];
            let operation = fd.obank().get(call).unwrap();
            assert_eq!(operation.num_input(), 1, "the terminal transfer has no arguments");
            let target = operation.get_in(0).unwrap();
            let target_value = fd.vbank().get(target).unwrap();
            let target_type = target_value.get_type().clone();
            let definition = target_value.get_def();
            assert!(target_value.is_constant());
            assert!(definition.is_none(), "constant callable typing must not require a synthetic CAST");
            assert_eq!(target_type.get_ptr_to().unwrap().get_metatype(),
                kuna_decomp::dtype::type_metatype::TYPE_CODE);
            let source = call_facts::without_value_casts(fd, target);
            let value = fd.vbank().get(source).unwrap();
            assert!(value.is_constant(), "the unmapped runtime destination stays numeric");
            assert_eq!(value.get_offset(), 0x200000);

            for native in [false, true, false] {
                program.arch_mut().ctypes = native;
                let body = print_c(program.arch_mut(), fd);
                let (_, tokens) = PrintC::new().doc_function_tokens(fd, program.arch());
                let conversions: Vec<_> = tokens.iter()
                    .filter(|token| token.kind == TokenKind::Type
                        && !token.in_var_decl && !token.in_proto && !token.in_return_type)
                    .collect();
                assert_eq!(conversions.len(), 1,
                    "numeric destination requires exactly one callable conversion:\n{body}");
                if native {
                    assert!(conversions[0].text.contains('('),
                        "native C requires a full callable signature:\n{body}");
                } else {
                    assert_eq!(conversions[0].text, "code *",
                        "legacy numeric destination must retain its generic callable conversion:\n{body}");
                }
                assert_eq!(fd.obank().get(call).unwrap().get_in(0), Some(target));
                assert_eq!(fd.vbank().get(target).unwrap().get_def(), definition);
                assert!(std::rc::Rc::ptr_eq(
                    fd.vbank().get(target).unwrap().get_type(), &target_type),
                    "dialect changes must preserve the analyzed callable datatype owner");
                assert_eq!(call_facts::without_value_casts(fd, target), source);
                assert_eq!(fd.vbank().get(source).unwrap().get_offset(), 0x200000);
            }
        },
    );
}

#[test]
fn injected_indirect_call_preserves_override_and_later_direct_collapse() {
    use kuna_decomp::dtype::type_metatype;
    use kuna_num::opcodes::OpCode;

    Corpus::load("injectoverride").run_all(
        &["callind_inject", "inject_collapse"],
        |program, fd| {
            let body = print_c(program.arch_mut(), fd);
            assert_eq!(fd.num_calls(), 1, "injection lost or duplicated its call:\n{body}");
            let call = fd.get_call_specs(0);
            let op = fd.obank().get(call.get_op()).unwrap();
            let arity = if fd.get_name() == "callind_inject" { 2 } else { 1 };
            assert_eq!(op.num_input(), arity + 1);
            assert_eq!(call.proto().num_params(), arity);
            assert_eq!(call.proto().get_output().get_type().unwrap().get_metatype(),
                type_metatype::TYPE_VOID);
            for slot in 0..arity {
                let parameter = call.proto().get_param(slot).unwrap();
                assert_eq!(parameter.get_type().unwrap().get_metatype(), type_metatype::TYPE_INT);
                assert_eq!(parameter.get_size(), 4);
                let source = call_facts::without_value_casts(fd, op.get_in(slot + 1).unwrap());
                let source = fd.vbank().get(source).unwrap();
                let input = fd.get_func_proto().get_param(slot).unwrap();
                assert_eq!(source.get_addr(), &input.get_address(),
                    "injection must forward the caller's ordered input parameters");
                assert_eq!(source.get_size(), 4);
                assert!(source.is_input());
            }
            if fd.get_name() == "callind_inject" {
                assert_eq!(op.get_addr().get_offset(), 0x18000c005);
                assert_eq!(op.code(), OpCode::CPUI_CALLIND);
                assert!(call.proto().is_override());
                assert!(call.get_entry_address().is_invalid());
                let target = call_facts::without_value_casts(fd, op.get_in(0).unwrap());
                let target = fd.vbank().get(target).unwrap();
                assert!(target.is_input());
                assert_eq!(target.get_addr().get_space().unwrap().get_name(), "register");
                assert_eq!(target.get_offset(), 0, "guard dispatch must retain its RAX-derived target");
                assert_eq!(target.get_size(), 8);
            } else {
                assert_eq!(op.code(), OpCode::CPUI_CALL);
                assert_eq!(call.get_name(), "collapsed");
                assert_eq!(call.get_entry_address().get_offset(), 0x18000c030);
            }
        },
    );
}

#[test]
fn scripted_corpus_functions_preserve_observable_behavior() {
    for (stem, functions) in [
        ("boolless", &["boolless"][..]),
        ("ccmp", &["ccmp"][..]),
        ("gp", &["test_gp"][..]),
        ("lzcount", &["cntlzwtest"][..]),
        ("condexesub", &["func", "iblockadd"][..]),
    ] {
        Corpus::load(stem).run_all(functions, |program, fd| {
            let body = print_c(program.arch_mut(), fd);
            match fd.get_name() {
                "boolless" => {
                    assert_eq!(fd.get_func_proto().num_params(), 0);
                    assert_eq!(fd.get_func_proto().get_output().get_size(), 1);
                }
                "ccmp" => assert_c_behavior(
                    &common::scratch_file("ccmp-conditional-call", "c"),
                    &format!("{C_TYPES}\nstatic unsigned calls;\nvoid otherfunc(void) {{ ++calls; }}"),
                    &body,
                    r#"
int main(void) {
    const int values[] = {INT_MIN, -1, 0, 8, 9, 10, INT_MAX};
    const unsigned bytes[] = {0, 0x3b, 0x3c, 0x3d, 255};
    for (unsigned i = 0; i < sizeof(values) / sizeof(values[0]); ++i) {
        for (unsigned j = 0; j < sizeof(bytes) / sizeof(bytes[0]); ++j) {
            uint1 ptr[2] = {0x3c, bytes[j]};
            calls = 0;
            ccmp(ptr, values[i]);
            if (calls != (unsigned)(bytes[j] == 0x3c && values[i] <= 9)) return 1;
        }
    }
    return 0;
}
"#,
                ),
                "test_gp" => {
                    assert_eq!(fd.get_func_proto().num_params(), 1);
                    let parameter = fd.get_func_proto().get_param(0).expect("GP input parameter");
                    let parameter_name = kuna_decomp::database::kuna_materialized_param_name(
                        program.arch().name_style_angr, 0, parameter.get_name());
                    assert!(
                        body.contains(&format!("printf(\"Hello\",{parameter_name})")),
                        "GP-relative loads must resolve the format string and preserve the input: {body}"
                    );
                    let mut calls: Vec<_> = (0..fd.num_calls())
                        .map(|i| fd.get_call_specs(i).get_name())
                        .collect();
                    calls.sort_unstable();
                    assert_eq!(calls, ["populate", "printf"], "GP-indirect calls must resolve");
                    assert!(
                        body.find("populate(").expect("populate call in C")
                            < body.find("printf(").expect("printf call in C"),
                        "GP calls were reordered: {body}"
                    );
                }
                "cntlzwtest" => assert_c_behavior(
                    &common::scratch_file("count-leading-zeros-zero-test", "c"),
                    C_TYPES,
                    &body,
                    r#"
int main(void) {
    const uint4 values[] = {0, 1, 2, 3, 4, 0x7fffffff, 0x80000000, 0xffffffff};
    for (unsigned i = 0; i < sizeof(values) / sizeof(values[0]); ++i)
        if ((unsigned)cntlzwtest(values[i]) != (unsigned)(values[i] == 3)) return 1;
    return 0;
}
"#,
                ),
                "func" => assert_c_behavior(
                    &common::scratch_file("conditional-member-stores", "c"),
                    &format!("{C_TYPES}\n#include <string.h>\n\
                        typedef struct foo {{ char buf[0x14]; char w, x, y, z; }} foo;\n\
                        static foo *glob1; static foo *result; static unsigned calls;\n\
                        foo *other(void) {{ ++calls; return result; }}"),
                    &body,
                    r#"
int main(void) {
    for (unsigned mode = 0; mode < 3; ++mode) {
        foo global, returned, expected_global, expected_returned;
        memset(&global, 0x55, sizeof(global));
        memset(&returned, 0x66, sizeof(returned));
        expected_global = global;
        expected_returned = returned;
        expected_global.w = 1;
        if (mode == 1) expected_returned.x = expected_returned.y = expected_returned.z = 0;
        if (mode == 2) expected_global.x = expected_global.y = expected_global.z = 0;
        glob1 = &global;
        result = mode == 0 ? 0 : mode == 1 ? &returned : &global;
        calls = 0;
        func();
        if (calls != 1 || memcmp(&global, &expected_global, sizeof(global)) ||
            memcmp(&returned, &expected_returned, sizeof(returned))) return 1;
    }
    return 0;
}
"#,
                ),
                "iblockadd" => assert_c_behavior(
                    &common::scratch_file("thumb-conditional-stores", "c"),
                    C_TYPES,
                    &body,
                    r#"
int main(void) {
    const int4 values[] = {INT32_MIN, -1, 0, 8, 9, 10, 11, INT32_MAX};
    for (unsigned k = 0; k < sizeof(values) / sizeof(values[0]); ++k) {
        int4 actual[4] = {101, 202, 303, 404};
        int4 expected[4] = {101, 202, 303, 404};
        iblockadd(actual, values[k], 0x12345678, -77);
        if (values[k] <= 9) { expected[0] = 0x12345678; expected[2] = -77; }
        else { expected[1] = -77; expected[3] = 0x12345678; }
        for (unsigned i = 0; i < 4; ++i) if (actual[i] != expected[i]) return 1;
    }
    return 0;
}
"#,
                ),
                name => panic!("unexpected script-selected function {name}"),
            }
        });
    }
}

#[test]
fn option_commands_change_readonly_resolution_and_null_rendering() {
    let mut corpus = Corpus::load("gp");
    corpus.run_to_function("test_gp");
    for enabled in [true, false, true] {
        corpus.command(&format!("option readonly {}", if enabled { "on" } else { "off" }))
            .expect("set read-only propagation");
        corpus.command("decompile").expect("decompile under changed read-only policy");
        let body = corpus.render_c();
        assert_eq!(
            body.contains("printf(\"Hello\","),
            enabled,
            "read-only propagation must control resolution through the GP table: {body}"
        );
    }

    let mut pointer_loop = Corpus::load("forloop_loaditer");
    pointer_loop.run_to_function("forloop_loaditer");
    let named_null = regex::Regex::new(r"loopvar\s*!=\s*NULL").unwrap();
    let casted_null = regex::Regex::new(r"loopvar\s*!=\s*(?:\([^)]*\)\s*)?0x0").unwrap();
    for enabled in [true, false, true] {
        pointer_loop.command(&format!("option nullprinting {}", if enabled { "on" } else { "off" }))
            .expect("set NULL printing");
        let body = pointer_loop.render_c();
        assert_eq!(named_null.is_match(&body), enabled, "NULL-rendering policy not applied: {body}");
        assert_eq!(casted_null.is_match(&body), !enabled, "typed zero-rendering policy not applied: {body}");
    }
}

#[test]
fn maxinstruction_option_bounds_flow_following() {
    let mut corpus = Corpus::load("gp");
    // Apply readonly, tracked t9 and printf's prototype before changing flow policy.
    corpus.run_to_function("test_gp");
    corpus.command("option errortoomanyinstructions on").unwrap();
    corpus.command("option maxinstruction 2").unwrap();
    let error = corpus.command("decompile").expect_err("the fatal instruction bound must abort");
    assert!(error.is_execution(), "instruction-budget failure must be an execution error: {error}");

    corpus.command("option errortoomanyinstructions off").unwrap();
    corpus.command("decompile").expect("nonfatal bound must truncate flow");
    let truncated = corpus.render_c();
    assert!(!truncated.contains("printf("), "truncation still reached the later call: {truncated}");

    corpus.command("option errortoomanyinstructions on").unwrap();
    corpus.command("option maxinstruction 100000").unwrap();
    corpus.command("decompile").expect("restored bound must decompile the complete function");
    let full = corpus.render_c();
    assert!(full.contains("populate(") && full.contains("printf(\"Hello\","),
        "restoring the bound did not recover both observable calls: {full}");
}


#[test]
fn lowered_switch_dispatch_uses_compared_input_not_reused_register() {
    let xml = std::fs::read_to_string(repo_root().join("tests/stages/kuna-loweredswitchvalue.xml"))
        .expect("lowered-switch fixture");
    let mut corpus = Corpus::from_xml("lowered-switch-value", &xml);
    for enabled in [false, true] {
        corpus.run_to_function("dispatch");
        let body = corpus.render_c();
        let preamble = format!("{C_TYPES}\n\
            static unsigned calls, selected;\n\
            static unsigned long forwarded;\n\
            unsigned long on_one(void) {{ ++calls; selected = 1; return 101; }}\n\
            unsigned long on_two(void) {{ ++calls; selected = 2; return 202; }}\n\
            unsigned long on_three_four(unsigned long value, int choice) {{\n\
                ++calls; selected = 3 + choice; forwarded = value; return 303 + choice;\n\
            }}\n");
        let driver = format!(r#"
int main(void) {{
    const unsigned long values[] = {{0, 1, 2, 3, 4, 5, 0x80000001UL, 0xffffffffUL}};
    for (unsigned i = 0; i < sizeof(values) / sizeof(values[0]); ++i) {{
        for (unsigned j = 0; j < sizeof(values) / sizeof(values[0]); ++j) {{
            uint32_t selector = (uint32_t)({enabled} ? values[i] : values[j]);
            unsigned want_case = selector >= 1 && selector <= 4 ? selector : 0;
            unsigned long expected = want_case == 1 ? 101 : want_case == 2 ? 202
                : want_case == 3 ? 303 : want_case == 4 ? 304 : 0xffffffffUL;
            calls = selected = 0;
            forwarded = 0;
            unsigned long actual = dispatch(values[i], values[j]);
            if (actual != expected || selected != want_case || calls != (want_case != 0))
                return 1;
            if (want_case >= 3 && forwarded != values[j])
                return 2;
        }}
    }}
    return 0;
}}
"#, enabled = u8::from(enabled));
        assert_c_behavior(
            &common::scratch_file(&format!("lowered-switch-{enabled}"), "c"),
            &preamble, &body, &driver,
        );
    }
}

#[test]
fn missing_thumb_context_rejects_the_required_function() {
    let xml = std::fs::read_to_string(repo_root().join("tests/datatests/condexesub.xml"))
        .expect("conditional-store fixture");
    let context = "<com>set context TMode 1 [ram,0x402d29e0] [ram,0x402d29ef]</com>";
    assert!(xml.contains(context), "fixture must contain the context command being removed");
    let mut corpus = Corpus::from_xml("condexesub-without-thumb-context", &xml.replace(context, ""));
    // The ARM function still succeeds; its success must not mask the required
    // Thumb function's rejected decode.
    corpus.run_to_function("func");
    let error = corpus.command("load function iblockadd")
        .expect_err("iblockadd cannot be followed as ARM when its bytes are Thumb");
    assert!(error.is_execution(), "{error}");
}
