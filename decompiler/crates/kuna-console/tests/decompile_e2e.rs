//! Real corpus scripts must preserve their required functions and observable effects.

mod common;
#[path = "common/corpus.rs"]
mod corpus;
#[path = "common/call_facts.rs"]
mod call_facts;

use corpus::{assert_c_behavior, repo_root, Corpus, C_TYPES};
use kuna_decomp::decompile_drive::print_c;

#[test]
fn callable_cast_rendering_uses_live_dialect_without_mutating_analysis() {
    use kuna_num::opcodes::OpCode;

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
            let cast = fd.vbank().get(operands[0]).unwrap().get_def().expect("semantic target CAST");
            assert_eq!(fd.obank().get(cast).unwrap().code(), OpCode::CPUI_CAST);
            let cast_input = fd.obank().get(cast).unwrap().get_in(0).unwrap();
            for native in [false, true, false] {
                program.arch_mut().ctypes = native;
                let body = print_c(program.arch_mut(), fd);
                let object_pointer = native || target_type.starts_with("void");
                assert_eq!(fd.obank().get(cast).unwrap().code(), OpCode::CPUI_CAST);
                assert_eq!(fd.obank().get(cast).unwrap().get_in(0), Some(cast_input));
                assert_eq!(fd.obank().get(cast).unwrap().get_out(), Some(operands[0]));
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
                    "live-callable-dialect",
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
    use kuna_num::opcodes::OpCode;

    let xml = std::fs::read_to_string(repo_root().join("tests/stages/ghdec-funcptralign.xml"))
        .expect("checked-in function-pointer alignment witness");
    Corpus::from_xml("funcptralign-callable", &xml).run_all(
        &["dispatch", "dispatch"], |program, fd| {
            assert_eq!(fd.num_calls(), 1);
            let call = fd.get_call_specs(0).get_op();
            let operands: Vec<_> = (0..fd.obank().get(call).unwrap().num_input())
                .map(|slot| fd.obank().get(call).unwrap().get_in(slot).unwrap()).collect();
            assert_eq!(operands.len(), 2);
            let cast = fd.vbank().get(operands[0]).unwrap().get_def().expect("semantic callback CAST");
            assert_eq!(fd.obank().get(cast).unwrap().code(), OpCode::CPUI_CAST);
            for native in [false, true, false] {
                program.arch_mut().ctypes = native;
                let body = print_c(program.arch_mut(), fd);
                assert_eq!(fd.obank().get(cast).unwrap().code(), OpCode::CPUI_CAST);
                let current: Vec<_> = (0..fd.obank().get(call).unwrap().num_input())
                    .map(|slot| fd.obank().get(call).unwrap().get_in(slot).unwrap()).collect();
                assert_eq!(current, operands);
                let table = if native {
                    "void *callbacks[2] = {(void *)decoy, (void *)handler};"
                } else {
                    "code *callbacks[2] = {decoy, handler};"
                };
                assert_c_behavior("indexed-callable-dialect", &format!(r#"{C_TYPES}
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
            {
                let code_type = target_type.get_ptr_to().unwrap();
                let view = code_type.read();
                assert!(view.get_code_prototype(code_type.id()).unwrap().is_some());
            }
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
                assert_eq!(fd.vbank().get(target).unwrap().get_type(), &target_type,
                    "dialect changes must preserve the analyzed callable datatype");
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
            // Exercise the actual renderer, but inspect call semantics rather
            // than requiring one dialect's choice of visible callable cast.
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
                // The exhaustive emitted-C return witness lives in deadcode_b4.
                "boolless" => {
                    assert_eq!(fd.get_func_proto().num_params(), 0);
                    assert_eq!(fd.get_func_proto().get_output().get_size(), 1);
                }
                "ccmp" => assert_c_behavior(
                    "ccmp-conditional-call",
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
                    // Unlocked prototypes can retain an empty stored name.
                    // Resolve its emitted binder using the same naming policy
                    // as the signature, then check the call forwards that input.
                    let parameter_name = kuna_decomp::database::kuna_materialized_param_name(
                        program.arch().name_style_angr,
                        0,
                        parameter.get_name(),
                    );
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
                    "count-leading-zeros-zero-test",
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
                    "conditional-member-stores",
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
                    "thumb-conditional-stores",
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
    let casted_null = regex::Regex::new(r"loopvar\s*!=\s*\([^)]*\*\s*\*\s*\)\s*0x0").unwrap();
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
    assert!(truncated.contains("instruction budget"), "missing truncation warning: {truncated}");
    assert!(!truncated.contains("printf("), "truncation still reached the later call: {truncated}");

    corpus.command("option errortoomanyinstructions on").unwrap();
    corpus.command("option maxinstruction 100000").unwrap();
    corpus.command("decompile").expect("restored bound must decompile the complete function");
    let full = corpus.render_c();
    assert!(full.contains("populate(") && full.contains("printf(\"Hello\","),
        "restoring the bound did not recover both observable calls: {full}");
}

#[test]
fn partial_pipeline_is_not_a_successful_decompilation() {
    let mut corpus = Corpus::load("boolless");
    corpus.command("load function boolless").expect("load byte-backed function");
    // The console breakpoint command is not implemented, but the production
    // action API supports it. Exercise the real pipeline, not a fake FD flag.
    let action = corpus.data().conf.as_mut().unwrap().arch_mut()
        .allacts.get_current_mut().expect("decompile action");
    assert!(action.set_break_point(kuna_decomp::action::breakflags::break_start, "heritage"));
    let error = corpus.command("decompile")
        .expect_err("a breakpoint must not be counted as a completed function");
    assert!(error.is_execution(), "{error}");
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
        assert_c_behavior(&format!("lowered-switch-{enabled}"), &preamble, &body, &driver);
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
