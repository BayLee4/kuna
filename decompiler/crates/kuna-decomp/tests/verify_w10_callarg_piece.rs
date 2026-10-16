//! Adversarial tests for item `w10-callarg-piece` — call-argument PIECE recovery
//! (the INPUT mirror of the struct-return field-binding `RulePieceStructure` path).
//!
//! ROOT CAUSE this item closed: a by-value struct (or any callee-typed
//! aggregate) passed as a CALL argument was rendered with the forming CONCAT
//! inlined (`structparam(CONCAT(regp2,regp1))`) instead of split into per-field
//! writes (`v1.A = regp1; v1.B = regp2; structparam(v1);`).  The split is done by
//! `RulePieceStructure`, which fires only when the CONCAT output Varnode carries
//! a *structured* data-type.  On the call-arg side that type comes from the
//! callee parameter (`TypeOpCall::getInputLocal`, typeop.cc:689), but the callee
//! `FuncProto` was never copied into the call's `FuncCallSpecs`
//! (`ActionDefaultParams`, coreaction.cc:2385: `fc->copy(otherfunc->getFuncProto())`)
//! because the declared callee's locked prototype (`parse line extern <sig>`,
//! `Architecture::setPrototype`, architecture.cc:393) was never applied to the
//! callee FunctionSymbol's `TypeCode`.  This item:
//!   * applies a parsed `extern` prototype to the matching FunctionSymbol
//!     (`apply_prototype_to_symbol` → `retype_symbol` with `getTypeCode(pieces)`);
//!   * surfaces the callee proto via the global-query snapshot
//!     (`Architecture::query_callee_proto` reading `TypeCode::getPrototype`);
//!   * copies it into the call spec at flow-construction time
//!     (`FlowInfo::build_call_specs`, flow.rs).
//!
//! The copy (`fc.proto_mut().copy(callee_proto)` + `setModel(evalfp)`) is the
//! RELOCATED home of the C++ `ActionDefaultParams::apply` copy arm
//! (coreaction.cc:2385): kuna performs it where `queryCall` already associates the
//! callee (flow.cc:678-688) rather than in the reserved `coreaction_protos.rs`.
//! The postpone is a documented no-op on the kuna path (the declared callee
//! signature is locked by `parse line extern` before flow runs — see the STUB
//! comment in flow.rs).
//!
//! These drive the *real* gate path: the committed Rust `decomp_test_dbg`
//! harness on `concat.xml` / `longdouble.xml` whose `<script>` runs
//! `parse line extern` + `lo fu` + `decompile` + `print C`.  Assertions preserve
//! the authored types, gathered field values, and ordering around the call,
//! without constraining storage comments or whole-function formatting.  The
//! different aggregate layouts exercise recovery beyond a single name/shape.
//! All tests SKIP (not fail) when a binary or `.sla` is unavailable,
//! honoring the same pattern as `verify_w10_input_prototype_adversarial.rs`.

use std::path::PathBuf;
use std::process::Command;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../..").canonicalize().unwrap()
}

fn specs_root() -> PathBuf {
    std::env::var_os("KUNA_SPECS")
        .map(PathBuf::from)
        .unwrap_or_else(|| repo_root().join("specs"))
}

fn datatests_dir() -> PathBuf {
    std::env::var_os("KUNA_DATATESTS")
        .map(PathBuf::from)
        .unwrap_or_else(|| repo_root().join("tests/datatests"))
}

fn rust_test_bin() -> PathBuf {
    std::env::var_os("KUNA_DECOMP_TEST_RUST")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../target/debug/decomp_test_dbg"))
}

/// Drive a `decomp_test_dbg` binary on one datatest with `KUNA_DUMP=1` and
/// return the dumped `print C` block.  `None` if the binary is missing or
/// produced no dump (no spec/`.sla`).
fn dump_print_c(bin: &PathBuf, stem: &str) -> Option<String> {
    if !bin.exists() {
        return None;
    }
    let out = Command::new(bin)
        .arg("-sleighpath")
        .arg(specs_root())
        .arg("-path")
        .arg(datatests_dir())
        .arg("datatests")
        .arg(format!("{stem}.xml"))
        .env("KUNA_DUMP", "1")
        .output()
        .ok()?;
    let text = String::from_utf8_lossy(&out.stdout).into_owned();
    let begin = text.find("===KUNA_DUMP_BEGIN")?;
    let after_begin = text[begin..].find('\n')? + begin + 1;
    let mid = text[after_begin..].find("===KUNA_DUMP_MID===")? + after_begin;
    Some(text[after_begin..mid].to_string())
}

/// Extract the body of a named function from a `print C` dump (the lines from the
/// `<sig> {`-introducing signature line through the matching closing brace).
fn function_block<'a>(dump: &'a str, name: &str) -> Option<&'a str> {
    let sig = dump.lines().position(|l| l.contains(name) && l.contains('('))?;
    let bytes = dump.as_bytes();
    // Find the byte offset of that signature line.
    let mut off = 0usize;
    for (i, line) in dump.lines().enumerate() {
        if i == sig {
            break;
        }
        off += line.len() + 1;
    }
    // Walk to the closing brace that returns depth to 0.
    let mut depth = 0i32;
    let mut seen_open = false;
    let mut end = off;
    for (i, &b) in bytes[off..].iter().enumerate() {
        if b == b'{' {
            depth += 1;
            seen_open = true;
        } else if b == b'}' {
            depth -= 1;
            if seen_open && depth == 0 {
                end = off + i + 1;
                break;
            }
        }
    }
    Some(&dump[off..end])
}

/// AT1 — POSITIVE: a by-value struct passed as a CALL argument is gathered and
/// rendered as per-field write statements (the INPUT mirror of the return-side
/// `v1.A = retp1; v1.B = retp2`), and the CONCAT no longer survives inline.
///
/// `concatregparam` calls `structparam(foo)` by value; the oracle renders
/// `v1.A = regp1; v1.B = regp2; structparam(v1);`.  Pre-item the Rust path
/// emitted `structparam(CONCAT(regp2,regp1));`.
#[test]
fn at1_by_value_struct_arg_renders_field_writes_not_inline_concat() {
    let rust = match dump_print_c(&rust_test_bin(), "concat") {
        Some(t) => t,
        None => {
            eprintln!("SKIP: rust decomp_test_dbg / .sla unavailable");
            return;
        }
    };
    let body = function_block(&rust, "concatregparam")
        .unwrap_or_else(|| panic!("no concatregparam block in:\n{rust}"));

    // The forming CONCAT must NOT survive as an inline call argument.
    assert!(
        !body.contains("structparam(CONCAT"),
        "by-value struct call argument still renders the inline CONCAT (RulePieceStructure \
         did not split the call-arg PIECE tree); got:\n{body}"
    );
    // The argument is passed as the gathered whole-struct variable.
    assert!(
        body.contains("structparam(v1)"),
        "the call argument is not the gathered whole-struct variable `v1`; got:\n{body}"
    );
    // Both fields are recovered as separate write statements (the per-field render).
    assert!(
        body.contains("v1.A = regp1;") && body.contains("v1.B = regp2;"),
        "the two struct fields are not rendered as separate writes; got:\n{body}"
    );

    assert!(
        regex::Regex::new(
            r"^\s*void\s+concatregparam\s*\(\s*int4\s+regp1\s*,\s*int4\s+regp2\s*\)"
        ).unwrap().is_match(body),
        "the caller must retain its void result and two int4 inputs:\n{body}"
    );
    let decl = regex::Regex::new(r"(?m)^\s*foo\s+v1\s*;").unwrap()
        .find(body)
        .unwrap_or_else(|| panic!("missing gathered foo local:\n{body}"))
        .start();
    let call = body.find("structparam(v1)").unwrap();
    // Either independent field order is valid, but both values must reach the call.
    for field in ["v1.A = regp1;", "v1.B = regp2;"] {
        let write = body.find(field).unwrap();
        assert!(
            decl < write && write < call,
            "the gathered local must be declared and initialized before the call; \
             field `{field}`:\n{body}"
        );
    }
}

/// AT2 — GENERIC (no name-keying): the same call-arg split fires for a DIFFERENT
/// struct (`fooshort`) with DIFFERENT field names (`a`/`b`/`c`/`d`) and a partial
/// in-place update.  `replaceshort` calls `structshort(fooshort)`; the oracle
/// gathers the struct from a mix of a replaced field and globals and renders
/// `v1.b = replace1; v1.a = globshort.a; ...; structshort(v1);`.
///
/// Because the recovery is keyed only on the callee parameter's *structured
/// data-type* (not on any name), a special-cased `foo`/`A`/`B`/`structparam`
/// decode could not satisfy this — the names here are entirely different.
#[test]
fn at2_generic_struct_arg_split_no_name_keying() {
    let rust = match dump_print_c(&rust_test_bin(), "concat") {
        Some(t) => t,
        None => {
            eprintln!("SKIP: rust decomp_test_dbg / .sla unavailable");
            return;
        }
    };
    let body = function_block(&rust, "replaceshort")
        .unwrap_or_else(|| panic!("no replaceshort block in:\n{rust}"));

    // No inline CONCAT survives as the call argument (a different struct/fields).
    assert!(
        !body.contains("structshort(CONCAT"),
        "fooshort by-value call argument still renders the inline CONCAT; got:\n{body}"
    );
    assert!(
        body.contains("structshort(v1)"),
        "the fooshort argument is not the gathered whole-struct variable; got:\n{body}"
    );
    // The four DIFFERENTLY-NAMED fields are recovered as separate writes — the
    // recovery walked the struct's own geometry, not a hardcoded `A`/`B` pair.
    for fw in ["v1.b = replace1;", "v1.a = globshort.a;", "v1.c = globshort.c;", "v1.d = globshort.d;"] {
        assert!(
            body.contains(fw),
            "missing generic field write `{fw}` (struct geometry not walked generically); \
             got:\n{body}"
        );
    }

    assert!(
        regex::Regex::new(
            r"^\s*void\s+replaceshort\s*\(\s*int2\s+replace1\s*,\s*int2\s+replace2\s*\)"
        ).unwrap().is_match(body),
        "the caller must retain its void result and two int2 inputs:\n{body}"
    );
    let decl = regex::Regex::new(r"(?m)^\s*fooshort\s+v1\s*;").unwrap()
        .find(body)
        .unwrap_or_else(|| panic!("missing gathered fooshort local:\n{body}"))
        .start();
    let call = body.find("structshort(v1)").unwrap();
    for field in [
        "v1.b = replace1;",
        "v1.a = globshort.a;",
        "v1.c = globshort.c;",
        "v1.d = globshort.d;",
    ] {
        let write = body.find(field).unwrap();
        assert!(
            decl < write && write < call,
            "the gathered local must be declared and initialized before the call; \
             field `{field}`:\n{body}"
        );
    }
    let before = body.find("globshort.b = replace1;")
        .unwrap_or_else(|| panic!("missing pre-call global update:\n{body}"));
    let after = body.find("globshort.d = replace2;")
        .unwrap_or_else(|| panic!("missing post-call global update:\n{body}"));
    assert!(
        before < call && call < after,
        "the call must observe the b update but precede the d update:\n{body}"
    );
}

/// AT3 — the split is DRIVEN BY THE CALLEE PROTO, not a same-function default.
/// The return-side `concatreturn` (its struct type comes from the FUNCTION's
/// recovered output) already split before this item; the call-arg `concatregparam`
/// (its struct type must come from the CALLEE param) did not.  Both now split, and
/// the call-arg block must show the *call* form (`structparam(v1)`), proving the
/// callee parameter type — not the function's own output type — drove it.
#[test]
fn at3_callarg_split_uses_callee_param_type() {
    let rust = match dump_print_c(&rust_test_bin(), "concat") {
        Some(t) => t,
        None => {
            eprintln!("SKIP: rust decomp_test_dbg / .sla unavailable");
            return;
        }
    };
    // The call-arg function gathers and CALLS with the whole struct.
    let call_body = function_block(&rust, "concatregparam")
        .unwrap_or_else(|| panic!("no concatregparam block in:\n{rust}"));
    assert!(
        call_body.contains("structparam(v1)") && !call_body.contains("CONCAT"),
        "call-arg struct not gathered from the callee param type; got:\n{call_body}"
    );
    // The return-side function still splits (regression guard for struct-return-v2).
    let ret_body = function_block(&rust, "concatreturn")
        .unwrap_or_else(|| panic!("no concatreturn block in:\n{rust}"));
    assert!(
        ret_body.contains("v1.A = retp1;")
            && ret_body.contains("v1.B = retp2;")
            && ret_body.contains("return v1;")
            && !ret_body.contains("CONCAT"),
        "return-side split regressed; got:\n{ret_body}"
    );
}

/// AT4 — POST-ALIGNMENT-MAP (w10-longdouble-reassembly, LOSS-223/224 restoration):
/// the wide-float (`float10`) CALL argument now folds to the BYTE-CLEAN oracle
/// render `writeLongDouble(ldarr,x)`.  The earlier waves built the float10 arg but
/// left it as `(float10)CONCAT28(z,CONCAT62(v1,x))` because the float10 *input
/// parameter* `x` was placed at the wrong stack offset (0x10 vs the oracle's
/// 0x18): its alignment resolved to 8 instead of 16.  Root: the cspec
/// `<size_alignment_map>` (x86-64 gcc 16->16) was never decoded into the
/// `TypeFactory`, so `getAlignment(getPrimitiveAlignSize(10)=16)` fell back to the
/// default map (->8).  Decoding the cspec map (this wave) gives float10 the
/// correct alignment 16, the param lands at 0x18 covering the call's stack value
/// exactly, and the CONCAT is no longer needed.  This is the documented LOSS-223
/// restoration ("converges to `writeLongDouble(ldarr,x)` when the stack-slot
/// coherence lands; re-tighten AT4 to require the clean `x`").  Long double
/// #3/#4/#7/#8/#9 flip green; regressed set EMPTY.
#[test]
fn at4_widefloat_callarg_concat_built_with_keystone() {
    let rust = match dump_print_c(&rust_test_bin(), "longdouble") {
        Some(t) => t,
        None => {
            eprintln!("SKIP: rust decomp_test_dbg / .sla unavailable");
            return;
        }
    };
    let body = function_block(&rust, "passmany")
        .unwrap_or_else(|| panic!("no passmany block in:\n{rust}"));
    // The float10 argument folds to the clean oracle render: the input parameter
    // `x` (float10, alignment 16 -> stack 0x18) covers the call's stack value
    // exactly, so the call passes `x` directly with no piece reassembly.
    assert!(
        body.contains("writeLongDouble(ldarr,x);") && !body.contains("CONCAT"),
        "the float10 call-arg did not fold to the clean oracle render \
         `writeLongDouble(ldarr,x)` (alignment-map / param-offset regression); got:\n{body}"
    );
}
