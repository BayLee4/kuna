//! Floating literals must preserve the original target bits when compiled as C.

use crate::common;
#[path = "common/corpus.rs"]
mod corpus;

use std::fmt::Write;
use corpus::{assert_c_behavior, Corpus, C_TYPES};

#[test]
fn emitted_float_boundaries_preserve_bits_in_their_return_type() {
    let cases: &[(u32, u64)] = &[
        (8, 0x7fefffffffffffff), (8, 0xffefffffffffffff),
        (8, 0x7feffffffffffffe), (8, 0x0000000000000001),
        (8, 0x000fffffffffffff), (8, 0x0010000000000000),
        (8, 0), (8, 0x8000000000000000),
        (4, 0x7f7fffff), (4, 0xff7fffff),
        (4, 0x7f7ffffe), (4, 0x00000001),
        (4, 0x007fffff), (4, 0x00800000),
        (4, 0), (4, 0x80000000),
    ];
    let mut xml = String::from("<decompilertest><binaryimage arch=\"x86:LE:64:default:gcc\">");
    let mut script = String::new();
    let mut driver = String::from("int main(void) {\n");
    for (i, &(size, bits)) in cases.iter().enumerate() {
        let addr = 0x1000 + 0x20 * i;
        let (ty, integer, prefix, suffix) = if size == 8 {
            ("double", "uint64_t", "48b8", "66480f6ec0c3")
        } else {
            ("float", "uint32_t", "b8", "660f6ec0c3")
        };
        write!(xml, "<bytechunk space=\"ram\" offset=\"0x{addr:x}\">{prefix}").unwrap();
        for byte in &bits.to_le_bytes()[..size as usize] {
            write!(xml, "{byte:02x}").unwrap();
        }
        write!(xml, "{suffix}</bytechunk><symbol space=\"ram\" offset=\"0x{addr:x}\" name=\"value_{i}\"/>").unwrap();
        write!(script, "<com>parse line extern {ty} value_{i}(void);</com><com>lo fu value_{i}</com><com>decompile</com>").unwrap();
        writeln!(driver, "{{ {ty} value = value_{i}(); {integer} bits; memcpy(&bits, &value, sizeof(bits)); if (bits != UINT{}_C(0x{bits:x})) {{ fprintf(stderr, \"value_{i} changed bits\\n\"); return 1; }} }}", size * 8).unwrap();
    }
    write!(xml, "</binaryimage><script>{script}</script></decompilertest>").unwrap();
    driver.push_str("return 0; }\n");
    let mut corpus = Corpus::from_xml("float-literals", &xml);
    let mut bodies = String::new();
    for i in 0..cases.len() {
        corpus.run_to_function(&format!("value_{i}"));
        bodies.push_str(&corpus.render_c());
        bodies.push('\n');
    }
    let preamble = format!("{C_TYPES}\ntypedef float float4;\ntypedef double float8;\n#include <stdio.h>\n#include <string.h>\n");
    assert_c_behavior(&common::scratch_file("float-literals", "c"), &preamble, &bodies, &driver);
}
