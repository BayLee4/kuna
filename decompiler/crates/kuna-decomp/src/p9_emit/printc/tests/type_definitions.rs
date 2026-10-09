use super::*;
use super::support::{assert_c_source, assert_rust_source, bare_arch, execution_printer};
use crate::dtype::{type_metatype, Datatype, TypeFactory, TypeFactoryImpl, TypeField};
use std::rc::Rc;

mod decompile_project_type_render {
    use super::*;
    use crate::dtype::flags;
    use crate::printc::{
        render_type_definitions,
        RealTypeCtx,
    };
    fn named(types: &TypeFactoryImpl, size: i32, m: type_metatype, nm: &str) -> Rc<Datatype> {
        types.get_base_named(size, m, nm).unwrap()
    }



    /// A complete named struct with the given (offset, name, type) fields and
    /// total size.

    fn make_enum(types: &TypeFactoryImpl, nm: &str, size: i32, m: type_metatype, entries: &[(u64, &str)]) -> Rc<Datatype> {
        let shell = types.get_type_enum_sized(nm, size, if m == type_metatype::TYPE_INT {
            type_metatype::TYPE_ENUM_INT
        } else { type_metatype::TYPE_ENUM_UINT }).unwrap();
        types.set_enum_values(&shell, entries.iter()
            .map(|(value, name)| (*value, (*name).to_string())).collect()).unwrap()
    }




    #[test]
    fn generated_enum_width_sign_and_complements_are_consumed_without_repair() {
        let types = TypeFactoryImpl::new();
        types.setup_sizes(Some(4), 8, 8);
        types.set_max_basetype_size(8);
        for size in [1, 2, 4, 8] {
            for signed in [false, true] {
                let meta = if signed { type_metatype::TYPE_INT } else { type_metatype::TYPE_UINT };
                let name = format!("Flags{}{}", size * 8, if signed { "s" } else { "u" });
                let ty = make_enum(&types, &name, size, meta, &[(1, "ONE"), (2, "TWO")]);
                let declarations = render_type_definitions(&[ty.clone()], RealTypeCtx::OFF);
                let mut checks = String::new();
                for flag in [1, 3] {
                    let value = kuna_base::address::calc_mask(size) ^ flag;
                    let mut print = PrintC::new();
                    print.set_output_stream();
                    print.push_enum_constant_ir(&ty, value, OpId::default(), VarnodeId::default());
                    let expression = print.emit_mut().output_str();
                    let expected = if signed {
                        format!("({}LL)", value as i128 - (1i128 << (size * 8)))
                    } else {
                        format!("{value}ULL")
                    };
                    checks.push_str(&format!("assert(({expression}) == {expected});\n"));
                }
                let source = format!(
                    "#include <assert.h>\n#include <stdint.h>\n{declarations}\n\
                     _Static_assert(sizeof({name}) == {size}, \"declared enum width\");\n\
                     _Static_assert((({name})-1 < 0) == {}, \"declared enum sign\");\n\
                     int main(void) {{ {checks} return 0; }}\n",
                    u8::from(signed),
                );
                super::assert_c_source(&source, &format!("enum-{name}"));
            }
        }
    }

    #[test]
    fn generated_partial_enum_keeps_upper_byte_values_without_signed_widening() {
        let types = TypeFactoryImpl::new();
        types.setup_sizes(Some(4), 8, 8);
        types.set_max_basetype_size(8);
        types.set_core_type("unknown1", 1, type_metatype::TYPE_UNKNOWN, false).unwrap();
        types.cache_core_types().unwrap();
        let parent = make_enum(&types, "Parent", 8, type_metatype::TYPE_INT, &[
            (0, "PARENT_ZERO"), (0x1_ffff_ffff, "PARENT_LOW"),
            (0x300_0000_0000, "PARENT_HIGH"), (0x8000_0000_0000_0000, "PARENT_SIGN"),
        ]);
        let partial = types.get_type_partial_enum(parent.clone(), 4, 4).unwrap();
        let declarations = render_type_definitions(&[parent], RealTypeCtx::OFF);
        let mut checks = String::new();
        for value in [0xffff_fffe, 0, 0x300, 0x8000_0000] {
            let mut print = PrintC::new();
            print.set_output_stream();
            print.push_enum_constant_ir(&partial, value, OpId::default(), VarnodeId::default());
            let expression = print.emit_mut().output_str();
            checks.push_str(&format!(
                "assert(({expression}) == {value}ULL);\n\
                 assert(!(({expression}) < (int64_t)-1));\n",
            ));
        }
        let source = format!(
            "#include <assert.h>\n#include <stdint.h>\n\
             typedef uint32_t uint4; typedef uint64_t uint8;\n\
             {declarations}\nint main(void) {{ {checks} return 0; }}\n",
        );
        super::assert_c_source(&source, "partial-enum-upper-bytes");
    }

    #[test]
    fn rust_enum_expression_consumers_preserve_complement_and_partial_width() {
        let types = TypeFactoryImpl::new();
        types.setup_sizes(Some(4), 8, 8);
        types.set_max_basetype_size(8);
        types.set_core_type("unknown1", 1, type_metatype::TYPE_UNKNOWN, false).unwrap();
        types.cache_core_types().unwrap();
        let arch = bare_arch();
        let mut source = String::new();
        let mut checks = String::new();
        for size in [1, 2, 4, 8] {
            for signed in [false, true] {
                let bits = size * 8;
                let name = format!("Flags{bits}{}", if signed { "s" } else { "u" });
                let one = format!("{name}_ONE");
                let two = format!("{name}_TWO");
                let scalar = format!("{}{bits}", if signed { "i" } else { "u" });
                source.push_str(&format!("const {one}: {scalar} = 1;\nconst {two}: {scalar} = 2;\n"));
                let ty = make_enum(&types, &name, size,
                    if signed { type_metatype::TYPE_INT } else { type_metatype::TYPE_UINT },
                    &[(1, &one), (2, &two)]);
                for flag in [1, 3] {
                    let value = kuna_base::address::calc_mask(size) ^ flag;
                    let mut print = execution_printer(&arch, true);
                    print.push_enum_constant_ir(&ty, value, OpId::default(), VarnodeId::default());
                    let expression = print.emit_mut().output_str();
                    let expected = if signed {
                        (value as i128 - (1i128 << bits)).to_string()
                    } else { value.to_string() };
                    checks.push_str(&format!("assert_eq!({expression}, {expected}{scalar});\n"));
                }
            }
        }
        source.push_str("const PARENT_ZERO: i64 = 0;\nconst PARENT_LOW: i64 = 8589934591;\nconst PARENT_HIGH: i64 = 0x30000000000;\nconst PARENT_SIGN: i64 = i64::MIN;\n");
        let parent = make_enum(&types, "Parent", 8, type_metatype::TYPE_INT, &[
            (0, "PARENT_ZERO"), (0x1_ffff_ffff, "PARENT_LOW"),
            (0x300_0000_0000, "PARENT_HIGH"), (0x8000_0000_0000_0000, "PARENT_SIGN"),
        ]);
        let partial = types.get_type_partial_enum(parent, 4, 4).unwrap();
        for value in [0xffff_fffe, 0, 0x300, 0x8000_0000] {
            let mut print = execution_printer(&arch, true);
            print.push_enum_constant_ir(&partial, value, OpId::default(), VarnodeId::default());
            let expression = print.emit_mut().output_str();
            checks.push_str(&format!("assert_eq!({expression}, {value}u32);\n"));
        }
        source.push_str(&format!("fn main() {{ {checks} }}"));
        super::assert_rust_source(&source, "enum-expression-width");
    }

    #[test]
    fn generated_bitfield_alias_preserves_byte_geometry_and_guards() {
        use crate::dtype::TypeBitField;
        let types = TypeFactoryImpl::new();
        types.setup_sizes(Some(4), 8, 8);
        types.set_max_basetype_size(8);
        let byte = named(&types, 1, type_metatype::TYPE_UINT, "uint1");
        let shell = types.get_type_struct("Bits").unwrap();
        let record = types.set_fields_struct_raw(&shell,
            vec![
                TypeField::new(0, 0, "before", byte.clone()),
                TypeField::new(2, 3, "after", byte.clone()),
            ],
            vec![
                TypeBitField {
                    name: "low".into(), field_type: byte.clone(), byte_offset: 1,
                    byte_size: 1, least_sig_bit: 0, num_bits: 3, is_big_endian: false, ident: 1,
                },
                TypeBitField {
                    name: "high".into(), field_type: byte, byte_offset: 1,
                    byte_size: 1, least_sig_bit: 5, num_bits: 3, is_big_endian: false, ident: 2,
                },
            ], 4, 1, flags::has_bitfields).unwrap();
        let alias = types.get_typedef(&record, "BitsAlias", Datatype::hash_name("BitsAlias"), 0).unwrap();
        let declarations = render_type_definitions(&[record, alias], RealTypeCtx::OFF);
        let source = format!(r#"
#include <assert.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
typedef uint8_t uint1;
typedef uint8_t undefined1;
{declarations}
_Static_assert(sizeof(BitsAlias) == 4, "bitfield record extent");
_Static_assert(offsetof(BitsAlias, before) == 0, "leading byte");
_Static_assert(offsetof(BitsAlias, after) == 3, "trailing byte");
int main(void) {{
    BitsAlias value;
    unsigned char bytes[4];
    memset(&value, 0xa5, sizeof(value));
    value.before = 0x11; value.after = 0x77;
    value.low = 6; value.high = 3;
    memcpy(bytes, &value, sizeof(bytes));
    assert(bytes[0] == 0x11 && bytes[1] == 0x66 && bytes[2] == 0xa5 && bytes[3] == 0x77);
    assert(value.low == 6 && value.high == 3);
    return 0;
}}
"#);
        super::assert_c_source(&source, "bitfield-alias");
    }

    #[test]
    fn generated_source_scalar_aliases_preserve_rank_on_lp64_and_llp64() {
        use std::process::Command;
        for (target, long_size) in [
            ("x86_64-unknown-linux-gnu", 8),
            ("x86_64-pc-windows-msvc", 4),
        ] {
            let types = TypeFactoryImpl::new();
            types.setup_sizes(Some(4), 8, 8);
            types.set_max_basetype_size(8);
            let long = named(&types, long_size, type_metatype::TYPE_INT, "long");
            let long_long = named(&types, 8, type_metatype::TYPE_INT, "long long");
            let unsigned = named(&types, long_size, type_metatype::TYPE_UINT, "unsigned long");
            let aliases = [
                types.get_typedef(&long, "SourceLong", Datatype::hash_name("SourceLong"), 0).unwrap(),
                types.get_typedef(&long_long, "SourceLongLong", Datatype::hash_name("SourceLongLong"), 0).unwrap(),
                types.get_typedef(&unsigned, "SourceUnsignedLong", Datatype::hash_name("SourceUnsignedLong"), 0).unwrap(),
            ];
            let declarations = render_type_definitions(&aliases, RealTypeCtx::OFF);
            let source = format!(r#"
{declarations}
_Static_assert(sizeof(SourceLong) == {long_size}, "long model width");
_Static_assert(sizeof(SourceLongLong) == 8, "long long width");
_Static_assert(((SourceLong)-1 < 0), "signed long");
_Static_assert(!((SourceUnsignedLong)-1 < 0), "unsigned long");
_Static_assert(_Generic((SourceLong)0, long: 1, default: 0), "source long rank");
_Static_assert(_Generic((SourceLongLong)0, long long: 1, default: 0), "source long long rank");
_Static_assert(!_Generic((SourceLong)0, long long: 1, default: 0), "equal width is not equal rank");
SourceLong provider(SourceLong x) {{ return x + 1; }}
"#);
            let dir = std::env::temp_dir().join(format!("kuna-source-rank-{}-{target}", std::process::id()));
            std::fs::create_dir_all(&dir).unwrap();
            let input = dir.join("consumer.c");
            std::fs::write(&input, &source).unwrap();
            for optimization in ["0", "2"] {
                let out = Command::new("clang")
                    .args(["-std=c11", "-ffreestanding", "-c"])
                    .arg(format!("--target={target}"))
                    .arg(format!("-O{optimization}"))
                    .arg(&input).arg("-o").arg(dir.join(format!("consumer-{optimization}.o")))
                    .output().expect("target-model compile requires clang");
                assert!(out.status.success(), "{target}/O{optimization}:\n{}\n{source}",
                    String::from_utf8_lossy(&out.stderr));
            }
            std::fs::remove_dir_all(dir).unwrap();
        }
    }

}
