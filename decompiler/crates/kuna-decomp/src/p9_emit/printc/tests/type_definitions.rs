use super::support::assert_c_source;
use crate::dtype::{type_metatype, Datatype, TypeFactory, TypeFactoryImpl, TypeField};
use std::rc::Rc;

mod decompile_project_type_render {
    use super::*;
    use crate::dtype::flags;
    use crate::printc::{
        compose_type_body, render_type_definitions,
        RealTypeCtx,
    };
    fn named(types: &TypeFactoryImpl, size: i32, m: type_metatype, nm: &str) -> Rc<Datatype> {
        types.get_base_named(size, m, nm).unwrap()
    }

    fn ptr_to(types: &TypeFactoryImpl, ptrto: Rc<Datatype>) -> Rc<Datatype> {
        types.get_type_pointer(8, ptrto, 1).unwrap()
    }

    fn array_of(types: &TypeFactoryImpl, arrayof: Rc<Datatype>, n: i32) -> Rc<Datatype> {
        types.get_type_array(n, arrayof).unwrap()
    }

    /// A complete named struct with the given (offset, name, type) fields and
    /// total size.
    fn struct_of(types: &TypeFactoryImpl, nm: &str, size: i32, fields: &[(i32, &str, Rc<Datatype>)]) -> Rc<Datatype> {
        let shell = types.get_type_struct(nm).unwrap();
        types.set_fields_struct_raw(&shell, fields.iter().enumerate()
            .map(|(i, (off, fnm, ft))| TypeField::new(i as i32, *off, *fnm, ft.clone()))
            .collect(), vec![], size, 8, 0).unwrap()
    }

    #[test]
    fn named_callable_definitions_preserve_recursive_aliases_and_function_type() {
        use crate::dtype::DatatypeKind;
        use crate::fspec::{FuncProto, ParameterPieces};
        let types = TypeFactoryImpl::new();
        types.set_default_alignment_map();
        types.setup_sizes(Some(4), 8, 8);
        types.set_max_basetype_size(8);
        let integer = named(&types, 8, type_metatype::TYPE_INT, "long long");
        let node = types.kuna_declare_record("Node", false).unwrap();
        let alias = types.get_typedef(&node, "NodeAlias", 0, 0).unwrap();
        let callback = |name: &str, output: Rc<Datatype>, input: Rc<Datatype>| {
            let mut proto = FuncProto::new();
            proto.attach_internal_store(Rc::new(Datatype::new(0, type_metatype::TYPE_VOID)));
            proto.set_output(&ParameterPieces { type_: Some(output), ..Default::default() });
            proto.store_set_input(0, "value", &ParameterPieces {
                type_: Some(input), ..Default::default()
            });
            let mut code = Datatype::new(1, type_metatype::TYPE_CODE);
            code.name = name.into();
            code.display_name = name.into();
            code.id = Datatype::hash_name(name);
            code.kind = DatatypeKind::Code { proto: Some(Rc::new(proto)) };
            Rc::new(code)
        };
        let code = callback("Callback", Rc::clone(&alias), Rc::clone(&alias));
        let pointer = ptr_to(&types, Rc::clone(&code));
        let complete = types.set_fields_struct_raw(&node, vec![
            TypeField::new(0, 0, "value", integer),
            TypeField::new(1, 8, "next", Rc::clone(&pointer)),
        ], Vec::new(), 16, 8, 0).unwrap();
        let code_alias = types.get_typedef(&code, "CallbackAlias", 0, 0).unwrap();
        let pointer_alias = types.get_typedef(&pointer, "CallbackPointer", 0, 0).unwrap();
        let array = types.get_type_array(2, Rc::clone(&complete)).unwrap();
        let array_alias = types.get_typedef(&array, "NodeArray", 0, 0).unwrap();
        let int = named(&types, 4, type_metatype::TYPE_INT, "int");
        let array_code = callback("ArrayCallback", int, Rc::clone(&array_alias));
        for first in [&code, &alias, &complete, &array_code] {
            let declarations = render_type_definitions(&[
                Rc::clone(first), Rc::clone(&code), Rc::clone(&complete), Rc::clone(&alias),
                Rc::clone(&code_alias), Rc::clone(&pointer_alias),
                Rc::clone(&array_alias), Rc::clone(&array_code),
            ], &RealTypeCtx::OFF);
            assert_eq!(declarations.matches("typedef NodeAlias Callback(NodeAlias);").count(), 1);
            assert!(declarations.contains("typedef Callback CallbackAlias;"), "{declarations}");
            assert!(declarations.contains("typedef Callback *CallbackPointer;"), "{declarations}");
            let source = format!(
                "#include <assert.h>\n{declarations}\n\
                 NodeAlias provider(NodeAlias value) {{ value.value += 7; return value; }}\n\
                 int array_provider(NodeArray values) {{ return values[0].value + values[1].value; }}\n\
                 int main(void) {{ NodeAlias value = {{5, provider}};\n\
                     CallbackAlias *call = provider; CallbackPointer pointer = provider;\n\
                     assert(value.next(value).value == 12 && call(value).value == 12);\n\
                     assert(pointer(value).value == 12);\n\
                     NodeArray values = {{{{3, provider}}, {{9, provider}}}};\n\
                     ArrayCallback *array_call = array_provider;\n\
                     assert(array_call(values) == 12); return 0; }}\n"
            );
            super::assert_c_source(&source, &format!("named-callable-{}", first.get_name()));
        }
        assert_eq!(code.get_name(), "Callback");
        assert_eq!(alias.get_name(), "NodeAlias");
        assert!(Rc::ptr_eq(code_alias.get_typedef().unwrap(), &code));
    }

    #[test]
    fn composite_declarations_preserve_layout_and_member_storage() {
        let types = TypeFactoryImpl::new();
        types.setup_sizes(Some(4), 8, 8);
        types.set_max_basetype_size(8);
        let i4 = named(&types, 4, type_metatype::TYPE_INT, "int4");
        let ch = named(&types, 1, type_metatype::TYPE_INT, "char");
        let s = struct_of(&types, "mystruct", 40, &[
            (0, "a", i4.clone()),
            (8, "p", ptr_to(&types, ch)),
            (16, "arr", array_of(&types, i4.clone(), 4)),
        ]);
        let f8 = named(&types, 8, type_metatype::TYPE_FLOAT, "float8");
        let shell = types.get_type_union("myunion").unwrap();
        let u = types.set_fields_union_raw(&shell, vec![
            TypeField::new(0, 0, "as_int", i4.clone()),
            TypeField::new(1, 0, "as_float", f8.clone()),
        ], 8, 8).unwrap();
        let source = format!(
            "#include <stdint.h>\n#include <stddef.h>\n#include <string.h>\n\
             typedef int32_t int4; typedef double float8; typedef uint8_t undefined1;\n{}{}\n{}",
            compose_type_body(&s, "mystruct", &RealTypeCtx::OFF),
            compose_type_body(&u, "myunion", &RealTypeCtx::OFF),
            r#"
_Static_assert(sizeof(struct mystruct) == 40, "struct extent");
_Static_assert(offsetof(struct mystruct, a) == 0, "scalar offset");
_Static_assert(offsetof(struct mystruct, p) == 8, "pointer offset");
_Static_assert(offsetof(struct mystruct, arr) == 16, "array offset");
_Static_assert(sizeof(((struct mystruct *)0)->arr) == 16, "array extent");
_Static_assert(sizeof(union myunion) == 8, "union extent");
_Static_assert(offsetof(union myunion, as_int) == 0, "integer union offset");
_Static_assert(offsetof(union myunion, as_float) == 0, "float union offset");
int main(void) {
    struct mystruct s;
    unsigned char expected[40];
    memset(&s, 0xa5, sizeof(s));
    memset(expected, 0xa5, sizeof(expected));
    int4 a = -739, values[4] = { 219, -415, 831, -991 };
    char text[] = "layout", *pointer = text;
    s.a = a; s.p = pointer;
    for (unsigned i = 0; i < 4; ++i) s.arr[i] = values[i];
    memcpy(expected, &a, sizeof(a));
    memcpy(expected + 8, &pointer, sizeof(pointer));
    memcpy(expected + 16, values, sizeof(values));
    if (memcmp(&s, expected, sizeof(s)) || s.p[2] != 'y' || s.arr[1] != -415) return 1;
    union myunion u;
    memset(&u, 0, sizeof(u));
    u.as_int = a;
    int4 integer;
    memcpy(&integer, &u, sizeof(integer));
    if (integer != a) return 2;
    u.as_float = -17.25;
    double floating;
    memcpy(&floating, &u, sizeof(floating));
    return floating != -17.25;
}
"#,
        );
        super::assert_c_source(&source, "composite-layout");
    }

    #[test]
    fn anonymous_enum_alias_registration_keeps_the_declared_alias_identity() {
        let types = TypeFactoryImpl::new();
        types.setup_sizes(Some(4), 8, 8);
        types.set_max_basetype_size(8);
        let shell = types.reserve_enum("", 0x27, 2, type_metatype::TYPE_ENUM_UINT).unwrap();
        let enumeration = types.set_enum_values(
            &shell, [(1, "ONE".to_string())].into_iter().collect(),
        ).unwrap();
        let first = types.get_typedef(&enumeration, "E2", 0x5b, 0).unwrap();
        let distinct_alias = types.get_typedef(&enumeration, "E2", 0x5c, 0).unwrap();
        let definitions = render_type_definitions(&[first, distinct_alias], &RealTypeCtx::OFF);
        assert!(definitions.contains("/* duplicate type name skipped: E2 */"), "{definitions}");
        assert_eq!(definitions.matches("ONE = ").count(), 1, "{definitions}");
    }

    #[test]
    fn anonymous_enum_reuse_retains_one_body_owner_in_each_emission_order() {
        let types = TypeFactoryImpl::new();
        types.setup_sizes(Some(4), 8, 8);
        types.set_max_basetype_size(8);
        let shell = types.reserve_enum("", 0x27, 2, type_metatype::TYPE_ENUM_UINT).unwrap();
        let enumeration = types.set_enum_values(
            &shell, [(1, "ONE".to_string())].into_iter().collect(),
        ).unwrap();
        let first = types.get_typedef(&enumeration, "E2", 0x5b, 0).unwrap();
        let second = types.get_typedef(&enumeration, "E2Alias", 0x5c, 0).unwrap();
        let third = types.get_typedef(&enumeration, "E2Third", 0x5d, 0).unwrap();
        for order in [[&first, &second, &third], [&second, &third, &first]] {
            let mut text = String::new();
            let forward = std::collections::HashSet::new();
            let mut writer = crate::printc::CTypeDefinitionWriter {
                rt: &RealTypeCtx::OFF, names: None,
                forward: &forward, defined: std::collections::HashMap::new(), out: &mut text,
            };
            for alias in order {
                writer.define(alias);
            }
            assert_eq!(writer.defined.values().filter(|(_, base)| base.is_some()).count(), 1);
            for alias in order {
                let declared = writer.defined.get(alias.get_name()).unwrap();
                assert_eq!(declared.0, Rc::as_ptr(alias) as usize);
            }
            assert!(writer.out.contains(&format!(
                "typedef {} {};", order[0].get_name(), order[2].get_name(),
            )), "{}", writer.out);
            assert_eq!(writer.out.matches("ONE = ").count(), 1);
        }
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
        let declarations = render_type_definitions(&[record, alias], &RealTypeCtx::OFF);
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
            let declarations = render_type_definitions(&aliases, &RealTypeCtx::OFF);
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
