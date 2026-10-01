//! Literal behavioral expectations for portable pinned-oracle NaN compatibility.
//! These cases extend, rather than replace or regenerate, the golden vectors.

use kuna_num::float::FloatFormat;

#[test]
fn binary_nan_sign_comes_from_first_encoded_nan() {
    // One/two NaNs, both operand orders, quiet/signaling and distinct payloads.
    // Expected bits are independent literals, never host arithmetic results.
    for (size, a, b, expected) in [
        (4, 0x7fc0_1234, 0x3f80_0000, 0x7fc0_0000),
        (4, 0x3f80_0000, 0x7fc0_1234, 0x7fc0_0000),
        (4, 0xffc0_4321, 0x3f80_0000, 0xffc0_0000),
        (4, 0x3f80_0000, 0xffc0_4321, 0xffc0_0000),
        (4, 0x7f80_0042, 0xff80_0000, 0x7fc0_0000),
        (4, 0xff80_0000, 0x7f80_0042, 0x7fc0_0000),
        (4, 0xff80_0021, 0x0000_0000, 0xffc0_0000),
        (4, 0x0000_0000, 0xff80_0021, 0xffc0_0000),
        (4, 0x7fc0_1234, 0xffc0_4321, 0x7fc0_0000),
        (4, 0xffc0_4321, 0x7fc0_1234, 0xffc0_0000),
        (4, 0x7f80_0042, 0xffc0_4321, 0x7fc0_0000),
        (4, 0xffc0_4321, 0x7f80_0042, 0xffc0_0000),
        (4, 0xff80_0021, 0x7fc0_1234, 0xffc0_0000),
        (4, 0x7fc0_1234, 0xff80_0021, 0x7fc0_0000),
        (4, 0x7f80_0042, 0xff80_0021, 0x7fc0_0000),
        (4, 0xff80_0021, 0x7f80_0042, 0xffc0_0000),
        (8, 0x7ff8_1234_5678_9abc, 0x3ff0_0000_0000_0000, 0x7ff8_0000_0000_0000),
        (8, 0x3ff0_0000_0000_0000, 0x7ff8_1234_5678_9abc, 0x7ff8_0000_0000_0000),
        (8, 0xfff8_4321_abcd_1234, 0x3ff0_0000_0000_0000, 0xfff8_0000_0000_0000),
        (8, 0x3ff0_0000_0000_0000, 0xfff8_4321_abcd_1234, 0xfff8_0000_0000_0000),
        (8, 0x7ff0_0000_0000_0042, 0xfff0_0000_0000_0000, 0x7ff8_0000_0000_0000),
        (8, 0xfff0_0000_0000_0000, 0x7ff0_0000_0000_0042, 0x7ff8_0000_0000_0000),
        (8, 0xfff0_0000_0000_0021, 0x0000_0000_0000_0000, 0xfff8_0000_0000_0000),
        (8, 0x0000_0000_0000_0000, 0xfff0_0000_0000_0021, 0xfff8_0000_0000_0000),
        (8, 0x7ff8_1234_5678_9abc, 0xfff8_4321_abcd_1234, 0x7ff8_0000_0000_0000),
        (8, 0xfff8_4321_abcd_1234, 0x7ff8_1234_5678_9abc, 0xfff8_0000_0000_0000),
        (8, 0x7ff0_0000_0000_0042, 0xfff8_4321_abcd_1234, 0x7ff8_0000_0000_0000),
        (8, 0xfff8_4321_abcd_1234, 0x7ff0_0000_0000_0042, 0xfff8_0000_0000_0000),
        (8, 0xfff0_0000_0000_0021, 0x7ff8_1234_5678_9abc, 0xfff8_0000_0000_0000),
        (8, 0x7ff8_1234_5678_9abc, 0xfff0_0000_0000_0021, 0x7ff8_0000_0000_0000),
        (8, 0x7ff0_0000_0000_0042, 0xfff0_0000_0000_0021, 0x7ff8_0000_0000_0000),
        (8, 0xfff0_0000_0000_0021, 0x7ff0_0000_0000_0042, 0xfff8_0000_0000_0000),
    ] {
        let fmt = FloatFormat::new(size);
        for (op, actual) in [
            ("add", fmt.op_add(a, b)),
            ("sub", fmt.op_sub(a, b)),
            ("mult", fmt.op_mult(a, b)),
            ("div", fmt.op_div(a, b)),
        ] {
            assert_eq!(actual, expected, "{op} size={size} a={a:#x} b={b:#x}");
        }
    }
}

#[test]
fn unary_nan_sign_rules_canonicalize_every_payload() {
    for (size, input, preserved, negated, absolute) in [
        (4, 0x7fc0_1234, 0x7fc0_0000, 0xffc0_0000, 0x7fc0_0000),
        (4, 0xffc0_4321, 0xffc0_0000, 0x7fc0_0000, 0x7fc0_0000),
        (4, 0x7f80_0042, 0x7fc0_0000, 0xffc0_0000, 0x7fc0_0000),
        (4, 0xff80_0021, 0xffc0_0000, 0x7fc0_0000, 0x7fc0_0000),
        (8, 0x7ff8_1234_5678_9abc, 0x7ff8_0000_0000_0000, 0xfff8_0000_0000_0000, 0x7ff8_0000_0000_0000),
        (8, 0xfff8_4321_abcd_1234, 0xfff8_0000_0000_0000, 0x7ff8_0000_0000_0000, 0x7ff8_0000_0000_0000),
        (8, 0x7ff0_0000_0000_0042, 0x7ff8_0000_0000_0000, 0xfff8_0000_0000_0000, 0x7ff8_0000_0000_0000),
        (8, 0xfff0_0000_0000_0021, 0xfff8_0000_0000_0000, 0x7ff8_0000_0000_0000, 0x7ff8_0000_0000_0000),
    ] {
        let fmt = FloatFormat::new(size);
        for (op, actual, expected) in [
            ("sqrt", fmt.op_sqrt(input), preserved),
            ("ceil", fmt.op_ceil(input), preserved),
            ("floor", fmt.op_floor(input), preserved),
            ("round", fmt.op_round(input), preserved),
            ("neg", fmt.op_neg(input), negated),
            ("abs", fmt.op_abs(input), absolute),
        ] {
            assert_eq!(actual, expected, "{op} size={size} input={input:#x}");
        }
    }
}

#[test]
fn generated_invalid_and_non_nan_binary_controls() {
    // Expected columns: add, sub, mult, div. Include neighboring infinities,
    // zeros and finite arithmetic so classifying all special values as NaN fails.
    for (size, a, b, expected) in [
        (4, 0x7f80_0000, 0xff80_0000, [0xffc0_0000, 0x7f80_0000, 0xff80_0000, 0xffc0_0000]),
        (4, 0x7f80_0000, 0x7f80_0000, [0x7f80_0000, 0xffc0_0000, 0x7f80_0000, 0xffc0_0000]),
        (4, 0x0000_0000, 0x0000_0000, [0x0000_0000, 0x0000_0000, 0x0000_0000, 0xffc0_0000]),
        (4, 0x0000_0000, 0x7f80_0000, [0x7f80_0000, 0xff80_0000, 0xffc0_0000, 0x0000_0000]),
        (4, 0x3f80_0000, 0x0000_0000, [0x3f80_0000, 0x3f80_0000, 0x0000_0000, 0x7f80_0000]),
        (4, 0x3f80_0000, 0x4000_0000, [0x4040_0000, 0xbf80_0000, 0x4000_0000, 0x3f00_0000]),
        (4, 0x8000_0000, 0x3f80_0000, [0x3f80_0000, 0xbf80_0000, 0x8000_0000, 0x8000_0000]),
        (8, 0x7ff0_0000_0000_0000, 0xfff0_0000_0000_0000, [0xfff8_0000_0000_0000, 0x7ff0_0000_0000_0000, 0xfff0_0000_0000_0000, 0xfff8_0000_0000_0000]),
        (8, 0x7ff0_0000_0000_0000, 0x7ff0_0000_0000_0000, [0x7ff0_0000_0000_0000, 0xfff8_0000_0000_0000, 0x7ff0_0000_0000_0000, 0xfff8_0000_0000_0000]),
        (8, 0x0000_0000_0000_0000, 0x0000_0000_0000_0000, [0x0000_0000_0000_0000, 0x0000_0000_0000_0000, 0x0000_0000_0000_0000, 0xfff8_0000_0000_0000]),
        (8, 0x0000_0000_0000_0000, 0x7ff0_0000_0000_0000, [0x7ff0_0000_0000_0000, 0xfff0_0000_0000_0000, 0xfff8_0000_0000_0000, 0x0000_0000_0000_0000]),
        (8, 0x3ff0_0000_0000_0000, 0x0000_0000_0000_0000, [0x3ff0_0000_0000_0000, 0x3ff0_0000_0000_0000, 0x0000_0000_0000_0000, 0x7ff0_0000_0000_0000]),
        (8, 0x3ff0_0000_0000_0000, 0x4000_0000_0000_0000, [0x4008_0000_0000_0000, 0xbff0_0000_0000_0000, 0x4000_0000_0000_0000, 0x3fe0_0000_0000_0000]),
        (8, 0x8000_0000_0000_0000, 0x3ff0_0000_0000_0000, [0x3ff0_0000_0000_0000, 0xbff0_0000_0000_0000, 0x8000_0000_0000_0000, 0x8000_0000_0000_0000]),
    ] {
        let fmt = FloatFormat::new(size);
        assert_eq!(
            [fmt.op_add(a, b), fmt.op_sub(a, b), fmt.op_mult(a, b), fmt.op_div(a, b)],
            expected,
            "size={size} a={a:#x} b={b:#x} columns=add,sub,mult,div"
        );
    }
}

#[test]
fn unary_invalid_and_non_nan_controls() {
    // Columns: neg, abs, sqrt, ceil, floor, round.
    for (size, input, expected) in [
        (4, 0x8000_0000, [0x0000_0000, 0x0000_0000, 0x8000_0000, 0x8000_0000, 0x8000_0000, 0x8000_0000]),
        (4, 0xbf80_0000, [0x3f80_0000, 0x3f80_0000, 0xffc0_0000, 0xbf80_0000, 0xbf80_0000, 0xbf80_0000]),
        (4, 0x7f80_0000, [0xff80_0000, 0x7f80_0000, 0x7f80_0000, 0x7f80_0000, 0x7f80_0000, 0x7f80_0000]),
        (4, 0xff80_0000, [0x7f80_0000, 0x7f80_0000, 0xffc0_0000, 0xff80_0000, 0xff80_0000, 0xff80_0000]),
        (4, 0x4010_0000, [0xc010_0000, 0x4010_0000, 0x3fc0_0000, 0x4040_0000, 0x4000_0000, 0x4000_0000]),
        (4, 0xc020_0000, [0x4020_0000, 0x4020_0000, 0xffc0_0000, 0xc000_0000, 0xc040_0000, 0xc040_0000]),
        (8, 0x8000_0000_0000_0000, [0x0000_0000_0000_0000, 0x0000_0000_0000_0000, 0x8000_0000_0000_0000, 0x8000_0000_0000_0000, 0x8000_0000_0000_0000, 0x8000_0000_0000_0000]),
        (8, 0xbff0_0000_0000_0000, [0x3ff0_0000_0000_0000, 0x3ff0_0000_0000_0000, 0xfff8_0000_0000_0000, 0xbff0_0000_0000_0000, 0xbff0_0000_0000_0000, 0xbff0_0000_0000_0000]),
        (8, 0x7ff0_0000_0000_0000, [0xfff0_0000_0000_0000, 0x7ff0_0000_0000_0000, 0x7ff0_0000_0000_0000, 0x7ff0_0000_0000_0000, 0x7ff0_0000_0000_0000, 0x7ff0_0000_0000_0000]),
        (8, 0xfff0_0000_0000_0000, [0x7ff0_0000_0000_0000, 0x7ff0_0000_0000_0000, 0xfff8_0000_0000_0000, 0xfff0_0000_0000_0000, 0xfff0_0000_0000_0000, 0xfff0_0000_0000_0000]),
        (8, 0x4002_0000_0000_0000, [0xc002_0000_0000_0000, 0x4002_0000_0000_0000, 0x3ff8_0000_0000_0000, 0x4008_0000_0000_0000, 0x4000_0000_0000_0000, 0x4000_0000_0000_0000]),
        (8, 0xc004_0000_0000_0000, [0x4004_0000_0000_0000, 0x4004_0000_0000_0000, 0xfff8_0000_0000_0000, 0xc000_0000_0000_0000, 0xc008_0000_0000_0000, 0xc008_0000_0000_0000]),
    ] {
        let fmt = FloatFormat::new(size);
        assert_eq!(
            [fmt.op_neg(input), fmt.op_abs(input), fmt.op_sqrt(input),
             fmt.op_ceil(input), fmt.op_floor(input), fmt.op_round(input)],
            expected,
            "size={size} input={input:#x} columns=neg,abs,sqrt,ceil,floor,round"
        );
    }
}

#[test]
fn encoded_nan_conversion_preserves_sign_not_payload() {
    let fmt4 = FloatFormat::new(4);
    let fmt8 = FloatFormat::new(8);
    for (input4, input8, expected4, expected8) in [
        (0x7fc0_1234, 0x7ff8_1234_5678_9abc, 0x7fc0_0000, 0x7ff8_0000_0000_0000),
        (0xffc0_4321, 0xfff8_4321_abcd_1234, 0xffc0_0000, 0xfff8_0000_0000_0000),
        (0x7f80_0042, 0x7ff0_0000_0000_0042, 0x7fc0_0000, 0x7ff8_0000_0000_0000),
        (0xff80_0021, 0xfff0_0000_0000_0021, 0xffc0_0000, 0xfff8_0000_0000_0000),
    ] {
        assert_eq!(fmt4.op_float2float(input4, &fmt8), expected8);
        assert_eq!(fmt8.op_float2float(input8, &fmt4), expected4);
        assert_eq!(fmt4.convert_encoding(input4, &fmt4), expected4);
        assert_eq!(fmt8.convert_encoding(input8, &fmt8), expected8);
    }
}
