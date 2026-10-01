//! Port of the C++ unit tests in `decompiler/unittests/testfloatemu.cc`.
//!
//! The arithmetic cases retain the C++ assertions and constants. Decimal
//! printing instead checks target-value preservation, not host-specific
//! stream spellings. The C++ TEST names (e.g.
//! `float_opNan`) are kept exactly for the port-audit gate, hence the
//! file-level `non_snake_case` allow.
//!
//! Scaffolding mapping (testfloatemu.cc:38-116):
//! - `floatFromRawBits`/`floatToRawBits`/`doubleFromRawBits`/`doubleToRawBits`
//!   (4/8-byte `memcpy` on the little-endian host) become
//!   `from_bits`/`to_bits` helpers.
//! - The `ASSERT_FLOAT_ENCODING`/`ASSERT_DOUBLE_ENCODING` macros become
//!   `assert_float_encoding`/`assert_double_encoding` fns taking `f64`: every
//!   C++ call site's argument is, or is promoted to, `double` at
//!   `format.getEncoding(f)`, and the float macro's `floatToRawBits(f)`
//!   narrows to `float` exactly as the C++ implicit conversion does.
//! - The file-static `float_test_values`/`int_test_values` vectors become
//!   fixture fns returning arrays (same values, same order).
//! - `std::numeric_limits` constants: `denorm_min()` and `quiet_NaN()` are
//!   pinned by bit pattern (the x86 host values the C++ oracle computes
//!   with); `min()`/`max()`/`infinity()` map to
//!   `MIN_POSITIVE`/`MAX`/`INFINITY`.
//!
//! Non-NaN results retain the C++ tests' native floating-point references.
//! NaN results use literal bits for the pinned-oracle compatibility policy,
//! not Rust's unspecified arithmetic or cast NaN signs.

#![allow(non_snake_case)] // C++ TEST(name) fn names are preserved exactly

use kuna_num::float::FloatFormat;

// utility functions (testfloatemu.cc:39-61)

/// C++ `floatFromRawBits(uintb e)`: memcpy of the low 4 bytes of `e` into a
/// float on the little-endian host.
fn float_from_raw_bits(e: u64) -> f32 {
    // truncation to the low 32 bits is exactly the C++ 4-byte memcpy
    f32::from_bits(e as u32)
}

/// C++ `floatToRawBits(float f)`: memcpy of the 4 float bytes into a zeroed
/// uintb on the little-endian host.
fn float_to_raw_bits(f: f32) -> u64 {
    u64::from(f.to_bits())
}

/// C++ `doubleFromRawBits(uintb e)`.
fn double_from_raw_bits(e: u64) -> f64 {
    f64::from_bits(e)
}

/// C++ `doubleToRawBits(double f)`.
fn double_to_raw_bits(f: f64) -> u64 {
    f.to_bits()
}

/// The fixture's only NaN is positive canonical quiet NaN. Supply explicit
/// host bits rather than depending on Rust's unspecified NaN cast behavior.
fn fixture_host(f: f32) -> f64 {
    match f.to_bits() {
        0x7fc0_0000 => f64::from_bits(0x7ff8_0000_0000_0000),
        _ => f64::from(f),
    }
}

// macros to preserve call site (testfloatemu.cc:64-82); Rust panics carry the
// fixture-fn location, but the assert message still shows both values.

/// C++ `ASSERT_FLOAT_ENCODING(f)`: `f` is `double` at every call site (the
/// `1.234` literals are doubles; the float-typed arguments are promoted at
/// `format.getEncoding(f)`).
fn assert_float_encoding(f: f64) {
    let format = FloatFormat::new(4);

    // C++ floatToRawBits(f) implicitly narrows double -> float
    let true_encoding = if f.is_nan() {
        match f.to_bits() >> 63 {
            0 => 0x7fc0_0000,
            _ => 0xffc0_0000,
        }
    } else {
        float_to_raw_bits(f as f32)
    };
    let encoding = format.get_encoding(f);

    assert_eq!(true_encoding, encoding);
}

/// C++ `ASSERT_DOUBLE_ENCODING(f)`.
fn assert_double_encoding(f: f64) {
    let format = FloatFormat::new(8);

    let true_encoding = if f.is_nan() {
        match f.to_bits() >> 63 {
            0 => 0x7ff8_0000_0000_0000,
            _ => 0xfff8_0000_0000_0000,
        }
    } else {
        double_to_raw_bits(f)
    };
    let encoding = format.get_encoding(f);

    assert_eq!(true_encoding, encoding);
}

// FloatFormat tests (C++ `////` section divider; clippy four_forward_slashes)

/// `std::numeric_limits<float>::denorm_min()`: smallest positive subnormal,
/// 2^-149.
const FLOAT_DENORM_MIN: f32 = f32::from_bits(1);
/// `std::numeric_limits<double>::denorm_min()`: smallest positive subnormal,
/// 2^-1074.
const DOUBLE_DENORM_MIN: f64 = f64::from_bits(1);
/// `std::numeric_limits<float>::quiet_NaN()` as the x86 host encodes it.
const FLOAT_QNAN: f32 = f32::from_bits(0x7fc0_0000);
/// `std::numeric_limits<double>::quiet_NaN()` as the x86 host encodes it.
const DOUBLE_QNAN: f64 = f64::from_bits(0x7ff8_0000_0000_0000);

/// C++ file-static `float_test_values` (testfloatemu.cc:86-112).  The
/// `min() +/- denorm_min()` arithmetic is exact (one-ulp steps off the
/// smallest normal), identical to the C++ constant folding.
fn float_test_values() -> [f32; 18] {
    [
        -0.0f32,
        0.0f32,
        -1.0,
        1.0,
        -1.234,
        1.234,
        -FLOAT_DENORM_MIN,
        FLOAT_DENORM_MIN,
        f32::MIN_POSITIVE - FLOAT_DENORM_MIN,
        f32::MIN_POSITIVE,
        f32::MIN_POSITIVE + FLOAT_DENORM_MIN,
        -f32::MIN_POSITIVE + FLOAT_DENORM_MIN,
        -f32::MIN_POSITIVE,
        -f32::MIN_POSITIVE - FLOAT_DENORM_MIN,
        f32::MAX,
        FLOAT_QNAN,
        -f32::INFINITY,
        f32::INFINITY,
    ]
}

/// C++ file-static `int_test_values` (testfloatemu.cc:114-116).
fn int_test_values() -> [i32; 7] {
    [0, -1, 1, 1234, -1234, i32::MIN, i32::MAX]
}

#[test]
fn float_encoding_normal() {
    assert_float_encoding(1.234);
    assert_float_encoding(-1.234);
}

#[test]
fn double_encoding_normal() {
    assert_double_encoding(1.234);
    assert_double_encoding(-1.234);
}

#[test]
fn float_encoding_nan() {
    assert_float_encoding(f64::from_bits(0x7ff8_0000_0000_0000));
    assert_float_encoding(f64::from_bits(0xfff8_0000_0000_0000));
}

#[test]
fn double_encoding_nan() {
    assert_double_encoding(DOUBLE_QNAN);
    assert_double_encoding(f64::from_bits(0xfff8_0000_0000_0000));
}

#[test]
fn float_encoding_subnormal() {
    assert_float_encoding(f64::from(FLOAT_DENORM_MIN));
    assert_float_encoding(f64::from(-FLOAT_DENORM_MIN));
}

#[test]
fn double_encoding_subnormal() {
    assert_double_encoding(DOUBLE_DENORM_MIN);
    assert_double_encoding(-DOUBLE_DENORM_MIN);
}

#[test]
fn float_encoding_min_normal() {
    assert_float_encoding(f64::from(f32::MIN_POSITIVE));
    assert_float_encoding(f64::from(-f32::MIN_POSITIVE));
}

#[test]
fn double_encoding_min_normal() {
    assert_double_encoding(f64::MIN_POSITIVE);
    assert_double_encoding(-f64::MIN_POSITIVE);
}

#[test]
fn float_encoding_infinity() {
    assert_float_encoding(f64::from(f32::INFINITY));
    assert_float_encoding(f64::from(-f32::INFINITY));
}

#[test]
fn double_encoding_infinity() {
    assert_double_encoding(f64::INFINITY);
    assert_double_encoding(-f64::INFINITY);
}

#[test]
fn float_decimal_precision() {
    let ff = FloatFormat::new(4);
    for magnitude in [
        0, 1, 0x007fffff, 0x00800000, 0x00800001, 0x7f7ffffe, 0x7f7fffff,
        0x34000001, 0x34800000, 0x3eaaaaab, 0x3e800000, 0x3de3ee46,
    ] {
        for sign in [0, 0x80000000] {
            let bits = magnitude | sign;
            for scientific in [false, true] {
                let text = ff.print_decimal(f64::from(f32::from_bits(bits)), scientific);
                assert_eq!(text.parse::<f32>().unwrap().to_bits(), bits, "{bits:08x}: {text}");
            }
        }
    }
}

#[test]
fn double_decimal_precision() {
    let ff = FloatFormat::new(8);
    for magnitude in [
        0, 1, 0x000fffffffffffff, 0x0010000000000000, 0x0010000000000001,
        0x7feffffffffffffe, 0x7fefffffffffffff, 0x3fc5555555555555,
        0x3fd555555c7dda4b, 0x3fd0000000000000, 0x3fb999999999999a, 0x3fbf7ced916872b0,
    ] {
        for sign in [0, 0x8000000000000000] {
            let bits = magnitude | sign;
            for scientific in [false, true] {
                let text = ff.print_decimal(f64::from_bits(bits), scientific);
                assert_eq!(text.parse::<f64>().unwrap().to_bits(), bits, "{bits:016x}: {text}");
            }
        }
    }
}

#[test]
fn float_midpoint_rounding() {
    let ff = FloatFormat::new(4);
    // IEEE754 recommends "round to nearest even" for binary formats, like single and double
    // precision floating point.  It rounds to the nearest integer (significand) when unambiguous,
    // and to the nearest even on the midpoint.

    // There are 52 bits of significand in a double and 23 in a float.
    // Below we construct a sequence of double precision values to demonstrate each case
    // in rounding,

    // 		d0 - zeros in low 29 bits, round down
    // 		d1 - on the rounding midpoint with integer even integer part, round down
    //      d2 - just above the midpoint, round up
    let d0 = double_from_raw_bits(0x4010000000000000);
    let d1 = double_from_raw_bits(0x4010000010000000);
    let d2 = double_from_raw_bits(0x4010000010000001);

    // 		d3 - zeros in low 29 bits, round down
    // 		d4 - on the rounding midpoint with integer part odd, round up
    //      d5 - just above the midpoint, round up
    let d3 = double_from_raw_bits(0x4010000020000000);
    let d4 = double_from_raw_bits(0x4010000030000000);
    let d5 = double_from_raw_bits(0x4010000030000001);

    // C++ (float)d: double -> float narrowing, round-to-nearest-even
    let f0 = d0 as f32;
    let f1 = d1 as f32;
    let f2 = d2 as f32;
    let f3 = d3 as f32;
    let f4 = d4 as f32;
    let f5 = d5 as f32;

    let e0 = ff.get_encoding(d0);
    let e1 = ff.get_encoding(d1);
    let e2 = ff.get_encoding(d2);
    let e3 = ff.get_encoding(d3);
    let e4 = ff.get_encoding(d4);
    let e5 = ff.get_encoding(d5);

    assert_eq!(float_to_raw_bits(f0), e0);
    assert_eq!(float_to_raw_bits(f1), e1);
    assert_eq!(float_to_raw_bits(f2), e2);
    assert_eq!(float_to_raw_bits(f3), e3);
    assert_eq!(float_to_raw_bits(f4), e4);
    assert_eq!(float_to_raw_bits(f5), e5);

    assert_eq!(e0, e1);
    assert_ne!(e1, e2);

    assert_ne!(e3, e4);
    assert_eq!(e4, e5);
}

// op tests

// generated

#[test]
fn float_opNan() {
    let format = FloatFormat::new(4);

    for f in float_test_values() {
        let true_result = u64::from(f.is_nan()); // C++ bool -> uintb
        let encoding = format.get_encoding(fixture_host(f));
        let result = format.op_nan(encoding);

        assert_eq!(true_result, result);
    }
}

#[test]
fn float_opNeg() {
    let format = FloatFormat::new(4);

    for f in float_test_values() {
        let true_result = if f.is_nan() {
            0xffc0_0000
        } else {
            float_to_raw_bits(-f)
        };
        let encoding = format.get_encoding(fixture_host(f));
        let result = format.op_neg(encoding);

        assert_eq!(true_result, result);
    }
}

#[test]
fn float_opAbs() {
    let format = FloatFormat::new(4);

    for f in float_test_values() {
        let true_result = if f.is_nan() {
            0x7fc0_0000
        } else {
            float_to_raw_bits(f.abs())
        };
        let encoding = format.get_encoding(fixture_host(f));
        let result = format.op_abs(encoding);

        assert_eq!(true_result, result);
    }
}

#[test]
fn float_opSqrt() {
    let format = FloatFormat::new(4);

    for f in float_test_values() {
        let true_result = if f.is_nan() {
            0x7fc0_0000
        } else if f < 0.0 {
            0xffc0_0000
        } else {
            float_to_raw_bits(f.sqrt())
        };
        let encoding = format.get_encoding(fixture_host(f));
        let result = format.op_sqrt(encoding);

        assert_eq!(true_result, result);
    }
}

#[test]
fn float_opCeil() {
    let format = FloatFormat::new(4);

    for f in float_test_values() {
        let true_result = if f.is_nan() {
            0x7fc0_0000
        } else {
            float_to_raw_bits(f.ceil())
        };
        let encoding = format.get_encoding(fixture_host(f));
        let result = format.op_ceil(encoding);

        assert_eq!(true_result, result);
    }
}

#[test]
fn float_opFloor() {
    let format = FloatFormat::new(4);

    for f in float_test_values() {
        let true_result = if f.is_nan() {
            0x7fc0_0000
        } else {
            float_to_raw_bits(f.floor())
        };
        let encoding = format.get_encoding(fixture_host(f));
        let result = format.op_floor(encoding);

        assert_eq!(true_result, result);
    }
}

#[test]
fn float_opRound() {
    let format = FloatFormat::new(4);

    for f in float_test_values() {
        // C++ std::round(float): round half away from zero, same as f32::round
        let true_result = if f.is_nan() {
            0x7fc0_0000
        } else {
            float_to_raw_bits(f.round())
        };
        let encoding = format.get_encoding(fixture_host(f));
        let result = format.op_round(encoding);

        assert_eq!(true_result, result);
    }
}

#[test]
fn float_opInt2Float_size4() {
    let format = FloatFormat::new(4);

    for i in int_test_values() {
        // C++ (float)i: int -> float, round-to-nearest (i32::MAX rounds up)
        let true_result = float_to_raw_bits(i as f32);
        // C++ implicitly converts the int argument to uintb (modular
        // reduction == sign extension through i64)
        let result = format.op_int2float(i as i64 as u64, 4);

        assert_eq!(true_result, result);
    }
}
// TODO other sized ints

#[test]
fn float_to_double_opFloat2Float() {
    let format = FloatFormat::new(4);
    let format8 = FloatFormat::new(8);

    for f in float_test_values() {
        // C++ (double)f: exact float -> double promotion
        let true_result = if f.is_nan() {
            0x7ff8_0000_0000_0000
        } else {
            double_to_raw_bits(f64::from(f))
        };
        let encoding = format.get_encoding(fixture_host(f));
        let result = format.op_float2float(encoding, &format8);

        assert_eq!(true_result, result);
    }
}

//  TODO float2float going the other direction, double_to_float_opFloat2Float

/// The C++ test's `(int64_t)f` cast as the oracle's x86 host performs it
/// (`cvttss2si`): truncation toward zero; NaN, infinities, and values whose
/// truncation falls outside the int64 range all produce `i64::MIN`.  Rust's
/// saturating `as` differs on exactly those cells (NaN -> 0, +inf/overflow ->
/// `i64::MAX`), which would change which test values the C++ range guard
/// skips.
#[allow(clippy::manual_range_contains)] // explicit asymmetric overflow bounds
fn host_float_to_int64(f: f32) -> i64 {
    if f.is_nan() {
        return i64::MIN;
    }
    // 2^63 is exactly representable as f32; anything >= it, or below -2^63,
    // is out of range (-2^63 itself converts exactly to i64::MIN).
    if f >= 9_223_372_036_854_775_808.0_f32 || f < -9_223_372_036_854_775_808.0_f32 {
        return i64::MIN;
    }
    f as i64 // in range: `as` truncates toward zero, same as cvttss2si
}

#[test]
fn float_opTrunc_to_int() {
    let format = FloatFormat::new(4);
    let _format8 = FloatFormat::new(8); // C++ declares format8 unused here

    for f in float_test_values() {
        // avoid undefined behavior
        // (the C++ `(int64_t)f` guard with host x86 cast semantics; see
        // host_float_to_int64)
        let host_i64 = host_float_to_int64(f);
        if host_i64 > i64::from(i32::MAX) || host_i64 < i64::from(i32::MIN) {
            continue;
        }
        // C++ ((uintb)(int32_t)f) & 0xffffffff: the guard above ensures f is
        // in int32 range, so `as i32` (truncate toward zero) matches the C++
        // host cast; int32_t -> uintb sign-extends, hence `as i64 as u64`.
        let true_result = (f as i32 as i64 as u64) & 0xffffffff;
        let encoding = format.get_encoding(fixture_host(f));
        let result = format.op_trunc(encoding, 4);

        assert_eq!(true_result, result);
    }
}

// TODO trunc to other sizes

#[test]
fn float_opEqual() {
    let format = FloatFormat::new(4);

    for f1 in float_test_values() {
        let encoding1 = format.get_encoding(fixture_host(f1));
        for f2 in float_test_values() {
            let true_result = u64::from(f1 == f2); // C++ bool -> uintb
            let encoding2 = format.get_encoding(fixture_host(f2));
            let result = format.op_equal(encoding1, encoding2);

            assert_eq!(true_result, result);
        }
    }
}

#[test]
fn float_opNotEqual() {
    let format = FloatFormat::new(4);

    for f1 in float_test_values() {
        let encoding1 = format.get_encoding(fixture_host(f1));
        for f2 in float_test_values() {
            let true_result = u64::from(f1 != f2); // C++ bool -> uintb
            let encoding2 = format.get_encoding(fixture_host(f2));
            let result = format.op_not_equal(encoding1, encoding2);

            assert_eq!(true_result, result);
        }
    }
}

#[test]
fn float_opLess() {
    let format = FloatFormat::new(4);

    for f1 in float_test_values() {
        let encoding1 = format.get_encoding(fixture_host(f1));
        for f2 in float_test_values() {
            let true_result = u64::from(f1 < f2); // C++ bool -> uintb
            let encoding2 = format.get_encoding(fixture_host(f2));
            let result = format.op_less(encoding1, encoding2);

            assert_eq!(true_result, result);
        }
    }
}

#[test]
fn float_opLessEqual() {
    let format = FloatFormat::new(4);

    for f1 in float_test_values() {
        let encoding1 = format.get_encoding(fixture_host(f1));
        for f2 in float_test_values() {
            let true_result = u64::from(f1 <= f2); // C++ bool -> uintb
            let encoding2 = format.get_encoding(fixture_host(f2));
            let result = format.op_less_equal(encoding1, encoding2);

            assert_eq!(true_result, result);
        }
    }
}

#[test]
fn float_opAdd() {
    let format = FloatFormat::new(4);

    for f1 in float_test_values() {
        let encoding1 = format.get_encoding(fixture_host(f1));
        for f2 in float_test_values() {
            let true_result = if f1.is_nan() || f2.is_nan() {
                0x7fc0_0000
            } else if f1.is_infinite() && f2 == -f1 {
                0xffc0_0000
            } else {
                float_to_raw_bits(f1 + f2)
            };
            let encoding2 = format.get_encoding(fixture_host(f2));
            let result = format.op_add(encoding1, encoding2);

            assert_eq!(true_result, result);
        }
    }
}

#[test]
fn float_opDiv() {
    let format = FloatFormat::new(4);

    for f1 in float_test_values() {
        let encoding1 = format.get_encoding(fixture_host(f1));
        for f2 in float_test_values() {
            let true_result = if f1.is_nan() || f2.is_nan() {
                0x7fc0_0000
            } else if (f1 == 0.0 && f2 == 0.0) || (f1.is_infinite() && f2.is_infinite()) {
                0xffc0_0000
            } else {
                float_to_raw_bits(f1 / f2)
            };
            let encoding2 = format.get_encoding(fixture_host(f2));
            let result = format.op_div(encoding1, encoding2);

            assert_eq!(true_result, result);
        }
    }
}

#[test]
fn float_opMult() {
    let format = FloatFormat::new(4);

    for f1 in float_test_values() {
        let encoding1 = format.get_encoding(fixture_host(f1));
        for f2 in float_test_values() {
            let true_result = if f1.is_nan() || f2.is_nan() {
                0x7fc0_0000
            } else if (f1 == 0.0 && f2.is_infinite()) || (f1.is_infinite() && f2 == 0.0) {
                0xffc0_0000
            } else {
                float_to_raw_bits(f1 * f2)
            };
            let encoding2 = format.get_encoding(fixture_host(f2));
            let result = format.op_mult(encoding1, encoding2);

            assert_eq!(true_result, result);
        }
    }
}

#[test]
fn float_opSub() {
    let format = FloatFormat::new(4);

    for f1 in float_test_values() {
        let encoding1 = format.get_encoding(fixture_host(f1));
        for f2 in float_test_values() {
            let true_result = if f1.is_nan() || f2.is_nan() {
                0x7fc0_0000
            } else if f1.is_infinite() && f1 == f2 {
                0xffc0_0000
            } else {
                float_to_raw_bits(f1 - f2)
            };
            let encoding2 = format.get_encoding(fixture_host(f2));
            let result = format.op_sub(encoding1, encoding2);

            assert_eq!(true_result, result);
        }
    }
}

// end generated
