//! Verifier adversarial tests for item `w2-harness-floatemu` (round 1).
//!
//! Independent of the ported `testfloatemu.rs`: fixtures and expected
//! values here are re-derived from the C++ source
//! (`decompiler/unittests/testfloatemu.cc`) and from a standalone C++
//! oracle probe of the `(int64_t)float` guard of TEST(float_opTrunc_to_int),
//! NOT from the
//! porter's helper functions.

use kuna_num::float::FloatFormat;

/// The 18 fixture bit patterns of the C++ `float_test_values` vector
/// (testfloatemu.cc:86-112), re-derived independently:
/// -0.0, +0.0, -1.0, +1.0, -1.234f, +1.234f, -denorm_min, +denorm_min,
/// min-denorm (largest subnormal), min, min+denorm, -min+denorm, -min,
/// -min-denorm, FLT_MAX, qNaN, -inf, +inf.
const FIXTURE_BITS: [u32; 18] = [
    0x8000_0000, // -0.0f
    0x0000_0000, // +0.0f
    0xbf80_0000, // -1.0f
    0x3f80_0000, // +1.0f
    0xbf9d_f3b6, // -1.234f
    0x3f9d_f3b6, // +1.234f
    0x8000_0001, // -denorm_min
    0x0000_0001, // +denorm_min
    0x007f_ffff, // min - denorm_min (largest subnormal)
    0x0080_0000, // min (FLT_MIN)
    0x0080_0001, // min + denorm_min
    0x807f_ffff, // -min + denorm_min (one ulp toward zero: -(largest subnormal))
    0x8080_0000, // -min
    0x8080_0001, // -min - denorm_min (one ulp away from zero)
    0x7f7f_ffff, // FLT_MAX
    0x7fc0_0000, // quiet_NaN (x86 host)
    0xff80_0000, // -inf
    0x7f80_0000, // +inf
];

/// Sanity: the bit patterns above really are the C++ constant-folded
/// values (one-ulp steps off FLT_MIN, exact in f32 arithmetic).
#[test]
fn verify_fixture_bits_rederivation() {
    let denorm = f32::from_bits(1);
    assert_eq!((-1.234f32).to_bits(), 0xbf9d_f3b6);
    assert_eq!((f32::MIN_POSITIVE - denorm).to_bits(), 0x007f_ffff);
    assert_eq!((f32::MIN_POSITIVE + denorm).to_bits(), 0x0080_0001);
    assert_eq!((-f32::MIN_POSITIVE + denorm).to_bits(), 0x807f_ffff);
    assert_eq!((-f32::MIN_POSITIVE - denorm).to_bits(), 0x8080_0001);
    assert_eq!(f32::MAX.to_bits(), 0x7f7f_ffff);
}

/// Non-NaN fixture promotion and re-encoding remain bit-exact, including the
/// subnormal boundaries. The NaN fixture uses explicit host bits because
/// Rust's float-to-double cast does not guarantee a NaN sign.
#[test]
fn verify_fixture_encodings_bit_exact() {
    let format = FloatFormat::new(4);
    for bits in FIXTURE_BITS {
        let host = match bits {
            0x7fc0_0000 => f64::from_bits(0x7ff8_0000_0000_0000),
            _ => f64::from(f32::from_bits(bits)),
        };
        let enc = format.get_encoding(host);
        assert_eq!(
            enc,
            u64::from(bits),
            "get_encoding not bit-exact for fixture 0x{bits:08x}"
        );
    }
}

/// Encoding an explicit host NaN preserves its sign and canonicalizes its
/// payload. Use raw f64 inputs: Rust float casts do not preserve NaN signs.
#[test]
fn verify_nan_encoding_preserves_sign_and_canonicalizes_payload() {
    let format4 = FloatFormat::new(4);
    let format8 = FloatFormat::new(8);
    for (bits, expected4, expected8) in [
        (0x7ff8_0000_0000_0000, 0x7fc0_0000, 0x7ff8_0000_0000_0000),
        (0xfff8_0000_0000_0000, 0xffc0_0000, 0xfff8_0000_0000_0000),
        (0x7ff8_1234_5678_9abc, 0x7fc0_0000, 0x7ff8_0000_0000_0000),
        (0xfff8_4321_abcd_1234, 0xffc0_0000, 0xfff8_0000_0000_0000),
        (0x7ff0_0000_0000_0042, 0x7fc0_0000, 0x7ff8_0000_0000_0000),
        (0xfff0_0000_0000_0042, 0xffc0_0000, 0xfff8_0000_0000_0000),
    ] {
        let host = f64::from_bits(bits);
        assert_eq!(format4.get_encoding(host), expected4, "binary32 input {bits:#018x}");
        assert_eq!(format8.get_encoding(host), expected8, "binary64 input {bits:#018x}");
    }
}

/// TEST(float_opTrunc_to_int)'s `(int64_t)f` guard is UB in C++ for NaN /
/// +-inf / FLT_MAX; the oracle host's cvttss2si yields i64::MIN for all
/// four (probe-verified: each prints -9223372036854775808 -> skipped), so
/// the C++ loop skips exactly those 4 of the 18 fixtures.  Re-derive the
/// skip set independently and check op_trunc on every KEPT cell against
/// `((uintb)(int32_t)f) & 0xffffffff` (sign-extension visible in the
/// mask: -1.234 truncates to -1 -> 0xffffffff).
#[test]
fn verify_trunc_guard_skip_set_and_kept_cells() {
    let format = FloatFormat::new(4);
    let skipped: [u32; 4] = [
        0x7f7f_ffff, // FLT_MAX: cvttss2si overflow -> i64::MIN -> skipped
        0x7fc0_0000, // qNaN: cvttss2si invalid -> i64::MIN -> skipped
        0xff80_0000, // -inf
        0x7f80_0000, // +inf
    ];
    let mut kept = 0;
    for bits in FIXTURE_BITS {
        if skipped.contains(&bits) {
            continue;
        }
        kept += 1;
        let f = f32::from_bits(bits);
        // independent expected value: truncate toward zero in f64 (exact
        // for every kept fixture), then C++ int32_t -> uintb sign extension
        let t = f64::from(f).trunc();
        assert!(t >= f64::from(i32::MIN) && t <= f64::from(i32::MAX));
        // cast: t is integral and in i32 range (asserted above)
        let expected = (t as i32 as i64 as u64) & 0xffff_ffff;
        let enc = format.get_encoding(f64::from(f));
        assert_eq!(
            format.op_trunc(enc, 4),
            expected,
            "op_trunc mismatch for fixture 0x{bits:08x}"
        );
    }
    assert_eq!(kept, 14, "C++ guard keeps exactly 14 of the 18 fixtures");
    // the sign-extension cell explicitly: -1.234 -> -1 -> 0xffffffff
    let enc = format.get_encoding(f64::from(f32::from_bits(0xbf9d_f3b6)));
    assert_eq!(format.op_trunc(enc, 4), 0xffff_ffff);
}

