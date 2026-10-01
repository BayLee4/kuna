//! Verifier adversarial tests for `rport/w10-console-family` (round 1).
//!
//! Focus of this wave: raw console address and sequence-number formatting.
//! These tests pin the *load-bearing, format-sensitive* details the hunt list
//! flagged as most fragile:
//!
//!  * the SeqNum `:uniq` token is emitted in **hex** (the stream-base carry-over
//!    from `Address::printRaw`) — a behavior change to an existing caller
//!    (`IopSpace::printRaw`), so it must be hex for *every* value, not just the
//!    handful in the corpus.
//!
//! Built with public APIs only (no porter notes).

use std::rc::Rc;

use kuna_base::address::{Address, SeqNum};
use kuna_base::space::{addrspace_flags, spacetype, AddrSpace, ConstantSpace};

fn ram() -> Rc<AddrSpace> {
    // wordsize 1 so AddrSpace::printRaw never appends a `+cut` suffix.
    Rc::new(AddrSpace::new(
        spacetype::IPTR_PROCESSOR,
        "ram",
        false,
        8,
        1,
        3,
        addrspace_flags::hasphysical,
        0,
        0,
    ))
}

/// C++ `operator<<(ostream&,const SeqNum&)`: `sq.pc.printRaw(s); s << ':' <<
/// sq.uniq;`.  `Address::printRaw` leaves the stream base in `hex`, so `uniq`
/// is hexadecimal.  This must hold for a `uniq` that actually *differs* between
/// decimal and hex (>= 10), and for the boundary value 0.
#[test]
fn seqnum_uniq_is_hex_not_decimal() {
    let ram = ram();

    // uniq = 0x2a = 42: hex "2a" must NOT render as decimal "42".
    let sq = SeqNum::new(Address::new(Rc::clone(&ram), 0x100017), 0x2a);
    let mut s = String::new();
    sq.print_raw(&mut s).expect("SeqNum::print_raw");
    assert!(
        s.ends_with(":2a"),
        "uniq must be hex (`:2a`), got {s:?} — a decimal `:42` is the LOSS-bug this wave fixed"
    );
    assert!(!s.ends_with(":42"), "uniq rendered in decimal: {s:?}");

    // uniq = 0xff = 255.
    let mut s2 = String::new();
    SeqNum::new(Address::new(Rc::clone(&ram), 0x100020), 0xff)
        .print_raw(&mut s2)
        .expect("SeqNum::print_raw");
    assert!(s2.ends_with(":ff"), "got {s2:?}");

    // uniq = 0: hex and dec agree, but the `:0` separator must still be present.
    let mut s3 = String::new();
    SeqNum::new(Address::new(Rc::clone(&ram), 0x100000), 0)
        .print_raw(&mut s3)
        .expect("SeqNum::print_raw");
    assert!(s3.ends_with(":0"), "got {s3:?}");
    // The address portion itself is always hex with a `0x` prefix.
    assert!(s3.starts_with("0x"), "address not hex-prefixed: {s3:?}");
}

/// A constant-space address (the `#`-shortcut operand) renders `0x<hex>` — the
/// base for the `#0xNN` constant tokens the printRaw listing emits.  Pin that a
/// value >= 10 is hex, never decimal.
#[test]
fn constant_space_address_is_hex() {
    let cst = Rc::new(ConstantSpace::new());
    let mut s = String::new();
    Address::new(cst, 0x64).print_raw(&mut s).expect("const Address::print_raw");
    assert_eq!(s, "0x64", "constant offset 0x64 must be hex, got {s:?}");
}

