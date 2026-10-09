//! Resolve zero-argument indirect-call targets from the actual CLI SSA listing.
//! This deliberately accepts only storage leaves and COPY/CAST edges.

use std::collections::{BTreeMap, BTreeSet};

pub fn indirect_targets(raw: &str) -> Vec<(u64, char, u64)> {
    let mut definitions = BTreeMap::new();
    let mut calls = Vec::new();
    let mut operations = 0;
    for line in raw.lines() {
        let Some((sequence, operation)) = line.split_once(":\t") else {
            continue;
        };
        let (pc, _) = sequence.split_once(':').expect("raw operation sequence");
        let pc = u64::from_str_radix(pc.trim().strip_prefix("0x").expect("raw PC"), 16)
            .expect("raw PC hexadecimal address");
        operations += 1;
        if let Some((output, input)) = operation.split_once(" = ") {
            assert!(
                !input.starts_with("call"),
                "unexpected value-returning call in void dispatch chain: {line}"
            );
            assert!(
                definitions.insert(output.trim(), input.trim()).is_none(),
                "duplicate SSA definition: {line}"
            );
        } else if let Some(target) = operation.strip_prefix("callind") {
            calls.push((pc, target.trim()));
        } else {
            assert!(
                !operation.starts_with("call"),
                "unexpected direct call in indirect dispatch chain: {line}"
            );
        }
    }
    assert!(
        operations > 0,
        "CLI did not supply the requested raw SSA listing"
    );
    calls
        .into_iter()
        .map(|(pc, mut value)| {
            let mut seen = BTreeSet::new();
            loop {
                assert!(seen.insert(value), "cyclic call-target dataflow at {pc:#x}");
                if let Some(storage) = value.strip_prefix('r').or_else(|| value.strip_prefix('s')) {
                    let (address, version) =
                        storage.split_once('(').expect("versioned storage leaf");
                    let version = version
                        .strip_suffix(')')
                        .expect("storage version terminator");
                    assert!(
                        !version.contains('(') && !version.contains(')'),
                        "unrecognized target operands: {value}"
                    );
                    let address = u64::from_str_radix(
                        address.strip_prefix("0x").expect("storage address"),
                        16,
                    )
                    .expect("hexadecimal storage address");
                    return (pc, value.chars().next().unwrap(), address);
                }
                let rhs = definitions.get(value).unwrap_or_else(|| {
                    panic!("missing call-target definition for {value} at {pc:#x}")
                });
                value = if let Some(cast) = rhs.strip_prefix("(cast)(") {
                    cast.strip_suffix(')').expect("CAST operand terminator")
                } else if (rhs.starts_with('r') || rhs.starts_with('s') || rhs.starts_with('u'))
                    && !rhs.contains(' ')
                {
                    rhs
                } else {
                    panic!("unrecognized call-target dataflow for {value}: {rhs}");
                };
            }
        })
        .collect()
}
