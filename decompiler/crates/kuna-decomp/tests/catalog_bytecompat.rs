//! Catalog completeness and lookup-error contracts.
//!
//! The legacy phase_catalog.json fixture is historical data, not an independent
//! C++ oracle: it was later recaptured from the Rust emitter after prose edits.
//! Check fresh output with the CLI's actual JSON consumer instead of pinning
//! descriptions. Framing, escaping and live values have unit coverage.

use std::collections::BTreeSet;

use kuna_decomp::kuna_phases::{emit_catalog_json, emit_catalog_json_one, lookup_settable};
use kuna_decomp::options::KUNA_OPTION_NAMES;

#[allow(dead_code)]
#[path = "../../kuna-cli/src/jsonfmt.rs"]
mod jsonfmt;

#[test]
fn catalog_has_all_238_settables_with_consumer_fields() {
    let jsonfmt::Json::Array(rows) = jsonfmt::parse(&emit_catalog_json(|_| None))
        .expect("catalog must parse through the CLI consumer") else {
        panic!("catalog must be an array");
    };
    assert_eq!(rows.len(), 238);
    let mut names = BTreeSet::new();
    for row in &rows {
        let jsonfmt::Json::Object(fields) = row else { panic!("catalog row must be an object") };
        let keys: BTreeSet<_> = fields.iter().map(|(key, _)| key.as_str()).collect();
        assert_eq!(keys.len(), fields.len(), "duplicate catalog keys");
        let field = |name: &str| fields.iter().find(|(key, _)| key == name).map(|(_, value)| value);
        let Some(jsonfmt::Json::Str(option)) = field("option") else { panic!("missing option name") };
        assert!(names.insert(option.as_str()), "duplicate option {option}");
        for name in ["default", "phase", "subphase", "strength", "rewind", "issue", "summary",
                     "use_when", "example", "source_decompiler", "inspiration", "change_kind", "tier"] {
            assert!(matches!(field(name), Some(jsonfmt::Json::Str(_))), "{option}: missing string field {name}");
        }
        assert!(matches!(field("destructive_as_default"), Some(jsonfmt::Json::Bool(_))),
            "{option}: missing destructive-default classification");
        for name in ["values", "symptoms"] {
            let Some(jsonfmt::Json::Array(values)) = field(name) else { panic!("{option}: missing array {name}") };
            assert!(values.iter().all(|value| matches!(value, jsonfmt::Json::Str(_))),
                "{option}: {name} must contain strings");
        }
    }
    let registered: BTreeSet<_> = KUNA_OPTION_NAMES.iter().copied().collect();
    assert_eq!(names, registered, "catalog and registered options disagree");
}

#[test]
fn unknown_single_settable_is_none() {
    assert!(emit_catalog_json_one("not-a-real-option", None).is_none());
    assert!(lookup_settable("not-a-real-option").is_none());
}
