use std::collections::BTreeSet;
use std::process::Command;

use kuna_decomp::options::KUNA_OPTION_NAMES;
use serde::de::{Deserialize, Deserializer, IgnoredAny, MapAccess, Visitor};
use serde_json::value::RawValue;

struct UniqueKeys;
impl<'de> Deserialize<'de> for UniqueKeys {
    fn deserialize<D: Deserializer<'de>>(decoder: D) -> Result<Self, D::Error> {
        struct Keys;
        impl<'de> Visitor<'de> for Keys {
            type Value = UniqueKeys;
            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("catalog object with unique keys")
            }
            fn visit_map<M: MapAccess<'de>>(self, mut map: M) -> Result<UniqueKeys, M::Error> {
                let mut keys = BTreeSet::new();
                while let Some((key, _)) = map.next_entry::<String, IgnoredAny>()? {
                    if !keys.insert(key) {
                        return Err(serde::de::Error::custom("duplicate catalog key"));
                    }
                }
                Ok(UniqueKeys)
            }
        }
        decoder.deserialize_map(Keys)
    }
}

#[test]
fn catalog_json_has_registered_options_and_consumer_fields() {
    let executable = std::env::var_os("KUNA_CLI").unwrap_or_else(|| env!("CARGO_BIN_EXE_kuna").into());
    let output = Command::new(executable).args(["catalog", "--json"]).output().expect("real kuna catalog");
    assert!(output.status.success(), "catalog failed: {}", String::from_utf8_lossy(&output.stderr));
    let rows: Vec<&RawValue> = serde_json::from_slice(&output.stdout).expect("catalog JSON array");
    let mut names = BTreeSet::new();
    for raw in rows {
        serde_json::from_str::<UniqueKeys>(raw.get()).expect("unique catalog object keys");
        let row: serde_json::Value = serde_json::from_str(raw.get()).unwrap();
        let option = row["option"].as_str().expect("option name");
        assert!(names.insert(option.to_owned()), "duplicate option {option}");
        for field in ["default", "phase", "subphase", "strength", "rewind", "issue", "summary", "use_when", "example", "source_decompiler", "inspiration", "change_kind", "tier"] {
            assert!(row[field].is_string(), "{option}: missing string {field}");
        }
        assert!(row["destructive_as_default"].is_boolean(), "{option}: destructive default classification");
        for field in ["values", "symptoms"] {
            let values = row[field].as_array().unwrap_or_else(|| panic!("{option}: missing array {field}"));
            assert!(values.iter().all(serde_json::Value::is_string), "{option}: {field} elements must be strings");
        }
    }
    let registered: BTreeSet<_> = KUNA_OPTION_NAMES.iter().map(|name| (*name).to_owned()).collect();
    assert_eq!(names, registered, "public catalog and registered options disagree");
}
