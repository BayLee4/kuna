//! Complete packed-document comparison, ignoring only syntax pairing identity.

use kuna_base::marshal::packed_format as pf;
use kuna_decomp::prettyprint::ids::{ATTRIB_CLOSE, ATTRIB_OPEN, ELEM_SYNTAX};
use std::collections::BTreeMap;

/// Compare all records exactly except signed syntax OPEN/CLOSE integer encodings.
/// Each document must independently contain unique, balanced, nested pairs.
pub fn assert_eq_modulo_syntax_pair_ids(left: &[u8], right: &[u8]) {
    #[derive(Debug, PartialEq)]
    enum Record<'a> {
        Raw(&'a [u8]),
        Pair(usize),
    }

    fn records(data: &[u8]) -> Vec<Record<'_>> {
        assert!(!data.is_empty() && !data.contains(&0), "empty or NUL-terminated packed document");
        let mut position = 0;
        let mut elements = Vec::new();
        let mut roots = 0;
        let mut attributes_allowed = false;
        let mut opened = BTreeMap::new();
        let mut pairs = Vec::new();
        let mut result = Vec::new();
        while position < data.len() {
            let start = position;
            let header = data[position];
            position += 1;
            let mut id = u32::from(header & pf::ELEMENTID_MASK);
            if header & pf::HEADEREXTEND_MASK != 0 {
                let extension = *data.get(position).expect("truncated extended record ID");
                assert_ne!(extension & pf::RAWDATA_MARKER, 0, "invalid extended record ID");
                id = (id << pf::RAWDATA_BITSPERBYTE) | u32::from(extension & pf::RAWDATA_MASK);
                position += 1;
            }
            assert_ne!(id, 0, "zero record ID");
            match header & pf::HEADER_MASK {
                pf::ELEMENT_START => {
                    if elements.is_empty() { roots += 1; }
                    elements.push(id);
                    attributes_allowed = true;
                }
                pf::ELEMENT_END => {
                    assert_eq!(elements.pop(), Some(id), "unbalanced packed elements");
                    attributes_allowed = false;
                }
                pf::ATTRIBUTE => {
                    assert!(attributes_allowed, "attribute outside element header");
                    let value_start = position;
                    let type_byte = *data.get(position).expect("truncated attribute type");
                    position += 1;
                    let kind = type_byte >> pf::TYPECODE_SHIFT;
                    let length = usize::from(type_byte & pf::LENGTHCODE_MASK);
                    assert!((pf::TYPECODE_BOOLEAN..=pf::TYPECODE_STRING).contains(&kind), "invalid attribute type");
                    let mut value = 0_u64;
                    if kind != pf::TYPECODE_BOOLEAN && kind != pf::TYPECODE_SPECIALSPACE {
                        let digits = data.get(position..position + length).expect("truncated attribute integer");
                        for &digit in digits {
                            assert_ne!(digit & pf::RAWDATA_MARKER, 0, "invalid attribute integer");
                            value = value.checked_mul(128).and_then(|v| v.checked_add(u64::from(digit & pf::RAWDATA_MASK)))
                                .expect("attribute integer overflow");
                        }
                        position += length;
                        if kind == pf::TYPECODE_STRING {
                            let length = usize::try_from(value).expect("string length overflow");
                            position = position.checked_add(length).expect("string length overflow");
                            assert!(position <= data.len(), "truncated attribute string");
                        }
                    } else {
                        assert!(length <= if kind == pf::TYPECODE_BOOLEAN { 1 } else { 4 }, "invalid attribute code");
                    }
                    if elements.last() == Some(&ELEM_SYNTAX.get_id())
                        && (id == ATTRIB_OPEN.get_id() || id == ATTRIB_CLOSE.get_id())
                    {
                        assert!(kind == pf::TYPECODE_SIGNEDINT_POSITIVE || kind == pf::TYPECODE_SIGNEDINT_NEGATIVE,
                            "syntax pair ID must be signed");
                        let pair_id = if kind == pf::TYPECODE_SIGNEDINT_NEGATIVE {
                            assert!(value <= 1_u64 << 63, "signed pair ID overflow");
                            (value as i64).wrapping_neg()
                        } else {
                            i64::try_from(value).expect("signed pair ID overflow")
                        };
                        let ordinal = if id == ATTRIB_OPEN.get_id() {
                            let ordinal = opened.len();
                            assert!(opened.insert(pair_id, ordinal).is_none(), "duplicate syntax opening ID");
                            pairs.push(pair_id);
                            ordinal
                        } else {
                            assert_eq!(pairs.pop(), Some(pair_id), "mismatched syntax closing ID");
                            *opened.get(&pair_id).expect("syntax close without open")
                        };
                        result.push(Record::Raw(&data[start..value_start]));
                        result.push(Record::Pair(ordinal));
                        continue;
                    }
                }
                _ => panic!("invalid packed record header"),
            }
            result.push(Record::Raw(&data[start..position]));
        }
        assert_eq!(roots, 1, "packed document must have one root");
        assert!(elements.is_empty(), "unfinished packed element");
        assert!(pairs.is_empty(), "unfinished syntax pair");
        result
    }

    assert_eq!(records(left), records(right), "packed documents differ beyond syntax pairing IDs");
}
