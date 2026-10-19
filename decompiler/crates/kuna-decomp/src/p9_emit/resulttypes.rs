//! Negotiated, invocation-local type identities for enhanced Ghidra results.
//!
//! The ordinary encoders are unchanged. This adapter records only references
//! actually emitted by the syntax tree, measurements and markup. Reservation
//! happens before descent, so recursive records and callable types terminate.

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::rc::Rc;

use kuna_base::error::KunaResult;
use kuna_base::marshal::{AttributeId, ElementId, Encoder, PackedEncode, ATTRIB_ID, ATTRIB_METATYPE, ATTRIB_NAME, ATTRIB_SIZE};
use kuna_base::space::AddrSpace;

use crate::dtype::Datatype;

pub const RESULT_VERSION: u32 = 1;
pub const ATTRIB_KUNA_RESULT_VERSION: AttributeId = AttributeId::new("kuna_result_version", 4003);
pub const ATTRIB_KUNA_LOCAL: AttributeId = AttributeId::new("kuna_local", 4004);
pub const ELEM_KUNA_RESULT: ElementId = ElementId::new("kuna_result", 4000);
pub const ELEM_KUNA_TYPE: ElementId = ElementId::new("kuna_type", 4003);
pub const ELEM_KUNA_DEFINITION: ElementId = ElementId::new("kuna_definition", 4002);

#[derive(Debug)]
struct Entry {
    handle: u64,
    name: String,
    id: u64,
    size: i32,
    meta: String,
    definition: Option<Vec<u8>>,
    markup_root: Option<Rc<Datatype>>,
}

#[derive(Debug, Default)]
pub struct ResultTypeTable {
    keys: BTreeMap<usize, usize>,
    entries: Vec<Entry>,
}

pub type SharedResultTypes = Rc<RefCell<ResultTypeTable>>;

pub fn result_metatype(datatype: &Datatype) -> &'static str {
    use crate::dtype::type_metatype;
    let meta = if datatype.is_enum_type() {
        if datatype.get_metatype() == type_metatype::TYPE_INT {
            type_metatype::TYPE_ENUM_INT
        } else {
            type_metatype::TYPE_ENUM_UINT
        }
    } else {
        datatype.get_metatype()
    };
    crate::dtype::metatype_name(meta)
}

impl ResultTypeTable {
    pub fn shared() -> SharedResultTypes {
        Rc::new(RefCell::new(Self::default()))
    }

    fn reserve(&mut self, key: usize, name: &str, id: u64, size: i32, meta: &str) -> (u64, bool) {
        if let Some(index) = self.keys.get(&key) {
            return (self.entries[*index].handle, false);
        }
        let index = self.entries.len();
        let handle = index as u64 + 1;
        self.keys.insert(key, index);
        self.entries.push(Entry {
            handle, name: name.to_owned(), id, size, meta: meta.to_owned(),
            definition: None, markup_root: None,
        });
        (handle, true)
    }

    /// A markup-only type is held until its description is encoded; source
    /// types retain their managed Java binding and never acquire local handles.
    pub fn markup_handle(&mut self, datatype: &Rc<Datatype>) -> Option<u64> {
        let datatype = if datatype.qualified_base().is_some() {
            Rc::clone(datatype)
        } else {
            Datatype::completed_record(datatype)
        };
        if datatype.is_host_type() {
            return None;
        }
        let meta = result_metatype(&datatype);
        let key = Rc::as_ptr(&datatype) as usize;
        let (handle, fresh) = self.reserve(key, datatype.get_name(), datatype.get_id(), datatype.get_size(), meta);
        if fresh {
            self.entries[handle as usize - 1].markup_root = Some(datatype);
        }
        Some(handle)
    }

    /// Finish markup roots and their transitive dependencies before writing the
    /// prelude. All reservations precede all definitions on the wire.
    fn complete_markup_roots(table: &SharedResultTypes) -> KunaResult<()> {
        let mut index = 0;
        loop {
            let root = {
                let mut types = table.borrow_mut();
                if index == types.entries.len() { break; }
                types.entries[index].markup_root.take()
            };
            if let Some(root) = root {
                let mut bytes = Vec::new();
                let mut packed = PackedEncode::new(&mut bytes);
                let mut local = ResultTypeEncoder::new(&mut packed, table);
                root.encode(&mut local)?;
                table.borrow_mut().entries[index].definition = Some(bytes);
            }
            index += 1;
        }
        Ok(())
    }

    pub fn encode_prelude_packed(table: &SharedResultTypes, output: &mut Vec<u8>) -> KunaResult<()> {
        // Complete descriptions first using the same encoder registration path.
        Self::complete_markup_roots(table)?;
        let mut packed = PackedEncode::new(output);
        packed.open_element(&ELEM_KUNA_RESULT);
        packed.write_unsigned_integer(&ATTRIB_KUNA_RESULT_VERSION, RESULT_VERSION as u64);
        {
            let types = table.borrow();
            for entry in &types.entries {
                packed.open_element(&ELEM_KUNA_TYPE);
                packed.write_unsigned_integer(&ATTRIB_KUNA_LOCAL, entry.handle);
                packed.write_string(&ATTRIB_NAME, entry.name.as_bytes());
                packed.write_unsigned_integer(&ATTRIB_ID, entry.id);
                packed.write_signed_integer(&ATTRIB_SIZE, entry.size as i64);
                packed.write_string(&ATTRIB_METATYPE, entry.meta.as_bytes());
                packed.close_element(&ELEM_KUNA_TYPE);
            }
        }
        for index in 0..table.borrow().entries.len() {
            {
                let mut packed = PackedEncode::new(output);
                packed.open_element(&ELEM_KUNA_DEFINITION);
                packed.write_unsigned_integer(&ATTRIB_KUNA_LOCAL, index as u64 + 1);
            }
            if let Some(definition) = &table.borrow().entries[index].definition {
                output.extend_from_slice(definition);
            }
            PackedEncode::new(output).close_element(&ELEM_KUNA_DEFINITION);
        }
        PackedEncode::new(output).close_element(&ELEM_KUNA_RESULT);
        Ok(())
    }
}

pub struct ResultTypeEncoder<'a> {
    encoder: &'a mut dyn Encoder,
    types: &'a SharedResultTypes,
}

impl<'a> ResultTypeEncoder<'a> {
    pub fn new(encoder: &'a mut dyn Encoder, types: &'a SharedResultTypes) -> Self {
        Self { encoder, types }
    }
}

impl Encoder for ResultTypeEncoder<'_> {
    fn admits_result_types(&self) -> bool { true }

    fn register_result_type(&mut self, key: usize, name: &str, id: u64, size: i32, meta: &str,
        describe: &mut dyn FnMut(&mut dyn Encoder) -> KunaResult<()>) -> KunaResult<Option<u64>> {
        let (handle, fresh) = self.types.borrow_mut().reserve(key, name, id, size, meta);
        if fresh {
            let mut bytes = Vec::new();
            let mut packed = PackedEncode::new(&mut bytes);
            describe(&mut ResultTypeEncoder::new(&mut packed, self.types))?;
            self.types.borrow_mut().entries[handle as usize - 1].definition = Some(bytes);
        }
        Ok(Some(handle))
    }
    fn open_element(&mut self, id: &ElementId) { self.encoder.open_element(id); }
    fn close_element(&mut self, id: &ElementId) { self.encoder.close_element(id); }
    fn write_bool(&mut self, id: &AttributeId, value: bool) { self.encoder.write_bool(id, value); }
    fn write_signed_integer(&mut self, id: &AttributeId, value: i64) { self.encoder.write_signed_integer(id, value); }
    fn write_unsigned_integer(&mut self, id: &AttributeId, value: u64) { self.encoder.write_unsigned_integer(id, value); }
    fn write_string(&mut self, id: &AttributeId, value: &[u8]) { self.encoder.write_string(id, value); }
    fn write_string_indexed(&mut self, id: &AttributeId, index: u32, value: &[u8]) { self.encoder.write_string_indexed(id, index, value); }
    fn write_space(&mut self, id: &AttributeId, space: &AddrSpace) { self.encoder.write_space(id, space); }
}

#[cfg(test)]
#[path = "resulttypes/tests.rs"]
mod tests;
