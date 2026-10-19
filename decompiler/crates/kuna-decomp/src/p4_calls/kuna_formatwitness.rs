//! P4 matching-format evidence for partial call argument recovery.
//!
//! [`kuna_calleearitylive`](crate::p4_calls::kuna_calleearitylive) normally
//! requires the callee body to prove a sibling's longer argument list.  That
//! proof deliberately declines variadic callees, whose register-save prologue
//! reads every argument register.  A stripped `printf` therefore leaves this
//! common shape unresolved:
//!
//! ```text
//! printf("position=(%d,%d)\n", old_x, old_y);
//! state->x = new_x;
//! state->y = new_y;
//! printf("position=(%d,%d)\n", new_x, new_y);
//! ```
//!
//! The stores make `onlyOpUse` reject `new_x` and `new_y`, even though the
//! assembly passes them.  The matching nonzero constant format pointer and its
//! parsed conversion count give the missing discriminator: another finalized
//! call to the same entry with exactly that many arguments is an arity witness.
//! The parser accepts a conservative printf subset and declines positional or
//! malformed formats.
//! Unavailable format bytes provide no optional witness; other acquisition
//! failures retain their error category and stop the caller.

use std::rc::Rc;

use kuna_base::address::Address;
use kuna_base::error::KunaError;
use kuna_base::types::int4;
use kuna_num::opcodes::OpCode;

use crate::context::OpId;
use crate::funcdata::Funcdata;
use crate::p4_calls::kuna_calleearity::witness_storage;

const MAX_FORMAT: usize = 256;

fn constant_pointer(data: &Funcdata, op: OpId) -> kuna_base::error::KunaResult<Option<Address>> {
    let Some(call) = data.obank().get(op) else { return Ok(None) };
    let Some(vn) = call.get_in(1).and_then(|vn| data.vbank().get(vn)) else { return Ok(None) };
    if !vn.is_constant() {
        return Ok(None);
    }
    pointer_target(data, vn.get_offset(), vn.get_size(), call.get_addr())
}

fn pointer_target(data: &Funcdata, value: u64, size: int4, point: &Address) -> kuna_base::error::KunaResult<Option<Address>> {
    if value == 0 {
        return Ok(None);
    }
    let glb = data.get_arch();
    let Some(space) = glb.manage().get_default_data_space().cloned() else { return Ok(None) };
    let mut full_encoding = 0;
    let resolved = glb
        .resolve_constant(&space, value, size, point, &mut full_encoding)?;
    Ok((!resolved.is_invalid()).then_some(resolved))
}

/// How many arguments the printf format that the pointer `value` (a `size`-byte
/// constant used at `point`) addresses consumes, when it reads as one. A string
/// without a `%` consumes none.
pub(crate) fn pointed_format_count(
    data: &Funcdata,
    value: u64,
    size: int4,
    point: &Address,
) -> kuna_base::error::KunaResult<Option<usize>> {
    let Some(addr) = pointer_target(data, value, size, point)? else { return Ok(None) };
    let Some(bytes) = read_format(data, &addr)? else { return Ok(None) };
    if !bytes.contains(&b'%') {
        return Ok(Some(0));
    }
    Ok(printf_argument_count(&bytes))
}

/// A constant format whose complete bytes, including the terminator, are
/// immutable in this image. Positive argument evidence requires immutability.
pub(super) fn pointed_readonly_format(
    data: &Funcdata, value: u64, size: int4, point: &Address,
) -> kuna_base::error::KunaResult<Option<Vec<u8>>> {
    let Some(addr) = pointer_target(data, value, size, point)? else { return Ok(None) };
    let Some(bytes) = read_format(data, &addr)? else { return Ok(None) };
    for offset in 0..=bytes.len() {
        let Some(space) = addr.get_space() else { return Ok(None) };
        let Some(offset) = addr.get_offset().checked_add(offset as u64) else { return Ok(None) };
        let at = Address::new(
            Rc::clone(space), offset,
        );
        let flags = data.get_arch().query_global_range_properties(&at)?;
        if flags & crate::varnode::varnode_flags::readonly == 0 {
            return Ok(None);
        }
    }
    Ok(Some(bytes))
}

fn read_format(data: &Funcdata, addr: &Address) -> kuna_base::error::KunaResult<Option<Vec<u8>>> {
    let mut bytes = Vec::new();
    for offset in 0..MAX_FORMAT {
        let mut byte = [0u8; 1];
        let Some(at_offset) = addr.get_offset().checked_add(offset as u64) else { return Ok(None) };
        let Some(space) = addr.get_space() else { return Ok(None) };
        let at = Address::new(Rc::clone(space), at_offset);
        match data.get_arch().loader_fill(&mut byte, &at) {
            Ok(()) => {}
            Err(KunaError::DataUnavail { .. }) => return Ok(None),
            Err(error) => return Err(error),
        }
        if byte[0] == 0 {
            return Ok((!bytes.is_empty()).then_some(bytes));
        }
        if !(byte[0].is_ascii_graphic() || byte[0].is_ascii_whitespace()) {
            return Ok(None);
        }
        bytes.push(byte[0]);
    }
    Ok(None)
}

fn take_digits(bytes: &[u8], mut i: usize) -> usize {
    while i < bytes.len() && bytes[i].is_ascii_digit() {
        i += 1;
    }
    i
}

pub(crate) fn printf_argument_count(bytes: &[u8]) -> Option<usize> {
    let mut count = 0usize;
    let mut i = 0usize;
    let mut saw_conversion = false;
    while i < bytes.len() {
        if bytes[i] != b'%' {
            i += 1;
            continue;
        }
        i += 1;
        if i >= bytes.len() {
            return None;
        }
        if bytes[i] == b'%' {
            i += 1;
            continue;
        }
        saw_conversion = true;
        while i < bytes.len() && b"#0- +'I".contains(&bytes[i]) {
            i += 1;
        }
        if i < bytes.len() && bytes[i] == b'*' {
            count += 1;
            i += 1;
            let end = take_digits(bytes, i);
            if end < bytes.len() && bytes[end] == b'$' {
                return None;
            }
        } else {
            let end = take_digits(bytes, i);
            if end < bytes.len() && bytes[end] == b'$' {
                return None;
            }
            i = end;
        }
        if i < bytes.len() && bytes[i] == b'.' {
            i += 1;
            if i < bytes.len() && bytes[i] == b'*' {
                count += 1;
                i += 1;
                let end = take_digits(bytes, i);
                if end < bytes.len() && bytes[end] == b'$' {
                    return None;
                }
            } else {
                i = take_digits(bytes, i);
            }
        }
        if i + 1 < bytes.len()
            && ((bytes[i] == b'h' && bytes[i + 1] == b'h')
                || (bytes[i] == b'l' && bytes[i + 1] == b'l'))
        {
            i += 2;
        } else if i < bytes.len() && b"hljztL".contains(&bytes[i]) {
            i += 1;
        }
        let conversion = *bytes.get(i)?;
        i += 1;
        match conversion {
            b'd' | b'i' | b'o' | b'u' | b'x' | b'X' | b'f' | b'F' | b'e' | b'E' | b'g' | b'G'
            | b'a' | b'A' | b'c' | b's' | b'p' | b'n' => count += 1,
            b'm' => {}
            _ => return None,
        }
    }
    saw_conversion.then_some(count)
}

pub(crate) fn best_witness(entry: &Address, op: OpId, data: &Funcdata) -> kuna_base::error::KunaResult<Vec<(Address, int4)>> {
    let Some(format_addr) = constant_pointer(data, op)? else {
        return Ok(Vec::new());
    };
    let Some(format) = read_format(data, &format_addr)? else {
        return Ok(Vec::new());
    };
    let Some(varargs) = printf_argument_count(&format) else {
        return Ok(Vec::new());
    };
    let expected = varargs + 1;
    let mut best = Vec::new();
    for i in 0..data.num_calls() {
        let sibling = data.get_call_specs(i);
        if sibling.is_input_active()
            || sibling.get_op() == op
            || sibling.get_entry_address() != entry
        {
            continue;
        }
        let sibling_op = sibling.get_op();
        if data.obank().get(sibling_op).map(|o| o.code()) != Some(OpCode::CPUI_CALL)
            || constant_pointer(data, sibling_op)?.as_ref() != Some(&format_addr)
        {
            continue;
        }
        let Some(storage) = witness_storage(data, sibling) else {
            continue;
        };
        if storage.len() == expected && storage.len() > best.len() {
            best = storage;
        }
    }
    Ok(best)
}

#[cfg(test)]
mod tests {
    use super::{printf_argument_count, read_format};
    use std::cell::{Cell, RefCell};
    use std::rc::Rc;

    use kuna_base::address::Address;
    use kuna_base::error::{KunaError, KunaResult};
    use kuna_base::space::{
        addrspace_flags, spacetype, AddrSpace, AddrSpaceManager, ConstantSpace, FspecSpace,
        IopSpace, UniqueSpace,
    };
    use kuna_sleigh::loadimage::LoadImage;

    use crate::context::ArchContext;
    use crate::funcdata::Funcdata;

    struct FormatImage {
        bytes: Vec<u8>,
        failure: KunaError,
        reads: Rc<Cell<usize>>,
    }

    impl LoadImage for FormatImage {
        fn get_file_name(&self) -> &str {
            "optional-format"
        }

        fn load_fill(&mut self, ptr: &mut [u8], addr: &Address) -> KunaResult<()> {
            self.reads.set(self.reads.get() + 1);
            let Some(start) = addr.get_offset().checked_sub(0x2004) else {
                return Err(self.failure.clone());
            };
            let Some(bytes) = self.bytes.get(start as usize..start as usize + ptr.len()) else {
                return Err(self.failure.clone());
            };
            ptr.copy_from_slice(bytes);
            Ok(())
        }

        fn get_arch_type(&self) -> Vec<u8> {
            b"optional-format".to_vec()
        }

        fn adjust_vma(&mut self, _adjust: i64) {}
    }

    fn format_fixture(bytes: &[u8], failure: KunaError) -> (Funcdata, Address, Rc<Cell<usize>>) {
        let mut manager = AddrSpaceManager::new();
        manager.insert_space(Rc::new(ConstantSpace::new())).unwrap();
        manager.insert_space(Rc::new(UniqueSpace::new(1, 0, false))).unwrap();
        manager.insert_space(Rc::new(IopSpace::new(2))).unwrap();
        manager.insert_space(Rc::new(FspecSpace::new(3))).unwrap();
        let ram = Rc::new(AddrSpace::new(
            spacetype::IPTR_PROCESSOR, "ram", false, 8, 1, 4,
            addrspace_flags::hasphysical, 1, 1,
        ));
        manager.insert_space(Rc::clone(&ram)).unwrap();
        let reads = Rc::new(Cell::new(0));
        let mut context = ArchContext::new(manager);
        context.loader = Some(Rc::new(RefCell::new(Box::new(FormatImage {
            bytes: bytes.to_vec(),
            failure,
            reads: Rc::clone(&reads),
        }) as Box<dyn LoadImage>)));
        let function = Funcdata::new(
            "format", "format", Rc::new(context), Address::new(Rc::clone(&ram), 0x1000),
            0x10000000, 0,
        ).unwrap();
        (function, Address::new(ram, 0x2004), reads)
    }

    #[test]
    fn unavailable_format_is_absence_even_after_a_readable_prefix() {
        for prefix in [b"".as_slice(), b"%d".as_slice()] {
            let (function, address, reads) = format_fixture(
                prefix, KunaError::data_unavail("format bytes are not mapped"),
            );
            assert_eq!(read_format(&function, &address).unwrap(), None);
            assert_eq!(reads.get(), prefix.len() + 1);
        }
    }

    #[test]
    fn format_query_failures_preserve_category_and_stop_at_the_failed_read() {
        for failure in [
            KunaError::transport("host closed while reading format"),
            KunaError::java("java.lang.IllegalStateException", "format query failed"),
            KunaError::decoder("malformed format response"),
            KunaError::lowlevel("format image failed"),
        ] {
            let (function, address, reads) = format_fixture(b"%d", failure.clone());
            assert_eq!(read_format(&function, &address).unwrap_err(), failure);
            assert_eq!(reads.get(), 3, "no read may follow the failed acquisition");
        }
    }

    #[test]
    fn complete_format_and_empty_string_keep_their_original_meaning() {
        let (function, address, reads) = format_fixture(
            b"%d\0", KunaError::data_unavail("past terminator"),
        );
        assert_eq!(read_format(&function, &address).unwrap(), Some(b"%d".to_vec()));
        assert_eq!(reads.get(), 3);
        let (function, address, reads) = format_fixture(
            b"\0", KunaError::data_unavail("past terminator"),
        );
        assert_eq!(read_format(&function, &address).unwrap(), None);
        assert_eq!(reads.get(), 1);
    }

    #[test]
    fn counts_conversions_and_star_operands() {
        assert_eq!(printf_argument_count(b"position=(%d,%d)\\n"), Some(2));
        assert_eq!(printf_argument_count(b"%*.*s %% %lld"), Some(4));
        assert_eq!(printf_argument_count(b"errno: %m"), Some(0));
    }

    #[test]
    fn declines_positional_and_malformed_formats() {
        assert_eq!(printf_argument_count(b"%2$d"), None);
        assert_eq!(printf_argument_count(b"%q"), None);
        assert_eq!(printf_argument_count(b"tail %"), None);
        assert_eq!(printf_argument_count(b"plain text"), None);
    }
}
