//! Mach-O data symbols (`datasyms`) of a linked image. A Mach-O symbol table states
//! no sizes, so the extent of a data symbol is the distance to the next defined
//! symbol of its section, or to the section's end for the last one. Names are kept
//! as the table spells them, as on ELF.

use std::collections::HashMap;

use object::{Object, ObjectSection, ObjectSymbol, SectionIndex, SymbolSection};

pub(crate) struct MachoData {
    starts: HashMap<SectionIndex, Vec<u64>>,
    ends: HashMap<SectionIndex, u64>,
}

impl MachoData {
    /// `None` for anything but a linked Mach-O image: an object file's symbols are
    /// section-relative, as an ELF relocatable's are.
    pub(crate) fn new(file: &object::File) -> Option<Self> {
        if file.format() != object::BinaryFormat::MachO || file.kind() == object::ObjectKind::Relocatable {
            return None;
        }
        let mut starts: HashMap<SectionIndex, Vec<u64>> = HashMap::new();
        for symbol in file.symbols() {
            if let SymbolSection::Section(index) = symbol.section() {
                starts.entry(index).or_default().push(symbol.address());
            }
        }
        for addresses in starts.values_mut() {
            addresses.sort_unstable();
            addresses.dedup();
        }
        let ends = file.sections().map(|s| (s.index(), s.address().saturating_add(s.size()))).collect();
        Some(MachoData { starts, ends })
    }

    /// The symbol's extent, or 0 when it lies in no section.
    pub(crate) fn extent<'a>(&self, symbol: &impl ObjectSymbol<'a>) -> u64 {
        let SymbolSection::Section(index) = symbol.section() else { return 0 };
        let (Some(starts), Some(&end)) = (self.starts.get(&index), self.ends.get(&index)) else {
            return 0;
        };
        let address = symbol.address();
        let stop = starts.get(starts.partition_point(|&a| a <= address)).map_or(end, |&next| next.min(end));
        stop.saturating_sub(address)
    }
}
