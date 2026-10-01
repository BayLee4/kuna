//! Semantic datatype declarations, borrowed graph operations and factory publication.
//! Internal dependencies are non-owning TypeIds; external TypeRoots retain a generation.
//! See dtype_graph for transactions/lifetimes, dtype_ops for read algorithms and
//! dtype_factory for construction, interning and shared CLI/Ghidra decoding.

use std::cell::{Cell, RefCell};
use std::cmp::Ordering;
use std::collections::BTreeMap;
use std::rc::Rc;

use kuna_base::address::Address;
use kuna_base::error::{KunaError, KunaResult};
use kuna_base::marshal::Decoder;
use kuna_base::space::AddrSpace;
use kuna_base::types::{int4, int8, uint4, uint8};

use crate::bitfield::BitRange;

// =============================================================================
// type_metatype (type.hh:80-100) — verbatim, discriminants load-bearing
// =============================================================================

/// The core meta-types supported by the decompiler (C++ `enum type_metatype`,
/// `type.hh:80-100`).
///
/// These are sizeless templates for the elements making up the type algebra.
/// **The index is important** for [`Datatype::base2sub`]'s array, and the
/// ordering is significant: the lower the number, the more \b specific the
/// data-type, affecting propagation.  Transcribed with explicit discriminants.
#[allow(non_camel_case_types)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum type_metatype {
    /// Part of a union
    TYPE_PARTIALUNION = 0,
    /// Part of a structure, stored separately from the whole
    TYPE_PARTIALSTRUCT = 1,
    /// Part of an enumerated value (specialization of TYPE_UINT)
    TYPE_PARTIALENUM = 2,
    /// An overlapping union of multiple datatypes
    TYPE_UNION = 3,
    /// Structure data-type, made up of component datatypes
    TYPE_STRUCT = 4,
    /// Signed enumeration data-type (specialization of TYPE_INT)
    TYPE_ENUM_INT = 5,
    /// Unsigned enumeration data-type (specialization of TYPE_UINT)
    TYPE_ENUM_UINT = 6,
    /// Array data-type, made up of a sequence of "element" datatype
    TYPE_ARRAY = 7,
    /// Pointer relative to another data-type (specialization of TYPE_PTR)
    TYPE_PTRREL = 8,
    /// Pointer data-type
    TYPE_PTR = 9,
    /// Floating-point
    TYPE_FLOAT = 10,
    /// Data is actual executable code
    TYPE_CODE = 11,
    /// Boolean
    TYPE_BOOL = 12,
    /// Unsigned integer
    TYPE_UINT = 13,
    /// Signed integer. Signed is considered less specific than unsigned in C
    TYPE_INT = 14,
    /// An unknown low-level type. Treated as an unsigned integer.
    TYPE_UNKNOWN = 15,
    /// Placeholder for symbol/type look-up calculations
    TYPE_SPACEBASE = 16,
    /// Standard "void" type, absence of type
    TYPE_VOID = 17,
}

impl type_metatype {
    /// The raw discriminant as an `i32`, matching the C++ enum's integer value.
    /// Used for the `<=`/ordering comparisons the C++ does directly on the enum
    /// (e.g. `Datatype::isPieceStructured`: `metatype <= TYPE_ARRAY`).
    #[inline]
    pub fn as_i32(self) -> i32 {
        self as i32
    }
}

// =============================================================================
// sub_metatype (type.hh:104-129) — verbatim, ordering drives cast propagation
// =============================================================================

/// Specializations of the core meta-types (C++ `enum sub_metatype`,
/// `type.hh:104-129`).
///
/// Each enumeration is associated with a specific [`type_metatype`].  Ordering
/// is important: the lower the number, the more \b specific the data-type,
/// affecting propagation.  This is the value [`Datatype::compare`] /
/// [`Datatype::compare_dependency`] sort on, so the discriminants are
/// transcribed verbatim.
#[allow(non_camel_case_types)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum sub_metatype {
    /// Compare as a TYPE_VOID
    SUB_VOID = 23,
    /// Compare as a TYPE_SPACEBASE
    SUB_SPACEBASE = 22,
    /// Compare as a TYPE_UNKNOWN
    SUB_UNKNOWN = 21,
    /// Compare as TYPE_PARTIALSTRUCT
    SUB_PARTIALSTRUCT = 20,
    /// Signed 1-byte character, sub-type of TYPE_INT
    SUB_INT_CHAR = 19,
    /// Unsigned 1-byte character, sub-type of TYPE_UINT
    SUB_UINT_CHAR = 18,
    /// Compare as a plain TYPE_INT
    SUB_INT_PLAIN = 17,
    /// Compare as a plain TYPE_UINT
    SUB_UINT_PLAIN = 16,
    /// Signed enum, sub-type of TYPE_INT
    SUB_INT_ENUM = 15,
    /// Unsigned partial enum, sub-type of TYPE_UINT
    SUB_UINT_PARTIALENUM = 14,
    /// Unsigned enum, sub-type of TYPE_UINT
    SUB_UINT_ENUM = 13,
    /// Signed wide character, sub-type of TYPE_INT
    SUB_INT_UNICODE = 12,
    /// Unsigned wide character, sub-type of TYPE_UINT
    SUB_UINT_UNICODE = 11,
    /// Compare as TYPE_BOOL
    SUB_BOOL = 10,
    /// Compare as TYPE_CODE
    SUB_CODE = 9,
    /// Compare as TYPE_FLOAT
    SUB_FLOAT = 8,
    /// Pointer to unknown field of struct, sub-type of TYPE_PTR
    SUB_PTRREL_UNK = 7,
    /// Compare as TYPE_PTR
    SUB_PTR = 6,
    /// Pointer relative to another data-type, sub-type of TYPE_PTR
    SUB_PTRREL = 5,
    /// Pointer into struct, sub-type of TYPE_PTR
    SUB_PTR_STRUCT = 4,
    /// Compare as TYPE_ARRAY
    SUB_ARRAY = 3,
    /// Compare as TYPE_STRUCT
    SUB_STRUCT = 2,
    /// Compare as TYPE_UNION
    SUB_UNION = 1,
    /// Compare as a TYPE_PARTIALUNION
    SUB_PARTIALUNION = 0,
}

impl sub_metatype {
    /// The raw discriminant as an `i32`, matching the C++ enum's integer value.
    #[inline]
    pub fn as_i32(self) -> i32 {
        self as i32
    }
}

// =============================================================================
// type_class (type.hh:132-142) — storage-assignment classes
// =============================================================================

/// Data-type classes for the purpose of assigning storage (C++ `enum
/// type_class`, `type.hh:132-142`).
#[allow(non_camel_case_types)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum type_class {
    /// General purpose
    TYPECLASS_GENERAL = 0,
    /// Floating-point data-types
    TYPECLASS_FLOAT = 1,
    /// Pointer data-types
    TYPECLASS_PTR = 2,
    /// Class for hidden return values
    TYPECLASS_HIDDENRET = 3,
    /// Vector data-types
    TYPECLASS_VECTOR = 4,
    /// Architecture specific class 1
    TYPECLASS_CLASS1 = 100,
    /// Architecture specific class 2
    TYPECLASS_CLASS2 = 101,
    /// Architecture specific class 3
    TYPECLASS_CLASS3 = 102,
    /// Architecture specific class 4
    TYPECLASS_CLASS4 = 103,
}

// =============================================================================
// Metatype helper free functions (type.cc:242-436)
// =============================================================================

/// `Datatype::base2sub[18]` (type.cc:23-27): per-metatype default submeta,
/// indexed by the metatype's discriminant.
///
/// The C++ `Datatype` constructor sets `submeta = base2sub[m]`.  Transcribed
/// verbatim from `type.cc`; index `i` corresponds to the `type_metatype` whose
/// discriminant is `i`.
pub const BASE2SUB: [sub_metatype; 18] = [
    sub_metatype::SUB_PARTIALUNION,     // 0  TYPE_PARTIALUNION
    sub_metatype::SUB_PARTIALSTRUCT,    // 1  TYPE_PARTIALSTRUCT
    sub_metatype::SUB_UINT_PARTIALENUM, // 2  TYPE_PARTIALENUM
    sub_metatype::SUB_UNION,            // 3  TYPE_UNION
    sub_metatype::SUB_STRUCT,           // 4  TYPE_STRUCT
    sub_metatype::SUB_INT_ENUM,         // 5  TYPE_ENUM_INT
    sub_metatype::SUB_UINT_ENUM,        // 6  TYPE_ENUM_UINT
    sub_metatype::SUB_ARRAY,            // 7  TYPE_ARRAY
    sub_metatype::SUB_PTRREL,           // 8  TYPE_PTRREL
    sub_metatype::SUB_PTR,              // 9  TYPE_PTR
    sub_metatype::SUB_FLOAT,            // 10 TYPE_FLOAT
    sub_metatype::SUB_CODE,             // 11 TYPE_CODE
    sub_metatype::SUB_BOOL,             // 12 TYPE_BOOL
    sub_metatype::SUB_UINT_PLAIN,       // 13 TYPE_UINT
    sub_metatype::SUB_INT_PLAIN,        // 14 TYPE_INT
    sub_metatype::SUB_UNKNOWN,          // 15 TYPE_UNKNOWN
    sub_metatype::SUB_SPACEBASE,        // 16 TYPE_SPACEBASE
    sub_metatype::SUB_VOID,             // 17 TYPE_VOID
];

/// Default sub-metatype for a given meta-type (C++ `Datatype::base2sub[m]`).
#[inline]
pub fn base2sub(m: type_metatype) -> sub_metatype {
    // cast: type_metatype discriminants are 0..17, all in-bounds for BASE2SUB[18].
    BASE2SUB[m as usize]
}

/// Convert a type \b meta-type into the string name of the meta-type
/// (C++ `metatype2string`, type.cc:242-303).
pub fn metatype2string(metatype: type_metatype) -> KunaResult<String> {
    use type_metatype::*;
    let res = match metatype {
        TYPE_VOID => "void",
        TYPE_PTR => "ptr",
        TYPE_PTRREL => "ptrrel",
        TYPE_ARRAY => "array",
        TYPE_PARTIALENUM => "partenum",
        TYPE_PARTIALSTRUCT => "partstruct",
        TYPE_PARTIALUNION => "partunion",
        TYPE_ENUM_INT => "enum_int",
        TYPE_ENUM_UINT => "enum_uint",
        TYPE_STRUCT => "struct",
        TYPE_UNION => "union",
        TYPE_SPACEBASE => "spacebase",
        TYPE_UNKNOWN => "unknown",
        TYPE_UINT => "uint",
        TYPE_INT => "int",
        TYPE_BOOL => "bool",
        TYPE_CODE => "code",
        TYPE_FLOAT => "float",
    };
    Ok(res.to_string())
}

/// Given a string description of a type \b meta-type, return the meta-type
/// (C++ `string2metatype`, type.cc:307-369).
///
/// The C++ dispatches on the first character then matches the full string; the
/// transcription preserves the same fall-through structure so an unrecognized
/// string under a known first character still errors (matching the C++ break +
/// final `throw`).
pub fn string2metatype(metastring: &str) -> KunaResult<type_metatype> {
    use type_metatype::*;
    let first = metastring.as_bytes().first().copied();
    let res: Option<type_metatype> = match first {
        Some(b'p') => {
            if metastring == "ptr" {
                Some(TYPE_PTR)
            } else if metastring == "ptrrel" {
                Some(TYPE_PTRREL)
            } else if metastring == "partunion" {
                Some(TYPE_PARTIALUNION)
            } else if metastring == "partstruct" {
                Some(TYPE_PARTIALSTRUCT)
            } else {
                None
            }
        }
        Some(b'a') => (metastring == "array").then_some(TYPE_ARRAY),
        Some(b'e') => {
            if metastring == "enum_int" {
                Some(TYPE_ENUM_INT)
            } else if metastring == "enum_uint" {
                Some(TYPE_ENUM_UINT)
            } else {
                None
            }
        }
        Some(b's') => {
            if metastring == "struct" {
                Some(TYPE_STRUCT)
            } else if metastring == "spacebase" {
                Some(TYPE_SPACEBASE)
            } else {
                None
            }
        }
        Some(b'u') => {
            if metastring == "unknown" {
                Some(TYPE_UNKNOWN)
            } else if metastring == "uint" {
                Some(TYPE_UINT)
            } else if metastring == "union" {
                Some(TYPE_UNION)
            } else {
                None
            }
        }
        Some(b'i') => (metastring == "int").then_some(TYPE_INT),
        Some(b'f') => (metastring == "float").then_some(TYPE_FLOAT),
        Some(b'b') => (metastring == "bool").then_some(TYPE_BOOL),
        Some(b'c') => (metastring == "code").then_some(TYPE_CODE),
        Some(b'v') => (metastring == "void").then_some(TYPE_VOID),
        _ => None,
    };
    res.ok_or_else(|| {
        KunaError::lowlevel(format!("Unknown metatype: {metastring}"))
    })
}

/// Given a description of a data-type \e class, return the [`type_class`]
/// (C++ `string2typeclass`, type.cc:375-415).
pub fn string2typeclass(classstring: &str) -> KunaResult<type_class> {
    use type_class::*;
    let first = classstring.as_bytes().first().copied();
    let res: Option<type_class> = match first {
        Some(b'c') => {
            if classstring == "class1" {
                Some(TYPECLASS_CLASS1)
            } else if classstring == "class2" {
                Some(TYPECLASS_CLASS2)
            } else if classstring == "class3" {
                Some(TYPECLASS_CLASS3)
            } else if classstring == "class4" {
                Some(TYPECLASS_CLASS4)
            } else {
                None
            }
        }
        Some(b'g') => (classstring == "general").then_some(TYPECLASS_GENERAL),
        Some(b'h') => (classstring == "hiddenret").then_some(TYPECLASS_HIDDENRET),
        Some(b'f') => (classstring == "float").then_some(TYPECLASS_FLOAT),
        Some(b'p') => {
            (classstring == "ptr" || classstring == "pointer").then_some(TYPECLASS_PTR)
        }
        Some(b'v') => (classstring == "vector").then_some(TYPECLASS_VECTOR),
        // C++: 'u' "unknown" maps to the general purpose class.
        Some(b'u') => (classstring == "unknown").then_some(TYPECLASS_GENERAL),
        _ => None,
    };
    res.ok_or_else(|| {
        KunaError::lowlevel(format!("Unknown data-type class: {classstring}"))
    })
}

/// Convert a data-type metatype to a data-type class (C++ `metatype2typeclass`,
/// type.cc:424-436).
///
///   - `TYPE_FLOAT`  -> `TYPECLASS_FLOAT`
///   - `TYPE_PTR`    -> `TYPECLASS_PTR`
///   - everything else -> `TYPECLASS_GENERAL`
pub fn metatype2typeclass(meta: type_metatype) -> type_class {
    match meta {
        type_metatype::TYPE_FLOAT => type_class::TYPECLASS_FLOAT,
        type_metatype::TYPE_PTR => type_class::TYPECLASS_PTR,
        _ => type_class::TYPECLASS_GENERAL,
    }
}

// =============================================================================
// Datatype flag bits (the anonymous enum, type.hh:171-189)
// =============================================================================

/// Boolean property bits of a [`Datatype`] (C++ `Datatype`'s anonymous protected
/// `enum`, `type.hh:171-189`).  These are the bits stored in `Datatype::flags`.
pub mod flags {
    #![allow(non_upper_case_globals)]
    use kuna_base::types::uint4;
    /// This is a basic type which will never be redefined
    pub const coretype: uint4 = 1;
    /// ASCII character data
    pub const chartype: uint4 = 2;
    /// An enumeration type (as well as an integer)
    pub const enumtype: uint4 = 4;
    /// An enumeration type where all values are of 2^^n form
    pub const poweroftwo: uint4 = 8;
    /// 16-bit wide chars in unicode UTF16
    pub const utf16: uint4 = 16;
    /// 32-bit wide chars in unicode UTF32
    pub const utf32: uint4 = 32;
    /// Structure that should be treated as a string
    pub const opaque_string: uint4 = 64;
    /// May be other structures with same name different lengths
    pub const variable_length: uint4 = 128;
    /// Datatype has a stripped form for formal declarations
    pub const has_stripped: uint4 = 0x100;
    /// Datatype is a TypePointerRel
    pub const is_ptrrel: uint4 = 0x200;
    /// Set if this (recursive) data-type has not been fully defined yet
    pub const type_incomplete: uint4 = 0x400;
    /// Datatype (union, pointer to union) needs resolution before propagation
    pub const needs_resolution: uint4 = 0x800;
    /// 3-bits encoding display format, 0=none, 1=hex, 2=dec, 3=oct, 4=bin, 5=char
    pub const force_format: uint4 = 0x7000;
    /// Pointer can be truncated and is big endian
    pub const truncate_bigendian: uint4 = 0x8000;
    /// Data-type is a pointer to an array
    pub const pointer_to_array: uint4 = 0x10000;
    /// Data-type has an associated \e warning string
    pub const warning_issued: uint4 = 0x20000;
    /// Data-type contains bitfields
    pub const has_bitfields: uint4 = 0x40000;
}

// =============================================================================
// TypeField / TypeBitField (type.hh:311-342) — light record carriers
// =============================================================================

/// A field within a structure or union (C++ `TypeField`, type.hh:311-325).
///
/// The field type is a non-owning graph edge. Graph-aware comparison and
/// encoding borrow its definition through a [`ReadView`].
#[derive(Debug, Clone)]
pub struct TypeField {
    /// Identifier of this within its containing structure or union
    pub ident: int4,
    /// Offset (into containing structure or union) of subfield
    pub offset: int4,
    /// Name of subfield
    pub name: String,
    /// Data-type of subfield
    pub field_type: TypeId,
}

impl TypeField {
    pub fn new(ident: int4, offset: int4, name: impl Into<String>, ct: TypeId) -> TypeField {
        TypeField { ident, offset, name: name.into(), field_type: ct }
    }
}

/// A field within a structure that is not aligned/sized on byte boundaries
/// (C++ `TypeBitField`, type.hh:328-342).
///
/// In C++ the `BitRange bits` member carries the full
/// `byteOffset`/`byteSize`/`leastSigBit`/`numBits`/`isBigEndian` tuple.
/// These fields retain that geometry alongside a non-owning graph type edge.
#[derive(Debug, Clone)]
pub struct TypeBitField {
    /// Name of bitfield
    pub name: String,
    /// Underlying (integer) data-type
    pub field_type: TypeId,
    /// Byte offset of the bitfield's container (C++ `bits.byteOffset`).
    pub byte_offset: int4,
    /// Byte size of the bitfield's container (C++ `bits.byteSize`).
    pub byte_size: int4,
    /// Least significant bit of the range within its container (C++
    /// `bits.leastSigBit`).
    pub least_sig_bit: int4,
    /// Number of bits in the range (C++ `bits.numBits`).
    pub num_bits: int4,
    /// Is the underlying encoding big endian (C++ `bits.isBigEndian`).
    pub is_big_endian: bool,
    /// Identifier of this within containing structure
    pub ident: int4,
}

impl TypeBitField {
    pub fn new(
        id: int4,
        num_bits: int4,
        is_big_endian: bool,
        nm: impl Into<String>,
        ct: TypeId,
    ) -> TypeBitField {
        TypeBitField {
            name: nm.into(),
            field_type: ct,
            byte_offset: 0,
            byte_size: (num_bits + 7) / 8,
            least_sig_bit: 0,
            num_bits,
            is_big_endian,
            ident: id,
        }
    }

    pub(super) fn bits_compare(&self, op2: &TypeBitField) -> int4 {
        if self.byte_offset != op2.byte_offset {
            return if self.byte_offset < op2.byte_offset { -1 } else { 1 };
        }
        if self.byte_size != op2.byte_size {
            return if self.byte_size < op2.byte_size { -1 } else { 1 };
        }
        if self.least_sig_bit != op2.least_sig_bit {
            return if self.least_sig_bit < op2.least_sig_bit { -1 } else { 1 };
        }
        if self.num_bits != op2.num_bits {
            return if self.num_bits < op2.num_bits { -1 } else { 1 };
        }
        0
    }

    pub fn bits(&self) -> BitRange {
        BitRange::new(
            self.byte_offset,
            self.byte_size,
            self.least_sig_bit,
            self.num_bits,
            self.is_big_endian,
        )
    }

    pub(super) fn compare_max_byte(off: int4, bitfield: &TypeBitField) -> bool {
        off < bitfield.byte_offset + bitfield.byte_size
    }
}

// =============================================================================
// BitFieldTriple (type.hh:344-357) — collectBitFields output record
// =============================================================================

/// A bitfield description, along with its offset within a root container, in one
/// record (C++ `BitFieldTriple`, type.hh:347-357).
///
/// In C++ the record carries a live `const TypeStruct *immedContainer` and a
/// `const TypeBitField *bitfield` pointer.  The only datum any caller reads off
/// the triple is `bitfield->bits` (the range, in `BitFieldTransform::
/// establishFields`, `type.cc` line 1815) plus `offset`; the immediate-container
/// pointer is never dereferenced after construction.  So the port carries an
/// owned [`TypeBitField`] clone (cheap — `TypeId` body) and the byte
/// `offset`, which is exactly the projection the bitfield transforms consume.
#[derive(Debug, Clone)]
pub struct BitFieldTriple {
    /// Description of the bitfield (C++ `bitfield`).
    pub bitfield: TypeBitField,
    /// Byte offset of the immediate container within parent (C++ `offset`).
    pub offset: int4,
}

impl BitFieldTriple {
    /// Construct from components (C++ `BitFieldTriple(const TypeStruct*,const
    /// TypeBitField*,int4)`, type.hh:352-353).  The `immedContainer` argument is
    /// dropped — see the type doc.
    pub fn new(bits: TypeBitField, off: int4) -> BitFieldTriple {
        BitFieldTriple { bitfield: bits, offset: off }
    }

    /// Comparator putting bitfields in byte order, least to most significant
    /// (C++ `BitFieldTriple::compare`, type.cc:932-949).  Returns `true` if
    /// `op1` sorts strictly before `op2`, the strict-weak ordering `std::sort`
    /// expects.  Mixed endianness is keyed off `op1`'s bitfield exactly as in
    /// C++.
    pub fn compare(op1: &BitFieldTriple, op2: &BitFieldTriple) -> bool {
        let is_big_endian = op1.bitfield.is_big_endian;
        let byte_off1 = op1.offset + op1.bitfield.byte_offset;
        let byte_off2 = op2.offset + op2.bitfield.byte_offset;
        if byte_off1 != byte_off2 {
            if is_big_endian {
                // Return least significant container; bigger byte offset is less
                // significant.
                return byte_off1 > byte_off2;
            }
            // Smaller byte offset is less significant.
            return byte_off1 < byte_off2;
        }
        let lsb1 = op1.bitfield.least_sig_bit;
        let lsb2 = op2.bitfield.least_sig_bit;
        if lsb1 != lsb2 {
            return lsb1 < lsb2;
        }
        // fields start at the same bit
        false
    }
}

// =============================================================================
// DatatypeKind — the subclass payloads (one variant per type.hh subclass)
// =============================================================================

/// The concrete subclass of a [`Datatype`], with the per-subclass data members
/// transcribed from `type.hh`.
///
/// In C++ each subclass (`TypePointer`, `TypeArray`, …) adds its own fields and
/// overrides the virtual methods.  Rust has no inheritance, so [`Datatype`]
/// carries the shared `Datatype` members (id/size/flags/name/metatype/submeta/…)
/// plus this enum for the subclass-specific payload. Graph-aware algorithms
/// on [`TypeRef`] match on `kind` to reproduce the virtual dispatch.
#[derive(Debug, Clone)]
pub enum DatatypeKind {
    /// `TypeBase` — fundamental atomic type with only name/size/meta-type
    /// (also the carrier for `TypeChar`/`TypeUnicode`, which are `TypeBase`
    /// subclasses distinguished only by flag bits: `chartype`/`utf16`/`utf32`).
    Base,
    /// `TypeVoid` (type.hh:435-446): the formal "void" data-type.
    Void,
    /// `TypeUnknown` — an unknown low-level type.  In C++ `TypeUnknown` is an
    /// alias relationship via `TypeBase` with metatype `TYPE_UNKNOWN`; carried
    /// as its own kind for clarity.
    Unknown,
    /// A nominal typedef. Its immediate target is `Datatype::typedef_imm`.
    Alias,
    /// `TypePointer` (type.hh:449-489).
    Pointer {
        /// Type being pointed to (C++ `ptrto`)
        ptrto: TypeId,
        /// Address space this is intended to point into (C++ `spaceid`)
        spaceid: Option<Rc<AddrSpace>>,
        /// Truncated form of the pointer, if any (C++ `truncate`)
        truncate: Option<TypeId>,
        /// What size unit does the pointer address (C++ `wordsize`)
        wordsize: uint4,
    },
    /// `TypeArray` (type.hh:492-523).
    Array {
        /// Type of which we have an array (C++ `arrayof`)
        arrayof: TypeId,
        /// Number of elements in the array (C++ `arraysize`)
        arraysize: int4,
    },
    /// `TypeStruct` (type.hh:566-611).
    Struct {
        /// List of fields (C++ `field`)
        field: Vec<TypeField>,
        /// List of fields not aligned/sized on byte boundaries (C++ `bitfield`)
        bitfield: Vec<TypeBitField>,
    },
    /// `TypeUnion` (type.hh:617-640).
    Union {
        /// The list of fields (C++ `field`)
        field: Vec<TypeField>,
    },
    /// `TypeEnum` (type.hh:529-563): an integer with named values.
    Enum {
        /// Map from integer to name (C++ `namemap`)
        namemap: std::collections::BTreeMap<u64, String>,
    },
    /// `TypeCode` (type.hh:771-792): executable code / function-pointer target.
    Code {
        /// If present, describes the prototype of the underlying function (C++
        /// `proto`, a `FuncProto *`).  Built by `getTypeCode(PrototypePieces)` ->
        /// `TypeCode::setPrototype` (type.cc:3177-3190); the recovered/anonymous
        /// case leaves it `None`.
        proto: Option<crate::fspec::LogicalCallable>,
    },
    /// `TypeSpacebase` (type.hh:799-824): a pointer that indexes the symbol table.
    Spacebase {
        /// The address space being treated as a structure (C++ `spaceid`)
        spaceid: Option<Rc<AddrSpace>>,
        /// Address of the function whose symbol table is indexed (C++ `localframe`)
        localframe: Address,
    },
    /// `TypePartialStruct` (type.hh:665-684): holds part of a TypeStruct/TypeArray.
    PartialStruct {
        /// The undefined data-type to use if a formal data-type is required
        /// (C++ `stripped`)
        stripped: TypeId,
        /// Parent structure or array of which this is a part (C++ `container`)
        container: TypeId,
        /// Byte offset within the parent where this starts (C++ `offset`)
        offset: int4,
    },
    /// `TypePartialUnion` (type.hh:692-717): a variable's relative position
    /// within a union data-type.
    PartialUnion {
        /// The undefined data-type to use if a formal data-type is required
        /// (C++ `stripped`)
        stripped: TypeId,
        /// Union data-type containing this partial (C++ `container`, a `TypeUnion *`)
        container: TypeId,
        /// Offset (in bytes) into the container union (C++ `offset`)
        offset: int4,
    },
    /// `TypePartialEnum` (type.hh:643-662): part of a TypeEnum plus padding.
    PartialEnum {
        /// The undefined data-type to use if a formal data-type is required
        /// (C++ `stripped`)
        stripped: TypeId,
        /// The enumeration data-type this is based on (C++ `parent`, a `TypeEnum *`)
        parent: TypeId,
        /// Byte offset within the parent enum where this starts (C++ `offset`)
        offset: int4,
    },
    /// `TypePointerRel` (type.hh:724-763): a pointer with a fixed offset into a
    /// container.  In C++ this *derives from* `TypePointer`, so it also carries
    /// the `Pointer` members (ptrto/spaceid/wordsize); those live in the shared
    /// `Datatype` view via the parallel `Pointer` accessors, with the relative
    /// extras here.
    PointerRel {
        /// Type being pointed to (C++ `TypePointer::ptrto`)
        ptrto: TypeId,
        spaceid: Option<Rc<AddrSpace>>,
        /// What size unit does the pointer address (C++ `TypePointer::wordsize`)
        wordsize: uint4,
        /// Same data-type with container info stripped (C++ `stripped`)
        stripped: Option<TypeId>,
        /// Parent structure/array which this is pointing into (C++ `parent`)
        parent: TypeId,
        /// Byte offset within the parent where this points to (C++ `offset`)
        offset: int4,
    },
}

// =============================================================================
// Datatype — the base class surface (type.hh:167-308)
// =============================================================================


/// The base datatype class for the decompiler (C++ `Datatype`, type.hh:167-308).
///
/// Used for symbols, function prototypes, type propagation, etc.  This carries
/// the member layout from `type.hh` plus a [`DatatypeKind`] for the subclass
/// payload. Owned values are construction drafts; published values are borrowed
/// through [`TypeRef`], while [`TypeRoot`] retains their generation.
#[derive(Debug, Clone)]
pub struct Datatype {
    /// A unique id for the type (or 0 if an id is not assigned)
    pub id: uint8,
    /// Size (of variable holding a value of this type)
    pub size: int4,
    /// Boolean properties of the type (see [`flags`])
    pub flags: uint4,
    /// Presentation override, intentionally outside semantic shape and intern keys.
    /// A core type may change formatting without mutating its immutable definition.
    presentation_format: Cell<Option<uint4>>,
    /// Name of type
    pub name: String,
    /// Name to display in output
    pub display_name: String,
    /// Meta-type - type disregarding size
    pub metatype: type_metatype,
    /// Sub-type of the meta-type, for comparisons
    pub submeta: sub_metatype,
    /// The immediate data-type being typedefed by this (C++ `typedefImm`)
    pub typedef_imm: Option<TypeId>,
    /// Byte alignment expected for this data-type in addressable memory
    pub alignment: int4,
    /// Size of data-type rounded up to a multiple of alignment
    pub align_size: int4,
    /// The concrete subclass payload
    pub kind: DatatypeKind,
}

impl Datatype {
    pub fn new_with_align(s: int4, align: int4, m: type_metatype) -> Datatype {
        Datatype {
            id: 0,
            size: s,
            flags: 0,
            presentation_format: Cell::new(None),
            name: String::new(),
            display_name: String::new(),
            metatype: m,
            submeta: base2sub(m),
            typedef_imm: None,
            alignment: align,
            align_size: s,
            kind: DatatypeKind::Base,
        }
    }

    pub fn new(size: int4, metatype: type_metatype) -> Datatype {
        Datatype::new_with_align(size, -1, metatype)
    }

    pub fn hash_name(nm: &str) -> uint8 {
        let mut res: uint8 = 123;
        for b in nm.bytes() {
            // A left rotate by 8 on a u64.
            res = res.rotate_left(8);
            res = res.wrapping_add(b as uint8);
            if (res & 1) == 0 {
                res ^= 0xfeabfeab; // Some kind of feedback
            }
        }
        res |= 0xC000000000000000; // Add header bits indicating a name hash
        res
    }

    pub fn is_core_type(&self) -> bool {
        (self.flags & flags::coretype) != 0
    }

    pub fn is_char_print(&self) -> bool {
        (self.flags & (flags::chartype | flags::utf16 | flags::utf32 | flags::opaque_string)) != 0
    }

    pub fn is_enum_type(&self) -> bool {
        (self.flags & flags::enumtype) != 0
    }

    pub fn is_ascii(&self) -> bool {
        (self.flags & flags::chartype) != 0
    }

    pub fn is_utf16(&self) -> bool {
        (self.flags & flags::utf16) != 0
    }

    pub fn is_utf32(&self) -> bool {
        (self.flags & flags::utf32) != 0
    }

    pub fn is_variable_length(&self) -> bool {
        (self.flags & flags::variable_length) != 0
    }

    pub fn is_opaque_string(&self) -> bool {
        (self.flags & flags::opaque_string) != 0
    }

    pub fn is_pointer_to_array(&self) -> bool {
        (self.flags & flags::pointer_to_array) != 0
    }

    pub fn is_pointer_rel(&self) -> bool {
        (self.flags & flags::is_ptrrel) != 0
    }

    pub fn is_formal_pointer_rel(&self) -> bool {
        (self.flags & (flags::is_ptrrel | flags::has_stripped)) == flags::is_ptrrel
    }

    pub fn has_stripped(&self) -> bool {
        (self.flags & flags::has_stripped) != 0
    }

    pub fn is_incomplete(&self) -> bool {
        (self.flags & flags::type_incomplete) != 0
    }

    pub fn needs_resolution(&self) -> bool {
        (self.flags & flags::needs_resolution) != 0
    }

    pub fn has_warning(&self) -> bool {
        (self.flags & flags::warning_issued) != 0
    }

    pub fn has_bitfields(&self) -> bool {
        (self.flags & flags::has_bitfields) != 0
    }

    pub fn inherit_for_pointer(&self) -> uint4 {
        self.flags & (flags::coretype | flags::warning_issued)
    }

    pub fn inherit_for_partial(&self) -> uint4 {
        self.flags & flags::warning_issued
    }

    pub fn get_display_format(&self) -> uint4 {
        self.presentation_format.get().unwrap_or((self.flags & flags::force_format) >> 12)
    }

    pub fn set_display_format(&mut self, format: uint4) {
        self.flags &= !flags::force_format; // Clear preexisting
        self.flags |= format << 12;
        self.presentation_format.set(Some(format));
    }

    pub fn get_metatype(&self) -> type_metatype {
        self.metatype
    }

    pub fn get_sub_meta(&self) -> sub_metatype {
        self.submeta
    }

    pub fn get_id(&self) -> uint8 {
        self.id
    }

    pub fn get_size(&self) -> int4 {
        self.size
    }

    pub fn get_align_size(&self) -> int4 {
        self.align_size
    }

    pub fn get_alignment(&self) -> int4 {
        self.alignment
    }

    pub fn get_name(&self) -> &str {
        &self.name
    }

    pub fn get_display_name(&self) -> &str {
        &self.display_name
    }

    pub fn get_unsized_id(&self) -> KunaResult<uint8> {
        Ok(self.id)
    }

    pub fn is_piece_structured(&self) -> bool {
        // C++ compares the raw enum values; TYPE_ARRAY == 7.
        self.metatype.as_i32() <= type_metatype::TYPE_ARRAY.as_i32()
    }

    pub fn calc_align_size(sz: int4, align: int4) -> int4 {
        let mod_ = sz % align;
        if mod_ != 0 {
            sz + (align - mod_)
        } else {
            sz
        }
    }

    pub fn set_name_map(&mut self, nmap: std::collections::BTreeMap<u64, String>) {
        if let DatatypeKind::Enum { namemap } = &mut self.kind {
            *namemap = nmap;
        }
    }

    pub fn assign_values(
        size: int4,
        type_name: &str,
        namelist: &[String],
        vallist: &[u64],
        assignlist: &[bool],
    ) -> KunaResult<std::collections::BTreeMap<u64, String>> {
        let mut nmap: std::collections::BTreeMap<u64, String> = std::collections::BTreeMap::new();
        let mask = kuna_base::address::calc_mask(size);
        let mut maxval: u64 = 0;
        for i in 0..namelist.len() {
            if assignlist[i] {
                // Did the user explicitly set value.
                let mut val = vallist[i];
                if val > maxval {
                    maxval = val;
                }
                val &= mask;
                if nmap.contains_key(&val) {
                    return Err(KunaError::lowlevel(format!(
                        "Enum \"{type_name}\": \"{}\" is a duplicate value",
                        namelist[i]
                    )));
                }
                nmap.insert(val, namelist[i].clone());
            }
        }
        for i in 0..namelist.len() {
            if !assignlist[i] {
                let mut val;
                loop {
                    // C++ `maxval += 1;` (wrapping u64 increment).
                    maxval = maxval.wrapping_add(1);
                    val = maxval;
                    val &= mask;
                    if !nmap.contains_key(&val) {
                        break;
                    }
                }
                nmap.insert(val, namelist[i].clone());
            }
        }
        Ok(nmap)
    }

    pub fn set_struct_fields(
        &mut self,
        fd: Vec<TypeField>,
        bit: Vec<TypeBitField>,
        new_size: int4,
        new_align: int4,
    ) {
        self.size = new_size;
        self.alignment = new_align;
        self.align_size = Datatype::calc_align_size(self.size, self.alignment);
        self.kind = DatatypeKind::Struct { field: fd, bitfield: bit };
    }

    pub fn set_union_fields(&mut self, fd: Vec<TypeField>, new_size: int4, new_align: int4) {
        self.size = new_size;
        self.alignment = new_align;
        self.align_size = Datatype::calc_align_size(self.size, self.alignment);
        self.kind = DatatypeKind::Union { field: fd };
    }

    pub fn decode_integer_format(val: uint4) -> KunaResult<&'static str> {
        match val {
            1 => Ok("hex"),
            2 => Ok("dec"),
            3 => Ok("oct"),
            4 => Ok("bin"),
            5 => Ok("char"),
            _ => Err(KunaError::lowlevel("Unrecognized integer format encoding")),
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EnumRepresentation {
    /// Name tokens that are ORed together (C++ `matchname`)
    pub match_name: Vec<String>,
    /// If `true`, bitwise complement value after ORing (C++ `complement`)
    pub complement: bool,
    /// Number of bits to left-shift final value (C++ `shiftAmount`)
    pub shift_amount: int4,
}

pub const ELEM_CORETYPES: kuna_base::marshal::ElementId =
    kuna_base::marshal::ElementId::new("coretypes", 41);
/// Marshaling element `<def>` — a typedef (C++ `ELEM_DEF`, type.cc:50).
pub const ELEM_DEF: kuna_base::marshal::ElementId =
    kuna_base::marshal::ElementId::new("def", 43);
/// Marshaling element `<typeref>` (C++ `ELEM_TYPEREF`, type.cc:70).
pub const ELEM_TYPEREF: kuna_base::marshal::ElementId =
    kuna_base::marshal::ElementId::new("typeref", 63);
/// Marshaling attribute "alignment" (C++ `ATTRIB_ALIGNMENT`, type.cc:29).
pub const ATTRIB_ALIGNMENT: kuna_base::marshal::AttributeId =
    kuna_base::marshal::AttributeId::new("alignment", 47);
/// Marshaling attribute "arraysize" (C++ `ATTRIB_ARRAYSIZE`, type.cc:30).
pub const ATTRIB_ARRAYSIZE: kuna_base::marshal::AttributeId =
    kuna_base::marshal::AttributeId::new("arraysize", 48);
/// Marshaling attribute "char" (C++ `ATTRIB_CHAR`, type.cc:31).
pub const ATTRIB_CHAR: kuna_base::marshal::AttributeId =
    kuna_base::marshal::AttributeId::new("char", 49);
/// Marshaling attribute "core" (C++ `ATTRIB_CORE`, type.cc:32).
pub const ATTRIB_CORE: kuna_base::marshal::AttributeId =
    kuna_base::marshal::AttributeId::new("core", 50);
/// Marshaling attribute "incomplete" (C++ `ATTRIB_INCOMPLETE`, type.cc:34).
pub const ATTRIB_INCOMPLETE: kuna_base::marshal::AttributeId =
    kuna_base::marshal::AttributeId::new("incomplete", 52);
/// Marshaling attribute "opaquestring" (C++ `ATTRIB_OPAQUESTRING`, type.cc:38).
pub const ATTRIB_OPAQUESTRING: kuna_base::marshal::AttributeId =
    kuna_base::marshal::AttributeId::new("opaquestring", 56);
/// Marshaling attribute "utf" (C++ `ATTRIB_UTF`, type.cc:41).
pub const ATTRIB_UTF: kuna_base::marshal::AttributeId =
    kuna_base::marshal::AttributeId::new("utf", 59);
/// Marshaling attribute "varlength" (C++ `ATTRIB_VARLENGTH`, type.cc:42).
pub const ATTRIB_VARLENGTH: kuna_base::marshal::AttributeId =
    kuna_base::marshal::AttributeId::new("varlength", 60);

pub const ATTRIB_KUNA_SOURCE_PROGRAM: kuna_base::marshal::AttributeId =
    kuna_base::marshal::AttributeId::new("kuna_source_program", 4041);
pub const ATTRIB_KUNA_SOURCE_REVISION: kuna_base::marshal::AttributeId =
    kuna_base::marshal::AttributeId::new("kuna_source_revision", 4042);
pub const ATTRIB_KUNA_SOURCE_ID: kuna_base::marshal::AttributeId =
    kuna_base::marshal::AttributeId::new("kuna_source_id", 4043);
pub const ATTRIB_KUNA_SOURCE_KIND: kuna_base::marshal::AttributeId =
    kuna_base::marshal::AttributeId::new("kuna_source_kind", 4044);
pub const ATTRIB_KUNA_SOURCE_SIZE: kuna_base::marshal::AttributeId =
    kuna_base::marshal::AttributeId::new("kuna_source_size", 4045);
pub const ATTRIB_KUNA_SOURCE_SCOPE: kuna_base::marshal::AttributeId =
    kuna_base::marshal::AttributeId::new("kuna_source_scope", 4046);
pub const ATTRIB_KUNA_SOURCE_BINDING: kuna_base::marshal::AttributeId =
    kuna_base::marshal::AttributeId::new("kuna_source_binding", 4047);

/// Register the wire type-vocabulary ids (for XML-form documents; the packed
/// wire form matches by number and needs no registry).
pub fn register_type_wire_ids(reg: &mut kuna_base::marshal::IdRegistry) {
    reg.register_element(&ELEM_CORETYPES);
    reg.register_element(&ELEM_DEF);
    reg.register_element(&ELEM_TYPEREF);
    reg.register_attribute(&ATTRIB_ALIGNMENT);
    reg.register_attribute(&ATTRIB_ARRAYSIZE);
    reg.register_attribute(&ATTRIB_CHAR);
    reg.register_attribute(&ATTRIB_CORE);
    reg.register_attribute(&ATTRIB_INCOMPLETE);
    reg.register_attribute(&ATTRIB_OPAQUESTRING);
    reg.register_attribute(&ATTRIB_UTF);
    reg.register_attribute(&ATTRIB_VARLENGTH);
    reg.register_attribute(&ATTRIB_KUNA_SOURCE_PROGRAM);
    reg.register_attribute(&ATTRIB_KUNA_SOURCE_REVISION);
    reg.register_attribute(&ATTRIB_KUNA_SOURCE_ID);
    reg.register_attribute(&ATTRIB_KUNA_SOURCE_KIND);
    reg.register_attribute(&ATTRIB_KUNA_SOURCE_SIZE);
    reg.register_attribute(&ATTRIB_KUNA_SOURCE_SCOPE);
    reg.register_attribute(&ATTRIB_KUNA_SOURCE_BINDING);
}


#[path = "dtype_graph.rs"]
mod graph;
#[path = "dtype_ops.rs"]
mod ops;
#[path = "dtype_factory.rs"]
mod factory;
pub use graph::{HostTypeSource, HostTypeSourceKind, ReadView, TypeId, TypeInstance, TypeRef, TypeRoot, TypeState};
pub use factory::{RemoteTypeFetch, TypeFactory, TypeFactoryImpl};
use graph::{GraphAccess, GraphStore};
use ops::{assign_field_offsets, assign_union_field_offsets};

