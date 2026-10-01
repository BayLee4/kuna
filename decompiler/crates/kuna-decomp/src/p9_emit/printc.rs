//! Port of `decompiler/cpp/printc.{cc,hh}` — the c-language token emitter
//! (`PrintC`), the concrete `PrintLanguage` back-end the M2/M3 datatests
//! string-match against.
//!
//! ## What this module ports faithfully *now*
//!
//! `PrintC` is a 3.9k-line subclass of `PrintLanguage`.  As of the
//! `w10-printc-body` item the **`PrintLanguage` RPN driver** (`pushOp`/
//! `pushAtom`/`pushVn`/`recurse`/`emitOp`/`emitAtom`/`opBinary`/`opUnary`/
//! `parentheses`, printlanguage.cc:129-580) is **ported here** (the
//! `impl PrintC` RPN-driver block) and drives the real `Emit` low-level driver
//! ([`crate::prettyprint`]'s `EmitNoMarkup`).  It is byte-faithfully
//! unit-tested against the C++ `emitOp`/`emitAtom`/`parentheses` logic (the
//! `rpn_*` tests).
//!
//! What still cannot be driven over a real function body is the IR-coupled leaf
//! of the driver — `recurse`'s implied-op `defOp->getOpcode()->push(...)`
//! dispatch and `pushVnExplicit`'s Symbol/HighVariable/Datatype/constant
//! resolution — together with the structured-/flat-block walk (`emitBlock*`,
//! printc.cc:2827-3514) and the real-prototype signature.  These are blocked
//! **upstream of the printer**: the merged tree's decompilation passes
//! (heritage / simplification / merge / type + proto recovery / block
//! structuring) are stubs, so the IR reaching the printer is *raw lifted
//! p-code* (no HighVariables-with-symbols, no recovered types, **empty
//! `sblocks`**, a `void NAME(void)` proto stub).  Printing it would emit non-C
//! garbage, not byte-parity.  Those edges are `// STUB(decompile-passes)`
//! (LOSS-130 / W10) and fall to the upstream pass items; the RPN engine they
//! feed is in place.  The parity gate `tests/printc_parity.rs` measures this
//! honestly: it decompiles + prints >= 8 corpus functions and byte-compares
//! each against the C++ oracle, reporting the (upstream-bounded) match count.
//!
//! What **is** ported faithfully here, and is what this module's tests exercise:
//!
//!   1. **The operator-token table** ([`tokens`]) — every `PrintC::*` `OpToken`
//!      static (printc.cc:24-78) with its exact precedence / associativity /
//!      token-type / spacing / bump, plus the negate cross-links
//!      (printc.cc:130-135) realized as [`token_negate`].  This is *the*
//!      precedence/parenthesization data that drives [`crate::printlanguage::parentheses`]
//!      — the print-fidelity-critical decision.
//!   2. **The keyword / punctuation constants** ([`keywords`], printc.cc:80-104).
//!   3. **`PrintCCapability`** registration metadata ([`CAPABILITY_NAME`],
//!      [`CAPABILITY_IS_DEFAULT`], printc.cc:109-114).
//!   4. **The PrintC options** ([`PrintCOptions`]) — the option fields, the
//!      `resetDefaultsPrintC` defaults (printc.cc:1649-1664, including the kuna
//!      DIV-2 default-on `option_arraynotation`), and the `set*` toggles
//!      (printc.hh:242-255).  These are the PrintC side of the options.cc
//!      `// STUB(W8)` markers (`setNULLPrinting`/`setInplaceOps`/… on the
//!      print object).
//!   5. **The self-contained constant/type formatting** — the byte-for-byte
//!      token-string builders that the M2/M3 datatests match:
//!      [`print_char_hex_escape`] (printc.cc:1580-1591), [`print_unicode`]
//!      (printc.cc:1494-1538), [`format_integer_token`] (the
//!      `push_integer` string body, printc.cc:1407-1434), [`format_float_token`]
//!      (the `push_float` string body, printc.cc:1449-1492, the cfmt `%g`
//!      path), [`generic_type_name`] (printc.cc:3532-3558), and
//!      [`generic_function_name`] (printc.cc:3516-3526).
//!   6. **The opcode→token dispatch** ([`op_emit_kind`]) — the data half of the
//!      inline `op*` overrides (printc.hh:289-351): which [`OpToken`] each
//!      arithmetic/comparison op maps to and through which RPN form
//!      (`opBinary`/`opUnary`/`opFunc`/`opTypeCast`).  The *emission* is the
//!      stub; the *mapping* is faithful data.
//!
//! ## Compareform / arraynotation kuna hooks
//!
//! The kuna `compareform` rendering hook and the `arraynotation` `&base[index]`
//! mode are both controlled from here: `arraynotation` is the
//! [`PrintCOptions::array_notation`] toggle (default on, DIV-2), consulted by
//! the `opPtradd` body; `compareform` is a stage-model assertion that
//! flips which comparison `OpToken` `op_emit_kind` selects (present vs.
//! canonical).  The toggle state lives here; the emission that reads it is the
//! W9 stub.

use kuna_base::address::{calc_mask, Address};
use kuna_base::space::AddrSpace;
use kuna_base::error::{KunaError, KunaResult};
use kuna_base::types::{int4, int8, uint4, uintb};

use crate::dtype::type_metatype;
use crate::fspec::ProtoParameter;
use crate::options::{BraceStyle, NamespaceStrategy};
use crate::prettyprint::{
    BraceStyle as EmitBraceStyle, Emit, EmitBase, EmitMarkup, EmitNoMarkup, EmitPrettyPrint,
    LowLevel, MarkupProvenance, MarkupRef, SyntaxHighlight, TypeTextOrigin,
};
use crate::kuna_langtypes::TypeText;
use crate::printlanguage::{
    format_binary, modifiers, most_natural_base, parentheses, unicode_needs_escape, Atom, OpToken,
    PrintContext, ReversePolish, TagType, TokenType,
};

// ===========================================================================
// PrintCCapability — the c-language back-end factory metadata
// (printc.cc:109-114)
// ===========================================================================

/// The name registered by `PrintCCapability` (C++ `name = "c-language"`,
/// printc.cc:112).
pub const CAPABILITY_NAME: &str = "c-language";

/// Whether `PrintCCapability` registers as the default language (C++
/// `isdefault = true`, printc.cc:113).
pub const CAPABILITY_IS_DEFAULT: bool = true;

// ===========================================================================
// Operator token table (printc.cc:24-78)
// ===========================================================================

/// Construct a `static` [`OpToken`] in field order matching the C++ aggregate
/// initializer `{ print1, print2, stage, precedence, associative, type,
/// spacing, bump, negate }`.  `negate` is always `None` here; the six negate
/// cross-links (printc.cc:130-135) are resolved by [`token_negate`] to avoid a
/// self-referential static.
// The eight parameters are the eight C++ `OpToken` aggregate-initializer fields
// in source order; keeping them positional makes the `tokens::*` table a
// line-for-line transcription of the printc.cc table.
#[allow(clippy::too_many_arguments)]
const fn op_token(
    print1: &'static str,
    print2: &'static str,
    stage: int4,
    precedence: int4,
    associative: bool,
    token_type: TokenType,
    spacing: int4,
    bump: int4,
) -> OpToken {
    OpToken {
        print1,
        print2,
        stage,
        precedence,
        associative,
        token_type,
        spacing,
        bump,
        negate: None,
        paren_before_angle: false,
        left_to_right_only: false,
    }
}

/// Construct a `static` [`OpToken`] that spells and ranks exactly like
/// [`op_token`] would but carries `left_to_right_only`.  Only the IEEE-754
/// arithmetic tokens use it.
const fn float_op_token(
    print1: &'static str,
    precedence: int4,
    spacing: int4,
) -> OpToken {
    OpToken {
        print1,
        print2: "",
        stage: 2,
        precedence,
        associative: false,
        token_type: TokenType::Binary,
        spacing,
        bump: 0,
        negate: None,
        paren_before_angle: false,
        left_to_right_only: true,
    }
}

/// The `PrintC` operator-token singletons (printc.cc:24-78).
///
/// These are `static` so [`crate::printlanguage::parentheses`]'s `std::ptr::eq`
/// identity check (the C++ `topToken == op2`) is meaningful.  The numbers are
/// the precedence/associativity/spacing/bump that define C operator
/// parenthesization; transcribed value-for-value from the C++ table.
pub mod tokens {
    use super::{float_op_token, op_token, OpToken, TokenType};

    /// Hidden functional (that may force parentheses) (printc.cc:24).
    pub static HIDDEN: OpToken = op_token("", "", 1, 70, false, TokenType::HiddenFunction, 0, 0);
    /// The sub-scope/namespace operator `::` (printc.cc:25).
    pub static SCOPE: OpToken = op_token("::", "", 2, 70, true, TokenType::Binary, 0, 0);
    /// The member operator `.` (printc.cc:26).
    pub static OBJECT_MEMBER: OpToken = op_token(".", "", 2, 66, true, TokenType::Binary, 0, 0);
    /// The points-to-member operator `->` (printc.cc:27).
    pub static POINTER_MEMBER: OpToken = op_token("->", "", 2, 66, true, TokenType::Binary, 0, 0);
    /// The array subscript operator `[ ]` (printc.cc:28).
    pub static SUBSCRIPT: OpToken = op_token("[", "]", 2, 66, false, TokenType::Postsurround, 0, 0);
    /// The function-call operator `( )` (printc.cc:29).
    pub static FUNCTION_CALL: OpToken =
        op_token("(", ")", 2, 66, false, TokenType::Postsurround, 0, 10);
    /// The bitwise-negate operator `~` (printc.cc:30).
    pub static BITWISE_NOT: OpToken = op_token("~", "", 1, 62, false, TokenType::UnaryPrefix, 0, 0);
    /// The boolean-not operator `!` (printc.cc:31).
    pub static BOOLEAN_NOT: OpToken = op_token("!", "", 1, 62, false, TokenType::UnaryPrefix, 0, 0);
    /// The unary-minus operator `-` (printc.cc:32).
    pub static UNARY_MINUS: OpToken = op_token("-", "", 1, 62, false, TokenType::UnaryPrefix, 0, 0);
    /// The unary-plus operator `+` (printc.cc:33).
    pub static UNARY_PLUS: OpToken = op_token("+", "", 1, 62, false, TokenType::UnaryPrefix, 0, 0);
    /// The address-of operator `&` (printc.cc:34).
    pub static ADDRESSOF: OpToken = op_token("&", "", 1, 62, false, TokenType::UnaryPrefix, 0, 0);
    /// The pointer-dereference operator `*` (printc.cc:35).
    pub static DEREFERENCE: OpToken = op_token("*", "", 1, 62, false, TokenType::UnaryPrefix, 0, 0);
    /// The type-cast operator `( )` (printc.cc:36).
    pub static TYPECAST: OpToken = op_token("(", ")", 2, 62, false, TokenType::Presurround, 0, 0);
    /// The multiplication operator `*` (printc.cc:37).
    pub static MULTIPLY: OpToken = op_token("*", "", 2, 54, true, TokenType::Binary, 1, 0);
    /// The division operator `/` (printc.cc:38).
    pub static DIVIDE: OpToken = op_token("/", "", 2, 54, false, TokenType::Binary, 1, 0);
    /// The modulo operator `%` (printc.cc:39).
    pub static MODULO: OpToken = op_token("%", "", 2, 54, false, TokenType::Binary, 1, 0);
    /// The binary-addition operator `+` (printc.cc:40).
    pub static BINARY_PLUS: OpToken = op_token("+", "", 2, 50, true, TokenType::Binary, 1, 0);
    /// The binary-subtraction operator `-` (printc.cc:41).
    pub static BINARY_MINUS: OpToken = op_token("-", "", 2, 50, false, TokenType::Binary, 1, 0);
    /// The left-shift operator `<<` (printc.cc:42).
    pub static SHIFT_LEFT: OpToken = op_token("<<", "", 2, 46, false, TokenType::Binary, 1, 0);
    /// The right-shift operator `>>` (printc.cc:43).
    pub static SHIFT_RIGHT: OpToken = op_token(">>", "", 2, 46, false, TokenType::Binary, 1, 0);
    /// The signed right-shift operator `>>` (printc.cc:44).
    pub static SHIFT_SRIGHT: OpToken = op_token(">>", "", 2, 46, false, TokenType::Binary, 1, 0);
    /// The less-than operator `<` (printc.cc:45).
    pub static LESS_THAN: OpToken = op_token("<", "", 2, 42, false, TokenType::Binary, 1, 0);
    /// The less-than-or-equal operator `<=` (printc.cc:46).
    pub static LESS_EQUAL: OpToken = op_token("<=", "", 2, 42, false, TokenType::Binary, 1, 0);
    /// The greater-than operator `>` (printc.cc:47).
    pub static GREATER_THAN: OpToken = op_token(">", "", 2, 42, false, TokenType::Binary, 1, 0);
    /// The greater-than-or-equal operator `>=` (printc.cc:48).
    pub static GREATER_EQUAL: OpToken = op_token(">=", "", 2, 42, false, TokenType::Binary, 1, 0);
    /// The equal operator `==` (printc.cc:49).
    pub static EQUAL: OpToken = op_token("==", "", 2, 38, false, TokenType::Binary, 1, 0);
    /// The not-equal operator `!=` (printc.cc:50).
    pub static NOT_EQUAL: OpToken = op_token("!=", "", 2, 38, false, TokenType::Binary, 1, 0);
    /// The logical-and operator `&` (printc.cc:51).
    pub static BITWISE_AND: OpToken = op_token("&", "", 2, 34, true, TokenType::Binary, 1, 0);
    /// The logical-xor operator `^` (printc.cc:52).
    pub static BITWISE_XOR: OpToken = op_token("^", "", 2, 30, true, TokenType::Binary, 1, 0);
    /// The logical-or operator `|` (printc.cc:53).
    pub static BITWISE_OR: OpToken = op_token("|", "", 2, 26, true, TokenType::Binary, 1, 0);
    /// The boolean-and operator `&&` (printc.cc:54).
    pub static BOOLEAN_AND: OpToken = op_token("&&", "", 2, 22, false, TokenType::Binary, 1, 0);
    /// The boolean-xor operator `^^` (printc.cc:55).
    pub static BOOLEAN_XOR: OpToken = op_token("^^", "", 2, 20, false, TokenType::Binary, 1, 0);
    /// The boolean-or operator `||` (printc.cc:56).
    pub static BOOLEAN_OR: OpToken = op_token("||", "", 2, 18, false, TokenType::Binary, 1, 0);
    /// The assignment operator `=` (printc.cc:57).
    pub static ASSIGNMENT: OpToken = op_token("=", "", 2, 14, false, TokenType::Binary, 1, 5);
    /// The comma operator `,` for parameter lists (printc.cc:58).
    pub static COMMA: OpToken = op_token(",", "", 2, 2, true, TokenType::Binary, 0, 0);
    /// Group a sequenced expression even in a call's argument surround, where
    /// the ordinary precedence rules deliberately leave parameter commas bare.
    pub static EXPRESSION_GROUP: OpToken =
        op_token("(", ")", 1, 70, false, TokenType::Presurround, 0, 0);
    /// The `new` operator (printc.cc:59).
    pub static NEW_OP: OpToken = op_token("", "", 2, 62, false, TokenType::Space, 1, 0);

    // In-place assignment operators (printc.cc:62-71)
    /// The in-place multiplication operator `*=` (printc.cc:62).
    pub static MULTEQUAL: OpToken = op_token("*=", "", 2, 14, false, TokenType::Binary, 1, 5);
    /// The in-place division operator `/=` (printc.cc:63).
    pub static DIVEQUAL: OpToken = op_token("/=", "", 2, 14, false, TokenType::Binary, 1, 5);
    /// The in-place modulo operator `%=` (printc.cc:64).
    pub static REMEQUAL: OpToken = op_token("%=", "", 2, 14, false, TokenType::Binary, 1, 5);
    /// The in-place addition operator `+=` (printc.cc:65).
    pub static PLUSEQUAL: OpToken = op_token("+=", "", 2, 14, false, TokenType::Binary, 1, 5);
    /// The in-place subtraction operator `-=` (printc.cc:66).
    pub static MINUSEQUAL: OpToken = op_token("-=", "", 2, 14, false, TokenType::Binary, 1, 5);
    /// The in-place left-shift operator `<<=` (printc.cc:67).
    pub static LEFTEQUAL: OpToken = op_token("<<=", "", 2, 14, false, TokenType::Binary, 1, 5);
    /// The in-place right-shift operator `>>=` (printc.cc:68).
    pub static RIGHTEQUAL: OpToken = op_token(">>=", "", 2, 14, false, TokenType::Binary, 1, 5);
    /// The in-place logical-and operator `&=` (printc.cc:69).
    pub static ANDEQUAL: OpToken = op_token("&=", "", 2, 14, false, TokenType::Binary, 1, 5);
    /// The in-place logical-or operator `|=` (printc.cc:70).
    pub static OREQUAL: OpToken = op_token("|=", "", 2, 14, false, TokenType::Binary, 1, 5);
    /// The in-place logical-xor operator `^=` (printc.cc:71).
    pub static XOREQUAL: OpToken = op_token("^=", "", 2, 14, false, TokenType::Binary, 1, 5);

    // Operator tokens for type expressions (printc.cc:74-78)
    /// Type declaration involving a space (printc.cc:74).
    pub static TYPE_EXPR_SPACE: OpToken = op_token("", "", 2, 10, false, TokenType::Space, 1, 0);
    /// Type declaration with no space (printc.cc:75).
    pub static TYPE_EXPR_NOSPACE: OpToken = op_token("", "", 2, 10, false, TokenType::Space, 0, 0);

    // (kuna) IEEE-754 arithmetic, which has no row upstream: the C++ table maps
    // the float opcodes onto the integer `*`/`+` above.  These two are spelled
    // and ranked exactly like that pair -- `float_tokens_match_their_integer_twins_except_for_grouping`
    // pins every field -- and differ only in not re-associating.

    /// IEEE-754 multiplication: [`MULTIPLY`] that does not re-associate. See
    /// `OpToken::left_to_right_only`.
    pub static FLOAT_MULTIPLY: OpToken = float_op_token("*", 54, 1);
    /// IEEE-754 addition: [`BINARY_PLUS`] that does not re-associate. See
    /// `OpToken::left_to_right_only`.
    pub static FLOAT_PLUS: OpToken = float_op_token("+", 50, 1);
    /// Pointer adornment for a type declaration `*` (printc.cc:76).
    pub static PTR_EXPR: OpToken = op_token("*", "", 1, 62, false, TokenType::UnaryPrefix, 0, 0);
    /// Array adornment for a type declaration `[ ]` (printc.cc:77).
    pub static ARRAY_EXPR: OpToken = op_token("[", "]", 2, 66, false, TokenType::Postsurround, 1, 0);
    /// The concatenation operator `|` for enumerated values (printc.cc:78).
    pub static ENUM_CAT: OpToken = op_token("|", "", 2, 26, true, TokenType::Binary, 0, 0);
}

/// The complementary (negated) token for the six comparison operators
/// (C++ `PrintC::PrintC` flip-token assignments, printc.cc:130-135).
///
/// In C++ these are stored in each `OpToken::negate` field, set in the
/// constructor.  Because a `static OpToken` cannot hold a `&'static` reference
/// to another `static` defined later (no self-referential statics), the link is
/// realized here as a pointer-identity lookup — the only consumer is
/// `op_binary` reading the complement under the `negatetoken` modifier.
/// Returns `None` for any token without a complement (every C++ token whose
/// `negate` stays null).
pub fn token_negate(tok: &'static OpToken) -> Option<&'static OpToken> {
    use tokens::*;
    // (kuna outlang) A language whose comparison tokens are its own statics
    // carries the pairing on the token (`OpToken::negate`, the C++ field the port
    // left unset because Rust statics cannot self-reference -- they CAN reference
    // each other). The C table below is unreachable for those.
    if let Some(n) = tok.negate {
        return Some(n);
    }
    if std::ptr::eq(tok, &LESS_THAN) {
        Some(&GREATER_EQUAL)
    } else if std::ptr::eq(tok, &LESS_EQUAL) {
        Some(&GREATER_THAN)
    } else if std::ptr::eq(tok, &GREATER_THAN) {
        Some(&LESS_EQUAL)
    } else if std::ptr::eq(tok, &GREATER_EQUAL) {
        Some(&LESS_THAN)
    } else if std::ptr::eq(tok, &EQUAL) {
        Some(&NOT_EQUAL)
    } else if std::ptr::eq(tok, &NOT_EQUAL) {
        Some(&EQUAL)
    } else {
        None
    }
}

// ===========================================================================
// Keyword / punctuation constants (printc.cc:80-104)
// ===========================================================================

/// The c-language keyword and punctuation tokens (C++ `PrintC::EMPTY_STRING`
/// .. `PrintC::typePointerRelToken`, printc.cc:80-104).
pub mod keywords {
    /// An empty token (printc.cc:80).
    pub const EMPTY_STRING: &str = "";
    /// `"{"` token (printc.cc:81).
    pub const OPEN_CURLY: &str = "{";
    /// `"}"` token (printc.cc:82).
    pub const CLOSE_CURLY: &str = "}";
    /// `";"` token (printc.cc:83).
    pub const SEMICOLON: &str = ";";
    /// `":"` token (printc.cc:84).
    pub const COLON: &str = ":";
    /// `"="` token (printc.cc:85).
    pub const EQUALSIGN: &str = "=";
    /// `","` token (printc.cc:86).
    pub const COMMA: &str = ",";
    /// `"..."` token (printc.cc:87).
    pub const DOTDOTDOT: &str = "...";
    /// `"void"` keyword (printc.cc:88).
    pub const KEYWORD_VOID: &str = "void";
    /// `"true"` keyword (printc.cc:89).
    pub const KEYWORD_TRUE: &str = "true";
    /// `"false"` keyword (printc.cc:90).
    pub const KEYWORD_FALSE: &str = "false";
    /// `"if"` keyword (printc.cc:91).
    pub const KEYWORD_IF: &str = "if";
    /// `"else"` keyword (printc.cc:92).
    pub const KEYWORD_ELSE: &str = "else";
    /// `"do"` keyword (printc.cc:93).
    pub const KEYWORD_DO: &str = "do";
    /// `"while"` keyword (printc.cc:94).
    pub const KEYWORD_WHILE: &str = "while";
    /// `"for"` keyword (printc.cc:95).
    pub const KEYWORD_FOR: &str = "for";
    /// `"goto"` keyword (printc.cc:96).
    pub const KEYWORD_GOTO: &str = "goto";
    /// `"break"` keyword (printc.cc:97).
    pub const KEYWORD_BREAK: &str = "break";
    /// `"continue"` keyword (printc.cc:98).
    pub const KEYWORD_CONTINUE: &str = "continue";
    /// `"case"` keyword (printc.cc:99).
    pub const KEYWORD_CASE: &str = "case";
    /// `"switch"` keyword (printc.cc:100).
    pub const KEYWORD_SWITCH: &str = "switch";
    /// `"default"` keyword (printc.cc:101).
    pub const KEYWORD_DEFAULT: &str = "default";
    /// `"return"` keyword (printc.cc:102).
    pub const KEYWORD_RETURN: &str = "return";
    /// `"new"` keyword (printc.cc:103).
    pub const KEYWORD_NEW: &str = "new";
    /// The token printed for a PTRSUB relative to a `TypePointerRel`
    /// (C++ `typePointerRelToken = "ADJ"`, printc.cc:104).
    pub const TYPE_POINTER_REL_TOKEN: &str = "ADJ";
}

// ===========================================================================
// Symbol display-format constants (Symbol::force_*, used by push_integer)
// ===========================================================================

/// The `Symbol::force_*` display-format selectors used by [`format_integer_token`]
/// (C++ `Symbol` anon enum; identical to [`crate::database::symbol_dispflags`]).
/// Re-stated here so the formatter is self-describing and matches the C++
/// `displayFormat` switch (printc.cc:1410-1429) value-for-value.
pub mod display_format {
    /// No format forced (C++ `0`).
    pub const NONE: u32 = 0;
    /// Force hexadecimal (`Symbol::force_hex`).
    pub const FORCE_HEX: u32 = 1;
    /// Force decimal (`Symbol::force_dec`).
    pub const FORCE_DEC: u32 = 2;
    /// Force octal (`Symbol::force_oct`).
    pub const FORCE_OCT: u32 = 3;
    /// Force binary (`Symbol::force_bin`).
    pub const FORCE_BIN: u32 = 4;
    /// Force character (`Symbol::force_char`).
    pub const FORCE_CHAR: u32 = 5;
}

// ===========================================================================
// PrintC options (printc.hh:146-156, 242-255; printc.cc:1649-1664)
// ===========================================================================

/// The PrintC-specific options block (C++ `PrintC` `option_*` members,
/// printc.hh:146-156).
///
/// `resetDefaultsPrintC` (printc.cc:1649-1664) establishes the defaults; the
/// `set*` methods (printc.hh:242-255) are the toggles wired from the options.cc
/// `// STUB(W8)` markers (`PrintC::setNULLPrinting(val)` etc.).  The kuna
/// `arraynotation` toggle (printc.hh:250-251) and its DIV-2 default-on
/// (printc.cc:1658) are carried here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PrintCOptions {
    /// Emit a `NULL` token for a null pointer (C++ `option_NULL`).
    pub null: bool,
    /// Use `+=` / `&=` etc. in-place operators (C++ `option_inplace_ops`).
    pub inplace_ops: bool,
    /// Print the calling convention (C++ `option_convention`).
    pub convention: bool,
    /// Do not print casts (C++ `option_nocasts`).
    pub nocasts: bool,
    /// Display unplaced comments (C++ `option_unplaced`).
    pub unplaced: bool,
    /// Hide implied extension operations (C++ `option_hide_exts`).
    pub hide_exts: bool,
    /// (kuna) Render standalone PTRADD as `&base[index]` rather than
    /// `base + index` (C++ `option_arraynotation`, printc.hh:152).
    pub array_notation: bool,
    /// (kuna) In boolean contexts (if/while/for/ternary conditions, `&&`/`||`/
    /// `!` operands), render `x != 0` as `x` and `x == 0` as `!x` (DIV-37,
    /// `option truthycond`).  Float compares, enum-typed and equate-named
    /// zeros are excluded; value contexts (`v = (x != 0)`) never normalize.
    pub truthy_cond: bool,
    /// (kuna) A single-statement if-body drops its braces and prints the
    /// statement indented on the next line (DIV-38, `option braceelide`).
    /// Copy-leaf single-statement bodies only; labels/comments keep braces.
    pub brace_elide: bool,
    /// (kuna) Warnings render as terse `// slug` end-of-line comments on the
    /// statement they describe instead of full `/* WARNING: ... */` banner
    /// lines (DIV-39, `option warnstyle inline|banner`).
    pub warn_inline: bool,
    /// (kuna) An access spanning more than one element of a mapped array Symbol
    /// renders as the width-carrying `name._<off>_<size>_` field instead of a
    /// subscript / bare name (`option arraycoverwidth`).
    pub array_cover_width: bool,
    /// (kuna) A constant pointer whose readonly target spells a ZERO-character
    /// string declines the `""` literal and prints its address instead
    /// (`option emptystrconst`).
    pub empty_str_const: bool,
    /// (kuna) Print the definitions of the composite/enum/typedef types this
    /// function's C names ABOVE the function (`option structdefs`).  See
    /// [`crate::kuna_structdefs`].
    pub struct_defs: bool,
    /// (kuna) A pointer-typed constant that addresses program data prints as
    /// `&dat_<addr>` rather than `(T *)0x<addr>` (`option globalref`).  See
    /// [`crate::kuna_globalref`].
    pub global_ref: bool,
    /// How function-declaration braces are formatted (C++ `option_brace_func`).
    pub brace_func: BraceStyle,
    /// How if/else-block braces are formatted (C++ `option_brace_ifelse`).
    pub brace_ifelse: BraceStyle,
    /// How loop-block braces are formatted (C++ `option_brace_loop`).
    pub brace_loop: BraceStyle,
    /// How switch-block braces are formatted (C++ `option_brace_switch`).
    pub brace_switch: BraceStyle,
}

impl Default for PrintCOptions {
    fn default() -> Self {
        Self::new()
    }
}

impl PrintCOptions {
    /// Construct with the `resetDefaultsPrintC` defaults (printc.cc:1649-1664).
    ///
    /// Note the kuna DIV-2 default-on `array_notation = true` (printc.cc:1658),
    /// the `&base[index]` form for a standalone PTRADD (GH-558), the kuna
    /// DIV-34 `brace_func = NextLine` (upstream `Emit::skip_line` leaves a blank
    /// line between the prototype and `{`; `option braceformat function skip`
    /// restores it), the kuna DIV-35 `null = true` (a zero pointer constant
    /// renders as `NULL`, not `(type *)0x0`; `option nullprinting off`
    /// restores the casted form), and the kuna DIV-36 `inplace_ops = true`
    /// (`out = out OP y` renders as `out OP= y` via the ported
    /// `emitInplaceOp`; `option inplaceops off` restores).
    pub fn new() -> PrintCOptions {
        PrintCOptions {
            convention: true,
            hide_exts: true,
            inplace_ops: true, // (kuna) DIV-36; upstream flag default off + never consumed
            nocasts: false,
            null: true, // (kuna) DIV-35; upstream option_NULL default off
            unplaced: false,
            array_notation: true, // (kuna) DIV-2 default-on (GH-558)
            truthy_cond: true, // (kuna) DIV-37; no upstream equivalent
            brace_elide: true, // (kuna) DIV-38; no upstream equivalent
            warn_inline: true, // (kuna) DIV-39; no upstream equivalent
            array_cover_width: true, // (kuna) no upstream equivalent
            empty_str_const: true,   // (kuna) no upstream equivalent
            struct_defs: false,      // (kuna) no upstream equivalent; opt-in
            global_ref: true,        // (kuna) no upstream equivalent
            brace_func: BraceStyle::NextLine,   // (kuna) DIV-34; upstream Emit::skip_line
            brace_ifelse: BraceStyle::SameLine, // Emit::same_line
            brace_loop: BraceStyle::SameLine,   // Emit::same_line
            brace_switch: BraceStyle::SameLine, // Emit::same_line
        }
    }

    /// C++ `setNULLPrinting(val)` (printc.hh:242).
    pub fn set_null_printing(&mut self, val: bool) {
        self.null = val;
    }
    /// C++ `setInplaceOps(val)` (printc.hh:243).
    pub fn set_inplace_ops(&mut self, val: bool) {
        self.inplace_ops = val;
    }
    /// C++ `setConvention(val)` (printc.hh:244).
    pub fn set_convention(&mut self, val: bool) {
        self.convention = val;
    }
    /// C++ `setNoCastPrinting(val)` (printc.hh:245).
    pub fn set_no_cast_printing(&mut self, val: bool) {
        self.nocasts = val;
    }
    /// C++ `setDisplayUnplaced(val)` (printc.hh:248).
    pub fn set_display_unplaced(&mut self, val: bool) {
        self.unplaced = val;
    }
    /// C++ `setHideImpliedExts(val)` (printc.hh:249).
    pub fn set_hide_implied_exts(&mut self, val: bool) {
        self.hide_exts = val;
    }
    /// (kuna) C++ `setArrayNotation(val)` (printc.hh:250).
    pub fn set_array_notation(&mut self, val: bool) {
        self.array_notation = val;
    }
    /// (kuna) Toggle truthy condition rendering (`option truthycond`, DIV-37).
    pub fn set_truthy_cond(&mut self, val: bool) {
        self.truthy_cond = val;
    }
    /// (kuna) Current truthy-condition rendering flag.
    pub fn truthy_cond(&self) -> bool {
        self.truthy_cond
    }
    /// (kuna) Toggle single-statement if-body brace elision (`option
    /// braceelide`, DIV-38).
    pub fn set_brace_elide(&mut self, val: bool) {
        self.brace_elide = val;
    }
    /// (kuna) Current brace-elision flag.
    pub fn brace_elide(&self) -> bool {
        self.brace_elide
    }
    /// (kuna) Toggle the width-carrying multi-element array-cover render
    /// (`option arraycoverwidth`).
    pub fn set_array_cover_width(&mut self, val: bool) {
        self.array_cover_width = val;
    }
    /// (kuna) Current array-cover width flag.
    pub fn array_cover_width(&self) -> bool {
        self.array_cover_width
    }
    /// (kuna) Toggle the zero-character string-constant suppression
    /// (`option emptystrconst`).
    pub fn set_empty_str_const(&mut self, val: bool) {
        self.empty_str_const = val;
    }
    /// (kuna) Current empty-string-constant flag.
    pub fn empty_str_const(&self) -> bool {
        self.empty_str_const
    }
    /// (kuna `structdefs`) Print the referenced type definitions above the
    /// function.
    pub fn set_struct_defs(&mut self, val: bool) {
        self.struct_defs = val;
    }
    /// (kuna `structdefs`) Is the per-function type-definition preamble on?
    pub fn struct_defs(&self) -> bool {
        self.struct_defs
    }
    /// (kuna `globalref`) Name constant addresses as the globals they point at.
    pub fn set_global_ref(&mut self, val: bool) {
        self.global_ref = val;
    }
    /// (kuna `globalref`) Current constant-address naming flag.
    pub fn global_ref(&self) -> bool {
        self.global_ref
    }
    /// (kuna) Toggle inline warning style (`option warnstyle`, DIV-39).
    pub fn set_warn_inline(&mut self, val: bool) {
        self.warn_inline = val;
    }
    /// (kuna) Current warning-style flag (true = inline `// slug`).
    pub fn warn_inline(&self) -> bool {
        self.warn_inline
    }
    /// (kuna) C++ `getArrayNotation()` (printc.hh:251).
    pub fn array_notation(&self) -> bool {
        self.array_notation
    }
    /// C++ `setBraceFormatFunction(style)` (printc.hh:252).
    pub fn set_brace_format_function(&mut self, style: BraceStyle) {
        self.brace_func = style;
    }
    /// C++ `setBraceFormatIfElse(style)` (printc.hh:253).
    pub fn set_brace_format_ifelse(&mut self, style: BraceStyle) {
        self.brace_ifelse = style;
    }
    /// C++ `setBraceFormatLoop(style)` (printc.hh:254).
    pub fn set_brace_format_loop(&mut self, style: BraceStyle) {
        self.brace_loop = style;
    }
    /// C++ `setBraceFormatSwitch(style)` (printc.hh:255).
    pub fn set_brace_format_switch(&mut self, style: BraceStyle) {
        self.brace_switch = style;
    }
}

// ===========================================================================
// Self-contained constant / type formatting
// ===========================================================================

/// The first run of decimal digits in `s`, parsed — the `{changes}` count a
/// count-carrying warning text embeds.
fn first_integer(s: &str) -> Option<u64> {
    let mut started = false;
    let mut out = String::new();
    for c in s.chars() {
        if c.is_ascii_digit() {
            started = true;
            out.push(c);
        } else if started {
            break;
        }
    }
    out.parse().ok()
}

/// (kuna warnstyle, DIV-39) Map a stored warning text (which carries its
/// `WARNING: ` / `WARNING (jumptable): ` prefix from `Funcdata::warning_prefix`)
/// to the terse `// slug` form.  Producer-tagged kuna warnings (`branchflip:`,
/// `taildup:`, ...) map by their stable prefix; upstream texts by their stable
/// stem; anything unrecognized keeps its full text behind a `warn:` marker so
/// no information is silently dropped.  Count-carrying header warnings
/// (`earlyreturn: hoisted 3 ...`) keep the count as an ` xN` suffix.
pub fn warning_slug(text: &str) -> String {
    let (body, jumptable) = if let Some(rest) = text.strip_prefix("WARNING (jumptable): ") {
        (rest, true)
    } else if let Some(rest) = text.strip_prefix("WARNING: ") {
        (rest, false)
    } else {
        (text, false)
    };
    // First integer in the body (the `{changes}` count of the P8 header warnings).
    let count: Option<u64> = first_integer(body);
    let xn = |slug: &str| -> String {
        match count {
            Some(n) if n > 1 => format!("{slug} x{n}"),
            _ => slug.to_string(),
        }
    };
    let slug = if body.starts_with("Subroutine does not return")
        || body.starts_with("Does not return")
    {
        "no-return".to_string()
    } else if body.starts_with("Treating indirect jump as call") {
        "jump-as-call".to_string()
    } else if body.starts_with("Treating indirect jump as return") {
        "jump-as-return".to_string()
    } else if body.starts_with("Could not inline here")
        || body.starts_with("No fallthrough prevents inlining here")
        || body.starts_with("Return address prevents inlining here")
    {
        "inline-failed".to_string()
    } else if body.starts_with("Read-only address") {
        "writes-rodata".to_string()
    } else if body.starts_with("branchflip:") {
        "branch-flip".to_string()
    } else if body.starts_with("tailcalljump:") {
        "tail-call".to_string()
    } else if body.starts_with("taildup:") {
        "return-dupe".to_string()
    } else if body.starts_with("crossjumprevert:") {
        "crossjump-dupe".to_string()
    } else if let Some(rest) = body.strip_prefix("int3pad:") {
        // The count is read from the text AFTER the tag: the tag itself carries a
        // digit, so the shared `count` above would report it as the pad length.
        match first_integer(rest) {
            Some(n) if n > 1 => format!("int3-pad x{n}"),
            _ => "int3-pad".to_string(),
        }
    } else if body.starts_with("outline:") {
        xn("outlined")
    } else if body.starts_with("returndup:") {
        xn("return-dupe")
    } else if body.starts_with("earlyreturn:") {
        xn("early-return")
    } else if body.starts_with("switchreturn:") {
        xn("switch-return")
    } else if body.starts_with("dedupitetail:") {
        xn("ite-dedupe")
    } else if body.starts_with("iteregion:") {
        xn("ternary")
    } else if body.starts_with("ifelseflatten:") {
        xn("else-flattened")
    } else if let Some(name) = body.strip_prefix("Inlined function: ") {
        format!("inlined: {name}")
    } else if body.starts_with("Function: ") && body.contains("replaced with injection") {
        "injected".to_string()
    } else if body.starts_with("Unable to use symbol") {
        "symbol-size-mismatch".to_string()
    } else {
        format!("warn: {body}")
    };
    if jumptable {
        format!("jt: {slug}")
    } else {
        slug
    }
}

/// C++ `PrintC::printCharHexEscape` (printc.cc:1580-1591).
///
/// Append `\x` followed by `val` in lowercase hex, zero-padded to 2/4/8 digits
/// by magnitude.  Transcribed including the `setfill('0')`/`setw` widths.
pub fn print_char_hex_escape(s: &mut String, val: int4) {
    use std::fmt::Write;
    if val < 256 {
        let _ = write!(s, "\\x{val:02x}");
    } else if val < 65536 {
        let _ = write!(s, "\\x{val:04x}");
    } else {
        let _ = write!(s, "\\x{val:08x}");
    }
}

/// C++ `PrintC::printUnicode` (printc.cc:1494-1538).
///
/// Emit a single (unicode) codepoint into a quoted-string/char context: special
/// C escapes for the small control characters, a generic `\x` escape for other
/// escape-needing codepoints, otherwise the raw UTF-8 bytes.  Transcribed
/// case-for-case from the C++ switch; the final non-escape branch is the C++
/// `StringManager::writeUtf8` (encoded here as a `char` push when the codepoint
/// is a valid scalar value, matching the UTF-8 byte emission).
pub fn print_unicode(s: &mut String, onechar: int4) {
    if unicode_needs_escape(onechar) {
        match onechar {
            0 => {
                s.push_str("\\0");
                return;
            }
            7 => {
                s.push_str("\\a");
                return;
            }
            8 => {
                s.push_str("\\b");
                return;
            }
            9 => {
                s.push_str("\\t");
                return;
            }
            10 => {
                s.push_str("\\n");
                return;
            }
            11 => {
                s.push_str("\\v");
                return;
            }
            12 => {
                s.push_str("\\f");
                return;
            }
            13 => {
                s.push_str("\\r");
                return;
            }
            92 => {
                s.push_str("\\\\");
                return;
            }
            0x22 => {
                // '"'
                s.push_str("\\\"");
                return;
            }
            0x27 => {
                // '\''
                s.push_str("\\\'");
                return;
            }
            _ => {}
        }
        // Generic escape code (C++ printCharHexEscape).
        print_char_hex_escape(s, onechar);
        return;
    }
    // C++ `StringManager::writeUtf8(s, onechar)` — emit the UTF-8 bytes of the
    // codepoint.  `char::from_u32` yields the same bytes Rust's UTF-8 encoder
    // and the C++ writer produce for any valid scalar value.
    if let Some(c) = char::from_u32(onechar as u32) {
        s.push(c);
    }
}

/// The Rust spelling of one codepoint inside a double-quoted string body.
///
/// (kuna outlang) Rust's escape set is a strict subset of C's in the ways that
/// matter here: it has no `\a`/`\b`/`\v`/`\f`, so those become `\xNN`; and a
/// single quote inside a `"..."` must be BARE, because `\'` is only an escape in
/// a character literal and `"PCRE\'s"` does not tokenize. Everything else --
/// `\0`, `\t`, `\n`, `\r`, `\\`, `\"`, printable ASCII, and any valid scalar
/// value emitted as UTF-8 -- spells identically in both languages.
pub fn print_unicode_rust(s: &mut String, onechar: int4) {
    if unicode_needs_escape(onechar) {
        match onechar {
            0 => s.push_str("\\0"),
            9 => s.push_str("\\t"),
            10 => s.push_str("\\n"),
            13 => s.push_str("\\r"),
            92 => s.push_str("\\\\"),
            0x22 => s.push_str("\\\""),
            // A bare `'` -- escaping it is what breaks the tokenizer.
            0x27 => s.push('\''),
            _ => print_char_hex_escape(s, onechar),
        }
        return;
    }
    if let Some(c) = char::from_u32(onechar as u32) {
        s.push(c);
    }
}

/// The string body of C++ `PrintC::push_integer` (printc.cc:1407-1434) — the
/// byte-for-byte token characters for an integer constant, given the
/// already-resolved sign decision and display format.
///
/// Mirrors the C++ `ostringstream t` construction exactly: optional leading
/// `-`, then the format-specific digits (`0x`+lower-hex / decimal / `0`+octal /
/// quoted char / `0b`+binary), then the optional `U` and size suffix.
///
/// `print_negsign`/`val`/`display_fmt`/`sz` are the values the C++ computes
/// before line 1407 (the sign-stripping at printc.cc:1381-1391 and the
/// hex/dec decision at printc.cc:1393-1405); [`resolve_integer_format`] computes
/// them so callers can reproduce the full path.  `force_unsigned`/`force_sized`
/// are the `vn->isUnsignedPrint()`/`isLongPrint()` flags (printc.cc:1378-1379);
/// `wide_char_prefix` is `doEmitWideCharPrefix()` (printc.cc:1417);
/// `size_suffix` is the `sizeSuffix` member (printc.cc:1433).
#[allow(clippy::too_many_arguments)]
pub fn format_integer_token(
    print_negsign: bool,
    val: uintb,
    display_fmt: u32,
    sz: int4,
    force_unsigned: bool,
    force_sized: bool,
    wide_char_prefix: bool,
    size_suffix: &str,
) -> String {
    use std::fmt::Write;
    let mut t = String::new();
    if print_negsign {
        t.push('-');
    }
    if display_fmt == display_format::FORCE_HEX {
        let _ = write!(t, "0x{val:x}");
    } else if display_fmt == display_format::FORCE_DEC {
        let _ = write!(t, "{val}");
    } else if display_fmt == display_format::FORCE_OCT {
        let _ = write!(t, "0{val:o}");
    } else if display_fmt == display_format::FORCE_CHAR {
        if wide_char_prefix && sz > 1 {
            t.push('L'); // wide character marker
        }
        t.push('\''); // char surrounded with single quotes
        if sz == 1 && val >= 0x80 {
            print_char_hex_escape(&mut t, val as int4);
        } else {
            print_unicode(&mut t, val as int4);
        }
        t.push('\'');
    } else {
        // Must be Symbol::force_bin
        t.push_str("0b");
        format_binary(&mut t, val);
    }
    if force_unsigned {
        t.push('U'); // force unsignedness explicitly
    }
    if force_sized {
        t.push_str(size_suffix);
    }
    t
}

/// Whether `val` at `sz` bytes has a Rust byte-literal spelling.
///
/// Rust byte literals are one byte, and `format_integer_token`'s escape set
/// (`print_unicode`) emits `\n`/`\t`/`\r`/`\0`/`\\`/`\'` plus printable ASCII --
/// all of which a `b'...'` accepts. Anything wider, or a byte outside that set,
/// has no byte-literal form and is rendered as the integer instead.
fn rust_byte_literal_spellable(val: uintb, sz: int4) -> bool {
    if sz != 1 {
        return false;
    }
    matches!(val, 0x20..=0x7e) || matches!(val, 0 | 0x09 | 0x0a | 0x0d)
}

/// The `print_negsign`/`val`/`display_fmt` resolution C++ `push_integer`
/// performs before formatting (printc.cc:1381-1405).
///
/// `sign` is the signedness request; `force_hex`/`force_dec` are the active
/// `mods` bits.  Returns `(print_negsign, val_to_print, display_fmt)`.  The
/// caller still owns the `vn`/`Symbol`-driven `displayFormat` override and the
/// equate short-circuit (printc.cc:1368-1380), which need the W7 Varnode/Symbol
/// graph; `display_fmt_in` is whatever override they resolved (`0` for none).
pub fn resolve_integer_format(
    mut val: uintb,
    sz: int4,
    sign: bool,
    display_fmt_in: u32,
    force_hex: bool,
    force_dec: bool,
) -> (bool, uintb, u32) {
    let print_negsign;
    // Sign handling (printc.cc:1381-1391).
    if sign && display_fmt_in != display_format::FORCE_CHAR {
        let mask = calc_mask(sz);
        let flip = val ^ mask;
        print_negsign = flip < val;
        if print_negsign {
            // C++ `val = flip+1;` — two's-complement magnitude.
            val = flip.wrapping_add(1);
        }
    } else {
        print_negsign = false;
    }

    // Hex/dec decision (printc.cc:1393-1405).
    let display_fmt = if display_fmt_in != display_format::NONE {
        display_fmt_in // forced by the Symbol or data-type
    } else if force_hex {
        display_format::FORCE_HEX
    } else if val <= 10 || force_dec {
        display_format::FORCE_DEC
    } else if most_natural_base(val) == 16 {
        display_format::FORCE_HEX
    } else {
        display_format::FORCE_DEC
    };
    (print_negsign, val, display_fmt)
}

/// The classification a host float resolves to (C++ `FloatFormat::floatclass`),
/// supplied by the caller of [`format_float_token`] from the
/// `glb->translate->getFloatFormat(sz)` decode plus
/// [`kuna_num::float::FloatFormat::get_host_float`] (W6, kuna-num).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FloatClass {
    /// A normal finite value (the `printDecimal` path).
    Normal,
    /// Positive or negative infinity.
    Infinity,
    /// Not-a-number.
    Nan,
    /// No `FloatFormat` for the size (`FLOAT_UNKNOWN`).
    Unknown,
}

/// The string body of C++ `PrintC::push_float` (printc.cc:1449-1492) — the
/// byte-for-byte token characters for a floating-point constant.
///
/// The `FloatFormat` decode (`getHostFloat`/`extractSign`/`printDecimal`) is a
/// W6 boundary (`FloatFormat`, `float.cc`, a separate item).  In particular
/// `printDecimal` is the shortest-round-trip precision loop at float.cc:446-479
/// — **not** a fixed-precision `%g` — so it must come from `FloatFormat`, not be
/// reinvented here.  This function therefore takes the *already-decoded*
/// results: the [`FloatClass`], the sign, and (for [`FloatClass::Normal`]) the
/// [`kuna_num::float::FloatFormat::print_decimal`]`(floatval, force_scinote)`
/// string the caller obtained from `FloatFormat`.  It reproduces only the parts
/// that live in `push_float`
/// itself: the `INFINITY`/`NAN`/`FLOAT_UNKNOWN` names (printc.cc:1454-1469) and
/// the `.0` suffix forced onto a non-scientific decimal that doesn't already
/// look like a float (printc.cc:1477-1487).
///
/// `force_scinote` is the active `mods & force_scinote` bit (printc.cc:1472);
/// when set the C++ skips the `.0` fix-up (the scientific form always has an
/// `e`), so `printed_decimal` is returned verbatim.
pub fn format_float_token(
    class: FloatClass,
    sign: bool,
    printed_decimal: &str,
    force_scinote: bool,
) -> String {
    match class {
        FloatClass::Unknown => "FLOAT_UNKNOWN".to_string(),
        FloatClass::Infinity => {
            if sign {
                "-INFINITY".to_string()
            } else {
                "INFINITY".to_string()
            }
        }
        FloatClass::Nan => {
            if sign {
                "-NAN".to_string()
            } else {
                "NAN".to_string()
            }
        }
        FloatClass::Normal => {
            if force_scinote {
                // C++ `token = format->printDecimal(floatval, true)` — used as is.
                printed_decimal.to_string()
            } else {
                let mut token = printed_decimal.to_string();
                // printc.cc:1477-1487: force the token to look like a float.
                let looks_like_float = token.bytes().any(|c| c == b'.' || c == b'e');
                if !looks_like_float {
                    token.push_str(".0");
                }
                token
            }
        }
    }
}

/// C++ `PrintC::genericFunctionName` (printc.cc:3516-3526), the non-kuna
/// (`func_<addr>`) branch.
///
/// The kuna angr-style `sub_<addr>` branch (printc.cc:3519-3520) is gated on
/// `kunaAngrNaming(glb)`, an Architecture query the caller owns; pass the
/// already-decided flag.  When `angr_naming` is true the caller substitutes
/// `kunaFunctionName(addr)` (the `kuna_naming` module); this function produces
/// the plain `func_` + raw address form.
pub fn generic_function_name(addr: &Address) -> KunaResult<String> {
    let mut s = String::from("func_");
    addr.print_raw(&mut s)?;
    Ok(s)
}

/// C++ `PrintC::genericTypeName` (printc.cc:3532-3558).
///
/// A generic name for an unnamed data-type: an `unk*` prefix by metatype with
/// the size appended, or a `BADSPACEBASE`/`BADTYPE` sentinel.  Transcribed
/// case-for-case.
pub fn generic_type_name(metatype: type_metatype, size: int4) -> String {
    use std::fmt::Write;
    use type_metatype::*;
    let mut s = String::new();
    let prefix = match metatype {
        TYPE_INT => "unkint",
        TYPE_UINT => "unkuint",
        TYPE_UNKNOWN => "unkbyte",
        TYPE_SPACEBASE => return "BADSPACEBASE".to_string(),
        TYPE_FLOAT => "unkfloat",
        _ => return "BADTYPE".to_string(),
    };
    s.push_str(prefix);
    let _ = write!(s, "{size}");
    s
}

// ===========================================================================
// Opcode -> token dispatch (printc.hh:289-351)
// ===========================================================================

/// How a `PcodeOp` is pushed onto the RPN stack by the `PrintC` `op*` override
/// (the C++ inline bodies in printc.hh:289-351).
///
/// This is the *data* half of those overrides: which [`OpToken`] and which RPN
/// form.  The *emission* (the actual `opBinary`/`opUnary`/`opFunc`/`opTypeCast`
/// call that pushes onto the stack and drives `Emit`) is the W9 stub.
#[derive(Debug, Clone, Copy)]
pub enum OpEmitKind {
    /// `opBinary(&token, op)` — a binary operator (printc.hh `opBinary` form).
    Binary(&'static OpToken),
    /// `opUnary(&token, op)` — a unary-prefix operator (printc.hh `opUnary` form).
    Unary(&'static OpToken),
    /// `opFunc(op)` — a functional `name(args)` form (printc.cc:444).
    Func,
    /// `opTypeCast(op)` — a type-cast form (printc.cc:468).
    TypeCast,
    /// The op has a hand-written override (`opLoad`/`opStore`/`opCall`/… and the
    /// no-op `opMultiequal`/`opIndirect`); not a simple table entry.
    Custom,
}

/// C++ `TypeOpSubpiece::computeByteOffsetForComposite(op)` (typeop.cc:2197): the
/// byte offset of the truncated piece into the assumed composite input, by
/// endianness.  `byteOff = isBigEndian ? (in0Size - outSize - lsb) : lsb`.
fn subpiece_byte_offset_for_composite(fd: &Funcdata, op: OpId) -> int8 {
    let o = match fd.obank().get(op) {
        Some(o) => o,
        None => return 0,
    };
    let lsb = o
        .get_in(1)
        .and_then(|v| fd.vbank().get(v))
        .map(|v| v.get_offset() as int8)
        .unwrap_or(0);
    let in0 = match o.get_in(0) {
        Some(v) => v,
        None => return lsb,
    };
    let big_endian = fd
        .vbank()
        .get(in0)
        .map(|v| v.get_space().is_big_endian())
        .unwrap_or(false);
    if big_endian {
        let in0_size = fd.vbank().get(in0).map(|v| v.get_size()).unwrap_or(0) as int8;
        let out_size = o
            .get_out()
            .and_then(|v| fd.vbank().get(v))
            .map(|v| v.get_size())
            .unwrap_or(0) as int8;
        in0_size - out_size - lsb
    } else {
        lsb
    }
}

/// The token/form each `PcodeOp` maps to in the C++ `PrintC` inline `op*`
/// overrides (printc.hh:289-351).
///
/// Returns the [`OpEmitKind`] for the opcodes whose override is a one-line
/// `opBinary`/`opUnary`/`opFunc`/`opTypeCast` delegation; [`OpEmitKind::Custom`]
/// for the opcodes with a hand-written body in printc.cc (those are stub-noted).
/// This is the faithful dispatch table; the emission it feeds is the W9 stub.
pub fn op_emit_kind(opcode: kuna_num::opcodes::OpCode) -> OpEmitKind {
    use kuna_num::opcodes::OpCode::*;
    use tokens::*;
    match opcode {
        // Comparisons (printc.hh:289-294, 319-322).
        CPUI_INT_EQUAL => OpEmitKind::Binary(&EQUAL),
        CPUI_INT_NOTEQUAL => OpEmitKind::Binary(&NOT_EQUAL),
        CPUI_INT_SLESS => OpEmitKind::Binary(&LESS_THAN),
        CPUI_INT_SLESSEQUAL => OpEmitKind::Binary(&LESS_EQUAL),
        CPUI_INT_LESS => OpEmitKind::Binary(&LESS_THAN),
        CPUI_INT_LESSEQUAL => OpEmitKind::Binary(&LESS_EQUAL),
        CPUI_FLOAT_EQUAL => OpEmitKind::Binary(&EQUAL),
        CPUI_FLOAT_NOTEQUAL => OpEmitKind::Binary(&NOT_EQUAL),
        CPUI_FLOAT_LESS => OpEmitKind::Binary(&LESS_THAN),
        CPUI_FLOAT_LESSEQUAL => OpEmitKind::Binary(&LESS_EQUAL),
        // Integer arithmetic (printc.hh:297-313).
        CPUI_INT_ADD => OpEmitKind::Binary(&BINARY_PLUS),
        CPUI_INT_SUB => OpEmitKind::Binary(&BINARY_MINUS),
        CPUI_INT_XOR => OpEmitKind::Binary(&BITWISE_XOR),
        CPUI_INT_AND => OpEmitKind::Binary(&BITWISE_AND),
        CPUI_INT_OR => OpEmitKind::Binary(&BITWISE_OR),
        CPUI_INT_LEFT => OpEmitKind::Binary(&SHIFT_LEFT),
        CPUI_INT_RIGHT => OpEmitKind::Binary(&SHIFT_RIGHT),
        CPUI_INT_SRIGHT => OpEmitKind::Binary(&SHIFT_SRIGHT),
        CPUI_INT_MULT => OpEmitKind::Binary(&MULTIPLY),
        CPUI_INT_DIV => OpEmitKind::Binary(&DIVIDE),
        CPUI_INT_SDIV => OpEmitKind::Binary(&DIVIDE),
        CPUI_INT_REM => OpEmitKind::Binary(&MODULO),
        CPUI_INT_SREM => OpEmitKind::Binary(&MODULO),
        // Integer unary (printc.hh:302-303).
        CPUI_INT_2COMP => OpEmitKind::Unary(&UNARY_MINUS),
        CPUI_INT_NEGATE => OpEmitKind::Unary(&BITWISE_NOT),
        // Integer functional (printc.hh:299-301).
        CPUI_INT_CARRY => OpEmitKind::Func,
        CPUI_INT_SCARRY => OpEmitKind::Func,
        CPUI_INT_SBORROW => OpEmitKind::Func,
        // Boolean (printc.hh:316-318).
        CPUI_BOOL_XOR => OpEmitKind::Binary(&BOOLEAN_XOR),
        CPUI_BOOL_AND => OpEmitKind::Binary(&BOOLEAN_AND),
        CPUI_BOOL_OR => OpEmitKind::Binary(&BOOLEAN_OR),
        // Float arithmetic (printc.hh:324-336).
        CPUI_FLOAT_ADD => OpEmitKind::Binary(&FLOAT_PLUS),
        CPUI_FLOAT_DIV => OpEmitKind::Binary(&DIVIDE),
        CPUI_FLOAT_MULT => OpEmitKind::Binary(&FLOAT_MULTIPLY),
        CPUI_FLOAT_SUB => OpEmitKind::Binary(&BINARY_MINUS),
        CPUI_FLOAT_NEG => OpEmitKind::Unary(&UNARY_MINUS),
        CPUI_FLOAT_NAN => OpEmitKind::Func,
        CPUI_FLOAT_ABS => OpEmitKind::Func,
        CPUI_FLOAT_SQRT => OpEmitKind::Func,
        CPUI_FLOAT_CEIL => OpEmitKind::Func,
        CPUI_FLOAT_FLOOR => OpEmitKind::Func,
        CPUI_FLOAT_ROUND => OpEmitKind::Func,
        CPUI_FLOAT_FLOAT2FLOAT => OpEmitKind::TypeCast,
        CPUI_FLOAT_TRUNC => OpEmitKind::TypeCast,
        // Cast (printc.hh:341).
        CPUI_CAST => OpEmitKind::TypeCast,
        // Misc functional (printc.hh:339, 350-351).
        CPUI_PIECE => OpEmitKind::Func,
        CPUI_POPCOUNT => OpEmitKind::Func,
        CPUI_LZCOUNT => OpEmitKind::Func,
        // Everything else has a hand-written override (printc.cc) or is a no-op
        // (opMultiequal/opIndirect, printc.hh:337-338).
        _ => OpEmitKind::Custom,
    }
}

// ===========================================================================
// The RPN/Emit-driven body of PrintC (w10-printc-body)
// ===========================================================================
//
// The `PrintLanguage` RPN driver (`pushOp`/`pushAtom`/`pushVn`/`recurse`/
// `emitOp`/`emitAtom`/`opBinary`/`opUnary`/`parentheses`, printlanguage.cc:
// 129-580) is now **ported** as the `impl PrintC` block below, driving the real
// `Emit` back-end (`prettyprint.rs`'s `EmitNoMarkup`).  It is byte-faithfully
// unit-tested against the C++ `emitOp`/`emitAtom`/`parentheses` logic (see the
// `rpn_*` tests) — `a + b`, `x = a`, `-a`, `a * (b + c)`, `a + b * c`,
// associativity, the negate-token flip, all match the upstream emitter.
//
// What is NOT yet driven over a real function body is the per-op IR leaf
// expansion (`recurse`'s `defOp->getOpcode()->push(...)` implied-op dispatch
// and `pushVnExplicit`'s Symbol/HighVariable/Datatype/constant resolution) plus
// the structured-/flat-block walk (`emitBlock*`).  Those are blocked NOT in the
// printer but UPSTREAM: the merged tree's decompilation passes (heritage /
// simplification / merge / type + proto recovery / block structuring) are
// stubs, so the IR reaching the printer is raw lifted p-code with no
// HighVariables-with-symbols, no recovered types, and **empty `sblocks`**.
// Printing it would emit non-C garbage, not byte-parity.  Those edges are
// `// STUB(decompile-passes)` (LOSS-130 / W10) and fall to the upstream pass
// items; the RPN engine they feed is in place here.
//
// The remaining data this module provides (the token table, negate links,
// keyword constants, options, the constant/float/char formatters, and the
// opcode dispatch) is exactly what those bodies consume:
//   - `parentheses` (printlanguage.rs) reads the `tokens::*` precedence data;
//   - `push_integer`/`push_float`/`pushCharConstant` reduce to
//     `format_integer_token`/`format_float_token`/`print_unicode`;
//   - the `op*` overrides reduce to `op_emit_kind` + `op_binary`/`op_unary`/…;
//   - the option toggles (`PrintCOptions`) gate the stubbed branches.

// ===========================================================================
// PrintEmit — the emit back-end selector (static, no-vtable delegation)
// ===========================================================================

/// The [`Emit`] back-end `PrintC` drives: raw text and raw token capture preserve
/// CLI coordinates; host documents use [`EmitPrettyPrint`] over packed markup.
///
/// C++ swaps a heap `Emit *lowlevel` in `EmitPrettyPrint::setMarkup`
/// (prettyprint.cc:2531); this port holds the back-ends in a concrete enum
/// so every one of the ~260 `self.emit.<method>()` call sites in `PrintC` stays
/// a **static** call that matches on the active variant — no `Box<dyn Emit>`,
/// no vtable on the hot path (the standalone datatest path is always
/// `NoMarkup`).  Mirrors the [`crate::prettyprint::LowLevel`] precedent
/// (prettyprint.rs:1740) but delegates the FULL `Emit` surface by static match
/// rather than through a `&mut dyn Emit` re-dispatch.
///
/// The delegation MUST cover every `Emit` method — required AND
/// default-provided — because [`EmitNoMarkup`] overrides `tag_line`
/// (pending-brace absorption, prettyprint.rs:603) and `clear`: a method left to
/// fall through to a `PrintEmit` trait default would silently diverge the
/// byte-exact `print C` output the 675 datatests pin.
#[derive(Debug)]
pub enum PrintEmit {
    /// The plain-text back-end (`print C`, the byte-exact datatest path).
    NoMarkup(EmitNoMarkup),
    /// Raw packed clang tokens, including standalone CLI source-map capture.
    Markup(EmitMarkup),
    /// Width-aware host document. Raw CLI capture deliberately bypasses it.
    Pretty(EmitPrettyPrint),
}

/// Forward one [`Emit`] call to whichever [`PrintEmit`] variant is active — the
/// static match that stands in for C++'s `Emit *` vtable dispatch.
macro_rules! pe_forward {
    ($self:ident . $method:ident ( $($arg:expr),* )) => {
        match $self {
            PrintEmit::NoMarkup(e) => e.$method($($arg),*),
            PrintEmit::Markup(e) => e.$method($($arg),*),
            PrintEmit::Pretty(e) => e.$method($($arg),*),
        }
    };
}

impl PrintEmit {
    fn emit_type_text(&mut self, text: TypeText, markup: &MarkupRef, origin: TypeTextOrigin) {
        let (text, spans) = text.into_parts();
        let color = match origin {
            TypeTextOrigin::Type => SyntaxHighlight::TypeColor,
            TypeTextOrigin::Syntax => SyntaxHighlight::NoColor,
        };
        self.tag_type_text(&text, color, markup, spans, origin);
    }

    /// Reset the active back-end's output buffer (C++ `Emit::setOutputStream`),
    /// dispatched to the concrete leaf (both leaves clear their owned sink).
    /// Type-divergent (not on the [`Emit`] trait): the leaves' sinks differ.
    pub fn set_output_stream(&mut self) {
        match self {
            PrintEmit::NoMarkup(e) => e.set_output_stream(),
            PrintEmit::Markup(e) => e.set_output_stream(),
            PrintEmit::Pretty(e) => e.set_output_stream(),
        }
    }
    /// Borrow the accumulated plain text (the `EmitNoMarkup` standalone
    /// `doc_function_full` return).  The markup leaf holds packed bytes, not
    /// text, so it yields `""` (mirrors [`crate::prettyprint::LowLevel::output`]).
    pub fn output_str(&self) -> &str {
        match self {
            PrintEmit::NoMarkup(e) => e.output(),
            PrintEmit::Markup(_) => "",
            PrintEmit::Pretty(e) => e.output(),
        }
    }
    /// Take ownership of the accumulated packed markup bytes (the `EmitMarkup`
    /// `doc_function_markup` return); empty on the plain-text leaf.
    pub fn take_markup_bytes(&mut self) -> Vec<u8> {
        self.markup_sink_mut().map(EmitMarkup::take_output).unwrap_or_default()
    }
    /// Take the structured associations captured by the markup leaf.
    pub fn take_markup_provenance(&mut self) -> MarkupProvenance {
        self.markup_sink_mut().map(EmitMarkup::take_provenance).unwrap_or_default()
    }
    /// Take the root statement associations captured by the plain-text leaf.
    pub fn take_plain_statement_provenance(&mut self) -> MarkupProvenance {
        match self {
            PrintEmit::NoMarkup(e) => e.take_statement_provenance(),
            PrintEmit::Markup(_) | PrintEmit::Pretty(_) => MarkupProvenance::default(),
        }
    }
    /// Enable or disable the plain-text statement-root sidecar.
    pub fn set_plain_statement_provenance(&mut self, val: bool) {
        if let PrintEmit::NoMarkup(e) = self {
            e.set_capture_statement_provenance(val);
        }
    }
    /// Enable or disable token capture on the markup leaf.
    pub fn set_capture_tokens(&mut self, val: bool) {
        if let Some(e) = self.markup_sink_mut() {
            e.set_capture_tokens(val);
        }
    }
    /// Take the tokens captured by the markup leaf.
    pub fn take_markup_tokens(&mut self) -> Vec<crate::prettyprint::EmitToken> {
        self.markup_sink_mut().map(EmitMarkup::take_tokens).unwrap_or_default()
    }

    fn markup_sink_mut(&mut self) -> Option<&mut EmitMarkup> {
        match self {
            PrintEmit::NoMarkup(_) => None,
            PrintEmit::Markup(e) => Some(e),
            PrintEmit::Pretty(e) => match e.lowlevel_mut() {
                LowLevel::Markup(e) => Some(e),
                LowLevel::NoMarkup(_) => None,
            },
        }
    }
    /// Whether the plain-text statement-root sidecar is active.
    pub fn captures_plain_statement_provenance(&self) -> bool {
        match self {
            PrintEmit::NoMarkup(e) => e.captures_statement_provenance(),
            PrintEmit::Markup(_) | PrintEmit::Pretty(_) => false,
        }
    }
}

// The FULL `Emit` surface (prettyprint.rs:235-492), each method static-delegated
// to the active leaf.  Required AND default-provided methods are ALL forwarded
// so no call can fall through to a `PrintEmit` default that would diverge from
// the leaf (`EmitNoMarkup` overrides `tag_line`/`clear`; see the type doc).
impl Emit for PrintEmit {
    fn state(&self) -> &EmitBase { pe_forward!(self.state()) }
    fn state_mut(&mut self) -> &mut EmitBase { pe_forward!(self.state_mut()) }

    fn begin_document(&mut self) -> int4 { pe_forward!(self.begin_document()) }
    fn end_document(&mut self, id: int4) { pe_forward!(self.end_document(id)) }
    fn begin_function(&mut self) -> int4 { pe_forward!(self.begin_function()) }
    fn end_function(&mut self, id: int4) { pe_forward!(self.end_function(id)) }
    fn begin_block(&mut self, blockref: int4) -> int4 { pe_forward!(self.begin_block(blockref)) }
    fn end_block(&mut self, id: int4) { pe_forward!(self.end_block(id)) }

    fn tag_line(&mut self) { pe_forward!(self.tag_line()) }
    fn tag_line_indent(&mut self, indent: int4) { pe_forward!(self.tag_line_indent(indent)) }

    fn begin_return_type(&mut self, markup: &MarkupRef) -> int4 { pe_forward!(self.begin_return_type(markup)) }
    fn end_return_type(&mut self, id: int4) { pe_forward!(self.end_return_type(id)) }
    fn begin_var_decl(&mut self, markup: &MarkupRef) -> int4 { pe_forward!(self.begin_var_decl(markup)) }
    fn end_var_decl(&mut self, id: int4) { pe_forward!(self.end_var_decl(id)) }
    fn begin_statement(&mut self, markup: &MarkupRef) -> int4 { pe_forward!(self.begin_statement(markup)) }
    fn end_statement(&mut self, id: int4) { pe_forward!(self.end_statement(id)) }
    fn begin_func_proto(&mut self) -> int4 { pe_forward!(self.begin_func_proto()) }
    fn end_func_proto(&mut self, id: int4) { pe_forward!(self.end_func_proto(id)) }

    fn tag_variable(&mut self, name: &str, hl: SyntaxHighlight, markup: &MarkupRef) { pe_forward!(self.tag_variable(name, hl, markup)) }
    fn tag_op(&mut self, name: &str, hl: SyntaxHighlight, markup: &MarkupRef) { pe_forward!(self.tag_op(name, hl, markup)) }
    fn tag_func_name(&mut self, name: &str, hl: SyntaxHighlight, markup: &MarkupRef) { pe_forward!(self.tag_func_name(name, hl, markup)) }
    fn tag_type(&mut self, name: &str, hl: SyntaxHighlight, markup: &MarkupRef) { pe_forward!(self.tag_type(name, hl, markup)) }
    fn tag_type_text(&mut self, text: &str, hl: SyntaxHighlight, markup: &MarkupRef,
        spans: Option<std::rc::Rc<[crate::kuna_langtypes::TypeSpan]>>, origin: TypeTextOrigin) {
        pe_forward!(self.tag_type_text(text, hl, markup, spans, origin))
    }
    fn tag_field(&mut self, name: &str, hl: SyntaxHighlight, off: int4, markup: &MarkupRef) { pe_forward!(self.tag_field(name, hl, off, markup)) }
    fn tag_bit_field(&mut self, name: &str, hl: SyntaxHighlight, id: int4, markup: &MarkupRef) { pe_forward!(self.tag_bit_field(name, hl, id, markup)) }
    fn tag_comment(&mut self, name: &str, hl: SyntaxHighlight, spc: &std::rc::Rc<AddrSpace>, off: uintb) { pe_forward!(self.tag_comment(name, hl, spc, off)) }
    fn tag_label(&mut self, name: &str, hl: SyntaxHighlight, spc: &std::rc::Rc<AddrSpace>, off: uintb) { pe_forward!(self.tag_label(name, hl, spc, off)) }
    fn tag_case_label(&mut self, name: &str, hl: SyntaxHighlight, markup: &MarkupRef, value: uintb) { pe_forward!(self.tag_case_label(name, hl, markup, value)) }
    fn print(&mut self, data: &str, hl: SyntaxHighlight) { pe_forward!(self.print(data, hl)) }

    fn open_paren(&mut self, paren: &str, id: int4) -> int4 { pe_forward!(self.open_paren(paren, id)) }
    fn close_paren(&mut self, paren: &str, id: int4) { pe_forward!(self.close_paren(paren, id)) }
    fn open_group(&mut self) -> int4 { pe_forward!(self.open_group()) }
    fn close_group(&mut self, id: int4) { pe_forward!(self.close_group(id)) }
    fn clear(&mut self) { pe_forward!(self.clear()) }
    fn set_markup(&mut self, val: bool) { pe_forward!(self.set_markup(val)) }
    fn set_packed_output(&mut self, val: bool) { pe_forward!(self.set_packed_output(val)) }
    fn start_indent(&mut self) -> int4 { pe_forward!(self.start_indent()) }
    fn stop_indent(&mut self, id: int4) { pe_forward!(self.stop_indent(id)) }
    fn start_comment(&mut self) -> int4 { pe_forward!(self.start_comment()) }
    fn stop_comment(&mut self, id: int4) { pe_forward!(self.stop_comment(id)) }
    fn flush(&mut self) -> KunaResult<()> { pe_forward!(self.flush()) }
    fn set_max_line_size(&mut self, mls: int4) -> KunaResult<()> { pe_forward!(self.set_max_line_size(mls)) }
    fn get_max_line_size(&self) -> int4 { pe_forward!(self.get_max_line_size()) }
    fn set_comment_fill(&mut self, fill: &str) { pe_forward!(self.set_comment_fill(fill)) }
    fn emits_markup(&self) -> bool { pe_forward!(self.emits_markup()) }
    fn reset_defaults(&mut self) { pe_forward!(self.reset_defaults()) }

    fn get_paren_level(&self) -> int4 { pe_forward!(self.get_paren_level()) }
    fn get_indent_increment(&self) -> int4 { pe_forward!(self.get_indent_increment()) }
    fn set_indent_increment(&mut self, val: int4) { pe_forward!(self.set_indent_increment(val)) }
    fn spaces(&mut self, num: int4, bump: int4) { pe_forward!(self.spaces(num, bump)) }
    fn open_brace_indent(&mut self, brace: &str, style: EmitBraceStyle) -> int4 { pe_forward!(self.open_brace_indent(brace, style)) }
    fn open_brace(&mut self, brace: &str, style: EmitBraceStyle) { pe_forward!(self.open_brace(brace, style)) }
    fn close_brace_indent(&mut self, brace: &str, id: int4) { pe_forward!(self.close_brace_indent(brace, id)) }
    fn set_pending_brace(&mut self, style: EmitBraceStyle) { pe_forward!(self.set_pending_brace(style)) }
    fn has_pending_brace(&self) -> bool { pe_forward!(self.has_pending_brace()) }
    fn cancel_pending_brace(&mut self) { pe_forward!(self.cancel_pending_brace()) }
    fn pending_brace_indent_id(&self) -> int4 { pe_forward!(self.pending_brace_indent_id()) }
    fn emit_pending(&mut self) { pe_forward!(self.emit_pending()) }
}

// ===========================================================================
// PrintC — the stateful c-language printer object (the `glb->print` the
// `Architecture` owns).  (w9x-arch-engine-glue)
// ===========================================================================

/// Convert an `options::BraceStyle` (the PrintC-option enum) to the
/// `prettyprint::BraceStyle` the [`Emit`] driver consumes.  Both are the same
/// 3-variant `same_line`/`next_line`/`skip_line` enum (printc.hh:252-255 vs
/// emit.hh); the conversion is the identity mapping.
pub(crate) fn to_emit_brace(style: BraceStyle) -> EmitBraceStyle {
    match style {
        BraceStyle::SameLine => EmitBraceStyle::SameLine,
        BraceStyle::NextLine => EmitBraceStyle::NextLine,
        BraceStyle::SkipLine => EmitBraceStyle::SkipLine,
    }
}

/// \brief The c-language print object (C++ `class PrintC : public
/// PrintLanguage`, printc.hh:138).
///
/// In C++ `PrintC` *is-a* `PrintLanguage`, owning the [`PrintContext`] member
/// state (mod/scope stacks, comment/namespace defaults) and an `Emit *` driver,
/// plus the c-language [`PrintCOptions`].  The [`Architecture`](crate::architecture::Architecture)
/// holds it as `glb->print`.  This port carries:
///
///   * the **[`PrintCOptions`]** (the option toggles the `option NAME VALUE`
///     command flips through `ArchOptionContext`),
///   * the **[`PrintContext`]** (the shared print-modification / comment /
///     namespace state),
///   * the **language name** (`"c-language"`, the `getName()` the options
///     `print_is_c_language` predicate reads),
///   * the **flat** flag (`print C flat`, C++ `flat` mod bit), and
///   * an owned **[`EmitNoMarkup`]** back-end (the plain-text `print C` sink).
///
/// ## What `doc_function` emits today
///
/// [`doc_function`](PrintC::doc_function) faithfully transcribes the **shell**
/// of C++ `PrintC::docFunction` / `emitFunctionDeclaration` (printc.cc:2726,
/// 2790) — `beginFunction` → header comment line → the prototype declaration
/// (return type, function name, parenthesized parameters) → `openBraceIndent`
/// → … → `closeBraceIndent` → `endFunction` → `flush` — driving the **real**
/// [`Emit`] primitives.  The function **body** (`emitLocalVarDecls` +
/// `emitBlockGraph`, the per-statement RPN expression emission) is the
/// `// STUB(W9-emit)` RPN/`Emit` driver documented in this module's header
/// (`pushVn`/`recurse`/`emitOp` against the IR), absent from the merged tree;
/// the body slot emits a single marker comment line so the C output is a
/// structurally-complete, compilable-looking function shell (a real signature +
/// matched braces), not full byte-parity C.  The W9 closure fills the body in.
pub struct PrintC {
    /// The c-language options (C++ the `option_*` members).
    pub options: PrintCOptions,
    /// The shared print context (mod/scope stacks, comment/namespace state).
    pub context: PrintContext,
    /// The language name (C++ `PrintLanguage::name`, `"c-language"`).
    name: String,
    /// Whether `print C flat` is active (C++ the `flat` mod bit).
    flat: bool,
    /// The emit back-end (C++ the bound `Emit *`).  Defaults to the plain-text
    /// [`EmitNoMarkup`] for the byte-exact `print C` path; [`set_markup`](PrintC::set_markup)
    /// swaps in the packed clang [`EmitMarkup`] for the ghidra-mode `decompileAt`
    /// `<function>` document.  A concrete enum (not `Box<dyn Emit>`), so the
    /// ~260 `self.emit.<method>()` sites stay static (see [`PrintEmit`]).
    pub(crate) emit: PrintEmit,
    /// Session configuration survives all disposable document sinks.
    max_line_size: int4,
    indent_increment: int4,
    /// Host layout is explicit: raw CLI source maps also use markup tokens.
    host_surface: bool,
    /// (kuna) Scoped raw pointer to the [`Funcdata`] currently being emitted,
    /// live ONLY for the duration of [`emit_function_document`](PrintC::emit_function_document).
    /// Lets the fd-free RPN leaf emitters ([`emit_atom`](PrintC::emit_atom) /
    /// [`emit_op`](PrintC::emit_op)) resolve an [`Atom`]'s carried op/varnode
    /// arena key back to the `get_time()` / `get_create_index()` the `<ast>`
    /// stamps — WITHOUT threading `fd` through the pure RPN engine (which the
    /// synthetic `rpn_*` unit tests drive fd-free).  Dereferenced only when the
    /// markup back-end is active (`emits_markup()`); the plain-text datatest path
    /// never touches it, so its byte output is unaffected.  `None` outside body
    /// emission.
    emit_fd: Option<*const Funcdata>,
    /// The reverse-polish-notation operator stack (C++ `PrintLanguage::revpol`).
    /// Owned here because `printlanguage.rs` deferred its RPN driver to this
    /// closure (the driver and the `PrintC` op-emitters are one unit).
    revpol: Vec<ReversePolish>,
    /// The pending data-flow node stack (C++ `PrintLanguage::nodepend`).
    nodepend: Vec<crate::printlanguage::NodePending>,
    /// How much of `nodepend` is claimed (C++ `PrintLanguage::pending`).
    pending: usize,
    /// Comment placement / walk state for the function being printed (C++
    /// `PrintLanguage::commsorter`).  Seeded by [`setup_comments`] at the start of
    /// the body and consulted by `emit_comment_block_tree`/`emit_comment_group`.
    commsorter: crate::comment::CommentSorter,
    /// (kuna `voidtailreturn`) The one `CPUI_RETURN` op `emit_basic_block_ops`
    /// must skip: the function's own trailing bare `return;` in a void function.
    /// Computed once per function by [`elidable_void_tail_return`] at the top of
    /// [`emit_function_body`](PrintC::emit_function_body) and cleared after, so it
    /// is live only for that function's emission.
    void_tail_return: Option<OpId>,
    /// (kuna) Resolved `realtypes` rendering context for the function currently
    /// being printed — the `Architecture::realtypes` gate plus the data-model fact
    /// (`long` is 8 bytes) needed to relabel residual `TYPE_UNKNOWN` (`xunknownN`)
    /// types as real C types.  Refreshed at the top of [`doc_function_full`] from
    /// the live `arch`; `OFF` until then (so an out-of-band print never relabels).
    pub(crate) rt_ctx: RealTypeCtx,
    /// (kuna outlang) The output language this document renders into.  Selects
    /// the surface vocabulary and capability record every language-varying site
    /// reads (`crate::kuna_lang`).  Refreshed per document alongside `rt_ctx`;
    /// `OutLang::C` until then, so an out-of-band print is never non-C.
    pub(crate) out_lang: crate::kuna_lang::OutLang,
    /// (kuna warnstyle, DIV-39) Warning slugs collected under `warn_inline` by
    /// [`emit_comment_group`](PrintC::emit_comment_group) /
    /// [`emit_comment_func_header`](PrintC::emit_comment_func_header), flushed
    /// as one `// slug, slug` end-of-line comment by
    /// [`flush_eol_warnings`](PrintC::flush_eol_warnings) at the owning line's
    /// last token (statement `;`, `if (cond) {` header, prototype, ...).
    pub(crate) eol_warns: Vec<(String, std::rc::Rc<kuna_base::space::AddrSpace>, u64)>,
    /// Per-document spelling for a local HighVariable whose recovered name
    /// collides in the C function scope. Body references consume the same map.
    local_name_overrides: std::collections::HashMap<crate::context::HighVariableId, String>,
    /// Strict subpieces suppressed in favor of their overlap group's unique
    /// whole-value declaration. References resolve through the whole owner.
    local_name_aliases: std::collections::HashMap<crate::context::HighVariableId, crate::context::HighVariableId>,
    /// Grouped pieces that must remain independent declarations because no
    /// same-named unique whole owner exists. Their references are relative to
    /// their own declared object, not the overlap group's synthetic symbol.
    local_name_standalones: std::collections::HashSet<crate::context::HighVariableId>,
    /// C-only captures for semantic aggregate calls transported through a
    /// hidden result pointer. These are printer locals, never IR variables.
    call_result_temps: std::collections::HashMap<OpId, String>,
    /// Whether every callable use in this document admits normalized transport.
    callable_transport_valid: bool,
    /// (kuna `signedness`) The declared-signedness decision for the function
    /// being emitted: which integer locals the operation set says to declare
    /// signed or unsigned, and which of those declarations actually got written
    /// (the ones whose now-redundant `(int)` casts may be dropped).  Empty under
    /// `signedness upstream`.  See [`crate::kuna_typeround`].
    sign_plan: crate::kuna_typeround::SignPlan,
    /// (kuna `castimplied`) The declarations written for the function being
    /// emitted, which decide the casts C's own conversions make redundant.  See
    /// [`crate::kuna_castimplied`].
    cast_implied: crate::kuna_castimplied::ImpliedCasts,
    /// (kuna `castimplied`) The op being printed as the statement `lhs = <op>;`.
    stmt_op: Option<OpId>,
    /// (kuna `globalref`) This function's constant-address globals: the facts
    /// the decision reads and the globals its C names. See
    /// [`crate::kuna_globalref`].
    globalref: crate::kuna_globalref::Plan,
}

impl Default for PrintC {
    fn default() -> Self {
        PrintC::new()
    }
}

impl PrintC {
    /// Construct the c-language printer (C++ `PrintC::PrintC` +
    /// `resetDefaultsPrintC`, printc.cc:118 / 1649).
    pub fn new() -> PrintC {
        PrintC {
            options: PrintCOptions::new(),
            context: PrintContext::new(),
            name: CAPABILITY_NAME.to_string(),
            flat: false,
            emit: PrintEmit::NoMarkup(EmitNoMarkup::new()),
            max_line_size: 100,
            indent_increment: 2,
            host_surface: false,
            emit_fd: None,
            revpol: Vec::new(),
            nodepend: Vec::new(),
            pending: 0,
            commsorter: crate::comment::CommentSorter::new(),
            void_tail_return: None,
            rt_ctx: RealTypeCtx::OFF,
            out_lang: crate::kuna_lang::OutLang::C,
            eol_warns: Vec::new(),
            local_name_overrides: std::collections::HashMap::new(),
            local_name_aliases: std::collections::HashMap::new(),
            local_name_standalones: std::collections::HashSet::new(),
            call_result_temps: std::collections::HashMap::new(),
            callable_transport_valid: false,
            sign_plan: crate::kuna_typeround::SignPlan::default(),
            cast_implied: crate::kuna_castimplied::ImpliedCasts::default(),
            stmt_op: None,
            globalref: crate::kuna_globalref::Plan::default(),
        }
    }

    /// How the active output language renders a recovered calling convention.
    #[inline]
    pub fn lang_abi(&self) -> &'static dyn crate::kuna_langabi::LangAbi {
        self.out_lang.abi()
    }

    /// The active output language's surface vocabulary and capability record.
    ///
    /// Every language-varying emit site reads through here rather than naming a
    /// `keywords::`/`tokens::` constant directly, so a second language is a new
    /// profile rather than a second emitter.
    #[inline]
    pub fn lang(&self) -> &'static crate::kuna_lang::LangProfile {
        self.out_lang.profile()
    }

    /// The printer name (C++ `PrintLanguage::getName`, `"c-language"`).
    pub fn get_name(&self) -> &str {
        &self.name
    }

    /// Set the active print language name (C++ `setPrintLanguage` swaps which
    /// `PrintLanguage` is current; here the single owned printer records the
    /// requested name so `print_is_c_language` reflects it).
    ///
    /// (kuna outlang) The name is the single source of truth for the output
    /// language: it also resolves `out_lang`, so a name kuna owns switches the
    /// emitter and a name it does not leaves the C emitter in place -- an unknown
    /// language never silently renders as something else.
    pub fn set_name(&mut self, name: &str) {
        self.name = name.to_string();
        self.out_lang =
            crate::kuna_lang::OutLang::from_print_name(name).unwrap_or(crate::kuna_lang::OutLang::C);
    }

    /// The active output language.
    pub fn out_lang(&self) -> crate::kuna_lang::OutLang {
        self.out_lang
    }

    /// `print C flat` toggle (C++ `PrintLanguage::setFlat`).
    pub fn set_flat(&mut self, val: bool) {
        self.flat = val;
    }

    /// Whether `print C flat` is active.
    pub fn is_flat(&self) -> bool {
        self.flat
    }

    /// Reset the emit buffer (C++ `setOutputStream`).
    pub fn set_output_stream(&mut self) {
        self.emit.set_output_stream();
    }

    /// Initialize from the architecture (C++ `PrintLanguage::initializeFromArchitecture`).
    /// The sizes/types coupling is the W6 type factory, already built by the
    /// architecture; the printer needs no per-arch state beyond its options here.
    pub fn initialize_from_architecture(&mut self) {}

    /// The **shell** of C++ `PrintC::docFunction` (printc.cc:2790) +
    /// `emitFunctionDeclaration` (printc.cc:2726), transcribed faithfully,
    /// driving the real [`Emit`] primitives.  The body (`emitBlockGraph`) is the
    /// `// STUB(W9-emit)` RPN driver; this emits a marker line in its place.
    ///
    /// `display_name` is `fd->getDisplayName()`; `model_name` is the prototype
    /// model name when `printModelInDecl()` (None when the model is hidden);
    /// `ret_type` is the return-type token (`fd->getFuncProto()` output type
    /// name, defaulting to `"void"`); `params` are the input parameters'
    /// `(type, name)` tokens.  Returns the rendered C text.
    pub fn doc_function(
        &mut self,
        display_name: &str,
        model_name: Option<&str>,
        ret_type: &str,
        params: &[(String, String)],
    ) -> String {
        self.emit.set_output_stream();
        let markup = MarkupRef::none();

        let id1 = self.emit.begin_function();
        // (kuna warnstyle, DIV-39) defensive: never let a pending slug from a
        // previous function on this shared printer leak into this one.
        self.eol_warns.clear();
        // emitCommentFuncHeader(fd) — the header comment line (the full
        // CommentSorter is the comment item; emit the marker header).
        self.emit.tag_line();

        // --- emitFunctionDeclaration -------------------------------------
        let idp = self.emit.begin_func_proto();
        // emitPrototypeOutput: the return type token.
        let idret = self.emit.begin_return_type(&markup);
        self.emit.tag_type(ret_type, SyntaxHighlight::TypeColor, &markup);
        self.emit.end_return_type(idret);
        self.emit.spaces(1, 0);
        // option_convention: print the model name when shown.
        if self.options.convention {
            if let Some(m) = model_name {
                self.emit.print(m, SyntaxHighlight::KeywordColor);
                self.emit.spaces(1, 0);
            }
        }
        let id1g = self.emit.open_group();
        self.emit.tag_func_name(display_name, SyntaxHighlight::FuncnameColor, &markup);
        // function_call spacing (C++ function_call.spacing==0,bump==0).
        let id2 = self.emit.open_paren("(", 0);
        // emitPrototypeInputs: void or the comma-separated (type name) list.
        if params.is_empty() {
            self.emit.tag_type("void", SyntaxHighlight::TypeColor, &markup);
        } else {
            for (i, (ty, nm)) in params.iter().enumerate() {
                if i != 0 {
                    self.emit.print(",", SyntaxHighlight::NoColor);
                    self.emit.spaces(1, 0);
                }
                self.emit.tag_type(ty, SyntaxHighlight::TypeColor, &markup);
                if !nm.is_empty() {
                    self.emit.spaces(1, 0);
                    self.emit.tag_variable(nm, SyntaxHighlight::ParamColor, &markup);
                }
            }
        }
        self.emit.close_paren(")", id2);
        self.emit.close_group(id1g);
        self.emit.end_func_proto(idp);

        let id = self.emit.open_brace_indent("{", to_emit_brace(self.options.brace_func));
        // emitLocalVarDecls(fd) + emitBlockGraph(...).  The RPN body *engine*
        // (push_op/push_atom/op_binary/op_unary/emit_op/emit_atom/parentheses)
        // is now ported and unit-tested in this module (byte-faithful to the
        // C++ emitOp/emitAtom/parentheses).  Driving it over a real function
        // body is blocked NOT in the printer but UPSTREAM: the merged tree's
        // decompilation passes (heritage / simplification / merge / type +
        // proto recovery / block structuring) are stubs, so the IR
        // reaching the printer is raw lifted p-code (no HighVariables with
        // symbols, no recovered types, no structured blocks) — printing it
        // would emit non-C garbage, not byte-parity (see LOSS-130 / W10).
        // Until those passes land, the body slot is a single marker line so the
        // shell is a complete, brace-matched function.
        self.emit.tag_line();
        self.emit.print(
            "/* WARNING: body emission blocked on upstream decompilation passes (raw p-code IR) */",
            SyntaxHighlight::CommentColor,
        );
        // (kuna warnstyle, DIV-39) drain any slug still pending from a
        // construct with no closer flush point onto the last body line, so no
        // warning is ever silently dropped or carried out of this function.
        self.flush_eol_warnings();
        self.emit.close_brace_indent("}", id);
        self.emit.tag_line();
        self.emit.end_function(id1);

        // After the C++ flush the bound ostream holds the text.
        self.emit.output_str().to_string()
    }

    // --- the options.cc `// STUB(W8)` print setters (now wired) -----------

    /// C++ `PrintC::setNULLPrinting` (options.cc:444).
    pub fn set_null_printing(&mut self, val: bool) {
        self.options.set_null_printing(val);
    }
    /// C++ `PrintC::setInplaceOps` (options.cc:459).
    pub fn set_inplace_ops(&mut self, val: bool) {
        self.options.set_inplace_ops(val);
    }
    /// C++ `PrintC::setConvention` (options.cc:474).
    pub fn set_convention_printing(&mut self, val: bool) {
        self.options.set_convention(val);
    }
    /// C++ `PrintC::setNoCastPrinting` (options.cc:489).
    pub fn set_no_cast_printing(&mut self, val: bool) {
        self.options.set_no_cast_printing(val);
    }
    /// C++ `PrintC::setHideImpliedExts` (options.cc:504).
    pub fn set_hide_implied_exts(&mut self, val: bool) {
        self.options.set_hide_implied_exts(val);
    }
    /// C++ `glb->print->setMaxLineSize(val)` (options.cc:524).
    pub fn set_max_line_size(&mut self, val: int4) -> KunaResult<()> {
        if !(20..=10000).contains(&val) {
            return Err(KunaError::lowlevel("Bad maximum line size"));
        }
        self.max_line_size = val;
        Ok(())
    }
    /// C++ `glb->print->setIndentIncrement(val)` (options.cc:541).
    pub fn set_indent_increment(&mut self, val: int4) {
        self.indent_increment = val;
        self.emit.set_indent_increment(val);
    }
    /// C++ `glb->print->setLineCommentIndent(val)` (options.cc:559).
    pub fn set_line_comment_indent(&mut self, val: int4) -> KunaResult<()> {
        self.context.set_line_comment_indent(val, self.max_line_size)
    }
    /// C++ `glb->print->getHeaderComment()` (options.cc:583).
    pub fn header_comment_flags(&self) -> uint4 {
        self.context.header_comment()
    }
    /// C++ `glb->print->setHeaderComment(flags)` (options.cc:589).
    pub fn set_header_comment_flags(&mut self, flags: uint4) {
        self.context.set_header_comment(flags);
    }
    /// C++ `glb->print->getInstructionComment()` (options.cc:604).
    pub fn instruction_comment_flags(&self) -> uint4 {
        self.context.instruction_comment()
    }
    /// C++ `glb->print->setInstructionComment(flags)` (options.cc:610).
    pub fn set_instruction_comment_flags(&mut self, flags: uint4) {
        self.context.set_instruction_comment(flags);
    }
    /// C++ `glb->print->setIntegerFormat(p1)` (options.cc:623).
    pub fn set_integer_format(&mut self, fmt: &str) -> KunaResult<()> {
        self.context.set_integer_format(fmt)
    }
    /// C++ `glb->print->setNamespaceStrategy(strategy)` (options.cc:1014).
    ///
    /// The option surface (`options::NamespaceStrategy`) and the print-context
    /// surface (`printlanguage::NamespaceStrategy`) are the same 3-variant
    /// `minimal`/`none`/`all` enum (printlanguage.hh); convert across the boundary.
    pub fn set_namespace_strategy(&mut self, strategy: NamespaceStrategy) {
        use crate::printlanguage::NamespaceStrategy as PlStrat;
        let pl = match strategy {
            NamespaceStrategy::Minimal => PlStrat::MinimalNamespaces,
            NamespaceStrategy::None => PlStrat::NoNamespaces,
            NamespaceStrategy::All => PlStrat::AllNamespaces,
        };
        self.context.set_namespace_strategy(pl);
    }
    /// C++ `PrintC::setBraceFormat*` (options.cc:655-664).
    pub fn set_brace_format(&mut self, category: crate::options::BraceCategory, style: BraceStyle) {
        use crate::options::BraceCategory;
        match category {
            BraceCategory::Function => self.options.set_brace_format_function(style),
            BraceCategory::IfElse => self.options.set_brace_format_ifelse(style),
            BraceCategory::Loop => self.options.set_brace_format_loop(style),
            BraceCategory::Switch => self.options.set_brace_format_switch(style),
        }
    }
    /// C++ `PrintC::setCommentStyle` (options.cc:570).
    /// (kuna, Phase 3) Reset the PrintC-proper state the wire options mutate
    /// to the construction defaults — the PrintC share of the upstream
    /// `PrintLanguage::resetDefaults`/`resetDefaultsPrintC` chain the
    /// ghidra-mode `setOptions` reset needs (`Architecture::
    /// reset_wire_defaults`): the [`PrintCOptions`] block (nullprinting,
    /// inplaceops, conventionprinting, nocastprinting, hideimpliedexts, the
    /// four brace formats — plus the kuna rendering toggles, whose
    /// construction defaults ARE the shipped defaults) and the emitter's
    /// indent increment (Java default 2) and host line width (100).
    /// Everything context-held (integer format, comment style/indent/flags,
    /// namespace strategy, language) is reset by the caller's fresh
    /// [`PrintContext`](crate::printlanguage::PrintContext).
    pub fn reset_wire_option_defaults(&mut self) {
        self.options = PrintCOptions::new();
        self.max_line_size = 100;
        self.set_indent_increment(2);
    }

    pub fn set_comment_style(&mut self, style: &str) -> KunaResult<()> {
        self.context.set_comment_style(style)
    }

    // =====================================================================
    // The PrintLanguage RPN driver (printlanguage.cc:129-580), realized here
    // because printlanguage.rs deferred its token-emitting driver to this
    // closure (the driver + the PrintC op-emitters are one unit; see the
    // module header).  These methods drive the real [`Emit`] back-end.
    //
    // The IR-coupled leaves of the driver (the implied-varnode `recurse` step
    // `defOp->getOpcode()->push(...)`, and `pushVnExplicit`'s symbol/constant
    // resolution) need the stubbed Symbol/HighVariable/Datatype/TypeOp
    // subsystems and the proto-/type-/heritage-recovery passes, which the
    // merged tree leaves unported (LOSS-130: the decompilation passes are
    // stubs, so the IR reaching the printer is raw lifted p-code).  The
    // RPN *engine* below is therefore transcribed and unit-tested against
    // synthetic atoms/tokens (byte-faithful to `emitOp`/`emitAtom`/
    // `parentheses`); the IR-leaf push is the `// STUB(decompile-passes)`
    // edge handed to the caller via [`push_atom`].
    // =====================================================================

    /// Borrow the emit back-end (so a body driver can interleave `tag_line`
    /// etc. between RPN expressions).  A [`PrintEmit`]; use
    /// [`output_str`](PrintEmit::output_str) for the plain-text buffer.
    pub fn emit_mut(&mut self) -> &mut PrintEmit {
        &mut self.emit
    }

    /// Whether the RPN stack is fully drained (C++ `isStackEmpty`).
    pub fn is_stack_empty(&self) -> bool {
        self.revpol.is_empty() && self.nodepend.is_empty()
    }

    /// C++ `PrintLanguage::clear` (printlanguage.cc:685) — drop any partial RPN
    /// state, leaving the modstack/scope to the [`PrintContext`].
    pub fn clear_rpn(&mut self) {
        self.revpol.clear();
        self.nodepend.clear();
        self.pending = 0;
    }

    /// C++ `PrintLanguage::pushOp` (printlanguage.cc:129).  Push an operator
    /// token onto the RPN stack, emitting any front part of the enclosing
    /// operator and opening the right group/paren.
    pub fn push_op(&mut self, tok: &'static OpToken, op: Option<crate::printlanguage::IrKey>) {
        if self.pending < self.nodepend.len() {
            self.recurse(); // Pending varnode pushes before op
        }
        let paren;
        let id;
        if self.revpol.is_empty() {
            paren = false;
            id = self.emit.open_group();
        } else {
            let mut back = self.revpol.last().unwrap().clone();
            self.emit_op(&mut back);
            // Reflect any id2 mutation emit_op performed back onto the stack.
            *self.revpol.last_mut().unwrap() = back;
            paren = self.parentheses_top(tok);
            if paren {
                id = self.emit.open_paren(crate::printlanguage::OPEN_PAREN, 0);
            } else {
                id = self.emit.open_group();
            }
        }
        self.revpol.push(ReversePolish { tok, visited: 0, paren, op, id, id2: 0 });
    }

    /// C++ `PrintLanguage::pushAtom` (printlanguage.cc:162).  Push a leaf token,
    /// draining as much of the RPN stack as is now complete.
    pub fn push_atom(&mut self, atom: &Atom) {
        if self.pending < self.nodepend.len() {
            self.recurse();
        }
        if self.revpol.is_empty() {
            self.emit_atom(atom);
        } else {
            let mut back = self.revpol.last().unwrap().clone();
            self.emit_op(&mut back);
            *self.revpol.last_mut().unwrap() = back;
            self.emit_atom(atom);
            loop {
                {
                    let top = self.revpol.last_mut().unwrap();
                    top.visited += 1;
                    if top.visited != top.tok.stage {
                        break;
                    }
                }
                let mut entry = self.revpol.last().unwrap().clone();
                self.emit_op(&mut entry);
                if entry.paren {
                    self.emit.close_paren(crate::printlanguage::CLOSE_PAREN, entry.id);
                } else {
                    self.emit.close_group(entry.id);
                }
                self.revpol.pop();
                if self.revpol.is_empty() {
                    break;
                }
            }
        }
    }

    /// C++ `PrintLanguage::pushVn` (printlanguage.cc:197).  Queue an implied
    /// Varnode whose producing expression will be recursed.  Inputs of one op
    /// are pushed in reverse order (C++ comment).
    pub fn push_vn(&mut self, vn: crate::printlanguage::IrKey, op: crate::printlanguage::IrKey, m: uint4) {
        self.nodepend.push(crate::printlanguage::NodePending::new(vn, op, m));
    }

    /// C++ `PrintLanguage::recurse` (printlanguage.cc:521).  Resolve every
    /// pending Varnode the current op claimed: in C++ an implied one expands its
    /// defining op (`defOp->getOpcode()->push`) and an explicit one becomes a
    /// leaf atom (`pushVnExplicit`).
    ///
    /// STUB(decompile-passes): the implied-op `push` dispatch and the explicit
    /// `pushVnExplicit` symbol/constant resolution need the stubbed
    /// Symbol/HighVariable/Datatype/TypeOp graph (absent in the merged tree).
    /// The `op_binary`/`op_unary` scaffold above therefore pushes already-
    /// resolved leaf [`Atom`]s directly (never via `push_vn`), so on the tested
    /// path `nodepend` is empty and this drains nothing.  When the upstream
    /// passes land and the body driver stages implied varnodes, this restores
    /// the C++ claim/pop loop; the pop-without-dispatch here just guarantees
    /// termination until then.
    pub fn recurse(&mut self) {
        let modsave = self.context.mods();
        let last_pending = self.pending;
        self.pending = self.nodepend.len();
        // C++: while (lastPending < pending) { pop nodepend.back(); ... }
        while self.nodepend.len() > last_pending {
            if let Some(pend) = self.nodepend.pop() {
                self.context.set_mods(pend.vnmod);
                // STUB(decompile-passes): no implied/explicit leaf expansion.
            }
            self.pending = self.nodepend.len();
        }
        self.context.set_mods(modsave);
    }

    /// C++ `PrintLanguage::opBinary` (printlanguage.cc:553) — the data-flow-free
    /// scaffold: push the operator, then its two operand atoms (supplied by the
    /// caller as the IR-leaf hook).  The negate-token flip is applied.
    pub fn op_binary(&mut self, tok: &'static OpToken, op: Option<crate::printlanguage::IrKey>, lhs: &Atom, rhs: &Atom) {
        let tok = if self.context.is_set(modifiers::NEGATETOKEN) {
            self.context.unset_mod(modifiers::NEGATETOKEN);
            token_negate(tok).unwrap_or(tok)
        } else {
            tok
        };
        self.push_op(tok, op);
        // C++ pushes in[1] then in[0]; pushAtom drains in stack order, so the
        // operands print in0 <op> in1.
        self.push_atom(lhs);
        self.push_atom(rhs);
    }

    /// C++ `PrintLanguage::opUnary` (printlanguage.cc:573) — the scaffold form.
    pub fn op_unary(&mut self, tok: &'static OpToken, op: Option<crate::printlanguage::IrKey>, operand: &Atom) {
        self.push_op(tok, op);
        self.push_atom(operand);
    }

    /// (kuna) The [`Funcdata`] published for the duration of
    /// [`emit_function_document`](PrintC::emit_function_document), else `None`.
    ///
    /// SAFETY: see the `emit_fd` field doc — the pointer is live only within that
    /// call, `fd` outlives it and is never mutated through the pointer, and it
    /// aliases `fd` (a distinct object from `self`).
    fn markup_fd(&self) -> Option<&Funcdata> {
        self.emit_fd.map(|p| unsafe { &*p })
    }

    /// (kuna) The `MarkupRef` for an RPN operator token from its arena key (C++
    /// `EmitMarkup::tagOp` derefs the entry's `PcodeOp *` for `opref =
    /// getTime()`).  The op's `get_time()` is exactly the `<seqnum uniq>`
    /// `PcodeOp::encode` writes into the `<ast>`, so the token resolves by
    /// construction.  Returns `none()` (no deref) unless the markup back-end is
    /// active and `fd` is in scope — a no-op on the byte-exact plain-text path.
    fn markup_for_op_key(&self, op_key: Option<crate::printlanguage::IrKey>) -> MarkupRef {
        if !self.emit.emits_markup() {
            return MarkupRef::none();
        }
        match self.markup_fd() {
            Some(fd) => MarkupRef::op(resolve_op_ref(fd, op_key)),
            None => MarkupRef::none(),
        }
    }

    /// (kuna) The `MarkupRef` for a leaf [`Atom`] from its carried op/varnode
    /// arena keys (C++ `EmitMarkup::tagVariable`/`tagOp`/`tagField`/`tagCaseLabel`
    /// deref the `Varnode *`/`PcodeOp *`).  `varref = vn->getCreateIndex()` and
    /// `opref = op->getTime()` are the SAME ids `Funcdata::encode` writes into the
    /// `<ast>` (`<addr ref>` / `<seqnum uniq>`), so a clang token resolves against
    /// the AST by construction.  `none()` (no deref) on the plain-text path.
    fn markup_for_atom(&self, atom: &Atom) -> MarkupRef {
        if !self.emit.emits_markup() {
            return MarkupRef::none();
        }
        let mut m = MarkupRef::none();
        if let Some(fd) = self.markup_fd() {
            if atom.tag == TagType::VarToken {
                if let crate::printlanguage::AtomData::Vn(key) = &atom.data {
                    let vn = VarnodeId::from(slotmap::KeyData::from_ffi(*key));
                    if fd.execution_input_slot_for_varnode(vn).is_some() {
                        // Java can recover a source Symbol through either varref
                        // or the PTRSUB opref fallback. Neither denotes authority here.
                        return MarkupRef::none();
                    }
                }
            }
            m.opref = resolve_op_ref(fd, atom.op);
            if let crate::printlanguage::AtomData::Vn(vn_key) = &atom.data {
                m.varref = resolve_var_ref(fd, *vn_key);
            }
        }
        if let crate::printlanguage::AtomData::Ct(ct) = &atom.data {
            let view = ct.read();
            let nominal = view.get(ct.id()).expect("retained atom datatype");
            m.type_id = Some(nominal.get_unsized_id().expect("nominal datatype host ID"));
            m.type_name = Some(nominal.get_name().to_owned());
        }
        m
    }

    /// (kuna) The `MarkupRef` for a DIRECT tag site that already holds an `OpId`
    /// (C++ passes the `PcodeOp *`): `opref = op->getTime()`, the `<ast>`
    /// `<seqnum uniq>`. Gated on the markup back-end or an explicitly requested
    /// plain statement sidecar, so the ordinary plain-text path does no lookup.
    fn op_markup(&self, fd: &Funcdata, op: OpId) -> MarkupRef {
        if !self.emit.emits_markup()
            && !self.emit.captures_plain_statement_provenance()
        {
            return MarkupRef::none();
        }
        MarkupRef::op(fd.obank().get(op).map(|o| o.get_time() as uintb))
    }

    /// C++ `PrintLanguage::emitOp` (printlanguage.cc:332) — resolve final
    /// spacing / parens for one RPN entry at its current stage.  Mutates the
    /// entry's `id2` for surround tokens (mirrored back by the callers).
    fn emit_op(&mut self, entry: &mut ReversePolish) {
        // (kuna) The operator's markup (C++ `EmitMarkup::tagOp` derefs the entry's
        // `PcodeOp *` for `opref = getTime()`).  Resolved from the entry's arena
        // key; `none()` (no lookup) on the plain-text path so the datatest bytes
        // are unchanged.
        let op_markup = self.markup_for_op_key(entry.op);
        match entry.tok.token_type {
            TokenType::Binary => {
                if entry.visited != 1 {
                    return;
                }
                self.emit.spaces(entry.tok.spacing, entry.tok.bump);
                self.emit.tag_op(entry.tok.print1, SyntaxHighlight::NoColor, &op_markup);
                self.emit.spaces(entry.tok.spacing, entry.tok.bump);
            }
            TokenType::UnaryPrefix => {
                if entry.visited != 0 {
                    return;
                }
                self.emit.tag_op(entry.tok.print1, SyntaxHighlight::NoColor, &op_markup);
                self.emit.spaces(entry.tok.spacing, entry.tok.bump);
            }
            TokenType::Postsurround => {
                if entry.visited == 0 {
                    return;
                }
                if entry.visited == 1 {
                    self.emit.spaces(entry.tok.spacing, entry.tok.bump);
                    entry.id2 = self.emit.open_paren(entry.tok.print1, 0);
                    self.emit.spaces(0, entry.tok.bump);
                } else {
                    self.emit.close_paren(entry.tok.print2, entry.id2);
                }
            }
            TokenType::Presurround => {
                if entry.visited == 2 {
                    return;
                }
                if entry.visited == 0 {
                    entry.id2 = self.emit.open_paren(entry.tok.print1, 0);
                } else {
                    self.emit.close_paren(entry.tok.print2, entry.id2);
                    self.emit.spaces(entry.tok.spacing, entry.tok.bump);
                }
            }
            TokenType::Space => {
                if entry.visited != 1 {
                    return;
                }
                self.emit.spaces(entry.tok.spacing, entry.tok.bump);
            }
            TokenType::HiddenFunction => {
                // Never directly prints anything.
            }
        }
    }

    /// C++ `PrintLanguage::emitAtom` (printlanguage.cc:379) — send a leaf token
    /// to the low-level emitter according to its tag type.
    fn emit_atom(&mut self, atom: &Atom) {
        // (kuna) Resolve the leaf's markup (C++ `EmitMarkup::tag*` derefs the
        // atom's `Varnode *`/`PcodeOp *` for `varref`/`opref`).  `none()` (no
        // lookup) on the plain-text path, so the datatest bytes are unchanged.
        let markup = self.markup_for_atom(atom);
        // (kuna outlang) A recovered name can be a demangled path (`hello::main`)
        // or carry generic arguments (`driftsort_main<T>`). C emits those verbatim
        // and is equally not-C for it; Rust output is parsed, so the same latent
        // problem has to be fixed rather than tolerated. Off for C, so the corpus
        // cannot move.
        let ident = |p: &PrintC, n: &String| -> Option<String> {
            let s = crate::kuna_rusttypes::sanitize_path(n);
            (p.lang().sanitize_identifiers && &s != n).then_some(s)
        };
        match atom.tag {
            TagType::Syntax => self.emit.print(&atom.name, to_emit_hl(atom.highlight)),
            TagType::VarToken => {
                let n = ident(self, &atom.name);
                let n = n.as_ref().unwrap_or(&atom.name);
                self.emit.tag_variable(n, to_emit_hl(atom.highlight), &markup)
            }
            TagType::FuncToken => {
                let n = ident(self, &atom.name);
                let n = n.as_ref().unwrap_or(&atom.name);
                self.emit.tag_func_name(n, to_emit_hl(atom.highlight), &markup)
            }
            TagType::OpToken => self.emit.tag_op(&atom.name, to_emit_hl(atom.highlight), &markup),
            TagType::TypeToken => {
                if let crate::printlanguage::AtomData::TypeSpans(spans) = &atom.data {
                    self.emit.tag_type_text(&atom.name, to_emit_hl(atom.highlight), &markup,
                        Some(spans.clone()), TypeTextOrigin::Type);
                } else {
                    self.emit.tag_type(&atom.name, to_emit_hl(atom.highlight), &markup);
                }
            }
            TagType::FieldToken => {
                self.emit.tag_field(&atom.name, to_emit_hl(atom.highlight), atom.offset, &markup)
            }
            TagType::BitFieldToken => {
                self.emit.tag_bit_field(&atom.name, to_emit_hl(atom.highlight), atom.offset, &markup)
            }
            TagType::CaseToken => {
                let value = match &atom.data {
                    crate::printlanguage::AtomData::IntValue(v) => *v,
                    _ => 0,
                };
                self.emit.tag_case_label(&atom.name, to_emit_hl(atom.highlight), &markup, value)
            }
            TagType::BlankToken => {} // Print nothing.
        }
    }

    /// C++ `PrintLanguage::parentheses` against the current RPN top
    /// (printlanguage.cc:270 reads `revpol.back()`).  Delegates to the pure
    /// [`crate::printlanguage::parentheses`] with the previous token for the
    /// `HiddenFunction` arm.
    fn parentheses_top(&self, op2: &OpToken) -> bool {
        let top = self.revpol.last().expect("parentheses on empty revpol");
        let prev = if self.revpol.len() > 1 {
            Some(self.revpol[self.revpol.len() - 2].tok)
        } else {
            None
        };
        parentheses(top, op2, prev)
    }
}

// ===========================================================================
// The IR-coupled statement-body driver (w10-structure-printbody).
//
// This is the W9-emit closure: the per-statement RPN expression emission
// over the *structured* `sblocks` tree (C++ `PrintC::emitBlockGraph` ->
// `emitBlock{Copy,Basic,Ls,If,...}` -> `emitStatement` -> `emitExpression` ->
// `op->getOpcode()->push(...)` -> `recurse`).  It drives the (already ported and
// unit-tested) RPN engine above (`push_op`/`push_atom`) over the real
// `Funcdata` IR, resolving each Varnode leaf via `push_vn_explicit_ir` (the
// faithful `pushVnExplicit`: annotation/constant/register/`dat_<addr>` naming).
//
// The leaf-naming falls back to the address-/register-based form when no
// HighVariable Symbol is bound (Merge/naming is the next layer); the *structure*
// of the body (the if/else hierarchy, the statement sequence, the operator
// expressions, the comparison rendering) is fully driven here.
// ===========================================================================

use crate::architecture::Architecture;
use crate::cast::{CastContext, CastStrategy, CastStrategyC, OpRef, VnRef};
use crate::funcdata::Funcdata;
use crate::context::{BlockId, OpId, VarnodeId};
use kuna_num::opcodes::OpCode;

/// One resolved member token of a partial-symbol access walk (C++
/// `PartialSymbolEntry`, printc.cc:1985-1994).  A struct/union field becomes a
/// `Member` (`.field`); an array element becomes a `Subscript` (`[index]`).
enum PartialEntry {
    /// `object_member` token: `.field` with its byte offset and nominal parent
    /// (printc.cc:2046-2052).
    Member(String, int4, crate::dtype::TypeRoot),
    /// `subscript` token: `[index]` for an array element (printc.cc:2062-2070).
    Subscript(int4),
    /// Artificial `object_member` with no backing field (C++ `entry.field == 0`,
    /// printc.cc:2106-2117): renders `unnamedField(offset,size)` = `._<off>_<sz>_`
    /// when a composite member walk lands on an offset/size with no exact field.
    Unnamed(int8, int4),
}

impl PrintC {
    /// C++ `PrintC::docFunction` (printc.cc:2790), transcribed faithfully and
    /// driven over a real [`Funcdata`] + [`Architecture`]: emit the signature
    /// shell (real return type from the recovered proto), then the **structured
    /// body** (`emitBlockGraph(&fd->getStructure())`) when `sblocks` is present,
    /// and return the plain-text C.
    ///
    /// The emission itself is [`emit_function_document`](PrintC::emit_function_document),
    /// shared verbatim with [`doc_function_markup`](PrintC::doc_function_markup)
    /// so plain-text and markup entries share the same semantic tokens. This
    /// entry selects raw text without host wrapping and returns its text.
    pub fn doc_function_full(&mut self, fd: &Funcdata, arch: &Architecture) -> String {
        self.with_document_sink(PrintEmit::NoMarkup(EmitNoMarkup::new()), false, |print| {
            print.emit_function_document(fd, arch);
            print.emit.flush()?;
            Ok(print.emit.output_str().to_string())
        }).expect("raw text emission is infallible")
    }

    /// Canonical plain host body for callable publication. It shares the host
    /// token spelling and source projections, but its type definitions and
    /// wrappers are owned by the explicit support inventory, not this fragment.
    pub fn doc_function_support(&mut self, fd: &Funcdata, arch: &Architecture) -> KunaResult<String> {
        let previous = self.options.struct_defs();
        self.options.set_struct_defs(false);
        let rendered = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            self.with_document_sink(PrintEmit::NoMarkup(EmitNoMarkup::new()), true, |print| {
                print.emit_function_document(fd, arch);
                print.emit.flush()?;
                Ok(print.emit.output_str().to_string())
            })
        }));
        self.options.set_struct_defs(previous);
        match rendered {
            Ok(result) => result,
            Err(payload) => std::panic::resume_unwind(payload),
        }
    }

    /// Emit plain C and retain only each statement root's `opref` in the same
    /// pass. This is intentionally smaller than token provenance: it exists so
    /// exact-site presentation repairs can bind a rendered statement to one
    /// p-code occurrence without paying for a second full markup render.
    pub fn doc_function_full_with_statement_provenance(
        &mut self,
        fd: &Funcdata,
        arch: &Architecture,
    ) -> (String, MarkupProvenance) {
        self.with_document_sink(PrintEmit::NoMarkup(EmitNoMarkup::new()), false, |print| {
            print.emit.set_plain_statement_provenance(true);
            print.emit_function_document(fd, arch);
            print.emit.flush()?;
            let text = print.emit.output_str().to_string();
            let provenance = print.emit.take_plain_statement_provenance();
            Ok((text, provenance))
        }).expect("raw text emission is infallible")
    }

    /// Select whether `PrintC` emits token-markup (C++
    /// `EmitPrettyPrint::setMarkup`, prettyprint.cc:2531, driven from
    /// `ArchitectureGhidra`'s ctor `print->setMarkup(true)`, ghidra_arch.cc:917).
    /// Swaps the concrete [`PrintEmit`] variant; a fresh buffer either way (each
    /// leaf owns its own sink). Persistent session indentation is applied to
    /// each new sink. This selects raw markup, not host line wrapping. The standalone
    /// datatest path NEVER calls this, so `emit` stays `NoMarkup` and the
    /// 675-assertion byte output is untouched.
    pub fn set_markup(&mut self, val: bool) {
        self.emit = if val {
            PrintEmit::Markup(EmitMarkup::new())
        } else {
            PrintEmit::NoMarkup(EmitNoMarkup::new())
        };
        self.emit.set_indent_increment(self.indent_increment);
    }

    /// Emit the ghidra-mode `decompileAt` clang token-markup `<function>` document
    /// (C++ `ArchitectureGhidra::print->docFunction(fd)`, ghidra_process.cc:329):
    /// run the IDENTICAL [`emit_function_document`](PrintC::emit_function_document)
    /// sequence that drives `doc_function_full`, but through [`EmitPrettyPrint`]
    /// into markup so each token carries its `opref`/`varref` (resolved to the SAME
    /// `get_time()` / `get_create_index()` that `Funcdata::encode`'s `<ast>` uses,
    /// so a token resolves against the AST by construction).  Returns the packed
    /// bytes after successful queue flush; the preceding sink is restored even
    /// when rendering fails or unwinds.
    pub fn doc_function_markup(&mut self, fd: &Funcdata, arch: &Architecture) -> KunaResult<Vec<u8>> {
        let mut sink = EmitPrettyPrint::new();
        sink.set_max_line_size(self.max_line_size)?;
        sink.set_markup(true);
        self.with_document_sink(PrintEmit::Pretty(sink), true, |print| {
            print.emit_function_document(fd, arch);
            print.emit.flush()?;
            Ok(print.emit.take_markup_bytes())
        })
    }

    /// Capture the source-line `opref`/`varref` associations produced by the
    /// same token stream as [`Self::doc_function_full`].
    pub fn doc_function_provenance(
        &mut self,
        fd: &Funcdata,
        arch: &Architecture,
    ) -> MarkupProvenance {
        self.with_document_sink(PrintEmit::Markup(EmitMarkup::new()), false, |print| {
            print.emit_function_document(fd, arch);
            print.emit.flush()?;
            Ok(print.emit.take_markup_provenance())
        }).expect("raw markup emission is infallible")
    }

    /// The markup pass of [`Self::doc_function_provenance`] with every token
    /// captured at its plain-text position ([`crate::prettyprint::EmitToken`]).
    pub fn doc_function_tokens(
        &mut self,
        fd: &Funcdata,
        arch: &Architecture,
    ) -> (MarkupProvenance, Vec<crate::prettyprint::EmitToken>) {
        self.with_document_sink(PrintEmit::Markup(EmitMarkup::new()), false, |print| {
            print.emit.set_capture_tokens(true);
            print.emit_function_document(fd, arch);
            print.emit.flush()?;
            let provenance = print.emit.take_markup_provenance();
            let tokens = print.emit.take_markup_tokens();
            Ok((provenance, tokens))
        }).expect("raw markup emission is infallible")
    }

    /// Select a document surface independently of token markup capture.
    pub(crate) fn is_host_surface(&self) -> bool {
        self.host_surface
    }

    fn with_document_sink<T>(
        &mut self,
        mut sink: PrintEmit,
        host_surface: bool,
        render: impl FnOnce(&mut Self) -> KunaResult<T>,
    ) -> KunaResult<T> {
        sink.set_indent_increment(self.indent_increment);
        let saved_sink = std::mem::replace(&mut self.emit, sink);
        let saved_surface = std::mem::replace(&mut self.host_surface, host_surface);
        let saved_fd = self.emit_fd;
        let checkpoint = self.context.checkpoint();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| render(self)));
        self.emit = saved_sink;
        self.host_surface = saved_surface;
        self.emit_fd = saved_fd;
        self.context.restore_checkpoint(checkpoint);
        if !matches!(&result, Ok(Ok(_))) {
            self.clear_rpn();
            self.eol_warns.clear();
            self.void_tail_return = None;
            self.stmt_op = None;
        }
        match result {
            Ok(result) => result,
            Err(panic) => std::panic::resume_unwind(panic),
        }
    }

    /// (kuna) Render ONLY the function's prototype declaration —
    /// `<ret> <name>(<params>);` — as plain text, for the `kuna
    /// decompile-project` `.h` artifact.
    ///
    /// Mirrors [`doc_function_full`](PrintC::doc_function_full)'s capture
    /// harness (`set_output_stream()` reset → emit → `output_str()`), driving
    /// the IDENTICAL [`emit_prototype_declaration`](PrintC::emit_prototype_declaration)
    /// token sequence the full function document emits, so the `.h` prototype
    /// (minus the trailing `;` added here) matches the `.c` definition line
    /// char-for-char.  Deliberately does NOT emit the header warning comments
    /// (`emit_comment_func_header`) — prototype only.
    pub fn doc_prototype(&mut self, fd: &Funcdata, arch: &Architecture) -> String {
        self.with_document_sink(PrintEmit::NoMarkup(EmitNoMarkup::new()), false, |print| {
            print.rt_ctx = RealTypeCtx::from_arch(arch, print.out_lang, print.options.convention);
            print.emit_prototype_declaration(fd, arch, &MarkupRef::none());
            print.emit.print(";", SyntaxHighlight::NoColor);
            print.emit.flush()?;
            Ok(print.emit.output_str().to_string())
        }).expect("raw text emission is infallible")
    }

    /// (kuna) C++ `PrintC::docTypeDefinitions` (decompiler/cpp/printc.cc:2779):
    /// emit a C definition for every user-defined data-type in the factory, in
    /// [`TypeFactoryImpl::dependent_order`](crate::dtype::TypeFactoryImpl::dependent_order)
    /// (definition-before-use), skipping core types — the `.h` artifact of
    /// `kuna decompile-project`.
    ///
    /// Documented `(kuna)` divergences from the upstream emission (which prints
    /// one `typedef struct {…} name;` per type through the emitter):
    ///
    ///   * **forward-declaration block first**: every struct/union gets a
    ///     `typedef struct <n> <n>;` up front, then bodies follow as plain
    ///     `struct <n> { … };` in dependency order.  Upstream's anonymous
    ///     `typedef struct {…} n;` form cannot express a self-referential or
    ///     mutually-recursive pointer field; the tag+typedef split always can.
    ///     An incomplete (fieldless) struct emits ONLY the forward declaration,
    ///     annotated `/* opaque */`.
    ///   * **padding fields**: struct field-offset gaps and trailing padding
    ///     render as explicit `undefined1 _pad<hexoff>[N];` members so
    ///     `sizeof(struct <n>)` matches the decompiler's layout when recompiled.
    ///   * **name sanitisation + dedup**: a non-C identifier is rewritten
    ///     (annotated `/* renamed from "…" */`); a later duplicate name emits
    ///     `/* duplicate type name skipped: <n> */` instead of a redefinition.
    ///
    /// Emission is direct string building (no emitter markup exists for type
    /// definitions); the per-type body renderers are pure functions
    /// ([`compose_type_body`] etc.) for unit-testability.
    pub fn doc_type_definitions(&mut self, arch: &Architecture) -> String {
        let deporder =
            crate::kuna_structsynth::ledger::in_name_order(arch.types_impl().dependent_order());
        render_type_definitions(&deporder, RealTypeCtx::from_arch(arch, self.out_lang, self.options.convention))
    }

    /// Lay out the generated callable declaration/adapter grammar, not arbitrary C.
    /// It contains identifiers, type names, decimal shifts and punctuation, but no
    /// quoted literals or comments. Keep compound punctuation and UTF-8 words intact.
    fn emit_callable_artifact(&mut self, text: &str) {
        let group = self.emit.open_group();
        let bytes = text.as_bytes();
        let mut start = 0;
        while start < bytes.len() {
            let space = bytes[start].is_ascii_whitespace();
            let word = bytes[start].is_ascii_alphanumeric() || bytes[start] == b'_' || bytes[start] >= 0x80;
            let mut end = start + 1;
            while end < bytes.len() && bytes[end].is_ascii_whitespace() == space
                && (space || (bytes[end].is_ascii_alphanumeric() || bytes[end] == b'_' || bytes[end] >= 0x80) == word)
            {
                end += 1;
            }
            if space {
                self.emit.spaces((end - start) as int4, 0);
            } else {
                if start != 0 && !bytes[start - 1].is_ascii_whitespace() {
                    self.emit.spaces(0, 0);
                }
                self.emit.print(&text[start..end], SyntaxHighlight::NoColor);
            }
            start = end;
        }
        self.emit.close_group(group);
    }

    /// The shared body-emission sequence of C++ `PrintC::docFunction`
    /// (printc.cc:2790), back-end-agnostic: `beginFunction` → header comment →
    /// prototype declaration → `openBraceIndent` → local var decls → block graph →
    /// `closeBraceIndent` → `endFunction`.  Driven by whichever [`PrintEmit`]
    /// variant is active, so [`doc_function_full`](PrintC::doc_function_full)
    /// (plain text) and [`doc_function_markup`](PrintC::doc_function_markup)
    /// (packed markup) share ONE emission path — the token stream (and every
    /// `MarkupRef` populated below) is identical; only the leaf that serializes it
    /// differs.
    fn emit_function_document(&mut self, fd: &Funcdata, arch: &Architecture) {
        self.emit.set_output_stream();
        // The host document and any definition preamble share a layout group;
        // invisible grouping adds no host markup elements.
        let layout_group = self.is_host_surface().then(|| self.emit.open_group());
        self.local_name_overrides.clear();
        self.local_name_aliases.clear();
        self.local_name_standalones.clear();
        self.call_result_temps.clear();
        let callable_transport = (self.out_lang == crate::kuna_lang::OutLang::C)
            .then(|| crate::kuna_callabletransport::validate_representations(fd));
        self.callable_transport_valid = callable_transport.as_ref().is_some_and(Result::is_ok);
        // (kuna `signedness`) Round the declared signedness of this function's
        // integer locals from the operations applied to them.  Computed before
        // any declaration is written and consumed by
        // `local_decl_type_and_comment` (the declaration) and `op_type_cast_ir`
        // (the casts the new declaration makes redundant).
        let cast_sign = arch.cast_sign && self.out_lang.profile().caps.integer_promotion;
        self.sign_plan = crate::kuna_typeround::plan(
            fd,
            arch.signedness,
            cast_sign,
            arch.types_impl(),
            |high| {
                decl_type_representative(fd, arch, high)
                    .and_then(|vn| fd.vbank().get(vn))
                    .map(|v| v.get_type().clone())
            },
        );
        let promotes = !self.options.nocasts && self.out_lang.profile().caps.integer_promotion;
        self.cast_implied.begin(
            arch.cast_implied && promotes,
            cast_sign,
            arch.cast_ternary && promotes && arch.types().get_size_of_int() == 4,
        );
        self.stmt_op = None;
        // (kuna) Publish the fd for the fd-free RPN leaf emitters (emit_atom /
        // emit_op) to resolve op/varnode arena keys to the <ast> ids while markup
        // is active.  SAFETY: `fd` outlives this call; it is only ever read
        // (get_time/get_create_index), never mutated through the pointer, and
        // aliases `fd` (a distinct object from `self`), so no `&mut self` here
        // conflicts.  Cleared before return so the pointer never escapes the call.
        self.emit_fd = Some(fd as *const Funcdata);
        // (kuna) Resolve the `realtypes` rendering context once per function from
        // the live architecture (the gate + the `long`-is-8 data-model fact); every
        // type-name chokepoint below reads `self.rt_ctx`.
        self.rt_ctx = RealTypeCtx::from_arch(arch, self.out_lang, self.options.convention);
        self.globalref = crate::kuna_globalref::plan(
            fd,
            arch,
            self.options.global_ref,
            self.out_lang == crate::kuna_lang::OutLang::C,
        );
        // commsorter.setupFunctionList(...) (C++ printc.cc:2799): place this
        // function's comments into their basic blocks so the body emitters can
        // pick them up in order.
        self.setup_comments(fd, arch);
        let markup = MarkupRef::none();

        let id1 = self.emit.begin_function();
        self.emit_type_definition_preamble(fd);
        let callable_artifacts = callable_transport.map(|representation| representation.and_then(|_| {
            if self.is_host_surface() {
                crate::kuna_callabletransport::export_artifacts(fd, arch, self)
            } else {
                crate::kuna_callabletransport::required_artifacts(fd, arch, self)
            }
        }));
        if let Some(artifacts) = &callable_artifacts {
            match artifacts {
                Ok(artifacts) => for artifact in artifacts.iter().filter(|artifact| artifact.required || artifact.definition.is_none()) {
                    self.emit.tag_line();
                    self.emit_callable_artifact(&artifact.declaration);
                },
                Err(error) => {
                    self.emit.tag_line();
                    self.emit.print(&format!("/* callable transport: {} */", comment_safe(&error.to_string())),
                        SyntaxHighlight::CommentColor);
                }
            }
        }

        // Selected header comments share the sorter's emitted state with body
        // comments, so no comment can be emitted twice through separate walks.
        self.emit_comment_func_header();
        let proto = fd.get_func_proto();
        if self.is_host_surface() && proto.has_execution_signature() {
            let source_output = proto.source_output().get_type()
                .filter(|source| Some(*source) != proto.get_output_type());
            for source in proto.input_projections().iter()
                .filter_map(|projection| projection.source.get_type()).chain(source_output)
            {
                let Some(code) = source.get_ptr_to()
                    .filter(|code| code.get_metatype() == type_metatype::TYPE_CODE)
                else { continue };
                let view = source.read();
                let nominal = view.get(source.id()).expect("source datatype");
                let nominal = if nominal.get_name().is_empty() {
                    view.get(code.id()).expect("source callable datatype")
                } else { nominal };
                if nominal.get_name().is_empty() { continue; }
                let type_id = nominal.get_unsized_id().expect("nominal datatype host ID");
                let mut markup = MarkupRef::none();
                markup.type_id = Some(type_id);
                markup.type_name = Some(nominal.get_name().to_owned());
                self.emit.tag_line();
                self.emit.print("/* source type: ", SyntaxHighlight::CommentColor);
                self.emit.tag_type(&comment_safe(nominal.get_name()), SyntaxHighlight::TypeColor, &markup);
                self.emit.print(" */", SyntaxHighlight::CommentColor);
            }
        }
        self.emit.tag_line(); // emitCommentFuncHeader trailing tagLine

        // emitFunctionDeclaration shell (the prototype segment, shared with
        // `doc_prototype`).
        self.emit_prototype_declaration(fd, arch, &markup);
        // (kuna warnstyle, DIV-39) header-warning slugs collected by
        // emit_comment_func_header land at the end of the prototype line —
        // except under `braceformat function same`, where the brace shares
        // that line and must print BEFORE the comment (a `// slug {` would
        // swallow the brace).
        let id = if self.options.brace_func == BraceStyle::SameLine {
            let id = self.emit.open_brace_indent("{", to_emit_brace(self.options.brace_func));
            self.flush_eol_warnings();
            id
        } else {
            self.flush_eol_warnings();
            self.emit.open_brace_indent("{", to_emit_brace(self.options.brace_func))
        };
        // emitLocalVarDecls(fd) (printc.cc:2805 / emitGlobalVarDeclsRecursive +
        // the scope walk): one `<type> <name>;` per named local HighVariable, in
        // name order, followed by a blank separating line before the body.  The
        // ScopeLocal symbol walk is the W4 surface; we emit from the named
        // HighVariables directly (the `kuna_name` stand-in), which is the same set
        // of locals the scope would declare.
        let _emitted_decls = self.emit_local_var_decls(fd, arch);
        self.emit_call_result_decls(fd, arch);
        if fd.sblocks_get_size() != 0 {
            self.emit_function_body(fd, arch);
        } else {
            // No structured tree: keep the brace-matched shell and name the real
            // cause.  A caught pipeline abort discards the analyzed Funcdata, so
            // what is being rendered is the previous, un-decompiled one — that is
            // a pipeline failure (the driver stamped its reason), NOT structuring
            // declining on analyzed IR.
            self.emit.tag_line();
            let text = match fd.kuna_pipeline_failure() {
                Some(reason) => format!("/* WARNING: decompilation failed: {reason} */"),
                None => {
                    "/* WARNING: structured blocks unavailable (structuring declined) */".to_string()
                }
            };
            self.emit.print(&text, SyntaxHighlight::CommentColor);
        }
        // (kuna warnstyle, DIV-39) drain any slug still pending from a
        // construct with no closer flush point onto the last body line, so no
        // warning is ever silently dropped or carried out of this function.
        self.flush_eol_warnings();
        self.emit.close_brace_indent("}", id);
        self.emit.tag_line();
        self.emit.end_function(id1);
        if let Some(group) = layout_group {
            self.emit.close_group(group);
        }
        // (kuna) Retire the scoped fd pointer (see the field doc): it is valid
        // only for this call's dynamic extent.
        self.emit_fd = None;
    }

    /// (kuna `structdefs`) Emit the definitions of the composite/enum/typedef
    /// types this function's C names, above the function.
    ///
    /// Off by default, and a no-op for a function that names none.  The text is
    /// [`render_type_definitions`] over the referenced subset — the SAME
    /// renderer `kuna decompile-project` builds its `.h` type block with, so a
    /// preamble line and a header line for one type are one line.  A project
    /// export's bodies therefore suppress it (they include that header);
    /// see [`crate::kuna_structdefs`].
    ///
    /// Emitted as whole lines rather than tokens: a type definition has no
    /// `Varnode`/`PcodeOp` to bind markup to, so there is nothing for the
    /// markup back-end to reference beyond the line itself.
    fn emit_type_definition_preamble(&mut self, fd: &Funcdata) {
        if !self.options.struct_defs {
            return;
        }
        // (kuna outlang) The renderer is C by contract -- it builds a `.h` --
        // and a `struct X { … };` block in a Rust document is neither valid
        // Rust nor readable C. `kuna decompile-project` refuses a non-C output
        // language for the same reason rather than half-honouring it; here the
        // preamble declines and the body is emitted as it would be anyway.
        // Teaching the definition renderer the language plane belongs to that
        // plane, not to this option.
        if self.out_lang != crate::kuna_lang::OutLang::C {
            return;
        }
        let types = crate::kuna_structdefs::referenced_types(fd);
        if types.is_empty() {
            return;
        }
        let text = render_type_definitions(&types, self.rt_ctx);
        for line in text.trim_end_matches('\n').split('\n') {
            self.emit.tag_line();
            if !line.is_empty() {
                self.emit.print(line, SyntaxHighlight::NoColor);
            }
        }
        self.emit.tag_line();
    }

    /// Emit the function prototype declaration (the `emitFunctionDeclaration`
    /// shell of C++ `PrintC::docFunction`, printc.cc:2790 →
    /// `emitFunctionDeclaration`, printc.cc:2380): the recovered return type,
    /// the function name, and the parenthesised
    /// [`emit_prototype_inputs`](PrintC::emit_prototype_inputs) parameter list —
    /// `<ret> <name>(<params>)`, no trailing `;` or body.
    ///
    /// Pure code motion out of
    /// [`emit_function_document`](PrintC::emit_function_document) (byte-identical
    /// there) so [`doc_prototype`](PrintC::doc_prototype) can emit the IDENTICAL
    /// token sequence standalone — the `.h`-prototype == `.c`-definition-line
    /// contract of `kuna decompile-project`.
    fn emit_prototype_declaration(
        &mut self,
        fd: &Funcdata,
        arch: &Architecture,
        markup: &MarkupRef,
    ) {
        match self.lang().forms.proto {
            crate::kuna_lang::ProtoForm::CPrefixReturn => {
                self.emit_prototype_declaration_c(fd, arch, markup)
            }
            crate::kuna_lang::ProtoForm::RustFnArrow => {
                self.emit_prototype_declaration_rust(fd, arch, markup)
            }
        }
    }

    fn emit_prototype_declaration_c(
        &mut self,
        fd: &Funcdata,
        arch: &Architecture,
        markup: &MarkupRef,
    ) {
        let display = crate::kuna_callabletransport::emitted_body_name(fd, self);
        // Return type from the recovered proto output (C++ `getFuncProto().
        // getOutputType()`), defaulting to "void".  The output storage/type is
        // recovered by `ActionOutputPrototype` (the stand-alone `ProtoStoreInternal`
        // path).  The TYPE NAME is the W8 `ActionInferTypes` surface: until it
        // lands the recovered output type is the size-correct but un-inferred
        // base (metatype UNKNOWN), rendered as `undefined<N>` — the documented
        // residual vs. the oracle's inferred `uint1`.
        let (ret_type, ret_back) = if fd.get_func_proto().has_store() {
            fd.get_func_proto()
                .get_output_type()
                .map(|t| self.declaration_type_text(t))
                .unwrap_or_else(|| (TypeText::plain("void"), TypeText::default()))
        } else {
            (TypeText::plain("void"), TypeText::default())
        };

        self.cast_implied.record_return(format!("{}{}", ret_type.text, ret_back.text));
        let idp = self.emit.begin_func_proto();
        let idret = self.emit.begin_return_type(markup);
        self.emit_type_text(ret_type, markup, TypeTextOrigin::Type);
        self.emit.end_return_type(idret);
        self.emit.spaces(1, 0);
        let proto = fd.get_func_proto();
        let name = emitted_model_name(proto, self.options.convention);
        if !name.is_empty() {
                let highlight = if proto.is_model_unknown() {
                    SyntaxHighlight::ErrorColor
                } else {
                    SyntaxHighlight::KeywordColor
                };
            self.emit.print(name, highlight);
            self.emit.spaces(1, 0);
        }
        let id1g = self.emit.open_group();
        self.emit.tag_func_name(&display, SyntaxHighlight::FuncnameColor, markup);
        let id2 = self.emit.open_paren("(", 0);
        // emitPrototypeInputs (printc.cc:2298): the recovered proto's parameter
        // list, or `void` when there are none.  Each `ProtoParameter` renders its
        // declared type + name (`twostruct *ptr`, `int8 a`) via the C-declarator
        // builder; the backing-`Symbol` path (`emitVarDecl`) is the W4 scope
        // surface, so the param's own stored name + type are used directly.
        self.emit_prototype_inputs(fd, arch, markup);
        self.emit.close_paren(")", id2);
        if !ret_back.text.is_empty() {
            self.emit_type_text(ret_back, markup, TypeTextOrigin::Syntax);
        }
        self.emit.close_group(id1g);
        self.emit.end_func_proto(idp);
    }

    /// Emit selected comments placed in the function header by CommentSorter.
    fn emit_comment_func_header(&mut self) {
        self.commsorter.setup_header(crate::comment::header_kind::HEADER_BASIC);
        while self.commsorter.has_next() {
            let (emitted, tp, text, addr) = {
                let comment = self.commsorter.get_next();
                (comment.is_emitted(), comment.get_type(), comment.get_text().to_vec(),
                    comment.get_addr().clone())
            };
            if emitted || self.context.header_comment() & tp == 0 {
                continue;
            }
            if self.inline_warning(tp, crate::comment::comment_type::WARNINGHEADER) {
                if let Some(space) = addr.get_space() {
                    self.eol_warns.push((warning_slug(&String::from_utf8_lossy(&text)),
                        space.clone(), addr.get_offset()));
                }
            } else {
                self.emit_line_comment(0, &text, &addr);
            }
            self.commsorter.mark_last_emitted();
        }
    }

    /// Emit the function prototype's input parameter list (C++
    /// `PrintC::emitPrototypeInputs`, printc.cc:2298): `void` if there are no
    /// parameters, else the comma-separated `<type> <name>` declarations,
    /// followed by `, ...` for a vararg prototype.
    ///
    /// The C++ emits each parameter through its backing `Symbol` (`emitVarDecl`)
    /// when present, else the type with no name.  The merged-tree `ProtoParameter`
    /// has no backing `Symbol` (W4 scope), but it *does* carry the declared name +
    /// type (set by `update_all_types` from the parsed `PrototypePieces`), so the
    /// name + the C-declarator are rendered directly here — observationally the
    /// same text the C++ `emitVarDecl` produces for a named, typed parameter.
    fn emit_prototype_inputs(&mut self, fd: &Funcdata, arch: &Architecture, markup: &MarkupRef) {
        let proto = fd.get_func_proto();
        if !proto.has_store() {
            self.emit.tag_type("void", SyntaxHighlight::TypeColor, markup);
            return;
        }
        let sz = proto.num_params();
        if sz == 0 {
            self.emit.tag_type("void", SyntaxHighlight::TypeColor, markup);
        } else {
            let mut print_comma = false;
            for i in 0..sz {
                let param = match proto.get_param(i) {
                    Some(p) => p,
                    None => continue,
                };
                // hide_thisparam + isThisPointer: the `this`-pointer hiding is the
                // C++ option/class-method surface (no `this` on the recovery path).
                // C++ `emit->print(COMMA)` with `COMMA = ","` — no trailing space.
                if print_comma {
                    self.emit.print(",", SyntaxHighlight::NoColor);
                }
                print_comma = true;
                // The function-being-decompiled's prototype is backed by a
                // `ProtoStoreSymbol` in C++; a recovered (unlocked) parameter with
                // an empty stored name resolves through its scope symbol to the
                // default name (`Scope::buildDefaultName`, the
                // `Symbol::function_parameter` branch).  kuna's merged-tree proto
                // store keeps the literal empty name, so reproduce that default
                // here: angr-style `a<i>`, ghidra-style `param_<i+1>`.
                let default_name;
                let mut name = param.get_name();
                if name.is_empty() {
                    default_name = crate::database::kuna_materialized_param_name(
                        arch.name_style_angr,
                        i,
                        "",
                    );
                    name = default_name.as_str();
                }
                match param.get_type() {
                    Some(ty) => {
                        let (front, back) = self.declarator_text(ty);
                        self.cast_implied.record_param(name, format!("{}{}", front.text, back.text));
                        // C++ `pushTypeStart(type, noident)`: the separating token is
                        // `type_expr_nospace` only when there is no identifier AND no
                        // declarator modifier (`noident && typestack.size()==1`); else
                        // `type_expr_space`.  A `*` front glues to the name (no space).
                        let has_modifier = front.text.ends_with('*') || !back.text.is_empty();
                        let want_space =
                            !front.text.ends_with('*') && (!name.is_empty() || has_modifier);
                        self.emit_type_text(front, markup, TypeTextOrigin::Type);
                        if want_space {
                            self.emit.spaces(1, 0);
                        }
                        if !name.is_empty() {
                            self.emit.tag_variable(name, SyntaxHighlight::VarColor, markup);
                        }
                        if !back.text.is_empty() {
                            self.emit_type_text(back, markup, TypeTextOrigin::Syntax);
                        }
                    }
                    None => {
                        self.emit.tag_type("void", SyntaxHighlight::TypeColor, markup);
                    }
                }
            }
        }
        if proto.is_dotdotdot() {
            if sz != 0 {
                self.emit.print(",", SyntaxHighlight::NoColor);
            }
            self.emit.print("...", SyntaxHighlight::NoColor);
        }
    }

    /// Emit one `<type> <name>;  // <storage>` declaration per named local
    /// HighVariable, in name order, returning `true` if any were emitted (C++
    /// `emitLocalVarDecls` + `emitVarDeclStatement`, printc.cc:2652).  The W4
    /// ScopeLocal symbol walk is the missing surface; the named HighVariables
    /// (`kuna_name`) are the same locals the scope would declare.  A trailing
    /// blank `tag_line` separates the decl block from the body (the C++ blank line
    /// `emitVarDecl`s produce before the statement list).
    pub fn emit_local_var_decls(&mut self, fd: &Funcdata, arch: &Architecture) -> bool {
        // Collect (name, type_name, storage_comment) for each named local high,
        // de-duplicated by high and ordered by name.
        let mut decls: Vec<(crate::context::HighVariableId, String)> = Vec::new();
        let mut seen: std::collections::BTreeSet<crate::context::HighVariableId> =
            std::collections::BTreeSet::new();
        // (kuna) The authoritative signature-parameter name set. The `is_param`
        // storage-containment test below false-positives on a LOCAL high that merely
        // has an instance overlapping a parameter register (a merge artifact: an
        // un-coalesced phi output that picked up a param-register varnode). Such a
        // local was then SKIPPED from body declarations yet still emitted in the
        // statements -> an **undeclared variable / invalid C** (e.g. tar
        // make_directory's `v5`). Ghidra keys declarations on the Symbol category, so a
        // no_category local is always declared even when it overlaps a parameter; gate
        // the skip on the high's name actually being one of the prototype's parameters.
        // This only makes the skip STRICTER (never removes a declaration) — byte-identical
        // on any function that was already valid C.
        let param_names: std::collections::BTreeSet<String> = {
            let proto = fd.get_func_proto();
            let mut s = std::collections::BTreeSet::new();
            if proto.has_store() {
                for i in 0..proto.num_params() {
                    if let Some(p) = proto.get_param(i) {
                        let n = p.get_name();
                        let nm = if n.is_empty() {
                            crate::database::kuna_materialized_param_name(
                                arch.name_style_angr,
                                i,
                                "",
                            )
                        } else {
                            n.to_string()
                        };
                        s.insert(nm);
                    }
                }
            }
            s
        };
        let vlist: Vec<crate::context::VarnodeId> = fd.vbank().iter_loc().collect();
        for vn in vlist {
            let high = match fd.vbank().get(vn).and_then(|v| v.get_high()) {
                Some(h) => h,
                None => continue,
            };
            if seen.contains(&high) {
                continue;
            }
            let name = match fd.high_bank().get(high).and_then(|h| h.kuna_name()) {
                Some(n) => n.to_string(),
                None => continue,
            };
            seen.insert(high);
            if fd.execution_input_slot_for_high(high).is_some() {
                continue; // Declared by the physical execution header.
            }
            // A `&symbol` reference's offset is a CONSTANT operand of the PTRSUB
            // markup, not a scope Symbol.  When a constant-only reference high
            // SHADOWS a real local that is already declared from its own storage —
            // i.e. there is a whole-symbol sibling (`kuna_symbol_offset == -1`) with
            // the same name — the constant reference must NOT be declared a second
            // time (C++ `emitScopeVarDecls` walks the ScopeLocal Symbols once
            // (printc.cc:2667); the `&val` reference renders inline via the PTRSUB
            // markup).  Skipping it removes the spurious `int8 val;` shadow of the
            // real `int4 val` stack local.  The whole-sibling guard is load-bearing:
            // a constant-only reference with NO real sibling (the stack array `c` in
            // passPtrToArray, materialized only through `&c`) IS the symbol's sole
            // declaration and must still print.
            let all_constant = fd
                .high_bank()
                .get(high)
                .map(|h| {
                    let n = h.num_instances();
                    n > 0
                        && (0..n).all(|i| {
                            fd.vbank()
                                .get(h.get_instance(i))
                                .map(|v| v.is_constant())
                                .unwrap_or(false)
                        })
                })
                .unwrap_or(false);
            // A real local with the same name exists when another HighVariable
            // carries that name and has at least one NON-constant (storage)
            // instance — the stack/register varnodes the printer declares from.
            let has_storage_sibling = all_constant
                && fd.high_bank().iter().any(|(id, h)| {
                    id != high
                        && h.kuna_name() == Some(name.as_str())
                        && (0..h.num_instances()).any(|i| {
                            fd.vbank()
                                .get(h.get_instance(i))
                                .map(|v| !v.is_constant())
                                .unwrap_or(false)
                        })
                });
            if has_storage_sibling {
                continue;
            }
            // C++ `emitLocalVarDecls` -> `emitScopeVarDecls(fd->getScopeLocal(),
            // no_category)` walks the LOCAL scope only (printc.cc:2336/2667).  A
            // global-mapped Symbol (`glob1`, `globalfree`, `myarray`) lives in the
            // GLOBAL scope, so it is never declared in a function body — it is named
            // in the body's statements but carries no local declaration.  Two global
            // discriminators, both faithful to "not in `fd->getScopeLocal()`":
            //   * `Varnode::isPersist` — a persistent global RAM store/load high
            //     (`glob1 = 0`), whose member varnodes are flagged persist; and
            //   * `HighVariable::kuna_global` — a `&symbol` reference whose
            //     `linkSpacebaseSymbol` resolved through the GLOBAL scope
            //     (`sb->getMap()` == the global scope for a ram spacebase, e.g.
            //     `myarray` materialized as a const base address).  A *local*-frame
            //     spacebase reference (`&a`, `&myval.b`, `&c` in passPtrToArray) is
            //     NOT flagged, so its stack-symbol decl still prints.
            let is_global = fd
                .high_bank()
                .get(high)
                .map(|h| {
                    h.kuna_global()
                        || (0..h.num_instances()).any(|i| {
                            fd.vbank().get(h.get_instance(i)).map(|v| v.is_persist()).unwrap_or(false)
                        })
                })
                .unwrap_or(false);
            if is_global {
                continue;
            }
            // STUB A — C++ `emitScopeVarDecls`: `if (entry->isPiece()) continue;`
            // (printc.cc:2688) plus the multi-entry `getFirstWholeMap() != entry`
            // skip (printc.cc:2697).  A register-returned struct is split into
            // per-field proto-partial pieces (`RulePieceStructure`); each piece's
            // HighVariable is bound to the ROOT's name + the ROOT's whole-struct type
            // + its own in-symbol byte offset (`bind_proto_partial_piece`,
            // coreaction_cleanup.rs).  C++ shares ONE declaration for the whole
            // Symbol (the `getFirstWholeMap()` entry, type `foo`); the pieces are
            // partial entries and emit none.
            //
            // The kuna stand-in for "this entry is a piece of a multi-entry Symbol
            // whose first-whole-map is a different entry": the piece carries a
            // composite `kuna_symbol_type` (the root's struct/array/union whole type,
            // which a scalar field varnode never has on its own) AND a sibling ROOT
            // high exists — same shared name, `kuna_symbol_offset == -1` (the whole
            // keeps the `-1` default; pieces carry `>= 0`).  The sibling root IS the
            // `getFirstWholeMap()` entry and declares the shared `foo v1;` from its
            // own whole-struct varnode type.  A referenced *whole* local (`&a`,
            // `&myval.b` in passPtrToArray) carries a composite `kuna_symbol_type`
            // too but has NO `-1` sibling of the same name, so it stays declarable.
            let is_proto_partial_piece = fd.high_bank().get(high).is_some_and(|h| {
                let composite = h.kuna_symbol_type().is_some_and(|t| {
                    use crate::dtype::type_metatype::*;
                    matches!(t.get_metatype(), TYPE_STRUCT | TYPE_ARRAY | TYPE_UNION)
                });
                composite
                    && h.kuna_symbol_offset() >= 0
                    && high_name_has_whole_sibling(fd, high, &name)
            });
            if is_proto_partial_piece {
                continue;
            }
            // STUB A (scalar analogue) — C++ `emitScopeVarDecls` walks the ScopeLocal
            // *Symbol* table ONCE per Symbol (printc.cc:2667/2696), so a tied SCALAR
            // local read at several widths (the int8 `local` of LOSS-245, accessed as
            // int4/int2 sub-fields that `mergeAddrTied`/`groupWith` grouped) yields ONE
            // declaration (`int8 local;`) — not one per partial high.  The kuna printer
            // walks HighVariables, so each partial cover of the one scalar Symbol shows
            // up as its own would-be decl.  Skip a high that is a STRICT PARTIAL of a
            // scalar mapped Symbol (its storage rep is narrower than the whole Symbol
            // type, or it is offset into the symbol) when a WHOLE-cover sibling of the
            // same name exists (an instance-0 storage rep of exactly the symbol type's
            // size at offset 0) — that sibling is the C++ `getFirstWholeMap()` entry and
            // emits the single declaration.  Composites are handled above; this targets
            // the scalar tied-local case only and is inert when no whole sibling exists
            // (the partial then remains the symbol's sole declaration, e.g. a lone
            // mapped sub-access).
            let is_scalar_partial_piece = fd.high_bank().get(high).is_some_and(|h| {
                let scalar_sym = h.kuna_symbol_type().is_some_and(|t| {
                    use crate::dtype::type_metatype::*;
                    !matches!(t.get_metatype(), TYPE_STRUCT | TYPE_ARRAY | TYPE_UNION)
                });
                if !scalar_sym {
                    return false;
                }
                let sym_size = h.kuna_symbol_type().map(|t| t.get_size()).unwrap_or(0);
                let rep_size = if h.num_instances() > 0 {
                    fd.vbank().get(h.get_instance(0)).map(|v| v.get_size()).unwrap_or(0)
                } else {
                    0
                };
                // A strict partial: offset into the symbol, or narrower than the whole.
                let is_strict_partial = h.kuna_symbol_offset() > 0 || rep_size < sym_size;
                is_strict_partial && high_name_has_scalar_whole_sibling(fd, high, &name)
            });
            if is_scalar_partial_piece {
                continue;
            }
            // C++ `emitLocalVarDecls` -> `emitScopeVarDecls(scope, no_category)`:
            // only `no_category` Symbols are declared in the body.  A high bound to
            // a `function_parameter` Symbol renders in the signature, never as a body
            // local — skip it.  The high carries the parameter Symbol (C++
            // `linkSymbol` binds the parameter entry to the high), so any member
            // varnode whose storage covers a `function_parameter` Symbol marks the
            // whole high as a parameter.
            let scope = fd.get_scope_local();
            let is_param = scope
                .map(|lm| {
                    let h = fd.high_bank().get(high);
                    let n = h.map(|h| h.num_instances()).unwrap_or(0);
                    // A high is a parameter (declared in the signature, not the body)
                    // only when a `function_parameter` Symbol *contains* a member's
                    // whole storage — the C++ `emitScopeVarDecls(no_category)` walks
                    // Symbols by their own category, not by storage overlap.  Using a
                    // containing query (not bare overlap) is load-bearing: a wider
                    // local merged onto a register that also holds a narrower
                    // parameter (a `float8` cast result on `XMM0`, which also carries
                    // the `float4` arg) overlaps the parameter entry but is its own
                    // `no_category` local (the C++ `handleSymbolConflict` conflict
                    // spawns a fresh Symbol), so it must still be declared.
                    (0..n).any(|i| {
                        let m = h.unwrap().get_instance(i);
                        fd.vbank()
                            .get(m)
                            .map(|v| (v.get_addr().clone(), v.get_size()))
                            .and_then(|(addr, size)| lm.containing_category_for_varnode(&addr, size))
                            == Some(crate::database::symbol_category::FUNCTION_PARAMETER)
                    })
                })
                .unwrap_or(false);
            // Only skip as a signature parameter when the high is ALSO named as one of
            // the prototype's parameters (see `param_names` above): the storage test
            // alone false-positives on a local overlapping a param register, which would
            // then be emitted UNDECLARED (invalid C).
            if is_param && param_names.contains(name.as_str()) {
                continue;
            }
            // (kuna `paramrefdecl`) The Symbol-identity half of the same C++
            // predicate: an `&parameter` reference high has only the PTRSUB offset
            // CONSTANT as storage, so the containment test above cannot see that it
            // IS the parameter -- and declaring it re-declares the signature
            // parameter under its own name (invalid C).  See
            // `crate::kuna_paramrefdecl`.  The `param_names` guard is the same one
            // the storage arm carries: it only ever makes the skip stricter.
            if arch.param_ref_decl
                && param_names.contains(name.as_str())
                && crate::kuna_paramrefdecl::references_parameter_symbol(fd, high)
            {
                continue;
            }
            decls.push((high, name));
        }
        // (kuna `signedness`) A rounded declaration is only written for a high
        // that owns its declaration line.  Every collapse below pairs two
        // candidates that render the same NAME, so restricting the plan to
        // sole-named candidates keeps a flip from moving a collapse key or
        // re-signing a line a non-flipped sibling reads through.
        self.sign_plan
            .retain_sole_named(decls.iter().map(|(h, n)| (*h, n.as_str())));
        // C++ `emitScopeVarDecls` walks the ScopeLocal *Symbol* table and emits
        // exactly one declaration per multi-entry Symbol (the `getFirstWholeMap()`
        // entry; printc.cc:2696).  The kuna printer instead walks HighVariables and
        // dedups by high id, so a single mapped composite Symbol that is
        // represented by several `&symbol`-reference highs (each a piece of the
        // array/struct, all constant-only PTRSUB operands) is declared once per
        // high — a spurious repeat like `int2 arr [32]; int2 arr [32];`.
        //
        // Collapse to one declaration per Symbol: two declared highs are the same
        // Symbol when they share a name AND the same *composite* mapped type by graph
        // identity.  The type factory interns array/struct/union types, so one
        // mapped Symbol's pieces all carry the identical `kuna_symbol_type` ID;
        // distinct same-shaped locals are disambiguated by their (unique) names.
        // Restricting to composites is load-bearing: primitive types are shared by
        // every scalar local of that type, so `(name, int4-ID)` would not identify
        // a single Symbol — scalars keep the per-high behavior.
        {
            let mut seen_sym: std::collections::HashSet<(String, crate::dtype::TypeId)> = std::collections::HashSet::new();
            decls.retain(|(high, name)| {
                let composite_id = fd.high_bank().get(*high).and_then(|h| {
                    let t = h.kuna_symbol_type()?;
                    use crate::dtype::type_metatype::*;
                    matches!(t.get_metatype(), TYPE_ARRAY | TYPE_STRUCT | TYPE_UNION)
                        .then(|| t.id())
                });
                match composite_id {
                    Some(id) => seen_sym.insert((name.clone(), id)),
                    None => true,
                }
            });
        }
        decls.sort_by(|a, b| a.1.cmp(&b.1));
        if decls.is_empty() {
            return false;
        }
        // (kuna) The scalar analogue of the composite collapse above, keyed on the
        // ScopeLocal *Symbol* rather than on the interned type Rc: several highs of
        // one mapped scalar Symbol yield ONE declaration, as C++ `emitScopeVarDecls`
        // does by construction.  Shares `option dedupvardecls` with the rendered-line
        // collapse it generalises.  Returns the `sym->getType()` override for a
        // surviving declaration whose group disagreed on the type.
        let symbol_decl_type = if arch.dedup_var_decls {
            self.collapse_symbol_decls(fd, arch, &mut decls)
        } else {
            std::collections::HashMap::new()
        };
        // Run the lossless rendered-line collapse before unique spellings make
        // genuinely distinct declarations differ by construction.
        if arch.dedup_var_decls {
            let mut dedup = crate::kuna_dedupvardecls::DeclDedup::new();
            decls.retain(|(high, name)| {
                let (mut decl_type, mut decl_back, mut array_count, comment) =
                    self.rendered_local_decl(fd, arch, *high);
                if let Some((t, b, a)) = symbol_decl_type.get(high) {
                    decl_type = t.clone();
                    decl_back = b.clone();
                    array_count = a.clone();
                }
                let array_sig = array_count.as_ref().map(|(t, c)| (t.clone(), *c));
                let comment_sig = if arch.name_style_angr {
                    comment.as_ref().map(|(c, _, off)| (c.clone(), *off))
                } else {
                    None
                };
                !dedup.is_duplicate((decl_type.text, decl_back.text, name.clone(), array_sig, comment_sig))
            });
        }
        // A VariableGroup can describe AL/AH/AX-style overlap without a mapped
        // ScopeLocal Symbol. After the ordinary Symbol/identity collapses have
        // chosen their survivors, suppress a strict subpiece only when exactly
        // one surviving same-named piece contains every piece in the group. The
        // owner is guaranteed to remain declared, and references alias through it.
        let declared_names: std::collections::HashMap<crate::context::HighVariableId, String> =
            decls.iter().cloned().collect();
        decls.retain(|(high, name)| {
            let owner = fd.high_bank().unique_group_covering_high(*high);
            match owner.filter(|owner| owner != high).and_then(|owner| {
                declared_names
                    .get(&owner)
                    .filter(|owner_name| *owner_name == name)
                    .map(|_| owner)
            }) {
                Some(owner) => {
                    self.local_name_aliases.insert(*high, owner);
                    false
                }
                None => true,
            }
        });
        // If every semantic collapse declined, repeated grouped names are
        // distinct declarations. Their accesses must be relative to their own
        // piece-sized objects; retaining the group's offset/type decoration would
        // produce forms such as `byte_2._1_1_` against a one-byte declaration.
        let mut remaining_name_count = std::collections::HashMap::<String, usize>::new();
        for (_, name) in &decls {
            *remaining_name_count.entry(name.clone()).or_default() += 1;
        }
        for (high, name) in &decls {
            if remaining_name_count.get(name).copied().unwrap_or(0) > 1
                && fd.high_bank().high_piece_id(*high).is_some()
            {
                self.local_name_standalones.insert(*high);
            }
        }
        // Existing collapses remove declarations proven to denote one Symbol.
        // Repeated names left here are distinct HighVariables: suffix them in
        // deterministic declaration order, reserving parameters, global/callee
        // identifiers, and every original local spelling. Reserving non-locals is
        // semantic: a generated `value_1` local must not capture an existing
        // `value_1` global or direct call. The override is also read by all body
        // render paths.
        {
            let original: Vec<String> = decls.iter().map(|(_, name)| name.clone()).collect();
            let occupied = declaration_occupied_names(fd, param_names);
            let mut names = crate::kuna_dedupvardecls::DeclNameUniquifier::new(
                original.iter().map(String::as_str),
                occupied.iter().map(String::as_str),
            );
            for (high, name) in &mut decls {
                let unique = names.unique(name);
                if unique != *name {
                    self.local_name_overrides.insert(*high, unique.clone());
                    *name = unique;
                }
            }
        }
        for (high, name) in &decls {
            // C++ `emitVarDecl(sym)` always writes the declared symbol's id
            // (prettyprint.cc:154 `writeUnsignedInteger(ATTRIB_SYMREF, sym->getId())`),
            // and Ghidra's `ClangVariableDecl.decode` does a REQUIRED read of `symref`:
            // an ABSENT attribute aborts the whole markup decode with "Attribute symref
            // is not present", so the Decompiler window shows nothing for any function
            // that declares a local.
            //
            // (kuna, ghidra Phase 4) The id must be the LocalSymbolMap id the
            // `<localdb>` encodes — Java resolves `symref` through that map
            // (`ClangVariableDecl.decode` → `pfactory.getSymbol(symref)`), and
            // right-click rename/retype ON THE DECLARATION LINE resolves the
            // HighSymbol exclusively through it.  Phase 2 wrote the
            // declaration representative's varnode create index here as a
            // stand-in (no symbols existed yet); now that real symbols do, an
            // unresolvable create index would log "Invalid symbol reference"
            // once per declaration per decompile AND leave declaration-token
            // rename/retype dead.  The create index survives only as the
            // fallback for a high the naming pass deliberately left
            // symbol-less.
            //
            // NO `varref`: upstream's `emitVarDecl` pushes an explicitly null
            // Varnode (`pushSymbol(sym,(Varnode *)0,(PcodeOp *)0)`,
            // printc.cc:2629-2640), and the omission is load-bearing —
            // `ClangVariableToken.getHighVariable` returns `inst.getHigh()`
            // from INSIDE its `inst != null` block, so a declaration carrying a
            // varref whose Varnode has no `<high>` yields a NULL HighVariable
            // where the (unconditional) parent-declaration fallback would have
            // supplied the symbol's own.
            let mut markup = MarkupRef::none();
            let decl_rep = decl_rep_varnode(fd, *high);
            let decl_rep_index = decl_rep
                .and_then(|vn| fd.vbank().get(vn))
                .map(|v| v.get_create_index() as uintb);
            // The declaration may be keyed on a GROUP MEMBER high while the
            // name (and therefore the Symbol) resolved on the group's naming
            // high — resolve through the declaration representative's own
            // high as well before falling back.
            markup.symref = fd
                .kuna_high_symbol_wire_id(*high)
                .or_else(|| {
                    decl_rep
                        .and_then(|vn| fd.vbank().get(vn))
                        .and_then(|v| v.get_high())
                        .and_then(|h| fd.kuna_high_symbol_wire_id(h))
                })
                .or(decl_rep_index);
            let (mut decl_type, mut decl_back, mut array_count, comment) =
                self.rendered_local_decl(fd, arch, *high);
            // (kuna) The Symbol-keyed collapse arbitrated a type disagreement between
            // the several highs of one Symbol.
            if let Some((t, b, a)) = symbol_decl_type.get(high) {
                decl_type = t.clone();
                decl_back = b.clone();
                array_count = a.clone();
            }
            // (kuna `signedness`) A cast on this local may only be dropped as
            // redundant when the rounded type is what actually reached the
            // declaration line - not when a Symbol/array/collapse override took
            // it back.
            if let Some(rounded) = self.sign_plan.decl_type(*high).cloned() {
                let want = type_name_for_decl(&rounded, self.rt_ctx);
                if decl_type.text == want.0 && decl_back.text == want.1 && array_count.is_none() {
                    self.sign_plan.record_applied(*high, rounded);
                }
            }
            if array_count.is_none() {
                self.cast_implied.record_local(*high, format!("{}{}", decl_type.text, decl_back.text));
            }
            self.emit.tag_line();
            let id = self.emit.begin_var_decl(&markup);
            match self.lang().forms.decl {
                crate::kuna_lang::DeclForm::CTypeThenName => {
                    let want_space = !decl_type.text.ends_with('*');
                    self.emit_type_text(decl_type, &markup, TypeTextOrigin::Type);
                    // C++ `ptr_expr` glues the `*` directly to the identifier (no
                    // space); every other base type gets the single
                    // `type_expr_space`.  A pointer declarator front already ends
                    // in `*`, so suppress the separator.
                    if want_space {
                        self.emit.spaces(1, 0);
                    }
                    self.emit.tag_variable(name, SyntaxHighlight::VarColor, &markup);
                    if let Some((_, count)) = &array_count {
                        // ` [count]` (C++ `emitArrayDecl`: a space then the
                        // bracketed count).
                        self.emit.spaces(1, 0);
                        self.emit.print("[", SyntaxHighlight::NoColor);
                        self.emit.print(&format!("{count}"), SyntaxHighlight::ConstColor);
                        self.emit.print("]", SyntaxHighlight::NoColor);
                    }
                    if !decl_back.text.is_empty() {
                        self.emit_type_text(decl_back, &markup, TypeTextOrigin::Syntax);
                    }
                }
                crate::kuna_lang::DeclForm::RustLetColon => {
                    let count = array_count.as_ref().map(|(_, c)| *c);
                    self.emit_var_decl_rust(name, decl_type, count, &markup);
                }
            }
            self.emit.end_var_decl(id);
            self.emit.print(self.lang().kw_semicolon, SyntaxHighlight::NoColor);
            // (kuna) the storage comment (`// eax` / `// stack - 0xNN`) is the
            // angr-style local annotation; the ghidra naming scheme (`option
            // namestyle ghidra`, `name_style_angr = false`) emits no storage
            // comment.  Gate the emit on the flag (default angr → unchanged, so
            // the 675 corpus is unaffected).
            if arch.name_style_angr {
                if let Some((ctext, spc, off)) = comment {
                    self.emit.spaces(1, 0);
                    self.emit.tag_comment(&format!("// {ctext}"), SyntaxHighlight::CommentColor, &spc, off);
                }
            }
        }
        // Blank separating line before the body (C++ emits a tag_line after the
        // last decl; the body's first statement then starts on its own line).
        self.emit.tag_line();
        true
    }

    /// Resolve the emitted spelling of a named HighVariable in this function.
    fn emitted_high_name(
        &self,
        fd: &Funcdata,
        high: crate::context::HighVariableId,
    ) -> Option<String> {
        let high = self.local_name_aliases.get(&high).copied().unwrap_or(high);
        if let Some(name) = self.local_name_overrides.get(&high) {
            return Some(name.clone());
        }
        let high = fd.high_bank().get(high)?;
        let name = high.kuna_name()?;
        Some(match high.kuna_symbol_scope() {
            Some(scope) => self.emitted_scoped_name(fd, name, scope, false),
            None => name.to_string(),
        })
    }

    /// Apply display-only namespace policy to the original symbol binding.
    /// Global scope itself is omitted except when minimal resolution needs `::`
    /// to escape a local collision, matching PrintC::pushSymbolScope.
    fn emitted_scoped_name(
        &self,
        fd: &Funcdata,
        base: &str,
        scope: &[String],
        declaration: bool,
    ) -> String {
        use crate::printlanguage::NamespaceStrategy;
        match self.context.namespace_strategy() {
            NamespaceStrategy::NoNamespaces => base.to_string(),
            NamespaceStrategy::MinimalNamespaces if !declaration => {
                let function_scope = fd.get_address().get_space().and_then(|_| {
                    fd.get_arch().name_for_global_varnode_scoped(
                        fd.get_address(), 1, &kuna_base::address::Address::new_invalid(),
                    )
                });
                let function_path = match function_scope {
                    Some((_, _, _, path)) if !path.is_empty() => path.into_iter().rev().collect(),
                    _ => crate::coreaction_cleanup::kuna_function_namespace_path(fd.get_display_name()),
                };
                crate::coreaction_cleanup::kuna_qualify_global_name(
                    base, scope, &function_path,
                    &|name| fd.get_scope_local().map(|lm| lm.local_name_used(name)).unwrap_or(false),
                )
            }
            _ => {
                let mut name = String::new();
                for part in scope.iter().rev() {
                    name.push_str(part);
                    name.push_str("::");
                }
                name.push_str(base);
                name
            }
        }
    }

    pub(crate) fn emitted_function_name(
        &self,
        fd: &Funcdata,
        name: &str,
        entry: &kuna_base::address::Address,
        declaration: bool,
    ) -> String {
        // The CLI's cross-scope lookup supplies a deliberately fully-qualified
        // display label, not a bare symbol plus optional ancestry. Preserve that
        // chosen spelling unless namespaces were explicitly disabled. Host
        // symbols instead carry their base label and ancestry separately.
        if let Some((_, base)) = name.rsplit_once("::") {
            return match self.context.namespace_strategy() {
                crate::printlanguage::NamespaceStrategy::NoNamespaces => base.to_string(),
                _ => name.to_string(),
            };
        }
        // Named intrinsics and synthetic calls need not have an address.
        // Without a real address and a matching symbol, the supplied name
        // is all the identity we have; do not invent global-scope ancestry.
        let scoped = entry.get_space().and_then(|_| {
            fd.get_arch().name_for_global_varnode_scoped(
                entry, 1, &kuna_base::address::Address::new_invalid(),
            )
        });
        let Some((_, _, _, scope)) = scoped else {
            return name.to_string();
        };
        self.emitted_scoped_name(fd, name, &scope, declaration)
    }

    /// Record the whole authenticated symbol, not the type of one partial read.
    fn record_named_global_binding(&mut self, fd: &Funcdata, address: &Address,
        offset: int4, name: &str, datatype: &crate::dtype::TypeRoot)
    {
        if self.out_lang != crate::kuna_lang::OutLang::C || offset < 0 || datatype.get_size() <= 0
            || matches!(datatype.get_metatype(), type_metatype::TYPE_CODE | type_metatype::TYPE_SPACEBASE)
            || !address.get_space().zip(fd.get_arch().manage().get_default_data_space())
                .is_some_and(|(space, data)| std::rc::Rc::ptr_eq(space, data)) { return; }
        let Some(base) = address.get_offset().checked_sub(offset as u64) else { return; };
        let base_address = Address::new(address.get_space().expect("authenticated global space").clone(), base);
        let volatile = fd.get_arch().query_container_global(&base_address, datatype.get_size(), &Address::new_invalid())
            .is_some_and(|entry| entry.entry_addr == base_address && entry.symbol_offset == 0
                && entry.symbol_type.as_ref() == Some(datatype)
                && entry.all_flags & crate::varnode::varnode_flags::volatil != 0);
        self.globalref.record_named(base, name, datatype, volatile);
    }

    fn record_named_high_global(&mut self, fd: &Funcdata, high: crate::context::HighVariableId,
        name: &str, datatype: &crate::dtype::TypeRoot)
    {
        if self.out_lang != crate::kuna_lang::OutLang::C
            || matches!(datatype.get_metatype(), type_metatype::TYPE_CODE | type_metatype::TYPE_SPACEBASE)
        { return; }
        let Some(high) = fd.high_bank().get(high) else { return; };
        if high.kuna_symbol_scope().is_none() { return; }
        for index in 0..high.num_instances() {
            let id = high.get_instance(index);
            let Some(value) = fd.vbank().get(id) else { continue; };
            let (address, size) = if value.is_constant() {
                if !high.kuna_global() { continue; }
                let Some(address) = fd.resolve_spacebase_ref_addr(id) else { continue; };
                (address, 1)
            } else { (value.get_addr().clone(), value.get_size()) };
            if !address.get_space().zip(fd.get_arch().manage().get_default_data_space())
                .is_some_and(|(space, data)| std::rc::Rc::ptr_eq(space, data)) { continue; }
            let Some((base, offset, Some(symbol_type), scope)) = fd.get_arch()
                .name_for_global_varnode_scoped(&address, size, &Address::new_invalid()) else { continue; };
            if &symbol_type != datatype || self.emitted_scoped_name(fd, &base, &scope, false) != name { continue; }
            self.record_named_global_binding(fd, &address, offset, name, &symbol_type);
            break;
        }
    }

    /// Resolve the emitted name plus the symbol-relative geometry used to render
    /// partial accesses. Independently declared fallback pieces deliberately have
    /// no shared-symbol geometry: their declared identifier denotes the piece.
    fn emitted_high_symbol(
        &mut self,
        fd: &Funcdata,
        high: crate::context::HighVariableId,
    ) -> Option<(String, int4, Option<crate::dtype::TypeRoot>)> {
        let name = self.emitted_high_name(fd, high)?;
        if self.local_name_standalones.contains(&high) {
            return Some((name, -1, None));
        }
        let h = fd.high_bank().get(high)?;
        let datatype = h.kuna_symbol_type().cloned();
        if let Some(datatype) = &datatype {
            self.record_named_high_global(fd, high, &name, datatype);
        }
        Some((name, h.kuna_symbol_offset(), datatype))
    }

    /// (kuna) The fully-rendered declaration of one local high: the final declarator
    /// type, the declarator suffix that follows the name (`)[16]` for a pointer to
    /// an array, else empty), the `[count]` array adornment (when the mapped Symbol
    /// — or the declaration representative itself — is an array), and the storage
    /// comment.
    ///
    /// Shared by [`Self::collapse_symbol_decls`] and the emit loop so the collapse
    /// compares exactly the bytes the emit loop would write.
    fn rendered_local_decl(
        &self,
        fd: &Funcdata,
        arch: &Architecture,
        high: crate::context::HighVariableId,
    ) -> (
        TypeText,
        TypeText,
        Option<(String, int4)>,
        Option<(String, std::rc::Rc<kuna_base::space::AddrSpace>, u64)>,
    ) {
        // Type: the high's recovered type name (W8-unknown -> `undefined<N>`).
        let (mut type_name, comment) = self.local_decl_type_and_comment(fd, arch, high);
        let rt = self.rt_ctx; // (kuna) realtypes ctx for the composite/array relabel

        // C++ `emitVarDecl` declares the whole *Symbol*'s type (printc.cc:1719
        // `sym->getType()`), not the partial member Varnode's type.  When the
        // high is a non-array partial cover of a composite Symbol (a struct/
        // union member, `kuna_symbol_offset() >= 0`), the local storage
        // representative carries only the truncated member type (e.g. the
        // 1-byte `flagfield` read => `undefined1`); declare the composite Symbol
        // type (`enumstruct`) so the member access `v1.flagfield` has a base of
        // the right type.  (The array case is handled by `array_count` below, so
        // it is excluded here.)
        if let Some(st) = fd.high_bank().get(high).and_then(|h| {
            if h.kuna_symbol_offset() >= 0 {
                h.kuna_symbol_type()
            } else {
                None
            }
        }) {
            let mt = st.get_metatype();
            if mt == crate::dtype::type_metatype::TYPE_STRUCT
                || mt == crate::dtype::type_metatype::TYPE_UNION
            {
                type_name = self.declaration_type_text(st);
            }
        }
        // Array member: if the mapped Symbol is an array, declare the base
        // type and an `[count]` adornment after the name (C++ `emitVarDecl`'s
        // array branch).
        let array_decl = fd
            .high_bank()
            .get(high)
            .and_then(|h| {
                let st = h.kuna_symbol_type()?;
                array_decl_parts(&st, rt, self.is_host_surface())
            })
            // No mapped-Symbol array: fall back to the declaration representative's
            // own data-type.  An anonymous `undefined1 [N]` array (an oversize
            // unknown - e.g. a 32-byte YMM FMA accumulator, GH-9184 - that
            // `getBase` widened past `max_basetype_size`) lives on the Varnode
            // itself, never a Symbol; declare it `<base> name [N]` instead of
            // flattening it to a scalar `undefined<N>`.
            .or_else(|| {
                let v = decl_rep_varnode(fd, high).and_then(|vn| fd.vbank().get(vn))?;
                array_decl_parts(v.get_type(), rt, self.is_host_surface())
            });
        let ((decl_type, decl_back), array_count) = match array_decl {
            Some(((front, back), count)) => {
                let name = front.text.clone();
                ((front, back), Some((name, count)))
            }
            None => (type_name, None),
        };
        (decl_type, decl_back, array_count, comment)
    }

    /// (kuna) Collapse the declarations of the several HighVariables that share one
    /// ScopeLocal **Symbol** into a single declaration, and report the type the
    /// survivor should carry.
    ///
    /// C++ `PrintC::emitScopeVarDecls` walks the Symbol table (printc.cc:2667/2696),
    /// so one Symbol is one declaration by construction; the kuna printer walks
    /// HighVariables, so a stack slot whose live ranges did not merge is declared once
    /// per high — the same identifier declared twice with two recovered types, which
    /// is invalid C.  Two declarations are the same Symbol when the storage of their
    /// declaration representatives resolves to the same containing ScopeLocal Symbol
    /// **and** they render the same identifier; requiring the name to match keeps the
    /// collapse from ever removing the sole declaration of a referenced name (the
    /// undeclared-variable failure mode of the `declmerge` gate).
    ///
    /// The survivor is the first in emission order.  A group that already agreed on a
    /// rendered type keeps it — the highs recovered it, which is sharper information
    /// than the (usually `undefined<N>`) Symbol type.  A group that did NOT agree is
    /// arbitrated by the returned type override: the Symbol's own type, the direct
    /// analogue of C++ `emitVarDecl`'s `sym->getType()` (printc.cc:1719), unless that
    /// type is **narrower** than the widest storage the group covers, in which case
    /// the widest member's rendering wins.  kuna's `ScopeLocal` ranges can be narrower
    /// than the accesses that reach them (upstream `restructure` would have grown the
    /// Symbol), and a declaration smaller than the object the body writes through is a
    /// fresh correctness bug, not a faithful one.
    fn collapse_symbol_decls(
        &self,
        fd: &Funcdata,
        arch: &Architecture,
        decls: &mut Vec<(crate::context::HighVariableId, String)>,
    ) -> std::collections::HashMap<crate::context::HighVariableId, DeclTypeOverride> {
        let mut overrides: std::collections::HashMap<
            crate::context::HighVariableId,
            DeclTypeOverride,
        > = std::collections::HashMap::new();
        let scope = match fd.get_scope_local() {
            Some(s) => s,
            None => return overrides,
        };
        // A collapse needs two declarations of one identifier, so nothing outside a
        // repeated name can move.  `decls` is sorted by name, so the repeats are
        // adjacent; when there are none (the overwhelming majority of functions) the
        // Symbol lookups below are skipped entirely.
        let repeated: std::collections::HashSet<&str> = decls
            .windows(2)
            .filter(|w| w[0].1 == w[1].1)
            .map(|w| w[0].1.as_str())
            .collect();
        if repeated.is_empty() {
            return overrides;
        }
        // The Symbol identity of each repeated-name declaration, plus the Symbol's own
        // type.  A high with no containing Symbol (a register/unique temp that never
        // reached the local scope) keeps the per-high behavior.
        let keys: Vec<Option<(crate::database::SymbolId, Option<crate::dtype::TypeRoot>)>> =
            decls
                .iter()
                .map(|(high, name)| {
                    if !repeated.contains(name.as_str()) {
                        return None;
                    }
                    let v = decl_rep_varnode(fd, *high).and_then(|vn| fd.vbank().get(vn))?;
                    scope.containing_symbol_for_storage(v.get_addr())
                })
                .collect();
        let mut groups: std::collections::HashMap<(crate::database::SymbolId, String), Vec<usize>> =
            std::collections::HashMap::new();
        for (i, key) in keys.iter().enumerate() {
            if let Some((sym, _)) = key {
                groups.entry((*sym, decls[i].1.clone())).or_default().push(i);
            }
        }
        let mut dropped: std::collections::HashSet<usize> = std::collections::HashSet::new();
        for idxs in groups.values() {
            if idxs.len() < 2 {
                continue;
            }
            let keep = idxs[0];
            for &i in &idxs[1..] {
                dropped.insert(i);
            }
            let rendered: Vec<DeclTypeOverride> = idxs
                .iter()
                .map(|&i| {
                    let (t, b, a, _) = self.rendered_local_decl(fd, arch, decls[i].0);
                    (t, b, a)
                })
                .collect();
            if rendered.iter().all(|r| same_decl_text(r, &rendered[0])) {
                continue;
            }
            // The group disagrees about the slot's type.  The widest storage any
            // member covers is the floor: the declared object must hold every access
            // the body renders through this name.
            let widths: Vec<int4> = idxs
                .iter()
                .map(|&i| {
                    decl_rep_varnode(fd, decls[i].0)
                        .and_then(|vn| fd.vbank().get(vn))
                        .map(|v| v.get_size())
                        .unwrap_or(0)
                })
                .collect();
            let wmax = widths.iter().copied().max().unwrap_or(0);
            // C++ declares the Symbol's own type.  A composite Symbol is already
            // collapsed by the type-Rc retain and declares through the array/struct
            // branches, so only a wide-enough scalar Symbol type arbitrates here.
            let symbol_type = keys[keep].as_ref().and_then(|(_, t)| t.as_ref()).filter(|st| {
                use crate::dtype::type_metatype::*;
                !matches!(st.get_metatype(), TYPE_ARRAY | TYPE_STRUCT | TYPE_UNION)
                    && st.get_size() >= wmax
            });
            match symbol_type {
                Some(st) => {
                    let (front, back) = self.declaration_type_text(st);
                    overrides.insert(decls[keep].0, (front, back, None));
                }
                // No usable Symbol type: declare the widest member's own rendering.
                None => {
                    let pos = widths.iter().position(|&w| w == wmax).unwrap_or(0);
                    if !same_decl_text(&rendered[pos], &rendered[0]) {
                        overrides.insert(decls[keep].0, rendered[pos].clone());
                    }
                }
            }
        }
        if !dropped.is_empty() {
            let mut i = 0;
            decls.retain(|_| {
                let keep = !dropped.contains(&i);
                i += 1;
                keep
            });
        }
        overrides
    }

    /// The declaration type name + storage comment for a named local high.  The
    /// comment is the angr `kunaStorageComment` (register name lowercased) for the
    /// high's name representative.
    fn local_decl_type_and_comment(
        &self,
        fd: &Funcdata,
        arch: &Architecture,
        high: crate::context::HighVariableId,
    ) -> ((TypeText, TypeText), Option<(String, std::rc::Rc<kuna_base::space::AddrSpace>, u64)>) {
        let h = match fd.high_bank().get(high) {
            Some(h) => h,
            None => return ((TypeText::plain("undefined1"), TypeText::default()), None),
        };
        // Type name + storage comment: from the high's storage representative -
        // the addr-tied (mapped, in-scope) member, which is the C++ symbol's
        // `getFirstWholeMap()` storage (e.g. the ACC register), NOT a trim-COPY
        // unique.  Fall back to instance 0 if none is addr-tied.
        let rep = decl_rep_varnode(fd, high);
        // (kuna `declhightype`) The declared type is the merged high's own -- the
        // one `ActionSetCasts` checked every use in the body against -- not
        // whichever member happens to be address-tied or first.  See
        // `crate::kuna_declhightype`.
        let type_rep = if arch.decl_high_type {
            crate::kuna_declhightype::type_representative(fd, high)
        } else {
            None
        };
        let type_rep = type_rep.filter(|_| {
            crate::kuna_declhightype::declares_from_high(fd, high)
        });
        let (type_name, comment) = match rep.and_then(|vn| fd.vbank().get(vn)) {
            Some(v) => {
                let decl_ty = type_rep
                    .and_then(|vn| fd.vbank().get(vn))
                    .map(|tv| tv.get_type())
                    .unwrap_or_else(|| v.get_type());
                // (kuna `signedness`) The rounded declaration, when the operation
                // set decided one for this high.
                let decl_ty = self.sign_plan.decl_type(high).unwrap_or(decl_ty);
                // Execution projections already carry their proved SSA type.
                // A native/global source pointer must not be widened by printing.
                let tn = self.declaration_type_text(decl_ty);
                let loc = v.get_addr().clone();
                let size = v.get_size();
                let comment = loc.get_space().and_then(|spc| {
                    let regname = arch.translate().get_register_name(spc, loc.get_offset(), size);
                    if !regname.is_empty() {
                        // kunaStorageComment: register name lowercased.
                        return Some((regname.to_ascii_lowercase(), spc.clone(), loc.get_offset()));
                    }
                    // Stack local: `// stack - 0xNN` / `// stack + 0xNN`
                    // (C++ `kunaStorageComment` for a spacebase local).
                    if spc.get_index() == fd.get_arch().manage().get_stack_space().map(|s| s.get_index()).unwrap_or(-99) {
                        // For an array/struct member the declaration is anchored at
                        // the Symbol base, so subtract the in-symbol byte offset.
                        let sym_off = h.kuna_symbol_offset();
                        let base_off = if sym_off > 0 {
                            loc.get_offset().wrapping_sub(sym_off as u64)
                        } else {
                            loc.get_offset()
                        };
                        // Signed offset within the stack space.
                        let signed = kuna_base::address::sign_extend(base_off as i64, (spc.get_addr_size() as i32) * 8 - 1);
                        let text = if signed < 0 {
                            format!("stack - {:#x}", (-signed) as u64)
                        } else {
                            format!("stack + {:#x}", signed as u64)
                        };
                        return Some((text, spc.clone(), loc.get_offset()));
                    }
                    None
                });
                (tn, comment)
            }
            None => ((TypeText::plain("undefined1"), TypeText::default()), None),
        };
        (type_name, comment)
    }

    /// Emit the structured function body into the open brace (C++
    /// `emitLocalVarDecls(fd)` + `emitBlockGraph(&fd->getStructure())`,
    /// printc.cc:2805-2809).  Local var decls need the Symbol table (the merge/
    /// naming layer); the structured block graph walk is driven here.
    pub fn emit_function_body(&mut self, fd: &Funcdata, arch: &Architecture) {
        let sroot = match fd.sblocks_ref().root {
            Some(r) => r,
            None => return,
        };
        // Drop any pending-brace fire log from a previous function so the
        // per-registration `pend_fired` record cannot accumulate across a
        // load-once/decompile-many run (generations are globally unique, so this
        // is purely to bound memory, not for correctness).
        self.emit.reset_pending_fired();
        self.void_tail_return = if arch.voidtailreturn {
            elidable_void_tail_return(fd, arch.decode_halt)
        } else {
            None
        };
        self.emit_block_graph(fd, arch, sroot);
        self.void_tail_return = None;
    }

    /// C++ `PrintC::emitBlockGraph` (printc.cc:2895): emit each component block.
    fn emit_block_graph(&mut self, fd: &Funcdata, arch: &Architecture, graph: BlockId) {
        let list: Vec<BlockId> = fd.sblocks_ref().block(graph).get_list().to_vec();
        for blk in list {
            let id = self.emit.begin_block(0);
            self.emit_block(fd, arch, blk);
            self.emit.end_block(id);
        }
    }

    /// Dispatch one structured block to its emitter (C++ the virtual
    /// `FlowBlock::emit(PrintLanguage*)` -> `PrintC::emitBlock*`).
    pub(crate) fn emit_block(&mut self, fd: &Funcdata, arch: &Architecture, blk: BlockId) {
        use crate::block::BlockType;
        match fd.sblocks_ref().block(blk).get_type() {
            BlockType::Copy => self.emit_block_copy(fd, arch, blk),
            BlockType::Basic => self.emit_block_basic(fd, arch, blk),
            BlockType::Ls => self.emit_block_ls(fd, arch, blk),
            BlockType::If => self.emit_block_if(fd, arch, blk),
            BlockType::Graph => self.emit_block_graph(fd, arch, blk),
            BlockType::Goto => self.emit_block_goto(fd, arch, blk),
            BlockType::WhileDo => self.emit_block_while_do(fd, arch, blk),
            BlockType::DoWhile => self.emit_block_do_while(fd, arch, blk),
            BlockType::InfLoop => self.emit_block_inf_loop(fd, arch, blk),
            BlockType::Condition => self.emit_block_condition(fd, arch, blk),
            BlockType::Switch => self.emit_block_switch(fd, arch, blk),
            // multigoto: its emitter is the next structuring layer.  Fall through
            // to the component blocks.
            _ => {
                let list: Vec<BlockId> = fd.sblocks_ref().block(blk).get_list().to_vec();
                for c in list {
                    self.emit_block(fd, arch, c);
                }
            }
        }
    }

    /// C++ `PrintC::emitBlockCondition` (printc.cc:2985): emit a `BlockCondition`
    /// (the two short-circuited `&&`/`||` clauses).
    ///
    /// The condition node has no statement body of its own; it is only emitted as
    /// the boolean expression of an enclosing `if`/loop.  In the `no_branch`
    /// state (the "statements before the branch" pass of `emitBlockIf`) only the
    /// first clause's leading statements print.  In the `only_branch`/
    /// `comma_separate` state (the branch-condition pass) the two clauses print
    /// glued by ` && ` / ` || `, each wrapped in parens — matching the C++
    /// `(a && b)` form.
    fn emit_block_condition(&mut self, fd: &Funcdata, arch: &Architecture, blk: BlockId) {
        let b0 = fd.sblocks_ref().block(blk).get_block(0);
        // no_branch: emit only the first clause's leading statements.
        if self.context.is_set(modifiers::NO_BRANCH) {
            let id = self.emit.begin_block(0);
            self.emit_block(fd, arch, b0);
            self.emit.end_block(id);
            return;
        }
        if self.context.is_set(modifiers::ONLY_BRANCH) || self.context.is_set(modifiers::COMMA_SEPARATE)
        {
            let b1 = fd.sblocks_ref().block(blk).get_block(1);
            let opc = fd
                .sblocks_ref()
                .block(blk)
                .get_condition_opcode()
                .unwrap_or(OpCode::CPUI_BOOL_AND);

            let id = self.emit.open_paren(crate::printlanguage::OPEN_PAREN, 0);
            self.emit_block(fd, arch, b0);
            self.context.push_mod();
            self.context.unset_mod(modifiers::ONLY_BRANCH);
            // comma_separate is placed only on the second block.
            self.context.set_mod(modifiers::COMMA_SEPARATE);

            // Emit the && / || token as if it were on the RPN stack (C++ builds a
            // ReversePolish with op==0, visited==1, and calls emitOp).
            let tok: &'static crate::printlanguage::OpToken = if opc == OpCode::CPUI_BOOL_AND {
                &tokens::BOOLEAN_AND
            } else {
                &tokens::BOOLEAN_OR
            };
            let mut pol = ReversePolish { tok, visited: 1, paren: false, op: None, id: 0, id2: 0 };
            self.emit_op(&mut pol);

            let id2 = self.emit.open_paren(crate::printlanguage::OPEN_PAREN, 0);
            self.emit_block(fd, arch, b1);
            self.emit.close_paren(crate::printlanguage::CLOSE_PAREN, id2);
            self.context.pop_mod();
            self.emit.close_paren(crate::printlanguage::CLOSE_PAREN, id);
        }
    }

    /// C++ `PrintC::emitBlockCopy` (printc.cc:2908): emit the underlying basic
    /// block (the `BlockCopy.copy` points back into `bblocks`).
    fn emit_block_copy(&mut self, fd: &Funcdata, arch: &Architecture, blk: BlockId) {
        // emitBlockCopy -> emitAnyLabelStatement(bl) (printc.cc:2894): a label line
        // for an unstructured-goto target.  Its `tag_line(0)` fires any pending
        // `else if` brace, forcing `else { label: if ... }` (the `else if`
        // collapse is suppressed when the clause carries a goto label).  Routing
        // through `emit_any_label_statement` skips the label when it was hoisted up
        // to an enclosing loop head (`isLabelBumpUp`).
        self.emit_any_label_statement(fd, blk);
        if let Some(under) = fd.sblocks_ref().block(blk).get_copy() {
            // The copy's `copy` field is a *bblocks* BlockId.
            self.emit_basic_block_ops(fd, arch, under, true);
        }
    }

    /// The display name for a goto target / label line (C++ `PrintC::emitLabel`,
    /// printc.cc:3328): the **entry address** of the block's front-leaf basic
    /// block, rendered in kuna's angr style as `label_<addr>`
    /// ([`kuna_label_name`](crate::database::kuna_label_name)).  Falls back to the
    /// reverse-post `LAB_<index>` form only when the block has no resolvable entry
    /// address, keeping a `goto`/target pair always consistent.
    pub(crate) fn block_label_name(&self, fd: &Funcdata, bl: BlockId) -> String {
        let addr = fd.sblock_entry_addr(bl);
        if addr.is_invalid() {
            let idx = fd.sblocks_ref().block(bl).get_index();
            format!("LAB_{idx:08x}")
        } else if fd.get_arch().kuna_name_style() == crate::database::KunaNameStyle::Ghidra {
            // (kuna, Phase 3) ghidra-mode: the GUI label convention LAB_%08x.
            crate::database::ghidra_label_name(&addr)
        } else {
            crate::database::kuna_label_name(&addr)
        }
    }

    /// C++ `PrintC::emitLabelStatement` (printc.cc:3355), structured-print arm: a
    /// `LABEL:` line for a `t_copy` block that is the target of an unstructured
    /// goto.  The label name is the block's entry-address-based `label_<addr>`
    /// ([`block_label_name`]) so a `goto`/target pair render the same name.
    fn emit_label_statement(&mut self, fd: &Funcdata, bl: BlockId) {
        match self.lang().forms.label {
            crate::kuna_lang::LabelForm::CColon => self.emit_label_statement_c(fd, bl),
            crate::kuna_lang::LabelForm::CommentOnly => self.emit_label_statement_rust(fd, bl),
        }
    }

    fn emit_label_statement_c(&mut self, fd: &Funcdata, bl: BlockId) {
        use crate::block::BlockType;
        if self.context.is_set(modifiers::ONLY_BRANCH) {
            return;
        }
        // Structured: only print labels for unstructured-jump targets that are
        // t_copy leaves.
        if !fd.sblocks_ref().block(bl).is_unstructured_target() {
            return;
        }
        if fd.sblocks_ref().block(bl).get_type() != BlockType::Copy {
            return;
        }
        self.emit.tag_line_indent(0);
        self.emit.print(&self.block_label_name(fd, bl), SyntaxHighlight::NoColor);
        self.emit.print(self.lang().kw_colon, SyntaxHighlight::NoColor);
    }

    /// C++ `PrintC::emitAnyLabelStatement` (printc.cc:3354): find the entry basic
    /// block of `bl` and emit any required label statement for it — unless the
    /// label was hoisted up the hierarchy (`isLabelBumpUp`), in which case the
    /// enclosing loop emitter prints it above the loop head instead (so a
    /// loop-head label never lands inside the loop condition).  The block does not
    /// have to be a basic block; `get_front_leaf` finds the entry `t_copy` leaf.
    pub(crate) fn emit_any_label_statement(&mut self, fd: &Funcdata, bl: BlockId) {
        // Label printed by someone else.
        if fd.sblocks_ref().block(bl).is_label_bump_up() {
            return;
        }
        let Some(front) = fd.sblocks_ref().get_front_leaf(bl) else {
            return;
        };
        self.emit_label_statement(fd, front);
    }

    /// Seed [`commsorter`](PrintC::commsorter) with this function's comments (C++
    /// `CommentSorter::setupFunctionList`, printc.cc:2799).  The architecture's
    /// warning sink stores comments as flat `ArchWarning` records; rebuild a real
    /// `CommentDatabaseInternal` (which sorts/uniqs by `(fad, addr, uniq)`) from
    /// them so the sorter's block placement reads the same ordered set C++ does.
    fn setup_comments(&mut self, fd: &Funcdata, arch: &Architecture) {
        use crate::comment::{CommentDatabase, CommentDatabaseInternal};
        // head_comment_type | instr_comment_type (printlanguage.cc:586-589).
        let tp = self.context.header_comment() | self.context.instruction_comment();
        let mut db = CommentDatabaseInternal::new();
        for w in arch.commentdb.comments() {
            db.add_comment(w.tp, &w.func_addr, &w.addr, w.text.as_bytes());
        }
        // option_unplaced is off by default (C++ resetDefaultsPrintC).
        if let Err(_e) = self.commsorter.setup_function_list(tp, fd, &db, false) {
            // A dead op reaching the sorter is a C++ LowlevelError; degrade to
            // "no comments placed" rather than aborting the whole print.
            self.commsorter = crate::comment::CommentSorter::new();
        }
    }

    /// C++ `PrintC::emitCommentGroup` (printc.cc:3388): emit the comment lines the
    /// sorter has associated with the statement rooted at `inst` (or, for `None`,
    /// any remaining comments in the current block).  Only `instr_comment_type`
    /// comments are shown.
    fn emit_comment_group(&mut self, fd: &Funcdata, inst: Option<OpId>) {
        use crate::comment::comment_type as ct;
        let instr_comment_type = self.context.instruction_comment();
        let landmark = inst.and_then(|op| {
            let o = fd.obank().get(op)?;
            let parent = o.get_parent()?;
            Some(crate::comment::OpListLandmark {
                index: fd.bblocks_ref().block(parent).get_index(),
                order: o.get_seq_num().get_order(),
            })
        });
        self.commsorter.setup_op_list(landmark);
        while self.commsorter.has_next() {
            let (emitted, tp, text, addr) = {
                let comm = self.commsorter.get_next();
                (
                    comm.is_emitted(),
                    comm.get_type(),
                    comm.get_text().to_vec(),
                    comm.get_addr().clone(),
                )
            };
            if emitted {
                continue;
            }
            if (instr_comment_type & tp) == 0 {
                continue;
            }
            // (kuna warnstyle, DIV-39) Inline mode: a WARNING comment becomes a
            // terse `// slug` collected for the owning line's end; every other
            // comment type keeps the banner-line render.
            if self.inline_warning(tp, ct::WARNING) {
                if let (Some(space), text_str) =
                    (addr.get_space().map(std::rc::Rc::clone), String::from_utf8_lossy(&text))
                {
                    self.eol_warns.push((
                        warning_slug(&text_str),
                        space,
                        addr.get_offset(),
                    ));
                    self.commsorter.mark_last_emitted();
                    continue;
                }
            }
            self.emit_line_comment(-1, &text, &addr);
            // emitLineComment sets comm->setEmitted(true) (printlanguage.cc:655),
            // so a later walk over the same window skips it.
            self.commsorter.mark_last_emitted();
        }
    }

    /// Warning bits also participate in visibility masks: the console's
    /// `comment instruction` stores the entire selected mask, just as upstream
    /// does. A comment carrying a user/header category remains an ordinary
    /// comment even when that mask also includes warnings. Only warning-only
    /// comments use the inline warning style or permit brace elision.
    fn inline_warning(&self, category: uint4, warning_kind: uint4) -> bool {
        use crate::comment::comment_type as ct;
        self.options.warn_inline
            && category & warning_kind != 0
            && category & !(ct::WARNING | ct::WARNINGHEADER) == 0
    }

    /// (kuna warnstyle, DIV-39) Append the collected warning slugs to the
    /// current line as one `// slug, slug` comment token.  Call sites are the
    /// last token of the line the warnings describe: the statement semicolon,
    /// the `if (cond)` header (brace / goto / elided forms), the loop header
    /// brace, the ternary statement, and the function prototype.  No-op when
    /// nothing was collected.
    pub(crate) fn flush_eol_warnings(&mut self) {
        if self.eol_warns.is_empty() {
            return;
        }
        let warns = std::mem::take(&mut self.eol_warns);
        let (space, off) = (std::rc::Rc::clone(&warns[0].1), warns[0].2);
        let joined =
            warns.iter().map(|w| w.0.as_str()).collect::<Vec<_>>().join(", ");
        self.emit.spaces(1, 0);
        // `warnstyle inline` deliberately selects single-line warning slugs;
        // `commentstyle` controls ordinary comments and warning banners.
        self.emit_comment_text(crate::printlanguage::CommentStyle::CPlusPlus, &joined, &space, off);
    }

    /// C++ `PrintLanguage::emitLineComment` (printlanguage.cc:596): a fresh line
    /// (at the comment indent) carrying `/* <text> */`.  The default C delimiters
    /// are `/* ` / ` */`; a negative `indent` uses the configured comment indent.
    fn emit_line_comment(&mut self, indent: int4, text: &[u8], addr: &kuna_base::address::Address) {
        let indent = if indent < 0 { self.context.line_comment_indent() } else { indent };
        let (space, off) = match addr.get_space() {
            Some(s) => (std::rc::Rc::clone(s), addr.get_offset()),
            None => return,
        };
        self.emit.tag_line_indent(indent);
        let body = String::from_utf8_lossy(text);
        self.emit_comment_text(self.context.comment_style(), &body, &space, off);
    }

    /// Keep whitespace as Emit break opportunities and annotations as single
    /// tokens. Explicit and width-driven line breaks use the same comment fill.
    fn emit_comment_text(
        &mut self,
        style: crate::printlanguage::CommentStyle,
        body: &str,
        space: &std::rc::Rc<kuna_base::space::AddrSpace>,
        off: uintb,
    ) {
        use crate::printlanguage::CommentStyle;
        let (start, stop, fill) = style.delimiters();
        self.emit.set_comment_fill(fill);
        let id = self.emit.start_comment();
        self.emit.tag_comment(start, SyntaxHighlight::CommentColor, space, off);
        let mut escaped = std::borrow::Cow::Borrowed(body);
        if escaped.contains('\r') {
            escaped = std::borrow::Cow::Owned(escaped.replace('\r', ""));
        }
        if style == CommentStyle::C && escaped.contains("*/") {
            escaped = std::borrow::Cow::Owned(escaped.replace("*/", "* /"));
        }
        for (line_number, line) in escaped.split('\n').enumerate() {
            if line_number != 0 {
                self.emit.tag_line();
            }
            let mut pos = 0;
            while pos < line.len() {
                let bytes = line.as_bytes();
                let begin = pos;
                if matches!(bytes[pos], b' ' | b'\t') {
                    pos += 1;
                    while pos < bytes.len() && matches!(bytes[pos], b' ' | b'\t') {
                        pos += 1;
                    }
                    self.emit.spaces((pos - begin) as int4, 0);
                } else {
                    if line[pos..].starts_with("{@") {
                        pos = line[pos..].find('}').map_or(line.len(), |end| pos + end + 1);
                    } else {
                        pos += 1;
                        while pos < bytes.len() && !matches!(bytes[pos], b' ' | b'\t') {
                            pos += 1;
                        }
                    }
                    self.emit.tag_comment(&line[begin..pos], SyntaxHighlight::CommentColor, space, off);
                }
            }
            // A trailing backslash would splice the next source line into a
            // C++ comment, even on compilers that allow intervening whitespace.
            if style == CommentStyle::CPlusPlus && line.trim_end().ends_with('\\') {
                self.emit.tag_comment(" //", SyntaxHighlight::CommentColor, space, off);
            }
        }
        if !stop.is_empty() {
            self.emit.tag_comment(stop, SyntaxHighlight::CommentColor, space, off);
        }
        self.emit.stop_comment(id);
    }

    /// C++ `PrintC::emitCommentBlockTree` (printc.cc:3404): emit any comments
    /// attached to basic blocks under the structured subtree rooted at the sblocks
    /// node `bl`.  Used where statements from several basic blocks land on one
    /// line (the `if (cond)` header) and a normal in-line comment would otherwise
    /// print mid-line — here it forces the pending `else if` brace.
    pub(crate) fn emit_comment_block_tree(&mut self, fd: &Funcdata, bl: BlockId) {
        use crate::block::BlockType;
        match fd.sblocks_ref().block(bl).get_type() {
            // BlockCopy: descend to the underlying bblocks BlockBasic.
            BlockType::Copy => {
                if let Some(under) = fd.sblocks_ref().block(bl).get_copy() {
                    // The copy's `copy` is a *bblocks* id (a BlockBasic).
                    self.commsorter.setup_block_list(fd.bblocks_ref().block(under).get_index());
                    self.emit_comment_group(fd, None);
                }
            }
            BlockType::Plain => {}
            // A bare sblocks BlockBasic (rare): its own index.
            BlockType::Basic => {
                self.commsorter.setup_block_list(fd.sblocks_ref().block(bl).get_index());
                self.emit_comment_group(fd, None);
            }
            // BlockGraph subtype: recurse into every component.
            _ => {
                let n = fd.sblocks_ref().block(bl).get_size();
                for i in 0..n {
                    let child = fd.sblocks_ref().block(bl).get_block(i);
                    self.emit_comment_block_tree(fd, child);
                }
            }
        }
    }

    /// C++ `PrintC::emitBlockBasic` for an sblocks Basic node (rare in the
    /// structured tree, but handled for completeness): the node *is* a basic
    /// block in the sblocks arena.
    fn emit_block_basic(&mut self, fd: &Funcdata, arch: &Architecture, blk: BlockId) {
        self.emit_basic_block_ops(fd, arch, blk, false);
    }

    /// C++ `PrintC::emitBlockLs` (printc.cc:2930): emit a list of blocks in
    /// sequence.  The first block keeps its branch suppressed (`no_branch`); the
    /// last block keeps the caller's branch state.  The per-edge `nextInFlow`
    /// goto-insertion (the `nofallthru` arm) is the goto-labeling layer; the
    /// structured list emitted here flows in declaration order.
    fn emit_block_ls(&mut self, fd: &Funcdata, arch: &Architecture, blk: BlockId) {
        let list: Vec<BlockId> = fd.sblocks_ref().block(blk).get_list().to_vec();
        if self.context.is_set(modifiers::ONLY_BRANCH) {
            if let Some(&last) = list.last() {
                self.emit_block(fd, arch, last);
            }
            return;
        }
        if list.is_empty() {
            return;
        }
        let n = list.len();
        let id1 = self.emit.begin_block(0);
        // C++ `PrintC::emitBlockLs` (printc.cc:2929-2933): a single-element list
        // emits its one block **once**, in the caller's branch state (before the
        // `no_branch` push), and returns.  Without this early-return the block is
        // emitted a second time below as the "Final block" (`list[0] == list[n-1]`),
        // duplicating it — e.g. the single-block `abort(); return;` tail that
        // `taildup`/`gotoreduce` wrap in a 1-element `BlockList`, which otherwise
        // renders `abort(); abort();`.  The datatest corpus never produces a
        // size-1 `Ls`, so this only surfaced under the kuna structuring passes.
        if n == 1 {
            self.emit_block(fd, arch, list[0]);
            self.emit.end_block(id1);
            return;
        }
        // First block: no_branch (unless flat).
        self.context.push_mod();
        if !self.is_flat() {
            self.context.set_mod(modifiers::NO_BRANCH);
        }
        self.emit_block(fd, arch, list[0]);
        self.emit.end_block(id1);
        // Middle blocks: no_branch.
        for &subbl in list.iter().take(n.saturating_sub(1)).skip(1) {
            let id2 = self.emit.begin_block(0);
            self.emit_block(fd, arch, subbl);
            self.emit.end_block(id2);
        }
        self.context.pop_mod();
        // Final block: caller's branch state.
        let id3 = self.emit.begin_block(0);
        self.emit_block(fd, arch, list[n - 1]);
        self.emit.end_block(id3);
    }

    /// C++ `PrintC::emitBlockIf` (printc.cc:3027): the `if (cond) { ... }` form
    /// (with optional `else`).  Block 0 is the condition, block 1 the true body,
    /// block 2 (optional) the else body.
    fn emit_block_if(&mut self, fd: &Funcdata, arch: &Architecture, blk: BlockId) {
        use crate::prettyprint::Emit;
        // (kuna) iteregion: a two-arm assignment diamond the S8 `iteregion` pass
        // marked (its condition `CBRANCH` carries the `kuna_iteregion` addl-flag)
        // renders as a single `dest = ( cond ) ? A : B;` ternary instead of the
        // if/else.  The mark is set only with `option iteregion on`, so when off
        // this is never taken and the if/else render is byte-identical.
        // (kuna) iteboolean: a `0`/`1` select diamond whose condition is a folded
        // short-circuit chain renders as the single boolean assignment
        // `dest = ( cond );`.  Checked BEFORE the ternary so the more specific
        // form wins when both match; the mark is set only with
        // `option iteboolean on`.
        if let Some(m) = self.ite_boolean_match(fd, blk) {
            self.emit_block_if_bool(fd, arch, m);
            return;
        }
        if let Some(m) = self.ite_ternary_match(fd, blk) {
            self.emit_block_if_ite(fd, arch, m);
            return;
        }
        let size = fd.sblocks_ref().block(blk).get_size();
        let cond_block = fd.sblocks_ref().block(blk).get_block(0);

        // When *this* BlockIf is the else-clause of a parent if, the parent set
        // the pending_brace mod; register a brace that opens lazily so a real
        // `else if` collapses.
        let mut registered_pending = false;
        let mut my_pending_gen = 0u64;
        if self.context.is_set(modifiers::PENDING_BRACE) {
            self.emit.set_pending_brace(to_emit_brace(self.options.brace_ifelse));
            // Remember *our* registration's generation so the close decision below
            // asks whether OUR brace fired, not whether the shared slot holds any
            // fired id (which could be a nested/sibling BlockIf's brace).
            my_pending_gen = self.emit.pending_reg_gen();
            registered_pending = true;
        }

        // if-block never prints final branch: clear no_branch/only_branch/pending_brace.
        self.context.push_mod();
        self.context.unset_mod(
            modifiers::NO_BRANCH | modifiers::ONLY_BRANCH | modifiers::PENDING_BRACE,
        );

        // Emit the condition block's statements (no_branch) ...
        self.context.push_mod();
        self.context.set_mod(modifiers::NO_BRANCH);
        self.emit_block(fd, arch, cond_block);
        self.context.pop_mod();
        // emitCommentBlockTree(condBlock): emit any comments under the condition
        // subtree before deciding `else if` vs `else {` — a comment forces the
        // pending brace to fire (suppressing the `else if` collapse).
        self.emit_comment_block_tree(fd, cond_block);

        // If a pending brace was issued but did not emit (no statements forced a
        // tag_line), cancel it to get `else if`; otherwise start `if` on a new
        // line.  When it *did* fire, snapshot the indent
        // id it opened into a local — the shared emitter slot can be overwritten
        // by a deeper BlockIf's own pending brace before we read it back.
        //
        // C++ asks `emit->hasPendingPrint(&pendingBrace)` — a *pointer-identity*
        // test against this frame's own `PendingBrace`, not "is any brace
        // pending".  Only the frame that registered the brace may collapse it into
        // `else if`; a nested `BlockIf` reached while emitting this if's condition
        // block (a condition list can lead with a whole `if` statement) must let
        // the ancestor's brace fire instead, or the ancestor's own `if` header
        // lands outside the `else` and its body escapes the arm.
        let mut my_pending_indent = -1;
        let my_brace_pending =
            registered_pending && self.emit.has_pending_brace() && self.emit.pending_reg_gen() == my_pending_gen;
        let mut my_brace_canceled = false;
        if my_brace_pending {
            self.emit.cancel_pending_brace();
            self.emit.spaces(1, 0);
            my_brace_canceled = true;
        } else {
            if registered_pending {
                // C++ `pendingBrace.getIndentId()`: close a lazy `else { … }`
                // brace only if OUR OWN registration fired.  Reading the shared
                // `pending_brace_indent_id()` here would pick up a stale id left by
                // a nested BlockIf's fire and emit an unmatched `}` (dumping code to
                // file scope) whenever our brace was shadowed but never opened.
                my_pending_indent = self.emit.pending_fired_indent(my_pending_gen);
            }
            self.emit.tag_line();
        }
        // Guard rail for the whole pending-brace family (debug builds only): a
        // frame that registers a lazy `else` brace must resolve its OWN
        // registration — either it fired (a real `else { … }`) or the frame
        // canceled it (the `else if` collapse).  Neither holding means some other
        // frame consumed the brace and this if's header is about to print outside
        // the `else` it belongs to.
        debug_assert!(
            !registered_pending || my_brace_canceled || my_pending_indent >= 0,
            "emit_block_if: pending else-brace consumed by another frame"
        );

        // ... then `if ` + the branch condition (only_branch).
        self.emit.tag_op(self.lang().kw_if, SyntaxHighlight::KeywordColor, &MarkupRef::none());
        self.emit.spaces(1, 0);
        self.context.push_mod();
        self.context.set_mod(modifiers::ONLY_BRANCH);
        self.emit_block(fd, arch, cond_block);
        self.context.pop_mod();

        // If the if has an unstructured-branch target, emit a goto/break/continue
        // instead of a braced body.
        let goto_target = fd.sblocks_ref().block(blk).get_if_goto_target();
        if let Some(target) = goto_target {
            let gototype = fd.sblocks_ref().block(blk).get_if_goto_type();
            // (kuna outlang) C's one-line `if (cond) goto L;` needs no braces; a
            // language that requires block braces gets `if cond { goto-form }`.
            if self.lang().caps.brace_elision {
                self.emit.spaces(1, 0);
                self.emit_goto_statement(fd, cond_block, target, gototype);
                // (kuna warnstyle, DIV-39) condition-attached warnings land at the
                // end of the one-line `if (cond) goto L;` form.
                self.flush_eol_warnings();
            } else {
                let id = self
                    .emit
                    .open_brace_indent(self.lang().kw_open_curly, to_emit_brace(self.options.brace_ifelse));
                self.flush_eol_warnings();
                self.emit.tag_line();
                self.emit_goto_statement(fd, cond_block, target, gototype);
                self.emit.close_brace_indent(self.lang().kw_close_curly, id);
            }
        } else if self.if_body_elides(fd, fd.sblocks_ref().block(blk).get_block(1)) {
            // (kuna braceelide, DIV-38) A single-statement then-body drops its
            // braces: the statement prints on the next line at one extra indent
            // (its own tag_line in emit_basic_block_ops breaks the line).  The
            // predicate is Copy-leaf-only, so the body can never itself be an
            // `if` and the dangling-else hazard cannot arise; the else arm (if
            // any) opens with its own tag_line below, unchanged.
            self.context.set_mod(modifiers::NO_BRANCH);
            // (kuna warnstyle, DIV-39) condition-attached warnings land at the
            // end of the braceless `if (cond)` header line.
            self.flush_eol_warnings();
            let body = fd.sblocks_ref().block(blk).get_block(1);
            let id = self.emit.start_indent();
            let id1 = self.emit.begin_block(0);
            self.emit_block(fd, arch, body);
            self.emit.end_block(id1);
            self.emit.stop_indent(id);
            if size == 3 {
                self.emit.tag_line();
                self.emit.print(self.lang().kw_else, SyntaxHighlight::KeywordColor);
                let else_block = fd.sblocks_ref().block(blk).get_block(2);
                let else_is_if = fd.sblocks_ref().block(else_block).get_type()
                    == crate::block::BlockType::If;
                if else_is_if {
                    self.context.set_mod(modifiers::PENDING_BRACE);
                    let id2 = self.emit.begin_block(0);
                    self.emit_block(fd, arch, else_block);
                    self.emit.end_block(id2);
                } else {
                    let id2 = self
                        .emit
                        .open_brace_indent(self.lang().kw_open_curly, to_emit_brace(self.options.brace_ifelse));
                    let id3 = self.emit.begin_block(0);
                    self.emit_block(fd, arch, else_block);
                    self.emit.end_block(id3);
                    self.emit.close_brace_indent(self.lang().kw_close_curly, id2);
                }
            }
        } else {
            // The true body in braces.
            self.context.set_mod(modifiers::NO_BRANCH);
            let id = self
                .emit
                .open_brace_indent(self.lang().kw_open_curly, to_emit_brace(self.options.brace_ifelse));
            // (kuna warnstyle, DIV-39) condition-attached warnings land after
            // the `if (cond) {` header brace.
            self.flush_eol_warnings();
            let id1 = self.emit.begin_block(0);
            self.emit_block(fd, arch, fd.sblocks_ref().block(blk).get_block(1));
            self.emit.end_block(id1);
            self.emit.close_brace_indent(self.lang().kw_close_curly, id);

            // Optional else.
            if size == 3 {
                self.emit.tag_line();
                self.emit.print(self.lang().kw_else, SyntaxHighlight::KeywordColor);
                let else_block = fd.sblocks_ref().block(blk).get_block(2);
                let else_is_if = fd.sblocks_ref().block(else_block).get_type()
                    == crate::block::BlockType::If;
                if else_is_if {
                    // Attempt to merge the "else" and "if" syntax: set pending_brace
                    // so the child BlockIf registers a lazy brace.
                    self.context.set_mod(modifiers::PENDING_BRACE);
                    let id2 = self.emit.begin_block(0);
                    self.emit_block(fd, arch, else_block);
                    self.emit.end_block(id2);
                } else {
                    let id2 = self
                        .emit
                        .open_brace_indent(self.lang().kw_open_curly, to_emit_brace(self.options.brace_ifelse));
                    let id3 = self.emit.begin_block(0);
                    self.emit_block(fd, arch, else_block);
                    self.emit.end_block(id3);
                    self.emit.close_brace_indent(self.lang().kw_close_curly, id2);
                }
            }
        }
        self.context.pop_mod();

        // When our own pending brace actually fired (the else-clause had
        // statements before its `if`, so it rendered `else { ... if`), close
        // that brace.
        if my_pending_indent >= 0 {
            self.emit.close_brace_indent(self.lang().kw_close_curly, my_pending_indent);
        }
    }

    /// (kuna braceelide, DIV-38) Does this if-body render braceless?  True when
    /// `option braceelide` is on and the body is a plain single-statement
    /// `BlockCopy` leaf: no label line (an unstructured-goto target keeps its
    /// braces), exactly ONE op that `emit_basic_block_ops` would print under
    /// NO_BRANCH (not-printed ops, branches, and implied-output ops are
    /// skipped, exactly mirroring its filter), and no comment positioned in the
    /// block (a comment renders as its own line).  Copy-leaf-only also rules
    /// out a nested `if` body, so eliding can never capture a dangling else.
    pub(crate) fn if_body_elides(&mut self, fd: &Funcdata, body: BlockId) -> bool {
        use crate::block::BlockType;
        // (kuna outlang) braceelide (DIV-38) drops the braces from a
        // single-statement body; a language that requires block braces must
        // never take that path, whatever the option says.
        if !self.options.brace_elide || !self.lang().caps.brace_elision {
            return false;
        }
        if fd.sblocks_ref().block(body).get_type() != BlockType::Copy {
            return false;
        }
        // Would emit_any_label_statement print a `label_xxx:` line?
        if !fd.sblocks_ref().block(body).is_label_bump_up() {
            if let Some(front) = fd.sblocks_ref().get_front_leaf(body) {
                if fd.sblocks_ref().block(front).is_unstructured_target() {
                    return false;
                }
            }
        }
        let Some(under) = fd.sblocks_ref().block(body).get_copy() else {
            return false;
        };
        let mut printed = 0;
        let mut cur = fd.bb_op_head(under);
        while let Some(inst) = cur {
            cur = fd.bb_op_next(inst);
            let o = match fd.obank().get(inst) {
                Some(o) => o,
                None => continue,
            };
            if o.not_printed() {
                continue;
            }
            // The body always prints under NO_BRANCH: every branch op is skipped.
            if o.is_branch() {
                continue;
            }
            if let Some(out) = o.get_out() {
                if fd.vbank().get(out).map(|v| v.is_implied()).unwrap_or(false) {
                    continue;
                }
            }
            printed += 1;
            if printed > 1 {
                return false;
            }
        }
        if printed != 1 {
            return false;
        }
        // A comment positioned in this block forces its own line; keep braces.
        // (kuna warnstyle, DIV-39: a WARNING comment under `warn_inline`
        // renders at end-of-line instead, so it does NOT force braces.)
        // The probe re-positions the sorter window without marking anything
        // emitted; emit_basic_block_ops sets the window again for the real walk.
        let bb_index = fd.bblocks_ref().block(under).get_index();
        self.commsorter.setup_block_list(bb_index);
        // setup_block_list sets start/stop but NOT the has_next() bound
        // (opstop); setup_op_list(None) widens it to the whole block window,
        // exactly as the real statement walk does before its has_next loop.
        self.commsorter.setup_op_list(None);
        while self.commsorter.has_next() {
            let (emitted, tp) = {
                let c = self.commsorter.get_next();
                (c.is_emitted(), c.get_type())
            };
            if emitted || self.context.instruction_comment() & tp == 0 {
                continue;
            }
            let inline_ok = self.inline_warning(tp, crate::comment::comment_type::WARNING);
            if !inline_ok {
                return false;
            }
        }
        true
    }

    /// (kuna) Is `blk` a two-arm assignment diamond that the S8 `iteregion` pass
    /// selected for `?:` rendering?  Returns the [`IteAssignMatch`] iff both (a) the
    /// structure still matches the narrow diamond schema and (b) its condition
    /// `CBRANCH` carries the [`kuna_iteregion`](crate::op::pcodeop_addlflags::kuna_iteregion)
    /// mark (set only under `option iteregion on`).  The flag is the gate, so with
    /// the option off this is always `None` and the if/else render is byte-identical.
    fn ite_ternary_match(
        &self,
        fd: &Funcdata,
        blk: BlockId,
    ) -> Option<crate::p8_structure::kuna_iteregion::IteAssignMatch> {
        let m = crate::p8_structure::kuna_iteregion::match_ite_assignment(fd, blk)?;
        let marked = fd
            .obank()
            .get(m.cbranch)
            .map(|o| (o.get_addlflags() & crate::op::pcodeop_addlflags::kuna_iteregion) != 0)
            .unwrap_or(false);
        if marked {
            Some(m)
        } else {
            None
        }
    }

    /// (kuna) Is `blk` a `0`/`1` select diamond that the S8 `iteboolean` pass
    /// selected for boolean-assignment rendering?  Returns the [`IteBoolMatch`] iff
    /// both (a) the structure still matches the schema and (b) the condition's
    /// terminal `CBRANCH` carries the
    /// [`kuna_iteboolean`](crate::op::pcodeop_addlflags::kuna_iteboolean) mark (set
    /// only under `option iteboolean on`).  The flag is the gate, so with the option
    /// off this is always `None` and the if/else render is byte-identical.
    fn ite_boolean_match(
        &self,
        fd: &Funcdata,
        blk: BlockId,
    ) -> Option<crate::p8_structure::kuna_iteboolean::IteBoolMatch> {
        let m = crate::p8_structure::kuna_iteboolean::match_ite_boolean(fd, blk)?;
        let marked = fd
            .obank()
            .get(m.cbranch)
            .map(|o| (o.get_addlflags() & crate::op::pcodeop_addlflags::kuna_iteboolean) != 0)
            .unwrap_or(false);
        if marked {
            Some(m)
        } else {
            None
        }
    }

    /// (kuna) Emit an `iteboolean`-selected `0`/`1` select diamond as the single
    /// statement `dest = ( cond );` — or `dest = !( cond );` when the true arm is the
    /// `0` one.  The condition goes through the *same* `ONLY_BRANCH` renderer that
    /// produced the `if (...)` header (a `CBRANCH` leaf via `op_cbranch`, a folded
    /// `&&`/`||` chain via `emit_block_condition`), so it is always parenthesized and
    /// its evaluation order, short-circuiting and comma-expression side effects are
    /// preserved verbatim.  Mirrors [`emit_block_if_ite`]'s pending-brace handling so
    /// a diamond that is itself an `else` clause renders `else { dest = ...; }`.
    fn emit_block_if_bool(
        &mut self,
        fd: &Funcdata,
        arch: &Architecture,
        m: crate::p8_structure::kuna_iteboolean::IteBoolMatch,
    ) {
        use crate::prettyprint::Emit;

        let mut registered_pending = false;
        let mut my_pending_gen = 0u64;
        if self.context.is_set(modifiers::PENDING_BRACE) {
            self.emit.set_pending_brace(to_emit_brace(self.options.brace_ifelse));
            my_pending_gen = self.emit.pending_reg_gen();
            registered_pending = true;
        }
        self.context.push_mod();
        self.context.unset_mod(
            modifiers::NO_BRANCH | modifiers::ONLY_BRANCH | modifiers::PENDING_BRACE,
        );

        // The condition block's leading statements, exactly as emit_block_if does.
        self.context.push_mod();
        self.context.set_mod(modifiers::NO_BRANCH);
        self.emit_block(fd, arch, m.cond_block);
        self.context.pop_mod();
        self.emit_comment_block_tree(fd, m.cond_block);

        self.emit.tag_line();
        let mut my_pending_indent = -1;
        if registered_pending {
            my_pending_indent = self.emit.pending_fired_indent(my_pending_gen);
        }

        // dest = ( cond ) ;   /   dest = !( cond ) ;
        let stmt_markup = self.op_markup(fd, m.assign_op);
        let sid = self.emit.begin_statement(&stmt_markup);
        self.push_vn_explicit_ir(fd, arch, m.dest, m.assign_op);
        self.emit.spaces(1, 0);
        self.emit.tag_op(tokens::ASSIGNMENT.print1, SyntaxHighlight::NoColor, &MarkupRef::none());
        self.emit.spaces(1, 0);
        if m.negate {
            self.emit.tag_op(
                tokens::BOOLEAN_NOT.print1,
                SyntaxHighlight::NoColor,
                &MarkupRef::none(),
            );
        }
        self.context.push_mod();
        self.context.set_mod(modifiers::ONLY_BRANCH);
        self.emit_block(fd, arch, m.cond_block);
        self.context.pop_mod();
        self.emit.end_statement(sid);
        self.emit.print(self.lang().kw_semicolon, SyntaxHighlight::NoColor);
        // (kuna warnstyle, DIV-39) condition-attached warnings land at the end of
        // the assignment line.
        self.flush_eol_warnings();

        if my_pending_indent >= 0 {
            self.emit.close_brace_indent(self.lang().kw_close_curly, my_pending_indent);
        }
        self.context.pop_mod();
    }

    /// (kuna) Emit an `iteregion`-selected assignment diamond as a single ternary
    /// statement `dest = ( cond ) ? A : B;` (angr `ITERegionConverter`).  Reuses the
    /// existing renderers: the LHS via `push_vn_explicit_ir`, the condition via the
    /// normal `ONLY_BRANCH` `CBRANCH` render (`( cond )`, honouring boolean-flip),
    /// and each arm's RHS via `op_push_ir` on the arm's `COPY` — every sub-expression
    /// drains on an empty RPN stack (the direct-resolution engine, as in
    /// `opCbranch`), interleaved with the raw `=`/`?`/`:` tokens (the same
    /// block-then-token pattern as `emit_block_condition`).  Honours the parent's
    /// pending brace so a diamond that is itself an `else` clause renders
    /// `else { dest = ...; }`.
    fn emit_block_if_ite(
        &mut self,
        fd: &Funcdata,
        arch: &Architecture,
        m: crate::p8_structure::kuna_iteregion::IteAssignMatch,
    ) {
        use crate::prettyprint::Emit;

        // Mirror emit_block_if's pending-brace handling: if this diamond is a
        // parent if's else-clause, register the lazy brace so the ternary statement
        // renders `else { ... }` (a statement can never be `else if`).
        let mut registered_pending = false;
        let mut my_pending_gen = 0u64;
        if self.context.is_set(modifiers::PENDING_BRACE) {
            self.emit.set_pending_brace(to_emit_brace(self.options.brace_ifelse));
            my_pending_gen = self.emit.pending_reg_gen();
            registered_pending = true;
        }
        self.context.push_mod();
        self.context.unset_mod(
            modifiers::NO_BRANCH | modifiers::ONLY_BRANCH | modifiers::PENDING_BRACE,
        );

        // Emit the condition block's leading statements (everything before the
        // CBRANCH — e.g. the `flags &= ~IFF_x` in front of each `_PF` diamond)
        // exactly as emit_block_if does (NO_BRANCH), so nothing is lost.  For a
        // clean condition (only the CBRANCH) this emits nothing.
        self.context.push_mod();
        self.context.set_mod(modifiers::NO_BRANCH);
        self.emit_block(fd, arch, m.cond_block);
        self.context.pop_mod();
        self.emit_comment_block_tree(fd, m.cond_block);

        // Start the ternary statement on a fresh line; the tag_line fires any
        // pending brace (so an else-clause diamond renders `else { v = ...; }`).
        // Read whether OUR registration fired only *after* the tag_line that fires
        // it, and key it to our own generation (per-frame, like emit_block_if) so a
        // nested/sibling fire can never leave us closing a brace we never opened.
        self.emit.tag_line();
        let mut my_pending_indent = -1;
        if registered_pending {
            my_pending_indent = self.emit.pending_fired_indent(my_pending_gen);
        }

        // dest = ( cond ) ? A : B ;  (opref = the ternary's true-branch assign op)
        let stmt_markup = self.op_markup(fd, m.true_op);
        let sid = self.emit.begin_statement(&stmt_markup);
        // LHS assignment target (drains as a leaf on the empty stack).
        self.push_vn_explicit_ir(fd, arch, m.dest, m.true_op);
        // ` = `
        self.emit.spaces(1, 0);
        self.emit.tag_op(tokens::ASSIGNMENT.print1, SyntaxHighlight::NoColor, &MarkupRef::none());
        self.emit.spaces(1, 0);
        // (kuna outlang) C spells the选 selection `cond ? A : B`; a language
        // without a ternary spells it `if cond { A } else { B }` -- which in Rust
        // is an EXPRESSION, so the `iteregion` recovery is not lost here, it is
        // rendered in the more natural form. Only the punctuation differs: the
        // condition and both arms are the same three emissions either way.
        let ternary = self.lang().caps.ternary;
        if !ternary {
            self.emit.tag_op(self.lang().kw_if, SyntaxHighlight::KeywordColor, &MarkupRef::none());
            self.emit.spaces(1, 0);
        }
        // ` ( cond ) ` — the normal ONLY_BRANCH CBRANCH render (boolean-flip aware).
        self.context.push_mod();
        self.context.set_mod(modifiers::ONLY_BRANCH);
        self.emit_block(fd, arch, m.cond_block);
        self.context.pop_mod();
        // ` ? A ` / ` { A }`
        self.emit.spaces(1, 0);
        self.emit.tag_op(if ternary { "?" } else { "{" }, SyntaxHighlight::NoColor, &MarkupRef::none());
        self.emit.spaces(1, 0);
        let arm_drops = self.conditional_arm_drops(fd, arch, &m);
        self.cast_implied.set_arm_drops(arm_drops);
        self.op_push_ir(fd, arch, m.true_op, None);
        if !ternary {
            // The arm has to be fully drained before the `}` token, which is
            // emitted directly rather than through the RPN stack.
            self.recurse();
        }
        // ` : B ` / ` } else { B }`
        self.emit.spaces(1, 0);
        self.emit.tag_op(
            if ternary { ":" } else { "} else {" },
            SyntaxHighlight::NoColor,
            &MarkupRef::none(),
        );
        self.emit.spaces(1, 0);
        self.op_push_ir(fd, arch, m.else_op, None);
        self.cast_implied.set_arm_drops(Vec::new());
        if !ternary {
            self.recurse();
            self.emit.spaces(1, 0);
            self.emit.print("}", SyntaxHighlight::NoColor);
        }
        self.emit.end_statement(sid);
        self.emit.print(self.lang().kw_semicolon, SyntaxHighlight::NoColor);
        // (kuna warnstyle, DIV-39) condition-attached warnings land at the end
        // of the ternary statement line.
        self.flush_eol_warnings();

        // Close the pending brace if it fired (the else-clause `{ ... }`).
        if my_pending_indent >= 0 {
            self.emit.close_brace_indent(self.lang().kw_close_curly, my_pending_indent);
        }
        self.context.pop_mod();
    }

    /// C++ `PrintC::emitBlockSwitch` (printc.cc:3470): emit a `BlockSwitch` — the
    /// statements before the switch, the `switch(v)` header, then the braced body
    /// of `case N:` / `default:` arms.
    fn emit_block_switch(&mut self, fd: &Funcdata, arch: &Architecture, blk: BlockId) {
        match self.lang().forms.switch {
            crate::kuna_lang::SwitchForm::CSwitch => self.emit_block_switch_c(fd, arch, blk),
            crate::kuna_lang::SwitchForm::RustMatch => self.emit_block_match_rust(fd, arch, blk),
        }
    }

    fn emit_block_switch_c(&mut self, fd: &Funcdata, arch: &Architecture, blk: BlockId) {
        // getSwitchBlock() == getBlock(0) (the switch component).
        let switch_block = fd.sblocks_ref().block(blk).get_block(0);

        self.context.push_mod();
        self.context.unset_mod(modifiers::NO_BRANCH | modifiers::ONLY_BRANCH);
        // Statements before the branch (no_branch).
        self.context.push_mod();
        self.context.set_mod(modifiers::NO_BRANCH);
        self.emit_block(fd, arch, switch_block);
        self.context.pop_mod();
        self.emit.tag_line();
        // The `switch(v)` header (only_branch|comma_separate).
        self.context.push_mod();
        self.context.set_mod(modifiers::ONLY_BRANCH | modifiers::COMMA_SEPARATE);
        self.emit_block(fd, arch, switch_block);
        self.context.pop_mod();
        let brace_id =
            self.emit.open_brace_indent(self.lang().kw_open_curly, to_emit_brace(self.options.brace_switch));
        // (kuna warnstyle, DIV-39) warnings pending from the switch block land
        // after the `switch (v) {` header brace.
        self.flush_eol_warnings();

        let ncase = fd.sblocks_ref().block(blk).switch_caseblocks().len();
        for i in 0..ncase {
            self.emit_switch_case(fd, arch, blk, i);
            let id = self.emit.start_indent();
            let gototype = fd.sblocks_ref().block(blk).switch_caseblocks()[i].gototype;
            if gototype != 0 {
                self.emit.tag_line();
                let caseblk = fd.sblocks_ref().block(blk).switch_caseblocks()[i].block;
                self.emit_goto_statement(fd, switch_block, caseblk, gototype);
            } else {
                let caseblk = fd.sblocks_ref().block(blk).switch_caseblocks()[i].block;
                let id2 = self.emit.begin_block(0);
                self.emit_block(fd, arch, caseblk);
                // Blocks that formally exit the switch need an explicit `break;`
                // (unless it is the last case, whose fall-through is the close).
                let isexit = fd.sblocks_ref().block(blk).switch_caseblocks()[i].isexit;
                if isexit && i != ncase - 1 {
                    self.emit.tag_line();
                    self.emit_goto_statement(fd, caseblk, caseblk, crate::block::block_flags::f_break_goto);
                }
                self.emit.end_block(id2);
            }
            self.emit.stop_indent(id);
        }
        self.emit.tag_line();
        self.emit.close_brace_indent(self.lang().kw_close_curly, brace_id);
        self.context.pop_mod();
    }

    /// C++ `PrintC::emitSwitchCase` (printc.cc:3278): emit the `case N:` /
    /// `default:` label(s) for one case arm.
    pub(crate) fn emit_switch_case(&mut self, fd: &Funcdata, arch: &Architecture, blk: BlockId, casenum: usize) {
        let case = fd.sblocks_ref().block(blk).switch_caseblocks()[casenum].clone();
        // The case block's first op — used only for markup tagging.
        let firstop = self.case_first_op(fd, case.block);

        if case.isdefault {
            // default: (the label value is informational; default emits no value).
            // C++ `emit->tagCaseLabel(..., op, ...)` with op = the case's first op —
            // `opref = firstop->getTime()`, the `<ast>` `<seqnum uniq>`.
            let case_markup = match firstop {
                Some(o) => self.op_markup(fd, o),
                None => MarkupRef::none(),
            };
            self.emit_default_case_label(case.label, &case_markup);
        } else {
            // case <label>: — one line per index targeting this case.
            let jt_index = fd.sblocks_ref().block(blk).switch_jt_index();
            let nlabels = match (jt_index, case.basicblock) {
                (Some(j), Some(bb)) => {
                    fd.get_jump_table(j as int4).num_indices_by_block(fd, bb).unwrap_or(1).max(1)
                }
                _ => 1,
            };
            for i in 0..nlabels {
                let val = match (jt_index, case.basicblock) {
                    (Some(j), Some(bb)) => {
                        let ind = fd
                            .get_jump_table(j as int4)
                            .get_index_by_block(fd, bb, i)
                            .unwrap_or(0);
                        fd.get_jump_table(j as int4).get_label_by_index(ind)
                    }
                    _ => case.label,
                };
                let sz = self.switch_var_size(fd, blk);
                // (kuna) Render the label signed when the recovered switch variable
                // is signed (the lowered-switch install records this on the table;
                // the C++ derives it from `getSwitchType()`'s signedness).
                let signed = jt_index
                    .map(|j| {
                        let jt = fd.get_jump_table(j as int4);
                        match jt.get_indirect_op().and_then(|op| lowered_switch_label_form(fd, arch, op)) {
                            Some((signed, _)) => signed,
                            None => jt.kuna_has_signed_labels(),
                        }
                    })
                    .unwrap_or(false);
                self.emit_numeric_case_label(
                    val,
                    sz,
                    signed,
                    firstop.or_else(|| self.any_op(fd, case.block)),
                );
            }
        }
        let _ = arch;
    }

    fn emit_default_case_label(&mut self, value: uintb, markup: &MarkupRef) {
        self.emit.tag_line();
        self.emit.tag_case_label(
            self.lang().kw_default,
            SyntaxHighlight::KeywordColor,
            markup,
            value,
        );
        self.emit.print(self.lang().kw_colon, SyntaxHighlight::NoColor);
    }

    fn emit_numeric_case_label(&mut self, value: uintb, size: int4, signed: bool, op: Option<OpId>) {
        self.emit.tag_line();
        self.emit.print(self.lang().kw_case, SyntaxHighlight::KeywordColor);
        self.emit.spaces(1, 0);
        match op {
            Some(op) => {
                if signed {
                    self.push_constant_ir_fmt_sign(value, size, op, display_format::NONE, true);
                } else {
                    self.push_constant_ir(value, size, op);
                }
                self.recurse();
            }
            None => {
                let force_dec = self.context.is_set(modifiers::FORCE_DEC);
                let force_hex = self.context.is_set(modifiers::FORCE_HEX);
                let (print_negsign, value, display_fmt) = resolve_integer_format(
                    value,
                    size,
                    signed,
                    display_format::NONE,
                    force_hex,
                    force_dec,
                );
                let token = format_integer_token(
                    print_negsign,
                    value,
                    display_fmt,
                    size,
                    false,
                    false,
                    true,
                    "",
                );
                self.emit.print(&token, SyntaxHighlight::ConstColor);
            }
        }
        self.emit.print(self.lang().kw_colon, SyntaxHighlight::NoColor);
    }

    /// First op of a case block (C++ `FlowBlock::firstOp` → front-leaf basic
    /// block's first op), used only for case-label markup tagging.
    pub(crate) fn case_first_op(&self, fd: &Funcdata, caseblk: BlockId) -> Option<OpId> {
        let front = fd.sblocks_ref().get_front_leaf(caseblk)?;
        let bb = fd.sblocks_ref().sub_block(front, 0)?;
        fd.bb_op_head(bb)
    }

    /// Any op tag in a case block (fallback for markup when the block is empty).
    pub(crate) fn any_op(&self, fd: &Funcdata, caseblk: BlockId) -> Option<OpId> {
        self.case_first_op(fd, caseblk)
    }

    /// The byte-size of the switch variable (C++ `getSwitchType()` size), used to
    /// format the case-label constant.  Resolved from the BRANCHIND's `in0`.
    pub(crate) fn switch_var_size(&self, fd: &Funcdata, blk: BlockId) -> int4 {
        let jt_index = match fd.sblocks_ref().block(blk).switch_jt_index() {
            Some(j) => j,
            None => return 4,
        };
        let indop = match fd.get_jump_table(jt_index as int4).get_indirect_op() {
            Some(op) => op,
            None => return 4,
        };
        fd.obank()
            .get(indop)
            .and_then(|o| o.get_in(0))
            .and_then(|vn| fd.vbank().get(vn))
            .map(|v| v.get_size())
            .unwrap_or(4)
    }

    /// C++ `PrintC::emitBlockGoto` (printc.cc:2915): emit the block's body
    /// (no_branch) then the trailing `goto`/`break`/`continue` statement.
    ///
    /// STUB(W7): `BlockGoto::gotoPrints` consults `getParent()->nextFlowAfter` to
    /// suppress a `goto` to the very next printed block; `nextFlowAfter` is not
    /// yet ported, so the goto is always emitted when a target is present (an
    /// over-emit, never an under-emit — a redundant `goto LAB_x;` to the
    /// fallthrough where C++ would drop it).  Recorded as a loss.
    fn emit_block_goto(&mut self, fd: &Funcdata, arch: &Architecture, blk: BlockId) {
        self.context.push_mod();
        self.context.set_mod(modifiers::NO_BRANCH);
        let inner = fd.sblocks_ref().block(blk).get_block(0);
        self.emit_block(fd, arch, inner);
        self.context.pop_mod();
        // gotoPrints(): emit the trailing goto unless it targets the next block.
        if let Some(target) = fd.sblocks_ref().block(blk).get_goto_target() {
            self.emit.tag_line();
            let gototype = fd.sblocks_ref().block(blk).get_goto_type();
            self.emit_goto_statement(fd, inner, target, gototype);
            // (kuna warnstyle, DIV-39) pending block warnings land after the
            // trailing goto/break/continue.
            self.flush_eol_warnings();
        }
    }

    /// C++ `PrintC::emitForLoop` (printc.cc:3106): emit a `for (init; cond; iter)`
    /// header (with the init/iterate statements hoisted out of the body) followed
    /// by the loop body.  Reached from [`emit_block_while_do`] when the whiledo
    /// node carries an `iterateOp` (set by `Funcdata::finalize_forloop_*`).
    fn emit_for_loop(&mut self, fd: &Funcdata, arch: &Architecture, blk: BlockId) {
        self.context.push_mod();
        self.context.unset_mod(modifiers::NO_BRANCH | modifiers::ONLY_BRANCH);
        // emitAnyLabelStatement(bl): hoist the loop-head label to its own line
        // above the `for` (it was marked f_label_bumpup, so the inline
        // emit_block_copy suppresses it).
        self.emit_any_label_statement(fd, blk);
        let cond_block = fd.sblocks_ref().block(blk).get_block(0);
        self.emit_comment_block_tree(fd, cond_block);
        self.emit.tag_line();
        self.emit.tag_op(self.lang().kw_for, SyntaxHighlight::KeywordColor, &MarkupRef::none());
        self.emit.spaces(1, 0);
        let id1 = self.emit.open_paren(crate::printlanguage::OPEN_PAREN, 0);
        self.context.push_mod();
        self.context.set_mod(modifiers::COMMA_SEPARATE);
        // Emit the (optional) initializer statement.
        if let Some(op) = fd.sblocks_ref().block(blk).get_initialize_op() {
            let id3 = self.emit.begin_statement(&MarkupRef::none());
            self.emit_expression_ir(fd, arch, op);
            self.emit.end_statement(id3);
        }
        self.emit.print(self.lang().kw_semicolon, SyntaxHighlight::NoColor);
        self.emit.spaces(1, 0);
        // Emit the conditional statement (the condition block, comma-separated).
        self.emit_block(fd, arch, cond_block);
        self.emit.print(self.lang().kw_semicolon, SyntaxHighlight::NoColor);
        self.emit.spaces(1, 0);
        // Emit the iterator statement.
        if let Some(op) = fd.sblocks_ref().block(blk).get_iterate_op() {
            let id4 = self.emit.begin_statement(&MarkupRef::none());
            self.emit_expression_ir(fd, arch, op);
            self.emit.end_statement(id4);
        }
        self.context.pop_mod();
        self.emit.close_paren(crate::printlanguage::CLOSE_PAREN, id1);
        let indent =
            self.emit.open_brace_indent(self.lang().kw_open_curly, to_emit_brace(self.options.brace_loop));
        // (kuna warnstyle, DIV-39) condition-attached warnings land after the
        // `for (...) {` header brace.
        self.flush_eol_warnings();
        self.context.set_mod(modifiers::NO_BRANCH); // Don't print goto at bottom of clause
        let id2 = self.emit.begin_block(0);
        self.emit_block(fd, arch, fd.sblocks_ref().block(blk).get_block(1));
        self.emit.end_block(id2);
        self.emit.close_brace_indent(self.lang().kw_close_curly, indent);
        self.context.pop_mod();
    }

    /// C++ `PrintC::emitBlockWhileDo` (printc.cc:3150): the top-tested loop.
    /// Block 0 is the condition, block 1 the body.  When the loop carries an
    /// `iterateOp` (recorded by the for-loop reroll), it is emitted as a `for`
    /// loop ([`emit_for_loop`]); otherwise the plain `while` form is emitted.
    fn emit_block_while_do(&mut self, fd: &Funcdata, arch: &Architecture, blk: BlockId) {
        match self.lang().forms.while_loop {
            crate::kuna_lang::WhileForm::CParenWhile => self.emit_block_while_do_c(fd, arch, blk),
            crate::kuna_lang::WhileForm::RustBareWhile => {
                self.emit_block_while_do_rust(fd, arch, blk)
            }
        }
    }

    fn emit_block_while_do_c(&mut self, fd: &Funcdata, arch: &Architecture, blk: BlockId) {
        if fd.sblocks_ref().block(blk).get_iterate_op().is_some() {
            self.emit_for_loop(fd, arch, blk);
            return;
        }
        // whiledo block NEVER prints the final branch.
        self.context.push_mod();
        self.context.unset_mod(modifiers::NO_BRANCH | modifiers::ONLY_BRANCH);
        // emitAnyLabelStatement(bl) (printc.cc:3146): hoist the loop-head label
        // above the `while` (suppressed inline via f_label_bumpup).
        self.emit_any_label_statement(fd, blk);
        let cond_block = fd.sblocks_ref().block(blk).get_block(0);
        let indent;
        if fd.sblocks_ref().block(blk).has_overflow_syntax() {
            // Renders: while( true ) { conditionbody...; break-on-branch }
            self.emit.tag_line();
            self.emit.tag_op(self.lang().kw_while, SyntaxHighlight::KeywordColor, &MarkupRef::none());
            let id1 = self.emit.open_paren(crate::printlanguage::OPEN_PAREN, 0);
            self.emit.spaces(1, 0);
            self.emit.print(self.lang().kw_true, SyntaxHighlight::ConstColor);
            self.emit.spaces(1, 0);
            self.emit.close_paren(crate::printlanguage::CLOSE_PAREN, id1);
            indent = self.emit.open_brace_indent(self.lang().kw_open_curly, to_emit_brace(self.options.brace_loop));
            self.context.push_mod();
            self.context.set_mod(modifiers::NO_BRANCH);
            self.emit_block(fd, arch, cond_block);
            self.context.pop_mod();
            self.emit.tag_line();
            self.emit.tag_op(self.lang().kw_if, SyntaxHighlight::KeywordColor, &MarkupRef::none());
            self.emit.spaces(1, 0);
            self.context.push_mod();
            self.context.set_mod(modifiers::ONLY_BRANCH);
            self.emit_block(fd, arch, cond_block);
            self.context.pop_mod();
            self.emit.spaces(1, 0);
            self.emit_goto_statement(fd, cond_block, cond_block, crate::block::block_flags::f_break_goto);
        } else {
            // Renders: while(condition) { ... }
            self.emit_comment_block_tree(fd, cond_block);
            self.emit.tag_line();
            self.emit.tag_op(self.lang().kw_while, SyntaxHighlight::KeywordColor, &MarkupRef::none());
            self.emit.spaces(1, 0);
            let id1 = self.emit.open_paren(crate::printlanguage::OPEN_PAREN, 0);
            self.context.push_mod();
            self.context.set_mod(modifiers::COMMA_SEPARATE);
            self.emit_block(fd, arch, cond_block);
            self.context.pop_mod();
            self.emit.close_paren(crate::printlanguage::CLOSE_PAREN, id1);
            indent = self.emit.open_brace_indent(self.lang().kw_open_curly, to_emit_brace(self.options.brace_loop));
            // (kuna warnstyle, DIV-39) condition-attached warnings land after
            // the `while (cond) {` header brace.
            self.flush_eol_warnings();
        }
        self.context.set_mod(modifiers::NO_BRANCH); // don't print goto at bottom of clause
        let id2 = self.emit.begin_block(0);
        self.emit_block(fd, arch, fd.sblocks_ref().block(blk).get_block(1));
        self.emit.end_block(id2);
        self.emit.close_brace_indent(self.lang().kw_close_curly, indent);
        self.context.pop_mod();
    }

    /// C++ `PrintC::emitBlockDoWhile` (printc.cc:3217): the bottom-tested loop.
    /// `do { block0-body } while (block0-branch);`.
    fn emit_block_do_while(&mut self, fd: &Funcdata, arch: &Architecture, blk: BlockId) {
        match self.lang().forms.do_while {
            crate::kuna_lang::DoWhileForm::CDoWhile => self.emit_block_do_while_c(fd, arch, blk),
            crate::kuna_lang::DoWhileForm::RustLoopBreakIf => {
                self.emit_block_do_while_rust(fd, arch, blk)
            }
        }
    }

    fn emit_block_do_while_c(&mut self, fd: &Funcdata, arch: &Architecture, blk: BlockId) {
        // dowhile block NEVER prints the final branch.
        self.context.push_mod();
        self.context.unset_mod(modifiers::NO_BRANCH | modifiers::ONLY_BRANCH);
        // emitAnyLabelStatement(bl) (printc.cc:3208): hoist the loop-head label
        // above the `do` (suppressed inline via f_label_bumpup).
        self.emit_any_label_statement(fd, blk);
        self.emit.tag_line();
        self.emit.print(self.lang().kw_do, SyntaxHighlight::KeywordColor);
        let id = self.emit.open_brace_indent(self.lang().kw_open_curly, to_emit_brace(self.options.brace_loop));
        let body = fd.sblocks_ref().block(blk).get_block(0);
        self.context.push_mod();
        let id2 = self.emit.begin_block(0);
        self.context.set_mod(modifiers::NO_BRANCH);
        self.emit_block(fd, arch, body);
        self.emit.end_block(id2);
        self.context.pop_mod();
        self.emit.close_brace_indent(self.lang().kw_close_curly, id);
        self.emit.spaces(1, 0);
        self.emit.tag_op(self.lang().kw_while, SyntaxHighlight::KeywordColor, &MarkupRef::none());
        self.emit.spaces(1, 0);
        self.context.set_mod(modifiers::ONLY_BRANCH);
        self.emit_block(fd, arch, body);
        self.emit.print(self.lang().kw_semicolon, SyntaxHighlight::NoColor);
        // (kuna warnstyle, DIV-39) body/condition warnings still pending land
        // at the end of the `} while (cond);` line.
        self.flush_eol_warnings();
        self.context.pop_mod();
    }

    /// C++ `PrintC::emitBlockInfLoop` (printc.cc:3246): the infinite loop.
    /// `do { block0-body } while( true );`.
    fn emit_block_inf_loop(&mut self, fd: &Funcdata, arch: &Architecture, blk: BlockId) {
        match self.lang().forms.inf_loop {
            crate::kuna_lang::InfLoopForm::CDoWhileTrue => {
                self.emit_block_inf_loop_c(fd, arch, blk)
            }
            crate::kuna_lang::InfLoopForm::RustLoop => self.emit_block_inf_loop_rust(fd, arch, blk),
        }
    }

    fn emit_block_inf_loop_c(&mut self, fd: &Funcdata, arch: &Architecture, blk: BlockId) {
        self.context.push_mod();
        self.context.unset_mod(modifiers::NO_BRANCH | modifiers::ONLY_BRANCH);
        // emitAnyLabelStatement(bl) (printc.cc:3236): hoist the loop-head label
        // above the `do` (suppressed inline via f_label_bumpup).
        self.emit_any_label_statement(fd, blk);
        self.emit.tag_line();
        self.emit.print(self.lang().kw_do, SyntaxHighlight::KeywordColor);
        let id = self.emit.open_brace_indent(self.lang().kw_open_curly, to_emit_brace(self.options.brace_loop));
        let body = fd.sblocks_ref().block(blk).get_block(0);
        let id1 = self.emit.begin_block(0);
        self.emit_block(fd, arch, body);
        self.emit.end_block(id1);
        self.emit.close_brace_indent(self.lang().kw_close_curly, id);
        self.emit.spaces(1, 0);
        self.emit.tag_op(self.lang().kw_while, SyntaxHighlight::KeywordColor, &MarkupRef::none());
        let id2 = self.emit.open_paren(crate::printlanguage::OPEN_PAREN, 0);
        self.emit.spaces(1, 0);
        self.emit.print(self.lang().kw_true, SyntaxHighlight::ConstColor);
        self.emit.spaces(1, 0);
        self.emit.close_paren(crate::printlanguage::CLOSE_PAREN, id2);
        self.emit.print(self.lang().kw_semicolon, SyntaxHighlight::NoColor);
        // (kuna warnstyle, DIV-39) pending body warnings land at the end of
        // the `} while ( true );` line.
        self.flush_eol_warnings();
        self.context.pop_mod();
    }

    /// C++ `PrintC::emitGotoStatement` (printc.cc:2379): a `goto`/`break`/
    /// `continue` statement for an unstructured branch.  The destination label is
    /// the target block's reverse-post index (`LAB_<index>` — full address-based
    /// label naming is the label/naming layer).
    pub(crate) fn emit_goto_statement(
        &mut self,
        fd: &Funcdata,
        _src: BlockId,
        target: BlockId,
        gototype: uint4,
    ) {
        use crate::block::block_flags;
        let id = self.emit.begin_statement(&MarkupRef::none());
        match gototype {
            x if x == block_flags::f_break_goto => {
                self.emit.print(self.lang().kw_break, SyntaxHighlight::KeywordColor);
            }
            x if x == block_flags::f_continue_goto => {
                self.emit.print(self.lang().kw_continue, SyntaxHighlight::KeywordColor);
            }
            _ => match self.lang().forms.goto {
                crate::kuna_lang::GotoForm::CGoto => {
                    self.emit.print(self.lang().kw_goto, SyntaxHighlight::KeywordColor);
                    self.emit.spaces(1, 0);
                    self.emit.print(&self.block_label_name(fd, target), SyntaxHighlight::NoColor);
                }
                crate::kuna_lang::GotoForm::Unrepresentable => {
                    self.emit_unrepresentable_goto(fd, target);
                }
            },
        }
        self.emit.print(self.lang().kw_semicolon, SyntaxHighlight::NoColor);
        self.emit.end_statement(id);
    }

    /// The op-list walk shared by `emitBlockCopy`/`emitBlockBasic` (C++
    /// `PrintC::emitBlockBasic`, printc.cc:2827).  `bblocks` selects which arena
    /// holds the basic block (a `BlockCopy` points into `bblocks`).
    fn emit_basic_block_ops(
        &mut self,
        fd: &Funcdata,
        arch: &Architecture,
        bb: BlockId,
        bblocks: bool,
    ) {
        // commsorter.setupBlockList(bb) (printc.cc:2833): the comment walk window
        // for this basic block.  The index is the *bblocks* BlockBasic's index
        // (the sblocks node is a BlockCopy mirror, so resolve through `copy`).
        let bb_index = if bblocks {
            fd.bblocks_ref().block(bb).get_index()
        } else {
            sblocks_basic_block_index(fd, bb)
        };
        self.commsorter.setup_block_list(bb_index);
        // only_branch: print only the block's branch instruction (CBRANCH).
        if self.context.is_set(modifiers::ONLY_BRANCH) {
            let last = if bblocks { fd.bb_op_tail(bb) } else { sblocks_basic_tail(fd, bb) };
            if let Some(inst) = last {
                if fd.obank().get(inst).map(|o| o.is_branch()).unwrap_or(false) {
                    self.emit_expression_ir(fd, arch, inst);
                }
            }
            return;
        }
        let mut separator = false;
        let mut cur = if bblocks { fd.bb_op_head(bb) } else { sblocks_basic_head(fd, bb) };
        while let Some(inst) = cur {
            cur = fd.bb_op_next(inst);
            let o = match fd.obank().get(inst) {
                Some(o) => o,
                None => continue,
            };
            if o.not_printed() {
                continue;
            }
            // (kuna `voidtailreturn`) The function's own trailing bare `return;`.
            // The source it came from just falls off the end of the body, and
            // pyjoern's CFG has no node there, so printing it is both redundant C
            // and a structural divergence.  Elided only when
            // `elidable_void_tail_return` proved it is the LAST statement of a void
            // function reached on exactly one structured path.
            if Some(inst) == self.void_tail_return {
                continue;
            }
            if o.is_branch() {
                if self.context.is_set(modifiers::NO_BRANCH) {
                    continue;
                }
                if o.code() == OpCode::CPUI_BRANCH {
                    continue;
                }
            }
            // Skip ops whose output is an implied varnode (inlined elsewhere).
            if let Some(out) = o.get_out() {
                if fd.vbank().get(out).map(|v| v.is_implied()).unwrap_or(false) {
                    continue;
                }
            }
            if separator {
                if self.context.is_set(modifiers::COMMA_SEPARATE) {
                    self.emit.print(self.lang().kw_comma, SyntaxHighlight::NoColor);
                    self.emit.spaces(1, 0);
                } else {
                    self.emit_comment_group(fd, Some(inst));
                    self.emit.tag_line();
                }
            } else if !self.context.is_set(modifiers::COMMA_SEPARATE) {
                self.emit_comment_group(fd, Some(inst));
                self.emit.tag_line();
            }
            self.emit_statement(fd, arch, inst);
            // (kuna warnstyle, DIV-39) warnings collected for this statement
            // land after its semicolon — but NEVER inside a comma-separated
            // header (`while (...)` / `for (...)` parens), where an inline
            // `// slug` would comment out the rest of the header line
            // (invalid C); those slugs ride to the header's own flush point.
            if !self.context.is_set(modifiers::COMMA_SEPARATE) {
                self.flush_eol_warnings();
            }
            separator = true;
        }
        // emitCommentGroup(None): any remaining comments in the block.
        if !self.context.is_set(modifiers::COMMA_SEPARATE) {
            self.emit_comment_group(fd, None);
            // (kuna warnstyle) trailing warnings — most commonly one attached
            // to this block's suppressed CBRANCH — stay PENDING here: for a
            // condition block the right line is the upcoming `if (cond)`
            // header, whose emitter flushes them.
        }
    }

    /// C++ `PrintC::emitStatement` (printc.cc:2361).
    fn emit_statement(&mut self, fd: &Funcdata, arch: &Architecture, inst: OpId) {
        // C++ `emit->beginStatement(inst)`: the statement's root op — `opref =
        // inst->getTime()`, the `<ast>` `<seqnum uniq>` a client clicks to.
        let stmt_markup = self.op_markup(fd, inst);
        let id = self.emit.begin_statement(&stmt_markup);
        self.emit_expression_ir(fd, arch, inst);
        self.emit.end_statement(id);
        if !self.context.is_set(modifiers::COMMA_SEPARATE) {
            self.emit.print(self.lang().kw_semicolon, SyntaxHighlight::NoColor);
        }
    }

    /// (kuna) The `loopcounterstore` / `tiedstorekeep` seam for
    /// [`Self::emit_inplace_op`]: when `op` is a `CPUI_COPY` of an IMPLIED
    /// two-input value, answer that value's defining op and its two inputs, so
    /// the in-place render can be decided on the arithmetic rather than on the
    /// store that survived on top of it.  `None` for every other shape, which
    /// leaves upstream's behaviour untouched.
    fn inplace_through_copy(
        &self,
        fd: &Funcdata,
        opc: OpCode,
        in0: Option<VarnodeId>,
        num_input: int4,
    ) -> Option<(OpId, VarnodeId, VarnodeId)> {
        if opc != OpCode::CPUI_COPY || num_input != 1 {
            return None;
        }
        let src = in0?;
        let srcvn = fd.vbank().get(src)?;
        if !srcvn.is_implied() {
            return None;
        }
        let def = fd.obank().get(srcvn.get_def()?)?;
        if def.num_input() != 2 {
            return None;
        }
        Some((srcvn.get_def()?, def.get_in(0)?, def.get_in(1)?))
    }

    /// C++ `PrintC::emitInplaceOp` (printc.cc, directly above `emitExpression`;
    /// gated by the `option_inplace_ops` head at printc.cc:2546 which upstream
    /// never wires beyond the flag — ported here as the flag's consumer,
    /// default-on per kuna DIV-36).
    ///
    /// When the statement is `out = out OP y` — a two-input integer op whose
    /// first input is the SAME high-level variable as the output — render the
    /// C compound-assignment form `out OP= y` instead.  Returns `true` when the
    /// in-place form was emitted (the caller stops), `false` to fall through to
    /// the ordinary `out = expr` render.
    ///
    /// Faithful to the upstream shape: the token map covers the ten integer
    /// ops with `OP=` tokens (printc.cc:62-71); the identity test is HighVariable
    /// equality (same high ⇒ same printed name); `in0` is pushed with
    /// `pushVnExplicit` (never expanded), `in1` with the ordinary `pushVn`.
    fn emit_inplace_op(&mut self, fd: &Funcdata, arch: &Architecture, op: OpId) -> bool {
        let (opc, out, in0, in1, num_input) = match fd.obank().get(op) {
            Some(o) => (o.code(), o.get_out(), o.get_in(0), o.get_in(1), o.num_input()),
            None => return false,
        };
        // (kuna) See through a surviving store: `option loopcounterstore` keeps
        // the address-tied `COPY` that writes a loop counter back to its frame
        // slot, so the statement's root op is that `COPY` and the arithmetic
        // hangs off it as an implied expression -- `out = out OP y` reaches here
        // as `out = COPY(t)` with `t = out OP y`.  Render it from the inner op,
        // which is what upstream would have seen had the copy been propagated.
        // Only an IMPLIED input qualifies: an explicit one has a name of its own
        // and the statement really is `out = <that name>`.
        let (opc, in0, in1, num_input, op) = match self.inplace_through_copy(fd, opc, in0, num_input) {
            Some((inner_op, i0, i1)) => (
                fd.obank().get(inner_op).map(|o| o.code()).unwrap_or(opc),
                Some(i0),
                Some(i1),
                2,
                inner_op,
            ),
            None => (opc, in0, in1, num_input, op),
        };
        // Rust compound operators would bypass the p-code-width wrapping
        // arithmetic below, including when the arithmetic is behind a COPY.
        if self.out_lang == crate::kuna_lang::OutLang::Rust
            && matches!(opc, OpCode::CPUI_INT_ADD | OpCode::CPUI_INT_SUB | OpCode::CPUI_INT_MULT)
        {
            return false;
        }
        let tok: &'static OpToken = match opc {
            OpCode::CPUI_INT_MULT => &tokens::MULTEQUAL,
            OpCode::CPUI_INT_DIV | OpCode::CPUI_INT_SDIV => &tokens::DIVEQUAL,
            OpCode::CPUI_INT_REM | OpCode::CPUI_INT_SREM => &tokens::REMEQUAL,
            OpCode::CPUI_INT_ADD => &tokens::PLUSEQUAL,
            OpCode::CPUI_INT_SUB => &tokens::MINUSEQUAL,
            OpCode::CPUI_INT_LEFT => &tokens::LEFTEQUAL,
            OpCode::CPUI_INT_RIGHT | OpCode::CPUI_INT_SRIGHT => &tokens::RIGHTEQUAL,
            OpCode::CPUI_INT_AND => &tokens::ANDEQUAL,
            OpCode::CPUI_INT_OR => &tokens::OREQUAL,
            OpCode::CPUI_INT_XOR => &tokens::XOREQUAL,
            _ => return false,
        };
        if num_input != 2 {
            return false;
        }
        let (out, in0, in1) = match (out, in0, in1) {
            (Some(a), Some(b), Some(c)) => (a, b, c),
            _ => return false,
        };
        // C++ `op->getOut()->getHigh() != vn->getHigh()` — pre-merge Nones never
        // fold (a None high is "not the same variable").
        let out_high = fd.vbank().get(out).and_then(|v| v.get_high());
        let in0_high = fd.vbank().get(in0).and_then(|v| v.get_high());
        match (out_high, in0_high) {
            (Some(a), Some(b)) if a == b => {}
            _ => return false,
        }
        // (kuna) `x += -c` reads poorly: when the INT_ADD addend is a plain
        // negative signed constant (no equate/display override, not char-typed,
        // not the unnegatable type minimum), render `x -= c` with the negated
        // magnitude instead.  The dataflow canonicalizes `sub x, c` into
        // INT_ADD(x, -c), so this restores the source's subtraction form.
        if opc == OpCode::CPUI_INT_ADD {
            if let Some(v) = fd.vbank().get(in1) {
                if v.is_constant() && fd.vn_high_display_format(in1) == 0 {
                    let ct = v.get_type_read_facing(op).clone();
                    let sz = v.get_size();
                    let mask = calc_mask(sz);
                    let val = v.get_offset() & mask;
                    let topbit = (mask >> 1) + 1;
                    if ct.get_metatype() == crate::dtype::type_metatype::TYPE_INT
                        && !ct.is_char_print()
                        && !ct.is_enum_type()
                        && (val & topbit) != 0
                        && val != topbit
                    {
                        let mag = (!val).wrapping_add(1) & mask;
                        self.push_op(&tokens::MINUSEQUAL, Some(op_key(op)));
                        self.push_vn_explicit_ir(fd, arch, in0, op);
                        self.push_constant_ir_fmt_sign(mag, sz, op, 0, true);
                        return true;
                    }
                }
            }
        }
        self.push_op(tok, Some(op_key(op)));
        self.push_vn_explicit_ir(fd, arch, in0, op);
        self.push_vn_ir(fd, arch, in1, op);
        true
    }

    /// C++ `PrintC::emitExpression` (printc.cc:2544): if the op has an output,
    /// open an assignment to it, then push the op's expression and recurse.
    fn emit_expression_ir(&mut self, fd: &Funcdata, arch: &Architecture, op: OpId) {
        // C++ `if (option_inplace_ops && emitInplaceOp(op)) return;`
        // (printc.cc:2546) — the in-place `OP=` render, kuna DIV-36 default-on
        // (`option inplaceops off` restores the upstream `out = out OP y` form).
        // Applied to standalone `;`-terminated statements only: comma contexts
        // (for-loop headers, condition-block side effects) keep the upstream
        // `out = out OP y` form, so `for (...; i = i + 1)` renders unchanged.
        if self.options.inplace_ops
            && !self.context.is_set(modifiers::COMMA_SEPARATE)
            && self.emit_inplace_op(fd, arch, op)
        {
            return;
        }
        // C++ special-printing dispatch (printc.cc:2547-2566): a STORE/INSERT
        // marked by the bitfield transforms renders as `ptr->field = value`
        // (the constructor and SUBPIECE special-print arms are other surfaces).
        if fd.obank().get(op).map(|o| o.does_special_printing()).unwrap_or(false) {
            match fd.obank().get(op).map(|o| o.code()) {
                Some(OpCode::CPUI_STORE) => {
                    self.emit_bitfield_store(fd, arch, op);
                    return;
                }
                Some(OpCode::CPUI_INSERT) => {
                    self.emit_bitfield_expression(fd, arch, op);
                    return;
                }
                // CPUI_SUBPIECE: don't modify printing here (printc.cc:2561).
                // The constructor arm and any other special-print op are other
                // surfaces; fall through to the normal render.
                _ => {}
            }
        }
        let outvn = fd.obank().get(op).and_then(|o| o.get_out());
        if let Some(out) = outvn {
            self.push_op(&tokens::ASSIGNMENT, Some(op_key(op)));
            self.push_vn_explicit_ir(fd, arch, out, op);
        }
        self.stmt_op = outvn.map(|_| op);
        self.op_push_ir(fd, arch, op, None);
        self.stmt_op = None;
    }

    /// C++ `op->getOpcode()->push(this,op,readop)` — the per-opcode RPN push
    /// (the `PrintC::op*` overrides, dispatched via [`op_emit_kind`] plus the
    /// hand-written cases the structured boolless body reaches).
    ///
    /// `read_op` is the C++ `readOp` argument threaded by `getOpcode()->push`:
    /// the op that *reads* `op`'s output when `op` is being pushed as an implied
    /// value (`pushVnImplied`/`pushImpliedField` pass the reader; printc.cc:2186),
    /// else `None` at the top of an expression (printc.cc:2579 passes `(PcodeOp *)0`).
    /// Only `opIntSext`/`opIntZext` consume it (the extension-cast-implied test,
    /// printc.cc:806-830); every other override ignores it.
    fn op_push_ir(&mut self, fd: &Funcdata, arch: &Architecture, op: OpId, read_op: Option<OpId>) {
        let opc = fd.obank().get(op).expect("op_push_ir: stale op").code();
        // (kuna truthycond, DIV-37) CONDITION_CONTEXT only survives through the
        // boolean-preserving operators; any other operator's operands are value
        // context, so scope the bit off across this dispatch (the mod-stack
        // frame restores it for our siblings).
        let scope_off_cond = self.context.is_set(modifiers::CONDITION_CONTEXT)
            && !matches!(
                opc,
                OpCode::CPUI_INT_EQUAL
                    | OpCode::CPUI_INT_NOTEQUAL
                    | OpCode::CPUI_FLOAT_EQUAL
                    | OpCode::CPUI_FLOAT_NOTEQUAL
                    | OpCode::CPUI_BOOL_AND
                    | OpCode::CPUI_BOOL_OR
                    | OpCode::CPUI_BOOL_NEGATE
                    | OpCode::CPUI_CBRANCH
            );
        if scope_off_cond {
            self.context.push_mod();
            self.context.unset_mod(modifiers::CONDITION_CONTEXT);
        }
        self.op_push_ir_inner(fd, arch, op, read_op, opc);
        if scope_off_cond {
            self.context.pop_mod();
        }
    }

    /// The per-opcode dispatch body of [`op_push_ir`](Self::op_push_ir) (split
    /// out so the CONDITION_CONTEXT scoping wraps every arm uniformly).
    fn op_push_ir_inner(
        &mut self,
        fd: &Funcdata,
        arch: &Architecture,
        op: OpId,
        read_op: Option<OpId>,
        opc: OpCode,
    ) {
        if self.out_lang == crate::kuna_lang::OutLang::Rust
            && matches!(opc, OpCode::CPUI_INT_ADD | OpCode::CPUI_INT_SUB | OpCode::CPUI_INT_MULT)
            && self.op_rust_wrapping_ir(fd, arch, op, opc)
        {
            return;
        }
        match opc {
            // INT_SEXT (printc.cc:819 opIntSext) / INT_ZEXT (printc.cc:806 opIntZext):
            // the cast-strategy decides whether the extension renders as an explicit
            // `(intN)`/`(uintN)` cast, is hidden (implied by integer promotion), or
            // falls back to the functional `SEXT(x)`/`ZEXT(x)` form.
            OpCode::CPUI_INT_SEXT => self.op_int_sext_ir(fd, arch, op, read_op),
            OpCode::CPUI_INT_ZEXT => self.op_int_zext_ir(fd, arch, op, read_op),
            // CBRANCH: the structured-if condition (printc.cc:556 opCbranch).
            // In the non-flat path opCbranch only emits the `( condition )`; the
            // `if` keyword is printed by emit_block_if.  yesparen = !comma_separate.
            OpCode::CPUI_CBRANCH => {
                // (kuna outlang) A language without parenthesised conditions
                // (`if c {` rather than `if (c)`) suppresses the paren; the
                // grouping token still opens so line breaking is unchanged.
                let yesparen = !self.context.is_set(modifiers::COMMA_SEPARATE)
                    && self.lang().caps.paren_conditions;
                let mut booleanflip = fd.obank().get(op).map(|o| o.is_boolean_flip()).unwrap_or(false);
                let in1 = fd.obank().get(op).and_then(|o| o.get_in(1));
                let id = if yesparen {
                    self.emit.open_paren(crate::printlanguage::OPEN_PAREN, 0)
                } else {
                    self.emit.open_group()
                };
                // C++ opCbranch (printc.cc:578): if the condition op can be
                // negated as a token (INT_EQUAL->INT_NOTEQUAL etc.), absorb the
                // `!` into the comparison via the `negatetoken` modifier instead
                // of emitting an explicit BOOL_NEGATE.
                let use_negate_token =
                    booleanflip && in1.map(|vn| self.check_print_negation(fd, vn)).unwrap_or(false);
                if use_negate_token {
                    booleanflip = false;
                }
                if booleanflip {
                    self.push_op(&tokens::BOOLEAN_NOT, Some(op_key(op)));
                }
                // (kuna truthycond, DIV-37) The condition value is consumed as
                // a boolean — mark the context so a `!= 0`/`== 0` comparison
                // renders in truthy form; same mod-stack frame carries the
                // negate-token absorption.
                self.context.push_mod();
                self.context.set_mod(modifiers::CONDITION_CONTEXT);
                if use_negate_token {
                    self.context.set_mod(modifiers::NEGATETOKEN);
                }
                if let Some(vn) = in1 {
                    self.push_vn_ir(fd, arch, vn, op);
                }
                self.context.pop_mod();
                // recurse() drains the stack: direct resolution above already
                // drained it (the RPN engine unwinds on the final push_atom), so
                // the paren can close now.
                if yesparen {
                    self.emit.close_paren(crate::printlanguage::CLOSE_PAREN, id);
                } else {
                    self.emit.close_group(id);
                }
            }
            // BRANCHIND (printc.cc:602 opBranchind): the switch header `switch(v)`.
            // The structured switch body (`{ case N: ... }`) is emitted by
            // `emit_block_switch`; here only the `switch(in0)` expression prints.
            OpCode::CPUI_BRANCHIND => {
                let kw_markup = self.op_markup(fd, op);
                self.emit.tag_op(self.lang().kw_switch, SyntaxHighlight::KeywordColor, &kw_markup);
                // (kuna outlang) `switch (v)` in C, `match v` in Rust.
                let paren = self.lang().caps.paren_conditions;
                let id = if paren {
                    self.emit.open_paren(crate::printlanguage::OPEN_PAREN, 0)
                } else {
                    self.emit.spaces(1, 0);
                    self.emit.open_group()
                };
                if let Some(vn) = fd.obank().get(op).and_then(|o| o.get_in(0)) {
                    let cast = lowered_switch_label_form(fd, arch, op).and_then(|(_, cast)| cast);
                    if let Some(ct) = &cast {
                        self.push_cast_open(ct, op);
                    }
                    self.push_vn_ir(fd, arch, vn, op);
                    if let Some(ct) = &cast {
                        self.push_cast_close(ct);
                    }
                }
                if paren {
                    self.emit.close_paren(crate::printlanguage::CLOSE_PAREN, id);
                } else {
                    self.emit.close_group(id);
                }
            }
            // RETURN (printc.cc:774 opReturn).
            OpCode::CPUI_RETURN => {
                let kw_markup = self.op_markup(fd, op);
                // (kuna decodehalt) The `getHaltType()` arms of the upstream
                // switch: a RETURN kuna planted because the bytes would not
                // decode is a pseudo-call naming the failure, not a return.
                let halt = fd.obank().get(op).map(|o| o.get_halt_type()).unwrap_or(0);
                let named = arch
                    .decode_halt
                    .then(|| crate::kuna_decodehalt::halt_call_name(halt))
                    .flatten();
                if let Some(nm) = named {
                    self.emit.tag_func_name(nm, SyntaxHighlight::FuncnameColor, &kw_markup);
                    self.emit.print(crate::printlanguage::OPEN_PAREN, SyntaxHighlight::NoColor);
                    self.emit.print(crate::printlanguage::CLOSE_PAREN, SyntaxHighlight::NoColor);
                    return;
                }
                self.emit.tag_op(self.lang().kw_return, SyntaxHighlight::KeywordColor, &kw_markup);
                let nin = fd.obank().get(op).map(|o| o.num_input()).unwrap_or(0);
                if nin > 1 {
                    self.emit.spaces(1, 0);
                    if let Some(vn) = fd.obank().get(op).and_then(|o| o.get_in(1)) {
                        self.push_vn_ir(fd, arch, vn, op);
                    }
                }
            }
            // COPY (printc.cc:501 opCopy): just push the input.
            OpCode::CPUI_COPY => {
                if let Some(vn) = fd.obank().get(op).and_then(|o| o.get_in(0)) {
                    self.push_vn_ir(fd, arch, vn, op);
                }
            }
            // LOAD (printc.cc:507 opLoad) / STORE (printc.cc:520 opStore).
            OpCode::CPUI_LOAD => self.op_load_ir(fd, arch, op),
            OpCode::CPUI_STORE => self.op_store_ir(fd, arch, op),
            // ZPULL (printc.cc:1294 opZpullOp) / SPULL (printc.cc:1320 opSpullOp):
            // a bitfield read.  Both render `ptr->field` / `symbol.field` via the
            // shared `op_pull_ir`, falling back to `ZPULL(...)`/`SPULL(...)` when
            // the structure/bitfield can't be recovered.
            OpCode::CPUI_ZPULL | OpCode::CPUI_SPULL => self.op_pull_ir(fd, arch, op),
            // BOOL_NEGATE (printc.cc:834 opBoolNegate): the `!x` unary, with the
            // double-negation cancellation (`negatetoken`) and the
            // flip-the-next-operator optimization (`checkPrintNegation`).
            OpCode::CPUI_BOOL_NEGATE => self.op_bool_negate_ir(fd, arch, op),
            // SUBPIECE (printc.cc:863 opSubpiece): a field-extraction special-print
            // (`symbol.field`) or the cast/functional dispatch.
            OpCode::CPUI_SUBPIECE => self.op_subpiece_ir(fd, arch, op),
            // PTRADD (printc.cc:900 opPtradd) / PTRSUB (printc.cc:953 opPtrsub).
            OpCode::CPUI_PTRADD => self.op_ptradd_ir(fd, arch, op),
            OpCode::CPUI_PTRSUB => self.op_ptrsub_ir(fd, arch, op),
            // CALL / CALLIND (printc.cc:613 opCall / 657 opCallind): the functional
            // `callee(arg1, arg2, ...)` form over the recovered call inputs.
            OpCode::CPUI_CALL | OpCode::CPUI_CALLIND => {
                self.op_call_ir(fd, arch, op);
            }
            // CALLOTHER (printc.cc:693 opCallother): a user p-code op.  The display
            // class (`userop->getDisplay()`) chooses the form: functional
            // `name(arg,...)` for a black-box op, `display_string` for the
            // internal-string builtin, or the no-operator/annotation forms.
            OpCode::CPUI_CALLOTHER => self.op_callother_ir(fd, arch, op),
            // FLOAT_INT2FLOAT (printc.cc:850 opFloatInt2Float): the int->float
            // conversion renders as a `(floatN)input` cast (NOT a functional
            // `FLOAT_INT2FLOAT(input)`), absorbing an implied INT_ZEXT on its
            // input so the widened source prints once.
            OpCode::CPUI_FLOAT_INT2FLOAT => self.op_float_int2float_ir(fd, arch, op),
            // MULTIEQUAL / INDIRECT: no-op (printc.hh:337-338 opMultiequal/
            // opIndirect) — copy markers, never printed as an operator.  The
            // phi's value is whatever its (single, post-merge) instance reads.
            OpCode::CPUI_MULTIEQUAL | OpCode::CPUI_INDIRECT => {
                // Push in0 so the assignment has a RHS (degenerate phi rendering;
                // faithful multi-instance phi rendering is the merge layer).
                if let Some(vn) = fd.obank().get(op).and_then(|o| o.get_in(0)) {
                    self.push_vn_ir(fd, arch, vn, op);
                }
            }
            _ => {
                // Table-driven binary / unary / functional forms.
                match op_emit_kind(opc) {
                    OpEmitKind::Binary(tok) => {
                        let tok = self.lang_token(tok);
                        self.op_binary_ir(fd, arch, tok, op)
                    }
                    OpEmitKind::Unary(tok) => {
                        let tok = self.lang_token(tok);
                        self.op_unary_ir(fd, arch, tok, op)
                    }
                    // opTypeCast (printc.cc:468): the C cast-notation `(type)operand`
                    // form.  CPUI_CAST / CPUI_FLOAT_FLOAT2FLOAT / CPUI_FLOAT_TRUNC
                    // all reduce to opTypeCast (printc.hh:332-341) — they render as
                    // a parenthesized type cast, not a functional `OPC(args)`.
                    OpEmitKind::TypeCast if opc == OpCode::CPUI_CAST => {
                        let implied = self.implied_cast_drops(fd, arch, op, read_op);
                        self.op_type_cast_ir_with(fd, arch, op, implied)
                    }
                    OpEmitKind::TypeCast => self.op_type_cast_ir(fd, arch, op),
                    OpEmitKind::Func | OpEmitKind::Custom => {
                        // opFunc / hand-written: the functional `OPC(args)` form.
                        // (The userop name resolution for true user p-code ops is
                        // a separate layer.)
                        self.op_func_ir(fd, arch, op);
                    }
                }
            }
        }
    }

    /// Rust integer operations use the p-code modulus in every build profile.
    fn op_rust_wrapping_ir(
        &mut self, fd: &Funcdata, arch: &Architecture, op: OpId, opc: OpCode,
    ) -> bool {
        use crate::dtype::type_metatype::{TYPE_INT, TYPE_UINT, TYPE_UNKNOWN};
        let Some(expr) = fd.obank().get(op) else { return false };
        let Some(out) = expr.get_out().and_then(|v| fd.vbank().get(v)) else { return false };
        let size = out.get_size();
        let result = out.get_high().and_then(|high| self.sign_plan.decl_type(high)).cloned()
            .or_else(|| expr.get_out().and_then(|v| declared_variable_type(fd, arch.decl_high_type, v)))
            .unwrap_or_else(|| out.get_type_def_facing().clone());
        if !matches!(result.get_metatype(), TYPE_INT | TYPE_UINT | TYPE_UNKNOWN) {
            return false; // Pointer arithmetic is not integer arithmetic.
        }
        // Rust has no primitive for other p-code widths. Keep the explicit
        // operation rather than silently rounding its modulus to a larger type.
        if !matches!(size, 1 | 2 | 4 | 8 | 16)
            || !matches!(result.get_size(), 1 | 2 | 4 | 8 | 16)
        {
            self.op_func_ir(fd, arch, op);
            return true;
        }
        let (Some(left), Some(right)) = (expr.get_in(0), expr.get_in(1)) else { return false };
        let meta = if result.get_metatype() == TYPE_INT && !result.is_char_print() {
            TYPE_INT
        } else {
            TYPE_UINT
        };
        let Ok(width) = arch.types().get_base_no_char(size, meta) else { return false };
        let widen = result.get_size() != size;
        if widen { self.push_cast_open(&result, op); }
        self.push_op(&tokens::FUNCTION_CALL, Some(op_key(op)));
        self.push_op(&tokens::OBJECT_MEMBER, Some(op_key(op)));
        self.push_rust_integer_operand(fd, arch, left, op, &width, self.context.mods());
        self.push_atom(&Atom::with_op(
            match opc {
                OpCode::CPUI_INT_ADD => "wrapping_add",
                OpCode::CPUI_INT_SUB => "wrapping_sub",
                _ => "wrapping_mul",
            }.to_string(),
            TagType::Syntax, crate::printlanguage::SyntaxHighlight::funcname_color, op_key(op),
        ));
        self.push_rust_integer_operand(fd, arch, right, op, &width, self.context.mods());
        if widen { self.push_cast_close(&result); }
        true
    }

    /// An explicit primitive cast is semantic here, not a cosmetic C cast:
    /// neither integer promotion nor the inferred declaration may choose the
    /// modulus of a p-code operation. Each operand is emitted exactly once.
    fn push_rust_integer_operand(
        &mut self, fd: &Funcdata, arch: &Architecture, vn: VarnodeId, op: OpId,
        ty: &crate::dtype::TypeRoot, mods: u32,
    ) {
        self.push_cast_open(ty, op);
        if let Some(value) = fd.vbank().get(vn).filter(|v| v.is_constant()
            && matches!(v.get_size(), 1 | 2 | 4 | 8 | 16))
        {
            // Give the bit pattern an unsigned source width. Unsuffixed
            // literals (especially negative minima cast to a narrower type)
            // can otherwise overflow Rust's inferred literal type.
            self.push_atom(&Atom::with_op(
                format!("{}u{}", value.get_offset() & calc_mask(value.get_size()), value.get_size() * 8),
                TagType::Syntax, crate::printlanguage::SyntaxHighlight::const_color, op_key(op),
            ));
        } else {
            self.push_vn_ir_m(fd, arch, vn, op, mods);
        }
        self.push_cast_close(ty);
    }

    /// C++ `PrintLanguage::opBinary` over the IR (printlanguage.cc:553).
    fn op_binary_ir(&mut self, fd: &Funcdata, arch: &Architecture, tok: &'static OpToken, op: OpId) {
        let tok = if self.context.is_set(modifiers::NEGATETOKEN) {
            self.context.unset_mod(modifiers::NEGATETOKEN);
            token_negate(tok).unwrap_or(tok)
        } else {
            tok
        };
        // (kuna truthycond, DIV-37) A comparison consumed as a boolean: after
        // the negate-token flip has settled which comparison actually prints,
        // `x != 0` renders as `x` and `x == 0` as `!x`.  The surviving operand
        // keeps CONDITION_CONTEXT (so `(a != 0) != 0` collapses fully); the
        // non-normalized comparison clears it (its operands are values).
        if self.context.is_set(modifiers::CONDITION_CONTEXT)
            && (tok.print1 == "==" || tok.print1 == "!=")
        {
            self.context.unset_mod(modifiers::CONDITION_CONTEXT);
            // (kuna outlang) truthycond (DIV-37) renders `x != 0` as `x`, which is
            // not a condition in a language without implicit bool conversion.
            if self.options.truthy_cond && self.lang().caps.implicit_bool_conditions {
                if let Some(other) = self.truthy_other_operand(fd, op) {
                    if tok.print1 == "==" {
                        self.push_op(&tokens::BOOLEAN_NOT, Some(op_key(op)));
                    }
                    self.context.push_mod();
                    self.context.set_mod(modifiers::CONDITION_CONTEXT);
                    self.push_vn_ir(fd, arch, other, op);
                    self.context.pop_mod();
                    return;
                }
            }
        }
        self.push_op(tok, Some(op_key(op)));
        // (kuna truthycond) `&&`/`||` operands are boolean contexts themselves
        // (this is semantics-preserving even in value position: both sides of
        // the equivalence yield the same 0/1).
        let boolean_operands = tok.print1 == "&&" || tok.print1 == "||";
        // C++ pushes in1 then in0 onto the LIFO nodepend; resolving directly,
        // push in0 then in1 so the operands print in0 <op> in1.
        for slot in 0..2 {
            if let Some(v) = fd.obank().get(op).and_then(|o| o.get_in(slot)) {
                if boolean_operands {
                    self.context.push_mod();
                    self.context.set_mod(modifiers::CONDITION_CONTEXT);
                    self.push_vn_ir(fd, arch, v, op);
                    self.context.pop_mod();
                } else {
                    self.push_vn_ir(fd, arch, v, op);
                }
            }
        }
    }

    /// (kuna truthycond, DIV-37) For an INT_EQUAL/INT_NOTEQUAL comparison with
    /// exactly one zero operand eligible for truthy rendering, return the OTHER
    /// operand.  A zero is eligible when it is a plain constant 0 (directly, or
    /// through one implied CAST — the casted null-pointer shape) whose
    /// read-facing type is not a float or an enum and which carries no
    /// equate/display override.
    fn truthy_other_operand(&self, fd: &Funcdata, op: OpId) -> Option<VarnodeId> {
        let o = fd.obank().get(op)?;
        if !matches!(o.code(), OpCode::CPUI_INT_EQUAL | OpCode::CPUI_INT_NOTEQUAL) {
            return None;
        }
        let (a, b) = (o.get_in(0)?, o.get_in(1)?);
        let za = self.is_truthy_zero(fd, a, op);
        let zb = self.is_truthy_zero(fd, b, op);
        match (za, zb) {
            (true, false) => Some(b),
            (false, true) => Some(a),
            _ => None,
        }
    }

    /// Whether `vn` is a zero constant eligible for truthy elision (see
    /// [`truthy_other_operand`](Self::truthy_other_operand)).
    fn is_truthy_zero(&self, fd: &Funcdata, vn: VarnodeId, op: OpId) -> bool {
        let eligible_const = |fd: &Funcdata, cvn: VarnodeId, read_op: OpId| -> bool {
            let v = match fd.vbank().get(cvn) {
                Some(v) => v,
                None => return false,
            };
            if !v.is_constant() || v.get_offset() != 0 {
                return false;
            }
            let ct = v.get_type_read_facing(read_op).clone();
            if ct.get_metatype() == crate::dtype::type_metatype::TYPE_FLOAT {
                return false;
            }
            if ct.is_enum_type() {
                return false;
            }
            // An equate symbol names this zero; keep the name visible.
            fd.vn_high_display_format(cvn) == 0
        };
        let v = match fd.vbank().get(vn) {
            Some(v) => v,
            None => return false,
        };
        if v.is_constant() {
            return eligible_const(fd, vn, op);
        }
        // Look through ONE implied CAST (the `(char *)0x0` shape when a real
        // CAST op was inserted rather than the constant being retyped).
        if v.is_implied() && v.is_written() {
            if let Some(def) = v.get_def() {
                if fd.obank().get(def).map(|o| o.code()) == Some(OpCode::CPUI_CAST) {
                    if let Some(inner) = fd.obank().get(def).and_then(|o| o.get_in(0)) {
                        return eligible_const(fd, inner, def);
                    }
                }
            }
        }
        false
    }

    /// C++ `PrintLanguage::opUnary` over the IR (printlanguage.cc:573).
    fn op_unary_ir(&mut self, fd: &Funcdata, arch: &Architecture, tok: &'static OpToken, op: OpId) {
        self.push_op(tok, Some(op_key(op)));
        if let Some(v0) = fd.obank().get(op).and_then(|o| o.get_in(0)) {
            self.push_vn_ir(fd, arch, v0, op);
        }
    }

    /// C++ `PrintC::checkPrintNegation` (printc.cc:2464): can the value `vn` be
    /// rendered with its *next* operator flipped (so the `!` is absorbed into a
    /// comparison) instead of emitting an explicit `!`?  True when `vn` is an
    /// implied, written value whose defining op-code has a boolean-flip complement
    /// (`get_booleanflip` != `CPUI_MAX`).
    fn check_print_negation(&self, fd: &Funcdata, vn: VarnodeId) -> bool {
        let v = match fd.vbank().get(vn) {
            Some(v) => v,
            None => return false,
        };
        if !v.is_implied() {
            return false;
        }
        if !v.is_written() {
            return false;
        }
        let def = match v.get_def() {
            Some(d) => d,
            None => return false,
        };
        let code = match fd.obank().get(def) {
            Some(o) => o.code(),
            None => return false,
        };
        let mut reorder = false;
        kuna_num::opcodes::get_booleanflip(code, &mut reorder) != OpCode::CPUI_MAX
    }

    /// C++ `PrintC::opBoolNegate` (printc.cc:834): print the `!x` boolean negate,
    /// but check for opportunities to flip the next operator instead.
    ///   - If we are negated by a previous BOOL_NEGATE (`negatetoken` is set),
    ///     consume that mod and print our input unmodified (double negation cancels).
    ///   - Else if the input's next operator can be flipped, don't print `!`; print
    ///     the input with `negatetoken` set so its comparison renders its complement.
    ///   - Otherwise print `!` followed by our input.
    fn op_bool_negate_ir(&mut self, fd: &Funcdata, arch: &Architecture, op: OpId) {
        let in0 = fd.obank().get(op).and_then(|o| o.get_in(0));
        // (kuna truthycond, DIV-37) Whether the operand may render truthy
        // depends on the arm: when the `!` is PRINTED (arm 3), the printed
        // operator re-booleanizes the value, so its operand is always a
        // boolean context.  When the `!` is ABSORBED (arm 2's negate-token
        // flip) or CANCELLED (arm 1's double negation), no boolean operator
        // remains in the render — eliding a zero-compare there would change
        // the VALUE (`v = !(x == 0)` must stay `v = x != 0`, never `v = x`) —
        // so those arms only propagate a bit that a genuine boolean consumer
        // (CBRANCH / `&&` / `||` / a printed `!`) already established.
        let entry_cond = self.context.is_set(modifiers::CONDITION_CONTEXT);
        if self.context.is_set(modifiers::NEGATETOKEN) {
            // Negated by a previous BOOL_NEGATE: consume the mod, print input as-is.
            self.context.unset_mod(modifiers::NEGATETOKEN);
            self.context.push_mod();
            if entry_cond {
                self.context.set_mod(modifiers::CONDITION_CONTEXT);
            }
            if let Some(vn) = in0 {
                self.push_vn_ir(fd, arch, vn, op);
            }
            self.context.pop_mod();
        } else if in0.map(|vn| self.check_print_negation(fd, vn)).unwrap_or(false) {
            // The next operator can be flipped: print the input with `negatetoken`
            // active (C++ `pushVn(in0, op, mods|negatetoken)`).
            self.context.push_mod();
            self.context.set_mod(modifiers::NEGATETOKEN);
            if entry_cond {
                self.context.set_mod(modifiers::CONDITION_CONTEXT);
            }
            if let Some(vn) = in0 {
                self.push_vn_ir(fd, arch, vn, op);
            }
            self.context.pop_mod();
        } else {
            // Otherwise print ourselves: `!` then the input.
            self.push_op(&tokens::BOOLEAN_NOT, Some(op_key(op)));
            self.context.push_mod();
            self.context.set_mod(modifiers::CONDITION_CONTEXT);
            if let Some(vn) = in0 {
                self.push_vn_ir(fd, arch, vn, op);
            }
            self.context.pop_mod();
        }
    }

    /// C++ `PrintC::opFunc` (printc.cc:444) — a functional `name(arg0,arg1,...)`
    /// form.  Pushes `function_call`, the (un-highlighted) operator name, an
    /// `(numInput-1)`-deep comma chain, then the operands.  The function name is
    /// the opcode's operator name (the full type/userop name resolution is the
    /// next layer).
    fn op_func_ir(&mut self, fd: &Funcdata, arch: &Architecture, op: OpId) {
        let opc = fd.obank().get(op).expect("op_func_ir: stale op").code();
        let name = func_operator_name(fd, op, opc);
        self.push_op(&tokens::FUNCTION_CALL, Some(op_key(op)));
        // The name is pushed as an *operator* token (C++ `optoken`, no_color).
        self.push_atom(&Atom::with_op(
            name,
            TagType::OpToken,
            crate::printlanguage::SyntaxHighlight::no_color,
            op_key(op),
        ));
        let nin = fd.obank().get(op).map(|o| o.num_input()).unwrap_or(0);
        if nin > 0 {
            // (numInput-1) comma operators glue the argument list.
            for _ in 0..(nin - 1) {
                self.push_op(&tokens::COMMA, Some(op_key(op)));
            }
            // C++ pushes args in reverse onto the LIFO queue; resolving directly
            // (the comma chain nests right), push in forward order.
            for i in 0..nin {
                if let Some(vn) = fd.obank().get(op).and_then(|o| o.get_in(i)) {
                    self.push_vn_ir(fd, arch, vn, op);
                }
            }
        } else {
            // Empty token for void (C++ blanktoken).
            self.push_atom(&Atom::syntax(
                "",
                TagType::BlankToken,
                crate::printlanguage::SyntaxHighlight::no_color,
            ));
        }
    }

    /// C++ `PrintC::opCallother` (printc.cc:693): render a CALLOTHER (user
    /// p-code op).  The op's in0 constant indexes a `UserPcodeOp` whose
    /// `getDisplay()` selects the form:
    ///   * `0` (functional): `name(arg1, arg2, ...)` over inputs 1..n-1, with the
    ///     name resolved through the userop table (`getOperatorName`).
    ///   * `annotation_assignment`: `in1 = in2`.
    ///   * `no_operator`: just `in1`.
    ///   * `display_string`: the output Varnode rendered as a quoted string
    ///     literal (the internal-string builtin), via `printCharacterConstant` on
    ///     the hash-keyed constant address in in1.
    fn op_callother_ir(&mut self, fd: &Funcdata, arch: &Architecture, op: OpId) {
        use crate::userop::userop_flags;
        let in0_off = match fd.obank().get(op).and_then(|o| o.get_in(0)) {
            Some(v) => fd.vbank().get(v).map(|vn| vn.get_offset()).unwrap_or(0),
            None => 0,
        };
        let display = arch
            .userops
            .get_op(in0_off as u32)
            .map(|u| u.get_display())
            .unwrap_or(0);
        let nin = fd.obank().get(op).map(|o| o.num_input()).unwrap_or(0);
        if display == 0 {
            // Functional syntax: for CALLOTHER the operator name resolves to the
            // userop's name (the base getOperatorName), or the generic
            // `CALLOTHER[index]` fallback.
            let nm = match arch.userops.get_op(in0_off as u32) {
                Some(u) => String::from_utf8_lossy(u.get_name()).into_owned(),
                None => format!("CALLOTHER[{:#x}]", in0_off),
            };
            self.push_op(&tokens::FUNCTION_CALL, Some(op_key(op)));
            self.push_atom(&Atom::with_op(
                nm,
                TagType::OpToken,
                crate::printlanguage::SyntaxHighlight::funcname_color,
                op_key(op),
            ));
            if nin > 1 {
                // (numInput-2) comma operators glue args 1..numInput-1.
                for _ in 1..(nin - 1) {
                    self.push_op(&tokens::COMMA, Some(op_key(op)));
                }
                for i in 1..nin {
                    if let Some(vn) = fd.obank().get(op).and_then(|o| o.get_in(i)) {
                        self.push_vn_ir(fd, arch, vn, op);
                    }
                }
            } else {
                // Empty token for void (C++ blanktoken).
                self.push_atom(&Atom::syntax(
                    "",
                    TagType::BlankToken,
                    crate::printlanguage::SyntaxHighlight::no_color,
                ));
            }
        } else if display == userop_flags::ANNOTATION_ASSIGNMENT {
            // C++ (printc.cc:713): pushOp(assignment); pushVn(in2); pushVn(in1).
            // The C++ pushes onto a LIFO that reverses, so in(1) (the volatile
            // annotation) ends up the LHS and in(2) (the value) the RHS:
            // `NVRAM[20] = 0`.  This direct-recursion engine renders in push
            // order (first push = leftmost), the inverse of the C++ LIFO, so the
            // annotation (in1) is pushed FIRST and the value (in2) second to keep
            // the same `annotation = value` shape (the same inversion op_store_ir
            // applies to its ptr/value pair).
            self.push_op(&tokens::ASSIGNMENT, Some(op_key(op)));
            if let Some(vn) = fd.obank().get(op).and_then(|o| o.get_in(1)) {
                self.push_vn_ir(fd, arch, vn, op);
            }
            if let Some(vn) = fd.obank().get(op).and_then(|o| o.get_in(2)) {
                self.push_vn_ir(fd, arch, vn, op);
            }
        } else if display == userop_flags::NO_OPERATOR {
            if let Some(vn) = fd.obank().get(op).and_then(|o| o.get_in(1)) {
                self.push_vn_ir(fd, arch, vn, op);
            }
        } else if display == userop_flags::DISPLAY_STRING {
            let outvn = fd.obank().get(op).and_then(|o| o.get_out());
            let mut s = String::new();
            let mut ok = false;
            if let Some(ovn) = outvn {
                let ct = fd.vbank().get(ovn).map(|v| v.get_type().clone());
                if let Some(ct) = ct {
                    if ct.get_metatype() == crate::dtype::type_metatype::TYPE_PTR {
                        if let Some(subct) = ct.get_ptr_to() {
                            // printCharacterConstant(str, op->getIn(1)->getAddr(), subct)
                            let in1addr = fd
                                .obank()
                                .get(op)
                                .and_then(|o| o.get_in(1))
                                .and_then(|v| fd.vbank().get(v).map(|vn| vn.get_addr().clone()));
                            if let Some(addr) = in1addr {
                                let mut chars_emitted: int4 = 0;
                                if self.print_character_constant(
                                    arch,
                                    &mut s,
                                    &addr,
                                    &subct,
                                    &mut chars_emitted,
                                ) {
                                    ok = true;
                                }
                            }
                        }
                    }
                }
            }
            if !ok {
                s.push_str("\"badstring\"");
            }
            if let Some(ovn) = outvn {
                self.push_atom(&Atom::with_op_vn(
                    s,
                    TagType::VarToken,
                    crate::printlanguage::SyntaxHighlight::const_color,
                    op_key(op),
                    vn_key(ovn),
                ));
            } else {
                self.push_atom(&Atom::with_op(
                    s,
                    TagType::VarToken,
                    crate::printlanguage::SyntaxHighlight::const_color,
                    op_key(op),
                ));
            }
        }
    }

    /// C++ `PrintC::opFloatInt2Float` (printc.cc:850): the integer→float
    /// conversion prints as a `(floatN)input` type-cast.  The input is the
    /// op's in0, unless that input is an implied `INT_ZEXT` (the C++
    /// `TypeOpFloatInt2Float::absorbZext`), in which case the ZEXT is absorbed
    /// and its source is the input — the zero-extension to the conversion's
    /// source width is implicit in the cast.  The cast's type is the output
    /// varnode's def-facing high type (`getOut()->getHighTypeDefFacing()`).
    /// With `option_nocasts` set the cast is suppressed and only the input
    /// prints.
    fn op_float_int2float_ir(&mut self, fd: &Funcdata, arch: &Architecture, op: OpId) {
        let in0 = fd.obank().get(op).and_then(|o| o.get_in(0));
        let vn0 = absorb_zext(fd, op)
            .and_then(|zext| fd.obank().get(zext).and_then(|o| o.get_in(0)))
            .or(in0);
        let cast_ty = if self.options.nocasts {
            None
        } else {
            fd.obank()
                .get(op)
                .and_then(|o| o.get_out())
                .and_then(|out| fd.vbank().get(out))
                .map(|v| v.get_type_def_facing().clone())
        };
        if let Some(ct) = &cast_ty {
            self.push_cast_open(ct, op);
        }
        if let Some(vn) = vn0 {
            self.push_vn_ir(fd, arch, vn, op);
        }
        if let Some(ct) = &cast_ty {
            self.push_cast_close(ct);
        }
    }

    /// C++ `PrintC::opTypeCast` (printc.cc:468): the C cast-notation `(type)operand`
    /// form shared by `opCast` / `opFloatFloat2Float` / `opFloatTrunc`
    /// (printc.hh:332-341, all `{ opTypeCast(op); }`).  The cast's target type is
    /// the op's **output** varnode's def-facing high type
    /// (`op->getOut()->getHighTypeDefFacing()`) — never a hardcoded or opcode-keyed
    /// type — and the operand is in0.
    ///
    /// With `option_nocasts` the cast is suppressed and only the operand prints
    /// (the underlying value flows through, parenthesized by precedence).
    ///
    /// The `isPointerToArray()` / [`check_address_of_cast`](Self::check_address_of_cast)
    /// arm renders a pointer-to-array cast as an address-of `&sym` (dropping the
    /// spurious `(T(*)[n])` cast) when the input is the address of an array Symbol of
    /// the matching size.  It never fires for the scalar `CPUI_CAST` /
    /// float-conversion casts this routes (whose output is a scalar `floatN`/`intN`,
    /// not a pointer-to-array).
    fn op_type_cast_ir(&mut self, fd: &Funcdata, arch: &Architecture, op: OpId) {
        self.op_type_cast_ir_with(fd, arch, op, false)
    }

    /// [`op_type_cast_ir`](Self::op_type_cast_ir), leaving the cast out when
    /// `implied` (kuna `castimplied`: C's own conversion performs it).
    fn op_type_cast_ir_with(&mut self, fd: &Funcdata, arch: &Architecture, op: OpId, implied: bool) {
        // C++ `opTypeCast` (printc.cc:468-484): when the target type is a
        // pointer-to-array, a CAST that is really an address-of an array Symbol
        // renders as `&sym` (dropping the spurious `(T(*)[n])` cast) instead of the
        // C cast form.  `checkAddressOfCast` decides this purely from the in/out
        // high types and the input's symbol/PTRSUB geometry — never opcode- or
        // name-keyed.
        let out_def = fd
            .obank()
            .get(op)
            .and_then(|o| o.get_out())
            .and_then(|out| fd.vbank().get(out))
            .map(|v| v.get_type_def_facing().clone());
        if out_def.as_ref().map(|t| t.is_pointer_to_array()).unwrap_or(false)
            && self.check_address_of_cast(fd, op)
        {
            let tok = self.lang_token(&tokens::ADDRESSOF);
            self.push_op(tok, Some(op_key(op)));
            if let Some(vn) = fd.obank().get(op).and_then(|o| o.get_in(0)) {
                self.push_vn_ir(fd, arch, vn, op);
            }
            return;
        }
        // (kuna `signedness`) A `(int)`/`(unsigned int)` whose operand is now
        // declared at that very type is a no-op token: dropping it leaves an
        // expression of exactly the same C type.
        let cast_ty = if self.options.nocasts || implied || self.sign_plan.drop_cast(fd, op) {
            None
        } else {
            out_def.and_then(|dest| self.callable_dialect_cast(fd, arch, op, dest))
        };
        if let Some(ct) = &cast_ty {
            self.push_cast_open(ct, op);
        }
        if let Some(vn) = fd.obank().get(op).and_then(|o| o.get_in(0)) {
            self.push_vn_ir(fd, arch, vn, op);
        }
        if let Some(ct) = &cast_ty {
            self.push_cast_close(ct);
        }
    }

    /// Project an operation-local callable conversion into this document's
    /// dialect: an already callable expression needs no wrapper; an integer
    /// address still needs the generic code-pointer conversion. Native C and
    /// ABI-bearing signatures retain the full typed CAST, unchanged in the IR.
    fn callable_dialect_cast(
        &self, fd: &Funcdata, arch: &Architecture, op: OpId,
        dest: crate::dtype::TypeRoot,
    ) -> Option<crate::dtype::TypeRoot> {
        use crate::dtype::{DatatypeKind, type_metatype};
        use std::rc::Rc;
        let Some(cast) = fd.obank().get(op) else { return Some(dest) };
        if cast.code() != OpCode::CPUI_CAST { return Some(dest); }
        let (Some(input), Some(output)) = (cast.get_in(0), cast.get_out()) else {
            return Some(dest);
        };
        let Some(consumer) = fd.lone_descend(output) else { return Some(dest) };
        let Some(code) = self.callable_dialect_code(fd, arch, consumer, output, &dest) else {
            return Some(dest);
        };
        let Some(source) = self.callable_operand_type(fd, arch, input, op, 16) else {
            return Some(dest);
        };
        if source.get_size() != dest.get_size() {
            return Some(dest);
        }
        if matches!(source.get_metatype(),
            type_metatype::TYPE_INT | type_metatype::TYPE_UINT | type_metatype::TYPE_UNKNOWN)
        {
            return Self::generic_callable_pointer(arch, &dest, code).or(Some(dest));
        }
        let generic_source = {
            let dest_view = dest.read();
            let source_view = source.read();
            let dest_def = dest_view.get(dest.id()).expect("retained destination type")
                .effective().expect("destination definition");
            let source_def = source_view.get(source.id()).expect("retained source type")
                .effective().expect("source definition");
            match (&dest_def.kind, &source_def.kind) {
                (DatatypeKind::Pointer {
                    spaceid: dest_space, truncate: dest_truncate, wordsize: dest_word, ..
                }, DatatypeKind::Pointer {
                    ptrto: source_base, spaceid: source_space,
                    truncate: source_truncate, wordsize: source_word,
                }) => {
                    source_word == dest_word
                        && match (source_space, dest_space) {
                            (None, None) => true,
                            (Some(a), Some(b)) => Rc::ptr_eq(a, b),
                            _ => false,
                        }
                        && source_truncate == dest_truncate
                        && self.rt_ctx.speller().is_generic_callable(
                            &self.rt_ctx, &source.related(*source_base).expect("pointer target"))
                }
                _ => false,
            }
        };
        if generic_source {
            None
        } else {
            Some(dest)
        }
    }

    /// Shared display policy for a CAST or a typed numeric pointer constant.
    /// Generic dialect spelling describes an inferred code address, not a
    /// supplied signature. Never hide an independently committed parameter,
    /// output, storage/model choice, override, or variadic ABI boundary.
    fn callable_dialect_code(
        &self, fd: &Funcdata, arch: &Architecture, call: OpId,
        target: VarnodeId, dest: &crate::dtype::TypeRoot,
    ) -> Option<crate::dtype::TypeRoot> {
        let op = fd.obank().get(call)?;
        if op.code() != OpCode::CPUI_CALLIND || op.get_in(0) != Some(target)
            || fd.lone_descend(target) != Some(call)
            || fd.vbank().get(target)?.get_size() != dest.get_size()
        {
            return None;
        }
        let ptrto = dest.get_ptr_to()?;
        let specs = fd.get_call_specs(fd.get_call_specs_index(call)?);
        let proto = specs.proto();
        if proto.logical_callable().is_some() {
            return None;
        }
        {
            let view = ptrto.read();
            let code = view.get(ptrto.id()).ok()?.effective().ok()?;
            match &code.kind {
                crate::dtype::DatatypeKind::Code { proto: None } => {}
                crate::dtype::DatatypeKind::Code { proto: Some(_) }
                    if specs.inferred_target_view() == Some(dest) => {}
                // Structural equality to a recovered signature is not evidence
                // of inference: cast insertion must have recorded this view.
                _ => return None,
            }
        }
        let inferred = |proto: &crate::fspec::FuncProto| {
            let committed = |param: &dyn crate::fspec::ProtoParameter| {
                param.is_type_locked() || param.is_name_locked() || param.is_size_type_locked()
            };
            proto.has_store() && !proto.is_override() && !proto.is_model_locked()
                && !proto.has_custom_storage() && !proto.is_input_locked()
                && !proto.is_dotdotdot() && proto.get_abi_first_vararg().is_none()
                && !committed(proto.get_output())
                && (0..proto.num_params()).all(|slot| {
                    proto.get_param(slot).is_some_and(|param| !committed(param))
                })
        };
        if !inferred(proto) { return None; }
        let code = arch.types().get_type_code().ok()?;
        self.rt_ctx.speller().is_generic_callable(&self.rt_ctx, &code).then_some(code)
    }

    /// An explicit numeric conversion must preserve pointer representation.
    /// A generic view cannot express custom address-space/truncation metadata.
    fn generic_callable_pointer(
        arch: &Architecture, dest: &crate::dtype::TypeRoot,
        code: crate::dtype::TypeRoot,
    ) -> Option<crate::dtype::TypeRoot> {
        let wordsize = {
            let view = dest.read();
            let def = view.get(dest.id()).ok()?.effective().ok()?;
            let crate::dtype::DatatypeKind::Pointer {
                spaceid: None, truncate: None, wordsize, ..
            } = &def.kind else { return None };
            *wordsize
        };
        arch.types().get_type_pointer(dest.get_size(), code, wordsize).ok()
    }

    /// A bounded proof of the type of the expression we actually print. In
    /// particular a LOAD inherits its printed pointer's element type, not the
    /// type guessed for the individual output Varnode. Unhandled expressions
    /// keep the full callable conversion.
    fn callable_operand_type(
        &self, fd: &Funcdata, arch: &Architecture, vn: VarnodeId,
        reader: OpId, depth: usize,
    ) -> Option<crate::dtype::TypeRoot> {
        use crate::dtype::type_metatype;
        if depth == 0 { return None; }
        let value = fd.vbank().get(vn)?;
        if value.is_annotation() { return None; }
        let raw = value.get_type_read_facing(reader);
        let scalar = |ty: &crate::dtype::TypeRoot| matches!(ty.get_metatype(),
            type_metatype::TYPE_INT | type_metatype::TYPE_UINT | type_metatype::TYPE_UNKNOWN);
        if value.is_constant() {
            return scalar(raw).then(|| raw.clone());
        }
        if !value.is_implied() {
            return declared_variable_type(fd, arch.decl_high_type, vn);
        }
        let def = value.get_def()?;
        let expr = fd.obank().get(def)?;
        let operand = |slot| self.callable_operand_type(fd, arch, expr.get_in(slot)?, def, depth - 1);
        match expr.code() {
            OpCode::CPUI_COPY => operand(0),
            OpCode::CPUI_CAST => {
                if self.options.nocasts || self.sign_plan.drop_cast(fd, def)
                    || self.implied_cast_drops(fd, arch, def, Some(reader))
                {
                    operand(0)
                } else {
                    Some(value.get_type_def_facing().clone())
                }
            }
            OpCode::CPUI_LOAD => {
                let pointer = operand(1)?;
                if pointer.get_metatype() != type_metatype::TYPE_PTR { return None; }
                let element = pointer.get_ptr_to()?;
                (element.get_size() == value.get_size()).then_some(element)
            }
            OpCode::CPUI_PTRADD => {
                let base = operand(0)?;
                if base.get_metatype() != type_metatype::TYPE_PTR
                    || base.get_size() != value.get_size()
                {
                    return None;
                }
                let stride = fd.vbank().get(expr.get_in(2)?)?;
                if !stride.is_constant()
                    || stride.get_offset().checked_mul(base.get_word_size()? as u64)?
                        != base.get_ptr_to()?.get_align_size() as u64
                    || !scalar(&operand(1)?)
                {
                    return None;
                }
                Some(base)
            }
            OpCode::CPUI_CALLOTHER if scalar(raw) => Some(raw.clone()),
            OpCode::CPUI_INT_SEXT | OpCode::CPUI_INT_ZEXT if scalar(raw) => {
                let input = operand(0)?;
                if !scalar(&input) { return None; }
                if let (Some(strat), Some((outtype, intype))) =
                    (cast_strategy_for(arch), self.sext_zext_facing_types(fd, def))
                {
                    let is_cast = if expr.code() == OpCode::CPUI_INT_SEXT {
                        strat.is_sext_cast(&outtype, &intype)
                    } else {
                        strat.is_zext_cast(&outtype, &intype)
                    };
                    if is_cast && (self.options.nocasts || self.sign_plan.drop_cast(fd, def)
                        || self.implied_cast_drops(fd, arch, def, Some(reader))
                        || (self.options.hide_exts
                            && self.is_extension_cast_implied(fd, &strat, def, Some(reader))))
                    {
                        return Some(input);
                    }
                }
                // The visible cast or the functional SEXT/ZEXT form both
                // produce the scalar width described by the operation.
                Some(raw.clone())
            }
            OpCode::CPUI_SUBPIECE if scalar(raw) => {
                let input = operand(0)?;
                if !scalar(&input) { return None; }
                if self.subpiece_cast_form(fd, arch, def).is_some()
                    && (self.options.nocasts || self.sign_plan.drop_cast(fd, def))
                {
                    Some(input)
                } else {
                    Some(raw.clone())
                }
            }
            OpCode::CPUI_INT_ADD | OpCode::CPUI_INT_SUB | OpCode::CPUI_INT_MULT
            | OpCode::CPUI_INT_DIV | OpCode::CPUI_INT_SDIV | OpCode::CPUI_INT_REM
            | OpCode::CPUI_INT_SREM | OpCode::CPUI_INT_AND | OpCode::CPUI_INT_OR
            | OpCode::CPUI_INT_XOR | OpCode::CPUI_INT_LEFT | OpCode::CPUI_INT_RIGHT
            | OpCode::CPUI_INT_SRIGHT | OpCode::CPUI_INT_NEGATE | OpCode::CPUI_INT_2COMP
            | OpCode::CPUI_PIECE
                if scalar(raw) =>
            {
                for slot in 0..expr.num_input() {
                    if !scalar(&operand(slot)?) { return None; }
                }
                Some(raw.clone())
            }
            _ => None,
        }
    }

    /// C++ `PrintC::checkAddressOfCast` (printc.cc:396-438): check that the output
    /// data-type is a pointer to an array and the input data-type is a pointer to
    /// the element type, and that the input variable represents a Symbol with an
    /// array data-type of the same total size.  When this holds the CAST is the
    /// implicit array-to-pointer decay of taking `&sym`, so the cast is dropped in
    /// favor of `&sym`.  Returns `true` if the CAST can be rendered as `&`.
    fn check_address_of_cast(&self, fd: &Funcdata, op: OpId) -> bool {
        use crate::dtype::type_metatype;
        let dt0 = match fd
            .obank()
            .get(op)
            .and_then(|o| o.get_out())
            .and_then(|out| fd.vbank().get(out))
            .map(|v| v.get_type_def_facing().clone())
        {
            Some(t) => t,
            None => return false,
        };
        let vnin = match fd.obank().get(op).and_then(|o| o.get_in(0)) {
            Some(v) => v,
            None => return false,
        };
        let dt1 = match fd.vbank().get(vnin).map(|v| v.get_type_read_facing(op).clone()) {
            Some(t) => t,
            None => return false,
        };
        if dt0.get_metatype() != type_metatype::TYPE_PTR
            || dt1.get_metatype() != type_metatype::TYPE_PTR
        {
            return false;
        }
        let base0 = match dt0.get_ptr_to() {
            Some(b) => b,
            None => return false,
        };
        let mut base1 = match dt1.get_ptr_to() {
            Some(b) => b,
            None => return false,
        };
        if base0.get_metatype() != type_metatype::TYPE_ARRAY {
            return false;
        }
        let array_size = base0.get_size();
        let mut base0 = match base0.get_array_base() {
            Some(b) => b,
            None => return false,
        };
        while let Some(t) = base0.get_typedef() {
            base0 = t;
        }
        while let Some(t) = base1.get_typedef() {
            base1 = t;
        }
        // C++ tests Datatype *pointer* identity; retained roots compare graph IDs
        // rather than allocation addresses. As a structural fallback (the
        // element types here are scalars whose
        // `compare` is implemented) a `compare == 0` also counts as equal; a compare
        // STUB (`Err`) is treated as not-equal (conservative: never collapses a cast
        // it cannot prove redundant).
        let base_eq = base0 == base1
            || matches!(base0.compare(&base1, 10), Ok(0));
        if !base_eq {
            return false;
        }
        // The kuna `getSymbolEntry()` stand-in is the high's bound Symbol — a
        // `kuna_name` with the mapped `kuna_symbol_type`; `getSymbolOffset()==-1`
        // is the whole-symbol match.
        let mut symbol_type: Option<crate::dtype::TypeRoot> = None;
        let vnin_high = fd.vbank().get(vnin).and_then(|v| v.get_high());
        let whole_sym = vnin_high.and_then(|h| fd.high_bank().get(h)).and_then(|h| {
            if h.kuna_symbol_offset() == -1 {
                h.kuna_symbol_type().cloned()
            } else {
                None
            }
        });
        if let Some(st) = whole_sym {
            symbol_type = Some(st);
        } else if fd.vbank().get(vnin).map(|v| v.is_written()).unwrap_or(false) {
            let ptrsub = fd.vbank().get(vnin).and_then(|v| v.get_def());
            if let Some(ptrsub) = ptrsub {
                if fd.obank().get(ptrsub).map(|o| o.code()) == Some(OpCode::CPUI_PTRSUB) {
                    let root_in0 = fd.obank().get(ptrsub).and_then(|o| o.get_in(0));
                    let root_type = root_in0
                        .and_then(|v| fd.vbank().get(v))
                        .map(|v| v.get_type_read_facing(ptrsub).clone());
                    if let Some(root_type) = root_type {
                        if root_type.get_metatype() == type_metatype::TYPE_PTR {
                            if let Some(root_ptr_to) = root_type.get_ptr_to() {
                                let off = fd
                                    .obank()
                                    .get(ptrsub)
                                    .and_then(|o| o.get_in(1))
                                    .and_then(|v| fd.vbank().get(v))
                                    .map(|v| v.get_offset())
                                    .unwrap_or(0) as int8;
                                // The virtual `getSubType` is `TypeSpacebase::getSubType`
                                // (type.cc:3411) for a spacebase root — it indexes the
                                // symbol-table Scope, which the bare `Datatype::get_sub_type`
                                // cannot reach (it routes to a `STUB(W6)` Err).  Route a
                                // spacebase through `Funcdata::spacebase_get_sub_type` (the
                                // ported `TypeSpacebase::getSubType`, funcdata_spacebase.rs),
                                // exactly as the spacebase-PTRSUB cast wave does; every other
                                // root keeps the pure `Datatype::get_sub_type`.
                                let resolved: Option<(crate::dtype::TypeRoot, int8)> =
                                    if root_ptr_to.get_metatype()
                                        == type_metatype::TYPE_SPACEBASE
                                    {
                                        fd.spacebase_get_sub_type(&root_ptr_to, off)
                                    } else {
                                        match root_ptr_to.get_sub_type(off) {
                                            Ok((sub, newoff)) => sub.map(|s| (s, newoff)),
                                            Err(_) => return false,
                                        }
                                    };
                                match resolved {
                                    Some((sub, newoff)) => {
                                        if newoff != 0 {
                                            return false;
                                        }
                                        symbol_type = Some(sub);
                                    }
                                    None => return false,
                                }
                            }
                        }
                    }
                }
            }
        }
        let symbol_type = match symbol_type {
            Some(s) => s,
            None => return false,
        };
        if symbol_type.get_metatype() != type_metatype::TYPE_ARRAY
            || symbol_type.get_size() != array_size
        {
            return false;
        }
        true
    }

    /// C++ `PrintC::opHiddenFunc` (printc.cc:494): the syntax represents `op`
    /// with a hidden (un-printed) one-input function — the input expression is
    /// printed without adornment, the [`tokens::HIDDEN`] token only guarding
    /// evaluation order.  Used by `opIntSext`/`opIntZext` to suppress an
    /// extension that is implied by integer promotion.
    fn op_hidden_func_ir(&mut self, fd: &Funcdata, arch: &Architecture, op: OpId) {
        self.push_op(&tokens::HIDDEN, Some(op_key(op)));
        if let Some(vn) = fd.obank().get(op).and_then(|o| o.get_in(0)) {
            self.push_vn_ir(fd, arch, vn, op);
        }
    }

    /// C++ `PrintC::opIntZext` (printc.cc:806): a zero-extension renders as an
    /// explicit `(uintN)`/`(intN)` cast when the cast strategy says the ZEXT is a
    /// cast (`isZextCast`), is hidden (`opHiddenFunc`) when the extension is
    /// implied by integer promotion in the surrounding expression
    /// (`option_hide_exts && isExtensionCastImplied`), and otherwise falls back to
    /// the functional `ZEXT(x)` form (`opFunc`).
    fn op_int_zext_ir(
        &mut self,
        fd: &Funcdata,
        arch: &Architecture,
        op: OpId,
        read_op: Option<OpId>,
    ) {
        let strat = match cast_strategy_for(arch) {
            Some(s) => s,
            // No type factory bound: degrade to the functional form, exactly as
            // the pre-cast-routing dispatch did.
            None => return self.op_func_ir(fd, arch, op),
        };
        let (outtype, intype) = match self.sext_zext_facing_types(fd, op) {
            Some(t) => t,
            None => return self.op_func_ir(fd, arch, op),
        };
        if strat.is_zext_cast(&outtype, &intype) {
            if self.options.hide_exts && self.is_extension_cast_implied(fd, &strat, op, read_op) {
                self.op_hidden_func_ir(fd, arch, op);
            } else if self.implied_cast_drops(fd, arch, op, read_op) {
                self.op_type_cast_ir_with(fd, arch, op, true);
            } else {
                self.op_type_cast_ir(fd, arch, op);
            }
        } else {
            self.op_func_ir(fd, arch, op);
        }
    }

    /// C++ `PrintC::opIntSext` (printc.cc:819): the sign-extension analogue of
    /// [`op_int_zext_ir`] — renders as an explicit `(intN)`/`(uintN)` cast
    /// (`isSextCast`), is hidden when implied, or falls back to `SEXT(x)`.
    fn op_int_sext_ir(
        &mut self,
        fd: &Funcdata,
        arch: &Architecture,
        op: OpId,
        read_op: Option<OpId>,
    ) {
        let strat = match cast_strategy_for(arch) {
            Some(s) => s,
            None => return self.op_func_ir(fd, arch, op),
        };
        let (outtype, intype) = match self.sext_zext_facing_types(fd, op) {
            Some(t) => t,
            None => return self.op_func_ir(fd, arch, op),
        };
        if self.out_lang == crate::kuna_lang::OutLang::C && intype.is_char_print() && !self.options.nocasts {
            let signed = arch.types().get_base_no_char(intype.get_size(), crate::dtype::type_metatype::TYPE_INT)
                .expect("numeric sign-extension source type");
            self.push_cast_open(&outtype, op);
            self.push_cast_open(&signed, op);
            if let Some(input) = fd.obank().get(op).and_then(|operation| operation.get_in(0)) {
                self.push_vn_ir(fd, arch, input, op);
            }
            self.push_cast_close(&signed);
            self.push_cast_close(&outtype);
            return;
        }
        if strat.is_sext_cast(&outtype, &intype) {
            if self.options.hide_exts && self.is_extension_cast_implied(fd, &strat, op, read_op) {
                self.op_hidden_func_ir(fd, arch, op);
            } else if self.implied_cast_drops(fd, arch, op, read_op) {
                self.op_type_cast_ir_with(fd, arch, op, true);
            } else {
                self.op_type_cast_ir(fd, arch, op);
            }
        } else {
            self.op_func_ir(fd, arch, op);
        }
    }

    /// C++ `PrintC::opSubpiece` (printc.cc:863-898).  A SUBPIECE marked for
    /// special printing (`doesSpecialPrinting`, set by `RuleSubRight` when the
    /// truncated input is a struct/union/array) extracts a composite member; it
    /// renders `symbol.field` via [`push_partial_symbol_ir`] (the symbol-mapped
    /// case, printc.cc:872-881) or `expr.field` via a struct `findTruncation`
    /// (printc.cc:882-888).  A non-special SUBPIECE falls to the cast/functional
    /// dispatch (the existing `is_subpiece_cast` → `opTypeCast` / `opFunc`).
    fn op_subpiece_ir(&mut self, fd: &Funcdata, arch: &Architecture, op: OpId) {
        use crate::dtype::type_metatype;
        if fd.obank().get(op).map(|o| o.does_special_printing()).unwrap_or(false) {
            let in0 = fd.obank().get(op).and_then(|o| o.get_in(0));
            if let Some(vn) = in0 {
                // The bare-Varnode read-facing type (the printc convention).
                let ct = fd.vbank().get(vn).map(|v| v.get_type_read_facing(op).clone());
                if let Some(ct) = ct {
                    if ct.is_piece_structured() {
                        let byte_off = subpiece_byte_offset_for_composite(fd, op);
                        let out_sz = fd
                            .obank()
                            .get(op)
                            .and_then(|o| o.get_out())
                            .and_then(|v| fd.vbank().get(v))
                            .map(|v| v.get_size())
                            .unwrap_or(0);
                        // The kuna_name binding stands in for C++ getSymbol().
                        let high = fd.vbank().get(vn).and_then(|v| v.get_high());
                        let is_explicit =
                            fd.vbank().get(vn).map(|v| v.is_explicit()).unwrap_or(false);
                        let sym = high.and_then(|high| self.emitted_high_symbol(fd, high));
                        if let (Some((name, sym_off, Some(sym_type))), true) = (sym, is_explicit) {
                            let mut boff = byte_off;
                            if sym_off > 0 {
                                boff += sym_off as int8;
                            }
                            let slot =
                                if sym_type.needs_resolution() { 1 } else { 0 };
                            let smt = sym_type.get_metatype();
                            if (smt == type_metatype::TYPE_STRUCT
                                || smt == type_metatype::TYPE_UNION)
                                && self.push_partial_symbol_ir(
                                    fd,
                                    arch,
                                    &name,
                                    sym_type.clone(),
                                    boff,
                                    out_sz,
                                    vn,
                                    op,
                                    slot,
                                    true,
                                )
                            {
                                return;
                            }
                            // Fall through to the cast/functional dispatch below.
                        } else {
                            // A struct findTruncation hit at offset 0 renders as
                            // an object_member access.
                            if ct.get_metatype() == type_metatype::TYPE_STRUCT {
                                if let Ok(Some((idx, off2))) =
                                    ct.find_truncation(byte_off, out_sz, op, 1)
                                {
                                    if off2 == 0 {
                                        let field = {
                                            let view = ct.read();
                                            view.get_field(ct.id(), idx).expect("retained field")
                                                .map(|f| (f.name.clone(), f.offset))
                                        };
                                        if let Some((fname, fident)) = field {
                                            self.push_op(
                                                &tokens::OBJECT_MEMBER,
                                                Some(op_key(op)),
                                            );
                                            self.push_vn_ir(fd, arch, vn, op);
                                            self.push_atom(&Atom::field(
                                                fname,
                                                TagType::FieldToken,
                                                crate::printlanguage::SyntaxHighlight::no_color,
                                                ct.clone(),
                                                fident,
                                                op_key(op),
                                            ));
                                            return;
                                        }
                                    }
                                }
                            }
                        }
                        // Fall thru to functional/cast printing (printc.cc:889).
                    }
                }
            }
        }
        // Non-special-print SUBPIECE (printc.cc:892-897): isSubpieceCast decides
        // between opTypeCast and opFunc.
        // The cast arm was previously gated out because it tripped a spurious
        // `(int4)ptr` cast on condconstsub (a free SUBPIECE the call-return stub
        // had left in the IR).  That IR bug is now fixed (the call-return-recovery
        // + ActionDeindirect wave landed: condconstsub's `process` returns the
        // recovered call output, no spurious SUBPIECE), so the faithful dispatch
        // is restored.
        use crate::kuna_boolbyte::TruncationForm;
        match self.subpiece_cast_form(fd, arch, op) {
            Some(TruncationForm::CastThroughByte) => self.op_bool_truncation_ir(fd, arch, op),
            Some(_) => self.op_type_cast_ir(fd, arch, op),
            None => self.op_func_ir(fd, arch, op),
        }
    }

    /// (kuna `boolbyte`) `(bool)(unsigned char)x`: a truncation into a `bool`
    /// whose operand may carry bits above the destination, which a bare
    /// `(bool)x` would test.
    fn op_bool_truncation_ir(&mut self, fd: &Funcdata, arch: &Architecture, op: OpId) {
        let out = fd.obank().get(op).and_then(|o| o.get_out()).and_then(|v| fd.vbank().get(v));
        let out_ty = out.map(|v| v.get_type_def_facing().clone());
        let byte_ty = out.and_then(|v| {
            arch.types().get_base(v.get_size(), crate::dtype::type_metatype::TYPE_UINT).ok()
        });
        let (out_ty, byte_ty) = match (out_ty, byte_ty) {
            (Some(o), Some(b)) if !self.options.nocasts => (o, b),
            _ => return self.op_type_cast_ir(fd, arch, op),
        };
        self.push_cast_open(&out_ty, op);
        self.push_cast_open(&byte_ty, op);
        if let Some(vn) = fd.obank().get(op).and_then(|o| o.get_in(0)) {
            self.push_vn_ir(fd, arch, vn, op);
        }
        self.push_cast_close(&byte_ty);
        self.push_cast_close(&out_ty);
    }

    /// C++ `castStrategy->isSubpieceCast(out->getHighTypeDefFacing(),
    /// in0->getHighTypeReadFacing(op), (uint4)in1->getOffset())` (printc.cc:892):
    /// `None` prints the functional form, `Some` a cast.
    fn subpiece_cast_form(
        &self,
        fd: &Funcdata,
        arch: &Architecture,
        op: OpId,
    ) -> Option<crate::kuna_boolbyte::TruncationForm> {
        use crate::kuna_boolbyte::TruncationForm;
        let strat = cast_strategy_for(arch)?;
        let outvn = fd.obank().get(op).and_then(|o| o.get_out())?;
        let invn = fd.obank().get(op).and_then(|o| o.get_in(0))?;
        let offset = fd
            .obank()
            .get(op)
            .and_then(|o| o.get_in(1))
            .and_then(|v| fd.vbank().get(v))
            .map(|v| v.get_offset())
            .unwrap_or(0) as uint4;
        let outv = fd.vbank().get(outvn)?;
        let outtype = outv.get_type_def_facing().clone();
        let out_size = outv.get_size();
        // intype = in0->getHighTypeReadFacing(op)  (printc.cc:892).  For a union
        // (or other needs-resolution composite) the C++ high read-facing accessor
        // resolves the field for this read edge through the per-function union
        // cache (`Datatype::findResolve`, type.cc:590).  The bare-Varnode
        // `getTypeReadFacing` stub leaves the unresolved union in place, so a
        // narrowing SUBPIECE of a resolved scalar union member (e.g. `int8 mylong`
        // → int4) would mis-dispatch to the functional `SUB84(...)` arm instead of
        // the `(int4)` cast.  Apply the same immutable cache consult the high
        // accessor would: see [`Funcdata::find_resolve_facing`].
        let inv = fd.vbank().get(invn)?;
        let intype = inv.get_type_read_facing(op).clone();
        let intype = if intype.needs_resolution() {
            let slot = fd.obank().get(op).map(|o| o.get_slot(invn)).unwrap_or(-1);
            fd.find_resolve_facing(&intype, op, slot)
        } else {
            intype
        };
        // (kuna `boolbyte`) `isSubpieceCast` never saw a TYPE_BOOL destination
        // upstream, so a truncation into one falls to the functional arm and
        // prints the raw `SUB41(x,0)` intrinsic -- an undeclared identifier, the
        // class `subright` exists to keep out of the output.
        match crate::kuna_boolbyte::truncation_form(
            arch.bool_byte,
            &outtype,
            &intype,
            offset,
            out_size,
            || crate::kuna_boolbyte::value_mask(fd, invn),
        ) {
            TruncationForm::Upstream => {}
            form => return Some(form),
        }
        strat.is_subpiece_cast(&outtype, &intype, offset).then_some(TruncationForm::Cast)
    }

    /// The `(out->getHighTypeDefFacing(), in0->getHighTypeReadFacing(op))` type
    /// pair the C++ `opIntSext`/`opIntZext` feed to `isSextCast`/`isZextCast`
    /// (printc.cc:809/822).  Resolved through the bare-Varnode facing accessors
    /// (the W10 printc convention: by print-time the merged HighVariable type is
    /// already pinned onto the Varnode, so `getTypeDefFacing`/`getTypeReadFacing`
    /// equal the high-facing types the C++ reads). // STUB(W8 union findResolve)
    fn sext_zext_facing_types(
        &self,
        fd: &Funcdata,
        op: OpId,
    ) -> Option<(crate::dtype::TypeRoot, crate::dtype::TypeRoot)> {
        let outvn = fd.obank().get(op)?.get_out()?;
        let invn = fd.obank().get(op)?.get_in(0)?;
        let outtype = fd.vbank().get(outvn)?.get_type_def_facing().clone();
        let intype = fd.vbank().get(invn)?.get_type_read_facing(op).clone();
        Some((outtype, intype))
    }

    /// C++ `castStrategy->isExtensionCastImplied(op, readOp)` (cast.cc:249) bridged
    /// through an immutable [`PrintCastContext`] over `&Funcdata`.  The predicate
    /// reads only IR shape + read-facing types (no mutation), so it runs on the
    /// `&Funcdata` print path.
    fn is_extension_cast_implied(
        &self,
        fd: &Funcdata,
        strat: &CastStrategyC,
        op: OpId,
        read_op: Option<OpId>,
    ) -> bool {
        let ctx = PrintCastContext::new(fd);
        let op_ref = ctx.op_ref(op);
        let read_ref = read_op.map(|r| ctx.op_ref(r));
        strat.is_extension_cast_implied(&ctx, op_ref, read_ref)
    }

    /// (kuna `castimplied`) Does C's own conversion already perform the cast `op`
    /// prints where `read_op` reads it?  See [`crate::kuna_castimplied`].
    fn implied_cast_drops(
        &self,
        fd: &Funcdata,
        arch: &Architecture,
        op: OpId,
        read_op: Option<OpId>,
    ) -> bool {
        if self.cast_implied.arm_dropped(op) {
            return true;
        }
        if !self.cast_implied.is_enabled() {
            return false;
        }
        let Some(strat) = cast_strategy_for(arch) else { return false };
        let view = ImpliedView { pc: self, fd, arch, strat };
        self.cast_implied.drops(&view, fd, op, read_op)
    }

    /// (kuna `castternary`) The casts to leave out of the arms of the conditional
    /// `iteregion` prints for `m`.  See [`crate::kuna_castternary`].
    fn conditional_arm_drops(
        &self,
        fd: &Funcdata,
        arch: &Architecture,
        m: &crate::p8_structure::kuna_iteregion::IteAssignMatch,
    ) -> Vec<OpId> {
        if !self.cast_implied.arms_enabled() || !self.lang().caps.ternary {
            return Vec::new();
        }
        let Some(strat) = cast_strategy_for(arch) else { return Vec::new() };
        let view = ImpliedView { pc: self, fd, arch, strat };
        crate::kuna_castternary::arm_drops(&self.cast_implied, &view, fd, [m.true_op, m.else_op], m.dest)
    }

    /// C++ `PrintC::pushType` (printc.cc:1540) for a base type, reduced to the
    /// cast use: emit the type name as a single type-token operand (the
    /// `(type)` half of a [`tokens::TYPECAST`]).  The full `pushTypeStart` /
    /// `buildTypeStack` declarator algorithm (pointer/array casts) is the next
    /// layer; this renders the base-type front of [`declarator_parts`], which
    /// is the only form the int→float cast produces (a scalar `floatN`).
    /// Open a conversion around an operand that is about to be pushed.
    ///
    /// (kuna outlang) C brackets the operand -- `(T)x`, a `Presurround` token
    /// whose type is pushed BEFORE the operand. Rust suffixes it -- `x as T`, a
    /// binary token whose type is the RIGHT operand and so must be pushed
    /// AFTER. Every cast site therefore brackets its operand push with
    /// `push_cast_open` / `push_cast_close` rather than emitting the type inline.
    /// Map a token from the opcode table onto the active language's spelling and
    /// precedence (`LangProfile::map_token`).
    fn lang_token(&self, tok: &'static OpToken) -> &'static OpToken {
        (self.lang().map_token)(tok)
    }

    /// Push the operator for a field reached THROUGH a pointer.
    ///
    /// (kuna outlang) C has a dedicated token for it (`p->f`). Rust raw pointers
    /// have no auto-deref, so the same access is `(*p).f` -- the member token
    /// over an explicit dereference of the operand that follows. The
    /// parenthesizer supplies the parens on its own: `*` binds looser than `.`,
    /// so the deref lands in a group.
    fn push_member_through_pointer(&mut self, key: Option<crate::printlanguage::IrKey>) {
        match self.lang().forms.member {
            crate::kuna_lang::MemberForm::CArrow => {
                self.push_op(&tokens::POINTER_MEMBER, key);
            }
            crate::kuna_lang::MemberForm::RustDerefParen => {
                self.push_op(&tokens::OBJECT_MEMBER, key);
                self.push_op(&tokens::DEREFERENCE, key);
            }
        }
    }

    fn push_cast_open(&mut self, ct: &crate::dtype::TypeRoot, op: OpId) {
        match self.lang().forms.cast {
            crate::kuna_lang::CastForm::PrefixParen => {
                self.push_op(&tokens::TYPECAST, Some(op_key(op)));
                self.push_cast_type(ct);
            }
            crate::kuna_lang::CastForm::PostfixAs => {
                let tok = self.lang().tok_typecast;
                self.push_op(tok, Some(op_key(op)));
            }
        }
    }

    /// Close a conversion opened by [`push_cast_open`], after the operand.
    fn push_cast_close(&mut self, ct: &crate::dtype::TypeRoot) {
        if self.lang().forms.cast == crate::kuna_lang::CastForm::PostfixAs {
            self.push_cast_type(ct);
        }
    }

    fn push_cast_type(&mut self, ct: &crate::dtype::TypeRoot) {
        let (mut front, back) = self.declarator_text(ct);
        front.append(back);
        let (name, spans) = front.into_parts();
        let mut atom = Atom::syntax(
            name,
            TagType::TypeToken,
            crate::printlanguage::SyntaxHighlight::type_color,
        );
        if let Some(spans) = spans {
            atom.data = crate::printlanguage::AtomData::TypeSpans(spans);
        }
        self.push_atom(&atom);
    }

    pub(crate) fn declarator_text(&self, ct: &crate::dtype::TypeRoot) -> (TypeText, TypeText) {
        self.rt_ctx.speller().declarator_annotated(&self.rt_ctx, ct, self.is_host_surface())
    }

    pub(crate) fn declaration_type_text(&self, ct: &crate::dtype::TypeRoot) -> (TypeText, TypeText) {
        self.rt_ctx.speller().type_name_annotated(&self.rt_ctx, ct, self.is_host_surface())
    }

    pub(crate) fn emit_type_text(&mut self, text: TypeText, markup: &MarkupRef, origin: TypeTextOrigin) {
        self.emit.emit_type_text(text, markup, origin);
    }

    /// Recover logical argument order from the ABI's authoritative source roles.
    /// The map describes the declaration prefix; recovered variadic operands
    /// beyond it keep their physical order. A broken prefix is an IR invariant
    /// failure, not permission to call a semantic signature with physical slots.
    fn logical_call_arguments(
        fd: &Funcdata,
        op: OpId,
        proto: &crate::fspec::FuncProto,
    ) -> Option<Vec<(int4, bool)>> {
        use crate::fspec::AbiInputOrigin;
        let code = proto.logical_callable().expect("logical callable source");
        let view = code.read();
        let declaration = view.get_code_prototype(code.id())
            .expect("retained callable").expect("logical callable declaration");
        let origins = proto.callable_input_origins();
        let call = fd.obank().get(op).expect("live call");
        assert!(proto.has_store(), "logical callable must retain its ABI storage");
        // The retained ABI storage describes exactly the declaration prefix.
        // Recovered variadic operands belong to the CALL, not this storage.
        assert_eq!(origins.len(), proto.num_params() as usize, "callable ABI origin prefix");
        assert!(call.num_input() > origins.len() as int4, "callable ABI prefix is incomplete");
        assert!(
            declaration.variadic || !declaration.input_closed
                || call.num_input() == origins.len() as int4 + 1,
            "closed nonvariadic callable has extra operands",
        );
        for slot in 1..call.num_input() {
            assert!(call.get_in(slot).is_some(), "callable operand is missing");
        }
        // Ordinary scalar signatures already have logical order and need no
        // scratch argument list. Still validate the retained map before using
        // the physical-order emission loop.
        if origins.len() == declaration.inputs.len()
            && !proto.get_output().is_indirect_storage()
            && origins.iter().enumerate().all(|(physical, role)| {
                *role == AbiInputOrigin::Declared(physical)
                    && !proto.get_param(physical as int4).expect("callable ABI parameter")
                        .is_indirect_storage()
            })
        {
            return None;
        }
        let mut arguments = vec![(-1, false); declaration.inputs.len()];
        let mut hidden = false;
        for (physical, origin) in origins.iter().enumerate() {
            let slot = physical as int4 + 1;
            match *origin {
                AbiInputOrigin::Declared(index) => {
                    let argument = arguments.get_mut(index).expect("callable declared input index");
                    assert_eq!(argument.0, -1, "duplicate callable declared input");
                    let param = proto.get_param(physical as int4).expect("callable ABI parameter");
                    *argument = (slot, param.is_indirect_storage());
                    if argument.1 {
                        let pointer = param.get_type().expect("indirect parameter type");
                        assert_eq!(pointer.get_metatype(), type_metatype::TYPE_PTR,
                            "indirect parameter must carry a pointer");
                    }
                }
                AbiInputOrigin::HiddenResult => {
                    assert!(!hidden, "duplicate callable hidden result");
                    hidden = true;
                }
            }
        }
        assert!(arguments.iter().all(|(slot, _)| *slot > 0), "callable declared input is missing");
        assert_eq!(hidden, proto.get_output().is_indirect_storage(), "callable result transport");
        for slot in origins.len() as int4 + 1..call.num_input() {
            arguments.push((slot, false));
        }
        Some(arguments)
    }

    /// A hidden result address and its physical pointer type. The source role,
    /// not an assumed first/last parameter position, identifies the storage.
    fn call_result_storage<'a>(
        fd: &Funcdata,
        op: OpId,
        proto: &'a crate::fspec::FuncProto,
    ) -> Option<(VarnodeId, &'a crate::dtype::TypeRoot)> {
        if !proto.get_output().is_indirect_storage() {
            return None;
        }
        let physical = proto.callable_input_origins().iter()
            .position(|role| *role == crate::fspec::AbiInputOrigin::HiddenResult)
            .expect("indirect callable result has a source role") as int4;
        let pointer = proto.get_param(physical).expect("hidden result parameter")
            .get_type().expect("hidden result pointer type");
        assert_eq!(pointer.get_metatype(), type_metatype::TYPE_PTR, "hidden result pointer");
        let address = fd.obank().get(op).expect("live call")
            .get_in(physical + 1).expect("hidden result operand");
        Some((address, pointer))
    }

    fn prepare_call_result_temps(&mut self, fd: &Funcdata, arch: &Architecture) {
        if self.out_lang != crate::kuna_lang::OutLang::C {
            return;
        }
        if !(0..fd.num_calls()).any(|index| {
            let proto = fd.get_call_specs(index).proto();
            proto.logical_callable().is_some() && proto.get_output().is_indirect_storage()
        }) {
            return;
        }
        let proto = fd.get_func_proto();
        let num_params = if proto.has_store() { proto.num_params() } else { 0 };
        let mut occupied = declaration_occupied_names(fd, (0..num_params).filter_map(|slot| {
            let param = proto.get_param(slot)?;
            Some(crate::database::kuna_materialized_param_name(
                arch.name_style_angr, slot, param.get_name(),
            ))
        }));
        occupied.extend(fd.high_bank().iter()
            .filter_map(|(_, high)| high.kuna_name().map(str::to_string)));
        occupied.extend(self.local_name_overrides.values().cloned());
        // C typedefs share the ordinary identifier namespace. A capture must
        // not shadow a type used by a later declaration or cast in this body.
        for ty in crate::kuna_structdefs::referenced_types(fd) {
            let view = ty.read();
            let node = view.get(ty.id()).expect("retained declaration type");
            occupied.push(sanitize_type_name(node.get_name()).into_owned());
        }
        let mut names = crate::kuna_dedupvardecls::DeclNameUniquifier::new(
            std::iter::empty::<&str>(), occupied.iter().map(String::as_str),
        );
        for index in 0..fd.num_calls() {
            let call = fd.get_call_specs(index);
            let proto = call.proto();
            if proto.logical_callable().is_none() || !proto.get_output().is_indirect_storage() {
                continue;
            }
            let op = call.get_op();
            let time = fd.obank().get(op).expect("live call spec").get_time();
            self.call_result_temps.insert(op, names.unique(&format!("kuna_retptr_{time}")));
        }
    }

    /// Synthetic captures have no IR Symbol: emit ordinary tokens, not a
    /// ClangVariableDecl with a fabricated symref. Their opref still names the
    /// real call, while actual address/argument tokens retain their varrefs.
    fn emit_call_result_decls(&mut self, fd: &Funcdata, arch: &Architecture) {
        self.prepare_call_result_temps(fd, arch);
        let mut emitted = false;
        for index in 0..fd.num_calls() {
            let call = fd.get_call_specs(index);
            let op = call.get_op();
            let Some(name) = self.call_result_temps.get(&op) else { continue };
            if fd.obank().get(op).expect("live call spec").is_dead() {
                continue;
            }
            let (_, pointer) = Self::call_result_storage(fd, op, call.proto())
                .expect("planned hidden result capture");
            let (front, back) = self.declarator_text(pointer);
            let want_space = !front.text.ends_with('*');
            let markup = self.op_markup(fd, op);
            self.emit.tag_line();
            self.emit.emit_type_text(front, &markup, TypeTextOrigin::Type);
            if want_space {
                self.emit.spaces(1, 0);
            }
            self.emit.tag_variable(name, SyntaxHighlight::VarColor, &markup);
            self.emit.emit_type_text(back, &markup, TypeTextOrigin::Syntax);
            self.emit.print(";", SyntaxHighlight::NoColor);
            emitted = true;
        }
        if emitted {
            self.emit.tag_line();
        }
    }

    fn push_call_result_temp(&mut self, name: &str, op: OpId) {
        self.push_atom(&Atom::with_op(
            name.to_string(), TagType::VarToken,
            crate::printlanguage::SyntaxHighlight::var_color, op_key(op),
        ));
    }

    /// A physical pointer may print through a scalar or void-pointer High.
    /// Reintroduce the actual ABI pointer type before dereferencing/capturing it,
    /// without changing that High's declaration or any IR datatype.
    fn push_call_pointer(
        &mut self, fd: &Funcdata, arch: &Architecture, vn: VarnodeId, op: OpId,
        pointer: &crate::dtype::TypeRoot, dereference: bool,
    ) {
        let printed = self.callable_operand_type(fd, arch, vn, op, 16).or_else(|| {
            let value = fd.vbank().get(vn)?;
            if !value.is_implied() { return None; }
            let producer = value.get_def()?;
            let proto = fd.get_call_specs(fd.get_call_specs_index(producer)?).proto();
            if !proto.has_store() { return None; }
            if let Some(code) = proto.logical_callable() {
                if proto.get_output().is_indirect_storage() {
                    // The sequenced call below deliberately yields this physical
                    // result, not the aggregate assigned to hidden storage.
                    Some(value.get_type_def_facing().clone())
                } else {
                    let view = code.read();
                    let declaration = view.get_code_prototype(code.id()).ok()??;
                    code.related(declaration.output).ok()
                }
            } else {
                proto.get_output().get_type().cloned()
            }
        });
        let cast = printed.as_ref().map(|ty|
            ty.get_metatype() != type_metatype::TYPE_PTR
                || ty.get_ptr_to() != pointer.get_ptr_to()
        ).unwrap_or(true);
        let mut mods = self.context.mods()
            & !(modifiers::PRINT_LOAD_VALUE | modifiers::PRINT_STORE_VALUE);
        if dereference {
            if !cast && self.check_array_deref(fd, vn)
                && !self.context.is_set(modifiers::FORCE_POINTER)
            {
                mods |= modifiers::PRINT_LOAD_VALUE;
            } else {
                self.push_op(&tokens::DEREFERENCE, Some(op_key(op)));
            }
        }
        if cast {
            self.push_cast_open(pointer, op);
        }
        self.push_vn_ir_m(fd, arch, vn, op, mods);
        if cast {
            self.push_cast_close(pointer);
        }
    }

    /// Emit C's semantic call when a declaration and its ABI source roles are
    /// retained. Rust's unsupported callable surface remains the existing opaque
    /// physical form rather than claiming a native Rust ABI.
    fn op_call_ir(&mut self, fd: &Funcdata, arch: &Architecture, op: OpId) {
        if self.out_lang == crate::kuna_lang::OutLang::C
            && crate::kuna_callabletransport::raw_boundary(fd, op).unwrap_or(true) {
            self.push_atom(&Atom::with_op(
                crate::kuna_callabletransport::raw_boundary_text(fd, op), TagType::OpToken,
                crate::printlanguage::SyntaxHighlight::no_color, op_key(op)));
            return;
        }
        let call = fd.obank().get(op).expect("op_call_ir: stale op");
        let opc = call.code();
        let nin = call.num_input();
        // Execution adapters consume the real SSA slots, not the retained
        // source-role prefix (which intentionally excludes physical-only state).
        let proto = (self.out_lang == crate::kuna_lang::OutLang::C)
            .then(|| fd.get_call_specs_index(op)).flatten()
            .filter(|index| {
                let call = fd.get_call_specs(*index);
                call.execution_callable().is_none() || fd.generated_execution_contracts().get(&op)
                    .is_some_and(|contract| contract.effects.hidden_result.is_some()
                        && call.execution_callable() == Some(&contract.family_code)
                        && call.proto().logical_callable() == Some(&contract.family_code))
            })
            .map(|index| fd.get_call_specs(index).proto())
            .filter(|proto| proto.logical_callable().is_some());
        let arguments = proto.and_then(|proto| Self::logical_call_arguments(fd, op, proto));
        let result = proto.and_then(|proto| Self::call_result_storage(fd, op, proto));
        let capture = result.map(|(address, pointer)| {
            if !self.call_result_temps.contains_key(&op) {
                self.prepare_call_result_temps(fd, arch);
            }
            let name = self.call_result_temps.get(&op).expect("hidden result capture").clone();
            // The comma sequence is explicitly grouped: when this call is an
            // implied argument, its commas must not become extra call arguments.
            self.push_op(&tokens::EXPRESSION_GROUP, Some(op_key(op)));
            self.push_op(&tokens::COMMA, Some(op_key(op)));
            if call.get_out().is_some() {
                self.push_op(&tokens::COMMA, Some(op_key(op)));
            }
            self.push_op(&tokens::ASSIGNMENT, Some(op_key(op)));
            self.push_call_result_temp(&name, op);
            self.push_call_pointer(fd, arch, address, op, pointer, false);
            self.push_op(&tokens::ASSIGNMENT, Some(op_key(op)));
            self.push_op(&tokens::DEREFERENCE, Some(op_key(op)));
            self.push_call_result_temp(&name, op);
            name
        });
        self.push_op(&tokens::FUNCTION_CALL, Some(op_key(op)));
        if opc == OpCode::CPUI_CALLIND {
            self.push_op(&tokens::DEREFERENCE, Some(op_key(op)));
            if let Some(callee) = call.get_in(0) {
                self.push_vn_ir(fd, arch, callee, op);
            }
        } else {
            let name = self.call_callee_name(fd, op);
            self.push_atom(&Atom::with_op(
                name, TagType::FuncToken,
                crate::printlanguage::SyntaxHighlight::funcname_color, op_key(op),
            ));
        }
        let count = arguments.as_ref().map(|args| args.len() as int4).unwrap_or(nin - 1);
        if count > 0 {
            for _ in 0..(count - 1) {
                self.push_op(&tokens::COMMA, Some(op_key(op)));
            }
            if let Some(arguments) = arguments {
                let proto = proto.expect("logical arguments");
                for (slot, indirect) in arguments {
                    let vn = call.get_in(slot).expect("validated callable operand");
                    if indirect {
                        let pointer = proto.get_param(slot - 1).expect("indirect parameter")
                            .get_type().expect("indirect parameter type");
                        self.push_call_pointer(fd, arch, vn, op, pointer, true);
                    } else {
                        self.push_vn_ir(fd, arch, vn, op);
                    }
                }
            } else {
                for slot in 1..nin {
                    if let Some(vn) = call.get_in(slot) {
                        self.push_vn_ir(fd, arch, vn, op);
                    }
                }
            }
        } else {
            self.push_atom(&Atom::syntax(
                "", TagType::BlankToken,
                crate::printlanguage::SyntaxHighlight::no_color,
            ));
        }
        if let (Some(name), Some(out)) = (capture, call.get_out()) {
            // The p-code result is still the ABI pointer, not the aggregate just
            // assigned through it. This also preserves implied return-pointer
            // consumers and keeps the ordinary statement assignment unchanged.
            let physical = fd.vbank().get(out).expect("call output").get_type_def_facing();
            let cast = physical.get_metatype() != type_metatype::TYPE_PTR;
            if cast {
                self.push_cast_open(physical, op);
            }
            self.push_call_result_temp(&name, op);
            if cast {
                self.push_cast_close(physical);
            }
        }
    }

    /// Recover the printed callee name for a direct CALL (C++ `PrintC::opCall`'s
    /// fspec-name branch): the registered call-spec name, else
    /// `genericFunctionName(entryaddress)` (`func_<addr>` / `sub_<addr>`).
    ///
    /// The name lives in the \e fspec annotation in0; the `FuncCallSpecs` carries
    /// it (looked up by op).  Falls back to the in0 varnode's printed address if no
    /// call spec is registered (an internal-only op — should not occur on the live
    /// CALL path).
    fn call_callee_name(&self, fd: &Funcdata, op: OpId) -> String {
        if let Some(idx) = fd.get_call_specs_index(op) {
            if self.callable_transport_valid {
                if let Some(adapter) = crate::kuna_callabletransport::direct_adapter_name(fd, idx) {
                    return adapter;
                }
            }
            let fc = fd.get_call_specs(idx);
            let nm = fc.get_name();
            if !nm.is_empty() {
                return self.emitted_function_name(fd, nm, fc.get_entry_address(), false);
            }
            // genericFunctionName(entryaddress): angr-style `sub_<addr>` or
            // `func_<addr>` (the architecture's name style).
            return fc.fspec_printed_name(fd.get_arch().kuna_name_style());
        }
        // No call spec (should not happen for a live CALL): print the in0 address.
        crate::printc::generic_function_name(
            fd.obank()
                .get(op)
                .and_then(|o| o.get_in(0))
                .and_then(|vn| fd.vbank().get(vn))
                .map(|v| v.get_addr())
                .unwrap_or(&kuna_base::address::Address::default()),
        )
        .unwrap_or_default()
    }

    /// C++ `PrintLanguage::recurse` per-Varnode (printlanguage.cc:533): an
    /// *implied* written Varnode expands its defining op's expression inline; an
    /// *explicit* (or input/free) Varnode becomes a leaf atom.  Resolved
    /// directly (depth-first) rather than via the lazy nodepend queue.
    fn push_vn_ir(&mut self, fd: &Funcdata, arch: &Architecture, vn: VarnodeId, op: OpId) {
        let (implied, has_field, def) = {
            let v = match fd.vbank().get(vn) {
                Some(v) => v,
                None => return,
            };
            (v.is_implied(), v.has_implied_field(), v.get_def())
        };
        if implied {
            // C++ `PrintLanguage::recurse` (printlanguage.cc:533): an implied
            // Varnode carrying a resolved union/struct field renders as
            // `<def-expr>.field` via `pushImpliedField`; otherwise just expand the
            // defining op.
            if has_field && self.push_implied_field_ir(fd, arch, vn, op) {
                return;
            }
            if let Some(defop) = def {
                // defOp->getOpcode()->push(this,defOp,op): `op` is the reading op
                // (the C++ `readOp`), threaded so opIntSext/opIntZext can test
                // isExtensionCastImplied against the surrounding expression.
                self.op_push_ir(fd, arch, defop, Some(op));
                return;
            }
        }
        self.push_vn_explicit_ir(fd, arch, vn, op);
    }

    /// C++ `PrintC::pushImpliedField` (printc.cc:2161-2192): an implied Varnode
    /// whose high data-type is a union (or a single-field struct) resolves, via the
    /// per-function union cache, to a specific field; render `<def-expr>.field`.
    ///
    /// Returns `true` when the field render was emitted (the C++ `proceed` arm);
    /// `false` when nothing resolved (the C++ "Just push original op" arm), so the
    /// caller falls back to expanding the defining op.
    ///
    /// STUB(merge high-type retention): the C++ reads the *unresolved* union parent
    /// off `vn->getHigh()->getType()`, then resolves the field through the cache.
    /// In the merged rust tree the implied Varnode's bare `get_type()` (the
    /// print-time high surface) has already been *updated* to the resolved field
    /// data-type by the cast/merge passes, so the union parent is not available
    /// here and `parent.needs_resolution()` is false for the value-member cases
    /// (`glob.intfield`, `(ptr->value).myint`).  This arm is therefore the faithful
    /// port but is *inert* until the HighVariable retains the needs-resolution
    /// union type at print time (a merge-stage surface owned elsewhere); it never
    /// changes a render today (gated on `has_implied_field`, union-resolution-only)
    /// and lights up the value-member renders once that retention lands.
    fn push_implied_field_ir(
        &mut self,
        fd: &Funcdata,
        arch: &Architecture,
        vn: VarnodeId,
        op: OpId,
    ) -> bool {
        // The bare type is the print-time high surface here.
        let parent = match fd.vbank().get(vn).map(|v| v.get_type().clone()) {
            Some(t) => t,
            None => return false,
        };
        let mut field: Option<(String, int4)> = None; // (name, byte offset)
        if parent.needs_resolution()
            && parent.get_metatype() != crate::dtype::type_metatype::TYPE_PTR
        {
            let slot = fd.obank().get(op).map(|o| o.get_slot(vn)).unwrap_or(-1);
            if let Some(res) = fd.get_union_field(&parent, op, slot) {
                let field_num = res.get_field_num();
                if field_num >= 0 {
                    let view = parent.read();
                    match parent.get_metatype() {
                        // STRUCT with fieldNum == 0: beginField().
                        crate::dtype::type_metatype::TYPE_STRUCT if field_num == 0 => {
                            if let Some(f) = view.get_field(parent.id(), 0).expect("retained field") {
                                field = Some((f.name.clone(), f.offset));
                            }
                        }
                        // UNION: getField(fieldNum).
                        crate::dtype::type_metatype::TYPE_UNION => {
                            if let Some(f) = view.get_field(parent.id(), field_num).expect("retained field") {
                                field = Some((f.name.clone(), f.offset));
                            }
                        }
                        _ => {}
                    }
                }
            }
        }
        let def_op = match fd.vbank().get(vn).and_then(|v| v.get_def()) {
            Some(d) => d,
            None => return false,
        };
        let (fieldname, fieldid) = match field {
            Some(f) => f,
            // C++: the no-proceed path pushes the def op; the caller does it here.
            None => return false,
        };
        self.push_op(&tokens::OBJECT_MEMBER, Some(op_key(op)));
        self.op_push_ir(fd, arch, def_op, Some(op));
        let field_atom = Atom::field(
            fieldname,
            TagType::FieldToken,
            crate::printlanguage::SyntaxHighlight::no_color,
            parent,
            fieldid,
            op_key(op),
        );
        self.push_atom(&field_atom);
        true
    }

    /// `pushVn(vn, op, m)` — set the value-rendering mods (`print_load_value` /
    /// `print_store_value`) for the recursive descent into `vn`'s defining op, then
    /// restore.  In the direct-recursion RPN engine the mods live on `self.context`
    /// (the C++ stashes them on the deferred `nodepend` entry).
    fn push_vn_ir_m(&mut self, fd: &Funcdata, arch: &Architecture, vn: VarnodeId, op: OpId, m: uint4) {
        let save = self.context.mods();
        self.context.set_mods(m);
        self.push_vn_ir(fd, arch, vn, op);
        self.context.set_mods(save);
    }

    /// C++ `PrintC::checkArrayDeref(vn)` (printc.cc:354): is `vn` an implied value
    /// produced by a PTRSUB/PTRADD (optionally through a SEGMENTOP)?  Such a value
    /// renders with array/member notation rather than an explicit `*` dereference.
    fn check_array_deref(&self, fd: &Funcdata, vn: VarnodeId) -> bool {
        let v = match fd.vbank().get(vn) {
            Some(v) => v,
            None => return false,
        };
        if !v.is_implied() || !v.is_written() {
            return false;
        }
        let mut op = match v.get_def() {
            Some(o) => o,
            None => return false,
        };
        if fd.obank().get(op).map(|o| o.code()) == Some(OpCode::CPUI_SEGMENTOP) {
            let vn2 = match fd.obank().get(op).and_then(|o| o.get_in(2)) {
                Some(v) => v,
                None => return false,
            };
            let v2 = match fd.vbank().get(vn2) {
                Some(v) => v,
                None => return false,
            };
            if !v2.is_implied() || !v2.is_written() {
                return false;
            }
            op = match v2.get_def() {
                Some(o) => o,
                None => return false,
            };
        }
        let code = fd.obank().get(op).map(|o| o.code());
        code == Some(OpCode::CPUI_PTRSUB) || code == Some(OpCode::CPUI_PTRADD)
    }

    /// C++ `PrintC::opLoad` (printc.cc:507).  A LOAD renders either as an array/
    /// member value (when the pointer is a PTRSUB/PTRADD, absorbing the deref) or
    /// as an explicit `*ptr`.
    fn op_load_ir(&mut self, fd: &Funcdata, arch: &Architecture, op: OpId) {
        let ptr = match fd.obank().get(op).and_then(|o| o.get_in(1)) {
            Some(v) => v,
            None => return,
        };
        let usearray = self.check_array_deref(fd, ptr);
        let mut m = self.context.mods();
        if usearray && !self.context.is_set(modifiers::FORCE_POINTER) {
            m |= modifiers::PRINT_LOAD_VALUE;
        } else {
            self.push_op(&tokens::DEREFERENCE, Some(op_key(op)));
        }
        self.push_vn_ir_m(fd, arch, ptr, op, m);
    }

    /// C++ `PrintC::opStore` (printc.cc:520).  `*ptr = value` (or member/array
    /// notation absorbing the deref).
    fn op_store_ir(&mut self, fd: &Funcdata, arch: &Architecture, op: OpId) {
        let mods = self.context.mods();
        self.push_op(&tokens::ASSIGNMENT, Some(op_key(op)));
        let ptr = match fd.obank().get(op).and_then(|o| o.get_in(1)) {
            Some(v) => v,
            None => return,
        };
        let val = fd.obank().get(op).and_then(|o| o.get_in(2));
        let usearray = self.check_array_deref(fd, ptr);
        let mut m = mods;
        if usearray && !self.context.is_set(modifiers::FORCE_POINTER) {
            m |= modifiers::PRINT_STORE_VALUE;
        } else {
            self.push_op(&tokens::DEREFERENCE, Some(op_key(op)));
        }
        // C++ pushes value (slot 2) then pointer (slot 1) onto the LIFO
        // nodepend, so the LIFO reversal makes the pointer the LHS:
        // `ptr = value`.  The direct-recursion engine here renders in push
        // order (first push = leftmost operand, the inverse of the C++ LIFO),
        // so to keep the pointer on the LHS of `=` we push the pointer first,
        // then the value — exactly as op_binary_ir inverts in0/in1.
        self.push_vn_ir_m(fd, arch, ptr, op, m);
        if let Some(val) = val {
            self.push_vn_ir_m(fd, arch, val, op, mods);
        }
    }

    /// C++ `PrintC::checkBitFieldMember` (printc.cc:378-389): decide whether a
    /// bitfield access through a LOAD/STORE should use member syntax (`.`) or
    /// pointer syntax (`->`).
    ///
    /// If the bitfield is not at byte offset 0 a PTRSUB must be present accessing
    /// the bitfield storage range; that PTRSUB is skipped and member syntax is
    /// used only when *another* PTRSUB/PTRADD remains underneath
    /// ([`check_array_deref`](Self::check_array_deref)).
    fn check_bit_field_member(&self, fd: &Funcdata, vn: VarnodeId, field: &crate::dtype::TypeBitField) -> bool {
        let mut vn = vn;
        if field.byte_offset != 0 {
            // Bitfield not at offset 0, a PTRSUB should be present.
            let v = match fd.vbank().get(vn) {
                Some(v) => v,
                None => return false,
            };
            if !v.is_written() {
                return false;
            }
            let op = match v.get_def() {
                Some(o) => o,
                None => return false,
            };
            if fd.obank().get(op).map(|o| o.code()) != Some(OpCode::CPUI_PTRSUB) {
                return false;
            }
            vn = match fd.obank().get(op).and_then(|o| o.get_in(0)) {
                Some(v) => v, // Skip this PTRSUB
                None => return false,
            };
        }
        self.check_array_deref(fd, vn)
    }

    /// Push the bitfield-name Atom (C++ `Atom(field->name,bitfieldtoken,no_color,
    /// theStruct,field->ident,op)`, e.g. printc.cc:1311). Bitfield metadata uses
    /// the field identifier rather than an ordinary member's byte offset.
    fn push_bitfield_atom(&mut self, parent: &crate::dtype::TypeRoot, field: &crate::dtype::TypeBitField, op: OpId) {
        self.push_atom(&Atom::field(
            field.name.clone(),
            TagType::BitFieldToken,
            crate::printlanguage::SyntaxHighlight::no_color,
            parent.clone(),
            field.ident,
            op_key(op),
        ));
    }

    /// C++ `PrintC::opZpullOp` (printc.cc:1294) / `PrintC::opSpullOp`
    /// (printc.cc:1320): render a bitfield read.  Both bodies are identical (the
    /// signed/unsigned distinction lives in the recovery's type, not the render),
    /// so they share this method.
    ///
    /// When the read goes through a LOAD, the structure pointer is pushed with
    /// member (`.`) or pointer (`->`) syntax and the bitfield name follows.  When
    /// the read is of a bound (partial) symbol, the symbol detail is pushed with
    /// member syntax.  On an unrecognized form, fall back to the functional
    /// `ZPULL(...)`/`SPULL(...)` render.
    fn op_pull_ir(&mut self, fd: &Funcdata, arch: &Architecture, op: OpId) {
        let expr = crate::bitfield::expression::PullExpression::new(fd, op);
        let bitfield = match (expr.is_valid(), &expr.expr.bitfield) {
            (true, Some(b)) => b.clone(),
            _ => {
                // If no other way to print it, print as functional operator.
                self.op_func_ir(fd, arch, op);
                return;
            }
        };
        if let Some(load_op) = expr.load_op {
            let load_ptr = fd.obank().get(load_op).and_then(|o| o.get_in(1));
            let mut m = self.context.mods();
            let use_member = load_ptr
                .map(|p| self.check_bit_field_member(fd, p, &bitfield))
                .unwrap_or(false);
            if use_member {
                m |= modifiers::PRINT_LOAD_VALUE;
                self.push_op(&tokens::OBJECT_MEMBER, Some(op_key(op)));
            } else {
                self.push_member_through_pointer(Some(op_key(op)));
            }
            if let Some(sp) = expr.struct_ptr {
                self.push_vn_ir_m(fd, arch, sp, op, m);
            }
            self.push_bitfield_atom(expr.expr.the_struct.as_ref().expect("valid bitfield parent"), &bitfield, op);
        } else {
            // Bound-symbol read: `symbol.field`.
            self.push_op(&tokens::OBJECT_MEMBER, Some(op_key(op)));
            if let Some(in0) = fd.obank().get(op).and_then(|o| o.get_in(0)) {
                self.push_vn_ir(fd, arch, in0, op);
            }
            self.push_bitfield_atom(expr.expr.the_struct.as_ref().expect("valid bitfield parent"), &bitfield, op);
        }
    }

    /// C++ `PrintC::emitBitFieldStore` (printc.cc:2595-2620): render a bitfield
    /// write through a STORE as `ptr->field = value` (or `ptr.field = value`).
    ///
    /// On an unrecognized form, fall back to the normal STORE render.
    fn emit_bitfield_store(&mut self, fd: &Funcdata, arch: &Architecture, op: OpId) {
        let expr = crate::bitfield::expression::InsertStoreExpression::new(fd, op);
        let bitfield = match (expr.is_valid(), &expr.expr.bitfield, expr.insert_op, expr.struct_ptr) {
            (true, Some(b), Some(_), Some(_)) => b.clone(),
            _ => {
                // The normal STORE push.
                self.op_store_ir(fd, arch, op);
                return;
            }
        };
        let insert_op = expr.insert_op.unwrap();
        let struct_ptr = expr.struct_ptr.unwrap();
        // We assume the STORE is a statement.
        self.push_op(&tokens::ASSIGNMENT, Some(op_key(op)));
        let store_ptr = fd.obank().get(op).and_then(|o| o.get_in(1));
        let mut m = self.context.mods();
        let use_member = store_ptr
            .map(|p| self.check_bit_field_member(fd, p, &bitfield))
            .unwrap_or(false);
        if use_member {
            m |= modifiers::PRINT_STORE_VALUE;
            self.push_op(&tokens::OBJECT_MEMBER, Some(op_key(insert_op)));
        } else {
            self.push_member_through_pointer(Some(op_key(insert_op)));
        }
        // C++ pushes the LHS (structPtr.field) then the RHS (insert value); the
        // direct RPN engine renders in push order, so push the pointer + bitfield
        // first (LHS of `=`), then the value.
        self.push_vn_ir_m(fd, arch, struct_ptr, op, m);
        self.push_bitfield_atom(expr.expr.the_struct.as_ref().expect("valid bitfield parent"), &bitfield, op);
        // The value being written.
        if let Some(val) = fd.obank().get(insert_op).and_then(|o| o.get_in(1)) {
            self.push_vn_ir_m(fd, arch, val, op, self.context.mods());
        }
    }

    /// Push the structure-carrying Symbol token of a bit-field assignment LHS,
    /// faithful to C++ `pushPartialSymbol(symbol, offsetToBitStruct,
    /// theStruct->getSize(), out, op, -1, false)` (printc.cc:2633).  The key is
    /// `sz = theStruct->getSize()` (the WHOLE struct), so the partial walk stops at
    /// the struct and renders the bare symbol name — the bit-field field token is
    /// appended by the caller.  Falls back to the plain explicit name when the
    /// output high carries no composite Symbol (the bit-field op already validated
    /// the form, so this is the degenerate no-symbol case).
    fn push_bitfield_struct_symbol(
        &mut self,
        fd: &Funcdata,
        arch: &Architecture,
        out: VarnodeId,
        op: OpId,
        expr: &crate::bitfield::expression::InsertExpression,
    ) {
        let named = fd
            .vbank()
            .get(out)
            .and_then(|v| v.get_high())
            .and_then(|high| self.emitted_high_symbol(fd, high))
            .map(|(name, _, ty)| (name, ty));
        if let Some((name, Some(st))) = named {
            let mt = st.get_metatype();
            if (mt == crate::dtype::type_metatype::TYPE_STRUCT
                || mt == crate::dtype::type_metatype::TYPE_UNION)
                && self.push_partial_symbol_ir(
                    fd,
                    arch,
                    &name,
                    st.clone(),
                    expr.expr.offset_to_bit_struct as int8,
                    st.get_size(),
                    out,
                    op,
                    -1,
                    false,
                )
            {
                return;
            }
            // Whole-symbol cover (the common bit-field case): render the bare name.
            self.push_atom(&Atom::with_op_vn(
                name,
                TagType::VarToken,
                crate::printlanguage::SyntaxHighlight::var_color,
                op_key(op),
                vn_key(out),
            ));
            return;
        }
        // No composite Symbol bound: fall back to the explicit-name surface.
        self.push_vn_explicit_ir(fd, arch, out, op);
    }

    /// C++ `PrintC::emitBitFieldExpression` (printc.cc:2622-2637): render a
    /// bitfield write into an explicit (mapped) Varnode as `symbol.field = value`.
    ///
    /// On an unrecognized form, fall back to the functional `INSERT(...)` render.
    fn emit_bitfield_expression(&mut self, fd: &Funcdata, arch: &Architecture, op: OpId) {
        let expr = crate::bitfield::expression::InsertExpression::new(fd, op);
        let bitfield = match (expr.expr.is_valid(), &expr.expr.bitfield) {
            (true, Some(b)) => b.clone(),
            _ => {
                // If no other way to print it, print as functional operator.
                self.op_func_ir(fd, arch, op);
                return;
            }
        };
        self.push_op(&tokens::ASSIGNMENT, Some(op_key(op)));
        self.push_op(&tokens::OBJECT_MEMBER, Some(op_key(op)));
        // C++ `pushPartialSymbol(symbol, offsetToBitStruct, theStruct->getSize(),
        // out, op, -1, false)` (printc.cc:2633): the (partial) symbol carrying the
        // *structure* — note `sz == theStruct->getSize()`, not the bit-field
        // Varnode's truncated size, so the partial walk stops at the struct
        // (`off==0 && sz==structSize` -> break) and renders the bare symbol name;
        // the bit-field field token is appended by `push_bitfield_atom` below.
        // Passing the truncated Varnode size here instead would drive the walk into
        // the artificial `._<off>_<sz>_` member (`v1._0_1_.fieldb`).
        if let Some(out) = fd.obank().get(op).and_then(|o| o.get_out()) {
            self.push_bitfield_struct_symbol(fd, arch, out, op, &expr);
        }
        self.push_bitfield_atom(expr.expr.the_struct.as_ref().expect("valid bitfield parent"), &bitfield, op);
        if let Some(val) = fd.obank().get(op).and_then(|o| o.get_in(1)) {
            self.push_vn_ir_m(fd, arch, val, op, self.context.mods());
        }
    }

    /// C++ `PrintC::opPtradd` (printc.cc:900).  `ptr[index]` (value), `&ptr[index]`
    /// (array-notation address), or `ptr + index` (plain pointer arithmetic).
    fn op_ptradd_ir(&mut self, fd: &Funcdata, arch: &Architecture, op: OpId) {
        if self.out_lang == crate::kuna_lang::OutLang::Rust {
            if !self.op_rust_ptradd_ir(fd, arch, op) {
                // C indexing would claim a pointer/stride/layout contract we
                // have not proved. Preserve the explicit p-code address and
                // the LOAD/STORE that requested its dereference.
                let access = modifiers::PRINT_LOAD_VALUE | modifiers::PRINT_STORE_VALUE;
                if self.context.is_set(access) {
                    self.push_op(&tokens::DEREFERENCE, Some(op_key(op)));
                }
                self.context.push_mod();
                self.context.unset_mod(access);
                self.op_func_ir(fd, arch, op);
                self.context.pop_mod();
            }
            return;
        }
        let printval = self
            .context
            .is_set(modifiers::PRINT_LOAD_VALUE | modifiers::PRINT_STORE_VALUE);
        let m = self.context.mods() & !(modifiers::PRINT_LOAD_VALUE | modifiers::PRINT_STORE_VALUE);
        if printval {
            self.push_op(&tokens::SUBSCRIPT, Some(op_key(op)));
        } else if self.options.array_notation() {
            // (kuna) S9 pointer-notation sub-stage: EMIT &base[index].
            let tok = self.lang_token(&tokens::ADDRESSOF);
            self.push_op(tok, Some(op_key(op)));
            self.push_op(&tokens::SUBSCRIPT, Some(op_key(op)));
        } else {
            self.push_op(&tokens::BINARY_PLUS, Some(op_key(op)));
        }
        // C++ pushes in1 (index) then in0 (base) onto the LIFO nodepend; the direct
        // RPN engine drains in push order, so push in0 (base) then in1 (index) to
        // render `base[index]`.
        let in0 = fd.obank().get(op).and_then(|o| o.get_in(0));
        let in1 = fd.obank().get(op).and_then(|o| o.get_in(1));
        if let Some(in0) = in0 {
            self.push_vn_ir_m(fd, arch, in0, op, m);
        }
        if let Some(in1) = in1 {
            self.push_vn_ir_m(fd, arch, in1, op, m);
        }
    }

    /// PTRADD's stride is in target address units, not host `size_of::<T>()`.
    /// Byte offsets preserve it even for recovered pointees with unknown layout.
    fn op_rust_ptradd_ir(&mut self, fd: &Funcdata, arch: &Architecture, op: OpId) -> bool {
        use crate::dtype::type_metatype::{TYPE_ARRAY, TYPE_PTR, TYPE_INT, TYPE_UINT, TYPE_UNKNOWN, TYPE_FLOAT};
        let Some(expr) = fd.obank().get(op) else { return false };
        let (Some(base), Some(index), Some(stride)) = (expr.get_in(0), expr.get_in(1), expr.get_in(2))
            else { return false };
        let Some(stride) = fd.vbank().get(stride).filter(|v| v.is_constant()) else { return false };
        let Some(out) = expr.get_out().and_then(|v| fd.vbank().get(v)) else { return false };
        let size = out.get_size();
        if !matches!(size, 4 | 8)
            || fd.vbank().get(index).is_none_or(|v| v.get_size() != size)
        {
            return false;
        }
        let Some(base_type) = self.rust_ptradd_base_type(fd, arch, base, op, 16) else { return false };
        let array = base_type.get_metatype() == TYPE_ARRAY;
        if array {
            let Some(element) = base_type.get_array_base() else { return false };
            // Keep actual-array lowering within the storage-known scalar
            // domain. A recovered struct's target layout is not such proof.
            let scalar_layout = match element.get_metatype() {
                TYPE_INT | TYPE_UINT | TYPE_UNKNOWN => matches!(element.get_size(), 1 | 2 | 4 | 8 | 16),
                TYPE_FLOAT => matches!(element.get_size(), 4 | 8),
                TYPE_PTR => element.get_size() == size,
                _ => false,
            };
            if !scalar_layout || element.get_align_size() != element.get_size()
                || element.get_size() as u64 != stride.get_offset() {
                return false;
            }
        } else if base_type.get_metatype() != TYPE_PTR
            || base_type.get_size() != size || base_type.get_word_size() != Some(1)
        {
            return false;
        }
        let Ok(integer) = arch.types().get_base_no_char(size, TYPE_INT) else { return false };
        let printval = self.context.is_set(modifiers::PRINT_LOAD_VALUE | modifiers::PRINT_STORE_VALUE);
        let mods = self.context.mods() & !(modifiers::PRINT_LOAD_VALUE | modifiers::PRINT_STORE_VALUE);
        // A compile-time rejection is preferable to truncating a host pointer
        // or interpreting a target-width index at the wrong host width.
        static WIDTH32: OpToken = op_token(
            "{ const { assert!(core::mem::size_of::<usize>() == 4, \"kuna: PTRADD target pointer width\"); } ",
            " }", 1, 70, false, TokenType::Presurround, 0, 0,
        );
        static WIDTH64: OpToken = op_token(
            "{ const { assert!(core::mem::size_of::<usize>() == 8, \"kuna: PTRADD target pointer width\"); } ",
            " }", 1, 70, false, TokenType::Presurround, 0, 0,
        );
        let guard = if size == 4 { &WIDTH32 } else { &WIDTH64 };
        if printval { self.push_op(&tokens::DEREFERENCE, Some(op_key(op))); }
        self.push_op(guard, Some(op_key(op)));
        self.push_op(&tokens::FUNCTION_CALL, Some(op_key(op)));
        self.push_op(&tokens::OBJECT_MEMBER, Some(op_key(op)));
        if array {
            // Array decay feeds the same target-width byte arithmetic as raw
            // pointers. Direct indexing would skip wrapping index*stride.
            // No reference to a possibly one-past-the-end element is created.
            self.push_op(&tokens::FUNCTION_CALL, Some(op_key(op)));
            self.push_op(&tokens::OBJECT_MEMBER, Some(op_key(op)));
        }
        self.push_vn_ir_m(fd, arch, base, op, mods);
        if array {
            self.push_atom(&Atom::with_op("as_mut_ptr".to_string(), TagType::Syntax,
                crate::printlanguage::SyntaxHighlight::funcname_color, op_key(op)));
            self.push_atom(&Atom::syntax("", TagType::BlankToken,
                crate::printlanguage::SyntaxHighlight::no_color));
        }
        self.push_atom(&Atom::with_op("wrapping_byte_offset".to_string(), TagType::Syntax,
            crate::printlanguage::SyntaxHighlight::funcname_color, op_key(op)));
        self.push_op(self.lang().tok_typecast, Some(op_key(op)));
        self.push_op(&tokens::FUNCTION_CALL, Some(op_key(op)));
        self.push_op(&tokens::OBJECT_MEMBER, Some(op_key(op)));
        self.push_rust_integer_operand(fd, arch, index, op, &integer, mods);
        self.push_atom(&Atom::with_op("wrapping_mul".to_string(), TagType::Syntax,
            crate::printlanguage::SyntaxHighlight::funcname_color, op_key(op)));
        self.push_cast_open(&integer, op);
        self.push_atom(&Atom::with_op(format!("{}u{}", stride.get_offset() & calc_mask(size), size * 8),
            TagType::Syntax, crate::printlanguage::SyntaxHighlight::const_color, op_key(op)));
        self.push_cast_close(&integer);
        self.push_atom(&Atom::syntax("isize", TagType::TypeToken,
            crate::printlanguage::SyntaxHighlight::type_color));
        true
    }

    /// PTRSUB array decay prints a real array in Rust, not a raw pointer.
    fn rust_ptradd_base_type(
        &mut self, fd: &Funcdata, arch: &Architecture, vn: VarnodeId, reader: OpId, depth: usize,
    ) -> Option<crate::dtype::TypeRoot> {
        use crate::dtype::type_metatype::{TYPE_ARRAY, TYPE_PTR, TYPE_SPACEBASE};
        if depth == 0 { return None; }
        let value = fd.vbank().get(vn)?;
        if value.is_implied() {
            let def = value.get_def()?;
            let expr = fd.obank().get(def)?;
            if expr.code() == OpCode::CPUI_PTRSUB {
                let offset = fd.vbank().get(expr.get_in(1)?)?;
                let raw = fd.vbank().get(expr.get_in(0)?)?.get_type_read_facing(def);
                if raw.get_ptr_to().is_some_and(|p| p.get_metatype() == TYPE_SPACEBASE) {
                    let (_, off, symbol) = self.emitted_high_symbol(fd, offset.get_high()?)?;
                    let symbol = symbol?;
                    if off == 0 && symbol.get_metatype() == TYPE_ARRAY {
                        return Some(symbol);
                    }
                    return None;
                }
                let pointer = self.callable_operand_type(fd, arch, expr.get_in(0)?, def, depth - 1)?;
                if pointer.get_metatype() == TYPE_PTR && offset.is_constant() && offset.get_offset() == 0 {
                    let array = pointer.get_ptr_to()?;
                    if array.get_metatype() == TYPE_ARRAY { return Some(array); }
                }
            }
        }
        self.callable_operand_type(fd, arch, vn, reader, depth)
    }

    /// C++ `PrintC::pushPartialSymbol` (printc.cc:2019-2141), the STRUCT / UNION /
    /// ARRAY arms of the type walk (the symbol-mapped member-access render
    /// `glob.intfield` / `val.c` / `globvar.b.bval1` and the array-element render
    /// `v1.arr[i]` for a struct field that is an array).
    ///
    /// Reconciled with the kuna naming layer: the base symbol name comes from the
    /// HighVariable's `kuna_name` binding (the `pushSymbol(sym,vn,op)` stand-in,
    /// printc.cc:2127) rather than a `Symbol *`; the walked data-type is the
    /// `kuna_symbol_type` (the `sym->getType()` stand-in, printc.cc:2030).  The
    /// UNION `findTruncation` (type.cc:2613-2627) reads the Funcdata union
    /// resolution cache via [`Funcdata::get_union_field`]; the STRUCT
    /// `findTruncation` (type.cc:1878) walks the field table
    /// ([`Datatype::find_truncation`]).
    ///
    /// Returns `true` when the walk produced a genuine member token (the partial
    /// cover render fired) and `false` otherwise — on `false` the caller renders
    /// the bare symbol name, so a non-partial read stays byte-identical.  The
    /// `allowCast` SUBPIECE-cast arm (printc.cc:2094-2105) is not reached from this
    /// entry (`allow_cast == false`); a whole-array Symbol is still handled by the
    /// caller's existing `name[index]` branch (this ARRAY arm only fires for an
    /// array nested inside a struct field, e.g. `mypiece.arr[i]`).
    #[allow(clippy::too_many_arguments)]
    fn push_partial_symbol_ir(
        &mut self,
        fd: &Funcdata,
        arch: &Architecture,
        name: &str,
        sym_type: crate::dtype::TypeRoot,
        off_in: int8,
        sz_in: int4,
        vn: VarnodeId,
        op: OpId,
        slot: int4,
        allow_cast: bool,
    ) -> bool {
        use crate::dtype::type_metatype;
        // PartialSymbolEntry stack (C++ `vector<PartialSymbolEntry> stack`,
        // printc.cc:2026): each entry is a resolved member token — either an
        // `object_member` (`.field`) for a struct/union field, or a `subscript`
        // (`[index]`) for an array element (printc.cc:2062-2070).
        let mut stack: Vec<PartialEntry> = Vec::new();
        let mut ct = Some(sym_type);
        let mut off: int8 = off_in;
        let mut sz: int4 = sz_in;
        // C++ `Datatype *finalcast = 0` (printc.cc:2024): set by the `allowCast`
        // arm when the trailing truncation is a SUBPIECE-style cast (`(undefined1)
        // v1.flagfield`); rendered as a leading `(cast)` before the member tokens.
        let mut finalcast: Option<crate::dtype::TypeRoot> = None;

        while let Some(cur) = ct.clone() {
            // (kuna arraycoverwidth) The upstream whole-symbol break exits the
            // walk before the ARRAY arm can see a cover that spans more than one
            // element, so a 16-byte `movaps` transfer through a `char v30[16]`
            // bank left the caller to render `v30[0]` -- a one-byte lvalue for a
            // sixteen-byte access.  Such a cover has no subscript that describes
            // it; letting the walk continue reaches the artificial-field branch
            // below and renders `v30._0_16_`, the same width-carrying notation a
            // PARTIAL multi-element access already gets.  Scalars, structs,
            // unions and single-element covers keep the upstream break.
            let wide_array_cover = self.options.array_cover_width
                && sz != 0
                && crate::kuna_arraycoverwidth::spans_multiple_elements(&cur, sz);
            if off == 0
                && !wide_array_cover
                && (sz == 0
                    || (sz == cur.get_size()
                        && (!cur.needs_resolution()
                            || cur.get_metatype() == type_metatype::TYPE_PTR)))
            {
                break;
            }
            let mut succeeded = false;
            let meta = cur.get_metatype();
            if meta == type_metatype::TYPE_STRUCT {
                // TypeStruct::findTruncation walks the field table (no cache).
                // (printc.cc:2044-2056; the needsResolution()/findResolve guard at
                // 2039-2043 only applies to a struct that itself needsResolution,
                // which the corpus structs do not — it would require the union
                // cache and is a no-op for a plain struct.)
                match cur.find_truncation(off, sz, op, slot) {
                    Ok(Some((idx, newoff))) => {
                        let view = cur.read();
                        if let Some(f) = view.get_field(cur.id(), idx).expect("retained field") {
                            off = newoff;
                            stack.push(PartialEntry::Member(f.name.clone(), f.offset, cur.clone()));
                            ct = Some(cur.related(f.field_type).expect("field type"));
                            succeeded = true;
                        }
                    }
                    Ok(None) | Err(_) => {
                        // C++ printc.cc:2057-2059: `else if (op->code()==CPUI_ZPULL ||
                        // CPUI_SPULL) break;` — the final byte field cannot be
                        // resolved because it is a *bit field* extracted by a
                        // ZPULL/SPULL; the Varnode is already fully resolved (the
                        // bitfield op carries the member), so stop WITHOUT emitting an
                        // artificial `._o_s_` token (which would wrongly produce
                        // `v1._0_1_.fieldb`).
                        let opc = fd.obank().get(op).map(|o| o.code());
                        if opc == Some(OpCode::CPUI_ZPULL) || opc == Some(OpCode::CPUI_SPULL) {
                            break;
                        }
                    }
                }
            } else if meta == type_metatype::TYPE_ARRAY {
                // C++ `TypeArray::getSubEntry` (type.cc:1430): the access maps to
                // element `el = off / elementAlignSize`, with `newoff = off %
                // elementAlignSize` the remaining offset INTO that element.  A
                // request spanning more than one element returns null (no subscript).
                if let Some(elem) = cur.get_array_base() {
                    let elsize = elem.get_align_size().max(1);
                    let noff = off % elsize as int8;
                    let nel = (off / elsize as int8) as int4;
                    if noff + sz as int8 <= elsize as int8 {
                        off = noff;
                        stack.push(PartialEntry::Subscript(nel));
                        ct = Some(elem);
                        succeeded = true;
                    }
                }
            } else if meta == type_metatype::TYPE_UNION {
                // TypeUnion::findTruncation (type.cc:2613): read the cached union
                // resolution for this (type, op, slot) edge.  No new scoring.
                let field = if cur.needs_resolution() {
                    fd.get_union_resolution(&cur, op, slot)
                        .map(|r| r.get_field_num())
                        .filter(|&n| n >= 0)
                        .and_then(|n| {
                            let view = cur.read();
                            view.get_field(cur.id(), n).expect("retained field").map(|f| (
                                n, f.offset, f.name.clone(),
                                cur.related(f.field_type).expect("field type"),
                            ))
                        })
                } else {
                    None
                };
                match field {
                    Some((_n, foff, fname, ftype)) => {
                        // newoff = offset - field->offset; truncation must fit the
                        // field (type.cc:2621-2624).
                        let newoff = off - foff as int8;
                        if newoff + sz as int8 > ftype.get_size() as int8 {
                            // Truncation spans more than one field: findTruncation
                            // returns null.  Fall to the `else if size==sz` check.
                            if cur.get_size() == sz {
                                break;
                            }
                            // !succeeded artificial-field fallthrough below.
                        } else {
                            off = newoff;
                            stack.push(PartialEntry::Member(fname, foff, cur.clone()));
                            ct = Some(ftype);
                            succeeded = true;
                        }
                    }
                    None => {
                        // else if (ct->getSize() == sz) break; (printc.cc:2091).
                        if cur.get_size() == sz {
                            break;
                        }
                    }
                }
            } else if allow_cast {
                // C++ `else if (allowCast)` (printc.cc:2094-2105): the walk has
                // reached a scalar leaf (e.g. the `flags` enum field) but the access
                // truncates it (a 1-byte read of the 8-byte `flagfield`).  When the
                // truncation is a low-end SUBPIECE-style cast, render it as a leading
                // `(outtype)` cast over the whole member: `(undefined1)v1.flagfield`.
                // `vn->getHigh()->getType()`: by the W10 print convention the high
                // type is pinned to the Varnode's own type at print-time (the same
                // stand-in `vn_high_type` uses), so read it directly.
                let outtype = fd.vbank().get(vn).map(|v| v.get_type().clone());
                // `getFirstWholeMap()->getAddr().getSpace()` is the Symbol's storage
                // space (the stack space for a stack local); its endianness gates the
                // SUBPIECE direction.  The Varnode's own space is the same storage
                // here, so use it as the C++ `spc == 0` fallback already does.
                let is_big = fd
                    .vbank()
                    .get(vn)
                    .and_then(|v| v.get_addr().get_space().map(|s| s.is_big_endian()))
                    .unwrap_or(false);
                if let (Some(outtype), Some(strat)) = (outtype, cast_strategy_for(arch)) {
                    let off_u = if off >= 0 { off as uint4 } else { 0 };
                    if strat.is_subpiece_cast_endian(&outtype, &cur, off_u, is_big) {
                        finalcast = Some(outtype);
                        ct = None;
                        succeeded = true;
                    }
                }
                // If the truncation is NOT a plain SUBPIECE-style cast, fall through
                // to the `!succeeded` artificial-field branch (C++ printc.cc:2106):
                // the leftover offset/size renders as `._<off>_<sz>_`.
            } else if !stack.is_empty() {
                // ARRAY/scalar leaf with allowCast disabled, but a member token was
                // already collected: emit the leftover as an artificial `._o_s_`
                // member rather than discarding the resolved prefix (C++ reaches the
                // `!succeeded` branch here too).  Leaving `succeeded == false`.
            }
            // NOTE: two leaves land here with an empty stack.  A SCALAR whose
            // truncation is not a SUBPIECE cast, and an ARRAY whose access spans
            // more than one element (`TypeArray::getSubEntry` returns null): an
            // 8-byte write into `undefined1[16]` has no subscript that describes
            // it, so it renders `v1._0_8_` — the size the subscript could not
            // carry.  C++ `pushPartialSymbol`
            // (printc.cc:2106-2117) takes the `!succeeded` artificial-field branch for a
            // scalar truncation that is not a SUBPIECE cast — the LOSS-245 store LHS
            // `local._2_2_ = big(...)` (an int2 write at offset 2 of the tied int8
            // `local`, `allowCast` off because the assignment output is not a read).
            // So this scalar leaf FALLS THROUGH (no bail) to the `._<off>_<sz>_` token
            // emitter below, matching the C++ render.  (Previously this bailed with
            // `return false` so a scalar rendered its bare name; that suppressed the
            // partial-field render for tied scalar sub-accesses.)
            if !succeeded {
                // Subtype was not good (printc.cc:2106-2117): generate an artificial
                // member name based on offset/size (`unnamedField(off,sz)` →
                // `._<off>_<sz>_`).  Reached when a composite member walk lands on an
                // offset/size with no exact field — the C++ emits the synthetic
                // `_o_s_` token and stops (`ct = 0`).
                if sz == 0 {
                    sz = cur.get_size() - off as int4;
                }
                stack.push(PartialEntry::Unnamed(off, sz));
                ct = None;
            }
        }

        // No member tokens collected and no trailing cast: this is a whole-symbol
        // cover, render bare (the caller emits the plain name).
        if stack.is_empty() && finalcast.is_none() {
            return false;
        }

        // A leading `(cast)` over the whole member access (Rust: a trailing
        // `as T`, closed at the single exit below).
        let final_cast_open = match (&finalcast, self.options.nocasts) {
            (Some(fc), false) => {
                self.push_cast_open(fc, op);
                Some(fc.clone())
            }
            _ => None,
        };

        // Push the member ops in REVERSE stack order (C++ printc.cc:2124-2126:
        // `for(i=stack.size()-1;i>=0;--i) pushOp(stack[i].token,op)`).  The
        // outermost access (the last-resolved element) binds tightest, so e.g. for
        // `v1.arr[i]` the stack is `[Member("arr"), Subscript(i)]` and the ops emit
        // SUBSCRIPT then OBJECT_MEMBER, yielding `(v1.arr)[i]` not `(v1[i]).arr`.
        for entry in stack.iter().rev() {
            match entry {
                PartialEntry::Member(_, _, _) | PartialEntry::Unnamed(_, _) => {
                    // C++ both the field and the artificial-name entry use
                    // `entry.token = &object_member` (printc.cc:2049 / 2109).
                    self.push_op(&tokens::OBJECT_MEMBER, Some(op_key(op)));
                }
                PartialEntry::Subscript(_) => {
                    self.push_op(&tokens::SUBSCRIPT, Some(op_key(op)));
                }
            }
        }
        // The base name (the kuna_name stand-in for pushSymbol).
        self.push_atom(&Atom::with_op_vn(
            name.to_string(),
            TagType::VarToken,
            crate::printlanguage::SyntaxHighlight::var_color,
            op_key(op),
            vn_key(vn),
        ));
        // Per entry, in forward order (printc.cc:2128-2140): a field emits its name
        // Atom carrying its nominal parent and byte offset; an array
        // subscript emits the index as a constant-color integer literal
        // (`push_integer(entry.offset,...)`, printc.cc:2133).
        for entry in &stack {
            match entry {
                PartialEntry::Member(fname, offset, parent) => {
                    self.push_atom(&Atom::field(
                        fname.clone(),
                        TagType::FieldToken,
                        crate::printlanguage::SyntaxHighlight::no_color,
                        parent.clone(),
                        *offset,
                        op_key(op),
                    ));
                }
                PartialEntry::Subscript(index) => {
                    // C++ `push_integer(entry.offset, entry.size, (entry.offset < 0),
                    // syntax, 0, op, 0)` (printc.cc:2132): an array-subscript entry
                    // has `entry.size == 0`, so the index renders through the integer
                    // formatter — the `val<=10 -> dec` / `mostNaturalBase` hex/dec
                    // rule, NOT an unconditional decimal.  (Previously emitted
                    // `format!("{index}")`, which forced decimal and lost the oracle's
                    // `arr[0xb]` hex rendering for an index whose natural base is 16.)
                    let sign = *index < 0;
                    self.push_constant_ir_fmt_sign(
                        *index as uintb,
                        0,
                        op,
                        display_format::NONE,
                        sign,
                    );
                }
                PartialEntry::Unnamed(eoff, esize) => {
                    // C++ printc.cc:2129-2135 (`entry.field == 0`): a negative/zero
                    // `size` renders the offset as an integer; a positive size emits
                    // the synthetic `_<off>_<size>_` field atom.
                    if *esize <= 0 {
                        self.push_constant_ir_fmt_sign(
                            *eoff as uintb,
                            *esize,
                            op,
                            display_format::NONE,
                            *eoff < 0,
                        );
                    } else {
                        let field = crate::printlanguage::unnamed_field(*eoff as int4, *esize);
                        self.push_atom(&Atom::with_op(
                            field,
                            TagType::Syntax,
                            crate::printlanguage::SyntaxHighlight::no_color,
                            op_key(op),
                        ));
                    }
                }
            }
        }
        if let Some(fc) = &final_cast_open {
            self.push_cast_close(fc);
        }
        true
    }

    /// C++ `PrintC::pushAnnotation` (printc.cc:1929): render a volatile
    /// read/write annotation operand.  Compute the annotation size from the
    /// userop (`extractAnnotationSize`), query the local scope's container at the
    /// annotation address, and render the whole Symbol (`NVRAM` when it covers
    /// exactly) or the partial-symbol array element (`NVRAM[30]`).  When no Symbol
    /// contains the access, fall to the register-name / `dat_<addr>` unnamed tail
    /// (printc.cc:1957-1974).
    fn push_annotation_ir(&mut self, fd: &Funcdata, arch: &Architecture, vn: VarnodeId, op: OpId) {
        let v = match fd.vbank().get(vn) {
            Some(v) => v,
            None => return,
        };
        let vaddr = v.get_addr().clone();
        let vsize = v.get_size();
        let opaddr = fd.obank().get(op).map(|o| o.get_addr().clone());

        // size = glb->userops.getOp(userind)->extractAnnotationSize(vn, op) for a
        // CALLOTHER; 0 otherwise.
        let mut size = 0i32;
        if let Some(o) = fd.obank().get(op) {
            if o.code() == OpCode::CPUI_CALLOTHER {
                let userind = o
                    .get_in(0)
                    .and_then(|c| fd.vbank().get(c))
                    .map(|cvn| cvn.get_offset())
                    .unwrap_or(0);
                let out_size = o.get_out().and_then(|x| fd.vbank().get(x)).map(|x| x.get_size());
                let in2_size = if o.num_input() > 2 {
                    o.get_in(2).and_then(|x| fd.vbank().get(x)).map(|x| x.get_size())
                } else {
                    None
                };
                if let Some(u) = arch.userops.get_op(userind as u32) {
                    size = u.extract_annotation_size(out_size, in2_size);
                }
            }
        }

        // entry = symScope->queryContainer(addr, size||1, op->getAddr()).  The
        // `map addr` global Symbol lives in the architecture's global scope, which
        // the detached per-function `localmap` reaches only through the
        // `GlobalQuery` snapshot (the same wire the high-naming pass uses); query
        // it for the covering Symbol.  When `size` was 0 the C++ queries with 1 and
        // then adopts the entry's own size — here `name_for_global_varnode` already
        // returns the covering Symbol regardless of the probe size.
        let usepoint = opaddr.unwrap_or_else(|| vaddr.clone());
        let query_size = if size != 0 { size } else { 1 };
        let arch_handle = fd.get_arch();
        let entry = arch_handle.name_for_global_varnode_scoped(&vaddr, query_size, &usepoint);
        // size adopts vn->getSize() only when the userop reported 0 and no entry.
        let size = if size != 0 { size } else { vsize };

        if let Some((name, sym_off, sym_type, scope)) = entry {
            let name = self.emitted_scoped_name(fd, &name, &scope, false);
            if let Some(datatype) = &sym_type {
                self.record_named_global_binding(fd, &vaddr, sym_off, &name, datatype);
            }
            // The volatile annotation Symbol renders in special_color (C++
            // pushSymbol: `sym->isVolatile()` -> special_color).  The mapped global
            // carried the `volatil` flag (set by `volatile [ram,...]`), so use it.
            let color = crate::printlanguage::SyntaxHighlight::special_color;
            // Whole-symbol when the access starts at the symbol base and spans the
            // whole type (C++ entry->getSize() == size).  Otherwise a partial cover.
            let whole = sym_off == 0
                && sym_type.as_ref().map(|t| t.get_size() == size).unwrap_or(false);
            if !whole {
                // Partial symbol (printc.cc:1953-1954 pushPartialSymbol).  For an
                // array-of-element symbol the access maps to element
                // `sym_off / elsize` — the array-subscript shape
                // push_vn_explicit_ir renders for symbol-bound highs.
                if let Some(st) = &sym_type {
                    if st.get_metatype() == crate::dtype::type_metatype::TYPE_ARRAY {
                        if let Some(elem) = st.get_array_base() {
                            let elsize = elem.get_align_size().max(1);
                            if sym_off >= 0 && (sym_off % elsize) == 0 && st.get_size() > elsize {
                                let index = sym_off / elsize;
                                self.push_op(&tokens::SUBSCRIPT, Some(op_key(op)));
                                self.push_atom(&Atom::with_op_vn(
                                    name,
                                    TagType::VarToken,
                                    color,
                                    op_key(op),
                                    vn_key(vn),
                                ));
                                // C++ `pushPartialSymbol` ARRAY arm: the subscript
                                // index renders via `push_integer(el, 0, (el < 0),
                                // syntax, 0, op, 0)` (printc.cc:2132) — the
                                // `val<=10 -> dec` / `mostNaturalBase` hex/dec rule,
                                // not an unconditional decimal.
                                let sign = index < 0;
                                self.push_constant_ir_fmt_sign(
                                    index as uintb,
                                    0,
                                    op,
                                    display_format::NONE,
                                    sign,
                                );
                                return;
                            }
                        }
                    }
                }
            }
            // Whole symbol, or a partial cover the array/struct walk did not turn
            // into a member token: render the bare Symbol name (printc.cc:1951).
            self.push_atom(&Atom::with_op_vn(
                name,
                TagType::VarToken,
                color,
                op_key(op),
                vn_key(vn),
            ));
            return;
        }

        // No containing Symbol: register name, then kuna `dat_<addr>` / `Space<hex>`
        // (printc.cc:1957-1974).
        let spc = match vaddr.get_space() {
            Some(s) => s,
            None => return,
        };
        let regname = arch.translate().get_register_name(spc, vaddr.get_offset(), size);
        let name = if !regname.is_empty() {
            regname
        } else if kuna_global_naming(spc) {
            kuna_global_data_name(arch.kuna_name_style(), vaddr.get_offset())
        } else {
            let mut s = String::new();
            let sn = spc.get_name();
            let mut chars = sn.chars();
            if let Some(c0) = chars.next() {
                s.extend(c0.to_uppercase());
            }
            s.push_str(chars.as_str());
            let byte_addr =
                kuna_base::space::AddrSpace::byte_to_address(vaddr.get_offset(), spc.get_word_size());
            s.push_str(&format!("{:0width$x}", byte_addr, width = 2 * spc.get_addr_size() as usize));
            s
        };
        self.push_atom(&Atom::with_op_vn(
            name,
            TagType::VarToken,
            crate::printlanguage::SyntaxHighlight::special_color,
            op_key(op),
            vn_key(vn),
        ));
    }

    /// C++ `PrintLanguage::pushVnExplicit` (printlanguage.cc:218) + the
    /// `PrintC` leaf-naming (`pushVnExplicit`/`pushUnnamedLocation`, printc.cc:
    /// 1900-2017): annotation -> constant -> SymbolEntry -> register name ->
    /// kuna `dat_<addr>` global -> `Space<hex>` fallback.
    fn push_vn_explicit_ir(&mut self, fd: &Funcdata, arch: &Architecture, vn: VarnodeId, op: OpId) {
        let v = match fd.vbank().get(vn) {
            Some(v) => v,
            None => return,
        };
        // C++ `PrintLanguage::pushVnExplicit` (printlanguage.cc:221): an annotation
        // operand (the volatile read/write address ref) routes through
        // `pushAnnotation`, never the constant/symbol paths.
        if v.is_annotation() {
            self.push_annotation_ir(fd, arch, vn, op);
            return;
        }
        if v.is_constant() {
            let (off, sz) = (v.get_offset(), v.get_size());
            // C++ `PrintLanguage::pushVnExplicit` (printlanguage.cc:227) calls
            // `pushConstant(vn->getOffset(), ct, ...)` with `ct =
            // vn->getHighTypeReadFacing(op)`.  `pushConstant` (printc.cc:1813)
            // switches on `ct->getMetatype()`: a `TYPE_FLOAT` constant is rendered
            // by `push_float` (the decimal literal), every other metatype reaches
            // `push_integer` with `ct->getDisplayFormat()` as its `displayFormat`.
            let ct = v.get_type_read_facing(op).clone();
            if self.callable_transport_valid
                && ct.get_ptr_to().is_some_and(|code| code.get_metatype() == type_metatype::TYPE_CODE) {
                if let Some(space) = fd.get_address().get_space() {
                    let entry = Address::new(space.clone(), kuna_base::space::AddrSpace::address_to_byte(off, space.get_word_size()));
                    if let Ok(Some((key, family))) = crate::kuna_callabletransport::pointer_adapter(fd, &entry) {
                        let name = if family.has_execution_signature() { Some(key) } else {
                            fd.get_arch().query_function(&entry).ok().flatten().map(|(name, target, _)|
                                self.emitted_function_name(fd, &name, &target, true))
                        };
                        if let Some(name) = name {
                            self.push_atom(&Atom::with_op(name, TagType::FuncToken,
                                crate::printlanguage::SyntaxHighlight::funcname_color, op_key(op)));
                            return;
                        }
                    }
                }
            }
            if ct.get_metatype() == crate::dtype::type_metatype::TYPE_FLOAT {
                // C++ `pushConstant` -> `push_float(val, ct->getSize(), ...)`.  The
                // float arm ignores the integer `displayFormat` entirely.
                self.push_float_ir(arch, off, ct.get_size(), op);
                return;
            }
            // Enum arm.  C++ `pushConstant` (printc.cc:1817-1833) switches on the
            // enum's base metatype (TYPE_INT / TYPE_UINT) and, when
            // `ct->isEnumType()`, delegates to `pushEnumConstant` (printc.cc:1822/
            // 1830) — which decomposes the value into the OR of matched flag names.
            // In kuna an enum carries metatype TYPE_INT/TYPE_UINT plus the
            // `enumtype` flag (dtype.rs:5244-5246), exactly as upstream, so the
            // dispatch is the `is_enum_type()` flag check (not a metatype match).
            if ct.is_enum_type() {
                self.push_enum_constant_ir(
                    arch.types(), &ct, off, op, vn, Self::enum_mask_is_zero_test(fd, op),
                );
                return;
            }
            // Char arm.  C++ `pushConstant` (printc.cc:1819/1827): a TYPE_INT /
            // TYPE_UINT constant whose data-type `isCharPrint()` is rendered as a
            // quoted character literal (`pushCharConstant`, printc.cc:1675).  This
            // is the metatype-driven char render (distinct from the equate-Symbol
            // `force_char` display-format path, which already routes through the
            // integer arm below with a FORCE_CHAR display-format override).
            {
                use crate::dtype::type_metatype::{TYPE_INT, TYPE_UINT};
                if matches!(ct.get_metatype(), TYPE_INT | TYPE_UINT) && ct.is_char_print() {
                    self.push_char_constant_ir(fd, &ct, off, op, vn);
                    return;
                }
            }
            // Pointer arm.  C++ `pushConstant` (printc.cc:1842-1854): a TYPE_PTR /
            // TYPE_PTRREL constant whose pointed-to type `isCharPrint()` is rendered
            // as a quoted string literal when the constant resolves to readonly
            // character data (`pushPtrCharConstant`).  If the pointer does not
            // resolve to a readable readonly string, the C++ falls through to the
            // default integer print — so does this arm (it only short-circuits on a
            // successful string push).  The TYPE_CODE (function-name) sub-arm is a
            // documented LOSS below.
            use crate::dtype::type_metatype::{TYPE_PTR, TYPE_PTRREL};
            if matches!(ct.get_metatype(), TYPE_PTR | TYPE_PTRREL) {
                if off != 0 {
                    if let Some(sub) = ct.get_ptr_to() {
                        if sub.is_char_print() {
                            // point = op->getAddr() (the using op's address; used only
                            // by a segmented resolver — flat spaces ignore it).
                            let point = fd
                                .obank()
                                .get(op)
                                .map(|o| o.get_addr().clone())
                                .unwrap_or_default();
                            if self.push_ptr_char_constant_ir(
                                arch,
                                off,
                                ct.get_size(),
                                &sub,
                                &point,
                                op,
                                vn,
                            ) {
                                return;
                            }
                        }
                    }
                }
                // C++ `pushConstant` TYPE_PTR/TYPE_PTRREL arm (printc.cc:1842-1880).
                // After the `pushPtrCharConstant` string short-circuit (above) and
                // the TYPE_CODE function-name sub-arm (a documented LOSS) fail, the
                // C++ `break`s to the shared "Default printing" tail: the gated NULL
                // token, the optional leading typecast, then a force_hex integer.
                // This is what renders a pointer-typed null as `(int4 **)0x0` — the
                // for-loop iterator compare `loopvar != (int4 **)0x0` — rather than a
                // bare decimal `0`.  Previously this arm fell straight through to the
                // signed/unsigned integer path below, dropping both the leading
                // typecast and the force_hex, so the pointer constant printed as `0`.
                if self.options.null && off == 0 {
                    // option_NULL set (OFF by kuna default): emit the NULL token.
                    self.push_atom(&Atom::with_op_vn(
                        self.lang().null_literal.to_string(),
                        TagType::VarToken,
                        crate::printlanguage::SyntaxHighlight::var_color,
                        op_key(op),
                        vn_key(vn),
                    ));
                    return;
                }
                if let Some(addr) = self.globalref.decide(fd, arch, vn, op, off, &ct) {
                    self.push_global_ref_ir(arch, addr, op, vn);
                    return;
                }
                // Constants can carry the completed callable type directly:
                // ActionSetCasts need not allocate a separate CAST. Only this
                // numeric fallback shares the inferred-code display policy;
                // strings, NULL, and symbol/global references above keep theirs.
                let numeric_cast = if self.options.nocasts {
                    None
                } else {
                    self.callable_dialect_code(fd, arch, op, vn, &ct)
                        .and_then(|code| Self::generic_callable_pointer(arch, &ct, code))
                        .or_else(|| Some(ct.clone()))
                };
                if let Some(cast) = &numeric_cast {
                    self.push_cast_open(cast, op);
                }
                self.context.push_mod();
                if !self.context.is_set(modifiers::FORCE_DEC) {
                    self.context.set_mod(modifiers::FORCE_HEX);
                }
                self.push_constant_ir_fmt_sign(off, sz, op, display_format::NONE, false);
                self.context.pop_mod();
                if let Some(cast) = &numeric_cast {
                    self.push_cast_close(cast);
                }
                return;
            }
            // Integer path.  Inside `push_integer` (printc.cc:1376) the varnode
            // high's equate-Symbol format OVERRIDES the read-facing type's format
            // when present.  So: equate-Symbol format wins; otherwise the
            // read-facing type format (e.g. `force datatype octint4 oct` ->
            // `globaloct = 05555`).
            let lit = self.integer_literal(fd, arch, vn, &ct);
            self.push_constant_ir_fmt_sign_flags(
                off,
                sz,
                op,
                lit.display_fmt,
                lit.sign,
                lit.force_unsigned,
                lit.force_sized,
                lit.size_suffix,
            );
            return;
        }
        // HighVariable name resolution (C++ `pushSymbolDetail`: `high->getSymbol()`
        // -> `pushSymbol` -> `sym->getDisplayName()`).  The merged tree binds the
        // angr default name directly on the HighVariable (`ActionNameVars` ->
        // `HighVariable::kuna_name`; the W4 `Symbol`/ScopeLocal stand-in), so a
        // named high renders its bound `vN` name here — for *every* member, which
        // is exactly how the C++ renders all instances of a merged local.
        if let Some(high) = v.get_high() {
            let named = self.emitted_high_symbol(fd, high);
            if let Some((name, sym_off, sym_type)) = named {
                // Symbol-mapped struct/union member access (C++ `PrintC::
                // pushSymbolDetail` -> `pushPartialSymbol`, printlanguage.cc:256-258
                // + printc.cc:2019-2141).  When the mapped Symbol's data-type is a
                // composite (a UNION that resolves to a field for this op, or a
                // STRUCT whose member contains the access) the varnode is a partial
                // cover of the larger Symbol and renders `name.field` /
                // `name.b.bval1` rather than its raw name.  This is GUARDED tightly:
                // it fires only when the type walk genuinely yields a member token,
                // so a non-partial-cover read (the common case) is byte-unchanged
                // and falls straight through to the bare-name render below.
                if let Some(st) = &sym_type {
                    let mt = st.get_metatype();
                    // C++ `pushSymbolDetail` (printlanguage.cc:256-258) routes EVERY
                    // composite-cover access through `pushPartialSymbol`, whose walk
                    // descends array/struct/union members uniformly.  The rust leaf
                    // render handled STRUCT/UNION here but split ARRAY off into a
                    // dedicated `name[index]` branch below, which computes
                    // `index = symboloff / elementAlignSize` WITHOUT consulting the
                    // access size — so an 8-byte write at offset 0 of an
                    // `undefined1[16]` rendered `v1[0] = a0`, claiming a one-byte
                    // store.  The walk's own ARRAY arm has the upstream
                    // `TypeArray::getSubEntry` guard (`noff + sz <= elsize`) and
                    // falls to the artificial `._<off>_<size>_` member when the
                    // access spans elements, so routing a plain ARRAY through it
                    // too both keeps `arr[3]` for a genuine in-element access and
                    // repairs the size-losing ones to `v1._0_8_`.  It also lets an
                    // array whose element needs union resolution (`simpunion
                    // arr[10]`, the `arr[3].ffield` access) descend past the
                    // subscript into the cached union field.  A whole-symbol cover
                    // still returns `false` and falls through to the branch below.
                    if mt == crate::dtype::type_metatype::TYPE_STRUCT
                        || mt == crate::dtype::type_metatype::TYPE_UNION
                        || mt == crate::dtype::type_metatype::TYPE_ARRAY
                    {
                        // C++ `pushSymbolDetail`: `isRead` is true when `op` reads
                        // `vn` (the input slot); false when `vn` is the output (the
                        // assignment LHS), where the artificial slot is -1.
                        let is_out =
                            fd.obank().get(op).and_then(|o| o.get_out()) == Some(vn);
                        let is_read = !is_out;
                        let inslot = if is_read {
                            fd.obank().get(op).map(|o| o.get_slot(vn)).unwrap_or(-1)
                        } else {
                            -1
                        };
                        // `symboloff` is the in-symbol byte offset; C++ resets a -1
                        // (whole-symbol) offset to 0 before the partial walk when the
                        // type needs resolution (printlanguage.cc:249-255).
                        let symoff = if sym_off < 0 { 0 } else { sym_off };
                        if self.push_partial_symbol_ir(
                            fd,
                            arch,
                            &name,
                            st.clone(),
                            symoff as int8,
                            v.get_size(),
                            vn,
                            op,
                            inslot,
                            is_read,
                        ) {
                            return;
                        }
                    }
                }
                // Array/struct member access: if the mapped Symbol is an array and
                // the access is at a non-base offset (or the symbol is strictly
                // larger than the access), render `name[index]` (C++
                // `PrintC::pushSymbolDetail`'s array branch).
                if let Some(st) = &sym_type {
                    if st.get_metatype() == crate::dtype::type_metatype::TYPE_ARRAY {
                        if let Some(elem) = st.get_array_base() {
                            // C++ `TypeArray::getSubEntry` (type.cc:1430-1434)
                            // strides by the element's *aligned* size, not its raw
                            // size: e.g. a 10-byte `float10` occupies 16 bytes per
                            // element, so `ldarr[1]` lives at byte offset 0x10.
                            let elsize = elem.get_align_size().max(1);
                            // The access maps to element `index` when it lies
                            // within the array and the offset divides the element.
                            if sym_off >= 0 && (sym_off % elsize) == 0 && st.get_size() > elsize {
                                let index = sym_off / elsize;
                                // `name[index]` via the subscript op-token.
                                self.push_op(&tokens::SUBSCRIPT, Some(op_key(op)));
                                self.push_atom(&Atom::with_op_vn(
                                    name,
                                    TagType::VarToken,
                                    crate::printlanguage::SyntaxHighlight::var_color,
                                    op_key(op),
                                    vn_key(vn),
                                ));
                                // C++ `pushPartialSymbol` ARRAY arm renders the index
                                // via `push_integer(el, 0, (el < 0), syntax, 0, op, 0)`
                                // (printc.cc:2132), so the subscript follows the
                                // `val<=10 -> dec` / `mostNaturalBase` hex/dec rule —
                                // not an unconditional decimal.  Without this an index
                                // whose natural base is 16 (e.g. `arr[0xb]`) lost the
                                // oracle's hex rendering.
                                let sign = index < 0;
                                self.push_constant_ir_fmt_sign(
                                    index as uintb,
                                    0,
                                    op,
                                    display_format::NONE,
                                    sign,
                                );
                                return;
                            }
                        }
                    }
                }
                // Scalar partial-cover access (C++ `pushSymbolDetail`,
                // printlanguage.cc:256-258): when a Varnode reads only PART of a
                // mapped SCALAR Symbol — `symboloff + vn->getSize() <=
                // sym->getType()->getSize()` and the access is NOT the whole symbol
                // — C++ routes it through `pushPartialSymbol`, NOT a bare name.  For
                // an int4/int2 sub-access of a tied int8 stack `local` (the
                // `mergeAddrTied`/`groupWith` partial-field members of LOSS-245),
                // `pushPartialSymbol`'s scalar arms render `(int4)local` (a
                // SUBPIECE-style `finalcast` for an off-0 truncation, printc.cc:2094-
                // 2105) or `local._2_2_` (the artificial `unnamedField` token for a
                // non-zero offset, printc.cc:2106-2117).  The composite branches above
                // already covered STRUCT/UNION/ARRAY symbols; this adds the scalar leaf
                // the C++ `pushSymbolDetail` treats identically.  `allowCast == isRead`
                // (the input slot is a read; the assignment LHS is an output), matching
                // the C++ `inslot`/`isRead` derivation.
                if let Some(st) = &sym_type {
                    let mt = st.get_metatype();
                    let is_composite = matches!(
                        mt,
                        crate::dtype::type_metatype::TYPE_STRUCT
                            | crate::dtype::type_metatype::TYPE_UNION
                            | crate::dtype::type_metatype::TYPE_ARRAY
                    );
                    let symoff = if sym_off < 0 { 0 } else { sym_off };
                    let asize = v.get_size();
                    // The C++ `pushSymbolDetail` gate (printlanguage.cc:256): the
                    // access fits within the symbol type and is a genuine PARTIAL
                    // (off > 0 or strictly narrower) — a whole-symbol cover keeps the
                    // bare name below (and `push_partial_symbol_ir` returns false for
                    // it anyway, so this is a no-op for the common full-width read).
                    let is_partial = symoff > 0 || asize < st.get_size();
                    if !is_composite
                        && is_partial
                        && (symoff as int8) + (asize as int8) <= st.get_size() as int8
                    {
                        let is_out =
                            fd.obank().get(op).and_then(|o| o.get_out()) == Some(vn);
                        let is_read = !is_out;
                        let inslot = if is_read {
                            fd.obank().get(op).map(|o| o.get_slot(vn)).unwrap_or(-1)
                        } else {
                            -1
                        };
                        if self.push_partial_symbol_ir(
                            fd,
                            arch,
                            &name,
                            st.clone(),
                            symoff as int8,
                            asize,
                            vn,
                            op,
                            inslot,
                            is_read,
                        ) {
                            return;
                        }
                    }
                }
                self.push_atom(&Atom::with_op_vn(
                    name,
                    TagType::VarToken,
                    crate::printlanguage::SyntaxHighlight::var_color,
                    op_key(op),
                    vn_key(vn),
                ));
                return;
            }
        }
        // No bound name: fall to the register / unnamed-location naming, which is
        // the faithful `pushUnnamedLocation` tail (printc.cc:1957-1974).
        //
        // (kuna) C++ `PrintC::pushSymbolDetail` renders EVERY member of a
        // HighVariable through `high->getSymbol()` — one shared name for the whole
        // variable.  A HighVariable that copy-shadow-merges a register/`unique`
        // scratch value with an addr-tied persistent GLOBAL — the `global =
        // COPY(reg)` store folded into the global's high, exactly as upstream's
        // variable-merge does (Ghidra's `goal_width` phi has all-register-EAX inputs
        // that every carry `hv=goal_width`) — therefore renders as the GLOBAL at
        // every member, never as the raw register.  kuna instead renders an unnamed
        // location from the *member's own* address, so a register/`unique` member of
        // such a mixed high would leak a stray `EAX` / `Unique<hex>`.  Mirror the C++
        // `getSymbol()` behavior: resolve the member to its high's canonical global
        // storage first — if any instance of this high lives at a real memory global
        // (a non-register `IPTR_PROCESSOR` address that renders `dat_<addr>`), render
        // THIS member from that global's (address,size) so the whole variable reads
        // one `dat_<addr>`.  A leaf that is itself a global, or whose high owns no
        // global member (an ordinary register/`unique` temp), is unaffected.
        let renders_as_global = |a: &kuna_base::address::Address, sz: int4| -> bool {
            match a.get_space() {
                Some(s) => {
                    arch.translate().get_register_name(s, a.get_offset(), sz).is_empty()
                        && kuna_global_naming(s)
                }
                None => false,
            }
        };
        let mut loc = v.get_addr().clone();
        let mut size = v.get_size();
        let mut stack_pointer_storage = false;
        if let Some(h) = v.get_high() {
            if let Some(hv) = fd.high_bank().get(h) {
                for i in 0..hv.num_instances() {
                    let ivn = hv.get_instance(i);
                    if let Some(iv) = fd.vbank().get(ivn) {
                        if iv.is_spacebase() && iv.is_input() && iv.is_unaffected() {
                            loc = iv.get_addr().clone();
                            size = iv.get_size();
                            stack_pointer_storage = true;
                            break;
                        }
                    }
                }
            }
        }
        if !stack_pointer_storage && !renders_as_global(&loc, size) {
            if let Some(h) = v.get_high() {
                if let Some(hv) = fd.high_bank().get(h) {
                    for i in 0..hv.num_instances() {
                        let ivn = hv.get_instance(i);
                        if let Some(iv) = fd.vbank().get(ivn) {
                            if iv.is_addr_tied() && renders_as_global(iv.get_addr(), iv.get_size()) {
                                loc = iv.get_addr().clone();
                                size = iv.get_size();
                                break;
                            }
                        }
                    }
                }
            }
        }
        let name = match if stack_pointer_storage {
            kuna_storage_location_name(&loc)
        } else {
            kuna_unnamed_location_name(arch, &loc, size)
        } {
            Some(n) => n,
            None => return,
        };
        self.push_atom(&Atom::with_op_vn(
            name,
            TagType::VarToken,
            crate::printlanguage::SyntaxHighlight::special_color,
            op_key(op),
            vn_key(vn),
        ));
    }

    /// C++ `PrintC::opPtrsub` (printc.cc:953).  `&ptr->field` / `ptr->field`
    /// (struct member) or `*ptr` / `ptr[0]` (array element), absorbing or emitting
    /// the dereference per the load/store value mods and the `&base[index]` flex.
    ///
    /// The SPACEBASE arm (a PTRSUB off a stack/global spacebase, requiring the
    /// Symbol/ScopeLocal surface) and the union arm are not on the pointer/array/
    /// struct corpus; they fall through to a functional render.
    /// STUB(W4 spacebase symbol) / STUB(W8 union).
    /// C++ `PrintC::pushTypePointerRel` (printc.hh:372-377): a PTRSUB acting
    /// relative to a `TypePointerRel` parent prints the `ADJ(...)` macro — a
    /// `function_call` op wrapping the `ADJ` token (rendered `funcname_color`).
    fn push_type_pointer_rel_ir(&mut self, op: OpId) {
        self.push_op(&tokens::FUNCTION_CALL, Some(op_key(op)));
        // The token is pushed as an *operator* token (C++ `optoken`), but with
        // funcname_color (matching the C++ Atom(typePointerRelToken,optoken,
        // funcname_color,op)).
        self.push_atom(&Atom::with_op(
            self.lang().kw_type_pointer_rel.to_string(),
            TagType::OpToken,
            crate::printlanguage::SyntaxHighlight::funcname_color,
            op_key(op),
        ));
    }

    /// The `symbol == 0` arm of C++ `PrintC::opPtrsub` (printc.cc:1096-1101): a
    /// spacebase `PTRSUB` whose offset no Symbol covers renders as the *storage*
    /// it names — `TypeSpacebase::getAddress(in1const, ptrsize, op->getAddr())`
    /// (type.cc:3542) pushed through `pushUnnamedLocation`, under the `&` the
    /// caller's value modifiers ask for.
    ///
    /// `sb_type` is the `TYPE_SPACEBASE` data-type `in0` points to.  A spacebase
    /// carrying no space (a hand-built fixture) is the one case with no storage to
    /// name; it keeps the functional render.
    fn push_spacebase_unnamed_ir(
        &mut self,
        fd: &Funcdata,
        arch: &Architecture,
        op: OpId,
        sb_type: &crate::dtype::TypeRoot,
        in1const: uintb,
        ptr_size: int4,
        valueon: bool,
    ) {
        let name = spacebase_unnamed_address(arch, fd, op, sb_type, in1const, ptr_size)
            .and_then(|loc| kuna_unnamed_location_name(arch, &loc, ptr_size));
        let name = match name {
            Some(n) => n,
            None => {
                self.op_func_ir(fd, arch, op);
                return;
            }
        };
        if !valueon {
            // EMIT  &name  (printc.cc:1091)
            let tok = self.lang_token(&tokens::ADDRESSOF);
            self.push_op(tok, Some(op_key(op)));
        }
        self.push_atom(&Atom::with_op(
            name,
            TagType::VarToken,
            crate::printlanguage::SyntaxHighlight::special_color,
            op_key(op),
        ));
    }

    /// (kuna `globalref`) `&dat_<addr>`: the address of the global a constant
    /// pointer names, in place of the `(T *)0x<addr>` cast.
    fn push_global_ref_ir(&mut self, arch: &Architecture, addr: u64, op: OpId, vn: VarnodeId) {
        let tok = self.lang_token(&tokens::ADDRESSOF);
        self.push_op(tok, Some(op_key(op)));
        self.push_atom(&Atom::with_op_vn(
            kuna_global_data_name(arch.kuna_name_style(), addr),
            TagType::VarToken,
            crate::printlanguage::SyntaxHighlight::special_color,
            op_key(op),
            vn_key(vn),
        ));
    }

    /// (kuna `globalref`) The plan of the last function printed: the globals it
    /// names by address, authenticated named symbols, and unnamed direct data.
    pub fn globalref_plan(&self) -> &crate::kuna_globalref::Plan {
        &self.globalref
    }

    fn op_ptrsub_ir(&mut self, fd: &Funcdata, arch: &Architecture, op: OpId) {
        let in0 = match fd.obank().get(op).and_then(|o| o.get_in(0)) {
            Some(v) => v,
            None => return,
        };
        let in1const = fd
            .obank()
            .get(op)
            .and_then(|o| o.get_in(1))
            .and_then(|v| fd.vbank().get(v))
            .map(|v| v.get_offset())
            .unwrap_or(0);
        // ptype = in0->getHighTypeReadFacing(op)  (== get_type for the non-union corpus).
        let ptype = match fd.vbank().get(in0).map(|v| v.get_type().clone()) {
            Some(t) => t,
            None => return,
        };
        let ptype = if ptrsub_resolves(&ptype) {
            ptype
        } else {
            high_pointer_type(fd, in0).filter(|t| ptrsub_resolves(t)).unwrap_or(ptype)
        };
        if ptype.get_metatype() != crate::dtype::type_metatype::TYPE_PTR {
            // C++ throws; fall to the functional render so output stays parseable.
            self.op_func_ir(fd, arch, op);
            return;
        }
        // Relative-pointer parent resolution.
        let is_rel = ptype.is_formal_pointer_rel()
            && ptype.evaluate_thru_parent(in1const) == Some(true);
        let ct = if is_rel {
            ptype.get_rel_parent()
        } else {
            ptype.get_ptr_to()
        };
        let ct = match ct {
            Some(c) => c,
            None => return,
        };
        let ptr_size = fd.vbank().get(in0).map(|v| v.get_size()).unwrap_or(8);
        let m = self.context.mods()
            & !(modifiers::PRINT_LOAD_VALUE | modifiers::PRINT_STORE_VALUE);
        let mut valueon = (self.context.mods()
            & (modifiers::PRINT_LOAD_VALUE | modifiers::PRINT_STORE_VALUE))
            != 0;
        let flex = self.is_value_flexible_ir(fd, in0);
        let word_size = ptype.get_word_size().unwrap_or(1);
        let metameta = ct.get_metatype();

        if metameta == crate::dtype::type_metatype::TYPE_STRUCT
            || metameta == crate::dtype::type_metatype::TYPE_UNION
        {
            // suboff = (int4)in1const  (+ relative offset).
            let mut suboff = in1const as int4 as int8;
            if is_rel {
                let addr_off = ptype.get_address_offset().unwrap_or(0) as int8;
                suboff = (((suboff + addr_off) as u64) & calc_mask(ptr_size)) as int8;
                if suboff == 0 {
                    // Special case where we do not print a field (printc.cc:988).
                    self.push_type_pointer_rel_ir(op);
                    let mm = if flex { m | modifiers::PRINT_LOAD_VALUE } else { m };
                    self.push_vn_ir_m(fd, arch, in0, op, mm);
                    return;
                }
            }
            let suboff_bytes = AddrSpace::address_to_byte_int(suboff, word_size);
            let (fieldname, fieldtype, fieldid) =
                if metameta == crate::dtype::type_metatype::TYPE_UNION {
                    // TYPE_UNION arm (printc.cc:1000-1014).  A non-zero offset is the
                    // C++ "PTRSUB accesses union with non-zero offset" throw.
                    if suboff_bytes != 0 {
                        // C++ throws; fall to the functional render so output stays
                        // parseable rather than aborting the whole function.
                        self.op_func_ir(fd, arch, op);
                        return;
                    }
                    // The cast plane (`ActionSetCasts::resolveUnion`) stored the
                    // resolution on this PTRSUB's write edge keyed on the
                    // pointer-to-union `ptype`; read it back here.
                    let res_field = fd
                        .get_union_field(&ptype, op, -1)
                        .map(|r| r.get_field_num())
                        .filter(|&n| n >= 0);
                    let field_num = match res_field {
                        Some(n) => n,
                        None => {
                            // C++ throws "PTRSUB for union that does not resolve
                            // to a field"; fall to the functional render.
                            self.op_func_ir(fd, arch, op);
                            return;
                        }
                    };
                    // fld = ((TypeUnion*)ct)->getField(resUnion->getFieldNum());
                    let field = {
                        let view = ct.read();
                        view.get_field(ct.id(), field_num).expect("retained field")
                            .map(|f| (f.name.clone(), Some(ct.related(f.field_type).expect("field type")), f.offset))
                    };
                    match field {
                        Some(f) => f,
                        None => {
                            self.op_func_ir(fd, arch, op);
                            return;
                        }
                    }
                } else {
                    // TYPE_STRUCT arm (printc.cc:1015-1033).
                    // fld = ct->findTruncation(suboff,0,op,0,newoff)
                    let fld = ct.find_truncation(suboff_bytes, 0, op, 0).ok().flatten();
                    match fld {
                        Some((idx, _newoff)) => {
                            let view = ct.read();
                            let f = view.get_field(ct.id(), idx).expect("retained field");
                            match f {
                                Some(f) => (f.name.clone(), Some(ct.related(f.field_type).expect("field type")), f.offset),
                                None => return,
                            }
                        }
                        None => {
                            if ct.get_size() as int8 <= suboff_bytes || suboff_bytes < 0 {
                                self.op_func_ir(fd, arch, op);
                                return;
                            }
                            // Default field name `field_0x<hex>`.
                            (format!("field_0x{suboff_bytes:x}"), None, suboff_bytes as int4)
                        }
                    }
                };
            let mut arrayvalue = false;
            // The '&' is dropped if the field is an array.
            if let Some(ft) = &fieldtype {
                if ft.get_metatype() == crate::dtype::type_metatype::TYPE_ARRAY {
                    arrayvalue = valueon; // If printing value, use [0]
                    valueon = true; // Don't print &
                }
            }
            let field_atom = Atom::field(
                fieldname,
                TagType::FieldToken,
                crate::printlanguage::SyntaxHighlight::no_color,
                ct.clone(),
                fieldid,
                op_key(op),
            );
            if !valueon {
                // Printing an ampersand.
                let tok = self.lang_token(&tokens::ADDRESSOF);
            self.push_op(tok, Some(op_key(op)));
                if flex {
                    // EMIT  &( ).name
                    self.push_op(&tokens::OBJECT_MEMBER, Some(op_key(op)));
                    if is_rel {
                        self.push_type_pointer_rel_ir(op);
                    }
                    self.push_vn_ir_m(fd, arch, in0, op, m | modifiers::PRINT_LOAD_VALUE);
                } else {
                    // EMIT  &( )->name
                    self.push_member_through_pointer(Some(op_key(op)));
                    if is_rel {
                        self.push_type_pointer_rel_ir(op);
                    }
                    self.push_vn_ir_m(fd, arch, in0, op, m);
                }
                self.push_atom(&field_atom);
            } else {
                if arrayvalue {
                    self.push_op(&tokens::SUBSCRIPT, Some(op_key(op)));
                }
                if flex {
                    // EMIT  ( ).name
                    self.push_op(&tokens::OBJECT_MEMBER, Some(op_key(op)));
                    if is_rel {
                        self.push_type_pointer_rel_ir(op);
                    }
                    self.push_vn_ir_m(fd, arch, in0, op, m | modifiers::PRINT_LOAD_VALUE);
                } else {
                    // EMIT  ( )->name
                    self.push_member_through_pointer(Some(op_key(op)));
                    if is_rel {
                        self.push_type_pointer_rel_ir(op);
                    }
                    self.push_vn_ir_m(fd, arch, in0, op, m);
                }
                self.push_atom(&field_atom);
                if arrayvalue {
                    self.push_constant_ir(0, 4, op);
                }
            }
        } else if metameta == crate::dtype::type_metatype::TYPE_ARRAY {
            // PTRSUB(*,0) drilling a pointer-to-array down to its element type.
            if !valueon {
                if flex {
                    // EMIT ( ) — absorb the dereference into in0.
                    if is_rel {
                        self.push_type_pointer_rel_ir(op);
                    }
                    self.push_vn_ir_m(fd, arch, in0, op, m | modifiers::PRINT_LOAD_VALUE);
                } else {
                    // EMIT *( )
                    self.push_op(&tokens::DEREFERENCE, Some(op_key(op)));
                    if is_rel {
                        self.push_type_pointer_rel_ir(op);
                    }
                    self.push_vn_ir_m(fd, arch, in0, op, m);
                }
            } else if flex {
                // EMIT ( )[0]
                self.push_op(&tokens::SUBSCRIPT, Some(op_key(op)));
                if is_rel {
                    self.push_type_pointer_rel_ir(op);
                }
                self.push_vn_ir_m(fd, arch, in0, op, m | modifiers::PRINT_LOAD_VALUE);
                self.push_constant_ir(0, 4, op);
            } else {
                // EMIT (* )[0]
                self.push_op(&tokens::SUBSCRIPT, Some(op_key(op)));
                self.push_op(&tokens::DEREFERENCE, Some(op_key(op)));
                if is_rel {
                    self.push_type_pointer_rel_ir(op);
                }
                self.push_vn_ir_m(fd, arch, in0, op, m);
                self.push_constant_ir(0, 4, op);
            }
        } else if metameta == crate::dtype::type_metatype::TYPE_SPACEBASE {
            // SPACEBASE arm (C++ `PrintC::opPtrsub`, printc.cc:1081-1121).  A
            // `PTRSUB(spacebase, off)` is a `&symbol` reference into a stack/global
            // frame.  `ActionNameVars::linkSpacebaseSymbol` decoded the reference
            // and parked the Symbol on the offset constant's HighVariable
            // (`Funcdata::link_symbol_reference` -> `kuna_name`/`symbol_offset`/
            // `kuna_symbol_type`), so this reads it back here.
            // The kuna stand-in: read the reference triple off in1's high.
            let in1 = fd.obank().get(op).and_then(|o| o.get_in(1));
            let (sym_name, sym_off, sym_type) = match in1.and_then(|v| fd.vbank().get(v)).and_then(|v| v.get_high()) {
                Some(high) => match self.emitted_high_symbol(fd, high) {
                    Some((name, off, ty)) => (Some(name), off, ty),
                    None => (None, -1, None),
                },
                None => (None, -1, None),
            };

            // C++ `opPtrsub` reaches a Symbol here whenever `linkSpacebaseSymbol`
            // attached one, and takes the `symbol == 0` arm otherwise.  In the kuna
            // model `link_symbol_reference` deliberately attaches ONLY a
            // defined-named Symbol (the mapped stack/global vars; an undefined-named
            // auto-local, or a frame whose spacebase could not be tracked to a
            // constant, is left unlinked — see `Funcdata::link_symbol_reference`),
            // so the symbol-less arm is reached far more often than upstream.  It is
            // the C++ `pushUnnamedLocation` leaf: the *storage* named by space and
            // offset (`Stack00000008`), never the functional `PTRSUB(<reg>, off)`
            // form — which is internal p-code leaking an undeclared operator and a
            // raw register name into the emitted C.
            let name = match &sym_name {
                Some(n) => n.clone(),
                None => {
                    self.push_spacebase_unnamed_ir(fd, arch, op, &ct, in1const, ptr_size, valueon);
                    return;
                }
            };

            let name = if self.callable_transport_valid && sym_off <= 0 && sym_type.as_ref()
                .is_some_and(|ty| ty.get_metatype() == type_metatype::TYPE_CODE)
            {
                fd.get_address().get_space().and_then(|space| {
                    let entry = Address::new(space.clone(), kuna_base::space::AddrSpace::address_to_byte(in1const, space.get_word_size()));
                    crate::kuna_callabletransport::pointer_adapter(fd, &entry).ok().flatten().and_then(|(key, family)| {
                        if family.has_execution_signature() { Some(key) } else {
                            fd.get_arch().query_function(&entry).ok().flatten().map(|(name, target, _)|
                                self.emitted_function_name(fd, &name, &target, true))
                        }
                    })
                }).unwrap_or(name)
            } else { name };
            let mut arrayvalue = false; // arrayvalue = false;
            if let Some(st) = &sym_type {
                // ct = symbol->getType(); (symbol != 0 always here)  (printc.cc:1086)
                let mt = st.get_metatype();
                if mt == crate::dtype::type_metatype::TYPE_ARRAY {
                    // The '&' is dropped if the output type is an array.
                    arrayvalue = valueon; // If printing value, use [0]
                    valueon = true; // If printing ptr, don't use &
                } else if mt == crate::dtype::type_metatype::TYPE_CODE {
                    valueon = true; // If printing ptr, don't use &
                }
            }

            // Readonly char-array string-literal coexistence (the kuna analog of
            // C++ `PrintC::pushConstant`'s TYPE_PTR -> `pushPtrCharConstant` arm,
            // printc.cc:1842-1880).  In upstream Ghidra a constant pointer to a
            // readonly char-printable object renders as the quoted literal even
            // when a data Symbol covers the address — the constant reaches
            // `pushConstant` and short-circuits to `pushPtrCharConstant` BEFORE any
            // symbol-name render.  kuna's analysis tier (StringLiteralPass /
            // ActionMapGlobals) instead promotes the same constant into a global
            // SPACEBASE `PTRSUB(spacebase, 0xADDR)` reference whose bound Symbol is
            // the planted `char[N]`, so the value arrives at THIS arm rather than
            // the `pushConstant` pointer arm — and the bare `pushSymbol` name
            // (`s_400915`) would SHADOW the literal.  To keep the data Symbol and
            // the literal coexisting (the Ghidra-observable behavior), route a
            // whole-symbol (`sym_off == 0`), pointer-value (`!arrayvalue`) reference
            // whose Symbol is a READONLY char-printable ARRAY through the same
            // `push_ptr_char_constant_ir` literal path the constant arm uses.
            // Guarded TIGHTLY (readonly + TYPE_ARRAY + char-printable element +
            // off==0 + printing-ptr) so every other symbol reference renders
            // EXACTLY as before — the XML datatest corpus never reaches this branch
            // with a readonly char-array spacebase symbol.
            if sym_off == 0 && !arrayvalue {
                if let Some(st) = &sym_type {
                    if st.get_metatype() == crate::dtype::type_metatype::TYPE_ARRAY {
                        if let Some(elem) = st.get_array_base() {
                            if elem.is_char_print() {
                                let point = fd
                                    .obank()
                                    .get(op)
                                    .map(|o| o.get_addr().clone())
                                    .unwrap_or_default();
                                if self.push_ptr_char_constant_ir(
                                    arch,
                                    in1const,
                                    ptr_size,
                                    &elem,
                                    &point,
                                    op,
                                    in1.unwrap_or_default(),
                                ) {
                                    return;
                                }
                            }
                        }
                    }
                }
            }

            if !valueon {
                // EMIT  &name  (printc.cc:1095)
                let tok = self.lang_token(&tokens::ADDRESSOF);
            self.push_op(tok, Some(op_key(op)));
            } else if arrayvalue {
                // EMIT  name  with a trailing subscript (printc.cc:1099)
                self.push_op(&tokens::SUBSCRIPT, Some(op_key(op)));
            }

            // int4 off = high->getSymbolOffset();  (printc.cc:1108)
            // off == 0 takes the bare `pushSymbol` arm; a `-1` `symboloffset` (the
            // whole-symbol cover the C++ `setSymbol` records for a size-matching
            // entry) is also a bare-name render, so `off <= 0` covers both.
            if sym_off <= 0 {
                // off == 0: pushSymbol(symbol, 0, op) — the bare name.
                let atom = match in1 {
                    Some(vn) => Atom::with_op_vn(
                        name.clone(),
                        TagType::VarToken,
                        crate::printlanguage::SyntaxHighlight::var_color,
                        op_key(op),
                        vn_key(vn),
                    ),
                    None => Atom::with_op(
                        name.clone(),
                        TagType::VarToken,
                        crate::printlanguage::SyntaxHighlight::var_color,
                        op_key(op),
                    ),
                };
                self.push_atom(&atom);
            } else {
                // off != 0: pushPartialSymbol(symbol, off, 0, 0, op, -1, false) —
                // `name.field` (printc.cc:1116).
                let st = sym_type.clone();
                let pushed = if let Some(st) = st {
                    self.push_partial_symbol_ir(
                        fd,
                        arch,
                        &name,
                        st,
                        sym_off as int8,
                        0,
                        in1.unwrap_or_default(),
                        op,
                        -1,
                        false,
                    )
                } else {
                    false
                };
                if !pushed {
                    // The partial walk produced no member token (a whole-symbol
                    // cover): render the bare name, matching `pushPartialSymbol`'s
                    // degenerate base case.
                    let atom = match in1 {
                        Some(vn) => Atom::with_op_vn(
                            name.clone(),
                            TagType::VarToken,
                            crate::printlanguage::SyntaxHighlight::var_color,
                            op_key(op),
                            vn_key(vn),
                        ),
                        None => Atom::with_op(
                            name.clone(),
                            TagType::VarToken,
                            crate::printlanguage::SyntaxHighlight::var_color,
                            op_key(op),
                        ),
                    };
                    self.push_atom(&atom);
                }
            }

            if arrayvalue {
                // The `[0]` subscript index.
                self.push_constant_ir(0, 4, op);
            }
        } else {
            // Union/other: functional fallback.
            self.op_func_ir(fd, arch, op);
        }
    }

    /// C++ `isValueFlexible(vn)` (printc.cc:919): the value `vn` is an implied
    /// PTRSUB/PTRADD result (possibly through a COPY) and so can absorb a
    /// dereference.
    fn is_value_flexible_ir(&self, fd: &Funcdata, vn: VarnodeId) -> bool {
        let v = match fd.vbank().get(vn) {
            Some(v) => v,
            None => return false,
        };
        if !(v.is_implied() && v.is_written()) {
            return false;
        }
        let def = match v.get_def() {
            Some(d) => d,
            None => return false,
        };
        let mut opc = fd.obank().get(def).map(|o| o.code()).unwrap_or(OpCode::CPUI_MAX);
        if opc == OpCode::CPUI_COPY {
            let invn = match fd.obank().get(def).and_then(|o| o.get_in(0)) {
                Some(v) => v,
                None => return false,
            };
            let iv = match fd.vbank().get(invn) {
                Some(v) => v,
                None => return false,
            };
            if !iv.is_implied() || !iv.is_written() {
                return false;
            }
            opc = iv
                .get_def()
                .and_then(|d| fd.obank().get(d).map(|o| o.code()))
                .unwrap_or(OpCode::CPUI_MAX);
        }
        opc == OpCode::CPUI_PTRSUB || opc == OpCode::CPUI_PTRADD
    }

    /// Widening an AND mask is harmless only when its result is consumed
    /// exclusively as a zero/nonzero test, not by arithmetic or signed ordering.
    fn enum_mask_is_zero_test(fd: &Funcdata, op: OpId) -> bool {
        let Some(mask) = fd.obank().get(op).filter(|o| o.code() == OpCode::CPUI_INT_AND)
            else { return false };
        let Some(output) = mask.get_out() else { return false };
        if !fd.vbank().get(output).is_some_and(|v| v.is_implied()) { return false; }
        let Some(reader) = fd.lone_descend(output).and_then(|id| fd.obank().get(id))
            else { return false };
        if reader.code() == OpCode::CPUI_CBRANCH {
            return reader.get_in(1) == Some(output);
        }
        matches!(reader.code(), OpCode::CPUI_INT_EQUAL | OpCode::CPUI_INT_NOTEQUAL)
            && [0, 1].into_iter().any(|slot| {
                reader.get_in(slot).and_then(|id| fd.vbank().get(id))
                    .is_some_and(|v| v.is_constant() && v.get_offset() == 0)
            })
    }

    /// Render named enum combinations at their declared width and signedness.
    /// Complements account for C integer promotion; partial enums normalize
    /// the parent before shifting, then preserve the projected result type.
    fn push_enum_constant_ir(
        &mut self, types: &dyn crate::dtype::TypeFactory,
        ct: &crate::dtype::TypeRoot, val: uintb, op: OpId, vn: VarnodeId,
        mask_zero_test: bool,
    ) {
        // C++ `ct->getMatches(val, rep)` (printc.cc:1740).  Our `get_matches`
        // returns a Result (the Err is the non-enum invariant); the dispatch
        // only reaches here for an `is_enum_type()` data-type, so a `getMatches`
        // failure means a corrupt enum kind — fall back to the raw integer.
        let rep = match ct.get_matches(val) {
            Ok(rep) => rep,
            Err(_) => {
                self.push_constant_ir_fmt(val, ct.get_size(), op, ct.get_display_format());
                return;
            }
        };
        if !rep.match_name.is_empty() {
            let parent = ct.get_partial_base();
            let rust = self.lang().forms.cast == crate::kuna_lang::CastForm::PostfixAs;
            let integer_size = types.get_size_of_int();
            let source = parent.as_ref().unwrap_or(ct);
            let widen = rep.complement
                && (rust || integer_size <= 0 || source.get_size() > integer_size);
            let normalize = if rep.complement {
                !rust && (integer_size <= 0
                    || (source.get_size() <= integer_size
                        && (parent.is_some() || ct.get_metatype() == type_metatype::TYPE_UINT)))
            } else {
                parent.as_ref().is_some_and(|parent| {
                    let shifted = val.wrapping_shl(rep.shift_amount as u32);
                    let sign_bit = calc_mask(parent.get_size()) ^ (calc_mask(parent.get_size()) >> 1);
                    rust || (parent.get_metatype() == type_metatype::TYPE_INT && shifted & sign_bit != 0)
                        || (!mask_zero_test && parent.get_size() == ct.get_size())
                        || (val == 0 && rep.shift_amount != 0
                            && (integer_size <= 0 || rep.shift_amount >= 8 * integer_size))
                })
            };
            let width = if let Some(parent) = parent.as_ref().filter(|_| widen || normalize) {
                types.get_base_no_char(parent.get_size(), type_metatype::TYPE_UINT)
                    .expect("partial enum has an integer parent width")
            } else {
                ct.clone()
            };
            // Even an exact widened value can change a signed comparison.
            // Only a non-complement mask tested for zero can ignore that type.
            let piece = parent.as_ref().filter(|parent| {
                parent.get_size() != ct.get_size()
                    && (rust || rep.complement || !mask_zero_test)
            }).map(|_| {
                types.get_base_no_char(ct.get_size(), type_metatype::TYPE_UINT)
                    .expect("partial enum has an integer piece width")
            });
            if let Some(piece) = &piece {
                self.push_cast_open(piece, op);
            }
            if rep.shift_amount != 0 {
                self.push_op(&tokens::SHIFT_RIGHT, Some(op_key(op)));
            }
            // The outer cast restores narrow widths after C integer promotion.
            if normalize {
                self.push_cast_open(&width, op);
            }
            if rep.complement {
                let tok = self.lang_token(&tokens::BITWISE_NOT);
                self.push_op(tok, Some(op_key(op)));
                // Widen before complementing too: a 64-bit enum's individual
                // C enumerator can have only a 32-bit unsigned type.
                if widen {
                    self.push_cast_open(&width, op);
                }
            }
            // printc.cc:1746-1747 — `for(i=size-1;i>0;--i) pushOp(&enum_cat,op);`
            // one `|` op per gap between the matched names.
            for _ in 1..rep.match_name.len() {
                self.push_op(&tokens::ENUM_CAT, Some(op_key(op)));
            }
            // printc.cc:1748-1749 — the flag-name atoms in forward order.  The
            // C++ uses `Atom(name,tag,const_color,op,vn,val)` with `tag =
            // vartoken` (the tag pushVnExplicit threaded into pushConstant); for
            // a non-casetoken tag the 6-arg ctor stores the Varnode (not val).
            for name in &rep.match_name {
                self.push_atom(&Atom::with_value(
                    name.clone(),
                    TagType::VarToken,
                    crate::printlanguage::SyntaxHighlight::const_color,
                    op_key(op),
                    vn_key(vn),
                    val,
                ));
            }
            if widen {
                self.push_cast_close(&width);
            }
            if normalize {
                self.push_cast_close(&width);
            }
            // The `>> 0x20` shift amount, rendered as a 4-byte unsigned literal,
            // no format (printc.cc:1750-1751).
            if rep.shift_amount != 0 {
                self.push_constant_ir_fmt(rep.shift_amount as uintb, 4, op, display_format::NONE);
            }
            if let Some(piece) = &piece {
                self.push_cast_close(piece);
            }
        } else {
            // printc.cc:1753-1754 — no named representation: the raw integer with
            // the enum's display format.
            self.push_constant_ir_fmt(val, ct.get_size(), op, ct.get_display_format());
        }
    }

    pub(crate) fn push_constant_ir(&mut self, val: uintb, sz: int4, op: OpId) {
        self.push_constant_ir_fmt(val, sz, op, display_format::NONE);
    }

    /// As [`push_constant_ir`](Self::push_constant_ir) but with the caller-resolved
    /// `displayFormat` override (C++ `push_integer`'s `displayFormat` argument,
    /// printc.cc:1360/1394).  A non-`NONE` `display_fmt_in` is the
    /// `vn->getHigh()->getSymbol()->getDisplayFormat()` value (the `force varnode`
    /// equate Symbol); it wins over the `val<=10`/`mostNaturalBase` default exactly
    /// as in [`resolve_integer_format`].
    fn push_constant_ir_fmt(&mut self, val: uintb, sz: int4, op: OpId, display_fmt_in: u32) {
        self.push_constant_ir_fmt_sign(val, sz, op, display_fmt_in, false);
    }

    /// As [`push_constant_ir_fmt`](Self::push_constant_ir_fmt) but threading the
    /// signedness the way C++ `PrintC::pushConstant` (printc.cc:1813) does: it
    /// switches on the constant's read-facing data-type metatype and calls
    /// `push_integer(..., sign, ...)` with `sign = (metatype == TYPE_INT)`
    /// (printc.cc:1832 vs. the `TYPE_UINT`/`TYPE_UNKNOWN` arms at 1824/1835 which
    /// pass `false`).  `push_integer` (printc.cc:1381-1391) then strips a set top
    /// bit into a leading `-` and the two\'s-complement magnitude, so a negative
    /// signed convert/equate constant renders `-512` / `-0xbb8` / `-0333` /
    /// `-0b...` rather than its full unsigned bit pattern.  `force_char` short-
    /// circuits the sign (printc.cc:1381), preserving the `L\'a\'` char convert.
    pub(crate) fn push_constant_ir_fmt_sign(
        &mut self,
        val: uintb,
        sz: int4,
        op: OpId,
        display_fmt_in: u32,
        sign: bool,
    ) {
        self.push_constant_ir_fmt_sign_flags(val, sz, op, display_fmt_in, sign, false, false, "");
    }

    /// As [`push_constant_ir_fmt_sign`](Self::push_constant_ir_fmt_sign) but
    /// threading the Varnode's `isUnsignedPrint()`/`isLongPrint()` flags, exactly
    /// as C++ `PrintC::push_integer` (printc.cc:1378-1379) reads them from the
    /// `vn` argument.  `force_unsigned` appends the `U` suffix and `force_sized`
    /// appends `size_suffix` (the `sizeSuffix` member, "LL"/"L", printc.cc:1430-
    /// 1433).  C++ clears `force_unsigned_token` when the value is printed signed
    /// (printc.cc:1387) — i.e. when `sign` is set and the format is not
    /// `force_char` — so this mirrors that gate before emitting the `U`.
    #[allow(clippy::too_many_arguments)]
    fn push_constant_ir_fmt_sign_flags(
        &mut self,
        val: uintb,
        sz: int4,
        op: OpId,
        display_fmt_in: u32,
        sign: bool,
        force_unsigned: bool,
        force_sized: bool,
        size_suffix: &str,
    ) {
        let tok = self.integer_token(val, sz, display_fmt_in, sign, force_unsigned, force_sized, size_suffix);
        self.push_atom(&Atom::with_op(
            tok,
            TagType::Syntax,
            crate::printlanguage::SyntaxHighlight::const_color,
            op_key(op),
        ));
    }

    /// The format, sign and suffixes the integer path of
    /// [`push_vn_explicit_ir`](Self::push_vn_explicit_ir) prints the constant `vn`
    /// with, whose read-facing type is `ct`.
    fn integer_literal(
        &self,
        fd: &Funcdata,
        arch: &Architecture,
        vn: VarnodeId,
        ct: &crate::dtype::TypeRoot,
    ) -> IntegerLiteral {
        let sym_fmt = fd.vn_high_display_format(vn);
        let display_fmt = if sym_fmt != display_format::NONE {
            sym_fmt
        } else {
            ct.get_display_format()
        };
        // C++ `pushConstant` (printc.cc:1817-1835) selects the `push_integer`
        // `sign` from the read-facing metatype: TYPE_INT -> signed
        // (printc.cc:1832), TYPE_UINT/TYPE_UNKNOWN -> unsigned (1824/1835).
        // The float/enum/char arms are dispatched before this path, so a plain
        // integer constant rendered here is signed exactly when its type is
        // TYPE_INT — which is what makes a negative `recv_signed(int4)` convert
        // constant print `-512` instead of its unsigned bit pattern.
        let sign = ct.get_metatype() == crate::dtype::type_metatype::TYPE_INT;
        // C++ `push_integer` (printc.cc:1378-1379) reads the explicit-print
        // flags off the Varnode: `isUnsignedPrint()` -> a `U` suffix,
        // `isLongPrint()` -> the `sizeSuffix` ("LL"/"L").  These are set by
        // `CastStrategy::markExplicitUnsigned`/`markExplicitLongSize` during
        // ActionSetCasts; without threading them here the `(val & 1U)` /
        // `<long>L` literals lose their suffix.
        // (kuna outlang) The `U`/`L`/`LL` suffixes are C's way of pinning a
        // literal's type in an expression. A language that infers the literal
        // type has no spelling for them, and inventing one (Rust `u32`) would
        // assert a width this site does not know. Suppressed, not translated.
        let (force_unsigned, force_sized) = if self.lang().caps.integer_suffixes {
            fd.vbank()
                .get(vn)
                .map(|v| (v.is_unsigned_print(), v.is_long_print()))
                .unwrap_or((false, false))
        } else {
            (false, false)
        };
        // C++ `sizeSuffix` (printc.cc:2412-2415): "LL" when long and int are
        // the same width, otherwise "L".
        let size_suffix = if force_sized {
            if arch.types().get_size_of_long() == arch.types().get_size_of_int() {
                "LL"
            } else {
                "L"
            }
        } else {
            ""
        };
        IntegerLiteral { display_fmt, sign, force_unsigned, force_sized, size_suffix }
    }

    /// (kuna `castternary`) The token the constant `vn` prints as where `op`
    /// reads it, when it takes the integer path of
    /// [`push_vn_explicit_ir`](Self::push_vn_explicit_ir).
    fn integer_constant_token(
        &self,
        fd: &Funcdata,
        arch: &Architecture,
        vn: VarnodeId,
        op: OpId,
    ) -> Option<String> {
        use crate::dtype::type_metatype::{TYPE_INT, TYPE_UINT};
        let v = fd.vbank().get(vn)?;
        if !v.is_constant() || v.is_annotation() {
            return None;
        }
        let ct = v.get_type_read_facing(op).clone();
        if ct.is_enum_type() || ct.is_char_print() || !matches!(ct.get_metatype(), TYPE_INT | TYPE_UINT) {
            return None;
        }
        let lit = self.integer_literal(fd, arch, vn, &ct);
        Some(self.integer_token(
            v.get_offset(),
            v.get_size(),
            lit.display_fmt,
            lit.sign,
            lit.force_unsigned,
            lit.force_sized,
            lit.size_suffix,
        ))
    }

    /// The token [`push_constant_ir_fmt_sign_flags`](Self::push_constant_ir_fmt_sign_flags)
    /// prints for an integer constant under the current modifiers.
    #[allow(clippy::too_many_arguments)]
    fn integer_token(
        &self,
        val: uintb,
        sz: int4,
        display_fmt_in: u32,
        sign: bool,
        force_unsigned: bool,
        force_sized: bool,
        size_suffix: &str,
    ) -> String {
        let force_dec = self.context.is_set(modifiers::FORCE_DEC);
        let force_hex = self.context.is_set(modifiers::FORCE_HEX);
        // C++ `push_integer` (printc.cc:1387): the `U` suffix is suppressed when
        // the constant is rendered as signed (sign && displayFormat != force_char).
        let signed_render = sign && display_fmt_in != display_format::FORCE_CHAR;
        let force_unsigned = force_unsigned && !signed_render;
        let (print_negsign, val, display_fmt) =
            resolve_integer_format(val, sz, sign, display_fmt_in, force_hex, force_dec);
        // C++ `push_integer` (printc.cc:1417) gates the wide-char `L` prefix on
        // `doEmitWideCharPrefix()` (always true for PrintC) AND `sz > 1`.  The
        // earlier port passed `false` here, dropping the `L` from a size>1
        // force_char constant (e.g. the convert `L'a'` equate on a size-4 char).
        // (kuna outlang) A language whose character type is not an integer of the
        // declared width cannot spell every FORCE_CHAR constant. Rust's `char` is
        // a 4-byte Unicode scalar with a validity invariant and has no `'\xff'`;
        // its byte literal `b'a'` covers the 1-byte printable cases and the rest
        // fall back to the integer, which is always exact.
        let display_fmt = if display_fmt == display_format::FORCE_CHAR
            && self.lang().forms.char_lit == crate::kuna_lang::CharForm::RustByte
            && !rust_byte_literal_spellable(val, sz)
        {
            if force_hex || !force_dec { display_format::FORCE_HEX } else { display_format::FORCE_DEC }
        } else {
            display_fmt
        };
        let tok = format_integer_token(
            print_negsign,
            val,
            display_fmt,
            sz,
            force_unsigned,
            force_sized,
            true, // doEmitWideCharPrefix() — PrintC
            size_suffix,
        );
        if display_fmt == display_format::FORCE_CHAR
            && self.lang().forms.char_lit == crate::kuna_lang::CharForm::RustByte
        {
            format!("b{tok}")
        } else {
            tok
        }
    }

    /// Render a character constant, preserving explicit display policy.
    /// A default high byte is numeric: C character escapes above ASCII depend
    /// on plain-char signedness and cannot represent an unsigned byte portably.
    fn push_char_constant_ir(&mut self, fd: &Funcdata, ct: &crate::dtype::TypeRoot, val: uintb, op: OpId, vn: VarnodeId) {
        // C++ `bool isSigned = (ct->getMetatype() == TYPE_INT);` (printc.cc:1679).
        let is_signed = ct.get_metatype() == crate::dtype::type_metatype::TYPE_INT;
        // C++ resolves `displayFormat` from the varnode-high's equate Symbol /
        // type (printc.cc:1680-1692).  The equate short-circuit needs the W7
        // EquateSymbol graph (not yet ported — the equate path renders via the
        // integer arm's `force_char` route instead); here we read the Symbol /
        // read-facing display-format override that `vn_high_display_format`
        // already exposes (the same value C++ `sym->getDisplayFormat()` /
        // `high->getType()->getDisplayFormat()` produces for a non-equate high).
        let mut display_fmt = fd.vn_high_display_format(vn);
        if display_fmt == display_format::NONE {
            display_fmt = ct.get_display_format();
        }
        // printc.cc:1693-1698 — a forced format other than `force_char`, when the
        // CastStrategy does not care about the char representation (the base
        // `caresAboutCharRepresentation` returns false), prints as an integer.
        if display_fmt != display_format::NONE && display_fmt != display_format::FORCE_CHAR {
            self.push_constant_ir_fmt_sign(val, ct.get_size(), op, display_fmt, is_signed);
            return;
        }
        if display_fmt == display_format::NONE && ct.get_size() == 1 && val >= 0x80 {
            // Rust spells recovered text bytes as u8, including C signed char.
            let signed_literal = is_signed
                && self.lang().forms.char_lit != crate::kuna_lang::CharForm::RustByte;
            self.push_constant_ir_fmt_sign(val, 1, op, display_fmt, signed_literal);
            return;
        }
        self.push_constant_ir_fmt_sign(val, ct.get_size(), op, display_format::FORCE_CHAR, is_signed);
    }

    /// Render a floating-point constant — the `TYPE_FLOAT` arm of C++
    /// `PrintC::pushConstant` (printc.cc:1859-1861) which delegates to
    /// `PrintC::push_float` (printc.cc:1448-1492).  Decodes the raw encoding `val`
    /// through `glb->translate->getFloatFormat(sz)`
    /// ([`FloatFormat::get_host_float`]/`extract_sign`/`print_decimal`) and emits
    /// the `INFINITY`/`NAN`/decimal token via [`format_float_token`].  When there
    /// is no `FloatFormat` for the size, the token is `FLOAT_UNKNOWN`.
    fn push_float_ir(&mut self, arch: &Architecture, val: uintb, sz: int4, op: OpId) {
        use kuna_num::float::floatclass;
        let force_scinote = self.context.is_set(modifiers::FORCE_SCINOTE);
        let tok = match arch.translate().get_float_format(sz) {
            None => format_float_token(FloatClass::Unknown, false, "", force_scinote),
            Some(format) => {
                let (floatval, class) = format.get_host_float(val);
                let sign = format.extract_sign(val);
                match class {
                    floatclass::infinity => {
                        format_float_token(FloatClass::Infinity, sign, "", force_scinote)
                    }
                    floatclass::nan => {
                        format_float_token(FloatClass::Nan, sign, "", force_scinote)
                    }
                    // normalized / zero / denormalized all take the printDecimal
                    // path (C++ `push_float` else-branch).
                    _ => {
                        let decimal = format.print_decimal(floatval, force_scinote);
                        format_float_token(FloatClass::Normal, sign, &decimal, force_scinote)
                    }
                }
            }
        };
        self.push_atom(&Atom::with_op(
            tok,
            TagType::Syntax,
            crate::printlanguage::SyntaxHighlight::const_color,
            op_key(op),
        ));
    }

    /// Try to push a quoted string literal for a constant pointer to character
    /// data — C++ `PrintC::pushPtrCharConstant` (printc.cc:1767).  Resolves the
    /// constant pointer to a data-space address, requires the location to be
    /// readonly, then reads/escapes the string via [`Self::print_character_constant`].
    /// Returns `true` only when a literal token was pushed (so the caller can fall
    /// through to the integer print otherwise).
    fn push_ptr_char_constant_ir(
        &mut self,
        arch: &Architecture,
        val: uintb,
        ptr_size: int4,
        subct: &crate::dtype::TypeRoot,
        point: &Address,
        op: OpId,
        vn: VarnodeId,
    ) -> bool {
        let spc = match arch.manage().get_default_data_space() {
            Some(s) => std::rc::Rc::clone(s),
            None => return false,
        };
        // `ptr_size` is the pointer-constant's width (C++ `ct->getSize()`).
        let mut full_encoding: uintb = 0;
        let stringaddr =
            match arch.resolve_constant(&spc, val, ptr_size, point, &mut full_encoding) {
                Ok(a) => a,
                Err(_) => return false,
            };
        if stringaddr.is_invalid() {
            return false;
        }
        // Check that the string location is readonly (the global-scope query).
        let gscope = match arch.symboltab.get_global_scope() {
            Some(g) => g,
            None => return false,
        };
        let nulladdr = Address::new_invalid();
        if !arch.symboltab.is_read_only(gscope, &stringaddr, 1, &nulladdr) {
            return false;
        }
        let mut s = String::new();
        let mut chars_emitted: int4 = 0;
        if !self.print_character_constant(arch, &mut s, &stringaddr, subct, &mut chars_emitted) {
            return false;
        }
        // (kuna emptystrconst) A zero-character literal names no byte of the
        // image, so it is strictly less informative than the address it would
        // displace -- unless the bytes there really are string data, which is
        // what a genuine `""` looks like.  Read the neighbourhood and let the
        // sub-stage decide; an unreadable window is not evidence, so the
        // upstream literal stands.
        if self.options.empty_str_const && chars_emitted == 0 {
            let mut window = [0u8; crate::kuna_emptystrconst::WINDOW];
            let readable = {
                let loader_rc = arch.translate().loader_rc();
                let mut loader = loader_rc.borrow_mut();
                loader.load_fill(&mut window, &stringaddr).is_ok()
            };
            if crate::kuna_emptystrconst::declines_literal(
                true,
                chars_emitted,
                if readable { Some(&window[..]) } else { None },
            ) {
                return false;
            }
        }
        self.push_atom(&Atom::with_op_vn(
            s,
            TagType::VarToken,
            crate::printlanguage::SyntaxHighlight::const_color,
            op_key(op),
            vn_key(vn),
        ));
        true
    }

    /// Render readonly character data at `addr` as a quoted C string literal —
    /// C++ `PrintC::printCharacterConstant` (printc.cc:1602).  Reads the UTF-8
    /// string bytes through the `StringManager` (over the loadimage), emits the
    /// optional `L` wide prefix, then the escaped contents between quotes (with the
    /// truncation marker when the literal was clipped).  Returns `false` when no
    /// string data is available.
    fn print_character_constant(
        &self,
        arch: &Architecture,
        s: &mut String,
        addr: &Address,
        char_type: &crate::dtype::TypeRoot,
        chars_emitted: &mut int4,
    ) -> bool {
        use crate::stringmanage::StringManager;
        // Pull UTF-8 string data through the architecture's persistent
        // `stringManager` (C++ `glb->stringManager`).  Using the shared instance
        // (not a transient one) is what lets `getInternalString`-registered
        // strings — keyed on a constant-space hash address that is *not* in the
        // loadimage — resolve here: `getStringData` returns the cached bytes for a
        // hit and otherwise reads the loadimage exactly as before.
        let loader_rc = arch.translate().loader_rc();
        let mut is_trunc = false;
        let buffer: Vec<u8> = {
            let mut mgr = arch.string_manager.borrow_mut();
            let mut loader = loader_rc.borrow_mut();
            let view = char_type.read();
            let def = view.get(char_type.id()).expect("character type")
                .effective().expect("character definition");
            mgr.get_string_data(addr, &def, &mut **loader, &mut is_trunc)
                .to_vec()
        };
        if buffer.is_empty() {
            return false;
        }
        // doEmitWideCharPrefix() (always true for PrintC) && size>1 && !opaque -> 'L'
        if char_type.get_size() > 1 && !char_type.is_opaque_string() {
            s.push('L');
        }
        s.push('"');
        // escapeCharacterData(s, buffer, len, 1, glb->translate->isBigEndian()):
        // the buffer is already UTF-8 (charsize 1); walk codepoints and re-escape.
        let bigend = arch.translate().is_big_endian();
        let mut i: int4 = 0;
        let count = buffer.len() as int4;
        while i < count {
            let mut skip: int4 = 1;
            let codepoint = StringManager::get_codepoint(&buffer[i as usize..], 1, bigend, &mut skip);
            if codepoint == 0 || codepoint == -1 {
                break;
            }
            match self.lang().forms.string_escape {
                crate::kuna_lang::StringEscape::CEscapes => print_unicode(s, codepoint),
                crate::kuna_lang::StringEscape::RustEscapes => print_unicode_rust(s, codepoint),
            }
            *chars_emitted += 1;
            i += skip;
        }
        if is_trunc {
            s.push_str("...\" /* TRUNCATED STRING LITERAL */");
        } else {
            s.push('"');
        }
        true
    }
}

/// Identifiers a generated local suffix must not capture.
pub(crate) fn declaration_occupied_names(
    fd: &Funcdata,
    names: impl IntoIterator<Item = String>,
) -> Vec<String> {
    let mut names: Vec<String> = names.into_iter().collect();
    names.extend(fd.get_arch().global_symbol_names());
    let name_style = fd.get_arch().kuna_name_style();
    names.extend((0..fd.num_calls()).filter_map(|index| {
        let call = fd.get_call_specs(index);
        if !call.get_name().is_empty() {
            Some(call.get_name().to_string())
        } else if !call.get_entry_address().is_invalid() {
            Some(call.fspec_printed_name(name_style))
        } else {
            // An unnamed CALLIND has no identifier to capture and its synthetic
            // call-spec address is deliberately invalid.
            None
        }
    }));
    names
}

/// Head op of an sblocks-arena basic block (when the structured node itself is
/// a Basic, not a Copy referencing bblocks).
fn sblocks_basic_head(fd: &Funcdata, bb: BlockId) -> Option<OpId> {
    use crate::block::BlockKind;
    match fd.sblocks_ref().block(bb).kind() {
        BlockKind::Basic(b) => b.op_head,
        _ => None,
    }
}

/// Tail op of an sblocks-arena basic block.
/// (kuna `voidtailreturn`) The function's own trailing bare `return;`, when it is
/// safe to elide.
///
/// kuna (faithfully to Ghidra) always prints the final RETURN, so a void function
/// ends `... }\n  return;\n}`.  The C source it was compiled from has no `return`
/// there at all -- it falls off the end -- and pyjoern's CFG for the source
/// therefore has no node for it, while kuna's printed statement re-materialises
/// one: +1 node, +1..2 edges, and an `is_exitpoint` role flip that alone breaks
/// GED's isomorphism test.  It is also simply redundant C.
///
/// Returns the `OpId` to skip, or `None` when ANY of the four conditions fails:
///
/// 1. **The function returns void.**  A `return <value>;` is never redundant, and
///    a non-void function that falls off the end is a different (invalid) program.
/// 2. **The op is the tail of the LAST structured leaf**, reached by descending
///    only the containers that do not themselves print a construct (`Graph`, `Ls`).
///    Descending an `If`/`WhileDo`/`Switch` arm would elide a return that is
///    nested inside a printed construct, which is not the trailing statement.
/// 3. **That leaf is not an unstructured (goto) target.**  bash `rl_echo_signal_char`
///    prints `label_115e79:` immediately above its trailing `return;`; eliding the
///    statement would leave a label with no statement after it -- invalid C.
/// 4. **Exactly one structured leaf has that op as its tail.**  `returndup` and
///    `taildup` clone a shared epilogue by giving several structured leaves the
///    SAME RETURN `OpId`; suppressing by id would then also delete genuine
///    mid-body early returns.  Requiring a unique owner makes the elision
///    positional, not identity-based.
fn elidable_void_tail_return(fd: &Funcdata, decode_halt: bool) -> Option<OpId> {
    use crate::block::BlockType;
    use crate::dtype::type_metatype;

    // (1) void return type.
    let out = fd.get_func_proto().get_output_type()?;
    if out.get_metatype() != type_metatype::TYPE_VOID {
        return None;
    }

    // (2) the last structured leaf, descending only non-printing containers.
    let mut cur = fd.sblocks_ref().root?;
    loop {
        match fd.sblocks_ref().block(cur).get_type() {
            BlockType::Graph | BlockType::Ls => {
                let list = fd.sblocks_ref().block(cur).get_list();
                cur = *list.last()?;
            }
            _ => break,
        }
    }
    if !matches!(fd.sblocks_ref().block(cur).get_type(), BlockType::Basic | BlockType::Copy) {
        return None;
    }
    // (3) not a goto target: a label would be left dangling.
    if fd.sblocks_ref().block(cur).is_unstructured_target() {
        return None;
    }
    let tail = structured_leaf_tail(fd, cur)?;
    let op = fd.obank().get(tail)?;
    if op.code() != OpCode::CPUI_RETURN || op.num_input() > 1 || op.not_printed() {
        return None;
    }
    // (kuna decodehalt) A decode-failure halt is a `RETURN` with one input, so it
    // matches the shape above -- but it is not the source's trailing fall-off, it
    // is the marker for flow kuna could not follow, and eliding it deletes the
    // only statement that says so.  Gated with the rendering, and only over the
    // halt causes the rendering claims: `decodehalt off` restores both halves,
    // and a `noreturn` halt keeps whatever `voidtailreturn` already did with it.
    if decode_halt && crate::kuna_decodehalt::halt_call_name(op.get_halt_type()).is_some() {
        return None;
    }

    // (4) exactly one structured leaf owns that op (returndup/taildup aliasing),
    // and (5) the function prints at least one OTHER statement.  A body whose only
    // statement is the return would come back completely empty -- not the source
    // shape this is chasing, and it leaves the ghidra markup document with no op to
    // cross-link to the `<ast>` (`kuna-ghidra` decompile_at_e2e pins exactly that:
    // "a bare `return;` still tags its statement/op").
    let mut owners = 0usize;
    let mut other_printed = false;
    let mut stack = vec![fd.sblocks_ref().root?];
    while let Some(b) = stack.pop() {
        let blk = fd.sblocks_ref().block(b);
        if matches!(blk.get_type(), BlockType::Basic | BlockType::Copy) {
            if structured_leaf_tail(fd, b) == Some(tail) {
                owners += 1;
                if owners > 1 {
                    return None;
                }
            }
            let mut cur = match blk.get_copy() {
                Some(u) => fd.bb_op_head(u),
                None => sblocks_basic_head(fd, b),
            };
            while let Some(inst) = cur {
                cur = fd.bb_op_next(inst);
                if inst == tail {
                    continue;
                }
                let Some(o) = fd.obank().get(inst) else { continue };
                if o.not_printed() || o.code() == OpCode::CPUI_BRANCH {
                    continue;
                }
                if let Some(out) = o.get_out() {
                    if fd.vbank().get(out).map(|v| v.is_implied()).unwrap_or(false) {
                        continue;
                    }
                }
                other_printed = true;
            }
        }
        stack.extend(blk.get_list().iter().copied());
    }
    if owners != 1 || !other_printed {
        return None;
    }
    Some(tail)
}

/// (kuna `voidtailreturn`) The last printed op of a structured LEAF, resolving a
/// `BlockCopy` mirror through to the bblocks basic block it stands for.
///
/// `emit_block_copy` emits its ops via `emit_basic_block_ops(.., under, true)`,
/// so a leaf's printed tail lives on the underlying bblocks block whenever the
/// sblocks node is a mirror -- which is the normal shape for the trailing block
/// of a structured function.  `sblocks_basic_tail` only knows the direct
/// `BlockKind::Basic` case and returns `None` for the mirror.
fn structured_leaf_tail(fd: &Funcdata, bb: BlockId) -> Option<OpId> {
    if let Some(under) = fd.sblocks_ref().block(bb).get_copy() {
        return fd.bb_op_tail(under);
    }
    sblocks_basic_tail(fd, bb)
}

fn sblocks_basic_tail(fd: &Funcdata, bb: BlockId) -> Option<OpId> {
    use crate::block::BlockKind;
    match fd.sblocks_ref().block(bb).kind() {
        BlockKind::Basic(b) => b.op_tail,
        _ => None,
    }
}

/// The `getIndex()` to feed `commsorter.setupBlockList` for an sblocks basic
/// node.  When the node is a `BlockCopy` mirror, use the underlying bblocks
/// block's index (the comment placement was keyed by the live basic block);
/// otherwise the node's own index.
fn sblocks_basic_block_index(fd: &Funcdata, bb: BlockId) -> int4 {
    if let Some(under) = fd.sblocks_ref().block(bb).get_copy() {
        fd.bblocks_ref().block(under).get_index()
    } else {
        fd.sblocks_ref().block(bb).get_index()
    }
}

/// Can `opPtrsub` name a member through a pointer of this type?
fn ptrsub_resolves(ptype: &crate::dtype::TypeRoot) -> bool {
    use crate::dtype::type_metatype;
    ptype.get_metatype() == crate::dtype::type_metatype::TYPE_PTR
        && (ptype.is_formal_pointer_rel()
            || ptype.get_ptr_to().is_some_and(|ct| {
                matches!(
                    ct.get_metatype(),
                    type_metatype::TYPE_STRUCT
                        | type_metatype::TYPE_UNION
                        | type_metatype::TYPE_ARRAY
                        | type_metatype::TYPE_SPACEBASE
                )
            }))
}

/// The pointer type of the variable `vn` belongs to, which C++ `opPtrsub` reads
/// (`getHighTypeReadFacing`): a PTRSUB is inserted against the merged
/// variable's type, and one member of the variable may still carry a
/// narrower pointer (`unsigned int *` for a global also assigned a
/// `struct_N *`), which cannot name the member.
fn high_pointer_type(fd: &Funcdata, vn: VarnodeId) -> Option<crate::dtype::TypeRoot> {
    let high = fd.vbank().get(vn)?.get_high()?;
    if let Some(t) = fd.high_bank().get(high).and_then(|h| h.kuna_symbol_type()) {
        return Some(t.clone());
    }
    let rep = crate::kuna_declhightype::type_representative(fd, high)?;
    fd.vbank().get(rep).map(|v| v.get_type().clone())
}

/// (kuna) The declarator a Symbol-keyed collapse imposes on the surviving
/// declaration: the final type text, its post-name declarator suffix, and the
/// `(base-type, count)` array adornment (`None` for a scalar).  Same shape as
/// `rendered_local_decl`'s first three returns.
type DeclTypeOverride = (TypeText, TypeText, Option<(String, int4)>);

/// Provenance never changes the existing spelling-based collapse decision.
fn same_decl_text(left: &DeclTypeOverride, right: &DeclTypeOverride) -> bool {
    left.0.text == right.0.text && left.1.text == right.1.text && left.2 == right.2
}

/// (kuna) The declaration *representative* Varnode of a local high: the addr-tied
/// (mapped, in-scope) storage member - the C++ symbol's `getFirstWholeMap()`
/// storage - else instance 0.  Shared by the type-name/comment path and the
/// array-declarator fallback (GH-9184) so both anchor on the same Varnode.
fn decl_rep_varnode(
    fd: &Funcdata,
    high: crate::context::HighVariableId,
) -> Option<crate::context::VarnodeId> {
    let h = fd.high_bank().get(high)?;
    (0..h.num_instances())
        .map(|i| h.get_instance(i))
        .find(|&vn| fd.vbank().get(vn).map(|v| v.is_addr_tied()).unwrap_or(false))
        .or_else(|| (0..h.num_instances()).map(|i| h.get_instance(i)).next())
}

/// (kuna) If `ct` is a `TYPE_ARRAY`, the `(base_type_name, count)` pair that
/// declares it `<base> name [count]` (C++ `emitVarDecl`'s array branch, where the
/// declared type is the *element* type and the count adorns the identifier).  The
/// base name is the element's [`type_name_for_decl`] halves, resolved with the
/// realtypes context - so an anonymous `undefined1 [N]` array (e.g. a 32-byte
/// oversize-unknown YMM FMA accumulator, GH-9184) declares its element type, not
/// the whole-array `undefined<N>` scalar.
fn array_decl_parts(
    ct: &crate::dtype::TypeRoot,
    rt: RealTypeCtx,
    annotate: bool,
) -> Option<((TypeText, TypeText), int4)> {
    if ct.get_metatype() != crate::dtype::type_metatype::TYPE_ARRAY {
        return None;
    }
    let base = ct.get_array_base()?;
    let elsize = base.get_size().max(1);
    let count = ct.get_size() / elsize;
    Some((rt.speller().type_name_annotated(&rt, &base, annotate), count))
}

/// Build the declarator front/back text bracketing an identifier for `ct`.
///
/// Returns `(front, back)` such that `<front><name><back>` is the full
/// declaration of an object named `name` of type `ct` -- e.g. in C
///   * `int8`              -> `("int8", "")`             -> `int8 a`
///   * `twostruct *`       -> `("twostruct *", "")`      -> `twostruct *ptr`
///   * `int4 (*)[1]`       -> `("int4 (*", ")[1]")`      -> `int4 (*a)[1]`
///
/// The C body -- the transcription of `PrintC::pushTypeStart`/`pushTypeEnd`
/// (printc.cc:265/314) plus `buildTypeStack` (printc.cc:143) -- moved to
/// `CSpeller::declarator` (`p9_emit/kuna_langc.rs`) when the output-language seam
/// landed. A language whose types are pure prefixes returns an empty `back`.
pub(crate) fn declarator_parts(
    ct: &crate::dtype::TypeRoot,
    rt: RealTypeCtx,
) -> (String, String) {
    rt.speller().declarator(&rt, ct)
}

/// (kuna) The full type string for `ct` with no identifier, rendered exactly as
/// the decompiler would print it — e.g. `int`, `char *`, `undefined8`, `int [16]`
/// in C; `i32`, `*mut u8`, `u64`, `[i32; 16]` in Rust.
///
/// A public wrapper over [`declarator_parts`] for out-of-crate consumers (the
/// `kuna decompile-all --json` variable extractor → decbench's `type_match`
/// metric).  It resolves the live `realtypes` context off the architecture so the
/// spelling matches `print_c`'s body, and concatenates the declarator
/// `front`/`back` around an empty identifier (`<front><back>`).
///
/// The name is historical: it follows the ACTIVE output language, which is read
/// off the architecture's printer.  Callers reach it while the printer is in
/// place; a caller that reaches it mid-emission (with the printer loaned out by
/// `take_print`) sees the default C language, which is the safe fallback.
pub fn type_to_c_string(
    arch: &Architecture,
    ct: &crate::dtype::TypeRoot,
) -> String {
    let (front, back) = declarator_parts(ct, RealTypeCtx::from_arch(arch, arch.print().out_lang(), arch.print().options.convention));
    format!("{front}{back}")
}

// ===========================================================================
// (kuna) `doc_type_definitions` rendering helpers — the pure per-type body
// renderers behind the `docTypeDefinitions` port (see
// `PrintC::doc_type_definitions` for the emission shape + divergences).  All
// take an explicit `RealTypeCtx` and hand-built `Datatype`s so they unit-test
// without an `Architecture`.
// ===========================================================================

/// (kuna) Rewrite `name` into a valid C identifier: every character outside
/// `[A-Za-z0-9_]` becomes `_`, and a leading digit gains a `_` prefix.
/// Borrowed unchanged when already valid (the caller emits a
/// `/* renamed from "…" */` comment when it changed).
pub fn sanitize_type_name(name: &str) -> std::borrow::Cow<'_, str> {
    let ok_char = |c: char| c.is_ascii_alphanumeric() || c == '_';
    let clean = !name.is_empty()
        && name.chars().all(ok_char)
        && !name.starts_with(|c: char| c.is_ascii_digit());
    if clean {
        return std::borrow::Cow::Borrowed(name);
    }
    let mut s = String::with_capacity(name.len() + 1);
    if name.starts_with(|c: char| c.is_ascii_digit()) {
        s.push('_');
    }
    for c in name.chars() {
        s.push(if ok_char(c) { c } else { '_' });
    }
    std::borrow::Cow::Owned(s)
}

/// (kuna, GH-340) Make `raw` safe to interpolate into a `/* … */` comment.
///
/// The `/* renamed from "<raw>" */` note prints the type name a binary actually
/// carried, and that string is unvalidated binary data: a `*/` in it closes the
/// comment early and turns the rest of the line into code, and a newline splits
/// the comment across two lines. Both re-open, in a different construct, exactly
/// the hole [`sanitize_type_name`] was written to close — so the note escapes
/// what it quotes. Every ASCII control byte becomes a space and both comment
/// delimiters lose their second character to `_`; nothing else is touched, so a
/// name that could never break a comment prints verbatim.
fn comment_safe(raw: &str) -> std::borrow::Cow<'_, str> {
    let breaks = |w: &[u8]| matches!(w, [b'*', b'/'] | [b'/', b'*']);
    let bytes = raw.as_bytes();
    let clean = !bytes.iter().any(|b| b.is_ascii_control())
        && !bytes.windows(2).any(breaks);
    if clean {
        return std::borrow::Cow::Borrowed(raw);
    }
    let mut out = String::with_capacity(raw.len());
    for (i, c) in raw.char_indices() {
        if c.is_ascii_control() {
            out.push(' ');
        } else if i > 0 && breaks(&bytes[i - 1..i + 1]) {
            out.push('_');
        } else {
            out.push(c);
        }
    }
    std::borrow::Cow::Owned(out)
}

/// (kuna `globalref`) `T name` for a global of type `ct`, via the same
/// declarator builder a structure member uses.
pub fn declaration_text(ct: &crate::dtype::TypeRoot, name: &str, rt: RealTypeCtx) -> String {
    field_decl_text(ct, name, rt)
}

/// (kuna `globalref`) The name the printer gives the unnamed global at `addr`.
pub fn global_data_name(arch: &Architecture, addr: u64) -> String {
    kuna_global_data_name(arch.kuna_name_style(), addr)
}

/// (kuna) One member declaration `<front><name><back>` via the C-declarator
/// builder [`declarator_parts`] — the same front/name spacing rule the emit
/// loop uses (`a `*` front glues to the identifier with no space).
fn field_decl_text(
    ct: &crate::dtype::TypeRoot,
    name: &str,
    rt: RealTypeCtx,
) -> String {
    let (front, back) = declarator_parts(ct, rt);
    let sep = if front.ends_with('*') || name.is_empty() { "" } else { " " };
    format!("{front}{sep}{name}{back}")
}

/// (kuna) The unsigned C integer spelling for a byte size (the empty-enum /
/// fallback scalar spelling; 8 covers any larger size best-effort).
fn unsigned_c_int_of_size(size: int4) -> &'static str {
    match size {
        1 => "unsigned char",
        2 => "unsigned short",
        4 => "unsigned int",
        _ => "unsigned long long",
    }
}

/// (kuna) Render ONE complete composite (struct/union) body definition —
/// `struct <name> { … };` — as a pure function of the data-type.
///
/// Struct field-offset gaps and trailing padding (vs `get_size()`) become
/// explicit `undefined1 _pad<hexoff>[N];` members.  Bitfields render
/// best-effort as `<type> <name> : <bits>;` with padding suppressed (their
/// byte coverage overlaps the gap computation).  Unions carry no padding.
/// Returns `""` for a non-composite kind.
pub(crate) fn compose_type_body(
    ct: &crate::dtype::TypeRoot,
    name: &str,
    rt: RealTypeCtx,
) -> String {
    use crate::dtype::DatatypeKind;
    let mut out = String::new();
    let view = ct.read();
    let def = view.get(ct.id()).expect("retained composite")
        .effective().expect("composite definition");
    match &def.kind {
        DatatypeKind::Struct { field, bitfield } => {
            out.push_str(&format!("struct {name} {{\n"));
            let have_bits = !bitfield.is_empty();
            let mut cur: int4 = 0;
            for f in field {
                if !have_bits && f.offset > cur {
                    out.push_str(&format!(
                        "    undefined1 _pad{:x}[{}];\n",
                        cur,
                        f.offset - cur
                    ));
                }
                let fname = sanitize_type_name(&f.name);
                let field_type = ct.related(f.field_type).expect("field type");
                out.push_str(&format!(
                    "    {};\n",
                    field_decl_text(&field_type, &fname, rt)
                ));
                cur = cur.max(f.offset + field_type.get_size());
            }
            if have_bits {
                out.push_str(
                    "    /* bitfields (byte layout approximate; padding omitted) */\n",
                );
                for bf in bitfield {
                    let bname = sanitize_type_name(&bf.name);
                    let field_type = ct.related(bf.field_type).expect("bitfield type");
                    out.push_str(&format!(
                        "    {} : {};\n",
                        field_decl_text(&field_type, &bname, rt),
                        bf.num_bits
                    ));
                }
            } else if ct.get_size() > cur {
                out.push_str(&format!(
                    "    undefined1 _pad{:x}[{}];\n",
                    cur,
                    ct.get_size() - cur
                ));
            }
            out.push_str("};\n");
        }
        DatatypeKind::Union { field } => {
            out.push_str(&format!("union {name} {{\n"));
            for f in field {
                let fname = sanitize_type_name(&f.name);
                let field_type = ct.related(f.field_type).expect("field type");
                out.push_str(&format!(
                    "    {};\n",
                    field_decl_text(&field_type, &fname, rt)
                ));
            }
            out.push_str("};\n");
        }
        _ => {}
    }
    out
}

/// (kuna) Render ONE enum definition — `typedef enum <name> { A = <v>, … }
/// <name>;` — from the `TypeEnum` namemap.  A `TYPE_INT`-facing enum (the
/// decode-time `TYPE_ENUM_INT` form) prints signed decimal values
/// (sign-extended by the enum's byte size); the `TYPE_UINT` form prints hex.
/// An empty namemap falls back to a plain integer typedef (an empty `enum {}`
/// is not valid C).
pub(crate) fn compose_enum_body(ct: &crate::dtype::TypeRoot, name: &str) -> String {
    use crate::dtype::type_metatype;
    let view = ct.read();
    let def = view.get(ct.id()).expect("retained enum")
        .effective().expect("enum definition");
    let Some(nmap) = def.as_enum_namemap() else {
        return String::new();
    };
    let size = ct.get_size();
    if nmap.is_empty() {
        return format!(
            "typedef {} {name}; /* empty enum */\n",
            unsigned_c_int_of_size(size)
        );
    }
    let signed = ct.get_metatype() == type_metatype::TYPE_INT;
    let mut out = format!("typedef enum {name} {{\n");
    let n = nmap.len();
    for (i, (val, ename)) in nmap.iter().enumerate() {
        let ename = sanitize_type_name(ename);
        let vtxt = if signed && size > 0 && size <= 8 {
            format!("{}", kuna_base::address::sign_extend(*val as i64, size * 8 - 1))
        } else {
            format!("0x{val:x}")
        };
        let comma = if i + 1 < n { "," } else { "" };
        out.push_str(&format!("    {ename} = {vtxt}{comma}\n"));
    }
    out.push_str(&format!("}} {name};\n"));
    out
}

/// (kuna) Render ONE typedef — `typedef <declarator around name>;` — of the
/// typedef's immediate base type (`get_typedef()`), via the C-declarator
/// builder (so `typedef char *mystr;` and array typedefs lay out correctly).
pub(crate) fn compose_typedef_line(
    base: &crate::dtype::TypeRoot,
    name: &str,
    rt: RealTypeCtx,
) -> String {
    format!("typedef {};\n", field_decl_text(base, name, rt))
}

pub(crate) fn compose_scalar_definition(ct: &crate::dtype::TypeRoot, name: &str, rt: RealTypeCtx) -> String {
    let spelling = crate::kuna_ctypes::core_type_spelling(
        &rt.model, ct.get_metatype(), ct.get_size(), ct.is_char_print(),
    ).or_else(|| (ct.get_metatype() == crate::dtype::type_metatype::TYPE_BOOL).then_some("bool"));
    let Some(spelling) = spelling else { return String::new(); };
    if crate::kuna_ctypes::is_builtin_type_name(name) {
        format!("typedef char kuna_core_size_{name}[(sizeof({name}) == {}) ? 1 : -1];\n", ct.get_size())
    } else {
        format!("typedef {spelling} {name};\n")
    }
}

/// One convention-visibility rule for actual C bodies and their publication receipts.
pub(crate) fn emitted_model_name(proto: &crate::fspec::FuncProto, enabled: bool) -> &str {
    if proto.has_model() { emitted_bound_model_name(proto.model(), enabled) } else { "" }
}

pub(crate) fn emitted_bound_model_name(model: &crate::fspec::ProtoModel, enabled: bool) -> &str {
    if enabled && model.print_in_decl() { model.get_name() } else { "" }
}

/// (kuna) The full `docTypeDefinitions` walk over an already
/// dependency-ordered type list (see
/// [`PrintC::doc_type_definitions`](PrintC::doc_type_definitions) for the
/// shape + divergence notes): pass 1 emits the struct/union forward-declaration
/// block, pass 2 the bodies (struct/union/enum/typedef) in dependency order.
/// Pure over the input slice for unit-testability.
pub(crate) fn render_type_definitions(
    deporder: &[crate::dtype::TypeRoot],
    rt: RealTypeCtx,
) -> String {
    use crate::dtype::{TypeRoot, type_metatype};
    use std::collections::HashSet;

    let is_composite = |ct: &TypeRoot| {
        matches!(ct.get_metatype(), type_metatype::TYPE_STRUCT | type_metatype::TYPE_UNION)
    };
    // A type this emitter renders: user-defined (non-core), named, not an
    // internal partial (`has_stripped`), and a typedef / struct / union / enum.
    let relevant = crate::kuna_structdefs::is_definable;

    // Which sanitized composite tag names have a COMPLETE definition somewhere
    // (drives the `/* opaque */` annotation on forward-only names).
    let mut complete_names: HashSet<String> = HashSet::new();
    for ct in deporder {
        if relevant(ct) && is_composite(ct) && ct.get_typedef().is_none() && !ct.is_incomplete()
        {
            let view = ct.read();
            let def = view.get(ct.id()).expect("retained declaration");
            complete_names.insert(sanitize_type_name(def.get_name()).into_owned());
        }
    }

    let mut out = String::new();

    // -- Pass 1: the forward-declaration block (every struct/union tag). -----
    let mut fwd: HashSet<String> = HashSet::new();
    for ct in deporder {
        if !relevant(ct) || !is_composite(ct) || ct.get_typedef().is_some() {
            continue;
        }
        let view = ct.read();
        let def = view.get(ct.id()).expect("retained declaration");
        let raw = def.get_name();
        let name = sanitize_type_name(raw);
        if !fwd.insert(name.to_string()) {
            continue; // one forward declaration per tag name
        }
        let kw = if ct.get_metatype() == type_metatype::TYPE_UNION { "union" } else { "struct" };
        out.push_str(&format!("typedef {kw} {name} {name};"));
        if name != raw {
            out.push_str(&format!(" /* renamed from \"{}\" */", comment_safe(raw)));
        }
        if !complete_names.contains(name.as_ref()) {
            out.push_str(" /* opaque */");
        }
        out.push('\n');
    }
    if !fwd.is_empty() {
        out.push('\n');
    }

    // -- Pass 2: bodies in dependency order. ---------------------------------
    let mut defined: HashSet<String> = HashSet::new();
    for ct in deporder {
        if !relevant(ct) {
            continue;
        }
        let view = ct.read();
        let def = view.get(ct.id()).expect("retained declaration");
        let raw = def.get_name();
        let name = sanitize_type_name(raw);
        if let Some(base) = ct.get_typedef() {
            // A typedef is checked before its effective composite kind. The struct-tag
            // forward typedef already claims its own name, so a same-named
            // typedef-of-struct is exactly that declaration — skip as a dup.
            if fwd.contains(name.as_ref()) || !defined.insert(name.to_string()) {
                out.push_str(&format!("/* duplicate type name skipped: {name} */\n"));
                continue;
            }
            if name != raw {
                out.push_str(&format!("/* renamed from \"{}\" */\n", comment_safe(raw)));
            }
            out.push_str(&compose_typedef_line(&base, &name, rt));
            out.push('\n');
        } else if is_composite(ct) {
            if ct.is_incomplete() {
                continue; // forward-declared only (`/* opaque */`)
            }
            if !defined.insert(name.to_string()) {
                out.push_str(&format!("/* duplicate type name skipped: {name} */\n"));
                continue;
            }
            if name != raw {
                out.push_str(&format!("/* renamed from \"{}\" */\n", comment_safe(raw)));
            }
            out.push_str(&compose_type_body(ct, &name, rt));
            out.push('\n');
        } else if ct.is_enum_type() {
            if fwd.contains(name.as_ref()) || !defined.insert(name.to_string()) {
                out.push_str(&format!("/* duplicate type name skipped: {name} */\n"));
                continue;
            }
            if name != raw {
                out.push_str(&format!("/* renamed from \"{}\" */\n", comment_safe(raw)));
            }
            out.push_str(&compose_enum_body(ct, &name));
            out.push('\n');
        } else if defined.insert(name.to_string()) {
            out.push_str(&crate::kuna_structdefs::definition_text(ct, rt));
            out.push('\n');
        }
    }
    out
}

/// The `(front, back)` type text to render around a declaration's name.
///
/// The C body moved to `CSpeller::type_name` (`p9_emit/kuna_langc.rs`) when the
/// output-language seam landed.
fn type_name_for_decl(
    t: &crate::dtype::TypeRoot,
    rt: RealTypeCtx,
) -> (String, String) {
    rt.speller().type_name(&rt, t)
}

/// (kuna) The per-document type-rendering context.
///
/// An alias for [`crate::kuna_langtypes::SpellCtx`], which is where it moved when
/// the output-language seam landed: it now also carries the output language, so
/// the free-function declarator family reaches its speller with no new threading.
pub(crate) type RealTypeCtx = crate::kuna_langtypes::SpellCtx;

impl crate::kuna_langtypes::SpellCtx {
    /// Resolve the context from the live architecture: the `realtypes`/`ctypes`
    /// gates and the target's decoded data organization.
    ///
    /// Language and convention visibility come from the actual printer, loaned
    /// out of the architecture for the duration of emission (`take_print`), so
    /// the architecture's copy is a placeholder while this runs. The printer owns
    /// the selection.
    pub fn from_arch(arch: &Architecture, lang: crate::kuna_lang::OutLang, conventions: bool) -> Self {
        Self {
            lang,
            enabled: arch.realtypes,
            long_is_8: arch.types().get_size_of_long() == 8,
            ctypes: arch.ctypes,
            conventions,
            model: crate::kuna_ctypes::CDataModel::from_types(&*arch.types()),
        }
    }
}

/// STUB A helper — the kuna stand-in for C++ `Symbol::getFirstWholeMap() != entry`
/// (printc.cc:2697): is there a *whole-symbol* sibling high (the proto-partial
/// ROOT) sharing `name` whose `kuna_symbol_offset == -1`?  A register-returned
/// struct's per-field pieces are all bound to the root's shared name; the root
/// keeps the `-1` whole-symbol-match offset and is the one entry that declares.
/// Per-function names are unique (the `vN` allocator), so the only sibling with a
/// shared name is the group's root, never an unrelated scalar.  `except` is the
/// piece itself (excluded so a lone whole high is not its own sibling).
fn high_name_has_whole_sibling(
    fd: &Funcdata,
    except: crate::context::HighVariableId,
    name: &str,
) -> bool {
    fd.high_bank().iter().any(|(id, h)| {
        id != except
            && h.kuna_symbol_offset() == -1
            && h.kuna_name() == Some(name)
    })
}

/// Does another HighVariable share `name` and represent the WHOLE scalar Symbol —
/// a non-constant storage rep at offset 0 whose size equals the mapped scalar symbol type's size
/// (the C++ `getFirstWholeMap()` entry that emits the single declaration)?  Used by
/// the decl walk to suppress the per-partial declarations of a tied scalar local
/// (LOSS-245: `int8 local` accessed as int4/int2 sub-fields) without affecting a
/// lone partial that has no whole cover.
fn high_name_has_scalar_whole_sibling(
    fd: &Funcdata,
    except: crate::context::HighVariableId,
    name: &str,
) -> bool {
    fd.high_bank().iter().any(|(id, h)| {
        if id == except || h.kuna_name() != Some(name) {
            return false;
        }
        if h.kuna_symbol_offset() != 0 {
            return false;
        }
        let sym_size = match h.kuna_symbol_type() {
            Some(t) => t.get_size(),
            None => return false,
        };
        if h.num_instances() == 0 {
            return false;
        }
        fd.vbank()
            .get(h.get_instance(0))
            .map(|v| !v.is_constant() && v.get_size() == sym_size)
            .unwrap_or(false)
    })
}

/// Whether `spc` should use the kuna angr-style `dat_<addr>` global naming (a
/// RAM/data space, not the stack).  (kuna) `kunaAngrNaming` gate, printc.cc:1961.
fn kuna_global_naming(spc: &std::rc::Rc<kuna_base::space::AddrSpace>) -> bool {
    use kuna_base::space::spacetype;
    matches!(spc.get_type(), spacetype::IPTR_PROCESSOR)
}

/// (kuna) `kunaGlobalDataName(Address)` — `dat_<hex offset>`; ghidra-mode
/// (`name_style_ghidra`) prints the Ghidra GUI convention `DAT_%08x` instead
/// (what Java's `isDynamicSymbolName` recognizes as dynamic).
fn kuna_global_data_name(style: crate::database::KunaNameStyle, off: u64) -> String {
    if style == crate::database::KunaNameStyle::Ghidra {
        return format!("DAT_{off:08x}");
    }
    format!("dat_{off:x}")
}

/// C++ `TypeSpacebase::getAddress` (type.cc:3542): the storage a
/// `PTRSUB(spacebase, in1const)` names.  A global spacebase (invalid localframe)
/// must be a full pointer encoding, which the C++ signals by suppressing the
/// size.
fn spacebase_unnamed_address(
    arch: &Architecture,
    fd: &Funcdata,
    op: OpId,
    sb_type: &crate::dtype::TypeRoot,
    in1const: uintb,
    ptr_size: int4,
) -> Option<kuna_base::address::Address> {
    let (spaceid, localframe) = sb_type.spacebase_parts()?;
    let spc = spaceid?;
    let sz = if localframe.is_invalid() { -1 } else { ptr_size };
    let point = fd.obank().get(op).map(|o| o.get_addr().clone()).unwrap_or_default();
    let mut full_encoding: uintb = 0;
    arch.resolve_constant(&spc, in1const, sz, &point, &mut full_encoding).ok()
}

/// C++ `PrintC::pushUnnamedLocation` (printc.cc:1957-1974) reduced to its name:
/// the register name covering `(loc, size)`, else the kuna angr-style
/// `dat_<addr>` for a data space, else the capitalized `Space<hex>` leaf.
///
/// Shared by the Varnode leaf (`push_symbol_detail_ir`'s tail) and the
/// symbol-less SPACEBASE arm of [`PrintC::op_ptrsub_ir`], which both need the
/// same "no Symbol covers this storage" identifier.  `None` only for an
/// address with no space.
fn kuna_unnamed_location_name(
    arch: &Architecture,
    loc: &kuna_base::address::Address,
    size: int4,
) -> Option<String> {
    let spc = loc.get_space()?;
    let regname = arch.translate().get_register_name(spc, loc.get_offset(), size);
    if !regname.is_empty() {
        return Some(regname);
    }
    if kuna_global_naming(spc) {
        return Some(kuna_global_data_name(arch.kuna_name_style(), loc.get_offset()));
    }
    let mut s = String::new();
    let sn = spc.get_name();
    let mut chars = sn.chars();
    if let Some(c0) = chars.next() {
        s.extend(c0.to_uppercase());
        s.push_str(chars.as_str());
    }
    use std::fmt::Write;
    let _ = write!(s, "{:0width$x}", loc.get_offset(), width = (2 * spc.get_addr_size()) as usize);
    Some(s)
}

/// Spell an address as storage, without treating a covering register name as a
/// source-level identifier.
fn kuna_storage_location_name(loc: &kuna_base::address::Address) -> Option<String> {
    let spc = loc.get_space()?;
    let mut s = String::new();
    let sn = spc.get_name();
    let mut chars = sn.chars();
    if let Some(c0) = chars.next() {
        s.extend(c0.to_uppercase());
        s.push_str(chars.as_str());
    }
    use std::fmt::Write;
    let _ = write!(s, "{:0width$x}", loc.get_offset(), width = (2 * spc.get_addr_size()) as usize);
    Some(s)
}

/// A stable per-op key for the `Atom.op` / `ReversePolish.op` slot (the C++
/// `PcodeOp *`).  The driver only needs a non-null marker here; use the op's
/// slotmap index bits.  (Round-trips through `usize`; only identity matters.)
fn op_key(op: OpId) -> crate::printlanguage::IrKey {
    use slotmap::Key;
    op.data().as_ffi()
}

/// A stable per-varnode key for the `Atom` varnode slot (the C++ `Varnode *`).
fn vn_key(vn: VarnodeId) -> crate::printlanguage::IrKey {
    use slotmap::Key;
    vn.data().as_ffi()
}

/// (kuna) Invert [`op_key`]: reconstruct the `OpId` from the arena key an
/// [`Atom`]/[`ReversePolish`] carries and return the op's `get_time()` — the
/// markup `opref` (C++ `EmitMarkup` derefs the `PcodeOp *` for `getTime()`),
/// identical to the `<seqnum uniq>` `PcodeOp::encode` writes into the `<ast>`
/// (op.rs:589; `funcdata_encode.rs`).  `None` when the key is null or the op is
/// no longer live (defensive — the emitted `opref` set stays a subset of the
/// AST's op times).
fn resolve_op_ref(fd: &Funcdata, op_key: Option<crate::printlanguage::IrKey>) -> Option<uintb> {
    let key = op_key?;
    let op = OpId::from(slotmap::KeyData::from_ffi(key));
    Some(fd.obank().get(op)?.get_time() as uintb)
}

/// (kuna) Invert [`vn_key`]: reconstruct the `VarnodeId` and return its
/// `get_create_index()` — the markup `varref` (C++ `EmitMarkup` derefs the
/// `Varnode *` for `getCreateIndex()`), identical to the `<addr ref>`
/// `Varnode::encode` writes into the `<ast>` `<varnodes>` (varnode.rs:629;
/// `funcdata_encode.rs`).  `IPTR_IOP` annotation Varnodes are excluded exactly as
/// `encode_tree` filters them out of `<varnodes>` — a `varref` to one would
/// dangle.  `None` when null / not live / iop-space.
fn resolve_var_ref(fd: &Funcdata, vn_key: crate::printlanguage::IrKey) -> Option<uintb> {
    let vn = VarnodeId::from(slotmap::KeyData::from_ffi(vn_key));
    let v = fd.vbank().get(vn)?;
    if v.get_space().get_type() == kuna_base::space::spacetype::IPTR_IOP {
        return None;
    }
    Some(v.get_create_index() as uintb)
}

/// C++ `TypeOpFloatInt2Float::absorbZext` (typeop.cc:1874): if the
/// `FLOAT_INT2FLOAT` op's in0 is an implied, written Varnode whose defining op
/// is an `INT_ZEXT`, return that ZEXT op (its source is the real conversion
/// input — the cast's `(floatN)` absorbs the zero-extension).  Otherwise
/// `None`.
fn absorb_zext(fd: &Funcdata, op: OpId) -> Option<OpId> {
    let vn0 = fd.obank().get(op).and_then(|o| o.get_in(0))?;
    let v = fd.vbank().get(vn0)?;
    if v.is_written() && v.is_implied() {
        let zext = v.get_def()?;
        if fd.obank().get(zext).map(|o| o.code()) == Some(OpCode::CPUI_INT_ZEXT) {
            return Some(zext);
        }
    }
    None
}

/// How the integer path of `push_vn_explicit_ir` prints one constant.
struct IntegerLiteral {
    display_fmt: u32,
    sign: bool,
    force_unsigned: bool,
    force_sized: bool,
    size_suffix: &'static str,
}

/// C++ `castStrategy = data.getArch()->print->getCastStrategy()` (the
/// `CastStrategyC` the C printer holds).  Rebuilt here from the bound type
/// factory each time it is needed (the strategy is stateless apart from the
/// factory + `promoteSize = tlst->getSizeOfInt()`, so the rebuild is exact).
fn cast_strategy_for(arch: &Architecture) -> Option<CastStrategyC> {
    let tlst = arch.types_rc() as std::rc::Rc<dyn crate::dtype::TypeFactory>;
    Some(CastStrategyC::new(tlst))
}

/// (kuna `castimplied`) The printer's answers to what
/// [`crate::kuna_castimplied`] asks about how an op prints.
struct ImpliedView<'a> {
    pc: &'a PrintC,
    fd: &'a Funcdata,
    arch: &'a Architecture,
    strat: CastStrategyC,
}

impl crate::kuna_castimplied::PrintedForms for ImpliedView<'_> {
    fn spell(&self, ty: &crate::dtype::TypeRoot) -> String {
        let (front, back) = declarator_parts(ty, self.pc.rt_ctx);
        front + &back
    }

    fn extension_is_cast(&self, op: OpId) -> bool {
        let Some((out, inn)) = self.pc.sext_zext_facing_types(self.fd, op) else {
            return false;
        };
        match self.fd.obank().get(op).map(|o| o.code()) {
            Some(OpCode::CPUI_INT_SEXT) => self.strat.is_sext_cast(&out, &inn),
            Some(OpCode::CPUI_INT_ZEXT) => self.strat.is_zext_cast(&out, &inn),
            _ => false,
        }
    }

    fn extension_hidden(&self, op: OpId, read_op: Option<OpId>) -> bool {
        self.pc.options.hide_exts
            && self.pc.is_extension_cast_implied(self.fd, &self.strat, op, read_op)
    }

    fn sign_dropped(&self, op: OpId) -> bool {
        self.pc.sign_plan.drop_cast(self.fd, op)
    }

    fn truncation_is_cast(&self, op: OpId) -> bool {
        !self.fd.obank().get(op).is_some_and(|o| o.does_special_printing())
            && self.pc.subpiece_cast_form(self.fd, self.arch, op).is_some()
    }

    fn high_name(&self, high: crate::context::HighVariableId) -> Option<String> {
        self.pc.emitted_high_name(self.fd, high)
    }

    fn planned_decl_type(
        &self,
        high: crate::context::HighVariableId,
    ) -> Option<crate::dtype::TypeRoot> {
        self.pc.sign_plan.decl_type(high).cloned()
    }

    fn is_statement(&self, op: OpId) -> bool {
        self.pc.stmt_op == Some(op)
    }

    fn literal_token(&self, vn: VarnodeId, op: OpId) -> Option<String> {
        self.pc.integer_constant_token(self.fd, self.arch, vn, op)
    }

    fn long_size(&self) -> i32 {
        self.arch.types().get_size_of_long()
    }
}

/// An immutable [`CastContext`] over `&Funcdata` for the print-time
/// `isExtensionCastImplied` query (C++ the `Varnode *`/`PcodeOp *` the const
/// `CastStrategyC::isExtensionCastImplied` dereferences).
///
/// `isExtensionCastImplied` makes only read-only IR queries, so unlike the
/// cast-insertion-phase [`crate::coreaction_casts::FuncdataCastContext`] (which
/// needs `&mut Funcdata` for the lazy HighVariable recompute and the constant
/// print-flag mutators) this bridge borrows `&Funcdata` and never mutates.  It
/// interns `VarnodeId`/`OpId` behind the opaque [`VnRef`]/[`OpRef`] handles via a
/// `RefCell<Vec<_>>` (index == handle), exactly as `FuncdataCastContext` does, so
/// the handles reproduce C++ pointer identity without a HashMap (clippy-banned).
///
/// Read-facing types resolve through the bare-Varnode accessor (the W10 print
/// convention; by print-time the merged HighVariable type is pinned onto the
/// Varnode). // STUB(W8 union findResolve)
struct PrintCastContext<'a> {
    fd: &'a Funcdata,
    vn_intern: std::cell::RefCell<Vec<VarnodeId>>,
    op_intern: std::cell::RefCell<Vec<OpId>>,
}

impl<'a> PrintCastContext<'a> {
    fn new(fd: &'a Funcdata) -> PrintCastContext<'a> {
        PrintCastContext {
            fd,
            vn_intern: std::cell::RefCell::new(Vec::new()),
            op_intern: std::cell::RefCell::new(Vec::new()),
        }
    }

    fn vn_ref(&self, vn: VarnodeId) -> VnRef {
        let mut tab = self.vn_intern.borrow_mut();
        if let Some(i) = tab.iter().position(|&k| k == vn) {
            return VnRef(i);
        }
        tab.push(vn);
        VnRef(tab.len() - 1)
    }

    fn op_ref(&self, op: OpId) -> OpRef {
        let mut tab = self.op_intern.borrow_mut();
        if let Some(i) = tab.iter().position(|&k| k == op) {
            return OpRef(i);
        }
        tab.push(op);
        OpRef(tab.len() - 1)
    }

    fn vn_key(&self, vn: VnRef) -> VarnodeId {
        self.vn_intern.borrow()[vn.0]
    }

    fn op_key(&self, op: OpRef) -> OpId {
        self.op_intern.borrow()[op.0]
    }
}

impl CastContext for PrintCastContext<'_> {
    fn op_code(&self, op: OpRef) -> OpCode {
        let op = self.op_key(op);
        self.fd.obank().get(op).expect("print cast ctx: stale op").code()
    }

    fn op_num_input(&self, op: OpRef) -> int4 {
        let op = self.op_key(op);
        self.fd.obank().get(op).expect("print cast ctx: stale op").num_input()
    }

    fn op_in(&self, op: OpRef, slot: int4) -> VnRef {
        let opk = self.op_key(op);
        let vn = self
            .fd
            .obank()
            .get(opk)
            .expect("print cast ctx: stale op")
            .get_in(slot)
            .expect("print cast ctx: missing input slot");
        self.vn_ref(vn)
    }

    fn op_out(&self, op: OpRef) -> Option<VnRef> {
        let opk = self.op_key(op);
        let out = self.fd.obank().get(opk).expect("print cast ctx: stale op").get_out();
        out.map(|vn| self.vn_ref(vn))
    }

    fn op_slot(&self, op: OpRef, vn: VnRef) -> int4 {
        let opk = self.op_key(op);
        let vnk = self.vn_key(vn);
        self.fd.obank().get(opk).expect("print cast ctx: stale op").get_slot(vnk)
    }

    fn vn_is_constant(&self, vn: VnRef) -> bool {
        let vn = self.vn_key(vn);
        self.fd.vbank().get(vn).expect("print cast ctx: stale vn").is_constant()
    }

    fn vn_is_explicit(&self, vn: VnRef) -> bool {
        let vn = self.vn_key(vn);
        self.fd.vbank().get(vn).expect("print cast ctx: stale vn").is_explicit()
    }

    fn vn_is_written(&self, vn: VnRef) -> bool {
        let vn = self.vn_key(vn);
        self.fd.vbank().get(vn).expect("print cast ctx: stale vn").is_written()
    }

    fn vn_size(&self, vn: VnRef) -> int4 {
        let vn = self.vn_key(vn);
        self.fd.vbank().get(vn).expect("print cast ctx: stale vn").get_size()
    }

    fn vn_offset(&self, vn: VnRef) -> uintb {
        let vn = self.vn_key(vn);
        self.fd.vbank().get(vn).expect("print cast ctx: stale vn").get_offset()
    }

    fn vn_def(&self, vn: VnRef) -> Option<OpRef> {
        let vn = self.vn_key(vn);
        let def = self.fd.vbank().get(vn).expect("print cast ctx: stale vn").get_def();
        def.map(|op| self.op_ref(op))
    }

    fn vn_lone_descend(&self, vn: VnRef) -> Option<OpRef> {
        let vnk = self.vn_key(vn);
        self.fd.lone_descend(vnk).map(|op| self.op_ref(op))
    }

    fn vn_high_type(&self, vn: VnRef) -> crate::dtype::TypeRoot {
        let vnk = self.vn_key(vn);
        // Bare-Varnode type (the W10 print convention; high type pinned by
        // print-time). // STUB(W8 union findResolve)
        self.fd.vbank().get(vnk).expect("print cast ctx: stale vn").get_type().clone()
    }

    fn vn_high_type_read_facing(&self, vn: VnRef, op: OpRef) -> crate::dtype::TypeRoot {
        let vnk = self.vn_key(vn);
        let opk = self.op_key(op);
        // The bare read-facing type by print-time.  STUB(W8 union findResolve)
        self.fd
            .vbank()
            .get(vnk)
            .expect("print cast ctx: stale vn")
            .get_type_read_facing(opk)
            .clone()
    }

    fn op_inherits_sign(&self, op: OpRef) -> bool {
        crate::typeop::type_op_info(self.op_code(op)).inherits_sign()
    }

    fn op_inherits_sign_first_param_only(&self, op: OpRef) -> bool {
        crate::typeop::type_op_info(self.op_code(op)).inherits_sign_first_param_only()
    }

    fn op_is_shift_op(&self, op: OpRef) -> bool {
        crate::typeop::type_op_info(self.op_code(op)).is_shift_op()
    }

    fn op_is_bool_output(&self, op: OpRef) -> bool {
        let opk = self.op_key(op);
        self.fd.obank().get(opk).expect("print cast ctx: stale op").is_bool_output()
    }

    fn op_is_call(&self, op: OpRef) -> bool {
        let opk = self.op_key(op);
        self.fd.obank().get(opk).expect("print cast ctx: stale op").is_call()
    }

    fn vn_set_unsigned_print(&mut self, _vn: VnRef) {
        // Only reached by `mark_explicit_unsigned`/`mark_explicit_long_size`, which
        // the print-time `isExtensionCastImplied` query never calls.  The immutable
        // print path holds no `&mut Funcdata`, so this is unreachable here.
        unreachable!("PrintCastContext is read-only: vn_set_unsigned_print not used by isExtensionCastImplied");
    }

    fn vn_set_long_print(&mut self, _vn: VnRef) {
        unreachable!("PrintCastContext is read-only: vn_set_long_print not used by isExtensionCastImplied");
    }
}

/// C++ `op->getOpcode()->getOperatorName(op)` for the op-codes rendered through
/// `PrintC::opFunc` (printc.cc:449).  Most opcodes return the bare static name
/// ([`opcode_print_name`]), but several `TypeOp*` overrides append the operand
/// sizes to disambiguate the functional form: ZEXT/SEXT/SUBPIECE append
/// `in0.size`+`out.size` (typeop.cc:1124/1150/2129), CONCAT appends
/// `in0.size`+`in1.size` (typeop.cc:2050), and CARRY/SCARRY/SBORROW append
/// `in0.size` (typeop.cc:1342/1358/1374).  Matches the raw-printer's
/// `operator_name` (funcdata_printraw.rs).
fn func_operator_name(fd: &Funcdata, op: OpId, opc: OpCode) -> String {
    use OpCode::*;
    let base = opcode_print_name(opc);
    let in_size = |i: int4| -> Option<int4> {
        fd.obank()
            .get(op)
            .and_then(|o| o.get_in(i))
            .and_then(|v| fd.vbank().get(v))
            .map(|vn| vn.get_size())
    };
    let out_size = || -> Option<int4> {
        fd.obank()
            .get(op)
            .and_then(|o| o.get_out())
            .and_then(|v| fd.vbank().get(v))
            .map(|vn| vn.get_size())
    };
    match opc {
        CPUI_INT_ZEXT | CPUI_INT_SEXT | CPUI_SUBPIECE => {
            match (in_size(0), out_size()) {
                (Some(a), Some(b)) => format!("{base}{a}{b}"),
                _ => base,
            }
        }
        CPUI_PIECE => match (in_size(0), in_size(1)) {
            (Some(a), Some(b)) => format!("{base}{a}{b}"),
            _ => base,
        },
        CPUI_INT_CARRY | CPUI_INT_SCARRY | CPUI_INT_SBORROW => match in_size(0) {
            Some(a) => format!("{base}{a}"),
            None => base,
        },
        _ => base,
    }
}

/// The functional print name for an opcode (C++ the `TypeOp::getOperatorName`
/// uppercase form used by `opFunc`).  Faithful for the common functional ops;
/// falls back to the raw opcode name otherwise.
fn opcode_print_name(opc: OpCode) -> String {
    use OpCode::*;
    match opc {
        CPUI_INT_ZEXT => "ZEXT".to_string(),
        CPUI_INT_SEXT => "SEXT".to_string(),
        CPUI_PIECE => "CONCAT".to_string(),
        CPUI_SUBPIECE => "SUB".to_string(),
        CPUI_INT_CARRY => "CARRY".to_string(),
        CPUI_INT_SCARRY => "SCARRY".to_string(),
        CPUI_INT_SBORROW => "SBORROW".to_string(),
        CPUI_POPCOUNT => "POPCOUNT".to_string(),
        CPUI_LZCOUNT => "LZCOUNT".to_string(),
        CPUI_FLOAT_NAN => "NAN".to_string(),
        CPUI_FLOAT_ABS => "ABS".to_string(),
        CPUI_FLOAT_SQRT => "SQRT".to_string(),
        other => format!("{other:?}").trim_start_matches("CPUI_").to_string(),
    }
}

/// Convert a [`crate::printlanguage::SyntaxHighlight`] (the [`Atom`] field, the
/// forward placeholder) to the [`prettyprint`](crate::prettyprint) enum the
/// [`Emit`] driver consumes.  Both carry the same 11 discriminants in the same
/// order (printlanguage.hh / prettyprint.hh "must match ClangToken").
fn to_emit_hl(hl: crate::printlanguage::SyntaxHighlight) -> SyntaxHighlight {
    use crate::printlanguage::SyntaxHighlight as Pl;
    match hl {
        Pl::keyword_color => SyntaxHighlight::KeywordColor,
        Pl::comment_color => SyntaxHighlight::CommentColor,
        Pl::type_color => SyntaxHighlight::TypeColor,
        Pl::funcname_color => SyntaxHighlight::FuncnameColor,
        Pl::var_color => SyntaxHighlight::VarColor,
        Pl::const_color => SyntaxHighlight::ConstColor,
        Pl::param_color => SyntaxHighlight::ParamColor,
        Pl::global_color => SyntaxHighlight::GlobalColor,
        Pl::no_color => SyntaxHighlight::NoColor,
        Pl::error_color => SyntaxHighlight::ErrorColor,
        Pl::special_color => SyntaxHighlight::SpecialColor,
    }
}

#[cfg(test)]
mod tests;

/// How the case labels of a re-rolled lowered switch print: their signedness,
/// and the cast its selector needs for them to name the values it routes.
///
/// (kuna `loweredswitchexact`) Over a one- or two-byte selector a label with the
/// sign bit set names different values signed and unsigned once C promotes the
/// selector (`case -0x7f:` never matches an `unsigned char`). The install records
/// a signedness from the compare tree before any type is inferred, so a selector
/// variable declared as an integer of the switch size gives the labels its own
/// signedness, and any other selector is cast to the recorded one. `None` leaves
/// the recorded signedness and no cast.
fn lowered_switch_label_form(
    fd: &Funcdata,
    arch: &Architecture,
    op: OpId,
) -> Option<(bool, Option<crate::dtype::TypeRoot>)> {
    use crate::dtype::type_metatype::{TYPE_INT, TYPE_UINT};
    if !arch.lowered_switch_exact {
        return None;
    }
    let jt = (0..fd.num_jump_tables()).map(|i| fd.get_jump_table(i)).find(|jt| jt.get_indirect_op() == Some(op))?;
    jt.kuna_lowered_var()?;
    let sz = fd.vbank().get(fd.obank().get(op)?.get_in(0)?)?.get_size();
    if sz != 1 && sz != 2 {
        return None;
    }
    let sign_bit: uintb = 1 << (8 * sz - 1);
    if !(0..jt.num_entries()).any(|i| jt.get_label_by_index(i) & sign_bit != 0) {
        return None;
    }
    if let Some(ct) = switch_variable_type(fd, arch, op) {
        if ct.get_size() == sz && matches!(ct.get_metatype(), TYPE_INT | TYPE_UINT) {
            return Some((ct.get_metatype() == TYPE_INT, None));
        }
    }
    let signed = jt.kuna_has_signed_labels();
    let cast = arch.types().get_base_no_char(sz, if signed { TYPE_INT } else { TYPE_UINT }).ok();
    Some((signed, cast))
}

/// The member Varnode whose data-type `local_decl_type_and_comment` writes as a
/// local high's declaration: the `declhightype` type representative when that
/// option is on and the high has no Symbol of its own, else the declaration
/// (storage) representative.
pub(crate) fn decl_type_representative(
    fd: &Funcdata,
    arch: &Architecture,
    high: crate::context::HighVariableId,
) -> Option<crate::context::VarnodeId> {
    let rep = decl_rep_varnode(fd, high)?;
    fd.vbank().get(rep)?;
    let type_rep = if arch.decl_high_type {
        crate::kuna_declhightype::type_representative(fd, high)
            .filter(|_| crate::kuna_declhightype::declares_from_high(fd, high))
    } else {
        None
    };
    Some(
        type_rep
            .filter(|vn| fd.vbank().get(*vn).is_some())
            .unwrap_or(rep),
    )
}

/// The declared type of the variable a `BRANCHIND` reads: a parameter's prototype
/// type, or a local's declaration type. `None` for an expression.
fn switch_variable_type(fd: &Funcdata, arch: &Architecture, op: OpId) -> Option<crate::dtype::TypeRoot> {
    let vid = fd.obank().get(op)?.get_in(0)?;
    declared_variable_type(fd, arch.decl_high_type, vid)
}

/// The type the printed C declares the variable `vid` belongs to: a parameter's
/// prototype type, or a local's declaration type. `None` for an expression.
pub(crate) fn declared_variable_type(
    fd: &Funcdata,
    decl_high_type: bool,
    vid: crate::context::VarnodeId,
) -> Option<crate::dtype::TypeRoot> {
    let vn = fd.vbank().get(vid)?;
    if vn.is_implied() {
        return None;
    }
    let hid = vn.get_high()?;
    let h = fd.high_bank().get(hid)?;
    let proto = fd.get_func_proto();
    for i in 0..h.num_instances() {
        let m = match fd.vbank().get(h.get_instance(i)) {
            Some(m) if m.is_input() => m,
            _ => continue,
        };
        for p in 0..proto.num_params() {
            if let Some(param) = proto.get_param(p) {
                if param.get_address() == *m.get_addr() && param.get_size() == m.get_size() {
                    return param.get_type().cloned();
                }
            }
        }
    }
    let type_rep = if decl_high_type {
        crate::kuna_declhightype::type_representative(fd, hid).filter(|_| crate::kuna_declhightype::declares_from_high(fd, hid))
    } else {
        None
    };
    let rep = type_rep.or_else(|| decl_rep_varnode(fd, hid))?;
    Some(fd.vbank().get(rep)?.get_type().clone())
}
