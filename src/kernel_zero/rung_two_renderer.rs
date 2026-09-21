//! Rung-2 integration evidence for canonical literal rendering.
//!
//! The components under test are production-compiled code in
//! `canonical_char_renderer`, `canonical_bool_renderer`,
//! `canonical_int_renderer`, and `canonical_string_renderer`; each derives
//! and independently replays its exact embedded Semaprax source into Kernel-0
//! before evaluating a byte lane. It replays that source binding at each full
//! byte-lane invocation. The formatter tests enable each component as a
//! shadow of the real canonical path, proving the integrations are not
//! isolated candidates.
//!
//! Rust output remains authoritative. A mismatch fails the shadow gate, but
//! the shipped formatter neither depends on nor falls back to the component.
//! This is the first rung-2 integration step, not rung-2 promotion.

use crate::hir::{self, DeclarationId};

use super::canonical_bool_renderer::{self as canonical_bool_renderer, SOURCE as BOOL_SOURCE};
use super::canonical_char_renderer::{self, RendererRefusal, SOURCE};
use super::canonical_int_renderer::{self as canonical_int_renderer, SOURCE as INT_SOURCE};
use super::canonical_operator_renderer::{
    self as canonical_operator_renderer, RendererRefusal as OperatorRendererRefusal,
    SOURCE as OPERATOR_SOURCE,
};
use super::canonical_string_renderer::{
    self as canonical_string_renderer, RendererRefusal as StringRendererRefusal,
    SOURCE as STRING_SOURCE,
};
use super::reify::BoundTranslation;

fn valid_scalar_corpus() -> Vec<u32> {
    let mut values = vec![
        0, 1, 8, 9, 10, 11, 12, 13, 14, 31, 32, 33, 34, 38, 39, 40, 91, 92, 93, 125, 126, 127, 128,
        255, 256, 4095, 4096, 65535, 65536, 0xd7ff, 0xe000, 0xffff, 0x10000, 0x10ffff,
    ];
    values.extend(
        (0..=0x10ffff)
            .step_by(16_381)
            .filter(|value| !(0xd800..=0xdfff).contains(value)),
    );
    values.sort_unstable();
    values.dedup();
    values
}

#[test]
fn exact_source_component_matches_the_rust_renderer_over_a_broad_scalar_corpus() {
    let parsed = crate::parse(SOURCE, "kernel-zero-canonical-char-renderer.spx")
        .expect("rung-2 renderer component must parse");
    let resolved = hir::resolve(&parsed).expect("rung-2 renderer component must resolve");
    for id in [
        "format.scalar-valid",
        "format.named-escape",
        "format.hex-digits",
        "format.hex-nibble",
        "format.render-length",
        "format.named-byte",
        "format.render-byte",
    ] {
        let id = DeclarationId::new(id);
        assert!(
            super::reifies_into_kernel_zero(&resolved, &id),
            "rung-2 renderer declaration {id} must stay in Kernel-0"
        );
    }
    let entry = DeclarationId::new("format.render-byte");
    let binding = BoundTranslation::derive(SOURCE, &entry)
        .expect("rung-2 renderer must have an exact-source Kernel-0 translation");
    assert!(binding.replay(SOURCE, &entry).is_ok());

    let values = valid_scalar_corpus();
    for scalar in &values {
        let expected = crate::format::canonical_char(*scalar);
        let bytes = canonical_char_renderer::render_bytes(*scalar).unwrap();
        assert_eq!(
            canonical_char_renderer::render(*scalar).unwrap(),
            expected,
            "scalar U+{scalar:04X}"
        );
        assert_eq!(
            bytes,
            expected.as_bytes(),
            "scalar U+{scalar:04X}: exact Kernel-0 byte lane must agree at every position"
        );
        assert!(
            (3..=12).contains(&bytes.len()),
            "scalar U+{scalar:04X}: component emitted an invalid canonical-char byte length"
        );
    }
    for invalid in [0xd800, 0xdfff, 0x110000] {
        assert_eq!(
            canonical_char_renderer::render(invalid),
            Err(RendererRefusal::InvalidScalar)
        );
    }
    assert!(values.len() > 90, "broad scalar corpus became vacuous");
}

#[test]
fn byte_lane_keeps_canonical_delimiters_and_exact_positions_at_each_escape_boundary() {
    // This is deliberately a small literal table rather than deriving the
    // oracle from the component.  It pins the representation transitions that
    // are easiest to accidentally agree on when only final Strings are
    // compared: named escapes, printable ASCII, and every Unicode digit width.
    let expected = [
        (0, "'\\0'"),
        (9, "'\\t'"),
        (10, "'\\n'"),
        (13, "'\\r'"),
        (39, "'\\\''"),
        (92, "'\\\\'"),
        (32, "' '"),
        (126, "'~'"),
        (127, "'\\u{7f}'"),
        (255, "'\\u{ff}'"),
        (256, "'\\u{100}'"),
        (4096, "'\\u{1000}'"),
        (65536, "'\\u{10000}'"),
        (0x10ffff, "'\\u{10ffff}'"),
    ];
    for (scalar, expected) in expected {
        let actual = canonical_char_renderer::render_bytes(scalar).unwrap();
        assert_eq!(actual, expected.as_bytes(), "scalar U+{scalar:04X}");
        assert_eq!(actual.first(), Some(&b'\''), "scalar U+{scalar:04X}");
        assert_eq!(actual.last(), Some(&b'\''), "scalar U+{scalar:04X}");
        for (index, (actual, expected)) in actual.iter().zip(expected.bytes()).enumerate() {
            assert_eq!(
                *actual, expected,
                "scalar U+{scalar:04X}: byte {index} drifted from the independent literal oracle"
            );
        }
    }
}

#[test]
fn canonical_formatter_executes_the_kernel_zero_shadow_on_real_char_nodes() {
    let source = r#"module test.kernel_zero_formatter_shadow;

@id("test.kernel-zero-formatter-shadow.literal")
fn literal() -> char { '\n' }

@id("test.kernel-zero-formatter-shadow.match")
fn classify(value: char) -> i64
{
    match value {
        '\'' => 1,
        '\u{10ffff}' => 2,
        _ => 0,
    }
}

@id("test.kernel-zero-formatter-shadow.main")
fn main() -> i64 { classify(literal()) }
"#;
    let parsed = crate::parse(source, "kernel-zero-formatter-shadow.spx").unwrap();
    let expected = crate::format::canonical(&parsed);
    let (actual, comparisons) =
        canonical_char_renderer::with_shadow(|| crate::format::canonical(&parsed));
    assert_eq!(
        actual, expected,
        "shadowing changed canonical formatter bytes"
    );
    assert_eq!(
        comparisons, 8,
        "the canonical traversal must shadow every visit to the literal and pattern characters"
    );
}

fn bool_literal_oracle(value: bool) -> &'static [u8] {
    // Keep this literal oracle independent of both the Rust formatter and the
    // component: the only two canonical boolean spellings are intentionally
    // pinned as byte sequences.
    if value {
        b"true"
    } else {
        b"false"
    }
}

#[test]
fn exact_source_component_matches_the_independent_boolean_byte_oracle() {
    let parsed = crate::parse(BOOL_SOURCE, "kernel-zero-canonical-bool-renderer.spx")
        .expect("rung-2 boolean renderer component must parse");
    let resolved = hir::resolve(&parsed).expect("rung-2 boolean renderer component must resolve");
    for id in [
        "format.render-length",
        "format.true-byte",
        "format.false-byte",
        "format.render-byte",
    ] {
        let id = DeclarationId::new(id);
        assert!(
            super::reifies_into_kernel_zero(&resolved, &id),
            "rung-2 boolean renderer declaration {id} must stay in Kernel-0"
        );
    }
    let entry = DeclarationId::new("format.render-byte");
    let binding = BoundTranslation::derive(BOOL_SOURCE, &entry)
        .expect("rung-2 boolean renderer must have an exact-source Kernel-0 translation");
    assert!(binding.replay(BOOL_SOURCE, &entry).is_ok());

    for value in [false, true] {
        let expected = bool_literal_oracle(value);
        let actual = canonical_bool_renderer::render_bytes(value).unwrap();
        assert_eq!(
            actual, expected,
            "boolean {value}: exact Kernel-0 byte lane must agree at every position"
        );
        assert_eq!(
            canonical_bool_renderer::render(value).unwrap().as_bytes(),
            expected,
            "boolean {value}: UTF-8 result diverged"
        );
        assert!(
            (4..=5).contains(&actual.len()),
            "boolean {value}: component emitted an invalid canonical byte length"
        );
    }
}

#[test]
fn boolean_byte_lane_pins_each_canonical_byte_position() {
    for (value, expected) in [(true, b"true".as_slice()), (false, b"false".as_slice())] {
        let actual = canonical_bool_renderer::render_bytes(value).unwrap();
        assert_eq!(actual, expected, "boolean {value}");
        for (index, (actual, expected)) in actual.iter().zip(expected).enumerate() {
            assert_eq!(
                actual, expected,
                "boolean {value}: byte {index} drifted from the independent literal oracle"
            );
        }
    }
}

#[test]
fn canonical_formatter_executes_the_kernel_zero_shadow_on_real_bool_nodes() {
    let source = r#"module test.kernel_zero_bool_formatter_shadow;

@id("test.kernel-zero-bool-formatter-shadow.literal")
fn literal() -> bool { true }

@id("test.kernel-zero-bool-formatter-shadow.classify")
fn classify(value: bool) -> i64
{
    match value {
        true => 1,
        false => 2,
    }
}

@id("test.kernel-zero-bool-formatter-shadow.main")
fn main() -> i64 { classify(literal()) }
"#;
    let parsed = crate::parse(source, "kernel-zero-bool-formatter-shadow.spx").unwrap();
    let expected = crate::format::canonical(&parsed);
    let (actual, comparisons) =
        canonical_bool_renderer::with_shadow(|| crate::format::canonical(&parsed));
    assert_eq!(
        actual, expected,
        "shadowing changed canonical formatter bytes"
    );
    // The fixture has exactly three boolean syntax nodes: the `true` body of
    // `literal`, then the `true` and `false` literal patterns of `classify`.
    //
    // The body literal is visited twice: once by `rendered_expr_lengths` in
    // the canonical capacity census and once by final emission. Each pattern
    // is visited three times: the match expression's measured rendering,
    // `rendered_match_pattern_len`'s exact per-arm capacity accounting, and
    // final emission. Literal patterns contribute nothing to
    // `legacy_match_pattern_bytes`, so there is no hidden fourth visit. The
    // `main` body contains no boolean literal.
    const BODY_LITERAL_VISITS: usize = 2;
    const PATTERN_LITERAL_VISITS: usize = 3;
    const BOOL_PATTERN_COUNT: usize = 2;
    const EXPECTED_COMPARISONS: usize =
        BODY_LITERAL_VISITS + PATTERN_LITERAL_VISITS * BOOL_PATTERN_COUNT;
    assert_eq!(
        comparisons, EXPECTED_COMPARISONS,
        "the canonical formatter's capacity and emitted traversals must shadow the one boolean expression and two boolean patterns"
    );
}

fn operator_oracle(opcode: i64) -> &'static [u8] {
    // Do not derive this from `BinaryOp::text`, the formatter, or the
    // component. This literal table is the independent finite oracle for the
    // exact in-process opcode inventory documented by the component boundary.
    match opcode {
        0 => b"+",
        1 => b"-",
        2 => b"*",
        3 => b"/",
        4 => b"%",
        5 => b"==",
        6 => b"!=",
        7 => b"<",
        8 => b"<=",
        9 => b">",
        10 => b">=",
        11 => b"&&",
        12 => b"||",
        13 => b"-",
        14 => b"!",
        _ => panic!("operator oracle received an unadmitted opcode {opcode}"),
    }
}

#[test]
fn exact_source_component_matches_the_independent_canonical_operator_oracle() {
    let parsed = crate::parse(
        OPERATOR_SOURCE,
        "kernel-zero-canonical-operator-renderer.spx",
    )
    .expect("rung-2 operator renderer component must parse");
    let resolved = hir::resolve(&parsed).expect("rung-2 operator renderer component must resolve");
    for id in [
        "format.operator-render-length",
        "format.operator-first-byte",
        "format.operator-render-byte",
    ] {
        let id = DeclarationId::new(id);
        assert!(
            super::reifies_into_kernel_zero(&resolved, &id),
            "rung-2 operator renderer declaration {id} must stay in Kernel-0"
        );
    }
    let entry = DeclarationId::new("format.operator-render-byte");
    let binding = BoundTranslation::derive(OPERATOR_SOURCE, &entry)
        .expect("rung-2 operator renderer must have an exact-source Kernel-0 translation");
    assert!(binding.replay(OPERATOR_SOURCE, &entry).is_ok());

    for opcode in 0..=14 {
        let expected = operator_oracle(opcode);
        let actual = canonical_operator_renderer::render_bytes(opcode).unwrap();
        assert_eq!(actual, expected, "operator opcode {opcode}");
        assert!(
            (1..=2).contains(&actual.len()),
            "operator opcode {opcode} escaped the bounded byte lane"
        );
        for (index, expected_byte) in expected.iter().copied().enumerate() {
            assert_eq!(
                canonical_operator_renderer::render_byte(opcode, index).unwrap(),
                expected_byte,
                "operator opcode {opcode}, byte {index} drifted from the independent literal oracle"
            );
        }
        assert_eq!(
            canonical_operator_renderer::render_byte(opcode, expected.len()),
            Err(OperatorRendererRefusal::InvalidByte),
            "operator opcode {opcode} must reject its first out-of-range byte index"
        );
    }
    for opcode in [i64::MIN, -1, 15, i64::MAX] {
        assert_eq!(
            canonical_operator_renderer::render_bytes(opcode),
            Err(OperatorRendererRefusal::InvalidOpcode),
            "unknown opcode {opcode} must refuse before renderer output"
        );
    }
}

#[test]
fn canonical_formatter_executes_the_kernel_zero_shadow_on_real_operator_nodes() {
    let source = r#"module test.kernel_zero_operator_formatter_shadow;

@id("test.kernel-zero-operator-formatter-shadow.add")
fn add(left: i64, right: i64) -> i64 { left + right }

@id("test.kernel-zero-operator-formatter-shadow.sub")
fn sub(left: i64, right: i64) -> i64 { left - right }

@id("test.kernel-zero-operator-formatter-shadow.mul")
fn mul(left: i64, right: i64) -> i64 { left * right }

@id("test.kernel-zero-operator-formatter-shadow.div")
fn div(left: i64, right: i64) -> i64 { left / right }

@id("test.kernel-zero-operator-formatter-shadow.rem")
fn rem(left: i64, right: i64) -> i64 { left % right }

@id("test.kernel-zero-operator-formatter-shadow.eq")
fn equal(left: i64, right: i64) -> bool { left == right }

@id("test.kernel-zero-operator-formatter-shadow.ne")
fn not_equal(left: i64, right: i64) -> bool { left != right }

@id("test.kernel-zero-operator-formatter-shadow.lt")
fn less(left: i64, right: i64) -> bool { left < right }

@id("test.kernel-zero-operator-formatter-shadow.le")
fn less_equal(left: i64, right: i64) -> bool { left <= right }

@id("test.kernel-zero-operator-formatter-shadow.gt")
fn greater(left: i64, right: i64) -> bool { left > right }

@id("test.kernel-zero-operator-formatter-shadow.ge")
fn greater_equal(left: i64, right: i64) -> bool { left >= right }

@id("test.kernel-zero-operator-formatter-shadow.and")
fn both(left: bool, right: bool) -> bool { left && right }

@id("test.kernel-zero-operator-formatter-shadow.or")
fn either(left: bool, right: bool) -> bool { left || right }

@id("test.kernel-zero-operator-formatter-shadow.neg")
fn negate(value: i64) -> i64 { -value }

@id("test.kernel-zero-operator-formatter-shadow.not")
fn invert(value: bool) -> bool { !value }
"#;
    let parsed = crate::parse(source, "kernel-zero-operator-formatter-shadow.spx").unwrap();
    let expected = crate::format::canonical(&parsed);
    let (actual, comparisons) =
        canonical_operator_renderer::with_shadow(|| crate::format::canonical(&parsed));
    assert_eq!(
        actual, expected,
        "shadowing changed canonical formatter bytes"
    );
    // Every function body is one operator expression. The formatter first
    // measures the body for exact capacity and then emits it, so every one of
    // the 13 binary and two unary tokens must cross the shadow twice.
    const BINARY_OPERATOR_COUNT: usize = 13;
    const UNARY_OPERATOR_COUNT: usize = 2;
    const MEASURED_AND_EMITTED_VISITS: usize = 2;
    const EXPECTED_COMPARISONS: usize =
        (BINARY_OPERATOR_COUNT + UNARY_OPERATOR_COUNT) * MEASURED_AND_EMITTED_VISITS;
    assert_eq!(
        comparisons, EXPECTED_COMPARISONS,
        "the canonical formatter's measured and emitted traversals must shadow every operator token"
    );
}

fn decimal_oracle(value: i64) -> Vec<u8> {
    // Deliberately independent of `format::canonical_int` and Rust's decimal
    // formatter. Widening before negation makes the signed minimum ordinary.
    let mut magnitude = i128::from(value);
    let negative = magnitude < 0;
    if negative {
        magnitude = -magnitude;
    }
    let mut reversed = [0u8; 19];
    let mut digits = 0;
    loop {
        reversed[digits] = b'0' + (magnitude % 10) as u8;
        digits += 1;
        magnitude /= 10;
        if magnitude == 0 {
            break;
        }
    }
    let mut output = Vec::with_capacity(digits + if negative { 1 } else { 0 });
    if negative {
        output.push(b'-');
    }
    output.extend(reversed[..digits].iter().rev());
    output
}

#[test]
fn exact_source_component_matches_an_independent_decimal_byte_oracle() {
    let parsed = crate::parse(INT_SOURCE, "kernel-zero-canonical-int-renderer.spx")
        .expect("rung-2 integer renderer component must parse");
    let resolved = hir::resolve(&parsed).expect("rung-2 integer renderer component must resolve");
    for id in [
        "format.negative",
        "format.at-least",
        "format.decimal-digits",
        "format.power-of-ten",
        "format.decimal-digit",
        "format.render-length",
        "format.render-byte",
    ] {
        let id = DeclarationId::new(id);
        assert!(
            super::reifies_into_kernel_zero(&resolved, &id),
            "rung-2 integer renderer declaration {id} must stay in Kernel-0"
        );
    }
    let entry = DeclarationId::new("format.render-byte");
    let binding = BoundTranslation::derive(INT_SOURCE, &entry)
        .expect("rung-2 integer renderer must have an exact-source Kernel-0 translation");
    assert!(binding.replay(INT_SOURCE, &entry).is_ok());

    let mut values = vec![i64::MIN, -1, 0, 1, i64::MAX];
    // Each transition runs on both sides: the positive comparison path and
    // the signed-min-safe negative comparison path must agree on digit count.
    for threshold in [
        10,
        100,
        1_000,
        10_000,
        100_000,
        1_000_000,
        10_000_000,
        100_000_000,
        1_000_000_000,
        10_000_000_000,
        100_000_000_000,
        1_000_000_000_000,
        10_000_000_000_000,
        100_000_000_000_000,
        1_000_000_000_000_000,
        10_000_000_000_000_000,
        100_000_000_000_000_000,
        1_000_000_000_000_000_000,
    ] {
        values.extend([threshold - 1, threshold, 1 - threshold, -threshold]);
    }
    for value in values {
        let expected = decimal_oracle(value);
        let actual = canonical_int_renderer::render_bytes(value).unwrap();
        assert_eq!(actual, expected, "integer {value}: byte lane diverged");
        assert_eq!(
            canonical_int_renderer::render(value).unwrap().as_bytes(),
            expected.as_slice(),
            "integer {value}: UTF-8 result diverged"
        );
        assert!(
            (1..=20).contains(&actual.len()),
            "integer {value}: component emitted an invalid decimal byte length"
        );
    }
}

#[test]
fn canonical_formatter_executes_the_kernel_zero_shadow_on_real_int_nodes() {
    let source = r#"module test.kernel_zero_integer_formatter_shadow;

@id("test.kernel-zero-integer-formatter-shadow.literal")
fn literal() -> i64 { -42 }

@id("test.kernel-zero-integer-formatter-shadow.classify")
fn classify(value: i64) -> i64
{
    match value {
        -9223372036854775808 => 1,
        0 => 2,
        9223372036854775807 => 3,
        _ => 0,
    }
}
@id("test.kernel-zero-integer-formatter-shadow.main")
fn main() -> i64 { classify(literal()) }
"#;
    let parsed = crate::parse(source, "kernel-zero-integer-formatter-shadow.spx").unwrap();
    let expected = crate::format::canonical(&parsed);
    let (actual, comparisons) =
        canonical_int_renderer::with_shadow(|| crate::format::canonical(&parsed));
    assert_eq!(
        actual, expected,
        "shadowing changed canonical formatter bytes"
    );
    assert_eq!(
        comparisons, 19,
        "the canonical formatter's measured and emitted traversals must shadow every raw integer expression and pattern literal"
    );
}

fn string_fragment_oracle(value: u32) -> Vec<u8> {
    // This deliberately does not call the formatter or the component.  It
    // chooses the escape family directly, then lets Rust's UTF-8 encoder only
    // encode the non-escaped Unicode scalar branch.
    let mut bytes = Vec::new();
    match char::from_u32(value).expect("test corpus contains only scalars") {
        '\\' => bytes.extend_from_slice(b"\\\\"),
        '"' => bytes.extend_from_slice(b"\\\""),
        '\n' => bytes.extend_from_slice(b"\\n"),
        '\r' => bytes.extend_from_slice(b"\\r"),
        '\t' => bytes.extend_from_slice(b"\\t"),
        ch if value < 0x20 || value == 0x7f => {
            bytes.extend_from_slice(b"\\u{");
            bytes.extend(format!("{value:x}").bytes());
            bytes.push(b'}');
            assert_eq!(ch as u32, value);
        }
        ch => {
            let mut encoded = [0; 4];
            bytes.extend_from_slice(ch.encode_utf8(&mut encoded).as_bytes());
        }
    }
    bytes
}

#[test]
fn exact_source_component_matches_an_independent_string_byte_oracle() {
    let parsed = crate::parse(STRING_SOURCE, "kernel-zero-canonical-string-renderer.spx")
        .expect("rung-2 string renderer component must parse");
    let resolved = hir::resolve(&parsed).expect("rung-2 string renderer component must resolve");
    for id in [
        "format.scalar-valid",
        "format.named-escape",
        "format.unicode-escape",
        "format.hex-digits",
        "format.hex-nibble",
        "format.utf8-length",
        "format.utf8-byte",
        "format.named-byte",
        "format.render-length",
        "format.render-byte",
    ] {
        let id = DeclarationId::new(id);
        assert!(
            super::reifies_into_kernel_zero(&resolved, &id),
            "rung-2 string renderer declaration {id} must stay in Kernel-0"
        );
    }
    let entry = DeclarationId::new("format.render-byte");
    let binding = BoundTranslation::derive(STRING_SOURCE, &entry)
        .expect("rung-2 string renderer must have an exact-source Kernel-0 translation");
    assert!(binding.replay(STRING_SOURCE, &entry).is_ok());

    let values = valid_scalar_corpus();
    for scalar in &values {
        let expected = string_fragment_oracle(*scalar);
        let actual = canonical_string_renderer::render_bytes(*scalar).unwrap();
        assert_eq!(
            actual, expected,
            "string scalar U+{scalar:04X}: byte lane diverged"
        );
        assert_eq!(
            canonical_string_renderer::render(*scalar)
                .unwrap()
                .as_bytes(),
            expected.as_slice(),
            "string scalar U+{scalar:04X}: UTF-8 result diverged"
        );
        assert!(
            (1..=10).contains(&actual.len()),
            "string scalar U+{scalar:04X}: component emitted an invalid fragment length"
        );
    }
    for invalid in [0xd800, 0xdfff, 0x110000] {
        assert_eq!(
            canonical_string_renderer::render(invalid),
            Err(StringRendererRefusal::InvalidScalar)
        );
    }
    assert!(values.len() > 90, "broad scalar corpus became vacuous");
}

#[test]
fn string_byte_lane_pins_escapes_and_every_utf8_width_at_each_position() {
    let expected = [
        (0, "\\u{0}"),
        (9, "\\t"),
        (10, "\\n"),
        (13, "\\r"),
        (31, "\\u{1f}"),
        (34, "\\\""),
        (92, "\\\\"),
        (127, "\\u{7f}"),
        (128, "\u{80}"),
        (2047, "\u{7ff}"),
        (2048, "\u{800}"),
        (65535, "\u{ffff}"),
        (65536, "\u{10000}"),
        (0x10ffff, "\u{10ffff}"),
    ];
    for (scalar, expected) in expected {
        let actual = canonical_string_renderer::render_bytes(scalar).unwrap();
        assert_eq!(actual, expected.as_bytes(), "string scalar U+{scalar:04X}");
        for (index, (actual, expected)) in actual.iter().zip(expected.bytes()).enumerate() {
            assert_eq!(
                *actual, expected,
                "string scalar U+{scalar:04X}: byte {index} drifted from the independent literal oracle"
            );
        }
    }
}

#[test]
fn canonical_formatter_executes_the_kernel_zero_shadow_on_real_string_nodes() {
    let source = r#"module test.kernel_zero_string_formatter_shadow;

@id("test.kernel-zero-string-formatter-shadow.literal")
fn literal() -> string { "\t\n\r\\\"\u{7f}é🦀" }

@id("test.kernel-zero-string-formatter-shadow.main")
fn main() -> string { literal() }
"#;
    let parsed = crate::parse(source, "kernel-zero-string-formatter-shadow.spx").unwrap();
    let expected = crate::format::canonical(&parsed);
    let (actual, comparisons) =
        canonical_string_renderer::with_shadow(|| crate::format::canonical(&parsed));
    assert_eq!(
        actual, expected,
        "shadowing changed canonical formatter bytes"
    );
    assert_eq!(
        comparisons, 16,
        "the canonical formatter's measured and emitted traversals must shadow every decoded string scalar"
    );
}
