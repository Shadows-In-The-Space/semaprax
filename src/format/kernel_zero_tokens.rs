//! Canonical scalar tokens mediated by the conservative Kernel-0 boundary.
//!
//! Rust forms the authoritative spelling. The adapter evaluates the
//! source-bound candidate before comparing bytes, then returns either an
//! equal fixed token or the original Rust bytes.

use crate::ast::{BinaryOp, UnaryOp};

fn copied(
    mut write: impl FnMut(&mut [u8; crate::kernel_zero::rung_two_authority::MAX_TOKEN_BYTES]) -> usize,
) -> String {
    let mut output = [0; crate::kernel_zero::rung_two_authority::MAX_TOKEN_BYTES];
    let len = write(&mut output);
    String::from_utf8(output[..len].to_vec()).expect("canonical token must be UTF-8")
}

pub(crate) fn canonical_char(value: u32) -> String {
    const ESCAPES: &[(u32, &str)] = &[
        (0x00, "\\0"),
        (0x09, "\\t"),
        (0x0A, "\\n"),
        (0x0D, "\\r"),
        (0x27, "\\'"),
        (0x5C, "\\\\"),
    ];
    let mut rust = String::from("'");
    if let Some((_, escape)) = ESCAPES.iter().find(|(scalar, _)| *scalar == value) {
        rust.push_str(escape);
    } else if (0x20..=0x7E).contains(&value) {
        rust.push(char::from_u32(value).expect("printable ASCII is a scalar value"));
    } else {
        rust.push_str(&format!("\\u{{{:x}}}", value));
    }
    rust.push('\'');
    let selected =
        copied(|output| crate::kernel_zero::rung_two_authority::char_into(value, &rust, output));
    #[cfg(test)]
    crate::kernel_zero::canonical_char_renderer::verify_shadow(value, &rust);
    selected
}

pub(crate) fn canonical_int(value: i64) -> String {
    let rust = value.to_string();
    let selected =
        copied(|output| crate::kernel_zero::rung_two_authority::int_into(value, &rust, output));
    #[cfg(test)]
    crate::kernel_zero::canonical_int_renderer::verify_shadow(value, &rust);
    selected
}

pub(crate) fn canonical_bool(value: bool) -> String {
    let rust = value.to_string();
    let selected =
        copied(|output| crate::kernel_zero::rung_two_authority::bool_into(value, &rust, output));
    #[cfg(test)]
    crate::kernel_zero::canonical_bool_renderer::verify_shadow(value, &rust);
    selected
}

pub(crate) fn canonical_binary_op(op: BinaryOp) -> String {
    let rust = op.text();
    let selected = copied(|output| {
        crate::kernel_zero::rung_two_authority::binary_operator_into(op, rust, output)
    });
    #[cfg(test)]
    crate::kernel_zero::canonical_operator_renderer::verify_binary_shadow(op, rust);
    selected
}

pub(crate) fn canonical_unary_op(op: UnaryOp) -> String {
    let rust = match op {
        UnaryOp::Neg => "-",
        UnaryOp::Not => "!",
    };
    let selected = copied(|output| {
        crate::kernel_zero::rung_two_authority::unary_operator_into(op, rust, output)
    });
    #[cfg(test)]
    crate::kernel_zero::canonical_operator_renderer::verify_unary_shadow(op, rust);
    selected
}

pub(crate) fn canonical_string(value: &str) -> String {
    let mut text = String::from("\"");
    write_string_escaped(&mut text, value);
    text.push('\"');
    text
}

pub(crate) fn write_string_escaped(output: &mut impl std::fmt::Write, value: &str) {
    for ch in value.chars() {
        write_string_scalar(output, ch);
    }
}

fn write_string_scalar(output: &mut impl std::fmt::Write, ch: char) {
    let rust = match ch {
        '\\' => "\\\\".to_owned(),
        '\"' => "\\\"".to_owned(),
        '\n' => "\\n".to_owned(),
        '\r' => "\\r".to_owned(),
        '\t' => "\\t".to_owned(),
        _ if (ch as u32) < 0x20 || ch == '\u{7f}' => format!("\\u{{{:x}}}", ch as u32),
        _ => ch.to_string(),
    };
    let selected = copied(|output| {
        crate::kernel_zero::rung_two_authority::string_scalar_into(u32::from(ch), &rust, output)
    });
    #[cfg(test)]
    crate::kernel_zero::canonical_string_renderer::verify_shadow(u32::from(ch), &rust);
    output.write_str(&selected).unwrap();
}
