//! Model-oriented v2 text codec over an already validated projection.

use std::collections::BTreeMap;

use super::{
    capacity_error, digest_bytes, encode_bytes, malformed_error, tokenize_json_literals,
    ByteCursor, CompactProjection, Diagnostic, Segment, MAX_DICTIONARY_ENTRIES, MAX_ENCODED_BYTES,
    MAX_ENTRY_BYTES, MAX_HEADER_FIELD_BYTES, MAX_SOURCE_BYTES,
};

pub const MODEL_TEXT_FORMAT_VERSION: u32 = 2;
const MAGIC: &[u8] = b"SEMAPRAX-MODEL-TEXT 2\n";
const MIN_SOURCE_BYTES: usize = 16 * 1024;
const MIN_LITERAL_BYTES: usize = 16;
const MARKER: u8 = b'@';

/// Encode a canonical model-text v2 envelope. Small projections deliberately
/// carry no dictionary; v2 is an optional prompt transport, never a new Raw
/// projection representation.
pub fn encode_model_text(projection: &CompactProjection) -> Result<String, Diagnostic> {
    let source = projection.reconstructed()?;
    if source.len() > MAX_SOURCE_BYTES {
        return Err(capacity_error(
            "model text source exceeds source bound".into(),
        ));
    }
    let segments = tokenize_json_literals(&source)?;
    let mut counts = BTreeMap::<Vec<u8>, usize>::new();
    if source.len() >= MIN_SOURCE_BYTES {
        for segment in &segments {
            if let Segment::Literal(value) = segment {
                if value.len() >= MIN_LITERAL_BYTES {
                    *counts.entry(value.to_vec()).or_default() += 1;
                }
            }
        }
    }
    let dictionary: Vec<Vec<u8>> = counts
        .into_iter()
        .filter_map(|(value, count)| (count >= 2).then_some(value))
        .collect();
    if dictionary.len() > MAX_DICTIONARY_ENTRIES {
        return Err(capacity_error(
            "model text dictionary exceeds entry bound".into(),
        ));
    }
    let indices: BTreeMap<&[u8], usize> = dictionary
        .iter()
        .enumerate()
        .map(|(i, v)| (v.as_slice(), i))
        .collect();
    let mut body = Vec::new();
    for segment in segments {
        match segment {
            Segment::Raw(value) => {
                if value.contains(&MARKER) {
                    return Err(malformed_error(
                        "model text raw JSON span contains @ marker".into(),
                    ));
                }
                body.extend_from_slice(value);
            }
            Segment::Literal(value) => match indices.get(value) {
                Some(index) => body.extend_from_slice(format!("@{index}").as_bytes()),
                None => body.extend_from_slice(value),
            },
        }
    }
    let mut out = Vec::new();
    out.extend_from_slice(MAGIC);
    write_field(&mut out, b"profile", projection.profile.as_bytes());
    write_field(&mut out, b"root", projection.root.as_bytes());
    write_field(
        &mut out,
        b"source_revision",
        projection.source_revision.as_bytes(),
    );
    write_field(
        &mut out,
        b"source_digest",
        projection.source_digest.as_bytes(),
    );
    out.extend_from_slice(format!("dict {}\n", dictionary.len()).as_bytes());
    for entry in &dictionary {
        if entry.len() > MAX_ENTRY_BYTES {
            return Err(capacity_error(
                "model text dictionary entry exceeds bound".into(),
            ));
        }
        out.extend_from_slice(entry);
        out.push(b'\n');
    }
    out.extend_from_slice(b"body\n");
    out.extend_from_slice(&body);
    if out.len() > MAX_ENCODED_BYTES {
        return Err(capacity_error(
            "model text wire exceeds encoded bound".into(),
        ));
    }
    String::from_utf8(out).map_err(|_| malformed_error("model text encoding is not UTF-8".into()))
}

pub fn decode_model_text(bytes: &[u8]) -> Result<CompactProjection, Diagnostic> {
    if bytes.len() > MAX_ENCODED_BYTES {
        return Err(capacity_error(
            "model text wire exceeds encoded bound".into(),
        ));
    }
    let mut c = ByteCursor::new(bytes);
    c.expect_bytes(MAGIC)?;
    let profile = text(c.read_text_field(b"profile", MAX_HEADER_FIELD_BYTES)?)?;
    let root = text(c.read_text_field(b"root", MAX_HEADER_FIELD_BYTES)?)?;
    let revision = text(c.read_text_field(b"source_revision", MAX_HEADER_FIELD_BYTES)?)?;
    let digest = text(c.read_text_field(b"source_digest", MAX_HEADER_FIELD_BYTES)?)?;
    c.expect_bytes(b"dict ")?;
    let count = c.read_decimal(b'\n', 10)?;
    if count > MAX_DICTIONARY_ENTRIES {
        return Err(capacity_error(
            "model text dictionary exceeds entry bound".into(),
        ));
    }
    let mut dictionary = Vec::with_capacity(count);
    for _ in 0..count {
        dictionary.push(c.read_dictionary_line(MAX_ENTRY_BYTES)?.to_vec());
    }
    if dictionary.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(malformed_error(
            "model text dictionary is not strict canonical byte order".into(),
        ));
    }
    c.expect_bytes(b"body\n")?;
    let body = c.take_remaining();
    let mut source = Vec::new();
    let mut i = 0;
    let mut in_string = false;
    let mut escaped = false;
    while i < body.len() {
        let byte = body[i];
        if in_string {
            append_bounded(&mut source, &[byte])?;
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == b'"' {
                in_string = false;
            }
            i += 1;
            continue;
        }
        if byte == b'"' {
            in_string = true;
            append_bounded(&mut source, &[byte])?;
            i += 1;
            continue;
        }
        if byte != MARKER {
            append_bounded(&mut source, &[byte])?;
            i += 1;
            continue;
        }
        let start = i + 1;
        let mut end = start;
        while end < body.len() && body[end].is_ascii_digit() {
            end += 1;
        }
        if start == end || (end - start > 1 && body[start] == b'0') {
            return Err(malformed_error(
                "model text @ reference is not canonical decimal".into(),
            ));
        }
        let index: usize = std::str::from_utf8(&body[start..end])
            .ok()
            .and_then(|s| s.parse().ok())
            .ok_or_else(|| malformed_error("model text reference index is invalid".into()))?;
        let entry = dictionary
            .get(index)
            .ok_or_else(|| malformed_error("model text reference is outside dictionary".into()))?;
        append_bounded(&mut source, entry)?;
        i = end;
    }
    if digest_bytes(&source) != digest {
        return Err(malformed_error("model text source digest mismatch".into()));
    }
    let projection = encode_bytes(&source, &profile, &root, &revision)?;
    let canonical = encode_model_text(&projection)?;
    if canonical.as_bytes() != bytes {
        return Err(malformed_error("model text wire is not canonical".into()));
    }
    Ok(projection)
}

fn append_bounded(out: &mut Vec<u8>, bytes: &[u8]) -> Result<(), Diagnostic> {
    if out
        .len()
        .checked_add(bytes.len())
        .filter(|size| *size <= MAX_SOURCE_BYTES)
        .is_none()
    {
        return Err(capacity_error(
            "model text reconstructed source exceeds source bound".into(),
        ));
    }
    out.extend_from_slice(bytes);
    Ok(())
}

fn write_field(out: &mut Vec<u8>, name: &[u8], value: &[u8]) {
    out.extend_from_slice(name);
    out.push(b' ');
    out.extend_from_slice(value.len().to_string().as_bytes());
    out.push(b' ');
    out.extend_from_slice(value);
    out.push(b'\n');
}
fn text(bytes: &[u8]) -> Result<String, Diagnostic> {
    String::from_utf8(bytes.to_vec())
        .map_err(|_| malformed_error("model text header is not UTF-8".into()))
}

/// Model-text counterpart of the v1 binding decoders.
pub fn decode_model_text_and_verify(
    bytes: &[u8],
    expected_profile: &str,
    expected_root: &str,
    expected_source_revision: &str,
) -> Result<CompactProjection, Diagnostic> {
    super::verify_binding(
        decode_model_text(bytes)?,
        expected_profile,
        expected_root,
        expected_source_revision,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frozen_tiny_v2_wire_is_exact_and_independently_reconstructs_source() {
        const WIRE: &[u8] = b"SEMAPRAX-MODEL-TEXT 2\nprofile 1 p\nroot 1 r\nsource_revision 3 rev\nsource_digest 71 sha256:c5fe15aafcc9239c38a132854aff4135fd4962b2a0c5e56c6c200059fa1fbf4d\ndict 0\nbody\n{}";
        let projection = encode_bytes(b"{}", "p", "r", "rev").unwrap();
        assert_eq!(encode_model_text(&projection).unwrap().as_bytes(), WIRE);
        assert_eq!(
            decode_model_text(WIRE).unwrap().reconstructed().unwrap(),
            b"{}"
        );
        let mut wrong_version = WIRE.to_vec();
        wrong_version[20] = b'3';
        assert!(decode_model_text(&wrong_version).is_err());
        assert_eq!(
            decode_model_text_and_verify(WIRE, "p", "wrong", "rev")
                .unwrap_err()
                .code,
            "SPX-Z908"
        );
    }

    #[test]
    fn small_documents_inline_escaped_markers_and_round_trip() {
        let projection =
            encode_bytes(br#"{"note":"@literal~escaped\"quote"}"#, "p", "r", "rev").unwrap();
        let wire = encode_model_text(&projection).unwrap();
        assert!(wire.contains("dict 0\n"));
        assert_eq!(
            decode_model_text(wire.as_bytes())
                .unwrap()
                .reconstructed()
                .unwrap(),
            projection.reconstructed().unwrap()
        );
    }

    #[test]
    fn large_repeated_literals_reference_and_digest_tamper_refuses() {
        let repeated = "x".repeat(32);
        let literal = crate::diagnostic::quote_json(&repeated);
        let source = format!(
            "[{}]",
            std::iter::repeat_n(literal, 700)
                .collect::<Vec<_>>()
                .join(",")
        );
        let projection = encode_bytes(source.as_bytes(), "p", "r", "rev").unwrap();
        let wire = encode_model_text(&projection).unwrap();
        assert!(wire.contains("@0"));
        assert_eq!(
            decode_model_text(wire.as_bytes())
                .unwrap()
                .reconstructed()
                .unwrap(),
            source.as_bytes()
        );
        let marker = wire.find("sha256:").unwrap() + "sha256:".len();
        let mut forged = wire.into_bytes();
        forged[marker] = if forged[marker] == b'0' { b'1' } else { b'0' };
        assert!(decode_model_text(&forged).is_err());
    }

    #[test]
    fn malformed_references_dictionary_order_and_expansion_are_bounded() {
        let wire = b"SEMAPRAX-MODEL-TEXT 2\nprofile 1 p\nroot 1 r\nsource_revision 3 rev\nsource_digest 0 \ndict 2\n\"z\"\n\"a\"\nbody\n@0";
        assert!(decode_model_text(wire).is_err());
        let huge = vec![b'x'; MAX_ENTRY_BYTES];
        let mut wire = b"SEMAPRAX-MODEL-TEXT 2\nprofile 1 p\nroot 1 r\nsource_revision 3 rev\nsource_digest 0 \ndict 1\n".to_vec();
        wire.extend_from_slice(&huge);
        wire.push(b'\n');
        wire.extend_from_slice(b"body\n");
        for _ in 0..(MAX_SOURCE_BYTES / MAX_ENTRY_BYTES + 1) {
            wire.extend_from_slice(b"@0");
        }
        assert!(decode_model_text(&wire).is_err());
        let malformed = b"SEMAPRAX-MODEL-TEXT 2\nprofile 1 p\nroot 1 r\nsource_revision 3 rev\nsource_digest 0 \ndict 0\nbody\n@01";
        assert!(decode_model_text(malformed).is_err());
    }
}
