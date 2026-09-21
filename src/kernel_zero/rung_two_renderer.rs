//! A bounded, byte-lane renderer candidate for self-hosting rung 2.
//!
//! This is deliberately a **component candidate**, not a rung-2 claim.  The
//! production formatter's [`crate::format::canonical_char`] renders one
//! Unicode scalar to bytes, while Kernel-0 has only `i64`/`bool` values and
//! no owned string or byte-buffer type.  The SEMAPRAX program below therefore
//! exposes the smallest lossless scalar interface available in Kernel-0:
//! `render_length` and `render_byte(scalar, index)`.  A caller which supplies
//! the indices `0..render_length(scalar)` receives exactly the formatter's
//! canonical bytes on the valid-Unicode-scalar domain.
//!
//! Keeping the interface byte-level matters.  A prior plan that returned an
//! abstract escape kind would have tested a decision table, not a renderer;
//! it could agree while choosing a wrong hex digit, delimiter, or quote.  This
//! candidate instead compares every produced byte against the authoritative
//! Rust formatter.  It remains below rung 2: it neither owns/emits a buffer
//! in SEMAPRAX nor establishes bootstrap reproducibility.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use crate::hir::{self, DeclarationId};
use crate::interpreter::{self, InterpreterOptions};

use super::reify::BoundTranslation;

static NEXT_ID: AtomicU64 = AtomicU64::new(0);

const MAX_RENDERED_BYTES: i64 = 12;

fn source() -> &'static str {
    r#"module test.kernel_zero_rung_two_renderer;

@id("format.scalar-valid")
fn scalar_valid(value: i64) -> bool
{
    value >= 0 && value <= 1114111 && !(value >= 55296 && value <= 57343)
}

@id("format.named-escape")
fn named_escape(value: i64) -> bool
{
    value == 0 || value == 9 || value == 10 || value == 13 || value == 39 || value == 92
}

@id("format.hex-digits")
fn hex_digits(value: i64) -> i64
{
    if value < 16 {
        1
    } else {
        if value < 256 {
            2
        } else {
            if value < 4096 {
                3
            } else {
                if value < 65536 {
                    4
                } else {
                    if value < 1048576 {
                        5
                    } else {
                        6
                    }
                }
            }
        }
    }
}

@id("format.hex-nibble")
fn hex_nibble(value: i64, position: i64, digits: i64) -> i64
{
    let shift = digits - position - 1;
    let divisor = if shift == 0 {
        1
    } else {
        if shift == 1 {
            16
        } else {
            if shift == 2 {
                256
            } else {
                if shift == 3 {
                    4096
                } else {
                    if shift == 4 {
                        65536
                    } else {
                        1048576
                    }
                }
            }
        }
    };
    let nibble = (value / divisor) % 16;
    if nibble < 10 {
        48 + nibble
    } else {
        87 + nibble
    }
}

@id("format.render-length")
fn render_length(value: i64) -> i64
{
    if !scalar_valid(value) {
        0
    } else {
        if named_escape(value) {
            4
        } else {
            if value >= 32 && value <= 126 {
                3
            } else {
                6 + hex_digits(value)
            }
        }
    }
}

@id("format.named-byte")
fn named_byte(value: i64) -> i64
{
    if value == 0 {
        48
    } else {
        if value == 9 {
            116
        } else {
            if value == 10 {
                110
            } else {
                if value == 13 {
                    114
                } else {
                    value
                }
            }
        }
    }
}

@id("format.render-byte")
fn render_byte(value: i64, index: i64) -> i64
{
    let length = render_length(value);
    if index < 0 || index >= length {
        0
    } else {
        if index == 0 || index == length - 1 {
            39
        } else {
            if named_escape(value) {
                if index == 1 {
                    92
                } else {
                    named_byte(value)
                }
            } else {
                if value >= 32 && value <= 126 {
                    value
                } else {
                    if index == 1 {
                        92
                    } else {
                        if index == 2 {
                            117
                        } else {
                            if index == 3 {
                                123
                            } else {
                                if index == length - 2 {
                                    125
                                } else {
                                    hex_nibble(value, index - 4, hex_digits(value))
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

@id("test.main")
fn main() -> i64
{
    render_length(65)
}
"#
}

fn write_temp(source: &str) -> PathBuf {
    let ordinal = NEXT_ID.fetch_add(1, Ordering::Relaxed);
    let path = std::env::temp_dir().join(format!(
        "semaprax-kernel-zero-rung-two-renderer-{}-{ordinal}.spx",
        std::process::id()
    ));
    std::fs::write(&path, source).expect("rung-2 candidate temp source must be writable");
    path
}

fn compiler_i64(path: &Path, entry: &str, arguments: &[i64]) -> i64 {
    let arguments = arguments.iter().map(i64::to_string).collect::<Vec<_>>();
    let response = interpreter::interpret(path, entry, &arguments, &InterpreterOptions::default())
        .unwrap_or_else(|diagnostics| {
            panic!("rung-2 renderer candidate must be admitted: {diagnostics:?}")
        });
    let document: serde_json::Value = serde_json::from_str(&response.envelope)
        .expect("compiler interpreter response must remain JSON");
    let outcome = &document["payload"]["outcome"];
    assert_eq!(outcome["kind"].as_str(), Some("returned"), "{document}");
    assert_eq!(outcome["type"].as_str(), Some("i64"), "{document}");
    outcome["value"]
        .as_str()
        .expect("i64 response must carry canonical text")
        .parse()
        .expect("compiler i64 response must parse")
}

fn valid_scalar_corpus() -> Vec<i64> {
    let mut values = vec![
        0, 1, 8, 9, 10, 11, 12, 13, 14, 31, 32, 33, 34, 38, 39, 40, 91, 92, 93, 125, 126, 127, 128,
        255, 256, 4095, 4096, 65535, 65536, 0xd7ff, 0xe000, 0xffff, 0x10000, 0x10ffff,
    ];
    // A deterministic spread across the non-surrogate scalar space catches
    // every hexadecimal-width region without pretending a finite corpus is a
    // universal byte-rendering theorem.
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
fn canonical_char_byte_lane_candidate_is_exact_over_a_broad_scalar_corpus() {
    let source = source();
    let parsed = crate::parse(source, "kernel-zero-rung-two-renderer.spx")
        .expect("rung-2 renderer candidate must parse");
    let resolved = hir::resolve(&parsed).expect("rung-2 renderer candidate must resolve");
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
    let binding = BoundTranslation::derive(source, &entry)
        .expect("rung-2 renderer must have an exact-source Kernel-0 translation");
    let replayed = binding
        .replay(source, &entry)
        .expect("rung-2 renderer translation must replay exact source");
    assert!(replayed.function(&entry).is_some());

    let path = write_temp(source);
    let mut compared = 0usize;
    for scalar in valid_scalar_corpus() {
        let expected = crate::format::canonical_char(scalar as u32).into_bytes();
        let length = compiler_i64(&path, "format.render-length", &[scalar]);
        assert_eq!(length as usize, expected.len(), "scalar U+{scalar:04X}");
        for index in -1..=MAX_RENDERED_BYTES {
            let actual = compiler_i64(&path, "format.render-byte", &[scalar, index]);
            let expected_byte = expected.get(index as usize).copied().unwrap_or(0) as i64;
            assert_eq!(actual, expected_byte, "scalar U+{scalar:04X}, byte {index}");
            compared += 1;
        }
    }
    for invalid in [-1, 0xd800, 0xdfff, 0x110000] {
        assert_eq!(compiler_i64(&path, "format.render-length", &[invalid]), 0);
        for index in -1..=MAX_RENDERED_BYTES {
            assert_eq!(
                compiler_i64(&path, "format.render-byte", &[invalid, index]),
                0
            );
            compared += 1;
        }
    }
    let _ = std::fs::remove_file(&path);
    assert_eq!(
        compared,
        (valid_scalar_corpus().len() + 4) * (MAX_RENDERED_BYTES as usize + 2),
        "the byte-comparison corpus changed unexpectedly"
    );
}
