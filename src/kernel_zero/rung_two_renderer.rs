//! Rung-2 integration evidence for canonical `char` rendering.
//!
//! The component under test is production-compiled code in
//! `canonical_char_renderer`; it derives and independently replays the exact
//! embedded Semaprax source into Kernel-0 before evaluating its byte lane.
//! The second test enables that component as a shadow of the real canonical
//! formatter path, proving the integration is not an isolated candidate.
//!
//! Rust output remains authoritative. A mismatch fails the shadow gate, but
//! the shipped formatter neither depends on nor falls back to the component.
//! This is the first rung-2 integration step, not rung-2 promotion.

use crate::hir::{self, DeclarationId};

use super::canonical_char_renderer::{self, RendererRefusal, SOURCE};
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
        assert_eq!(
            canonical_char_renderer::render(*scalar).unwrap(),
            crate::format::canonical_char(*scalar),
            "scalar U+{scalar:04X}"
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
