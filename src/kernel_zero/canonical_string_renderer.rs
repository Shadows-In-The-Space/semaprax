//! Exact-source Kernel-0 component boundary for canonical string escaping.
//!
//! Kernel-0 represents one Unicode scalar at a time, so this component is a
//! bounded byte lane for a single already-decoded scalar.  It emits the exact
//! bytes that belong between the Rust formatter's outer string delimiters:
//! named escapes, lowercase `\\u{...}` controls, or direct UTF-8.  There is no
//! Kernel-0 string buffer, ownership route, or formatter authority here.
//!
//! The component is deliberately non-authoritative.  The production formatter
//! still emits Rust's canonical scalar fragment.  Tests can enable the shadow
//! hook below, which independently derives and replays the exact embedded
//! source before comparing its bytes at each real formatter visit.

use std::sync::OnceLock;

use crate::hir::DeclarationId;

use super::eval::eval_program;
use super::reify::{BoundTranslation, Refusal};
use super::term::KernelProgram;
use super::value::Value;

pub(crate) const SOURCE: &str = include_str!("canonical_string_renderer.spx");
const MAX_RENDERED_BYTES: usize = 10;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RendererRefusal {
    InvalidScalar,
    Profile,
    MissingEntry,
    Evaluation,
    InvalidLength,
    InvalidByte,
}

impl From<Refusal> for RendererRefusal {
    fn from(_: Refusal) -> Self {
        Self::Profile
    }
}

struct Renderer {
    /// The binding, not only an initially translated program, is retained so
    /// every complete byte lane replays its exact source bytes before it can
    /// evaluate.  A prior success cannot bless drifted component source.
    binding: BoundTranslation,
}

impl Renderer {
    fn derive() -> Result<Self, RendererRefusal> {
        Self::derive_from_source(SOURCE)
    }

    fn derive_from_source(source: &str) -> Result<Self, RendererRefusal> {
        let entry = DeclarationId::new("format.render-byte");
        let binding = BoundTranslation::derive(source, &entry)?;
        Ok(Self { binding })
    }

    fn int(
        &self,
        program: &KernelProgram,
        entry: &str,
        arguments: &[i64],
    ) -> Result<i64, RendererRefusal> {
        let entry = program
            .function(&DeclarationId::new(entry))
            .ok_or(RendererRefusal::MissingEntry)?;
        let arguments = arguments
            .iter()
            .copied()
            .map(Value::Int)
            .collect::<Vec<_>>();
        match eval_program(program, entry, &arguments) {
            Ok(Value::Int(value)) => Ok(value),
            Ok(Value::Bool(_)) | Err(_) => Err(RendererRefusal::Evaluation),
        }
    }

    fn bytes(&self, source: &str, value: u32) -> Result<Vec<u8>, RendererRefusal> {
        if char::from_u32(value).is_none() {
            return Err(RendererRefusal::InvalidScalar);
        }
        let bound_entry = DeclarationId::new("format.render-byte");
        let program = self.binding.replay(source, &bound_entry)?;
        let value = i64::from(value);
        let length = self.int(program, "format.render-length", &[value])?;
        let length = usize::try_from(length).map_err(|_| RendererRefusal::InvalidLength)?;
        if !(1..=MAX_RENDERED_BYTES).contains(&length) {
            return Err(RendererRefusal::InvalidLength);
        }
        let mut bytes = Vec::with_capacity(length);
        for index in 0..length {
            let byte = self.int(program, "format.render-byte", &[value, index as i64])?;
            bytes.push(u8::try_from(byte).map_err(|_| RendererRefusal::InvalidByte)?);
        }
        Ok(bytes)
    }

    fn render(&self, source: &str, value: u32) -> Result<String, RendererRefusal> {
        String::from_utf8(self.bytes(source, value)?).map_err(|_| RendererRefusal::InvalidByte)
    }
}

pub(crate) fn render(value: u32) -> Result<String, RendererRefusal> {
    static RENDERER: OnceLock<Result<Renderer, RendererRefusal>> = OnceLock::new();
    RENDERER
        .get_or_init(Renderer::derive)
        .as_ref()
        .map_err(|error| *error)?
        .render(SOURCE, value)
}

/// Test-only access to the independently evaluated scalar byte lane.  The
/// ordinary interface stays fragment-shaped rather than allocating a
/// Kernel-0-owned string or granting the component production authority.
#[cfg(test)]
pub(crate) fn render_bytes(value: u32) -> Result<Vec<u8>, RendererRefusal> {
    static RENDERER: OnceLock<Result<Renderer, RendererRefusal>> = OnceLock::new();
    RENDERER
        .get_or_init(Renderer::derive)
        .as_ref()
        .map_err(|error| *error)?
        .bytes(SOURCE, value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cached_renderer_replays_the_exact_component_source_before_emitting_bytes() {
        let renderer = Renderer::derive().expect("embedded component must derive");
        assert_eq!(
            renderer.bytes(SOURCE, u32::from('🦀')).unwrap(),
            "🦀".as_bytes(),
            "the exact embedded source must replay before byte-lane evaluation"
        );

        let drifted = SOURCE.replacen("value == 9", "value == 8", 1);
        assert_ne!(drifted, SOURCE, "source-drift control must mutate bytes");
        assert_eq!(
            renderer.bytes(&drifted, u32::from('A')),
            Err(RendererRefusal::Profile),
            "a cached translation must not evaluate against changed component bytes"
        );
    }
}

#[cfg(test)]
mod shadow {
    use std::cell::Cell;

    thread_local! {
        static ENABLED: Cell<bool> = const { Cell::new(false) };
        static COMPARISONS: Cell<usize> = const { Cell::new(0) };
    }

    pub(super) fn verify(value: u32, rust: &str) {
        if !ENABLED.get() {
            return;
        }
        let rendered = super::render(value)
            .unwrap_or_else(|error| panic!("Kernel-0 canonical-string shadow refused: {error:?}"));
        assert_eq!(rendered, rust, "Kernel-0 canonical-string shadow disagreed");
        COMPARISONS.set(COMPARISONS.get() + 1);
    }

    pub(super) fn run<T>(operation: impl FnOnce() -> T) -> (T, usize) {
        ENABLED.with(|enabled| {
            assert!(
                !enabled.replace(true),
                "canonical-string shadow cannot nest"
            );
        });
        COMPARISONS.set(0);
        struct Restore;
        impl Drop for Restore {
            fn drop(&mut self) {
                ENABLED.set(false);
            }
        }
        let restore = Restore;
        let output = operation();
        let comparisons = COMPARISONS.get();
        drop(restore);
        (output, comparisons)
    }
}

#[cfg(test)]
pub(crate) fn verify_shadow(value: u32, rust: &str) {
    shadow::verify(value, rust);
}

#[cfg(test)]
pub(crate) fn with_shadow<T>(operation: impl FnOnce() -> T) -> (T, usize) {
    shadow::run(operation)
}
