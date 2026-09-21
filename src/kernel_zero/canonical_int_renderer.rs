//! Exact-source Kernel-0 component boundary for canonical signed-integer rendering.
//!
//! The component uses a bounded byte lane: Kernel-0 has no owned buffer, so
//! one evaluation obtains the decimal byte length and the later evaluations
//! obtain individual bytes.  It preserves `i64::MIN` exactly by never taking
//! an absolute value; quotient/remainder signs are normalized per digit.
//!
//! This is test-only shadow evidence.  The formatter's Rust decimal rendering
//! remains authoritative; a later rung still needs reproducibility, durable
//! artifacts, recovery evidence, and hosted execution before any authority
//! could move.

use std::sync::OnceLock;

use crate::hir::DeclarationId;

use super::eval::eval_program;
use super::reify::{BoundTranslation, Refusal};
use super::term::KernelProgram;
use super::value::Value;

pub(crate) const SOURCE: &str = include_str!("canonical_int_renderer.spx");
const MAX_RENDERED_BYTES: usize = 20;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RendererRefusal {
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
    /// Retain the binding rather than just a first translated program so every
    /// byte-lane invocation replays the exact component source before use.
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

    fn bytes(&self, source: &str, value: i64) -> Result<Vec<u8>, RendererRefusal> {
        let bound_entry = DeclarationId::new("format.render-byte");
        let program = self.binding.replay(source, &bound_entry)?;
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

    fn render(&self, source: &str, value: i64) -> Result<String, RendererRefusal> {
        String::from_utf8(self.bytes(source, value)?).map_err(|_| RendererRefusal::InvalidByte)
    }
}

pub(crate) fn render(value: i64) -> Result<String, RendererRefusal> {
    static RENDERER: OnceLock<Result<Renderer, RendererRefusal>> = OnceLock::new();
    RENDERER
        .get_or_init(Renderer::derive)
        .as_ref()
        .map_err(|error| *error)?
        .render(SOURCE, value)
}

#[cfg(test)]
pub(crate) fn render_bytes(value: i64) -> Result<Vec<u8>, RendererRefusal> {
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
            renderer.bytes(SOURCE, i64::MIN).unwrap(),
            b"-9223372036854775808".to_vec(),
            "the exact embedded source must replay before byte-lane evaluation"
        );

        let drifted = SOURCE.replacen("value < 0", "value <= 0", 1);
        assert_ne!(drifted, SOURCE, "source-drift control must mutate bytes");
        assert_eq!(
            renderer.bytes(&drifted, 42),
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

    pub(super) fn verify(value: i64, rust: &str) {
        if !ENABLED.get() {
            return;
        }
        let rendered = super::render(value)
            .unwrap_or_else(|error| panic!("Kernel-0 canonical-int shadow refused: {error:?}"));
        assert_eq!(rendered, rust, "Kernel-0 canonical-int shadow disagreed");
        COMPARISONS.set(COMPARISONS.get() + 1);
    }

    pub(super) fn run<T>(operation: impl FnOnce() -> T) -> (T, usize) {
        ENABLED.with(|enabled| {
            assert!(!enabled.replace(true), "canonical-int shadow cannot nest");
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
pub(crate) fn verify_shadow(value: i64, rust: &str) {
    shadow::verify(value, rust);
}

#[cfg(test)]
pub(crate) fn with_shadow<T>(operation: impl FnOnce() -> T) -> (T, usize) {
    shadow::run(operation)
}
