//! Exact-source Kernel-0 component boundary for canonical `char` rendering.
//!
//! The embedded Semaprax module is parsed, resolved, bounded, translated, and
//! independently replayed before its Kernel-0 program can render a byte.  The
//! interface remains a scalar byte lane because Kernel-0 has no owned buffer:
//! one call obtains the length and subsequent calls obtain each byte.
//!
//! This component is not authoritative.  The production formatter continues
//! to return its Rust rendering.  Tests can enable the shadow hook below so the
//! real formatting path executes this component and refuses disagreement.  A
//! later rung must add bootstrap reproducibility, a durable generated artifact,
//! fallback/recovery evidence, and hosted execution before authority can move.

use std::sync::OnceLock;

use crate::hir::DeclarationId;

use super::eval::eval_program;
use super::reify::{BoundTranslation, Refusal};
use super::term::KernelProgram;
use super::value::Value;

pub(crate) const SOURCE: &str = include_str!("canonical_char_renderer.spx");
const MAX_RENDERED_BYTES: usize = 12;

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
    program: KernelProgram,
}

impl Renderer {
    fn derive() -> Result<Self, RendererRefusal> {
        let entry = DeclarationId::new("format.render-byte");
        let binding = BoundTranslation::derive(SOURCE, &entry)?;
        let program = binding.replay(SOURCE, &entry)?.clone();
        Ok(Self { program })
    }

    fn int(&self, entry: &str, arguments: &[i64]) -> Result<i64, RendererRefusal> {
        let entry = self
            .program
            .function(&DeclarationId::new(entry))
            .ok_or(RendererRefusal::MissingEntry)?;
        let arguments = arguments
            .iter()
            .copied()
            .map(Value::Int)
            .collect::<Vec<_>>();
        match eval_program(&self.program, entry, &arguments) {
            Ok(Value::Int(value)) => Ok(value),
            Ok(Value::Bool(_)) | Err(_) => Err(RendererRefusal::Evaluation),
        }
    }

    fn render(&self, value: u32) -> Result<String, RendererRefusal> {
        if char::from_u32(value).is_none() {
            return Err(RendererRefusal::InvalidScalar);
        }
        let value = i64::from(value);
        let length = self.int("format.render-length", &[value])?;
        let length = usize::try_from(length).map_err(|_| RendererRefusal::InvalidLength)?;
        if !(3..=MAX_RENDERED_BYTES).contains(&length) {
            return Err(RendererRefusal::InvalidLength);
        }
        let mut bytes = Vec::with_capacity(length);
        for index in 0..length {
            let byte = self.int("format.render-byte", &[value, index as i64])?;
            bytes.push(u8::try_from(byte).map_err(|_| RendererRefusal::InvalidByte)?);
        }
        String::from_utf8(bytes).map_err(|_| RendererRefusal::InvalidByte)
    }
}

pub(crate) fn render(value: u32) -> Result<String, RendererRefusal> {
    static RENDERER: OnceLock<Result<Renderer, RendererRefusal>> = OnceLock::new();
    RENDERER
        .get_or_init(Renderer::derive)
        .as_ref()
        .map_err(|error| *error)?
        .render(value)
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
            .unwrap_or_else(|error| panic!("Kernel-0 canonical-char shadow refused: {error:?}"));
        assert_eq!(rendered, rust, "Kernel-0 canonical-char shadow disagreed");
        COMPARISONS.set(COMPARISONS.get() + 1);
    }

    pub(super) fn run<T>(operation: impl FnOnce() -> T) -> (T, usize) {
        ENABLED.with(|enabled| {
            assert!(!enabled.replace(true), "canonical-char shadow cannot nest");
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
