//! Durable, exact-source bootstrap artifact for the five Kernel-0 renderer
//! fragments.
//!
//! This module deliberately packages compiler outputs, not formatter authority.
//! The ordinary formatter continues to be Rust-authoritative; consumers must
//! independently decode and replay an artifact before treating it as evidence.
//! Raw C11 and Core-Wasm bytes are reproducible target payloads only. The
//! closed v2 wire also retains a private scalar-export Wasm companion for
//! execution evidence; it is neither a public ABI nor formatter authority.

mod artifact;
mod decode;

pub(crate) fn canonical_term_bytes(program: &super::term::KernelProgram) -> Result<Vec<u8>, ()> {
    artifact::encode_program(program).map_err(|_| ())
}

pub(crate) fn renderer_core_definitions() -> [(&'static str, &'static str); 5] {
    artifact::component_defs().map(|component| (component.source, component.entry))
}

#[cfg(test)]
mod recovery;
#[cfg(test)]
mod target_execution;
#[cfg(test)]
mod tests;

#[cfg(test)]
pub(super) fn with_target_scratch(work: impl FnOnce(&std::path::Path)) {
    let scratch = target_execution::Scratch::create().expect("bounded target scratch");
    work(scratch.path());
}

#[cfg(test)]
pub(super) fn run_target(
    command: &mut std::process::Command,
) -> Result<(bool, Vec<u8>, Vec<u8>), ()> {
    target_execution::run_bounded(command)
        .map(|output| (output.status.success(), output.stdout, output.stderr))
        .map_err(|_| ())
}
