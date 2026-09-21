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

#[cfg(test)]
mod recovery;
#[cfg(test)]
mod target_execution;
#[cfg(test)]
mod tests;
