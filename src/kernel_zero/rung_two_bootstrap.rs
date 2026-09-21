//! Durable, exact-source bootstrap artifact for the five Kernel-0 renderer
//! fragments.
//!
//! This module deliberately packages compiler outputs, not formatter authority.
//! The ordinary formatter continues to be Rust-authoritative; consumers must
//! independently decode and replay an artifact before treating it as evidence.
//! Raw C11 and Core-Wasm bytes are reproducible target payloads only.  They have
//! no component entry wrapper here, so this module does not claim target
//! execution or a self-hosting-rung promotion.

mod artifact;
mod decode;

#[cfg(test)]
mod tests;
