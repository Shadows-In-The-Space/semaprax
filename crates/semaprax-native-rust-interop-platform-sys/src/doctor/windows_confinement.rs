//! Windows confinement and settlement contract for
//! [`DOCTOR-PRODUCTION-PROVISIONER-WINDOWS-V1`][doc] (issue #236).
//!
//! This is a standalone confinement primitive, analogous to
//! `doctor::darwin_confinement`: it is not the ordinary `--version` probe in
//! `doctor::windows` (which already assigns a suspended leader to a
//! non-breakaway job before any user code runs, and is not touched by this
//! module), and it is not wired into any ordinary CLI route or into
//! `provisioned_doctor_*`.
//!
//! This module is split so that the parts with no Win32 dependency --
//! sealed-capsule structural validation ([`capsule`]), fail-closed admission
//! ordering ([`refusal`]), and the sticky settlement state machine
//! ([`settlement`]) -- compile and run their tests on every host this crate
//! builds on, this one included. Only [`primitive`], the actual restricted
//! token / tightened job object / ACL'd scratch root / sealed-capsule
//! consumption wiring, is `#[cfg(windows)]`: it has never been compiled or
//! executed on this authoring host (macOS arm64, no Windows toolchain, no
//! `*-pc-windows-*` target). See [`primitive`]'s module documentation for
//! exactly what was and was not verified about it, and for the specific
//! simplifications it makes relative to the full contract in the owning
//! specification.
//!
//! [doc]: https://github.com/wavect/semaprax/blob/main/docs/DOCTOR-PRODUCTION-PROVISIONER-WINDOWS-V1.md
//!
//! `dead_code` is allowed for this module tree because `src/lib.rs` --
//! outside this session's file lease (`crates/semaprax-native-rust-interop-platform-sys/src/doctor/**`,
//! `crates/semaprax-doctor-collector/**`, `docs/DOCTOR-*.md`) -- does not yet
//! re-export it the way it re-exports `doctor::darwin_confinement`, so these
//! otherwise-`pub` items are unreachable from the crate's own public surface
//! on a plain (non-test) build. A session with `src/lib.rs` in its lease
//! should add `pub use doctor::windows_confinement;` there (mirroring the
//! existing `darwin_confinement` re-export) and delete this allow.
#![allow(dead_code)]
pub mod capsule;
#[cfg(windows)]
pub mod primitive;
pub mod refusal;
pub mod settlement;
