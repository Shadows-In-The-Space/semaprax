//! Structural (non-cryptographic) mirror of `semaprax-doctor-capsule`'s wire
//! body format, for the Windows confinement contract's sealed-capsule stage.
//!
//! This module deliberately does **not** verify the release Ed25519
//! signature that `semaprax_doctor_capsule::parse_signed` requires before a
//! capsule may be trusted. That crate (`crates/semaprax-doctor-capsule`) is
//! today a `cfg(target_os = "linux")`-only dependency of this crate
//! (`crates/semaprax-native-rust-interop-platform-sys/Cargo.toml`) -- a file
//! outside this session's file lease
//! (`crates/semaprax-native-rust-interop-platform-sys/src/doctor/**`,
//! `crates/semaprax-doctor-collector/**`, `docs/DOCTOR-*.md`). A
//! Windows-capable session with `Cargo.toml` in its lease should add
//! `semaprax-doctor-capsule` as a `cfg(windows)` dependency too and delete
//! this module's body decoder in favor of calling that crate's
//! `parse_signed` directly. Duplicating a signature-relevant wire decoder
//! indefinitely is exactly the drift this repository's invariants warn
//! against ("do not sort, repair, or reinterpret canonical ... downstream");
//! this module exists only so the Windows admission ordering in
//! [`super::refusal`] and this crate's own hostile-input tests have real
//! capsule structure to refuse against, on any host, today, and so that a
//! future swap to the shared codec is a deletion, not a format migration.
//!
//! Every constant, field order, and validation rule below is kept
//! byte-for-byte identical to `semaprax-doctor-capsule` 0.1.0's private body
//! decoder (`crates/semaprax-doctor-capsule/src/lib.rs`, `parse_signed`'s
//! body-parsing stage). A [`CapsuleBody`] alone is **not** a trust decision:
//! its `unverified_signature` field is copied out but never checked, and
//! callers must not treat a successful [`parse_capsule_body`] as sealed-input
//! admission under [`DOCTOR-SEALED-INPUT-V1`][sealed] or
//! [`DOCTOR-PRODUCTION-PROVISIONER-V1`][provisioner]'s signed-capsule
//! contract.
//!
//! [sealed]: https://github.com/wavect/semaprax/blob/main/docs/DOCTOR-SEALED-INPUT-V1.md
//! [provisioner]: https://github.com/wavect/semaprax/blob/main/docs/DOCTOR-PRODUCTION-PROVISIONER-V1.md

pub const ARTIFACT_COUNT: usize = 5;
pub const MAX_CAPSULE_BYTES: usize = 341;
/// Held equal to the shared codec's `MAX_ARTIFACT_BYTES`: this bound is a
/// wire-format field width sanity check, not an independent capacity policy.
pub const MAX_ARTIFACT_BYTES: u64 = 1024 * 1024 * 1024;

const MAGIC: &[u8; 8] = b"SPXDPC1\0";
const VERSION: u8 = 1;
const SIGNATURE_BYTES: usize = 64;
const MAX_SELECTOR_BYTES: usize = 64;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CapsuleError {
    Invalid,
    Limit,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Artifact {
    pub length: u64,
    pub digest: [u8; 32],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CapsuleBody {
    pub architecture: u8,
    pub target: u8,
    pub roles: u8,
    pub selector: String,
    pub artifacts: [Artifact; ARTIFACT_COUNT],
    /// Copied verbatim from the trailing 64 bytes; never checked by this
    /// module. See the module documentation: signature verification is the
    /// reused `semaprax-doctor-capsule` crate's job, once it is available on
    /// Windows.
    pub unverified_signature: [u8; SIGNATURE_BYTES],
}

/// Structurally decode a capsule's body fields without verifying its
/// signature. Field order, bounds, and error classification are identical to
/// `semaprax_doctor_capsule::parse_signed`'s body stage; see the module
/// documentation for why the signature step is absent here.
pub fn parse_capsule_body(bytes: &[u8]) -> Result<CapsuleBody, CapsuleError> {
    if bytes.len() > MAX_CAPSULE_BYTES {
        return Err(CapsuleError::Limit);
    }
    if bytes.len() < MAGIC.len() + 5 + ARTIFACT_COUNT * 40 + SIGNATURE_BYTES {
        return Err(CapsuleError::Invalid);
    }
    let body_len = bytes.len() - SIGNATURE_BYTES;
    let (body, signature) = bytes.split_at(body_len);
    let unverified_signature: [u8; SIGNATURE_BYTES] =
        signature.try_into().map_err(|_| CapsuleError::Invalid)?;

    let mut cursor = 0usize;
    if take(body, &mut cursor, MAGIC.len())? != MAGIC || byte(body, &mut cursor)? != VERSION {
        return Err(CapsuleError::Invalid);
    }
    let architecture = byte(body, &mut cursor)?;
    validate_architecture(architecture)?;
    let target = byte(body, &mut cursor)?;
    let expected_roles = roles_for_target(target).ok_or(CapsuleError::Invalid)?;
    let roles = byte(body, &mut cursor)?;
    if roles != expected_roles {
        return Err(CapsuleError::Invalid);
    }
    let selector_len = usize::from(byte(body, &mut cursor)?);
    let selector_bytes = take(body, &mut cursor, selector_len)?;
    validate_selector(selector_bytes)?;
    let selector = std::str::from_utf8(selector_bytes)
        .map_err(|_| CapsuleError::Invalid)?
        .to_owned();
    let mut artifacts = [Artifact {
        length: 0,
        digest: [0; 32],
    }; ARTIFACT_COUNT];
    for artifact in &mut artifacts {
        artifact.length = u64::from_le_bytes(array(body, &mut cursor)?);
        artifact.digest = array(body, &mut cursor)?;
    }
    validate_artifacts(&artifacts)?;
    if cursor != body.len() {
        return Err(CapsuleError::Invalid);
    }
    Ok(CapsuleBody {
        architecture,
        target,
        roles,
        selector,
        artifacts,
        unverified_signature,
    })
}

pub fn roles_for_target(target: u8) -> Option<u8> {
    match target {
        0 => Some(4),
        1 => Some(1),
        2 => Some(2),
        3 => Some(7),
        _ => None,
    }
}

fn validate_architecture(architecture: u8) -> Result<(), CapsuleError> {
    if matches!(architecture, 1 | 2) {
        Ok(())
    } else {
        Err(CapsuleError::Invalid)
    }
}

fn validate_selector(selector: &[u8]) -> Result<(), CapsuleError> {
    if selector.is_empty()
        || selector.len() > MAX_SELECTOR_BYTES
        || !selector[0].is_ascii_lowercase()
        || !selector
            .iter()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'-')
    {
        Err(CapsuleError::Invalid)
    } else {
        Ok(())
    }
}

fn validate_artifacts(artifacts: &[Artifact; ARTIFACT_COUNT]) -> Result<(), CapsuleError> {
    if artifacts
        .iter()
        .any(|artifact| artifact.length == 0 || artifact.length > MAX_ARTIFACT_BYTES)
    {
        Err(CapsuleError::Limit)
    } else {
        Ok(())
    }
}

fn byte(bytes: &[u8], cursor: &mut usize) -> Result<u8, CapsuleError> {
    Ok(take(bytes, cursor, 1)?[0])
}

fn take<'a>(bytes: &'a [u8], cursor: &mut usize, count: usize) -> Result<&'a [u8], CapsuleError> {
    let end = cursor.checked_add(count).ok_or(CapsuleError::Limit)?;
    let value = bytes.get(*cursor..end).ok_or(CapsuleError::Invalid)?;
    *cursor = end;
    Ok(value)
}

fn array<const N: usize>(bytes: &[u8], cursor: &mut usize) -> Result<[u8; N], CapsuleError> {
    take(bytes, cursor, N)?
        .try_into()
        .map_err(|_| CapsuleError::Invalid)
}

#[cfg(test)]
mod tests;
