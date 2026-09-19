//! Optional, caller-opt-in Ed25519 signature verification for
//! `semaprax.audit-capsule.v1` (issue #209's forged-signature gap).
//!
//! [`super::check_signature_policy`] never cryptographically verified a
//! [`super::SignatureEntry`]: a well-formed but forged `signature` naming an
//! approved, unexpired, unrevoked identity passed silently -- the module doc
//! and `nonclaims::ALWAYS_REQUIRED_NONCLAIMS`'s
//! `"signatures-not-cryptographically-verified"` entry both said so
//! plainly, attributing the gap to "no signing key ... exists in this
//! repository" (issue #168). That reasoning only ever covers *producing* a
//! signature. A caller who already holds a trusted verifying key for a
//! signer -- the ordinary "I already know Alice's public key" case, which
//! needs no signing key at all -- had no way to make this module check it.
//!
//! This closes that gap for `ed25519-raw-v1`, the one
//! [`super::KNOWN_SIGNATURE_ALGORITHMS`] entry a pure verifier can check with
//! no network access and no external tool:
//! [`super::SignaturePolicyContext::identity_public_keys`] lets a caller
//! supply a roster of `identity -> Ed25519 verifying key`. An empty roster
//! (the default, and every caller before this capability existed) preserves
//! the original opaque, policy-only behavior exactly -- this is strictly
//! additive. A non-empty roster switches on strict mode: every signature in
//! the capsule is then required to (a) name an identity the roster
//! recognizes, (b) use an algorithm this module can verify locally, (c)
//! carry a structurally valid signature encoding, and (d) verify against the
//! capsule's own exact signable bytes -- four independently diagnosable
//! failures, so "unverifiable", "unknown identity", "wrong bytes", and
//! "missing" (still `check_signature_policy`'s own role-presence check)
//! never collapse into one message.
//!
//! `sigstore-cosign-bundle-v0.3` remains unverifiable here: checking a
//! Sigstore bundle needs Rekor, which needs network access this module must
//! never touch (see the crate module doc). A capsule using that algorithm
//! under strict mode fails closed as unverifiable, exactly like a
//! structurally malformed signature -- never silently accepted just because
//! its role, identity, expiry, and revocation status all looked fine.

use std::collections::BTreeMap;

use ed25519_dalek::{Signature, VerifyingKey};
use serde_json::Value;

use crate::diagnostic::Diagnostic;

use super::{
    parse_json, signature_error, sorted_json, ParsedCapsule, SignatureEntry, SignaturePolicyContext,
};

const ED25519_RAW_V1: &str = "ed25519-raw-v1";

/// The exact bytes an `ed25519-raw-v1` [`SignatureEntry::signature`] must be
/// an Ed25519 signature over: `manifest_bytes` with its `signatures` field
/// replaced by an empty array and object keys sorted, LF-terminated --
/// mirroring `super::transparency_leaf_digest_bytes`'s fixed-point avoidance
/// (a signature cannot honestly cover the very bytes that carry it). Every
/// other field -- `profile`, `subject`, `objects`, `associations`,
/// `transparency`, `nonclaims` -- is covered, so tampering any of them
/// changes what a valid signature must have been computed over.
pub(super) fn signable_bytes(manifest_bytes: &[u8]) -> Result<Vec<u8>, Diagnostic> {
    let mut value = parse_json(manifest_bytes, "audit capsule")?;
    let Some(map) = value.as_object_mut() else {
        return Err(signature_error(
            "audit capsule must be a JSON object to compute its signable bytes".to_owned(),
        ));
    };
    map.insert("signatures".to_owned(), Value::Array(Vec::new()));
    let mut text = serde_json::to_string(&sorted_json(&value)).map_err(|_| {
        signature_error("audit capsule cannot be canonically re-serialized".to_owned())
    })?;
    text.push('\n');
    Ok(text.into_bytes())
}

fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

/// Decodes exactly `2 * N` lowercase hexadecimal characters into `N` bytes.
/// Uppercase, short, long, or non-hex input is rejected rather than
/// tolerated -- the same "strict lower hex" discipline
/// `super::is_sha256_wire_form` already applies to digests.
fn decode_lower_hex<const N: usize>(text: &str) -> Option<[u8; N]> {
    if text.len() != N * 2 || !text.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return None;
    }
    let mut out = [0u8; N];
    let bytes = text.as_bytes();
    for (index, slot) in out.iter_mut().enumerate() {
        let high = hex_nibble(bytes[index * 2])?;
        let low = hex_nibble(bytes[index * 2 + 1])?;
        *slot = (high << 4) | low;
    }
    Some(out)
}

/// Cryptographically checks every signature in `capsule` against
/// `ctx.identity_public_keys` when that roster is non-empty; a no-op when it
/// is empty (see the module doc: empty is the strictly-backward-compatible
/// default). Called from [`super::check_signature_policy`] after its own
/// role/expiry/revocation checks.
pub(super) fn verify_against_roster(
    capsule: &ParsedCapsule,
    ctx: &SignaturePolicyContext,
    manifest_bytes: &[u8],
) -> Result<(), Diagnostic> {
    if ctx.identity_public_keys.is_empty() {
        return Ok(());
    }
    let signable = signable_bytes(manifest_bytes)?;
    for entry in &capsule.signatures {
        verify_one(entry, &ctx.identity_public_keys, &signable)?;
    }
    Ok(())
}

fn verify_one(
    entry: &SignatureEntry,
    roster: &BTreeMap<String, [u8; 32]>,
    signable: &[u8],
) -> Result<(), Diagnostic> {
    let Some(public_key_bytes) = roster.get(&entry.identity) else {
        return Err(signature_error(format!(
            "signature role `{}` identity `{}` is not in the trusted signer roster; an identity \
             absent from the roster cannot be cryptographically approved, so its signature -- \
             forged or not -- is rejected as unknown",
            entry.role, entry.identity
        )));
    };
    if entry.algorithm != ED25519_RAW_V1 {
        return Err(signature_error(format!(
            "signature role `{}` identity `{}` uses algorithm `{}`, which this module cannot \
             verify locally; only `{ED25519_RAW_V1}` has a local verifier, so this signature is \
             unverifiable rather than trusted",
            entry.role, entry.identity, entry.algorithm
        )));
    }
    let Some(signature_bytes) = decode_lower_hex::<64>(&entry.signature) else {
        return Err(signature_error(format!(
            "signature role `{}` identity `{}` is not 128 lowercase-hex characters encoding a \
             64-byte `{ED25519_RAW_V1}` signature; it is unverifiable",
            entry.role, entry.identity
        )));
    };
    let verifying_key = VerifyingKey::from_bytes(public_key_bytes).map_err(|_| {
        signature_error(format!(
            "signature role `{}` identity `{}`'s configured trust-roster public key is not a \
             valid Ed25519 verifying key; it is unverifiable",
            entry.role, entry.identity
        ))
    })?;
    verifying_key
        .verify_strict(signable, &Signature::from_bytes(&signature_bytes))
        .map_err(|_| {
            signature_error(format!(
                "signature role `{}` identity `{}` does not verify against this capsule's exact \
                 manifest bytes -- it was not produced over this capsule, whether forged from \
                 nothing or copied from a different one",
                entry.role, entry.identity
            ))
        })
}

#[cfg(test)]
mod tests;
