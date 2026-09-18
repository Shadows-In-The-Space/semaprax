//! Machine-readable `nonclaims`: the facts a `semaprax.audit-capsule.v1`
//! capsule explicitly does **not** establish, carried inside the manifest
//! itself rather than only in this repository's prose (issue #209).
//!
//! ## Why this is a manifest field and not documentation
//!
//! A capsule is meant to travel: its whole point is that someone who was not
//! present can verify it later, elsewhere, with no access to this repository.
//! A nonclaim recorded only in `docs/AUDIT-CAPSULE-V1.md` or in a Rust doc
//! comment does not travel with the bytes, so a downstream reader who never
//! reads this repository would see a fully green [`super::verify_capsule`]
//! report and reasonably -- and wrongly -- conclude the capsule's signatures
//! were cryptographically checked. Recording nonclaims as a required,
//! closed-vocabulary, canonically ordered manifest field makes that
//! misreading impossible: the disclaimer is part of the signed-over,
//! digested, transparency-committed bytes.
//!
//! ## Why a downstream reader cannot lose them
//!
//! Declaring nonclaims would be worthless if a producer could simply omit
//! the inconvenient ones. [`check_nonclaims`] therefore does not trust the
//! manifest's own list: it **re-derives** the set of nonclaims this exact
//! capsule is obliged to carry from the capsule's own structural facts (see
//! [`derive_required_nonclaims`]) and fails closed when the declared list
//! omits any of them. Stripping
//! `"signatures-not-cryptographically-verified"` from a capsule to make it
//! look stronger does not produce a weaker-but-valid capsule; it produces a
//! capsule that no longer verifies at all.
//!
//! A capsule may declare *more* nonclaims than are derived as mandatory --
//! being more modest than required is always admitted -- but never fewer,
//! and never one outside [`KNOWN_NONCLAIMS`].

use std::collections::BTreeSet;

use serde_json::Value;

use crate::diagnostic::Diagnostic;

use super::{require_array, require_string, ParsedCapsule};

/// The closed nonclaim vocabulary. A free-text disclaimer field would be
/// unusable by a downstream *tool* -- which is the whole point of making
/// nonclaims machine-readable -- so every admitted nonclaim is one of these
/// exact identifiers.
pub const KNOWN_NONCLAIMS: &[&str] = &[
    // No signature in this capsule was cryptographically verified. See the
    // module doc of [`super`]: no signing key, keyless-signing identity, or
    // signature-verification dependency exists in this repository at all,
    // so a forged `signature` naming an approved identity is not detected.
    "signatures-not-cryptographically-verified",
    // No transparency log was contacted. [`super::check_transparency`]
    // checks a caller-supplied entry's internal consistency only; nothing
    // proves a real, independently operated log ever accepted this capsule.
    "transparency-inclusion-not-independently-confirmed",
    // Verifying this capsule authorizes nothing. It is evidence that some
    // objects were bound together unmodified, never permission to publish,
    // execute, sign, or release whatever the capsule describes.
    "evidence-is-not-authorization",
    // Everything referenced here was produced on a private developer
    // machine. Nothing in this capsule is evidence of a hosted CI run, a
    // physical-device run, or a production deployment (`AGENTS.md` forbids
    // describing local or proof-only evidence as any of those).
    "local-evidence-only",
    // At least one object is redacted, so at least one fact a complete
    // capsule would carry is unavailable to this reader.
    "redacted-objects-withhold-facts",
    // This capsule's identities were taken from its producer's own
    // assertion rather than re-derived from source. A capsule carrying this
    // nonclaim has *not* passed
    // [`super::change_replay::verify_change_capsule_against_source`].
    "identities-not-replayed-against-source",
    // Composing several profiles into one capsule is not implemented; this
    // capsule covers exactly one subject.
    "profile-composition-unsupported",
];

/// The nonclaims **every** capsule must carry, whatever its profile or
/// contents. These are properties of this implementation rather than of any
/// particular capsule, which is precisely why a producer must not be able to
/// opt out of them.
pub const ALWAYS_REQUIRED_NONCLAIMS: &[&str] = &[
    "signatures-not-cryptographically-verified",
    "transparency-inclusion-not-independently-confirmed",
    "evidence-is-not-authorization",
    "local-evidence-only",
];

fn nonclaim_error(message: String) -> Diagnostic {
    Diagnostic::io("SPX-Z908", message)
}

/// Parses and canonicalizes the manifest's `nonclaims` array.
///
/// Requires a non-empty, strictly ascending, duplicate-free list drawn from
/// [`KNOWN_NONCLAIMS`]. Ascending order is required rather than repaired:
/// canonical capsule bytes are a repository invariant, and silently sorting
/// a caller's unsorted list here would let two different byte sequences
/// describe one capsule.
pub fn parse_nonclaims(value: &Value) -> Result<Vec<String>, Diagnostic> {
    let entries = require_array(value, "nonclaims")?;
    if entries.is_empty() {
        return Err(nonclaim_error(
            "a capsule must declare at least the always-required nonclaims; an empty `nonclaims` \
             list would let a reader believe this capsule establishes more than it does"
                .to_owned(),
        ));
    }
    let mut parsed: Vec<String> = Vec::with_capacity(entries.len());
    for entry in entries {
        let text = require_string(entry, "nonclaims entry")?;
        if !KNOWN_NONCLAIMS.contains(&text) {
            return Err(nonclaim_error(format!(
                "nonclaim `{text}` is not one of the admitted nonclaims; a free-text disclaimer \
                 cannot be acted on by a downstream tool"
            )));
        }
        parsed.push(text.to_owned());
    }
    for window in parsed.windows(2) {
        let [previous, current] = window else {
            unreachable!("windows(2) always yields exactly two elements")
        };
        if current == previous {
            return Err(nonclaim_error(format!(
                "nonclaim `{current}` is declared more than once"
            )));
        }
        if current < previous {
            return Err(nonclaim_error(format!(
                "nonclaims are not in ascending canonical order: `{current}` follows `{previous}`"
            )));
        }
    }
    Ok(parsed)
}

/// Re-derives the nonclaims this exact capsule is **obliged** to carry, from
/// the capsule's own structural facts rather than from anything it says
/// about itself.
///
/// [`ALWAYS_REQUIRED_NONCLAIMS`] always applies. In addition, a capsule with
/// any redacted object must admit that redaction withheld facts -- the
/// failure case issue #209 names as "redaction can remove facts required to
/// validate a claim while leaving a misleading green summary".
#[must_use]
pub fn derive_required_nonclaims(capsule: &ParsedCapsule) -> BTreeSet<String> {
    let mut required: BTreeSet<String> = ALWAYS_REQUIRED_NONCLAIMS
        .iter()
        .map(|entry| (*entry).to_owned())
        .collect();
    if capsule.objects.iter().any(|candidate| candidate.redacted) {
        required.insert("redacted-objects-withhold-facts".to_owned());
    }
    required
}

/// Fails closed when the capsule's declared `nonclaims` omit any nonclaim
/// [`derive_required_nonclaims`] independently establishes it must carry.
///
/// This is the check that makes a nonclaim unstrippable: the derivation
/// shares no data with the declared list, so removing a line from the
/// manifest to make a capsule look stronger makes it invalid instead.
pub fn check_nonclaims(capsule: &ParsedCapsule) -> Result<(), Diagnostic> {
    let declared: BTreeSet<&str> = capsule.nonclaims.iter().map(String::as_str).collect();
    for required in derive_required_nonclaims(capsule) {
        if !declared.contains(required.as_str()) {
            return Err(nonclaim_error(format!(
                "this capsule must declare the nonclaim `{required}`, which its manifest omits; \
                 a capsule may declare more nonclaims than are required of it, never fewer"
            )));
        }
    }
    Ok(())
}

/// The canonical rendering of a nonclaim list for [`super::render_capsule`]:
/// deduplicated and sorted ascending, so a producer handing in an unordered
/// set still yields the one canonical byte sequence for that set.
#[must_use]
pub fn canonical_nonclaims(entries: &[String]) -> Vec<String> {
    let unique: BTreeSet<String> = entries.iter().cloned().collect();
    unique.into_iter().collect()
}

#[cfg(test)]
mod tests;
