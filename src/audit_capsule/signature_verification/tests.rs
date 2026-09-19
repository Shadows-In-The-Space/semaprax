//! Reproduction and regression tests for the forged-signature gap
//! `signature_verification` closes: a structurally well-formed signature
//! naming an approved, unexpired, unrevoked identity must not be accepted
//! unless it is *actually* an Ed25519 signature over this exact capsule's
//! bytes, once the caller has opted in with a trust roster.
//!
//! `an_empty_trust_roster_preserves_the_legacy_policy_only_behavior` is the
//! reproduction case: it asserts today's (pre-fix, and still roster-off)
//! behavior accepts a garbage `signature` string outright, which is the
//! defect the issue named. Every other test here exercises the fix with the
//! roster populated.

use std::collections::BTreeMap;

use ed25519_dalek::{Signer as _, SigningKey};

use super::{signable_bytes, verify_against_roster};
use crate::audit_capsule::{
    nonclaims, render_capsule, sha256_digest, AssociationEdge, ObjectRef, Profile, SignatureEntry,
    SignaturePolicyContext, TransparencyEntry,
};

const OBJECT_A_BYTES: &[u8] = b"signature-verification fixture: program-root";
const OBJECT_B_BYTES: &[u8] = b"signature-verification fixture: semantic-transaction";
const OBJECT_C_BYTES: &[u8] = b"signature-verification fixture: assurance-manifest";
const OBJECT_D_BYTES: &[u8] = b"signature-verification fixture: source-projection";

/// A minimal, otherwise-well-formed `change` capsule carrying exactly
/// `signatures`, built through the public [`render_capsule`] API rather than
/// hand-written JSON so every fixture here stays valid if the wire format
/// ever changes shape.
fn minimal_signed_capsule(signatures: &[SignatureEntry]) -> Vec<u8> {
    let mut subject = BTreeMap::new();
    subject.insert("source_digest".to_owned(), "sha256:fixture".to_owned());
    subject.insert("root_digest".to_owned(), "sha256:fixture".to_owned());
    subject.insert("revision".to_owned(), "r1".to_owned());
    subject.insert("compiler_version".to_owned(), "0.0.0-fixture".to_owned());

    let objects = [
        ObjectRef {
            id: "obj-a-program-root".to_owned(),
            object_type: "program-root".to_owned(),
            schema: "semaprax.program-root.v3".to_owned(),
            digest: sha256_digest(OBJECT_A_BYTES),
            redacted: false,
            redaction_reason: None,
            binds: BTreeMap::new(),
        },
        ObjectRef {
            id: "obj-b-semantic-transaction".to_owned(),
            object_type: "semantic-transaction".to_owned(),
            schema: "semaprax.project-candidate-semantic-delta.v1".to_owned(),
            digest: sha256_digest(OBJECT_B_BYTES),
            redacted: false,
            redaction_reason: None,
            binds: BTreeMap::new(),
        },
        ObjectRef {
            id: "obj-c-assurance-manifest".to_owned(),
            object_type: "assurance-manifest".to_owned(),
            schema: "semaprax.assurance-manifest.v1".to_owned(),
            digest: sha256_digest(OBJECT_C_BYTES),
            redacted: false,
            redaction_reason: None,
            binds: BTreeMap::new(),
        },
        ObjectRef {
            id: "obj-d-source-projection".to_owned(),
            object_type: "source-projection".to_owned(),
            schema: "semaprax.program-root.v3".to_owned(),
            digest: sha256_digest(OBJECT_D_BYTES),
            redacted: false,
            redaction_reason: None,
            binds: BTreeMap::new(),
        },
    ];
    let associations: [AssociationEdge; 0] = [];
    let nonclaims: Vec<String> = nonclaims::ALWAYS_REQUIRED_NONCLAIMS
        .iter()
        .map(|entry| (*entry).to_owned())
        .collect();
    let transparency: Option<&TransparencyEntry> = None;

    render_capsule(
        Profile::Change,
        &subject,
        &objects,
        &associations,
        signatures,
        transparency,
        &nonclaims,
    )
    .expect("fixture capsule is well-formed")
}

fn signature(role: &str, identity: &str, algorithm: &str, signature: &str) -> SignatureEntry {
    SignatureEntry {
        role: role.to_owned(),
        identity: identity.to_owned(),
        algorithm: algorithm.to_owned(),
        signature: signature.to_owned(),
        not_valid_after_unix_seconds: 9_999_999_999,
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

// ---------------------------------------------------------------------
// Reproduction: with no trust roster configured, a garbage `signature`
// naming an otherwise-approved identity is accepted -- this is the exact
// defect issue #209 names. It stays true after the fix (by design: an
// empty roster is the strictly-backward-compatible opt-out), so this test
// also documents the boundary of what strict mode actually changes.
// ---------------------------------------------------------------------

#[test]
fn an_empty_trust_roster_preserves_the_legacy_policy_only_behavior() {
    let entries = [signature(
        "publisher",
        "agent://alice",
        "ed25519-raw-v1",
        "not-a-real-signature-just-forged-text",
    )];
    let manifest = minimal_signed_capsule(&entries);
    let capsule = crate::audit_capsule::parse_capsule(&manifest).expect("fixture parses");
    let ctx = SignaturePolicyContext::default();
    assert!(
        ctx.identity_public_keys.is_empty(),
        "the reproduction relies on the roster being empty by default"
    );
    verify_against_roster(&capsule, &ctx, &manifest)
        .expect("an empty roster must not reject a forged signature -- it never looks at one");
}

// ---------------------------------------------------------------------
// Strict mode: a real key pair, a real signature, and each of the four
// distinct failure conditions the issue's Definition of Done names.
// ---------------------------------------------------------------------

#[test]
fn a_genuine_signature_over_the_exact_capsule_bytes_verifies_against_the_roster() {
    let signing_key = SigningKey::from_bytes(&[7u8; 32]);
    let verifying_key = signing_key.verifying_key();

    // The signature is computed after the manifest exists, so it must be
    // over the manifest's *own* signable bytes -- chicken-and-egg, solved
    // the same way real capsule production would: render once with a
    // placeholder signature to learn the signable bytes, sign those bytes,
    // then render again with the real signature in place.
    let placeholder = [signature(
        "publisher",
        "agent://alice",
        "ed25519-raw-v1",
        &"0".repeat(128),
    )];
    let placeholder_manifest = minimal_signed_capsule(&placeholder);
    let bytes_to_sign =
        signable_bytes(&placeholder_manifest).expect("placeholder manifest is well-formed");
    let real_signature = signing_key.sign(&bytes_to_sign);

    let entries = [signature(
        "publisher",
        "agent://alice",
        "ed25519-raw-v1",
        &hex_encode(&real_signature.to_bytes()),
    )];
    let manifest = minimal_signed_capsule(&entries);
    let capsule = crate::audit_capsule::parse_capsule(&manifest).expect("fixture parses");

    let mut roster = BTreeMap::new();
    roster.insert("agent://alice".to_owned(), verifying_key.to_bytes());
    let ctx = SignaturePolicyContext {
        identity_public_keys: roster,
        ..SignaturePolicyContext::default()
    };
    verify_against_roster(&capsule, &ctx, &manifest)
        .expect("a genuine signature over this exact capsule's bytes must verify");
}

#[test]
fn a_forged_signature_naming_an_approved_identity_is_rejected_once_a_roster_is_active() {
    let signing_key = SigningKey::from_bytes(&[7u8; 32]);
    let verifying_key = signing_key.verifying_key();

    // Structurally perfect: correct length, correct hex, and an identity the
    // roster genuinely approves -- but never actually produced by the key.
    let forged = "ab".repeat(64);
    let entries = [signature(
        "publisher",
        "agent://alice",
        "ed25519-raw-v1",
        &forged,
    )];
    let manifest = minimal_signed_capsule(&entries);
    let capsule = crate::audit_capsule::parse_capsule(&manifest).expect("fixture parses");

    let mut roster = BTreeMap::new();
    roster.insert("agent://alice".to_owned(), verifying_key.to_bytes());
    let ctx = SignaturePolicyContext {
        identity_public_keys: roster,
        ..SignaturePolicyContext::default()
    };
    let error = verify_against_roster(&capsule, &ctx, &manifest).unwrap_err();
    assert_eq!(error.code, "SPX-Z905");
    assert!(
        error.message.contains("does not verify against"),
        "{}",
        error.message
    );
}

#[test]
fn a_signature_genuinely_valid_over_a_different_capsules_bytes_is_rejected() {
    let signing_key = SigningKey::from_bytes(&[7u8; 32]);
    let verifying_key = signing_key.verifying_key();

    // Sign a *different* manifest (a different revision) for real, then
    // paste that genuine signature into the capsule under test with the
    // same role and identity. The bytes are authentic Ed25519 output --
    // just not over this capsule.
    let placeholder = [signature(
        "publisher",
        "agent://alice",
        "ed25519-raw-v1",
        &"0".repeat(128),
    )];
    let other_manifest = minimal_signed_capsule(&placeholder);
    // Tamper the *other* manifest's revision so its signable bytes differ
    // from the capsule under test while staying well-formed JSON.
    let other_manifest_text = String::from_utf8(other_manifest)
        .unwrap()
        .replacen("\"r1\"", "\"r2\"", 1);
    let signed_elsewhere = signing_key.sign(
        &signable_bytes(other_manifest_text.as_bytes())
            .expect("tampered manifest stays well-formed JSON"),
    );

    let entries = [signature(
        "publisher",
        "agent://alice",
        "ed25519-raw-v1",
        &hex_encode(&signed_elsewhere.to_bytes()),
    )];
    let manifest = minimal_signed_capsule(&entries);
    let capsule = crate::audit_capsule::parse_capsule(&manifest).expect("fixture parses");

    let mut roster = BTreeMap::new();
    roster.insert("agent://alice".to_owned(), verifying_key.to_bytes());
    let ctx = SignaturePolicyContext {
        identity_public_keys: roster,
        ..SignaturePolicyContext::default()
    };
    let error = verify_against_roster(&capsule, &ctx, &manifest).unwrap_err();
    assert_eq!(error.code, "SPX-Z905");
    assert!(
        error.message.contains("does not verify against"),
        "{}",
        error.message
    );
}

#[test]
fn an_identity_absent_from_the_roster_is_rejected_as_unknown_not_forged() {
    let entries = [signature(
        "publisher",
        "agent://mallory",
        "ed25519-raw-v1",
        &"c".repeat(128),
    )];
    let manifest = minimal_signed_capsule(&entries);
    let capsule = crate::audit_capsule::parse_capsule(&manifest).expect("fixture parses");

    // The roster is non-empty (strict mode is on) but knows nobody named
    // "agent://mallory".
    let mut roster = BTreeMap::new();
    roster.insert("agent://alice".to_owned(), [1u8; 32]);
    let ctx = SignaturePolicyContext {
        identity_public_keys: roster,
        ..SignaturePolicyContext::default()
    };
    let error = verify_against_roster(&capsule, &ctx, &manifest).unwrap_err();
    assert_eq!(error.code, "SPX-Z905");
    assert!(
        error.message.contains("not in the trusted signer roster"),
        "{}",
        error.message
    );
}

#[test]
fn an_algorithm_with_no_local_verifier_is_rejected_as_unverifiable_under_strict_mode() {
    let entries = [signature(
        "publisher",
        "agent://alice",
        "sigstore-cosign-bundle-v0.3",
        "irrelevant-opaque-bundle-text",
    )];
    let manifest = minimal_signed_capsule(&entries);
    let capsule = crate::audit_capsule::parse_capsule(&manifest).expect("fixture parses");

    let mut roster = BTreeMap::new();
    roster.insert("agent://alice".to_owned(), [1u8; 32]);
    let ctx = SignaturePolicyContext {
        identity_public_keys: roster,
        ..SignaturePolicyContext::default()
    };
    let error = verify_against_roster(&capsule, &ctx, &manifest).unwrap_err();
    assert_eq!(error.code, "SPX-Z905");
    assert!(
        error.message.contains("cannot verify locally"),
        "{}",
        error.message
    );
}

#[test]
fn a_malformed_signature_encoding_is_rejected_as_unverifiable_under_strict_mode() {
    let entries = [signature(
        "publisher",
        "agent://alice",
        "ed25519-raw-v1",
        "not-hex-at-all",
    )];
    let manifest = minimal_signed_capsule(&entries);
    let capsule = crate::audit_capsule::parse_capsule(&manifest).expect("fixture parses");

    let mut roster = BTreeMap::new();
    roster.insert("agent://alice".to_owned(), [1u8; 32]);
    let ctx = SignaturePolicyContext {
        identity_public_keys: roster,
        ..SignaturePolicyContext::default()
    };
    let error = verify_against_roster(&capsule, &ctx, &manifest).unwrap_err();
    assert_eq!(error.code, "SPX-Z905");
    assert!(error.message.contains("unverifiable"), "{}", error.message);
}

// ---------------------------------------------------------------------
// `check_signature_policy` end to end: strict mode composes with the
// pre-existing role/expiry/revocation checks rather than replacing them.
// ---------------------------------------------------------------------

#[test]
fn check_signature_policy_still_enforces_a_missing_required_role_before_any_crypto_check() {
    let entries = [signature(
        "publisher",
        "agent://alice",
        "ed25519-raw-v1",
        &"0".repeat(128),
    )];
    let manifest = minimal_signed_capsule(&entries);
    let capsule = crate::audit_capsule::parse_capsule(&manifest).expect("fixture parses");

    let mut roster = BTreeMap::new();
    roster.insert("agent://alice".to_owned(), [1u8; 32]);
    let ctx = SignaturePolicyContext {
        identity_public_keys: roster,
        required_roles: vec!["approver".to_owned()],
        ..SignaturePolicyContext::default()
    };
    let error =
        crate::audit_capsule::check_signature_policy(&capsule, &manifest, &ctx).unwrap_err();
    assert_eq!(error.code, "SPX-Z905");
    assert!(
        error.message.contains("no signature carries"),
        "{}",
        error.message
    );
}
