//! Unit tests for the machine-readable `nonclaims` field (issue #209).
//!
//! The property under test throughout is **unstrippability**: a producer who
//! deletes an inconvenient nonclaim must end up with an invalid capsule, not
//! a valid-looking stronger one. Every fixture here therefore tampers only
//! the `nonclaims` array and asserts the exact `SPX-Z908` diagnostic the
//! tamper earns, leaving the rest of the manifest well-formed.

use std::collections::BTreeMap;

use super::*;
use crate::audit_capsule::{
    parse_capsule, sha256_digest, verify_capsule, SignaturePolicyContext, TransparencyContext,
};

const OBJECT_BYTES: &[u8] = b"nonclaims fixture object bytes";

/// A well-formed `change` capsule whose `nonclaims` array is exactly
/// `nonclaims_json`, with everything else held constant.
fn fixture(nonclaims_json: &str, redacted: bool) -> (String, BTreeMap<String, Vec<u8>>) {
    let digest = sha256_digest(OBJECT_BYTES);
    let redaction_reason = if redacted {
        "\"withheld for the fixture\""
    } else {
        "null"
    };
    let manifest = format!(
        r#"{{
  "schema": "semaprax.audit-capsule.v1",
  "profile": "change",
  "subject": {{
    "source_digest": "sha256:1111111111111111111111111111111111111111111111111111111111111111",
    "root_digest": "sha256:2222222222222222222222222222222222222222222222222222222222222222",
    "revision": "r1",
    "compiler_version": "{compiler}"
  }},
  "objects": [
    {{"id": "obj-a-assurance-manifest", "object_type": "assurance-manifest", "schema": "semaprax.assurance-manifest.v1", "digest": "{digest}", "redacted": false, "redaction_reason": null, "binds": {{}}}},
    {{"id": "obj-b-program-root", "object_type": "program-root", "schema": "semaprax.graph.v40", "digest": "{digest}", "redacted": {redacted}, "redaction_reason": {redaction_reason}, "binds": {{}}}},
    {{"id": "obj-c-semantic-transaction", "object_type": "semantic-transaction", "schema": "semaprax.project-candidate-semantic-delta.v1", "digest": "{digest}", "redacted": false, "redaction_reason": null, "binds": {{}}}},
    {{"id": "obj-d-source-projection", "object_type": "source-projection", "schema": "semaprax.canonical-source.v1", "digest": "{digest}", "redacted": false, "redaction_reason": null, "binds": {{}}}}
  ],
  "associations": [],
  "signatures": [],
  "transparency": null,
  "nonclaims": {nonclaims_json}
}}"#,
        compiler = env!("CARGO_PKG_VERSION"),
    );
    let mut object_bytes = BTreeMap::new();
    for id in [
        "obj-a-assurance-manifest",
        "obj-b-program-root",
        "obj-c-semantic-transaction",
        "obj-d-source-projection",
    ] {
        if redacted && id == "obj-b-program-root" {
            continue;
        }
        object_bytes.insert(id.to_owned(), OBJECT_BYTES.to_vec());
    }
    (manifest, object_bytes)
}

const BASE_JSON: &str = r#"["evidence-is-not-authorization", "local-evidence-only", "signatures-not-cryptographically-verified", "transparency-inclusion-not-independently-confirmed"]"#;

const REDACTED_JSON: &str = r#"["evidence-is-not-authorization", "local-evidence-only", "redacted-objects-withhold-facts", "signatures-not-cryptographically-verified", "transparency-inclusion-not-independently-confirmed"]"#;

fn empty_signature_ctx() -> SignaturePolicyContext {
    SignaturePolicyContext {
        verification_time_unix_seconds: 1_000,
        revoked_identities: Default::default(),
        required_roles: Vec::new(),
    }
}

fn empty_transparency_ctx() -> TransparencyContext {
    TransparencyContext {
        known_logs: Default::default(),
        minimum_accepted_checkpoint_size: 0,
    }
}

#[test]
fn a_capsule_declaring_every_required_nonclaim_verifies() {
    let (manifest, object_bytes) = fixture(BASE_JSON, false);
    let report = verify_capsule(
        manifest.as_bytes(),
        &object_bytes,
        &empty_signature_ctx(),
        &empty_transparency_ctx(),
    )
    .expect("an honest capsule verifies");
    assert_eq!(report.nonclaims.len(), 4);
}

#[test]
fn stripping_the_unsigned_nonclaim_makes_the_capsule_invalid_rather_than_stronger() {
    // The exact attack the field exists to stop: a producer deletes the
    // admission that nothing was cryptographically verified, hoping for a
    // green report that implies signatures were checked.
    let stripped = r#"["evidence-is-not-authorization", "local-evidence-only", "transparency-inclusion-not-independently-confirmed"]"#;
    let (manifest, object_bytes) = fixture(stripped, false);
    let error = verify_capsule(
        manifest.as_bytes(),
        &object_bytes,
        &empty_signature_ctx(),
        &empty_transparency_ctx(),
    )
    .unwrap_err();
    assert_eq!(error.code, "SPX-Z908");
    assert!(
        error
            .message
            .contains("signatures-not-cryptographically-verified"),
        "{}",
        error.message
    );
}

#[test]
fn stripping_the_evidence_is_not_authorization_nonclaim_is_rejected() {
    let stripped = r#"["local-evidence-only", "signatures-not-cryptographically-verified", "transparency-inclusion-not-independently-confirmed"]"#;
    let (manifest, object_bytes) = fixture(stripped, false);
    let error = verify_capsule(
        manifest.as_bytes(),
        &object_bytes,
        &empty_signature_ctx(),
        &empty_transparency_ctx(),
    )
    .unwrap_err();
    assert_eq!(error.code, "SPX-Z908");
    assert!(
        error.message.contains("evidence-is-not-authorization"),
        "{}",
        error.message
    );
}

#[test]
fn a_redacted_capsule_must_additionally_admit_that_redaction_withheld_facts() {
    // Issue #209's failure case: "redaction can remove facts required to
    // validate a claim while leaving a misleading green summary." Declaring
    // only the base nonclaims while redacting an object is exactly that
    // misleading summary, and it is refused.
    let (manifest, object_bytes) = fixture(BASE_JSON, true);
    let error = verify_capsule(
        manifest.as_bytes(),
        &object_bytes,
        &empty_signature_ctx(),
        &empty_transparency_ctx(),
    )
    .unwrap_err();
    assert_eq!(error.code, "SPX-Z908");
    assert!(
        error.message.contains("redacted-objects-withhold-facts"),
        "{}",
        error.message
    );

    let (honest, honest_bytes) = fixture(REDACTED_JSON, true);
    let report = verify_capsule(
        honest.as_bytes(),
        &honest_bytes,
        &empty_signature_ctx(),
        &empty_transparency_ctx(),
    )
    .expect("a redacted capsule that admits the redaction verifies");
    assert_eq!(report.unavailable_claims.len(), 1);
    assert!(report
        .nonclaims
        .iter()
        .any(|entry| entry == "redacted-objects-withhold-facts"));
}

#[test]
fn an_empty_nonclaims_list_is_rejected_at_parse_time() {
    let (manifest, _) = fixture("[]", false);
    let error = parse_capsule(manifest.as_bytes()).unwrap_err();
    assert_eq!(error.code, "SPX-Z908");
    assert!(error.message.contains("at least"), "{}", error.message);
}

#[test]
fn a_nonclaim_outside_the_closed_vocabulary_is_rejected() {
    let invented = r#"["evidence-is-not-authorization", "local-evidence-only", "signatures-are-fine-actually", "signatures-not-cryptographically-verified", "transparency-inclusion-not-independently-confirmed"]"#;
    let (manifest, _) = fixture(invented, false);
    let error = parse_capsule(manifest.as_bytes()).unwrap_err();
    assert_eq!(error.code, "SPX-Z908");
    assert!(
        error.message.contains("signatures-are-fine-actually"),
        "{}",
        error.message
    );
}

#[test]
fn unsorted_nonclaims_are_rejected_rather_than_silently_repaired() {
    // Canonical bytes are a repository invariant: two orderings of one set
    // must not both be admitted, or one capsule would have two digests.
    let unsorted = r#"["local-evidence-only", "evidence-is-not-authorization", "signatures-not-cryptographically-verified", "transparency-inclusion-not-independently-confirmed"]"#;
    let (manifest, _) = fixture(unsorted, false);
    let error = parse_capsule(manifest.as_bytes()).unwrap_err();
    assert_eq!(error.code, "SPX-Z908");
    assert!(
        error.message.contains("ascending canonical order"),
        "{}",
        error.message
    );
}

#[test]
fn a_duplicated_nonclaim_is_rejected() {
    let duplicated = r#"["evidence-is-not-authorization", "evidence-is-not-authorization", "local-evidence-only", "signatures-not-cryptographically-verified", "transparency-inclusion-not-independently-confirmed"]"#;
    let (manifest, _) = fixture(duplicated, false);
    let error = parse_capsule(manifest.as_bytes()).unwrap_err();
    assert_eq!(error.code, "SPX-Z908");
    assert!(
        error.message.contains("more than once"),
        "{}",
        error.message
    );
}

#[test]
fn a_capsule_may_declare_more_nonclaims_than_are_required_of_it() {
    // Being more modest than required is always admitted; only being less
    // modest is refused.
    let extra = r#"["evidence-is-not-authorization", "identities-not-replayed-against-source", "local-evidence-only", "profile-composition-unsupported", "signatures-not-cryptographically-verified", "transparency-inclusion-not-independently-confirmed"]"#;
    let (manifest, object_bytes) = fixture(extra, false);
    let report = verify_capsule(
        manifest.as_bytes(),
        &object_bytes,
        &empty_signature_ctx(),
        &empty_transparency_ctx(),
    )
    .expect("declaring extra nonclaims is admitted");
    assert_eq!(report.nonclaims.len(), 6);
}

#[test]
fn every_always_required_nonclaim_is_part_of_the_closed_vocabulary() {
    // Guards against a future edit adding a required nonclaim that no
    // capsule could ever legally declare, which would make every capsule
    // unverifiable rather than merely stricter.
    for required in ALWAYS_REQUIRED_NONCLAIMS {
        assert!(
            KNOWN_NONCLAIMS.contains(required),
            "`{required}` is required but not in the closed vocabulary"
        );
    }
}

#[test]
fn the_derived_requirement_set_is_a_function_of_capsule_facts_not_of_its_declarations() {
    // `derive_required_nonclaims` must reach the same answer whatever the
    // capsule declared -- that independence is what makes the declared list
    // unable to weaken the requirement.
    let (honest, _) = fixture(REDACTED_JSON, true);
    let (dishonest, _) = fixture(BASE_JSON, true);
    let honest_capsule = parse_capsule(honest.as_bytes()).expect("well-formed");
    let dishonest_capsule = parse_capsule(dishonest.as_bytes()).expect("well-formed");
    assert_eq!(
        derive_required_nonclaims(&honest_capsule),
        derive_required_nonclaims(&dishonest_capsule)
    );
    assert!(
        derive_required_nonclaims(&dishonest_capsule).contains("redacted-objects-withhold-facts")
    );
}

#[test]
fn canonical_nonclaims_deduplicates_and_sorts_a_producers_unordered_set() {
    let messy = vec![
        "local-evidence-only".to_owned(),
        "evidence-is-not-authorization".to_owned(),
        "local-evidence-only".to_owned(),
    ];
    assert_eq!(
        canonical_nonclaims(&messy),
        vec![
            "evidence-is-not-authorization".to_owned(),
            "local-evidence-only".to_owned(),
        ]
    );
}
