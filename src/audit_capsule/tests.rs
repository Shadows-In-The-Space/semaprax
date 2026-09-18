//! Unit tests for `semaprax.audit-capsule.v1` (issue #209).
//!
//! Every hostile fixture here tampers exactly one **input** (a byte in a
//! referenced object, a bound subject key, an association edge, an object
//! type, a signature role, a transparency field) and asserts the **specific**
//! [`Diagnostic::code`] and a distinguishing message substring the tamper is
//! named for, following the pattern issue #168's `release_provenance` tests
//! set: a single mutated fact must be rejected for the exact reason it
//! violates, with the surrounding document staying otherwise well-formed
//! JSON, never by disabling a check in source.

use std::collections::BTreeMap;

use super::*;

const OBJECT_A_BYTES: &[u8] = b"program-root canonical bytes for the fixture change";
const OBJECT_B_BYTES: &[u8] = b"semantic transaction canonical bytes for the fixture change";
const OBJECT_C_BYTES: &[u8] = b"assurance manifest canonical bytes for the fixture change";
const OBJECT_D_BYTES: &[u8] = b"source projection canonical bytes for the fixture change";

/// Builds a well-formed `change`-profile capsule manifest (as raw JSON
/// text) plus the object-bytes map it references, parameterized only by
/// the fields tests need to vary. Every object binds `source_digest` and
/// `revision` to the subject's own values, so an honest fixture always
/// passes [`check_subject_bindings`].
fn change_fixture(revision: &str) -> (String, BTreeMap<String, Vec<u8>>) {
    let digest_a = sha256_digest(OBJECT_A_BYTES);
    let digest_b = sha256_digest(OBJECT_B_BYTES);
    let digest_c = sha256_digest(OBJECT_C_BYTES);
    let digest_d = sha256_digest(OBJECT_D_BYTES);
    let manifest = format!(
        r#"{{
  "schema": "semaprax.audit-capsule.v1",
  "profile": "change",
  "subject": {{
    "source_digest": "sha256:1111111111111111111111111111111111111111111111111111111111111111",
    "root_digest": "sha256:2222222222222222222222222222222222222222222222222222222222222222",
    "revision": "{revision}"
  }},
  "objects": [
    {{"id": "obj-a-program-root", "object_type": "program-root", "schema": "semaprax.program-root.v3", "digest": "{digest_a}", "redacted": false, "redaction_reason": null, "binds": {{"revision": "{revision}"}}}},
    {{"id": "obj-b-semantic-transaction", "object_type": "semantic-transaction", "schema": "semaprax.project-candidate-semantic-delta.v1", "digest": "{digest_b}", "redacted": false, "redaction_reason": null, "binds": {{"revision": "{revision}"}}}},
    {{"id": "obj-c-assurance-manifest", "object_type": "assurance-manifest", "schema": "semaprax.assurance-manifest.v1", "digest": "{digest_c}", "redacted": false, "redaction_reason": null, "binds": {{}}}},
    {{"id": "obj-d-source-projection", "object_type": "source-projection", "schema": "semaprax.program-root.v3", "digest": "{digest_d}", "redacted": false, "redaction_reason": null, "binds": {{"source_digest": "sha256:1111111111111111111111111111111111111111111111111111111111111111"}}}}
  ],
  "associations": [
    {{"from_id": "obj-b-semantic-transaction", "relation": "derived_from", "to_id": "obj-a-program-root"}},
    {{"from_id": "obj-c-assurance-manifest", "relation": "attests", "to_id": "obj-b-semantic-transaction"}}
  ],
  "signatures": [],
  "transparency": null
}}"#
    );
    let mut object_bytes = BTreeMap::new();
    object_bytes.insert("obj-a-program-root".to_owned(), OBJECT_A_BYTES.to_vec());
    object_bytes.insert(
        "obj-b-semantic-transaction".to_owned(),
        OBJECT_B_BYTES.to_vec(),
    );
    object_bytes.insert(
        "obj-c-assurance-manifest".to_owned(),
        OBJECT_C_BYTES.to_vec(),
    );
    object_bytes.insert(
        "obj-d-source-projection".to_owned(),
        OBJECT_D_BYTES.to_vec(),
    );
    (manifest, object_bytes)
}

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

// ---------------------------------------------------------------------
// Canonical pack/unpack/verify and deterministic ordering.
// ---------------------------------------------------------------------

#[test]
fn a_well_formed_change_capsule_verifies_and_reports_every_object_verified() {
    let (manifest, object_bytes) = change_fixture("r1");
    let report = verify_capsule(
        manifest.as_bytes(),
        &object_bytes,
        &empty_signature_ctx(),
        &empty_transparency_ctx(),
    )
    .expect("well-formed fixture must verify");
    assert_eq!(report.profile, Profile::Change);
    assert_eq!(report.verified_object_ids.len(), 4);
    assert!(report.unavailable_claims.is_empty());
}

#[test]
fn two_capsules_built_from_identical_bytes_produce_the_identical_digest() {
    let (manifest_one, _) = change_fixture("r1");
    let (manifest_two, _) = change_fixture("r1");
    assert_eq!(
        capsule_digest(manifest_one.as_bytes()),
        capsule_digest(manifest_two.as_bytes())
    );
}

#[test]
fn a_single_byte_change_to_the_manifest_changes_the_capsule_digest() {
    let (manifest, _) = change_fixture("r1");
    let mut tampered = manifest.clone().into_bytes();
    let position = tampered
        .iter()
        .position(|&byte| byte == b'r')
        .expect("fixture contains the letter r");
    tampered[position] = b'x';
    assert_ne!(
        capsule_digest(manifest.as_bytes()),
        capsule_digest(&tampered)
    );
}

#[test]
fn objects_out_of_ascending_canonical_order_are_rejected() {
    let (manifest, _) = change_fixture("r1");
    // Swap the first two object entries so the array is well-formed JSON
    // but no longer sorted by id.
    let swapped = manifest.replacen(
        r#""id": "obj-a-program-root""#,
        r#""id": "obj-z-program-root""#,
        1,
    );
    let error = parse_capsule(swapped.as_bytes()).unwrap_err();
    assert_eq!(error.code, "SPX-Z901");
    assert!(
        error.message.contains("ascending canonical order"),
        "{}",
        error.message
    );
}

#[test]
fn a_duplicate_object_id_is_rejected() {
    let (manifest, _) = change_fixture("r1");
    let duplicated = manifest.replacen(
        r#""id": "obj-b-semantic-transaction""#,
        r#""id": "obj-a-program-root""#,
        1,
    );
    let error = parse_capsule(duplicated.as_bytes()).unwrap_err();
    assert_eq!(error.code, "SPX-Z901");
    assert!(
        error.message.contains("duplicate object id"),
        "{}",
        error.message
    );
}

// ---------------------------------------------------------------------
// Missing, extra, duplicate, cyclic, wrong-type, stale, and substituted
// object references (issue #209's named failure list).
// ---------------------------------------------------------------------

#[test]
fn a_missing_required_object_type_is_rejected() {
    let (manifest, mut object_bytes) = change_fixture("r1");
    object_bytes.remove("obj-c-assurance-manifest");
    // Remove exactly the obj-c entry (indentation, braces, and trailing
    // comma included) rather than the object entries around it, so the
    // remaining array stays exactly as well-formed as the fixture's other
    // three entries.
    let obj_c_entry = format!(
        "    {{\"id\": \"obj-c-assurance-manifest\", \"object_type\": \"assurance-manifest\", \
         \"schema\": \"semaprax.assurance-manifest.v1\", \"digest\": \"{}\", \"redacted\": \
         false, \"redaction_reason\": null, \"binds\": {{}}}},\n",
        sha256_digest(OBJECT_C_BYTES)
    );
    assert!(
        manifest.contains(&obj_c_entry),
        "fixture format drifted from this test's expected obj-c entry text"
    );
    let without_assurance_manifest = manifest.replacen(&obj_c_entry, "", 1);
    let capsule = parse_capsule(without_assurance_manifest.as_bytes())
        .expect("manifest stays otherwise well-formed");
    let error = check_required_object_types(&capsule).unwrap_err();
    assert_eq!(error.code, "SPX-Z902");
    assert!(error.message.contains("none is"), "{}", error.message);
}

#[test]
fn an_extra_copy_of_a_required_object_type_is_rejected() {
    let (manifest, _object_bytes) = change_fixture("r1");
    // Append a *fifth*, additional `program-root` object (a new id, not a
    // conversion of an existing required object) so every originally
    // required type stays present and only `program-root` becomes
    // ambiguous -- this is what keeps this "extra" case distinct from the
    // "missing" case above.
    let extra_entry = format!(
        ",\n    {{\"id\": \"obj-e-program-root-duplicate\", \"object_type\": \"program-root\", \
         \"schema\": \"semaprax.program-root.v3\", \"digest\": \"{}\", \"redacted\": false, \
         \"redaction_reason\": null, \"binds\": {{}}}}",
        sha256_digest(b"duplicate program-root bytes for the extra-object test")
    );
    let marker = "\n  ],\n  \"associations\"";
    assert!(
        manifest.contains(marker),
        "fixture format drifted from this test's expected objects/associations boundary"
    );
    let duplicated_type = manifest.replacen(marker, &format!("{extra_entry}{marker}"), 1);
    let capsule =
        parse_capsule(duplicated_type.as_bytes()).expect("manifest stays otherwise well-formed");
    let error = check_required_object_types(&capsule).unwrap_err();
    assert_eq!(error.code, "SPX-Z902");
    assert!(error.message.contains("exactly one"), "{}", error.message);
    assert!(error.message.contains("program-root"), "{}", error.message);
}

#[test]
fn a_cyclic_association_graph_is_rejected() {
    let (manifest, _) = change_fixture("r1");
    let cyclic = manifest.replacen(
        r#""associations": [
    {"from_id": "obj-b-semantic-transaction", "relation": "derived_from", "to_id": "obj-a-program-root"},
    {"from_id": "obj-c-assurance-manifest", "relation": "attests", "to_id": "obj-b-semantic-transaction"}
  ]"#,
        r#""associations": [
    {"from_id": "obj-b-semantic-transaction", "relation": "derived_from", "to_id": "obj-a-program-root"},
    {"from_id": "obj-a-program-root", "relation": "supersedes", "to_id": "obj-b-semantic-transaction"}
  ]"#,
        1,
    );
    let capsule = parse_capsule(cyclic.as_bytes()).expect("manifest stays otherwise well-formed");
    let error = check_associations(&capsule).unwrap_err();
    assert_eq!(error.code, "SPX-Z903");
    assert!(error.message.contains("cyclic"), "{}", error.message);
}

#[test]
fn an_association_naming_an_unknown_object_id_is_rejected_as_dangling() {
    let (manifest, _) = change_fixture("r1");
    let dangling = manifest.replacen("obj-a-program-root\"}", "obj-does-not-exist\"}", 1);
    let capsule = parse_capsule(dangling.as_bytes()).expect("manifest stays otherwise well-formed");
    let error = check_associations(&capsule).unwrap_err();
    assert_eq!(error.code, "SPX-Z903");
    assert!(
        error.message.contains("unknown object id"),
        "{}",
        error.message
    );
}

#[test]
fn an_object_type_outside_the_closed_vocabulary_is_rejected() {
    let (manifest, _) = change_fixture("r1");
    let wrong_type = manifest.replacen(
        r#""object_type": "program-root""#,
        r#""object_type": "audit-capsule""#,
        1,
    );
    let error = parse_capsule(wrong_type.as_bytes()).unwrap_err();
    assert_eq!(error.code, "SPX-Z902");
    assert!(
        error.message.contains("closed object-type vocabulary"),
        "{}",
        error.message
    );
}

#[test]
fn an_object_bound_to_a_stale_revision_is_rejected() {
    let (manifest, _) = change_fixture("r1");
    // Only the bound claim is changed; the subject's own revision (`r1`)
    // stays untouched, so this models an object honestly minted for an
    // earlier revision and left unrefreshed in a newer capsule.
    let stale = manifest.replacen(r#""revision": "r1"}}"#, r#""revision": "r0"}}"#, 1);
    let capsule = parse_capsule(stale.as_bytes()).expect("manifest stays otherwise well-formed");
    let error = check_subject_bindings(&capsule).unwrap_err();
    assert_eq!(error.code, "SPX-Z904");
    assert!(error.message.contains("stale"), "{}", error.message);
}

#[test]
fn a_substituted_object_whose_bytes_do_not_match_its_digest_is_rejected() {
    let (manifest, mut object_bytes) = change_fixture("r1");
    object_bytes.insert(
        "obj-a-program-root".to_owned(),
        b"these are not the bytes this digest commits to".to_vec(),
    );
    let capsule = parse_capsule(manifest.as_bytes()).expect("well-formed fixture parses");
    let error = check_object_bytes(&capsule, &object_bytes).unwrap_err();
    assert_eq!(error.code, "SPX-Z904");
    assert!(error.message.contains("substituted"), "{}", error.message);
}

#[test]
fn a_missing_retained_object_body_is_rejected_distinctly_from_substitution() {
    let (manifest, mut object_bytes) = change_fixture("r1");
    object_bytes.remove("obj-a-program-root");
    let capsule = parse_capsule(manifest.as_bytes()).expect("well-formed fixture parses");
    let error = check_object_bytes(&capsule, &object_bytes).unwrap_err();
    assert_eq!(error.code, "SPX-Z904");
    assert!(
        error.message.contains("no retained bytes were supplied"),
        "{}",
        error.message
    );
}

#[test]
fn supplying_retained_bytes_for_a_redacted_object_is_rejected_as_a_leak() {
    let digest_a = sha256_digest(OBJECT_A_BYTES);
    let digest_b = sha256_digest(OBJECT_B_BYTES);
    let digest_c = sha256_digest(OBJECT_C_BYTES);
    let digest_d = sha256_digest(OBJECT_D_BYTES);
    let manifest = format!(
        r#"{{
  "schema": "semaprax.audit-capsule.v1",
  "profile": "change",
  "subject": {{
    "source_digest": "sha256:1111111111111111111111111111111111111111111111111111111111111111",
    "root_digest": "sha256:2222222222222222222222222222222222222222222222222222222222222222",
    "revision": "r1"
  }},
  "objects": [
    {{"id": "obj-a-program-root", "object_type": "program-root", "schema": "semaprax.program-root.v3", "digest": "{digest_a}", "redacted": true, "redaction_reason": "withheld for the fixture", "binds": {{"revision": "r1"}}}},
    {{"id": "obj-b-semantic-transaction", "object_type": "semantic-transaction", "schema": "semaprax.project-candidate-semantic-delta.v1", "digest": "{digest_b}", "redacted": false, "redaction_reason": null, "binds": {{"revision": "r1"}}}},
    {{"id": "obj-c-assurance-manifest", "object_type": "assurance-manifest", "schema": "semaprax.assurance-manifest.v1", "digest": "{digest_c}", "redacted": false, "redaction_reason": null, "binds": {{}}}},
    {{"id": "obj-d-source-projection", "object_type": "source-projection", "schema": "semaprax.program-root.v3", "digest": "{digest_d}", "redacted": false, "redaction_reason": null, "binds": {{"source_digest": "sha256:1111111111111111111111111111111111111111111111111111111111111111"}}}}
  ],
  "associations": [],
  "signatures": [],
  "transparency": null
}}"#
    );
    let capsule = parse_capsule(manifest.as_bytes()).expect("manifest is well-formed");
    let mut object_bytes = BTreeMap::new();
    object_bytes.insert("obj-a-program-root".to_owned(), OBJECT_A_BYTES.to_vec());
    object_bytes.insert(
        "obj-b-semantic-transaction".to_owned(),
        OBJECT_B_BYTES.to_vec(),
    );
    object_bytes.insert(
        "obj-c-assurance-manifest".to_owned(),
        OBJECT_C_BYTES.to_vec(),
    );
    object_bytes.insert(
        "obj-d-source-projection".to_owned(),
        OBJECT_D_BYTES.to_vec(),
    );
    let error = check_object_bytes(&capsule, &object_bytes).unwrap_err();
    assert_eq!(error.code, "SPX-Z904");
    assert!(
        error.message.contains("retained bytes were supplied"),
        "{}",
        error.message
    );
}

// ---------------------------------------------------------------------
// Redaction shows unavailable claims and verifies retained commitments.
// ---------------------------------------------------------------------

#[test]
fn a_redacted_object_verifies_without_its_bytes_and_is_reported_as_unavailable() {
    let digest_a = sha256_digest(OBJECT_A_BYTES);
    let digest_b = sha256_digest(OBJECT_B_BYTES);
    let digest_c = sha256_digest(OBJECT_C_BYTES);
    let digest_d = sha256_digest(OBJECT_D_BYTES);
    let manifest = format!(
        r#"{{
  "schema": "semaprax.audit-capsule.v1",
  "profile": "change",
  "subject": {{
    "source_digest": "sha256:1111111111111111111111111111111111111111111111111111111111111111",
    "root_digest": "sha256:2222222222222222222222222222222222222222222222222222222222222222",
    "revision": "r1"
  }},
  "objects": [
    {{"id": "obj-a-program-root", "object_type": "program-root", "schema": "semaprax.program-root.v3", "digest": "{digest_a}", "redacted": true, "redaction_reason": "contains private paths", "binds": {{"revision": "r1"}}}},
    {{"id": "obj-b-semantic-transaction", "object_type": "semantic-transaction", "schema": "semaprax.project-candidate-semantic-delta.v1", "digest": "{digest_b}", "redacted": false, "redaction_reason": null, "binds": {{"revision": "r1"}}}},
    {{"id": "obj-c-assurance-manifest", "object_type": "assurance-manifest", "schema": "semaprax.assurance-manifest.v1", "digest": "{digest_c}", "redacted": false, "redaction_reason": null, "binds": {{}}}},
    {{"id": "obj-d-source-projection", "object_type": "source-projection", "schema": "semaprax.program-root.v3", "digest": "{digest_d}", "redacted": false, "redaction_reason": null, "binds": {{"source_digest": "sha256:1111111111111111111111111111111111111111111111111111111111111111"}}}}
  ],
  "associations": [],
  "signatures": [],
  "transparency": null
}}"#
    );
    let mut object_bytes = BTreeMap::new();
    object_bytes.insert(
        "obj-b-semantic-transaction".to_owned(),
        OBJECT_B_BYTES.to_vec(),
    );
    object_bytes.insert(
        "obj-c-assurance-manifest".to_owned(),
        OBJECT_C_BYTES.to_vec(),
    );
    object_bytes.insert(
        "obj-d-source-projection".to_owned(),
        OBJECT_D_BYTES.to_vec(),
    );
    let report = verify_capsule(
        manifest.as_bytes(),
        &object_bytes,
        &empty_signature_ctx(),
        &empty_transparency_ctx(),
    )
    .expect("a redacted object with no supplied bytes must still verify");
    assert_eq!(report.verified_object_ids.len(), 3);
    assert_eq!(report.unavailable_claims.len(), 1);
    let (id, object_type, reason) = &report.unavailable_claims[0];
    assert_eq!(id, "obj-a-program-root");
    assert_eq!(object_type, "program-root");
    assert_eq!(reason, "contains private paths");
}

#[test]
fn a_redacted_object_missing_its_reason_is_rejected_at_parse_time() {
    let (manifest, _) = change_fixture("r1");
    let malformed = manifest.replacen(
        r#""redacted": false, "redaction_reason": null, "binds": {"revision": "r1"}}"#,
        r#""redacted": true, "redaction_reason": null, "binds": {"revision": "r1"}}"#,
        1,
    );
    let error = parse_capsule(malformed.as_bytes()).unwrap_err();
    assert_eq!(error.code, "SPX-Z901");
    assert!(
        error.message.contains("no redaction_reason"),
        "{}",
        error.message
    );
}

// ---------------------------------------------------------------------
// Signature identity/role/expiry/revocation and multi-signature policy.
// ---------------------------------------------------------------------

fn signed_manifest(signatures_json: &str) -> String {
    let (manifest, _) = change_fixture("r1");
    manifest.replacen(
        "\"signatures\": []",
        &format!("\"signatures\": {signatures_json}"),
        1,
    )
}

#[test]
fn distinct_roles_may_each_sign_once_and_are_looked_up_by_their_own_role() {
    let manifest = signed_manifest(
        r#"[
      {"role": "proposer", "identity": "agent://alice", "algorithm": "ed25519-raw-v1", "signature": "fixture-sig-1", "not_valid_after_unix_seconds": 5000},
      {"role": "approver", "identity": "agent://bob", "algorithm": "ed25519-raw-v1", "signature": "fixture-sig-2", "not_valid_after_unix_seconds": 5000}
    ]"#,
    );
    let capsule = parse_capsule(manifest.as_bytes()).expect("manifest is well-formed");
    assert_eq!(capsule.signatures.len(), 2);
    // A caller looking up "publisher" must get nothing back, never the
    // approver's entry -- this is what keeps roles from being confused.
    assert!(!capsule
        .signatures
        .iter()
        .any(|signature| signature.role == "publisher"));
    let ctx = SignaturePolicyContext {
        verification_time_unix_seconds: 1_000,
        revoked_identities: Default::default(),
        required_roles: vec!["proposer".to_owned(), "approver".to_owned()],
    };
    check_signature_policy(&capsule, &ctx).expect("both required roles are present and unexpired");
}

#[test]
fn two_signatures_claiming_the_same_role_are_rejected_at_parse_time() {
    let manifest = signed_manifest(
        r#"[
      {"role": "approver", "identity": "agent://alice", "algorithm": "ed25519-raw-v1", "signature": "fixture-sig-1", "not_valid_after_unix_seconds": 5000},
      {"role": "approver", "identity": "agent://bob", "algorithm": "ed25519-raw-v1", "signature": "fixture-sig-2", "not_valid_after_unix_seconds": 5000}
    ]"#,
    );
    let error = parse_capsule(manifest.as_bytes()).unwrap_err();
    assert_eq!(error.code, "SPX-Z901");
    assert!(
        error.message.contains("more than one signature"),
        "{}",
        error.message
    );
}

#[test]
fn a_missing_required_signature_role_is_rejected() {
    let manifest = signed_manifest(
        r#"[{"role": "proposer", "identity": "agent://alice", "algorithm": "ed25519-raw-v1", "signature": "fixture-sig-1", "not_valid_after_unix_seconds": 5000}]"#,
    );
    let capsule = parse_capsule(manifest.as_bytes()).expect("manifest is well-formed");
    let ctx = SignaturePolicyContext {
        verification_time_unix_seconds: 1_000,
        revoked_identities: Default::default(),
        required_roles: vec!["publisher".to_owned()],
    };
    let error = check_signature_policy(&capsule, &ctx).unwrap_err();
    assert_eq!(error.code, "SPX-Z905");
    assert!(
        error.message.contains("no signature carries"),
        "{}",
        error.message
    );
}

#[test]
fn an_expired_signature_is_rejected() {
    let manifest = signed_manifest(
        r#"[{"role": "publisher", "identity": "agent://alice", "algorithm": "ed25519-raw-v1", "signature": "fixture-sig-1", "not_valid_after_unix_seconds": 500}]"#,
    );
    let capsule = parse_capsule(manifest.as_bytes()).expect("manifest is well-formed");
    let ctx = SignaturePolicyContext {
        verification_time_unix_seconds: 1_000,
        revoked_identities: Default::default(),
        required_roles: Vec::new(),
    };
    let error = check_signature_policy(&capsule, &ctx).unwrap_err();
    assert_eq!(error.code, "SPX-Z905");
    assert!(error.message.contains("expired"), "{}", error.message);
}

#[test]
fn a_revoked_identity_signature_is_rejected() {
    let manifest = signed_manifest(
        r#"[{"role": "publisher", "identity": "agent://alice", "algorithm": "ed25519-raw-v1", "signature": "fixture-sig-1", "not_valid_after_unix_seconds": 5000}]"#,
    );
    let capsule = parse_capsule(manifest.as_bytes()).expect("manifest is well-formed");
    let mut revoked = std::collections::BTreeSet::new();
    revoked.insert("agent://alice".to_owned());
    let ctx = SignaturePolicyContext {
        verification_time_unix_seconds: 1_000,
        revoked_identities: revoked,
        required_roles: Vec::new(),
    };
    let error = check_signature_policy(&capsule, &ctx).unwrap_err();
    assert_eq!(error.code, "SPX-Z905");
    assert!(error.message.contains("revoked"), "{}", error.message);
}

#[test]
fn an_unrecognized_signature_role_is_rejected_at_parse_time() {
    let manifest = signed_manifest(
        r#"[{"role": "notary", "identity": "agent://alice", "algorithm": "ed25519-raw-v1", "signature": "fixture-sig-1", "not_valid_after_unix_seconds": 5000}]"#,
    );
    let error = parse_capsule(manifest.as_bytes()).unwrap_err();
    assert_eq!(error.code, "SPX-Z902");
    assert!(
        error.message.contains("closed role vocabulary"),
        "{}",
        error.message
    );
}

// ---------------------------------------------------------------------
// Transparency inclusion valid/invalid/stale log cases.
// ---------------------------------------------------------------------

fn manifest_with_transparency(transparency_json: &str) -> String {
    let (manifest, _) = change_fixture("r1");
    manifest.replacen("\"transparency\": null", transparency_json, 1)
}

#[test]
fn a_valid_transparency_entry_passes() {
    let (manifest, _object_bytes) = change_fixture("r1");
    // `transparency_leaf_digest` nulls the `transparency` field before
    // hashing, so it can be computed once, up front, against the manifest
    // that still carries `"transparency": null` -- no fixed point to solve,
    // unlike hashing the manifest bytes verbatim would require.
    let leaf_digest =
        transparency_leaf_digest(manifest.as_bytes()).expect("manifest is well-formed JSON");
    let final_manifest = manifest.replacen(
        "\"transparency\": null",
        &format!(
            r#""transparency": {{"log_id": "known-log", "leaf_digest": "{leaf_digest}", "inclusion_proof": ["step-1"], "observed_checkpoint_size": 100}}"#
        ),
        1,
    );
    let capsule = parse_capsule(final_manifest.as_bytes()).expect("manifest is well-formed");
    let mut known_logs = std::collections::BTreeSet::new();
    known_logs.insert("known-log".to_owned());
    let ctx = TransparencyContext {
        known_logs,
        minimum_accepted_checkpoint_size: 10,
    };
    check_transparency(&capsule, final_manifest.as_bytes(), &ctx)
        .expect("leaf digest matches, log is known, checkpoint is fresh");
}

#[test]
fn a_transparency_leaf_digest_that_does_not_match_the_manifest_is_invalid() {
    let manifest = manifest_with_transparency(
        r#""transparency": {"log_id": "known-log", "leaf_digest": "sha256:3333333333333333333333333333333333333333333333333333333333333333", "inclusion_proof": ["step-1"], "observed_checkpoint_size": 100}"#,
    );
    let capsule = parse_capsule(manifest.as_bytes()).expect("manifest is well-formed");
    let mut known_logs = std::collections::BTreeSet::new();
    known_logs.insert("known-log".to_owned());
    let ctx = TransparencyContext {
        known_logs,
        minimum_accepted_checkpoint_size: 0,
    };
    let error = check_transparency(&capsule, manifest.as_bytes(), &ctx).unwrap_err();
    assert_eq!(error.code, "SPX-Z906");
    assert!(error.message.contains("invalid"), "{}", error.message);
}

#[test]
fn a_transparency_entry_from_an_unknown_log_is_invalid() {
    let (manifest, _object_bytes) = change_fixture("r1");
    let leaf_digest =
        transparency_leaf_digest(manifest.as_bytes()).expect("manifest is well-formed JSON");
    let final_manifest = manifest.replacen(
        "\"transparency\": null",
        &format!(
            r#""transparency": {{"log_id": "untrusted-log", "leaf_digest": "{leaf_digest}", "inclusion_proof": ["step-1"], "observed_checkpoint_size": 100}}"#
        ),
        1,
    );
    let capsule = parse_capsule(final_manifest.as_bytes()).expect("manifest is well-formed");
    let ctx = TransparencyContext {
        known_logs: Default::default(),
        minimum_accepted_checkpoint_size: 0,
    };
    let error = check_transparency(&capsule, final_manifest.as_bytes(), &ctx).unwrap_err();
    assert_eq!(error.code, "SPX-Z906");
    assert!(error.message.contains("trusted logs"), "{}", error.message);
}

#[test]
fn a_transparency_entry_observed_before_the_trusted_checkpoint_is_stale() {
    let (manifest, _object_bytes) = change_fixture("r1");
    let leaf_digest =
        transparency_leaf_digest(manifest.as_bytes()).expect("manifest is well-formed JSON");
    let final_manifest = manifest.replacen(
        "\"transparency\": null",
        &format!(
            r#""transparency": {{"log_id": "known-log", "leaf_digest": "{leaf_digest}", "inclusion_proof": ["step-1"], "observed_checkpoint_size": 5}}"#
        ),
        1,
    );
    let capsule = parse_capsule(final_manifest.as_bytes()).expect("manifest is well-formed");
    let mut known_logs = std::collections::BTreeSet::new();
    known_logs.insert("known-log".to_owned());
    let ctx = TransparencyContext {
        known_logs,
        minimum_accepted_checkpoint_size: 100,
    };
    let error = check_transparency(&capsule, final_manifest.as_bytes(), &ctx).unwrap_err();
    assert_eq!(error.code, "SPX-Z906");
    assert!(error.message.contains("stale"), "{}", error.message);
}

#[test]
fn tampering_any_field_other_than_transparency_still_changes_the_leaf_digest() {
    let (manifest, _object_bytes) = change_fixture("r1");
    let original = transparency_leaf_digest(manifest.as_bytes()).expect("well-formed JSON");
    let tampered_revision = manifest.replacen("\"revision\": \"r1\"", "\"revision\": \"r9\"", 1);
    let tampered =
        transparency_leaf_digest(tampered_revision.as_bytes()).expect("well-formed JSON");
    assert_ne!(
        original, tampered,
        "the leaf digest must still cover subject/objects/associations/signatures"
    );
}

// ---------------------------------------------------------------------
// Verification performs no artifact/model/tool/source write or
// publication -- and is fully portable (no compiler, no network, no
// filesystem needed to verify, only in-memory bytes).
// ---------------------------------------------------------------------

#[test]
fn verification_operates_purely_on_in_memory_bytes_with_no_filesystem_or_network_access() {
    // Every input here is a byte slice, a string map, or a plain integer --
    // never a `Path`, a socket, or a spawned process. A capsule assembled
    // by any producer can be checked by copying exactly this test's
    // shape: read `manifest_bytes` and `object_bytes` from wherever they
    // live (a variable, a network response already fully received, a
    // single in-memory buffer) and call `verify_capsule` -- nothing here
    // reaches back out to re-fetch, recompile, or re-run anything.
    let (manifest, object_bytes) = change_fixture("r1");
    let report = verify_capsule(
        manifest.as_bytes(),
        &object_bytes,
        &empty_signature_ctx(),
        &empty_transparency_ctx(),
    )
    .expect("portable verification succeeds from bytes alone");
    assert_eq!(report.verified_object_ids.len(), 4);
}

// ---------------------------------------------------------------------
// Change, Agent-run, and release profile fixtures.
// ---------------------------------------------------------------------

#[test]
fn an_agent_run_profile_capsule_with_the_wrong_required_types_is_rejected() {
    // Reuses the `change` fixture's objects under the `agent-run` profile,
    // which requires an entirely different object-type set -- every
    // required type is therefore missing.
    let (manifest, _) = change_fixture("r1");
    let agent_run_manifest = manifest
        .replacen("\"profile\": \"change\"", "\"profile\": \"agent-run\"", 1)
        .replacen(
            "\"source_digest\": \"sha256:1111111111111111111111111111111111111111111111111111111111111111\",\n    \"root_digest\": \"sha256:2222222222222222222222222222222222222222222222222222222222222222\",\n    \"revision\": \"r1\"",
            "\"session_id\": \"session-1\",\n    \"deployment_digest\": \"sha256:1111111111111111111111111111111111111111111111111111111111111111\",\n    \"target_digest\": \"sha256:2222222222222222222222222222222222222222222222222222222222222222\"",
            1,
        )
        .replacen("\"binds\": {\"revision\": \"r1\"}", "\"binds\": {}", 3)
        .replacen(
            "\"binds\": {\"source_digest\": \"sha256:1111111111111111111111111111111111111111111111111111111111111111\"}",
            "\"binds\": {}",
            1,
        );
    let capsule =
        parse_capsule(agent_run_manifest.as_bytes()).expect("manifest is well-formed JSON");
    assert_eq!(capsule.profile, Profile::AgentRun);
    let error = check_required_object_types(&capsule).unwrap_err();
    assert_eq!(error.code, "SPX-Z902");
    assert!(error.message.contains("agent-run"), "{}", error.message);
}

#[test]
fn a_release_profile_capsule_with_its_own_required_types_present_verifies() {
    let artifact_bytes = b"release archive bytes for the fixture";
    let provenance_bytes = b"release provenance canonical bytes for the fixture";
    let signature_claim_bytes = b"release signature claim canonical bytes for the fixture";
    let package_manifest_bytes = b"package manifest canonical bytes for the fixture";
    let manifest = format!(
        r#"{{
  "schema": "semaprax.audit-capsule.v1",
  "profile": "release",
  "subject": {{
    "release_tag": "v1.2.3",
    "commit": "0123456789abcdef0123456789abcdef01234567",
    "artifact_digest": "{artifact_digest}"
  }},
  "objects": [
    {{"id": "obj-a-artifact", "object_type": "artifact", "schema": "semaprax.release-manifest.v1", "digest": "{artifact_digest}", "redacted": false, "redaction_reason": null, "binds": {{"artifact_digest": "{artifact_digest}"}}}},
    {{"id": "obj-b-package-manifest", "object_type": "package-manifest", "schema": "semaprax.package-manifest.v1", "digest": "{package_manifest_digest}", "redacted": false, "redaction_reason": null, "binds": {{}}}},
    {{"id": "obj-c-release-provenance", "object_type": "release-provenance", "schema": "semaprax.release-provenance.v1", "digest": "{provenance_digest}", "redacted": false, "redaction_reason": null, "binds": {{"commit": "0123456789abcdef0123456789abcdef01234567"}}}},
    {{"id": "obj-d-release-signature-claim", "object_type": "release-signature-claim", "schema": "semaprax.release-signature-claim.v1", "digest": "{signature_claim_digest}", "redacted": false, "redaction_reason": null, "binds": {{}}}}
  ],
  "associations": [
    {{"from_id": "obj-c-release-provenance", "relation": "attests", "to_id": "obj-a-artifact"}},
    {{"from_id": "obj-d-release-signature-claim", "relation": "attests", "to_id": "obj-c-release-provenance"}}
  ],
  "signatures": [
    {{"role": "publisher", "identity": "agent://release-bot", "algorithm": "sigstore-cosign-bundle-v0.3", "signature": "fixture-signature", "not_valid_after_unix_seconds": 9999999999}}
  ],
  "transparency": null
}}"#,
        artifact_digest = sha256_digest(artifact_bytes),
        package_manifest_digest = sha256_digest(package_manifest_bytes),
        provenance_digest = sha256_digest(provenance_bytes),
        signature_claim_digest = sha256_digest(signature_claim_bytes),
    );
    let mut object_bytes = BTreeMap::new();
    object_bytes.insert("obj-a-artifact".to_owned(), artifact_bytes.to_vec());
    object_bytes.insert(
        "obj-b-package-manifest".to_owned(),
        package_manifest_bytes.to_vec(),
    );
    object_bytes.insert(
        "obj-c-release-provenance".to_owned(),
        provenance_bytes.to_vec(),
    );
    object_bytes.insert(
        "obj-d-release-signature-claim".to_owned(),
        signature_claim_bytes.to_vec(),
    );
    let ctx = SignaturePolicyContext {
        verification_time_unix_seconds: 1_000,
        revoked_identities: Default::default(),
        required_roles: vec!["publisher".to_owned()],
    };
    let report = verify_capsule(
        manifest.as_bytes(),
        &object_bytes,
        &ctx,
        &empty_transparency_ctx(),
    )
    .expect("release-profile fixture with its own required object types verifies");
    assert_eq!(report.profile, Profile::Release);
    assert_eq!(report.verified_object_ids.len(), 4);
}

// ---------------------------------------------------------------------
// Bounds: an enormous capsule and a self-referential object type are
// both rejected structurally, not merely discouraged.
// ---------------------------------------------------------------------

#[test]
fn a_manifest_over_the_byte_limit_is_rejected_before_json_parsing() {
    let oversized = vec![b' '; MAX_MANIFEST_BYTES + 1];
    let error = parse_capsule(&oversized).unwrap_err();
    assert_eq!(error.code, "SPX-Z907");
    assert!(error.message.contains("exceeding"), "{}", error.message);
}

#[test]
fn an_object_claiming_to_be_an_audit_capsule_itself_is_rejected() {
    // `KNOWN_OBJECT_TYPES` never includes "audit-capsule", so a capsule
    // cannot embed another capsule as one of its own objects -- the
    // structural guard against "a capsule recursively references itself."
    assert!(!KNOWN_OBJECT_TYPES.contains(&"audit-capsule"));
    let (manifest, _) = change_fixture("r1");
    let self_embedding = manifest.replacen(
        r#""object_type": "program-root""#,
        r#""object_type": "audit-capsule""#,
        1,
    );
    let error = parse_capsule(self_embedding.as_bytes()).unwrap_err();
    assert_eq!(error.code, "SPX-Z902");
}

// ---------------------------------------------------------------------
// `render_capsule`: the "emit" half of issue #209 -- building canonical
// manifest bytes from typed pieces, round-tripping through `parse_capsule`
// and `verify_capsule` exactly like a hand-written fixture.
// ---------------------------------------------------------------------

fn revision_binds(revision: &str) -> BTreeMap<String, String> {
    let mut binds = BTreeMap::new();
    binds.insert("revision".to_owned(), revision.to_owned());
    binds
}

fn source_binds() -> BTreeMap<String, String> {
    let mut binds = BTreeMap::new();
    binds.insert(
        "source_digest".to_owned(),
        "sha256:1111111111111111111111111111111111111111111111111111111111111111".to_owned(),
    );
    binds
}

fn change_subject(revision: &str) -> BTreeMap<String, String> {
    let mut subject = BTreeMap::new();
    subject.insert(
        "source_digest".to_owned(),
        "sha256:1111111111111111111111111111111111111111111111111111111111111111".to_owned(),
    );
    subject.insert(
        "root_digest".to_owned(),
        "sha256:2222222222222222222222222222222222222222222222222222222222222222".to_owned(),
    );
    subject.insert("revision".to_owned(), revision.to_owned());
    subject
}

#[test]
fn render_capsule_builds_bytes_that_verify_identically_to_a_hand_written_manifest() {
    let (_, object_bytes) = change_fixture("r1");
    let subject = change_subject("r1");

    // Deliberately handed in *descending* order: `render_capsule` must sort
    // into the canonical ascending order itself rather than merely
    // requiring the caller to have done so already.
    let objects = vec![
        ObjectRef {
            id: "obj-d-source-projection".to_owned(),
            object_type: "source-projection".to_owned(),
            schema: "semaprax.program-root.v3".to_owned(),
            digest: sha256_digest(OBJECT_D_BYTES),
            redacted: false,
            redaction_reason: None,
            binds: source_binds(),
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
            id: "obj-b-semantic-transaction".to_owned(),
            object_type: "semantic-transaction".to_owned(),
            schema: "semaprax.project-candidate-semantic-delta.v1".to_owned(),
            digest: sha256_digest(OBJECT_B_BYTES),
            redacted: false,
            redaction_reason: None,
            binds: revision_binds("r1"),
        },
        ObjectRef {
            id: "obj-a-program-root".to_owned(),
            object_type: "program-root".to_owned(),
            schema: "semaprax.program-root.v3".to_owned(),
            digest: sha256_digest(OBJECT_A_BYTES),
            redacted: false,
            redaction_reason: None,
            binds: revision_binds("r1"),
        },
    ];
    let associations = vec![
        AssociationEdge {
            from_id: "obj-b-semantic-transaction".to_owned(),
            relation: "derived_from".to_owned(),
            to_id: "obj-a-program-root".to_owned(),
        },
        AssociationEdge {
            from_id: "obj-c-assurance-manifest".to_owned(),
            relation: "attests".to_owned(),
            to_id: "obj-b-semantic-transaction".to_owned(),
        },
    ];

    let rendered = render_capsule(
        Profile::Change,
        &subject,
        &objects,
        &associations,
        &[],
        None,
    )
    .expect("well-formed pieces render into a well-formed manifest");
    let report = verify_capsule(
        &rendered,
        &object_bytes,
        &empty_signature_ctx(),
        &empty_transparency_ctx(),
    )
    .expect("rendered capsule verifies exactly like the hand-written fixture");
    assert_eq!(report.verified_object_ids.len(), 4);

    let capsule = parse_capsule(&rendered).expect("rendered bytes parse");
    let ids: Vec<&str> = capsule.objects.iter().map(|o| o.id.as_str()).collect();
    assert_eq!(
        ids,
        vec![
            "obj-a-program-root",
            "obj-b-semantic-transaction",
            "obj-c-assurance-manifest",
            "obj-d-source-projection"
        ],
        "render_capsule must emit objects in ascending canonical order regardless of input order"
    );
}

#[test]
fn render_capsule_rejects_a_subject_missing_a_required_key_for_its_profile() {
    let mut subject = BTreeMap::new();
    subject.insert(
        "source_digest".to_owned(),
        "sha256:1111111111111111111111111111111111111111111111111111111111111111".to_owned(),
    );
    // "root_digest" and "revision" are missing.
    let error = render_capsule(Profile::Change, &subject, &[], &[], &[], None).unwrap_err();
    assert_eq!(error.code, "SPX-Z901");
    assert!(
        error.message.contains("subject keys must be exactly"),
        "{}",
        error.message
    );
}

// ---------------------------------------------------------------------
// Selective disclosure: a redacted release and a later disclosed release
// of the same object commit to the exact same digest, so a verifier can
// check a disclosure against a fact the redacted capsule already recorded
// rather than trusting a brand-new, unrelated claim.
// ---------------------------------------------------------------------

#[test]
fn a_disclosed_object_verifies_against_the_exact_commitment_a_prior_redacted_capsule_recorded() {
    let subject = change_subject("r1");
    let secret_bytes = b"program root containing a private path the author chose to withhold";
    let secret_digest = sha256_digest(secret_bytes);

    let other_objects = vec![
        ObjectRef {
            id: "obj-b-semantic-transaction".to_owned(),
            object_type: "semantic-transaction".to_owned(),
            schema: "semaprax.project-candidate-semantic-delta.v1".to_owned(),
            digest: sha256_digest(OBJECT_B_BYTES),
            redacted: false,
            redaction_reason: None,
            binds: revision_binds("r1"),
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

    let redacted_object = ObjectRef {
        id: "obj-a-program-root".to_owned(),
        object_type: "program-root".to_owned(),
        schema: "semaprax.program-root.v3".to_owned(),
        digest: secret_digest.clone(),
        redacted: true,
        redaction_reason: Some("contains a private filesystem path".to_owned()),
        binds: revision_binds("r1"),
    };
    let mut redacted_objects = vec![redacted_object];
    redacted_objects.extend(other_objects.iter().cloned());
    let redacted_manifest =
        render_capsule(Profile::Change, &subject, &redacted_objects, &[], &[], None)
            .expect("redacted capsule renders");

    let mut object_bytes_without_secret = BTreeMap::new();
    object_bytes_without_secret.insert(
        "obj-b-semantic-transaction".to_owned(),
        OBJECT_B_BYTES.to_vec(),
    );
    object_bytes_without_secret.insert(
        "obj-c-assurance-manifest".to_owned(),
        OBJECT_C_BYTES.to_vec(),
    );
    object_bytes_without_secret.insert(
        "obj-d-source-projection".to_owned(),
        OBJECT_D_BYTES.to_vec(),
    );
    let redacted_report = verify_capsule(
        &redacted_manifest,
        &object_bytes_without_secret,
        &empty_signature_ctx(),
        &empty_transparency_ctx(),
    )
    .expect("a capsule with one redacted object still verifies");
    assert_eq!(redacted_report.unavailable_claims.len(), 1);
    assert_eq!(
        redacted_report.unavailable_claims[0].0,
        "obj-a-program-root"
    );

    let disclosed_object = ObjectRef {
        id: "obj-a-program-root".to_owned(),
        object_type: "program-root".to_owned(),
        schema: "semaprax.program-root.v3".to_owned(),
        digest: secret_digest,
        redacted: false,
        redaction_reason: None,
        binds: revision_binds("r1"),
    };
    let mut disclosed_objects = vec![disclosed_object];
    disclosed_objects.extend(other_objects);
    let disclosed_manifest = render_capsule(
        Profile::Change,
        &subject,
        &disclosed_objects,
        &[],
        &[],
        None,
    )
    .expect("disclosed capsule renders");
    let mut object_bytes_with_secret = object_bytes_without_secret;
    object_bytes_with_secret.insert("obj-a-program-root".to_owned(), secret_bytes.to_vec());
    let disclosed_report = verify_capsule(
        &disclosed_manifest,
        &object_bytes_with_secret,
        &empty_signature_ctx(),
        &empty_transparency_ctx(),
    )
    .expect("the disclosed object's bytes must match the digest the redacted capsule already committed to");
    assert!(disclosed_report.unavailable_claims.is_empty());
    assert_eq!(disclosed_report.verified_object_ids.len(), 4);

    // The commitment itself never moved between the two releases.
    let redacted_capsule = parse_capsule(&redacted_manifest).unwrap();
    let disclosed_capsule = parse_capsule(&disclosed_manifest).unwrap();
    let redacted_digest = &redacted_capsule
        .objects
        .iter()
        .find(|o| o.id == "obj-a-program-root")
        .unwrap()
        .digest;
    let disclosed_digest = &disclosed_capsule
        .objects
        .iter()
        .find(|o| o.id == "obj-a-program-root")
        .unwrap()
        .digest;
    assert_eq!(redacted_digest, disclosed_digest);
}

// ---------------------------------------------------------------------
// Decision records stay a distinct object type from technical evidence,
// and a role-tagged signature is a third, separate mechanism again --
// issue #209's "do not collapse technical evidence and human decisions
// into one status."
// ---------------------------------------------------------------------

#[test]
fn a_decision_record_object_stays_distinct_from_technical_evidence_and_from_signatures() {
    let (manifest, mut object_bytes) = change_fixture("r1");
    let decision_bytes = b"decision record: approver decided to proceed for revision r1";
    let decision_digest = sha256_digest(decision_bytes);
    let decision_entry = format!(
        ",\n    {{\"id\": \"obj-z-decision-record\", \"object_type\": \"decision-record\", \
         \"schema\": \"semaprax.decision-record.v1\", \"digest\": \"{decision_digest}\", \
         \"redacted\": false, \"redaction_reason\": null, \"binds\": {{}}}}"
    );
    let marker = "\n  ],\n  \"associations\"";
    assert!(manifest.contains(marker));
    let with_decision = manifest
        .replacen(marker, &format!("{decision_entry}{marker}"), 1)
        .replacen(
            "\"signatures\": []",
            r#""signatures": [{"role": "approver", "identity": "agent://carol", "algorithm": "ed25519-raw-v1", "signature": "fixture-sig", "not_valid_after_unix_seconds": 9999999999}]"#,
            1,
        );
    object_bytes.insert("obj-z-decision-record".to_owned(), decision_bytes.to_vec());

    let capsule = parse_capsule(with_decision.as_bytes()).expect("manifest is well-formed");
    let decision_objects: Vec<&ObjectRef> = capsule
        .objects
        .iter()
        .filter(|candidate| candidate.object_type == "decision-record")
        .collect();
    assert_eq!(decision_objects.len(), 1);
    // The decision-record object (a human decision, recorded as evidence)
    // and the approver signature (who attests to it) are two distinct
    // facts -- neither is implied by, nor collapsed into, the other.
    assert_eq!(capsule.signatures.len(), 1);
    assert_eq!(capsule.signatures[0].role, "approver");

    let ctx = SignaturePolicyContext {
        verification_time_unix_seconds: 1_000,
        revoked_identities: Default::default(),
        required_roles: vec!["approver".to_owned()],
    };
    let report = verify_capsule(
        with_decision.as_bytes(),
        &object_bytes,
        &ctx,
        &empty_transparency_ctx(),
    )
    .expect("technical evidence and a human decision coexist and both verify");
    assert_eq!(report.verified_object_ids.len(), 5);
}

// ---------------------------------------------------------------------
// Verification code never accidentally executes an included artifact
// (issue #209's failure list) -- a hostile-looking payload is still just
// opaque, hashed bytes.
// ---------------------------------------------------------------------

#[test]
fn an_artifact_object_containing_executable_looking_bytes_verifies_as_opaque_data() {
    // Shebang plus an ELF magic number: bytes that look maximally
    // dangerous to run, deliberately chosen so this test would be the one
    // to fail if `check_object_bytes` ever grew a code path that
    // interpreted, spawned, or loaded an object's bytes instead of only
    // hashing and comparing them.
    let hostile_artifact: &[u8] = b"#!/bin/sh\nrm -rf / --no-preserve-root\n\x7fELF\x02\x01\x01";
    let (manifest, mut object_bytes) = change_fixture("r1");
    let artifact_digest = sha256_digest(hostile_artifact);
    let artifact_entry = format!(
        ",\n    {{\"id\": \"obj-z-artifact\", \"object_type\": \"artifact\", \"schema\": \
         \"semaprax.release-manifest.v1\", \"digest\": \"{artifact_digest}\", \"redacted\": \
         false, \"redaction_reason\": null, \"binds\": {{}}}}"
    );
    let marker = "\n  ],\n  \"associations\"";
    let with_artifact = manifest.replacen(marker, &format!("{artifact_entry}{marker}"), 1);
    object_bytes.insert("obj-z-artifact".to_owned(), hostile_artifact.to_vec());

    let report = verify_capsule(
        with_artifact.as_bytes(),
        &object_bytes,
        &empty_signature_ctx(),
        &empty_transparency_ctx(),
    )
    .expect("hostile-looking bytes are still just an opaque, verifiable blob");
    assert_eq!(report.verified_object_ids.len(), 5);
    assert!(report
        .verified_object_ids
        .contains(&"obj-z-artifact".to_owned()));
}

// ---------------------------------------------------------------------
// Evidence, not authority: verifying the same capsule repeatedly never
// changes, because verification is a pure read-only check that grants
// nothing that could be spent, expired by use, or double-checked against a
// prior "already used" record. If verification conferred one-time
// authority, a second identical call would have to behave differently.
// ---------------------------------------------------------------------

#[test]
fn verifying_the_same_capsule_repeatedly_produces_byte_identical_reports_every_time() {
    let (manifest, object_bytes) = change_fixture("r1");
    let first = verify_capsule(
        manifest.as_bytes(),
        &object_bytes,
        &empty_signature_ctx(),
        &empty_transparency_ctx(),
    )
    .expect("verifies");
    for _ in 0..5 {
        let repeat = verify_capsule(
            manifest.as_bytes(),
            &object_bytes,
            &empty_signature_ctx(),
            &empty_transparency_ctx(),
        )
        .expect("verifies identically every time -- nothing here is consumed by a prior call");
        assert_eq!(repeat.profile, first.profile);
        assert_eq!(repeat.verified_object_ids, first.verified_object_ids);
        assert_eq!(repeat.unavailable_claims, first.unavailable_claims);
    }
}

// ---------------------------------------------------------------------
// `diff_capsules`: the library half of issue #209's `semaprax audit diff`.
// ---------------------------------------------------------------------

#[test]
fn diffing_two_capsules_built_from_identical_bytes_is_empty() {
    let (manifest, _) = change_fixture("r1");
    let capsule_one = parse_capsule(manifest.as_bytes()).unwrap();
    let capsule_two = parse_capsule(manifest.as_bytes()).unwrap();
    let diff = diff_capsules(&capsule_one, &capsule_two);
    assert!(diff.is_empty());
}

#[test]
fn diffing_two_revisions_reports_the_subject_change() {
    let (manifest_r1, _) = change_fixture("r1");
    let (manifest_r2, _) = change_fixture("r2");
    let capsule_r1 = parse_capsule(manifest_r1.as_bytes()).unwrap();
    let capsule_r2 = parse_capsule(manifest_r2.as_bytes()).unwrap();
    let diff = diff_capsules(&capsule_r1, &capsule_r2);
    assert_eq!(
        diff.subject_changed.get("revision"),
        Some(&(Some("r1".to_owned()), Some("r2".to_owned())))
    );
    assert!(diff.added_object_ids.is_empty());
    assert!(diff.removed_object_ids.is_empty());
}

#[test]
fn diffing_capsules_with_an_added_object_and_a_changed_digest_reports_both_distinctly() {
    let (manifest, _) = change_fixture("r1");
    let capsule_before = parse_capsule(manifest.as_bytes()).unwrap();

    let new_digest = sha256_digest(b"a newer program-root for the same revision");
    let changed = manifest.replacen(&sha256_digest(OBJECT_A_BYTES), &new_digest, 1);
    let extra_entry = format!(
        ",\n    {{\"id\": \"obj-z-decision-record\", \"object_type\": \"decision-record\", \
         \"schema\": \"semaprax.decision-record.v1\", \"digest\": \"{}\", \"redacted\": false, \
         \"redaction_reason\": null, \"binds\": {{}}}}",
        sha256_digest(b"a brand new decision record")
    );
    let marker = "\n  ],\n  \"associations\"";
    let after_manifest = changed.replacen(marker, &format!("{extra_entry}{marker}"), 1);
    let capsule_after = parse_capsule(after_manifest.as_bytes()).unwrap();

    let diff = diff_capsules(&capsule_before, &capsule_after);
    assert_eq!(
        diff.added_object_ids,
        vec!["obj-z-decision-record".to_owned()]
    );
    assert!(diff.removed_object_ids.is_empty());
    assert_eq!(diff.changed_objects.len(), 1);
    match diff.changed_objects.get("obj-a-program-root") {
        Some(ObjectChange::Changed {
            before_digest,
            after_digest,
        }) => {
            assert_eq!(before_digest, &sha256_digest(OBJECT_A_BYTES));
            assert_eq!(after_digest, &new_digest);
        }
        other => panic!("expected a Changed entry for obj-a-program-root, got {other:?}"),
    }
}

#[test]
fn diffing_capsules_reports_an_added_association_edge() {
    let (manifest, _) = change_fixture("r1");
    let capsule_before = parse_capsule(manifest.as_bytes()).unwrap();
    let with_extra_edge = manifest.replacen(
        r#""associations": [
    {"from_id": "obj-b-semantic-transaction", "relation": "derived_from", "to_id": "obj-a-program-root"},
    {"from_id": "obj-c-assurance-manifest", "relation": "attests", "to_id": "obj-b-semantic-transaction"}
  ]"#,
        r#""associations": [
    {"from_id": "obj-b-semantic-transaction", "relation": "derived_from", "to_id": "obj-a-program-root"},
    {"from_id": "obj-c-assurance-manifest", "relation": "attests", "to_id": "obj-b-semantic-transaction"},
    {"from_id": "obj-d-source-projection", "relation": "attests", "to_id": "obj-a-program-root"}
  ]"#,
        1,
    );
    let capsule_after = parse_capsule(with_extra_edge.as_bytes()).unwrap();
    let diff = diff_capsules(&capsule_before, &capsule_after);
    assert_eq!(diff.added_associations.len(), 1);
    assert_eq!(
        diff.added_associations[0].from_id,
        "obj-d-source-projection"
    );
    assert!(diff.removed_associations.is_empty());
}

#[test]
fn diffing_capsules_reports_added_and_removed_signature_roles() {
    let manifest_before = signed_manifest(
        r#"[{"role": "proposer", "identity": "agent://alice", "algorithm": "ed25519-raw-v1", "signature": "fixture-sig-1", "not_valid_after_unix_seconds": 5000}]"#,
    );
    let manifest_after = signed_manifest(
        r#"[{"role": "approver", "identity": "agent://bob", "algorithm": "ed25519-raw-v1", "signature": "fixture-sig-2", "not_valid_after_unix_seconds": 5000}]"#,
    );
    let capsule_before = parse_capsule(manifest_before.as_bytes()).unwrap();
    let capsule_after = parse_capsule(manifest_after.as_bytes()).unwrap();
    let diff = diff_capsules(&capsule_before, &capsule_after);
    assert_eq!(diff.removed_signature_roles, vec!["proposer".to_owned()]);
    assert_eq!(diff.added_signature_roles, vec!["approver".to_owned()]);
}
