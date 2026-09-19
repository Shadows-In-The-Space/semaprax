//! Two hostile-input cases from issue #209's "prove all object
//! associations" requirement that the rest of `tests.rs` does not already
//! cover verbatim:
//!
//! - a redaction that removes an object another entry still references
//!   (distinct from `supplying_retained_bytes_for_a_redacted_object_is_\
//!   rejected_as_a_leak`, which is about *leaking* a redacted object's
//!   bytes, not about another object's association *edge* surviving
//!   redaction);
//! - a transparency-log inclusion proof genuinely valid for a *different*
//!   capsule, rather than an arbitrary wrong digest string.
//!
//! Every other named case in the issue's matrix already has a direct
//! regression test in `tests.rs`: a missing retained object body
//! (`a_missing_retained_object_body_is_rejected_distinctly_from_substitution`),
//! a mismatched digest (`a_substituted_object_whose_bytes_do_not_match_its_digest_is_rejected`),
//! and a duplicate object id carrying different content
//! (`a_duplicate_object_id_is_rejected`, which renames one of two
//! *differently-typed* fixture objects to collide -- same id, different
//! `object_type`/`digest`/`binds`). Selective redaction's two properties --
//! a redacted capsule still verifies its remaining facts, and a later
//! disclosure must match the exact digest the redacted capsule already
//! committed to -- are proven by
//! `a_disclosed_object_verifies_against_the_exact_commitment_a_prior_redacted_capsule_recorded`
//! together with `diffing_capsules_with_an_added_object_and_a_changed_digest_reports_both_distinctly`,
//! which shows a changed digest for the same object id is never invisible
//! to a diff.

use std::collections::{BTreeMap, BTreeSet};

use super::*;

#[test]
fn an_association_edge_into_a_redacted_object_still_verifies_but_the_objects_own_facts_stay_unavailable(
) {
    let subject = change_subject("r1");
    let secret_bytes = b"program root a downstream object still derives_from, once redacted";
    let secret_digest = sha256_digest(secret_bytes);

    let objects = vec![
        ObjectRef {
            id: "obj-a-program-root".to_owned(),
            object_type: "program-root".to_owned(),
            schema: "semaprax.program-root.v3".to_owned(),
            digest: secret_digest,
            redacted: true,
            redaction_reason: Some("contains a private filesystem path".to_owned()),
            binds: revision_binds("r1"),
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
    // The non-redacted semantic-transaction object still associates to the
    // now-redacted program root -- exactly the shape a real "which change
    // did this transaction derive from" claim takes once the root is
    // withheld.
    let associations = [AssociationEdge {
        from_id: "obj-b-semantic-transaction".to_owned(),
        relation: "derived_from".to_owned(),
        to_id: "obj-a-program-root".to_owned(),
    }];

    // The association graph itself only needs both ids to exist; it must
    // not require bytes for either endpoint.
    check_associations(&ParsedCapsule {
        profile: Profile::Change,
        subject: subject.clone(),
        objects: objects.clone(),
        associations: associations.to_vec(),
        signatures: Vec::new(),
        transparency: None,
        nonclaims: redacted_nonclaims(),
    })
    .expect("an association edge into a redacted object is not dangling");

    let manifest = render_capsule(
        Profile::Change,
        &subject,
        &objects,
        &associations,
        &[],
        None,
        &redacted_nonclaims(),
    )
    .expect("fixture capsule renders");

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
        &manifest,
        &object_bytes,
        &empty_signature_ctx(),
        &empty_transparency_ctx(),
    )
    .expect("a capsule where a live object associates to a redacted one still verifies as a whole");
    // The association survives redaction, but the redacted object's own
    // facts are still explicitly reported as unavailable rather than
    // silently folded into a green result.
    assert_eq!(report.unavailable_claims.len(), 1);
    assert_eq!(report.unavailable_claims[0].0, "obj-a-program-root");
    assert_eq!(report.verified_object_ids.len(), 3);
}

#[test]
fn a_transparency_entry_genuinely_valid_for_a_different_capsule_is_rejected() {
    let (manifest_r1, _) = change_fixture("r1");
    let (manifest_r2, _) = change_fixture("r2");

    // A real leaf digest, honestly computed -- just for the wrong capsule.
    let leaf_digest_for_r1 = transparency_leaf_digest(manifest_r1.as_bytes())
        .expect("r1 fixture manifest is well-formed");
    assert_ne!(
        leaf_digest_for_r1,
        transparency_leaf_digest(manifest_r2.as_bytes()).unwrap(),
        "the fixtures must actually differ, or this test would not exercise anything"
    );

    let borrowed = manifest_r2.replacen(
        "\"transparency\": null",
        &format!(
            "\"transparency\": {{\"log_id\": \"known-log\", \"leaf_digest\": \"{leaf_digest_for_r1}\", \
             \"inclusion_proof\": [\"step-1\"], \"observed_checkpoint_size\": 100}}"
        ),
        1,
    );
    let capsule = parse_capsule(borrowed.as_bytes()).expect("manifest stays well-formed JSON");
    let mut known_logs: BTreeSet<String> = BTreeSet::new();
    known_logs.insert("known-log".to_owned());
    let ctx = TransparencyContext {
        known_logs,
        minimum_accepted_checkpoint_size: 0,
    };
    let error = check_transparency(&capsule, borrowed.as_bytes(), &ctx).unwrap_err();
    assert_eq!(error.code, "SPX-Z906");
    assert!(
        error.message.contains("does not match"),
        "a leaf digest genuinely computed for a different capsule must still be rejected as a \
         mismatch, not silently accepted: {}",
        error.message
    );
}
