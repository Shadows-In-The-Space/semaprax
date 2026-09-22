//! Issue #173: the independent reference decoder's own coverage.
//!
//! These tests bind the decoder to the specification, not to the production
//! codec: if both implementations drifted together, the corpus cross-check
//! in [`super::super::hostile_corpus`] would still pass, so the properties
//! that make the decoder *independent* are pinned here directly.

use super::*;
use crate::public_generic_abi::carrier::frame::{
    parse_bounded, CarrierFrameBinding, CarrierLeaf, LeafKind,
};

fn plan() -> ReferencePlan {
    ReferencePlan::new(
        Direction::Input,
        "sha256:1111111111111111111111111111111111111111111111111111111111111111",
        "issue173.reference.decoder.export",
        "sha256:2222222222222222222222222222222222222222222222222222222222222222",
        vec!["value.left".to_owned(), "value.right".to_owned()],
    )
}

fn payloads() -> Vec<Vec<u8>> {
    vec![Vec::new(), vec![0x00, 0x80, 0xff]]
}

#[test]
fn reference_bounds_equal_the_frozen_boundary_profile() {
    assert!(
        reference_bounds_match_boundary_profile(),
        "this decoder restates the frozen bounds deliberately; a production \
         bound change must be mirrored here rather than silently diverging"
    );
    assert_eq!(REFERENCE_MAX_OWNED_LEAVES, 256);
    assert_eq!(REFERENCE_MAX_BYTES_PER_LEAF, 65_536);
    assert_eq!(REFERENCE_MAX_TOTAL_PAYLOAD_BYTES, 16 * 1024 * 1024);
    // The frozen identity the production profile also pins: a carrier can
    // never exceed the aggregate bound without first breaking a narrower one.
    assert_eq!(
        REFERENCE_MAX_OWNED_LEAVES * REFERENCE_MAX_BYTES_PER_LEAF,
        REFERENCE_MAX_TOTAL_PAYLOAD_BYTES
    );
}

#[test]
fn the_reference_encoding_is_byte_identical_to_the_production_encoding() {
    // The whole cross-check rests on both implementations agreeing on what
    // the canonical bytes *are*. Pin that here, once, rather than assuming
    // it everywhere else.
    let plan = plan();
    let reference = encode_canonical(&plan, &payloads()).expect("paired payloads");

    let binding = CarrierFrameBinding::new(
        Direction::Input,
        plan.descriptor_digest(),
        plan.endpoint_identity_digest(),
        plan.instance_identity_digest(),
        plan.leaf_paths().to_vec(),
    );
    let produced = binding
        .frame_with_leaves(
            plan.leaf_paths()
                .iter()
                .zip(payloads())
                .map(|(path, payload)| CarrierLeaf::new(path.clone(), LeafKind::Bytes, payload))
                .collect(),
        )
        .encode();
    assert_eq!(reference, produced);
}

#[test]
fn the_reference_derives_the_same_inventory_identity_as_the_production_binding() {
    let plan = plan();
    let binding = CarrierFrameBinding::new(
        Direction::Input,
        plan.descriptor_digest(),
        plan.endpoint_identity_digest(),
        plan.instance_identity_digest(),
        plan.leaf_paths().to_vec(),
    );
    // The production binding derives its inventory identity internally; the
    // only way to observe it is through a frame it forms.
    let produced = binding.frame_with_leaves(Vec::new());
    let reference_inventory = leaf_inventory_digest(plan.leaf_paths());
    let encoded = produced.encode();
    assert!(
        encoded
            .windows(reference_inventory.len())
            .any(|window| window == reference_inventory.as_bytes()),
        "the production binding must carry the independently recomputed \
         inventory identity"
    );
}

#[test]
fn the_inventory_preimage_cannot_be_confused_by_regrouping_paths() {
    // A count-prefixed, length-framed preimage is what stops `["a", "bc"]`
    // and `["ab", "c"]` sharing an identity. A naive concatenation would.
    let left = leaf_inventory_digest(&["a".to_owned(), "bc".to_owned()]);
    let right = leaf_inventory_digest(&["ab".to_owned(), "c".to_owned()]);
    assert_ne!(left, right);
}

#[test]
fn the_endpoint_identity_is_domain_separated_from_the_inventory_identity() {
    // Two derived identities over the same bytes must never collide.
    let endpoint = endpoint_identity_digest("x");
    let inventory = leaf_inventory_digest(&["x".to_owned()]);
    assert_ne!(endpoint, inventory);
}

#[test]
fn a_canonical_document_round_trips_through_both_readers() {
    let plan = plan();
    let bytes = encode_canonical(&plan, &payloads()).expect("paired payloads");
    let admitted = decode_and_bind(&bytes, &plan).expect("the canonical document is admitted");
    assert_eq!(admitted.len(), 2);
    assert_eq!(admitted[0].path, "value.left");
    assert!(admitted[0].payload.is_empty());
    assert_eq!(admitted[1].payload, vec![0x00, 0x80, 0xff]);
    parse_bounded(&bytes).expect("the production codec admits the same document");
}

#[test]
fn encode_canonical_refuses_a_payload_list_that_does_not_match_the_inventory() {
    let plan = plan();
    assert!(encode_canonical(&plan, &[Vec::new()]).is_none());
    assert!(encode_canonical(&plan, &[Vec::new(), Vec::new(), Vec::new()]).is_none());
}

#[test]
fn the_refusal_class_is_a_closed_bijection_with_the_stable_codes() {
    for class in [
        CarrierRefusal::Malformed,
        CarrierRefusal::Capacity,
        CarrierRefusal::ReplayMismatch,
        CarrierRefusal::IllegalTransition,
        CarrierRefusal::GenerationMismatch,
    ] {
        assert_eq!(CarrierRefusal::from_code(class.code()), Some(class));
    }
    // A code outside the carrier family never normalizes into the class, so
    // a reader that refuses for an unrelated reason cannot be scored as
    // agreeing with this decoder.
    assert_eq!(CarrierRefusal::from_code("SPX-PG701"), None);
    assert_eq!(CarrierRefusal::from_code(""), None);
}

#[test]
fn a_zero_generation_guard_cannot_be_constructed() {
    assert_eq!(
        ReferenceAdmission::new(plan(), 0, "sha256:aa").unwrap_err(),
        CarrierRefusal::Malformed
    );
    assert!(ReferenceAdmission::new(plan(), 1, "sha256:aa").is_ok());
}

#[test]
fn reminting_a_canonical_document_reproduces_it_exactly() {
    let bytes = encode_canonical(&plan(), &payloads()).expect("paired payloads");
    assert_eq!(
        remint_facts_digest(&bytes).as_deref(),
        Some(bytes.as_slice())
    );
}

#[test]
fn a_reminted_forgery_is_self_consistent_and_still_refused() {
    // The decisive property: after reminting, the document passes every
    // internal consistency check it carries -- and is still refused, because
    // the endpoint identity is recomputed from the trusted export identity
    // rather than read from the wire.
    let trusted = plan();
    let forged_plan = ReferencePlan::new(
        Direction::Input,
        trusted.descriptor_digest(),
        "issue173.reference.decoder.other_export",
        trusted.instance_identity_digest(),
        trusted.leaf_paths().to_vec(),
    );
    let forged = encode_canonical(&forged_plan, &payloads()).expect("paired payloads");

    // Self-consistent: the production codec, which checks only structure and
    // the self-digest, admits it outright.
    parse_bounded(&forged).expect("a reminted forgery decodes structurally");

    // Bound: the trusted-root replay refuses it.
    assert_eq!(
        decode_and_bind(&forged, &trusted).unwrap_err(),
        CarrierRefusal::ReplayMismatch
    );
}

#[test]
fn a_truncation_at_every_byte_boundary_is_refused() {
    // Exhaustive rather than sampled: every prefix of a canonical document
    // is hostile, and none may be admitted.
    let bytes = encode_canonical(&plan(), &payloads()).expect("paired payloads");
    for cut in 0..bytes.len() {
        assert!(
            decode_and_bind(&bytes[..cut], &plan()).is_err(),
            "prefix of {cut} byte(s) was admitted"
        );
    }
    assert!(decode_and_bind(&bytes, &plan()).is_ok());
}

#[test]
fn every_single_byte_corruption_is_refused() {
    // Exhaustive over positions, with one flip per position: the self-digest
    // plus the trusted-root replay must leave no admissible corruption.
    let trusted = plan();
    let bytes = encode_canonical(&trusted, &payloads()).expect("paired payloads");
    for index in 0..bytes.len() {
        let mut corrupted = bytes.clone();
        corrupted[index] ^= 0xff;
        assert!(
            decode_and_bind(&corrupted, &trusted).is_err(),
            "a single flipped byte at {index} was admitted"
        );
    }
}

#[test]
fn a_hostile_length_claim_never_drives_a_large_read() {
    // A document that declares a leaf count of `u64::MAX` must be refused by
    // the bound, not by an attempted 2^64-element reservation.
    let trusted = plan();
    let mut bytes = encode_canonical(&trusted, &payloads()).expect("paired payloads");
    // Walk to the leaf-count field: six framed fields precede it.
    let mut offset = 0usize;
    for _ in 0..6 {
        let length = u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap()) as usize;
        offset += 8 + length;
    }
    bytes[offset..offset + 8].copy_from_slice(&u64::MAX.to_le_bytes());
    assert_eq!(
        decode_and_bind(&bytes, &trusted).unwrap_err(),
        CarrierRefusal::Capacity
    );
}

#[test]
fn the_admission_envelope_is_checked_before_the_document() {
    // A ticket that is hostile in both the envelope and the document must
    // publish the envelope's class, so the two implementations agree on a
    // document that violates more than one invariant.
    let guard = ReferenceAdmission::new(plan(), 7, "sha256:aa").expect("nonzero generation");
    let ticket = ReferenceTicket {
        generation: 6,
        ownership: ReferenceOwnership::Caller,
        cleanup_plan_digest: "sha256:aa".to_owned(),
        frame_bytes: Vec::new(),
    };
    assert_eq!(
        guard.admit(&ticket).unwrap_err(),
        CarrierRefusal::GenerationMismatch
    );

    let ticket = ReferenceTicket {
        generation: 7,
        ownership: ReferenceOwnership::Provider,
        cleanup_plan_digest: "sha256:aa".to_owned(),
        frame_bytes: Vec::new(),
    };
    assert_eq!(
        guard.admit(&ticket).unwrap_err(),
        CarrierRefusal::IllegalTransition
    );

    let ticket = ReferenceTicket {
        generation: 7,
        ownership: ReferenceOwnership::Caller,
        cleanup_plan_digest: "sha256:bb".to_owned(),
        frame_bytes: Vec::new(),
    };
    assert_eq!(
        guard.admit(&ticket).unwrap_err(),
        CarrierRefusal::ReplayMismatch
    );
}

#[test]
fn the_admission_guard_admits_a_canonical_ticket() {
    let guard = ReferenceAdmission::new(plan(), 7, "sha256:aa").expect("nonzero generation");
    let ticket = ReferenceTicket {
        generation: 7,
        ownership: ReferenceOwnership::Caller,
        cleanup_plan_digest: "sha256:aa".to_owned(),
        frame_bytes: encode_canonical(&plan(), &payloads()).expect("paired payloads"),
    };
    let leaves = guard
        .admit(&ticket)
        .expect("a canonical ticket is admitted");
    assert_eq!(leaves.len(), 2);
}
