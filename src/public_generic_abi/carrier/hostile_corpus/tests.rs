//! Issue #173: the executable half of [Hostile Carrier Corpus
//! v1](../../../../docs/PUBLIC-GENERIC-CARRIER-HOSTILE-CORPUS-V1.md).
//!
//! Every case is driven through two implementations that share no code —
//! the production codec ([`parse_bounded`] plus
//! [`CarrierFrameBinding::validate_frame`]) and the
//! [independent reference decoder](super::super::reference_decoder) — and
//! both must publish the same closed public class. A defect a self-checking
//! corpus would mirror shows up here as disagreement.
//!
//! The manifest itself is pinned twice: once per case, by the SHA-256 of
//! the produced document, and once for the whole corpus. A regenerated
//! corpus that drifts fails a known answer instead of quietly covering less.

use std::collections::{BTreeMap, BTreeSet};

use sha2::{Digest as _, Sha256};

use super::*;
use crate::public_generic_abi::carrier::frame::{parse_bounded, CarrierFrameBinding};
use crate::public_generic_abi::carrier::reference_decoder::CarrierRefusal;

fn sha256(bytes: &[u8]) -> String {
    format!(
        "sha256:{:x}",
        crate::digest_hex::LowerHex(Sha256::digest(bytes))
    )
}

/// The production-side trusted binding for the fixture plan. Built through
/// the public [`CarrierFrameBinding::new`] constructor so it derives its own
/// inventory identity rather than borrowing the reference decoder's.
fn production_binding() -> CarrierFrameBinding {
    let plan = fixture_plan();
    CarrierFrameBinding::new(
        Direction::Input,
        plan.descriptor_digest(),
        plan.endpoint_identity_digest(),
        plan.instance_identity_digest(),
        plan.leaf_paths().to_vec(),
    )
}

/// The production reader's closed class for one document: structural
/// admission followed by semantic binding, exactly as
/// `NativeInputAdmission::admit` composes them.
fn production_document_class(bytes: &[u8]) -> Result<usize, CarrierRefusal> {
    let binding = production_binding();
    let frame = parse_bounded(bytes).map_err(|error| {
        CarrierRefusal::from_code(&error.code).unwrap_or_else(|| {
            panic!(
                "the production codec refused with {}, which is outside the closed carrier class",
                error.code
            )
        })
    })?;
    binding.validate_frame(&frame).map_err(|error| {
        CarrierRefusal::from_code(&error.code).unwrap_or_else(|| {
            panic!(
                "the production binding refused with {}, which is outside the closed carrier class",
                error.code
            )
        })
    })?;
    Ok(frame.leaves().len())
}

/// Whether a case's hostility lives in the admission envelope rather than in
/// the document bytes.
fn is_envelope_case(case: &CarrierHostileCase) -> bool {
    !matches!(case.ticket, TicketMutation::None)
}

#[test]
fn the_case_count_is_closed_and_every_identity_is_unique() {
    let cases = cases();
    assert_eq!(
        cases.len(),
        CARRIER_HOSTILE_CORPUS_CASE_COUNT,
        "the published case count must match the manifest"
    );

    let mut ids = BTreeSet::new();
    for case in &cases {
        assert!(
            ids.insert(case.id),
            "{}: a case identity appears twice",
            case.id
        );
    }

    // Document uniqueness is asserted over the document cases only. The
    // envelope cases deliberately share the canonical document -- that is
    // exactly what makes them discriminating -- so they are asserted to
    // carry it rather than to differ from it.
    let canonical = canonical_document();
    let mut documents: BTreeMap<String, &str> = BTreeMap::new();
    for case in &cases {
        if is_envelope_case(case) {
            assert_eq!(
                case.document(),
                canonical,
                "{}: an envelope case must submit the canonical document, so \
                 that only its envelope can be refused",
                case.id
            );
            continue;
        }
        let digest = sha256(&case.document());
        if let Some(previous) = documents.insert(digest, case.id) {
            panic!(
                "{} and {} produce byte-identical documents; a corpus entry \
                 that duplicates another proves nothing new",
                previous, case.id
            );
        }
    }
    assert_eq!(
        documents.len() + cases.iter().filter(|case| is_envelope_case(case)).count(),
        cases.len()
    );
}

#[test]
fn every_hostile_document_or_envelope_differs_from_the_canonical_fixture() {
    let canonical = canonical_document();
    for case in cases() {
        if matches!(case.expected, Expected::Admitted) {
            continue;
        }
        let differs = case.document() != canonical || is_envelope_case(&case);
        assert!(
            differs,
            "{}: a hostile case must differ from the canonical fixture in its \
             document, its envelope, or both",
            case.id
        );
    }
}

#[test]
fn every_case_document_is_pinned_by_its_recorded_digest() {
    let mut drift = Vec::new();
    for case in cases() {
        let actual = sha256(&case.document());
        if actual != case.bytes_sha256 {
            drift.push(format!(
                "{}\texpected {}\tactual {}",
                case.id, case.bytes_sha256, actual
            ));
        }
    }
    assert!(
        drift.is_empty(),
        "the recorded mutations no longer produce the pinned documents:\n{}",
        drift.join("\n")
    );
}

#[test]
fn the_versioned_manifest_digest_is_stable() {
    assert_eq!(
        CARRIER_HOSTILE_CORPUS_SCHEMA,
        "semaprax.public-generic-carrier-hostile-corpus.v1"
    );
    assert_eq!(
        sha256(&manifest_payload()),
        CARRIER_HOSTILE_CORPUS_DIGEST,
        "a changed case id, invariant, mutation, expected class or document \
         must deliberately mint a new corpus version or update this known answer"
    );
}

#[test]
fn every_case_meets_its_expectation_in_the_independent_reference_reader() {
    let guard = reference_admission();
    let mut failures = Vec::new();
    for case in cases() {
        let outcome = guard.admit(&case.reference_ticket());
        match (case.expected, outcome) {
            (Expected::Admitted, Ok(_)) => {}
            (Expected::Refused(expected), Err(actual)) if expected == actual => {}
            (expected, actual) => failures.push(format!(
                "{}\t[{}]\texpected {:?}\tactual {:?}",
                case.id,
                case.invariant.describe(),
                expected,
                actual.map(|leaves| leaves.len())
            )),
        }
    }
    assert!(
        failures.is_empty(),
        "the independent reference reader disagreed with the manifest:\n{}",
        failures.join("\n")
    );
}

#[test]
fn the_production_reader_publishes_the_same_closed_class_for_every_document() {
    // The document axis only: the production codec has no envelope, so the
    // five envelope cases are asserted separately below.
    let mut failures = Vec::new();
    for case in cases() {
        if is_envelope_case(&case) {
            continue;
        }
        let production = production_document_class(&case.document());
        match (case.expected, production) {
            (Expected::Admitted, Ok(_)) => {}
            (Expected::Refused(expected), Err(actual)) if expected == actual => {}
            (expected, actual) => failures.push(format!(
                "{}\t[{}]\texpected {:?}\tproduction {:?}",
                case.id,
                case.invariant.describe(),
                expected,
                actual
            )),
        }
    }
    assert!(
        failures.is_empty(),
        "the production reader disagreed with the manifest:\n{}",
        failures.join("\n")
    );
}

#[test]
fn the_two_independent_readers_never_disagree() {
    // The property the whole corpus exists to prove, asserted directly
    // between the two implementations rather than through the manifest, so
    // a manifest that was itself wrong could not hide a divergence.
    let plan = fixture_plan();
    let mut divergences = Vec::new();
    for case in cases() {
        if is_envelope_case(&case) {
            continue;
        }
        let document = case.document();
        let reference = super::super::reference_decoder::decode_and_bind(&document, &plan)
            .map(|leaves| leaves.len());
        let production = production_document_class(&document);
        if reference.is_ok() != production.is_ok() || reference.err() != production.err() {
            divergences.push(format!(
                "{}\treference {:?}\tproduction {:?}",
                case.id,
                super::super::reference_decoder::decode_and_bind(&document, &plan)
                    .map(|leaves| leaves.len()),
                production
            ));
        }
    }
    assert!(
        divergences.is_empty(),
        "two implementations that share no code disagreed:\n{}",
        divergences.join("\n")
    );
}

#[test]
fn an_envelope_case_carries_a_document_both_readers_admit() {
    // This is what makes an envelope case discriminating: the bytes are
    // canonical and admissible, so only the envelope check can refuse the
    // ticket. A reader that authenticates bytes but forgets the envelope
    // admits all five.
    let plan = fixture_plan();
    for case in cases() {
        if !is_envelope_case(&case) {
            continue;
        }
        let document = case.document();
        production_document_class(&document).unwrap_or_else(|refusal| {
            panic!(
                "{}: the production reader refused an envelope case's document with {refusal:?}",
                case.id
            )
        });
        super::super::reference_decoder::decode_and_bind(&document, &plan).unwrap_or_else(
            |refusal| {
                panic!(
                    "{}: the reference reader refused an envelope case's document with {refusal:?}",
                    case.id
                )
            },
        );
        assert!(
            matches!(case.expected, Expected::Refused(_)),
            "{}: an envelope case must be refused by the envelope",
            case.id
        );
    }
}

#[test]
fn the_corpus_covers_every_invariant_in_the_closed_vocabulary() {
    // A corpus that silently stopped covering an invariant would still pass
    // every other test in this file. Enumerate the vocabulary explicitly.
    const VOCABULARY: &[CarrierInvariant] = &[
        CarrierInvariant::CanonicalDocumentIsAdmitted,
        CarrierInvariant::FramingIsComplete,
        CarrierInvariant::NoTrailingBytes,
        CarrierInvariant::SchemaLiteralIsFrozen,
        CarrierInvariant::DirectionLiteralIsClosed,
        CarrierInvariant::TextFieldsAreUtf8,
        CarrierInvariant::LeafKindTagIsAdmitted,
        CarrierInvariant::LeafCountWithinBound,
        CarrierInvariant::TotalPayloadWithinBound,
        CarrierInvariant::LeafPayloadWithinBound,
        CarrierInvariant::WireBytesWithinBound,
        CarrierInvariant::DeclaredTotalMatchesLeaves,
        CarrierInvariant::LeafPathsAreUnique,
        CarrierInvariant::SelfDigestIsConsistent,
        CarrierInvariant::DescriptorIdentityIsBound,
        CarrierInvariant::EndpointIdentityIsRecomputed,
        CarrierInvariant::InstanceIdentityIsBound,
        CarrierInvariant::InventoryIdentityIsRecomputed,
        CarrierInvariant::LeafSequenceMatchesInventory,
        CarrierInvariant::DirectionMatchesPlan,
        CarrierInvariant::GenerationIsLive,
        CarrierInvariant::OwnershipIsCallerHeld,
        CarrierInvariant::CleanupPlanIsBound,
    ];
    let covered: BTreeSet<CarrierInvariant> = cases().iter().map(|case| case.invariant).collect();
    let missing: Vec<&CarrierInvariant> = VOCABULARY
        .iter()
        .filter(|invariant| !covered.contains(invariant))
        .collect();
    assert!(
        missing.is_empty(),
        "these invariants have no case: {missing:?}"
    );
    let unexpected: Vec<&CarrierInvariant> = covered
        .iter()
        .filter(|invariant| !VOCABULARY.contains(invariant))
        .collect();
    assert!(
        unexpected.is_empty(),
        "these invariants are not in the published vocabulary: {unexpected:?}"
    );
    for invariant in VOCABULARY {
        assert!(
            !invariant.describe().is_empty(),
            "{invariant:?} has no description"
        );
    }
}

#[test]
fn the_corpus_retains_positive_controls_in_every_refusal_neighbourhood() {
    // A reader that refuses everything must fail this corpus. Beyond the
    // bare canonical control, each bound has an admitted neighbour exactly
    // at the maximum, so "maximum" and "maximum plus one" are distinguished
    // rather than merely both refused.
    let admitted: Vec<&str> = cases()
        .iter()
        .filter(|case| matches!(case.expected, Expected::Admitted))
        .map(|case| case.id)
        .collect();
    assert_eq!(
        admitted,
        vec![
            "canonical_document_admitted",
            "leaf_payload_at_exact_bound_admitted",
            "trailing_empty_payload_admitted",
        ]
    );
    let guard = reference_admission();
    for case in cases() {
        if matches!(case.expected, Expected::Admitted) {
            let leaves = guard
                .admit(&case.reference_ticket())
                .unwrap_or_else(|refusal| {
                    panic!("{}: refused a control with {refusal:?}", case.id)
                });
            assert_eq!(
                leaves.len(),
                fixture_leaf_paths().len(),
                "{}: a control must expose the whole canonical inventory",
                case.id
            );
        }
    }
}

#[test]
fn the_bound_neighbours_are_exactly_one_apart_and_classify_differently() {
    // Pin the pairing itself, so a future edit cannot quietly drop one half
    // of a maximum / maximum-plus-one pair and leave the other looking like
    // complete boundary coverage.
    let by_id: BTreeMap<&str, CarrierHostileCase> =
        cases().into_iter().map(|case| (case.id, case)).collect();
    for (at_bound, over_bound) in [
        (
            "declared_leaf_count_at_exact_bound",
            "declared_leaf_count_one_over_bound",
        ),
        (
            "declared_total_payload_at_exact_bound",
            "declared_total_payload_one_over_bound",
        ),
        (
            "declared_leaf_payload_at_exact_bound",
            "declared_leaf_payload_one_over_bound",
        ),
        (
            "leaf_payload_at_exact_bound_admitted",
            "leaf_payload_one_byte_over_bound",
        ),
    ] {
        let at = by_id.get(at_bound).expect(at_bound);
        let over = by_id.get(over_bound).expect(over_bound);
        assert_ne!(
            at.expected, over.expected,
            "{at_bound} and {over_bound} must classify differently"
        );
        assert_eq!(
            over.expected,
            Expected::Refused(CarrierRefusal::Capacity),
            "{over_bound} must be refused by the bound itself"
        );
    }
}

#[test]
fn a_reminted_case_is_internally_self_consistent_before_it_is_refused() {
    // The forged-document property, asserted on the cases that claim it: the
    // production codec, which checks structure and the self-digest but no
    // trusted root, *admits* every reminted document outright. Only the
    // trusted-root replay refuses them. If reminting silently stopped
    // working, these cases would still be refused -- for the wrong reason --
    // and every other test here would still pass.
    let reminted: Vec<CarrierHostileCase> = cases()
        .into_iter()
        .filter(|case| matches!(case.remint, Remint::Recompute))
        .collect();
    assert!(
        reminted.len() >= 5,
        "the corpus must keep proving the digest-only failure mode"
    );
    for case in reminted {
        let document = case.document();
        match parse_bounded(&document) {
            Ok(_) => {
                // Structurally perfect; the binding must be what refuses it.
                assert_eq!(
                    production_document_class(&document),
                    Err(CarrierRefusal::ReplayMismatch),
                    "{}: a self-consistent forgery must be refused by the \
                     trusted-root replay, not by structure",
                    case.id
                );
            }
            Err(error) => {
                // The only admissible exception is a case whose named
                // invariant is itself structural, such as a duplicate path.
                assert_eq!(
                    CarrierRefusal::from_code(&error.code),
                    Some(CarrierRefusal::Malformed),
                    "{}: a reminted document may only fail structurally for a \
                     structural invariant",
                    case.id
                );
                assert_eq!(
                    case.invariant,
                    CarrierInvariant::LeafPathsAreUnique,
                    "{}: unexpected structural refusal of a reminted document",
                    case.id
                );
            }
        }
    }
}

#[test]
fn no_admitted_case_exposes_a_leaf_that_was_never_in_the_trusted_inventory() {
    // Admission is not merely "did not refuse": what it exposes must be
    // exactly the trusted inventory, in order.
    let guard = reference_admission();
    let expected = fixture_leaf_paths();
    for case in cases() {
        if let Ok(leaves) = guard.admit(&case.reference_ticket()) {
            let paths: Vec<String> = leaves.into_iter().map(|leaf| leaf.path).collect();
            assert_eq!(paths, expected, "{}", case.id);
        }
    }
}

#[test]
#[ignore = "regeneration aid: prints the pinned digests for this corpus"]
fn print_pinned_digests() {
    for case in cases() {
        println!("{}\t{}", case.id, sha256(&case.document()));
    }
    println!("MANIFEST\t{}", sha256(&manifest_payload()));
}
