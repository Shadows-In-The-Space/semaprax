//! Bounded, deterministic property/fuzz coverage for the Descriptor v1
//! reference codec (issue #173, implementation-sequence item 7). See
//! [`crate::public_generic_abi::fuzz_support`] for why this is a hand-rolled
//! fixed-seed mutation engine rather than a `proptest`/`quickcheck`
//! dependency, and for the hard bounds it enforces (a fixed trial count, a
//! bounded point-mutation count, a bounded length delta) -- this is
//! deliberately bounded fuzzing, not the "unbounded fuzzing" #173 excludes.
//!
//! The property under test: independent replay against a trusted
//! descriptor never accepts a mutated byte string unless that mutation
//! left the identity digest unchanged (the one documented exception --
//! `tests::a_display_rename_changes_wire_bytes_but_not_identity` -- a
//! presentation-only `export_name` edit). Every other outcome must be one
//! of the four closed, already-catalogued stable diagnostic codes this
//! module defines, and `decode`/`replay` must never panic on adversarial
//! bytes. A trial that violates either property has its exact input bytes
//! rendered as a pasteable literal in the failure message -- issue #173's
//! "persist minimized reproductions for any discovered distinct invariant".

use super::*;
use crate::public_generic_abi::fuzz_support::{minimized_repro_literal, mutate, TRIALS};

fn baseline() -> DescriptorV1 {
    DescriptorV1::new(
        "issue173.fuzz.export",
        "fuzz_export",
        format!("sha256:{}", "1".repeat(64)),
        format!("sha256:{}", "2".repeat(64)),
        format!("sha256:{}", "3".repeat(64)),
        InstanceBinding {
            term: "@13:issue173.pair<bytes,bool>".to_owned(),
            instance_digest: format!("sha256:{}", "4".repeat(64)),
        },
        InstanceBinding {
            term: "@13:issue173.pair<bytes,i64>".to_owned(),
            instance_digest: format!("sha256:{}", "5".repeat(64)),
        },
    )
}

/// The closed set of stable diagnostic codes `replay` may ever return for
/// descriptor bytes (`decode` returns a subset of the same two). Any other
/// code is a distinct, previously uncatalogued invariant violation.
const CLOSED_CODES: &[&str] = &[
    MALFORMED_DESCRIPTOR,
    DESCRIPTOR_CAPACITY,
    DESCRIPTOR_REPLAY_MISMATCH,
    DESCRIPTOR_VERSION_MISMATCH,
];

#[test]
fn bounded_mutation_replay_always_fails_closed_or_preserves_identity() {
    let trusted = baseline();
    let trusted_bytes = trusted.encode();
    let mut findings = Vec::new();

    for trial in 0..TRIALS {
        let candidate = mutate(&trusted_bytes, trial);
        let candidate_ref = &candidate;
        let trusted_ref = &trusted;
        let outcome = std::panic::catch_unwind(move || replay(candidate_ref, trusted_ref));
        match outcome {
            Err(_) => findings.push(format!(
                "trial {trial}: replay panicked on {}",
                minimized_repro_literal(&candidate)
            )),
            Ok(Ok(value)) => {
                if candidate != trusted_bytes
                    && value.identity_digest() != trusted.identity_digest()
                {
                    findings.push(format!(
                        "trial {trial}: replay ACCEPTED a non-identity-preserving mutation {}",
                        minimized_repro_literal(&candidate)
                    ));
                }
            }
            Ok(Err(error)) => {
                if !CLOSED_CODES.contains(&error.code) {
                    findings.push(format!(
                        "trial {trial}: replay refused with an undocumented code {:?} on {}",
                        error.code,
                        minimized_repro_literal(&candidate)
                    ));
                }
            }
        }
    }

    assert!(
        findings.is_empty(),
        "bounded descriptor mutation fuzz found {} distinct invariant violation(s) in {TRIALS} trials, minimized reproductions:\n{}",
        findings.len(),
        findings.join("\n")
    );
}

/// Same property, but for the standalone `decode` entry point (no trusted
/// counterpart): it must never panic and must never return a code outside
/// the two it documents.
#[test]
fn bounded_mutation_decode_never_panics_and_stays_within_its_documented_codes() {
    let trusted_bytes = baseline().encode();
    let mut findings = Vec::new();

    for trial in 0..TRIALS {
        let candidate = mutate(&trusted_bytes, trial);
        let candidate_ref = &candidate;
        let outcome = std::panic::catch_unwind(move || decode(candidate_ref));
        match outcome {
            Err(_) => findings.push(format!(
                "trial {trial}: decode panicked on {}",
                minimized_repro_literal(&candidate)
            )),
            Ok(Err(error))
                if error.code != MALFORMED_DESCRIPTOR && error.code != DESCRIPTOR_CAPACITY =>
            {
                findings.push(format!(
                    "trial {trial}: decode refused with an undocumented code {:?} on {}",
                    error.code,
                    minimized_repro_literal(&candidate)
                ));
            }
            Ok(_) => {}
        }
    }

    assert!(
        findings.is_empty(),
        "bounded descriptor mutation fuzz found {} distinct invariant violation(s) in {TRIALS} trials, minimized reproductions:\n{}",
        findings.len(),
        findings.join("\n")
    );
}
