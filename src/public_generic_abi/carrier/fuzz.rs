//! Bounded, deterministic property/fuzz coverage for the `CarrierBindingV1`
//! reference codec (issue #173, implementation-sequence item 7). See
//! [`crate::public_generic_abi::fuzz_support`] for the shared mutation
//! engine and its hard, named bounds.
//!
//! Unlike `DescriptorV1`, a `CarrierBindingV1` carries no presentation-only
//! field: `encode()` and its identity preimage are the same bytes (see
//! `CarrierBindingV1::encode`'s own doc comment), so the property here is
//! strictly simpler than the descriptor's -- `replay_binding` may only ever
//! accept a candidate that is byte-identical to the trusted encoding. Any
//! other acceptance is a forged-binding invariant violation, and any
//! refusal outside the two catalogued codes is an uncatalogued one. Either
//! is reported with the exact input bytes as a pasteable literal -- #173's
//! "persist minimized reproductions for any discovered distinct invariant".

use super::*;
use crate::public_generic_abi::fuzz_support::{minimized_repro_literal, mutate, TRIALS};

fn baseline() -> CarrierBindingV1 {
    CarrierBindingV1::new(
        format!("sha256:{}", "6".repeat(64)),
        TargetProfile::NativeC11,
        "runtime:issue173-fuzz-native-c11",
    )
}

const CLOSED_CODES: &[&str] = &[MALFORMED_CARRIER, CARRIER_CAPACITY, CARRIER_REPLAY_MISMATCH];

#[test]
fn bounded_mutation_replay_binding_never_accepts_a_non_identical_candidate() {
    let trusted = baseline();
    let trusted_bytes = trusted.encode();
    let mut findings = Vec::new();

    for trial in 0..TRIALS {
        let candidate = mutate(&trusted_bytes, trial);
        let candidate_ref = &candidate;
        let trusted_ref = &trusted;
        let outcome = std::panic::catch_unwind(move || replay_binding(candidate_ref, trusted_ref));
        match outcome {
            Err(_) => findings.push(format!(
                "trial {trial}: replay_binding panicked on {}",
                minimized_repro_literal(&candidate)
            )),
            Ok(Ok(_)) => {
                if candidate != trusted_bytes {
                    findings.push(format!(
                        "trial {trial}: replay_binding ACCEPTED a non-identical mutation {}",
                        minimized_repro_literal(&candidate)
                    ));
                }
            }
            Ok(Err(error)) => {
                if !CLOSED_CODES.contains(&error.code) {
                    findings.push(format!(
                        "trial {trial}: replay_binding refused with an undocumented code {:?} on {}",
                        error.code,
                        minimized_repro_literal(&candidate)
                    ));
                }
            }
        }
    }

    assert!(
        findings.is_empty(),
        "bounded carrier-binding mutation fuzz found {} distinct invariant violation(s) in {TRIALS} trials, minimized reproductions:\n{}",
        findings.len(),
        findings.join("\n")
    );
}

#[test]
fn bounded_mutation_decode_binding_never_panics_and_stays_within_its_documented_codes() {
    let trusted_bytes = baseline().encode();
    let mut findings = Vec::new();

    for trial in 0..TRIALS {
        let candidate = mutate(&trusted_bytes, trial);
        let candidate_ref = &candidate;
        let outcome = std::panic::catch_unwind(move || decode_binding(candidate_ref));
        match outcome {
            Err(_) => findings.push(format!(
                "trial {trial}: decode_binding panicked on {}",
                minimized_repro_literal(&candidate)
            )),
            Ok(Err(error)) if error.code != MALFORMED_CARRIER && error.code != CARRIER_CAPACITY => {
                findings.push(format!(
                    "trial {trial}: decode_binding refused with an undocumented code {:?} on {}",
                    error.code,
                    minimized_repro_literal(&candidate)
                ));
            }
            Ok(_) => {}
        }
    }

    assert!(
        findings.is_empty(),
        "bounded carrier-binding mutation fuzz found {} distinct invariant violation(s) in {TRIALS} trials, minimized reproductions:\n{}",
        findings.len(),
        findings.join("\n")
    );
}
