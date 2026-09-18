//! Cases for Package Registry Federation v1. Every refusal test asserts the
//! exact diagnostic code, and every refusal that could plausibly be caused by
//! its fixture rather than by the rule under test carries a control proving
//! the same fixture is admitted on its own.
//!
//! Fixture note: as the parent module's tests explain, a valid Subject-v3
//! fixture must carry one of the exact package identities embedded in the
//! `examples/*.spx` Report-v2 it replays, and only `examples.meaning` and
//! `examples.calculator` have fixtures that replay cleanly. Both sit under
//! the `examples` namespace, which is precisely why the claim table matches
//! *dotted prefixes* rather than only top-level segments: the two-registry
//! fixtures below claim `examples.meaning` and `examples.calculator`
//! separately, and `a_whole_namespace_claim_covers_every_package_under_it`
//! covers the one-segment case on its own.

use super::super::tests::{calculator_entry, meaning_entry, yanked, CALCULATOR, MEANING};
use super::*;

const ALPHA: &str = "alpha.registry";
const BETA: &str = "beta.registry";

fn registry(registry_id: &str, entries: &[PublishedEntry]) -> FederatedRegistry {
    FederatedRegistry {
        registry_id: registry_id.to_owned(),
        snapshot: super::super::build_snapshot(entries).expect("snapshot fixture"),
    }
}

fn claim(namespace: &str, registry_id: &str) -> NamespaceClaim {
    NamespaceClaim {
        namespace: namespace.to_owned(),
        registry_id: registry_id.to_owned(),
    }
}

/// The standard two-registry fixture: `alpha.registry` owns
/// `examples.meaning`, `beta.registry` owns `examples.calculator`.
fn two_registries() -> (Vec<FederatedRegistry>, Vec<NamespaceClaim>) {
    let registries = vec![
        registry(ALPHA, &[meaning_entry("1.0.0", "alpha")]),
        registry(BETA, &[calculator_entry("2.0.0", "beta")]),
    ];
    let claims = vec![claim(MEANING, ALPHA), claim(CALCULATOR, BETA)];
    (registries, claims)
}

// --- Determinism -------------------------------------------------------------

#[test]
fn the_standard_two_registry_fixture_is_admitted() {
    let (registries, claims) = two_registries();
    let federation = build_federation(&registries, &claims).expect("build");
    assert_eq!(
        federation.coordinates(),
        vec![
            FederatedCoordinate {
                registry_id: BETA.to_owned(),
                package: CALCULATOR.to_owned(),
                version: "2.0.0".to_owned(),
            },
            FederatedCoordinate {
                registry_id: ALPHA.to_owned(),
                package: MEANING.to_owned(),
                version: "1.0.0".to_owned(),
            },
        ],
        "coordinates are ordered globally by (package, version), not by registry"
    );
}

#[test]
fn a_whole_namespace_claim_covers_every_package_under_it() {
    // One single-segment claim, one registry, both packages: the prefix rule
    // is what a real registry namespace looks like, and the per-package
    // claims elsewhere in this file are the narrow end of the same rule.
    let only = registry(
        ALPHA,
        &[
            meaning_entry("1.0.0", "alpha"),
            calculator_entry("2.0.0", "alpha"),
        ],
    );
    let federation =
        build_federation(&[only], &[claim("examples", ALPHA)]).expect("whole-namespace claim");
    assert_eq!(federation.coordinates().len(), 2);
}

#[test]
fn a_sibling_namespace_with_a_shared_text_prefix_is_not_covered() {
    // `example` is a text prefix of `examples.meaning` but not a segment
    // prefix, so it must not authorize it -- otherwise a squatter could claim
    // `example` and quietly cover the whole `examples` namespace.
    let only = registry(ALPHA, &[meaning_entry("1.0.0", "alpha")]);
    assert_eq!(
        build_federation(&[only], &[claim("example", ALPHA)])
            .unwrap_err()
            .code,
        "SPX-PKR612"
    );
}

#[test]
fn same_inputs_produce_byte_identical_federations_every_time() {
    let (registries, claims) = two_registries();
    let first = build_federation(&registries, &claims).expect("first build");
    let second = build_federation(&registries, &claims).expect("second build");
    assert_eq!(first.envelope(), second.envelope());
    assert_eq!(first.digest(), second.digest());
}

#[test]
fn registry_and_claim_order_do_not_affect_canonical_bytes() {
    let (registries, claims) = two_registries();
    let forward = build_federation(&registries, &claims).expect("forward build");
    let mut reversed_registries = registries;
    reversed_registries.reverse();
    let mut reversed_claims = claims;
    reversed_claims.reverse();
    let reversed =
        build_federation(&reversed_registries, &reversed_claims).expect("reversed build");
    assert_eq!(forward.envelope(), reversed.envelope());
    assert_eq!(forward.digest(), reversed.digest());
}

#[test]
fn a_changed_snapshot_changes_the_federation_digest() {
    let (registries, claims) = two_registries();
    let baseline = build_federation(&registries, &claims).expect("baseline build");
    // Swap `beta.registry`'s snapshot for one holding a different version of
    // the same package: nothing about the federation's own fields changes,
    // only the bound snapshot digest.
    let changed_registries = vec![
        registries[0].clone(),
        registry(BETA, &[calculator_entry("2.0.1", "beta")]),
    ];
    let changed = build_federation(&changed_registries, &claims).expect("changed build");
    assert_ne!(baseline.digest(), changed.digest());
    assert_ne!(baseline.envelope(), changed.envelope());
}

#[test]
fn a_changed_namespace_claim_changes_the_federation_digest() {
    let (registries, claims) = two_registries();
    let baseline = build_federation(&registries, &claims).expect("baseline build");
    // An extra claim covering nothing served here is admitted and must still
    // change the bytes: the claim table is part of the evidence, not an
    // out-of-band hint.
    let mut extended = claims;
    extended.push(claim("unused", BETA));
    let changed = build_federation(&registries, &extended).expect("changed build");
    assert_ne!(baseline.digest(), changed.digest());
}

/// The canonical bytes, pinned field for field. The snapshot and content
/// digests are interpolated from the already-digest-bound snapshot layer
/// rather than hardcoded: this golden pins *this format's* own rendering --
/// field names, field order, separators, counts, nesting -- which is what a
/// downstream decoder depends on, and stays honest if an `examples/*.spx`
/// fixture is edited.
#[test]
fn the_canonical_envelope_is_pinned_field_for_field() {
    let (registries, claims) = two_registries();
    let federation = build_federation(&registries, &claims).expect("build");
    let content = |package: &str| -> String {
        federation
            .packages
            .iter()
            .find(|((name, _), _)| name == package)
            .map(|(_, (_, entry))| entry.content_digest.clone())
            .unwrap_or_else(|| panic!("{package} is in the federation"))
    };
    let payload = format!(
        concat!(
            "{{\"schema\":\"semaprax.package-registry-federation.v1\",",
            "\"registry_count\":2,\"namespace_count\":2,\"package_count\":2,",
            "\"registries\":[",
            "{{\"registry_id\":\"alpha.registry\",\"snapshot_digest\":\"{alpha}\"}},",
            "{{\"registry_id\":\"beta.registry\",\"snapshot_digest\":\"{beta}\"}}],",
            "\"namespaces\":[",
            "{{\"namespace\":\"examples.calculator\",\"registry_id\":\"beta.registry\"}},",
            "{{\"namespace\":\"examples.meaning\",\"registry_id\":\"alpha.registry\"}}],",
            "\"packages\":[",
            "{{\"package\":\"examples.calculator\",\"version\":\"2.0.0\",",
            "\"registry_id\":\"beta.registry\",\"content_digest\":\"{calculator}\",",
            "\"status\":{{\"state\":\"active\"}}}},",
            "{{\"package\":\"examples.meaning\",\"version\":\"1.0.0\",",
            "\"registry_id\":\"alpha.registry\",\"content_digest\":\"{meaning}\",",
            "\"status\":{{\"state\":\"active\"}}}}]}}"
        ),
        alpha = registries[0].snapshot.digest(),
        beta = registries[1].snapshot.digest(),
        calculator = content(CALCULATOR),
        meaning = content(MEANING),
    );
    let expected = format!(
        "{{\"schema\":\"semaprax.package-registry-federation.v1\",\"digest\":\"{}\",\"bytes\":{},\"payload\":{payload}}}",
        federation.digest(),
        payload.len(),
    );
    assert_eq!(federation.envelope(), expected);
}

#[test]
fn verify_federation_round_trips_exactly() {
    let (registries, claims) = two_registries();
    let federation = build_federation(&registries, &claims).expect("build");
    let verified = verify_federation(federation.envelope(), &registries, &claims).expect("verify");
    assert_eq!(verified.digest, federation.digest());
    assert_eq!(verified.coordinates, federation.coordinates());
}

#[test]
fn verify_federation_refuses_a_single_tampered_byte() {
    let (registries, claims) = two_registries();
    let federation = build_federation(&registries, &claims).expect("build");
    let marker = "\"digest\":\"sha256:";
    let position = federation.envelope().find(marker).unwrap() + marker.len();
    let mut bytes = federation.envelope().as_bytes().to_vec();
    bytes[position] = if bytes[position] == b'0' { b'1' } else { b'0' };
    let tampered = String::from_utf8(bytes).expect("ASCII hex digit swap stays valid UTF-8");
    assert_eq!(
        verify_federation(&tampered, &registries, &claims)
            .unwrap_err()
            .code,
        "SPX-PKR608"
    );
}

#[test]
fn verify_federation_refuses_a_substituted_snapshot_under_the_same_registry_id() {
    let (registries, claims) = two_registries();
    let federation = build_federation(&registries, &claims).expect("build");
    // Control: the evidence genuinely replays its own inputs first, so the
    // refusal below is about the substitution, not a malformed baseline.
    assert!(verify_federation(federation.envelope(), &registries, &claims).is_ok());
    let substituted = vec![
        registries[0].clone(),
        registry(BETA, &[calculator_entry("9.9.9", "beta")]),
    ];
    assert_eq!(
        verify_federation(federation.envelope(), &substituted, &claims)
            .unwrap_err()
            .code,
        "SPX-PKR608"
    );
}

// --- Cross-registry dependency confusion -------------------------------------

#[test]
fn the_same_package_name_served_by_two_registries_is_refused() {
    // Controls: each registry alone federates cleanly, so the refusal below
    // is caused by the two of them together, not by either snapshot.
    let alpha = registry(ALPHA, &[meaning_entry("1.0.0", "alpha")]);
    let beta = registry(BETA, &[meaning_entry("2.0.0", "beta")]);
    assert!(build_federation(std::slice::from_ref(&alpha), &[claim(MEANING, ALPHA)]).is_ok());
    assert!(build_federation(std::slice::from_ref(&beta), &[claim(MEANING, BETA)]).is_ok());
    let error = build_federation(&[alpha, beta], &[claim(MEANING, ALPHA)]).unwrap_err();
    assert_eq!(error.code, "SPX-PKR611");
    assert!(
        error.message.contains(MEANING),
        "the refusal must name the confused package: {}",
        error.message
    );
}

#[test]
fn dependency_confusion_is_refused_regardless_of_registry_order() {
    let alpha = registry(ALPHA, &[meaning_entry("1.0.0", "alpha")]);
    let beta = registry(BETA, &[meaning_entry("2.0.0", "beta")]);
    let claims = [claim(MEANING, ALPHA)];
    let forward = build_federation(&[alpha.clone(), beta.clone()], &claims).unwrap_err();
    let reversed = build_federation(&[beta, alpha], &claims).unwrap_err();
    assert_eq!(forward.code, "SPX-PKR611");
    assert_eq!(
        forward.message, reversed.message,
        "which registry is reported as the owner must depend on content, not argument order"
    );
}

#[test]
fn confusion_is_refused_even_when_the_squatting_registry_serves_a_different_version() {
    // The attack does not require colliding on an exact version: owning the
    // *name* anywhere else in the federation is already enough to make
    // resolution ambiguous.
    let alpha = registry(ALPHA, &[calculator_entry("2.0.0", "alpha")]);
    let beta = registry(BETA, &[calculator_entry("99.0.0", "squatter")]);
    assert_eq!(
        build_federation(&[alpha, beta], &[claim(CALCULATOR, ALPHA)])
            .unwrap_err()
            .code,
        "SPX-PKR611"
    );
}

// --- Namespace authority -----------------------------------------------------

#[test]
fn a_served_package_no_claim_covers_is_refused() {
    let (registries, _claims) = two_registries();
    // `examples.calculator` is deliberately left unclaimed.
    let error = build_federation(&registries, &[claim(MEANING, ALPHA)]).unwrap_err();
    assert_eq!(error.code, "SPX-PKR612");
    assert!(
        error.message.contains(CALCULATOR),
        "the refusal must name the unauthorized package: {}",
        error.message
    );
}

#[test]
fn a_package_claimed_by_one_registry_but_served_by_another_is_refused() {
    let (registries, _claims) = two_registries();
    // Both claims point at `alpha.registry`, but `examples.calculator` is
    // served by `beta.registry`.
    let error = build_federation(
        &registries,
        &[claim(MEANING, ALPHA), claim(CALCULATOR, ALPHA)],
    )
    .unwrap_err();
    assert_eq!(error.code, "SPX-PKR612");
    assert!(
        error.message.contains(CALCULATOR),
        "the refusal must name the misrouted package: {}",
        error.message
    );
}

#[test]
fn overlapping_claims_are_refused_rather_than_ranked_by_longest_match() {
    // `examples` and `examples.meaning` both cover `examples.meaning`. A
    // longest-match rule would silently pick one; this format refuses,
    // because a silent tie-break between two claims over one package name is
    // exactly the ambiguity dependency confusion exploits.
    let (registries, claims) = two_registries();
    // Control: the unoverlapped table is admitted.
    assert!(build_federation(&registries, &claims).is_ok());
    let mut overlapping = claims;
    overlapping.push(claim("examples", ALPHA));
    let error = build_federation(&registries, &overlapping).unwrap_err();
    assert_eq!(error.code, "SPX-PKR612");
    assert!(
        error.message.contains("more than one namespace claim"),
        "the refusal must say the claims overlap: {}",
        error.message
    );
}

#[test]
fn a_claim_naming_a_registry_outside_the_federation_is_refused() {
    let (registries, mut claims) = two_registries();
    claims.push(claim("other", "absent.registry"));
    assert_eq!(
        build_federation(&registries, &claims).unwrap_err().code,
        "SPX-PKR612"
    );
}

#[test]
fn two_claims_for_one_namespace_are_refused() {
    let (registries, claims) = two_registries();
    // Control: the unduplicated table is admitted.
    assert!(build_federation(&registries, &claims).is_ok());
    let mut duplicated = claims;
    duplicated.push(claim(MEANING, BETA));
    assert_eq!(
        build_federation(&registries, &duplicated).unwrap_err().code,
        "SPX-PKR612"
    );
}

#[test]
fn an_identical_duplicate_claim_for_one_namespace_is_also_refused() {
    // Even a harmless-looking exact duplicate is refused: "exactly one
    // claim" is checked structurally, not by comparing targets, so a table
    // cannot grow ambiguous entries that happen to agree today.
    let (registries, claims) = two_registries();
    let mut duplicated = claims;
    duplicated.push(claim(MEANING, ALPHA));
    assert_eq!(
        build_federation(&registries, &duplicated).unwrap_err().code,
        "SPX-PKR612"
    );
}

#[test]
fn a_namespace_claim_with_an_empty_segment_is_refused_as_a_shape_violation() {
    let (registries, _claims) = two_registries();
    assert_eq!(
        build_federation(
            &registries,
            &[claim("examples.", ALPHA), claim(CALCULATOR, BETA)]
        )
        .unwrap_err()
        .code,
        "SPX-PKR601"
    );
}

// --- Registry-set well-formedness --------------------------------------------

#[test]
fn one_registry_id_bound_to_two_different_snapshots_is_refused() {
    let first = registry(ALPHA, &[meaning_entry("1.0.0", "alpha")]);
    let second = registry(ALPHA, &[calculator_entry("2.0.0", "alpha")]);
    assert_eq!(
        build_federation(&[first, second], &[claim("examples", ALPHA)])
            .unwrap_err()
            .code,
        "SPX-PKR604"
    );
}

#[test]
fn one_registry_id_listed_twice_with_the_same_snapshot_is_refused_as_duplicate() {
    let only = registry(ALPHA, &[meaning_entry("1.0.0", "alpha")]);
    assert!(build_federation(std::slice::from_ref(&only), &[claim(MEANING, ALPHA)]).is_ok());
    assert_eq!(
        build_federation(&[only.clone(), only], &[claim(MEANING, ALPHA)])
            .unwrap_err()
            .code,
        "SPX-PKR605"
    );
}

#[test]
fn an_empty_registry_set_is_refused() {
    assert_eq!(
        build_federation(&[], &[claim(MEANING, ALPHA)])
            .unwrap_err()
            .code,
        "SPX-PKR606"
    );
}

#[test]
fn a_registry_id_with_a_control_byte_is_refused() {
    let mut hostile = registry(ALPHA, &[meaning_entry("1.0.0", "alpha")]);
    hostile.registry_id = "alpha\u{0}registry".to_owned();
    assert_eq!(
        build_federation(&[hostile], &[claim(MEANING, ALPHA)])
            .unwrap_err()
            .code,
        "SPX-PKR601"
    );
}

#[test]
fn an_uppercase_registry_id_is_refused() {
    let mut hostile = registry(ALPHA, &[meaning_entry("1.0.0", "alpha")]);
    hostile.registry_id = "Alpha.Registry".to_owned();
    assert_eq!(
        build_federation(&[hostile], &[claim(MEANING, ALPHA)])
            .unwrap_err()
            .code,
        "SPX-PKR601"
    );
}

// --- Revocation and resolver composition -------------------------------------

#[test]
fn a_yanked_entry_follows_the_single_registry_policy_across_the_federation() {
    let registries = vec![
        registry(ALPHA, &[meaning_entry("1.0.0", "alpha")]),
        registry(
            BETA,
            &[yanked(calculator_entry("2.0.0", "beta"), "withdrawn")],
        ),
    ];
    let claims = [claim(MEANING, ALPHA), claim(CALCULATOR, BETA)];
    let federation = build_federation(&registries, &claims).expect("build");

    let excluded =
        project_federated_subjects(&federation, YankPolicy::ExcludeYanked).expect("exclude policy");
    assert_eq!(excluded.subjects.len(), 1);
    assert!(excluded.warnings.is_empty());

    assert_eq!(
        project_federated_subjects(&federation, YankPolicy::RefuseIfYanked)
            .unwrap_err()
            .code,
        "SPX-PKR610"
    );

    let warned = project_federated_subjects(&federation, YankPolicy::AllowYankedWithWarning)
        .expect("warn policy");
    assert_eq!(warned.subjects.len(), 2);
    assert_eq!(warned.warnings.len(), 1);
    assert_eq!(warned.warnings[0].code, "SPX-PKR609");
}

#[test]
fn a_yank_never_removes_an_entry_from_the_federation_evidence() {
    // Reproducibility: the yanked coordinate stays in the digest-bound
    // bytes, so a later yank cannot silently rewrite an already-resolved
    // federation -- only the projection policy changes.
    let registries = vec![
        registry(
            ALPHA,
            &[yanked(meaning_entry("1.0.0", "alpha"), "withdrawn")],
        ),
        registry(BETA, &[calculator_entry("2.0.0", "beta")]),
    ];
    let federation = build_federation(
        &registries,
        &[claim(MEANING, ALPHA), claim(CALCULATOR, BETA)],
    )
    .expect("build");
    assert!(federation.envelope().contains("\"state\":\"yanked\""));
    assert!(federation
        .coordinates()
        .iter()
        .any(|coordinate| coordinate.package == MEANING));
}

#[test]
fn federated_subjects_resolve_deterministically_through_package_resolver_v2() {
    let (registries, claims) = two_registries();
    let federation = build_federation(&registries, &claims).expect("build");
    let catalog =
        project_federated_subjects(&federation, YankPolicy::ExcludeYanked).expect("projection");
    let input = crate::package_resolver_v2::ResolutionInput {
        requirements: vec![crate::package_resolver_v2::Requirement {
            package: MEANING.to_owned(),
            range: "^1.0.0".to_owned(),
        }],
        subjects: catalog.subjects,
        target: "native64".to_owned(),
        allowed_capabilities: vec![],
    };
    let options = crate::package_resolver_v2::ResolutionOptions::default();
    let first = crate::package_resolver_v2::generate(&input, &options).expect("first resolve");
    let second = crate::package_resolver_v2::generate(&input, &options).expect("second resolve");
    assert_eq!(
        first, second,
        "a federated catalog must resolve byte-identically on repeat"
    );
    let verified = crate::package_resolver_v2::verify(&first, &input, &options)
        .expect("resolver-v2 must independently replay the federation-projected catalog");
    assert_eq!(
        verified.packages,
        vec![crate::package_lock_v3::Coordinate {
            package: MEANING.to_owned(),
            version: "1.0.0".to_owned(),
        }]
    );
}

// --- Nonclaims ---------------------------------------------------------------

/// The determinism and no-ambient-authority arguments are structural, not
/// merely "it passed twice": this greps the module's own source for exactly
/// the constructs the docstring claims are absent. If someone later reaches
/// for a `HashMap`, the clock, the environment, or the filesystem here, this
/// fails rather than the claim quietly becoming false.
#[test]
fn federation_source_contains_no_ambient_authority_or_unordered_iteration() {
    // Matched as real Rust syntax (`<`/`::`), not the bare word, so this does
    // not trip over the module docstring's own prose describing the property.
    let source = include_str!("../federation.rs");
    for forbidden in [
        "HashMap<",
        "HashMap::",
        "HashSet<",
        "HashSet::",
        "SystemTime::now",
        "Instant::now",
        "std::env::",
        "std::fs::",
        "read_dir(",
        "TcpStream",
    ] {
        assert!(
            !source.contains(forbidden),
            "federation.rs must not contain `{forbidden}`, which would make canonical bytes \
             depend on something other than the supplied registries and claims"
        );
    }
}

/// The signed half of issue #195 is `HUMAN_BLOCKED` (#168). This layer adds
/// no cryptography: it never reads `signature` at all, so a federation of
/// snapshots carrying obviously forged signatures is accepted exactly as
/// readily as any other. Pinned as an executable assertion so that the day
/// real verification lands, this fails and forces the claim to be updated.
#[test]
fn signatures_are_never_examined_by_the_federation_layer() {
    let mut forged = meaning_entry("1.0.0", "alpha");
    forged.signature.identity = "totally-unverified-identity".to_owned();
    forged.signature.signature = "not-a-signature".to_owned();
    forged.signature.algorithm = "no-such-algorithm".to_owned();
    let federation = build_federation(&[registry(ALPHA, &[forged])], &[claim(MEANING, ALPHA)])
        .expect("a forged signature is not rejected by this layer");
    assert!(
        !federation.envelope().contains("signature"),
        "the federation envelope has no signature field at all"
    );
}
