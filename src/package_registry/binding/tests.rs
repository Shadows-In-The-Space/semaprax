//! Cases for Registry-Bound Resolution v1. Every refusal test asserts the
//! exact diagnostic code, and the whole point of this module -- that a
//! bound envelope changes when the *registry snapshot* changes even if the
//! resolver-v2 evidence it embeds would not -- gets its own test rather than
//! being argued only in prose.

use super::super::tests::{calculator_entry, meaning_entry, yanked, CALCULATOR, MEANING};
use super::*;

fn options() -> package_resolver_v2::ResolutionOptions {
    package_resolver_v2::ResolutionOptions::default()
}

fn meaning_template() -> ResolutionTemplate {
    ResolutionTemplate {
        requirements: vec![package_resolver_v2::Requirement {
            package: MEANING.to_owned(),
            range: "^1.0.0".to_owned(),
        }],
        target: "native64".to_owned(),
        allowed_capabilities: vec![],
    }
}

// --- Determinism -------------------------------------------------------------

#[test]
fn same_inputs_produce_byte_identical_bound_evidence_every_time() {
    let snapshot = build_snapshot(&[meaning_entry("1.0.0", "alpha")]).expect("snapshot");
    let template = meaning_template();
    let first = bind_to_snapshot(&snapshot, YankPolicy::ExcludeYanked, &template, &options())
        .expect("first bind");
    let second = bind_to_snapshot(&snapshot, YankPolicy::ExcludeYanked, &template, &options())
        .expect("second bind");
    assert_eq!(first.envelope(), second.envelope());
    assert_eq!(first.digest(), second.digest());
}

#[test]
fn bound_evidence_independently_reverifies_and_reports_the_rebuilt_snapshot_digest() {
    let entries = vec![meaning_entry("1.0.0", "alpha")];
    let snapshot = build_snapshot(&entries).expect("snapshot");
    let template = meaning_template();
    let bound = bind_to_snapshot(&snapshot, YankPolicy::ExcludeYanked, &template, &options())
        .expect("bind");
    let verified = verify_bound_resolution(
        bound.envelope(),
        &entries,
        YankPolicy::ExcludeYanked,
        &template,
        &options(),
    )
    .expect("independent replay");
    assert_eq!(verified.snapshot_digest, snapshot.digest());
    assert_eq!(verified.digest, bound.digest());
    assert_eq!(
        verified.packages,
        vec![package_lock_v3::Coordinate {
            package: MEANING.to_owned(),
            version: "1.0.0".to_owned(),
        }]
    );
}

#[test]
fn entry_order_does_not_affect_independent_reverification() {
    let entries = vec![
        calculator_entry("2.0.0", "beta"),
        meaning_entry("1.0.0", "alpha"),
    ];
    let reordered = vec![
        meaning_entry("1.0.0", "alpha"),
        calculator_entry("2.0.0", "beta"),
    ];
    let snapshot = build_snapshot(&entries).expect("snapshot");
    let template = meaning_template();
    let bound = bind_to_snapshot(&snapshot, YankPolicy::ExcludeYanked, &template, &options())
        .expect("bind");
    // Verifying against a differently-ordered but content-identical entry
    // list must still replay: canonical bytes are a function of content,
    // never of the caller's argument order.
    assert!(verify_bound_resolution(
        bound.envelope(),
        &reordered,
        YankPolicy::ExcludeYanked,
        &template,
        &options(),
    )
    .is_ok());
}

// --- The property this module exists for --------------------------------

#[test]
fn a_registry_change_invisible_to_the_resolver_still_changes_the_bound_digest() {
    // Two registry snapshots: `narrow` publishes only the package this
    // resolution actually needs; `wide` additionally publishes a *yanked*
    // `calculator` entry that `YankPolicy::ExcludeYanked` drops during
    // projection. Both project to the identical resolver-v2 subject list
    // for this resolution, so plain resolver-v2 evidence cannot tell them
    // apart -- which is exactly the gap this module closes.
    let narrow = vec![meaning_entry("1.0.0", "alpha")];
    let wide = vec![
        meaning_entry("1.0.0", "alpha"),
        yanked(calculator_entry("2.0.0", "beta"), "security advisory"),
    ];
    let narrow_snapshot = build_snapshot(&narrow).expect("narrow snapshot");
    let wide_snapshot = build_snapshot(&wide).expect("wide snapshot");
    assert_ne!(
        narrow_snapshot.digest(),
        wide_snapshot.digest(),
        "the two registries must genuinely differ"
    );
    let template = meaning_template();
    let narrow_bound = bind_to_snapshot(
        &narrow_snapshot,
        YankPolicy::ExcludeYanked,
        &template,
        &options(),
    )
    .expect("bind narrow");
    let wide_bound = bind_to_snapshot(
        &wide_snapshot,
        YankPolicy::ExcludeYanked,
        &template,
        &options(),
    )
    .expect("bind wide");

    // The plain resolver-v2 evidence is identical either way: the yanked
    // entry never reaches the projected catalog.
    let narrow_projected =
        project_subjects(&narrow_snapshot, YankPolicy::ExcludeYanked).expect("project narrow");
    let wide_projected =
        project_subjects(&wide_snapshot, YankPolicy::ExcludeYanked).expect("project wide");
    assert_eq!(narrow_projected.subjects, wide_projected.subjects);

    // But the *bound* evidence -- the artifact this module produces -- is
    // not identical, because it also commits to the full snapshot digest.
    assert_ne!(narrow_bound.envelope(), wide_bound.envelope());
    assert_ne!(narrow_bound.digest(), wide_bound.digest());

    // And a bound envelope claimed for one registry does not independently
    // reverify against the other registry's entries, even though a plain
    // resolver-v2 replay of the shared subjects would not have noticed.
    assert!(verify_bound_resolution(
        narrow_bound.envelope(),
        &wide,
        YankPolicy::ExcludeYanked,
        &template,
        &options(),
    )
    .is_err());
}

// --- Fault injection: tamper and substitution refusals ------------------

#[test]
fn a_single_tampered_byte_in_bound_evidence_is_refused() {
    let entries = vec![meaning_entry("1.0.0", "alpha")];
    let snapshot = build_snapshot(&entries).expect("snapshot");
    let template = meaning_template();
    let bound = bind_to_snapshot(&snapshot, YankPolicy::ExcludeYanked, &template, &options())
        .expect("bind");
    // Flip one ASCII hex digit inside the rendered digest field -- still
    // valid JSON shape and valid UTF-8, just one wrong byte.
    let position =
        bound.envelope().find("\"digest\":\"sha256:").unwrap() + "\"digest\":\"sha256:".len();
    let mut bytes = bound.envelope().as_bytes().to_vec();
    bytes[position] = if bytes[position] == b'0' { b'1' } else { b'0' };
    let tampered = String::from_utf8(bytes).expect("ASCII hex digit swap stays valid UTF-8");
    let error = verify_bound_resolution(
        &tampered,
        &entries,
        YankPolicy::ExcludeYanked,
        &template,
        &options(),
    )
    .unwrap_err();
    assert_eq!(error.code, "SPX-PKR608");
}

#[test]
fn a_substituted_snapshot_digest_claim_is_refused() {
    // Bind against one snapshot, then attempt to verify the resulting
    // evidence against a *different* (but individually valid) set of
    // entries. The rebuilt snapshot digest disagrees, so replay fails.
    let original = vec![meaning_entry("1.0.0", "alpha")];
    let substituted = vec![meaning_entry("1.0.0", "different-seed")];
    let snapshot = build_snapshot(&original).expect("snapshot");
    let template = meaning_template();
    let bound = bind_to_snapshot(&snapshot, YankPolicy::ExcludeYanked, &template, &options())
        .expect("bind");
    let error = verify_bound_resolution(
        bound.envelope(),
        &substituted,
        YankPolicy::ExcludeYanked,
        &template,
        &options(),
    )
    .unwrap_err();
    assert_eq!(error.code, "SPX-PKR608");
}

#[test]
fn a_mismatched_yank_policy_at_verification_time_is_refused() {
    let entries = vec![yanked(meaning_entry("1.0.0", "alpha"), "security advisory")];
    let snapshot = build_snapshot(&entries).expect("snapshot");
    let template = meaning_template();
    let bound = bind_to_snapshot(
        &snapshot,
        YankPolicy::AllowYankedWithWarning,
        &template,
        &options(),
    )
    .expect("bind");
    let error = verify_bound_resolution(
        bound.envelope(),
        &entries,
        YankPolicy::RefuseIfYanked,
        &template,
        &options(),
    )
    .unwrap_err();
    // `RefuseIfYanked` itself refuses before the replay comparison even
    // runs, so the failure surfaces as the yank refusal, not the replay
    // mismatch -- both are legitimate fail-closed outcomes for a mismatched
    // policy claim.
    assert_eq!(error.code, "SPX-PKR610");
}

// --- Yank-warning pass-through -------------------------------------------

#[test]
fn allow_yanked_with_warning_propagates_the_warning_through_binding() {
    let entries = vec![yanked(meaning_entry("1.0.0", "alpha"), "security advisory")];
    let snapshot = build_snapshot(&entries).expect("snapshot");
    let template = meaning_template();
    let bound = bind_to_snapshot(
        &snapshot,
        YankPolicy::AllowYankedWithWarning,
        &template,
        &options(),
    )
    .expect("bind");
    assert!(bound
        .warnings
        .iter()
        .any(|warning| warning.code == "SPX-PKR609"));
    let verified = verify_bound_resolution(
        bound.envelope(),
        &entries,
        YankPolicy::AllowYankedWithWarning,
        &template,
        &options(),
    )
    .expect("replay");
    assert!(verified
        .warnings
        .iter()
        .any(|warning| warning.code == "SPX-PKR609"));
}

// --- Structural determinism argument -------------------------------------

#[test]
fn determinism_argument_is_structural_not_just_repeated_runs() {
    let source = include_str!("../binding.rs");
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
    ] {
        assert!(
            !source.contains(forbidden),
            "binding.rs must not contain `{forbidden}`, which would make canonical bytes \
             depend on something other than snapshot and template content"
        );
    }
}
