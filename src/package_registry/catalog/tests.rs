//! Cases for the read-only snapshot queries. The selection rule gets the
//! attention here: a wrong "highest satisfying version" answer would be
//! silent, so ordering, range exclusion and yank exclusion each have their
//! own case with a passing control.

use super::super::build_snapshot;
use super::super::tests::{calculator_entry, meaning_entry, yanked, CALCULATOR, MEANING};
use super::*;

fn snapshot(entries: Vec<super::super::PublishedEntry>) -> RegistrySnapshot {
    build_snapshot(&entries).expect("snapshot")
}

#[test]
fn listing_reports_every_entry_in_canonical_coordinate_order() {
    let snapshot = snapshot(vec![
        meaning_entry("1.2.0", "alpha"),
        calculator_entry("2.0.0", "alpha"),
        meaning_entry("1.0.0", "alpha"),
    ]);
    let listed: Vec<(String, String)> = snapshot
        .listing()
        .into_iter()
        .map(|entry| (entry.package, entry.version))
        .collect();
    assert_eq!(
        listed,
        vec![
            (CALCULATOR.to_owned(), "2.0.0".to_owned()),
            (MEANING.to_owned(), "1.0.0".to_owned()),
            (MEANING.to_owned(), "1.2.0".to_owned()),
        ]
    );
}

#[test]
fn listing_reports_the_yank_reason_and_the_unverified_publisher_claim() {
    let snapshot = snapshot(vec![yanked(meaning_entry("1.0.0", "alpha"), "unsound")]);
    let listed = snapshot.listing();
    assert_eq!(listed[0].status, "yanked");
    assert_eq!(listed[0].yank_reason.as_deref(), Some("unsound"));
    assert_eq!(listed[0].publisher, "signer.alpha");
}

#[test]
fn subject_bytes_returns_the_exact_published_bytes_for_one_coordinate() {
    let entry = meaning_entry("1.0.0", "alpha");
    let expected = entry.subject_bytes.clone();
    let snapshot = snapshot(vec![entry, calculator_entry("2.0.0", "alpha")]);
    assert_eq!(snapshot.subject_bytes(MEANING, "1.0.0"), Some(&*expected));
}

#[test]
fn subject_bytes_refuses_a_non_canonical_version_spelling_rather_than_guessing() {
    let snapshot = snapshot(vec![meaning_entry("1.0.0", "alpha")]);
    assert!(snapshot.subject_bytes(MEANING, "1.0.0").is_some());
    assert!(snapshot.subject_bytes(MEANING, "1.0").is_none());
    assert!(snapshot.subject_bytes(MEANING, "01.0.0").is_none());
    assert!(snapshot.subject_bytes("examples", "1.0.0").is_none());
}

// --- Selection ---------------------------------------------------------------

#[test]
fn select_version_picks_the_highest_satisfying_version() {
    let snapshot = snapshot(vec![
        meaning_entry("1.0.0", "alpha"),
        meaning_entry("1.2.0", "alpha"),
        meaning_entry("1.1.0", "alpha"),
    ]);
    let selected =
        select_version(&snapshot, MEANING, "^1.0.0", YankPolicy::ExcludeYanked).expect("selected");
    assert_eq!(selected.version, "1.2.0");
}

#[test]
fn select_version_never_leaves_the_range_it_was_given() {
    let snapshot = snapshot(vec![
        meaning_entry("1.0.0", "alpha"),
        meaning_entry("2.0.0", "alpha"),
    ]);
    let selected =
        select_version(&snapshot, MEANING, "~1.0.0", YankPolicy::ExcludeYanked).expect("selected");
    assert_eq!(selected.version, "1.0.0");
}

#[test]
fn select_version_skips_a_yanked_version_under_the_excluding_policy() {
    let entries = vec![
        meaning_entry("1.0.0", "alpha"),
        yanked(meaning_entry("1.2.0", "alpha"), "unsound"),
    ];
    let snapshot = snapshot(entries);
    let excluded =
        select_version(&snapshot, MEANING, "^1.0.0", YankPolicy::ExcludeYanked).expect("selected");
    assert_eq!(excluded.version, "1.0.0");
    // The control: the same snapshot under a policy that admits yanked
    // versions selects the yanked one, so the exclusion above is about the
    // policy and not about `1.2.0` being unselectable.
    let admitted = select_version(
        &snapshot,
        MEANING,
        "^1.0.0",
        YankPolicy::AllowYankedWithWarning,
    )
    .expect("selected");
    assert_eq!(admitted.version, "1.2.0");
    assert_eq!(admitted.status, "yanked");
}

#[test]
fn select_version_refuses_an_unpublished_package_under_the_shape_code() {
    let snapshot = snapshot(vec![meaning_entry("1.0.0", "alpha")]);
    let error = select_version(&snapshot, CALCULATOR, "^1.0.0", YankPolicy::ExcludeYanked)
        .expect_err("refused");
    assert_eq!(error.code, "SPX-PKR601");
    assert!(error.message.contains("no version"), "{}", error.message);
}

#[test]
fn select_version_refuses_a_range_no_published_version_satisfies() {
    let snapshot = snapshot(vec![meaning_entry("1.0.0", "alpha")]);
    let error = select_version(&snapshot, MEANING, "^2.0.0", YankPolicy::ExcludeYanked)
        .expect_err("refused");
    assert_eq!(error.code, "SPX-PKR601");
    assert!(error.message.contains("satisfies"), "{}", error.message);
}

#[test]
fn select_version_refuses_a_malformed_range_rather_than_matching_everything() {
    let snapshot = snapshot(vec![meaning_entry("1.0.0", "alpha")]);
    let error = select_version(&snapshot, MEANING, "latest", YankPolicy::ExcludeYanked)
        .expect_err("refused");
    assert_eq!(error.code, "SPX-PKR601");
}
