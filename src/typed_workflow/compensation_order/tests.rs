use super::*;

fn rec(step: u32, run: u64) -> CommitRecord {
    CommitRecord {
        step: StepId(step),
        run,
    }
}

#[test]
fn empty_log_requires_no_compensation() {
    let log = CommitLog::new();
    let proof = log.compensation_order();
    assert!(proof.required().is_empty());
    assert_eq!(proof.verify_complete(&[]), Ok(()));
}

#[test]
fn required_order_is_the_exact_reverse_of_commit_order() {
    let mut log = CommitLog::new();
    log.record(StepId(1), 1);
    log.record(StepId(2), 1);
    log.record(StepId(3), 1);

    let proof = log.compensation_order();
    assert_eq!(proof.required(), &[rec(3, 1), rec(2, 1), rec(1, 1)]);
}

#[test]
fn required_order_is_reverse_of_recorded_call_order_not_a_sort() {
    // Commit order is neither ascending nor descending by StepId, so a
    // sort in either direction would produce a different answer than the
    // genuine reversal of call order.
    let mut log = CommitLog::new();
    log.record(StepId(5), 1);
    log.record(StepId(9), 1);
    log.record(StepId(1), 1);

    let proof = log.compensation_order();
    let reversed_call_order = &[rec(1, 1), rec(9, 1), rec(5, 1)];
    let ascending_sort = &[rec(1, 1), rec(5, 1), rec(9, 1)];
    let descending_sort = &[rec(9, 1), rec(5, 1), rec(1, 1)];

    assert_eq!(proof.required(), reversed_call_order);
    assert_ne!(proof.required(), ascending_sort);
    assert_ne!(proof.required(), descending_sort);
}

#[test]
fn distinct_runs_of_the_same_step_each_get_their_own_slot_in_commit_order() {
    let mut log = CommitLog::new();
    log.record(StepId(7), 1);
    log.record(StepId(7), 2);

    assert_eq!(log.commits(), &[rec(7, 1), rec(7, 2)]);
    let proof = log.compensation_order();
    assert_eq!(proof.required(), &[rec(7, 2), rec(7, 1)]);
}

#[test]
fn commit_log_never_reorders_or_merges_recorded_commits() {
    let mut log = CommitLog::new();
    log.record(StepId(3), 1);
    log.record(StepId(1), 1);
    log.record(StepId(2), 1);
    // Recorded call order is preserved exactly, not sorted by StepId.
    assert_eq!(log.commits(), &[rec(3, 1), rec(1, 1), rec(2, 1)]);
}

#[test]
fn verify_complete_accepts_the_exact_reverse_order() {
    let mut log = CommitLog::new();
    log.record(StepId(1), 1);
    log.record(StepId(2), 1);
    let proof = log.compensation_order();

    assert_eq!(proof.verify_complete(&[rec(2, 1), rec(1, 1)]), Ok(()));
}

#[test]
fn verify_complete_refuses_forward_replay_order() {
    let mut log = CommitLog::new();
    log.record(StepId(1), 1);
    log.record(StepId(2), 1);
    let proof = log.compensation_order();

    // Replaying in commit order (not reversed) must be refused, not
    // accepted as "close enough".
    let result = proof.verify_complete(&[rec(1, 1), rec(2, 1)]);
    assert_eq!(
        result,
        Err(OrderViolation::OutOfOrder {
            index: 0,
            expected: rec(2, 1),
            actual: rec(1, 1),
        })
    );
}

#[test]
fn verify_complete_refuses_a_correct_set_replayed_in_the_wrong_order() {
    let mut log = CommitLog::new();
    log.record(StepId(1), 1);
    log.record(StepId(2), 1);
    log.record(StepId(3), 1);
    let proof = log.compensation_order();
    // required = [3, 2, 1]; attempt swaps the first two.
    let result = proof.verify_complete(&[rec(2, 1), rec(3, 1), rec(1, 1)]);
    assert_eq!(
        result,
        Err(OrderViolation::OutOfOrder {
            index: 0,
            expected: rec(3, 1),
            actual: rec(2, 1),
        })
    );
}

#[test]
fn verify_prefix_accepts_a_correct_partial_replay() {
    let mut log = CommitLog::new();
    log.record(StepId(1), 1);
    log.record(StepId(2), 1);
    log.record(StepId(3), 1);
    let proof = log.compensation_order();

    // Only the first required compensation (step 3) has run so far.
    assert_eq!(proof.verify_prefix(&[rec(3, 1)]), Ok(()));
}

#[test]
fn verify_prefix_refuses_at_the_first_wrong_element_even_if_the_rest_would_match() {
    let mut log = CommitLog::new();
    log.record(StepId(1), 1);
    log.record(StepId(2), 1);
    let proof = log.compensation_order();

    // required = [2, 1]; attempted starts wrong even though "1" does
    // appear later in the required order.
    let result = proof.verify_prefix(&[rec(1, 1)]);
    assert_eq!(
        result,
        Err(OrderViolation::OutOfOrder {
            index: 0,
            expected: rec(2, 1),
            actual: rec(1, 1),
        })
    );
}

#[test]
fn verify_complete_refuses_an_incomplete_replay() {
    let mut log = CommitLog::new();
    log.record(StepId(1), 1);
    log.record(StepId(2), 1);
    let proof = log.compensation_order();

    // Correct so far, but only one of the two required compensations ran.
    let result = proof.verify_complete(&[rec(2, 1)]);
    assert_eq!(
        result,
        Err(OrderViolation::Incomplete {
            completed: 1,
            required: 2,
        })
    );
}

#[test]
fn verify_complete_refuses_extraneous_entries_beyond_what_was_ever_committed() {
    let mut log = CommitLog::new();
    log.record(StepId(1), 1);
    let proof = log.compensation_order();

    let result = proof.verify_complete(&[rec(1, 1), rec(9, 1)]);
    assert_eq!(result, Err(OrderViolation::Extraneous(1)));
}

#[test]
fn verify_complete_refuses_a_duplicated_entry_masquerading_as_a_second_compensation() {
    let mut log = CommitLog::new();
    log.record(StepId(1), 1);
    let proof = log.compensation_order();

    // Replaying the one required compensation twice is not the same as
    // completing the required order; the second occurrence has no
    // corresponding commit.
    let result = proof.verify_complete(&[rec(1, 1), rec(1, 1)]);
    assert_eq!(result, Err(OrderViolation::Extraneous(1)));
}

#[test]
fn verify_prefix_on_an_empty_attempt_is_always_ok() {
    let mut log = CommitLog::new();
    log.record(StepId(1), 1);
    log.record(StepId(2), 1);
    let proof = log.compensation_order();

    assert_eq!(proof.verify_prefix(&[]), Ok(()));
}

#[test]
fn canonical_bytes_are_deterministic_across_repeated_calls() {
    let mut log = CommitLog::new();
    log.record(StepId(1), 1);
    log.record(StepId(2), 42);
    log.record(StepId(3), 7);
    let proof = log.compensation_order();

    let first = proof.canonical_bytes();
    let second = proof.canonical_bytes();
    let third = proof.canonical_bytes();
    assert_eq!(first, second);
    assert_eq!(second, third);
}

#[test]
fn canonical_bytes_differ_when_commit_order_differs_for_the_same_set_of_records() {
    let mut forward = CommitLog::new();
    forward.record(StepId(1), 1);
    forward.record(StepId(2), 1);

    let mut backward = CommitLog::new();
    backward.record(StepId(2), 1);
    backward.record(StepId(1), 1);

    let forward_bytes = forward.compensation_order().canonical_bytes();
    let backward_bytes = backward.compensation_order().canonical_bytes();
    assert_ne!(
        forward_bytes, backward_bytes,
        "canonical encoding must reflect commit order, not merely the set of commits"
    );
}

#[test]
fn canonical_bytes_are_sensitive_to_run_not_just_step() {
    let mut a = CommitLog::new();
    a.record(StepId(1), 1);

    let mut b = CommitLog::new();
    b.record(StepId(1), 2);

    assert_ne!(
        a.compensation_order().canonical_bytes(),
        b.compensation_order().canonical_bytes()
    );
}

#[test]
fn canonical_bytes_length_is_twelve_bytes_per_record() {
    let mut log = CommitLog::new();
    log.record(StepId(1), 1);
    log.record(StepId(2), 1);
    log.record(StepId(3), 1);
    let proof = log.compensation_order();
    assert_eq!(proof.canonical_bytes().len(), 3 * 12);
}

#[test]
fn commits_accessor_reflects_every_recorded_call_including_repeats() {
    let mut log = CommitLog::new();
    for step in [4u32, 4, 4] {
        log.record(StepId(step), 1);
    }
    assert_eq!(log.commits().len(), 3);
}
