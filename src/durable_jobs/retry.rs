//! Pure, bounded retry/backoff decision procedures.
//!
//! Every function here is total, effect-free, and takes only scalars —
//! the same shape `std.jobs.retry` specifies in
//! `docs/DURABLE-JOBS-V1.md`. Nothing in this file touches [`JobRecord`]
//! or a store; `super::store` is the only caller, and it is the only place
//! these decisions turn into a state transition.

use super::model::{AttemptOutcome, JobState, RetryPolicy};

/// The state a job moves to after one attempt's outcome, given the attempt
/// number *of the attempt that just finished* (1-based) and the policy's
/// ceiling. Mirrors `std.jobs.retry.next_state_after_outcome`:
///
/// - success is always terminal `Succeeded`.
/// - a permanent failure is always terminal `PermanentFailure`.
/// - a retryable failure that has now reached the ceiling dead-letters;
///   otherwise it becomes `RetryableFailure`, which `GenerationJobStore`
///   returns to `Pending` so a later `claim` can pick it back up.
pub fn next_state_after_attempt(
    outcome: AttemptOutcome,
    attempt: u32,
    policy: RetryPolicy,
) -> JobState {
    match outcome {
        AttemptOutcome::Success => JobState::Succeeded,
        AttemptOutcome::Permanent => JobState::PermanentFailure,
        AttemptOutcome::Retryable => {
            if should_dead_letter(attempt, policy.max_attempts) {
                JobState::DeadLettered
            } else {
                JobState::RetryableFailure
            }
        }
    }
}

/// `true` once the attempt ceiling has been reached or exceeded. `attempt`
/// is the count of attempts already made (including the one that just
/// failed), so a policy with `max_attempts == 1` dead-letters on the first
/// failure.
pub fn should_dead_letter(attempt: u32, max_attempts: u32) -> bool {
    attempt >= max_attempts
}

/// Bounded exponential backoff: doubles `base_backoff_ticks` once per
/// attempt already made, capped at `max_backoff_ticks`. `ensures result <=
/// max_backoff_ticks` holds by construction — a runaway attempt counter can
/// never produce an unbounded wait, matching "no unbounded retries."
/// Saturates on overflow rather than wrapping, so an absurdly large attempt
/// count still returns the cap, never a small wrapped value.
pub fn backoff_ticks(attempt: u32, policy: RetryPolicy) -> u64 {
    let mut ticks = policy.base_backoff_ticks.max(1);
    for _ in 0..attempt.min(63) {
        ticks = ticks.saturating_mul(2);
        if ticks >= policy.max_backoff_ticks {
            return policy.max_backoff_ticks;
        }
    }
    ticks.min(policy.max_backoff_ticks)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy(max_attempts: u32) -> RetryPolicy {
        RetryPolicy::new(max_attempts, 10, 1000)
    }

    #[test]
    fn success_is_always_terminal_succeeded() {
        assert_eq!(
            next_state_after_attempt(AttemptOutcome::Success, 1, policy(5)),
            JobState::Succeeded
        );
    }

    #[test]
    fn permanent_failure_is_always_terminal_permanent_failure() {
        assert_eq!(
            next_state_after_attempt(AttemptOutcome::Permanent, 1, policy(5)),
            JobState::PermanentFailure
        );
    }

    #[test]
    fn retryable_failure_under_ceiling_is_retryable_failure() {
        assert_eq!(
            next_state_after_attempt(AttemptOutcome::Retryable, 2, policy(5)),
            JobState::RetryableFailure
        );
    }

    #[test]
    fn retryable_failure_at_ceiling_dead_letters() {
        assert_eq!(
            next_state_after_attempt(AttemptOutcome::Retryable, 5, policy(5)),
            JobState::DeadLettered
        );
    }

    #[test]
    fn retryable_failure_past_ceiling_dead_letters() {
        assert_eq!(
            next_state_after_attempt(AttemptOutcome::Retryable, 9, policy(5)),
            JobState::DeadLettered
        );
    }

    #[test]
    fn backoff_never_exceeds_the_declared_cap() {
        let policy = RetryPolicy::new(1000, 1, 100);
        for attempt in 0..200 {
            assert!(backoff_ticks(attempt, policy) <= 100);
        }
    }

    #[test]
    fn backoff_doubles_until_the_cap() {
        let policy = RetryPolicy::new(10, 4, 100);
        assert_eq!(backoff_ticks(0, policy), 4);
        assert_eq!(backoff_ticks(1, policy), 8);
        assert_eq!(backoff_ticks(2, policy), 16);
        assert_eq!(backoff_ticks(3, policy), 32);
        assert_eq!(backoff_ticks(4, policy), 64);
        assert_eq!(backoff_ticks(5, policy), 100);
    }

    #[test]
    fn backoff_does_not_overflow_or_wrap_on_a_huge_attempt_count() {
        let policy = RetryPolicy::new(u32::MAX, u64::MAX / 2, u64::MAX - 1);
        assert_eq!(backoff_ticks(u32::MAX, policy), u64::MAX - 1);
    }
}
