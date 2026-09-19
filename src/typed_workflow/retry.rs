//! Retry safety for workflow steps.
//!
//! This module deliberately does not invent its own safe/unsafe retry
//! taxonomy. It reuses
//! [`crate::model_budget_policy::classification::AttemptOutcomeClass`] and
//! [`crate::model_budget_policy::classification::retry_is_permitted`] —
//! the same closed vocabulary and rule issue #179 already established and
//! this repository's other retry/failover call sites are built on — so a
//! second, possibly divergent, notion of "which outcomes are safe to retry"
//! cannot appear here. In particular
//! [`AttemptOutcomeClass::Uncertain`] (delivery status unknown) and
//! [`AttemptOutcomeClass::CompletedWithResponse`] (the call is known to
//! have happened already) are never retried automatically by
//! [`decide_retry`], matching `retry_is_permitted` exactly.
//!
//! What this module adds on top is purely a bounded attempt budget: even a
//! provably safe class stops being retried once the budget is exhausted.

pub use crate::model_budget_policy::classification::{retry_is_permitted, AttemptOutcomeClass};

/// A bounded retry budget for one workflow step instance. `max_attempts`
/// counts total attempts, including the first; it must be nonzero for the
/// step to run at all, but that is enforced by the caller wiring the
/// budget in, not by this type.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RetryBudget {
    pub max_attempts: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RetryDecision {
    /// Retry now: the outcome is provably safe and budget remains.
    Retry,
    /// The outcome itself forbids automatic retry, regardless of budget.
    GiveUp,
    /// The outcome would have permitted a retry, but the budget is spent.
    ExhaustedButPermitted,
}

/// `attempts_made` is the count of attempts already consumed (the one that
/// produced `outcome` included).
#[must_use]
pub fn decide_retry(
    budget: RetryBudget,
    attempts_made: u32,
    outcome: AttemptOutcomeClass,
) -> RetryDecision {
    if !retry_is_permitted(outcome) {
        return RetryDecision::GiveUp;
    }
    if attempts_made >= budget.max_attempts {
        return RetryDecision::ExhaustedButPermitted;
    }
    RetryDecision::Retry
}

/// One scripted attempt of a step's effect, for callers (currently
/// [`super::engine::run`]) that need to drive [`decide_retry`] against a
/// sequence of outcomes rather than a single one.
///
/// `succeeded` is deliberately a separate field from `outcome` rather than a
/// sixth [`AttemptOutcomeClass`] variant: the classification answers "is
/// retrying this outcome provably safe", which is orthogonal to whether the
/// attempt actually produced the effect the step wanted (an attempt can be
/// [`AttemptOutcomeClass::CompletedWithResponse`] and still have failed the
/// caller's request). A successful attempt's `outcome` is never consulted by
/// [`decide_retry`] — there is nothing left to decide once the step got what
/// it needed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ScriptedAttempt {
    pub outcome: AttemptOutcomeClass,
    pub succeeded: bool,
}

impl ScriptedAttempt {
    #[must_use]
    pub fn success() -> Self {
        ScriptedAttempt {
            // Never consulted: `succeeded` short-circuits before `outcome`
            // is read. Named honestly rather than left to an arbitrary
            // default so a reader never mistakes it for a real classification.
            outcome: AttemptOutcomeClass::CompletedWithResponse,
            succeeded: true,
        }
    }

    #[must_use]
    pub fn failed(outcome: AttemptOutcomeClass) -> Self {
        ScriptedAttempt {
            outcome,
            succeeded: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn not_dispatched_retries_while_budget_remains() {
        let decision = decide_retry(
            RetryBudget { max_attempts: 3 },
            1,
            AttemptOutcomeClass::NotDispatched,
        );
        assert_eq!(decision, RetryDecision::Retry);
    }

    #[test]
    fn provider_reported_retryable_stops_once_budget_is_spent() {
        let decision = decide_retry(
            RetryBudget { max_attempts: 2 },
            2,
            AttemptOutcomeClass::ProviderReportedRetryable,
        );
        assert_eq!(decision, RetryDecision::ExhaustedButPermitted);
    }

    #[test]
    fn uncertain_outcome_is_never_retried_even_with_budget_remaining() {
        let decision = decide_retry(
            RetryBudget { max_attempts: 10 },
            1,
            AttemptOutcomeClass::Uncertain,
        );
        assert_eq!(decision, RetryDecision::GiveUp);
    }

    #[test]
    fn completed_with_response_is_never_retried() {
        let decision = decide_retry(
            RetryBudget { max_attempts: 10 },
            1,
            AttemptOutcomeClass::CompletedWithResponse,
        );
        assert_eq!(decision, RetryDecision::GiveUp);
    }

    #[test]
    fn rejected_before_processing_retries_while_budget_remains() {
        let decision = decide_retry(
            RetryBudget { max_attempts: 5 },
            0,
            AttemptOutcomeClass::RejectedBeforeProcessing,
        );
        assert_eq!(decision, RetryDecision::Retry);
    }
}
