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
