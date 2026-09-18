//! Compensation as an explicit, idempotent effect.
//!
//! A compensation is a new effect the workflow performs to counteract a
//! prior step's effect — it is never treated as proof that the original
//! effect was undone (per the repository's "settlement/proof data is not
//! permission" invariant, applied here to rollback). [`CompensationLedger`]
//! exists to make one specific property checkable: a compensation keyed by
//! (step, run) executes its effect at most once, even if the surrounding
//! workflow is retried or resumed from a checkpoint and asks this ledger to
//! apply the same compensation again.

use super::graph::StepId;
use std::collections::BTreeSet;

/// Identifies one compensation instance: a specific step's compensation for
/// a specific run of the workflow. Retrying or resuming the *same* run must
/// not re-run its compensations; a genuinely new run gets a new `run` value
/// and is free to compensate again.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct CompensationKey {
    pub step: StepId,
    pub run: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CompensationOutcome {
    Applied,
    AlreadyApplied,
}

/// Durable-enough-to-snapshot record of which compensations have already
/// run. Not a wire format: [`CompensationLedger::snapshot`] returns a
/// plain in-memory `Vec` for a caller (e.g. [`super::checkpoint`]) to fold
/// into its own state; there is no independent byte-level encoding here.
#[derive(Default, Debug, Clone, Eq, PartialEq)]
pub struct CompensationLedger {
    applied: BTreeSet<CompensationKey>,
}

impl CompensationLedger {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn snapshot(&self) -> Vec<(u32, u64)> {
        self.applied.iter().map(|k| (k.step.0, k.run)).collect()
    }

    #[must_use]
    pub fn restore(entries: &[(u32, u64)]) -> Self {
        Self {
            applied: entries
                .iter()
                .map(|&(step, run)| CompensationKey {
                    step: StepId(step),
                    run,
                })
                .collect(),
        }
    }

    #[must_use]
    pub fn is_applied(&self, key: CompensationKey) -> bool {
        self.applied.contains(&key)
    }

    /// Runs `effect` exactly once for `key`. If `key` was already applied
    /// (in this ledger, including one restored from a checkpoint
    /// snapshot), `effect` is not called at all and
    /// `CompensationOutcome::AlreadyApplied` is returned.
    pub fn apply(&mut self, key: CompensationKey, effect: impl FnOnce()) -> CompensationOutcome {
        if !self.applied.insert(key) {
            return CompensationOutcome::AlreadyApplied;
        }
        effect();
        CompensationOutcome::Applied
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    #[test]
    fn first_application_runs_the_effect() {
        let mut ledger = CompensationLedger::new();
        let calls = Cell::new(0);
        let outcome = ledger.apply(
            CompensationKey {
                step: StepId(1),
                run: 1,
            },
            || calls.set(calls.get() + 1),
        );
        assert_eq!(outcome, CompensationOutcome::Applied);
        assert_eq!(calls.get(), 1);
    }

    #[test]
    fn retrying_the_same_key_does_not_run_the_effect_twice() {
        let mut ledger = CompensationLedger::new();
        let calls = Cell::new(0);
        let key = CompensationKey {
            step: StepId(1),
            run: 1,
        };
        ledger.apply(key, || calls.set(calls.get() + 1));
        let second = ledger.apply(key, || calls.set(calls.get() + 1));
        assert_eq!(second, CompensationOutcome::AlreadyApplied);
        assert_eq!(
            calls.get(),
            1,
            "compensation effect ran more than once for the same (step, run)"
        );
    }

    #[test]
    fn resuming_from_a_restored_snapshot_still_refuses_to_double_run() {
        let mut ledger = CompensationLedger::new();
        let key = CompensationKey {
            step: StepId(3),
            run: 9,
        };
        let calls = Cell::new(0);
        ledger.apply(key, || calls.set(calls.get() + 1));

        // Simulate a crash-and-resume: only the snapshot survives, a fresh
        // ledger is built from it, and the workflow re-drives the same
        // compensation because it does not itself remember having applied
        // it.
        let snapshot = ledger.snapshot();
        let mut resumed = CompensationLedger::restore(&snapshot);
        let outcome = resumed.apply(key, || calls.set(calls.get() + 1));

        assert_eq!(outcome, CompensationOutcome::AlreadyApplied);
        assert_eq!(
            calls.get(),
            1,
            "resume must not re-run an already-applied compensation"
        );
    }

    #[test]
    fn a_distinct_run_of_the_same_step_may_compensate_again() {
        let mut ledger = CompensationLedger::new();
        let calls = Cell::new(0);
        ledger.apply(
            CompensationKey {
                step: StepId(1),
                run: 1,
            },
            || calls.set(calls.get() + 1),
        );
        ledger.apply(
            CompensationKey {
                step: StepId(1),
                run: 2,
            },
            || calls.set(calls.get() + 1),
        );
        assert_eq!(calls.get(), 2);
    }

    #[test]
    fn is_applied_reports_ledger_state_without_running_anything() {
        let mut ledger = CompensationLedger::new();
        let key = CompensationKey {
            step: StepId(5),
            run: 1,
        };
        assert!(!ledger.is_applied(key));
        ledger.apply(key, || {});
        assert!(ledger.is_applied(key));
    }
}
