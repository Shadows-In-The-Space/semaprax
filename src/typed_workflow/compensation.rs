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

/// The physical compensation effect itself did not succeed. Per issue
/// #208's own failure list ("Compensation can fail or be non-equivalent to
/// rollback"), this is a distinct, named outcome from
/// [`CompensationOutcome`] rather than a panic, a silently swallowed error,
/// or a bare `()` return that could never report it. `reason` is a bare
/// description for a human or log to read; this type carries no retry
/// authority and decides nothing about what happens next -- that is
/// [`CompensationLedger::apply`]'s caller's job, exactly as this module's
/// other outcomes never decide anything either.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompensationFailure {
    pub reason: String,
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

    /// Attempts `effect` exactly once for `key`. If `key` was already
    /// attempted (in this ledger, including one restored from a checkpoint
    /// snapshot), `effect` is not called at all and
    /// `Ok(CompensationOutcome::AlreadyApplied)` is returned -- regardless
    /// of whether the earlier attempt succeeded or failed.
    ///
    /// `key` is marked attempted *before* `effect` runs, not only on
    /// success: this module never automatically retries a compensation
    /// under the same key, even one whose effect reported
    /// [`CompensationFailure`]. That is the same choice this repository's
    /// retry policy makes for an [`super::retry::AttemptOutcomeClass::Uncertain`]
    /// step outcome -- an effect whose result is unknown or unsuccessful is
    /// never silently retried, because retrying could double-apply an
    /// effect that actually went through. A caller that wants to retry a
    /// failed compensation must do so deliberately, under a new key (for
    /// example a new logical retry count folded into `run`), never by
    /// calling `apply` again with the same one.
    ///
    /// # Errors
    ///
    /// Returns `Err(CompensationFailure)` if `effect` itself reports
    /// failure. This never leaves the ledger in a state where the failed
    /// attempt could be silently re-run: see above.
    pub fn apply(
        &mut self,
        key: CompensationKey,
        effect: impl FnOnce() -> Result<(), CompensationFailure>,
    ) -> Result<CompensationOutcome, CompensationFailure> {
        if !self.applied.insert(key) {
            return Ok(CompensationOutcome::AlreadyApplied);
        }
        effect()?;
        Ok(CompensationOutcome::Applied)
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
            || {
                calls.set(calls.get() + 1);
                Ok(())
            },
        );
        assert_eq!(outcome, Ok(CompensationOutcome::Applied));
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
        ledger
            .apply(key, || {
                calls.set(calls.get() + 1);
                Ok(())
            })
            .unwrap();
        let second = ledger.apply(key, || {
            calls.set(calls.get() + 1);
            Ok(())
        });
        assert_eq!(second, Ok(CompensationOutcome::AlreadyApplied));
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
        ledger
            .apply(key, || {
                calls.set(calls.get() + 1);
                Ok(())
            })
            .unwrap();

        // Simulate a crash-and-resume: only the snapshot survives, a fresh
        // ledger is built from it, and the workflow re-drives the same
        // compensation because it does not itself remember having applied
        // it.
        let snapshot = ledger.snapshot();
        let mut resumed = CompensationLedger::restore(&snapshot);
        let outcome = resumed.apply(key, || {
            calls.set(calls.get() + 1);
            Ok(())
        });

        assert_eq!(outcome, Ok(CompensationOutcome::AlreadyApplied));
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
        ledger
            .apply(
                CompensationKey {
                    step: StepId(1),
                    run: 1,
                },
                || {
                    calls.set(calls.get() + 1);
                    Ok(())
                },
            )
            .unwrap();
        ledger
            .apply(
                CompensationKey {
                    step: StepId(1),
                    run: 2,
                },
                || {
                    calls.set(calls.get() + 1);
                    Ok(())
                },
            )
            .unwrap();
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
        ledger.apply(key, || Ok(())).unwrap();
        assert!(ledger.is_applied(key));
    }

    /// Issue #208's own failure list: "Compensation can fail or be
    /// non-equivalent to rollback." A failing compensation effect is
    /// reported as `Err(CompensationFailure)`, never silently swallowed
    /// into `Applied`, and never panics or loses the reason.
    #[test]
    fn a_failing_compensation_effect_is_reported_not_swallowed() {
        let mut ledger = CompensationLedger::new();
        let key = CompensationKey {
            step: StepId(6),
            run: 1,
        };
        let outcome = ledger.apply(key, || {
            Err(CompensationFailure {
                reason: "downstream refund API returned 503".to_owned(),
            })
        });
        assert_eq!(
            outcome,
            Err(CompensationFailure {
                reason: "downstream refund API returned 503".to_owned()
            })
        );
    }

    /// A failed attempt still marks the key attempted: this module never
    /// automatically re-runs a compensation under the same key just
    /// because its one attempt failed, matching how an `Uncertain` step
    /// outcome is never automatically retried elsewhere in this module
    /// ([`super::retry`]). `is_applied` reports the key as attempted even
    /// though the attempt did not succeed -- callers must not read
    /// `is_applied` as "and it worked."
    #[test]
    fn a_failed_attempt_is_never_silently_retried_under_the_same_key() {
        let mut ledger = CompensationLedger::new();
        let key = CompensationKey {
            step: StepId(7),
            run: 1,
        };
        let calls = Cell::new(0);
        let first = ledger.apply(key, || {
            calls.set(calls.get() + 1);
            Err(CompensationFailure {
                reason: "refund declined".to_owned(),
            })
        });
        assert!(first.is_err());
        assert!(ledger.is_applied(key));

        // A second call under the exact same key never re-invokes the
        // effect, even though the first attempt failed.
        let second = ledger.apply(key, || {
            calls.set(calls.get() + 1);
            Ok(())
        });
        assert_eq!(second, Ok(CompensationOutcome::AlreadyApplied));
        assert_eq!(
            calls.get(),
            1,
            "a failed compensation attempt must not be silently retried under the same key"
        );
    }
}
