//! Deterministic run control: the step-cost budget that stands in for a
//! timeout, and the cooperative cancellation signal, plus the terminal
//! [`RunOutcome`] a run ends in.
//!
//! # Why there is no wall-clock timeout here
//!
//! Issue #208's in-scope list names "timeout" beside retry and
//! compensation. This module deliberately does **not** implement one as
//! elapsed wall-clock time, and that is a design decision rather than an
//! omission.
//!
//! This repository's non-negotiable invariants require diagnostics, graph
//! JSON and generated artifacts to be deterministic, and
//! [`super::engine::run`] documents that the same graph and the same
//! [`super::engine::ExecInputs`] produce a byte-identical
//! [`super::engine::ExecTrace`] every time. A wall-clock deadline would
//! break exactly that: the same run, replayed on a slower machine or under
//! a loaded scheduler, would cut off at a different step and produce a
//! different trace, a different [`super::compensation_order::CommitLog`],
//! and therefore a different compensation obligation. A workflow engine
//! whose failure record depends on how busy the host was is not
//! replayable, and this module would rather leave "seconds" unimplemented
//! than buy the word at that price.
//!
//! What a timeout is actually *for* — bounding how much work one run may
//! consume before it is cut off, so a run cannot burn resources forever —
//! is implemented instead as a **declared cost budget** charged per step
//! execution and per retry attempt: [`StepBudget`], metered by
//! [`TickMeter`] against the schedule in [`step_cost`]. It is the same
//! shape as the engine's existing `MAX_STEP_EXECUTIONS` ceiling, refined
//! from "how many steps" to "how much declared cost", so that a `ModelCall`
//! that retries sixteen times is charged more than sixteen `Sequential`
//! steps. Exhausting it is [`BudgetExhausted`], surfaced as the engine's
//! own distinct `StepBudgetExhausted` refusal — never the retry-ceiling
//! refusal (`StepFailed`), and never an
//! [`super::retry::AttemptOutcomeClass::Uncertain`] outcome, which is a
//! statement about one effect's delivery status and has nothing to do with
//! a run running out of budget.
//!
//! The costs in [`step_cost`] are an **ordinal schedule, not a prediction
//! of duration**. They rank kinds against each other so a budget can be
//! sized deliberately; they do not claim that a `ModelCall` takes sixteen
//! times as long as a `Sequential` step, and nothing in this module reads a
//! clock to find out.
//!
//! # Cancellation is a coordinate, not a flag
//!
//! Cancellation is cooperative and observed only at defined boundaries
//! (see [`CancelWatch`]). For the same replayability reason, the request
//! itself is not an ambient flag another thread flips at an arbitrary
//! moment: it is a [`CancelSignal`] carried in the run's own inputs,
//! addressed by a deterministic run-internal coordinate — the number of
//! step executions already recorded. Replaying a run with the same inputs
//! therefore cancels at exactly the same step and yields exactly the same
//! trace. A host that wants to cancel a *live* run maps its own
//! out-of-band request onto that coordinate once, at the boundary where it
//! is observed, and the value it chose is then part of the run's recorded
//! inputs like every other decision.
//!
//! A cancelled run is a terminal state of its own
//! ([`RunOutcome::Cancelled`]): it is not success, it is not a permanent
//! failure, and it is not uncertain. See [`RunOutcome`] for what that means
//! for already-recorded compensation entries.

use super::graph::{StepId, StepKind};

/// Declared cost of executing one step of each kind, charged by
/// [`TickMeter`] in [`super::engine::dispatch_step`] before the step runs.
///
/// An ordinal schedule, not a duration estimate (see the module
/// documentation). Control-flow kinds cost the minimum: reaching them
/// performs no effect, so all they consume is the engine's own bounded
/// bookkeeping. `Declared` kinds cost more because each one decides an
/// admission a caller may act on, and `ModelCall` costs most because it is
/// the one kind in this engine whose step may retry a real effect.
///
/// `const` and total over [`StepKind`]: adding a step kind is a compile
/// error here rather than a kind that silently costs nothing.
#[must_use]
pub const fn step_cost(kind: &StepKind) -> u64 {
    match kind {
        StepKind::Sequential
        | StepKind::Conditional { .. }
        | StepKind::Parallel
        | StepKind::Join { .. }
        | StepKind::Loop { .. }
        | StepKind::HumanGate
        | StepKind::Terminal => 1,
        StepKind::Declared(_) => 4,
        StepKind::ModelCall { .. } => 16,
    }
}

/// Cost charged for each retry attempt of a `ModelCall` step's effect,
/// beyond the one-off [`step_cost`] of reaching the step.
///
/// This is what makes the budget behave like the thing a timeout is
/// actually wanted for: a step that keeps failing and retrying drains the
/// run's budget, and a run that spends its whole budget inside one step's
/// retry loop is cut off rather than allowed to keep going because the
/// *step* count never advanced.
pub const RETRY_ATTEMPT_COST: u64 = 8;

/// A run's total declared cost ceiling — the deterministic stand-in for a
/// timeout. `max_ticks` is a total over the whole run, not a per-step
/// allowance.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StepBudget {
    pub max_ticks: u64,
}

/// The refusal [`TickMeter::charge`] produces when a charge would take the
/// run past its declared ceiling.
///
/// `spent` is the cost already charged *before* the refused charge, so
/// `spent + requested > limit` always holds and a reader can see exactly
/// which charge was refused rather than a post-hoc total.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BudgetExhausted {
    pub spent: u64,
    pub requested: u64,
    pub limit: u64,
}

/// Meters a run's declared cost against its [`StepBudget`], if it declared
/// one.
///
/// With no budget, `charge` always succeeds and only accumulates the total,
/// so an existing caller that declares nothing runs exactly as it did
/// before this existed (the engine's independent `MAX_STEP_EXECUTIONS`
/// ceiling still bounds it). Arithmetic saturates: a hostile or absurd cost
/// schedule can never wrap the counter into looking cheap.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TickMeter {
    spent: u64,
    budget: Option<StepBudget>,
}

impl TickMeter {
    #[must_use]
    pub fn new(budget: Option<StepBudget>) -> Self {
        TickMeter { spent: 0, budget }
    }

    /// Total cost charged so far. Accumulated even with no declared budget,
    /// so a caller can size one from a real run.
    #[must_use]
    pub fn spent(&self) -> u64 {
        self.spent
    }

    /// Charges `ticks`. On refusal the meter is left unchanged: a refused
    /// charge is not spent, because the work it would have paid for does
    /// not run.
    ///
    /// # Errors
    ///
    /// [`BudgetExhausted`] if a declared budget cannot cover the charge.
    pub fn charge(&mut self, ticks: u64) -> Result<(), BudgetExhausted> {
        let next = self.spent.saturating_add(ticks);
        if let Some(budget) = self.budget {
            if next > budget.max_ticks {
                return Err(BudgetExhausted {
                    spent: self.spent,
                    requested: ticks,
                    limit: budget.max_ticks,
                });
            }
        }
        self.spent = next;
        Ok(())
    }
}

/// A cancellation request, addressed by a deterministic run-internal
/// coordinate rather than by wall-clock time or an ambient flag.
///
/// Cancellation is observed at the first cancellation boundary reached once
/// `after_steps` step executions have been recorded for the run. `0`
/// cancels before the entry step runs at all, which is the strongest form:
/// a run cancelled at `after_steps: 0` performs nothing and commits
/// nothing.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CancelSignal {
    pub after_steps: u32,
}

/// Observes a [`CancelSignal`] at the engine's defined cancellation
/// boundaries and remembers where it fired.
///
/// The boundaries are exactly two, both *between* steps and never inside
/// one: before the engine dispatches the next top-level step, and before it
/// dispatches the next branch of a `Parallel`. A step that has begun
/// executing is never interrupted part-way, so cancellation can never
/// split a step's effect from the engine's record of it — which is what
/// keeps at-most-once compensation intact across a cancellation.
///
/// `observe` latches: once cancellation has fired, the step it fired before
/// is remembered and never overwritten by a later boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CancelWatch {
    signal: Option<CancelSignal>,
    observed: Option<StepId>,
}

impl CancelWatch {
    #[must_use]
    pub fn new(signal: Option<CancelSignal>) -> Self {
        CancelWatch {
            signal,
            observed: None,
        }
    }

    /// Called at a cancellation boundary with the number of step executions
    /// already recorded and the step that would run next. Returns `true`
    /// when the run must stop before `next`.
    pub fn observe(&mut self, steps_executed: usize, next: StepId) -> bool {
        if self.observed.is_some() {
            return true;
        }
        let Some(signal) = self.signal else {
            return false;
        };
        if steps_executed as u64 >= u64::from(signal.after_steps) {
            self.observed = Some(next);
            return true;
        }
        false
    }

    /// The step the run stopped before, if cancellation was observed.
    #[must_use]
    pub fn observed(&self) -> Option<StepId> {
        self.observed
    }
}

/// How a run ended.
///
/// `Cancelled` is a terminal state in its own right, deliberately distinct
/// from every other outcome this module can produce: it is **not** success
/// (no `Terminal` step was reached), **not** a permanent failure (nothing
/// refused anything — the run was asked to stop), and **not**
/// [`super::retry::AttemptOutcomeClass::Uncertain`] (which classifies one
/// effect's delivery status, not a run's ending). The engine returns it as
/// a value on the `Ok` side because the partial trace and the commit record
/// it leaves behind are valid proof data the caller needs; it is never a
/// claim that the workflow succeeded, and
/// [`super::engine::ExecTrace::completed`] is the one predicate that says
/// so.
///
/// # Compensation entries of a cancelled run
///
/// Cancellation leaves every already-recorded
/// [`super::compensation_order::CommitRecord`] exactly as it was. It does
/// not erase, rewind, or compensate them, for the same reason
/// [`super::engine::run`] never compensates a failure: a commit record is
/// proof that an effect happened, and a run being cancelled afterwards does
/// not make it un-happen. The caller drives compensation for a cancelled
/// run exactly as for a failed one — read back
/// [`super::compensation_order::CommitLog::compensation_order`] and apply
/// its own [`super::compensation::CompensationLedger`] against it.
///
/// At-most-once therefore still holds without any special case:
/// compensation is keyed by
/// [`super::compensation::CompensationKey`]`{step, run}`, so replaying a
/// cancelled run under the same `run_id` and the same ledger re-derives the
/// identical commit order and every `apply` for an already-compensated step
/// returns
/// [`super::compensation::CompensationOutcome::AlreadyApplied`] without
/// running the effect a second time.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RunOutcome {
    /// The run reached a `Terminal` step.
    Completed,
    /// A [`CancelSignal`] was observed at a boundary, and the run stopped
    /// before executing `before`.
    Cancelled { before: StepId },
}

impl RunOutcome {
    /// True only for [`RunOutcome::Completed`]. The one place "did this
    /// workflow actually finish" is answered, so a caller cannot answer it
    /// by accident with a `Result::is_ok` that is also true for a cancelled
    /// run.
    #[must_use]
    pub fn completed(&self) -> bool {
        matches!(self, RunOutcome::Completed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::typed_workflow::graph::DeclaredStepKind;

    #[test]
    fn an_unbudgeted_meter_never_refuses_and_still_totals() {
        let mut meter = TickMeter::new(None);
        for _ in 0..1000 {
            assert_eq!(meter.charge(16), Ok(()));
        }
        assert_eq!(meter.spent(), 16_000);
    }

    #[test]
    fn a_budget_refuses_the_charge_that_would_exceed_it_and_stays_unspent() {
        let mut meter = TickMeter::new(Some(StepBudget { max_ticks: 10 }));
        assert_eq!(meter.charge(6), Ok(()));
        assert_eq!(
            meter.charge(6),
            Err(BudgetExhausted {
                spent: 6,
                requested: 6,
                limit: 10,
            })
        );
        // The refused charge is not spent: the work it would have paid for
        // never ran, so charging for it would misreport the run's cost.
        assert_eq!(meter.spent(), 6);
        // And the exact remaining budget is still spendable afterwards.
        assert_eq!(meter.charge(4), Ok(()));
        assert_eq!(meter.spent(), 10);
    }

    #[test]
    fn a_charge_exactly_at_the_limit_is_admitted() {
        let mut meter = TickMeter::new(Some(StepBudget { max_ticks: 16 }));
        assert_eq!(meter.charge(16), Ok(()));
        assert_eq!(meter.spent(), 16);
    }

    #[test]
    fn an_absurd_charge_saturates_instead_of_wrapping_into_looking_cheap() {
        let mut meter = TickMeter::new(Some(StepBudget {
            max_ticks: u64::MAX,
        }));
        assert_eq!(meter.charge(u64::MAX), Ok(()));
        // Without saturation this second charge would wrap to a small
        // number and be admitted as if the run had spent almost nothing.
        assert_eq!(meter.charge(u64::MAX), Ok(()));
        assert_eq!(meter.spent(), u64::MAX);
    }

    #[test]
    fn an_effectful_kind_costs_more_than_a_control_flow_kind() {
        assert!(
            step_cost(&StepKind::ModelCall {
                requested_model: "m".to_owned()
            }) > step_cost(&StepKind::Declared(DeclaredStepKind::AgentCall))
        );
        assert!(
            step_cost(&StepKind::Declared(DeclaredStepKind::AgentCall))
                > step_cost(&StepKind::Sequential)
        );
        assert_eq!(
            step_cost(&StepKind::Sequential),
            step_cost(&StepKind::Terminal)
        );
    }

    #[test]
    fn a_retry_attempt_costs_more_than_reaching_a_control_flow_step() {
        // The point of charging attempts at all: a step that keeps retrying
        // must drain the budget even though the step count does not move.
        assert!(RETRY_ATTEMPT_COST > step_cost(&StepKind::Sequential));
    }

    #[test]
    fn no_signal_never_observes_cancellation() {
        let mut watch = CancelWatch::new(None);
        for steps in 0..64 {
            assert!(!watch.observe(steps, StepId(7)));
        }
        assert_eq!(watch.observed(), None);
    }

    #[test]
    fn a_zero_coordinate_cancels_before_the_first_step_runs() {
        let mut watch = CancelWatch::new(Some(CancelSignal { after_steps: 0 }));
        assert!(watch.observe(0, StepId(0)));
        assert_eq!(watch.observed(), Some(StepId(0)));
    }

    #[test]
    fn cancellation_fires_at_the_first_boundary_past_the_coordinate_and_latches() {
        let mut watch = CancelWatch::new(Some(CancelSignal { after_steps: 2 }));
        assert!(!watch.observe(0, StepId(0)));
        assert!(!watch.observe(1, StepId(1)));
        assert!(watch.observe(2, StepId(2)));
        // Latched: a later boundary never moves the recorded step, so the
        // reported cancellation point is a function of the coordinate, not
        // of how many times a caller happened to ask.
        assert!(watch.observe(9, StepId(9)));
        assert_eq!(watch.observed(), Some(StepId(2)));
    }

    #[test]
    fn cancelled_is_not_completed() {
        assert!(RunOutcome::Completed.completed());
        assert!(!RunOutcome::Cancelled { before: StepId(3) }.completed());
    }
}
