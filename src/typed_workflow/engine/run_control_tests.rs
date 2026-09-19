//! Execution tests for the two run-control primitives issue #208's in-scope
//! list names and this engine previously had no concept of: a deterministic
//! **timeout** (a declared step-cost budget, never a wall clock) and
//! **cancellation** (cooperative, observed at defined boundaries, replayable
//! to the identical trace).
//!
//! Kept as its own file rather than grown onto `engine/tests.rs` per the
//! repository's module-size guidance, the same way
//! `engine/declared_dispatch_tests.rs` is.
//!
//! What these tests are built to catch, beyond "the feature works":
//!
//! - Budget exhaustion and retry-ceiling exhaustion must never collapse
//!   into one outcome. `budget_exhaustion_and_a_retry_ceiling_are_different_refusals`
//!   runs the *same* failing script twice, changing only which ceiling is
//!   reached first, and requires two different errors.
//! - A cancelled run must not be readable as a success.
//!   `a_cancelled_run_is_ok_but_never_completed` pins that `Result::is_ok`
//!   is not the success predicate.
//! - Cancellation must not break at-most-once compensation.
//!   `a_cancelled_run_replays_identically_and_never_compensates_twice`
//!   cancels, compensates, replays the same run id against the same ledger,
//!   and requires the effect to have run exactly once in total.

use super::*;
use crate::typed_workflow::claims::ClaimSet;
use crate::typed_workflow::compensation::{
    CompensationKey, CompensationLedger, CompensationOutcome,
};
use crate::typed_workflow::graph::{EdgeDef, EdgeId, Port, PortId, PortType, StepDef};
use crate::typed_workflow::run_control::{
    step_cost, BudgetExhausted, CancelSignal, RunOutcome, StepBudget, RETRY_ATTEMPT_COST,
};
use std::cell::Cell;

fn unit_port(id: u32) -> Port {
    Port {
        id: PortId(id),
        ty: PortType::Unit,
    }
}

fn seq(id: u32) -> StepDef {
    StepDef {
        id: StepId(id),
        kind: StepKind::Sequential,
        in_ports: vec![unit_port(0)],
        out_ports: vec![unit_port(0)],
    }
}

fn terminal(id: u32) -> StepDef {
    StepDef {
        id: StepId(id),
        kind: StepKind::Terminal,
        in_ports: vec![unit_port(0)],
        out_ports: vec![],
    }
}

fn edge(id: u32, from: u32, to: u32) -> EdgeDef {
    EdgeDef {
        id: EdgeId(id),
        from: StepId(from),
        from_port: PortId(0),
        to: StepId(to),
        to_port: PortId(0),
    }
}

/// `0 -> 1 -> 2 -> terminal(3)`, four steps of unit cost each.
fn pipeline() -> WorkflowGraph {
    WorkflowGraph {
        steps: vec![seq(0), seq(1), seq(2), terminal(3)],
        edges: vec![edge(0, 0, 1), edge(1, 1, 2), edge(2, 2, 3)],
        entry: StepId(0),
        claims: ClaimSet::none(),
    }
}

/// A `ModelCall` at `StepId(0)` followed by a terminal.
fn model_call_pipeline() -> WorkflowGraph {
    let call = StepDef {
        id: StepId(0),
        kind: StepKind::ModelCall {
            requested_model: "checked-small-1".to_string(),
        },
        in_ports: vec![unit_port(0)],
        out_ports: vec![unit_port(0)],
    };
    WorkflowGraph {
        steps: vec![call, terminal(1)],
        edges: vec![edge(0, 0, 1)],
        entry: StepId(0),
        claims: ClaimSet::none(),
    }
}

/// Two `Sequential` branches under one `Parallel`, recombining at a `Join`.
fn parallel_pipeline() -> WorkflowGraph {
    WorkflowGraph {
        steps: vec![
            StepDef {
                id: StepId(0),
                kind: StepKind::Parallel,
                in_ports: vec![],
                out_ports: vec![unit_port(0), unit_port(1)],
            },
            seq(10),
            seq(11),
            StepDef {
                id: StepId(1),
                kind: StepKind::Join {
                    parallel: StepId(0),
                },
                in_ports: vec![unit_port(0), unit_port(1)],
                out_ports: vec![unit_port(0)],
            },
            terminal(2),
        ],
        edges: vec![
            EdgeDef {
                id: EdgeId(0),
                from: StepId(0),
                from_port: PortId(0),
                to: StepId(10),
                to_port: PortId(0),
            },
            EdgeDef {
                id: EdgeId(1),
                from: StepId(0),
                from_port: PortId(1),
                to: StepId(11),
                to_port: PortId(0),
            },
            EdgeDef {
                id: EdgeId(2),
                from: StepId(10),
                from_port: PortId(0),
                to: StepId(1),
                to_port: PortId(0),
            },
            EdgeDef {
                id: EdgeId(3),
                from: StepId(11),
                from_port: PortId(0),
                to: StepId(1),
                to_port: PortId(1),
            },
            edge(4, 1, 2),
        ],
        entry: StepId(0),
        claims: ClaimSet::none(),
    }
}

fn run_fresh(graph: &WorkflowGraph, inputs: &ExecInputs) -> Result<ExecTrace, ExecError> {
    run(graph, inputs, &mut GateLedger::new(), &mut CommitLog::new())
}

// ---------------------------------------------------------------------------
// Step-cost budget: the deterministic stand-in for a timeout.
// ---------------------------------------------------------------------------

#[test]
fn a_run_declaring_no_budget_completes_and_still_reports_what_it_spent() {
    let trace = run_fresh(&pipeline(), &ExecInputs::default()).unwrap();
    assert_eq!(trace.outcome, RunOutcome::Completed);
    assert!(trace.completed());
    // Four unit-cost steps. Reported even with no budget declared, so a
    // caller can size one from a real run instead of guessing.
    assert_eq!(trace.ticks_spent, 4 * step_cost(&StepKind::Sequential));
}

#[test]
fn a_budget_sized_from_an_unbudgeted_run_admits_that_run_exactly() {
    let graph = pipeline();
    let measured = run_fresh(&graph, &ExecInputs::default())
        .unwrap()
        .ticks_spent;

    let mut exact = ExecInputs {
        step_budget: Some(StepBudget {
            max_ticks: measured,
        }),
        ..ExecInputs::default()
    };
    let trace = run_fresh(&graph, &exact).unwrap();
    assert!(trace.completed());
    assert_eq!(trace.ticks_spent, measured);

    // One tick less is the boundary: the last step's charge is refused.
    exact.step_budget = Some(StepBudget {
        max_ticks: measured - 1,
    });
    let error = run_fresh(&graph, &exact).unwrap_err();
    assert_eq!(
        error,
        ExecError::StepBudgetExhausted(
            StepId(3),
            BudgetExhausted {
                spent: measured - 1,
                requested: 1,
                limit: measured - 1,
            }
        )
    );
}

#[test]
fn the_step_a_budget_cannot_cover_never_runs_and_never_appears_as_visited() {
    // The distinction that matters for a trace being evidence: a refused
    // charge means the step did not execute, so it must not be recorded as
    // though it had.
    let graph = pipeline();
    let inputs = ExecInputs {
        step_budget: Some(StepBudget { max_ticks: 2 }),
        ..ExecInputs::default()
    };
    let error = run_fresh(&graph, &inputs).unwrap_err();
    assert!(matches!(
        error,
        ExecError::StepBudgetExhausted(StepId(2), _)
    ));

    // The same run without the budget visits all four, so the two the
    // budget cut off are genuinely missing rather than never reachable.
    let full = run_fresh(&graph, &ExecInputs::default()).unwrap();
    assert_eq!(
        full.visited,
        vec![StepId(0), StepId(1), StepId(2), StepId(3)]
    );
}

#[test]
fn budget_exhaustion_and_a_retry_ceiling_are_different_refusals() {
    // The same step, the same failing scripted attempts, two different
    // ceilings. Which one is reached first must decide *which* refusal is
    // returned -- these are different facts about the run and must never
    // collapse into one outcome.
    let graph = model_call_pipeline();
    let script = vec![
        ScriptedAttempt::failed(AttemptOutcomeClass::NotDispatched),
        ScriptedAttempt::failed(AttemptOutcomeClass::NotDispatched),
        ScriptedAttempt::failed(AttemptOutcomeClass::NotDispatched),
        ScriptedAttempt::failed(AttemptOutcomeClass::NotDispatched),
    ];
    let mut inputs = ExecInputs::default();
    inputs.model_policies.insert(
        StepId(0),
        DeploymentPolicy::new(["checked-small-1".to_string()]),
    );
    inputs.attempt_script.insert(StepId(0), script);

    // (a) A tight retry ceiling, no cost budget: the retry ceiling wins.
    inputs
        .retry_budgets
        .insert(StepId(0), RetryBudget { max_attempts: 2 });
    assert_eq!(
        run_fresh(&graph, &inputs).unwrap_err(),
        ExecError::StepFailed(StepId(0), AttemptOutcomeClass::NotDispatched)
    );

    // (b) A generous retry ceiling and a cost budget that runs out inside
    // the retry loop: the budget wins, with its own refusal. This is the
    // case a wall-clock timeout would otherwise be reached for -- a step
    // retrying for a long time while the step count never advances.
    inputs
        .retry_budgets
        .insert(StepId(0), RetryBudget { max_attempts: 64 });
    inputs.step_budget = Some(StepBudget {
        max_ticks: step_cost(&StepKind::ModelCall {
            requested_model: "checked-small-1".to_string(),
        }) + RETRY_ATTEMPT_COST,
    });
    let error = run_fresh(&graph, &inputs).unwrap_err();
    assert!(
        matches!(error, ExecError::StepBudgetExhausted(StepId(0), _)),
        "expected a budget refusal, got {error:?}"
    );
    // And explicitly not the retry-ceiling refusal, nor anything carrying an
    // `Uncertain` classification: nothing was dispatched to be uncertain
    // about, because the charge was refused before the attempt.
    assert!(!matches!(error, ExecError::StepFailed(..)));
}

#[test]
fn a_declared_budget_bounds_a_bounded_loop_the_step_limit_would_have_allowed() {
    // A `Loop` step bounded at 64 iterations is well within
    // `MAX_STEP_EXECUTIONS`, so the existing ceiling never fires. The cost
    // budget is what cuts it short, which is the point: it bounds a run
    // that is already structurally legal.
    let looped = StepDef {
        id: StepId(0),
        kind: StepKind::Loop { max_iterations: 64 },
        in_ports: vec![unit_port(0)],
        out_ports: vec![unit_port(0)],
    };
    // No terminal: the loop is the whole graph, so nothing is unreachable
    // and the only way out is a bound being reached.
    let graph = WorkflowGraph {
        steps: vec![looped, seq(1)],
        edges: vec![edge(0, 0, 1), edge(1, 1, 0)],
        entry: StepId(0),
        claims: ClaimSet::none(),
    };
    // Unbudgeted, this run ends at the loop bound, not at the step limit.
    assert_eq!(
        run_fresh(&graph, &ExecInputs::default()).unwrap_err(),
        ExecError::LoopBoundExceeded(StepId(0))
    );
    let inputs = ExecInputs {
        step_budget: Some(StepBudget { max_ticks: 5 }),
        ..ExecInputs::default()
    };
    assert!(matches!(
        run_fresh(&graph, &inputs).unwrap_err(),
        ExecError::StepBudgetExhausted(..)
    ));
}

#[test]
fn the_same_budgeted_run_is_byte_identical_across_repeated_runs() {
    let graph = pipeline();
    let inputs = ExecInputs {
        step_budget: Some(StepBudget { max_ticks: 3 }),
        ..ExecInputs::default()
    };
    let first = run_fresh(&graph, &inputs);
    let second = run_fresh(&graph, &inputs);
    let third = run_fresh(&graph, &inputs);
    assert_eq!(first, second);
    assert_eq!(second, third);
}

// ---------------------------------------------------------------------------
// Cancellation.
// ---------------------------------------------------------------------------

#[test]
fn a_cancelled_run_is_ok_but_never_completed() {
    let graph = pipeline();
    let inputs = ExecInputs {
        cancel: Some(CancelSignal { after_steps: 2 }),
        ..ExecInputs::default()
    };
    let trace = run_fresh(&graph, &inputs).expect("cancellation is a terminal state, not an error");
    // `is_ok` is deliberately NOT the success predicate: a cancelled run
    // carries a valid partial trace and must never be read as a workflow
    // that finished.
    assert!(!trace.completed());
    assert_eq!(trace.outcome, RunOutcome::Cancelled { before: StepId(2) });
    assert_eq!(trace.visited, vec![StepId(0), StepId(1)]);
}

#[test]
fn cancelling_before_the_first_step_performs_and_commits_nothing() {
    let graph = pipeline();
    let inputs = ExecInputs {
        cancel: Some(CancelSignal { after_steps: 0 }),
        ..ExecInputs::default()
    };
    let mut commits = CommitLog::new();
    let trace = run(&graph, &inputs, &mut GateLedger::new(), &mut commits).unwrap();
    assert_eq!(trace.outcome, RunOutcome::Cancelled { before: StepId(0) });
    assert!(trace.visited.is_empty());
    assert_eq!(trace.ticks_spent, 0);
    assert!(commits.commits().is_empty());
}

#[test]
fn a_cancelled_run_is_a_prefix_of_the_uncancelled_one_and_replays_identically() {
    let graph = pipeline();
    let inputs = ExecInputs {
        cancel: Some(CancelSignal { after_steps: 3 }),
        ..ExecInputs::default()
    };
    let cancelled = run_fresh(&graph, &inputs).unwrap();
    let full = run_fresh(&graph, &ExecInputs::default()).unwrap();
    assert_eq!(cancelled.visited, full.visited[..3].to_vec());

    // Three separate runs of the identical inputs, each with its own fresh
    // ledgers: replayability is what makes a cancelled run's trace evidence
    // rather than an artifact of when someone pressed stop.
    let again = run_fresh(&graph, &inputs).unwrap();
    let once_more = run_fresh(&graph, &inputs).unwrap();
    assert_eq!(cancelled, again);
    assert_eq!(again, once_more);
}

#[test]
fn cancellation_between_parallel_branches_stops_before_the_next_and_never_joins() {
    let graph = parallel_pipeline();
    // Uncancelled: Parallel(0), branch 10, branch 11, Join(1), Terminal(2).
    let full = run_fresh(&graph, &ExecInputs::default()).unwrap();
    assert_eq!(
        full.visited,
        vec![StepId(0), StepId(10), StepId(11), StepId(1), StepId(2)]
    );
    assert!(full.completed());

    // Cancelled at the second branch boundary: the first branch ran, the
    // second never did, and the Join -- which would have meant "every
    // branch arrived" -- is never recorded.
    let inputs = ExecInputs {
        cancel: Some(CancelSignal { after_steps: 2 }),
        ..ExecInputs::default()
    };
    let trace = run_fresh(&graph, &inputs).unwrap();
    assert_eq!(trace.visited, vec![StepId(0), StepId(10)]);
    assert_eq!(trace.outcome, RunOutcome::Cancelled { before: StepId(11) });
    assert!(!trace.visited.contains(&StepId(1)));
    assert!(!trace.visited.contains(&StepId(2)));
}

#[test]
fn a_cancelled_run_keeps_its_commits_and_never_compensates_them_itself() {
    // A compensable ModelCall commits, then the run is cancelled before the
    // terminal. The commit record must survive: cancelling a run does not
    // un-happen an effect that already occurred, and `run` never performs
    // the compensation itself either way.
    let graph = model_call_pipeline();
    let mut inputs = ExecInputs {
        cancel: Some(CancelSignal { after_steps: 1 }),
        run_id: 7,
        ..ExecInputs::default()
    };
    inputs.model_policies.insert(
        StepId(0),
        DeploymentPolicy::new(["checked-small-1".to_string()]),
    );
    inputs.compensable.insert(StepId(0));

    let mut commits = CommitLog::new();
    let trace = run(&graph, &inputs, &mut GateLedger::new(), &mut commits).unwrap();
    assert_eq!(trace.outcome, RunOutcome::Cancelled { before: StepId(1) });
    let recorded: Vec<StepId> = commits.commits().iter().map(|c| c.step).collect();
    assert_eq!(recorded, vec![StepId(0)]);
}

#[test]
fn a_cancelled_run_replays_identically_and_never_compensates_twice() {
    // At-most-once across a cancellation: cancel, compensate what
    // committed, then replay the *same* run id against the *same*
    // compensation ledger. The replay re-derives the identical trace and
    // identical commit order, and every compensation is already applied --
    // so the effect runs exactly once in total.
    let graph = model_call_pipeline();
    let mut inputs = ExecInputs {
        cancel: Some(CancelSignal { after_steps: 1 }),
        run_id: 11,
        ..ExecInputs::default()
    };
    inputs.model_policies.insert(
        StepId(0),
        DeploymentPolicy::new(["checked-small-1".to_string()]),
    );
    inputs.compensable.insert(StepId(0));

    let mut ledger = CompensationLedger::new();
    let effects_run = Cell::new(0);

    let mut first_commits = CommitLog::new();
    let first = run(&graph, &inputs, &mut GateLedger::new(), &mut first_commits).unwrap();
    for record in first_commits.compensation_order().required() {
        let outcome = ledger.apply(
            CompensationKey {
                step: record.step,
                run: record.run,
            },
            || {
                effects_run.set(effects_run.get() + 1);
                Ok(())
            },
        );
        assert_eq!(outcome, Ok(CompensationOutcome::Applied));
    }
    assert_eq!(effects_run.get(), 1);

    let mut second_commits = CommitLog::new();
    let second = run(&graph, &inputs, &mut GateLedger::new(), &mut second_commits).unwrap();
    assert_eq!(
        first, second,
        "a cancelled run must replay to the same trace"
    );
    assert_eq!(
        first_commits.compensation_order().canonical_bytes(),
        second_commits.compensation_order().canonical_bytes()
    );
    for record in second_commits.compensation_order().required() {
        let outcome = ledger.apply(
            CompensationKey {
                step: record.step,
                run: record.run,
            },
            || {
                effects_run.set(effects_run.get() + 1);
                Ok(())
            },
        );
        assert_eq!(outcome, Ok(CompensationOutcome::AlreadyApplied));
    }
    assert_eq!(
        effects_run.get(),
        1,
        "at-most-once must survive cancellation and replay"
    );
}

#[test]
fn cancellation_and_a_budget_do_not_mask_each_other() {
    // Cancellation is observed at a boundary *before* the next step is
    // charged, so a run cancelled at a boundary the budget could not have
    // passed anyway still reports cancellation -- a deliberate,
    // documented precedence rather than whichever check happened to be
    // written first.
    let graph = pipeline();
    let inputs = ExecInputs {
        cancel: Some(CancelSignal { after_steps: 2 }),
        step_budget: Some(StepBudget { max_ticks: 2 }),
        ..ExecInputs::default()
    };
    let trace = run_fresh(&graph, &inputs).unwrap();
    assert_eq!(trace.outcome, RunOutcome::Cancelled { before: StepId(2) });
    assert_eq!(trace.ticks_spent, 2);
}
