use super::*;
use crate::typed_workflow::checkpoint::RevisionId;
use crate::typed_workflow::graph::{
    DeclaredStepKind, EdgeDef, EdgeId, Port, PortId, PortType, StepDef,
};
use crate::typed_workflow::human_gate::Role;

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

fn edge(id: u32, from: u32, to: u32) -> EdgeDef {
    EdgeDef {
        id: EdgeId(id),
        from: StepId(from),
        from_port: PortId(0),
        to: StepId(to),
        to_port: PortId(0),
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

#[test]
fn sequential_pipeline_runs_to_completion_deterministically() {
    let graph = WorkflowGraph {
        steps: vec![seq(0), seq(1), terminal(2)],
        edges: vec![edge(0, 0, 1), edge(1, 1, 2)],
        entry: StepId(0),
    };
    let inputs = ExecInputs::default();
    let first = run(
        &graph,
        &inputs,
        &mut GateLedger::new(),
        &mut CommitLog::new(),
    )
    .unwrap();
    let second = run(
        &graph,
        &inputs,
        &mut GateLedger::new(),
        &mut CommitLog::new(),
    )
    .unwrap();
    assert_eq!(first, second);
    assert_eq!(first.visited, vec![StepId(0), StepId(1), StepId(2)]);
}

fn conditional_graph() -> WorkflowGraph {
    let cond = StepDef {
        id: StepId(0),
        kind: StepKind::Conditional {
            condition_port: PortId(0),
        },
        in_ports: vec![Port {
            id: PortId(0),
            ty: PortType::Bool,
        }],
        out_ports: vec![unit_port(0), unit_port(1)],
    };
    WorkflowGraph {
        steps: vec![cond, terminal(1), terminal(2)],
        edges: vec![
            EdgeDef {
                id: EdgeId(0),
                from: StepId(0),
                from_port: THEN_PORT,
                to: StepId(1),
                to_port: PortId(0),
            },
            EdgeDef {
                id: EdgeId(1),
                from: StepId(0),
                from_port: ELSE_PORT,
                to: StepId(2),
                to_port: PortId(0),
            },
        ],
        entry: StepId(0),
    }
}

#[test]
fn conditional_true_follows_then_branch() {
    let graph = conditional_graph();
    let mut inputs = ExecInputs::default();
    inputs.conditions.insert(StepId(0), true);
    let trace = run(
        &graph,
        &inputs,
        &mut GateLedger::new(),
        &mut CommitLog::new(),
    )
    .unwrap();
    assert_eq!(trace.visited, vec![StepId(0), StepId(1)]);
}

#[test]
fn conditional_false_follows_else_branch() {
    let graph = conditional_graph();
    let mut inputs = ExecInputs::default();
    inputs.conditions.insert(StepId(0), false);
    let trace = run(
        &graph,
        &inputs,
        &mut GateLedger::new(),
        &mut CommitLog::new(),
    )
    .unwrap();
    assert_eq!(trace.visited, vec![StepId(0), StepId(2)]);
}

#[test]
fn missing_condition_input_is_a_defined_refusal_not_a_default_branch() {
    let graph = conditional_graph();
    let inputs = ExecInputs::default();
    assert_eq!(
        run(
            &graph,
            &inputs,
            &mut GateLedger::new(),
            &mut CommitLog::new()
        ),
        Err(ExecError::MissingConditionInput(StepId(0)))
    );
}

fn looping_graph(max_iterations: u32) -> WorkflowGraph {
    let looper = StepDef {
        id: StepId(0),
        kind: StepKind::Loop { max_iterations },
        in_ports: vec![unit_port(0)],
        out_ports: vec![unit_port(0)],
    };
    WorkflowGraph {
        steps: vec![looper, seq(1)],
        edges: vec![edge(0, 0, 1), edge(1, 1, 0)],
        entry: StepId(0),
    }
}

#[test]
fn loop_runs_up_to_its_bound_then_refuses() {
    let graph = looping_graph(2);
    let inputs = ExecInputs::default();
    let err = run(
        &graph,
        &inputs,
        &mut GateLedger::new(),
        &mut CommitLog::new(),
    )
    .unwrap_err();
    assert_eq!(err, ExecError::LoopBoundExceeded(StepId(0)));
}

#[test]
fn loop_step_within_its_bound_runs_to_completion() {
    // A `Loop` step that is only ever entered once (no back edge here)
    // never approaches its bound, and the workflow completes normally.
    let looper = StepDef {
        id: StepId(0),
        kind: StepKind::Loop { max_iterations: 1 },
        in_ports: vec![unit_port(0)],
        out_ports: vec![unit_port(0)],
    };
    let graph = WorkflowGraph {
        steps: vec![looper, seq(1), terminal(2)],
        edges: vec![edge(0, 0, 1), edge(1, 1, 2)],
        entry: StepId(0),
    };
    let trace = run(
        &graph,
        &ExecInputs::default(),
        &mut GateLedger::new(),
        &mut CommitLog::new(),
    )
    .unwrap();
    assert_eq!(trace.visited, vec![StepId(0), StepId(1), StepId(2)]);
}

fn model_call_graph(requested: &str) -> WorkflowGraph {
    let call = StepDef {
        id: StepId(0),
        kind: StepKind::ModelCall {
            requested_model: requested.to_string(),
        },
        in_ports: vec![unit_port(0)],
        out_ports: vec![unit_port(0)],
    };
    WorkflowGraph {
        steps: vec![call, terminal(1)],
        edges: vec![edge(0, 0, 1)],
        entry: StepId(0),
    }
}

#[test]
fn model_call_routes_within_policy_and_records_it() {
    let graph = model_call_graph("checked-small-1");
    let mut inputs = ExecInputs::default();
    inputs.model_policies.insert(
        StepId(0),
        DeploymentPolicy::new(["checked-small-1".to_string()]),
    );
    let trace = run(
        &graph,
        &inputs,
        &mut GateLedger::new(),
        &mut CommitLog::new(),
    )
    .unwrap();
    assert_eq!(
        trace.routed_models,
        vec![(StepId(0), "checked-small-1".to_string())]
    );
}

#[test]
fn model_call_outside_policy_is_refused_not_substituted() {
    let graph = model_call_graph("unlisted-model");
    let mut inputs = ExecInputs::default();
    inputs.model_policies.insert(
        StepId(0),
        DeploymentPolicy::new(["checked-small-1".to_string()]),
    );
    assert_eq!(
        run(
            &graph,
            &inputs,
            &mut GateLedger::new(),
            &mut CommitLog::new()
        ),
        Err(ExecError::RoutingRefused(
            StepId(0),
            RoutingError::NotInPolicy
        ))
    );
}

#[test]
fn invalid_graph_is_refused_before_any_step_runs() {
    let graph = WorkflowGraph {
        steps: vec![seq(0)],
        edges: vec![],
        entry: StepId(0),
    };
    assert_eq!(
        run(
            &graph,
            &ExecInputs::default(),
            &mut GateLedger::new(),
            &mut CommitLog::new()
        ),
        Err(ExecError::InvalidGraph)
    );
}

// -----------------------------------------------------------------
// Human gate wiring: reaching the gate must never itself authorize it.
// -----------------------------------------------------------------

fn gated_graph() -> WorkflowGraph {
    let gate = StepDef {
        id: StepId(0),
        kind: StepKind::HumanGate,
        in_ports: vec![unit_port(0)],
        out_ports: vec![unit_port(0)],
    };
    WorkflowGraph {
        steps: vec![gate, terminal(1)],
        edges: vec![edge(7, 0, 1)],
        entry: StepId(0),
    }
}

fn gate_spec() -> GateSpec {
    GateSpec {
        revision: RevisionId(1),
        candidate_digest: [3u8; 32],
        required_role: Role("release-manager".to_string()),
        expires_at: 1_000,
        grants_edge: EdgeId(7),
    }
}

fn gate_decision(id: u64) -> GateDecision {
    GateDecision {
        decision_id: id,
        revision: RevisionId(1),
        candidate_digest: [3u8; 32],
        role: Role("release-manager".to_string()),
        decided_at: 500,
        approve: true,
    }
}

/// The property item 1 exists to prove: a gated step's downstream edge
/// is never taken before its gate resolves. With no spec and no
/// decision supplied at all, the engine must stop *at* the gate with a
/// defined error — the terminal step immediately past it must never be
/// reported as visited.
#[test]
fn human_gate_step_cannot_execute_before_its_gate_resolves() {
    let graph = gated_graph();
    let err = run(
        &graph,
        &ExecInputs::default(),
        &mut GateLedger::new(),
        &mut CommitLog::new(),
    )
    .unwrap_err();
    assert_eq!(err, ExecError::GateNotDecided(StepId(0)));
    // `run` returns `Err`, not a partial `ExecTrace` — there is no
    // route to inspect a `visited` list that snuck past the gate. The
    // absence of any such list *is* the proof: nothing past the gate
    // ever ran.
}

#[test]
fn human_gate_with_a_spec_but_no_decision_still_cannot_execute() {
    let graph = gated_graph();
    let mut inputs = ExecInputs::default();
    inputs.gate_specs.insert(StepId(0), gate_spec());
    // Deliberately no `gate_decisions` entry: reaching the gate and a
    // spec existing for it are still not permission.
    assert_eq!(
        run(
            &graph,
            &inputs,
            &mut GateLedger::new(),
            &mut CommitLog::new()
        ),
        Err(ExecError::GateNotDecided(StepId(0)))
    );
}

#[test]
fn human_gate_with_an_approved_decision_proceeds_to_the_named_edge() {
    let graph = gated_graph();
    let mut inputs = ExecInputs::default();
    inputs.gate_specs.insert(StepId(0), gate_spec());
    inputs.gate_decisions.insert(StepId(0), gate_decision(1));
    let trace = run(
        &graph,
        &inputs,
        &mut GateLedger::new(),
        &mut CommitLog::new(),
    )
    .unwrap();
    assert_eq!(trace.visited, vec![StepId(0), StepId(1)]);
}

#[test]
fn human_gate_wrong_role_decision_is_refused_not_substituted() {
    let graph = gated_graph();
    let mut inputs = ExecInputs::default();
    inputs.gate_specs.insert(StepId(0), gate_spec());
    let mut wrong_role = gate_decision(1);
    wrong_role.role = Role("intern".to_string());
    inputs.gate_decisions.insert(StepId(0), wrong_role);
    assert_eq!(
        run(
            &graph,
            &inputs,
            &mut GateLedger::new(),
            &mut CommitLog::new()
        ),
        Err(ExecError::GateRefused(StepId(0), GateError::WrongRole))
    );
}

#[test]
fn human_gate_replayed_decision_id_is_refused_even_on_a_fresh_run() {
    let graph = gated_graph();
    let mut inputs = ExecInputs::default();
    inputs.gate_specs.insert(StepId(0), gate_spec());
    inputs.gate_decisions.insert(StepId(0), gate_decision(9));

    let mut ledger = GateLedger::new();
    assert!(run(&graph, &inputs, &mut ledger, &mut CommitLog::new()).is_ok());
    // Same ledger, same decision id, a second run of the same graph:
    // the second run must not re-spend the same human decision.
    assert_eq!(
        run(&graph, &inputs, &mut ledger, &mut CommitLog::new()),
        Err(ExecError::GateRefused(StepId(0), GateError::Replayed))
    );
}

#[test]
fn human_gate_spec_naming_a_foreign_edge_is_refused() {
    let graph = gated_graph();
    let mut inputs = ExecInputs::default();
    let mut mismatched = gate_spec();
    mismatched.grants_edge = EdgeId(999); // does not leave StepId(0)
    inputs.gate_specs.insert(StepId(0), mismatched);
    inputs.gate_decisions.insert(StepId(0), gate_decision(1));
    assert_eq!(
        run(
            &graph,
            &inputs,
            &mut GateLedger::new(),
            &mut CommitLog::new()
        ),
        Err(ExecError::GateEdgeMismatch(StepId(0)))
    );
}

// -----------------------------------------------------------------
// Parallel / Join: deterministic sequential simulation.
// -----------------------------------------------------------------

/// `branch_count` single-step branches, each `Sequential`, fanning out
/// from a `Parallel` and back into one `Join`, then a shared
/// `Terminal`. Edge ids are declared in descending branch order on
/// purpose, so a test relying on ascending edge-declaration order
/// (instead of ascending `StepId`) would fail.
fn parallel_join_graph(branch_count: u32) -> WorkflowGraph {
    let mut steps = vec![StepDef {
        id: StepId(0),
        kind: StepKind::Parallel,
        in_ports: vec![],
        out_ports: (0..branch_count).map(unit_port).collect(),
    }];
    let mut edges = Vec::new();
    for i in (0..branch_count).rev() {
        let branch_id = 10 + i;
        steps.push(seq(branch_id));
        edges.push(EdgeDef {
            id: EdgeId(i),
            from: StepId(0),
            from_port: PortId(i),
            to: StepId(branch_id),
            to_port: PortId(0),
        });
        edges.push(EdgeDef {
            id: EdgeId(100 + i),
            from: StepId(branch_id),
            from_port: PortId(0),
            to: StepId(1),
            to_port: PortId(i),
        });
    }
    steps.push(StepDef {
        id: StepId(1),
        kind: StepKind::Join {
            parallel: StepId(0),
        },
        in_ports: (0..branch_count).map(unit_port).collect(),
        out_ports: vec![unit_port(0)],
    });
    steps.push(terminal(2));
    edges.push(edge(999, 1, 2));
    WorkflowGraph {
        steps,
        edges,
        entry: StepId(0),
    }
}

#[test]
fn parallel_join_runs_every_branch_and_continues_past_the_join() {
    let graph = parallel_join_graph(3);
    let trace = run(
        &graph,
        &ExecInputs::default(),
        &mut GateLedger::new(),
        &mut CommitLog::new(),
    )
    .unwrap();
    assert_eq!(
        trace.visited,
        vec![
            StepId(0),
            StepId(10),
            StepId(11),
            StepId(12),
            StepId(1),
            StepId(2),
        ],
        "branches must run in ascending StepId order, not edge-declaration order"
    );
}

#[test]
fn parallel_join_execution_is_deterministic_across_repeated_runs() {
    let graph = parallel_join_graph(4);
    let inputs = ExecInputs::default();
    let first = run(
        &graph,
        &inputs,
        &mut GateLedger::new(),
        &mut CommitLog::new(),
    )
    .unwrap();
    let second = run(
        &graph,
        &inputs,
        &mut GateLedger::new(),
        &mut CommitLog::new(),
    )
    .unwrap();
    let third = run(
        &graph,
        &inputs,
        &mut GateLedger::new(),
        &mut CommitLog::new(),
    )
    .unwrap();
    assert_eq!(first, second);
    assert_eq!(second, third);
}

#[test]
fn parallel_join_routes_a_model_call_branch_and_records_it_in_branch_order() {
    let mut graph = parallel_join_graph(2);
    // Replace branch StepId(11) with a ModelCall step so a branch can
    // perform a routed effect, not just a bare Sequential pass-through.
    for step in &mut graph.steps {
        if step.id == StepId(11) {
            step.kind = StepKind::ModelCall {
                requested_model: "checked-small-1".to_string(),
            };
        }
    }
    let mut inputs = ExecInputs::default();
    inputs.model_policies.insert(
        StepId(11),
        DeploymentPolicy::new(["checked-small-1".to_string()]),
    );
    let trace = run(
        &graph,
        &inputs,
        &mut GateLedger::new(),
        &mut CommitLog::new(),
    )
    .unwrap();
    assert_eq!(
        trace.routed_models,
        vec![(StepId(11), "checked-small-1".to_string())]
    );
}

#[test]
fn parallel_with_no_join_referencing_it_is_a_defined_refusal() {
    // Two branches, each wired straight to its own Terminal instead of
    // a shared Join: structurally valid per `WorkflowGraph::validate`
    // (nothing requires a Parallel to recombine), but this engine only
    // knows how to run a Parallel a Join is waiting on.
    let graph = WorkflowGraph {
        steps: vec![
            StepDef {
                id: StepId(0),
                kind: StepKind::Parallel,
                in_ports: vec![],
                out_ports: vec![unit_port(0), unit_port(1)],
            },
            seq(10),
            seq(11),
            terminal(20),
            terminal(21),
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
            edge(2, 10, 20),
            edge(3, 11, 21),
        ],
        entry: StepId(0),
    };
    assert_eq!(graph.validate(), Ok(()));
    assert_eq!(
        run(
            &graph,
            &ExecInputs::default(),
            &mut GateLedger::new(),
            &mut CommitLog::new()
        ),
        Err(ExecError::NoJoinForParallel(StepId(0)))
    );
}

#[test]
fn join_step_dispatched_directly_is_refused_not_only_reachable_via_its_parallel() {
    // `ParallelExecutor` is the only code path that ever legitimately
    // advances past a `Join` step, immediately after it has itself run
    // every one of that `Join`'s branches. Dispatching the `Join` step
    // directly — simulating any other, uncoordinated call site that
    // might otherwise try to step onto it — must refuse rather than
    // silently taking its one out edge.
    let graph = parallel_join_graph(2);
    let mut visited = Vec::new();
    let mut loop_counts = BTreeMap::new();
    let mut ledger = GateLedger::new();
    let mut commits = CommitLog::new();
    let err = dispatch_step(
        StepId(1), // the Join step
        &graph,
        &ExecInputs::default(),
        &mut ledger,
        &mut commits,
        &mut loop_counts,
        &mut visited,
    )
    .unwrap_err();
    assert_eq!(err, ExecError::NotExecutable(StepId(1)));
}

#[test]
fn human_gate_step_is_never_silently_executed() {
    // A HumanGate that dispatch never routes to NotExecutableExecutor:
    // confirms the dispatch table itself, not just `run`, treats
    // HumanGate as a real (gated) executor rather than a refusal.
    let mut visited = Vec::new();
    let mut loop_counts = BTreeMap::new();
    let mut ledger = GateLedger::new();
    let mut commits = CommitLog::new();
    let graph = gated_graph();
    let err = dispatch_step(
        StepId(0),
        &graph,
        &ExecInputs::default(),
        &mut ledger,
        &mut commits,
        &mut loop_counts,
        &mut visited,
    )
    .unwrap_err();
    assert_eq!(err, ExecError::GateNotDecided(StepId(0)));
}

#[test]
fn declared_step_kind_is_never_silently_executed() {
    let declared = StepDef {
        id: StepId(0),
        kind: StepKind::Declared(DeclaredStepKind::Job),
        in_ports: vec![unit_port(0)],
        out_ports: vec![unit_port(0)],
    };
    let graph = WorkflowGraph {
        steps: vec![declared, terminal(1)],
        edges: vec![edge(0, 0, 1)],
        entry: StepId(0),
    };
    assert_eq!(
        run(
            &graph,
            &ExecInputs::default(),
            &mut GateLedger::new(),
            &mut CommitLog::new()
        ),
        Err(ExecError::NotExecutable(StepId(0)))
    );
}

// -----------------------------------------------------------------
// Retry ceiling and compensation ordering, driven through `run`.
// -----------------------------------------------------------------

#[test]
fn retry_ceiling_stops_before_a_later_scripted_success() {
    // Budget of 2 attempts; the script has a 3rd entry that would
    // succeed. If the ceiling were not genuinely enforced -- if the
    // engine kept consuming scripted attempts while
    // `ProviderReportedRetryable` classifications kept arriving,
    // ignoring `max_attempts` -- this would observe `Ok(..)` because
    // attempt 3 succeeds. A genuinely enforced ceiling means `run` must
    // fail after exactly the 2nd attempt, never reaching attempt 3.
    let graph = model_call_graph("checked-small-1");
    let mut inputs = ExecInputs::default();
    inputs.model_policies.insert(
        StepId(0),
        DeploymentPolicy::new(["checked-small-1".to_string()]),
    );
    inputs
        .retry_budgets
        .insert(StepId(0), RetryBudget { max_attempts: 2 });
    inputs.attempt_script.insert(
        StepId(0),
        vec![
            ScriptedAttempt::failed(AttemptOutcomeClass::ProviderReportedRetryable),
            ScriptedAttempt::failed(AttemptOutcomeClass::ProviderReportedRetryable),
            ScriptedAttempt::success(),
        ],
    );
    let err = run(
        &graph,
        &inputs,
        &mut GateLedger::new(),
        &mut CommitLog::new(),
    )
    .unwrap_err();
    assert_eq!(
        err,
        ExecError::StepFailed(StepId(0), AttemptOutcomeClass::ProviderReportedRetryable)
    );
}

#[test]
fn a_budget_with_room_actually_retries_to_a_later_success() {
    // The mirror case: with enough budget, the same two failed attempts
    // are absorbed and the third, succeeding, scripted attempt is
    // actually reached -- proving the loop advances through the script
    // rather than merely deciding in the abstract.
    let graph = model_call_graph("checked-small-1");
    let mut inputs = ExecInputs::default();
    inputs.model_policies.insert(
        StepId(0),
        DeploymentPolicy::new(["checked-small-1".to_string()]),
    );
    inputs
        .retry_budgets
        .insert(StepId(0), RetryBudget { max_attempts: 3 });
    inputs.attempt_script.insert(
        StepId(0),
        vec![
            ScriptedAttempt::failed(AttemptOutcomeClass::ProviderReportedRetryable),
            ScriptedAttempt::failed(AttemptOutcomeClass::ProviderReportedRetryable),
            ScriptedAttempt::success(),
        ],
    );
    let trace = run(
        &graph,
        &inputs,
        &mut GateLedger::new(),
        &mut CommitLog::new(),
    )
    .unwrap();
    assert_eq!(
        trace.routed_models,
        vec![(StepId(0), "checked-small-1".to_string())]
    );
}

#[test]
fn uncertain_outcome_stops_before_a_later_scripted_success() {
    // Ten attempts of budget, but the very first attempt is classified
    // `Uncertain` -- never safe to retry per `retry_is_permitted`,
    // regardless of remaining budget. A second scripted entry that
    // would succeed must never be reached.
    let graph = model_call_graph("checked-small-1");
    let mut inputs = ExecInputs::default();
    inputs.model_policies.insert(
        StepId(0),
        DeploymentPolicy::new(["checked-small-1".to_string()]),
    );
    inputs
        .retry_budgets
        .insert(StepId(0), RetryBudget { max_attempts: 10 });
    inputs.attempt_script.insert(
        StepId(0),
        vec![
            ScriptedAttempt::failed(AttemptOutcomeClass::Uncertain),
            ScriptedAttempt::success(),
        ],
    );
    let err = run(
        &graph,
        &inputs,
        &mut GateLedger::new(),
        &mut CommitLog::new(),
    )
    .unwrap_err();
    assert_eq!(
        err,
        ExecError::StepFailed(StepId(0), AttemptOutcomeClass::Uncertain)
    );
}

#[test]
fn model_call_with_no_script_is_unaffected_by_retry_wiring() {
    // Backward-compatibility guard: a `ModelCall` step with no
    // `attempt_script` entry behaves exactly as before this change --
    // no retry loop, and no `MissingRetryBudget` refusal even though no
    // budget was supplied.
    let graph = model_call_graph("checked-small-1");
    let mut inputs = ExecInputs::default();
    inputs.model_policies.insert(
        StepId(0),
        DeploymentPolicy::new(["checked-small-1".to_string()]),
    );
    let trace = run(
        &graph,
        &inputs,
        &mut GateLedger::new(),
        &mut CommitLog::new(),
    )
    .unwrap();
    assert_eq!(
        trace.routed_models,
        vec![(StepId(0), "checked-small-1".to_string())]
    );
}

#[test]
fn scripted_step_with_no_retry_budget_is_a_defined_refusal() {
    let graph = model_call_graph("checked-small-1");
    let mut inputs = ExecInputs::default();
    inputs.model_policies.insert(
        StepId(0),
        DeploymentPolicy::new(["checked-small-1".to_string()]),
    );
    inputs
        .attempt_script
        .insert(StepId(0), vec![ScriptedAttempt::success()]);
    // Deliberately no `retry_budgets` entry.
    assert_eq!(
        run(
            &graph,
            &inputs,
            &mut GateLedger::new(),
            &mut CommitLog::new()
        ),
        Err(ExecError::MissingRetryBudget(StepId(0)))
    );
}

/// Three `ModelCall` steps in sequence, ending in a `Terminal`.
fn compensable_pipeline() -> WorkflowGraph {
    fn model_call(id: u32, model: &str) -> StepDef {
        StepDef {
            id: StepId(id),
            kind: StepKind::ModelCall {
                requested_model: model.to_string(),
            },
            in_ports: vec![unit_port(0)],
            out_ports: vec![unit_port(0)],
        }
    }
    WorkflowGraph {
        steps: vec![
            model_call(0, "checked-small-1"),
            model_call(1, "checked-small-1"),
            model_call(2, "checked-small-1"),
            terminal(3),
        ],
        edges: vec![edge(0, 0, 1), edge(1, 1, 2), edge(2, 2, 3)],
        entry: StepId(0),
    }
}

/// The property that matters most for #208's compensation requirement:
/// when a step fails mid-workflow, the steps that already committed a
/// compensable effect are compensated in *exactly* the reverse of the
/// order they committed -- not declaration order, not a sorted order --
/// checked with the same `CompensationOrderProof`/`CompensationLedger`
/// machinery `compensation_order.rs` and `compensation.rs` test
/// standalone, now driven end to end from a real `run` failure.
#[test]
fn compensation_replays_in_exact_reverse_of_commit_order_after_a_mid_workflow_failure() {
    use crate::typed_workflow::compensation::{CompensationKey, CompensationLedger};

    let graph = compensable_pipeline();
    let mut inputs = ExecInputs::default();
    for id in [0u32, 1, 2] {
        inputs.model_policies.insert(
            StepId(id),
            DeploymentPolicy::new(["checked-small-1".to_string()]),
        );
    }
    inputs.compensable.insert(StepId(0));
    inputs.compensable.insert(StepId(1));
    // Step 2 fails permanently (`Uncertain`, never retried) after 0 and
    // 1 have already committed.
    inputs
        .retry_budgets
        .insert(StepId(2), RetryBudget { max_attempts: 5 });
    inputs.attempt_script.insert(
        StepId(2),
        vec![ScriptedAttempt::failed(AttemptOutcomeClass::Uncertain)],
    );
    inputs.run_id = 42;

    let mut commits = CommitLog::new();
    let err = run(&graph, &inputs, &mut GateLedger::new(), &mut commits).unwrap_err();
    assert_eq!(
        err,
        ExecError::StepFailed(StepId(2), AttemptOutcomeClass::Uncertain)
    );

    // Step 2 never committed (it failed), so only 0 and 1 are in the
    // log, in commit order.
    assert_eq!(
        commits
            .commits()
            .iter()
            .map(|c| (c.step, c.run))
            .collect::<Vec<_>>(),
        vec![(StepId(0), 42), (StepId(1), 42)]
    );

    let proof = commits.compensation_order();

    // Actually drive compensation through `CompensationLedger`, in the
    // order the proof requires, recording what really ran.
    let mut ledger = CompensationLedger::new();
    let mut actually_compensated = Vec::new();
    for record in proof.required() {
        ledger.apply(
            CompensationKey {
                step: record.step,
                run: record.run,
            },
            || {},
        );
        actually_compensated.push(*record);
    }
    assert!(proof.verify_complete(&actually_compensated).is_ok());
    assert_eq!(
        actually_compensated
            .iter()
            .map(|r| r.step)
            .collect::<Vec<_>>(),
        vec![StepId(1), StepId(0)],
        "compensation must replay in exact reverse of commit order"
    );
}

/// Negative control for the ordering claim itself: compensating in
/// commit order (rather than the required reverse) must be refused by
/// `verify_complete`, not silently accepted because the same *set* of
/// steps was compensated.
#[test]
fn compensating_in_commit_order_instead_of_reverse_is_refused() {
    let graph = compensable_pipeline();
    let mut inputs = ExecInputs::default();
    for id in [0u32, 1, 2] {
        inputs.model_policies.insert(
            StepId(id),
            DeploymentPolicy::new(["checked-small-1".to_string()]),
        );
    }
    inputs.compensable.insert(StepId(0));
    inputs.compensable.insert(StepId(1));
    inputs
        .retry_budgets
        .insert(StepId(2), RetryBudget { max_attempts: 5 });
    inputs.attempt_script.insert(
        StepId(2),
        vec![ScriptedAttempt::failed(AttemptOutcomeClass::Uncertain)],
    );
    inputs.run_id = 7;

    let mut commits = CommitLog::new();
    run(&graph, &inputs, &mut GateLedger::new(), &mut commits).unwrap_err();
    let proof = commits.compensation_order();

    // Wrong order: forward (commit order) instead of the required
    // reverse.
    let wrong_order: Vec<_> = commits.commits().to_vec();
    assert!(proof.verify_complete(&wrong_order).is_err());
}

/// A step never marked `compensable` commits nothing even on success --
/// compensability is declared by the caller, never inferred from a step
/// merely succeeding.
#[test]
fn a_step_not_marked_compensable_records_no_commit() {
    let graph = model_call_graph("checked-small-1");
    let mut inputs = ExecInputs::default();
    inputs.model_policies.insert(
        StepId(0),
        DeploymentPolicy::new(["checked-small-1".to_string()]),
    );
    let mut commits = CommitLog::new();
    run(&graph, &inputs, &mut GateLedger::new(), &mut commits).unwrap();
    assert!(commits.commits().is_empty());
}
