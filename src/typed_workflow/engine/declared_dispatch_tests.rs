//! Fault-injection-grade tests for the five decide-and-record `Declared`
//! kinds (`AgentCall`, `ToolCall`, `Job`, `TestBuild`, `PublicationRequest`)
//! and the sixth kind, `SemanticChange`, which this engine refuses
//! unconditionally. Kept as its own file (rather than growing
//! `engine/tests.rs`) per the repository's module-size guidance to prefer a
//! new submodule from the start.

use super::*;
use crate::typed_workflow::claims::ClaimSet;
use crate::typed_workflow::declared_dispatch::{DispatchError, DispatchPolicy, DispatchRequest};
use crate::typed_workflow::graph::{
    DeclaredStepKind, EdgeDef, EdgeId, Port, PortId, PortType, StepDef,
};

fn unit_port(id: u32) -> Port {
    Port {
        id: PortId(id),
        ty: PortType::Unit,
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

fn declared_graph(kind: DeclaredStepKind) -> WorkflowGraph {
    let declared = StepDef {
        id: StepId(0),
        kind: StepKind::Declared(kind),
        in_ports: vec![unit_port(0)],
        out_ports: vec![unit_port(0)],
    };
    WorkflowGraph {
        steps: vec![declared, terminal(1)],
        edges: vec![edge(0, 0, 1)],
        entry: StepId(0),
        claims: ClaimSet::none(),
    }
}

fn admitting_inputs(target: &str, allowed: &str) -> ExecInputs {
    let mut inputs = ExecInputs::default();
    inputs.declared_dispatch_requests.insert(
        StepId(0),
        DispatchRequest {
            target: target.to_string(),
        },
    );
    inputs
        .declared_dispatch_policies
        .insert(StepId(0), DispatchPolicy::new([allowed.to_string()]));
    inputs
}

// ---------------------------------------------------------------------
// One success + one negative control per kind, run through `run` (not
// just the bare decision function `declared_dispatch::decide` already
// covers standalone) so the dispatch-table wiring itself is exercised.
// ---------------------------------------------------------------------

fn admission_succeeds_for(kind: DeclaredStepKind) {
    let graph = declared_graph(kind);
    let inputs = admitting_inputs("release-agent", "release-agent");
    let trace = run(
        &graph,
        &inputs,
        &mut GateLedger::new(),
        &mut CommitLog::new(),
    )
    .unwrap();
    assert_eq!(
        trace.admitted_dispatches,
        vec![(StepId(0), kind, "release-agent".to_string())]
    );
    assert_eq!(trace.visited, vec![StepId(0), StepId(1)]);
}

fn admission_refuses_for(kind: DeclaredStepKind) {
    let graph = declared_graph(kind);
    let inputs = admitting_inputs("unlisted-target", "release-agent");
    let err = run(
        &graph,
        &inputs,
        &mut GateLedger::new(),
        &mut CommitLog::new(),
    )
    .unwrap_err();
    assert_eq!(
        err,
        ExecError::DispatchRefused(StepId(0), DispatchError::NotInPolicy)
    );
}

fn reaching_without_a_declaration_refuses_for(kind: DeclaredStepKind) {
    let graph = declared_graph(kind);
    let err = run(
        &graph,
        &ExecInputs::default(),
        &mut GateLedger::new(),
        &mut CommitLog::new(),
    )
    .unwrap_err();
    assert_eq!(err, ExecError::DispatchNotDeclared(StepId(0)));
}

#[test]
fn agent_call_admits_a_policy_member() {
    admission_succeeds_for(DeclaredStepKind::AgentCall);
}

#[test]
fn agent_call_refuses_a_target_outside_policy() {
    admission_refuses_for(DeclaredStepKind::AgentCall);
}

#[test]
fn agent_call_refuses_with_nothing_declared() {
    reaching_without_a_declaration_refuses_for(DeclaredStepKind::AgentCall);
}

#[test]
fn tool_call_admits_a_policy_member() {
    admission_succeeds_for(DeclaredStepKind::ToolCall);
}

#[test]
fn tool_call_refuses_a_target_outside_policy() {
    admission_refuses_for(DeclaredStepKind::ToolCall);
}

#[test]
fn tool_call_refuses_with_nothing_declared() {
    reaching_without_a_declaration_refuses_for(DeclaredStepKind::ToolCall);
}

#[test]
fn job_admits_a_policy_member() {
    admission_succeeds_for(DeclaredStepKind::Job);
}

#[test]
fn job_refuses_a_target_outside_policy() {
    admission_refuses_for(DeclaredStepKind::Job);
}

#[test]
fn job_refuses_with_nothing_declared() {
    reaching_without_a_declaration_refuses_for(DeclaredStepKind::Job);
}

#[test]
fn test_build_admits_a_policy_member() {
    admission_succeeds_for(DeclaredStepKind::TestBuild);
}

#[test]
fn test_build_refuses_a_target_outside_policy() {
    admission_refuses_for(DeclaredStepKind::TestBuild);
}

#[test]
fn test_build_refuses_with_nothing_declared() {
    reaching_without_a_declaration_refuses_for(DeclaredStepKind::TestBuild);
}

#[test]
fn publication_request_admits_a_policy_member() {
    admission_succeeds_for(DeclaredStepKind::PublicationRequest);
}

#[test]
fn publication_request_refuses_a_target_outside_policy() {
    admission_refuses_for(DeclaredStepKind::PublicationRequest);
}

#[test]
fn publication_request_refuses_with_nothing_declared() {
    reaching_without_a_declaration_refuses_for(DeclaredStepKind::PublicationRequest);
}

// ---------------------------------------------------------------------
// SemanticChange: unconditional refusal, even with a request/policy a
// caller might mistakenly suppose would be honored the way the other
// five kinds are.
// ---------------------------------------------------------------------

#[test]
fn semantic_change_refuses_even_with_a_declared_request_and_policy() {
    let graph = declared_graph(DeclaredStepKind::SemanticChange);
    let inputs = admitting_inputs("release-agent", "release-agent");
    let err = run(
        &graph,
        &inputs,
        &mut GateLedger::new(),
        &mut CommitLog::new(),
    )
    .unwrap_err();
    assert_eq!(err, ExecError::SemanticChangeNotGranted(StepId(0)));
}

#[test]
fn semantic_change_refuses_with_nothing_declared() {
    let graph = declared_graph(DeclaredStepKind::SemanticChange);
    let err = run(
        &graph,
        &ExecInputs::default(),
        &mut GateLedger::new(),
        &mut CommitLog::new(),
    )
    .unwrap_err();
    assert_eq!(err, ExecError::SemanticChangeNotGranted(StepId(0)));
}

// ---------------------------------------------------------------------
// No-authority proof: an admitted dispatch is nothing but a recorded
// decision. There is no side channel in `ExecInputs`, `GateLedger`, or
// `CommitLog` that a `DispatchExecutor` could use to actually invoke,
// spawn, or publish anything, and admitting a step never records it into
// the compensation `CommitLog` (only `ModelCall` steps named in
// `ExecInputs::compensable` do) — proving, by construction, that a
// caller cannot mistake an admission for a performed action or for an
// effect that would need compensating.
// ---------------------------------------------------------------------

#[test]
fn an_admitted_dispatch_never_enters_the_compensation_commit_log() {
    let graph = declared_graph(DeclaredStepKind::Job);
    let inputs = admitting_inputs("release-agent", "release-agent");
    let mut commits = CommitLog::new();
    let trace = run(&graph, &inputs, &mut GateLedger::new(), &mut commits).unwrap();
    assert_eq!(trace.admitted_dispatches.len(), 1);
    assert!(
        commits.commits().is_empty(),
        "a decide-and-record admission must never be treated as a committed, \
         compensable effect"
    );
}

#[test]
fn admitting_five_different_kinds_in_one_run_records_five_distinct_decisions_and_nothing_else() {
    // A wider structural proof than the per-kind tests above: run all five
    // decide-and-record kinds back to back in one graph and check the
    // recorded trace names exactly those five decisions, in step order,
    // with no other side effect (`routed_models` stays empty — nothing
    // here is a `ModelCall`).
    fn declared(id: u32, kind: DeclaredStepKind) -> StepDef {
        StepDef {
            id: StepId(id),
            kind: StepKind::Declared(kind),
            in_ports: vec![unit_port(0)],
            out_ports: vec![unit_port(0)],
        }
    }

    let kinds = [
        DeclaredStepKind::AgentCall,
        DeclaredStepKind::ToolCall,
        DeclaredStepKind::Job,
        DeclaredStepKind::TestBuild,
        DeclaredStepKind::PublicationRequest,
    ];
    let mut steps: Vec<StepDef> = kinds
        .iter()
        .enumerate()
        .map(|(i, kind)| declared(i as u32, *kind))
        .collect();
    steps.push(terminal(kinds.len() as u32));
    let edges = (0..kinds.len() as u32).map(|i| edge(i, i, i + 1)).collect();
    let graph = WorkflowGraph {
        steps,
        edges,
        entry: StepId(0),
        claims: ClaimSet::none(),
    };

    let mut inputs = ExecInputs::default();
    for i in 0..kinds.len() as u32 {
        inputs.declared_dispatch_requests.insert(
            StepId(i),
            DispatchRequest {
                target: "ok".to_string(),
            },
        );
        inputs
            .declared_dispatch_policies
            .insert(StepId(i), DispatchPolicy::new(["ok".to_string()]));
    }

    let trace = run(
        &graph,
        &inputs,
        &mut GateLedger::new(),
        &mut CommitLog::new(),
    )
    .unwrap();

    let expected: Vec<(StepId, DeclaredStepKind, String)> = kinds
        .iter()
        .enumerate()
        .map(|(i, kind)| (StepId(i as u32), *kind, "ok".to_string()))
        .collect();
    assert_eq!(trace.admitted_dispatches, expected);
    assert!(trace.routed_models.is_empty());
}
