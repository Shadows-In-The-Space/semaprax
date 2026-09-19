//! Validation tests for declared resource claims: the static refusal of
//! issue #208's own named failure case, "parallel branches can race on
//! shared resources or semantic candidates".
//!
//! Kept as its own file rather than grown onto `graph.rs`'s inline `mod
//! tests` per the repository's module-size guidance.
//!
//! The negative controls are the load-bearing half here. A rule that
//! refuses every repeated claim anywhere in a graph would pass the
//! conflict tests and be wrong: `the_same_claim_on_two_sequential_steps_is_not_a_conflict`
//! is what pins the rule to *concurrency* rather than to uniqueness, and
//! `a_conflicting_graph_cannot_be_executed_at_all` is what makes the
//! refusal static rather than advisory.

use super::*;
use crate::typed_workflow::claims::ResourceClaim;
use crate::typed_workflow::compensation_order::CommitLog;
use crate::typed_workflow::engine::{run, ExecError, ExecInputs};
use crate::typed_workflow::human_gate::GateLedger;

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

/// `Parallel(0)` fanning out to `seq(10)` and `seq(11)`, rejoining at
/// `Join(1)` and ending at `terminal(2)`.
fn parallel_graph(claims: ClaimSet) -> WorkflowGraph {
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
        claims,
    }
}

#[test]
fn a_graph_declaring_no_claims_validates_exactly_as_before() {
    assert_eq!(parallel_graph(ClaimSet::none()).validate(), Ok(()));
}

#[test]
fn disjoint_claims_on_concurrent_branches_validate() {
    let mut claims = ClaimSet::none();
    claims.declare(StepId(10), ResourceClaim::resource("left"));
    claims.declare(StepId(11), ResourceClaim::resource("right"));
    assert_eq!(parallel_graph(claims).validate(), Ok(()));
}

#[test]
fn concurrent_branches_claiming_one_resource_are_refused() {
    let mut claims = ClaimSet::none();
    claims.declare(StepId(10), ResourceClaim::resource("workspace/main"));
    claims.declare(StepId(11), ResourceClaim::resource("workspace/main"));
    let graph = parallel_graph(claims);
    assert_eq!(
        graph.validate(),
        Err(GraphError::ConflictingConcurrentClaims(
            StepId(10),
            StepId(11)
        ))
    );
    // The same finding, with the claim attached, for a caller rendering a
    // user-facing diagnostic. Both come from one function, so the CLI can
    // never report a different conflict from the one validation refused.
    let conflict = graph.first_claim_conflict().expect("the same conflict");
    assert_eq!(conflict.parallel, StepId(0));
    assert_eq!(conflict.left, StepId(10));
    assert_eq!(conflict.right, StepId(11));
    assert_eq!(conflict.claim, ResourceClaim::resource("workspace/main"));
}

#[test]
fn concurrent_branches_claiming_one_semantic_candidate_are_refused() {
    let mut claims = ClaimSet::none();
    claims.declare(StepId(10), ResourceClaim::semantic_candidate("cand-3"));
    claims.declare(StepId(11), ResourceClaim::semantic_candidate("cand-3"));
    assert_eq!(
        parallel_graph(claims).validate(),
        Err(GraphError::ConflictingConcurrentClaims(
            StepId(10),
            StepId(11)
        ))
    );
}

#[test]
fn the_same_claim_on_two_sequential_steps_is_not_a_conflict() {
    // The negative control that keeps this a concurrency rule rather than a
    // global uniqueness rule. Two steps that run one after the other may
    // both claim the same resource -- that is ordinary sequential use, and
    // refusing it would make the feature unusable.
    let mut claims = ClaimSet::none();
    claims.declare(StepId(0), ResourceClaim::resource("shared"));
    claims.declare(StepId(1), ResourceClaim::resource("shared"));
    let graph = WorkflowGraph {
        steps: vec![seq(0), seq(1), terminal(2)],
        edges: vec![edge(0, 0, 1), edge(1, 1, 2)],
        entry: StepId(0),
        claims,
    };
    assert_eq!(graph.validate(), Ok(()));
    assert_eq!(graph.first_claim_conflict(), None);
}

#[test]
fn the_same_claim_on_one_branch_and_a_step_after_the_join_is_not_a_conflict() {
    // A step after the join does not run concurrently with a branch: the
    // join is precisely the point at which every branch has finished.
    let mut claims = ClaimSet::none();
    claims.declare(StepId(10), ResourceClaim::resource("shared"));
    claims.declare(StepId(1), ResourceClaim::resource("shared"));
    assert_eq!(parallel_graph(claims).validate(), Ok(()));
}

#[test]
fn a_claim_for_a_step_this_graph_does_not_have_is_refused() {
    // Refused rather than ignored: a claim silently dropped because its
    // step id moved is exactly the claim that stops protecting the branch
    // it was written for.
    let mut claims = ClaimSet::none();
    claims.declare(StepId(99), ResourceClaim::resource("gone"));
    assert_eq!(
        parallel_graph(claims).validate(),
        Err(GraphError::ClaimForUnknownStep(StepId(99)))
    );
}

#[test]
fn a_step_declaring_more_than_the_claim_bound_is_refused() {
    let mut claims = ClaimSet::none();
    for index in 0..=crate::typed_workflow::claims::MAX_CLAIMS_PER_STEP {
        claims.declare(StepId(10), ResourceClaim::resource(format!("r{index}")));
    }
    assert_eq!(
        parallel_graph(claims).validate(),
        Err(GraphError::TooManyClaims(StepId(10)))
    );
}

#[test]
fn a_conflicting_graph_cannot_be_executed_at_all() {
    // The whole point of making this static: `engine::run` validates first,
    // so a graph whose concurrent branches conflict is unrunnable rather
    // than merely reported on. A runtime race detector would have to
    // observe the race; this refuses before any step executes.
    let mut claims = ClaimSet::none();
    claims.declare(StepId(10), ResourceClaim::resource("workspace/main"));
    claims.declare(StepId(11), ResourceClaim::resource("workspace/main"));
    let graph = parallel_graph(claims);
    let mut commits = CommitLog::new();
    let error = run(
        &graph,
        &ExecInputs::default(),
        &mut GateLedger::new(),
        &mut commits,
    )
    .unwrap_err();
    assert_eq!(error, ExecError::InvalidGraph);
    assert!(commits.commits().is_empty());
}

#[test]
fn claim_validation_is_deterministic_across_repeated_calls() {
    let mut claims = ClaimSet::none();
    for step in [10u32, 11] {
        claims.declare(StepId(step), ResourceClaim::resource("zulu"));
        claims.declare(StepId(step), ResourceClaim::resource("alpha"));
    }
    let graph = parallel_graph(claims);
    let first = graph.validate();
    for _ in 0..8 {
        assert_eq!(graph.validate(), first);
        assert_eq!(
            graph.first_claim_conflict().map(|c| c.claim),
            Some(ResourceClaim::resource("alpha"))
        );
    }
}
