//! A minimal, deterministic executor for the step kinds this slice
//! actually implements.
//!
//! [`run`] only executes [`StepKind::Sequential`], [`StepKind::Conditional`],
//! [`StepKind::Loop`] (bounded) and [`StepKind::ModelCall`] (routed through
//! [`super::model_routing`]). Reaching [`StepKind::Parallel`],
//! [`StepKind::Join`], [`StepKind::HumanGate`] or [`StepKind::Declared`]
//! is a defined refusal (`ExecError::NotExecutable`), never a silent
//! no-op or a made-up default transition — this repository's completion
//! matrix must not claim those are implemented on the strength of this
//! function alone.
//!
//! `run` always validates the graph first, so a caller can never execute
//! an unchecked structure. Given the same graph and the same
//! [`ExecInputs`], `run` produces a byte-identical [`ExecTrace`] every
//! time: it makes no use of wall-clock time, randomness, thread
//! scheduling, or map/set iteration order (`ExecInputs` lookups are keyed,
//! not iterated).

use super::graph::{StepId, StepKind, WorkflowGraph, ELSE_PORT, THEN_PORT};
use super::model_routing::{route, DeploymentPolicy, RoutingError};
use std::collections::BTreeMap;

/// Hard ceiling on total step executions in one `run`, independent of any
/// per-`Loop`-step bound: a pathological chain of many distinct bounded
/// loops could otherwise still run arbitrarily long.
const MAX_STEP_EXECUTIONS: usize = 4096;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExecError {
    InvalidGraph,
    NotExecutable(StepId),
    LoopBoundExceeded(StepId),
    MissingConditionInput(StepId),
    MissingModelPolicy(StepId),
    RoutingRefused(StepId, RoutingError),
    StepLimitExceeded,
}

/// Caller-supplied values the engine has no way to compute itself: the
/// boolean at each `Conditional` step's condition port, and the deployment
/// policy in force for each `ModelCall` step.
#[derive(Default, Debug, Clone)]
pub struct ExecInputs {
    pub conditions: BTreeMap<StepId, bool>,
    pub model_policies: BTreeMap<StepId, DeploymentPolicy>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExecTrace {
    pub visited: Vec<StepId>,
    pub routed_models: Vec<(StepId, String)>,
}

pub fn run(graph: &WorkflowGraph, inputs: &ExecInputs) -> Result<ExecTrace, ExecError> {
    graph.validate().map_err(|_| ExecError::InvalidGraph)?;

    let mut current = graph.entry;
    let mut visited = Vec::new();
    let mut routed_models = Vec::new();
    let mut loop_counts: BTreeMap<StepId, u32> = BTreeMap::new();

    loop {
        if visited.len() >= MAX_STEP_EXECUTIONS {
            return Err(ExecError::StepLimitExceeded);
        }
        visited.push(current);
        let step = graph
            .steps
            .iter()
            .find(|s| s.id == current)
            .expect("validated graph: current step id always exists");

        match &step.kind {
            StepKind::Terminal => break,
            StepKind::Sequential => {
                current = only_out_edge(graph, current);
            }
            StepKind::Conditional { .. } => {
                let cond = inputs
                    .conditions
                    .get(&current)
                    .copied()
                    .ok_or(ExecError::MissingConditionInput(current))?;
                let branch_port = if cond { THEN_PORT } else { ELSE_PORT };
                current = graph
                    .edges
                    .iter()
                    .find(|e| e.from == current && e.from_port == branch_port)
                    .map(|e| e.to)
                    .expect("validated graph: both conditional branches exist");
            }
            StepKind::Loop { max_iterations } => {
                let count = loop_counts.entry(current).or_insert(0);
                *count += 1;
                if *count > *max_iterations {
                    return Err(ExecError::LoopBoundExceeded(current));
                }
                current = only_out_edge(graph, current);
            }
            StepKind::ModelCall { requested_model } => {
                let policy = inputs
                    .model_policies
                    .get(&current)
                    .ok_or(ExecError::MissingModelPolicy(current))?;
                let routed = route(policy, requested_model)
                    .map_err(|e| ExecError::RoutingRefused(current, e))?;
                routed_models.push((current, routed));
                current = only_out_edge(graph, current);
            }
            StepKind::Parallel
            | StepKind::Join { .. }
            | StepKind::HumanGate
            | StepKind::Declared(_) => {
                return Err(ExecError::NotExecutable(current));
            }
        }
    }

    Ok(ExecTrace {
        visited,
        routed_models,
    })
}

fn only_out_edge(graph: &WorkflowGraph, from: StepId) -> StepId {
    graph
        .edges
        .iter()
        .find(|e| e.from == from)
        .map(|e| e.to)
        .expect("validated graph: non-branching step has exactly one out edge")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::typed_workflow::graph::{EdgeDef, EdgeId, Port, PortId, PortType, StepDef};

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
        let first = run(&graph, &inputs).unwrap();
        let second = run(&graph, &inputs).unwrap();
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
        let trace = run(&graph, &inputs).unwrap();
        assert_eq!(trace.visited, vec![StepId(0), StepId(1)]);
    }

    #[test]
    fn conditional_false_follows_else_branch() {
        let graph = conditional_graph();
        let mut inputs = ExecInputs::default();
        inputs.conditions.insert(StepId(0), false);
        let trace = run(&graph, &inputs).unwrap();
        assert_eq!(trace.visited, vec![StepId(0), StepId(2)]);
    }

    #[test]
    fn missing_condition_input_is_a_defined_refusal_not_a_default_branch() {
        let graph = conditional_graph();
        let inputs = ExecInputs::default();
        assert_eq!(
            run(&graph, &inputs),
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
        let err = run(&graph, &inputs).unwrap_err();
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
        let trace = run(&graph, &ExecInputs::default()).unwrap();
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
        let trace = run(&graph, &inputs).unwrap();
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
            run(&graph, &inputs),
            Err(ExecError::RoutingRefused(
                StepId(0),
                RoutingError::NotInPolicy
            ))
        );
    }

    #[test]
    fn human_gate_step_is_never_silently_executed() {
        let gate = StepDef {
            id: StepId(0),
            kind: StepKind::HumanGate,
            in_ports: vec![unit_port(0)],
            out_ports: vec![unit_port(0)],
        };
        let graph = WorkflowGraph {
            steps: vec![gate, terminal(1)],
            edges: vec![edge(0, 0, 1)],
            entry: StepId(0),
        };
        assert_eq!(
            run(&graph, &ExecInputs::default()),
            Err(ExecError::NotExecutable(StepId(0)))
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
            run(&graph, &ExecInputs::default()),
            Err(ExecError::InvalidGraph)
        );
    }
}
