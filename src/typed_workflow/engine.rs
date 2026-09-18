//! A minimal, deterministic executor for the step kinds this slice
//! actually implements.
//!
//! [`run`] executes [`StepKind::Sequential`], [`StepKind::Conditional`],
//! [`StepKind::Loop`] (bounded), [`StepKind::ModelCall`] (routed through
//! [`super::model_routing`]), [`StepKind::HumanGate`] (authorized through
//! [`super::human_gate`]) and [`StepKind::Parallel`]/[`StepKind::Join`] (as
//! a deterministic sequential simulation — see [`StepExecutor`] below).
//! Reaching [`StepKind::Declared`] is a defined refusal
//! (`ExecError::NotExecutable`), never a silent no-op or a made-up default
//! transition — this repository's completion matrix must not claim that
//! kind is implemented on the strength of this function alone.
//!
//! `run` always validates the graph first, so a caller can never execute
//! an unchecked structure. Given the same graph, the same [`ExecInputs`],
//! and a caller-supplied [`super::human_gate::GateLedger`] in the same
//! starting state, `run` produces a byte-identical [`ExecTrace`] every
//! time: it makes no use of wall-clock time, randomness, thread spawning,
//! or map/set iteration order beyond `BTreeMap`/`BTreeSet`'s own key
//! order, which is itself a deterministic total order over [`StepId`].
//!
//! # The step-executor seam
//!
//! Every step kind this module actually runs is dispatched to exactly one
//! [`StepExecutor`] implementation through [`dispatch_step`], the single
//! call point. `StepExecutor` is sealed (see the private `sealed` module):
//! nothing outside this file can implement it, so a new step kind's
//! behavior cannot be bolted on at a second, uncoordinated call site the
//! way it could if `run` inlined every kind's logic in one large match with
//! no shared contract. Reaching an executor's `execute` additionally
//! requires a [`StepAuthority`], an unforgeable, no-public-constructor
//! value minted only inside `dispatch_step` — the same shape
//! `src/agent_lifecycle/authorization.rs` uses for its `StageExecutor`
//! seam, applied here to workflow step kinds instead of Agent lifecycle
//! stages.

use super::graph::{StepDef, StepId, StepKind, WorkflowGraph, ELSE_PORT, THEN_PORT};
use super::human_gate::{GateDecision, GateError, GateLedger, GateSpec};
use super::model_routing::{route, DeploymentPolicy, RoutingError};
use std::collections::{BTreeMap, BTreeSet};

/// Hard ceiling on total step executions in one `run`, independent of any
/// per-`Loop`-step bound: a pathological chain of many distinct bounded
/// loops, or a wide tree of nested `Parallel` steps, could otherwise still
/// run arbitrarily long. Every step this module executes — including each
/// branch of a `Parallel` — passes through [`dispatch_step`], so this bound
/// is enforced in exactly one place.
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
    /// A `HumanGate` step was reached but the caller supplied neither a
    /// [`GateSpec`] nor a [`GateDecision`] for it in [`ExecInputs`]. The
    /// engine never treats "reached the gate" as "past the gate": this is
    /// the defined refusal that proves it.
    GateNotDecided(StepId),
    /// A `HumanGate` step was reached with a spec and decision present, but
    /// [`GateLedger::evaluate`] refused them (wrong revision, wrong
    /// candidate, wrong role, expired, rejected, or replayed).
    GateRefused(StepId, GateError),
    /// The [`GateSpec::grants_edge`] the caller supplied for a `HumanGate`
    /// step does not name an edge that actually leaves that step. A
    /// well-formed workflow author never produces this; it catches a
    /// caller wiring a decision to the wrong gate.
    GateEdgeMismatch(StepId),
    /// A `Parallel` step has no `Join` step in the graph whose `parallel`
    /// field names it. Structurally valid per [`super::graph::WorkflowGraph::validate`]
    /// (a `Parallel`'s branches are free to terminate on their own instead
    /// of recombining), but not executable: this engine only knows how to
    /// run a `Parallel` that a `Join` waits on.
    NoJoinForParallel(StepId),
    /// More than one `Join` step in the graph names the same `Parallel`.
    /// Believed unreachable once [`super::graph::WorkflowGraph::validate`]
    /// has passed — every step's single out edge is exactly one target
    /// under that validation, so two distinct `Join`s cannot both appear in
    /// one branch step's (at most one) predecessor set — but checked
    /// explicitly rather than assumed, in case a future schema change
    /// loosens that constraint.
    AmbiguousJoinForParallel(StepId),
    /// A `Parallel` step's branch did not lead directly to the `Join`
    /// waiting on it. Believed unreachable once
    /// [`super::graph::WorkflowGraph::validate`] has passed, for the same
    /// reason `AmbiguousJoinForParallel` is: a branch step's one permitted
    /// out edge is proven, by the join-predecessor-set check, to target the
    /// join. Kept as a checked refusal rather than a panic or a silently
    /// accepted wrong continuation.
    BranchDidNotReachJoin(StepId, StepId),
}

/// Caller-supplied values the engine has no way to compute itself: the
/// boolean at each `Conditional` step's condition port, the deployment
/// policy in force for each `ModelCall` step, and the declared spec plus
/// the out-of-band decision for each `HumanGate` step.
#[derive(Default, Debug, Clone)]
pub struct ExecInputs {
    pub conditions: BTreeMap<StepId, bool>,
    pub model_policies: BTreeMap<StepId, DeploymentPolicy>,
    pub gate_specs: BTreeMap<StepId, GateSpec>,
    pub gate_decisions: BTreeMap<StepId, GateDecision>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExecTrace {
    pub visited: Vec<StepId>,
    pub routed_models: Vec<(StepId, String)>,
}

/// Runs `graph` to completion (or a defined refusal) against `inputs`,
/// authorizing every `HumanGate` step it reaches through `gates`.
///
/// `gates` is threaded through by the caller rather than owned by `run`:
/// replay protection for a human decision is a property of the ledger
/// instance, not of one call to `run`, so a caller that wants a decision to
/// stay consumed across a retried or resumed run must keep reusing the same
/// [`GateLedger`] (the same way [`super::checkpoint::Checkpoint`] threads a
/// [`super::compensation::CompensationLedger`] rather than owning one
/// itself).
pub fn run(
    graph: &WorkflowGraph,
    inputs: &ExecInputs,
    gates: &mut GateLedger,
) -> Result<ExecTrace, ExecError> {
    graph.validate().map_err(|_| ExecError::InvalidGraph)?;

    let mut current = graph.entry;
    let mut visited = Vec::new();
    let mut routed_models = Vec::new();
    let mut loop_counts: BTreeMap<StepId, u32> = BTreeMap::new();

    loop {
        let effect = dispatch_step(
            current,
            graph,
            inputs,
            gates,
            &mut loop_counts,
            &mut visited,
        )?;
        routed_models.extend(effect.routed_models);
        match effect.next {
            Some(next) => current = next,
            None => break,
        }
    }

    Ok(ExecTrace {
        visited,
        routed_models,
    })
}

fn find_step(graph: &WorkflowGraph, id: StepId) -> &StepDef {
    graph
        .steps
        .iter()
        .find(|s| s.id == id)
        .expect("validated graph: current step id always exists")
}

fn only_out_edge(graph: &WorkflowGraph, from: StepId) -> StepId {
    graph
        .edges
        .iter()
        .find(|e| e.from == from)
        .map(|e| e.to)
        .expect("validated graph: non-branching step has exactly one out edge")
}

// ---------------------------------------------------------------------------
// The step-executor seam.
// ---------------------------------------------------------------------------

mod sealed {
    /// Closed over this module. `sealed` is private, so only `engine.rs`
    /// itself can name `Sealed`, and therefore only the executors declared
    /// in this file can implement [`super::StepExecutor`] — the standard
    /// Rust sealed-trait idiom, enforced by the compiler at the `impl`
    /// site, matching the shape `src/agent_lifecycle/authorization.rs` uses
    /// for its `StageExecutor` seam.
    pub trait Sealed {}
}

/// Explicit, unforgeable authority to dispatch one step to a
/// [`StepExecutor`].
///
/// No public constructor, no `Clone`, no `Copy`, no `Default`: a caller
/// cannot build one from a struct literal (its field is private) and
/// cannot manufacture one from nothing. The only route is
/// [`StepAuthority::grant`], called only from [`dispatch_step`].
pub struct StepAuthority(());

impl StepAuthority {
    fn grant() -> Self {
        StepAuthority(())
    }
}

/// The borrowed state one step's dispatch needs. Built fresh by
/// [`dispatch_step`] for each step (including each branch of a
/// `Parallel`), so no executor holds state across two steps.
pub(crate) struct StepContext<'a> {
    current: StepId,
    step: &'a StepDef,
    graph: &'a WorkflowGraph,
    inputs: &'a ExecInputs,
    gates: &'a mut GateLedger,
    loop_counts: &'a mut BTreeMap<StepId, u32>,
    visited: &'a mut Vec<StepId>,
}

/// The result of executing exactly one step: which step to visit next (or
/// `None`, at a `Terminal`), plus any model routings that step performed.
/// `Parallel` is the only kind that can report more than one routed model
/// in a single [`StepEffect`], since it runs every branch before reporting
/// back to its caller.
#[derive(Debug)]
pub(crate) struct StepEffect {
    next: Option<StepId>,
    routed_models: Vec<(StepId, String)>,
}

impl StepEffect {
    fn advance(next: StepId) -> Self {
        StepEffect {
            next: Some(next),
            routed_models: Vec::new(),
        }
    }

    fn terminal() -> Self {
        StepEffect {
            next: None,
            routed_models: Vec::new(),
        }
    }
}

/// The sealed executor seam for running one workflow step.
///
/// Every step kind [`run`] actually executes has exactly one implementor
/// here: [`SequentialExecutor`], [`ConditionalExecutor`], [`LoopExecutor`],
/// [`ModelCallExecutor`], [`HumanGateExecutor`], [`ParallelExecutor`], and
/// [`TerminalExecutor`]. [`NotExecutableExecutor`] backs every kind this
/// slice deliberately refuses to run ([`StepKind::Join`] reached any way
/// other than immediately after [`ParallelExecutor`] finishes its branches,
/// and [`StepKind::Declared`]). `StepExecutor` is `pub(crate)` so its
/// contract is visible within the crate, but it cannot be *implemented*
/// from outside this file: the supertrait bound requires `sealed::Sealed`,
/// and `sealed` is private to this module.
pub(crate) trait StepExecutor: sealed::Sealed {
    fn execute(
        &self,
        authority: StepAuthority,
        ctx: &mut StepContext<'_>,
    ) -> Result<StepEffect, ExecError>;
}

struct SequentialExecutor;
impl sealed::Sealed for SequentialExecutor {}
impl StepExecutor for SequentialExecutor {
    fn execute(
        &self,
        _authority: StepAuthority,
        ctx: &mut StepContext<'_>,
    ) -> Result<StepEffect, ExecError> {
        Ok(StepEffect::advance(only_out_edge(ctx.graph, ctx.current)))
    }
}

struct ConditionalExecutor;
impl sealed::Sealed for ConditionalExecutor {}
impl StepExecutor for ConditionalExecutor {
    fn execute(
        &self,
        _authority: StepAuthority,
        ctx: &mut StepContext<'_>,
    ) -> Result<StepEffect, ExecError> {
        let cond = ctx
            .inputs
            .conditions
            .get(&ctx.current)
            .copied()
            .ok_or(ExecError::MissingConditionInput(ctx.current))?;
        let branch_port = if cond { THEN_PORT } else { ELSE_PORT };
        let next = ctx
            .graph
            .edges
            .iter()
            .find(|e| e.from == ctx.current && e.from_port == branch_port)
            .map(|e| e.to)
            .expect("validated graph: both conditional branches exist");
        Ok(StepEffect::advance(next))
    }
}

struct LoopExecutor;
impl sealed::Sealed for LoopExecutor {}
impl StepExecutor for LoopExecutor {
    fn execute(
        &self,
        _authority: StepAuthority,
        ctx: &mut StepContext<'_>,
    ) -> Result<StepEffect, ExecError> {
        let StepKind::Loop { max_iterations } = &ctx.step.kind else {
            unreachable!("dispatch only routes StepKind::Loop here")
        };
        let count = ctx.loop_counts.entry(ctx.current).or_insert(0);
        *count += 1;
        if *count > *max_iterations {
            return Err(ExecError::LoopBoundExceeded(ctx.current));
        }
        Ok(StepEffect::advance(only_out_edge(ctx.graph, ctx.current)))
    }
}

struct ModelCallExecutor;
impl sealed::Sealed for ModelCallExecutor {}
impl StepExecutor for ModelCallExecutor {
    fn execute(
        &self,
        _authority: StepAuthority,
        ctx: &mut StepContext<'_>,
    ) -> Result<StepEffect, ExecError> {
        let StepKind::ModelCall { requested_model } = &ctx.step.kind else {
            unreachable!("dispatch only routes StepKind::ModelCall here")
        };
        let policy = ctx
            .inputs
            .model_policies
            .get(&ctx.current)
            .ok_or(ExecError::MissingModelPolicy(ctx.current))?;
        let routed = route(policy, requested_model)
            .map_err(|e| ExecError::RoutingRefused(ctx.current, e))?;
        let mut effect = StepEffect::advance(only_out_edge(ctx.graph, ctx.current));
        effect.routed_models.push((ctx.current, routed));
        Ok(effect)
    }
}

/// Advances past a `HumanGate` step only given an explicit spec and
/// decision that [`GateLedger::evaluate`] accepts. There is no code path
/// in this executor that returns `Ok` without a successful `evaluate` call
/// — proving, by construction, that reaching the step never authorizes it.
struct HumanGateExecutor;
impl sealed::Sealed for HumanGateExecutor {}
impl StepExecutor for HumanGateExecutor {
    fn execute(
        &self,
        _authority: StepAuthority,
        ctx: &mut StepContext<'_>,
    ) -> Result<StepEffect, ExecError> {
        let spec = ctx
            .inputs
            .gate_specs
            .get(&ctx.current)
            .ok_or(ExecError::GateNotDecided(ctx.current))?;
        let decision = ctx
            .inputs
            .gate_decisions
            .get(&ctx.current)
            .ok_or(ExecError::GateNotDecided(ctx.current))?;
        let granted_edge = ctx
            .gates
            .evaluate(spec, decision)
            .map_err(|e| ExecError::GateRefused(ctx.current, e))?;
        let next = ctx
            .graph
            .edges
            .iter()
            .find(|e| e.id == granted_edge && e.from == ctx.current)
            .map(|e| e.to)
            .ok_or(ExecError::GateEdgeMismatch(ctx.current))?;
        Ok(StepEffect::advance(next))
    }
}

struct TerminalExecutor;
impl sealed::Sealed for TerminalExecutor {}
impl StepExecutor for TerminalExecutor {
    fn execute(
        &self,
        _authority: StepAuthority,
        _ctx: &mut StepContext<'_>,
    ) -> Result<StepEffect, ExecError> {
        Ok(StepEffect::terminal())
    }
}

/// Refuses unconditionally. Backs [`StepKind::Declared`] (schema-only in
/// this slice) and any reach of [`StepKind::Join`] that did not go through
/// [`ParallelExecutor`] finishing its branches.
struct NotExecutableExecutor;
impl sealed::Sealed for NotExecutableExecutor {}
impl StepExecutor for NotExecutableExecutor {
    fn execute(
        &self,
        _authority: StepAuthority,
        ctx: &mut StepContext<'_>,
    ) -> Result<StepEffect, ExecError> {
        Err(ExecError::NotExecutable(ctx.current))
    }
}

/// Runs every branch of a `Parallel` step, then continues past its `Join`.
///
/// This is a deterministic *sequential simulation* of concurrency, not real
/// concurrency: branches run one at a time, in ascending [`StepId`] order,
/// on the one thread already running `run`. No thread is spawned, no
/// channel or lock is used, and no branch's execution can observe or race
/// another's — there is nothing nondeterministic to reproduce. Given the
/// same graph and inputs, the branch order and every routed model are
/// identical on every call; see the `parallel_join` tests below for the
/// repeated-run check that pins this.
///
/// Per [`super::graph::WorkflowGraph::validate`], a branch is always
/// exactly one step whose sole out edge targets the `Join` — see the
/// [`StepKind::Parallel`] documentation for why. This executor still
/// checks that at runtime ([`ExecError::BranchDidNotReachJoin`]) rather
/// than assuming it, and looks up the one `Join` that names this
/// `Parallel` rather than assuming exactly one exists
/// ([`ExecError::NoJoinForParallel`], [`ExecError::AmbiguousJoinForParallel`]).
struct ParallelExecutor;
impl sealed::Sealed for ParallelExecutor {}
impl StepExecutor for ParallelExecutor {
    fn execute(
        &self,
        _authority: StepAuthority,
        ctx: &mut StepContext<'_>,
    ) -> Result<StepEffect, ExecError> {
        let current = ctx.current;
        let join_id = find_unique_join(ctx.graph, current)?;

        // `BTreeSet` iterates in ascending `StepId` order, which is what
        // makes branch order a pure function of the graph rather than of
        // edge-declaration order or any hash-map iteration order.
        let branches: BTreeSet<StepId> = ctx
            .graph
            .edges
            .iter()
            .filter(|e| e.from == current)
            .map(|e| e.to)
            .collect();

        let mut routed_models = Vec::new();
        for branch in branches {
            let effect = dispatch_step(
                branch,
                ctx.graph,
                ctx.inputs,
                ctx.gates,
                ctx.loop_counts,
                ctx.visited,
            )?;
            routed_models.extend(effect.routed_models);
            if effect.next != Some(join_id) {
                return Err(ExecError::BranchDidNotReachJoin(current, branch));
            }
        }

        record_visit(ctx.visited, join_id)?;
        let after_join = only_out_edge(ctx.graph, join_id);
        Ok(StepEffect {
            next: Some(after_join),
            routed_models,
        })
    }
}

/// Finds the one `Join` step whose `parallel` field names `parallel_id`.
fn find_unique_join(graph: &WorkflowGraph, parallel_id: StepId) -> Result<StepId, ExecError> {
    let mut joins = graph
        .steps
        .iter()
        .filter(|s| matches!(&s.kind, StepKind::Join { parallel } if *parallel == parallel_id));
    match (joins.next(), joins.next()) {
        (Some(join), None) => Ok(join.id),
        (None, _) => Err(ExecError::NoJoinForParallel(parallel_id)),
        (Some(_), Some(_)) => Err(ExecError::AmbiguousJoinForParallel(parallel_id)),
    }
}

fn record_visit(visited: &mut Vec<StepId>, id: StepId) -> Result<(), ExecError> {
    if visited.len() >= MAX_STEP_EXECUTIONS {
        return Err(ExecError::StepLimitExceeded);
    }
    visited.push(id);
    Ok(())
}

fn dispatch(kind: &StepKind) -> &'static dyn StepExecutor {
    match kind {
        StepKind::Sequential => &SequentialExecutor,
        StepKind::Conditional { .. } => &ConditionalExecutor,
        StepKind::Loop { .. } => &LoopExecutor,
        StepKind::ModelCall { .. } => &ModelCallExecutor,
        StepKind::HumanGate => &HumanGateExecutor,
        StepKind::Terminal => &TerminalExecutor,
        StepKind::Parallel => &ParallelExecutor,
        StepKind::Join { .. } | StepKind::Declared(_) => &NotExecutableExecutor,
    }
}

/// The single call point every step this module executes passes through —
/// the top-level loop in [`run`] and [`ParallelExecutor`]'s per-branch
/// dispatch both call this, never a step kind's executor directly. Records
/// `current` into `visited` (bounded by [`MAX_STEP_EXECUTIONS`]) before
/// dispatching, so every step this module ever runs — top-level or nested
/// in a branch — is accounted for by exactly one counter.
fn dispatch_step(
    current: StepId,
    graph: &WorkflowGraph,
    inputs: &ExecInputs,
    gates: &mut GateLedger,
    loop_counts: &mut BTreeMap<StepId, u32>,
    visited: &mut Vec<StepId>,
) -> Result<StepEffect, ExecError> {
    record_visit(visited, current)?;
    let step = find_step(graph, current);
    let authority = StepAuthority::grant();
    let mut ctx = StepContext {
        current,
        step,
        graph,
        inputs,
        gates,
        loop_counts,
        visited,
    };
    dispatch(&step.kind).execute(authority, &mut ctx)
}

#[cfg(test)]
mod tests {
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
        let first = run(&graph, &inputs, &mut GateLedger::new()).unwrap();
        let second = run(&graph, &inputs, &mut GateLedger::new()).unwrap();
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
        let trace = run(&graph, &inputs, &mut GateLedger::new()).unwrap();
        assert_eq!(trace.visited, vec![StepId(0), StepId(1)]);
    }

    #[test]
    fn conditional_false_follows_else_branch() {
        let graph = conditional_graph();
        let mut inputs = ExecInputs::default();
        inputs.conditions.insert(StepId(0), false);
        let trace = run(&graph, &inputs, &mut GateLedger::new()).unwrap();
        assert_eq!(trace.visited, vec![StepId(0), StepId(2)]);
    }

    #[test]
    fn missing_condition_input_is_a_defined_refusal_not_a_default_branch() {
        let graph = conditional_graph();
        let inputs = ExecInputs::default();
        assert_eq!(
            run(&graph, &inputs, &mut GateLedger::new()),
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
        let err = run(&graph, &inputs, &mut GateLedger::new()).unwrap_err();
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
        let trace = run(&graph, &ExecInputs::default(), &mut GateLedger::new()).unwrap();
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
        let trace = run(&graph, &inputs, &mut GateLedger::new()).unwrap();
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
            run(&graph, &inputs, &mut GateLedger::new()),
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
            run(&graph, &ExecInputs::default(), &mut GateLedger::new()),
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
        let err = run(&graph, &ExecInputs::default(), &mut GateLedger::new()).unwrap_err();
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
            run(&graph, &inputs, &mut GateLedger::new()),
            Err(ExecError::GateNotDecided(StepId(0)))
        );
    }

    #[test]
    fn human_gate_with_an_approved_decision_proceeds_to_the_named_edge() {
        let graph = gated_graph();
        let mut inputs = ExecInputs::default();
        inputs.gate_specs.insert(StepId(0), gate_spec());
        inputs.gate_decisions.insert(StepId(0), gate_decision(1));
        let trace = run(&graph, &inputs, &mut GateLedger::new()).unwrap();
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
            run(&graph, &inputs, &mut GateLedger::new()),
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
        assert!(run(&graph, &inputs, &mut ledger).is_ok());
        // Same ledger, same decision id, a second run of the same graph:
        // the second run must not re-spend the same human decision.
        assert_eq!(
            run(&graph, &inputs, &mut ledger),
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
            run(&graph, &inputs, &mut GateLedger::new()),
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
        let trace = run(&graph, &ExecInputs::default(), &mut GateLedger::new()).unwrap();
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
        let first = run(&graph, &inputs, &mut GateLedger::new()).unwrap();
        let second = run(&graph, &inputs, &mut GateLedger::new()).unwrap();
        let third = run(&graph, &inputs, &mut GateLedger::new()).unwrap();
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
        let trace = run(&graph, &inputs, &mut GateLedger::new()).unwrap();
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
            run(&graph, &ExecInputs::default(), &mut GateLedger::new()),
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
        let err = dispatch_step(
            StepId(1), // the Join step
            &graph,
            &ExecInputs::default(),
            &mut ledger,
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
        let graph = gated_graph();
        let err = dispatch_step(
            StepId(0),
            &graph,
            &ExecInputs::default(),
            &mut ledger,
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
            run(&graph, &ExecInputs::default(), &mut GateLedger::new()),
            Err(ExecError::NotExecutable(StepId(0)))
        );
    }
}
