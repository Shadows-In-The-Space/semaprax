//! Typed workflow graph: stable step/edge identities, typed ports, and
//! validation into a bounded, deterministic state machine.
//!
//! This is the graph/schema layer for issue #208's typed workflow profile
//! (model routing, human gates, retries, compensation, checkpoints). It
//! shares a source file with, but is otherwise unrelated to, the
//! current-thread compiler-stage timing observer in `workflow_profile::Stage` and
//! `workflow_profile::enabled` — that module measures wall-clock time around
//! compiler phases and grants no semantics or authority; this module
//! defines the workflow engine's own step/edge/port schema.
//!
//! [`StepKind::Sequential`], [`StepKind::Conditional`],
//! [`StepKind::Parallel`]/[`StepKind::Join`], [`StepKind::Loop`],
//! [`StepKind::ModelCall`], [`StepKind::HumanGate`] and
//! [`StepKind::Terminal`] all have execution semantics in
//! [`super::engine`]. `Parallel`/`Join` execute as a deterministic
//! sequential simulation — every branch runs, in ascending [`StepId`]
//! order, on the one calling thread; there is no real concurrency to race
//! and no scheduler nondeterminism to reproduce (see
//! [`super::engine::StepExecutor`] for the seam every step kind's executor
//! goes through). [`StepKind::HumanGate`] grants nothing merely by being
//! reached: the engine only advances past it given an explicit, separately
//! evaluated [`super::human_gate::GateDecision`] (see [`super::human_gate`]
//! for the authority argument). [`StepKind::Declared`] variants are
//! admitted into the graph schema and validated structurally, but have no
//! executor in this slice; running one is a defined refusal, not a silent
//! no-op.

use std::collections::{BTreeMap, BTreeSet};

/// Maximum steps admitted in one workflow graph. Bounds validation cost and
/// rules out unbounded fan-out per the issue's "explicitly out of scope"
/// list.
pub const MAX_STEPS: usize = 256;

/// Bounds on one `Parallel`/`Join` pair's branch count. The issue asks for
/// "one bounded parallel/join profile first"; this is that bound.
pub const MIN_PARALLEL_BRANCHES: usize = 2;
pub const MAX_PARALLEL_BRANCHES: usize = 8;

/// Stable, persistent identity for one workflow step within its graph.
/// Mirrors the repository's "public declarations have persistent `@id`
/// identities" invariant for the workflow domain.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct StepId(pub u32);

/// Stable identity for one edge within its graph.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct EdgeId(pub u32);

/// A port identity, scoped to the step that declares it (not global).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct PortId(pub u32);

/// Closed, minimal typed-port vocabulary for dataflow checking. Not a
/// general type system: workflow ports carry small checked values, never
/// live capabilities, grants, secrets, or transport handles.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum PortType {
    Unit,
    Bool,
    Int,
    Text,
}

/// By convention, a [`StepKind::Conditional`] declares exactly two output
/// ports at these fixed IDs: the branch taken when its condition port is
/// `true`, and the branch taken when it is `false`.
pub const THEN_PORT: PortId = PortId(0);
pub const ELSE_PORT: PortId = PortId(1);

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Port {
    pub id: PortId,
    pub ty: PortType,
}

/// Step kinds declared but not executable by [`super::engine`] in this
/// slice. Each names a typed package interface the issue lists in scope;
/// none hard-codes a provider. Admitted into the graph schema so a workflow
/// author can declare the intended shape of a larger workflow today, but
/// running one is a defined refusal (see `engine::ExecError::NotExecutable`)
/// rather than a silent success.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeclaredStepKind {
    AgentCall,
    ToolCall,
    Job,
    SemanticChange,
    TestBuild,
    PublicationRequest,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum StepKind {
    /// One input, one output, no branching.
    Sequential,
    /// `condition_port` (declared in `in_ports`, typed `Bool`) selects
    /// exactly one of the two fixed branch out-ports ([`THEN_PORT`] /
    /// [`ELSE_PORT`]).
    Conditional { condition_port: PortId },
    /// Fan-out to a bounded set of direct successor steps (its branches).
    /// The branch set is exactly this step's out-edge targets, deduplicated
    /// — there is no separate declared branch list to drift from the edges.
    /// Because every non-branching step kind admits exactly one outgoing
    /// edge (see [`GraphError::AmbiguousOutEdges`]), and a `Join` step's
    /// declared predecessors must equal exactly this set (see
    /// [`GraphError::MissingJoinPath`]/[`GraphError::UnexpectedJoinPredecessor`]),
    /// a branch in a validated graph is always exactly one step whose sole
    /// out edge targets the join. The engine (see
    /// [`super::engine::StepExecutor`]) runs each branch step in ascending
    /// [`StepId`] order on one thread — a deterministic simulation of
    /// concurrency, not real concurrency, so there is nothing to race.
    Parallel,
    /// Waits for every branch of `parallel` and only those branches, then
    /// continues along its own single out edge. The engine reaches this
    /// kind only immediately after it has itself executed every branch of
    /// `parallel`; a `Join` step is never independently dispatched.
    Join { parallel: StepId },
    /// Explicit human decision boundary. Carries no authority by itself:
    /// see [`super::human_gate`]. The engine advances past this kind only
    /// given an explicit, separately evaluated
    /// [`super::human_gate::GateDecision`] presented out of band through
    /// [`super::engine::ExecInputs`]; reaching the step without one is a
    /// defined refusal ([`super::engine::ExecError::GateNotDecided`]), never
    /// a silent pass-through.
    HumanGate,
    /// Bounded loop controller. `max_iterations` must be nonzero. Only a
    /// [`StepKind::Loop`] step may be the target of a back edge (see
    /// [`GraphError::CycleWithoutBound`]); the engine refuses to enter a
    /// loop step beyond its declared bound.
    Loop { max_iterations: u32 },
    /// Deterministic model routing: `requested_model` is checked against a
    /// closed deployment policy at execution time (see
    /// [`super::model_routing`]), never chosen dynamically outside it.
    ModelCall { requested_model: String },
    /// No outgoing edges are permitted.
    Terminal,
    /// See [`DeclaredStepKind`].
    Declared(DeclaredStepKind),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StepDef {
    pub id: StepId,
    pub kind: StepKind,
    pub in_ports: Vec<Port>,
    pub out_ports: Vec<Port>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EdgeDef {
    pub id: EdgeId,
    pub from: StepId,
    pub from_port: PortId,
    pub to: StepId,
    pub to_port: PortId,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkflowGraph {
    pub steps: Vec<StepDef>,
    pub edges: Vec<EdgeDef>,
    pub entry: StepId,
}

/// Closed validation failure vocabulary. Every variant is a specific,
/// stable, structural reason; [`WorkflowGraph::validate`] never panics on
/// malformed input and never returns a partially-checked success.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GraphError {
    TooManySteps,
    DuplicateStepId(StepId),
    UnknownEntry(StepId),
    EdgeUnknownStep(EdgeId),
    EdgeUnknownPort(EdgeId),
    TypeMismatch(EdgeId),
    UnreachableStep(StepId),
    TerminalHasOutgoingEdge(StepId),
    DeadEnd(StepId),
    MissingConditionPort(StepId),
    MissingBranch(StepId, PortId),
    TooFewParallelBranches(StepId),
    TooManyParallelBranches(StepId),
    JoinReferencesNonParallel(StepId),
    MissingJoinPath(StepId, StepId),
    UnexpectedJoinPredecessor(StepId, StepId),
    UnboundedLoop(StepId),
    CycleWithoutBound(StepId),
    /// A non-branching step (anything other than `Conditional`, `Parallel`
    /// or `Join`) declared more than one outgoing edge. The engine in
    /// [`super::engine`] executes exactly one edge per non-branching step,
    /// so more than one would be a silent, unvalidated ambiguity.
    AmbiguousOutEdges(StepId),
}

impl WorkflowGraph {
    fn step(&self, id: StepId) -> Option<&StepDef> {
        self.steps.iter().find(|s| s.id == id)
    }

    fn out_edges(&self, id: StepId) -> impl Iterator<Item = &EdgeDef> {
        self.edges.iter().filter(move |e| e.from == id)
    }

    fn in_edges(&self, id: StepId) -> impl Iterator<Item = &EdgeDef> {
        self.edges.iter().filter(move |e| e.to == id)
    }

    fn successors(&self, id: StepId) -> BTreeSet<StepId> {
        self.out_edges(id).map(|e| e.to).collect()
    }

    fn predecessors(&self, id: StepId) -> BTreeSet<StepId> {
        self.in_edges(id).map(|e| e.from).collect()
    }

    /// Structural validation: unique identities, well-typed edges,
    /// reachability from `entry`, and the per-kind shape rules documented
    /// on [`StepKind`]. Deterministic: same graph, same first error (or
    /// success) every time — checks run in a fixed order over the input
    /// vectors' own order, never over an unordered set.
    pub fn validate(&self) -> Result<(), GraphError> {
        if self.steps.len() > MAX_STEPS {
            return Err(GraphError::TooManySteps);
        }
        let mut seen = BTreeSet::new();
        for step in &self.steps {
            if !seen.insert(step.id) {
                return Err(GraphError::DuplicateStepId(step.id));
            }
        }
        if self.step(self.entry).is_none() {
            return Err(GraphError::UnknownEntry(self.entry));
        }
        for edge in &self.edges {
            let (Some(from), Some(to)) = (self.step(edge.from), self.step(edge.to)) else {
                return Err(GraphError::EdgeUnknownStep(edge.id));
            };
            let from_ok = from.out_ports.iter().any(|p| p.id == edge.from_port);
            let to_ok = to.in_ports.iter().any(|p| p.id == edge.to_port);
            if !from_ok || !to_ok {
                return Err(GraphError::EdgeUnknownPort(edge.id));
            }
            let from_ty = from
                .out_ports
                .iter()
                .find(|p| p.id == edge.from_port)
                .map(|p| p.ty);
            let to_ty = to
                .in_ports
                .iter()
                .find(|p| p.id == edge.to_port)
                .map(|p| p.ty);
            if from_ty != to_ty {
                return Err(GraphError::TypeMismatch(edge.id));
            }
        }

        let reachable = self.reachable_from(self.entry);
        for step in &self.steps {
            if !reachable.contains(&step.id) {
                return Err(GraphError::UnreachableStep(step.id));
            }
        }

        for step in &self.steps {
            let out_count = self.out_edges(step.id).count();
            match &step.kind {
                StepKind::Terminal => {
                    if out_count != 0 {
                        return Err(GraphError::TerminalHasOutgoingEdge(step.id));
                    }
                }
                StepKind::Conditional { condition_port } => {
                    let has_condition = step
                        .in_ports
                        .iter()
                        .any(|p| p.id == *condition_port && p.ty == PortType::Bool);
                    if !has_condition {
                        return Err(GraphError::MissingConditionPort(step.id));
                    }
                    for branch in [THEN_PORT, ELSE_PORT] {
                        let has_edge = self.out_edges(step.id).any(|e| e.from_port == branch);
                        if !has_edge {
                            return Err(GraphError::MissingBranch(step.id, branch));
                        }
                    }
                }
                StepKind::Parallel => {
                    let branches = self.successors(step.id);
                    if branches.len() < MIN_PARALLEL_BRANCHES {
                        return Err(GraphError::TooFewParallelBranches(step.id));
                    }
                    if branches.len() > MAX_PARALLEL_BRANCHES {
                        return Err(GraphError::TooManyParallelBranches(step.id));
                    }
                }
                StepKind::Join { parallel } => {
                    let is_parallel = matches!(
                        self.step(*parallel).map(|s| &s.kind),
                        Some(StepKind::Parallel)
                    );
                    if !is_parallel {
                        return Err(GraphError::JoinReferencesNonParallel(step.id));
                    }
                    let branches = self.successors(*parallel);
                    let preds = self.predecessors(step.id);
                    if let Some(missing) = branches.iter().find(|b| !preds.contains(b)) {
                        return Err(GraphError::MissingJoinPath(*parallel, *missing));
                    }
                    if let Some(extra) = preds.iter().find(|p| !branches.contains(p)) {
                        return Err(GraphError::UnexpectedJoinPredecessor(step.id, *extra));
                    }
                    if out_count == 0 {
                        return Err(GraphError::DeadEnd(step.id));
                    }
                    // A `Join` step continues with exactly one successor once
                    // every branch has arrived, the same single-exit rule
                    // every other non-branching kind gets below. Without
                    // this, `engine::only_out_edge` would silently pick
                    // whichever of two out edges happened to be first in
                    // the vector instead of this being a caught authoring
                    // error.
                    if out_count > 1 {
                        return Err(GraphError::AmbiguousOutEdges(step.id));
                    }
                }
                StepKind::Loop { max_iterations } => {
                    if *max_iterations == 0 {
                        return Err(GraphError::UnboundedLoop(step.id));
                    }
                    if out_count == 0 {
                        return Err(GraphError::DeadEnd(step.id));
                    }
                    if out_count > 1 {
                        return Err(GraphError::AmbiguousOutEdges(step.id));
                    }
                }
                StepKind::Sequential
                | StepKind::HumanGate
                | StepKind::ModelCall { .. }
                | StepKind::Declared(_) => {
                    if out_count == 0 {
                        return Err(GraphError::DeadEnd(step.id));
                    }
                    if out_count > 1 {
                        return Err(GraphError::AmbiguousOutEdges(step.id));
                    }
                }
            }
        }

        self.check_bounded_cycles()
    }

    fn reachable_from(&self, start: StepId) -> BTreeSet<StepId> {
        let mut visited = BTreeSet::new();
        let mut stack = vec![start];
        while let Some(id) = stack.pop() {
            if !visited.insert(id) {
                continue;
            }
            for succ in self.successors(id) {
                if !visited.contains(&succ) {
                    stack.push(succ);
                }
            }
        }
        visited
    }

    /// Every back edge (target still on the current DFS stack) must target
    /// a [`StepKind::Loop`] step: that is what makes re-entering it bounded
    /// rather than an unbounded loop. Iterative DFS to stay within a fixed
    /// stack budget regardless of graph depth.
    fn check_bounded_cycles(&self) -> Result<(), GraphError> {
        #[derive(Clone, Copy, PartialEq)]
        enum Color {
            White,
            Gray,
            Black,
        }
        let mut color: BTreeMap<StepId, Color> =
            self.steps.iter().map(|s| (s.id, Color::White)).collect();
        // Explicit stack of (node, remaining children iterator index) to
        // avoid recursion depth tracking a hostile input's structure.
        for step in &self.steps {
            if color[&step.id] != Color::White {
                continue;
            }
            let mut stack: Vec<(StepId, Vec<StepId>, usize)> =
                vec![(step.id, self.successors(step.id).into_iter().collect(), 0)];
            color.insert(step.id, Color::Gray);
            while let Some((node, children, idx)) = stack.last_mut() {
                if *idx >= children.len() {
                    color.insert(*node, Color::Black);
                    stack.pop();
                    continue;
                }
                let child = children[*idx];
                *idx += 1;
                match color[&child] {
                    Color::White => {
                        color.insert(child, Color::Gray);
                        let grand = self.successors(child).into_iter().collect();
                        stack.push((child, grand, 0));
                    }
                    Color::Gray => {
                        let is_loop = matches!(
                            self.step(child).map(|s| &s.kind),
                            Some(StepKind::Loop { .. })
                        );
                        if !is_loop {
                            return Err(GraphError::CycleWithoutBound(child));
                        }
                    }
                    Color::Black => {}
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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

    #[test]
    fn linear_sequential_pipeline_validates() {
        let graph = WorkflowGraph {
            steps: vec![
                seq(0),
                seq(1),
                StepDef {
                    id: StepId(2),
                    kind: StepKind::Terminal,
                    in_ports: vec![unit_port(0)],
                    out_ports: vec![],
                },
            ],
            edges: vec![edge(0, 0, 1), edge(1, 1, 2)],
            entry: StepId(0),
        };
        assert_eq!(graph.validate(), Ok(()));
    }

    #[test]
    fn unreachable_step_is_detected() {
        let graph = WorkflowGraph {
            steps: vec![
                StepDef {
                    id: StepId(0),
                    kind: StepKind::Terminal,
                    in_ports: vec![],
                    out_ports: vec![],
                },
                seq(1),
            ],
            edges: vec![],
            entry: StepId(0),
        };
        assert_eq!(
            graph.validate(),
            Err(GraphError::UnreachableStep(StepId(1)))
        );
    }

    #[test]
    fn dead_end_non_terminal_step_is_detected() {
        let graph = WorkflowGraph {
            steps: vec![StepDef {
                id: StepId(0),
                kind: StepKind::Sequential,
                in_ports: vec![],
                out_ports: vec![],
            }],
            edges: vec![],
            entry: StepId(0),
        };
        assert_eq!(graph.validate(), Err(GraphError::DeadEnd(StepId(0))));
    }

    #[test]
    fn terminal_with_outgoing_edge_is_rejected() {
        let graph = WorkflowGraph {
            steps: vec![
                StepDef {
                    id: StepId(0),
                    kind: StepKind::Terminal,
                    in_ports: vec![],
                    out_ports: vec![unit_port(0)],
                },
                seq(1),
            ],
            edges: vec![edge(0, 0, 1)],
            entry: StepId(0),
        };
        assert_eq!(
            graph.validate(),
            Err(GraphError::TerminalHasOutgoingEdge(StepId(0)))
        );
    }

    #[test]
    fn type_mismatch_across_edge_is_rejected() {
        let bool_out = StepDef {
            id: StepId(0),
            kind: StepKind::Sequential,
            in_ports: vec![],
            out_ports: vec![Port {
                id: PortId(0),
                ty: PortType::Bool,
            }],
        };
        let int_in = StepDef {
            id: StepId(1),
            kind: StepKind::Terminal,
            in_ports: vec![Port {
                id: PortId(0),
                ty: PortType::Int,
            }],
            out_ports: vec![],
        };
        let graph = WorkflowGraph {
            steps: vec![bool_out, int_in],
            edges: vec![edge(0, 0, 1)],
            entry: StepId(0),
        };
        assert_eq!(graph.validate(), Err(GraphError::TypeMismatch(EdgeId(0))));
    }

    fn conditional_graph(then_edge: bool, else_edge: bool) -> WorkflowGraph {
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
        let mut edges = vec![];
        let mut steps = vec![cond];
        if then_edge {
            edges.push(EdgeDef {
                id: EdgeId(0),
                from: StepId(0),
                from_port: THEN_PORT,
                to: StepId(1),
                to_port: PortId(0),
            });
            steps.push(StepDef {
                id: StepId(1),
                kind: StepKind::Terminal,
                in_ports: vec![unit_port(0)],
                out_ports: vec![],
            });
        }
        if else_edge {
            edges.push(EdgeDef {
                id: EdgeId(1),
                from: StepId(0),
                from_port: ELSE_PORT,
                to: StepId(2),
                to_port: PortId(0),
            });
            steps.push(StepDef {
                id: StepId(2),
                kind: StepKind::Terminal,
                in_ports: vec![unit_port(0)],
                out_ports: vec![],
            });
        }
        WorkflowGraph {
            steps,
            edges,
            entry: StepId(0),
        }
    }

    #[test]
    fn conditional_with_both_branches_validates() {
        assert_eq!(conditional_graph(true, true).validate(), Ok(()));
    }

    #[test]
    fn conditional_missing_else_branch_is_detected() {
        assert_eq!(
            conditional_graph(true, false).validate(),
            Err(GraphError::MissingBranch(StepId(0), ELSE_PORT))
        );
    }

    /// When `wire_all_to_join` is false, branch 0 is instead wired to a
    /// dummy sink terminal so it still has an outgoing edge (and so
    /// validation reaches the `MissingJoinPath` check for it rather than
    /// stopping earlier on an unrelated `DeadEnd`).
    fn parallel_join_graph(branch_count: usize, wire_all_to_join: bool) -> WorkflowGraph {
        let mut steps = vec![StepDef {
            id: StepId(0),
            kind: StepKind::Parallel,
            in_ports: vec![],
            out_ports: (0..branch_count as u32).map(unit_port).collect(),
        }];
        let mut edges = vec![];
        const DUMMY_SINK: u32 = 900;
        let mut needs_dummy_sink = false;
        for i in 0..branch_count as u32 {
            let branch_id = 10 + i;
            steps.push(seq(branch_id));
            edges.push(EdgeDef {
                id: EdgeId(i),
                from: StepId(0),
                from_port: PortId(i),
                to: StepId(branch_id),
                to_port: PortId(0),
            });
            if wire_all_to_join || i > 0 {
                edges.push(EdgeDef {
                    id: EdgeId(100 + i),
                    from: StepId(branch_id),
                    from_port: PortId(0),
                    to: StepId(1),
                    to_port: PortId(i),
                });
            } else {
                edges.push(EdgeDef {
                    id: EdgeId(200 + i),
                    from: StepId(branch_id),
                    from_port: PortId(0),
                    to: StepId(DUMMY_SINK),
                    to_port: PortId(0),
                });
                needs_dummy_sink = true;
            }
        }
        if needs_dummy_sink {
            steps.push(StepDef {
                id: StepId(DUMMY_SINK),
                kind: StepKind::Terminal,
                in_ports: vec![unit_port(0)],
                out_ports: vec![],
            });
        }
        steps.push(StepDef {
            id: StepId(1),
            kind: StepKind::Join {
                parallel: StepId(0),
            },
            in_ports: (0..branch_count as u32).map(unit_port).collect(),
            out_ports: vec![unit_port(0)],
        });
        steps.push(StepDef {
            id: StepId(2),
            kind: StepKind::Terminal,
            in_ports: vec![unit_port(0)],
            out_ports: vec![],
        });
        edges.push(EdgeDef {
            id: EdgeId(999),
            from: StepId(1),
            from_port: PortId(0),
            to: StepId(2),
            to_port: PortId(0),
        });
        WorkflowGraph {
            steps,
            edges,
            entry: StepId(0),
        }
    }

    #[test]
    fn bounded_parallel_join_validates() {
        assert_eq!(parallel_join_graph(3, true).validate(), Ok(()));
    }

    #[test]
    fn parallel_below_minimum_branches_is_rejected() {
        let graph = WorkflowGraph {
            steps: vec![
                StepDef {
                    id: StepId(0),
                    kind: StepKind::Parallel,
                    in_ports: vec![],
                    out_ports: vec![unit_port(0)],
                },
                seq(1),
            ],
            edges: vec![edge(0, 0, 1)],
            entry: StepId(0),
        };
        assert_eq!(
            graph.validate(),
            Err(GraphError::TooFewParallelBranches(StepId(0)))
        );
    }

    #[test]
    fn parallel_above_maximum_branches_is_rejected() {
        let n = MAX_PARALLEL_BRANCHES + 1;
        let graph = parallel_join_graph(n, true);
        // Reachability/dead-end pass before the branch-count check reaches
        // it; this fixture is unreachable-clean, so the branch bound fires.
        assert_eq!(
            graph.validate(),
            Err(GraphError::TooManyParallelBranches(StepId(0)))
        );
    }

    #[test]
    fn join_missing_a_branch_path_is_detected() {
        let graph = parallel_join_graph(3, false);
        assert_eq!(
            graph.validate(),
            Err(GraphError::MissingJoinPath(StepId(0), StepId(10)))
        );
    }

    #[test]
    fn join_step_with_two_out_edges_is_rejected_as_ambiguous() {
        let mut graph = parallel_join_graph(2, true);
        // Give the join step (StepId(1)) a second outgoing edge alongside
        // its existing one to StepId(2); a bare `Terminal` sink keeps this
        // fixture otherwise well-formed.
        graph.steps.push(StepDef {
            id: StepId(50),
            kind: StepKind::Terminal,
            in_ports: vec![unit_port(0)],
            out_ports: vec![],
        });
        graph.edges.push(EdgeDef {
            id: EdgeId(998),
            from: StepId(1),
            from_port: PortId(0),
            to: StepId(50),
            to_port: PortId(0),
        });
        assert_eq!(
            graph.validate(),
            Err(GraphError::AmbiguousOutEdges(StepId(1)))
        );
    }

    #[test]
    fn join_referencing_non_parallel_step_is_rejected() {
        let graph = WorkflowGraph {
            steps: vec![
                seq(0),
                StepDef {
                    id: StepId(1),
                    kind: StepKind::Join {
                        parallel: StepId(0),
                    },
                    in_ports: vec![unit_port(0)],
                    out_ports: vec![unit_port(0)],
                },
                StepDef {
                    id: StepId(2),
                    kind: StepKind::Terminal,
                    in_ports: vec![unit_port(0)],
                    out_ports: vec![],
                },
            ],
            edges: vec![edge(0, 0, 1), edge(1, 1, 2)],
            entry: StepId(0),
        };
        assert_eq!(
            graph.validate(),
            Err(GraphError::JoinReferencesNonParallel(StepId(1)))
        );
    }

    #[test]
    fn loop_with_zero_bound_is_rejected() {
        let graph = WorkflowGraph {
            steps: vec![
                StepDef {
                    id: StepId(0),
                    kind: StepKind::Loop { max_iterations: 0 },
                    in_ports: vec![unit_port(0)],
                    out_ports: vec![unit_port(0)],
                },
                StepDef {
                    id: StepId(1),
                    kind: StepKind::Terminal,
                    in_ports: vec![unit_port(0)],
                    out_ports: vec![],
                },
            ],
            edges: vec![edge(0, 0, 1)],
            entry: StepId(0),
        };
        assert_eq!(graph.validate(), Err(GraphError::UnboundedLoop(StepId(0))));
    }

    #[test]
    fn back_edge_into_a_loop_step_validates() {
        let graph = WorkflowGraph {
            steps: vec![
                StepDef {
                    id: StepId(0),
                    kind: StepKind::Loop { max_iterations: 3 },
                    in_ports: vec![unit_port(0)],
                    out_ports: vec![unit_port(0)],
                },
                StepDef {
                    id: StepId(1),
                    kind: StepKind::Conditional {
                        condition_port: PortId(1),
                    },
                    in_ports: vec![
                        unit_port(0),
                        Port {
                            id: PortId(1),
                            ty: PortType::Bool,
                        },
                    ],
                    out_ports: vec![unit_port(0), unit_port(1)],
                },
                StepDef {
                    id: StepId(2),
                    kind: StepKind::Terminal,
                    in_ports: vec![unit_port(0)],
                    out_ports: vec![],
                },
            ],
            edges: vec![
                edge(0, 0, 1),
                EdgeDef {
                    id: EdgeId(1),
                    from: StepId(1),
                    from_port: THEN_PORT,
                    to: StepId(0),
                    to_port: PortId(0),
                },
                EdgeDef {
                    id: EdgeId(2),
                    from: StepId(1),
                    from_port: ELSE_PORT,
                    to: StepId(2),
                    to_port: PortId(0),
                },
            ],
            entry: StepId(0),
        };
        assert_eq!(graph.validate(), Ok(()));
    }

    #[test]
    fn back_edge_into_a_non_loop_step_is_rejected() {
        let graph = WorkflowGraph {
            steps: vec![
                seq(0),
                StepDef {
                    id: StepId(1),
                    kind: StepKind::Conditional {
                        condition_port: PortId(1),
                    },
                    in_ports: vec![
                        unit_port(0),
                        Port {
                            id: PortId(1),
                            ty: PortType::Bool,
                        },
                    ],
                    out_ports: vec![unit_port(0), unit_port(1)],
                },
                StepDef {
                    id: StepId(2),
                    kind: StepKind::Terminal,
                    in_ports: vec![unit_port(0)],
                    out_ports: vec![],
                },
            ],
            edges: vec![
                edge(0, 0, 1),
                EdgeDef {
                    id: EdgeId(1),
                    from: StepId(1),
                    from_port: THEN_PORT,
                    to: StepId(0),
                    to_port: PortId(0),
                },
                EdgeDef {
                    id: EdgeId(2),
                    from: StepId(1),
                    from_port: ELSE_PORT,
                    to: StepId(2),
                    to_port: PortId(0),
                },
            ],
            entry: StepId(0),
        };
        assert_eq!(
            graph.validate(),
            Err(GraphError::CycleWithoutBound(StepId(0)))
        );
    }

    #[test]
    fn duplicate_step_id_is_detected() {
        let graph = WorkflowGraph {
            steps: vec![seq(0), seq(0)],
            edges: vec![],
            entry: StepId(0),
        };
        assert_eq!(
            graph.validate(),
            Err(GraphError::DuplicateStepId(StepId(0)))
        );
    }

    #[test]
    fn unknown_entry_is_detected() {
        let graph = WorkflowGraph {
            steps: vec![seq(0)],
            edges: vec![],
            entry: StepId(9),
        };
        assert_eq!(graph.validate(), Err(GraphError::UnknownEntry(StepId(9))));
    }

    #[test]
    fn edge_referencing_unknown_step_is_detected() {
        let graph = WorkflowGraph {
            steps: vec![seq(0)],
            edges: vec![edge(0, 0, 5)],
            entry: StepId(0),
        };
        assert_eq!(
            graph.validate(),
            Err(GraphError::EdgeUnknownStep(EdgeId(0)))
        );
    }

    #[test]
    fn edge_referencing_unknown_port_is_detected() {
        let graph = WorkflowGraph {
            steps: vec![seq(0), seq(1)],
            edges: vec![EdgeDef {
                id: EdgeId(0),
                from: StepId(0),
                from_port: PortId(9),
                to: StepId(1),
                to_port: PortId(0),
            }],
            entry: StepId(0),
        };
        assert_eq!(
            graph.validate(),
            Err(GraphError::EdgeUnknownPort(EdgeId(0)))
        );
    }

    #[test]
    fn too_many_steps_is_rejected() {
        let steps: Vec<StepDef> = (0..=MAX_STEPS as u32).map(seq).collect();
        let graph = WorkflowGraph {
            steps,
            edges: vec![],
            entry: StepId(0),
        };
        assert_eq!(graph.validate(), Err(GraphError::TooManySteps));
    }

    #[test]
    fn sequential_step_with_two_out_edges_is_rejected_as_ambiguous() {
        let branchy = StepDef {
            id: StepId(0),
            kind: StepKind::Sequential,
            in_ports: vec![],
            out_ports: vec![unit_port(0)],
        };
        let graph = WorkflowGraph {
            steps: vec![branchy, seq(1), seq(2)],
            edges: vec![
                EdgeDef {
                    id: EdgeId(0),
                    from: StepId(0),
                    from_port: PortId(0),
                    to: StepId(1),
                    to_port: PortId(0),
                },
                EdgeDef {
                    id: EdgeId(1),
                    from: StepId(0),
                    from_port: PortId(0),
                    to: StepId(2),
                    to_port: PortId(0),
                },
            ],
            entry: StepId(0),
        };
        assert_eq!(
            graph.validate(),
            Err(GraphError::AmbiguousOutEdges(StepId(0)))
        );
    }

    #[test]
    fn declared_step_kind_validates_structurally() {
        let graph = WorkflowGraph {
            steps: vec![
                StepDef {
                    id: StepId(0),
                    kind: StepKind::Declared(DeclaredStepKind::Job),
                    in_ports: vec![],
                    out_ports: vec![unit_port(0)],
                },
                StepDef {
                    id: StepId(1),
                    kind: StepKind::Terminal,
                    in_ports: vec![unit_port(0)],
                    out_ports: vec![],
                },
            ],
            edges: vec![edge(0, 0, 1)],
            entry: StepId(0),
        };
        assert_eq!(graph.validate(), Ok(()));
    }
}
