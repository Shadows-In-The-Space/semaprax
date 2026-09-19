//! A minimal, deterministic executor for the step kinds this slice
//! actually implements.
//!
//! [`run`] executes [`StepKind::Sequential`], [`StepKind::Conditional`],
//! [`StepKind::Loop`] (bounded), [`StepKind::ModelCall`] (routed through
//! [`super::model_routing`], with an opt-in retry loop against a scripted
//! attempt sequence — see [`ExecInputs::attempt_script`] below),
//! [`StepKind::HumanGate`] (authorized through [`super::human_gate`]),
//! [`StepKind::Parallel`]/[`StepKind::Join`] (as a deterministic sequential
//! simulation — see [`StepExecutor`] below), and the five
//! decide-and-record [`super::graph::DeclaredStepKind`] kinds — AgentCall,
//! ToolCall, Job, TestBuild, PublicationRequest — routed through
//! [`DispatchExecutor`] and [`super::declared_dispatch`]. The sixth,
//! `SemanticChange`, is a defined refusal
//! (`ExecError::SemanticChangeNotGranted`, see [`SemanticChangeExecutor`]),
//! never a silent no-op or a made-up default transition — this
//! repository's completion matrix must not claim more than each executor
//! actually does.
//!
//! `run` always validates the graph first, so a caller can never execute
//! an unchecked structure. Given the same graph, the same [`ExecInputs`],
//! and a caller-supplied [`super::human_gate::GateLedger`] in the same
//! starting state, `run` produces a byte-identical [`ExecTrace`] every
//! time: it makes no use of wall-clock time, randomness, thread spawning,
//! or map/set iteration order beyond `BTreeMap`/`BTreeSet`'s own key
//! order, which is itself a deterministic total order over [`StepId`].
//!
//! # Retry ceiling and compensation commit order
//!
//! A `ModelCall` step with an [`ExecInputs::attempt_script`] entry retries
//! its effect by consuming that script's entries in order, deciding after
//! each failed attempt with [`super::retry::decide_retry`] against the
//! step's declared [`ExecInputs::retry_budgets`] ceiling — the same
//! function [`super::retry`]'s own unit tests exercise standalone, now
//! actually stopping the loop rather than only classifying one outcome in
//! isolation. A step with no script entry is unaffected: it routes and
//! succeeds exactly as it did before this existed.
//!
//! Every step named in [`ExecInputs::compensable`] that succeeds is
//! recorded, in execution order, into the [`super::compensation_order::CommitLog`]
//! the caller threads through `run` — the same log
//! [`super::compensation_order::CommitLog::compensation_order`] derives a
//! replay proof from. `run` never runs a compensation itself: on any
//! failure (a `StepFailed` from an exhausted retry budget or any other
//! `ExecError`), the caller reads back whatever committed before the error
//! and drives its own [`super::compensation::CompensationLedger`] against
//! the derived order.
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

use super::compensation_order::CommitLog;
use super::declared_dispatch::{
    decide as decide_dispatch, DispatchError, DispatchPolicy, DispatchRequest,
};
use super::graph::{
    DeclaredStepKind, StepDef, StepId, StepKind, WorkflowGraph, ELSE_PORT, THEN_PORT,
};
use super::human_gate::{GateDecision, GateError, GateLedger, GateSpec};
use super::model_routing::{route, DeploymentPolicy, RoutingError};
use super::retry::{
    decide_retry, AttemptOutcomeClass, RetryBudget, RetryDecision, ScriptedAttempt,
};
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
    /// A `ModelCall` step has a scripted [`ScriptedAttempt`] sequence in
    /// [`ExecInputs::attempt_script`] but no matching entry in
    /// [`ExecInputs::retry_budgets`]. A step that can fail must have an
    /// explicit retry ceiling; there is no implicit unlimited or
    /// zero-attempt default.
    MissingRetryBudget(StepId),
    /// A `ModelCall` step's [`ScriptedAttempt`] sequence ran out before any
    /// attempt resolved (succeeded, or was classified `GiveUp`/exhausted).
    /// This is a caller-scripting error, not a runtime retry failure: it
    /// means the script under-specifies what should happen, and the engine
    /// refuses rather than guessing a default outcome for the missing entry.
    AttemptScriptExhausted(StepId),
    /// A `ModelCall` step exhausted its retry budget, or hit an outcome
    /// class [`super::retry::retry_is_permitted`] never allows to retry,
    /// without ever succeeding. This is the one failure this module raises
    /// after some prior steps may already have committed compensable
    /// effects — see [`ExecInputs::compensable`] and [`run`]'s own
    /// documentation for how a caller recovers the order to compensate them
    /// in.
    StepFailed(StepId, AttemptOutcomeClass),
    /// A `Declared` step (`AgentCall`, `ToolCall`, `Job`, `TestBuild`, or
    /// `PublicationRequest`) was reached but the caller supplied neither a
    /// [`DispatchRequest`] nor a [`DispatchPolicy`] for it in
    /// [`ExecInputs::declared_dispatch_requests`] /
    /// [`ExecInputs::declared_dispatch_policies`]. Mirrors
    /// `GateNotDecided`: reaching a schema-only step never authorizes it on
    /// its own.
    DispatchNotDeclared(StepId),
    /// A `Declared` step's [`DispatchRequest::target`] is not a member of
    /// the [`DispatchPolicy`] the caller declared for it. [`DispatchExecutor`]
    /// only ever decides admissibility — it never invokes, spawns, or
    /// publishes anything itself, admitted or not; see
    /// [`super::declared_dispatch`].
    DispatchRefused(StepId, DispatchError),
    /// A `SemanticChange` step was reached. Refused unconditionally: the
    /// graph schema carries no target payload for this engine to decide
    /// about (see [`super::graph::DeclaredStepKind`]), and this engine has
    /// no filesystem or project authority to rewrite authoritative source
    /// even if it did. Issue #274 additionally found that the one operation
    /// this repository has actually built a checked preview for,
    /// `rename_display_name` in `src/project/semantic_transaction.rs`, is
    /// unsatisfiable for any project with commented bundled dependencies —
    /// so a decide-and-record executor here would not have a generally
    /// trustworthy decision to make even given real project state. See
    /// [`SemanticChangeExecutor`].
    SemanticChangeNotGranted(StepId),
}

/// Caller-supplied values the engine has no way to compute itself: the
/// boolean at each `Conditional` step's condition port, the deployment
/// policy in force for each `ModelCall` step, the declared spec plus the
/// out-of-band decision for each `HumanGate` step, and — for a `ModelCall`
/// step whose effect can genuinely fail — its retry budget, its scripted
/// attempt outcomes, and whether it commits an effect that needs
/// compensating.
///
/// `attempt_script`/`retry_budgets` are opt in per step: a `ModelCall` step
/// with no entry in `attempt_script` behaves exactly as before this field
/// existed — it routes and succeeds on the strength of [`super::model_routing::route`]
/// alone, with no retry loop and nothing recorded into a [`CommitLog`].
#[derive(Default, Debug, Clone)]
pub struct ExecInputs {
    pub conditions: BTreeMap<StepId, bool>,
    pub model_policies: BTreeMap<StepId, DeploymentPolicy>,
    pub gate_specs: BTreeMap<StepId, GateSpec>,
    pub gate_decisions: BTreeMap<StepId, GateDecision>,
    /// Per-step retry ceiling. Required (and consulted) only for a step
    /// that also has an entry in `attempt_script`.
    pub retry_budgets: BTreeMap<StepId, RetryBudget>,
    /// Per-step scripted sequence of attempt outcomes, consumed in order as
    /// the engine (re)attempts that step's effect. Presence of an entry
    /// here is what turns on the retry loop for that step at all.
    pub attempt_script: BTreeMap<StepId, Vec<ScriptedAttempt>>,
    /// Steps whose successful effect must be recorded into the [`CommitLog`]
    /// `run` is given, because it needs compensating if a later step in the
    /// same run fails. A step's own success never decides this on its
    /// behalf — compensability is a property the workflow's deployment
    /// declares, not one the engine infers from a step kind.
    pub compensable: BTreeSet<StepId>,
    /// Per-step declared dispatch request for one of the five
    /// decide-and-record `Declared` kinds (`AgentCall`, `ToolCall`, `Job`,
    /// `TestBuild`, `PublicationRequest`). Required (together with a
    /// matching entry in `declared_dispatch_policies`) only for a step of
    /// one of those kinds; absent for every other step kind and for
    /// `SemanticChange`, which this engine always refuses regardless of
    /// what a caller supplies here.
    pub declared_dispatch_requests: BTreeMap<StepId, DispatchRequest>,
    /// Per-step declared allow-list a `declared_dispatch_requests` entry is
    /// checked against. See [`super::declared_dispatch::DispatchPolicy`].
    pub declared_dispatch_policies: BTreeMap<StepId, DispatchPolicy>,
    /// Identifies this execution for [`super::compensation::CompensationKey`]
    /// / [`super::compensation_order::CommitRecord`] purposes. A caller
    /// resuming the *same* logical run (so that its compensations must not
    /// re-fire) reuses the same `run_id`; a genuinely new run uses a new one.
    pub run_id: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExecTrace {
    pub visited: Vec<StepId>,
    pub routed_models: Vec<(StepId, String)>,
    /// Every `Declared`-kind admission [`DispatchExecutor`] decided during
    /// this run, in execution order: the step that decided it, which
    /// [`DeclaredStepKind`] it was, and the admitted target name. Recording
    /// an entry here is the full extent of what this engine does for that
    /// step — it never itself invokes, spawns, or publishes the named
    /// target.
    pub admitted_dispatches: Vec<(StepId, DeclaredStepKind, String)>,
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
///
/// `commits` is threaded the same way, and is what closes the "compensation
/// ledger not threaded through `run`" gap: every step named in
/// [`ExecInputs::compensable`] that succeeds is recorded into it, in
/// execution order, using [`ExecInputs::run_id`]. `run` never calls
/// [`super::compensation::CompensationLedger::apply`] itself and never
/// decides what a compensation *does* — per the repository invariant that a
/// settlement or concurrency model is proof data, not permission to perform
/// a physical finalizer, `run` only produces the ordered record; a caller
/// that catches an `Err` here (or any other, since `commits` reflects
/// whatever committed before the error regardless of its kind) recovers the
/// required replay order with `commits.compensation_order()` and drives its
/// own [`super::compensation::CompensationLedger`] against it.
pub fn run(
    graph: &WorkflowGraph,
    inputs: &ExecInputs,
    gates: &mut GateLedger,
    commits: &mut CommitLog,
) -> Result<ExecTrace, ExecError> {
    graph.validate().map_err(|_| ExecError::InvalidGraph)?;

    let mut current = graph.entry;
    let mut visited = Vec::new();
    let mut routed_models = Vec::new();
    let mut admitted_dispatches = Vec::new();
    let mut loop_counts: BTreeMap<StepId, u32> = BTreeMap::new();

    loop {
        let effect = dispatch_step(
            current,
            graph,
            inputs,
            gates,
            commits,
            &mut loop_counts,
            &mut visited,
        )?;
        routed_models.extend(effect.routed_models);
        admitted_dispatches.extend(effect.admitted_dispatches);
        match effect.next {
            Some(next) => current = next,
            None => break,
        }
    }

    Ok(ExecTrace {
        visited,
        routed_models,
        admitted_dispatches,
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
    commits: &'a mut CommitLog,
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
    admitted_dispatches: Vec<(StepId, DeclaredStepKind, String)>,
}

impl StepEffect {
    fn advance(next: StepId) -> Self {
        StepEffect {
            next: Some(next),
            routed_models: Vec::new(),
            admitted_dispatches: Vec::new(),
        }
    }

    fn terminal() -> Self {
        StepEffect {
            next: None,
            routed_models: Vec::new(),
            admitted_dispatches: Vec::new(),
        }
    }
}

/// The sealed executor seam for running one workflow step.
///
/// Every step kind [`run`] actually executes has exactly one implementor
/// here: [`SequentialExecutor`], [`ConditionalExecutor`], [`LoopExecutor`],
/// [`ModelCallExecutor`], [`HumanGateExecutor`], [`ParallelExecutor`],
/// [`TerminalExecutor`], and (one instance per kind) [`DispatchExecutor`]
/// for the five decide-and-record `Declared` kinds. [`SemanticChangeExecutor`]
/// unconditionally refuses the sixth, `SemanticChange`.
/// [`NotExecutableExecutor`] backs the one remaining refusal this slice
/// has: [`StepKind::Join`] reached any way other than immediately after
/// [`ParallelExecutor`] finishes its branches. `StepExecutor` is
/// `pub(crate)` so its contract is visible within the crate, but it cannot
/// be *implemented* from outside this file: the supertrait bound requires
/// `sealed::Sealed`, and `sealed` is private to this module.
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

/// Executes a `ModelCall` step, retrying its effect against a scripted
/// attempt sequence when the caller supplied one.
///
/// Routing (whether `requested_model` is in policy) is checked once, before
/// any attempt: a request outside the deployment policy is a configuration
/// refusal, never something a retry could fix, so it is never itself an
/// [`AttemptOutcomeClass`] and never consumes retry budget.
///
/// With no [`ExecInputs::attempt_script`] entry for this step, behavior is
/// exactly what it was before this executor could retry at all: route, then
/// succeed. With an entry, each attempt is consumed from the script in
/// order; [`decide_retry`] — the same function [`super::retry`]'s own tests
/// exercise standalone — decides, from the *real* [`RetryBudget`] threaded
/// in through [`ExecInputs::retry_budgets`], whether to consume another
/// scripted attempt or stop. A budget of `max_attempts: 2` genuinely stops
/// the loop after two attempts even if the script has a third, succeeding,
/// entry still unconsumed — proven by
/// `retry_ceiling_stops_before_a_later_scripted_success` below — and an
/// [`AttemptOutcomeClass`] retry never permits (`Uncertain`,
/// `CompletedWithResponse`) stops the loop on its very first failed attempt
/// regardless of remaining budget, proven by
/// `uncertain_outcome_stops_before_a_later_scripted_success`.
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

        if let Some(script) = ctx.inputs.attempt_script.get(&ctx.current) {
            let budget = ctx
                .inputs
                .retry_budgets
                .get(&ctx.current)
                .copied()
                .ok_or(ExecError::MissingRetryBudget(ctx.current))?;
            let mut attempts_made: u32 = 0;
            loop {
                let attempt = script
                    .get(attempts_made as usize)
                    .ok_or(ExecError::AttemptScriptExhausted(ctx.current))?;
                attempts_made += 1;
                if attempt.succeeded {
                    break;
                }
                match decide_retry(budget, attempts_made, attempt.outcome) {
                    RetryDecision::Retry => continue,
                    RetryDecision::GiveUp | RetryDecision::ExhaustedButPermitted => {
                        return Err(ExecError::StepFailed(ctx.current, attempt.outcome));
                    }
                }
            }
        }

        if ctx.inputs.compensable.contains(&ctx.current) {
            ctx.commits.record(ctx.current, ctx.inputs.run_id);
        }

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

/// Refuses unconditionally. Backs any reach of [`StepKind::Join`] that did
/// not go through [`ParallelExecutor`] finishing its branches.
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

/// Decides admissibility for one of the five decide-and-record `Declared`
/// kinds ([`DeclaredStepKind::AgentCall`], `ToolCall`, `Job`, `TestBuild`,
/// `PublicationRequest`). One instance per kind (its field), constructed
/// fresh in [`dispatch`]; the field only ever labels which kind is being
/// recorded and plays no part in the decision itself.
///
/// Given a caller-declared [`DispatchRequest`] and [`DispatchPolicy`] for
/// the current step (both required — see [`ExecError::DispatchNotDeclared`]),
/// this executor calls [`super::declared_dispatch::decide`], the one pure
/// admission-decision function, and on success records `(step, kind,
/// admitted target)` into the effect's `admitted_dispatches`. It never
/// invokes an agent, runs a tool, spawns a job, runs a build, or publishes
/// anything: recording the decision is the entire effect. A caller with its
/// own, separately granted authority is free to act on an admitted
/// dispatch; this executor only ever decided whether the request was in
/// scope.
struct DispatchExecutor(DeclaredStepKind);
impl sealed::Sealed for DispatchExecutor {}
impl StepExecutor for DispatchExecutor {
    fn execute(
        &self,
        _authority: StepAuthority,
        ctx: &mut StepContext<'_>,
    ) -> Result<StepEffect, ExecError> {
        let (request, policy) = match (
            ctx.inputs.declared_dispatch_requests.get(&ctx.current),
            ctx.inputs.declared_dispatch_policies.get(&ctx.current),
        ) {
            (Some(request), Some(policy)) => (request, policy),
            _ => return Err(ExecError::DispatchNotDeclared(ctx.current)),
        };
        let target = decide_dispatch(policy, request)
            .map_err(|e| ExecError::DispatchRefused(ctx.current, e))?;
        let mut effect = StepEffect::advance(only_out_edge(ctx.graph, ctx.current));
        effect
            .admitted_dispatches
            .push((ctx.current, self.0, target));
        Ok(effect)
    }
}

/// Refuses `SemanticChange` unconditionally, with
/// [`ExecError::SemanticChangeNotGranted`] naming why.
///
/// `src/project/semantic_transaction.rs` has real machinery for staging a
/// checked source rewrite (`SemanticTransaction::rename_display_name` and
/// its siblings) — but two things rule out wiring this schema-only step to
/// it the way the other five `Declared` kinds are wired to
/// [`DispatchExecutor`]:
///
/// 1. [`StepKind::Declared`] carries no target payload at all (see
///    [`DeclaredStepKind`]), so there is no project, workspace revision,
///    rename target, or expected-old-value for this engine to decide
///    anything about even in principle. Threading real project state in
///    would mean this graph-and-step-id-only engine reaching outside
///    itself for a live project handle — exactly the ambient authority
///    this repository's capabilities invariant rules out for
///    compiler-adjacent code.
/// 2. Issue #274 found that the one operation this repository has actually
///    built a checked preview for, `rename_display_name`, is unsatisfiable
///    for any project with commented bundled dependencies. Even a caller
///    that did thread real project state through would not get a
///    generally trustworthy decision out of it today.
///
/// Refusing here, with a distinct error naming the reason, is preferred
/// over inventing a decision this engine cannot make honestly, or wiring an
/// executor whose only real-world path is one issue #274 already proved
/// cannot succeed.
struct SemanticChangeExecutor;
impl sealed::Sealed for SemanticChangeExecutor {}
impl StepExecutor for SemanticChangeExecutor {
    fn execute(
        &self,
        _authority: StepAuthority,
        ctx: &mut StepContext<'_>,
    ) -> Result<StepEffect, ExecError> {
        Err(ExecError::SemanticChangeNotGranted(ctx.current))
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
        let mut admitted_dispatches = Vec::new();
        for branch in branches {
            let effect = dispatch_step(
                branch,
                ctx.graph,
                ctx.inputs,
                ctx.gates,
                ctx.commits,
                ctx.loop_counts,
                ctx.visited,
            )?;
            routed_models.extend(effect.routed_models);
            admitted_dispatches.extend(effect.admitted_dispatches);
            if effect.next != Some(join_id) {
                return Err(ExecError::BranchDidNotReachJoin(current, branch));
            }
        }

        record_visit(ctx.visited, join_id)?;
        let after_join = only_out_edge(ctx.graph, join_id);
        Ok(StepEffect {
            next: Some(after_join),
            routed_models,
            admitted_dispatches,
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
        StepKind::Join { .. } => &NotExecutableExecutor,
        StepKind::Declared(DeclaredStepKind::AgentCall) => {
            &DispatchExecutor(DeclaredStepKind::AgentCall)
        }
        StepKind::Declared(DeclaredStepKind::ToolCall) => {
            &DispatchExecutor(DeclaredStepKind::ToolCall)
        }
        StepKind::Declared(DeclaredStepKind::Job) => &DispatchExecutor(DeclaredStepKind::Job),
        StepKind::Declared(DeclaredStepKind::TestBuild) => {
            &DispatchExecutor(DeclaredStepKind::TestBuild)
        }
        StepKind::Declared(DeclaredStepKind::PublicationRequest) => {
            &DispatchExecutor(DeclaredStepKind::PublicationRequest)
        }
        StepKind::Declared(DeclaredStepKind::SemanticChange) => &SemanticChangeExecutor,
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
    commits: &mut CommitLog,
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
        commits,
        loop_counts,
        visited,
    };
    dispatch(&step.kind).execute(authority, &mut ctx)
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod declared_dispatch_tests;
