//! Issue #208's typed workflow profile: a bounded, validated workflow state
//! machine with model routing, human gates, retries, compensation, and
//! checkpoints.
//!
//! This is deliberately *not* `workflow_profile`, which despite the similar
//! name is an opt-in current-thread timing observer for benchmark hosts and
//! carries no validation or execution authority. The two concerns are
//! unrelated, and keeping them apart is what lets this module build
//! unconditionally while the timing observer stays behind its
//! `unstable-workflow-profiling` feature.
//!
//! Authority boundaries this module holds to, each proven by test rather than
//! asserted here:
//!
//! - Reaching a [`graph::StepKind::HumanGate`] step never authorizes the
//!   gated transition, in the graph schema ([`human_gate`]) *and* in the
//!   executor that actually walks the graph ([`engine`]): [`engine::run`]
//!   only crosses a gate given an explicit, separately evaluated
//!   [`human_gate::GateDecision`] supplied through [`engine::ExecInputs`],
//!   and the decision is a separate recorded action bound to an exact
//!   revision, role, scope and expiry, granting only the one named edge.
//! - A compensating effect never runs twice for one key, including across a
//!   restored snapshot; see [`compensation`]. Compensations must additionally
//!   replay in the exact reverse of their commit order; that claim is
//!   checked as inert proof data, never as permission to run anything, by
//!   [`compensation_order`]. [`engine::run`] itself records which
//!   [`engine::ExecInputs::compensable`] steps actually committed, in commit
//!   order, into the caller-supplied [`compensation_order::CommitLog`] — but
//!   `run` never calls [`compensation::CompensationLedger::apply`] or
//!   decides what a compensation does; a caller that catches an `Err` here
//!   recovers the required order with `CommitLog::compensation_order()` and
//!   drives its own ledger against it.
//! - An uncertain outcome is never retried automatically. [`retry`] reuses
//!   [`crate::model_budget_policy::classification`] rather than introducing a
//!   second, divergent notion of which failures are safe. For a `ModelCall`
//!   step with a scripted [`engine::ExecInputs::attempt_script`],
//!   [`engine::run`] enforces this and the declared
//!   [`engine::ExecInputs::retry_budgets`] ceiling live during execution,
//!   not only as a standalone decision function.
//! - Model routing is closed over the declared deployment policy; a request
//!   outside it is refused, never silently substituted. See [`model_routing`].
//! - Resuming a checkpoint fails closed on revision drift or corruption, and a
//!   migration without a mapping for the actual step is refused; see
//!   [`checkpoint`].
//! - `Parallel`/`Join` execution never introduces real concurrency: every
//!   branch runs on the one calling thread, in ascending step-id order, so
//!   there is nothing to race and the resulting trace is byte-identical
//!   across repeated runs of the same graph and inputs; see the
//!   `parallel_join` tests in [`engine`]. Separately, and for the workflow
//!   *author* rather than this executor, a graph whose concurrent branches
//!   declare overlapping [`claims`] is refused by
//!   [`graph::WorkflowGraph::validate`] before anything runs — a static
//!   refusal under [`claims::CONFLICT_DIAGNOSTIC_CODE`], in the spirit of
//!   this repository's invariant that ownership errors are compile-time
//!   diagnostics and never backend accidents.
//! - Bounding a run is deterministic and replayable. There is no
//!   wall-clock timeout anywhere in this module, deliberately: a deadline
//!   measured in elapsed time would make the same run cut off at a
//!   different step on a busier machine, producing a different trace and a
//!   different compensation obligation each replay. A run is bounded
//!   instead by a declared cost budget charged per step execution and per
//!   retry attempt ([`run_control::StepBudget`]), whose exhaustion is its
//!   own refusal ([`engine::ExecError::StepBudgetExhausted`]) — never the
//!   retry-ceiling refusal, and never an
//!   [`retry::AttemptOutcomeClass::Uncertain`] outcome.
//! - Cancellation is cooperative, observed only between steps and between
//!   parallel branches, and addressed by a deterministic run-internal
//!   coordinate rather than an ambient flag, so a cancelled run replays to
//!   the identical trace ([`run_control::CancelSignal`]). It produces a
//!   terminal state of its own, [`run_control::RunOutcome::Cancelled`] —
//!   not success, not a permanent failure, not uncertain — and
//!   [`engine::ExecTrace::completed`] is the one predicate that answers
//!   "did this workflow finish". A cancelled run keeps every commit record
//!   it had already made: cancelling does not un-happen an effect, `run`
//!   never compensates one itself, and at-most-once holds across
//!   cancellation and replay because compensation is keyed by
//!   `(step, run_id)`.
//!
//! # Scope decision: per-step capability and budget
//!
//! The issue's in-scope list names "effects/capabilities and budgets".
//! These are answered differently on purpose, and the difference is
//! recorded here so a reviewer reading the list literally does not keep
//! rediscovering it as a gap:
//!
//! - **Budget is universal.** Every step kind, with no exception, is
//!   charged against the run's declared cost budget at
//!   `engine::dispatch_step` — the one call point every step this module
//!   executes passes through, including each branch of a `Parallel` and
//!   each iteration of a `Loop`. A `Sequential` step costs the minimum and
//!   a `ModelCall` costs most (see [`run_control::step_cost`]), but none
//!   costs nothing.
//! - **Capability is scoped to effect, and that is deliberate.** A step
//!   kind is authorized where it can actually do something: `ModelCall`
//!   against a [`model_routing::DeploymentPolicy`], the five dispatchable
//!   `Declared` kinds against a [`declared_dispatch::DispatchPolicy`],
//!   `HumanGate` against a separately recorded
//!   [`human_gate::GateDecision`]. `Sequential`, `Conditional`,
//!   `Parallel`, `Join`, `Loop` and `Terminal` have **no** capability
//!   concept, because they perform no effect at all: they choose which
//!   step runs next and nothing else. There is no filesystem access, no
//!   process, no network, no model call, and no publication for a
//!   capability to authorize or refuse.
//!
//!   Giving them one anyway would mean minting a token that gates nothing
//!   — a concept that reads, in a completion matrix or a review, as
//!   enforcement while enforcing nothing. This repository's rule that
//!   capabilities are explicit is a rule about *authority over effects*,
//!   and the honest way to satisfy it for an effect-free step kind is to
//!   have no authority to grant, not to invent a hollow one. If a future
//!   step kind performs an effect, it is authorized like the others; that
//!   is what the sealed `engine::StepExecutor` seam exists to make
//!   unavoidable.
//!
//! Scope boundary: [`engine::run`] executes Sequential, Conditional, bounded
//! Loop, ModelCall, HumanGate, and bounded Parallel/Join steps
//! deterministically, each dispatched through the sealed
//! [`engine::StepExecutor`] seam. Five of the six declared step kinds —
//! AgentCall, ToolCall, Job, TestBuild, and PublicationRequest — get a
//! decide-and-record executor ([`declared_dispatch`]): given an explicit,
//! caller-supplied [`declared_dispatch::DispatchRequest`] and
//! [`declared_dispatch::DispatchPolicy`] in [`engine::ExecInputs`], the
//! engine decides whether the named target is admissible and records that
//! decision, but never itself invokes an agent, runs a tool, spawns a job,
//! runs a build, or publishes anything — the physical action, if any, is
//! entirely the caller's own, separately authorized business. Reaching one
//! of these five without a declared request and policy is a defined
//! refusal ([`engine::ExecError::DispatchNotDeclared`]), never a silent
//! pass. The sixth, SemanticChange, is refused unconditionally
//! ([`engine::ExecError::SemanticChangeNotGranted`]): the graph schema
//! carries no target payload for it to decide about, and issue #274 found
//! the one operation this repository has actually built a preview for,
//! `rename_display_name`, unsatisfiable for any project with commented
//! bundled dependencies — see `engine::SemanticChangeExecutor`'s doc
//! comment. None of the six has retry or compensation wiring, since a
//! decide-only or unconditionally-refusing executor commits no effect that
//! would ever need compensating. For `ModelCall`, retry ceiling
//! enforcement and compensation-commit ordering are now threaded through
//! [`engine::run`] itself (see [`engine::ExecInputs::attempt_script`],
//! [`engine::ExecInputs::retry_budgets`], [`engine::ExecInputs::compensable`]);
//! `run` produces the ordered [`compensation_order::CommitLog`] a failure
//! leaves behind, but running the actual compensation effect through
//! [`compensation::CompensationLedger`] stays the caller's job, matching the
//! rest of this module's separation of proof from authority. The wire-level
//! checkpoint format persists a [`compensation::CompensationLedger`]
//! snapshot (see [`checkpoint`]), but a [`compensation_order::CommitLog`]
//! itself has no wire format and is not part of a checkpoint's persisted
//! state — a resumed run starts that log empty.

pub mod checkpoint;
pub mod claims;
pub mod compensation;
pub mod compensation_order;
pub mod declared_dispatch;
pub mod engine;
pub mod graph;
pub mod graph_wire;
pub mod human_gate;
pub mod model_routing;
pub mod retry;
pub mod run_control;
