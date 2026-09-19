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
//!   `parallel_join` tests in [`engine`].
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
pub mod compensation;
pub mod compensation_order;
pub mod declared_dispatch;
pub mod engine;
pub mod graph;
pub mod graph_wire;
pub mod human_gate;
pub mod model_routing;
pub mod retry;
