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
//! - Reaching a [`graph::StepKind::HumanGate`] never authorizes the gated
//!   transition. Approval is a separate recorded decision bound to an exact
//!   revision, role, scope and expiry, and grants only the one named edge; see
//!   [`human_gate`].
//! - A compensating effect never runs twice for one key, including across a
//!   restored snapshot; see [`compensation`].
//! - An uncertain outcome is never retried automatically. [`retry`] reuses
//!   [`crate::model_budget_policy::classification`] rather than introducing a
//!   second, divergent notion of which failures are safe.
//! - Model routing is closed over the declared deployment policy; a request
//!   outside it is refused, never silently substituted. See [`model_routing`].
//! - Resuming a checkpoint fails closed on revision drift or corruption, and a
//!   migration without a mapping for the actual step is refused; see
//!   [`checkpoint`].
//!
//! Scope boundary: [`engine::run`] executes Sequential, Conditional, bounded
//! Loop, ModelCall and Terminal steps deterministically. Parallel and Join are
//! validated at the graph level but refused at execution with
//! [`engine::ExecError::NotExecutable`], and the declared step kinds
//! (Agent/Tool/Job/SemanticChange/TestBuild/PublicationRequest) are schema
//! only. Checkpoints are an in-memory model, not a versioned wire format.

pub mod checkpoint;
pub mod compensation;
pub mod engine;
pub mod graph;
pub mod human_gate;
pub mod model_routing;
pub mod retry;
