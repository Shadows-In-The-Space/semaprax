//! Model-call receipts: canonical, replayable, redactable evidence for one
//! `model.invoke` attempt (issue #180).
//!
//! # Relationship to `src/live_invocation/`
//!
//! The authoritative live journals remain the only causal record. The
//! [`journal_projection`] and [`source_projection`] modules derive opaque
//! per-attempt evidence directly from generic kernel journals and authenticated
//! source checkpoints. Missing host timing and billing facts remain unknown in
//! that additive schema. The enriched [`receipt::ModelCallReceipt`] v1 contract
//! remains available for hosts that independently retain its required metadata.
//! Both forms are evidence, and their replay paths cannot dispatch providers.
//!
//! # A receipt is evidence, not authority
//!
//! Nothing here mints, decodes, or reconstructs a
//! [`crate::live_invocation::model_invoke::AuthorizationGrant`]: this module
//! does not import [`crate::live_invocation::model_invoke::AuthorizationGate`]
//! at all. A [`receipt::ModelCallReceipt`] cannot authorize a call, widen a
//! budget, select a provider, or approve itself — see
//! [`receipt::ModelCallReceipt`]'s own doc test for a caller who tries to use
//! one as a grant, which is rejected at compile time, not by a runtime
//! check.
//!
//! # No live network call, no real provider, no key
//!
//! Every test in this module is built from offline fixture bytes and the
//! same deterministic fixture seams `crate::live_invocation::fixture`
//! already ships (`FixtureModelHandler`, `FixtureProposalDecoder`). Wiring
//! a real provider adapter, a real compiled proposal grammar, or a real
//! invoice-import transport is downstream, human-gated integration work
//! against the traits this module and `live_invocation` already fix.

pub mod audit_view;
pub mod journal_projection;
pub mod receipt;
pub mod reconciliation;
pub mod replay;
pub mod source_projection;

pub use audit_view::{
    redact, verify_audit_view, AuditViewError, ModelCallAuditView, ReceiptPrivateExtras,
    RedactedField, RedactionPolicy, AUDIT_VIEW_SCHEMA,
};
pub use receipt::{
    commit_observation_bytes, commit_proposal_bytes, commit_response_bytes, commit_task_bytes,
    verify_root_binding, BindingError, ModelCallReceipt, PayloadPrivacyClaim,
    ProviderReportedUsage, ReceiptRootBinding, ReceiptStage, RootBindingContext,
    LOW_ENTROPY_BYTE_THRESHOLD, RECEIPT_SCHEMA,
};
pub use reconciliation::{BillingReconciler, ProviderInvoiceRow, ReconciliationOutcome};
pub use replay::{replay_receipt, ReplayError};
