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
//! Tests use offline fixture adapters, including actual compiled-schema bridge
//! execution and retained journal replay. No live provider or invoice transport
//! is supplied by this module. Adapter observations remain untrusted evidence.

pub mod adapter_projection;
pub mod audit_view;
pub mod generic_enrichment;
pub mod journal_projection;
pub mod observed_usage;
pub mod receipt;
pub mod receipt_decode;
pub mod reconciliation;
pub mod replay;
pub mod source_enrichment;
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
pub use receipt_decode::{
    decode_receipt, DecodeError, MAX_RECEIPT_BYTES, MAX_RECEIPT_STRING_BYTES,
};
pub use reconciliation::{
    BillingReconciler, ProviderInvoiceRow, ProviderReportedSource, ProviderUsageDiscrepancy,
    ReconciliationOutcome,
};
pub use replay::{replay_receipt, ReplayError};
