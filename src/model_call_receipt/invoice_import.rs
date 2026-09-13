//! Bounded, adapter-verified import of one provider invoice row.
//!
//! This module deliberately has no transport, credential, clock, or provider
//! authority.  An adapter receives the exact caller-supplied bytes only after
//! the importer has bounded them, and its result is checked again against the
//! caller-held account, call, and adapter identities before an opaque import is
//! emitted.  The built-in verifier is an offline fixture verifier: matching an
//! independently retained content digest is local evidence, not provider
//! authentication or a claim of real-provider support.

use std::collections::BTreeSet;

use sha2::{Digest as _, Sha256};

use crate::diagnostic::quote_json;
use crate::digest_hex::LowerHex;

use super::reconciliation::{
    BillingReconciler, ProviderInvoiceRow, ProviderReportedSource, ReconciliationOutcome,
};

/// Version tag for the canonical import envelope.
pub const INVOICE_IMPORT_SCHEMA: &str = "semaprax.model-call-invoice-import.v1";
/// Maximum raw invoice bytes accepted by this local importer.
pub const MAX_INVOICE_IMPORT_BYTES: usize = 65_536;
/// Bound rendered evidence separately from raw input because JSON escaping expands labels.
pub const MAX_INVOICE_EVIDENCE_BYTES: usize = 262_144;
/// Maximum UTF-8 byte length of an expected or imported identity label.
pub const MAX_INVOICE_IMPORT_LABEL_BYTES: usize = 4_096;

const RAW_INVOICE_DOMAIN: &[u8] = b"semaprax.model-call-invoice-import.raw.v1\0";
const IMPORT_ENVELOPE_DOMAIN: &[u8] = b"semaprax.model-call-invoice-import.envelope.v1\0";
const RECONCILIATION_RECORD_DOMAIN: &[u8] =
    b"semaprax.model-call-invoice-reconciliation-record.v1\0";
const RECONCILIATION_SOURCE_SNAPSHOT_DOMAIN: &[u8] =
    b"semaprax.model-call-invoice-reconciliation-source-snapshot.v1\0";

/// Version tag for the canonical reconciliation result record.
pub const RECONCILIATION_RECORD_SCHEMA: &str =
    "semaprax.model-call-invoice-reconciliation-record.v1";

/// Errors produced before an invoice row becomes verified evidence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum InvoiceImportError {
    RawBytesTooLarge {
        maximum: usize,
        actual: usize,
    },
    EmptyLabel {
        field: &'static str,
    },
    LabelTooLarge {
        field: &'static str,
        maximum: usize,
        actual: usize,
    },
    AdapterMismatch {
        expected: String,
        found: String,
    },
    AccountMismatch {
        expected: String,
        found: String,
    },
    CallMismatch {
        expected: String,
        found: String,
    },
    InvalidExpectedDigest,
    RawDigestMismatch,
    InvalidRawInvoice(&'static str),
    DuplicateRawInvoiceKey,
    UnknownRawInvoiceKey,
    NegativeCost {
        value: i64,
    },
    ReplayMismatch,
    InvalidReconciliationOutcome {
        field: &'static str,
    },
}

/// Caller-held identities that an adapter result must match exactly.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InvoiceImportExpectation {
    account_id: String,
    provider_call_id: String,
    adapter_identity: String,
}

impl InvoiceImportExpectation {
    /// Creates bounded expected identities. These are checked both during
    /// import and during replay; they never come from an adapter result.
    pub fn new(
        account_id: &str,
        provider_call_id: &str,
        adapter_identity: &str,
    ) -> Result<Self, InvoiceImportError> {
        validate_label("account_id", account_id)?;
        validate_label("provider_call_id", provider_call_id)?;
        validate_label("adapter_identity", adapter_identity)?;
        Ok(Self {
            account_id: account_id.to_owned(),
            provider_call_id: provider_call_id.to_owned(),
            adapter_identity: adapter_identity.to_owned(),
        })
    }

    #[must_use]
    pub fn account_id(&self) -> &str {
        &self.account_id
    }

    #[must_use]
    pub fn provider_call_id(&self) -> &str {
        &self.provider_call_id
    }

    #[must_use]
    pub fn adapter_identity(&self) -> &str {
        &self.adapter_identity
    }
}

/// Caller-retained raw invoice bytes for an independent exact-byte replay.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RetainedInvoiceBytes(Vec<u8>);

impl RetainedInvoiceBytes {
    /// Bounds raw bytes before an adapter can inspect them.
    pub fn new(bytes: &[u8]) -> Result<Self, InvoiceImportError> {
        if bytes.len() > MAX_INVOICE_IMPORT_BYTES {
            return Err(InvoiceImportError::RawBytesTooLarge {
                maximum: MAX_INVOICE_IMPORT_BYTES,
                actual: bytes.len(),
            });
        }
        Ok(Self(bytes.to_vec()))
    }

    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// Adapter seam for an already captured invoice/usage payload.
///
/// Implementations must inspect `raw_bytes`; the importer does not trust their
/// returned identities and independently compares them to `expected`.
pub trait InvoiceImportVerifier {
    fn adapter_identity(&self) -> &str;

    fn verify(
        &self,
        raw_bytes: &[u8],
        expected: &InvoiceImportExpectation,
    ) -> Result<ProviderInvoiceRow, InvoiceImportError>;
}

/// Opaque, verified invoice evidence. It retains commitments and a canonical
/// envelope, never the caller's raw invoice bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedInvoiceImport {
    adapter_identity: String,
    raw_invoice_digest: String,
    row: ProviderInvoiceRow,
}

impl VerifiedInvoiceImport {
    #[must_use]
    pub fn row(&self) -> &ProviderInvoiceRow {
        &self.row
    }

    #[must_use]
    pub fn raw_invoice_digest(&self) -> &str {
        &self.raw_invoice_digest
    }

    /// Domain-separated digest of this exact canonical envelope.
    #[must_use]
    pub fn digest(&self) -> String {
        canonical_digest(IMPORT_ENVELOPE_DOMAIN, self.render().as_bytes())
    }

    /// Fixed-order canonical envelope suitable for retaining beside the raw
    /// bytes. The raw bytes stay caller-owned in [`RetainedInvoiceBytes`].
    #[must_use]
    pub fn render(&self) -> String {
        format!(
            "{{\"schema\":{},\"adapter_identity\":{},\"raw_invoice_digest\":{},\"account_id\":{},\"provider_call_id\":{},\"tokens_in\":{},\"tokens_out\":{},\"cost_micros\":{}}}",
            quote_json(INVOICE_IMPORT_SCHEMA),
            quote_json(&self.adapter_identity),
            quote_json(&self.raw_invoice_digest),
            quote_json(&self.row.account_id),
            quote_json(&self.row.provider_call_id),
            self.row.tokens_in,
            self.row.tokens_out,
            self.row.cost_micros,
        )
    }

    /// Pure exact-byte replay for the closed offline digest verifier. It has
    /// no adapter callback parameter and cannot dispatch a provider.
    pub fn replay(
        &self,
        submitted_envelope: &[u8],
        retained: &RetainedInvoiceBytes,
        expected: &InvoiceImportExpectation,
        verifier: &ExpectedContentDigestVerifier,
    ) -> Result<(), InvoiceImportError> {
        if submitted_envelope.len() > MAX_INVOICE_EVIDENCE_BYTES {
            return Err(InvoiceImportError::RawBytesTooLarge {
                maximum: MAX_INVOICE_EVIDENCE_BYTES,
                actual: submitted_envelope.len(),
            });
        }
        if submitted_envelope != self.render().as_bytes() {
            return Err(InvoiceImportError::ReplayMismatch);
        }
        let replayed = import_invoice_row(retained, expected, verifier)?;
        if replayed.render() != self.render() {
            return Err(InvoiceImportError::ReplayMismatch);
        }
        Ok(())
    }

    /// Rechecks an import with a caller-supplied adapter. Unlike [`Self::replay`],
    /// this deliberately invokes the adapter callback and must not be described
    /// as zero-dispatch or pure replay.
    pub fn reverify<V: InvoiceImportVerifier>(
        &self,
        submitted_envelope: &[u8],
        retained: &RetainedInvoiceBytes,
        expected: &InvoiceImportExpectation,
        verifier: &V,
    ) -> Result<(), InvoiceImportError> {
        if submitted_envelope.len() > MAX_INVOICE_EVIDENCE_BYTES {
            return Err(InvoiceImportError::RawBytesTooLarge {
                maximum: MAX_INVOICE_EVIDENCE_BYTES,
                actual: submitted_envelope.len(),
            });
        }
        if submitted_envelope != self.render().as_bytes() {
            return Err(InvoiceImportError::ReplayMismatch);
        }
        let reverified = import_invoice_row(retained, expected, verifier)?;
        if reverified.render() != self.render() {
            return Err(InvoiceImportError::ReplayMismatch);
        }
        Ok(())
    }
}

/// Imports one bounded raw invoice row after adapter verification.
pub fn import_invoice_row<V: InvoiceImportVerifier>(
    retained: &RetainedInvoiceBytes,
    expected: &InvoiceImportExpectation,
    verifier: &V,
) -> Result<VerifiedInvoiceImport, InvoiceImportError> {
    validate_label("account_id", expected.account_id())?;
    validate_label("provider_call_id", expected.provider_call_id())?;
    validate_label("adapter_identity", expected.adapter_identity())?;
    validate_label("adapter_identity", verifier.adapter_identity())?;
    if verifier.adapter_identity() != expected.adapter_identity() {
        return Err(InvoiceImportError::AdapterMismatch {
            expected: expected.adapter_identity().to_owned(),
            found: verifier.adapter_identity().to_owned(),
        });
    }

    let row = verifier.verify(retained.as_bytes(), expected)?;
    validate_label("adapter_identity", verifier.adapter_identity())?;
    if verifier.adapter_identity() != expected.adapter_identity() {
        return Err(InvoiceImportError::AdapterMismatch {
            expected: expected.adapter_identity().to_owned(),
            found: verifier.adapter_identity().to_owned(),
        });
    }
    validate_row(&row)?;
    if row.account_id != expected.account_id() {
        return Err(InvoiceImportError::AccountMismatch {
            expected: expected.account_id().to_owned(),
            found: row.account_id,
        });
    }
    if row.provider_call_id != expected.provider_call_id() {
        return Err(InvoiceImportError::CallMismatch {
            expected: expected.provider_call_id().to_owned(),
            found: row.provider_call_id,
        });
    }
    Ok(VerifiedInvoiceImport {
        adapter_identity: expected.adapter_identity().to_owned(),
        raw_invoice_digest: raw_invoice_digest(retained.as_bytes()),
        row,
    })
}

/// Reconciles an already verified import through the existing actual-provider
/// usage path and captures its result as immutable local evidence. Verification
/// does not turn the invoice into semantic proof.
pub fn reconcile_verified_provider_import<S: ProviderReportedSource>(
    reconciler: &mut BillingReconciler,
    source: &S,
    imported: &VerifiedInvoiceImport,
) -> Result<ReconciliationRecord, InvoiceImportError> {
    let snapshot = capture_reconciliation_source(source)?;
    let source_provider_call_id = snapshot.provider_call_reference.clone();
    let source_snapshot_digest = snapshot.digest();
    let imported_envelope_digest = imported.digest();
    let outcome = reconciler.reconcile_provider_reported(&snapshot, Some(imported.row()));
    validate_outcome(&outcome)?;
    Ok(ReconciliationRecord {
        source_provider_call_id,
        source_snapshot_digest,
        imported_envelope_digest,
        outcome,
    })
}

impl BillingReconciler {
    /// Convenience integration for a [`VerifiedInvoiceImport`].
    pub fn reconcile_verified_provider_import<S: ProviderReportedSource>(
        &mut self,
        source: &S,
        imported: &VerifiedInvoiceImport,
    ) -> Result<ReconciliationRecord, InvoiceImportError> {
        reconcile_verified_provider_import(self, source, imported)
    }
}

/// Immutable local evidence for one actual reconciliation call.
///
/// `verify_replay` is deliberately pure: duplicate detection belongs to the
/// mutable reconciler, so rerunning it could produce a different duplicate
/// outcome. A caller retains the expected outcome separately and verifies it
/// with the original source and verified import instead of re-consuming a row.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReconciliationRecord {
    source_provider_call_id: String,
    source_snapshot_digest: String,
    imported_envelope_digest: String,
    outcome: ReconciliationOutcome,
}

impl ReconciliationRecord {
    #[must_use]
    pub fn outcome(&self) -> &ReconciliationOutcome {
        &self.outcome
    }

    #[must_use]
    pub fn source_provider_call_id(&self) -> &str {
        &self.source_provider_call_id
    }

    #[must_use]
    pub fn source_snapshot_digest(&self) -> &str {
        &self.source_snapshot_digest
    }

    #[must_use]
    pub fn imported_envelope_digest(&self) -> &str {
        &self.imported_envelope_digest
    }

    /// Fixed-order canonical local evidence. It contains the complete closed
    /// outcome vocabulary, including every discrepancy field.
    #[must_use]
    pub fn render(&self) -> String {
        format!(
            "{{\"schema\":{},\"source_provider_call_id\":{},\"source_snapshot_digest\":{},\"imported_envelope_digest\":{},\"outcome\":{}}}",
            quote_json(RECONCILIATION_RECORD_SCHEMA),
            quote_json(&self.source_provider_call_id),
            quote_json(&self.source_snapshot_digest),
            quote_json(&self.imported_envelope_digest),
            render_outcome(&self.outcome),
        )
    }

    #[must_use]
    pub fn digest(&self) -> String {
        canonical_digest(RECONCILIATION_RECORD_DOMAIN, self.render().as_bytes())
    }

    /// Checks the exact canonical record bytes as well as independent inputs.
    pub fn replay_rendered<S: ProviderReportedSource>(
        &self,
        submitted: &[u8],
        source: &S,
        imported: &VerifiedInvoiceImport,
        expected_outcome: &ReconciliationOutcome,
    ) -> Result<(), ReconciliationRecordError> {
        if submitted.len() > MAX_INVOICE_EVIDENCE_BYTES || submitted != self.render().as_bytes() {
            return Err(ReconciliationRecordError::RenderedMismatch);
        }
        self.verify_replay(source, imported, expected_outcome)
    }

    /// Pure replay check over caller-retained inputs. It never invokes a
    /// reconciler and therefore never consumes duplicate-tracking state.
    pub fn verify_replay<S: ProviderReportedSource>(
        &self,
        source: &S,
        imported: &VerifiedInvoiceImport,
        expected_outcome: &ReconciliationOutcome,
    ) -> Result<(), ReconciliationRecordError> {
        let snapshot = capture_reconciliation_source(source)
            .map_err(|_| ReconciliationRecordError::SourceSnapshotInvalid)?;
        if self.source_provider_call_id != snapshot.provider_call_reference() {
            return Err(ReconciliationRecordError::SourceCallMismatch);
        }
        if self.source_snapshot_digest != snapshot.digest() {
            return Err(ReconciliationRecordError::SourceSnapshotDigestMismatch);
        }
        if self.imported_envelope_digest != imported.digest() {
            return Err(ReconciliationRecordError::ImportedEnvelopeDigestMismatch);
        }
        if validate_outcome(expected_outcome).is_err() {
            return Err(ReconciliationRecordError::ExpectedOutcomeInvalid);
        }
        if &self.outcome != expected_outcome {
            return Err(ReconciliationRecordError::OutcomeMismatch);
        }
        Ok(())
    }
}

/// A pure reconciliation-record replay mismatch.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ReconciliationRecordError {
    RenderedMismatch,
    SourceSnapshotInvalid,
    SourceCallMismatch,
    SourceSnapshotDigestMismatch,
    ImportedEnvelopeDigestMismatch,
    ExpectedOutcomeInvalid,
    OutcomeMismatch,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ReconciliationSourceSnapshot {
    provider_call_reference: String,
    provider_reported: Option<super::reconciliation::ProviderReportedUsageFields>,
    settled: bool,
}

impl ProviderReportedSource for ReconciliationSourceSnapshot {
    fn provider_reported_usage(
        &self,
    ) -> Option<super::reconciliation::ProviderReportedUsageFields> {
        self.provider_reported.clone()
    }

    fn provider_call_reference(&self) -> &str {
        &self.provider_call_reference
    }

    fn is_settled(&self) -> bool {
        self.settled
    }
}

impl ReconciliationSourceSnapshot {
    fn digest(&self) -> String {
        canonical_digest(
            RECONCILIATION_SOURCE_SNAPSHOT_DOMAIN,
            self.render().as_bytes(),
        )
    }

    fn render(&self) -> String {
        let reported = self.provider_reported.as_ref().map_or_else(
            || "null".into(),
            |value| format!(
                "{{\"provider_call_id\":{},\"tokens_in\":{},\"tokens_out\":{},\"provider_cost_micros\":{}}}",
                quote_json(&value.provider_call_id),
                render_optional_u64(value.tokens_in),
                render_optional_u64(value.tokens_out),
                render_optional_i64(value.provider_cost_micros),
            ),
        );
        format!(
            "{{\"provider_call_reference\":{},\"provider_reported\":{},\"is_settled\":{}}}",
            quote_json(&self.provider_call_reference),
            reported,
            self.settled,
        )
    }
}

fn capture_reconciliation_source<S: ProviderReportedSource>(
    source: &S,
) -> Result<ReconciliationSourceSnapshot, InvoiceImportError> {
    let provider_call_reference = source.provider_call_reference();
    validate_label("source_provider_call_reference", provider_call_reference)?;
    let provider_reported = source.provider_reported_usage();
    if let Some(reported) = &provider_reported {
        validate_label(
            "source_reported_provider_call_id",
            &reported.provider_call_id,
        )?;
    }
    let settled = source.is_settled();
    Ok(ReconciliationSourceSnapshot {
        provider_call_reference: provider_call_reference.to_owned(),
        provider_reported,
        settled,
    })
}

fn validate_outcome(outcome: &ReconciliationOutcome) -> Result<(), InvoiceImportError> {
    let fields: Vec<(&'static str, &str)> = match outcome {
        ReconciliationOutcome::ProviderUsageOverReported { discrepancy }
        | ReconciliationOutcome::ProviderUsageUnderReported { discrepancy }
        | ReconciliationOutcome::ProviderUsageDiscrepancy { discrepancy } => {
            vec![("outcome_provider_call_id", &discrepancy.provider_call_id)]
        }
        ReconciliationOutcome::DuplicateInvoiceRow { provider_call_id }
        | ReconciliationOutcome::UnknownCall { provider_call_id } => {
            vec![("outcome_provider_call_id", provider_call_id)]
        }
        ReconciliationOutcome::WrongAccount { expected, found } => vec![
            ("outcome_expected_account", expected),
            ("outcome_found_account", found),
        ],
        _ => Vec::new(),
    };
    for (field, value) in fields {
        if validate_label(field, value).is_err() {
            return Err(InvoiceImportError::InvalidReconciliationOutcome { field });
        }
    }
    Ok(())
}

fn render_outcome(outcome: &ReconciliationOutcome) -> String {
    match outcome {
        ReconciliationOutcome::Reconciled => "{\"tag\":\"reconciled\"}".into(),
        ReconciliationOutcome::ProviderOverReported {
            local_units,
            provider_units,
        } => format!(
            "{{\"tag\":\"provider_over_reported\",\"local_units\":{local_units},\"provider_units\":{provider_units}}}"
        ),
        ReconciliationOutcome::ProviderUnderReported {
            local_units,
            provider_units,
        } => format!(
            "{{\"tag\":\"provider_under_reported\",\"local_units\":{local_units},\"provider_units\":{provider_units}}}"
        ),
        ReconciliationOutcome::ProviderUsageOverReported { discrepancy } => format!(
            "{{\"tag\":\"provider_usage_over_reported\",\"discrepancy\":{}}}",
            render_discrepancy(discrepancy)
        ),
        ReconciliationOutcome::ProviderUsageUnderReported { discrepancy } => format!(
            "{{\"tag\":\"provider_usage_under_reported\",\"discrepancy\":{}}}",
            render_discrepancy(discrepancy)
        ),
        ReconciliationOutcome::ProviderUsageDiscrepancy { discrepancy } => format!(
            "{{\"tag\":\"provider_usage_discrepancy\",\"discrepancy\":{}}}",
            render_discrepancy(discrepancy)
        ),
        ReconciliationOutcome::DuplicateInvoiceRow { provider_call_id } => format!(
            "{{\"tag\":\"duplicate_invoice_row\",\"provider_call_id\":{}}}",
            quote_json(provider_call_id)
        ),
        ReconciliationOutcome::UnknownCall { provider_call_id } => format!(
            "{{\"tag\":\"unknown_call\",\"provider_call_id\":{}}}",
            quote_json(provider_call_id)
        ),
        ReconciliationOutcome::WrongAccount { expected, found } => format!(
            "{{\"tag\":\"wrong_account\",\"expected\":{},\"found\":{}}}",
            quote_json(expected),
            quote_json(found)
        ),
        ReconciliationOutcome::InvalidProviderUsage { field, value } => format!(
            "{{\"tag\":\"invalid_provider_usage\",\"field\":{},\"value\":{value}}}",
            quote_json(field)
        ),
        ReconciliationOutcome::Uncertain { reason } => format!(
            "{{\"tag\":\"uncertain\",\"reason\":{}}}",
            quote_json(reason)
        ),
    }
}

fn render_discrepancy(value: &super::reconciliation::ProviderUsageDiscrepancy) -> String {
    format!(
        "{{\"provider_call_id\":{},\"reported_tokens_in\":{},\"invoice_tokens_in\":{},\"reported_tokens_out\":{},\"invoice_tokens_out\":{},\"reported_cost_micros\":{},\"invoice_cost_micros\":{}}}",
        quote_json(&value.provider_call_id),
        render_optional_u64(value.reported_tokens_in),
        value.invoice_tokens_in,
        render_optional_u64(value.reported_tokens_out),
        value.invoice_tokens_out,
        render_optional_i64(value.reported_cost_micros),
        value.invoice_cost_micros,
    )
}

fn render_optional_u64(value: Option<u64>) -> String {
    value.map_or_else(|| "null".into(), |value| value.to_string())
}

fn render_optional_i64(value: Option<i64>) -> String {
    value.map_or_else(|| "null".into(), |value| value.to_string())
}

/// Offline verifier for fixture-backed local evidence only.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExpectedContentDigestVerifier {
    adapter_identity: String,
    expected_raw_digest: String,
}

impl ExpectedContentDigestVerifier {
    pub fn new(
        adapter_identity: &str,
        expected_raw_digest: &str,
    ) -> Result<Self, InvoiceImportError> {
        validate_label("adapter_identity", adapter_identity)?;
        if !is_digest(expected_raw_digest) {
            return Err(InvoiceImportError::InvalidExpectedDigest);
        }
        Ok(Self {
            adapter_identity: adapter_identity.to_owned(),
            expected_raw_digest: expected_raw_digest.to_owned(),
        })
    }
}

impl InvoiceImportVerifier for ExpectedContentDigestVerifier {
    fn adapter_identity(&self) -> &str {
        &self.adapter_identity
    }

    fn verify(
        &self,
        raw_bytes: &[u8],
        _expected: &InvoiceImportExpectation,
    ) -> Result<ProviderInvoiceRow, InvoiceImportError> {
        if raw_bytes.len() > MAX_INVOICE_IMPORT_BYTES {
            return Err(InvoiceImportError::RawBytesTooLarge {
                maximum: MAX_INVOICE_IMPORT_BYTES,
                actual: raw_bytes.len(),
            });
        }
        if !is_digest(&self.expected_raw_digest) {
            return Err(InvoiceImportError::InvalidExpectedDigest);
        }
        if raw_invoice_digest(raw_bytes) != self.expected_raw_digest {
            return Err(InvoiceImportError::RawDigestMismatch);
        }
        decode_canonical_invoice_row(raw_bytes)
    }
}

/// Domain-separated digest of exactly the bytes supplied to the verifier.
#[must_use]
pub fn raw_invoice_digest(raw_bytes: &[u8]) -> String {
    canonical_digest(RAW_INVOICE_DOMAIN, raw_bytes)
}

fn canonical_digest(domain: &[u8], bytes: impl AsRef<[u8]>) -> String {
    let mut hash = Sha256::new();
    hash.update(domain);
    hash.update(bytes.as_ref());
    format!("sha256:{:x}", LowerHex(hash.finalize()))
}

fn validate_label(field: &'static str, value: &str) -> Result<(), InvoiceImportError> {
    if value.is_empty() {
        return Err(InvoiceImportError::EmptyLabel { field });
    }
    if value.len() > MAX_INVOICE_IMPORT_LABEL_BYTES {
        return Err(InvoiceImportError::LabelTooLarge {
            field,
            maximum: MAX_INVOICE_IMPORT_LABEL_BYTES,
            actual: value.len(),
        });
    }
    Ok(())
}

fn validate_row(row: &ProviderInvoiceRow) -> Result<(), InvoiceImportError> {
    validate_label("account_id", &row.account_id)?;
    validate_label("provider_call_id", &row.provider_call_id)?;
    if row.cost_micros < 0 {
        return Err(InvoiceImportError::NegativeCost {
            value: row.cost_micros,
        });
    }
    Ok(())
}

fn is_digest(value: &str) -> bool {
    value.len() == 71
        && value.starts_with("sha256:")
        && value.as_bytes()[7..]
            .iter()
            .all(|byte| byte.is_ascii_digit() || matches!(*byte, b'a'..=b'f'))
}

fn decode_canonical_invoice_row(
    raw_bytes: &[u8],
) -> Result<ProviderInvoiceRow, InvoiceImportError> {
    let mut parser = InvoiceRowParser::new(raw_bytes);
    let row = parser.parse()?;
    validate_row(&row)?;
    if render_canonical_row(&row).as_bytes() != raw_bytes {
        return Err(InvoiceImportError::InvalidRawInvoice(
            "invoice row is not canonical",
        ));
    }
    Ok(row)
}

fn render_canonical_row(row: &ProviderInvoiceRow) -> String {
    format!(
        "{{\"account_id\":{},\"cost_micros\":{},\"provider_call_id\":{},\"tokens_in\":{},\"tokens_out\":{}}}",
        quote_json(&row.account_id),
        row.cost_micros,
        quote_json(&row.provider_call_id),
        row.tokens_in,
        row.tokens_out,
    )
}

struct InvoiceRowParser<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> InvoiceRowParser<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn parse(&mut self) -> Result<ProviderInvoiceRow, InvoiceImportError> {
        self.expect(b'{')?;
        let mut keys = BTreeSet::new();
        let mut account_id = None;
        let mut provider_call_id = None;
        let mut tokens_in = None;
        let mut tokens_out = None;
        let mut cost_micros = None;
        loop {
            let key = self.string()?;
            if !keys.insert(key.clone()) {
                return Err(InvoiceImportError::DuplicateRawInvoiceKey);
            }
            self.expect(b':')?;
            match key.as_str() {
                "account_id" => account_id = Some(self.string()?),
                "provider_call_id" => provider_call_id = Some(self.string()?),
                "tokens_in" => tokens_in = Some(self.u64()?),
                "tokens_out" => tokens_out = Some(self.u64()?),
                "cost_micros" => cost_micros = Some(self.i64()?),
                _ => return Err(InvoiceImportError::UnknownRawInvoiceKey),
            }
            if self.take(b'}') {
                break;
            }
            self.expect(b',')?;
        }
        if self.offset != self.bytes.len() {
            return Err(InvoiceImportError::InvalidRawInvoice(
                "trailing invoice bytes",
            ));
        }
        Ok(ProviderInvoiceRow {
            provider_call_id: provider_call_id.ok_or(InvoiceImportError::InvalidRawInvoice(
                "missing provider_call_id",
            ))?,
            account_id: account_id
                .ok_or(InvoiceImportError::InvalidRawInvoice("missing account_id"))?,
            tokens_in: tokens_in
                .ok_or(InvoiceImportError::InvalidRawInvoice("missing tokens_in"))?,
            tokens_out: tokens_out
                .ok_or(InvoiceImportError::InvalidRawInvoice("missing tokens_out"))?,
            cost_micros: cost_micros
                .ok_or(InvoiceImportError::InvalidRawInvoice("missing cost_micros"))?,
        })
    }

    fn string(&mut self) -> Result<String, InvoiceImportError> {
        let start = self.offset;
        self.expect(b'"')?;
        let mut escaped = false;
        while let Some(byte) = self.peek() {
            self.offset += 1;
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == b'"' {
                let wire = std::str::from_utf8(&self.bytes[start..self.offset])
                    .map_err(|_| InvoiceImportError::InvalidRawInvoice("invoice is not UTF-8"))?;
                let value: String = serde_json::from_str(wire).map_err(|_| {
                    InvoiceImportError::InvalidRawInvoice("invoice string is invalid")
                })?;
                if quote_json(&value) != wire {
                    return Err(InvoiceImportError::InvalidRawInvoice(
                        "invoice string is not canonical",
                    ));
                }
                return Ok(value);
            } else if byte < 0x20 {
                return Err(InvoiceImportError::InvalidRawInvoice(
                    "invoice string contains a control byte",
                ));
            }
        }
        Err(InvoiceImportError::InvalidRawInvoice(
            "invoice string is unterminated",
        ))
    }

    fn u64(&mut self) -> Result<u64, InvoiceImportError> {
        let token = self.integer(false)?;
        token
            .parse()
            .map_err(|_| InvoiceImportError::InvalidRawInvoice("invoice integer overflows u64"))
    }

    fn i64(&mut self) -> Result<i64, InvoiceImportError> {
        let token = self.integer(true)?;
        token
            .parse()
            .map_err(|_| InvoiceImportError::InvalidRawInvoice("invoice integer overflows i64"))
    }

    fn integer(&mut self, allow_negative: bool) -> Result<&str, InvoiceImportError> {
        let start = self.offset;
        if allow_negative && self.take(b'-') {}
        let digits_start = self.offset;
        if !matches!(self.peek(), Some(b'0'..=b'9')) {
            return Err(InvoiceImportError::InvalidRawInvoice(
                "invoice integer is invalid",
            ));
        }
        while matches!(self.peek(), Some(b'0'..=b'9')) {
            self.offset += 1;
        }
        let token = std::str::from_utf8(&self.bytes[start..self.offset])
            .map_err(|_| InvoiceImportError::InvalidRawInvoice("invoice integer is invalid"))?;
        let digits = &self.bytes[digits_start..self.offset];
        if (digits.len() > 1 && digits[0] == b'0') || token == "-0" {
            return Err(InvoiceImportError::InvalidRawInvoice(
                "invoice integer is not canonical",
            ));
        }
        Ok(token)
    }

    fn expect(&mut self, expected: u8) -> Result<(), InvoiceImportError> {
        if self.take(expected) {
            Ok(())
        } else {
            Err(InvoiceImportError::InvalidRawInvoice(
                "invoice punctuation is invalid",
            ))
        }
    }

    fn take(&mut self, expected: u8) -> bool {
        if self.peek() == Some(expected) {
            self.offset += 1;
            true
        } else {
            false
        }
    }

    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.offset).copied()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model_call_receipt::receipt::ProviderReportedUsage;

    fn raw() -> Vec<u8> {
        br#"{"account_id":"acct-1","cost_micros":1234,"provider_call_id":"call-1","tokens_in":11,"tokens_out":22}"#.to_vec()
    }

    fn expectation() -> InvoiceImportExpectation {
        InvoiceImportExpectation::new("acct-1", "call-1", "fixture-digest-v1").unwrap()
    }

    fn verifier(raw: &[u8]) -> ExpectedContentDigestVerifier {
        let digest = raw_invoice_digest(raw);
        ExpectedContentDigestVerifier::new("fixture-digest-v1", &digest).unwrap()
    }

    #[test]
    fn digest_verified_canonical_row_imports_and_replays_exact_retained_bytes() {
        let raw = raw();
        let retained = RetainedInvoiceBytes::new(&raw).unwrap();
        let imported = import_invoice_row(&retained, &expectation(), &verifier(&raw)).unwrap();
        assert_eq!(imported.row().tokens_in, 11);
        assert_eq!(
            imported.render(),
            "{\"schema\":\"semaprax.model-call-invoice-import.v1\",\"adapter_identity\":\"fixture-digest-v1\",\"raw_invoice_digest\":\"".to_owned()
                + &raw_invoice_digest(&raw)
                + "\",\"account_id\":\"acct-1\",\"provider_call_id\":\"call-1\",\"tokens_in\":11,\"tokens_out\":22,\"cost_micros\":1234}"
        );
        let submitted = imported.render();
        assert_eq!(
            imported.replay(
                submitted.as_bytes(),
                &retained,
                &expectation(),
                &verifier(&raw),
            ),
            Ok(())
        );
        let mutated_raw = br#"{"account_id":"acct-1","cost_micros":1234,"provider_call_id":"call-1","tokens_in":12,"tokens_out":22}"#;
        let mutated = RetainedInvoiceBytes::new(mutated_raw).unwrap();
        assert_eq!(
            imported.replay(
                submitted.as_bytes(),
                &mutated,
                &expectation(),
                &verifier(&raw),
            ),
            Err(InvoiceImportError::RawDigestMismatch)
        );
        let mut tampered_envelope = submitted.into_bytes();
        tampered_envelope[0] ^= 1;
        assert_eq!(
            imported.replay(
                &tampered_envelope,
                &retained,
                &expectation(),
                &verifier(&raw),
            ),
            Err(InvoiceImportError::ReplayMismatch)
        );
    }

    #[test]
    fn digest_verifier_rejects_duplicate_unknown_and_noncanonical_numeric_fields() {
        for raw in [
            br#"{"account_id":"acct-1","account_id":"acct-1","cost_micros":1,"provider_call_id":"call-1","tokens_in":1,"tokens_out":2}"#.as_slice(),
            br#"{"account_id":"acct-1","cost_micros":1,"provider_call_id":"call-1","tokens_in":1,"tokens_out":2,"extra":3}"#.as_slice(),
            br#"{"account_id":"acct-1","cost_micros":01,"provider_call_id":"call-1","tokens_in":1,"tokens_out":2}"#.as_slice(),
        ] {
            let retained = RetainedInvoiceBytes::new(raw).unwrap();
            assert!(import_invoice_row(&retained, &expectation(), &verifier(raw)).is_err());
        }
    }

    #[test]
    fn raw_bytes_and_caller_held_labels_are_bounded_before_verification() {
        let oversized = vec![0; MAX_INVOICE_IMPORT_BYTES + 1];
        assert_eq!(
            RetainedInvoiceBytes::new(&oversized),
            Err(InvoiceImportError::RawBytesTooLarge {
                maximum: MAX_INVOICE_IMPORT_BYTES,
                actual: MAX_INVOICE_IMPORT_BYTES + 1,
            })
        );
        let oversized_label = "a".repeat(MAX_INVOICE_IMPORT_LABEL_BYTES + 1);
        assert_eq!(
            InvoiceImportExpectation::new("acct", "call", &oversized_label),
            Err(InvoiceImportError::LabelTooLarge {
                field: "adapter_identity",
                maximum: MAX_INVOICE_IMPORT_LABEL_BYTES,
                actual: MAX_INVOICE_IMPORT_LABEL_BYTES + 1,
            })
        );
    }

    #[test]
    fn importer_rechecks_adapter_account_call_and_negative_cost_after_verification() {
        struct ForgedVerifier;
        impl InvoiceImportVerifier for ForgedVerifier {
            fn adapter_identity(&self) -> &str {
                "fixture-digest-v1"
            }
            fn verify(
                &self,
                _: &[u8],
                _: &InvoiceImportExpectation,
            ) -> Result<ProviderInvoiceRow, InvoiceImportError> {
                Ok(ProviderInvoiceRow {
                    provider_call_id: "another-call".into(),
                    account_id: "other-account".into(),
                    tokens_in: 0,
                    tokens_out: 0,
                    cost_micros: -1,
                })
            }
        }
        let raw = raw();
        let retained = RetainedInvoiceBytes::new(&raw).unwrap();
        assert_eq!(
            import_invoice_row(&retained, &expectation(), &ForgedVerifier),
            Err(InvoiceImportError::NegativeCost { value: -1 })
        );
        let retained_digest = raw_invoice_digest(retained.as_bytes());
        let wrong_adapter =
            ExpectedContentDigestVerifier::new("other-adapter", &retained_digest).unwrap();
        assert!(matches!(
            import_invoice_row(&retained, &expectation(), &wrong_adapter),
            Err(InvoiceImportError::AdapterMismatch { .. })
        ));

        struct MismatchedRowVerifier(ProviderInvoiceRow);
        impl InvoiceImportVerifier for MismatchedRowVerifier {
            fn adapter_identity(&self) -> &str {
                "fixture-digest-v1"
            }
            fn verify(
                &self,
                _: &[u8],
                _: &InvoiceImportExpectation,
            ) -> Result<ProviderInvoiceRow, InvoiceImportError> {
                Ok(self.0.clone())
            }
        }
        let wrong_account = MismatchedRowVerifier(ProviderInvoiceRow {
            provider_call_id: "call-1".into(),
            account_id: "other-account".into(),
            tokens_in: 0,
            tokens_out: 0,
            cost_micros: 0,
        });
        assert!(matches!(
            import_invoice_row(&retained, &expectation(), &wrong_account),
            Err(InvoiceImportError::AccountMismatch { .. })
        ));
        let wrong_call = MismatchedRowVerifier(ProviderInvoiceRow {
            provider_call_id: "other-call".into(),
            account_id: "acct-1".into(),
            tokens_in: 0,
            tokens_out: 0,
            cost_micros: 0,
        });
        assert!(matches!(
            import_invoice_row(&retained, &expectation(), &wrong_call),
            Err(InvoiceImportError::CallMismatch { .. })
        ));
    }

    #[test]
    fn verified_import_uses_existing_actual_provider_usage_reconciliation() {
        let raw = raw();
        let retained = RetainedInvoiceBytes::new(&raw).unwrap();
        let imported = import_invoice_row(&retained, &expectation(), &verifier(&raw)).unwrap();
        let source = ProviderReportedUsage {
            provider_call_id: "call-1".into(),
            tokens_in: 11,
            tokens_out: 22,
            provider_cost_micros: 1234,
        };
        let mut reconciler = BillingReconciler::new("acct-1");
        let record = reconciler
            .reconcile_verified_provider_import(&source, &imported)
            .unwrap();
        assert_eq!(record.outcome(), &ReconciliationOutcome::Reconciled);
        assert!(record.render().contains("\"tag\":\"reconciled\""));
        record
            .replay_rendered(
                record.render().as_bytes(),
                &source,
                &imported,
                &ReconciliationOutcome::Reconciled,
            )
            .unwrap();
        let mut changed_wire = record.render().into_bytes();
        changed_wire[0] ^= 1;
        assert_eq!(
            record.replay_rendered(
                &changed_wire,
                &source,
                &imported,
                &ReconciliationOutcome::Reconciled
            ),
            Err(ReconciliationRecordError::RenderedMismatch)
        );
        assert_eq!(
            record.verify_replay(&source, &imported, &ReconciliationOutcome::Reconciled),
            Ok(())
        );
        let changed_source = ProviderReportedUsage {
            provider_call_id: "call-1".into(),
            tokens_in: 11,
            tokens_out: 23,
            provider_cost_micros: 1234,
        };
        assert_eq!(
            record.verify_replay(
                &changed_source,
                &imported,
                &ReconciliationOutcome::Reconciled,
            ),
            Err(ReconciliationRecordError::SourceSnapshotDigestMismatch)
        );
    }
    #[test]
    fn escaped_labels_round_trip_with_the_separate_evidence_bound() {
        let label = "\0".repeat(MAX_INVOICE_IMPORT_LABEL_BYTES);
        let raw = format!("{{\"account_id\":{},\"cost_micros\":0,\"provider_call_id\":{},\"tokens_in\":0,\"tokens_out\":0}}", quote_json(&label), quote_json(&label));
        let retained = RetainedInvoiceBytes::new(raw.as_bytes()).unwrap();
        let expected = InvoiceImportExpectation::new(&label, &label, &label).unwrap();
        let verifier =
            ExpectedContentDigestVerifier::new(&label, &raw_invoice_digest(raw.as_bytes()))
                .unwrap();
        let imported = import_invoice_row(&retained, &expected, &verifier).unwrap();
        assert!(imported.render().len() > MAX_INVOICE_IMPORT_BYTES);
        imported
            .replay(
                imported.render().as_bytes(),
                &retained,
                &expected,
                &verifier,
            )
            .unwrap();
    }
}
