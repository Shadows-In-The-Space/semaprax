//! Billing/usage reconciliation: importing a provider's invoice/usage
//! record as **untrusted external evidence** and comparing it against a
//! receipt's own local accounting.
//!
//! # What this explicitly does not claim
//!
//! [`ProviderInvoiceRow`] is exactly that — an externally supplied record a
//! deployment received from a provider, imported here with no adapter-side
//! verification of its authenticity. This module never treats it as proof
//! of anything about the call's semantic correctness (that would be
//! "treating provider invoices as proof of semantic correctness," explicitly
//! out of scope for #180), and never widens a budget, authorizes a future
//! call, or repairs a receipt to make it agree — a discrepancy is reported,
//! never silently normalized away. The original [`BillingReconciler::reconcile`]
//! path compares a byte-count proxy this module can compute without a real
//! tokenizer (`local_request_bytes + local_response_bytes`). The separate
//! [`BillingReconciler::reconcile_provider_reported`] path compares actual
//! provider-reported fields and never substitutes that proxy for missing
//! usage.

use std::collections::HashSet;

use super::receipt::{ModelCallReceipt, ProviderReportedUsage};

/// One externally supplied provider usage/invoice line, imported as
/// untrusted evidence. Never constructed from anything this crate itself
/// computed — a real caller parses this out of an actual provider invoice
/// or usage export.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProviderInvoiceRow {
    pub provider_call_id: String,
    pub account_id: String,
    pub tokens_in: u64,
    pub tokens_out: u64,
    pub cost_micros: i64,
}

/// A provider usage observation with independently optional fields. Provider
/// adapters may report only one or two dimensions; an absent field remains
/// unknown and is never treated as zero. A complete
/// [`ProviderReportedUsage`] is converted to this shape by the built-in
/// source implementation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProviderReportedUsageFields {
    pub provider_call_id: String,
    pub tokens_in: Option<u64>,
    pub tokens_out: Option<u64>,
    pub provider_cost_micros: Option<i64>,
}

/// The independently compared fields in an actual provider usage report and
/// a later invoice row.  The values are observations only: `reported_*` came
/// from the settled call evidence and `invoice_*` came from the untrusted
/// imported row.  Keeping the three dimensions separate prevents a matching
/// token total from hiding a cost or per-direction discrepancy.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProviderUsageDiscrepancy {
    pub provider_call_id: String,
    pub reported_tokens_in: Option<u64>,
    pub invoice_tokens_in: u64,
    pub reported_tokens_out: Option<u64>,
    pub invoice_tokens_out: u64,
    pub reported_cost_micros: Option<i64>,
    pub invoice_cost_micros: i64,
}

impl ProviderUsageDiscrepancy {
    /// Whether every differing invoice field is greater than the actual
    /// provider report.  Equal fields are allowed, so this remains useful
    /// when only one of the three dimensions differs.
    #[must_use]
    pub fn invoice_is_over_reported(&self) -> bool {
        let mut differs = false;
        if let Some(reported) = self.reported_tokens_in {
            if self.invoice_tokens_in < reported {
                return false;
            }
            differs |= self.invoice_tokens_in > reported;
        }
        if let Some(reported) = self.reported_tokens_out {
            if self.invoice_tokens_out < reported {
                return false;
            }
            differs |= self.invoice_tokens_out > reported;
        }
        if let Some(reported) = self.reported_cost_micros {
            if self.invoice_cost_micros < reported {
                return false;
            }
            differs |= self.invoice_cost_micros > reported;
        }
        differs
    }

    /// Whether every differing invoice field is less than the actual
    /// provider report.  Equal fields are allowed, so this remains useful
    /// when only one of the three dimensions differs.
    #[must_use]
    pub fn invoice_is_under_reported(&self) -> bool {
        let mut differs = false;
        if let Some(reported) = self.reported_tokens_in {
            if self.invoice_tokens_in > reported {
                return false;
            }
            differs |= self.invoice_tokens_in < reported;
        }
        if let Some(reported) = self.reported_tokens_out {
            if self.invoice_tokens_out > reported {
                return false;
            }
            differs |= self.invoice_tokens_out < reported;
        }
        if let Some(reported) = self.reported_cost_micros {
            if self.invoice_cost_micros > reported {
                return false;
            }
            differs |= self.invoice_cost_micros < reported;
        }
        differs
    }
}

/// A source for the actual usage observation used by
/// [`BillingReconciler::reconcile_provider_reported`].  Receipts additionally
/// contribute settlement state and the host-generated call reference.  The
/// direct implementation on [`ProviderReportedUsage`] is useful to hosts
/// that retain the observation beside (rather than inside) a receipt; it does
/// not authenticate that observation or the invoice row.
pub trait ProviderReportedSource {
    fn provider_reported_usage(&self) -> Option<ProviderReportedUsageFields>;
    fn provider_call_reference(&self) -> &str;
    fn is_settled(&self) -> bool;
}

impl ProviderReportedSource for ModelCallReceipt {
    fn provider_reported_usage(&self) -> Option<ProviderReportedUsageFields> {
        self.provider_reported
            .as_ref()
            .map(ProviderReportedUsageFields::from)
    }

    fn provider_call_reference(&self) -> &str {
        &self.provider_call_reference
    }

    fn is_settled(&self) -> bool {
        self.terminal_stage.is_settled()
    }
}

impl ProviderReportedSource for ProviderReportedUsage {
    fn provider_reported_usage(&self) -> Option<ProviderReportedUsageFields> {
        Some(self.into())
    }

    fn provider_call_reference(&self) -> &str {
        &self.provider_call_id
    }

    fn is_settled(&self) -> bool {
        true
    }
}

impl From<&ProviderReportedUsage> for ProviderReportedUsageFields {
    fn from(value: &ProviderReportedUsage) -> Self {
        Self {
            provider_call_id: value.provider_call_id.clone(),
            tokens_in: Some(value.tokens_in),
            tokens_out: Some(value.tokens_out),
            provider_cost_micros: Some(value.provider_cost_micros),
        }
    }
}

impl ProviderReportedSource for ProviderReportedUsageFields {
    fn provider_reported_usage(&self) -> Option<ProviderReportedUsageFields> {
        Some(self.clone())
    }

    fn provider_call_reference(&self) -> &str {
        &self.provider_call_id
    }

    fn is_settled(&self) -> bool {
        true
    }
}

/// The closed reconciliation outcome vocabulary. Every discrepancy variant
/// carries the specific figures or identifiers that disagreed, never just a
/// boolean "mismatch."
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ReconciliationOutcome {
    /// The invoice row's reported units exactly match this receipt's local
    /// accounting, cite the expected call reference, and belong to the
    /// expected account.
    Reconciled,
    /// The provider reported more usage units than this receipt's local
    /// accounting recorded.
    ProviderOverReported {
        local_units: u64,
        provider_units: u64,
    },
    /// The provider reported fewer usage units than this receipt's local
    /// accounting recorded.
    ProviderUnderReported {
        local_units: u64,
        provider_units: u64,
    },
    /// The invoice differs from an actual provider usage observation in the
    /// same direction for every differing field.  Values remain split into
    /// input tokens, output tokens, and cost; no byte proxy is involved.
    ProviderUsageOverReported {
        discrepancy: ProviderUsageDiscrepancy,
    },
    /// The invoice differs from an actual provider usage observation in the
    /// same direction for every differing field.  Values remain split into
    /// input tokens, output tokens, and cost; no byte proxy is involved.
    ProviderUsageUnderReported {
        discrepancy: ProviderUsageDiscrepancy,
    },
    /// A provider usage/invoice disagreement has mixed directions across its
    /// independently compared fields.
    ProviderUsageDiscrepancy {
        discrepancy: ProviderUsageDiscrepancy,
    },
    /// This exact `provider_call_id` was already reconciled once before —
    /// the same invoice line submitted twice (or a genuine double-bill).
    DuplicateInvoiceRow { provider_call_id: String },
    /// The invoice row's `provider_call_id` does not match this receipt's
    /// own `provider_call_reference` — it is not evidence about this call
    /// at all.
    UnknownCall { provider_call_id: String },
    /// The invoice row's `account_id` is not the account this reconciler
    /// was constructed to reconcile against.
    WrongAccount { expected: String, found: String },
    /// A provider usage observation or invoice row contained a negative
    /// monetary amount. Negative usage/cost is invalid evidence and is never
    /// treated as a credit or consumed for duplicate tracking.
    InvalidProviderUsage { field: &'static str, value: i64 },
    /// Reconciliation cannot yet run: either the receipt has not settled
    /// (`ModelCallReceipt::terminal_stage`), or no provider record has
    /// arrived yet. Provider usage may legitimately arrive late; this is
    /// the explicit "not yet known" state, never silently treated as
    /// agreement.
    Uncertain { reason: &'static str },
}

/// Reconciles one receipt against provider-reported invoice rows, tracking
/// which `provider_call_id`s have already been consumed so a duplicate row
/// is detected rather than silently re-applied.
#[derive(Debug)]
pub struct BillingReconciler {
    expected_account: String,
    seen_provider_call_ids: HashSet<String>,
}

impl BillingReconciler {
    #[must_use]
    pub fn new(expected_account: impl Into<String>) -> Self {
        Self {
            expected_account: expected_account.into(),
            seen_provider_call_ids: HashSet::new(),
        }
    }

    /// Reconciles `receipt` against `row` (`None` when no provider record
    /// has arrived for this call yet).
    pub fn reconcile(
        &mut self,
        receipt: &ModelCallReceipt,
        row: Option<&ProviderInvoiceRow>,
    ) -> ReconciliationOutcome {
        if !receipt.terminal_stage.is_settled() {
            return ReconciliationOutcome::Uncertain {
                reason: "receipt has not settled yet",
            };
        }
        let Some(row) = row else {
            return ReconciliationOutcome::Uncertain {
                reason: "no provider invoice row observed yet",
            };
        };
        if row.provider_call_id != receipt.provider_call_reference {
            return ReconciliationOutcome::UnknownCall {
                provider_call_id: row.provider_call_id.clone(),
            };
        }
        if !self
            .seen_provider_call_ids
            .insert(row.provider_call_id.clone())
        {
            return ReconciliationOutcome::DuplicateInvoiceRow {
                provider_call_id: row.provider_call_id.clone(),
            };
        }
        if row.account_id != self.expected_account {
            return ReconciliationOutcome::WrongAccount {
                expected: self.expected_account.clone(),
                found: row.account_id.clone(),
            };
        }

        let local_units = (receipt.local_request_bytes + receipt.local_response_bytes) as u64;
        let provider_units = row.tokens_in + row.tokens_out;
        if provider_units == local_units {
            ReconciliationOutcome::Reconciled
        } else if provider_units > local_units {
            ReconciliationOutcome::ProviderOverReported {
                local_units,
                provider_units,
            }
        } else {
            ReconciliationOutcome::ProviderUnderReported {
                local_units,
                provider_units,
            }
        }
    }

    /// Reconciles an actual provider usage observation against a later,
    /// untrusted invoice row. This path intentionally does not consult the
    /// receipt's local byte counters or `cost_estimate_micros`; those are
    /// local estimates and remain covered only by [`Self::reconcile`].
    ///
    /// The source is checked for settlement and missing usage first. The
    /// source's provider call reference, the row's exact call id, and the
    /// expected account are all checked before the row is consumed for
    /// duplicate detection. Thus a wrong-account or unknown row can be
    /// corrected and submitted again without losing the valid row to the
    /// duplicate set.
    pub fn reconcile_provider_reported<S: ProviderReportedSource>(
        &mut self,
        source: &S,
        row: Option<&ProviderInvoiceRow>,
    ) -> ReconciliationOutcome {
        if !source.is_settled() {
            return ReconciliationOutcome::Uncertain {
                reason: "receipt has not settled yet",
            };
        }
        let Some(reported) = source.provider_reported_usage() else {
            return ReconciliationOutcome::Uncertain {
                reason: "provider usage has not been reported yet",
            };
        };
        let Some(row) = row else {
            return ReconciliationOutcome::Uncertain {
                reason: "no provider invoice row observed yet",
            };
        };

        let expected_call_id = source.provider_call_reference();
        if reported.provider_call_id != expected_call_id {
            return ReconciliationOutcome::UnknownCall {
                provider_call_id: reported.provider_call_id.clone(),
            };
        }
        if row.provider_call_id != expected_call_id {
            return ReconciliationOutcome::UnknownCall {
                provider_call_id: row.provider_call_id.clone(),
            };
        }
        if row.account_id != self.expected_account {
            return ReconciliationOutcome::WrongAccount {
                expected: self.expected_account.clone(),
                found: row.account_id.clone(),
            };
        }
        if let Some(cost) = reported.provider_cost_micros {
            if cost < 0 {
                return ReconciliationOutcome::InvalidProviderUsage {
                    field: "provider_cost_micros",
                    value: cost,
                };
            }
        }
        if row.cost_micros < 0 {
            return ReconciliationOutcome::InvalidProviderUsage {
                field: "cost_micros",
                value: row.cost_micros,
            };
        }
        let discrepancy = ProviderUsageDiscrepancy {
            provider_call_id: expected_call_id.to_owned(),
            reported_tokens_in: reported.tokens_in,
            invoice_tokens_in: row.tokens_in,
            reported_tokens_out: reported.tokens_out,
            invoice_tokens_out: row.tokens_out,
            reported_cost_micros: reported.provider_cost_micros,
            invoice_cost_micros: row.cost_micros,
        };
        let tokens_in_match = discrepancy
            .reported_tokens_in
            .map(|reported| reported == discrepancy.invoice_tokens_in)
            .unwrap_or(true);
        let tokens_out_match = discrepancy
            .reported_tokens_out
            .map(|reported| reported == discrepancy.invoice_tokens_out)
            .unwrap_or(true);
        let cost_match = discrepancy
            .reported_cost_micros
            .map(|reported| reported == discrepancy.invoice_cost_micros)
            .unwrap_or(true);
        let all_fields_present = discrepancy.reported_tokens_in.is_some()
            && discrepancy.reported_tokens_out.is_some()
            && discrepancy.reported_cost_micros.is_some();
        if !all_fields_present && tokens_in_match && tokens_out_match && cost_match {
            ReconciliationOutcome::Uncertain {
                reason: "provider usage has missing fields",
            }
        } else {
            if !self
                .seen_provider_call_ids
                .insert(row.provider_call_id.clone())
            {
                return ReconciliationOutcome::DuplicateInvoiceRow {
                    provider_call_id: row.provider_call_id.clone(),
                };
            }
            if all_fields_present && tokens_in_match && tokens_out_match && cost_match {
                ReconciliationOutcome::Reconciled
            } else if discrepancy.invoice_is_over_reported() {
                ReconciliationOutcome::ProviderUsageOverReported { discrepancy }
            } else if discrepancy.invoice_is_under_reported() {
                ReconciliationOutcome::ProviderUsageUnderReported { discrepancy }
            } else {
                ReconciliationOutcome::ProviderUsageDiscrepancy { discrepancy }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model_call_receipt::receipt::tests::sample_receipt;
    use crate::model_call_receipt::receipt::ReceiptStage;

    fn settled_receipt() -> ModelCallReceipt {
        let mut receipt = sample_receipt();
        receipt.terminal_stage = ReceiptStage::Decoded;
        receipt.local_request_bytes = 10;
        receipt.local_response_bytes = 20;
        receipt.provider_call_reference = "call-ref-1".into();
        receipt
    }

    fn row(
        provider_call_id: &str,
        account_id: &str,
        tokens_in: u64,
        tokens_out: u64,
    ) -> ProviderInvoiceRow {
        ProviderInvoiceRow {
            provider_call_id: provider_call_id.into(),
            account_id: account_id.into(),
            tokens_in,
            tokens_out,
            cost_micros: 1234,
        }
    }

    fn reported(tokens_in: u64, tokens_out: u64, cost_micros: i64) -> ProviderReportedUsage {
        ProviderReportedUsage {
            provider_call_id: "call-ref-1".into(),
            tokens_in,
            tokens_out,
            provider_cost_micros: cost_micros,
        }
    }

    fn receipt_with_reported(
        tokens_in: u64,
        tokens_out: u64,
        cost_micros: i64,
    ) -> ModelCallReceipt {
        let mut receipt = settled_receipt();
        receipt.provider_reported = Some(reported(tokens_in, tokens_out, cost_micros));
        receipt
    }

    #[test]
    fn exact_match_reconciles() {
        let receipt = settled_receipt();
        let mut reconciler = BillingReconciler::new("acct-1");
        let outcome = reconciler.reconcile(&receipt, Some(&row("call-ref-1", "acct-1", 18, 12)));
        // local_units = 10 + 20 = 30; provider tokens_in+tokens_out = 30.
        assert_eq!(outcome, ReconciliationOutcome::Reconciled);
    }

    #[test]
    fn provider_over_report_is_detected_with_the_specific_units() {
        let receipt = settled_receipt();
        let mut reconciler = BillingReconciler::new("acct-1");
        let outcome = reconciler.reconcile(&receipt, Some(&row("call-ref-1", "acct-1", 20, 20)));
        assert_eq!(
            outcome,
            ReconciliationOutcome::ProviderOverReported {
                local_units: 30,
                provider_units: 40
            }
        );
    }

    #[test]
    fn provider_under_report_is_detected_with_the_specific_units() {
        let receipt = settled_receipt();
        let mut reconciler = BillingReconciler::new("acct-1");
        let outcome = reconciler.reconcile(&receipt, Some(&row("call-ref-1", "acct-1", 5, 5)));
        assert_eq!(
            outcome,
            ReconciliationOutcome::ProviderUnderReported {
                local_units: 30,
                provider_units: 10
            }
        );
    }

    #[test]
    fn a_duplicate_invoice_row_is_rejected_on_its_second_submission() {
        let receipt = settled_receipt();
        let mut reconciler = BillingReconciler::new("acct-1");
        let first = reconciler.reconcile(&receipt, Some(&row("call-ref-1", "acct-1", 18, 12)));
        assert_eq!(first, ReconciliationOutcome::Reconciled);
        let second = reconciler.reconcile(&receipt, Some(&row("call-ref-1", "acct-1", 18, 12)));
        assert_eq!(
            second,
            ReconciliationOutcome::DuplicateInvoiceRow {
                provider_call_id: "call-ref-1".into()
            }
        );
    }

    #[test]
    fn a_row_naming_a_different_call_is_unknown() {
        let receipt = settled_receipt();
        let mut reconciler = BillingReconciler::new("acct-1");
        let outcome =
            reconciler.reconcile(&receipt, Some(&row("some-other-call", "acct-1", 30, 0)));
        assert_eq!(
            outcome,
            ReconciliationOutcome::UnknownCall {
                provider_call_id: "some-other-call".into()
            }
        );
    }

    #[test]
    fn a_row_for_the_wrong_account_is_rejected() {
        let receipt = settled_receipt();
        let mut reconciler = BillingReconciler::new("acct-1");
        let outcome = reconciler.reconcile(
            &receipt,
            Some(&row("call-ref-1", "acct-9-not-ours", 18, 12)),
        );
        assert_eq!(
            outcome,
            ReconciliationOutcome::WrongAccount {
                expected: "acct-1".into(),
                found: "acct-9-not-ours".into()
            }
        );
    }

    #[test]
    fn reconciliation_is_uncertain_before_the_receipt_settles_or_before_a_row_arrives() {
        let mut unsettled = settled_receipt();
        unsettled.terminal_stage = ReceiptStage::Dispatched;
        let mut reconciler = BillingReconciler::new("acct-1");
        assert_eq!(
            reconciler.reconcile(&unsettled, Some(&row("call-ref-1", "acct-1", 18, 12))),
            ReconciliationOutcome::Uncertain {
                reason: "receipt has not settled yet"
            }
        );

        let settled = settled_receipt();
        let mut reconciler = BillingReconciler::new("acct-1");
        assert_eq!(
            reconciler.reconcile(&settled, None),
            ReconciliationOutcome::Uncertain {
                reason: "no provider invoice row observed yet"
            }
        );
    }

    #[test]
    fn actual_provider_usage_reconciles_tokens_and_cost_independently() {
        let receipt = receipt_with_reported(11, 22, 1234);
        let mut reconciler = BillingReconciler::new("acct-1");
        let outcome = reconciler.reconcile_provider_reported(
            &receipt,
            Some(&ProviderInvoiceRow {
                provider_call_id: "call-ref-1".into(),
                account_id: "acct-1".into(),
                tokens_in: 11,
                tokens_out: 22,
                cost_micros: 1234,
            }),
        );
        assert_eq!(outcome, ReconciliationOutcome::Reconciled);
    }

    #[test]
    fn actual_provider_usage_over_report_keeps_each_field_visible() {
        let receipt = receipt_with_reported(11, 22, 1234);
        let mut reconciler = BillingReconciler::new("acct-1");
        let outcome = reconciler.reconcile_provider_reported(
            &receipt,
            Some(&ProviderInvoiceRow {
                provider_call_id: "call-ref-1".into(),
                account_id: "acct-1".into(),
                tokens_in: 12,
                tokens_out: 23,
                cost_micros: 1235,
            }),
        );
        assert_eq!(
            outcome,
            ReconciliationOutcome::ProviderUsageOverReported {
                discrepancy: ProviderUsageDiscrepancy {
                    provider_call_id: "call-ref-1".into(),
                    reported_tokens_in: Some(11),
                    invoice_tokens_in: 12,
                    reported_tokens_out: Some(22),
                    invoice_tokens_out: 23,
                    reported_cost_micros: Some(1234),
                    invoice_cost_micros: 1235,
                }
            }
        );
    }

    #[test]
    fn actual_provider_usage_under_report_is_not_a_zero_or_byte_proxy_match() {
        let receipt = receipt_with_reported(11, 22, 1234);
        // The local byte proxy is 30, while both actual and invoice token
        // totals are 33.  Only actual provider fields may drive this path.
        let mut reconciler = BillingReconciler::new("acct-1");
        let outcome = reconciler.reconcile_provider_reported(
            &receipt,
            Some(&ProviderInvoiceRow {
                provider_call_id: "call-ref-1".into(),
                account_id: "acct-1".into(),
                tokens_in: 10,
                tokens_out: 21,
                cost_micros: 1233,
            }),
        );
        assert_eq!(
            outcome,
            ReconciliationOutcome::ProviderUsageUnderReported {
                discrepancy: ProviderUsageDiscrepancy {
                    provider_call_id: "call-ref-1".into(),
                    reported_tokens_in: Some(11),
                    invoice_tokens_in: 10,
                    reported_tokens_out: Some(22),
                    invoice_tokens_out: 21,
                    reported_cost_micros: Some(1234),
                    invoice_cost_micros: 1233,
                }
            }
        );
    }

    #[test]
    fn actual_provider_usage_duplicate_is_detected_after_the_first_row() {
        let receipt = receipt_with_reported(11, 22, 1234);
        let invoice = ProviderInvoiceRow {
            provider_call_id: "call-ref-1".into(),
            account_id: "acct-1".into(),
            tokens_in: 11,
            tokens_out: 22,
            cost_micros: 1234,
        };
        let mut reconciler = BillingReconciler::new("acct-1");
        assert_eq!(
            reconciler.reconcile_provider_reported(&receipt, Some(&invoice)),
            ReconciliationOutcome::Reconciled
        );
        assert_eq!(
            reconciler.reconcile_provider_reported(&receipt, Some(&invoice)),
            ReconciliationOutcome::DuplicateInvoiceRow {
                provider_call_id: "call-ref-1".into()
            }
        );
    }

    #[test]
    fn actual_provider_usage_unknown_call_is_not_consumed() {
        let receipt = receipt_with_reported(11, 22, 1234);
        let mut reconciler = BillingReconciler::new("acct-1");
        assert_eq!(
            reconciler.reconcile_provider_reported(
                &receipt,
                Some(&ProviderInvoiceRow {
                    provider_call_id: "other-call".into(),
                    account_id: "acct-1".into(),
                    tokens_in: 11,
                    tokens_out: 22,
                    cost_micros: 1234,
                }),
            ),
            ReconciliationOutcome::UnknownCall {
                provider_call_id: "other-call".into()
            }
        );
        let valid = ProviderInvoiceRow {
            provider_call_id: "call-ref-1".into(),
            account_id: "acct-1".into(),
            tokens_in: 11,
            tokens_out: 22,
            cost_micros: 1234,
        };
        assert_eq!(
            reconciler.reconcile_provider_reported(&receipt, Some(&valid)),
            ReconciliationOutcome::Reconciled
        );
    }

    #[test]
    fn actual_provider_usage_wrong_account_is_not_consumed() {
        let receipt = receipt_with_reported(11, 22, 1234);
        let mut reconciler = BillingReconciler::new("acct-1");
        assert_eq!(
            reconciler.reconcile_provider_reported(
                &receipt,
                Some(&ProviderInvoiceRow {
                    provider_call_id: "call-ref-1".into(),
                    account_id: "acct-9".into(),
                    tokens_in: 11,
                    tokens_out: 22,
                    cost_micros: 1234,
                }),
            ),
            ReconciliationOutcome::WrongAccount {
                expected: "acct-1".into(),
                found: "acct-9".into()
            }
        );
        let valid = ProviderInvoiceRow {
            provider_call_id: "call-ref-1".into(),
            account_id: "acct-1".into(),
            tokens_in: 11,
            tokens_out: 22,
            cost_micros: 1234,
        };
        assert_eq!(
            reconciler.reconcile_provider_reported(&receipt, Some(&valid)),
            ReconciliationOutcome::Reconciled
        );
    }

    #[test]
    fn actual_provider_usage_missing_report_or_invoice_stays_uncertain() {
        let mut no_report = settled_receipt();
        no_report.provider_reported = None;
        let valid = row("call-ref-1", "acct-1", 11, 22);
        let mut reconciler = BillingReconciler::new("acct-1");
        assert_eq!(
            reconciler.reconcile_provider_reported(&no_report, Some(&valid)),
            ReconciliationOutcome::Uncertain {
                reason: "provider usage has not been reported yet"
            }
        );

        let receipt = receipt_with_reported(11, 22, 1234);
        assert_eq!(
            reconciler.reconcile_provider_reported(&receipt, None),
            ReconciliationOutcome::Uncertain {
                reason: "no provider invoice row observed yet"
            }
        );
    }

    #[test]
    fn partial_provider_usage_compares_known_fields_but_keeps_missing_fields_unknown() {
        let partial = ProviderReportedUsageFields {
            provider_call_id: "call-ref-1".into(),
            tokens_in: Some(11),
            tokens_out: None,
            provider_cost_micros: None,
        };
        let invoice = ProviderInvoiceRow {
            provider_call_id: "call-ref-1".into(),
            account_id: "acct-1".into(),
            // These values must not be treated as zero or compared while the
            // corresponding provider fields are absent.
            tokens_in: 11,
            tokens_out: 999,
            cost_micros: 999,
        };
        let mut reconciler = BillingReconciler::new("acct-1");
        assert_eq!(
            reconciler.reconcile_provider_reported(&partial, Some(&invoice)),
            ReconciliationOutcome::Uncertain {
                reason: "provider usage has missing fields"
            }
        );

        // Incompleteness did not consume the row. A later complete report can
        // reconcile the same invoice line.
        let complete = reported(11, 999, 999);
        assert_eq!(
            reconciler.reconcile_provider_reported(&complete, Some(&invoice)),
            ReconciliationOutcome::Reconciled
        );
    }

    #[test]
    fn partial_provider_usage_reports_a_known_field_discrepancy_without_fabricating_zeroes() {
        let partial = ProviderReportedUsageFields {
            provider_call_id: "call-ref-1".into(),
            tokens_in: Some(11),
            tokens_out: None,
            provider_cost_micros: None,
        };
        let invoice = ProviderInvoiceRow {
            provider_call_id: "call-ref-1".into(),
            account_id: "acct-1".into(),
            tokens_in: 12,
            tokens_out: 0,
            cost_micros: 0,
        };
        let mut reconciler = BillingReconciler::new("acct-1");
        assert_eq!(
            reconciler.reconcile_provider_reported(&partial, Some(&invoice)),
            ReconciliationOutcome::ProviderUsageOverReported {
                discrepancy: ProviderUsageDiscrepancy {
                    provider_call_id: "call-ref-1".into(),
                    reported_tokens_in: Some(11),
                    invoice_tokens_in: 12,
                    reported_tokens_out: None,
                    invoice_tokens_out: 0,
                    reported_cost_micros: None,
                    invoice_cost_micros: 0,
                }
            }
        );
    }

    #[test]
    fn negative_provider_cost_or_invoice_cost_is_invalid_and_not_consumed() {
        let receipt = receipt_with_reported(11, 22, -1);
        let valid = ProviderInvoiceRow {
            provider_call_id: "call-ref-1".into(),
            account_id: "acct-1".into(),
            tokens_in: 11,
            tokens_out: 22,
            cost_micros: 0,
        };
        let mut reconciler = BillingReconciler::new("acct-1");
        assert_eq!(
            reconciler.reconcile_provider_reported(&receipt, Some(&valid)),
            ReconciliationOutcome::InvalidProviderUsage {
                field: "provider_cost_micros",
                value: -1
            }
        );

        let receipt = receipt_with_reported(11, 22, 0);
        let invalid_invoice = ProviderInvoiceRow {
            cost_micros: -1,
            ..valid
        };
        assert_eq!(
            reconciler.reconcile_provider_reported(&receipt, Some(&invalid_invoice)),
            ReconciliationOutcome::InvalidProviderUsage {
                field: "cost_micros",
                value: -1
            }
        );
        assert_eq!(
            reconciler.reconcile_provider_reported(
                &receipt,
                Some(&ProviderInvoiceRow {
                    provider_call_id: "call-ref-1".into(),
                    account_id: "acct-1".into(),
                    tokens_in: 11,
                    tokens_out: 22,
                    cost_micros: 0,
                }),
            ),
            ReconciliationOutcome::Reconciled
        );
    }
}
