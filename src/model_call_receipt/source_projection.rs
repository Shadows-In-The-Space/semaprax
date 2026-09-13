//! Per-attempt receipts projected from an authenticated source checkpoint.
//!
//! Source journals retain no provider identity or timing.  This projection
//! preserves that absence, while retaining the source-specific prompt digest
//! and exact priced observations where the journal committed them.

use serde_json::json;

use crate::audit_capsule::sha256_digest;
use crate::live_invocation::pricing::ProviderChargeObservation;
use crate::live_invocation::source_journal::{
    source_response_digest, PricedAttemptUsageV4, RecoveredSourceCheckpoint, SourceJournalEntry,
    SourceReportedUsage, SourceUsageObservationV4,
};

use super::journal_projection::{JournalCallReceipt, ProjectionError, MAX_PROJECTION_BYTES};

// A receipt has a substantially larger fixed canonical shape than this lower
// bound. It keeps an adversarial checkpoint from allocating an unbounded
// receipt vector before the final exact rendered-size check below.
const MIN_RECEIPT_BYTES: usize = 256;

/// Projects every committed source-model intent in its authenticated causal
/// order. An intent without a settlement remains `uncertain`; this does not
/// infer that a provider did or did not receive the request.
pub fn project_source_calls(
    checkpoint: &RecoveredSourceCheckpoint,
) -> Result<Vec<JournalCallReceipt>, ProjectionError> {
    let profile = source_profile(checkpoint);
    let mut receipts = Vec::new();
    let mut observation = None;
    let mut projected_bytes = 0usize;

    for entry in checkpoint.entries() {
        match entry {
            SourceJournalEntry::TurnObserved {
                observation: value, ..
            } => {
                observation = Some(value.as_str());
            }
            SourceJournalEntry::AttemptIntent {
                turn,
                attempt,
                request_digest,
                prompt_digest,
                request_bytes,
                reserved_units,
                ..
            } => {
                reserve_receipt_slot(receipts.len())?;
                let mut receipt = JournalCallReceipt::new(
                    profile,
                    checkpoint.invocation(),
                    checkpoint.chain(),
                    *turn,
                    *attempt,
                );
                populate_intent(
                    &mut receipt,
                    request_digest,
                    prompt_digest,
                    *request_bytes,
                    *reserved_units,
                    observation,
                );
                receipts.push(receipt);
            }
            SourceJournalEntry::PricedAttemptIntent(intent) => {
                reserve_receipt_slot(receipts.len())?;
                let mut receipt = JournalCallReceipt::new(
                    profile,
                    checkpoint.invocation(),
                    checkpoint.chain(),
                    intent.turn,
                    intent.attempt,
                );
                populate_intent(
                    &mut receipt,
                    &intent.request_digest,
                    &intent.prompt_digest,
                    intent.request_bytes,
                    intent.reserved_units,
                    observation,
                );
                receipts.push(receipt);
            }
            SourceJournalEntry::AttemptSettled {
                turn,
                attempt,
                response,
                response_digest,
            } => {
                if source_response_digest(response) != *response_digest {
                    return Err(ProjectionError::ResponseDigest);
                }
                let receipt = receipt_mut(&mut receipts, *turn, *attempt)?;
                receipt.value["response_digest"] = json!(response_digest);
                receipt.value["response_bytes"] = json!(response.len());
                receipt.value["stage"] = json!("completed");
            }
            SourceJournalEntry::AttemptFailed {
                turn,
                attempt,
                reason,
                ..
            } => {
                let receipt = receipt_mut(&mut receipts, *turn, *attempt)?;
                receipt.value["failure"] = json!(reason.as_str());
                receipt.value["stage"] = json!(if reason.as_str() == "cancelled" {
                    "cancelled"
                } else {
                    "failed"
                });
            }
            SourceJournalEntry::AttemptUsage {
                turn,
                attempt,
                reported: Some(reported),
            } => {
                receipt_mut(&mut receipts, *turn, *attempt)?.value["provider_reported"] =
                    usage_value(reported);
            }
            SourceJournalEntry::AttemptUsage { .. } => {}
            SourceJournalEntry::PricedAttemptUsage(usage) => {
                apply_priced_usage(&mut receipts, usage)?;
            }
            SourceJournalEntry::ProposalAdmitted {
                turn,
                attempt,
                proposal_digest,
            } => {
                let receipt = receipt_mut(&mut receipts, *turn, *attempt)?;
                receipt.value["proposal_digest"] = json!(proposal_digest);
                receipt.value["stage"] = json!("decoded");
            }
            SourceJournalEntry::ProposalRefused {
                turn,
                attempt,
                reason,
            } => {
                let receipt = receipt_mut(&mut receipts, *turn, *attempt)?;
                // The source reason is closed, but the receipt commits it so
                // this common projection never exposes a decoder payload.
                receipt.value["proposal_refusal"] =
                    json!(sha256_digest(reason.as_str().as_bytes()));
                receipt.value["stage"] = json!("rejected");
            }
            _ => {}
        }
    }

    for receipt in &receipts {
        projected_bytes = projected_bytes
            .checked_add(receipt.render().len())
            .ok_or(ProjectionError::Limit)?;
        if projected_bytes > MAX_PROJECTION_BYTES {
            return Err(ProjectionError::Limit);
        }
    }
    Ok(receipts)
}

/// Recomputes the source projection from the same authenticated checkpoint.
/// It never accepts a provider, tool, decoder, or mutable journal input.
pub fn replay_source_calls(
    receipts: &[JournalCallReceipt],
    checkpoint: &RecoveredSourceCheckpoint,
) -> Result<(), ProjectionError> {
    if project_source_calls(checkpoint)? == receipts {
        Ok(())
    } else {
        Err(ProjectionError::Mismatch)
    }
}

/// Verifies one persisted receipt's exact canonical bytes against the current
/// authenticated checkpoint projection. This only compares retained evidence;
/// it does not parse a caller-selected schema or contact a provider.
pub fn verify_source_receipt_bytes(
    receipt_bytes: &[u8],
    checkpoint: &RecoveredSourceCheckpoint,
    turn: u32,
    attempt: u32,
) -> Result<(), ProjectionError> {
    if receipt_bytes.len() > MAX_PROJECTION_BYTES {
        return Err(ProjectionError::Limit);
    }
    let expected = project_source_calls(checkpoint)?
        .iter()
        .find(|receipt| receipt.turn() == turn && receipt.attempt() == attempt)
        .ok_or(ProjectionError::Mismatch)?
        .render();
    if expected.as_bytes() == receipt_bytes {
        Ok(())
    } else {
        Err(ProjectionError::Mismatch)
    }
}

impl RecoveredSourceCheckpoint {
    /// Derives non-authorizing per-attempt evidence from this authenticated
    /// checkpoint. No source entry is written and no model is contacted.
    pub fn model_call_receipts(&self) -> Result<Vec<JournalCallReceipt>, ProjectionError> {
        project_source_calls(self)
    }
}

fn source_profile(checkpoint: &RecoveredSourceCheckpoint) -> &'static str {
    if checkpoint.io_totals().is_some() {
        "source-v5"
    } else if checkpoint.priced_totals().is_some() {
        if matches!(
            checkpoint.entries().first(),
            Some(SourceJournalEntry::MigrationOpened { .. })
        ) {
            "source-v4-migrated"
        } else {
            "source-v4"
        }
    } else if matches!(
        checkpoint.entries().first(),
        Some(SourceJournalEntry::MigrationOpened { .. })
    ) {
        "source-v3"
    } else if checkpoint.evaluator_profile().is_some() {
        "source-v2"
    } else {
        "source-v1"
    }
}

fn populate_intent(
    receipt: &mut JournalCallReceipt,
    request_digest: &str,
    prompt_digest: &str,
    request_bytes: usize,
    reserved_units: i64,
    observation: Option<&str>,
) {
    receipt.value["request_digest"] = json!(request_digest);
    receipt.value["source_prompt_digest"] = json!(prompt_digest);
    receipt.value["request_bytes"] = json!(request_bytes);
    receipt.value["reserved_units"] = json!(reserved_units);
    if let Some(observation) = observation {
        receipt.value["observation_digest"] = json!(observation);
    }
}

fn receipt_mut(
    receipts: &mut [JournalCallReceipt],
    turn: u32,
    attempt: u32,
) -> Result<&mut JournalCallReceipt, ProjectionError> {
    receipts
        .iter_mut()
        .rev()
        .find(|receipt| receipt.turn() == turn && receipt.attempt() == attempt)
        .ok_or(ProjectionError::InvalidJournal)
}

fn reserve_receipt_slot(current: usize) -> Result<(), ProjectionError> {
    current
        .checked_add(1)
        .and_then(|count| count.checked_mul(MIN_RECEIPT_BYTES))
        .filter(|bytes| *bytes <= MAX_PROJECTION_BYTES)
        .ok_or(ProjectionError::Limit)
        .map(|_| ())
}

fn usage_value(reported: &SourceReportedUsage) -> serde_json::Value {
    json!({
        "total": reported.total,
        "input": reported.input,
        "output": reported.output,
        "reasoning": reported.reasoning,
        "cache_read": reported.cache_read,
        "cache_write": reported.cache_write,
    })
}

fn apply_priced_usage(
    receipts: &mut [JournalCallReceipt],
    usage: &PricedAttemptUsageV4,
) -> Result<(), ProjectionError> {
    let receipt = receipt_mut(receipts, usage.turn, usage.attempt)?;
    if let SourceUsageObservationV4::Observed(reported) = &usage.usage {
        receipt.value["provider_reported"] = usage_value(reported);
    }
    if let ProviderChargeObservation::Observed {
        currency,
        minor_unit_exponent,
        amount_minor,
    } = &usage.charge
    {
        receipt.value["cost"] = json!({
            "currency": currency,
            "minor_unit_exponent": minor_unit_exponent,
            "amount_minor": amount_minor,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests;
