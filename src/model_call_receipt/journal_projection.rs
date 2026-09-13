//! Per-attempt evidence derived from retained journals, without invented host facts.
//!
//! This is a separate schema from the enriched v1 receipt: legacy journals do
//! not record provider identity, timestamps or monetary cost. Those facts stay
//! absent instead of being manufactured as zero-valued measurements.
use std::collections::BTreeMap;

use crate::audit_capsule::ObjectRef;
use crate::live_invocation::{identity::LiveInvocationId, journal, kernel::LiveKernelRun};
use serde_json::{json, Value};

pub const JOURNAL_RECEIPT_SCHEMA: &str = "semaprax.model-call-journal-receipt.v1";
pub const MAX_PROJECTION_BYTES: usize = 4 * 1024 * 1024;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProjectionError {
    Limit,
    InvalidJournal,
    ResponseDigest,
    Mismatch,
}

/// Opaque, deterministic evidence. Replaying it never calls a provider or tool.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct JournalCallReceipt {
    pub(super) value: Value,
}
impl JournalCallReceipt {
    pub fn render(&self) -> String {
        let mut bytes = self.value.to_string();
        bytes.push('\n');
        bytes
    }
    pub fn digest(&self) -> String {
        crate::audit_capsule::sha256_digest(self.render().as_bytes())
    }
    pub fn turn(&self) -> u32 {
        self.value["turn"].as_u64().unwrap() as u32
    }
    pub fn attempt(&self) -> u32 {
        self.value["attempt"].as_u64().unwrap() as u32
    }
    /// Content-addressed reference; the capsule verifier still checks its bytes
    /// and subject. This creates no signature, publication or dispatch authority.
    pub fn audit_object(&self) -> ObjectRef {
        ObjectRef {
            id: format!("model-call-{}", &self.digest()[7..]),
            object_type: "model-call-receipt".into(),
            schema: JOURNAL_RECEIPT_SCHEMA.into(),
            digest: self.digest(),
            redacted: false,
            redaction_reason: None,
            binds: BTreeMap::from([(
                "session_id".into(),
                self.value["invocation_id"].as_str().unwrap().into(),
            )]),
        }
    }
    pub(super) fn new(
        profile: &str,
        invocation: &str,
        chain: &str,
        turn: u32,
        attempt: u32,
    ) -> Self {
        Self {
            value: json!({
                "schema": JOURNAL_RECEIPT_SCHEMA, "journal_profile": profile,
                "invocation_id": invocation, "journal_chain": chain,
                "turn": turn, "attempt": attempt, "stage": "uncertain",
                "request_digest": null, "observation_digest": null, "source_prompt_digest": null,
                "request_bytes": null, "reserved_units": null,
                "response_digest": null, "response_bytes": null,
                "failure": null, "proposal_digest": null, "proposal_refusal": null,
                "provider_reported": null, "timing": null, "cost": null
            }),
        }
    }
}

/// Projects actual generic-kernel journals, including unresolved durable intents.
/// The invocation id must come from the caller's independently retained identity.
/// Validation is repeated here: `ValidatedJournal` has public fields and is not
/// an authentication token. The journal chain binds even non-model rows.
pub fn project_kernel_calls(
    entries: &[journal::JournalEntry],
    identity: &LiveInvocationId,
) -> Result<Vec<JournalCallReceipt>, ProjectionError> {
    use journal::JournalEntry as E;
    if entries.len() > journal::MAX_JOURNAL_ENTRIES {
        return Err(ProjectionError::Limit);
    }
    // Bound all variable-sized fields before encoding/hashing the journal.
    let mut size = 0usize;
    for entry in entries {
        let lengths: Vec<usize> = match entry {
            E::TurnOpened {
                invocation,
                observation_digest,
                ..
            } => vec![invocation.len(), observation_digest.len()],
            E::RequestIntent { request_digest, .. } => vec![request_digest.len()],
            E::ResponseRecorded {
                response_digest,
                response,
                ..
            } => vec![response_digest.len(), response.len()],
            E::ResponseFailed { failure, .. } => vec![failure.len()],
            E::ProposalAdmitted {
                proposal_digest, ..
            } => vec![proposal_digest.len()],
            E::ProposalRefused { reason, .. } | E::AuthorizationRefused { reason, .. } => {
                vec![reason.len()]
            }
            E::AuthorizationConsumed { grant_digest, .. } => vec![grant_digest.len()],
            E::EffectIntent {
                operation,
                request_digest,
                ..
            } => vec![operation.len(), request_digest.len()],
            E::EffectObserved {
                operation,
                observation_digest,
                ..
            } => vec![operation.len(), observation_digest.len()],
            E::EffectFailed {
                operation, reason, ..
            } => vec![operation.len(), reason.len()],
            E::Transition {
                case,
                carrier_digest,
                ..
            }
            | E::TerminalOutcome {
                case,
                carrier_digest,
                ..
            } => vec![case.len(), carrier_digest.len()],
        };
        // JSON escaping can expand each input byte sixfold, plus fixed fields.
        for length in lengths {
            size = size.saturating_add(length.saturating_mul(6));
        }
        size = size.saturating_add(512);
        if size > MAX_PROJECTION_BYTES {
            return Err(ProjectionError::Limit);
        }
    }
    if entries.is_empty() {
        return Ok(Vec::new());
    }
    journal::validate(entries, identity.digest()).map_err(|_| ProjectionError::InvalidJournal)?;
    let chain = journal::chain(entries);
    let mut receipts: Vec<JournalCallReceipt> = Vec::new();
    let mut observation = String::new();
    for entry in entries {
        match entry {
            E::TurnOpened {
                observation_digest, ..
            } => {
                if !crate::live_invocation::identity::looks_like_digest(observation_digest) {
                    return Err(ProjectionError::InvalidJournal);
                }
                observation.clone_from(observation_digest);
            }
            E::RequestIntent {
                turn,
                request_digest,
                reserved_budget,
            } => {
                if *reserved_budget < 0
                    || !crate::live_invocation::identity::looks_like_digest(request_digest)
                {
                    return Err(ProjectionError::InvalidJournal);
                }
                if receipts.len() >= MAX_PROJECTION_BYTES / 4096 {
                    return Err(ProjectionError::Limit);
                }
                let mut receipt =
                    JournalCallReceipt::new("generic-v1", identity.digest(), &chain, *turn, 1);
                receipt.value["request_digest"] = json!(request_digest);
                receipt.value["reserved_units"] = json!(reserved_budget);
                receipt.value["observation_digest"] = json!(observation);
                receipts.push(receipt);
            }
            E::ResponseRecorded {
                response_digest,
                response,
                ..
            } => {
                if crate::live_invocation::identity::digest(
                    b"semaprax.live-invocation.response.v1\0",
                    response,
                ) != *response_digest
                {
                    return Err(ProjectionError::ResponseDigest);
                }
                let r = &mut receipts
                    .last_mut()
                    .ok_or(ProjectionError::InvalidJournal)?
                    .value;
                r["response_digest"] = json!(response_digest);
                r["response_bytes"] = json!(response.len());
                r["stage"] = json!("completed");
            }
            E::ResponseFailed { failure, .. } => {
                if !matches!(
                    failure.as_str(),
                    "timeout"
                        | "cancelled"
                        | "capacity_exceeded"
                        | "provider_error"
                        | "malformed_response"
                        | "refused"
                        | "budget_exhausted"
                        | "deadline_exceeded"
                        | "negative_request"
                        | "clock_domain_mismatch"
                        | "clock_regressed"
                        | "reservation_mismatch"
                        | "model_policy_exhausted"
                        | "model_policy_invalid_quote"
                ) {
                    return Err(ProjectionError::InvalidJournal);
                }
                let r = &mut receipts
                    .last_mut()
                    .ok_or(ProjectionError::InvalidJournal)?
                    .value;
                r["failure"] = json!(failure);
                r["stage"] = json!(if failure == "cancelled" {
                    "cancelled"
                } else {
                    "failed"
                });
            }
            E::ProposalAdmitted {
                proposal_digest, ..
            } => {
                if !crate::live_invocation::identity::looks_like_digest(proposal_digest) {
                    return Err(ProjectionError::InvalidJournal);
                }
                let r = &mut receipts
                    .last_mut()
                    .ok_or(ProjectionError::InvalidJournal)?
                    .value;
                r["proposal_digest"] = json!(proposal_digest);
                r["stage"] = json!("decoded");
            }
            E::ProposalRefused { reason, .. } => {
                let r = &mut receipts
                    .last_mut()
                    .ok_or(ProjectionError::InvalidJournal)?
                    .value;
                // Free-form refusal strings can contain payloads; commit, never disclose.
                r["proposal_refusal"] =
                    json!(crate::audit_capsule::sha256_digest(reason.as_bytes()));
                r["stage"] = json!("rejected");
            }
            _ => {}
        }
    }
    let mut rendered_bytes = 0usize;
    for receipt in &receipts {
        rendered_bytes = rendered_bytes.saturating_add(receipt.render().len());
        if rendered_bytes > MAX_PROJECTION_BYTES {
            return Err(ProjectionError::Limit);
        }
    }
    Ok(receipts)
}

/// Recompute from retained evidence and compare exact canonical bytes. No live seams.
pub fn replay_kernel_calls(
    receipts: &[JournalCallReceipt],
    entries: &[journal::JournalEntry],
    identity: &LiveInvocationId,
) -> Result<(), ProjectionError> {
    if project_kernel_calls(entries, identity)? == receipts {
        Ok(())
    } else {
        Err(ProjectionError::Mismatch)
    }
}

/// Verify one externally retained receipt by exact regeneration, without trusting
/// fields parsed from that receipt. The caller selects the expected turn.
pub fn verify_kernel_receipt_bytes(
    bytes: &[u8],
    entries: &[journal::JournalEntry],
    identity: &LiveInvocationId,
    turn: u32,
) -> Result<(), ProjectionError> {
    if bytes.len() > MAX_PROJECTION_BYTES {
        return Err(ProjectionError::Limit);
    }
    let receipts = project_kernel_calls(entries, identity)?;
    let receipt = receipts
        .iter()
        .find(|r| r.turn() == turn)
        .ok_or(ProjectionError::Mismatch)?;
    if receipt.render().as_bytes() == bytes {
        Ok(())
    } else {
        Err(ProjectionError::Mismatch)
    }
}

impl LiveKernelRun {
    pub fn model_call_receipts(
        &self,
        identity: &LiveInvocationId,
    ) -> Result<Vec<JournalCallReceipt>, ProjectionError> {
        project_kernel_calls(&self.journal, identity)
    }
}

#[cfg(test)]
mod tests;
