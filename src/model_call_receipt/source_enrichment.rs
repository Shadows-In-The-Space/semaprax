//! Rich receipts reconstructed from an authenticated source checkpoint.
//!
//! Source journals intentionally omit host/provider facts.  This module only
//! constructs `ModelCallReceipt` when a caller retains those facts separately;
//! it never manufactures a provider identity, time, cost, or call reference.

use crate::agent_proposal::CompiledAgentProposalSchema;
use crate::live_invocation::{
    identity::digest,
    source_journal::{
        source_prompt_digest, source_response_digest, RecoveredSourceCheckpoint,
        SourceJournalEntry, SourceReportedUsage, SourceUsageObservationV4,
    },
};

use super::receipt::*;
use std::collections::BTreeMap;

const MAX_RECEIPT_BYTES: usize = 65_536;
const MAX_TOTAL_RECEIPT_BYTES: usize = 4 * 1024 * 1024;
const MAX_TEXT_BYTES: usize = 4_096;
const SOURCE_PROPOSAL_DOMAIN: &[u8] = b"semaprax.source-proposal.v2\0";
const SOURCE_OBSERVATION_DOMAIN: &[u8] = b"semaprax.source-observation.v2\0";
const MAX_ATTEMPTS: usize = 1_024;

/// Immutable source binding inputs retained independently of the recovered
/// checkpoint. `compiled_schema` is required when a checkpoint records a
/// proposal decode outcome, so an admitted result is reproduced from the
/// original response rather than trusted from the journal tag alone.
pub struct SourceReceiptBindingInputs<'a> {
    pub source_revision: &'a str,
    pub deployment_binding: &'a str,
    pub task: &'a [u8],
    pub task_budget: i64,
    pub proposal_schema_digest: &'a str,
    pub compiled_schema: Option<&'a CompiledAgentProposalSchema>,
}

/// Independently retained host and request facts for one source attempt.
///
/// `prompt` is the exact source prompt whose source-journal commitment is
/// checked. `observation` is the exact `encode_value(observation)` byte
/// sequence retained by the source route; its source-observation-v2 digest
/// must match the authoritative `TurnObserved` entry before it is committed
/// again in the rich receipt domain. All host timing fields share one
/// invocation clock domain.
pub struct SourceAttemptMetadata<'a> {
    pub turn: u32,
    /// The source journal's zero-based retry ordinal. The constructed rich
    /// receipt uses this value plus one, as required by `ModelCallReceipt`.
    pub attempt: u32,
    pub observation: &'a [u8],
    pub prompt: &'a [u8],
    pub roots: RootBindingContext<'a>,
    pub model_class: &'a str,
    pub provider_class: &'a str,
    pub adapter_identity: &'a str,
    pub provider_call_reference: &'a str,
    pub reserved_at_ms: u64,
    pub dispatched_at_ms: Option<u64>,
    pub first_byte_at_ms: Option<u64>,
    pub completed_at_ms: Option<u64>,
    pub cost_estimate_micros: i64,
    pub provider_reported: Option<&'a ProviderReportedUsage>,
}

/// Why source enrichment refused to turn evidence into a rich receipt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SourceEnrichmentError {
    Limit,
    Binding,
    MissingMetadata,
    DuplicateMetadata,
    HostFacts,
    Journal,
    Decode,
    Root,
    Mismatch,
}

/// Builds one rich receipt for each durable source attempt in causal order.
///
/// This is a pure read of an opaque recovered checkpoint. In particular, it
/// accepts no provider handler and cannot dispatch a replacement model call.
pub fn enrich_source_calls(
    checkpoint: &RecoveredSourceCheckpoint,
    inputs: &SourceReceiptBindingInputs<'_>,
    attempts: &[SourceAttemptMetadata<'_>],
) -> Result<Vec<ModelCallReceipt>, SourceEnrichmentError> {
    use SourceEnrichmentError as E;
    validate_binding(checkpoint, inputs, attempts)?;
    let metadata = metadata_index(attempts)?;
    let checkpoint_index = checkpoint_index(checkpoint)?;

    let mut receipts = Vec::new();
    let mut rendered_bytes = 0usize;
    for entry in checkpoint.entries() {
        let (turn, attempt, request_digest, prompt_digest, request_bytes, reserved_budget) =
            match entry {
                SourceJournalEntry::AttemptIntent {
                    turn,
                    attempt,
                    request_digest,
                    prompt_digest,
                    request_bytes,
                    reserved_units,
                    ..
                } => (
                    *turn,
                    *attempt,
                    request_digest.as_str(),
                    prompt_digest.as_str(),
                    *request_bytes,
                    *reserved_units,
                ),
                SourceJournalEntry::PricedAttemptIntent(intent) => (
                    intent.turn,
                    intent.attempt,
                    intent.request_digest.as_str(),
                    intent.prompt_digest.as_str(),
                    intent.request_bytes,
                    intent.reserved_units,
                ),
                _ => continue,
            };
        reserve_slot(receipts.len())?;
        let host = metadata
            .get(&(turn, attempt))
            .copied()
            .ok_or(E::MissingMetadata)?;
        if host.prompt.len() != request_bytes || source_prompt_digest(host.prompt) != prompt_digest
        {
            return Err(E::Journal);
        }
        let recorded_observation = checkpoint_index.observations.get(&turn).ok_or(E::Journal)?;
        if digest(SOURCE_OBSERVATION_DOMAIN, host.observation).as_str() != *recorded_observation {
            return Err(E::Journal);
        }
        if let Some(reported) = host.provider_reported {
            let journal_usage = checkpoint_index
                .attempts
                .get(&(turn, attempt))
                .and_then(|evidence| evidence.usage);
            check_usage_consistency(reported, journal_usage)?;
        }
        let outcome = source_outcome(
            checkpoint_index.attempts.get(&(turn, attempt)),
            inputs.compiled_schema,
            host.dispatched_at_ms.is_some(),
            host.first_byte_at_ms.is_some(),
        )?;
        let receipt_attempt = attempt.checked_add(1).ok_or(E::Limit)?;
        let receipt = ModelCallReceipt {
            agent_id: host.roots.agent_id.into(),
            program_root: host.roots.program_root.into(),
            deployment_root: host.roots.deployment_root.into(),
            instance_root: host.roots.instance_root.into(),
            invocation_id: checkpoint.invocation().into(),
            turn,
            attempt: receipt_attempt,
            model_class: host.model_class.into(),
            provider_class: host.provider_class.into(),
            adapter_identity: host.adapter_identity.into(),
            proposal_grammar_digest: inputs.proposal_schema_digest.into(),
            deployment_policy_digest: inputs.deployment_binding.into(),
            task_digest: commit_task_bytes(inputs.task),
            observation_digest: commit_observation_bytes(host.observation),
            request_digest: request_digest.into(),
            request_bytes_len: request_bytes,
            reserved_budget,
            response_digest: outcome.response.map(commit_response_bytes),
            response_bytes_len: outcome.response.map(<[u8]>::len),
            private_payload_reference: None,
            terminal_stage: outcome.stage,
            failure: outcome.failure,
            proposal_digest: outcome.proposal_digest,
            proposal_refusal_reason: outcome.proposal_refusal_reason,
            reserved_at_ms: host.reserved_at_ms,
            dispatched_at_ms: host.dispatched_at_ms,
            first_byte_at_ms: host.first_byte_at_ms,
            completed_at_ms: host.completed_at_ms,
            local_request_bytes: request_bytes,
            local_response_bytes: outcome
                .response
                .map_or(outcome.attempted_bytes, <[u8]>::len),
            cost_estimate_micros: host.cost_estimate_micros,
            provider_call_reference: host.provider_call_reference.into(),
            provider_reported: host.provider_reported.cloned(),
        };
        verify_root_binding(&receipt, &host.roots).map_err(|_| E::Root)?;
        let rendered = receipt.render();
        if rendered.len() > MAX_RECEIPT_BYTES {
            return Err(E::Limit);
        }
        rendered_bytes = rendered_bytes.checked_add(rendered.len()).ok_or(E::Limit)?;
        if rendered_bytes > MAX_TOTAL_RECEIPT_BYTES {
            return Err(E::Limit);
        }
        receipts.push(receipt);
    }
    if metadata.len() != receipts.len() {
        return Err(E::MissingMetadata);
    }
    Ok(receipts)
}

/// Pure exact-byte replay. Submitted bytes are compared only after a complete
/// reconstruction from checkpoint, binding inputs, source schema, and host
/// facts. This API has no provider dispatch capability.
pub fn replay_source_enriched_calls(
    submitted: &[u8],
    checkpoint: &RecoveredSourceCheckpoint,
    inputs: &SourceReceiptBindingInputs<'_>,
    attempts: &[SourceAttemptMetadata<'_>],
) -> Result<(), SourceEnrichmentError> {
    if submitted.len() > MAX_TOTAL_RECEIPT_BYTES {
        return Err(SourceEnrichmentError::Limit);
    }
    let expected = enrich_source_calls(checkpoint, inputs, attempts)?;
    let mut rendered = Vec::new();
    for receipt in expected {
        rendered.extend_from_slice(receipt.render().as_bytes());
    }
    if rendered.as_slice() == submitted {
        Ok(())
    } else {
        Err(SourceEnrichmentError::Mismatch)
    }
}

fn validate_binding(
    checkpoint: &RecoveredSourceCheckpoint,
    inputs: &SourceReceiptBindingInputs<'_>,
    attempts: &[SourceAttemptMetadata<'_>],
) -> Result<(), SourceEnrichmentError> {
    use SourceEnrichmentError as E;
    if inputs.task.len() > 65_536
        || attempts.len() > MAX_ATTEMPTS
        || attempts.len().saturating_mul(256) > MAX_TOTAL_RECEIPT_BYTES
    {
        return Err(E::Limit);
    }
    for text in [
        inputs.source_revision,
        inputs.deployment_binding,
        inputs.proposal_schema_digest,
    ] {
        if text.len() > MAX_TEXT_BYTES {
            return Err(E::Limit);
        }
    }
    if !checkpoint.matches_proposal_source(
        inputs.source_revision,
        inputs.deployment_binding,
        inputs.task,
        inputs.task_budget,
        inputs.proposal_schema_digest,
    ) {
        return Err(E::Binding);
    }
    if let Some(schema) = inputs.compiled_schema {
        if schema.schema().digest() != inputs.proposal_schema_digest
            || schema.source_revision() != inputs.source_revision
        {
            return Err(E::Binding);
        }
    }
    for host in attempts {
        let program_root = checkpoint.program_root().ok_or(E::Binding)?;
        if host.roots.program_root != program_root
            || host.roots.invocation_id != checkpoint.invocation()
            || host.roots.proposal_grammar_digest != inputs.proposal_schema_digest
            || host.roots.deployment_policy_digest != inputs.deployment_binding
            || host.roots.previous_attempt != host.attempt
        {
            return Err(E::Root);
        }
        if host.observation.len() > 65_536
            || host.prompt.len() > 65_536
            || host.cost_estimate_micros < 0
        {
            return Err(E::Limit);
        }
        for text in [
            host.roots.agent_id,
            host.roots.program_root,
            host.roots.deployment_root,
            host.roots.instance_root,
            host.roots.invocation_id,
            host.model_class,
            host.provider_class,
            host.adapter_identity,
            host.provider_call_reference,
        ] {
            if text.len() > MAX_TEXT_BYTES {
                return Err(E::Limit);
            }
        }
        let mut previous = host.reserved_at_ms;
        for time in [
            host.dispatched_at_ms,
            host.first_byte_at_ms,
            host.completed_at_ms,
        ]
        .into_iter()
        .flatten()
        {
            if time < previous {
                return Err(E::HostFacts);
            }
            previous = time;
        }
        if let Some(reported) = host.provider_reported {
            if reported.provider_call_id.len() > MAX_TEXT_BYTES
                || reported.provider_call_id != host.provider_call_reference
                || reported.provider_cost_micros < 0
            {
                return Err(E::HostFacts);
            }
        }
    }
    Ok(())
}

fn metadata_index<'a>(
    attempts: &'a [SourceAttemptMetadata<'a>],
) -> Result<BTreeMap<(u32, u32), &'a SourceAttemptMetadata<'a>>, SourceEnrichmentError> {
    let mut index = BTreeMap::new();
    for host in attempts {
        if index.insert((host.turn, host.attempt), host).is_some() {
            return Err(SourceEnrichmentError::DuplicateMetadata);
        }
    }
    Ok(index)
}

#[derive(Default)]
struct AttemptEvidence<'a> {
    response: Option<&'a [u8]>,
    failure: Option<(&'a str, usize)>,
    admitted: Option<&'a str>,
    refused: Option<&'a str>,
    usage: Option<&'a SourceReportedUsage>,
}

struct CheckpointIndex<'a> {
    observations: BTreeMap<u32, &'a str>,
    attempts: BTreeMap<(u32, u32), AttemptEvidence<'a>>,
}

fn checkpoint_index<'a>(
    checkpoint: &'a RecoveredSourceCheckpoint,
) -> Result<CheckpointIndex<'a>, SourceEnrichmentError> {
    let mut observations = BTreeMap::new();
    let mut attempts: BTreeMap<(u32, u32), AttemptEvidence<'a>> = BTreeMap::new();
    for entry in checkpoint.entries() {
        match entry {
            SourceJournalEntry::TurnObserved {
                turn, observation, ..
            } => {
                observations.insert(*turn, observation.as_str());
            }
            SourceJournalEntry::AttemptSettled {
                turn,
                attempt,
                response,
                response_digest,
            } => {
                if source_response_digest(response) != *response_digest {
                    return Err(SourceEnrichmentError::Journal);
                }
                attempts.entry((*turn, *attempt)).or_default().response = Some(response.as_slice());
            }
            SourceJournalEntry::AttemptFailed {
                turn,
                attempt,
                reason,
                attempted_bytes,
            } => {
                attempts.entry((*turn, *attempt)).or_default().failure =
                    Some((reason.as_str(), *attempted_bytes));
            }
            SourceJournalEntry::ProposalAdmitted {
                turn,
                attempt,
                proposal_digest,
            } => {
                attempts.entry((*turn, *attempt)).or_default().admitted =
                    Some(proposal_digest.as_str());
            }
            SourceJournalEntry::ProposalRefused {
                turn,
                attempt,
                reason,
            } => {
                attempts.entry((*turn, *attempt)).or_default().refused = Some(reason.as_str());
            }
            SourceJournalEntry::AttemptUsage {
                turn,
                attempt,
                reported,
            } => {
                attempts.entry((*turn, *attempt)).or_default().usage = reported.as_ref();
            }
            SourceJournalEntry::PricedAttemptUsage(usage) => {
                if let SourceUsageObservationV4::Observed(reported) = &usage.usage {
                    attempts
                        .entry((usage.turn, usage.attempt))
                        .or_default()
                        .usage = Some(reported);
                }
            }
            _ => {}
        }
    }
    Ok(CheckpointIndex {
        observations,
        attempts,
    })
}

/// Compares only the source dimensions that have compatible semantics with
/// the complete rich receipt usage. Source `total`, reasoning, and cache
/// counters remain distinct dimensions; they are never summed or normalized
/// into the rich receipt's input/output fields. A priced source charge also
/// remains a separate journal projection: `provider_cost_micros` has no
/// declared currency or minor-unit exponent in `ProviderReportedUsage`, so
/// this route cannot establish compatible monetary units to compare.
fn check_usage_consistency(
    provider: &ProviderReportedUsage,
    journal: Option<&SourceReportedUsage>,
) -> Result<(), SourceEnrichmentError> {
    let Some(journal) = journal else {
        // Legacy `reported: None` and priced `usage: Unknown` are durable
        // unknowns. They do not contradict independently retained host facts.
        return Ok(());
    };
    if journal
        .input
        .is_some_and(|value| value != provider.tokens_in)
        || journal
            .output
            .is_some_and(|value| value != provider.tokens_out)
    {
        return Err(SourceEnrichmentError::HostFacts);
    }
    Ok(())
}

struct Outcome<'a> {
    response: Option<&'a [u8]>,
    attempted_bytes: usize,
    stage: ReceiptStage,
    failure: Option<String>,
    proposal_digest: Option<String>,
    proposal_refusal_reason: Option<String>,
}

fn source_outcome<'a>(
    evidence: Option<&AttemptEvidence<'a>>,
    schema: Option<&CompiledAgentProposalSchema>,
    dispatched: bool,
    first_byte: bool,
) -> Result<Outcome<'a>, SourceEnrichmentError> {
    use SourceEnrichmentError as E;
    let response = evidence.and_then(|evidence| evidence.response);
    let failure = evidence
        .and_then(|evidence| evidence.failure)
        .map(|(reason, _)| reason.to_owned());
    let attempted_bytes = evidence
        .and_then(|evidence| evidence.failure)
        .map_or(0, |(_, bytes)| bytes);
    let admitted = evidence.and_then(|evidence| evidence.admitted);
    let refused = evidence.and_then(|evidence| evidence.refused);
    if response.is_some() && failure.is_some() || admitted.is_some() && refused.is_some() {
        return Err(E::Journal);
    }
    let (proposal_digest, proposal_refusal_reason, stage) = match (admitted, refused) {
        (Some(recorded), None) => {
            let response = response.ok_or(E::Journal)?;
            let source = std::str::from_utf8(response).map_err(|_| E::Decode)?;
            let schema = schema.ok_or(E::Decode)?;
            let proposal = schema.decode(source).map_err(|_| E::Decode)?;
            let canonical = proposal.canonical_json();
            if digest(SOURCE_PROPOSAL_DOMAIN, canonical.as_bytes()) != recorded {
                return Err(E::Decode);
            }
            (
                Some(commit_proposal_bytes(canonical.as_bytes())),
                None,
                ReceiptStage::Decoded,
            )
        }
        (None, Some(recorded)) => {
            let response = response.ok_or(E::Journal)?;
            match std::str::from_utf8(response) {
                Ok(source) if recorded == "malformed_decode" => {
                    let schema = schema.ok_or(E::Decode)?;
                    if schema.decode(source).is_ok() {
                        return Err(E::Decode);
                    }
                }
                Err(_) if recorded == "invalid_utf8" => {}
                // Deadline/projection refusal is a source lifecycle outcome,
                // not a schema-decoder claim this module can reproduce.
                _ if matches!(recorded, "deadline_exceeded" | "projection_failed") => {}
                _ => return Err(E::Decode),
            }
            (None, Some(recorded.to_owned()), ReceiptStage::Rejected)
        }
        (None, None) if response.is_some() => (None, None, ReceiptStage::Completed),
        (None, None) if failure.as_deref() == Some("cancelled") => {
            (None, None, ReceiptStage::Cancelled)
        }
        (None, None) if failure.is_some() => (
            None,
            None,
            if dispatched {
                ReceiptStage::Dispatched
            } else {
                ReceiptStage::IntentPersisted
            },
        ),
        (None, None) if first_byte => (None, None, ReceiptStage::FirstByte),
        (None, None) if dispatched => (None, None, ReceiptStage::Dispatched),
        (None, None) => (None, None, ReceiptStage::Uncertain),
        (Some(_), Some(_)) => return Err(E::Journal),
    };
    Ok(Outcome {
        response,
        attempted_bytes,
        stage,
        failure,
        proposal_digest,
        proposal_refusal_reason,
    })
}

fn reserve_slot(current: usize) -> Result<(), SourceEnrichmentError> {
    current
        .checked_add(1)
        .and_then(|count| count.checked_mul(256))
        .filter(|bytes| *bytes <= MAX_TOTAL_RECEIPT_BYTES)
        .ok_or(SourceEnrichmentError::Limit)
        .map(|_| ())
}

#[cfg(test)]
mod tests;
