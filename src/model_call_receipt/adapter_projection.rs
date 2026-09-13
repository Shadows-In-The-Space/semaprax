//! Schema-checked binding of a settled adapter transcript to its live journal.
//! This additive evidence does not invent billing, timing, or root metadata.
use super::journal_projection::project_kernel_calls;
use crate::agent_interaction_schema::CompiledInteractionSchema;
use crate::live_invocation::{
    identity::{digest, LiveInvocationId, LiveInvocationSeed},
    journal::JournalEntry,
    model_invoke::ModelInvocationRequest,
};
use crate::provider_adapter_sdk::{
    bridge::adapter_request_for,
    observation::{AttemptObservation, ReplayInputs},
};

pub const ADAPTER_CALL_SCHEMA: &str = "semaprax.model-call-adapter-evidence.v1";

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AdapterProjectionError {
    Limit,
    Binding,
    Journal,
    Transcript,
    Schema,
    Mismatch,
}

/// Opaque evidence derived from independently retained inputs. No authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdapterCallEvidence {
    canonical: String,
}
impl AdapterCallEvidence {
    pub fn render(&self) -> &str {
        &self.canonical
    }
    pub fn digest(&self) -> String {
        crate::audit_capsule::sha256_digest(self.canonical.as_bytes())
    }
}

/// Bind a successfully decoded transport settlement to a generic live attempt.
/// Provider profile must be one of the seed's explicitly approved identities.
/// Failed/pre-dispatch attempts continue to use the journal projection; this
/// function deliberately requires a retained settlement and response record.
pub fn project_settled_adapter_call(
    entries: &[JournalEntry],
    seed: &LiveInvocationSeed,
    request: &ModelInvocationRequest,
    schema: &CompiledInteractionSchema,
    observation: &AttemptObservation,
    retained: &ReplayInputs<'_>,
) -> Result<AdapterCallEvidence, AdapterProjectionError> {
    use AdapterProjectionError as E;
    if seed.approved_providers.len() > 1024 {
        return Err(E::Limit);
    }
    let seed_size = seed
        .approved_providers
        .iter()
        .try_fold(
            seed.program_root
                .len()
                .saturating_add(seed.deployment_policy.len())
                .saturating_add(seed.task.len())
                .saturating_add(seed.interaction_schema_digest.len()),
            |sum, p| sum.checked_add(p.len()),
        )
        .ok_or(E::Limit)?;
    if seed_size > 262_144
        || seed.approved_providers.len() > 1024
        || request.task.len().saturating_add(request.observation.len()) > 65_536
        || request.proposal_grammar_digest.len() > 128
        || request.deployment_binding.len() > 262_144
    {
        return Err(E::Limit);
    }
    if seed.task != request.task
        || seed.deployment_policy != request.deployment_binding
        || seed.interaction_schema_digest != schema.schema().digest()
        || request.proposal_grammar_digest != schema.schema().digest()
        || retained.compiled_grammar_digest != schema.schema().digest()
        || !seed
            .approved_providers
            .iter()
            .any(|p| p == observation.capabilities().provider_profile())
    {
        return Err(E::Binding);
    }
    let provider_schema = schema.provider_json_schema();
    if provider_schema.len() > 262_144 {
        return Err(E::Limit);
    }
    let transport = adapter_request_for(request, &provider_schema);
    if transport.request_bytes != retained.request.request_bytes
        || transport.max_response_bytes != retained.request.max_response_bytes
    {
        return Err(E::Binding);
    }
    observation.replay(retained).map_err(|_| E::Transcript)?;
    let settlement = retained.settlement.ok_or(E::Transcript)?;
    let decoded = schema
        .decode(&settlement.response_bytes)
        .map_err(|_| E::Schema)?;
    let identity = LiveInvocationId::derive(seed);
    let calls = project_kernel_calls(entries, &identity).map_err(|_| E::Journal)?;
    let call = calls
        .iter()
        .find(|c| c.turn() == request.turn)
        .ok_or(E::Journal)?;
    if call.value["request_digest"].as_str() != Some(request.digest().as_str())
        || call.value["reserved_units"].as_i64() != Some(request.effective_budget)
        || call.value["observation_digest"].as_str()
            != Some(
                digest(
                    b"semaprax.live-invocation.observation.v1\0",
                    &request.observation,
                )
                .as_str(),
            )
    {
        return Err(E::Binding);
    }
    let response = entries
        .iter()
        .find_map(|entry| match entry {
            JournalEntry::ResponseRecorded { turn, response, .. } if *turn == request.turn => {
                Some(response)
            }
            _ => None,
        })
        .ok_or(E::Journal)?;
    if response.as_slice() != decoded.canonical_json().as_bytes() {
        return Err(E::Binding);
    }
    if let Some(proposal) = call.value["proposal_digest"].as_str() {
        if proposal != digest(b"semaprax.live-invocation.proposal.v1\0", response) {
            return Err(E::Binding);
        }
    }
    let canonical = serde_json::json!({
        "schema": ADAPTER_CALL_SCHEMA,
        "journal_receipt_digest": call.digest(),
        "adapter_observation_digest": observation.digest(),
        "invocation_id": identity.digest(), "turn": request.turn, "attempt": call.attempt(),
        "program_root": seed.program_root, "deployment_policy": seed.deployment_policy,
        "proposal_grammar_digest": schema.schema().digest(),
        "request_digest": request.digest(),
        "transport_request_bytes": transport.request_bytes.len(),
        "transport_response_bytes": settlement.response_bytes.len(),
        "decoded_response_digest": digest(b"semaprax.live-invocation.response.v1\0", response),
    })
    .to_string()
        + "\n";
    if canonical.len() > 4096 {
        return Err(E::Limit);
    }
    Ok(AdapterCallEvidence { canonical })
}

/// Exact-byte replay against the original journal, compiled schema, and
/// retained transport events. This API has no provider dispatch capability.
pub fn replay_settled_adapter_call(
    submitted: &[u8],
    entries: &[JournalEntry],
    seed: &LiveInvocationSeed,
    request: &ModelInvocationRequest,
    schema: &CompiledInteractionSchema,
    observation: &AttemptObservation,
    retained: &ReplayInputs<'_>,
) -> Result<(), AdapterProjectionError> {
    if submitted.len() > 4096 {
        return Err(AdapterProjectionError::Limit);
    }
    let expected =
        project_settled_adapter_call(entries, seed, request, schema, observation, retained)?;
    if expected.render().as_bytes() != submitted {
        return Err(AdapterProjectionError::Mismatch);
    }
    Ok(())
}
