//! Rich receipts from actual generic-kernel journals and independently retained
//! host facts. Required v1 host fields are explicit inputs, never invented.
use super::{journal_projection::project_kernel_calls, receipt::*};
use crate::agent_interaction_schema::CompiledInteractionSchema;
use crate::live_invocation::{
    compiled_decoder::CompiledProposalDecoder,
    identity::{digest, LiveInvocationId, LiveInvocationSeed},
    journal::JournalEntry,
    model_invoke::{ModelInvocationRequest, ProposalDecoder, ProposalOutcome},
};

/// Host-owned facts retained before/around this attempt. Values use one
/// invocation clock domain. A missing timestamp is unknown, not zero.
pub struct GenericAttemptMetadata<'a> {
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

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EnrichmentError {
    Limit,
    Roots,
    Request,
    Journal,
    Decode,
    HostFacts,
    Mismatch,
}

/// Constructs the rich v1 receipt for any retained generic attempt: response,
/// refusal, failure, cancellation, or unresolved durable intent. Agent,
/// DeploymentRoot and InstanceRoot come from the host's independent binding;
/// ProgramRoot, policy, grammar and invocation additionally match the seed.
/// The exact retained logical request must match the journal commitment.
pub fn enrich_generic_call(
    entries: &[JournalEntry],
    seed: &LiveInvocationSeed,
    request: &ModelInvocationRequest,
    schema: &CompiledInteractionSchema,
    roots: &RootBindingContext<'_>,
    host: &GenericAttemptMetadata<'_>,
) -> Result<ModelCallReceipt, EnrichmentError> {
    use EnrichmentError as E;
    if seed.approved_providers.len() > 1024
        || seed.task.len() > 65_536
        || request.task.len().saturating_add(request.observation.len()) > 65_536
    {
        return Err(E::Limit);
    }
    for text in [
        seed.program_root.as_str(),
        &seed.deployment_policy,
        &seed.interaction_schema_digest,
        &request.proposal_grammar_digest,
        &request.deployment_binding,
        roots.agent_id,
        roots.program_root,
        roots.deployment_root,
        roots.instance_root,
        roots.invocation_id,
        roots.proposal_grammar_digest,
        roots.deployment_policy_digest,
        host.model_class,
        host.provider_class,
        host.adapter_identity,
        host.provider_call_reference,
    ]
    .into_iter()
    .chain(seed.approved_providers.iter().map(String::as_str))
    {
        if text.len() > 4096 {
            return Err(E::Limit);
        }
    }
    if let Some(usage) = host.provider_reported {
        if usage.provider_call_id.len() > 4096 {
            return Err(E::Limit);
        }
        if usage.provider_call_id != host.provider_call_reference || usage.provider_cost_micros < 0
        {
            return Err(E::HostFacts);
        }
    }
    let mut prior = host.reserved_at_ms;
    for now in [
        host.dispatched_at_ms,
        host.first_byte_at_ms,
        host.completed_at_ms,
    ]
    .into_iter()
    .flatten()
    {
        if now < prior {
            return Err(E::HostFacts);
        }
        prior = now;
    }
    if host.cost_estimate_micros < 0 {
        return Err(E::HostFacts);
    }
    let identity = LiveInvocationId::derive(seed);
    if roots.invocation_id != identity.digest()
        || roots.program_root != seed.program_root
        || roots.deployment_policy_digest != seed.deployment_policy
        || roots.proposal_grammar_digest != schema.schema().digest()
        || roots.previous_attempt != 0
        || seed.interaction_schema_digest != schema.schema().digest()
    {
        return Err(E::Roots);
    }
    if request.task != seed.task
        || request.deployment_binding != seed.deployment_policy
        || request.proposal_grammar_digest != schema.schema().digest()
        || !seed
            .approved_providers
            .iter()
            .any(|p| p == host.provider_class)
    {
        return Err(E::Request);
    }
    let projected = project_kernel_calls(entries, &identity).map_err(|_| E::Journal)?;
    let call = projected
        .iter()
        .find(|c| c.turn() == request.turn)
        .ok_or(E::Journal)?;
    if call.value["request_digest"].as_str() != Some(request.digest().as_str())
        || call.value["observation_digest"].as_str()
            != Some(
                digest(
                    b"semaprax.live-invocation.observation.v1\0",
                    &request.observation,
                )
                .as_str(),
            )
    {
        return Err(E::Request);
    }
    // A denied reservation records zero reserved units but commits to the
    // original requested budget. Preserve both facts rather than rewriting it.
    let reserved = call.value["reserved_units"].as_i64().ok_or(E::Journal)?;
    let mut response = None;
    let mut failure = None;
    let mut attempted_bytes = 0;
    let mut proposal = None;
    let mut refusal = None;
    let mut authorized = false;
    for entry in entries {
        match entry {
            JournalEntry::ResponseRecorded {
                turn,
                response: bytes,
                ..
            } if *turn == request.turn => response = Some(bytes.as_slice()),
            JournalEntry::ResponseFailed {
                turn,
                failure: reason,
                attempted_bytes: bytes,
            } if *turn == request.turn => {
                failure = Some(reason.as_str());
                attempted_bytes = *bytes;
            }
            JournalEntry::ProposalAdmitted {
                turn,
                proposal_digest,
            } if *turn == request.turn => proposal = Some(proposal_digest.as_str()),
            JournalEntry::ProposalRefused { turn, reason } if *turn == request.turn => {
                refusal = Some(reason.as_str())
            }
            JournalEntry::AuthorizationConsumed { turn, .. } if *turn == request.turn => {
                authorized = true
            }
            _ => {}
        }
    }
    if reserved != request.effective_budget
        && !(reserved == 0 && failure.is_some() && host.dispatched_at_ms.is_none())
    {
        return Err(E::Request);
    }
    let mut proposal_digest = None;
    let mut proposal_refusal_reason = None;
    if proposal.is_some() || refusal.is_some() {
        let response = response.ok_or(E::Journal)?;
        let mut decoder = CompiledProposalDecoder::new(schema);
        match decoder.decode(request.turn, response) {
            ProposalOutcome::Admitted(bytes) => {
                if proposal
                    != Some(digest(b"semaprax.live-invocation.proposal.v1\0", &bytes).as_str())
                    || refusal.is_some()
                {
                    return Err(E::Decode);
                }
                proposal_digest = Some(commit_proposal_bytes(&bytes));
            }
            ProposalOutcome::Refused(reason) => {
                if refusal != Some(reason.as_str()) || proposal.is_some() {
                    return Err(E::Decode);
                }
                proposal_refusal_reason = Some(reason);
            }
        }
    }
    let stage = if authorized {
        ReceiptStage::Accepted
    } else if proposal.is_some() {
        ReceiptStage::Decoded
    } else if refusal.is_some() {
        ReceiptStage::Rejected
    } else if response.is_some() {
        ReceiptStage::Completed
    } else if failure == Some("cancelled") {
        ReceiptStage::Cancelled
    } else if failure.is_some() {
        if host.dispatched_at_ms.is_some() {
            ReceiptStage::Dispatched
        } else {
            ReceiptStage::IntentPersisted
        }
    } else {
        ReceiptStage::Uncertain
    };
    let receipt = ModelCallReceipt {
        agent_id: roots.agent_id.into(),
        program_root: roots.program_root.into(),
        deployment_root: roots.deployment_root.into(),
        instance_root: roots.instance_root.into(),
        invocation_id: identity.digest().into(),
        turn: request.turn,
        attempt: 1,
        model_class: host.model_class.into(),
        provider_class: host.provider_class.into(),
        adapter_identity: host.adapter_identity.into(),
        proposal_grammar_digest: schema.schema().digest().into(),
        deployment_policy_digest: seed.deployment_policy.clone(),
        task_digest: commit_task_bytes(&request.task),
        observation_digest: commit_observation_bytes(&request.observation),
        request_digest: request.digest(),
        request_bytes_len: request.canonical_json().len(),
        reserved_budget: reserved,
        response_digest: response.map(commit_response_bytes),
        response_bytes_len: response.map(<[u8]>::len),
        private_payload_reference: None,
        terminal_stage: stage,
        failure: failure.map(str::to_owned),
        proposal_digest,
        proposal_refusal_reason,
        reserved_at_ms: host.reserved_at_ms,
        dispatched_at_ms: host.dispatched_at_ms,
        first_byte_at_ms: host.first_byte_at_ms,
        completed_at_ms: host.completed_at_ms,
        local_request_bytes: request.task.len() + request.observation.len(),
        local_response_bytes: response.map_or(attempted_bytes, <[u8]>::len),
        cost_estimate_micros: host.cost_estimate_micros,
        provider_call_reference: host.provider_call_reference.into(),
        provider_reported: host.provider_reported.cloned(),
    };
    verify_root_binding(&receipt, roots).map_err(|_| E::Roots)?;
    if receipt.render().len() > 65_536 {
        return Err(E::Limit);
    }
    Ok(receipt)
}

/// Independently reconstructs all fields from the original journal/request,
/// checked schema and host binding. Submitted receipts supply no replay inputs.
pub fn replay_generic_call(
    submitted: &[u8],
    entries: &[JournalEntry],
    seed: &LiveInvocationSeed,
    request: &ModelInvocationRequest,
    schema: &CompiledInteractionSchema,
    roots: &RootBindingContext<'_>,
    host: &GenericAttemptMetadata<'_>,
) -> Result<(), EnrichmentError> {
    if submitted.len() > 65_536 {
        return Err(EnrichmentError::Limit);
    }
    let expected = enrich_generic_call(entries, seed, request, schema, roots, host)?;
    if expected.render().as_bytes() != submitted {
        return Err(EnrichmentError::Mismatch);
    }
    Ok(())
}

/// Enriches a journal receipt with facts from the actual adapter decorator.
/// Logical request size remains distinct from transport byte accounting.
/// Partial/provider-unavailable usage stays absent in the complete-only v1
/// field and remains available in the separately retained observation.
pub fn enrich_observed_generic_call(
    entries: &[JournalEntry],
    seed: &LiveInvocationSeed,
    request: &ModelInvocationRequest,
    schema: &CompiledInteractionSchema,
    roots: &RootBindingContext<'_>,
    host: &GenericAttemptMetadata<'_>,
    observation: &crate::provider_adapter_sdk::AttemptObservation,
    retained: &crate::provider_adapter_sdk::ReplayInputs<'_>,
) -> Result<ModelCallReceipt, EnrichmentError> {
    use EnrichmentError as E;
    let mut receipt = enrich_generic_call(entries, seed, request, schema, roots, host)?;
    let provider_schema = schema.provider_json_schema();
    if provider_schema.len() > 262_144 {
        return Err(E::Limit);
    }
    let transport =
        crate::provider_adapter_sdk::bridge::adapter_request_for(request, &provider_schema);
    if transport.request_bytes != retained.request.request_bytes
        || transport.max_response_bytes != retained.request.max_response_bytes
        || retained.compiled_grammar_digest != schema.schema().digest()
        || observation.capabilities().adapter_identity() != host.adapter_identity
        || observation.capabilities().provider_profile() != host.provider_class
    {
        return Err(E::HostFacts);
    }
    observation.replay(retained).map_err(|_| E::HostFacts)?;
    if let Some(response) = &receipt.response_digest {
        let settlement = retained.settlement.ok_or(E::HostFacts)?;
        if *response != commit_response_bytes(&settlement.response_bytes) {
            return Err(E::HostFacts);
        }
    }
    for (recorded, supplied) in [
        (observation.observed_started_at_ms(), host.dispatched_at_ms),
        (observation.observed_finished_at_ms(), host.completed_at_ms),
    ] {
        if recorded.zip(supplied).is_some_and(|(a, b)| a != b) {
            return Err(E::HostFacts);
        }
    }
    let usage = super::observed_usage::complete_provider_reported_usage(
        observation,
        host.provider_call_reference,
    );
    if host.provider_reported.is_some() && host.provider_reported != usage.as_ref() {
        return Err(E::HostFacts);
    }
    receipt.provider_reported = usage;
    receipt.local_request_bytes = transport.request_bytes.len();
    receipt.dispatched_at_ms = observation
        .observed_started_at_ms()
        .or(host.dispatched_at_ms);
    receipt.completed_at_ms = observation
        .observed_finished_at_ms()
        .or(host.completed_at_ms);
    let mut prior = receipt.reserved_at_ms;
    for now in [
        receipt.dispatched_at_ms,
        receipt.first_byte_at_ms,
        receipt.completed_at_ms,
    ]
    .into_iter()
    .flatten()
    {
        if now < prior {
            return Err(E::HostFacts);
        }
        prior = now;
    }
    if receipt
        .provider_reported
        .as_ref()
        .is_some_and(|u| u.provider_cost_micros < 0)
    {
        return Err(E::HostFacts);
    }
    Ok(receipt)
}

/// Exact-byte replay including the independently retained adapter observation.
pub fn replay_observed_generic_call(
    submitted: &[u8],
    entries: &[JournalEntry],
    seed: &LiveInvocationSeed,
    request: &ModelInvocationRequest,
    schema: &CompiledInteractionSchema,
    roots: &RootBindingContext<'_>,
    host: &GenericAttemptMetadata<'_>,
    observation: &crate::provider_adapter_sdk::AttemptObservation,
    retained: &crate::provider_adapter_sdk::ReplayInputs<'_>,
) -> Result<(), EnrichmentError> {
    if submitted.len() > 65_536 {
        return Err(EnrichmentError::Limit);
    }
    let receipt = enrich_observed_generic_call(
        entries,
        seed,
        request,
        schema,
        roots,
        host,
        observation,
        retained,
    )?;
    if receipt.render().as_bytes() != submitted {
        return Err(EnrichmentError::Mismatch);
    }
    Ok(())
}
