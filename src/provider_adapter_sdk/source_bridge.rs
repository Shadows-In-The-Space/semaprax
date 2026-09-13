//! Offline SDK bridge for the ordinary source `ProposalSource` seam.
//!
//! This adapter intentionally exposes no checkpoint policy. A checkpointed
//! source needs a host-bound request/prompt identity before its durable intent
//! is appended; that identity is not carried by the SDK ABI yet.

use crate::agent_lifecycle::iterative::driver::{ProposalRequest, ProposalSource};
use crate::agent_proposal::CompiledAgentProposalSchema;
use crate::agent_runtime::AgentCancellation;
use crate::agent_runtime_v2::{
    SourceModelBinding, SourceModelEvidence, SourceModelInvocationCapability,
};
use crate::diagnostic::{quote_json, Diagnostic};
use crate::live_invocation::InvocationClock;
use crate::streaming_proposal_decode::{
    SourceProposalStreamDecoder, SourcePushOutcome, MAX_STREAM_BYTES,
};

use super::adapter::{
    AdapterEvent, AdapterInvocationCapability, AdapterPoll, AdapterRequest, ProviderAdapter,
};
use super::capability::{negotiate, RequiredCapabilities, StructuredOutputMode};

const MAX_SOURCE_POLLS: usize = 10_000;

/// Constructs exactly one fresh adapter per source attempt. Reusing an
/// already-settled adapter would violate `ProviderAdapter::start`'s one-start
/// contract, so the factory is explicit rather than hidden inside the source.
pub trait SourceAdapterFactory {
    fn create(&mut self) -> Box<dyn ProviderAdapter>;
}

impl<F> SourceAdapterFactory for F
where
    F: FnMut() -> Box<dyn ProviderAdapter>,
{
    fn create(&mut self) -> Box<dyn ProviderAdapter> {
        self()
    }
}

pub struct StreamingSourceProposalAdapter<'a> {
    factory: &'a mut dyn SourceAdapterFactory,
    capability: AdapterInvocationCapability,
    schema: &'a CompiledAgentProposalSchema,
    cancellation: Option<&'a AgentCancellation>,
    clock: Option<&'a dyn InvocationClock>,
    deadline_millis: Option<i64>,
    binding: Option<SourceModelBinding>,
    binding_capability: Option<SourceModelInvocationCapability>,
    evidence: SourceModelEvidence,
}

impl<'a> StreamingSourceProposalAdapter<'a> {
    #[must_use]
    pub fn new(
        factory: &'a mut dyn SourceAdapterFactory,
        capability: AdapterInvocationCapability,
        schema: &'a CompiledAgentProposalSchema,
    ) -> Self {
        Self {
            factory,
            capability,
            schema,
            cancellation: None,
            clock: None,
            deadline_millis: None,
            binding: None,
            binding_capability: None,
            evidence: SourceModelEvidence::default(),
        }
    }

    /// Constructs the additive Direct Runtime v2 bound source route. The
    /// existing constructor remains the compatibility route; this one refuses
    /// schema/revision or capability drift before a factory can be called.
    pub fn new_bound(
        factory: &'a mut dyn SourceAdapterFactory,
        capability: AdapterInvocationCapability,
        schema: &'a CompiledAgentProposalSchema,
        binding: SourceModelBinding,
        binding_capability: SourceModelInvocationCapability,
    ) -> Result<Self, Vec<Diagnostic>> {
        if schema.schema().digest() != binding.proposal_schema_digest()
            || schema.source_revision() != binding.source_revision()
            || !binding.capability_matches(&binding_capability)
        {
            return Err(Self::refusal("source.model_binding"));
        }
        Ok(Self {
            factory,
            capability,
            schema,
            cancellation: None,
            clock: None,
            deadline_millis: None,
            binding: Some(binding),
            binding_capability: Some(binding_capability),
            evidence: SourceModelEvidence::default(),
        })
    }

    /// Checks that this adapter is still attached to the exact runtime
    /// binding. It performs no host operation and exposes no adapter.
    pub fn validate_model_binding(
        &self,
        binding: &SourceModelBinding,
    ) -> Result<(), Vec<Diagnostic>> {
        if self.binding.as_ref() != Some(binding)
            || self
                .binding_capability
                .as_ref()
                .is_none_or(|value| !binding.capability_matches(value))
            || self.schema.schema().digest() != binding.proposal_schema_digest()
            || self.schema.source_revision() != binding.source_revision()
        {
            return Err(Self::refusal("source.model_binding"));
        }
        Ok(())
    }

    /// Returns only bounded digests, lengths, closed terminal tags and usage
    /// observations. Prompt and response bytes are never retained here.
    #[must_use]
    pub fn model_evidence(&self) -> &SourceModelEvidence {
        &self.evidence
    }

    /// Exposes only the checked binding facts needed by the consuming Direct
    /// Runtime producer to reject cross-runtime substitution before dispatch.
    #[must_use]
    pub fn model_binding(&self) -> Option<&SourceModelBinding> {
        self.binding.as_ref()
    }
    #[must_use]
    pub fn with_cancellation(mut self, cancellation: &'a AgentCancellation) -> Self {
        self.cancellation = Some(cancellation);
        self
    }
    #[must_use]
    pub fn with_cancellation_and_deadline(
        mut self,
        cancellation: &'a AgentCancellation,
        clock: &'a dyn InvocationClock,
        deadline_millis: i64,
    ) -> Self {
        self.cancellation = Some(cancellation);
        self.clock = Some(clock);
        self.deadline_millis = Some(deadline_millis);
        self
    }
    fn refusal(code: &'static str) -> Vec<Diagnostic> {
        vec![Diagnostic::io(
            code,
            "provider adapter source proposal refused",
        )]
    }

    fn record(
        &mut self,
        request: &[u8],
        response: Option<&[u8]>,
        terminal: &str,
        tokens_in: Option<u64>,
        tokens_out: Option<u64>,
        cost_micros: Option<i64>,
    ) {
        if self.binding.is_some() {
            self.evidence.record(
                request,
                response,
                terminal,
                tokens_in,
                tokens_out,
                cost_micros,
            );
        }
    }
}

impl ProposalSource for StreamingSourceProposalAdapter<'_> {
    fn check_deadline(&self) -> Result<(), Vec<Diagnostic>> {
        if self.cancellation.is_some_and(|value| value.is_cancelled()) {
            return Err(Self::refusal("source.adapter_cancelled"));
        }
        if self
            .clock
            .zip(self.deadline_millis)
            .is_some_and(|(clock, deadline)| clock.now_millis() >= deadline)
        {
            return Err(Self::refusal("source.adapter_timeout"));
        }
        Ok(())
    }
    fn propose(&mut self, request: ProposalRequest<'_>) -> Result<String, Vec<Diagnostic>> {
        self.check_deadline()?;
        if request.proposal_schema_digest != self.schema.schema().digest()
            || request.source_revision != self.schema.source_revision()
        {
            return Err(Self::refusal("source.adapter_schema_drift"));
        }
        let max_request_bytes = self
            .binding
            .as_ref()
            .map_or(MAX_STREAM_BYTES, SourceModelBinding::max_request_bytes);
        let max_response_bytes = self
            .binding
            .as_ref()
            .map_or(MAX_STREAM_BYTES, SourceModelBinding::max_response_bytes);
        let schema = self.schema.schema().canonical_json();
        if schema.len() > max_request_bytes || request.task.objective.len() > max_request_bytes {
            return Err(Self::refusal("source.adapter_request_bound"));
        }
        if request
            .previous_effect
            .is_some_and(|bytes| bytes.len() > MAX_STREAM_BYTES)
            || request
                .previous_rejection
                .is_some_and(|text| text.len() > MAX_STREAM_BYTES)
            || !bounded_retained(request.state)
            || !bounded_retained(request.observation)
        {
            return Err(Self::refusal("source.adapter_request_bound"));
        }
        let prompt = format!("{{\"schema\":\"semaprax.source-adapter-prompt.v1\",\"task_hex\":{},\"task_budget\":{},\"source_revision\":{},\"turn\":{},\"attempt\":{},\"remaining_iterations\":{},\"state\":{},\"observation\":{},\"previous_effect_hex\":{},\"previous_rejection\":{},\"proposal_schema\":{}}}", quote_json(&hex(&request.task.objective)), request.task.budget, quote_json(request.source_revision), request.turn, request.attempt, request.remaining_iterations, crate::agent_lifecycle::canonical_retained_value_json(request.state), crate::agent_lifecycle::canonical_retained_value_json(request.observation), request.previous_effect.map(hex).map_or_else(|| "null".to_owned(), |value| quote_json(&value)), request.previous_rejection.map_or_else(|| "null".to_owned(), quote_json), schema);
        if prompt.len() > max_request_bytes {
            return Err(Self::refusal("source.adapter_request_bound"));
        }
        self.check_deadline()?;
        if self.binding.is_some() && !self.evidence.can_record() {
            return Err(Self::refusal("source.model_evidence_capacity"));
        }
        let mut adapter = self.factory.create();
        let adapter_request = AdapterRequest {
            request_bytes: prompt.into_bytes(),
            max_response_bytes,
        };
        if self
            .binding
            .as_ref()
            .is_some_and(|binding| !binding.adapter_matches(adapter.capabilities()))
        {
            self.record(
                &adapter_request.request_bytes,
                None,
                "adapter_identity_refused",
                None,
                None,
                None,
            );
            return Err(Self::refusal("source.model_adapter_identity"));
        }
        let required = RequiredCapabilities {
            require_streaming: true,
            require_structured_output_mode: Some(StructuredOutputMode::RawText),
            max_request_bytes: adapter_request.request_bytes.len(),
            max_response_bytes,
        };
        if negotiate(adapter.capabilities(), &required).is_err() {
            self.record(
                &adapter_request.request_bytes,
                None,
                "adapter_negotiation_refused",
                None,
                None,
                None,
            );
            return Err(Self::refusal("source.adapter_negotiation"));
        }
        self.check_deadline()?;
        if adapter.start(&self.capability, &adapter_request).is_err() {
            adapter.cancel("source start refusal");
            self.record(
                &adapter_request.request_bytes,
                None,
                "adapter_start_refused",
                None,
                None,
                None,
            );
            return Err(Self::refusal("source.adapter_negotiation"));
        }
        let mut decoder = SourceProposalStreamDecoder::new(self.schema);
        let mut bytes = Vec::new();
        let mut completed = false;
        let mut usage: Option<(u64, u64, i64)> = None;
        for _ in 0..MAX_SOURCE_POLLS {
            if let Err(diagnostics) = self.check_deadline() {
                adapter.cancel("source cancellation or deadline");
                self.record(
                    &adapter_request.request_bytes,
                    Some(&bytes),
                    "cancelled_or_timed_out",
                    usage.map(|value| value.0),
                    usage.map(|value| value.1),
                    usage.map(|value| value.2),
                );
                return Err(diagnostics);
            }
            match adapter.poll() {
                AdapterPoll::Pending => continue,
                AdapterPoll::Event(AdapterEvent::Delta(chunk)) => {
                    if completed || bytes.len().saturating_add(chunk.len()) > max_response_bytes {
                        adapter.cancel("source stream bound");
                        self.record(
                            &adapter_request.request_bytes,
                            Some(&bytes),
                            "stream_refused",
                            usage.map(|value| value.0),
                            usage.map(|value| value.1),
                            usage.map(|value| value.2),
                        );
                        return Err(Self::refusal("source.adapter_stream"));
                    }
                    bytes.extend_from_slice(&chunk);
                    if matches!(decoder.push(&chunk), SourcePushOutcome::Refused(_)) {
                        adapter.cancel("source decoder refusal");
                        self.record(
                            &adapter_request.request_bytes,
                            Some(&bytes),
                            "decode_refused",
                            usage.map(|value| value.0),
                            usage.map(|value| value.1),
                            usage.map(|value| value.2),
                        );
                        return Err(Self::refusal("source.adapter_decode"));
                    }
                }
                AdapterPoll::Event(AdapterEvent::Completed) => {
                    if completed {
                        adapter.cancel("duplicate completion");
                        self.record(
                            &adapter_request.request_bytes,
                            Some(&bytes),
                            "stream_refused",
                            usage.map(|value| value.0),
                            usage.map(|value| value.1),
                            usage.map(|value| value.2),
                        );
                        return Err(Self::refusal("source.adapter_stream"));
                    }
                    completed = true;
                }
                AdapterPoll::Event(AdapterEvent::Usage {
                    tokens_in,
                    tokens_out,
                    cost_micros,
                }) => {
                    if completed
                        || cost_micros < 0
                        || usage.is_some_and(|prior| {
                            tokens_in < prior.0 || tokens_out < prior.1 || cost_micros < prior.2
                        })
                    {
                        adapter.cancel("invalid usage");
                        self.record(
                            &adapter_request.request_bytes,
                            Some(&bytes),
                            "usage_refused",
                            usage.map(|value| value.0),
                            usage.map(|value| value.1),
                            usage.map(|value| value.2),
                        );
                        return Err(Self::refusal("source.adapter_usage"));
                    }
                    usage = Some((tokens_in, tokens_out, cost_micros));
                }
                AdapterPoll::Settled(settlement) => {
                    if let Err(diagnostics) = self.check_deadline() {
                        adapter.cancel("source cancellation or deadline at settlement");
                        self.record(
                            &adapter_request.request_bytes,
                            Some(&bytes),
                            "cancelled_or_timed_out",
                            settlement.usage.tokens_in,
                            settlement.usage.tokens_out,
                            settlement.usage.cost_micros,
                        );
                        return Err(diagnostics);
                    }
                    if !completed
                        || settlement.response_bytes != bytes
                        || settlement.usage.cost_micros.is_some_and(|cost| cost < 0)
                        || usage.is_some_and(|prior| {
                            settlement.usage.tokens_in.is_some_and(|v| v < prior.0)
                                || settlement.usage.tokens_out.is_some_and(|v| v < prior.1)
                                || settlement.usage.cost_micros.is_some_and(|v| v < prior.2)
                        })
                    {
                        adapter.cancel("settlement mismatch");
                        self.record(
                            &adapter_request.request_bytes,
                            Some(&bytes),
                            "settlement_refused",
                            settlement.usage.tokens_in,
                            settlement.usage.tokens_out,
                            settlement.usage.cost_micros,
                        );
                        return Err(Self::refusal("source.adapter_stream"));
                    }
                    return match decoder.finish() {
                        SourcePushOutcome::Accepted(value) => {
                            self.record(
                                &adapter_request.request_bytes,
                                Some(&bytes),
                                "admitted",
                                settlement.usage.tokens_in,
                                settlement.usage.tokens_out,
                                settlement.usage.cost_micros,
                            );
                            Ok(value.canonical_json().to_owned())
                        }
                        _ => {
                            self.record(
                                &adapter_request.request_bytes,
                                Some(&bytes),
                                "decode_refused",
                                settlement.usage.tokens_in,
                                settlement.usage.tokens_out,
                                settlement.usage.cost_micros,
                            );
                            Err(Self::refusal("source.adapter_decode"))
                        }
                    };
                }
                AdapterPoll::Failed {
                    failure,
                    attempted_bytes: _,
                } => {
                    adapter.cancel("source adapter failed");
                    self.record(
                        &adapter_request.request_bytes,
                        Some(&bytes),
                        failure.as_str(),
                        usage.map(|value| value.0),
                        usage.map(|value| value.1),
                        usage.map(|value| value.2),
                    );
                    return Err(Self::refusal("source.adapter_failed"));
                }
            }
        }
        adapter.cancel("source adapter poll budget");
        self.record(
            &adapter_request.request_bytes,
            Some(&bytes),
            "poll_budget_exhausted",
            usage.map(|value| value.0),
            usage.map(|value| value.1),
            usage.map(|value| value.2),
        );
        Err(Self::refusal("source.adapter_timeout"))
    }
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        output.push(DIGITS[usize::from(byte >> 4)] as char);
        output.push(DIGITS[usize::from(byte & 15)] as char);
    }
    output
}

// Refuse hostile host-constructed carriers before the recursive canonical
// renderer allocates. This is a conservative byte upper bound, not a second
// retained-value serializer; the lifecycle renderer still owns exact bytes.
fn bounded_retained(value: &crate::interpreter::retained_call::RetainedValue) -> bool {
    use crate::interpreter::retained_call::RetainedValue;
    fn visit(value: &RetainedValue, depth: usize, remaining: &mut usize) -> bool {
        if depth > 64 {
            return false;
        }
        let (overhead, fields) = match value {
            RetainedValue::Bytes(bytes) => (bytes.len().saturating_mul(2).saturating_add(16), None),
            RetainedValue::Record(record) => (
                record
                    .record
                    .as_str()
                    .len()
                    .saturating_mul(6)
                    .saturating_add(32),
                Some(record.fields.as_slice()),
            ),
            RetainedValue::Variant(variant) => (
                variant
                    .variant
                    .as_str()
                    .len()
                    .saturating_add(variant.case.as_str().len())
                    .saturating_mul(6)
                    .saturating_add(48),
                Some(variant.fields.as_slice()),
            ),
            _ => (24, None),
        };
        let Some(left) = remaining.checked_sub(overhead) else {
            return false;
        };
        *remaining = left;
        if let Some(fields) = fields {
            for field in fields {
                let Some(left) = remaining.checked_sub(
                    field
                        .field
                        .as_str()
                        .len()
                        .saturating_mul(6)
                        .saturating_add(32),
                ) else {
                    return false;
                };
                *remaining = left;
                if !visit(&field.value, depth + 1, remaining) {
                    return false;
                }
            }
        }
        true
    }
    let mut remaining = MAX_STREAM_BYTES;
    visit(value, 0, &mut remaining)
}

#[cfg(test)]
mod tests;
