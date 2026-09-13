//! Streaming adapter implementation of the generic `ModelHandler` seam.

use crate::agent_interaction_schema::CompiledInteractionSchema;
use crate::agent_runtime::AgentCancellation;
use crate::diagnostic::quote_json;
use crate::live_invocation::budget::InvocationClock;
use crate::live_invocation::model_invoke::{
    ModelFailure, ModelHandler, ModelInvocationOutcome, ModelInvocationRequest,
    ModelInvokeCapability,
};
use crate::streaming_proposal_decode::{ProposalStreamDecoder, PushOutcome};

use super::adapter::{
    AdapterEvent, AdapterInvocationCapability, AdapterPoll, AdapterRequest, ProviderAdapter,
};
use super::capability::{negotiate, RequiredCapabilities, StructuredOutputMode};

const MAX_BRIDGE_POLLS: usize = 10_000;
const MAX_BRIDGE_INPUT_BYTES: usize = 65_536;
const MAX_BRIDGE_SCHEMA_BYTES: usize = 262_144;

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        output.push(DIGITS[usize::from(byte >> 4)] as char);
        output.push(DIGITS[usize::from(byte & 0x0f)] as char);
    }
    output
}

/// The exact request projection shared by live dispatch and receipt replay.
/// Callers validate the logical request and schema bounds before constructing it.
pub(crate) fn adapter_request_for(
    request: &ModelInvocationRequest,
    provider_schema: &str,
) -> AdapterRequest {
    // Hex preserves arbitrary task/observation bytes without lossy UTF-8.
    let prompt = format!(
        "{{\"task_hex\":{},\"observation_hex\":{},\"proposal_schema\":{}}}",
        quote_json(&hex(&request.task)),
        quote_json(&hex(&request.observation)),
        provider_schema,
    );
    AdapterRequest {
        request_bytes: prompt.into_bytes(),
        max_response_bytes: request
            .max_response_bytes
            .min(crate::streaming_proposal_decode::MAX_STREAM_BYTES),
    }
}

/// A provider-neutral, bounded streaming transport bridge. The adapter is
/// negotiated before `start`; each `Delta` is validated before another poll;
/// and an early decode refusal requests cancellation and returns immediately.
pub struct StreamingModelHandler<'a> {
    adapter: &'a mut dyn ProviderAdapter,
    adapter_capability: AdapterInvocationCapability,
    schema: &'a CompiledInteractionSchema,
    cancellation: Option<&'a AgentCancellation>,
    clock: Option<&'a dyn InvocationClock>,
    deadline_millis: Option<i64>,
}

impl<'a> StreamingModelHandler<'a> {
    #[must_use]
    pub fn new(
        adapter: &'a mut dyn ProviderAdapter,
        adapter_capability: AdapterInvocationCapability,
        schema: &'a CompiledInteractionSchema,
    ) -> Self {
        Self {
            adapter,
            adapter_capability,
            schema,
            cancellation: None,
            clock: None,
            deadline_millis: None,
        }
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

    fn refuse(&mut self, bytes: usize, reason: &str) -> ModelInvocationOutcome {
        self.adapter.cancel(reason);
        ModelInvocationOutcome::Failed {
            failure: ModelFailure::MalformedResponse,
            attempted_bytes: bytes,
        }
    }
}

impl ModelHandler for StreamingModelHandler<'_> {
    fn invoke(
        &mut self,
        _: &ModelInvokeCapability,
        request: &ModelInvocationRequest,
    ) -> ModelInvocationOutcome {
        if request.proposal_grammar_digest != self.schema.schema().digest() {
            return ModelInvocationOutcome::Failed {
                failure: ModelFailure::Refused,
                attempted_bytes: 0,
            };
        }
        if request.task.len().saturating_add(request.observation.len()) > MAX_BRIDGE_INPUT_BYTES {
            return ModelInvocationOutcome::Failed {
                failure: ModelFailure::Refused,
                attempted_bytes: 0,
            };
        }
        let provider_schema = self.schema.provider_json_schema();
        if provider_schema.len() > MAX_BRIDGE_SCHEMA_BYTES {
            return ModelInvocationOutcome::Failed {
                failure: ModelFailure::Refused,
                attempted_bytes: 0,
            };
        }
        if self
            .cancellation
            .is_some_and(|cancellation| cancellation.is_cancelled())
        {
            return ModelInvocationOutcome::Failed {
                failure: ModelFailure::Cancelled,
                attempted_bytes: 0,
            };
        }
        if self
            .clock
            .zip(self.deadline_millis)
            .is_some_and(|(clock, deadline)| clock.now_millis() >= deadline)
        {
            return ModelInvocationOutcome::Failed {
                failure: ModelFailure::Timeout,
                attempted_bytes: 0,
            };
        }
        let adapter_request = adapter_request_for(request, &provider_schema);
        let response_cap = adapter_request.max_response_bytes;
        let required = RequiredCapabilities {
            require_streaming: true,
            require_structured_output_mode: Some(StructuredOutputMode::RawText),
            max_request_bytes: adapter_request.request_bytes.len(),
            max_response_bytes: adapter_request.max_response_bytes,
        };
        if negotiate(self.adapter.capabilities(), &required).is_err()
            || self
                .adapter
                .start(&self.adapter_capability, &adapter_request)
                .is_err()
        {
            return ModelInvocationOutcome::Failed {
                failure: ModelFailure::Refused,
                attempted_bytes: 0,
            };
        }

        let mut decoder = ProposalStreamDecoder::new(self.schema);
        let mut bytes = Vec::new();
        let mut completed = false;
        let mut usage = None;
        for _ in 0..MAX_BRIDGE_POLLS {
            if self
                .cancellation
                .is_some_and(|cancellation| cancellation.is_cancelled())
            {
                self.adapter.cancel("bridge cancellation");
                return ModelInvocationOutcome::Failed {
                    failure: ModelFailure::Cancelled,
                    attempted_bytes: bytes.len(),
                };
            }
            if self
                .clock
                .zip(self.deadline_millis)
                .is_some_and(|(clock, deadline)| clock.now_millis() >= deadline)
            {
                self.adapter.cancel("bridge deadline exceeded");
                return ModelInvocationOutcome::Failed {
                    failure: ModelFailure::Timeout,
                    attempted_bytes: bytes.len(),
                };
            }
            match self.adapter.poll() {
                AdapterPoll::Pending => continue,
                AdapterPoll::Event(AdapterEvent::Delta(chunk)) => {
                    if completed || bytes.len().saturating_add(chunk.len()) > response_cap {
                        return self.refuse(bytes.len(), "invalid adapter delta");
                    }
                    bytes.extend_from_slice(&chunk);
                    if matches!(decoder.push(&chunk), PushOutcome::Refused(_)) {
                        return self.refuse(bytes.len(), "stream decoder refused delta");
                    }
                }
                AdapterPoll::Event(AdapterEvent::Usage {
                    tokens_in,
                    tokens_out,
                    cost_micros,
                }) => {
                    if completed
                        || cost_micros < 0
                        || usage.is_some_and(|prior: (u64, u64, i64)| {
                            tokens_in < prior.0 || tokens_out < prior.1 || cost_micros < prior.2
                        })
                    {
                        return self.refuse(bytes.len(), "invalid adapter usage");
                    }
                    usage = Some((tokens_in, tokens_out, cost_micros));
                }
                AdapterPoll::Event(AdapterEvent::Completed) => {
                    if completed {
                        return self.refuse(bytes.len(), "duplicate adapter completion");
                    }
                    completed = true;
                }
                AdapterPoll::Settled(settlement) => {
                    // Poll may block or signal cancellation while returning completion.
                    // Recheck before publishing a locally accepted response.
                    if self.cancellation.is_some_and(|value| value.is_cancelled()) {
                        self.adapter.cancel("bridge cancellation at settlement");
                        return ModelInvocationOutcome::Failed {
                            failure: ModelFailure::Cancelled,
                            attempted_bytes: bytes.len(),
                        };
                    }
                    if self
                        .clock
                        .zip(self.deadline_millis)
                        .is_some_and(|(clock, deadline)| clock.now_millis() >= deadline)
                    {
                        self.adapter.cancel("bridge deadline at settlement");
                        return ModelInvocationOutcome::Failed {
                            failure: ModelFailure::Timeout,
                            attempted_bytes: bytes.len(),
                        };
                    }
                    if !completed || settlement.response_bytes != bytes {
                        return self
                            .refuse(bytes.len(), "adapter settlement disagreed with stream");
                    }
                    if settlement.usage.cost_micros.is_some_and(|cost| cost < 0)
                        || usage.is_some_and(|prior: (u64, u64, i64)| {
                            settlement
                                .usage
                                .tokens_in
                                .is_some_and(|value| value < prior.0)
                                || settlement
                                    .usage
                                    .tokens_out
                                    .is_some_and(|value| value < prior.1)
                                || settlement
                                    .usage
                                    .cost_micros
                                    .is_some_and(|value| value < prior.2)
                        })
                    {
                        return self.refuse(bytes.len(), "adapter settlement usage regressed");
                    }
                    return match decoder.finish() {
                        PushOutcome::Accepted(value) => ModelInvocationOutcome::Settled(
                            value.canonical_json().as_bytes().to_vec(),
                        ),
                        PushOutcome::Refused(_) | PushOutcome::Incomplete => {
                            self.refuse(bytes.len(), "stream decoder refused completed response")
                        }
                    };
                }
                AdapterPoll::Failed {
                    failure,
                    attempted_bytes,
                } => {
                    return ModelInvocationOutcome::Failed {
                        failure,
                        attempted_bytes: attempted_bytes.min(request.max_response_bytes),
                    }
                }
            }
        }
        self.adapter.cancel("adapter poll budget exceeded");
        ModelInvocationOutcome::Failed {
            failure: ModelFailure::Timeout,
            attempted_bytes: bytes.len(),
        }
    }
}

#[cfg(test)]
mod tests;
