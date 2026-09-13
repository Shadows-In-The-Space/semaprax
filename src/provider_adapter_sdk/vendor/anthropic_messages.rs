//! Anthropic Messages API streaming adapter over host-injected HTTP/SSE.
//!
//! The protocol emits `message_start`, ordered content-block events,
//! cumulative `message_delta.usage`, and `message_stop`. Only `text_delta`
//! bytes become proposal deltas. `tool_use`, `server_tool_use`, and
//! `input_json_delta` cause local cancellation plus a normalized refusal;
//! neither native nor server tools have an execution path from this module.

use std::collections::{BTreeSet, VecDeque};

use serde_json::{json, Value};

use crate::live_invocation::model_invoke::ModelFailure;
use crate::model_budget_policy::classification::AttemptOutcomeClass;

use super::super::adapter::{
    AdapterEvent, AdapterInvocationCapability, AdapterPoll, AdapterRefusal, AdapterRequest,
    AdapterSettlement, AdapterUsage, ProviderAdapter,
};
use super::super::capability::{
    AdapterCapabilities, CancellationSemantics, EndpointPolicy, StructuredOutputMode,
    TokenAccountingSource,
};
use super::transport::{
    HostHttpStream, HostHttpStreamTransport, ProviderHttpRequest, SseDecoder, TransportFailure,
    TransportFailureKind, TransportPoll,
};

const MAX_REQUEST_BYTES: usize = 65_536;
const MAX_RESPONSE_BYTES: usize = 262_144;

/// A Messages-protocol normalizer. `model` and `max_tokens` are host deployment
/// choices; the injected transport owns the API origin and `x-api-key` header.
pub struct AnthropicMessagesAdapter {
    capabilities: AdapterCapabilities,
    model: String,
    max_tokens: u64,
    transport: Box<dyn HostHttpStreamTransport>,
    stream: Option<Box<dyn HostHttpStream>>,
    decoder: SseDecoder,
    queued: VecDeque<AdapterPoll>,
    response: Vec<u8>,
    response_limit: usize,
    usage: AdapterUsage,
    terminal: Option<AdapterPoll>,
    outcome_class: Option<AttemptOutcomeClass>,
    completed: bool,
    message_started: bool,
    saw_final_stop_reason: bool,
    open_blocks: BTreeSet<u64>,
    text_blocks: BTreeSet<u64>,
    started: bool,
}

impl AnthropicMessagesAdapter {
    #[must_use]
    pub fn new(
        model: impl Into<String>,
        max_tokens: u64,
        transport: Box<dyn HostHttpStreamTransport>,
    ) -> Self {
        Self {
            capabilities: AdapterCapabilities {
                adapter_identity: "anthropic-messages-sse".into(),
                adapter_version: "1.0.0".into(),
                provider_profile: "anthropic-messages".into(),
                structured_output_modes: vec![StructuredOutputMode::RawText],
                supports_streaming: true,
                token_accounting_source: TokenAccountingSource::ProviderReported,
                cancellation_semantics: CancellationSemantics::BestEffortRequestStop,
                retryable_failure_classes: vec![
                    AttemptOutcomeClass::NotDispatched,
                    AttemptOutcomeClass::RejectedBeforeProcessing,
                    AttemptOutcomeClass::ProviderReportedRetryable,
                ],
                endpoint_policy: EndpointPolicy::HostInjected,
                max_request_bytes: MAX_REQUEST_BYTES,
                max_response_bytes: MAX_RESPONSE_BYTES,
                max_context_tokens: 200_000,
                max_output_tokens: max_tokens,
            },
            model: model.into(),
            max_tokens: max_tokens,
            transport,
            stream: None,
            decoder: SseDecoder::default(),
            queued: VecDeque::new(),
            response: Vec::new(),
            response_limit: 0,
            usage: unknown_usage(),
            terminal: None,
            outcome_class: None,
            completed: false,
            message_started: false,
            saw_final_stop_reason: false,
            open_blocks: BTreeSet::new(),
            text_blocks: BTreeSet::new(),
            started: false,
        }
    }

    #[must_use]
    pub fn attempt_outcome_class(&self) -> Option<AttemptOutcomeClass> {
        self.outcome_class
    }

    fn fail(&mut self, failure: ModelFailure, class: AttemptOutcomeClass) {
        self.fail_with_attempted(failure, class, self.response.len());
    }
    fn fail_with_attempted(
        &mut self,
        failure: ModelFailure,
        class: AttemptOutcomeClass,
        attempted_bytes: usize,
    ) {
        self.outcome_class = Some(class);
        self.queued.clear();
        self.terminal = Some(AdapterPoll::Failed {
            failure,
            attempted_bytes,
        });
    }

    fn handle_event(&mut self, bytes: Vec<u8>) {
        if self.completed {
            return self.fail(
                ModelFailure::MalformedResponse,
                AttemptOutcomeClass::Uncertain,
            );
        }
        let value: Value = match serde_json::from_slice(&bytes) {
            Ok(value) => value,
            Err(_) => {
                return self.fail(
                    ModelFailure::MalformedResponse,
                    AttemptOutcomeClass::Uncertain,
                )
            }
        };
        let Some(kind) = value.get("type").and_then(Value::as_str) else {
            return self.fail(
                ModelFailure::MalformedResponse,
                AttemptOutcomeClass::Uncertain,
            );
        };
        match kind {
            "message_start" => {
                if self.message_started {
                    return self.fail(
                        ModelFailure::MalformedResponse,
                        AttemptOutcomeClass::Uncertain,
                    );
                }
                self.message_started = true;
                self.update_usage(
                    value
                        .get("message")
                        .and_then(|message| message.get("usage")),
                    true,
                );
            }
            "content_block_start" => {
                let Some(index) = value.get("index").and_then(Value::as_u64) else {
                    return self.fail(
                        ModelFailure::MalformedResponse,
                        AttemptOutcomeClass::Uncertain,
                    );
                };
                if !self.message_started
                    || self.open_blocks.len() >= 1_024
                    || !self.open_blocks.insert(index)
                {
                    return self.fail(
                        ModelFailure::MalformedResponse,
                        AttemptOutcomeClass::Uncertain,
                    );
                }
                let kind = value
                    .get("content_block")
                    .and_then(|block| block.get("type"))
                    .and_then(Value::as_str)
                    .unwrap_or("");
                if kind.contains("tool_use") {
                    self.reject_tool_call();
                } else if kind == "text" {
                    self.text_blocks.insert(index);
                } else if kind.is_empty() {
                    self.fail(
                        ModelFailure::MalformedResponse,
                        AttemptOutcomeClass::Uncertain,
                    );
                }
            }
            "content_block_stop" => {
                let Some(index) = value.get("index").and_then(Value::as_u64) else {
                    return self.fail(
                        ModelFailure::MalformedResponse,
                        AttemptOutcomeClass::Uncertain,
                    );
                };
                if !self.open_blocks.remove(&index) {
                    self.fail(
                        ModelFailure::MalformedResponse,
                        AttemptOutcomeClass::Uncertain,
                    );
                }
                self.text_blocks.remove(&index);
            }
            "content_block_delta" => {
                let Some(index) = value.get("index").and_then(Value::as_u64) else {
                    return self.fail(
                        ModelFailure::MalformedResponse,
                        AttemptOutcomeClass::Uncertain,
                    );
                };
                let delta_kind = value
                    .get("delta")
                    .and_then(|delta| delta.get("type"))
                    .and_then(Value::as_str);
                if delta_kind == Some("input_json_delta") {
                    return self.reject_tool_call();
                }
                if !self.open_blocks.contains(&index) {
                    return self.fail(
                        ModelFailure::MalformedResponse,
                        AttemptOutcomeClass::Uncertain,
                    );
                }
                match delta_kind {
                    Some("text_delta") if self.text_blocks.contains(&index) => match value
                        .get("delta")
                        .and_then(|delta| delta.get("text"))
                        .and_then(Value::as_str)
                    {
                        Some(text) => self.push_delta(text.as_bytes()),
                        None => self.fail(
                            ModelFailure::MalformedResponse,
                            AttemptOutcomeClass::Uncertain,
                        ),
                    },
                    Some("text_delta") => self.fail(
                        ModelFailure::MalformedResponse,
                        AttemptOutcomeClass::Uncertain,
                    ),
                    _ => {}
                }
            }
            "message_delta" => {
                if !self.message_started || !self.open_blocks.is_empty() {
                    return self.fail(
                        ModelFailure::MalformedResponse,
                        AttemptOutcomeClass::Uncertain,
                    );
                }
                self.update_usage(value.get("usage"), false);
                match value
                    .get("delta")
                    .and_then(|delta| delta.get("stop_reason"))
                    .and_then(Value::as_str)
                {
                    Some("end_turn") | Some("stop_sequence") => self.saw_final_stop_reason = true,
                    Some("tool_use") => self.reject_tool_call(),
                    _ => self.fail(
                        ModelFailure::MalformedResponse,
                        AttemptOutcomeClass::CompletedWithResponse,
                    ),
                }
            }
            "message_stop" => {
                if !self.message_started
                    || !self.open_blocks.is_empty()
                    || !self.saw_final_stop_reason
                {
                    return self.fail(
                        ModelFailure::MalformedResponse,
                        AttemptOutcomeClass::Uncertain,
                    );
                }
                self.completed = true;
                self.outcome_class = Some(AttemptOutcomeClass::CompletedWithResponse);
                self.queued
                    .push_back(AdapterPoll::Event(AdapterEvent::Completed));
            }
            "error" => {
                let error_type = value
                    .get("error")
                    .and_then(|error| error.get("type"))
                    .and_then(Value::as_str);
                let failure = if matches!(
                    error_type,
                    Some("overloaded_error") | Some("rate_limit_error")
                ) {
                    ModelFailure::CapacityExceeded
                } else {
                    ModelFailure::ProviderError
                };
                self.fail(failure, AttemptOutcomeClass::CompletedWithResponse);
            }
            "ping" => {}
            _ => {}
        }
    }

    fn push_delta(&mut self, delta: &[u8]) {
        if self.response.len().saturating_add(delta.len()) > self.response_limit {
            return self.fail(
                ModelFailure::MalformedResponse,
                AttemptOutcomeClass::Uncertain,
            );
        }
        self.response.extend_from_slice(delta);
        self.queued
            .push_back(AdapterPoll::Event(AdapterEvent::Delta(delta.to_vec())));
    }

    fn update_usage(&mut self, usage: Option<&Value>, input: bool) {
        let field = if input {
            "input_tokens"
        } else {
            "output_tokens"
        };
        let Some(value) = usage.and_then(|usage| usage.get(field)) else {
            return;
        };
        let Some(next) = value.as_u64() else {
            return self.fail(
                ModelFailure::MalformedResponse,
                AttemptOutcomeClass::Uncertain,
            );
        };
        let previous = if input {
            self.usage.tokens_in
        } else {
            self.usage.tokens_out
        };
        if previous.is_some_and(|previous| next < previous) {
            return self.fail(
                ModelFailure::MalformedResponse,
                AttemptOutcomeClass::Uncertain,
            );
        }
        if input {
            self.usage.tokens_in = Some(next);
        } else {
            self.usage.tokens_out = Some(next);
        }
    }

    fn reject_tool_call(&mut self) {
        if let Some(stream) = &mut self.stream {
            stream.cancel("provider-native-tool-call-refused");
        }
        self.fail(
            ModelFailure::Refused,
            AttemptOutcomeClass::CompletedWithResponse,
        );
    }

    fn from_transport_failure(&mut self, failure: TransportFailure) {
        let (normalized, class) = match failure.kind {
            TransportFailureKind::NotDispatched => {
                (ModelFailure::Refused, AttemptOutcomeClass::NotDispatched)
            }
            TransportFailureKind::RejectedBeforeProcessing => (
                ModelFailure::Refused,
                AttemptOutcomeClass::RejectedBeforeProcessing,
            ),
            TransportFailureKind::CapacityExceeded => (
                ModelFailure::CapacityExceeded,
                AttemptOutcomeClass::RejectedBeforeProcessing,
            ),
            TransportFailureKind::TimeoutAfterDispatch => {
                (ModelFailure::Timeout, AttemptOutcomeClass::Uncertain)
            }
            TransportFailureKind::CancelledAfterDispatch => {
                (ModelFailure::Cancelled, AttemptOutcomeClass::Uncertain)
            }
            TransportFailureKind::UncertainAfterDispatch => {
                (ModelFailure::ProviderError, AttemptOutcomeClass::Uncertain)
            }
            TransportFailureKind::MalformedResponse => (
                ModelFailure::MalformedResponse,
                AttemptOutcomeClass::Uncertain,
            ),
        };
        self.fail_with_attempted(
            normalized,
            class,
            failure.attempted_bytes.min(MAX_RESPONSE_BYTES),
        );
    }
}

impl ProviderAdapter for AnthropicMessagesAdapter {
    fn capabilities(&self) -> &AdapterCapabilities {
        &self.capabilities
    }
    fn start(
        &mut self,
        _capability: &AdapterInvocationCapability,
        request: &AdapterRequest,
    ) -> Result<(), AdapterRefusal> {
        if self.model.is_empty()
            || self.model.len() > 256
            || self.max_tokens == 0
            || self.max_tokens > 1_048_576
        {
            return Err(AdapterRefusal(
                "provider model or output token bound invalid".into(),
            ));
        }
        if self.started {
            return Err(AdapterRefusal(
                "Anthropic adapter instances admit one start".into(),
            ));
        }
        if request.request_bytes.len() > MAX_REQUEST_BYTES
            || request.max_response_bytes > MAX_RESPONSE_BYTES
        {
            return Err(AdapterRefusal(
                "Anthropic request exceeds declared adapter byte limit".into(),
            ));
        }
        let prompt = std::str::from_utf8(&request.request_bytes).map_err(|_| {
            AdapterRefusal("Anthropic request bytes must be UTF-8 before dispatch".into())
        })?;
        let body = serde_json::to_vec(&json!({ "model": self.model, "max_tokens": self.max_tokens, "stream": true, "messages": [{"role":"user", "content":prompt}] }))
            .map_err(|_| AdapterRefusal("Anthropic request could not be rendered".into()))?;
        self.started = true;
        self.response_limit = request.max_response_bytes;
        match self.transport.start(ProviderHttpRequest {
            method: "POST",
            path: "/v1/messages",
            headers: vec![
                ("content-type", "application/json"),
                ("accept", "text/event-stream"),
                ("anthropic-version", "2023-06-01"),
            ],
            body,
            max_response_bytes: super::transport::MAX_TOTAL_WIRE_BYTES,
        }) {
            Ok(stream) => {
                self.stream = Some(stream);
                Ok(())
            }
            Err(failure) if failure.kind == TransportFailureKind::NotDispatched => {
                self.outcome_class = Some(AttemptOutcomeClass::NotDispatched);
                Err(AdapterRefusal(
                    "host transport declined Anthropic dispatch before submission".into(),
                ))
            }
            Err(failure) => {
                self.from_transport_failure(failure);
                Ok(())
            }
        }
    }
    fn poll(&mut self) -> AdapterPoll {
        if let Some(poll) = self.queued.pop_front() {
            return poll;
        }
        if let Some(terminal) = &self.terminal {
            return terminal.clone();
        }
        let Some(stream) = &mut self.stream else {
            return AdapterPoll::Failed {
                failure: ModelFailure::ProviderError,
                attempted_bytes: 0,
            };
        };
        match stream.poll() {
            TransportPoll::Pending => AdapterPoll::Pending,
            TransportPoll::End if self.completed && self.decoder.is_empty() => {
                let settled = AdapterPoll::Settled(AdapterSettlement {
                    response_bytes: self.response.clone(),
                    usage: self.usage,
                });
                self.terminal = Some(settled.clone());
                settled
            }
            TransportPoll::End if !self.decoder.is_empty() => {
                self.fail(
                    ModelFailure::MalformedResponse,
                    AttemptOutcomeClass::Uncertain,
                );
                self.terminal.clone().unwrap()
            }
            TransportPoll::End => {
                self.fail(ModelFailure::ProviderError, AttemptOutcomeClass::Uncertain);
                self.terminal.clone().unwrap()
            }
            TransportPoll::Failed(failure) => {
                self.from_transport_failure(failure);
                self.terminal.clone().unwrap()
            }
            TransportPoll::Chunk(chunk) => match self.decoder.push(&chunk) {
                Err(()) => {
                    self.fail(
                        ModelFailure::MalformedResponse,
                        AttemptOutcomeClass::Uncertain,
                    );
                    self.terminal.clone().unwrap()
                }
                Ok(events) => {
                    for event in events {
                        self.handle_event(event);
                        if self.terminal.is_some() {
                            break;
                        }
                    }
                    self.queued
                        .pop_front()
                        .or_else(|| self.terminal.clone())
                        .unwrap_or(AdapterPoll::Pending)
                }
            },
        }
    }
    fn cancel(&mut self, reason: &str) {
        if let Some(stream) = &mut self.stream {
            stream.cancel(reason);
        }
        if self.terminal.is_none() {
            self.fail(ModelFailure::Cancelled, AttemptOutcomeClass::Uncertain);
        }
    }
}

fn unknown_usage() -> AdapterUsage {
    AdapterUsage {
        tokens_in: None,
        tokens_out: None,
        cost_micros: None,
    }
}
