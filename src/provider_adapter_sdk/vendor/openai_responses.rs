//! OpenAI Responses API streaming adapter.
//!
//! This maps `response.output_text.delta` SSE events to raw proposal deltas,
//! reads provider `usage`, and accepts only a terminal `response.completed`
//! with status `completed`. Function/MCP tool events are refused locally and
//! never become Semaprax tool execution. The host transport owns the OpenAI
//! origin and Authorization header; this adapter only asks for `/v1/responses`.

use std::collections::VecDeque;

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

/// A real OpenAI Responses-protocol normalizer over a host-supplied stream.
/// `model` is a host deployment selection, never an endpoint or credential.
pub struct OpenAiResponsesAdapter {
    capabilities: AdapterCapabilities,
    model: String,
    max_output_tokens: u64,
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
    started: bool,
}

impl OpenAiResponsesAdapter {
    #[must_use]
    pub fn new(
        model: impl Into<String>,
        max_output_tokens: u64,
        transport: Box<dyn HostHttpStreamTransport>,
    ) -> Self {
        Self {
            capabilities: AdapterCapabilities {
                adapter_identity: "openai-responses-sse".into(),
                adapter_version: "1.0.0".into(),
                provider_profile: "openai-responses".into(),
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
                max_output_tokens: max_output_tokens,
            },
            model: model.into(),
            max_output_tokens: max_output_tokens,
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
            started: false,
        }
    }

    /// Trusted transport-side retry classification for the completed attempt.
    /// It is `None` before a terminal poll and is deliberately separate from
    /// the provider payload and `ModelFailure` display taxonomy.
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
        let poll = AdapterPoll::Failed {
            failure,
            attempted_bytes,
        };
        self.outcome_class = Some(class);
        self.queued.clear();
        self.terminal = Some(poll);
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
        let kind = match value.get("type").and_then(Value::as_str) {
            Some(kind) => kind,
            None => {
                return self.fail(
                    ModelFailure::MalformedResponse,
                    AttemptOutcomeClass::Uncertain,
                )
            }
        };
        if kind.starts_with("response.function_call") || kind.starts_with("response.mcp_call") {
            return self.reject_tool_call();
        }
        match kind {
            "response.output_text.delta" => match value.get("delta").and_then(Value::as_str) {
                Some(delta) => self.push_delta(delta.as_bytes()),
                None => self.fail(
                    ModelFailure::MalformedResponse,
                    AttemptOutcomeClass::Uncertain,
                ),
            },
            "response.output_item.added" | "response.output_item.done" => {
                if value
                    .get("item")
                    .and_then(|item| item.get("type"))
                    .and_then(Value::as_str)
                    .is_some_and(is_unsupported_output_item)
                {
                    self.reject_tool_call();
                }
            }
            "response.completed" => self.completed(&value),
            "response.failed" | "error" => self.fail(
                ModelFailure::ProviderError,
                AttemptOutcomeClass::CompletedWithResponse,
            ),
            "response.incomplete" => self.fail(
                ModelFailure::MalformedResponse,
                AttemptOutcomeClass::CompletedWithResponse,
            ),
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

    fn completed(&mut self, value: &Value) {
        let response = value.get("response").unwrap_or(value);
        match response.get("status").and_then(Value::as_str) {
            Some("completed") => {
                match final_output_text(response) {
                    Ok(Some(final_text)) if final_text.as_bytes() != self.response => {
                        return self.fail(
                            ModelFailure::MalformedResponse,
                            AttemptOutcomeClass::CompletedWithResponse,
                        )
                    }
                    Err(()) => {
                        return self.fail(
                            ModelFailure::Refused,
                            AttemptOutcomeClass::CompletedWithResponse,
                        )
                    }
                    _ => {}
                }
                if !self.update_usage(response.get("usage")) {
                    return self.fail(
                        ModelFailure::MalformedResponse,
                        AttemptOutcomeClass::CompletedWithResponse,
                    );
                }
                if self.usage.tokens_in.is_some()
                    && self.usage.tokens_out.is_some()
                    && self.usage.cost_micros.is_some()
                {
                    self.queued
                        .push_back(AdapterPoll::Event(AdapterEvent::Usage {
                            tokens_in: self.usage.tokens_in.unwrap(),
                            tokens_out: self.usage.tokens_out.unwrap(),
                            cost_micros: self.usage.cost_micros.unwrap(),
                        }));
                }
                self.queued
                    .push_back(AdapterPoll::Event(AdapterEvent::Completed));
                self.outcome_class = Some(AttemptOutcomeClass::CompletedWithResponse);
                self.completed = true;
            }
            Some("cancelled") | Some("canceled") => {
                self.fail(ModelFailure::Cancelled, AttemptOutcomeClass::Uncertain)
            }
            Some("incomplete") => self.fail(
                ModelFailure::MalformedResponse,
                AttemptOutcomeClass::CompletedWithResponse,
            ),
            _ => self.fail(
                ModelFailure::ProviderError,
                AttemptOutcomeClass::CompletedWithResponse,
            ),
        }
    }

    fn update_usage(&mut self, usage: Option<&Value>) -> bool {
        let Some(usage) = usage else { return true };
        for (field, input) in [("input_tokens", true), ("output_tokens", false)] {
            let Some(value) = usage.get(field) else {
                continue;
            };
            let Some(tokens) = value.as_u64() else {
                return false;
            };
            if input {
                self.usage.tokens_in = Some(tokens);
            } else {
                self.usage.tokens_out = Some(tokens);
            }
        }
        true
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

impl ProviderAdapter for OpenAiResponsesAdapter {
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
            || self.max_output_tokens == 0
            || self.max_output_tokens > 1_048_576
        {
            return Err(AdapterRefusal(
                "provider model or output token bound invalid".into(),
            ));
        }
        if self.started {
            return Err(AdapterRefusal(
                "OpenAI adapter instances admit one start".into(),
            ));
        }
        if request.request_bytes.len() > MAX_REQUEST_BYTES
            || request.max_response_bytes > MAX_RESPONSE_BYTES
        {
            return Err(AdapterRefusal(
                "OpenAI request exceeds declared adapter byte limit".into(),
            ));
        }
        let prompt = std::str::from_utf8(&request.request_bytes).map_err(|_| {
            AdapterRefusal("OpenAI request bytes must be UTF-8 before dispatch".into())
        })?;
        let body = serde_json::to_vec(&json!({
            "model": self.model,
            "input": [{"role": "user", "content": [{"type": "input_text", "text": prompt}]}],
            "stream": true,
            "store": false,
            "max_output_tokens": self.max_output_tokens,
        }))
        .map_err(|_| AdapterRefusal("OpenAI request could not be rendered".into()))?;
        self.started = true;
        self.response_limit = request.max_response_bytes;
        match self.transport.start(ProviderHttpRequest {
            method: "POST",
            path: "/v1/responses",
            headers: vec![
                ("content-type", "application/json"),
                ("accept", "text/event-stream"),
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
                    "host transport declined OpenAI dispatch before submission".into(),
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

fn is_unsupported_output_item(kind: &str) -> bool {
    !matches!(kind, "message" | "reasoning")
}

fn final_output_text(response: &Value) -> Result<Option<String>, ()> {
    let Some(output) = response.get("output") else {
        return Ok(None);
    };
    let mut text = String::new();
    let mut saw_text = false;
    for item in output.as_array().ok_or(())? {
        let kind = item.get("type").and_then(Value::as_str).ok_or(())?;
        if is_unsupported_output_item(kind) {
            return Err(());
        }
        for content in item
            .get("content")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            match content.get("type").and_then(Value::as_str) {
                Some("output_text") => {
                    text.push_str(content.get("text").and_then(Value::as_str).ok_or(())?);
                    saw_text = true;
                }
                Some("refusal") => return Err(()),
                _ => {}
            }
        }
    }
    Ok(saw_text.then_some(text))
}
