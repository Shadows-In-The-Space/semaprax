use std::cell::RefCell;
use std::collections::VecDeque;
use std::rc::Rc;

use serde_json::json;

use crate::agent_interaction_schema::compile_agent_interaction_schema;
use crate::live_invocation::model_invoke::{
    ModelFailure, ModelHandler, ModelInvocationOutcome, ModelInvocationRequest,
    ModelInvokeCapability,
};
use crate::provider_adapter_sdk::StreamingModelHandler;

use super::super::{AdapterInvocationCapability, AdapterPoll, AdapterRequest, ProviderAdapter};
use super::*;

#[derive(Clone, Copy)]
enum Protocol {
    OpenAi,
    Anthropic,
}

struct ScriptedStream {
    polls: VecDeque<TransportPoll>,
    cancelled: Rc<RefCell<Vec<String>>>,
}

impl HostHttpStream for ScriptedStream {
    fn poll(&mut self) -> TransportPoll {
        self.polls.pop_front().unwrap_or(TransportPoll::End)
    }
    fn cancel(&mut self, reason: &str) {
        self.cancelled.borrow_mut().push(reason.into());
    }
}

struct ScriptedTransport {
    polls: VecDeque<TransportPoll>,
    requests: Rc<RefCell<Vec<ProviderHttpRequest>>>,
    cancelled: Rc<RefCell<Vec<String>>>,
}

impl HostHttpStreamTransport for ScriptedTransport {
    fn start(
        &mut self,
        request: ProviderHttpRequest,
    ) -> Result<Box<dyn HostHttpStream>, TransportFailure> {
        self.requests.borrow_mut().push(request);
        Ok(Box::new(ScriptedStream {
            polls: std::mem::take(&mut self.polls),
            cancelled: self.cancelled.clone(),
        }))
    }
}

fn transport(
    polls: Vec<TransportPoll>,
) -> (
    Box<dyn HostHttpStreamTransport>,
    Rc<RefCell<Vec<ProviderHttpRequest>>>,
    Rc<RefCell<Vec<String>>>,
) {
    let requests = Rc::new(RefCell::new(Vec::new()));
    let cancelled = Rc::new(RefCell::new(Vec::new()));
    (
        Box::new(ScriptedTransport {
            polls: polls.into(),
            requests: requests.clone(),
            cancelled: cancelled.clone(),
        }),
        requests,
        cancelled,
    )
}

fn request() -> AdapterRequest {
    AdapterRequest {
        request_bytes: b"canonical proposal prompt".to_vec(),
        max_response_bytes: 128,
    }
}
fn cap() -> AdapterInvocationCapability {
    AdapterInvocationCapability::grant("vendor wire fixture")
}

fn adapter_for(protocol: Protocol, polls: Vec<TransportPoll>) -> Box<dyn ProviderAdapter> {
    let (transport, _, _) = transport(polls);
    match protocol {
        Protocol::OpenAi => Box::new(OpenAiResponsesAdapter::new("gpt-test", 16, transport)),
        Protocol::Anthropic => {
            Box::new(AnthropicMessagesAdapter::new("claude-test", 16, transport))
        }
    }
}

fn eventually_failed(adapter: &mut dyn ProviderAdapter) -> ModelFailure {
    for _ in 0..8 {
        if let AdapterPoll::Failed { failure, .. } = adapter.poll() {
            return failure;
        }
    }
    panic!("hostile vendor wire did not fail within the bounded poll budget");
}

#[test]
fn openai_responses_normalizes_split_sse_text_and_waits_for_end() {
    let (transport, requests, _) = transport(vec![
        TransportPoll::Chunk(b"data: {\"type\":\"response.output_text.delta\",\"delta\":\"hel".to_vec()),
        TransportPoll::Chunk(b"lo\"}\n\ndata: {\"type\":\"response.completed\",\"response\":{\"status\":\"completed\",\"usage\":{\"input_tokens\":2,\"output_tokens\":1},\"output\":[{\"type\":\"message\",\"content\":[{\"type\":\"output_text\",\"text\":\"hello\"}]}]}}\n\n".to_vec()),
        TransportPoll::End,
    ]);
    let mut adapter = OpenAiResponsesAdapter::new("gpt-test", 16, transport);
    adapter.start(&cap(), &request()).unwrap();
    assert_eq!(requests.borrow()[0].path, "/v1/responses");
    assert!(!String::from_utf8_lossy(&requests.borrow()[0].body).contains("Authorization"));
    assert!(matches!(adapter.poll(), AdapterPoll::Pending));
    assert!(
        matches!(adapter.poll(), AdapterPoll::Event(super::super::AdapterEvent::Delta(bytes)) if bytes == b"hello")
    );
    assert!(matches!(
        adapter.poll(),
        AdapterPoll::Event(super::super::AdapterEvent::Completed)
    ));
    assert!(
        matches!(adapter.poll(), AdapterPoll::Settled(settlement) if settlement.response_bytes == b"hello" && settlement.usage.tokens_in == Some(2))
    );
}

#[test]
fn anthropic_messages_normalizes_message_flow_and_usage() {
    let (transport, requests, _) = transport(vec![TransportPoll::Chunk(b"event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"usage\":{\"input_tokens\":3}}}\n\nevent: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"text\"}}\n\nevent: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"ok\"}}\n\nevent: content_block_stop\ndata: {\"type\":\"content_block_stop\",\"index\":0}\n\nevent: message_delta\ndata: {\"type\":\"message_delta\",\"usage\":{\"output_tokens\":1},\"delta\":{\"stop_reason\":\"end_turn\"}}\n\nevent: message_stop\ndata: {\"type\":\"message_stop\"}\n\n".to_vec()), TransportPoll::End]);
    let mut adapter = AnthropicMessagesAdapter::new("claude-test", 32, transport);
    adapter.start(&cap(), &request()).unwrap();
    assert_eq!(requests.borrow()[0].path, "/v1/messages");
    assert!(requests.borrow()[0]
        .headers
        .iter()
        .any(|header| *header == ("anthropic-version", "2023-06-01")));
    assert!(
        matches!(adapter.poll(), AdapterPoll::Event(super::super::AdapterEvent::Delta(bytes)) if bytes == b"ok")
    );
    assert!(matches!(
        adapter.poll(),
        AdapterPoll::Event(super::super::AdapterEvent::Completed)
    ));
    assert!(
        matches!(adapter.poll(), AdapterPoll::Settled(settlement) if settlement.usage.tokens_in == Some(3) && settlement.usage.tokens_out == Some(1))
    );
}

#[test]
fn openai_function_call_is_refused_and_cancels_host_stream() {
    let (transport, _, cancelled) = transport(vec![TransportPoll::Chunk(
        b"data: {\"type\":\"response.function_call_arguments.delta\",\"delta\":\"{}\"}\n\n"
            .to_vec(),
    )]);
    let mut adapter = OpenAiResponsesAdapter::new("gpt-test", 16, transport);
    adapter.start(&cap(), &request()).unwrap();
    assert!(matches!(
        adapter.poll(),
        AdapterPoll::Failed {
            failure: ModelFailure::Refused,
            ..
        }
    ));
    assert_eq!(
        cancelled.borrow().as_slice(),
        ["provider-native-tool-call-refused"]
    );
}

#[test]
fn anthropic_tool_start_is_refused_and_cancels_host_stream() {
    let (transport, _, cancelled) = transport(vec![TransportPoll::Chunk(b"event: message_start\ndata: {\"type\":\"message_start\",\"message\":{}}\n\nevent: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"tool_use\"}}\n\n".to_vec())]);
    let mut adapter = AnthropicMessagesAdapter::new("claude-test", 16, transport);
    adapter.start(&cap(), &request()).unwrap();
    assert!(matches!(
        adapter.poll(),
        AdapterPoll::Failed {
            failure: ModelFailure::Refused,
            ..
        }
    ));
    assert_eq!(
        cancelled.borrow().as_slice(),
        ["provider-native-tool-call-refused"]
    );
}

#[test]
fn vendor_hostile_wire_corpus_refuses_order_truncation_size_and_usage_cases() {
    let oversized = "x".repeat(129);
    let cases = vec![
        (Protocol::OpenAi, "data: {\"type\":\"response.completed\",\"response\":{\"status\":\"completed\",\"output\":[]}}\n\ndata: {\"type\":\"response.output_text.delta\",\"delta\":\"late\"}\n\n".to_owned()),
        (Protocol::OpenAi, format!("data: {{\"type\":\"response.output_text.delta\",\"delta\":\"{oversized}\"}}\n\n")),
        (Protocol::OpenAi, "data: {\"type\":\"response.completed\",\"response\":{\"status\":\"completed\",\"usage\":{\"input_tokens\":-1},\"output\":[]}}\n\n".to_owned()),
        (Protocol::Anthropic, "data: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"out-of-order\"}}\n\n".to_owned()),
        (Protocol::Anthropic, "data: {\"type\":\"message_start\",\"message\":{}}\n\ndata: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"text\"}}\n\ndata: {\"type\":\"content_block_stop\",\"index\":0}\n\ndata: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\"}}\n\ndata: {\"type\":\"message_stop\"}\n\ndata: {".to_owned()),
        (Protocol::Anthropic, format!("data: {{\"type\":\"message_start\",\"message\":{{}}}}\n\ndata: {{\"type\":\"content_block_start\",\"index\":0,\"content_block\":{{\"type\":\"text\"}}}}\n\ndata: {{\"type\":\"content_block_delta\",\"index\":0,\"delta\":{{\"type\":\"text_delta\",\"text\":\"{oversized}\"}}}}\n\n")),
        (Protocol::Anthropic, "data: {\"type\":\"message_start\",\"message\":{\"usage\":{\"input_tokens\":-1}}}\n\n".to_owned()),
    ];
    for (protocol, wire) in cases {
        let mut adapter = adapter_for(
            protocol,
            vec![TransportPoll::Chunk(wire.into_bytes()), TransportPoll::End],
        );
        adapter.start(&cap(), &request()).unwrap();
        assert_eq!(
            eventually_failed(adapter.as_mut()),
            ModelFailure::MalformedResponse
        );
    }
}

#[test]
fn both_protocols_cancel_before_consuming_later_wire() {
    for protocol in [Protocol::OpenAi, Protocol::Anthropic] {
        let mut adapter = adapter_for(protocol, vec![TransportPoll::Pending]);
        adapter.start(&cap(), &request()).unwrap();
        adapter.cancel("fixture cancellation");
        assert!(matches!(
            adapter.poll(),
            AdapterPoll::Failed {
                failure: ModelFailure::Cancelled,
                ..
            }
        ));
    }
}

struct UncertainTransport;
impl HostHttpStreamTransport for UncertainTransport {
    fn start(
        &mut self,
        _: ProviderHttpRequest,
    ) -> Result<Box<dyn HostHttpStream>, TransportFailure> {
        Err(TransportFailure {
            kind: TransportFailureKind::UncertainAfterDispatch,
            attempted_bytes: 7,
        })
    }
}

#[test]
fn both_protocols_surface_after_dispatch_transport_uncertainty() {
    let mut openai = OpenAiResponsesAdapter::new("gpt-test", 16, Box::new(UncertainTransport));
    assert!(openai.start(&cap(), &request()).is_ok());
    assert!(matches!(
        openai.poll(),
        AdapterPoll::Failed {
            failure: ModelFailure::ProviderError,
            attempted_bytes: 7
        }
    ));
    assert_eq!(
        openai.attempt_outcome_class(),
        Some(crate::model_budget_policy::classification::AttemptOutcomeClass::Uncertain)
    );
    let mut anthropic =
        AnthropicMessagesAdapter::new("claude-test", 16, Box::new(UncertainTransport));
    assert!(anthropic.start(&cap(), &request()).is_ok());
    assert!(matches!(
        anthropic.poll(),
        AdapterPoll::Failed {
            failure: ModelFailure::ProviderError,
            attempted_bytes: 7
        }
    ));
    assert_eq!(
        anthropic.attempt_outcome_class(),
        Some(crate::model_budget_policy::classification::AttemptOutcomeClass::Uncertain)
    );
}

#[test]
fn both_protocols_pass_the_same_neutral_conformance_request() {
    use crate::provider_adapter_sdk::{
        run_conformance_suite, ExpectedOutcome, RequiredCapabilities,
    };
    let required = RequiredCapabilities {
        require_streaming: true,
        require_structured_output_mode: None,
        max_request_bytes: 64,
        max_response_bytes: 128,
    };
    let fixtures = [
        (Protocol::OpenAi, b"data: {\"type\":\"response.output_text.delta\",\"delta\":\"ok\"}\n\ndata: {\"type\":\"response.completed\",\"response\":{\"status\":\"completed\",\"output\":[{\"type\":\"message\",\"content\":[{\"type\":\"output_text\",\"text\":\"ok\"}]}]}}\n\n".to_vec()),
        (Protocol::Anthropic, b"data: {\"type\":\"message_start\",\"message\":{}}\n\ndata: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"text\"}}\n\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"ok\"}}\n\ndata: {\"type\":\"content_block_stop\",\"index\":0}\n\ndata: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\"}}\n\ndata: {\"type\":\"message_stop\"}\n\n".to_vec()),
    ];
    for (protocol, wire) in fixtures {
        let mut adapter = adapter_for(
            protocol,
            vec![TransportPoll::Chunk(wire), TransportPoll::End],
        );
        let report = run_conformance_suite(
            adapter.as_mut(),
            &cap(),
            &required,
            &request(),
            None,
            &ExpectedOutcome::Settled {
                response_bytes: b"ok".to_vec(),
            },
        );
        assert!(report.cases.iter().all(|case| case.passed), "{report:?}");
    }
}

const SCHEMA_SOURCE: &str = "module vendor.bridge;\n\n@id(\"answer.type\")\nrecord Answer {\n    @id(\"answer.note\")\n    note: string,\n}\n\n@id(\"app.main\")\nfn main() -> i64 { 0 }\n";

fn compiled_schema() -> crate::agent_interaction_schema::CompiledInteractionSchema {
    let path =
        std::env::temp_dir().join(format!("semaprax-vendor-bridge-{}.spx", std::process::id()));
    std::fs::write(&path, SCHEMA_SOURCE).unwrap();
    let result = compile_agent_interaction_schema(&path, "answer.type");
    std::fs::remove_file(path).unwrap();
    result.unwrap()
}

fn schema_document(
    schema: &crate::agent_interaction_schema::CompiledInteractionSchema,
    field: &str,
) -> Vec<u8> {
    format!(
        "{{\"schema\":\"semaprax.agent-interaction-value.v1\",\"root_type_id\":\"answer.type\",\"schema_digest\":{},\"value\":{{\"fields\":{{{}:\"ok\"}}}}}}\n",
        serde_json::to_string(schema.schema().digest()).unwrap(),
        serde_json::to_string(field).unwrap(),
    ).into_bytes()
}

fn bridge_request(
    schema: &crate::agent_interaction_schema::CompiledInteractionSchema,
) -> ModelInvocationRequest {
    ModelInvocationRequest {
        turn: 0,
        task: b"task".to_vec(),
        observation: b"observation".to_vec(),
        proposal_grammar_digest: schema.schema().digest().to_owned(),
        deployment_binding: "vendor-test".into(),
        max_response_bytes: 4096,
        effective_budget: 1,
    }
}

fn protocol_wire(protocol: Protocol, text: &str) -> Vec<u8> {
    let event = |value| format!("data: {}\n\n", serde_json::to_string(&value).unwrap());
    match protocol {
        Protocol::OpenAi => format!(
            "{}{}",
            event(json!({"type":"response.output_text.delta","delta":text})),
            event(json!({"type":"response.completed","response":{"status":"completed","output":[{"type":"message","content":[{"type":"output_text","text":text}]}]}})),
        ).into_bytes(),
        Protocol::Anthropic => format!(
            "{}{}{}{}{}{}",
            event(json!({"type":"message_start","message":{}})),
            event(json!({"type":"content_block_start","index":0,"content_block":{"type":"text"}})),
            event(json!({"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":text}})),
            event(json!({"type":"content_block_stop","index":0})),
            event(json!({"type":"message_delta","delta":{"stop_reason":"end_turn"}})),
            event(json!({"type":"message_stop"})),
        ).into_bytes(),
    }
}

#[test]
fn both_protocols_cross_the_same_compiled_schema_bridge_and_reject_wrong_fields() {
    let schema = compiled_schema();
    for protocol in [Protocol::OpenAi, Protocol::Anthropic] {
        let valid = schema_document(&schema, "answer.note");
        let mut adapter = adapter_for(
            protocol,
            vec![
                TransportPoll::Chunk(protocol_wire(
                    protocol,
                    std::str::from_utf8(&valid).unwrap(),
                )),
                TransportPoll::End,
            ],
        );
        let outcome = StreamingModelHandler::new(adapter.as_mut(), cap(), &schema).invoke(
            &ModelInvokeCapability::grant("vendor compiled bridge"),
            &bridge_request(&schema),
        );
        assert!(matches!(outcome, ModelInvocationOutcome::Settled(_)));

        let wrong = schema_document(&schema, "wrong.field");
        let mut adapter = adapter_for(
            protocol,
            vec![
                TransportPoll::Chunk(protocol_wire(
                    protocol,
                    std::str::from_utf8(&wrong).unwrap(),
                )),
                TransportPoll::End,
            ],
        );
        let outcome = StreamingModelHandler::new(adapter.as_mut(), cap(), &schema).invoke(
            &ModelInvokeCapability::grant("vendor compiled bridge"),
            &bridge_request(&schema),
        );
        assert!(matches!(
            outcome,
            ModelInvocationOutcome::Failed {
                failure: ModelFailure::MalformedResponse,
                ..
            }
        ));
    }
}
