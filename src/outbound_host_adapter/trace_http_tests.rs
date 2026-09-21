use super::*;

#[derive(Default)]
struct RecordingAdapter {
    requests: Vec<Vec<(String, String)>>,
}

impl OutboundAdapter for RecordingAdapter {
    fn send(&mut self, request: &PreparedRequest) -> AdapterObservation {
        self.requests.push(request.headers().to_vec());
        AdapterObservation::Response {
            status: 204,
            body: Vec::new(),
        }
    }
}

fn policy() -> OutboundPolicy {
    OutboundPolicy::new(
        "traced-http-policy-v1",
        ["https://api.example.test".into()],
        64,
        32,
        2_000,
        8,
        8,
    )
    .unwrap()
}

fn capability() -> OutboundCapability {
    OutboundCapability::grant_for_trusted_host(
        "traced-http-deployment-v1",
        "traced-http-invocation-1",
        policy(),
    )
    .unwrap()
}

fn request() -> HttpRequest {
    HttpRequest {
        method: HttpMethod::Post,
        endpoint: "https://api.example.test/v1/items".into(),
        request_id: "traced-request-1".into(),
        idempotency_key: "traced-idempotency-1".into(),
        content_type: Some("application/json".into()),
        headers: vec![HttpHeader::new("x-public-mode", "bounded").unwrap()],
        body: br#"{"value":7}"#.to_vec(),
        deadline_ms: 1_000,
    }
}

fn context() -> TraceContext {
    struct Entropy;

    impl TraceEntropyCapability for Entropy {
        fn fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), TraceContextError> {
            for (index, byte) in destination.iter_mut().enumerate() {
                *byte = (index + 1) as u8;
            }
            Ok(())
        }
    }

    TraceContext::fresh(&mut Entropy, true).unwrap()
}

#[test]
fn typed_context_emits_one_canonical_traceparent_at_dispatch() {
    let expected = context().traceparent();
    let mut adapter = RecordingAdapter::default();
    let result = deliver_traced_http(
        capability(),
        TracedHttpRequest::new(request(), context()),
        &mut adapter,
    )
    .unwrap();
    assert!(matches!(
        result.evidence.disposition(),
        DeliveryDisposition::Accepted { status: 204 }
    ));
    assert_eq!(adapter.requests.len(), 1);
    let traceparents = adapter.requests[0]
        .iter()
        .filter(|(name, _)| name == "traceparent")
        .collect::<Vec<_>>();
    assert_eq!(traceparents.len(), 1);
    assert_eq!(traceparents[0].0, "traceparent");
    assert_eq!(traceparents[0].1, expected);
    assert!(!adapter.requests[0]
        .iter()
        .any(|(name, _)| name == "tracestate"));
}

#[test]
fn typed_trace_header_counts_against_global_header_limit() {
    let mut at_limit_without_trace = request();
    at_limit_without_trace.headers = (0..5)
        .map(|index| HttpHeader::new(format!("x-public-{index}"), "v").unwrap())
        .collect();
    assert!(prepare_http_delivery(capability(), at_limit_without_trace).is_ok());

    let mut at_limit_with_trace = request();
    at_limit_with_trace.headers = (0..5)
        .map(|index| HttpHeader::new(format!("x-public-{index}"), "v").unwrap())
        .collect();
    assert!(matches!(
        prepare_traced_http_delivery(
            capability(),
            TracedHttpRequest::new(at_limit_with_trace, context()),
        ),
        Err(Refusal::InvalidHeader)
    ));
}

#[test]
fn raw_trace_headers_and_changed_context_refuse_or_conflict() {
    assert_eq!(
        HttpHeader::new(
            "traceparent",
            "00-11111111111111111111111111111111-2222222222222222-01"
        ),
        Err(Refusal::InvalidHeader)
    );
    assert_eq!(
        HttpHeader::new("tracestate", "vendor=value"),
        Err(Refusal::InvalidHeader)
    );

    let mut session = HttpDeliverySession::new(2).unwrap();
    let mut first_adapter = RecordingAdapter::default();
    let first = session
        .reconcile(
            prepare_traced_http_delivery(
                capability(),
                TracedHttpRequest::new(request(), context()),
            )
            .unwrap(),
            &mut first_adapter,
        )
        .unwrap();
    assert!(!first.was_replayed());
    assert_eq!(first_adapter.requests.len(), 1);

    let inbound = TraceContext::from_traceparent(
        "00-11111111111111111111111111111111-2222222222222222-01",
        &mut FixedEntropy,
    )
    .unwrap();
    let mut replay_adapter = RecordingAdapter::default();
    assert_eq!(
        session.reconcile(
            prepare_traced_http_delivery(capability(), TracedHttpRequest::new(request(), inbound),)
                .unwrap(),
            &mut replay_adapter,
        ),
        Err(HttpLedgerRefusal::Ledger(LedgerRefusal::ConflictingRequest))
    );
    assert!(replay_adapter.requests.is_empty());
}

struct FixedEntropy;

impl TraceEntropyCapability for FixedEntropy {
    fn fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), TraceContextError> {
        destination.fill(0x33);
        Ok(())
    }
}
