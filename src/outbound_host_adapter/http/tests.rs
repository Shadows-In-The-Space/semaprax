use super::*;

#[derive(Default)]
struct RecordingAdapter {
    requests: Vec<(HttpMethod, String, Vec<(String, String)>, Vec<u8>)>,
    observation: Option<AdapterObservation>,
}

impl RecordingAdapter {
    fn returning(observation: AdapterObservation) -> Self {
        Self {
            requests: Vec::new(),
            observation: Some(observation),
        }
    }
}

impl OutboundAdapter for RecordingAdapter {
    fn send(&mut self, request: &PreparedRequest) -> AdapterObservation {
        self.requests.push((
            request.method(),
            request.endpoint().to_owned(),
            request.headers().to_vec(),
            request.body().to_vec(),
        ));
        self.observation
            .take()
            .unwrap_or(AdapterObservation::NotDispatched {
                reason: AdapterFailure::PolicyRejected,
            })
    }
}

fn policy() -> OutboundPolicy {
    OutboundPolicy::new(
        "http-policy-v1",
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
    OutboundCapability::grant_for_trusted_host("deployment-http-v1", "invocation-http-1", policy())
        .unwrap()
}

fn request(method: HttpMethod) -> HttpRequest {
    HttpRequest {
        method,
        endpoint: "https://api.example.test/v1/items?limit=2".into(),
        request_id: "request-1".into(),
        idempotency_key: "idempotency-1".into(),
        content_type: Some("application/json".into()),
        headers: vec![HttpHeader::new("x-public-mode", "bounded").unwrap()],
        body: if method == HttpMethod::Get {
            Vec::new()
        } else {
            br#"{"value":7}"#.to_vec()
        },
        deadline_ms: 1_000,
    }
}

#[test]
fn every_typed_method_reaches_the_adapter_once_without_redirect_or_retry() {
    for (index, method) in [
        HttpMethod::Get,
        HttpMethod::Post,
        HttpMethod::Put,
        HttpMethod::Patch,
        HttpMethod::Delete,
    ]
    .into_iter()
    .enumerate()
    {
        let mut request = request(method);
        request.request_id = format!("request-{index}");
        request.idempotency_key = format!("idempotency-{index}");
        let expected_body = request.body.clone();
        let mut adapter = RecordingAdapter::returning(AdapterObservation::Response {
            status: 200,
            body: b"ok".to_vec(),
        });
        let result = deliver_http(capability(), request, &mut adapter).unwrap();
        assert_eq!(adapter.requests.len(), 1);
        assert_eq!(adapter.requests[0].0, method);
        assert_eq!(adapter.requests[0].3, expected_body);
        assert_eq!(result.response_body, Some(b"ok".to_vec()));
        assert_eq!(
            result.evidence.disposition(),
            &DeliveryDisposition::Accepted { status: 200 }
        );
    }
}

#[test]
fn request_admission_refuses_authority_bounds_and_credential_headers_before_dispatch() {
    assert_eq!(
        HttpHeader::new("authorization", "Bearer private"),
        Err(Refusal::InvalidHeader)
    );
    assert_eq!(
        HttpHeader::new("x-api-key", "private"),
        Err(Refusal::InvalidHeader)
    );
    assert_eq!(
        HttpHeader::new("x-semaprax-delivery-id", "forged"),
        Err(Refusal::InvalidHeader)
    );
    assert_eq!(
        HttpHeader::new("X-Mixed-Case", "public"),
        Err(Refusal::InvalidHeader)
    );

    let mut unauthorized = request(HttpMethod::Post);
    unauthorized.endpoint = "https://other.example.test/v1/items".into();
    assert!(matches!(
        prepare_http_delivery(capability(), unauthorized),
        Err(Refusal::AuthorityDenied)
    ));

    let mut oversized = request(HttpMethod::Post);
    oversized.body = vec![0; 65];
    assert!(matches!(
        prepare_http_delivery(capability(), oversized),
        Err(Refusal::RequestTooLarge)
    ));

    let mut get_with_body = request(HttpMethod::Get);
    get_with_body.body.push(1);
    assert!(matches!(
        prepare_http_delivery(capability(), get_with_body),
        Err(Refusal::InvalidHeader)
    ));

    let mut too_many_headers = request(HttpMethod::Post);
    too_many_headers.headers = (0..7)
        .map(|index| HttpHeader::new(format!("x-public-{index}"), "v").unwrap())
        .collect();
    assert!(matches!(
        prepare_http_delivery(capability(), too_many_headers),
        Err(Refusal::InvalidHeader)
    ));
}

#[test]
fn debug_surfaces_redact_identifiers_header_values_and_body_bytes() {
    let http_request = request(HttpMethod::Post);
    let request_debug = format!("{http_request:?}");
    assert!(!request_debug.contains("request-1"));
    assert!(!request_debug.contains("idempotency-1"));
    assert!(!request_debug.contains("bounded"));
    assert!(!request_debug.contains("value"));
    assert!(request_debug.contains("x-public-mode"));

    let header = HttpHeader::new("x-visible-name", "private-value").unwrap();
    let header_debug = format!("{header:?}");
    assert!(header_debug.contains("x-visible-name"));
    assert!(!header_debug.contains("private-value"));

    let prepared = prepare_http_delivery(capability(), request(HttpMethod::Post)).unwrap();
    let prepared_debug = format!("{prepared:?}");
    assert!(!prepared_debug.contains("idempotency-1"));
    assert!(!prepared_debug.contains("bounded"));
    assert!(!prepared_debug.contains("value"));
}

#[test]
fn exact_replay_never_redispatches_and_changed_method_or_request_id_refuses() {
    let mut session = HttpDeliverySession::new(2).unwrap();
    let mut first_adapter = RecordingAdapter::returning(AdapterObservation::Response {
        status: 202,
        body: b"accepted-but-not-retained".to_vec(),
    });
    let prepared = prepare_http_delivery(capability(), request(HttpMethod::Post)).unwrap();
    let expected_request = prepared.request.clone();
    let first = session.reconcile(prepared, &mut first_adapter).unwrap();
    assert!(!first.was_replayed());
    assert_eq!(first_adapter.requests.len(), 1);

    let mut replay_adapter = RecordingAdapter::returning(AdapterObservation::DeadlineAfterStart);
    let replay = session
        .reconcile(
            prepare_http_delivery(capability(), request(HttpMethod::Post)).unwrap(),
            &mut replay_adapter,
        )
        .unwrap();
    assert!(replay.was_replayed());
    assert!(replay_adapter.requests.is_empty());
    assert_eq!(replay.evidence(), first.evidence());
    first
        .evidence()
        .replay(
            "deployment-http-v1",
            "invocation-http-1",
            "http-policy-v1",
            first.evidence().disposition(),
            &expected_request,
        )
        .unwrap();

    let mut changed = request(HttpMethod::Put);
    changed.body = request(HttpMethod::Post).body;
    let mut changed_adapter = RecordingAdapter::returning(AdapterObservation::Response {
        status: 204,
        body: Vec::new(),
    });
    assert_eq!(
        session.reconcile(
            prepare_http_delivery(capability(), changed).unwrap(),
            &mut changed_adapter,
        ),
        Err(HttpLedgerRefusal::Ledger(LedgerRefusal::ConflictingRequest))
    );
    assert!(changed_adapter.requests.is_empty());

    let mut changed_id = request(HttpMethod::Post);
    changed_id.request_id = "request-2".into();
    let mut changed_id_adapter = RecordingAdapter::returning(AdapterObservation::Response {
        status: 204,
        body: Vec::new(),
    });
    assert_eq!(
        session.reconcile(
            prepare_http_delivery(capability(), changed_id).unwrap(),
            &mut changed_id_adapter,
        ),
        Err(HttpLedgerRefusal::Ledger(LedgerRefusal::ConflictingRequest))
    );
    assert!(changed_id_adapter.requests.is_empty());
}

#[test]
fn response_and_panic_uncertainty_are_sticky_and_checkpointed() {
    let mut session = HttpDeliverySession::new(2).unwrap();
    let mut oversized_adapter = RecordingAdapter::returning(AdapterObservation::Response {
        status: 200,
        body: vec![0; 33],
    });
    let oversized = session
        .reconcile(
            prepare_http_delivery(capability(), request(HttpMethod::Post)).unwrap(),
            &mut oversized_adapter,
        )
        .unwrap();
    assert_eq!(
        oversized.evidence().disposition(),
        &DeliveryDisposition::ResponseTooLargeUncertain
    );
    let checkpoint = session.checkpoint().unwrap();
    session.verify_checkpoint(&checkpoint).unwrap();

    struct PanickingAdapter;
    impl OutboundAdapter for PanickingAdapter {
        fn send(&mut self, _: &PreparedRequest) -> AdapterObservation {
            panic!("fixture panic after adapter entry")
        }
    }
    let mut panic_session = HttpDeliverySession::new(1).unwrap();
    let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        panic_session.reconcile(
            prepare_http_delivery(capability(), request(HttpMethod::Post)).unwrap(),
            &mut PanickingAdapter,
        )
    }));
    assert!(panic.is_err());
    let mut replay_adapter = RecordingAdapter::returning(AdapterObservation::Response {
        status: 204,
        body: Vec::new(),
    });
    let replay = panic_session
        .reconcile(
            prepare_http_delivery(capability(), request(HttpMethod::Post)).unwrap(),
            &mut replay_adapter,
        )
        .unwrap();
    assert!(replay.was_replayed());
    assert!(replay_adapter.requests.is_empty());
    assert_eq!(
        replay.evidence().disposition(),
        &DeliveryDisposition::Uncertain {
            reason: AdapterFailure::Transport,
        }
    );
}
