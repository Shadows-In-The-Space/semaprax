use super::*;

#[derive(Default)]
struct Adapter {
    calls: Vec<PreparedRequest>,
}

impl OutboundAdapter for Adapter {
    fn send(&mut self, request: &PreparedRequest) -> AdapterObservation {
        self.calls.push(request.clone());
        AdapterObservation::FailedAfterStart {
            reason: AdapterFailure::Transport,
        }
    }
}

fn capability() -> OutboundCapability {
    capability_with_limit(4_096)
}

fn capability_with_limit(max_request_bytes: usize) -> OutboundCapability {
    OutboundCapability::grant_for_trusted_host(
        "trace-deployment",
        "trace-invocation",
        OutboundPolicy::new(
            "trace-policy",
            ["https://telemetry.example.test".into()],
            max_request_bytes,
            128,
            2_000,
            2,
            2,
        )
        .unwrap(),
    )
    .unwrap()
}

#[test]
fn trace_scoped_span_identity_dispatches_equal_span_ids_independently() {
    let mut session = SpanExportSession::new(2).unwrap();
    let mut adapter = Adapter::default();
    let first = span();
    let mut second = span();
    second.trace_id = "fedcba9876543210fedcba9876543210".into();
    session.reconcile(prepare(first), &mut adapter).unwrap();
    session.reconcile(prepare(second), &mut adapter).unwrap();
    assert_eq!(adapter.calls.len(), 2);
    assert_ne!(
        adapter.calls[0].headers()[1].1,
        adapter.calls[1].headers()[1].1
    );
}

#[test]
fn span_json_escaping_obeys_the_exact_policy_byte_cap() {
    let mut hostile = span();
    hostile.attributes = vec![ExportField {
        name: "message".into(),
        value: ExportFieldValue::Public("\"\\".repeat(32)),
    }];
    let generous = capability_with_limit(4_096);
    let exact = hostile.encode(&generous.policy).unwrap().len();
    assert!(prepare_span_export(
        capability_with_limit(exact),
        "https://telemetry.example.test/v1/spans".into(),
        1_000,
        hostile.clone(),
    )
    .is_ok());
    assert!(matches!(
        prepare_span_export(
            capability_with_limit(exact - 1),
            "https://telemetry.example.test/v1/spans".into(),
            1_000,
            hostile,
        ),
        Err(Refusal::RequestTooLarge)
    ));
}

fn span() -> SpanExport {
    SpanExport {
        trace_id: "0123456789abcdef0123456789abcdef".into(),
        span_id: "0123456789abcdef".into(),
        parent_span_id: Some("fedcba9876543210".into()),
        name: "checkout.authorize".into(),
        duration_micros: 42,
        status: SpanStatus::Error,
        attributes: vec![
            ExportField {
                name: "region".into(),
                value: ExportFieldValue::Public("eu".into()),
            },
            ExportField {
                name: "bearer_token".into(),
                value: ProtectedExportValue::from_host_bytes(b"span-secret".to_vec())
                    .unwrap()
                    .into_redacted(true),
            },
        ],
    }
}

fn prepare(span: SpanExport) -> PreparedSpanExport {
    prepare_span_export(
        capability(),
        "https://telemetry.example.test/v1/spans".into(),
        1_000,
        span,
    )
    .unwrap()
}

#[test]
fn typed_span_redacts_and_keeps_transport_failure_as_uncertain() {
    let mut session = SpanExportSession::new(1).unwrap();
    let mut adapter = Adapter::default();
    let receipt = session.reconcile(prepare(span()), &mut adapter).unwrap();
    assert_eq!(adapter.calls.len(), 1);
    assert!(matches!(
        receipt.evidence().disposition(),
        DeliveryDisposition::Uncertain {
            reason: AdapterFailure::Transport
        }
    ));
    assert_eq!(
        adapter.calls[0].headers()[0],
        (
            "content-type".into(),
            "application/vnd.semaprax.span.v1+json".into()
        )
    );
    let payload = std::str::from_utf8(adapter.calls[0].body()).unwrap();
    assert!(payload.contains("semaprax.operational-span.v1"));
    assert!(payload.contains("[REDACTED]"));
    assert!(payload.contains("sha256:"));
    assert!(!payload.contains("span-secret"));
    assert_eq!(
        verify_span_export(adapter.calls[0].body(), &adapter.calls[0]),
        Ok(())
    );
    assert!(!format!("{:?}{receipt:?}", adapter.calls[0]).contains("span-secret"));

    let mut replay_adapter = Adapter::default();
    assert!(session
        .reconcile(prepare(span()), &mut replay_adapter)
        .unwrap()
        .was_replayed());
    assert!(replay_adapter.calls.is_empty());
}

#[test]
fn span_wire_decoder_refuses_unknown_noncanonical_and_unbound_inputs() {
    let mut session = SpanExportSession::new(1).unwrap();
    let mut adapter = Adapter::default();
    session.reconcile(prepare(span()), &mut adapter).unwrap();
    let request = &adapter.calls[0];
    let mut unknown: serde_json::Value = serde_json::from_slice(request.body()).unwrap();
    unknown["unknown"] = serde_json::json!(true);
    assert_eq!(
        verify_span_export(&serde_json::to_vec(&unknown).unwrap(), request),
        Err(SpanWireMismatch::Schema)
    );
    let spaced = format!(" {}", std::str::from_utf8(request.body()).unwrap());
    assert_eq!(
        verify_span_export(spaced.as_bytes(), request),
        Err(SpanWireMismatch::NonCanonical)
    );
    let canonical = std::str::from_utf8(request.body()).unwrap();
    let duplicate = format!(r#"{{"schema":"duplicate",{}"#, &canonical[1..]);
    assert_eq!(
        verify_span_export(duplicate.as_bytes(), request),
        Err(SpanWireMismatch::NonCanonical)
    );
    let mut wrong_request = request.clone();
    wrong_request.headers[2].1 = "fedcba9876543210".into();
    assert_eq!(
        verify_span_export(request.body(), &wrong_request),
        Err(SpanWireMismatch::PreparedRequest)
    );
}

#[test]
fn malformed_untrusted_context_and_public_protected_attributes_refuse() {
    let mut cases = Vec::new();
    let mut uppercase = span();
    uppercase.trace_id = "A123456789abcdef0123456789abcdef".into();
    cases.push(uppercase);
    let mut zero = span();
    zero.span_id = "0000000000000000".into();
    cases.push(zero);
    let mut self_parent = span();
    self_parent.parent_span_id = Some(self_parent.span_id.clone());
    cases.push(self_parent);
    let mut injected_name = span();
    injected_name.name = "safe\nforged".into();
    cases.push(injected_name);
    let mut public_secret = span();
    public_secret.attributes = vec![ExportField {
        name: "authorization".into(),
        value: ExportFieldValue::Public("Bearer should-not-export".into()),
    }];
    cases.push(public_secret);

    for hostile in cases {
        assert!(matches!(
            prepare_span_export(
                capability(),
                "https://telemetry.example.test/v1/spans".into(),
                1_000,
                hostile,
            ),
            Err(Refusal::InvalidIdentity | Refusal::ProtectedValue)
        ));
    }
}

#[test]
fn span_attribute_and_session_maximum_plus_one_refuse() {
    let mut too_many = span();
    too_many.attributes.push(ExportField {
        name: "third".into(),
        value: ExportFieldValue::Public("value".into()),
    });
    assert!(matches!(
        prepare_span_export(
            capability(),
            "https://telemetry.example.test/v1/spans".into(),
            1_000,
            too_many,
        ),
        Err(Refusal::CardinalityExceeded)
    ));
    assert!(SpanExportSession::new(MAX_LEDGER_ENTRIES + 1).is_err());

    let mut overbound = span();
    overbound.attributes = vec![ExportField {
        name: "message".into(),
        value: ExportFieldValue::Public("x".repeat(MAX_EXPORT_VALUE_BYTES + 1)),
    }];
    assert!(matches!(
        prepare_span_export(
            capability(),
            "https://telemetry.example.test/v1/spans".into(),
            1_000,
            overbound,
        ),
        Err(Refusal::RequestTooLarge)
    ));
}
