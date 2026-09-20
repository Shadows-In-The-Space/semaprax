use super::*;

#[test]
fn legacy_post_request_digest_is_a_fixed_v1_known_answer() {
    let request = PreparedRequest {
        method: HttpMethod::Post,
        endpoint: "https://fixture.example.test/v1/events".into(),
        headers: vec![
            ("content-type".into(), "application/json".into()),
            ("idempotency-key".into(), "fixture-key-1".into()),
        ],
        body: br#"{"ok":true}"#.to_vec(),
        deadline_ms: 1_000,
        max_redirects: 0,
        max_response_bytes: 4_096,
    };
    assert_eq!(
        request_digest(&request),
        "sha256:a7492c353b236c2b7df6408dfff3a29f82d1da5d279deb5901f8b67ad05b07e5"
    );
    let mut non_post = request.clone();
    non_post.method = HttpMethod::Put;
    assert_ne!(request_digest(&non_post), request_digest(&request));
}

#[derive(Default)]
struct FixtureAdapter {
    calls: Vec<PreparedRequest>,
    next: Option<AdapterObservation>,
}

impl FixtureAdapter {
    fn returning(observation: AdapterObservation) -> Self {
        Self {
            calls: Vec::new(),
            next: Some(observation),
        }
    }
}

impl OutboundAdapter for FixtureAdapter {
    fn send(&mut self, request: &PreparedRequest) -> AdapterObservation {
        self.calls.push(request.clone());
        self.next
            .take()
            .expect("the boundary invokes a fixture at most once")
    }
}

fn policy() -> OutboundPolicy {
    OutboundPolicy::new(
        "deploy.outbound.v1",
        ["https://hooks.example.test".to_owned()],
        1_024,
        512,
        5_000,
        4,
        3,
    )
    .unwrap()
}

fn capability() -> OutboundCapability {
    OutboundCapability::grant_for_trusted_host("sha256:deployment", "invocation-7", policy())
        .unwrap()
}

fn webhook() -> WebhookRequest {
    WebhookRequest {
        endpoint: "https://hooks.example.test/events?tenant=one".into(),
        delivery_id: "delivery-1".into(),
        idempotency_key: "job-9:event-4".into(),
        content_type: "application/json".into(),
        body: br#"{"ok":true}"#.to_vec(),
        deadline_ms: 2_000,
    }
}

fn email_policy() -> OutboundPolicy {
    OutboundPolicy::new(
        "deploy.email.v1",
        ["https://email-provider.example.test".to_owned()],
        MAX_REQUEST_BODY_BYTES,
        MAX_RESPONSE_BODY_BYTES,
        MAX_DEADLINE_MS,
        MAX_EXPORT_FIELDS,
        MAX_EXPORT_LABELS,
    )
    .unwrap()
}

fn email_capability() -> OutboundCapability {
    OutboundCapability::grant_for_trusted_host("sha256:deployment", "invocation-7", email_policy())
        .unwrap()
}

fn email() -> EmailRequest {
    EmailRequest {
        endpoint: "https://email-provider.example.test/v1/send".into(),
        delivery_id: "mail-42".into(),
        idempotency_key: "job-9:mail-42".into(),
        sender: "sender@example.test".into(),
        recipients: vec!["zoe@example.test".into(), "amy@example.test".into()],
        reply_to: Some("reply@example.test".into()),
        subject: "Task complete".into(),
        body: b"done".to_vec(),
        attachments: vec![
            EmailAttachment {
                name: "z-last.txt".into(),
                media_type: "text/plain".into(),
                body: b"z".to_vec(),
            },
            EmailAttachment {
                name: "a-first.txt".into(),
                media_type: "text/plain".into(),
                body: b"a".to_vec(),
            },
        ],
        deadline_ms: 2_000,
    }
}

#[test]
fn webhook_is_signed_once_and_evidence_replays_against_exact_request() {
    let mut adapter = FixtureAdapter::returning(AdapterObservation::Response {
        status: 202,
        body: b"queued".to_vec(),
    });
    let result = deliver_webhook(
        capability(),
        WebhookSigningSecret::from_trusted_host_bytes([7; 32]),
        webhook(),
        &mut adapter,
    )
    .unwrap();
    assert_eq!(adapter.calls.len(), 1);
    let sent = &adapter.calls[0];
    assert_eq!(sent.endpoint, webhook().endpoint);
    assert_eq!(sent.body, webhook().body);
    assert_eq!(sent.max_redirects, 0);
    assert_eq!(sent.headers.len(), 4);
    assert_eq!(
        sent.headers[0],
        ("content-type".into(), "application/json".into())
    );
    assert_eq!(
        sent.headers[1],
        ("idempotency-key".into(), "job-9:event-4".into())
    );
    assert_eq!(
        sent.headers[2],
        ("x-semaprax-delivery-id".into(), "delivery-1".into())
    );
    assert_eq!(sent.headers[3].0, "x-semaprax-signature-v2");
    assert!(sent.headers[3].1.starts_with("hmac-sha256="));
    assert_eq!(sent.headers[3].1.len(), "hmac-sha256=".len() + 64);
    let debug_request = format!("{sent:?}");
    assert!(!debug_request.contains("{\"ok\":true}"));
    assert!(!debug_request.contains("tenant=one"));
    assert!(!debug_request.contains("job-9:event-4"));
    assert_eq!(result.response_body.as_deref(), Some(b"queued".as_slice()));
    assert_eq!(
        result.evidence.disposition(),
        &DeliveryDisposition::Accepted { status: 202 }
    );
    result
        .evidence
        .replay(
            "sha256:deployment",
            "invocation-7",
            "deploy.outbound.v1",
            result.evidence.disposition(),
            sent,
        )
        .unwrap();
    let wire = result.evidence.render();
    assert_eq!(
        DeliveryEvidence::decode_and_replay(
            wire.as_bytes(),
            "sha256:deployment",
            "invocation-7",
            "deploy.outbound.v1",
            result.evidence.disposition(),
            sent,
        )
        .unwrap(),
        result.evidence
    );

    let mut tampered = sent.clone();
    tampered.body.push(b'!');
    assert_eq!(
        result.evidence.replay(
            "sha256:deployment",
            "invocation-7",
            "deploy.outbound.v1",
            result.evidence.disposition(),
            &tampered,
        ),
        Err(EvidenceMismatch::Request)
    );
    assert_eq!(
        result.evidence.replay(
            "sha256:other",
            "invocation-7",
            "deploy.outbound.v1",
            result.evidence.disposition(),
            sent,
        ),
        Err(EvidenceMismatch::Binding)
    );
}

#[test]
fn every_policy_refusal_happens_before_adapter_dispatch() {
    let cases = [
        ("http://hooks.example.test/events", Refusal::InvalidEndpoint),
        (
            "https://hooks.example.test@evil.test/",
            Refusal::InvalidEndpoint,
        ),
        (
            "https://hooks.example.test/events#secret",
            Refusal::InvalidEndpoint,
        ),
        (
            "https://other.example.test/events",
            Refusal::AuthorityDenied,
        ),
    ];
    for (endpoint, expected) in cases {
        let mut request = webhook();
        request.endpoint = endpoint.into();
        let mut adapter = FixtureAdapter::returning(AdapterObservation::DeadlineAfterStart);
        assert_eq!(
            deliver_webhook(
                capability(),
                WebhookSigningSecret::from_trusted_host_bytes([7; 32]),
                request,
                &mut adapter,
            ),
            Err(expected),
            "{endpoint}"
        );
        assert!(adapter.calls.is_empty(), "{endpoint} reached the adapter");
    }

    let mut bad = webhook();
    bad.body = vec![0; 1_025];
    let mut adapter = FixtureAdapter::returning(AdapterObservation::DeadlineAfterStart);
    assert_eq!(
        deliver_webhook(
            capability(),
            WebhookSigningSecret::from_trusted_host_bytes([7; 32]),
            bad,
            &mut adapter,
        ),
        Err(Refusal::RequestTooLarge)
    );
    assert!(adapter.calls.is_empty());

    for deadline_ms in [0, 5_001] {
        let mut request = webhook();
        request.deadline_ms = deadline_ms;
        let mut adapter = FixtureAdapter::returning(AdapterObservation::DeadlineAfterStart);
        assert_eq!(
            deliver_webhook(
                capability(),
                WebhookSigningSecret::from_trusted_host_bytes([7; 32]),
                request,
                &mut adapter,
            ),
            Err(Refusal::InvalidDeadline)
        );
        assert!(adapter.calls.is_empty());
    }
}

#[test]
fn header_injection_and_identity_injection_are_refused_before_signing_or_send() {
    let mutations: Vec<(fn(&mut WebhookRequest), Refusal)> = vec![
        (
            |request| request.content_type = "application/json\r\nx-evil: yes".into(),
            Refusal::InvalidContentType,
        ),
        (
            |request| request.delivery_id = "delivery\nsecond".into(),
            Refusal::InvalidIdentity,
        ),
        (
            |request| request.idempotency_key = "key value".into(),
            Refusal::InvalidIdentity,
        ),
    ];
    for (mutate, expected) in mutations {
        let mut request = webhook();
        mutate(&mut request);
        let mut adapter = FixtureAdapter::returning(AdapterObservation::DeadlineAfterStart);
        assert_eq!(
            deliver_webhook(
                capability(),
                WebhookSigningSecret::from_trusted_host_bytes([9; 32]),
                request,
                &mut adapter,
            ),
            Err(expected)
        );
        assert!(adapter.calls.is_empty());
    }
}

#[test]
fn post_start_failures_and_overbound_responses_are_sticky_uncertain() {
    let observations = [
        AdapterObservation::FailedAfterStart {
            reason: AdapterFailure::Tls,
        },
        AdapterObservation::DeadlineAfterStart,
        AdapterObservation::Response {
            status: 200,
            body: vec![0; 513],
        },
    ];
    for observation in observations {
        let mut adapter = FixtureAdapter::returning(observation);
        let result = deliver_webhook(
            capability(),
            WebhookSigningSecret::from_trusted_host_bytes([7; 32]),
            webhook(),
            &mut adapter,
        )
        .unwrap();
        assert!(matches!(
            result.evidence.disposition(),
            DeliveryDisposition::Uncertain { .. }
                | DeliveryDisposition::DeadlineUncertain
                | DeliveryDisposition::ResponseTooLargeUncertain
        ));
        assert!(result.response_body.is_none());
        assert_eq!(adapter.calls.len(), 1);
    }
}

#[test]
fn exporter_sorts_fields_redacts_secrets_and_preserves_primary_failure() {
    let event = ExportEvent {
        stable_event_id: "app.payment.failed".into(),
        labels: vec![
            ("region".into(), "eu".into()),
            ("kind".into(), "card".into()),
        ],
        fields: vec![
            ExportField {
                name: "token".into(),
                value: ProtectedExportValue::from_host_bytes(b"actual-secret-token".to_vec())
                    .unwrap()
                    .into_redacted(true),
            },
            ExportField {
                name: "message".into(),
                value: ExportFieldValue::Public("declined".into()),
            },
        ],
    };
    let mut adapter = FixtureAdapter::returning(AdapterObservation::FailedAfterStart {
        reason: AdapterFailure::Transport,
    });
    let observed = export_after_primary(
        Err::<(), _>("primary database failure"),
        capability(),
        "https://hooks.example.test/collect".into(),
        1_000,
        event,
        &mut adapter,
    );
    assert_eq!(observed.primary, Err("primary database failure"));
    let exported = observed.export.unwrap();
    assert!(matches!(
        exported.evidence.disposition(),
        DeliveryDisposition::Uncertain { .. }
    ));
    let payload = std::str::from_utf8(&adapter.calls[0].body).unwrap();
    assert!(payload.contains("[REDACTED]"));
    assert!(!payload.contains("actual-secret-token"));
    assert!(payload.contains("sha256:"));
    assert!(payload.find("message").unwrap() < payload.find("token").unwrap());
    assert!(payload.find("kind").unwrap() < payload.find("region").unwrap());
}

#[test]
fn exporter_cardinality_and_duplicate_names_refuse_without_transport() {
    let events = [
        ExportEvent {
            stable_event_id: "event".into(),
            labels: vec![("same".into(), "one".into()), ("same".into(), "two".into())],
            fields: Vec::new(),
        },
        ExportEvent {
            stable_event_id: "event".into(),
            labels: (0..4)
                .map(|index| (format!("label{index}"), "x".into()))
                .collect(),
            fields: Vec::new(),
        },
        ExportEvent {
            stable_event_id: "event".into(),
            labels: Vec::new(),
            fields: vec![
                ExportField {
                    name: "same".into(),
                    value: ExportFieldValue::Public("a".into()),
                },
                ExportField {
                    name: "same".into(),
                    value: ExportFieldValue::Public("b".into()),
                },
            ],
        },
    ];
    for event in events {
        let mut adapter = FixtureAdapter::returning(AdapterObservation::DeadlineAfterStart);
        assert_eq!(
            export_event(
                capability(),
                "https://hooks.example.test/collect".into(),
                1_000,
                event,
                &mut adapter,
            ),
            Err(Refusal::CardinalityExceeded)
        );
        assert!(adapter.calls.is_empty());
    }
}

#[test]
fn exporter_refuses_member_and_aggregate_max_plus_one_before_dispatch() {
    let cases = [
        ExportEvent {
            stable_event_id: "event.member-overflow".into(),
            labels: Vec::new(),
            fields: vec![ExportField {
                name: "value".into(),
                value: ExportFieldValue::Public("x".repeat(MAX_EXPORT_VALUE_BYTES + 1)),
            }],
        },
        ExportEvent {
            stable_event_id: "event.aggregate-overflow".into(),
            labels: Vec::new(),
            fields: vec![
                ExportField {
                    name: "first".into(),
                    value: ExportFieldValue::Public("x".repeat(600)),
                },
                ExportField {
                    name: "second".into(),
                    value: ExportFieldValue::Public("y".repeat(600)),
                },
            ],
        },
        // Raw members fit the aggregate preflight, but JSON escaping would
        // exceed the request budget. The capped writer must refuse without
        // growing beyond that budget or calling the adapter.
        ExportEvent {
            stable_event_id: "event.escape-overflow".into(),
            labels: Vec::new(),
            fields: vec![ExportField {
                name: "slashes".into(),
                value: ExportFieldValue::Public("\\".repeat(900)),
            }],
        },
    ];
    for event in cases {
        let mut adapter = FixtureAdapter::returning(AdapterObservation::DeadlineAfterStart);
        assert_eq!(
            export_event(
                capability(),
                "https://hooks.example.test/collect".into(),
                1_000,
                event,
                &mut adapter,
            ),
            Err(Refusal::RequestTooLarge)
        );
        assert!(adapter.calls.is_empty());
    }
}

#[test]
fn exact_body_deadline_and_cardinality_limits_remain_admitted() {
    let mut request = webhook();
    request.body = vec![b'x'; 1_024];
    request.deadline_ms = 5_000;
    let mut adapter = FixtureAdapter::returning(AdapterObservation::Response {
        status: 200,
        body: vec![b'y'; 512],
    });
    assert!(deliver_webhook(
        capability(),
        WebhookSigningSecret::from_trusted_host_bytes([8; 32]),
        request,
        &mut adapter,
    )
    .is_ok());

    let event = ExportEvent {
        stable_event_id: "event.maximum".into(),
        labels: (0..3)
            .map(|index| (format!("label{index}"), "x".into()))
            .collect(),
        fields: (0..4)
            .map(|index| ExportField {
                name: format!("field{index}"),
                value: ExportFieldValue::Public("x".into()),
            })
            .collect(),
    };
    let mut adapter = FixtureAdapter::returning(AdapterObservation::Response {
        status: 200,
        body: Vec::new(),
    });
    assert!(export_event(
        capability(),
        "https://hooks.example.test/collect".into(),
        5_000,
        event,
        &mut adapter,
    )
    .is_ok());
}

#[test]
fn signature_binds_delivery_identity_and_payload_without_exposing_key() {
    assert_eq!(
        format!(
            "{:?}",
            WebhookSigningSecret::from_trusted_host_bytes([0x41; 32])
        ),
        "WebhookSigningSecret([REDACTED])"
    );
    let mut first = FixtureAdapter::returning(AdapterObservation::NotDispatched {
        reason: AdapterFailure::PolicyRejected,
    });
    let mut second = FixtureAdapter::returning(AdapterObservation::NotDispatched {
        reason: AdapterFailure::PolicyRejected,
    });
    let mut third = FixtureAdapter::returning(AdapterObservation::NotDispatched {
        reason: AdapterFailure::PolicyRejected,
    });
    deliver_webhook(
        capability(),
        WebhookSigningSecret::from_trusted_host_bytes([3; 32]),
        webhook(),
        &mut first,
    )
    .unwrap();
    let mut changed = webhook();
    changed.delivery_id = "delivery-2".into();
    deliver_webhook(
        capability(),
        WebhookSigningSecret::from_trusted_host_bytes([3; 32]),
        changed,
        &mut second,
    )
    .unwrap();
    assert_ne!(first.calls[0].headers[3], second.calls[0].headers[3]);

    let mut changed = webhook();
    changed.idempotency_key = "job-9:event-5".into();
    deliver_webhook(
        capability(),
        WebhookSigningSecret::from_trusted_host_bytes([3; 32]),
        changed,
        &mut third,
    )
    .unwrap();
    assert_ne!(first.calls[0].headers[3], third.calls[0].headers[3]);
}

#[test]
fn signature_binds_post_origin_target_and_deployment() {
    fn authority(origin: &str, deployment: &str) -> OutboundCapability {
        let policy = OutboundPolicy::new(
            "deploy.outbound.v1",
            [origin.to_owned()],
            1_024,
            512,
            5_000,
            4,
            3,
        )
        .unwrap();
        OutboundCapability::grant_for_trusted_host(deployment, "invocation-7", policy).unwrap()
    }

    let cases = [
        (
            authority("https://hooks.example.test", "sha256:deployment"),
            "https://hooks.example.test/events?tenant=one",
        ),
        (
            authority("https://hooks-two.example.test", "sha256:deployment"),
            "https://hooks-two.example.test/events?tenant=one",
        ),
        (
            authority("https://hooks.example.test", "sha256:deployment"),
            "https://hooks.example.test/other?tenant=one",
        ),
        (
            authority("https://hooks.example.test", "sha256:other-deployment"),
            "https://hooks.example.test/events?tenant=one",
        ),
    ];
    let mut signatures = Vec::new();
    for (capability, endpoint) in cases {
        let mut request = webhook();
        request.endpoint = endpoint.into();
        let mut adapter = FixtureAdapter::returning(AdapterObservation::NotDispatched {
            reason: AdapterFailure::PolicyRejected,
        });
        deliver_webhook(
            capability,
            WebhookSigningSecret::from_trusted_host_bytes([3; 32]),
            request,
            &mut adapter,
        )
        .unwrap();
        signatures.push(adapter.calls[0].headers[3].1.clone());
    }
    let distinct = signatures.iter().collect::<std::collections::BTreeSet<_>>();
    assert_eq!(distinct.len(), signatures.len());
}

#[test]
fn evidence_decoder_refuses_noncanonical_unknown_and_drifted_inputs() {
    let mut adapter = FixtureAdapter::returning(AdapterObservation::Response {
        status: 204,
        body: Vec::new(),
    });
    let result = deliver_webhook(
        capability(),
        WebhookSigningSecret::from_trusted_host_bytes([4; 32]),
        webhook(),
        &mut adapter,
    )
    .unwrap();
    let sent = &adapter.calls[0];
    let wire = result.evidence.render();

    let spaced = format!(" {wire}");
    assert_eq!(
        DeliveryEvidence::decode_and_replay(
            spaced.as_bytes(),
            "sha256:deployment",
            "invocation-7",
            "deploy.outbound.v1",
            result.evidence.disposition(),
            sent,
        ),
        Err(EvidenceMismatch::NonCanonical)
    );
    let mut extra: serde_json::Value = serde_json::from_str(&wire).unwrap();
    extra["unexpected"] = serde_json::json!(true);
    assert_eq!(
        DeliveryEvidence::decode_and_replay(
            serde_json::to_string(&extra).unwrap().as_bytes(),
            "sha256:deployment",
            "invocation-7",
            "deploy.outbound.v1",
            result.evidence.disposition(),
            sent,
        ),
        Err(EvidenceMismatch::Malformed)
    );
    assert_eq!(
        DeliveryEvidence::decode_and_replay(
            wire.as_bytes(),
            "sha256:deployment",
            "invocation-7",
            "different-policy",
            result.evidence.disposition(),
            sent,
        ),
        Err(EvidenceMismatch::Policy)
    );
    let mut drifted: serde_json::Value = serde_json::from_str(&wire).unwrap();
    drifted["delivery_id"] = serde_json::json!("different-delivery");
    let drifted = serde_json::to_string(&drifted).unwrap();
    assert_eq!(
        DeliveryEvidence::decode_and_replay(
            drifted.as_bytes(),
            "sha256:deployment",
            "invocation-7",
            "deploy.outbound.v1",
            result.evidence.disposition(),
            sent,
        ),
        Err(EvidenceMismatch::Settlement)
    );
    assert_eq!(
        DeliveryEvidence::decode_and_replay(
            &vec![b'x'; MAX_EVIDENCE_BYTES + 1],
            "sha256:deployment",
            "invocation-7",
            "deploy.outbound.v1",
            result.evidence.disposition(),
            sent,
        ),
        Err(EvidenceMismatch::Malformed)
    );
}

#[test]
fn default_port_is_canonical_but_redirect_authority_is_never_inferred() {
    assert_eq!(
        canonical_origin("https://EXAMPLE.test:443/path"),
        Some("https://example.test".into())
    );
    assert_eq!(canonical_origin("https://example.test:0443/path"), None);
    assert_eq!(
        canonical_origin("https://example.test:444/path"),
        Some("https://example.test:444".into())
    );
    assert_eq!(canonical_origin("https://example.test/path#fragment"), None);
    assert_eq!(canonical_origin("https://bad..example/path"), None);
    assert_eq!(canonical_origin("https://-bad.example/path"), None);
    assert_eq!(canonical_origin("https://[not-ipv6]/path"), None);
    assert_eq!(canonical_origin("https://example.test/a/../b"), None);
    assert_eq!(canonical_origin("https://example.test/%2e%2e/b"), None);
    assert_eq!(
        canonical_origin("https://example.test/%41"),
        Some("https://example.test".into())
    );
}

#[test]
fn email_envelope_is_canonical_replayable_and_redacted_from_debug() {
    let mut adapter = FixtureAdapter::returning(AdapterObservation::Response {
        status: 202,
        body: b"queued".to_vec(),
    });
    let result = deliver_email(email_capability(), email(), &mut adapter).unwrap();
    assert_eq!(adapter.calls.len(), 1);
    let sent = &adapter.calls[0];
    assert_eq!(sent.endpoint, "https://email-provider.example.test/v1/send");
    assert_eq!(sent.max_redirects, 0);
    assert_eq!(
        sent.headers,
        vec![
            (
                "content-type".into(),
                "application/vnd.semaprax.email.v1+json".into(),
            ),
            ("idempotency-key".into(), "job-9:mail-42".into()),
            ("x-semaprax-delivery-id".into(), "mail-42".into()),
        ]
    );
    let envelope: serde_json::Value = serde_json::from_slice(&sent.body).unwrap();
    assert_eq!(
        envelope,
        serde_json::json!({
            "attachments": [
                {"body_hex": "7a", "media_type": "text/plain", "name": "z-last.txt"},
                {"body_hex": "61", "media_type": "text/plain", "name": "a-first.txt"},
            ],
            "body_hex": "646f6e65",
            "recipients": ["zoe@example.test", "amy@example.test"],
            "reply_to": "reply@example.test",
            "schema": "semaprax.outbound.email-request.v1",
            "sender": "sender@example.test",
            "subject": "Task complete",
        })
    );
    let request_debug = format!("{:?}", email());
    assert!(!request_debug.contains("sender@example.test"));
    assert!(!request_debug.contains("Task complete"));
    assert!(!request_debug.contains("done"));
    let evidence_debug = format!("{:?}", result.evidence);
    assert!(!evidence_debug.contains("sender@example.test"));
    assert!(!evidence_debug.contains("Task complete"));
    assert_eq!(
        DeliveryEvidence::decode_and_replay(
            result.evidence.render().as_bytes(),
            "sha256:deployment",
            "invocation-7",
            "deploy.email.v1",
            result.evidence.disposition(),
            sent,
        ),
        Ok(result.evidence.clone())
    );
    assert_eq!(verify_email_envelope(&sent.body, sent), Ok(()));

    let canonical = String::from_utf8(sent.body.clone()).unwrap();
    let value: serde_json::Value = serde_json::from_str(&canonical).unwrap();
    let reordered = format!(
        r#"{{"schema":{},"attachments":{},"body_hex":{},"recipients":{},"reply_to":{},"sender":{},"subject":{}}}"#,
        serde_json::to_string(&value["schema"]).unwrap(),
        serde_json::to_string(&value["attachments"]).unwrap(),
        serde_json::to_string(&value["body_hex"]).unwrap(),
        serde_json::to_string(&value["recipients"]).unwrap(),
        serde_json::to_string(&value["reply_to"]).unwrap(),
        serde_json::to_string(&value["sender"]).unwrap(),
        serde_json::to_string(&value["subject"]).unwrap(),
    );
    assert_eq!(
        verify_email_envelope(reordered.as_bytes(), sent),
        Err(EmailEnvelopeMismatch::NonCanonical)
    );
    let duplicate_schema = format!(
        r#"{{"schema":"semaprax.outbound.email-request.v1",{}"#,
        &canonical[1..]
    );
    assert_eq!(
        verify_email_envelope(duplicate_schema.as_bytes(), sent),
        Err(EmailEnvelopeMismatch::NonCanonical)
    );
    let mut unknown = value.clone();
    unknown["unknown"] = serde_json::json!(true);
    assert_eq!(
        verify_email_envelope(&serde_json::to_vec(&unknown).unwrap(), sent),
        Err(EmailEnvelopeMismatch::Malformed)
    );
    let mut uppercase_hex = value.clone();
    uppercase_hex["body_hex"] = serde_json::json!("646F6E65");
    assert_eq!(
        verify_email_envelope(&serde_json::to_vec(&uppercase_hex).unwrap(), sent),
        Err(EmailEnvelopeMismatch::Malformed)
    );
    let mut short_hex = serde_json::from_str::<serde_json::Value>(&canonical).unwrap();
    short_hex["body_hex"] = serde_json::json!("0");
    assert_eq!(
        verify_email_envelope(&serde_json::to_vec(&short_hex).unwrap(), sent),
        Err(EmailEnvelopeMismatch::Bound)
    );
    let mut nonhex = short_hex;
    nonhex["body_hex"] = serde_json::json!("gg");
    assert_eq!(
        verify_email_envelope(&serde_json::to_vec(&nonhex).unwrap(), sent),
        Err(EmailEnvelopeMismatch::Malformed)
    );
    let mut overbound_hex = value;
    overbound_hex["body_hex"] = serde_json::json!("00".repeat(MAX_EMAIL_BODY_BYTES + 1));
    assert_eq!(
        verify_email_envelope(&serde_json::to_vec(&overbound_hex).unwrap(), sent),
        Err(EmailEnvelopeMismatch::Bound)
    );
    let mut wrong_prepared = sent.clone();
    wrong_prepared.headers[0].1 = "application/json".into();
    assert_eq!(
        verify_email_envelope(&sent.body, &wrong_prepared),
        Err(EmailEnvelopeMismatch::PreparedRequest)
    );
}

#[test]
fn email_refuses_every_unadmitted_envelope_part_before_dispatch() {
    let cases: Vec<(EmailRequest, Refusal)> = vec![
        (
            EmailRequest {
                sender: "sender@localhost".into(),
                ..email()
            },
            Refusal::InvalidEmail,
        ),
        (
            EmailRequest {
                sender: "sender name@example.test".into(),
                ..email()
            },
            Refusal::InvalidEmail,
        ),
        (
            EmailRequest {
                sender: "first..last@example.test".into(),
                ..email()
            },
            Refusal::InvalidEmail,
        ),
        (
            EmailRequest {
                sender: ".first@example.test".into(),
                ..email()
            },
            Refusal::InvalidEmail,
        ),
        (
            EmailRequest {
                sender: "first.@example.test".into(),
                ..email()
            },
            Refusal::InvalidEmail,
        ),
        (
            EmailRequest {
                sender: "first@example..test".into(),
                ..email()
            },
            Refusal::InvalidEmail,
        ),
        (
            EmailRequest {
                sender: "first@-example.test".into(),
                ..email()
            },
            Refusal::InvalidEmail,
        ),
        (
            EmailRequest {
                sender: "first@example-.test".into(),
                ..email()
            },
            Refusal::InvalidEmail,
        ),
        (
            EmailRequest {
                sender: "first@exam_ple.test".into(),
                ..email()
            },
            Refusal::InvalidEmail,
        ),
        (
            EmailRequest {
                sender: "fïrst@example.test".into(),
                ..email()
            },
            Refusal::InvalidEmail,
        ),
        (
            EmailRequest {
                recipients: Vec::new(),
                ..email()
            },
            Refusal::InvalidEmail,
        ),
        (
            EmailRequest {
                recipients: (0..MAX_EMAIL_RECIPIENTS + 1)
                    .map(|index| format!("recipient-{index}@example.test"))
                    .collect(),
                ..email()
            },
            Refusal::InvalidEmail,
        ),
        (
            EmailRequest {
                recipients: vec!["same@example.test".into(), "same@example.test".into()],
                ..email()
            },
            Refusal::CardinalityExceeded,
        ),
        (
            EmailRequest {
                recipients: vec!["recipient@example.test\r\nBcc: other@example.test".into()],
                ..email()
            },
            Refusal::InvalidEmail,
        ),
        (
            EmailRequest {
                reply_to: Some("reply@example.test\0hidden".into()),
                ..email()
            },
            Refusal::InvalidEmail,
        ),
        (
            EmailRequest {
                subject: "ok\r\nBcc: other@example.test".into(),
                ..email()
            },
            Refusal::InvalidEmail,
        ),
        (
            EmailRequest {
                subject: "ok\u{001f}hidden".into(),
                ..email()
            },
            Refusal::InvalidEmail,
        ),
        (
            EmailRequest {
                body: vec![0; MAX_EMAIL_BODY_BYTES + 1],
                ..email()
            },
            Refusal::RequestTooLarge,
        ),
        (
            EmailRequest {
                attachments: (0..MAX_EMAIL_ATTACHMENTS + 1)
                    .map(|index| EmailAttachment {
                        name: format!("file-{index}.txt"),
                        media_type: "text/plain".into(),
                        body: Vec::new(),
                    })
                    .collect(),
                ..email()
            },
            Refusal::RequestTooLarge,
        ),
        // Aggregate bounds precede member grammar: an overlarge hostile list
        // must not spend time evaluating every bad member first.
        (
            EmailRequest {
                attachments: (0..MAX_EMAIL_ATTACHMENTS + 1)
                    .map(|_| EmailAttachment {
                        name: "../poison".into(),
                        media_type: "not a media type".into(),
                        body: Vec::new(),
                    })
                    .collect(),
                ..email()
            },
            Refusal::RequestTooLarge,
        ),
        (
            EmailRequest {
                attachments: vec![EmailAttachment {
                    name: "../escape.txt".into(),
                    media_type: "text/plain".into(),
                    body: Vec::new(),
                }],
                ..email()
            },
            Refusal::InvalidEmail,
        ),
        (
            EmailRequest {
                attachments: vec![EmailAttachment {
                    name: "body.txt".into(),
                    media_type: "text/plain\r\nX-Evil: yes".into(),
                    body: Vec::new(),
                }],
                ..email()
            },
            Refusal::InvalidEmail,
        ),
        (
            EmailRequest {
                attachments: vec![EmailAttachment {
                    name: "body.txt".into(),
                    media_type: "text/plain".into(),
                    body: vec![0; MAX_EMAIL_ATTACHMENT_BYTES + 1],
                }],
                ..email()
            },
            Refusal::RequestTooLarge,
        ),
        (
            EmailRequest {
                attachments: vec![
                    EmailAttachment {
                        name: "same.txt".into(),
                        media_type: "text/plain".into(),
                        body: Vec::new(),
                    },
                    EmailAttachment {
                        name: "same.txt".into(),
                        media_type: "text/plain".into(),
                        body: Vec::new(),
                    },
                ],
                ..email()
            },
            Refusal::CardinalityExceeded,
        ),
    ];
    for (request, expected) in cases {
        let mut adapter = FixtureAdapter::returning(AdapterObservation::DeadlineAfterStart);
        assert_eq!(
            deliver_email(email_capability(), request, &mut adapter),
            Err(expected)
        );
        assert!(adapter.calls.is_empty());
    }
}

#[test]
fn email_exact_limits_are_admitted_once_and_started_failures_stay_uncertain() {
    let mut exact = email();
    exact.subject = "s".repeat(MAX_EMAIL_SUBJECT_BYTES);
    exact.body = vec![b'b'; MAX_EMAIL_BODY_BYTES];
    exact.recipients = (0..MAX_EMAIL_RECIPIENTS)
        .map(|index| format!("recipient-{index}@example.test"))
        .collect();
    exact.attachments = (0..MAX_EMAIL_ATTACHMENTS)
        .map(|index| EmailAttachment {
            name: format!("attachment-{index}.txt"),
            media_type: "text/plain".into(),
            body: vec![b'a'; MAX_EMAIL_ATTACHMENT_BYTES],
        })
        .collect();
    let mut adapter = FixtureAdapter::returning(AdapterObservation::Response {
        status: 200,
        body: vec![b'o'; MAX_RESPONSE_BODY_BYTES],
    });
    let result = deliver_email(email_capability(), exact, &mut adapter).unwrap();
    assert!(matches!(
        result.evidence.disposition(),
        DeliveryDisposition::Accepted { status: 200 }
    ));
    assert_eq!(adapter.calls.len(), 1);

    let tiny_policy = OutboundPolicy::new(
        "deploy.email.tiny",
        ["https://email-provider.example.test".to_owned()],
        64,
        MAX_RESPONSE_BODY_BYTES,
        MAX_DEADLINE_MS,
        MAX_EXPORT_FIELDS,
        MAX_EXPORT_LABELS,
    )
    .unwrap();
    let tiny_capability = OutboundCapability::grant_for_trusted_host(
        "sha256:deployment",
        "invocation-7",
        tiny_policy,
    )
    .unwrap();
    let mut adapter = FixtureAdapter::returning(AdapterObservation::DeadlineAfterStart);
    assert_eq!(
        deliver_email(tiny_capability, email(), &mut adapter),
        Err(Refusal::RequestTooLarge)
    );
    assert!(adapter.calls.is_empty());

    let mut adapter = FixtureAdapter::returning(AdapterObservation::DeadlineAfterStart);
    let result = deliver_email(email_capability(), email(), &mut adapter).unwrap();
    assert_eq!(
        result.evidence.disposition(),
        &DeliveryDisposition::DeadlineUncertain
    );
    assert_eq!(adapter.calls.len(), 1);
}

#[test]
fn email_ledger_session_replays_exact_disposition_without_provider_response_bytes() {
    let mut session = EmailDeliverySession::new(2).unwrap();
    let mut first_adapter = FixtureAdapter::returning(AdapterObservation::Response {
        status: 202,
        body: b"provider-private-queued-token".to_vec(),
    });
    let first = session
        .reconcile(
            prepare_email_delivery(email_capability(), email()).unwrap(),
            &mut first_adapter,
        )
        .unwrap();
    assert_eq!(first_adapter.calls.len(), 1);
    assert!(!first.was_replayed());
    assert_eq!(
        first.evidence().disposition(),
        &DeliveryDisposition::Accepted { status: 202 }
    );
    let first_wire = first.evidence().render();
    assert!(!format!("{first:?}").contains("provider-private-queued-token"));

    let mut replay_adapter = FixtureAdapter::returning(AdapterObservation::DeadlineAfterStart);
    let replay = session
        .reconcile(
            prepare_email_delivery(email_capability(), email()).unwrap(),
            &mut replay_adapter,
        )
        .unwrap();
    assert!(replay.was_replayed());
    assert!(replay_adapter.calls.is_empty());
    assert_eq!(replay.evidence().render(), first_wire);
    assert_eq!(session.len(), 1);
}

#[test]
fn email_ledger_session_refuses_changed_requests_and_policy_drift_before_dispatch() {
    let mut session = EmailDeliverySession::new(2).unwrap();
    let mut first_adapter = FixtureAdapter::returning(AdapterObservation::Response {
        status: 204,
        body: Vec::new(),
    });
    session
        .reconcile(
            prepare_email_delivery(email_capability(), email()).unwrap(),
            &mut first_adapter,
        )
        .unwrap();

    let mut changed = email();
    changed.body.push(b'!');
    let mut changed_adapter = FixtureAdapter::returning(AdapterObservation::DeadlineAfterStart);
    assert_eq!(
        session.reconcile(
            prepare_email_delivery(email_capability(), changed).unwrap(),
            &mut changed_adapter,
        ),
        Err(EmailLedgerRefusal::Ledger(
            LedgerRefusal::ConflictingRequest
        ))
    );
    assert!(changed_adapter.calls.is_empty());

    // A host-owned policy label is not assumed content-addressed. This changes
    // an effective policy field while retaining the exact same label and
    // prepared request, so only the complete policy commitment can reject it.
    let drifted_policy = OutboundPolicy::new(
        "deploy.email.v1",
        ["https://email-provider.example.test".to_owned()],
        MAX_REQUEST_BODY_BYTES,
        MAX_RESPONSE_BODY_BYTES,
        MAX_DEADLINE_MS,
        MAX_EXPORT_FIELDS - 1,
        MAX_EXPORT_LABELS,
    )
    .unwrap();
    let drifted_capability = OutboundCapability::grant_for_trusted_host(
        "sha256:deployment",
        "invocation-7",
        drifted_policy,
    )
    .unwrap();
    let mut drifted_adapter = FixtureAdapter::returning(AdapterObservation::DeadlineAfterStart);
    assert_eq!(
        session.reconcile(
            prepare_email_delivery(drifted_capability, email()).unwrap(),
            &mut drifted_adapter,
        ),
        Err(EmailLedgerRefusal::PolicyChanged)
    );
    assert!(drifted_adapter.calls.is_empty());
}

struct PanickingEmailAdapter;

impl OutboundAdapter for PanickingEmailAdapter {
    fn send(&mut self, _request: &PreparedRequest) -> AdapterObservation {
        panic!("simulated adapter unwind after physical start")
    }
}

#[test]
fn email_ledger_session_keeps_an_unwinding_attempt_sticky_without_retry() {
    let mut session = EmailDeliverySession::new(1).unwrap();
    let unwind = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let mut adapter = PanickingEmailAdapter;
        let _ = session.reconcile(
            prepare_email_delivery(email_capability(), email()).unwrap(),
            &mut adapter,
        );
    }));
    assert!(unwind.is_err());
    assert_eq!(session.len(), 1);

    let mut retry_adapter = FixtureAdapter::returning(AdapterObservation::Response {
        status: 204,
        body: Vec::new(),
    });
    let replay = session
        .reconcile(
            prepare_email_delivery(email_capability(), email()).unwrap(),
            &mut retry_adapter,
        )
        .unwrap();
    assert!(replay.was_replayed());
    assert_eq!(
        replay.evidence().disposition(),
        &DeliveryDisposition::Uncertain {
            reason: AdapterFailure::Transport,
        }
    );
    assert!(retry_adapter.calls.is_empty());
}

#[test]
fn webhook_ledger_session_replays_exact_disposition_without_response_or_redispatch() {
    let mut session = WebhookDeliverySession::new(2).unwrap();
    let mut first_adapter = FixtureAdapter::returning(AdapterObservation::Response {
        status: 202,
        body: b"provider-private-receipt".to_vec(),
    });
    let first = session
        .reconcile(
            prepare_webhook_delivery(
                capability(),
                WebhookSigningSecret::from_trusted_host_bytes([7; 32]),
                webhook(),
            )
            .unwrap(),
            &mut first_adapter,
        )
        .unwrap();
    assert_eq!(first_adapter.calls.len(), 1);
    assert!(!first.was_replayed());
    assert_eq!(
        first.evidence().disposition(),
        &DeliveryDisposition::Accepted { status: 202 }
    );
    let first_wire = first.evidence().render();
    assert!(!format!("{first:?}").contains("provider-private-receipt"));

    let mut replay_adapter = FixtureAdapter::returning(AdapterObservation::DeadlineAfterStart);
    let replay = session
        .reconcile(
            prepare_webhook_delivery(
                capability(),
                WebhookSigningSecret::from_trusted_host_bytes([7; 32]),
                webhook(),
            )
            .unwrap(),
            &mut replay_adapter,
        )
        .unwrap();
    assert!(replay.was_replayed());
    assert!(replay_adapter.calls.is_empty());
    assert_eq!(replay.evidence().render(), first_wire);
    assert_eq!(session.len(), 1);
}

#[test]
fn webhook_ledger_refuses_payload_secret_and_policy_drift_before_dispatch() {
    let mut session = WebhookDeliverySession::new(2).unwrap();
    let mut first_adapter = FixtureAdapter::returning(AdapterObservation::Response {
        status: 204,
        body: Vec::new(),
    });
    session
        .reconcile(
            prepare_webhook_delivery(
                capability(),
                WebhookSigningSecret::from_trusted_host_bytes([7; 32]),
                webhook(),
            )
            .unwrap(),
            &mut first_adapter,
        )
        .unwrap();

    let mut changed = webhook();
    changed.body.push(b'!');
    let mut changed_adapter = FixtureAdapter::returning(AdapterObservation::DeadlineAfterStart);
    assert_eq!(
        session.reconcile(
            prepare_webhook_delivery(
                capability(),
                WebhookSigningSecret::from_trusted_host_bytes([7; 32]),
                changed,
            )
            .unwrap(),
            &mut changed_adapter,
        ),
        Err(WebhookLedgerRefusal::Ledger(
            LedgerRefusal::ConflictingRequest
        ))
    );
    assert!(changed_adapter.calls.is_empty());

    // The signature is part of the exact prepared request, so replacing the
    // deployment-selected secret cannot silently replay another key's result.
    let mut secret_adapter = FixtureAdapter::returning(AdapterObservation::DeadlineAfterStart);
    assert_eq!(
        session.reconcile(
            prepare_webhook_delivery(
                capability(),
                WebhookSigningSecret::from_trusted_host_bytes([8; 32]),
                webhook(),
            )
            .unwrap(),
            &mut secret_adapter,
        ),
        Err(WebhookLedgerRefusal::Ledger(
            LedgerRefusal::ConflictingRequest
        ))
    );
    assert!(secret_adapter.calls.is_empty());

    let drifted_policy = OutboundPolicy::new(
        "deploy.outbound.v1",
        ["https://hooks.example.test".to_owned()],
        1_024,
        512,
        5_000,
        3,
        3,
    )
    .unwrap();
    let drifted_capability = OutboundCapability::grant_for_trusted_host(
        "sha256:deployment",
        "invocation-7",
        drifted_policy,
    )
    .unwrap();
    let mut drifted_adapter = FixtureAdapter::returning(AdapterObservation::DeadlineAfterStart);
    assert_eq!(
        session.reconcile(
            prepare_webhook_delivery(
                drifted_capability,
                WebhookSigningSecret::from_trusted_host_bytes([7; 32]),
                webhook(),
            )
            .unwrap(),
            &mut drifted_adapter,
        ),
        Err(WebhookLedgerRefusal::PolicyChanged)
    );
    assert!(drifted_adapter.calls.is_empty());
}

struct PanickingWebhookAdapter;

impl OutboundAdapter for PanickingWebhookAdapter {
    fn send(&mut self, _request: &PreparedRequest) -> AdapterObservation {
        panic!("simulated webhook adapter unwind after physical start")
    }
}

#[test]
fn webhook_ledger_keeps_unwind_sticky_and_capacity_precedes_dispatch() {
    let mut session = WebhookDeliverySession::new(1).unwrap();
    let unwind = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let mut adapter = PanickingWebhookAdapter;
        let _ = session.reconcile(
            prepare_webhook_delivery(
                capability(),
                WebhookSigningSecret::from_trusted_host_bytes([7; 32]),
                webhook(),
            )
            .unwrap(),
            &mut adapter,
        );
    }));
    assert!(unwind.is_err());
    assert_eq!(session.len(), 1);

    let mut retry_adapter = FixtureAdapter::returning(AdapterObservation::Response {
        status: 204,
        body: Vec::new(),
    });
    let replay = session
        .reconcile(
            prepare_webhook_delivery(
                capability(),
                WebhookSigningSecret::from_trusted_host_bytes([7; 32]),
                webhook(),
            )
            .unwrap(),
            &mut retry_adapter,
        )
        .unwrap();
    assert!(replay.was_replayed());
    assert_eq!(
        replay.evidence().disposition(),
        &DeliveryDisposition::Uncertain {
            reason: AdapterFailure::Transport,
        }
    );
    assert!(retry_adapter.calls.is_empty());

    let mut second = webhook();
    second.idempotency_key = "job-9:event-5".into();
    second.delivery_id = "delivery-2".into();
    let mut capacity_adapter = FixtureAdapter::returning(AdapterObservation::Response {
        status: 204,
        body: Vec::new(),
    });
    assert_eq!(
        session.reconcile(
            prepare_webhook_delivery(
                capability(),
                WebhookSigningSecret::from_trusted_host_bytes([7; 32]),
                second,
            )
            .unwrap(),
            &mut capacity_adapter,
        ),
        Err(WebhookLedgerRefusal::Ledger(
            LedgerRefusal::CapacityExceeded
        ))
    );
    assert!(capacity_adapter.calls.is_empty());
}
