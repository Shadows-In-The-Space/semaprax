use super::*;
use crate::outbound_host_adapter::AdapterFailure;
use std::panic::{catch_unwind, AssertUnwindSafe};

fn identity(n: usize) -> DeliveryIdentity {
    DeliveryIdentity::new(
        "private-deployment",
        format!("private-invocation-{n}"),
        format!("private-key-{n}"),
    )
    .unwrap()
}

fn request(n: usize) -> PreparedRequest {
    PreparedRequest {
        endpoint: "https://private.example.test/mail".into(),
        headers: vec![("idempotency-key".into(), format!("private-key-{n}"))],
        body: b"private-email-or-webhook-or-tracing-content".to_vec(),
        deadline_ms: 1000,
        max_redirects: 0,
        max_response_bytes: 128,
    }
}

fn record(ledger: &mut HostDeliveryLedger, n: usize, disposition: DeliveryDisposition) {
    ledger
        .reconcile(identity(n), &request(n), |_| disposition)
        .unwrap();
}

fn decode(checkpoint: &LedgerCheckpoint) -> LedgerCheckpoint {
    LedgerCheckpoint::decode(checkpoint.render().as_bytes(), &checkpoint.digest()).unwrap()
}

fn decode_hostile(value: serde_json::Value) -> Result<LedgerCheckpoint, LedgerCheckpointRefusal> {
    let wire = serde_json::to_vec(&value).unwrap();
    LedgerCheckpoint::decode(&wire, &wire_digest(&wire))
}

#[test]
fn canonical_checkpoint_round_trips_all_dispositions_without_private_material() {
    let cases = [
        DeliveryDisposition::Accepted { status: 202 },
        DeliveryDisposition::Rejected { status: 429 },
        DeliveryDisposition::NotDispatched {
            reason: AdapterFailure::PolicyRejected,
        },
        DeliveryDisposition::Uncertain {
            reason: AdapterFailure::Tls,
        },
        DeliveryDisposition::DeadlineUncertain,
        DeliveryDisposition::ResponseTooLargeUncertain,
    ];
    let mut left = HostDeliveryLedger::new(cases.len()).unwrap();
    let mut right = HostDeliveryLedger::new(cases.len()).unwrap();
    for (n, disposition) in cases.iter().cloned().enumerate() {
        record(&mut left, n, disposition);
    }
    for (n, disposition) in cases.iter().cloned().enumerate().rev() {
        record(&mut right, n, disposition);
    }
    let checkpoint = left.checkpoint().unwrap();
    assert_eq!(checkpoint, right.checkpoint().unwrap());
    let imported = decode(&checkpoint);
    assert_eq!(imported, checkpoint);
    assert_eq!(imported.verify_against(&left), Ok(()));
    for (n, disposition) in cases.iter().enumerate() {
        assert_eq!(
            imported
                .lookup(&identity(n), &request(n))
                .unwrap()
                .disposition(),
            disposition
        );
    }
    let rendered = format!("{}{imported:?}", imported.render());
    for secret in [
        "private-deployment",
        "private-invocation",
        "private-key",
        "private.example",
        "private-email",
    ] {
        assert!(!rendered.contains(secret));
    }
}

#[test]
fn commitment_and_exact_live_state_refuse_byte_or_state_drift() {
    let mut ledger = HostDeliveryLedger::new(2).unwrap();
    let empty = ledger.checkpoint().unwrap();
    assert!(empty.is_empty());
    assert_eq!(empty.capacity(), 2);
    assert_eq!(
        empty.digest(),
        "sha256:3707cd02bdf34b54336b73d4c4f86f04d432b6a2b250a61cd1bda715ac1c7370"
    );
    assert_eq!(empty.render(), "{\"capacity\":2,\"entries\":[],\"schema\":\"semaprax.outbound.delivery-ledger-checkpoint.v1\"}");
    record(&mut ledger, 1, DeliveryDisposition::DeadlineUncertain);
    assert_eq!(
        empty.verify_against(&ledger),
        Err(LedgerCheckpointRefusal::StateChanged)
    );
    let current = ledger.checkpoint().unwrap();
    assert_eq!(
        LedgerCheckpoint::decode(current.render().as_bytes(), &empty.digest()),
        Err(LedgerCheckpointRefusal::BindingMismatch)
    );
    assert_eq!(
        LedgerCheckpoint::decode(current.render().as_bytes(), "SHA256:invalid"),
        Err(LedgerCheckpointRefusal::BindingMismatch)
    );
    let imported = decode(&current);
    assert_eq!(
        imported.lookup(&identity(2), &request(2)),
        Err(LedgerCheckpointRefusal::UnknownIdentity)
    );
    assert_eq!(
        imported.lookup(&identity(2), &request(1)),
        Err(LedgerCheckpointRefusal::IdentityRequestMismatch)
    );
    let mut changed = request(1);
    changed.body.push(0);
    assert_eq!(
        imported.lookup(&identity(1), &changed),
        Err(LedgerCheckpointRefusal::ConflictingObservation)
    );
    assert_eq!(imported.len(), 1);
}

#[test]
fn merge_is_atomic_commutative_and_never_replaces_sticky_uncertainty() {
    let mut left = HostDeliveryLedger::new(2).unwrap();
    record(&mut left, 1, DeliveryDisposition::DeadlineUncertain);
    let mut right = HostDeliveryLedger::new(2).unwrap();
    record(&mut right, 2, DeliveryDisposition::Accepted { status: 204 });
    let a = decode(&left.checkpoint().unwrap());
    let b = decode(&right.checkpoint().unwrap());
    let a_wire = a.render();
    assert_eq!(a.merge(&b), b.merge(&a));
    let merged = a.merge(&b).unwrap();
    assert_eq!(merged.merge(&a), Ok(merged.clone()));
    assert_eq!(merged.len(), 2);
    let mut conflict = HostDeliveryLedger::new(2).unwrap();
    record(
        &mut conflict,
        1,
        DeliveryDisposition::Accepted { status: 200 },
    );
    assert_eq!(
        a.merge(&conflict.checkpoint().unwrap()),
        Err(LedgerCheckpointRefusal::ConflictingObservation)
    );
    record(
        &mut conflict,
        3,
        DeliveryDisposition::Rejected { status: 400 },
    );
    assert_eq!(
        b.merge(&conflict.checkpoint().unwrap()),
        Err(LedgerCheckpointRefusal::CapacityExceeded)
    );
    assert_eq!(
        a.merge(&HostDeliveryLedger::new(1).unwrap().checkpoint().unwrap()),
        Err(LedgerCheckpointRefusal::InvalidCapacity)
    );
    assert_eq!(a.render(), a_wire);
}

#[test]
fn an_unwound_dispatch_exports_sticky_uncertainty_and_import_cannot_dispatch() {
    let mut ledger = HostDeliveryLedger::new(1).unwrap();
    assert!(catch_unwind(AssertUnwindSafe(|| {
        let _ = ledger.reconcile(identity(1), &request(1), |_| {
            panic!("physical attempt then panic")
        });
    }))
    .is_err());
    let imported = decode(&ledger.checkpoint().unwrap());
    assert_eq!(
        imported
            .lookup(&identity(1), &request(1))
            .unwrap()
            .disposition(),
        &DeliveryDisposition::Uncertain {
            reason: AdapterFailure::Transport
        }
    );
    let replay = ledger
        .reconcile(identity(1), &request(1), |_| panic!("must never retry"))
        .unwrap();
    assert!(!replay.was_dispatched());
    imported.verify_against(&ledger).unwrap();
}

#[test]
fn input_and_inventory_bounds_admit_full_capacity_and_refuse_maximum_plus_one() {
    let mut full = HostDeliveryLedger::new(MAX_LEDGER_ENTRIES).unwrap();
    for n in 0..MAX_LEDGER_ENTRIES {
        record(
            &mut full,
            n,
            DeliveryDisposition::Uncertain {
                reason: AdapterFailure::NameResolution,
            },
        );
    }
    let checkpoint = full.checkpoint().unwrap();
    assert!(checkpoint.render().len() < MAX_LEDGER_CHECKPOINT_BYTES);
    assert_eq!(decode(&checkpoint).len(), MAX_LEDGER_ENTRIES);
    let too_large = vec![b' '; MAX_LEDGER_CHECKPOINT_BYTES + 1];
    assert_eq!(
        LedgerCheckpoint::decode(&too_large, "bad"),
        Err(LedgerCheckpointRefusal::TooLarge)
    );
    let exactly_max = vec![b' '; MAX_LEDGER_CHECKPOINT_BYTES];
    assert_eq!(
        LedgerCheckpoint::decode(&exactly_max, &wire_digest(&exactly_max)),
        Err(LedgerCheckpointRefusal::Malformed)
    );
    let mut value: serde_json::Value = serde_json::from_str(&checkpoint.render()).unwrap();
    let duplicate = value["entries"][0].clone();
    value["entries"].as_array_mut().unwrap().push(duplicate);
    assert_eq!(
        decode_hostile(value),
        Err(LedgerCheckpointRefusal::CapacityExceeded)
    );
}

#[test]
fn hostile_closed_schema_status_digests_and_ordering_are_refused() {
    let mut ledger = HostDeliveryLedger::new(2).unwrap();
    record(
        &mut ledger,
        1,
        DeliveryDisposition::Accepted { status: 202 },
    );
    record(
        &mut ledger,
        2,
        DeliveryDisposition::Rejected { status: 500 },
    );
    let checkpoint = ledger.checkpoint().unwrap();
    let base: serde_json::Value = serde_json::from_str(&checkpoint.render()).unwrap();
    let mut cases = Vec::new();
    for (key, value) in [
        ("schema", serde_json::json!("other")),
        ("extra", serde_json::json!(true)),
        ("entries", serde_json::json!({})),
    ] {
        let mut changed = base.clone();
        changed[key] = value;
        cases.push(changed);
    }
    for capacity in [0, 257] {
        let mut changed = base.clone();
        changed["capacity"] = serde_json::json!(capacity);
        cases.push(changed);
    }
    for disposition in [
        serde_json::json!({"kind":"accepted","status":500}),
        serde_json::json!({"kind":"rejected","status":200}),
        serde_json::json!({"kind":"accepted","status":99}),
        serde_json::json!({"kind":"rejected","status":600}),
        serde_json::json!({"kind":"uncertain","reason":"private-error"}),
        serde_json::json!({"kind":"deadline_uncertain","extra":true}),
        serde_json::json!({"kind":"missing"}),
    ] {
        let mut changed = base.clone();
        changed["entries"][0]["disposition"] = disposition;
        cases.push(changed);
    }
    for key in ["identity_digest", "request_digest"] {
        let mut changed = base.clone();
        changed["entries"][0][key] = serde_json::json!("sha256:invalid");
        cases.push(changed);
    }
    let mut duplicate = base.clone();
    duplicate["entries"][1] = duplicate["entries"][0].clone();
    cases.push(duplicate);
    let mut reversed = base.clone();
    reversed["entries"].as_array_mut().unwrap().reverse();
    cases.push(reversed);
    for value in cases {
        assert!(decode_hostile(value.clone()).is_err(), "accepted {value}");
    }
    for bytes in [
        format!("{}\n", checkpoint.render()).into_bytes(),
        checkpoint
            .render()
            .replacen("\"capacity\":2", "\"capacity\":2,\"capacity\":2", 1)
            .into_bytes(),
        vec![0xff],
    ] {
        assert!(LedgerCheckpoint::decode(&bytes, &wire_digest(&bytes)).is_err());
    }
    let mut invalid = HostDeliveryLedger::new(1).unwrap();
    record(
        &mut invalid,
        0,
        DeliveryDisposition::Accepted { status: 500 },
    );
    assert_eq!(
        invalid.checkpoint(),
        Err(LedgerCheckpointRefusal::Malformed)
    );
}

#[test]
fn all_three_adapter_sessions_export_exact_read_only_observations() {
    use crate::outbound_host_adapter::*;
    struct Adapter(Vec<PreparedRequest>);
    impl OutboundAdapter for Adapter {
        fn send(&mut self, request: &PreparedRequest) -> AdapterObservation {
            self.0.push(request.clone());
            AdapterObservation::DeadlineAfterStart
        }
    }
    fn capability() -> OutboundCapability {
        let policy = OutboundPolicy::new(
            "private-policy",
            ["https://private.example.test".into()],
            8192,
            128,
            1000,
            8,
            8,
        )
        .unwrap();
        OutboundCapability::grant_for_trusted_host(
            "private-deployment",
            "private-invocation",
            policy,
        )
        .unwrap()
    }
    let endpoint = "https://private.example.test/deliver";
    let mut adapter = Adapter(Vec::new());
    let mut email = EmailDeliverySession::new(2).unwrap();
    let prepared = prepare_email_delivery(
        capability(),
        EmailRequest {
            endpoint: endpoint.into(),
            delivery_id: "private-delivery".into(),
            idempotency_key: "private-email-key".into(),
            sender: "private-sender@example.test".into(),
            recipients: vec!["private-recipient@example.test".into()],
            reply_to: None,
            subject: "private-subject".into(),
            body: b"private-message".to_vec(),
            attachments: vec![],
            deadline_ms: 1000,
        },
    )
    .unwrap();
    email.reconcile(prepared, &mut adapter).unwrap();
    let email_checkpoint = decode(&email.checkpoint().unwrap());
    email.verify_checkpoint(&email_checkpoint).unwrap();

    let mut webhook = WebhookDeliverySession::new(2).unwrap();
    webhook
        .reconcile(
            prepare_webhook_delivery(
                capability(),
                WebhookSigningSecret::from_trusted_host_bytes([23; 32]),
                WebhookRequest {
                    endpoint: endpoint.into(),
                    delivery_id: "private-delivery".into(),
                    idempotency_key: "private-webhook-key".into(),
                    content_type: "application/json".into(),
                    body: b"private-body".to_vec(),
                    deadline_ms: 1000,
                },
            )
            .unwrap(),
            &mut adapter,
        )
        .unwrap();
    let webhook_checkpoint = decode(&webhook.checkpoint().unwrap());
    webhook.verify_checkpoint(&webhook_checkpoint).unwrap();

    let mut tracing = ExportEventSession::new(2).unwrap();
    tracing
        .reconcile(
            prepare_export_event(
                capability(),
                endpoint.into(),
                1000,
                ExportEvent {
                    stable_event_id: "private-event".into(),
                    labels: vec![],
                    fields: vec![ExportField {
                        name: "payload".into(),
                        value: ProtectedExportValue::from_host_bytes(b"private-secret".to_vec())
                            .unwrap()
                            .into_redacted(true),
                    }],
                },
            )
            .unwrap(),
            &mut adapter,
        )
        .unwrap();
    let tracing_checkpoint = decode(&tracing.checkpoint().unwrap());
    tracing.verify_checkpoint(&tracing_checkpoint).unwrap();

    assert_eq!(adapter.0.len(), 3);
    for (checkpoint, request) in [email_checkpoint, webhook_checkpoint, tracing_checkpoint]
        .iter()
        .zip(&adapter.0)
    {
        let key = request
            .headers()
            .iter()
            .find(|(name, _)| name == "idempotency-key")
            .unwrap()
            .1
            .clone();
        let identity =
            DeliveryIdentity::new("private-deployment", "private-invocation", key).unwrap();
        assert_eq!(
            checkpoint.lookup(&identity, request).unwrap().disposition(),
            &DeliveryDisposition::DeadlineUncertain
        );
        assert!(!checkpoint.render().contains("private-"));
        assert!(!format!("{checkpoint:?}").contains("private-"));
    }
    assert_eq!(
        adapter.0.len(),
        3,
        "offline imports and queries cannot enter adapters"
    );
}
