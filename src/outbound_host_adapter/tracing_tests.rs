use std::panic::{catch_unwind, AssertUnwindSafe};

use super::*;

#[derive(Default)]
struct RecordingAdapter {
    calls: Vec<PreparedRequest>,
    next: Option<AdapterObservation>,
}

impl RecordingAdapter {
    fn returning(observation: AdapterObservation) -> Self {
        Self {
            calls: Vec::new(),
            next: Some(observation),
        }
    }
}

impl OutboundAdapter for RecordingAdapter {
    fn send(&mut self, request: &PreparedRequest) -> AdapterObservation {
        self.calls.push(request.clone());
        self.next
            .take()
            .expect("a reconciliation dispatches at most once")
    }
}

struct PanickingAdapter;

impl OutboundAdapter for PanickingAdapter {
    fn send(&mut self, _request: &PreparedRequest) -> AdapterObservation {
        panic!("simulated exporter unwind after physical start")
    }
}

fn policy() -> OutboundPolicy {
    OutboundPolicy::new(
        "deploy.tracing.v1",
        ["https://traces.example.test".to_owned()],
        4_096,
        512,
        5_000,
        4,
        3,
    )
    .unwrap()
}

fn capability(invocation: &str) -> OutboundCapability {
    OutboundCapability::grant_for_trusted_host("sha256:tracing-deployment", invocation, policy())
        .unwrap()
}

fn event(public_value: &str, protected: &[u8]) -> ExportEvent {
    event_with_id("trace-event-17", public_value, protected)
}

fn event_with_id(stable_event_id: &str, public_value: &str, protected: &[u8]) -> ExportEvent {
    ExportEvent {
        stable_event_id: stable_event_id.into(),
        labels: vec![("service".into(), "checkout".into())],
        fields: vec![
            ExportField {
                name: "duration_ms".into(),
                value: ExportFieldValue::Public(public_value.into()),
            },
            ExportField {
                name: "credential".into(),
                value: ProtectedExportValue::from_host_bytes(protected.to_vec())
                    .unwrap()
                    .into_redacted(true),
            },
        ],
    }
}

fn prepare(invocation: &str, event: ExportEvent) -> PreparedExportEvent {
    prepare_export_event(
        capability(invocation),
        "https://traces.example.test/v1/events".into(),
        2_000,
        event,
    )
    .unwrap()
}

#[test]
fn prepared_export_preserves_legacy_helper_but_replay_is_disposition_only() {
    let secret = b"never-retain-this-api-token";
    let expected_event = event("31", secret);
    let mut legacy_adapter = RecordingAdapter::returning(AdapterObservation::Response {
        status: 202,
        body: b"legacy-provider-response".to_vec(),
    });
    let legacy = export_event(
        capability("invocation-legacy"),
        "https://traces.example.test/v1/events".into(),
        2_000,
        expected_event.clone(),
        &mut legacy_adapter,
    )
    .unwrap();
    assert_eq!(
        legacy.response_body.as_deref(),
        Some(b"legacy-provider-response".as_slice()),
        "the additive session must not change the legacy helper"
    );

    assert_eq!(legacy.evidence.idempotency_key, "export-no-retry");
    assert_eq!(legacy_adapter.calls[0].headers[1].1, "export-no-retry");

    let prepared = prepare("invocation-legacy", expected_event);
    assert_ne!(prepared.request.headers[1].1, "export-no-retry");
    assert_eq!(prepared.request.headers[1].1, prepared.idempotency_key);
    assert_eq!(
        prepared.request.headers[0],
        legacy_adapter.calls[0].headers[0]
    );
    assert_eq!(
        prepared.request.headers[2],
        legacy_adapter.calls[0].headers[2]
    );
    assert_eq!(prepared.request.endpoint, legacy_adapter.calls[0].endpoint);
    assert_eq!(prepared.request.body, legacy_adapter.calls[0].body);
    assert_eq!(
        prepared.request.deadline_ms,
        legacy_adapter.calls[0].deadline_ms
    );
    assert_eq!(
        prepared.request.max_redirects,
        legacy_adapter.calls[0].max_redirects
    );
    assert_eq!(
        prepared.request.max_response_bytes,
        legacy_adapter.calls[0].max_response_bytes
    );
    assert!(!prepared
        .request
        .body()
        .windows(secret.len())
        .any(|part| part == secret));
    assert!(String::from_utf8_lossy(prepared.request.body()).contains("[REDACTED]"));

    let mut session = ExportEventSession::new(2).unwrap();
    let mut first_adapter = RecordingAdapter::returning(AdapterObservation::Response {
        status: 202,
        body: b"session-private-provider-response".to_vec(),
    });
    let first = session.reconcile(prepared, &mut first_adapter).unwrap();
    assert!(!first.was_replayed());
    assert_eq!(first_adapter.calls.len(), 1);
    assert_eq!(
        first.evidence().disposition(),
        &DeliveryDisposition::Accepted { status: 202 }
    );

    let mut replay_adapter = RecordingAdapter::returning(AdapterObservation::DeadlineAfterStart);
    let replay = session
        .reconcile(
            prepare("invocation-legacy", event("31", secret)),
            &mut replay_adapter,
        )
        .unwrap();
    assert!(replay.was_replayed());
    assert!(replay_adapter.calls.is_empty());
    assert_eq!(replay.evidence().render(), first.evidence().render());
    assert!(!format!("{first:?}{replay:?}").contains("session-private-provider-response"));

    let retained = format!(
        "{}{:?}",
        session.ledger.render(),
        session.commitments.values().collect::<Vec<_>>()
    );
    assert!(!retained.contains(std::str::from_utf8(secret).unwrap()));
    assert!(!retained.contains("duration_ms"));
    assert!(!retained.contains("checkout"));
}

#[test]
fn distinct_event_ids_get_distinct_delivery_identities_and_replay_independently() {
    let mut session = ExportEventSession::new(2).unwrap();
    let first_prepared = prepare(
        "invocation-multiple-events",
        event_with_id("trace-event-17", "31", b"first-secret"),
    );
    let second_prepared = prepare(
        "invocation-multiple-events",
        event_with_id("trace-event-18", "31", b"second-secret"),
    );
    let first_key = first_prepared.idempotency_key.clone();
    let second_key = second_prepared.idempotency_key.clone();
    assert_ne!(first_key, second_key);
    assert_eq!(first_prepared.request.headers[1].1, first_key);
    assert_eq!(second_prepared.request.headers[1].1, second_key);
    assert!(valid_identity(&first_key));
    assert!(valid_identity(&second_key));
    assert!(valid_sha256(&first_key));
    assert!(valid_sha256(&second_key));
    assert!(first_key.len() <= MAX_HEADER_VALUE_BYTES);
    assert!(second_key.len() <= MAX_HEADER_VALUE_BYTES);
    assert_eq!(
        first_prepared.session_identity_digest,
        session_identity_digest(
            "sha256:tracing-deployment",
            "invocation-multiple-events",
            &first_key,
        )
    );
    assert_eq!(
        second_prepared.session_identity_digest,
        session_identity_digest(
            "sha256:tracing-deployment",
            "invocation-multiple-events",
            &second_key,
        )
    );

    let mut first_adapter = RecordingAdapter::returning(AdapterObservation::Response {
        status: 202,
        body: Vec::new(),
    });
    let first = session
        .reconcile(first_prepared, &mut first_adapter)
        .unwrap();
    let mut second_adapter = RecordingAdapter::returning(AdapterObservation::Response {
        status: 204,
        body: Vec::new(),
    });
    let second = session
        .reconcile(second_prepared, &mut second_adapter)
        .unwrap();
    assert_eq!(first_adapter.calls.len(), 1);
    assert_eq!(second_adapter.calls.len(), 1);
    assert_eq!(session.len(), 2);
    assert_eq!(first.evidence().idempotency_key, first_key);
    assert_eq!(second.evidence().idempotency_key, second_key);

    for (event_id, key, secret) in [
        ("trace-event-17", first_key, b"first-secret".as_slice()),
        ("trace-event-18", second_key, b"second-secret".as_slice()),
    ] {
        let mut replay_adapter =
            RecordingAdapter::returning(AdapterObservation::DeadlineAfterStart);
        let replay = session
            .reconcile(
                prepare(
                    "invocation-multiple-events",
                    event_with_id(event_id, "31", secret),
                ),
                &mut replay_adapter,
            )
            .unwrap();
        assert!(replay.was_replayed());
        assert!(replay_adapter.calls.is_empty());
        assert_eq!(replay.evidence().idempotency_key, key);
    }
}

#[test]
fn policy_event_protected_commitment_and_request_drift_refuse_before_dispatch() {
    let mut session = ExportEventSession::new(2).unwrap();
    let mut first_adapter = RecordingAdapter::returning(AdapterObservation::Response {
        status: 204,
        body: Vec::new(),
    });
    session
        .reconcile(
            prepare("invocation-drift", event("31", b"secret-one")),
            &mut first_adapter,
        )
        .unwrap();

    let drifted_policy = OutboundPolicy::new(
        "deploy.tracing.v1",
        ["https://traces.example.test".to_owned()],
        4_096,
        511,
        5_000,
        4,
        3,
    )
    .unwrap();
    let drifted_capability = OutboundCapability::grant_for_trusted_host(
        "sha256:tracing-deployment",
        "invocation-drift",
        drifted_policy,
    )
    .unwrap();
    let mut no_dispatch = RecordingAdapter::returning(AdapterObservation::DeadlineAfterStart);
    assert_eq!(
        session.reconcile(
            prepare_export_event(
                drifted_capability,
                "https://traces.example.test/v1/events".into(),
                2_000,
                event("31", b"secret-one"),
            )
            .unwrap(),
            &mut no_dispatch,
        ),
        Err(ExportEventLedgerRefusal::PolicyChanged)
    );
    assert!(no_dispatch.calls.is_empty());

    let mut public_drift = RecordingAdapter::returning(AdapterObservation::DeadlineAfterStart);
    assert_eq!(
        session.reconcile(
            prepare("invocation-drift", event("32", b"secret-one")),
            &mut public_drift,
        ),
        Err(ExportEventLedgerRefusal::EventChanged)
    );
    assert!(public_drift.calls.is_empty());

    let mut commitment_drift = RecordingAdapter::returning(AdapterObservation::DeadlineAfterStart);
    assert_eq!(
        session.reconcile(
            prepare("invocation-drift", event("31", b"secret-two")),
            &mut commitment_drift,
        ),
        Err(ExportEventLedgerRefusal::EventChanged)
    );
    assert!(commitment_drift.calls.is_empty());

    let mut request_drift = prepare("invocation-drift", event("31", b"secret-one"));
    request_drift.request.deadline_ms += 1;
    let mut request_adapter = RecordingAdapter::returning(AdapterObservation::DeadlineAfterStart);
    assert_eq!(
        session.reconcile(request_drift, &mut request_adapter),
        Err(ExportEventLedgerRefusal::RequestChanged)
    );
    assert!(request_adapter.calls.is_empty());
}

#[test]
fn panic_is_sticky_and_capacity_refuses_before_adapter_entry() {
    let mut session = ExportEventSession::new(1).unwrap();
    let unwind = catch_unwind(AssertUnwindSafe(|| {
        let mut adapter = PanickingAdapter;
        let _ = session.reconcile(
            prepare("invocation-panic", event("31", b"panic-secret")),
            &mut adapter,
        );
    }));
    assert!(unwind.is_err());
    assert_eq!(session.len(), 1);

    let mut retry_adapter = RecordingAdapter::returning(AdapterObservation::Response {
        status: 204,
        body: Vec::new(),
    });
    let replay = session
        .reconcile(
            prepare("invocation-panic", event("31", b"panic-secret")),
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

    let mut capacity_adapter = RecordingAdapter::returning(AdapterObservation::Response {
        status: 204,
        body: Vec::new(),
    });
    assert_eq!(
        session.reconcile(
            prepare("invocation-capacity", event("31", b"capacity-secret")),
            &mut capacity_adapter,
        ),
        Err(ExportEventLedgerRefusal::Ledger(
            LedgerRefusal::CapacityExceeded
        ))
    );
    assert!(capacity_adapter.calls.is_empty());
}
