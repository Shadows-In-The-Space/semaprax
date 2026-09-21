use super::*;

#[derive(Default)]
struct Adapter {
    calls: Vec<PreparedRequest>,
}

impl OutboundAdapter for Adapter {
    fn send(&mut self, request: &PreparedRequest) -> AdapterObservation {
        self.calls.push(request.clone());
        AdapterObservation::Response {
            status: 202,
            body: b"provider-private".to_vec(),
        }
    }
}

fn capability(invocation: &str, max_labels: usize) -> OutboundCapability {
    capability_with_limit(invocation, max_labels, 4_096)
}

fn capability_with_limit(
    invocation: &str,
    max_labels: usize,
    max_request_bytes: usize,
) -> OutboundCapability {
    OutboundCapability::grant_for_trusted_host(
        "metric-deployment",
        invocation,
        OutboundPolicy::new(
            "metric-policy",
            ["https://telemetry.example.test".into()],
            max_request_bytes,
            128,
            2_000,
            8,
            max_labels,
        )
        .unwrap(),
    )
    .unwrap()
}

#[test]
fn metric_json_escaping_obeys_the_exact_policy_byte_cap() {
    let hostile = metric(
        "observation-escaped",
        vec![("message".into(), "\"\\".repeat(32))],
    );
    let generous = capability_with_limit("invocation-escaped", 2, 4_096);
    let exact = hostile.encode(&generous.policy).unwrap().len();
    assert!(prepare_metric_export(
        capability_with_limit("invocation-escaped", 2, exact),
        "https://telemetry.example.test/v1/metrics".into(),
        1_000,
        hostile.clone(),
    )
    .is_ok());
    assert!(matches!(
        prepare_metric_export(
            capability_with_limit("invocation-escaped", 2, exact - 1),
            "https://telemetry.example.test/v1/metrics".into(),
            1_000,
            hostile,
        ),
        Err(Refusal::RequestTooLarge)
    ));
}

fn metric(observation_id: &str, labels: Vec<(String, String)>) -> MetricExport {
    MetricExport {
        stable_metric_id: "checkout.requests".into(),
        observation_id: observation_id.into(),
        labels,
        kind: MetricKind::CounterIncrement(1),
    }
}

fn prepare(invocation: &str, metric: MetricExport) -> PreparedMetricExport {
    prepare_metric_export(
        capability(invocation, 2),
        "https://telemetry.example.test/v1/metrics".into(),
        1_000,
        metric,
    )
    .unwrap()
}

#[test]
fn typed_metric_is_canonical_replayable_and_response_free() {
    let mut session = MetricExportSession::new(2).unwrap();
    let mut adapter = Adapter::default();
    let first = session
        .reconcile(
            prepare(
                "invocation-1",
                metric(
                    "observation-1",
                    vec![
                        ("region".into(), "eu".into()),
                        ("method".into(), "POST".into()),
                    ],
                ),
            ),
            &mut adapter,
        )
        .unwrap();
    assert!(!first.was_replayed());
    assert_eq!(adapter.calls.len(), 1);
    assert_eq!(
        adapter.calls[0].headers(),
        [
            (
                "content-type".into(),
                "application/vnd.semaprax.metric.v1+json".into()
            ),
            (
                "idempotency-key".into(),
                adapter.calls[0].headers()[1].1.clone()
            ),
            ("x-semaprax-observation-id".into(), "observation-1".into()),
        ]
    );
    let payload = std::str::from_utf8(adapter.calls[0].body()).unwrap();
    assert!(payload.contains("semaprax.operational-metric.v1"));
    assert!(payload.find("method").unwrap() < payload.find("region").unwrap());
    assert_eq!(
        verify_metric_export(adapter.calls[0].body(), &adapter.calls[0]),
        Ok(())
    );
    assert!(!format!("{first:?}").contains("provider-private"));

    let mut replay_adapter = Adapter::default();
    let replay = session
        .reconcile(
            prepare(
                "invocation-1",
                metric(
                    "observation-1",
                    vec![
                        ("region".into(), "eu".into()),
                        ("method".into(), "POST".into()),
                    ],
                ),
            ),
            &mut replay_adapter,
        )
        .unwrap();
    assert!(replay.was_replayed());
    assert!(replay_adapter.calls.is_empty());
    assert_eq!(first.evidence().render(), replay.evidence().render());

    let mut drifted = metric("observation-1", vec![("method".into(), "POST".into())]);
    drifted.kind = MetricKind::Gauge(1);
    let mut drift_adapter = Adapter::default();
    assert_eq!(
        session.reconcile(prepare("invocation-1", drifted), &mut drift_adapter),
        Err(ExportEventLedgerRefusal::EventChanged)
    );
    assert!(drift_adapter.calls.is_empty());
}

#[test]
fn metric_wire_decoder_refuses_unknown_noncanonical_and_unbound_inputs() {
    let mut session = MetricExportSession::new(1).unwrap();
    let mut adapter = Adapter::default();
    session
        .reconcile(
            prepare(
                "invocation-wire",
                metric("observation-wire", vec![("region".into(), "eu".into())]),
            ),
            &mut adapter,
        )
        .unwrap();
    let request = &adapter.calls[0];
    let mut unknown: serde_json::Value = serde_json::from_slice(request.body()).unwrap();
    unknown["unknown"] = serde_json::json!(true);
    assert_eq!(
        verify_metric_export(&serde_json::to_vec(&unknown).unwrap(), request),
        Err(MetricWireMismatch::Schema)
    );
    let spaced = format!(" {}", std::str::from_utf8(request.body()).unwrap());
    assert_eq!(
        verify_metric_export(spaced.as_bytes(), request),
        Err(MetricWireMismatch::NonCanonical)
    );
    let canonical = std::str::from_utf8(request.body()).unwrap();
    let duplicate = format!(r#"{{"schema":"duplicate",{}"#, &canonical[1..]);
    assert_eq!(
        verify_metric_export(duplicate.as_bytes(), request),
        Err(MetricWireMismatch::NonCanonical)
    );
    let mut wrong_request = request.clone();
    wrong_request.headers[2].1 = "other-observation".into();
    assert_eq!(
        verify_metric_export(request.body(), &wrong_request),
        Err(MetricWireMismatch::PreparedRequest)
    );
}

#[test]
fn metric_cardinality_identity_and_protected_labels_refuse_before_dispatch() {
    let cases = [
        metric(
            "observation-1",
            vec![("password".into(), "not-exportable".into())],
        ),
        metric(
            "observation-1",
            vec![("same".into(), "one".into()), ("same".into(), "two".into())],
        ),
        metric(
            "observation-1",
            vec![
                ("one".into(), "1".into()),
                ("two".into(), "2".into()),
                ("three".into(), "3".into()),
            ],
        ),
    ];
    for metric in cases {
        let result = prepare_metric_export(
            capability("invocation-refuse", 2),
            "https://telemetry.example.test/v1/metrics".into(),
            1_000,
            metric,
        );
        assert!(matches!(
            result,
            Err(Refusal::ProtectedValue | Refusal::CardinalityExceeded)
        ));
    }

    let zero = MetricExport {
        kind: MetricKind::CounterIncrement(0),
        ..metric("observation-zero", Vec::new())
    };
    assert!(matches!(
        prepare_metric_export(
            capability("invocation-refuse", 2),
            "https://telemetry.example.test/v1/metrics".into(),
            1_000,
            zero,
        ),
        Err(Refusal::InvalidIdentity)
    ));

    let overbound = metric(
        "observation-overbound",
        vec![("region".into(), "x".repeat(MAX_EXPORT_VALUE_BYTES + 1))],
    );
    assert!(matches!(
        prepare_metric_export(
            capability("invocation-refuse", 2),
            "https://telemetry.example.test/v1/metrics".into(),
            1_000,
            overbound,
        ),
        Err(Refusal::RequestTooLarge)
    ));
}

#[test]
fn distinct_observations_and_metric_kinds_have_bounded_independent_state() {
    let mut session = MetricExportSession::new(3).unwrap();
    for (observation_id, kind) in [
        ("counter-1", MetricKind::CounterIncrement(u64::MAX)),
        ("gauge-1", MetricKind::Gauge(i64::MIN)),
        ("histogram-1", MetricKind::HistogramObservation(i64::MAX)),
    ] {
        let mut adapter = Adapter::default();
        let prepared = prepare(
            "invocation-kinds",
            MetricExport {
                kind,
                ..metric(observation_id, Vec::new())
            },
        );
        session.reconcile(prepared, &mut adapter).unwrap();
        assert_eq!(adapter.calls.len(), 1);
    }
    assert_eq!(session.len(), 3);
    assert!(MetricExportSession::new(MAX_LEDGER_ENTRIES + 1).is_err());
}

#[derive(Default)]
struct SessionStore(Vec<ExportSessionCheckpoint>);

impl ExportSessionCheckpointStore for SessionStore {
    fn commit(&mut self, checkpoint: &ExportSessionCheckpoint) -> CheckpointCommit {
        self.0.push(checkpoint.clone());
        CheckpointCommit::Committed
    }
}

#[test]
fn metric_session_exposes_typed_durable_reconcile_and_restore() {
    let mut session = MetricExportSession::new(1).unwrap();
    let mut store = SessionStore::default();
    let mut adapter = Adapter::default();
    let outcome = session
        .reconcile_durable(
            prepare(
                "invocation-durable-metric",
                metric("metric-durable", Vec::new()),
            ),
            &mut store,
            &mut adapter,
        )
        .unwrap();
    assert!(matches!(outcome, DurableExportEventOutcome::Dispatched(_)));
    assert_eq!(store.0.len(), 2);
    let checkpoint = session.session_checkpoint().unwrap();
    let capability = ExportSessionRestoreCapability::grant_for_trusted_host(
        checkpoint.digest(),
        checkpoint.capacity(),
    )
    .unwrap();
    let restored =
        MetricExportSession::restore_authenticated(checkpoint.render().as_bytes(), capability)
            .unwrap();
    assert_eq!(restored.len(), 1);
}
