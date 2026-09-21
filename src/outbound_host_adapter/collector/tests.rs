use super::*;

#[derive(Default)]
struct Adapter {
    requests: Vec<PreparedRequest>,
}

impl OutboundAdapter for Adapter {
    fn send(&mut self, request: &PreparedRequest) -> AdapterObservation {
        self.requests.push(request.clone());
        AdapterObservation::Response {
            status: 202,
            body: Vec::new(),
        }
    }
}

#[derive(Default)]
struct Store(Vec<ExportSessionCheckpoint>);

impl ExportSessionCheckpointStore for Store {
    fn commit(&mut self, checkpoint: &ExportSessionCheckpoint) -> CheckpointCommit {
        self.0.push(checkpoint.clone());
        CheckpointCommit::Committed
    }
}

fn policy(origins: impl IntoIterator<Item = String>) -> OutboundPolicy {
    OutboundPolicy::new("collector-policy", origins, 4_096, 128, 1_000, 8, 8).unwrap()
}

fn capability(origins: impl IntoIterator<Item = String>) -> OutboundCapability {
    OutboundCapability::grant_for_trusted_host(
        "collector-deployment",
        "collector-invocation",
        policy(origins),
    )
    .unwrap()
}

fn target() -> TelemetryCollectorTarget {
    TelemetryCollectorTarget::for_trusted_host("https://collector.example.test").unwrap()
}

fn other_target() -> TelemetryCollectorTarget {
    TelemetryCollectorTarget::for_trusted_host("https://other.example.test").unwrap()
}

fn metric() -> MetricExport {
    MetricExport {
        stable_metric_id: "checkout.requests".into(),
        observation_id: "metric-1".into(),
        labels: vec![("region".into(), "eu".into())],
        kind: MetricKind::CounterIncrement(1),
    }
}

fn span() -> SpanExport {
    SpanExport {
        trace_id: "0123456789abcdef0123456789abcdef".into(),
        span_id: "0123456789abcdef".into(),
        parent_span_id: None,
        name: "checkout.authorize".into(),
        duration_micros: 7,
        status: SpanStatus::Ok,
        attributes: vec![],
    }
}

fn event() -> ExportEvent {
    ExportEvent {
        stable_event_id: "event-1".into(),
        labels: vec![("region".into(), "eu".into())],
        fields: vec![ExportField {
            name: "message".into(),
            value: ExportFieldValue::Public("checkout accepted".into()),
        }],
    }
}

#[test]
fn target_owns_exact_signal_routes_and_closed_wires() {
    let origins = [
        "https://collector.example.test".into(),
        "https://other.example.test".into(),
    ];
    let mut metric_session = MetricExportSession::new(1).unwrap();
    let mut span_session = SpanExportSession::new(1).unwrap();
    let mut event_session = ExportEventSession::new(1).unwrap();
    let mut adapter = Adapter::default();

    metric_session
        .reconcile(
            TelemetryCollectorCapability::bind_for_trusted_host(
                capability(origins.clone()),
                target(),
            )
            .unwrap()
            .prepare_metric(500, metric())
            .unwrap(),
            &mut adapter,
        )
        .unwrap();
    span_session
        .reconcile(
            TelemetryCollectorCapability::bind_for_trusted_host(
                capability(origins.clone()),
                target(),
            )
            .unwrap()
            .prepare_span(500, span())
            .unwrap(),
            &mut adapter,
        )
        .unwrap();
    event_session
        .reconcile(
            TelemetryCollectorCapability::bind_for_trusted_host(capability(origins), target())
                .unwrap()
                .prepare_event(500, event())
                .unwrap(),
            &mut adapter,
        )
        .unwrap();

    assert_eq!(adapter.requests.len(), 3);
    assert_eq!(
        adapter.requests[0].endpoint(),
        "https://collector.example.test/v1/metrics"
    );
    assert_eq!(
        adapter.requests[1].endpoint(),
        "https://collector.example.test/v1/spans"
    );
    assert_eq!(
        adapter.requests[2].endpoint(),
        "https://collector.example.test/v1/events"
    );
    assert_eq!(
        adapter.requests[0].headers()[0].1,
        "application/vnd.semaprax.metric.v1+json"
    );
    assert_eq!(
        adapter.requests[1].headers()[0].1,
        "application/vnd.semaprax.span.v1+json"
    );
    assert_eq!(adapter.requests[2].headers()[0].1, "application/json");
    assert!(adapter
        .requests
        .iter()
        .all(|request| request.max_redirects() == 0));
}

#[test]
fn collector_target_is_canonical_origin_only_and_policy_cannot_be_expanded() {
    for target in [
        "https://collector.example.test/",
        "https://collector.example.test/v1/metrics",
        "https://collector.example.test?tenant=other",
        "https://user:pass@collector.example.test",
        "http://collector.example.test",
    ] {
        assert_eq!(
            TelemetryCollectorTarget::for_trusted_host(target),
            Err(CollectorRefusal::InvalidTarget)
        );
    }
    assert!(matches!(
        TelemetryCollectorCapability::bind_for_trusted_host(
            capability(["https://other.example.test".into()]),
            target(),
        ),
        Err(CollectorRefusal::AuthorityDenied)
    ));
}

#[test]
fn collector_preparation_keeps_existing_pre_dispatch_bounds() {
    assert!(matches!(
        TelemetryCollectorCapability::bind_for_trusted_host(
            capability(["https://collector.example.test".into()]),
            target(),
        )
        .unwrap()
        .prepare_metric(0, metric()),
        Err(CollectorRefusal::Export(Refusal::InvalidDeadline))
    ));
}

#[test]
fn collector_prepared_metric_keeps_the_typed_durable_ack_before_dispatch_boundary() {
    let mut session = MetricExportSession::new(1).unwrap();
    let mut store = Store::default();
    let mut adapter = Adapter::default();
    let outcome = session
        .reconcile_durable(
            TelemetryCollectorCapability::bind_for_trusted_host(
                capability(["https://collector.example.test".into()]),
                target(),
            )
            .unwrap()
            .prepare_metric(500, metric())
            .unwrap(),
            &mut store,
            &mut adapter,
        )
        .unwrap();
    assert!(matches!(outcome, DurableExportEventOutcome::Dispatched(_)));
    assert_eq!(store.0.len(), 2);
    assert_eq!(adapter.requests.len(), 1);
    assert_eq!(
        adapter.requests[0].endpoint(),
        "https://collector.example.test/v1/metrics"
    );
}

#[test]
fn collector_target_drift_is_bound_into_typed_metric_replay_identity() {
    let origins = [
        "https://collector.example.test".into(),
        "https://other.example.test".into(),
    ];
    let mut session = MetricExportSession::new(1).unwrap();
    let mut adapter = Adapter::default();
    session
        .reconcile(
            TelemetryCollectorCapability::bind_for_trusted_host(
                capability(origins.clone()),
                target(),
            )
            .unwrap()
            .prepare_metric(500, metric())
            .unwrap(),
            &mut adapter,
        )
        .unwrap();
    let refusal = session.reconcile(
        TelemetryCollectorCapability::bind_for_trusted_host(capability(origins), other_target())
            .unwrap()
            .prepare_metric(500, metric())
            .unwrap(),
        &mut adapter,
    );
    assert_eq!(refusal, Err(ExportEventLedgerRefusal::RequestChanged));
    assert_eq!(adapter.requests.len(), 1);
}
