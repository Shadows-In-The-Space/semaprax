use super::super::email::{
    DurableEmailDeliveryOutcome, EmailDeliverySessionCheckpoint,
    EmailDeliverySessionCheckpointStore,
};
use super::super::http::{
    DurableHttpDeliveryOutcome, HttpDeliverySessionCheckpoint, HttpDeliverySessionCheckpointStore,
    HttpDeliverySessionRestoreCapability,
};
use super::super::webhook::{
    DurableWebhookDeliveryOutcome, WebhookDeliverySessionCheckpoint,
    WebhookDeliverySessionCheckpointStore,
};
use super::*;

struct DurableStore {
    outcomes: Vec<CheckpointCommit>,
    checkpoints: Vec<String>,
}

impl HttpDeliverySessionCheckpointStore for DurableStore {
    fn commit(&mut self, checkpoint: &HttpDeliverySessionCheckpoint) -> CheckpointCommit {
        self.checkpoints.push(checkpoint.render());
        self.outcomes.remove(0)
    }
}

impl WebhookDeliverySessionCheckpointStore for DurableStore {
    fn commit(&mut self, checkpoint: &WebhookDeliverySessionCheckpoint) -> CheckpointCommit {
        self.checkpoints.push(checkpoint.render());
        self.outcomes.remove(0)
    }
}

impl EmailDeliverySessionCheckpointStore for DurableStore {
    fn commit(&mut self, checkpoint: &EmailDeliverySessionCheckpoint) -> CheckpointCommit {
        self.checkpoints.push(checkpoint.render());
        self.outcomes.remove(0)
    }
}

fn durable_http_request(path: &str, identity: &str) -> HttpRequest {
    HttpRequest {
        method: HttpMethod::Post,
        endpoint: format!("https://hooks.example.test/{path}"),
        request_id: identity.into(),
        idempotency_key: format!("{identity}-key"),
        content_type: Some("application/json".into()),
        headers: Vec::new(),
        body: b"{}".to_vec(),
        deadline_ms: 1_000,
    }
}

#[test]
fn durable_http_acknowledges_typed_intent_before_dispatch_and_restores_exactly() {
    let mut session = HttpDeliverySession::new(1).unwrap();
    let mut store = DurableStore {
        outcomes: vec![CheckpointCommit::Committed, CheckpointCommit::Committed],
        checkpoints: Vec::new(),
    };
    let mut adapter = FixtureAdapter::returning(AdapterObservation::Response {
        status: 202,
        body: Vec::new(),
    });
    let outcome = session
        .reconcile_durable(
            prepare_http_delivery(
                capability(),
                durable_http_request("durable", "durable-http"),
            )
            .unwrap(),
            &mut store,
            &mut adapter,
        )
        .unwrap();
    assert!(matches!(outcome, DurableHttpDeliveryOutcome::Dispatched(_)));
    assert_eq!(adapter.calls.len(), 1);
    assert_eq!(store.checkpoints.len(), 2);

    let checkpoint = session.session_checkpoint().unwrap();
    let mut restored = HttpDeliverySession::restore_authenticated(
        checkpoint.render().as_bytes(),
        HttpDeliverySessionRestoreCapability::grant_for_trusted_host(
            checkpoint.digest(),
            checkpoint.capacity(),
        )
        .unwrap(),
    )
    .unwrap();
    let mut replay_store = DurableStore {
        outcomes: Vec::new(),
        checkpoints: Vec::new(),
    };
    let mut replay_adapter = FixtureAdapter::returning(AdapterObservation::DeadlineAfterStart);
    let replay = restored
        .reconcile_durable(
            prepare_http_delivery(
                capability(),
                durable_http_request("durable", "durable-http"),
            )
            .unwrap(),
            &mut replay_store,
            &mut replay_adapter,
        )
        .unwrap();
    assert!(matches!(replay, DurableHttpDeliveryOutcome::Replayed(_)));
    assert!(replay_adapter.calls.is_empty());
    assert!(replay_store.checkpoints.is_empty());
}

#[test]
fn durable_http_known_unacknowledged_intent_never_dispatches() {
    let mut session = HttpDeliverySession::new(1).unwrap();
    let mut store = DurableStore {
        outcomes: vec![CheckpointCommit::NotCommitted],
        checkpoints: Vec::new(),
    };
    let mut adapter = FixtureAdapter::returning(AdapterObservation::DeadlineAfterStart);
    let outcome = session
        .reconcile_durable(
            prepare_http_delivery(
                capability(),
                durable_http_request("unacknowledged", "unacknowledged-http"),
            )
            .unwrap(),
            &mut store,
            &mut adapter,
        )
        .unwrap();
    assert_eq!(outcome, DurableHttpDeliveryOutcome::IntentNotCommitted);
    assert!(adapter.calls.is_empty());
    assert_eq!(session.len(), 0);
}

#[test]
fn durable_webhook_and_email_ack_before_dispatch() {
    let mut webhook_session = WebhookDeliverySession::new(1).unwrap();
    let mut webhook_store = DurableStore {
        outcomes: vec![CheckpointCommit::Committed, CheckpointCommit::Committed],
        checkpoints: Vec::new(),
    };
    let mut webhook_adapter = FixtureAdapter::returning(AdapterObservation::Response {
        status: 204,
        body: Vec::new(),
    });
    let webhook_outcome = webhook_session
        .reconcile_durable(
            prepare_webhook_delivery(
                capability(),
                WebhookSigningSecret::from_trusted_host_bytes([7; 32]),
                webhook(),
            )
            .unwrap(),
            &mut webhook_store,
            &mut webhook_adapter,
        )
        .unwrap();
    assert!(matches!(
        webhook_outcome,
        DurableWebhookDeliveryOutcome::Dispatched(_)
    ));
    assert_eq!(webhook_adapter.calls.len(), 1);
    assert_eq!(webhook_store.checkpoints.len(), 2);

    let mut email_session = EmailDeliverySession::new(1).unwrap();
    let mut email_store = DurableStore {
        outcomes: vec![CheckpointCommit::Committed, CheckpointCommit::Committed],
        checkpoints: Vec::new(),
    };
    let mut email_adapter = FixtureAdapter::returning(AdapterObservation::Response {
        status: 202,
        body: Vec::new(),
    });
    let email_outcome = email_session
        .reconcile_durable(
            prepare_email_delivery(email_capability(), email()).unwrap(),
            &mut email_store,
            &mut email_adapter,
        )
        .unwrap();
    assert!(matches!(
        email_outcome,
        DurableEmailDeliveryOutcome::Dispatched(_)
    ));
    assert_eq!(email_adapter.calls.len(), 1);
    assert_eq!(email_store.checkpoints.len(), 2);
}
