use super::*;
use semaprax::outbound_host_adapter::{
    prepare_email_delivery, prepare_webhook_delivery, DurableEmailDeliveryOutcome,
    DurableWebhookDeliveryOutcome, EmailDeliverySession, EmailDeliverySessionRestoreCapability,
    EmailRequest, WebhookDeliverySession, WebhookDeliverySessionRestoreCapability, WebhookRequest,
    WebhookSigningSecret,
};

// This wrapper injects only the sync result into the real local store commit
// path. It neither substitutes the session ledger nor grants dispatch authority.
struct FailingSyncStore<'a> {
    store: OutboundDeliveryStore<'a>,
    fail_file: bool,
    calls: Cell<(usize, usize)>,
}

macro_rules! typed_case {
    ($module:ident, $session:ident, $checkpoint:ident, $store_trait:ident,
     $restore:ident, $outcome:ident, $kind:ident, $prepare:expr) => {
        impl $store_trait for FailingSyncStore<'_> {
            fn commit(&mut self, checkpoint: &$checkpoint) -> CheckpointCommit {
                let calls = &self.calls;
                let fail_file = self.fail_file;
                self.store.commit_rendered_with_directory_sync(
                    OutboundCheckpointKind::$kind,
                    &checkpoint.digest(),
                    &checkpoint.render(),
                    platform::write_file_new,
                    |file| {
                        calls.set((calls.get().0 + 1, calls.get().1));
                        if fail_file {
                            Err(platform::Error::Changed)
                        } else {
                            platform::sync_regular_file(file)
                        }
                    },
                    |_| {
                        calls.set((calls.get().0, calls.get().1 + 1));
                        Err(platform::Error::Changed)
                    },
                )
            }
        }

        mod $module {
            use super::*;

            #[test]
            fn namespace_ack_reopens_and_replays_without_dispatch() {
                let temp = TempDirectory::new();
                let directory = platform::hold_directory(temp.path()).unwrap();
                let mut store = namespace_store(&directory);
                let mut session = $session::new(1).unwrap();
                let mut adapter = RecordingAdapter::default();
                assert!(matches!(
                    session
                        .reconcile_durable(($prepare)(), &mut store, &mut adapter)
                        .unwrap(),
                    $outcome::Dispatched(_)
                ));
                assert_eq!(adapter.0.len(), 1);
                let checkpoint = session.session_checkpoint().unwrap();
                // Exercise idempotent existing terminal bytes in the strong mode.
                assert_eq!(
                    $store_trait::commit(&mut store, &checkpoint),
                    CheckpointCommit::Committed
                );
                drop(directory);
                let reopened = platform::hold_directory(temp.path()).unwrap();
                let mut store = namespace_store(&reopened);
                let bytes = store
                    .load(OutboundCheckpointKind::$kind, &checkpoint.digest())
                    .unwrap();
                assert_eq!(bytes, checkpoint.render().as_bytes());
                let mut restored = $session::restore_authenticated(
                    &bytes,
                    $restore::grant_for_trusted_host(checkpoint.digest(), checkpoint.capacity())
                        .unwrap(),
                )
                .unwrap();
                let mut replay_adapter = RecordingAdapter::default();
                assert!(matches!(
                    restored
                        .reconcile_durable(($prepare)(), &mut store, &mut replay_adapter)
                        .unwrap(),
                    $outcome::Replayed(_)
                ));
                assert!(replay_adapter.0.is_empty());
            }

            #[test]
            fn either_sync_failure_is_sticky_without_dispatch_or_retry() {
                for fail_file in [false, true] {
                    let temp = TempDirectory::new();
                    let directory = platform::hold_directory(temp.path()).unwrap();
                    let mut store = FailingSyncStore {
                        store: namespace_store(&directory),
                        fail_file,
                        calls: Cell::new((0, 0)),
                    };
                    let mut session = $session::new(1).unwrap();
                    let mut adapter = RecordingAdapter::default();
                    assert!(matches!(
                        session
                            .reconcile_durable(($prepare)(), &mut store, &mut adapter)
                            .unwrap(),
                        $outcome::IntentUncertain(_)
                    ));
                    let calls = store.calls.get();
                    assert_eq!(calls, (1, usize::from(!fail_file)));
                    assert!(matches!(
                        session
                            .reconcile_durable(($prepare)(), &mut store, &mut adapter)
                            .unwrap(),
                        $outcome::Replayed(_)
                    ));
                    assert_eq!(
                        store.calls.get(),
                        calls,
                        "sticky replay must not retry storage"
                    );
                    assert!(
                        adapter.0.is_empty(),
                        "unacknowledged intent cannot dispatch"
                    );
                }
            }
        }
    };
}

typed_case!(
    http,
    HttpDeliverySession,
    HttpDeliverySessionCheckpoint,
    HttpDeliverySessionCheckpointStore,
    HttpDeliverySessionRestoreCapability,
    DurableHttpDeliveryOutcome,
    HttpSession,
    || prepare_http_delivery(capability(), request()).unwrap()
);

typed_case!(
    webhook,
    WebhookDeliverySession,
    WebhookDeliverySessionCheckpoint,
    WebhookDeliverySessionCheckpointStore,
    WebhookDeliverySessionRestoreCapability,
    DurableWebhookDeliveryOutcome,
    WebhookSession,
    || prepare_webhook_delivery(
        capability(),
        WebhookSigningSecret::from_trusted_host_bytes([7; 32]),
        WebhookRequest {
            endpoint: "https://store.example.test/events".into(),
            delivery_id: "store-webhook".into(),
            idempotency_key: "store-webhook-key".into(),
            content_type: "application/json".into(),
            body: b"{}".to_vec(),
            deadline_ms: 1_000,
        }
    )
    .unwrap()
);

typed_case!(
    email,
    EmailDeliverySession,
    EmailDeliverySessionCheckpoint,
    EmailDeliverySessionCheckpointStore,
    EmailDeliverySessionRestoreCapability,
    DurableEmailDeliveryOutcome,
    EmailSession,
    || prepare_email_delivery(
        capability(),
        EmailRequest {
            endpoint: "https://store.example.test/email".into(),
            delivery_id: "store-email".into(),
            idempotency_key: "store-email-key".into(),
            sender: "sender@example.test".into(),
            recipients: vec!["recipient@example.test".into()],
            reply_to: None,
            subject: "Ready".into(),
            body: b"ready".to_vec(),
            attachments: Vec::new(),
            deadline_ms: 1_000,
        }
    )
    .unwrap()
);
