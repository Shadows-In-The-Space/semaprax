use super::*;
use semaprax::outbound_host_adapter::{
    prepare_email_delivery, prepare_webhook_delivery, DurableEmailDeliveryOutcome,
    DurableWebhookDeliveryOutcome, EmailDeliverySession, EmailDeliverySessionRestoreCapability,
    EmailRequest, HttpDeliverySessionRestoreRefusal, WebhookDeliverySession,
    WebhookDeliverySessionRestoreCapability, WebhookRequest, WebhookSigningSecret,
};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

const CHILD_MODE: &str = "SEMAPRAX_OUTBOUND_RESTART_CHILD_MODE";
const CHILD_DIRECTORY: &str = "SEMAPRAX_OUTBOUND_RESTART_DIRECTORY";
const CHILD_DIGEST: &str = "SEMAPRAX_OUTBOUND_RESTART_DIGEST";
const CHILD_CAPACITY: &str = "SEMAPRAX_OUTBOUND_RESTART_CAPACITY";
const CHILD_TAMPERED: &str = "SEMAPRAX_OUTBOUND_RESTART_TAMPERED";
const ACCEPTED_DISPATCH_MARKER: &str = "outbound-accepted-dispatch.marker";
const CHILD_WAIT: Duration = Duration::from_secs(5);
const CHILD_POLL: Duration = Duration::from_millis(10);

// The parent releases its held directory before the child acquires a fresh
// caller-selected hold. These local tests bind restored sessions to exact
// checkpoint bytes, digest, and capacity; they do not claim root-identity
// continuity, copied-byte refusal, crash/power-loss durability, or an external
// delivery outcome.
struct PanicOnDispatch;

impl OutboundAdapter for PanicOnDispatch {
    fn send(&mut self, _: &PreparedRequest) -> AdapterObservation {
        panic!("a restored terminal checkpoint must not redispatch")
    }
}

fn child_value(name: &str, maximum: usize) -> String {
    let value = std::env::var(name).unwrap_or_else(|_| panic!("child missing {name}"));
    assert!(
        !value.is_empty() && value.len() <= maximum,
        "child {name} exceeds its bounded fixture input"
    );
    value
}

fn child_fixture() -> (std::path::PathBuf, String, usize) {
    assert_eq!(
        std::env::var(CHILD_MODE).as_deref(),
        Ok("replay-v1"),
        "the child mode is one-shot and does not recurse"
    );
    let directory = std::path::PathBuf::from(child_value(CHILD_DIRECTORY, 4_096));
    let digest = child_value(CHILD_DIGEST, 71);
    let capacity = child_value(CHILD_CAPACITY, 20)
        .parse::<usize>()
        .expect("child capacity is decimal");
    assert!(
        capacity > 0,
        "child capacity remains an exact positive bound"
    );
    (directory, digest, capacity)
}

fn assert_one_accepted_dispatch(directory: &std::path::Path) {
    assert_eq!(
        fs::read(directory.join(ACCEPTED_DISPATCH_MARKER)).expect("read accepted dispatch marker"),
        b"accepted-dispatch-v1\n",
        "the parent accepted exactly one local fixture dispatch before child replay"
    );
}

fn inherit_platform_loader_environment(command: &mut Command) {
    // The fresh child gets no configuration environment. These are the small
    // platform loader allowlist needed by dynamically linked test executables.
    for name in [
        "DYLD_LIBRARY_PATH",
        "DYLD_FALLBACK_LIBRARY_PATH",
        "LD_LIBRARY_PATH",
        "LIBPATH",
    ] {
        if let Some(value) = std::env::var_os(name) {
            command.env(name, value);
        }
    }
}

fn spawn_child(
    test_name: &str,
    directory: &std::path::Path,
    digest: &str,
    capacity: usize,
    tampered: bool,
) {
    // `current_exe` is only the Rust test harness; it is not a product process
    // authority or provider route. The child gets no inherited configuration.
    let executable = std::env::current_exe().expect("current test executable");
    let mut command = Command::new(executable);
    command
        .arg("--exact")
        .arg(test_name)
        .arg("--nocapture")
        .env_clear();
    inherit_platform_loader_environment(&mut command);
    let mut child = command
        .env(CHILD_MODE, "replay-v1")
        .env(CHILD_DIRECTORY, directory)
        .env(CHILD_DIGEST, digest)
        .env(CHILD_CAPACITY, capacity.to_string())
        .env(CHILD_TAMPERED, if tampered { "yes" } else { "no" })
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn bounded local replay child");
    let deadline = Instant::now() + CHILD_WAIT;
    loop {
        if let Some(status) = child.try_wait().expect("poll replay child") {
            assert!(status.success(), "local replay child must pass: {status}");
            return;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("local replay child exceeded its bounded wait");
        }
        std::thread::sleep(CHILD_POLL);
    }
}

macro_rules! typed_process_restart_case {
    ($module:ident, $session:ident, $restore:ident, $outcome:ident, $kind:ident, $prepare:expr) => {
        mod $module {
            use super::*;

            const TEST_NAME: &str = concat!(
                "outbound_delivery_store::tests::namespace_sync::process_restart::",
                stringify!($module),
                "::separate_process_reopens_exact_checkpoint_without_redispatch"
            );

            #[test]
            fn separate_process_reopens_exact_checkpoint_without_redispatch() {
                if std::env::var_os(CHILD_MODE).is_some() {
                    let (directory_path, digest, capacity) = child_fixture();
                    assert_eq!(std::env::var(CHILD_TAMPERED).as_deref(), Ok("no"));
                    let directory = platform::hold_directory(&directory_path)
                        .expect("child freshly holds caller-selected directory");
                    assert_one_accepted_dispatch(&directory_path);
                    let store = namespace_store(&directory);
                    let bytes = store
                        .load(OutboundCheckpointKind::$kind, &digest)
                        .expect("child loads only its parent-retained exact digest");
                    let mut restored = $session::restore_authenticated(
                        &bytes,
                        $restore::grant_for_trusted_host(&digest, capacity)
                            .expect("child binds the handed exact digest and capacity"),
                    )
                    .expect("child authenticates the typed terminal checkpoint");
                    let mut replay_store = namespace_store(&directory);
                    let mut replay_adapter = PanicOnDispatch;
                    assert!(matches!(
                        restored
                            .reconcile_durable(($prepare)(), &mut replay_store, &mut replay_adapter)
                            .expect("terminal recovery is local replay"),
                        $outcome::Replayed(_)
                    ));
                    return;
                }

                let temp = TempDirectory::new();
                let directory = platform::hold_directory(temp.path())
                    .expect("parent holds caller-selected directory");
                let mut store = namespace_store(&directory);
                let mut session = $session::new(1).expect("bounded typed session");
                let mut adapter = RecordingAdapter::default();
                assert!(matches!(
                    session
                        .reconcile_durable(($prepare)(), &mut store, &mut adapter)
                        .expect("namespace-synced local dispatch"),
                    $outcome::Dispatched(_)
                ));
                assert_eq!(adapter.0.len(), 1, "one accepted fixture dispatch");
                fs::write(
                    temp.path().join(ACCEPTED_DISPATCH_MARKER),
                    b"accepted-dispatch-v1\n",
                )
                .expect("record one accepted local fixture dispatch");
                let checkpoint = session.session_checkpoint().expect("terminal checkpoint");
                let digest = checkpoint.digest();
                let capacity = checkpoint.capacity();
                drop(directory);
                spawn_child(TEST_NAME, temp.path(), &digest, capacity, false);
            }
        }
    };
}

typed_process_restart_case!(
    http,
    HttpDeliverySession,
    HttpDeliverySessionRestoreCapability,
    DurableHttpDeliveryOutcome,
    HttpSession,
    || prepare_http_delivery(capability(), request()).unwrap()
);

#[test]
fn separate_process_content_tamper_refuses_before_adapter() {
    const TEST_NAME: &str = "outbound_delivery_store::tests::namespace_sync::process_restart::separate_process_content_tamper_refuses_before_adapter";
    if std::env::var_os(CHILD_MODE).is_some() {
        let (directory_path, digest, capacity) = child_fixture();
        assert_eq!(std::env::var(CHILD_TAMPERED).as_deref(), Ok("yes"));
        let directory = platform::hold_directory(&directory_path)
            .expect("child freshly holds caller-selected directory");
        assert_one_accepted_dispatch(&directory_path);
        let store = namespace_store(&directory);
        let bytes = store
            .load(OutboundCheckpointKind::HttpSession, &digest)
            .expect("child reads replacement bytes as untrusted data");
        assert!(matches!(
            HttpDeliverySession::restore_authenticated(
                &bytes,
                HttpDeliverySessionRestoreCapability::grant_for_trusted_host(&digest, capacity)
                    .expect("child binds the handed exact digest and capacity"),
            ),
            Err(HttpDeliverySessionRestoreRefusal::Checkpoint(
                DeliverySessionCheckpointRefusal::BindingMismatch
            ))
        ));
        return;
    }

    let temp = TempDirectory::new();
    let directory = platform::hold_directory(temp.path()).expect("parent holds caller directory");
    let mut store = namespace_store(&directory);
    let mut session = HttpDeliverySession::new(1).expect("bounded HTTP session");
    let mut adapter = RecordingAdapter::default();
    assert!(matches!(
        session
            .reconcile_durable(
                prepare_http_delivery(capability(), request()).unwrap(),
                &mut store,
                &mut adapter,
            )
            .unwrap(),
        DurableHttpDeliveryOutcome::Dispatched(_)
    ));
    assert_eq!(adapter.0.len(), 1, "one accepted fixture dispatch");
    fs::write(
        temp.path().join(ACCEPTED_DISPATCH_MARKER),
        b"accepted-dispatch-v1\n",
    )
    .unwrap();
    let checkpoint = session.session_checkpoint().unwrap();
    let digest = checkpoint.digest();
    let capacity = checkpoint.capacity();
    let filename = checkpoint_filename(OutboundCheckpointKind::HttpSession, &digest).unwrap();
    let replacement = temp.path().join("tampered-checkpoint-replacement");
    fs::write(&replacement, b"tampered checkpoint").unwrap();
    fs::rename(replacement, temp.path().join(filename))
        .expect("hostile owner rename-replaces checkpoint before fresh child open");
    drop(directory);
    spawn_child(TEST_NAME, temp.path(), &digest, capacity, true);
}

typed_process_restart_case!(
    webhook,
    WebhookDeliverySession,
    WebhookDeliverySessionRestoreCapability,
    DurableWebhookDeliveryOutcome,
    WebhookSession,
    || prepare_webhook_delivery(
        capability(),
        WebhookSigningSecret::from_trusted_host_bytes([7; 32]),
        WebhookRequest {
            endpoint: "https://store.example.test/events".into(),
            delivery_id: "process-restart-webhook".into(),
            idempotency_key: "process-restart-webhook-key".into(),
            content_type: "application/json".into(),
            body: b"{}".to_vec(),
            deadline_ms: 1_000,
        }
    )
    .unwrap()
);

typed_process_restart_case!(
    email,
    EmailDeliverySession,
    EmailDeliverySessionRestoreCapability,
    DurableEmailDeliveryOutcome,
    EmailSession,
    || prepare_email_delivery(
        capability(),
        EmailRequest {
            endpoint: "https://store.example.test/email".into(),
            delivery_id: "process-restart-email".into(),
            idempotency_key: "process-restart-email-key".into(),
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
