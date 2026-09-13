use super::*;

fn checkpoint() -> RuntimeCheckpoint {
    let mut evidence = JobEvidenceLog::new();
    evidence.append(JobEvidenceEntry::Enqueued { scheduled: false }, 0);
    RuntimeCheckpoint {
        schema_digest: "sha256:test".to_owned(),
        bound_revision: 1,
        submission: JobSubmission {
            idempotency_key: b"job-a".to_vec(),
            payload_descriptor: b"payload.v1".to_vec(),
            payload: br#"{}"#.to_vec(),
            schedule: None,
            max_attempts: 3,
            is_idempotent_handler: false,
            base_backoff_ticks: 1,
            max_backoff_ticks: 8,
        },
        entries: evidence.entries().to_vec(),
        replay_facts: vec![ReplayFact::default()],
        claimed_final_state: evidence.claimed_final_state(),
    }
}

#[test]
fn checkpoint_v1_round_trips_by_replaying_its_own_bounded_evidence() {
    let checkpoint = checkpoint();
    let encoded = checkpoint.encode().unwrap();
    let decoded = RuntimeCheckpoint::decode(&encoded).unwrap();
    assert_eq!(decoded.schema_digest, checkpoint.schema_digest);
    assert_eq!(decoded.submission.payload, checkpoint.submission.payload);
    assert_eq!(
        JobEvidenceLog::from_entries(decoded.entries, decoded.claimed_final_state)
            .unwrap()
            .replay(),
        Ok(JobState::Pending.code())
    );
}

#[test]
fn checkpoint_decoder_refuses_trailing_or_noncanonical_boolean_bytes() {
    let mut trailing = checkpoint().encode().unwrap();
    trailing.push(0);
    assert!(matches!(
        RuntimeCheckpoint::decode(&trailing),
        Err(JobRuntimeError::Checkpoint)
    ));
    let mut malformed = checkpoint().encode().unwrap();
    // The submission's idempotency flag follows fixed header, schema,
    // key, descriptor, payload, and max-attempt fields in v1.
    let offset = 8 + 2 + "sha256:test".len() + 1 + 2 + 5 + 2 + 10 + 4 + 2 + 1;
    malformed[offset] = 2;
    assert!(matches!(
        RuntimeCheckpoint::decode(&malformed),
        Err(JobRuntimeError::Checkpoint)
    ));
}

#[cfg(not(any(target_arch = "wasm32", target_arch = "wasm64")))]
#[test]
fn physical_store_refuses_stale_cas_and_retains_current_generation() {
    let root = std::env::temp_dir().join(format!("semaprax-job-runtime-{}", std::process::id()));
    fs::create_dir_all(&root).unwrap();
    let mut store = FileJobCheckpointStore::open(&root).unwrap();
    let document = checkpoint().encode().unwrap();
    assert_eq!(store.compare_and_swap(None, &document), Ok(1));
    assert_eq!(
        store.compare_and_swap(None, &document),
        Err(CheckpointStoreError)
    );
    assert_eq!(store.load().unwrap().unwrap().generation, 1);
    let _ = fs::remove_file(root.join(STORE_FILE));
    let _ = fs::remove_file(root.join(STORE_LOCK));
    let _ = fs::remove_dir(&root);
}

const SCHEMA_FIXTURE: &str = r#"
module test.job_runtime;

@id("answer.type")
record Answer {
    @id("answer.note")
    note: string,
}

@id("app.main")
fn main() -> i64 { 0 }
"#;

static TEMP_FILE_COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

fn compiled_schema() -> CompiledInteractionSchema {
    let unique = TEMP_FILE_COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let path = std::env::temp_dir().join(format!(
        "semaprax-job-runtime-{}-{unique}.spx",
        std::process::id()
    ));
    std::fs::write(&path, SCHEMA_FIXTURE).unwrap();
    let compiled =
        crate::agent_interaction_schema::compile_agent_interaction_schema(&path, "answer.type")
            .expect("job runtime schema fixture compiles");
    std::fs::remove_file(path).unwrap();
    compiled
}

fn admitted_payload(schema: &CompiledInteractionSchema) -> Vec<u8> {
    format!(
        "{{\"schema\":\"semaprax.agent-interaction-value.v1\",\"root_type_id\":\"answer.type\",\"schema_digest\":{},\"value\":{{\"fields\":{{\"answer.note\":\"retry test\"}}}}}}\n",
        crate::diagnostic::quote_json(schema.schema().digest()),
    )
    .into_bytes()
}

fn submission(schema: &CompiledInteractionSchema, key: &[u8]) -> JobSubmission {
    JobSubmission {
        idempotency_key: key.to_vec(),
        payload_descriptor: b"answer.v1".to_vec(),
        payload: admitted_payload(schema),
        schedule: None,
        max_attempts: 3,
        is_idempotent_handler: true,
        base_backoff_ticks: 5,
        max_backoff_ticks: 20,
    }
}

fn recurring_submission(schema: &CompiledInteractionSchema, key: &[u8]) -> JobSubmission {
    let mut job = submission(schema, key);
    job.schedule = Some(Schedule {
        next_run_tick: 10,
        interval_tick: 5,
        max_occurrences: 2,
        max_catch_up: 2,
    });
    job
}

#[derive(Default)]
struct MemoryCheckpointStore {
    current: Option<StoredJobCheckpoint>,
    calls: usize,
    fail_call: Option<usize>,
    write_before_failure: bool,
}

impl MemoryCheckpointStore {
    fn fail_on(&mut self, call: usize, write_before_failure: bool) {
        self.fail_call = Some(call);
        self.write_before_failure = write_before_failure;
    }
}

impl JobCheckpointStore for MemoryCheckpointStore {
    fn load(&mut self) -> Result<Option<StoredJobCheckpoint>, CheckpointStoreError> {
        Ok(self.current.clone())
    }

    fn compare_and_swap(
        &mut self,
        expected_generation: Option<u64>,
        document: &[u8],
    ) -> Result<u64, CheckpointStoreError> {
        self.calls += 1;
        if self.current.as_ref().map(|stored| stored.generation) != expected_generation {
            return Err(CheckpointStoreError);
        }
        let next_generation = expected_generation.map_or(1, |generation| generation + 1);
        let next = StoredJobCheckpoint {
            generation: next_generation,
            bytes: document.to_vec(),
        };
        if self.fail_call == Some(self.calls) {
            if self.write_before_failure {
                self.current = Some(next);
            }
            return Err(CheckpointStoreError);
        }
        self.current = Some(next);
        Ok(next_generation)
    }
}

struct ScriptedHandler {
    outcomes: Vec<HostJobOutcome>,
}

impl ScriptedHandler {
    fn new(outcomes: impl IntoIterator<Item = HostJobOutcome>) -> Self {
        Self {
            outcomes: outcomes.into_iter().collect(),
        }
    }
}

impl HostJobHandler for ScriptedHandler {
    fn execute(&mut self, _admitted_payload: &[u8]) -> HostJobOutcome {
        self.outcomes
            .is_empty()
            .then_some(HostJobOutcome::Uncertain)
            .unwrap_or_else(|| self.outcomes.remove(0))
    }
}

#[test]
fn retryable_drive_recovery_honors_backoff_before_later_success() {
    let schema = compiled_schema();
    let mut checkpoints = MemoryCheckpointStore::default();
    let mut runtime = JobRuntime::enqueue(
        &mut checkpoints,
        &schema,
        1,
        submission(&schema, b"retry-and-recover"),
    )
    .unwrap();
    let mut handler =
        ScriptedHandler::new([HostJobOutcome::RetryableFailure, HostJobOutcome::Succeeded]);

    assert_eq!(
        runtime.drive_once(&mut checkpoints, &mut handler, 7, 100, 10),
        Ok(DriveOutcome::Completed(JobState::Scheduled))
    );
    let mut runtime = JobRuntime::recover(&mut checkpoints, &schema, 1).unwrap();
    assert_eq!(runtime.state(), JobState::Scheduled);
    assert_eq!(
        runtime.drive_once(&mut checkpoints, &mut handler, 7, 109, 10),
        Ok(DriveOutcome::NoWork)
    );
    assert_eq!(
        runtime.drive_once(&mut checkpoints, &mut handler, 7, 110, 10),
        Ok(DriveOutcome::Completed(JobState::Succeeded))
    );
    let recovered = JobRuntime::recover(&mut checkpoints, &schema, 1).unwrap();
    assert_eq!(recovered.state(), JobState::Succeeded);
}

#[test]
fn cancellation_is_checkpointed_and_recovered_without_reopening_the_job() {
    let schema = compiled_schema();
    let mut checkpoints = MemoryCheckpointStore::default();
    let mut runtime = JobRuntime::enqueue(
        &mut checkpoints,
        &schema,
        1,
        submission(&schema, b"cancel-recovery"),
    )
    .unwrap();
    assert_eq!(runtime.cancel(&mut checkpoints), Ok(JobState::Cancelled));
    let recovered = JobRuntime::recover(&mut checkpoints, &schema, 1).unwrap();
    assert_eq!(recovered.state(), JobState::Cancelled);
    assert!(matches!(
        recovered.evidence().entries().last(),
        Some(JobEvidenceEntry::Cancelled)
    ));
}

#[test]
fn recurring_success_advances_exact_due_tick_across_recovery() {
    let schema = compiled_schema();
    let mut checkpoints = MemoryCheckpointStore::default();
    let mut runtime = JobRuntime::enqueue(
        &mut checkpoints,
        &schema,
        1,
        recurring_submission(&schema, b"recurring-recovery"),
    )
    .unwrap();
    let mut handler = ScriptedHandler::new([HostJobOutcome::Succeeded, HostJobOutcome::Succeeded]);
    assert_eq!(
        runtime.drive_once(&mut checkpoints, &mut handler, 2, 10, 2),
        Ok(DriveOutcome::Completed(JobState::Scheduled))
    );
    let mut recovered = JobRuntime::recover(&mut checkpoints, &schema, 1).unwrap();
    assert_eq!(recovered.state(), JobState::Scheduled);
    assert_eq!(
        recovered.drive_once(&mut checkpoints, &mut handler, 2, 14, 2),
        Ok(DriveOutcome::NoWork)
    );
    assert_eq!(
        recovered.drive_once(&mut checkpoints, &mut handler, 2, 15, 2),
        Ok(DriveOutcome::Completed(JobState::Succeeded))
    );
    assert_eq!(
        JobRuntime::recover(&mut checkpoints, &schema, 1)
            .unwrap()
            .state(),
        JobState::Succeeded
    );
}

#[test]
fn recurring_overflow_is_refused_before_claim_or_handler_dispatch() {
    let schema = compiled_schema();
    let mut checkpoints = MemoryCheckpointStore::default();
    let mut job = recurring_submission(&schema, b"recurring-overflow");
    job.schedule = Some(Schedule {
        next_run_tick: u64::MAX - 3,
        interval_tick: 4,
        max_occurrences: 2,
        max_catch_up: 0,
    });
    job.base_backoff_ticks = 0;
    job.max_backoff_ticks = 0;
    let mut runtime = JobRuntime::enqueue(&mut checkpoints, &schema, 1, job).unwrap();
    let mut handler = ScriptedHandler::new([HostJobOutcome::Succeeded]);
    assert_eq!(
        runtime.drive_once(&mut checkpoints, &mut handler, 2, u64::MAX - 3, 1),
        Err(JobRuntimeError::Store(JobFixtureError::ScheduleOverflow))
    );
    assert_eq!(runtime.state(), JobState::Scheduled);
    assert_eq!(runtime.evidence().entries().len(), 1);
}

#[test]
fn persisted_running_recovery_records_uncertain_and_cas_failure_poison_is_sticky() {
    let schema = compiled_schema();
    let mut checkpoints = MemoryCheckpointStore::default();
    checkpoints.fail_on(3, true);
    let mut runtime = JobRuntime::enqueue(
        &mut checkpoints,
        &schema,
        1,
        submission(&schema, b"running-recovery"),
    )
    .unwrap();
    let mut handler = ScriptedHandler::new([HostJobOutcome::Succeeded]);
    assert_eq!(
        runtime.drive_once(&mut checkpoints, &mut handler, 9, 100, 10),
        Err(JobRuntimeError::Checkpoint)
    );
    let recovered = JobRuntime::recover(&mut checkpoints, &schema, 1).unwrap();
    assert_eq!(recovered.state(), JobState::Uncertain);
    assert!(matches!(
        recovered.evidence().entries().last(),
        Some(JobEvidenceEntry::ConnectionUncertain)
    ));

    let mut poisoned_checkpoints = MemoryCheckpointStore::default();
    let mut poisoned = JobRuntime::enqueue(
        &mut poisoned_checkpoints,
        &schema,
        1,
        submission(&schema, b"poisoned-cas"),
    )
    .unwrap();
    poisoned_checkpoints.fail_on(2, false);
    let mut handler = ScriptedHandler::new([HostJobOutcome::Succeeded]);
    assert_eq!(
        poisoned.drive_once(&mut poisoned_checkpoints, &mut handler, 1, 100, 10),
        Err(JobRuntimeError::Checkpoint)
    );
    assert_eq!(
        poisoned.drive_once(&mut poisoned_checkpoints, &mut handler, 1, 100, 10),
        Err(JobRuntimeError::Poisoned)
    );
}

#[test]
fn enqueue_and_drive_refuse_revision_zero_and_tick_overflow() {
    let schema = compiled_schema();
    let mut checkpoints = MemoryCheckpointStore::default();
    assert!(matches!(
        JobRuntime::enqueue(
            &mut checkpoints,
            &schema,
            0,
            submission(&schema, b"bad-revision"),
        ),
        Err(JobRuntimeError::InvalidSubmission)
    ));
    let mut mismatch_checkpoints = MemoryCheckpointStore::default();
    JobRuntime::enqueue(
        &mut mismatch_checkpoints,
        &schema,
        2,
        submission(&schema, b"future-revision"),
    )
    .unwrap();
    assert!(matches!(
        JobRuntime::recover(&mut mismatch_checkpoints, &schema, 1),
        Err(JobRuntimeError::Store(JobFixtureError::RevisionRefused))
    ));
    let mut runtime = JobRuntime::enqueue(
        &mut checkpoints,
        &schema,
        1,
        submission(&schema, b"tick-overflow"),
    )
    .unwrap();
    let mut handler = ScriptedHandler::new([HostJobOutcome::Succeeded]);
    assert_eq!(
        runtime.drive_once(&mut checkpoints, &mut handler, 1, u64::MAX, 1),
        Err(JobRuntimeError::InvalidSubmission)
    );
}
