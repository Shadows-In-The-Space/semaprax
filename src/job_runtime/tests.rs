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

const SCHEMA_FIXTURE_V2: &str = r#"
module test.job_runtime;

@id("answer.type")
record Answer {
    @id("answer.note")
    note: string,
    @id("answer.extra")
    extra: string,
}

@id("app.main")
fn main() -> i64 { 0 }
"#;

/// A second, differently shaped schema under the same root type ID: it
/// compiles to a different digest, standing in for a handler/payload schema
/// change made between when a job was enqueued and a later recovery.
fn compiled_schema_variant() -> CompiledInteractionSchema {
    let unique = TEMP_FILE_COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let path = std::env::temp_dir().join(format!(
        "semaprax-job-runtime-variant-{}-{unique}.spx",
        std::process::id()
    ));
    std::fs::write(&path, SCHEMA_FIXTURE_V2).unwrap();
    let compiled =
        crate::agent_interaction_schema::compile_agent_interaction_schema(&path, "answer.type")
            .expect("job runtime schema variant fixture compiles");
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
    fn execute(
        &mut self,
        _admitted_payload: &[u8],
        _heartbeat: &mut dyn JobHeartbeat,
    ) -> HostJobOutcome {
        if self.outcomes.is_empty() {
            HostJobOutcome::Uncertain
        } else {
            self.outcomes.remove(0)
        }
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

/// A handler that inspects and extends its own lease through the
/// [`JobHeartbeat`] handle before returning `outcome`, recording what it
/// observed for the test to assert on afterward.
struct HeartbeatingHandler {
    extend_ticks: u64,
    outcome: HostJobOutcome,
    initial_deadline: Option<u64>,
    extend_result: Option<Result<u64, JobRuntimeError>>,
    deadline_after_extend: Option<u64>,
}

impl HostJobHandler for HeartbeatingHandler {
    fn execute(
        &mut self,
        _admitted_payload: &[u8],
        heartbeat: &mut dyn JobHeartbeat,
    ) -> HostJobOutcome {
        self.initial_deadline = Some(heartbeat.current_deadline());
        self.extend_result = Some(heartbeat.extend_lease(self.extend_ticks));
        self.deadline_after_extend = Some(heartbeat.current_deadline());
        self.outcome
    }
}

#[test]
fn a_handler_can_extend_its_own_lease_mid_execution_and_the_extra_checkpoint_is_written() {
    let schema = compiled_schema();
    let mut checkpoints = MemoryCheckpointStore::default();
    let mut runtime = JobRuntime::enqueue(
        &mut checkpoints,
        &schema,
        1,
        submission(&schema, b"heartbeat-extends"),
    )
    .unwrap();
    let mut handler = HeartbeatingHandler {
        extend_ticks: 50,
        outcome: HostJobOutcome::Succeeded,
        initial_deadline: None,
        extend_result: None,
        deadline_after_extend: None,
    };
    let calls_before = checkpoints.calls;
    assert_eq!(
        runtime.drive_once(&mut checkpoints, &mut handler, 3, 100, 10),
        Ok(DriveOutcome::Completed(JobState::Succeeded))
    );
    // Claimed at tick 100 with a 10-tick lease: the handle reports the
    // originally granted deadline before any extension. Extension is
    // relative to `now_tick` (the tick `drive_once` was called with), not the
    // current deadline, exactly like `JobStore::heartbeat` it delegates to.
    assert_eq!(handler.initial_deadline, Some(110));
    assert_eq!(handler.extend_result, Some(Ok(150)));
    assert_eq!(handler.deadline_after_extend, Some(150));
    // Claim, begin-execution, the mid-execution heartbeat, and the final
    // completion each persist a checkpoint: one more than a plain drive.
    assert_eq!(checkpoints.calls - calls_before, 4);
    // A confirmed heartbeat is not a new lifecycle fact: it adds no evidence
    // entry, so the recorded history is exactly Enqueued/Claimed/
    // BegunExecution/DurableCompleted, same as a drive without a heartbeat.
    assert_eq!(runtime.evidence().entries().len(), 4);
    let recovered = JobRuntime::recover(&mut checkpoints, &schema, 1).unwrap();
    assert_eq!(recovered.state(), JobState::Succeeded);
}

#[test]
fn heartbeat_refuses_tick_overflow_without_poisoning_or_blocking_completion() {
    let schema = compiled_schema();
    let mut checkpoints = MemoryCheckpointStore::default();
    let mut runtime = JobRuntime::enqueue(
        &mut checkpoints,
        &schema,
        1,
        submission(&schema, b"heartbeat-overflow"),
    )
    .unwrap();
    let mut handler = HeartbeatingHandler {
        extend_ticks: u64::MAX,
        outcome: HostJobOutcome::Succeeded,
        initial_deadline: None,
        extend_result: None,
        deadline_after_extend: None,
    };
    assert_eq!(
        runtime.drive_once(&mut checkpoints, &mut handler, 4, 100, 10),
        Ok(DriveOutcome::Completed(JobState::Succeeded))
    );
    assert_eq!(
        handler.extend_result,
        Some(Err(JobRuntimeError::InvalidSubmission))
    );
    // A refused heartbeat leaves the deadline exactly as originally claimed
    // and never poisons the runtime or blocks the job from completing.
    assert_eq!(handler.deadline_after_extend, Some(110));
    assert_eq!(runtime.state(), JobState::Succeeded);
}

/// The strongest possible proof that a job's effect never runs twice: a
/// handler that panics the instant it is invoked at all. Any test that
/// drives to completion with `drive_once` returning `NoWork` while holding
/// this handler proves, by construction rather than inspection, that no
/// stray re-dispatch occurred.
struct PanicIfCalledHandler;

impl HostJobHandler for PanicIfCalledHandler {
    fn execute(
        &mut self,
        _admitted_payload: &[u8],
        _heartbeat: &mut dyn JobHeartbeat,
    ) -> HostJobOutcome {
        panic!("a completed or non-retriable job must never redispatch its handler");
    }
}

#[test]
fn a_recovered_succeeded_job_never_redispatches_its_handler() {
    let schema = compiled_schema();
    let mut checkpoints = MemoryCheckpointStore::default();
    let mut runtime = JobRuntime::enqueue(
        &mut checkpoints,
        &schema,
        1,
        submission(&schema, b"idempotent-terminal"),
    )
    .unwrap();
    let mut handler = ScriptedHandler::new([HostJobOutcome::Succeeded]);
    assert_eq!(
        runtime.drive_once(&mut checkpoints, &mut handler, 1, 100, 10),
        Ok(DriveOutcome::Completed(JobState::Succeeded))
    );
    // Recovering, as a separate crash-and-resume attempt would, must not
    // reopen a terminal job.
    let mut recovered = JobRuntime::recover(&mut checkpoints, &schema, 1).unwrap();
    assert_eq!(recovered.state(), JobState::Succeeded);
    let mut panic_handler = PanicIfCalledHandler;
    // A terminal job is never legal to claim again, so `drive_once` must
    // refuse without ever invoking the handler that would panic if it did.
    assert_eq!(
        recovered.drive_once(&mut checkpoints, &mut panic_handler, 2, 200, 10),
        Ok(DriveOutcome::NoWork)
    );
    // A second, independent recovery still agrees: the effect never ran
    // twice at any point along this crash-and-resume path.
    assert_eq!(
        JobRuntime::recover(&mut checkpoints, &schema, 1)
            .unwrap()
            .state(),
        JobState::Succeeded
    );
}

#[test]
fn an_uncertain_non_idempotent_job_never_redispatches_even_after_a_refused_retry_reconcile() {
    let schema = compiled_schema();
    let mut checkpoints = MemoryCheckpointStore::default();
    let mut job = submission(&schema, b"uncertain-non-idempotent");
    job.is_idempotent_handler = false;
    let mut runtime = JobRuntime::enqueue(&mut checkpoints, &schema, 1, job).unwrap();
    // Fail the checkpoint write for the `BegunExecution` persist (call 3:
    // enqueue, claim, begin-execution) after it has already physically
    // landed, the same crash-after-write simulation the CAS-poison test
    // above uses. Recovery must then find a `Running` checkpoint and force
    // `Uncertain` before any handler could possibly run again.
    checkpoints.fail_on(3, true);
    let mut handler = ScriptedHandler::new([HostJobOutcome::Succeeded]);
    assert_eq!(
        runtime.drive_once(&mut checkpoints, &mut handler, 1, 100, 10),
        Err(JobRuntimeError::Checkpoint)
    );
    let mut recovered = JobRuntime::recover(&mut checkpoints, &schema, 1).unwrap();
    assert_eq!(recovered.state(), JobState::Uncertain);
    let mut panic_handler = PanicIfCalledHandler;
    // `Uncertain` is not a claimable state: no drive can dispatch the
    // handler while reconciliation is still pending.
    assert_eq!(
        recovered.drive_once(&mut checkpoints, &mut panic_handler, 2, 200, 10),
        Ok(DriveOutcome::NoWork)
    );
    // Explicitly requesting a retry is refused to change the state at all,
    // because the handler was declared non-idempotent: issue #192 requires
    // exactly this, an uncertain non-idempotent effect is never
    // automatically retried.
    assert_eq!(
        recovered.reconcile(&mut checkpoints, 2),
        Ok(JobState::Uncertain)
    );
    // And still never dispatches: with a `PanicIfCalledHandler`, any stray
    // re-dispatch here would fail loudly rather than passing silently.
    assert_eq!(
        recovered.drive_once(&mut checkpoints, &mut panic_handler, 2, 300, 10),
        Ok(DriveOutcome::NoWork)
    );
}

#[test]
fn enqueue_refuses_a_payload_that_does_not_decode_against_the_schema() {
    let schema = compiled_schema();
    let mut checkpoints = MemoryCheckpointStore::default();
    let mut job = submission(&schema, b"bad-payload");
    job.payload = b"not an admitted interaction value".to_vec();
    assert!(matches!(
        JobRuntime::enqueue(&mut checkpoints, &schema, 1, job),
        Err(JobRuntimeError::PayloadRefused)
    ));
}

#[test]
fn recover_refuses_a_checkpoint_whose_schema_digest_no_longer_matches() {
    let schema = compiled_schema();
    let variant_schema = compiled_schema_variant();
    assert_ne!(schema.schema().digest(), variant_schema.schema().digest());
    let mut checkpoints = MemoryCheckpointStore::default();
    JobRuntime::enqueue(
        &mut checkpoints,
        &schema,
        1,
        submission(&schema, b"schema-changed-underneath"),
    )
    .unwrap();
    // A caller recovering with today's (changed) schema must fail closed
    // rather than decode a queued job against a schema it was never
    // admitted under.
    assert!(matches!(
        JobRuntime::recover(&mut checkpoints, &variant_schema, 1),
        Err(JobRuntimeError::PayloadRefused)
    ));
}

#[test]
fn compensation_is_required_exactly_when_a_running_job_ends_in_permanent_failure() {
    let schema = compiled_schema();
    let mut checkpoints = MemoryCheckpointStore::default();
    let mut runtime = JobRuntime::enqueue(
        &mut checkpoints,
        &schema,
        1,
        submission(&schema, b"compensation-needed"),
    )
    .unwrap();
    assert!(!runtime.compensation_is_required());
    let mut handler = ScriptedHandler::new([HostJobOutcome::PermanentFailure]);
    assert_eq!(
        runtime.drive_once(&mut checkpoints, &mut handler, 1, 100, 10),
        Ok(DriveOutcome::Completed(JobState::PermanentFailure))
    );
    assert!(runtime.compensation_is_required());
    let recovered = JobRuntime::recover(&mut checkpoints, &schema, 1).unwrap();
    assert!(recovered.compensation_is_required());
}

#[test]
fn compensation_is_not_required_when_a_job_is_cancelled_before_it_ever_ran() {
    let schema = compiled_schema();
    let mut checkpoints = MemoryCheckpointStore::default();
    let mut runtime = JobRuntime::enqueue(
        &mut checkpoints,
        &schema,
        1,
        submission(&schema, b"never-ran-cancelled"),
    )
    .unwrap();
    assert_eq!(runtime.cancel(&mut checkpoints), Ok(JobState::Cancelled));
    // Cancelling a job that never started running leaves no partial
    // external effect outstanding, so no compensation hook is required.
    assert!(!runtime.compensation_is_required());
}
