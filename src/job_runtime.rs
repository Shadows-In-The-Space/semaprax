//! Explicit host-driven durable-job execution for the bounded `std.jobs`
//! lifecycle. This is deliberately a small adapter over [`JobStore`], not a
//! second job state machine: enqueue, claim, durable completion, and recovery
//! all call the existing fixture's checked-decision mirror.
//!
//! The host must supply both an explicit checkpoint store and a
//! [`CompiledInteractionSchema`]. The runtime validates the bounded payload
//! against that exact compiler-derived schema before it invokes a
//! [`HostJobHandler`]. It never evaluates source text, discovers a path,
//! creates a thread, or opens a network connection. The handler is a host
//! adapter selected by the host; it receives only admitted data. Binding that
//! adapter to a compiled SEMAPRAX callable remains a separate integration.
//!
//! `FileJobCheckpointStore` is an explicit, single-job, caller-selected-root
//! implementation. It uses a fixed private filename, an advisory file lock, and
//! same-directory atomic replacement. It deliberately makes no power-loss,
//! NFS, distributed-lock, or hostile-root claim. A caller that needs another
//! persistence medium implements [`JobCheckpointStore`] with the same CAS
//! contract.

#[cfg(not(any(target_arch = "wasm32", target_arch = "wasm64")))]
use std::fs::{self, File, OpenOptions};
#[cfg(not(any(target_arch = "wasm32", target_arch = "wasm64")))]
use std::io::{Read, Write};
#[cfg(not(any(target_arch = "wasm32", target_arch = "wasm64")))]
use std::path::{Path, PathBuf};

use crate::agent_interaction_schema::CompiledInteractionSchema;
use crate::database_fixture::DatabaseFixture;
use crate::job_evidence::{JobEvidenceEntry, JobEvidenceLog};
use crate::job_fixture::{
    decisions, CompletionAttempt, EnqueueOutcome, JobFixtureError, JobState, JobStore, OutcomeKind,
    Schedule,
};

mod source_handler;
pub use source_handler::{
    drive_checked_source_job, SourceJobDriveError, SourceJobHandlerBinding, SourceJobHandlerRefusal,
};

pub const JOB_RUNTIME_CHECKPOINT_SCHEMA: &str = "semaprax.job-runtime-checkpoint.v1";
pub const MAX_JOB_RUNTIME_PAYLOAD_BYTES: usize = 4096;
pub const MAX_JOB_RUNTIME_KEY_BYTES: usize = 256;
pub const MAX_JOB_RUNTIME_DESCRIPTOR_BYTES: usize = 256;
pub const MAX_JOB_RUNTIME_SCHEMA_DIGEST_BYTES: usize = 128;
pub const MAX_JOB_RUNTIME_EVIDENCE_ENTRIES: usize = 64;
pub const MAX_JOB_RUNTIME_CHECKPOINT_BYTES: usize = 16 * 1024;

const CHECKPOINT_MAGIC: &[u8; 8] = b"SPXJOB01";
const STORE_FILE: &str = "job-runtime.checkpoint.v1";
const STORE_LOCK: &str = "job-runtime.checkpoint.lock";
const STORE_STAGE: &str = "job-runtime.checkpoint.stage";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CheckpointStoreError;

/// One generation read from an explicit checkpoint store. `generation` must
/// increase on every successful compare-and-swap, including when a later
/// document has identical bytes; it prevents ABA acceptance.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StoredJobCheckpoint {
    pub generation: u64,
    pub bytes: Vec<u8>,
}

/// Caller-owned, one-job checkpoint persistence. A successful `compare_and_swap`
/// publishes all `document` bytes or retains the prior generation. An expected
/// generation mismatch is a refusal, never a blind overwrite.
pub trait JobCheckpointStore {
    fn load(&mut self) -> Result<Option<StoredJobCheckpoint>, CheckpointStoreError>;
    fn compare_and_swap(
        &mut self,
        expected_generation: Option<u64>,
        document: &[u8],
    ) -> Result<u64, CheckpointStoreError>;
}

/// A physical implementation rooted at one caller-selected existing directory.
/// It has no API accepting arbitrary later paths or filenames.
#[cfg(not(any(target_arch = "wasm32", target_arch = "wasm64")))]
pub struct FileJobCheckpointStore {
    root: PathBuf,
}

#[cfg(not(any(target_arch = "wasm32", target_arch = "wasm64")))]
impl FileJobCheckpointStore {
    pub fn open(root: &Path) -> Result<Self, CheckpointStoreError> {
        let metadata = fs::symlink_metadata(root).map_err(|_| CheckpointStoreError)?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(CheckpointStoreError);
        }
        Ok(Self {
            root: root.to_owned(),
        })
    }

    fn path(&self, name: &str) -> PathBuf {
        self.root.join(name)
    }

    fn read_current(&self) -> Result<Option<StoredJobCheckpoint>, CheckpointStoreError> {
        let path = self.path(STORE_FILE);
        let metadata = match fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(_) => return Err(CheckpointStoreError),
        };
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(CheckpointStoreError);
        }
        if metadata.len() < 8 || metadata.len() > (MAX_JOB_RUNTIME_CHECKPOINT_BYTES + 8) as u64 {
            return Err(CheckpointStoreError);
        }
        let mut bytes = Vec::with_capacity(metadata.len() as usize);
        File::open(path)
            .and_then(|mut file| file.read_to_end(&mut bytes))
            .map_err(|_| CheckpointStoreError)?;
        let generation =
            u64::from_le_bytes(bytes[..8].try_into().map_err(|_| CheckpointStoreError)?);
        Ok(Some(StoredJobCheckpoint {
            generation,
            bytes: bytes[8..].to_vec(),
        }))
    }

    fn lock(&self) -> Result<StoreLock, CheckpointStoreError> {
        let path = self.path(STORE_LOCK);
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&path)
            .map_err(|_| CheckpointStoreError)?;
        fs2::FileExt::try_lock_exclusive(&file).map_err(|_| CheckpointStoreError)?;
        Ok(StoreLock(file))
    }
}

#[cfg(not(any(target_arch = "wasm32", target_arch = "wasm64")))]
struct StoreLock(File);

#[cfg(not(any(target_arch = "wasm32", target_arch = "wasm64")))]
impl Drop for StoreLock {
    fn drop(&mut self) {
        let _ = fs2::FileExt::unlock(&self.0);
    }
}

#[cfg(not(any(target_arch = "wasm32", target_arch = "wasm64")))]
impl JobCheckpointStore for FileJobCheckpointStore {
    fn load(&mut self) -> Result<Option<StoredJobCheckpoint>, CheckpointStoreError> {
        self.read_current()
    }

    fn compare_and_swap(
        &mut self,
        expected_generation: Option<u64>,
        document: &[u8],
    ) -> Result<u64, CheckpointStoreError> {
        if document.len() > MAX_JOB_RUNTIME_CHECKPOINT_BYTES {
            return Err(CheckpointStoreError);
        }
        let _lock = self.lock()?;
        let current = self.read_current()?;
        if current.as_ref().map(|stored| stored.generation) != expected_generation {
            return Err(CheckpointStoreError);
        }
        let next = match expected_generation {
            None => 1,
            Some(generation) => generation.checked_add(1).ok_or(CheckpointStoreError)?,
        };
        let stage = self.path(STORE_STAGE);
        match fs::symlink_metadata(&stage) {
            Ok(metadata)
                if metadata.file_type().is_file() && !metadata.file_type().is_symlink() =>
            {
                // A prior writer died before its replace. The fixed stage name
                // is owned exclusively under the selected root and cannot be a
                // current writer while this store lock is held.
                fs::remove_file(&stage).map_err(|_| CheckpointStoreError)?;
            }
            Ok(_) => return Err(CheckpointStoreError),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err(CheckpointStoreError),
        }
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&stage)
            .map_err(|_| CheckpointStoreError)?;
        file.write_all(&next.to_le_bytes())
            .and_then(|_| file.write_all(document))
            .and_then(|_| file.sync_all())
            .map_err(|_| CheckpointStoreError)?;
        drop(file);
        fs::rename(stage, self.path(STORE_FILE)).map_err(|_| CheckpointStoreError)?;
        Ok(next)
    }
}

/// One bounded job submission. The payload is a complete interaction document
/// admitted by the supplied [`CompiledInteractionSchema`], rather than source
/// text or an arbitrary callback program.
#[derive(Clone, Debug)]
pub struct JobSubmission {
    pub idempotency_key: Vec<u8>,
    pub payload_descriptor: Vec<u8>,
    pub payload: Vec<u8>,
    pub schedule: Option<Schedule>,
    pub max_attempts: u8,
    pub is_idempotent_handler: bool,
    pub base_backoff_ticks: u64,
    pub max_backoff_ticks: u64,
}

/// A host adapter. The runtime does not execute arbitrary source: it first
/// admits the payload with the exact schema supplied at enqueue/recovery, then
/// hands the same bytes to this explicit host seam. This trait alone does not
/// prove its implementation invokes a compiler-checked SEMAPRAX callable.
pub trait HostJobHandler {
    fn execute(&mut self, admitted_payload: &[u8]) -> HostJobOutcome;
}

/// The closed outcome reported by a host adapter. `Uncertain` is reserved for
/// a provider-observed outcome-unknown signal, such as `std.fs`'s checked
/// atomic write outcome, or a post-dispatch failure whose result cannot be
/// determined. Callers must classify conservatively; uncertain is never
/// retried automatically unless the existing JobStore reducer permits it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HostJobOutcome {
    Succeeded,
    RetryableFailure,
    PermanentFailure,
    Uncertain,
}

impl HostJobOutcome {
    fn job_outcome(self) -> OutcomeKind {
        match self {
            Self::Succeeded => OutcomeKind::Success,
            Self::RetryableFailure => OutcomeKind::Retryable,
            Self::PermanentFailure => OutcomeKind::Permanent,
            Self::Uncertain => OutcomeKind::Uncertain,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum JobRuntimeError {
    Checkpoint,
    InvalidSubmission,
    PayloadRefused,
    Evidence,
    Store(JobFixtureError),
    StaleLease,
    Poisoned,
}

/// Result of one explicit host drive. A runner never loops or schedules work
/// itself; the caller supplies each worker, tick, and lease duration.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DriveOutcome {
    Completed(JobState),
    NoWork,
}

/// Restorable runtime state. `JobStore` remains the sole lifecycle reducer;
/// the checkpoint is a bounded configuration plus replayable evidence, not a
/// second copy of lease/state truth.
pub struct JobRuntime<'schema> {
    schema: &'schema CompiledInteractionSchema,
    submission: JobSubmission,
    store: JobStore,
    ledger: DatabaseFixture,
    job_id: u64,
    evidence: JobEvidenceLog,
    replay_facts: Vec<ReplayFact>,
    bound_revision: u8,
    checkpoint_generation: Option<u64>,
    poisoned: bool,
}
#[derive(Clone, Copy, Debug, Default)]
struct ReplayFact {
    tick: u64,
    worker_id: u32,
    lease_ticks: u64,
}

impl<'schema> JobRuntime<'schema> {
    pub fn enqueue(
        checkpoints: &mut impl JobCheckpointStore,
        schema: &'schema CompiledInteractionSchema,
        current_revision: u8,
        submission: JobSubmission,
    ) -> Result<Self, JobRuntimeError> {
        if current_revision == 0 {
            return Err(JobRuntimeError::InvalidSubmission);
        }
        validate_submission(schema, &submission)?;
        let mut ledger = DatabaseFixture::new();
        JobStore::install_ledger_schema(&mut ledger);
        let mut store = JobStore::new(current_revision);
        let EnqueueOutcome::Created(job_id) = store
            .enqueue(
                &mut ledger,
                submission.idempotency_key.clone(),
                submission.payload_descriptor.clone(),
                submission.schedule,
                submission.max_attempts,
                submission.is_idempotent_handler,
            )
            .map_err(JobRuntimeError::Store)?
        else {
            return Err(JobRuntimeError::InvalidSubmission);
        };
        let mut evidence = JobEvidenceLog::new();
        evidence.append(
            JobEvidenceEntry::Enqueued {
                scheduled: submission.schedule.is_some(),
            },
            store.state_of(job_id).expect("created job exists").code(),
        );
        let mut runtime = Self {
            schema,
            submission,
            store,
            ledger,
            job_id,
            evidence,
            replay_facts: vec![ReplayFact::default()],
            bound_revision: current_revision,
            checkpoint_generation: None,
            poisoned: false,
        };
        runtime.persist(checkpoints)?;
        Ok(runtime)
    }

    /// Opens one exact checkpoint under the supplied current schema. Evidence
    /// is replayed before state is rebuilt. A persisted `RUNNING` checkpoint
    /// never returns to `PENDING`: recovery records `UNCERTAIN` first.
    pub fn recover(
        checkpoints: &mut impl JobCheckpointStore,
        schema: &'schema CompiledInteractionSchema,
        current_revision: u8,
    ) -> Result<Self, JobRuntimeError> {
        if current_revision == 0 {
            return Err(JobRuntimeError::InvalidSubmission);
        }
        let stored = checkpoints
            .load()
            .map_err(|_| JobRuntimeError::Checkpoint)?
            .ok_or(JobRuntimeError::Checkpoint)?;
        let checkpoint = RuntimeCheckpoint::decode(&stored.bytes)?;
        if checkpoint.schema_digest != schema.schema().digest() {
            return Err(JobRuntimeError::PayloadRefused);
        }
        if checkpoint.bound_revision > current_revision {
            return Err(JobRuntimeError::Store(JobFixtureError::RevisionRefused));
        }
        validate_submission(schema, &checkpoint.submission)?;
        let evidence =
            JobEvidenceLog::from_entries(checkpoint.entries, checkpoint.claimed_final_state)
                .map_err(|_| JobRuntimeError::Evidence)?;
        let mut runtime = Self::replay_store(
            schema,
            current_revision,
            checkpoint.submission,
            evidence,
            checkpoint.replay_facts,
            checkpoint.bound_revision,
            Some(stored.generation),
        )?;
        match runtime.store.state_of(runtime.job_id) {
            Some(JobState::Leased) => {
                let claim = runtime
                    .replay_facts
                    .iter()
                    .rev()
                    .find(|f| f.lease_ticks != 0)
                    .ok_or(JobRuntimeError::Evidence)?;
                let expiry = claim
                    .tick
                    .checked_add(claim.lease_ticks)
                    .ok_or(JobRuntimeError::Evidence)?;
                if runtime.store.expire_stale_leases(expiry) != [runtime.job_id] {
                    return Err(JobRuntimeError::Evidence);
                }
                runtime
                    .evidence
                    .append(JobEvidenceEntry::LeaseExpired, JobState::Pending.code());
                runtime.replay_facts.push(ReplayFact {
                    tick: expiry,
                    ..ReplayFact::default()
                });
                runtime.persist(checkpoints)?;
            }
            Some(JobState::Running) => {
                runtime
                    .store
                    .record_connection_uncertain(runtime.job_id)
                    .map_err(JobRuntimeError::Store)?;
                runtime.evidence.append(
                    JobEvidenceEntry::ConnectionUncertain,
                    JobState::Uncertain.code(),
                );
                runtime.replay_facts.push(ReplayFact::default());
                runtime.persist(checkpoints)?;
            }
            Some(_) => {}
            None => return Err(JobRuntimeError::Evidence),
        }
        Ok(runtime)
    }

    pub fn state(&self) -> JobState {
        self.store
            .state_of(self.job_id)
            .expect("runtime job exists")
    }

    pub fn evidence(&self) -> &JobEvidenceLog {
        &self.evidence
    }

    /// The exact compiled payload-schema digest this runtime was admitted
    /// against. Checked source handlers compare it before claiming a job.
    #[must_use]
    pub fn schema_digest(&self) -> &str {
        self.schema.schema().digest()
    }

    /// The opaque descriptor persisted with this submission. Checked source
    /// handlers bind it to their exact retained deployment identity before a
    /// job can be claimed.
    #[must_use]
    pub fn payload_descriptor(&self) -> &[u8] {
        &self.submission.payload_descriptor
    }

    /// Persists an explicit cancellation through the canonical JobStore
    /// reducer. A running job is refused by that reducer and no checkpoint is
    /// written; a successful cancellation is immediately checkpointed.
    pub fn cancel(
        &mut self,
        checkpoints: &mut impl JobCheckpointStore,
    ) -> Result<JobState, JobRuntimeError> {
        if self.poisoned {
            return Err(JobRuntimeError::Poisoned);
        }
        let state = self
            .store
            .cancel(self.job_id)
            .map_err(JobRuntimeError::Store)?;
        self.evidence
            .append(JobEvidenceEntry::Cancelled, state.code());
        self.replay_facts.push(ReplayFact::default());
        self.persist(checkpoints)?;
        Ok(state)
    }

    /// Performs one host-selected attempt. It checkpoints after claim and
    /// before handler execution, so a crash in the handler window recovers to
    /// `UNCERTAIN`; it cannot cause an unsafe blind retry.
    pub fn drive_once(
        &mut self,
        checkpoints: &mut impl JobCheckpointStore,
        handler: &mut impl HostJobHandler,
        worker_id: u32,
        now_tick: u64,
        lease_ticks: u64,
    ) -> Result<DriveOutcome, JobRuntimeError> {
        if self.poisoned {
            return Err(JobRuntimeError::Poisoned);
        }
        if lease_ticks == 0
            || now_tick.checked_add(lease_ticks).is_none()
            || now_tick
                .checked_add(self.submission.max_backoff_ticks)
                .is_none()
        {
            return Err(JobRuntimeError::InvalidSubmission);
        }
        self.store
            .revision_check(self.job_id)
            .map_err(JobRuntimeError::Store)?;
        if let Some(schedule) = self.submission.schedule {
            self.store
                .recurring_advance_is_safe(self.job_id, now_tick, schedule.max_catch_up)
                .map_err(JobRuntimeError::Store)?;
        }
        let (_, lease_generation, _) =
            match self
                .store
                .claim(self.job_id, worker_id, now_tick, lease_ticks)
            {
                Ok(lease) => lease,
                Err(JobFixtureError::ClaimNotLegal) => return Ok(DriveOutcome::NoWork),
                Err(error) => return Err(JobRuntimeError::Store(error)),
            };
        if self.store.leased_worker_id(self.job_id) != Some(worker_id) {
            return Err(JobRuntimeError::StaleLease);
        }
        self.evidence.append(
            JobEvidenceEntry::Claimed { is_due: true },
            JobState::Leased.code(),
        );
        self.replay_facts.push(ReplayFact {
            tick: now_tick,
            worker_id,
            lease_ticks,
        });
        self.persist(checkpoints)?;
        self.store
            .begin_execution(self.job_id, lease_generation, now_tick)
            .map_err(JobRuntimeError::Store)?;
        self.evidence
            .append(JobEvidenceEntry::BegunExecution, JobState::Running.code());
        self.replay_facts.push(ReplayFact {
            tick: now_tick,
            worker_id,
            ..ReplayFact::default()
        });
        self.persist(checkpoints)?;

        // The schema check is repeated at the execution boundary. A source
        // revision/schema change cannot turn retained bytes into handler input.
        validate_submission(self.schema, &self.submission)?;
        let outcome = handler.execute(&self.submission.payload).job_outcome();
        if self.store.leased_worker_id(self.job_id) != Some(worker_id) {
            return Err(JobRuntimeError::StaleLease);
        }
        let attempt_before = self
            .store
            .attempt_of(self.job_id)
            .ok_or(JobRuntimeError::Store(JobFixtureError::UnknownJob))?;
        let mut state = self
            .store
            .complete_durable(
                &mut self.ledger,
                self.job_id,
                CompletionAttempt {
                    lease_generation,
                    now_tick,
                    outcome,
                    base_backoff_ticks: self.submission.base_backoff_ticks,
                    max_backoff_ticks: self.submission.max_backoff_ticks,
                },
            )
            .map_err(JobRuntimeError::Store)?;
        let natural = completion_state(outcome, attempt_before, self.submission.max_attempts);
        self.evidence.append(
            JobEvidenceEntry::DurableCompleted {
                outcome_kind: outcome_code(outcome),
                attempt_before,
                max_attempts: self.submission.max_attempts,
                commit_confirmed: state == natural,
            },
            state.code(),
        );
        self.replay_facts.push(ReplayFact {
            tick: now_tick,
            worker_id,
            ..ReplayFact::default()
        });
        if outcome == OutcomeKind::Success && state == JobState::Succeeded {
            if let Some(schedule) = &self.submission.schedule {
                let next_run_tick = self
                    .store
                    .advance_recurring_schedule(self.job_id, now_tick, schedule.max_catch_up)
                    .map_err(JobRuntimeError::Store)?;
                let occurrences_run = self
                    .store
                    .occurrences_run_of(self.job_id)
                    .ok_or(JobRuntimeError::Store(JobFixtureError::UnknownJob))?;
                state = self.state();
                self.evidence.append(
                    JobEvidenceEntry::RecurringAdvanced {
                        next_run_tick,
                        occurrences_run,
                    },
                    state.code(),
                );
                self.replay_facts.push(ReplayFact {
                    tick: now_tick,
                    worker_id,
                    ..ReplayFact::default()
                });
            }
        }
        self.persist(checkpoints)?;
        Ok(DriveOutcome::Completed(state))
    }

    /// Applies a human/operator reconciliation finding. A retry finding only
    /// changes an uncertain job when `JobStore`'s idempotency/attempt reducer
    /// permits it; no handler is run by this method.
    pub fn reconcile(
        &mut self,
        checkpoints: &mut impl JobCheckpointStore,
        decision: usize,
    ) -> Result<JobState, JobRuntimeError> {
        if self.poisoned {
            return Err(JobRuntimeError::Poisoned);
        }
        let attempt = self
            .store
            .attempt_of(self.job_id)
            .ok_or(JobRuntimeError::Store(JobFixtureError::UnknownJob))?;
        let state = self
            .store
            .reconcile_uncertain(self.job_id, decision)
            .map_err(JobRuntimeError::Store)?;
        self.evidence.append(
            JobEvidenceEntry::ReconciledUncertain {
                decision,
                is_idempotent_handler: self.submission.is_idempotent_handler,
                attempt,
                max_attempts: self.submission.max_attempts,
            },
            state.code(),
        );
        self.replay_facts.push(ReplayFact::default());
        self.persist(checkpoints)?;
        Ok(state)
    }

    fn persist(
        &mut self,
        checkpoints: &mut impl JobCheckpointStore,
    ) -> Result<(), JobRuntimeError> {
        let document = match RuntimeCheckpoint::from_runtime(self).encode() {
            Ok(document) => document,
            Err(error) => {
                self.poisoned = true;
                return Err(error);
            }
        };
        let generation = match checkpoints.compare_and_swap(self.checkpoint_generation, &document) {
            Ok(generation) => generation,
            Err(_) => {
                self.poisoned = true;
                return Err(JobRuntimeError::Checkpoint);
            }
        };
        self.checkpoint_generation = Some(generation);
        Ok(())
    }

    fn replay_store(
        schema: &'schema CompiledInteractionSchema,
        current_revision: u8,
        submission: JobSubmission,
        evidence: JobEvidenceLog,
        replay_facts: Vec<ReplayFact>,
        bound_revision: u8,
        checkpoint_generation: Option<u64>,
    ) -> Result<Self, JobRuntimeError> {
        let mut ledger = DatabaseFixture::new();
        JobStore::install_ledger_schema(&mut ledger);
        let mut store = JobStore::new(bound_revision);
        let EnqueueOutcome::Created(job_id) = store
            .enqueue(
                &mut ledger,
                submission.idempotency_key.clone(),
                submission.payload_descriptor.clone(),
                submission.schedule,
                submission.max_attempts,
                submission.is_idempotent_handler,
            )
            .map_err(JobRuntimeError::Store)?
        else {
            return Err(JobRuntimeError::Evidence);
        };
        store.set_current_revision(current_revision);
        if evidence.entries().len() != replay_facts.len() {
            return Err(JobRuntimeError::Evidence);
        }
        let mut lease_generation = None;
        for (index, (entry, fact)) in evidence
            .entries()
            .iter()
            .copied()
            .zip(replay_facts.iter().copied())
            .enumerate()
        {
            if matches!(
                entry,
                JobEvidenceEntry::Completed { .. } | JobEvidenceEntry::DurableCompleted { .. }
            ) && fact
                .tick
                .checked_add(submission.max_backoff_ticks)
                .is_none()
            {
                return Err(JobRuntimeError::Evidence);
            }
            match entry {
                JobEvidenceEntry::Enqueued { scheduled }
                    if index == 0 && scheduled == submission.schedule.is_some() => {}
                JobEvidenceEntry::Claimed { is_due } => {
                    if fact.lease_ticks == 0
                        || fact.tick.checked_add(fact.lease_ticks).is_none()
                        || is_due
                            != submission
                                .schedule
                                .is_none_or(|schedule| fact.tick >= schedule.next_run_tick)
                    {
                        return Err(JobRuntimeError::Evidence);
                    }
                    let (_, lease, _) = store
                        .claim(job_id, fact.worker_id, fact.tick, fact.lease_ticks)
                        .map_err(|_| JobRuntimeError::Evidence)?;
                    lease_generation = Some(lease);
                }
                JobEvidenceEntry::BegunExecution => store
                    .begin_execution(
                        job_id,
                        lease_generation.ok_or(JobRuntimeError::Evidence)?,
                        fact.tick,
                    )
                    .map_err(|_| JobRuntimeError::Evidence)?,
                JobEvidenceEntry::Completed {
                    outcome_kind,
                    attempt_before,
                    max_attempts,
                } => replay_completion(
                    &mut store,
                    job_id,
                    lease_generation,
                    fact.tick,
                    outcome_kind,
                    attempt_before,
                    max_attempts,
                    &submission,
                )?,
                JobEvidenceEntry::DurableCompleted {
                    outcome_kind,
                    attempt_before,
                    max_attempts,
                    commit_confirmed,
                } if commit_confirmed => {
                    if max_attempts != submission.max_attempts
                        || store.attempt_of(job_id) != Some(attempt_before)
                    {
                        return Err(JobRuntimeError::Evidence);
                    }
                    store
                        .complete_durable(
                            &mut ledger,
                            job_id,
                            CompletionAttempt {
                                lease_generation: lease_generation
                                    .ok_or(JobRuntimeError::Evidence)?,
                                now_tick: fact.tick,
                                outcome: outcome_from_code(outcome_kind)
                                    .ok_or(JobRuntimeError::Evidence)?,
                                base_backoff_ticks: submission.base_backoff_ticks,
                                max_backoff_ticks: submission.max_backoff_ticks,
                            },
                        )
                        .map_err(|_| JobRuntimeError::Evidence)?;
                }
                JobEvidenceEntry::DurableCompleted {
                    outcome_kind,
                    attempt_before,
                    max_attempts,
                    commit_confirmed: false,
                } => {
                    if max_attempts != submission.max_attempts
                        || store.attempt_of(job_id) != Some(attempt_before)
                        || outcome_from_code(outcome_kind).is_none()
                    {
                        return Err(JobRuntimeError::Evidence);
                    }
                    store
                        .record_connection_uncertain(job_id)
                        .map_err(|_| JobRuntimeError::Evidence)?;
                }
                JobEvidenceEntry::ConnectionUncertain => store
                    .record_connection_uncertain(job_id)
                    .map_err(|_| JobRuntimeError::Evidence)?,
                JobEvidenceEntry::ReconciledUncertain {
                    decision,
                    is_idempotent_handler,
                    attempt,
                    max_attempts,
                } if is_idempotent_handler == submission.is_idempotent_handler
                    && max_attempts == submission.max_attempts
                    && store.attempt_of(job_id) == Some(attempt) =>
                {
                    store
                        .reconcile_uncertain(job_id, decision)
                        .map_err(|_| JobRuntimeError::Evidence)?;
                }
                JobEvidenceEntry::Cancelled => {
                    store
                        .cancel(job_id)
                        .map_err(|_| JobRuntimeError::Evidence)?;
                }
                JobEvidenceEntry::RecurringAdvanced {
                    next_run_tick,
                    occurrences_run,
                } => {
                    let schedule = submission.schedule.ok_or(JobRuntimeError::Evidence)?;
                    let advanced = store
                        .advance_recurring_schedule(job_id, fact.tick, schedule.max_catch_up)
                        .map_err(|_| JobRuntimeError::Evidence)?;
                    if advanced != next_run_tick
                        || store.occurrences_run_of(job_id) != Some(occurrences_run)
                    {
                        return Err(JobRuntimeError::Evidence);
                    }
                }
                JobEvidenceEntry::LeaseExpired => {
                    if store.expire_stale_leases(fact.tick) != [job_id] {
                        return Err(JobRuntimeError::Evidence);
                    }
                }
                _ => return Err(JobRuntimeError::Evidence),
            }
        }
        if store.state_of(job_id).map(JobState::code) != evidence.replay().ok() {
            return Err(JobRuntimeError::Evidence);
        }
        Ok(Self {
            schema,
            submission,
            store,
            ledger,
            job_id,
            evidence,
            replay_facts,
            bound_revision,
            checkpoint_generation,
            poisoned: false,
        })
    }
}

fn validate_submission(
    schema: &CompiledInteractionSchema,
    submission: &JobSubmission,
) -> Result<(), JobRuntimeError> {
    if submission.idempotency_key.is_empty()
        || submission.idempotency_key.len() > MAX_JOB_RUNTIME_KEY_BYTES
        || submission.payload_descriptor.is_empty()
        || submission.payload_descriptor.len() > MAX_JOB_RUNTIME_DESCRIPTOR_BYTES
        || submission.payload.len() > MAX_JOB_RUNTIME_PAYLOAD_BYTES
        || submission.max_attempts == 0
        || submission.base_backoff_ticks > submission.max_backoff_ticks
        || submission
            .schedule
            .is_some_and(|schedule| schedule.interval_tick == 0 || schedule.max_occurrences == 0)
    {
        return Err(JobRuntimeError::InvalidSubmission);
    }
    schema
        .decode(&submission.payload)
        .map_err(|_| JobRuntimeError::PayloadRefused)?;
    Ok(())
}

fn outcome_code(outcome: OutcomeKind) -> usize {
    match outcome {
        OutcomeKind::Success => 0,
        OutcomeKind::Retryable => 1,
        OutcomeKind::Permanent => 2,
        OutcomeKind::Uncertain => 3,
    }
}

fn outcome_from_code(code: usize) -> Option<OutcomeKind> {
    Some(match code {
        0 => OutcomeKind::Success,
        1 => OutcomeKind::Retryable,
        2 => OutcomeKind::Permanent,
        3 => OutcomeKind::Uncertain,
        _ => return None,
    })
}

fn completion_state(outcome: OutcomeKind, attempt_before: u8, max_attempts: u8) -> JobState {
    let attempt_after = if outcome == OutcomeKind::Success {
        attempt_before
    } else {
        attempt_before.saturating_add(1)
    };
    match decisions::retry_next_state_after_outcome(
        outcome_code(outcome),
        attempt_after,
        max_attempts,
    ) {
        5 => JobState::Scheduled,
        0 => JobState::Pending,
        1 => JobState::Scheduled,
        2 => JobState::Leased,
        3 => JobState::Running,
        4 => JobState::Succeeded,
        6 => JobState::PermanentFailure,
        7 => JobState::Cancelled,
        8 => JobState::Uncertain,
        _ => JobState::DeadLettered,
    }
}

#[allow(clippy::too_many_arguments)]
fn replay_completion(
    store: &mut JobStore,
    job_id: u64,
    lease_generation: Option<u64>,
    tick: u64,
    outcome_kind: usize,
    attempt_before: u8,
    max_attempts: u8,
    submission: &JobSubmission,
) -> Result<(), JobRuntimeError> {
    if max_attempts != submission.max_attempts || store.attempt_of(job_id) != Some(attempt_before) {
        return Err(JobRuntimeError::Evidence);
    }
    if tick.checked_add(submission.max_backoff_ticks).is_none() {
        return Err(JobRuntimeError::Evidence);
    }
    store
        .complete(
            job_id,
            lease_generation.ok_or(JobRuntimeError::Evidence)?,
            tick,
            outcome_from_code(outcome_kind).ok_or(JobRuntimeError::Evidence)?,
            submission.base_backoff_ticks,
            submission.max_backoff_ticks,
        )
        .map_err(|_| JobRuntimeError::Evidence)?;
    Ok(())
}

#[derive(Clone, Debug)]
struct RuntimeCheckpoint {
    schema_digest: String,
    bound_revision: u8,
    submission: JobSubmission,
    entries: Vec<JobEvidenceEntry>,
    replay_facts: Vec<ReplayFact>,
    claimed_final_state: usize,
}

impl RuntimeCheckpoint {
    fn from_runtime(runtime: &JobRuntime<'_>) -> Self {
        Self {
            schema_digest: runtime.schema.schema().digest().to_owned(),
            bound_revision: runtime.bound_revision,
            submission: runtime.submission.clone(),
            entries: runtime.evidence.entries().to_vec(),
            replay_facts: runtime.replay_facts.clone(),
            claimed_final_state: runtime.evidence.claimed_final_state(),
        }
    }

    fn encode(&self) -> Result<Vec<u8>, JobRuntimeError> {
        if self.schema_digest.len() > MAX_JOB_RUNTIME_SCHEMA_DIGEST_BYTES
            || self.entries.len() > MAX_JOB_RUNTIME_EVIDENCE_ENTRIES
            || self.entries.len() != self.replay_facts.len()
        {
            return Err(JobRuntimeError::InvalidSubmission);
        }
        let mut bytes = CHECKPOINT_MAGIC.to_vec();
        push_u16(&mut bytes, self.schema_digest.len())?;
        bytes.extend_from_slice(self.schema_digest.as_bytes());
        bytes.push(self.bound_revision);
        push_bytes(
            &mut bytes,
            &self.submission.idempotency_key,
            MAX_JOB_RUNTIME_KEY_BYTES,
        )?;
        push_bytes(
            &mut bytes,
            &self.submission.payload_descriptor,
            MAX_JOB_RUNTIME_DESCRIPTOR_BYTES,
        )?;
        push_u32(&mut bytes, self.submission.payload.len())?;
        bytes.extend_from_slice(&self.submission.payload);
        bytes.push(self.submission.max_attempts);
        bytes.push(u8::from(self.submission.is_idempotent_handler));
        match self.submission.schedule {
            None => bytes.push(0),
            Some(schedule) => {
                bytes.push(1);
                for field in [
                    schedule.next_run_tick,
                    schedule.interval_tick,
                    schedule.max_occurrences,
                    schedule.max_catch_up,
                ] {
                    bytes.extend_from_slice(&field.to_le_bytes());
                }
            }
        }
        bytes.extend_from_slice(&self.submission.base_backoff_ticks.to_le_bytes());
        bytes.extend_from_slice(&self.submission.max_backoff_ticks.to_le_bytes());
        push_u16(&mut bytes, self.entries.len())?;
        for (entry, fact) in self.entries.iter().zip(self.replay_facts.iter()) {
            let encoded = entry.canonical_bytes();
            if encoded.len() > u8::MAX as usize {
                return Err(JobRuntimeError::Evidence);
            }
            bytes.push(encoded.len() as u8);
            bytes.extend_from_slice(&encoded);
            bytes.extend_from_slice(&fact.tick.to_le_bytes());
            bytes.extend_from_slice(&fact.worker_id.to_le_bytes());
            bytes.extend_from_slice(&fact.lease_ticks.to_le_bytes());
        }
        let claimed =
            u8::try_from(self.claimed_final_state).map_err(|_| JobRuntimeError::Evidence)?;
        bytes.push(claimed);
        if bytes.len() > MAX_JOB_RUNTIME_CHECKPOINT_BYTES {
            return Err(JobRuntimeError::InvalidSubmission);
        }
        Ok(bytes)
    }

    fn decode(bytes: &[u8]) -> Result<Self, JobRuntimeError> {
        if bytes.len() > MAX_JOB_RUNTIME_CHECKPOINT_BYTES {
            return Err(JobRuntimeError::Checkpoint);
        }
        let mut reader = Reader::new(bytes);
        if reader.take(8)? != CHECKPOINT_MAGIC {
            return Err(JobRuntimeError::Checkpoint);
        }
        let schema_digest_len = reader.u16()? as usize;
        let schema_digest = String::from_utf8(reader.take(schema_digest_len)?.to_vec())
            .map_err(|_| JobRuntimeError::Checkpoint)?;
        if schema_digest.is_empty() || schema_digest.len() > MAX_JOB_RUNTIME_SCHEMA_DIGEST_BYTES {
            return Err(JobRuntimeError::Checkpoint);
        }
        let bound_revision = reader.u8()?;
        if bound_revision == 0 {
            return Err(JobRuntimeError::Checkpoint);
        }
        let idempotency_key = reader.sized_bytes(2, MAX_JOB_RUNTIME_KEY_BYTES)?;
        let payload_descriptor = reader.sized_bytes(2, MAX_JOB_RUNTIME_DESCRIPTOR_BYTES)?;
        let payload = reader.sized_bytes(4, MAX_JOB_RUNTIME_PAYLOAD_BYTES)?;
        let max_attempts = reader.u8()?;
        let is_idempotent_handler = reader.bool()?;
        let schedule = match reader.u8()? {
            0 => None,
            1 => Some(Schedule {
                next_run_tick: reader.u64()?,
                interval_tick: reader.u64()?,
                max_occurrences: reader.u64()?,
                max_catch_up: reader.u64()?,
            }),
            _ => return Err(JobRuntimeError::Checkpoint),
        };
        let base_backoff_ticks = reader.u64()?;
        let max_backoff_ticks = reader.u64()?;
        let entry_count = reader.u16()? as usize;
        if entry_count == 0 || entry_count > MAX_JOB_RUNTIME_EVIDENCE_ENTRIES {
            return Err(JobRuntimeError::Checkpoint);
        }
        let mut entries = Vec::with_capacity(entry_count);
        let mut replay_facts = Vec::with_capacity(entry_count);
        for _ in 0..entry_count {
            let entry_len = reader.u8()? as usize;
            let entry = JobEvidenceEntry::from_canonical_bytes(reader.take(entry_len)?)
                .ok_or(JobRuntimeError::Checkpoint)?;
            entries.push(entry);
            replay_facts.push(ReplayFact {
                tick: reader.u64()?,
                worker_id: reader.u32()?,
                lease_ticks: reader.u64()?,
            });
        }
        let claimed_final_state = reader.u8()? as usize;
        if !reader.is_empty() || claimed_final_state > 9 {
            return Err(JobRuntimeError::Checkpoint);
        }
        Ok(Self {
            schema_digest,
            bound_revision,
            submission: JobSubmission {
                idempotency_key,
                payload_descriptor,
                payload,
                schedule,
                max_attempts,
                is_idempotent_handler,
                base_backoff_ticks,
                max_backoff_ticks,
            },
            entries,
            replay_facts,
            claimed_final_state,
        })
    }
}

fn push_u16(bytes: &mut Vec<u8>, value: usize) -> Result<(), JobRuntimeError> {
    bytes.extend_from_slice(
        &u16::try_from(value)
            .map_err(|_| JobRuntimeError::InvalidSubmission)?
            .to_le_bytes(),
    );
    Ok(())
}

fn push_u32(bytes: &mut Vec<u8>, value: usize) -> Result<(), JobRuntimeError> {
    bytes.extend_from_slice(
        &u32::try_from(value)
            .map_err(|_| JobRuntimeError::InvalidSubmission)?
            .to_le_bytes(),
    );
    Ok(())
}

fn push_bytes(bytes: &mut Vec<u8>, value: &[u8], maximum: usize) -> Result<(), JobRuntimeError> {
    if value.is_empty() || value.len() > maximum {
        return Err(JobRuntimeError::InvalidSubmission);
    }
    push_u16(bytes, value.len())?;
    bytes.extend_from_slice(value);
    Ok(())
}

struct Reader<'a> {
    remaining: &'a [u8],
}

impl<'a> Reader<'a> {
    fn new(remaining: &'a [u8]) -> Self {
        Self { remaining }
    }
    fn take(&mut self, len: usize) -> Result<&'a [u8], JobRuntimeError> {
        if self.remaining.len() < len {
            return Err(JobRuntimeError::Checkpoint);
        }
        let (head, tail) = self.remaining.split_at(len);
        self.remaining = tail;
        Ok(head)
    }
    fn u8(&mut self) -> Result<u8, JobRuntimeError> {
        Ok(self.take(1)?[0])
    }
    fn bool(&mut self) -> Result<bool, JobRuntimeError> {
        match self.u8()? {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(JobRuntimeError::Checkpoint),
        }
    }
    fn u16(&mut self) -> Result<u16, JobRuntimeError> {
        Ok(u16::from_le_bytes(
            self.take(2)?
                .try_into()
                .map_err(|_| JobRuntimeError::Checkpoint)?,
        ))
    }
    fn u32(&mut self) -> Result<u32, JobRuntimeError> {
        Ok(u32::from_le_bytes(
            self.take(4)?
                .try_into()
                .map_err(|_| JobRuntimeError::Checkpoint)?,
        ))
    }
    fn u64(&mut self) -> Result<u64, JobRuntimeError> {
        Ok(u64::from_le_bytes(
            self.take(8)?
                .try_into()
                .map_err(|_| JobRuntimeError::Checkpoint)?,
        ))
    }
    fn sized_bytes(&mut self, width: u8, maximum: usize) -> Result<Vec<u8>, JobRuntimeError> {
        let len = match width {
            2 => self.u16()? as usize,
            4 => self.u32()? as usize,
            _ => return Err(JobRuntimeError::Checkpoint),
        };
        if len == 0 || len > maximum {
            return Err(JobRuntimeError::Checkpoint);
        }
        Ok(self.take(len)?.to_vec())
    }
    fn is_empty(&self) -> bool {
        self.remaining.is_empty()
    }
}

#[cfg(test)]
mod tests;
