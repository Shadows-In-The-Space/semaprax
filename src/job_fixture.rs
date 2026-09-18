//! A deterministic in-memory durable-job fixture for issue #192's job-queue
//! profile.
//!
//! **This is not a message broker, not a durable transport, and not
//! reachable from checked SEMAPRAX source.** `std/jobs` (see
//! `docs/DURABLE-JOBS-V1.md`) specifies the pure, effect-free decision
//! procedures that govern a job's lifecycle state, lease legality, retry and
//! backoff, idempotent enqueue, scheduling, cancellation, and delivery
//! uncertainty, and those procedures execute as checked SEMAPRAX code on
//! every backend. This module is a separate, Rust-only proof that the same
//! decision procedures compose into something a real job runner could
//! implement: real lease claims with generation and deadline tracking, real
//! heartbeats, real worker-crash recovery, a deterministic single-threaded
//! *scripted* concurrent-claim simulation, a second concurrent-claim race
//! driven by genuine OS threads racing under a `Barrier` (proving the same
//! fencing invariant under real nondeterministic scheduling rather than a
//! call order this module's own test chose), real retry with bounded
//! backoff, and a real dead-letter ceiling. It composes with
//! `crate::database_fixture` rather than reinventing a parallel ledger:
//! `enqueue` commits a job row and an idempotency-key uniqueness check
//! through the *same* `DatabaseFixture` transaction as any application-state
//! row a caller wants written atomically alongside it. In production use —
//! outside this module's own tests, which alone spawn real OS threads solely
//! to race against it — `JobStore` and `DatabaseFixture` grant no
//! filesystem, network, or process authority, open no socket, and spawn no
//! thread of their own.
//!
//! **Classified uncertainty.** The checked atomic-write provider route now
//! returns `Published`, `NotPublished`, or `Uncertain` as a checked value
//! (`docs/HOST-OPERATION-OUTCOME-V1.md`). A host runner may map only that
//! provider-observed third outcome to [`OutcomeKind::Uncertain`].
//! [`JobStore::record_connection_uncertain`] remains the recovery path for a
//! lost completion acknowledgement or an interrupted durable checkpoint; it
//! must not be used to turn ordinary failures into uncertainty.

use std::collections::BTreeMap;

use crate::database_fixture::{Column, DatabaseFixture, Value};

/// Rust-side mirrors of `std/jobs/src/jobs.spx`'s pure decision procedures,
/// duplicated deliberately (the same choice `database_fixture.rs` made for
/// `std.db`): this proves the decision procedures hold at the Rust layer
/// independent of the interpreter, not that this module calls it.
pub mod decisions {
    /// `std.jobs.state.is_terminal`.
    pub fn state_is_terminal(state: usize) -> bool {
        matches!(state, 4 | 6 | 7 | 9)
    }

    /// `std.jobs.lease.is_current`.
    pub fn lease_is_current(
        lease_generation: u64,
        job_generation: u64,
        now_tick: u64,
        deadline_tick: u64,
    ) -> bool {
        lease_generation == job_generation && now_tick < deadline_tick
    }

    /// `std.jobs.claim.is_legal`.
    pub fn claim_is_legal(state: usize, is_due: bool) -> bool {
        state == 0 || (state == 1 && is_due)
    }

    /// `std.jobs.retry.should_dead_letter`.
    pub fn retry_should_dead_letter(attempt: u8, max_attempts: u8) -> bool {
        attempt >= max_attempts
    }

    /// `std.jobs.retry.next_state_after_outcome`. `kind`: 0 success, 1
    /// retryable failure, 2 permanent failure, 3 uncertain.
    pub fn retry_next_state_after_outcome(kind: usize, attempt: u8, max_attempts: u8) -> usize {
        if kind > 3 {
            6
        } else if kind == 0 {
            4
        } else if kind == 2 {
            6
        } else if kind == 3 {
            8
        } else if retry_should_dead_letter(attempt, max_attempts) {
            9
        } else {
            5
        }
    }

    /// `std.jobs.retry.backoff_ticks`.
    pub fn retry_backoff_ticks(attempt: u8, base_ticks: u64, max_ticks: u64) -> u64 {
        let mut ticks = base_ticks.min(max_ticks);
        for _ in 0..attempt {
            if ticks >= max_ticks {
                break;
            }
            ticks = ticks.saturating_mul(2).min(max_ticks);
        }
        ticks
    }

    /// `std.jobs.cancel.is_legal`.
    pub fn cancel_is_legal(state: usize) -> bool {
        matches!(state, 0 | 1 | 2 | 5)
    }

    /// `std.jobs.uncertain.retry_is_permitted`.
    pub fn uncertain_retry_is_permitted(
        is_idempotent_handler: bool,
        attempt: u8,
        max_attempts: u8,
    ) -> bool {
        is_idempotent_handler && !retry_should_dead_letter(attempt, max_attempts)
    }

    /// `std.jobs.schedule.is_due`.
    pub fn schedule_is_due(now_tick: u64, next_run_tick: u64) -> bool {
        now_tick >= next_run_tick
    }

    /// `std.jobs.schedule.catch_up_next_run` (skip-missed policy, bounded).
    pub fn schedule_catch_up_next_run(
        now_tick: u64,
        next_run_tick: u64,
        interval_tick: u64,
        max_catch_up: u64,
    ) -> u64 {
        let missed = if now_tick <= next_run_tick {
            0
        } else {
            (now_tick - next_run_tick) / interval_tick
        };
        let bounded_missed = missed.min(max_catch_up);
        next_run_tick + interval_tick * (bounded_missed + 1)
    }
}

use decisions::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum JobState {
    Pending,
    Scheduled,
    Leased,
    Running,
    Succeeded,
    RetryableFailure,
    PermanentFailure,
    Cancelled,
    Uncertain,
    DeadLettered,
}

impl JobState {
    /// The numeric `std.jobs.state.*` code this variant mirrors. Public so
    /// `crate::job_evidence` can record and replay a run's true state
    /// without duplicating this mapping as a second source of truth.
    pub fn code(self) -> usize {
        match self {
            JobState::Pending => 0,
            JobState::Scheduled => 1,
            JobState::Leased => 2,
            JobState::Running => 3,
            JobState::Succeeded => 4,
            JobState::RetryableFailure => 5,
            JobState::PermanentFailure => 6,
            JobState::Cancelled => 7,
            JobState::Uncertain => 8,
            JobState::DeadLettered => 9,
        }
    }

    fn from_code(code: usize) -> Self {
        match code {
            0 => JobState::Pending,
            1 => JobState::Scheduled,
            2 => JobState::Leased,
            3 => JobState::Running,
            4 => JobState::Succeeded,
            5 => JobState::RetryableFailure,
            6 => JobState::PermanentFailure,
            7 => JobState::Cancelled,
            8 => JobState::Uncertain,
            _ => JobState::DeadLettered,
        }
    }

    pub fn is_terminal(self) -> bool {
        state_is_terminal(self.code())
    }
}

/// An outcome kind reported after an attempt, mirroring `std.jobs.outcome`:
/// `Success`, `Retryable`, `Permanent`, or `Uncertain`. The last variant is
/// reserved for an actual provider-observed outcome-unknown signal.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OutcomeKind {
    Success,
    Retryable,
    Permanent,
    Uncertain,
}

impl OutcomeKind {
    fn code(self) -> usize {
        match self {
            OutcomeKind::Success => 0,
            OutcomeKind::Retryable => 1,
            OutcomeKind::Permanent => 2,
            OutcomeKind::Uncertain => 3,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum JobFixtureError {
    UnknownJob,
    ClaimNotLegal,
    LeaseNotCurrent,
    CancelNotLegal,
    NotUncertain,
    RetryNotPermitted,
    RevisionRefused,
    ScheduleOverflow,
    ScheduleNotAdvanceable,
}

#[derive(Clone, Copy, Debug)]
struct Lease {
    worker_id: u32,
    lease_generation: u64,
    deadline_tick: u64,
}

#[derive(Clone, Debug)]
struct JobRecord {
    idempotency_key: Vec<u8>,
    payload_descriptor: Vec<u8>,
    bound_revision: u8,
    state: JobState,
    job_generation: u64,
    /// Strictly increases on every [`JobStore::claim`], across every
    /// completion and reclaim this job ever undergoes, and is never derived
    /// from (or reset by) the currently outstanding lease. `claim` folding
    /// this value from `self.lease`'s own stored generation instead would
    /// restart the count from `1` the moment `self.lease` is `None` again —
    /// which happens after *every* completion and *every* expiry-driven
    /// reclaim — so two different lease grants for the same job could be
    /// handed the identical `lease_generation`. A worker whose call arrives
    /// late (after its lease was reassigned) would then satisfy
    /// [`decisions::lease_is_current`] against the new holder's lease by
    /// coincidence, exactly the "lease expiry ... can produce concurrent
    /// execution" case issue #192 requires be refused. Keeping this counter
    /// on the record itself, incremented once per claim and never reset,
    /// guarantees every lease this job ever grants gets a value no other
    /// grant can ever match again.
    lease_epoch: u64,
    lease: Option<Lease>,
    attempt: u8,
    max_attempts: u8,
    is_idempotent_handler: bool,
    ever_ran: bool,
    next_run_tick: Option<u64>,
    interval_tick: Option<u64>,
    max_occurrences: Option<u64>,
    occurrences_run: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EnqueueOutcome {
    Created(u64),
    Duplicate(u64),
    Conflict,
}

/// A recurring schedule: fires every `interval_tick` starting at
/// `next_run_tick`, for at most `max_occurrences` runs, using the
/// "skip-missed" catch-up policy bounded by `max_catch_up`.
#[derive(Clone, Copy, Debug)]
pub struct Schedule {
    pub next_run_tick: u64,
    pub interval_tick: u64,
    pub max_occurrences: u64,
    pub max_catch_up: u64,
}

/// Bundles [`JobStore::complete_durable`]'s per-attempt inputs, the same
/// bundling [`Schedule`] already uses for `enqueue`'s optional schedule
/// parameters, so this call's parameter count stays small independent of
/// how many bounded inputs a completion needs.
#[derive(Clone, Copy, Debug)]
pub struct CompletionAttempt {
    pub lease_generation: u64,
    pub now_tick: u64,
    pub outcome: OutcomeKind,
    pub base_backoff_ticks: u64,
    pub max_backoff_ticks: u64,
}

/// The in-memory job store. `ledger` rows back every enqueue with a real
/// `DatabaseFixture` transaction; lease bookkeeping (ephemeral, not part of
/// the durable ledger row) lives in `jobs`.
pub struct JobStore {
    jobs: BTreeMap<u64, JobRecord>,
    next_id: u64,
    current_revision: u8,
}

const JOBS_TABLE: &str = "jobs";

impl JobStore {
    pub fn new(current_revision: u8) -> Self {
        Self {
            jobs: BTreeMap::new(),
            next_id: 1,
            current_revision,
        }
    }

    /// Advances the revision ledger a recovered runner validates queued jobs
    /// against. Existing jobs retain their enqueue-time `bound_revision`;
    /// lowering this value therefore makes a previously queued newer job fail
    /// closed at [`Self::revision_check`].
    pub fn set_current_revision(&mut self, current_revision: u8) {
        self.current_revision = current_revision;
    }

    /// Creates the ledger-backed `jobs` table on a fresh `DatabaseFixture`.
    /// Columns: `id` (Usize), `idempotency_key` (Bytes), `state` (Usize).
    pub fn install_ledger_schema(ledger: &mut DatabaseFixture) {
        ledger
            .create_table(
                JOBS_TABLE,
                vec![
                    Column {
                        name: "id".to_owned(),
                        tag: 3,
                    },
                    Column {
                        name: "idempotency_key".to_owned(),
                        tag: 4,
                    },
                    Column {
                        name: "state".to_owned(),
                        tag: 3,
                    },
                ],
            )
            .expect("fixture identifiers are safe literals");
    }

    /// Enqueues a job. `ledger` is a `DatabaseFixture` whose "jobs" table
    /// (see [`Self::install_ledger_schema`]) already exists: enqueue begins a
    /// transaction, checks the idempotency key against both the in-memory
    /// index and the ledger row set, inserts the new row, and commits — the
    /// same transaction an application-state write can be added to before
    /// this call returns, demonstrating "database transaction integration
    /// for enqueue plus application state change" without a parallel ledger.
    #[allow(clippy::too_many_arguments)]
    pub fn enqueue(
        &mut self,
        ledger: &mut DatabaseFixture,
        idempotency_key: Vec<u8>,
        payload_descriptor: Vec<u8>,
        schedule: Option<Schedule>,
        max_attempts: u8,
        is_idempotent_handler: bool,
    ) -> Result<EnqueueOutcome, JobFixtureError> {
        if let Some(existing) = self
            .jobs
            .iter()
            .find(|(_, job)| job.idempotency_key == idempotency_key)
        {
            let (&id, job) = existing;
            return if job.payload_descriptor == payload_descriptor {
                Ok(EnqueueOutcome::Duplicate(id))
            } else {
                Ok(EnqueueOutcome::Conflict)
            };
        }
        ledger.begin().expect("ledger connection is reusable");
        let id = self.next_id;
        ledger
            .insert(
                JOBS_TABLE,
                vec![
                    Value::Usize(id as usize),
                    Value::Bytes(idempotency_key.clone()),
                    Value::Usize(0),
                ],
            )
            .expect("jobs table schema matches the inserted row shape");
        ledger.commit().expect("no other transaction is open");
        self.next_id += 1;
        let (state, next_run_tick, interval_tick, max_occurrences) = match schedule {
            Some(schedule) => (
                JobState::Scheduled,
                Some(schedule.next_run_tick),
                Some(schedule.interval_tick),
                Some(schedule.max_occurrences),
            ),
            None => (JobState::Pending, None, None, None),
        };
        self.jobs.insert(
            id,
            JobRecord {
                idempotency_key,
                payload_descriptor,
                bound_revision: self.current_revision,
                state,
                job_generation: 0,
                lease_epoch: 0,
                lease: None,
                attempt: 0,
                max_attempts,
                is_idempotent_handler,
                ever_ran: false,
                next_run_tick,
                interval_tick,
                max_occurrences,
                occurrences_run: 0,
            },
        );
        Ok(EnqueueOutcome::Created(id))
    }

    fn job_mut(&mut self, id: u64) -> Result<&mut JobRecord, JobFixtureError> {
        self.jobs.get_mut(&id).ok_or(JobFixtureError::UnknownJob)
    }

    pub fn state_of(&self, id: u64) -> Option<JobState> {
        self.jobs.get(&id).map(|job| job.state)
    }

    pub fn attempt_of(&self, id: u64) -> Option<u8> {
        self.jobs.get(&id).map(|job| job.attempt)
    }

    /// The worker currently holding this job's lease, if any.
    pub fn leased_worker_id(&self, id: u64) -> Option<u32> {
        self.jobs
            .get(&id)
            .and_then(|job| job.lease)
            .map(|lease| lease.worker_id)
    }

    /// Claims a job for `worker_id` if `claim_is_legal` holds for its
    /// current state and (for a scheduled job) `now_tick`. Returns the
    /// granted `(job_generation, lease_generation, deadline_tick)` a worker
    /// must present to every later call.
    pub fn claim(
        &mut self,
        id: u64,
        worker_id: u32,
        now_tick: u64,
        lease_ticks: u64,
    ) -> Result<(u64, u64, u64), JobFixtureError> {
        let job = self.job_mut(id)?;
        let is_due = job
            .next_run_tick
            .is_none_or(|next_run| schedule_is_due(now_tick, next_run));
        if !claim_is_legal(job.state.code(), is_due) {
            return Err(JobFixtureError::ClaimNotLegal);
        }
        // Never derived from `job.lease`: see `JobRecord::lease_epoch`'s doc
        // comment for exactly why folding this from the outstanding lease
        // (which becomes `None`, and would restart this count from `1`,
        // after every completion and every expiry-driven reclaim) would let
        // two different lease grants collide on the same value.
        job.lease_epoch += 1;
        let lease_generation = job.lease_epoch;
        let deadline_tick = now_tick + lease_ticks;
        job.state = JobState::Leased;
        job.lease = Some(Lease {
            worker_id,
            lease_generation,
            deadline_tick,
        });
        Ok((job.job_generation, lease_generation, deadline_tick))
    }

    fn current_lease(
        job: &JobRecord,
        lease_generation: u64,
        now_tick: u64,
    ) -> Result<Lease, JobFixtureError> {
        let lease = job.lease.ok_or(JobFixtureError::LeaseNotCurrent)?;
        if !lease_is_current(
            lease_generation,
            lease.lease_generation,
            now_tick,
            lease.deadline_tick,
        ) {
            return Err(JobFixtureError::LeaseNotCurrent);
        }
        Ok(lease)
    }

    /// Extends the current lease's deadline by `extend_ticks`. Refused
    /// unless the caller's `lease_generation` matches the current one and
    /// the current deadline has not yet passed (`heartbeat.is_legal`).
    pub fn heartbeat(
        &mut self,
        id: u64,
        lease_generation: u64,
        now_tick: u64,
        extend_ticks: u64,
    ) -> Result<u64, JobFixtureError> {
        let job = self.job_mut(id)?;
        if !matches!(job.state, JobState::Leased | JobState::Running) {
            return Err(JobFixtureError::LeaseNotCurrent);
        }
        let mut lease = Self::current_lease(job, lease_generation, now_tick)?;
        lease.deadline_tick = now_tick + extend_ticks;
        job.lease = Some(lease);
        Ok(lease.deadline_tick)
    }

    /// Moves a leased job to `Running`. Refused unless the presented lease is
    /// current for a job still exactly in `Leased`.
    pub fn begin_execution(
        &mut self,
        id: u64,
        lease_generation: u64,
        now_tick: u64,
    ) -> Result<(), JobFixtureError> {
        let job = self.job_mut(id)?;
        if job.state != JobState::Leased {
            return Err(JobFixtureError::LeaseNotCurrent);
        }
        Self::current_lease(job, lease_generation, now_tick)?;
        job.state = JobState::Running;
        job.ever_ran = true;
        Ok(())
    }

    /// Records an attempt outcome. Refused unless the presented lease is
    /// current for a job exactly `Running` (`completion.is_legal`). On a
    /// retryable failure that is not yet dead-lettered, the job returns to
    /// `Pending` (or `Scheduled`, past `retry.backoff_ticks`) for reclaim
    /// rather than staying `RetryableFailure` forever; a permanent failure,
    /// success, dead-letter, or uncertain outcome is recorded as-is.
    pub fn complete(
        &mut self,
        id: u64,
        lease_generation: u64,
        now_tick: u64,
        outcome: OutcomeKind,
        base_backoff_ticks: u64,
        max_backoff_ticks: u64,
    ) -> Result<JobState, JobFixtureError> {
        let job = self.job_mut(id)?;
        if job.state != JobState::Running {
            return Err(JobFixtureError::LeaseNotCurrent);
        }
        Self::current_lease(job, lease_generation, now_tick)?;
        if outcome != OutcomeKind::Success {
            job.attempt = job.attempt.saturating_add(1);
        }
        let next = retry_next_state_after_outcome(outcome.code(), job.attempt, job.max_attempts);
        job.state = JobState::from_code(next);
        job.lease = None;
        if job.state == JobState::RetryableFailure {
            let backoff = retry_backoff_ticks(job.attempt, base_backoff_ticks, max_backoff_ticks);
            job.next_run_tick = Some(now_tick + backoff);
            job.state = JobState::Scheduled;
        }
        Ok(job.state)
    }

    /// Durably completes a job: unlike [`Self::complete`], which only ever
    /// mutates the in-memory record, this commits the outcome's resulting
    /// state into the same ledger row `enqueue` created *before* applying
    /// it in memory. `complete` alone cannot distinguish "the handler
    /// succeeded and that fact is durably recorded" from "the handler
    /// succeeded, then the worker crashed before its completion write was
    /// confirmed" — the exact gap issue #192 names: "a job that completed
    /// but whose completion record was not durably written before a
    /// crash." If the ledger transaction cannot be confirmed `Committed`
    /// (a stuck-open prior transaction, a shape mismatch, or the row
    /// having vanished), this method does not apply `outcome`'s natural
    /// resulting state at all: it forces the job to the same honest,
    /// non-terminal `Uncertain` resting state
    /// [`Self::record_connection_uncertain`] uses for a dropped network
    /// connection, because the two situations are the same shape — an
    /// externally observed signal that a completion's effect cannot be
    /// confirmed — and this fixture refuses to guess `Succeeded` (or any
    /// other resulting state) either way.
    pub fn complete_durable(
        &mut self,
        ledger: &mut DatabaseFixture,
        id: u64,
        attempt: CompletionAttempt,
    ) -> Result<JobState, JobFixtureError> {
        let CompletionAttempt {
            lease_generation,
            now_tick,
            outcome,
            base_backoff_ticks,
            max_backoff_ticks,
        } = attempt;
        let (attempt, max_attempts) = {
            let job = self.jobs.get(&id).ok_or(JobFixtureError::UnknownJob)?;
            if job.state != JobState::Running {
                return Err(JobFixtureError::LeaseNotCurrent);
            }
            Self::current_lease(job, lease_generation, now_tick)?;
            (job.attempt, job.max_attempts)
        };
        let attempt_after = if outcome == OutcomeKind::Success {
            attempt
        } else {
            attempt.saturating_add(1)
        };
        let projected = JobState::from_code(retry_next_state_after_outcome(
            outcome.code(),
            attempt_after,
            max_attempts,
        ));
        // `complete` folds a fresh `RetryableFailure` back to `Scheduled`
        // once backoff is computed; the ledger records that same final
        // resting state, not the transient code, so a reader of the ledger
        // alone sees exactly what `complete` would have produced.
        let ledger_state = if projected == JobState::RetryableFailure {
            JobState::Scheduled
        } else {
            projected
        };

        let commit_confirmed = (|| -> Result<(), ()> {
            ledger.begin().map_err(|_| ())?;
            let rows_updated = ledger
                .update_column(
                    JOBS_TABLE,
                    0,
                    &Value::Usize(id as usize),
                    2,
                    Value::Usize(ledger_state.code()),
                )
                .map_err(|_| ())?;
            if rows_updated != 1 {
                let _ = ledger.rollback();
                return Err(());
            }
            ledger.commit().map_err(|_| ())
        })()
        .is_ok();

        if commit_confirmed {
            self.complete(
                id,
                lease_generation,
                now_tick,
                outcome,
                base_backoff_ticks,
                max_backoff_ticks,
            )
        } else {
            self.record_connection_uncertain(id)?;
            Ok(JobState::Uncertain)
        }
    }

    /// The one transition driven by an external signal rather than a
    /// requested operation: the host observed that a lease-holding job's
    /// outcome cannot be determined (a dropped connection, a post-publication
    /// I/O failure whose acknowledgement never arrived) and forces the
    /// honest `Uncertain` resting state rather than guessing success or
    /// failure. Mirrors `DatabaseFixture::connection_lost` exactly; see the
    /// checked publication outcome or checkpoint-recovery signal, never an
    /// ordinary failure relabelled by a caller.
    pub fn record_connection_uncertain(&mut self, id: u64) -> Result<(), JobFixtureError> {
        let job = self.job_mut(id)?;
        if !matches!(job.state, JobState::Leased | JobState::Running) {
            return Err(JobFixtureError::LeaseNotCurrent);
        }
        job.ever_ran = job.ever_ran || job.state == JobState::Running;
        job.state = JobState::Uncertain;
        job.lease = None;
        Ok(())
    }

    /// Reconciles an `Uncertain` job. `decision`: 0 confirmed succeeded, 1
    /// confirmed failed, 2 retry (only proceeds when the handler is declared
    /// idempotent and the attempt ceiling is not reached; otherwise the job
    /// stays `Uncertain`, never silently retried or dead-lettered).
    pub fn reconcile_uncertain(
        &mut self,
        id: u64,
        decision: usize,
    ) -> Result<JobState, JobFixtureError> {
        let job = self.job_mut(id)?;
        if job.state != JobState::Uncertain {
            return Err(JobFixtureError::NotUncertain);
        }
        job.state = match decision {
            0 => JobState::Succeeded,
            1 => JobState::PermanentFailure,
            2 if uncertain_retry_is_permitted(
                job.is_idempotent_handler,
                job.attempt,
                job.max_attempts,
            ) =>
            {
                job.attempt = job.attempt.saturating_add(1);
                JobState::Pending
            }
            _ => JobState::Uncertain,
        };
        Ok(job.state)
    }

    /// Reclaims any job whose lease has expired without a completion signal:
    /// bumps `job_generation` (so the stale worker's lease can never again
    /// satisfy `lease.is_current`) and returns it to `Pending` for a new
    /// claim. This is plain crash/timeout recovery, distinct from
    /// [`Self::record_connection_uncertain`]: no signal was ever observed
    /// about the in-flight attempt, so this profile presumes the worker is
    /// simply gone and lets a fresh attempt run, exactly the "at-least-once"
    /// baseline the issue asks for.
    pub fn expire_stale_leases(&mut self, now_tick: u64) -> Vec<u64> {
        let mut reclaimed = Vec::new();
        for (&id, job) in self.jobs.iter_mut() {
            if let Some(lease) = job.lease {
                if now_tick >= lease.deadline_tick {
                    job.job_generation += 1;
                    job.lease = None;
                    job.state = JobState::Pending;
                    reclaimed.push(id);
                }
            }
        }
        reclaimed
    }

    /// Cancels a job if `cancel.is_legal` holds for its current state. A
    /// `Running` job cannot be cancelled from outside; only a cooperative
    /// check inside the handler could stop it, which is outside this fixture.
    pub fn cancel(&mut self, id: u64) -> Result<JobState, JobFixtureError> {
        let job = self.job_mut(id)?;
        if !cancel_is_legal(job.state.code()) {
            return Err(JobFixtureError::CancelNotLegal);
        }
        job.state = JobState::Cancelled;
        job.lease = None;
        Ok(job.state)
    }

    pub fn compensation_is_required(&self, id: u64) -> Option<bool> {
        self.jobs.get(&id).map(|job| {
            job.ever_ran && matches!(job.state, JobState::PermanentFailure | JobState::Cancelled)
        })
    }

    /// Advances a completed recurring job's schedule using the skip-missed
    /// catch-up policy, or dead-letters it (by staying `Cancelled`-adjacent —
    /// concretely, this fixture reports exhaustion via `None`) once its
    /// bounded occurrence count is reached.
    pub fn advance_recurring_schedule(
        &mut self,
        id: u64,
        now_tick: u64,
        max_catch_up: u64,
    ) -> Result<Option<u64>, JobFixtureError> {
        let job = self.job_mut(id)?;
        if job.state != JobState::Succeeded {
            return Err(JobFixtureError::ScheduleNotAdvanceable);
        }
        let (Some(next_run_tick), Some(interval_tick), Some(max_occurrences)) =
            (job.next_run_tick, job.interval_tick, job.max_occurrences)
        else {
            return Ok(None);
        };
        let occurrences_run = job
            .occurrences_run
            .checked_add(1)
            .ok_or(JobFixtureError::ScheduleOverflow)?;
        if occurrences_run >= max_occurrences {
            job.occurrences_run = occurrences_run;
            job.next_run_tick = None;
            return Ok(None);
        }
        let next = recurring_next_run(next_run_tick, interval_tick, now_tick, max_catch_up)?;
        job.occurrences_run = occurrences_run;
        // A scheduled recurrence is a fresh occurrence. Failures from the
        // prior one must not consume the next occurrence's attempt ceiling.
        job.attempt = 0;
        job.next_run_tick = Some(next);
        job.state = JobState::Scheduled;
        Ok(Some(next))
    }

    pub fn occurrences_run_of(&self, id: u64) -> Option<u64> {
        self.jobs.get(&id).map(|job| job.occurrences_run)
    }

    /// Checks the same bounded recurrence arithmetic `advance_recurring_schedule`
    /// will use, before an execution is dispatched.
    pub fn recurring_advance_is_safe(
        &self,
        id: u64,
        now_tick: u64,
        max_catch_up: u64,
    ) -> Result<(), JobFixtureError> {
        let job = self.jobs.get(&id).ok_or(JobFixtureError::UnknownJob)?;
        let (Some(next_run_tick), Some(interval_tick), Some(max_occurrences)) =
            (job.next_run_tick, job.interval_tick, job.max_occurrences)
        else {
            return Ok(());
        };
        let occurrences_run = job
            .occurrences_run
            .checked_add(1)
            .ok_or(JobFixtureError::ScheduleOverflow)?;
        if occurrences_run < max_occurrences {
            let _ = recurring_next_run(next_run_tick, interval_tick, now_tick, max_catch_up)?;
        }
        Ok(())
    }

    /// Refuses a job bound to an unknown handler/schema revision (below `1`
    /// or above `current_revision`), mirroring `std.db.migration`'s
    /// gapless, only-grows ledger.
    pub fn revision_check(&self, id: u64) -> Result<(), JobFixtureError> {
        let job = self.jobs.get(&id).ok_or(JobFixtureError::UnknownJob)?;
        let known = job.bound_revision >= 1 && job.bound_revision <= self.current_revision;
        if known {
            Ok(())
        } else {
            Err(JobFixtureError::RevisionRefused)
        }
    }
}

fn recurring_next_run(
    next_run_tick: u64,
    interval_tick: u64,
    now_tick: u64,
    max_catch_up: u64,
) -> Result<u64, JobFixtureError> {
    if interval_tick == 0 {
        return Err(JobFixtureError::ScheduleOverflow);
    }
    let missed = now_tick.saturating_sub(next_run_tick) / interval_tick;
    let steps = missed
        .min(max_catch_up)
        .checked_add(1)
        .ok_or(JobFixtureError::ScheduleOverflow)?;
    next_run_tick
        .checked_add(
            interval_tick
                .checked_mul(steps)
                .ok_or(JobFixtureError::ScheduleOverflow)?,
        )
        .ok_or(JobFixtureError::ScheduleOverflow)
}

#[cfg(test)]
mod tests;
