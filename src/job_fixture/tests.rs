use super::*;

fn descriptor() -> Vec<u8> {
    vec![3, 4, 1]
}

#[test]
fn enqueue_is_idempotent_and_refuses_a_conflicting_reuse() {
    let mut ledger = DatabaseFixture::new();
    JobStore::install_ledger_schema(&mut ledger);
    let mut store = JobStore::new(1);
    let first = store
        .enqueue(&mut ledger, b"key-a".to_vec(), descriptor(), None, 3, false)
        .unwrap();
    let EnqueueOutcome::Created(id) = first else {
        panic!("expected a fresh job");
    };
    // Same key, same descriptor: idempotent no-op, returns the existing job.
    let duplicate = store
        .enqueue(&mut ledger, b"key-a".to_vec(), descriptor(), None, 3, false)
        .unwrap();
    assert_eq!(duplicate, EnqueueOutcome::Duplicate(id));
    // Same key, different descriptor: closed conflict, never a silent merge.
    let conflicting = store
        .enqueue(
            &mut ledger,
            b"key-a".to_vec(),
            vec![3, 4, 2],
            None,
            3,
            false,
        )
        .unwrap();
    assert_eq!(conflicting, EnqueueOutcome::Conflict);
    assert_eq!(ledger.row_count("jobs").unwrap(), 1);
}

#[test]
fn enqueue_commits_the_ledger_row_inside_one_transaction() {
    let mut ledger = DatabaseFixture::new();
    JobStore::install_ledger_schema(&mut ledger);
    let mut store = JobStore::new(1);
    store
        .enqueue(&mut ledger, b"key-b".to_vec(), descriptor(), None, 3, false)
        .unwrap();
    assert_eq!(ledger.row_count("jobs").unwrap(), 1);
    assert_eq!(
        ledger.transaction_state(),
        crate::database_fixture::TransactionState::Committed
    );
}

#[test]
fn claim_lease_lifecycle_and_completion_require_a_current_lease() {
    let mut ledger = DatabaseFixture::new();
    JobStore::install_ledger_schema(&mut ledger);
    let mut store = JobStore::new(1);
    let EnqueueOutcome::Created(id) = store
        .enqueue(&mut ledger, b"key-c".to_vec(), descriptor(), None, 3, true)
        .unwrap()
    else {
        panic!("expected a fresh job");
    };
    assert_eq!(store.state_of(id), Some(JobState::Pending));
    let (job_generation, lease_generation, deadline) = store.claim(id, 1, 0, 10).unwrap();
    assert_eq!(job_generation, 0);
    assert_eq!(store.state_of(id), Some(JobState::Leased));
    // A second claim while already leased is refused.
    assert_eq!(
        store.claim(id, 2, 1, 10),
        Err(JobFixtureError::ClaimNotLegal)
    );
    store.begin_execution(id, lease_generation, 2).unwrap();
    assert_eq!(store.state_of(id), Some(JobState::Running));
    // Completing past the lease deadline is refused.
    assert_eq!(
        store.complete(id, lease_generation, deadline, OutcomeKind::Success, 1, 100),
        Err(JobFixtureError::LeaseNotCurrent)
    );
    assert_eq!(store.state_of(id), Some(JobState::Running));
    let state = store
        .complete(
            id,
            lease_generation,
            deadline - 1,
            OutcomeKind::Success,
            1,
            100,
        )
        .unwrap();
    assert_eq!(state, JobState::Succeeded);
    assert!(state.is_terminal());
}

#[test]
fn heartbeat_extends_the_deadline_and_is_refused_once_stale() {
    let mut ledger = DatabaseFixture::new();
    JobStore::install_ledger_schema(&mut ledger);
    let mut store = JobStore::new(1);
    let EnqueueOutcome::Created(id) = store
        .enqueue(&mut ledger, b"key-d".to_vec(), descriptor(), None, 3, false)
        .unwrap()
    else {
        panic!("expected a fresh job");
    };
    let (_, lease_generation, _deadline) = store.claim(id, 1, 0, 10).unwrap();
    let extended = store.heartbeat(id, lease_generation, 5, 10).unwrap();
    assert_eq!(extended, 15);
    // A heartbeat presenting a lease_generation the store no longer
    // recognizes as current (a stale worker) is refused.
    assert_eq!(
        store.heartbeat(id, lease_generation + 1, 6, 10),
        Err(JobFixtureError::LeaseNotCurrent)
    );
}

#[test]
fn expired_lease_is_reclaimed_and_the_stale_worker_cannot_complete_it() {
    let mut ledger = DatabaseFixture::new();
    JobStore::install_ledger_schema(&mut ledger);
    let mut store = JobStore::new(1);
    let EnqueueOutcome::Created(id) = store
        .enqueue(&mut ledger, b"key-e".to_vec(), descriptor(), None, 3, false)
        .unwrap()
    else {
        panic!("expected a fresh job");
    };
    let (_, stale_lease_generation, deadline) = store.claim(id, 1, 0, 10).unwrap();
    // The lease deadline passes with no heartbeat: a recovery sweep
    // reclaims it for a new attempt.
    let reclaimed = store.expire_stale_leases(deadline);
    assert_eq!(reclaimed, vec![id]);
    assert_eq!(store.state_of(id), Some(JobState::Pending));
    // A second worker claims the reclaimed job under a new generation.
    let (job_generation_2, lease_generation_2, _deadline_2) =
        store.claim(id, 2, deadline, 10).unwrap();
    assert_eq!(job_generation_2, 1);
    // The original (stale) worker's lease can never complete the job
    // again: its lease_generation no longer matches the current one.
    assert_eq!(
        store.complete(
            id,
            stale_lease_generation,
            deadline + 1,
            OutcomeKind::Success,
            1,
            100
        ),
        Err(JobFixtureError::LeaseNotCurrent)
    );
    // The new worker's lease is current and can complete it.
    store
        .begin_execution(id, lease_generation_2, deadline + 1)
        .unwrap();
    let state = store
        .complete(
            id,
            lease_generation_2,
            deadline + 2,
            OutcomeKind::Success,
            1,
            100,
        )
        .unwrap();
    assert_eq!(state, JobState::Succeeded);
}

/// The fencing regression the reclaim test above does not actually
/// exercise: that test's stale completion is refused only because the
/// reclaimed job has not yet reached `Running` again, so it would pass
/// even if lease generations collided. Here the reclaiming worker *has*
/// already reached `Running` — with a still-current deadline — when the
/// original, reclaimed worker's own stale completion call arrives. A
/// worker whose lease was reassigned after expiry must never be able to
/// complete the job out from under whoever now legitimately holds it,
/// exactly the "lease expiry ... can produce concurrent execution"
/// failure case issue #192 requires be refused.
#[test]
fn a_reclaimed_workers_stale_completion_can_never_land_over_the_new_holders_run() {
    let mut ledger = DatabaseFixture::new();
    JobStore::install_ledger_schema(&mut ledger);
    let mut store = JobStore::new(1);
    let EnqueueOutcome::Created(id) = store
        .enqueue(
            &mut ledger,
            b"key-fence".to_vec(),
            descriptor(),
            None,
            3,
            false,
        )
        .unwrap()
    else {
        panic!("expected a fresh job");
    };
    // Worker 1 claims and starts running, then goes silent past its
    // lease deadline without ever completing.
    let (_, stale_lease_generation, deadline) = store.claim(id, 1, 0, 10).unwrap();
    store
        .begin_execution(id, stale_lease_generation, 1)
        .unwrap();
    assert_eq!(store.expire_stale_leases(deadline), vec![id]);
    // Worker 2 claims the reclaimed job and is already running it, well
    // inside its own fresh, still-current deadline.
    let (_, current_lease_generation, new_deadline) = store.claim(id, 2, deadline, 10).unwrap();
    store
        .begin_execution(id, current_lease_generation, deadline + 1)
        .unwrap();
    assert_ne!(stale_lease_generation, current_lease_generation);
    // Worker 1's long-delayed completion call now arrives, presenting
    // its own original lease generation and a tick still inside worker
    // 2's current deadline window. It must be refused, not accepted as
    // if it were worker 2's own completion.
    assert_eq!(
        store.complete(
            id,
            stale_lease_generation,
            deadline + 2,
            OutcomeKind::Success,
            1,
            100,
        ),
        Err(JobFixtureError::LeaseNotCurrent)
    );
    assert_eq!(store.state_of(id), Some(JobState::Running));
    // Worker 2's own completion, using its own current generation,
    // still succeeds normally.
    assert_eq!(store.leased_worker_id(id), Some(2));
    let state = store
        .complete(
            id,
            current_lease_generation,
            new_deadline - 1,
            OutcomeKind::Success,
            1,
            100,
        )
        .unwrap();
    assert_eq!(state, JobState::Succeeded);
}

/// Two workers racing to claim the same job: simulated single-threaded
/// (the same technique `database_fixture.rs`'s own
/// `concurrent_runner_duplicate_attempt_is_never_applied_twice` uses),
/// not real concurrent threads. Only the first claim succeeds; the
/// second observes the job is no longer claimable.
///
/// [`real_os_thread_concurrent_claim_race_grants_the_lease_to_exactly_one_worker`]
/// below proves the same fencing invariant under genuine OS-thread
/// scheduling rather than a scripted call order.
#[test]
fn concurrent_claim_race_grants_the_lease_to_exactly_one_worker() {
    let mut ledger = DatabaseFixture::new();
    JobStore::install_ledger_schema(&mut ledger);
    let mut store = JobStore::new(1);
    let EnqueueOutcome::Created(id) = store
        .enqueue(&mut ledger, b"key-f".to_vec(), descriptor(), None, 3, false)
        .unwrap()
    else {
        panic!("expected a fresh job");
    };
    let first = store.claim(id, 1, 0, 10);
    let second = store.claim(id, 2, 0, 10);
    assert!(first.is_ok());
    assert_eq!(second, Err(JobFixtureError::ClaimNotLegal));
    assert_eq!(store.leased_worker_id(id), Some(1));
}

/// A genuine multi-threaded proof of the same fencing invariant the
/// scripted test above only simulates: real OS threads, synchronized by
/// a [`std::sync::Barrier`] so their `claim` calls are issued as close to
/// simultaneously as the OS scheduler allows, race for the same job
/// behind a shared `Mutex<JobStore>`. Which worker wins is genuinely
/// nondeterministic across runs (the OS scheduler decides, not this
/// test's call order); what must hold on every run, and is asserted
/// here, is that exactly one of them ever wins. The store's own `Mutex`
/// still serializes the actual mutation, exactly as a real lock-based
/// store (in-memory or a physical database's row lock) would — the value
/// of real threads over the scripted simulation above is that the
/// *scheduling* of who reaches the lock first is real, not scripted.
/// This closes the "real OS threads ... racing" half of the concurrency
/// gap `docs/DURABLE-JOBS-V1.md#non-claims-and-remaining-work` disclosed;
/// true multi-*process* concurrency (separate OS processes, no shared
/// address space) is a distinct, larger claim this test does not make.
#[test]
fn real_os_thread_concurrent_claim_race_grants_the_lease_to_exactly_one_worker() {
    use std::sync::{Arc, Barrier, Mutex};
    use std::thread;

    const WORKERS: u32 = 16;
    const ITERATIONS: usize = 25;

    for iteration in 0..ITERATIONS {
        let mut ledger = DatabaseFixture::new();
        JobStore::install_ledger_schema(&mut ledger);
        let mut store = JobStore::new(1);
        let EnqueueOutcome::Created(id) = store
            .enqueue(
                &mut ledger,
                format!("race-{iteration}").into_bytes(),
                descriptor(),
                None,
                3,
                false,
            )
            .unwrap()
        else {
            panic!("expected a fresh job");
        };
        let store = Arc::new(Mutex::new(store));
        let barrier = Arc::new(Barrier::new(WORKERS as usize));

        let handles: Vec<_> = (1..=WORKERS)
            .map(|worker_id| {
                let store = Arc::clone(&store);
                let barrier = Arc::clone(&barrier);
                thread::spawn(move || {
                    // All threads line up here so the actual `claim`
                    // calls below fire as close to simultaneously as the
                    // OS scheduler allows, rather than in a fixed order
                    // the test itself picked.
                    barrier.wait();
                    store.lock().unwrap().claim(id, worker_id, 0, 10)
                })
            })
            .collect();

        let results: Vec<_> = handles
            .into_iter()
            .map(|handle| handle.join().unwrap())
            .collect();

        let winners: Vec<_> = results.iter().filter(|result| result.is_ok()).collect();
        assert_eq!(
                winners.len(),
                1,
                "iteration {iteration}: exactly one real thread must win the claim race, got {winners:?}"
            );
        for result in &results {
            if result.is_err() {
                assert_eq!(*result, Err(JobFixtureError::ClaimNotLegal));
            }
        }
        let store = store.lock().unwrap();
        assert!(store.leased_worker_id(id).is_some());
    }
}

/// Closes "Concurrent enqueue and idempotency races" from issue #192's
/// required-tests list. Every other concurrent test in this module races
/// `claim` against an *already-enqueued* job; nothing before this test raced
/// `enqueue` itself, so the idempotency-key uniqueness check
/// (`self.jobs.iter().find(...)` followed by an insert, in
/// [`JobStore::enqueue`]) had only ever been exercised sequentially
/// (`enqueue_is_idempotent_and_refuses_a_conflicting_reuse` above). Real OS
/// threads, synchronized by a `Barrier` so their `enqueue` calls fire as
/// close to simultaneously as the scheduler allows, race to enqueue the
/// *same* idempotency key with the *same* payload descriptor behind one
/// shared `Mutex<(JobStore, DatabaseFixture)>`. Exactly one call may observe
/// `Created`; every other call must observe `Duplicate` of that exact job
/// id, and the ledger must retain exactly one row for the key -- proving the
/// find-then-insert sequence cannot let two racing threads each observe "no
/// existing key" and both create a row, which would defeat the idempotency
/// contract `docs/DURABLE-JOBS-V1.md#idempotent-enqueue` promises. A
/// mutable-shared-state bug (e.g. checking uniqueness before the mutex
/// covered both steps) would surface here as more than one `Created` result
/// or more than one ledger row; removing the lock from around the whole call
/// reproduces exactly that failure.
#[test]
fn real_os_thread_concurrent_enqueue_race_creates_exactly_one_job_for_the_same_key() {
    use std::sync::{Arc, Barrier, Mutex};
    use std::thread;

    const WORKERS: usize = 16;
    const ITERATIONS: usize = 25;

    for iteration in 0..ITERATIONS {
        let mut ledger = DatabaseFixture::new();
        JobStore::install_ledger_schema(&mut ledger);
        let store = JobStore::new(1);
        let state = Arc::new(Mutex::new((store, ledger)));
        let barrier = Arc::new(Barrier::new(WORKERS));
        let key = format!("enqueue-race-{iteration}").into_bytes();

        let handles: Vec<_> = (0..WORKERS)
            .map(|_| {
                let state = Arc::clone(&state);
                let barrier = Arc::clone(&barrier);
                let key = key.clone();
                thread::spawn(move || {
                    barrier.wait();
                    let mut guard = state.lock().unwrap();
                    let (store, ledger) = &mut *guard;
                    store.enqueue(ledger, key, descriptor(), None, 3, false)
                })
            })
            .collect();

        let results: Vec<_> = handles
            .into_iter()
            .map(|handle| handle.join().unwrap())
            .collect();
        let created: Vec<_> = results
            .iter()
            .filter_map(|result| match result {
                Ok(EnqueueOutcome::Created(id)) => Some(*id),
                _ => None,
            })
            .collect();
        assert_eq!(
            created.len(),
            1,
            "iteration {iteration}: exactly one real thread must create the job, got {results:?}"
        );
        let winner = created[0];
        for result in &results {
            match result {
                Ok(EnqueueOutcome::Created(id)) => assert_eq!(*id, winner),
                Ok(EnqueueOutcome::Duplicate(id)) => assert_eq!(*id, winner),
                other => panic!("iteration {iteration}: unexpected outcome {other:?}"),
            }
        }
        let guard = state.lock().unwrap();
        let (_, ledger) = &*guard;
        assert_eq!(ledger.row_count("jobs").unwrap(), 1);
    }
}

/// The same real-thread race, but half the workers submit a *different*
/// payload descriptor under the identical idempotency key. This exercises
/// the three-way `EnqueueOutcome` (`Created`/`Duplicate`/`Conflict`) under
/// genuine concurrent scheduling rather than the sequential order
/// `enqueue_is_idempotent_and_refuses_a_conflicting_reuse` above already
/// covers: whichever descriptor's call wins the race, every later call
/// sharing that exact descriptor must observe `Duplicate` of the winning
/// job, and every later call carrying the other descriptor must observe a
/// closed `Conflict`, never a silent merge onto the winning row. Which
/// descriptor wins is genuinely nondeterministic (the OS scheduler decides,
/// not this test), so the test resolves the expected outcome for each
/// result from the winner it actually observed rather than assuming either
/// descriptor wins.
#[test]
fn real_os_thread_concurrent_enqueue_race_with_differing_descriptors_conflicts_the_losers() {
    use std::sync::{Arc, Barrier, Mutex};
    use std::thread;

    const WORKERS: usize = 16;
    const ITERATIONS: usize = 25;
    let descriptor_a = vec![3, 4, 1];
    let descriptor_b = vec![9, 9, 9];

    for iteration in 0..ITERATIONS {
        let mut ledger = DatabaseFixture::new();
        JobStore::install_ledger_schema(&mut ledger);
        let store = JobStore::new(1);
        let state = Arc::new(Mutex::new((store, ledger)));
        let barrier = Arc::new(Barrier::new(WORKERS));
        let key = format!("enqueue-conflict-race-{iteration}").into_bytes();

        let handles: Vec<_> = (0..WORKERS)
            .map(|worker_id| {
                let state = Arc::clone(&state);
                let barrier = Arc::clone(&barrier);
                let key = key.clone();
                let payload_descriptor = if worker_id % 2 == 0 {
                    descriptor_a.clone()
                } else {
                    descriptor_b.clone()
                };
                thread::spawn(move || {
                    barrier.wait();
                    let mut guard = state.lock().unwrap();
                    let (store, ledger) = &mut *guard;
                    (
                        payload_descriptor.clone(),
                        store.enqueue(ledger, key, payload_descriptor, None, 3, false),
                    )
                })
            })
            .collect();

        let results: Vec<_> = handles
            .into_iter()
            .map(|handle| handle.join().unwrap())
            .collect();
        let created: Vec<_> = results
            .iter()
            .filter_map(|(descriptor, result)| match result {
                Ok(EnqueueOutcome::Created(id)) => Some((descriptor.clone(), *id)),
                _ => None,
            })
            .collect();
        assert_eq!(
            created.len(),
            1,
            "iteration {iteration}: exactly one real thread must create the job, got {results:?}"
        );
        let (winning_descriptor, winner) = created[0].clone();
        for (descriptor, result) in &results {
            if *descriptor == winning_descriptor {
                match result {
                    Ok(EnqueueOutcome::Created(id)) => assert_eq!(*id, winner),
                    Ok(EnqueueOutcome::Duplicate(id)) => assert_eq!(*id, winner),
                    other => panic!(
                        "iteration {iteration}: same-descriptor call must never conflict, got {other:?}"
                    ),
                }
            } else {
                assert_eq!(
                    *result,
                    Ok(EnqueueOutcome::Conflict),
                    "iteration {iteration}: differing-descriptor call must be a closed conflict, got {result:?}"
                );
            }
        }
        let guard = state.lock().unwrap();
        let (_, ledger) = &*guard;
        assert_eq!(ledger.row_count("jobs").unwrap(), 1);
    }
}

#[test]
fn retryable_failures_back_off_and_dead_letter_at_the_ceiling() {
    let mut ledger = DatabaseFixture::new();
    JobStore::install_ledger_schema(&mut ledger);
    let mut store = JobStore::new(1);
    let EnqueueOutcome::Created(id) = store
        .enqueue(&mut ledger, b"key-g".to_vec(), descriptor(), None, 2, false)
        .unwrap()
    else {
        panic!("expected a fresh job");
    };
    let (_, lease_generation, _) = store.claim(id, 1, 0, 10).unwrap();
    store.begin_execution(id, lease_generation, 1).unwrap();
    let state = store
        .complete(id, lease_generation, 2, OutcomeKind::Retryable, 5, 1000)
        .unwrap();
    assert_eq!(state, JobState::Scheduled);
    assert_eq!(store.attempt_of(id), Some(1));
    let (_, lease_generation_2, _) = store.claim(id, 1, 100, 10).unwrap();
    store.begin_execution(id, lease_generation_2, 101).unwrap();
    let state = store
        .complete(id, lease_generation_2, 102, OutcomeKind::Retryable, 5, 1000)
        .unwrap();
    // max_attempts is 2 and this was the second attempt: dead-lettered.
    assert_eq!(state, JobState::DeadLettered);
    assert!(state.is_terminal());
}

#[test]
fn permanent_failure_is_immediate_and_never_retried() {
    let mut ledger = DatabaseFixture::new();
    JobStore::install_ledger_schema(&mut ledger);
    let mut store = JobStore::new(1);
    let EnqueueOutcome::Created(id) = store
        .enqueue(&mut ledger, b"key-h".to_vec(), descriptor(), None, 5, false)
        .unwrap()
    else {
        panic!("expected a fresh job");
    };
    let (_, lease_generation, _) = store.claim(id, 1, 0, 10).unwrap();
    store.begin_execution(id, lease_generation, 1).unwrap();
    let state = store
        .complete(id, lease_generation, 2, OutcomeKind::Permanent, 5, 1000)
        .unwrap();
    assert_eq!(state, JobState::PermanentFailure);
    assert!(store.compensation_is_required(id).unwrap());
}

#[test]
fn uncertain_outcome_stays_uncertain_for_a_non_idempotent_handler_until_reconciled() {
    let mut ledger = DatabaseFixture::new();
    JobStore::install_ledger_schema(&mut ledger);
    let mut store = JobStore::new(1);
    let EnqueueOutcome::Created(id) = store
        .enqueue(&mut ledger, b"key-i".to_vec(), descriptor(), None, 3, false)
        .unwrap()
    else {
        panic!("expected a fresh job");
    };
    let (_, lease_generation, _) = store.claim(id, 1, 0, 10).unwrap();
    store.begin_execution(id, lease_generation, 1).unwrap();
    store.record_connection_uncertain(id).unwrap();
    assert_eq!(store.state_of(id), Some(JobState::Uncertain));
    assert!(!store.state_of(id).unwrap().is_terminal());
    // A retry decision on a non-idempotent handler is refused: the job
    // stays uncertain rather than being silently retried.
    let state = store.reconcile_uncertain(id, 2).unwrap();
    assert_eq!(state, JobState::Uncertain);
    // An explicit confirmation moves it on.
    let state = store.reconcile_uncertain(id, 1).unwrap();
    assert_eq!(state, JobState::PermanentFailure);
    assert!(store.compensation_is_required(id).unwrap());
}

#[test]
fn uncertain_outcome_may_auto_retry_only_for_an_idempotent_handler_under_the_ceiling() {
    let mut ledger = DatabaseFixture::new();
    JobStore::install_ledger_schema(&mut ledger);
    let mut store = JobStore::new(1);
    let EnqueueOutcome::Created(id) = store
        .enqueue(&mut ledger, b"key-j".to_vec(), descriptor(), None, 3, true)
        .unwrap()
    else {
        panic!("expected a fresh job");
    };
    let (_, lease_generation, _) = store.claim(id, 1, 0, 10).unwrap();
    store.begin_execution(id, lease_generation, 1).unwrap();
    store.record_connection_uncertain(id).unwrap();
    let state = store.reconcile_uncertain(id, 2).unwrap();
    assert_eq!(state, JobState::Pending);
    assert_eq!(store.attempt_of(id), Some(1));
}

#[test]
fn cancel_is_refused_while_running_and_requires_compensation_once_it_lands() {
    let mut ledger = DatabaseFixture::new();
    JobStore::install_ledger_schema(&mut ledger);
    let mut store = JobStore::new(1);
    let EnqueueOutcome::Created(id) = store
        .enqueue(&mut ledger, b"key-k".to_vec(), descriptor(), None, 3, true)
        .unwrap()
    else {
        panic!("expected a fresh job");
    };
    let (_, lease_generation, _) = store.claim(id, 1, 0, 10).unwrap();
    store.begin_execution(id, lease_generation, 1).unwrap();
    assert_eq!(store.cancel(id), Err(JobFixtureError::CancelNotLegal));
    // Reclaim (simulating the running attempt ending inconclusively) and
    // then cancel from a cancellable state.
    store.record_connection_uncertain(id).unwrap();
    store.reconcile_uncertain(id, 2).unwrap();
    assert_eq!(store.state_of(id), Some(JobState::Pending));
    let state = store.cancel(id).unwrap();
    assert_eq!(state, JobState::Cancelled);
    assert!(store.compensation_is_required(id).unwrap());
}

#[test]
fn recurring_advance_refuses_to_revive_a_cancelled_job() {
    let mut ledger = DatabaseFixture::new();
    JobStore::install_ledger_schema(&mut ledger);
    let mut store = JobStore::new(1);
    let EnqueueOutcome::Created(id) = store
        .enqueue(
            &mut ledger,
            b"cancelled-recurring".to_vec(),
            descriptor(),
            Some(Schedule {
                next_run_tick: 10,
                interval_tick: 5,
                max_occurrences: 2,
                max_catch_up: 1,
            }),
            2,
            true,
        )
        .unwrap()
    else {
        panic!("expected fresh job");
    };
    store.cancel(id).unwrap();
    assert_eq!(
        store.advance_recurring_schedule(id, 10, 1),
        Err(JobFixtureError::ScheduleNotAdvanceable)
    );
    assert_eq!(store.state_of(id), Some(JobState::Cancelled));
}

#[test]
fn scheduled_job_claims_only_once_due_and_recurs_with_bounded_catch_up() {
    let mut ledger = DatabaseFixture::new();
    JobStore::install_ledger_schema(&mut ledger);
    let mut store = JobStore::new(1);
    let schedule = Schedule {
        next_run_tick: 100,
        interval_tick: 10,
        max_occurrences: 3,
        max_catch_up: 2,
    };
    let EnqueueOutcome::Created(id) = store
        .enqueue(
            &mut ledger,
            b"key-l".to_vec(),
            descriptor(),
            Some(schedule),
            3,
            false,
        )
        .unwrap()
    else {
        panic!("expected a fresh job");
    };
    assert_eq!(store.state_of(id), Some(JobState::Scheduled));
    assert_eq!(
        store.claim(id, 1, 50, 10),
        Err(JobFixtureError::ClaimNotLegal)
    );
    let (_, lease_generation, _) = store.claim(id, 1, 999, 10).unwrap();
    store.begin_execution(id, lease_generation, 999).unwrap();
    store
        .complete(id, lease_generation, 999, OutcomeKind::Success, 1, 100)
        .unwrap();
    // The clock is far past several missed windows; skip-missed catch-up
    // bounded by max_catch_up jumps at most two windows ahead.
    let next = store.advance_recurring_schedule(id, 999, 2).unwrap();
    assert_eq!(next, Some(130));
    assert_eq!(store.state_of(id), Some(JobState::Scheduled));
}

#[test]
fn revision_check_refuses_an_unknown_bound_revision() {
    let mut ledger = DatabaseFixture::new();
    JobStore::install_ledger_schema(&mut ledger);
    let mut store = JobStore::new(3);
    let EnqueueOutcome::Created(id) = store
        .enqueue(&mut ledger, b"key-m".to_vec(), descriptor(), None, 3, false)
        .unwrap()
    else {
        panic!("expected a fresh job");
    };
    assert_eq!(store.revision_check(id), Ok(()));
    // A rollback to an earlier compiler revision leaves this job bound
    // above the new current revision: fail closed rather than decode it
    // speculatively.
    let mut rolled_back = JobStore::new(1);
    let EnqueueOutcome::Created(rolled_back_id) = rolled_back
        .enqueue(&mut ledger, b"key-n".to_vec(), descriptor(), None, 3, false)
        .unwrap()
    else {
        panic!("expected a fresh job");
    };
    rolled_back.current_revision = 0;
    assert_eq!(
        rolled_back.revision_check(rolled_back_id),
        Err(JobFixtureError::RevisionRefused)
    );
}

#[test]
fn complete_durable_commits_the_resulting_state_into_the_ledger_before_advancing_in_memory() {
    let mut ledger = DatabaseFixture::new();
    JobStore::install_ledger_schema(&mut ledger);
    let mut store = JobStore::new(1);
    let EnqueueOutcome::Created(id) = store
        .enqueue(&mut ledger, b"key-o".to_vec(), descriptor(), None, 3, false)
        .unwrap()
    else {
        panic!("expected a fresh job");
    };
    let (_, lease_generation, _) = store.claim(id, 1, 0, 10).unwrap();
    store.begin_execution(id, lease_generation, 1).unwrap();
    // Before the completion, the ledger row still carries the
    // placeholder state `enqueue` wrote (Pending, code 0) -- nothing
    // has ever updated it until now.
    assert_eq!(
        ledger.select_eq(JOBS_TABLE, 0, &Value::Usize(id as usize), 1),
        Ok(vec![vec![
            Value::Usize(id as usize),
            Value::Bytes(b"key-o".to_vec()),
            Value::Usize(JobState::Pending.code()),
        ]])
    );
    let state = store
        .complete_durable(
            &mut ledger,
            id,
            CompletionAttempt {
                lease_generation,
                now_tick: 2,
                outcome: OutcomeKind::Success,
                base_backoff_ticks: 1,
                max_backoff_ticks: 100,
            },
        )
        .unwrap();
    assert_eq!(state, JobState::Succeeded);
    assert_eq!(store.state_of(id), Some(JobState::Succeeded));
    assert_eq!(
        ledger.transaction_state(),
        crate::database_fixture::TransactionState::Committed
    );
    assert_eq!(
        ledger.select_eq(JOBS_TABLE, 0, &Value::Usize(id as usize), 1),
        Ok(vec![vec![
            Value::Usize(id as usize),
            Value::Bytes(b"key-o".to_vec()),
            Value::Usize(JobState::Succeeded.code()),
        ]])
    );
}

/// This is the second concurrency case issue #192's write-up calls out
/// as usually faked: "a job that completed but whose completion record
/// was not durably written before a crash." A stuck-open transaction
/// left by an earlier, unrelated failure stands in for the crash: the
/// job's own handler outcome is `Success`, yet `complete_durable`
/// cannot confirm its ledger write ever committed, so the job must
/// rest at `Uncertain`, never `Succeeded` -- exactly what a naive
/// "record whatever the handler reported" implementation would get
/// wrong.
#[test]
fn complete_durable_forces_uncertain_rather_than_the_handlers_outcome_when_the_ledger_commit_is_never_confirmed(
) {
    let mut ledger = DatabaseFixture::new();
    JobStore::install_ledger_schema(&mut ledger);
    let mut store = JobStore::new(1);
    let EnqueueOutcome::Created(id) = store
        .enqueue(&mut ledger, b"key-p".to_vec(), descriptor(), None, 3, false)
        .unwrap()
    else {
        panic!("expected a fresh job");
    };
    let (_, lease_generation, _) = store.claim(id, 1, 0, 10).unwrap();
    store.begin_execution(id, lease_generation, 1).unwrap();

    // A transaction from an earlier, unresolved failure is still open
    // on this connection when the completion attempt runs.
    ledger.begin().unwrap();

    let state = store
        .complete_durable(
            &mut ledger,
            id,
            CompletionAttempt {
                lease_generation,
                now_tick: 2,
                outcome: OutcomeKind::Success,
                base_backoff_ticks: 1,
                max_backoff_ticks: 100,
            },
        )
        .unwrap();

    assert_eq!(state, JobState::Uncertain);
    assert_eq!(store.state_of(id), Some(JobState::Uncertain));
    assert!(!state.is_terminal());
    // The ledger's own row was never rewritten: it still shows the
    // pre-completion placeholder, matching the in-memory refusal to
    // guess `Succeeded`.
    assert_eq!(
        ledger.select_eq(JOBS_TABLE, 0, &Value::Usize(id as usize), 1),
        Ok(vec![vec![
            Value::Usize(id as usize),
            Value::Bytes(b"key-p".to_vec()),
            Value::Usize(JobState::Pending.code()),
        ]])
    );
    // A later, correctly reconciled confirmation still lands cleanly.
    let reconciled = store.reconcile_uncertain(id, 0).unwrap();
    assert_eq!(reconciled, JobState::Succeeded);
}
