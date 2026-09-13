use super::*;

#[derive(Default)]
struct Store {
    document: String,
    lose_ack: std::rc::Rc<std::cell::Cell<bool>>,
}
impl CheckpointStore for Store {
    fn commit(&mut self, _: u64, document: &str) -> Result<(), CheckpointStoreError> {
        self.document = document.to_owned();
        if self.lose_ack.replace(false) {
            Err(CheckpointStoreError)
        } else {
            Ok(())
        }
    }
}
fn hash(label: &str) -> String {
    digest(b"semaprax.source-migration.test\0", label.as_bytes())
}
fn fixture(max_total_steps: usize) -> SourceInvocationBinding {
    let seed = SourceInvocationSeed {
        lifecycle_digest: hash("lifecycle-b"),
        source_revision: hash("source-b"),
        deployment_binding: hash("deployment"),
        task: b"task".to_vec(),
        task_budget: 2,
        proposal_schema_digest: hash("proposal-b"),
        response_limit: 256,
        max_iterations: 4,
        max_stages: 12,
        max_attempts: 4,
        max_steps_per_stage: 10,
        max_total_steps,
        ceiling: 6,
        reservation_units: 3,
        unit: "fixed_units".into(),
        clock_domain: "stable_ms".into(),
        initial_millis: 10,
        deadline_millis: 100,
        program_root: Some(hash("program-b")),
    };
    let mut carry = SourceMigrationCarry {
        handoff_digest: String::new(),
        previous_schema: SOURCE_EXECUTION_JOURNAL_SCHEMA.into(),
        previous_invocation: hash("invocation-a"),
        previous_generation: 7,
        previous_chain: hash("chain-a"),
        previous_program_root: hash("program-a"),
        destination_program_root: hash("program-b"),
        old_state_id: "state.a".into(),
        new_state_id: "state.b".into(),
        migration_function: "migration.b".into(),
        migration_closure: hash("closure-b"),
        task_digest: source_migration_task_digest(&seed.task, seed.task_budget),
        carried_model_units: 3,
        carried_stage_fuel: 40,
        carried_turns: 1,
        carried_stages: 4,
        carried_effects: 1,
        carried_attempts: 1,
        previous_ceiling: 6,
        previous_max_iterations: 4,
        previous_max_stages: 12,
        previous_max_steps_per_stage: 10,
        previous_max_total_steps: 100,
        previous_reservation_units: 3,
        previous_unit: "fixed_units".into(),
        previous_clock_domain: "stable_ms".into(),
        previous_last_checked_millis: 10,
        previous_deadline_millis: 100,
        evaluation_steps: 10,
    };
    carry.handoff_digest = carry.digest();
    SourceInvocationBinding::bind_migrated_execution(seed, &hash("evaluator"), carry).unwrap()
}
fn opened(sink: &mut SourceCheckpointSink<'_>, binding: &SourceInvocationBinding) {
    sink.append_at(
        SourceJournalEntry::MigrationOpened {
            handoff_digest: binding.migration().unwrap().handoff_digest.clone(),
        },
        10,
    )
    .unwrap();
}

#[test]
fn v3_pure_intent_is_charged_and_first_runtime_stage_is_observe() {
    let binding = fixture(100);
    let mut store = Store::default();
    let mut sink = SourceCheckpointSink::new(&mut store, binding.clone());
    opened(&mut sink, &binding);
    assert_eq!(sink.committed_stage_fuel().unwrap(), 40);
    sink.append_at(
        SourceJournalEntry::MigrationEvaluationIntent {
            attempt: 0,
            fuel: 20,
        },
        11,
    )
    .unwrap();
    assert_eq!(sink.committed_stage_fuel().unwrap(), 60);
    // A crash after the first intent does not refund its reservation. A
    // second pure evaluation needs its own numbered, acknowledged intent.
    sink.append_at(
        SourceJournalEntry::MigrationEvaluationIntent {
            attempt: 1,
            fuel: 20,
        },
        12,
    )
    .unwrap();
    let state = b"{}".to_vec();
    sink.append_at(
        SourceJournalEntry::MigrationEvaluationSettled {
            attempt: 1,
            state_digest: source_migration_state_digest(&state),
            state,
        },
        13,
    )
    .unwrap();
    sink.append_at(SourceJournalEntry::RunOpened, 14).unwrap();
    assert_eq!(
        sink.append_at(
            SourceJournalEntry::StageReservation {
                turn: 1,
                attempt: None,
                role: SourceStageRole::Initialize,
                fuel: 10,
            },
            15
        ),
        Err(SourceJournalError::Order)
    );
    sink.append_at(
        SourceJournalEntry::StageReservation {
            turn: 1,
            attempt: None,
            role: SourceStageRole::Observe,
            fuel: 10,
        },
        15,
    )
    .unwrap();
    let recovered = sink.checkpoint().unwrap();
    assert_eq!(recovered.committed_stage_fuel(), 90);
    assert_eq!(recovered.committed_reserved_units(), 3);
    drop(sink);
    assert!(store.document.contains(SOURCE_MIGRATED_JOURNAL_SCHEMA));
    assert_eq!(
        recover_source_checkpoint(&store.document, &binding)
            .unwrap()
            .generation(),
        6
    );
    assert_eq!(
        recover_source_checkpoint(
            &store.document,
            &SourceInvocationBinding::bind_execution(
                SourceInvocationSeed {
                    lifecycle_digest: hash("lifecycle-b"),
                    source_revision: hash("source-b"),
                    deployment_binding: hash("deployment"),
                    task: b"task".to_vec(),
                    task_budget: 2,
                    proposal_schema_digest: hash("proposal-b"),
                    response_limit: 256,
                    max_iterations: 4,
                    max_stages: 12,
                    max_attempts: 4,
                    max_steps_per_stage: 10,
                    max_total_steps: 100,
                    ceiling: 6,
                    reservation_units: 3,
                    unit: "fixed_units".into(),
                    clock_domain: "stable_ms".into(),
                    initial_millis: 10,
                    deadline_millis: 100,
                    program_root: Some(hash("program-b")),
                },
                &hash("evaluator")
            )
            .unwrap()
        )
        .unwrap_err(),
        SourceJournalError::Malformed
    );
}

#[test]
fn malformed_prefix_and_second_reservation_over_ceiling_refuse() {
    let binding = fixture(75);
    let mut store = Store::default();
    let mut sink = SourceCheckpointSink::new(&mut store, binding.clone());
    opened(&mut sink, &binding);
    assert_eq!(
        sink.append_at(
            SourceJournalEntry::MigrationEvaluationSettled {
                attempt: 0,
                state: b"{}".to_vec(),
                state_digest: source_migration_state_digest(b"{}"),
            },
            11
        ),
        Err(SourceJournalError::Order)
    );
    assert_eq!(
        sink.append_at(SourceJournalEntry::RunOpened, 11),
        Err(SourceJournalError::Order)
    );
    sink.append_at(
        SourceJournalEntry::MigrationEvaluationIntent {
            attempt: 0,
            fuel: 20,
        },
        11,
    )
    .unwrap();
    assert_eq!(
        sink.append_at(
            SourceJournalEntry::MigrationEvaluationIntent {
                attempt: 1,
                fuel: 20,
            },
            12
        ),
        Err(SourceJournalError::Capacity)
    );
    assert_eq!(sink.checkpoint().unwrap().committed_stage_fuel(), 60);
    assert_eq!(
        sink.append_at(
            SourceJournalEntry::MigrationEvaluationSettled {
                attempt: 0,
                state: b"{}".to_vec(),
                state_digest: hash("wrong-state"),
            },
            12
        ),
        Err(SourceJournalError::Order)
    );
}

#[test]
fn lost_ack_poison_requires_latest_reload_and_fresh_charged_pure_intent() {
    let binding = fixture(100);
    let mut store = Store::default();
    let lose_ack = store.lose_ack.clone();
    let mut sink = SourceCheckpointSink::new(&mut store, binding.clone());
    opened(&mut sink, &binding);
    lose_ack.set(true);
    // The store writes the new generation but loses the acknowledgement.
    assert_eq!(
        sink.append_at(
            SourceJournalEntry::MigrationEvaluationIntent {
                attempt: 0,
                fuel: 20,
            },
            11
        ),
        Err(SourceJournalError::Store(CheckpointStoreError))
    );
    assert!(sink.poisoned());
    assert_eq!(
        sink.append_at(
            SourceJournalEntry::MigrationEvaluationIntent {
                attempt: 0,
                fuel: 20,
            },
            11
        ),
        Err(SourceJournalError::Poisoned)
    );
    drop(sink);
    let recovered = recover_source_checkpoint(&store.document, &binding).unwrap();
    assert_eq!(recovered.committed_stage_fuel(), 60);
    let mut resumed = SourceCheckpointSink::resume(&mut store, recovered).unwrap();
    resumed
        .append_at(
            SourceJournalEntry::MigrationEvaluationIntent {
                attempt: 1,
                fuel: 20,
            },
            12,
        )
        .unwrap();
    assert_eq!(resumed.checkpoint().unwrap().committed_stage_fuel(), 80);
}
