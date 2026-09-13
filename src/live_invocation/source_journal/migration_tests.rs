use super::*;
use crate::live_invocation::pricing::ValidatedPricing;
use crate::model_budget_policy::{intersect, ModelBudgetLimits};

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
    opened_at(sink, binding, 10);
}

fn opened_at(sink: &mut SourceCheckpointSink<'_>, binding: &SourceInvocationBinding, now: i64) {
    sink.append_at(
        SourceJournalEntry::MigrationOpened {
            handoff_digest: binding.migration_handoff_digest().unwrap().to_owned(),
        },
        now,
    )
    .unwrap();
}

fn priced_seed(program: &str) -> SourceInvocationSeed {
    SourceInvocationSeed {
        lifecycle_digest: hash("priced-lifecycle"),
        source_revision: hash("priced-source"),
        deployment_binding: hash("priced-deployment"),
        task: b"priced task".to_vec(),
        task_budget: 2,
        proposal_schema_digest: hash("priced-proposal"),
        response_limit: 32,
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
        program_root: Some(hash(program)),
    }
}

fn priced_contract(ceiling_minor: i64) -> ValidatedPricing {
    ValidatedPricing::new("fixed_units".into(), "USD".into(), 2, 5, ceiling_minor).unwrap()
}

fn priced_destination_seed() -> SourceInvocationSeed {
    let mut seed = priced_seed("priced-program-b");
    seed.initial_millis = 22;
    seed
}

fn priced_predecessor() -> (SourceInvocationBinding, RecoveredSourceCheckpoint) {
    let binding = SourceInvocationBinding::bind_priced_execution(
        priced_seed("priced-program-a"),
        &hash("priced-evaluator"),
        priced_contract(30),
    )
    .unwrap();
    let mut store = Store::default();
    {
        let mut sink = SourceCheckpointSink::new(&mut store, binding.clone());
        sink.append_at(SourceJournalEntry::RunOpened, 10).unwrap();
        sink.append_at(
            SourceJournalEntry::StageReservation {
                turn: 0,
                attempt: None,
                role: SourceStageRole::Initialize,
                fuel: 10,
            },
            11,
        )
        .unwrap();
        sink.append_at(
            SourceJournalEntry::StageReservation {
                turn: 0,
                attempt: None,
                role: SourceStageRole::Observe,
                fuel: 10,
            },
            12,
        )
        .unwrap();
        sink.append_at(
            SourceJournalEntry::TurnObserved {
                turn: 0,
                state: hash("priced-state"),
                observation: hash("priced-observation"),
                feedback: hash("priced-feedback"),
            },
            13,
        )
        .unwrap();
        let intent = sink
            .attempt_intent(0, 0, hash("priced-request"), hash("priced-prompt"), 12)
            .unwrap();
        sink.append_at(intent, 14).unwrap();
        sink.append_at(
            SourceJournalEntry::AttemptSettled {
                turn: 0,
                attempt: 0,
                response: b"proposal".to_vec(),
                response_digest: source_response_digest(b"proposal"),
            },
            15,
        )
        .unwrap();
        let usage = sink
            .priced_attempt_usage(0, 0, None, ProviderChargeObservation::Unknown)
            .unwrap();
        sink.append_at(usage, 15).unwrap();
        sink.append_at(
            SourceJournalEntry::ProposalAdmitted {
                turn: 0,
                attempt: 0,
                proposal_digest: hash("priced-admitted"),
            },
            16,
        )
        .unwrap();
        sink.append_at(
            SourceJournalEntry::StageReservation {
                turn: 0,
                attempt: Some(0),
                role: SourceStageRole::Authorize,
                fuel: 10,
            },
            17,
        )
        .unwrap();
        sink.append_at(
            SourceJournalEntry::AuthorizationConsumed {
                turn: 0,
                attempt: 0,
                grant_digest: hash("priced-grant"),
            },
            18,
        )
        .unwrap();
        sink.append_at(
            SourceJournalEntry::EffectIntent {
                turn: 0,
                attempt: 0,
                operation: "read.fixture".into(),
                request_digest: hash("priced-effect"),
            },
            19,
        )
        .unwrap();
        sink.append_at(
            SourceJournalEntry::EffectObserved {
                turn: 0,
                attempt: 0,
                operation: "read.fixture".into(),
                observation: b"result".to_vec(),
                observation_digest: source_effect_digest(b"result"),
            },
            20,
        )
        .unwrap();
        sink.append_at(
            SourceJournalEntry::StageReservation {
                turn: 0,
                attempt: Some(0),
                role: SourceStageRole::Reduce,
                fuel: 10,
            },
            21,
        )
        .unwrap();
        let carrier = b"true".to_vec();
        sink.append_at(
            SourceJournalEntry::Transition {
                turn: 0,
                attempt: 0,
                case: SourceTransitionCase::Complete,
                carrier_digest: digest(b"semaprax.agent-step.value.v2\0", &carrier),
            },
            22,
        )
        .unwrap();
        let terminal = sink
            .terminal_snapshot_entry(
                Some(0),
                SourceTerminalStatus::Complete,
                Some(carrier),
                SourceTerminalEvidenceInput {
                    completed_stages: 4,
                    omitted_stage_rows: 1,
                    stage_rows: vec![
                        SourceStageSummary {
                            role: SourceStageRole::Initialize,
                            function_id: hash("initialize"),
                            outcome: SourceStageOutcome::Returned,
                            steps_used: 2,
                        },
                        SourceStageSummary {
                            role: SourceStageRole::Observe,
                            function_id: hash("observe"),
                            outcome: SourceStageOutcome::Returned,
                            steps_used: 2,
                        },
                        SourceStageSummary {
                            role: SourceStageRole::Authorize,
                            function_id: hash("authorize"),
                            outcome: SourceStageOutcome::Returned,
                            steps_used: 2,
                        },
                    ],
                    checked_run_evidence: None,
                },
            )
            .unwrap();
        sink.append_at(terminal, 22).unwrap();
    }
    let recovered = recover_source_checkpoint(&store.document, &binding).unwrap();
    (binding, recovered)
}

fn policy_contract(
    model: &str,
    policy: &str,
    provider: &str,
    aggregate: u64,
) -> SourcePolicyBindingV6 {
    let limits = ModelBudgetLimits {
        max_calls: 2,
        max_retries: 0,
        max_providers: 0,
        max_context_tokens: 8,
        max_output_tokens: 8,
        max_aggregate_tokens: aggregate,
        max_cost_micros: 100,
        max_latency_millis: i64::MAX,
    };
    SourcePolicyBindingV6::new(
        hash(model),
        hash(policy),
        provider.into(),
        intersect(limits, limits, limits).unwrap(),
    )
    .unwrap()
}
fn policy_quote(policy: &str, request: &str, provider: &str) -> SourcePolicyQuoteV6 {
    SourcePolicyQuoteV6 {
        policy_binding_digest: hash(policy),
        request_digest: hash(request),
        provider_id: provider.into(),
        context_tokens: 3,
        output_tokens: 3,
        estimated_cost_micros: 10,
    }
}

fn policy_predecessor() -> (SourceInvocationBinding, RecoveredSourceCheckpoint) {
    let binding = SourceInvocationBinding::bind_policy_execution(
        priced_seed("priced-program-a"),
        &hash("priced-evaluator"),
        policy_contract("model-a", "policy-a", "provider.a", 12),
    )
    .unwrap();
    let mut store = Store::default();
    {
        let mut sink = SourceCheckpointSink::new(&mut store, binding.clone());
        sink.append_at(SourceJournalEntry::RunOpened, 10).unwrap();
        sink.append_at(
            SourceJournalEntry::StageReservation {
                turn: 0,
                attempt: None,
                role: SourceStageRole::Initialize,
                fuel: 10,
            },
            11,
        )
        .unwrap();
        sink.append_at(
            SourceJournalEntry::StageReservation {
                turn: 0,
                attempt: None,
                role: SourceStageRole::Observe,
                fuel: 10,
            },
            12,
        )
        .unwrap();
        sink.append_at(
            SourceJournalEntry::TurnObserved {
                turn: 0,
                state: hash("priced-state"),
                observation: hash("priced-observation"),
                feedback: hash("priced-feedback"),
            },
            13,
        )
        .unwrap();
        let intent = sink
            .policy_attempt_intent(
                0,
                0,
                hash("priced-request"),
                hash("priced-prompt"),
                12,
                policy_quote("policy-a", "priced-request", "provider.a"),
            )
            .unwrap();
        sink.append_at(SourceJournalEntry::PolicyAttemptIntent(intent), 14)
            .unwrap();
        sink.append_at(
            SourceJournalEntry::AttemptSettled {
                turn: 0,
                attempt: 0,
                response: b"proposal".to_vec(),
                response_digest: source_response_digest(b"proposal"),
            },
            15,
        )
        .unwrap();
        let usage = sink
            .policy_attempt_usage(0, 0, 0, PolicyAttemptUsageV6::Unknown)
            .unwrap();
        sink.append_at(usage, 15).unwrap();
        sink.append_at(
            SourceJournalEntry::ProposalAdmitted {
                turn: 0,
                attempt: 0,
                proposal_digest: hash("priced-admitted"),
            },
            16,
        )
        .unwrap();
        sink.append_at(
            SourceJournalEntry::StageReservation {
                turn: 0,
                attempt: Some(0),
                role: SourceStageRole::Authorize,
                fuel: 10,
            },
            17,
        )
        .unwrap();
        sink.append_at(
            SourceJournalEntry::AuthorizationConsumed {
                turn: 0,
                attempt: 0,
                grant_digest: hash("priced-grant"),
            },
            18,
        )
        .unwrap();
        sink.append_at(
            SourceJournalEntry::EffectIntent {
                turn: 0,
                attempt: 0,
                operation: "read.fixture".into(),
                request_digest: hash("priced-effect"),
            },
            19,
        )
        .unwrap();
        sink.append_at(
            SourceJournalEntry::EffectObserved {
                turn: 0,
                attempt: 0,
                operation: "read.fixture".into(),
                observation: b"result".to_vec(),
                observation_digest: source_effect_digest(b"result"),
            },
            20,
        )
        .unwrap();
        sink.append_at(
            SourceJournalEntry::StageReservation {
                turn: 0,
                attempt: Some(0),
                role: SourceStageRole::Reduce,
                fuel: 10,
            },
            21,
        )
        .unwrap();
        let carrier = b"true".to_vec();
        sink.append_at(
            SourceJournalEntry::Transition {
                turn: 0,
                attempt: 0,
                case: SourceTransitionCase::Complete,
                carrier_digest: digest(b"semaprax.agent-step.value.v2\0", &carrier),
            },
            22,
        )
        .unwrap();
        let terminal = sink
            .terminal_snapshot_entry(
                Some(0),
                SourceTerminalStatus::Complete,
                Some(carrier),
                SourceTerminalEvidenceInput {
                    completed_stages: 4,
                    omitted_stage_rows: 1,
                    stage_rows: vec![
                        SourceStageSummary {
                            role: SourceStageRole::Initialize,
                            function_id: hash("initialize"),
                            outcome: SourceStageOutcome::Returned,
                            steps_used: 2,
                        },
                        SourceStageSummary {
                            role: SourceStageRole::Observe,
                            function_id: hash("observe"),
                            outcome: SourceStageOutcome::Returned,
                            steps_used: 2,
                        },
                        SourceStageSummary {
                            role: SourceStageRole::Authorize,
                            function_id: hash("authorize"),
                            outcome: SourceStageOutcome::Returned,
                            steps_used: 2,
                        },
                    ],
                    checked_run_evidence: None,
                },
            )
            .unwrap();
        sink.append_at(terminal, 22).unwrap();
    }
    let recovered = recover_source_checkpoint(&store.document, &binding).unwrap();
    (binding, recovered)
}

fn policy_carry(
    predecessor: &SourceInvocationBinding,
    recovered: &RecoveredSourceCheckpoint,
) -> PolicyMigrationCarryV6 {
    let seed = priced_seed("priced-program-b");
    let mut base = SourceMigrationCarry {
        handoff_digest: String::new(),
        previous_schema: predecessor.schema().into(),
        previous_invocation: predecessor.invocation().into(),
        previous_generation: recovered.generation(),
        previous_chain: recovered.chain().into(),
        previous_program_root: hash("priced-program-a"),
        destination_program_root: hash("priced-program-b"),
        old_state_id: "state.a".into(),
        new_state_id: "state.b".into(),
        migration_function: "migration.b".into(),
        migration_closure: hash("policy-closure"),
        task_digest: source_migration_task_digest(&seed.task, seed.task_budget),
        carried_model_units: recovered.committed_reserved_units(),
        carried_stage_fuel: recovered.committed_stage_fuel(),
        carried_turns: 1,
        carried_stages: 4,
        carried_effects: 1,
        carried_attempts: 1,
        previous_ceiling: recovered.ceiling(),
        previous_max_iterations: recovered.max_iterations(),
        previous_max_stages: recovered.max_stages(),
        previous_max_steps_per_stage: recovered.max_steps_per_stage().unwrap(),
        previous_max_total_steps: recovered.max_total_steps().unwrap(),
        previous_reservation_units: recovered.reservation_units(),
        previous_unit: recovered.unit().into(),
        previous_clock_domain: recovered.clock_domain().into(),
        previous_last_checked_millis: recovered.last_checked_millis(),
        previous_deadline_millis: recovered.deadline_millis(),
        evaluation_steps: 10,
    };
    base.handoff_digest = base.digest();
    PolicyMigrationCarryV6::from_predecessor(
        base,
        predecessor,
        recovered,
        &policy_contract("model-b", "policy-b", "provider.a", 12),
    )
    .unwrap()
}

fn priced_carry(
    predecessor: &SourceInvocationBinding,
    recovered: &RecoveredSourceCheckpoint,
    closure: &str,
) -> PricedMigrationCarryV4 {
    let seed = priced_seed("priced-program-b");
    let mut base = SourceMigrationCarry {
        handoff_digest: String::new(),
        previous_schema: predecessor.schema().to_owned(),
        previous_invocation: predecessor.invocation().to_owned(),
        previous_generation: recovered.generation(),
        previous_chain: recovered.chain().to_owned(),
        previous_program_root: hash("priced-program-a"),
        destination_program_root: hash("priced-program-b"),
        old_state_id: "state.a".into(),
        new_state_id: "state.b".into(),
        migration_function: "migration.b".into(),
        migration_closure: hash(closure),
        task_digest: source_migration_task_digest(&seed.task, seed.task_budget),
        carried_model_units: recovered.committed_reserved_units(),
        carried_stage_fuel: recovered.committed_stage_fuel(),
        carried_turns: 1,
        carried_stages: 4,
        carried_effects: 1,
        carried_attempts: 1,
        previous_ceiling: recovered.ceiling(),
        previous_max_iterations: recovered.max_iterations(),
        previous_max_stages: recovered.max_stages(),
        previous_max_steps_per_stage: recovered.max_steps_per_stage().unwrap(),
        previous_max_total_steps: recovered.max_total_steps().unwrap(),
        previous_reservation_units: recovered.reservation_units(),
        previous_unit: recovered.unit().to_owned(),
        previous_clock_domain: recovered.clock_domain().to_owned(),
        previous_last_checked_millis: recovered.last_checked_millis(),
        previous_deadline_millis: recovered.deadline_millis(),
        evaluation_steps: 10,
    };
    base.handoff_digest = base.digest();
    PricedMigrationCarryV4::from_predecessor(base, predecessor, recovered, priced_contract(15))
        .unwrap()
}

#[test]
fn policy_v6_migration_carries_exposure_and_refuses_tampering_or_widening() {
    let (predecessor, recovered) = policy_predecessor();
    let carry = policy_carry(&predecessor, &recovered);
    assert_eq!(carry.totals.next_ordinal, 1);
    assert_eq!(carry.reservations.len(), 1);
    let destination_policy = policy_contract("model-b", "policy-b", "provider.a", 12);
    let destination = SourceInvocationBinding::bind_policy_migrated_execution(
        priced_destination_seed(),
        &hash("priced-evaluator"),
        carry.clone(),
        destination_policy.clone(),
    )
    .unwrap();
    let intent = SourceJournal::new(destination.clone())
        .policy_attempt_intent(
            1,
            0,
            hash("next-request"),
            hash("next-prompt"),
            12,
            policy_quote("policy-b", "next-request", "provider.a"),
        )
        .unwrap();
    assert_eq!(intent.reservation.ordinal, 1);
    assert_ne!(
        destination.policy_binding().unwrap().model_binding_digest,
        predecessor.policy_binding().unwrap().model_binding_digest
    );
    let mut tampered = carry.clone();
    tampered.totals.next_ordinal = 2;
    assert!(SourceInvocationBinding::bind_policy_migrated_execution(
        priced_destination_seed(),
        &hash("priced-evaluator"),
        tampered,
        destination_policy.clone()
    )
    .is_err());
    assert!(PolicyMigrationCarryV6::from_predecessor(
        carry.base.clone(),
        &predecessor,
        &recovered,
        &policy_contract("model-b", "policy-b", "provider.b", 12)
    )
    .is_err());
    assert!(PolicyMigrationCarryV6::from_predecessor(
        carry.base.clone(),
        &predecessor,
        &recovered,
        &policy_contract("model-b", "policy-b", "provider.a", 13)
    )
    .is_err());
}

#[test]
fn priced_migration_recovery_carries_accounting_and_binds_handoff_to_attempts() {
    let (predecessor, recovered) = priced_predecessor();
    let carry = priced_carry(&predecessor, &recovered, "closure-b");
    assert_eq!(carry.monetary.next_ordinal(), 1);
    let destination = SourceInvocationBinding::bind_priced_migrated_execution(
        priced_destination_seed(),
        &hash("priced-evaluator"),
        carry.clone(),
        priced_contract(15),
    )
    .unwrap();
    assert_eq!(
        destination.priced_binding().unwrap().invocation(),
        destination.invocation()
    );
    let intent = destination
        .attempt_intent_at_ordinal(1, 0, hash("next-request"), hash("next-prompt"), 12, 1)
        .unwrap();
    let SourceJournalEntry::PricedAttemptIntent(intent) = intent else {
        panic!("priced destination must retain typed intent")
    };
    assert_eq!(intent.money_ordinal, 1);

    let other = SourceInvocationBinding::bind_priced_migrated_execution(
        priced_destination_seed(),
        &hash("priced-evaluator"),
        priced_carry(&predecessor, &recovered, "closure-c"),
        priced_contract(15),
    )
    .unwrap();
    let SourceJournalEntry::PricedAttemptIntent(other_intent) = other
        .attempt_intent_at_ordinal(1, 0, hash("next-request"), hash("next-prompt"), 12, 1)
        .unwrap()
    else {
        panic!("priced destination must retain typed intent")
    };
    assert_ne!(destination.invocation(), other.invocation());
    assert_ne!(intent.attempt_digest, other_intent.attempt_digest);

    let mut store = Store::default();
    {
        let mut sink = SourceCheckpointSink::new(&mut store, destination.clone());
        opened_at(&mut sink, &destination, 22);
        sink.append_at(
            SourceJournalEntry::MigrationEvaluationIntent {
                attempt: 0,
                fuel: 20,
            },
            23,
        )
        .unwrap();
        let state = b"{}".to_vec();
        sink.append_at(
            SourceJournalEntry::MigrationEvaluationSettled {
                attempt: 0,
                state_digest: source_migration_state_digest(&state),
                state,
            },
            24,
        )
        .unwrap();
        sink.append_at(SourceJournalEntry::RunOpened, 25).unwrap();
        let SourceJournalEntry::PricedAttemptIntent(resumed_intent) = sink
            .attempt_intent(1, 0, hash("next-request"), hash("next-prompt"), 12)
            .unwrap()
        else {
            panic!("priced sink must retain typed intent")
        };
        assert_eq!(resumed_intent.money_ordinal, 1);
        assert_eq!(resumed_intent.attempt_digest, intent.attempt_digest);
    }
    let migrated = recover_source_checkpoint(&store.document, &destination).unwrap();
    let totals = migrated.priced_totals().unwrap();
    assert_eq!(totals.reserved_minor, 15);
    assert_eq!(totals.unknown_charge_reservation_minor, 15);
    assert_eq!(totals.remaining_admission_minor, 0);

    let wrong_currency = SourceInvocationBinding::bind_priced_execution(
        priced_seed("priced-program-a"),
        &hash("priced-evaluator"),
        ValidatedPricing::new("fixed_units".into(), "EUR".into(), 2, 5, 30).unwrap(),
    )
    .unwrap();
    let mut invalid = carry.base.clone();
    invalid.handoff_digest = invalid.digest();
    assert_eq!(
        PricedMigrationCarryV4::from_predecessor(
            invalid,
            &wrong_currency,
            &recovered,
            priced_contract(15)
        ),
        Err(SourceJournalError::Binding)
    );
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
