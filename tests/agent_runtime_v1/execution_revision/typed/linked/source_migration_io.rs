use super::*;
use semaprax::agent_lifecycle::iterative::source_live::{
    prepare_source_live_migration_with_io_limits, SourceIoLimits,
};

fn priced(ceiling: i64) -> SourceLivePricing {
    SourceLivePricing {
        currency: "USD".into(),
        minor_unit_exponent: 6,
        price_per_work_unit_minor: 7,
        money_ceiling_minor: ceiling,
    }
}

fn live_request<'a>(
    task: &'a LifecycleTask,
    policy: &'a SourceLivePolicy,
    clock: &'a Clock,
    cancellation: &'a AgentCancellation,
    checkpoint: Option<&'a str>,
) -> SourceLiveRequest<'a> {
    SourceLiveRequest {
        task,
        budget: budget(),
        policy,
        clock,
        cancellation,
        checkpoint,
    }
}

#[test]
fn io_source_migration_a_to_b_to_c_preserves_totals_and_rejects_widening() {
    let a = durable::first();
    let b = durable::successor(&a, "State", "StateB", "b", &["marker"], true);
    let c = durable::successor(&b, "StateB", "StateC", "c", &["marker", "extra"], false);
    let (project_a, project_b, project_c) = (retained(&a), retained(&b), retained(&c));
    let (life_a, life_b, life_c) = (
        compiled(&project_a),
        compiled(&project_b),
        compiled(&project_c),
    );
    let (policy_a, policy_b, policy_c) =
        (policy(&project_a), policy(&project_b), policy(&project_c));
    // Each successor quote is narrower while still admitting its three
    // attempts after carrying the predecessor's reservation.
    let (price_a, price_b, price_c) = (priced(84), priced(77), priced(70));
    let io_a = SourceIoLimits {
        max_request_bytes: 65_536,
        max_total_request_bytes: 3_000_000,
        max_total_response_bytes: 40_000,
    };
    let io_b = SourceIoLimits {
        max_request_bytes: 65_535,
        max_total_request_bytes: 2_900_000,
        max_total_response_bytes: 39_000,
    };
    let io_c = SourceIoLimits {
        max_request_bytes: 65_534,
        max_total_request_bytes: 2_800_000,
        max_total_response_bytes: 36_864,
    };
    let task = task();
    let clock = Clock::at(0);
    let cancellation = AgentCancellation::new();

    let mut a_store = Store::default();
    let mut a_model = Model::new(&life_a);
    let mut a_read = Read::default();
    let a_run = life_a
        .run_live_durable_with_io_limits(
            live_request(&task, &policy_a, &clock, &cancellation, None),
            Some(&price_a),
            &io_a,
            &mut a_model,
            &mut a_read,
            &mut a_store,
        )
        .unwrap();
    assert_eq!((a_model.calls, a_read.calls), (3, 3));
    assert_eq!(a_run.checkpoint.priced_totals().unwrap().reserved_minor, 21);
    let a_io = a_run.checkpoint.io_totals().unwrap();
    assert!(a_io.reserved_request_bytes > 0);
    assert_eq!(a_io.reserved_response_bytes, 3 * 4096);
    assert_eq!(
        a_run
            .checkpoint
            .priced_totals()
            .unwrap()
            .unknown_charge_reservation_minor,
        21
    );

    let binding_a = policy_a
        .binding_with_io_limits(&life_a, &task, budget(), Some(&price_a), &io_a)
        .unwrap();
    assert!(prepare_source_live_priced_migration(
        SourceLiveMigrationRequest {
            previous: endpoint(&project_a, &life_a, &policy_a),
            previous_binding: &binding_a,
            previous_checkpoint: &a_store.document,
            destination: endpoint(&project_b, &life_b, &policy_b),
            task: &task,
            migration_function: "fixture.agent.fn.migrate_b",
            max_migration_steps: 10_000,
            expected_handoff_digest: None,
        },
        &price_a,
        &price_b
    )
    .is_err());
    let mut b_store = Store::default();
    let prepared_b = prepare_source_live_migration_with_io_limits(
        SourceLiveMigrationRequest {
            previous: endpoint(&project_a, &life_a, &policy_a),
            previous_binding: &binding_a,
            previous_checkpoint: &a_store.document,
            destination: endpoint(&project_b, &life_b, &policy_b),
            task: &task,
            migration_function: "fixture.agent.fn.migrate_b",
            max_migration_steps: 10_000,
            expected_handoff_digest: None,
        },
        Some(&price_a),
        Some(&price_b),
        &io_a,
        &io_b,
    )
    .unwrap();
    let binding_b = prepared_b.binding().clone();
    let mut b_model = Model::new(&life_b);
    let mut b_read = Read::default();
    let b_run = prepared_b
        .run(
            &mut b_model,
            &mut b_read,
            &mut b_store,
            &clock,
            &cancellation,
        )
        .unwrap();
    assert_eq!((b_model.calls, b_read.calls), (3, 3));
    assert_eq!(b_run.checkpoint.priced_totals().unwrap().reserved_minor, 42);
    let b_io = b_run.checkpoint.io_totals().unwrap();
    let local_request_bytes =
        |checkpoint: &semaprax::live_invocation::source_journal::RecoveredSourceCheckpoint| -> u64 {
            checkpoint
                .entries()
                .iter()
                .filter_map(|entry| match entry {
                    SourceJournalEntry::PricedAttemptIntent(intent) => {
                        Some(intent.request_bytes as u64)
                    }
                    _ => None,
                })
                .sum()
        };
    assert_eq!(
        b_io.reserved_request_bytes,
        a_io.reserved_request_bytes + local_request_bytes(&b_run.checkpoint)
    );
    assert_eq!(b_io.reserved_response_bytes, 6 * 4096);
    assert_eq!(
        b_io.unknown_response_reservation_bytes,
        a_io.unknown_response_reservation_bytes
    );
    assert_eq!(
        b_run
            .checkpoint
            .priced_totals()
            .unwrap()
            .unknown_charge_reservation_minor,
        42
    );
    let ordinals: Vec<u32> = b_run
        .checkpoint
        .entries()
        .iter()
        .filter_map(|entry| match entry {
            SourceJournalEntry::PricedAttemptIntent(intent) => Some(intent.money_ordinal),
            _ => None,
        })
        .collect();
    assert_eq!(ordinals, vec![3, 4, 5]);

    let mut c_store = Store::default();
    let prepared_c = prepare_source_live_migration_with_io_limits(
        SourceLiveMigrationRequest {
            previous: endpoint(&project_b, &life_b, &policy_b),
            previous_binding: &binding_b,
            previous_checkpoint: &b_store.document,
            destination: endpoint(&project_c, &life_c, &policy_c),
            task: &task,
            migration_function: "fixture.agent.fn.migrate_c",
            max_migration_steps: 10_000,
            expected_handoff_digest: None,
        },
        Some(&price_b),
        Some(&price_c),
        &io_b,
        &io_c,
    )
    .unwrap();
    let mut c_model = Model::new(&life_c);
    let mut c_read = Read::default();
    let c_run = prepared_c
        .run(
            &mut c_model,
            &mut c_read,
            &mut c_store,
            &clock,
            &cancellation,
        )
        .unwrap();
    assert_eq!((c_model.calls, c_read.calls), (3, 3));
    assert_eq!(c_run.checkpoint.priced_totals().unwrap().reserved_minor, 63);
    let c_io = c_run.checkpoint.io_totals().unwrap();
    assert_eq!(
        c_io.reserved_request_bytes,
        b_io.reserved_request_bytes + local_request_bytes(&c_run.checkpoint)
    );
    assert_eq!(c_io.reserved_response_bytes, 9 * 4096);
    assert_eq!(c_io.reserved_response_bytes, io_c.max_total_response_bytes);
    let c_ordinals: Vec<u32> = c_run
        .checkpoint
        .entries()
        .iter()
        .filter_map(|entry| match entry {
            SourceJournalEntry::PricedAttemptIntent(intent) => Some(intent.money_ordinal),
            _ => None,
        })
        .collect();
    assert_eq!(c_ordinals, vec![6, 7, 8]);
    assert_eq!(
        c_run
            .checkpoint
            .priced_totals()
            .unwrap()
            .unknown_charge_reservation_minor,
        63
    );
    assert_eq!(
        c_run
            .checkpoint
            .entries()
            .iter()
            .filter_map(|entry| match entry {
                SourceJournalEntry::PricedAttemptIntent(intent) => Some(intent.money_ordinal),
                _ => None,
            })
            .next_back(),
        Some(8)
    );

    let terminal = c_store.document.clone();
    let mut no_model = Model::new(&life_c);
    let mut no_read = Read::default();
    let recovered = prepare_source_live_migration_with_io_limits(
        SourceLiveMigrationRequest {
            previous: endpoint(&project_b, &life_b, &policy_b),
            previous_binding: &binding_b,
            previous_checkpoint: &b_store.document,
            destination: endpoint(&project_c, &life_c, &policy_c),
            task: &task,
            migration_function: "fixture.agent.fn.migrate_c",
            max_migration_steps: 10_000,
            expected_handoff_digest: None,
        },
        Some(&price_b),
        Some(&price_c),
        &io_b,
        &io_c,
    )
    .unwrap()
    .with_checkpoint(&terminal)
    .run(
        &mut no_model,
        &mut no_read,
        &mut c_store,
        &clock,
        &cancellation,
    )
    .unwrap();
    assert!(recovered.checked_run.is_none());
    assert_eq!((no_model.calls, no_read.calls), (0, 0));
    assert_eq!(
        recovered.checkpoint.priced_totals().unwrap().reserved_minor,
        63
    );

    let changed = SourceLivePricing {
        price_per_work_unit_minor: 8,
        ..price_b.clone()
    };
    assert!(prepare_source_live_migration_with_io_limits(
        SourceLiveMigrationRequest {
            previous: endpoint(&project_b, &life_b, &policy_b),
            previous_binding: &binding_b,
            previous_checkpoint: &b_store.document,
            destination: endpoint(&project_c, &life_c, &policy_c),
            task: &task,
            migration_function: "fixture.agent.fn.migrate_c",
            max_migration_steps: 10_000,
            expected_handoff_digest: None,
        },
        Some(&changed),
        Some(&price_c),
        &io_b,
        &io_c
    )
    .is_err());
    let io_wide_request = SourceIoLimits {
        max_request_bytes: 65_536,
        ..io_b.clone()
    };
    let io_wide_response = SourceIoLimits {
        max_total_response_bytes: io_b.max_total_response_bytes + 1,
        ..io_b.clone()
    };
    let before_widening_rejection = b_store.document.clone();
    assert!(prepare_source_live_migration_with_io_limits(
        SourceLiveMigrationRequest {
            previous: endpoint(&project_b, &life_b, &policy_b),
            previous_binding: &binding_b,
            previous_checkpoint: &b_store.document,
            destination: endpoint(&project_c, &life_c, &policy_c),
            task: &task,
            migration_function: "fixture.agent.fn.migrate_c",
            max_migration_steps: 10_000,
            expected_handoff_digest: None,
        },
        Some(&price_b),
        Some(&price_c),
        &io_b,
        &io_wide_request
    )
    .is_err());
    assert!(prepare_source_live_migration_with_io_limits(
        SourceLiveMigrationRequest {
            previous: endpoint(&project_b, &life_b, &policy_b),
            previous_binding: &binding_b,
            previous_checkpoint: &b_store.document,
            destination: endpoint(&project_c, &life_c, &policy_c),
            task: &task,
            migration_function: "fixture.agent.fn.migrate_c",
            max_migration_steps: 10_000,
            expected_handoff_digest: None,
        },
        Some(&price_b),
        Some(&price_c),
        &io_b,
        &io_wide_response
    )
    .is_err());
    assert_eq!(b_store.document, before_widening_rejection);
    let narrow = priced(42);
    let prepared_narrow = prepare_source_live_migration_with_io_limits(
        SourceLiveMigrationRequest {
            previous: endpoint(&project_b, &life_b, &policy_b),
            previous_binding: &binding_b,
            previous_checkpoint: &b_store.document,
            destination: endpoint(&project_c, &life_c, &policy_c),
            task: &task,
            migration_function: "fixture.agent.fn.migrate_c",
            max_migration_steps: 10_000,
            expected_handoff_digest: None,
        },
        Some(&price_b),
        Some(&narrow),
        &io_b,
        &io_c,
    )
    .unwrap();
    let mut refused_model = Model::new(&life_c);
    let mut refused_read = Read::default();
    let refused = prepared_narrow
        .run(
            &mut refused_model,
            &mut refused_read,
            &mut Store::default(),
            &clock,
            &cancellation,
        )
        .err()
        .expect("a ceiling equal to carried money refuses before dispatch");
    assert_eq!(
        refused.selected,
        Some(SourceTerminalStatus::BudgetExhausted)
    );
    assert_eq!(
        refused
            .checkpoint
            .as_ref()
            .unwrap()
            .priced_totals()
            .unwrap()
            .reserved_minor,
        42
    );
    assert_eq!((refused_model.calls, refused_read.calls), (0, 0));
}
