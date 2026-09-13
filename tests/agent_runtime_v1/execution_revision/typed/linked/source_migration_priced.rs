use super::*;

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
fn priced_source_migration_a_to_b_to_c_preserves_money_history_and_ordinals() {
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
    let task = task();
    let clock = Clock::at(0);
    let cancellation = AgentCancellation::new();

    let mut a_store = Store::default();
    let mut a_model = Model::new(&life_a);
    let mut a_read = Read::default();
    let a_run = life_a
        .run_live_durable_priced(
            live_request(&task, &policy_a, &clock, &cancellation, None),
            &price_a,
            &mut a_model,
            &mut a_read,
            &mut a_store,
        )
        .unwrap();
    assert_eq!((a_model.calls, a_read.calls), (3, 3));
    assert_eq!(a_run.checkpoint.priced_totals().unwrap().reserved_minor, 21);
    assert_eq!(
        a_run
            .checkpoint
            .priced_totals()
            .unwrap()
            .unknown_charge_reservation_minor,
        21
    );

    let binding_a = policy_a
        .binding_priced(&life_a, &task, budget(), &price_a)
        .unwrap();
    let mut b_store = Store::default();
    let prepared_b = prepare_source_live_priced_migration(
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
        &price_b,
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
    let prepared_c = prepare_source_live_priced_migration(
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
        &price_b,
        &price_c,
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
            .last(),
        Some(8)
    );

    let terminal = c_store.document.clone();
    let mut no_model = Model::new(&life_c);
    let mut no_read = Read::default();
    let recovered = prepare_source_live_priced_migration(
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
        &price_b,
        &price_c,
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
    assert!(prepare_source_live_priced_migration(
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
        &changed,
        &price_c
    )
    .is_err());
    let narrow = priced(42);
    let prepared_narrow = prepare_source_live_priced_migration(
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
        &price_b,
        &narrow,
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
