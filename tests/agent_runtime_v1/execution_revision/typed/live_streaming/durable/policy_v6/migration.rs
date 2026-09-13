use super::*;
use semaprax::agent_lifecycle::iterative::source_live::SourceLiveMigrationRequest;
use semaprax::agent_runtime_v2::AgentRuntimeV2;
use semaprax::live_invocation::source_journal::SourceIoLimits;
use std::sync::Arc;

type Project = semaprax::project::ProjectRevision;
fn retained(fixture: &crate::execution_revision::Fixture) -> Arc<Project> {
    with_authenticated_project(&fixture.0.join("semaprax.toml"), |snapshot| {
        Ok(snapshot.retain_revision())
    })
    .unwrap()
}
fn budget() -> IterativeBudget {
    IterativeBudget {
        max_iterations: 6,
        max_stages: 96,
        ..IterativeBudget::default()
    }
}
fn task() -> LifecycleTask {
    LifecycleTask {
        objective: b"streamed typed task".to_vec(),
        budget: 12,
    }
}
fn runtime(project: Arc<Project>) -> AgentRuntimeV2 {
    let root = project.program_root().unwrap();
    let (_, deployment) = migrate_agent_definition_v1(
        project.agent_definitions()[0]
            .definition()
            .canonical_source(),
        "fixture.streaming.runtime",
    )
    .unwrap();
    bind_agent_runtime_v2_live(
        project,
        ProgramRootRef::V1(&root),
        root.program_root_digest(),
        "src/app.spx",
        "fixture.agent",
        "fixture.agent.type.step",
        "fixture.agent.type.proposal.sequence",
        operations(),
        &deployment,
        task(),
        budget(),
        EffectBudget {
            max_calls: 6,
            max_argument_bytes: 4096,
            max_result_bytes: 4096,
            max_total_bytes: 16384,
        },
    )
    .unwrap()
}
fn live_policy(binding: &SourceModelBinding) -> SourceLivePolicy {
    SourceLivePolicy {
        ceiling: 6,
        max_total_steps: 10_000_000,
        ..policy(binding)
    }
}
#[test]
fn typed_policy_io_migration_keeps_prior_usage_and_replays_without_dispatch() {
    use crate::execution_revision::typed::migration::durable as fixtures;
    let a = fixtures::first();
    let path = a.0.join("src/app.spx");
    let mut text = std::fs::read_to_string(&path).unwrap();
    for key in ["max_turns", "max_provider_attempts", "max_tool_calls"] {
        text = text.replace(&format!("\\\"{key}\\\":3"), &format!("\\\"{key}\\\":6"));
    }
    text = text.replace(
        r#"\"max_usd_microunits\":0"#,
        r#"\"max_usd_microunits\":10"#,
    );
    std::fs::write(&path, text).unwrap();
    let b = fixtures::successor(&a, "State", "StateB", "b", &["carried"], false);
    let a = retained(&a);
    let b = retained(&b);
    let old = runtime(a.clone());
    let destination = runtime(b.clone());
    let old_binding = old.source_model_binding(identity()).unwrap();
    let new_binding = destination.source_model_binding(identity()).unwrap();
    let limits = ModelBudgetLimits {
        max_calls: 6,
        max_aggregate_tokens: 12,
        max_cost_micros: 10,
        ..ModelBudgetLimits::unbounded()
    };
    let old_model_policy = old
        .source_model_policy_binding(&old_binding, limits)
        .unwrap();
    let new_model_policy = destination
        .source_model_policy_binding(&new_binding, limits)
        .unwrap();
    let io = SourceIoLimits {
        max_request_bytes: old_binding.max_request_bytes(),
        max_total_request_bytes: old_binding.max_request_bytes() as u64 * 6,
        max_total_response_bytes: old_binding.max_response_bytes() as u64 * 6,
    };
    let clock = Clock;
    let cancellation = AgentCancellation::new();
    let constructions = Rc::new(Cell::new(0));
    let starts = Rc::new(Cell::new(0));
    let mut factory = counted_factory(
        documents(old.proposal_schema()),
        constructions.clone(),
        starts.clone(),
    );
    let mut quoter = ExactPolicyQuoter;
    let mut source = policy_source(
        &mut factory,
        old.proposal_schema(),
        old_binding.clone(),
        old_model_policy.clone(),
        &mut quoter,
        &cancellation,
        &clock,
    )
    .unwrap();
    let mut handler = Handler {
        calls: Vec::new(),
        wrong: false,
    };
    let mut store = Store::default();
    let run = runtime(a.clone())
        .run_live_bound_model_durable_with_io_limits(
            &mut source,
            &mut handler,
            live_policy(&old_binding),
            &clock,
            &cancellation,
            None,
            &mut store,
            &io,
        )
        .map_err(|e| e.failure().diagnostics.clone())
        .unwrap();
    assert_eq!(
        run.run().checkpoint.terminal_snapshot().unwrap().status(),
        semaprax::live_invocation::source_journal::SourceTerminalStatus::Suspend
    );
    assert_eq!(constructions.get(), 3);
    let previous_document = store.documents.last().unwrap().clone();
    let before_policy = run.run().checkpoint.policy_totals().unwrap().clone();
    let before_io = run.run().checkpoint.io_totals().unwrap().clone();
    assert_eq!(before_policy.exposure_cost_micros, 3);
    let old_policy = old
        .source_live_model_policy(&old_binding, &old_model_policy, live_policy(&old_binding))
        .unwrap();
    let new_policy = destination
        .source_live_model_policy(
            &new_binding,
            &new_model_policy,
            SourceLivePolicy {
                initial_millis: run.run().checkpoint.last_checked_millis(),
                ..live_policy(&new_binding)
            },
        )
        .unwrap();
    let task = task();
    let request = || SourceLiveMigrationRequest {
        previous: old.source_live_migration_endpoint("src/app.spx", "fixture.agent", &old_policy),
        previous_binding: run.run().checkpoint.binding(),
        previous_checkpoint: &previous_document,
        destination: destination.source_live_migration_endpoint(
            "src/app.spx",
            "fixture.agent",
            &new_policy,
        ),
        task: &task,
        migration_function: "fixture.agent.fn.migrate_b",
        max_migration_steps: 100_000,
        expected_handoff_digest: None,
    };
    let prepare = || {
        destination.prepare_live_bound_model_durable_policy_migration_with_io_limits(
            &old,
            request(),
            &old_binding,
            &old_model_policy,
            &new_binding,
            &new_model_policy,
            &io,
            &io,
        )
    };
    let widened = SourceIoLimits {
        max_total_response_bytes: io.max_total_response_bytes + 1,
        ..io.clone()
    };
    assert!(destination
        .prepare_live_bound_model_durable_policy_migration_with_io_limits(
            &old,
            request(),
            &old_binding,
            &old_model_policy,
            &new_binding,
            &new_model_policy,
            &io,
            &widened
        )
        .is_err());
    assert!(
        old.prepare_live_bound_model_durable_policy_migration_with_io_limits(
            &old,
            request(),
            &old_binding,
            &old_model_policy,
            &new_binding,
            &new_model_policy,
            &io,
            &io
        )
        .is_err(),
        "destination runtime cannot be substituted"
    );
    let prepared = prepare().unwrap();
    let mut factory = counted_factory(
        documents(destination.proposal_schema()),
        constructions.clone(),
        starts.clone(),
    );
    let mut quoter = ExactPolicyQuoter;
    let mut source = policy_source(
        &mut factory,
        destination.proposal_schema(),
        new_binding.clone(),
        new_model_policy.clone(),
        &mut quoter,
        &cancellation,
        &clock,
    )
    .unwrap();
    let mut next_handler = Handler {
        calls: Vec::new(),
        wrong: false,
    };
    let mut next_store = Store::default();
    let migrated = prepared
        .run(
            &mut source,
            &mut next_handler,
            &clock,
            &cancellation,
            &mut next_store,
        )
        .map_err(|e| e.failure().diagnostics.clone())
        .unwrap();
    let checkpoint = &migrated.run().checkpoint;
    assert_eq!(
        checkpoint.terminal_snapshot().unwrap().status(),
        semaprax::live_invocation::source_journal::SourceTerminalStatus::Complete
    );
    let after_policy = checkpoint.policy_totals().unwrap();
    assert_eq!(after_policy.calls, 6);
    assert_eq!(after_policy.next_ordinal, 6);
    assert_eq!(
        after_policy.exposure_cost_micros,
        before_policy.exposure_cost_micros + 3
    );
    assert_eq!(after_policy.reserved_context_tokens, 6);
    let after_io = checkpoint.io_totals().unwrap();
    assert!(after_io.reserved_request_bytes > before_io.reserved_request_bytes);
    assert_eq!(
        after_io.reserved_response_bytes,
        io.max_total_response_bytes
    );
    assert_eq!(checkpoint.deadline_millis(), 1_000);
    assert_eq!(constructions.get(), 6);
    assert_eq!(starts.get(), 6);
    assert_eq!(next_handler.calls.len(), 3);
    let terminal = next_store.documents.last().unwrap().clone();
    let mut factory = counted_factory(Vec::new(), constructions.clone(), starts.clone());
    let mut quoter = BadDigestQuoter;
    let mut source = policy_source(
        &mut factory,
        destination.proposal_schema(),
        new_binding.clone(),
        new_model_policy.clone(),
        &mut quoter,
        &cancellation,
        &clock,
    )
    .unwrap();
    let mut never = Handler {
        calls: Vec::new(),
        wrong: false,
    };
    let replay = prepare()
        .unwrap()
        .with_checkpoint(&terminal)
        .run(
            &mut source,
            &mut never,
            &clock,
            &cancellation,
            &mut Store::default(),
        )
        .map_err(|e| e.failure().diagnostics.clone())
        .unwrap();
    assert_eq!(replay.run().checkpoint.policy_totals(), Some(after_policy));
    assert_eq!(replay.run().checkpoint.io_totals(), Some(after_io));
    assert!(never.calls.is_empty());
    assert_eq!(constructions.get(), 6);
    assert_eq!(starts.get(), 6);
}
