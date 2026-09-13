use super::*;
use semaprax::agent_runtime_v2::{SourceModelBinding, SourceModelPolicyBinding};

fn policy_source<'a>(
    factory: &'a mut dyn SourceAdapterFactory,
    schema: &'a semaprax::agent_proposal::CompiledAgentProposalSchema,
    binding: SourceModelBinding,
    policy_binding: SourceModelPolicyBinding,
    quoter: &'a mut dyn SourceModelAttemptQuoter,
    cancellation: &'a AgentCancellation,
    clock: &'a Clock,
) -> Result<StreamingSourceProposalAdapter<'a>, Vec<semaprax::diagnostic::Diagnostic>> {
    StreamingSourceProposalAdapter::new_bound_checkpointed_with_policy(
        factory,
        AdapterInvocationCapability::grant("durable quoted policy fixture"),
        schema,
        binding.clone(),
        binding.invocation_capability(),
        checkpoint_policy(&binding),
        policy_binding,
        quoter,
        cancellation,
        clock,
        1_000,
    )
}

#[test]
fn durable_policy_reserves_aggregate_tokens_and_replays_terminal_without_requoting() {
    let fixture = typed_fixture();
    // Give the positive token rows explicit source cost headroom; the
    // invocation cost-zero row still proves observed overage stops later work.
    let path = fixture.0.join("src/app.spx");
    let source = std::fs::read_to_string(&path).unwrap();
    let priced = source.replace(
        r#"\"max_usd_microunits\":0"#,
        r#"\"max_usd_microunits\":10"#,
    );
    assert_ne!(priced, source);
    std::fs::write(&path, priced).unwrap();
    with_authenticated_project(&fixture.0.join("semaprax.toml"), |snapshot| {
        let project = snapshot.retain_revision();
        let root = project.program_root()?;
        let compiled = compile_source_agent_lifecycle_v2(
            project.sources()[0].source(),
            project.sources()[0].path(),
            "fixture.agent",
            "fixture.agent.type.step",
        )?;
        let schema = compiled.proposal_schema();
        for (aggregate, cost_limit, latency, expected_calls) in [
            (0, i64::MAX, i64::MAX, 0),
            (5, i64::MAX, i64::MAX, 2),
            (6, i64::MAX, i64::MAX, 3),
            (6, 0, i64::MAX, 1),
            (6, i64::MAX, 0, 0),
        ] {
            let runtime = bind(project.clone(), &root)?;
            let binding = runtime.source_model_binding(identity())?;
            let io_limits = semaprax::live_invocation::source_journal::SourceIoLimits {
                max_request_bytes: binding.max_request_bytes(),
                max_total_request_bytes: binding.max_request_bytes() as u64 * 3,
                max_total_response_bytes: binding.max_response_bytes() as u64 * 3,
            };
            let mut limits = ModelBudgetLimits::unbounded();
            limits.max_aggregate_tokens = aggregate;
            limits.max_cost_micros = cost_limit;
            limits.max_latency_millis = latency;
            let model_policy = runtime.source_model_policy_binding(&binding, limits)?;
            let constructions = Rc::new(Cell::new(0));
            let starts = Rc::new(Cell::new(0));
            let mut factory =
                counted_factory(documents(schema), constructions.clone(), starts.clone());
            let cancellation = AgentCancellation::new();
            let clock = Clock;
            let mut quoter = ExactPolicyQuoter;
            let mut source = policy_source(
                &mut factory,
                schema,
                binding.clone(),
                model_policy,
                &mut quoter,
                &cancellation,
                &clock,
            )?;
            let mut handler = Handler {
                calls: Vec::new(),
                wrong: false,
            };
            let mut store = Store::default();
            let result = runtime.run_live_bound_model_durable_with_io_limits(
                &mut source,
                &mut handler,
                policy(&binding),
                &clock,
                &cancellation,
                None,
                &mut store,
                &io_limits,
            );
            assert_eq!(
                constructions.get(),
                expected_calls,
                "aggregate {aggregate}; diagnostics={:?}",
                result
                    .as_ref()
                    .err()
                    .map(|failure| &failure.failure().diagnostics)
            );
            assert_eq!(starts.get(), expected_calls, "aggregate {aggregate}");
            assert_eq!(handler.calls.len(), expected_calls);
            if expected_calls < 3 {
                assert!(
                    result.is_err(),
                    "insufficient aggregate token or observed cost capacity must stop"
                );
                if expected_calls > 0 {
                    let failure = result.err().unwrap();
                    let totals = failure
                        .failure()
                        .checkpoint
                        .as_ref()
                        .unwrap()
                        .policy_totals()
                        .unwrap();
                    assert_eq!(totals.calls, expected_calls as u32);
                    assert_eq!(
                        totals.reserved_context_tokens + totals.reserved_output_tokens,
                        expected_calls as u64 * 2
                    );
                }
                continue;
            }
            let complete = result.map_err(|failure| failure.failure().diagnostics.clone())?;
            let totals = complete.run().checkpoint.policy_totals().unwrap();
            assert_eq!(totals.calls, 3);
            assert_eq!(totals.reserved_context_tokens, 3);
            assert_eq!(totals.reserved_output_tokens, 3);
            assert_eq!(totals.observed_context_tokens, 3);
            assert_eq!(totals.observed_output_tokens, 3);
            assert_eq!(
                totals.exposure_cost_micros, 3,
                "observed cost above zero quote is retained"
            );
            assert_eq!(totals.next_ordinal, 3);
            let io = complete.run().checkpoint.io_totals().unwrap();
            assert!(io.reserved_request_bytes > 0);
            assert_eq!(
                io.reserved_response_bytes,
                io_limits.max_total_response_bytes
            );
            assert!(io.observed_response_bytes > 0);
            assert_eq!(io.unknown_response_reservation_bytes, 0);
            let retained = store.documents.last().unwrap().clone();
            assert!(retained.contains("policy_attempt_intent"));

            // A hostile quoter proves recovery does not silently re-price the
            // acknowledged prefix. Neither provider nor typed effect can run.
            let runtime = bind(project.clone(), &root)?;
            let binding = runtime.source_model_binding(identity())?;
            let model_policy = runtime.source_model_policy_binding(&binding, limits)?;
            let mut factory = counted_factory(Vec::new(), constructions.clone(), starts.clone());
            let mut bad_quoter = BadDigestQuoter;
            let mut source = policy_source(
                &mut factory,
                schema,
                binding.clone(),
                model_policy,
                &mut bad_quoter,
                &cancellation,
                &clock,
            )?;
            let mut never = Handler {
                calls: Vec::new(),
                wrong: false,
            };
            let replay = runtime
                .run_live_bound_model_durable_with_io_limits(
                    &mut source,
                    &mut never,
                    policy(&binding),
                    &clock,
                    &cancellation,
                    Some(&retained),
                    &mut Store::default(),
                    &io_limits,
                )
                .map_err(|failure| failure.failure().diagnostics.clone())?;
            assert_eq!(replay.run().checkpoint.policy_totals().unwrap(), totals);
            assert!(never.calls.is_empty());
            assert_eq!(constructions.get(), 3);
            assert_eq!(starts.get(), 3);
        }
        Ok(())
    })
    .unwrap();
}

#[derive(Default)]
struct LostPolicyAck {
    document: Option<String>,
}
impl CheckpointStore for LostPolicyAck {
    fn commit(&mut self, _: u64, document: &str) -> Result<(), CheckpointStoreError> {
        self.document = Some(document.to_owned());
        if document.contains("\"kind\":\"policy_attempt_intent\"") {
            return Err(CheckpointStoreError);
        }
        Ok(())
    }
}

#[test]
fn durable_policy_unacknowledged_intent_retains_reservation_without_redispatch() {
    let fixture = typed_fixture();
    with_authenticated_project(&fixture.0.join("semaprax.toml"), |snapshot| {
        let project = snapshot.retain_revision();
        let root = project.program_root()?;
        let compiled = compile_source_agent_lifecycle_v2(
            project.sources()[0].source(),
            project.sources()[0].path(),
            "fixture.agent",
            "fixture.agent.type.step",
        )?;
        let schema = compiled.proposal_schema();
        let clock = Clock;
        let cancellation = AgentCancellation::new();
        let calls = Rc::new(Cell::new(0));
        let starts = Rc::new(Cell::new(0));
        let mut retained = None;
        for recovering in [false, true] {
            let runtime = bind(project.clone(), &root)?;
            let binding = runtime.source_model_binding(identity())?;
            let model_policy =
                runtime.source_model_policy_binding(&binding, ModelBudgetLimits::unbounded())?;
            let mut factory = counted_factory(Vec::new(), calls.clone(), starts.clone());
            let mut quoter = ExactPolicyQuoter;
            let mut source = policy_source(
                &mut factory,
                schema,
                binding.clone(),
                model_policy,
                &mut quoter,
                &cancellation,
                &clock,
            )?;
            let mut handler = Handler {
                calls: Vec::new(),
                wrong: false,
            };
            let mut store = LostPolicyAck::default();
            let result = runtime.run_live_bound_model_durable(
                &mut source,
                &mut handler,
                policy(&binding),
                &clock,
                &cancellation,
                retained.as_deref(),
                &mut store,
            );
            assert!(result.is_err());
            assert_eq!(calls.get(), 0);
            assert_eq!(starts.get(), 0);
            assert!(handler.calls.is_empty());
            if recovering {
                assert!(
                    store.document.is_none(),
                    "uncertain recovery cannot publish a fresh attempt"
                );
            } else {
                let document = store
                    .document
                    .expect("intent offered to store before dispatch");
                assert!(document.contains("\"policy_ordinal\":0"));
                assert!(document.contains("\"reserved_context_tokens\":1"));
                retained = Some(document);
            }
        }
        Ok(())
    })
    .unwrap();
}

#[path = "policy_v6/migration.rs"]
mod migration;
