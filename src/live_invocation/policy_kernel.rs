//! Executable durable generic retry/failover route.
//!
//! This is an additive V2 route.  It uses the existing adapter scheduler for
//! every factory/start/poll boundary and only adds checkpointing around its
//! already-admitted attempts; V1 generic journals are neither decoded nor
//! rewritten here.

use crate::agent_interaction_schema::CompiledInteractionSchema;
use crate::agent_lifecycle::CheckpointStore;
use crate::agent_runtime::AgentCancellation;
use crate::live_invocation::budget::InvocationClock;
use crate::live_invocation::model_invoke::ModelInvocationRequest;
use crate::live_invocation::persistence::policy::PolicyCheckpointJournal;
use crate::live_invocation::policy_journal::{PolicyJournal, PolicyRecovery};
use crate::model_budget_policy::retry::{
    AdapterAttemptPlan, FailureClassifier, ProviderAdapterFactory, RetryBackoff, RetryCursor,
    RetryFailoverOutcome, RetryFailoverScheduler, SchedulerRefusal,
};
use crate::model_budget_policy::DurablePolicyBinding;
use crate::provider_adapter_sdk::AdapterInvocationCapability;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DurablePolicyRun {
    /// The exact settled response is replayed from the journal with no host
    /// factory or adapter call.
    Replayed(Vec<u8>),
    /// A fresh or safely continued execution settled and was checkpointed.
    Settled(Vec<u8>),
    /// Recovery found an unresolved intent or an unsafe result.  A caller may
    /// reconcile externally, but cannot ask this route to retry it.
    Uncertain,
    Refused(DurablePolicyRunError),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DurablePolicyRunError {
    RequestBindingMismatch,
    DeadlineExceeded,
    Recovery,
    Scheduler(SchedulerRefusal),
}

#[allow(clippy::too_many_arguments)]
pub fn run_durable_policy_invocation(
    binding: &DurablePolicyBinding,
    schema: &CompiledInteractionSchema,
    request: &ModelInvocationRequest,
    plan: &AdapterAttemptPlan,
    clock: &dyn InvocationClock,
    cancellation: &AgentCancellation,
    capability: AdapterInvocationCapability,
    factory: &mut dyn ProviderAdapterFactory,
    classifier: &mut dyn FailureClassifier,
    backoff: &mut dyn RetryBackoff,
    store: &mut dyn CheckpointStore,
    recovered: Option<(&str, u64)>,
) -> DurablePolicyRun {
    if request.deployment_binding != binding.deployment_policy()
        || !binding.request_matches(schema, request)
    {
        return DurablePolicyRun::Refused(DurablePolicyRunError::RequestBindingMismatch);
    }
    let (journal, generation, reservations, cursor) = match recovered {
        None => (
            PolicyJournal::new(binding, request, plan),
            0,
            Vec::new(),
            RetryCursor::FRESH,
        ),
        Some((document, generation)) => {
            match PolicyJournal::recover(document, binding, request, plan) {
                Ok((_, PolicyRecovery::Settled(response))) => {
                    if schema.decode(&response).is_err() {
                        return DurablePolicyRun::Refused(DurablePolicyRunError::Recovery);
                    }
                    return DurablePolicyRun::Replayed(response);
                }
                Ok((_, PolicyRecovery::Uncertain)) => return DurablePolicyRun::Uncertain,
                Ok((
                    journal,
                    PolicyRecovery::Continue {
                        reservations,
                        cursor,
                    },
                )) => (journal, generation, reservations, cursor),
                Err(_) => return DurablePolicyRun::Refused(DurablePolicyRunError::Recovery),
            }
        }
    };
    if !binding.check_clock(clock) {
        return DurablePolicyRun::Refused(DurablePolicyRunError::DeadlineExceeded);
    }
    let mut checkpoint = if generation == 0 {
        PolicyCheckpointJournal::new(store, journal)
    } else {
        PolicyCheckpointJournal::resume(store, journal, generation)
    };
    let scheduler = if reservations.is_empty() {
        RetryFailoverScheduler::new(
            binding.limits(),
            binding.policy().clone(),
            binding.deadline_millis(),
            clock,
            cancellation,
            capability,
            factory,
        )
    } else {
        RetryFailoverScheduler::resume(
            binding.limits(),
            binding.policy().clone(),
            binding.deadline_millis(),
            clock,
            cancellation,
            capability,
            factory,
            &reservations,
        )
    };
    let mut scheduler = match scheduler {
        Ok(scheduler) => scheduler,
        Err(refusal) => {
            return DurablePolicyRun::Refused(DurablePolicyRunError::Scheduler(refusal))
        }
    };
    let run = match binding.model_selections() {
        Some(models) => scheduler.run_compiled_durable_from(
            schema,
            request,
            plan,
            models,
            classifier,
            backoff,
            cursor,
            Some(&mut checkpoint),
        ),
        None => scheduler.run_compiled_from(
            schema,
            request,
            plan,
            classifier,
            backoff,
            cursor,
            Some(&mut checkpoint),
        ),
    };
    match run.outcome {
        RetryFailoverOutcome::Settled { response_bytes, .. } => {
            DurablePolicyRun::Settled(response_bytes)
        }
        RetryFailoverOutcome::Failed { result, .. } => match result {
            crate::model_budget_policy::retry::AdapterAttemptResult::Failed {
                classification,
                ..
            } if !crate::model_budget_policy::retry_is_permitted(classification) => {
                DurablePolicyRun::Uncertain
            }
            crate::model_budget_policy::retry::AdapterAttemptResult::Failed {
                refusal: Some(refusal),
                ..
            } => DurablePolicyRun::Refused(DurablePolicyRunError::Scheduler(refusal)),
            _ => DurablePolicyRun::Uncertain,
        },
        RetryFailoverOutcome::Refused { refusal, .. } => {
            DurablePolicyRun::Refused(DurablePolicyRunError::Scheduler(refusal))
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{
        cell::RefCell,
        collections::VecDeque,
        rc::Rc,
        sync::atomic::{AtomicU64, Ordering},
    };

    use super::*;
    use crate::agent_interaction_schema::compile_agent_interaction_schema;
    use crate::agent_lifecycle::CheckpointStoreError;
    use crate::live_invocation::fixture::StepClock;
    use crate::live_invocation::{LiveInvocationId, LiveInvocationSeed};
    use crate::model_budget_policy::{
        intersect, AttemptOutcomeClass, DurablePolicyBinding, ModelBudgetLimits, ProviderPolicy,
        ProviderSlot,
    };
    use crate::provider_adapter_sdk::fixture_adapters::{
        base_capabilities, usage, ScriptedAdapter,
    };
    use crate::provider_adapter_sdk::{
        AdapterEvent, AdapterPoll, AdapterSettlement, ProviderAdapter,
    };

    const SOURCE: &str = "module test.durable_policy;\n\n@id(\"answer.type\")\nrecord Answer {\n    @id(\"answer.note\")\n    note: string,\n}\n\n@id(\"app.main\")\nfn main() -> i64 { 0 }\n";
    static NEXT_FILE: AtomicU64 = AtomicU64::new(0);

    struct Store {
        documents: Vec<String>,
        fail_commit: Option<usize>,
    }
    impl CheckpointStore for Store {
        fn commit(&mut self, _: u64, document: &str) -> Result<(), CheckpointStoreError> {
            let next = self.documents.len() + 1;
            if self.fail_commit == Some(next) {
                return Err(CheckpointStoreError);
            }
            self.documents.push(document.to_owned());
            Ok(())
        }
    }

    struct CapacitySafe;
    impl FailureClassifier for CapacitySafe {
        fn classify(
            &mut self,
            _: &str,
            _: crate::live_invocation::ModelFailure,
        ) -> AttemptOutcomeClass {
            AttemptOutcomeClass::ProviderReportedRetryable
        }
    }

    fn schema() -> CompiledInteractionSchema {
        let path = std::env::temp_dir().join(format!(
            "semaprax-durable-policy-{}-{}.spx",
            std::process::id(),
            NEXT_FILE.fetch_add(1, Ordering::Relaxed),
        ));
        std::fs::write(&path, SOURCE).unwrap();
        let schema = compile_agent_interaction_schema(&path, "answer.type").unwrap();
        std::fs::remove_file(path).unwrap();
        schema
    }

    fn response(schema: &CompiledInteractionSchema) -> Vec<u8> {
        format!(
            "{{\"schema\":\"semaprax.agent-interaction-value.v1\",\"root_type_id\":\"answer.type\",\"schema_digest\":\"{}\",\"value\":{{\"fields\":{{\"answer.note\":\"ok\"}}}}}}\n",
            schema.schema().digest(),
        ).into_bytes()
    }

    fn request(schema: &CompiledInteractionSchema) -> ModelInvocationRequest {
        ModelInvocationRequest {
            turn: 0,
            task: b"task".to_vec(),
            observation: b"observation".to_vec(),
            proposal_grammar_digest: schema.schema().digest().to_owned(),
            deployment_binding: "sha256:test-policy".into(),
            max_response_bytes: 1024,
            effective_budget: 1,
        }
    }

    fn binding(schema: &CompiledInteractionSchema, retries: u32) -> DurablePolicyBinding {
        let mut limits = ModelBudgetLimits::unbounded();
        limits.max_calls = 3;
        limits.max_retries = retries;
        limits.max_providers = 1;
        limits.max_context_tokens = 8;
        limits.max_output_tokens = 8;
        limits.max_aggregate_tokens = 32;
        limits.max_cost_micros = 20;
        let limits = intersect(limits, limits, limits).unwrap();
        DurablePolicyBinding::fixture(
            LiveInvocationId::derive(&LiveInvocationSeed {
                program_root: "sha256:program".into(),
                deployment_policy: "sha256:test-policy".into(),
                task: b"task".to_vec(),
                budget: 1,
                interaction_schema_digest: schema.schema().digest().to_owned(),
                approved_providers: vec!["primary".into(), "fallback".into()],
            }),
            ProviderPolicy::new(vec![
                ProviderSlot::authorized("primary"),
                ProviderSlot::authorized("fallback"),
            ]),
            limits,
            b"task",
            schema.schema().digest(),
            1,
        )
    }

    fn plan(
        schema: &CompiledInteractionSchema,
        request: &ModelInvocationRequest,
    ) -> AdapterAttemptPlan {
        AdapterAttemptPlan::for_compiled(schema, request, 4, 2, 3, 4).unwrap()
    }

    fn adapter(provider: &str, script: Vec<AdapterPoll>) -> Box<dyn ProviderAdapter> {
        let mut caps = base_capabilities(provider, true);
        caps.provider_profile = provider.to_owned();
        caps.retryable_failure_classes
            .push(AttemptOutcomeClass::ProviderReportedRetryable);
        Box::new(ScriptedAdapter::new(caps, script, true))
    }

    fn settled(schema: &CompiledInteractionSchema, provider: &str) -> Box<dyn ProviderAdapter> {
        let response = response(schema);
        adapter(
            provider,
            vec![
                AdapterPoll::Event(AdapterEvent::Delta(response.clone())),
                AdapterPoll::Event(AdapterEvent::Completed),
                AdapterPoll::Settled(AdapterSettlement {
                    response_bytes: response,
                    usage: usage(4, 2, 3),
                }),
            ],
        )
    }

    #[test]
    fn durable_safe_retry_checkpoints_every_ack_and_replays_without_a_factory() {
        let schema = schema();
        let request = request(&schema);
        let policy = binding(&schema, 1);
        let queued = Rc::new(RefCell::new(VecDeque::from(vec![
            adapter(
                "primary",
                vec![AdapterPoll::Failed {
                    failure: crate::live_invocation::ModelFailure::CapacityExceeded,
                    attempted_bytes: 0,
                }],
            ),
            settled(&schema, "primary"),
        ])));
        let calls = Rc::new(RefCell::new(Vec::new()));
        let queue = queued.clone();
        let call_trace = calls.clone();
        let mut factory = move |provider: &str| {
            call_trace.borrow_mut().push(provider.to_owned());
            queue
                .borrow_mut()
                .pop_front()
                .ok_or_else(|| crate::model_budget_policy::AdapterFactoryRefusal(provider.into()))
        };
        let clock = StepClock::new(0);
        let cancellation = AgentCancellation::new();
        let mut classifier = CapacitySafe;
        let mut backoff = crate::model_budget_policy::NoDelayBackoff;
        let mut store = Store {
            documents: Vec::new(),
            fail_commit: None,
        };
        let run = run_durable_policy_invocation(
            &policy,
            &schema,
            &request,
            &plan(&schema, &request),
            &clock,
            &cancellation,
            AdapterInvocationCapability::grant("fixture"),
            &mut factory,
            &mut classifier,
            &mut backoff,
            &mut store,
            None,
        );
        assert_eq!(run, DurablePolicyRun::Settled(response(&schema)));
        assert_eq!(calls.borrow().as_slice(), ["primary", "primary"]);
        assert_eq!(
            store.documents.len(),
            4,
            "intent/outcome ACKs precede both calls"
        );
        assert!(store.documents[0].contains("\"context\":4"));
        assert!(store.documents[0].contains("\"cost\":3"));
        let terminal = store.documents.last().unwrap().clone();
        let replay_calls = Rc::new(RefCell::new(0usize));
        let replay_count = replay_calls.clone();
        let mut replay_factory = move |_: &str| -> Result<Box<dyn ProviderAdapter>, _> {
            *replay_count.borrow_mut() += 1;
            Err(crate::model_budget_policy::AdapterFactoryRefusal(
                "must_not_run".into(),
            ))
        };
        assert_eq!(
            run_durable_policy_invocation(
                &policy,
                &schema,
                &request,
                &plan(&schema, &request),
                &clock,
                &cancellation,
                AdapterInvocationCapability::grant("fixture"),
                &mut replay_factory,
                &mut classifier,
                &mut backoff,
                &mut store,
                Some((&terminal, 4)),
            ),
            DurablePolicyRun::Replayed(response(&schema)),
        );
        assert_eq!(*replay_calls.borrow(), 0);
    }

    #[test]
    fn intent_checkpoint_failure_and_stale_or_uncertain_recovery_never_construct_a_factory() {
        let schema = schema();
        let request = request(&schema);
        let policy = binding(&schema, 0);
        let clock = StepClock::new(0);
        let cancellation = AgentCancellation::new();
        let mut classifier = CapacitySafe;
        let mut backoff = crate::model_budget_policy::NoDelayBackoff;
        let calls = Rc::new(RefCell::new(0usize));
        let count = calls.clone();
        let mut factory = move |_: &str| -> Result<Box<dyn ProviderAdapter>, _> {
            *count.borrow_mut() += 1;
            Err(crate::model_budget_policy::AdapterFactoryRefusal(
                "unexpected".into(),
            ))
        };
        let mut failed_store = Store {
            documents: Vec::new(),
            fail_commit: Some(1),
        };
        assert!(matches!(
            run_durable_policy_invocation(
                &policy,
                &schema,
                &request,
                &plan(&schema, &request),
                &clock,
                &cancellation,
                AdapterInvocationCapability::grant("fixture"),
                &mut factory,
                &mut classifier,
                &mut backoff,
                &mut failed_store,
                None,
            ),
            DurablePolicyRun::Refused(DurablePolicyRunError::Scheduler(SchedulerRefusal::Journal(
                _
            )))
        ));
        assert_eq!(*calls.borrow(), 0);
        let mut journal = PolicyJournal::new(&policy, &request, &plan(&schema, &request));
        journal
            .append_intent(crate::model_budget_policy::AttemptReservation {
                ordinal: 0,
                kind: crate::model_budget_policy::AttemptKind::Fresh,
                provider_id: "primary".into(),
                reserved_context_tokens: 4,
                reserved_output_tokens: 2,
                reserved_cost_micros: 3,
            })
            .unwrap();
        let unresolved = journal.render();
        let mut sink = Store {
            documents: Vec::new(),
            fail_commit: None,
        };
        assert_eq!(
            run_durable_policy_invocation(
                &policy,
                &schema,
                &request,
                &plan(&schema, &request),
                &clock,
                &cancellation,
                AdapterInvocationCapability::grant("fixture"),
                &mut factory,
                &mut classifier,
                &mut backoff,
                &mut sink,
                Some((&unresolved, 1)),
            ),
            DurablePolicyRun::Uncertain,
        );
        let stale = unresolved.replacen("sha256:test-binding", "sha256:stale-binding", 1);
        assert!(matches!(
            run_durable_policy_invocation(
                &policy,
                &schema,
                &request,
                &plan(&schema, &request),
                &clock,
                &cancellation,
                AdapterInvocationCapability::grant("fixture"),
                &mut factory,
                &mut classifier,
                &mut backoff,
                &mut sink,
                Some((&stale, 1)),
            ),
            DurablePolicyRun::Refused(DurablePolicyRunError::Recovery)
        ));
        assert_eq!(*calls.borrow(), 0);
    }

    #[test]
    fn original_absolute_deadline_refuses_before_factory_without_rebasing() {
        let schema = schema();
        let request = request(&schema);
        let original = binding(&schema, 0);
        let policy = DurablePolicyBinding::fixture_with_deadline(original, 5);
        let clock = StepClock::new(5);
        let cancellation = AgentCancellation::new();
        let mut classifier = CapacitySafe;
        let mut backoff = crate::model_budget_policy::NoDelayBackoff;
        let calls = Rc::new(RefCell::new(0usize));
        let count = calls.clone();
        let mut factory = move |_: &str| -> Result<Box<dyn ProviderAdapter>, _> {
            *count.borrow_mut() += 1;
            Err(crate::model_budget_policy::AdapterFactoryRefusal(
                "unexpected".into(),
            ))
        };
        let mut store = Store {
            documents: Vec::new(),
            fail_commit: None,
        };
        assert_eq!(
            run_durable_policy_invocation(
                &policy,
                &schema,
                &request,
                &plan(&schema, &request),
                &clock,
                &cancellation,
                AdapterInvocationCapability::grant("fixture"),
                &mut factory,
                &mut classifier,
                &mut backoff,
                &mut store,
                None,
            ),
            DurablePolicyRun::Refused(DurablePolicyRunError::DeadlineExceeded),
        );
        assert_eq!(*calls.borrow(), 0);
    }

    #[test]
    fn safe_failure_with_no_retry_budget_fails_over_in_the_checked_provider_order() {
        let schema = schema();
        let request = request(&schema);
        let policy = binding(&schema, 0);
        let queued = Rc::new(RefCell::new(VecDeque::from(vec![
            adapter(
                "primary",
                vec![AdapterPoll::Failed {
                    failure: crate::live_invocation::ModelFailure::CapacityExceeded,
                    attempted_bytes: 0,
                }],
            ),
            settled(&schema, "fallback"),
        ])));
        let trace = Rc::new(RefCell::new(Vec::new()));
        let queue = queued.clone();
        let observed = trace.clone();
        let mut factory = move |provider: &str| {
            observed.borrow_mut().push(provider.to_owned());
            queue
                .borrow_mut()
                .pop_front()
                .ok_or_else(|| crate::model_budget_policy::AdapterFactoryRefusal(provider.into()))
        };
        let clock = StepClock::new(0);
        let cancellation = AgentCancellation::new();
        let mut classifier = CapacitySafe;
        let mut backoff = crate::model_budget_policy::NoDelayBackoff;
        let mut store = Store {
            documents: Vec::new(),
            fail_commit: None,
        };
        assert_eq!(
            run_durable_policy_invocation(
                &policy,
                &schema,
                &request,
                &plan(&schema, &request),
                &clock,
                &cancellation,
                AdapterInvocationCapability::grant("fixture"),
                &mut factory,
                &mut classifier,
                &mut backoff,
                &mut store,
                None,
            ),
            DurablePolicyRun::Settled(response(&schema)),
        );
        assert_eq!(trace.borrow().as_slice(), ["primary", "fallback"]);
    }

    mod v3_tests;
}
