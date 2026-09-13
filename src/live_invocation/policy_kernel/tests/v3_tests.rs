use super::*;
use crate::live_invocation::policy_journal_v3::PolicyJournalV3;
use crate::live_invocation::policy_kernel_v3::run_durable_byte_policy_invocation;
use crate::model_budget_policy::{AttemptKind, AttemptReservation, DurableByteBudget};

fn byte_budget(plan: &AdapterAttemptPlan, attempts: u64) -> DurableByteBudget {
    DurableByteBudget {
        max_request_bytes: u64::try_from(plan.required.max_request_bytes).unwrap(),
        max_response_bytes: u64::try_from(plan.required.max_response_bytes).unwrap(),
        max_total_input_bytes: u64::try_from(plan.required.max_request_bytes).unwrap() * attempts,
        max_total_output_bytes: u64::try_from(plan.required.max_response_bytes).unwrap() * attempts,
    }
}

fn run_v3(
    policy: &DurablePolicyBinding,
    schema: &CompiledInteractionSchema,
    request: &ModelInvocationRequest,
    plan: &AdapterAttemptPlan,
    budget: DurableByteBudget,
    clock: &StepClock,
    cancellation: &AgentCancellation,
    factory: &mut dyn ProviderAdapterFactory,
    classifier: &mut dyn FailureClassifier,
    backoff: &mut dyn RetryBackoff,
    store: &mut Store,
    recovered: Option<(&str, u64)>,
) -> DurablePolicyRun {
    run_durable_byte_policy_invocation(
        policy,
        budget,
        schema,
        request,
        plan,
        clock,
        cancellation,
        AdapterInvocationCapability::grant("v3 fixture"),
        factory,
        classifier,
        backoff,
        store,
        recovered,
    )
}

#[test]
fn v3_settles_then_terminal_replay_constructs_zero_adapters() {
    let schema = schema();
    let request = request(&schema);
    let policy = binding(&schema, 0);
    let plan = plan(&schema, &request);
    let budget = byte_budget(&plan, 1);
    let calls = Rc::new(RefCell::new(0usize));
    let count = calls.clone();
    let adapter_schema = &schema;
    let mut factory = move |provider: &str| {
        *count.borrow_mut() += 1;
        Ok(settled(adapter_schema, provider))
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
        run_v3(
            &policy,
            &schema,
            &request,
            &plan,
            budget,
            &clock,
            &cancellation,
            &mut factory,
            &mut classifier,
            &mut backoff,
            &mut store,
            None
        ),
        DurablePolicyRun::Settled(response(&schema))
    );
    let terminal = store.documents.last().unwrap().clone();
    let replay_calls = Rc::new(RefCell::new(0usize));
    let replay_count = replay_calls.clone();
    let mut replay = move |_: &str| -> Result<Box<dyn ProviderAdapter>, _> {
        *replay_count.borrow_mut() += 1;
        Err(crate::model_budget_policy::AdapterFactoryRefusal(
            "replay".into(),
        ))
    };
    assert_eq!(
        run_v3(
            &policy,
            &schema,
            &request,
            &plan,
            budget,
            &clock,
            &cancellation,
            &mut replay,
            &mut classifier,
            &mut backoff,
            &mut store,
            Some((&terminal, 2))
        ),
        DurablePolicyRun::Replayed(response(&schema))
    );
    assert_eq!(*replay_calls.borrow(), 0);
}

#[test]
fn v3_retry_byte_exhaustion_refuses_before_second_factory() {
    let schema = schema();
    let request = request(&schema);
    let policy = binding(&schema, 1);
    let plan = plan(&schema, &request);
    let budget = byte_budget(&plan, 1);
    let calls = Rc::new(RefCell::new(0usize));
    let count = calls.clone();
    let mut factory = move |provider: &str| {
        *count.borrow_mut() += 1;
        Ok(adapter(
            provider,
            vec![AdapterPoll::Failed {
                failure: crate::live_invocation::ModelFailure::CapacityExceeded,
                attempted_bytes: 0,
            }],
        ))
    };
    let clock = StepClock::new(0);
    let cancellation = AgentCancellation::new();
    let mut classifier = CapacitySafe;
    let mut backoff = crate::model_budget_policy::NoDelayBackoff;
    let mut store = Store {
        documents: Vec::new(),
        fail_commit: None,
    };
    assert!(matches!(
        run_v3(
            &policy,
            &schema,
            &request,
            &plan,
            budget,
            &clock,
            &cancellation,
            &mut factory,
            &mut classifier,
            &mut backoff,
            &mut store,
            None
        ),
        DurablePolicyRun::Refused(DurablePolicyRunError::Scheduler(SchedulerRefusal::Journal(
            _
        )))
    ));
    assert_eq!(*calls.borrow(), 1);
}

#[test]
fn v3_tampered_budget_or_plan_refuses_recovery_before_factory() {
    let schema = schema();
    let request = request(&schema);
    let policy = binding(&schema, 0);
    let plan = plan(&schema, &request);
    let budget = byte_budget(&plan, 1);
    let journal = PolicyJournalV3::new(&policy, &request, &plan, budget).unwrap();
    let document = journal.render().unwrap();
    let calls = Rc::new(RefCell::new(0usize));
    let count = calls.clone();
    let mut factory = move |_: &str| -> Result<Box<dyn ProviderAdapter>, _> {
        *count.borrow_mut() += 1;
        Err(crate::model_budget_policy::AdapterFactoryRefusal(
            "must not run".into(),
        ))
    };
    let clock = StepClock::new(0);
    let cancellation = AgentCancellation::new();
    let mut classifier = CapacitySafe;
    let mut backoff = crate::model_budget_policy::NoDelayBackoff;
    let mut store = Store {
        documents: Vec::new(),
        fail_commit: None,
    };
    let mut tampered_value: serde_json::Value = serde_json::from_str(&document).unwrap();
    tampered_value["budget"]["total_output"] = serde_json::json!(budget.max_total_output_bytes - 1);
    let tampered = serde_json::to_string(&tampered_value).unwrap();
    assert!(matches!(
        run_v3(
            &policy,
            &schema,
            &request,
            &plan,
            budget,
            &clock,
            &cancellation,
            &mut factory,
            &mut classifier,
            &mut backoff,
            &mut store,
            Some((&tampered, 1))
        ),
        DurablePolicyRun::Refused(DurablePolicyRunError::Recovery)
    ));
    let mut stale_plan = plan.clone();
    stale_plan.required.max_request_bytes += 1;
    assert!(matches!(
        run_v3(
            &policy,
            &schema,
            &request,
            &stale_plan,
            budget,
            &clock,
            &cancellation,
            &mut factory,
            &mut classifier,
            &mut backoff,
            &mut store,
            Some((&document, 1))
        ),
        DurablePolicyRun::Refused(DurablePolicyRunError::RequestBindingMismatch)
    ));
    assert_eq!(*calls.borrow(), 0);
}

#[test]
fn v3_unresolved_ack_is_uncertain_and_never_redispatches() {
    let schema = schema();
    let request = request(&schema);
    let policy = binding(&schema, 0);
    let plan = plan(&schema, &request);
    let budget = byte_budget(&plan, 1);
    let mut journal = PolicyJournalV3::new(&policy, &request, &plan, budget).unwrap();
    journal
        .append_intent(AttemptReservation {
            ordinal: 0,
            kind: AttemptKind::Fresh,
            provider_id: "primary".into(),
            reserved_context_tokens: 4,
            reserved_output_tokens: 2,
            reserved_cost_micros: 3,
        })
        .unwrap();
    let document = journal.render().unwrap();
    let calls = Rc::new(RefCell::new(0usize));
    let count = calls.clone();
    let mut factory = move |_: &str| -> Result<Box<dyn ProviderAdapter>, _> {
        *count.borrow_mut() += 1;
        Err(crate::model_budget_policy::AdapterFactoryRefusal(
            "must not run".into(),
        ))
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
        run_v3(
            &policy,
            &schema,
            &request,
            &plan,
            budget,
            &clock,
            &cancellation,
            &mut factory,
            &mut classifier,
            &mut backoff,
            &mut store,
            Some((&document, 1))
        ),
        DurablePolicyRun::Uncertain
    );
    assert_eq!(*calls.borrow(), 0);
}
