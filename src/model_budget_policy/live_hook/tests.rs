use super::*;
use crate::live_invocation::{
    fixture::*,
    identity::{LiveInvocationId, LiveInvocationSeed},
    kernel::*,
    model_invoke::*,
};
use crate::model_budget_policy::{intersect, ModelBudgetLimits};

struct Quote {
    stale: bool,
}
impl ModelAttemptQuoter for Quote {
    fn quote(
        &mut self,
        request: &ModelInvocationRequest,
    ) -> Result<ModelAttemptQuote, BudgetRefusal> {
        Ok(ModelAttemptQuote {
            request_digest: if self.stale {
                "stale".into()
            } else {
                request.digest()
            },
            context_tokens: 8,
            output_tokens: 4,
            estimated_cost_micros: 3,
        })
    }
}
fn limits(calls: u32) -> EffectiveModelBudget {
    let mut limits = ModelBudgetLimits::unbounded();
    limits.max_calls = calls;
    limits.max_latency_millis = 100;
    intersect(limits, limits, limits).unwrap()
}
fn request() -> ModelInvocationRequest {
    ModelInvocationRequest {
        turn: 0,
        task: vec![],
        observation: vec![],
        proposal_grammar_digest: "grammar".into(),
        deployment_binding: "policy".into(),
        max_response_bytes: 64,
        effective_budget: 10,
    }
}
#[test]
fn actual_kernel_stops_second_dispatch_and_receipts_preserve_policy_refusal() {
    let identity = LiveInvocationId::derive(&LiveInvocationSeed {
        program_root: "root".into(),
        deployment_policy: "policy".into(),
        task: vec![],
        budget: 100,
        interaction_schema_digest: "grammar".into(),
        approved_providers: vec!["fixture".into()],
    });
    let config = LiveInvocationConfig {
        identity: &identity,
        task: &[],
        deployment_binding: "policy",
        interaction_schema_digest: "grammar",
        max_turns: 2,
        max_response_bytes: 4096,
        requested_budget_per_turn: 10,
    };
    let clock = StepClock::new(0);
    let cancellation = AgentCancellation::new();
    let mut inner = FixtureBudgetHook::new(10);
    let mut quoter = Quote { stale: false };
    let mut budget = LiveModelPolicyHook::new(
        limits(1),
        ProviderSlot::authorized("fixture"),
        0,
        &clock,
        &mut inner,
        &mut quoter,
        &cancellation,
    )
    .unwrap();
    let mut handler = FixtureModelHandler::scripted(vec![ModelInvocationOutcome::Settled(
        fixture_response(0, "ok"),
    )]);
    let capability = ModelInvokeCapability::grant("test");
    let mut decoder = FixtureProposalDecoder::new("grammar");
    let mut gate = FixtureAuthorizationGate::new(2);
    let mut observer = FixtureObserver;
    let mut policy = FixturePolicy { total_turns: 2 };
    let run = run_live_invocation(
        &config,
        vec![],
        &mut LiveInvocationHandlers {
            capability: &capability,
            handler: &mut handler,
            decoder: &mut decoder,
            gate: &mut gate,
            budget: &mut budget,
            observer: &mut observer,
            policy: &mut policy,
            effect: None,
            sink: None,
        },
        &cancellation,
    )
    .unwrap();
    assert_eq!(run.dispatched, 1);
    assert_eq!(handler.calls, 1);
    assert_eq!(budget.ledger().calls_committed(), 1);
    assert_eq!(budget.ledger().aggregate_tokens_committed(), 12);
    assert_eq!(budget.ledger().cost_committed_micros(), 3);
    assert!(
        budget.ledger().usage().is_empty(),
        "bytes must not masquerade as observed token usage"
    );
    let receipts = run.model_call_receipts(&identity).unwrap();
    assert_eq!(receipts.len(), 2);
    assert!(receipts[1].render().contains(POLICY_EXHAUSTED));
}

#[test]
fn stale_quote_and_cancellation_never_reserve() {
    let clock = StepClock::new(0);
    let cancellation = AgentCancellation::new();
    let mut inner = FixtureBudgetHook::new(10);
    let mut quoter = Quote { stale: true };
    let mut hook = LiveModelPolicyHook::new(
        limits(3),
        ProviderSlot::authorized("fixture"),
        0,
        &clock,
        &mut inner,
        &mut quoter,
        &cancellation,
    )
    .unwrap();
    assert_eq!(hook.reserve(&request()).unwrap_err().0, INVALID_QUOTE);
    assert!(hook.reservations().is_empty());
    cancellation.cancel();
    assert_eq!(hook.reserve(&request()).unwrap_err().0, "cancelled");
    assert_eq!(hook.ledger().calls_committed(), 0);
}

#[test]
fn inner_refusal_never_refunds_and_deadline_stays_original() {
    struct Clock(std::cell::Cell<i64>);
    impl InvocationClock for Clock {
        fn now_millis(&self) -> i64 {
            self.0.get()
        }
    }
    struct Refuse;
    impl InvocationBudgetHook for Refuse {
        fn reserve(&mut self, _: &ModelInvocationRequest) -> Result<ReservedBudget, BudgetRefusal> {
            Err(BudgetRefusal("budget_exhausted".into()))
        }
        fn record(&mut self, _: &InvocationUsage) {}
    }
    let clock = Clock(std::cell::Cell::new(0));
    let cancellation = AgentCancellation::new();
    let mut inner = Refuse;
    let mut quoter = Quote { stale: false };
    let mut hook = LiveModelPolicyHook::new(
        limits(3),
        ProviderSlot::authorized("fixture"),
        0,
        &clock,
        &mut inner,
        &mut quoter,
        &cancellation,
    )
    .unwrap();
    assert_eq!(hook.reserve(&request()).unwrap_err().0, "budget_exhausted");
    assert_eq!(hook.ledger().calls_committed(), 1);
    assert_eq!(hook.reservations()[0].request_digest, request().digest());
    clock.0.set(100);
    assert_eq!(hook.check_deadline().unwrap_err().0, DEADLINE_EXCEEDED);
    assert_eq!(hook.reserve(&request()).unwrap_err().0, DEADLINE_EXCEEDED);
    assert_eq!(hook.ledger().calls_committed(), 1);
}
