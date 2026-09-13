use super::*;

use crate::agent_lifecycle::CheckpointStoreError;
use crate::live_invocation::fixture::{
    fixture_response, FixtureAuthorizationGate, FixtureBudgetHook, FixtureModelHandler,
    FixtureObserver, FixturePolicy, FixtureProposalDecoder,
};
use crate::live_invocation::identity::{LiveInvocationId, LiveInvocationSeed};
use crate::live_invocation::kernel::LiveInvocationConfig;
use crate::live_invocation::model_invoke::{
    BudgetRefusal, InvocationBudgetHook, InvocationUsage, ModelInvocationOutcome,
    ModelInvocationRequest, ModelInvokeCapability, ReservedBudget,
};

const SCHEMA: &str = "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";

#[derive(Default)]
struct Store {
    documents: Vec<String>,
    calls: usize,
    fail_from: Option<usize>,
}

struct ExactBudget(FixtureBudgetHook);

impl InvocationBudgetHook for ExactBudget {
    fn check_deadline(&self) -> Result<(), BudgetRefusal> {
        self.0.check_deadline()
    }

    fn reserve(
        &mut self,
        request: &ModelInvocationRequest,
    ) -> Result<ReservedBudget, BudgetRefusal> {
        self.0.reserve(request)
    }

    fn record(&mut self, usage: &InvocationUsage) {
        self.0.record(usage);
    }
}

impl PricedWorkBudgetHook for ExactBudget {
    fn quote_priced_reservation(
        &self,
        _request: &ModelInvocationRequest,
    ) -> Result<ReservedBudget, BudgetRefusal> {
        if self.0.per_turn_amount < 0 {
            return Err(BudgetRefusal("fixture_refuses_all".to_owned()));
        }
        Ok(ReservedBudget {
            amount: self.0.per_turn_amount,
        })
    }
}

impl crate::agent_lifecycle::CheckpointStore for Store {
    fn commit(&mut self, _: u64, document: &str) -> Result<(), CheckpointStoreError> {
        self.calls += 1;
        if self.fail_from == Some(self.calls) {
            return Err(CheckpointStoreError);
        }
        self.documents.push(document.to_owned());
        Ok(())
    }
}

fn identity() -> LiveInvocationId {
    identity_for(b"priced task")
}

fn identity_for(task: &[u8]) -> LiveInvocationId {
    LiveInvocationId::derive(&LiveInvocationSeed {
        program_root: "sha256:".to_owned() + &"a".repeat(64),
        deployment_policy: "sha256:".to_owned() + &"b".repeat(64),
        task: task.to_vec(),
        budget: 100,
        interaction_schema_digest: SCHEMA.to_owned(),
        approved_providers: vec!["priced.fixture".to_owned()],
    })
}

fn config<'a>(identity: &'a LiveInvocationId) -> LiveInvocationConfig<'a> {
    LiveInvocationConfig {
        identity,
        task: b"priced task",
        deployment_binding: "sha256:priced-deploy",
        interaction_schema_digest: SCHEMA,
        max_turns: 1,
        max_response_bytes: 1024,
        requested_budget_per_turn: 10,
    }
}

fn pricing() -> GenericPricing {
    pricing_with_ceiling(30)
}

fn pricing_with_ceiling(ceiling_minor: i64) -> GenericPricing {
    GenericPricing::new(
        ValidatedPricing::new(
            "generic.work.v1".to_owned(),
            "USD".to_owned(),
            6,
            3,
            ceiling_minor,
        )
        .unwrap(),
    )
}

fn handlers<'a>(
    capability: &'a ModelInvokeCapability,
    handler: &'a mut FixtureModelHandler,
    decoder: &'a mut FixtureProposalDecoder,
    gate: &'a mut FixtureAuthorizationGate,
    budget: &'a mut ExactBudget,
    observer: &'a mut FixtureObserver,
    policy: &'a mut FixturePolicy,
    store: &'a mut Store,
) -> PricedLiveInvocationHandlers<'a> {
    PricedLiveInvocationHandlers {
        capability,
        handler,
        decoder,
        gate,
        work_budget: budget,
        observer,
        policy,
        effect: None,
        store,
    }
}

#[test]
fn priced_generic_dispatch_persists_unknown_charge_and_reconciles_exact_envelope() {
    let id = identity();
    let capability = ModelInvokeCapability::grant("priced fixture");
    let mut handler = FixtureModelHandler::scripted(vec![ModelInvocationOutcome::Settled(
        fixture_response(0, "ok"),
    )]);
    let mut decoder = FixtureProposalDecoder::new(SCHEMA);
    let mut gate = FixtureAuthorizationGate::new(1);
    let mut budget = ExactBudget(FixtureBudgetHook::new(10));
    let mut observer = FixtureObserver;
    let mut policy = FixturePolicy { total_turns: 1 };
    let mut store = Store::default();
    let run = run_priced_live_invocation(
        &config(&id),
        PricedInvocationState::fresh(pricing()),
        &mut handlers(
            &capability,
            &mut handler,
            &mut decoder,
            &mut gate,
            &mut budget,
            &mut observer,
            &mut policy,
            &mut store,
        ),
        &AgentCancellation::new(),
    )
    .unwrap();
    assert_eq!(run.run.dispatched, 1);
    assert!(run.receipt().contains("\"reserved_minor\":30"));
    assert!(run.receipt().contains("\"kind\":\"unknown\""));
    let recovered = PricedInvocationState::recover(store.documents.last().unwrap(), &id).unwrap();
    assert_eq!(recovered.journal(), run.state.journal());
    assert_eq!(recovered.generation(), run.state.generation());
}

#[test]
fn priced_generic_recovery_of_durable_intent_never_redispatches() {
    let id = identity();
    let capability = ModelInvokeCapability::grant("priced crash fixture");
    let mut handler = FixtureModelHandler::scripted(vec![ModelInvocationOutcome::Settled(
        fixture_response(0, "ok"),
    )]);
    let mut decoder = FixtureProposalDecoder::new(SCHEMA);
    let mut gate = FixtureAuthorizationGate::new(1);
    let mut budget = ExactBudget(FixtureBudgetHook::new(10));
    let mut observer = FixtureObserver;
    let mut policy = FixturePolicy { total_turns: 1 };
    let mut store = Store {
        fail_from: Some(3),
        ..Store::default()
    };
    let failure = run_priced_live_invocation(
        &config(&id),
        PricedInvocationState::fresh(pricing()),
        &mut handlers(
            &capability,
            &mut handler,
            &mut decoder,
            &mut gate,
            &mut budget,
            &mut observer,
            &mut policy,
            &mut store,
        ),
        &AgentCancellation::new(),
    );
    assert!(matches!(
        failure,
        Err(LiveKernelError::PersistenceFailed { dispatched: 1 })
    ));
    assert_eq!(handler.calls, 1);
    let recovered = PricedInvocationState::recover(store.documents.last().unwrap(), &id).unwrap();
    let mut never = FixtureModelHandler::must_not_be_called();
    let mut decoder = FixtureProposalDecoder::new(SCHEMA);
    let mut gate = FixtureAuthorizationGate::new(0);
    let mut budget = ExactBudget(FixtureBudgetHook::new(10));
    let mut observer = FixtureObserver;
    let mut policy = FixturePolicy { total_turns: 1 };
    let mut resumed_store = Store::default();
    let result = run_priced_live_invocation(
        &config(&id),
        recovered,
        &mut handlers(
            &capability,
            &mut never,
            &mut decoder,
            &mut gate,
            &mut budget,
            &mut observer,
            &mut policy,
            &mut resumed_store,
        ),
        &AgentCancellation::new(),
    );
    assert!(matches!(result, Err(LiveKernelError::UncertainIntent)));
    assert_eq!(never.calls, 0);
}

#[test]
fn priced_successor_dispatch_then_recovery_preserves_immutable_carry() {
    let predecessor_id = identity();
    let destination_id = identity_for(b"priced successor task");
    let capability = ModelInvokeCapability::grant("priced successor fixture");
    let mut first_handler = FixtureModelHandler::scripted(vec![ModelInvocationOutcome::Settled(
        fixture_response(0, "first"),
    )]);
    let mut decoder = FixtureProposalDecoder::new(SCHEMA);
    let mut gate = FixtureAuthorizationGate::new(1);
    let mut budget = ExactBudget(FixtureBudgetHook::new(10));
    let mut observer = FixtureObserver;
    let mut policy = FixturePolicy { total_turns: 1 };
    let mut predecessor_store = Store::default();
    let predecessor = run_priced_live_invocation(
        &config(&predecessor_id),
        PricedInvocationState::fresh(pricing_with_ceiling(60)),
        &mut handlers(
            &capability,
            &mut first_handler,
            &mut decoder,
            &mut gate,
            &mut budget,
            &mut observer,
            &mut policy,
            &mut predecessor_store,
        ),
        &AgentCancellation::new(),
    )
    .unwrap()
    .state;
    let successor = PricedInvocationState::successor(
        &predecessor,
        &predecessor_id,
        &destination_id,
        pricing_with_ceiling(60),
    )
    .unwrap();
    let mut second_handler = FixtureModelHandler::scripted(vec![ModelInvocationOutcome::Settled(
        fixture_response(0, "second"),
    )]);
    let mut decoder = FixtureProposalDecoder::new(SCHEMA);
    let mut gate = FixtureAuthorizationGate::new(1);
    let mut budget = ExactBudget(FixtureBudgetHook::new(10));
    let mut observer = FixtureObserver;
    let mut policy = FixturePolicy { total_turns: 1 };
    let mut destination_store = Store::default();
    let successor = run_priced_live_invocation(
        &config(&destination_id),
        successor,
        &mut handlers(
            &capability,
            &mut second_handler,
            &mut decoder,
            &mut gate,
            &mut budget,
            &mut observer,
            &mut policy,
            &mut destination_store,
        ),
        &AgentCancellation::new(),
    )
    .unwrap();
    assert_eq!(successor.run.dispatched, 1);
    let recovered = PricedInvocationState::recover(
        destination_store.documents.last().unwrap(),
        &destination_id,
    )
    .expect("successor handoff and its original carry recover after a new attempt");
    assert_eq!(recovered.generation(), successor.state.generation());
}
