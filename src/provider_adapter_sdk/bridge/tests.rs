use super::*;
use crate::agent_interaction_schema::compile_agent_interaction_schema;
use crate::live_invocation::fixture::{
    FixtureAuthorizationGate, FixtureBudgetHook, FixtureObserver, FixturePolicy, StepClock,
};
use crate::live_invocation::identity::{LiveInvocationId, LiveInvocationSeed};
use crate::live_invocation::kernel::{
    run_live_invocation, LiveInvocationConfig, LiveInvocationHandlers, LiveKernelRun,
};
use crate::live_invocation::model_invoke::BudgetRefusal;
use crate::model_budget_policy::live_hook::{
    LiveModelPolicyHook, ModelAttemptQuote, ModelAttemptQuoter,
};
use crate::model_budget_policy::{intersect, ModelBudgetLimits, ProviderSlot};
use crate::provider_adapter_sdk::adapter::{AdapterRefusal, AdapterSettlement, AdapterUsage};
use crate::provider_adapter_sdk::capability::{
    AdapterCapabilities, CancellationSemantics, EndpointPolicy, TokenAccountingSource,
};
use crate::provider_adapter_sdk::fixture_adapters::PanicsOnStartAdapter;
use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};

mod adapter_projection;
mod generic_enrichment;

const SOURCE: &str = "module test.bridge;\n\n@id(\"answer.type\")\nrecord Answer {\n    @id(\"answer.note\")\n    note: string,\n}\n\n@id(\"app.main\")\nfn main() -> i64 { 0 }\n";
static NEXT_FILE: AtomicU64 = AtomicU64::new(0);
fn schema() -> CompiledInteractionSchema {
    let path = std::env::temp_dir().join(format!(
        "semaprax-bridge-{}-{}.spx",
        std::process::id(),
        NEXT_FILE.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::write(&path, SOURCE).unwrap();
    let result = compile_agent_interaction_schema(&path, "answer.type");
    std::fs::remove_file(path).unwrap();
    result.unwrap()
}
fn document(schema: &CompiledInteractionSchema) -> Vec<u8> {
    format!("{{\"schema\":\"semaprax.agent-interaction-value.v1\",\"root_type_id\":\"answer.type\",\"schema_digest\":{},\"value\":{}}}\n", quote_json(schema.schema().digest()), r#"{"fields":{"answer.note":"ok"}}"#).into_bytes()
}
fn request(schema: &CompiledInteractionSchema) -> ModelInvocationRequest {
    ModelInvocationRequest {
        turn: 0,
        task: b"task".to_vec(),
        observation: b"observation".to_vec(),
        proposal_grammar_digest: schema.schema().digest().to_owned(),
        deployment_binding: "policy".into(),
        max_response_bytes: 4096,
        effective_budget: 1,
    }
}
fn caps() -> AdapterCapabilities {
    AdapterCapabilities {
        adapter_identity: "bridge-test".into(),
        adapter_version: "1".into(),
        provider_profile: "fixture".into(),
        structured_output_modes: vec![StructuredOutputMode::RawText],
        supports_streaming: true,
        token_accounting_source: TokenAccountingSource::Unavailable,
        cancellation_semantics: CancellationSemantics::BestEffortRequestStop,
        retryable_failure_classes: vec![],
        endpoint_policy: EndpointPolicy::HostInjected,
        max_request_bytes: 65_536,
        max_response_bytes: 65_536,
        max_context_tokens: 1,
        max_output_tokens: 1,
    }
}
struct Probe {
    caps: AdapterCapabilities,
    script: VecDeque<AdapterPoll>,
    polls: usize,
    starts: usize,
    cancels: usize,
}
impl Probe {
    fn new(script: Vec<AdapterPoll>) -> Self {
        Self {
            caps: caps(),
            script: script.into(),
            polls: 0,
            starts: 0,
            cancels: 0,
        }
    }
}
impl ProviderAdapter for Probe {
    fn capabilities(&self) -> &AdapterCapabilities {
        &self.caps
    }
    fn start(
        &mut self,
        _: &AdapterInvocationCapability,
        _: &AdapterRequest,
    ) -> Result<(), AdapterRefusal> {
        self.starts += 1;
        Ok(())
    }
    fn poll(&mut self) -> AdapterPoll {
        self.polls += 1;
        self.script
            .pop_front()
            .expect("bridge polled after its boundary")
    }
    fn cancel(&mut self, _: &str) {
        self.cancels += 1;
    }
}
struct Quote;
impl ModelAttemptQuoter for Quote {
    fn quote(
        &mut self,
        request: &ModelInvocationRequest,
    ) -> Result<ModelAttemptQuote, BudgetRefusal> {
        Ok(ModelAttemptQuote {
            request_digest: request.digest(),
            context_tokens: 8,
            output_tokens: 4,
            estimated_cost_micros: 3,
        })
    }
}
fn kernel(
    schema: &CompiledInteractionSchema,
    adapter: &mut dyn ProviderAdapter,
) -> (LiveKernelRun, usize) {
    let identity = LiveInvocationId::derive(&LiveInvocationSeed {
        program_root: "root".into(),
        deployment_policy: "policy".into(),
        task: b"task".to_vec(),
        budget: 1,
        interaction_schema_digest: schema.schema().digest().into(),
        approved_providers: vec!["fixture".into()],
    });
    let config = LiveInvocationConfig {
        identity: &identity,
        task: b"task",
        deployment_binding: "policy",
        interaction_schema_digest: schema.schema().digest(),
        max_turns: 1,
        max_response_bytes: 4096,
        requested_budget_per_turn: 1,
    };
    let capability = ModelInvokeCapability::grant("bridge test");
    let mut handler = StreamingModelHandler::new(
        adapter,
        AdapterInvocationCapability::grant("bridge test"),
        schema,
    );
    let mut decoder =
        crate::live_invocation::compiled_decoder::CompiledProposalDecoder::new(schema);
    let mut gate = FixtureAuthorizationGate::new(1);
    let mut inner = FixtureBudgetHook::new(1);
    let mut quote = Quote;
    let clock = StepClock::new(0);
    let cancellation = AgentCancellation::new();
    let limits = ModelBudgetLimits::single_call_only(8, 4);
    let mut budget = LiveModelPolicyHook::new(
        intersect(limits, limits, limits).unwrap(),
        ProviderSlot::authorized("fixture"),
        0,
        &clock,
        &mut inner,
        &mut quote,
        &cancellation,
    )
    .unwrap();
    let mut observer = FixtureObserver;
    let mut policy = FixturePolicy { total_turns: 1 };
    let run = run_live_invocation(
        &config,
        Vec::new(),
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
    assert_eq!(budget.ledger().calls_committed(), 1);
    assert_eq!(budget.ledger().cost_committed_micros(), 3);
    assert_eq!(run.model_call_receipts(&identity).unwrap().len(), 1);
    (run, gate.granted)
}
#[test]
fn compiled_stream_policy_and_receipt_reach_the_actual_kernel() {
    let schema = schema();
    let bytes = document(&schema);
    schema.decode(&bytes).unwrap();
    let mut script: Vec<_> = bytes
        .iter()
        .map(|byte| AdapterPoll::Event(AdapterEvent::Delta(vec![*byte])))
        .collect();
    script.push(AdapterPoll::Event(AdapterEvent::Completed));
    script.push(AdapterPoll::Settled(AdapterSettlement {
        response_bytes: bytes,
        usage: AdapterUsage {
            tokens_in: None,
            tokens_out: None,
            cost_micros: None,
        },
    }));
    let mut adapter = Probe::new(script);
    let (run, granted) = kernel(&schema, &mut adapter);
    assert_eq!(run.dispatched, 1);
    assert_eq!(granted, 1);
    assert_eq!(adapter.starts, 1);
    assert_eq!(adapter.cancels, 0);
}
#[test]
fn malformed_first_delta_stops_reads_and_never_authorizes() {
    let schema = schema();
    let mut adapter = Probe::new(vec![AdapterPoll::Event(AdapterEvent::Delta(b"!".to_vec()))]);
    let (_, granted) = kernel(&schema, &mut adapter);
    assert_eq!(granted, 0);
    assert_eq!(adapter.polls, 1);
    assert_eq!(adapter.cancels, 1);
}
#[test]
fn cancellation_deadline_and_schema_mismatch_prevent_adapter_start() {
    let schema = schema();
    let cancellation = AgentCancellation::new();
    cancellation.cancel();
    let clock = StepClock::new(0);
    let mut adapter = PanicsOnStartAdapter::new(caps());
    let outcome = StreamingModelHandler::new(
        &mut adapter,
        AdapterInvocationCapability::grant("test"),
        &schema,
    )
    .with_cancellation_and_deadline(&cancellation, &clock, 10)
    .invoke(&ModelInvokeCapability::grant("test"), &request(&schema));
    assert!(matches!(
        outcome,
        ModelInvocationOutcome::Failed {
            failure: ModelFailure::Cancelled,
            attempted_bytes: 0
        }
    ));
    let cancellation = AgentCancellation::new();
    let outcome = StreamingModelHandler::new(
        &mut adapter,
        AdapterInvocationCapability::grant("test"),
        &schema,
    )
    .with_cancellation_and_deadline(&cancellation, &clock, 0)
    .invoke(&ModelInvokeCapability::grant("test"), &request(&schema));
    assert!(matches!(
        outcome,
        ModelInvocationOutcome::Failed {
            failure: ModelFailure::Timeout,
            attempted_bytes: 0
        }
    ));
    let mut mismatched = request(&schema);
    mismatched.proposal_grammar_digest = "wrong-schema".into();
    assert!(matches!(
        StreamingModelHandler::new(
            &mut adapter,
            AdapterInvocationCapability::grant("test"),
            &schema
        )
        .invoke(&ModelInvokeCapability::grant("test"), &mismatched),
        ModelInvocationOutcome::Failed {
            failure: ModelFailure::Refused,
            ..
        }
    ));
}
#[test]
fn pending_polls_stop_at_deadline_and_oversized_delta_is_bounded() {
    struct Clock(std::cell::Cell<i64>);
    impl InvocationClock for Clock {
        fn now_millis(&self) -> i64 {
            let n = self.0.get();
            self.0.set(n + 1);
            n
        }
    }
    let schema = schema();
    let clock = Clock(std::cell::Cell::new(0));
    let cancellation = AgentCancellation::new();
    let mut adapter = Probe::new(vec![AdapterPoll::Pending, AdapterPoll::Pending]);
    let result = StreamingModelHandler::new(
        &mut adapter,
        AdapterInvocationCapability::grant("test"),
        &schema,
    )
    .with_cancellation_and_deadline(&cancellation, &clock, 3)
    .invoke(&ModelInvokeCapability::grant("test"), &request(&schema));
    assert!(matches!(
        result,
        ModelInvocationOutcome::Failed {
            failure: ModelFailure::Timeout,
            ..
        }
    ));
    assert_eq!(adapter.polls, 2);
    let mut adapter = Probe::new(vec![AdapterPoll::Event(AdapterEvent::Delta(vec![
        b'x';
        65_537
    ]))]);
    let mut large = request(&schema);
    large.max_response_bytes = usize::MAX;
    assert!(matches!(
        StreamingModelHandler::new(
            &mut adapter,
            AdapterInvocationCapability::grant("test"),
            &schema
        )
        .invoke(&ModelInvokeCapability::grant("test"), &large),
        ModelInvocationOutcome::Failed {
            failure: ModelFailure::MalformedResponse,
            attempted_bytes: 0
        }
    ));
    assert_eq!(adapter.polls, 1);
}

mod settlement_boundary;
