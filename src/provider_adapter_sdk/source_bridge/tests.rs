use std::cell::RefCell;
use std::collections::VecDeque;
use std::rc::Rc;

use super::*;
use crate::agent_lifecycle::LifecycleTask;
use crate::interpreter::retained_call::RetainedValue;
use crate::provider_adapter_sdk::adapter::{AdapterRefusal, AdapterSettlement};
use crate::provider_adapter_sdk::capability::AdapterCapabilities;
use crate::provider_adapter_sdk::fixture_adapters::{base_capabilities, usage};
use crate::streaming_proposal_decode::source::tests::{fixture_document, fixture_schema};

mod recording;

static STATE: RetainedValue = RetainedValue::I64(1);
fn request<'a>(
    task: &'a LifecycleTask,
    schema: &'a CompiledAgentProposalSchema,
) -> ProposalRequest<'a> {
    ProposalRequest {
        turn: 1,
        attempt: 2,
        source_revision: schema.source_revision(),
        proposal_schema_digest: schema.schema().digest(),
        task,
        state: &STATE,
        observation: &STATE,
        previous_effect: Some(b"prior"),
        previous_rejection: Some("rejected"),
        remaining_iterations: 2,
    }
}
#[derive(Default)]
struct Counts {
    requests: Vec<Vec<u8>>,
    polls: usize,
    cancels: usize,
}
struct Probe {
    counts: Rc<RefCell<Counts>>,
    script: VecDeque<AdapterPoll>,
    caps: AdapterCapabilities,
}
impl ProviderAdapter for Probe {
    fn capabilities(&self) -> &AdapterCapabilities {
        &self.caps
    }
    fn start(
        &mut self,
        _: &AdapterInvocationCapability,
        request: &AdapterRequest,
    ) -> Result<(), AdapterRefusal> {
        self.counts
            .borrow_mut()
            .requests
            .push(request.request_bytes.clone());
        Ok(())
    }
    fn poll(&mut self) -> AdapterPoll {
        self.counts.borrow_mut().polls += 1;
        self.script
            .pop_front()
            .expect("must not poll after refusal")
    }
    fn cancel(&mut self, _: &str) {
        self.counts.borrow_mut().cancels += 1;
    }
}
fn factory(counts: Rc<RefCell<Counts>>, script: Vec<AdapterPoll>) -> impl SourceAdapterFactory {
    move || {
        let mut caps = base_capabilities("source-test", true);
        caps.max_request_bytes = MAX_STREAM_BYTES;
        Box::new(Probe {
            counts: counts.clone(),
            script: script.clone().into(),
            caps,
        }) as Box<dyn ProviderAdapter>
    }
}
fn task() -> LifecycleTask {
    LifecycleTask {
        objective: vec![0, 255],
        budget: 3,
    }
}
fn capability() -> AdapterInvocationCapability {
    AdapterInvocationCapability::grant("offline test")
}

#[test]
fn source_adapter_admits_each_attempt_with_exact_iterative_context() {
    let schema = fixture_schema();
    let bytes = fixture_document(&schema, "ok");
    let counts = Rc::new(RefCell::new(Counts::default()));
    let mut script: Vec<_> = bytes
        .chunks(3)
        .map(|chunk| AdapterPoll::Event(AdapterEvent::Delta(chunk.to_vec())))
        .collect();
    script.push(AdapterPoll::Event(AdapterEvent::Completed));
    script.push(AdapterPoll::Settled(AdapterSettlement {
        response_bytes: bytes.clone(),
        usage: usage(1, 1, 1),
    }));
    let mut factory = factory(counts.clone(), script);
    let task = task();
    let mut source = StreamingSourceProposalAdapter::new(&mut factory, capability(), &schema);
    assert!(source.checkpoint_policy().is_none());
    for _ in 0..2 {
        assert_eq!(
            source.propose(request(&task, &schema)).unwrap().as_bytes(),
            bytes
        );
    }
    let observed = counts.borrow();
    assert_eq!(observed.requests.len(), 2);
    let prompt: serde_json::Value = serde_json::from_slice(&observed.requests[0]).unwrap();
    assert_eq!(prompt["schema"], "semaprax.source-adapter-prompt.v1");
    assert_eq!(prompt["task_hex"], "00ff");
    assert_eq!(prompt["task_budget"], 3);
    assert_eq!(prompt["state"], "1");
    assert_eq!(prompt["observation"], "1");
    assert_eq!(prompt["previous_effect_hex"], "7072696f72");
    assert_eq!(prompt["previous_rejection"], "rejected");
    assert_eq!(prompt["turn"], 1);
    assert_eq!(prompt["attempt"], 2);
    assert_eq!(prompt["remaining_iterations"], 2);
    assert_eq!(observed.cancels, 0);
}

#[test]
fn malformed_first_chunk_refuses_and_cancels_without_a_second_poll() {
    let schema = fixture_schema();
    let counts = Rc::new(RefCell::new(Counts::default()));
    let mut factory = factory(
        counts.clone(),
        vec![AdapterPoll::Event(AdapterEvent::Delta(b"!".to_vec()))],
    );
    let task = task();
    let mut source = StreamingSourceProposalAdapter::new(&mut factory, capability(), &schema);
    assert_eq!(
        source.propose(request(&task, &schema)).unwrap_err()[0].code,
        "source.adapter_decode"
    );
    assert_eq!(counts.borrow().polls, 1);
    assert_eq!(counts.borrow().cancels, 1);
}

struct Clock(i64);
impl InvocationClock for Clock {
    fn now_millis(&self) -> i64 {
        self.0
    }
}
#[test]
fn cancellation_deadline_drift_and_capacity_refuse_before_factory() {
    let schema = fixture_schema();
    let task = task();
    let mut factory = || -> Box<dyn ProviderAdapter> { panic!("no adapter may be constructed") };
    let cancellation = AgentCancellation::new();
    cancellation.cancel();
    let mut source = StreamingSourceProposalAdapter::new(&mut factory, capability(), &schema)
        .with_cancellation(&cancellation);
    assert_eq!(
        source.propose(request(&task, &schema)).unwrap_err()[0].code,
        "source.adapter_cancelled"
    );
    let clear = AgentCancellation::new();
    let clock = Clock(10);
    let mut source = StreamingSourceProposalAdapter::new(&mut factory, capability(), &schema)
        .with_cancellation_and_deadline(&clear, &clock, 10);
    assert_eq!(
        source.propose(request(&task, &schema)).unwrap_err()[0].code,
        "source.adapter_timeout"
    );
    let mut source = StreamingSourceProposalAdapter::new(&mut factory, capability(), &schema);
    let mut drift = request(&task, &schema);
    drift.source_revision = "stale";
    assert_eq!(
        source.propose(drift).unwrap_err()[0].code,
        "source.adapter_schema_drift"
    );
    let huge = RetainedValue::Bytes(vec![0; MAX_STREAM_BYTES]);
    let mut bounded = request(&task, &schema);
    bounded.state = &huge;
    assert_eq!(
        source.propose(bounded).unwrap_err()[0].code,
        "source.adapter_request_bound"
    );
}

#[test]
fn settlement_bytes_and_regressing_usage_are_refused() {
    let schema = fixture_schema();
    let bytes = fixture_document(&schema, "ok");
    let task = task();
    for script in [
        vec![
            AdapterPoll::Event(AdapterEvent::Delta(bytes.clone())),
            AdapterPoll::Event(AdapterEvent::Completed),
            AdapterPoll::Settled(AdapterSettlement {
                response_bytes: b"different".to_vec(),
                usage: usage(1, 1, 1),
            }),
        ],
        vec![
            AdapterPoll::Event(AdapterEvent::Usage {
                tokens_in: 2,
                tokens_out: 1,
                cost_micros: 1,
            }),
            AdapterPoll::Event(AdapterEvent::Usage {
                tokens_in: 1,
                tokens_out: 1,
                cost_micros: 1,
            }),
        ],
    ] {
        let counts = Rc::new(RefCell::new(Counts::default()));
        let mut factory = factory(counts.clone(), script);
        let mut source = StreamingSourceProposalAdapter::new(&mut factory, capability(), &schema);
        assert!(source.propose(request(&task, &schema)).is_err());
        assert_eq!(counts.borrow().cancels, 1);
    }
}

mod settlement_boundary;
