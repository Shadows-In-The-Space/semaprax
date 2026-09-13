use std::cell::RefCell;
use std::rc::Rc;

use super::*;
use crate::provider_adapter_sdk::adapter::{AdapterRefusal, ProviderAdapter};
use crate::provider_adapter_sdk::capability::AdapterCapabilities;
use crate::provider_adapter_sdk::commit_delta;
use crate::provider_adapter_sdk::fixture_adapters::{
    base_capabilities, usage, RecordedReplayAdapter,
};
use crate::provider_adapter_sdk::{
    AdapterEvent, AdapterInvocationCapability, AdapterPoll, AdapterRequest, AdapterSettlement,
    AttemptObservation, ObservedEvent, RecordingAdapter, ReplayCancellation, ReplayInputs,
};
use crate::streaming_proposal_decode::MAX_STREAM_BYTES;

/// Keeps the SDK's owned recording decorator inside the source factory's
/// `Box<dyn ProviderAdapter>` boundary, and retains its immutable observation
/// when the one-attempt source adapter is dropped.
struct RetainingRecordingAdapter {
    recorder: RecordingAdapter<'static>,
    retained: Rc<RefCell<Option<AttemptObservation>>>,
}

impl RetainingRecordingAdapter {
    fn new(
        inner: Box<dyn ProviderAdapter>,
        grammar_digest: &str,
        retained: Rc<RefCell<Option<AttemptObservation>>>,
    ) -> Self {
        Self {
            recorder: RecordingAdapter::from_box(inner, grammar_digest),
            retained,
        }
    }
}

impl Drop for RetainingRecordingAdapter {
    fn drop(&mut self) {
        *self.retained.borrow_mut() = Some(self.recorder.observation().clone());
    }
}

impl ProviderAdapter for RetainingRecordingAdapter {
    fn capabilities(&self) -> &AdapterCapabilities {
        self.recorder.capabilities()
    }

    fn start(
        &mut self,
        capability: &AdapterInvocationCapability,
        request: &AdapterRequest,
    ) -> Result<(), AdapterRefusal> {
        self.recorder.start(capability, request)
    }

    fn poll(&mut self) -> AdapterPoll {
        self.recorder.poll()
    }

    fn cancel(&mut self, reason: &str) {
        self.recorder.cancel(reason);
    }
}

fn recording_factory(
    counts: Rc<RefCell<Counts>>,
    script: Vec<AdapterPoll>,
    grammar_digest: String,
    retained: Rc<RefCell<Option<AttemptObservation>>>,
) -> impl SourceAdapterFactory {
    move || {
        let mut caps = base_capabilities("recording-source-test", true);
        caps.max_request_bytes = MAX_STREAM_BYTES;
        Box::new(RetainingRecordingAdapter::new(
            Box::new(Probe {
                counts: counts.clone(),
                script: script.clone().into(),
                caps,
            }),
            &grammar_digest,
            retained.clone(),
        )) as Box<dyn ProviderAdapter>
    }
}

#[test]
fn source_factory_records_ordered_events_and_replays_the_typed_proposal_without_dispatch() {
    let schema = fixture_schema();
    let grammar_digest = schema.schema().digest().to_owned();
    let bytes = fixture_document(&schema, "recorded");
    let events = vec![
        AdapterEvent::Delta(bytes[..17].to_vec()),
        AdapterEvent::Usage {
            tokens_in: 3,
            tokens_out: 2,
            cost_micros: 7,
        },
        AdapterEvent::Delta(bytes[17..].to_vec()),
        AdapterEvent::Completed,
    ];
    let settlement = AdapterSettlement {
        response_bytes: bytes.clone(),
        usage: usage(3, 2, 7),
    };
    let mut script: Vec<_> = events.iter().cloned().map(AdapterPoll::Event).collect();
    script.push(AdapterPoll::Settled(settlement.clone()));
    let counts = Rc::new(RefCell::new(Counts::default()));
    let retained = Rc::new(RefCell::new(None));
    let mut factory = recording_factory(
        counts.clone(),
        script,
        grammar_digest.clone(),
        retained.clone(),
    );
    let task = task();
    let actual = {
        let mut source = StreamingSourceProposalAdapter::new(&mut factory, capability(), &schema);
        source.propose(request(&task, &schema)).unwrap()
    };
    assert_eq!(actual.as_bytes(), bytes);
    let typed = schema.decode(&actual).unwrap();
    assert_eq!(typed.canonical_json(), actual);

    let observation = retained
        .borrow_mut()
        .take()
        .expect("factory-owned recorder retained observation");
    let request_bytes = counts.borrow().requests[0].clone();
    let adapter_request = AdapterRequest {
        request_bytes,
        max_response_bytes: MAX_STREAM_BYTES,
    };
    assert_eq!(observation.events().len(), events.len());
    assert_eq!(observation.proposal_grammar_digest(), grammar_digest);
    assert_eq!(
        observation.replay(&ReplayInputs {
            request: &adapter_request,
            events: &events,
            settlement: Some(&settlement),
            failure: None,
            start_refusal: None,
            cancellation: None,
            compiled_grammar_digest: &grammar_digest,
        }),
        Ok(())
    );
    let calls_before = counts.borrow().polls;
    assert_eq!(
        observation.replay(&ReplayInputs {
            request: &adapter_request,
            events: &events,
            settlement: Some(&settlement),
            failure: None,
            start_refusal: None,
            cancellation: None,
            compiled_grammar_digest: &grammar_digest,
        }),
        Ok(())
    );
    assert_eq!(counts.borrow().polls, calls_before);

    let replay_events = events.clone();
    let replay_settlement = settlement.clone();
    let mut replay_factory = move || {
        Box::new(RecordedReplayAdapter::from_recording(
            base_capabilities("recorded-source-replay", true),
            replay_events.clone(),
            replay_settlement.clone(),
        )) as Box<dyn ProviderAdapter>
    };
    let replayed = StreamingSourceProposalAdapter::new(&mut replay_factory, capability(), &schema)
        .propose(request(&task, &schema))
        .unwrap();
    assert_eq!(schema.decode(&replayed).unwrap(), typed);
    assert_eq!(counts.borrow().polls, calls_before);
}

#[test]
fn source_recording_captures_the_malformed_first_chunk_before_early_cancellation() {
    let schema = fixture_schema();
    let counts = Rc::new(RefCell::new(Counts::default()));
    let retained = Rc::new(RefCell::new(None));
    let mut factory = recording_factory(
        counts.clone(),
        vec![AdapterPoll::Event(AdapterEvent::Delta(b"!".to_vec()))],
        schema.schema().digest().to_owned(),
        retained.clone(),
    );
    let task = task();
    {
        let mut source = StreamingSourceProposalAdapter::new(&mut factory, capability(), &schema);
        assert_eq!(
            source.propose(request(&task, &schema)).unwrap_err()[0].code,
            "source.adapter_decode"
        );
    }
    let observation = retained
        .borrow_mut()
        .take()
        .expect("cancelled attempt retained");
    assert_eq!(counts.borrow().polls, 1);
    assert_eq!(observation.events().len(), 1);
    assert!(matches!(
        &observation.events()[0],
        ObservedEvent::Delta(commitment)
            if commitment.commitment() == commit_delta(b"!") && commitment.bytes_len() == 1
    ));
    assert_eq!(observation.cancellation().unwrap().requests(), 1);
    let adapter_request = AdapterRequest {
        request_bytes: counts.borrow().requests[0].clone(),
        max_response_bytes: MAX_STREAM_BYTES,
    };
    assert_eq!(
        observation.replay(&ReplayInputs {
            request: &adapter_request,
            events: &[AdapterEvent::Delta(b"!".to_vec())],
            settlement: None,
            failure: None,
            start_refusal: None,
            cancellation: Some(ReplayCancellation {
                first_reason: "source decoder refusal",
                requests: 1,
            }),
            compiled_grammar_digest: schema.schema().digest(),
        }),
        Ok(())
    );
}
