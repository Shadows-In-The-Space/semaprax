use super::*;
use crate::agent_interaction_schema::CompiledInteractionSchema;
use crate::live_invocation::identity::LiveInvocationSeed;
use crate::live_invocation::model_invoke::ModelInvocationRequest;
use crate::model_call_receipt::adapter_projection::{
    project_settled_adapter_call, replay_settled_adapter_call, AdapterProjectionError,
};
use crate::provider_adapter_sdk::{
    AdapterEvent, AdapterPoll, AdapterSettlement, AdapterUsage, RecordingAdapter, ReplayInputs,
};

fn seed(schema: &CompiledInteractionSchema) -> LiveInvocationSeed {
    LiveInvocationSeed {
        program_root: "root".into(),
        deployment_policy: "policy".into(),
        task: b"task".to_vec(),
        budget: 1,
        interaction_schema_digest: schema.schema().digest().into(),
        approved_providers: vec!["fixture".into()],
    }
}

/// This is the logical request `kernel` constructs for its one FixtureObserver
/// turn: the observer emits `observation:0` and the policy hook reserves one.
fn kernel_request(schema: &CompiledInteractionSchema) -> ModelInvocationRequest {
    ModelInvocationRequest {
        turn: 0,
        task: b"task".to_vec(),
        observation: b"observation:0".to_vec(),
        proposal_grammar_digest: schema.schema().digest().to_owned(),
        deployment_binding: "policy".into(),
        max_response_bytes: 4096,
        effective_budget: 1,
    }
}

#[test]
fn actual_kernel_recording_projects_and_replays_adapter_evidence() {
    let schema = schema();
    let response = document(&schema);
    let events = vec![
        AdapterEvent::Delta(response[..13].to_vec()),
        AdapterEvent::Usage {
            tokens_in: 3,
            tokens_out: 2,
            cost_micros: 7,
        },
        AdapterEvent::Delta(response[13..].to_vec()),
        AdapterEvent::Completed,
    ];
    let settlement = AdapterSettlement {
        response_bytes: response,
        usage: AdapterUsage {
            tokens_in: Some(3),
            tokens_out: Some(2),
            cost_micros: Some(7),
        },
    };
    let mut script: Vec<_> = events.iter().cloned().map(AdapterPoll::Event).collect();
    script.push(AdapterPoll::Settled(settlement.clone()));
    let mut adapter = Probe::new(script);
    let mut recorder = RecordingAdapter::new(&mut adapter, schema.schema().digest());
    let (run, granted) = kernel(&schema, &mut recorder);
    assert_eq!(granted, 1);

    let logical_request = kernel_request(&schema);
    let retained_request =
        super::super::adapter_request_for(&logical_request, &schema.provider_json_schema());
    let retained = ReplayInputs {
        request: &retained_request,
        events: &events,
        settlement: Some(&settlement),
        failure: None,
        start_refusal: None,
        cancellation: None,
        compiled_grammar_digest: schema.schema().digest(),
    };
    let invocation_seed = seed(&schema);
    let evidence = project_settled_adapter_call(
        &run.journal,
        &invocation_seed,
        &logical_request,
        &schema,
        recorder.observation(),
        &retained,
    )
    .unwrap();
    replay_settled_adapter_call(
        evidence.render().as_bytes(),
        &run.journal,
        &invocation_seed,
        &logical_request,
        &schema,
        recorder.observation(),
        &retained,
    )
    .unwrap();

    let mut altered_request = logical_request.clone();
    altered_request.task.push(b'!');
    assert_eq!(
        project_settled_adapter_call(
            &run.journal,
            &invocation_seed,
            &altered_request,
            &schema,
            recorder.observation(),
            &retained,
        ),
        Err(AdapterProjectionError::Binding)
    );

    let mut altered_seed = invocation_seed.clone();
    altered_seed.task.push(b'!');
    assert_eq!(
        project_settled_adapter_call(
            &run.journal,
            &altered_seed,
            &logical_request,
            &schema,
            recorder.observation(),
            &retained,
        ),
        Err(AdapterProjectionError::Binding)
    );

    let mut altered_events = events.clone();
    altered_events[0] = AdapterEvent::Delta(b"changed".to_vec());
    let altered_transcript = ReplayInputs {
        request: &retained_request,
        events: &altered_events,
        settlement: Some(&settlement),
        failure: None,
        start_refusal: None,
        cancellation: None,
        compiled_grammar_digest: schema.schema().digest(),
    };
    assert_eq!(
        project_settled_adapter_call(
            &run.journal,
            &invocation_seed,
            &logical_request,
            &schema,
            recorder.observation(),
            &altered_transcript,
        ),
        Err(AdapterProjectionError::Transcript)
    );

    let mut submitted = evidence.render().as_bytes().to_vec();
    submitted[0] ^= 1;
    assert_eq!(
        replay_settled_adapter_call(
            &submitted,
            &run.journal,
            &invocation_seed,
            &logical_request,
            &schema,
            recorder.observation(),
            &retained,
        ),
        Err(AdapterProjectionError::Mismatch)
    );
}
