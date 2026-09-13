//! Actual generic-kernel coverage for rich model-call receipt enrichment.

use super::*;
use crate::live_invocation::identity::{LiveInvocationId, LiveInvocationSeed};
use crate::live_invocation::journal::{self, JournalEntry};
use crate::live_invocation::model_invoke::ModelFailure;
use crate::model_call_receipt::generic_enrichment::{
    enrich_generic_call, enrich_observed_generic_call, replay_generic_call, EnrichmentError,
    GenericAttemptMetadata,
};
use crate::model_call_receipt::{decode_receipt, ReceiptStage, RootBindingContext};
use crate::provider_adapter_sdk::{
    AdapterEvent, AdapterPoll, AdapterSettlement, AdapterUsage, RecordingAdapter,
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

fn logical_request(schema: &CompiledInteractionSchema) -> ModelInvocationRequest {
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

fn host<'a>() -> GenericAttemptMetadata<'a> {
    GenericAttemptMetadata {
        model_class: "fixture-model",
        provider_class: "fixture",
        adapter_identity: "bridge-test",
        provider_call_reference: "provider-call-1",
        reserved_at_ms: 10,
        dispatched_at_ms: Some(11),
        first_byte_at_ms: Some(12),
        completed_at_ms: Some(13),
        cost_estimate_micros: 3,
        provider_reported: None,
    }
}

fn bound_roots<'a>(
    schema: &'a CompiledInteractionSchema,
    seed: &'a LiveInvocationSeed,
    identity: &'a LiveInvocationId,
) -> RootBindingContext<'a> {
    RootBindingContext {
        agent_id: "agent",
        program_root: "root",
        deployment_root: "deployment",
        instance_root: "instance",
        invocation_id: identity.digest(),
        proposal_grammar_digest: schema.schema().digest(),
        deployment_policy_digest: &seed.deployment_policy,
        previous_attempt: 0,
    }
}

fn accepted_run(schema: &CompiledInteractionSchema) -> (LiveKernelRun, RecordingAdapter<'static>) {
    let response = document(schema);
    let events = vec![
        AdapterPoll::Event(AdapterEvent::Delta(response[..13].to_vec())),
        AdapterPoll::Event(AdapterEvent::Delta(response[13..].to_vec())),
        AdapterPoll::Event(AdapterEvent::Completed),
        AdapterPoll::Settled(AdapterSettlement {
            response_bytes: response,
            usage: AdapterUsage {
                tokens_in: None,
                tokens_out: None,
                cost_micros: None,
            },
        }),
    ];
    let mut recorder =
        RecordingAdapter::from_box(Box::new(Probe::new(events)), schema.schema().digest());
    let (run, granted) = kernel(schema, &mut recorder);
    assert_eq!(granted, 1);
    (run, recorder)
}

#[test]
fn accepted_actual_kernel_receipt_enriches_replays_and_decodes() {
    let schema = schema();
    let seed = seed(&schema);
    let identity = LiveInvocationId::derive(&seed);
    let roots = bound_roots(&schema, &seed, &identity);
    let request = logical_request(&schema);
    let (run, recorder) = accepted_run(&schema);
    let host = host();

    let receipt =
        enrich_generic_call(&run.journal, &seed, &request, &schema, &roots, &host).unwrap();
    assert_eq!(receipt.terminal_stage, ReceiptStage::Accepted);
    assert_eq!(receipt.first_byte_at_ms, Some(12));
    assert_eq!(receipt.completed_at_ms, Some(13));
    let rendered = receipt.render();
    assert_eq!(decode_receipt(rendered.as_bytes()), Ok(receipt.clone()));
    assert_eq!(
        replay_generic_call(
            rendered.as_bytes(),
            &run.journal,
            &seed,
            &request,
            &schema,
            &roots,
            &host
        ),
        Ok(())
    );
    assert!(recorder.observation().response_commitment().is_some());
}

#[test]
fn observed_adapter_enrichment_binds_the_real_transport_request_and_identity() {
    let schema = schema();
    let seed = seed(&schema);
    let identity = LiveInvocationId::derive(&seed);
    let roots = bound_roots(&schema, &seed, &identity);
    let request = logical_request(&schema);
    let response = document(&schema);
    let events = vec![
        AdapterEvent::Delta(response[..13].to_vec()),
        AdapterEvent::Delta(response[13..].to_vec()),
        AdapterEvent::Completed,
    ];
    let settlement = AdapterSettlement {
        response_bytes: response,
        usage: AdapterUsage {
            tokens_in: None,
            tokens_out: None,
            cost_micros: None,
        },
    };
    let mut script: Vec<_> = events.iter().cloned().map(AdapterPoll::Event).collect();
    script.push(AdapterPoll::Settled(settlement.clone()));
    let mut recorder =
        RecordingAdapter::from_box(Box::new(Probe::new(script)), schema.schema().digest());
    let (run, granted) = kernel(&schema, &mut recorder);
    assert_eq!(granted, 1);
    let transport = crate::provider_adapter_sdk::bridge::adapter_request_for(
        &request,
        &schema.provider_json_schema(),
    );
    let retained = crate::provider_adapter_sdk::ReplayInputs {
        request: &transport,
        events: &events,
        settlement: Some(&settlement),
        failure: None,
        start_refusal: None,
        cancellation: None,
        compiled_grammar_digest: schema.schema().digest(),
    };
    let metadata = host();
    let receipt = enrich_observed_generic_call(
        &run.journal,
        &seed,
        &request,
        &schema,
        &roots,
        &metadata,
        recorder.observation(),
        &retained,
    )
    .unwrap();
    crate::model_call_receipt::generic_enrichment::replay_observed_generic_call(
        receipt.render().as_bytes(),
        &run.journal,
        &seed,
        &request,
        &schema,
        &roots,
        &metadata,
        recorder.observation(),
        &retained,
    )
    .unwrap();
    assert_eq!(receipt.local_request_bytes, transport.request_bytes.len());
    assert_eq!(receipt.request_bytes_len, request.canonical_json().len());

    let mut wrong_identity = host();
    wrong_identity.adapter_identity = "other-adapter";
    assert_eq!(
        enrich_observed_generic_call(
            &run.journal,
            &seed,
            &request,
            &schema,
            &roots,
            &wrong_identity,
            recorder.observation(),
            &retained,
        ),
        Err(EnrichmentError::HostFacts)
    );
}

#[test]
fn generic_enrichment_rejects_root_grammar_policy_attempt_request_and_response_drift() {
    let schema = schema();
    let seed = seed(&schema);
    let identity = LiveInvocationId::derive(&seed);
    let roots = bound_roots(&schema, &seed, &identity);
    let request = logical_request(&schema);
    let (run, _) = accepted_run(&schema);
    let host = host();

    let mut wrong_roots = roots.clone();
    wrong_roots.program_root = "other-root";
    assert_eq!(
        enrich_generic_call(&run.journal, &seed, &request, &schema, &wrong_roots, &host),
        Err(EnrichmentError::Roots)
    );
    let mut wrong_grammar = roots.clone();
    wrong_grammar.proposal_grammar_digest = "sha256:other";
    assert_eq!(
        enrich_generic_call(
            &run.journal,
            &seed,
            &request,
            &schema,
            &wrong_grammar,
            &host
        ),
        Err(EnrichmentError::Roots)
    );
    let mut wrong_policy = roots.clone();
    wrong_policy.deployment_policy_digest = "other-policy";
    assert_eq!(
        enrich_generic_call(&run.journal, &seed, &request, &schema, &wrong_policy, &host),
        Err(EnrichmentError::Roots)
    );
    let mut wrong_attempt = roots.clone();
    wrong_attempt.previous_attempt = 1;
    assert_eq!(
        enrich_generic_call(
            &run.journal,
            &seed,
            &request,
            &schema,
            &wrong_attempt,
            &host
        ),
        Err(EnrichmentError::Roots)
    );
    let mut wrong_request = request.clone();
    wrong_request.task.push(b'!');
    assert_eq!(
        enrich_generic_call(&run.journal, &seed, &wrong_request, &schema, &roots, &host),
        Err(EnrichmentError::Request)
    );
    let mut wrong_response = run.journal.clone();
    for entry in &mut wrong_response {
        if let JournalEntry::ResponseRecorded { response, .. } = entry {
            response.push(b'!');
            break;
        }
    }
    assert_eq!(
        enrich_generic_call(&wrong_response, &seed, &request, &schema, &roots, &host),
        Err(EnrichmentError::Journal)
    );
}

#[test]
fn failed_cancelled_and_validated_unresolved_prefixes_remain_distinct_receipt_stages() {
    let schema = schema();
    let seed = seed(&schema);
    let identity = LiveInvocationId::derive(&seed);
    let roots = bound_roots(&schema, &seed, &identity);
    let request = logical_request(&schema);
    let metadata = host();

    for (failure, expected) in [
        (ModelFailure::ProviderError, ReceiptStage::Dispatched),
        (ModelFailure::Cancelled, ReceiptStage::Cancelled),
    ] {
        let script = vec![AdapterPoll::Failed {
            failure,
            attempted_bytes: 9,
        }];
        let mut recorder =
            RecordingAdapter::from_box(Box::new(Probe::new(script)), schema.schema().digest());
        let (run, granted) = kernel(&schema, &mut recorder);
        assert_eq!(granted, 0);
        let receipt =
            enrich_generic_call(&run.journal, &seed, &request, &schema, &roots, &metadata).unwrap();
        assert_eq!(receipt.terminal_stage, expected);
        assert_eq!(receipt.failure.as_deref(), Some(failure.as_str()));
    }

    let (run, _) = accepted_run(&schema);
    let intent_end = run
        .journal
        .iter()
        .position(|entry| matches!(entry, JournalEntry::RequestIntent { .. }))
        .unwrap();
    let prefix = run.journal[..=intent_end].to_vec();
    assert!(journal::validate(&prefix, identity.digest()).is_ok());
    let mut unresolved_host = host();
    unresolved_host.dispatched_at_ms = None;
    unresolved_host.first_byte_at_ms = None;
    unresolved_host.completed_at_ms = None;
    let receipt =
        enrich_generic_call(&prefix, &seed, &request, &schema, &roots, &unresolved_host).unwrap();
    assert_eq!(receipt.terminal_stage, ReceiptStage::Uncertain);
    assert_eq!(receipt.response_digest, None);
}
