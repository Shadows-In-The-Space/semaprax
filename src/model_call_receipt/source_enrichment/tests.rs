use super::*;
use crate::agent_lifecycle::{CheckpointStore, CheckpointStoreError};
use crate::live_invocation::identity::digest;
use crate::live_invocation::source_journal::{
    source_prompt_digest, source_response_digest, SourceCheckpointSink, SourceInvocationBinding,
    SourceInvocationSeed, SourceJournalEntry, SourceReportedUsage,
};
use crate::streaming_proposal_decode::source::tests::{fixture_document, fixture_schema};

#[derive(Default)]
struct Store(String);
impl CheckpointStore for Store {
    fn commit(&mut self, _: u64, document: &str) -> Result<(), CheckpointStoreError> {
        self.0 = document.into();
        Ok(())
    }
}

fn hash(value: &str) -> String {
    digest(b"semaprax.source-enrichment.test\0", value.as_bytes())
}

fn seed() -> SourceInvocationSeed {
    SourceInvocationSeed {
        lifecycle_digest: hash("lifecycle"),
        source_revision: hash("source"),
        deployment_binding: hash("deployment"),
        task: b"task".to_vec(),
        task_budget: 4,
        proposal_schema_digest: hash("grammar"),
        response_limit: 64,
        max_iterations: 1,
        max_stages: 4,
        max_attempts: 2,
        max_steps_per_stage: 1,
        max_total_steps: 4,
        ceiling: 4,
        reservation_units: 2,
        unit: "unit.v1".into(),
        clock_domain: "clock.v1".into(),
        initial_millis: 0,
        deadline_millis: 10,
        program_root: Some(hash("program")),
    }
}

fn checkpoint() -> (RecoveredSourceCheckpoint, SourceInvocationSeed) {
    checkpoint_with_usage(None, false)
}

fn checkpoint_with_usage(
    reported: Option<SourceReportedUsage>,
    settled: bool,
) -> (RecoveredSourceCheckpoint, SourceInvocationSeed) {
    let seed = seed();
    let binding = if settled {
        SourceInvocationBinding::bind_execution(seed.clone(), &hash("evaluator")).unwrap()
    } else {
        SourceInvocationBinding::bind(seed.clone()).unwrap()
    };
    let prompt = b"prompt";
    let request = hash("request");
    let mut store = Store::default();
    let checkpoint = {
        let mut sink = SourceCheckpointSink::new(&mut store, binding.clone());
        sink.append_at(SourceJournalEntry::RunOpened, 0).unwrap();
        if settled {
            use crate::live_invocation::source_journal::SourceStageRole;
            for role in [SourceStageRole::Initialize, SourceStageRole::Observe] {
                sink.append_at(
                    SourceJournalEntry::StageReservation {
                        turn: 0,
                        attempt: None,
                        role,
                        fuel: 1,
                    },
                    0,
                )
                .unwrap();
            }
        }
        sink.append_at(
            SourceJournalEntry::TurnObserved {
                turn: 0,
                state: hash("state"),
                observation: digest(b"semaprax.source-observation.v2\0", b"observation bytes"),
                feedback: hash("feedback"),
            },
            1,
        )
        .unwrap();
        sink.append_at(
            SourceJournalEntry::AttemptIntent {
                turn: 0,
                attempt: 0,
                attempt_digest: binding.attempt_digest(
                    0,
                    0,
                    &request,
                    &source_prompt_digest(prompt),
                    prompt.len(),
                ),
                request_digest: request,
                prompt_digest: source_prompt_digest(prompt),
                request_bytes: prompt.len(),
                reserved_units: 2,
                response_limit: 64,
            },
            2,
        )
        .unwrap();
        if settled {
            let response = b"response".to_vec();
            sink.append_at(
                SourceJournalEntry::AttemptSettled {
                    turn: 0,
                    attempt: 0,
                    response: response.clone(),
                    response_digest: source_response_digest(&response),
                },
                3,
            )
            .unwrap();
            sink.append_at(
                SourceJournalEntry::AttemptUsage {
                    turn: 0,
                    attempt: 0,
                    reported,
                },
                4,
            )
            .unwrap();
        }
        sink.checkpoint().unwrap()
    };
    (checkpoint, seed)
}

fn host_metadata<'a>(
    checkpoint: &'a RecoveredSourceCheckpoint,
    seed: &'a SourceInvocationSeed,
) -> SourceAttemptMetadata<'a> {
    SourceAttemptMetadata {
        turn: 0,
        attempt: 0,
        observation: b"observation bytes",
        prompt: b"prompt",
        roots: RootBindingContext {
            agent_id: "agent",
            program_root: checkpoint.program_root().unwrap(),
            deployment_root: "deployment-root",
            instance_root: "instance-root",
            invocation_id: checkpoint.invocation(),
            proposal_grammar_digest: &seed.proposal_schema_digest,
            deployment_policy_digest: &seed.deployment_binding,
            previous_attempt: 0,
        },
        model_class: "model",
        provider_class: "provider",
        adapter_identity: "adapter",
        provider_call_reference: "call-0",
        reserved_at_ms: 1,
        dispatched_at_ms: Some(2),
        first_byte_at_ms: None,
        completed_at_ms: None,
        cost_estimate_micros: 7,
        provider_reported: None,
    }
}

fn admitted_checkpoint(
    schema: &crate::agent_proposal::CompiledAgentProposalSchema,
) -> (RecoveredSourceCheckpoint, SourceInvocationSeed, Vec<u8>) {
    let mut seed = seed();
    seed.source_revision = schema.source_revision().to_owned();
    seed.proposal_schema_digest = schema.schema().digest().to_owned();
    seed.response_limit = 4_096;
    let binding = SourceInvocationBinding::bind(seed.clone()).unwrap();
    let prompt = b"prompt";
    let request = hash("compiled-request");
    let response = fixture_document(schema, "accepted");
    let canonical = schema
        .decode(std::str::from_utf8(&response).unwrap())
        .unwrap()
        .canonical_json()
        .as_bytes()
        .to_vec();
    assert_eq!(canonical, response);
    let mut store = Store::default();
    let checkpoint = {
        let mut sink = SourceCheckpointSink::new(&mut store, binding.clone());
        sink.append_at(SourceJournalEntry::RunOpened, 0).unwrap();
        sink.append_at(
            SourceJournalEntry::TurnObserved {
                turn: 0,
                state: hash("compiled-state"),
                observation: digest(b"semaprax.source-observation.v2\0", b"observation bytes"),
                feedback: hash("compiled-feedback"),
            },
            1,
        )
        .unwrap();
        sink.append_at(
            SourceJournalEntry::AttemptIntent {
                turn: 0,
                attempt: 0,
                attempt_digest: binding.attempt_digest(
                    0,
                    0,
                    &request,
                    &source_prompt_digest(prompt),
                    prompt.len(),
                ),
                request_digest: request,
                prompt_digest: source_prompt_digest(prompt),
                request_bytes: prompt.len(),
                reserved_units: 2,
                response_limit: 4_096,
            },
            2,
        )
        .unwrap();
        sink.append_at(
            SourceJournalEntry::AttemptSettled {
                turn: 0,
                attempt: 0,
                response: response.clone(),
                response_digest: source_response_digest(&response),
            },
            3,
        )
        .unwrap();
        sink.append_at(
            SourceJournalEntry::ProposalAdmitted {
                turn: 0,
                attempt: 0,
                proposal_digest: digest(b"semaprax.source-proposal.v2\0", &canonical),
            },
            4,
        )
        .unwrap();
        sink.checkpoint().unwrap()
    };
    (checkpoint, seed, response)
}

#[test]
fn source_enrichment_retains_an_unresolved_intent_and_replays_exact_bytes() {
    let (checkpoint, seed) = checkpoint();
    let binding = SourceReceiptBindingInputs {
        source_revision: &seed.source_revision,
        deployment_binding: &seed.deployment_binding,
        task: &seed.task,
        task_budget: seed.task_budget,
        proposal_schema_digest: &seed.proposal_schema_digest,
        compiled_schema: None,
    };
    let mut metadata = host_metadata(&checkpoint, &seed);
    metadata.dispatched_at_ms = None;
    let receipts = checkpoint
        .rich_model_call_receipts(&binding, &[metadata])
        .unwrap();
    assert_eq!(receipts.len(), 1);
    assert_eq!(receipts[0].terminal_stage, ReceiptStage::Uncertain);
    assert_eq!(receipts[0].attempt, 1);
    assert_eq!(receipts[0].invocation_id, checkpoint.invocation());

    let mut first_byte_metadata = host_metadata(&checkpoint, &seed);
    first_byte_metadata.first_byte_at_ms = Some(3);
    let first_byte_receipts =
        enrich_source_calls(&checkpoint, &binding, &[first_byte_metadata]).unwrap();
    assert_eq!(
        first_byte_receipts[0].terminal_stage,
        ReceiptStage::FirstByte
    );

    let bytes = receipts
        .iter()
        .flat_map(|receipt| receipt.render().into_bytes())
        .collect::<Vec<_>>();
    let mut metadata = host_metadata(&checkpoint, &seed);
    metadata.dispatched_at_ms = None;
    replay_source_enriched_calls(&bytes, &checkpoint, &binding, &[metadata]).unwrap();
}

#[test]
fn source_enrichment_rejects_a_checkpoint_binding_or_host_root_mismatch() {
    let (checkpoint, seed) = checkpoint();
    let mut bad_revision = seed.source_revision.clone();
    bad_revision.replace_range(7..8, "0");
    let binding = SourceReceiptBindingInputs {
        source_revision: &bad_revision,
        deployment_binding: &seed.deployment_binding,
        task: &seed.task,
        task_budget: seed.task_budget,
        proposal_schema_digest: &seed.proposal_schema_digest,
        compiled_schema: None,
    };
    let metadata = host_metadata(&checkpoint, &seed);
    assert_eq!(
        enrich_source_calls(&checkpoint, &binding, &[metadata]),
        Err(SourceEnrichmentError::Binding)
    );

    let binding = SourceReceiptBindingInputs {
        source_revision: &seed.source_revision,
        deployment_binding: &seed.deployment_binding,
        task: &seed.task,
        task_budget: seed.task_budget,
        proposal_schema_digest: &seed.proposal_schema_digest,
        compiled_schema: None,
    };
    let mut metadata = host_metadata(&checkpoint, &seed);
    metadata.roots.program_root = "wrong";
    assert_eq!(
        enrich_source_calls(&checkpoint, &binding, &[metadata]),
        Err(SourceEnrichmentError::Root)
    );
}

#[test]
fn source_enrichment_checks_known_input_output_usage_without_normalizing_other_dimensions() {
    let journal_usage = SourceReportedUsage {
        total: Some(999),
        input: Some(11),
        output: None,
        reasoning: Some(5),
        cache_read: Some(3),
        cache_write: Some(2),
    };
    let (checkpoint, seed) = checkpoint_with_usage(Some(journal_usage), true);
    let binding = SourceReceiptBindingInputs {
        source_revision: &seed.source_revision,
        deployment_binding: &seed.deployment_binding,
        task: &seed.task,
        task_budget: seed.task_budget,
        proposal_schema_digest: &seed.proposal_schema_digest,
        compiled_schema: None,
    };
    let provider = ProviderReportedUsage {
        provider_call_id: "call-0".into(),
        tokens_in: 11,
        tokens_out: 7,
        provider_cost_micros: 13,
    };
    let mut metadata = host_metadata(&checkpoint, &seed);
    metadata.provider_reported = Some(&provider);
    let receipts = enrich_source_calls(&checkpoint, &binding, &[metadata]).unwrap();
    assert_eq!(receipts[0].provider_reported, Some(provider.clone()));

    // The journal did not report output, so a differing host output remains
    // independently retained rather than being compared to an unknown.
    let mismatched_provider = ProviderReportedUsage {
        tokens_out: 8,
        ..provider.clone()
    };
    let mut metadata = host_metadata(&checkpoint, &seed);
    metadata.provider_reported = Some(&mismatched_provider);
    assert!(enrich_source_calls(&checkpoint, &binding, &[metadata]).is_ok());

    let mismatched_provider = ProviderReportedUsage {
        tokens_in: 12,
        ..provider
    };
    let mut metadata = host_metadata(&checkpoint, &seed);
    metadata.provider_reported = Some(&mismatched_provider);
    assert_eq!(
        enrich_source_calls(&checkpoint, &binding, &[metadata]),
        Err(SourceEnrichmentError::HostFacts)
    );
}

#[test]
fn source_enrichment_rejects_a_known_output_mismatch_and_keeps_missing_usage_unknown() {
    let journal_usage = SourceReportedUsage {
        total: None,
        input: None,
        output: Some(7),
        reasoning: None,
        cache_read: None,
        cache_write: None,
    };
    let (checkpoint, seed) = checkpoint_with_usage(Some(journal_usage), true);
    let binding = SourceReceiptBindingInputs {
        source_revision: &seed.source_revision,
        deployment_binding: &seed.deployment_binding,
        task: &seed.task,
        task_budget: seed.task_budget,
        proposal_schema_digest: &seed.proposal_schema_digest,
        compiled_schema: None,
    };
    let mut metadata = host_metadata(&checkpoint, &seed);
    let provider = ProviderReportedUsage {
        provider_call_id: "call-0".into(),
        tokens_in: 11,
        tokens_out: 8,
        provider_cost_micros: 13,
    };
    metadata.provider_reported = Some(&provider);
    assert_eq!(
        enrich_source_calls(&checkpoint, &binding, &[metadata]),
        Err(SourceEnrichmentError::HostFacts)
    );

    // A missing independently retained provider report cannot be completed
    // from journal evidence; the rich receipt keeps usage absent.
    let mut metadata = host_metadata(&checkpoint, &seed);
    metadata.provider_reported = None;
    let receipts = enrich_source_calls(&checkpoint, &binding, &[metadata]).unwrap();
    assert_eq!(receipts[0].provider_reported, None);

    // The priced/legacy journal's explicit unknown state likewise does not
    // contradict a separately retained complete host report.
    let (unknown_checkpoint, unknown_seed) = checkpoint_with_usage(None, true);
    let unknown_binding = SourceReceiptBindingInputs {
        source_revision: &unknown_seed.source_revision,
        deployment_binding: &unknown_seed.deployment_binding,
        task: &unknown_seed.task,
        task_budget: unknown_seed.task_budget,
        proposal_schema_digest: &unknown_seed.proposal_schema_digest,
        compiled_schema: None,
    };
    let mut metadata = host_metadata(&unknown_checkpoint, &unknown_seed);
    let provider = ProviderReportedUsage {
        provider_call_id: "call-0".into(),
        tokens_in: 999,
        tokens_out: 888,
        provider_cost_micros: 13,
    };
    metadata.provider_reported = Some(&provider);
    assert!(enrich_source_calls(&unknown_checkpoint, &unknown_binding, &[metadata]).is_ok());
}

#[test]
fn source_enrichment_replays_an_admitted_compiled_proposal() {
    let schema = fixture_schema();
    let (checkpoint, seed, response) = admitted_checkpoint(&schema);
    let binding = SourceReceiptBindingInputs {
        source_revision: &seed.source_revision,
        deployment_binding: &seed.deployment_binding,
        task: &seed.task,
        task_budget: seed.task_budget,
        proposal_schema_digest: &seed.proposal_schema_digest,
        compiled_schema: Some(&schema),
    };
    let metadata = host_metadata(&checkpoint, &seed);
    let receipts = enrich_source_calls(&checkpoint, &binding, &[metadata]).unwrap();
    assert_eq!(receipts[0].terminal_stage, ReceiptStage::Decoded);
    assert_eq!(
        receipts[0].proposal_digest,
        Some(commit_proposal_bytes(&response))
    );
    assert_eq!(
        receipts[0].response_digest,
        Some(commit_response_bytes(&response))
    );

    let mut submitted = receipts[0].render().into_bytes();
    submitted[0] ^= 1;
    let metadata = host_metadata(&checkpoint, &seed);
    assert_eq!(
        replay_source_enriched_calls(&submitted, &checkpoint, &binding, &[metadata]),
        Err(SourceEnrichmentError::Mismatch)
    );

    let wrong_binding = SourceReceiptBindingInputs {
        proposal_schema_digest: "sha256:wrong",
        ..binding
    };
    let metadata = host_metadata(&checkpoint, &seed);
    assert_eq!(
        enrich_source_calls(&checkpoint, &wrong_binding, &[metadata]),
        Err(SourceEnrichmentError::Binding)
    );
}
