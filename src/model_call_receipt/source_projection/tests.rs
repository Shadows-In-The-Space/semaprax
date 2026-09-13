use super::*;
use crate::agent_lifecycle::{CheckpointStore, CheckpointStoreError};
use crate::live_invocation::identity::digest;
use crate::live_invocation::pricing::{ProviderChargeObservation, ValidatedPricing};
use crate::live_invocation::source_journal::{
    source_prompt_digest, source_response_digest, SourceCheckpointSink, SourceInvocationBinding,
    SourceInvocationSeed, SourceIoLimits, SourceJournalEntry, SourceProposalRefusal,
    SourceReportedUsage, SourceStageRole,
};

#[derive(Default)]
struct Store(String);

impl CheckpointStore for Store {
    fn commit(&mut self, _: u64, document: &str) -> Result<(), CheckpointStoreError> {
        self.0 = document.to_owned();
        Ok(())
    }
}

fn hash(value: &str) -> String {
    digest(b"semaprax.source-projection.test\0", value.as_bytes())
}

fn binding() -> SourceInvocationBinding {
    SourceInvocationBinding::bind(SourceInvocationSeed {
        lifecycle_digest: hash("lifecycle"),
        source_revision: hash("source"),
        deployment_binding: hash("deployment"),
        task: b"task".to_vec(),
        task_budget: 1,
        proposal_schema_digest: hash("proposal"),
        response_limit: 32,
        max_iterations: 1,
        max_stages: 4,
        max_attempts: 1,
        max_steps_per_stage: 1,
        max_total_steps: 4,
        ceiling: 1,
        reservation_units: 1,
        unit: "unit.v1".into(),
        clock_domain: "clock.v1".into(),
        initial_millis: 0,
        deadline_millis: 10,
        program_root: None,
    })
    .unwrap()
}

fn priced_v5_binding() -> SourceInvocationBinding {
    let mut seed = SourceInvocationSeed {
        lifecycle_digest: hash("priced-lifecycle"),
        source_revision: hash("priced-source"),
        deployment_binding: hash("priced-deployment"),
        task: b"priced task".to_vec(),
        task_budget: 1,
        proposal_schema_digest: hash("priced-proposal"),
        response_limit: 32,
        max_iterations: 1,
        max_stages: 8,
        max_attempts: 2,
        max_steps_per_stage: 4,
        max_total_steps: 32,
        ceiling: 2,
        reservation_units: 1,
        unit: "unit.v1".into(),
        clock_domain: "clock.v1".into(),
        initial_millis: 0,
        deadline_millis: 20,
        program_root: None,
    };
    seed.task.extend_from_slice(b" v5");
    SourceInvocationBinding::bind_priced_execution(
        seed,
        &hash("evaluator"),
        ValidatedPricing::new("unit.v1".into(), "USD".into(), 2, 7, 20).unwrap(),
    )
    .unwrap()
    .with_io_limits(
        SourceIoLimits {
            max_request_bytes: 32,
            max_total_request_bytes: 64,
            max_total_response_bytes: 64,
        },
        None,
    )
    .unwrap()
}

#[test]
fn source_checkpoint_projects_exact_intent_settlement_and_replays() {
    let binding = binding();
    let request = hash("request");
    let prompt = source_prompt_digest(b"prompt bytes");
    let response = b"response".to_vec();
    let mut store = Store::default();
    let checkpoint = {
        let mut sink = SourceCheckpointSink::new(&mut store, binding.clone());
        sink.append_at(SourceJournalEntry::RunOpened, 0).unwrap();
        sink.append_at(
            SourceJournalEntry::TurnObserved {
                turn: 0,
                state: hash("state"),
                observation: hash("observation"),
                feedback: hash("feedback"),
            },
            1,
        )
        .unwrap();
        sink.append_at(
            SourceJournalEntry::AttemptIntent {
                turn: 0,
                attempt: 0,
                attempt_digest: binding.attempt_digest(0, 0, &request, &prompt, 7),
                request_digest: request.clone(),
                prompt_digest: prompt.clone(),
                request_bytes: 7,
                reserved_units: 1,
                response_limit: 32,
            },
            2,
        )
        .unwrap();
        let uncertain = sink.checkpoint().unwrap();
        let uncertain_receipts = project_source_calls(&uncertain).unwrap();
        assert_eq!(uncertain_receipts[0].value["stage"], "uncertain");
        assert!(uncertain_receipts[0].value["provider_reported"].is_null());
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
                proposal_digest: hash("proposal-result"),
            },
            4,
        )
        .unwrap();
        sink.checkpoint().unwrap()
    };

    let receipts = project_source_calls(&checkpoint).unwrap();
    assert_eq!(receipts.len(), 1);
    let receipt = &receipts[0];
    assert_eq!(receipt.turn(), 0);
    assert_eq!(receipt.attempt(), 0);
    assert_eq!(receipt.value["journal_profile"], "source-v1");
    assert_eq!(receipt.value["request_digest"], request);
    assert_eq!(receipt.value["source_prompt_digest"], prompt);
    assert_eq!(
        receipt.value["response_digest"],
        source_response_digest(&response)
    );
    assert_eq!(receipt.value["response_bytes"], response.len());
    assert_eq!(receipt.value["stage"], "decoded");
    assert!(receipt.value["timing"].is_null());
    assert!(receipt.value["provider_reported"].is_null());
    assert!(receipt.value["cost"].is_null());
    replay_source_calls(&receipts, &checkpoint).unwrap();
    verify_source_receipt_bytes(
        receipt.render().as_bytes(),
        &checkpoint,
        receipt.turn(),
        receipt.attempt(),
    )
    .unwrap();

    let mut changed = receipts.clone();
    changed[0].value["source_prompt_digest"] = json!(hash("other"));
    assert_eq!(
        replay_source_calls(&changed, &checkpoint),
        Err(ProjectionError::Mismatch)
    );
}

#[test]
fn priced_v5_checkpoint_projects_observed_money_and_a_decode_retry() {
    let binding = priced_v5_binding();
    let mut store = Store::default();
    let checkpoint = {
        let mut sink = SourceCheckpointSink::new(&mut store, binding);
        sink.append_at(SourceJournalEntry::RunOpened, 0).unwrap();
        for role in [SourceStageRole::Initialize, SourceStageRole::Observe] {
            sink.append_at(
                SourceJournalEntry::StageReservation {
                    turn: 0,
                    attempt: None,
                    role,
                    fuel: 4,
                },
                1,
            )
            .unwrap();
        }
        sink.append_at(
            SourceJournalEntry::TurnObserved {
                turn: 0,
                state: hash("priced-state"),
                observation: hash("priced-observation"),
                feedback: hash("priced-feedback"),
            },
            2,
        )
        .unwrap();
        let first_intent = sink
            .attempt_intent(0, 0, hash("priced-request-0"), hash("priced-prompt-0"), 8)
            .unwrap();
        sink.append_at(first_intent, 3).unwrap();
        sink.append_at(
            SourceJournalEntry::AttemptSettled {
                turn: 0,
                attempt: 0,
                response: b"bad proposal".to_vec(),
                response_digest: source_response_digest(b"bad proposal"),
            },
            4,
        )
        .unwrap();
        let usage = sink
            .priced_attempt_usage(
                0,
                0,
                Some(SourceReportedUsage {
                    total: Some(9),
                    input: Some(5),
                    output: Some(4),
                    reasoning: None,
                    cache_read: None,
                    cache_write: None,
                }),
                ProviderChargeObservation::Observed {
                    currency: "USD".into(),
                    minor_unit_exponent: 2,
                    amount_minor: 7,
                },
            )
            .unwrap();
        sink.append_at(usage, 4).unwrap();
        sink.append_at(
            SourceJournalEntry::ProposalRefused {
                turn: 0,
                attempt: 0,
                reason: SourceProposalRefusal::MalformedDecode,
            },
            5,
        )
        .unwrap();
        let retry = sink
            .attempt_intent(0, 1, hash("priced-request-1"), hash("priced-prompt-1"), 8)
            .unwrap();
        sink.append_at(retry, 6).unwrap();
        sink.checkpoint().unwrap()
    };

    let receipts = project_source_calls(&checkpoint).unwrap();
    assert_eq!(receipts.len(), 2);
    assert_eq!(receipts[0].value["journal_profile"], "source-v5");
    assert_eq!(receipts[0].value["stage"], "rejected");
    assert_eq!(receipts[0].value["provider_reported"]["total"], 9);
    assert_eq!(receipts[0].value["cost"]["currency"], "USD");
    assert_eq!(receipts[0].value["cost"]["amount_minor"], 7);
    assert_eq!(receipts[1].attempt(), 1);
    assert_eq!(receipts[1].value["stage"], "uncertain");
    replay_source_calls(&receipts, &checkpoint).unwrap();
}
