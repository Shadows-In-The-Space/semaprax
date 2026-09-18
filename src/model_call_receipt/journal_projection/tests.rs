use super::*;
use crate::agent_runtime::AgentCancellation;
use crate::live_invocation::{
    fixture::*, identity::LiveInvocationSeed, kernel::*, model_invoke::*,
};

fn run() -> (LiveInvocationId, LiveKernelRun) {
    let identity = LiveInvocationId::derive(&LiveInvocationSeed {
        program_root: "root".into(),
        deployment_policy: "policy".into(),
        task: b"secret task".to_vec(),
        budget: 100,
        interaction_schema_digest: "grammar".into(),
        approved_providers: vec!["fixture".into()],
    });
    let cfg = LiveInvocationConfig {
        identity: &identity,
        task: b"secret task",
        deployment_binding: "policy",
        interaction_schema_digest: "grammar",
        max_turns: 2,
        max_response_bytes: 4096,
        requested_budget_per_turn: 10,
    };
    let cap = ModelInvokeCapability::grant("offline receipt test");
    let mut handler = FixtureModelHandler::scripted(vec![
        ModelInvocationOutcome::Settled(fixture_response(0, "secret response")),
        ModelInvocationOutcome::Settled(fixture_response(1, "second response")),
    ]);
    let mut decoder = FixtureProposalDecoder::new("grammar");
    let mut gate = FixtureAuthorizationGate::new(2);
    let mut budget = FixtureBudgetHook::new(10);
    let mut observer = FixtureObserver;
    let mut policy = FixturePolicy { total_turns: 2 };
    let result = run_live_invocation(
        &cfg,
        Vec::new(),
        &mut LiveInvocationHandlers {
            capability: &cap,
            handler: &mut handler,
            decoder: &mut decoder,
            gate: &mut gate,
            budget: &mut budget,
            observer: &mut observer,
            policy: &mut policy,
            effect: None,
            sink: None,
        },
        &AgentCancellation::new(),
    )
    .unwrap();
    assert_eq!(handler.calls, 2);
    (identity, result)
}

#[test]
fn actual_kernel_calls_project_replay_and_bind_audit_objects() {
    let (identity, run) = run();
    let receipts = run.model_call_receipts(&identity).unwrap();
    assert_eq!(receipts.len(), 2);
    for (turn, receipt) in receipts.iter().enumerate() {
        assert_eq!(receipt.turn(), turn as u32);
        assert_eq!(receipt.attempt(), 1);
        assert_eq!(receipt.value["stage"], "decoded");
        assert!(receipt.value["timing"].is_null());
        assert!(receipt.value["provider_reported"].is_null());
        assert!(receipt.value["cost"].is_null());
        assert!(!receipt.render().contains("secret"));
        let object = receipt.audit_object();
        assert_eq!(
            object.digest,
            crate::audit_capsule::sha256_digest(receipt.render().as_bytes())
        );
        assert_eq!(object.binds["session_id"], identity.digest());
        let mut capsule = crate::audit_capsule::ParsedCapsule {
            profile: crate::audit_capsule::Profile::AgentRun,
            subject: BTreeMap::from([("session_id".into(), identity.digest().into())]),
            objects: vec![object.clone()],
            associations: vec![],
            signatures: vec![],
            transparency: None,
            nonclaims: crate::audit_capsule::nonclaims::ALWAYS_REQUIRED_NONCLAIMS
                .iter()
                .map(|entry| (*entry).to_owned())
                .collect(),
        };
        let bytes = BTreeMap::from([(object.id.clone(), receipt.render().into_bytes())]);
        crate::audit_capsule::check_subject_bindings(&capsule).unwrap();
        crate::audit_capsule::check_object_bytes(&capsule, &bytes).unwrap();
        capsule
            .subject
            .insert("session_id".into(), "different invocation".into());
        assert!(crate::audit_capsule::check_subject_bindings(&capsule).is_err());
        let substituted = BTreeMap::from([(object.id, b"{}".to_vec())]);
        assert!(crate::audit_capsule::check_object_bytes(&capsule, &substituted).is_err());
    }
    replay_kernel_calls(&receipts, &run.journal, &identity).unwrap();
    verify_kernel_receipt_bytes(receipts[0].render().as_bytes(), &run.journal, &identity, 0)
        .unwrap();
    assert_eq!(
        verify_kernel_receipt_bytes(receipts[0].render().as_bytes(), &run.journal, &identity, 1),
        Err(ProjectionError::Mismatch)
    );
    let mut changed = receipts.clone();
    changed[0].value["response_bytes"] = json!(0);
    assert_eq!(
        replay_kernel_calls(&changed, &run.journal, &identity),
        Err(ProjectionError::Mismatch)
    );
}

#[test]
fn unresolved_intent_stays_uncertain_and_drift_is_refused() {
    let (identity, run) = run();
    let prefix = &run.journal[..2];
    let receipts = project_kernel_calls(prefix, &identity).unwrap();
    assert_eq!(receipts.len(), 1);
    assert_eq!(receipts[0].value["stage"], "uncertain");
    assert!(receipts[0].value["response_bytes"].is_null());
    assert_eq!(
        replay_kernel_calls(&receipts, &run.journal, &identity),
        Err(ProjectionError::Mismatch)
    );
    let mut changed = run.journal.clone();
    if let journal::JournalEntry::ResponseRecorded { response, .. } = &mut changed[2] {
        response.push(0);
    }
    assert_eq!(
        project_kernel_calls(&changed, &identity),
        Err(ProjectionError::ResponseDigest)
    );
    changed = run.journal.clone();
    changed.swap(0, 1);
    assert_eq!(
        project_kernel_calls(&changed, &identity),
        Err(ProjectionError::InvalidJournal)
    );
    let mut oversized = prefix.to_vec();
    if let journal::JournalEntry::RequestIntent { request_digest, .. } = &mut oversized[1] {
        *request_digest = "x".repeat(MAX_PROJECTION_BYTES / 6);
    }
    assert_eq!(
        project_kernel_calls(&oversized, &identity),
        Err(ProjectionError::Limit)
    );
}

#[test]
fn failed_attempt_does_not_turn_a_zero_sentinel_into_observed_usage() {
    let (identity, run) = run();
    let mut prefix = run.journal[..2].to_vec();
    prefix.push(journal::JournalEntry::ResponseFailed {
        turn: 0,
        failure: "timeout".into(),
        attempted_bytes: 0,
    });
    let receipts = project_kernel_calls(&prefix, &identity).unwrap();
    assert_eq!(receipts[0].value["failure"], "timeout");
    assert!(receipts[0].value["response_bytes"].is_null());
    prefix[2] = journal::JournalEntry::ResponseFailed {
        turn: 0,
        failure: "provider credential".into(),
        attempted_bytes: 0,
    };
    assert_eq!(
        project_kernel_calls(&prefix, &identity),
        Err(ProjectionError::InvalidJournal)
    );
}
