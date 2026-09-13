use super::*;

fn hash(label: &str) -> String {
    crate::live_invocation::identity::digest(
        b"semaprax.source-journal.io-v5-test\0",
        label.as_bytes(),
    )
}

fn binding(limits: SourceIoLimits) -> SourceInvocationBinding {
    SourceInvocationBinding::bind_execution(
        SourceInvocationSeed {
            lifecycle_digest: hash("lifecycle"),
            source_revision: hash("revision"),
            deployment_binding: hash("deployment"),
            task: b"I/O test".to_vec(),
            task_budget: 1,
            proposal_schema_digest: hash("schema"),
            response_limit: 4,
            max_iterations: 2,
            max_stages: 8,
            max_attempts: 2,
            max_steps_per_stage: 10,
            max_total_steps: 80,
            ceiling: 2,
            reservation_units: 1,
            unit: "unit.v1".into(),
            clock_domain: "clock.v1".into(),
            initial_millis: 0,
            deadline_millis: 10,
            program_root: None,
        },
        &hash("evaluator"),
    )
    .unwrap()
    .with_io_limits(limits, None)
    .unwrap()
}

fn intent(binding: &SourceInvocationBinding, attempt: u32) -> SourceJournalEntry {
    let request_digest = hash("request");
    let prompt_digest = hash("prompt");
    SourceJournalEntry::AttemptIntent {
        turn: 0,
        attempt,
        attempt_digest: binding.attempt_digest(0, attempt, &request_digest, &prompt_digest, 3),
        request_digest,
        prompt_digest,
        request_bytes: 3,
        reserved_units: 1,
        response_limit: 4,
    }
}

#[test]
fn reserve_accepts_exact_caps_and_refuses_overflow_without_mutating() {
    let limits = SourceIoLimits {
        max_request_bytes: 3,
        max_total_request_bytes: 3,
        max_total_response_bytes: 4,
    };
    let mut totals = SourceIoTotals::default();
    totals.reserve(&limits, 3, 4).unwrap();
    assert_eq!(
        totals,
        SourceIoTotals {
            reserved_request_bytes: 3,
            reserved_response_bytes: 4,
            observed_response_bytes: 0,
            unknown_response_reservation_bytes: 4,
        }
    );
    let exact = totals.clone();
    assert_eq!(
        totals.reserve(&limits, 1, 1),
        Err(SourceJournalError::Capacity)
    );
    assert_eq!(totals, exact);

    let wide = SourceIoLimits {
        max_request_bytes: usize::MAX,
        max_total_request_bytes: u64::MAX,
        max_total_response_bytes: u64::MAX,
    };
    let mut overflowing = SourceIoTotals {
        reserved_request_bytes: u64::MAX,
        ..SourceIoTotals::default()
    };
    let before = overflowing.clone();
    assert_eq!(
        overflowing.reserve(&wide, 1, 1),
        Err(SourceJournalError::Capacity)
    );
    assert_eq!(overflowing, before);
}

#[test]
fn fold_distinguishes_settled_observation_from_failed_unknown_reservation() {
    let binding = binding(SourceIoLimits {
        max_request_bytes: 3,
        max_total_request_bytes: 6,
        max_total_response_bytes: 8,
    });
    let settled = SourceJournalEntry::AttemptSettled {
        turn: 0,
        attempt: 0,
        response: b"ok".to_vec(),
        response_digest: source_response_digest(b"ok"),
    };
    assert_eq!(
        fold(&binding, &[intent(&binding, 0), settled]).unwrap(),
        Some(SourceIoTotals {
            reserved_request_bytes: 3,
            reserved_response_bytes: 4,
            observed_response_bytes: 2,
            unknown_response_reservation_bytes: 0,
        })
    );
    let failed = SourceJournalEntry::AttemptFailed {
        turn: 0,
        attempt: 0,
        reason: SourceAttemptFailure::Timeout,
        attempted_bytes: 2,
    };
    assert_eq!(
        fold(&binding, &[intent(&binding, 0), failed]).unwrap(),
        Some(SourceIoTotals {
            reserved_request_bytes: 3,
            reserved_response_bytes: 4,
            observed_response_bytes: 0,
            unknown_response_reservation_bytes: 4,
        })
    );
}
