//! Cumulative source-model reservation boundaries over the checked live route.

use super::*;
use crate::agent_lifecycle::iterative::driver::{ProposalRequest, ProposalSource};
use crate::live_invocation::source_journal::{SourceCheckpointSink, SourceTerminalStatus};
use crate::live_invocation::{CumulativeBudgetLedger, SourceInvocationClock};
use std::cell::Cell;

struct CountingSource {
    inner: Source,
    proposal_requests: Cell<usize>,
}

impl ProposalSource for CountingSource {
    fn checkpoint_policy(&self) -> Option<SourceProposalPolicy<'_>> {
        self.inner.checkpoint_policy()
    }

    fn checkpoint_attempt_identity(
        &self,
        request: &ProposalRequest<'_>,
    ) -> Result<SourceAttemptIdentity, Vec<Diagnostic>> {
        self.proposal_requests
            .set(self.proposal_requests.get().saturating_add(1));
        self.inner.checkpoint_attempt_identity(request)
    }

    fn propose_checkpointed(
        &mut self,
        request: ProposalRequest<'_>,
        sink: &mut SourceCheckpointSink<'_>,
        ledger: &mut CumulativeBudgetLedger<'_>,
        clock: &dyn SourceInvocationClock,
    ) -> SourceProposalOutcome {
        self.inner
            .propose_checkpointed(request, sink, ledger, clock)
    }

    fn propose(&mut self, request: ProposalRequest<'_>) -> Result<String, Vec<Diagnostic>> {
        self.inner.propose(request)
    }
}

#[test]
fn model_reservation_zero_exact_and_one_over_refuse_before_an_extra_dispatch() {
    let compiled = lifecycle();
    let task = task();
    let clock = Clock { now: 1 };
    let cancellation = AgentCancellation::default();

    // One source attempt reserves two opaque operator units. The source loop
    // needs more than one attempt, so both the exact ceiling and one unit
    // above it must retain the same single admitted reservation: the extra
    // unit cannot fund a second attempt.
    for (ceiling, expected_requests, expected_dispatches, expected_reserved) in
        [(0, 1, 0, 0), (2, 2, 1, 2), (3, 2, 1, 2)]
    {
        let mut policy = policy(ceiling);
        policy.reservation_units = 2;
        let mut source = CountingSource {
            inner: Source {
                responses: vec![Source::valid_response(&compiled); 2],
                calls: 0,
                deployment: DEPLOYMENT.into(),
                response_limit: 4096,
                reservation_units: 2,
            },
            proposal_requests: Cell::new(0),
        };
        let mut read = Read { calls: 0 };
        let mut store = Store::default();

        let failure = compiled
            .run_live_durable(
                request(&task, &policy, &clock, &cancellation),
                &mut source,
                &mut read,
                &mut store,
            )
            .err()
            .expect("the reservation boundary stops this multi-turn fixture");
        let checkpoint = failure
            .checkpoint
            .as_ref()
            .expect("the durable refusal retains terminal accounting evidence");

        assert_eq!(
            failure.selected,
            Some(SourceTerminalStatus::BudgetExhausted),
            "ceiling {ceiling}"
        );
        assert_eq!(
            (
                source.proposal_requests.get(),
                source.inner.calls,
                failure.model_dispatches,
                read.calls,
                failure.effect_dispatches,
            ),
            (
                expected_requests,
                expected_dispatches,
                expected_dispatches as u32,
                expected_dispatches,
                expected_dispatches as u32
            ),
            "ceiling {ceiling}"
        );
        assert_eq!(
            checkpoint.committed_reserved_units(),
            expected_reserved,
            "ceiling {ceiling}"
        );
        let terminal = checkpoint.terminal_snapshot().unwrap();
        let terminal_evidence = terminal.evidence().to_vec();
        let terminal_generation = checkpoint.generation();
        let evidence: serde_json::Value = serde_json::from_slice(terminal.evidence()).unwrap();
        assert_eq!(evidence["committed_model_units"], expected_reserved);
        assert_eq!(evidence["attempts"], expected_dispatches);

        let checkpoint_document = store.document.clone();
        let mut recovered_source = CountingSource {
            inner: Source {
                responses: Vec::new(),
                calls: 0,
                deployment: DEPLOYMENT.into(),
                response_limit: 4096,
                reservation_units: 2,
            },
            proposal_requests: Cell::new(0),
        };
        let mut recovered_read = Read { calls: 0 };
        let mut recovered_store = Store::default();
        let recovered = compiled
            .run_live_durable(
                SourceLiveRequest {
                    task: &task,
                    budget: IterativeBudget::default(),
                    policy: &policy,
                    clock: &clock,
                    cancellation: &cancellation,
                    checkpoint: Some(&checkpoint_document),
                },
                &mut recovered_source,
                &mut recovered_read,
                &mut recovered_store,
            )
            .expect("terminal budget receipt is read-only on recovery");
        assert_eq!(
            (
                recovered_source.proposal_requests.get(),
                recovered_source.inner.calls,
                recovered_read.calls,
                recovered.model_dispatches,
                recovered.effect_dispatches,
            ),
            (0, 0, 0, 0, 0),
            "ceiling {ceiling}"
        );
        assert_eq!(recovered.checkpoint.generation(), terminal_generation);
        assert_eq!(
            recovered.checkpoint.committed_reserved_units(),
            expected_reserved,
            "ceiling {ceiling}"
        );
        assert_eq!(
            recovered.checkpoint.terminal_snapshot().unwrap().evidence(),
            terminal_evidence,
            "ceiling {ceiling}"
        );
    }
}
