use super::*;
use crate::outbound_host_adapter::{AdapterFailure, HttpMethod};
use std::cell::Cell;
use std::rc::Rc;

fn identity(n: usize) -> DeliveryIdentity {
    DeliveryIdentity::new("deployment", format!("invocation-{n}"), format!("key-{n}")).unwrap()
}

fn request(n: usize) -> PreparedRequest {
    PreparedRequest {
        method: HttpMethod::Post,
        endpoint: "https://collector.example.test/v1/metrics".into(),
        headers: vec![("idempotency-key".into(), format!("key-{n}"))],
        body: format!("metric-{n}").into_bytes(),
        deadline_ms: 1000,
        max_redirects: 0,
        max_response_bytes: 128,
    }
}

struct Store {
    outcomes: Vec<CheckpointCommit>,
    checkpoints: Vec<LedgerCheckpoint>,
    commits: Rc<Cell<usize>>,
}

impl LedgerCheckpointStore for Store {
    fn commit(&mut self, checkpoint: &LedgerCheckpoint) -> CheckpointCommit {
        self.checkpoints.push(checkpoint.clone());
        self.commits.set(self.commits.get() + 1);
        self.outcomes.remove(0)
    }
}

#[test]
fn intent_is_durably_acknowledged_before_the_physical_export() {
    let mut ledger = HostDeliveryLedger::new(2).unwrap();
    let commits = Rc::new(Cell::new(0));
    let mut store = Store {
        outcomes: vec![CheckpointCommit::Committed, CheckpointCommit::Committed],
        checkpoints: Vec::new(),
        commits: Rc::clone(&commits),
    };
    let calls = Cell::new(0);
    let outcome = ledger
        .reconcile_durable(identity(1), &request(1), &mut store, |_| {
            assert_eq!(commits.get(), 1, "intent ACK precedes dispatch");
            calls.set(calls.get() + 1);
            DeliveryDisposition::Accepted { status: 202 }
        })
        .unwrap();
    assert!(outcome.was_dispatched());
    assert_eq!(calls.get(), 1);
    assert_eq!(store.checkpoints.len(), 2);
    assert!(matches!(
        store.checkpoints[0]
            .lookup(&identity(1), &request(1))
            .unwrap()
            .disposition(),
        DeliveryDisposition::Uncertain {
            reason: AdapterFailure::Transport
        }
    ));
    assert_eq!(
        store.checkpoints[1]
            .lookup(&identity(1), &request(1))
            .unwrap()
            .disposition(),
        &DeliveryDisposition::Accepted { status: 202 }
    );
}

#[test]
fn failed_or_uncertain_intent_commit_never_dispatches() {
    for expected in [CheckpointCommit::NotCommitted, CheckpointCommit::Uncertain] {
        let mut ledger = HostDeliveryLedger::new(1).unwrap();
        let mut store = Store {
            outcomes: vec![expected],
            checkpoints: Vec::new(),
            commits: Rc::new(Cell::new(0)),
        };
        let calls = Cell::new(0);
        let outcome = ledger
            .reconcile_durable(identity(1), &request(1), &mut store, |_| {
                calls.set(calls.get() + 1);
                DeliveryDisposition::Accepted { status: 200 }
            })
            .unwrap();
        assert_eq!(calls.get(), 0);
        match expected {
            CheckpointCommit::NotCommitted => {
                assert_eq!(outcome, DurableLedgerOutcome::IntentNotCommitted);
                assert!(ledger.is_empty());
            }
            CheckpointCommit::Uncertain => {
                assert!(matches!(outcome, DurableLedgerOutcome::IntentUncertain(_)));
                assert_eq!(ledger.len(), 1);
            }
            CheckpointCommit::Committed => unreachable!(),
        }
    }
}

#[test]
fn lost_settlement_ack_is_sticky_uncertainty_and_never_auto_retries() {
    for final_commit in [CheckpointCommit::NotCommitted, CheckpointCommit::Uncertain] {
        let mut ledger = HostDeliveryLedger::new(1).unwrap();
        let mut store = Store {
            outcomes: vec![CheckpointCommit::Committed, final_commit],
            checkpoints: Vec::new(),
            commits: Rc::new(Cell::new(0)),
        };
        let outcome = ledger
            .reconcile_durable(identity(1), &request(1), &mut store, |_| {
                DeliveryDisposition::Accepted { status: 202 }
            })
            .unwrap();
        assert!(matches!(
            outcome,
            DurableLedgerOutcome::SettlementUncertain(_)
        ));
        let calls = Cell::new(0);
        let replay = ledger
            .reconcile_durable(identity(1), &request(1), &mut store, |_| {
                calls.set(calls.get() + 1);
                DeliveryDisposition::Accepted { status: 200 }
            })
            .unwrap();
        assert!(matches!(replay, DurableLedgerOutcome::Replayed(_)));
        assert_eq!(calls.get(), 0);
    }
}

#[test]
fn invalid_terminal_checkpoint_restores_the_acknowledged_uncertainty() {
    let mut ledger = HostDeliveryLedger::new(1).unwrap();
    let mut store = Store {
        outcomes: vec![CheckpointCommit::Committed],
        checkpoints: Vec::new(),
        commits: Rc::new(Cell::new(0)),
    };
    assert_eq!(
        ledger.reconcile_durable(identity(1), &request(1), &mut store, |_| {
            DeliveryDisposition::Accepted { status: 0 }
        }),
        Err(DurableLedgerRefusal::Checkpoint(
            LedgerCheckpointRefusal::Malformed
        ))
    );
    assert_eq!(store.checkpoints.len(), 1);

    let calls = Cell::new(0);
    let replay = ledger
        .reconcile_durable(identity(1), &request(1), &mut store, |_| {
            calls.set(calls.get() + 1);
            DeliveryDisposition::Accepted { status: 200 }
        })
        .unwrap();
    assert!(matches!(replay, DurableLedgerOutcome::Replayed(_)));
    assert!(matches!(
        replay.record().unwrap().disposition(),
        DeliveryDisposition::Uncertain {
            reason: AdapterFailure::Transport
        }
    ));
    assert_eq!(calls.get(), 0);
}

#[test]
fn exact_authenticated_restart_replays_without_a_dispatch_factory() {
    let mut ledger = HostDeliveryLedger::new(2).unwrap();
    let mut store = Store {
        outcomes: vec![CheckpointCommit::Committed, CheckpointCommit::Committed],
        checkpoints: Vec::new(),
        commits: Rc::new(Cell::new(0)),
    };
    ledger
        .reconcile_durable(identity(1), &request(1), &mut store, |_| {
            DeliveryDisposition::Accepted { status: 204 }
        })
        .unwrap();
    let checkpoint = store.checkpoints.last().unwrap();
    let wire = checkpoint.render();
    let capability =
        LedgerRestoreCapability::grant_for_trusted_host(checkpoint.digest(), 2).unwrap();
    let mut restored =
        HostDeliveryLedger::restore_authenticated(wire.as_bytes(), capability).unwrap();
    let calls = Cell::new(0);
    let mut unused_store = Store {
        outcomes: Vec::new(),
        checkpoints: Vec::new(),
        commits: Rc::new(Cell::new(0)),
    };
    let replay = restored
        .reconcile_durable(identity(1), &request(1), &mut unused_store, |_| {
            calls.set(calls.get() + 1);
            DeliveryDisposition::Accepted { status: 200 }
        })
        .unwrap();
    assert!(matches!(replay, DurableLedgerOutcome::Replayed(_)));
    assert_eq!(calls.get(), 0);
    assert!(unused_store.checkpoints.is_empty());

    let wrong_capacity =
        LedgerRestoreCapability::grant_for_trusted_host(checkpoint.digest(), 1).unwrap();
    assert_eq!(
        HostDeliveryLedger::restore_authenticated(wire.as_bytes(), wrong_capacity),
        Err(LedgerRestoreRefusal::CapacityMismatch)
    );
    let mut changed = wire.into_bytes();
    changed[0] ^= 1;
    let capability =
        LedgerRestoreCapability::grant_for_trusted_host(checkpoint.digest(), 2).unwrap();
    assert!(matches!(
        HostDeliveryLedger::restore_authenticated(&changed, capability),
        Err(LedgerRestoreRefusal::Checkpoint(
            LedgerCheckpointRefusal::BindingMismatch
        ))
    ));
}
