//! Explicit durable ACK ordering for outbound delivery reconciliation.
//!
//! Storage is injected and typed: `Committed` is the only result that permits
//! physical dispatch. An uncertain intent commit never dispatches; an
//! uncertain terminal commit falls back to the already persisted provisional
//! uncertainty. Checkpoint bytes remain evidence, never authority. Restart
//! requires a separately granted exact-digest restore capability.

use super::*;
use crate::outbound_host_adapter::{valid_sha256, AdapterFailure};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CheckpointCommit {
    Committed,
    NotCommitted,
    Uncertain,
}

pub trait LedgerCheckpointStore {
    fn commit(&mut self, checkpoint: &LedgerCheckpoint) -> CheckpointCommit;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DurableLedgerOutcome {
    Dispatched(LedgerRecord),
    Replayed(LedgerRecord),
    IntentNotCommitted,
    IntentUncertain(LedgerRecord),
    SettlementUncertain(LedgerRecord),
}

impl DurableLedgerOutcome {
    pub fn record(&self) -> Option<&LedgerRecord> {
        match self {
            Self::Dispatched(record)
            | Self::Replayed(record)
            | Self::IntentUncertain(record)
            | Self::SettlementUncertain(record) => Some(record),
            Self::IntentNotCommitted => None,
        }
    }

    pub fn was_dispatched(&self) -> bool {
        matches!(self, Self::Dispatched(_) | Self::SettlementUncertain(_))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DurableLedgerRefusal {
    Ledger(LedgerRefusal),
    Checkpoint(LedgerCheckpointRefusal),
}

impl From<LedgerRefusal> for DurableLedgerRefusal {
    fn from(value: LedgerRefusal) -> Self {
        Self::Ledger(value)
    }
}

impl From<LedgerCheckpointRefusal> for DurableLedgerRefusal {
    fn from(value: LedgerCheckpointRefusal) -> Self {
        Self::Checkpoint(value)
    }
}

/// Move-only assertion by a trusted storage host that these exact bytes and
/// digest were loaded from its authenticated durable namespace. Constructing
/// it does not authenticate untrusted bytes; the caller owns that provenance.
pub struct LedgerRestoreCapability {
    expected_digest: String,
    expected_capacity: usize,
}

impl LedgerRestoreCapability {
    pub fn grant_for_trusted_host(
        expected_digest: impl Into<String>,
        expected_capacity: usize,
    ) -> Result<Self, LedgerRestoreRefusal> {
        let expected_digest = expected_digest.into();
        if !valid_sha256(&expected_digest)
            || expected_capacity == 0
            || expected_capacity > MAX_LEDGER_ENTRIES
        {
            return Err(LedgerRestoreRefusal::InvalidCapability);
        }
        Ok(Self {
            expected_digest,
            expected_capacity,
        })
    }
}

impl std::fmt::Debug for LedgerRestoreCapability {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("LedgerRestoreCapability")
            .field("expected_digest", &self.expected_digest)
            .field("expected_capacity", &self.expected_capacity)
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LedgerRestoreRefusal {
    InvalidCapability,
    Checkpoint(LedgerCheckpointRefusal),
    CapacityMismatch,
}

pub(super) fn restore_authenticated(
    bytes: &[u8],
    capability: LedgerRestoreCapability,
) -> Result<HostDeliveryLedger, LedgerRestoreRefusal> {
    let checkpoint = LedgerCheckpoint::decode(bytes, &capability.expected_digest)
        .map_err(LedgerRestoreRefusal::Checkpoint)?;
    if checkpoint.capacity() != capability.expected_capacity {
        return Err(LedgerRestoreRefusal::CapacityMismatch);
    }
    let (capacity, entries) = checkpoint.into_parts();
    Ok(HostDeliveryLedger { capacity, entries })
}

pub(super) fn reconcile(
    ledger: &mut HostDeliveryLedger,
    identity: DeliveryIdentity,
    request: &PreparedRequest,
    store: &mut impl LedgerCheckpointStore,
    dispatch: impl FnOnce(&PreparedRequest) -> DeliveryDisposition,
) -> Result<DurableLedgerOutcome, DurableLedgerRefusal> {
    if !identity.matches_request(request) {
        return Err(LedgerRefusal::IdentityRequestMismatch.into());
    }
    let identity_digest = identity.digest();
    let request_digest = request_digest(request);
    if let Some(record) = ledger.entries.get(&identity_digest) {
        return if record.request_digest == request_digest {
            Ok(DurableLedgerOutcome::Replayed(record.clone()))
        } else {
            Err(LedgerRefusal::ConflictingRequest.into())
        };
    }
    if ledger.entries.len() >= ledger.capacity {
        return Err(LedgerRefusal::CapacityExceeded.into());
    }

    let provisional = LedgerRecord {
        request_digest,
        disposition: DeliveryDisposition::Uncertain {
            reason: AdapterFailure::Transport,
        },
    };
    ledger
        .entries
        .insert(identity_digest.clone(), provisional.clone());
    let intent = ledger.checkpoint()?;
    match store.commit(&intent) {
        CheckpointCommit::Committed => {}
        CheckpointCommit::NotCommitted => {
            ledger.entries.remove(&identity_digest);
            return Ok(DurableLedgerOutcome::IntentNotCommitted);
        }
        CheckpointCommit::Uncertain => {
            return Ok(DurableLedgerOutcome::IntentUncertain(provisional));
        }
    }

    let disposition = dispatch(request);
    let terminal = LedgerRecord {
        request_digest: provisional.request_digest.clone(),
        disposition,
    };
    ledger
        .entries
        .insert(identity_digest.clone(), terminal.clone());
    let settlement = match ledger.checkpoint() {
        Ok(checkpoint) => checkpoint,
        Err(error) => {
            ledger.entries.insert(identity_digest, provisional);
            return Err(error.into());
        }
    };
    match store.commit(&settlement) {
        CheckpointCommit::Committed => Ok(DurableLedgerOutcome::Dispatched(terminal)),
        CheckpointCommit::NotCommitted | CheckpointCommit::Uncertain => {
            ledger.entries.insert(identity_digest, provisional.clone());
            Ok(DurableLedgerOutcome::SettlementUncertain(provisional))
        }
    }
}

#[cfg(test)]
#[path = "ledger/durable_tests.rs"]
mod tests;
