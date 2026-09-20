//! Authority-free, read-only transport of disposition-ledger observations.
//!
//! An imported checkpoint cannot become a live ledger. Missing identities are
//! unknown, not permission to dispatch; commitments need host-authenticated
//! provenance and do not prove freshness, remote receipt, or crash durability.

use super::*;
use crate::outbound_host_adapter::{decode_disposition, valid_sha256};

const SCHEMA: &str = "semaprax.outbound.delivery-ledger-checkpoint.v1";
const DIGEST_DOMAIN: &[u8] = b"semaprax.outbound.delivery-ledger-checkpoint.v1\0";

/// Maximum input size, checked before JSON parsing or digest work.
pub const MAX_LEDGER_CHECKPOINT_BYTES: usize = 96 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LedgerCheckpointRefusal {
    TooLarge,
    Malformed,
    NonCanonical,
    BindingMismatch,
    InvalidCapacity,
    CapacityExceeded,
    IdentityRequestMismatch,
    UnknownIdentity,
    ConflictingObservation,
    StateChanged,
}

/// Immutable offline observations, deliberately lacking a dispatch/restore API.
/// Only digests and closed dispositions are retained; hashes are not secrecy.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LedgerCheckpoint {
    capacity: usize,
    entries: BTreeMap<String, LedgerRecord>,
}

impl LedgerCheckpoint {
    pub(super) fn from_ledger(
        ledger: &HostDeliveryLedger,
    ) -> Result<Self, LedgerCheckpointRefusal> {
        for record in ledger.entries.values() {
            validate_disposition(&record.disposition)?;
        }
        Ok(Self {
            capacity: ledger.capacity,
            entries: ledger.entries.clone(),
        })
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// Canonical wire, sorted by identity commitment, containing no raw data.
    pub fn render(&self) -> String {
        let entries = self
            .entries
            .iter()
            .map(|(identity, record)| {
                serde_json::json!({
                    "identity_digest": identity,
                    "request_digest": record.request_digest,
                    "disposition": render_disposition(&record.disposition),
                })
            })
            .collect::<Vec<_>>();
        let mut value = serde_json::json!({
            "schema": SCHEMA, "capacity": self.capacity, "entries": entries,
        });
        // Canonical bytes must not depend on serde_json's feature-unified
        // object-map implementation (`BTreeMap` versus `preserve_order`).
        value.sort_all_objects();
        serde_json::to_string(&value).expect("bounded closed checkpoint encodes")
    }

    /// Domain-separated commitment for independent host retention. This is not
    /// a signature: accepting a digest supplied with untrusted bytes does not
    /// authenticate their provenance or establish their freshness.
    pub fn digest(&self) -> String {
        wire_digest(self.render().as_bytes())
    }

    /// Verify an exact caller-retained commitment, closed schema and canonical
    /// bytes. No imported state is ever inserted into a dispatch-capable ledger.
    pub fn decode(bytes: &[u8], expected_digest: &str) -> Result<Self, LedgerCheckpointRefusal> {
        if bytes.len() > MAX_LEDGER_CHECKPOINT_BYTES {
            return Err(LedgerCheckpointRefusal::TooLarge);
        }
        if !valid_sha256(expected_digest) || wire_digest(bytes) != expected_digest {
            return Err(LedgerCheckpointRefusal::BindingMismatch);
        }
        let value: serde_json::Value =
            serde_json::from_slice(bytes).map_err(|_| LedgerCheckpointRefusal::Malformed)?;
        let object = value
            .as_object()
            .ok_or(LedgerCheckpointRefusal::Malformed)?;
        if object.len() != 3 || value["schema"].as_str() != Some(SCHEMA) {
            return Err(LedgerCheckpointRefusal::Malformed);
        }
        let capacity = value["capacity"]
            .as_u64()
            .and_then(|n| usize::try_from(n).ok())
            .filter(|n| (1..=MAX_LEDGER_ENTRIES).contains(n))
            .ok_or(LedgerCheckpointRefusal::InvalidCapacity)?;
        let records = value["entries"]
            .as_array()
            .ok_or(LedgerCheckpointRefusal::Malformed)?;
        if records.len() > capacity {
            return Err(LedgerCheckpointRefusal::CapacityExceeded);
        }
        let mut entries = BTreeMap::new();
        for entry in records {
            let object = entry
                .as_object()
                .ok_or(LedgerCheckpointRefusal::Malformed)?;
            if object.len() != 3 || !object.contains_key("disposition") {
                return Err(LedgerCheckpointRefusal::Malformed);
            }
            let identity = digest_member(entry, "identity_digest")?;
            let request_digest = digest_member(entry, "request_digest")?.to_owned();
            let disposition = parse_disposition(&entry["disposition"])?;
            if entries
                .insert(
                    identity.to_owned(),
                    LedgerRecord {
                        request_digest,
                        disposition,
                    },
                )
                .is_some()
            {
                return Err(LedgerCheckpointRefusal::Malformed);
            }
        }
        let checkpoint = Self { capacity, entries };
        if checkpoint.render().as_bytes() != bytes {
            return Err(LedgerCheckpointRefusal::NonCanonical);
        }
        Ok(checkpoint)
    }

    /// Compare every entry and capacity against a still-live host ledger.
    /// Equal observations do not prove that the host persisted them durably.
    pub fn verify_against(
        &self,
        ledger: &HostDeliveryLedger,
    ) -> Result<(), LedgerCheckpointRefusal> {
        if self.capacity != ledger.capacity || self.entries != ledger.entries {
            return Err(LedgerCheckpointRefusal::StateChanged);
        }
        Ok(())
    }

    /// Query one exact prepared request without consuming it or dispatching.
    /// Missing state remains unknown even if a request would otherwise be valid.
    pub fn lookup(
        &self,
        identity: &DeliveryIdentity,
        request: &PreparedRequest,
    ) -> Result<&LedgerRecord, LedgerCheckpointRefusal> {
        if !identity.matches_request(request) {
            return Err(LedgerCheckpointRefusal::IdentityRequestMismatch);
        }
        let record = self
            .entries
            .get(&identity.digest())
            .ok_or(LedgerCheckpointRefusal::UnknownIdentity)?;
        if record.request_digest != request_digest(request) {
            return Err(LedgerCheckpointRefusal::ConflictingObservation);
        }
        Ok(record)
    }

    /// Monotonic, deterministic union of compatible *observations*. Conflicting
    /// request bytes or any disposition change, including uncertainty becoming
    /// accepted, refuse atomically. Neither input changes on any outcome.
    pub fn merge(&self, other: &Self) -> Result<Self, LedgerCheckpointRefusal> {
        if self.capacity != other.capacity {
            return Err(LedgerCheckpointRefusal::InvalidCapacity);
        }
        for (identity, record) in &other.entries {
            if self.entries.get(identity).is_some_and(|old| old != record) {
                return Err(LedgerCheckpointRefusal::ConflictingObservation);
            }
        }
        let additional = other
            .entries
            .keys()
            .filter(|key| !self.entries.contains_key(*key))
            .count();
        if self.entries.len() + additional > self.capacity {
            return Err(LedgerCheckpointRefusal::CapacityExceeded);
        }
        let mut merged = self.clone();
        merged.entries.extend(other.entries.clone());
        Ok(merged)
    }
}

fn wire_digest(bytes: &[u8]) -> String {
    let mut hash = Sha256::new();
    hash.update(DIGEST_DOMAIN);
    hash.update((bytes.len() as u64).to_le_bytes());
    hash.update(bytes);
    format!("sha256:{:x}", crate::digest_hex::LowerHex(hash.finalize()))
}

fn digest_member<'a>(
    value: &'a serde_json::Value,
    key: &str,
) -> Result<&'a str, LedgerCheckpointRefusal> {
    value[key]
        .as_str()
        .filter(|value| valid_sha256(value))
        .ok_or(LedgerCheckpointRefusal::Malformed)
}

fn validate_disposition(disposition: &DeliveryDisposition) -> Result<(), LedgerCheckpointRefusal> {
    let valid = match disposition {
        DeliveryDisposition::Accepted { status } => (200..300).contains(status),
        DeliveryDisposition::Rejected { status } => {
            (100..600).contains(status) && !(200..300).contains(status)
        }
        _ => true,
    };
    if valid {
        Ok(())
    } else {
        Err(LedgerCheckpointRefusal::Malformed)
    }
}

fn parse_disposition(
    value: &serde_json::Value,
) -> Result<DeliveryDisposition, LedgerCheckpointRefusal> {
    let object = value
        .as_object()
        .ok_or(LedgerCheckpointRefusal::Malformed)?;
    let disposition = match value["kind"].as_str() {
        Some("deadline_uncertain") if object.len() == 1 => DeliveryDisposition::DeadlineUncertain,
        Some("response_too_large_uncertain") if object.len() == 1 => {
            DeliveryDisposition::ResponseTooLargeUncertain
        }
        _ => decode_disposition(value).map_err(|_| LedgerCheckpointRefusal::Malformed)?,
    };
    validate_disposition(&disposition)?;
    Ok(disposition)
}

#[cfg(test)]
#[path = "ledger_checkpoint_tests.rs"]
mod tests;
