//! Canonical durable session bindings for typed outbound delivery families.
//!
//! The lower ledger knows only identity, request, and disposition. A delivery
//! family also needs its independent policy commitment after restart. This
//! module binds those two layers without retaining raw request or identity
//! material and without granting storage or dispatch authority.

use std::collections::BTreeMap;

use sha2::{Digest as _, Sha256};

use super::super::valid_sha256;
use super::*;

const SCHEMA: &str = "semaprax.outbound.delivery-session-checkpoint.v1";
const DIGEST_DOMAIN: &[u8] = b"semaprax.outbound.delivery-session-checkpoint.v1\0";
pub(crate) const MAX_DELIVERY_SESSION_CHECKPOINT_BYTES: usize = 192 * 1024;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct DeliverySessionCommitment {
    pub(crate) policy: String,
    pub(crate) request: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeliverySessionCheckpointRefusal {
    TooLarge,
    Malformed,
    NonCanonical,
    BindingMismatch,
    InvalidCapacity,
    CapacityMismatch,
    Ledger(LedgerCheckpointRefusal),
    Restore(LedgerRestoreRefusal),
}

impl From<LedgerCheckpointRefusal> for DeliverySessionCheckpointRefusal {
    fn from(value: LedgerCheckpointRefusal) -> Self {
        Self::Ledger(value)
    }
}

impl From<LedgerRestoreRefusal> for DeliverySessionCheckpointRefusal {
    fn from(value: LedgerRestoreRefusal) -> Self {
        Self::Restore(value)
    }
}

/// Bounded typed session state. The wire includes only SHA-256 commitments and
/// the lower ledger's closed dispositions; it has no request bytes, endpoint,
/// signing material, or adapter capability.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct DeliverySessionCheckpoint {
    kind: String,
    ledger: LedgerCheckpoint,
    commitments: BTreeMap<String, DeliverySessionCommitment>,
}

impl DeliverySessionCheckpoint {
    pub(crate) fn from_session(
        kind: &str,
        ledger: &HostDeliveryLedger,
        commitments: &BTreeMap<String, DeliverySessionCommitment>,
    ) -> Result<Self, DeliverySessionCheckpointRefusal> {
        if !valid_kind(kind) {
            return Err(DeliverySessionCheckpointRefusal::Malformed);
        }
        let ledger = ledger.checkpoint()?;
        validate_bindings(&ledger, commitments)?;
        let checkpoint = Self {
            kind: kind.to_owned(),
            ledger,
            commitments: commitments.clone(),
        };
        if checkpoint.render().len() > MAX_DELIVERY_SESSION_CHECKPOINT_BYTES {
            return Err(DeliverySessionCheckpointRefusal::TooLarge);
        }
        Ok(checkpoint)
    }

    pub(crate) fn decode(
        bytes: &[u8],
        expected_digest: &str,
        expected_kind: &str,
    ) -> Result<Self, DeliverySessionCheckpointRefusal> {
        if bytes.len() > MAX_DELIVERY_SESSION_CHECKPOINT_BYTES {
            return Err(DeliverySessionCheckpointRefusal::TooLarge);
        }
        if !valid_sha256(expected_digest) || digest(bytes) != expected_digest {
            return Err(DeliverySessionCheckpointRefusal::BindingMismatch);
        }
        if !valid_kind(expected_kind) {
            return Err(DeliverySessionCheckpointRefusal::Malformed);
        }
        let value: serde_json::Value = serde_json::from_slice(bytes)
            .map_err(|_| DeliverySessionCheckpointRefusal::Malformed)?;
        let object = value
            .as_object()
            .filter(|object| object.len() == 6)
            .ok_or(DeliverySessionCheckpointRefusal::Malformed)?;
        if object.keys().map(String::as_str).collect::<Vec<_>>()
            != [
                "capacity",
                "commitments",
                "kind",
                "ledger",
                "ledger_digest",
                "schema",
            ]
            .as_slice()
            || value["schema"].as_str() != Some(SCHEMA)
            || value["kind"].as_str() != Some(expected_kind)
        {
            return Err(DeliverySessionCheckpointRefusal::Malformed);
        }
        let capacity = value["capacity"]
            .as_u64()
            .and_then(|value| usize::try_from(value).ok())
            .filter(|value| (1..=MAX_LEDGER_ENTRIES).contains(value))
            .ok_or(DeliverySessionCheckpointRefusal::InvalidCapacity)?;
        let ledger_digest = value["ledger_digest"]
            .as_str()
            .filter(|value| valid_sha256(value))
            .ok_or(DeliverySessionCheckpointRefusal::Malformed)?;
        let mut ledger_value = value["ledger"].clone();
        ledger_value.sort_all_objects();
        let ledger_bytes = serde_json::to_vec(&ledger_value)
            .map_err(|_| DeliverySessionCheckpointRefusal::Malformed)?;
        let ledger = LedgerCheckpoint::decode(&ledger_bytes, ledger_digest)?;
        if ledger.capacity() != capacity {
            return Err(DeliverySessionCheckpointRefusal::CapacityMismatch);
        }
        let rows = value["commitments"]
            .as_array()
            .filter(|rows| rows.len() <= capacity)
            .ok_or(DeliverySessionCheckpointRefusal::Malformed)?;
        let mut commitments = BTreeMap::new();
        for row in rows {
            let row = row
                .as_object()
                .filter(|row| row.len() == 4)
                .ok_or(DeliverySessionCheckpointRefusal::Malformed)?;
            if row.keys().map(String::as_str).collect::<Vec<_>>()
                != ["ledger_identity", "policy", "request", "session_identity"].as_slice()
            {
                return Err(DeliverySessionCheckpointRefusal::Malformed);
            }
            let session_identity = digest_member(row, "session_identity")?;
            let policy = digest_member(row, "policy")?;
            let request = digest_member(row, "request")?;
            let ledger_identity = digest_member(row, "ledger_identity")?;
            if ledger_bindings(&ledger)?.get(request).map(String::as_str) != Some(ledger_identity) {
                return Err(DeliverySessionCheckpointRefusal::BindingMismatch);
            }
            if commitments
                .insert(
                    session_identity.to_owned(),
                    DeliverySessionCommitment {
                        policy: policy.to_owned(),
                        request: request.to_owned(),
                    },
                )
                .is_some()
            {
                return Err(DeliverySessionCheckpointRefusal::Malformed);
            }
        }
        validate_bindings(&ledger, &commitments)?;
        let checkpoint = Self {
            kind: expected_kind.to_owned(),
            ledger,
            commitments,
        };
        if checkpoint.render().as_bytes() != bytes {
            return Err(DeliverySessionCheckpointRefusal::NonCanonical);
        }
        Ok(checkpoint)
    }

    pub(crate) fn render(&self) -> String {
        let bindings = ledger_bindings(&self.ledger)
            .expect("a constructed delivery session checkpoint has valid lower bindings");
        let commitments = self
            .commitments
            .iter()
            .map(|(session_identity, commitment)| {
                serde_json::json!({
                    "session_identity": session_identity,
                    "policy": commitment.policy,
                    "request": commitment.request,
                    "ledger_identity": bindings[&commitment.request],
                })
            })
            .collect::<Vec<_>>();
        let mut ledger: serde_json::Value = serde_json::from_str(&self.ledger.render())
            .expect("ledger checkpoint always renders canonical JSON");
        ledger.sort_all_objects();
        let mut value = serde_json::json!({
            "schema": SCHEMA,
            "kind": self.kind,
            "capacity": self.ledger.capacity(),
            "ledger_digest": self.ledger.digest(),
            "ledger": ledger,
            "commitments": commitments,
        });
        value.sort_all_objects();
        serde_json::to_string(&value).expect("delivery session checkpoint always renders JSON")
    }

    pub(crate) fn digest(&self) -> String {
        digest(self.render().as_bytes())
    }

    pub(crate) fn capacity(&self) -> usize {
        self.ledger.capacity()
    }

    pub(crate) fn kind(&self) -> &str {
        &self.kind
    }

    pub(crate) fn restore(
        self,
    ) -> Result<
        (
            HostDeliveryLedger,
            BTreeMap<String, DeliverySessionCommitment>,
        ),
        DeliverySessionCheckpointRefusal,
    > {
        let ledger_bytes = self.ledger.render();
        let capability = LedgerRestoreCapability::grant_for_trusted_host(
            self.ledger.digest(),
            self.ledger.capacity(),
        )
        .map_err(DeliverySessionCheckpointRefusal::Restore)?;
        let ledger = HostDeliveryLedger::restore_authenticated(ledger_bytes.as_bytes(), capability)
            .map_err(DeliverySessionCheckpointRefusal::Restore)?;
        Ok((ledger, self.commitments))
    }
}

pub(crate) trait DeliverySessionCheckpointStore {
    fn commit(&mut self, checkpoint: &DeliverySessionCheckpoint) -> CheckpointCommit;
}

pub(crate) struct TypedDeliveryCheckpointStore<'a, Store> {
    pub(crate) store: &'a mut Store,
    pub(crate) kind: &'static str,
    pub(crate) commitments: &'a BTreeMap<String, DeliverySessionCommitment>,
}

impl<Store: DeliverySessionCheckpointStore> LedgerCheckpointStore
    for TypedDeliveryCheckpointStore<'_, Store>
{
    fn commit(&mut self, ledger: &LedgerCheckpoint) -> CheckpointCommit {
        let session = match delivery_checkpoint_from_ledger(self.kind, ledger, self.commitments) {
            Ok(session) => session,
            Err(_) => return CheckpointCommit::NotCommitted,
        };
        self.store.commit(&session)
    }
}

fn delivery_checkpoint_from_ledger(
    kind: &str,
    ledger: &LedgerCheckpoint,
    commitments: &BTreeMap<String, DeliverySessionCommitment>,
) -> Result<DeliverySessionCheckpoint, DeliverySessionCheckpointRefusal> {
    if !valid_kind(kind) {
        return Err(DeliverySessionCheckpointRefusal::Malformed);
    }
    validate_bindings(ledger, commitments)?;
    let checkpoint = DeliverySessionCheckpoint {
        kind: kind.to_owned(),
        ledger: ledger.clone(),
        commitments: commitments.clone(),
    };
    if checkpoint.render().len() > MAX_DELIVERY_SESSION_CHECKPOINT_BYTES {
        return Err(DeliverySessionCheckpointRefusal::TooLarge);
    }
    Ok(checkpoint)
}

fn validate_bindings(
    ledger: &LedgerCheckpoint,
    commitments: &BTreeMap<String, DeliverySessionCommitment>,
) -> Result<(), DeliverySessionCheckpointRefusal> {
    if commitments.len() != ledger.len() {
        return Err(DeliverySessionCheckpointRefusal::BindingMismatch);
    }
    let mut bindings = ledger_bindings(ledger)?;
    for commitment in commitments.values() {
        if !valid_sha256(&commitment.policy) || !valid_sha256(&commitment.request) {
            return Err(DeliverySessionCheckpointRefusal::BindingMismatch);
        }
        if bindings.remove(&commitment.request).is_none() {
            return Err(DeliverySessionCheckpointRefusal::BindingMismatch);
        }
    }
    if !bindings.is_empty() {
        return Err(DeliverySessionCheckpointRefusal::BindingMismatch);
    }
    Ok(())
}

fn ledger_bindings(
    ledger: &LedgerCheckpoint,
) -> Result<BTreeMap<String, String>, DeliverySessionCheckpointRefusal> {
    let value: serde_json::Value = serde_json::from_str(&ledger.render())
        .map_err(|_| DeliverySessionCheckpointRefusal::Malformed)?;
    let rows = value["entries"]
        .as_array()
        .ok_or(DeliverySessionCheckpointRefusal::Malformed)?;
    let mut bindings = BTreeMap::new();
    for row in rows {
        let request = row["request_digest"]
            .as_str()
            .filter(|value| valid_sha256(value))
            .ok_or(DeliverySessionCheckpointRefusal::Malformed)?;
        let identity = row["identity_digest"]
            .as_str()
            .filter(|value| valid_sha256(value))
            .ok_or(DeliverySessionCheckpointRefusal::Malformed)?;
        if bindings
            .insert(request.to_owned(), identity.to_owned())
            .is_some()
        {
            return Err(DeliverySessionCheckpointRefusal::BindingMismatch);
        }
    }
    Ok(bindings)
}

fn digest_member<'a>(
    row: &'a serde_json::Map<String, serde_json::Value>,
    name: &str,
) -> Result<&'a str, DeliverySessionCheckpointRefusal> {
    row.get(name)
        .and_then(serde_json::Value::as_str)
        .filter(|value| valid_sha256(value))
        .ok_or(DeliverySessionCheckpointRefusal::Malformed)
}

fn valid_kind(kind: &str) -> bool {
    matches!(kind, "http" | "webhook" | "email")
}

fn digest(bytes: &[u8]) -> String {
    let mut hash = Sha256::new();
    hash.update(DIGEST_DOMAIN);
    hash.update((bytes.len() as u64).to_le_bytes());
    hash.update(bytes);
    format!("sha256:{:x}", crate::digest_hex::LowerHex(hash.finalize()))
}
