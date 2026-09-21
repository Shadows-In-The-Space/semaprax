//! Process-local, disposition-only reconciliation for structured exports.
//!
//! This is additive to [`super::export_event`]. The legacy helper remains a
//! stateless one-shot operation; hosts that need in-process duplicate
//! suppression explicitly prepare an event and retain an [`ExportEventSession`].

use std::collections::BTreeMap;
use std::fmt;

use sha2::{Digest as _, Sha256};

use super::*;

const EXPORT_IDEMPOTENCY_DOMAIN: &[u8] = b"semaprax.outbound.export-event.idempotency.v1\0";
const SESSION_IDENTITY_DOMAIN: &[u8] = b"semaprax.outbound.export-session.identity.v1\0";
const POLICY_COMMITMENT_DOMAIN: &[u8] = b"semaprax.outbound.export-session.policy.v1\0";
const EVENT_COMMITMENT_DOMAIN: &[u8] = b"semaprax.outbound.export-session.event.v1\0";
const SESSION_CHECKPOINT_SCHEMA: &str = "semaprax.outbound.export-session-checkpoint.v1";
const SESSION_CHECKPOINT_DIGEST_DOMAIN: &[u8] = b"semaprax.outbound.export-session-checkpoint.v1\0";
pub const MAX_EXPORT_SESSION_CHECKPOINT_BYTES: usize = 192 * 1024;

/// An admitted operational export that has not reached an adapter.
///
/// Its request body contains only the canonical public/redacted event wire.
/// Values the trusted caller supplies through [`ProtectedExportValue`] are
/// zeroized before producing an [`ExportFieldValue::Redacted`]; as with the
/// legacy helper, this boundary does not infer classification for public text.
pub struct PreparedExportEvent {
    capability: OutboundCapability,
    origin: String,
    event_id: String,
    idempotency_key: String,
    identity: DeliveryIdentity,
    session_identity_digest: String,
    policy_digest: String,
    event_digest: String,
    request_digest: String,
    request: PreparedRequest,
}

impl fmt::Debug for PreparedExportEvent {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PreparedExportEvent")
            .field("origin", &self.origin)
            .field("request", &self.request)
            .field("bindings", &"[REDACTED]")
            .finish()
    }
}

/// Disposition-only result of one structured-export reconciliation.
///
/// Accepted response bytes are discarded before session state is committed;
/// replay reconstructs evidence from commitments and the remembered closed
/// disposition, never from a provider response.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExportEventReceipt {
    evidence: DeliveryEvidence,
    replayed: bool,
}

impl ExportEventReceipt {
    pub fn evidence(&self) -> &DeliveryEvidence {
        &self.evidence
    }

    pub fn was_replayed(&self) -> bool {
        self.replayed
    }
}

/// Refusal from the additive structured-export reconciliation session.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExportEventLedgerRefusal {
    Ledger(LedgerRefusal),
    PolicyChanged,
    EventChanged,
    RequestChanged,
    ReplayBindingUnavailable,
}

impl From<LedgerRefusal> for ExportEventLedgerRefusal {
    fn from(value: LedgerRefusal) -> Self {
        Self::Ledger(value)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ExportCommitments {
    policy: String,
    event: String,
    request: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ExportCheckpointCommitments {
    policy: String,
    event: String,
    request: String,
    ledger_identity: String,
}

/// Authority-free, bounded durable image of one typed export session.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExportSessionCheckpoint {
    ledger: LedgerCheckpoint,
    commitments: BTreeMap<String, ExportCheckpointCommitments>,
}

impl ExportSessionCheckpoint {
    fn from_session(session: &ExportEventSession) -> Result<Self, ExportSessionCheckpointRefusal> {
        if session.commitments.len() != session.ledger.len() {
            return Err(ExportSessionCheckpointRefusal::BindingMismatch);
        }
        let ledger = session.ledger.checkpoint()?;
        let commitments = bind_checkpoint_commitments(&ledger, &session.commitments)?;
        let checkpoint = Self {
            ledger,
            commitments,
        };
        if checkpoint.render().len() > MAX_EXPORT_SESSION_CHECKPOINT_BYTES {
            return Err(ExportSessionCheckpointRefusal::TooLarge);
        }
        Ok(checkpoint)
    }

    pub fn render(&self) -> String {
        let commitments = self
            .commitments
            .iter()
            .map(|(identity, value)| {
                serde_json::json!({
                    "event": value.event,
                    "identity": identity,
                    "ledger_identity": value.ledger_identity,
                    "policy": value.policy,
                    "request": value.request,
                })
            })
            .collect::<Vec<_>>();
        let mut value = serde_json::json!({
            "commitments": commitments,
            "ledger": self.ledger.render(),
            "ledger_digest": self.ledger.digest(),
            "schema": SESSION_CHECKPOINT_SCHEMA,
        });
        value.sort_all_objects();
        serde_json::to_string(&value).expect("bounded export session checkpoint encodes")
    }

    pub fn len(&self) -> usize {
        self.ledger.len()
    }

    pub fn capacity(&self) -> usize {
        self.ledger.capacity()
    }

    pub fn digest(&self) -> String {
        session_checkpoint_digest(self.render().as_bytes())
    }

    pub fn decode(
        bytes: &[u8],
        expected_digest: &str,
    ) -> Result<Self, ExportSessionCheckpointRefusal> {
        if bytes.len() > MAX_EXPORT_SESSION_CHECKPOINT_BYTES {
            return Err(ExportSessionCheckpointRefusal::TooLarge);
        }
        if !valid_sha256(expected_digest) || session_checkpoint_digest(bytes) != expected_digest {
            return Err(ExportSessionCheckpointRefusal::BindingMismatch);
        }
        let value: serde_json::Value =
            serde_json::from_slice(bytes).map_err(|_| ExportSessionCheckpointRefusal::Malformed)?;
        let _root = value
            .as_object()
            .filter(|root| root.len() == 4)
            .ok_or(ExportSessionCheckpointRefusal::Malformed)?;
        if value["schema"].as_str() != Some(SESSION_CHECKPOINT_SCHEMA) {
            return Err(ExportSessionCheckpointRefusal::Malformed);
        }
        let ledger_wire = value["ledger"]
            .as_str()
            .ok_or(ExportSessionCheckpointRefusal::Malformed)?;
        let ledger_digest = value["ledger_digest"]
            .as_str()
            .ok_or(ExportSessionCheckpointRefusal::Malformed)?;
        let ledger = LedgerCheckpoint::decode(ledger_wire.as_bytes(), ledger_digest)?;
        let entries = value["commitments"]
            .as_array()
            .ok_or(ExportSessionCheckpointRefusal::Malformed)?;
        if entries.len() > ledger.capacity() {
            return Err(ExportSessionCheckpointRefusal::CapacityExceeded);
        }
        let mut commitments = BTreeMap::new();
        for entry in entries {
            let object = entry
                .as_object()
                .filter(|object| object.len() == 5)
                .ok_or(ExportSessionCheckpointRefusal::Malformed)?;
            let member = |name| {
                object
                    .get(name)
                    .and_then(serde_json::Value::as_str)
                    .filter(|value| valid_sha256(value))
                    .map(str::to_owned)
                    .ok_or(ExportSessionCheckpointRefusal::Malformed)
            };
            let identity = member("identity")?;
            let binding = ExportCommitments {
                policy: member("policy")?,
                event: member("event")?,
                request: member("request")?,
            };
            let binding = ExportCheckpointCommitments {
                policy: binding.policy,
                event: binding.event,
                request: binding.request,
                ledger_identity: member("ledger_identity")?,
            };
            if commitments.insert(identity, binding).is_some() {
                return Err(ExportSessionCheckpointRefusal::Malformed);
            }
        }
        if commitments.len() != ledger.len() {
            return Err(ExportSessionCheckpointRefusal::BindingMismatch);
        }
        let ledger_bindings = ledger_identity_request_bindings(&ledger)?;
        if commitments
            .values()
            .any(|binding| ledger_bindings.get(&binding.request) != Some(&binding.ledger_identity))
        {
            return Err(ExportSessionCheckpointRefusal::BindingMismatch);
        }
        let checkpoint = Self {
            ledger,
            commitments,
        };
        if checkpoint.render().as_bytes() != bytes {
            return Err(ExportSessionCheckpointRefusal::NonCanonical);
        }
        Ok(checkpoint)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExportSessionCheckpointRefusal {
    TooLarge,
    Malformed,
    NonCanonical,
    BindingMismatch,
    CapacityExceeded,
    Ledger(LedgerCheckpointRefusal),
}

impl From<LedgerCheckpointRefusal> for ExportSessionCheckpointRefusal {
    fn from(value: LedgerCheckpointRefusal) -> Self {
        Self::Ledger(value)
    }
}

pub trait ExportSessionCheckpointStore {
    fn commit(&mut self, checkpoint: &ExportSessionCheckpoint) -> CheckpointCommit;
}

pub struct ExportSessionRestoreCapability {
    expected_digest: String,
    expected_capacity: usize,
}

impl ExportSessionRestoreCapability {
    pub fn grant_for_trusted_host(
        expected_digest: impl Into<String>,
        expected_capacity: usize,
    ) -> Result<Self, ExportSessionRestoreRefusal> {
        let expected_digest = expected_digest.into();
        if !valid_sha256(&expected_digest)
            || expected_capacity == 0
            || expected_capacity > MAX_LEDGER_ENTRIES
        {
            return Err(ExportSessionRestoreRefusal::InvalidCapability);
        }
        Ok(Self {
            expected_digest,
            expected_capacity,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExportSessionRestoreRefusal {
    InvalidCapability,
    Checkpoint(ExportSessionCheckpointRefusal),
    CapacityMismatch,
    Ledger(LedgerRestoreRefusal),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DurableExportEventOutcome {
    Dispatched(ExportEventReceipt),
    Replayed(ExportEventReceipt),
    IntentNotCommitted,
    IntentUncertain(ExportEventReceipt),
    SettlementUncertain(ExportEventReceipt),
}

impl DurableExportEventOutcome {
    pub fn receipt(&self) -> Option<&ExportEventReceipt> {
        match self {
            Self::Dispatched(receipt)
            | Self::Replayed(receipt)
            | Self::IntentUncertain(receipt)
            | Self::SettlementUncertain(receipt) => Some(receipt),
            Self::IntentNotCommitted => None,
        }
    }

    pub fn was_dispatched(&self) -> bool {
        matches!(self, Self::Dispatched(_) | Self::SettlementUncertain(_))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DurableExportEventRefusal {
    Session(ExportEventLedgerRefusal),
    Durable(DurableLedgerRefusal),
    Checkpoint(ExportSessionCheckpointRefusal),
}

fn ledger_identity_request_bindings(
    ledger: &LedgerCheckpoint,
) -> Result<BTreeMap<String, String>, ExportSessionCheckpointRefusal> {
    let value: serde_json::Value = serde_json::from_str(&ledger.render())
        .map_err(|_| ExportSessionCheckpointRefusal::Malformed)?;
    let entries = value["entries"]
        .as_array()
        .ok_or(ExportSessionCheckpointRefusal::Malformed)?;
    let mut by_request = BTreeMap::new();
    for entry in entries {
        let request = entry["request_digest"]
            .as_str()
            .filter(|value| valid_sha256(value))
            .ok_or(ExportSessionCheckpointRefusal::Malformed)?;
        let identity = entry["identity_digest"]
            .as_str()
            .filter(|value| valid_sha256(value))
            .ok_or(ExportSessionCheckpointRefusal::Malformed)?;
        if by_request
            .insert(request.to_owned(), identity.to_owned())
            .is_some()
        {
            return Err(ExportSessionCheckpointRefusal::BindingMismatch);
        }
    }
    Ok(by_request)
}

fn bind_checkpoint_commitments(
    ledger: &LedgerCheckpoint,
    commitments: &BTreeMap<String, ExportCommitments>,
) -> Result<BTreeMap<String, ExportCheckpointCommitments>, ExportSessionCheckpointRefusal> {
    if commitments.len() != ledger.len() {
        return Err(ExportSessionCheckpointRefusal::BindingMismatch);
    }
    let mut ledger_identities = ledger_identity_request_bindings(ledger)?;
    let mut bound = BTreeMap::new();
    for (identity, binding) in commitments {
        let ledger_identity = ledger_identities
            .remove(&binding.request)
            .ok_or(ExportSessionCheckpointRefusal::BindingMismatch)?;
        bound.insert(
            identity.clone(),
            ExportCheckpointCommitments {
                policy: binding.policy.clone(),
                event: binding.event.clone(),
                request: binding.request.clone(),
                ledger_identity,
            },
        );
    }
    if !ledger_identities.is_empty() {
        return Err(ExportSessionCheckpointRefusal::BindingMismatch);
    }
    Ok(bound)
}

struct TypedCheckpointStore<'a, Store> {
    store: &'a mut Store,
    commitments: &'a BTreeMap<String, ExportCommitments>,
}

fn commit_typed_checkpoint(
    store: &mut impl ExportSessionCheckpointStore,
    ledger: &LedgerCheckpoint,
    commitments: &BTreeMap<String, ExportCommitments>,
    maximum_bytes: usize,
) -> CheckpointCommit {
    let Ok(commitments) = bind_checkpoint_commitments(ledger, commitments) else {
        return CheckpointCommit::NotCommitted;
    };
    let checkpoint = ExportSessionCheckpoint {
        ledger: ledger.clone(),
        commitments,
    };
    if checkpoint.render().len() > maximum_bytes {
        return CheckpointCommit::NotCommitted;
    }
    store.commit(&checkpoint)
}

impl<Store: ExportSessionCheckpointStore> LedgerCheckpointStore
    for TypedCheckpointStore<'_, Store>
{
    fn commit(&mut self, ledger: &LedgerCheckpoint) -> CheckpointCommit {
        commit_typed_checkpoint(
            self.store,
            ledger,
            self.commitments,
            MAX_EXPORT_SESSION_CHECKPOINT_BYTES,
        )
    }
}

/// Bounded process-local reconciliation state for operational exports.
///
/// The session retains only domain-separated SHA-256 commitments plus the
/// underlying ledger's request commitment and disposition. It retains no
/// event fields, labels, protected values, request bytes, response bytes, or
/// raw delivery identity. Dropping it loses all replay knowledge by design.
pub struct ExportEventSession {
    ledger: HostDeliveryLedger,
    commitments: BTreeMap<String, ExportCommitments>,
}

impl ExportEventSession {
    pub fn new(capacity: usize) -> Result<Self, ExportEventLedgerRefusal> {
        Ok(Self {
            ledger: HostDeliveryLedger::new(capacity)?,
            commitments: BTreeMap::new(),
        })
    }

    pub fn len(&self) -> usize {
        self.ledger.len()
    }

    /// Export disposition observations only, excluding policy/event bindings.
    /// An imported checkpoint is read-only and cannot restore this session.
    pub fn checkpoint(&self) -> Result<LedgerCheckpoint, LedgerCheckpointRefusal> {
        self.ledger.checkpoint()
    }

    /// Export the typed session state, including policy/event/request
    /// commitments needed to refuse drift after authenticated restoration.
    pub fn session_checkpoint(
        &self,
    ) -> Result<ExportSessionCheckpoint, ExportSessionCheckpointRefusal> {
        ExportSessionCheckpoint::from_session(self)
    }

    /// Restore dispatch-capable typed state only with exact host provenance.
    /// This creates no storage, timer, retry, or adapter authority.
    pub fn restore_authenticated(
        bytes: &[u8],
        capability: ExportSessionRestoreCapability,
    ) -> Result<Self, ExportSessionRestoreRefusal> {
        let checkpoint = ExportSessionCheckpoint::decode(bytes, &capability.expected_digest)
            .map_err(ExportSessionRestoreRefusal::Checkpoint)?;
        if checkpoint.ledger.capacity() != capability.expected_capacity {
            return Err(ExportSessionRestoreRefusal::CapacityMismatch);
        }
        let ledger_bytes = checkpoint.ledger.render();
        let ledger_capability = LedgerRestoreCapability::grant_for_trusted_host(
            checkpoint.ledger.digest(),
            checkpoint.ledger.capacity(),
        )
        .map_err(ExportSessionRestoreRefusal::Ledger)?;
        let ledger =
            HostDeliveryLedger::restore_authenticated(ledger_bytes.as_bytes(), ledger_capability)
                .map_err(ExportSessionRestoreRefusal::Ledger)?;
        Ok(Self {
            ledger,
            commitments: checkpoint
                .commitments
                .into_iter()
                .map(|(identity, binding)| {
                    (
                        identity,
                        ExportCommitments {
                            policy: binding.policy,
                            event: binding.event,
                            request: binding.request,
                        },
                    )
                })
                .collect(),
        })
    }

    pub fn verify_checkpoint(
        &self,
        checkpoint: &LedgerCheckpoint,
    ) -> Result<(), LedgerCheckpointRefusal> {
        checkpoint.verify_against(&self.ledger)
    }

    /// Reconcile one exact prepared export before adapter dispatch.
    ///
    /// Exact replay never calls `adapter.send`. Policy, canonical event, and
    /// complete prepared-request drift are refused before dispatch. The ledger
    /// reserves uncertainty before entering the adapter, so an unwind is
    /// sticky alongside its commitments: it cannot be retried through this
    /// session, but its exact uncertainty can be replayed without dispatch.
    pub fn reconcile(
        &mut self,
        prepared: PreparedExportEvent,
        adapter: &mut impl OutboundAdapter,
    ) -> Result<ExportEventReceipt, ExportEventLedgerRefusal> {
        // Authenticate the opaque prepared value again at its use boundary.
        // This is redundant for safe external Rust callers (all fields are
        // private), but keeps the binding explicit and makes internal drift
        // fail before either ledger allocation or adapter entry.
        if policy_digest(&prepared.capability.policy) != prepared.policy_digest {
            return Err(ExportEventLedgerRefusal::PolicyChanged);
        }
        if event_digest(prepared.request.body()) != prepared.event_digest {
            return Err(ExportEventLedgerRefusal::EventChanged);
        }
        if request_digest(&prepared.request) != prepared.request_digest {
            return Err(ExportEventLedgerRefusal::RequestChanged);
        }
        if let Some(existing) = self.commitments.get(&prepared.session_identity_digest) {
            if existing.policy != prepared.policy_digest {
                return Err(ExportEventLedgerRefusal::PolicyChanged);
            }
            if existing.event != prepared.event_digest {
                return Err(ExportEventLedgerRefusal::EventChanged);
            }
            if existing.request != prepared.request_digest {
                return Err(ExportEventLedgerRefusal::RequestChanged);
            }
        }

        let inserted_commitment = if self
            .commitments
            .contains_key(&prepared.session_identity_digest)
        {
            false
        } else {
            self.commitments.insert(
                prepared.session_identity_digest.clone(),
                ExportCommitments {
                    policy: prepared.policy_digest.clone(),
                    event: prepared.event_digest.clone(),
                    request: prepared.request_digest.clone(),
                },
            );
            true
        };
        let outcome =
            match self
                .ledger
                .reconcile(prepared.identity.clone(), &prepared.request, |request| {
                    let observation = adapter.send(request);
                    settlement_disposition(request, &observation)
                }) {
                Ok(outcome) => outcome,
                Err(refusal) => {
                    if inserted_commitment {
                        self.commitments.remove(&prepared.session_identity_digest);
                    }
                    return Err(refusal.into());
                }
            };
        let replayed = !outcome.was_dispatched();
        if replayed
            && !self
                .commitments
                .contains_key(&prepared.session_identity_digest)
        {
            return Err(ExportEventLedgerRefusal::ReplayBindingUnavailable);
        }
        let disposition = outcome.record().disposition().clone();
        Ok(ExportEventReceipt {
            evidence: delivery_evidence(
                prepared.capability,
                prepared.origin,
                prepared.event_id,
                prepared.idempotency_key,
                prepared.request,
                disposition,
            ),
            replayed,
        })
    }

    /// Persist typed intent before physical dispatch and typed settlement
    /// afterwards. Only a `Committed` intent ACK permits `adapter.send`.
    pub fn reconcile_durable(
        &mut self,
        prepared: PreparedExportEvent,
        store: &mut impl ExportSessionCheckpointStore,
        adapter: &mut impl OutboundAdapter,
    ) -> Result<DurableExportEventOutcome, DurableExportEventRefusal> {
        if policy_digest(&prepared.capability.policy) != prepared.policy_digest {
            return Err(DurableExportEventRefusal::Session(
                ExportEventLedgerRefusal::PolicyChanged,
            ));
        }
        if event_digest(prepared.request.body()) != prepared.event_digest {
            return Err(DurableExportEventRefusal::Session(
                ExportEventLedgerRefusal::EventChanged,
            ));
        }
        if request_digest(&prepared.request) != prepared.request_digest {
            return Err(DurableExportEventRefusal::Session(
                ExportEventLedgerRefusal::RequestChanged,
            ));
        }
        if let Some(existing) = self.commitments.get(&prepared.session_identity_digest) {
            if existing.policy != prepared.policy_digest {
                return Err(DurableExportEventRefusal::Session(
                    ExportEventLedgerRefusal::PolicyChanged,
                ));
            }
            if existing.event != prepared.event_digest {
                return Err(DurableExportEventRefusal::Session(
                    ExportEventLedgerRefusal::EventChanged,
                ));
            }
            if existing.request != prepared.request_digest {
                return Err(DurableExportEventRefusal::Session(
                    ExportEventLedgerRefusal::RequestChanged,
                ));
            }
        }
        let inserted = if self
            .commitments
            .contains_key(&prepared.session_identity_digest)
        {
            false
        } else {
            self.commitments.insert(
                prepared.session_identity_digest.clone(),
                ExportCommitments {
                    policy: prepared.policy_digest.clone(),
                    event: prepared.event_digest.clone(),
                    request: prepared.request_digest.clone(),
                },
            );
            true
        };
        let mut typed_store = TypedCheckpointStore {
            store,
            commitments: &self.commitments,
        };
        let outcome = self.ledger.reconcile_durable(
            prepared.identity.clone(),
            &prepared.request,
            &mut typed_store,
            |request| {
                let observation = adapter.send(request);
                settlement_disposition(request, &observation)
            },
        );
        let outcome = match outcome {
            Ok(outcome) => outcome,
            Err(error) => {
                if inserted {
                    self.commitments.remove(&prepared.session_identity_digest);
                }
                return Err(DurableExportEventRefusal::Durable(error));
            }
        };
        if matches!(outcome, DurableLedgerOutcome::IntentNotCommitted) && inserted {
            self.commitments.remove(&prepared.session_identity_digest);
        }
        Ok(match outcome {
            DurableLedgerOutcome::Dispatched(record) => {
                DurableExportEventOutcome::Dispatched(durable_receipt(prepared, record, false))
            }
            DurableLedgerOutcome::Replayed(record) => {
                DurableExportEventOutcome::Replayed(durable_receipt(prepared, record, true))
            }
            DurableLedgerOutcome::IntentNotCommitted => {
                DurableExportEventOutcome::IntentNotCommitted
            }
            DurableLedgerOutcome::IntentUncertain(record) => {
                DurableExportEventOutcome::IntentUncertain(durable_receipt(prepared, record, false))
            }
            DurableLedgerOutcome::SettlementUncertain(record) => {
                DurableExportEventOutcome::SettlementUncertain(durable_receipt(
                    prepared, record, false,
                ))
            }
        })
    }
}

fn durable_receipt(
    prepared: PreparedExportEvent,
    record: LedgerRecord,
    replayed: bool,
) -> ExportEventReceipt {
    ExportEventReceipt {
        evidence: delivery_evidence(
            prepared.capability,
            prepared.origin,
            prepared.event_id,
            prepared.idempotency_key,
            prepared.request,
            record.disposition().clone(),
        ),
        replayed,
    }
}

fn session_checkpoint_digest(bytes: &[u8]) -> String {
    let mut hash = Sha256::new();
    hash.update(SESSION_CHECKPOINT_DIGEST_DOMAIN);
    hash.update(bytes);
    format!("sha256:{:x}", crate::digest_hex::LowerHex(hash.finalize()))
}

/// Validate and construct the exact structured-export request that a session
/// may physically dispatch once. Its bounded idempotency key is a
/// domain-separated commitment to deployment, invocation, and stable event
/// identity, so sibling events in one invocation remain independent. No
/// adapter is called here.
pub fn prepare_export_event(
    capability: OutboundCapability,
    endpoint: String,
    deadline_ms: u64,
    event: ExportEvent,
) -> Result<PreparedExportEvent, Refusal> {
    let body = event.encode(&capability.policy)?;
    let event_id = event.stable_event_id;
    prepare_operational_export(
        capability,
        endpoint,
        deadline_ms,
        event_id,
        None,
        "application/json",
        "x-semaprax-event-id",
        EXPORT_IDEMPOTENCY_DOMAIN,
        body,
    )
}

/// Shared constructor for closed operational-export schemas. Each caller owns
/// its schema validation and a distinct idempotency domain; this helper only
/// binds the already-admitted canonical bytes to the common one-shot session.
pub(super) fn prepare_operational_export(
    capability: OutboundCapability,
    endpoint: String,
    deadline_ms: u64,
    record_id: String,
    replay_identity: Option<String>,
    content_type: &'static str,
    identity_header: &'static str,
    idempotency_domain: &'static [u8],
    body: Vec<u8>,
) -> Result<PreparedExportEvent, Refusal> {
    let origin = validate_common(&capability.policy, &endpoint, deadline_ms)?;
    let replay_identity = replay_identity.as_deref().unwrap_or(&record_id);
    if !valid_identity(&record_id) || !valid_identity(replay_identity) {
        return Err(Refusal::InvalidIdentity);
    }
    if body.len() > capability.policy.max_request_bytes {
        return Err(Refusal::RequestTooLarge);
    }
    let idempotency_key = operational_export_idempotency_key(
        idempotency_domain,
        &capability.deployment_binding,
        &capability.invocation_id,
        replay_identity,
    );
    let identity = DeliveryIdentity::new(
        capability.deployment_binding.clone(),
        capability.invocation_id.clone(),
        idempotency_key.clone(),
    )
    .map_err(|_| Refusal::InvalidIdentity)?;
    let session_identity_digest = session_identity_digest(
        &capability.deployment_binding,
        &capability.invocation_id,
        &idempotency_key,
    );
    let policy_digest = policy_digest(&capability.policy);
    let event_digest = event_digest(&body);
    let max_response_bytes = capability.policy.max_response_bytes;
    let request = PreparedRequest {
        method: HttpMethod::Post,
        endpoint,
        headers: vec![
            ("content-type".into(), content_type.into()),
            ("idempotency-key".into(), idempotency_key.clone()),
            (identity_header.into(), record_id.clone()),
        ],
        body,
        deadline_ms,
        max_redirects: 0,
        max_response_bytes,
    };
    let request_digest = request_digest(&request);
    Ok(PreparedExportEvent {
        capability,
        origin,
        event_id: record_id,
        idempotency_key,
        identity,
        session_identity_digest,
        policy_digest,
        event_digest,
        request_digest,
        request,
    })
}

fn export_idempotency_key(
    deployment_binding: &str,
    invocation_id: &str,
    stable_event_id: &str,
) -> String {
    operational_export_idempotency_key(
        EXPORT_IDEMPOTENCY_DOMAIN,
        deployment_binding,
        invocation_id,
        stable_event_id,
    )
}

fn operational_export_idempotency_key(
    domain: &[u8],
    deployment_binding: &str,
    invocation_id: &str,
    stable_record_id: &str,
) -> String {
    let mut hash = Sha256::new();
    hash.update(domain);
    for part in [deployment_binding, invocation_id, stable_record_id] {
        digest_part(&mut hash, part.as_bytes());
    }
    format!("sha256:{:x}", crate::digest_hex::LowerHex(hash.finalize()))
}

fn session_identity_digest(
    deployment_binding: &str,
    invocation_id: &str,
    idempotency_key: &str,
) -> String {
    let mut hash = Sha256::new();
    hash.update(SESSION_IDENTITY_DOMAIN);
    for part in [deployment_binding, invocation_id, idempotency_key] {
        digest_part(&mut hash, part.as_bytes());
    }
    format!("sha256:{:x}", crate::digest_hex::LowerHex(hash.finalize()))
}

fn policy_digest(policy: &OutboundPolicy) -> String {
    let mut hash = Sha256::new();
    hash.update(POLICY_COMMITMENT_DOMAIN);
    digest_part(&mut hash, policy.policy_id.as_bytes());
    hash.update((policy.allowed_origins.len() as u64).to_le_bytes());
    for origin in &policy.allowed_origins {
        digest_part(&mut hash, origin.as_bytes());
    }
    hash.update((policy.max_request_bytes as u64).to_le_bytes());
    hash.update((policy.max_response_bytes as u64).to_le_bytes());
    hash.update(policy.max_deadline_ms.to_le_bytes());
    hash.update((policy.max_export_fields as u64).to_le_bytes());
    hash.update((policy.max_export_labels as u64).to_le_bytes());
    format!("sha256:{:x}", crate::digest_hex::LowerHex(hash.finalize()))
}

fn event_digest(body: &[u8]) -> String {
    let mut hash = Sha256::new();
    hash.update(EVENT_COMMITMENT_DOMAIN);
    digest_part(&mut hash, body);
    format!("sha256:{:x}", crate::digest_hex::LowerHex(hash.finalize()))
}

#[cfg(test)]
#[path = "tracing_tests.rs"]
mod tests;
