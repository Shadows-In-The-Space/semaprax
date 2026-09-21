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
