//! Host-owned reconciliation for signed webhook delivery.
//!
//! Preparing consumes the signing secret and retains only the resulting
//! bounded request. Reconciliation records a disposition, not provider
//! response bytes, and exact replay never re-enters the adapter.

use std::collections::BTreeMap;
use std::fmt;

use sha2::{Digest as _, Sha256};

use super::ledger::delivery_session::{
    DeliverySessionCheckpoint, DeliverySessionCheckpointRefusal, DeliverySessionCheckpointStore,
    DeliverySessionCommitment, TypedDeliveryCheckpointStore,
};
use super::*;

/// An admitted and signed webhook request that has not reached an adapter.
/// The signing secret has already been consumed and zeroized; it is never
/// retained by this value or by the reconciliation session.
pub struct PreparedWebhookDelivery {
    capability: OutboundCapability,
    origin: String,
    delivery_id: String,
    idempotency_key: String,
    identity: DeliveryIdentity,
    session_identity_digest: String,
    policy_digest: String,
    request: PreparedRequest,
}

impl fmt::Debug for PreparedWebhookDelivery {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PreparedWebhookDelivery")
            .field("origin", &self.origin)
            .field("request", &self.request)
            .field("bindings", &"[REDACTED]")
            .finish()
    }
}

/// A disposition-only result from a host-owned webhook reconciliation
/// session. Provider response bytes are deliberately not retained or replayed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WebhookDeliveryReceipt {
    evidence: DeliveryEvidence,
    replayed: bool,
}

impl WebhookDeliveryReceipt {
    pub fn evidence(&self) -> &DeliveryEvidence {
        &self.evidence
    }

    pub fn was_replayed(&self) -> bool {
        self.replayed
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WebhookLedgerRefusal {
    Ledger(LedgerRefusal),
    PolicyChanged,
    ReplayBindingUnavailable,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WebhookDeliverySessionCheckpoint {
    inner: DeliverySessionCheckpoint,
}

impl WebhookDeliverySessionCheckpoint {
    pub fn render(&self) -> String {
        self.inner.render()
    }
    pub fn digest(&self) -> String {
        self.inner.digest()
    }
    pub fn capacity(&self) -> usize {
        self.inner.capacity()
    }
}

pub trait WebhookDeliverySessionCheckpointStore {
    fn commit(&mut self, checkpoint: &WebhookDeliverySessionCheckpoint) -> CheckpointCommit;
}

pub struct WebhookDeliverySessionRestoreCapability {
    expected_digest: String,
    expected_capacity: usize,
}

impl WebhookDeliverySessionRestoreCapability {
    pub fn grant_for_trusted_host(
        expected_digest: impl Into<String>,
        expected_capacity: usize,
    ) -> Result<Self, WebhookDeliverySessionRestoreRefusal> {
        let expected_digest = expected_digest.into();
        if !valid_sha256(&expected_digest)
            || expected_capacity == 0
            || expected_capacity > MAX_LEDGER_ENTRIES
        {
            return Err(WebhookDeliverySessionRestoreRefusal::InvalidCapability);
        }
        Ok(Self {
            expected_digest,
            expected_capacity,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WebhookDeliverySessionRestoreRefusal {
    InvalidCapability,
    Checkpoint(DeliverySessionCheckpointRefusal),
    CapacityMismatch,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DurableWebhookDeliveryOutcome {
    Dispatched(WebhookDeliveryReceipt),
    Replayed(WebhookDeliveryReceipt),
    IntentNotCommitted,
    IntentUncertain(WebhookDeliveryReceipt),
    SettlementUncertain(WebhookDeliveryReceipt),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DurableWebhookLedgerRefusal {
    Session(WebhookLedgerRefusal),
    Durable(DurableLedgerRefusal),
}

impl From<LedgerRefusal> for WebhookLedgerRefusal {
    fn from(value: LedgerRefusal) -> Self {
        Self::Ledger(value)
    }
}

/// Process-local disposition ledger for signed webhooks. Commitments bind the
/// complete effective policy rather than treating its caller-selected label as
/// content addressed. This is neither durable storage nor delivery authority.
pub struct WebhookDeliverySession {
    ledger: HostDeliveryLedger,
    policy_commitments: BTreeMap<String, DeliverySessionCommitment>,
}

impl WebhookDeliverySession {
    pub fn new(capacity: usize) -> Result<Self, WebhookLedgerRefusal> {
        Ok(Self {
            ledger: HostDeliveryLedger::new(capacity)?,
            policy_commitments: BTreeMap::new(),
        })
    }

    pub fn len(&self) -> usize {
        self.ledger.len()
    }

    /// Export disposition observations only, excluding session policy bindings.
    /// An imported checkpoint is read-only and cannot restore this session.
    pub fn checkpoint(&self) -> Result<LedgerCheckpoint, LedgerCheckpointRefusal> {
        self.ledger.checkpoint()
    }

    pub fn session_checkpoint(
        &self,
    ) -> Result<WebhookDeliverySessionCheckpoint, DeliverySessionCheckpointRefusal> {
        Ok(WebhookDeliverySessionCheckpoint {
            inner: DeliverySessionCheckpoint::from_session(
                "webhook",
                &self.ledger,
                &self.policy_commitments,
            )?,
        })
    }

    pub fn restore_authenticated(
        bytes: &[u8],
        capability: WebhookDeliverySessionRestoreCapability,
    ) -> Result<Self, WebhookDeliverySessionRestoreRefusal> {
        let checkpoint =
            DeliverySessionCheckpoint::decode(bytes, &capability.expected_digest, "webhook")
                .map_err(WebhookDeliverySessionRestoreRefusal::Checkpoint)?;
        if checkpoint.capacity() != capability.expected_capacity {
            return Err(WebhookDeliverySessionRestoreRefusal::CapacityMismatch);
        }
        let (ledger, policy_commitments) = checkpoint
            .restore()
            .map_err(WebhookDeliverySessionRestoreRefusal::Checkpoint)?;
        Ok(Self {
            ledger,
            policy_commitments,
        })
    }

    pub fn verify_checkpoint(
        &self,
        checkpoint: &LedgerCheckpoint,
    ) -> Result<(), LedgerCheckpointRefusal> {
        checkpoint.verify_against(&self.ledger)
    }

    /// Reconcile exactly one prepared request. A matching replay does not call
    /// the adapter. A panic after adapter entry leaves the ledger's provisional
    /// uncertainty and its policy binding sticky, preventing an automatic
    /// retry while allowing an exact receipt replay in this session.
    pub fn reconcile(
        &mut self,
        prepared: PreparedWebhookDelivery,
        adapter: &mut impl OutboundAdapter,
    ) -> Result<WebhookDeliveryReceipt, WebhookLedgerRefusal> {
        if let Some(existing) = self
            .policy_commitments
            .get(&prepared.session_identity_digest)
        {
            if existing.policy != prepared.policy_digest {
                return Err(WebhookLedgerRefusal::PolicyChanged);
            }
        }

        let inserted_commitment = if self
            .policy_commitments
            .contains_key(&prepared.session_identity_digest)
        {
            false
        } else {
            self.policy_commitments.insert(
                prepared.session_identity_digest.clone(),
                DeliverySessionCommitment {
                    policy: prepared.policy_digest.clone(),
                    request: request_digest(&prepared.request),
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
                        self.policy_commitments
                            .remove(&prepared.session_identity_digest);
                    }
                    return Err(refusal.into());
                }
            };
        let replayed = !outcome.was_dispatched();
        if replayed
            && !self
                .policy_commitments
                .contains_key(&prepared.session_identity_digest)
        {
            return Err(WebhookLedgerRefusal::ReplayBindingUnavailable);
        }
        let disposition = outcome.record().disposition().clone();
        Ok(WebhookDeliveryReceipt {
            evidence: delivery_evidence(
                prepared.capability,
                prepared.origin,
                prepared.delivery_id,
                prepared.idempotency_key,
                prepared.request,
                disposition,
            ),
            replayed,
        })
    }

    pub fn reconcile_durable(
        &mut self,
        prepared: PreparedWebhookDelivery,
        store: &mut impl WebhookDeliverySessionCheckpointStore,
        adapter: &mut impl OutboundAdapter,
    ) -> Result<DurableWebhookDeliveryOutcome, DurableWebhookLedgerRefusal> {
        if policy_digest(&prepared.capability.policy) != prepared.policy_digest {
            return Err(DurableWebhookLedgerRefusal::Session(
                WebhookLedgerRefusal::PolicyChanged,
            ));
        }
        if let Some(existing) = self
            .policy_commitments
            .get(&prepared.session_identity_digest)
        {
            if existing.policy != prepared.policy_digest {
                return Err(DurableWebhookLedgerRefusal::Session(
                    WebhookLedgerRefusal::PolicyChanged,
                ));
            }
        }
        let inserted = if self
            .policy_commitments
            .contains_key(&prepared.session_identity_digest)
        {
            false
        } else {
            self.policy_commitments.insert(
                prepared.session_identity_digest.clone(),
                DeliverySessionCommitment {
                    policy: prepared.policy_digest.clone(),
                    request: request_digest(&prepared.request),
                },
            );
            true
        };
        let mut wrapper = WebhookTypedCheckpointStore { store };
        let mut typed_store = TypedDeliveryCheckpointStore {
            store: &mut wrapper,
            kind: "webhook",
            commitments: &self.policy_commitments,
        };
        let outcome = self.ledger.reconcile_durable(
            prepared.identity.clone(),
            &prepared.request,
            &mut typed_store,
            |request| settlement_disposition(request, &adapter.send(request)),
        );
        let outcome = match outcome {
            Ok(outcome) => outcome,
            Err(error) => {
                if inserted {
                    self.policy_commitments
                        .remove(&prepared.session_identity_digest);
                }
                return Err(DurableWebhookLedgerRefusal::Durable(error));
            }
        };
        if matches!(outcome, DurableLedgerOutcome::IntentNotCommitted) && inserted {
            self.policy_commitments
                .remove(&prepared.session_identity_digest);
        }
        Ok(match outcome {
            DurableLedgerOutcome::Dispatched(record) => DurableWebhookDeliveryOutcome::Dispatched(
                durable_webhook_receipt(prepared, record, false),
            ),
            DurableLedgerOutcome::Replayed(record) => DurableWebhookDeliveryOutcome::Replayed(
                durable_webhook_receipt(prepared, record, true),
            ),
            DurableLedgerOutcome::IntentNotCommitted => {
                DurableWebhookDeliveryOutcome::IntentNotCommitted
            }
            DurableLedgerOutcome::IntentUncertain(record) => {
                DurableWebhookDeliveryOutcome::IntentUncertain(durable_webhook_receipt(
                    prepared, record, false,
                ))
            }
            DurableLedgerOutcome::SettlementUncertain(record) => {
                DurableWebhookDeliveryOutcome::SettlementUncertain(durable_webhook_receipt(
                    prepared, record, false,
                ))
            }
        })
    }
}

struct WebhookTypedCheckpointStore<'a, Store> {
    store: &'a mut Store,
}

impl<Store: WebhookDeliverySessionCheckpointStore> DeliverySessionCheckpointStore
    for WebhookTypedCheckpointStore<'_, Store>
{
    fn commit(&mut self, checkpoint: &DeliverySessionCheckpoint) -> CheckpointCommit {
        self.store.commit(&WebhookDeliverySessionCheckpoint {
            inner: checkpoint.clone(),
        })
    }
}

fn durable_webhook_receipt(
    prepared: PreparedWebhookDelivery,
    record: LedgerRecord,
    replayed: bool,
) -> WebhookDeliveryReceipt {
    WebhookDeliveryReceipt {
        evidence: delivery_evidence(
            prepared.capability,
            prepared.origin,
            prepared.delivery_id,
            prepared.idempotency_key,
            prepared.request,
            record.disposition().clone(),
        ),
        replayed,
    }
}

/// Validate and sign the exact request that a reconciliation session may
/// dispatch once. No adapter is called and no signing key is retained.
pub fn prepare_webhook_delivery(
    capability: OutboundCapability,
    secret: WebhookSigningSecret,
    request: WebhookRequest,
) -> Result<PreparedWebhookDelivery, Refusal> {
    validate_webhook(&capability.policy, &request)?;
    let (origin, target) =
        canonical_endpoint_parts(&request.endpoint).ok_or(Refusal::InvalidEndpoint)?;
    if !capability.policy.allowed_origins.contains(&origin) {
        return Err(Refusal::AuthorityDenied);
    }
    let signature = sign_webhook(
        &secret,
        &capability.deployment_binding,
        &origin,
        &target,
        &request.delivery_id,
        &request.idempotency_key,
        &request.content_type,
        &request.body,
    )?;
    let identity = DeliveryIdentity::new(
        capability.deployment_binding.clone(),
        capability.invocation_id.clone(),
        request.idempotency_key.clone(),
    )
    .map_err(|_| Refusal::InvalidIdentity)?;
    let session_identity_digest = session_identity_digest(
        &capability.deployment_binding,
        &capability.invocation_id,
        &request.idempotency_key,
    );
    let policy_digest = policy_digest(&capability.policy);
    let max_response_bytes = capability.policy.max_response_bytes;
    Ok(PreparedWebhookDelivery {
        capability,
        origin,
        delivery_id: request.delivery_id.clone(),
        idempotency_key: request.idempotency_key.clone(),
        identity,
        session_identity_digest,
        policy_digest,
        request: PreparedRequest {
            method: HttpMethod::Post,
            endpoint: request.endpoint,
            headers: vec![
                ("content-type".into(), request.content_type),
                ("idempotency-key".into(), request.idempotency_key),
                ("x-semaprax-delivery-id".into(), request.delivery_id),
                ("x-semaprax-signature-v2".into(), signature),
            ],
            body: request.body,
            deadline_ms: request.deadline_ms,
            max_redirects: 0,
            max_response_bytes,
        },
    })
}

fn session_identity_digest(
    deployment_binding: &str,
    invocation_id: &str,
    idempotency_key: &str,
) -> String {
    let mut hash = Sha256::new();
    hash.update(b"semaprax.outbound.webhook-session.identity.v1\0");
    for part in [deployment_binding, invocation_id, idempotency_key] {
        digest_part(&mut hash, part.as_bytes());
    }
    format!("sha256:{:x}", crate::digest_hex::LowerHex(hash.finalize()))
}

fn policy_digest(policy: &OutboundPolicy) -> String {
    let mut hash = Sha256::new();
    hash.update(b"semaprax.outbound.webhook-session.policy.v1\0");
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
