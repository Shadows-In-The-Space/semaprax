//! Host-owned reconciliation for signed webhook delivery.
//!
//! Preparing consumes the signing secret and retains only the resulting
//! bounded request. Reconciliation records a disposition, not provider
//! response bytes, and exact replay never re-enters the adapter.

use std::collections::BTreeMap;
use std::fmt;

use sha2::{Digest as _, Sha256};

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
    policy_commitments: BTreeMap<String, String>,
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

    /// Reconcile exactly one prepared request. A matching replay does not call
    /// the adapter. A panic after adapter entry leaves the ledger's provisional
    /// uncertainty sticky, preventing an automatic retry in this session.
    pub fn reconcile(
        &mut self,
        prepared: PreparedWebhookDelivery,
        adapter: &mut impl OutboundAdapter,
    ) -> Result<WebhookDeliveryReceipt, WebhookLedgerRefusal> {
        if let Some(existing) = self
            .policy_commitments
            .get(&prepared.session_identity_digest)
        {
            if existing != &prepared.policy_digest {
                return Err(WebhookLedgerRefusal::PolicyChanged);
            }
        }

        let outcome =
            self.ledger
                .reconcile(prepared.identity.clone(), &prepared.request, |request| {
                    let observation = adapter.send(request);
                    settlement_disposition(request, &observation)
                })?;
        let replayed = !outcome.was_dispatched();
        if replayed
            && !self
                .policy_commitments
                .contains_key(&prepared.session_identity_digest)
        {
            return Err(WebhookLedgerRefusal::ReplayBindingUnavailable);
        }
        if !replayed {
            self.policy_commitments.insert(
                prepared.session_identity_digest.clone(),
                prepared.policy_digest.clone(),
            );
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
