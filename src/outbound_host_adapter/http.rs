//! Bounded high-level HTTPS requests with process-local idempotency replay.
//!
//! This module owns request admission and settlement only. It grants no DNS,
//! socket, credential, retry, redirect, or persistence authority. The injected
//! adapter remains the sole physical transport capability.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use sha2::{Digest as _, Sha256};

use super::*;

const RESERVED_HEADERS: [&str; 3] = ["content-type", "idempotency-key", "x-semaprax-delivery-id"];
// Names with an `x-` prefix are not protected-name aliases, but are still
// explicit credential channels at this caller-controlled boundary.
const EXPLICIT_CREDENTIAL_HEADERS: [&str; 1] = ["x-api-key"];

/// One public caller-selected header. Credential-bearing header names are not
/// admitted; a trusted provider adapter may add credentials outside this
/// request value without exposing them to source or evidence.
#[derive(Clone, Eq, PartialEq)]
pub struct HttpHeader {
    name: String,
    value: String,
}

impl HttpHeader {
    pub fn new(name: impl Into<String>, value: impl Into<String>) -> Result<Self, Refusal> {
        let name = name.into();
        let value = value.into();
        if name != name.to_ascii_lowercase()
            || !valid_header_name(&name)
            || value.len() > MAX_HEADER_VALUE_BYTES
            || contains_control(&value)
            || RESERVED_HEADERS.contains(&name.as_str())
            || credential_header_name(&name)
        {
            return Err(Refusal::InvalidHeader);
        }
        Ok(Self { name, value })
    }

    pub fn name(&self) -> &str {
        &self.name
    }
}

impl fmt::Debug for HttpHeader {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HttpHeader")
            .field("name", &self.name)
            .field("value", &"[REDACTED]")
            .finish()
    }
}

/// One bounded high-level HTTPS request. Redirects and transport retries are
/// always disabled. `idempotency_key` identifies process-local reconciliation;
/// it does not assert that a remote service implements exactly-once delivery.
pub struct HttpRequest {
    pub method: HttpMethod,
    pub endpoint: String,
    pub request_id: String,
    pub idempotency_key: String,
    pub content_type: Option<String>,
    pub headers: Vec<HttpHeader>,
    pub body: Vec<u8>,
    pub deadline_ms: u64,
}

impl fmt::Debug for HttpRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HttpRequest")
            .field("method", &self.method)
            .field("endpoint_origin", &canonical_origin(&self.endpoint))
            .field("request_id", &"[REDACTED]")
            .field("idempotency_key", &"[REDACTED]")
            .field(
                "header_names",
                &self
                    .headers
                    .iter()
                    .map(HttpHeader::name)
                    .collect::<Vec<_>>(),
            )
            .field("body_bytes", &self.body.len())
            .field("deadline_ms", &self.deadline_ms)
            .finish()
    }
}

pub struct PreparedHttpDelivery {
    capability: OutboundCapability,
    origin: String,
    request_id: String,
    idempotency_key: String,
    identity: DeliveryIdentity,
    session_identity_digest: String,
    policy_digest: String,
    request: PreparedRequest,
}

impl fmt::Debug for PreparedHttpDelivery {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PreparedHttpDelivery")
            .field("origin", &self.origin)
            .field("request", &self.request)
            .field("bindings", &"[REDACTED]")
            .finish()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HttpDeliveryReceipt {
    evidence: DeliveryEvidence,
    replayed: bool,
}

impl HttpDeliveryReceipt {
    pub fn evidence(&self) -> &DeliveryEvidence {
        &self.evidence
    }

    pub fn was_replayed(&self) -> bool {
        self.replayed
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HttpLedgerRefusal {
    Ledger(LedgerRefusal),
    PolicyChanged,
    ReplayBindingUnavailable,
}

impl From<LedgerRefusal> for HttpLedgerRefusal {
    fn from(value: LedgerRefusal) -> Self {
        Self::Ledger(value)
    }
}

/// Process-local disposition reconciliation for high-level HTTPS requests.
/// Provider response bytes are deliberately not stored or replayed.
pub struct HttpDeliverySession {
    ledger: HostDeliveryLedger,
    policy_commitments: BTreeMap<String, String>,
}

impl HttpDeliverySession {
    pub fn new(capacity: usize) -> Result<Self, HttpLedgerRefusal> {
        Ok(Self {
            ledger: HostDeliveryLedger::new(capacity)?,
            policy_commitments: BTreeMap::new(),
        })
    }

    pub fn len(&self) -> usize {
        self.ledger.len()
    }

    pub fn checkpoint(&self) -> Result<LedgerCheckpoint, LedgerCheckpointRefusal> {
        self.ledger.checkpoint()
    }

    pub fn verify_checkpoint(
        &self,
        checkpoint: &LedgerCheckpoint,
    ) -> Result<(), LedgerCheckpointRefusal> {
        checkpoint.verify_against(&self.ledger)
    }

    pub fn reconcile(
        &mut self,
        prepared: PreparedHttpDelivery,
        adapter: &mut impl OutboundAdapter,
    ) -> Result<HttpDeliveryReceipt, HttpLedgerRefusal> {
        if let Some(existing) = self
            .policy_commitments
            .get(&prepared.session_identity_digest)
        {
            if existing != &prepared.policy_digest {
                return Err(HttpLedgerRefusal::PolicyChanged);
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
                prepared.policy_digest.clone(),
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
            return Err(HttpLedgerRefusal::ReplayBindingUnavailable);
        }
        let disposition = outcome.record().disposition().clone();
        Ok(HttpDeliveryReceipt {
            evidence: delivery_evidence(
                prepared.capability,
                prepared.origin,
                prepared.request_id,
                prepared.idempotency_key,
                prepared.request,
                disposition,
            ),
            replayed,
        })
    }
}

/// Validate the complete request before it can reach a transport.
pub fn prepare_http_delivery(
    capability: OutboundCapability,
    request: HttpRequest,
) -> Result<PreparedHttpDelivery, Refusal> {
    let origin = validate_http(&capability.policy, &request)?;
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
    let request_id = request.request_id.clone();
    let idempotency_key = request.idempotency_key.clone();
    let max_response_bytes = capability.policy.max_response_bytes;
    let prepared = into_prepared(request, max_response_bytes);
    Ok(PreparedHttpDelivery {
        capability,
        origin,
        request_id,
        idempotency_key,
        identity,
        session_identity_digest,
        policy_digest,
        request: prepared,
    })
}

/// Validate and attempt exactly one request. The adapter contract disables
/// redirects and retries; any failure after entry is settled as uncertain.
pub fn deliver_http(
    capability: OutboundCapability,
    request: HttpRequest,
    adapter: &mut impl OutboundAdapter,
) -> Result<DeliveryResult, Refusal> {
    let origin = validate_http(&capability.policy, &request)?;
    let request_id = request.request_id.clone();
    let idempotency_key = request.idempotency_key.clone();
    let max_response_bytes = capability.policy.max_response_bytes;
    let prepared = into_prepared(request, max_response_bytes);
    let observation = adapter.send(&prepared);
    Ok(settle(
        capability,
        origin,
        request_id,
        idempotency_key,
        prepared,
        observation,
    ))
}

fn validate_http(policy: &OutboundPolicy, request: &HttpRequest) -> Result<String, Refusal> {
    let origin = validate_common(policy, &request.endpoint, request.deadline_ms)?;
    if !valid_identity(&request.request_id) || !valid_identity(&request.idempotency_key) {
        return Err(Refusal::InvalidIdentity);
    }
    if request.body.len() > policy.max_request_bytes {
        return Err(Refusal::RequestTooLarge);
    }
    if request.method == HttpMethod::Get && !request.body.is_empty() {
        return Err(Refusal::InvalidHeader);
    }
    if request.headers.len() + usize::from(request.content_type.is_some()) + 2 > MAX_HEADERS {
        return Err(Refusal::InvalidHeader);
    }
    if request.content_type.as_ref().is_some_and(|value| {
        value.is_empty() || value.len() > 128 || contains_control(value) || value.contains(' ')
    }) {
        return Err(Refusal::InvalidContentType);
    }
    let mut names = BTreeSet::new();
    if request.headers.iter().any(|header| {
        !names.insert(header.name.as_str())
            || RESERVED_HEADERS.contains(&header.name.as_str())
            || credential_header_name(&header.name)
    }) {
        return Err(Refusal::InvalidHeader);
    }
    Ok(origin)
}

/// Reject both the HTTP-specific credential channels and the shared closed
/// protected-name vocabulary. This keeps caller-selected HTTP headers from
/// becoming a bypass around the export/redaction boundary while preserving the
/// deliberately exact (not substring-based) protected-name policy.
fn credential_header_name(name: &str) -> bool {
    EXPLICIT_CREDENTIAL_HEADERS.contains(&name) || protected_names::is_protected(name)
}

fn into_prepared(request: HttpRequest, max_response_bytes: usize) -> PreparedRequest {
    let mut headers = Vec::with_capacity(request.headers.len() + 3);
    headers.push(("idempotency-key".into(), request.idempotency_key));
    headers.push(("x-semaprax-delivery-id".into(), request.request_id));
    if let Some(content_type) = request.content_type {
        headers.push(("content-type".into(), content_type));
    }
    headers.extend(
        request
            .headers
            .into_iter()
            .map(|header| (header.name, header.value)),
    );
    PreparedRequest {
        method: request.method,
        endpoint: request.endpoint,
        headers,
        body: request.body,
        deadline_ms: request.deadline_ms,
        max_redirects: 0,
        max_response_bytes,
    }
}

fn session_identity_digest(
    deployment_binding: &str,
    invocation_id: &str,
    idempotency_key: &str,
) -> String {
    let mut hash = Sha256::new();
    hash.update(b"semaprax.outbound.http-session.identity.v1\0");
    for part in [deployment_binding, invocation_id, idempotency_key] {
        digest_part(&mut hash, part.as_bytes());
    }
    format!("sha256:{:x}", crate::digest_hex::LowerHex(hash.finalize()))
}

fn policy_digest(policy: &OutboundPolicy) -> String {
    let mut hash = Sha256::new();
    hash.update(b"semaprax.outbound.http-session.policy.v1\0");
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

#[cfg(test)]
mod tests;
