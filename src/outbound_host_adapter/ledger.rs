//! Bounded, host-owned reconciliation for outbound delivery state.
//!
//! This is deliberately below the capability boundary. It remembers only a
//! canonical request digest and a closed local disposition; it cannot mint an
//! [`super::OutboundCapability`], prove remote receipt, replay a response, or
//! recover work after a process restart without separate host authority.

use std::collections::BTreeMap;
use std::fmt;

use sha2::{Digest as _, Sha256};

use super::{request_digest, valid_identity, DeliveryDisposition, PreparedRequest};

#[path = "ledger_checkpoint.rs"]
mod checkpoint;
pub use checkpoint::{LedgerCheckpoint, LedgerCheckpointRefusal, MAX_LEDGER_CHECKPOINT_BYTES};
#[path = "ledger_durable.rs"]
mod durable;
pub use durable::{
    CheckpointCommit, DurableLedgerOutcome, DurableLedgerRefusal, LedgerCheckpointStore,
    LedgerRestoreCapability, LedgerRestoreRefusal,
};

const LEDGER_IDENTITY_DOMAIN: &[u8] = b"semaprax.outbound.delivery-ledger.identity.v1\0";
const LEDGER_STATE_DOMAIN: &str = "semaprax.outbound.delivery-ledger.v1";

/// Upper bound on remembered outbound identities in one host-owned ledger.
pub const MAX_LEDGER_ENTRIES: usize = 256;

/// Bounded identity selected by the trusted host before it enters its adapter.
///
/// The complete request is bound separately through the canonical digest of the
/// prepared request. A delivery ID is therefore not repeated here: the
/// boundary-owned delivery/event header is already part of that digest.
#[derive(Clone, Eq, Ord, PartialEq, PartialOrd)]
pub struct DeliveryIdentity {
    deployment_binding: String,
    invocation_id: String,
    idempotency_key: String,
}

impl DeliveryIdentity {
    pub fn new(
        deployment_binding: impl Into<String>,
        invocation_id: impl Into<String>,
        idempotency_key: impl Into<String>,
    ) -> Result<Self, LedgerRefusal> {
        let deployment_binding = deployment_binding.into();
        let invocation_id = invocation_id.into();
        let idempotency_key = idempotency_key.into();
        if !valid_identity(&deployment_binding)
            || !valid_identity(&invocation_id)
            || !valid_identity(&idempotency_key)
        {
            return Err(LedgerRefusal::InvalidIdentity);
        }
        Ok(Self {
            deployment_binding,
            invocation_id,
            idempotency_key,
        })
    }

    fn digest(&self) -> String {
        let mut hash = Sha256::new();
        hash.update(LEDGER_IDENTITY_DOMAIN);
        for part in [
            self.deployment_binding.as_bytes(),
            self.invocation_id.as_bytes(),
            self.idempotency_key.as_bytes(),
        ] {
            hash.update((part.len() as u64).to_le_bytes());
            hash.update(part);
        }
        format!("sha256:{:x}", crate::digest_hex::LowerHex(hash.finalize()))
    }

    fn matches_request(&self, request: &PreparedRequest) -> bool {
        let mut headers = request
            .headers()
            .iter()
            .filter(|(name, _)| name == "idempotency-key");
        matches!(headers.next(), Some((_, value)) if value == &self.idempotency_key)
            && headers.next().is_none()
    }
}

impl fmt::Debug for DeliveryIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DeliveryIdentity")
            .field("binding", &"[OMITTED]")
            .finish()
    }
}

/// A closed local disposition remembered by a host ledger.
///
/// This is not evidence, a remote receipt, or authority to issue another
/// request. It intentionally retains no request body, headers, response body,
/// endpoint, or raw identity components.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LedgerRecord {
    request_digest: String,
    disposition: DeliveryDisposition,
}

impl LedgerRecord {
    pub fn request_digest(&self) -> &str {
        &self.request_digest
    }

    pub fn disposition(&self) -> &DeliveryDisposition {
        &self.disposition
    }
}

/// Whether the caller's dispatch closure was entered by reconciliation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LedgerOutcome {
    /// The ledger had no prior knowledge and ran the supplied one-shot action.
    Dispatched(LedgerRecord),
    /// Exact prior identity and request; the action was deliberately not run.
    Replayed(LedgerRecord),
}

impl LedgerOutcome {
    pub fn record(&self) -> &LedgerRecord {
        match self {
            Self::Dispatched(record) | Self::Replayed(record) => record,
        }
    }

    pub fn was_dispatched(&self) -> bool {
        matches!(self, Self::Dispatched(_))
    }
}

/// Refusals that occur before the reconciliation closure is entered.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LedgerRefusal {
    InvalidIdentity,
    IdentityRequestMismatch,
    InvalidCapacity,
    CapacityExceeded,
    ConflictingRequest,
}

/// Bounded reconciliation state owned by a trusted host.
///
/// A fresh identity is admitted only while there is capacity. The closure is
/// invoked at most once for that identity/request pair, and its resulting
/// local observation is sticky. In particular, `Uncertain` is never retried by
/// this type. Plain construction is process-local; authenticated checkpoint
/// restoration is an explicit, separately authorized host action.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HostDeliveryLedger {
    capacity: usize,
    // Raw identity components are deliberately transient. This map retains
    // only their domain-separated SHA-256 commitment, not deployment,
    // invocation, or idempotency strings.
    entries: BTreeMap<String, LedgerRecord>,
}

impl HostDeliveryLedger {
    pub fn new(capacity: usize) -> Result<Self, LedgerRefusal> {
        if capacity == 0 || capacity > MAX_LEDGER_ENTRIES {
            return Err(LedgerRefusal::InvalidCapacity);
        }
        Ok(Self {
            capacity,
            entries: BTreeMap::new(),
        })
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Export bounded, commitment-only observations for offline comparison.
    /// Import returns a read-only checkpoint, never another dispatch ledger.
    pub fn checkpoint(&self) -> Result<LedgerCheckpoint, LedgerCheckpointRefusal> {
        LedgerCheckpoint::from_ledger(self)
    }

    /// Restore dispatch-capable state only through an independently granted
    /// host capability bound to the exact checkpoint commitment and capacity.
    /// The checkpoint itself remains authority-free.
    pub fn restore_authenticated(
        bytes: &[u8],
        capability: LedgerRestoreCapability,
    ) -> Result<Self, LedgerRestoreRefusal> {
        durable::restore_authenticated(bytes, capability)
    }

    /// Persist intent before dispatch and terminal observation afterwards.
    /// No timer or retry is created: a caller must present a distinct trusted
    /// capability/identity for any later attempt.
    pub fn reconcile_durable(
        &mut self,
        identity: DeliveryIdentity,
        request: &PreparedRequest,
        store: &mut impl LedgerCheckpointStore,
        dispatch: impl FnOnce(&PreparedRequest) -> DeliveryDisposition,
    ) -> Result<DurableLedgerOutcome, DurableLedgerRefusal> {
        durable::reconcile(self, identity, request, store, dispatch)
    }

    /// Reconcile one exact prepared request before adapter dispatch.
    ///
    /// The action receives the exact request whose canonical digest is bound
    /// into this ledger entry, must perform at most one physical attempt, and
    /// returns the closed disposition for that attempt. The ledger's replay
    /// branch does not enter it, which prevents an exact retry even for
    /// `NotDispatched`; callers wanting a distinct human-authorized attempt
    /// must allocate a distinct invocation identity.
    pub fn reconcile(
        &mut self,
        identity: DeliveryIdentity,
        request: &PreparedRequest,
        dispatch: impl FnOnce(&PreparedRequest) -> DeliveryDisposition,
    ) -> Result<LedgerOutcome, LedgerRefusal> {
        if !identity.matches_request(request) {
            return Err(LedgerRefusal::IdentityRequestMismatch);
        }
        let identity_digest = identity.digest();
        let digest = request_digest(request);
        if let Some(record) = self.entries.get(&identity_digest) {
            return if record.request_digest == digest {
                Ok(LedgerOutcome::Replayed(record.clone()))
            } else {
                Err(LedgerRefusal::ConflictingRequest)
            };
        }
        if self.entries.len() >= self.capacity {
            return Err(LedgerRefusal::CapacityExceeded);
        }

        // Reserve an unknown terminal disposition before the host closure can
        // reach a physical adapter. If it unwinds after start, normal Rust
        // unwinding leaves this conservative state in the map and a caught
        // caller cannot make this ledger retry the request.
        let provisional = LedgerRecord {
            request_digest: digest,
            disposition: DeliveryDisposition::Uncertain {
                reason: super::AdapterFailure::Transport,
            },
        };
        self.entries.insert(identity_digest.clone(), provisional);
        let disposition = dispatch(request);
        let record = self
            .entries
            .get_mut(&identity_digest)
            .expect("just-reserved ledger entry remains present");
        record.disposition = disposition;
        let record = record.clone();
        Ok(LedgerOutcome::Dispatched(record))
    }

    /// Canonical bounded diagnostic state for a trusted host's own storage.
    ///
    /// This wire form records no raw identity or request material. Its SHA-256
    /// commitments are not confidential redactions; a low-entropy identity can
    /// be guessed and checked offline. The bytes alone carry no authority. An
    /// exact checkpoint can become live state only through
    /// `restore_authenticated` and a separately host-minted capability bound to
    /// its independently retained digest and capacity.
    pub fn render(&self) -> String {
        let entries = self
            .entries
            .iter()
            .map(|(identity_digest, record)| {
                serde_json::json!({
                    "identity_digest": identity_digest,
                    "request_digest": record.request_digest,
                    "disposition": render_disposition(&record.disposition),
                })
            })
            .collect::<Vec<_>>();
        serde_json::to_string(&serde_json::json!({
            "schema": LEDGER_STATE_DOMAIN,
            "capacity": self.capacity,
            "entries": entries,
        }))
        .expect("bounded host ledger state always encodes")
    }
}

fn render_disposition(disposition: &DeliveryDisposition) -> serde_json::Value {
    match disposition {
        DeliveryDisposition::NotDispatched { reason } => {
            serde_json::json!({"kind": "not_dispatched", "reason": reason.as_str()})
        }
        DeliveryDisposition::Accepted { status } => {
            serde_json::json!({"kind": "accepted", "status": status})
        }
        DeliveryDisposition::Rejected { status } => {
            serde_json::json!({"kind": "rejected", "status": status})
        }
        DeliveryDisposition::Uncertain { reason } => {
            serde_json::json!({"kind": "uncertain", "reason": reason.as_str()})
        }
        DeliveryDisposition::DeadlineUncertain => serde_json::json!({"kind": "deadline_uncertain"}),
        DeliveryDisposition::ResponseTooLargeUncertain => {
            serde_json::json!({"kind": "response_too_large_uncertain"})
        }
    }
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;
    use std::panic::{catch_unwind, AssertUnwindSafe};

    use super::*;
    use crate::outbound_host_adapter::AdapterFailure;

    fn identity(number: u8) -> DeliveryIdentity {
        DeliveryIdentity::new(
            format!("deployment-{number}"),
            format!("invocation-{number}"),
            format!("idempotency-{number}"),
        )
        .unwrap()
    }

    fn request(number: u8, body: &[u8]) -> PreparedRequest {
        PreparedRequest {
            method: crate::outbound_host_adapter::HttpMethod::Post,
            endpoint: "https://hooks.example.test/v1/events".into(),
            headers: vec![
                ("content-type".into(), "application/json".into()),
                ("idempotency-key".into(), format!("idempotency-{number}")),
                ("x-semaprax-delivery-id".into(), "delivery-1".into()),
            ],
            body: body.to_vec(),
            deadline_ms: 1_000,
            max_redirects: 0,
            max_response_bytes: 128,
        }
    }

    #[test]
    fn exact_replay_is_observational_and_never_redispatches() {
        let mut ledger = HostDeliveryLedger::new(2).unwrap();
        let calls = Cell::new(0);
        let first = ledger
            .reconcile(identity(1), &request(1, b"same"), |prepared| {
                assert_eq!(prepared.body(), b"same");
                calls.set(calls.get() + 1);
                DeliveryDisposition::Accepted { status: 202 }
            })
            .unwrap();
        let replay = ledger
            .reconcile(identity(1), &request(1, b"same"), |_| {
                calls.set(calls.get() + 1);
                DeliveryDisposition::Rejected { status: 500 }
            })
            .unwrap();

        assert!(first.was_dispatched());
        assert!(!replay.was_dispatched());
        assert_eq!(calls.get(), 1);
        assert_eq!(first.record(), replay.record());
        assert_eq!(
            replay.record().disposition(),
            &DeliveryDisposition::Accepted { status: 202 }
        );
    }

    #[test]
    fn changed_payload_under_the_same_identity_refuses_before_dispatch() {
        let mut ledger = HostDeliveryLedger::new(2).unwrap();
        ledger
            .reconcile(identity(1), &request(1, b"first"), |_| {
                DeliveryDisposition::Rejected { status: 409 }
            })
            .unwrap();
        let calls = Cell::new(0);
        assert_eq!(
            ledger.reconcile(identity(1), &request(1, b"changed"), |_| {
                calls.set(calls.get() + 1);
                DeliveryDisposition::Accepted { status: 200 }
            }),
            Err(LedgerRefusal::ConflictingRequest)
        );
        assert_eq!(calls.get(), 0);
    }

    #[test]
    fn mismatched_or_duplicate_idempotency_header_refuses_before_dispatch() {
        let mut ledger = HostDeliveryLedger::new(2).unwrap();
        let calls = Cell::new(0);
        assert_eq!(
            ledger.reconcile(identity(2), &request(1, b"same"), |_| {
                calls.set(calls.get() + 1);
                DeliveryDisposition::Accepted { status: 200 }
            }),
            Err(LedgerRefusal::IdentityRequestMismatch)
        );

        let mut duplicate = request(1, b"same");
        duplicate
            .headers
            .push(("idempotency-key".into(), "idempotency-1".into()));
        assert_eq!(
            ledger.reconcile(identity(1), &duplicate, |_| {
                calls.set(calls.get() + 1);
                DeliveryDisposition::Accepted { status: 200 }
            }),
            Err(LedgerRefusal::IdentityRequestMismatch)
        );
        assert_eq!(calls.get(), 0);
    }

    #[test]
    fn uncertain_knowledge_is_sticky_and_never_auto_retried() {
        let mut ledger = HostDeliveryLedger::new(2).unwrap();
        let calls = Cell::new(0);
        let first = ledger
            .reconcile(identity(1), &request(1, b"uncertain"), |_| {
                calls.set(calls.get() + 1);
                DeliveryDisposition::Uncertain {
                    reason: AdapterFailure::Transport,
                }
            })
            .unwrap();
        let replay = ledger
            .reconcile(identity(1), &request(1, b"uncertain"), |_| {
                calls.set(calls.get() + 1);
                DeliveryDisposition::Accepted { status: 200 }
            })
            .unwrap();

        assert!(first.was_dispatched());
        assert!(!replay.was_dispatched());
        assert_eq!(calls.get(), 1);
        assert_eq!(
            replay.record().disposition(),
            &DeliveryDisposition::Uncertain {
                reason: AdapterFailure::Transport
            }
        );
    }

    #[test]
    fn unwinding_dispatch_leaves_a_sticky_provisional_uncertainty() {
        let mut ledger = HostDeliveryLedger::new(2).unwrap();
        let calls = Cell::new(0);
        let panic = catch_unwind(AssertUnwindSafe(|| {
            let _ = ledger.reconcile(identity(1), &request(1, b"started"), |_| {
                calls.set(calls.get() + 1);
                panic!("adapter started then unwound")
            });
        }));
        assert!(panic.is_err());

        let replay = ledger
            .reconcile(identity(1), &request(1, b"started"), |_| {
                calls.set(calls.get() + 1);
                DeliveryDisposition::Accepted { status: 200 }
            })
            .unwrap();
        assert!(!replay.was_dispatched());
        assert_eq!(calls.get(), 1);
        assert_eq!(
            replay.record().disposition(),
            &DeliveryDisposition::Uncertain {
                reason: AdapterFailure::Transport
            }
        );
    }

    #[test]
    fn capacity_is_reserved_before_any_new_dispatch() {
        let mut ledger = HostDeliveryLedger::new(1).unwrap();
        ledger
            .reconcile(identity(1), &request(1, b"first"), |_| {
                DeliveryDisposition::Accepted { status: 200 }
            })
            .unwrap();
        let calls = Cell::new(0);
        assert_eq!(
            ledger.reconcile(identity(2), &request(2, b"second"), |_| {
                calls.set(calls.get() + 1);
                DeliveryDisposition::Accepted { status: 200 }
            }),
            Err(LedgerRefusal::CapacityExceeded)
        );
        assert_eq!(calls.get(), 0);
        assert_eq!(
            HostDeliveryLedger::new(0),
            Err(LedgerRefusal::InvalidCapacity)
        );
        assert_eq!(
            HostDeliveryLedger::new(MAX_LEDGER_ENTRIES + 1),
            Err(LedgerRefusal::InvalidCapacity)
        );
    }

    #[test]
    fn terminal_records_have_stable_commitment_state_without_raw_identities() {
        let mut left = HostDeliveryLedger::new(3).unwrap();
        let mut right = HostDeliveryLedger::new(3).unwrap();
        let cases = [
            (
                identity(3),
                request(3, b"third"),
                DeliveryDisposition::Uncertain {
                    reason: AdapterFailure::Tls,
                },
            ),
            (
                identity(1),
                request(1, b"first"),
                DeliveryDisposition::Accepted { status: 201 },
            ),
            (
                identity(2),
                request(2, b"second"),
                DeliveryDisposition::Rejected { status: 422 },
            ),
        ];
        for (identity, request, disposition) in cases.iter().cloned() {
            left.reconcile(identity, &request, |_| disposition).unwrap();
        }
        for (identity, request, disposition) in cases.into_iter().rev() {
            right
                .reconcile(identity, &request, |_| disposition)
                .unwrap();
        }
        assert_eq!(left.render(), right.render());
        let state = left.render();
        assert!(state.contains(LEDGER_STATE_DOMAIN));
        assert!(state.contains("identity_digest"));
        assert!(!state.contains("deployment-1"));
        assert!(!state.contains("idempotency-1"));
        assert!(!state.contains("first"));
    }

    #[test]
    fn malformed_identity_is_refused_before_ledger_allocation_or_dispatch() {
        assert_eq!(
            DeliveryIdentity::new("deployment", "invocation\n", "idempotency"),
            Err(LedgerRefusal::InvalidIdentity)
        );
    }
}
