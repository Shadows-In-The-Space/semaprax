//! Capability-gated outbound host adapters for operational exports, webhooks,
//! and provider-neutral email.
//!
//! The policy boundary is deliberately transport-injected: it reads no
//! environment variables and creates no threads or timers. A host supplies an
//! [`OutboundAdapter`], an exact deployment policy, and a single-use
//! [`OutboundCapability`]. The boundary validates and signs the complete request
//! before invoking the adapter once. [`NativeHttpsAdapter`] is the explicit
//! physical implementation on native targets; fixture adapters stay IO-free.

use std::collections::BTreeSet;
use std::fmt;

use hmac::{Hmac, KeyInit, Mac};
use sha2::{Digest as _, Sha256};
use zeroize::Zeroize;

mod collector;
mod email;
mod http;
mod ledger;
mod metrics;
mod protected_names;
mod spans;
mod trace_context;
mod trace_http;
mod tracing;
mod webhook;

pub use collector::{CollectorRefusal, TelemetryCollectorCapability, TelemetryCollectorTarget};
pub use email::{
    deliver_email, prepare_email_delivery, verify_email_envelope, EmailAttachment,
    EmailDeliveryReceipt, EmailDeliverySession, EmailEnvelopeMismatch, EmailLedgerRefusal,
    EmailRequest, PreparedEmailDelivery, MAX_EMAIL_ATTACHMENTS, MAX_EMAIL_ATTACHMENT_BYTES,
    MAX_EMAIL_ATTACHMENT_NAME_BYTES, MAX_EMAIL_BODY_BYTES, MAX_EMAIL_RECIPIENTS,
    MAX_EMAIL_SUBJECT_BYTES,
};
pub use http::{
    deliver_http, prepare_http_delivery, HttpDeliveryReceipt, HttpDeliverySession, HttpHeader,
    HttpLedgerRefusal, HttpRequest, PreparedHttpDelivery,
};
pub use ledger::{
    CheckpointCommit, DeliveryIdentity, DurableLedgerOutcome, DurableLedgerRefusal,
    HostDeliveryLedger, LedgerCheckpoint, LedgerCheckpointRefusal, LedgerCheckpointStore,
    LedgerOutcome, LedgerRecord, LedgerRefusal, LedgerRestoreCapability, LedgerRestoreRefusal,
    MAX_LEDGER_CHECKPOINT_BYTES, MAX_LEDGER_ENTRIES,
};
pub use metrics::{
    prepare_metric_export, verify_metric_export, MetricExport, MetricExportSession, MetricKind,
    MetricWireMismatch, PreparedMetricExport,
};
pub use spans::{
    prepare_span_export, verify_span_export, PreparedSpanExport, SpanExport, SpanExportSession,
    SpanStatus, SpanWireMismatch,
};
pub use trace_context::{
    TraceContext, TraceContextError, TraceEntropyCapability, TraceState, TraceStateError,
    MAX_TRACESTATE_BYTES, MAX_TRACESTATE_MEMBERS, MAX_TRACESTATE_MEMBER_BYTES,
};
pub use trace_http::{deliver_traced_http, prepare_traced_http_delivery, TracedHttpRequest};
pub use tracing::{
    prepare_export_event, DurableExportEventOutcome, DurableExportEventRefusal,
    ExportEventLedgerRefusal, ExportEventReceipt, ExportEventSession, ExportSessionCheckpoint,
    ExportSessionCheckpointRefusal, ExportSessionCheckpointStore, ExportSessionRestoreCapability,
    ExportSessionRestoreRefusal, PreparedExportEvent, MAX_EXPORT_SESSION_CHECKPOINT_BYTES,
};
pub use webhook::{
    prepare_webhook_delivery, PreparedWebhookDelivery, WebhookDeliveryReceipt,
    WebhookDeliverySession, WebhookLedgerRefusal,
};

type HmacSha256 = Hmac<Sha256>;

const WEBHOOK_MAC_DOMAIN: &[u8] = b"semaprax.outbound.webhook-signature.v2\0";
const DIGEST_DOMAIN_V1: &[u8] = b"semaprax.outbound.request.v1\0";
const DIGEST_DOMAIN_V2: &[u8] = b"semaprax.outbound.request.v2\0";

pub const MAX_ENDPOINT_BYTES: usize = 2_048;
pub const MAX_REQUEST_BODY_BYTES: usize = 65_536;
pub const MAX_RESPONSE_BODY_BYTES: usize = 65_536;
pub const MAX_HEADERS: usize = 8;
pub const MAX_HEADER_VALUE_BYTES: usize = 512;
pub const MAX_EXPORT_FIELDS: usize = 64;
pub const MAX_EXPORT_LABELS: usize = 32;
pub const MAX_EXPORT_VALUE_BYTES: usize = 4_096;
pub const MAX_DEADLINE_MS: u64 = 120_000;
pub const MAX_EVIDENCE_BYTES: usize = 4_096;

/// Closed validation and admission failures. Every variant precedes dispatch.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Refusal {
    InvalidPolicy,
    InvalidEndpoint,
    AuthorityDenied,
    InvalidDeadline,
    RequestTooLarge,
    InvalidIdentity,
    InvalidContentType,
    InvalidHeader,
    CardinalityExceeded,
    SecretUnavailable,
    ProtectedValue,
    InvalidEmail,
}

/// Closed request methods supported by the bounded HTTPS adapter.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HttpMethod {
    Get,
    Post,
    Put,
    Patch,
    Delete,
}

impl HttpMethod {
    fn as_str(self) -> &'static str {
        match self {
            Self::Get => "GET",
            Self::Post => "POST",
            Self::Put => "PUT",
            Self::Patch => "PATCH",
            Self::Delete => "DELETE",
        }
    }
}

/// Exact deployment-owned limits and destinations for one outbound effect.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OutboundPolicy {
    policy_id: String,
    allowed_origins: BTreeSet<String>,
    max_request_bytes: usize,
    max_response_bytes: usize,
    max_deadline_ms: u64,
    max_export_fields: usize,
    max_export_labels: usize,
}

impl OutboundPolicy {
    pub fn new(
        policy_id: impl Into<String>,
        allowed_origins: impl IntoIterator<Item = String>,
        max_request_bytes: usize,
        max_response_bytes: usize,
        max_deadline_ms: u64,
        max_export_fields: usize,
        max_export_labels: usize,
    ) -> Result<Self, Refusal> {
        let policy_id = policy_id.into();
        if !valid_identity(&policy_id)
            || max_request_bytes == 0
            || max_request_bytes > MAX_REQUEST_BODY_BYTES
            || max_response_bytes == 0
            || max_response_bytes > MAX_RESPONSE_BODY_BYTES
            || max_deadline_ms == 0
            || max_deadline_ms > MAX_DEADLINE_MS
            || max_export_fields == 0
            || max_export_fields > MAX_EXPORT_FIELDS
            || max_export_labels == 0
            || max_export_labels > MAX_EXPORT_LABELS
        {
            return Err(Refusal::InvalidPolicy);
        }
        let mut origins = BTreeSet::new();
        for origin in allowed_origins {
            if canonical_origin(&origin).as_deref() != Some(origin.as_str())
                || !origins.insert(origin)
                || origins.len() > 8
            {
                return Err(Refusal::InvalidPolicy);
            }
        }
        if origins.is_empty() {
            return Err(Refusal::InvalidPolicy);
        }
        Ok(Self {
            policy_id,
            allowed_origins: origins,
            max_request_bytes,
            max_response_bytes,
            max_deadline_ms,
            max_export_fields,
            max_export_labels,
        })
    }

    pub fn policy_id(&self) -> &str {
        &self.policy_id
    }
}

/// Move-only authority for exactly one attempted outbound operation.
///
/// Consuming this value does not prove dispatch or delivery. It only prevents
/// this API from accidentally reusing one grant for an automatic retry. This
/// is a trusted Rust-host boundary, not an unforgeable token against arbitrary
/// Rust code: an embedder that calls
/// [`OutboundCapability::grant_for_trusted_host`] is asserting
/// that deployment policy already authorized the operation. SEMAPRAX source
/// cannot construct this Rust value.
pub struct OutboundCapability {
    deployment_binding: String,
    invocation_id: String,
    policy: OutboundPolicy,
}

impl fmt::Debug for OutboundCapability {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OutboundCapability")
            .field("deployment_binding", &"[REDACTED]")
            .field("invocation_id", &"[REDACTED]")
            .field("policy_id", &self.policy.policy_id)
            .finish()
    }
}

impl OutboundCapability {
    /// Mint one grant from trusted host policy. Untrusted request or source
    /// data must never select this constructor or its `policy` argument.
    pub fn grant_for_trusted_host(
        deployment_binding: impl Into<String>,
        invocation_id: impl Into<String>,
        policy: OutboundPolicy,
    ) -> Result<Self, Refusal> {
        let deployment_binding = deployment_binding.into();
        let invocation_id = invocation_id.into();
        if !valid_identity(&deployment_binding) || !valid_identity(&invocation_id) {
            return Err(Refusal::InvalidIdentity);
        }
        Ok(Self {
            deployment_binding,
            invocation_id,
            policy,
        })
    }
}

/// Signing key bytes that are neither clonable nor printable. The owned array
/// in this value is zeroized on drop; this does not claim erasure of caller,
/// allocator, transport, process-dump, or operating-system copies. Source
/// values and evidence cannot construct or recover these bytes through this API.
pub struct WebhookSigningSecret([u8; 32]);

impl WebhookSigningSecret {
    /// Import key bytes selected by a trusted Rust host. Request/source data
    /// must not be treated as a signing-key source.
    pub fn from_trusted_host_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

impl fmt::Debug for WebhookSigningSecret {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("WebhookSigningSecret([REDACTED])")
    }
}

impl Drop for WebhookSigningSecret {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// Caller-selected webhook data. Header construction remains inside the
/// boundary so untrusted values cannot inject or replace credentials.
#[derive(Clone, Eq, PartialEq)]
pub struct WebhookRequest {
    pub endpoint: String,
    pub delivery_id: String,
    pub idempotency_key: String,
    pub content_type: String,
    pub body: Vec<u8>,
    pub deadline_ms: u64,
}

impl fmt::Debug for WebhookRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WebhookRequest")
            .field("endpoint_origin", &canonical_origin(&self.endpoint))
            .field("delivery_id", &"[REDACTED]")
            .field("idempotency_key", &"[REDACTED]")
            .field("content_type", &self.content_type)
            .field("body_bytes", &self.body.len())
            .field("deadline_ms", &self.deadline_ms)
            .finish()
    }
}

/// One field admitted to an operational export. Protected data can only enter
/// as a visible marker and optional one-way commitment, never as plaintext.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ExportFieldValue {
    Public(String),
    Redacted { commitment: Option<String> },
}

/// Explicit protected export input. It has no text conversion, clone, or
/// printable representation; callers can only turn it into a redacted field.
pub struct ProtectedExportValue(Vec<u8>);

impl ProtectedExportValue {
    pub fn from_host_bytes(bytes: Vec<u8>) -> Result<Self, Refusal> {
        if bytes.len() > MAX_EXPORT_VALUE_BYTES {
            return Err(Refusal::RequestTooLarge);
        }
        Ok(Self(bytes))
    }

    pub fn into_redacted(mut self, commit: bool) -> ExportFieldValue {
        let commitment = commit.then(|| sha256(&self.0));
        self.0.zeroize();
        ExportFieldValue::Redacted { commitment }
    }
}

impl fmt::Debug for ProtectedExportValue {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ProtectedExportValue([REDACTED])")
    }
}

impl Drop for ProtectedExportValue {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExportField {
    pub name: String,
    pub value: ExportFieldValue,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExportEvent {
    pub stable_event_id: String,
    pub labels: Vec<(String, String)>,
    pub fields: Vec<ExportField>,
}

impl ExportEvent {
    /// Canonical, bounded JSON payload. Map-like inputs are sorted and duplicate
    /// names are refused, preventing order-dependent cardinality accounting.
    fn encode(&self, policy: &OutboundPolicy) -> Result<Vec<u8>, Refusal> {
        if !valid_identity(&self.stable_event_id) {
            return Err(Refusal::InvalidIdentity);
        }
        if self.fields.len() > policy.max_export_fields
            || self.labels.len() > policy.max_export_labels
        {
            return Err(Refusal::CardinalityExceeded);
        }
        if self
            .labels
            .iter()
            .any(|(name, value)| !valid_name(name) || contains_control(value))
            || self.fields.iter().any(|field| {
                !valid_name(&field.name)
                    || match &field.value {
                        ExportFieldValue::Public(value) => contains_control(value),
                        ExportFieldValue::Redacted { commitment } => commitment
                            .as_deref()
                            .is_some_and(|value| !valid_sha256(value)),
                    }
            })
        {
            return Err(Refusal::InvalidIdentity);
        }
        // The host boundary independently applies the same closed protected
        // name policy as `std.log.redact`. Callers cannot relabel an obvious
        // credential as a public field or metric label and bypass the typed
        // `ProtectedExportValue` route. Matching is exact after ASCII case and
        // '-'/'_' normalization; names such as `password_hash` remain ordinary
        // public names rather than being rejected by substring guesswork.
        if self
            .labels
            .iter()
            .any(|(name, _)| protected_names::is_protected(name))
            || self.fields.iter().any(|field| {
                protected_names::is_protected(&field.name)
                    && matches!(&field.value, ExportFieldValue::Public(_))
            })
        {
            return Err(Refusal::ProtectedValue);
        }
        if self
            .labels
            .iter()
            .any(|(_, value)| value.len() > MAX_EXPORT_VALUE_BYTES)
            || self.fields.iter().any(|field| {
                matches!(&field.value, ExportFieldValue::Public(value) if value.len() > MAX_EXPORT_VALUE_BYTES)
            })
        {
            return Err(Refusal::RequestTooLarge);
        }
        let aggregate = self
            .labels
            .iter()
            .try_fold(self.stable_event_id.len(), |total, (name, value)| {
                total.checked_add(name.len())?.checked_add(value.len())
            })
            .and_then(|total| {
                self.fields.iter().try_fold(total, |total, field| {
                    let value_len = match &field.value {
                        ExportFieldValue::Public(value) => value.len(),
                        ExportFieldValue::Redacted { commitment } => {
                            "[REDACTED]".len() + commitment.as_deref().map_or(0, str::len)
                        }
                    };
                    total.checked_add(field.name.len())?.checked_add(value_len)
                })
            })
            .ok_or(Refusal::RequestTooLarge)?;
        if aggregate > policy.max_request_bytes {
            return Err(Refusal::RequestTooLarge);
        }

        let mut labels = self.labels.iter().collect::<Vec<_>>();
        labels.sort();
        if labels.windows(2).any(|pair| pair[0].0 == pair[1].0) {
            return Err(Refusal::CardinalityExceeded);
        }
        let mut fields = self.fields.iter().collect::<Vec<_>>();
        fields.sort_by(|left, right| left.name.cmp(&right.name));
        if fields.windows(2).any(|pair| pair[0].name == pair[1].name) {
            return Err(Refusal::CardinalityExceeded);
        }
        let labels = labels
            .into_iter()
            .map(|(name, value)| serde_json::json!({"name": name, "value": value}))
            .collect::<Vec<_>>();
        let fields = fields
            .into_iter()
            .map(|field| match &field.value {
                ExportFieldValue::Public(value) => {
                    serde_json::json!({"name": &field.name, "value": value})
                }
                ExportFieldValue::Redacted { commitment } => serde_json::json!({
                    "name": &field.name,
                    "value": "[REDACTED]",
                    "commitment": commitment,
                }),
            })
            .collect::<Vec<_>>();
        let value = serde_json::json!({
            "schema": "semaprax.operational-export.v1",
            "event_id": self.stable_event_id,
            "labels": labels,
            "fields": fields,
        });
        let mut output = CappedJsonWriter::new(policy.max_request_bytes);
        serde_json::to_writer(&mut output, &value).map_err(|_| Refusal::RequestTooLarge)?;
        Ok(output.finish())
    }
}

struct CappedJsonWriter {
    bytes: Vec<u8>,
    limit: usize,
}

impl CappedJsonWriter {
    fn new(limit: usize) -> Self {
        Self {
            bytes: Vec::with_capacity(limit),
            limit,
        }
    }

    fn finish(self) -> Vec<u8> {
        self.bytes
    }
}

impl std::io::Write for CappedJsonWriter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if bytes.len() > self.limit.saturating_sub(self.bytes.len()) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::StorageFull,
                "operational export exceeds its admitted byte budget",
            ));
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Complete, validated request passed to the injected host transport.
#[derive(Clone, Eq, PartialEq)]
pub struct PreparedRequest {
    method: HttpMethod,
    endpoint: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
    deadline_ms: u64,
    max_redirects: usize,
    max_response_bytes: usize,
}

impl fmt::Debug for PreparedRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let header_names = self
            .headers
            .iter()
            .map(|(name, _)| name.as_str())
            .collect::<Vec<_>>();
        formatter
            .debug_struct("PreparedRequest")
            .field("method", &self.method)
            .field("endpoint_origin", &canonical_origin(&self.endpoint))
            .field("header_names", &header_names)
            .field("body_bytes", &self.body.len())
            .field("deadline_ms", &self.deadline_ms)
            .field("max_redirects", &self.max_redirects)
            .field("max_response_bytes", &self.max_response_bytes)
            .finish()
    }
}

impl PreparedRequest {
    pub fn method(&self) -> HttpMethod {
        self.method
    }

    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }

    pub fn headers(&self) -> &[(String, String)] {
        &self.headers
    }

    pub fn body(&self) -> &[u8] {
        &self.body
    }

    pub fn deadline_ms(&self) -> u64 {
        self.deadline_ms
    }

    pub fn max_redirects(&self) -> usize {
        self.max_redirects
    }

    pub fn max_response_bytes(&self) -> usize {
        self.max_response_bytes
    }
}

/// Closed adapter failures. Provider or platform error strings never enter
/// evidence and therefore cannot smuggle secrets through diagnostics.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AdapterFailure {
    PolicyRejected,
    NameResolution,
    Tls,
    Transport,
    Protocol,
    Cancelled,
}

impl AdapterFailure {
    fn as_str(self) -> &'static str {
        match self {
            Self::PolicyRejected => "policy_rejected",
            Self::NameResolution => "name_resolution",
            Self::Tls => "tls",
            Self::Transport => "transport",
            Self::Protocol => "protocol",
            Self::Cancelled => "cancelled",
        }
    }
}

/// A transport observation. Once `send` is entered, failure without an exact
/// response is uncertain because the remote side may already have acted.
#[derive(Clone, Eq, PartialEq)]
pub enum AdapterObservation {
    NotDispatched { reason: AdapterFailure },
    Response { status: u16, body: Vec<u8> },
    FailedAfterStart { reason: AdapterFailure },
    DeadlineAfterStart,
    ResponseTooLargeAfterStart,
}

impl fmt::Debug for AdapterObservation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotDispatched { reason } => formatter
                .debug_struct("NotDispatched")
                .field("reason", reason)
                .finish(),
            Self::Response { status, body } => formatter
                .debug_struct("Response")
                .field("status", status)
                .field("body_bytes", &body.len())
                .finish(),
            Self::FailedAfterStart { reason } => formatter
                .debug_struct("FailedAfterStart")
                .field("reason", reason)
                .finish(),
            Self::DeadlineAfterStart => formatter.write_str("DeadlineAfterStart"),
            Self::ResponseTooLargeAfterStart => formatter.write_str("ResponseTooLargeAfterStart"),
        }
    }
}

/// Trusted Rust-host physical-effect seam.
///
/// Custom implementations are assumed to issue at most the one prepared
/// request and to avoid redirects and retries; the type system cannot enforce
/// those properties against arbitrary Rust code. [`NativeHttpsAdapter`] is the
/// repository implementation that enforces them. Fixture implementations must
/// remain IO-free. The capability has already been consumed when this is called.
pub trait OutboundAdapter {
    fn send(&mut self, request: &PreparedRequest) -> AdapterObservation;
}

/// Native HTTPS implementation of the boundary. It has no ambient proxy,
/// redirect, or retry behavior and accepts TLS roots only from its host.
#[cfg(not(any(target_arch = "wasm32", target_arch = "wasm64")))]
pub struct NativeHttpsAdapter {
    client: reqwest::blocking::Client,
}

#[cfg(not(any(target_arch = "wasm32", target_arch = "wasm64")))]
impl NativeHttpsAdapter {
    pub fn with_tls_config(tls: rustls::ClientConfig) -> Result<Self, Refusal> {
        let client = reqwest::blocking::Client::builder()
            .no_proxy()
            .tls_backend_preconfigured(tls)
            .https_only(true)
            .redirect(reqwest::redirect::Policy::none())
            .retry(reqwest::retry::never())
            .pool_max_idle_per_host(8)
            .build()
            .map_err(|_| Refusal::InvalidPolicy)?;
        Ok(Self { client })
    }
}

#[cfg(not(any(target_arch = "wasm32", target_arch = "wasm64")))]
impl OutboundAdapter for NativeHttpsAdapter {
    fn send(&mut self, request: &PreparedRequest) -> AdapterObservation {
        use std::io::Read as _;
        use std::time::Duration;

        if request.max_redirects != 0
            || canonical_origin(&request.endpoint).is_none()
            || request.body.len() > MAX_REQUEST_BODY_BYTES
            || request.deadline_ms == 0
            || request.deadline_ms > MAX_DEADLINE_MS
            || request.max_response_bytes == 0
            || request.max_response_bytes > MAX_RESPONSE_BODY_BYTES
            || request.headers.len() > MAX_HEADERS
            || request.headers.iter().any(|(name, value)| {
                !valid_header_name(name)
                    || value.len() > MAX_HEADER_VALUE_BYTES
                    || contains_control(value)
            })
        {
            return AdapterObservation::NotDispatched {
                reason: AdapterFailure::PolicyRejected,
            };
        }
        let mut builder = self
            .client
            .request(
                match request.method {
                    HttpMethod::Get => reqwest::Method::GET,
                    HttpMethod::Post => reqwest::Method::POST,
                    HttpMethod::Put => reqwest::Method::PUT,
                    HttpMethod::Patch => reqwest::Method::PATCH,
                    HttpMethod::Delete => reqwest::Method::DELETE,
                },
                &request.endpoint,
            )
            .timeout(Duration::from_millis(request.deadline_ms))
            .body(request.body.clone());
        for (name, value) in &request.headers {
            let Ok(name) = reqwest::header::HeaderName::from_bytes(name.as_bytes()) else {
                return AdapterObservation::NotDispatched {
                    reason: AdapterFailure::PolicyRejected,
                };
            };
            let Ok(value) = reqwest::header::HeaderValue::from_str(value) else {
                return AdapterObservation::NotDispatched {
                    reason: AdapterFailure::PolicyRejected,
                };
            };
            builder = builder.header(name, value);
        }
        let response = match builder.send() {
            Ok(response) => response,
            Err(error) if error.is_timeout() => return AdapterObservation::DeadlineAfterStart,
            Err(_) => {
                return AdapterObservation::FailedAfterStart {
                    reason: AdapterFailure::Transport,
                };
            }
        };
        let status = response.status().as_u16();
        if response
            .content_length()
            .is_some_and(|length| length > request.max_response_bytes as u64)
        {
            return AdapterObservation::ResponseTooLargeAfterStart;
        }
        let take = (request.max_response_bytes as u64).saturating_add(1);
        let mut body = Vec::new();
        if response.take(take).read_to_end(&mut body).is_err() {
            return AdapterObservation::FailedAfterStart {
                reason: AdapterFailure::Transport,
            };
        }
        if body.len() > request.max_response_bytes {
            AdapterObservation::ResponseTooLargeAfterStart
        } else {
            AdapterObservation::Response { status, body }
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DeliveryDisposition {
    NotDispatched { reason: AdapterFailure },
    Accepted { status: u16 },
    Rejected { status: u16 },
    Uncertain { reason: AdapterFailure },
    DeadlineUncertain,
    ResponseTooLargeUncertain,
}

/// Non-authoritative record sufficient to replay the adapter boundary's
/// deterministic decision against exact deployment/request bindings.
#[derive(Clone, Eq, PartialEq)]
pub struct DeliveryEvidence {
    schema: &'static str,
    deployment_binding: String,
    invocation_id: String,
    policy_id: String,
    endpoint_origin: String,
    request_digest: String,
    delivery_id: String,
    idempotency_key: String,
    disposition: DeliveryDisposition,
}

impl fmt::Debug for DeliveryEvidence {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DeliveryEvidence")
            .field("schema", &self.schema)
            .field("bindings", &"[REDACTED]")
            .field("policy_id", &self.policy_id)
            .field("endpoint_origin", &self.endpoint_origin)
            .field("request_digest", &self.request_digest)
            .field("delivery_identity", &"[REDACTED]")
            .field("disposition", &self.disposition)
            .finish()
    }
}

impl DeliveryEvidence {
    pub fn disposition(&self) -> &DeliveryDisposition {
        &self.disposition
    }

    pub fn render(&self) -> String {
        serde_json::to_string(&serde_json::json!({
            "schema": self.schema,
            "deployment_binding": self.deployment_binding,
            "invocation_id": self.invocation_id,
            "policy_id": self.policy_id,
            "endpoint_origin": self.endpoint_origin,
            "request_digest": self.request_digest,
            "delivery_id": self.delivery_id,
            "idempotency_key": self.idempotency_key,
            "disposition": render_disposition(&self.disposition),
        }))
        .expect("bounded evidence values always encode")
    }

    pub fn replay(
        &self,
        expected_deployment: &str,
        expected_invocation: &str,
        expected_policy: &str,
        expected_disposition: &DeliveryDisposition,
        expected_request: &PreparedRequest,
    ) -> Result<(), EvidenceMismatch> {
        if self.schema != "semaprax.outbound-delivery-evidence.v1" {
            return Err(EvidenceMismatch::Schema);
        }
        if self.deployment_binding != expected_deployment
            || self.invocation_id != expected_invocation
        {
            return Err(EvidenceMismatch::Binding);
        }
        if self.policy_id != expected_policy {
            return Err(EvidenceMismatch::Policy);
        }
        if self.request_digest != request_digest(expected_request) {
            return Err(EvidenceMismatch::Request);
        }
        let expected_origin =
            canonical_origin(&expected_request.endpoint).ok_or(EvidenceMismatch::Request)?;
        let expected_delivery_id = expected_request
            .headers
            .iter()
            .find(|(name, _)| name == "x-semaprax-delivery-id" || name == "x-semaprax-event-id")
            .map(|(_, value)| value.as_str())
            .ok_or(EvidenceMismatch::Request)?;
        let expected_idempotency = expected_request
            .headers
            .iter()
            .find(|(name, _)| name == "idempotency-key")
            .map(|(_, value)| value.as_str())
            .ok_or(EvidenceMismatch::Request)?;
        if self.endpoint_origin != expected_origin
            || self.delivery_id != expected_delivery_id
            || self.idempotency_key != expected_idempotency
            || &self.disposition != expected_disposition
        {
            return Err(EvidenceMismatch::Settlement);
        }
        Ok(())
    }

    /// Decode canonical evidence and replay its exact bindings. Parsing is
    /// bounded and the byte-for-byte canonical rendering is required.
    pub fn decode_and_replay(
        bytes: &[u8],
        expected_deployment: &str,
        expected_invocation: &str,
        expected_policy: &str,
        expected_disposition: &DeliveryDisposition,
        expected_request: &PreparedRequest,
    ) -> Result<Self, EvidenceMismatch> {
        if bytes.is_empty() || bytes.len() > MAX_EVIDENCE_BYTES {
            return Err(EvidenceMismatch::Malformed);
        }
        let value: serde_json::Value =
            serde_json::from_slice(bytes).map_err(|_| EvidenceMismatch::Malformed)?;
        let object = value.as_object().ok_or(EvidenceMismatch::Malformed)?;
        const KEYS: [&str; 9] = [
            "schema",
            "deployment_binding",
            "invocation_id",
            "policy_id",
            "endpoint_origin",
            "request_digest",
            "delivery_id",
            "idempotency_key",
            "disposition",
        ];
        if object.len() != KEYS.len() || !KEYS.iter().all(|key| object.contains_key(*key)) {
            return Err(EvidenceMismatch::Malformed);
        }
        let text = |key: &str| {
            object
                .get(key)
                .and_then(serde_json::Value::as_str)
                .map(str::to_owned)
                .ok_or(EvidenceMismatch::Malformed)
        };
        if text("schema")? != "semaprax.outbound-delivery-evidence.v1" {
            return Err(EvidenceMismatch::Schema);
        }
        let disposition = decode_disposition(
            object
                .get("disposition")
                .ok_or(EvidenceMismatch::Malformed)?,
        )?;
        let evidence = Self {
            schema: "semaprax.outbound-delivery-evidence.v1",
            deployment_binding: text("deployment_binding")?,
            invocation_id: text("invocation_id")?,
            policy_id: text("policy_id")?,
            endpoint_origin: text("endpoint_origin")?,
            request_digest: text("request_digest")?,
            delivery_id: text("delivery_id")?,
            idempotency_key: text("idempotency_key")?,
            disposition,
        };
        if !valid_identity(&evidence.deployment_binding)
            || !valid_identity(&evidence.invocation_id)
            || !valid_identity(&evidence.policy_id)
            || !valid_identity(&evidence.delivery_id)
            || !valid_identity(&evidence.idempotency_key)
            || !valid_sha256(&evidence.request_digest)
            || canonical_origin(&evidence.endpoint_origin).as_deref()
                != Some(evidence.endpoint_origin.as_str())
        {
            return Err(EvidenceMismatch::Malformed);
        }
        if evidence.render().as_bytes() != bytes {
            return Err(EvidenceMismatch::NonCanonical);
        }
        evidence.replay(
            expected_deployment,
            expected_invocation,
            expected_policy,
            expected_disposition,
            expected_request,
        )?;
        Ok(evidence)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EvidenceMismatch {
    Malformed,
    NonCanonical,
    Schema,
    Binding,
    Policy,
    Request,
    Settlement,
}

#[derive(Clone, Eq, PartialEq)]
pub struct DeliveryResult {
    pub response_body: Option<Vec<u8>>,
    pub evidence: DeliveryEvidence,
}

impl fmt::Debug for DeliveryResult {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DeliveryResult")
            .field(
                "response_body_bytes",
                &self.response_body.as_ref().map(Vec::len),
            )
            .field("evidence", &self.evidence)
            .finish()
    }
}

/// Validate, sign, and attempt exactly one webhook delivery.
pub fn deliver_webhook(
    capability: OutboundCapability,
    secret: WebhookSigningSecret,
    request: WebhookRequest,
    adapter: &mut impl OutboundAdapter,
) -> Result<DeliveryResult, Refusal> {
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
    let prepared = PreparedRequest {
        method: HttpMethod::Post,
        endpoint: request.endpoint.clone(),
        headers: vec![
            ("content-type".into(), request.content_type.clone()),
            ("idempotency-key".into(), request.idempotency_key.clone()),
            ("x-semaprax-delivery-id".into(), request.delivery_id.clone()),
            ("x-semaprax-signature-v2".into(), signature),
        ],
        body: request.body,
        deadline_ms: request.deadline_ms,
        max_redirects: 0,
        max_response_bytes: capability.policy.max_response_bytes,
    };
    let observation = adapter.send(&prepared);
    Ok(settle(
        capability,
        origin,
        request.delivery_id,
        request.idempotency_key,
        prepared,
        observation,
    ))
}

/// Export one structured event through the same capability-gated boundary.
/// The endpoint receives no user-selected headers and redirects/retries remain
/// forbidden by the injected adapter contract.
pub fn export_event(
    capability: OutboundCapability,
    endpoint: String,
    deadline_ms: u64,
    event: ExportEvent,
    adapter: &mut impl OutboundAdapter,
) -> Result<DeliveryResult, Refusal> {
    let origin = validate_common(&capability.policy, &endpoint, deadline_ms)?;
    let body = event.encode(&capability.policy)?;
    if body.len() > capability.policy.max_request_bytes {
        return Err(Refusal::RequestTooLarge);
    }
    let prepared = PreparedRequest {
        method: HttpMethod::Post,
        endpoint,
        headers: vec![
            ("content-type".into(), "application/json".into()),
            ("idempotency-key".into(), "export-no-retry".into()),
            ("x-semaprax-event-id".into(), event.stable_event_id.clone()),
        ],
        body,
        deadline_ms,
        max_redirects: 0,
        max_response_bytes: capability.policy.max_response_bytes,
    };
    let observation = adapter.send(&prepared);
    Ok(settle(
        capability,
        origin,
        event.stable_event_id,
        "export-no-retry".into(),
        prepared,
        observation,
    ))
}

/// Keeps the primary application result and exporter result in separate slots.
/// Export failure therefore cannot replace a primary failure or success.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ObservedPrimary<T> {
    pub primary: T,
    pub export: Result<DeliveryResult, Refusal>,
}

pub fn export_after_primary<T>(
    primary: T,
    capability: OutboundCapability,
    endpoint: String,
    deadline_ms: u64,
    event: ExportEvent,
    adapter: &mut impl OutboundAdapter,
) -> ObservedPrimary<T> {
    ObservedPrimary {
        primary,
        export: export_event(capability, endpoint, deadline_ms, event, adapter),
    }
}

fn validate_webhook(policy: &OutboundPolicy, request: &WebhookRequest) -> Result<(), Refusal> {
    validate_common(policy, &request.endpoint, request.deadline_ms)?;
    if request.body.len() > policy.max_request_bytes {
        return Err(Refusal::RequestTooLarge);
    }
    if !valid_identity(&request.delivery_id) || !valid_identity(&request.idempotency_key) {
        return Err(Refusal::InvalidIdentity);
    }
    if request.content_type.is_empty()
        || request.content_type.len() > 128
        || contains_control(&request.content_type)
        || request.content_type.contains(' ')
    {
        return Err(Refusal::InvalidContentType);
    }
    Ok(())
}

fn validate_common(
    policy: &OutboundPolicy,
    endpoint: &str,
    deadline_ms: u64,
) -> Result<String, Refusal> {
    let origin = canonical_origin(endpoint).ok_or(Refusal::InvalidEndpoint)?;
    if !policy.allowed_origins.contains(&origin) {
        return Err(Refusal::AuthorityDenied);
    }
    if deadline_ms == 0 || deadline_ms > policy.max_deadline_ms {
        return Err(Refusal::InvalidDeadline);
    }
    Ok(origin)
}

fn sign_webhook(
    secret: &WebhookSigningSecret,
    deployment_binding: &str,
    origin: &str,
    target: &str,
    delivery_id: &str,
    idempotency_key: &str,
    content_type: &str,
    body: &[u8],
) -> Result<String, Refusal> {
    let mut mac = HmacSha256::new_from_slice(&secret.0).map_err(|_| Refusal::SecretUnavailable)?;
    mac.update(WEBHOOK_MAC_DOMAIN);
    mac_part(&mut mac, b"POST");
    mac_part(&mut mac, deployment_binding.as_bytes());
    mac_part(&mut mac, origin.as_bytes());
    mac_part(&mut mac, target.as_bytes());
    mac_part(&mut mac, delivery_id.as_bytes());
    mac_part(&mut mac, idempotency_key.as_bytes());
    mac_part(&mut mac, content_type.as_bytes());
    mac_part(&mut mac, body);
    Ok(format!(
        "hmac-sha256={:x}",
        crate::digest_hex::LowerHex(mac.finalize().into_bytes())
    ))
}

fn mac_part(mac: &mut HmacSha256, bytes: &[u8]) {
    mac.update(&(bytes.len() as u64).to_le_bytes());
    mac.update(bytes);
}

fn settle(
    capability: OutboundCapability,
    origin: String,
    delivery_id: String,
    idempotency_key: String,
    prepared: PreparedRequest,
    observation: AdapterObservation,
) -> DeliveryResult {
    let disposition = settlement_disposition(&prepared, &observation);
    let response_body = match observation {
        AdapterObservation::Response { status, body }
            if body.len() <= prepared.max_response_bytes && (200..300).contains(&status) =>
        {
            Some(body)
        }
        _ => None,
    };
    DeliveryResult {
        response_body,
        evidence: delivery_evidence(
            capability,
            origin,
            delivery_id,
            idempotency_key,
            prepared,
            disposition,
        ),
    }
}

/// Classify a completed adapter observation without retaining a response body.
/// Reconciliation modes that settle disposition-only use this before dropping
/// provider response bytes.
fn settlement_disposition(
    prepared: &PreparedRequest,
    observation: &AdapterObservation,
) -> DeliveryDisposition {
    match observation {
        AdapterObservation::NotDispatched { reason } => {
            DeliveryDisposition::NotDispatched { reason: *reason }
        }
        AdapterObservation::Response { body, .. } if body.len() > prepared.max_response_bytes => {
            DeliveryDisposition::ResponseTooLargeUncertain
        }
        AdapterObservation::Response { status, .. } if !(100..600).contains(status) => {
            DeliveryDisposition::Uncertain {
                reason: AdapterFailure::Protocol,
            }
        }
        AdapterObservation::Response { status, .. } if (200..300).contains(status) => {
            DeliveryDisposition::Accepted { status: *status }
        }
        AdapterObservation::Response { status, .. } => {
            DeliveryDisposition::Rejected { status: *status }
        }
        AdapterObservation::FailedAfterStart { reason } => {
            DeliveryDisposition::Uncertain { reason: *reason }
        }
        AdapterObservation::DeadlineAfterStart => DeliveryDisposition::DeadlineUncertain,
        AdapterObservation::ResponseTooLargeAfterStart => {
            DeliveryDisposition::ResponseTooLargeUncertain
        }
    }
}

fn delivery_evidence(
    capability: OutboundCapability,
    origin: String,
    delivery_id: String,
    idempotency_key: String,
    prepared: PreparedRequest,
    disposition: DeliveryDisposition,
) -> DeliveryEvidence {
    DeliveryEvidence {
        schema: "semaprax.outbound-delivery-evidence.v1",
        deployment_binding: capability.deployment_binding,
        invocation_id: capability.invocation_id,
        policy_id: capability.policy.policy_id,
        endpoint_origin: origin,
        request_digest: request_digest(&prepared),
        delivery_id,
        idempotency_key,
        disposition,
    }
}

fn request_digest(request: &PreparedRequest) -> String {
    let mut hash = Sha256::new();
    if request.method == HttpMethod::Post {
        // Preserve every existing email, webhook, and export commitment.
        hash.update(DIGEST_DOMAIN_V1);
    } else {
        hash.update(DIGEST_DOMAIN_V2);
        digest_part(&mut hash, request.method.as_str().as_bytes());
    }
    digest_part(&mut hash, request.endpoint.as_bytes());
    hash.update((request.headers.len() as u64).to_le_bytes());
    for (name, value) in &request.headers {
        digest_part(&mut hash, name.as_bytes());
        digest_part(&mut hash, value.as_bytes());
    }
    digest_part(&mut hash, &request.body);
    hash.update(request.deadline_ms.to_le_bytes());
    hash.update((request.max_redirects as u64).to_le_bytes());
    hash.update((request.max_response_bytes as u64).to_le_bytes());
    format!("sha256:{:x}", crate::digest_hex::LowerHex(hash.finalize()))
}

fn digest_part(hash: &mut Sha256, bytes: &[u8]) {
    hash.update((bytes.len() as u64).to_le_bytes());
    hash.update(bytes);
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
        DeliveryDisposition::DeadlineUncertain => {
            serde_json::json!({"kind": "uncertain", "reason": "deadline_after_start"})
        }
        DeliveryDisposition::ResponseTooLargeUncertain => serde_json::json!({
            "kind": "uncertain",
            "reason": "response_too_large_after_start"
        }),
    }
}

fn decode_disposition(value: &serde_json::Value) -> Result<DeliveryDisposition, EvidenceMismatch> {
    let object = value.as_object().ok_or(EvidenceMismatch::Malformed)?;
    let kind = object
        .get("kind")
        .and_then(serde_json::Value::as_str)
        .ok_or(EvidenceMismatch::Malformed)?;
    match kind {
        "accepted" | "rejected" => {
            if object.len() != 2 || !object.contains_key("status") {
                return Err(EvidenceMismatch::Malformed);
            }
            let status = object["status"]
                .as_u64()
                .and_then(|status| u16::try_from(status).ok())
                .filter(|status| (100..600).contains(status))
                .ok_or(EvidenceMismatch::Malformed)?;
            Ok(if kind == "accepted" {
                DeliveryDisposition::Accepted { status }
            } else {
                DeliveryDisposition::Rejected { status }
            })
        }
        "not_dispatched" | "uncertain" => {
            if object.len() != 2 || !object.contains_key("reason") {
                return Err(EvidenceMismatch::Malformed);
            }
            let reason = object["reason"]
                .as_str()
                .ok_or(EvidenceMismatch::Malformed)?;
            if kind == "uncertain" && reason == "deadline_after_start" {
                return Ok(DeliveryDisposition::DeadlineUncertain);
            }
            if kind == "uncertain" && reason == "response_too_large_after_start" {
                return Ok(DeliveryDisposition::ResponseTooLargeUncertain);
            }
            let reason = match reason {
                "policy_rejected" => AdapterFailure::PolicyRejected,
                "name_resolution" => AdapterFailure::NameResolution,
                "tls" => AdapterFailure::Tls,
                "transport" => AdapterFailure::Transport,
                "protocol" => AdapterFailure::Protocol,
                "cancelled" => AdapterFailure::Cancelled,
                _ => return Err(EvidenceMismatch::Malformed),
            };
            Ok(if kind == "not_dispatched" {
                DeliveryDisposition::NotDispatched { reason }
            } else {
                DeliveryDisposition::Uncertain { reason }
            })
        }
        _ => Err(EvidenceMismatch::Malformed),
    }
}

fn canonical_origin(endpoint: &str) -> Option<String> {
    canonical_endpoint_parts(endpoint).map(|(origin, _)| origin)
}

fn canonical_endpoint_parts(endpoint: &str) -> Option<(String, String)> {
    if endpoint.is_empty()
        || endpoint.len() > MAX_ENDPOINT_BYTES
        || !endpoint.is_ascii()
        || endpoint.bytes().any(|byte| byte <= 0x20 || byte == 0x7f)
        || endpoint.contains('#')
    {
        return None;
    }
    let remainder = endpoint.strip_prefix("https://")?;
    let authority_end = remainder
        .bytes()
        .position(|byte| matches!(byte, b'/' | b'?'))
        .unwrap_or(remainder.len());
    let authority = &remainder[..authority_end];
    if authority.is_empty() || authority.contains('@') {
        return None;
    }
    let (host, port) = if authority.starts_with('[') {
        let close = authority.find(']')?;
        let address = authority[1..close].parse::<std::net::Ipv6Addr>().ok()?;
        let host = format!("[{address}]");
        let suffix = &authority[close + 1..];
        let port = if suffix.is_empty() {
            None
        } else {
            Some(suffix.strip_prefix(':')?)
        };
        (host, port)
    } else if let Some((host, port)) = authority.rsplit_once(':') {
        if host.contains(':') {
            return None;
        }
        (host.to_owned(), Some(port))
    } else {
        (authority.to_owned(), None)
    };
    if host.is_empty()
        || (!host.starts_with('[')
            && host.split('.').any(|label| {
                label.is_empty()
                    || label.len() > 63
                    || !label
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
                    || !label.as_bytes()[0].is_ascii_alphanumeric()
                    || !label.as_bytes()[label.len() - 1].is_ascii_alphanumeric()
            }))
    {
        return None;
    }
    let port = match port {
        None | Some("443") => None,
        Some(value) => {
            if value.is_empty()
                || value.starts_with('0')
                || value
                    .parse::<u16>()
                    .ok()
                    .filter(|port| *port != 0)
                    .is_none()
            {
                return None;
            }
            Some(value)
        }
    };
    let host = host.to_ascii_lowercase();
    let origin = match port {
        Some(port) => format!("https://{host}:{port}"),
        None => format!("https://{host}"),
    };
    let raw_target = &remainder[authority_end..];
    let target = if raw_target.is_empty() {
        "/".to_owned()
    } else if raw_target.starts_with('?') {
        format!("/{raw_target}")
    } else {
        raw_target.to_owned()
    };
    if !canonical_request_target(&target) {
        return None;
    }
    Some((origin, target))
}

fn canonical_request_target(target: &str) -> bool {
    if !target.starts_with('/') || target.contains('\\') {
        return false;
    }
    let path = target.split_once('?').map_or(target, |(path, _)| path);
    if path
        .split('/')
        .any(|segment| segment == "." || segment == "..")
    {
        return false;
    }
    let bytes = target.as_bytes();
    let mut index = 0usize;
    while index < bytes.len() {
        let byte = bytes[index];
        if byte == b'%' {
            if index + 2 >= bytes.len()
                || !canonical_hex(bytes[index + 1])
                || !canonical_hex(bytes[index + 2])
                || (bytes[index + 1] == b'2' && matches!(bytes[index + 2], b'E' | b'e'))
            {
                return false;
            }
            index += 3;
            continue;
        }
        if !(byte.is_ascii_alphanumeric()
            || matches!(
                byte,
                b'/' | b'?'
                    | b':'
                    | b'@'
                    | b'-'
                    | b'.'
                    | b'_'
                    | b'~'
                    | b'!'
                    | b'$'
                    | b'&'
                    | b'\''
                    | b'('
                    | b')'
                    | b'*'
                    | b'+'
                    | b','
                    | b';'
                    | b'='
            ))
        {
            return false;
        }
        index += 1;
    }
    true
}

fn canonical_hex(byte: u8) -> bool {
    byte.is_ascii_digit() || (b'A'..=b'F').contains(&byte)
}

fn valid_identity(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'/' | b'-')
        })
}

fn valid_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

fn valid_header_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'!' | b'#'..=b'\'' | b'*' | b'+' | b'-' | b'.' | b'^'..=b'`' | b'|' | b'~')
        })
}

fn contains_control(value: &str) -> bool {
    value.bytes().any(|byte| byte < 0x20 || byte == 0x7f)
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 71
        && value.strip_prefix("sha256:").is_some_and(|hex| {
            hex.bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        })
}

fn sha256(bytes: &[u8]) -> String {
    let mut hash = Sha256::new();
    hash.update(bytes);
    format!("sha256:{:x}", crate::digest_hex::LowerHex(hash.finalize()))
}

#[cfg(test)]
mod tests;
