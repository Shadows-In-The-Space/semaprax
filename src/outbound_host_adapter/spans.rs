//! Typed trace-span exports over the same capability-gated host boundary.
//!
//! IDs are explicit inputs and are never synthesized from ambient randomness.
//! A host that creates IDs must do so through its separately authorized entropy
//! provider before constructing this value.

use std::fmt;

use super::*;

const SPAN_IDEMPOTENCY_DOMAIN: &[u8] = b"semaprax.outbound.span-export.idempotency.v1\0";
const MAX_SPAN_NAME_BYTES: usize = 128;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SpanStatus {
    Unset,
    Ok,
    Error,
}

/// One completed span. Duration is an elapsed value rather than a wall-clock
/// timestamp so the boundary neither reads a clock nor creates time authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SpanExport {
    pub trace_id: String,
    pub span_id: String,
    pub parent_span_id: Option<String>,
    pub name: String,
    pub duration_micros: u64,
    pub status: SpanStatus,
    pub attributes: Vec<ExportField>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SpanWireMismatch {
    Bound,
    Malformed,
    Schema,
    NonCanonical,
    PreparedRequest,
}

impl SpanExport {
    pub fn from_trace_context(
        context: &super::trace_context::TraceContext,
        name: String,
        duration_micros: u64,
        status: SpanStatus,
        attributes: Vec<ExportField>,
    ) -> Self {
        Self {
            trace_id: context.trace_id(),
            span_id: context.span_id(),
            parent_span_id: context.parent_span_id(),
            name,
            duration_micros,
            status,
            attributes,
        }
    }

    fn encode(&self, policy: &OutboundPolicy) -> Result<Vec<u8>, Refusal> {
        if !lower_hex_id(&self.trace_id, 32)
            || !lower_hex_id(&self.span_id, 16)
            || self
                .parent_span_id
                .as_deref()
                .is_some_and(|parent| !lower_hex_id(parent, 16) || parent == self.span_id)
            || self.name.is_empty()
            || self.name.len() > MAX_SPAN_NAME_BYTES
            || contains_control(&self.name)
        {
            return Err(Refusal::InvalidIdentity);
        }
        if self.attributes.len() > policy.max_export_fields {
            return Err(Refusal::CardinalityExceeded);
        }
        if self.attributes.iter().any(|field| {
            !valid_name(&field.name)
                || match &field.value {
                    ExportFieldValue::Public(value) => contains_control(value),
                    ExportFieldValue::Redacted { commitment } => commitment
                        .as_deref()
                        .is_some_and(|value| !valid_sha256(value)),
                }
        }) {
            return Err(Refusal::InvalidIdentity);
        }
        if self.attributes.iter().any(|field| {
            matches!(&field.value, ExportFieldValue::Public(value) if value.len() > MAX_EXPORT_VALUE_BYTES)
        }) {
            return Err(Refusal::RequestTooLarge);
        }
        if self.attributes.iter().any(|field| {
            super::protected_names::is_protected(&field.name)
                && matches!(&field.value, ExportFieldValue::Public(_))
        }) {
            return Err(Refusal::ProtectedValue);
        }
        let mut attributes = self.attributes.iter().collect::<Vec<_>>();
        attributes.sort_by(|left, right| left.name.cmp(&right.name));
        if attributes
            .windows(2)
            .any(|pair| pair[0].name == pair[1].name)
        {
            return Err(Refusal::CardinalityExceeded);
        }
        let aggregate = attributes
            .iter()
            .try_fold(
                self.trace_id.len()
                    + self.span_id.len()
                    + self.parent_span_id.as_deref().map_or(0, str::len)
                    + self.name.len(),
                |total, field| {
                    let value_len = match &field.value {
                        ExportFieldValue::Public(value) => value.len(),
                        ExportFieldValue::Redacted { commitment } => {
                            "[REDACTED]".len() + commitment.as_deref().map_or(0, str::len)
                        }
                    };
                    total.checked_add(field.name.len())?.checked_add(value_len)
                },
            )
            .ok_or(Refusal::RequestTooLarge)?;
        if aggregate > policy.max_request_bytes {
            return Err(Refusal::RequestTooLarge);
        }
        let attributes = attributes
            .into_iter()
            .map(|field| match &field.value {
                ExportFieldValue::Public(value) => {
                    serde_json::json!({"name": field.name, "value": value})
                }
                ExportFieldValue::Redacted { commitment } => serde_json::json!({
                    "name": field.name,
                    "value": "[REDACTED]",
                    "commitment": commitment,
                }),
            })
            .collect::<Vec<_>>();
        let status = match self.status {
            SpanStatus::Unset => "unset",
            SpanStatus::Ok => "ok",
            SpanStatus::Error => "error",
        };
        let value = serde_json::json!({
            "schema": "semaprax.operational-span.v1",
            "trace_id": &self.trace_id,
            "span_id": &self.span_id,
            "parent_span_id": &self.parent_span_id,
            "name": &self.name,
            "duration_micros": self.duration_micros,
            "status": status,
            "attributes": attributes,
        });
        let mut output = CappedJsonWriter::new(policy.max_request_bytes);
        serde_json::to_writer(&mut output, &value).map_err(|_| Refusal::RequestTooLarge)?;
        Ok(output.finish())
    }
}

fn lower_hex_id(value: &str, expected_len: usize) -> bool {
    value.len() == expected_len
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
        && value.bytes().any(|byte| byte != b'0')
}

pub struct PreparedSpanExport {
    inner: PreparedExportEvent,
}

impl fmt::Debug for PreparedSpanExport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PreparedSpanExport")
            .field("inner", &self.inner)
            .finish()
    }
}

pub struct SpanExportSession {
    inner: ExportEventSession,
}

impl SpanExportSession {
    pub fn new(capacity: usize) -> Result<Self, ExportEventLedgerRefusal> {
        Ok(Self {
            inner: ExportEventSession::new(capacity)?,
        })
    }

    pub fn len(&self) -> usize {
        self.inner.len()
    }

    pub fn checkpoint(&self) -> Result<LedgerCheckpoint, LedgerCheckpointRefusal> {
        self.inner.checkpoint()
    }

    pub fn verify_checkpoint(
        &self,
        checkpoint: &LedgerCheckpoint,
    ) -> Result<(), LedgerCheckpointRefusal> {
        self.inner.verify_checkpoint(checkpoint)
    }

    pub fn reconcile(
        &mut self,
        prepared: PreparedSpanExport,
        adapter: &mut impl OutboundAdapter,
    ) -> Result<ExportEventReceipt, ExportEventLedgerRefusal> {
        self.inner.reconcile(prepared.inner, adapter)
    }
}

pub fn prepare_span_export(
    capability: OutboundCapability,
    endpoint: String,
    deadline_ms: u64,
    span: SpanExport,
) -> Result<PreparedSpanExport, Refusal> {
    let body = span.encode(&capability.policy)?;
    let replay_identity = format!("{}:{}", span.trace_id, span.span_id);
    let span_id = span.span_id;
    Ok(PreparedSpanExport {
        inner: super::tracing::prepare_operational_export(
            capability,
            endpoint,
            deadline_ms,
            span_id,
            Some(replay_identity),
            "application/vnd.semaprax.span.v1+json",
            "x-semaprax-span-id",
            SPAN_IDEMPOTENCY_DOMAIN,
            body,
        )?,
    })
}

/// Independently decode the closed span schema and bind it to one prepared
/// request without recovering authority or permitting dispatch.
pub fn verify_span_export(
    bytes: &[u8],
    expected_request: &PreparedRequest,
) -> Result<(), SpanWireMismatch> {
    if bytes.is_empty() || bytes.len() > MAX_REQUEST_BODY_BYTES {
        return Err(SpanWireMismatch::Bound);
    }
    let value: serde_json::Value =
        serde_json::from_slice(bytes).map_err(|_| SpanWireMismatch::Malformed)?;
    decode_span(&value)?;
    let canonical = serde_json::to_vec(&value).map_err(|_| SpanWireMismatch::Malformed)?;
    if canonical != bytes {
        return Err(SpanWireMismatch::NonCanonical);
    }
    let span_id = value["span_id"].as_str().ok_or(SpanWireMismatch::Schema)?;
    if expected_request.body() != bytes
        || expected_request.headers().len() != 3
        || expected_request.headers()[0]
            != (
                "content-type".into(),
                "application/vnd.semaprax.span.v1+json".into(),
            )
        || expected_request.headers()[1].0 != "idempotency-key"
        || !valid_sha256(&expected_request.headers()[1].1)
        || expected_request.headers()[2] != ("x-semaprax-span-id".into(), span_id.into())
    {
        return Err(SpanWireMismatch::PreparedRequest);
    }
    Ok(())
}

fn decode_span(value: &serde_json::Value) -> Result<(), SpanWireMismatch> {
    const KEYS: [&str; 8] = [
        "attributes",
        "duration_micros",
        "name",
        "parent_span_id",
        "schema",
        "span_id",
        "status",
        "trace_id",
    ];
    let object = value.as_object().ok_or(SpanWireMismatch::Schema)?;
    if object.len() != KEYS.len() || KEYS.iter().any(|key| !object.contains_key(*key)) {
        return Err(SpanWireMismatch::Schema);
    }
    let trace_id = value["trace_id"].as_str().ok_or(SpanWireMismatch::Schema)?;
    let span_id = value["span_id"].as_str().ok_or(SpanWireMismatch::Schema)?;
    let parent_span_id = if value["parent_span_id"].is_null() {
        None
    } else {
        Some(
            value["parent_span_id"]
                .as_str()
                .ok_or(SpanWireMismatch::Schema)?,
        )
    };
    let name = value["name"].as_str().ok_or(SpanWireMismatch::Schema)?;
    let status = value["status"].as_str().ok_or(SpanWireMismatch::Schema)?;
    if value["schema"] != "semaprax.operational-span.v1"
        || !lower_hex_id(trace_id, 32)
        || !lower_hex_id(span_id, 16)
        || parent_span_id.is_some_and(|parent| !lower_hex_id(parent, 16) || parent == span_id)
        || name.is_empty()
        || name.len() > MAX_SPAN_NAME_BYTES
        || contains_control(name)
        || !matches!(status, "unset" | "ok" | "error")
        || value["duration_micros"].as_u64().is_none()
    {
        return Err(SpanWireMismatch::Schema);
    }
    let attributes = value["attributes"]
        .as_array()
        .ok_or(SpanWireMismatch::Schema)?;
    if attributes.len() > MAX_EXPORT_FIELDS {
        return Err(SpanWireMismatch::Bound);
    }
    let mut previous = None;
    for attribute in attributes {
        let object = attribute.as_object().ok_or(SpanWireMismatch::Schema)?;
        let name = attribute["name"].as_str().ok_or(SpanWireMismatch::Schema)?;
        let value = attribute["value"]
            .as_str()
            .ok_or(SpanWireMismatch::Schema)?;
        let redacted = object.contains_key("commitment");
        let shape_ok = if redacted {
            object.len() == 3
                && value == "[REDACTED]"
                && object.contains_key("commitment")
                && (attribute["commitment"].is_null()
                    || attribute["commitment"].as_str().is_some_and(valid_sha256))
        } else {
            object.len() == 2
        };
        if !shape_ok
            || !object.contains_key("name")
            || !object.contains_key("value")
            || !valid_name(name)
            || contains_control(value)
            || value.len() > MAX_EXPORT_VALUE_BYTES
            || (!redacted && super::protected_names::is_protected(name))
            || previous.is_some_and(|previous: &str| previous >= name)
        {
            return Err(SpanWireMismatch::Schema);
        }
        previous = Some(name);
    }
    Ok(())
}

#[cfg(test)]
#[path = "spans_tests.rs"]
mod tests;
