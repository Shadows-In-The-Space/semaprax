//! Typed, bounded metric exports over the operational host boundary.
//!
//! Metric values and labels are canonical data, not formatting instructions.
//! This module allocates no global registry and performs no network I/O; the
//! caller must supply one deployment-bound capability per observation.

use std::fmt;

use super::*;

const METRIC_IDEMPOTENCY_DOMAIN: &[u8] = b"semaprax.outbound.metric-export.idempotency.v1\0";

/// Closed metric value vocabulary. Integer values avoid non-canonical NaN and
/// infinity spellings at the export boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MetricKind {
    CounterIncrement(u64),
    Gauge(i64),
    HistogramObservation(i64),
}

/// One independently identified metric observation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MetricExport {
    pub stable_metric_id: String,
    pub observation_id: String,
    pub labels: Vec<(String, String)>,
    pub kind: MetricKind,
}

/// Failure while independently checking the metric wire and its prepared
/// request binding.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MetricWireMismatch {
    Bound,
    Malformed,
    Schema,
    NonCanonical,
    PreparedRequest,
}

impl MetricExport {
    fn encode(&self, policy: &OutboundPolicy) -> Result<Vec<u8>, Refusal> {
        if !valid_identity(&self.stable_metric_id) || !valid_identity(&self.observation_id) {
            return Err(Refusal::InvalidIdentity);
        }
        if self.labels.len() > policy.max_export_labels {
            return Err(Refusal::CardinalityExceeded);
        }
        if matches!(self.kind, MetricKind::CounterIncrement(0)) {
            return Err(Refusal::InvalidIdentity);
        }
        if self
            .labels
            .iter()
            .any(|(name, value)| !valid_name(name) || contains_control(value))
        {
            return Err(Refusal::InvalidIdentity);
        }
        if self
            .labels
            .iter()
            .any(|(_, value)| value.len() > MAX_EXPORT_VALUE_BYTES)
        {
            return Err(Refusal::RequestTooLarge);
        }
        if self
            .labels
            .iter()
            .any(|(name, _)| super::protected_names::is_protected(name))
        {
            return Err(Refusal::ProtectedValue);
        }
        let aggregate = self
            .labels
            .iter()
            .try_fold(
                self.stable_metric_id.len() + self.observation_id.len(),
                |total, (name, value)| total.checked_add(name.len())?.checked_add(value.len()),
            )
            .ok_or(Refusal::RequestTooLarge)?;
        if aggregate > policy.max_request_bytes {
            return Err(Refusal::RequestTooLarge);
        }

        let mut labels = self.labels.iter().collect::<Vec<_>>();
        labels.sort();
        if labels.windows(2).any(|pair| pair[0].0 == pair[1].0) {
            return Err(Refusal::CardinalityExceeded);
        }
        let labels = labels
            .into_iter()
            .map(|(name, value)| serde_json::json!({"name": name, "value": value}))
            .collect::<Vec<_>>();
        let (kind, value) = match self.kind {
            MetricKind::CounterIncrement(value) => ("counter_increment", serde_json::json!(value)),
            MetricKind::Gauge(value) => ("gauge", serde_json::json!(value)),
            MetricKind::HistogramObservation(value) => {
                ("histogram_observation", serde_json::json!(value))
            }
        };
        let value = serde_json::json!({
            "schema": "semaprax.operational-metric.v1",
            "metric_id": &self.stable_metric_id,
            "observation_id": &self.observation_id,
            "kind": kind,
            "value": value,
            "labels": labels,
        });
        let mut output = CappedJsonWriter::new(policy.max_request_bytes);
        serde_json::to_writer(&mut output, &value).map_err(|_| Refusal::RequestTooLarge)?;
        Ok(output.finish())
    }
}

/// Opaque admitted metric request. It cannot dispatch without a session and
/// contains the consumed one-shot capability inside the common prepared form.
pub struct PreparedMetricExport {
    inner: PreparedExportEvent,
}

impl fmt::Debug for PreparedMetricExport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PreparedMetricExport")
            .field("inner", &self.inner)
            .finish()
    }
}

/// Bounded process-local replay suppression for typed metric observations.
pub struct MetricExportSession {
    inner: ExportEventSession,
}

impl MetricExportSession {
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
        prepared: PreparedMetricExport,
        adapter: &mut impl OutboundAdapter,
    ) -> Result<ExportEventReceipt, ExportEventLedgerRefusal> {
        self.inner.reconcile(prepared.inner, adapter)
    }
}

/// Validate and bind one metric observation without entering an adapter.
pub fn prepare_metric_export(
    capability: OutboundCapability,
    endpoint: String,
    deadline_ms: u64,
    metric: MetricExport,
) -> Result<PreparedMetricExport, Refusal> {
    let body = metric.encode(&capability.policy)?;
    Ok(PreparedMetricExport {
        inner: super::tracing::prepare_operational_export(
            capability,
            endpoint,
            deadline_ms,
            metric.observation_id,
            None,
            "application/vnd.semaprax.metric.v1+json",
            "x-semaprax-observation-id",
            METRIC_IDEMPOTENCY_DOMAIN,
            body,
        )?,
    })
}

/// Independently decode a canonical metric payload and bind it to the exact
/// prepared request. This grants no capability and cannot dispatch it.
pub fn verify_metric_export(
    bytes: &[u8],
    expected_request: &PreparedRequest,
) -> Result<(), MetricWireMismatch> {
    if bytes.is_empty() || bytes.len() > MAX_REQUEST_BODY_BYTES {
        return Err(MetricWireMismatch::Bound);
    }
    let value: serde_json::Value =
        serde_json::from_slice(bytes).map_err(|_| MetricWireMismatch::Malformed)?;
    decode_metric(&value)?;
    let canonical = serde_json::to_vec(&value).map_err(|_| MetricWireMismatch::Malformed)?;
    if canonical != bytes {
        return Err(MetricWireMismatch::NonCanonical);
    }
    let observation_id = value["observation_id"]
        .as_str()
        .ok_or(MetricWireMismatch::Schema)?;
    if expected_request.body() != bytes
        || expected_request.headers().len() != 3
        || expected_request.headers()[0]
            != (
                "content-type".into(),
                "application/vnd.semaprax.metric.v1+json".into(),
            )
        || expected_request.headers()[1].0 != "idempotency-key"
        || !valid_sha256(&expected_request.headers()[1].1)
        || expected_request.headers()[2]
            != ("x-semaprax-observation-id".into(), observation_id.into())
    {
        return Err(MetricWireMismatch::PreparedRequest);
    }
    Ok(())
}

fn decode_metric(value: &serde_json::Value) -> Result<(), MetricWireMismatch> {
    const KEYS: [&str; 6] = [
        "kind",
        "labels",
        "metric_id",
        "observation_id",
        "schema",
        "value",
    ];
    let object = value.as_object().ok_or(MetricWireMismatch::Schema)?;
    if object.len() != KEYS.len() || KEYS.iter().any(|key| !object.contains_key(*key)) {
        return Err(MetricWireMismatch::Schema);
    }
    let metric_id = value["metric_id"]
        .as_str()
        .ok_or(MetricWireMismatch::Schema)?;
    let observation_id = value["observation_id"]
        .as_str()
        .ok_or(MetricWireMismatch::Schema)?;
    if value["schema"] != "semaprax.operational-metric.v1"
        || !valid_identity(metric_id)
        || !valid_identity(observation_id)
    {
        return Err(MetricWireMismatch::Schema);
    }
    let kind = value["kind"].as_str().ok_or(MetricWireMismatch::Schema)?;
    let valid_value = match kind {
        "counter_increment" => value["value"].as_u64().is_some_and(|value| value != 0),
        "gauge" | "histogram_observation" => value["value"].as_i64().is_some(),
        _ => false,
    };
    if !valid_value {
        return Err(MetricWireMismatch::Schema);
    }
    let labels = value["labels"]
        .as_array()
        .ok_or(MetricWireMismatch::Schema)?;
    if labels.len() > MAX_EXPORT_LABELS {
        return Err(MetricWireMismatch::Bound);
    }
    let mut previous = None;
    for label in labels {
        let object = label.as_object().ok_or(MetricWireMismatch::Schema)?;
        if object.len() != 2 || !object.contains_key("name") || !object.contains_key("value") {
            return Err(MetricWireMismatch::Schema);
        }
        let name = label["name"].as_str().ok_or(MetricWireMismatch::Schema)?;
        let value = label["value"].as_str().ok_or(MetricWireMismatch::Schema)?;
        if !valid_name(name)
            || contains_control(value)
            || value.len() > MAX_EXPORT_VALUE_BYTES
            || super::protected_names::is_protected(name)
            || previous.is_some_and(|previous: &str| previous >= name)
        {
            return Err(MetricWireMismatch::Schema);
        }
        previous = Some(name);
    }
    Ok(())
}

#[cfg(test)]
#[path = "metrics_tests.rs"]
mod tests;
