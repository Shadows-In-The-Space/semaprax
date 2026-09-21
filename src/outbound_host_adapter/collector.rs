//! Host-selected telemetry collector routes for the closed operational wires.
//!
//! This module deliberately owns only route selection.  A target contains one
//! canonical HTTPS origin and derives the three fixed v1 signal paths; callers
//! cannot supply a path, headers, content type, storage, retry policy, or an
//! adapter through this API.  A separate move-only [`OutboundCapability`] is
//! still required for each preparation, and an injected [`OutboundAdapter`]
//! is still required later to attempt the already prepared request.

use std::fmt;

use super::*;

const METRICS_PATH: &str = "/v1/metrics";
const SPANS_PATH: &str = "/v1/spans";
const EVENTS_PATH: &str = "/v1/events";

/// One host-configured collector origin for the SEMAPRAX telemetry v1 routes.
///
/// The constructor accepts only the canonical origin form (for example
/// `https://collector.example.test`), never a path, query, credentials, or
/// fragment.  Each signal path is a module constant so a source value cannot
/// turn a metric or span export into an arbitrary POST target.
#[derive(Clone, Eq, PartialEq)]
pub struct TelemetryCollectorTarget {
    origin: String,
}

impl fmt::Debug for TelemetryCollectorTarget {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TelemetryCollectorTarget")
            .field("origin", &self.origin)
            .finish()
    }
}

impl TelemetryCollectorTarget {
    /// Admit an exact deployment-selected collector origin.
    ///
    /// This is a Rust-host configuration seam.  SEMAPRAX source does not
    /// construct this value, and constructing it does not grant network,
    /// storage, timer, or retry authority.
    pub fn for_trusted_host(origin: impl Into<String>) -> Result<Self, CollectorRefusal> {
        let origin = origin.into();
        if canonical_origin(&origin).as_deref() != Some(origin.as_str())
            || [METRICS_PATH, SPANS_PATH, EVENTS_PATH]
                .iter()
                .any(|path| origin.len().saturating_add(path.len()) > MAX_ENDPOINT_BYTES)
        {
            return Err(CollectorRefusal::InvalidTarget);
        }
        Ok(Self { origin })
    }

    /// The immutable canonical collector origin, never a signal endpoint.
    pub fn origin(&self) -> &str {
        &self.origin
    }

    fn endpoint(&self, path: &str) -> String {
        format!("{}{path}", self.origin)
    }
}

/// Closed pre-dispatch refusals from the collector route boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CollectorRefusal {
    InvalidTarget,
    AuthorityDenied,
    Export(Refusal),
}

impl From<Refusal> for CollectorRefusal {
    fn from(value: Refusal) -> Self {
        Self::Export(value)
    }
}

/// One host-bound preparation grant for exactly one telemetry signal.
///
/// It is intentionally neither `Clone` nor reusable.  Binding checks the
/// exact collector origin against the underlying deployment policy before a
/// signal can be prepared.  Consuming it only creates an opaque prepared
/// request; it does not dispatch it.
pub struct TelemetryCollectorCapability {
    capability: OutboundCapability,
    target: TelemetryCollectorTarget,
}

impl fmt::Debug for TelemetryCollectorCapability {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TelemetryCollectorCapability")
            .field("target", &self.target)
            .field("bindings", &"[REDACTED]")
            .finish()
    }
}

impl TelemetryCollectorCapability {
    /// Bind one ordinary deployment grant to one exact trusted collector.
    ///
    /// The collector must be present in the already-admitted outbound policy;
    /// a target configuration never expands that policy's authority.
    pub fn bind_for_trusted_host(
        capability: OutboundCapability,
        target: TelemetryCollectorTarget,
    ) -> Result<Self, CollectorRefusal> {
        if !capability.policy.allowed_origins.contains(target.origin()) {
            return Err(CollectorRefusal::AuthorityDenied);
        }
        Ok(Self { capability, target })
    }

    /// Prepare the fixed `/v1/metrics` protocol route.
    pub fn prepare_metric(
        self,
        deadline_ms: u64,
        metric: MetricExport,
    ) -> Result<PreparedMetricExport, CollectorRefusal> {
        Ok(super::metrics::prepare_metric_export(
            self.capability,
            self.target.endpoint(METRICS_PATH),
            deadline_ms,
            metric,
        )?)
    }

    /// Prepare the fixed `/v1/spans` protocol route.
    pub fn prepare_span(
        self,
        deadline_ms: u64,
        span: SpanExport,
    ) -> Result<PreparedSpanExport, CollectorRefusal> {
        Ok(super::spans::prepare_span_export(
            self.capability,
            self.target.endpoint(SPANS_PATH),
            deadline_ms,
            span,
        )?)
    }

    /// Prepare the fixed `/v1/events` protocol route for a structured event.
    pub fn prepare_event(
        self,
        deadline_ms: u64,
        event: ExportEvent,
    ) -> Result<PreparedExportEvent, CollectorRefusal> {
        Ok(super::tracing::prepare_export_event(
            self.capability,
            self.target.endpoint(EVENTS_PATH),
            deadline_ms,
            event,
        )?)
    }
}

#[cfg(test)]
mod tests;
