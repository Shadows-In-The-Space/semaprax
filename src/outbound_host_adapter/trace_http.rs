//! Typed W3C trace propagation through the bounded HTTP effect boundary.
//!
//! A trace context is correlation data, never an outbound authority. The
//! caller still needs an [`OutboundCapability`] and an injected adapter before
//! this value can cause physical network activity.

use super::*;

/// An HTTP request coupled to one locally-owned current span.
///
/// The public HTTP header type deliberately refuses `traceparent` and
/// `tracestate`. This wrapper is the only way this adapter emits a
/// `traceparent`, so the transported parent always comes from a parsed or
/// entropy-derived [`TraceContext`]. Vendor state may only enter through a
/// separately parsed [`TraceState`], never through caller-selected headers.
pub struct TracedHttpRequest {
    request: HttpRequest,
    context: TraceContext,
    tracestate: Option<TraceState>,
}

impl TracedHttpRequest {
    pub fn new(request: HttpRequest, context: TraceContext) -> Self {
        Self {
            request,
            context,
            tracestate: None,
        }
    }

    pub fn trace_context(&self) -> &TraceContext {
        &self.context
    }

    /// Bind one already-admitted vendor state carrier for canonical forwarding.
    ///
    /// The type has no raw-string constructor on this request path, so it
    /// cannot become an unbounded reserved-header injection bypass.
    pub fn with_tracestate(mut self, tracestate: TraceState) -> Self {
        self.tracestate = Some(tracestate);
        self
    }

    pub fn tracestate(&self) -> Option<&TraceState> {
        self.tracestate.as_ref()
    }

    fn into_parts(self) -> (HttpRequest, TraceContext, Option<TraceState>) {
        (self.request, self.context, self.tracestate)
    }
}

/// Validate and prepare a request with one canonical `traceparent` header.
///
/// The header counts toward the global HTTP header bound and is covered by the
/// prepared request digest, so changing the span conflicts with a retained
/// idempotency identity rather than silently replaying another context.
pub fn prepare_traced_http_delivery(
    capability: OutboundCapability,
    request: TracedHttpRequest,
) -> Result<PreparedHttpDelivery, Refusal> {
    let (request, context, tracestate) = request.into_parts();
    super::http::prepare_http_delivery_with_trace_context(
        capability,
        request,
        Some(&context),
        tracestate.as_ref(),
    )
}

/// Validate and dispatch exactly one request with a canonical `traceparent`.
///
/// This preserves the ordinary HTTP boundary's no-retry and sticky-settlement
/// rules. The typed context neither adds network authority nor authenticates a
/// remote caller.
pub fn deliver_traced_http(
    capability: OutboundCapability,
    request: TracedHttpRequest,
    adapter: &mut impl OutboundAdapter,
) -> Result<DeliveryResult, Refusal> {
    let (request, context, tracestate) = request.into_parts();
    super::http::deliver_http_with_trace_context(
        capability,
        request,
        Some(&context),
        tracestate.as_ref(),
        adapter,
    )
}

#[cfg(test)]
#[path = "trace_http_tests.rs"]
mod tests;
