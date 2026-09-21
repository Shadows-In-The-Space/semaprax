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
/// entropy-derived [`TraceContext`]. `tracestate` is not represented or
/// forwarded by this v1 boundary.
pub struct TracedHttpRequest {
    request: HttpRequest,
    context: TraceContext,
}

impl TracedHttpRequest {
    pub fn new(request: HttpRequest, context: TraceContext) -> Self {
        Self { request, context }
    }

    pub fn trace_context(&self) -> &TraceContext {
        &self.context
    }

    fn into_parts(self) -> (HttpRequest, TraceContext) {
        (self.request, self.context)
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
    let (request, context) = request.into_parts();
    super::http::prepare_http_delivery_with_trace_context(capability, request, Some(&context))
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
    let (request, context) = request.into_parts();
    super::http::deliver_http_with_trace_context(capability, request, Some(&context), adapter)
}

#[cfg(test)]
#[path = "trace_http_tests.rs"]
mod tests;
