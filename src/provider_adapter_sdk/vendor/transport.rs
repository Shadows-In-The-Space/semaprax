//! The host-owned HTTP/SSE seam used by concrete provider adapters.
//!
//! `HostHttpStreamTransport` is intentionally more narrow than an HTTP client:
//! it receives no absolute URL and does not return headers or credentials to an
//! adapter.  A host binds its approved origin, proxy policy, TLS, authentication
//! and secret handling while constructing this object.  This module neither
//! reads environment variables nor imports an HTTP implementation.

/// Public, provider-protocol request data.  `path` must be an API-relative
/// path; the adapter cannot select an origin.  `headers` contain only fixed
/// protocol headers and must never contain authentication material.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProviderHttpRequest {
    pub method: &'static str,
    pub path: &'static str,
    pub headers: Vec<(&'static str, &'static str)>,
    pub body: Vec<u8>,
    /// Maximum HTTP/SSE wire bytes; separate from decoded Proposal capacity.
    pub max_response_bytes: usize,
}

/// A host transport's classification of a transport-side failure.  This is
/// trusted host evidence, never parsed from a provider body.  In particular,
/// `UncertainAfterDispatch` prohibits automatic retry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransportFailureKind {
    NotDispatched,
    RejectedBeforeProcessing,
    CapacityExceeded,
    TimeoutAfterDispatch,
    CancelledAfterDispatch,
    UncertainAfterDispatch,
    MalformedResponse,
}

/// Bounded, redacted transport failure metadata. `attempted_bytes` must be
/// the amount of response data observed, never a provider error body.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TransportFailure {
    pub kind: TransportFailureKind,
    pub attempted_bytes: usize,
}

/// One poll result from a host-owned HTTP response stream.  Chunk boundaries
/// are arbitrary and need not align to UTF-8, JSON, SSE lines, or SSE events.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TransportPoll {
    Pending,
    Chunk(Vec<u8>),
    End,
    Failed(TransportFailure),
}

/// The in-flight stream controlled by a host transport.  `cancel` is a
/// request to close locally/abort the request; it does not claim remote work
/// stopped, nor does it expose a provider cancellation endpoint.
pub trait HostHttpStream {
    fn poll(&mut self) -> TransportPoll;
    fn cancel(&mut self, reason: &str);
}

/// One explicitly injected host authority for a provider invocation.  Hosts
/// must reject any path outside their configured provider origin and attach
/// credentials themselves.  The adapter has no URL, proxy, credential or
/// environment field from which it could widen that authority.
pub trait HostHttpStreamTransport {
    fn start(
        &mut self,
        request: ProviderHttpRequest,
    ) -> Result<Box<dyn HostHttpStream>, TransportFailure>;
}

/// Maximum retained undecoded wire data per transport poll. It bounds both a
/// hostile peer that never sends a blank line and a host that presents an
/// oversized chunk; ordinary response-byte limits are checked separately by
/// each adapter before exposing a delta.
pub(crate) const MAX_SSE_EVENT_BYTES: usize = 1_048_576;
pub(crate) const MAX_TOTAL_WIRE_BYTES: usize = 8 * 1_048_576;
/// Stops a valid-but-hostile chunk from creating unbounded queued events.
pub(crate) const MAX_SSE_EVENTS_PER_CHUNK: usize = 4_096;

/// Minimal SSE framing parser. It preserves arbitrary TCP chunk boundaries,
/// accepts CRLF or LF, joins multi-line `data:` fields as SSE specifies, and
/// intentionally ignores event comments/ids/retry fields. Provider event type
/// is carried in the JSON payload by both supported protocols.
#[derive(Default)]
pub(crate) struct SseDecoder {
    pending: Vec<u8>,
    total_bytes: usize,
}

impl SseDecoder {
    pub(crate) fn is_empty(&self) -> bool {
        self.pending.is_empty()
    }
    pub(crate) fn push(&mut self, chunk: &[u8]) -> Result<Vec<Vec<u8>>, ()> {
        // Include ignored comments and incomplete frames in the invocation bound.
        if chunk.len() > MAX_TOTAL_WIRE_BYTES.saturating_sub(self.total_bytes) {
            return Err(());
        }
        self.total_bytes += chunk.len();
        if self.pending.len().saturating_add(chunk.len()) > MAX_SSE_EVENT_BYTES {
            return Err(());
        }
        self.pending.extend_from_slice(chunk);
        let mut events = Vec::new();
        let mut consumed = 0;
        let mut frames = 0;
        while let Some((end, separator_len)) = find_event_end(&self.pending[consumed..]) {
            if frames == MAX_SSE_EVENTS_PER_CHUNK {
                return Err(());
            }
            frames += 1;
            let raw = &self.pending[consumed..consumed + end];
            consumed += end + separator_len;
            let mut data = Vec::new();
            let mut has_data = false;
            for line in raw.split(|byte| *byte == b'\n') {
                let line = line.strip_suffix(b"\r").unwrap_or(line);
                if let Some(value) = line.strip_prefix(b"data:") {
                    let value = value.strip_prefix(b" ").unwrap_or(value);
                    if has_data {
                        data.push(b'\n');
                    }
                    has_data = true;
                    data.extend_from_slice(value);
                }
            }
            if has_data {
                events.push(data);
            }
        }
        self.pending.drain(..consumed);
        Ok(events)
    }
}

fn find_event_end(bytes: &[u8]) -> Option<(usize, usize)> {
    for index in 0..bytes.len() {
        if bytes[index..].starts_with(b"\n\n") {
            return Some((index, 2));
        }
        if bytes[index..].starts_with(b"\r\n\r\n") {
            return Some((index, 4));
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn wire_bounds_include_ignored_comments_and_frame_inventory() {
        let mut decoder = SseDecoder::default();
        let mut comment = vec![b'x'; MAX_SSE_EVENT_BYTES];
        comment[0] = b':';
        comment[MAX_SSE_EVENT_BYTES - 2..].copy_from_slice(b"\n\n");
        for _ in 0..8 {
            assert!(decoder.push(&comment).unwrap().is_empty());
        }
        assert!(decoder.push(b":\n\n").is_err());
        assert!(SseDecoder::default()
            .push(&b":\n\n".repeat(MAX_SSE_EVENTS_PER_CHUNK + 1))
            .is_err());
    }
    #[test]
    fn empty_data_lines_are_preserved_and_chunk_boundaries_are_lossless() {
        let mut decoder = SseDecoder::default();
        assert!(decoder.push(b"data:\r\ndata: x\r\n\r").unwrap().is_empty());
        assert_eq!(decoder.push(b"\n").unwrap(), vec![b"\nx".to_vec()]);
        assert!(decoder.is_empty());
    }
}
