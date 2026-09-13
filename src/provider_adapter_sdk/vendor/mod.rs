//! Bounded, real-provider wire normalizers.
//!
//! The adapters here implement the public [`ProviderAdapter`](super::ProviderAdapter)
//! seam, but deliberately do not implement HTTP, DNS, proxy discovery, endpoint
//! selection, credential lookup, or TLS.  A host injects all of that in
//! [`HostHttpStreamTransport`].  The only values an adapter gives that transport
//! are a fixed relative API path, public protocol headers, and a bounded body.
//! Consequently a provider response cannot create network authority and no
//! credential has a representation in this module.
//!
//! They normalize OpenAI's Responses SSE protocol and Anthropic's Messages SSE
//! protocol.  Both reject provider-native tool/function events before they can
//! reach the compiler bridge; only ordinary text deltas are exposed as
//! `AdapterEvent::Delta`.  A closed stream or reset after dispatch is reported
//! as `ProviderError` and recorded here as `AttemptOutcomeClass::Uncertain`;
//! that is intentionally not an automatic-retry signal.

mod anthropic_messages;
mod openai_responses;
mod transport;

pub use anthropic_messages::AnthropicMessagesAdapter;
pub use openai_responses::OpenAiResponsesAdapter;
pub use transport::{
    HostHttpStream, HostHttpStreamTransport, ProviderHttpRequest, TransportFailure,
    TransportFailureKind, TransportPoll,
};

#[cfg(test)]
mod tests;

#[cfg(test)]
mod bounds_tests;
