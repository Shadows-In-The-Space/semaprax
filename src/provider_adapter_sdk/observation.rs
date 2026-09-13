//! Bounded, redacted observation of one concrete provider-adapter attempt.
//!
//! `RecordingAdapter` is a decorator over an already injected
//! [`ProviderAdapter`].  It has no transport, clock, credential, or replay
//! authority of its own.  It records commitments and counters only; request,
//! delta, settlement, usage, and cancellation plaintext never enter the
//! observation or its canonical rendering.

use sha2::{Digest as _, Sha256};

use crate::diagnostic::quote_json;
use crate::digest_hex::LowerHex;
use crate::live_invocation::model_invoke::ModelFailure;

use super::adapter::{
    AdapterEvent, AdapterInvocationCapability, AdapterPoll, AdapterRefusal, AdapterRequest,
    AdapterSettlement, AdapterUsage, ProviderAdapter,
};
use super::capability::{AdapterCapabilities, TokenAccountingSource};

pub const ATTEMPT_OBSERVATION_SCHEMA: &str = "semaprax.provider-adapter-attempt-observation.v1";
pub const MAX_OBSERVED_EVENTS: usize = 10_000;
/// Any provider-declared label retained in evidence is bounded before it is
/// cloned. Oversized labels are replaced by a deterministic commitment.
pub const MAX_OBSERVED_METADATA_BYTES: usize = 4_096;
/// Replay never allocates more response bytes than the existing streaming
/// grammar admits, even if hostile replay input names a larger request bound.
pub const MAX_REPLAY_RESPONSE_BYTES: usize = 65_536;
/// Largest possible v1 canonical rendering under the fixed event and metadata
/// bounds. Submitted render bytes are rejected before comparison above this.
pub const MAX_OBSERVATION_RENDER_BYTES: usize = 2_000_000;

const OBSERVATION_DOMAIN: &[u8] = b"semaprax.provider-adapter-attempt-observation.v1\0";
const REQUEST_DOMAIN: &[u8] = b"semaprax.provider-adapter-attempt.request.v1\0";
const DELTA_DOMAIN: &[u8] = b"semaprax.provider-adapter-attempt.delta.v1\0";
const RESPONSE_DOMAIN: &[u8] = b"semaprax.provider-adapter-attempt.response.v1\0";
const REFUSAL_DOMAIN: &[u8] = b"semaprax.provider-adapter-attempt.refusal.v1\0";
const CANCEL_DOMAIN: &[u8] = b"semaprax.provider-adapter-attempt.cancel.v1\0";
const METADATA_DOMAIN: &[u8] = b"semaprax.provider-adapter-attempt.metadata.v1\0";

fn digest(domain: &[u8], bytes: &[u8]) -> String {
    let mut hash = Sha256::new();
    hash.update(domain);
    hash.update(bytes);
    format!("sha256:{:x}", LowerHex(hash.finalize()))
}

/// Commits to exact request bytes without retaining them.
#[must_use]
pub fn commit_request(bytes: &[u8]) -> String {
    digest(REQUEST_DOMAIN, bytes)
}

/// Commits to one exact streaming chunk, including an empty chunk.
#[must_use]
pub fn commit_delta(bytes: &[u8]) -> String {
    digest(DELTA_DOMAIN, bytes)
}

/// Commits to the terminal adapter response without retaining it.
#[must_use]
pub fn commit_response(bytes: &[u8]) -> String {
    digest(RESPONSE_DOMAIN, bytes)
}

fn commit_refusal(bytes: &[u8]) -> String {
    digest(REFUSAL_DOMAIN, bytes)
}

fn commit_cancel(bytes: &[u8]) -> String {
    digest(CANCEL_DOMAIN, bytes)
}

fn bounded_metadata(value: &str) -> (String, bool) {
    if value.len() <= MAX_OBSERVED_METADATA_BYTES {
        (value.to_owned(), false)
    } else {
        (
            format!("oversized:{}", digest(METADATA_DOMAIN, value.as_bytes())),
            true,
        )
    }
}

/// An explicitly injected source of observation timestamps.  Implementors may
/// return `None`; the recorder never reads a wall clock or invents a time.
pub trait AttemptClock {
    fn observed_at_ms(&self) -> Option<u64>;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ByteCommitment {
    commitment: String,
    bytes_len: usize,
}

impl ByteCommitment {
    fn new(commitment: String, bytes_len: usize) -> Self {
        Self {
            commitment,
            bytes_len,
        }
    }

    #[must_use]
    pub fn commitment(&self) -> &str {
        &self.commitment
    }

    #[must_use]
    pub fn bytes_len(&self) -> usize {
        self.bytes_len
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ObservedUsage {
    pub tokens_in: Option<u64>,
    pub tokens_out: Option<u64>,
    pub cost_micros: Option<i64>,
}

impl From<AdapterUsage> for ObservedUsage {
    fn from(usage: AdapterUsage) -> Self {
        Self {
            tokens_in: usage.tokens_in,
            tokens_out: usage.tokens_out,
            cost_micros: usage.cost_micros,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ObservedEvent {
    Delta(ByteCommitment),
    Usage(ObservedUsage),
    Completed,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AttemptTerminal {
    StartRefused(ByteCommitment),
    Settled {
        response: ByteCommitment,
        usage: ObservedUsage,
    },
    Failed {
        failure: ModelFailure,
        attempted_bytes: usize,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CancellationObservation {
    reason: ByteCommitment,
    requests: usize,
}

impl CancellationObservation {
    #[must_use]
    pub fn reason(&self) -> &ByteCommitment {
        &self.reason
    }

    #[must_use]
    pub fn requests(&self) -> usize {
        self.requests
    }
}

/// Facts copied from the adapter's declaration before the attempt starts.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ObservedCapabilities {
    adapter_identity: String,
    adapter_version: String,
    provider_profile: String,
    token_accounting_source: TokenAccountingSource,
    supports_streaming: bool,
    max_request_bytes: usize,
    max_response_bytes: usize,
}

impl ObservedCapabilities {
    fn bounded(capabilities: &AdapterCapabilities) -> (Self, bool) {
        let (adapter_identity, identity_overflow) =
            bounded_metadata(&capabilities.adapter_identity);
        let (adapter_version, version_overflow) = bounded_metadata(&capabilities.adapter_version);
        let (provider_profile, profile_overflow) = bounded_metadata(&capabilities.provider_profile);
        (
            Self {
                adapter_identity,
                adapter_version,
                provider_profile,
                token_accounting_source: capabilities.token_accounting_source,
                supports_streaming: capabilities.supports_streaming,
                max_request_bytes: capabilities.max_request_bytes,
                max_response_bytes: capabilities.max_response_bytes,
            },
            identity_overflow || version_overflow || profile_overflow,
        )
    }
    #[must_use]
    pub fn adapter_identity(&self) -> &str {
        &self.adapter_identity
    }
    #[must_use]
    pub fn adapter_version(&self) -> &str {
        &self.adapter_version
    }
    #[must_use]
    pub fn provider_profile(&self) -> &str {
        &self.provider_profile
    }
    #[must_use]
    pub fn token_accounting_source(&self) -> TokenAccountingSource {
        self.token_accounting_source
    }
    #[must_use]
    pub fn supports_streaming(&self) -> bool {
        self.supports_streaming
    }
    #[must_use]
    pub fn max_request_bytes(&self) -> usize {
        self.max_request_bytes
    }
    #[must_use]
    pub fn max_response_bytes(&self) -> usize {
        self.max_response_bytes
    }
}

/// Immutable, bounded attempt evidence.  A capture overflow is represented
/// explicitly and makes independent replay refuse rather than silently
/// accepting a prefix of an attempt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AttemptObservation {
    capabilities: ObservedCapabilities,
    proposal_grammar_digest: String,
    request: Option<ByteCommitment>,
    request_max_response_bytes: Option<usize>,
    events: Vec<ObservedEvent>,
    terminal: Option<AttemptTerminal>,
    cancellation: Option<CancellationObservation>,
    observed_started_at_ms: Option<u64>,
    observed_finished_at_ms: Option<u64>,
    capture_overflow: bool,
}

impl AttemptObservation {
    fn new(capabilities: &AdapterCapabilities, proposal_grammar_digest: &str) -> Self {
        let (capabilities, capabilities_overflow) = ObservedCapabilities::bounded(capabilities);
        let (proposal_grammar_digest, grammar_overflow) = bounded_metadata(proposal_grammar_digest);
        Self {
            capabilities,
            proposal_grammar_digest,
            request: None,
            request_max_response_bytes: None,
            events: Vec::new(),
            terminal: None,
            cancellation: None,
            observed_started_at_ms: None,
            observed_finished_at_ms: None,
            capture_overflow: capabilities_overflow || grammar_overflow,
        }
    }

    #[must_use]
    pub fn capabilities(&self) -> &ObservedCapabilities {
        &self.capabilities
    }
    #[must_use]
    pub fn proposal_grammar_digest(&self) -> &str {
        &self.proposal_grammar_digest
    }
    #[must_use]
    pub fn request(&self) -> Option<&ByteCommitment> {
        self.request.as_ref()
    }
    #[must_use]
    pub fn request_commitment(&self) -> Option<&str> {
        self.request.as_ref().map(ByteCommitment::commitment)
    }
    #[must_use]
    pub fn request_bytes_len(&self) -> Option<usize> {
        self.request.as_ref().map(ByteCommitment::bytes_len)
    }
    #[must_use]
    pub fn request_max_response_bytes(&self) -> Option<usize> {
        self.request_max_response_bytes
    }
    #[must_use]
    pub fn events(&self) -> &[ObservedEvent] {
        &self.events
    }
    #[must_use]
    pub fn terminal(&self) -> Option<&AttemptTerminal> {
        self.terminal.as_ref()
    }
    #[must_use]
    pub fn response_commitment(&self) -> Option<&str> {
        match self.terminal.as_ref() {
            Some(AttemptTerminal::Settled { response, .. }) => Some(response.commitment()),
            _ => None,
        }
    }
    #[must_use]
    pub fn response_bytes_len(&self) -> Option<usize> {
        match self.terminal.as_ref() {
            Some(AttemptTerminal::Settled { response, .. }) => Some(response.bytes_len()),
            _ => None,
        }
    }
    #[must_use]
    pub fn settlement_usage(&self) -> Option<ObservedUsage> {
        match self.terminal.as_ref() {
            Some(AttemptTerminal::Settled { usage, .. }) => Some(*usage),
            _ => None,
        }
    }
    #[must_use]
    pub fn start_refusal_commitment(&self) -> Option<&str> {
        match self.terminal.as_ref() {
            Some(AttemptTerminal::StartRefused(reason)) => Some(reason.commitment()),
            _ => None,
        }
    }
    #[must_use]
    pub fn failure(&self) -> Option<(ModelFailure, usize)> {
        match self.terminal.as_ref() {
            Some(AttemptTerminal::Failed {
                failure,
                attempted_bytes,
            }) => Some((*failure, *attempted_bytes)),
            _ => None,
        }
    }
    #[must_use]
    pub fn cancellation(&self) -> Option<&CancellationObservation> {
        self.cancellation.as_ref()
    }
    #[must_use]
    pub fn observed_started_at_ms(&self) -> Option<u64> {
        self.observed_started_at_ms
    }
    #[must_use]
    pub fn observed_finished_at_ms(&self) -> Option<u64> {
        self.observed_finished_at_ms
    }
    #[must_use]
    pub fn capture_overflow(&self) -> bool {
        self.capture_overflow
    }

    /// Fixed-order JSON containing commitments and counters only.
    #[must_use]
    pub fn render(&self) -> String {
        let events = self
            .events
            .iter()
            .map(render_event)
            .collect::<Vec<_>>()
            .join(",");
        format!(
            concat!(
                "{{\"schema\":{},\"adapter_identity\":{},\"adapter_version\":{},",
                "\"provider_profile\":{},\"token_accounting_source\":{},",
                "\"supports_streaming\":{},\"max_request_bytes\":{},",
                "\"max_response_bytes\":{},\"proposal_grammar_digest\":{},",
                "\"request\":{},\"request_max_response_bytes\":{},\"events\":[{}],",
                "\"terminal\":{},\"cancellation\":{},\"observed_started_at_ms\":{},",
                "\"observed_finished_at_ms\":{},\"capture_overflow\":{}}}\n"
            ),
            quote_json(ATTEMPT_OBSERVATION_SCHEMA),
            quote_json(&self.capabilities.adapter_identity),
            quote_json(&self.capabilities.adapter_version),
            quote_json(&self.capabilities.provider_profile),
            quote_json(self.capabilities.token_accounting_source.as_str()),
            self.capabilities.supports_streaming,
            self.capabilities.max_request_bytes,
            self.capabilities.max_response_bytes,
            quote_json(&self.proposal_grammar_digest),
            render_commitment(self.request.as_ref()),
            render_usize(self.request_max_response_bytes),
            events,
            render_terminal(self.terminal.as_ref()),
            render_cancellation(self.cancellation.as_ref()),
            render_u64(self.observed_started_at_ms),
            render_u64(self.observed_finished_at_ms),
            self.capture_overflow,
        )
    }

    #[must_use]
    pub fn digest(&self) -> String {
        digest(OBSERVATION_DOMAIN, self.render().as_bytes())
    }

    /// Replays only supplied bytes and metadata.  This function deliberately
    /// has no adapter parameter and cannot instantiate or dispatch one.
    pub fn replay(&self, inputs: &ReplayInputs<'_>) -> Result<(), ReplayError> {
        if self.capture_overflow {
            return Err(ReplayError::CaptureOverflow);
        }
        if inputs.compiled_grammar_digest != self.proposal_grammar_digest {
            return Err(ReplayError::GrammarDigestMismatch);
        }
        match (&self.cancellation, inputs.cancellation) {
            (None, None) => {}
            (Some(recorded), Some(supplied))
                if recorded.requests == supplied.requests
                    && recorded.reason.commitment
                        == commit_cancel(supplied.first_reason.as_bytes())
                    && recorded.reason.bytes_len == supplied.first_reason.len() => {}
            _ => return Err(ReplayError::CancellationMismatch),
        }
        let request = self.request.as_ref().ok_or(ReplayError::MissingRequest)?;
        if request.commitment != commit_request(&inputs.request.request_bytes)
            || request.bytes_len != inputs.request.request_bytes.len()
            || self.request_max_response_bytes != Some(inputs.request.max_response_bytes)
        {
            return Err(ReplayError::RequestMismatch);
        }
        if inputs.request.max_response_bytes > MAX_REPLAY_RESPONSE_BYTES {
            return Err(ReplayError::ResponseTooLarge);
        }
        if inputs.events.len() != self.events.len() {
            return Err(ReplayError::EventCountMismatch);
        }
        let mut saw_completed = false;
        let mut response = Vec::new();
        for (recorded, supplied) in self.events.iter().zip(inputs.events) {
            match (recorded, supplied) {
                (ObservedEvent::Delta(recorded), AdapterEvent::Delta(chunk)) => {
                    if saw_completed
                        || recorded.commitment != commit_delta(chunk)
                        || recorded.bytes_len != chunk.len()
                    {
                        return Err(ReplayError::EventMismatch);
                    }
                    let next = response
                        .len()
                        .checked_add(chunk.len())
                        .ok_or(ReplayError::ResponseTooLarge)?;
                    if next > inputs.request.max_response_bytes || next > MAX_REPLAY_RESPONSE_BYTES
                    {
                        return Err(ReplayError::ResponseTooLarge);
                    }
                    response.extend_from_slice(chunk);
                }
                (
                    ObservedEvent::Usage(recorded),
                    AdapterEvent::Usage {
                        tokens_in,
                        tokens_out,
                        cost_micros,
                    },
                ) => {
                    if saw_completed
                        || recorded
                            != &(ObservedUsage {
                                tokens_in: Some(*tokens_in),
                                tokens_out: Some(*tokens_out),
                                cost_micros: Some(*cost_micros),
                            })
                    {
                        return Err(ReplayError::EventMismatch);
                    }
                }
                (ObservedEvent::Completed, AdapterEvent::Completed) => {
                    if saw_completed {
                        return Err(ReplayError::EventMismatch);
                    }
                    saw_completed = true;
                }
                _ => return Err(ReplayError::EventMismatch),
            }
        }
        match (
            &self.terminal,
            inputs.settlement,
            inputs.failure,
            inputs.start_refusal,
        ) {
            (
                Some(AttemptTerminal::Settled {
                    response: recorded,
                    usage,
                }),
                Some(settlement),
                None,
                None,
            ) => {
                if !saw_completed
                    || settlement.response_bytes != response
                    || recorded.commitment != commit_response(&settlement.response_bytes)
                    || recorded.bytes_len != settlement.response_bytes.len()
                    || *usage != settlement.usage.into()
                {
                    return Err(ReplayError::SettlementMismatch);
                }
            }
            (
                Some(AttemptTerminal::Failed {
                    failure,
                    attempted_bytes,
                }),
                None,
                Some((actual, bytes)),
                None,
            ) if *failure == actual && *attempted_bytes == bytes => {}
            (Some(AttemptTerminal::StartRefused(recorded)), None, None, Some(reason))
                if recorded.commitment == commit_refusal(reason.as_bytes())
                    && recorded.bytes_len == reason.len() => {}
            (None, None, None, None) => {}
            _ => return Err(ReplayError::TerminalMismatch),
        }
        Ok(())
    }

    /// Replays retained attempt inputs and then compares the exact submitted
    /// canonical observation bytes. Provider labels and timestamps remain
    /// host observations: this verifies their recorded bytes, never claims
    /// to independently rediscover them.
    pub fn replay_rendered_bytes(
        &self,
        submitted: &[u8],
        inputs: &ReplayInputs<'_>,
    ) -> Result<(), ReplayError> {
        if submitted.len() > MAX_OBSERVATION_RENDER_BYTES {
            return Err(ReplayError::RenderedObservationMismatch);
        }
        self.replay(inputs)?;
        if self.render().as_bytes() != submitted {
            return Err(ReplayError::RenderedObservationMismatch);
        }
        Ok(())
    }
}

/// Exact inputs an independent transcript replay must receive.  It contains
/// no `ProviderAdapter`, factory, callback, or other dispatch capability.
pub struct ReplayInputs<'a> {
    pub request: &'a AdapterRequest,
    pub events: &'a [AdapterEvent],
    pub settlement: Option<&'a AdapterSettlement>,
    pub failure: Option<(ModelFailure, usize)>,
    pub start_refusal: Option<&'a str>,
    pub cancellation: Option<ReplayCancellation<'a>>,
    pub compiled_grammar_digest: &'a str,
}

/// The caller-held cancellation request corresponding to the observation.
/// It is replay input only; the observation renders its commitment and count.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReplayCancellation<'a> {
    pub first_reason: &'a str,
    pub requests: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ReplayError {
    CaptureOverflow,
    GrammarDigestMismatch,
    CancellationMismatch,
    MissingRequest,
    RequestMismatch,
    EventCountMismatch,
    EventMismatch,
    ResponseTooLarge,
    SettlementMismatch,
    TerminalMismatch,
    RenderedObservationMismatch,
}

/// A one-start decorator that records what its injected adapter actually
/// returns.  It never copies raw provider bytes into evidence.
pub struct RecordingAdapter<'a> {
    inner: AdapterHandle<'a>,
    observation: AttemptObservation,
    clock: Option<&'a dyn AttemptClock>,
    started: bool,
    terminal_poll: Option<AdapterPoll>,
}

enum AdapterHandle<'a> {
    Borrowed(&'a mut dyn ProviderAdapter),
    Owned(Box<dyn ProviderAdapter>),
}

impl AdapterHandle<'_> {
    fn as_ref(&self) -> &dyn ProviderAdapter {
        match self {
            Self::Borrowed(adapter) => &**adapter,
            Self::Owned(adapter) => adapter.as_ref(),
        }
    }

    fn as_mut(&mut self) -> &mut dyn ProviderAdapter {
        match self {
            Self::Borrowed(adapter) => &mut **adapter,
            Self::Owned(adapter) => adapter.as_mut(),
        }
    }
}

impl<'a> RecordingAdapter<'a> {
    #[must_use]
    pub fn new(inner: &'a mut dyn ProviderAdapter, proposal_grammar_digest: &str) -> Self {
        let observation = AttemptObservation::new(inner.capabilities(), proposal_grammar_digest);
        Self {
            inner: AdapterHandle::Borrowed(inner),
            observation,
            clock: None,
            started: false,
            terminal_poll: None,
        }
    }

    /// Owns a factory-produced adapter for one attempt.  This is useful for
    /// source bridges whose factory returns `Box<dyn ProviderAdapter +
    /// 'static>`; the recorded object remains the exact same decorator.
    #[must_use]
    pub fn from_box(
        inner: Box<dyn ProviderAdapter>,
        proposal_grammar_digest: &str,
    ) -> RecordingAdapter<'static> {
        let observation = AttemptObservation::new(inner.capabilities(), proposal_grammar_digest);
        RecordingAdapter {
            inner: AdapterHandle::Owned(inner),
            observation,
            clock: None,
            started: false,
            terminal_poll: None,
        }
    }

    /// The owned-factory form with an explicit observation clock.  The clock
    /// lifetime bounds only the recorder; it grants no authority to the
    /// owned adapter.
    #[must_use]
    pub fn from_box_with_clock(
        inner: Box<dyn ProviderAdapter>,
        proposal_grammar_digest: &str,
        clock: &'a dyn AttemptClock,
    ) -> Self {
        let observation = AttemptObservation::new(inner.capabilities(), proposal_grammar_digest);
        Self {
            inner: AdapterHandle::Owned(inner),
            observation,
            clock: Some(clock),
            started: false,
            terminal_poll: None,
        }
    }

    #[must_use]
    pub fn with_clock(
        inner: &'a mut dyn ProviderAdapter,
        proposal_grammar_digest: &str,
        clock: &'a dyn AttemptClock,
    ) -> Self {
        let mut recorder = Self::new(inner, proposal_grammar_digest);
        recorder.clock = Some(clock);
        recorder
    }

    #[must_use]
    pub fn observation(&self) -> &AttemptObservation {
        &self.observation
    }

    fn now(&self) -> Option<u64> {
        self.clock.and_then(|clock| clock.observed_at_ms())
    }

    fn finish(&mut self, terminal: AttemptTerminal, poll: Option<AdapterPoll>) {
        if self.observation.terminal.is_none() {
            self.observation.terminal = Some(terminal);
            self.observation.observed_finished_at_ms = self.now();
        }
        if self.terminal_poll.is_none() {
            self.terminal_poll = poll;
        }
    }

    fn record_event(&mut self, event: &AdapterEvent) {
        if self.observation.events.len() == MAX_OBSERVED_EVENTS {
            self.observation.capture_overflow = true;
            return;
        }
        let observed = match event {
            AdapterEvent::Delta(bytes) => {
                ObservedEvent::Delta(ByteCommitment::new(commit_delta(bytes), bytes.len()))
            }
            AdapterEvent::Usage {
                tokens_in,
                tokens_out,
                cost_micros,
            } => ObservedEvent::Usage(ObservedUsage {
                tokens_in: Some(*tokens_in),
                tokens_out: Some(*tokens_out),
                cost_micros: Some(*cost_micros),
            }),
            AdapterEvent::Completed => ObservedEvent::Completed,
        };
        self.observation.events.push(observed);
    }
}

impl ProviderAdapter for RecordingAdapter<'_> {
    fn capabilities(&self) -> &AdapterCapabilities {
        self.inner.as_ref().capabilities()
    }

    fn start(
        &mut self,
        capability: &AdapterInvocationCapability,
        request: &AdapterRequest,
    ) -> Result<(), AdapterRefusal> {
        if self.started {
            return Err(AdapterRefusal(
                "recording adapter accepts one start".to_owned(),
            ));
        }
        self.started = true;
        self.observation.request = Some(ByteCommitment::new(
            commit_request(&request.request_bytes),
            request.request_bytes.len(),
        ));
        self.observation.request_max_response_bytes = Some(request.max_response_bytes);
        self.observation.observed_started_at_ms = self.now();
        match self.inner.as_mut().start(capability, request) {
            Ok(()) => Ok(()),
            Err(refusal) => {
                let sticky = AdapterPoll::Failed {
                    failure: ModelFailure::Refused,
                    attempted_bytes: 0,
                };
                self.finish(
                    AttemptTerminal::StartRefused(ByteCommitment::new(
                        commit_refusal(refusal.0.as_bytes()),
                        refusal.0.len(),
                    )),
                    Some(sticky),
                );
                Err(refusal)
            }
        }
    }

    fn poll(&mut self) -> AdapterPoll {
        if let Some(terminal) = &self.terminal_poll {
            return terminal.clone();
        }
        let poll = self.inner.as_mut().poll();
        match &poll {
            AdapterPoll::Event(event) => self.record_event(event),
            AdapterPoll::Settled(settlement) => {
                if settlement.response_bytes.len() > MAX_REPLAY_RESPONSE_BYTES {
                    self.observation.capture_overflow = true;
                    let sticky = AdapterPoll::Failed {
                        failure: ModelFailure::CapacityExceeded,
                        attempted_bytes: settlement.response_bytes.len(),
                    };
                    self.finish(
                        AttemptTerminal::Failed {
                            failure: ModelFailure::CapacityExceeded,
                            attempted_bytes: settlement.response_bytes.len(),
                        },
                        Some(sticky.clone()),
                    );
                    return sticky;
                }
                self.finish(
                    AttemptTerminal::Settled {
                        response: ByteCommitment::new(
                            commit_response(&settlement.response_bytes),
                            settlement.response_bytes.len(),
                        ),
                        usage: settlement.usage.into(),
                    },
                    Some(poll.clone()),
                );
            }
            AdapterPoll::Failed {
                failure,
                attempted_bytes,
            } => self.finish(
                AttemptTerminal::Failed {
                    failure: *failure,
                    attempted_bytes: *attempted_bytes,
                },
                Some(poll.clone()),
            ),
            AdapterPoll::Pending => {}
        }
        poll
    }

    fn cancel(&mut self, reason: &str) {
        match &mut self.observation.cancellation {
            Some(existing) => existing.requests = existing.requests.saturating_add(1),
            None => {
                self.observation.cancellation = Some(CancellationObservation {
                    reason: ByteCommitment::new(commit_cancel(reason.as_bytes()), reason.len()),
                    requests: 1,
                })
            }
        }
        self.inner.as_mut().cancel(reason);
    }
}

fn render_usize(value: Option<usize>) -> String {
    value.map_or_else(|| "null".to_owned(), |v| v.to_string())
}
fn render_u64(value: Option<u64>) -> String {
    value.map_or_else(|| "null".to_owned(), |v| v.to_string())
}
fn render_commitment(value: Option<&ByteCommitment>) -> String {
    value.map_or_else(
        || "null".to_owned(),
        |v| {
            format!(
                "{{\"commitment\":{},\"bytes_len\":{}}}",
                quote_json(&v.commitment),
                v.bytes_len
            )
        },
    )
}
fn render_usage(usage: ObservedUsage) -> String {
    format!(
        "{{\"tokens_in\":{},\"tokens_out\":{},\"cost_micros\":{}}}",
        render_u64(usage.tokens_in),
        render_u64(usage.tokens_out),
        usage
            .cost_micros
            .map_or_else(|| "null".to_owned(), |v| v.to_string())
    )
}
fn render_event(event: &ObservedEvent) -> String {
    match event {
        ObservedEvent::Delta(value) => format!(
            "{{\"kind\":\"delta\",\"commitment\":{},\"bytes_len\":{}}}",
            quote_json(&value.commitment),
            value.bytes_len
        ),
        ObservedEvent::Usage(value) => {
            format!("{{\"kind\":\"usage\",\"usage\":{}}}", render_usage(*value))
        }
        ObservedEvent::Completed => "{\"kind\":\"completed\"}".to_owned(),
    }
}
fn render_terminal(value: Option<&AttemptTerminal>) -> String {
    match value {
        None => "null".to_owned(),
        Some(AttemptTerminal::StartRefused(reason)) => format!(
            "{{\"kind\":\"start_refused\",\"reason\":{}}}",
            render_commitment(Some(reason))
        ),
        Some(AttemptTerminal::Settled { response, usage }) => format!(
            "{{\"kind\":\"settled\",\"response\":{},\"usage\":{}}}",
            render_commitment(Some(response)),
            render_usage(*usage)
        ),
        Some(AttemptTerminal::Failed {
            failure,
            attempted_bytes,
        }) => format!(
            "{{\"kind\":\"failed\",\"failure\":{},\"attempted_bytes\":{}}}",
            quote_json(failure.as_str()),
            attempted_bytes
        ),
    }
}
fn render_cancellation(value: Option<&CancellationObservation>) -> String {
    value.map_or_else(
        || "null".to_owned(),
        |v| {
            format!(
                "{{\"reason\":{},\"requests\":{}}}",
                render_commitment(Some(&v.reason)),
                v.requests
            )
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::provider_adapter_sdk::fixture_adapters::{usage, ScriptedStreamingAdapter};
    use crate::provider_adapter_sdk::hostile;

    fn request() -> AdapterRequest {
        AdapterRequest {
            request_bytes: b"secret prompt".to_vec(),
            max_response_bytes: 64,
        }
    }
    fn cap() -> AdapterInvocationCapability {
        AdapterInvocationCapability::grant("fixture")
    }

    #[test]
    fn records_actual_empty_chunks_usage_completion_and_settlement_without_plaintext() {
        let events = vec![Vec::new(), b"ok".to_vec()];
        let settlement = b"ok".to_vec();
        let mut script: Vec<_> = events
            .into_iter()
            .map(|bytes| AdapterPoll::Event(AdapterEvent::Delta(bytes)))
            .collect();
        script.push(AdapterPoll::Event(AdapterEvent::Usage {
            tokens_in: 3,
            tokens_out: 2,
            cost_micros: 1,
        }));
        script.push(AdapterPoll::Event(AdapterEvent::Completed));
        script.push(AdapterPoll::Settled(AdapterSettlement {
            response_bytes: settlement.clone(),
            usage: usage(3, 2, 1),
        }));
        let mut adapter = crate::provider_adapter_sdk::fixture_adapters::ScriptedAdapter::new(
            crate::provider_adapter_sdk::fixture_adapters::base_capabilities(
                "observation-test",
                true,
            ),
            script,
            true,
        );
        let mut recorder = RecordingAdapter::new(&mut adapter, "sha256:grammar");
        let request = request();
        recorder.start(&cap(), &request).unwrap();
        let mut actual = Vec::new();
        loop {
            match recorder.poll() {
                AdapterPoll::Event(event) => actual.push(event),
                AdapterPoll::Settled(value) => {
                    assert_eq!(value.response_bytes, settlement);
                    break;
                }
                other => panic!("unexpected poll: {other:?}"),
            }
        }
        let observation = recorder.observation();
        assert_eq!(observation.events().len(), 4);
        assert!(!observation.render().contains("secret prompt"));
        assert!(!observation.render().contains("\"ok\""));
        assert_eq!(
            observation.replay(&ReplayInputs {
                request: &request,
                events: &actual,
                settlement: Some(&AdapterSettlement {
                    response_bytes: settlement.clone(),
                    usage: usage(3, 2, 1)
                }),
                failure: None,
                start_refusal: None,
                cancellation: None,
                compiled_grammar_digest: "sha256:grammar"
            }),
            Ok(())
        );
        let submitted = observation.render();
        let replayed_settlement = AdapterSettlement {
            response_bytes: settlement,
            usage: usage(3, 2, 1),
        };
        let replay_inputs = ReplayInputs {
            request: &request,
            events: &actual,
            settlement: Some(&replayed_settlement),
            failure: None,
            start_refusal: None,
            cancellation: None,
            compiled_grammar_digest: "sha256:grammar",
        };
        assert_eq!(
            observation.replay_rendered_bytes(submitted.as_bytes(), &replay_inputs),
            Ok(())
        );
        let mut altered = submitted.into_bytes();
        altered[0] = b'[';
        assert_eq!(
            observation.replay_rendered_bytes(&altered, &replay_inputs),
            Err(ReplayError::RenderedObservationMismatch)
        );
    }

    #[test]
    fn replay_rejects_reordered_or_settlement_mismatched_transcripts() {
        let chunks = vec![b"a".to_vec(), b"b".to_vec()];
        let mut adapter =
            ScriptedStreamingAdapter::new(chunks, b"ab".to_vec(), usage(1, 1, 0), true);
        let mut recorder = RecordingAdapter::new(&mut adapter, "sha256:grammar");
        let request = request();
        recorder.start(&cap(), &request).unwrap();
        let mut events = Vec::new();
        let settlement = loop {
            match recorder.poll() {
                AdapterPoll::Event(event) => events.push(event),
                AdapterPoll::Settled(value) => break value,
                other => panic!("unexpected {other:?}"),
            }
        };
        events.swap(0, 1);
        assert_eq!(
            recorder.observation().replay(&ReplayInputs {
                request: &request,
                events: &events,
                settlement: Some(&settlement),
                failure: None,
                start_refusal: None,
                cancellation: None,
                compiled_grammar_digest: "sha256:grammar"
            }),
            Err(ReplayError::EventMismatch)
        );
        let bad = AdapterSettlement {
            response_bytes: b"ax".to_vec(),
            usage: settlement.usage,
        };
        let good_events = vec![
            AdapterEvent::Delta(b"a".to_vec()),
            AdapterEvent::Delta(b"b".to_vec()),
            AdapterEvent::Completed,
        ];
        assert_eq!(
            recorder.observation().replay(&ReplayInputs {
                request: &request,
                events: &good_events,
                settlement: Some(&bad),
                failure: None,
                start_refusal: None,
                cancellation: None,
                compiled_grammar_digest: "sha256:grammar"
            }),
            Err(ReplayError::SettlementMismatch)
        );
    }

    #[test]
    fn hostile_oversized_delta_is_committed_without_copying_and_replay_fails_before_assembly() {
        let mut adapter = hostile::oversized_chunk_adapter(MAX_REPLAY_RESPONSE_BYTES + 1);
        let mut recorder = RecordingAdapter::new(&mut adapter, "sha256:grammar");
        let request = AdapterRequest {
            request_bytes: b"small request".to_vec(),
            max_response_bytes: MAX_REPLAY_RESPONSE_BYTES + 1,
        };
        recorder.start(&cap(), &request).unwrap();
        let AdapterPoll::Event(event) = recorder.poll() else {
            panic!("hostile adapter must yield its oversized Delta");
        };
        assert!(
            matches!(recorder.observation().events(), [ObservedEvent::Delta(value)] if value.bytes_len() == MAX_REPLAY_RESPONSE_BYTES + 1)
        );
        assert_eq!(
            recorder.observation().replay(&ReplayInputs {
                request: &request,
                events: &[event],
                settlement: None,
                failure: None,
                start_refusal: None,
                cancellation: None,
                compiled_grammar_digest: "sha256:grammar",
            }),
            Err(ReplayError::ResponseTooLarge)
        );
        assert!(matches!(
            recorder.poll(),
            AdapterPoll::Event(AdapterEvent::Completed)
        ));
        assert!(matches!(
            recorder.poll(),
            AdapterPoll::Failed {
                failure: ModelFailure::CapacityExceeded,
                attempted_bytes,
            } if attempted_bytes == MAX_REPLAY_RESPONSE_BYTES + 1
        ));
        assert!(recorder.observation().capture_overflow());
    }

    #[test]
    fn timestamps_are_unknown_without_a_clock_and_only_come_from_an_explicit_clock() {
        struct FixedClock;
        impl AttemptClock for FixedClock {
            fn observed_at_ms(&self) -> Option<u64> {
                Some(41)
            }
        }
        let clock = FixedClock;
        let mut adapter =
            ScriptedStreamingAdapter::new(vec![b"x".to_vec()], b"x".to_vec(), usage(1, 1, 0), true);
        let request = request();
        let mut recorder = RecordingAdapter::with_clock(&mut adapter, "sha256:grammar", &clock);
        recorder.start(&cap(), &request).unwrap();
        while !matches!(recorder.poll(), AdapterPoll::Settled(_)) {}
        assert_eq!(recorder.observation().observed_started_at_ms(), Some(41));
        assert_eq!(recorder.observation().observed_finished_at_ms(), Some(41));

        let mut without_clock =
            ScriptedStreamingAdapter::new(vec![b"x".to_vec()], b"x".to_vec(), usage(1, 1, 0), true);
        let mut recorder = RecordingAdapter::new(&mut without_clock, "sha256:grammar");
        recorder.start(&cap(), &request).unwrap();
        while !matches!(recorder.poll(), AdapterPoll::Settled(_)) {}
        assert_eq!(recorder.observation().observed_started_at_ms(), None);
        assert_eq!(recorder.observation().observed_finished_at_ms(), None);
    }

    #[test]
    fn cancellation_is_committed_not_rendered_and_must_replay_exactly() {
        let mut adapter = ScriptedStreamingAdapter::new(
            vec![b"before-cancel".to_vec()],
            b"before-cancel".to_vec(),
            usage(1, 1, 0),
            true,
        );
        let request = request();
        let mut recorder = RecordingAdapter::new(&mut adapter, "sha256:grammar");
        recorder.start(&cap(), &request).unwrap();
        let first = match recorder.poll() {
            AdapterPoll::Event(event) => event,
            other => panic!("expected first event, got {other:?}"),
        };
        recorder.cancel("private cancellation reason");
        assert!(matches!(
            recorder.poll(),
            AdapterPoll::Failed {
                failure: ModelFailure::Cancelled,
                attempted_bytes: 0,
            }
        ));
        let observation = recorder.observation();
        assert!(!observation.render().contains("private cancellation reason"));
        let exact = ReplayInputs {
            request: &request,
            events: &[first],
            settlement: None,
            failure: Some((ModelFailure::Cancelled, 0)),
            start_refusal: None,
            cancellation: Some(ReplayCancellation {
                first_reason: "private cancellation reason",
                requests: 1,
            }),
            compiled_grammar_digest: "sha256:grammar",
        };
        assert_eq!(observation.replay(&exact), Ok(()));
        let wrong = ReplayInputs {
            cancellation: Some(ReplayCancellation {
                first_reason: "different reason",
                requests: 1,
            }),
            ..exact
        };
        assert_eq!(
            observation.replay(&wrong),
            Err(ReplayError::CancellationMismatch)
        );
    }

    #[test]
    fn failed_start_is_observed_before_the_adapter_can_dispatch() {
        struct Refusing(AdapterCapabilities);
        impl ProviderAdapter for Refusing {
            fn capabilities(&self) -> &AdapterCapabilities {
                &self.0
            }
            fn start(
                &mut self,
                _: &AdapterInvocationCapability,
                _: &AdapterRequest,
            ) -> Result<(), AdapterRefusal> {
                Err(AdapterRefusal("private refusal".to_owned()))
            }
            fn poll(&mut self) -> AdapterPoll {
                panic!("must not poll")
            }
            fn cancel(&mut self, _: &str) {}
        }
        let mut inner = Refusing(super::super::fixture_adapters::base_capabilities(
            "refusing", false,
        ));
        let request = request();
        let mut recorder = RecordingAdapter::new(&mut inner, "sha256:grammar");
        assert!(recorder.start(&cap(), &request).is_err());
        assert!(matches!(
            recorder.observation().terminal(),
            Some(AttemptTerminal::StartRefused(_))
        ));
        assert!(!recorder.observation().render().contains("private refusal"));
    }
}
