//! Bounded source-model request protocol for target-parity execution.
//!
//! The protocol turns the live lifecycle's checked [`driver::ProposalRequest`]
//! into one canonical, authority-free host request. The injected host can
//! return only bounded UTF-8 proposal bytes. A private move-only grant is
//! consumed at dispatch, so request/evidence bytes cannot be replayed into a
//! second model call.

use std::panic::{catch_unwind, AssertUnwindSafe};

use sha2::{Digest, Sha256};

use super::driver::{ProposalRequest, ProposalSource};
use crate::agent_lifecycle::canonical_retained_value_json;
use crate::agent_runtime::AgentCancellation;
use crate::diagnostic::{quote_json, Diagnostic};

pub const REQUEST_SCHEMA: &str = "semaprax.agent-model-host-request.v1";
pub const EVIDENCE_SCHEMA: &str = "semaprax.agent-model-host-evidence.v1";

const GRANT_DOMAIN: &[u8] = b"semaprax.agent-model-host.grant.v1\0";
const REQUEST_DOMAIN: &[u8] = b"semaprax.agent-model-host.request.v1\0";
const RESPONSE_DOMAIN: &[u8] = b"semaprax.agent-model-host.response.v1\0";
const EVIDENCE_DOMAIN: &[u8] = b"semaprax.agent-model-host.evidence.v1\0";
const TARGET_BINDING_DOMAIN: &[u8] = b"semaprax.agent-model-host.target-execution-binding.v1\0";
const MAX_FIELD_BYTES: usize = 65_536;
const MAX_WIRE_BYTES: usize = 1_048_576;

fn diagnostic(field: &str) -> Vec<Diagnostic> {
    vec![Diagnostic::io(
        "SPX-G582",
        format!("Agent iterative lifecycle invariant failed: model.{field}"),
    )]
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ModelLimits {
    pub max_calls: u64,
    pub max_request_bytes: u64,
    pub max_response_bytes: u64,
    pub max_total_bytes: u64,
    pub max_fuel: u64,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ModelAccounting {
    calls: u64,
    request_bytes: u64,
    response_bytes: u64,
    fuel: u64,
}

impl ModelAccounting {
    pub fn calls(self) -> u64 {
        self.calls
    }
    pub fn request_bytes(self) -> u64 {
        self.request_bytes
    }
    pub fn response_bytes(self) -> u64 {
        self.response_bytes
    }
    pub fn fuel(self) -> u64 {
        self.fuel
    }

    fn reserve(
        &mut self,
        request_bytes: usize,
        limits: ModelLimits,
    ) -> Result<(), ModelSettlement> {
        let request_bytes =
            u64::try_from(request_bytes).map_err(|_| ModelSettlement::RequestBudget)?;
        let calls = self
            .calls
            .checked_add(1)
            .ok_or(ModelSettlement::CallBudget)?;
        let requests = self
            .request_bytes
            .checked_add(request_bytes)
            .ok_or(ModelSettlement::RequestBudget)?;
        let fuel = self
            .fuel
            .checked_add(1)
            .ok_or(ModelSettlement::FuelExhausted)?;
        if calls > limits.max_calls {
            return Err(ModelSettlement::CallBudget);
        }
        if request_bytes > limits.max_request_bytes || requests > limits.max_request_bytes {
            return Err(ModelSettlement::RequestBudget);
        }
        if requests
            .checked_add(self.response_bytes)
            .is_none_or(|v| v > limits.max_total_bytes)
        {
            return Err(ModelSettlement::RequestBudget);
        }
        if fuel > limits.max_fuel {
            return Err(ModelSettlement::FuelExhausted);
        }
        self.calls = calls;
        self.request_bytes = requests;
        self.fuel = fuel;
        Ok(())
    }

    fn charge_response(
        &mut self,
        bytes: usize,
        limits: ModelLimits,
    ) -> Result<(), ModelSettlement> {
        let charged = u64::try_from(bytes).unwrap_or(u64::MAX);
        self.response_bytes = self.response_bytes.saturating_add(charged);
        if charged > limits.max_response_bytes
            || self.response_bytes > limits.max_response_bytes
            || self
                .request_bytes
                .checked_add(self.response_bytes)
                .is_none_or(|v| v > limits.max_total_bytes)
        {
            Err(ModelSettlement::ResponseBudget)
        } else {
            Ok(())
        }
    }
}

/// Host-selected deterministic root for one injected model source. It is a
/// binding label, not provider, network, credential, or retry authority.
pub struct ModelSourceBinding {
    root: String,
    execution_binding: Option<String>,
}

impl ModelSourceBinding {
    pub fn new(root: impl Into<String>) -> Result<Self, ModelProtocolError> {
        let root = root.into();
        validate_text(&root)?;
        Ok(Self {
            root,
            execution_binding: None,
        })
    }

    /// Local target-parity binding. It is descriptive proof data, not a
    /// provider capability: the model host remains the explicitly injected
    /// handler owned by [`TargetModelSource`].
    pub(in crate::agent_lifecycle) fn for_target(
        root: impl Into<String>,
        program_binding: &str,
        backend: &str,
    ) -> Result<Self, ModelProtocolError> {
        let root = root.into();
        validate_text(&root)?;
        validate_digest(program_binding)?;
        validate_text(backend)?;
        let execution_binding = digest(
            TARGET_BINDING_DOMAIN,
            format!("{}\0{}\0{}", root, program_binding, backend).as_bytes(),
        );
        Ok(Self {
            root,
            execution_binding: Some(execution_binding),
        })
    }
}

struct ModelGrant {
    grant_id: String,
}

impl ModelGrant {
    fn bind(binding: &ModelSourceBinding, request_without_grant: &[u8]) -> Self {
        let mut bytes = Vec::new();
        frame(&mut bytes, binding.root.as_bytes());
        if let Some(execution_binding) = &binding.execution_binding {
            frame(&mut bytes, execution_binding.as_bytes());
        }
        frame(&mut bytes, request_without_grant);
        Self {
            grant_id: digest(GRANT_DOMAIN, &bytes),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ModelHostRequest {
    grant_id: String,
    turn: u64,
    attempt: u64,
    source_revision: String,
    proposal_schema_digest: String,
    remaining_iterations: u64,
    context: Vec<u8>,
}

impl ModelHostRequest {
    pub fn grant_id(&self) -> &str {
        &self.grant_id
    }
    pub fn turn(&self) -> u64 {
        self.turn
    }
    pub fn attempt(&self) -> u64 {
        self.attempt
    }
    pub fn proposal_schema_digest(&self) -> &str {
        &self.proposal_schema_digest
    }
    pub fn context(&self) -> &[u8] {
        &self.context
    }

    pub fn canonical_wire(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(self.context.len() + 512);
        frame(&mut bytes, REQUEST_SCHEMA.as_bytes());
        frame(&mut bytes, self.grant_id.as_bytes());
        frame(&mut bytes, &self.turn.to_be_bytes());
        frame(&mut bytes, &self.attempt.to_be_bytes());
        frame(&mut bytes, self.source_revision.as_bytes());
        frame(&mut bytes, self.proposal_schema_digest.as_bytes());
        frame(&mut bytes, &self.remaining_iterations.to_be_bytes());
        frame(&mut bytes, &self.context);
        bytes
    }

    fn without_grant_wire(
        turn: u64,
        attempt: u64,
        source_revision: &str,
        proposal_schema_digest: &str,
        remaining_iterations: u64,
        context: &[u8],
    ) -> Vec<u8> {
        let mut bytes = Vec::new();
        frame(&mut bytes, &turn.to_be_bytes());
        frame(&mut bytes, &attempt.to_be_bytes());
        frame(&mut bytes, source_revision.as_bytes());
        frame(&mut bytes, proposal_schema_digest.as_bytes());
        frame(&mut bytes, &remaining_iterations.to_be_bytes());
        frame(&mut bytes, context);
        bytes
    }

    fn decode(bytes: &[u8]) -> Result<Self, ModelProtocolError> {
        if bytes.len() > MAX_WIRE_BYTES {
            return Err(ModelProtocolError::MalformedRequest);
        }
        let mut cursor = 0;
        let schema = take(bytes, &mut cursor)?;
        let grant_id = text(take(bytes, &mut cursor)?)?;
        let turn = number(take(bytes, &mut cursor)?)?;
        let attempt = number(take(bytes, &mut cursor)?)?;
        let source_revision = text(take(bytes, &mut cursor)?)?;
        let proposal_schema_digest = text(take(bytes, &mut cursor)?)?;
        let remaining_iterations = number(take(bytes, &mut cursor)?)?;
        let context = take(bytes, &mut cursor)?.to_vec();
        if cursor != bytes.len() || schema != REQUEST_SCHEMA.as_bytes() {
            return Err(ModelProtocolError::MalformedRequest);
        }
        validate_digest(&grant_id).map_err(|_| ModelProtocolError::MalformedRequest)?;
        validate_text(&source_revision).map_err(|_| ModelProtocolError::MalformedRequest)?;
        validate_text(&proposal_schema_digest).map_err(|_| ModelProtocolError::MalformedRequest)?;
        let value = Self {
            grant_id,
            turn,
            attempt,
            source_revision,
            proposal_schema_digest,
            remaining_iterations,
            context,
        };
        if value.canonical_wire() != bytes {
            return Err(ModelProtocolError::MalformedRequest);
        }
        Ok(value)
    }
}

pub trait ModelHostHandler {
    fn dispatch(
        &mut self,
        request: &ModelHostRequest,
        response: &mut ModelResponseSink,
    ) -> Result<(), ModelHostError>;
}

pub struct ModelResponseSink {
    bytes: Vec<u8>,
    limit: usize,
    overflowed: bool,
}

impl ModelResponseSink {
    fn new(limit: usize) -> Self {
        Self {
            bytes: Vec::with_capacity(limit.min(4096)),
            limit,
            overflowed: false,
        }
    }

    pub fn write(&mut self, bytes: &[u8]) -> Result<(), ModelResponseOverflow> {
        if self.overflowed
            || self
                .bytes
                .len()
                .checked_add(bytes.len())
                .is_none_or(|n| n > self.limit)
        {
            self.overflowed = true;
            return Err(ModelResponseOverflow);
        }
        self.bytes.extend_from_slice(bytes);
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ModelResponseOverflow;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ModelHostError {
    Failed,
    Unavailable,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ModelSettlement {
    Returned,
    Cancelled,
    CallBudget,
    RequestBudget,
    ResponseBudget,
    FuelExhausted,
    HostFailed,
    HostPanicked,
    MalformedResponse,
}

impl ModelSettlement {
    fn text(self) -> &'static str {
        match self {
            Self::Returned => "returned",
            Self::Cancelled => "cancelled",
            Self::CallBudget => "call_budget",
            Self::RequestBudget => "request_budget",
            Self::ResponseBudget => "response_budget",
            Self::FuelExhausted => "fuel_exhausted",
            Self::HostFailed => "host_failed",
            Self::HostPanicked => "host_panicked",
            Self::MalformedResponse => "malformed_response",
        }
    }

    fn parse(value: &str) -> Option<Self> {
        Some(match value {
            "returned" => Self::Returned,
            "cancelled" => Self::Cancelled,
            "call_budget" => Self::CallBudget,
            "request_budget" => Self::RequestBudget,
            "response_budget" => Self::ResponseBudget,
            "fuel_exhausted" => Self::FuelExhausted,
            "host_failed" => Self::HostFailed,
            "host_panicked" => Self::HostPanicked,
            "malformed_response" => Self::MalformedResponse,
            _ => return None,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ModelEvidence {
    grant_id: String,
    turn: u64,
    attempt: u64,
    request_digest: String,
    response_digest: Option<String>,
    accounting: ModelAccounting,
    dispatched: bool,
    settlement: ModelSettlement,
    digest: String,
}

impl ModelEvidence {
    pub fn grant_id(&self) -> &str {
        &self.grant_id
    }

    pub fn settlement(&self) -> ModelSettlement {
        self.settlement
    }
    pub fn dispatched(&self) -> bool {
        self.dispatched
    }
    pub fn accounting(&self) -> ModelAccounting {
        self.accounting
    }
    pub fn digest(&self) -> &str {
        &self.digest
    }

    pub fn canonical_wire(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        frame(&mut bytes, EVIDENCE_SCHEMA.as_bytes());
        frame(&mut bytes, self.grant_id.as_bytes());
        frame(&mut bytes, &self.turn.to_be_bytes());
        frame(&mut bytes, &self.attempt.to_be_bytes());
        frame(&mut bytes, self.request_digest.as_bytes());
        frame(
            &mut bytes,
            self.response_digest.as_deref().unwrap_or("").as_bytes(),
        );
        frame(&mut bytes, &self.accounting.calls.to_be_bytes());
        frame(&mut bytes, &self.accounting.request_bytes.to_be_bytes());
        frame(&mut bytes, &self.accounting.response_bytes.to_be_bytes());
        frame(&mut bytes, &self.accounting.fuel.to_be_bytes());
        frame(&mut bytes, &[u8::from(self.dispatched)]);
        frame(&mut bytes, self.settlement.text().as_bytes());
        bytes
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, ModelProtocolError> {
        if bytes.len() > MAX_WIRE_BYTES {
            return Err(ModelProtocolError::MalformedEvidence);
        }
        let mut cursor = 0;
        let schema = take(bytes, &mut cursor)?;
        let grant_id = text(take(bytes, &mut cursor)?)?;
        let turn = number(take(bytes, &mut cursor)?)?;
        let attempt = number(take(bytes, &mut cursor)?)?;
        let request_digest = text(take(bytes, &mut cursor)?)?;
        let response = text(take(bytes, &mut cursor)?)?;
        let calls = number(take(bytes, &mut cursor)?)?;
        let request_bytes = number(take(bytes, &mut cursor)?)?;
        let response_bytes = number(take(bytes, &mut cursor)?)?;
        let fuel = number(take(bytes, &mut cursor)?)?;
        let dispatched = take(bytes, &mut cursor)?;
        let settlement = text(take(bytes, &mut cursor)?)?;
        if cursor != bytes.len() || schema != EVIDENCE_SCHEMA.as_bytes() || dispatched.len() != 1 {
            return Err(ModelProtocolError::MalformedEvidence);
        }
        validate_digest(&grant_id).map_err(|_| ModelProtocolError::MalformedEvidence)?;
        validate_digest(&request_digest).map_err(|_| ModelProtocolError::MalformedEvidence)?;
        let response_digest = if response.is_empty() {
            None
        } else {
            validate_digest(&response).map_err(|_| ModelProtocolError::MalformedEvidence)?;
            Some(response)
        };
        let dispatched = match dispatched[0] {
            0 => false,
            1 => true,
            _ => return Err(ModelProtocolError::MalformedEvidence),
        };
        let settlement =
            ModelSettlement::parse(&settlement).ok_or(ModelProtocolError::MalformedEvidence)?;
        let mut value = Self {
            grant_id,
            turn,
            attempt,
            request_digest,
            response_digest,
            accounting: ModelAccounting {
                calls,
                request_bytes,
                response_bytes,
                fuel,
            },
            dispatched,
            settlement,
            digest: String::new(),
        };
        value
            .validate()
            .map_err(|_| ModelProtocolError::MalformedEvidence)?;
        value.digest = value.compute_digest();
        if value.canonical_wire() != bytes {
            return Err(ModelProtocolError::MalformedEvidence);
        }
        Ok(value)
    }

    pub fn replay_wire(&self, request_wire: &[u8]) -> Result<(), ModelProtocolError> {
        let request = ModelHostRequest::decode(request_wire)?;
        if request.grant_id != self.grant_id
            || request.turn != self.turn
            || request.attempt != self.attempt
            || digest(REQUEST_DOMAIN, request_wire) != self.request_digest
            || self.compute_digest() != self.digest
        {
            return Err(ModelProtocolError::ReplayMismatch);
        }
        self.validate()
    }

    /// Replay the exact request/response exchange without acquiring a model
    /// grant or invoking a model host.
    ///
    /// A response is mandatory exactly when the evidence commits one. Besides
    /// checking its domain-separated digest, replay rechecks the selected
    /// settlement's UTF-8 meaning so a fabricated observation cannot label
    /// arbitrary bytes as a returned proposal or a malformed response.
    pub fn replay_exchange_wire(
        &self,
        request_wire: &[u8],
        response_wire: Option<&[u8]>,
    ) -> Result<(), ModelProtocolError> {
        self.replay_wire(request_wire)?;
        match (self.response_digest.as_deref(), response_wire) {
            (None, None) => return Ok(()),
            (Some(expected), Some(response))
                if response.len() <= MAX_FIELD_BYTES
                    && digest(RESPONSE_DOMAIN, response) == expected => {}
            _ => return Err(ModelProtocolError::ReplayMismatch),
        }

        let response = response_wire.expect("matched committed model response bytes");
        let shape_matches = match self.settlement {
            ModelSettlement::Returned => std::str::from_utf8(response).is_ok(),
            ModelSettlement::MalformedResponse => std::str::from_utf8(response).is_err(),
            _ => false,
        };
        if shape_matches {
            Ok(())
        } else {
            Err(ModelProtocolError::ReplayMismatch)
        }
    }

    fn validate(&self) -> Result<(), ModelProtocolError> {
        let predispatch = matches!(
            self.settlement,
            ModelSettlement::Cancelled
                | ModelSettlement::CallBudget
                | ModelSettlement::RequestBudget
                | ModelSettlement::FuelExhausted
        );
        let response_expected = matches!(
            self.settlement,
            ModelSettlement::Returned | ModelSettlement::MalformedResponse
        );
        if predispatch == self.dispatched || response_expected != self.response_digest.is_some() {
            return Err(ModelProtocolError::ReplayMismatch);
        }
        Ok(())
    }

    fn compute_digest(&self) -> String {
        digest(EVIDENCE_DOMAIN, &self.canonical_wire())
    }
}

/// Proposal source that crosses exactly one injected model host boundary per
/// lifecycle request and retains its canonical request/evidence pairs.
pub struct TargetModelSource<'a> {
    binding: ModelSourceBinding,
    limits: ModelLimits,
    accounting: ModelAccounting,
    cancellation: &'a AgentCancellation,
    handler: &'a mut dyn ModelHostHandler,
    requests: Vec<Vec<u8>>,
    evidence: Vec<ModelEvidence>,
}

impl<'a> TargetModelSource<'a> {
    pub fn new(
        binding: ModelSourceBinding,
        limits: ModelLimits,
        cancellation: &'a AgentCancellation,
        handler: &'a mut dyn ModelHostHandler,
    ) -> Self {
        Self {
            binding,
            limits,
            accounting: ModelAccounting::default(),
            cancellation,
            handler,
            requests: Vec::new(),
            evidence: Vec::new(),
        }
    }

    pub fn accounting(&self) -> ModelAccounting {
        self.accounting
    }
    pub fn request_wires(&self) -> &[Vec<u8>] {
        &self.requests
    }
    pub fn evidence(&self) -> &[ModelEvidence] {
        &self.evidence
    }

    fn request(
        request: &ProposalRequest<'_>,
        binding: &ModelSourceBinding,
    ) -> Result<(ModelGrant, ModelHostRequest), ModelProtocolError> {
        let turn = u64::try_from(request.turn).map_err(|_| ModelProtocolError::Capacity)?;
        let attempt = u64::try_from(request.attempt).map_err(|_| ModelProtocolError::Capacity)?;
        let remaining = u64::try_from(request.remaining_iterations)
            .map_err(|_| ModelProtocolError::Capacity)?;
        validate_text(request.source_revision)?;
        validate_text(request.proposal_schema_digest)?;
        let context = format!(
            "{{\"task_budget\":{},\"task_objective\":{},\"state\":{},\"observation\":{},\"previous_effect\":{},\"previous_rejection\":{}}}\n",
            request.task.budget,
            hex(&request.task.objective),
            canonical_retained_value_json(request.state),
            canonical_retained_value_json(request.observation),
            request.previous_effect.map(hex).unwrap_or_else(|| "null".into()),
            request.previous_rejection.map(json).unwrap_or_else(|| "null".into()),
        ).into_bytes();
        if context.len() > MAX_FIELD_BYTES {
            return Err(ModelProtocolError::Capacity);
        }
        let unbound = ModelHostRequest::without_grant_wire(
            turn,
            attempt,
            request.source_revision,
            request.proposal_schema_digest,
            remaining,
            &context,
        );
        let grant = ModelGrant::bind(binding, &unbound);
        let host = ModelHostRequest {
            grant_id: grant.grant_id.clone(),
            turn,
            attempt,
            source_revision: request.source_revision.to_owned(),
            proposal_schema_digest: request.proposal_schema_digest.to_owned(),
            remaining_iterations: remaining,
            context,
        };
        if host.canonical_wire().len() > MAX_WIRE_BYTES {
            return Err(ModelProtocolError::Capacity);
        }
        Ok((grant, host))
    }

    fn settle(
        &mut self,
        request: &ModelHostRequest,
        settlement: ModelSettlement,
        dispatched: bool,
        response: Option<&[u8]>,
    ) {
        let mut evidence = ModelEvidence {
            grant_id: request.grant_id.clone(),
            turn: request.turn,
            attempt: request.attempt,
            request_digest: digest(REQUEST_DOMAIN, &request.canonical_wire()),
            response_digest: response.map(|bytes| digest(RESPONSE_DOMAIN, bytes)),
            accounting: self.accounting,
            dispatched,
            settlement,
            digest: String::new(),
        };
        evidence.digest = evidence.compute_digest();
        self.requests.push(request.canonical_wire());
        self.evidence.push(evidence);
    }
}

impl ProposalSource for TargetModelSource<'_> {
    fn check_deadline(&self) -> Result<(), Vec<Diagnostic>> {
        if self.cancellation.is_cancelled() {
            Err(diagnostic("cancelled"))
        } else {
            Ok(())
        }
    }

    fn propose(&mut self, request: ProposalRequest<'_>) -> Result<String, Vec<Diagnostic>> {
        let (grant, host_request) =
            Self::request(&request, &self.binding).map_err(|_| diagnostic("request"))?;
        // Destructuring consumes the private grant before the one host call;
        // no request/evidence bytes can reconstruct this value.
        let ModelGrant { grant_id } = grant;
        debug_assert_eq!(grant_id, host_request.grant_id);
        if self.cancellation.is_cancelled() {
            self.settle(&host_request, ModelSettlement::Cancelled, false, None);
            return Err(diagnostic("cancelled"));
        }
        if let Err(settlement) = self
            .accounting
            .reserve(host_request.canonical_wire().len(), self.limits)
        {
            self.settle(&host_request, settlement, false, None);
            return Err(diagnostic(settlement.text()));
        }
        let limit = usize::try_from(self.limits.max_response_bytes)
            .unwrap_or(usize::MAX)
            .min(MAX_FIELD_BYTES);
        let mut sink = ModelResponseSink::new(limit);
        let outcome = catch_unwind(AssertUnwindSafe(|| {
            self.handler.dispatch(&host_request, &mut sink)
        }));
        match outcome {
            Err(_) => {
                self.settle(&host_request, ModelSettlement::HostPanicked, true, None);
                Err(diagnostic("host_panicked"))
            }
            Ok(Err(_)) => {
                self.settle(&host_request, ModelSettlement::HostFailed, true, None);
                Err(diagnostic("host_failed"))
            }
            Ok(Ok(())) if sink.overflowed => {
                self.accounting
                    .charge_response(limit.saturating_add(1), self.limits)
                    .ok();
                self.settle(&host_request, ModelSettlement::ResponseBudget, true, None);
                Err(diagnostic("response_budget"))
            }
            Ok(Ok(())) => {
                if let Err(settlement) = self
                    .accounting
                    .charge_response(sink.bytes.len(), self.limits)
                {
                    self.settle(&host_request, settlement, true, None);
                    return Err(diagnostic(settlement.text()));
                }
                let proposal = match String::from_utf8(sink.bytes) {
                    Ok(value) => value,
                    Err(error) => {
                        let bytes = error.into_bytes();
                        self.settle(
                            &host_request,
                            ModelSettlement::MalformedResponse,
                            true,
                            Some(&bytes),
                        );
                        return Err(diagnostic("malformed_response"));
                    }
                };
                self.settle(
                    &host_request,
                    ModelSettlement::Returned,
                    true,
                    Some(proposal.as_bytes()),
                );
                Ok(proposal)
            }
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ModelProtocolError {
    Capacity,
    MalformedRequest,
    MalformedEvidence,
    ReplayMismatch,
}

fn frame(out: &mut Vec<u8>, value: &[u8]) {
    out.extend_from_slice(&(value.len() as u64).to_be_bytes());
    out.extend_from_slice(value);
}

fn take<'a>(input: &'a [u8], cursor: &mut usize) -> Result<&'a [u8], ModelProtocolError> {
    if input.len().saturating_sub(*cursor) < 8 {
        return Err(ModelProtocolError::MalformedRequest);
    }
    let mut length = [0u8; 8];
    length.copy_from_slice(&input[*cursor..*cursor + 8]);
    *cursor += 8;
    let length =
        usize::try_from(u64::from_be_bytes(length)).map_err(|_| ModelProtocolError::Capacity)?;
    if length > MAX_FIELD_BYTES || input.len().saturating_sub(*cursor) < length {
        return Err(ModelProtocolError::MalformedRequest);
    }
    let value = &input[*cursor..*cursor + length];
    *cursor += length;
    Ok(value)
}

fn text(bytes: &[u8]) -> Result<String, ModelProtocolError> {
    std::str::from_utf8(bytes)
        .map(str::to_owned)
        .map_err(|_| ModelProtocolError::MalformedRequest)
}

fn number(bytes: &[u8]) -> Result<u64, ModelProtocolError> {
    let value: [u8; 8] = bytes
        .try_into()
        .map_err(|_| ModelProtocolError::MalformedRequest)?;
    Ok(u64::from_be_bytes(value))
}

fn validate_text(value: &str) -> Result<(), ModelProtocolError> {
    if value.is_empty() || value.len() > MAX_FIELD_BYTES || value.bytes().any(|b| b == 0) {
        Err(ModelProtocolError::Capacity)
    } else {
        Ok(())
    }
}

fn validate_digest(value: &str) -> Result<(), ModelProtocolError> {
    if value.len() == 71
        && value.starts_with("sha256:")
        && value[7..]
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    {
        Ok(())
    } else {
        Err(ModelProtocolError::MalformedRequest)
    }
}

fn digest(domain: &[u8], bytes: &[u8]) -> String {
    let mut hash = Sha256::new();
    hash.update(domain);
    hash.update(bytes);
    format!("sha256:{:x}", crate::digest_hex::LowerHex(hash.finalize()))
}

fn hex(bytes: &[u8]) -> String {
    let mut value = String::with_capacity(bytes.len() * 2 + 2);
    value.push('"');
    for byte in bytes {
        value.push_str(&format!("{byte:02x}"));
    }
    value.push('"');
    value
}

fn json(value: &str) -> String {
    quote_json(value)
}

#[cfg(test)]
mod replay_tests {
    use super::*;

    fn request() -> ModelHostRequest {
        ModelHostRequest {
            grant_id: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                .into(),
            turn: 3,
            attempt: 1,
            source_revision: "fixture.source".into(),
            proposal_schema_digest: "fixture.proposal".into(),
            remaining_iterations: 4,
            context: b"context".to_vec(),
        }
    }

    fn evidence(
        request: &ModelHostRequest,
        response: Option<&[u8]>,
        settlement: ModelSettlement,
        dispatched: bool,
    ) -> ModelEvidence {
        let mut evidence = ModelEvidence {
            grant_id: request.grant_id.clone(),
            turn: request.turn,
            attempt: request.attempt,
            request_digest: digest(REQUEST_DOMAIN, &request.canonical_wire()),
            response_digest: response.map(|bytes| digest(RESPONSE_DOMAIN, bytes)),
            accounting: ModelAccounting {
                calls: u64::from(dispatched),
                request_bytes: if dispatched {
                    request.canonical_wire().len() as u64
                } else {
                    0
                },
                response_bytes: response.map_or(0, |bytes| bytes.len() as u64),
                fuel: u64::from(dispatched),
            },
            dispatched,
            settlement,
            digest: String::new(),
        };
        evidence.digest = evidence.compute_digest();
        evidence
    }

    #[test]
    fn exchange_replay_binds_exact_response_bytes_and_settlement_shape() {
        let request = request();
        let request_wire = request.canonical_wire();
        let returned = evidence(&request, Some(b"proposal"), ModelSettlement::Returned, true);
        returned
            .replay_exchange_wire(&request_wire, Some(b"proposal"))
            .unwrap();
        assert_eq!(
            returned.replay_exchange_wire(&request_wire, Some(b"changed")),
            Err(ModelProtocolError::ReplayMismatch)
        );
        assert_eq!(
            returned.replay_exchange_wire(&request_wire, None),
            Err(ModelProtocolError::ReplayMismatch)
        );

        let malformed = evidence(
            &request,
            Some(&[0xff]),
            ModelSettlement::MalformedResponse,
            true,
        );
        malformed
            .replay_exchange_wire(&request_wire, Some(&[0xff]))
            .unwrap();

        // Matching digests are insufficient if the claimed settlement does
        // not agree with the exact response's UTF-8 meaning.
        let mislabeled = evidence(&request, Some(&[0xff]), ModelSettlement::Returned, true);
        assert_eq!(
            mislabeled.replay_exchange_wire(&request_wire, Some(&[0xff])),
            Err(ModelProtocolError::ReplayMismatch)
        );

        let cancelled = evidence(&request, None, ModelSettlement::Cancelled, false);
        cancelled.replay_exchange_wire(&request_wire, None).unwrap();
        assert_eq!(
            cancelled.replay_exchange_wire(&request_wire, Some(b"unexpected")),
            Err(ModelProtocolError::ReplayMismatch)
        );
    }
}
