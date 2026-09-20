//! Target-neutral, authority-free Agent host-call protocol (#182).
//!
//! This module is deliberately below `authorization`: construction takes the
//! real, opaque [`super::Authorized`] value, so source code, a decoded
//! proposal, and a C/Wasm adapter cannot forge a turn grant.  It is not wired
//! into the iterative driver yet.  That single future adapter must transfer
//! the freshly minted `Authorized` into [`TargetGrant::bind`] and route its
//! injected handler through [`dispatch`]; it must not deserialize a grant or
//! call the handler directly.

use std::panic::{catch_unwind, AssertUnwindSafe};

use sha2::{Digest, Sha256};

use super::{Authorized, AuthorizedRequest};
use crate::agent_runtime::AgentCancellation;

/// Closed, length-framed schema for an admitted target result carrier.
pub const CARRIER_SCHEMA: &str = "semaprax.agent-target-carrier.v1";
/// Schema for an authority-free target execution observation.
pub const EVIDENCE_SCHEMA: &str = "semaprax.agent-target-host-evidence.v1";

const GRANT_DOMAIN: &[u8] = b"semaprax.agent-target-host.grant.v1\0";
const ARGUMENT_DOMAIN: &[u8] = b"semaprax.agent-target-host.argument.v1\0";
const REQUEST_DOMAIN: &[u8] = b"semaprax.agent-target-host.request.v1\0";
const RESULT_DOMAIN: &[u8] = b"semaprax.agent-target-host.result.v1\0";
const EVIDENCE_DOMAIN: &[u8] = b"semaprax.agent-target-host.evidence.v1\0";
const MAX_IDENTIFIER_BYTES: usize = 240;
const MAX_CARRIER_BYTES: usize = 65_536;

/// Exact source-owned operation facts.  A grant is bound to both identities.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TargetOperation {
    operation_id: String,
    effect_id: String,
    argument_type: String,
    result_type: String,
}

impl TargetOperation {
    pub fn new(
        operation_id: impl Into<String>,
        effect_id: impl Into<String>,
        argument_type: impl Into<String>,
        result_type: impl Into<String>,
    ) -> Result<Self, ProtocolError> {
        let value = Self {
            operation_id: operation_id.into(),
            effect_id: effect_id.into(),
            argument_type: argument_type.into(),
            result_type: result_type.into(),
        };
        for identifier in [
            &value.operation_id,
            &value.effect_id,
            &value.argument_type,
            &value.result_type,
        ] {
            validate_identifier(identifier)?;
        }
        Ok(value)
    }

    pub fn operation_id(&self) -> &str {
        &self.operation_id
    }

    pub fn effect_id(&self) -> &str {
        &self.effect_id
    }

    pub fn argument_type(&self) -> &str {
        &self.argument_type
    }

    pub fn result_type(&self) -> &str {
        &self.result_type
    }

    fn canonical(&self, out: &mut Vec<u8>) {
        frame(out, self.operation_id.as_bytes());
        frame(out, self.effect_id.as_bytes());
        frame(out, self.argument_type.as_bytes());
        frame(out, self.result_type.as_bytes());
    }
}

/// A bounded typed carrier.  Its wire is length framed, never a host-selected
/// pointer or a source scalar standing in for nominal type identity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TypedCarrier {
    type_id: String,
    payload: Vec<u8>,
}

impl TypedCarrier {
    pub fn new(type_id: impl Into<String>, payload: Vec<u8>) -> Result<Self, ProtocolError> {
        let value = Self {
            type_id: type_id.into(),
            payload,
        };
        validate_identifier(&value.type_id)?;
        let encoded_len = 3usize
            .checked_mul(std::mem::size_of::<u64>())
            .and_then(|length| length.checked_add(CARRIER_SCHEMA.len()))
            .and_then(|length| length.checked_add(value.type_id.len()))
            .and_then(|length| length.checked_add(value.payload.len()))
            .ok_or(ProtocolError::CarrierTooLarge)?;
        if encoded_len > MAX_CARRIER_BYTES {
            return Err(ProtocolError::CarrierTooLarge);
        }
        Ok(value)
    }

    pub fn type_id(&self) -> &str {
        &self.type_id
    }

    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut bytes =
            Vec::with_capacity(CARRIER_SCHEMA.len() + self.type_id.len() + self.payload.len() + 16);
        frame(&mut bytes, CARRIER_SCHEMA.as_bytes());
        frame(&mut bytes, self.type_id.as_bytes());
        frame(&mut bytes, &self.payload);
        bytes
    }

    /// Independently validates the entire carrier before a result is exposed.
    pub fn decode(bytes: &[u8], expected_type: &str) -> Result<Self, ProtocolError> {
        if bytes.len() > MAX_CARRIER_BYTES {
            return Err(ProtocolError::CarrierTooLarge);
        }
        let mut cursor = 0;
        let schema = take_frame(bytes, &mut cursor)?;
        let type_id = take_frame(bytes, &mut cursor)?;
        let payload = take_frame(bytes, &mut cursor)?;
        if cursor != bytes.len() || schema != CARRIER_SCHEMA.as_bytes() {
            return Err(ProtocolError::MalformedCarrier);
        }
        let type_id = std::str::from_utf8(type_id).map_err(|_| ProtocolError::MalformedCarrier)?;
        validate_identifier(type_id)?;
        if type_id != expected_type {
            return Err(ProtocolError::ResultTypeMismatch);
        }
        let value = Self::new(type_id, payload.to_vec())?;
        if value.encode() != bytes {
            return Err(ProtocolError::MalformedCarrier);
        }
        Ok(value)
    }
}

/// Per-invocation ceilings.  These are checked and reserved before dispatch.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TargetLimits {
    pub max_calls: u64,
    pub max_request_bytes: u64,
    pub max_result_bytes: u64,
    pub max_fuel: u64,
}

/// Cumulative accounting held by the lifecycle driver, never by a target
/// adapter.  A dispatched request remains charged after host/result failure.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct TargetAccounting {
    calls: u64,
    request_bytes: u64,
    result_bytes: u64,
    fuel: u64,
}

impl TargetAccounting {
    pub fn calls(&self) -> u64 {
        self.calls
    }
    pub fn request_bytes(&self) -> u64 {
        self.request_bytes
    }
    pub fn result_bytes(&self) -> u64 {
        self.result_bytes
    }
    pub fn fuel(&self) -> u64 {
        self.fuel
    }

    fn reserve(
        &mut self,
        request_bytes: u64,
        fuel: u64,
        limits: TargetLimits,
    ) -> Result<(), Settlement> {
        let calls = self.calls.checked_add(1).ok_or(Settlement::CallBudget)?;
        let bytes = self
            .request_bytes
            .checked_add(request_bytes)
            .ok_or(Settlement::RequestBudget)?;
        let total_fuel = self
            .fuel
            .checked_add(fuel)
            .ok_or(Settlement::FuelExhausted)?;
        if calls > limits.max_calls {
            return Err(Settlement::CallBudget);
        }
        if bytes > limits.max_request_bytes {
            return Err(Settlement::RequestBudget);
        }
        if total_fuel > limits.max_fuel {
            return Err(Settlement::FuelExhausted);
        }
        self.calls = calls;
        self.request_bytes = bytes;
        self.fuel = total_fuel;
        Ok(())
    }

    fn charge_result(&mut self, raw_bytes: usize, limits: TargetLimits) -> Result<u64, Settlement> {
        let charged = u64::try_from(raw_bytes)
            .unwrap_or(u64::MAX)
            .min(limits.max_result_bytes.saturating_add(1));
        self.result_bytes = self.result_bytes.saturating_add(charged);
        if raw_bytes > usize::try_from(limits.max_result_bytes).unwrap_or(usize::MAX)
            || self.result_bytes > limits.max_result_bytes
        {
            Err(Settlement::ResultBudget)
        } else {
            Ok(charged)
        }
    }
}

/// A target-private, move-only grant.  It cannot be constructed from a
/// binding string, copied into a checkpoint, or reused after `dispatch`.
pub struct TargetGrant {
    grant_id: String,
    authorization_binding: String,
    operation: TargetOperation,
    argument_digest: String,
    turn: u64,
    granted_budget: i64,
}

impl TargetGrant {
    /// Consumes the only real lifecycle grant and binds it to one operation
    /// and invocation turn.  The source-level seal never leaves this module.
    pub(in crate::agent_lifecycle) fn bind(
        authorization: Authorized,
        invocation_root: &str,
        turn: u64,
        operation: TargetOperation,
        argument: &TypedCarrier,
    ) -> Result<Self, ProtocolError> {
        validate_digest(invocation_root)?;
        let request = authorization.consume();
        Ok(Self::bind_request(
            request,
            invocation_root,
            turn,
            operation,
            argument,
        ))
    }

    fn bind_request(
        authorization: AuthorizedRequest,
        invocation_root: &str,
        turn: u64,
        operation: TargetOperation,
        argument: &TypedCarrier,
    ) -> Self {
        let argument_digest = digest(ARGUMENT_DOMAIN, &argument.encode());
        let mut bytes = Vec::new();
        frame(&mut bytes, authorization.binding().as_bytes());
        frame(&mut bytes, authorization.seal());
        frame(&mut bytes, invocation_root.as_bytes());
        frame(&mut bytes, &turn.to_be_bytes());
        operation.canonical(&mut bytes);
        frame(&mut bytes, argument_digest.as_bytes());
        let grant_id = digest(GRANT_DOMAIN, &bytes);
        Self {
            grant_id,
            authorization_binding: authorization.binding().to_owned(),
            operation,
            argument_digest,
            turn,
            granted_budget: authorization.budget(),
        }
    }
}

/// Exact request passed to a target adapter.  It carries no ambient handle,
/// source pointer, seal, capability, or mutable accounting authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TargetHostRequest {
    grant_id: String,
    operation: TargetOperation,
    turn: u64,
    argument: TypedCarrier,
    fuel: u64,
}

impl TargetHostRequest {
    pub fn grant_id(&self) -> &str {
        &self.grant_id
    }
    pub fn operation(&self) -> &TargetOperation {
        &self.operation
    }
    pub fn turn(&self) -> u64 {
        self.turn
    }
    pub fn argument(&self) -> &TypedCarrier {
        &self.argument
    }
    pub fn fuel(&self) -> u64 {
        self.fuel
    }

    fn encode(&self) -> Vec<u8> {
        let argument = self.argument.encode();
        let mut bytes = Vec::with_capacity(argument.len() + 512);
        frame(&mut bytes, self.grant_id.as_bytes());
        self.operation.canonical(&mut bytes);
        frame(&mut bytes, &self.turn.to_be_bytes());
        frame(&mut bytes, &self.fuel.to_be_bytes());
        frame(&mut bytes, &argument);
        bytes
    }
}

/// The only target-specific capability.  Implementations receive a closed
/// request and may return untrusted carrier bytes or a normalized host error.
pub trait TargetHostHandler {
    fn dispatch(&mut self, request: &TargetHostRequest) -> Result<Vec<u8>, TargetHostError>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TargetHostError {
    Unavailable,
    Failed,
}

/// Stable terminal meaning shared by the retained, C11, and Wasm adapters.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Settlement {
    Returned,
    Cancelled,
    GrantBudget,
    CallBudget,
    RequestBudget,
    FuelExhausted,
    ResultBudget,
    HostFailed,
    HostPanicked,
    ArgumentTypeMismatch,
    ArgumentBindingMismatch,
    MalformedResult,
    ResultTypeMismatch,
}

impl Settlement {
    fn text(self) -> &'static str {
        match self {
            Self::Returned => "returned",
            Self::Cancelled => "cancelled",
            Self::GrantBudget => "grant_budget",
            Self::CallBudget => "call_budget",
            Self::RequestBudget => "request_budget",
            Self::FuelExhausted => "fuel_exhausted",
            Self::ResultBudget => "result_budget",
            Self::HostFailed => "host_failed",
            Self::HostPanicked => "host_panicked",
            Self::ArgumentTypeMismatch => "argument_type_mismatch",
            Self::ArgumentBindingMismatch => "argument_binding_mismatch",
            Self::MalformedResult => "malformed_result",
            Self::ResultTypeMismatch => "result_type_mismatch",
        }
    }
}

/// The settled turn result.  A failure never carries a typed result.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TargetDispatch {
    result: Option<TypedCarrier>,
    evidence: TargetEvidence,
}

impl TargetDispatch {
    pub fn result(&self) -> Option<&TypedCarrier> {
        self.result.as_ref()
    }
    pub fn evidence(&self) -> &TargetEvidence {
        &self.evidence
    }
}

/// Common, replayable semantic evidence; it is observational and grants no
/// handler, target execution, checkpoint, or publication authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TargetEvidence {
    grant_id: String,
    authorization_binding: String,
    operation: TargetOperation,
    turn: u64,
    request_digest: String,
    result_digest: Option<String>,
    accounting: TargetAccounting,
    dispatched: bool,
    settlement: Settlement,
    digest: String,
}

impl TargetEvidence {
    pub fn settlement(&self) -> Settlement {
        self.settlement
    }
    pub fn dispatched(&self) -> bool {
        self.dispatched
    }
    pub fn accounting(&self) -> TargetAccounting {
        self.accounting
    }
    pub fn digest(&self) -> &str {
        &self.digest
    }

    /// Independent no-dispatch replay.  It rederives the request commitment
    /// from exact host-visible data and verifies the sealed observation.
    pub fn replay(&self, request: &TargetHostRequest) -> Result<(), ProtocolError> {
        if request.grant_id != self.grant_id
            || request.operation != self.operation
            || request.turn != self.turn
        {
            return Err(ProtocolError::ReplayMismatch);
        }
        if digest(REQUEST_DOMAIN, &request.encode()) != self.request_digest
            || self.digest != self.compute_digest()
        {
            return Err(ProtocolError::ReplayMismatch);
        }
        if !self.dispatched && self.result_digest.is_some() {
            return Err(ProtocolError::ReplayMismatch);
        }
        if self.settlement == Settlement::Returned && self.result_digest.is_none() {
            return Err(ProtocolError::ReplayMismatch);
        }
        Ok(())
    }

    fn compute_digest(&self) -> String {
        let mut bytes = Vec::new();
        frame(&mut bytes, EVIDENCE_SCHEMA.as_bytes());
        frame(&mut bytes, self.grant_id.as_bytes());
        frame(&mut bytes, self.authorization_binding.as_bytes());
        self.operation.canonical(&mut bytes);
        frame(&mut bytes, &self.turn.to_be_bytes());
        frame(&mut bytes, self.request_digest.as_bytes());
        frame(
            &mut bytes,
            self.result_digest.as_deref().unwrap_or("").as_bytes(),
        );
        frame(&mut bytes, &self.accounting.calls.to_be_bytes());
        frame(&mut bytes, &self.accounting.request_bytes.to_be_bytes());
        frame(&mut bytes, &self.accounting.result_bytes.to_be_bytes());
        frame(&mut bytes, &self.accounting.fuel.to_be_bytes());
        frame(&mut bytes, &[u8::from(self.dispatched)]);
        frame(&mut bytes, self.settlement.text().as_bytes());
        digest(EVIDENCE_DOMAIN, &bytes)
    }
}

/// Runs pre-dispatch checks, reserves accounting, performs exactly one injected
/// target call, and normalizes every post-dispatch failure to sticky settlement.
pub(in crate::agent_lifecycle) fn dispatch(
    grant: TargetGrant,
    argument: TypedCarrier,
    fuel: u64,
    limits: TargetLimits,
    accounting: &mut TargetAccounting,
    cancellation: &AgentCancellation,
    handler: &mut dyn TargetHostHandler,
) -> TargetDispatch {
    let request = TargetHostRequest {
        grant_id: grant.grant_id.clone(),
        operation: grant.operation.clone(),
        turn: grant.turn,
        argument,
        fuel,
    };
    let request_digest = digest(REQUEST_DOMAIN, &request.encode());
    let baseline = *accounting;
    if cancellation.is_cancelled() {
        return settled(
            grant,
            request_digest,
            baseline,
            false,
            Settlement::Cancelled,
            None,
            None,
        );
    }
    if request.argument.type_id != request.operation.argument_type {
        return settled(
            grant,
            request_digest,
            baseline,
            false,
            Settlement::ArgumentTypeMismatch,
            None,
            None,
        );
    }
    if digest(ARGUMENT_DOMAIN, &request.argument.encode()) != grant.argument_digest {
        return settled(
            grant,
            request_digest,
            baseline,
            false,
            Settlement::ArgumentBindingMismatch,
            None,
            None,
        );
    }
    if grant.granted_budget < 0 || u64::try_from(grant.granted_budget).unwrap_or(0) < fuel {
        return settled(
            grant,
            request_digest,
            baseline,
            false,
            Settlement::GrantBudget,
            None,
            None,
        );
    }
    if let Err(settlement) = accounting.reserve(request.encode().len() as u64, fuel, limits) {
        return settled(
            grant,
            request_digest,
            baseline,
            false,
            settlement,
            None,
            None,
        );
    }
    let charged = *accounting;
    let raw = match catch_unwind(AssertUnwindSafe(|| handler.dispatch(&request))) {
        Ok(Ok(bytes)) => bytes,
        Ok(Err(_)) => {
            return settled(
                grant,
                request_digest,
                charged,
                true,
                Settlement::HostFailed,
                None,
                None,
            )
        }
        Err(_) => {
            return settled(
                grant,
                request_digest,
                charged,
                true,
                Settlement::HostPanicked,
                None,
                None,
            )
        }
    };
    let result_digest = digest(RESULT_DOMAIN, &raw);
    if let Err(settlement) = accounting.charge_result(raw.len(), limits) {
        return settled(
            grant,
            request_digest,
            *accounting,
            true,
            settlement,
            None,
            Some(result_digest),
        );
    }
    match TypedCarrier::decode(&raw, request.operation.result_type()) {
        Ok(result) => settled(
            grant,
            request_digest,
            *accounting,
            true,
            Settlement::Returned,
            Some(result),
            Some(result_digest),
        ),
        Err(ProtocolError::ResultTypeMismatch) => settled(
            grant,
            request_digest,
            *accounting,
            true,
            Settlement::ResultTypeMismatch,
            None,
            Some(result_digest),
        ),
        Err(_) => settled(
            grant,
            request_digest,
            *accounting,
            true,
            Settlement::MalformedResult,
            None,
            Some(result_digest),
        ),
    }
}

fn settled(
    grant: TargetGrant,
    request_digest: String,
    accounting: TargetAccounting,
    dispatched: bool,
    settlement: Settlement,
    result: Option<TypedCarrier>,
    result_digest: Option<String>,
) -> TargetDispatch {
    let mut evidence = TargetEvidence {
        grant_id: grant.grant_id,
        authorization_binding: grant.authorization_binding,
        operation: grant.operation,
        turn: grant.turn,
        request_digest,
        result_digest,
        accounting,
        dispatched,
        settlement,
        digest: String::new(),
    };
    evidence.digest = evidence.compute_digest();
    TargetDispatch { result, evidence }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProtocolError {
    InvalidIdentifier,
    InvalidDigest,
    CarrierTooLarge,
    MalformedCarrier,
    ResultTypeMismatch,
    ReplayMismatch,
}

fn validate_identifier(value: &str) -> Result<(), ProtocolError> {
    if value.is_empty()
        || value.len() > MAX_IDENTIFIER_BYTES
        || value
            .bytes()
            .any(|byte| !(byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-')))
    {
        Err(ProtocolError::InvalidIdentifier)
    } else {
        Ok(())
    }
}

fn validate_digest(value: &str) -> Result<(), ProtocolError> {
    if value.len() == 71
        && value.starts_with("sha256:")
        && value[7..]
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        Ok(())
    } else {
        Err(ProtocolError::InvalidDigest)
    }
}

fn frame(out: &mut Vec<u8>, value: &[u8]) {
    out.extend_from_slice(&(value.len() as u64).to_be_bytes());
    out.extend_from_slice(value);
}

fn take_frame<'a>(input: &'a [u8], cursor: &mut usize) -> Result<&'a [u8], ProtocolError> {
    let end = cursor
        .checked_add(8)
        .ok_or(ProtocolError::MalformedCarrier)?;
    let length = input
        .get(*cursor..end)
        .ok_or(ProtocolError::MalformedCarrier)?;
    *cursor = end;
    let size = usize::try_from(u64::from_be_bytes(
        length
            .try_into()
            .map_err(|_| ProtocolError::MalformedCarrier)?,
    ))
    .map_err(|_| ProtocolError::MalformedCarrier)?;
    let end = cursor
        .checked_add(size)
        .ok_or(ProtocolError::MalformedCarrier)?;
    let value = input
        .get(*cursor..end)
        .ok_or(ProtocolError::MalformedCarrier)?;
    *cursor = end;
    Ok(value)
}

fn digest(domain: &[u8], bytes: &[u8]) -> String {
    let mut hash = Sha256::new();
    hash.update(domain);
    hash.update(bytes);
    format!("sha256:{:x}", crate::digest_hex::LowerHex(hash.finalize()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn operation() -> TargetOperation {
        TargetOperation::new(
            "fixture.agent.effect.read",
            "read",
            "fixture.Argument",
            "fixture.Result",
        )
        .unwrap()
    }

    fn carrier(type_id: &str, payload: &[u8]) -> TypedCarrier {
        TypedCarrier::new(type_id, payload.to_vec()).unwrap()
    }

    fn limits() -> TargetLimits {
        TargetLimits {
            max_calls: 1,
            max_request_bytes: 4096,
            max_result_bytes: 1024,
            max_fuel: 20,
        }
    }

    fn request() -> AuthorizedRequest {
        AuthorizedRequest {
            binding: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                .into(),
            budget: 10,
            seal: b"seal".to_vec(),
        }
    }

    fn grant() -> TargetGrant {
        TargetGrant::bind_request(
            request(),
            "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            3,
            operation(),
            &carrier("fixture.Argument", b"request"),
        )
    }

    struct Handler {
        calls: usize,
        response: Result<Vec<u8>, TargetHostError>,
    }
    impl TargetHostHandler for Handler {
        fn dispatch(&mut self, _: &TargetHostRequest) -> Result<Vec<u8>, TargetHostError> {
            self.calls += 1;
            self.response.clone()
        }
    }

    #[test]
    fn exact_typed_result_is_dispatched_once_and_evidence_replays_without_host_work() {
        let response = carrier("fixture.Result", b"ok").encode();
        let mut handler = Handler {
            calls: 0,
            response: Ok(response),
        };
        let mut accounting = TargetAccounting::default();
        let run = dispatch(
            grant(),
            carrier("fixture.Argument", b"request"),
            4,
            limits(),
            &mut accounting,
            &AgentCancellation::new(),
            &mut handler,
        );
        assert_eq!(handler.calls, 1);
        assert_eq!(run.evidence().settlement(), Settlement::Returned);
        assert_eq!(run.result().unwrap().payload(), b"ok");
        assert_eq!(run.evidence().accounting().calls(), 1);
        let request = TargetHostRequest {
            grant_id: run.evidence().grant_id.clone(),
            operation: operation(),
            turn: 3,
            argument: carrier("fixture.Argument", b"request"),
            fuel: 4,
        };
        run.evidence().replay(&request).unwrap();
        assert_eq!(
            handler.calls, 1,
            "evidence replay has no dispatch authority"
        );
    }

    #[test]
    fn cancellation_call_budget_fuel_and_grant_budget_refuse_before_host_dispatch() {
        let cases = [
            (true, limits(), 4, 10, Settlement::Cancelled),
            (
                false,
                TargetLimits {
                    max_calls: 0,
                    ..limits()
                },
                4,
                10,
                Settlement::CallBudget,
            ),
            (
                false,
                TargetLimits {
                    max_fuel: 3,
                    ..limits()
                },
                4,
                10,
                Settlement::FuelExhausted,
            ),
            (
                false,
                TargetLimits {
                    max_request_bytes: 1,
                    ..limits()
                },
                4,
                10,
                Settlement::RequestBudget,
            ),
            (false, limits(), 11, 10, Settlement::GrantBudget),
        ];
        for (cancelled, limits, fuel, budget, expected) in cases {
            let mut handler = Handler {
                calls: 0,
                response: Ok(carrier("fixture.Result", b"ok").encode()),
            };
            let mut accounting = TargetAccounting::default();
            let cancellation = AgentCancellation::new();
            if cancelled {
                cancellation.cancel();
            }
            let mut grant = grant();
            grant.granted_budget = budget;
            let run = dispatch(
                grant,
                carrier("fixture.Argument", b"request"),
                fuel,
                limits,
                &mut accounting,
                &cancellation,
                &mut handler,
            );
            assert_eq!(run.evidence().settlement(), expected);
            assert!(!run.evidence().dispatched());
            assert_eq!(handler.calls, 0);
        }

        let mut handler = Handler {
            calls: 0,
            response: Ok(carrier("fixture.Result", b"ok").encode()),
        };
        let mut accounting = TargetAccounting::default();
        let run = dispatch(
            grant(),
            carrier("fixture.OtherArgument", b"request"),
            4,
            limits(),
            &mut accounting,
            &AgentCancellation::new(),
            &mut handler,
        );
        assert_eq!(
            run.evidence().settlement(),
            Settlement::ArgumentTypeMismatch
        );
        assert_eq!(handler.calls, 0);
    }

    #[test]
    fn same_typed_argument_substitution_is_refused_before_dispatch() {
        let mut handler = Handler {
            calls: 0,
            response: Ok(carrier("fixture.Result", b"ok").encode()),
        };
        let mut accounting = TargetAccounting::default();
        let run = dispatch(
            grant(),
            carrier("fixture.Argument", b"substituted"),
            4,
            limits(),
            &mut accounting,
            &AgentCancellation::new(),
            &mut handler,
        );
        assert_eq!(handler.calls, 0);
        assert_eq!(accounting, TargetAccounting::default());
        assert_eq!(
            run.evidence().settlement(),
            Settlement::ArgumentBindingMismatch
        );
    }

    #[test]
    fn malformed_wrong_type_and_oversized_results_are_sticky_charged_and_stop_at_host_boundary() {
        let malformed = vec![0, 1, 2];
        let wrong_type = carrier("fixture.Other", b"wrong").encode();
        let oversized = vec![42; 1025];
        for (response, expected) in [
            (malformed, Settlement::MalformedResult),
            (wrong_type, Settlement::ResultTypeMismatch),
            (oversized, Settlement::ResultBudget),
        ] {
            let mut handler = Handler {
                calls: 0,
                response: Ok(response),
            };
            let mut accounting = TargetAccounting::default();
            let run = dispatch(
                grant(),
                carrier("fixture.Argument", b"request"),
                4,
                limits(),
                &mut accounting,
                &AgentCancellation::new(),
                &mut handler,
            );
            assert_eq!(run.evidence().settlement(), expected);
            assert!(run.evidence().dispatched());
            assert!(run.result().is_none());
            assert_eq!(handler.calls, 1);
            assert_eq!(
                run.evidence().accounting().calls(),
                1,
                "host work remains charged"
            );
        }
    }

    #[test]
    fn hostile_carrier_frames_and_forged_evidence_do_not_replay() {
        let valid = carrier("fixture.Result", b"ok").encode();
        let mut duplicate = valid.clone();
        duplicate.extend_from_slice(&valid);
        assert_eq!(
            TypedCarrier::decode(&duplicate, "fixture.Result"),
            Err(ProtocolError::MalformedCarrier)
        );

        let mut handler = Handler {
            calls: 0,
            response: Ok(valid),
        };
        let mut accounting = TargetAccounting::default();
        let run = dispatch(
            grant(),
            carrier("fixture.Argument", b"request"),
            4,
            limits(),
            &mut accounting,
            &AgentCancellation::new(),
            &mut handler,
        );
        let mut forged = run.evidence().clone();
        forged.dispatched = false;
        let request = TargetHostRequest {
            grant_id: forged.grant_id.clone(),
            operation: operation(),
            turn: 3,
            argument: carrier("fixture.Argument", b"request"),
            fuel: 4,
        };
        assert_eq!(forged.replay(&request), Err(ProtocolError::ReplayMismatch));
        assert_eq!(handler.calls, 1);
    }

    #[test]
    fn carrier_limit_applies_to_the_complete_wire_not_only_its_payload() {
        let type_id = "app.types.Result";
        let overhead = 3 * std::mem::size_of::<u64>() + CARRIER_SCHEMA.len() + type_id.len();
        let exact = TypedCarrier::new(type_id, vec![0; MAX_CARRIER_BYTES - overhead]).unwrap();
        assert_eq!(exact.encode().len(), MAX_CARRIER_BYTES);
        assert_eq!(
            TypedCarrier::new(type_id, vec![0; MAX_CARRIER_BYTES - overhead + 1]),
            Err(ProtocolError::CarrierTooLarge)
        );
    }

    #[test]
    fn host_failure_is_sticky_after_reservation() {
        let mut handler = Handler {
            calls: 0,
            response: Err(TargetHostError::Unavailable),
        };
        let mut accounting = TargetAccounting::default();
        let run = dispatch(
            grant(),
            carrier("fixture.Argument", b"request"),
            4,
            limits(),
            &mut accounting,
            &AgentCancellation::new(),
            &mut handler,
        );
        assert_eq!(run.evidence().settlement(), Settlement::HostFailed);
        assert!(run.evidence().dispatched());
        assert_eq!(run.evidence().accounting().calls(), 1);
        assert_eq!(run.evidence().accounting().result_bytes(), 0);
    }
}
