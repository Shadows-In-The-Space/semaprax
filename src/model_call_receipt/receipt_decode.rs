//! Bounded, independent decoding of the canonical Model Call Receipt v1.
//!
//! The receipt type intentionally has a small construction surface but no
//! wire decoder. This module is the inverse boundary for retained bytes: it
//! parses into the existing public type, validates the fields which can be
//! checked without retained payloads, and finally requires the bytes to equal
//! [`ModelCallReceipt::render`] byte for byte. The final comparison rejects
//! unknown, duplicate, reordered, whitespace-padded, and otherwise
//! non-canonical JSON without relying on `serde_json`'s duplicate-key policy.

use serde_json::{Map, Value};

use super::receipt::{ModelCallReceipt, ProviderReportedUsage, ReceiptStage, RECEIPT_SCHEMA};

/// Maximum accepted canonical receipt size.
pub const MAX_RECEIPT_BYTES: usize = 65_536;
/// Maximum UTF-8 byte length of any individual receipt string.
pub const MAX_RECEIPT_STRING_BYTES: usize = 4_096;

/// Why [`decode_receipt`] refused retained bytes. The error deliberately
/// reports a stable category and field, never echoes untrusted input.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DecodeError {
    TooLarge,
    InvalidJson,
    ExpectedObject,
    MissingField(&'static str),
    WrongType(&'static str),
    InvalidString(&'static str),
    InvalidDigest(&'static str),
    InvalidNumber(&'static str),
    NegativeValue(&'static str),
    InvalidLifecycle(&'static str),
    NonCanonical,
}

/// Decodes one canonical `semaprax.model-call-receipt.v1` document.
///
/// This function never accepts an extension field or silently normalizes
/// JSON. It also does not recompute payload commitments: that requires the
/// caller-held bytes and belongs to [`super::replay::replay_receipt`].
pub fn decode_receipt(bytes: &[u8]) -> Result<ModelCallReceipt, DecodeError> {
    if bytes.len() > MAX_RECEIPT_BYTES {
        return Err(DecodeError::TooLarge);
    }
    let value: Value = serde_json::from_slice(bytes).map_err(|_| DecodeError::InvalidJson)?;
    let object = value.as_object().ok_or(DecodeError::ExpectedObject)?;

    // Keep this explicit list in canonical field order. The rendered-byte
    // comparison below catches duplicates and reordering; this set also
    // makes the accepted object vocabulary apparent and future additions
    // fail closed until the schema is deliberately extended.
    const FIELDS: &[&str] = &[
        "schema",
        "agent_id",
        "program_root",
        "deployment_root",
        "instance_root",
        "invocation_id",
        "turn",
        "attempt",
        "model_class",
        "provider_class",
        "adapter_identity",
        "proposal_grammar_digest",
        "deployment_policy_digest",
        "task_digest",
        "observation_digest",
        "request_digest",
        "request_bytes_len",
        "reserved_budget",
        "response_digest",
        "response_bytes_len",
        "private_payload_reference",
        "terminal_stage",
        "failure",
        "proposal_digest",
        "proposal_refusal_reason",
        "reserved_at_ms",
        "dispatched_at_ms",
        "first_byte_at_ms",
        "completed_at_ms",
        "local_request_bytes",
        "local_response_bytes",
        "cost_estimate_micros",
        "provider_call_reference",
        "provider_reported",
    ];
    if object.len() != FIELDS.len() || FIELDS.iter().any(|field| !object.contains_key(*field)) {
        return Err(DecodeError::NonCanonical);
    }
    if object.keys().any(|field| !FIELDS.contains(&field.as_str())) {
        return Err(DecodeError::NonCanonical);
    }

    let schema = required_string(object, "schema")?;
    if schema != RECEIPT_SCHEMA {
        return Err(DecodeError::InvalidLifecycle("schema"));
    }
    let agent_id = required_string(object, "agent_id")?;
    let program_root = required_string(object, "program_root")?;
    let deployment_root = required_string(object, "deployment_root")?;
    let instance_root = required_string(object, "instance_root")?;
    // Invocation and root associations are bounded opaque bindings here;
    // some legacy callers use stable labels while generic identity producers
    // use a digest. Commitment fields below are always strict digests.
    let invocation_id = required_string(object, "invocation_id")?;
    let turn = required_u64(object, "turn")?;
    let attempt = required_u64(object, "attempt")?;
    if attempt == 0 {
        return Err(DecodeError::InvalidNumber("attempt"));
    }
    let model_class = required_string(object, "model_class")?;
    let provider_class = required_string(object, "provider_class")?;
    let adapter_identity = required_string(object, "adapter_identity")?;
    let proposal_grammar_digest = required_digest(object, "proposal_grammar_digest")?;
    // The deployment policy binding is intentionally opaque in receipt v1;
    // its owning live-invocation contract permits labels such as
    // `sha256:policy` as well as real digests.
    let deployment_policy_digest = required_string(object, "deployment_policy_digest")?;
    let task_digest = required_digest(object, "task_digest")?;
    let observation_digest = required_digest(object, "observation_digest")?;
    let request_digest = required_digest(object, "request_digest")?;
    let request_bytes_len = required_usize(object, "request_bytes_len")?;
    let reserved_budget = required_nonnegative_i64(object, "reserved_budget")?;
    let response_digest = optional_digest(object, "response_digest")?;
    let response_bytes_len = optional_usize(object, "response_bytes_len")?;
    let private_payload_reference = optional_string(object, "private_payload_reference")?;
    let terminal_stage = parse_stage(required_string(object, "terminal_stage")?)?;
    let failure = optional_string(object, "failure")?;
    let proposal_digest = optional_digest(object, "proposal_digest")?;
    let proposal_refusal_reason = optional_string(object, "proposal_refusal_reason")?;
    let reserved_at_ms = required_u64(object, "reserved_at_ms")?;
    let dispatched_at_ms = optional_u64(object, "dispatched_at_ms")?;
    let first_byte_at_ms = optional_u64(object, "first_byte_at_ms")?;
    let completed_at_ms = optional_u64(object, "completed_at_ms")?;
    let local_request_bytes = required_usize(object, "local_request_bytes")?;
    let local_response_bytes = required_usize(object, "local_response_bytes")?;
    let cost_estimate_micros = required_nonnegative_i64(object, "cost_estimate_micros")?;
    let provider_call_reference = required_string(object, "provider_call_reference")?;
    let provider_reported = optional_provider_report(object, "provider_reported")?;
    if provider_reported
        .as_ref()
        .is_some_and(|reported| reported.provider_call_id != provider_call_reference)
    {
        return Err(DecodeError::InvalidLifecycle("provider_call_reference"));
    }

    validate_timestamps(
        reserved_at_ms,
        dispatched_at_ms,
        first_byte_at_ms,
        completed_at_ms,
    )?;
    validate_lifecycle(
        terminal_stage,
        response_digest.is_some(),
        response_bytes_len.is_some(),
        proposal_digest.is_some(),
        proposal_refusal_reason.is_some(),
    )?;

    let receipt = ModelCallReceipt {
        agent_id,
        program_root,
        deployment_root,
        instance_root,
        invocation_id,
        turn: u32::try_from(turn).map_err(|_| DecodeError::InvalidNumber("turn"))?,
        attempt: u32::try_from(attempt).map_err(|_| DecodeError::InvalidNumber("attempt"))?,
        model_class,
        provider_class,
        adapter_identity,
        proposal_grammar_digest,
        deployment_policy_digest,
        task_digest,
        observation_digest,
        request_digest,
        request_bytes_len,
        reserved_budget,
        response_digest,
        response_bytes_len,
        private_payload_reference,
        terminal_stage,
        failure,
        proposal_digest,
        proposal_refusal_reason,
        reserved_at_ms,
        dispatched_at_ms,
        first_byte_at_ms,
        completed_at_ms,
        local_request_bytes,
        local_response_bytes,
        cost_estimate_micros,
        provider_call_reference,
        provider_reported,
    };
    if receipt.render().as_bytes() != bytes {
        return Err(DecodeError::NonCanonical);
    }
    Ok(receipt)
}

fn value<'a>(
    object: &'a Map<String, Value>,
    field: &'static str,
) -> Result<&'a Value, DecodeError> {
    object.get(field).ok_or(DecodeError::MissingField(field))
}

fn required_string(
    object: &Map<String, Value>,
    field: &'static str,
) -> Result<String, DecodeError> {
    let value = value(object, field)?;
    let string = value.as_str().ok_or(DecodeError::WrongType(field))?;
    validate_string(string, field)?;
    Ok(string.to_owned())
}

fn required_digest(
    object: &Map<String, Value>,
    field: &'static str,
) -> Result<String, DecodeError> {
    let digest = required_string(object, field)?;
    if !crate::live_invocation::identity::looks_like_digest(&digest) {
        return Err(DecodeError::InvalidDigest(field));
    }
    Ok(digest)
}

fn optional_string(
    object: &Map<String, Value>,
    field: &'static str,
) -> Result<Option<String>, DecodeError> {
    match value(object, field)? {
        Value::Null => Ok(None),
        Value::String(string) => {
            validate_string(string, field)?;
            Ok(Some(string.clone()))
        }
        _ => Err(DecodeError::WrongType(field)),
    }
}

fn optional_digest(
    object: &Map<String, Value>,
    field: &'static str,
) -> Result<Option<String>, DecodeError> {
    let digest = optional_string(object, field)?;
    if digest
        .as_deref()
        .is_some_and(|value| !crate::live_invocation::identity::looks_like_digest(value))
    {
        return Err(DecodeError::InvalidDigest(field));
    }
    Ok(digest)
}

fn validate_string(string: &str, field: &'static str) -> Result<(), DecodeError> {
    if string.is_empty() || string.len() > MAX_RECEIPT_STRING_BYTES {
        return Err(DecodeError::InvalidString(field));
    }
    Ok(())
}

fn required_u64(object: &Map<String, Value>, field: &'static str) -> Result<u64, DecodeError> {
    value(object, field)?
        .as_u64()
        .ok_or(DecodeError::InvalidNumber(field))
}

fn optional_u64(
    object: &Map<String, Value>,
    field: &'static str,
) -> Result<Option<u64>, DecodeError> {
    match value(object, field)? {
        Value::Null => Ok(None),
        value => value
            .as_u64()
            .map(Some)
            .ok_or(DecodeError::InvalidNumber(field)),
    }
}

fn required_usize(object: &Map<String, Value>, field: &'static str) -> Result<usize, DecodeError> {
    usize::try_from(required_u64(object, field)?).map_err(|_| DecodeError::InvalidNumber(field))
}

fn optional_usize(
    object: &Map<String, Value>,
    field: &'static str,
) -> Result<Option<usize>, DecodeError> {
    optional_u64(object, field)?
        .map(|value| usize::try_from(value).map_err(|_| DecodeError::InvalidNumber(field)))
        .transpose()
}

fn required_nonnegative_i64(
    object: &Map<String, Value>,
    field: &'static str,
) -> Result<i64, DecodeError> {
    let number = value(object, field)?
        .as_i64()
        .ok_or(DecodeError::InvalidNumber(field))?;
    if number < 0 {
        return Err(DecodeError::NegativeValue(field));
    }
    Ok(number)
}

fn parse_stage(stage: String) -> Result<ReceiptStage, DecodeError> {
    let parsed = match stage.as_str() {
        "reserved" => ReceiptStage::Reserved,
        "intent_persisted" => ReceiptStage::IntentPersisted,
        "dispatched" => ReceiptStage::Dispatched,
        "first_byte" => ReceiptStage::FirstByte,
        "completed" => ReceiptStage::Completed,
        "decoded" => ReceiptStage::Decoded,
        "accepted" => ReceiptStage::Accepted,
        "rejected" => ReceiptStage::Rejected,
        "cancelled" => ReceiptStage::Cancelled,
        "uncertain" => ReceiptStage::Uncertain,
        "reconciled" => ReceiptStage::Reconciled,
        _ => return Err(DecodeError::InvalidLifecycle("terminal_stage")),
    };
    Ok(parsed)
}

fn optional_provider_report(
    object: &Map<String, Value>,
    field: &'static str,
) -> Result<Option<ProviderReportedUsage>, DecodeError> {
    let Value::Object(report) = value(object, field)? else {
        if value(object, field)? == &Value::Null {
            return Ok(None);
        }
        return Err(DecodeError::WrongType(field));
    };
    const FIELDS: &[&str] = &[
        "provider_call_id",
        "tokens_in",
        "tokens_out",
        "provider_cost_micros",
    ];
    if report.len() != FIELDS.len() || report.keys().any(|key| !FIELDS.contains(&key.as_str())) {
        return Err(DecodeError::NonCanonical);
    }
    let provider_call_id = required_string(report, "provider_call_id")?;
    let tokens_in = required_u64(report, "tokens_in")?;
    let tokens_out = required_u64(report, "tokens_out")?;
    let provider_cost_micros = required_nonnegative_i64(report, "provider_cost_micros")?;
    Ok(Some(ProviderReportedUsage {
        provider_call_id,
        tokens_in,
        tokens_out,
        provider_cost_micros,
    }))
}

fn validate_timestamps(
    reserved: u64,
    dispatched: Option<u64>,
    first_byte: Option<u64>,
    completed: Option<u64>,
) -> Result<(), DecodeError> {
    let mut previous = reserved;
    for (field, value) in [
        ("dispatched_at_ms", dispatched),
        ("first_byte_at_ms", first_byte),
        ("completed_at_ms", completed),
    ] {
        if let Some(value) = value {
            if value < previous {
                return Err(DecodeError::InvalidLifecycle(field));
            }
            previous = value;
        }
    }
    Ok(())
}

fn validate_lifecycle(
    stage: ReceiptStage,
    has_response_digest: bool,
    has_response_length: bool,
    has_proposal_digest: bool,
    has_refusal: bool,
) -> Result<(), DecodeError> {
    if has_response_digest != has_response_length {
        return Err(DecodeError::InvalidLifecycle("response"));
    }
    if has_proposal_digest && has_refusal {
        return Err(DecodeError::InvalidLifecycle("proposal_outcome"));
    }
    if (has_proposal_digest || has_refusal) && !has_response_digest {
        return Err(DecodeError::InvalidLifecycle("proposal_response"));
    }
    if stage.is_settled() && !has_response_digest {
        return Err(DecodeError::InvalidLifecycle("settled_response"));
    }
    if stage == ReceiptStage::Decoded && !has_proposal_digest {
        return Err(DecodeError::InvalidLifecycle("decoded_outcome"));
    }
    if stage == ReceiptStage::Accepted && !has_proposal_digest {
        return Err(DecodeError::InvalidLifecycle("accepted_proposal"));
    }
    if stage == ReceiptStage::Rejected && !has_refusal {
        return Err(DecodeError::InvalidLifecycle("rejected_proposal"));
    }
    Ok(())
}

#[cfg(test)]
mod tests;
