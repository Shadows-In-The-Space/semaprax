//! Additive v2 wrapper for generic priced-I/O evidence.
//!
//! The exact v1 priced document is carried as canonical bytes, so neither the
//! accepted v1 envelope nor the frozen causal journal needs a field mutation.

use crate::diagnostic::quote_json;

use super::super::identity::{unhex, LiveInvocationId};
use super::super::io::{
    GenericIoAccounting, GenericIoAttempt, GenericIoHandoff, GenericIoLimits, GenericIoTotals,
};
use super::super::journal::JournalEntry;
use super::super::journal::MAX_JOURNAL_ENTRIES;
use super::super::model_invoke::{digest_canonical_request, ModelInvocationRequest};
use super::super::priced::PricedSuccessorHandoff;
use super::{
    encode_priced_envelope_with_handoff, recover_priced_journal, PricedRecoveryError,
    RecoveredPricedJournal,
};

use serde_json::Value;

pub const PERSISTED_PRICED_IO_JOURNAL_SCHEMA: &str =
    "semaprax.live-invocation.persisted-priced-io-journal.v2";

pub(crate) struct RecoveredPricedIoJournal {
    pub(crate) priced: RecoveredPricedJournal,
    pub(crate) io: GenericIoAccounting,
}

pub(crate) fn encode_priced_io_envelope(
    invocation: &str,
    generation: u64,
    journal: &[JournalEntry],
    accounting: &crate::live_invocation::pricing::MonetaryAccounting,
    handoff: Option<&PricedSuccessorHandoff>,
    io: &GenericIoAccounting,
) -> Result<String, PricedRecoveryError> {
    let priced =
        encode_priced_envelope_with_handoff(invocation, generation, journal, accounting, handoff)?;
    validate_paired_handoffs(handoff, io.handoff())?;
    validate_io_against_journal(io, journal)?;
    Ok(format!(
        "{{\"schema\":{},\"priced_document\":{},\"io\":{}}}\n",
        quote_json(PERSISTED_PRICED_IO_JOURNAL_SCHEMA),
        quote_json(&priced),
        render_io(io),
    ))
}

pub(crate) fn recover_priced_io_journal(
    document: &str,
    identity: &LiveInvocationId,
) -> Result<RecoveredPricedIoJournal, PricedRecoveryError> {
    let value: Value =
        serde_json::from_str(document).map_err(|_| PricedRecoveryError::Malformed)?;
    let object = value.as_object().ok_or(PricedRecoveryError::Malformed)?;
    const KEYS: [&str; 3] = ["schema", "priced_document", "io"];
    if object.len() != KEYS.len() || !KEYS.iter().all(|key| object.contains_key(*key)) {
        return Err(PricedRecoveryError::Malformed);
    }
    if object["schema"].as_str() != Some(PERSISTED_PRICED_IO_JOURNAL_SCHEMA) {
        return Err(PricedRecoveryError::SchemaMismatch);
    }
    let priced_document = object["priced_document"]
        .as_str()
        .ok_or(PricedRecoveryError::Malformed)?;
    let priced = recover_priced_journal(priced_document, identity)?;
    let io = decode_io(&object["io"], identity.digest())?;
    validate_paired_handoffs(priced.handoff.as_ref(), io.handoff())?;
    validate_io_against_journal(&io, &priced.entries)?;
    if document
        != encode_priced_io_envelope(
            identity.digest(),
            priced.generation,
            &priced.entries,
            &priced.accounting,
            priced.handoff.as_ref(),
            &io,
        )?
    {
        return Err(PricedRecoveryError::Malformed);
    }
    Ok(RecoveredPricedIoJournal { priced, io })
}

/// The priced-I/O successor is a single migration. Its monetary and I/O
/// carries have independent contents, but must name the same immutable
/// predecessor generation and journal chain. A sidecar cannot splice either
/// carry from a different completed invocation.
fn validate_paired_handoffs(
    monetary: Option<&PricedSuccessorHandoff>,
    io: Option<&GenericIoHandoff>,
) -> Result<(), PricedRecoveryError> {
    match (monetary, io) {
        (None, None) => Ok(()),
        (Some(monetary), Some(io))
            if monetary.predecessor_invocation == io.predecessor_invocation
                && monetary.destination_invocation == io.destination_invocation
                && monetary.predecessor_generation == io.predecessor_generation
                && monetary.predecessor_chain == io.predecessor_chain =>
        {
            Ok(())
        }
        _ => Err(PricedRecoveryError::Pricing),
    }
}

fn render_io(io: &GenericIoAccounting) -> String {
    let limits = io.limits();
    let carry = io.carry();
    let attempts = io
        .attempts()
        .iter()
        .map(|attempt| {
            format!(
                "{{\"turn\":{},\"request_digest\":{},\"canonical_request\":{},\"request_bytes\":{},\"response_limit\":{},\"observed_response_bytes\":{}}}",
                attempt.turn,
                quote_json(&attempt.request_digest),
                quote_json(&attempt.canonical_request),
                attempt.request_bytes,
                attempt.response_limit,
                attempt
                    .observed_response_bytes
                    .map_or_else(|| "null".to_owned(), |value| value.to_string()),
            )
        })
        .collect::<Vec<_>>()
        .join(",");
    format!(
        "{{\"limits\":{{\"max_request_bytes\":{},\"max_total_request_bytes\":{},\"max_total_response_bytes\":{}}},\"carry\":{{\"reserved_request_bytes\":{},\"reserved_response_bytes\":{},\"observed_response_bytes\":{},\"unknown_response_reservation_bytes\":{}}},\"handoff\":{},\"attempts\":[{}]}}",
        limits.max_request_bytes,
        limits.max_total_request_bytes,
        limits.max_total_response_bytes,
        carry.reserved_request_bytes,
        carry.reserved_response_bytes,
        carry.observed_response_bytes,
        carry.unknown_response_reservation_bytes,
        render_handoff(io.handoff()),
        attempts,
    )
}

fn decode_io(
    value: &Value,
    destination_invocation: &str,
) -> Result<GenericIoAccounting, PricedRecoveryError> {
    let object = value.as_object().ok_or(PricedRecoveryError::Malformed)?;
    const KEYS: [&str; 4] = ["limits", "carry", "handoff", "attempts"];
    if object.len() != KEYS.len() || !KEYS.iter().all(|key| object.contains_key(*key)) {
        return Err(PricedRecoveryError::Malformed);
    }
    let limits = decode_limits(&object["limits"])?;
    let carry = decode_totals(&object["carry"])?;
    let values = object["attempts"]
        .as_array()
        .ok_or(PricedRecoveryError::Malformed)?;
    if values.len() > MAX_JOURNAL_ENTRIES {
        return Err(PricedRecoveryError::Malformed);
    }
    let mut attempts = Vec::with_capacity(values.len());
    for value in values {
        let object = value.as_object().ok_or(PricedRecoveryError::Malformed)?;
        const KEYS: [&str; 6] = [
            "turn",
            "request_digest",
            "canonical_request",
            "request_bytes",
            "response_limit",
            "observed_response_bytes",
        ];
        if object.len() != KEYS.len() || !KEYS.iter().all(|key| object.contains_key(*key)) {
            return Err(PricedRecoveryError::Malformed);
        }
        attempts.push(GenericIoAttempt {
            turn: u32::try_from(
                object["turn"]
                    .as_u64()
                    .ok_or(PricedRecoveryError::Malformed)?,
            )
            .map_err(|_| PricedRecoveryError::Malformed)?,
            request_digest: object["request_digest"]
                .as_str()
                .ok_or(PricedRecoveryError::Malformed)?
                .to_owned(),
            canonical_request: object["canonical_request"]
                .as_str()
                .ok_or(PricedRecoveryError::Malformed)?
                .to_owned(),
            request_bytes: usize::try_from(
                object["request_bytes"]
                    .as_u64()
                    .ok_or(PricedRecoveryError::Malformed)?,
            )
            .map_err(|_| PricedRecoveryError::Malformed)?,
            response_limit: usize::try_from(
                object["response_limit"]
                    .as_u64()
                    .ok_or(PricedRecoveryError::Malformed)?,
            )
            .map_err(|_| PricedRecoveryError::Malformed)?,
            observed_response_bytes: match &object["observed_response_bytes"] {
                Value::Null => None,
                value => Some(
                    usize::try_from(value.as_u64().ok_or(PricedRecoveryError::Malformed)?)
                        .map_err(|_| PricedRecoveryError::Malformed)?,
                ),
            },
        });
    }
    let handoff = decode_handoff(&object["handoff"], destination_invocation, &limits, &carry)?;
    GenericIoAccounting::from_parts(limits, carry, attempts, handoff)
        .map_err(|_| PricedRecoveryError::Pricing)
}

fn render_handoff(handoff: Option<&GenericIoHandoff>) -> String {
    let Some(handoff) = handoff else {
        return "null".to_owned();
    };
    let limits = &handoff.predecessor_limits;
    let totals = &handoff.predecessor_totals;
    format!(
        "{{\"predecessor_invocation\":{},\"destination_invocation\":{},\"predecessor_generation\":{},\"predecessor_chain\":{},\"limits\":{{\"max_request_bytes\":{},\"max_total_request_bytes\":{},\"max_total_response_bytes\":{}}},\"totals\":{{\"reserved_request_bytes\":{},\"reserved_response_bytes\":{},\"observed_response_bytes\":{},\"unknown_response_reservation_bytes\":{}}},\"handoff_digest\":{}}}",
        quote_json(&handoff.predecessor_invocation), quote_json(&handoff.destination_invocation),
        handoff.predecessor_generation, quote_json(&handoff.predecessor_chain),
        limits.max_request_bytes, limits.max_total_request_bytes, limits.max_total_response_bytes,
        totals.reserved_request_bytes, totals.reserved_response_bytes,
        totals.observed_response_bytes, totals.unknown_response_reservation_bytes,
        quote_json(&handoff.handoff_digest),
    )
}

fn decode_handoff(
    value: &Value,
    destination_invocation: &str,
    destination_limits: &GenericIoLimits,
    carry: &GenericIoTotals,
) -> Result<Option<GenericIoHandoff>, PricedRecoveryError> {
    if value.is_null() {
        return Ok(None);
    }
    let object = value.as_object().ok_or(PricedRecoveryError::Malformed)?;
    const KEYS: [&str; 7] = [
        "predecessor_invocation",
        "destination_invocation",
        "predecessor_generation",
        "predecessor_chain",
        "limits",
        "totals",
        "handoff_digest",
    ];
    if object.len() != KEYS.len() || !KEYS.iter().all(|key| object.contains_key(*key)) {
        return Err(PricedRecoveryError::Malformed);
    }
    let handoff = GenericIoHandoff {
        predecessor_invocation: object["predecessor_invocation"]
            .as_str()
            .ok_or(PricedRecoveryError::Malformed)?
            .to_owned(),
        destination_invocation: object["destination_invocation"]
            .as_str()
            .ok_or(PricedRecoveryError::Malformed)?
            .to_owned(),
        predecessor_generation: object["predecessor_generation"]
            .as_u64()
            .ok_or(PricedRecoveryError::Malformed)?,
        predecessor_chain: object["predecessor_chain"]
            .as_str()
            .ok_or(PricedRecoveryError::Malformed)?
            .to_owned(),
        predecessor_limits: decode_limits(&object["limits"])?,
        predecessor_totals: decode_totals(&object["totals"])?,
        handoff_digest: object["handoff_digest"]
            .as_str()
            .ok_or(PricedRecoveryError::Malformed)?
            .to_owned(),
    };
    handoff
        .validates(destination_invocation, destination_limits, carry)
        .then_some(Some(handoff))
        .ok_or(PricedRecoveryError::Pricing)
}

fn decode_limits(value: &Value) -> Result<GenericIoLimits, PricedRecoveryError> {
    let object = value.as_object().ok_or(PricedRecoveryError::Malformed)?;
    const KEYS: [&str; 3] = [
        "max_request_bytes",
        "max_total_request_bytes",
        "max_total_response_bytes",
    ];
    if object.len() != KEYS.len() || !KEYS.iter().all(|key| object.contains_key(*key)) {
        return Err(PricedRecoveryError::Malformed);
    }
    Ok(GenericIoLimits {
        max_request_bytes: usize::try_from(
            object["max_request_bytes"]
                .as_u64()
                .ok_or(PricedRecoveryError::Malformed)?,
        )
        .map_err(|_| PricedRecoveryError::Malformed)?,
        max_total_request_bytes: object["max_total_request_bytes"]
            .as_u64()
            .ok_or(PricedRecoveryError::Malformed)?,
        max_total_response_bytes: object["max_total_response_bytes"]
            .as_u64()
            .ok_or(PricedRecoveryError::Malformed)?,
    })
}

fn decode_totals(value: &Value) -> Result<GenericIoTotals, PricedRecoveryError> {
    let object = value.as_object().ok_or(PricedRecoveryError::Malformed)?;
    const KEYS: [&str; 4] = [
        "reserved_request_bytes",
        "reserved_response_bytes",
        "observed_response_bytes",
        "unknown_response_reservation_bytes",
    ];
    if object.len() != KEYS.len() || !KEYS.iter().all(|key| object.contains_key(*key)) {
        return Err(PricedRecoveryError::Malformed);
    }
    Ok(GenericIoTotals {
        reserved_request_bytes: object["reserved_request_bytes"]
            .as_u64()
            .ok_or(PricedRecoveryError::Malformed)?,
        reserved_response_bytes: object["reserved_response_bytes"]
            .as_u64()
            .ok_or(PricedRecoveryError::Malformed)?,
        observed_response_bytes: object["observed_response_bytes"]
            .as_u64()
            .ok_or(PricedRecoveryError::Malformed)?,
        unknown_response_reservation_bytes: object["unknown_response_reservation_bytes"]
            .as_u64()
            .ok_or(PricedRecoveryError::Malformed)?,
    })
}

fn validate_io_against_journal(
    io: &GenericIoAccounting,
    journal: &[JournalEntry],
) -> Result<(), PricedRecoveryError> {
    let intents = journal
        .iter()
        .filter_map(|entry| match entry {
            JournalEntry::RequestIntent {
                turn,
                request_digest,
                reserved_budget,
                ..
            } if *reserved_budget > 0 => Some((*turn, request_digest)),
            _ => None,
        })
        .collect::<Vec<_>>();
    if intents.len() != io.attempts().len()
        || intents
            .iter()
            .zip(io.attempts())
            .any(|((turn, digest), attempt)| {
                turn != &attempt.turn
                    || digest.as_str() != attempt.request_digest.as_str()
                    || digest_canonical_request(&attempt.canonical_request).as_str()
                        != attempt.request_digest.as_str()
                    || attempt.canonical_request.len() != attempt.request_bytes
            })
    {
        return Err(PricedRecoveryError::Pricing);
    }
    for attempt in io.attempts() {
        validate_canonical_request(attempt)?;
        let response = journal.iter().find_map(|entry| match entry {
            JournalEntry::ResponseRecorded { turn, response, .. } if *turn == attempt.turn => {
                Some(Some(response.len()))
            }
            JournalEntry::ResponseFailed { turn, .. } if *turn == attempt.turn => Some(None),
            _ => None,
        });
        // The kernel persists `ResponseRecorded` before its infallible
        // observational `record` hook. A crash at that exact acknowledged
        // boundary therefore retains an honest Unknown reservation even
        // though response bytes are present; a later checkpoint records the
        // observed count. Never accept a conflicting claimed observation.
        if attempt
            .observed_response_bytes
            .is_some_and(|observed| response.flatten() != Some(observed))
        {
            return Err(PricedRecoveryError::Pricing);
        }
    }
    Ok(())
}

fn validate_canonical_request(attempt: &GenericIoAttempt) -> Result<(), PricedRecoveryError> {
    let value: Value = serde_json::from_str(&attempt.canonical_request)
        .map_err(|_| PricedRecoveryError::Malformed)?;
    let object = value.as_object().ok_or(PricedRecoveryError::Malformed)?;
    const KEYS: [&str; 8] = [
        "schema",
        "turn",
        "task",
        "observation",
        "proposal_grammar_digest",
        "deployment_binding",
        "max_response_bytes",
        "effective_budget",
    ];
    if object.len() != KEYS.len()
        || !KEYS.iter().all(|key| object.contains_key(*key))
        || object["schema"].as_str() != Some("semaprax.live-invocation.model-request.v1")
    {
        return Err(PricedRecoveryError::Pricing);
    }
    let request = ModelInvocationRequest {
        turn: u32::try_from(
            object["turn"]
                .as_u64()
                .ok_or(PricedRecoveryError::Malformed)?,
        )
        .map_err(|_| PricedRecoveryError::Malformed)?,
        task: unhex(
            object["task"]
                .as_str()
                .ok_or(PricedRecoveryError::Malformed)?,
        )
        .ok_or(PricedRecoveryError::Malformed)?,
        observation: unhex(
            object["observation"]
                .as_str()
                .ok_or(PricedRecoveryError::Malformed)?,
        )
        .ok_or(PricedRecoveryError::Malformed)?,
        proposal_grammar_digest: object["proposal_grammar_digest"]
            .as_str()
            .ok_or(PricedRecoveryError::Malformed)?
            .to_owned(),
        deployment_binding: object["deployment_binding"]
            .as_str()
            .ok_or(PricedRecoveryError::Malformed)?
            .to_owned(),
        max_response_bytes: usize::try_from(
            object["max_response_bytes"]
                .as_u64()
                .ok_or(PricedRecoveryError::Malformed)?,
        )
        .map_err(|_| PricedRecoveryError::Malformed)?,
        effective_budget: object["effective_budget"]
            .as_i64()
            .ok_or(PricedRecoveryError::Malformed)?,
    };
    if request.turn != attempt.turn
        || request.max_response_bytes != attempt.response_limit
        || request.canonical_json() != attempt.canonical_request
        || request.digest() != attempt.request_digest
    {
        return Err(PricedRecoveryError::Pricing);
    }
    Ok(())
}
