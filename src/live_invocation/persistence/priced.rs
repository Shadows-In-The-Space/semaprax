use std::cell::RefCell;
use std::rc::Rc;

use serde_json::Value;

use crate::agent_lifecycle::{CheckpointStore, CheckpointStoreError};
use crate::diagnostic::quote_json;

use super::super::identity::LiveInvocationId;
use super::super::io::GenericIoAccounting;
use super::super::journal::{self, JournalEntry, MAX_JOURNAL_ENTRIES};
use super::super::priced::PricedSuccessorHandoff;
use super::super::pricing::{
    MonetaryAccounting, MonetaryAttempt, MonetaryReservation, PricedMonetaryCarry,
    ProviderChargeObservation, ValidatedPricing,
};
use super::encode_priced_io_envelope;
use super::JournalSink;

/// Schema of the additive generic priced envelope. Older persisted-journal.v1
/// bytes remain in the old recovery route and never gain money fields.
pub const PERSISTED_PRICED_JOURNAL_SCHEMA: &str =
    "semaprax.live-invocation.persisted-priced-journal.v1";

/// The only sink accepted by the generic priced runner. It commits the exact
/// journal prefix and the paired monetary snapshot in one store generation.
pub struct PricedCheckpointJournalSink<'a> {
    store: &'a mut dyn CheckpointStore,
    invocation: String,
    generation: u64,
    accounting: Rc<RefCell<MonetaryAccounting>>,
    io: Option<Rc<RefCell<GenericIoAccounting>>>,
    handoff: Option<PricedSuccessorHandoff>,
}

impl<'a> PricedCheckpointJournalSink<'a> {
    pub(crate) fn new(
        store: &'a mut dyn CheckpointStore,
        invocation: impl Into<String>,
        accounting: Rc<RefCell<MonetaryAccounting>>,
        io: Option<Rc<RefCell<GenericIoAccounting>>>,
        handoff: Option<PricedSuccessorHandoff>,
    ) -> Self {
        Self {
            store,
            invocation: invocation.into(),
            generation: 0,
            accounting,
            io,
            handoff,
        }
    }

    pub(crate) fn resume(
        store: &'a mut dyn CheckpointStore,
        invocation: impl Into<String>,
        generation: u64,
        accounting: Rc<RefCell<MonetaryAccounting>>,
        io: Option<Rc<RefCell<GenericIoAccounting>>>,
        handoff: Option<PricedSuccessorHandoff>,
    ) -> Self {
        Self {
            store,
            invocation: invocation.into(),
            generation,
            accounting,
            io,
            handoff,
        }
    }

    pub const fn generation(&self) -> u64 {
        self.generation
    }
}

impl JournalSink for PricedCheckpointJournalSink<'_> {
    fn persist(&mut self, journal: &[JournalEntry]) -> Result<(), CheckpointStoreError> {
        let generation = self.generation.checked_add(1).ok_or(CheckpointStoreError)?;
        let document = match &self.io {
            Some(io) => encode_priced_io_envelope(
                &self.invocation,
                generation,
                journal,
                &self.accounting.borrow(),
                self.handoff.as_ref(),
                &io.borrow(),
            ),
            None => encode_priced_envelope_with_handoff(
                &self.invocation,
                generation,
                journal,
                &self.accounting.borrow(),
                self.handoff.as_ref(),
            ),
        }
        .map_err(|_| CheckpointStoreError)?;
        self.store.commit(generation, &document)?;
        self.generation = generation;
        Ok(())
    }
}

/// An independently decoded priced envelope. The causal journal is handed to
/// the existing kernel validator; this recovery only owns the additive money
/// binding, snapshot, and whole-journal chain check.
pub struct RecoveredPricedJournal {
    pub entries: Vec<JournalEntry>,
    pub generation: u64,
    pub(crate) accounting: MonetaryAccounting,
    pub(crate) handoff: Option<PricedSuccessorHandoff>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PricedRecoveryError {
    Malformed,
    SchemaMismatch,
    InvocationMismatch,
    Journal(journal::DecodeError),
    ChainMismatch,
    Pricing,
}

pub(crate) fn encode_priced_envelope_with_handoff(
    invocation: &str,
    generation: u64,
    journal: &[JournalEntry],
    accounting: &MonetaryAccounting,
    handoff: Option<&PricedSuccessorHandoff>,
) -> Result<String, PricedRecoveryError> {
    if accounting.attempts().len()
        != journal
            .iter()
            .filter(|entry| matches!(entry, JournalEntry::RequestIntent { reserved_budget, .. } if *reserved_budget > 0))
            .count()
    {
        return Err(PricedRecoveryError::Pricing);
    }
    let pricing = accounting.pricing();
    let carry = accounting
        .persisted_carry()
        .map_err(|_| PricedRecoveryError::Pricing)?;
    let intents = journal
        .iter()
        .filter_map(|entry| match entry {
            JournalEntry::RequestIntent {
                reserved_budget, ..
            } if *reserved_budget > 0 => Some(*reserved_budget),
            _ => None,
        })
        .collect::<Vec<_>>();
    if accounting
        .attempts()
        .iter()
        .zip(&intents)
        .any(|(attempt, reserved)| attempt.reservation.work_units() != *reserved)
    {
        return Err(PricedRecoveryError::Pricing);
    }
    let attempts = accounting
        .attempts()
        .iter()
        .map(render_attempt)
        .collect::<Vec<_>>()
        .join(",");
    Ok(format!(
        "{{\"schema\":{},\"invocation\":{},\"generation\":{},\"chain\":{},\"pricing\":{{\"work_unit\":{},\"currency\":{},\"minor_unit_exponent\":{},\"price_per_work_unit_minor\":{},\"ceiling_minor\":{}}},\"carry\":{},\"handoff\":{},\"attempts\":[{}],\"entries\":{}}}\n",
        quote_json(PERSISTED_PRICED_JOURNAL_SCHEMA),
        quote_json(invocation),
        generation,
        quote_json(&journal::chain(journal)),
        quote_json(pricing.work_unit()),
        quote_json(pricing.currency()),
        pricing.minor_unit_exponent(),
        pricing.price_per_work_unit_minor(),
        pricing.ceiling_minor(),
        render_carry(&carry),
        render_handoff(handoff),
        attempts,
        journal::render(journal).trim_end(),
    ))
}

pub fn recover_priced_journal(
    document: &str,
    identity: &LiveInvocationId,
) -> Result<RecoveredPricedJournal, PricedRecoveryError> {
    let value: Value =
        serde_json::from_str(document).map_err(|_| PricedRecoveryError::Malformed)?;
    let object = value.as_object().ok_or(PricedRecoveryError::Malformed)?;
    const KEYS: [&str; 9] = [
        "schema",
        "invocation",
        "generation",
        "chain",
        "pricing",
        "carry",
        "handoff",
        "attempts",
        "entries",
    ];
    if object.len() != KEYS.len() || !KEYS.iter().all(|key| object.contains_key(*key)) {
        return Err(PricedRecoveryError::Malformed);
    }
    if object["schema"].as_str() != Some(PERSISTED_PRICED_JOURNAL_SCHEMA) {
        return Err(PricedRecoveryError::SchemaMismatch);
    }
    if object["invocation"].as_str() != Some(identity.digest()) {
        return Err(PricedRecoveryError::InvocationMismatch);
    }
    let generation = object["generation"]
        .as_u64()
        .ok_or(PricedRecoveryError::Malformed)?;
    let entries = journal::decode(&value["entries"]).map_err(PricedRecoveryError::Journal)?;
    let chain = journal::chain(&entries);
    if object["chain"].as_str() != Some(&chain) {
        return Err(PricedRecoveryError::ChainMismatch);
    }
    let pricing = decode_pricing(&value["pricing"])?;
    let carry = decode_carry(&value["carry"], &pricing)?;
    let attempts = decode_attempts(&value["attempts"], &pricing, carry.next_ordinal())?;
    if attempts.len()
        != entries
            .iter()
            .filter(|entry| matches!(entry, JournalEntry::RequestIntent { reserved_budget, .. } if *reserved_budget > 0))
            .count()
    {
        return Err(PricedRecoveryError::Pricing);
    }
    let handoff = decode_handoff(
        &value["handoff"],
        object["invocation"]
            .as_str()
            .ok_or(PricedRecoveryError::Malformed)?,
        &carry,
        &pricing,
    )?;
    let accounting = MonetaryAccounting::resume_with_priced_carry(pricing, carry, &attempts)
        .map_err(|_| PricedRecoveryError::Pricing)?;
    if document
        != encode_priced_envelope_with_handoff(
            identity.digest(),
            generation,
            &entries,
            &accounting,
            handoff.as_ref(),
        )?
    {
        return Err(PricedRecoveryError::Malformed);
    }
    Ok(RecoveredPricedJournal {
        entries,
        generation,
        accounting,
        handoff,
    })
}

fn render_attempt(attempt: &MonetaryAttempt) -> String {
    let reservation = attempt.reservation;
    let charge = match &attempt.charge {
        ProviderChargeObservation::Unknown => "{\"kind\":\"unknown\"}".to_owned(),
        ProviderChargeObservation::Observed {
            currency,
            minor_unit_exponent,
            amount_minor,
        } => format!(
            "{{\"kind\":\"observed\",\"currency\":{},\"minor_unit_exponent\":{},\"amount_minor\":{}}}",
            quote_json(currency), minor_unit_exponent, amount_minor
        ),
    };
    format!(
        "{{\"ordinal\":{},\"work_units\":{},\"reserved_minor\":{},\"charge\":{}}}",
        reservation.ordinal(),
        reservation.work_units(),
        reservation.reserved_minor(),
        charge,
    )
}

fn decode_pricing(value: &Value) -> Result<ValidatedPricing, PricedRecoveryError> {
    let object = value.as_object().ok_or(PricedRecoveryError::Malformed)?;
    const KEYS: [&str; 5] = [
        "work_unit",
        "currency",
        "minor_unit_exponent",
        "price_per_work_unit_minor",
        "ceiling_minor",
    ];
    if object.len() != KEYS.len() || !KEYS.iter().all(|key| object.contains_key(*key)) {
        return Err(PricedRecoveryError::Malformed);
    }
    ValidatedPricing::new(
        object["work_unit"]
            .as_str()
            .ok_or(PricedRecoveryError::Malformed)?
            .to_owned(),
        object["currency"]
            .as_str()
            .ok_or(PricedRecoveryError::Malformed)?
            .to_owned(),
        u8::try_from(
            object["minor_unit_exponent"]
                .as_u64()
                .ok_or(PricedRecoveryError::Malformed)?,
        )
        .map_err(|_| PricedRecoveryError::Malformed)?,
        object["price_per_work_unit_minor"]
            .as_i64()
            .ok_or(PricedRecoveryError::Malformed)?,
        object["ceiling_minor"]
            .as_i64()
            .ok_or(PricedRecoveryError::Malformed)?,
    )
    .map_err(|_| PricedRecoveryError::Pricing)
}

fn decode_attempts(
    value: &Value,
    pricing: &ValidatedPricing,
    first_ordinal: u32,
) -> Result<Vec<MonetaryAttempt>, PricedRecoveryError> {
    let values = value.as_array().ok_or(PricedRecoveryError::Malformed)?;
    if values.len() > MAX_JOURNAL_ENTRIES {
        return Err(PricedRecoveryError::Malformed);
    }
    let mut attempts = Vec::with_capacity(values.len());
    for (index, value) in values.iter().enumerate() {
        let object = value.as_object().ok_or(PricedRecoveryError::Malformed)?;
        const KEYS: [&str; 4] = ["ordinal", "work_units", "reserved_minor", "charge"];
        if object.len() != KEYS.len()
            || !KEYS.iter().all(|key| object.contains_key(*key))
            || object["ordinal"].as_u64()
                != Some(u64::from(
                    first_ordinal
                        .checked_add(
                            u32::try_from(index).map_err(|_| PricedRecoveryError::Malformed)?,
                        )
                        .ok_or(PricedRecoveryError::Malformed)?,
                ))
        {
            return Err(PricedRecoveryError::Malformed);
        }
        let reservation = MonetaryReservation::recover(
            pricing,
            first_ordinal
                .checked_add(u32::try_from(index).map_err(|_| PricedRecoveryError::Malformed)?)
                .ok_or(PricedRecoveryError::Malformed)?,
            object["work_units"]
                .as_i64()
                .ok_or(PricedRecoveryError::Malformed)?,
            object["reserved_minor"]
                .as_i64()
                .ok_or(PricedRecoveryError::Malformed)?,
        )
        .map_err(|_| PricedRecoveryError::Pricing)?;
        attempts.push(MonetaryAttempt {
            reservation,
            charge: decode_charge(&object["charge"])?,
        });
    }
    Ok(attempts)
}

fn decode_charge(value: &Value) -> Result<ProviderChargeObservation, PricedRecoveryError> {
    let object = value.as_object().ok_or(PricedRecoveryError::Malformed)?;
    match object.get("kind").and_then(Value::as_str) {
        Some("unknown") if object.len() == 1 => Ok(ProviderChargeObservation::Unknown),
        Some("observed") if object.len() == 4 => Ok(ProviderChargeObservation::Observed {
            currency: object["currency"]
                .as_str()
                .ok_or(PricedRecoveryError::Malformed)?
                .to_owned(),
            minor_unit_exponent: u8::try_from(
                object["minor_unit_exponent"]
                    .as_u64()
                    .ok_or(PricedRecoveryError::Malformed)?,
            )
            .map_err(|_| PricedRecoveryError::Malformed)?,
            amount_minor: object["amount_minor"]
                .as_i64()
                .ok_or(PricedRecoveryError::Malformed)?,
        }),
        _ => Err(PricedRecoveryError::Malformed),
    }
}

fn render_carry(carry: &PricedMonetaryCarry) -> String {
    format!(
        "{{\"reserved_minor\":{},\"observed_minor\":{},\"unknown_reservation_minor\":{},\"observed_over_reservation_minor\":{},\"next_ordinal\":{}}}",
        carry.reserved_minor(),
        carry.observed_minor(),
        carry.unknown_reservation_minor(),
        carry.observed_over_reservation_minor(),
        carry.next_ordinal(),
    )
}

fn render_handoff(handoff: Option<&PricedSuccessorHandoff>) -> String {
    let Some(handoff) = handoff else {
        return "null".to_owned();
    };
    let pricing = &handoff.predecessor_pricing;
    format!(
        "{{\"predecessor_invocation\":{},\"destination_invocation\":{},\"predecessor_generation\":{},\"predecessor_chain\":{},\"pricing\":{{\"work_unit\":{},\"currency\":{},\"minor_unit_exponent\":{},\"price_per_work_unit_minor\":{},\"ceiling_minor\":{}}},\"carry\":{},\"handoff_digest\":{}}}",
        quote_json(&handoff.predecessor_invocation),
        quote_json(&handoff.destination_invocation),
        handoff.predecessor_generation,
        quote_json(&handoff.predecessor_chain),
        quote_json(pricing.work_unit()),
        quote_json(pricing.currency()),
        pricing.minor_unit_exponent(),
        pricing.price_per_work_unit_minor(),
        pricing.ceiling_minor(),
        render_carry(&handoff.predecessor_carry),
        quote_json(&handoff.handoff_digest),
    )
}

fn decode_handoff(
    value: &Value,
    destination_invocation: &str,
    carry: &PricedMonetaryCarry,
    destination_pricing: &ValidatedPricing,
) -> Result<Option<PricedSuccessorHandoff>, PricedRecoveryError> {
    if value.is_null() {
        return Ok(None);
    }
    let object = value.as_object().ok_or(PricedRecoveryError::Malformed)?;
    const KEYS: [&str; 7] = [
        "predecessor_invocation",
        "destination_invocation",
        "predecessor_generation",
        "predecessor_chain",
        "pricing",
        "carry",
        "handoff_digest",
    ];
    if object.len() != KEYS.len() || !KEYS.iter().all(|key| object.contains_key(*key)) {
        return Err(PricedRecoveryError::Malformed);
    }
    let predecessor_pricing = decode_pricing(&object["pricing"])?;
    let predecessor_carry = decode_carry(&object["carry"], &predecessor_pricing)?;
    predecessor_carry
        .validate_destination(destination_pricing)
        .map_err(|_| PricedRecoveryError::Pricing)?;
    let handoff = PricedSuccessorHandoff {
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
        predecessor_pricing,
        predecessor_carry,
        handoff_digest: object["handoff_digest"]
            .as_str()
            .ok_or(PricedRecoveryError::Malformed)?
            .to_owned(),
    };
    if !handoff.is_bound_to(destination_invocation, carry) {
        return Err(PricedRecoveryError::Pricing);
    }
    Ok(Some(handoff))
}

fn decode_carry(
    value: &Value,
    pricing: &ValidatedPricing,
) -> Result<PricedMonetaryCarry, PricedRecoveryError> {
    let object = value.as_object().ok_or(PricedRecoveryError::Malformed)?;
    const KEYS: [&str; 5] = [
        "reserved_minor",
        "observed_minor",
        "unknown_reservation_minor",
        "observed_over_reservation_minor",
        "next_ordinal",
    ];
    if object.len() != KEYS.len() || !KEYS.iter().all(|key| object.contains_key(*key)) {
        return Err(PricedRecoveryError::Malformed);
    }
    PricedMonetaryCarry::from_validated(
        pricing.clone(),
        object["reserved_minor"]
            .as_i64()
            .ok_or(PricedRecoveryError::Malformed)?,
        object["observed_minor"]
            .as_i64()
            .ok_or(PricedRecoveryError::Malformed)?,
        object["unknown_reservation_minor"]
            .as_i64()
            .ok_or(PricedRecoveryError::Malformed)?,
        object["observed_over_reservation_minor"]
            .as_i64()
            .ok_or(PricedRecoveryError::Malformed)?,
        u32::try_from(
            object["next_ordinal"]
                .as_u64()
                .ok_or(PricedRecoveryError::Malformed)?,
        )
        .map_err(|_| PricedRecoveryError::Malformed)?,
    )
    .map_err(|_| PricedRecoveryError::Pricing)
}
