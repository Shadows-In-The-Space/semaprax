//! Additive v4 priced-source journal payloads.
//!
//! The explicit priced source route uses this profile without widening the
//! frozen v1/v2/v3 decoders.

use crate::diagnostic::quote_json;
use crate::live_invocation::identity::{digest, looks_like_digest};
use crate::live_invocation::pricing::{
    MonetaryAccounting, MonetaryAttempt, MonetaryReservation, ProviderChargeObservation,
    ValidatedPricing,
};
use serde_json::{Map, Value};

use super::{SourceJournalError, SourceReportedUsage, MAX_SOURCE_REQUEST_BYTES};

#[cfg(test)]
#[path = "priced_v4_tests.rs"]
mod tests;

const PRICED_BINDING_DOMAIN: &[u8] = b"semaprax.live-invocation.source-pricing-binding.v4\0";
const PRICED_ATTEMPT_DOMAIN: &[u8] = b"semaprax.live-invocation.source-priced-attempt.v4\0";

/// The pricing portion of an additive v4 profile. Its base invocation is the
/// already-derived source binding, and its own identity commits every integer
/// pricing field before a provider can be called.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PricedSourceBindingV4 {
    base_invocation: String,
    fixed_reservation_units: i64,
    pricing: ValidatedPricing,
    invocation: String,
}

impl PricedSourceBindingV4 {
    pub(crate) fn new(
        base_invocation: String,
        base_work_unit: &str,
        fixed_reservation_units: i64,
        pricing: ValidatedPricing,
    ) -> Result<Self, SourceJournalError> {
        if !looks_like_digest(&base_invocation)
            || fixed_reservation_units <= 0
            || pricing.work_unit() != base_work_unit
            || pricing
                .quote(base_work_unit, fixed_reservation_units)
                .is_err()
        {
            return Err(SourceJournalError::Binding);
        }
        let canonical = canonical_binding(&base_invocation, fixed_reservation_units, &pricing);
        let invocation = digest(PRICED_BINDING_DOMAIN, canonical.as_bytes());
        Ok(Self {
            base_invocation,
            fixed_reservation_units,
            pricing,
            invocation,
        })
    }

    pub(crate) fn invocation(&self) -> &str {
        &self.invocation
    }

    pub(crate) fn pricing(&self) -> &ValidatedPricing {
        &self.pricing
    }

    pub(crate) fn attempt_digest(
        &self,
        turn: u32,
        attempt: u32,
        money_ordinal: u32,
        request_digest: &str,
        prompt_digest: &str,
        request_bytes: usize,
        response_limit: usize,
    ) -> Result<String, SourceJournalError> {
        if ![request_digest, prompt_digest]
            .into_iter()
            .all(|value| looks_like_digest(value))
            || !(1..=MAX_SOURCE_REQUEST_BYTES).contains(&request_bytes)
            || response_limit == 0
        {
            return Err(SourceJournalError::Binding);
        }
        let reserved_minor = self
            .pricing
            .quote(self.pricing.work_unit(), self.fixed_reservation_units)
            .map_err(|_| SourceJournalError::Binding)?;
        let canonical = format!(
            "{{\"invocation\":{},\"turn\":{},\"attempt\":{},\"money_ordinal\":{},\"request\":{},\"prompt\":{},\"request_bytes\":{},\"reserved_units\":{},\"reserved_minor\":{},\"response_limit\":{}}}",
            quote_json(&self.invocation), turn, attempt, money_ordinal,
            quote_json(request_digest), quote_json(prompt_digest), request_bytes,
            self.fixed_reservation_units, reserved_minor, response_limit,
        );
        Ok(digest(PRICED_ATTEMPT_DOMAIN, canonical.as_bytes()))
    }
}

fn canonical_binding(
    base_invocation: &str,
    fixed_reservation_units: i64,
    pricing: &ValidatedPricing,
) -> String {
    format!(
        "{{\"schema\":\"semaprax.live-invocation.source-pricing-binding.v4\",\"base_invocation\":{},\"work_unit\":{},\"fixed_reservation_units\":{},\"currency\":{},\"minor_unit_exponent\":{},\"price_per_work_unit_minor\":{},\"money_ceiling_minor\":{}}}",
        quote_json(base_invocation), quote_json(pricing.work_unit()),
        fixed_reservation_units, quote_json(pricing.currency()),
        pricing.minor_unit_exponent(), pricing.price_per_work_unit_minor(),
        pricing.ceiling_minor(),
    )
}

/// V4 durable intent. `money_ordinal` is global across the invocation; it is
/// intentionally distinct from the per-turn retry ordinal.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PricedAttemptIntentV4 {
    pub turn: u32,
    pub attempt: u32,
    pub money_ordinal: u32,
    pub attempt_digest: String,
    pub request_digest: String,
    pub prompt_digest: String,
    pub request_bytes: usize,
    pub reserved_units: i64,
    pub reserved_minor: i64,
    pub response_limit: usize,
}

impl PricedAttemptIntentV4 {
    pub(crate) fn reservation(
        &self,
        binding: &PricedSourceBindingV4,
    ) -> Result<MonetaryReservation, SourceJournalError> {
        if self.reserved_units != binding.fixed_reservation_units
            || self.attempt_digest
                != binding.attempt_digest(
                    self.turn,
                    self.attempt,
                    self.money_ordinal,
                    &self.request_digest,
                    &self.prompt_digest,
                    self.request_bytes,
                    self.response_limit,
                )?
        {
            return Err(SourceJournalError::Binding);
        }
        MonetaryReservation::recover(
            binding.pricing(),
            self.money_ordinal,
            self.reserved_units,
            self.reserved_minor,
        )
        .map_err(|_| SourceJournalError::Binding)
    }

    pub(crate) fn render(&self, seq: usize) -> String {
        format!(
            "{{\"seq\":{},\"kind\":\"priced_attempt_intent\",\"turn\":{},\"attempt\":{},\"money_ordinal\":{},\"attempt_digest\":{},\"request_digest\":{},\"prompt_digest\":{},\"request_bytes\":{},\"reserved_units\":{},\"reserved_minor\":{},\"response_limit\":{}}}",
            seq, self.turn, self.attempt, self.money_ordinal,
            quote_json(&self.attempt_digest), quote_json(&self.request_digest),
            quote_json(&self.prompt_digest), self.request_bytes, self.reserved_units,
            self.reserved_minor, self.response_limit,
        )
    }

    pub(crate) fn decode(
        value: &Value,
        seq: usize,
        binding: &PricedSourceBindingV4,
    ) -> Result<Self, SourceJournalError> {
        let map = object(value)?;
        let result = Self {
            turn: u32_field(map, "turn")?,
            attempt: u32_field(map, "attempt")?,
            money_ordinal: u32_field(map, "money_ordinal")?,
            attempt_digest: string(map, "attempt_digest")?,
            request_digest: string(map, "request_digest")?,
            prompt_digest: string(map, "prompt_digest")?,
            request_bytes: usize_field(map, "request_bytes")?,
            reserved_units: i64_field(map, "reserved_units")?,
            reserved_minor: i64_field(map, "reserved_minor")?,
            response_limit: usize_field(map, "response_limit")?,
        };
        if usize_field(map, "seq")? != seq
            || string(map, "kind")? != "priced_attempt_intent"
            || serde_json::from_str::<Value>(&result.render(seq))
                .map_err(|_| SourceJournalError::Malformed)?
                != *value
        {
            return Err(SourceJournalError::Malformed);
        }
        result.reservation(binding)?;
        Ok(result)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SourceUsageObservationV4 {
    Unknown,
    Observed(SourceReportedUsage),
}

/// Durable, replay-derived monetary view.  These numbers are reservations and
/// observations only; none is an invoice, credit, or refund authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PricedTotalsV4 {
    pub currency: String,
    pub minor_unit_exponent: u8,
    pub reserved_minor: i64,
    pub observed_charge_minor: i64,
    pub unknown_charge_reservation_minor: i64,
    pub observed_over_reservation_minor: i64,
    pub remaining_admission_minor: i64,
}

pub(crate) fn fold(
    binding: &PricedSourceBindingV4,
    entries: &[super::SourceJournalEntry],
) -> Result<PricedTotalsV4, SourceJournalError> {
    let mut attempts = Vec::new();
    let mut closed = Vec::new();
    let mut scopes = Vec::new();
    for (index, entry) in entries.iter().enumerate() {
        match entry {
            super::SourceJournalEntry::PricedAttemptIntent(intent) => {
                let reservation = intent.reservation(binding)?;
                if reservation.ordinal()
                    != u32::try_from(attempts.len()).map_err(|_| SourceJournalError::Capacity)?
                {
                    return Err(SourceJournalError::Order);
                }
                attempts.push(MonetaryAttempt {
                    reservation,
                    charge: ProviderChargeObservation::Unknown,
                });
                closed.push(false);
                scopes.push((intent.turn, intent.attempt));
            }
            super::SourceJournalEntry::PricedAttemptUsage(usage) => {
                let prior = entries.get(index.wrapping_sub(1));
                if !matches!(prior,
                    Some(super::SourceJournalEntry::AttemptSettled { turn, attempt, .. }
                        | super::SourceJournalEntry::AttemptFailed { turn, attempt, .. })
                        if *turn == usage.turn && *attempt == usage.attempt)
                {
                    return Err(SourceJournalError::Order);
                }
                let ordinal = usize::try_from(usage.money_ordinal)
                    .map_err(|_| SourceJournalError::Capacity)?;
                let stored = attempts.get_mut(ordinal).ok_or(SourceJournalError::Order)?;
                if closed.get(ordinal) != Some(&false)
                    || stored.reservation.ordinal() != usage.money_ordinal
                    || scopes.get(ordinal) != Some(&(usage.turn, usage.attempt))
                {
                    return Err(SourceJournalError::Order);
                }
                stored.charge = usage.charge.clone();
                closed[ordinal] = true;
            }
            super::SourceJournalEntry::AttemptIntent { .. }
            | super::SourceJournalEntry::AttemptUsage { .. } => {
                return Err(SourceJournalError::Order)
            }
            _ => {}
        }
    }
    let accounting = MonetaryAccounting::resume(binding.pricing().clone(), &attempts)
        .map_err(|_| SourceJournalError::Capacity)?;
    let exposure = accounting
        .conservative_exposure_minor()
        .map_err(|_| SourceJournalError::Capacity)?;
    let remaining_admission_minor = binding
        .pricing()
        .ceiling_minor()
        .checked_sub(exposure)
        .unwrap_or(0)
        .max(0);
    Ok(PricedTotalsV4 {
        currency: binding.pricing().currency().to_owned(),
        minor_unit_exponent: binding.pricing().minor_unit_exponent(),
        reserved_minor: accounting.reserved_minor(),
        observed_charge_minor: accounting.observed_minor(),
        unknown_charge_reservation_minor: accounting.unknown_reservation_minor(),
        observed_over_reservation_minor: accounting.observed_over_reservation_minor(),
        remaining_admission_minor,
    })
}

/// V4 durable post-settlement evidence. The observation is neither an invoice
/// nor a capacity credit; `MonetaryAccounting` remains conservative.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PricedAttemptUsageV4 {
    pub turn: u32,
    pub attempt: u32,
    pub money_ordinal: u32,
    pub usage: SourceUsageObservationV4,
    pub charge: ProviderChargeObservation,
}

impl PricedAttemptUsageV4 {
    pub(crate) fn render(&self, seq: usize) -> String {
        format!(
            "{{\"seq\":{},\"kind\":\"priced_attempt_usage\",\"turn\":{},\"attempt\":{},\"money_ordinal\":{},\"usage\":{},\"charge\":{}}}",
            seq, self.turn, self.attempt, self.money_ordinal,
            render_usage(&self.usage), render_charge(&self.charge),
        )
    }

    pub(crate) fn decode(
        value: &Value,
        seq: usize,
        binding: &PricedSourceBindingV4,
    ) -> Result<Self, SourceJournalError> {
        let map = object(value)?;
        let result = Self {
            turn: u32_field(map, "turn")?,
            attempt: u32_field(map, "attempt")?,
            money_ordinal: u32_field(map, "money_ordinal")?,
            usage: decode_usage(map.get("usage"))?,
            charge: decode_charge(map.get("charge"))?,
        };
        if usize_field(map, "seq")? != seq
            || string(map, "kind")? != "priced_attempt_usage"
            || serde_json::from_str::<Value>(&result.render(seq))
                .map_err(|_| SourceJournalError::Malformed)?
                != *value
        {
            return Err(SourceJournalError::Malformed);
        }
        if let ProviderChargeObservation::Observed {
            currency,
            minor_unit_exponent,
            amount_minor,
        } = &result.charge
        {
            if currency != binding.pricing().currency()
                || *minor_unit_exponent != binding.pricing().minor_unit_exponent()
                || *amount_minor < 0
            {
                return Err(SourceJournalError::Binding);
            }
        }
        Ok(result)
    }
}

fn render_usage(usage: &SourceUsageObservationV4) -> String {
    match usage {
        SourceUsageObservationV4::Unknown => "{\"kind\":\"unknown\"}".to_owned(),
        SourceUsageObservationV4::Observed(value) => format!(
            "{{\"kind\":\"observed\",\"total\":{},\"input\":{},\"output\":{},\"reasoning\":{},\"cache_read\":{},\"cache_write\":{}}}",
            optional_u64(value.total), optional_u64(value.input), optional_u64(value.output),
            optional_u64(value.reasoning), optional_u64(value.cache_read), optional_u64(value.cache_write),
        ),
    }
}

fn render_charge(charge: &ProviderChargeObservation) -> String {
    match charge {
        ProviderChargeObservation::Unknown => "{\"kind\":\"unknown\"}".to_owned(),
        ProviderChargeObservation::Observed { currency, minor_unit_exponent, amount_minor } => format!(
            "{{\"kind\":\"observed\",\"currency\":{},\"minor_unit_exponent\":{},\"amount_minor\":{}}}",
            quote_json(currency), minor_unit_exponent, amount_minor,
        ),
    }
}

fn decode_usage(value: Option<&Value>) -> Result<SourceUsageObservationV4, SourceJournalError> {
    let map = object(value.ok_or(SourceJournalError::Malformed)?)?;
    match string(map, "kind")?.as_str() {
        "unknown" if map.len() == 1 => Ok(SourceUsageObservationV4::Unknown),
        "observed" if map.len() == 7 => {
            Ok(SourceUsageObservationV4::Observed(SourceReportedUsage {
                total: optional_u64_field(map, "total")?,
                input: optional_u64_field(map, "input")?,
                output: optional_u64_field(map, "output")?,
                reasoning: optional_u64_field(map, "reasoning")?,
                cache_read: optional_u64_field(map, "cache_read")?,
                cache_write: optional_u64_field(map, "cache_write")?,
            }))
        }
        _ => Err(SourceJournalError::Malformed),
    }
}

fn decode_charge(value: Option<&Value>) -> Result<ProviderChargeObservation, SourceJournalError> {
    let map = object(value.ok_or(SourceJournalError::Malformed)?)?;
    match string(map, "kind")?.as_str() {
        "unknown" if map.len() == 1 => Ok(ProviderChargeObservation::Unknown),
        "observed" if map.len() == 4 => Ok(ProviderChargeObservation::Observed {
            currency: string(map, "currency")?,
            minor_unit_exponent: u8::try_from(u64_field(map, "minor_unit_exponent")?)
                .map_err(|_| SourceJournalError::Malformed)?,
            amount_minor: i64_field(map, "amount_minor")?,
        }),
        _ => Err(SourceJournalError::Malformed),
    }
}

fn object(value: &Value) -> Result<&Map<String, Value>, SourceJournalError> {
    value.as_object().ok_or(SourceJournalError::Malformed)
}
fn string(map: &Map<String, Value>, key: &str) -> Result<String, SourceJournalError> {
    map.get(key)
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or(SourceJournalError::Malformed)
}
fn u64_field(map: &Map<String, Value>, key: &str) -> Result<u64, SourceJournalError> {
    map.get(key)
        .and_then(Value::as_u64)
        .ok_or(SourceJournalError::Malformed)
}
fn u32_field(map: &Map<String, Value>, key: &str) -> Result<u32, SourceJournalError> {
    u32::try_from(u64_field(map, key)?).map_err(|_| SourceJournalError::Malformed)
}
fn usize_field(map: &Map<String, Value>, key: &str) -> Result<usize, SourceJournalError> {
    usize::try_from(u64_field(map, key)?).map_err(|_| SourceJournalError::Malformed)
}
fn i64_field(map: &Map<String, Value>, key: &str) -> Result<i64, SourceJournalError> {
    map.get(key)
        .and_then(Value::as_i64)
        .ok_or(SourceJournalError::Malformed)
}
fn optional_u64(value: Option<u64>) -> String {
    value.map_or_else(|| "null".to_owned(), |number| number.to_string())
}
fn optional_u64_field(
    map: &Map<String, Value>,
    key: &str,
) -> Result<Option<u64>, SourceJournalError> {
    match map.get(key) {
        Some(Value::Null) => Ok(None),
        Some(value) => value
            .as_u64()
            .map(Some)
            .ok_or(SourceJournalError::Malformed),
        None => Err(SourceJournalError::Malformed),
    }
}
