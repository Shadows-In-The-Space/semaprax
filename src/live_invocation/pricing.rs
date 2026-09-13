//! Pure, conservative operator pricing shared by priced live routes.
//!
//! The pricing identity is explicit and immutable for one invocation. The
//! existing work-unit ledger remains authoritative for its own quota. This
//! core supplies paired monetary admission/evidence without treating tokens,
//! a floating provider cost, or an observation as billing authority.

use super::model_invoke::BudgetRefusal;
use super::source_journal::MAX_SOURCE_ENTRIES;

#[cfg(test)]
#[path = "pricing/tests.rs"]
mod tests;

pub(crate) const PRICING_UNIT_MISMATCH: &str = "pricing_unit_mismatch";
pub(crate) const PRICING_BUDGET_EXHAUSTED: &str = "pricing_budget_exhausted";
pub(crate) const PRICING_NEGATIVE_WORK: &str = "pricing_negative_work";
pub(crate) const PRICING_ZERO_WORK: &str = "pricing_zero_work";
pub(crate) const PRICING_PRODUCT_OVERFLOW: &str = "pricing_product_overflow";
pub(crate) const PRICING_TOTAL_OVERFLOW: &str = "pricing_total_overflow";
pub(crate) const PRICING_ATTEMPT_CAPACITY: &str = "pricing_attempt_capacity";
pub(crate) const PRICING_UNKNOWN_RESERVATION: &str = "pricing_unknown_reservation";
pub(crate) const PRICING_ALREADY_OBSERVED: &str = "pricing_already_observed";
pub(crate) const PRICING_CURRENCY_MISMATCH: &str = "pricing_currency_mismatch";
pub(crate) const PRICING_SCALE_MISMATCH: &str = "pricing_scale_mismatch";
pub(crate) const PRICING_RATE_MISMATCH: &str = "pricing_rate_mismatch";
pub(crate) const PRICING_NEGATIVE_OBSERVATION: &str = "pricing_negative_observation";

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PricingConfigError {
    InvalidWorkUnit,
    InvalidCurrency,
    InvalidMinorUnitExponent,
    NonPositiveQuote,
    NegativeCeiling,
}

/// Immutable operator policy for one exact source work-unit contract.
///
/// The quote is a maximum admitted-work estimate in integer minor units. It
/// is neither a token price nor proof of a provider invoice. Currency is only
/// an exact binding; this core performs no conversion or lookup.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedPricing {
    work_unit: String,
    currency: String,
    minor_unit_exponent: u8,
    price_per_work_unit_minor: i64,
    ceiling_minor: i64,
}

impl ValidatedPricing {
    pub fn new(
        work_unit: String,
        currency: String,
        minor_unit_exponent: u8,
        price_per_work_unit_minor: i64,
        ceiling_minor: i64,
    ) -> Result<Self, PricingConfigError> {
        if !valid_work_unit(&work_unit) {
            return Err(PricingConfigError::InvalidWorkUnit);
        }
        if !valid_currency(&currency) {
            return Err(PricingConfigError::InvalidCurrency);
        }
        if minor_unit_exponent > 9 {
            return Err(PricingConfigError::InvalidMinorUnitExponent);
        }
        if price_per_work_unit_minor <= 0 {
            return Err(PricingConfigError::NonPositiveQuote);
        }
        if ceiling_minor < 0 {
            return Err(PricingConfigError::NegativeCeiling);
        }
        Ok(Self {
            work_unit,
            currency,
            minor_unit_exponent,
            price_per_work_unit_minor,
            ceiling_minor,
        })
    }

    pub fn work_unit(&self) -> &str {
        &self.work_unit
    }
    pub fn currency(&self) -> &str {
        &self.currency
    }
    pub const fn minor_unit_exponent(&self) -> u8 {
        self.minor_unit_exponent
    }
    pub const fn price_per_work_unit_minor(&self) -> i64 {
        self.price_per_work_unit_minor
    }
    pub const fn ceiling_minor(&self) -> i64 {
        self.ceiling_minor
    }

    /// Quotes exact bound work. The caller still reserves against the total.
    pub fn quote(&self, work_unit: &str, work_units: i64) -> Result<i64, BudgetRefusal> {
        if work_unit != self.work_unit {
            return Err(refusal(PRICING_UNIT_MISMATCH));
        }
        if work_units < 0 {
            return Err(refusal(PRICING_NEGATIVE_WORK));
        }
        if work_units == 0 {
            return Err(refusal(PRICING_ZERO_WORK));
        }
        work_units
            .checked_mul(self.price_per_work_unit_minor)
            .ok_or_else(|| refusal(PRICING_PRODUCT_OVERFLOW))
    }
}

/// Opaque reservation. Recovery must use `recover`, which rechecks the quote.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct MonetaryReservation {
    ordinal: u32,
    work_units: i64,
    reserved_minor: i64,
}

/// A V2/V3 predecessor has durable work reservations but no typed monetary
/// evidence.  V4 migration carries that checked operator estimate as unknown
/// exposure instead of manufacturing one v4 attempt per old journal row.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct MonetaryCarry {
    work_units: i64,
    work_unit: String,
    currency: String,
    minor_unit_exponent: u8,
    price_per_work_unit_minor: i64,
    reserved_minor: i64,
}

/// Validated cumulative v4 evidence carried across a priced migration.  It
/// has no synthetic per-attempt provenance; `next_ordinal` preserves the
/// global ordinal for the destination's real v4 entries.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PricedMonetaryCarry {
    pricing: ValidatedPricing,
    reserved_minor: i64,
    observed_minor: i64,
    unknown_reservation_minor: i64,
    observed_over_reservation_minor: i64,
    next_ordinal: u32,
}

impl MonetaryCarry {
    pub(crate) fn from_legacy_work(
        pricing: &ValidatedPricing,
        work_units: i64,
    ) -> Result<Self, BudgetRefusal> {
        if work_units < 0 {
            return Err(refusal(PRICING_NEGATIVE_WORK));
        }
        // A predecessor with no committed attempts is a valid migration
        // baseline.  It carries zero exposure without pretending to reserve a
        // zero-work V4 attempt.
        let reserved_minor = if work_units == 0 {
            0
        } else {
            pricing.quote(pricing.work_unit(), work_units)?
        };
        Ok(Self {
            work_units,
            work_unit: pricing.work_unit.clone(),
            currency: pricing.currency.clone(),
            minor_unit_exponent: pricing.minor_unit_exponent,
            price_per_work_unit_minor: pricing.price_per_work_unit_minor,
            reserved_minor,
        })
    }

    fn validate_destination(&self, pricing: &ValidatedPricing) -> Result<(), BudgetRefusal> {
        if self.work_unit != pricing.work_unit {
            return Err(refusal(PRICING_UNIT_MISMATCH));
        }
        if self.currency != pricing.currency {
            return Err(refusal(PRICING_CURRENCY_MISMATCH));
        }
        if self.minor_unit_exponent != pricing.minor_unit_exponent {
            return Err(refusal(PRICING_SCALE_MISMATCH));
        }
        if self.price_per_work_unit_minor != pricing.price_per_work_unit_minor {
            return Err(refusal(PRICING_RATE_MISMATCH));
        }
        let expected = self
            .work_units
            .checked_mul(pricing.price_per_work_unit_minor)
            .ok_or_else(|| refusal(PRICING_PRODUCT_OVERFLOW))?;
        if self.reserved_minor != expected {
            return Err(refusal(PRICING_UNIT_MISMATCH));
        }
        Ok(())
    }
}

impl PricedMonetaryCarry {
    pub(crate) fn from_validated(
        pricing: ValidatedPricing,
        reserved_minor: i64,
        observed_minor: i64,
        unknown_reservation_minor: i64,
        observed_over_reservation_minor: i64,
        next_ordinal: u32,
    ) -> Result<Self, BudgetRefusal> {
        if reserved_minor < 0
            || observed_minor < 0
            || unknown_reservation_minor < 0
            || observed_over_reservation_minor < 0
            || unknown_reservation_minor > reserved_minor
            || observed_over_reservation_minor > observed_minor
            || reserved_minor
                .checked_add(observed_over_reservation_minor)
                .is_none()
        {
            return Err(refusal(PRICING_TOTAL_OVERFLOW));
        }
        Ok(Self {
            pricing,
            reserved_minor,
            observed_minor,
            unknown_reservation_minor,
            observed_over_reservation_minor,
            next_ordinal,
        })
    }

    pub(crate) fn pricing(&self) -> &ValidatedPricing {
        &self.pricing
    }

    pub(crate) const fn reserved_minor(&self) -> i64 {
        self.reserved_minor
    }
    pub(crate) const fn observed_minor(&self) -> i64 {
        self.observed_minor
    }
    pub(crate) const fn unknown_reservation_minor(&self) -> i64 {
        self.unknown_reservation_minor
    }
    pub(crate) const fn observed_over_reservation_minor(&self) -> i64 {
        self.observed_over_reservation_minor
    }
    pub(crate) const fn next_ordinal(&self) -> u32 {
        self.next_ordinal
    }

    pub(crate) fn validate_destination(
        &self,
        destination: &ValidatedPricing,
    ) -> Result<(), BudgetRefusal> {
        if self.pricing.work_unit != destination.work_unit {
            return Err(refusal(PRICING_UNIT_MISMATCH));
        }
        if self.pricing.currency != destination.currency {
            return Err(refusal(PRICING_CURRENCY_MISMATCH));
        }
        if self.pricing.minor_unit_exponent != destination.minor_unit_exponent {
            return Err(refusal(PRICING_SCALE_MISMATCH));
        }
        if self.pricing.price_per_work_unit_minor != destination.price_per_work_unit_minor {
            return Err(refusal(PRICING_RATE_MISMATCH));
        }
        if destination.ceiling_minor > self.pricing.ceiling_minor {
            return Err(refusal(PRICING_BUDGET_EXHAUSTED));
        }
        if self.reserved_minor > destination.ceiling_minor {
            return Err(refusal(PRICING_BUDGET_EXHAUSTED));
        }
        Ok(())
    }
}

impl MonetaryReservation {
    pub const fn ordinal(self) -> u32 {
        self.ordinal
    }
    pub(crate) const fn work_units(self) -> i64 {
        self.work_units
    }
    pub(crate) const fn reserved_minor(self) -> i64 {
        self.reserved_minor
    }

    pub(crate) fn recover(
        pricing: &ValidatedPricing,
        ordinal: u32,
        work_units: i64,
        reserved_minor: i64,
    ) -> Result<Self, BudgetRefusal> {
        if reserved_minor != pricing.quote(pricing.work_unit(), work_units)? {
            return Err(refusal(PRICING_UNIT_MISMATCH));
        }
        Ok(Self {
            ordinal,
            work_units,
            reserved_minor,
        })
    }
}

/// Provider monetary evidence after settlement. Unknown is explicit and keeps
/// full reserved exposure. Observed accepts no different currency/scale and
/// never refunds or establishes an invoice claim.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProviderChargeObservation {
    Unknown,
    Observed {
        currency: String,
        minor_unit_exponent: u8,
        amount_minor: i64,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct MonetaryAttempt {
    pub(crate) reservation: MonetaryReservation,
    pub(crate) charge: ProviderChargeObservation,
}

/// Cumulative monetary accounting paired with, but separate from, source work
/// quota. The v4 integration must reserve both at the same acknowledged intent.
#[derive(Clone, Debug)]
pub(crate) struct MonetaryAccounting {
    pricing: ValidatedPricing,
    attempts: Vec<MonetaryAttempt>,
    reserved_minor: i64,
    observed_minor: i64,
    unknown_reservation_minor: i64,
    observed_over_reservation_minor: i64,
    next_ordinal: u32,
    failure: Option<&'static str>,
}

impl MonetaryAccounting {
    pub(crate) fn new(pricing: ValidatedPricing) -> Self {
        Self {
            pricing,
            attempts: Vec::new(),
            reserved_minor: 0,
            observed_minor: 0,
            unknown_reservation_minor: 0,
            observed_over_reservation_minor: 0,
            next_ordinal: 0,
            failure: None,
        }
    }

    /// Starts a v4 destination after a checked V2/V3 handoff.  There is no
    /// typed provider amount in the predecessor, so the carried amount is
    /// both reserved and unknown.  Its absence from `attempts` is intentional:
    /// a made-up v4 ordinal would falsify durable provenance.
    pub(crate) fn with_legacy_carry(
        pricing: ValidatedPricing,
        carry: MonetaryCarry,
    ) -> Result<Self, BudgetRefusal> {
        carry.validate_destination(&pricing)?;
        if carry.reserved_minor > pricing.ceiling_minor() {
            return Err(refusal(PRICING_BUDGET_EXHAUSTED));
        }
        Ok(Self {
            pricing,
            attempts: Vec::new(),
            reserved_minor: carry.reserved_minor,
            observed_minor: 0,
            unknown_reservation_minor: carry.reserved_minor,
            observed_over_reservation_minor: 0,
            next_ordinal: 0,
            failure: None,
        })
    }

    /// Rebuild only from v4 durable attempts in strict ordinal order.
    pub(crate) fn resume(
        pricing: ValidatedPricing,
        attempts: &[MonetaryAttempt],
    ) -> Result<Self, BudgetRefusal> {
        Self::resume_with_legacy_carry(pricing, None, attempts)
    }

    /// Replays only actual V4 attempts after the separately bound legacy
    /// carry.  New V4 money ordinals still start at zero, preserving the
    /// meaning of the v4 attempt wire without rewriting predecessor history.
    pub(crate) fn resume_with_legacy_carry(
        pricing: ValidatedPricing,
        carry: Option<MonetaryCarry>,
        attempts: &[MonetaryAttempt],
    ) -> Result<Self, BudgetRefusal> {
        let mut accounting = match carry {
            Some(carry) => Self::with_legacy_carry(pricing, carry)?,
            None => Self::new(pricing),
        };
        for persisted in attempts {
            let ordinal = u32::try_from(accounting.attempts.len())
                .map_err(|_| refusal(PRICING_TOTAL_OVERFLOW))?;
            if persisted.reservation.ordinal != ordinal {
                return Err(refusal(PRICING_UNKNOWN_RESERVATION));
            }
            let reservation = MonetaryReservation::recover(
                &accounting.pricing,
                ordinal,
                persisted.reservation.work_units,
                persisted.reservation.reserved_minor,
            )?;
            accounting.reserve_replayed(reservation)?;
            accounting.record_charge(reservation, persisted.charge.clone())?;
        }
        Ok(accounting)
    }

    pub(crate) fn resume_with_priced_carry(
        pricing: ValidatedPricing,
        carry: PricedMonetaryCarry,
        attempts: &[MonetaryAttempt],
    ) -> Result<Self, BudgetRefusal> {
        carry.validate_destination(&pricing)?;
        let mut accounting = Self {
            pricing,
            attempts: Vec::new(),
            reserved_minor: carry.reserved_minor,
            observed_minor: carry.observed_minor,
            unknown_reservation_minor: carry.unknown_reservation_minor,
            observed_over_reservation_minor: carry.observed_over_reservation_minor,
            next_ordinal: carry.next_ordinal,
            failure: None,
        };
        for persisted in attempts {
            if persisted.reservation.ordinal != accounting.next_ordinal {
                return Err(refusal(PRICING_UNKNOWN_RESERVATION));
            }
            let reservation = MonetaryReservation::recover(
                &accounting.pricing,
                accounting.next_ordinal,
                persisted.reservation.work_units,
                persisted.reservation.reserved_minor,
            )?;
            accounting.reserve_replayed(reservation)?;
            accounting.record_charge(reservation, persisted.charge.clone())?;
        }
        Ok(accounting)
    }

    pub(crate) fn pricing(&self) -> &ValidatedPricing {
        &self.pricing
    }

    pub(crate) fn preflight_reserve(
        &self,
        work_unit: &str,
        work_units: i64,
    ) -> Result<(), BudgetRefusal> {
        self.ensure_live()?;
        let reserved_minor = self.pricing.quote(work_unit, work_units)?;
        self.ensure_capacity()?;
        let prior_exposure = self
            .reserved_minor
            .checked_add(self.observed_over_reservation_minor)
            .ok_or_else(|| refusal(PRICING_TOTAL_OVERFLOW))?;
        let admission_exposure = prior_exposure
            .checked_add(reserved_minor)
            .ok_or_else(|| refusal(PRICING_TOTAL_OVERFLOW))?;
        (admission_exposure <= self.pricing.ceiling_minor())
            .then_some(())
            .ok_or_else(|| refusal(PRICING_BUDGET_EXHAUSTED))
    }

    /// Commits the maximum price before physical dispatch. The current source
    /// work ledger remains separate until the v4 integration joins boundaries.
    pub(crate) fn reserve(
        &mut self,
        work_unit: &str,
        work_units: i64,
    ) -> Result<MonetaryReservation, BudgetRefusal> {
        self.ensure_live()?;
        let reserved_minor = self.pricing.quote(work_unit, work_units)?;
        self.ensure_capacity()?;
        let prior_exposure = match self
            .reserved_minor
            .checked_add(self.observed_over_reservation_minor)
        {
            Some(value) => value,
            None => return Err(self.fail_stop(PRICING_TOTAL_OVERFLOW)),
        };
        let admission_exposure = match prior_exposure.checked_add(reserved_minor) {
            Some(value) => value,
            None => return Err(self.fail_stop(PRICING_TOTAL_OVERFLOW)),
        };
        if admission_exposure > self.pricing.ceiling_minor() {
            return Err(refusal(PRICING_BUDGET_EXHAUSTED));
        }
        let ordinal = self.next_ordinal;
        let reservation = MonetaryReservation {
            ordinal,
            work_units,
            reserved_minor,
        };
        self.reserve_recovered(reservation)?;
        Ok(reservation)
    }

    /// Records one terminal provider charge. An attempt begins Unknown, so a
    /// pending/crashed attempt remains exposed. A matching observation removes
    /// only its unknown label, never its reservation; overages stay visible.
    pub(crate) fn record_charge(
        &mut self,
        reservation: MonetaryReservation,
        charge: ProviderChargeObservation,
    ) -> Result<(), BudgetRefusal> {
        self.ensure_live()?;
        let ordinal_base = self
            .next_ordinal
            .checked_sub(
                u32::try_from(self.attempts.len())
                    .map_err(|_| refusal(PRICING_UNKNOWN_RESERVATION))?,
            )
            .ok_or_else(|| refusal(PRICING_UNKNOWN_RESERVATION))?;
        let index = usize::try_from(
            reservation
                .ordinal
                .checked_sub(ordinal_base)
                .ok_or_else(|| refusal(PRICING_UNKNOWN_RESERVATION))?,
        )
        .map_err(|_| refusal(PRICING_UNKNOWN_RESERVATION))?;
        let attempt = self
            .attempts
            .get(index)
            .ok_or_else(|| refusal(PRICING_UNKNOWN_RESERVATION))?;
        if attempt.reservation != reservation {
            return Err(refusal(PRICING_UNKNOWN_RESERVATION));
        }
        if !matches!(&attempt.charge, ProviderChargeObservation::Unknown) {
            return Err(refusal(PRICING_ALREADY_OBSERVED));
        }
        let (observed, overage) = match &charge {
            ProviderChargeObservation::Unknown => return Ok(()),
            ProviderChargeObservation::Observed {
                currency,
                minor_unit_exponent,
                amount_minor,
            } => {
                if currency != self.pricing.currency() {
                    return Err(refusal(PRICING_CURRENCY_MISMATCH));
                }
                if *minor_unit_exponent != self.pricing.minor_unit_exponent() {
                    return Err(refusal(PRICING_SCALE_MISMATCH));
                }
                if *amount_minor < 0 {
                    return Err(refusal(PRICING_NEGATIVE_OBSERVATION));
                }
                let overage = if *amount_minor > reservation.reserved_minor {
                    match amount_minor.checked_sub(reservation.reserved_minor) {
                        Some(value) => value,
                        None => return Err(self.fail_stop(PRICING_TOTAL_OVERFLOW)),
                    }
                } else {
                    0
                };
                (*amount_minor, overage)
            }
        };
        let observed_total = match self.observed_minor.checked_add(observed) {
            Some(value) => value,
            None => return Err(self.fail_stop(PRICING_TOTAL_OVERFLOW)),
        };
        let unknown_total = match self
            .unknown_reservation_minor
            .checked_sub(reservation.reserved_minor)
        {
            Some(value) => value,
            None => return Err(self.fail_stop(PRICING_TOTAL_OVERFLOW)),
        };
        let overage_total = match self.observed_over_reservation_minor.checked_add(overage) {
            Some(value) => value,
            None => return Err(self.fail_stop(PRICING_TOTAL_OVERFLOW)),
        };
        // Leave the attempt Unknown until every following checked total fits.
        // A v4 checkpoint must refuse this representation failure rather than
        // publishing a fake zero charge or a partial counter update.
        self.observed_minor = observed_total;
        self.unknown_reservation_minor = unknown_total;
        self.observed_over_reservation_minor = overage_total;
        self.attempts[index].charge = charge;
        Ok(())
    }

    pub(crate) fn attempts(&self) -> &[MonetaryAttempt] {
        &self.attempts
    }
    pub(crate) fn persisted_carry(&self) -> Result<PricedMonetaryCarry, BudgetRefusal> {
        let base_next = self
            .next_ordinal
            .checked_sub(
                u32::try_from(self.attempts.len()).map_err(|_| refusal(PRICING_TOTAL_OVERFLOW))?,
            )
            .ok_or_else(|| refusal(PRICING_TOTAL_OVERFLOW))?;
        let replayed = Self::resume_with_priced_carry(
            self.pricing.clone(),
            PricedMonetaryCarry::from_validated(self.pricing.clone(), 0, 0, 0, 0, base_next)?,
            &self.attempts,
        )?;
        PricedMonetaryCarry::from_validated(
            self.pricing.clone(),
            self.reserved_minor
                .checked_sub(replayed.reserved_minor)
                .ok_or_else(|| refusal(PRICING_TOTAL_OVERFLOW))?,
            self.observed_minor
                .checked_sub(replayed.observed_minor)
                .ok_or_else(|| refusal(PRICING_TOTAL_OVERFLOW))?,
            self.unknown_reservation_minor
                .checked_sub(replayed.unknown_reservation_minor)
                .ok_or_else(|| refusal(PRICING_TOTAL_OVERFLOW))?,
            self.observed_over_reservation_minor
                .checked_sub(replayed.observed_over_reservation_minor)
                .ok_or_else(|| refusal(PRICING_TOTAL_OVERFLOW))?,
            // `next_ordinal` is a sequence coordinate rather than an
            // additive amount.  The destination attempts begin at this
            // exact base; subtracting the replayed end would silently reset
            // a migrated/previously recovered sequence to zero.
            base_next,
        )
    }
    pub(crate) fn total_carry(&self) -> Result<PricedMonetaryCarry, BudgetRefusal> {
        PricedMonetaryCarry::from_validated(
            self.pricing.clone(),
            self.reserved_minor,
            self.observed_minor,
            self.unknown_reservation_minor,
            self.observed_over_reservation_minor,
            self.next_ordinal,
        )
    }
    pub(crate) const fn reserved_minor(&self) -> i64 {
        self.reserved_minor
    }
    pub(crate) const fn observed_minor(&self) -> i64 {
        self.observed_minor
    }
    pub(crate) const fn unknown_reservation_minor(&self) -> i64 {
        self.unknown_reservation_minor
    }
    pub(crate) const fn observed_over_reservation_minor(&self) -> i64 {
        self.observed_over_reservation_minor
    }
    pub(crate) const fn failure(&self) -> Option<&'static str> {
        self.failure
    }
    pub(crate) fn conservative_exposure_minor(&self) -> Result<i64, BudgetRefusal> {
        self.reserved_minor
            .checked_add(self.observed_over_reservation_minor)
            .ok_or_else(|| refusal(PRICING_TOTAL_OVERFLOW))
    }

    fn reserve_recovered(&mut self, reservation: MonetaryReservation) -> Result<(), BudgetRefusal> {
        self.ensure_capacity()?;
        let reserved_total = self
            .reserved_minor
            .checked_add(reservation.reserved_minor)
            .ok_or_else(|| refusal(PRICING_TOTAL_OVERFLOW))?;
        if reserved_total > self.pricing.ceiling_minor() {
            return Err(refusal(PRICING_BUDGET_EXHAUSTED));
        }
        let unknown_total = self
            .unknown_reservation_minor
            .checked_add(reservation.reserved_minor)
            .ok_or_else(|| refusal(PRICING_TOTAL_OVERFLOW))?;
        let next_ordinal = self
            .next_ordinal
            .checked_add(1)
            .ok_or_else(|| refusal(PRICING_TOTAL_OVERFLOW))?;
        self.reserved_minor = reserved_total;
        self.unknown_reservation_minor = unknown_total;
        self.attempts.push(MonetaryAttempt {
            reservation,
            charge: ProviderChargeObservation::Unknown,
        });
        self.next_ordinal = next_ordinal;
        Ok(())
    }

    /// Replays an already durable V4 intent in sequence.  A terminal charge
    /// may have exceeded its own reservation, but that overage was visible
    /// before any following intent could have been acknowledged; accepting a
    /// later intent that would then exceed the ceiling would rewrite history.
    fn reserve_replayed(&mut self, reservation: MonetaryReservation) -> Result<(), BudgetRefusal> {
        let prior_exposure = self
            .reserved_minor
            .checked_add(self.observed_over_reservation_minor)
            .ok_or_else(|| refusal(PRICING_TOTAL_OVERFLOW))?;
        let admission_exposure = prior_exposure
            .checked_add(reservation.reserved_minor)
            .ok_or_else(|| refusal(PRICING_TOTAL_OVERFLOW))?;
        if admission_exposure > self.pricing.ceiling_minor() {
            return Err(refusal(PRICING_BUDGET_EXHAUSTED));
        }
        self.reserve_recovered(reservation)
    }

    fn ensure_capacity(&self) -> Result<(), BudgetRefusal> {
        // The journal contains entries besides model attempts, so this is an
        // intentionally loose safety ceiling. It does not confuse the
        // per-turn retry maximum with a whole-invocation attempt limit.
        (self.attempts.len() < MAX_SOURCE_ENTRIES)
            .then_some(())
            .ok_or_else(|| refusal(PRICING_ATTEMPT_CAPACITY))
    }

    fn ensure_live(&self) -> Result<(), BudgetRefusal> {
        self.failure.map_or(Ok(()), |reason| Err(refusal(reason)))
    }

    fn fail_stop(&mut self, reason: &'static str) -> BudgetRefusal {
        self.failure.get_or_insert(reason);
        refusal(reason)
    }
}

fn refusal(reason: &str) -> BudgetRefusal {
    BudgetRefusal(reason.to_owned())
}

fn valid_work_unit(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.' | b':' | b'/')
        })
}

fn valid_currency(value: &str) -> bool {
    value.len() == 3 && value.bytes().all(|byte| byte.is_ascii_uppercase())
}
