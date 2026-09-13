//! Additive V3 byte reservations for durable model-policy attempts.
//!
//! This is intentionally independent from the frozen V2 policy journal.  A
//! V3 checkpoint records these facts beside its V2 policy document; observed
//! output is evidence only and never returns reserved capacity.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DurableByteBudget {
    pub max_request_bytes: u64,
    pub max_response_bytes: u64,
    pub max_total_input_bytes: u64,
    pub max_total_output_bytes: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DurableByteReservation {
    pub ordinal: u64,
    pub input_bytes: u64,
    pub reserved_output_bytes: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DurableByteObservation {
    pub ordinal: u64,
    pub observed_output_bytes: u64,
    pub output_unknown: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DurableByteRefusal {
    PerAttemptInput,
    PerAttemptOutput,
    TotalInput,
    TotalOutput,
    Overflow,
    UnknownReservation,
    AlreadyObserved,
}

#[derive(Clone, Debug)]
pub struct DurableByteLedger {
    budget: DurableByteBudget,
    reservations: Vec<DurableByteReservation>,
    observations: Vec<Option<DurableByteObservation>>,
    total_input_bytes: u64,
    total_reserved_output_bytes: u64,
}

impl DurableByteLedger {
    pub fn new(budget: DurableByteBudget) -> Self {
        Self {
            budget,
            reservations: Vec::new(),
            observations: Vec::new(),
            total_input_bytes: 0,
            total_reserved_output_bytes: 0,
        }
    }

    pub fn reserve(
        &mut self,
        input_bytes: u64,
        reserved_output_bytes: u64,
    ) -> Result<DurableByteReservation, DurableByteRefusal> {
        if input_bytes > self.budget.max_request_bytes {
            return Err(DurableByteRefusal::PerAttemptInput);
        }
        if reserved_output_bytes > self.budget.max_response_bytes {
            return Err(DurableByteRefusal::PerAttemptOutput);
        }
        let total_input_bytes = self
            .total_input_bytes
            .checked_add(input_bytes)
            .ok_or(DurableByteRefusal::Overflow)?;
        if total_input_bytes > self.budget.max_total_input_bytes {
            return Err(DurableByteRefusal::TotalInput);
        }
        let total_reserved_output_bytes = self
            .total_reserved_output_bytes
            .checked_add(reserved_output_bytes)
            .ok_or(DurableByteRefusal::Overflow)?;
        if total_reserved_output_bytes > self.budget.max_total_output_bytes {
            return Err(DurableByteRefusal::TotalOutput);
        }
        let reservation = DurableByteReservation {
            ordinal: u64::try_from(self.reservations.len())
                .map_err(|_| DurableByteRefusal::Overflow)?,
            input_bytes,
            reserved_output_bytes,
        };
        self.total_input_bytes = total_input_bytes;
        self.total_reserved_output_bytes = total_reserved_output_bytes;
        self.reservations.push(reservation);
        self.observations.push(None);
        Ok(reservation)
    }

    pub fn observe(
        &mut self,
        reservation: DurableByteReservation,
        observed_output_bytes: u64,
        output_unknown: bool,
    ) -> Result<DurableByteObservation, DurableByteRefusal> {
        let index = usize::try_from(reservation.ordinal)
            .map_err(|_| DurableByteRefusal::UnknownReservation)?;
        if self.reservations.get(index) != Some(&reservation) {
            return Err(DurableByteRefusal::UnknownReservation);
        }
        if self.observations.get(index).is_none_or(Option::is_some) {
            return Err(DurableByteRefusal::AlreadyObserved);
        }
        // A settled response is exact provider evidence, so it must fit the
        // acknowledged reservation.  A failed dispatch may report bytes from
        // the overflowing chunk that caused the failure; retain that fact as
        // unknown exposure rather than laundering it into a settled result.
        if !output_unknown && observed_output_bytes > reservation.reserved_output_bytes {
            return Err(DurableByteRefusal::PerAttemptOutput);
        }
        let observation = DurableByteObservation {
            ordinal: reservation.ordinal,
            observed_output_bytes,
            output_unknown,
        };
        self.observations[index] = Some(observation);
        Ok(observation)
    }

    pub(crate) const fn budget(&self) -> DurableByteBudget {
        self.budget
    }

    pub fn reservations(&self) -> &[DurableByteReservation] {
        &self.reservations
    }
    pub fn observations(&self) -> &[Option<DurableByteObservation>] {
        &self.observations
    }
    pub const fn total_input_bytes(&self) -> u64 {
        self.total_input_bytes
    }
    pub const fn total_reserved_output_bytes(&self) -> u64 {
        self.total_reserved_output_bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn budget() -> DurableByteBudget {
        DurableByteBudget {
            max_request_bytes: 4,
            max_response_bytes: 5,
            max_total_input_bytes: 8,
            max_total_output_bytes: 10,
        }
    }

    #[test]
    fn reservations_are_nonrefundable_and_unknown_output_is_explicit() {
        let mut ledger = DurableByteLedger::new(budget());
        let first = ledger.reserve(4, 5).unwrap();
        ledger.observe(first, 2, true).unwrap();
        assert_eq!(ledger.total_reserved_output_bytes(), 5);
        ledger.reserve(4, 5).unwrap();
        assert_eq!(ledger.reserve(1, 1), Err(DurableByteRefusal::TotalInput));
    }

    #[test]
    fn settled_output_cannot_exceed_its_acknowledged_reservation() {
        let mut ledger = DurableByteLedger::new(budget());
        let reservation = ledger.reserve(1, 5).unwrap();
        assert_eq!(
            ledger.observe(reservation, 6, false),
            Err(DurableByteRefusal::PerAttemptOutput)
        );
        assert_eq!(ledger.observations(), &[None]);
        ledger.observe(reservation, 6, true).unwrap();
    }
}
