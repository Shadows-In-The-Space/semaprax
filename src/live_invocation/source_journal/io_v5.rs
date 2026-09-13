//! Additive provider I/O limits. Acknowledged intent bytes never refund.
use super::*;

const ID_DOMAIN: &[u8] = b"semaprax.live-invocation.source-io-id.v5\0";

#[cfg(test)]
#[path = "io_v5_tests.rs"]
mod tests;

/// Request includes the complete prepared provider prompt/context envelope.
/// Responses reserve the existing per-attempt response limit before dispatch.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SourceIoLimits {
    pub max_request_bytes: usize,
    pub max_total_request_bytes: u64,
    pub max_total_response_bytes: u64,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct SourceIoTotals {
    pub reserved_request_bytes: u64,
    pub reserved_response_bytes: u64,
    pub observed_response_bytes: u64,
    pub unknown_response_reservation_bytes: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct IoBindingV5 {
    pub limits: SourceIoLimits,
    pub carried: SourceIoTotals,
    pub handoff: Option<String>,
}

impl SourceIoLimits {
    pub(crate) fn validate(&self) -> Result<(), SourceJournalError> {
        if self.max_request_bytes > MAX_SOURCE_REQUEST_BYTES {
            return Err(SourceJournalError::Binding);
        }
        Ok(())
    }
    pub(crate) fn admits(&self, totals: &SourceIoTotals) -> bool {
        totals.reserved_request_bytes <= self.max_total_request_bytes
            && totals.reserved_response_bytes <= self.max_total_response_bytes
    }
    pub(crate) fn narrows(&self, previous: &Self) -> bool {
        self.max_request_bytes <= previous.max_request_bytes
            && self.max_total_request_bytes <= previous.max_total_request_bytes
            && self.max_total_response_bytes <= previous.max_total_response_bytes
    }
}

impl SourceInvocationBinding {
    pub fn io_limits(&self) -> Option<&SourceIoLimits> {
        self.io.as_ref().map(|io| &io.limits)
    }
    pub(crate) fn with_io_limits(
        mut self,
        limits: SourceIoLimits,
        predecessor: Option<&RecoveredSourceCheckpoint>,
    ) -> Result<Self, SourceJournalError> {
        limits.validate()?;
        if self.io.is_some() || !self.is_execution_profile() {
            return Err(SourceJournalError::Binding);
        }
        let (carried, handoff) = match (self.migration(), predecessor) {
            (None, None) => (SourceIoTotals::default(), None),
            (Some(carry), Some(previous)) => {
                let prior_limits = previous
                    .journal
                    .binding
                    .io_limits()
                    .ok_or(SourceJournalError::Binding)?;
                if previous.invocation() != carry.previous_invocation
                    || previous.generation() != carry.previous_generation
                    || previous.chain() != carry.previous_chain
                    || !limits.narrows(prior_limits)
                {
                    return Err(SourceJournalError::Binding);
                }
                let totals = previous
                    .io_totals()
                    .ok_or(SourceJournalError::Binding)?
                    .clone();
                let material = format!(
                    "{}\0{}",
                    self.migration_handoff_digest()
                        .ok_or(SourceJournalError::Binding)?,
                    totals.material()
                );
                (
                    totals,
                    Some(digest(
                        b"semaprax.source-io-handoff.v5\0",
                        material.as_bytes(),
                    )),
                )
            }
            _ => return Err(SourceJournalError::Binding),
        };
        if !limits.admits(&carried) {
            return Err(SourceJournalError::Capacity);
        }
        let material = format!(
            "{}\0{}\0{}\0{}\0{}\0{}",
            self.invocation,
            limits.max_request_bytes,
            limits.max_total_request_bytes,
            limits.max_total_response_bytes,
            carried.material(),
            handoff.as_deref().unwrap_or("")
        );
        self.invocation = digest(ID_DOMAIN, material.as_bytes());
        match &mut self.profile {
            SourceProfile::PricedV4 { pricing, .. }
            | SourceProfile::PricedMigratedV4 { pricing, .. } => {
                *pricing = pricing.rebound_to_invocation(self.invocation.clone())?;
            }
            _ => {}
        }
        self.io = Some(IoBindingV5 {
            limits,
            carried,
            handoff,
        });
        Ok(self)
    }
}

impl SourceIoTotals {
    fn material(&self) -> String {
        format!(
            "{},{},{},{}",
            self.reserved_request_bytes,
            self.reserved_response_bytes,
            self.observed_response_bytes,
            self.unknown_response_reservation_bytes
        )
    }
    fn reserve(
        &mut self,
        limits: &SourceIoLimits,
        request: usize,
        response: usize,
    ) -> Result<(), SourceJournalError> {
        if request > limits.max_request_bytes {
            return Err(SourceJournalError::Capacity);
        }
        let mut next = self.clone();
        next.reserved_request_bytes = next
            .reserved_request_bytes
            .checked_add(request as u64)
            .ok_or(SourceJournalError::Capacity)?;
        next.reserved_response_bytes = next
            .reserved_response_bytes
            .checked_add(response as u64)
            .ok_or(SourceJournalError::Capacity)?;
        next.unknown_response_reservation_bytes = next
            .unknown_response_reservation_bytes
            .checked_add(response as u64)
            .ok_or(SourceJournalError::Capacity)?;
        if !limits.admits(&next) {
            return Err(SourceJournalError::Capacity);
        }
        *self = next;
        Ok(())
    }
}

/// Execution validation has already proved causal order and response bounds.
/// Failure/uncertain response observations leave the entire reservation unknown.
pub(super) fn fold(
    binding: &SourceInvocationBinding,
    entries: &[SourceJournalEntry],
) -> Result<Option<SourceIoTotals>, SourceJournalError> {
    let Some(io) = &binding.io else {
        return Ok(None);
    };
    let mut totals = io.carried.clone();
    let mut pending = None;
    for entry in entries {
        match entry {
            SourceJournalEntry::AttemptIntent {
                turn,
                attempt,
                request_bytes,
                response_limit,
                ..
            } => {
                totals.reserve(&io.limits, *request_bytes, *response_limit)?;
                pending = Some((*turn, *attempt, *response_limit));
            }
            SourceJournalEntry::PricedAttemptIntent(intent) => {
                totals.reserve(&io.limits, intent.request_bytes, intent.response_limit)?;
                pending = Some((intent.turn, intent.attempt, intent.response_limit));
            }
            SourceJournalEntry::PolicyAttemptIntent(intent) => {
                totals.reserve(&io.limits, intent.request_bytes, intent.response_limit)?;
                pending = Some((intent.turn, intent.attempt, intent.response_limit));
            }
            SourceJournalEntry::AttemptSettled {
                turn,
                attempt,
                response,
                ..
            } => {
                let (old_turn, old_attempt, reserved) =
                    pending.take().ok_or(SourceJournalError::Order)?;
                if (*turn, *attempt) != (old_turn, old_attempt) || response.len() > reserved {
                    return Err(SourceJournalError::Order);
                }
                totals.observed_response_bytes = totals
                    .observed_response_bytes
                    .checked_add(response.len() as u64)
                    .ok_or(SourceJournalError::Capacity)?;
                totals.unknown_response_reservation_bytes = totals
                    .unknown_response_reservation_bytes
                    .checked_sub(reserved as u64)
                    .ok_or(SourceJournalError::Order)?;
            }
            SourceJournalEntry::AttemptFailed { .. } => {
                pending = None;
            }
            _ => {}
        }
    }
    Ok(Some(totals))
}
