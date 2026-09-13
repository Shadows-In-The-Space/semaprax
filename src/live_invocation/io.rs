//! Checked, conservative provider-I/O accounting for the generic priced route.
//!
//! This is intentionally a new additive profile. The generic causal journal
//! remains byte-identical; its v1 request intent has only a digest, so the
//! v2 priced-I/O envelope carries the request and response reservations that
//! recovery must replay independently.

use super::identity::digest;
use super::model_invoke::BudgetRefusal;

const IO_HANDOFF_DOMAIN: &[u8] = b"semaprax.live-invocation.priced-io-handoff.v2\0";

pub const GENERIC_IO_CAPACITY: &str = "generic_io_capacity";
pub const GENERIC_IO_REQUEST_LIMIT: &str = "generic_io_request_limit";
pub const GENERIC_IO_OBSERVATION: &str = "generic_io_observation";

/// Explicit bounds for one priced generic invocation. A request count is the
/// exact canonical `model-request.v1` document, excluding only external host
/// transport framing that this generic kernel never owns.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GenericIoLimits {
    pub max_request_bytes: usize,
    pub max_total_request_bytes: u64,
    pub max_total_response_bytes: u64,
}

/// Conservative totals. Failed or uncertain responses retain their complete
/// predispatch response reservation as unknown exposure.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct GenericIoTotals {
    pub reserved_request_bytes: u64,
    pub reserved_response_bytes: u64,
    pub observed_response_bytes: u64,
    pub unknown_response_reservation_bytes: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct GenericIoAttempt {
    pub(crate) turn: u32,
    pub(crate) request_digest: String,
    pub(crate) canonical_request: String,
    pub(crate) request_bytes: usize,
    pub(crate) response_limit: usize,
    pub(crate) observed_response_bytes: Option<usize>,
}

#[derive(Clone, Debug)]
pub(crate) struct GenericIoAccounting {
    limits: GenericIoLimits,
    carry: GenericIoTotals,
    attempts: Vec<GenericIoAttempt>,
    handoff: Option<GenericIoHandoff>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct GenericIoHandoff {
    pub(crate) predecessor_invocation: String,
    pub(crate) destination_invocation: String,
    pub(crate) predecessor_generation: u64,
    pub(crate) predecessor_chain: String,
    pub(crate) predecessor_limits: GenericIoLimits,
    pub(crate) predecessor_totals: GenericIoTotals,
    pub(crate) handoff_digest: String,
}

impl GenericIoLimits {
    pub(crate) fn admits(&self, totals: &GenericIoTotals) -> bool {
        totals.reserved_request_bytes <= self.max_total_request_bytes
            && totals.reserved_response_bytes <= self.max_total_response_bytes
    }

    pub(crate) fn narrows(&self, previous: &Self) -> bool {
        self.max_request_bytes <= previous.max_request_bytes
            && self.max_total_request_bytes <= previous.max_total_request_bytes
            && self.max_total_response_bytes <= previous.max_total_response_bytes
    }
}

impl GenericIoAccounting {
    pub(crate) fn new(limits: GenericIoLimits) -> Self {
        Self {
            limits,
            carry: GenericIoTotals::default(),
            attempts: Vec::new(),
            handoff: None,
        }
    }

    pub(crate) fn with_carry(
        limits: GenericIoLimits,
        previous_limits: &GenericIoLimits,
        carry: GenericIoTotals,
    ) -> Result<Self, BudgetRefusal> {
        if !limits.narrows(previous_limits) || !limits.admits(&carry) {
            return Err(refusal(GENERIC_IO_CAPACITY));
        }
        Ok(Self {
            limits,
            carry,
            attempts: Vec::new(),
            handoff: None,
        })
    }

    pub(crate) fn limits(&self) -> &GenericIoLimits {
        &self.limits
    }

    pub(crate) fn carry(&self) -> &GenericIoTotals {
        &self.carry
    }

    pub(crate) fn attempts(&self) -> &[GenericIoAttempt] {
        &self.attempts
    }

    pub(crate) fn from_parts(
        limits: GenericIoLimits,
        carry: GenericIoTotals,
        attempts: Vec<GenericIoAttempt>,
        handoff: Option<GenericIoHandoff>,
    ) -> Result<Self, BudgetRefusal> {
        let accounting = Self {
            limits,
            carry,
            attempts,
            handoff,
        };
        accounting.totals()?;
        Ok(accounting)
    }

    pub(crate) fn successor_bound(
        &self,
        predecessor_invocation: &str,
        destination_invocation: &str,
        predecessor_generation: u64,
        predecessor_chain: String,
        limits: GenericIoLimits,
    ) -> Result<Self, BudgetRefusal> {
        let totals = self.totals()?;
        let mut successor = Self::with_carry(limits, &self.limits, totals.clone())?;
        successor.handoff = Some(GenericIoHandoff::new(
            predecessor_invocation,
            destination_invocation,
            predecessor_generation,
            predecessor_chain,
            self.limits.clone(),
            totals,
        ));
        Ok(successor)
    }

    pub(crate) fn handoff(&self) -> Option<&GenericIoHandoff> {
        self.handoff.as_ref()
    }

    pub(crate) fn preflight(
        &self,
        request_bytes: usize,
        response_limit: usize,
    ) -> Result<(), BudgetRefusal> {
        let mut next = self.totals()?;
        reserve(&mut next, &self.limits, request_bytes, response_limit)
    }

    pub(crate) fn reserve(
        &mut self,
        turn: u32,
        request_digest: String,
        canonical_request: String,
        response_limit: usize,
    ) -> Result<(), BudgetRefusal> {
        let request_bytes = canonical_request.len();
        self.preflight(request_bytes, response_limit)?;
        self.attempts.push(GenericIoAttempt {
            turn,
            request_digest,
            canonical_request,
            request_bytes,
            response_limit,
            observed_response_bytes: None,
        });
        Ok(())
    }

    pub(crate) fn observe(
        &mut self,
        turn: u32,
        response_bytes: usize,
        failed: bool,
    ) -> Result<(), BudgetRefusal> {
        if failed {
            return Ok(());
        }
        let attempt = self
            .attempts
            .iter_mut()
            .rev()
            .find(|attempt| attempt.turn == turn && attempt.observed_response_bytes.is_none())
            .ok_or_else(|| refusal(GENERIC_IO_OBSERVATION))?;
        if response_bytes > attempt.response_limit {
            return Err(refusal(GENERIC_IO_OBSERVATION));
        }
        attempt.observed_response_bytes = Some(response_bytes);
        Ok(())
    }

    pub(crate) fn totals(&self) -> Result<GenericIoTotals, BudgetRefusal> {
        let mut totals = self.carry.clone();
        for attempt in &self.attempts {
            reserve(
                &mut totals,
                &self.limits,
                attempt.request_bytes,
                attempt.response_limit,
            )?;
            if let Some(observed) = attempt.observed_response_bytes {
                totals.observed_response_bytes = totals
                    .observed_response_bytes
                    .checked_add(u64::try_from(observed).map_err(|_| refusal(GENERIC_IO_CAPACITY))?)
                    .ok_or_else(|| refusal(GENERIC_IO_CAPACITY))?;
                totals.unknown_response_reservation_bytes = totals
                    .unknown_response_reservation_bytes
                    .checked_sub(
                        u64::try_from(attempt.response_limit)
                            .map_err(|_| refusal(GENERIC_IO_CAPACITY))?,
                    )
                    .ok_or_else(|| refusal(GENERIC_IO_OBSERVATION))?;
            }
        }
        Ok(totals)
    }
}

impl GenericIoHandoff {
    fn new(
        predecessor_invocation: &str,
        destination_invocation: &str,
        predecessor_generation: u64,
        predecessor_chain: String,
        predecessor_limits: GenericIoLimits,
        predecessor_totals: GenericIoTotals,
    ) -> Self {
        let mut handoff = Self {
            predecessor_invocation: predecessor_invocation.to_owned(),
            destination_invocation: destination_invocation.to_owned(),
            predecessor_generation,
            predecessor_chain,
            predecessor_limits,
            predecessor_totals,
            handoff_digest: String::new(),
        };
        handoff.handoff_digest = handoff.digest();
        handoff
    }

    pub(crate) fn digest(&self) -> String {
        digest(
            IO_HANDOFF_DOMAIN,
            format!(
                "{}\0{}\0{}\0{}\0{},{},{}\0{},{},{},{}",
                self.predecessor_invocation,
                self.destination_invocation,
                self.predecessor_generation,
                self.predecessor_chain,
                self.predecessor_limits.max_request_bytes,
                self.predecessor_limits.max_total_request_bytes,
                self.predecessor_limits.max_total_response_bytes,
                self.predecessor_totals.reserved_request_bytes,
                self.predecessor_totals.reserved_response_bytes,
                self.predecessor_totals.observed_response_bytes,
                self.predecessor_totals.unknown_response_reservation_bytes,
            )
            .as_bytes(),
        )
    }

    pub(crate) fn validates(
        &self,
        destination: &str,
        limits: &GenericIoLimits,
        carry: &GenericIoTotals,
    ) -> bool {
        self.destination_invocation == destination
            && self.handoff_digest == self.digest()
            && limits.narrows(&self.predecessor_limits)
            && carry == &self.predecessor_totals
            && limits.admits(carry)
    }
}

fn reserve(
    totals: &mut GenericIoTotals,
    limits: &GenericIoLimits,
    request_bytes: usize,
    response_limit: usize,
) -> Result<(), BudgetRefusal> {
    if request_bytes > limits.max_request_bytes {
        return Err(refusal(GENERIC_IO_REQUEST_LIMIT));
    }
    let request = u64::try_from(request_bytes).map_err(|_| refusal(GENERIC_IO_CAPACITY))?;
    let response = u64::try_from(response_limit).map_err(|_| refusal(GENERIC_IO_CAPACITY))?;
    let mut next = totals.clone();
    next.reserved_request_bytes = next
        .reserved_request_bytes
        .checked_add(request)
        .ok_or_else(|| refusal(GENERIC_IO_CAPACITY))?;
    next.reserved_response_bytes = next
        .reserved_response_bytes
        .checked_add(response)
        .ok_or_else(|| refusal(GENERIC_IO_CAPACITY))?;
    next.unknown_response_reservation_bytes = next
        .unknown_response_reservation_bytes
        .checked_add(response)
        .ok_or_else(|| refusal(GENERIC_IO_CAPACITY))?;
    if !limits.admits(&next) {
        return Err(refusal(GENERIC_IO_CAPACITY));
    }
    *totals = next;
    Ok(())
}

fn refusal(reason: &str) -> BudgetRefusal {
    BudgetRefusal(reason.to_owned())
}

#[cfg(test)]
#[path = "io/tests.rs"]
mod tests;
