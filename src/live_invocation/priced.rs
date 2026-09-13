//! Additive priced execution for the generic live-invocation kernel.
//!
//! The original journal and `model-request.v1` stay byte-identical. This
//! opt-in route pairs its existing opaque work reservation with an
//! operator-supplied integer money reservation, then persists both in one
//! new envelope before model dispatch. Generic model handlers have no typed
//! currency report, so every settled call remains an explicit unknown charge.

use std::cell::RefCell;
use std::rc::Rc;

use crate::agent_lifecycle::CheckpointStore;
use crate::agent_runtime::AgentCancellation;

use super::identity::{digest, LiveInvocationId};
use super::io::{GenericIoAccounting, GenericIoLimits};
use super::journal::{self, JournalEntry};
use super::kernel::{
    run_live_invocation, LiveInvocationConfig, LiveInvocationHandlers, LiveKernelError,
    LiveKernelRun, TurnEffect, TurnObserver, TurnPolicy,
};
use super::model_invoke::{
    AuthorizationGate, BudgetRefusal, InvocationBudgetHook, InvocationUsage, ModelHandler,
    ModelInvocationRequest, ModelInvokeCapability, ProposalDecoder, ReservedBudget,
};
use super::persistence::{
    encode_priced_envelope_with_handoff, encode_priced_io_envelope, recover_priced_io_journal,
    recover_priced_journal, PricedCheckpointJournalSink, PricedRecoveryError,
    RecoveredPricedIoJournal, RecoveredPricedJournal,
};
use super::pricing::{MonetaryAccounting, ValidatedPricing};

const PRICED_SUCCESSOR_HANDOFF_DOMAIN: &[u8] =
    b"semaprax.live-invocation.priced-successor-handoff.v1\0";
const PRICED_RESERVATION_MISMATCH: &str = "priced_reservation_mismatch";

/// One immutable operator price contract for a generic invocation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GenericPricing {
    pricing: ValidatedPricing,
}

impl GenericPricing {
    /// Binds currency, scale, quote, and ceiling before any attempt is admitted.
    #[must_use]
    pub fn new(pricing: ValidatedPricing) -> Self {
        Self { pricing }
    }

    #[must_use]
    pub fn pricing(&self) -> &ValidatedPricing {
        &self.pricing
    }
}

/// Durable generic state for the opt-in priced route.
pub struct PricedInvocationState {
    journal: Vec<JournalEntry>,
    accounting: MonetaryAccounting,
    generation: u64,
    bound_invocation: Option<String>,
    handoff: Option<PricedSuccessorHandoff>,
    io: Option<GenericIoAccounting>,
}

impl PricedInvocationState {
    /// Starts without any work or monetary reservation.
    #[must_use]
    pub fn fresh(pricing: GenericPricing) -> Self {
        Self {
            journal: Vec::new(),
            accounting: MonetaryAccounting::new(pricing.pricing),
            generation: 0,
            bound_invocation: None,
            handoff: None,
            io: None,
        }
    }

    /// Starts the additive v2 priced-I/O profile. Its limits are explicit and
    /// its journal remains the frozen generic v1 causal vocabulary.
    #[must_use]
    pub fn fresh_with_io(pricing: GenericPricing, limits: GenericIoLimits) -> Self {
        Self {
            journal: Vec::new(),
            accounting: MonetaryAccounting::new(pricing.pricing),
            generation: 0,
            bound_invocation: None,
            handoff: None,
            io: Some(GenericIoAccounting::new(limits)),
        }
    }

    /// Restores only a separately decoded priced envelope.
    pub fn recover(
        document: &str,
        identity: &LiveInvocationId,
    ) -> Result<Self, PricedRecoveryError> {
        let recovered = recover_priced_journal(document, identity)?;
        Ok(Self::from_recovered(recovered, identity.digest()))
    }

    fn from_recovered(recovered: RecoveredPricedJournal, identity: &str) -> Self {
        Self {
            journal: recovered.entries,
            accounting: recovered.accounting,
            generation: recovered.generation,
            bound_invocation: Some(identity.to_owned()),
            handoff: recovered.handoff,
            io: None,
        }
    }

    /// Restores only the additive v2 priced-I/O envelope.
    pub fn recover_with_io(
        document: &str,
        identity: &LiveInvocationId,
    ) -> Result<Self, PricedRecoveryError> {
        let recovered = recover_priced_io_journal(document, identity)?;
        Ok(Self::from_recovered_io(recovered, identity.digest()))
    }

    fn from_recovered_io(recovered: RecoveredPricedIoJournal, identity: &str) -> Self {
        let RecoveredPricedIoJournal { priced, io } = recovered;
        Self {
            journal: priced.entries,
            accounting: priced.accounting,
            generation: priced.generation,
            bound_invocation: Some(identity.to_owned()),
            handoff: priced.handoff,
            io: Some(io),
        }
    }

    /// Starts a distinct successor only after the predecessor fully settled.
    /// The destination inherits conservative exposure as Unknown; it never
    /// rewrites the predecessor journal or relaxes its price identity.
    pub fn successor(
        predecessor: &Self,
        predecessor_identity: &LiveInvocationId,
        destination_identity: &LiveInvocationId,
        destination_pricing: GenericPricing,
    ) -> Result<Self, PricedMigrationError> {
        if predecessor_identity == destination_identity {
            return Err(PricedMigrationError::IdentityCollision);
        }
        if predecessor.io.is_some() {
            return Err(PricedMigrationError::IoProfileRequired);
        }
        if predecessor.bound_invocation.as_deref() != Some(predecessor_identity.digest())
            || !journal::validate(&predecessor.journal, predecessor_identity.digest())
                .map_err(PricedMigrationError::InvalidPredecessor)?
                .terminal
        {
            return Err(PricedMigrationError::PredecessorNotTerminal);
        }
        let carry = predecessor
            .accounting
            .total_carry()
            .map_err(|_| PricedMigrationError::Pricing)?;
        carry
            .validate_destination(destination_pricing.pricing())
            .map_err(|_| PricedMigrationError::Pricing)?;
        let handoff = PricedSuccessorHandoff::new(
            predecessor_identity.digest(),
            destination_identity.digest(),
            predecessor.generation,
            journal::chain(&predecessor.journal),
            carry.clone(),
        );
        let accounting =
            MonetaryAccounting::resume_with_priced_carry(destination_pricing.pricing, carry, &[])
                .map_err(|_| PricedMigrationError::Pricing)?;
        Ok(Self {
            journal: Vec::new(),
            accounting,
            generation: 0,
            bound_invocation: Some(destination_identity.digest().to_owned()),
            handoff: Some(handoff),
            io: None,
        })
    }

    /// Starts a successor of the priced-I/O profile with only non-loosening
    /// I/O limits and the full preceding unknown exposure carried forward.
    pub fn successor_with_io(
        predecessor: &Self,
        predecessor_identity: &LiveInvocationId,
        destination_identity: &LiveInvocationId,
        destination_pricing: GenericPricing,
        destination_io: GenericIoLimits,
    ) -> Result<Self, PricedMigrationError> {
        let previous_io = predecessor
            .io
            .as_ref()
            .ok_or(PricedMigrationError::IoProfileRequired)?;
        let shadow = Self {
            journal: predecessor.journal.clone(),
            accounting: predecessor.accounting.clone(),
            generation: predecessor.generation,
            bound_invocation: predecessor.bound_invocation.clone(),
            handoff: predecessor.handoff.clone(),
            io: None,
        };
        let carried_io = previous_io
            .successor_bound(
                predecessor_identity.digest(),
                destination_identity.digest(),
                predecessor.generation,
                journal::chain(&predecessor.journal),
                destination_io,
            )
            .map_err(|_| PricedMigrationError::Io)?;
        let mut successor = Self::successor(
            &shadow,
            predecessor_identity,
            destination_identity,
            destination_pricing,
        )?;
        successor.io = Some(carried_io);
        Ok(successor)
    }

    #[must_use]
    pub fn journal(&self) -> &[JournalEntry] {
        &self.journal
    }

    #[must_use]
    pub fn generation(&self) -> u64 {
        self.generation
    }
}

/// A refused priced successor. This narrow route accepts only a completed,
/// exact predecessor and a non-loosening quote.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PricedMigrationError {
    IdentityCollision,
    InvalidPredecessor(journal::JournalError),
    PredecessorNotTerminal,
    Pricing,
    IoProfileRequired,
    Io,
}

/// A work ledger that can quote the exact amount it will reserve for this
/// request. The priced route refuses ordinary hooks because it must prepare
/// monetary admission before mutating the work ledger; an implementation
/// returning a different amount from `reserve` violates this explicit host
/// contract. The runner retains the admitted quote, durably closes that
/// intent, and fails closed before model dispatch; it cannot roll an opaque
/// host ledger back.
pub trait PricedWorkBudgetHook: InvocationBudgetHook {
    fn quote_priced_reservation(
        &self,
        request: &ModelInvocationRequest,
    ) -> Result<ReservedBudget, BudgetRefusal>;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PricedSuccessorHandoff {
    pub(crate) predecessor_invocation: String,
    pub(crate) destination_invocation: String,
    pub(crate) predecessor_generation: u64,
    pub(crate) predecessor_chain: String,
    pub(crate) predecessor_pricing: ValidatedPricing,
    pub(crate) predecessor_carry: super::pricing::PricedMonetaryCarry,
    pub(crate) handoff_digest: String,
}

impl PricedSuccessorHandoff {
    pub(crate) fn new(
        predecessor_invocation: &str,
        destination_invocation: &str,
        predecessor_generation: u64,
        predecessor_chain: String,
        predecessor_carry: super::pricing::PricedMonetaryCarry,
    ) -> Self {
        let predecessor_pricing = predecessor_carry.pricing().clone();
        let mut handoff = Self {
            predecessor_invocation: predecessor_invocation.to_owned(),
            destination_invocation: destination_invocation.to_owned(),
            predecessor_generation,
            predecessor_chain,
            predecessor_pricing,
            predecessor_carry,
            handoff_digest: String::new(),
        };
        handoff.handoff_digest = handoff.digest();
        handoff
    }

    pub(crate) fn digest(&self) -> String {
        let pricing = &self.predecessor_pricing;
        let carry = &self.predecessor_carry;
        digest(
            PRICED_SUCCESSOR_HANDOFF_DOMAIN,
            format!(
                "{{\"schema\":\"semaprax.live-invocation.priced-successor-handoff.v1\",\"predecessor_invocation\":{},\"destination_invocation\":{},\"predecessor_generation\":{},\"predecessor_chain\":{},\"work_unit\":{},\"currency\":{},\"minor_unit_exponent\":{},\"price_per_work_unit_minor\":{},\"previous_ceiling_minor\":{},\"reserved_minor\":{},\"observed_minor\":{},\"unknown_reservation_minor\":{},\"observed_over_reservation_minor\":{},\"next_ordinal\":{}}}",
                crate::diagnostic::quote_json(&self.predecessor_invocation),
                crate::diagnostic::quote_json(&self.destination_invocation),
                self.predecessor_generation,
                crate::diagnostic::quote_json(&self.predecessor_chain),
                crate::diagnostic::quote_json(pricing.work_unit()),
                crate::diagnostic::quote_json(pricing.currency()),
                pricing.minor_unit_exponent(),
                pricing.price_per_work_unit_minor(),
                pricing.ceiling_minor(),
                carry.reserved_minor(),
                carry.observed_minor(),
                carry.unknown_reservation_minor(),
                carry.observed_over_reservation_minor(),
                carry.next_ordinal(),
            )
            .as_bytes(),
        )
    }

    pub(crate) fn is_bound_to(
        &self,
        invocation: &str,
        carry: &super::pricing::PricedMonetaryCarry,
    ) -> bool {
        self.destination_invocation == invocation
            && self.handoff_digest == self.digest()
            && self.predecessor_carry.reserved_minor() == carry.reserved_minor()
            && self.predecessor_carry.observed_minor() == carry.observed_minor()
            && self.predecessor_carry.unknown_reservation_minor()
                == carry.unknown_reservation_minor()
            && self.predecessor_carry.observed_over_reservation_minor()
                == carry.observed_over_reservation_minor()
            && self.predecessor_carry.next_ordinal() == carry.next_ordinal()
    }
}

/// The injected seams for the priced route. It intentionally has no ordinary
/// `JournalSink`: a priced attempt needs the priced envelope sink below.
pub struct PricedLiveInvocationHandlers<'a> {
    pub capability: &'a ModelInvokeCapability,
    pub handler: &'a mut dyn ModelHandler,
    pub decoder: &'a mut dyn ProposalDecoder,
    pub gate: &'a mut dyn AuthorizationGate,
    pub work_budget: &'a mut dyn PricedWorkBudgetHook,
    pub observer: &'a mut dyn TurnObserver,
    pub policy: &'a mut dyn TurnPolicy,
    pub effect: Option<&'a mut dyn TurnEffect>,
    pub store: &'a mut dyn CheckpointStore,
}

/// The output of actual priced kernel execution and its canonical receipt.
pub struct PricedLiveKernelRun {
    pub run: LiveKernelRun,
    pub state: PricedInvocationState,
    receipt: String,
}

impl PricedLiveKernelRun {
    /// Returns the authority-free receipt bound to this exact journal prefix.
    #[must_use]
    pub fn receipt(&self) -> &str {
        &self.receipt
    }
}

/// Runs the existing generic kernel with paired durable money accounting.
///
/// `work_budget` remains the authority on generic work units. This wrapper
/// only accepts an operator pricing contract whose work-unit name is bound by
/// that contract; it does not relabel request bytes or provider usage as money.
pub fn run_priced_live_invocation(
    config: &LiveInvocationConfig<'_>,
    mut state: PricedInvocationState,
    handlers: &mut PricedLiveInvocationHandlers<'_>,
    cancellation: &AgentCancellation,
) -> Result<PricedLiveKernelRun, LiveKernelError> {
    if state
        .bound_invocation
        .as_deref()
        .is_some_and(|bound| bound != config.identity.digest())
    {
        return Err(LiveKernelError::InvocationIdentityDrift);
    }
    let accounting = Rc::new(RefCell::new(state.accounting));
    let io = state.io.map(|value| Rc::new(RefCell::new(value)));
    let mut budget = PairedBudgetHook {
        work: &mut *handlers.work_budget,
        accounting: Rc::clone(&accounting),
        io: io.as_ref().map(Rc::clone),
        post_reservation_refusal: None,
    };
    let mut sink = if state.generation == 0 {
        PricedCheckpointJournalSink::new(
            &mut *handlers.store,
            config.identity.digest(),
            Rc::clone(&accounting),
            io.as_ref().map(Rc::clone),
            state.handoff.clone(),
        )
    } else {
        PricedCheckpointJournalSink::resume(
            &mut *handlers.store,
            config.identity.digest(),
            state.generation,
            Rc::clone(&accounting),
            io.as_ref().map(Rc::clone),
            state.handoff.clone(),
        )
    };
    let mut kernel_handlers = LiveInvocationHandlers {
        capability: handlers.capability,
        handler: &mut *handlers.handler,
        decoder: &mut *handlers.decoder,
        gate: &mut *handlers.gate,
        budget: &mut budget,
        observer: &mut *handlers.observer,
        policy: &mut *handlers.policy,
        // `as_deref_mut` preserves the handlers lifetime here, which would
        // incorrectly require the local paired budget and sink to live that
        // long. Reborrow the optional host effect only for this kernel call.
        effect: match handlers.effect.as_mut() {
            Some(effect) => Some(&mut **effect),
            None => None,
        },
        sink: Some(&mut sink),
    };
    let run = run_live_invocation(config, state.journal, &mut kernel_handlers, cancellation)?;
    let _ = &kernel_handlers;
    state.journal = run.journal.clone();
    state.generation = sink.generation();
    state.bound_invocation = Some(config.identity.digest().to_owned());
    let _ = &sink;
    let _ = &budget;
    state.accounting = Rc::try_unwrap(accounting)
        .map_err(|_| LiveKernelError::PersistenceFailed {
            dispatched: run.dispatched,
        })?
        .into_inner();
    state.io = io
        .map(Rc::try_unwrap)
        .transpose()
        .map_err(|_| LiveKernelError::PersistenceFailed {
            dispatched: run.dispatched,
        })?
        .map(RefCell::into_inner);
    let receipt = match state.io.as_ref() {
        Some(io) => encode_priced_io_envelope(
            config.identity.digest(),
            state.generation,
            &state.journal,
            &state.accounting,
            state.handoff.as_ref(),
            io,
        ),
        None => encode_priced_envelope_with_handoff(
            config.identity.digest(),
            state.generation,
            &state.journal,
            &state.accounting,
            state.handoff.as_ref(),
        ),
    }
    .map_err(|_| LiveKernelError::PersistenceFailed {
        dispatched: run.dispatched,
    })?;
    Ok(PricedLiveKernelRun {
        run,
        state,
        receipt,
    })
}

struct PairedBudgetHook<'a> {
    work: &'a mut dyn PricedWorkBudgetHook,
    accounting: Rc<RefCell<MonetaryAccounting>>,
    io: Option<Rc<RefCell<GenericIoAccounting>>>,
    /// A dishonest host may mutate its ledger and return an amount different
    /// from its prior quote. The generic kernel must first durably retain the
    /// quoted reservation, then refuse before dispatch; it cannot roll an
    /// arbitrary host ledger back.
    post_reservation_refusal: Option<BudgetRefusal>,
}

impl InvocationBudgetHook for PairedBudgetHook<'_> {
    fn check_deadline(&self) -> Result<(), BudgetRefusal> {
        self.work.check_deadline()
    }

    fn check_pre_dispatch(&self) -> Result<(), BudgetRefusal> {
        if let Some(refusal) = &self.post_reservation_refusal {
            return Err(refusal.clone());
        }
        self.work.check_deadline()
    }

    fn reserve(
        &mut self,
        request: &ModelInvocationRequest,
    ) -> Result<ReservedBudget, BudgetRefusal> {
        let quoted = self.work.quote_priced_reservation(request)?;
        let work_unit = {
            let accounting = self.accounting.borrow();
            let work_unit = accounting.pricing().work_unit().to_owned();
            accounting.preflight_reserve(&work_unit, quoted.amount)?;
            work_unit
        };
        // Build the new monetary state before the work ledger mutates. A
        // failed quote/capacity check therefore cannot leave charged work
        // without a matching money reservation.
        let mut prepared = self.accounting.borrow().clone();
        prepared.reserve(&work_unit, quoted.amount)?;
        let mut committed_request = request.clone();
        committed_request.effective_budget = quoted.amount;
        let canonical_request = committed_request.canonical_json();
        let request_digest = committed_request.digest();
        let mut prepared_io = match &self.io {
            Some(io) => {
                let mut prepared = io.borrow().clone();
                prepared.reserve(
                    request.turn,
                    request_digest,
                    canonical_request,
                    request.max_response_bytes,
                )?;
                Some(prepared)
            }
            None => None,
        };
        let reserved = self.work.reserve(request)?;
        if reserved.amount != quoted.amount {
            // The quoted reservation is the only amount whose admission and
            // request binding were checked before the host mutation. Retain
            // it conservatively and make the kernel close the durable intent
            // before it can dispatch. A host that charged a different amount
            // has violated `PricedWorkBudgetHook`; generic code has no
            // authority to invent a rollback for that external ledger.
            *self.accounting.borrow_mut() = prepared;
            if let (Some(io), Some(prepared)) = (&self.io, prepared_io.take()) {
                *io.borrow_mut() = prepared;
            }
            self.post_reservation_refusal =
                Some(BudgetRefusal(PRICED_RESERVATION_MISMATCH.to_owned()));
            return Ok(quoted);
        }
        *self.accounting.borrow_mut() = prepared;
        if let (Some(io), Some(prepared)) = (&self.io, prepared_io.take()) {
            *io.borrow_mut() = prepared;
        }
        Ok(reserved)
    }

    fn record(&mut self, usage: &InvocationUsage) {
        self.work.record(usage);
        if let Some(io) = &self.io {
            let _ = io
                .borrow_mut()
                .observe(usage.turn, usage.response_bytes, usage.failed);
        }
    }
}

#[cfg(test)]
#[path = "priced/tests.rs"]
mod tests;
