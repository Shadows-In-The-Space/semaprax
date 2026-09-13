//! Explicit operator quote for the additive priced source route.
use super::*;
use crate::live_invocation::pricing::ValidatedPricing;

/// Integer operator price, not a provider invoice or currency conversion.
/// The work unit is inherited from the ordinary bound source policy.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SourceLivePricing {
    pub currency: String,
    pub minor_unit_exponent: u8,
    pub price_per_work_unit_minor: i64,
    pub money_ceiling_minor: i64,
}

impl SourceLivePricing {
    pub(crate) fn validated(
        &self,
        work_unit: &str,
    ) -> Result<ValidatedPricing, SourceJournalError> {
        ValidatedPricing::new(
            work_unit.to_owned(),
            self.currency.clone(),
            self.minor_unit_exponent,
            self.price_per_work_unit_minor,
            self.money_ceiling_minor,
        )
        .map_err(|_| SourceJournalError::Binding)
    }
}

impl SourceLivePolicy {
    pub fn binding_priced(
        &self,
        compiled: &CompiledIterativeLifecycle,
        task: &LifecycleTask,
        budget: IterativeBudget,
        pricing: &SourceLivePricing,
    ) -> Result<SourceInvocationBinding, SourceJournalError> {
        let pricing = pricing.validated(&self.unit)?;
        SourceInvocationBinding::bind_priced_execution(
            self.seed(compiled, task, budget)?,
            &Self::evaluator_profile(),
            pricing,
        )
    }
}

impl CompiledIterativeLifecycle {
    /// Runs or recovers only a v4 checkpoint bound to the explicit quote.
    /// Existing unpriced entry points retain their original binding domains.
    pub fn run_live_durable_priced(
        &self,
        request: SourceLiveRequest<'_>,
        pricing: &SourceLivePricing,
        source: &mut dyn driver::ProposalSource,
        read: &mut dyn AgentReadOperation,
        store: &mut dyn CheckpointStore,
    ) -> Result<SourceLiveOutcome, SourceLiveFailure> {
        let binding = request
            .policy
            .binding_priced(self, request.task, request.budget, pricing)
            .map_err(|error| SourceLiveFailure::initial(error, None))?;
        self.run_live_durable_bound(request, source, read, store, binding)
    }
}

impl SourceLivePolicy {
    pub fn binding_with_io_limits(
        &self,
        compiled: &CompiledIterativeLifecycle,
        task: &LifecycleTask,
        budget: IterativeBudget,
        pricing: Option<&SourceLivePricing>,
        limits: &SourceIoLimits,
    ) -> Result<SourceInvocationBinding, SourceJournalError> {
        let binding = match pricing {
            Some(price) => self.binding_priced(compiled, task, budget, price)?,
            None => self.binding(compiled, task, budget)?,
        };
        binding.with_io_limits(limits.clone(), None)
    }
}
impl CompiledIterativeLifecycle {
    pub fn run_live_durable_with_io_limits(
        &self,
        request: SourceLiveRequest<'_>,
        pricing: Option<&SourceLivePricing>,
        limits: &SourceIoLimits,
        source: &mut dyn driver::ProposalSource,
        read: &mut dyn AgentReadOperation,
        store: &mut dyn CheckpointStore,
    ) -> Result<SourceLiveOutcome, SourceLiveFailure> {
        let binding = request
            .policy
            .binding_with_io_limits(self, request.task, request.budget, pricing, limits)
            .map_err(|error| SourceLiveFailure::initial(error, None))?;
        self.run_live_durable_bound(request, source, read, store, binding)
    }
}
