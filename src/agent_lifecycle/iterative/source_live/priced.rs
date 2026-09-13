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

impl SourceLivePolicy {
    pub fn binding_priced(
        &self,
        compiled: &CompiledIterativeLifecycle,
        task: &LifecycleTask,
        budget: IterativeBudget,
        pricing: &SourceLivePricing,
    ) -> Result<SourceInvocationBinding, SourceJournalError> {
        let pricing = ValidatedPricing::new(
            self.unit.clone(),
            pricing.currency.clone(),
            pricing.minor_unit_exponent,
            pricing.price_per_work_unit_minor,
            pricing.money_ceiling_minor,
        )
        .map_err(|_| SourceJournalError::Binding)?;
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
