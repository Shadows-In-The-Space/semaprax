//! Additive V6 Source Live binding for a host-validated model policy.
use super::*;
use crate::live_invocation::source_journal::{SourceIoLimits, SourcePolicyBindingV6};

impl SourceLivePolicy {
    /// Binds the V6 policy identity before any source checkpoint is opened.
    /// The caller supplies a validated, explicit provider policy; this does
    /// not price, reserve, or permit a provider operation.
    pub(crate) fn binding_with_model_policy(
        &self,
        compiled: &CompiledIterativeLifecycle,
        task: &LifecycleTask,
        budget: IterativeBudget,
        policy: SourcePolicyBindingV6,
    ) -> Result<SourceInvocationBinding, SourceJournalError> {
        SourceInvocationBinding::bind_policy_execution(
            self.seed(compiled, task, budget)?,
            &Self::evaluator_profile(),
            policy,
        )
    }

    /// Adds the existing V5 cumulative I/O limits to the V6 model-policy
    /// identity. The limits are therefore journal facts before an attempt can
    /// acknowledge its provider request.
    pub(crate) fn binding_with_model_policy_and_io_limits(
        &self,
        compiled: &CompiledIterativeLifecycle,
        task: &LifecycleTask,
        budget: IterativeBudget,
        policy: SourcePolicyBindingV6,
        limits: &SourceIoLimits,
    ) -> Result<SourceInvocationBinding, SourceJournalError> {
        self.binding_with_model_policy(compiled, task, budget, policy)?
            .with_io_limits(limits.clone(), None)
    }
}

impl CompiledIterativeLifecycle {
    /// Internal typed-adapter entry for an acknowledged V6 model-policy
    /// journal. Older source routes retain their frozen bindings and wire.
    pub(crate) fn run_live_durable_with_model_policy(
        &self,
        request: SourceLiveRequest<'_>,
        policy: SourcePolicyBindingV6,
        source: &mut dyn driver::ProposalSource,
        driver: &mut dyn driver::IterativeDriver,
        store: &mut dyn CheckpointStore,
    ) -> Result<SourceLiveOutcome, SourceLiveFailure> {
        let binding = request
            .policy
            .binding_with_model_policy(self, request.task, request.budget, policy)
            .map_err(|error| SourceLiveFailure::initial(error, None))?;
        self.run_live_durable_bound(request, source, driver, store, binding)
    }

    /// V6 model-policy route with cumulative provider I/O limits in the same
    /// checkpoint identity.
    pub(crate) fn run_live_durable_with_model_policy_and_io_limits(
        &self,
        request: SourceLiveRequest<'_>,
        policy: SourcePolicyBindingV6,
        limits: &SourceIoLimits,
        source: &mut dyn driver::ProposalSource,
        driver: &mut dyn driver::IterativeDriver,
        store: &mut dyn CheckpointStore,
    ) -> Result<SourceLiveOutcome, SourceLiveFailure> {
        let binding = request
            .policy
            .binding_with_model_policy_and_io_limits(
                self,
                request.task,
                request.budget,
                policy,
                limits,
            )
            .map_err(|error| SourceLiveFailure::initial(error, None))?;
        self.run_live_durable_bound(request, source, driver, store, binding)
    }
}
