//! Durable-only model identity admission for the generic retry scheduler.

use crate::agent_deployment::DeploymentModelSelection;
use crate::agent_interaction_schema::CompiledInteractionSchema;
use crate::live_invocation::model_invoke::ModelInvocationRequest;
use crate::provider_adapter_sdk::bridge::adapter_request_for;
use crate::provider_adapter_sdk::ProviderAdapter;

use super::{
    AdapterAttemptPlan, FailureClassifier, RetryAttemptJournal, RetryBackoff, RetryCursor,
    RetryFailoverRun, RetryFailoverScheduler, SchedulerRefusal, MAX_ADAPTER_REQUEST_BYTES,
};

impl<'a> RetryFailoverScheduler<'a> {
    /// Runs the durable profile with exact deployment model rows. A returned
    /// adapter must declare the matching host-selected row before `start`.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn run_compiled_durable_from(
        &mut self,
        schema: &CompiledInteractionSchema,
        invocation_request: &ModelInvocationRequest,
        plan: &AdapterAttemptPlan,
        models: &[DeploymentModelSelection],
        classifier: &mut dyn FailureClassifier,
        backoff: &mut dyn RetryBackoff,
        cursor: RetryCursor,
        journal: Option<&mut dyn RetryAttemptJournal>,
    ) -> RetryFailoverRun {
        if models.len() != self.providers.len()
            || models.iter().enumerate().any(|(index, model)| {
                self.providers
                    .slot(index)
                    .is_none_or(|slot| slot.id != model.provider_id())
            })
        {
            return self.refused(
                Vec::new(),
                Vec::new(),
                None,
                SchedulerRefusal::ModelIdentityMismatch {
                    provider: "deployment".to_owned(),
                    model: "selection".to_owned(),
                },
            );
        }
        if invocation_request.proposal_grammar_digest != schema.schema().digest() {
            return self.refused(
                Vec::new(),
                Vec::new(),
                None,
                SchedulerRefusal::GrammarBindingMismatch,
            );
        }
        if invocation_request
            .task
            .len()
            .saturating_add(invocation_request.observation.len())
            > MAX_ADAPTER_REQUEST_BYTES
        {
            return self.refused(
                Vec::new(),
                Vec::new(),
                None,
                SchedulerRefusal::RequestBytesExceeded {
                    requested: invocation_request
                        .task
                        .len()
                        .saturating_add(invocation_request.observation.len()),
                    max: MAX_ADAPTER_REQUEST_BYTES,
                },
            );
        }
        let provider_schema = schema.provider_json_schema();
        if provider_schema.len() > 262_144 {
            return self.refused(
                Vec::new(),
                Vec::new(),
                None,
                SchedulerRefusal::SchemaBytesExceeded {
                    requested: provider_schema.len(),
                    max: 262_144,
                },
            );
        }
        let adapter_request = adapter_request_for(invocation_request, &provider_schema);
        self.run_projected(
            invocation_request,
            &adapter_request,
            plan,
            classifier,
            backoff,
            Some(schema),
            Some(models),
            cursor,
            journal,
        )
    }
}

pub(super) fn require_model_identity(
    adapter: &dyn ProviderAdapter,
    provider_id: &str,
    expected: &DeploymentModelSelection,
) -> Result<(), SchedulerRefusal> {
    let Some(declared) = adapter.model_identity() else {
        return Err(SchedulerRefusal::ModelIdentityUnavailable {
            provider: provider_id.to_owned(),
        });
    };
    if declared.provider_id != expected.provider_id()
        || declared.model_id != expected.model_id()
        || declared.capabilities.as_slice() != expected.capabilities()
    {
        return Err(SchedulerRefusal::ModelIdentityMismatch {
            provider: provider_id.to_owned(),
            model: expected.model_id().to_owned(),
        });
    }
    Ok(())
}
