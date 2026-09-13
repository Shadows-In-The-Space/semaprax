//! Additive byte-accounted durable route over the existing retry scheduler.
//! V2 wire and entry points remain unchanged. Each byte reservation is persisted
//! with its attempt intent before factory creation; recovery never refunds it.

use crate::agent_interaction_schema::CompiledInteractionSchema;
use crate::agent_lifecycle::CheckpointStore;
use crate::agent_runtime::AgentCancellation;
use crate::live_invocation::budget::InvocationClock;
use crate::live_invocation::model_invoke::ModelInvocationRequest;
use crate::live_invocation::persistence::policy_v3::PolicyCheckpointJournalV3;
use crate::live_invocation::policy_journal::PolicyRecovery;
use crate::live_invocation::policy_journal_v3::PolicyJournalV3;
use crate::live_invocation::policy_kernel::{DurablePolicyRun, DurablePolicyRunError};
use crate::model_budget_policy::retry::{
    AdapterAttemptPlan, FailureClassifier, ProviderAdapterFactory, RetryBackoff, RetryCursor,
    RetryFailoverOutcome, RetryFailoverScheduler,
};
use crate::model_budget_policy::DurablePolicyBinding;
use crate::provider_adapter_sdk::AdapterInvocationCapability;

#[allow(clippy::too_many_arguments)]
pub fn run_durable_byte_policy_invocation(
    binding: &DurablePolicyBinding,
    byte_budget: crate::model_budget_policy::DurableByteBudget,
    schema: &CompiledInteractionSchema,
    request: &ModelInvocationRequest,
    plan: &AdapterAttemptPlan,
    clock: &dyn InvocationClock,
    cancellation: &AgentCancellation,
    capability: AdapterInvocationCapability,
    factory: &mut dyn ProviderAdapterFactory,
    classifier: &mut dyn FailureClassifier,
    backoff: &mut dyn RetryBackoff,
    store: &mut dyn CheckpointStore,
    recovered: Option<(&str, u64)>,
) -> DurablePolicyRun {
    if request.deployment_binding != binding.deployment_policy()
        || !binding.request_matches(schema, request)
    {
        return DurablePolicyRun::Refused(DurablePolicyRunError::RequestBindingMismatch);
    }
    // Derive the exact SDK envelope with the scheduler's own bounded projector.
    // The V3 journal may use the plan's sizes only after this equality proof.
    let exact_plan = match AdapterAttemptPlan::for_compiled(
        schema,
        request,
        plan.context_tokens,
        plan.requested_output_tokens,
        plan.estimated_cost_micros,
        plan.max_polls,
    ) {
        Ok(plan) => plan,
        Err(error) => return DurablePolicyRun::Refused(DurablePolicyRunError::Scheduler(error)),
    };
    if exact_plan.required.max_request_bytes != plan.required.max_request_bytes
        || exact_plan.required.max_response_bytes != plan.required.max_response_bytes
    {
        return DurablePolicyRun::Refused(DurablePolicyRunError::RequestBindingMismatch);
    }
    let byte_budget = match binding.narrow_byte_budget(byte_budget) {
        Ok(budget) => budget,
        Err(_) => return DurablePolicyRun::Refused(DurablePolicyRunError::RequestBindingMismatch),
    };
    let (journal, generation, reservations, cursor) = match recovered {
        None => (
            match PolicyJournalV3::new(binding, request, plan, byte_budget) {
                Ok(journal) => journal,
                Err(_) => return DurablePolicyRun::Refused(DurablePolicyRunError::Recovery),
            },
            0,
            Vec::new(),
            RetryCursor::FRESH,
        ),
        Some((document, generation)) => {
            match PolicyJournalV3::recover(document, binding, request, plan, byte_budget) {
                Ok((_, PolicyRecovery::Settled(response))) => {
                    if schema.decode(&response).is_err() {
                        return DurablePolicyRun::Refused(DurablePolicyRunError::Recovery);
                    }
                    return DurablePolicyRun::Replayed(response);
                }
                Ok((_, PolicyRecovery::Uncertain)) => return DurablePolicyRun::Uncertain,
                Ok((
                    journal,
                    PolicyRecovery::Continue {
                        reservations,
                        cursor,
                    },
                )) => (journal, generation, reservations, cursor),
                Err(_) => return DurablePolicyRun::Refused(DurablePolicyRunError::Recovery),
            }
        }
    };
    if !binding.check_clock(clock) {
        return DurablePolicyRun::Refused(DurablePolicyRunError::DeadlineExceeded);
    }
    let mut checkpoint = if generation == 0 {
        PolicyCheckpointJournalV3::new(store, journal)
    } else {
        PolicyCheckpointJournalV3::resume(store, journal, generation)
    };
    let scheduler = if reservations.is_empty() {
        RetryFailoverScheduler::new(
            binding.limits(),
            binding.policy().clone(),
            binding.deadline_millis(),
            clock,
            cancellation,
            capability,
            factory,
        )
    } else {
        RetryFailoverScheduler::resume(
            binding.limits(),
            binding.policy().clone(),
            binding.deadline_millis(),
            clock,
            cancellation,
            capability,
            factory,
            &reservations,
        )
    };
    let mut scheduler = match scheduler {
        Ok(scheduler) => scheduler,
        Err(refusal) => {
            return DurablePolicyRun::Refused(DurablePolicyRunError::Scheduler(refusal))
        }
    };
    let run = match binding.model_selections() {
        Some(models) => scheduler.run_compiled_durable_from(
            schema,
            request,
            plan,
            models,
            classifier,
            backoff,
            cursor,
            Some(&mut checkpoint),
        ),
        None => scheduler.run_compiled_from(
            schema,
            request,
            plan,
            classifier,
            backoff,
            cursor,
            Some(&mut checkpoint),
        ),
    };
    match run.outcome {
        RetryFailoverOutcome::Settled { response_bytes, .. } => {
            DurablePolicyRun::Settled(response_bytes)
        }
        RetryFailoverOutcome::Failed { result, .. } => match result {
            crate::model_budget_policy::retry::AdapterAttemptResult::Failed {
                classification,
                ..
            } if !crate::model_budget_policy::retry_is_permitted(classification) => {
                DurablePolicyRun::Uncertain
            }
            crate::model_budget_policy::retry::AdapterAttemptResult::Failed {
                refusal: Some(refusal),
                ..
            } => DurablePolicyRun::Refused(DurablePolicyRunError::Scheduler(refusal)),
            _ => DurablePolicyRun::Uncertain,
        },
        RetryFailoverOutcome::Refused { refusal, .. } => {
            DurablePolicyRun::Refused(DurablePolicyRunError::Scheduler(refusal))
        }
    }
}
