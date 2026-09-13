//! Live source-proposal entry for the checked typed-effect runner.
//!
//! Proposal acquisition remains outside the typed effect boundary. This
//! adapter receives only the source driver's accepted canonical proposal at
//! its `before_effect` boundary, then uses the same Dispatch as frozen input.

use super::*;
use crate::agent_lifecycle::iterative::driver::{EffectContext, IterativeDriver, ProposalSource};
use crate::agent_lifecycle::iterative::source_live::{
    PreparedSourceLiveMigration, SourceLiveFailure, SourceLiveOutcome, SourceLiveRequest,
};
use crate::agent_lifecycle::CheckpointStore;
use crate::live_invocation::source_journal::{SourceIoLimits, SourcePolicyBindingV6};

struct LiveDispatch<'a> {
    dispatch: Dispatch<'a>,
    proposal: Option<String>,
}

struct LiveEffectPlan {
    operation: String,
    request_digest: String,
    argument_bytes: usize,
}

impl LiveDispatch<'_> {
    fn effect_plan(
        &self,
        authorization: &AuthorizedRequest,
    ) -> Result<LiveEffectPlan, Vec<Diagnostic>> {
        let source = self
            .proposal
            .as_deref()
            .ok_or_else(|| error("live.effect_context"))?;
        let lifecycle = &self.dispatch.compiled.lifecycle;
        let decoded = lifecycle
            .inner
            .proposal
            .decode(source)
            .map_err(|_| error("live.proposal_decode"))?;
        let Some(ProposalValue::Unsigned(selector)) =
            decoded.field(&self.dispatch.compiled.selector)
        else {
            return Err(error("live.selector_type"));
        };
        let index = usize::try_from(*selector).map_err(|_| error("live.selector_range"))?;
        let operation = self
            .dispatch
            .compiled
            .operations
            .get(index)
            .ok_or_else(|| error("live.selector_range"))?;
        let projected = lifecycle
            .inner
            .project(&decoded)
            .ok_or_else(|| error("live.projection"))?;
        let mut arguments = Vec::new();
        for argument in &operation.arguments {
            let field = lifecycle
                .inner
                .binding
                .proposal
                .iter()
                .position(|value| value.field.as_str() == argument.proposal_field_id)
                .ok_or_else(|| error("live.argument_identity"))?;
            let value = projected
                .get(field)
                .ok_or_else(|| error("live.argument_index"))?;
            if !argument.kind.accepts(value) {
                return Err(error("live.argument_type"));
            }
            arguments.push((argument.argument_id.clone(), value.clone()));
        }
        for ((_, value), limit) in arguments
            .iter()
            .zip(&self.dispatch.compiled.field_limits[index].0)
        {
            if scalar_bytes(value).is_none_or(|size| size > *limit) {
                return Err(error("live.argument_field_budget"));
            }
        }
        let encoded_arguments = encode_fields(&arguments);
        let results = operation
            .results
            .iter()
            .map(|result| {
                format!(
                    "[{},{}]",
                    quote_json(&result.result_id),
                    quote_json(result.kind.name())
                )
            })
            .collect::<Vec<_>>()
            .join(",");
        let identity = format!(
            "{{\"schema\":\"semaprax.source-typed-effect-request.v1\",\"registry\":{},\"operation\":{},\"effect\":{},\"authorization\":{},\"budget\":{},\"seal\":{},\"arguments\":{},\"results\":[{}]}}",
            quote_json(self.dispatch.compiled.digest()),
            quote_json(&operation.operation_id),
            quote_json(&operation.effect_id),
            quote_json(authorization.binding()),
            authorization.budget(),
            crate::agent_lifecycle::canonical_retained_value_json(&RetainedValue::Bytes(
                authorization.seal().to_vec(),
            )),
            encoded_arguments,
            results,
        );
        Ok(LiveEffectPlan {
            operation: operation.operation_id.clone(),
            request_digest: digest(
                b"semaprax.source-typed-effect-request.v1\0",
                identity.as_bytes(),
            ),
            argument_bytes: encoded_arguments.len(),
        })
    }

    fn restore_replayed_effect(
        &mut self,
        authorization: &AuthorizedRequest,
        observation: Option<&[u8]>,
    ) -> Result<(), Vec<Diagnostic>> {
        let plan = self.effect_plan(authorization)?;
        if self.dispatch.dispatched >= self.dispatch.budget.max_calls {
            return Err(error("live.replay_call_budget"));
        }
        let arguments = self
            .dispatch
            .arguments
            .checked_add(plan.argument_bytes)
            .ok_or_else(|| error("live.replay_argument_overflow"))?;
        if plan.argument_bytes > self.dispatch.budget.max_argument_bytes
            || arguments
                .checked_add(self.dispatch.results)
                .is_none_or(|total| total > self.dispatch.budget.max_total_bytes)
        {
            return Err(error("live.replay_argument_budget"));
        }
        let result_bytes = observation.map_or(0, <[u8]>::len);
        let results = self
            .dispatch
            .results
            .checked_add(result_bytes)
            .ok_or_else(|| error("live.replay_result_overflow"))?;
        if result_bytes > self.dispatch.budget.max_result_bytes
            || arguments
                .checked_add(results)
                .is_none_or(|total| total > self.dispatch.budget.max_total_bytes)
        {
            return Err(error("live.replay_result_budget"));
        }
        self.dispatch.dispatched += 1;
        self.dispatch.arguments = arguments;
        self.dispatch.results = results;
        self.proposal = None;
        Ok(())
    }
}

impl IterativeDriver for LiveDispatch<'_> {
    fn before_effect(&mut self, context: EffectContext<'_>) -> Result<(), Vec<Diagnostic>> {
        self.proposal = Some(context.proposal_canonical.to_owned());
        Ok(())
    }

    fn source_effect_identity(
        &mut self,
        authorization: &AuthorizedRequest,
    ) -> Result<Option<(String, String)>, Vec<Diagnostic>> {
        let plan = self.effect_plan(authorization)?;
        Ok(Some((plan.operation, plan.request_digest)))
    }

    fn validate_replayed_read(
        &mut self,
        authorization: &AuthorizedRequest,
        observation: Option<&[u8]>,
    ) -> Result<(), Vec<Diagnostic>> {
        self.restore_replayed_effect(authorization, observation)
    }

    fn read(
        &mut self,
        authorization: &AuthorizedRequest,
    ) -> Result<Option<Vec<u8>>, Vec<Diagnostic>> {
        let proposal = self
            .proposal
            .take()
            .ok_or_else(|| error("live.effect_context"))?;
        match self.dispatch.invoke_proposal(authorization, &proposal) {
            Ok(value) => Ok(Some(value)),
            Err(reason) => {
                self.dispatch.failure = Some(reason);
                Ok(None)
            }
        }
    }
}

impl CompiledTypedEffects {
    /// Execute with an injected source proposal stream instead of a submitted
    /// proposal inventory. The lifecycle still authorizes before `Dispatch`
    /// can invoke any typed effect.
    pub fn run_live(
        &self,
        task: &LifecycleTask,
        source: &mut dyn ProposalSource,
        handler: &mut dyn TypedEffectHandler,
        stages: IterativeBudget,
        effects: EffectBudget,
        cancellation: &AgentCancellation,
    ) -> Result<TypedEffectRun, Vec<Diagnostic>> {
        let budget = EffectBudget {
            max_calls: effects.max_calls.min(self.limits.max_calls),
            max_argument_bytes: effects
                .max_argument_bytes
                .min(self.limits.max_argument_bytes),
            max_result_bytes: effects.max_result_bytes.min(self.limits.max_result_bytes),
            max_total_bytes: effects.max_total_bytes.min(self.limits.max_total_bytes),
        };
        let mut dispatch = LiveDispatch {
            dispatch: Dispatch {
                compiled: self,
                proposals: &[],
                handler,
                budget,
                dispatched: 0,
                arguments: 0,
                results: 0,
                failure: None,
            },
            proposal: None,
        };
        let stages = IterativeBudget {
            max_iterations: stages.max_iterations.min(self.max_iterations),
            ..stages
        };
        let lifecycle = self
            .lifecycle
            .run_with_driver_live(task, source, &mut dispatch, stages, cancellation)
            .map_err(crate::agent_lifecycle::iterative::driver::DriverFailure::into_diagnostics)?;
        let evidence = format!(
            "{{\"schema\":\"semaprax.agent-typed-effects-evidence.v3\",\"registry\":{},\"lifecycle_evidence\":{},\"limits\":[{},{},{},{}],\"dispatched\":{},\"argument_bytes\":{},\"result_bytes\":{},\"failure\":{}}}\n",
            quote_json(self.digest()),
            quote_json(lifecycle.evidence_digest()),
            budget.max_calls,
            budget.max_argument_bytes,
            budget.max_result_bytes,
            budget.max_total_bytes,
            dispatch.dispatch.dispatched,
            dispatch.dispatch.arguments,
            dispatch.dispatch.results,
            dispatch.dispatch.failure.map(quote_json).unwrap_or_else(|| "null".into())
        );
        Ok(TypedEffectRun {
            lifecycle,
            dispatched: dispatch.dispatch.dispatched,
            argument_bytes: dispatch.dispatch.arguments,
            result_bytes: dispatch.dispatch.results,
            failure: dispatch.dispatch.failure,
            digest: digest(
                b"semaprax.agent-typed-effects-evidence.v3\0",
                evidence.as_bytes(),
            ),
            evidence,
        })
    }

    /// Durable live proposals use the existing Source Live Journal v2 cursor.
    /// The typed registry remains the sole effect dispatcher; this does not
    /// construct the frozen-operation checkpoint profile.
    pub(crate) fn run_live_durable_source(
        &self,
        request: SourceLiveRequest<'_>,
        source: &mut dyn ProposalSource,
        handler: &mut dyn TypedEffectHandler,
        effects: EffectBudget,
        store: &mut dyn CheckpointStore,
    ) -> Result<SourceLiveOutcome, SourceLiveFailure> {
        let budget = EffectBudget {
            max_calls: effects.max_calls.min(self.limits.max_calls),
            max_argument_bytes: effects
                .max_argument_bytes
                .min(self.limits.max_argument_bytes),
            max_result_bytes: effects.max_result_bytes.min(self.limits.max_result_bytes),
            max_total_bytes: effects.max_total_bytes.min(self.limits.max_total_bytes),
        };
        let mut dispatch = LiveDispatch {
            dispatch: Dispatch {
                compiled: self,
                proposals: &[],
                handler,
                budget,
                dispatched: 0,
                arguments: 0,
                results: 0,
                failure: None,
            },
            proposal: None,
        };
        self.lifecycle
            .run_live_durable_with_driver(request, source, &mut dispatch, store)
    }

    /// V6 durable source route with an explicit, host-validated model policy.
    /// It keeps the existing typed-effect dispatcher and one source cursor.
    pub(crate) fn run_live_durable_source_with_model_policy(
        &self,
        request: SourceLiveRequest<'_>,
        policy: SourcePolicyBindingV6,
        source: &mut dyn ProposalSource,
        handler: &mut dyn TypedEffectHandler,
        effects: EffectBudget,
        store: &mut dyn CheckpointStore,
    ) -> Result<SourceLiveOutcome, SourceLiveFailure> {
        let budget = EffectBudget {
            max_calls: effects.max_calls.min(self.limits.max_calls),
            max_argument_bytes: effects
                .max_argument_bytes
                .min(self.limits.max_argument_bytes),
            max_result_bytes: effects.max_result_bytes.min(self.limits.max_result_bytes),
            max_total_bytes: effects.max_total_bytes.min(self.limits.max_total_bytes),
        };
        let mut dispatch = LiveDispatch {
            dispatch: Dispatch {
                compiled: self,
                proposals: &[],
                handler,
                budget,
                dispatched: 0,
                arguments: 0,
                results: 0,
                failure: None,
            },
            proposal: None,
        };
        self.lifecycle.run_live_durable_with_model_policy(
            request,
            policy,
            source,
            &mut dispatch,
            store,
        )
    }

    /// V6 model policy and V5 cumulative I/O limits share this typed-effect
    /// dispatcher and one journal cursor.
    pub(crate) fn run_live_durable_source_with_model_policy_and_io_limits(
        &self,
        request: SourceLiveRequest<'_>,
        policy: SourcePolicyBindingV6,
        limits: &SourceIoLimits,
        source: &mut dyn ProposalSource,
        handler: &mut dyn TypedEffectHandler,
        effects: EffectBudget,
        store: &mut dyn CheckpointStore,
    ) -> Result<SourceLiveOutcome, SourceLiveFailure> {
        let budget = EffectBudget {
            max_calls: effects.max_calls.min(self.limits.max_calls),
            max_argument_bytes: effects
                .max_argument_bytes
                .min(self.limits.max_argument_bytes),
            max_result_bytes: effects.max_result_bytes.min(self.limits.max_result_bytes),
            max_total_bytes: effects.max_total_bytes.min(self.limits.max_total_bytes),
        };
        let mut dispatch = LiveDispatch {
            dispatch: Dispatch {
                compiled: self,
                proposals: &[],
                handler,
                budget,
                dispatched: 0,
                arguments: 0,
                results: 0,
                failure: None,
            },
            proposal: None,
        };
        self.lifecycle
            .run_live_durable_with_model_policy_and_io_limits(
                request,
                policy,
                limits,
                source,
                &mut dispatch,
                store,
            )
    }

    /// Continues an already checked Source Live migration with the same typed
    /// effect identity and replay validation as the direct durable route.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn run_prepared_source_migration(
        &self,
        prepared: PreparedSourceLiveMigration<'_>,
        source: &mut dyn ProposalSource,
        handler: &mut dyn TypedEffectHandler,
        effects: EffectBudget,
        store: &mut dyn CheckpointStore,
        clock: &dyn crate::live_invocation::SourceInvocationClock,
        cancellation: &AgentCancellation,
    ) -> Result<SourceLiveOutcome, SourceLiveFailure> {
        let budget = EffectBudget {
            max_calls: effects.max_calls.min(self.limits.max_calls),
            max_argument_bytes: effects
                .max_argument_bytes
                .min(self.limits.max_argument_bytes),
            max_result_bytes: effects.max_result_bytes.min(self.limits.max_result_bytes),
            max_total_bytes: effects.max_total_bytes.min(self.limits.max_total_bytes),
        };
        let mut dispatch = LiveDispatch {
            dispatch: Dispatch {
                compiled: self,
                proposals: &[],
                handler,
                budget,
                dispatched: 0,
                arguments: 0,
                results: 0,
                failure: None,
            },
            proposal: None,
        };
        prepared.run_with_driver(source, &mut dispatch, store, clock, cancellation)
    }
}
