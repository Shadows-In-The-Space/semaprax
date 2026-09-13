//! Live source-proposal entry for the checked typed-effect runner.
//!
//! Proposal acquisition remains outside the typed effect boundary. This
//! adapter receives only the source driver's accepted canonical proposal at
//! its `before_effect` boundary, then uses the same Dispatch as frozen input.

use super::*;
use crate::agent_lifecycle::iterative::driver::{EffectContext, IterativeDriver, ProposalSource};

struct LiveDispatch<'a> {
    dispatch: Dispatch<'a>,
    proposal: Option<String>,
}

impl IterativeDriver for LiveDispatch<'_> {
    fn before_effect(&mut self, context: EffectContext<'_>) -> Result<(), Vec<Diagnostic>> {
        self.proposal = Some(context.proposal_canonical.to_owned());
        Ok(())
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
}
