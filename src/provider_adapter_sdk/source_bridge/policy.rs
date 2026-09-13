//! Host-local #179 accounting for the source adapter bridge.

use crate::agent_runtime::AgentCancellation;
use crate::agent_runtime_v2::source_model::source_request_digest;
use crate::agent_runtime_v2::{SourceModelBinding, SourceModelPolicyBinding};
use crate::live_invocation::source_journal::{PolicyAttemptReservationV6, SourcePolicyQuoteV6};
use crate::live_invocation::InvocationClock;
use crate::model_budget_policy::live_hook::ModelAttemptQuote;
use crate::model_budget_policy::{
    AttemptKind, AttemptRefusal, AttemptRequest, AttemptReservation, ModelPolicyLedger,
    ProviderPolicy, ProviderSlot,
};

use super::{AdapterRequest, SourceModelAttemptQuoter};

pub(super) struct SourceModelPolicySession<'a> {
    binding: SourceModelPolicyBinding,
    ledger: ModelPolicyLedger<'a>,
    quoter: &'a mut dyn SourceModelAttemptQuoter,
    cancellation: &'a AgentCancellation,
    clock: &'a dyn InvocationClock,
    deadline_millis: Option<i64>,
    overage_context_tokens: u64,
    overage_output_tokens: u64,
    overage_cost_micros: i64,
    overage_overflowed: bool,
    observed_ordinal: Option<u64>,
    observed_context_tokens: u64,
    observed_output_tokens: u64,
    observed_cost_micros: i64,
}

impl<'a> SourceModelPolicySession<'a> {
    pub(super) fn new(
        binding: SourceModelPolicyBinding,
        quoter: &'a mut dyn SourceModelAttemptQuoter,
        cancellation: &'a AgentCancellation,
        clock: &'a dyn InvocationClock,
        deadline_millis: Option<i64>,
    ) -> Self {
        let provider = ProviderSlot::authorized(binding.provider_id().to_owned());
        Self {
            ledger: ModelPolicyLedger::new(
                binding.effective(),
                ProviderPolicy::new(vec![provider]),
                deadline_millis,
                clock,
            ),
            binding,
            quoter,
            cancellation,
            clock,
            deadline_millis,
            overage_context_tokens: 0,
            overage_output_tokens: 0,
            overage_cost_micros: 0,
            overage_overflowed: false,
            observed_ordinal: None,
            observed_context_tokens: 0,
            observed_output_tokens: 0,
            observed_cost_micros: 0,
        }
    }

    pub(super) fn binding(&self) -> &SourceModelPolicyBinding {
        &self.binding
    }

    pub(super) fn deadline_millis(&self) -> Option<i64> {
        self.deadline_millis
    }

    pub(super) fn quote(
        &mut self,
        request: &AdapterRequest,
        binding: &SourceModelBinding,
    ) -> Result<ModelAttemptQuote, &'static str> {
        let quote = self
            .quoter
            .quote(request, binding)
            .map_err(|_| "policy_quote_refused")?;
        if quote.request_digest != source_request_digest(&request.request_bytes)
            || quote.estimated_cost_micros < 0
            || quote
                .context_tokens
                .checked_add(quote.output_tokens)
                .is_none()
        {
            return Err("policy_quote_refused");
        }
        Ok(quote)
    }

    pub(super) fn reserve(
        &mut self,
        quote: &ModelAttemptQuote,
    ) -> Result<AttemptReservation, AttemptRefusal> {
        self.require_exposure_headroom(quote)?;
        let provider_id = self.binding.provider_id().to_owned();
        self.ledger.reserve_attempt(
            self.cancellation,
            &AttemptRequest {
                kind: AttemptKind::Fresh,
                provider_id,
                context_tokens: quote.context_tokens,
                requested_output_tokens: quote.output_tokens,
                estimated_cost_micros: quote.estimated_cost_micros,
                prior_classification: None,
            },
        )
    }

    pub(super) fn observe(
        &mut self,
        reservation: &AttemptReservation,
        context_tokens: u64,
        output_tokens: u64,
        cost_micros: i64,
    ) {
        if cost_micros < 0 {
            return;
        }
        if self.observed_ordinal != Some(reservation.ordinal) {
            self.observed_ordinal = Some(reservation.ordinal);
            self.observed_context_tokens = 0;
            self.observed_output_tokens = 0;
            self.observed_cost_micros = 0;
        }
        self.observe_u64(
            context_tokens.saturating_sub(reservation.reserved_context_tokens),
            true,
        );
        self.observe_u64(
            output_tokens.saturating_sub(reservation.reserved_output_tokens),
            false,
        );
        self.observe_cost(cost_micros.saturating_sub(reservation.reserved_cost_micros));
    }

    pub(super) fn quote_v6(
        &mut self,
        request: &AdapterRequest,
        binding: &SourceModelBinding,
    ) -> Result<SourcePolicyQuoteV6, &'static str> {
        let quote = self.quote(request, binding)?;
        Ok(SourcePolicyQuoteV6 {
            policy_binding_digest: self.binding.digest().to_owned(),
            request_digest: quote.request_digest,
            provider_id: self.binding.provider_id().to_owned(),
            context_tokens: quote.context_tokens,
            output_tokens: quote.output_tokens,
            estimated_cost_micros: quote.estimated_cost_micros,
        })
    }

    pub(super) fn resume(
        &mut self,
        reservations: &[PolicyAttemptReservationV6],
    ) -> Result<(), &'static str> {
        let mut restored = Vec::with_capacity(reservations.len());
        let provider_id = self.binding.provider_id();
        let mut prior_ordinal = None;
        for reservation in reservations {
            if reservation.kind != AttemptKind::Fresh
                || reservation.provider_id != provider_id
                || prior_ordinal.is_some_and(|prior| reservation.ordinal <= prior)
                || reservation
                    .reserved_context_tokens
                    .checked_add(reservation.reserved_output_tokens)
                    .is_none()
                || reservation.reserved_cost_micros < 0
            {
                return Err("source.model_policy_recovery");
            }
            prior_ordinal = Some(reservation.ordinal);
            restored.push(AttemptReservation {
                ordinal: reservation.ordinal,
                kind: reservation.kind,
                provider_id: reservation.provider_id.clone(),
                reserved_context_tokens: reservation.reserved_context_tokens,
                reserved_output_tokens: reservation.reserved_output_tokens,
                reserved_cost_micros: reservation.reserved_cost_micros,
            });
        }
        self.ledger = ModelPolicyLedger::resume(
            self.binding.effective(),
            ProviderPolicy::new(vec![ProviderSlot::authorized(provider_id.to_owned())]),
            self.deadline_millis,
            self.clock,
            &restored,
        );
        self.overage_context_tokens = 0;
        self.overage_output_tokens = 0;
        self.overage_cost_micros = 0;
        self.overage_overflowed = false;
        self.observed_ordinal = None;
        Ok(())
    }

    fn require_exposure_headroom(&self, quote: &ModelAttemptQuote) -> Result<(), AttemptRefusal> {
        let limits = self.binding.effective().limits();
        let tokens = self
            .ledger
            .aggregate_tokens_committed()
            .checked_add(self.overage_context_tokens)
            .and_then(|value| value.checked_add(self.overage_output_tokens));
        let cost = self
            .ledger
            .cost_committed_micros()
            .checked_add(self.overage_cost_micros);
        let requested_tokens = quote.context_tokens.checked_add(quote.output_tokens);
        if self.overage_overflowed || tokens.is_none() || requested_tokens.is_none() {
            return Err(AttemptRefusal::AggregateTokensExhausted {
                requested: u64::MAX,
                remaining: 0,
            });
        }
        let tokens = tokens.expect("checked above");
        let requested_tokens = requested_tokens.expect("checked above");
        if tokens
            .checked_add(requested_tokens)
            .is_none_or(|value| value > limits.max_aggregate_tokens)
        {
            return Err(AttemptRefusal::AggregateTokensExhausted {
                requested: requested_tokens,
                remaining: limits.max_aggregate_tokens.saturating_sub(tokens),
            });
        }
        if self.overage_overflowed || cost.is_none() {
            return Err(AttemptRefusal::CostExhausted {
                requested: quote.estimated_cost_micros,
                remaining: 0,
            });
        }
        let cost = cost.expect("checked above");
        if cost
            .checked_add(quote.estimated_cost_micros)
            .is_none_or(|value| value > limits.max_cost_micros)
        {
            return Err(AttemptRefusal::CostExhausted {
                requested: quote.estimated_cost_micros,
                remaining: (limits.max_cost_micros - cost).max(0),
            });
        }
        Ok(())
    }

    fn observe_u64(&mut self, current: u64, context: bool) {
        let prior = if context {
            &mut self.observed_context_tokens
        } else {
            &mut self.observed_output_tokens
        };
        if current <= *prior {
            return;
        }
        let delta = current - *prior;
        *prior = current;
        let exposure = if context {
            &mut self.overage_context_tokens
        } else {
            &mut self.overage_output_tokens
        };
        if let Some(next) = exposure.checked_add(delta) {
            *exposure = next;
        } else {
            self.overage_overflowed = true;
        }
    }

    fn observe_cost(&mut self, current: i64) {
        if current <= self.observed_cost_micros {
            return;
        }
        let delta = current - self.observed_cost_micros;
        self.observed_cost_micros = current;
        if let Some(next) = self.overage_cost_micros.checked_add(delta) {
            self.overage_cost_micros = next;
        } else {
            self.overage_overflowed = true;
        }
    }
}
