//! Live-kernel composition of model policy and the existing work-budget hook.
//! Quotes are explicit host estimates bound to exact request bytes, never
//! provider usage observations. Reservations remain spent even if a later
//! gate refuses. This retained hook is not a crash-recovery journal.
use super::{
    AttemptKind, AttemptRequest, AttemptReservation, EffectiveModelBudget, ModelPolicyLedger,
    ProviderPolicy, ProviderSlot,
};
use crate::agent_runtime::AgentCancellation;
use crate::live_invocation::budget::{InvocationClock, DEADLINE_EXCEEDED, RESERVATION_MISMATCH};
use crate::live_invocation::model_invoke::{
    BudgetRefusal, InvocationBudgetHook, InvocationUsage, ModelInvocationRequest, ReservedBudget,
};

pub const POLICY_EXHAUSTED: &str = "model_policy_exhausted";
pub const INVALID_QUOTE: &str = "model_policy_invalid_quote";
pub const MAX_RETAINED_RESERVATIONS: usize = 4096;

/// A host's bound upper estimate for this exact request, including its maximum
/// output allowance. The host must use the selected model's tokenizer/pricing;
/// the compiler does not reinterpret bytes as tokens or guess exchange rates.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ModelAttemptQuote {
    pub request_digest: String,
    pub context_tokens: u64,
    pub output_tokens: u64,
    pub estimated_cost_micros: i64,
}

pub trait ModelAttemptQuoter {
    fn quote(
        &mut self,
        request: &ModelInvocationRequest,
    ) -> Result<ModelAttemptQuote, BudgetRefusal>;
}

/// Records a local pre-dispatch reservation, not proof of provider delivery.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LivePolicyReservation {
    pub request_digest: String,
    pub reservation: AttemptReservation,
}

/// The generic kernel has one fresh model attempt per turn and never performs
/// automatic retry or failover. The host binds one authorized provider here and
/// must wire that same provider into its ModelHandler. Keeping this hook across
/// runs retains all conservative charges; reconstructing one resets them and
/// must not be described as recovery.
pub struct LiveModelPolicyHook<'a> {
    ledger: ModelPolicyLedger<'a>,
    provider: String,
    inner: &'a mut dyn InvocationBudgetHook,
    quoter: &'a mut dyn ModelAttemptQuoter,
    cancellation: &'a AgentCancellation,
    reservations: Vec<LivePolicyReservation>,
}

impl<'a> LiveModelPolicyHook<'a> {
    /// Intersect limits before construction. The latency ceiling becomes one
    /// absolute deadline from the original start, with checked arithmetic.
    /// i64::MAX is the explicit unbounded latency sentinel.
    pub fn new(
        limits: EffectiveModelBudget,
        provider: ProviderSlot,
        started_at_millis: i64,
        clock: &'a dyn InvocationClock,
        inner: &'a mut dyn InvocationBudgetHook,
        quoter: &'a mut dyn ModelAttemptQuoter,
        cancellation: &'a AgentCancellation,
    ) -> Result<Self, BudgetRefusal> {
        if !provider.authorized || provider.id.is_empty() || provider.id.len() > 256 {
            return Err(BudgetRefusal("model_policy_provider_refused".into()));
        }
        let duration = limits.limits().max_latency_millis;
        let deadline = if duration == i64::MAX {
            None
        } else {
            Some(
                started_at_millis
                    .checked_add(duration)
                    .ok_or_else(|| BudgetRefusal("model_policy_invalid_deadline".into()))?,
            )
        };
        let provider_id = provider.id.clone();
        Ok(Self {
            ledger: ModelPolicyLedger::new(
                limits,
                ProviderPolicy::new(vec![provider]),
                deadline,
                clock,
            ),
            provider: provider_id,
            inner,
            quoter,
            cancellation,
            reservations: Vec::new(),
        })
    }

    pub fn reservations(&self) -> &[LivePolicyReservation] {
        &self.reservations
    }
    pub fn ledger(&self) -> &ModelPolicyLedger<'a> {
        &self.ledger
    }
}

impl InvocationBudgetHook for LiveModelPolicyHook<'_> {
    fn check_deadline(&self) -> Result<(), BudgetRefusal> {
        if self.cancellation.is_cancelled() {
            return Err(BudgetRefusal("cancelled".into()));
        }
        self.ledger
            .check_deadline()
            .map_err(|_| BudgetRefusal(DEADLINE_EXCEEDED.into()))?;
        self.inner.check_deadline()
    }

    fn reserve(
        &mut self,
        request: &ModelInvocationRequest,
    ) -> Result<ReservedBudget, BudgetRefusal> {
        self.check_deadline()?;
        if self.reservations.len() >= MAX_RETAINED_RESERVATIONS {
            return Err(BudgetRefusal(POLICY_EXHAUSTED.into()));
        }
        let quote = self
            .quoter
            .quote(request)
            .map_err(|_| BudgetRefusal(INVALID_QUOTE.into()))?;
        let digest = request.digest();
        if quote.request_digest != digest
            || quote.estimated_cost_micros < 0
            || quote
                .context_tokens
                .checked_add(quote.output_tokens)
                .is_none()
        {
            return Err(BudgetRefusal(INVALID_QUOTE.into()));
        }
        self.check_deadline()?;
        let reservation = self
            .ledger
            .reserve_attempt(
                self.cancellation,
                &AttemptRequest {
                    kind: AttemptKind::Fresh,
                    provider_id: self.provider.clone(),
                    context_tokens: quote.context_tokens,
                    requested_output_tokens: quote.output_tokens,
                    estimated_cost_micros: quote.estimated_cost_micros,
                    prior_classification: None,
                },
            )
            .map_err(|reason| {
                BudgetRefusal(
                    match reason {
                        super::AttemptRefusal::Cancelled => "cancelled",
                        super::AttemptRefusal::DeadlineExceeded => DEADLINE_EXCEEDED,
                        _ => POLICY_EXHAUSTED,
                    }
                    .into(),
                )
            })?;
        self.reservations.push(LivePolicyReservation {
            request_digest: digest,
            reservation,
        });
        // A later refusal never refunds the model-policy reservation.
        let reserved = self.inner.reserve(request)?;
        if reserved.amount != request.effective_budget {
            return Err(BudgetRefusal(RESERVATION_MISMATCH.into()));
        }
        Ok(reserved)
    }

    fn record(&mut self, usage: &InvocationUsage) {
        // Byte counters do not establish token usage, actual cost or delivery
        // classification, so do not invent ModelPolicyLedger::AttemptUsage.
        self.inner.record(usage);
    }
}

#[cfg(test)]
mod tests;
