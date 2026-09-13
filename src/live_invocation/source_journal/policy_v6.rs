//! Additive durable ModelPolicyLedger facts for the Source Live journal.
//!
//! V6 records only the host's bounded quote reservation and closed usage
//! observation. It is not a price lookup, invoice, or permission to bill.

use crate::diagnostic::quote_json;
use crate::model_budget_policy::{
    AttemptKind, AttemptReservation, EffectiveModelBudget, ModelBudgetLimits,
};

use super::{
    SourceCheckpointSink, SourceInvocationBinding, SourceJournal, SourceJournalEntry,
    SourceJournalError,
};

const MAX_POLICY_ID_BYTES: usize = 256;

/// Policy facts bound into one V6 source invocation. The effective limits are
/// copied from the already-checked runtime binding so recovery can validate
/// durable reservations independently before it reconstructs a ledger.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SourcePolicyBindingV6 {
    pub(crate) model_binding_digest: String,
    pub(crate) policy_binding_digest: String,
    pub(crate) provider_id: String,
    pub(crate) limits: ModelBudgetLimits,
}

impl SourcePolicyBindingV6 {
    pub(crate) fn new(
        model_binding_digest: String,
        policy_binding_digest: String,
        provider_id: String,
        effective: EffectiveModelBudget,
    ) -> Result<Self, SourceJournalError> {
        if !valid_id(&model_binding_digest)
            || !valid_id(&policy_binding_digest)
            || !valid_id(&provider_id)
        {
            return Err(SourceJournalError::Binding);
        }
        let limits = effective.limits();
        if limits.max_calls == 0 || limits.max_cost_micros < 0 || limits.max_latency_millis < 0 {
            return Err(SourceJournalError::Binding);
        }
        Ok(Self {
            model_binding_digest,
            policy_binding_digest,
            provider_id,
            limits,
        })
    }

    pub(crate) fn canonical(&self, base_invocation: &str, deadline_millis: i64) -> String {
        let limits = self.limits;
        format!(
            "{{\"schema\":\"semaprax.live-invocation.source-policy-binding.v6\",\"base_invocation\":{},\"model_binding\":{},\"policy_binding\":{},\"provider\":{},\"max_calls\":{},\"max_retries\":{},\"max_providers\":{},\"max_context_tokens\":{},\"max_output_tokens\":{},\"max_aggregate_tokens\":{},\"max_cost_micros\":{},\"max_latency_millis\":{},\"deadline_millis\":{}}}",
            quote_json(base_invocation), quote_json(&self.model_binding_digest),
            quote_json(&self.policy_binding_digest), quote_json(&self.provider_id),
            limits.max_calls, limits.max_retries, limits.max_providers,
            limits.max_context_tokens, limits.max_output_tokens,
            limits.max_aggregate_tokens, limits.max_cost_micros,
            limits.max_latency_millis, deadline_millis,
        )
    }
}

/// A request-bound host quote prepared without reservation or dispatch.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SourcePolicyQuoteV6 {
    pub policy_binding_digest: String,
    pub request_digest: String,
    pub provider_id: String,
    pub context_tokens: u64,
    pub output_tokens: u64,
    pub estimated_cost_micros: i64,
}

/// The complete nonrefundable policy reservation made durable with an
/// acknowledged V6 attempt intent.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PolicyAttemptReservationV6 {
    pub ordinal: u64,
    pub kind: AttemptKind,
    pub provider_id: String,
    pub reserved_context_tokens: u64,
    pub reserved_output_tokens: u64,
    pub reserved_cost_micros: i64,
}

/// V6 attempt intent. It carries the exact source request identity as well as
/// the quote-derived reservation that must have fitted before acknowledgement.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PolicyAttemptIntentV6 {
    pub turn: u32,
    pub attempt: u32,
    pub attempt_digest: String,
    pub request_digest: String,
    pub prompt_digest: String,
    pub request_bytes: usize,
    pub reserved_units: i64,
    pub response_limit: usize,
    pub reservation: PolicyAttemptReservationV6,
}

/// Closed post-dispatch policy usage. Unknown retains the full reservation;
/// observed values are evidence only and never refund capacity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PolicyAttemptUsageV6 {
    Unknown,
    Observed {
        context_tokens: u64,
        output_tokens: u64,
        cost_micros: i64,
    },
}

/// Journal-derived policy totals. `exposure_*` is the checked maximum of each
/// reservation and its observed value, so an observed overage cannot reopen a
/// later attempt's capacity.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct SourcePolicyTotalsV6 {
    pub calls: u32,
    pub reserved_context_tokens: u64,
    pub reserved_output_tokens: u64,
    pub reserved_cost_micros: i64,
    pub observed_context_tokens: u64,
    pub observed_output_tokens: u64,
    pub observed_cost_micros: i64,
    pub exposure_context_tokens: u64,
    pub exposure_output_tokens: u64,
    pub exposure_cost_micros: i64,
    pub next_ordinal: u64,
}

fn valid_id(value: &str) -> bool {
    !value.is_empty() && value.len() <= MAX_POLICY_ID_BYTES && !value.chars().any(char::is_control)
}

pub(crate) fn intent(
    binding: &SourcePolicyBindingV6,
    source: &SourceInvocationBinding,
    entries: &[SourceJournalEntry],
    turn: u32,
    attempt: u32,
    request_digest: String,
    prompt_digest: String,
    request_bytes: usize,
    quote: SourcePolicyQuoteV6,
) -> Result<PolicyAttemptIntentV6, SourceJournalError> {
    if quote.policy_binding_digest != binding.policy_binding_digest
        || quote.request_digest != request_digest
        || quote.provider_id != binding.provider_id
        || quote.estimated_cost_micros < 0
        || quote
            .context_tokens
            .checked_add(quote.output_tokens)
            .is_none()
    {
        return Err(SourceJournalError::Binding);
    }
    let totals = fold(source, entries)?.totals;
    let limits = binding.limits;
    if totals.calls >= limits.max_calls
        || quote.context_tokens > limits.max_context_tokens
        || quote.output_tokens > limits.max_output_tokens
        || totals
            .exposure_context_tokens
            .checked_add(totals.exposure_output_tokens)
            .and_then(|value| value.checked_add(quote.context_tokens))
            .and_then(|value| value.checked_add(quote.output_tokens))
            .is_none_or(|value| value > limits.max_aggregate_tokens)
        || totals
            .exposure_cost_micros
            .checked_add(quote.estimated_cost_micros)
            .is_none_or(|value| value > limits.max_cost_micros)
    {
        return Err(SourceJournalError::Binding);
    }
    Ok(PolicyAttemptIntentV6 {
        turn,
        attempt,
        attempt_digest: source.attempt_digest(
            turn,
            attempt,
            &request_digest,
            &prompt_digest,
            request_bytes,
        ),
        request_digest,
        prompt_digest,
        request_bytes,
        reserved_units: source.reservation_units(),
        response_limit: source.response_limit(),
        reservation: PolicyAttemptReservationV6 {
            ordinal: totals.next_ordinal,
            kind: AttemptKind::Fresh,
            provider_id: binding.provider_id.clone(),
            reserved_context_tokens: quote.context_tokens,
            reserved_output_tokens: quote.output_tokens,
            reserved_cost_micros: quote.estimated_cost_micros,
        },
    })
}

pub(crate) fn usage(
    source: &SourceInvocationBinding,
    entries: &[SourceJournalEntry],
    turn: u32,
    attempt: u32,
    ordinal: u64,
    usage: PolicyAttemptUsageV6,
) -> Result<SourceJournalEntry, SourceJournalError> {
    let folded = fold(source, entries)?;
    let intent = folded
        .intents
        .iter()
        .find(|intent| {
            intent.turn == turn
                && intent.attempt == attempt
                && intent.reservation.ordinal == ordinal
        })
        .ok_or(SourceJournalError::Order)?;
    if folded.used_ordinals.contains(&ordinal)
        || matches!(&usage, PolicyAttemptUsageV6::Observed { cost_micros, .. } if *cost_micros < 0)
        || intent.reservation.kind != AttemptKind::Fresh
    {
        return Err(SourceJournalError::Order);
    }
    Ok(SourceJournalEntry::PolicyAttemptUsage {
        turn,
        attempt,
        ordinal,
        usage,
    })
}

impl From<&PolicyAttemptReservationV6> for AttemptReservation {
    fn from(value: &PolicyAttemptReservationV6) -> Self {
        Self {
            ordinal: value.ordinal,
            kind: value.kind,
            provider_id: value.provider_id.clone(),
            reserved_context_tokens: value.reserved_context_tokens,
            reserved_output_tokens: value.reserved_output_tokens,
            reserved_cost_micros: value.reserved_cost_micros,
        }
    }
}

pub(crate) struct PolicyFoldV6 {
    pub totals: SourcePolicyTotalsV6,
    pub reservations: Vec<PolicyAttemptReservationV6>,
    intents: Vec<PolicyAttemptIntentV6>,
    used_ordinals: Vec<u64>,
}

pub(crate) fn fold(
    source: &SourceInvocationBinding,
    entries: &[SourceJournalEntry],
) -> Result<PolicyFoldV6, SourceJournalError> {
    let binding = source.policy_binding().ok_or(SourceJournalError::Binding)?;
    let carry = source.policy_migration_carry();
    let mut result = PolicyFoldV6 {
        totals: carry.map_or_else(SourcePolicyTotalsV6::default, |carry| carry.totals.clone()),
        reservations: carry.map_or_else(Vec::new, |carry| carry.reservations.clone()),
        intents: Vec::new(),
        used_ordinals: Vec::new(),
    };
    for (index, entry) in entries.iter().enumerate() {
        match entry {
            SourceJournalEntry::PolicyAttemptIntent(intent) => {
                let reservation = &intent.reservation;
                if reservation.ordinal != result.totals.next_ordinal
                    || reservation.kind != AttemptKind::Fresh
                    || reservation.provider_id != binding.provider_id
                    || reservation.reserved_cost_micros < 0
                    || reservation.reserved_context_tokens > binding.limits.max_context_tokens
                    || reservation.reserved_output_tokens > binding.limits.max_output_tokens
                    || intent.reserved_units <= 0
                    || intent.response_limit == 0
                {
                    return Err(SourceJournalError::Binding);
                }
                let aggregate_exposure = result
                    .totals
                    .exposure_context_tokens
                    .checked_add(result.totals.exposure_output_tokens)
                    .and_then(|value| value.checked_add(reservation.reserved_context_tokens))
                    .and_then(|value| value.checked_add(reservation.reserved_output_tokens))
                    .ok_or(SourceJournalError::Capacity)?;
                let next_cost = add_i64(
                    result.totals.exposure_cost_micros,
                    reservation.reserved_cost_micros,
                )?;
                if result.totals.calls >= binding.limits.max_calls
                    || aggregate_exposure > binding.limits.max_aggregate_tokens
                    || next_cost > binding.limits.max_cost_micros
                {
                    return Err(SourceJournalError::Binding);
                }
                result.totals.calls = result
                    .totals
                    .calls
                    .checked_add(1)
                    .ok_or(SourceJournalError::Capacity)?;
                result.totals.reserved_context_tokens = add_u64(
                    result.totals.reserved_context_tokens,
                    reservation.reserved_context_tokens,
                )?;
                result.totals.reserved_output_tokens = add_u64(
                    result.totals.reserved_output_tokens,
                    reservation.reserved_output_tokens,
                )?;
                result.totals.reserved_cost_micros = add_i64(
                    result.totals.reserved_cost_micros,
                    reservation.reserved_cost_micros,
                )?;
                result.totals.exposure_context_tokens = add_u64(
                    result.totals.exposure_context_tokens,
                    reservation.reserved_context_tokens,
                )?;
                result.totals.exposure_output_tokens = add_u64(
                    result.totals.exposure_output_tokens,
                    reservation.reserved_output_tokens,
                )?;
                result.totals.exposure_cost_micros = next_cost;
                result.totals.next_ordinal = result
                    .totals
                    .next_ordinal
                    .checked_add(1)
                    .ok_or(SourceJournalError::Capacity)?;
                result.reservations.push(reservation.clone());
                result.intents.push(intent.clone());
            }
            SourceJournalEntry::PolicyAttemptUsage {
                turn,
                attempt,
                ordinal,
                usage,
            } => {
                let intent = result
                    .intents
                    .iter()
                    .find(|intent| {
                        intent.turn == *turn
                            && intent.attempt == *attempt
                            && intent.reservation.ordinal == *ordinal
                    })
                    .ok_or(SourceJournalError::Order)?;
                if !matches!(entries.get(index.checked_sub(1).ok_or(SourceJournalError::Order)?),
                    Some(SourceJournalEntry::AttemptSettled { turn: closed_turn, attempt: closed_attempt, .. }
                    | SourceJournalEntry::AttemptFailed { turn: closed_turn, attempt: closed_attempt, .. })
                    if (*closed_turn, *closed_attempt) == (*turn, *attempt))
                    || result.used_ordinals.contains(ordinal)
                    || matches!(usage, PolicyAttemptUsageV6::Observed { cost_micros, .. } if *cost_micros < 0)
                {
                    return Err(SourceJournalError::Order);
                }
                if let PolicyAttemptUsageV6::Observed {
                    context_tokens,
                    output_tokens,
                    cost_micros,
                } = usage
                {
                    result.totals.observed_context_tokens =
                        add_u64(result.totals.observed_context_tokens, *context_tokens)?;
                    result.totals.observed_output_tokens =
                        add_u64(result.totals.observed_output_tokens, *output_tokens)?;
                    result.totals.observed_cost_micros =
                        add_i64(result.totals.observed_cost_micros, *cost_micros)?;
                    if *context_tokens > intent.reservation.reserved_context_tokens {
                        result.totals.exposure_context_tokens = add_u64(
                            result.totals.exposure_context_tokens,
                            context_tokens - intent.reservation.reserved_context_tokens,
                        )?;
                    }
                    if *output_tokens > intent.reservation.reserved_output_tokens {
                        result.totals.exposure_output_tokens = add_u64(
                            result.totals.exposure_output_tokens,
                            output_tokens - intent.reservation.reserved_output_tokens,
                        )?;
                    }
                    if *cost_micros > intent.reservation.reserved_cost_micros {
                        result.totals.exposure_cost_micros = add_i64(
                            result.totals.exposure_cost_micros,
                            cost_micros - intent.reservation.reserved_cost_micros,
                        )?;
                    }
                }
                result.used_ordinals.push(*ordinal);
            }
            _ => {}
        }
    }
    Ok(result)
}

fn add_u64(left: u64, right: u64) -> Result<u64, SourceJournalError> {
    left.checked_add(right).ok_or(SourceJournalError::Capacity)
}

fn add_i64(left: i64, right: i64) -> Result<i64, SourceJournalError> {
    left.checked_add(right).ok_or(SourceJournalError::Capacity)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::live_invocation::identity::digest;
    use crate::live_invocation::source_journal::SourceInvocationSeed;
    use crate::model_budget_policy::{intersect, ModelBudgetLimits};

    fn hash(label: &str) -> String {
        digest(b"source.policy.v6.test\0", label.as_bytes())
    }
    fn binding() -> SourceInvocationBinding {
        let limits = ModelBudgetLimits {
            max_calls: 2,
            max_retries: 0,
            max_providers: 0,
            max_context_tokens: 10,
            max_output_tokens: 10,
            max_aggregate_tokens: 12,
            max_cost_micros: 100,
            max_latency_millis: i64::MAX,
        };
        let effective = intersect(limits, limits, limits).unwrap();
        let policy = SourcePolicyBindingV6::new(
            hash("model"),
            hash("policy"),
            "provider.a".into(),
            effective,
        )
        .unwrap();
        SourceInvocationBinding::bind_policy_execution(
            SourceInvocationSeed {
                lifecycle_digest: hash("lifecycle"),
                source_revision: hash("source"),
                deployment_binding: hash("deployment"),
                task: b"task".to_vec(),
                task_budget: 1,
                proposal_schema_digest: hash("schema"),
                response_limit: 32,
                max_iterations: 2,
                max_stages: 8,
                max_attempts: 2,
                max_steps_per_stage: 10,
                max_total_steps: 100,
                ceiling: 6,
                reservation_units: 3,
                unit: "fixed_units".into(),
                clock_domain: "stable_ms".into(),
                initial_millis: 0,
                deadline_millis: 100,
                program_root: None,
            },
            &hash("evaluator"),
            policy,
        )
        .unwrap()
    }
    fn quote(request: &str) -> SourcePolicyQuoteV6 {
        SourcePolicyQuoteV6 {
            policy_binding_digest: hash("policy"),
            request_digest: hash(request),
            provider_id: "provider.a".into(),
            context_tokens: 3,
            output_tokens: 3,
            estimated_cost_micros: 10,
        }
    }

    #[test]
    fn observed_overage_is_retained_and_blocks_the_next_policy_intent() {
        let binding = binding();
        let first = intent(
            &binding.policy_binding().unwrap(),
            &binding,
            &[],
            0,
            0,
            hash("request-0"),
            hash("prompt-0"),
            12,
            quote("request-0"),
        )
        .unwrap();
        let entries = vec![
            SourceJournalEntry::PolicyAttemptIntent(first),
            SourceJournalEntry::AttemptSettled {
                turn: 0,
                attempt: 0,
                response: Vec::new(),
                response_digest: super::super::source_response_digest(&[]),
            },
            SourceJournalEntry::PolicyAttemptUsage {
                turn: 0,
                attempt: 0,
                ordinal: 0,
                usage: PolicyAttemptUsageV6::Observed {
                    context_tokens: 8,
                    output_tokens: 8,
                    cost_micros: 10,
                },
            },
        ];
        let totals = fold(&binding, &entries).unwrap().totals;
        assert_eq!(totals.exposure_context_tokens, 8);
        assert_eq!(totals.exposure_output_tokens, 8);
        assert!(intent(
            &binding.policy_binding().unwrap(),
            &binding,
            &entries,
            1,
            0,
            hash("request-1"),
            hash("prompt-1"),
            12,
            quote("request-1")
        )
        .is_err());
    }

    #[test]
    fn policy_usage_requires_the_immediately_closed_attempt() {
        let binding = binding();
        let first = intent(
            &binding.policy_binding().unwrap(),
            &binding,
            &[],
            0,
            0,
            hash("request-0"),
            hash("prompt-0"),
            12,
            quote("request-0"),
        )
        .unwrap();
        let entries = vec![
            SourceJournalEntry::PolicyAttemptIntent(first),
            SourceJournalEntry::PolicyAttemptUsage {
                turn: 0,
                attempt: 0,
                ordinal: 0,
                usage: PolicyAttemptUsageV6::Unknown,
            },
        ];
        assert!(matches!(
            fold(&binding, &entries),
            Err(SourceJournalError::Order)
        ));
    }
}

// V6-only journal construction stays with the V6 facts rather than growing
// the frozen source-journal root module.
impl SourceJournal {
    pub fn policy_attempt_intent(
        &self,
        turn: u32,
        attempt: u32,
        request_digest: String,
        prompt_digest: String,
        request_bytes: usize,
        quote: SourcePolicyQuoteV6,
    ) -> Result<PolicyAttemptIntentV6, SourceJournalError> {
        intent(
            self.binding
                .policy_binding()
                .ok_or(SourceJournalError::Binding)?,
            &self.binding,
            self.entries.as_slice(),
            turn,
            attempt,
            request_digest,
            prompt_digest,
            request_bytes,
            quote,
        )
    }

    pub fn policy_attempt_usage(
        &self,
        turn: u32,
        attempt: u32,
        ordinal: u64,
        usage_value: PolicyAttemptUsageV6,
    ) -> Result<SourceJournalEntry, SourceJournalError> {
        usage(
            &self.binding,
            self.entries.as_slice(),
            turn,
            attempt,
            ordinal,
            usage_value,
        )
    }
}

impl SourceCheckpointSink<'_> {
    /// Builds the V6 candidate a source adapter must acknowledge before
    /// reserving its physical model operation or constructing a provider.
    pub fn policy_attempt_intent(
        &self,
        turn: u32,
        attempt: u32,
        request_digest: String,
        prompt_digest: String,
        request_bytes: usize,
        quote: SourcePolicyQuoteV6,
    ) -> Result<PolicyAttemptIntentV6, SourceJournalError> {
        self.journal.policy_attempt_intent(
            turn,
            attempt,
            request_digest,
            prompt_digest,
            request_bytes,
            quote,
        )
    }

    pub fn policy_attempt_usage(
        &self,
        turn: u32,
        attempt: u32,
        ordinal: u64,
        usage: PolicyAttemptUsageV6,
    ) -> Result<SourceJournalEntry, SourceJournalError> {
        self.journal
            .policy_attempt_usage(turn, attempt, ordinal, usage)
    }
}
