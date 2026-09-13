//! Durable generic retry/failover journal v2.
//!
//! V1 `JournalEntry` remains frozen.  This profile records one exact model
//! request and every separately charged policy attempt.  An intent without an
//! outcome is an uncertain prefix; recovery refuses it before an adapter is
//! constructed.

use serde_json::Value;

use crate::diagnostic::quote_json;
use crate::live_invocation::identity::{digest, hex, unhex};
use crate::live_invocation::model_invoke::ModelInvocationRequest;
use crate::model_budget_policy::retry::RetryCursor;
use crate::model_budget_policy::AdapterAttemptPlan;
use crate::model_budget_policy::{
    retry_is_permitted, AttemptKind, AttemptOutcomeClass, AttemptReservation, DurablePolicyBinding,
};
use crate::provider_adapter_sdk::AdapterUsage;

pub(crate) const POLICY_JOURNAL_SCHEMA: &str = "semaprax.live-invocation.generic-model-policy.v2";
pub(crate) const MAX_POLICY_ENTRIES: usize = 2048;
pub(crate) const MAX_POLICY_RESPONSE_BYTES: usize = 65_536;
const MAX_POLICY_DOCUMENT_BYTES: usize = 1_048_576;
const CHAIN_DOMAIN: &[u8] = b"semaprax.live-invocation.generic-model-policy.chain.v2\0";

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum PolicyAttemptOutcome {
    Settled {
        response: Vec<u8>,
        usage: AdapterUsage,
    },
    Failed {
        class: AttemptOutcomeClass,
        attempted_bytes: usize,
    },
}

impl PolicyAttemptOutcome {
    pub(crate) fn class(&self) -> AttemptOutcomeClass {
        match self {
            Self::Settled { .. } => AttemptOutcomeClass::CompletedWithResponse,
            Self::Failed { class, .. } => *class,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum PolicyJournalEntry {
    Intent(AttemptReservation),
    Outcome {
        ordinal: u64,
        outcome: PolicyAttemptOutcome,
    },
}

/// Exact durable state; the raw canonical request is retained so recovery
/// rejects a sidecar that changes a typed request field while retaining a
/// previously valid digest.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PolicyJournal {
    binding_digest: String,
    invocation: String,
    request: String,
    quote: String,
    entries: Vec<PolicyJournalEntry>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum PolicyJournalError {
    Malformed,
    HeaderMismatch,
    RequestMismatch,
    TooManyEntries,
    ResponseTooLarge,
    InvalidSequence,
    UnsafePrefix,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum PolicyRecovery {
    /// A completed response is replayed without creating a factory.
    Settled(Vec<u8>),
    /// A safe failure admits one later scheduler step using this prefix.
    Continue {
        reservations: Vec<AttemptReservation>,
        cursor: RetryCursor,
    },
    /// An intent was committed before its dispatch/settlement crossed the
    /// durable boundary, or its failure is unsafe.  Neither is retried.
    Uncertain,
}

impl PolicyJournal {
    pub(crate) fn new(
        binding: &DurablePolicyBinding,
        request: &ModelInvocationRequest,
        plan: &AdapterAttemptPlan,
    ) -> Self {
        Self {
            binding_digest: binding.digest().to_owned(),
            invocation: binding.invocation().digest().to_owned(),
            request: request.canonical_json(),
            quote: quote(plan),
            entries: Vec::new(),
        }
    }

    pub(crate) fn entries(&self) -> &[PolicyJournalEntry] {
        &self.entries
    }

    pub(crate) fn append_intent(
        &mut self,
        reservation: AttemptReservation,
    ) -> Result<(), PolicyJournalError> {
        if self.entries.len() >= MAX_POLICY_ENTRIES {
            return Err(PolicyJournalError::TooManyEntries);
        }
        if self
            .entries
            .last()
            .is_some_and(|entry| matches!(entry, PolicyJournalEntry::Intent(_)))
        {
            return Err(PolicyJournalError::UnsafePrefix);
        }
        self.entries.push(PolicyJournalEntry::Intent(reservation));
        Ok(())
    }

    pub(crate) fn append_outcome(
        &mut self,
        ordinal: u64,
        outcome: PolicyAttemptOutcome,
    ) -> Result<(), PolicyJournalError> {
        if matches!(outcome, PolicyAttemptOutcome::Settled { ref response, .. } if response.len() > MAX_POLICY_RESPONSE_BYTES)
        {
            return Err(PolicyJournalError::ResponseTooLarge);
        }
        let Some(PolicyJournalEntry::Intent(intent)) = self.entries.last() else {
            return Err(PolicyJournalError::InvalidSequence);
        };
        if intent.ordinal != ordinal {
            return Err(PolicyJournalError::InvalidSequence);
        }
        self.entries
            .push(PolicyJournalEntry::Outcome { ordinal, outcome });
        Ok(())
    }

    pub(crate) fn render(&self) -> String {
        let entries = self
            .entries
            .iter()
            .map(render_entry)
            .collect::<Vec<_>>()
            .join(",");
        let chain = digest(CHAIN_DOMAIN, entries.as_bytes());
        format!(
            "{{\"schema\":{},\"binding\":{},\"invocation\":{},\"request\":{},\"quote\":{},\"chain\":{},\"entries\":[{}]}}\n",
            quote_json(POLICY_JOURNAL_SCHEMA),
            quote_json(&self.binding_digest),
            quote_json(&self.invocation),
            quote_json(&self.request),
            quote_json(&self.quote),
            quote_json(&chain),
            entries,
        )
    }

    pub(crate) fn recover(
        document: &str,
        binding: &DurablePolicyBinding,
        request: &ModelInvocationRequest,
        plan: &AdapterAttemptPlan,
    ) -> Result<(Self, PolicyRecovery), PolicyJournalError> {
        if document.len() > MAX_POLICY_DOCUMENT_BYTES {
            return Err(PolicyJournalError::Malformed);
        }
        let value: Value =
            serde_json::from_str(document).map_err(|_| PolicyJournalError::Malformed)?;
        let object = value.as_object().ok_or(PolicyJournalError::Malformed)?;
        if object.len() != 7
            || object.get("schema").and_then(Value::as_str) != Some(POLICY_JOURNAL_SCHEMA)
            || object.get("binding").and_then(Value::as_str) != Some(binding.digest())
            || object.get("invocation").and_then(Value::as_str)
                != Some(binding.invocation().digest())
        {
            return Err(PolicyJournalError::HeaderMismatch);
        }
        let canonical = request.canonical_json();
        if object.get("request").and_then(Value::as_str) != Some(canonical.as_str()) {
            return Err(PolicyJournalError::RequestMismatch);
        }
        let expected_quote = quote(plan);
        if object.get("quote").and_then(Value::as_str) != Some(expected_quote.as_str()) {
            return Err(PolicyJournalError::RequestMismatch);
        }
        let raw_entries = object
            .get("entries")
            .and_then(Value::as_array)
            .ok_or(PolicyJournalError::Malformed)?;
        if raw_entries.len() > MAX_POLICY_ENTRIES {
            return Err(PolicyJournalError::TooManyEntries);
        }
        let entries = raw_entries
            .iter()
            .map(parse_entry)
            .collect::<Result<Vec<_>, _>>()?;
        let rendered = entries
            .iter()
            .map(render_entry)
            .collect::<Vec<_>>()
            .join(",");
        if object.get("chain").and_then(Value::as_str)
            != Some(digest(CHAIN_DOMAIN, rendered.as_bytes()).as_str())
        {
            return Err(PolicyJournalError::HeaderMismatch);
        }
        let journal = Self {
            binding_digest: binding.digest().to_owned(),
            invocation: binding.invocation().digest().to_owned(),
            request: canonical,
            quote: expected_quote,
            entries,
        };
        let recovery = journal.validate_prefix(binding, plan)?;
        Ok((journal, recovery))
    }

    fn validate_prefix(
        &self,
        binding: &DurablePolicyBinding,
        plan: &AdapterAttemptPlan,
    ) -> Result<PolicyRecovery, PolicyJournalError> {
        let mut reservations = Vec::new();
        let mut expected_ordinal = 0u64;
        let mut prior = None;
        let mut provider_index = 0usize;
        let mut retries = 0u32;
        let mut continuations = 0u32;
        let mut failovers = 0u32;
        let mut aggregate_tokens = 0u64;
        let mut aggregate_cost = 0i64;
        let limits = binding.limits().limits();
        let mut index = 0usize;
        while index < self.entries.len() {
            let PolicyJournalEntry::Intent(intent) = &self.entries[index] else {
                return Err(PolicyJournalError::InvalidSequence);
            };
            if intent.ordinal != expected_ordinal || intent.provider_id.len() > 256 {
                return Err(PolicyJournalError::InvalidSequence);
            }
            let expected_kind = if intent.ordinal == 0 {
                AttemptKind::Fresh
            } else if retries < limits.max_retries {
                AttemptKind::Retry
            } else {
                AttemptKind::Failover
            };
            validate_reservation(binding, intent, provider_index, prior, expected_kind)?;
            if intent.reserved_context_tokens != plan.context_tokens
                || intent.reserved_output_tokens != plan.requested_output_tokens
                || intent.reserved_cost_micros != plan.estimated_cost_micros
            {
                return Err(PolicyJournalError::InvalidSequence);
            }
            let total = intent
                .reserved_context_tokens
                .checked_add(intent.reserved_output_tokens)
                .ok_or(PolicyJournalError::InvalidSequence)?;
            aggregate_tokens = aggregate_tokens
                .checked_add(total)
                .ok_or(PolicyJournalError::InvalidSequence)?;
            aggregate_cost = aggregate_cost
                .checked_add(intent.reserved_cost_micros)
                .ok_or(PolicyJournalError::InvalidSequence)?;
            if u32::try_from(reservations.len() + 1)
                .map_err(|_| PolicyJournalError::InvalidSequence)?
                > limits.max_calls
                || aggregate_tokens > limits.max_aggregate_tokens
                || aggregate_cost > limits.max_cost_micros
            {
                return Err(PolicyJournalError::InvalidSequence);
            }
            if intent.kind == AttemptKind::Retry {
                retries = retries
                    .checked_add(1)
                    .ok_or(PolicyJournalError::InvalidSequence)?;
            }
            if intent.kind != AttemptKind::Fresh {
                continuations = continuations
                    .checked_add(1)
                    .ok_or(PolicyJournalError::InvalidSequence)?;
            }
            if intent.kind == AttemptKind::Failover {
                failovers = failovers
                    .checked_add(1)
                    .ok_or(PolicyJournalError::InvalidSequence)?;
                if failovers > limits.max_providers {
                    return Err(PolicyJournalError::InvalidSequence);
                }
                provider_index = provider_index
                    .checked_add(1)
                    .ok_or(PolicyJournalError::InvalidSequence)?;
            }
            reservations.push(intent.clone());
            expected_ordinal = expected_ordinal
                .checked_add(1)
                .ok_or(PolicyJournalError::InvalidSequence)?;
            let Some(PolicyJournalEntry::Outcome { ordinal, outcome }) =
                self.entries.get(index + 1)
            else {
                return Ok(PolicyRecovery::Uncertain);
            };
            if *ordinal != intent.ordinal {
                return Err(PolicyJournalError::InvalidSequence);
            }
            match outcome {
                PolicyAttemptOutcome::Settled { response, .. } => {
                    if response.len() > MAX_POLICY_RESPONSE_BYTES || index + 2 != self.entries.len()
                    {
                        return Err(PolicyJournalError::InvalidSequence);
                    }
                    return Ok(PolicyRecovery::Settled(response.clone()));
                }
                PolicyAttemptOutcome::Failed {
                    class,
                    attempted_bytes,
                } if retry_is_permitted(*class) && *attempted_bytes == 0 => prior = Some(*class),
                PolicyAttemptOutcome::Failed { class, .. } if retry_is_permitted(*class) => {
                    return Err(PolicyJournalError::UnsafePrefix);
                }
                PolicyAttemptOutcome::Failed { .. } => {
                    if index + 2 != self.entries.len() {
                        return Err(PolicyJournalError::InvalidSequence);
                    }
                    return Ok(PolicyRecovery::Uncertain);
                }
            }
            index += 2;
        }
        let cursor = if reservations.is_empty() {
            RetryCursor::FRESH
        } else {
            RetryCursor {
                provider_index,
                kind: AttemptKind::Retry,
                prior,
                retry_ordinal: continuations,
            }
        };
        Ok(PolicyRecovery::Continue {
            reservations,
            cursor,
        })
    }
}

fn validate_reservation(
    binding: &DurablePolicyBinding,
    intent: &AttemptReservation,
    provider_index: usize,
    prior: Option<AttemptOutcomeClass>,
    expected_kind: AttemptKind,
) -> Result<(), PolicyJournalError> {
    if intent.kind != expected_kind {
        return Err(PolicyJournalError::InvalidSequence);
    }
    if intent.kind == AttemptKind::Fresh && (intent.ordinal != 0 || prior.is_some()) {
        return Err(PolicyJournalError::InvalidSequence);
    }
    if intent.kind != AttemptKind::Fresh && !prior.is_some_and(retry_is_permitted) {
        return Err(PolicyJournalError::UnsafePrefix);
    }
    let slot_index = if intent.kind == AttemptKind::Failover {
        provider_index + 1
    } else {
        provider_index
    };
    let slot = binding
        .policy()
        .slot(slot_index)
        .ok_or(PolicyJournalError::InvalidSequence)?;
    if !slot.authorized || slot.id != intent.provider_id {
        return Err(PolicyJournalError::InvalidSequence);
    }
    let limits = binding.limits().limits();
    if intent.reserved_context_tokens > limits.max_context_tokens
        || intent.reserved_output_tokens > limits.max_output_tokens
        || intent.reserved_cost_micros < 0
        || intent
            .reserved_context_tokens
            .checked_add(intent.reserved_output_tokens)
            .is_none()
    {
        return Err(PolicyJournalError::InvalidSequence);
    }
    Ok(())
}

fn render_entry(entry: &PolicyJournalEntry) -> String {
    match entry {
        PolicyJournalEntry::Intent(intent) => format!(
            "{{\"tag\":\"intent\",\"ordinal\":{},\"kind\":{},\"provider\":{},\"context\":{},\"output\":{},\"cost\":{}}}",
            intent.ordinal, quote_json(kind_tag(intent.kind)), quote_json(&intent.provider_id),
            intent.reserved_context_tokens, intent.reserved_output_tokens, intent.reserved_cost_micros,
        ),
        PolicyJournalEntry::Outcome { ordinal, outcome } => match outcome {
            PolicyAttemptOutcome::Settled { response, usage } => format!(
                "{{\"tag\":\"settled\",\"ordinal\":{},\"response\":{},\"usage\":{{\"tokens_in\":{},\"tokens_out\":{},\"cost_micros\":{}}}}}",
                ordinal, quote_json(&hex(response)), render_optional_u64(usage.tokens_in), render_optional_u64(usage.tokens_out), render_optional_i64(usage.cost_micros),
            ),
            PolicyAttemptOutcome::Failed { class, attempted_bytes } => format!(
                "{{\"tag\":\"failed\",\"ordinal\":{},\"class\":{},\"attempted_bytes\":{}}}",
                ordinal, quote_json(class.as_str()), attempted_bytes,
            ),
        },
    }
}

fn parse_entry(value: &Value) -> Result<PolicyJournalEntry, PolicyJournalError> {
    let object = value.as_object().ok_or(PolicyJournalError::Malformed)?;
    let tag = object
        .get("tag")
        .and_then(Value::as_str)
        .ok_or(PolicyJournalError::Malformed)?;
    match tag {
        "intent" if object.len() == 7 => Ok(PolicyJournalEntry::Intent(AttemptReservation {
            ordinal: number(object, "ordinal")?,
            kind: parse_kind(string(object, "kind")?)?,
            provider_id: string(object, "provider")?.to_owned(),
            reserved_context_tokens: number(object, "context")?,
            reserved_output_tokens: number(object, "output")?,
            reserved_cost_micros: signed(object, "cost")?,
        })),
        "settled" if object.len() == 4 => {
            let encoded = string(object, "response")?;
            if encoded.len() > MAX_POLICY_RESPONSE_BYTES.saturating_mul(2) {
                return Err(PolicyJournalError::ResponseTooLarge);
            }
            let response = unhex(encoded).ok_or(PolicyJournalError::Malformed)?;
            let usage = object
                .get("usage")
                .and_then(Value::as_object)
                .ok_or(PolicyJournalError::Malformed)?;
            if usage.len() != 3 {
                return Err(PolicyJournalError::Malformed);
            }
            Ok(PolicyJournalEntry::Outcome {
                ordinal: number(object, "ordinal")?,
                outcome: PolicyAttemptOutcome::Settled {
                    response,
                    usage: AdapterUsage {
                        tokens_in: parse_optional_u64(usage, "tokens_in")?,
                        tokens_out: parse_optional_u64(usage, "tokens_out")?,
                        cost_micros: parse_optional_i64(usage, "cost_micros")?,
                    },
                },
            })
        }
        "failed" if object.len() == 4 => Ok(PolicyJournalEntry::Outcome {
            ordinal: number(object, "ordinal")?,
            outcome: PolicyAttemptOutcome::Failed {
                class: parse_class(string(object, "class")?)?,
                attempted_bytes: number(object, "attempted_bytes")?,
            },
        }),
        _ => Err(PolicyJournalError::Malformed),
    }
}

fn string<'a>(
    object: &'a serde_json::Map<String, Value>,
    key: &str,
) -> Result<&'a str, PolicyJournalError> {
    object
        .get(key)
        .and_then(Value::as_str)
        .ok_or(PolicyJournalError::Malformed)
}
fn number<T: TryFrom<u64>>(
    object: &serde_json::Map<String, Value>,
    key: &str,
) -> Result<T, PolicyJournalError> {
    object
        .get(key)
        .and_then(Value::as_u64)
        .and_then(|n| n.try_into().ok())
        .ok_or(PolicyJournalError::Malformed)
}
fn signed(object: &serde_json::Map<String, Value>, key: &str) -> Result<i64, PolicyJournalError> {
    object
        .get(key)
        .and_then(Value::as_i64)
        .ok_or(PolicyJournalError::Malformed)
}
fn render_optional_u64(value: Option<u64>) -> String {
    value.map_or_else(|| "null".to_owned(), |item| item.to_string())
}
fn render_optional_i64(value: Option<i64>) -> String {
    value.map_or_else(|| "null".to_owned(), |item| item.to_string())
}
fn parse_optional_u64(
    object: &serde_json::Map<String, Value>,
    key: &str,
) -> Result<Option<u64>, PolicyJournalError> {
    match object.get(key) {
        Some(Value::Null) => Ok(None),
        Some(value) => value
            .as_u64()
            .map(Some)
            .ok_or(PolicyJournalError::Malformed),
        None => Err(PolicyJournalError::Malformed),
    }
}
fn parse_optional_i64(
    object: &serde_json::Map<String, Value>,
    key: &str,
) -> Result<Option<i64>, PolicyJournalError> {
    match object.get(key) {
        Some(Value::Null) => Ok(None),
        Some(value) => value
            .as_i64()
            .map(Some)
            .ok_or(PolicyJournalError::Malformed),
        None => Err(PolicyJournalError::Malformed),
    }
}
fn kind_tag(kind: AttemptKind) -> &'static str {
    match kind {
        AttemptKind::Fresh => "fresh",
        AttemptKind::Retry => "retry",
        AttemptKind::Failover => "failover",
    }
}
fn parse_kind(tag: &str) -> Result<AttemptKind, PolicyJournalError> {
    match tag {
        "fresh" => Ok(AttemptKind::Fresh),
        "retry" => Ok(AttemptKind::Retry),
        "failover" => Ok(AttemptKind::Failover),
        _ => Err(PolicyJournalError::Malformed),
    }
}
fn parse_class(tag: &str) -> Result<AttemptOutcomeClass, PolicyJournalError> {
    match tag {
        "not_dispatched" => Ok(AttemptOutcomeClass::NotDispatched),
        "rejected_before_processing" => Ok(AttemptOutcomeClass::RejectedBeforeProcessing),
        "completed_with_response" => Ok(AttemptOutcomeClass::CompletedWithResponse),
        "uncertain" => Ok(AttemptOutcomeClass::Uncertain),
        "provider_reported_retryable" => Ok(AttemptOutcomeClass::ProviderReportedRetryable),
        _ => Err(PolicyJournalError::Malformed),
    }
}
fn quote(plan: &AdapterAttemptPlan) -> String {
    let mode = plan
        .required
        .require_structured_output_mode
        .map(|mode| quote_json(mode.as_str()))
        .unwrap_or_else(|| "null".to_owned());
    format!(
        "{{\"context\":{},\"output\":{},\"cost\":{},\"polls\":{},\"request_bytes\":{},\"response_bytes\":{},\"streaming\":{},\"structured_output_mode\":{}}}",
        plan.context_tokens,
        plan.requested_output_tokens,
        plan.estimated_cost_micros,
        plan.max_polls,
        plan.required.max_request_bytes,
        plan.required.max_response_bytes,
        plan.required.require_streaming,
        mode,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::live_invocation::{LiveInvocationId, LiveInvocationSeed};
    use crate::model_budget_policy::{
        intersect, DurablePolicyBinding, ModelBudgetLimits, ProviderPolicy, ProviderSlot,
    };

    fn request() -> ModelInvocationRequest {
        ModelInvocationRequest {
            turn: 0,
            task: b"task".to_vec(),
            observation: b"observation".to_vec(),
            proposal_grammar_digest: "sha256:schema".into(),
            deployment_binding: "sha256:test-policy".into(),
            max_response_bytes: 64,
            effective_budget: 1,
        }
    }

    fn binding(retries: u32) -> DurablePolicyBinding {
        let mut limits = ModelBudgetLimits::unbounded();
        limits.max_calls = 3;
        limits.max_retries = retries;
        limits.max_providers = 1;
        limits.max_context_tokens = 8;
        limits.max_output_tokens = 8;
        limits.max_aggregate_tokens = 32;
        limits.max_cost_micros = 20;
        let limits = intersect(limits, limits, limits).unwrap();
        DurablePolicyBinding::fixture(
            LiveInvocationId::derive(&LiveInvocationSeed {
                program_root: "sha256:program".into(),
                deployment_policy: "sha256:test-policy".into(),
                task: b"task".to_vec(),
                budget: 1,
                interaction_schema_digest: "sha256:schema".into(),
                approved_providers: vec!["primary".into(), "fallback".into()],
            }),
            ProviderPolicy::new(vec![
                ProviderSlot::authorized("primary"),
                ProviderSlot::authorized("fallback"),
            ]),
            limits,
            b"task",
            "sha256:schema",
            1,
        )
    }

    fn plan() -> AdapterAttemptPlan {
        AdapterAttemptPlan {
            required: crate::provider_adapter_sdk::RequiredCapabilities {
                require_streaming: false,
                require_structured_output_mode: None,
                max_request_bytes: 1,
                max_response_bytes: 64,
            },
            context_tokens: 2,
            requested_output_tokens: 1,
            estimated_cost_micros: 2,
            max_polls: 1,
        }
    }

    fn reservation(ordinal: u64, kind: AttemptKind, provider: &str) -> AttemptReservation {
        AttemptReservation {
            ordinal,
            kind,
            provider_id: provider.into(),
            reserved_context_tokens: 2,
            reserved_output_tokens: 1,
            reserved_cost_micros: 2,
        }
    }

    #[test]
    fn unresolved_intent_recovers_as_uncertain_without_a_retry_cursor() {
        let binding = binding(1);
        let request = request();
        let mut journal = PolicyJournal::new(&binding, &request, &plan());
        journal
            .append_intent(reservation(0, AttemptKind::Fresh, "primary"))
            .unwrap();
        let (_, recovered) =
            PolicyJournal::recover(&journal.render(), &binding, &request, &plan()).unwrap();
        assert_eq!(recovered, PolicyRecovery::Uncertain);
    }

    #[test]
    fn safe_failure_recovers_the_next_retry_cursor_and_preserves_the_charge() {
        let binding = binding(1);
        let request = request();
        let mut journal = PolicyJournal::new(&binding, &request, &plan());
        journal
            .append_intent(reservation(0, AttemptKind::Fresh, "primary"))
            .unwrap();
        journal
            .append_outcome(
                0,
                PolicyAttemptOutcome::Failed {
                    class: AttemptOutcomeClass::ProviderReportedRetryable,
                    attempted_bytes: 0,
                },
            )
            .unwrap();
        let (_, recovered) =
            PolicyJournal::recover(&journal.render(), &binding, &request, &plan()).unwrap();
        let PolicyRecovery::Continue {
            reservations,
            cursor,
        } = recovered
        else {
            panic!("safe failure must continue")
        };
        assert_eq!(
            reservations,
            vec![reservation(0, AttemptKind::Fresh, "primary")]
        );
        assert_eq!(cursor.kind, AttemptKind::Retry);
        assert_eq!(cursor.provider_index, 0);
    }

    #[test]
    fn failover_is_rejected_until_the_retry_ceiling_is_exhausted() {
        let binding = binding(1);
        let request = request();
        let mut journal = PolicyJournal::new(&binding, &request, &plan());
        journal
            .append_intent(reservation(0, AttemptKind::Fresh, "primary"))
            .unwrap();
        journal
            .append_outcome(
                0,
                PolicyAttemptOutcome::Failed {
                    class: AttemptOutcomeClass::ProviderReportedRetryable,
                    attempted_bytes: 0,
                },
            )
            .unwrap();
        journal
            .append_intent(reservation(1, AttemptKind::Failover, "fallback"))
            .unwrap();
        assert!(matches!(
            PolicyJournal::recover(&journal.render(), &binding, &request, &plan()),
            Err(PolicyJournalError::InvalidSequence)
        ));
    }

    #[test]
    fn safe_classification_with_observed_bytes_never_reopens_the_retry_cursor() {
        let binding = binding(1);
        let request = request();
        let mut journal = PolicyJournal::new(&binding, &request, &plan());
        journal
            .append_intent(reservation(0, AttemptKind::Fresh, "primary"))
            .unwrap();
        journal
            .append_outcome(
                0,
                PolicyAttemptOutcome::Failed {
                    class: AttemptOutcomeClass::ProviderReportedRetryable,
                    attempted_bytes: 1,
                },
            )
            .unwrap();
        assert!(matches!(
            PolicyJournal::recover(&journal.render(), &binding, &request, &plan()),
            Err(PolicyJournalError::UnsafePrefix)
        ));
    }

    #[test]
    fn changed_streaming_or_structured_output_quote_is_not_a_recovery_equivalent() {
        let binding = binding(0);
        let request = request();
        let journal = PolicyJournal::new(&binding, &request, &plan());
        let mut changed = plan();
        changed.required.require_streaming = true;
        assert!(matches!(
            PolicyJournal::recover(&journal.render(), &binding, &request, &changed),
            Err(PolicyJournalError::RequestMismatch)
        ));
        changed.required.require_streaming = false;
        changed.required.require_structured_output_mode =
            Some(crate::provider_adapter_sdk::StructuredOutputMode::RawText);
        assert!(matches!(
            PolicyJournal::recover(&journal.render(), &binding, &request, &changed),
            Err(PolicyJournalError::RequestMismatch)
        ));
    }

    #[test]
    fn changed_canonical_request_or_later_entry_after_uncertainty_is_refused() {
        let binding = binding(0);
        let request = request();
        let mut journal = PolicyJournal::new(&binding, &request, &plan());
        journal
            .append_intent(reservation(0, AttemptKind::Fresh, "primary"))
            .unwrap();
        journal
            .append_outcome(
                0,
                PolicyAttemptOutcome::Failed {
                    class: AttemptOutcomeClass::Uncertain,
                    attempted_bytes: 1,
                },
            )
            .unwrap();
        journal
            .append_intent(reservation(1, AttemptKind::Failover, "fallback"))
            .unwrap();
        assert!(matches!(
            PolicyJournal::recover(&journal.render(), &binding, &request, &plan()),
            Err(PolicyJournalError::InvalidSequence)
        ));
        let mut stale = request.clone();
        stale.max_response_bytes = 65;
        assert!(matches!(
            PolicyJournal::recover(&journal.render(), &binding, &stale, &plan()),
            Err(PolicyJournalError::RequestMismatch)
        ));
    }
}
