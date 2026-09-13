//! Additive byte-accounted wrapper around the frozen generic policy journal V2.

use serde_json::Value;

use crate::diagnostic::quote_json;
use crate::live_invocation::model_invoke::ModelInvocationRequest;
use crate::model_budget_policy::{
    AdapterAttemptPlan, DurableByteBudget, DurableByteLedger, DurableByteObservation,
    DurableByteRefusal, DurablePolicyBinding,
};

use super::policy_journal::{
    PolicyAttemptOutcome, PolicyJournal, PolicyJournalEntry, PolicyJournalError, PolicyRecovery,
};

pub(crate) const POLICY_JOURNAL_V3_SCHEMA: &str =
    "semaprax.live-invocation.generic-model-policy.v3";
pub(crate) const MAX_POLICY_V3_DOCUMENT_BYTES: usize = 1_048_576;

pub(crate) struct PolicyJournalV3 {
    inner: PolicyJournal,
    bytes: DurableByteLedger,
    request_bytes: u64,
    response_bytes: u64,
}

impl PolicyJournalV3 {
    pub(crate) fn new(
        binding: &DurablePolicyBinding,
        request: &ModelInvocationRequest,
        plan: &AdapterAttemptPlan,
        budget: DurableByteBudget,
    ) -> Result<Self, PolicyJournalError> {
        let request_bytes = u64::try_from(plan.required.max_request_bytes)
            .map_err(|_| PolicyJournalError::InvalidSequence)?;
        let response_bytes = u64::try_from(plan.required.max_response_bytes)
            .map_err(|_| PolicyJournalError::InvalidSequence)?;
        Ok(Self {
            inner: PolicyJournal::new(binding, request, plan),
            bytes: DurableByteLedger::new(budget),
            request_bytes,
            response_bytes,
        })
    }
    pub(crate) fn append_intent(
        &mut self,
        reservation: crate::model_budget_policy::AttemptReservation,
    ) -> Result<(), PolicyJournalError> {
        // Construct a complete next state before publishing either side of
        // this coupled journal.  A rejected V2 intent must not leave an
        // unpaired byte reservation behind to charge a later attempt.
        let mut next_inner = self.inner.clone();
        next_inner.append_intent(reservation.clone())?;
        let mut next_bytes = self.bytes.clone();
        let bytes = next_bytes
            .reserve(self.request_bytes, self.response_bytes)
            .map_err(byte_error)?;
        if bytes.ordinal != reservation.ordinal {
            return Err(PolicyJournalError::InvalidSequence);
        }
        self.inner = next_inner;
        self.bytes = next_bytes;
        Ok(())
    }
    pub(crate) fn append_outcome(
        &mut self,
        ordinal: u64,
        outcome: PolicyAttemptOutcome,
    ) -> Result<(), PolicyJournalError> {
        let (observed, unknown) = match &outcome {
            PolicyAttemptOutcome::Settled { response, .. } => (
                u64::try_from(response.len()).map_err(|_| PolicyJournalError::InvalidSequence)?,
                false,
            ),
            PolicyAttemptOutcome::Failed {
                attempted_bytes, ..
            } => (
                u64::try_from(*attempted_bytes).map_err(|_| PolicyJournalError::InvalidSequence)?,
                true,
            ),
        };
        // The adapter may already have received an overflowing chunk, but it
        // must not turn that overage into a durable outcome.  Leaving the
        // acknowledged intent unresolved is conservative: recovery returns
        // `Uncertain` and cannot redispatch it.  The byte-ledger primitive can
        // still represent unknown overage evidence for non-journal callers.
        if observed > self.response_bytes {
            return Err(PolicyJournalError::ResponseTooLarge);
        }
        // As with the intent, no rejected V2 settlement may leave a durable
        // byte observation without its corresponding outcome row.
        let mut next_inner = self.inner.clone();
        next_inner.append_outcome(ordinal, outcome)?;
        let mut next_bytes = self.bytes.clone();
        let reservation = *next_bytes
            .reservations()
            .get(usize::try_from(ordinal).map_err(|_| PolicyJournalError::InvalidSequence)?)
            .ok_or(PolicyJournalError::InvalidSequence)?;
        next_bytes
            .observe(reservation, observed, unknown)
            .map_err(byte_error)?;
        self.inner = next_inner;
        self.bytes = next_bytes;
        Ok(())
    }
    pub(crate) fn render(&self) -> Result<String, PolicyJournalError> {
        let budget = self.bytes_budget();
        let inner = self.inner.render();
        if inner.len() > MAX_POLICY_V3_DOCUMENT_BYTES {
            return Err(PolicyJournalError::ResponseTooLarge);
        }
        let prefix = format!("{{\"schema\":{},\"budget\":{{\"request\":{},\"response\":{},\"total_input\":{},\"total_output\":{}}},\"v2\":", quote_json(POLICY_JOURNAL_V3_SCHEMA), budget.max_request_bytes, budget.max_response_bytes, budget.max_total_input_bytes, budget.max_total_output_bytes);
        // Count quote_json's escaping before allocating the outer document.
        // The fixed-size header and closing brace/newline are included.
        let mut total = prefix.len() + 4;
        for character in inner.chars() {
            total += match character {
                '\"' | '\\' | '\n' | '\r' | '\t' => 2,
                character if character.is_control() => 6,
                character => character.len_utf8(),
            };
            if total > MAX_POLICY_V3_DOCUMENT_BYTES {
                return Err(PolicyJournalError::ResponseTooLarge);
            }
        }
        let rendered = format!("{}{}}}\n", prefix, quote_json(&inner));
        Ok(rendered)
    }
    pub(crate) fn inner(&self) -> &PolicyJournal {
        &self.inner
    }
    pub(crate) fn byte_observations(&self) -> &[Option<DurableByteObservation>] {
        self.bytes.observations()
    }
    fn bytes_budget(&self) -> DurableByteBudget {
        // retained in ledger but intentionally only exposed through canonical facts
        // Reconstructing from one zero reservation is impossible, so V3 owns these facts at construction.
        // The access is supplied below by a small ledger accessor.
        self.bytes.budget()
    }
}

impl PolicyJournalV3 {
    pub(crate) fn recover(
        document: &str,
        binding: &DurablePolicyBinding,
        request: &ModelInvocationRequest,
        plan: &AdapterAttemptPlan,
        budget: DurableByteBudget,
    ) -> Result<(Self, PolicyRecovery), PolicyJournalError> {
        if document.len() > MAX_POLICY_V3_DOCUMENT_BYTES {
            return Err(PolicyJournalError::Malformed);
        }
        let value: Value =
            serde_json::from_str(document).map_err(|_| PolicyJournalError::Malformed)?;
        let object = value.as_object().ok_or(PolicyJournalError::Malformed)?;
        if object.len() != 3
            || object.get("schema").and_then(Value::as_str) != Some(POLICY_JOURNAL_V3_SCHEMA)
        {
            return Err(PolicyJournalError::HeaderMismatch);
        }
        let expected = format!(
            "{{\"request\":{},\"response\":{},\"total_input\":{},\"total_output\":{}}}",
            budget.max_request_bytes,
            budget.max_response_bytes,
            budget.max_total_input_bytes,
            budget.max_total_output_bytes
        );
        let rendered =
            serde_json::to_string(object.get("budget").ok_or(PolicyJournalError::Malformed)?)
                .map_err(|_| PolicyJournalError::Malformed)?;
        if rendered != expected {
            return Err(PolicyJournalError::HeaderMismatch);
        }
        let inner = object
            .get("v2")
            .and_then(Value::as_str)
            .ok_or(PolicyJournalError::Malformed)?;
        let (inner, recovery) = PolicyJournal::recover(inner, binding, request, plan)?;
        let mut journal = Self::new(binding, request, plan, budget)?;
        for entry in inner.entries() {
            match entry {
                PolicyJournalEntry::Intent(reservation) => {
                    journal.append_intent(reservation.clone())?
                }
                PolicyJournalEntry::Outcome { ordinal, outcome } => {
                    journal.append_outcome(*ordinal, outcome.clone())?
                }
            }
        }
        if document != journal.render()? {
            return Err(PolicyJournalError::Malformed);
        }
        Ok((journal, recovery))
    }
}

fn byte_error(_: DurableByteRefusal) -> PolicyJournalError {
    PolicyJournalError::InvalidSequence
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::live_invocation::{LiveInvocationId, LiveInvocationSeed};
    use crate::model_budget_policy::{
        intersect, AttemptKind, AttemptReservation, DurablePolicyBinding, ModelBudgetLimits,
        ProviderPolicy, ProviderSlot,
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
    fn binding() -> DurablePolicyBinding {
        let mut limits = ModelBudgetLimits::unbounded();
        limits.max_calls = 3;
        limits.max_retries = 1;
        limits.max_providers = 1;
        limits.max_context_tokens = 8;
        limits.max_output_tokens = 8;
        limits.max_aggregate_tokens = 32;
        limits.max_cost_micros = 20;
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
            intersect(limits, limits, limits).unwrap(),
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
    fn budget() -> DurableByteBudget {
        DurableByteBudget {
            max_request_bytes: 1,
            max_response_bytes: 64,
            max_total_input_bytes: 3,
            max_total_output_bytes: 192,
        }
    }
    fn reservation() -> AttemptReservation {
        AttemptReservation {
            ordinal: 0,
            kind: AttemptKind::Fresh,
            provider_id: "primary".into(),
            reserved_context_tokens: 2,
            reserved_output_tokens: 1,
            reserved_cost_micros: 2,
        }
    }

    #[test]
    fn canonical_round_trip_rebuilds_byte_observation_from_frozen_v2() {
        let binding = binding();
        let request = request();
        let plan = plan();
        let mut journal = PolicyJournalV3::new(&binding, &request, &plan, budget()).unwrap();
        journal.append_intent(reservation()).unwrap();
        journal
            .append_outcome(
                0,
                PolicyAttemptOutcome::Failed {
                    class:
                        crate::model_budget_policy::AttemptOutcomeClass::ProviderReportedRetryable,
                    attempted_bytes: 0,
                },
            )
            .unwrap();
        let rendered = journal.render().unwrap();
        let (recovered, _) =
            PolicyJournalV3::recover(&rendered, &binding, &request, &plan, budget()).unwrap();
        assert_eq!(
            recovered.byte_observations()[0].unwrap().output_unknown,
            true
        );
        assert_eq!(recovered.inner().render(), journal.inner().render());
    }

    #[test]
    fn changed_budget_or_oversized_outer_document_refuses_before_inner_replay() {
        let binding = binding();
        let request = request();
        let plan = plan();
        let journal = PolicyJournalV3::new(&binding, &request, &plan, budget()).unwrap();
        let rendered = journal.render().unwrap();
        let changed = DurableByteBudget {
            max_total_output_bytes: 191,
            ..budget()
        };
        assert!(matches!(
            PolicyJournalV3::recover(&rendered, &binding, &request, &plan, changed),
            Err(PolicyJournalError::HeaderMismatch)
        ));
        assert!(matches!(
            PolicyJournalV3::recover(
                &"x".repeat(MAX_POLICY_V3_DOCUMENT_BYTES + 1),
                &binding,
                &request,
                &plan,
                budget()
            ),
            Err(PolicyJournalError::Malformed)
        ));
    }

    #[test]
    fn recovery_refuses_noncanonical_outer_bytes() {
        let binding = binding();
        let request = request();
        let plan = plan();
        let journal = PolicyJournalV3::new(&binding, &request, &plan, budget()).unwrap();
        let rendered = journal.render().unwrap();
        let noncanonical = format!("\n{rendered}");
        assert!(matches!(
            PolicyJournalV3::recover(&noncanonical, &binding, &request, &plan, budget()),
            Err(PolicyJournalError::Malformed)
        ));
    }

    #[test]
    fn rejected_append_keeps_the_byte_ledger_and_v2_rows_atomic() {
        let binding = binding();
        let request = request();
        let plan = plan();
        let mut journal = PolicyJournalV3::new(&binding, &request, &plan, budget()).unwrap();
        journal.append_intent(reservation()).unwrap();
        let before_rows = journal.inner().render();
        let before_reservations = journal.bytes.reservations().to_vec();
        assert!(matches!(
            journal.append_intent(crate::model_budget_policy::AttemptReservation {
                ordinal: 1,
                ..reservation()
            }),
            Err(PolicyJournalError::UnsafePrefix)
        ));
        assert_eq!(journal.inner().render(), before_rows);
        assert_eq!(journal.bytes.reservations(), before_reservations);
        assert_eq!(journal.byte_observations(), &[None]);

        let oversized = PolicyAttemptOutcome::Settled {
            response: vec![0; 65],
            usage: crate::provider_adapter_sdk::AdapterUsage {
                tokens_in: None,
                tokens_out: None,
                cost_micros: None,
            },
        };
        assert!(matches!(
            journal.append_outcome(0, oversized),
            Err(PolicyJournalError::ResponseTooLarge)
        ));
        assert_eq!(journal.inner().render(), before_rows);
        assert_eq!(journal.byte_observations(), &[None]);

        let overflowing_failure = PolicyAttemptOutcome::Failed {
            class: crate::model_budget_policy::AttemptOutcomeClass::ProviderReportedRetryable,
            attempted_bytes: 65,
        };
        assert!(matches!(
            journal.append_outcome(0, overflowing_failure),
            Err(PolicyJournalError::ResponseTooLarge)
        ));
        assert_eq!(journal.inner().render(), before_rows);
        assert_eq!(journal.byte_observations(), &[None]);
        assert!(matches!(
            PolicyJournalV3::recover(
                &journal.render().unwrap(),
                &binding,
                &request,
                &plan,
                budget()
            ),
            Ok((_, PolicyRecovery::Uncertain))
        ));
    }
}
