//! Projects usage facts observed by a provider adapter into the receipt
//! reconciliation vocabulary.
//!
//! The adapter observation is immutable evidence of one attempt, while the
//! provider call id is retained independently by the host. This module joins
//! them only when the adapter expressly declared provider-reported accounting
//! and actually settled. Missing dimensions remain `None`; this module never
//! turns an absent provider field into zero or a local estimate.

use crate::provider_adapter_sdk::{AttemptObservation, AttemptTerminal, TokenAccountingSource};

use super::receipt::ProviderReportedUsage;
use super::reconciliation::ProviderReportedUsageFields;

/// Projects independently optional provider usage dimensions from one settled
/// adapter observation. `provider_call_id` is caller-retained identity, not a
/// value invented or inferred from the adapter's capability declaration.
#[must_use]
pub fn provider_reported_usage_fields(
    observation: &AttemptObservation,
    provider_call_id: &str,
) -> Option<ProviderReportedUsageFields> {
    if provider_call_id.is_empty()
        || provider_call_id.len() > 4096
        || observation.capture_overflow()
        || observation.capabilities().token_accounting_source()
            != TokenAccountingSource::ProviderReported
        || !matches!(
            observation.terminal(),
            Some(AttemptTerminal::Settled { .. })
        )
    {
        return None;
    }
    let usage = observation.settlement_usage()?;
    Some(ProviderReportedUsageFields {
        provider_call_id: provider_call_id.to_owned(),
        tokens_in: usage.tokens_in,
        tokens_out: usage.tokens_out,
        provider_cost_micros: usage.cost_micros,
    })
}

/// Returns the receipt's complete usage shape only when every independently
/// reported provider dimension exists. Partial provider reports must use
/// [`provider_reported_usage_fields`] so reconciliation can retain unknowns.
#[must_use]
pub fn complete_provider_reported_usage(
    observation: &AttemptObservation,
    provider_call_id: &str,
) -> Option<ProviderReportedUsage> {
    let fields = provider_reported_usage_fields(observation, provider_call_id)?;
    Some(ProviderReportedUsage {
        provider_call_id: fields.provider_call_id,
        tokens_in: fields.tokens_in?,
        tokens_out: fields.tokens_out?,
        provider_cost_micros: fields.provider_cost_micros?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model_call_receipt::reconciliation::{
        BillingReconciler, ProviderInvoiceRow, ReconciliationOutcome,
    };
    use crate::provider_adapter_sdk::fixture_adapters::{base_capabilities, ScriptedAdapter};
    use crate::provider_adapter_sdk::{
        AdapterEvent, AdapterInvocationCapability, AdapterPoll, AdapterRequest, AdapterSettlement,
        AdapterUsage, ProviderAdapter, RecordingAdapter,
    };

    fn observation(source: TokenAccountingSource, usage: AdapterUsage) -> AttemptObservation {
        let mut capabilities = base_capabilities("usage-projection", true);
        capabilities.token_accounting_source = source;
        let script = vec![
            AdapterPoll::Event(AdapterEvent::Delta(b"response".to_vec())),
            AdapterPoll::Event(AdapterEvent::Completed),
            AdapterPoll::Settled(AdapterSettlement {
                response_bytes: b"response".to_vec(),
                usage,
            }),
        ];
        let mut adapter = ScriptedAdapter::new(capabilities, script, true);
        let request = AdapterRequest {
            request_bytes: b"request".to_vec(),
            max_response_bytes: 4096,
        };
        let mut recorder = RecordingAdapter::new(&mut adapter, "sha256:grammar");
        recorder
            .start(&AdapterInvocationCapability::grant("usage test"), &request)
            .unwrap();
        while !matches!(recorder.poll(), AdapterPoll::Settled(_)) {}
        recorder.observation().clone()
    }

    fn invoice() -> ProviderInvoiceRow {
        ProviderInvoiceRow {
            provider_call_id: "provider-call-7".into(),
            account_id: "acct-1".into(),
            tokens_in: 11,
            tokens_out: 7,
            cost_micros: 33,
        }
    }

    #[test]
    fn settled_provider_reported_usage_projects_exactly_and_reconciles() {
        let observation = observation(
            TokenAccountingSource::ProviderReported,
            AdapterUsage {
                tokens_in: Some(11),
                tokens_out: Some(7),
                cost_micros: Some(33),
            },
        );
        let fields = provider_reported_usage_fields(&observation, "provider-call-7").unwrap();
        assert_eq!(
            fields,
            ProviderReportedUsageFields {
                provider_call_id: "provider-call-7".into(),
                tokens_in: Some(11),
                tokens_out: Some(7),
                provider_cost_micros: Some(33),
            }
        );
        assert_eq!(
            complete_provider_reported_usage(&observation, "provider-call-7"),
            Some(ProviderReportedUsage {
                provider_call_id: "provider-call-7".into(),
                tokens_in: 11,
                tokens_out: 7,
                provider_cost_micros: 33,
            })
        );
        let mut reconciler = BillingReconciler::new("acct-1");
        assert_eq!(
            reconciler.reconcile_provider_reported(&fields, Some(&invoice())),
            ReconciliationOutcome::Reconciled
        );
    }

    #[test]
    fn local_estimates_do_not_become_provider_reported_usage() {
        let observation = observation(
            TokenAccountingSource::LocalEstimate,
            AdapterUsage {
                tokens_in: Some(11),
                tokens_out: Some(7),
                cost_micros: Some(33),
            },
        );
        assert_eq!(
            provider_reported_usage_fields(&observation, "provider-call-7"),
            None
        );
        assert_eq!(
            complete_provider_reported_usage(&observation, "provider-call-7"),
            None
        );
    }

    #[test]
    fn empty_or_oversized_retained_provider_call_ids_are_not_projected() {
        let observation = observation(
            TokenAccountingSource::ProviderReported,
            AdapterUsage {
                tokens_in: Some(11),
                tokens_out: Some(7),
                cost_micros: Some(33),
            },
        );
        assert_eq!(provider_reported_usage_fields(&observation, ""), None);
        assert_eq!(
            provider_reported_usage_fields(&observation, &"x".repeat(4_097)),
            None
        );
    }

    #[test]
    fn partial_provider_usage_preserves_unknown_dimensions_and_refuses_complete_projection() {
        let observation = observation(
            TokenAccountingSource::ProviderReported,
            AdapterUsage {
                tokens_in: Some(11),
                tokens_out: None,
                cost_micros: None,
            },
        );
        assert_eq!(
            provider_reported_usage_fields(&observation, "provider-call-7"),
            Some(ProviderReportedUsageFields {
                provider_call_id: "provider-call-7".into(),
                tokens_in: Some(11),
                tokens_out: None,
                provider_cost_micros: None,
            })
        );
        assert_eq!(
            complete_provider_reported_usage(&observation, "provider-call-7"),
            None
        );
    }

    #[test]
    fn a_nonsettled_attempt_never_projects_usage() {
        let mut capabilities = base_capabilities("usage-projection", true);
        capabilities.token_accounting_source = TokenAccountingSource::ProviderReported;
        let mut adapter = ScriptedAdapter::new(
            capabilities,
            vec![AdapterPoll::Failed {
                failure: crate::live_invocation::model_invoke::ModelFailure::Timeout,
                attempted_bytes: 0,
            }],
            true,
        );
        let request = AdapterRequest {
            request_bytes: b"request".to_vec(),
            max_response_bytes: 4096,
        };
        let mut recorder = RecordingAdapter::new(&mut adapter, "sha256:grammar");
        recorder
            .start(&AdapterInvocationCapability::grant("usage test"), &request)
            .unwrap();
        assert!(matches!(recorder.poll(), AdapterPoll::Failed { .. }));
        assert_eq!(
            provider_reported_usage_fields(recorder.observation(), "provider-call-7"),
            None
        );
    }
}
