//! Bounded, in-process retry and ordered provider-failover orchestration.
//!
//! The scheduler owns no endpoint, credential, wall clock, or sleep API. A
//! host injects one fresh [`ProviderAdapter`] factory, its explicit adapter
//! capability, a trusted failure classifier, and an optional deterministic
//! backoff seam. Every factory/start/poll path first reserves its own ledger
//! ordinal, so a retry and a failover are separately charged attempts rather
//! than a replay of the previous call.

use crate::agent_deployment::DeploymentModelSelection;
use crate::agent_interaction_schema::CompiledInteractionSchema;
use crate::agent_runtime::AgentCancellation;
use crate::live_invocation::{
    budget::InvocationClock,
    model_invoke::{ModelFailure, ModelInvocationRequest},
};
use crate::provider_adapter_sdk::bridge::adapter_request_for;
use crate::provider_adapter_sdk::{
    negotiate, AdapterEvent, AdapterInvocationCapability, AdapterPoll, AdapterRefusal,
    AdapterRequest, AdapterUsage, NegotiationRefusal, ProviderAdapter, RequiredCapabilities,
    StructuredOutputMode,
};

use super::{
    retry_is_permitted, AttemptKind, AttemptOutcomeClass, AttemptRefusal, AttemptRequest,
    AttemptReservation, AttemptUsage, EffectiveModelBudget, ModelPolicyLedger, ProviderPolicy,
};

#[path = "retry/durable.rs"]
mod durable;

/// A hard upper bound on host adapter polls for one model attempt. The host
/// may request a smaller bound in [`AdapterAttemptPlan`], never a larger one.
pub const MAX_ATTEMPT_POLLS: usize = 10_000;
pub const MAX_RETAINED_ATTEMPTS: usize = 1_024;
const MAX_ADAPTER_REQUEST_BYTES: usize = 65_536;
const MAX_PROVIDER_SLOTS: usize = 256;
const MAX_PROVIDER_ID_BYTES: usize = 256;

/// Constructs one fresh SDK adapter for an exact, deployment-selected
/// provider profile. Factory construction is explicit host authority; it is
/// never inferred from model bytes or an environment lookup by this module.
pub trait ProviderAdapterFactory {
    fn create(
        &mut self,
        provider_id: &str,
    ) -> Result<Box<dyn ProviderAdapter>, AdapterFactoryRefusal>;
}

impl<F> ProviderAdapterFactory for F
where
    F: FnMut(&str) -> Result<Box<dyn ProviderAdapter>, AdapterFactoryRefusal>,
{
    fn create(
        &mut self,
        provider_id: &str,
    ) -> Result<Box<dyn ProviderAdapter>, AdapterFactoryRefusal> {
        self(provider_id)
    }
}

/// A host-local factory failure. It means no adapter was created, hence no
/// provider dispatch could have occurred.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdapterFactoryRefusal(pub String);

/// Maps a normalized failure observed *after* adapter start to the closed
/// retry-safety classification. Implementations are trusted host/adapter
/// policy: raw provider response bytes never reach this interface.
pub trait FailureClassifier {
    fn classify(&mut self, provider_id: &str, failure: ModelFailure) -> AttemptOutcomeClass;
}

/// Conservative default for hosts without independent settlement evidence.
/// A failure after `start` may have reached and charged a provider, so it
/// stops the schedule rather than retrying or failing over.
#[derive(Clone, Copy, Debug, Default)]
pub struct ConservativeFailureClassifier;

impl FailureClassifier for ConservativeFailureClassifier {
    fn classify(&mut self, _: &str, _: ModelFailure) -> AttemptOutcomeClass {
        AttemptOutcomeClass::Uncertain
    }
}

/// The explicit backoff callback made between admitted automatic attempts.
/// The scheduler never sleeps, reads time, or schedules runtime work itself.
pub trait RetryBackoff {
    fn wait(&mut self, retry_ordinal: u32, provider_id: &str) -> Result<(), RetryBackoffRefusal>;
}

/// Durable observation of an admitted attempt.  The scheduler calls
/// [`Self::intent`] after the ledger has charged an ordinal but before it
/// constructs an adapter, and [`Self::settled`] after the adapter returns.
/// A checkpoint refusal stops the scheduler: an intent that was written but
/// whose settlement was not written is deliberately recovered as uncertain,
/// never retried.
pub trait RetryAttemptJournal {
    fn intent(&mut self, reservation: &AttemptReservation) -> Result<(), String>;
    fn settled(
        &mut self,
        reservation: &AttemptReservation,
        result: &AdapterAttemptResult,
    ) -> Result<(), String>;
}

/// The next admissible scheduler step after a validated durable prefix.
/// Construction is intentionally crate-private: persistence recovery derives
/// this from the complete ordered evidence prefix, so callers cannot skip a
/// prior uncertain result or select a later provider themselves.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct RetryCursor {
    pub(crate) provider_index: usize,
    pub(crate) kind: AttemptKind,
    pub(crate) prior: Option<AttemptOutcomeClass>,
    pub(crate) retry_ordinal: u32,
}

impl RetryCursor {
    pub(crate) const FRESH: Self = Self {
        provider_index: 0,
        kind: AttemptKind::Fresh,
        prior: None,
        retry_ordinal: 0,
    };
}

/// A deterministic no-delay backoff useful when a deployment's declared
/// retry policy requires no wait.
#[derive(Clone, Copy, Debug, Default)]
pub struct NoDelayBackoff;

impl RetryBackoff for NoDelayBackoff {
    fn wait(&mut self, _: u32, _: &str) -> Result<(), RetryBackoffRefusal> {
        Ok(())
    }
}

/// A host backoff refusal. It neither claims a provider cancellation nor
/// refunds a reservation already committed for the next attempt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RetryBackoffRefusal(pub String);

/// Fixed, host-derived bounds and estimates for every attempt in one run.
/// Token and cost values are conservative reservations, never derived from
/// an adapter response.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdapterAttemptPlan {
    pub required: RequiredCapabilities,
    pub context_tokens: u64,
    pub requested_output_tokens: u64,
    pub estimated_cost_micros: i64,
    pub max_polls: usize,
}

impl AdapterAttemptPlan {
    /// Builds the host quote portion of a streaming compiled invocation plan.
    /// Callers never reproduce the private provider prompt or guess its byte
    /// length: this constructor derives the same canonical envelope and
    /// capability requirement that [`RetryFailoverScheduler::run_compiled`]
    /// will bind before adapter construction.
    pub fn for_compiled(
        schema: &CompiledInteractionSchema,
        invocation_request: &ModelInvocationRequest,
        context_tokens: u64,
        requested_output_tokens: u64,
        estimated_cost_micros: i64,
        max_polls: usize,
    ) -> Result<Self, SchedulerRefusal> {
        if invocation_request.proposal_grammar_digest != schema.schema().digest() {
            return Err(SchedulerRefusal::GrammarBindingMismatch);
        }
        if invocation_request
            .task
            .len()
            .saturating_add(invocation_request.observation.len())
            > MAX_ADAPTER_REQUEST_BYTES
        {
            return Err(SchedulerRefusal::RequestBytesExceeded {
                requested: invocation_request
                    .task
                    .len()
                    .saturating_add(invocation_request.observation.len()),
                max: MAX_ADAPTER_REQUEST_BYTES,
            });
        }
        let provider_schema = schema.provider_json_schema();
        if provider_schema.len() > 262_144 {
            return Err(SchedulerRefusal::SchemaBytesExceeded {
                requested: provider_schema.len(),
                max: 262_144,
            });
        }
        let request = adapter_request_for(invocation_request, &provider_schema);
        Ok(Self {
            required: RequiredCapabilities {
                require_streaming: true,
                require_structured_output_mode: Some(StructuredOutputMode::RawText),
                max_request_bytes: request.request_bytes.len(),
                max_response_bytes: request.max_response_bytes,
            },
            context_tokens,
            requested_output_tokens,
            estimated_cost_micros,
            max_polls,
        })
    }
}

/// Why the scheduler stopped without starting another adapter.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SchedulerRefusal {
    NoPrimaryProvider,
    PrimaryProviderNotAuthorized {
        provider_id: String,
    },
    PollLimitOutOfRange {
        requested: usize,
        max: usize,
    },
    RequestBoundMismatch,
    GrammarBindingMismatch,
    RetainedAttemptLimit {
        max: usize,
    },
    ProviderPolicyTooLarge {
        max: usize,
    },
    ProviderIdTooLong {
        max: usize,
    },
    RequestBytesExceeded {
        requested: usize,
        max: usize,
    },
    SchemaBytesExceeded {
        requested: usize,
        max: usize,
    },
    Policy(AttemptRefusal),
    Backoff(RetryBackoffRefusal),
    Factory(AdapterFactoryRefusal),
    Negotiation(NegotiationRefusal),
    ProviderProfileMismatch {
        selected: String,
        declared: String,
    },
    ModelIdentityUnavailable {
        provider: String,
    },
    ModelIdentityMismatch {
        provider: String,
        model: String,
    },
    AdapterStart(AdapterRefusal),
    PollBudgetExceeded {
        max_polls: usize,
    },
    AdapterProtocol {
        code: &'static str,
    },
    /// The durable policy journal could not commit an intent or settlement.
    /// A previously committed intent remains an uncertain prefix on recovery.
    Journal(String),
    CancelledAfterDispatch,
    DeadlineExceededAfterDispatch,
}

/// The result of one adapter attempt. A returned classification is an audit
/// fact for the scheduler; only safe classes may lead to a later attempt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AdapterAttemptResult {
    Settled {
        response_bytes: Vec<u8>,
        usage: AdapterUsage,
    },
    Failed {
        classification: AttemptOutcomeClass,
        failure: Option<ModelFailure>,
        attempted_bytes: usize,
        refusal: Option<SchedulerRefusal>,
    },
}

/// The terminal outcome of a retry/failover run.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RetryFailoverOutcome {
    Settled {
        reservation: AttemptReservation,
        response_bytes: Vec<u8>,
        usage: AdapterUsage,
    },
    Failed {
        reservation: AttemptReservation,
        result: AdapterAttemptResult,
    },
    Refused {
        reservation: Option<AttemptReservation>,
        refusal: SchedulerRefusal,
    },
}

/// Complete in-process evidence from one scheduler call. Reservations are in
/// the exact dispatch-attempt order and never reused; this is not a durable
/// journal and must not be treated as crash-recovery authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RetryFailoverRun {
    pub attempts: Vec<AttemptReservation>,
    pub evidence: Vec<RetryAttemptEvidence>,
    pub outcome: RetryFailoverOutcome,
}

/// Terminal adapter evidence retained for every admitted reservation,
/// including a safe failure that selected a later retry/failover.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RetryAttemptEvidence {
    pub reservation: AttemptReservation,
    pub result: AdapterAttemptResult,
}

/// A policy-owned runtime driver for the SDK's real adapter interface.
pub struct RetryFailoverScheduler<'a> {
    ledger: ModelPolicyLedger<'a>,
    providers: ProviderPolicy,
    cancellation: &'a AgentCancellation,
    capability: AdapterInvocationCapability,
    factory: &'a mut dyn ProviderAdapterFactory,
}

impl<'a> RetryFailoverScheduler<'a> {
    /// Creates a scheduler bound to one immutable, ordered provider policy.
    /// The primary is checked here as well as fallback slots being checked by
    /// the ledger, so an unauthorized primary can never receive `start`.
    pub fn new(
        limits: EffectiveModelBudget,
        providers: ProviderPolicy,
        deadline_millis: Option<i64>,
        clock: &'a dyn InvocationClock,
        cancellation: &'a AgentCancellation,
        capability: AdapterInvocationCapability,
        factory: &'a mut dyn ProviderAdapterFactory,
    ) -> Result<Self, SchedulerRefusal> {
        let Some(primary) = providers.primary() else {
            return Err(SchedulerRefusal::NoPrimaryProvider);
        };
        if !primary.authorized {
            return Err(SchedulerRefusal::PrimaryProviderNotAuthorized {
                provider_id: primary.id.clone(),
            });
        }
        if providers.len() > MAX_PROVIDER_SLOTS {
            return Err(SchedulerRefusal::ProviderPolicyTooLarge {
                max: MAX_PROVIDER_SLOTS,
            });
        }
        if (0..providers.len()).any(|index| {
            providers
                .slot(index)
                .is_some_and(|slot| slot.id.len() > MAX_PROVIDER_ID_BYTES)
        }) {
            return Err(SchedulerRefusal::ProviderIdTooLong {
                max: MAX_PROVIDER_ID_BYTES,
            });
        }
        Ok(Self {
            ledger: ModelPolicyLedger::new(limits, providers.clone(), deadline_millis, clock),
            providers,
            cancellation,
            capability,
            factory,
        })
    }

    /// Rebuilds the scheduler ledger from a policy-journal prefix that has
    /// already been independently checked for exact ordinals, provider order
    /// and conservative terminality.  `ModelPolicyLedger::resume` itself is
    /// intentionally not a hostile-input decoder, so this constructor stays
    /// crate-private and is reachable only after that validation.
    pub(crate) fn resume(
        limits: EffectiveModelBudget,
        providers: ProviderPolicy,
        deadline_millis: Option<i64>,
        clock: &'a dyn InvocationClock,
        cancellation: &'a AgentCancellation,
        capability: AdapterInvocationCapability,
        factory: &'a mut dyn ProviderAdapterFactory,
        reservations: &[AttemptReservation],
    ) -> Result<Self, SchedulerRefusal> {
        let mut scheduler = Self::new(
            limits,
            providers,
            deadline_millis,
            clock,
            cancellation,
            capability,
            factory,
        )?;
        scheduler.ledger = ModelPolicyLedger::resume(
            limits,
            scheduler.providers.clone(),
            deadline_millis,
            clock,
            reservations,
        );
        Ok(scheduler)
    }

    #[must_use]
    pub fn ledger(&self) -> &ModelPolicyLedger<'a> {
        &self.ledger
    }

    /// Drives the selected provider directly through `start` and bounded
    /// `poll` calls. On a safe failure it tries the same provider as a retry;
    /// only a retry-ceiling refusal advances to the exact next provider.
    pub fn run_compiled(
        &mut self,
        schema: &CompiledInteractionSchema,
        invocation_request: &ModelInvocationRequest,
        plan: &AdapterAttemptPlan,
        classifier: &mut dyn FailureClassifier,
        backoff: &mut dyn RetryBackoff,
    ) -> RetryFailoverRun {
        self.run_compiled_from(
            schema,
            invocation_request,
            plan,
            classifier,
            backoff,
            RetryCursor::FRESH,
            None,
        )
    }

    /// Continues an independently validated durable prefix.  This is crate
    /// internal because only the V2 policy-journal decoder may derive a
    /// cursor; accepting caller-selected ordinal/provider state here would
    /// let a caller bypass the ordered failover policy.
    pub(crate) fn run_compiled_from(
        &mut self,
        schema: &CompiledInteractionSchema,
        invocation_request: &ModelInvocationRequest,
        plan: &AdapterAttemptPlan,
        classifier: &mut dyn FailureClassifier,
        backoff: &mut dyn RetryBackoff,
        cursor: RetryCursor,
        journal: Option<&mut dyn RetryAttemptJournal>,
    ) -> RetryFailoverRun {
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
        let mut run = self.run_projected(
            invocation_request,
            &adapter_request,
            plan,
            classifier,
            backoff,
            Some(schema),
            None,
            cursor,
            journal,
        );
        let invalid_settlement = match &run.outcome {
            RetryFailoverOutcome::Settled {
                reservation,
                response_bytes,
                ..
            } if schema.decode(response_bytes).is_err() => {
                Some((reservation.clone(), response_bytes.len()))
            }
            _ => None,
        };
        if let Some((reservation, response_bytes_len)) = invalid_settlement {
            let result = failed(
                AttemptOutcomeClass::CompletedWithResponse,
                Some(ModelFailure::MalformedResponse),
                response_bytes_len,
                Some(SchedulerRefusal::AdapterProtocol {
                    code: "ADAPTER-SCHEMA-DECODE",
                }),
            );
            if let Some(last) = run.evidence.last_mut() {
                last.result = result.clone();
            }
            run.outcome = RetryFailoverOutcome::Failed {
                reservation,
                result,
            };
        }
        run
    }

    fn run_projected(
        &mut self,
        invocation_request: &ModelInvocationRequest,
        adapter_request: &AdapterRequest,
        plan: &AdapterAttemptPlan,
        classifier: &mut dyn FailureClassifier,
        backoff: &mut dyn RetryBackoff,
        schema: Option<&CompiledInteractionSchema>,
        models: Option<&[DeploymentModelSelection]>,
        cursor: RetryCursor,
        mut journal: Option<&mut dyn RetryAttemptJournal>,
    ) -> RetryFailoverRun {
        if let Err(refusal) = Self::validate_plan(invocation_request, adapter_request, plan) {
            return self.refused(Vec::new(), Vec::new(), None, refusal);
        }
        let mut attempts = Vec::new();
        let mut evidence = Vec::new();
        let mut provider_index = cursor.provider_index;
        let mut kind = cursor.kind;
        let mut prior = cursor.prior;
        let mut retry_ordinal = cursor.retry_ordinal;

        loop {
            if attempts.len() >= MAX_RETAINED_ATTEMPTS {
                return self.refused(
                    attempts,
                    evidence,
                    None,
                    SchedulerRefusal::RetainedAttemptLimit {
                        max: MAX_RETAINED_ATTEMPTS,
                    },
                );
            }
            let Some(slot) = self.providers.slot(provider_index) else {
                return self.refused(
                    attempts,
                    evidence,
                    None,
                    SchedulerRefusal::Policy(AttemptRefusal::ProviderRefused(
                        super::ProviderRefusal::AlternativesExhausted {
                            next_index: provider_index,
                        },
                    )),
                );
            };
            let provider_id = slot.id.clone();
            let request = AttemptRequest {
                kind,
                provider_id: provider_id.clone(),
                context_tokens: plan.context_tokens,
                requested_output_tokens: plan.requested_output_tokens,
                estimated_cost_micros: plan.estimated_cost_micros,
                prior_classification: prior,
            };
            let reservation = match self.ledger.reserve_attempt(self.cancellation, &request) {
                Ok(reservation) => reservation,
                Err(AttemptRefusal::RetriesExhausted { .. }) if kind == AttemptKind::Retry => {
                    provider_index = provider_index.saturating_add(1);
                    kind = AttemptKind::Failover;
                    continue;
                }
                Err(refusal) => {
                    return self.refused(
                        attempts,
                        evidence,
                        None,
                        SchedulerRefusal::Policy(refusal),
                    )
                }
            };
            if kind != AttemptKind::Fresh {
                retry_ordinal = retry_ordinal.saturating_add(1);
                if let Err(refusal) = backoff.wait(retry_ordinal, &provider_id) {
                    attempts.push(reservation.clone());
                    return self.refused(
                        attempts,
                        evidence,
                        Some(reservation),
                        SchedulerRefusal::Backoff(refusal),
                    );
                }
            }
            // The admission is durable before adapter construction.  A
            // checkpoint refusal is before dispatch, so returning here is
            // safe; a crash after this succeeds leaves this exact intent
            // unresolved and recovery must refuse to redispatch it.
            if let Some(journal) = journal.as_deref_mut() {
                if let Err(detail) = journal.intent(&reservation) {
                    attempts.push(reservation.clone());
                    return self.refused(
                        attempts,
                        evidence,
                        Some(reservation),
                        SchedulerRefusal::Journal(detail),
                    );
                }
            }
            attempts.push(reservation.clone());
            let mut result = self.drive(
                &provider_id,
                models.and_then(|models| models.get(provider_index)),
                adapter_request,
                plan,
                classifier,
            );
            let schema_failure = match (schema, &result) {
                (Some(schema), AdapterAttemptResult::Settled { response_bytes, .. })
                    if schema.decode(response_bytes).is_err() =>
                {
                    Some(response_bytes.len())
                }
                _ => None,
            };
            if let Some(response_bytes_len) = schema_failure {
                result = failed(
                    AttemptOutcomeClass::CompletedWithResponse,
                    Some(ModelFailure::MalformedResponse),
                    response_bytes_len,
                    Some(SchedulerRefusal::AdapterProtocol {
                        code: "ADAPTER-SCHEMA-DECODE",
                    }),
                );
            }
            // This write is deliberately after `drive`: a failure here does
            // not manufacture an in-memory settlement.  The prior durable
            // intent is the conservative recovery fact.
            if let Some(journal) = journal.as_deref_mut() {
                if let Err(detail) = journal.settled(&reservation, &result) {
                    return self.refused(
                        attempts,
                        evidence,
                        Some(reservation),
                        SchedulerRefusal::Journal(detail),
                    );
                }
            }
            evidence.push(RetryAttemptEvidence {
                reservation: reservation.clone(),
                result: result.clone(),
            });
            match result {
                AdapterAttemptResult::Settled {
                    response_bytes,
                    usage,
                } => {
                    self.record_usage(&reservation, usage);
                    return RetryFailoverRun {
                        attempts,
                        evidence,
                        outcome: RetryFailoverOutcome::Settled {
                            reservation,
                            response_bytes,
                            usage,
                        },
                    };
                }
                AdapterAttemptResult::Failed {
                    classification,
                    failure,
                    attempted_bytes,
                    refusal,
                } => {
                    let result = AdapterAttemptResult::Failed {
                        classification,
                        failure,
                        attempted_bytes,
                        refusal,
                    };
                    if !retry_is_permitted(classification) {
                        return RetryFailoverRun {
                            attempts,
                            evidence,
                            outcome: RetryFailoverOutcome::Failed {
                                reservation,
                                result,
                            },
                        };
                    }
                    prior = Some(classification);
                    kind = AttemptKind::Retry;
                }
            }
        }
    }

    fn validate_plan(
        _: &ModelInvocationRequest,
        adapter_request: &AdapterRequest,
        plan: &AdapterAttemptPlan,
    ) -> Result<(), SchedulerRefusal> {
        if plan.max_polls == 0 || plan.max_polls > MAX_ATTEMPT_POLLS {
            return Err(SchedulerRefusal::PollLimitOutOfRange {
                requested: plan.max_polls,
                max: MAX_ATTEMPT_POLLS,
            });
        }
        if adapter_request.request_bytes.len() > MAX_ADAPTER_REQUEST_BYTES {
            return Err(SchedulerRefusal::RequestBytesExceeded {
                requested: adapter_request.request_bytes.len(),
                max: MAX_ADAPTER_REQUEST_BYTES,
            });
        }
        if plan.required.max_request_bytes != adapter_request.request_bytes.len()
            || plan.required.max_response_bytes != adapter_request.max_response_bytes
        {
            return Err(SchedulerRefusal::RequestBoundMismatch);
        }
        Ok(())
    }

    fn refused(
        &self,
        attempts: Vec<AttemptReservation>,
        evidence: Vec<RetryAttemptEvidence>,
        reservation: Option<AttemptReservation>,
        refusal: SchedulerRefusal,
    ) -> RetryFailoverRun {
        RetryFailoverRun {
            attempts,
            evidence,
            outcome: RetryFailoverOutcome::Refused {
                reservation,
                refusal,
            },
        }
    }

    fn record_usage(&mut self, reservation: &AttemptReservation, usage: AdapterUsage) {
        let (Some(actual_context_tokens), Some(actual_output_tokens), Some(actual_cost_micros)) =
            (usage.tokens_in, usage.tokens_out, usage.cost_micros)
        else {
            return;
        };
        if actual_cost_micros < 0 {
            return;
        }
        self.ledger.record_outcome(AttemptUsage {
            ordinal: reservation.ordinal,
            classification: AttemptOutcomeClass::CompletedWithResponse,
            actual_context_tokens,
            actual_output_tokens,
            actual_cost_micros,
        });
    }

    fn drive(
        &mut self,
        provider_id: &str,
        expected_model: Option<&DeploymentModelSelection>,
        adapter_request: &AdapterRequest,
        plan: &AdapterAttemptPlan,
        classifier: &mut dyn FailureClassifier,
    ) -> AdapterAttemptResult {
        if self.cancellation.is_cancelled() {
            return failed(
                AttemptOutcomeClass::NotDispatched,
                None,
                0,
                Some(SchedulerRefusal::Policy(AttemptRefusal::Cancelled)),
            );
        }
        if self.ledger.check_deadline().is_err() {
            return failed(
                AttemptOutcomeClass::NotDispatched,
                None,
                0,
                Some(SchedulerRefusal::Policy(AttemptRefusal::DeadlineExceeded)),
            );
        }
        let mut adapter = match self.factory.create(provider_id) {
            Ok(adapter) => adapter,
            Err(refusal) => {
                return failed(
                    AttemptOutcomeClass::NotDispatched,
                    None,
                    0,
                    Some(SchedulerRefusal::Factory(refusal)),
                )
            }
        };
        if adapter.capabilities().provider_profile != provider_id {
            return failed(
                AttemptOutcomeClass::NotDispatched,
                None,
                0,
                Some(SchedulerRefusal::ProviderProfileMismatch {
                    selected: provider_id.to_owned(),
                    declared: adapter.capabilities().provider_profile.clone(),
                }),
            );
        }
        if let Some(expected) = expected_model {
            if let Err(refusal) =
                durable::require_model_identity(adapter.as_ref(), provider_id, expected)
            {
                return failed(AttemptOutcomeClass::NotDispatched, None, 0, Some(refusal));
            }
        }
        if let Err(refusal) = negotiate(adapter.capabilities(), &plan.required) {
            return failed(
                AttemptOutcomeClass::NotDispatched,
                None,
                0,
                Some(SchedulerRefusal::Negotiation(refusal)),
            );
        }
        if self.cancellation.is_cancelled() {
            return failed(
                AttemptOutcomeClass::NotDispatched,
                None,
                0,
                Some(SchedulerRefusal::Policy(AttemptRefusal::Cancelled)),
            );
        }
        if self.ledger.check_deadline().is_err() {
            return failed(
                AttemptOutcomeClass::NotDispatched,
                None,
                0,
                Some(SchedulerRefusal::Policy(AttemptRefusal::DeadlineExceeded)),
            );
        }
        if let Err(refusal) = adapter.start(&self.capability, adapter_request) {
            return failed(
                AttemptOutcomeClass::RejectedBeforeProcessing,
                Some(ModelFailure::Refused),
                0,
                Some(SchedulerRefusal::AdapterStart(refusal)),
            );
        }

        let mut bytes = Vec::new();
        let mut completed = false;
        let mut last_usage: Option<(u64, u64, i64)> = None;
        for _ in 0..plan.max_polls {
            if self.cancellation.is_cancelled() {
                adapter.cancel("model policy cancellation");
                return failed(
                    AttemptOutcomeClass::Uncertain,
                    Some(ModelFailure::Cancelled),
                    bytes.len(),
                    Some(SchedulerRefusal::CancelledAfterDispatch),
                );
            }
            if self.ledger.check_deadline().is_err() {
                adapter.cancel("model policy deadline");
                return failed(
                    AttemptOutcomeClass::Uncertain,
                    Some(ModelFailure::Timeout),
                    bytes.len(),
                    Some(SchedulerRefusal::DeadlineExceededAfterDispatch),
                );
            }
            let poll = adapter.poll();
            let observed_after_poll = match &poll {
                AdapterPoll::Failed {
                    attempted_bytes, ..
                } => *attempted_bytes,
                AdapterPoll::Event(AdapterEvent::Delta(chunk)) => {
                    bytes.len().saturating_add(chunk.len())
                }
                AdapterPoll::Settled(settlement) => settlement.response_bytes.len(),
                _ => bytes.len(),
            };
            if self.cancellation.is_cancelled() {
                adapter.cancel("model policy cancellation after poll");
                return failed(
                    AttemptOutcomeClass::Uncertain,
                    Some(ModelFailure::Cancelled),
                    observed_after_poll,
                    Some(SchedulerRefusal::CancelledAfterDispatch),
                );
            }
            if self.ledger.check_deadline().is_err() {
                adapter.cancel("model policy deadline after poll");
                return failed(
                    AttemptOutcomeClass::Uncertain,
                    Some(ModelFailure::Timeout),
                    observed_after_poll,
                    Some(SchedulerRefusal::DeadlineExceededAfterDispatch),
                );
            }
            match poll {
                AdapterPoll::Pending => {}
                AdapterPoll::Event(AdapterEvent::Delta(chunk)) => {
                    if completed {
                        adapter.cancel("delta after completed");
                        return protocol_failure(bytes.len(), "ADAPTER-EVENT-AFTER-COMPLETION");
                    }
                    if bytes.len().saturating_add(chunk.len()) > adapter_request.max_response_bytes
                    {
                        adapter.cancel("response byte bound");
                        return protocol_failure(bytes.len(), "ADAPTER-OVERSIZED-RESPONSE");
                    }
                    bytes.extend_from_slice(&chunk);
                }
                AdapterPoll::Event(AdapterEvent::Completed) => {
                    if completed {
                        adapter.cancel("duplicate completion");
                        return protocol_failure(bytes.len(), "ADAPTER-DUPLICATE-COMPLETION");
                    }
                    completed = true;
                }
                AdapterPoll::Event(AdapterEvent::Usage {
                    tokens_in,
                    tokens_out,
                    cost_micros,
                }) => {
                    if completed {
                        adapter.cancel("usage after completed");
                        return protocol_failure(bytes.len(), "ADAPTER-EVENT-AFTER-COMPLETION");
                    }
                    if cost_micros < 0
                        || last_usage.is_some_and(|previous| {
                            tokens_in < previous.0
                                || tokens_out < previous.1
                                || cost_micros < previous.2
                        })
                    {
                        adapter.cancel("contradictory usage");
                        return protocol_failure(bytes.len(), "ADAPTER-CONTRADICTORY-USAGE");
                    }
                    last_usage = Some((tokens_in, tokens_out, cost_micros));
                }
                AdapterPoll::Settled(settlement) => {
                    if !completed || bytes != settlement.response_bytes {
                        adapter.cancel("incomplete or contradictory settlement");
                        return protocol_failure(bytes.len(), "ADAPTER-SETTLEMENT-MISMATCH");
                    }
                    if let (Some(tokens_in), Some(tokens_out), Some(cost_micros)) = (
                        settlement.usage.tokens_in,
                        settlement.usage.tokens_out,
                        settlement.usage.cost_micros,
                    ) {
                        if cost_micros < 0
                            || last_usage.is_some_and(|previous| {
                                tokens_in < previous.0
                                    || tokens_out < previous.1
                                    || cost_micros < previous.2
                            })
                        {
                            adapter.cancel("contradictory settlement usage");
                            return protocol_failure(bytes.len(), "ADAPTER-CONTRADICTORY-USAGE");
                        }
                    }
                    // The shared post-poll checkpoint above covers
                    // cancellation and deadline before this publication.
                    let response_bytes = bytes;
                    if response_bytes.len() > adapter_request.max_response_bytes {
                        adapter.cancel("settled response byte bound");
                        return protocol_failure(
                            response_bytes.len(),
                            "ADAPTER-OVERSIZED-RESPONSE",
                        );
                    }
                    return AdapterAttemptResult::Settled {
                        response_bytes,
                        usage: settlement.usage,
                    };
                }
                AdapterPoll::Failed {
                    failure,
                    attempted_bytes,
                } => {
                    // A classifier may only identify a provider-declared
                    // safe condition before any bytes were observed. A
                    // malformed/partial response or any other post-start
                    // failure remains uncertain even if a buggy host tries
                    // to label it retryable.
                    let class = if !completed
                        && attempted_bytes == 0
                        && matches!(
                            failure,
                            ModelFailure::CapacityExceeded | ModelFailure::ProviderError
                        ) {
                        classifier.classify(provider_id, failure)
                    } else {
                        AttemptOutcomeClass::Uncertain
                    };
                    let class = if retry_is_permitted(class)
                        && !adapter
                            .capabilities()
                            .retryable_failure_classes
                            .contains(&class)
                    {
                        AttemptOutcomeClass::Uncertain
                    } else {
                        class
                    };
                    return failed(class, Some(failure), attempted_bytes, None);
                }
            }
        }
        adapter.cancel("adapter poll budget exhausted");
        failed(
            AttemptOutcomeClass::Uncertain,
            Some(ModelFailure::Timeout),
            bytes.len(),
            Some(SchedulerRefusal::PollBudgetExceeded {
                max_polls: plan.max_polls,
            }),
        )
    }
}

fn failed(
    classification: AttemptOutcomeClass,
    failure: Option<ModelFailure>,
    attempted_bytes: usize,
    refusal: Option<SchedulerRefusal>,
) -> AdapterAttemptResult {
    AdapterAttemptResult::Failed {
        classification,
        failure,
        attempted_bytes,
        refusal,
    }
}

fn protocol_failure(attempted_bytes: usize, code: &'static str) -> AdapterAttemptResult {
    failed(
        AttemptOutcomeClass::Uncertain,
        Some(ModelFailure::MalformedResponse),
        attempted_bytes,
        Some(SchedulerRefusal::AdapterProtocol { code }),
    )
}

#[cfg(test)]
mod tests {
    use std::{
        cell::RefCell,
        collections::VecDeque,
        rc::Rc,
        sync::atomic::{AtomicU64, Ordering},
    };

    use super::*;
    use crate::agent_interaction_schema::compile_agent_interaction_schema;
    use crate::live_invocation::fixture::StepClock;
    use crate::model_budget_policy::{intersect, ModelBudgetLimits, ProviderSlot};
    use crate::provider_adapter_sdk::fixture_adapters::{
        base_capabilities, usage, ScriptedAdapter,
    };
    use crate::provider_adapter_sdk::AdapterSettlement;

    const SOURCE: &str = "module test.retry;\n\n@id(\"answer.type\")\nrecord Answer {\n    @id(\"answer.note\")\n    note: string,\n}\n\n@id(\"app.main\")\nfn main() -> i64 { 0 }\n";
    static NEXT_FILE: AtomicU64 = AtomicU64::new(0);

    fn schema() -> CompiledInteractionSchema {
        let path = std::env::temp_dir().join(format!(
            "semaprax-retry-{}-{}.spx",
            std::process::id(),
            NEXT_FILE.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::write(&path, SOURCE).unwrap();
        let result = compile_agent_interaction_schema(&path, "answer.type");
        std::fs::remove_file(path).unwrap();
        result.unwrap()
    }

    fn document(schema: &CompiledInteractionSchema) -> Vec<u8> {
        format!(
            "{{\"schema\":\"semaprax.agent-interaction-value.v1\",\"root_type_id\":\"answer.type\",\"schema_digest\":\"{}\",\"value\":{{\"fields\":{{\"answer.note\":\"ok\"}}}}}}\n",
            schema.schema().digest()
        )
        .into_bytes()
    }

    fn limits(calls: u32, retries: u32, providers: u32) -> EffectiveModelBudget {
        let mut limits = ModelBudgetLimits::unbounded();
        limits.max_calls = calls;
        limits.max_retries = retries;
        limits.max_providers = providers;
        limits.max_context_tokens = 16;
        limits.max_output_tokens = 8;
        limits.max_aggregate_tokens = 48;
        limits.max_cost_micros = 100;
        intersect(limits, limits, limits).unwrap()
    }

    fn plan() -> AdapterAttemptPlan {
        let request = request();
        AdapterAttemptPlan {
            required: RequiredCapabilities {
                require_streaming: false,
                require_structured_output_mode: None,
                max_request_bytes: request.request_bytes.len(),
                max_response_bytes: request.max_response_bytes,
            },
            context_tokens: 4,
            requested_output_tokens: 2,
            estimated_cost_micros: 3,
            max_polls: 4,
        }
    }

    fn request() -> AdapterRequest {
        AdapterRequest {
            request_bytes: b"request".to_vec(),
            max_response_bytes: 64,
        }
    }

    fn invocation() -> ModelInvocationRequest {
        ModelInvocationRequest {
            turn: 0,
            task: vec![],
            observation: vec![],
            proposal_grammar_digest: "grammar".into(),
            deployment_binding: "policy".into(),
            max_response_bytes: 64,
            effective_budget: 1,
        }
    }

    fn adapter(provider: &str, script: Vec<AdapterPoll>) -> Box<dyn ProviderAdapter> {
        let mut caps = base_capabilities(provider, true);
        caps.provider_profile = provider.to_owned();
        caps.retryable_failure_classes
            .push(AttemptOutcomeClass::ProviderReportedRetryable);
        Box::new(ScriptedAdapter::new(caps, script, true))
    }

    struct CapacityIsSafe;
    impl FailureClassifier for CapacityIsSafe {
        fn classify(&mut self, _: &str, failure: ModelFailure) -> AttemptOutcomeClass {
            match failure {
                ModelFailure::CapacityExceeded => AttemptOutcomeClass::ProviderReportedRetryable,
                _ => AttemptOutcomeClass::Uncertain,
            }
        }
    }

    struct RecordedBackoff(Rc<RefCell<Vec<String>>>);
    impl RetryBackoff for RecordedBackoff {
        fn wait(&mut self, ordinal: u32, provider: &str) -> Result<(), RetryBackoffRefusal> {
            self.0.borrow_mut().push(format!("{ordinal}:{provider}"));
            Ok(())
        }
    }

    #[test]
    fn a_safe_adapter_failure_retries_with_a_new_charged_ordinal() {
        let queued = Rc::new(RefCell::new(VecDeque::from(vec![
            adapter(
                "primary",
                vec![AdapterPoll::Failed {
                    failure: ModelFailure::CapacityExceeded,
                    attempted_bytes: 0,
                }],
            ),
            adapter(
                "primary",
                vec![
                    AdapterPoll::Event(AdapterEvent::Delta(b"ok".to_vec())),
                    AdapterPoll::Event(AdapterEvent::Completed),
                    AdapterPoll::Settled(AdapterSettlement {
                        response_bytes: b"ok".to_vec(),
                        usage: usage(4, 2, 3),
                    }),
                ],
            ),
        ])));
        let observed = queued.clone();
        let mut factory = move |provider: &str| {
            observed
                .borrow_mut()
                .pop_front()
                .ok_or_else(|| AdapterFactoryRefusal(provider.into()))
        };
        let clock = StepClock::new(0);
        let cancellation = AgentCancellation::new();
        let mut scheduler = RetryFailoverScheduler::new(
            limits(2, 1, 0),
            ProviderPolicy::new(vec![ProviderSlot::authorized("primary")]),
            None,
            &clock,
            &cancellation,
            AdapterInvocationCapability::grant("test"),
            &mut factory,
        )
        .unwrap();
        let backoff_events = Rc::new(RefCell::new(Vec::new()));
        let mut backoff = RecordedBackoff(backoff_events.clone());
        let mut classifier = CapacityIsSafe;
        let run = scheduler.run_projected(
            &invocation(),
            &request(),
            &plan(),
            &mut classifier,
            &mut backoff,
            None,
            None,
            RetryCursor::FRESH,
            None,
        );
        assert_eq!(run.attempts.len(), 2);
        assert_eq!(run.attempts[0].kind, AttemptKind::Fresh);
        assert_eq!(run.attempts[1].kind, AttemptKind::Retry);
        assert_eq!(run.attempts[0].ordinal, 0);
        assert_eq!(run.attempts[1].ordinal, 1);
        assert_eq!(scheduler.ledger().cost_committed_micros(), 6);
        assert_eq!(backoff_events.borrow().as_slice(), ["1:primary"]);
        assert!(matches!(run.outcome, RetryFailoverOutcome::Settled { .. }));
    }

    #[test]
    fn retry_exhaustion_advances_only_to_the_next_ordered_adapter() {
        let queued = Rc::new(RefCell::new(VecDeque::from(vec![
            adapter(
                "primary",
                vec![AdapterPoll::Failed {
                    failure: ModelFailure::CapacityExceeded,
                    attempted_bytes: 0,
                }],
            ),
            adapter(
                "fallback",
                vec![
                    AdapterPoll::Event(AdapterEvent::Delta(b"fallback".to_vec())),
                    AdapterPoll::Event(AdapterEvent::Completed),
                    AdapterPoll::Settled(AdapterSettlement {
                        response_bytes: b"fallback".to_vec(),
                        usage: usage(4, 2, 3),
                    }),
                ],
            ),
        ])));
        let observed = queued.clone();
        let mut factory = move |provider: &str| {
            observed
                .borrow_mut()
                .pop_front()
                .ok_or_else(|| AdapterFactoryRefusal(provider.into()))
        };
        let clock = StepClock::new(0);
        let cancellation = AgentCancellation::new();
        let mut scheduler = RetryFailoverScheduler::new(
            limits(2, 0, 1),
            ProviderPolicy::new(vec![
                ProviderSlot::authorized("primary"),
                ProviderSlot::authorized("fallback"),
            ]),
            None,
            &clock,
            &cancellation,
            AdapterInvocationCapability::grant("test"),
            &mut factory,
        )
        .unwrap();
        let mut classifier = CapacityIsSafe;
        let mut backoff = NoDelayBackoff;
        let run = scheduler.run_projected(
            &invocation(),
            &request(),
            &plan(),
            &mut classifier,
            &mut backoff,
            None,
            None,
            RetryCursor::FRESH,
            None,
        );
        assert_eq!(
            run.attempts
                .iter()
                .map(|item| item.kind)
                .collect::<Vec<_>>(),
            vec![AttemptKind::Fresh, AttemptKind::Failover]
        );
        assert_eq!(run.attempts[1].provider_id, "fallback");
        assert!(matches!(run.outcome, RetryFailoverOutcome::Settled { .. }));
    }

    #[test]
    fn an_uncertain_post_start_failure_never_constructs_a_fallback_adapter() {
        let calls = Rc::new(RefCell::new(Vec::new()));
        let seen = calls.clone();
        let mut factory = move |provider: &str| {
            seen.borrow_mut().push(provider.to_owned());
            Ok(adapter(
                provider,
                vec![AdapterPoll::Failed {
                    failure: ModelFailure::Timeout,
                    attempted_bytes: 2,
                }],
            ))
        };
        let clock = StepClock::new(0);
        let cancellation = AgentCancellation::new();
        let mut scheduler = RetryFailoverScheduler::new(
            limits(3, 2, 1),
            ProviderPolicy::new(vec![
                ProviderSlot::authorized("primary"),
                ProviderSlot::authorized("fallback"),
            ]),
            None,
            &clock,
            &cancellation,
            AdapterInvocationCapability::grant("test"),
            &mut factory,
        )
        .unwrap();
        let mut classifier = ConservativeFailureClassifier;
        let mut backoff = NoDelayBackoff;
        let run = scheduler.run_projected(
            &invocation(),
            &request(),
            &plan(),
            &mut classifier,
            &mut backoff,
            None,
            None,
            RetryCursor::FRESH,
            None,
        );
        assert_eq!(calls.borrow().as_slice(), ["primary"]);
        assert_eq!(run.attempts.len(), 1);
        assert!(matches!(
            run.outcome,
            RetryFailoverOutcome::Failed {
                result: AdapterAttemptResult::Failed {
                    classification: AttemptOutcomeClass::Uncertain,
                    ..
                },
                ..
            }
        ));
    }

    #[test]
    fn public_compiled_route_accepts_only_a_decoded_streamed_document() {
        let schema = schema();
        let mut request = invocation();
        request.proposal_grammar_digest = schema.schema().digest().to_owned();
        request.max_response_bytes = 4_096;
        let response = document(&schema);
        let queued = Rc::new(RefCell::new(VecDeque::from(vec![adapter(
            "primary",
            vec![
                AdapterPoll::Event(AdapterEvent::Delta(response.clone())),
                AdapterPoll::Event(AdapterEvent::Completed),
                AdapterPoll::Settled(AdapterSettlement {
                    response_bytes: response,
                    usage: usage(4, 2, 3),
                }),
            ],
        )])));
        let observed = queued.clone();
        let mut factory = move |provider: &str| {
            observed
                .borrow_mut()
                .pop_front()
                .ok_or_else(|| AdapterFactoryRefusal(provider.into()))
        };
        let clock = StepClock::new(0);
        let cancellation = AgentCancellation::new();
        let mut scheduler = RetryFailoverScheduler::new(
            limits(1, 0, 0),
            ProviderPolicy::new(vec![ProviderSlot::authorized("primary")]),
            None,
            &clock,
            &cancellation,
            AdapterInvocationCapability::grant("test"),
            &mut factory,
        )
        .unwrap();
        let plan = AdapterAttemptPlan::for_compiled(&schema, &request, 4, 2, 3, 4).unwrap();
        let mut classifier = ConservativeFailureClassifier;
        let mut backoff = NoDelayBackoff;
        let run = scheduler.run_compiled(&schema, &request, &plan, &mut classifier, &mut backoff);
        assert!(
            matches!(run.outcome, RetryFailoverOutcome::Settled { .. }),
            "public compiled run must settle: {run:?}"
        );
    }

    #[test]
    fn public_compiled_route_refuses_stale_grammar_before_factory() {
        let schema = schema();
        let mut request = invocation();
        request.proposal_grammar_digest = schema.schema().digest().to_owned();
        request.max_response_bytes = 4_096;
        let plan = AdapterAttemptPlan::for_compiled(&schema, &request, 4, 2, 3, 4).unwrap();
        request.proposal_grammar_digest = "stale".into();
        let calls = Rc::new(RefCell::new(0usize));
        let seen = calls.clone();
        let mut factory = move |_: &str| {
            *seen.borrow_mut() += 1;
            Err(AdapterFactoryRefusal("must not create".into()))
        };
        let clock = StepClock::new(0);
        let cancellation = AgentCancellation::new();
        let mut scheduler = RetryFailoverScheduler::new(
            limits(1, 0, 0),
            ProviderPolicy::new(vec![ProviderSlot::authorized("primary")]),
            None,
            &clock,
            &cancellation,
            AdapterInvocationCapability::grant("test"),
            &mut factory,
        )
        .unwrap();
        let mut classifier = ConservativeFailureClassifier;
        let mut backoff = NoDelayBackoff;
        let run = scheduler.run_compiled(&schema, &request, &plan, &mut classifier, &mut backoff);
        assert_eq!(*calls.borrow(), 0);
        assert!(matches!(
            run.outcome,
            RetryFailoverOutcome::Refused {
                refusal: SchedulerRefusal::GrammarBindingMismatch,
                ..
            }
        ));
    }

    #[test]
    fn malformed_completed_response_is_not_reported_as_public_success() {
        let schema = schema();
        let mut request = invocation();
        request.proposal_grammar_digest = schema.schema().digest().to_owned();
        let malformed = b"{}".to_vec();
        let queued = Rc::new(RefCell::new(VecDeque::from(vec![adapter(
            "primary",
            vec![
                AdapterPoll::Event(AdapterEvent::Delta(malformed.clone())),
                AdapterPoll::Event(AdapterEvent::Completed),
                AdapterPoll::Settled(AdapterSettlement {
                    response_bytes: malformed,
                    usage: usage(4, 2, 3),
                }),
            ],
        )])));
        let observed = queued.clone();
        let mut factory = move |provider: &str| {
            observed
                .borrow_mut()
                .pop_front()
                .ok_or_else(|| AdapterFactoryRefusal(provider.into()))
        };
        let clock = StepClock::new(0);
        let cancellation = AgentCancellation::new();
        let mut scheduler = RetryFailoverScheduler::new(
            limits(1, 0, 0),
            ProviderPolicy::new(vec![ProviderSlot::authorized("primary")]),
            None,
            &clock,
            &cancellation,
            AdapterInvocationCapability::grant("test"),
            &mut factory,
        )
        .unwrap();
        let plan = AdapterAttemptPlan::for_compiled(&schema, &request, 4, 2, 3, 4).unwrap();
        let mut classifier = ConservativeFailureClassifier;
        let mut backoff = NoDelayBackoff;
        let run = scheduler.run_compiled(&schema, &request, &plan, &mut classifier, &mut backoff);
        assert!(matches!(
            run.outcome,
            RetryFailoverOutcome::Failed {
                result: AdapterAttemptResult::Failed {
                    classification: AttemptOutcomeClass::CompletedWithResponse,
                    ..
                },
                ..
            }
        ));
    }
    mod cancellation_tests;
}
