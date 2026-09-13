//! Typed Runtime v2 facade for a checked V6 Source Live migration.
//!
//! The public source migration request still carries the exact retained source
//! checkpoint binding.  This facade verifies that its endpoints are the
//! current typed runtimes, binds their typed effect profiles, and supplies the
//! typed dispatcher for the destination continuation.

use super::*;
use crate::agent_lifecycle::iterative::effects::TypedEffectHandler;
use crate::agent_lifecycle::iterative::source_live::{
    prepare_source_live_policy_migration_profiled,
    prepare_source_live_policy_migration_with_io_limits_profiled, InvocationRootProfile,
    PreparedSourceLiveMigration, SourceIoLimits, SourceLiveFailure, SourceLiveMigrationRequest,
    SourceLivePolicy,
};
use crate::agent_lifecycle::CheckpointStore;
use crate::agent_runtime_v2::{SourceModelBinding, SourceModelPolicyBinding};
use crate::diagnostic::Diagnostic;
use crate::live_invocation::source_journal::SourcePolicyBindingV6;
use crate::live_invocation::SourceInvocationClock;
use crate::provider_adapter_sdk::StreamingSourceProposalAdapter;

/// A checked typed wrapper around one prepared Source Live V6 migration.
/// It retains no provider capability: callers still supply the explicit,
/// capability-bound source adapter when they run it.
pub struct PreparedAgentRuntimeV2SourceMigration<'a> {
    destination: &'a AgentRuntimeV2,
    prepared: PreparedSourceLiveMigration<'a>,
    binding_digest: String,
    policy_digest: String,
    typed_profile: String,
    deadline_millis: i64,
}

impl AgentRuntimeV2 {
    /// Prepares a V6 bound-model source migration from `previous` into `self`.
    ///
    /// Both endpoint policies must come from [`Self::source_live_model_policy`]
    /// and `request.previous_binding` must be the exact binding recovered with
    /// the predecessor checkpoint.  The source journal rechecks that binding
    /// and carries its nonrefundable policy reservations before any destination
    /// source adapter can start.
    #[allow(clippy::too_many_arguments)]
    pub fn prepare_live_bound_model_durable_policy_migration<'a>(
        &'a self,
        previous: &'a AgentRuntimeV2,
        request: SourceLiveMigrationRequest<'a>,
        previous_model_binding: &SourceModelBinding,
        previous_model_policy: &SourceModelPolicyBinding,
        destination_model_binding: &SourceModelBinding,
        destination_model_policy: &SourceModelPolicyBinding,
    ) -> std::result::Result<PreparedAgentRuntimeV2SourceMigration<'a>, Vec<Diagnostic>> {
        self.prepare_live_bound_model_durable_policy_migration_inner(
            previous,
            request,
            previous_model_binding,
            previous_model_policy,
            destination_model_binding,
            destination_model_policy,
            None,
        )
    }

    /// Adds the existing V5 cumulative I/O limits to the V6 typed migration
    /// identity. The destination limits may only narrow the predecessor's
    /// acknowledged carrier.
    #[allow(clippy::too_many_arguments)]
    pub fn prepare_live_bound_model_durable_policy_migration_with_io_limits<'a>(
        &'a self,
        previous: &'a AgentRuntimeV2,
        request: SourceLiveMigrationRequest<'a>,
        previous_model_binding: &SourceModelBinding,
        previous_model_policy: &SourceModelPolicyBinding,
        destination_model_binding: &SourceModelBinding,
        destination_model_policy: &SourceModelPolicyBinding,
        previous_io_limits: &'a SourceIoLimits,
        destination_io_limits: &'a SourceIoLimits,
    ) -> std::result::Result<PreparedAgentRuntimeV2SourceMigration<'a>, Vec<Diagnostic>> {
        self.prepare_live_bound_model_durable_policy_migration_inner(
            previous,
            request,
            previous_model_binding,
            previous_model_policy,
            destination_model_binding,
            destination_model_policy,
            Some((previous_io_limits, destination_io_limits)),
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn prepare_live_bound_model_durable_policy_migration_inner<'a>(
        &'a self,
        previous: &'a AgentRuntimeV2,
        request: SourceLiveMigrationRequest<'a>,
        previous_model_binding: &SourceModelBinding,
        previous_model_policy: &SourceModelPolicyBinding,
        destination_model_binding: &SourceModelBinding,
        destination_model_policy: &SourceModelPolicyBinding,
        io_limits: Option<(&'a SourceIoLimits, &'a SourceIoLimits)>,
    ) -> std::result::Result<PreparedAgentRuntimeV2SourceMigration<'a>, Vec<Diagnostic>> {
        if !previous.proposals.is_empty()
            || !self.proposals.is_empty()
            || request.task != &previous.task
            || request.task != &self.task
            || !effects_narrow(self.effects, previous.effects)
        {
            return Err(refusal("migration.typed_profile"));
        }
        let previous_policy = previous.source_live_model_policy(
            previous_model_binding,
            previous_model_policy,
            request.previous.policy.clone(),
        )?;
        let destination_policy = self.source_live_model_policy(
            destination_model_binding,
            destination_model_policy,
            request.destination.policy.clone(),
        )?;
        let (previous_source, destination_source) =
            crate::execution_revision::typed::migration::validate_linked_source_migration(
                previous,
                self,
                request.migration_function,
            )?;
        if !endpoint_matches(
            previous,
            &request.previous,
            &previous_source.source_path,
            &previous_source.agent_id,
            &previous_policy,
        ) || !endpoint_matches(
            self,
            &request.destination,
            &destination_source.source_path,
            &destination_source.agent_id,
            &destination_policy,
        ) {
            return Err(refusal("migration.typed_endpoint"));
        }
        let previous_journal_policy =
            source_policy_binding_v6(previous_model_binding, previous_model_policy)?;
        let destination_journal_policy =
            source_policy_binding_v6(destination_model_binding, destination_model_policy)?;
        let previous_root = typed_source_program_root(
            &previous.program_root,
            previous.lifecycle.digest(),
            previous.effects,
        );
        let destination_root =
            typed_source_program_root(&self.program_root, self.lifecycle.digest(), self.effects);
        let profile = InvocationRootProfile::Typed {
            previous_program_root: previous_root,
            destination_program_root: destination_root.clone(),
        };
        let prepared = match io_limits {
            Some((previous_limits, destination_limits)) => {
                prepare_source_live_policy_migration_with_io_limits_profiled(
                    request,
                    &previous_journal_policy,
                    &destination_journal_policy,
                    previous_limits,
                    destination_limits,
                    profile,
                )
            }
            None => prepare_source_live_policy_migration_profiled(
                request,
                &previous_journal_policy,
                &destination_journal_policy,
                profile,
            ),
        }
        .map_err(|failure| failure.diagnostics)?;
        Ok(PreparedAgentRuntimeV2SourceMigration {
            destination: self,
            prepared,
            binding_digest: destination_model_binding.digest().to_owned(),
            policy_digest: destination_model_policy.digest().to_owned(),
            typed_profile: destination_root,
            deadline_millis: destination_policy.deadline_millis,
        })
    }
}

impl<'a> PreparedAgentRuntimeV2SourceMigration<'a> {
    pub fn binding(&self) -> &crate::live_invocation::source_journal::SourceInvocationBinding {
        self.prepared.binding()
    }

    pub fn handoff_digest(&self) -> &str {
        self.prepared.handoff_digest()
    }

    /// Supplies the latest trusted destination checkpoint before recovery.
    pub fn with_checkpoint(mut self, checkpoint: &'a str) -> Self {
        let prepared = self.prepared;
        self.prepared = prepared.with_checkpoint(checkpoint);
        self
    }

    /// Runs the prepared source migration through the destination's typed
    /// dispatcher. Adapter/model-policy substitution is refused before the
    /// journal can replay or dispatch a provider request.
    pub fn run(
        self,
        source: &mut StreamingSourceProposalAdapter<'_>,
        handler: &mut dyn TypedEffectHandler,
        clock: &dyn SourceInvocationClock,
        cancellation: &AgentCancellation,
        store: &mut dyn CheckpointStore,
    ) -> std::result::Result<AgentRuntimeV2DurableModelEvidence, AgentRuntimeV2DurableModelFailure>
    {
        let Self {
            destination,
            prepared,
            binding_digest,
            policy_digest,
            typed_profile,
            deadline_millis,
        } = self;
        let valid = source.model_binding().is_some_and(|binding| {
            binding.digest() == binding_digest
                && binding.runtime_matches(
                    destination.deployment.digest(),
                    destination.instance.digest(),
                    destination.lifecycle.proposal_schema().source_revision(),
                    destination.lifecycle.proposal_schema().schema().digest(),
                )
        }) && source.model_policy_binding().is_some_and(|policy| {
            policy.digest() == policy_digest
                && source
                    .model_binding()
                    .is_some_and(|binding| policy.matches(binding))
        }) && source.model_policy_deadline_matches(deadline_millis)
            && source.model_evidence().attempts().is_empty();
        if !valid {
            return Err(migration_preflight(
                destination,
                source,
                &binding_digest,
                &policy_digest,
                &typed_profile,
                "migration_source_binding",
            ));
        }
        source.configure_durable_boundary(cancellation, deadline_millis);
        let source_binding = prepared.binding().clone();
        match destination.lifecycle.run_prepared_source_migration(
            prepared,
            source,
            handler,
            destination.effects,
            store,
            clock,
            cancellation,
        ) {
            Ok(run) => {
                let model_evidence = source.model_evidence().clone();
                let evidence = durable_model_policy_evidence_root(
                    destination,
                    &run,
                    &model_evidence,
                    &binding_digest,
                    &policy_digest,
                    &typed_profile,
                    "migration_completed",
                );
                Ok(AgentRuntimeV2DurableModelEvidence {
                    run,
                    model_evidence,
                    evidence,
                    revision: destination.revision.clone(),
                    source_binding: Some(source_binding),
                    source_policy: None,
                    source_model_binding_digest: Some(binding_digest),
                    source_model_policy: source.model_policy_binding().cloned(),
                })
            }
            Err(failure) => {
                let model_evidence = source.model_evidence().clone();
                let evidence = durable_model_policy_failure_root(
                    destination,
                    &failure,
                    &model_evidence,
                    &binding_digest,
                    &policy_digest,
                    &typed_profile,
                    "migration_source_live_failed",
                );
                Err(AgentRuntimeV2DurableModelFailure {
                    failure,
                    model_evidence,
                    evidence,
                    revision: destination.revision.clone(),
                })
            }
        }
    }
}

fn source_policy_binding_v6(
    binding: &SourceModelBinding,
    policy: &SourceModelPolicyBinding,
) -> std::result::Result<SourcePolicyBindingV6, Vec<Diagnostic>> {
    super::source_policy_binding_v6(binding, policy).map_err(|_| refusal("migration.policy"))
}

fn endpoint_matches(
    runtime: &AgentRuntimeV2,
    endpoint: &crate::agent_lifecycle::iterative::source_live::SourceLiveMigrationEndpoint<'_>,
    source_path: &str,
    agent_id: &str,
    expected_policy: &SourceLivePolicy,
) -> bool {
    endpoint.project.project_revision() == runtime.project.project_revision()
        && endpoint.source_path == source_path
        && endpoint.agent_id == agent_id
        && endpoint.lifecycle.digest() == runtime.lifecycle.digest()
        && endpoint.lifecycle.source_revision()
            == runtime.lifecycle.source_lifecycle().source_revision()
        && endpoint.lifecycle.proposal_schema().schema().digest()
            == runtime.lifecycle.proposal_schema().schema().digest()
        && endpoint.budget == runtime.budget
        && same_policy(endpoint.policy, expected_policy)
}

fn same_policy(left: &SourceLivePolicy, right: &SourceLivePolicy) -> bool {
    left.deployment_binding == right.deployment_binding
        && left.response_limit == right.response_limit
        && left.ceiling == right.ceiling
        && left.reservation_units == right.reservation_units
        && left.unit == right.unit
        && left.clock_domain == right.clock_domain
        && left.initial_millis == right.initial_millis
        && left.deadline_millis == right.deadline_millis
        && left.max_total_steps == right.max_total_steps
        && left.program_root == right.program_root
}

fn effects_narrow(
    destination: crate::agent_lifecycle::iterative::effects::EffectBudget,
    previous: crate::agent_lifecycle::iterative::effects::EffectBudget,
) -> bool {
    destination.max_calls <= previous.max_calls
        && destination.max_argument_bytes <= previous.max_argument_bytes
        && destination.max_result_bytes <= previous.max_result_bytes
        && destination.max_total_bytes <= previous.max_total_bytes
}

fn refusal(field: &str) -> Vec<Diagnostic> {
    vec![Diagnostic::io(
        "source.model_durable_migration",
        format!("typed durable source migration refused: {field}"),
    )]
}

fn migration_preflight(
    runtime: &AgentRuntimeV2,
    source: &StreamingSourceProposalAdapter<'_>,
    binding: &str,
    policy: &str,
    typed_profile: &str,
    status: &str,
) -> AgentRuntimeV2DurableModelFailure {
    let model_evidence = source.model_evidence().clone();
    let failure = SourceLiveFailure {
        diagnostics: refusal(status),
        selected: None,
        checked_run: None,
        checkpoint: None,
        stage_rows: Vec::new(),
        model_dispatches: 0,
        effect_dispatches: 0,
        journal_error: None,
    };
    let evidence = durable_model_policy_failure_root(
        runtime,
        &failure,
        &model_evidence,
        binding,
        policy,
        typed_profile,
        status,
    );
    AgentRuntimeV2DurableModelFailure {
        failure,
        model_evidence,
        evidence,
        revision: runtime.revision.clone(),
    }
}
