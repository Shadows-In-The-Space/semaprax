//! Store-backed direct Runtime v2 execution and evidence association.
use super::*;
use crate::agent_lifecycle::iterative::effects::{
    DurableTypedFailure, DurableTypedRun, TypedEffectHandler,
};
use crate::agent_lifecycle::iterative::source_live::{
    SourceLiveFailure, SourceLiveOutcome, SourceLivePolicy, SourceLiveRequest,
};
use crate::agent_lifecycle::CheckpointStore;
use crate::agent_runtime_v2::SourceModelEvidence;
use crate::diagnostic::Diagnostic;
use crate::live_invocation::SourceInvocationClock;
use crate::provider_adapter_sdk::StreamingSourceProposalAdapter;

impl AgentRuntimeV2 {
    /// Execute using a caller-owned single-writer checkpoint store.
    ///
    /// `retained_checkpoint` must be an acknowledged snapshot from that trusted
    /// store. Its hashes detect drift; they do not authenticate host observations.
    /// The checked producer replays pure stages under fresh authorizations before
    /// using retained observations. An uncertain effect intent cannot redispatch.
    pub fn run_durable(
        self,
        handler: &mut dyn TypedEffectHandler,
        cancellation: &AgentCancellation,
        retained_checkpoint: Option<&str>,
        store: &mut dyn CheckpointStore,
        max_reserved_fuel: u64,
    ) -> std::result::Result<AgentRuntimeV2DurableEvidence, DurableTypedFailure> {
        let run = self.lifecycle.run_durable(
            &self.task,
            &self.proposals,
            handler,
            self.budget,
            self.effects,
            cancellation,
            self.revision.digest(),
            &self.program_root,
            retained_checkpoint,
            store,
            max_reserved_fuel,
        )?;
        let evidence = root(
            "semaprax.evidence-root.v4",
            json!({
                "execution_revision": self.revision.digest(),
                "instance_root": self.instance.digest(),
                "typed_effect_evidence": run.run().evidence_digest(),
                "checkpoint_digest": run.checkpoint_digest(),
                "max_reserved_fuel": max_reserved_fuel,
            }),
        );
        Ok(AgentRuntimeV2DurableEvidence {
            run,
            evidence,
            revision: self.revision,
            migration_handoff: None,
            migrated_checkpoint: None,
        })
    }

    /// Runs the explicitly checkpoint-capable, bound source adapter through
    /// the Source Live Journal.  A priced in-memory model ledger cannot be
    /// reconstructed from this journal profile, so that opt-in route refuses
    /// here before it can issue a provider call.
    #[allow(clippy::too_many_arguments)]
    pub fn run_live_bound_model_durable(
        self,
        source: &mut StreamingSourceProposalAdapter<'_>,
        handler: &mut dyn TypedEffectHandler,
        mut policy: SourceLivePolicy,
        clock: &dyn SourceInvocationClock,
        cancellation: &AgentCancellation,
        retained_checkpoint: Option<&str>,
        store: &mut dyn CheckpointStore,
    ) -> std::result::Result<AgentRuntimeV2DurableModelEvidence, AgentRuntimeV2DurableModelFailure>
    {
        let binding = match source.model_binding() {
            Some(binding)
                if binding.runtime_matches(
                    self.deployment.digest(),
                    self.instance.digest(),
                    self.lifecycle.proposal_schema().source_revision(),
                    self.lifecycle.proposal_schema().schema().digest(),
                ) =>
            {
                binding
            }
            _ => {
                return Err(AgentRuntimeV2DurableModelFailure::preflight(
                    &self, source, "binding",
                ))
            }
        };
        if !self.proposals.is_empty()
            || !source.model_evidence().attempts().is_empty()
            || source.model_policy_binding().is_some()
            || policy.deployment_binding != binding.digest()
            || policy.response_limit != binding.max_response_bytes()
            || policy.reservation_units <= 0
        {
            return Err(AgentRuntimeV2DurableModelFailure::preflight(
                &self,
                source,
                "source_preflight",
            ));
        }
        let checkpoint_root =
            typed_source_program_root(&self.program_root, self.lifecycle.digest(), self.effects);
        let binding_digest = binding.digest().to_owned();
        source.configure_durable_boundary(cancellation, policy.deadline_millis);
        policy.program_root = Some(checkpoint_root.clone());
        let request = SourceLiveRequest {
            task: &self.task,
            budget: self.budget,
            policy: &policy,
            clock,
            cancellation,
            checkpoint: retained_checkpoint,
        };
        match self
            .lifecycle
            .run_live_durable_source(request, source, handler, self.effects, store)
        {
            Ok(run) => {
                let model_evidence = source.model_evidence().clone();
                let evidence = durable_model_evidence_root(
                    &self,
                    &run,
                    &model_evidence,
                    &binding_digest,
                    &checkpoint_root,
                    "completed",
                );
                Ok(AgentRuntimeV2DurableModelEvidence {
                    run,
                    model_evidence,
                    evidence,
                    revision: self.revision,
                })
            }
            Err(failure) => {
                let model_evidence = source.model_evidence().clone();
                let evidence = durable_model_failure_root(
                    &self,
                    &failure,
                    &model_evidence,
                    &binding_digest,
                    &checkpoint_root,
                    "source_live_failed",
                );
                Err(AgentRuntimeV2DurableModelFailure {
                    failure,
                    model_evidence,
                    evidence,
                    revision: self.revision,
                })
            }
        }
    }
}

fn typed_source_program_root(
    program_root: &str,
    registry: &str,
    effects: crate::agent_lifecycle::iterative::effects::EffectBudget,
) -> String {
    crate::live_invocation::identity::digest(
        b"semaprax.source-live.typed-effect-profile.v1\0",
        format!(
            "{}\0{}\0{}\0{}\0{}\0{}",
            program_root,
            registry,
            effects.max_calls,
            effects.max_argument_bytes,
            effects.max_result_bytes,
            effects.max_total_bytes,
        )
        .as_bytes(),
    )
}

/// Durable evidence binds the acknowledged journal product to both the exact
/// source-model selection and the typed registry/effect-cap profile.
pub struct AgentRuntimeV2DurableModelEvidence {
    run: SourceLiveOutcome,
    model_evidence: SourceModelEvidence,
    evidence: ExecutionRoot,
    revision: ExecutionRoot,
}

impl AgentRuntimeV2DurableModelEvidence {
    pub fn run(&self) -> &SourceLiveOutcome {
        &self.run
    }
    pub fn model_evidence(&self) -> &SourceModelEvidence {
        &self.model_evidence
    }
    pub fn evidence_root(&self) -> &ExecutionRoot {
        &self.evidence
    }
    pub fn execution_revision(&self) -> &ExecutionRoot {
        &self.revision
    }
}

/// A durable source failure retains its last acknowledged journal prefix and
/// redacted model evidence; it exposes neither provider request nor response.
pub struct AgentRuntimeV2DurableModelFailure {
    failure: SourceLiveFailure,
    model_evidence: SourceModelEvidence,
    evidence: ExecutionRoot,
    revision: ExecutionRoot,
}

impl AgentRuntimeV2DurableModelFailure {
    fn preflight(
        runtime: &AgentRuntimeV2,
        source: &StreamingSourceProposalAdapter<'_>,
        status: &str,
    ) -> Self {
        let model_evidence = SourceModelEvidence::default();
        let failure = SourceLiveFailure {
            diagnostics: vec![Diagnostic::io(
                "source.model_durable_preflight",
                "durable bound model source refused",
            )],
            selected: None,
            checked_run: None,
            checkpoint: None,
            stage_rows: Vec::new(),
            model_dispatches: 0,
            effect_dispatches: 0,
            journal_error: None,
        };
        let evidence = durable_model_failure_root(
            runtime,
            &failure,
            &model_evidence,
            source
                .model_binding()
                .map_or("", |binding| binding.digest()),
            "",
            status,
        );
        Self {
            failure,
            model_evidence,
            evidence,
            revision: runtime.revision.clone(),
        }
    }
    pub fn failure(&self) -> &SourceLiveFailure {
        &self.failure
    }
    pub fn model_evidence(&self) -> &SourceModelEvidence {
        &self.model_evidence
    }
    pub fn evidence_root(&self) -> &ExecutionRoot {
        &self.evidence
    }
    pub fn execution_revision(&self) -> &ExecutionRoot {
        &self.revision
    }
}

fn durable_model_evidence_root(
    runtime: &AgentRuntimeV2,
    run: &SourceLiveOutcome,
    model_evidence: &SourceModelEvidence,
    binding: &str,
    typed_profile: &str,
    status: &str,
) -> ExecutionRoot {
    root(
        "semaprax.evidence-root.v4",
        json!({
            "execution_revision": runtime.revision.digest(),
            "instance_root": runtime.instance.digest(),
            "source_model_binding": binding,
            "typed_effect_profile": typed_profile,
            "source_checkpoint": run.checkpoint.chain(),
            "model_evidence": model_evidence.digest(),
            "model_dispatches": run.model_dispatches,
            "effect_dispatches": run.effect_dispatches,
            "status": status,
        }),
    )
}

fn durable_model_failure_root(
    runtime: &AgentRuntimeV2,
    failure: &SourceLiveFailure,
    model_evidence: &SourceModelEvidence,
    binding: &str,
    typed_profile: &str,
    status: &str,
) -> ExecutionRoot {
    root(
        "semaprax.evidence-root.v4",
        json!({
            "execution_revision": runtime.revision.digest(),
            "instance_root": runtime.instance.digest(),
            "source_model_binding": binding,
            "typed_effect_profile": typed_profile,
            "model_evidence": model_evidence.digest(),
            "model_dispatches": failure.model_dispatches,
            "effect_dispatches": failure.effect_dispatches,
            "selected": failure.selected.map(|status| status.as_str()),
            "status": status,
        }),
    )
}

/// Evidence from the invocation that performed or replayed the durable run.
pub struct AgentRuntimeV2DurableEvidence {
    run: DurableTypedRun,
    evidence: ExecutionRoot,
    revision: ExecutionRoot,
    migration_handoff: Option<String>,
    migrated_checkpoint: Option<String>,
}
impl AgentRuntimeV2DurableEvidence {
    pub(super) fn from_migration(
        run: DurableTypedRun,
        evidence: ExecutionRoot,
        revision: ExecutionRoot,
        handoff: String,
        checkpoint: String,
    ) -> Self {
        Self {
            run,
            evidence,
            revision,
            migration_handoff: Some(handoff),
            migrated_checkpoint: Some(checkpoint),
        }
    }
    /// Snapshot from the caller-owned store, including any durable migration handoff.
    pub fn checkpoint(&self) -> &str {
        self.migrated_checkpoint
            .as_deref()
            .unwrap_or_else(|| self.run.checkpoint())
    }
    pub fn migration_handoff_digest(&self) -> Option<&str> {
        self.migration_handoff.as_deref()
    }
    pub fn run(&self) -> &DurableTypedRun {
        &self.run
    }
    pub fn evidence_root(&self) -> &ExecutionRoot {
        &self.evidence
    }
    pub fn execution_revision(&self) -> &ExecutionRoot {
        &self.revision
    }
}
