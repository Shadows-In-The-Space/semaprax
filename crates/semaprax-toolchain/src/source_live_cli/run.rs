use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::opencode_host::source::OpenCodeDurableProposalSource;
use crate::opencode_host::{
    OpenCodeGrammar, OpenCodeHostConfig, OpenCodeModelHandler, OpenCodeRunner,
    ProcessOpenCodeRunner, OPENCODE_MODEL,
};
use semaprax::agent_lifecycle::iterative::source_live::{
    prepare_source_live_migration, SourceLiveFailure, SourceLiveMigrationEndpoint,
    SourceLiveMigrationRequest, SourceLiveOutcome, SourceLivePolicy, SourceLiveRequest,
};
use semaprax::agent_lifecycle::iterative::{
    compile_project_agent_lifecycle_v2, CompiledIterativeLifecycle, IterativeBudget,
};
use semaprax::agent_lifecycle::{AgentReadOperation, AuthorizedRequest, LifecycleTask};
use semaprax::agent_runtime::AgentCancellation;
use semaprax::digest_hex::LowerHex;
use semaprax::live_invocation::source_journal::{
    recover_source_checkpoint, RecoveredSourceCheckpoint, MAX_SOURCE_EFFECT_BYTES,
    MAX_SOURCE_REQUEST_BYTES,
};
use semaprax::live_invocation::{InvocationClock, ModelInvokeCapability, SourceInvocationClock};
use semaprax::project::{with_authenticated_project, ProjectRevision};
use sha2::{Digest, Sha256};

use super::checkpoint::{bounded_read, CheckpointDir};
use super::options::{Command, SessionConfig};
use super::CliError;

const CLOCK_DOMAIN: &str = "unix_epoch_millis.v1";
const UNIT: &str = "fixed_model_attempt_units.v1";
const MAX_ONE_PROVIDER_CALL_MS: i64 = 30_000;

struct UnixClock;
impl InvocationClock for UnixClock {
    fn now_millis(&self) -> i64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .ok()
            .and_then(|duration| i64::try_from(duration.as_millis()).ok())
            .unwrap_or(i64::MIN)
    }
}
impl SourceInvocationClock for UnixClock {
    fn clock_domain(&self) -> &str {
        CLOCK_DOMAIN
    }
}

struct ReadSnapshot(Vec<u8>);
impl AgentReadOperation for ReadSnapshot {
    fn read(&mut self, _: &AuthorizedRequest) -> Option<Vec<u8>> {
        Some(self.0.clone())
    }
}

struct Endpoint {
    project_root: PathBuf,
    project: Arc<ProjectRevision>,
    compiled: CompiledIterativeLifecycle,
    config: SessionConfig,
    task: LifecycleTask,
    read: Vec<u8>,
    budget: IterativeBudget,
    policy: SourceLivePolicy,
}

impl Endpoint {
    fn load(config: SessionConfig) -> Result<Self, CliError> {
        let manifest = config
            .manifest
            .canonicalize()
            .map_err(|_| CliError::refused("Project manifest is unavailable"))?;
        let project_root = manifest
            .parent()
            .ok_or(CliError::refused("Project manifest has no root"))?
            .to_owned();
        let project =
            with_authenticated_project(&manifest, |snapshot| Ok(snapshot.retain_revision()))
                .map_err(|_| CliError::refused("Project authentication refused"))?;
        let compiled = compile_project_agent_lifecycle_v2(
            &project,
            &config.source_path,
            &config.agent_id,
            &config.step_id,
        )
        .map_err(|_| CliError::refused("checked Project Agent compilation refused"))?;
        let program_root = project
            .program_root()
            .map_err(|_| CliError::refused("Project ProgramRoot is unavailable"))?
            .program_root_digest()
            .to_owned();
        let objective = bounded_read(&config.task_path, MAX_SOURCE_REQUEST_BYTES)?;
        let read = bounded_read(&config.read_path, MAX_SOURCE_EFFECT_BYTES)?;
        let task = LifecycleTask {
            objective,
            budget: config.task_budget,
        };
        let budget = IterativeBudget {
            max_iterations: config.max_iterations,
            max_stages: config.max_stages,
            max_steps_per_stage: config.max_steps_per_stage,
        };
        let policy = SourceLivePolicy {
            deployment_binding: deployment_binding(&read),
            response_limit: config.response_limit,
            ceiling: config.ceiling,
            reservation_units: config.reservation_units,
            unit: UNIT.into(),
            clock_domain: CLOCK_DOMAIN.into(),
            initial_millis: 0,
            deadline_millis: config.deadline_millis,
            max_total_steps: config.max_total_steps,
            program_root: Some(program_root),
        };
        policy
            .binding(&compiled, &task, budget)
            .map_err(|_| CliError::refused("source execution policy refused"))?;
        Ok(Self {
            project_root,
            project,
            compiled,
            config,
            task,
            read,
            budget,
            policy,
        })
    }

    fn migration_endpoint(&self) -> SourceLiveMigrationEndpoint<'_> {
        SourceLiveMigrationEndpoint {
            project: &self.project,
            source_path: &self.config.source_path,
            agent_id: &self.config.agent_id,
            lifecycle: &self.compiled,
            policy: &self.policy,
            budget: self.budget,
        }
    }
}

fn deployment_binding(read: &[u8]) -> String {
    let mut hash = Sha256::new();
    hash.update(b"semaprax.source-live-cli.deployment.v1\0");
    hash.update(OPENCODE_MODEL.as_bytes());
    hash.update([0]);
    hash.update(read);
    format!("sha256:{:x}", LowerHex(hash.finalize()))
}

fn source_error(failure: SourceLiveFailure) -> CliError {
    let diagnostic_code = failure
        .diagnostics
        .first()
        .map_or("unclassified", |diagnostic| diagnostic.code);
    let status = failure
        .selected
        .map_or("unselected", |status| status.as_str());
    let generation = failure
        .checkpoint
        .as_ref()
        .map_or(0, RecoveredSourceCheckpoint::generation);
    let units = failure
        .checkpoint
        .as_ref()
        .map_or(0, RecoveredSourceCheckpoint::committed_reserved_units);
    let fuel = failure
        .checkpoint
        .as_ref()
        .map_or(0, RecoveredSourceCheckpoint::committed_stage_fuel);
    CliError::detail(format!(
        "checked source run failed; code={diagnostic_code}; selected={status}; acknowledged_generation={generation}; committed_model_units={units}; committed_stage_fuel={fuel}"
    ))
}

fn receipt(outcome: SourceLiveOutcome) -> Result<String, CliError> {
    let terminal = outcome
        .checkpoint
        .terminal_snapshot()
        .ok_or(CliError::refused("checked run has no terminal checkpoint"))?;
    Ok(format!(
        "{{\"schema\":\"semaprax.source-live-cli.receipt.v1\",\"status\":{},\"invocation\":{},\"generation\":{},\"chain\":{},\"committed_model_units\":{},\"committed_stage_fuel\":{},\"model_dispatches\":{},\"effect_dispatches\":{}}}\n",
        serde_json::to_string(terminal.status().as_str()).expect("static status"),
        serde_json::to_string(outcome.checkpoint.invocation()).expect("bound invocation"),
        outcome.checkpoint.generation(),
        serde_json::to_string(outcome.checkpoint.chain()).expect("bound chain"),
        outcome.checkpoint.committed_reserved_units(),
        outcome.checkpoint.committed_stage_fuel(),
        outcome.model_dispatches,
        outcome.effect_dispatches,
    ))
}

fn provider<R: OpenCodeRunner>(
    endpoint: &Endpoint,
    executable: PathBuf,
    scratch: PathBuf,
    runner: R,
    clock: &dyn SourceInvocationClock,
) -> Result<
    (
        OpenCodeModelHandler<R>,
        OpenCodeGrammar,
        ModelInvokeCapability,
    ),
    CliError,
> {
    let grammar = OpenCodeGrammar::from_proposal(endpoint.compiled.proposal_schema())
        .map_err(|_| CliError::refused("OpenCode grammar admission refused"))?;
    let remaining = endpoint
        .policy
        .deadline_millis
        .saturating_sub(clock.now_millis());
    let call_ms = remaining.clamp(1, MAX_ONE_PROVIDER_CALL_MS) as u64;
    let config = OpenCodeHostConfig::new(
        executable,
        scratch,
        Duration::from_millis(call_ms),
        grammar.clone(),
    )
    .map_err(|_| CliError::refused("private OpenCode host configuration refused"))?;
    Ok((
        OpenCodeModelHandler::new(config, runner),
        grammar,
        ModelInvokeCapability::grant("source-live CLI fixed free provider"),
    ))
}

pub(super) fn execute(command: Command) -> Result<String, CliError> {
    execute_with_runner(command, ProcessOpenCodeRunner)
}

pub(super) fn execute_with_runner<R: OpenCodeRunner>(
    command: Command,
    runner: R,
) -> Result<String, CliError> {
    match command {
        Command::Run {
            config,
            checkpoint,
            executable,
            scratch,
        } => execute_run(config, checkpoint, executable, scratch, true, runner),
        Command::Resume {
            config,
            checkpoint,
            executable,
            scratch,
        } => execute_run(config, checkpoint, executable, scratch, false, runner),
        Command::Migrate {
            previous_config,
            previous_checkpoint,
            destination_config,
            destination_checkpoint,
            function,
            steps,
            executable,
            scratch,
        } => execute_migrate(
            previous_config,
            previous_checkpoint,
            destination_config,
            destination_checkpoint,
            &function,
            steps,
            executable,
            scratch,
            runner,
        ),
    }
}

fn execute_run<R: OpenCodeRunner>(
    config: PathBuf,
    checkpoint: PathBuf,
    executable: PathBuf,
    scratch: PathBuf,
    fresh: bool,
    runner: R,
) -> Result<String, CliError> {
    let endpoint = Endpoint::load(SessionConfig::load(&config)?)?;
    let binding = endpoint
        .policy
        .binding(&endpoint.compiled, &endpoint.task, endpoint.budget)
        .map_err(|_| CliError::refused("source execution binding refused"))?;
    let mut store = if fresh {
        CheckpointDir::fresh(&checkpoint, &endpoint.project_root)?
    } else {
        CheckpointDir::existing(&checkpoint, &endpoint.project_root)?
    };
    let latest = store.latest()?;
    if fresh && latest.is_some() || !fresh && latest.is_none() {
        return Err(CliError::refused(
            "checkpoint mode does not match latest journal",
        ));
    }
    if let Some(document) = latest.as_deref() {
        let recovered = recover_source_checkpoint(document, &binding)
            .map_err(|_| CliError::refused("latest source checkpoint binding refused"))?;
        store.set_generation(recovered.generation());
        if recovered.terminal_snapshot().is_some() {
            return receipt(SourceLiveOutcome {
                checked_run: None,
                checkpoint: recovered,
                model_dispatches: 0,
                effect_dispatches: 0,
            });
        }
    }
    let clock = UnixClock;
    let (mut handler, grammar, capability) =
        provider(&endpoint, executable, scratch, runner, &clock)?;
    let mut source = OpenCodeDurableProposalSource::new(
        &mut handler,
        &capability,
        endpoint.policy.deployment_binding.clone(),
        grammar,
        endpoint.policy.response_limit,
        endpoint.policy.reservation_units,
    )
    .map_err(|_| CliError::refused("durable OpenCode source refused"))?;
    let mut read = ReadSnapshot(endpoint.read.clone());
    let cancellation = AgentCancellation::new();
    let result = endpoint.compiled.run_live_durable(
        SourceLiveRequest {
            task: &endpoint.task,
            budget: endpoint.budget,
            policy: &endpoint.policy,
            clock: &clock,
            cancellation: &cancellation,
            checkpoint: latest.as_deref(),
        },
        &mut source,
        &mut read,
        &mut store,
    );
    drop(source);
    result.map_err(source_error).and_then(receipt)
}

#[allow(clippy::too_many_arguments)]
fn execute_migrate<R: OpenCodeRunner>(
    previous_config: PathBuf,
    previous_checkpoint: PathBuf,
    destination_config: PathBuf,
    destination_checkpoint: PathBuf,
    function: &str,
    steps: usize,
    executable: PathBuf,
    scratch: PathBuf,
    runner: R,
) -> Result<String, CliError> {
    let previous = Endpoint::load(SessionConfig::load(&previous_config)?)?;
    let mut destination = Endpoint::load(SessionConfig::load(&destination_config)?)?;
    if previous.task.objective != destination.task.objective
        || previous.task.budget != destination.task.budget
    {
        return Err(CliError::refused("migration task changed"));
    }
    let previous_binding = previous
        .policy
        .binding(&previous.compiled, &previous.task, previous.budget)
        .map_err(|_| CliError::refused("predecessor binding refused"))?;
    // A v3 predecessor cannot satisfy this v2 binding. This CLI version
    // deliberately refuses multi-hop store topology instead of inferring a
    // previous handoff authority from submitted checkpoint bytes.
    let previous_store = CheckpointDir::existing(&previous_checkpoint, &previous.project_root)?;
    let previous_document = previous_store
        .latest()?
        .ok_or(CliError::refused("predecessor has no latest checkpoint"))?;
    let predecessor = recover_source_checkpoint(&previous_document, &previous_binding)
        .map_err(|_| CliError::refused("predecessor v2 checkpoint refused"))?;
    // The destination clock origin is carried from the authenticated latest
    // predecessor, not reset by the operator's destination CONFIG. Repeating
    // this handoff derives the same origin from the same held source journal.
    destination.policy.initial_millis = predecessor.last_checked_millis();
    let prepared = prepare_source_live_migration(SourceLiveMigrationRequest {
        previous: previous.migration_endpoint(),
        previous_binding: &previous_binding,
        previous_checkpoint: &previous_document,
        destination: destination.migration_endpoint(),
        task: &destination.task,
        migration_function: function,
        max_migration_steps: steps,
        expected_handoff_digest: None,
    })
    .map_err(source_error)?;
    let path_was_new = !destination_checkpoint.exists();
    let mut destination_store = if path_was_new {
        CheckpointDir::fresh(&destination_checkpoint, &destination.project_root)?
    } else {
        CheckpointDir::existing(&destination_checkpoint, &destination.project_root)?
    };
    if destination_store.path() == previous_store.path() {
        return Err(CliError::refused(
            "migration destination equals predecessor store",
        ));
    }
    let destination_document = destination_store.latest()?;
    if let Some(document) = destination_document.as_deref() {
        let recovered = recover_source_checkpoint(document, prepared.binding())
            .map_err(|_| CliError::refused("destination latest checkpoint binding refused"))?;
        destination_store.set_generation(recovered.generation());
    }
    let clock = UnixClock;
    // Check provider configuration before making the irreversible claim, but
    // permit a terminal receipt to be retrieved without opening a new child.
    let terminal = destination_document.as_deref().and_then(|document| {
        recover_source_checkpoint(document, prepared.binding())
            .ok()
            .filter(|checkpoint| checkpoint.terminal_snapshot().is_some())
    });
    let prepared_provider = if terminal.is_none() {
        Some(provider(&destination, executable, scratch, runner, &clock)?)
    } else {
        None
    };
    previous_store.claim_handoff(
        prepared.handoff_digest(),
        destination_store.path(),
        prepared.binding().invocation(),
    )?;
    if let Some(checkpoint) = terminal {
        return receipt(SourceLiveOutcome {
            checked_run: None,
            checkpoint,
            model_dispatches: 0,
            effect_dispatches: 0,
        });
    }
    let (mut handler, grammar, capability) = prepared_provider.expect("nonterminal prepared");
    let mut source = OpenCodeDurableProposalSource::new(
        &mut handler,
        &capability,
        destination.policy.deployment_binding.clone(),
        grammar,
        destination.policy.response_limit,
        destination.policy.reservation_units,
    )
    .map_err(|_| CliError::refused("durable OpenCode source refused"))?;
    let mut read = ReadSnapshot(destination.read.clone());
    let cancellation = AgentCancellation::new();
    let prepared = if let Some(document) = destination_document.as_deref() {
        prepared.with_checkpoint(document)
    } else {
        prepared
    };
    let outcome = prepared.run(
        &mut source,
        &mut read,
        &mut destination_store,
        &clock,
        &cancellation,
    );
    drop(source);
    outcome.map_err(source_error).and_then(receipt)
}
