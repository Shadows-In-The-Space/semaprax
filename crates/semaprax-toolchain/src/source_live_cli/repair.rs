//! Host-selected, durable, config-driven checked candidate-repair preview.
//!
//! This generalizes the fixed `offline-repair` demonstration's
//! candidate-preview/source-diff/semantic-impact evidence
//! (`OfflineRepairEnvelope`/`OfflineRepairHandler`) to an arbitrary
//! host-selected Project, target declaration and effect contract, driven
//! through the durable, checkpoint-capable `AgentRuntimeV2` route
//! (`run_live_bound_model_durable`) so the run is resumable like the general
//! `source-live run|resume` verbs. The provider stays a bounded, scripted,
//! credential-free fixture (no live network call): this command produces
//! reviewable evidence for an *ephemeral* candidate only. It performs no
//! publication or source mutation; a separately authorized, exact-digest-bound
//! session (`project-candidate-git-publish`) is the only route that can commit.
use std::cell::{Cell, RefCell};
use std::collections::VecDeque;
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::sync::Arc;

use semaprax::agent_deployment::migrate_agent_definition_v1;
use semaprax::agent_lifecycle::iterative::compile_source_agent_lifecycle_v2;
use semaprax::agent_lifecycle::iterative::effects::{
    EffectArgument, EffectBudget, EffectOperation, EffectResult, EffectScalar,
};
use semaprax::agent_lifecycle::iterative::source_live::{SourceLivePolicy, SourceProposalPolicy};
use semaprax::agent_lifecycle::iterative::IterativeBudget;
use semaprax::agent_lifecycle::LifecycleTask;
use semaprax::agent_runtime::AgentCancellation;
use semaprax::agent_runtime_v2::{
    bind_agent_runtime_v2_live, OfflineRepairEnvelope, OfflineRepairHandler,
    SourceModelAdapterIdentity,
};
use semaprax::execution_revision::ProgramRootRef;
use semaprax::live_invocation::{InvocationClock, SourceInvocationClock};
use semaprax::project::{with_authenticated_project, ProjectRevision};
use semaprax::provider_adapter_sdk::fixture_adapters::{usage, ScriptedStreamingAdapter};
use semaprax::provider_adapter_sdk::{
    AdapterInvocationCapability, AdapterPoll, AdapterRefusal, AdapterRequest, ProviderAdapter,
    StreamingSourceProposalAdapter,
};
use serde_json::{json, Map, Value};

use super::checkpoint::{bounded_read, CheckpointDir};
use super::CliError;

const CLOCK_DOMAIN: &str = "semaprax.source-live-cli.repair.v1";
const MAX_CONFIG_BYTES: usize = 16384;
const MAX_TOKEN_BYTES: usize = 240;
const MAX_TASK_BYTES: usize = 4096;
const MAX_PROPOSAL_BYTES: usize = 8192;
const RECEIPT_SCHEMA: &str = "semaprax.source-live-cli.repair-receipt.v1";
const CONFIG_SCHEMA: &str = "semaprax.source-live-cli.repair-config.v1";

fn is_absolute_like(path: &Path) -> bool {
    path.is_absolute() || path.to_string_lossy().starts_with('/')
}

struct FixedClock;
impl InvocationClock for FixedClock {
    fn now_millis(&self) -> i64 {
        0
    }
}
impl SourceInvocationClock for FixedClock {
    fn clock_domain(&self) -> &str {
        CLOCK_DOMAIN
    }
}

/// One scripted provider turn: the exact canonical proposal document the
/// fixture provider returns, and (for a corrective turn) the diagnostic
/// feedback hex it must have observed in the prompt to prove the turn used
/// the checked rejection rather than repeating the malformed guess blind.
#[derive(Clone, Debug, Eq, PartialEq)]
struct RepairTurn {
    document: String,
    requires_prior_feedback: bool,
}

/// Host-selected, config-driven repair session. Every identity below is a
/// host operand; the model supplies only the scalar argument value routed
/// through `argument_id`/`proposal_field_id`. No path, target or provider is
/// chosen by proposal text.
struct RepairConfig {
    manifest: PathBuf,
    source_path: String,
    agent_id: String,
    step_id: String,
    selector_field_id: String,
    deployment_migration_id: String,
    target: String,
    malformed_operation_id: String,
    corrected_operation_id: String,
    effect_id: String,
    argument_id: String,
    proposal_field_id: String,
    result_id: String,
    task_path: PathBuf,
    task_budget: i64,
    deadline_millis: i64,
    ceiling: i64,
    reservation_units: i64,
    max_total_steps: usize,
    max_calls: usize,
    max_argument_bytes: usize,
    max_result_bytes: usize,
    max_total_bytes: usize,
    malformed_replacement: i64,
    malformed_bool_literal: bool,
    turns: [RepairTurn; 2],
}

impl RepairConfig {
    fn load(path: &Path) -> Result<Self, CliError> {
        if !is_absolute_like(path) {
            return Err(CliError::usage("configuration path must be absolute"));
        }
        let bytes = bounded_read(path, MAX_CONFIG_BYTES)?;
        let value: Value = serde_json::from_slice(&bytes)
            .map_err(|_| CliError::refused("configuration JSON is malformed"))?;
        let canonical = serde_json::to_vec(&value)
            .map_err(|_| CliError::refused("configuration cannot be encoded"))?;
        if bytes.as_slice() != canonical.as_slice()
            && bytes.strip_suffix(b"\n") != Some(canonical.as_slice())
        {
            return Err(CliError::refused("configuration must be canonical JSON"));
        }
        let map = value
            .as_object()
            .ok_or(CliError::refused("configuration must be an object"))?;
        const KEYS: [&str; 24] = [
            "schema",
            "manifest",
            "source_path",
            "agent_id",
            "step_id",
            "selector_field_id",
            "deployment_migration_id",
            "target",
            "malformed_operation_id",
            "corrected_operation_id",
            "effect_id",
            "argument_id",
            "proposal_field_id",
            "result_id",
            "task_path",
            "task_budget",
            "deadline_millis",
            "ceiling",
            "reservation_units",
            "max_total_steps",
            "effect_budget",
            "malformed_replacement",
            "malformed_bool_literal",
            "turns",
        ];
        if text(map, "schema")? != CONFIG_SCHEMA
            || map.len() != KEYS.len()
            || !KEYS.iter().all(|key| map.contains_key(*key))
        {
            return Err(CliError::refused(
                "repair configuration has missing or unknown keys",
            ));
        }
        let manifest = absolute(map, "manifest")?;
        let source_path = token(map, "source_path")?;
        if is_absolute_like(Path::new(&source_path))
            || Path::new(&source_path)
                .components()
                .any(|component| !matches!(component, std::path::Component::Normal(_)))
            || !source_path.ends_with(".spx")
        {
            return Err(CliError::refused(
                "source_path must be a relative Project .spx path",
            ));
        }
        let target = token(map, "target")?;
        if target.len() > 256 {
            return Err(CliError::refused("target exceeds bounds"));
        }
        let effect_budget = map
            .get("effect_budget")
            .and_then(Value::as_object)
            .ok_or(CliError::refused("effect_budget must be an object"))?;
        const EFFECT_BUDGET_KEYS: [&str; 4] = [
            "max_calls",
            "max_argument_bytes",
            "max_result_bytes",
            "max_total_bytes",
        ];
        if effect_budget.len() != EFFECT_BUDGET_KEYS.len()
            || !EFFECT_BUDGET_KEYS
                .iter()
                .all(|key| effect_budget.contains_key(*key))
        {
            return Err(CliError::refused(
                "effect_budget has missing or unknown keys",
            ));
        }
        let turns = map
            .get("turns")
            .and_then(Value::as_array)
            .ok_or(CliError::refused("turns must be an array"))?;
        let [first, second] = turns.as_slice() else {
            return Err(CliError::refused("turns must have exactly two entries"));
        };
        let turn = |value: &Value| -> Result<RepairTurn, CliError> {
            let object = value
                .as_object()
                .ok_or(CliError::refused("turn must be an object"))?;
            const TURN_KEYS: [&str; 2] = ["document", "requires_prior_feedback"];
            if object.len() != TURN_KEYS.len()
                || !TURN_KEYS.iter().all(|key| object.contains_key(*key))
            {
                return Err(CliError::refused("turn has missing or unknown keys"));
            }
            let document = text(object, "document")?.to_owned();
            if document.is_empty() || document.len() > MAX_PROPOSAL_BYTES {
                return Err(CliError::refused("turn document exceeds bounds"));
            }
            let requires_prior_feedback = object
                .get("requires_prior_feedback")
                .and_then(Value::as_bool)
                .ok_or(CliError::refused("requires_prior_feedback must be boolean"))?;
            Ok(RepairTurn {
                document,
                requires_prior_feedback,
            })
        };
        Ok(Self {
            manifest,
            source_path,
            agent_id: token(map, "agent_id")?,
            step_id: token(map, "step_id")?,
            selector_field_id: token(map, "selector_field_id")?,
            deployment_migration_id: token(map, "deployment_migration_id")?,
            target,
            malformed_operation_id: token(map, "malformed_operation_id")?,
            corrected_operation_id: token(map, "corrected_operation_id")?,
            effect_id: token(map, "effect_id")?,
            argument_id: token(map, "argument_id")?,
            proposal_field_id: token(map, "proposal_field_id")?,
            result_id: token(map, "result_id")?,
            task_path: absolute(map, "task_path")?,
            task_budget: nonnegative_i64(map, "task_budget")?,
            deadline_millis: positive_i64(map, "deadline_millis")?,
            ceiling: nonnegative_i64(map, "ceiling")?,
            reservation_units: positive_i64(map, "reservation_units")?,
            max_total_steps: positive_usize(map, "max_total_steps")?,
            max_calls: positive_usize(effect_budget, "max_calls")?,
            max_argument_bytes: positive_usize(effect_budget, "max_argument_bytes")?,
            max_result_bytes: positive_usize(effect_budget, "max_result_bytes")?,
            max_total_bytes: positive_usize(effect_budget, "max_total_bytes")?,
            malformed_replacement: signed_i64(map, "malformed_replacement")?,
            malformed_bool_literal: map
                .get("malformed_bool_literal")
                .and_then(Value::as_bool)
                .ok_or(CliError::refused("malformed_bool_literal must be boolean"))?,
            turns: [turn(first)?, turn(second)?],
        })
    }
}

fn text<'a>(map: &'a Map<String, Value>, key: &str) -> Result<&'a str, CliError> {
    map.get(key)
        .and_then(Value::as_str)
        .ok_or(CliError::refused("configuration field has the wrong type"))
}

fn token(map: &Map<String, Value>, key: &str) -> Result<String, CliError> {
    let value = text(map, key)?;
    if value.is_empty()
        || value.len() > MAX_TOKEN_BYTES
        || value.bytes().any(|byte| byte.is_ascii_control())
    {
        return Err(CliError::refused("configuration identifier is invalid"));
    }
    Ok(value.to_owned())
}

fn absolute(map: &Map<String, Value>, key: &str) -> Result<PathBuf, CliError> {
    let path = PathBuf::from(text(map, key)?);
    if !is_absolute_like(&path) {
        return Err(CliError::refused("configuration path must be absolute"));
    }
    Ok(path)
}

fn positive_i64(map: &Map<String, Value>, key: &str) -> Result<i64, CliError> {
    let value = map
        .get(key)
        .and_then(Value::as_i64)
        .ok_or(CliError::refused("configuration integer is invalid"))?;
    (value > 0)
        .then_some(value)
        .ok_or(CliError::refused("configuration integer must be positive"))
}

fn nonnegative_i64(map: &Map<String, Value>, key: &str) -> Result<i64, CliError> {
    let value = map
        .get(key)
        .and_then(Value::as_i64)
        .ok_or(CliError::refused("configuration integer is invalid"))?;
    (value >= 0).then_some(value).ok_or(CliError::refused(
        "configuration integer must be nonnegative",
    ))
}

fn signed_i64(map: &Map<String, Value>, key: &str) -> Result<i64, CliError> {
    map.get(key)
        .and_then(Value::as_i64)
        .ok_or(CliError::refused("configuration integer is invalid"))
}

fn positive_usize(map: &Map<String, Value>, key: &str) -> Result<usize, CliError> {
    let value = map
        .get(key)
        .and_then(Value::as_u64)
        .and_then(|number| usize::try_from(number).ok())
        .ok_or(CliError::refused("configuration capacity is invalid"))?;
    (value > 0)
        .then_some(value)
        .ok_or(CliError::refused("configuration capacity must be positive"))
}

pub(super) enum Command {
    Run {
        config: PathBuf,
        checkpoint: PathBuf,
    },
    Resume {
        config: PathBuf,
        checkpoint: PathBuf,
    },
}

impl Command {
    pub(super) fn parse(arguments: &[String]) -> Result<Self, CliError> {
        let [verb, config, checkpoint] = arguments else {
            return Err(CliError::usage(
                "repair requires exactly run|resume <config.json> <checkpoint-dir>",
            ));
        };
        let config = absolute_operand(config)?;
        let checkpoint = absolute_operand(checkpoint)?;
        match verb.as_str() {
            "run" => Ok(Self::Run { config, checkpoint }),
            "resume" => Ok(Self::Resume { config, checkpoint }),
            _ => Err(CliError::usage("repair expected run or resume")),
        }
    }
}

fn absolute_operand(value: &str) -> Result<PathBuf, CliError> {
    let path = PathBuf::from(value);
    if !is_absolute_like(&path) {
        return Err(CliError::usage("repair operands must be absolute paths"));
    }
    Ok(path)
}

fn diagnostic_error(context: &str, diagnostics: Vec<semaprax::diagnostic::Diagnostic>) -> CliError {
    CliError::detail(format!("{context}: {diagnostics:?}"))
}

fn checked_value(document: &str, field: &'static str) -> Result<Value, CliError> {
    serde_json::from_str(document).map_err(|_| CliError::refused(field))
}

fn identity() -> SourceModelAdapterIdentity {
    SourceModelAdapterIdentity {
        provider_id: "fake.local".to_owned(),
        model_id: "fake-basic".to_owned(),
        adapter_identity: "scripted-streaming-adapter".to_owned(),
        adapter_version: "1.0.0".to_owned(),
        provider_profile: "fixture".to_owned(),
    }
}

fn operations(config: &RepairConfig) -> Vec<EffectOperation> {
    [
        &config.malformed_operation_id,
        &config.corrected_operation_id,
    ]
    .into_iter()
    .map(|operation_id| EffectOperation {
        operation_id: operation_id.clone(),
        effect_id: config.effect_id.clone(),
        arguments: vec![EffectArgument {
            argument_id: config.argument_id.clone(),
            proposal_field_id: config.proposal_field_id.clone(),
            kind: EffectScalar::I64,
        }],
        results: vec![EffectResult {
            result_id: config.result_id.clone(),
            kind: EffectScalar::I64,
        }],
    })
    .collect()
}

fn policy(
    config: &RepairConfig,
    deployment_binding: &str,
    response_limit: usize,
) -> SourceLivePolicy {
    SourceLivePolicy {
        deployment_binding: deployment_binding.to_owned(),
        response_limit,
        ceiling: config.ceiling,
        reservation_units: config.reservation_units,
        unit: "semaprax.source-live-cli.repair-unit.v1".to_owned(),
        clock_domain: CLOCK_DOMAIN.to_owned(),
        initial_millis: 0,
        deadline_millis: config.deadline_millis,
        max_total_steps: config.max_total_steps,
        program_root: None,
    }
}

fn checkpoint_policy<'a>(
    deployment_binding: &'a str,
    response_limit: usize,
    reservation_units: i64,
) -> SourceProposalPolicy<'a> {
    SourceProposalPolicy {
        deployment_binding,
        response_limit,
        reservation_units,
    }
}

fn feedback_hex(code: i64, result_id: &str) -> String {
    format!(
        "{{\"schema\":\"semaprax.agent-effect-fields.v1\",\"fields\":[[\"{result_id}\",\"{code}\"]]}}\n"
    )
    .bytes()
    .map(|byte| format!("{byte:02x}"))
    .collect()
}

fn feedback_code(diagnostics: &[semaprax::diagnostic::Diagnostic]) -> i64 {
    diagnostics
        .iter()
        .find_map(|diagnostic| {
            diagnostic
                .code
                .strip_prefix("SPX-G")
                .and_then(|code| code.parse::<i64>().ok())
        })
        .unwrap_or(583)
}

struct FeedbackGuardedAdapter {
    inner: ScriptedStreamingAdapter,
    starts: Rc<Cell<usize>>,
    required_feedback: Option<String>,
    refuse_start: bool,
}
impl ProviderAdapter for FeedbackGuardedAdapter {
    fn capabilities(&self) -> &semaprax::provider_adapter_sdk::AdapterCapabilities {
        self.inner.capabilities()
    }

    fn start(
        &mut self,
        capability: &AdapterInvocationCapability,
        request: &AdapterRequest,
    ) -> Result<(), AdapterRefusal> {
        if self.refuse_start {
            return Err(AdapterRefusal(
                "repair preview exhausted its scripted proposal turns".to_owned(),
            ));
        }
        self.starts.set(self.starts.get() + 1);
        if self.required_feedback.as_ref().is_some_and(|expected| {
            serde_json::from_slice::<Value>(&request.request_bytes)
                .ok()
                .and_then(|prompt| prompt["previous_effect_hex"].as_str().map(str::to_owned))
                .as_deref()
                != Some(expected)
        }) {
            return Err(AdapterRefusal(
                "repair correction omitted checked diagnostic feedback".to_owned(),
            ));
        }
        self.inner.start(capability, request)
    }

    fn poll(&mut self) -> AdapterPoll {
        self.inner.poll()
    }

    fn cancel(&mut self, reason: &str) {
        self.inner.cancel(reason);
    }
}

pub(super) fn run(arguments: &[String]) -> Result<String, CliError> {
    execute(Command::parse(arguments)?)
}

fn execute(command: Command) -> Result<String, CliError> {
    let (config_path, checkpoint_path, fresh) = match command {
        Command::Run { config, checkpoint } => (config, checkpoint, true),
        Command::Resume { config, checkpoint } => (config, checkpoint, false),
    };
    let config = RepairConfig::load(&config_path)?;

    // --- Ordinary lock/authority is acquired first, before any evidence
    // replay, staging or candidate creation. ---
    let manifest = config
        .manifest
        .canonicalize()
        .map_err(|_| CliError::refused("repair Project manifest is unavailable"))?;
    let project_root = manifest
        .parent()
        .ok_or(CliError::refused("repair Project manifest has no root"))?
        .to_owned();
    let project = with_authenticated_project(&manifest, |snapshot| Ok(snapshot.retain_revision()))
        .map_err(|diagnostics| {
            diagnostic_error("repair Project authentication refused", diagnostics)
        })?;

    let source = project
        .sources()
        .iter()
        .find(|source| source.path() == config.source_path)
        .ok_or(CliError::refused("repair source is unavailable"))?;
    let source_disk_path = project_root.join(&config.source_path);
    let source_before = std::fs::read(&source_disk_path)
        .map_err(|_| CliError::refused("repair source cannot be read"))?;

    let root = project
        .program_root()
        .map_err(|_| CliError::refused("repair ProgramRoot is unavailable"))?;
    let (_, deployment) = migrate_agent_definition_v1(
        project.agent_definitions()[0]
            .definition()
            .canonical_source(),
        &config.deployment_migration_id,
    )
    .map_err(|diagnostics| diagnostic_error("repair deployment migration refused", diagnostics))?;
    let compiled = compile_source_agent_lifecycle_v2(
        source.source(),
        source.path(),
        &config.agent_id,
        &config.step_id,
    )
    .map_err(|diagnostics| diagnostic_error("repair lifecycle compilation refused", diagnostics))?;
    let task = LifecycleTask {
        objective: bounded_read(&config.task_path, MAX_TASK_BYTES)?,
        budget: config.task_budget,
    };
    let iterative_budget = IterativeBudget::default();
    let effect_budget = EffectBudget {
        max_calls: config.max_calls,
        max_argument_bytes: config.max_argument_bytes,
        max_result_bytes: config.max_result_bytes,
        max_total_bytes: config.max_total_bytes,
    };
    let runtime = bind_agent_runtime_v2_live(
        Arc::clone(&project),
        ProgramRootRef::V1(&root),
        root.program_root_digest(),
        &config.source_path,
        &config.agent_id,
        &config.step_id,
        &config.selector_field_id,
        operations(&config),
        &deployment,
        task.clone(),
        iterative_budget,
        effect_budget,
    )
    .map_err(|diagnostics| diagnostic_error("repair runtime binding refused", diagnostics))?;
    let model_binding = runtime
        .source_model_binding(identity())
        .map_err(|diagnostics| {
            diagnostic_error("repair source model binding refused", diagnostics)
        })?;
    let source_policy = policy(
        &config,
        model_binding.digest(),
        model_binding.max_response_bytes(),
    );

    // --- Any existing evidence is replayed before staging or candidate
    // creation can occur. `run_live_bound_model_durable` below recovers the
    // retained checkpoint against its own checked binding (program root,
    // lifecycle digest and effect contract) before it can dispatch anything;
    // a terminal generation is never redispatched, and a binding mismatch
    // (including source drift) is refused rather than silently replayed
    // against stale evidence -- see the hostile
    // `repair_resume_refuses_when_source_drifts_between_preview_and_resume`
    // regression. This route intentionally reuses that single checked
    // recovery rather than duplicating an independent pre-check with a
    // different (and therefore inevitably divergent) binding derivation. ---
    let mut store = if fresh {
        CheckpointDir::fresh(&checkpoint_path, &project_root)?
    } else {
        CheckpointDir::existing(&checkpoint_path, &project_root)?
    };
    let latest = store.latest()?;
    if fresh && latest.is_some() || !fresh && latest.is_none() {
        return Err(CliError::refused(
            "checkpoint mode does not match latest journal",
        ));
    }

    // --- Only this live invocation performs any work below this point; the
    // candidate it may create is ephemeral and is never committed here. ---
    let envelope = OfflineRepairEnvelope::new(Arc::clone(&project), config.target.clone())
        .map_err(|diagnostics| diagnostic_error("repair target envelope refused", diagnostics))?;
    let malformed = envelope
        .preview(config.malformed_replacement, config.malformed_bool_literal)
        .err()
        .ok_or(CliError::refused(
            "repair malformed replacement unexpectedly admitted",
        ))?;
    let expected_feedback = feedback_hex(feedback_code(&malformed), &config.result_id);
    let mut handler = OfflineRepairHandler::new(
        envelope,
        config.malformed_operation_id.clone(),
        config.corrected_operation_id.clone(),
        config.effect_id.clone(),
        config.argument_id.clone(),
        config.result_id.clone(),
    )
    .map_err(|diagnostics| diagnostic_error("repair effect contract refused", diagnostics))?;

    let scripts = RefCell::new(VecDeque::from(config.turns.clone().map(|turn| {
        (
            turn.document,
            turn.requires_prior_feedback
                .then(|| expected_feedback.clone()),
        )
    })));
    let starts = Rc::new(Cell::new(0));
    let factory_starts = Rc::clone(&starts);
    let mut factory = move || -> Box<dyn ProviderAdapter> {
        let next = scripts.borrow_mut().pop_front();
        let refuse_start = next.is_none();
        let (document, required_feedback) = next.unwrap_or_else(|| (String::new(), None));
        Box::new(FeedbackGuardedAdapter {
            inner: ScriptedStreamingAdapter::new(
                document
                    .as_bytes()
                    .chunks(3)
                    .map(ToOwned::to_owned)
                    .collect(),
                document.into_bytes(),
                usage(1, 1, 0),
                true,
            ),
            starts: Rc::clone(&factory_starts),
            required_feedback,
            refuse_start,
        })
    };
    let cancellation = AgentCancellation::new();
    let mut source = StreamingSourceProposalAdapter::new_bound_checkpointed(
        &mut factory,
        AdapterInvocationCapability::grant("source-live repair preview fixed free provider"),
        compiled.proposal_schema(),
        model_binding.clone(),
        model_binding.invocation_capability(),
        checkpoint_policy(
            model_binding.digest(),
            model_binding.max_response_bytes(),
            config.reservation_units,
        ),
    )
    .map_err(|diagnostics| diagnostic_error("repair source adapter refused", diagnostics))?;
    let retained_checkpoint = latest.as_deref();
    let complete = runtime
        .run_live_bound_model_durable(
            &mut source,
            &mut handler,
            source_policy,
            &FixedClock,
            &cancellation,
            retained_checkpoint,
            &mut store,
        )
        .map_err(|failure| {
            diagnostic_error(
                "repair checked source execution refused",
                failure.failure().diagnostics.to_vec(),
            )
        })?;
    drop(source);

    let model_dispatches = complete.run().model_dispatches;
    let effect_dispatches = complete.run().effect_dispatches;
    // A pure terminal-checkpoint replay dispatches nothing and therefore
    // never starts the scripted provider; only a fresh (redispatching)
    // attempt must consume its exact scripted turn sequence.
    if model_dispatches > 0 && starts.get() != config.turns.len() {
        return Err(CliError::refused(
            "repair preview did not consume its exact scripted turn sequence",
        ));
    }
    if std::fs::read(&source_disk_path)
        .map_err(|_| CliError::refused("repair source cannot be reread"))?
        != source_before
    {
        return Err(CliError::refused("repair source changed during execution"));
    }

    let preview = handler.latest_preview();
    let rejection_count = handler.rejection_count();
    receipt_with_preview(
        &config,
        preview,
        rejection_count,
        &complete.run().checkpoint,
        model_dispatches,
        effect_dispatches,
    )
}

fn receipt(
    config: &RepairConfig,
    preview: Option<&semaprax::agent_runtime_v2::OfflineRepairPreview>,
    checkpoint: &semaprax::live_invocation::source_journal::RecoveredSourceCheckpoint,
    model_dispatches: u32,
    effect_dispatches: u32,
) -> Result<String, CliError> {
    let terminal = checkpoint.terminal_snapshot().ok_or(CliError::refused(
        "repair checkpoint has no terminal snapshot",
    ))?;
    let mut report = json!({
        "schema": RECEIPT_SCHEMA,
        "target": config.target,
        "status": terminal.status().as_str(),
        "generation": checkpoint.generation(),
        "model_dispatches": model_dispatches,
        "effect_dispatches": effect_dispatches,
        "source_mutation": false,
        "publication_authority": false,
    });
    if let Some(preview) = preview {
        report["candidate_digest"] = json!(preview.candidate().candidate_digest());
        report["source_review"] =
            checked_value(preview.source_review(), "repair source review refused")?;
        report["semantic_delta"] =
            checked_value(preview.semantic_delta(), "repair semantic delta refused")?;
        report["impact_summary"] =
            checked_value(preview.impact_summary(), "repair impact summary refused")?;
    } else {
        report["candidate_digest"] = Value::Null;
        report["source_review"] = Value::Null;
        report["semantic_delta"] = Value::Null;
        report["impact_summary"] = Value::Null;
    }
    serde_json::to_string(&report)
        .map(|report| format!("{report}\n"))
        .map_err(|_| CliError::refused("repair report cannot be rendered"))
}

#[allow(clippy::too_many_arguments)]
fn receipt_with_preview(
    config: &RepairConfig,
    preview: Option<&semaprax::agent_runtime_v2::OfflineRepairPreview>,
    rejection_count: u32,
    checkpoint: &semaprax::live_invocation::source_journal::RecoveredSourceCheckpoint,
    model_dispatches: u32,
    effect_dispatches: u32,
) -> Result<String, CliError> {
    let base = receipt(
        config,
        preview,
        checkpoint,
        model_dispatches,
        effect_dispatches,
    )?;
    let mut value: Value = serde_json::from_str(&base)
        .map_err(|_| CliError::refused("repair report cannot be rendered"))?;
    value["rejected_candidates"] = json!(rejection_count);
    serde_json::to_string(&value)
        .map(|report| format!("{report}\n"))
        .map_err(|_| CliError::refused("repair report cannot be rendered"))
}

#[cfg(test)]
#[path = "repair_tests.rs"]
mod tests;
