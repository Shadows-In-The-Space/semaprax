//! Host-selected, durable, config-driven checked candidate-repair preview.
//!
//! This generalizes the fixed `offline-repair` demonstration's
//! candidate-preview/source-diff/semantic-impact evidence
//! (`OfflineRepairEnvelope`/`OfflineRepairHandler`) to an arbitrary
//! host-selected Project, target declaration and effect contract, driven
//! through the durable, checkpoint-capable `AgentRuntimeV2` route
//! (`run_live_bound_model_durable`) so the run is resumable like the general
//! `source-live run|resume` verbs. V1 retains a bounded, credential-free
//! scripted fixture for tests; V2 binds the same explicit OpenCode process
//! provider boundary as `source-live run`. Both modes produce reviewable
//! evidence for an *ephemeral* candidate only. They perform no publication or
//! source mutation; a separately authorized, exact-digest-bound session
//! (`project-candidate-git-publish`) is the only route that can commit.
use std::cell::{Cell, RefCell};
use std::collections::VecDeque;
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use semaprax::agent_deployment::migrate_agent_definition_v1;
use semaprax::agent_lifecycle::canonical_retained_value_json;
use semaprax::agent_lifecycle::iterative::compile_source_agent_lifecycle_v2;
use semaprax::agent_lifecycle::iterative::effects::{
    EffectArgument, EffectBudget, EffectOperation, EffectResult, EffectScalar, TypedEffectHandler,
    TypedEffectRequest,
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
use semaprax::interpreter::retained_call::RetainedValue;
use semaprax::live_invocation::{InvocationClock, SourceInvocationClock};
use semaprax::project::{with_authenticated_project, ProjectRevision};
use semaprax::provider_adapter_sdk::fixture_adapters::{usage, ScriptedStreamingAdapter};
use semaprax::provider_adapter_sdk::{
    AdapterInvocationCapability, AdapterPoll, AdapterRefusal, AdapterRequest, ProviderAdapter,
    StreamingSourceProposalAdapter,
};
use serde_json::{json, Map, Value};

use crate::opencode_host::repair_adapter::{
    source_model_identity, source_model_identity_for_config, OpenCodeRepairAdapter,
};
use crate::opencode_host::{
    OpenCodeGrammar, OpenCodeHostConfig, OpenCodeRunner, ProcessOpenCodeRunner,
};

use super::checkpoint::{bounded_read, CheckpointDir};
use super::CliError;

const FIXTURE_CLOCK_DOMAIN: &str = "semaprax.source-live-cli.repair.v1";
const UNIX_CLOCK_DOMAIN: &str = "unix_epoch_millis.v1";
const MAX_CONFIG_BYTES: usize = 16384;
const MAX_TOKEN_BYTES: usize = 240;
const MAX_TASK_BYTES: usize = 4096;
const MAX_PROPOSAL_BYTES: usize = 8192;
const RECEIPT_SCHEMA_V1: &str = "semaprax.source-live-cli.repair-receipt.v1";
const RECEIPT_SCHEMA_V2: &str = "semaprax.source-live-cli.repair-receipt.v2";
const CONFIG_SCHEMA_V1: &str = "semaprax.source-live-cli.repair-config.v1";
const CONFIG_SCHEMA_V2: &str = "semaprax.source-live-cli.repair-config.v2";
const MAX_ONE_PROVIDER_CALL_MS: i64 = 30_000;

use super::candidate_test::{
    candidate_test_bound_identity, candidate_test_evidence, candidate_test_subject,
    replayed_candidate_test_evidence,
};
pub(super) use super::candidate_test::{
    CandidateTestCapability, CandidateTestEvidence, CandidateTestHost, CandidateTestObservation,
    CandidateTestObservationError, CandidateTestObserver, CandidateTestStatus,
    CandidateTestSubject, ReplayedCandidateTestEvidence, CANDIDATE_TEST_SCHEMA,
    MAX_CANDIDATE_TEST_OBSERVATION_BYTES,
};

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
        FIXTURE_CLOCK_DOMAIN
    }
}

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
        UNIX_CLOCK_DOMAIN
    }
}

/// One scripted provider turn: the exact canonical proposal document the
/// fixture provider returns and whether it must observe the preceding checked
/// effect result in its prompt. The fixture never precomputes that result:
/// terminal recovery must be able to replay before any candidate preview is
/// derived from fixture-only inputs.
#[derive(Clone, Debug, Eq, PartialEq)]
struct RepairTurn {
    document: String,
    requires_prior_feedback: bool,
}

/// V1 is a deliberate local test seam. V2 is selected only by the explicit
/// OpenCode executable and empty scratch-directory operands; source/config
/// text cannot select a provider, endpoint, credential or publication route.
enum RepairProvider {
    Scripted([RepairTurn; 2]),
    OpenCode,
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
    provider: RepairProvider,
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
        const V1_KEYS: [&str; 24] = [
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
        const V2_KEYS: [&str; 23] = [
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
        ];
        let schema = text(map, "schema")?;
        let v1 = schema == CONFIG_SCHEMA_V1
            && map.len() == V1_KEYS.len()
            && V1_KEYS.iter().all(|key| map.contains_key(*key));
        let v2 = schema == CONFIG_SCHEMA_V2
            && map.len() == V2_KEYS.len()
            && V2_KEYS.iter().all(|key| map.contains_key(*key));
        if !v1 && !v2 {
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
        // These V1 fixture-only fields remain syntactically validated to keep
        // its frozen configuration key set, but candidate feedback now comes
        // from the live handler's actual preceding effect result.
        let _ = signed_i64(map, "malformed_replacement")?;
        let _ = map
            .get("malformed_bool_literal")
            .and_then(Value::as_bool)
            .ok_or(CliError::refused("malformed_bool_literal must be boolean"))?;
        let provider = if v1 {
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
            RepairProvider::Scripted([turn(first)?, turn(second)?])
        } else {
            RepairProvider::OpenCode
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
            provider,
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
        provider: Option<OpenCodeOperands>,
    },
    Resume {
        config: PathBuf,
        checkpoint: PathBuf,
        provider: Option<OpenCodeOperands>,
    },
}

pub(super) struct OpenCodeOperands {
    executable: PathBuf,
    scratch: PathBuf,
}

impl Command {
    pub(super) fn parse(arguments: &[String]) -> Result<Self, CliError> {
        let (verb, config, checkpoint, provider) = match arguments {
            [verb, config, checkpoint] => (verb, config, checkpoint, None),
            [verb, config, checkpoint, executable_flag, executable, scratch_flag, scratch]
                if executable_flag == "--opencode" && scratch_flag == "--scratch" =>
            {
                (
                    verb,
                    config,
                    checkpoint,
                    Some(OpenCodeOperands {
                        executable: absolute_operand(executable)?,
                        scratch: absolute_operand(scratch)?,
                    }),
                )
            }
            _ => {
                return Err(CliError::usage(
                    "repair requires run|resume <config.json> <checkpoint-dir> [--opencode ABS --scratch EMPTY_ABS]",
                ));
            }
        };
        let config = absolute_operand(config)?;
        let checkpoint = absolute_operand(checkpoint)?;
        match verb.as_str() {
            "run" => Ok(Self::Run {
                config,
                checkpoint,
                provider,
            }),
            "resume" => Ok(Self::Resume {
                config,
                checkpoint,
                provider,
            }),
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

fn scripted_identity() -> SourceModelAdapterIdentity {
    SourceModelAdapterIdentity {
        provider_id: "fake.local".to_owned(),
        model_id: "fake-basic".to_owned(),
        adapter_identity: "scripted-streaming-adapter".to_owned(),
        adapter_version: "1.0.0".to_owned(),
        provider_profile: "fixture".to_owned(),
    }
}

/// Source Agent model rows carry the provider and model as separate fields.
/// The fixed OpenCode command model is provider-qualified, so retain that
/// qualification for the host adapter while binding only its exact model
/// component to the checked source deployment.
fn source_deployment_identity(
    mut identity: SourceModelAdapterIdentity,
) -> Result<SourceModelAdapterIdentity, CliError> {
    identity.model_id = identity
        .model_id
        .strip_prefix("opencode/")
        .filter(|model| !model.is_empty())
        .map(str::to_owned)
        .ok_or(CliError::refused(
            "repair OpenCode model identity is not provider-qualified",
        ))?;
    Ok(identity)
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
    clock_domain: &str,
) -> SourceLivePolicy {
    SourceLivePolicy {
        deployment_binding: deployment_binding.to_owned(),
        response_limit,
        ceiling: config.ceiling,
        reservation_units: config.reservation_units,
        unit: "semaprax.source-live-cli.repair-unit.v1".to_owned(),
        clock_domain: clock_domain.to_owned(),
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

struct FeedbackGuardedAdapter {
    inner: ScriptedStreamingAdapter,
    starts: Rc<Cell<usize>>,
    requires_prior_feedback: bool,
    expected_feedback: Rc<RefCell<Option<String>>>,
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
        if self.requires_prior_feedback {
            let observed = serde_json::from_slice::<Value>(&request.request_bytes)
                .ok()
                .and_then(|prompt| {
                    prompt["previous_effect_hex"]
                        .as_str()
                        .map(ToOwned::to_owned)
                });
            let expected = self.expected_feedback.borrow();
            if expected.is_none() || observed.as_deref() != expected.as_deref() {
                return Err(AdapterRefusal(
                    "repair correction omitted checked diagnostic feedback".to_owned(),
                ));
            }
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

/// Captures the canonical bytes returned by the actual effect handler so the
/// scripted corrective turn can verify the runtime's preceding observation.
/// This is populated only after recovery has admitted and dispatched an
/// effect; it never previews a fixture candidate to manufacture feedback.
struct FeedbackRecordingHandler<'host, 'observer> {
    inner: OfflineRepairHandler,
    preceding_effect_hex: Rc<RefCell<Option<String>>>,
    source_revision: String,
    candidate_test: Option<&'host mut CandidateTestHost<'observer>>,
    candidate_test_evidence: Option<CandidateTestEvidence>,
    candidate_test_refused: bool,
}

impl FeedbackRecordingHandler<'_, '_> {
    fn latest_preview(&self) -> Option<&semaprax::agent_runtime_v2::OfflineRepairPreview> {
        self.inner.latest_preview()
    }

    fn rejection_count(&self) -> u32 {
        self.inner.rejection_count()
    }

    fn candidate_test_evidence(&self) -> Option<&CandidateTestEvidence> {
        self.candidate_test_evidence.as_ref()
    }

    fn candidate_test_refused(&self) -> bool {
        self.candidate_test_refused
    }
}

impl TypedEffectHandler for FeedbackRecordingHandler<'_, '_> {
    fn execute(
        &mut self,
        request: &TypedEffectRequest<'_>,
    ) -> Option<Vec<(String, RetainedValue)>> {
        let mut result = self.inner.execute(request)?;
        if let (Some(candidate_test), Some(preview)) = (
            self.candidate_test.as_deref_mut(),
            self.inner.latest_preview(),
        ) {
            let subject =
                candidate_test_subject(&candidate_test.capability, preview, &self.source_revision);
            let observation = match candidate_test.observe(&subject) {
                Ok(observation) => observation,
                Err(_) => {
                    self.candidate_test_refused = true;
                    return None;
                }
            };
            let evidence = match candidate_test_evidence(observation, &subject) {
                Ok(evidence) => evidence,
                Err(()) => {
                    self.candidate_test_refused = true;
                    return None;
                }
            };
            let [(result_id, RetainedValue::I64(_))] = result.as_slice() else {
                return None;
            };
            result = vec![(
                result_id.clone(),
                RetainedValue::I64(evidence.feedback_code),
            )];
            self.candidate_test_evidence = Some(evidence);
        }
        *self.preceding_effect_hex.borrow_mut() = Some(canonical_effect_hex(&result));
        Some(result)
    }
}

fn canonical_effect_hex(fields: &[(String, RetainedValue)]) -> String {
    let rows = fields
        .iter()
        .map(|(id, value)| {
            format!(
                "[{},{}]",
                serde_json::to_string(id).expect("effect result identifiers are strings"),
                canonical_retained_value_json(value)
            )
        })
        .collect::<Vec<_>>();
    format!(
        "{{\"schema\":\"semaprax.agent-effect-fields.v1\",\"fields\":[{}]}}\n",
        rows.join(",")
    )
    .bytes()
    .map(|byte| format!("{byte:02x}"))
    .collect()
}

/// One runner instance can serve successive fresh adapter instances while the
/// SDK preserves the one-start-per-adapter rule. The shared cell is private to
/// one CLI traversal and is never checkpointed; the journal, not this handle,
/// decides whether recovery may dispatch again.
struct SharedRunner<R>(Rc<RefCell<R>>);

impl<R: OpenCodeRunner> OpenCodeRunner for SharedRunner<R> {
    fn run(
        &mut self,
        config: &OpenCodeHostConfig,
        prompt: &str,
    ) -> Result<Vec<u8>, crate::opencode_host::OpenCodeRunnerFailure> {
        self.0.borrow_mut().run(config, prompt)
    }

    fn export(
        &mut self,
        config: &OpenCodeHostConfig,
        session: &str,
    ) -> Result<Vec<u8>, crate::opencode_host::OpenCodeRunnerFailure> {
        self.0.borrow_mut().export(config, session)
    }

    fn cancelled(&self, config: &OpenCodeHostConfig) -> bool {
        self.0.borrow().cancelled(config)
    }
}

pub(super) fn run(arguments: &[String]) -> Result<String, CliError> {
    execute_with_runner(Command::parse(arguments)?, ProcessOpenCodeRunner)
}

fn execute_with_runner<R: OpenCodeRunner + 'static>(
    command: Command,
    runner: R,
) -> Result<String, CliError> {
    execute_with_runner_and_candidate_test(command, runner, None)
}

/// Private embedding seam for an already-selected candidate-test capability.
pub(super) fn execute_with_runner_and_candidate_test<
    'host,
    'observer,
    R: OpenCodeRunner + 'static,
>(
    command: Command,
    runner: R,
    mut candidate_test: Option<&'host mut CandidateTestHost<'observer>>,
) -> Result<String, CliError> {
    let candidate_test_selected = candidate_test.is_some();
    let (config_path, checkpoint_path, fresh, provider_operands) = match command {
        Command::Run {
            config,
            checkpoint,
            provider,
        } => (config, checkpoint, true, provider),
        Command::Resume {
            config,
            checkpoint,
            provider,
        } => (config, checkpoint, false, provider),
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
    if candidate_test.is_some() && !matches!(&config.provider, RepairProvider::OpenCode) {
        return Err(CliError::refused(
            "candidate-test capability requires OpenCode repair configuration",
        ));
    }
    let (adapter_identity, clock, process_adapter_identity): (
        _,
        Box<dyn SourceInvocationClock>,
        Option<String>,
    ) = match &config.provider {
        RepairProvider::Scripted(_) if provider_operands.is_none() => {
            (scripted_identity(), Box::new(FixedClock), None)
        }
        RepairProvider::Scripted(_) => {
            return Err(CliError::usage(
                "repair fixture configuration does not accept OpenCode operands",
            ));
        }
        RepairProvider::OpenCode if provider_operands.is_some() => {
            let operands = provider_operands
                .as_ref()
                .expect("provider operands were checked");
            let executable = operands
                .executable
                .canonicalize()
                .map_err(|_| CliError::refused("repair OpenCode executable is unavailable"))?;
            let scratch = operands
                .scratch
                .canonicalize()
                .map_err(|_| CliError::refused("repair OpenCode scratch is unavailable"))?;
            let process_identity = source_model_identity(&executable, &scratch);
            let process_adapter_identity = process_identity.adapter_identity.clone();
            (
                candidate_test_bound_identity(
                    source_deployment_identity(process_identity)?,
                    candidate_test.as_deref().map(|host| &host.capability),
                    &config.target,
                    source.source_revision(),
                ),
                Box::new(UnixClock),
                Some(process_adapter_identity),
            )
        }
        RepairProvider::OpenCode => {
            return Err(CliError::usage(
                "repair OpenCode configuration requires --opencode ABS --scratch EMPTY_ABS",
            ));
        }
    };
    let bound_adapter_identity = adapter_identity.adapter_identity.clone();
    let model_binding = runtime
        .source_model_binding(adapter_identity)
        .map_err(|diagnostics| {
            diagnostic_error("repair source model binding refused", diagnostics)
        })?;
    let source_policy = policy(
        &config,
        model_binding.digest(),
        model_binding.max_response_bytes(),
        clock.clock_domain(),
    );

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

    let envelope = OfflineRepairEnvelope::new(Arc::clone(&project), config.target.clone())
        .map_err(|diagnostics| diagnostic_error("repair target envelope refused", diagnostics))?;
    let preceding_effect_hex = Rc::new(RefCell::new(None));
    let mut handler = FeedbackRecordingHandler {
        inner: OfflineRepairHandler::new(
            envelope,
            config.malformed_operation_id.clone(),
            config.corrected_operation_id.clone(),
            config.effect_id.clone(),
            config.argument_id.clone(),
            config.result_id.clone(),
        )
        .map_err(|diagnostics| diagnostic_error("repair effect contract refused", diagnostics))?,
        preceding_effect_hex: Rc::clone(&preceding_effect_hex),
        source_revision: source.source_revision().to_owned(),
        candidate_test: candidate_test.take(),
        candidate_test_evidence: None,
        candidate_test_refused: false,
    };

    let mut scripted_starts = None;
    let mut factory: Box<dyn FnMut() -> Box<dyn ProviderAdapter>> = match &config.provider {
        RepairProvider::Scripted(turns) => {
            let scripts = RefCell::new(VecDeque::from(
                turns
                    .clone()
                    .map(|turn| (turn.document, turn.requires_prior_feedback)),
            ));
            let starts = Rc::new(Cell::new(0));
            scripted_starts = Some((Rc::clone(&starts), turns.len()));
            Box::new(move || -> Box<dyn ProviderAdapter> {
                let next = scripts.borrow_mut().pop_front();
                let refuse_start = next.is_none();
                let (document, requires_prior_feedback) =
                    next.unwrap_or_else(|| (String::new(), false));
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
                    starts: Rc::clone(&starts),
                    requires_prior_feedback,
                    expected_feedback: Rc::clone(&preceding_effect_hex),
                    refuse_start,
                })
            })
        }
        RepairProvider::OpenCode => {
            let operands = provider_operands.expect("OpenCode operands were checked above");
            let grammar = OpenCodeGrammar::from_proposal(compiled.proposal_schema())
                .map_err(|_| CliError::refused("repair OpenCode grammar admission refused"))?;
            let remaining = config.deadline_millis.saturating_sub(clock.now_millis());
            let call_millis = remaining.clamp(1, MAX_ONE_PROVIDER_CALL_MS) as u64;
            let host = OpenCodeHostConfig::new(
                operands.executable,
                operands.scratch,
                Duration::from_millis(call_millis),
                grammar,
            )
            .map_err(|_| CliError::refused("repair OpenCode host configuration refused"))?;
            if process_adapter_identity.as_deref()
                != Some(
                    source_model_identity_for_config(&host)
                        .adapter_identity
                        .as_str(),
                )
            {
                return Err(CliError::refused(
                    "repair OpenCode executable changed while binding the host",
                ));
            }
            let runner = Rc::new(RefCell::new(runner));
            let bound_adapter_identity = bound_adapter_identity.clone();
            Box::new(move || -> Box<dyn ProviderAdapter> {
                Box::new(OpenCodeRepairAdapter::new_with_adapter_identity(
                    host.clone(),
                    SharedRunner(Rc::clone(&runner)),
                    bound_adapter_identity.clone(),
                ))
            })
        }
    };
    let cancellation = AgentCancellation::new();
    let mut source = StreamingSourceProposalAdapter::new_bound_checkpointed(
        &mut factory,
        AdapterInvocationCapability::grant("source-live repair host-selected provider"),
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
            clock.as_ref(),
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

    if handler.candidate_test_refused() {
        return Err(CliError::refused(
            "repair candidate-test observation was refused",
        ));
    }

    let model_dispatches = complete.run().model_dispatches;
    let effect_dispatches = complete.run().effect_dispatches;
    // A pure terminal-checkpoint replay dispatches nothing. Fixture mode also
    // proves its complete fixed sequence was consumed; OpenCode mode instead
    // relies on the retained journal's acknowledged intent/settlement chain.
    if let Some((starts, turns)) = scripted_starts {
        if model_dispatches > 0 && starts.get() != turns {
            return Err(CliError::refused(
                "repair preview did not consume its exact scripted turn sequence",
            ));
        }
    }
    if std::fs::read(&source_disk_path)
        .map_err(|_| CliError::refused("repair source cannot be reread"))?
        != source_before
    {
        return Err(CliError::refused("repair source changed during execution"));
    }

    let preview = handler.latest_preview();
    let rejection_count = handler.rejection_count();
    let candidate_test_evidence = handler.candidate_test_evidence();
    let replayed_candidate_test_evidence = if fresh {
        None
    } else {
        replayed_candidate_test_evidence(
            &complete.run().checkpoint,
            &config.corrected_operation_id,
            &config.result_id,
            candidate_test_selected,
        )
    };
    receipt_with_preview(
        &config,
        preview,
        rejection_count,
        candidate_test_evidence,
        replayed_candidate_test_evidence,
        candidate_test_selected,
        &complete.run().checkpoint,
        model_dispatches,
        effect_dispatches,
    )
}

fn receipt(
    config: &RepairConfig,
    preview: Option<&semaprax::agent_runtime_v2::OfflineRepairPreview>,
    candidate_test_evidence: Option<&CandidateTestEvidence>,
    replayed_candidate_test_evidence: Option<ReplayedCandidateTestEvidence>,
    candidate_test_selected: bool,
    checkpoint: &semaprax::live_invocation::source_journal::RecoveredSourceCheckpoint,
    model_dispatches: u32,
    effect_dispatches: u32,
) -> Result<String, CliError> {
    let terminal = checkpoint.terminal_snapshot().ok_or(CliError::refused(
        "repair checkpoint has no terminal snapshot",
    ))?;
    let mut report = json!({
        "schema": RECEIPT_SCHEMA_V1,
        "target": config.target,
        "status": terminal.status().as_str(),
        "generation": checkpoint.generation(),
        "model_dispatches": model_dispatches,
        "effect_dispatches": effect_dispatches,
        "source_mutation": false,
        "publication_authority": false,
    });
    if matches!(&config.provider, RepairProvider::OpenCode) {
        report["schema"] = json!(RECEIPT_SCHEMA_V2);
        report["journal_binding"] = json!({
            "invocation": checkpoint.invocation(),
            "chain": checkpoint.chain(),
            "generation": checkpoint.generation(),
        });
        report["candidate_test_execution"] =
            match (candidate_test_evidence, replayed_candidate_test_evidence) {
                (Some(evidence), None) => json!({
                    "schema": CANDIDATE_TEST_SCHEMA,
                    "status": evidence.status.text(),
                    "feedback_code": evidence.feedback_code,
                    "replayed": false,
                    "observation": checked_value(
                        &evidence.canonical,
                        "repair candidate-test observation refused",
                    )?,
                }),
                (None, Some(evidence)) => json!({
                    "schema": CANDIDATE_TEST_SCHEMA,
                    "status": evidence.status.text(),
                    "feedback_code": evidence.feedback_code,
                    "replayed": true,
                    "observation": Value::Null,
                }),
                (None, None) => json!({
                    "status": "not_run",
                    "reason": if candidate_test_selected {
                        "no settled candidate-test observation is available"
                    } else {
                        "this repair host has no candidate test-execution authority"
                    },
                }),
                (Some(_), Some(_)) => {
                    return Err(CliError::refused(
                        "repair candidate-test receipt has conflicting observations",
                    ))
                }
            };
    }
    if let Some(preview) = preview {
        report["candidate_digest"] = json!(preview.candidate().candidate_digest());
        report["source_review"] =
            checked_value(preview.source_review(), "repair source review refused")?;
        report["semantic_delta"] =
            checked_value(preview.semantic_delta(), "repair semantic delta refused")?;
        report["impact_summary"] =
            checked_value(preview.impact_summary(), "repair impact summary refused")?;
        if matches!(&config.provider, RepairProvider::OpenCode) {
            let candidate_test_ran =
                candidate_test_evidence.is_some() || replayed_candidate_test_evidence.is_some();
            let mut blind_spots = vec![
                Value::String(
                    "no publication, Git mutation, or physical delivery is authorized by this receipt"
                        .to_owned(),
                ),
                Value::String(
                    "provider usage is an observation, not cost or delivery proof".to_owned(),
                ),
            ];
            if !candidate_test_ran {
                blind_spots.insert(0, Value::String(if candidate_test_selected {
                    "candidate tests were not observed: no settled candidate-test observation is available"
                        .to_owned()
                } else {
                    "candidate tests were not executed: this host has no test-execution authority"
                        .to_owned()
                }));
            } else if replayed_candidate_test_evidence.is_some() {
                blind_spots.insert(
                    0,
                    Value::String(
                        "candidate-test observation is replayed from the durable journal; no new test was executed"
                            .to_owned(),
                    ),
                );
            }
            report["analysis"] = json!({
                "coverage": {
                    "source_review": true,
                    "semantic_delta": true,
                    "impact_summary": true,
                    "candidate_test_execution": candidate_test_ran,
                },
                "blind_spots": blind_spots,
            });
        }
    } else {
        report["candidate_digest"] = Value::Null;
        report["source_review"] = Value::Null;
        report["semantic_delta"] = Value::Null;
        report["impact_summary"] = Value::Null;
        if matches!(&config.provider, RepairProvider::OpenCode) {
            let replayed_candidate_test = replayed_candidate_test_evidence.is_some();
            report["analysis"] = json!({
                "coverage": {
                    "source_review": false,
                    "semantic_delta": false,
                    "impact_summary": false,
                    "candidate_test_execution": replayed_candidate_test,
                },
                "blind_spots": [
                    "terminal checkpoint replay did not create or revalidate a candidate",
                    if replayed_candidate_test_evidence.is_some() {
                        "candidate-test observation is replayed from the durable journal; no new test was executed"
                    } else if candidate_test_selected {
                        "no settled candidate-test observation is available"
                    } else {
                        "candidate tests were not executed: this host has no test-execution authority"
                    },
                    "no publication, Git mutation, or physical delivery is authorized by this receipt",
                ],
            });
        }
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
    candidate_test_evidence: Option<&CandidateTestEvidence>,
    replayed_candidate_test_evidence: Option<ReplayedCandidateTestEvidence>,
    candidate_test_selected: bool,
    checkpoint: &semaprax::live_invocation::source_journal::RecoveredSourceCheckpoint,
    model_dispatches: u32,
    effect_dispatches: u32,
) -> Result<String, CliError> {
    let base = receipt(
        config,
        preview,
        candidate_test_evidence,
        replayed_candidate_test_evidence,
        candidate_test_selected,
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
