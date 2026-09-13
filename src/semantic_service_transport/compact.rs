//! Retained-generation compact-projection service route.
//!
//! This route only selects existing compact projection kernels.  A source
//! label is matched against exact source bytes already retained in the selected
//! service generation; it never names a host path or contributes source bytes.

use std::sync::Arc;

use serde_json::{json, Map, Value};

use crate::compact_semantic_projection::{
    encode_bytes, encode_profile, encode_selected, CompactProjection, ProjectionSelection,
    ProjectionSource, MAX_ENCODED_BYTES,
};
use crate::graph::{AgentContextDirection, AgentContextFilter, AgentContextV2Options};
use crate::project::{
    ProjectCandidate, ProjectRevision, SemanticWorkspaceService,
    MAX_PROJECT_CANDIDATE_RECOVERY_BYTES,
};
use crate::semantic_task_context::{CompilationBudget, CompilationGoal, CompilationSeed};

use super::{capacity, invalid, Result};

const PROFILE_FULL_GRAPH: &str = "full-graph";
const PROFILE_AGENT_CONTEXT: &str = "agent-context-v2";
const PROFILE_TASK_CONTEXT: &str = "task-context-v1";
const PROFILE_API_SURFACE: &str = "api-surface-v8-owned-data";
const PROFILE_CANDIDATE_DIFF: &str = "candidate-semantic-delta-catalog";
const PROFILE_AGENT_DEFINITION: &str = "agent-definition-graph";
const MAX_SELECTOR_BYTES: usize = 4096;

/// Select and encode one compact projection from the exact active generation.
pub(super) fn project(
    service: &SemanticWorkspaceService,
    params: Option<Map<String, Value>>,
) -> Result<Value> {
    let mut params = compact_params(params)?;
    let expected = required(&mut params, "expected_workspace_revision")?;
    // Bind before parsing, recovery, or any selected-kernel work.
    let snapshot = service.snapshot(&expected)?;
    let profile = required(&mut params, "profile")?;
    let encoding = required(&mut params, "encoding")?;
    if !matches!(encoding.as_str(), "text" | "binary" | "model-text") {
        return Err(invalid(
            "compact projection encoding must be text, binary or model-text",
        ));
    }
    let source_path = optional(&mut params, "source_path")?;
    let root = optional(&mut params, "root")?;
    let candidate_capsule = optional(&mut params, "candidate_capsule")?;
    let agent_id = optional(&mut params, "agent_id")?;

    let projection = match profile.as_str() {
        PROFILE_FULL_GRAPH => {
            reject_irrelevant(&root, &candidate_capsule, &agent_id)?;
            if let Some(source_path) = source_path.as_deref() {
                let program =
                    retained_program(snapshot.generation().revision(), Some(source_path))?;
                encode_profile(&program, ProjectionSource::FullGraph)?
            } else {
                let revision = snapshot.generation().revision();
                encode_bytes(
                    revision.semantic_graph().as_bytes(),
                    PROFILE_FULL_GRAPH,
                    "*",
                    revision.project_revision(),
                )
                .map_err(|error| vec![error])?
            }
        }
        PROFILE_AGENT_CONTEXT => {
            reject_irrelevant(&candidate_capsule, &None, &agent_id)?;
            let root = root.ok_or_else(|| invalid("agent-context-v2 requires root"))?;
            let program =
                retained_program(snapshot.generation().revision(), source_path.as_deref())?;
            let options = context_options()?;
            encode_profile(
                &program,
                ProjectionSource::AgentContextV2 {
                    symbol: &root,
                    options: &options,
                },
            )?
        }
        PROFILE_TASK_CONTEXT => {
            reject_irrelevant(&candidate_capsule, &None, &agent_id)?;
            let root = root.ok_or_else(|| invalid("task-context-v1 requires root"))?;
            let program =
                retained_program(snapshot.generation().revision(), source_path.as_deref())?;
            let options = context_options()?;
            let goal = CompilationGoal::new(vec![CompilationSeed::new(root, 1, "service")])
                .map_err(|error| vec![error])?;
            let budget =
                CompilationBudget::new(64 * 1024, "byte-v1").map_err(|error| vec![error])?;
            encode_selected(ProjectionSelection::TaskContext {
                program: &program,
                goal: &goal,
                options: &options,
                budget,
            })?
        }
        PROFILE_API_SURFACE => {
            reject_all(source_path, root, candidate_capsule, agent_id)?;
            encode_selected(ProjectionSelection::ApiSurface {
                revision: snapshot.generation().revision(),
            })?
        }
        PROFILE_CANDIDATE_DIFF => {
            reject_irrelevant(&source_path, &root, &agent_id)?;
            let capsule = candidate_capsule.ok_or_else(|| {
                invalid("candidate-semantic-delta-catalog requires candidate_capsule")
            })?;
            if capsule.len() > MAX_PROJECT_CANDIDATE_RECOVERY_BYTES {
                return Err(capacity(
                    "candidate capsule exceeds compact route byte limit",
                ));
            }
            let base = Arc::clone(snapshot.generation().revision());
            let candidate = ProjectCandidate::restore(
                Arc::clone(&base),
                base.project_revision(),
                capsule.as_bytes(),
            )?;
            let digest = candidate.candidate_digest().to_owned();
            encode_selected(ProjectionSelection::CandidateDiff {
                candidate: &candidate,
                expected_candidate: &digest,
            })?
        }
        PROFILE_AGENT_DEFINITION => {
            reject_irrelevant(&source_path, &root, &candidate_capsule)?;
            let agent_id =
                agent_id.ok_or_else(|| invalid("agent-definition-graph requires agent_id"))?;
            let definition = snapshot
                .generation()
                .compiled_agent_definitions()
                .iter()
                .find(|definition| definition.definition().agent_id() == agent_id)
                .ok_or_else(|| invalid("agent definition does not exist in retained generation"))?;
            encode_selected(ProjectionSelection::AgentDefinition { definition })?
        }
        _ => return Err(invalid("unsupported compact projection profile")),
    };

    render(&projection, &encoding)
}

fn compact_params(params: Option<Map<String, Value>>) -> Result<Map<String, Value>> {
    const REQUIRED: &[&str] = &["expected_workspace_revision", "profile", "encoding"];
    const ALLOWED: &[&str] = &[
        "expected_workspace_revision",
        "profile",
        "encoding",
        "source_path",
        "root",
        "candidate_capsule",
        "agent_id",
    ];
    let params = params.ok_or_else(|| invalid("workspace/compact-projection requires params"))?;
    if params.keys().any(|key| !ALLOWED.contains(&key.as_str()))
        || REQUIRED.iter().any(|key| !params.contains_key(*key))
    {
        return Err(invalid(
            "compact projection params have missing or unknown members",
        ));
    }
    Ok(params)
}

fn required(params: &mut Map<String, Value>, key: &str) -> Result<String> {
    optional(params, key)?.ok_or_else(|| invalid("compact projection parameter is required"))
}

fn optional(params: &mut Map<String, Value>, key: &str) -> Result<Option<String>> {
    match params.remove(key) {
        None => Ok(None),
        Some(Value::String(value))
            if !value.is_empty()
                && !value.as_bytes().contains(&0)
                && (key == "candidate_capsule" || value.len() <= MAX_SELECTOR_BYTES) =>
        {
            Ok(Some(value))
        }
        _ => Err(invalid(
            "compact projection parameter must be a nonempty string without NUL bytes",
        )),
    }
}

fn reject_irrelevant(
    first: &Option<String>,
    second: &Option<String>,
    third: &Option<String>,
) -> Result<()> {
    if first.is_some() || second.is_some() || third.is_some() {
        Err(invalid(
            "compact projection profile received irrelevant selector",
        ))
    } else {
        Ok(())
    }
}

fn reject_all(
    source_path: Option<String>,
    root: Option<String>,
    candidate_capsule: Option<String>,
    agent_id: Option<String>,
) -> Result<()> {
    reject_irrelevant(&source_path, &root, &candidate_capsule)?;
    if agent_id.is_some() {
        Err(invalid(
            "compact projection profile received irrelevant selector",
        ))
    } else {
        Ok(())
    }
}

fn retained_program(
    revision: &ProjectRevision,
    source_path: Option<&str>,
) -> Result<crate::ast::Program> {
    let source_path =
        source_path.ok_or_else(|| invalid("compact source profile requires source_path"))?;
    let source = revision
        .sources()
        .iter()
        .find(|source| source.path() == source_path)
        .ok_or_else(|| invalid("source_path is not a retained Project source label"))?;
    crate::parse(source.source(), source.path()).map_err(|error| vec![error])
}

fn context_options() -> Result<AgentContextV2Options> {
    AgentContextV2Options::new(
        1,
        64 * 1024,
        256,
        [
            AgentContextFilter::Contracts,
            AgentContextFilter::Ownership,
            AgentContextFilter::Effects,
            AgentContextFilter::Types,
        ],
        AgentContextDirection::Forward,
    )
    .map_err(|error| vec![error])
}

fn render(projection: &CompactProjection, encoding: &str) -> Result<Value> {
    let encoded = match encoding {
        "model-text" => crate::compact_semantic_projection::encode_model_text(projection)
            .map_err(|error| vec![error])?,
        "text" => {
            let text = projection.to_text();
            if text.len() > MAX_ENCODED_BYTES {
                return Err(capacity(
                    "compact projection text result exceeds route byte limit",
                ));
            }
            text
        }
        "binary" => {
            let bytes = projection.to_binary();
            if bytes.len() > MAX_ENCODED_BYTES {
                return Err(capacity(
                    "compact projection binary result exceeds route byte limit",
                ));
            }
            hex(&bytes)
        }
        _ => unreachable!("encoding is admitted before selected-kernel work"),
    };
    Ok(json!({
        "authority": false,
        "encoding": encoding,
        "format_version": if encoding == "model-text" { crate::compact_semantic_projection::MODEL_TEXT_FORMAT_VERSION } else { crate::compact_semantic_projection::FORMAT_VERSION },
        "profile": projection.profile(),
        "root": projection.root(),
        "source_digest": projection.source_digest(),
        "source_revision": projection.source_revision(),
        "value": encoded,
    }))
}

fn hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut text = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        text.push(HEX[(byte >> 4) as usize] as char);
        text.push(HEX[(byte & 0x0f) as usize] as char);
    }
    text
}
