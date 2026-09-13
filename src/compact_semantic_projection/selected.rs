//! Authoritative selected-view profiles for Compact Semantic Projection v1.
//!
//! Unlike the compatible `ProjectionSource` inputs, these profiles take the
//! retained object that owns selection and regenerate it during replay.

use crate::agent_definition::CompiledAgentDefinition;
use crate::diagnostic::Diagnostic;
use crate::graph;
use crate::project::{ProjectCandidate, ProjectRevision};
use crate::semantic_task_context::{self, CompilationBudget, CompilationGoal};

use super::{decode_binary_and_verify, decode_text_and_verify, encode_bytes, CompactProjection};

fn replay_mismatch() -> Diagnostic {
    Diagnostic::io(
        "SPX-Z910",
        "compact semantic projection does not equal freshly regenerated selected content",
    )
}

/// One authoritative selection source. Each variant names the existing kernel
/// that owns its semantics; this module only compacts its canonical bytes.
pub enum ProjectionSelection<'a> {
    TaskContext {
        program: &'a crate::ast::Program,
        goal: &'a CompilationGoal,
        options: &'a crate::graph::AgentContextV2Options,
        budget: CompilationBudget,
    },
    /// Exactly the Project v8 owned-data descriptor; no broader Project view.
    ApiSurface { revision: &'a ProjectRevision },
    CandidateDiff {
        candidate: &'a ProjectCandidate,
        expected_candidate: &'a str,
    },
    AgentDefinition {
        definition: &'a CompiledAgentDefinition,
    },
}

impl ProjectionSelection<'_> {
    fn selected(&self) -> Result<(String, String, String, Vec<u8>), Vec<Diagnostic>> {
        match self {
            Self::TaskContext {
                program,
                goal,
                options,
                budget,
            } => Ok((
                "task-context-v1".to_owned(),
                "goal".to_owned(),
                graph::revision(program),
                semantic_task_context::compile(program, goal, options, *budget)?.into_bytes(),
            )),
            Self::ApiSurface { revision } => {
                let descriptor = revision.public_api_descriptor()?;
                Ok((
                    "api-surface-v8-owned-data".to_owned(),
                    "public-api".to_owned(),
                    revision.project_revision().to_owned(),
                    descriptor.canonical_bytes(),
                ))
            }
            Self::CandidateDiff {
                candidate,
                expected_candidate,
            } => Ok((
                "candidate-semantic-delta-catalog".to_owned(),
                (*expected_candidate).to_owned(),
                candidate.revision().project_revision().to_owned(),
                candidate
                    .semantic_delta_catalog(expected_candidate)?
                    .into_bytes(),
            )),
            Self::AgentDefinition { definition } => Ok((
                "agent-definition-graph".to_owned(),
                definition.definition().agent_id().to_owned(),
                definition.graph().digest().to_owned(),
                definition.graph().canonical_json().as_bytes().to_vec(),
            )),
        }
    }
}

/// Compact one freshly selected authoritative profile.
pub fn encode_selected(
    selection: ProjectionSelection<'_>,
) -> Result<CompactProjection, Vec<Diagnostic>> {
    let (profile, root, revision, bytes) = selection.selected()?;
    encode_bytes(&bytes, &profile, &root, &revision).map_err(|error| vec![error])
}

/// Decode text and prove it equals a fresh invocation of the selected kernel.
pub fn replay_selected_text(
    selection: ProjectionSelection<'_>,
    text: &str,
) -> Result<CompactProjection, Vec<Diagnostic>> {
    replay_selected(selection, |expected| {
        decode_text_and_verify(
            text,
            expected.profile(),
            expected.root(),
            expected.source_revision(),
        )
    })
}

/// Binary counterpart of [`replay_selected_text`].
pub fn replay_selected_binary(
    selection: ProjectionSelection<'_>,
    bytes: &[u8],
) -> Result<CompactProjection, Vec<Diagnostic>> {
    replay_selected(selection, |expected| {
        decode_binary_and_verify(
            bytes,
            expected.profile(),
            expected.root(),
            expected.source_revision(),
        )
    })
}

fn replay_selected(
    selection: ProjectionSelection<'_>,
    decode: impl FnOnce(&CompactProjection) -> Result<CompactProjection, Diagnostic>,
) -> Result<CompactProjection, Vec<Diagnostic>> {
    let expected = encode_selected(selection)?;
    let replayed = decode(&expected).map_err(|error| vec![error])?;
    if replayed.reconstructed().map_err(|error| vec![error])?
        != expected.reconstructed().map_err(|error| vec![error])?
    {
        return Err(vec![replay_mismatch()]);
    }
    Ok(replayed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent_definition::compile_agent_definition;
    use crate::graph::{AgentContextDirection, AgentContextFilter, AgentContextV2Options};
    use crate::project::{
        ProjectCandidate, ProjectFrontendCache, ProjectFrontendSource, ProjectManifest,
    };
    use crate::semantic_task_context::{CompilationGoal, CompilationSeed};
    use std::sync::Arc;

    const SOURCE: &str = "module compact.selected;\n\n@id(\"selected.helper\")\nfn helper(value: i64) -> i64 { value }\n\n@id(\"selected.main\")\nfn main() -> i64 { helper(1) }\n";

    fn options() -> AgentContextV2Options {
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
        .unwrap()
    }

    fn goal() -> CompilationGoal {
        CompilationGoal::new(vec![CompilationSeed::new("selected.main", 1, "test")]).unwrap()
    }

    fn selection<'a>(
        program: &'a crate::ast::Program,
        goal: &'a CompilationGoal,
        options: &'a AgentContextV2Options,
    ) -> ProjectionSelection<'a> {
        ProjectionSelection::TaskContext {
            program,
            goal,
            options,
            budget: CompilationBudget::new(64 * 1024, "byte-v1").unwrap(),
        }
    }

    fn project_revision() -> Arc<ProjectRevision> {
        let manifest = ProjectManifest::parse(include_str!(
            "../../examples/frame-payload-project/semaprax.toml"
        ))
        .unwrap();
        let sources = [
            (
                "src/app.spx",
                include_str!("../../examples/frame-payload-project/src/app.spx"),
            ),
            (
                "src/frame.spx",
                include_str!("../../examples/frame-payload-project/src/frame.spx"),
            ),
            (
                "src/tests.spx",
                include_str!("../../examples/frame-payload-project/src/tests.spx"),
            ),
        ]
        .into_iter()
        .map(|(path, source)| ProjectFrontendSource::new(path, source).unwrap())
        .collect::<Vec<_>>();
        let mut cache = ProjectFrontendCache::new_with_semantic_cache();
        cache.build(&manifest, &sources).unwrap().into_revision()
    }

    #[test]
    fn task_context_replay_regenerates_the_authoritative_selected_content() {
        let program = crate::parse(SOURCE, "selected.spx").unwrap();
        let goal = goal();
        let options = options();
        let encoded = encode_selected(selection(&program, &goal, &options)).unwrap();
        let replayed =
            replay_selected_binary(selection(&program, &goal, &options), &encoded.to_binary())
                .unwrap();
        assert_eq!(
            replayed.reconstructed().unwrap(),
            encoded.reconstructed().unwrap()
        );
    }

    #[test]
    fn task_context_replay_refuses_a_stale_freshly_regenerated_revision() {
        let before = crate::parse(SOURCE, "selected.spx").unwrap();
        let after =
            crate::parse(&SOURCE.replace("helper(1)", "helper(2)"), "selected.spx").unwrap();
        let goal = goal();
        let options = options();
        let encoded = encode_selected(selection(&before, &goal, &options)).unwrap();
        let error = replay_selected_text(selection(&after, &goal, &options), &encoded.to_text())
            .unwrap_err();
        assert_eq!(error[0].code, "SPX-Z908");
    }

    #[test]
    fn self_rehashed_forged_content_with_the_same_binding_is_refused() {
        let program = crate::parse(SOURCE, "selected.spx").unwrap();
        let goal = goal();
        let options = options();
        let expected = encode_selected(selection(&program, &goal, &options)).unwrap();
        // This is a valid compact envelope whose own digest was freshly minted
        // for different JSON, while retaining every selected-profile header.
        // Header/digest verification alone would accept it; regeneration must
        // reject it against the actual task-context compiler output.
        let forged = encode_bytes(
            br#"{"forged":true}"#,
            expected.profile(),
            expected.root(),
            expected.source_revision(),
        )
        .unwrap();
        let error =
            replay_selected_binary(selection(&program, &goal, &options), &forged.to_binary())
                .unwrap_err();
        assert_eq!(error[0].code, "SPX-Z910");
    }

    #[test]
    fn api_surface_and_candidate_diff_profiles_replay_their_authoritative_project_bytes() {
        let revision = project_revision();
        let api = encode_selected(ProjectionSelection::ApiSurface {
            revision: &revision,
        })
        .unwrap();
        let api_replayed = replay_selected_binary(
            ProjectionSelection::ApiSurface {
                revision: &revision,
            },
            &api.to_binary(),
        )
        .unwrap();
        assert_eq!(
            api_replayed.reconstructed().unwrap(),
            api.reconstructed().unwrap()
        );

        let candidate =
            ProjectCandidate::open(Arc::clone(&revision), revision.project_revision()).unwrap();
        let expected = candidate.candidate_digest().to_owned();
        let diff = encode_selected(ProjectionSelection::CandidateDiff {
            candidate: &candidate,
            expected_candidate: &expected,
        })
        .unwrap();
        let diff_replayed = replay_selected_text(
            ProjectionSelection::CandidateDiff {
                candidate: &candidate,
                expected_candidate: &expected,
            },
            &diff.to_text(),
        )
        .unwrap();
        assert_eq!(
            diff_replayed.reconstructed().unwrap(),
            diff.reconstructed().unwrap()
        );
    }

    #[test]
    fn agent_definition_profile_replays_the_compiler_derived_graph() {
        let definition =
            compile_agent_definition(crate::streaming_proposal_decode::source::tests::DEFINITION)
                .unwrap();
        let encoded = encode_selected(ProjectionSelection::AgentDefinition {
            definition: &definition,
        })
        .unwrap();
        let replayed = replay_selected_text(
            ProjectionSelection::AgentDefinition {
                definition: &definition,
            },
            &encoded.to_text(),
        )
        .unwrap();
        assert_eq!(
            replayed.reconstructed().unwrap(),
            definition.graph().canonical_json().as_bytes()
        );
    }
}
