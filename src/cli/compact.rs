//! Compact projections are read-only views; replay always regenerates selection.
use semaprax::compact_semantic_projection::{
    self as compact, CompactProjection, ProjectionSelection, ProjectionSource,
};
use semaprax::diagnostic::Diagnostic;
use semaprax::graph::{AgentContextDirection, AgentContextFilter, AgentContextV2Options};
use semaprax::project::{with_authenticated_project, ProjectCandidate};
use semaprax::semantic_task_context::{CompilationBudget, CompilationGoal, CompilationSeed};
use std::path::{Path, PathBuf};

pub(crate) struct Options {
    profile: String,
    input: PathBuf,
    selection: Option<String>,
    encoding: compact::negotiation::ProjectionEncoding,
    replay: Option<PathBuf>,
    max_bytes: usize,
    max_tokens: usize,
}

pub(crate) fn parse(args: &[String]) -> Result<Options, u8> {
    parse_inner(args).map_err(|message| {
        eprintln!("compact: {message}");
        2
    })
}
fn parse_inner(args: &[String]) -> Result<Options, &'static str> {
    let [profile, input, rest @ ..] = args else {
        return Err("requires <profile> <input> [selection] [options]");
    };
    let needs_selection = match profile.as_str() {
        "context" | "task-context" | "candidate-diff" => true,
        "graph" | "api-surface" | "agent-definition" => false,
        _ => return Err("unknown profile"),
    };
    if input.is_empty() || input.starts_with('-') {
        return Err("input must be an explicit path");
    }
    let (selection, rest) = if needs_selection {
        let [selection, rest @ ..] = rest else {
            return Err("profile requires a stable ID or candidate capsule path");
        };
        if selection.is_empty() || selection.starts_with('-') {
            return Err("missing profile selection");
        }
        (Some(selection.clone()), rest)
    } else {
        (None, rest)
    };
    let mut options = Options {
        profile: profile.clone(),
        input: input.into(),
        selection,
        encoding: compact::negotiation::ProjectionEncoding::Text,
        replay: None,
        max_bytes: 65_536,
        max_tokens: 65_536,
    };
    let mut seen = std::collections::BTreeSet::new();
    let mut chunks = rest.chunks_exact(2);
    for pair in &mut chunks {
        if !seen.insert(pair[0].as_str()) {
            return Err("duplicate option");
        }
        match pair[0].as_str() {
            "--encoding" => {
                options.encoding = match pair[1].as_str() {
                    "text" => compact::negotiation::ProjectionEncoding::Text,
                    "binary" => compact::negotiation::ProjectionEncoding::Binary,
                    "model-text" => compact::negotiation::ProjectionEncoding::ModelText,
                    _ => return Err("encoding must be text, binary or model-text"),
                }
            }
            "--replay" if !pair[1].is_empty() && !pair[1].starts_with('-') => {
                options.replay = Some((&pair[1]).into())
            }
            "--max-bytes" if matches!(profile.as_str(), "context" | "task-context") => {
                options.max_bytes = pair[1].parse().map_err(|_| "invalid byte limit")?
            }
            "--max-tokens" if profile == "task-context" => {
                options.max_tokens = pair[1].parse().map_err(|_| "invalid token limit")?
            }
            _ => return Err("unknown or inapplicable option"),
        }
    }
    if !chunks.remainder().is_empty() {
        return Err("option requires a value");
    }
    if matches!(profile.as_str(), "graph" | "api-surface" | "candidate-diff") {
        options.input = super::project::resolve_positional(options.input);
    }
    Ok(options)
}
fn read(path: &Path, limit: usize) -> Result<Vec<u8>, Vec<Diagnostic>> {
    super::project_image::read_bounded(path, limit).map_err(|error| vec![error])
}
fn text(path: &Path, limit: usize) -> Result<String, Vec<Diagnostic>> {
    String::from_utf8(read(path, limit)?)
        .map_err(|_| vec![Diagnostic::io("SPX-Z904", "compact input must be UTF-8")])
}
fn context_options(max_bytes: usize) -> Result<AgentContextV2Options, Vec<Diagnostic>> {
    AgentContextV2Options::new(
        1,
        max_bytes,
        256,
        [
            AgentContextFilter::Contracts,
            AgentContextFilter::Ownership,
            AgentContextFilter::Effects,
            AgentContextFilter::Types,
            AgentContextFilter::Diagnostics,
            AgentContextFilter::Tests,
        ],
        AgentContextDirection::Forward,
    )
    .map_err(|error| vec![error])
}
fn encode(options: &Options) -> Result<CompactProjection, Vec<Diagnostic>> {
    match options.profile.as_str() {
        "graph" if super::project::is_project_manifest(&options.input) => {
            with_authenticated_project(&options.input, |snapshot| {
                compact::encode_bytes(
                    snapshot.semantic_graph().as_bytes(),
                    "full-graph",
                    "*",
                    snapshot.project_revision(),
                )
                .map_err(|error| vec![error])
            })
        }
        "api-surface" => with_authenticated_project(&options.input, |snapshot| {
            compact::encode_selected(ProjectionSelection::ApiSurface {
                revision: &snapshot.retain_revision(),
            })
        }),
        "candidate-diff" => {
            let capsule = super::project_candidate::read_capsule(Path::new(
                options.selection.as_ref().expect("parsed selection"),
            ))
            .map_err(|error| vec![error])?;
            with_authenticated_project(&options.input, |snapshot| {
                let candidate = ProjectCandidate::restore(
                    snapshot.retain_revision(),
                    snapshot.project_revision(),
                    &capsule,
                )?;
                compact::encode_selected(ProjectionSelection::CandidateDiff {
                    candidate: &candidate,
                    expected_candidate: candidate.candidate_digest(),
                })
            })
        }
        "agent-definition" => {
            let source = text(&options.input, 1_310_720)?;
            let definition = semaprax::agent_definition::compile_agent_definition(&source)?;
            compact::encode_selected(ProjectionSelection::AgentDefinition {
                definition: &definition,
            })
        }
        _ => {
            let source = text(&options.input, compact::MAX_SOURCE_BYTES)?;
            let program = semaprax::check(&source, &options.input)?;
            match options.profile.as_str() {
                "graph" => compact::encode_profile(&program, ProjectionSource::FullGraph),
                "context" => compact::encode_profile(
                    &program,
                    ProjectionSource::AgentContextV2 {
                        symbol: options.selection.as_ref().expect("parsed selection"),
                        options: &context_options(options.max_bytes)?,
                    },
                ),
                "task-context" => {
                    let goal = CompilationGoal::new(vec![CompilationSeed::new(
                        options.selection.as_ref().expect("parsed selection"),
                        1,
                        "explicit CLI task root",
                    )])
                    .map_err(|error| vec![error])?;
                    let budget = CompilationBudget::new(options.max_tokens, "byte-v1")
                        .map_err(|error| vec![error])?;
                    compact::encode_selected(ProjectionSelection::TaskContext {
                        program: &program,
                        goal: &goal,
                        options: &context_options(options.max_bytes)?,
                        budget,
                    })
                }
                _ => unreachable!("closed profile parser"),
            }
        }
    }
}

pub(crate) fn output(options: &Options) -> Result<Vec<u8>, Vec<Diagnostic>> {
    let expected = encode(options)?;
    if let Some(path) = &options.replay {
        let bytes = read(path, compact::MAX_ENCODED_BYTES)?;
        let decoded = match options.encoding {
            compact::negotiation::ProjectionEncoding::Binary => compact::decode_binary_and_verify(
                &bytes,
                expected.profile(),
                expected.root(),
                expected.source_revision(),
            ),
            compact::negotiation::ProjectionEncoding::Text => {
                let encoded = std::str::from_utf8(&bytes)
                    .map_err(|_| vec![Diagnostic::io("SPX-Z904", "compact text must be UTF-8")])?;
                compact::decode_text_and_verify(
                    encoded,
                    expected.profile(),
                    expected.root(),
                    expected.source_revision(),
                )
            }
            compact::negotiation::ProjectionEncoding::ModelText => {
                compact::decode_model_text_and_verify(
                    &bytes,
                    expected.profile(),
                    expected.root(),
                    expected.source_revision(),
                )
            }
        }
        .map_err(|error| vec![error])?;
        let full = decoded.reconstructed().map_err(|error| vec![error])?;
        if full != expected.reconstructed().map_err(|error| vec![error])? {
            return Err(vec![Diagnostic::io(
                "SPX-Z910",
                "compact replay differs from freshly selected content",
            )]);
        }
        Ok(full)
    } else {
        match options.encoding {
            compact::negotiation::ProjectionEncoding::Binary => Ok(expected.to_binary()),
            compact::negotiation::ProjectionEncoding::Text => Ok(expected.to_text().into_bytes()),
            compact::negotiation::ProjectionEncoding::ModelText => {
                compact::encode_model_text(&expected)
                    .map(String::into_bytes)
                    .map_err(|error| vec![error])
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn args(values: &[&str]) -> Vec<String> {
        values.iter().map(|s| (*s).to_owned()).collect()
    }
    #[test]
    fn compact_cli_grammar_is_closed_and_profile_specific() {
        assert_eq!(
            parse_inner(&args(&["graph", "input.spx", "--encoding", "binary"]))
                .unwrap()
                .encoding,
            compact::negotiation::ProjectionEncoding::Binary
        );
        for input in [
            vec!["unknown", "input"],
            vec!["graph", "input", "extra"],
            vec!["context", "input"],
            vec!["graph", "input", "--max-tokens", "3"],
            vec![
                "graph",
                "input",
                "--encoding",
                "text",
                "--encoding",
                "binary",
            ],
        ] {
            assert!(parse_inner(&args(&input)).is_err());
        }
    }
    #[test]
    fn actual_graph_cli_output_is_independently_reconstructed() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"));
        let path = root.join("examples/banking_ledger.spx");
        let options = parse_inner(&args(&["graph", path.to_str().unwrap()])).unwrap();
        let encoded = output(&options).unwrap();
        let decoded = compact::decode_text(std::str::from_utf8(&encoded).unwrap()).unwrap();
        let model_options = parse_inner(&args(&[
            "graph",
            path.to_str().unwrap(),
            "--encoding",
            "model-text",
        ]))
        .unwrap();
        let model_wire = output(&model_options).unwrap();
        assert_eq!(
            compact::decode_model_text(&model_wire)
                .unwrap()
                .reconstructed()
                .unwrap(),
            decoded.reconstructed().unwrap()
        );
        let source = std::fs::read_to_string(&path).unwrap();
        let program = semaprax::parse(&source, &path).unwrap();
        assert_eq!(
            decoded.reconstructed().unwrap(),
            semaprax::graph::to_json(&program).unwrap().as_bytes()
        );
    }
}
