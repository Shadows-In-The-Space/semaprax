//! A small external host using only SEMAPRAX's public embedding facade.
//!
//! This is a checkout consumer: the path dependency makes it runnable before
//! the embedding API is published. It intentionally does not access compiler
//! internals, the CLI, or the filesystem.

use semaprax::embedding_api::{
    check_source, check_source_with_request, context_source_with_cancellation,
    execute_entry_source, format_source, graph_source, negotiate_features, open_project_session,
    AnalysisOptions, AnalysisRequest, EmbeddingCancellation, ExecutionCancellation,
    ExecutionCapability, ExecutionOptions, ProjectSessionInput, ProjectSourceInput,
    EMBEDDING_API_VERSION,
};

const SOURCE: &str =
    "module host.demo;\n\n@id(\"host.demo.main\")\nfn main() -> i64\n{\n    42\n}\n";

fn main() {
    assert!(EMBEDDING_API_VERSION.is_compatible_with(2));
    assert!(!EMBEDDING_API_VERSION.is_compatible_with(0));
    assert!(!EMBEDDING_API_VERSION.is_compatible_with(1));
    EMBEDDING_API_VERSION
        .require_compatible(2)
        .expect("the example is written for embedding API v2");

    negotiate_features(
        2,
        0,
        &[
            "context-v1",
            "project-session-v1",
            "deterministic-i64-entry-v1",
        ],
    )
    .expect("the host supports every required operation profile");

    let request = AnalysisRequest::new("host-demo.spx", SOURCE)
        .with_options(AnalysisOptions::new(4096, 128).expect("host analysis limits"));
    let checked = check_source_with_request(request);
    assert!(
        checked.ok,
        "valid source was rejected: {:?}",
        checked.diagnostics
    );
    assert!(checked.diagnostics.is_empty());
    assert!(checked.revision.is_some());
    assert_eq!(checked.unit_name, "host-demo.spx");

    let formatted = format_source("host-demo.spx", SOURCE);
    assert!(
        formatted.ok,
        "valid source did not format: {:?}",
        formatted.diagnostics
    );
    let canonical = formatted
        .canonical_source
        .expect("successful formatting must return canonical source");
    assert_eq!(
        canonical, SOURCE,
        "formatting returns the exact canonical source"
    );
    assert_eq!(
        format_source("host-demo.spx", &canonical).canonical_source,
        Some(canonical)
    );

    let graphed = graph_source("host-demo.spx", SOURCE);
    assert!(
        graphed.ok,
        "valid source did not graph: {:?}",
        graphed.diagnostics
    );
    let graph = graphed
        .graph_json
        .expect("successful graph rendering must return graph JSON");
    assert!(graph.contains("host.demo.main"));

    let malformed = check_source("host-demo.spx", "module host.demo;\n");
    assert!(!malformed.ok);
    assert_eq!(malformed.diagnostics[0].code, "SPX-P101");

    let warned = check_source(
        "host-demo.spx",
        "module host.demo;\n\nfn main() -> i64\n{\n    42\n}\n",
    );
    assert!(warned.ok);
    assert!(warned
        .diagnostics
        .iter()
        .any(|diagnostic| diagnostic.code == "SPX-S103"));

    let cancellation = EmbeddingCancellation::new();
    let context = context_source_with_cancellation(
        "host-demo.spx",
        SOURCE,
        "host.demo.main",
        &Default::default(),
        &cancellation,
    );
    assert!(context.ok, "context failed: {:?}", context.diagnostics);
    assert!(context.context_json.is_some());

    let execution = execute_entry_source(
        &ExecutionCapability::grant("the host admits deterministic demo evaluation"),
        "host-demo.spx",
        SOURCE,
        &ExecutionOptions::default(),
        &ExecutionCancellation::new(),
    );
    assert!(
        execution.ok,
        "execution failed: {:?}",
        execution.diagnostics
    );

    let project_input = ProjectSessionInput::new(
        include_str!("../../../examples/calculator-project/semaprax.toml"),
        vec![
            ProjectSourceInput::new(
                "src/app.spx",
                include_str!("../../../examples/calculator-project/src/app.spx"),
            )
            .expect("bounded Project source"),
            ProjectSourceInput::new(
                "src/core.spx",
                include_str!("../../../examples/calculator-project/src/core.spx"),
            )
            .expect("bounded Project source"),
            ProjectSourceInput::new(
                "src/tests.spx",
                include_str!("../../../examples/calculator-project/src/tests.spx"),
            )
            .expect("bounded Project source"),
        ],
    )
    .expect("canonical embedded Project input");
    let (session, opened) = open_project_session(&project_input);
    assert!(opened.ok, "Project open failed: {:?}", opened.diagnostics);
    let session = session.expect("successful Project open returns its opaque handle");
    assert!(session.workspace_revision().is_some());
}
