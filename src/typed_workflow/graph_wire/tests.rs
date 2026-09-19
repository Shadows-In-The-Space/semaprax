use super::*;
use crate::typed_workflow::graph::{GraphError, MAX_STEPS};

/// A minimal two-step `sequential -> terminal` graph, the canonical
/// well-formed fixture every positive test starts from.
fn minimal_document() -> String {
    r#"{
        "schema": "semaprax.typed-workflow.graph.v1",
        "entry": 0,
        "steps": [
            {"id": 0, "kind": "sequential", "in_ports": [],
             "out_ports": [{"id": 0, "ty": "unit"}]},
            {"id": 1, "kind": "terminal", "in_ports": [{"id": 0, "ty": "unit"}],
             "out_ports": []}
        ],
        "edges": [
            {"id": 0, "from": 0, "from_port": 0, "to": 1, "to_port": 0}
        ]
    }"#
    .to_owned()
}

#[test]
fn a_minimal_linear_graph_parses_and_validates() {
    let graph = parse_graph(minimal_document().as_bytes()).unwrap();
    assert_eq!(graph.entry, StepId(0));
    assert_eq!(graph.steps.len(), 2);
    assert_eq!(graph.edges.len(), 1);
    assert_eq!(graph.steps[0].kind, StepKind::Sequential);
    assert_eq!(graph.steps[1].kind, StepKind::Terminal);
    assert_eq!(graph.validate(), Ok(()));
}

/// Same bytes, parsed twice, must produce exactly the same value: this
/// decoder makes no use of hash-map iteration order, wall-clock time, or
/// randomness anywhere in its call graph.
#[test]
fn parsing_is_deterministic() {
    let bytes = minimal_document();
    let first = parse_graph(bytes.as_bytes()).unwrap();
    let second = parse_graph(bytes.as_bytes()).unwrap();
    assert_eq!(first, second);
}

/// Exercises every admitted [`StepKind`] shape in one document, proving each
/// decode arm reaches the right variant with the right payload. This is a
/// decode-fidelity test only -- the fixture's ports and edges are not wired
/// to satisfy [`WorkflowGraph::validate`] (that is exercised separately, on
/// a much smaller graph, by `a_minimal_linear_graph_parses_and_validates`
/// and by [`super::super::graph::tests`]'s own per-kind validation tests).
#[test]
fn every_step_kind_decodes_to_its_variant() {
    let document = r#"{
        "schema": "semaprax.typed-workflow.graph.v1",
        "entry": 0,
        "steps": [
            {"id": 0, "kind": "conditional", "condition_port": 0,
             "in_ports": [{"id": 0, "ty": "bool"}],
             "out_ports": [{"id": 0, "ty": "unit"}, {"id": 1, "ty": "unit"}]},
            {"id": 1, "kind": "sequential", "in_ports": [], "out_ports": []},
            {"id": 2, "kind": "sequential", "in_ports": [], "out_ports": []},
            {"id": 3, "kind": "parallel", "in_ports": [], "out_ports": []},
            {"id": 4, "kind": "sequential", "in_ports": [], "out_ports": []},
            {"id": 5, "kind": "sequential", "in_ports": [], "out_ports": []},
            {"id": 6, "kind": "join", "parallel": 3, "in_ports": [], "out_ports": []},
            {"id": 7, "kind": "human_gate", "in_ports": [], "out_ports": []},
            {"id": 8, "kind": "loop", "max_iterations": 3, "in_ports": [], "out_ports": []},
            {"id": 9, "kind": "model_call", "requested_model": "gpt",
             "in_ports": [], "out_ports": []},
            {"id": 10, "kind": "declared", "declared_kind": "agent_call",
             "in_ports": [], "out_ports": []},
            {"id": 11, "kind": "terminal", "in_ports": [], "out_ports": []}
        ],
        "edges": [
            {"id": 0, "from": 0, "from_port": 0, "to": 1, "to_port": 0},
            {"id": 1, "from": 0, "from_port": 1, "to": 2, "to_port": 0},
            {"id": 2, "from": 1, "from_port": 0, "to": 3, "to_port": 0},
            {"id": 3, "from": 2, "from_port": 0, "to": 3, "to_port": 0},
            {"id": 4, "from": 3, "from_port": 0, "to": 4, "to_port": 0},
            {"id": 5, "from": 3, "from_port": 0, "to": 5, "to_port": 0},
            {"id": 6, "from": 4, "from_port": 0, "to": 6, "to_port": 0},
            {"id": 7, "from": 5, "from_port": 0, "to": 6, "to_port": 0},
            {"id": 8, "from": 6, "from_port": 0, "to": 7, "to_port": 0},
            {"id": 9, "from": 7, "from_port": 0, "to": 8, "to_port": 0},
            {"id": 10, "from": 8, "from_port": 0, "to": 9, "to_port": 0},
            {"id": 11, "from": 9, "from_port": 0, "to": 10, "to_port": 0},
            {"id": 12, "from": 10, "from_port": 0, "to": 11, "to_port": 0}
        ]
    }"#;
    let graph = parse_graph(document.as_bytes()).unwrap();
    assert_eq!(
        graph.steps[0].kind,
        StepKind::Conditional {
            condition_port: PortId(0)
        }
    );
    assert_eq!(graph.steps[3].kind, StepKind::Parallel);
    assert_eq!(
        graph.steps[6].kind,
        StepKind::Join {
            parallel: StepId(3)
        }
    );
    assert_eq!(graph.steps[7].kind, StepKind::HumanGate);
    assert_eq!(graph.steps[8].kind, StepKind::Loop { max_iterations: 3 });
    assert_eq!(
        graph.steps[9].kind,
        StepKind::ModelCall {
            requested_model: "gpt".to_owned()
        }
    );
    assert_eq!(
        graph.steps[10].kind,
        StepKind::Declared(DeclaredStepKind::AgentCall)
    );
    assert_eq!(graph.steps[11].kind, StepKind::Terminal);
}

/// A declared step naming each of the six [`DeclaredStepKind`] names round
/// trips to the matching variant, including `semantic_change`, which the
/// engine refuses to execute but this decoder still admits into the schema.
#[test]
fn every_declared_kind_name_decodes() {
    for (name, expected) in [
        ("agent_call", DeclaredStepKind::AgentCall),
        ("tool_call", DeclaredStepKind::ToolCall),
        ("job", DeclaredStepKind::Job),
        ("semantic_change", DeclaredStepKind::SemanticChange),
        ("test_build", DeclaredStepKind::TestBuild),
        ("publication_request", DeclaredStepKind::PublicationRequest),
    ] {
        let document = format!(
            r#"{{"schema": "semaprax.typed-workflow.graph.v1", "entry": 0, "steps": [
                {{"id": 0, "kind": "declared", "declared_kind": "{name}",
                  "in_ports": [], "out_ports": []}}
            ], "edges": []}}"#
        );
        let graph = parse_graph(document.as_bytes()).unwrap();
        assert_eq!(graph.steps[0].kind, StepKind::Declared(expected), "{name}");
    }
}

// ---------------------------------------------------------------------------
// Fault injection / hostile input: each of these must be refused with the
// front's own `SPX-Z921` code, never panic, and never silently repair the
// document into something the caller did not write.
// ---------------------------------------------------------------------------

fn assert_malformed(bytes: &[u8]) {
    let error = parse_graph(bytes).expect_err("expected a malformed-document refusal");
    assert_eq!(error.code, "SPX-Z921");
}

#[test]
fn non_utf8_bytes_are_refused() {
    assert_malformed(&[0xff, 0xfe, 0xfd]);
}

#[test]
fn invalid_json_syntax_is_refused() {
    assert_malformed(b"{ this is not json");
}

#[test]
fn a_non_object_top_level_value_is_refused() {
    assert_malformed(b"[1, 2, 3]");
}

#[test]
fn an_unknown_top_level_field_is_refused() {
    let document =
        minimal_document().replace("\"entry\": 0,", "\"entry\": 0, \"unexpected\": true,");
    assert_malformed(document.as_bytes());
}

#[test]
fn a_missing_top_level_field_is_refused() {
    let document = minimal_document().replace("\"edges\": [", "\"edges_typo\": [");
    assert_malformed(document.as_bytes());
}

#[test]
fn the_wrong_schema_is_refused() {
    let document = minimal_document().replace(
        "semaprax.typed-workflow.graph.v1",
        "semaprax.typed-workflow.graph.v2",
    );
    assert_malformed(document.as_bytes());
}

#[test]
fn an_unknown_step_kind_is_refused() {
    let document = minimal_document().replace("\"sequential\"", "\"sequentialx\"");
    assert_malformed(document.as_bytes());
}

#[test]
fn an_unknown_port_type_is_refused() {
    let document = r#"{"schema": "semaprax.typed-workflow.graph.v1", "entry": 0, "steps": [
        {"id": 0, "kind": "conditional", "condition_port": 0,
         "in_ports": [{"id": 0, "ty": "float"}], "out_ports": []}
    ], "edges": []}"#;
    assert_malformed(document.as_bytes());
}

#[test]
fn an_unknown_declared_kind_is_refused() {
    let document = r#"{"schema": "semaprax.typed-workflow.graph.v1", "entry": 0, "steps": [
        {"id": 0, "kind": "declared", "declared_kind": "email_send",
         "in_ports": [], "out_ports": []}
    ], "edges": []}"#;
    assert_malformed(document.as_bytes());
}

/// A field that belongs to a different step kind -- `max_iterations` on a
/// `sequential` step -- must be refused by the closed-key check for that
/// kind, never silently accepted or ignored.
#[test]
fn a_field_from_a_different_step_kind_is_refused() {
    let document = r#"{"schema": "semaprax.typed-workflow.graph.v1", "entry": 0, "steps": [
        {"id": 0, "kind": "sequential", "max_iterations": 3,
         "in_ports": [], "out_ports": []}
    ], "edges": []}"#;
    assert_malformed(document.as_bytes());
}

#[test]
fn a_non_integer_entry_is_refused() {
    let document = minimal_document().replace("\"entry\": 0,", "\"entry\": \"zero\",");
    assert_malformed(document.as_bytes());
}

#[test]
fn a_negative_step_id_is_refused() {
    let document = minimal_document().replace(
        "\"id\": 0, \"kind\": \"sequential\"",
        "\"id\": -1, \"kind\": \"sequential\"",
    );
    assert_malformed(document.as_bytes());
}

/// A number that does not fit in `u32` (here, `u32::MAX as u64 + 1`) is
/// refused rather than silently truncated.
#[test]
fn a_step_id_beyond_u32_is_refused() {
    let document = minimal_document().replace(
        "\"id\": 0, \"kind\": \"sequential\"",
        "\"id\": 4294967296, \"kind\": \"sequential\"",
    );
    assert_malformed(document.as_bytes());
}

#[test]
fn an_oversized_document_is_refused_before_parsing() {
    let padding = "x".repeat(MAX_WIRE_BYTES + 1);
    let hostile = format!("{{\"padding\": \"{padding}\"}}");
    assert!(hostile.len() > MAX_WIRE_BYTES);
    assert_malformed(hostile.as_bytes());
}

/// More steps than [`MAX_STEPS`] admits is refused by this decoder itself,
/// before a graph is ever handed to [`super::graph::WorkflowGraph::validate`]
/// (which enforces the same bound again, independently, on any graph built
/// by hand rather than through this decoder).
#[test]
fn too_many_steps_is_refused_by_the_decoder() {
    let mut steps = String::new();
    for id in 0..=MAX_STEPS {
        if id > 0 {
            steps.push(',');
        }
        steps.push_str(&format!(
            "{{\"id\": {id}, \"kind\": \"sequential\", \"in_ports\": [], \"out_ports\": []}}"
        ));
    }
    let document = format!(
        r#"{{"schema": "semaprax.typed-workflow.graph.v1", "entry": 0, "steps": [{steps}], "edges": []}}"#
    );
    assert_malformed(document.as_bytes());
}

/// A structurally well-formed document (this decoder's whole job) can still
/// describe a semantically invalid graph -- that is
/// [`super::graph::WorkflowGraph::validate`]'s job, never this decoder's.
/// `entry` naming a step id that does not exist parses cleanly...
#[test]
fn a_structurally_valid_but_semantically_invalid_graph_still_parses() {
    let document = minimal_document().replace("\"entry\": 0,", "\"entry\": 99,");
    let graph = parse_graph(document.as_bytes()).unwrap();
    // ...and only fails when the caller separately validates it.
    assert_eq!(graph.validate(), Err(GraphError::UnknownEntry(StepId(99))));
}
