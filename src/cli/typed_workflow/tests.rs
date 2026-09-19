use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use semaprax::typed_workflow::checkpoint::{Checkpoint, RevisionId};
use semaprax::typed_workflow::compensation::CompensationLedger;
use semaprax::typed_workflow::graph::StepId;

use super::*;

static NEXT: AtomicU64 = AtomicU64::new(0);

fn scratch_dir(label: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!(
        "semaprax-cli-typed-workflow-{label}-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    fs::create_dir_all(&path).expect("scratch directory must be creatable");
    path
}

fn write(dir: &std::path::Path, name: &str, bytes: &[u8]) -> PathBuf {
    let path = dir.join(name);
    fs::write(&path, bytes).expect("fixture must be writable");
    path
}

const VALID_GRAPH: &str = r#"{
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
}"#;

/// Structurally decodable (this front's `inspect` accepts it) but not
/// reachable-and-terminal-clean (`validate` must reject it): step 1 has no
/// outgoing edge and is not `Terminal`, a `DeadEnd`.
const INVALID_GRAPH: &str = r#"{
    "schema": "semaprax.typed-workflow.graph.v1",
    "entry": 0,
    "steps": [
        {"id": 0, "kind": "sequential", "in_ports": [],
         "out_ports": [{"id": 0, "ty": "unit"}]},
        {"id": 1, "kind": "sequential", "in_ports": [{"id": 0, "ty": "unit"}],
         "out_ports": []}
    ],
    "edges": [
        {"id": 0, "from": 0, "from_port": 0, "to": 1, "to_port": 0}
    ]
}"#;

fn valid_checkpoint_document() -> String {
    let ledger = CompensationLedger::new();
    Checkpoint::new(RevisionId(7), StepId(3), 1, &ledger).encode()
}

// ---------------------------------------------------------------------
// `parse`: closed argument grammar.
// ---------------------------------------------------------------------

fn strings(values: &[&str]) -> Vec<String> {
    values.iter().map(|value| (*value).to_owned()).collect()
}

#[test]
fn parse_admits_every_documented_shape() {
    assert!(matches!(
        parse(&strings(&["inspect", "graph.json"])),
        Ok(WorkflowCommand::Inspect(_))
    ));
    assert!(matches!(
        parse(&strings(&["validate", "graph.json"])),
        Ok(WorkflowCommand::Validate(_))
    ));
    assert!(matches!(
        parse(&strings(&["checkpoint", "checkpoint.json"])),
        Ok(WorkflowCommand::Checkpoint(_))
    ));
    assert!(matches!(
        parse(&strings(&["dispatch", "policy.json", "request.json"])),
        Ok(WorkflowCommand::Dispatch(_, _))
    ));
}

#[test]
fn parse_rejects_every_malformed_shape() {
    for malformed in [
        &[][..],
        &["inspect"][..],
        &["inspect", "graph.json", "extra"][..],
        &["inspect", ""][..],
        &["inspect", "--json"][..],
        &["validate"][..],
        &["checkpoint"][..],
        &["dispatch"][..],
        &["dispatch", "policy.json"][..],
        &["dispatch", "", "request.json"][..],
        &["dispatch", "policy.json", "--flag"][..],
        &["run", "graph.json"][..],
        &["execute", "graph.json"][..],
    ] {
        assert!(parse(&strings(malformed)).is_err(), "{malformed:?}");
    }
}

// ---------------------------------------------------------------------
// `workflow inspect`
// ---------------------------------------------------------------------

#[test]
fn inspect_reports_the_structural_shape_of_a_valid_graph() {
    let dir = scratch_dir("inspect-valid");
    let path = write(&dir, "graph.json", VALID_GRAPH.as_bytes());
    let report = run_inspect(&path).unwrap();
    assert!(report.contains("entry: 0"));
    assert!(report.contains("steps: 2"));
    assert!(report.contains("edges: 1"));
    assert!(report.contains("status: INSPECTED"));
}

/// `inspect` never validates: a structurally decodable but semantically
/// invalid graph (a dead end) is still reported, not refused.
#[test]
fn inspect_accepts_a_structurally_valid_but_semantically_invalid_graph() {
    let dir = scratch_dir("inspect-invalid");
    let path = write(&dir, "graph.json", INVALID_GRAPH.as_bytes());
    let report = run_inspect(&path).unwrap();
    assert!(report.contains("status: INSPECTED"));
}

#[test]
fn inspect_repeats_the_owning_decoders_own_code_on_a_malformed_graph() {
    let dir = scratch_dir("inspect-malformed");
    let path = write(&dir, "graph.json", b"not json");
    let error = run_inspect(&path).unwrap_err();
    // Decode failures keep `graph_wire`'s own code, never this front's.
    assert_eq!(error.code, "SPX-Z921");
}

#[test]
fn inspect_is_deterministic() {
    let dir = scratch_dir("inspect-determinism");
    let path = write(&dir, "graph.json", VALID_GRAPH.as_bytes());
    assert_eq!(run_inspect(&path).unwrap(), run_inspect(&path).unwrap());
}

// ---------------------------------------------------------------------
// `workflow validate`
// ---------------------------------------------------------------------

#[test]
fn validate_reports_valid_for_a_well_formed_graph() {
    let dir = scratch_dir("validate-valid");
    let path = write(&dir, "graph.json", VALID_GRAPH.as_bytes());
    let report = run_validate(&path).unwrap();
    assert!(report.contains("status: VALID"));
}

#[test]
fn validate_fails_closed_on_a_dead_end_with_this_fronts_own_code() {
    let dir = scratch_dir("validate-invalid");
    let path = write(&dir, "graph.json", INVALID_GRAPH.as_bytes());
    let error = run_validate(&path).unwrap_err();
    assert_eq!(error.code, "SPX-Z924");
    assert!(error.message.contains("DeadEnd"), "{}", error.message);
}

#[test]
fn validate_is_deterministic() {
    let dir = scratch_dir("validate-determinism");
    let path = write(&dir, "graph.json", VALID_GRAPH.as_bytes());
    assert_eq!(run_validate(&path).unwrap(), run_validate(&path).unwrap());
}

// ---------------------------------------------------------------------
// `workflow checkpoint`
// ---------------------------------------------------------------------

#[test]
fn checkpoint_reports_the_recorded_state() {
    let dir = scratch_dir("checkpoint-valid");
    let path = write(&dir, "checkpoint.json", valid_checkpoint_document().as_bytes());
    let report = run_checkpoint(&path).unwrap();
    assert!(report.contains("revision: 7"));
    assert!(report.contains("step: 3"));
    assert!(report.contains("sequence: 1"));
    assert!(report.contains("compensation ledger entries: 0"));
    assert!(report.contains("status: DECODED"));
}

#[test]
fn checkpoint_fails_closed_on_a_malformed_document() {
    let dir = scratch_dir("checkpoint-malformed");
    let path = write(&dir, "checkpoint.json", b"not a checkpoint\n");
    let error = run_checkpoint(&path).unwrap_err();
    assert_eq!(error.code, "SPX-Z923");
}

#[test]
fn checkpoint_never_resumes_or_migrates() {
    // Documentation-as-test: `run_checkpoint` never calls `Checkpoint::resume`
    // or `Checkpoint::migrate`, so decoding a checkpoint through this front
    // can never authorize continuing a run at its recorded step.
    let source = include_str!("../typed_workflow.rs");
    assert!(!source.contains(".resume("));
    assert!(!source.contains(".migrate("));
}

// ---------------------------------------------------------------------
// `workflow dispatch`
// ---------------------------------------------------------------------

#[test]
fn dispatch_admits_a_target_inside_the_declared_policy() {
    let dir = scratch_dir("dispatch-admitted");
    let policy = write(
        &dir,
        "policy.json",
        br#"{"allowed_targets": ["release-agent"]}"#,
    );
    let request = write(&dir, "request.json", br#"{"target": "release-agent"}"#);
    let report = run_dispatch(&policy, &request).unwrap();
    assert!(report.contains("admitted target: release-agent"));
    assert!(report.contains("status: ADMITTED"));
}

#[test]
fn dispatch_refuses_a_target_outside_the_declared_policy_with_this_fronts_own_code() {
    let dir = scratch_dir("dispatch-refused");
    let policy = write(&dir, "policy.json", br#"{"allowed_targets": []}"#);
    let request = write(&dir, "request.json", br#"{"target": "unlisted-agent"}"#);
    let error = run_dispatch(&policy, &request).unwrap_err();
    assert_eq!(error.code, "SPX-Z924");
    assert!(error.message.contains("unlisted-agent"));
}

/// A dispatch request naming a path-traversal-shaped target is decided (and,
/// here, refused) as an ordinary opaque string -- this front never resolves
/// a `target` against the filesystem.
#[test]
fn dispatch_treats_a_path_traversal_shaped_target_as_an_opaque_string() {
    let dir = scratch_dir("dispatch-traversal");
    let policy = write(&dir, "policy.json", br#"{"allowed_targets": []}"#);
    let request = write(
        &dir,
        "request.json",
        br#"{"target": "../../etc/passwd"}"#,
    );
    let error = run_dispatch(&policy, &request).unwrap_err();
    assert_eq!(error.code, "SPX-Z924");
    assert!(error.message.contains("../../etc/passwd"));
}

#[test]
fn dispatch_is_deterministic() {
    let dir = scratch_dir("dispatch-determinism");
    let policy = write(
        &dir,
        "policy.json",
        br#"{"allowed_targets": ["release-agent"]}"#,
    );
    let request = write(&dir, "request.json", br#"{"target": "release-agent"}"#);
    assert_eq!(
        run_dispatch(&policy, &request).unwrap(),
        run_dispatch(&policy, &request).unwrap()
    );
}

// ---------------------------------------------------------------------
// Cross-cutting: bounded reads, hostile input, and front-level fail-closed
// behavior for every verb.
// ---------------------------------------------------------------------

#[test]
fn an_oversized_document_is_refused_before_any_decoder_sees_it() {
    let dir = scratch_dir("oversized");
    let oversized = vec![b'x'; (MAX_DOCUMENT_BYTES + 1) as usize];
    let path = write(&dir, "graph.json", &oversized);
    let error = run_inspect(&path).unwrap_err();
    assert_eq!(error.code, "SPX-Z923");
}

#[test]
fn a_missing_document_fails_closed_with_this_fronts_own_code() {
    let dir = scratch_dir("missing");
    let error = run_inspect(&dir.join("does-not-exist.json")).unwrap_err();
    assert_eq!(error.code, "SPX-Z923");
}

#[test]
fn a_non_utf8_checkpoint_document_is_refused() {
    let dir = scratch_dir("checkpoint-non-utf8");
    let path = write(&dir, "checkpoint.json", &[0xff, 0xfe, 0xfd]);
    let error = run_checkpoint(&path).unwrap_err();
    assert_eq!(error.code, "SPX-Z923");
}

// ---------------------------------------------------------------------
// Portability / authority: structural asserts on this front's own source
// text, mirroring `cli::audit`'s own such tests.
// ---------------------------------------------------------------------

#[test]
fn this_front_spawns_no_process_reaches_no_network_and_writes_nothing() {
    let source = include_str!("../typed_workflow.rs");
    assert!(!source.contains("std::process::Command"));
    assert!(!source.contains("TcpStream"));
    assert!(!source.contains("std::net::"));
    assert!(!source.contains("fs::write"));
    assert!(!source.contains("fs::remove"));
    assert!(!source.contains("fs::create_dir"));
    assert!(!source.contains("OpenOptions"));
}
