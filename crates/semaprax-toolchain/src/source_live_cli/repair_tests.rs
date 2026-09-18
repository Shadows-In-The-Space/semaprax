use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use super::*;

static NEXT: AtomicU64 = AtomicU64::new(0);

struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        let parent = std::env::temp_dir().canonicalize().unwrap();
        let path = parent.join(format!(
            "spx-source-live-repair-test-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(path.join("project/src")).unwrap();
        Self(path)
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

const MANIFEST: &str = include_str!("../../../../examples/offline-repair-project/semaprax.toml");
const APP: &str = include_str!("../../../../examples/offline-repair-project/src/app.spx");
const TESTS_SPX: &str = include_str!("../../../../examples/offline-repair-project/src/tests.spx");

/// Writes a fresh, host-selected copy of the checked-in offline-repair-demo
/// Project into the fixture, with `app_source` as its one mutable module.
/// This proves the candidate-preview machinery below is no longer hardwired
/// to a single compiled-in manifest path: it is driven entirely off the
/// operand config, same as any other host-selected `.spx` Project.
fn write_project(fixture: &Fixture, app_source: &str) -> PathBuf {
    let root = fixture.0.join("project");
    fs::create_dir_all(root.join("src")).unwrap();
    fs::write(root.join("semaprax.toml"), MANIFEST).unwrap();
    fs::write(root.join("src/app.spx"), app_source).unwrap();
    fs::write(root.join("src/tests.spx"), TESTS_SPX).unwrap();
    root.join("semaprax.toml")
}

fn schema_digest(app_source: &str) -> String {
    let compiled = compile_source_agent_lifecycle_v2(
        app_source,
        "src/app.spx",
        "fixture.agent",
        "fixture.agent.type.step",
    )
    .unwrap();
    compiled.proposal_schema().schema().digest().to_owned()
}

fn proposal(schema_digest: &str, budget: &str, sequence: &str) -> String {
    format!(
        concat!(
            "{{\"schema\":\"semaprax.agent-proposal.v1\",\"agent_id\":\"fixture.agent\",",
            "\"proposal_schema_digest\":\"{schema_digest}\",\"value\":{{\"fields\":{{",
            "\"fixture.agent.type.proposal.budget\":\"{budget}\",",
            "\"fixture.agent.type.proposal.urgent\":false,",
            "\"fixture.agent.type.proposal.sequence\":\"{sequence}\"}}}}}}\n"
        ),
        schema_digest = schema_digest,
        budget = budget,
        sequence = sequence,
    )
}

#[allow(clippy::too_many_arguments)]
fn repair_config_value(
    manifest: &Path,
    task_path: &Path,
    schema_digest: &str,
    migration_id: &str,
) -> serde_json::Value {
    serde_json::json!({
        "schema": "semaprax.source-live-cli.repair-config.v1",
        "manifest": manifest.to_str().unwrap(),
        "source_path": "src/app.spx",
        "agent_id": "fixture.agent",
        "step_id": "fixture.agent.type.step",
        "selector_field_id": "fixture.agent.type.proposal.sequence",
        "deployment_migration_id": migration_id,
        "target": "fixture.repair.value",
        "malformed_operation_id": "fixture.read",
        "corrected_operation_id": "fixture.read.second",
        "effect_id": "read",
        "argument_id": "query",
        "proposal_field_id": "fixture.agent.type.proposal.budget",
        "result_id": "value",
        "task_path": task_path.to_str().unwrap(),
        "task_budget": 12,
        "deadline_millis": 1000,
        "ceiling": 2,
        "reservation_units": 1,
        "max_total_steps": 2_000_000,
        "effect_budget": {
            "max_calls": 2,
            "max_argument_bytes": 4096,
            "max_result_bytes": 4096,
            "max_total_bytes": 8192,
        },
        "malformed_replacement": 0,
        "malformed_bool_literal": true,
        "turns": [
            {"document": proposal(schema_digest, "0", "0"), "requires_prior_feedback": false},
            {"document": proposal(schema_digest, "7", "1"), "requires_prior_feedback": true},
        ],
    })
}

fn write_config(fixture: &Fixture, value: &serde_json::Value) -> PathBuf {
    let path = fixture.0.join("config.json");
    fs::write(&path, serde_json::to_vec(value).unwrap()).unwrap();
    path
}

fn run_repair(verb: &str, config: &Path, checkpoint: &Path) -> Result<String, CliError> {
    run(&[
        verb.to_owned(),
        config.to_str().unwrap().to_owned(),
        checkpoint.to_str().unwrap().to_owned(),
    ])
}

fn setup(fixture: &Fixture, migration_id: &str) -> (PathBuf, PathBuf) {
    let manifest = write_project(fixture, APP).canonicalize().unwrap();
    let digest = schema_digest(APP);
    let task_path = fixture.0.join("task.txt");
    fs::write(&task_path, b"repair the checked candidate").unwrap();
    let config_value = repair_config_value(&manifest, &task_path, &digest, migration_id);
    let config = write_config(fixture, &config_value);
    let checkpoint = fixture.0.join("checkpoint");
    (config, checkpoint)
}

/// Generalization: the exact candidate-preview/source-diff/semantic-impact
/// evidence the fixed `offline-repair` demo produces is reachable for a
/// host-selected Project and target through operand config alone, with a
/// durable (resumable) checkpoint rather than an in-memory-only journal.
#[test]
fn repair_run_generalizes_candidate_preview_for_a_host_selected_project() {
    let fixture = Fixture::new();
    let (config, checkpoint) = setup(&fixture, "test.repair.run.v1");

    let rendered = run_repair("run", &config, &checkpoint).unwrap();
    let report: serde_json::Value = serde_json::from_str(&rendered).unwrap();
    assert_eq!(report["schema"], RECEIPT_SCHEMA);
    assert_eq!(report["target"], "fixture.repair.value");
    assert_eq!(report["status"], "complete");
    assert_eq!(report["model_dispatches"], 2);
    assert_eq!(report["effect_dispatches"], 2);
    assert_eq!(report["rejected_candidates"], 1);
    assert_eq!(report["source_mutation"], false);
    assert_eq!(report["publication_authority"], false);
    assert!(report["candidate_digest"].is_string());
    assert!(report["source_review"].is_object());
    assert!(report["semantic_delta"].is_object());
    assert!(report["impact_summary"].is_object());
}

/// Ordering property: replay happens before staging or candidate creation.
/// A resumed terminal checkpoint redispatches no model or effect call and
/// fabricates no fresh candidate evidence; only the exact live invocation
/// that produced it holds that evidence.
#[test]
fn repair_resume_replays_terminal_checkpoint_without_redispatch_or_refabricated_evidence() {
    let fixture = Fixture::new();
    let (config, checkpoint) = setup(&fixture, "test.repair.resume.v1");

    let first = run_repair("run", &config, &checkpoint).unwrap();
    let first_report: serde_json::Value = serde_json::from_str(&first).unwrap();
    assert_eq!(first_report["model_dispatches"], 2);
    assert!(first_report["candidate_digest"].is_string());

    let checkpoint_document = checkpoint.join("checkpoint.json");
    let bytes_before = fs::read(&checkpoint_document).unwrap();

    let resumed = run_repair("resume", &config, &checkpoint).unwrap();
    let resumed_report: serde_json::Value = serde_json::from_str(&resumed).unwrap();
    assert_eq!(resumed_report["status"], "complete");
    assert_eq!(resumed_report["model_dispatches"], 0);
    assert_eq!(resumed_report["effect_dispatches"], 0);
    assert_eq!(resumed_report["candidate_digest"], serde_json::Value::Null);
    assert_eq!(resumed_report["generation"], first_report["generation"]);
    assert_eq!(fs::read(&checkpoint_document).unwrap(), bytes_before);
}

/// Ordering property: the ordinary Project lock/authority is acquired before
/// any checkpoint store is touched. An unauthenticatable manifest refuses
/// before a checkpoint directory is ever created, so no replay, staging or
/// candidate creation can be reached without it.
#[test]
fn repair_run_acquires_project_authority_before_creating_the_checkpoint_store() {
    let fixture = Fixture::new();
    let manifest = fixture.0.join("missing-project/semaprax.toml");
    let task_path = fixture.0.join("task.txt");
    fs::write(&task_path, b"objective").unwrap();
    let digest = schema_digest(APP);
    let config_value = repair_config_value(&manifest, &task_path, &digest, "test.repair.auth.v1");
    let config = write_config(&fixture, &config_value);
    let checkpoint = fixture.0.join("checkpoint");

    assert!(run_repair("run", &config, &checkpoint).is_err());
    assert!(!checkpoint.exists());
}

/// The hostile, load-bearing case: source drift between the checked preview
/// and a later resume fails closed rather than silently replaying stale
/// evidence against a Project that no longer matches it. The refused resume
/// leaves the checkpoint exactly as it was; it advances nothing.
#[test]
fn repair_resume_refuses_when_source_drifts_between_preview_and_resume() {
    let fixture = Fixture::new();
    let (config, checkpoint) = setup(&fixture, "test.repair.drift.v1");

    let first = run_repair("run", &config, &checkpoint).unwrap();
    let first_report: serde_json::Value = serde_json::from_str(&first).unwrap();
    assert_eq!(first_report["status"], "complete");

    let checkpoint_document = checkpoint.join("checkpoint.json");
    let bytes_before = fs::read(&checkpoint_document).unwrap();

    // Mutate the exact checked source that produced the retained preview,
    // after that preview was produced and the terminal checkpoint committed,
    // but before any later session reads it again.
    let manifest = PathBuf::from(config_manifest(&config));
    let source_path = manifest.parent().unwrap().join("src/app.spx");
    let mutated = APP.replacen(
        "@id(\"fixture.repair.value\")\nfn repair_value() -> i64\n{\n    0\n}",
        "@id(\"fixture.repair.value\")\nfn repair_value() -> i64\n{\n    9\n}",
        1,
    );
    assert_ne!(
        mutated, APP,
        "the drift edit must actually change the source"
    );
    fs::write(&source_path, &mutated).unwrap();

    let resumed = run_repair("resume", &config, &checkpoint);
    assert!(
        resumed.is_err(),
        "a resume against drifted source must be refused, not silently replayed"
    );
    assert_eq!(
        fs::read(&checkpoint_document).unwrap(),
        bytes_before,
        "a refused drifted resume must not advance or corrupt the checkpoint"
    );
}

fn config_manifest(config: &Path) -> String {
    let value: serde_json::Value = serde_json::from_slice(&fs::read(config).unwrap()).unwrap();
    value["manifest"].as_str().unwrap().to_owned()
}

#[test]
fn command_grammar_requires_run_or_resume_and_absolute_operands() {
    let args = |values: &[&str]| {
        values
            .iter()
            .map(|value| (*value).into())
            .collect::<Vec<_>>()
    };
    assert!(Command::parse(&args(&[])).is_err());
    assert!(Command::parse(&args(&["run", "relative.json", "/checkpoint"])).is_err());
    assert!(Command::parse(&args(&["migrate", "/config.json", "/checkpoint"])).is_err());
    assert!(Command::parse(&args(&["run", "/config.json", "/checkpoint"])).is_ok());
    assert!(Command::parse(&args(&["resume", "/config.json", "/checkpoint"])).is_ok());
}
