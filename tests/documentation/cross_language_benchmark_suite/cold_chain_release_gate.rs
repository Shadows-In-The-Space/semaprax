//! Real-toolchain regression coverage for `cold-chain-release-gate-v1`.
//!
//! The candidate predicate is shared by public and hidden overlays. These
//! cases prove the committed conjunction candidates and a plausible
//! disjunction bug through the Rust, TypeScript, and SEMAPRAX ports.

use super::*;

const TASK: &str = "cold-chain-release-gate-v1";

fn task_source() -> PathBuf {
    root().join(SUITE).join("tasks").join(TASK)
}

fn task_inventory(directory: &Path, id: &str) -> PathBuf {
    let tasks = serde_json::json!({
        "schema": "benchmark.cross_language.tasks.v1",
        "tasks": [{
            "id": id,
            "category": "validation",
            "split": "held_out",
            "summary": "cold-chain release gate candidate regression control",
            "equivalence": "task/EQUIVALENCE.md",
            "languages": {
                "rust": {"public": "task/public/rust", "hidden": "task/hidden/rust"},
                "typescript": {"public": "task/public/typescript", "hidden": "task/hidden/typescript"},
                "semaprax-project": {"public": "task/public/semaprax", "hidden": "task/hidden/semaprax"}
            }
        }]
    });
    let path = directory.join("tasks.json");
    write_json(&path, &tasks);
    path
}

fn copy_task(directory: &Path) {
    let source = task_source();
    let task = directory.join("task");
    for language in ["rust", "typescript", "semaprax"] {
        copy_fixture_tree(
            &source.join(format!("public/{language}")),
            &task.join(format!("public/{language}")),
        );
        copy_fixture_tree(
            &source.join(format!("hidden/{language}")),
            &task.join(format!("hidden/{language}")),
        );
    }
    std::fs::copy(source.join("EQUIVALENCE.md"), task.join("EQUIVALENCE.md")).unwrap();
}

fn run_all_ports(directory: &Path, tasks: &Path, id: &str) -> (std::process::Output, PathBuf) {
    let output = directory.join("result.json");
    let result = runner()
        .arg("--root")
        .arg(directory)
        .arg("--tasks")
        .arg(tasks)
        .arg("--adapters")
        .arg(root().join(SUITE).join("adapters.json"))
        .arg("--semaprax")
        .arg(env!("CARGO_BIN_EXE_semaprax"))
        .arg("--only")
        .arg(id)
        .arg("--language")
        .arg("rust")
        .arg("--language")
        .arg("typescript")
        .arg("--language")
        .arg("semaprax-project")
        .arg("--output")
        .arg(&output)
        .output()
        .unwrap();
    (result, output)
}

#[test]
fn cold_chain_release_gate_v1_correct_candidates_pass_public_and_hidden_in_all_ports() {
    let directory = scratch("cold-chain-release-correct");
    copy_task(&directory);
    let tasks = task_inventory(&directory, "cold-chain-release-correct");
    let (result, output) = run_all_ports(&directory, &tasks, "cold-chain-release-correct");
    assert!(
        result.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&result.stderr)
    );
    let report = document(&output);
    for language in ["rust", "typescript", "semaprax-project"] {
        let record = result_for(&report, &format!("cold-chain-release-correct::{language}"));
        assert_eq!(record["status"], "ok", "{record}");
        assert_eq!(record["public"]["passed"], true, "{record}");
        assert_eq!(record["hidden"]["passed"], true, "{record}");
        assert_eq!(record["leak_check"], "ok", "{record}");
    }
}

#[test]
fn disjunctive_cold_chain_candidate_passes_public_but_fails_hidden_in_all_ports() {
    let directory = scratch("cold-chain-release-disjunction");
    copy_task(&directory);
    let task = directory.join("task");
    for (path, wrong_candidate) in [
        (
            task.join("public/rust/candidate.rs"),
            r#"pub fn release_allowed(core_temperature: i64, seal_pressure: i64) -> i64 {
    if (core_temperature >= 2 && core_temperature <= 8)
        || (seal_pressure >= 95 && seal_pressure <= 105)
    {
        1
    } else {
        0
    }
}
"#,
        ),
        (
            task.join("public/typescript/candidate.ts"),
            r#"export function releaseAllowed(coreTemperature: number, sealPressure: number): number {
  return (coreTemperature >= 2 && coreTemperature <= 8) || (sealPressure >= 95 && sealPressure <= 105)
    ? 1
    : 0;
}
"#,
        ),
        (
            task.join("public/semaprax/src/candidate.spx"),
            r#"module bench.coldchain.candidate;

@id("bench.coldchain.release_allowed")
fn release_allowed(core_temperature: i32, seal_pressure: i32) -> i32
{
    if (core_temperature >= 2i32 && core_temperature <= 8i32) || (seal_pressure >= 95i32 && seal_pressure <= 105i32) { 1i32 } else { 0i32 }
}
"#,
        ),
    ] {
        let candidate = if path.extension().is_some_and(|extension| extension == "spx") {
            semaprax::parse_canonical(wrong_candidate, &path).unwrap().1
        } else {
            wrong_candidate.to_owned()
        };
        std::fs::write(path, candidate).unwrap();
    }

    let tasks = task_inventory(&directory, "cold-chain-release-disjunction");
    let (result, output) = run_all_ports(&directory, &tasks, "cold-chain-release-disjunction");
    assert_eq!(result.status.code(), Some(1), "{result:?}");
    let report = document(&output);
    for language in ["rust", "typescript", "semaprax-project"] {
        let record = result_for(
            &report,
            &format!("cold-chain-release-disjunction::{language}"),
        );
        assert_eq!(record["public"]["passed"], true, "{language}: {record}");
        assert_eq!(record["hidden"]["passed"], false, "{language}: {record}");
        assert_eq!(record["leak_check"], "ok", "{language}: {record}");
        assert_eq!(record["status"], "failed", "{language}: {record}");
    }
}
