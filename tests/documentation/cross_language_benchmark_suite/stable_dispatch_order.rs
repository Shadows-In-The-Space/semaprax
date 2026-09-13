//! Real-toolchain regression coverage for `stable-dispatch-order-v1`.
//!
//! The candidate orderer is shared by public and hidden overlays. These tests
//! prove stable tie handling and a strict-comparison negative control through
//! Rust, TypeScript, and SEMAPRAX.

use super::*;

const TASK: &str = "stable-dispatch-order-v1";

fn task_source() -> PathBuf {
    root().join(SUITE).join("tasks").join(TASK)
}

fn task_inventory(directory: &Path, id: &str) -> PathBuf {
    let tasks = serde_json::json!({
        "schema": "benchmark.cross_language.tasks.v1",
        "tasks": [{
            "id": id,
            "category": "greenfield",
            "split": "held_out",
            "summary": "stable dispatch ordering candidate regression control",
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
fn stable_dispatch_order_v1_correct_candidates_pass_public_and_hidden_in_all_ports() {
    let directory = scratch("stable-dispatch-correct");
    copy_task(&directory);
    let tasks = task_inventory(&directory, "stable-dispatch-correct");
    let (result, output) = run_all_ports(&directory, &tasks, "stable-dispatch-correct");
    assert!(
        result.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&result.stderr)
    );
    let report = document(&output);
    for language in ["rust", "typescript", "semaprax-project"] {
        let record = result_for(&report, &format!("stable-dispatch-correct::{language}"));
        assert_eq!(record["status"], "ok", "{record}");
        assert_eq!(record["public"]["passed"], true, "{record}");
        assert_eq!(record["hidden"]["passed"], true, "{record}");
        assert_eq!(record["leak_check"], "ok", "{record}");
    }
}

#[test]
fn strict_comparison_dispatch_candidate_passes_public_but_fails_hidden_in_all_ports() {
    let directory = scratch("stable-dispatch-strict-comparisons");
    copy_task(&directory);
    let task = directory.join("task");
    for path in [
        task.join("public/rust/candidate.rs"),
        task.join("public/typescript/candidate.ts"),
        task.join("public/semaprax/src/candidate.spx"),
    ] {
        let source = std::fs::read_to_string(&path).unwrap();
        assert!(
            source.contains("<="),
            "mutation target missing: {}",
            path.display()
        );
        std::fs::write(path, source.replace("<=", "<")).unwrap();
    }

    let tasks = task_inventory(&directory, "stable-dispatch-strict-comparisons");
    let (result, output) = run_all_ports(&directory, &tasks, "stable-dispatch-strict-comparisons");
    assert_eq!(result.status.code(), Some(1), "{result:?}");
    let report = document(&output);
    for language in ["rust", "typescript", "semaprax-project"] {
        let record = result_for(
            &report,
            &format!("stable-dispatch-strict-comparisons::{language}"),
        );
        assert_eq!(record["public"]["passed"], true, "{language}: {record}");
        assert_eq!(record["hidden"]["passed"], false, "{language}: {record}");
        assert_eq!(record["leak_check"], "ok", "{language}: {record}");
        assert_eq!(record["status"], "failed", "{language}: {record}");
    }
}
