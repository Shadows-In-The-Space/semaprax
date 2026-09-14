//! Real-toolchain regression coverage for `booking-window-conflict-v1`.
//!
//! The task's candidate lives in a module shared by the public and hidden
//! scratch trees. These tests prove both the committed correct candidates and
//! the intended inclusive-end negative control through all three ports.

use super::*;

const TASK: &str = "booking-window-conflict-v1";

fn task_source() -> PathBuf {
    root().join(SUITE).join("tasks").join(TASK)
}

fn task_inventory(directory: &Path, id: &str) -> PathBuf {
    let tasks = serde_json::json!({
        "schema": "benchmark.cross_language.tasks.v1",
        "tasks": [{
            "id": id,
            "category": "repair",
            "split": "held_out",
            "summary": "half-open booking-window candidate regression control",
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
#[cfg_attr(target_os = "windows", ignore = "requires Unix toolchain")]
fn booking_window_conflict_v1_correct_candidates_pass_public_and_hidden_in_all_ports() {
    let directory = scratch("booking-window-correct");
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
    let tasks = task_inventory(&directory, "booking-window-correct");
    let (result, output) = run_all_ports(&directory, &tasks, "booking-window-correct");
    assert!(
        result.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&result.stderr)
    );
    let report = document(&output);
    for language in ["rust", "typescript", "semaprax-project"] {
        let record = result_for(&report, &format!("booking-window-correct::{language}"));
        assert_eq!(record["status"], "ok", "{record}");
        assert_eq!(record["public"]["passed"], true, "{record}");
        assert_eq!(record["hidden"]["passed"], true, "{record}");
        assert_eq!(record["leak_check"], "ok", "{record}");
    }
}

#[test]
#[cfg_attr(target_os = "windows", ignore = "requires Unix toolchain")]
fn inclusive_end_booking_candidate_passes_public_but_fails_hidden_in_all_ports() {
    let directory = scratch("booking-window-inclusive-end");
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

    for (path, expected, replacement) in [
        (
            task.join("public/rust/candidate.rs"),
            "a_start < b_end && b_start < a_end",
            "a_start <= b_end && b_start <= a_end",
        ),
        (
            task.join("public/typescript/candidate.ts"),
            "aStart < bEnd && bStart < aEnd",
            "aStart <= bEnd && bStart <= aEnd",
        ),
        (
            task.join("public/semaprax/src/candidate.spx"),
            "a_start < b_end && b_start < a_end",
            "a_start <= b_end && b_start <= a_end",
        ),
    ] {
        let source = std::fs::read_to_string(&path).unwrap();
        assert!(
            source.contains(expected),
            "mutation target missing: {}",
            path.display()
        );
        std::fs::write(path, source.replacen(expected, replacement, 1)).unwrap();
    }

    let tasks = task_inventory(&directory, "booking-window-inclusive-end");
    let (result, output) = run_all_ports(&directory, &tasks, "booking-window-inclusive-end");
    assert_eq!(result.status.code(), Some(1), "{result:?}");
    let report = document(&output);
    for language in ["rust", "typescript", "semaprax-project"] {
        let record = result_for(
            &report,
            &format!("booking-window-inclusive-end::{language}"),
        );
        assert_eq!(record["public"]["passed"], true, "{language}: {record}");
        assert_eq!(record["hidden"]["passed"], false, "{language}: {record}");
        assert_eq!(record["leak_check"], "ok", "{language}: {record}");
        assert_eq!(record["status"], "failed", "{language}: {record}");
    }
}
