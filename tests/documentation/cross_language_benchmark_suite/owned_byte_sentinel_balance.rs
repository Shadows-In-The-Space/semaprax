//! Real-toolchain regression coverage for `owned-byte-sentinel-balance-v1`.
//!
//! The candidate consumes or copies into an owned byte buffer, maps sentinel
//! values, and computes a positional checksum. Hidden entry points import the
//! public candidate, so visible assertion edits cannot affect hidden scoring.

use super::*;

const TASK: &str = "owned-byte-sentinel-balance-v1";

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
            "summary": "owned-byte mapping and positional checksum regression control",
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

fn assert_ok(report: &Value, id: &str) {
    for language in ["rust", "typescript", "semaprax-project"] {
        let record = result_for(report, &format!("{id}::{language}"));
        assert_eq!(record["status"], "ok", "{record}");
        assert_eq!(record["public"]["passed"], true, "{record}");
        assert_eq!(record["hidden"]["passed"], true, "{record}");
        assert_eq!(record["leak_check"], "ok", "{record}");
    }
}

#[test]
fn owned_byte_sentinel_balance_correct_candidates_pass_public_and_hidden_in_all_ports() {
    let directory = scratch("owned-byte-sentinel-correct");
    copy_task(&directory);
    let tasks = task_inventory(&directory, "owned-byte-sentinel-correct");
    let (result, output) = run_all_ports(&directory, &tasks, "owned-byte-sentinel-correct");
    assert!(
        result.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert_ok(&document(&output), "owned-byte-sentinel-correct");
}

#[test]
fn forgetting_zero_mapping_passes_public_but_fails_hidden_in_all_ports() {
    let directory = scratch("owned-byte-sentinel-wrong-candidate");
    copy_task(&directory);
    let task = directory.join("task");
    for (path, expected, replacement) in [
        (
            task.join("public/rust/candidate.rs"),
            "*byte = 0xff;",
            "*byte = 0x01;",
        ),
        (
            task.join("public/typescript/candidate.ts"),
            "transformed[index] = 0xff;",
            "transformed[index] = 0x01;",
        ),
        (
            task.join("public/semaprax/src/app.spx"),
            "if byte == 0u8 { 255u8 } else { 1u8 }",
            "if byte == 0u8 { 1u8 } else { 1u8 }",
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

    let tasks = task_inventory(&directory, "owned-byte-sentinel-wrong-candidate");
    let (result, output) = run_all_ports(&directory, &tasks, "owned-byte-sentinel-wrong-candidate");
    assert_eq!(result.status.code(), Some(1), "{result:?}");
    let report = document(&output);
    for language in ["rust", "typescript", "semaprax-project"] {
        let record = result_for(
            &report,
            &format!("owned-byte-sentinel-wrong-candidate::{language}"),
        );
        assert_eq!(record["public"]["passed"], true, "{language}: {record}");
        assert_eq!(record["hidden"]["passed"], false, "{language}: {record}");
        assert_eq!(record["leak_check"], "ok", "{language}: {record}");
        assert_eq!(record["status"], "failed", "{language}: {record}");
    }
}

#[test]
fn deleting_visible_assertions_does_not_change_hidden_owned_byte_rejection() {
    let directory = scratch("owned-byte-sentinel-visible-tamper");
    copy_task(&directory);
    let task = directory.join("task");
    for (path, expected, replacement) in [
        (
            task.join("public/rust/candidate.rs"),
            "*byte = 0xff;",
            "*byte = 0x01;",
        ),
        (
            task.join("public/typescript/candidate.ts"),
            "transformed[index] = 0xff;",
            "transformed[index] = 0x01;",
        ),
        (
            task.join("public/semaprax/src/app.spx"),
            "if byte == 0u8 { 255u8 } else { 1u8 }",
            "if byte == 0u8 { 1u8 } else { 1u8 }",
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
    std::fs::write(task.join("public/rust/main.rs"), "fn main() {}\n").unwrap();
    std::fs::write(task.join("public/typescript/index.ts"), "export {};\n").unwrap();
    std::fs::write(
        task.join("public/semaprax/src/entry.spx"),
        "module bench.owned.entry;\n\n@id(\"bench.owned.entry.main\")\nfn main() -> i64\n{\n    0\n}\n",
    )
    .unwrap();
    let tasks = task_inventory(&directory, "owned-byte-sentinel-visible-tamper");
    let (result, output) = run_all_ports(&directory, &tasks, "owned-byte-sentinel-visible-tamper");
    assert_eq!(result.status.code(), Some(1), "{result:?}");
    let report = document(&output);
    for language in ["rust", "typescript", "semaprax-project"] {
        let record = result_for(
            &report,
            &format!("owned-byte-sentinel-visible-tamper::{language}"),
        );
        assert_eq!(record["public"]["passed"], true, "{language}: {record}");
        assert_eq!(record["hidden"]["passed"], false, "{language}: {record}");
        assert_eq!(record["leak_check"], "ok", "{language}: {record}");
        assert_eq!(record["status"], "failed", "{language}: {record}");
    }
}
