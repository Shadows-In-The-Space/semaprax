//! Real-toolchain regression coverage for `stale-edit-preservation-v1`
//! (issue #106).
//!
//! This task's candidate module carries two independent functions: the one
//! the task asks a solver to repair (`apply_discount`), and one left by a
//! "prior session" that is out of scope for the repair (`stale_note`). The
//! task exists to catch a solver that repairs the first while clobbering the
//! second -- a failure mode none of this suite's other tasks can detect,
//! since every other task's candidate module contains only in-scope code.

use super::*;

const TASK: &str = "stale-edit-preservation-v1";

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
            "summary": "stale-edit-preservation candidate regression control",
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

#[test]
#[cfg_attr(target_os = "windows", ignore = "requires Unix toolchain")]
fn stale_edit_preservation_v1_correct_candidates_pass_public_and_hidden_in_all_ports() {
    let directory = scratch("stale-edit-correct");
    copy_task(&directory);
    let tasks = task_inventory(&directory, "stale-edit-correct");
    let (result, output) = run_all_ports(&directory, &tasks, "stale-edit-correct");
    assert!(
        result.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&result.stderr)
    );
    let report = document(&output);
    for language in ["rust", "typescript", "semaprax-project"] {
        let record = result_for(&report, &format!("stale-edit-correct::{language}"));
        assert_eq!(record["status"], "ok", "{record}");
        assert_eq!(record["public"]["passed"], true, "{record}");
        assert_eq!(record["hidden"]["passed"], true, "{record}");
        assert_eq!(record["leak_check"], "ok", "{record}");
    }
}

#[test]
#[cfg_attr(target_os = "windows", ignore = "requires Unix toolchain")]
fn a_missing_zero_floor_repair_passes_public_but_fails_hidden_in_all_ports() {
    // A plausible *incomplete* repair: it never clamps a corrupted
    // percentage's result to zero. Every public vector uses a percentage at
    // or below 100, so this passes public and only the hidden
    // corrupted-percentage vectors catch it.
    let directory = scratch("stale-edit-missing-clamp");
    copy_task(&directory);
    let task = directory.join("task");

    for (path, expected, replacement) in [
        (
            task.join("public/rust/candidate.rs"),
            "let raw = price - (price * pct) / 100;\n    if raw < 0 {\n        0\n    } else {\n        raw\n    }",
            "price - (price * pct) / 100",
        ),
        (
            task.join("public/typescript/candidate.ts"),
            "const raw = price - Math.trunc((price * pct) / 100);\n  return raw < 0 ? 0 : raw;",
            "return price - Math.trunc((price * pct) / 100);",
        ),
        (
            task.join("public/semaprax/src/candidate.spx"),
            "let raw = price - price * pct / 100i32;\n    if raw < 0i32 { 0i32 } else { raw }",
            "price - price * pct / 100i32",
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
    // The SEMAPRAX mutation above drops the surrounding braces' interior to
    // a bare expression; reformat it canonically so the run step scores the
    // repair defect itself, not incidental formatting drift.
    let spx_path = task.join("public/semaprax/src/candidate.spx");
    let (_, canonical) =
        semaprax::parse_canonical(&std::fs::read_to_string(&spx_path).unwrap(), &spx_path).unwrap();
    std::fs::write(&spx_path, canonical).unwrap();

    let tasks = task_inventory(&directory, "stale-edit-missing-clamp");
    let (result, output) = run_all_ports(&directory, &tasks, "stale-edit-missing-clamp");
    assert_eq!(result.status.code(), Some(1), "{result:?}");
    let report = document(&output);
    for language in ["rust", "typescript", "semaprax-project"] {
        let record = result_for(&report, &format!("stale-edit-missing-clamp::{language}"));
        assert_eq!(record["public"]["passed"], true, "{language}: {record}");
        assert_eq!(record["hidden"]["passed"], false, "{language}: {record}");
        assert_eq!(record["leak_check"], "ok", "{language}: {record}");
        assert_eq!(record["status"], "failed", "{language}: {record}");
    }
}

#[test]
#[cfg_attr(target_os = "windows", ignore = "requires Unix toolchain")]
fn a_candidate_that_deletes_the_preexisting_stale_helper_passes_public_but_fails_hidden_in_all_ports(
) {
    // The task-defining negative control: `apply_discount`'s repair stays
    // intact and correct, but the unrelated, already-completed
    // `stale_note`/`staleNote` helper is deleted, as an over-aggressive
    // "cleanup" edit might do. No public vector calls it, so this passes
    // public; only the hidden vectors that call it directly catch the loss.
    let directory = scratch("stale-edit-deleted-helper");
    copy_task(&directory);
    let task = directory.join("task");

    std::fs::write(
        task.join("public/rust/candidate.rs"),
        "pub fn apply_discount(price: i64, pct: i64) -> i64 {\n    let raw = price - (price * pct) / 100;\n    if raw < 0 {\n        0\n    } else {\n        raw\n    }\n}\n",
    )
    .unwrap();
    std::fs::write(
        task.join("public/typescript/candidate.ts"),
        "export function applyDiscount(price: number, pct: number): number {\n  const raw = price - Math.trunc((price * pct) / 100);\n  return raw < 0 ? 0 : raw;\n}\n",
    )
    .unwrap();
    let spx_path = task.join("public/semaprax/src/candidate.spx");
    let spx_source = "module bench.stale.candidate;\n\n@id(\"bench.stale.apply_discount\")\nfn apply_discount(price: i32, pct: i32) -> i32\n{\n    let raw = price - price * pct / 100i32;\n    if raw < 0i32 { 0i32 } else { raw }\n}\n";
    let (_, canonical) = semaprax::parse_canonical(spx_source, &spx_path).unwrap();
    std::fs::write(&spx_path, canonical).unwrap();

    let tasks = task_inventory(&directory, "stale-edit-deleted-helper");
    let (result, output) = run_all_ports(&directory, &tasks, "stale-edit-deleted-helper");
    assert_eq!(result.status.code(), Some(1), "{result:?}");
    let report = document(&output);
    for language in ["rust", "typescript", "semaprax-project"] {
        let record = result_for(&report, &format!("stale-edit-deleted-helper::{language}"));
        assert_eq!(record["public"]["passed"], true, "{language}: {record}");
        assert_eq!(record["hidden"]["passed"], false, "{language}: {record}");
        assert_eq!(record["leak_check"], "ok", "{language}: {record}");
        assert_eq!(record["status"], "failed", "{language}: {record}");
    }
}
