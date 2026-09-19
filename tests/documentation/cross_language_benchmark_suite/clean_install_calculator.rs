//! Real-toolchain regression coverage for `clean-install-calculator-v1`
//! (issue #106).
//!
//! This task's SEMAPRAX public candidate is the verbatim output of
//! `semaprax new <dest> --template calculator` (see `EQUIVALENCE.md`), plus
//! the `subtract` operation this task asks a solver to add. The negative
//! control below mutates `subtract` to a plausible mistake specific to
//! this corpus: reusing the "floor a negative result at zero" idiom this
//! same suite's `stale-edit-preservation-v1`/`bounded-counter-repair-v1`
//! use elsewhere, which is wrong for an ordinary calculator subtraction.

use super::*;

const TASK: &str = "clean-install-calculator-v1";

fn task_source() -> PathBuf {
    root().join(SUITE).join("tasks").join(TASK)
}

fn task_inventory(directory: &Path, id: &str) -> PathBuf {
    let tasks = serde_json::json!({
        "schema": "benchmark.cross_language.tasks.v1",
        "tasks": [{
            "id": id,
            "category": "onboarding",
            "split": "held_out",
            "summary": "clean-install-calculator candidate regression control",
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
fn clean_install_calculator_v1_correct_candidates_pass_public_and_hidden_in_all_ports() {
    let directory = scratch("clean-install-correct");
    copy_task(&directory);
    let tasks = task_inventory(&directory, "clean-install-correct");
    let (result, output) = run_all_ports(&directory, &tasks, "clean-install-correct");
    assert!(
        result.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&result.stderr)
    );
    let report = document(&output);
    for language in ["rust", "typescript", "semaprax-project"] {
        let record = result_for(&report, &format!("clean-install-correct::{language}"));
        assert_eq!(record["status"], "ok", "{record}");
        assert_eq!(record["public"]["passed"], true, "{record}");
        assert_eq!(record["hidden"]["passed"], true, "{record}");
        assert_eq!(record["leak_check"], "ok", "{record}");
    }
}

#[test]
#[cfg_attr(target_os = "windows", ignore = "requires Unix toolchain")]
fn a_bounded_counter_floor_habit_borrowed_from_a_neighboring_task_passes_public_but_fails_hidden_in_all_ports(
) {
    // The task-defining negative control: `subtract` clamps a negative
    // difference to zero, as this same suite's saturating/bounded-counter
    // tasks correctly do for their own domain. Every public vector's
    // subtraction is nonnegative, so this passes public; only the hidden
    // vectors with a genuinely negative difference catch the borrowed habit.
    let directory = scratch("clean-install-floor-habit");
    copy_task(&directory);
    let task = directory.join("task");

    for (path, expected, replacement) in [
        (
            task.join("public/rust/candidate.rs"),
            "pub fn subtract(left: i64, right: i64) -> i64 {\n    left - right\n}",
            "pub fn subtract(left: i64, right: i64) -> i64 {\n    let raw = left - right;\n    if raw < 0 {\n        0\n    } else {\n        raw\n    }\n}",
        ),
        (
            task.join("public/typescript/candidate.ts"),
            "export function subtract(left: number, right: number): number {\n  return left - right;\n}",
            "export function subtract(left: number, right: number): number {\n  const raw = left - right;\n  return raw < 0 ? 0 : raw;\n}",
        ),
        (
            task.join("public/semaprax/src/core.spx"),
            "@id(\"clean-install-calculator.subtract\")\nfn subtract(left: i64, right: i64) -> i64\n{\n    left - right\n}",
            "@id(\"clean-install-calculator.subtract\")\nfn subtract(left: i64, right: i64) -> i64\n{\n    let raw = left - right;\n    if raw < 0 { 0 } else { raw }\n}",
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
    // Reformat the mutated SEMAPRAX source canonically so the run step
    // scores the repair defect itself, not incidental formatting drift.
    let spx_path = task.join("public/semaprax/src/core.spx");
    let (_, canonical) =
        semaprax::parse_canonical(&std::fs::read_to_string(&spx_path).unwrap(), &spx_path).unwrap();
    std::fs::write(&spx_path, canonical).unwrap();

    let tasks = task_inventory(&directory, "clean-install-floor-habit");
    let (result, output) = run_all_ports(&directory, &tasks, "clean-install-floor-habit");
    assert_eq!(result.status.code(), Some(1), "{result:?}");
    let report = document(&output);
    for language in ["rust", "typescript", "semaprax-project"] {
        let record = result_for(&report, &format!("clean-install-floor-habit::{language}"));
        assert_eq!(record["public"]["passed"], true, "{language}: {record}");
        assert_eq!(record["hidden"]["passed"], false, "{language}: {record}");
        assert_eq!(record["leak_check"], "ok", "{language}: {record}");
        assert_eq!(record["status"], "failed", "{language}: {record}");
    }
}
