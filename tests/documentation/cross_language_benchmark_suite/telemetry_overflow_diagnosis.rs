//! Real-toolchain regression coverage for `telemetry-overflow-diagnosis-v1`
//! (issue #106).
//!
//! This task's candidate module computes `delta_a + delta_b`, saturated to
//! the signed 32-bit range, and never wraps, traps, or leaves that range.
//! Public vectors never approach the boundary, so an unguarded addition
//! coincidentally matches the correct answer there; only the hidden
//! boundary vectors catch the missing saturation guard -- and catch it
//! through three genuinely different failure mechanisms in the three real
//! ports (a Rust debug-build overflow panic, a silently out-of-range
//! TypeScript number, and a SEMAPRAX checked-arithmetic fault), exactly as
//! `EQUIVALENCE.md` explains.

use super::*;

const TASK: &str = "telemetry-overflow-diagnosis-v1";

fn task_source() -> PathBuf {
    root().join(SUITE).join("tasks").join(TASK)
}

fn task_inventory(directory: &Path, id: &str) -> PathBuf {
    let tasks = serde_json::json!({
        "schema": "benchmark.cross_language.tasks.v1",
        "tasks": [{
            "id": id,
            "category": "diagnosis",
            "split": "held_out",
            "summary": "telemetry-overflow-diagnosis candidate regression control",
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
fn telemetry_overflow_diagnosis_v1_correct_candidates_pass_public_and_hidden_in_all_ports() {
    let directory = scratch("telemetry-overflow-correct");
    copy_task(&directory);
    let tasks = task_inventory(&directory, "telemetry-overflow-correct");
    let (result, output) = run_all_ports(&directory, &tasks, "telemetry-overflow-correct");
    assert!(
        result.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&result.stderr)
    );
    let report = document(&output);
    for language in ["rust", "typescript", "semaprax-project"] {
        let record = result_for(&report, &format!("telemetry-overflow-correct::{language}"));
        assert_eq!(record["status"], "ok", "{record}");
        assert_eq!(record["public"]["passed"], true, "{record}");
        assert_eq!(record["hidden"]["passed"], true, "{record}");
        assert_eq!(record["leak_check"], "ok", "{record}");
    }
}

#[test]
#[cfg_attr(target_os = "windows", ignore = "requires Unix toolchain")]
fn an_unguarded_addition_passes_public_but_fails_hidden_in_all_three_ports_for_three_different_reasons(
) {
    // The task-defining negative control: dropping the saturation guard
    // leaves a plain `delta_a + delta_b`, which coincidentally matches the
    // correct answer for every public (non-boundary) vector, and only the
    // hidden boundary vectors catch it -- through three distinct failure
    // mechanisms this asserts on directly, not merely "hidden failed".
    let directory = scratch("telemetry-overflow-unguarded");
    copy_task(&directory);
    let task = directory.join("task");

    for (path, expected, replacement) in [
        (
            task.join("public/rust/candidate.rs"),
            "if delta_b > 0 && delta_a > i32::MAX - delta_b {\n        i32::MAX\n    } else if delta_b < 0 && delta_a < i32::MIN - delta_b {\n        i32::MIN\n    } else {\n        delta_a + delta_b\n    }",
            "delta_a + delta_b",
        ),
        (
            task.join("public/typescript/candidate.ts"),
            "if (deltaB > 0 && deltaA > I32_MAX - deltaB) return I32_MAX;\n  if (deltaB < 0 && deltaA < I32_MIN - deltaB) return I32_MIN;\n  return deltaA + deltaB;",
            "return deltaA + deltaB;",
        ),
        (
            task.join("public/semaprax/src/candidate.spx"),
            "if delta_b > 0i32 { if delta_a > 2147483647i32 - delta_b { 2147483647i32 } else { delta_a + delta_b } } else { if delta_b < 0i32 { if delta_a < -2147483648i32 - delta_b { -2147483648i32 } else { delta_a + delta_b } } else { delta_a + delta_b } }",
            "delta_a + delta_b",
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

    let tasks = task_inventory(&directory, "telemetry-overflow-unguarded");
    let (result, output) = run_all_ports(&directory, &tasks, "telemetry-overflow-unguarded");
    assert_eq!(result.status.code(), Some(1), "{result:?}");
    let report = document(&output);
    for language in ["rust", "typescript", "semaprax-project"] {
        let record = result_for(
            &report,
            &format!("telemetry-overflow-unguarded::{language}"),
        );
        assert_eq!(record["public"]["passed"], true, "{language}: {record}");
        assert_eq!(record["hidden"]["passed"], false, "{language}: {record}");
        assert_eq!(record["leak_check"], "ok", "{language}: {record}");
        assert_eq!(record["status"], "failed", "{language}: {record}");
    }
}
