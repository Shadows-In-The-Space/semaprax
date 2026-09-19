//! Real-toolchain regression coverage for `concurrent-delta-merge-v1`.
//!
//! The candidate predicate is shared by public and hidden overlays. These
//! cases prove the committed correct-merge candidate and a plausible
//! sequential-clamp bug through the Rust, TypeScript, and SEMAPRAX ports,
//! following `cold_chain_release_gate.rs`'s established pattern for this
//! suite. See `benchmarks/cross-language-v1/tasks/concurrent-delta-merge-v1/EQUIVALENCE.md`
//! for the task's oracle, boundary vectors, and hand-verified wrong-candidate
//! divergence this module now exercises automatically instead of by hand.

use super::*;

const TASK: &str = "concurrent-delta-merge-v1";

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
            "summary": "concurrent-delta-merge candidate regression control",
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
#[cfg_attr(target_os = "windows", ignore = "requires Unix toolchain")]
fn concurrent_delta_merge_v1_correct_candidates_pass_public_and_hidden_in_all_ports() {
    let directory = scratch("concurrent-delta-merge-correct");
    copy_task(&directory);
    let tasks = task_inventory(&directory, "concurrent-delta-merge-correct");
    let (result, output) = run_all_ports(&directory, &tasks, "concurrent-delta-merge-correct");
    assert!(
        result.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&result.stderr)
    );
    let report = document(&output);
    for language in ["rust", "typescript", "semaprax-project"] {
        let record = result_for(
            &report,
            &format!("concurrent-delta-merge-correct::{language}"),
        );
        assert_eq!(record["status"], "ok", "{record}");
        assert_eq!(record["public"]["passed"], true, "{record}");
        assert_eq!(record["hidden"]["passed"], true, "{record}");
        assert_eq!(record["leak_check"], "ok", "{record}");
    }
}

#[test]
#[cfg_attr(target_os = "windows", ignore = "requires Unix toolchain")]
fn sequential_clamp_candidate_passes_public_but_fails_hidden_in_all_ports() {
    let directory = scratch("concurrent-delta-merge-sequential");
    copy_task(&directory);
    let task = directory.join("task");
    // The sequential-clamp bug this task is built to catch: apply `delta_a`
    // to `base` and clamp immediately, then apply `delta_b` to that
    // already-clamped result and clamp again, instead of folding both
    // deltas into `base` before ever touching a bound. This agrees with the
    // correct concurrent merge on every public vector (none pushes the
    // intermediate one-delta sum outside [0, 1_000_000]) and diverges on
    // both hidden boundary vectors, exactly as EQUIVALENCE.md hand-verifies
    // against real rustc/tsc/semaprax.
    for (path, wrong_candidate) in [
        (
            task.join("public/rust/candidate.rs"),
            r#"fn clamp(value: i64) -> i64 {
    if value < 0 {
        0
    } else if value > 1_000_000 {
        1_000_000
    } else {
        value
    }
}

pub fn merge_concurrent_deltas(base: i64, delta_a: i64, delta_b: i64) -> i64 {
    clamp(clamp(base + delta_a) + delta_b)
}
"#,
        ),
        (
            task.join("public/typescript/candidate.ts"),
            r#"function clamp(value: number): number {
  if (value < 0) return 0;
  if (value > 1_000_000) return 1_000_000;
  return value;
}

export function mergeConcurrentDeltas(base: number, deltaA: number, deltaB: number): number {
  return clamp(clamp(base + deltaA) + deltaB);
}
"#,
        ),
        (
            task.join("public/semaprax/src/candidate.spx"),
            r#"module bench.concurrentmerge.candidate;

@id("bench.concurrentmerge.merge_concurrent_deltas")
fn merge_concurrent_deltas(base: i64, delta_a: i64, delta_b: i64) -> i64
{
    let first = base + delta_a;
    let clamped_first = if first < 0 { 0 } else { if first > 1000000 { 1000000 } else { first } };
    let second = clamped_first + delta_b;
    if second < 0 { 0 } else { if second > 1000000 { 1000000 } else { second } }
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

    let tasks = task_inventory(&directory, "concurrent-delta-merge-sequential");
    let (result, output) = run_all_ports(&directory, &tasks, "concurrent-delta-merge-sequential");
    assert_eq!(result.status.code(), Some(1), "{result:?}");
    let report = document(&output);
    for language in ["rust", "typescript", "semaprax-project"] {
        let record = result_for(
            &report,
            &format!("concurrent-delta-merge-sequential::{language}"),
        );
        assert_eq!(record["public"]["passed"], true, "{language}: {record}");
        assert_eq!(record["hidden"]["passed"], false, "{language}: {record}");
        assert_eq!(record["leak_check"], "ok", "{language}: {record}");
        assert_eq!(record["status"], "failed", "{language}: {record}");
    }
}
