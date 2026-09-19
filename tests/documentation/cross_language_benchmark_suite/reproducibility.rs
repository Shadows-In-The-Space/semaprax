//! Cross-host reproducibility proxy for the laboratory's own scoring inputs
//! (issue #211's "Reproduction on a second host yields equivalent scoring
//! inputs" required-evidence row).
//!
//! There is no second physical host in this sandbox, and this module does
//! not claim to have run on one --
//! `python_entry_point_resolves_the_committed_suite_from_any_working_directory`
//! already proves working-directory independence on this one host, and
//! `docs/METHODOLOGY.md` records host reproduction as unverified beyond
//! that. What *is* available here is process/environment variation for the
//! axes that legitimately differ between two real hosts and that a naive
//! implementation could accidentally let leak into scoring output: the
//! interpreter's per-process hash seed (Python randomizes this by default,
//! so an implementation that ever iterated a `dict`/`set` into JSON without
//! sorting would already be nondeterministic *within a single host*, let
//! alone across two), the active locale (which changes str/path sort order
//! under some libc configurations), the system timezone, and the base
//! temporary-directory root each host's scratch trees are created under.
//!
//! This is not a substitute for running on an actual second machine --
//! `host_facts()` (platform/release/cpu_count/python version) is out of
//! scope for this comparison, exactly as `docs/METHODOLOGY.md`'s "No
//! timing" section already treats the host block as informational, not
//! comparable. What this test does check: with those four axes forced to
//! disagree between two subprocess runs, the harness's *scoring-relevant*
//! document fields -- schema, revision, summary, and every result's
//! status/leak_check/public/hidden/provenance -- come back identical as
//! parsed JSON. Only `timestamp` (a wall-clock value by design) is excluded
//! from the comparison.

use super::*;

#[allow(clippy::too_many_arguments)]
fn run_with_environment(
    directory: &Path,
    tasks_path: &Path,
    adapters_path: &Path,
    output: &Path,
    hash_seed: &str,
    locale: &str,
    timezone: &str,
    tmp_root: &Path,
) -> Value {
    std::fs::create_dir_all(tmp_root).unwrap();
    let result = runner()
        .arg("--root")
        .arg(directory)
        .arg("--tasks")
        .arg(tasks_path)
        .arg("--adapters")
        .arg(adapters_path)
        .arg("--output")
        .arg(output)
        .env("PYTHONHASHSEED", hash_seed)
        .env("LC_ALL", locale)
        .env("LANG", locale)
        .env("TZ", timezone)
        .env("TMPDIR", tmp_root)
        .output()
        .unwrap();
    assert!(
        result.status.code() == Some(0) || result.status.code() == Some(1),
        "run.py crashed under PYTHONHASHSEED={hash_seed} LC_ALL={locale} TZ={timezone}: {}",
        String::from_utf8_lossy(&result.stderr)
    );
    document(output)
}

/// What this catches: any code path in `run.py` that serializes a `dict` or
/// `set` (Python's hash-seed-randomized iteration order) into the result
/// document without first sorting it. Reverting `digest_tree`'s
/// `sorted(directory.rglob("*"))` call to an unsorted `directory.rglob("*")`
/// reproduces exactly this failure mode: the same bytes hashed in a
/// different (hash-seed- and filesystem-order-dependent) sequence produce a
/// different digest under one of the two forced seeds below, and this test
/// turns red instead of the drift being invisible on a single developer
/// machine that always happens to get the same random seed.
#[test]
fn scoring_document_is_identical_across_varied_hash_seed_locale_timezone_and_scratch_root() {
    let directory = scratch("repro-mock");
    let task_dir = directory.join("task");
    write_mock_language(
        &task_dir,
        &MockLanguage {
            id: "mockok",
            exit_code: 0,
            hidden_exit_code: None,
        },
    );
    write_mock_language(
        &task_dir,
        &MockLanguage {
            id: "mockfail",
            exit_code: 0,
            hidden_exit_code: Some(1),
        },
    );
    let adapters_path = directory.join("adapters.json");
    let tasks_path = directory.join("tasks.json");
    write_json(
        &adapters_path,
        &mock_adapters_document(&["mockok", "mockfail"]),
    );
    write_json(
        &tasks_path,
        &mock_tasks_document("mock-task", &["mockok", "mockfail"]),
    );

    let output_a = directory.join("result-a.json");
    let output_b = directory.join("result-b.json");

    // Two "hosts" that disagree on every axis a real second machine could
    // plausibly disagree on, except the one this test cannot vary from
    // inside a single process (the CPU/OS identity `host_facts()` reports),
    // which this comparison deliberately does not claim to cover.
    let document_a = run_with_environment(
        &directory,
        &tasks_path,
        &adapters_path,
        &output_a,
        "0",
        "C",
        "UTC",
        &directory.join("tmp-a"),
    );
    let document_b = run_with_environment(
        &directory,
        &tasks_path,
        &adapters_path,
        &output_b,
        "4276993775",
        "en_US.UTF-8",
        "Pacific/Kiritimati",
        &directory.join("tmp-b"),
    );

    let strip_timestamp = |mut value: Value| {
        value.as_object_mut().unwrap().remove("timestamp");
        value
    };
    let a = strip_timestamp(document_a);
    let b = strip_timestamp(document_b);

    assert_eq!(a["schema"], b["schema"]);
    assert_eq!(a["revision"], b["revision"]);
    assert_eq!(a["summary"], b["summary"]);
    assert_eq!(
        a["results"], b["results"],
        "scoring output (status/leak_check/public/hidden/provenance) must not \
         depend on hash seed, locale, timezone, or scratch root: a={a} b={b}"
    );
}
