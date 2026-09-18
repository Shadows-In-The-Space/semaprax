#!/usr/bin/env python3
"""Fresh-process cold/warm/edited/recovered semantic-cache workflow timing.

Each scenario below is one or more literal, independent `semaprax` process
launches driving the persistent semantic-cache CLI
(`semantic-cache-cold-open`, `semantic-cache-warm-open`,
`semantic-cache-persist`, `semantic-cache-evict`; see
docs/PERSISTENT-SEMANTIC-CACHE-V1.md). `cold-open` and `warm-open` share one
code path (`VNextSession::open_with_semantic_cache` /
`open_with_retained_semantic_cache`) and differ only in whether a persisted
cache is threaded in, so comparing one fresh process of each isolates cache
state as the only varying input — see
`tests/semantic_cache_store_cli_v1.rs::cold_open_and_warm_open_agree_on_unchanged_source_and_isolate_cache_state`
for the same guarantee proven functionally.

This script does NOT gate on a quiet host. It is meant to run on whatever
machine is available, including a loaded one, and it records host load before
and after every single repetition specifically so a loaded run is never
silently reported as clean. Compare host_before/host_after across the JSON
output before citing any number from it as a magnitude rather than a shape.

What is measured:
  - Wall time: `time.perf_counter()` around the whole subprocess (matches
    `run.py`'s macro methodology) — this is genuine cross-process latency,
    process spawn included.
  - Peak resident set size, where the host provides one: macOS via
    `/usr/bin/time -l` ("maximum resident set size", bytes), Linux via
    `/usr/bin/time -v` ("Maximum resident set size", KiB, converted to
    bytes). Any other platform, or a `/usr/bin/time` that does not exist or
    does not support the flag, records `peak_rss_bytes: null` with
    `peak_rss_basis` naming why — never an estimate.

Scenarios, each run for `--repetitions` independent fresh processes:
  - cold_open: no persisted cache exists yet.
  - warm_open_unchanged: cache persisted from the exact same source.
  - warm_open_local_edit: one leaf module (`src/app.spx`, which nothing in
    the fixture imports) gets a commuted, result-identical body edit before
    the warm open; the persisted entry is unchanged.
  - warm_open_provider_edit: the shared provider (`src/core.spx`, imported by
    both other modules) gets the same kind of body edit; this exercises the
    conservative reverse-import invalidation the docs describe, not just the
    edited module.
  - stale_recovery: the persisted entry is evicted, so the following
    warm-open attempt fails closed (this is timed and recorded as a failure,
    not silently skipped); the following cold-open is the caller's actual
    recovery path.

Non-claims: this is local, single-host, single-build evidence. It is not a
hosted, cross-platform, or production benchmark, and no speedup or magnitude
claim should be quoted from it without checking `host_before`/`host_after`
and `profile` in the same run's output first.
"""
import argparse
import importlib.util
import json
import os
import pathlib
import platform
import re
import shutil
import statistics
import subprocess
import sys
import time

SUITE = pathlib.Path(__file__).resolve().parent
ROOT = SUITE.parent.parent
SCHEMA = "benchmark.semantic-cache-workflow.v1"
SPEC = importlib.util.spec_from_file_location("performance_runner", SUITE / "run.py")
PERFORMANCE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PERFORMANCE)

FIXTURE_FILES = ["semaprax.toml", "src/app.spx", "src/core.spx", "src/tests.spx"]
SCENARIOS = [
    "cold_open",
    "warm_open_unchanged",
    "warm_open_local_edit",
    "warm_open_provider_edit",
    "stale_recovery",
]


def peak_rss(stderr_text: str):
    """Parse peak RSS from a `/usr/bin/time -l` (macOS) or `-v` (Linux)
    report already captured in `stderr_text`. Returns (bytes_or_None, basis)."""
    system = platform.system()
    if system == "Darwin":
        match = re.search(r"(\d+)\s+maximum resident set size", stderr_text)
        if match:
            return int(match.group(1)), "darwin_time_dash_l_maximum_resident_set_size_bytes"
        return None, "darwin_time_dash_l_output_not_found"
    if system == "Linux":
        match = re.search(r"Maximum resident set size \(kbytes\):\s*(\d+)", stderr_text)
        if match:
            return int(match.group(1)) * 1024, "linux_time_dash_v_maximum_resident_set_size_kib"
        return None, "linux_time_dash_v_output_not_found"
    return None, f"unsupported_platform_{system.lower()}"


def time_wrapper():
    """The `/usr/bin/time` invocation prefix for this platform, or None if
    the peak-RSS-reporting flag this script parses is not available here."""
    time_bin = shutil.which("time") or "/usr/bin/time"
    if not pathlib.Path(time_bin).exists():
        return None
    system = platform.system()
    if system == "Darwin":
        return [time_bin, "-l"]
    if system == "Linux":
        return [time_bin, "-v"]
    return None


def run_process(argv, cwd, role: str, expect_ok: bool = True):
    """One fresh-process invocation. Returns a JSON-safe record: wall time via
    an outer perf_counter (never trusts `/usr/bin/time`'s own "real" field,
    which has coarser resolution), exit status, stdout/stderr, and peak RSS
    parsed from `/usr/bin/time`'s report when available. `role` labels what
    this record measures within its scenario (e.g. a scenario with more than
    one process per repetition), independent of whether it happened to
    succeed; `expect_ok=False` marks a record whose success would itself be
    the anomaly (the deliberately failing half of `stale_recovery`)."""
    wrapper = time_wrapper()
    command = (wrapper + argv) if wrapper else argv
    host_before = PERFORMANCE.host_facts()
    start = time.perf_counter()
    completed = subprocess.run(
        command, cwd=cwd, capture_output=True, timeout=120, check=False
    )
    wall_seconds = time.perf_counter() - start
    host_after = PERFORMANCE.host_facts()
    stderr_text = completed.stderr.decode("utf-8", errors="replace")
    rss_bytes, rss_basis = (peak_rss(stderr_text) if wrapper else (None, "time_command_unavailable"))
    ok = completed.returncode == 0
    return {
        "role": role,
        "argv": argv,
        "exit_code": completed.returncode,
        "ok": ok,
        "matched_expectation": ok == expect_ok,
        "wall_seconds": wall_seconds,
        "peak_rss_bytes": rss_bytes,
        "peak_rss_basis": rss_basis,
        "stdout_bytes": len(completed.stdout),
        "stderr_tail": stderr_text[-2048:] if not ok else "",
        "host_before": host_before,
        "host_after": host_after,
    }


def write_fixture(directory: pathlib.Path):
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "src").mkdir(exist_ok=True)
    example = ROOT / "examples" / "calculator-project"
    for relative in FIXTURE_FILES:
        (directory / relative).write_bytes((example / relative).read_bytes())


def edit_leaf(directory: pathlib.Path):
    """A commuted, result-identical body edit to the module nothing else in
    the fixture imports. Must stay canonical, so it is regenerated through
    the compiler's own formatter via the `semaprax fmt` command."""
    path = directory / "src/app.spx"
    path.write_text(
        path.read_text().replace("multiply(6, 7)", "multiply(7, 6)"), encoding="utf-8"
    )


def edit_provider(directory: pathlib.Path):
    """A commuted, result-identical body edit to the shared provider module,
    imported by both other modules in the fixture."""
    path = directory / "src/core.spx"
    path.write_text(
        path.read_text().replace("left + right", "right + left"), encoding="utf-8"
    )


def canonicalize(binary: pathlib.Path, directory: pathlib.Path):
    for relative in ("src/app.spx", "src/core.spx"):
        path = directory / relative
        completed = subprocess.run(
            [str(binary), "fmt", str(path)], capture_output=True, timeout=30, check=False
        )
        if completed.returncode != 0:
            raise RuntimeError(
                f"fixture edit at {relative} did not stay admissible: "
                f"{completed.stderr.decode(errors='replace')}"
            )


def install_compiler(source: pathlib.Path, scratch: pathlib.Path) -> pathlib.Path:
    """The persistent semantic-cache store binds the exact compiler
    executable and rejects any installation that is not a single-link,
    non-group/other-writable regular file (see `semantic_cache_store/unix.rs`
    `compiler_fact`). A live `target/debug/semaprax` fails that check
    whenever a concurrent `cargo build`/`cargo test` is relinking it — which,
    on this shared checkout, is routine, not exceptional. Stage a private,
    read-only, single-link copy once and use only that copy for every
    subprocess this script launches, exactly as
    `tests/semantic_cache_store_cli_v1.rs`'s `Fixture` does."""
    installed = scratch / "semaprax-installed"
    if installed.exists():
        return installed
    staged = scratch / ".semaprax-installed.stage"
    with source.open("rb") as reader, staged.open("wb") as writer:
        shutil.copyfileobj(reader, writer)
        writer.flush()
        os.fsync(writer.fileno())
    staged.rename(installed)
    installed.chmod(0o555)
    stat = installed.stat()
    if stat.st_nlink != 1 or (stat.st_mode & 0o022) != 0:
        raise RuntimeError(
            f"staged compiler copy failed the single-link/no-group-write invariant: nlink={stat.st_nlink} mode={oct(stat.st_mode)}"
        )
    return installed


def init_store(binary: pathlib.Path, store: pathlib.Path):
    if store.exists():
        shutil.rmtree(store)
    store.mkdir(mode=0o700)
    completed = subprocess.run(
        [str(binary), "semantic-cache-init", str(store)],
        capture_output=True, timeout=30, check=False,
    )
    if completed.returncode != 0:
        raise RuntimeError(f"semantic-cache-init failed: {completed.stderr.decode(errors='replace')}")


def persist(binary: pathlib.Path, manifest: pathlib.Path, store: pathlib.Path):
    completed = subprocess.run(
        [str(binary), "semantic-cache-persist", str(manifest), str(store)],
        capture_output=True, timeout=30, check=False,
    )
    if completed.returncode != 0:
        raise RuntimeError(f"semantic-cache-persist failed: {completed.stderr.decode(errors='replace')}")
    return json.loads(completed.stdout)["entry_digest"]


def evict(binary: pathlib.Path, store: pathlib.Path, digest: str):
    subprocess.run(
        [str(binary), "semantic-cache-evict", str(store), digest],
        capture_output=True, timeout=30, check=False,
    )


def run_scenario(scenario: str, binary: pathlib.Path, scratch: pathlib.Path, repetition: int):
    """Every repetition gets an isolated fixture+store directory so no
    repetition's on-disk state can leak into another's, and returns the list
    of process records that make up this one repetition (one for cold_open
    and the three unedited/edited warm_open variants; two for stale_recovery,
    which times the failing warm-open attempt and the recovering cold-open
    as separate records)."""
    directory = scratch / f"{scenario}-{repetition}"
    write_fixture(directory)
    manifest = directory / "semaprax.toml"
    store = directory / ".semaprax-semantic-cache"

    if scenario == "cold_open":
        return [run_process([str(binary), "semantic-cache-cold-open", str(manifest)], directory, "cold_open")]

    init_store(binary, store)
    digest = persist(binary, manifest, store)

    if scenario == "warm_open_unchanged":
        return [run_process(
            [str(binary), "semantic-cache-warm-open", str(manifest), str(store), digest], directory, "warm_open"
        )]
    if scenario == "warm_open_local_edit":
        edit_leaf(directory)
        canonicalize(binary, directory)
        return [run_process(
            [str(binary), "semantic-cache-warm-open", str(manifest), str(store), digest], directory, "warm_open"
        )]
    if scenario == "warm_open_provider_edit":
        edit_provider(directory)
        canonicalize(binary, directory)
        return [run_process(
            [str(binary), "semantic-cache-warm-open", str(manifest), str(store), digest], directory, "warm_open"
        )]
    if scenario == "stale_recovery":
        evict(binary, store, digest)
        failed_attempt = run_process(
            [str(binary), "semantic-cache-warm-open", str(manifest), str(store), digest], directory,
            "stale_warm_open_attempt", expect_ok=False,
        )
        recovery = run_process(
            [str(binary), "semantic-cache-cold-open", str(manifest)], directory, "cold_open_recovery"
        )
        return [failed_attempt, recovery]
    raise ValueError(f"unknown scenario {scenario}")


def summarize(records):
    """One block per distinct `role`. Stats are computed only over records
    that matched their own expectation (`matched_expectation`): a scenario
    where success is the point, or one like `stale_recovery`'s first half
    where failure is the point. A record that did the wrong thing is excluded
    from timing stats and always visible via `n_unexpected` instead of being
    silently averaged in either direction."""
    by_role = {}
    for record in records:
        by_role.setdefault(record["role"], []).append(record)
    summary = {}
    for role, role_records in by_role.items():
        matched = [record for record in role_records if record["matched_expectation"]]
        wall = [record["wall_seconds"] for record in matched]
        rss = [record["peak_rss_bytes"] for record in matched if record["peak_rss_bytes"] is not None]
        block = {
            "n": len(role_records),
            "n_matched_expectation": len(matched),
            "n_unexpected": len(role_records) - len(matched),
        }
        if wall:
            block["wall_seconds"] = {"min": min(wall), "median": statistics.median(wall), "max": max(wall)}
        if rss:
            block["peak_rss_bytes"] = {"min": min(rss), "median": statistics.median(rss), "max": max(rss)}
        summary[role] = block
    return summary


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--semaprax", type=pathlib.Path, default=ROOT / "target/debug/semaprax")
    parser.add_argument("--profile", default="debug", help="label recorded verbatim; not inferred from the binary")
    parser.add_argument("--repetitions", type=int, default=11)
    parser.add_argument("--scratch", type=pathlib.Path, default=None)
    parser.add_argument("--output", required=True, type=pathlib.Path)
    parser.add_argument(
        "--acknowledge-loaded-host", action="store_true",
        help="required: this script performs no quiet-host gate and will refuse to run without it",
    )
    args = parser.parse_args(argv)
    if not args.acknowledge_loaded_host:
        parser.error(
            "this harness does not gate on a quiet host (see module docstring); "
            "pass --acknowledge-loaded-host to run it and disclose host_before/host_after yourself"
        )
    live_binary = args.semaprax.resolve(strict=True)
    scratch = args.scratch or (pathlib.Path.cwd() / f".semantic-cache-workflow-scratch-{time.time_ns()}")
    scratch.mkdir(parents=True, exist_ok=True)
    binary = install_compiler(live_binary, scratch)

    document = {
        "schema": SCHEMA,
        "profile": args.profile,
        "repetitions": args.repetitions,
        "binary": {
            "path": str(binary),
            "digest": PERFORMANCE.sha256_file(binary),
            "staged_from": str(live_binary),
            "staging_note": "copied read-only single-link before measurement; see install_compiler()",
        },
        "git": PERFORMANCE.git_revision(ROOT),
        "scenarios": {},
        "nonclaims": [
            "not_a_quiet_host_measurement",
            "not_hosted_or_cross_platform_evidence",
            "not_a_speedup_claim",
            "wall_time_includes_process_spawn_and_is_a_debug_build_unless___profile_release_was_passed",
        ],
    }
    try:
        for scenario in SCENARIOS:
            records = []
            for repetition in range(args.repetitions):
                records.extend(run_scenario(scenario, binary, scratch, repetition))
            document["scenarios"][scenario] = {
                "records": records,
                "summary": summarize(records),
            }
    finally:
        shutil.rmtree(scratch, ignore_errors=True)

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")
    unexpected = {
        name: role
        for name, body in document["scenarios"].items()
        for role, block in body["summary"].items()
        if block["n_unexpected"] > 0
    }
    if unexpected:
        print(f"unexpected exit status against a record's own expectation: {unexpected}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
