#!/usr/bin/env python3
"""Capture bounded, independently launched workflow observations on a quiet host."""

import argparse
import hashlib
import importlib.util
import json
import math
import pathlib
import statistics
import subprocess
import sys
import time

ROOT = pathlib.Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("performance_runner", pathlib.Path(__file__).with_name("run.py"))
PERFORMANCE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PERFORMANCE)
SCHEMA = "benchmark.workflow-campaign.v1"
STAGES = ["parse", "canonicalize", "resolve", "hir_validate", "workspace_preflight",
          "project_link", "graph_render", "analysis_index", "target_admission",
          "image_derivation", "interpreter_preparation", "prepared_execution"]
ROWS = {f"cache-{scale}x-{variant}": {"cold", "warm"}
        for scale in (1, 2, 4) for variant in ("unchanged", "leaf", "provider")}
ROWS.update({f"prepared-{subject}-{mode}": {"cold", "prepared"}
             for subject in ("scalar-loop", "calculator", "apex")
             for mode in ("traced", "untraced")})


def digest(path):
    hasher = hashlib.sha256()
    with pathlib.Path(path).open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            hasher.update(block)
    return "sha256:" + hasher.hexdigest()


def git(*args):
    return subprocess.check_output(["git", "-C", str(ROOT), *args], timeout=30)


def source_identity():
    # Include untracked compiler/benchmark files too, but never caches or logs.
    inventory = []
    for folder in ("src", "benches", "crates"):
        inventory.extend(path for path in (ROOT / folder).rglob("*")
                         if path.is_file() and path.suffix in (".rs", ".toml", ".txt"))
    inventory.extend(ROOT / name for name in ("Cargo.toml", "Cargo.lock"))
    for name in ("calculator-project", "apex-supply-chain"):
        inventory.extend(path for path in (ROOT / "examples" / name).rglob("*")
                         if path.is_file() and path.suffix in (".spx", ".toml"))
    inventory.extend([pathlib.Path(__file__).resolve(), pathlib.Path(__file__).with_name("run.py")])
    rows = [(str(path.relative_to(ROOT)), digest(path)) for path in sorted(set(inventory))]
    return "sha256:" + hashlib.sha256(json.dumps(rows, separators=(",", ":")).encode()).hexdigest()


def quiet(host, max_load_per_cpu, min_available_bytes):
    cpus, load = host.get("cpu_count"), host.get("load_average")
    available = host.get("available_memory", {}).get("bytes")
    return (type(cpus) is int and cpus > 0 and isinstance(load, list) and len(load) == 3
            and all(type(value) in (int, float) and math.isfinite(value)
                    and 0 <= value <= cpus * max_load_per_cpu for value in load)
            and type(available) is int and available >= min_available_bytes)


def integer(value):
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def validate(document, samples):
    if document.get("schema") != "benchmark.workflow-observation.v1" or (not integer(document.get("samples")) or document.get("samples") != samples):
        raise ValueError("wrong workflow schema or sample count")
    if document.get("stages") != STAGES:
        raise ValueError("stage inventory drift")
    rows = document.get("rows", [])
    if len(rows) != len(ROWS) or {row.get("id") for row in rows} != set(ROWS):
        raise ValueError("missing, duplicate, or extra workflow row")
    for row in rows:
        arms = row.get("arms", {})
        if set(arms) != ROWS[row["id"]]:
            raise ValueError("wrong workflow arm inventory")
        for arm in arms.values():
            if len(arm) != samples:
                raise ValueError("wrong arm sample count")
            for sample in arm:
                observation = sample.get("observation", {})
                stages = observation.get("stages", [])
                if observation.get("complete") is not True or not integer(observation.get("total_ns")):
                    raise ValueError("incomplete or invalid observation")
                if not integer(sample.get("plain_ns")):
                    raise ValueError("missing uncaptured comparison sample")
                if [stage.get("stage") for stage in stages] != STAGES:
                    raise ValueError("sample stage inventory drift")
                for stage in stages:
                    if not all(integer(stage.get(key)) for key in ("calls", "inclusive_ns", "self_ns")):
                        raise ValueError("invalid stage observation")
                    if stage["self_ns"] > stage["inclusive_ns"]:
                        raise ValueError("invalid nested attribution")
                if sum(stage["self_ns"] for stage in stages) > observation["total_ns"]:
                    raise ValueError("double-counted self time")


def summarize(campaigns):
    result = []
    for row_id, arm_names in ROWS.items():
        for arm in sorted(arm_names):
            values = []
            for campaign in campaigns:
                row = next(row for row in campaign["observations"]["rows"] if row["id"] == row_id)
                values.extend(sample["observation"]["total_ns"] for sample in row["arms"][arm])
            result.append({"row": row_id, "arm": arm, "count": len(values),
                           "median_ns": statistics.median(values), "min_ns": min(values),
                           "max_ns": max(values), "stdev_ns": statistics.pstdev(values)})
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--observer", required=True, type=pathlib.Path)
    parser.add_argument("--output", required=True, type=pathlib.Path)
    parser.add_argument("--profile", required=True, choices=("dev", "release", "bench"))
    parser.add_argument("--campaigns", type=int, default=3, choices=range(1, 6))
    parser.add_argument("--samples", type=int, default=5, choices=range(1, 21))
    parser.add_argument("--max-load-per-cpu", type=float, default=0.25)
    parser.add_argument("--min-available-bytes", type=int, default=1024**3)
    args = parser.parse_args(argv)
    if not math.isfinite(args.max_load_per_cpu) or not 0 < args.max_load_per_cpu <= 1:
        parser.error("--max-load-per-cpu must be finite and in (0,1]")
    if args.min_available_bytes < 0:
        parser.error("--min-available-bytes cannot be negative")
    observer = args.observer.resolve(strict=True)
    before_identity = source_identity()
    binary_digest = digest(observer)
    report = {"schema": SCHEMA, "status": "incomplete", "profile": args.profile,
              "commit": git("rev-parse", "HEAD").decode().strip(),
              "tracked_dirty": bool(git("diff", "HEAD", "--name-only")),
              "source_inventory_digest": before_identity,
              "observer": {"path": str(observer), "digest": binary_digest},
              "configuration": {"campaigns": args.campaigns, "samples": args.samples,
                                "max_load_per_cpu": args.max_load_per_cpu,
                                "min_available_bytes": args.min_available_bytes},
              "started_unix_seconds": time.time(), "campaigns": [],
              "nonclaims": ["not a hosted result", "not a production speedup claim",
                            "current-thread attribution; worker interiors are not separated",
                            "instrumented build; uncaptured samples still contain inactive hooks"]}
    for index in range(args.campaigns):
        before = PERFORMANCE.host_facts()
        if not quiet(before, args.max_load_per_cpu, args.min_available_bytes):
            report.update(status="nonquiet", refused_host=before)
            break
        try:
            process = subprocess.run([str(observer), "--samples", str(args.samples)], cwd=ROOT,
                                     capture_output=True, timeout=180, check=False)
            after = PERFORMANCE.host_facts()
            if process.returncode or len(process.stdout) > 8 * 1024 * 1024:
                raise ValueError(f"observer exit {process.returncode}: {process.stderr[:4096].decode(errors='replace')}")
            document = json.loads(process.stdout)
            validate(document, args.samples)
            report["campaigns"].append({"index": index, "host_before": before, "host_after": after,
                                         "observations": document})
            if not quiet(after, args.max_load_per_cpu, args.min_available_bytes):
                report["status"] = "nonquiet"
                break
        except (ValueError, OSError, subprocess.TimeoutExpired) as error:
            report.update(status="failed", error=str(error))
            break
    else:
        report["status"] = "quiet_observed"
        report["summary"] = summarize(report["campaigns"])
    if source_identity() != before_identity or digest(observer) != binary_digest:
        report["status"] = "drifted"
        report.pop("summary", None)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    return 0 if report["status"] == "quiet_observed" else 1


if __name__ == "__main__":
    sys.exit(main())
