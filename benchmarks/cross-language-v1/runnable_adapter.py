#!/usr/bin/env python3
"""Bounded, offline runnable-adapter extension for cross-language v1.

This is deliberately an extension of ``agent.baseline_admission``.  The
baseline descriptor remains the authority for the canonical task inventory,
the pinned external subject, and the independently reviewed port digests.  A
runnable descriptor only adds the local execution facts that admission does
not (and must not) claim: the exact committed adapter inventory, one declared
adapter/task pair, a bounded argv invocation, and an authenticated local
receipt.  It never provisions a toolchain or turns an unavailable baseline
into a comparison observation by itself.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import subprocess
import sys
import tempfile
from typing import Any


SUITE = pathlib.Path(__file__).resolve().parent
ROOT = SUITE.parent.parent
TASKS = SUITE / "tasks.json"
ADAPTERS = SUITE / "adapters.json"
RUNNER = SUITE / "run.py"
SCHEMA = "benchmark.cross_language.runnable_adapter.v1"
MAX_DESCRIPTOR_BYTES = 64 * 1024
MAX_RECEIPT_BYTES = 8 * 1024
MAX_TIMEOUT_SECONDS = 120

if str(SUITE) not in sys.path:
    sys.path.insert(0, str(SUITE))

from agent.baseline_admission import (  # noqa: E402
    ADMISSION_SCHEMA,
    _canonical_owner_task_inventory,
    admit_baseline_descriptor,
)


def _sha256(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _canonical_bytes(value: Any) -> bytes:
    return (json.dumps(value, indent=2, ensure_ascii=True) + "\n").encode("utf-8")


def _unavailable(reason: str) -> dict[str, Any]:
    return {"schema": SCHEMA, "status": "unavailable", "reason": reason}


def _parse_canonical_descriptor(descriptor_bytes: bytes) -> dict[str, Any] | None:
    if not isinstance(descriptor_bytes, bytes) or not descriptor_bytes or len(descriptor_bytes) > MAX_DESCRIPTOR_BYTES:
        return None
    try:
        descriptor = json.loads(descriptor_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None
    if not isinstance(descriptor, dict) or _canonical_bytes(descriptor) != descriptor_bytes:
        return None
    return descriptor


def admit_runnable_descriptor(
    descriptor_bytes: bytes,
    owner_task_inventory_bytes: bytes,
    adapter_inventory_bytes: bytes,
) -> dict[str, Any]:
    """Authenticate a runnable extension without executing anything.

    ``baseline`` is passed unchanged to the existing unavailable-only gate.
    This function intentionally does not duplicate its identity, canonical
    inventory, port-order, toolchain-source, or equivalence-review rules.
    """
    descriptor = _parse_canonical_descriptor(descriptor_bytes)
    if descriptor is None:
        return _unavailable("invalid_runnable_descriptor")
    if set(descriptor) != {"schema", "baseline", "execution"} or descriptor["schema"] != SCHEMA:
        return _unavailable("invalid_runnable_descriptor")
    baseline = descriptor["baseline"]
    if not isinstance(baseline, dict) or baseline.get("schema") != ADMISSION_SCHEMA:
        return _unavailable("invalid_baseline_descriptor")
    baseline_decision = admit_baseline_descriptor(baseline, owner_task_inventory_bytes)
    if baseline_decision.get("status") != "unavailable":
        return _unavailable("baseline_descriptor_not_admissible")
    if baseline_decision.get("reason") != "offline_admission_is_not_execution_evidence":
        return _unavailable(baseline_decision["reason"])
    if _canonical_owner_task_inventory(owner_task_inventory_bytes) is None:
        return _unavailable("invalid_required_task_inventory")
    try:
        adapters = json.loads(adapter_inventory_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return _unavailable("invalid_adapter_inventory")
    # Unlike the owner task inventory, the existing adapter inventory has no
    # canonical-JSON rendering contract.  Its exact source bytes are instead
    # bound below by ``adapter_inventory_sha256``; requiring a second renderer
    # here would reject the committed inventory and invent a new parser rule.
    if set(adapters) != {"schema", "adapters"}:
        return _unavailable("invalid_adapter_inventory")
    if adapters.get("schema") != "benchmark.cross_language.adapters.v1" or not isinstance(adapters["adapters"], list):
        return _unavailable("invalid_adapter_inventory")
    by_id = {row.get("id"): row for row in adapters["adapters"] if isinstance(row, dict)}
    if len(by_id) != len(adapters["adapters"]):
        return _unavailable("invalid_adapter_inventory")

    execution = descriptor["execution"]
    required = {"classification", "adapter_id", "task_id", "adapter_inventory_sha256", "receipt", "receipt_sha256", "timeout_seconds"}
    if not isinstance(execution, dict) or set(execution) != required:
        return _unavailable("invalid_execution_provenance")
    if execution["classification"] != "local_fixture":
        return _unavailable("external_execution_requires_provisioned_review")
    if execution["adapter_inventory_sha256"] != _sha256(adapter_inventory_bytes):
        return _unavailable("adapter_inventory_drifted")
    if not isinstance(execution["receipt"], str) or len(execution["receipt"].encode("utf-8")) > MAX_RECEIPT_BYTES:
        return _unavailable("invalid_execution_receipt")
    if execution["receipt_sha256"] != _sha256(execution["receipt"].encode("utf-8")):
        return _unavailable("execution_receipt_digest_disagrees")
    if not isinstance(execution["timeout_seconds"], int) or not 1 <= execution["timeout_seconds"] <= MAX_TIMEOUT_SECONDS:
        return _unavailable("invalid_execution_bounds")
    adapter = by_id.get(execution["adapter_id"])
    if not isinstance(execution["task_id"], str) or not isinstance(adapter, dict):
        return _unavailable("undeclared_task_or_adapter")
    if not adapter.get("implemented", False):
        return _unavailable("adapter_remains_unavailable")
    owner = json.loads(owner_task_inventory_bytes.decode("utf-8"))
    task = next((row for row in owner["tasks"] if row["id"] == execution["task_id"]), None)
    if task is None or execution["adapter_id"] not in task["languages"]:
        return _unavailable("task_does_not_declare_adapter")
    return {
        "schema": SCHEMA,
        "status": "fixture_admitted",
        "classification": "local_fixture",
        "baseline": baseline_decision["provenance"],
        "task_id": execution["task_id"],
        "adapter_id": execution["adapter_id"],
        "timeout_seconds": execution["timeout_seconds"],
    }


def execute_local_fixture(
    descriptor_bytes: bytes,
    owner_task_inventory_bytes: bytes,
    adapter_inventory_bytes: bytes,
    root: pathlib.Path,
) -> dict[str, Any]:
    """Run exactly one admitted local fixture through the existing scorer."""
    admitted = admit_runnable_descriptor(descriptor_bytes, owner_task_inventory_bytes, adapter_inventory_bytes)
    if admitted.get("status") != "fixture_admitted":
        return admitted
    if root.resolve() != ROOT.resolve() or owner_task_inventory_bytes != TASKS.read_bytes() or adapter_inventory_bytes != ADAPTERS.read_bytes():
        return _unavailable("execution_inputs_drifted")
    with tempfile.TemporaryDirectory(prefix="spx-runnable-adapter-") as temporary:
        output = pathlib.Path(temporary) / "result.json"
        command = [
            sys.executable,
            str(RUNNER),
            "--root", str(root.resolve()),
            "--tasks", str(TASKS),
            "--adapters", str(ADAPTERS),
            "--only", admitted["task_id"],
            "--language", admitted["adapter_id"],
            "--output", str(output),
        ]
        try:
            completed = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=admitted["timeout_seconds"],
                check=False,
            )
        except subprocess.TimeoutExpired:
            return _unavailable("execution_timed_out")
        if completed.returncode != 0 or not output.is_file():
            return _unavailable("fixture_execution_failed")
        try:
            document = json.loads(output.read_text())
        except (OSError, json.JSONDecodeError):
            return _unavailable("fixture_result_invalid")
    rows = document.get("results")
    if not isinstance(rows, list) or len(rows) != 1 or rows[0].get("status") != "ok":
        return _unavailable("fixture_scoring_failed")
    return {
        "schema": SCHEMA,
        "status": "fixture_ok",
        "classification": "local_fixture",
        "result": rows[0],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="bounded runnable-adapter fixture executor")
    parser.add_argument("--descriptor", required=True)
    parser.add_argument("--root", default=str(ROOT))
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    descriptor_path = pathlib.Path(args.descriptor)
    result = execute_local_fixture(descriptor_path.read_bytes(), TASKS.read_bytes(), ADAPTERS.read_bytes(), pathlib.Path(args.root))
    pathlib.Path(args.output).write_bytes(_canonical_bytes(result))
    return 0 if result.get("status") == "fixture_ok" else 1


if __name__ == "__main__":
    raise SystemExit(main())
