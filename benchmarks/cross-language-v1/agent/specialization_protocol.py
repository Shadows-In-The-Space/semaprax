"""Freeze a no-spend specialization evaluation before any model invocation.

This is deliberately an *input-only* protocol builder.  It accepts a
reviewable proposal, authenticates the current task inventory supplied by the
caller, and emits a canonical schedule for the complete held-out subset.  It
does not construct a transport, read credentials, invoke a toolchain, write a
candidate, or score an outcome.  In particular, a valid protocol always
renders as ``not_authorized`` / ``not_attempted`` rather than becoming a model
evaluation claim.

The point is to stop a future experiment from changing one of its controls
while it runs: base model identity, resource ceiling, independent oracle, and
the held-out task set are all bound before an external operator can dispatch a
single trial.  The three required variants isolate versioned semantic guidance
and schema-constrained actions from the base model.  A proposed adapter may be
added, but its training task IDs are derived from the owner inventory and must
all be in the development split; it remains a proposal, not a trained model.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path
from typing import Any


PROTOCOL_SCHEMA = "benchmark.cross_language.agent.specialization_protocol.v1"
PLAN_SCHEMA = "benchmark.cross_language.agent.specialization_plan.v1"
TASKS_SCHEMA = "benchmark.cross_language.tasks.v1"

REQUIRED_METRICS = (
    "accepted_outcome",
    "model_input_tokens",
    "model_output_tokens",
    "presented_context_bytes",
    "tool_calls",
    "tool_request_bytes",
    "tool_response_bytes",
    "failed_attempts",
    "stale_failures",
    "stale_recovery_actions",
    "validation_wall_ms",
    "review_wall_ms",
    "human_interventions",
    "total_cost_usd",
)
REQUIRED_VARIANTS = ("base", "guided", "constrained")
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_IDENTIFIER = re.compile(r"[a-z0-9][a-z0-9-]*\Z")
_MUTABLE = {"head", "latest", "main", "master", "stable", "trunk"}


class ProtocolError(ValueError):
    """A protocol defect that must be resolved before execution is possible."""


def canonical_bytes(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n").encode("ascii")


def sha256(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _exact(value: Any, keys: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != keys:
        raise ProtocolError(f"{label} must have exactly {sorted(keys)}")
    return value


def _digest(value: Any, label: str) -> str:
    if not isinstance(value, str) or not _DIGEST.fullmatch(value):
        raise ProtocolError(f"{label} must be a sha256 digest")
    return value


def _identifier(value: Any, label: str) -> str:
    if not isinstance(value, str) or not _IDENTIFIER.fullmatch(value):
        raise ProtocolError(f"{label} must be a lowercase identifier")
    return value


def _immutable(value: Any, label: str) -> str:
    if not isinstance(value, str) or value != value.strip() or not value:
        raise ProtocolError(f"{label} must be non-empty, explicit text")
    if value.lower() in _MUTABLE or value.startswith("@"):
        raise ProtocolError(f"{label} must not be a mutable alias")
    return value


def _nonnegative_int(value: Any, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ProtocolError(f"{label} must be a nonnegative integer")
    return value


def _canonical_tasks(task_inventory_bytes: bytes) -> list[dict[str, Any]]:
    """Authenticate and extract only public task metadata.

    The protocol intentionally never walks a public or hidden task directory.
    Task selection comes exclusively from the canonical owner inventory.
    """
    if not isinstance(task_inventory_bytes, bytes):
        raise ProtocolError("task inventory must be supplied as bytes")
    try:
        document = json.loads(task_inventory_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ProtocolError("task inventory must be valid UTF-8 JSON") from error
    expected = (json.dumps(document, indent=2, ensure_ascii=True) + "\n").encode("utf-8")
    if task_inventory_bytes != expected:
        raise ProtocolError("task inventory must be its exact canonical owner bytes")
    if not isinstance(document, dict) or set(document) != {"schema", "tasks"}:
        raise ProtocolError("task inventory has an invalid top-level shape")
    if document["schema"] != TASKS_SCHEMA or not isinstance(document["tasks"], list):
        raise ProtocolError("task inventory has an unsupported schema")
    tasks: list[dict[str, Any]] = []
    seen: set[str] = set()
    for row in document["tasks"]:
        if not isinstance(row, dict):
            raise ProtocolError("task inventory has a non-object task")
        task_id = _identifier(row.get("id"), "task id")
        split = row.get("split")
        if split not in {"development", "validation", "held_out"}:
            raise ProtocolError(f"task {task_id} has an unsupported split")
        languages = row.get("languages")
        if not isinstance(languages, dict) or not languages:
            raise ProtocolError(f"task {task_id} has no language inventory")
        if task_id in seen:
            raise ProtocolError("task inventory duplicates a task id")
        seen.add(task_id)
        tasks.append({"id": task_id, "split": split, "languages": tuple(languages)})
    if not tasks:
        raise ProtocolError("task inventory must not be empty")
    return tasks


def _model(value: Any, label: str) -> dict[str, str]:
    value = _exact(value, {"provider", "model", "revision"}, label)
    return {field: _immutable(value[field], f"{label}.{field}") for field in ("provider", "model", "revision")}


def _budget(value: Any) -> dict[str, Any]:
    value = _exact(value, {
        "max_prompt_tokens", "max_completion_tokens", "max_total_tokens", "max_retries", "max_cost_usd",
    }, "resource_policy")
    parsed = {
        field: _nonnegative_int(value[field], f"resource_policy.{field}")
        for field in ("max_prompt_tokens", "max_completion_tokens", "max_total_tokens", "max_retries")
    }
    if parsed["max_prompt_tokens"] == 0 or parsed["max_completion_tokens"] == 0 or parsed["max_total_tokens"] == 0:
        raise ProtocolError("resource_policy token ceilings must be positive")
    if parsed["max_total_tokens"] < parsed["max_prompt_tokens"] + parsed["max_completion_tokens"]:
        raise ProtocolError("resource_policy max_total_tokens cannot undercut both component ceilings")
    cost = value["max_cost_usd"]
    if isinstance(cost, bool) or not isinstance(cost, (int, float)) or cost < 0:
        raise ProtocolError("resource_policy.max_cost_usd must be nonnegative")
    parsed["max_cost_usd"] = cost
    return parsed


def _mode(value: Any, label: str, expected: str) -> dict[str, str]:
    if expected == "none":
        _exact(value, {"mode"}, label)
        if value["mode"] != "none":
            raise ProtocolError(f"{label} must be none")
        return {"mode": "none"}
    _exact(value, {"mode", "sha256"}, label)
    if value["mode"] != expected:
        raise ProtocolError(f"{label} must have mode {expected}")
    return {"mode": expected, "sha256": _digest(value["sha256"], f"{label}.sha256")}


def _adaptation(value: Any, tasks: list[dict[str, Any]]) -> dict[str, Any] | None:
    if value is None:
        return None
    value = _exact(value, {"status", "dataset_manifest_sha256", "task_ids"}, "adaptation")
    if value["status"] != "proposed":
        raise ProtocolError("adaptation status must remain proposed until separately approved")
    task_ids = value["task_ids"]
    if not isinstance(task_ids, list) or not task_ids or task_ids != sorted(set(task_ids)):
        raise ProtocolError("adaptation task_ids must be a sorted, non-empty, unique list")
    by_id = {task["id"]: task for task in tasks}
    for task_id in task_ids:
        _identifier(task_id, "adaptation task id")
        task = by_id.get(task_id)
        if task is None or task["split"] != "development":
            raise ProtocolError("adaptation may use only owner-declared development tasks")
    return {
        "status": "proposed",
        "dataset_manifest_sha256": _digest(value["dataset_manifest_sha256"], "adaptation.dataset_manifest_sha256"),
        "task_ids": task_ids,
    }


def _variant(value: Any, tasks: list[dict[str, Any]], base_model: dict[str, str]) -> dict[str, Any]:
    value = _exact(value, {"id", "model", "guidance", "action_constraint", "adaptation"}, "variant")
    variant_id = _identifier(value["id"], "variant id")
    model = _model(value["model"], f"variant {variant_id} model")
    if model != base_model:
        raise ProtocolError(f"variant {variant_id} changes the base model identity")
    adaptation = _adaptation(value["adaptation"], tasks)
    if variant_id == "base":
        guidance = _mode(value["guidance"], "base guidance", "none")
        constraint = _mode(value["action_constraint"], "base action_constraint", "none")
        if adaptation is not None:
            raise ProtocolError("base variant may not propose adaptation")
    elif variant_id == "guided":
        guidance = _mode(value["guidance"], "guided guidance", "versioned")
        constraint = _mode(value["action_constraint"], "guided action_constraint", "none")
        if adaptation is not None:
            raise ProtocolError("guided variant may not propose adaptation")
    elif variant_id == "constrained":
        guidance = _mode(value["guidance"], "constrained guidance", "versioned")
        constraint = _mode(value["action_constraint"], "constrained action_constraint", "schema")
        if adaptation is not None:
            raise ProtocolError("constrained variant may not propose adaptation")
    elif variant_id == "adapted":
        guidance = _mode(value["guidance"], "adapted guidance", "versioned")
        constraint = _mode(value["action_constraint"], "adapted action_constraint", "schema")
        if adaptation is None:
            raise ProtocolError("adapted variant requires a proposed development-only adaptation")
    else:
        raise ProtocolError("variant id must be base, guided, constrained, or adapted")
    return {
        "id": variant_id,
        "model": model,
        "guidance": guidance,
        "action_constraint": constraint,
        "adaptation": adaptation,
    }


def build_plan(protocol: Any, task_inventory_bytes: bytes) -> dict[str, Any]:
    """Validate a frozen protocol and return a no-execution held-out schedule."""
    tasks = _canonical_tasks(task_inventory_bytes)
    protocol = _exact(protocol, {
        "schema", "id", "base_model", "tool_configuration", "resource_policy", "acceptance_oracle",
        "metrics", "evaluation", "repetitions", "variants", "authorization",
    }, "specialization protocol")
    if protocol["schema"] != PROTOCOL_SCHEMA:
        raise ProtocolError("unsupported specialization protocol schema")
    protocol_id = _identifier(protocol["id"], "protocol id")
    base_model = _model(protocol["base_model"], "base_model")
    tools = _exact(protocol["tool_configuration"], {"runner", "revision", "action_api_sha256"}, "tool_configuration")
    tool_configuration = {
        "runner": _immutable(tools["runner"], "tool_configuration.runner"),
        "revision": _immutable(tools["revision"], "tool_configuration.revision"),
        "action_api_sha256": _digest(tools["action_api_sha256"], "tool_configuration.action_api_sha256"),
    }
    resource_policy = _budget(protocol["resource_policy"])
    oracle = _exact(protocol["acceptance_oracle"], {"runner", "revision", "sha256"}, "acceptance_oracle")
    acceptance_oracle = {
        "runner": _immutable(oracle["runner"], "acceptance_oracle.runner"),
        "revision": _immutable(oracle["revision"], "acceptance_oracle.revision"),
        "sha256": _digest(oracle["sha256"], "acceptance_oracle.sha256"),
    }
    if protocol["metrics"] != list(REQUIRED_METRICS):
        raise ProtocolError("metrics must be the exact required specialization metric inventory")
    evaluation = _exact(protocol["evaluation"], {"language", "task_inventory_sha256"}, "evaluation")
    language = _identifier(evaluation["language"], "evaluation language")
    inventory_sha = sha256(task_inventory_bytes)
    if _digest(evaluation["task_inventory_sha256"], "evaluation.task_inventory_sha256") != inventory_sha:
        raise ProtocolError("evaluation task inventory digest disagrees with supplied owner bytes")
    repetitions = _nonnegative_int(protocol["repetitions"], "repetitions")
    if repetitions < 2:
        raise ProtocolError("repetitions must be at least two for nondeterministic evaluation")
    authorization = _exact(protocol["authorization"], {"status", "required"}, "authorization")
    if authorization["status"] != "not_authorized" or not isinstance(authorization["required"], list):
        raise ProtocolError("authorization must remain an explicit not_authorized record")
    required = [_immutable(item, "authorization requirement") for item in authorization["required"]]
    if not required or required != sorted(set(required)):
        raise ProtocolError("authorization required must be a sorted, non-empty, unique list")
    variants = protocol["variants"]
    if not isinstance(variants, list) or [item.get("id") if isinstance(item, dict) else None for item in variants] not in (
        list(REQUIRED_VARIANTS), list(REQUIRED_VARIANTS) + ["adapted"],
    ):
        raise ProtocolError("variants must be base, guided, constrained, with optional adapted last")
    variants = [_variant(item, tasks, base_model) for item in variants]
    guided = variants[1]["guidance"]["sha256"]
    if variants[2]["guidance"]["sha256"] != guided:
        raise ProtocolError("guided and constrained variants must bind the same guidance bytes")
    if len(variants) == 4 and variants[3]["guidance"]["sha256"] != guided:
        raise ProtocolError("adapted variant must bind the same guidance bytes as the controls")
    evaluation_tasks = [task for task in tasks if task["split"] == "held_out" and language in task["languages"]]
    if not evaluation_tasks:
        raise ProtocolError("no owner-declared held-out tasks support the evaluation language")
    protocol_bytes = canonical_bytes(protocol)
    rows = []
    for variant in variants:
        for task in evaluation_tasks:
            for trial in range(1, repetitions + 1):
                rows.append({
                    "variant": variant["id"],
                    "task": task["id"],
                    "language": language,
                    "split": "held_out",
                    "trial": trial,
                    "execution": "not_attempted",
                })
    return {
        "schema": PLAN_SCHEMA,
        "status": "not_authorized",
        "execution": "not_attempted",
        "non_claim": "A frozen offline schedule is not a model invocation, trained adapter, or evaluation result.",
        "protocol_id": protocol_id,
        "protocol_sha256": sha256(protocol_bytes),
        "task_inventory_sha256": inventory_sha,
        "base_model": base_model,
        "tool_configuration": tool_configuration,
        "resource_policy": resource_policy,
        "acceptance_oracle": acceptance_oracle,
        "metrics": list(REQUIRED_METRICS),
        "authorization_required": required,
        "variants": variants,
        "rows": rows,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--protocol", required=True, help="canonical protocol JSON proposal")
    parser.add_argument("--tasks", required=True, help="canonical owner tasks.json")
    parser.add_argument("--output", required=True, help="new plan JSON path")
    args = parser.parse_args(argv)
    output = Path(args.output)
    if output.exists() or output.is_symlink():
        parser.error("output must not already exist")
    try:
        protocol = json.loads(Path(args.protocol).read_text(encoding="utf-8"))
        plan = build_plan(protocol, Path(args.tasks).read_bytes())
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_bytes(canonical_bytes(plan))
    except (OSError, json.JSONDecodeError, ProtocolError) as error:
        parser.error(str(error))
    print(f"wrote {output}: status=not_authorized execution=not_attempted rows={len(plan['rows'])}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
