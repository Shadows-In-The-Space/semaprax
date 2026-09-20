#!/usr/bin/env python3
"""Build and verify a deterministic, input-only benchmark reproduction capsule.

This deliberately has no adapter, subprocess, network, clock, credential, or
model capability.  A matching capsule says only that the declared scoring
inputs match; it never says that a toolchain or model was run.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import pathlib
import stat
import sys
from typing import Any


CAPSULE_SCHEMA = "benchmark.cross_language.reproduction_capsule.v1"
TASKS_SCHEMA = "benchmark.cross_language.tasks.v1"
ADAPTERS_SCHEMA = "benchmark.cross_language.adapters.v1"
_IDENTIFIER = "abcdefghijklmnopqrstuvwxyz0123456789-"
_TASK_KEYS = {"id", "category", "issue_211_category", "split", "summary", "equivalence", "languages"}
_PATH_KEYS = {"public", "hidden"}
_IMPLEMENTED_ADAPTER_KEYS = {
    "id", "language", "implemented", "official_workflow", "version_command",
    "entry_file", "run_command", "success",
}
_IMPLEMENTED_ADAPTER_WITH_BUILD_KEYS = _IMPLEMENTED_ADAPTER_KEYS | {"build_command"}
_BLOCKED_ADAPTER_KEYS = {"id", "language", "implemented", "blocked_reason"}
_CAPSULE_KEYS = {"schema", "kind", "execution", "inventory", "pairs", "digest"}
_DESCRIPTOR_TRAVERSAL_AVAILABLE = (
    hasattr(os, "O_NOFOLLOW")
    and hasattr(os, "O_DIRECTORY")
    and os.open in os.supports_dir_fd
    and os.stat in os.supports_dir_fd
    and os.stat in os.supports_follow_symlinks
    and os.listdir in os.supports_fd
)


class CapsuleError(ValueError):
    """A stable refusal reason for untrusted capsule inputs."""


def _fail(reason: str) -> None:
    raise CapsuleError(reason)


def _canonical_json(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n").encode("utf-8")


def _sha256(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _exact_keys(value: Any, keys: set[str]) -> bool:
    return isinstance(value, dict) and set(value) == keys


def _identifier(value: Any) -> bool:
    return (isinstance(value, str) and bool(value) and value[0].isalpha()
            and all(character in _IDENTIFIER for character in value))


def _text(value: Any) -> bool:
    return isinstance(value, str) and bool(value) and "\x00" not in value


def _relative_path(value: Any) -> bool:
    if not _text(value) or "\\" in value or ":" in value:
        return False
    parts = value.split("/")
    return all(part not in {"", ".", ".."} for part in parts)


def _parse_canonical_json(data: bytes, label: str) -> Any:
    if not isinstance(data, bytes):
        _fail(f"{label}_not_bytes")
    try:
        value = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        _fail(f"invalid_{label}_json")
    # The capsule itself is canonical.  Owner inventories are intentionally
    # bound as supplied raw bytes because their published formatting is part
    # of the reproducibility input, and adapters.json is not canonical JSON.
    if label == "capsule" and _canonical_json(value) != data:
        _fail(f"noncanonical_{label}_bytes")
    return value


def _validate_command(command: Any) -> bool:
    return isinstance(command, list) and bool(command) and all(_text(part) for part in command)


def _identity(info: os.stat_result) -> tuple[int, int, int, int, int, int]:
    """Fields that must stay fixed across one descriptor-backed read."""
    return (
        info.st_dev,
        info.st_ino,
        stat.S_IFMT(info.st_mode),
        info.st_size,
        info.st_mtime_ns,
        info.st_ctime_ns,
    )


def _descriptor_traversal_available() -> bool:
    """Whether this host can keep every ancestor out of pathname resolution."""
    return _DESCRIPTOR_TRAVERSAL_AVAILABLE


def _descriptor_flags(*, directory: bool) -> int:
    flags = os.O_RDONLY | os.O_NOFOLLOW
    if directory:
        flags |= os.O_DIRECTORY
    return flags


def _close(descriptor: int) -> None:
    """Best-effort cleanup must never replace the selected refusal."""
    try:
        os.close(descriptor)
    except OSError:
        pass


def _fstat(descriptor: int) -> os.stat_result:
    try:
        return os.fstat(descriptor)
    except OSError:
        _fail("scoring_input_changed_during_read")


def _duplicate(descriptor: int) -> int:
    try:
        return os.dup(descriptor)
    except OSError:
        _fail("scoring_input_changed_during_read")


def _open_root(root: pathlib.Path) -> int:
    """Open the declared root once, refusing a root symlink or unsupported host."""
    if not _descriptor_traversal_available():
        _fail("descriptor_traversal_unavailable")
    try:
        before = root.lstat()
    except OSError:
        _fail("invalid_root")
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISDIR(before.st_mode):
        _fail("invalid_root")
    try:
        descriptor = os.open(root, _descriptor_flags(directory=True))
    except OSError:
        _fail("invalid_root")
    try:
        if _identity(_fstat(descriptor)) != _identity(before):
            _fail("scoring_input_changed_during_read")
        return descriptor
    except Exception:
        _close(descriptor)
        raise


def _entry_stat(parent: int, name: str) -> os.stat_result:
    try:
        return os.stat(name, dir_fd=parent, follow_symlinks=False)
    except OSError:
        _fail("scoring_input_changed_during_read")


def _open_directory_at(parent: int, name: str) -> int:
    before = _entry_stat(parent, name)
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISDIR(before.st_mode):
        _fail("unsafe_scoring_tree")
    try:
        descriptor = os.open(name, _descriptor_flags(directory=True), dir_fd=parent)
    except OSError:
        _fail("scoring_input_changed_during_read")
    try:
        if _identity(_fstat(descriptor)) != _identity(before):
            _fail("scoring_input_changed_during_read")
        return descriptor
    except Exception:
        _close(descriptor)
        raise


def _open_directory_relative(root: int, relative: str) -> int:
    if not _relative_path(relative):
        _fail("unsafe_task_path")
    descriptor = _duplicate(root)
    try:
        for name in relative.split("/"):
            child = _open_directory_at(descriptor, name)
            _close(descriptor)
            descriptor = child
        return descriptor
    except Exception:
        _close(descriptor)
        raise


def _read_regular_at(parent: int, name: str) -> bytes:
    before = _entry_stat(parent, name)
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
        _fail("unsafe_scoring_tree")
    try:
        descriptor = os.open(name, _descriptor_flags(directory=False), dir_fd=parent)
    except OSError:
        _fail("scoring_input_changed_during_read")
    try:
        opened = _fstat(descriptor)
        if _identity(opened) != _identity(before):
            _fail("scoring_input_changed_during_read")
        chunks: list[bytes] = []
        while True:
            try:
                chunk = os.read(descriptor, 65536)
            except OSError:
                _fail("scoring_input_changed_during_read")
            if not chunk:
                break
            chunks.append(chunk)
        if _identity(_fstat(descriptor)) != _identity(opened):
            _fail("scoring_input_changed_during_read")
        if _identity(_entry_stat(parent, name)) != _identity(before):
            _fail("scoring_input_changed_during_read")
        return b"".join(chunks)
    finally:
        _close(descriptor)


def _read_regular_relative(root: int, relative: str) -> bytes:
    if not _relative_path(relative):
        _fail("unsafe_task_path")
    parts = relative.split("/")
    parent = _open_directory_relative(root, "/".join(parts[:-1])) if len(parts) > 1 else _duplicate(root)
    try:
        return _read_regular_at(parent, parts[-1])
    finally:
        _close(parent)


def _parse_inventory(tasks_bytes: bytes, adapters_bytes: bytes) -> tuple[list[dict[str, Any]], dict[str, dict[str, Any]]]:
    tasks_document = _parse_canonical_json(tasks_bytes, "tasks")
    if not _exact_keys(tasks_document, {"schema", "tasks"}) or tasks_document["schema"] != TASKS_SCHEMA:
        _fail("invalid_tasks_schema")
    tasks = tasks_document["tasks"]
    if not isinstance(tasks, list) or not tasks:
        _fail("invalid_tasks")
    task_ids: set[str] = set()
    for task in tasks:
        if not _exact_keys(task, _TASK_KEYS):
            _fail("invalid_task_shape")
        if not all(_text(task[field]) for field in ("id", "category", "issue_211_category", "split", "summary", "equivalence")):
            _fail("invalid_task_field")
        if not _identifier(task["id"]) or task["id"] in task_ids:
            _fail("invalid_task_id")
        if task["equivalence"] != f"tasks/{task['id']}/EQUIVALENCE.md":
            _fail("invalid_equivalence_path")
        languages = task["languages"]
        if not isinstance(languages, dict) or not languages:
            _fail("invalid_task_languages")
        for language, paths in languages.items():
            if not _identifier(language) or not _exact_keys(paths, _PATH_KEYS):
                _fail("invalid_task_languages")
            if not all(_relative_path(paths[field]) for field in _PATH_KEYS):
                _fail("unsafe_task_path")
        task_ids.add(task["id"])

    adapters_document = _parse_canonical_json(adapters_bytes, "adapters")
    if not _exact_keys(adapters_document, {"schema", "adapters"}) or adapters_document["schema"] != ADAPTERS_SCHEMA:
        _fail("invalid_adapters_schema")
    rows = adapters_document["adapters"]
    if not isinstance(rows, list) or not rows:
        _fail("invalid_adapters")
    adapters: dict[str, dict[str, Any]] = {}
    for row in rows:
        if not isinstance(row, dict) or not _identifier(row.get("id")) or not _text(row.get("language")):
            _fail("invalid_adapter_identity")
        adapter_id = row["id"]
        if adapter_id in adapters or not isinstance(row.get("implemented"), bool):
            _fail("invalid_adapter_identity")
        if row["implemented"]:
            if set(row) != _IMPLEMENTED_ADAPTER_KEYS and set(row) != _IMPLEMENTED_ADAPTER_WITH_BUILD_KEYS:
                _fail("invalid_implemented_adapter_shape")
            if not all(_text(row[field]) for field in ("official_workflow", "entry_file")):
                _fail("invalid_implemented_adapter")
            if not _validate_command(row["version_command"]) or not _validate_command(row["run_command"]):
                _fail("invalid_implemented_adapter")
            if "build_command" in row and not _validate_command(row["build_command"]):
                _fail("invalid_implemented_adapter")
            success = row["success"]
            if not isinstance(success, dict) or success.get("kind") not in {"stdout_equals", "exit_code_zero"}:
                _fail("invalid_implemented_adapter")
            if success["kind"] == "stdout_equals" and (
                    set(success) != {"kind", "value"} or not _text(success.get("value"))):
                _fail("invalid_implemented_adapter")
            if success["kind"] == "exit_code_zero" and set(success) != {"kind"}:
                _fail("invalid_implemented_adapter")
        elif not _exact_keys(row, _BLOCKED_ADAPTER_KEYS) or not _text(row["blocked_reason"]):
            _fail("invalid_blocked_adapter_shape")
        adapters[adapter_id] = row
    for task in tasks:
        if not set(task["languages"]).issubset(adapters):
            _fail("task_language_without_adapter")
    return tasks, adapters


def _tree_digest(directory: int) -> str:
    rows: list[str] = []

    def visit(descriptor: int, relative: str) -> None:
        before = _fstat(descriptor)
        if not stat.S_ISDIR(before.st_mode):
            _fail("unsafe_scoring_tree")
        try:
            children = sorted(os.listdir(descriptor))
        except OSError:
            _fail("scoring_input_changed_during_read")
        for name in children:
            child_relative = f"{relative}/{name}" if relative else name
            mode = _entry_stat(descriptor, name).st_mode
            if stat.S_ISLNK(mode) or not (stat.S_ISDIR(mode) or stat.S_ISREG(mode)):
                _fail("unsafe_scoring_tree")
            if stat.S_ISDIR(mode):
                # Directory rows make empty directories and nesting part of the
                # bound scoring input, rather than silently hashing as absent.
                rows.append(f"D\0{child_relative}")
                child = _open_directory_at(descriptor, name)
                try:
                    visit(child, child_relative)
                finally:
                    _close(child)
            else:
                rows.append(f"F\0{child_relative}\0{_sha256(_read_regular_at(descriptor, name))}")
        if _identity(_fstat(descriptor)) != _identity(before):
            _fail("scoring_input_changed_during_read")

    visit(directory, "")
    return _sha256("\n".join(rows).encode("utf-8"))


def _capsule_without_digest(root: pathlib.Path, tasks_bytes: bytes, adapters_bytes: bytes) -> dict[str, Any]:
    tasks, adapters = _parse_inventory(tasks_bytes, adapters_bytes)
    root_descriptor = _open_root(root)
    try:
        pairs: list[dict[str, str]] = []
        for task in sorted(tasks, key=lambda item: item["id"]):
            equivalence_path = "benchmarks/cross-language-v1/" + task["equivalence"]
            for language in sorted(task["languages"]):
                paths = task["languages"][language]
                public = _open_directory_relative(root_descriptor, paths["public"])
                try:
                    hidden = _open_directory_relative(root_descriptor, paths["hidden"])
                    try:
                        pairs.append({
                            "id": f"{task['id']}::{language}",
                            "task": task["id"],
                            "language": language,
                            "adapter_sha256": _sha256(_canonical_json(adapters[language])),
                            "public_tree_sha256": _tree_digest(public),
                            "hidden_tree_sha256": _tree_digest(hidden),
                            "equivalence_sha256": _sha256(_read_regular_relative(root_descriptor, equivalence_path)),
                        })
                    finally:
                        _close(hidden)
                finally:
                    _close(public)
    finally:
        _close(root_descriptor)
    return {
        "schema": CAPSULE_SCHEMA,
        "kind": "scoring_input",
        "execution": "not_attempted",
        "inventory": {
            "tasks_sha256": _sha256(tasks_bytes),
            "adapters_sha256": _sha256(adapters_bytes),
            "task_ids": [task["id"] for task in tasks],
            "adapter_ids": list(adapters),
        },
        "pairs": pairs,
    }


def build_capsule(root: pathlib.Path | str, tasks_bytes: bytes, adapters_bytes: bytes) -> bytes:
    """Return canonical bytes binding every declared scoring input, without scoring it."""
    document = _capsule_without_digest(pathlib.Path(root), tasks_bytes, adapters_bytes)
    document["digest"] = _sha256(_canonical_json(document))
    return _canonical_json(document)


def _valid_capsule(capsule_bytes: bytes) -> bool:
    try:
        document = _parse_canonical_json(capsule_bytes, "capsule")
    except CapsuleError:
        return False
    if not _exact_keys(document, _CAPSULE_KEYS) or document.get("schema") != CAPSULE_SCHEMA:
        return False
    if document.get("kind") != "scoring_input" or document.get("execution") != "not_attempted":
        return False
    digest = document.get("digest")
    without_digest = dict(document)
    without_digest.pop("digest")
    return isinstance(digest, str) and digest == _sha256(_canonical_json(without_digest))


def verify_capsule(capsule_bytes: bytes, root: pathlib.Path | str, tasks_bytes: bytes, adapters_bytes: bytes) -> dict[str, str]:
    """Verify inputs only; a match is explicitly not a benchmark execution."""
    if not _valid_capsule(capsule_bytes):
        return {"status": "unavailable", "reason": "invalid_capsule", "execution": "not_attempted"}
    try:
        expected = build_capsule(root, tasks_bytes, adapters_bytes)
    except CapsuleError as error:
        return {"status": "unavailable", "reason": str(error), "execution": "not_attempted"}
    if capsule_bytes != expected:
        return {"status": "unavailable", "reason": "scoring_inputs_drifted", "execution": "not_attempted"}
    return {"status": "inputs_match", "reason": "no_execution_performed", "execution": "not_attempted"}


def main() -> int:
    parser = argparse.ArgumentParser(description="create or verify a non-executing cross-language input capsule")
    parser.add_argument("mode", choices=("create", "verify"))
    parser.add_argument("--root", required=True, help="repository root containing the declared task trees")
    parser.add_argument("--tasks", required=True, help="exact canonical tasks.json bytes")
    parser.add_argument("--adapters", required=True, help="exact canonical adapters.json bytes")
    parser.add_argument("--output", help="capsule output path for create, or capsule input path for verify")
    args = parser.parse_args()
    if not args.output:
        parser.error("--output is required")
    try:
        tasks_bytes = pathlib.Path(args.tasks).read_bytes()
        adapters_bytes = pathlib.Path(args.adapters).read_bytes()
        if args.mode == "create":
            capsule = build_capsule(args.root, tasks_bytes, adapters_bytes)
            pathlib.Path(args.output).write_bytes(capsule)
            print(f"Wrote {args.output}: execution=not_attempted")
            return 0
        result = verify_capsule(pathlib.Path(args.output).read_bytes(), args.root, tasks_bytes, adapters_bytes)
    except (OSError, CapsuleError) as error:
        result = {"status": "unavailable", "reason": str(error), "execution": "not_attempted"}
    print(json.dumps(result, sort_keys=True))
    return 0 if result["status"] == "inputs_match" else 1


if __name__ == "__main__":
    sys.exit(main())
