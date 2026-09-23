#!/usr/bin/env python3
"""Bounded, offline runnable-adapter extension for cross-language v1.

The baseline descriptor remains the only owner of task/equivalence identity.
This module snapshots one already-admitted local fixture and invokes the
existing scorer under a POSIX-only containment profile. It does not provision
tools, inherit a caller's tool search path, or create an external result.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import pathlib
import plistlib
import selectors
import signal
import stat
import subprocess
import sys
import tempfile
import time
from typing import Any

SUITE = pathlib.Path(__file__).resolve().parent
ROOT = SUITE.parent.parent
TASKS = SUITE / "tasks.json"
ADAPTERS = SUITE / "adapters.json"
RUNNER = SUITE / "run.py"
SCHEMA = "benchmark.cross_language.runnable_adapter.v1"
MAX_DESCRIPTOR_BYTES = 64 * 1024
MAX_RECEIPT_BYTES = 8 * 1024
MAX_RESULT_BYTES = 256 * 1024
MAX_PROCESS_OUTPUT_BYTES = 64 * 1024
MAX_SOURCE_FILE_BYTES = 1024 * 1024
MAX_SOURCE_TOTAL_BYTES = 8 * 1024 * 1024
MAX_TOOLCHAIN_BYTES = 512 * 1024 * 1024
MAX_TOOL_BYTES = MAX_TOOLCHAIN_BYTES
MAX_TIMEOUT_SECONDS = 120
CLOSED_ENVIRONMENT = {"LANG": "C", "LC_ALL": "C", "TZ": "UTC"}

if str(SUITE) not in sys.path:
    sys.path.insert(0, str(SUITE))

from agent.baseline_admission import (  # noqa: E402
    ADMISSION_SCHEMA,
    _canonical_owner_task_inventory,
    admit_baseline_descriptor,
)


class SnapshotError(ValueError):
    pass


def _sha256(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _canonical_bytes(value: Any) -> bytes:
    return (json.dumps(value, indent=2, ensure_ascii=True) + "\n").encode("utf-8")


def _unavailable(reason: str) -> dict[str, Any]:
    return {"schema": SCHEMA, "status": "unavailable", "reason": reason}


def _read_regular(path: pathlib.Path, limit: int) -> tuple[bytes, os.stat_result]:
    """Read a non-link regular file without opening a FIFO or huge input."""
    if os.name != "posix" or not path.is_absolute() or limit < 1:
        raise SnapshotError("unsupported_regular_file_acquisition")
    flags = os.O_RDONLY | os.O_NONBLOCK | os.O_CLOEXEC | os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise SnapshotError("regular_file_open_refused") from error
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_size > limit:
            raise SnapshotError("regular_file_type_or_size_refused")
        contents = bytearray()
        while True:
            chunk = os.read(descriptor, min(8192, limit + 1 - len(contents)))
            if not chunk:
                break
            contents.extend(chunk)
            if len(contents) > limit:
                raise SnapshotError("regular_file_type_or_size_refused")
        after = os.fstat(descriptor)
        facts = (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
        if facts != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns):
            raise SnapshotError("regular_file_changed_while_reading")
        return bytes(contents), before
    finally:
        os.close(descriptor)


def _write_snapshot_file(path: pathlib.Path, contents: bytes, source_mode: int = 0o600) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW, source_mode & 0o700)
    try:
        offset = 0
        while offset < len(contents):
            offset += os.write(descriptor, contents[offset:])
    finally:
        os.close(descriptor)


def _write_new_regular(path: pathlib.Path, contents: bytes) -> None:
    if len(contents) > MAX_RESULT_BYTES:
        raise SnapshotError("result_exceeds_byte_bound")
    _write_snapshot_file(path, contents)


def _parse_canonical_descriptor(descriptor_bytes: bytes) -> dict[str, Any] | None:
    if type(descriptor_bytes) is not bytes or not descriptor_bytes or len(descriptor_bytes) > MAX_DESCRIPTOR_BYTES:
        return None
    try:
        descriptor = json.loads(descriptor_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None
    return descriptor if isinstance(descriptor, dict) and _canonical_bytes(descriptor) == descriptor_bytes else None


def _adapter_inventory(adapter_inventory_bytes: bytes) -> dict[str, dict[str, Any]] | None:
    try:
        adapters = json.loads(adapter_inventory_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None
    if not isinstance(adapters, dict) or set(adapters) != {"schema", "adapters"}:
        return None
    rows = adapters.get("adapters")
    if adapters.get("schema") != "benchmark.cross_language.adapters.v1" or not isinstance(rows, list):
        return None
    by_id = {row.get("id"): row for row in rows if isinstance(row, dict)}
    return by_id if len(by_id) == len(rows) and all(isinstance(key, str) for key in by_id) else None


def admit_runnable_descriptor(descriptor_bytes: bytes, owner_task_inventory_bytes: bytes,
                              adapter_inventory_bytes: bytes) -> dict[str, Any]:
    """Extend, rather than duplicate, unavailable baseline admission."""
    descriptor = _parse_canonical_descriptor(descriptor_bytes)
    if descriptor is None or set(descriptor) != {"schema", "baseline", "execution"} or descriptor.get("schema") != SCHEMA:
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
    by_id = _adapter_inventory(adapter_inventory_bytes)
    if by_id is None:
        return _unavailable("invalid_adapter_inventory")
    execution = descriptor["execution"]
    required = {"classification", "adapter_id", "task_id", "adapter_inventory_sha256", "receipt", "receipt_sha256", "timeout_seconds", "tool_path", "tool_sha256", "tool_root", "tool_root_sha256", "linker_path", "linker_sha256", "link_editor_path", "link_editor_sha256", "sdk_root", "sdk_version", "sdk_build", "sdk_settings_sha256", "sdk_system_version_sha256"}
    if not isinstance(execution, dict) or set(execution) != required:
        return _unavailable("invalid_execution_provenance")
    if execution["classification"] != "local_fixture":
        return _unavailable("external_execution_requires_provisioned_review")
    if execution["adapter_inventory_sha256"] != _sha256(adapter_inventory_bytes):
        return _unavailable("adapter_inventory_drifted")
    if (not isinstance(execution["receipt"], str) or len(execution["receipt"].encode("utf-8")) > MAX_RECEIPT_BYTES
            or not isinstance(execution["receipt_sha256"], str)):
        return _unavailable("invalid_execution_receipt")
    if execution["receipt_sha256"] != _sha256(execution["receipt"].encode("utf-8")):
        return _unavailable("execution_receipt_digest_disagrees")
    if type(execution["timeout_seconds"]) is not int or not 1 <= execution["timeout_seconds"] <= MAX_TIMEOUT_SECONDS:
        return _unavailable("invalid_execution_bounds")
    if not all(isinstance(execution[field], str) for field in ("tool_path", "tool_sha256", "tool_root", "tool_root_sha256", "linker_path", "linker_sha256", "link_editor_path", "link_editor_sha256")):
        return _unavailable("invalid_tool_identity")
    tool = pathlib.Path(execution["tool_path"])
    tool_root = pathlib.Path(execution["tool_root"])
    if (not tool.is_absolute() or not tool_root.is_absolute() or tool != tool.resolve()
            or tool_root != tool_root.resolve() or tool != tool_root / "bin" / "rustc"):
        return _unavailable("invalid_tool_identity")
    linker = pathlib.Path(execution["linker_path"])
    if not linker.is_absolute():
        return _unavailable("invalid_tool_identity")
    link_editor = pathlib.Path(execution["link_editor_path"])
    if not link_editor.is_absolute() or link_editor.name != "ld":
        return _unavailable("invalid_tool_identity")
    if not all(isinstance(execution[field], str) for field in ("sdk_root", "sdk_version", "sdk_build", "sdk_settings_sha256", "sdk_system_version_sha256")):
        return _unavailable("invalid_sdk_identity")
    adapter = by_id.get(execution["adapter_id"])
    if not isinstance(execution["task_id"], str) or not isinstance(adapter, dict):
        return _unavailable("undeclared_task_or_adapter")
    if adapter.get("implemented") is not True:
        return _unavailable("adapter_remains_unavailable")
    owner = json.loads(owner_task_inventory_bytes.decode("utf-8"))
    task = next((row for row in owner["tasks"] if row["id"] == execution["task_id"]), None)
    if not isinstance(task, dict) or execution["adapter_id"] not in task["languages"]:
        return _unavailable("task_does_not_declare_adapter")
    return {"schema": SCHEMA, "status": "fixture_admitted", "baseline": baseline_decision["provenance"],
            "task_id": execution["task_id"], "adapter_id": execution["adapter_id"],
            "timeout_seconds": execution["timeout_seconds"], "tool_path": tool, "tool_sha256": execution["tool_sha256"],
            "tool_root": tool_root, "tool_root_sha256": execution["tool_root_sha256"],
            "linker_path": linker, "linker_sha256": execution["linker_sha256"], "link_editor_path": link_editor,
            "link_editor_sha256": execution["link_editor_sha256"],
            "sdk_root": pathlib.Path(execution["sdk_root"]), "sdk_version": execution["sdk_version"],
            "sdk_build": execution["sdk_build"], "sdk_settings_sha256": execution["sdk_settings_sha256"],
            "sdk_system_version_sha256": execution["sdk_system_version_sha256"]}


def _safe_relative(value: Any) -> pathlib.PurePosixPath:
    if not isinstance(value, str):
        raise SnapshotError("invalid_selected_source_path")
    relative = pathlib.PurePosixPath(value)
    if relative.is_absolute() or not relative.parts or any(part in ("", ".", "..") for part in relative.parts):
        raise SnapshotError("invalid_selected_source_path")
    return relative


def _admit_host_sdk(admitted: dict[str, Any]) -> tuple[pathlib.Path, pathlib.Path]:
    """Bind the narrow macOS SDK receipt without traversing its contents."""
    root = admitted["sdk_root"]
    if not root.is_absolute() or root.is_symlink() or root != root.resolve() or not root.is_dir():
        raise SnapshotError("sdk_root_refused")
    settings, _ = _read_regular(root / "SDKSettings.json", MAX_DESCRIPTOR_BYTES)
    version, _ = _read_regular(root / "System" / "Library" / "CoreServices" / "SystemVersion.plist", MAX_DESCRIPTOR_BYTES)
    if _sha256(settings) != admitted["sdk_settings_sha256"] or _sha256(version) != admitted["sdk_system_version_sha256"]:
        raise SnapshotError("sdk_receipt_drifted")
    try:
        settings_value = json.loads(settings.decode("utf-8"))
        version_value = plistlib.loads(version)
    except (UnicodeDecodeError, json.JSONDecodeError, plistlib.InvalidFileException):
        raise SnapshotError("sdk_receipt_invalid")
    if (settings_value.get("Version") != admitted["sdk_version"]
            or version_value.get("ProductVersion") != admitted["sdk_version"]
            or version_value.get("ProductBuildVersion") != admitted["sdk_build"]):
        raise SnapshotError("sdk_version_drifted")
    developer = root.parent.parent
    if developer.is_symlink() or not developer.is_dir() or developer != developer.resolve():
        raise SnapshotError("developer_root_refused")
    return root, developer


def _admit_host_executable(path: pathlib.Path, expected_sha256: str, label: str) -> pathlib.Path:
    """Bind one root-owned, canonical macOS linker executable for this fixture."""
    canonical = path.resolve()
    if path != canonical:
        raise SnapshotError(f"{label}_path_refused")
    data, facts = _read_regular(canonical, MAX_TOOL_BYTES)
    if _sha256(data) != expected_sha256:
        raise SnapshotError(f"{label}_identity_drifted")
    if facts.st_uid != 0 or facts.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
        raise SnapshotError(f"{label}_ownership_refused")
    return canonical


def _copy_tree(source: pathlib.Path, destination: pathlib.Path, digest: hashlib._Hash, budget: list[int],
               identity: pathlib.PurePosixPath) -> None:
    if source.is_symlink() or not source.is_dir():
        raise SnapshotError("selected_source_link_refused")
    try:
        entries = sorted(os.scandir(source), key=lambda entry: entry.name)
    except OSError as error:
        raise SnapshotError("selected_source_unavailable") from error
    destination.mkdir(mode=0o700, parents=True, exist_ok=True)
    for entry in entries:
        source_path = pathlib.Path(entry.path)
        target = destination / entry.name
        item_identity = identity / entry.name
        if entry.is_symlink():
            raise SnapshotError("selected_source_link_refused")
        if entry.is_dir(follow_symlinks=False):
            _copy_tree(source_path, target, digest, budget, item_identity)
        elif entry.is_file(follow_symlinks=False):
            data, source_stat = _read_regular(source_path, MAX_SOURCE_FILE_BYTES)
            budget[0] += len(data)
            if budget[0] > MAX_SOURCE_TOTAL_BYTES:
                raise SnapshotError("selected_source_exceeds_byte_bound")
            digest.update(str(item_identity).encode("utf-8"))
            digest.update(b"\0")
            digest.update(hashlib.sha256(data).digest())
            _write_snapshot_file(target, data, source_stat.st_mode)
        else:
            raise SnapshotError("selected_source_type_refused")


def _toolchain_digest(root: pathlib.Path, copy_to: pathlib.Path | None = None) -> str:
    """Hash and, when requested, privately materialize one complete tool root."""
    if not root.is_absolute() or root.is_symlink() or not root.is_dir():
        raise SnapshotError("toolchain_root_refused")
    digest = hashlib.sha256()
    budget = [0]

    def walk(source: pathlib.Path, relative: pathlib.PurePosixPath) -> None:
        try:
            entries = sorted(os.scandir(source), key=lambda entry: entry.name)
        except OSError as error:
            raise SnapshotError("toolchain_root_refused") from error
        if copy_to is not None:
            (copy_to / relative).mkdir(mode=0o700, parents=True, exist_ok=True)
        for entry in entries:
            item_relative = relative / entry.name
            source_path = pathlib.Path(entry.path)
            destination = copy_to / item_relative if copy_to is not None else None
            if entry.is_symlink():
                target = os.readlink(source_path)
                resolved = (source_path.parent / target).resolve()
                if root in (resolved, *resolved.parents):
                    digest.update(b"L\0" + str(item_relative).encode() + b"\0" + target.encode())
                    if destination is not None:
                        destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                        os.symlink(target, destination)
                elif resolved.is_file():
                    data, source_stat = _read_regular(resolved, MAX_TOOL_BYTES)
                    budget[0] += len(data)
                    if budget[0] > MAX_TOOLCHAIN_BYTES:
                        raise SnapshotError("toolchain_root_exceeds_byte_bound")
                    digest.update(b"X\0" + str(item_relative).encode() + b"\0" + target.encode() + hashlib.sha256(data).digest())
                    if destination is not None:
                        _write_snapshot_file(destination, data, source_stat.st_mode)
                else:
                    raise SnapshotError("toolchain_link_escapes_root")
            elif entry.is_dir(follow_symlinks=False):
                digest.update(b"D\0" + str(item_relative).encode() + b"\0")
                walk(source_path, item_relative)
            elif entry.is_file(follow_symlinks=False):
                data, source_stat = _read_regular(source_path, MAX_TOOL_BYTES)
                budget[0] += len(data)
                if budget[0] > MAX_TOOLCHAIN_BYTES:
                    raise SnapshotError("toolchain_root_exceeds_byte_bound")
                digest.update(b"F\0" + str(item_relative).encode() + b"\0" + hashlib.sha256(data).digest())
                if destination is not None:
                    _write_snapshot_file(destination, data, source_stat.st_mode)
            else:
                raise SnapshotError("toolchain_root_type_refused")

    walk(root, pathlib.PurePosixPath())
    return _sha256(digest.digest())


def _snapshot_adapter(adapters: bytes, adapter_id: str, tool: pathlib.Path, tool_sha256: str,
                      tool_root: pathlib.Path, tool_root_sha256: str, linker: pathlib.Path,
                      link_editor: pathlib.Path, root: pathlib.Path) -> bytes:
    copied_root = root / "toolchain"
    if _toolchain_digest(tool_root, copied_root) != tool_root_sha256:
        raise SnapshotError("toolchain_root_identity_drifted")
    tool_copy = copied_root / "bin" / "rustc"
    tool_data, _ = _read_regular(tool_copy.resolve(), MAX_TOOL_BYTES)
    if _sha256(tool_data) != tool_sha256:
        raise SnapshotError("tool_identity_drifted")
    document = json.loads(adapters.decode("utf-8"))
    adapter = next(row for row in document["adapters"] if row["id"] == adapter_id)
    for key in ("version_command", "build_command", "run_command"):
        command = adapter.get(key)
        if command is None:
            continue
        if not isinstance(command, list) or not command or any(not isinstance(arg, str) for arg in command):
            raise SnapshotError("selected_adapter_command_not_admitted")
        if key == "run_command" and command[0] == "./test_bin":
            continue
        if command[0] != "rustc":
            raise SnapshotError("selected_adapter_command_not_admitted")
        command[0] = str(tool_copy)
        if key == "build_command":
            command.extend(["-C", f"linker={linker}", "-C", f"link-arg=-B{link_editor.parent}"])
    return _canonical_bytes(document)


def _kill_group(process: subprocess.Popen) -> None:
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError):
        # A prior group kill may already have reaped the leader on Darwin.
        # Never treat that race as permission to resume execution.
        pass


def _run_bounded_group(command: list[str], cwd: pathlib.Path, deadline: float,
                       environment: dict[str, str]) -> tuple[int | None, bytes, bytes, str | None]:
    if os.name != "posix":
        return None, b"", b"", "posix_containment_unavailable"
    process = subprocess.Popen(command, cwd=cwd, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               text=False, env=environment, start_new_session=True)
    selector = selectors.DefaultSelector()
    streams = [process.stdout, process.stderr]
    for stream in streams:
        assert stream is not None
        os.set_blocking(stream.fileno(), False)
        selector.register(stream, selectors.EVENT_READ)
    captured = {process.stdout: bytearray(), process.stderr: bytearray()}
    reason = None
    while selector.get_map() and reason is None:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            reason = "execution_timed_out"
            break
        for key, _ in selector.select(min(remaining, 0.1)):
            chunk = os.read(key.fileobj.fileno(), min(8192, MAX_PROCESS_OUTPUT_BYTES + 1))
            if not chunk:
                selector.unregister(key.fileobj)
            else:
                captured[key.fileobj].extend(chunk)
                if len(captured[key.fileobj]) > MAX_PROCESS_OUTPUT_BYTES:
                    reason = "execution_output_exceeded"
                    break
    selector.close()
    if reason is not None:
        _kill_group(process)
    try:
        process.wait(timeout=max(0.0, deadline - time.monotonic()))
    except subprocess.TimeoutExpired:
        reason = "execution_timed_out"
        _kill_group(process)
        process.wait()
    stdout = bytes(captured[process.stdout])
    stderr = bytes(captured[process.stderr])
    assert process.stdout is not None and process.stderr is not None
    process.stdout.close()
    process.stderr.close()
    return process.returncode, stdout, stderr, reason


def _after_snapshot_before_launch(snapshot_root: pathlib.Path) -> None:
    """Narrow test seam: production execution has no action between bind and launch."""
    del snapshot_root


def execute_local_fixture(descriptor_bytes: bytes, owner_task_inventory_bytes: bytes,
                          adapter_inventory_bytes: bytes, root: pathlib.Path) -> dict[str, Any]:
    """Execute one immutable snapshot; never fall back to ambient tooling."""
    admitted = admit_runnable_descriptor(descriptor_bytes, owner_task_inventory_bytes, adapter_inventory_bytes)
    if admitted.get("status") != "fixture_admitted":
        return admitted
    if os.name != "posix" or root.resolve() != ROOT.resolve():
        return _unavailable("posix_snapshot_execution_unavailable")
    try:
        tasks_now, _ = _read_regular(TASKS, MAX_DESCRIPTOR_BYTES)
        adapters_now, _ = _read_regular(ADAPTERS, MAX_DESCRIPTOR_BYTES)
        if tasks_now != owner_task_inventory_bytes or adapters_now != adapter_inventory_bytes:
            return _unavailable("execution_inputs_drifted")
        sdk_root, developer_root = _admit_host_sdk(admitted)
        linker = _admit_host_executable(admitted["linker_path"], admitted["linker_sha256"], "linker")
        link_editor = _admit_host_executable(admitted["link_editor_path"], admitted["link_editor_sha256"], "link_editor")
        deadline = time.monotonic() + admitted["timeout_seconds"]
        with tempfile.TemporaryDirectory(prefix="spx-runnable-adapter-") as temporary:
            snapshot_root = pathlib.Path(temporary) / "repository"
            snapshot_suite = snapshot_root / "benchmarks" / "cross-language-v1"
            runner_bytes, runner_stat = _read_regular(RUNNER, MAX_SOURCE_FILE_BYTES)
            _write_snapshot_file(snapshot_suite / "run.py", runner_bytes, runner_stat.st_mode)
            _write_snapshot_file(snapshot_suite / "runnable-descriptor.json", descriptor_bytes)
            _write_snapshot_file(snapshot_suite / "tasks.json", owner_task_inventory_bytes)
            inventory = json.loads(owner_task_inventory_bytes.decode("utf-8"))
            task = next(row for row in inventory["tasks"] if row["id"] == admitted["task_id"])
            paths = task["languages"][admitted["adapter_id"]]
            tree_digest = hashlib.sha256()
            budget = [0]
            for kind in ("public", "hidden"):
                relative = _safe_relative(paths[kind])
                _copy_tree(root / relative, snapshot_root / relative, tree_digest, budget, relative)
            equivalence = _safe_relative(task["equivalence"])
            equivalence_source = root / "benchmarks" / "cross-language-v1" / equivalence
            equivalence_bytes, equivalence_stat = _read_regular(equivalence_source, MAX_SOURCE_FILE_BYTES)
            budget[0] += len(equivalence_bytes)
            if budget[0] > MAX_SOURCE_TOTAL_BYTES:
                raise SnapshotError("selected_source_exceeds_byte_bound")
            equivalence_identity = pathlib.PurePosixPath("benchmarks/cross-language-v1") / equivalence
            tree_digest.update(str(equivalence_identity).encode("utf-8"))
            tree_digest.update(b"\0\0")
            tree_digest.update(hashlib.sha256(equivalence_bytes).digest())
            _write_snapshot_file(snapshot_root / equivalence_identity, equivalence_bytes, equivalence_stat.st_mode)
            snapshotted_adapters = _snapshot_adapter(
                adapter_inventory_bytes, admitted["adapter_id"], admitted["tool_path"], admitted["tool_sha256"],
                admitted["tool_root"], admitted["tool_root_sha256"], linker, link_editor, snapshot_root,
            )
            _write_snapshot_file(snapshot_suite / "adapters.json", snapshotted_adapters)
            output = snapshot_root / "result.json"
            command = [sys.executable, str(snapshot_suite / "run.py"), "--hardened-posix",
                       "--execution-deadline-monotonic", repr(deadline), "--execution-output-bytes", str(MAX_PROCESS_OUTPUT_BYTES),
                       "--root", str(snapshot_root), "--tasks", str(snapshot_suite / "tasks.json"),
                       "--adapters", str(snapshot_suite / "adapters.json"), "--only", admitted["task_id"],
                       "--language", admitted["adapter_id"], "--output", str(output)]
            _after_snapshot_before_launch(snapshot_root)
            code, _, _, reason = _run_bounded_group(
                command, snapshot_root, deadline,
                CLOSED_ENVIRONMENT | {"SDKROOT": str(sdk_root), "DEVELOPER_DIR": str(developer_root)},
            )
            if reason is not None:
                return _unavailable(reason)
            if code != 0:
                return _unavailable("fixture_execution_failed")
            result_bytes, _ = _read_regular(output, MAX_RESULT_BYTES)
            result = json.loads(result_bytes.decode("utf-8"))
    except SnapshotError as error:
        return _unavailable(str(error))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, KeyError, TypeError, ValueError):
        return _unavailable("snapshot_or_result_refused")
    rows = result.get("results") if isinstance(result, dict) else None
    if not isinstance(rows, list) or len(rows) != 1 or not isinstance(rows[0], dict) or rows[0].get("status") != "ok":
        return _unavailable("fixture_scoring_failed")
    return {"schema": SCHEMA, "status": "fixture_ok", "classification": "local_fixture",
            "snapshot_sha256": _sha256(tree_digest.digest()), "result": rows[0]}


def main() -> int:
    parser = argparse.ArgumentParser(description="bounded runnable-adapter fixture executor")
    parser.add_argument("--descriptor", required=True)
    parser.add_argument("--root", default=str(ROOT))
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    try:
        descriptor_bytes, _ = _read_regular(pathlib.Path(args.descriptor).absolute(), MAX_DESCRIPTOR_BYTES)
        tasks_bytes, _ = _read_regular(TASKS, MAX_DESCRIPTOR_BYTES)
        adapters_bytes, _ = _read_regular(ADAPTERS, MAX_DESCRIPTOR_BYTES)
        result = execute_local_fixture(descriptor_bytes, tasks_bytes, adapters_bytes, pathlib.Path(args.root))
    except SnapshotError as error:
        result = _unavailable(str(error))
    try:
        _write_new_regular(pathlib.Path(args.output).absolute(), _canonical_bytes(result))
    except (SnapshotError, OSError):
        return 2
    return 0 if result.get("status") == "fixture_ok" else 1


if __name__ == "__main__":
    raise SystemExit(main())
