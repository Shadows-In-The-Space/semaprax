"""Real, fail-closed measurement and eligibility for the four missing pilot metrics.

Issue #105 established that all 18 frozen 2026-09-13 pilot tuples are ineligible for
exactly four missing measurements: exact model-context presentation bytes, blinded
active review time, complete typed stale/recovery metrics, and the intervention
ledger. Before this module the runner never measured any of them: eligibility was a
hardcoded string (`ineligibility_reason`) and `replay.py` hardcoded
`eligible_observation: False`.

This module gives each of the four a precise definition, a deterministic
serialization, and a fail-closed reader/writer pair. `compute_eligibility` is the
single predicate: a trial is eligible only when all four are present and internally
consistent; any missing or malformed measurement makes it ineligible and names the
metric by exact string, never raises, and never fabricates a zero. It computes
nothing for the 2026-09-13 cohort's archived evidence directories beyond what their
already-archived transport bytes actually contain: those trials never recorded a
blinded review or an intervention ledger, so they remain ineligible.
"""
import base64
import hashlib
import json
import os
from pathlib import Path
import stat
import time

from opencode_agent_task_pilot.evidence import _bytes as decode_base64

DRIFT_TARGET = "src/core.spx"
STALE_WRITE_RETURN_CODE = 126
STALE_WRITE_REFUSAL = b"pilot-write-source precondition is stale\n"
MAX_PILOT_WRITE_SOURCE_BYTES = 1_048_576

STALE_TRIGGER_KINDS = ("drift_on_source_read", "drift_on_identifying_command")
STALE_IDENTIFYING_COMMANDS = frozenset(
    {"graph", "context", "query", "workspace-graph", "workspace-context"}
)
RECOVERY_OUTCOME_KINDS = (
    "recovered_conditional_write",
    "rejected_stale_write",
    "no_recovery_attempt",
)

REVIEW_SCHEMA = "semaprax.opencode-agent-task-pilot-blinded-review.v1"
REVIEW_KEYS = frozenset(
    {"schema", "reviewer_id", "blinded", "diff_sha256", "started_monotonic_ns",
     "stopped_monotonic_ns", "active_ms"}
)
REVIEW_KEYS_V2 = REVIEW_KEYS | frozenset({"candidate_digest", "packet_sha256", "verdict"})
MAX_REVIEW_BYTES = 65536

INTERVENTION_SCHEMA = "semaprax.opencode-agent-task-pilot-intervention.v1"
INTERVENTION_KEYS = frozenset({"schema", "sequence", "kind", "target", "timestamp_ns", "note"})
INTERVENTION_KINDS = (
    "timeout_extension",
    "manual_process_kill",
    "manual_source_edit",
    "manual_harness_restart",
    "manual_config_override",
    "other_operator_action",
)
MAX_INTERVENTION_LEDGER_BYTES = 1_048_576


# --- 1. presentation bytes -------------------------------------------------


def presented_context_bytes(prompt, mcp_metrics):
    """Exact bytes made visible to the model at the pilot's own transport boundary.

    Defined as the frozen task prompt bytes (presented exactly once, at session
    start) plus every MCP `tools/call` response byte returned to the model as tool
    context (`mcp_metrics['tool_response_bytes']`), summed with repeats across the
    whole trial. Both terms are exact bytes captured on a transport the pilot
    itself owns (the literal argv handed to `opencode run`, and the literal MCP
    wire frames archived in `mcp-wire.jsonl`); neither is estimated from a token
    count. `mcp_metrics` must be an `observed` result from
    `opencode_agent_task_pilot.evidence.mcp_tool_metrics`; anything else makes this
    unavailable rather than a guess.
    """
    if not isinstance(prompt, str) or not prompt:
        return {"status": "unavailable", "reason": "frozen task prompt text is missing"}
    if not isinstance(mcp_metrics, dict) or mcp_metrics.get("status") != "observed":
        return {"status": "unavailable", "reason": "MCP tool response wire is not observed"}
    tool_response_bytes = mcp_metrics.get("tool_response_bytes")
    if (
        isinstance(tool_response_bytes, bool)
        or not isinstance(tool_response_bytes, int)
        or tool_response_bytes < 0
    ):
        return {"status": "unavailable", "reason": "MCP tool response byte total is invalid"}
    prompt_bytes = len(prompt.encode("utf-8"))
    return {
        "status": "observed",
        "method": "prompt_bytes_plus_mcp_tool_response_wire_bytes",
        "prompt_bytes": prompt_bytes,
        "tool_response_bytes": tool_response_bytes,
        "presented_context_bytes": prompt_bytes + tool_response_bytes,
    }


# --- 2. blinded active review time -----------------------------------------


def record_blinded_review(evidence_dir, reviewer_id, started_ns, stopped_ns, active_ms, blinded,
                          packet_path=None, candidate_digest=None, verdict=None):
    """Write one operator-supplied blinded active review record, once.

    The reviewer works from a packet whose direct lane, model, and runner
    labels are withheld; task content and paths remain visible by design.
    Blinding is an operator attestation via `blinded=True`; any other value
    fails closed. Interval fields are milliseconds/nanoseconds; `active_ms` must be
    positive and no larger than the wall interval it was measured inside, so a
    fabricated or inconsistent number cannot be recorded. Exclusive file creation
    means a trial gets exactly one review record; a redo needs a fresh trial.
    """
    evidence_dir = Path(evidence_dir)
    from opencode_agent_task_pilot.review_workflow import _read_regular
    diff = evidence_dir / "candidate.diff"
    diff_body = _read_regular(diff, 2 * 1024 * 1024)
    if blinded is not True:
        raise ValueError("a review record must attest blinded=True to be recorded")
    if not isinstance(reviewer_id, str) or not reviewer_id:
        raise ValueError("reviewer id is required")
    if any(
        isinstance(value, bool) or not isinstance(value, int)
        for value in (started_ns, stopped_ns, active_ms)
    ):
        raise ValueError("review interval fields must be plain integers")
    if started_ns < 0 or stopped_ns < 0 or active_ms < 0:
        raise ValueError("review interval fields must be nonnegative")
    if stopped_ns <= started_ns:
        raise ValueError("review stop must be strictly after review start")
    elapsed_ms = (stopped_ns - started_ns) // 1_000_000
    if not (0 < active_ms <= elapsed_ms):
        raise ValueError("active review time must be positive and within the elapsed interval")
    packet_sha256 = None
    if packet_path is not None:
        from opencode_agent_task_pilot.review_workflow import candidate_digest_for_evidence, load_review_packet
        fixed_packet = evidence_dir / "review-packet.json"
        if Path(packet_path).resolve() != fixed_packet.resolve():
            raise ValueError("review packet must be the fixed evidence packet")
        packet_path = fixed_packet
        packet = load_review_packet(packet_path)
        live_digest = candidate_digest_for_evidence(evidence_dir)
        if packet["candidate_digest"] != live_digest:
            raise ValueError("review packet is stale for the archived candidate")
        if candidate_digest != packet["candidate_digest"]:
            raise ValueError("review submission candidate digest differs from packet")
        if verdict not in ("accept", "reject"):
            raise ValueError("packet-bound review requires verdict accept or reject")
        packet_sha256 = hashlib.sha256(_read_regular(packet_path, 8 * 1024 * 1024)).hexdigest()
    elif candidate_digest is not None:
        raise ValueError("candidate digest requires a review packet")
    record = {
        "schema": REVIEW_SCHEMA,
        "reviewer_id": reviewer_id,
        "blinded": True,
        "diff_sha256": hashlib.sha256(diff_body).hexdigest(),
        "started_monotonic_ns": started_ns,
        "stopped_monotonic_ns": stopped_ns,
        "active_ms": active_ms,
    }
    if packet_sha256 is not None:
        record["candidate_digest"] = candidate_digest
        record["packet_sha256"] = packet_sha256
        record["verdict"] = verdict
    path = evidence_dir / "review.json"
    body = (json.dumps(record, sort_keys=True) + "\n").encode("utf-8")
    fd = None
    created = False
    try:
        if not hasattr(os, "O_NOFOLLOW"):
            raise ValueError("safe no-follow review writes are unavailable")
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        created = True
        written = 0
        while written < len(body):
            count = os.write(fd, body[written:])
            if count <= 0:
                raise ValueError("review write made no progress")
            written += count
    except (OSError, ValueError):
        if created:
            try:
                held = os.fstat(fd)
                current = os.stat(path, follow_symlinks=False)
                if (held.st_dev, held.st_ino) == (current.st_dev, current.st_ino):
                    os.unlink(path)
            except OSError:
                pass
        raise
    finally:
        if fd is not None:
            os.close(fd)
    return record


def blinded_review_slot(evidence_dir):
    """Read the recorded input slot for blinded active review time.

    This never fabricates a number: with no `review.json` in `evidence_dir` the
    metric is simply unavailable, and any shape, attestation, or binding defect
    (not blinded, wrong diff, non-positive or out-of-range interval) is also
    unavailable rather than silently accepted or zeroed.
    """
    evidence_dir = Path(evidence_dir)
    path = evidence_dir / "review.json"
    if not path.exists() or path.is_symlink():
        return {"status": "unavailable", "reason": "no blinded review record is present"}
    try:
        from opencode_agent_task_pilot.review_workflow import (
            _read_regular, candidate_digest_for_evidence, load_review_packet,
        )
        value = json.loads(_read_regular(path, MAX_REVIEW_BYTES).decode("utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError):
        return {"status": "unavailable", "reason": "blinded review record is not readable JSON"}
    if not isinstance(value, dict) or set(value) not in (REVIEW_KEYS, REVIEW_KEYS_V2):
        return {"status": "unavailable", "reason": "blinded review record has an unexpected shape"}
    if value.get("schema") != REVIEW_SCHEMA:
        return {"status": "unavailable", "reason": "blinded review record schema differs"}
    if value.get("blinded") is not True:
        return {"status": "unavailable", "reason": "review was not attested as blinded"}
    reviewer_id = value.get("reviewer_id")
    if not isinstance(reviewer_id, str) or not reviewer_id:
        return {"status": "unavailable", "reason": "blinded review reviewer id is missing"}
    started, stopped, active = (
        value.get("started_monotonic_ns"), value.get("stopped_monotonic_ns"), value.get("active_ms"),
    )
    if any(isinstance(item, bool) or not isinstance(item, int) for item in (started, stopped, active)):
        return {"status": "unavailable", "reason": "blinded review interval fields are not integers"}
    if stopped <= started:
        return {"status": "unavailable", "reason": "blinded review interval is non-positive"}
    elapsed_ms = (stopped - started) // 1_000_000
    if not (0 < active <= elapsed_ms):
        return {"status": "unavailable", "reason": "blinded active review time is outside the elapsed interval"}
    diff = evidence_dir / "candidate.diff"
    if not diff.is_file() or diff.is_symlink():
        return {"status": "unavailable", "reason": "candidate diff for blinded review binding is absent"}
    diff_body = _read_regular(diff, 2 * 1024 * 1024)
    if value.get("diff_sha256") != hashlib.sha256(diff_body).hexdigest():
        return {"status": "unavailable", "reason": "blinded review binds a different candidate diff"}
    if set(value) == REVIEW_KEYS:
        return {
            "status": "observed", "assurance": "legacy_unbound",
            "review_wall_ms": active, "reviewer_id": reviewer_id,
            "diff_sha256": value["diff_sha256"],
        }
    if set(value) != REVIEW_KEYS_V2:
        return {"status": "unavailable", "reason": "review packet binding is malformed"}
    if (not isinstance(value.get("candidate_digest"), str) or len(value["candidate_digest"]) != 64 or
            any(c not in "0123456789abcdef" for c in value["candidate_digest"]) or
            not isinstance(value.get("packet_sha256"), str) or len(value["packet_sha256"]) != 64 or
            any(c not in "0123456789abcdef" for c in value["packet_sha256"])):
        return {"status": "unavailable", "reason": "review packet binding is malformed"}
    if value.get("verdict") not in ("accept", "reject"):
        return {"status": "unavailable", "reason": "review verdict is invalid"}
    packet_path = evidence_dir / "review-packet.json"
    try:
        packet_bytes = _read_regular(packet_path, 8 * 1024 * 1024)
        packet = load_review_packet(packet_path)
        live_digest = candidate_digest_for_evidence(evidence_dir)
    except ValueError as error:
        return {"status": "unavailable", "reason": str(error)}
    if hashlib.sha256(packet_bytes).hexdigest() != value["packet_sha256"]:
        return {"status": "unavailable", "reason": "review packet was deleted or replaced"}
    if packet["candidate_digest"] != value["candidate_digest"] or live_digest != value["candidate_digest"]:
        return {"status": "unavailable", "reason": "review packet candidate digest is stale"}
    return {
        "status": "observed",
        "assurance": "packet_bound",
        "review_wall_ms": active,
        "reviewer_id": reviewer_id,
        "diff_sha256": value["diff_sha256"],
        "verdict": value["verdict"],
    }


# --- 3. typed stale/recovery metrics ----------------------------------------


def _decode_gateway_events(gateway_log_bytes):
    if not isinstance(gateway_log_bytes, bytes):
        raise ValueError("gateway body must be bytes")
    events = []
    for line in gateway_log_bytes.splitlines():
        try:
            event = json.loads(line)
        except json.JSONDecodeError as error:
            raise ValueError("gateway log is not JSONL") from error
        if not isinstance(event, dict) or set(event) != {
            "argv_b64", "stdout_b64", "stderr_b64", "returncode",
        }:
            raise ValueError("gateway event has an unexpected shape")
        argv_bytes = decode_base64(event["argv_b64"], "gateway argv")
        if isinstance(event["returncode"], bool) or not isinstance(event["returncode"], int):
            raise ValueError("gateway return code is invalid")
        argv = argv_bytes.decode("utf-8", "surrogateescape").split("\0")
        events.append({
            "argv": argv,
            "stderr": decode_base64(event["stderr_b64"], "gateway stderr"),
            "returncode": event["returncode"],
        })
    return events


def _valid_pilot_write_source(argv):
    """Whether argv is exactly the gateway's conditional source-write shape."""
    if (
        len(argv) != 4
        or argv[0] != "pilot-write-source"
    ):
        return False
    digest, encoded = argv[2:]
    if len(digest) != 64 or any(character not in "0123456789abcdef" for character in digest):
        return False
    try:
        body = base64.b64decode(encoded, validate=True)
    except (ValueError, TypeError):
        return False
    return len(body) <= MAX_PILOT_WRITE_SOURCE_BYTES and base64.b64encode(body).decode("ascii") == encoded


def stale_recovery_events(gateway_log_bytes, drift_declared):
    """Typed, mechanical classification of the drift trigger and its recovery.

    `drift_declared` must be the manifest binding's exact `drift_patch is not
    None` truth value for this task. A task with no declared drift scenario must
    show zero triggers; one with a declared scenario must show exactly one -
    anything else is internally inconsistent and reported unavailable rather than
    coerced.

    For the one trigger (if any), the outcome is read from the first later
    exactly shaped `pilot-write-source src/core.spx <lowercase-sha256>
    <canonical-base64>` command, which is the sole admitted conditional
    source-recovery action in the source-first lane:
    `recovered_conditional_write` (that write succeeded),
    `rejected_stale_write` (the gateway returned its exact stale-precondition
    refusal),
    or `no_recovery_attempt` (no such write occurred). A later read or an
    unrelated command mentioning the path is *not* recovery and cannot turn
    this metric into a false success. A malformed source-write record or any
    other write failure is unavailable rather than being relabelled as stale.
    This reads real recorded exit codes; it makes no claim about source-level
    correctness, which is the separate job of `independent_acceptance`.
    """
    if not isinstance(drift_declared, bool):
        raise ValueError("drift_declared must be an explicit boolean")
    events = _decode_gateway_events(gateway_log_bytes)
    triggers = []
    for index, event in enumerate(events):
        argv = event["argv"]
        if argv[:1] != ["pilot-drift"]:
            continue
        if len(argv) != 2 or argv[1] not in {"pilot-read", *STALE_IDENTIFYING_COMMANDS}:
            return {"status": "unavailable", "reason": "gateway drift trigger is malformed"}
        trigger_command = argv[1]
        trigger_kind = (
            "drift_on_source_read"
            if trigger_command == "pilot-read"
            else "drift_on_identifying_command"
        )
        outcome = "no_recovery_attempt"
        for later in events[index + 1:]:
            later_argv = later["argv"]
            if later_argv[:1] != ["pilot-write-source"]:
                continue
            if not _valid_pilot_write_source(later_argv):
                return {"status": "unavailable", "reason": "gateway source-recovery write is malformed"}
            if later_argv[1] != DRIFT_TARGET:
                continue
            if later["returncode"] == 0:
                if later["stderr"]:
                    return {"status": "unavailable", "reason": "successful source-recovery write wrote stderr"}
                outcome = "recovered_conditional_write"
            elif (
                later["returncode"] == STALE_WRITE_RETURN_CODE
                and later["stderr"] == STALE_WRITE_REFUSAL
            ):
                outcome = "rejected_stale_write"
            else:
                return {"status": "unavailable", "reason": "source-recovery write did not have the gateway stale-precondition refusal"}
            break
        triggers.append({"trigger": trigger_kind, "recovery_outcome": outcome})
    if drift_declared and not triggers:
        return {
            "status": "unavailable",
            "reason": "manifest declares a drift scenario but the gateway recorded no trigger",
        }
    if not drift_declared and triggers:
        return {
            "status": "unavailable",
            "reason": "gateway recorded a drift trigger for a task without one",
        }
    if len(triggers) > 1:
        return {"status": "unavailable", "reason": "gateway recorded more than one drift trigger"}
    return {
        "status": "observed",
        "stale_failures": len(triggers),
        "stale_recovery_actions": sum(
            trigger["recovery_outcome"] == "recovered_conditional_write" for trigger in triggers
        ),
        "events": triggers,
    }


# --- 4. intervention ledger ---------------------------------------------------


def append_intervention(evidence_dir, kind, target, note=None, timestamp_ns=None):
    """Append one entry to a trial's append-only operator intervention ledger.

    Entries are ordered by a strictly increasing `sequence` starting at 1 and by
    non-decreasing `timestamp_ns`; the file is opened for append only, so an
    earlier entry can never be rewritten. `kind` must be one of the closed
    `INTERVENTION_KINDS`.
    """
    if kind not in INTERVENTION_KINDS:
        raise ValueError(f"intervention kind must be one of {INTERVENTION_KINDS}")
    if not isinstance(target, str) or not target:
        raise ValueError("intervention target is required")
    if note is not None and not isinstance(note, str):
        raise ValueError("intervention note must be text or absent")
    evidence_dir = Path(evidence_dir)
    path = evidence_dir / "interventions.jsonl"
    existing = intervention_ledger(evidence_dir) if path.exists() else {"status": "observed", "events": []}
    if existing["status"] != "observed":
        raise ValueError(f"cannot append to a malformed intervention ledger: {existing['reason']}")
    prior_events = existing["events"]
    last_timestamp = prior_events[-1]["timestamp_ns"] if prior_events else -1
    when = timestamp_ns if timestamp_ns is not None else time.time_ns()
    if isinstance(when, bool) or not isinstance(when, int) or when < 0:
        raise ValueError("intervention timestamp must be a nonnegative integer")
    if when < last_timestamp:
        raise ValueError("intervention timestamp precedes the ledger's last recorded entry")
    entry = {
        "schema": INTERVENTION_SCHEMA,
        "sequence": len(prior_events) + 1,
        "kind": kind,
        "target": target,
        "timestamp_ns": when,
        "note": note,
    }
    body = (json.dumps(entry, sort_keys=True) + "\n").encode("utf-8")
    fd = None
    try:
        fd = os.open(path, os.O_WRONLY | os.O_APPEND | getattr(os, "O_NOFOLLOW", 0))
        held = os.fstat(fd)
        if not stat.S_ISREG(held.st_mode) or held.st_nlink != 1:
            raise ValueError("intervention ledger is not a bounded regular file")
        current = os.stat(path, follow_symlinks=False)
        if (current.st_dev, current.st_ino) != (held.st_dev, held.st_ino):
            raise ValueError("intervention ledger changed during append")
        written = 0
        while written < len(body):
            count = os.write(fd, body[written:])
            if count <= 0:
                raise ValueError("intervention ledger append made no progress")
            written += count
        if os.fstat(fd).st_size != held.st_size + len(body):
            raise ValueError("intervention ledger append was incomplete")
    except OSError as error:
        raise ValueError("intervention ledger is not safely appendable") from error
    finally:
        if fd is not None:
            os.close(fd)
    return entry


def intervention_ledger(evidence_dir):
    """Read and validate a trial's append-only operator intervention ledger.

    A present, empty ledger (zero interventions) is a valid `observed` result
    with `human_interventions: 0` - its existence and digest are the auditable
    basis for that zero. An absent ledger file is unavailable, never a
    fabricated zero. Any structural defect (bad JSON, wrong shape, non-monotonic
    sequence or timestamp, an unknown kind) is also unavailable rather than
    partially trusted.
    """
    path = Path(evidence_dir) / "interventions.jsonl"
    if not path.exists() or path.is_symlink():
        return {"status": "unavailable", "reason": "intervention ledger file is absent"}
    try:
        from opencode_agent_task_pilot.review_workflow import _read_regular
        body = _read_regular(path, MAX_INTERVENTION_LEDGER_BYTES)
    except (OSError, ValueError):
        return {"status": "unavailable", "reason": "intervention ledger is not readable"}
    events = []
    expected_sequence = 0
    last_timestamp = -1
    for line in body.splitlines():
        try:
            entry = json.loads(line)
        except json.JSONDecodeError:
            return {"status": "unavailable", "reason": "intervention ledger is not JSONL"}
        if not isinstance(entry, dict) or set(entry) != INTERVENTION_KEYS:
            return {"status": "unavailable", "reason": "intervention ledger entry has an unexpected shape"}
        if entry.get("schema") != INTERVENTION_SCHEMA:
            return {"status": "unavailable", "reason": "intervention ledger entry schema differs"}
        expected_sequence += 1
        if entry.get("sequence") != expected_sequence:
            return {"status": "unavailable", "reason": "intervention ledger sequence is not append-only"}
        if entry.get("kind") not in INTERVENTION_KINDS:
            return {"status": "unavailable", "reason": "intervention ledger kind is not a closed enum member"}
        target = entry.get("target")
        if not isinstance(target, str) or not target:
            return {"status": "unavailable", "reason": "intervention ledger target is missing"}
        timestamp = entry.get("timestamp_ns")
        if isinstance(timestamp, bool) or not isinstance(timestamp, int) or timestamp < last_timestamp:
            return {"status": "unavailable", "reason": "intervention ledger timestamps are not monotonic"}
        last_timestamp = timestamp
        note = entry.get("note")
        if note is not None and not isinstance(note, str):
            return {"status": "unavailable", "reason": "intervention ledger note must be text or null"}
        events.append(entry)
    return {
        "status": "observed",
        "human_interventions": len(events),
        "events": events,
        "sha256": hashlib.sha256(body).hexdigest(),
    }


def initialize_intervention_ledger(evidence_dir):
    """Create a trial's empty intervention ledger file, exactly once.

    Call this when a trial's evidence directory is created, before any run
    activity, so the ledger's existence (even with zero entries) is itself
    part of that trial's evidence rather than an artifact assembled after the
    fact.
    """
    path = Path(evidence_dir) / "interventions.jsonl"
    path.touch(exist_ok=False)
    return path


# --- combined eligibility predicate ------------------------------------------


def compute_eligibility(*, prompt, mcp_metrics, gateway_log_bytes, drift_declared, evidence_dir):
    """The one eligibility predicate: eligible only when all four measurements
    are present and internally consistent. Never raises - any unexpected defect
    in an individual measurement is treated as that measurement being missing,
    which makes the whole trial ineligible and names the metric, rather than
    crashing or silently passing.
    """
    reasons = []

    try:
        context = presented_context_bytes(prompt, mcp_metrics)
    except Exception as error:  # noqa: BLE001 - fail closed, never propagate
        context = {"status": "unavailable", "reason": f"presentation byte computation failed: {error}"}
    if context.get("status") != "observed":
        reasons.append("presentation bytes: " + context.get("reason", "unavailable"))

    try:
        stale = stale_recovery_events(gateway_log_bytes, drift_declared)
    except Exception as error:  # noqa: BLE001 - fail closed, never propagate
        stale = {"status": "unavailable", "reason": f"stale/recovery computation failed: {error}"}
    if stale.get("status") != "observed":
        reasons.append("typed stale/recovery metrics: " + stale.get("reason", "unavailable"))

    try:
        review = blinded_review_slot(evidence_dir)
    except Exception as error:  # noqa: BLE001 - fail closed, never propagate
        review = {"status": "unavailable", "reason": f"blinded review computation failed: {error}"}
    if review.get("status") != "observed":
        reasons.append("blinded active review time: " + review.get("reason", "unavailable"))
    elif review.get("assurance") != "packet_bound":
        reasons.append("blinded active review time: legacy review lacks packet binding")

    try:
        interventions = intervention_ledger(evidence_dir)
    except Exception as error:  # noqa: BLE001 - fail closed, never propagate
        interventions = {"status": "unavailable", "reason": f"intervention ledger computation failed: {error}"}
    if interventions.get("status") != "observed":
        reasons.append("intervention ledger: " + interventions.get("reason", "unavailable"))

    return {
        "eligible": not reasons,
        "reasons": reasons,
        "presentation_bytes": context,
        "stale_recovery": stale,
        "blinded_review": review,
        "intervention_ledger": interventions,
    }
