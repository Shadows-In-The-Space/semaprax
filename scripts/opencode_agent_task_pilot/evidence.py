"""Fail-closed extraction of counters from archived OpenCode pilot evidence."""

import base64
import hashlib
import json
from pathlib import Path


def _bytes(value, label):
    if not isinstance(value, str):
        raise ValueError(f"{label} must be base64 text")
    try:
        return base64.b64decode(value, validate=True)
    except Exception as error:
        raise ValueError(f"{label} is not canonical base64") from error


def gateway_diagnostics(body):
    """Summarize internal gateway argv/stdout records without calling them MCP metrics."""
    calls = []
    if not isinstance(body, bytes):
        raise ValueError("gateway body must be bytes")
    for line in body.splitlines():
        try:
            event = json.loads(line)
        except json.JSONDecodeError as error:
            raise ValueError("gateway log is not JSONL") from error
        if set(event) != {"argv_b64", "stdout_b64", "stderr_b64", "returncode"}:
            raise ValueError("gateway event has an unexpected shape")
        argv = _bytes(event["argv_b64"], "gateway argv")
        stdout = _bytes(event["stdout_b64"], "gateway stdout")
        stderr = _bytes(event["stderr_b64"], "gateway stderr")
        if isinstance(event["returncode"], bool) or not isinstance(event["returncode"], int):
            raise ValueError("gateway return code is invalid")
        # The synthetic harness injection is evidence of staleness, never a
        # model-issued tool call.
        if argv.startswith(b"pilot-drift\0"):
            continue
        calls.append(
            {
                "request_bytes": len(argv),
                "response_bytes": len(stdout) + len(stderr),
                "returncode": event["returncode"],
            }
        )
    return {
        "status": "observed",
        "gateway_invocations": len(calls),
        "gateway_argv_bytes": sum(call["request_bytes"] for call in calls),
        "gateway_stdio_bytes": sum(call["response_bytes"] for call in calls),
        "gateway_failures": sum(call["returncode"] != 0 for call in calls),
        "calls": calls,
    }


def mcp_tool_metrics(body):
    """Derive actual MCP `tools/call` wire bytes, never gateway internals."""
    calls = []
    if not isinstance(body, bytes):
        raise ValueError("MCP wire body must be bytes")
    for line in body.splitlines():
        try:
            frame = json.loads(line)
        except json.JSONDecodeError as error:
            raise ValueError("MCP wire log is not JSONL") from error
        if set(frame) != {"request_b64", "response_b64"}:
            raise ValueError("MCP wire frame has an unexpected shape")
        request = _bytes(frame["request_b64"], "MCP request")
        response = _bytes(frame["response_b64"], "MCP response")
        try:
            call = json.loads(request)
            reply = json.loads(response)
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise ValueError("MCP wire frame is not JSON") from error
        params = call.get("params") if isinstance(call, dict) else None
        arguments = params.get("arguments") if isinstance(params, dict) else None
        if (not isinstance(call, dict) or call.get("jsonrpc") != "2.0"
                or call.get("method") != "tools/call" or not isinstance(params, dict)
                or params.get("name") != "command" or not isinstance(arguments, dict)
                or set(arguments) != {"argv"}):
            raise ValueError("MCP wire frame is not the admitted compiler call")
        failed = not isinstance(reply, dict) or "error" in reply
        if not failed:
            result = reply.get("result")
            failed = not isinstance(result, dict) or result.get("isError") is True
        calls.append({"request_bytes": len(request), "response_bytes": len(response), "failed": failed})
    return {
        "status": "observed",
        "tool_calls": len(calls),
        "tool_request_bytes": sum(call["request_bytes"] for call in calls),
        "tool_response_bytes": sum(call["response_bytes"] for call in calls),
        "failed_attempts": sum(call["failed"] for call in calls),
        "calls": calls,
    }


def provider_usage(body, model):
    """Read only exact provider-reported token counters from an export.

    The caller may retain an unavailable result; it must never synthesize a
    zero or estimate tokens from text. Multiple assistant turns are retained
    separately because OpenCode's exported values are per message.
    """
    if not isinstance(body, bytes) or not isinstance(model, str) or "/" not in model:
        raise ValueError("provider usage inputs are invalid")
    provider, model_id = model.split("/", 1)
    try:
        session = json.loads(body)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        return {"status": "unavailable", "reason": "export is not a JSON object"}
    if not isinstance(session, dict) or not isinstance(session.get("messages"), list):
        return {"status": "unavailable", "reason": "export lacks message inventory"}
    rows = []
    for message in session["messages"]:
        info = message.get("info") if isinstance(message, dict) else None
        if not isinstance(info, dict) or info.get("role") != "assistant":
            continue
        if info.get("providerID") != provider or info.get("modelID") != model_id:
            return {"status": "unavailable", "reason": "assistant model binding differs"}
        tokens = info.get("tokens")
        if not isinstance(tokens, dict):
            return {"status": "unavailable", "reason": "assistant token counters are absent"}
        input_tokens, output_tokens = tokens.get("input"), tokens.get("output")
        if any(isinstance(value, bool) or not isinstance(value, int) or value < 0
               for value in (input_tokens, output_tokens)):
            return {"status": "unavailable", "reason": "assistant token counters are invalid"}
        rows.append({"input_tokens": input_tokens, "output_tokens": output_tokens})
    if not rows:
        return {"status": "unavailable", "reason": "export has no matching assistant usage"}
    return {
        "status": "observed",
        "model_input_tokens": sum(row["input_tokens"] for row in rows),
        "model_output_tokens": sum(row["output_tokens"] for row in rows),
        "messages": rows,
    }


def stream_provider_usage(body, expected_session, configured_model):
    """Derive provider-reported usage from exact OpenCode JSONL step finishes.

    This is an offline fallback when the exported session is truncated. It binds
    every counted finish to the caller's session identifier and configured
    provider/model; it never estimates tokens from stream bytes.
    """
    if not isinstance(body, bytes) or len(body) > 1_048_576 or not isinstance(expected_session, str) or not expected_session:
        return {"status": "unavailable", "reason": "stream usage inputs are invalid"}
    if (not isinstance(configured_model, str) or configured_model.count("/") != 1 or not all(configured_model.split("/"))
            or any(character.isspace() for character in configured_model)):
        return {"status": "unavailable", "reason": "configured model is invalid"}
    rows = []
    part_ids = set()
    message_ids = set()
    for line in body.splitlines():
        try:
            event = json.loads(line)
        except (UnicodeDecodeError, json.JSONDecodeError):
            return {"status": "unavailable", "reason": "stream is not JSONL"}
        if not isinstance(event, dict) or event.get("sessionID") != expected_session:
            return {"status": "unavailable", "reason": "stream session differs"}
        if event.get("type") != "step_finish":
            continue
        part = event.get("part")
        if (not isinstance(part, dict) or part.get("type") != "step-finish"
                or part.get("sessionID") != expected_session):
            return {"status": "unavailable", "reason": "step finish is malformed"}
        part_id, message_id = part.get("id"), part.get("messageID")
        if (not isinstance(part_id, str) or not part_id or not isinstance(message_id, str)
                or not message_id or part_id in part_ids or message_id in message_ids):
            return {"status": "unavailable", "reason": "step finish identity is invalid"}
        tokens = part.get("tokens")
        if not isinstance(tokens, dict):
            return {"status": "unavailable", "reason": "step finish token counters are absent"}
        cache = tokens.get("cache")
        if not isinstance(cache, dict):
            return {"status": "unavailable", "reason": "step finish cache counters are absent"}
        counters = [tokens.get("input"), tokens.get("output"), tokens.get("reasoning"),
                    cache.get("read"), cache.get("write")]
        if any(isinstance(value, bool) or not isinstance(value, int) or value < 0
               for value in counters):
            return {"status": "unavailable", "reason": "step finish token counters are invalid"}
        # OpenCode 1.18.27 Session.getUsage subtracts cache from input and
        # reasoning from output; reconstruct the full provider counters.
        input_tokens = counters[0] + counters[3] + counters[4]
        output_tokens = counters[1] + counters[2]
        part_ids.add(part_id)
        message_ids.add(message_id)
        rows.append({"message_id": message_id, "step_id": part_id,
                     "input_tokens": input_tokens, "output_tokens": output_tokens,
                     "uncached_input_tokens": counters[0], "text_output_tokens": counters[1],
                     "reasoning_tokens": counters[2], "cache_read_tokens": counters[3],
                     "cache_write_tokens": counters[4]})
    if not rows:
        return {"status": "unavailable", "reason": "stream has no matching step finishes"}
    return {
        "status": "observed",
        "method": "configured-model CLI stream report",
        "configured_model": configured_model,
        "session_id": expected_session,
        "model_input_tokens": sum(row["input_tokens"] for row in rows),
        "model_output_tokens": sum(row["output_tokens"] for row in rows),
        "messages": rows,
    }


def write_stream_provider_usage_derivation(evidence_dir, expected_session, configured_model):
    """Write a new offline stream-usage artifact without altering raw evidence."""
    evidence = Path(evidence_dir)
    stream = evidence / "stdout.jsonl"
    record = evidence / "record.json"
    output = evidence / "provider-usage-stream-v2.json"
    if not evidence.is_dir() or not stream.is_file() or not record.is_file() or output.exists():
        raise ValueError("stream usage derivation requires untouched pilot evidence")
    if stream.is_symlink() or stream.stat().st_nlink != 1 or stream.stat().st_size > 1_048_576:
        raise ValueError("stream usage source is not bounded regular evidence")
    body = stream.read_bytes()
    derived = stream_provider_usage(body, expected_session, configured_model)
    derived["source"] = {"path": "stdout.jsonl", "bytes": len(body),
                         "sha256": hashlib.sha256(body).hexdigest()}
    with output.open("x", encoding="utf-8") as destination:
        destination.write(json.dumps(derived, sort_keys=True, separators=(",", ":")) + "\n")
    return output
