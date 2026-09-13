"""Fail-closed extraction of counters from archived OpenCode pilot evidence."""

import base64
import json


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
