#!/usr/bin/env python3
"""One local MCP argv tool over the pilot's lane-checked compiler gateway.

No shell command text, filesystem API, model transport, or dependency install.
The enclosing pilot still owns OS confinement, lane policy and archive custody.
"""
import base64
import json
import os
from pathlib import Path
import selectors
import signal
import subprocess
import sys
import time

CAP = 1_048_576
TOOL = {
    "name": "command",
    "description": "Run the lane-approved SEMAPRAX compiler gateway using an argv array, without a shell. For source-first use pilot-read for raw source, pilot-write-source <relative .spx> <expected lowercase sha256> <base64> for source replacement, and ordinary compiler commands. For graph-operational use graph/context/query for semantic inspection, pilot-write for bounded patch artifacts, and admitted workspace/candidate operations. The gateway enforces the selected lane.",
    "inputSchema": {"type": "object", "properties": {
        "argv": {"type": "array", "items": {"type": "string"}, "minItems": 1, "maxItems": 64}},
        "required": ["argv"], "additionalProperties": False},
}


def invoke(gateway, argv):
    if (not isinstance(argv, list) or not 1 <= len(argv) <= 64
            or any(not isinstance(x, str) or "\0" in x for x in argv)
            or sum(len(x.encode()) for x in argv) > CAP):
        raise ValueError("invalid bounded argv")
    process = subprocess.Popen([gateway, *argv], stdin=subprocess.DEVNULL,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               start_new_session=True)
    outputs = {process.stdout: bytearray(), process.stderr: bytearray()}
    selector = selectors.DefaultSelector()
    for stream in outputs:
        selector.register(stream, selectors.EVENT_READ)
    end = time.monotonic() + 60
    try:
        while selector.get_map():
            if time.monotonic() >= end:
                raise ValueError("compiler gateway timeout")
            for key, _ in selector.select(min(0.25, max(0, end - time.monotonic()))):
                data = os.read(key.fd, 65536)
                if not data:
                    selector.unregister(key.fileobj)
                    continue
                outputs[key.fileobj].extend(data)
                if sum(map(len, outputs.values())) > CAP:
                    raise ValueError("compiler gateway output exceeds bound")
        code = process.wait(timeout=max(0.001, end - time.monotonic()))
        return {"content": [{"type": "text", "text": json.dumps({
            "exit_code": code, "stdout": bytes(outputs[process.stdout]).decode("utf-8", "replace"),
            "stderr": bytes(outputs[process.stderr]).decode("utf-8", "replace")}, sort_keys=True)}],
            "isError": code != 0}
    finally:
        # Terminate leftover compiler descendants as well as timed-out work.
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait()
        selector.close()
        for stream in outputs:
            stream.close()


def dispatch(message, gateway):
    method = message.get("method")
    if method == "initialize":
        return {"protocolVersion": "2024-11-05", "capabilities": {"tools": {}},
                "serverInfo": {"name": "semaprax-pilot", "version": "1"}}
    if method == "ping":
        return {}
    if method == "tools/list":
        return {"tools": [TOOL]}
    if method == "tools/call":
        params = message.get("params", {})
        if not isinstance(params, dict):
            raise ValueError("invalid tool parameters")
        arguments = params.get("arguments", {})
        if params.get("name") != "command" or not isinstance(arguments, dict) or set(arguments) != {"argv"}:
            raise ValueError("unknown tool or arguments")
        return invoke(gateway, arguments["argv"])
    raise ValueError("unsupported method")


def main():
    gateway = str(Path(sys.argv[1]).resolve(strict=True))
    log = Path(sys.argv[2]) if len(sys.argv) == 3 else None
    max_log = 32 * CAP
    record_reservation = 14 * CAP
    while True:
        line = sys.stdin.buffer.readline(CAP + 1)
        if not line:
            return
        if len(line) > CAP:
            return
        message = None
        try:
            message = json.loads(line)
            if not isinstance(message, dict) or message.get("jsonrpc") != "2.0":
                raise ValueError("invalid JSON-RPC")
            if "id" not in message:
                continue
            if (log is not None and message.get("method") == "tools/call"
                    and (log.stat().st_size if log.exists() else 0) + record_reservation > max_log):
                raise ValueError("MCP evidence capacity exhausted before dispatch")
            result = {"jsonrpc": "2.0", "id": message["id"], "result": dispatch(message, gateway)}
        except (ValueError, OSError, subprocess.TimeoutExpired) as error:
            result = {"jsonrpc": "2.0", "id": message.get("id") if isinstance(message, dict) else None,
                      "error": {"code": -32602, "message": str(error)}}
        response = (json.dumps(result, separators=(",", ":"), ensure_ascii=False) + "\n").encode()
        if log is not None and isinstance(message, dict) and message.get("method") == "tools/call":
            record = (json.dumps({"request_b64": base64.b64encode(line).decode(),
                                  "response_b64": base64.b64encode(response).decode()},
                                 separators=(",", ":")) + "\n").encode()
            if (log.stat().st_size if log.exists() else 0) + len(record) > max_log:
                raise ValueError("MCP evidence archive exhausted")
            with log.open("ab") as stream:
                stream.write(record)
        sys.stdout.buffer.write(response)
        sys.stdout.buffer.flush()


if __name__ == "__main__":
    main()
