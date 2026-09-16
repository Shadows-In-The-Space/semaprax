#!/usr/bin/env python3
"""Compile/replay native settlement evidence. Standard library + C11 compiler.

Uses the same manifest, C observers, provider body and probe as the existing
Cargo integration harness. It does not claim to run the Rust or Wasm models.
Evidence replay reconstructs outcomes by compiling trusted checkout sources;
it never executes a submitted provider or trusts a submitted digest as authority.
"""
from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import tempfile
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "tests/fixtures/public-generic-settlement-v1"
NATIVE = ROOT / "tests/public_generic_native_adapter_v1"
CORPUS = "semaprax.public-generic-settlement-corpus.v1"
EVIDENCE = "semaprax.public-generic-settlement-evidence.v1"
LABELS = ["FrameValidated", "LeafAllocationStarted", "LeafAllocationCommitted",
          "LeafPayloadCopied", "InputValuePrepared", "InputTransferCommitted",
          "ExecutionStarted", "ExecutionFinished", "ResultLeafAllocationStarted",
          "ResultLeafAllocationCommitted", "ResultValuePrepared", "ResultCommit",
          "LeafRelease", "CarrierRelease"]
FIELDS = ["case_id", "accepted", "status", "live_alloc", "live_handles", "fixture_live",
          "fixture_peak", "overwrite", "trace", "result", "live_bytes", "peak_alloc",
          "peak_bytes", "peak_handles", "endpoint_invoked", "release_order", "secondary_cleanup"]


def canonical(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n").encode("ascii")


def digest(domain: str, data: bytes) -> str:
    return "sha256:" + hashlib.sha256(domain.encode("ascii") + b"\0" + struct.pack("<Q", len(data)) + data).hexdigest()


def require(condition: bool, reason: str) -> None:
    if not condition:
        raise ValueError(reason)


def read_bounded(path: Path, maximum: int) -> bytes:
    with path.open("rb") as stream:
        data = stream.read(maximum + 1)
    require(len(data) <= maximum, "input-bound")
    return data


def read_canonical(data: bytes, maximum: int) -> Any:
    require(len(data) <= maximum, "input-bound")
    value = json.loads(data)
    require(canonical(value) == data, "noncanonical-json")
    return value


def frame(data: bytes) -> bytes:
    return struct.pack("<Q", len(data)) + data


def case_leaves(case: dict[str, Any]) -> list[bytes]:
    leaves: list[bytes] = []
    total = 0
    require(type(case["input_leaves"]) is list and len(case["input_leaves"]) <= 257, "recipe-bound")
    for recipe in case["input_leaves"]:
        if set(recipe) == {"hex"}:
            text = recipe["hex"]
            require(type(text) is str and len(text) <= 131074 and len(text) % 2 == 0
                    and all(c in "0123456789abcdef" for c in text), "payload-hex")
            leaf, count = bytes.fromhex(text), 1
        else:
            require(set(recipe) == {"byte", "length", "count"}, "recipe-fields")
            require(all(type(recipe[k]) is int for k in recipe), "recipe-integer")
            require(0 <= recipe["byte"] <= 255 and 0 <= recipe["length"] <= 65537
                    and 1 <= recipe["count"] <= 257, "recipe-bound")
            leaf, count = bytes([recipe["byte"]]) * recipe["length"], recipe["count"]
        total += len(leaf) * count
        require(len(leaves) + count <= 257 and total <= 16 * 1024 * 1024 + 1, "payload-bound")
        leaves.extend([leaf] * count)
    return leaves


def input_carrier(case: dict[str, Any]) -> bytes:
    leaves = case_leaves(case)
    return struct.pack("<Q", len(leaves)) + b"".join(map(frame, leaves))


def load_manifest() -> tuple[dict[str, Any], bytes]:
    data = read_bounded(FIXTURE / "cases.json", 64 * 1024)
    manifest = read_canonical(data, 64 * 1024)
    require(set(manifest) == {"schema", "profile", "carrier_format", "normalized_result_format",
                              "applicable_engines", "cases"}, "manifest-fields")
    require(manifest["schema"] == CORPUS and manifest["profile"] == "flat-owned-bytes-reference-fixture.v1",
            "manifest-schema")
    require(manifest["carrier_format"] == "u64le-leaf-count-and-u64le-length-framed-bytes"
            and manifest["normalized_result_format"] == "u64le-length-framed-bytes-without-leaf-count"
            and manifest["applicable_engines"] == ["interpreter", "core-wasm-model", "native-c11-O0", "native-c11-O2"], "manifest-profile")
    cases = manifest["cases"]
    require(type(cases) is list and 0 < len(cases) <= 64, "case-count")
    seen = set()
    for case in cases:
        require(set(case) == {"case_id", "description", "input_leaves", "failure_injection_id",
            "compound_cleanup_injection", "expected_accepted", "expected_primary_status",
            "expected_endpoint_invoked", "input_carrier_digest", "expected_result_carrier_digest",
            "expected_final_live_allocations", "expected_final_live_handles", "expected_final_live_bytes"}, "case-fields")
        require(type(case["expected_accepted"]) is bool and type(case["expected_endpoint_invoked"]) is bool
                and type(case["expected_primary_status"]) is int and 0 <= case["expected_primary_status"] <= 13,
                "expectation-types")
        require(case["expected_accepted"] == (case["expected_primary_status"] == 0), "expectation-status")
        for field in ["expected_final_live_allocations", "expected_final_live_handles", "expected_final_live_bytes"]:
            require(type(case[field]) is int and case[field] == 0, "expectation-resources")
        name = case["case_id"]
        require(type(name) is str and 0 < len(name) <= 100 and name.isascii()
                and all(c.isalnum() or c == "_" for c in name) and name not in seen, "case-id")
        seen.add(name)
        for field in ["failure_injection_id", "compound_cleanup_injection"]:
            require(case[field] is None or case[field] in LABELS, "injection-id")
        require(case["input_carrier_digest"] == digest(CORPUS + "/input", input_carrier(case)), "input-digest")
        leaves = case_leaves(case)
        result = b"".join(frame(leaf[::-1]) for leaf in leaves)
        expected = digest(CORPUS + "/result", result) if case["expected_accepted"] else None
        require(case["expected_result_carrier_digest"] == expected, "result-digest")
    return manifest, data


def c_array(name: str, data: bytes, length_name: str | None = None) -> str:
    text = f"static const uint8_t {name}[] = {{" + ",".join(f"0x{b:02x}" for b in data) + "};\n"
    if length_name:
        text += f"static const size_t {length_name} = {len(data)};\n"
    return text


def render(cases: list[dict[str, Any]]) -> tuple[str, bytes, bytes]:
    # Exact preimages used by settlement_corpus.rs's NativeProviderBindingV1:
    # every field is u64le length-framed, not JSON or a host struct layout.
    descriptor = (FIXTURE / "descriptor.txt").read_bytes()
    carrier_binding = b"".join(frame(x.encode("ascii")) for x in [
        "semaprax.public-generic-carrier.v1", "sha256:settlement-corpus-native-descriptor-identity",
        "native-c11", "sha256:settlement-corpus-native-runtime-identity"])
    binding = b"".join(map(frame, [b"semaprax.public-generic-native-adapter.v1", carrier_binding,
        b"v1", b"sha256:settlement-corpus-native-provider-artifact-fixture",
        b"spx_pg_endpoint_reverse_bytes_v1", b"semaprax-0.4.1", b"unsupported-unpublished"]))
    parts = [(ROOT / "tests/support/native_fixture_stdio.c").read_text(),
             (NATIVE / "allocations.c").read_text(),
             (NATIVE / "settlement_corpus/observations.c").read_text(),
             (ROOT / "src/public_generic_abi/native/spx_pg_v1.h").read_text(),
             c_array("SPX_PG_TRUSTED_DESCRIPTOR_BYTES", descriptor, "SPX_PG_TRUSTED_DESCRIPTOR_LEN"),
             c_array("SPX_PG_TRUSTED_BINDING_BYTES", binding, "SPX_PG_TRUSTED_BINDING_LEN"),
             (ROOT / "src/public_generic_abi/native/provider_body.c").read_text(),
             (NATIVE / "settlement_corpus/probe.c").read_text(),
             (NATIVE / "settlement_corpus/failure_regressions.c").read_text()]
    for i, case in enumerate(cases):
        parts.append(c_array(f"CASE_{i}_CARRIER", input_carrier(case)))
    parts.append("int main(void) { REQUIRE(fixture_binary_stdout());\n")
    for i, case in enumerate(cases):
        injections = [LABELS.index(case[field]) if case[field] is not None else -1
                      for field in ["failure_injection_id", "compound_cleanup_injection"]]
        parts.append(f'run_one_case("{case["case_id"]}", CASE_{i}_CARRIER, sizeof(CASE_{i}_CARRIER), '
                     f'{injections[0]}, {injections[1]});\n')
    parts.append('check_failure_regressions(); puts("settlement-corpus-native-probe-done"); return 0; }\n')
    return "\n".join(parts), descriptor, binding


def unsigned(value: str) -> int:
    require(value.isascii() and value.isdecimal() and (value == "0" or not value.startswith("0")), "counter-encoding")
    require(len(value) <= 20, "counter-bound")
    result = int(value)
    require(result <= (1 << 64) - 1, "counter-bound")
    return result


def parse_line(line: str, case: dict[str, Any]) -> dict[str, Any]:
    require(line.startswith("CASE "), "evidence-prefix")
    fields = [field.split("=", 1) for field in line[5:].split(" ")]
    require(all(len(field) == 2 for field in fields) and [f[0] for f in fields] == FIELDS, "evidence-fields")
    values = dict(fields)
    require(values["case_id"] == case["case_id"], "case-id-order")
    result_hex = values.pop("result")
    trace_text = values.pop("trace")
    trace = [unsigned(n) for n in trace_text.split(",")] if trace_text else []
    require(len(trace) < 4096 and all(label <= 14 for label in trace), "trace-bound")
    release_text = values.pop("release_order")
    releases = [[unsigned(n) for n in entry.split(":")]
                for entry in release_text.split(",")] if release_text else []
    require(all(len(x) == 2 and x[0] <= 1 and x[1] < 256 for x in releases), "release-order")
    secondary_text = values.pop("secondary_cleanup")
    secondary = [unsigned(n) for n in secondary_text.split(",")] if secondary_text else []
    require(len(secondary) <= 16 and all(n == 11 for n in secondary), "cleanup-status")
    numbers = {key: unsigned(value) for key, value in values.items() if key != "case_id"}
    require(numbers["accepted"] in (0, 1) and numbers["endpoint_invoked"] in (0, 1), "boolean")
    require(numbers["accepted"] == case["expected_accepted"] and numbers["status"] == case["expected_primary_status"], "primary-status")
    require(numbers["endpoint_invoked"] == case["expected_endpoint_invoked"], "endpoint-invoked")
    require(all(numbers[key] == 0 for key in ["live_alloc", "live_handles", "live_bytes", "fixture_live"]), "live-resource")
    if result_hex == "-":
        require(not case["expected_accepted"], "missing-result")
        result_digest = None
    else:
        require(len(result_hex) <= 2 * (16 * 1024 * 1024 + 2056) and len(result_hex) % 2 == 0
                and all(c in "0123456789abcdef" for c in result_hex), "result-hex")
        raw = bytes.fromhex(result_hex)
        leaves = case_leaves(case)
        expected = struct.pack("<Q", len(leaves)) + b"".join(frame(leaf[::-1]) for leaf in leaves)
        require(case["expected_accepted"] and raw == expected, "result-carrier")
        result_digest = digest(CORPUS + "/result", raw[8:])
    require(result_digest == case["expected_result_carrier_digest"], "result-digest")
    return dict(numbers, case_id=case["case_id"], trace=trace, release_order=releases,
                secondary_cleanup=secondary, result_digest=result_digest)


def evidence_row(outcome: dict[str, Any], engine: str, artifact: str, descriptor: bytes, binding: bytes) -> dict[str, Any]:
    return {
        "case_id": outcome["case_id"], "engine_id": engine,
        "consumer_route": "native-c11-reference-probe",
        "provider_artifact_digest": artifact,
        "provider_binding_digest": digest(EVIDENCE + "/binding", binding),
        "descriptor_digest": digest(EVIDENCE + "/descriptor", descriptor),
        "accepted": bool(outcome["accepted"]), "endpoint_invoked": bool(outcome["endpoint_invoked"]),
        "primary_status": outcome["status"], "secondary_cleanup_statuses": outcome["secondary_cleanup"],
        "result_digest": outcome["result_digest"],
        "trace_digest": digest(EVIDENCE + "/trace", canonical(outcome["trace"])),
        "release_order_digest": digest(EVIDENCE + "/release-order", canonical(outcome["release_order"])),
        "final_live_resources": {"allocations": outcome["live_alloc"], "handles": outcome["live_handles"], "bytes": outcome["live_bytes"]},
        "target_local_peaks": {"allocations": outcome["peak_alloc"], "handles": outcome["peak_handles"], "bytes": outcome["peak_bytes"]},
        "settlement_overwrite_attempts": outcome["overwrite"],
    }


def seal(body: dict[str, Any]) -> bytes:
    return canonical(dict(body, summary_digest=digest(EVIDENCE + "/summary", canonical(body))))


def replay(submitted: bytes, trusted: bytes) -> None:
    # The trusted bytes come ONLY from fresh checked executions, never from
    # the submitted artifact or a caller-selected case/engine identity.
    value = read_canonical(submitted, 1024 * 1024)
    require(type(value) is dict and set(value) == {"schema", "profile", "manifest_digest",
            "provider_sources_digest", "expectations_digest", "rows", "summary_digest"}
            and value["schema"] == EVIDENCE and value["profile"] == "flat-owned-bytes-reference-fixture.v1",
            "evidence-schema")
    require(type(value["rows"]) is list and 0 < len(value["rows"]) <= 192, "evidence-row-bound")
    body = {key: item for key, item in value.items() if key != "summary_digest"}
    require(seal(body) == submitted, "summary-digest")
    require(submitted == trusted, "trusted-replay-mismatch")


def check_negative_controls(trusted: bytes) -> int:
    original = json.loads(trusted)
    corruptions: list[bytes] = [trusted[:-1], trusted[:-20], b" " + trusted,
                               trusted.replace(b'{', b'{"unknown":0,', 1)]
    for field in original["rows"][0]:
        changed = copy.deepcopy(original)
        current = changed["rows"][0][field]
        if type(current) is bool:
            altered = not current
        elif type(current) is int:
            altered = (current + 1) % 14
        elif type(current) is list:
            altered = [11] if current != [11] else []
        elif type(current) is dict:
            altered = dict(current, allocations=current["allocations"] + 1)
        elif type(current) is str and current.startswith("sha256:"):
            altered = "sha256:" + "f" * 64
        elif field == "case_id":
            altered = changed["rows"][1]["case_id"]
        elif field == "engine_id":
            altered = "native-c11-O2"
        else:
            altered = "forged"
        changed["rows"][0][field] = altered
        changed.pop("summary_digest")
        corruptions.append(seal(changed))  # attacker correctly remints public hash
    for transform in [lambda v: v["rows"].reverse(), lambda v: v["rows"][0].pop("primary_status"),
                      lambda v: v["rows"][0].update(unknown=0), lambda v: v["rows"].pop(),
                      lambda v: v.update(schema="unknown")]:
        changed = copy.deepcopy(original)
        transform(changed)
        changed.pop("summary_digest")
        corruptions.append(seal(changed))
    for bad in corruptions:
        try:
            replay(bad, trusted)
        except (ValueError, TypeError, KeyError):
            continue
        raise ValueError("negative-control-accepted")
    return len(corruptions)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, help="write payload-free canonical evidence here")
    parser.add_argument("--replay", type=Path, help="reconstruct and verify this evidence.json")
    parser.add_argument("--sanitizers", action="store_true", help="also require ASan + UBSan at -O1")
    parser.add_argument("--cc", default=os.environ.get("CLANG", "clang"))
    args = parser.parse_args()
    submitted = None
    if args.replay:
        submitted = read_bounded(args.replay, 1024 * 1024)
        # Canonical framing and integrity are checked before compilation.
        replay(submitted, submitted)
    compiler = shutil.which(args.cc)
    require(compiler is not None, "compiler-unavailable")
    manifest, manifest_bytes = load_manifest()
    cases = manifest["cases"]
    expectation_bytes = read_bounded(FIXTURE / "native-expectations.json", 64 * 1024)
    expectations = read_canonical(expectation_bytes, 64 * 1024)
    require(set(expectations) == {"schema", "manifest_digest", "cases"}
            and expectations["schema"] == "semaprax.public-generic-native-settlement-expectations.v1"
            and expectations["manifest_digest"] == digest(EVIDENCE + "/manifest", manifest_bytes),
            "native-expectation-binding")
    require([case["case_id"] for case in expectations["cases"]] == [case["case_id"] for case in cases],
            "native-expectation-inventory")
    expectation_keys = {"case_id", "trace", "release_order", "peak_alloc", "peak_handles",
                        "secondary_cleanup", "overwrite", "endpoint_invoked"}
    require(all(set(case) == expectation_keys for case in expectations["cases"]), "native-expectation-fields")
    source, descriptor, binding = render(cases)
    engines = [("native-c11-O0", ["-O0"]), ("native-c11-O2", ["-O2"])]
    if args.sanitizers:
        engines.append(("native-c11-asan-ubsan", ["-O1", "-fsanitize=address,undefined", "-fno-omit-frame-pointer"]))
    rows, outcomes = [], []
    with tempfile.TemporaryDirectory(prefix="spx-settlement-") as temp:
        work = Path(temp)
        (work / "settlement_corpus_probe.c").write_text(source, encoding="utf-8")
        for engine, flags in engines:
            binary = work / (engine + (".exe" if os.name == "nt" else ""))
            command = [compiler, "-std=c11", "-Wall", "-Wextra", "-Werror", *flags,
                       "settlement_corpus_probe.c", "-o", binary.name]
            compiled = subprocess.run(command, cwd=work, capture_output=True, text=True, timeout=120)
            require(compiled.returncode == 0, "compile-failed: " + compiled.stderr)
            env = dict(os.environ, ASAN_OPTIONS="detect_leaks=1:halt_on_error=1", UBSAN_OPTIONS="halt_on_error=1")
            run = subprocess.run([str(binary)], cwd=work, capture_output=True, text=True, env=env, timeout=120)
            require(run.returncode == 0 and not run.stderr, "probe-failed: " + run.stderr)
            lines = run.stdout.splitlines()
            require(len(lines) == len(cases) + 1 and lines[-1] == "settlement-corpus-native-probe-done", "case-inventory")
            measured = [parse_line(line, case) for line, case in zip(lines[:-1], cases)]
            for actual, expected in zip(measured, expectations["cases"]):
                require({key: actual[key] for key in expectation_keys} == expected,
                        "native-pinned-expectation-mismatch: " + actual["case_id"])
            if outcomes:
                require(measured == outcomes[0], "native-optimization-disagreement")
            outcomes.append(measured)
            artifact = digest(EVIDENCE + "/provider-artifact", binary.read_bytes())
            rows.extend(evidence_row(item, engine, artifact, descriptor, binding) for item in measured)
            print(f"PASS {engine}: {len(cases)} shared cases, compound/rollback regressions, zero resources")
    body = {"schema": EVIDENCE, "profile": manifest["profile"],
            "manifest_digest": digest(EVIDENCE + "/manifest", manifest_bytes),
            "provider_sources_digest": digest(EVIDENCE + "/sources", source.encode("utf-8")),
            "expectations_digest": digest(EVIDENCE + "/expectations", expectation_bytes), "rows": rows}
    trusted = seal(body)
    replay(trusted, trusted)
    print(f"PASS evidence replay: {check_negative_controls(trusted)} reminted/structural negative controls")
    if args.replay:
        require(submitted is not None, "missing-replay")
        replay(submitted, trusted)
        print("PASS independent replay against fresh trusted execution")
    if args.output:
        args.output.mkdir(parents=True, exist_ok=True)
        (args.output / "evidence.json").write_bytes(trusted)
        print(f"Wrote {args.output / 'evidence.json'}")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (ValueError, KeyError, TypeError, OSError, subprocess.SubprocessError) as error:
        print(f"FAIL {error}", file=sys.stderr)
        sys.exit(1)
