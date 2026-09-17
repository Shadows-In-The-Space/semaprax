#!/usr/bin/env python3
"""Native single-owner admission regressions, not concurrent-runtime support.

Reuses the existing settlement fixture, framing, canonical JSON and digest
helpers. The only spawned threads live in the C test driver. Independent replay
compiles trusted checkout source and never executes submitted artifacts.
"""
from __future__ import annotations

import argparse
import copy
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
from typing import Any

from public_generic_settlement_evidence import (
    ROOT, NATIVE, FIXTURE, canonical, c_array, digest, read_bounded,
    read_canonical, render, require, unsigned,
)

SCHEMA = "semaprax.public-generic-native-thread-admission-corpus.v1"
EVIDENCE = "semaprax.public-generic-native-thread-admission-evidence.v1"
PROFILE = "native-reference-single-owner-no-cancellation"
LIMIT = 256 * 1024
FIELDS = ["case", "checks", "refusals", "endpoints", "winners", "losers",
          "peak_alloc", "live", "bytes", "fixture_live", "owner_released"]
ENGINES = {"native-c11-O0", "native-c11-O2", "native-c11-asan-ubsan", "native-c11-tsan"}
CASE_IDS = ["foreign-input", "foreign-result", "foreign-fault-arm", "foreign-fault-clear",
            "reentry-open", "reentry-prepare", "reentry-call", "reentry-export",
            "reentry-input-release", "reentry-result-release", "reentry-close",
            "reentry-cleanup-failure", "paused-open", "paused-prepare", "paused-call",
            "paused-export", "paused-release", "paused-close", "refusal-stress",
            "contended-first-open", "contended-epochs", "overlapping-owner-handoff", "owner-handoff",
            "last-provider-close", "failed-open-unpins", "thread-identity-bound"]


def manifest() -> tuple[dict[str, Any], bytes]:
    data = read_bounded(FIXTURE / "native-thread-admission-cases.json", LIMIT)
    value = read_canonical(data, LIMIT)
    require(set(value) == {"schema", "profile", "cases"} and value["schema"] == SCHEMA
            and value["profile"] == PROFILE, "thread-manifest-schema")
    require(type(value["cases"]) is list
            and [row["case_id"] for row in value["cases"]] == CASE_IDS, "thread-case-inventory")
    for row in value["cases"]:
        require(set(row) == {"case_id", "expected"}, "thread-case-fields")
        require(set(row["expected"]) == set(FIELDS[1:]), "thread-expectation-fields")
        require(all(type(n) is int and 0 <= n <= 20000 for n in row["expected"].values()),
                "thread-expectation-integer")
        require(row["expected"]["checks"] == 1 and row["expected"]["owner_released"] == 1
                and all(row["expected"][k] == 0 for k in ["live", "bytes", "fixture_live"]),
                "thread-terminal-resources")
    return value, data


def render_provider() -> tuple[str, bytes, bytes]:
    # Same trusted fixture constants as the existing Cargo settlement corpus.
    # Compose exactly native/template.rs; --generated-provider verifies the
    # byte identity against that real Rust renderer when Cargo is available.
    _, descriptor, binding = render([])
    native = ROOT / "src/public_generic_abi/native"
    source = (native / "spx_pg_v1.h").read_text() + "\n"
    source += ("/* Trusted constants substituted by src/public_generic_abi/native/template.rs from a\n"
               "* real VerifiedPublicGenericDescriptor and NativeProviderBindingV1. Never hand-edited. */\n")
    source += c_array("SPX_PG_TRUSTED_DESCRIPTOR_BYTES", descriptor, "SPX_PG_TRUSTED_DESCRIPTOR_LEN")
    source += c_array("SPX_PG_TRUSTED_BINDING_BYTES", binding, "SPX_PG_TRUSTED_BINDING_LEN")
    source += "\n" + (native / "provider_body.c").read_text()
    return source, descriptor, binding


def assemble(provider: str) -> str:
    files = NATIVE / "thread_admission"
    return "\n".join([(ROOT / "tests/support/native_fixture_stdio.c").read_text(),
        (NATIVE / "allocations.c").read_text(), (files / "hooks.c").read_text(), provider,
        (files / "probe.c").read_text(), (files / "contention.c").read_text(),
        "int main(int argc, char **argv) { REQUIRE(fixture_binary_stdout()); "
        "return argc == 2 ? run_admission_case(argv[1]) : 2; }\n"])


def parse_receipt(text: str, expected: dict[str, Any]) -> dict[str, Any]:
    require(text.endswith("\n") and text.count("\n") == 1 and text.startswith("THREAD "),
            "thread-receipt-framing")
    parts = [item.split("=", 1) for item in text[7:-1].split(" ")]
    require(all(len(pair) == 2 for pair in parts) and [p[0] for p in parts] == FIELDS,
            "thread-receipt-fields")
    row = dict(parts)
    require(row.pop("case") == expected["case_id"], "thread-receipt-case")
    numbers = {k: unsigned(v) for k, v in row.items()}
    require(numbers == expected["expected"], "thread-observation-mismatch:" + expected["case_id"])
    return {"case_id": expected["case_id"], **numbers}


def seal(body: dict[str, Any]) -> bytes:
    return canonical(dict(body, evidence_digest=digest(EVIDENCE, canonical(body))))


def validate(data: bytes) -> dict[str, Any]:
    value = read_canonical(data, LIMIT)
    require(type(value) is dict and set(value) == {"schema", "profile", "manifest_digest",
            "sources_digest", "descriptor_digest", "binding_digest", "rows", "evidence_digest"},
            "thread-evidence-fields")
    require(value["schema"] == EVIDENCE and value["profile"] == PROFILE, "thread-evidence-schema")
    for key in ["manifest_digest", "sources_digest", "descriptor_digest", "binding_digest", "evidence_digest"]:
        require(type(value[key]) is str and re.fullmatch(r"sha256:[0-9a-f]{64}", value[key]) is not None,
                "thread-digest-encoding")
    rows = value["rows"]
    require(type(rows) is list and 0 < len(rows) <= len(CASE_IDS) * len(ENGINES), "thread-row-bound")
    require(len(rows) % len(CASE_IDS) == 0, "thread-row-count")
    seen = set()
    for index, row in enumerate(rows):
        require(type(row) is dict and set(row) == set(FIELDS[1:]) | {
            "case_id", "engine_id", "provider_artifact_digest"}, "thread-row-fields")
        require(type(row["engine_id"]) is str and row["engine_id"] in ENGINES, "thread-engine")
        require(row["case_id"] == CASE_IDS[index % len(CASE_IDS)], "thread-case-order")
        if index % len(CASE_IDS) == 0:
            require(row["engine_id"] not in seen, "thread-duplicate-engine")
            seen.add(row["engine_id"])
        else:
            require(row["engine_id"] == rows[index - 1]["engine_id"], "thread-engine-order")
        require(type(row["provider_artifact_digest"]) is str and re.fullmatch(
            r"sha256:[0-9a-f]{64}", row["provider_artifact_digest"]) is not None, "thread-provider-digest")
        require(all(type(row[k]) is int and 0 <= row[k] <= 20000 for k in FIELDS[1:]),
                "thread-counter")
    body = dict(value)
    submitted_digest = body.pop("evidence_digest")
    require(digest(EVIDENCE, canonical(body)) == submitted_digest, "thread-evidence-integrity")
    return value


def replay(submitted: bytes, trusted: bytes) -> None:
    validate(submitted)
    validate(trusted)
    require(submitted == trusted, "thread-trusted-replay-mismatch")


def negative_controls(trusted: bytes, expected: dict[str, Any], receipt: str) -> int:
    body = dict(validate(trusted)); body.pop("evidence_digest")
    bad = [trusted[:-1], trusted + b"\n", b" " + trusted, trusted + b"{}", b"x" * (LIMIT + 1)]
    for key in ["schema", "profile", "manifest_digest", "sources_digest", "descriptor_digest", "binding_digest"]:
        altered = copy.deepcopy(body)
        altered[key] = "changed" if key in ["schema", "profile"] else "sha256:" + "f" * 64
        bad.append(seal(altered))
    for key in body:
        altered = copy.deepcopy(body); del altered[key]; bad.append(seal(altered))
    for key in ["case_id", "engine_id", "provider_artifact_digest", *FIELDS[1:]]:
        altered = copy.deepcopy(body)
        altered["rows"][0][key] = ("changed" if key.endswith("id") else
            "sha256:" + "f" * 64 if key.endswith("digest") else altered["rows"][0][key] + 1)
        bad.append(seal(altered))
    for key in body["rows"][0]:
        altered = copy.deepcopy(body); del altered["rows"][0][key]; bad.append(seal(altered))
    for change in ["truncate", "reorder", "extra", "bool", "unknown", "duplicate-key"]:
        altered = copy.deepcopy(body)
        if change == "truncate": altered["rows"].pop()
        elif change == "reorder": altered["rows"][0], altered["rows"][1] = altered["rows"][1], altered["rows"][0]
        elif change == "extra": altered["rows"].append(altered["rows"][0])
        elif change == "bool": altered["rows"][0]["checks"] = True
        elif change == "unknown": altered["rows"][0]["unknown"] = 0
        else:
            bad.append(trusted.replace(b'{"binding_digest":', b'{"checks":0,"checks":1,"binding_digest":', 1))
            continue
        bad.append(seal(altered))
    for data in bad:
        try:
            replay(data, trusted)
        except (ValueError, KeyError, TypeError):
            continue
        raise ValueError("thread-negative-evidence-accepted")
    bad_receipts = [receipt[:-1], receipt + "\n", receipt.replace(" checks=1", " checks=01"),
        receipt.replace(" live=0", " live=1"), receipt.replace(" live=0", " live=true"),
        receipt.replace(" live=0", " live=18446744073709551616"),
        receipt.replace(" live=0 bytes=0", " bytes=0 live=0"),
        receipt.replace(" checks=1", " checks=1 unknown=0"),
        receipt.replace(" checks=1", " checks=1 checks=1"),
        receipt.replace(" case=", " case=changed"), receipt.replace("\n", "\r\n")]
    for text in bad_receipts:
        try:
            parse_receipt(text, expected)
        except (ValueError, KeyError, TypeError):
            continue
        raise ValueError("thread-negative-receipt-accepted")
    return len(bad) + len(bad_receipts)


def compile_probe(work: Path, compiler: str, flags: list[str], source: str) -> Path:
    (work / "thread_probe.c").write_text(source, encoding="utf-8")
    binary = work / "thread_probe"
    command = [compiler, "-std=c11", "-Wall", "-Wextra", "-Werror", "-pthread", *flags,
               "thread_probe.c", "-o", binary.name]
    built = subprocess.run(command, cwd=work, capture_output=True, text=True, timeout=120)
    require(built.returncode == 0, "thread-compile-failed:" + built.stderr)
    return binary


def execute(binary: Path, case_id: str) -> subprocess.CompletedProcess[str]:
    environment = dict(os.environ, ASAN_OPTIONS="detect_leaks=1:halt_on_error=1",
        UBSAN_OPTIONS="halt_on_error=1:print_stacktrace=1", TSAN_OPTIONS="halt_on_error=1")
    return subprocess.run([str(binary), case_id], cwd=binary.parent, env=environment,
        capture_output=True, text=True, timeout=120)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cc", default=os.environ.get("CLANG", "clang"))
    parser.add_argument("--sanitizers", action="store_true")
    parser.add_argument("--thread-sanitizer", action="store_true",
                        help="also require a provisioned, working TSan runtime; never silently skip")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--replay", type=Path)
    parser.add_argument("--generated-provider", type=Path,
                        help="compare and execute the actual Rust renderer's output")
    args = parser.parse_args()
    require(os.name == "posix", "thread-gate-requires-posix-host")
    submitted = read_bounded(args.replay, LIMIT) if args.replay else None
    if submitted is not None: validate(submitted)
    cases, raw_manifest = manifest()
    provider, descriptor, binding = render_provider()
    if args.generated_provider:
        actual = read_bounded(args.generated_provider, LIMIT).decode("utf-8")
        require(actual == provider, "thread-actual-generator-byte-mismatch")
        provider = actual
    source = assemble(provider)
    compiler = shutil.which(args.cc)
    require(compiler is not None, "thread-compiler-unavailable")
    engines = [("native-c11-O0", ["-O0"]), ("native-c11-O2", ["-O2"])]
    if args.sanitizers:
        engines.append(("native-c11-asan-ubsan", ["-O1", "-fsanitize=address,undefined",
                        "-fno-sanitize-recover=all", "-fno-omit-frame-pointer"]))
    if args.thread_sanitizer:
        engines.append(("native-c11-tsan", ["-O1", "-fsanitize=thread", "-fno-omit-frame-pointer"]))
    rows: list[dict[str, Any]] = []
    receipt = ""
    with tempfile.TemporaryDirectory(prefix="spx-thread-admission-") as temp:
        work = Path(temp)
        for engine, flags in engines:
            binary = compile_probe(work, compiler, flags, source)
            artifact = digest(EVIDENCE + "/provider-artifact", binary.read_bytes())
            for case in cases["cases"]:
                result = execute(binary, case["case_id"])
                require(result.returncode == 0 and not result.stderr,
                        "thread-probe-failed:" + case["case_id"] + ":" + result.stderr)
                measured = parse_receipt(result.stdout, case)
                rows.append(dict(measured, engine_id=engine, provider_artifact_digest=artifact))
                if case["case_id"] == CASE_IDS[0]: receipt = result.stdout
            print(f"PASS {engine}: {len(cases['cases'])} admission/settlement cases; zero live resources", flush=True)
    trusted = seal({"schema": EVIDENCE, "profile": PROFILE,
        "manifest_digest": digest(EVIDENCE + "/manifest", raw_manifest),
        "sources_digest": digest(EVIDENCE + "/sources", source.encode("utf-8")),
        "descriptor_digest": digest(EVIDENCE + "/descriptor", descriptor),
        "binding_digest": digest(EVIDENCE + "/binding", binding), "rows": rows})
    replay(trusted, trusted)
    count = negative_controls(trusted, cases["cases"][0], receipt)
    print(f"PASS {count} reminted/structural/wire negative controls", flush=True)
    if submitted is not None:
        replay(submitted, trusted)
        print("PASS independent replay against freshly compiled trusted source", flush=True)
    if args.output:
        args.output.mkdir(parents=True, exist_ok=True)
        (args.output / "native-thread-admission-evidence.json").write_bytes(trusted)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (ValueError, KeyError, TypeError, OSError, RecursionError, subprocess.SubprocessError) as error:
        print(f"FAIL {error}", file=sys.stderr)
        sys.exit(1)
