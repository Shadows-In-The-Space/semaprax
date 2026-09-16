"""Native physical result/release evidence for the existing settlement gate.

This is a companion, not a new provider or an interpreter/Wasm engine. The
legacy logical labels remain frozen. Every new phase receipt comes from actual
allocation, exact copy, commit eligibility, export preflight or physical free.
"""
from __future__ import annotations

import copy
import json
from functools import lru_cache
from typing import Any

import public_generic_settlement_evidence as core

CORPUS = "semaprax.public-generic-native-result-phase-corpus.v1"
EVIDENCE = "semaprax.public-generic-native-result-phase-evidence.v1"
FIELDS = ["case_id", "status", "result_verified", "release_status", "retries", "endpoints", "copies_checked",
          "peak_alloc", "peak_handles", "peak_bytes", "live_alloc", "live_handles", "live_bytes",
          "secondary", "releases", "events"]
ROW_LIMIT = 128
BYTE_LIMIT = 1024 * 1024


def parse_line(line: str) -> dict[str, Any]:
    core.require(len(line) <= 256 * 1024 and line.startswith("PHASE "), "phase-wire-bound")
    pairs = [item.split("=", 1) for item in line[6:].split(" ")]
    core.require(all(len(item) == 2 for item in pairs) and [p[0] for p in pairs] == FIELDS,
                 "phase-wire-fields")
    values = dict(pairs)
    name = values.pop("case_id")
    core.require(0 < len(name) <= 100 and name.isascii()
                 and all(c.isalnum() or c in "_-" for c in name), "phase-case-id")
    arrays: dict[str, Any] = {}
    for key, width, limit in [("secondary", 1, 16), ("releases", 2, 512), ("events", 6, 4096)]:
        text = values.pop(key)
        rows = [[core.unsigned(n) for n in row.split(":")] for row in text.split(",")] if text else []
        core.require(len(rows) <= limit and all(len(row) == width for row in rows), "phase-array-bound")
        arrays[key] = [row[0] for row in rows] if width == 1 else rows
    core.require(all(n == 11 for n in arrays["secondary"]), "phase-secondary-status")
    core.require(all(d <= 1 and i < 256 for d, i in arrays["releases"]), "phase-release-index")
    for phase, direction, leaf, allocations, handles, injected in arrays["events"]:
        core.require(phase <= 7 and direction <= 1 and (leaf < 256 or leaf == 4294967295)
                     and allocations <= 1024 and handles <= 256 and injected <= 1, "phase-event-domain")
        core.require((leaf == 4294967295) == (phase in (3, 4, 5)), "phase-root-index")
        core.require(direction == 1 or phase == 7, "phase-direction")
    numbers = {key: core.unsigned(value) for key, value in values.items()}
    core.require(numbers["status"] in (0, 10, 11) and numbers["release_status"] in (0, 11), "phase-status")
    core.require(all(numbers[key] in (0, 1) for key in ["result_verified", "retries", "endpoints"]),
                 "phase-boolean")
    core.require(numbers["copies_checked"] <= 256 and numbers["peak_alloc"] <= 1024 and numbers["peak_handles"] <= 256
                 and numbers["peak_bytes"] <= 34 * 1024 * 1024, "phase-peak-bound")
    core.require(all(numbers[key] == 0 for key in ["live_alloc", "live_handles", "live_bytes"]),
                 "phase-live-resource")
    return dict(case_id=name, **numbers, **arrays)


def parse_receipts(text: str) -> list[dict[str, Any]]:
    core.require(text.endswith("\n") and "\r" not in text and len(text) <= BYTE_LIMIT, "phase-wire-framing")
    lines = text[:-1].split("\n")
    core.require(0 < len(lines) <= ROW_LIMIT, "phase-case-count")
    rows = [parse_line(line) for line in lines]
    core.require(len({row["case_id"] for row in rows}) == len(rows), "phase-duplicate-case")
    return rows


def load_manifest(manifest_bytes: bytes) -> dict[str, Any]:
    value = core.read_canonical(manifest_bytes, BYTE_LIMIT)
    core.require(set(value) == {"schema", "profile", "shared_manifest_digest", "cases"}
                 and value["schema"] == CORPUS and value["profile"] == "flat-owned-bytes-reference-fixture.v1",
                 "phase-manifest-schema")
    _, shared_bytes = core.load_manifest()
    core.require(value["shared_manifest_digest"] == core.digest(CORPUS + "/shared-manifest", shared_bytes),
                 "phase-shared-manifest-binding")
    cases = value["cases"]
    core.require(type(cases) is list and len(cases) == 72, "phase-manifest-count")
    fields = set(FIELDS) - {"peak_bytes"}
    for row in cases:
        core.require(type(row) is dict and set(row) == fields, "phase-manifest-fields")
        # Reuse the strict wire decoder as the typed expectation validator.
        values = dict(row, peak_bytes=0)
        words = []
        for key in FIELDS:
            item = values[key]
            if key in ("events", "releases"):
                item = ",".join(":".join(str(n) for n in entry) for entry in item)
            elif key == "secondary":
                item = ",".join(str(n) for n in item)
            words.append(f"{key}={item}")
        core.require(parse_line("PHASE " + " ".join(words)) == values, "phase-manifest-types")
    core.require(len({case["case_id"] for case in cases}) == len(cases), "phase-manifest-duplicate")
    return value


def verify_receipts(text: str, manifest: dict[str, Any]) -> list[dict[str, Any]]:
    rows = parse_receipts(text)
    core.require([row["case_id"] for row in rows] == [row["case_id"] for row in manifest["cases"]],
                 "phase-case-inventory")
    for row, expected in zip(rows, manifest["cases"]):
        comparable = {key: value for key, value in row.items() if key != "peak_bytes"}
        core.require(comparable == expected, "phase-pinned-expectation-mismatch: " + row["case_id"])
    return rows


def result_digest(row: dict[str, Any]) -> str | None:
    # The C probe compares EVERY exported byte against its independent recipe
    # before result_verified=1. Hash that proven-equal canonical value. This is
    # not the source of the native test's expected bytes and never ignores an
    # exported byte merely because a provider returned status OK.
    if not row["result_verified"]:
        return None
    name = row["case_id"]
    return _recipe_digest(name if name in ("max_success", "zero_success") else "ordinary")


@lru_cache(maxsize=3)
def _recipe_digest(shape: str) -> str:
    if shape == "max_success":
        leaves = [bytes((offset * 17 + leaf) & 255 for offset in range(256)) * 256 for leaf in range(256)]
    else:
        leaves = [b"" if shape == "zero_success" else b"AB", b"C\0D"]
    return core.digest(core.CORPUS + "/result", b"".join(core.frame(leaf[::-1]) for leaf in leaves))


def evidence_rows(rows: list[dict[str, Any]], engine: str, artifact: str,
                  descriptor: bytes, binding: bytes) -> list[dict[str, Any]]:
    output = []
    for row in rows:
        output.append({
            "case_id": row["case_id"], "engine_id": engine,
            "consumer_route": "native-c11-physical-result-phase-probe",
            "provider_artifact_digest": artifact,
            "descriptor_digest": core.digest(core.EVIDENCE + "/descriptor", descriptor),
            "provider_binding_digest": core.digest(core.EVIDENCE + "/binding", binding),
            "accepted": row["status"] == 0, "primary_status": row["status"],
            "endpoint_invoked": bool(row["endpoints"]),
            "exact_result_leaf_copies_checked": row["copies_checked"],
            "verified_result_carrier_digest": result_digest(row),
            "release_operation_status": row["release_status"],
            "secondary_cleanup_statuses": row["secondary"],
            "export_retry_count": row["retries"],
            "physical_phase_trace_digest": core.digest(EVIDENCE + "/phases", core.canonical(row["events"])),
            "release_order_digest": core.digest(EVIDENCE + "/release-order", core.canonical(row["releases"])),
            "peak_allocations": row["peak_alloc"], "peak_handles": row["peak_handles"],
            "peak_requested_bytes": row["peak_bytes"],
            "final_live_allocations": row["live_alloc"], "final_live_handles": row["live_handles"],
            "final_live_bytes": row["live_bytes"],
        })
    return output


def seal(body: dict[str, Any]) -> bytes:
    return core.canonical(dict(body, summary_digest=core.digest(EVIDENCE + "/summary", core.canonical(body))))


def replay(submitted: bytes, trusted: bytes) -> None:
    value = core.read_canonical(submitted, BYTE_LIMIT)
    core.require(type(value) is dict and set(value) == {"schema", "manifest_digest", "settlement_evidence_digest",
                                                       "rows", "summary_digest"}
                 and value["schema"] == EVIDENCE, "phase-evidence-schema")
    core.require(type(value["rows"]) is list and 0 < len(value["rows"]) <= ROW_LIMIT * 3, "phase-evidence-bound")
    fields = {"case_id", "engine_id", "consumer_route", "provider_artifact_digest", "descriptor_digest",
              "provider_binding_digest", "accepted", "primary_status", "endpoint_invoked",
              "exact_result_leaf_copies_checked", "verified_result_carrier_digest", "release_operation_status",
              "secondary_cleanup_statuses", "export_retry_count", "physical_phase_trace_digest",
              "release_order_digest", "peak_allocations", "peak_handles", "peak_requested_bytes",
              "final_live_allocations", "final_live_handles", "final_live_bytes"}
    seen = set()
    for row in value["rows"]:
        core.require(type(row) is dict and set(row) == fields, "phase-evidence-row-fields")
        core.require(row["engine_id"] in ("native-c11-O0", "native-c11-O2", "native-c11-asan-ubsan")
                     and row["consumer_route"] == "native-c11-physical-result-phase-probe", "phase-evidence-route")
        core.require(type(row["case_id"]) is str and 0 < len(row["case_id"]) <= 100
                     and row["case_id"].isascii()
                     and all(c.isalnum() or c in "_-" for c in row["case_id"]), "phase-evidence-case")
        pair = (row["engine_id"], row["case_id"])
        core.require(pair not in seen, "phase-evidence-duplicate")
        seen.add(pair)
        for key in fields:
            item = row[key]
            if key.endswith("digest"):
                if key == "verified_result_carrier_digest" and item is None:
                    continue
                core.require(type(item) is str and len(item) == 71 and item.startswith("sha256:")
                             and all(c in "0123456789abcdef" for c in item[7:]), "phase-evidence-digest")
        core.require(type(row["accepted"]) is bool and type(row["endpoint_invoked"]) is bool,
                     "phase-evidence-boolean")
        limits = {"primary_status": (0, 10, 11), "release_operation_status": (0, 11), "export_retry_count": (0, 1)}
        for key, allowed in limits.items():
            core.require(type(row[key]) is int and row[key] in allowed, "phase-evidence-status")
        core.require(row["accepted"] == (row["primary_status"] == 0), "phase-evidence-acceptance")
        for key, maximum in [("exact_result_leaf_copies_checked", 256), ("peak_allocations", 1024),
                             ("peak_handles", 256), ("peak_requested_bytes", 34 * 1024 * 1024),
                             ("final_live_allocations", 0), ("final_live_handles", 0), ("final_live_bytes", 0)]:
            core.require(type(row[key]) is int and 0 <= row[key] <= maximum, "phase-evidence-counter")
        core.require(type(row["secondary_cleanup_statuses"]) is list and len(row["secondary_cleanup_statuses"]) <= 16
                     and all(type(status) is int and status == 11 for status in row["secondary_cleanup_statuses"]),
                     "phase-evidence-secondary")
    body = {key: item for key, item in value.items() if key != "summary_digest"}
    core.require(seal(body) == submitted, "phase-summary-digest")
    core.require(submitted == trusted, "phase-trusted-replay-mismatch")


def negative_controls(trusted: bytes, receipt: str, manifest: dict[str, Any]) -> int:
    original = json.loads(trusted)
    bad = [trusted[:-1], trusted[:-25], b" " + trusted, trusted + b"{}",
           trusted.replace(b'{', b'{"unknown":0,', 1), b" " * (BYTE_LIMIT + 1)]
    for field in original["rows"][0]:
        value = copy.deepcopy(original)
        item = value["rows"][0][field]
        value["rows"][0][field] = not item if type(item) is bool else item + 1 if type(item) is int else "forged"
        value.pop("summary_digest")
        bad.append(seal(value))
    for transform in [lambda v: v["rows"].reverse(), lambda v: v["rows"].pop(),
                      lambda v: v["rows"][0].pop("physical_phase_trace_digest"),
                      lambda v: v["rows"][0].update(unknown=0),
                      lambda v: v.update(manifest_digest="sha256:" + "a" * 64),
                      lambda v: v.update(settlement_evidence_digest="sha256:" + "b" * 64),
                      lambda v: v["rows"].append(v["rows"][0]),
                      lambda v: v.update(rows=[v["rows"][0]] * (ROW_LIMIT * 3 + 1))]:
        value = copy.deepcopy(original)
        transform(value)
        value.pop("summary_digest")
        bad.append(seal(value))
    for item in bad:
        try:
            replay(item, trusted)
        except (ValueError, KeyError, TypeError):
            continue
        raise ValueError("phase-negative-control-accepted")
    first, *rest = receipt.splitlines(keepends=True)
    bad_wire = [receipt[:-1], receipt + first, first + receipt, "".join(reversed(receipt.splitlines(keepends=True))),
                receipt.replace(" status=", " missing=", 1), receipt.replace(" live_alloc=0", " live_alloc=1", 1),
                receipt.replace(" live_bytes=0", " live_bytes=00", 1),
                receipt.replace(" endpoints=1", " endpoints=true", 1),
                receipt.replace(" events=", " events=99:1:0:8:0:0,", 1),
                receipt.replace(" releases=", " releases=1:256,", 1),
                first.rstrip() + " \n" + "".join(rest),
                receipt.replace("\n", "\r\n", 1),
                receipt.replace(" peak_handles=1", " peak_handles=257", 1),
                receipt.replace(" live_bytes=0", " live_bytes=18446744073709551616", 1),
                receipt.replace(" retries=0", " retries=1", 1),
                receipt.replace(" result_verified=1", " result_verified=0", 1)]
    first_rows = parse_receipts(receipt)
    # Exercise each newly bounded wire field without relying on a downstream
    # semantic mismatch to notice the malformed scalar or phase coordinate.
    for key, replacement in [
        ("status", "12"), ("release_status", "12"), ("copies_checked", "257"),
        ("peak_alloc", "1025"), ("peak_bytes", str(34 * 1024 * 1024 + 1)),
        ("secondary", ",".join(["11"] * 17)), ("secondary", "10"),
        ("events", "0:0:0:1:0:0"), ("events", "3:1:0:1:0:0"),
        ("events", "0:1:0:1:0:2"), ("events", ",".join(["0:1:0:1:0:0"] * 4097)),
        ("releases", ",".join(["0:0"] * 513))]:
        words = first.rstrip("\n").split(" ")
        words = [key + "=" + replacement if word.startswith(key + "=") else word for word in words]
        bad_wire.append(" ".join(words) + "\n" + "".join(rest))
    core.require(len(first_rows) == 72, "phase-negative-control-inventory")
    bad_wire.extend([first * (ROW_LIMIT + 1), " " * (BYTE_LIMIT + 1) + "\n"])
    for item in bad_wire:
        core.require(item != receipt, "dead-phase-negative-control")
        try:
            verify_receipts(item, manifest)
        except (ValueError, KeyError, TypeError):
            continue
        raise ValueError("phase-wire-negative-control-accepted")
    return len(bad) + len(bad_wire)
