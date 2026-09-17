"""Closed evidence contract for the private C11-to-Core-Wasm reference route.

Reuse the existing corpus/oracles. Do not reinterpret a native binding as a
new public Wasm profile; this route is explicitly a compiled reference fixture.
"""
from __future__ import annotations

import copy
import json
from functools import lru_cache
from typing import Any

import public_generic_settlement_evidence as core
import public_generic_settlement_phases as phases

SCHEMA = "semaprax.public-generic-compiled-reference-evidence.v1"
CORPUS = "semaprax.public-generic-compiled-reference-corpus.v1"
PROFILE = "compiled-c11-reference-in-core-wasm-not-compiler-generic-v1"
LIMIT = 8 * 1024 * 1024
OBS_KEYS = {"endpoint_invoked", "peak_alloc", "peak_bytes", "peak_handles", "live_alloc",
            "live_bytes", "live_handles", "allocator_live", "allocator_bytes", "release_order",
            "secondary_cleanup", "trace", "overwrite"}
IN_RELEASE = [[0, 1], [0, 0]]
FULL_RELEASE = IN_RELEASE + [[1, 1], [1, 0]]
PARTIAL_RELEASE = [[1, 0]] + IN_RELEASE
ORDINARY_RESULT = bytes.fromhex("0200000000000000020000000000000042410300000000000000440043")
# Literals derived from the operations in host.mjs, not generated from a run.
# Each entry pins statuses, endpoint count, exact release order, result copy-out.
HOST_CASES = [
    ("open_out_of_memory_range", [256], 0, [], False),
    ("open_private_memory_range", [256], 0, [], False),
    ("open_overbound_precedence", [6], 0, [], False),
    ("descriptor_mismatch", [2], 0, [], False),
    ("binding_mismatch", [4], 0, [], False),
    ("missing_descriptor", [13], 0, [], False),
    ("prepare_overflow_range", [256], 0, [], False),
    ("prepare_private_memory", [256], 0, [], False),
    ("prepare_scratch_end_plus_one", [256], 0, [], False),
    ("prepare_total_bound_plus_one", [6], 0, [], False),
    ("prepare_invalid_u32_length", [6], 0, [], False),
    ("trailing_input", [5], 0, [], False),
    ("truncated_input", [5], 0, [], False),
    ("unknown_handles", [8, 8], 0, [], False),
    ("wrong_provider_preserves_input", [8, 0], 1, FULL_RELEASE, True),
    ("input_used_as_result", [8], 0, IN_RELEASE, False),
    ("close_with_live_input", [7], 0, IN_RELEASE, False),
    ("stale_input_after_new_prepare", [8, 0], 1, IN_RELEASE + FULL_RELEASE, True),
    ("stale_child_after_recreation", [8], 0, IN_RELEASE, False),
    ("consumed_input_cannot_execute_twice", [8], 1, FULL_RELEASE, True),
    ("result_wrong_kind_release", [7], 1, FULL_RELEASE, True),
    ("result_export_bad_ranges", [256, 256, 256], 1, FULL_RELEASE, True),
    ("result_export_overbound", [6], 1, FULL_RELEASE, True),
    ("memory_growth_reacquires_views", [0], 1, FULL_RELEASE, True),
    ("ingress_mutation_is_not_owned_alias", [0], 1, FULL_RELEASE, True),
    ("export_copy_remains_independent", [0], 1, FULL_RELEASE, True),
    ("export_failure_retry_no_reexecution", [11, 0], 1, FULL_RELEASE, True),
    ("result_release_failure_still_settles", [11, 8], 1, FULL_RELEASE, False),
    ("result_staging_failure_no_handle", [10], 1, PARTIAL_RELEASE, False),
    ("result_failure_plus_cleanup_sticky", [10, 11], 1, PARTIAL_RELEASE, False),
    ("observation_reset_cannot_hide_live_owner", [258], 0, [], False),
    ("invalid_injection_option", [257, 257], 0, [], False),
    ("test_selector_is_closed", [257], 0, [], False),
    ("memory_growth_bound_refuses", [0], 1, FULL_RELEASE, True),
]


def manifest_bytes() -> bytes:
    return core.canonical({"schema": CORPUS, "profile": PROFILE, "cases": [
        {"case_id": name, "statuses": statuses, "endpoint_invoked": count,
         "release_order": releases, "result_carrier_hex": ORDINARY_RESULT.hex() if result else None}
        for name, statuses, count, releases, result in HOST_CASES]})


def result_digest(raw: bytes) -> str:
    # Same normalization as the shared corpus: count was independently checked.
    return core.digest(core.CORPUS + "/result", raw[8:])


def check_observations(row: dict[str, Any], extra: set[str]) -> None:
    core.require(type(row) is dict and set(row) == OBS_KEYS | extra, "observation-fields")
    for field in OBS_KEYS - {"release_order", "secondary_cleanup", "trace"}:
        core.require(type(row[field]) is int and 0 <= row[field] <= 40 * 1024 * 1024,
                     "observation-integer:" + field)
    for field in ["live_alloc", "live_bytes", "live_handles", "allocator_live", "allocator_bytes"]:
        core.require(row[field] == 0, "observation-live-resource:" + field)
    core.require(row["endpoint_invoked"] in (0, 1) and row["peak_alloc"] <= 1024
                 and row["peak_handles"] <= 256, "observation-count-bound")
    core.require(type(row["trace"]) is list and len(row["trace"]) < 4096
                 and all(type(n) is int and 0 <= n <= 14 for n in row["trace"]), "observation-trace")
    core.require(type(row["release_order"]) is list and len(row["release_order"]) <= 512,
                 "observation-releases")
    for item in row["release_order"]:
        core.require(type(item) is list and len(item) == 2 and all(type(n) is int for n in item)
                     and item[0] in (0, 1) and 0 <= item[1] < 256, "observation-release")
    core.require(type(row["secondary_cleanup"]) is list and len(row["secondary_cleanup"]) <= 16
                 and all(type(n) is int and n == 11 for n in row["secondary_cleanup"]), "observation-secondary")


def check_host(rows: list[dict[str, Any]]) -> None:
    core.require(type(rows) is list and len(rows) == len(HOST_CASES), "host-case-count")
    for row, (name, statuses, endpoints, releases, result) in zip(rows, HOST_CASES):
        check_observations(row, {"case_id", "statuses", "result_hex"})
        core.require(row["case_id"] == name and type(row["statuses"]) is list
                     and all(type(n) is int for n in row["statuses"]) and row["statuses"] == statuses,
                     "host-status:" + name)
        core.require(row["endpoint_invoked"] == endpoints and row["release_order"] == releases,
                     "host-settlement:" + name)
        core.require(row["result_hex"] == (ORDINARY_RESULT.hex() if result else None), "host-result:" + name)
        core.require(row["secondary_cleanup"] == ([11] if name == "result_failure_plus_cleanup_sticky" else []),
                     "host-secondary:" + name)


def seal(body: dict[str, Any]) -> bytes:
    return core.canonical(dict(body, summary_digest=core.digest(SCHEMA + "/summary", core.canonical(body))))


def _hash(value: Any) -> bool:
    return type(value) is str and len(value) == 71 and value.startswith("sha256:") and all(c in "0123456789abcdef" for c in value[7:])


@lru_cache(maxsize=2)
def inventory(stress: bool) -> dict[str, list[dict[str, Any]]]:
    """Local, bounded, trusted manifests select cases; evidence cannot add any."""
    shared, _ = core.load_manifest()
    phase = phases.load_manifest(core.read_bounded(
        core.FIXTURE / "native-result-phase-cases.json", phases.BYTE_LIMIT))
    lifecycle, _ = core.lifecycle_manifest(stress)
    return {"shared-c-probe": shared["cases"], "result-phase-c-probe": phase["cases"],
            "lifecycle-c-probe": lifecycle, "raw-wasm-transport": shared["cases"],
            "hostile-wasm-transport": [{"case_id": case[0]} for case in HOST_CASES]}


def checked_row_observation(row: dict[str, Any], expected: dict[str, Any]) -> None:
    obs, route = row["observations"], row["route"]
    core.require(type(obs) is dict, "evidence-observations")
    if route in ("raw-wasm-transport", "hostile-wasm-transport"):
        key = "status" if route == "raw-wasm-transport" else "statuses"
        check_observations(obs, {key})
        statuses = [obs[key]] if key == "status" else obs[key]
        core.require(type(statuses) is list and 0 < len(statuses) <= 4 and all(
            type(n) is int and n in {*range(14), 256, 257, 258} for n in statuses), "evidence-statuses")
    elif route == "shared-c-probe":
        fields = set(core.FIELDS) - {"case_id", "result"}
        core.require(set(obs) == fields, "evidence-shared-fields")
        check_observations({key: obs[key] for key in OBS_KEYS - {"allocator_live", "allocator_bytes"}}
                           | {"allocator_live": 0, "allocator_bytes": 0}, set())
        for key in fields - {"trace", "release_order", "secondary_cleanup"}:
            core.require(type(obs[key]) is int and 0 <= obs[key] <= 40 * 1024 * 1024, "evidence-shared-integer")
        core.require(obs["fixture_live"] == 0 and obs["accepted"] == int(expected["expected_accepted"])
                     and obs["status"] == expected["expected_primary_status"], "evidence-shared-status")
        core.require(row["result_digest"] == expected["expected_result_carrier_digest"], "evidence-shared-result")
    elif route == "result-phase-c-probe":
        core.require(set(obs) == set(phases.FIELDS) - {"case_id"}, "evidence-phase-fields")
        # Strict integer domains and fixed-width event arrays; bool is never 0.
        for key, value in obs.items():
            if key in ("secondary", "releases", "events"):
                core.require(type(value) is list and len(value) <= 4096, "evidence-phase-array")
                for entry in value:
                    nums = [entry] if key == "secondary" else entry
                    core.require(type(nums) is list and len(nums) == {"secondary": 1, "releases": 2, "events": 6}[key]
                                 and all(type(n) is int for n in nums), "evidence-phase-entry")
            else:
                core.require(type(value) is int, "evidence-phase-integer")
        values = dict(obs, case_id=row["case_id"])
        words = []
        for key in phases.FIELDS:
            value = values[key]
            if key in ("events", "releases"):
                value = ",".join(":".join(str(n) for n in entry) for entry in value)
            elif key == "secondary":
                value = ",".join(map(str, value))
            words.append(f"{key}={value}")
        core.require(phases.parse_line("PHASE " + " ".join(words)) == values, "evidence-phase-types")
        core.require({k: values[k] for k in expected} == expected, "evidence-phase-expectation")
    else:
        core.require(set(obs) == set(core.LIFECYCLE_FIELDS) - {"case_id"}, "evidence-lifecycle-fields")
        core.require(all(type(v) is int for v in obs.values()), "evidence-lifecycle-integer")
        core.require(dict(obs, case_id=row["case_id"]) == expected, "evidence-lifecycle-expectation")


def verify(submitted: bytes, trusted: bytes | None = None) -> None:
    value = core.read_canonical(submitted, LIMIT)
    core.require(type(value) is dict and set(value) == {"schema", "profile", "source_digest", "manifest_digest",
        "descriptor_digest", "reference_binding_digest", "configuration", "rows", "summary_digest"}, "evidence-fields")
    core.require(value["schema"] == SCHEMA and value["profile"] == PROFILE, "evidence-schema")
    for key in ["source_digest", "manifest_digest", "descriptor_digest", "reference_binding_digest", "summary_digest"]:
        core.require(_hash(value[key]), "evidence-hash")
    config = value["configuration"]
    core.require(type(config) is dict and set(config) == {"stress", "sanitizers", "wasm_opts", "v8_tiers"}
        and type(config["stress"]) is bool and type(config["sanitizers"]) is bool
        and config["wasm_opts"] == ["O0", "O2"] and config["v8_tiers"] == ["liftoff", "turbofan"], "evidence-configuration")
    rows = value["rows"]
    core.require(type(rows) is list and 0 < len(rows) <= 2048, "evidence-row-count")
    engines = ["native-O0", "native-O2"] + (["native-sanitizers"] if config["sanitizers"] else [])
    engines += [f"wasm-{opt}-{tier}" for opt in config["wasm_opts"] for tier in config["v8_tiers"]]
    cases = inventory(config["stress"])
    selected = [(engine, route, case) for engine in engines for route, group in cases.items()
                if engine.startswith("wasm-") or route.endswith("c-probe") for case in group]
    core.require(len(rows) == len(selected), "evidence-complete-inventory")
    seen: set[tuple[str, str, str]] = set()
    for row, (engine, route, expected) in zip(rows, selected):
        core.require(type(row) is dict and set(row) == {"case_id", "engine_id", "route", "artifact_digest",
            "observations", "result_digest", "observation_digest"}, "evidence-row-fields")
        core.require(type(row["case_id"]) is str and 0 < len(row["case_id"]) <= 120
                     and all(c.isascii() and (c.isalnum() or c in '_-') for c in row["case_id"]), "evidence-case-id")
        core.require(row["engine_id"] in engines and row["route"] in {"shared-c-probe", "result-phase-c-probe",
            "lifecycle-c-probe", "raw-wasm-transport", "hostile-wasm-transport"}, "evidence-route")
        core.require((row["engine_id"], row["route"], row["case_id"]) == (engine, route, expected["case_id"]),
                     "evidence-trusted-case-order")
        pair = row["engine_id"], row["route"], row["case_id"]
        core.require(pair not in seen, "evidence-duplicate-row"); seen.add(pair)
        core.require(_hash(row["artifact_digest"]) and _hash(row["observation_digest"])
                     and (row["result_digest"] is None or _hash(row["result_digest"])), "evidence-row-hash")
        checked_row_observation(row, expected)
        obs = row["observations"]
        core.require(row["observation_digest"] == core.digest(SCHEMA + "/observation", core.canonical(obs)), "evidence-observation-digest")
    body = {k: v for k, v in value.items() if k != "summary_digest"}
    core.require(seal(body) == submitted, "evidence-summary-digest")
    if trusted is not None:
        core.require(submitted == trusted, "evidence-trusted-replay-mismatch")


def negative_controls(trusted: bytes) -> int:
    verify(trusted, trusted)
    original = json.loads(trusted)
    bad = [trusted[:-1], b" " + trusted, trusted + b"{}", trusted.replace(b'{', b'{"unknown":0,', 1),
           b" " * (LIMIT + 1)]
    for field in original["rows"][0]:
        item = copy.deepcopy(original)
        item["rows"][0][field] = "forged"
        item.pop("summary_digest"); bad.append(seal(item))
    def mutate(transform: Any) -> None:
        item = copy.deepcopy(original); transform(item)
        for row in item["rows"]:
            if "observations" in row:
                row["observation_digest"] = core.digest(SCHEMA + "/observation", core.canonical(row["observations"]))
        item.pop("summary_digest"); bad.append(seal(item))
    for field in original["rows"][0]["observations"]:
        mutate(lambda v, f=field: v["rows"][0]["observations"].pop(f))
        mutate(lambda v, f=field: v["rows"][0]["observations"].update({f: True}))
    for transform in [lambda v:v["rows"].reverse(),lambda v:v["rows"].pop(),
        lambda v:v["rows"].append(v["rows"][0]),lambda v:v["rows"][0].update(case_id="another_case"),
        lambda v:v["rows"][0].update(engine_id="wasm-O2-turbofan"),
        lambda v:v["rows"][0]["observations"].update(unknown=0),
        lambda v:v["rows"][0]["observations"].update(live_alloc=1),
        lambda v:v["rows"][0]["observations"].update(trace=[]),
        lambda v:v["rows"][0]["observations"].update(release_order=[]),
        lambda v:v["rows"][0]["observations"].update(status=11),
        lambda v:v.update(source_digest="sha256:" + "f" * 64),
        lambda v:v.update(descriptor_digest="sha256:" + "f" * 64),
        lambda v:v.update(reference_binding_digest="sha256:" + "f" * 64)]:
        mutate(transform)
    for submitted in bad:
        try: verify(submitted, trusted)
        except (ValueError, TypeError, KeyError): continue
        raise ValueError("compiled-reference-negative-control-accepted")
    return len(bad)
