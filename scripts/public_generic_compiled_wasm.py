#!/usr/bin/env python3
"""Execute the native reference provider *inside* compiled Core Wasm.

The checked Semaprax generic export pipeline is NOT implemented by this test.
Reuse the existing provider, native oracle, carrier recipes and failure probes;
no provider body or ABI is restated. Clang/wasm-ld + Node are mandatory. No WASI,
network installation, hand-assembled endpoint, or host-owned semantic heap.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
from typing import Any

import public_generic_settlement_evidence as core
import public_generic_settlement_phases as phases
import public_generic_settlement_threads as threads
import public_generic_compiled_wasm_contract as contract

ROOT = Path(__file__).resolve().parents[1]
ASSETS = ROOT / "tests/public_generic_wasm_adapter_v1/compiled_provider"
HOST = ASSETS / "host.mjs"
TIER_FLAGS = {"liftoff": ["--liftoff-only", "--no-wasm-tier-up"], "turbofan": ["--no-liftoff", "--no-wasm-tier-up"]}


def sources(cases: list[dict[str, Any]], generated: Path | None = None) -> tuple[str, str, bytes, bytes]:
    native, descriptor, binding = core.render(cases)
    provider, d, b = threads.render_provider()
    core.require((descriptor, binding) == (d, b), "reference-provider-fixture-binding")
    if generated is not None:
        actual = core.read_bounded(generated, contract.LIMIT).decode("utf8")
        core.require(actual == provider, "actual-renderer-byte-mismatch")
        provider = actual
    # Reuse the EXACT renderer composition already owned by stage 6. Replace
    # only the well-delimited provider block in the existing corpus composer.
    fragment = "\n".join([(ROOT / "src/public_generic_abi/native/spx_pg_v1.h").read_text(),
        core.c_array("SPX_PG_TRUSTED_DESCRIPTOR_BYTES", descriptor, "SPX_PG_TRUSTED_DESCRIPTOR_LEN"),
        core.c_array("SPX_PG_TRUSTED_BINDING_BYTES", binding, "SPX_PG_TRUSTED_BINDING_LEN"),
        (ROOT / "src/public_generic_abi/native/provider_body.c").read_text()])
    core.require(native.count(fragment) == 1, "provider-composition-boundary")
    native = native.replace(fragment, provider)
    wasm = "\n".join([(ASSETS / "runtime.c").read_text(), native, (ASSETS / "transport.c").read_text()])
    return native, wasm, descriptor, binding


def host_inputs(cases: list[dict[str, Any]], descriptor: bytes, binding: bytes, stress: bool) -> bytes:
    rows = []
    for case in cases:
        leaves = core.case_leaves(case)
        result = len(leaves).to_bytes(8, "little") + b"".join(core.frame(leaf[::-1]) for leaf in leaves)
        rows.append({"case_id": case["case_id"], "carrier_hex": core.input_carrier(case).hex(),
            "result_hex": result.hex() if case["expected_accepted"] else None,
            "expected_status": case["expected_primary_status"], "injections": [core.LABELS.index(case[key])
                for key in ["failure_injection_id", "compound_cleanup_injection"] if case[key] is not None]})
    return core.canonical({"schema": "semaprax.public-generic-compiled-reference-input.v1",
        "descriptor_hex": descriptor.hex(), "binding_hex": binding.hex(), "stress": stress, "cases": rows})


def run(command: list[str], cwd: Path, label: str, logs: list[dict[str, Any]], env: dict[str, str] | None = None) -> str:
    completed = subprocess.run(command, cwd=cwd, capture_output=True, text=True, timeout=180, env=env)
    logs.append({"label": label, "command": command, "returncode": completed.returncode,
                 "stdout": completed.stdout, "stderr": completed.stderr})
    core.require(completed.returncode == 0 and not completed.stderr, label + ":" + completed.stderr + completed.stdout[-4096:])
    return completed.stdout


def compile_wasm(compiler: str, work: Path, source: str, optimization: str, logs: list[dict[str, Any]]) -> Path:
    work.mkdir(parents=True, exist_ok=True)
    (work / "provider.c").write_text(source, encoding="utf8", newline="\n")
    binary = work / "provider.wasm"
    command = [compiler, "--target=wasm32-unknown-unknown", "-std=c11", "-ffreestanding", "-fno-builtin",
        "-nostdlib", "-Wall", "-Wextra", "-Werror", "-" + optimization, "-I", str(ASSETS / "include"),
        "provider.c", "-Wl,--no-entry", "-Wl,--export-memory", "-Wl,--initial-memory=134217728",
        "-Wl,--max-memory=201326592", "-Wl,-z,stack-size=1048576", "-Wl,--stack-first", "-Wl,--strip-all",
        "-o", "provider.wasm"]
    run(command, work, "compile-wasm-" + optimization, logs)
    return binary


def shared_receipts(text: str, cases: list[dict[str, Any]], expectations: list[dict[str, Any]]) -> list[dict[str, Any]]:
    lines = text.splitlines()
    core.require(len(lines) == len(cases) + 1 and lines[-1] == "settlement-corpus-native-probe-done", "shared-receipt-inventory")
    rows = [core.parse_line(line, case) for line, case in zip(lines[:-1], cases)]
    for row, expected in zip(rows, expectations):
        core.require({key: row[key] for key in expected} == expected, "shared-independent-expectation:" + row["case_id"])
    return rows


def record(outcome: dict[str, Any], route: str, engine: str, artifact: str, result: str | None = None) -> dict[str, Any]:
    observed = dict(outcome)
    case_id = observed.pop("case_id")
    if "result_digest" in observed:
        result = observed.pop("result_digest")
    if "result_hex" in observed:
        raw = observed.pop("result_hex")
        result = contract.result_digest(bytes.fromhex(raw)) if raw is not None else None
    return {"case_id": case_id, "engine_id": engine, "route": route, "artifact_digest": artifact,
        "observations": observed, "result_digest": result,
        "observation_digest": core.digest(contract.SCHEMA + "/observation", core.canonical(observed))}


def compare(reference: list[dict[str, Any]], actual: list[dict[str, Any]], local: set[str], label: str) -> None:
    core.require(len(reference) == len(actual), "comparison-row-count:" + label)
    for a, b in zip(reference, actual):
        for field in set(a) | set(b):
            if field not in local:
                core.require(field in a and field in b and a[field] == b[field],
                             f"comparison:{label}:{a.get('case_id')}:{field}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--replay", type=Path)
    parser.add_argument("--stress", action="store_true")
    parser.add_argument("--sanitizers", action="store_true", help="require the native provider + probes under ASan/UBSan")
    parser.add_argument("--cc", default=os.environ.get("CLANG", "clang"))
    parser.add_argument("--generated-provider", type=Path, help="require byte equality with actual Rust-rendered provider")
    args = parser.parse_args()
    submitted = core.read_bounded(args.replay, contract.LIMIT) if args.replay else None
    if submitted is not None:
        contract.verify(submitted)  # Syntax/integrity only, never a trust claim.
    compiler, node = shutil.which(args.cc), shutil.which("node")
    core.require(compiler is not None and node is not None, "required-compiler-or-node-unavailable")
    manifest, manifest_raw = core.load_manifest()
    cases = manifest["cases"]
    expect_raw = core.read_bounded(core.FIXTURE / "native-expectations.json", 65536)
    expectations = core.read_canonical(expect_raw, 65536)
    core.require(expectations["manifest_digest"] == core.digest(core.EVIDENCE + "/manifest", manifest_raw), "expectation-binding")
    core.require([c["case_id"] for c in cases] == [r["case_id"] for r in expectations["cases"]], "expectation-inventory")
    phase_raw = core.read_bounded(core.FIXTURE / "native-result-phase-cases.json", phases.BYTE_LIMIT)
    phase_manifest = phases.load_manifest(phase_raw)
    life_cases, life_raw = core.lifecycle_manifest(args.stress)
    retained_host = core.read_bounded(ASSETS / "cases.json", 65536)
    core.require(retained_host == contract.manifest_bytes(), "compiled-reference-host-manifest-drift")
    native_source, wasm_source, descriptor, binding = sources(cases, args.generated_provider)
    inputs = host_inputs(cases, descriptor, binding, args.stress)
    native_reference = phase_reference = None
    wasm_reference = None
    rows: list[dict[str, Any]] = []
    logs: list[dict[str, Any]] = []
    with tempfile.TemporaryDirectory(prefix="spx-compiled-reference-") as temporary:
        work = Path(temporary)
        (work / "inputs.json").write_bytes(inputs)
        (work / "provider.c").write_text(native_source, encoding="utf8", newline="\n")
        flags = [("native-O0", ["-O0"]), ("native-O2", ["-O2"])]
        if args.sanitizers:
            flags.append(("native-sanitizers", ["-O1", "-fsanitize=address,undefined", "-fno-sanitize-recover=all", "-fno-omit-frame-pointer"]))
        env = dict(os.environ, ASAN_OPTIONS="detect_leaks=1:halt_on_error=1", UBSAN_OPTIONS="halt_on_error=1")
        for engine, options in flags:
            binary = work / (engine + (".exe" if os.name == "nt" else ""))
            run([compiler, "-std=c11", "-Wall", "-Wextra", "-Werror", *options, "provider.c", "-o", binary.name], work, "compile-" + engine, logs)
            artifact = core.digest(contract.SCHEMA + "/artifact", binary.read_bytes())
            observed = shared_receipts(run([str(binary)], work, engine, logs, env), cases, expectations["cases"])
            phase_observed = phases.verify_receipts(run([str(binary), "result-phases"], work, engine + "-phases", logs, env), phase_manifest)
            if native_reference is None:
                native_reference, phase_reference = observed, phase_observed
            else:
                compare(native_reference, observed, set(), engine)
                compare(phase_reference, phase_observed, set(), engine + "-phases")
            rows += [record(o, "shared-c-probe", engine, artifact) for o in observed]
            rows += [record(o, "result-phase-c-probe", engine, artifact, phases.result_digest(o)) for o in phase_observed]
            for expected in life_cases:
                observed_life = core.parse_lifecycle(run([str(binary), expected["case_id"]], work, engine + "-" + expected["case_id"], logs, env), expected)
                rows.append(record(observed_life, "lifecycle-c-probe", engine, artifact))
            print(f"PASS {engine}: 22 shared, 61 additional failure assertions, 72 result-phase and {len(life_cases)} lifecycle cases", flush=True)
        for optimization in ["O0", "O2"]:
            binary = compile_wasm(compiler, work / optimization, wasm_source, optimization, logs)
            # Independent second compilation must reproduce the module bytes.
            repeated = compile_wasm(compiler, work / (optimization + "-rebuild"), wasm_source, optimization, logs)
            core.require(binary.read_bytes() == repeated.read_bytes(), "wasm-build-nondeterminism")
            artifact = core.digest(contract.SCHEMA + "/artifact", binary.read_bytes())
            for tier, tier_flags in TIER_FLAGS.items():
                engine = f"wasm-{optimization}-{tier}"
                text = run([node, *tier_flags, str(HOST), str(binary), str(work / "inputs.json"), "suite"], work, engine, logs)
                core.require(len(text) <= 4 * 1024 * 1024, "host-observation-bound")
                measured = json.loads(text)
                core.require(type(measured) is dict and set(measured) == {"selectors", "raw", "host"}, "host-output-fields")
                selectors = measured["selectors"]
                core.require(len(selectors) == len(life_cases) + 2 and [r["selector"] for r in selectors] == list(range(len(selectors))), "wasm-selector-inventory")
                for selection in selectors:
                    core.require(set(selection) == {"selector", "receipt"}, "wasm-selector-fields")
                observed = shared_receipts(selectors[0]["receipt"], cases, expectations["cases"])
                phase_observed = phases.verify_receipts(selectors[1]["receipt"], phase_manifest)
                # Requested-byte peaks differ at 32-bit vs 64-bit pointer/size_t
                # widths. Every peak stays in evidence; logical counts, release
                # order, traces, statuses and final bytes must match exactly.
                compare(native_reference, observed, {"peak_bytes"}, engine)
                compare(phase_reference, phase_observed, {"peak_bytes"}, engine + "-phases")
                rows += [record(o, "shared-c-probe", engine, artifact) for o in observed]
                rows += [record(o, "result-phase-c-probe", engine, artifact, phases.result_digest(o)) for o in phase_observed]
                for selected, expected in zip(selectors[2:], life_cases):
                    rows.append(record(core.parse_lifecycle(selected["receipt"], expected), "lifecycle-c-probe", engine, artifact))
                raw = measured["raw"]
                core.require(type(raw) is list and len(raw) == len(cases), "raw-case-count")
                for observed_raw, same_wasm, expected in zip(raw, observed, json.loads(inputs)["cases"]):
                    contract.check_observations(observed_raw, {"case_id", "status", "result_hex"})
                    core.require(observed_raw["case_id"] == expected["case_id"] and observed_raw["result_hex"] == expected["result_hex"], "raw-result")
                    for field in contract.OBS_KEYS & set(same_wasm) | {"status"}:
                        core.require(observed_raw[field] == same_wasm[field], "raw-provider-disagreement:" + expected["case_id"] + ":" + field)
                    rows.append(record(observed_raw, "raw-wasm-transport", engine, artifact))
                contract.check_host(measured["host"])
                rows += [record(o, "hostile-wasm-transport", engine, artifact) for o in measured["host"]]
                if wasm_reference is None:
                    wasm_reference = measured
                else:
                    core.require(measured == wasm_reference, "wasm-optimization-or-engine-disagreement")
                print(f"PASS {engine}: full in-module corpus, {len(raw)} raw calls, {len(measured['host'])} hostile/memory cases; zero resources", flush=True)
        helpers = [HOST, Path(__file__), Path(contract.__file__), Path(core.__file__), Path(phases.__file__), Path(threads.__file__), *sorted((ASSETS / "include").glob("*.h"))]
        source_bytes = core.frame(native_source.encode()) + core.frame(wasm_source.encode()) + b"".join(core.frame(p.read_bytes()) for p in helpers)
        body = {"schema": contract.SCHEMA, "profile": contract.PROFILE,
            "source_digest": core.digest(contract.SCHEMA + "/sources", source_bytes),
            "manifest_digest": core.digest(contract.SCHEMA + "/manifests", b"".join(map(core.frame, [manifest_raw, expect_raw, phase_raw, life_raw, retained_host]))),
            "descriptor_digest": core.digest(contract.SCHEMA + "/descriptor", descriptor),
            "reference_binding_digest": core.digest(contract.SCHEMA + "/binding", binding),
            "configuration": {"stress": args.stress, "sanitizers": args.sanitizers, "wasm_opts": ["O0", "O2"], "v8_tiers": list(TIER_FLAGS)},
            "rows": rows}
        evidence = contract.seal(body)
        contract.verify(evidence, evidence)
        negatives = contract.negative_controls(evidence)
        if submitted is not None:
            contract.verify(submitted, evidence)
            print("PASS independent replay: trusted source recompilation and execution match every evidence byte", flush=True)
        if args.output:
            args.output.mkdir(parents=True, exist_ok=True)
            (args.output / "compiled-reference-evidence.json").write_bytes(evidence)
            (args.output / "commands.json").write_bytes(core.canonical(logs))
            # Modules are intentionally not a published binary package. Keep
            # their digests in evidence, not unchecked cached executables.
        print(f"PASS compiled-reference gate: {len(rows)} records; {negatives} tampering controls; public generic PG-7 remains partial", flush=True)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ValueError, KeyError, TypeError, OSError, RecursionError, subprocess.SubprocessError) as error:
        print(f"FAIL compiled-reference: {error}", file=sys.stderr)
        raise SystemExit(1)
