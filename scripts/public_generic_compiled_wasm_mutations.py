#!/usr/bin/env python3
"""Negative controls for the private compiled reference route, not public support.

Each mutant compiles successfully and fails a named runtime assertion which
passed first against the unchanged artifact. A compile error or Wasm trap does
not count as a successful assertion-based negative control.
"""
from __future__ import annotations

import argparse
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

import public_generic_compiled_wasm as gate
import public_generic_settlement_evidence as core


def replace_once(source: str, before: str, after: str, count: int = 1) -> str:
    core.require(source.count(before) == count, "mutation-anchor-drift")
    return source.replace(before, after)


def allocator_sanitizer(compiler: str, work: Path, logs: list[dict]) -> None:
    runtime = (gate.ASSETS / "runtime.c").read_text()
    runtime = replace_once(runtime,
        '#define PG_WASM_EXPORT(name) __attribute__((export_name(name)))',
        '#define PG_WASM_EXPORT(name)')
    # Never interpose the host libc/ASan allocator or string functions. Only
    # this translation unit's exact private runtime bodies are renamed.
    names = ["malloc", "free", "memcpy", "memset", "memcmp", "strcmp", "strlen",
             "printf", "fprintf", "snprintf", "puts", "abort"]
    source = "\n".join(f"#define {name} pg_test_{name}" for name in names)
    source += "\n" + runtime + "\nint main(void) { pg_runtime_self_test(); return 0; }\n"
    (work / "allocator.c").write_text(source, encoding="utf8", newline="\n")
    gate.run([compiler, "-std=c11", "-O1", "-ffreestanding", "-fno-builtin", "-Wall", "-Wextra", "-Werror",
        "-fsanitize=address,undefined", "-fno-sanitize-recover=all", "-fno-omit-frame-pointer",
        "-I", str(gate.ASSETS / "include"), "allocator.c", "-o", "allocator-test"], work, "allocator-sanitizer-build", logs)
    env = dict(os.environ, ASAN_OPTIONS="detect_leaks=1:halt_on_error=1", UBSAN_OPTIONS="halt_on_error=1")
    gate.run([str(work / "allocator-test")], work, "allocator-sanitizer-execution", logs, env)
    print("PASS exact private allocator bodies under ASan/UBSan: byte bound, 4096 allocations, first-over, reuse and scrub", flush=True)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--cc", default=os.environ.get("CLANG", "clang"))
    args = parser.parse_args()
    compiler, node = shutil.which(args.cc), shutil.which("node")
    core.require(compiler is not None and node is not None, "required-compiler-or-node-unavailable")
    manifest, _ = core.load_manifest()
    _, source, descriptor, binding = gate.sources(manifest["cases"])
    mutations = [
        ("identity-instead-of-reversal", "export_copy_remains_independent", "exact committed carrier",
         "input_leaf_bytes[leaf][length - 1 - index]", "input_leaf_bytes[leaf][index]", 1),
        ("masked-explicit-release", "result_release_failure_still_settles", "explicit release status",
         "return release_status;", "return SPX_PG_STATUS_OK + 0 * release_status;", 2),
        ("lost-sticky-primary", "result_failure_plus_cleanup_sticky", "sticky primary status",
         "spx_pg_select_primary_failure(status);\n        for (uint32_t undo = completed;",
         "(void)status;\n        for (uint32_t undo = completed;", 1),
        ("partial-export-on-failure", "export_failure_retry_no_reexecution", "failed export remains atomic",
         "if (spx_pg_physical_phase(SPX_PG_PHASE_EXPORT_LEAF_PENDING, 1, index)) {",
         "out_bytes[0] = 0;\n        if (spx_pg_physical_phase(SPX_PG_PHASE_EXPORT_LEAF_PENDING, 1, index)) {", 1),
        ("private-range-admitted", "open_private_memory_range", "HOST open_private_memory_range",
         "length > sizeof(pg_transport_scratch) - (pointer - base)) return PG_REF_RANGE;",
         "length > sizeof(pg_transport_scratch) - (pointer - base)) return 0;", 1),
        ("bounds-precedence-lost", "open_overbound_precedence", "HOST open_overbound_precedence",
         "if (length > bound) return SPX_PG_STATUS_CARRIER_CAPACITY;",
         "if (length > bound) bound = length;", 1),
        ("provider-resource-leak", "export_copy_remains_independent", "live resource 0",
         "return (uint32_t)spx_pg_provider_close_v1(&provider);", "(void)provider; return 0;", 1),
        ("false-reset-while-live", "observation_reset_cannot_hide_live_owner", "HOST observation_reset_cannot_hide_live_owner",
         "if (g_spx_pg_live_allocations || pg_heap_live || fixture_live || pg_live_handles) return PG_REF_LIVE_OBSERVATION;",
         "if (g_spx_pg_live_allocations || pg_heap_live || fixture_live || pg_live_handles) return 0;", 1),
        ("partial-result-handle-forged", "result_staging_failure_no_handle", "HOST result_staging_failure_no_handle",
         "return pg_lane(status, pg_identity_index(result));", "return pg_lane(status, result ? pg_identity_index(result) : input_id);", 1),
    ]
    logs: list[dict] = []
    with tempfile.TemporaryDirectory(prefix="spx-wasm-negative-") as temporary:
        work = Path(temporary)
        allocator_sanitizer(compiler, work, logs)
        inputs = work / "inputs.json"
        inputs.write_bytes(gate.host_inputs(manifest["cases"], descriptor, binding, False))
        baseline = gate.compile_wasm(compiler, work / "baseline", source, "O2", logs)
        for name, case, marker, before, after, count in mutations:
            command = [node, *gate.TIER_FLAGS["turbofan"], str(gate.HOST), str(baseline), str(inputs), "host:" + case]
            gate.run(command, work, "positive-" + name, logs)
            mutated = replace_once(source, before, after, count)
            binary = gate.compile_wasm(compiler, work / name, mutated, "O2", logs)
            command[4] = str(binary)
            # Positions: node, two V8 flags, HOST, binary, inputs, selector.
            result = subprocess.run(command, cwd=work, capture_output=True, text=True, timeout=60)
            logs.append({"label": "negative-" + name, "command": command, "returncode": result.returncode,
                         "stdout": result.stdout, "stderr": result.stderr})
            core.require(result.returncode != 0 and "AssertionError" in result.stderr
                         and marker in result.stderr and "RuntimeError: unreachable" not in result.stderr,
                         "mutant-not-rejected-by-intended-assertion:" + name + ":" + result.stderr)
            print("PASS compiled Wasm mutant rejected: " + name, flush=True)
    if args.output:
        args.output.mkdir(parents=True, exist_ok=True)
        (args.output / "mutation-commands.json").write_bytes(core.canonical(logs))
    print(f"PASS {len(mutations)} compiled semantic mutants; each unchanged positive control passed", flush=True)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ValueError, KeyError, TypeError, OSError, RecursionError, subprocess.SubprocessError) as error:
        raise SystemExit("FAIL compiled-reference mutations: " + str(error)) from error
