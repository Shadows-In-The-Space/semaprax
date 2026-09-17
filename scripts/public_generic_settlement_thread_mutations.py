#!/usr/bin/env python3
"""Compiled admission mutants must fail at their intended runtime assertions."""
from __future__ import annotations

import argparse
from pathlib import Path
import shutil
import tempfile

from public_generic_settlement_threads import (
    assemble, compile_probe, execute, manifest, parse_receipt, render_provider, require,
)


def replace(source: str, old: str, new: str) -> str:
    require(source.count(old) == 1, "thread-mutation-anchor:" + old[:60])
    return source.replace(old, new, 1)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cc", default="clang")
    parser.add_argument("--thread-sanitizer", action="store_true",
                        help="also require TSan to detect a relaxed-order publication mutant")
    args = parser.parse_args()
    compiler = shutil.which(args.cc)
    require(compiler is not None, "thread-mutation-compiler-unavailable")
    provider, _, _ = render_provider()
    cases = {row["case_id"]: row for row in manifest()[0]["cases"]}
    plans = [
        ("shared-faults", "foreign-fault-arm", "spx_pg_call_v1(thread_provider, thread_input, &thread_output) == SPX_PG_STATUS_OK"),
        ("shared-trace", "foreign-input", "spx_pg_test_trace_len_v1() == 0"),
        ("shared-diagnostics", "owner-handoff", "spx_pg_test_settlement_overwrite_attempts_v1() == 0"),
        ("foreign-steals-owner", "foreign-input", "actual == expected"),
        ("refusal-unlocks-owner", "paused-open", "actual == expected"),
        ("failure-keeps-entry", "failed-open-unpins", "spx_pg_test_live_allocations_v1() == 0"),
        ("false-zero-counter", "foreign-input", "spx_pg_test_live_allocations_v1() == SIZE_MAX"),
        ("output-before-admission", "foreign-input", "provider == &marker_provider"),
        ("reentrant-fault-arm", "reentry-open", "first == g_spx_pg_injected_ordinals[0]"),
        ("early-owner-handoff", "foreign-input", "actual == expected"),
        ("thread-counter-wrap", "thread-identity-bound", "actual == expected"),
    ]
    with tempfile.TemporaryDirectory(prefix="spx-thread-mutants-") as temp:
        work = Path(temp)
        for name, case_id, assertion in plans:
            binary = compile_probe(work, compiler, ["-O2"], assemble(provider))
            good = execute(binary, case_id)
            require(good.returncode == 0 and not good.stderr, "thread-positive-control:" + good.stderr)
            parse_receipt(good.stdout, cases[case_id])
            bad = provider
            if name == "shared-faults":
                bad = replace(bad, "static SPX_PG_THREAD_LOCAL uint32_t g_spx_pg_injected_ordinals", "static uint32_t g_spx_pg_injected_ordinals")
            elif name == "shared-trace":
                bad = replace(bad, "static SPX_PG_THREAD_LOCAL size_t g_spx_pg_trace_len", "static size_t g_spx_pg_trace_len")
            elif name == "shared-diagnostics":
                bad = replace(bad, "static SPX_PG_THREAD_LOCAL size_t g_spx_pg_settlement_overwrites", "static size_t g_spx_pg_settlement_overwrites")
            elif name == "foreign-steals-owner":
                bad = replace(bad, "if (observed != 0 && observed != owner) return SPX_PG_STATUS_ILLEGAL_TRANSITION;", "/* deliberately allow stealing an idle/active owner */")
            elif name == "refusal-unlocks-owner":
                bad = replace(bad, "if (observed != 0 && observed != owner) return SPX_PG_STATUS_ILLEGAL_TRANSITION;", "if (observed != 0 && observed != owner) { spx_pg_atomic_store(&g_spx_pg_entry_state, 0); return SPX_PG_STATUS_ILLEGAL_TRANSITION; }")
            elif name == "failure-keeps-entry":
                anchor = "    spx_pg_status_v1 outcome = spx_pg_provider_open_v1_impl(descriptor_bytes, descriptor_len, provider_binding_bytes, provider_binding_len, out_provider);\n"
                bad = replace(bad, anchor, anchor + "    if (outcome != SPX_PG_STATUS_OK) return outcome;\n")
            elif name == "false-zero-counter":
                anchor = "    if (admission != SPX_PG_STATUS_OK) return SIZE_MAX;\n    size_t outcome = spx_pg_test_live_allocations_v1_impl();"
                bad = replace(bad, anchor, anchor.replace("return SIZE_MAX", "return 0"))
            elif name == "output-before-admission":
                anchor = "    spx_pg_status_v1 admission = spx_pg_enter();\n    if (admission != SPX_PG_STATUS_OK) return admission;\n    spx_pg_status_v1 outcome = spx_pg_provider_open_v1_impl"
                bad = replace(bad, anchor, "    if (out_provider != NULL) *out_provider = NULL;\n" + anchor)
            elif name == "reentrant-fault-arm":
                anchor = "     * the active invocation's plan; a foreign thread may only alter its own. */\n    if (g_spx_pg_entry_active) return;"
                bad = replace(bad, anchor, anchor.replace("    if (g_spx_pg_entry_active) return;", ""))
            elif name == "early-owner-handoff":
                bad = replace(bad, "            next = g_spx_pg_thread_id << 1;", "            next = 0; /* deliberately unpin live providers */")
            elif name == "thread-counter-wrap":
                bad = replace(bad, "if (previous == SPX_PG_THREAD_ID_LIMIT)", "if (previous > SPX_PG_THREAD_ID_LIMIT)")
            binary = compile_probe(work, compiler, ["-O2"], assemble(bad))
            result = execute(binary, case_id)
            require(result.returncode != 0 and assertion in result.stderr,
                    f"wrong-thread-mutation-failure:{name}:{result.stderr}")
            print(f"PASS {name}: unchanged case passed; compiled mutant rejected by {assertion}", flush=True)
    if args.thread_sanitizer:
        with tempfile.TemporaryDirectory(prefix="spx-thread-tsan-mutant-") as temp:
            work = Path(temp)
            flags = ["-O1", "-fsanitize=thread", "-fno-omit-frame-pointer"]
            binary = compile_probe(work, compiler, flags, assemble(provider))
            good = execute(binary, "overlapping-owner-handoff")
            require(good.returncode == 0 and not good.stderr, "thread-tsan-positive:" + good.stderr)
            parse_receipt(good.stdout, cases["overlapping-owner-handoff"])
            bad = provider.replace("memory_order_acquire", "memory_order_relaxed")
            bad = bad.replace("memory_order_release", "memory_order_relaxed")
            bad = bad.replace("memory_order_acq_rel", "memory_order_relaxed")
            binary = compile_probe(work, compiler, flags, assemble(bad))
            result = execute(binary, "overlapping-owner-handoff")
            require(result.returncode != 0 and "WARNING: ThreadSanitizer: data race" in result.stderr,
                    "thread-tsan-mutation-not-detected:" + result.stderr)
            print("PASS relaxed-publication: unchanged case TSan-clean; compiled mutant has a detected data race", flush=True)
    print(f"PASS {len(plans) + int(args.thread_sanitizer)} compiled behavioral mutants; no compile error/timeout counted", flush=True)


if __name__ == "__main__":
    main()
