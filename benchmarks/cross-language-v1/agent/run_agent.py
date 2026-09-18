#!/usr/bin/env python3
"""Agent-driven cross-language benchmark runner (issue #211's missing seam).

`run.py` (this suite's existing harness) scores a fixed, human-written
source tree. This script instead asks a `SolverTransport` to *produce* the
candidate file(s) for one (task, language) pair, spends an explicit,
recorded budget doing so, and then scores that candidate through the exact
same build/test/leak-check/provenance machinery `run.py` already uses (see
`orchestrator.py`). Every model, sampling, and budget parameter is a command
line flag; none has an environment-variable fallback.

Usage (deterministic replay, no network, no credentials):

  python3 benchmarks/cross-language-v1/agent/run_agent.py \\
    --task structured-input-error-handling-v1 --language rust \\
    --candidate-path candidate.rs \\
    --transport replay \\
    --fixture benchmarks/cross-language-v1/agent/fixtures/structured-input-error-handling-v1-rust-ok.json \\
    --model-provider anthropic --model-name claude-mock --model-revision fixture-2026-09-18 \\
    --temperature 0.0 --top-p 1.0 --seed 1 --max-output-tokens 2000 \\
    --max-prompt-tokens 100000 --max-completion-tokens 100000 --max-total-tokens 100000 \\
    --max-retries 3 --max-cost-usd 1.0 \\
    --output /tmp/agent-result.json

Usage (declared, inert live transport -- refuses without a real key, and
refuses even with one; see `live_transport.py`):

  python3 benchmarks/cross-language-v1/agent/run_agent.py ... \\
    --transport live --live-provider anthropic --live-api-key "$SOME_REAL_KEY"

`--live-api-key` is read only from this explicit flag, never from an
environment variable, so supplying live credentials is always a visible,
deliberate act in the invoking command line, never an ambient lookup.
"""
from __future__ import annotations

import argparse
import json
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
from agent._harness import repo_root, run_module  # noqa: E402
from agent.contracts import Budget, ModelIdentity, PricingRates, SamplingParams  # noqa: E402
from agent.live_transport import LiveTransport  # noqa: E402
from agent.orchestrator import build_request, evaluate_agent_pair  # noqa: E402
from agent.replay_transport import ReplayTransport  # noqa: E402


def parse_args():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--task", required=True, help="task id from tasks.json")
    parser.add_argument("--language", required=True, help="language id from adapters.json")
    parser.add_argument("--candidate-path", action="append", required=True, dest="candidate_paths",
                         help="relative path within the task's public tree the transport must supply "
                              "(repeatable)")
    parser.add_argument("--output", required=True, help="output JSON path")
    parser.add_argument("--root", help="repository root task paths resolve against (default: repo root)")
    parser.add_argument("--tasks", help="task inventory path (default: this suite's tasks.json)")
    parser.add_argument("--adapters", help="adapter inventory path (default: this suite's adapters.json)")
    parser.add_argument("--semaprax", help="path to the semaprax binary, if the adapter needs it")

    parser.add_argument("--transport", choices=["replay", "live"], required=True)
    parser.add_argument("--fixture", help="replay fixture JSON path (required for --transport replay)")
    parser.add_argument("--live-provider", help="provider name (required for --transport live)")
    parser.add_argument("--live-api-key", help="explicit API key (required for --transport live; "
                                                "never read from an environment variable)")
    parser.add_argument("--live-endpoint", default="", help="explicit endpoint override for --transport live")

    parser.add_argument("--model-provider", required=True)
    parser.add_argument("--model-name", required=True)
    parser.add_argument("--model-revision", required=True)
    parser.add_argument("--temperature", type=float, required=True)
    parser.add_argument("--top-p", type=float, required=True)
    parser.add_argument("--seed", type=int, required=True)
    parser.add_argument("--max-output-tokens", type=int, required=True)

    parser.add_argument("--max-prompt-tokens", type=int, required=True)
    parser.add_argument("--max-completion-tokens", type=int, required=True)
    parser.add_argument("--max-total-tokens", type=int, required=True)
    parser.add_argument("--max-retries", type=int, required=True)
    parser.add_argument("--max-cost-usd", type=float, required=True)
    parser.add_argument("--input-usd-per-1k", type=float, default=0.0)
    parser.add_argument("--output-usd-per-1k", type=float, default=0.0)
    return parser.parse_args()


def fail(message: str) -> int:
    print(f"error: {message}", file=sys.stderr)
    return 2


def main() -> int:
    args = parse_args()
    run = run_module()

    root = pathlib.Path(args.root).resolve() if args.root else repo_root()
    tasks_path = pathlib.Path(args.tasks).resolve() if args.tasks else (repo_root() / "benchmarks/cross-language-v1/tasks.json")
    adapters_path = pathlib.Path(args.adapters).resolve() if args.adapters else (repo_root() / "benchmarks/cross-language-v1/adapters.json")

    try:
        tasks_document = run.load_json(tasks_path, run.TASKS_SCHEMA, "task inventory")
    except FileNotFoundError:
        return fail(f"task inventory not found: {tasks_path}")
    except (json.JSONDecodeError, ValueError) as error:
        return fail(f"task inventory is invalid: {tasks_path}: {error}")
    try:
        adapters = run.resolve_adapters(adapters_path)
    except FileNotFoundError:
        return fail(f"adapter inventory not found: {adapters_path}")
    except (json.JSONDecodeError, ValueError) as error:
        return fail(f"adapter inventory is invalid: {adapters_path}: {error}")

    task = next((t for t in tasks_document["tasks"] if t["id"] == args.task), None)
    if task is None:
        return fail(f"unknown task id: {args.task}")
    adapter = adapters.get(args.language)
    if adapter is None:
        return fail(f"unknown language id: {args.language}")

    paths = task.get("languages", {}).get(args.language)
    if paths is None:
        return fail(f"{args.task} declares no {args.language} implementation")
    public_dir = root / paths["public"]
    equivalence_path = root / "benchmarks/cross-language-v1" / task.get("equivalence", "")
    equivalence_text = equivalence_path.read_text() if equivalence_path.is_file() else ""

    model = ModelIdentity(provider=args.model_provider, model=args.model_name, revision=args.model_revision)
    sampling = SamplingParams(
        temperature=args.temperature, top_p=args.top_p, seed=args.seed,
        max_output_tokens=args.max_output_tokens,
    )
    budget = Budget(
        max_prompt_tokens=args.max_prompt_tokens,
        max_completion_tokens=args.max_completion_tokens,
        max_total_tokens=args.max_total_tokens,
        max_retries=args.max_retries,
        max_cost_usd=args.max_cost_usd,
    )
    pricing = PricingRates(input_usd_per_1k=args.input_usd_per_1k, output_usd_per_1k=args.output_usd_per_1k)

    request = build_request(
        task, args.language, model, sampling, budget, pricing,
        equivalence_text, public_dir, args.candidate_paths,
    )

    if args.transport == "replay":
        if not args.fixture:
            return fail("--transport replay requires --fixture")
        transport = ReplayTransport(args.fixture)
    else:
        if not args.live_provider or not args.live_api_key:
            return fail("--transport live requires --live-provider and --live-api-key")
        transport = LiveTransport(provider=args.live_provider, api_key=args.live_api_key, endpoint=args.live_endpoint)

    record = evaluate_agent_pair(
        root, task, args.language, adapter, transport, request,
        semaprax_binary=args.semaprax or "semaprax",
        candidate_paths=args.candidate_paths,
    )
    document = {
        "schema": "benchmark.cross_language.agent.v1",
        "host": run.host_facts(),
        "revision": run.git_revision(repo_root()),
        "result": record,
    }
    out_path = pathlib.Path(args.output)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(document, sort_keys=True, indent=2) + "\n")
    print(f"Wrote {out_path}: status={record['status']}")
    return 0 if record["status"] == "ok" else 1


if __name__ == "__main__":
    sys.exit(main())
