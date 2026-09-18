"""Offline, credential-free, network-free self-tests for the agent-driver
seam (issue #211's residual gap).

Every test here runs with `python3` alone: no model credentials, no network
access, and (with the exception of the two tests marked "real toolchain"
below, which use this host's already-installed `rustc` exactly as
`tests/documentation/cross_language_benchmark_suite.rs` already does for the
harness's own self-tests) no external process beyond the Python interpreter
itself. Run with:

    python3 -m unittest discover -s benchmarks/cross-language-v1/agent/tests -v

or as a script:

    python3 benchmarks/cross-language-v1/agent/tests/test_agent_driver.py
"""
from __future__ import annotations

import json
import pathlib
import shutil
import subprocess
import sys
import tempfile
import unittest

_SUITE = pathlib.Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(_SUITE))

from agent._harness import repo_root, run_module  # noqa: E402
from agent.budget import BudgetExceededError, BudgetLedger, RetriesExhaustedError  # noqa: E402
from agent.contracts import Budget, ModelIdentity, PricingRates, SamplingParams  # noqa: E402
from agent.orchestrator import build_request, evaluate_agent_pair  # noqa: E402
from agent.prompts import build_prompt  # noqa: E402
from agent.replay_transport import ReplayTransport  # noqa: E402
from agent.live_transport import LiveTransport  # noqa: E402
from agent.transport import CredentialsRequiredError, LiveTransportUnexercisedError  # noqa: E402

FIXTURE_OK = _SUITE / "agent/fixtures/structured-input-error-handling-v1-rust-ok.json"
TASK_DIR = _SUITE / "tasks/structured-input-error-handling-v1"


def write_fixture(directory: pathlib.Path, attempts: list) -> pathlib.Path:
    path = directory / "fixture.json"
    path.write_text(json.dumps({
        "schema": "benchmark.cross_language.agent.replay_fixture.v1",
        "attempts": attempts,
    }))
    return path


def mid_budget(**overrides) -> Budget:
    base = dict(
        max_prompt_tokens=100_000,
        max_completion_tokens=100_000,
        max_total_tokens=100_000,
        max_retries=3,
        max_cost_usd=1.0,
    )
    base.update(overrides)
    return Budget(**base)


def model() -> ModelIdentity:
    return ModelIdentity(provider="anthropic", model="claude-mock", revision="fixture-2026-09-18")


def sampling(seed=1) -> SamplingParams:
    return SamplingParams(temperature=0.0, top_p=1.0, seed=seed, max_output_tokens=2000)


def real_task_and_adapter():
    run = run_module()
    tasks_doc = run.load_json(_SUITE / "tasks.json", run.TASKS_SCHEMA, "tasks")
    adapters = run.resolve_adapters(_SUITE / "adapters.json")
    task = next(t for t in tasks_doc["tasks"] if t["id"] == "structured-input-error-handling-v1")
    return task, adapters["rust"]


def real_request(budget=None):
    task, _ = real_task_and_adapter()
    equivalence = (_SUITE / "tasks/structured-input-error-handling-v1/EQUIVALENCE.md").read_text()
    public_dir = _SUITE / "tasks/structured-input-error-handling-v1/public/rust"
    return build_request(
        task, "rust", model(), sampling(), budget or mid_budget(), PricingRates(),
        equivalence, public_dir, ["candidate.rs"],
    )


class ContractsTests(unittest.TestCase):
    def test_model_identity_rejects_mutable_alias(self):
        with self.assertRaises(ValueError):
            ModelIdentity(provider="anthropic", model="latest", revision="1")
        with self.assertRaises(ValueError):
            ModelIdentity(provider="anthropic", model="claude", revision="@main")

    def test_model_identity_rejects_empty_field(self):
        with self.assertRaises(ValueError):
            ModelIdentity(provider="", model="claude", revision="1")

    def test_prompt_excludes_hidden_content_and_candidate_placeholder(self):
        task, _ = real_task_and_adapter()
        equivalence = (TASK_DIR / "EQUIVALENCE.md").read_text()
        prompt = build_prompt(
            task["id"], "rust", equivalence, TASK_DIR / "public/rust", ["candidate.rs"],
        )
        hidden_only_text = "compound_invalid_records_preserve_first_error_precedence"
        self.assertNotIn(hidden_only_text, prompt, "prompt must never contain hidden-only content")
        self.assertNotIn("pub fn validate", prompt, "prompt must not show the candidate's own content")
        self.assertIn("mod candidate;", prompt, "prompt must show the fixed public scaffold")

    def test_prompt_digest_is_stable(self):
        task, _ = real_task_and_adapter()
        equivalence = (TASK_DIR / "EQUIVALENCE.md").read_text()
        first = build_prompt(task["id"], "rust", equivalence, TASK_DIR / "public/rust", ["candidate.rs"])
        second = build_prompt(task["id"], "rust", equivalence, TASK_DIR / "public/rust", ["candidate.rs"])
        self.assertEqual(first, second)


class BudgetLedgerTests(unittest.TestCase):
    def test_charge_within_budget_commits(self):
        ledger = BudgetLedger(mid_budget())
        ledger.charge_attempt(prompt_tokens=100, completion_tokens=50, cost_usd=0.01, is_retry=False)
        self.assertEqual(ledger.usage.prompt_tokens, 100)
        self.assertEqual(ledger.usage.completion_tokens, 50)
        self.assertEqual(ledger.usage.retries_used, 0)

    def test_charge_over_prompt_tokens_raises_and_leaves_usage_unchanged(self):
        ledger = BudgetLedger(mid_budget(max_prompt_tokens=50))
        with self.assertRaises(BudgetExceededError) as ctx:
            ledger.charge_attempt(prompt_tokens=51, completion_tokens=0, cost_usd=0.0, is_retry=False)
        self.assertIn("max_prompt_tokens", str(ctx.exception))
        self.assertEqual(ledger.usage.prompt_tokens, 0, "a rejected charge must not be partially applied")

    def test_charge_over_cost_raises(self):
        ledger = BudgetLedger(mid_budget(max_cost_usd=0.001))
        with self.assertRaises(BudgetExceededError) as ctx:
            ledger.charge_attempt(prompt_tokens=1, completion_tokens=1, cost_usd=0.5, is_retry=False)
        self.assertIn("max_cost_usd", str(ctx.exception))

    def test_retry_over_max_retries_raises_retries_exhausted(self):
        ledger = BudgetLedger(mid_budget(max_retries=0))
        with self.assertRaises(RetriesExhaustedError):
            ledger.charge_attempt(prompt_tokens=1, completion_tokens=1, cost_usd=0.0, is_retry=True)


class ReplayTransportTests(unittest.TestCase):
    def test_replay_is_byte_for_byte_deterministic(self):
        transport = ReplayTransport(FIXTURE_OK)
        request = real_request()
        first = transport.complete(request)
        second = transport.complete(request)
        self.assertEqual(first.usage.to_dict(), second.usage.to_dict())
        self.assertEqual(first.transcript_digest, second.transcript_digest)
        self.assertEqual(first.candidate_files, second.candidate_files)

    def test_replay_accounts_the_declared_retry(self):
        transport = ReplayTransport(FIXTURE_OK)
        response = transport.complete(real_request())
        self.assertEqual(response.usage.retries_used, 1)
        self.assertEqual(len(response.transcript), 4, "two attempts x (prompt, response)")

    def test_wrong_fixture_schema_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            bad = pathlib.Path(directory) / "bad.json"
            bad.write_text(json.dumps({"schema": "not.the.right.schema", "attempts": []}))
            with self.assertRaises(ValueError):
                ReplayTransport(bad)

    def test_budget_exceeded_on_first_attempt_fails_closed_before_any_retry(self):
        with tempfile.TemporaryDirectory() as directory:
            fixture = write_fixture(pathlib.Path(directory), [
                {"attempt": 1, "kind": "final", "prompt_tokens": 1000, "completion_tokens": 10,
                 "cost_usd": 0.0, "response_text": "would exceed budget",
                 "candidate_files": {"candidate.rs": "pub fn validate() {}\n"}},
            ])
            transport = ReplayTransport(fixture)
            tiny_budget = mid_budget(max_prompt_tokens=100)
            request = real_request(budget=tiny_budget)
            with self.assertRaises(BudgetExceededError) as ctx:
                transport.complete(request)
            error = ctx.exception
            self.assertIn("max_prompt_tokens", str(error))
            self.assertEqual(error.usage.prompt_tokens, 0, "nothing was committed before the raise")
            self.assertEqual(len(error.transcript), 2, "the rejected attempt is still recorded")

    def test_retries_exhausted_when_fixture_never_reaches_final(self):
        with tempfile.TemporaryDirectory() as directory:
            fixture = write_fixture(pathlib.Path(directory), [
                {"attempt": 1, "kind": "retryable_error", "prompt_tokens": 10, "completion_tokens": 0,
                 "cost_usd": 0.0, "response_text": "transient error 1"},
                {"attempt": 2, "kind": "retryable_error", "prompt_tokens": 10, "completion_tokens": 0,
                 "cost_usd": 0.0, "response_text": "transient error 2"},
            ])
            transport = ReplayTransport(fixture)
            request = real_request(budget=mid_budget(max_retries=1))
            with self.assertRaises(RetriesExhaustedError) as ctx:
                transport.complete(request)
            self.assertEqual(ctx.exception.usage.retries_used, 1)


class LiveTransportTests(unittest.TestCase):
    def test_refuses_construction_without_api_key(self):
        with self.assertRaises(CredentialsRequiredError):
            LiveTransport(provider="anthropic", api_key="")

    def test_refuses_construction_without_provider(self):
        with self.assertRaises(CredentialsRequiredError):
            LiveTransport(provider="", api_key="sk-something")

    def test_complete_refuses_even_with_a_real_looking_key(self):
        transport = LiveTransport(provider="anthropic", api_key="sk-ant-not-a-real-key-but-present")
        with self.assertRaises(LiveTransportUnexercisedError) as ctx:
            transport.complete(real_request())
        self.assertIn("never been executed", str(ctx.exception))

    def test_no_environment_variable_can_satisfy_construction(self):
        import os
        original = dict(os.environ)
        try:
            os.environ["ANTHROPIC_API_KEY"] = "sk-ambient-should-be-ignored"
            os.environ["OPENAI_API_KEY"] = "sk-ambient-should-be-ignored"
            with self.assertRaises(CredentialsRequiredError):
                LiveTransport(provider="anthropic", api_key="")
        finally:
            os.environ.clear()
            os.environ.update(original)


class OrchestratorBudgetFailureTests(unittest.TestCase):
    """The required proof: exceeding a declared budget terminates the run
    with a recorded outcome, never a silent continuation into a build/run
    step."""

    def test_budget_exceeded_pair_never_reaches_build_or_run(self):
        task, adapter = real_task_and_adapter()
        with tempfile.TemporaryDirectory() as directory:
            fixture = write_fixture(pathlib.Path(directory), [
                {"attempt": 1, "kind": "final", "prompt_tokens": 5000, "completion_tokens": 10,
                 "cost_usd": 0.0, "response_text": "irrelevant: budget is exceeded first",
                 "candidate_files": {"candidate.rs": "pub fn validate() {}\n"}},
            ])
            tiny_budget = mid_budget(max_prompt_tokens=10)
            request = real_request(budget=tiny_budget)
            transport = ReplayTransport(fixture)
            record = evaluate_agent_pair(repo_root(), task, "rust", adapter, transport, request)
        self.assertEqual(record["status"], "budget_exceeded")
        self.assertIn("max_prompt_tokens", record["reason"])
        self.assertNotIn("public", record, "a budget-exceeded pair must never carry a build/run artifact")
        self.assertNotIn("hidden", record, "a budget-exceeded pair must never carry a build/run artifact")
        self.assertNotIn("provenance", record, "no candidate was ever produced, so no digest can be bound")
        self.assertIn("usage", record)
        self.assertIn("transcript", record)

    def test_retries_exhausted_pair_never_reaches_build_or_run(self):
        task, adapter = real_task_and_adapter()
        with tempfile.TemporaryDirectory() as directory:
            fixture = write_fixture(pathlib.Path(directory), [
                {"attempt": 1, "kind": "retryable_error", "prompt_tokens": 5, "completion_tokens": 0,
                 "cost_usd": 0.0, "response_text": "transient 1"},
                {"attempt": 2, "kind": "retryable_error", "prompt_tokens": 5, "completion_tokens": 0,
                 "cost_usd": 0.0, "response_text": "transient 2"},
            ])
            request = real_request(budget=mid_budget(max_retries=0))
            transport = ReplayTransport(fixture)
            record = evaluate_agent_pair(repo_root(), task, "rust", adapter, transport, request)
        self.assertEqual(record["status"], "retries_exhausted")
        self.assertNotIn("public", record)
        self.assertNotIn("hidden", record)


@unittest.skipUnless(shutil.which("rustc"), "requires a real rustc toolchain, as run.py's own tests already do")
class RealToolchainEndToEndTests(unittest.TestCase):
    """Proves the whole path -- prompt, replay transport, retry accounting,
    scoring, leak check, provenance -- against a genuine, unmodified,
    committed task and a real `rustc`, not a mock."""

    def test_replay_candidate_passes_public_and_hidden_under_real_rustc(self):
        task, adapter = real_task_and_adapter()
        transport = ReplayTransport(FIXTURE_OK)
        request = real_request()
        record = evaluate_agent_pair(repo_root(), task, "rust", adapter, transport, request,
                                      candidate_paths=["candidate.rs"])
        self.assertEqual(record["status"], "ok", record)
        self.assertEqual(record["leak_check"], "ok", record)
        self.assertTrue(record["public"]["passed"], record)
        self.assertTrue(record["hidden"]["passed"], record)
        self.assertEqual(record["usage"]["retries_used"], 1)
        provenance = record["provenance"]
        self.assertTrue(provenance["digest"].startswith("sha256:"))
        self.assertEqual(provenance["model"]["provider"], "anthropic")
        self.assertEqual(provenance["seed"], 1)
        self.assertTrue(provenance["prompt_digest"].startswith("sha256:"))
        self.assertTrue(provenance["transcript_digest"].startswith("sha256:"))

    def test_wrong_candidate_from_transport_passes_public_but_fails_hidden(self):
        # The strongest available proof that scoring actually runs the
        # transport's own candidate, not the committed reference: hand-author
        # a plausible but WRONG precedence (checks version before kind) and
        # confirm it is caught by the held-out hidden vector exactly the way
        # `tests/documentation/cross_language_benchmark_suite.rs`'s
        # `structured_input_hidden_oracle_rejects_version_first_candidate...`
        # proves for the non-agent path.
        task, adapter = real_task_and_adapter()
        with tempfile.TemporaryDirectory() as directory:
            fixture = write_fixture(pathlib.Path(directory), [
                {"attempt": 1, "kind": "final", "prompt_tokens": 400, "completion_tokens": 80,
                 "cost_usd": 0.001, "response_text": "wrong precedence: version-first",
                 "candidate_files": {
                     "candidate.rs": (
                         "pub fn validate(kind: i64, version: i64, payload_len: i64) -> i64 {\n"
                         "    if version != 1 { 2 } else if kind != 7 { 1 }\n"
                         "    else if !(1..=64).contains(&payload_len) { 3 } else { 0 }\n"
                         "}\n"
                     )
                 }},
            ])
            request = real_request()
            transport = ReplayTransport(fixture)
            record = evaluate_agent_pair(repo_root(), task, "rust", adapter, transport, request,
                                          candidate_paths=["candidate.rs"])
        self.assertTrue(record["public"]["passed"], record)
        self.assertFalse(record["hidden"]["passed"], record)
        self.assertEqual(record["status"], "failed")
        self.assertEqual(record["leak_check"], "ok")

    def test_cli_runs_end_to_end_and_writes_a_result(self):
        with tempfile.TemporaryDirectory() as directory:
            output = pathlib.Path(directory) / "result.json"
            result = subprocess.run(
                [sys.executable, str(_SUITE / "agent/run_agent.py"),
                 "--task", "structured-input-error-handling-v1", "--language", "rust",
                 "--candidate-path", "candidate.rs",
                 "--transport", "replay", "--fixture", str(FIXTURE_OK),
                 "--model-provider", "anthropic", "--model-name", "claude-mock",
                 "--model-revision", "fixture-2026-09-18",
                 "--temperature", "0.0", "--top-p", "1.0", "--seed", "1",
                 "--max-output-tokens", "2000",
                 "--max-prompt-tokens", "100000", "--max-completion-tokens", "100000",
                 "--max-total-tokens", "100000", "--max-retries", "3", "--max-cost-usd", "1.0",
                 "--output", str(output)],
                capture_output=True, text=True,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            document = json.loads(output.read_text())
            self.assertEqual(document["result"]["status"], "ok")

    def test_cli_budget_exceeded_exits_nonzero_and_still_records_an_outcome(self):
        with tempfile.TemporaryDirectory() as directory:
            output = pathlib.Path(directory) / "result.json"
            result = subprocess.run(
                [sys.executable, str(_SUITE / "agent/run_agent.py"),
                 "--task", "structured-input-error-handling-v1", "--language", "rust",
                 "--candidate-path", "candidate.rs",
                 "--transport", "replay", "--fixture", str(FIXTURE_OK),
                 "--model-provider", "anthropic", "--model-name", "claude-mock",
                 "--model-revision", "fixture-2026-09-18",
                 "--temperature", "0.0", "--top-p", "1.0", "--seed", "1",
                 "--max-output-tokens", "2000",
                 "--max-prompt-tokens", "10", "--max-completion-tokens", "100000",
                 "--max-total-tokens", "100000", "--max-retries", "3", "--max-cost-usd", "1.0",
                 "--output", str(output)],
                capture_output=True, text=True,
            )
            self.assertEqual(result.returncode, 1, result.stderr)
            document = json.loads(output.read_text())
            self.assertEqual(document["result"]["status"], "budget_exceeded")
            self.assertNotIn("public", document["result"])


if __name__ == "__main__":
    unittest.main()
