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
from agent.baseline_admission import (  # noqa: E402
    ADMISSION_SCHEMA,
    OWNER_TASK_INVENTORY_SHA256,
    admit_baseline_descriptor,
)
from agent.budget import BudgetExceededError, BudgetLedger, RetriesExhaustedError  # noqa: E402
from agent.contracts import (  # noqa: E402
    REDACTION_SCHEMA,
    Budget,
    ModelIdentity,
    PricingRates,
    SamplingParams,
    load_redaction_literals,
    redaction_policy_digest,
)
from agent.orchestrator import build_request, evaluate_agent_pair  # noqa: E402
from agent.prompts import build_prompt  # noqa: E402
from agent.replay_transport import ReplayTransport  # noqa: E402
from agent.specialization_protocol import (  # noqa: E402
    PLAN_SCHEMA,
    ProtocolError,
    REQUIRED_METRICS,
    build_plan,
    canonical_bytes,
)
from agent.live_transport import LiveTransport  # noqa: E402
from agent.transport import CredentialsRequiredError, LiveTransportUnexercisedError  # noqa: E402

FIXTURE_OK = _SUITE / "agent/fixtures/structured-input-error-handling-v1-rust-ok.json"
TASK_DIR = _SUITE / "tasks/structured-input-error-handling-v1"
SPECIALIZATION_PROTOCOL = _SUITE / "agent/specialization-protocol.example.json"


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

    def test_versioned_redaction_policy_is_explicit_and_does_not_publish_literals(self):
        with tempfile.TemporaryDirectory() as directory:
            policy = pathlib.Path(directory) / "redactions.json"
            policy.write_text(json.dumps({
                "schema": REDACTION_SCHEMA,
                "literals": ["candidate-private-value", "private"],
            }))
            literals = load_redaction_literals(policy)
        self.assertEqual(literals, ("candidate-private-value", "private"))
        digest = redaction_policy_digest(literals)
        self.assertTrue(digest.startswith("sha256:"))
        self.assertNotIn("private", digest)

    def test_redaction_policy_rejects_unversioned_or_duplicate_literals(self):
        with tempfile.TemporaryDirectory() as directory:
            policy = pathlib.Path(directory) / "redactions.json"
            policy.write_text(json.dumps({"literals": ["private"]}))
            with self.assertRaisesRegex(ValueError, "exactly schema and literals"):
                load_redaction_literals(policy)
            policy.write_text(json.dumps({
                "schema": REDACTION_SCHEMA,
                "literals": ["private", "private"],
            }))
            with self.assertRaisesRegex(ValueError, "unique"):
                load_redaction_literals(policy)


class BaselineAdmissionTests(unittest.TestCase):
    """A provenance declaration never upgrades an unexecuted baseline."""

    @staticmethod
    def digest(letter: str) -> str:
        return "sha256:" + letter * 64

    def owner_inventory(self) -> bytes:
        return (_SUITE / "tasks.json").read_bytes()

    def required_tasks(self) -> list[str]:
        return [task["id"] for task in json.loads(self.owner_inventory())["tasks"]]

    def document(self) -> dict:
        return {
            "schema": ADMISSION_SCHEMA,
            "system": {"id": "zero", "display_name": "Zero"},
            "toolchain": {
                "official_source": "https://github.com/vercel-labs/zerolang",
                "revision": "eb2ed6c22fe3f6e3152efa0c0d05ffcf1ff4a2c7",
                "version": "0.1.0",
                "artifact_sha256": self.digest("a"),
                "installation_receipt_sha256": self.digest("9"),
                "license": "MIT",
            },
            "agent_interface": {
                "version": "2026-09-20",
                "guidance_sha256": self.digest("b"),
                "invocation_contract_sha256": self.digest("c"),
            },
            "model": {"provider": "example-provider", "model": "example-model", "revision": "2026-09-20"},
            "ports": [
                {
                    "task_id": task_id, "port_tree_sha256": self.digest("d"),
                    "oracle_sha256": self.digest("e"), "equivalence_review_sha256": self.digest("f"),
                    "candidate_paths": ["src/candidate.zero"],
                }
                for task_id in self.required_tasks()
            ],
            "execution": {"status": "not_executed"},
        }

    def test_complete_offline_descriptor_stays_unavailable(self):
        decision = admit_baseline_descriptor(self.document(), self.owner_inventory())
        self.assertEqual(decision["status"], "unavailable")
        self.assertEqual(decision["reason"], "offline_admission_is_not_execution_evidence")
        self.assertEqual(decision["provenance"]["system_id"], "zero")
        self.assertEqual(decision["provenance"]["task_ids"], self.required_tasks())
        self.assertEqual(decision["provenance"]["tasks_sha256"], OWNER_TASK_INVENTORY_SHA256)
        self.assertTrue(decision["provenance"]["descriptor_sha256"].startswith("sha256:"))

    def test_descriptor_digest_is_deterministic_over_object_key_order(self):
        document = self.document()
        shuffled = json.loads(json.dumps(document, sort_keys=True, indent=2))
        first = admit_baseline_descriptor(document, self.owner_inventory())
        second = admit_baseline_descriptor(shuffled, self.owner_inventory())
        self.assertEqual(first, second)

    def test_missing_or_extra_required_port_is_refused(self):
        missing = self.document()
        missing["ports"] = missing["ports"][:1]
        self.assertEqual(
            admit_baseline_descriptor(missing, self.owner_inventory())["reason"],
            "ports_do_not_cover_required_tasks",
        )
        extra = self.document()
        extra["ports"].append(extra["ports"][0].copy())
        self.assertEqual(
            admit_baseline_descriptor(extra, self.owner_inventory())["reason"],
            "ports_do_not_cover_required_tasks",
        )

    def test_mutable_or_malformed_immutable_inputs_are_refused(self):
        mutable = self.document()
        mutable["toolchain"]["revision"] = "refs/heads/main"
        self.assertEqual(
            admit_baseline_descriptor(mutable, self.owner_inventory())["reason"],
            "invalid_toolchain_provenance",
        )
        whitespace = self.document()
        whitespace["toolchain"]["revision"] = " eb2ed6c22fe3f6e3152efa0c0d05ffcf1ff4a2c7"
        self.assertEqual(
            admit_baseline_descriptor(whitespace, self.owner_inventory())["reason"],
            "invalid_toolchain_provenance",
        )
        malformed = self.document()
        malformed["agent_interface"]["guidance_sha256"] = "sha256:UPPERCASE"
        self.assertEqual(
            admit_baseline_descriptor(malformed, self.owner_inventory())["reason"],
            "invalid_agent_interface_provenance",
        )

    def test_execution_claim_or_undeclared_field_is_refused(self):
        claimed = self.document()
        claimed["execution"] = {"status": "executed"}
        self.assertEqual(
            admit_baseline_descriptor(claimed, self.owner_inventory())["reason"],
            "execution_evidence_not_admissible_here",
        )
        secret = self.document()
        secret["model"]["api_key"] = "must-not-be-admitted"
        self.assertEqual(
            admit_baseline_descriptor(secret, self.owner_inventory())["reason"],
            "invalid_model_identity",
        )

    def test_order_and_different_task_inventory_are_refused(self):
        reordered = self.document()
        reordered["ports"].reverse()
        self.assertEqual(
            admit_baseline_descriptor(reordered, self.owner_inventory())["reason"],
            "ports_do_not_cover_required_tasks",
        )
        different = self.document()
        different["ports"][1]["task_id"] = "other-task"
        self.assertEqual(
            admit_baseline_descriptor(different, self.owner_inventory())["reason"],
            "ports_do_not_cover_required_tasks",
        )

    def test_detached_or_noncanonical_task_inventory_is_refused(self):
        legacy_pair = {"task_ids": self.required_tasks(), "tasks_sha256": OWNER_TASK_INVENTORY_SHA256}
        self.assertEqual(
            admit_baseline_descriptor(self.document(), legacy_pair)["reason"],
            "invalid_required_task_inventory",
        )
        noncanonical = self.owner_inventory() + b"\n"
        self.assertEqual(
            admit_baseline_descriptor(self.document(), noncanonical)["reason"],
            "invalid_required_task_inventory",
        )

    def test_forged_well_formed_owner_digest_or_task_set_is_refused(self):
        altered_content = json.loads(self.owner_inventory())
        altered_content["tasks"][0]["summary"] = "forged but well-formed task content"
        altered_content_bytes = (json.dumps(altered_content, indent=2, ensure_ascii=True) + "\n").encode("utf-8")
        self.assertEqual(
            admit_baseline_descriptor(self.document(), altered_content_bytes)["reason"],
            "invalid_required_task_inventory",
        )
        forged = json.loads(self.owner_inventory())
        forged["tasks"][0]["id"] = "forged-task-v1"
        forged_bytes = (json.dumps(forged, indent=2, ensure_ascii=True) + "\n").encode("utf-8")
        self.assertEqual(
            admit_baseline_descriptor(self.document(), forged_bytes)["reason"],
            "invalid_required_task_inventory",
        )

    def test_non_string_candidate_path_is_refused_without_raising(self):
        malformed = self.document()
        malformed["ports"][0]["candidate_paths"] = ["src/candidate.zero", 7]
        decision = admit_baseline_descriptor(malformed, self.owner_inventory())
        self.assertEqual(decision["status"], "unavailable")
        self.assertEqual(decision["reason"], "invalid_port_provenance")

    def test_wrong_source_or_near_miss_or_moving_revision_is_refused(self):
        wrong_source = self.document()
        wrong_source["toolchain"]["official_source"] = "https://example.invalid/zerolang"
        self.assertEqual(
            admit_baseline_descriptor(wrong_source, self.owner_inventory())["reason"],
            "toolchain_identity_does_not_match_pinned_baseline",
        )
        near_miss = self.document()
        near_miss["toolchain"]["revision"] = "eb2ed6c22fe3f6e3152efa0c0d05ffcf1ff4a2c8"
        self.assertEqual(
            admit_baseline_descriptor(near_miss, self.owner_inventory())["reason"],
            "toolchain_identity_does_not_match_pinned_baseline",
        )
        moving = self.document()
        moving["toolchain"]["revision"] = "main"
        self.assertEqual(
            admit_baseline_descriptor(moving, self.owner_inventory())["reason"],
            "invalid_toolchain_provenance",
        )

    def test_unknown_or_unpinned_mainstream_system_is_refused(self):
        unknown = self.document()
        unknown["system"] = {"id": "mainstream-agent", "display_name": "Mainstream agent"}
        self.assertEqual(
            admit_baseline_descriptor(unknown, self.owner_inventory())["reason"],
            "baseline_system_not_pinned",
        )

    def test_windows_absolute_candidate_paths_are_refused(self):
        for path in ("C:/candidate.zero", "C:\\candidate.zero", "\\\\server\\share\\candidate.zero", "volume:entry"):
            with self.subTest(path=path):
                malformed = self.document()
                malformed["ports"][0]["candidate_paths"] = [path]
                self.assertEqual(
                    admit_baseline_descriptor(malformed, self.owner_inventory())["reason"],
                    "invalid_port_provenance",
                )


class SpecializationProtocolTests(unittest.TestCase):
    """The #147 preparation artifact is deliberately not an execution path."""

    def protocol(self) -> dict:
        return json.loads(SPECIALIZATION_PROTOCOL.read_text())

    def inventory(self) -> bytes:
        return (_SUITE / "tasks.json").read_bytes()

    def test_canonical_plan_uses_every_held_out_task_and_never_claims_execution(self):
        protocol = self.protocol()
        first = build_plan(protocol, self.inventory())
        second = build_plan(json.loads(canonical_bytes(protocol)), self.inventory())
        self.assertEqual(first, second)
        self.assertEqual(first["schema"], PLAN_SCHEMA)
        self.assertEqual(first["status"], "not_authorized")
        self.assertEqual(first["execution"], "not_attempted")
        self.assertEqual(first["metrics"], list(REQUIRED_METRICS))
        held_out = [
            task["id"] for task in json.loads(self.inventory())["tasks"]
            if task["split"] == "held_out" and "semaprax-project" in task["languages"]
        ]
        self.assertEqual(
            [(row["variant"], row["task"], row["trial"]) for row in first["rows"]],
            [
                (variant, task, trial)
                for variant in ("base", "guided", "constrained")
                for task in held_out
                for trial in range(1, 4)
            ],
        )
        self.assertTrue(all(row["split"] == "held_out" for row in first["rows"]))
        self.assertTrue(all(row["execution"] == "not_attempted" for row in first["rows"]))

    def test_controls_cannot_change_model_budget_or_oracle(self):
        protocol = self.protocol()
        protocol["variants"][1]["model"]["revision"] = "different-model-snapshot"
        with self.assertRaisesRegex(ProtocolError, "base model identity"):
            build_plan(protocol, self.inventory())

        protocol = self.protocol()
        protocol["resource_policy"]["max_total_tokens"] = 47_999
        with self.assertRaisesRegex(ProtocolError, "max_total_tokens"):
            build_plan(protocol, self.inventory())

        protocol = self.protocol()
        protocol["variants"][2]["guidance"]["sha256"] = "sha256:" + "0" * 64
        with self.assertRaisesRegex(ProtocolError, "same guidance bytes"):
            build_plan(protocol, self.inventory())

    def test_adaptation_is_optional_but_cannot_train_on_held_out_tasks(self):
        protocol = self.protocol()
        adapted = {
            "id": "adapted",
            "model": protocol["base_model"].copy(),
            "guidance": protocol["variants"][2]["guidance"].copy(),
            "action_constraint": protocol["variants"][2]["action_constraint"].copy(),
            "adaptation": {
                "status": "proposed",
                "dataset_manifest_sha256": "sha256:" + "a" * 64,
                "task_ids": ["bounded-counter-repair-v1"],
            },
        }
        protocol["variants"].append(adapted)
        with self.assertRaisesRegex(ProtocolError, "development tasks"):
            build_plan(protocol, self.inventory())

        adapted["adaptation"]["task_ids"] = ["sequence-digest-v1"]
        plan = build_plan(protocol, self.inventory())
        self.assertEqual(plan["variants"][-1]["adaptation"]["status"], "proposed")
        self.assertEqual(plan["variants"][-1]["adaptation"]["task_ids"], ["sequence-digest-v1"])

    def test_protocol_requires_the_full_measurement_inventory_and_explicit_authorization(self):
        protocol = self.protocol()
        protocol["metrics"] = protocol["metrics"][:-1]
        with self.assertRaisesRegex(ProtocolError, "metric inventory"):
            build_plan(protocol, self.inventory())

        protocol = self.protocol()
        protocol["authorization"]["status"] = "approved"
        with self.assertRaisesRegex(ProtocolError, "not_authorized"):
            build_plan(protocol, self.inventory())


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


class EvidenceAndCandidateBoundaryTests(unittest.TestCase):
    """A transport's evidence is complete or explicitly redacted, and it
    cannot rewrite a scaffold/test path while being scored."""

    def test_redacted_evidence_retains_all_transcript_and_candidate_artifacts(self):
        task, adapter = real_task_and_adapter()
        record = evaluate_agent_pair(
            repo_root(), task, "rust", adapter, ReplayTransport(FIXTURE_OK), real_request(),
            candidate_paths=["candidate.rs"],
            redactions=("transient 503", "pub fn validate"),
        )
        self.assertEqual(record["status"], "ok", record)
        self.assertEqual(len(record["transcript"]), 4)
        self.assertTrue(all("content" in row and "content_digest" in row for row in record["transcript"]))
        self.assertTrue(any(row["redacted"] for row in record["transcript"]))
        self.assertNotIn("transient 503", json.dumps(record))
        artifacts = record["evidence"]["candidate_artifacts"]
        self.assertEqual([row["path"] for row in artifacts], ["candidate.rs"])
        self.assertTrue(artifacts[0]["redacted"])
        self.assertNotIn("pub fn validate", artifacts[0]["content"])
        self.assertTrue(artifacts[0]["content_digest"].startswith("sha256:"))
        self.assertEqual(
            record["evidence"]["redaction_policy_digest"],
            redaction_policy_digest(("transient 503", "pub fn validate")),
        )

    def test_extra_or_traversal_candidate_paths_are_refused_before_any_scoring_write(self):
        task, adapter = real_task_and_adapter()
        with tempfile.TemporaryDirectory() as directory:
            fixture = write_fixture(pathlib.Path(directory), [
                {
                    "attempt": 1,
                    "kind": "final",
                    "prompt_tokens": 1,
                    "completion_tokens": 1,
                    "cost_usd": 0.0,
                    "response_text": "unexpected file",
                    "candidate_files": {
                        "candidate.rs": "pub fn validate() {}\n",
                        "../escape.rs": "must never be written\n",
                    },
                },
            ])
            record = evaluate_agent_pair(
                repo_root(), task, "rust", adapter, ReplayTransport(fixture), real_request(),
                candidate_paths=["candidate.rs"],
            )
        self.assertEqual(record["status"], "failed")
        self.assertIn("invalid transport candidate artifacts", record["reason"])
        self.assertIn("../escape.rs", record["reason"])
        self.assertNotIn("candidate_artifacts", record["evidence"])
        self.assertNotIn("public", record)
        self.assertNotIn("hidden", record)

    def test_extra_declared_regular_path_is_refused_before_scoring(self):
        task, adapter = real_task_and_adapter()
        with tempfile.TemporaryDirectory() as directory:
            fixture = write_fixture(pathlib.Path(directory), [
                {
                    "attempt": 1,
                    "kind": "final",
                    "prompt_tokens": 1,
                    "completion_tokens": 1,
                    "cost_usd": 0.0,
                    "response_text": "extra scaffold replacement",
                    "candidate_files": {
                        "candidate.rs": "pub fn validate() {}\n",
                        "main.rs": "fn main() {}\n",
                    },
                },
            ])
            record = evaluate_agent_pair(
                repo_root(), task, "rust", adapter, ReplayTransport(fixture), real_request(),
                candidate_paths=["candidate.rs"],
            )
        self.assertEqual(record["status"], "failed")
        self.assertEqual(
            record["reason"],
            "transport candidate paths mismatch: missing=[]; unexpected=['main.rs']",
        )
        self.assertNotIn("candidate_artifacts", record["evidence"])

    def test_empty_or_platform_root_candidate_declaration_is_refused_before_scoring(self):
        task, adapter = real_task_and_adapter()
        transport = ReplayTransport(FIXTURE_OK)
        empty = evaluate_agent_pair(
            repo_root(), task, "rust", adapter, transport, real_request(), candidate_paths=[],
        )
        self.assertEqual(empty["status"], "failed")
        self.assertEqual(empty["reason"], "at least one candidate path must be declared")

        platform_path = evaluate_agent_pair(
            repo_root(), task, "rust", adapter, transport, real_request(), candidate_paths=["C:escape.rs"],
        )
        self.assertEqual(platform_path["status"], "failed")
        self.assertIn("platform-specific root", platform_path["reason"])


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
