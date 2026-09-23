#!/usr/bin/env python3
"""Focused, offline regressions for runnable-adapter v1."""
from __future__ import annotations

import hashlib
import importlib.util
import json
import pathlib
import tempfile
import unittest


SUITE = pathlib.Path(__file__).resolve().parent
MODULE_SPEC = importlib.util.spec_from_file_location("runnable_adapter", SUITE / "runnable_adapter.py")
assert MODULE_SPEC and MODULE_SPEC.loader
RUNNABLE = importlib.util.module_from_spec(MODULE_SPEC)
MODULE_SPEC.loader.exec_module(RUNNABLE)


def canonical(value: object) -> bytes:
    return (json.dumps(value, indent=2, ensure_ascii=True) + "\n").encode("utf-8")


def digest(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


class RunnableAdapterTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tasks = (SUITE / "tasks.json").read_bytes()
        self.adapters = (SUITE / "adapters.json").read_bytes()

    def baseline(self) -> dict:
        task_ids = [row["id"] for row in json.loads(self.tasks)["tasks"]]
        return {
            "schema": "benchmark.cross_language.agent.baseline_admission.v1",
            "system": {"id": "zero", "display_name": "Zero"},
            "toolchain": {
                "official_source": "https://github.com/vercel-labs/zerolang",
                "revision": "eb2ed6c22fe3f6e3152efa0c0d05ffcf1ff4a2c7",
                "version": "fixture-only",
                "artifact_sha256": digest(b"fixture artifact"),
                "installation_receipt_sha256": digest(b"fixture install receipt"),
                "license": "fixture-only",
            },
            "agent_interface": {
                "version": "fixture-v1",
                "guidance_sha256": digest(b"fixture guidance"),
                "invocation_contract_sha256": digest(b"fixture contract"),
            },
            "model": {"provider": "fixture", "model": "fixture", "revision": "fixture-v1"},
            "ports": [{
                "task_id": task_id,
                "port_tree_sha256": digest(f"port:{task_id}".encode()),
                "oracle_sha256": digest(f"oracle:{task_id}".encode()),
                "equivalence_review_sha256": digest(f"review:{task_id}".encode()),
                "candidate_paths": ["src/candidate.zero"],
            } for task_id in task_ids],
            "execution": {"status": "not_executed"},
        }

    def descriptor(self) -> bytes:
        receipt = "local Rust fixture; execution is not an external-language result"
        return canonical({
            "schema": RUNNABLE.SCHEMA,
            "baseline": self.baseline(),
            "execution": {
                "classification": "local_fixture",
                "adapter_id": "rust",
                "task_id": "sequence-digest-v1",
                "adapter_inventory_sha256": digest(self.adapters),
                "receipt": receipt,
                "receipt_sha256": digest(receipt.encode()),
                "timeout_seconds": 120,
            },
        })

    def test_local_rust_fixture_replays_the_existing_public_hidden_scorer(self) -> None:
        result = RUNNABLE.execute_local_fixture(self.descriptor(), self.tasks, self.adapters, RUNNABLE.ROOT)
        self.assertEqual(result["status"], "fixture_ok", result)
        self.assertEqual(result["classification"], "local_fixture")
        self.assertEqual(result["result"]["id"], "sequence-digest-v1::rust")
        self.assertEqual(result["result"]["leak_check"], "ok")
        self.assertTrue(result["result"]["public"]["passed"])
        self.assertTrue(result["result"]["hidden"]["passed"])

    def test_mutation_and_external_claims_refuse_before_execution(self) -> None:
        descriptor = json.loads(self.descriptor())
        descriptor["execution"]["adapter_inventory_sha256"] = digest(b"wrong")
        self.assertEqual(
            RUNNABLE.admit_runnable_descriptor(canonical(descriptor), self.tasks, self.adapters)["reason"],
            "adapter_inventory_drifted",
        )
        descriptor = json.loads(self.descriptor())
        descriptor["execution"]["receipt"] = "tampered"
        self.assertEqual(
            RUNNABLE.admit_runnable_descriptor(canonical(descriptor), self.tasks, self.adapters)["reason"],
            "execution_receipt_digest_disagrees",
        )
        descriptor = json.loads(self.descriptor())
        descriptor["execution"]["classification"] = "external"
        self.assertEqual(
            RUNNABLE.admit_runnable_descriptor(canonical(descriptor), self.tasks, self.adapters)["reason"],
            "external_execution_requires_provisioned_review",
        )
        self.assertEqual(
            RUNNABLE.admit_runnable_descriptor(self.descriptor() + b" ", self.tasks, self.adapters)["reason"],
            "invalid_runnable_descriptor",
        )
        self.assertEqual(
            RUNNABLE.execute_local_fixture(self.descriptor(), self.tasks + b" ", self.adapters, RUNNABLE.ROOT)["reason"],
            "invalid_required_task_inventory",
        )
        with tempfile.TemporaryDirectory(prefix="spx-runnable-root-") as temporary:
            self.assertEqual(
                RUNNABLE.execute_local_fixture(self.descriptor(), self.tasks, self.adapters, pathlib.Path(temporary))["reason"],
                "execution_inputs_drifted",
            )

    def test_scoring_inventory_retains_every_blocked_adapter(self) -> None:
        with tempfile.TemporaryDirectory(prefix="spx-runnable-plan-") as temporary:
            output = pathlib.Path(temporary) / "plan.json"
            completed = RUNNABLE.subprocess.run([
                RUNNABLE.sys.executable, str(RUNNABLE.RUNNER), "--dry-run",
                "--root", str(RUNNABLE.ROOT), "--tasks", str(RUNNABLE.TASKS),
                "--adapters", str(RUNNABLE.ADAPTERS), "--output", str(output),
            ], capture_output=True, text=True, timeout=120, check=False)
            self.assertEqual(completed.returncode, 0, completed.stderr)
            plan = json.loads(output.read_text())
        self.assertEqual(len(plan["pairs"]), 120)
        by_language = {}
        for pair in plan["pairs"]:
            by_language[pair["language"]] = by_language.get(pair["language"], 0) + 1
        for language in ("zero", "ntnt", "aver", "vera", "hale", "moonbit"):
            self.assertEqual(by_language.get(language), 12)
            self.assertFalse(any(pair["language"] == language and pair["implemented"] for pair in plan["pairs"]))


if __name__ == "__main__":
    unittest.main()
