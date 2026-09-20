#!/usr/bin/env python3
"""Focused regression tests for the non-executing reproduction capsule."""

from __future__ import annotations

import importlib.util
import json
import pathlib
import tempfile
import unittest
from unittest import mock


MODULE = pathlib.Path(__file__).with_name("reproduction_capsule.py")
SPEC = importlib.util.spec_from_file_location("reproduction_capsule", MODULE)
assert SPEC and SPEC.loader
CAPSULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CAPSULE)


def canonical(value):
    return (json.dumps(value, indent=2, ensure_ascii=True) + "\n").encode()


def inventory():
    task_id = "repair-v1"
    tasks = {
        "schema": "benchmark.cross_language.tasks.v1",
        "tasks": [{
            "id": task_id, "category": "repair", "issue_211_category": "failure recovery",
            "split": "held_out", "summary": "repair exactly one deterministic fixture",
            "equivalence": f"tasks/{task_id}/EQUIVALENCE.md",
            "languages": {"rust": {
                "public": f"benchmarks/cross-language-v1/tasks/{task_id}/public/rust",
                "hidden": f"benchmarks/cross-language-v1/tasks/{task_id}/hidden/rust",
            }},
        }],
    }
    adapters = {
        "schema": "benchmark.cross_language.adapters.v1",
        "adapters": [{
            "id": "rust", "language": "Rust", "implemented": True,
            "official_workflow": "offline fixture only", "version_command": ["rustc", "--version"],
            "entry_file": "main.rs", "run_command": ["./test_bin"],
            "success": {"kind": "exit_code_zero"},
        }],
    }
    return canonical(tasks), canonical(adapters)


class ReproductionCapsuleTests(unittest.TestCase):
    def fixture_root(self):
        temp = tempfile.TemporaryDirectory()
        root = pathlib.Path(temp.name)
        task = root / "benchmarks/cross-language-v1/tasks/repair-v1"
        (task / "public/rust").mkdir(parents=True)
        (task / "hidden/rust").mkdir(parents=True)
        (task / "EQUIVALENCE.md").write_text("same observable result\n")
        (task / "public/rust/main.rs").write_text("fn main() {}\n")
        (task / "hidden/rust/test.rs").write_text("#[test] fn hidden() {}\n")
        return temp, root, *inventory()

    def test_deterministic_closed_input_capsule_and_explicit_nonclaim(self):
        temp, root, tasks, adapters = self.fixture_root()
        with temp:
            first = CAPSULE.build_capsule(root, tasks, adapters)
            second = CAPSULE.build_capsule(root, tasks, adapters)
            self.assertEqual(first, second)
            document = json.loads(first)
            self.assertEqual(document["execution"], "not_attempted")
            self.assertEqual(document["inventory"]["task_ids"], ["repair-v1"])
            self.assertEqual(document["pairs"], sorted(document["pairs"], key=lambda pair: pair["id"]))
            self.assertEqual(
                CAPSULE.verify_capsule(first, root, tasks, adapters),
                {"status": "inputs_match", "reason": "no_execution_performed", "execution": "not_attempted"},
            )

    def test_mutated_scoring_inputs_are_unavailable_not_a_result(self):
        temp, root, tasks, adapters = self.fixture_root()
        with temp:
            capsule = CAPSULE.build_capsule(root, tasks, adapters)
            path = root / "benchmarks/cross-language-v1/tasks/repair-v1/public/rust/main.rs"
            path.write_text("fn main() { panic!(); }\n")
            self.assertEqual(
                CAPSULE.verify_capsule(capsule, root, tasks, adapters)["reason"],
                "scoring_inputs_drifted",
            )
            self.assertEqual(
                CAPSULE.verify_capsule(capsule[:-1] + b" ", root, tasks, adapters)["reason"],
                "invalid_capsule",
            )

    def test_exact_owner_bytes_are_bound_even_when_json_meaning_is_unchanged(self):
        temp, root, tasks, adapters = self.fixture_root()
        with temp:
            capsule = CAPSULE.build_capsule(root, tasks, adapters)
            self.assertEqual(
                CAPSULE.verify_capsule(capsule, root, tasks + b"\n", adapters)["reason"],
                "scoring_inputs_drifted",
            )

    def test_empty_directory_is_a_bound_scoring_input(self):
        temp, root, tasks, adapters = self.fixture_root()
        with temp:
            capsule = CAPSULE.build_capsule(root, tasks, adapters)
            (root / "benchmarks/cross-language-v1/tasks/repair-v1/hidden/rust/empty").mkdir()
            self.assertEqual(
                CAPSULE.verify_capsule(capsule, root, tasks, adapters)["reason"],
                "scoring_inputs_drifted",
            )

    def test_rejects_deterministic_path_swap_during_descriptor_read(self):
        temp, root, tasks, adapters = self.fixture_root()
        with temp:
            if not CAPSULE._descriptor_traversal_available():
                self.skipTest("host lacks descriptor-relative no-follow traversal")
            target = root / "benchmarks/cross-language-v1/tasks/repair-v1/public/rust/main.rs"
            replacement = target.with_name("replacement.rs")
            replacement.write_text("fn main() { panic!(); }\n")
            original_open = CAPSULE.os.open

            def swap_then_open(path, *args, **kwargs):
                if path == "main.rs" and kwargs.get("dir_fd") is not None:
                    replacement.replace(target)
                return original_open(path, *args, **kwargs)

            with mock.patch.object(CAPSULE.os, "open", swap_then_open):
                with self.assertRaisesRegex(CAPSULE.CapsuleError, "scoring_input_changed_during_read"):
                    CAPSULE.build_capsule(root, tasks, adapters)

    def test_rejects_ancestor_swap_before_any_external_tree_can_be_read(self):
        """A former pathname walk could follow this replacement directory."""
        temp, root, tasks, adapters = self.fixture_root()
        with temp:
            if not CAPSULE._descriptor_traversal_available():
                self.skipTest("host lacks descriptor-relative no-follow traversal")
            public = root / "benchmarks/cross-language-v1/tasks/repair-v1/public"
            held_public = public.with_name("public-held")
            outside = root / "outside"
            (outside / "rust").mkdir(parents=True)
            (outside / "rust/main.rs").write_text("fn main() { /* external */ }\n")
            original_open = CAPSULE.os.open

            def swap_ancestor_then_open(path, *args, **kwargs):
                if path == "public" and kwargs.get("dir_fd") is not None and public.exists():
                    public.replace(held_public)
                    public.symlink_to(outside, target_is_directory=True)
                return original_open(path, *args, **kwargs)

            with mock.patch.object(CAPSULE.os, "open", swap_ancestor_then_open):
                with self.assertRaisesRegex(CAPSULE.CapsuleError, "scoring_input_changed_during_read"):
                    CAPSULE.build_capsule(root, tasks, adapters)

    def test_closes_public_descriptor_when_hidden_open_refuses(self):
        temp, root, tasks, adapters = self.fixture_root()
        with temp:
            original_open_relative = CAPSULE._open_directory_relative
            original_close = CAPSULE.os.close
            public_descriptor = None
            closed = []

            def open_then_refuse(root_descriptor, relative):
                nonlocal public_descriptor
                if relative.endswith("/hidden/rust"):
                    raise CAPSULE.CapsuleError("scoring_input_changed_during_read")
                descriptor = original_open_relative(root_descriptor, relative)
                if relative.endswith("/public/rust"):
                    public_descriptor = descriptor
                return descriptor

            def recording_close(descriptor):
                closed.append(descriptor)
                return original_close(descriptor)

            with mock.patch.object(CAPSULE, "_open_directory_relative", open_then_refuse), \
                    mock.patch.object(CAPSULE.os, "close", recording_close):
                with self.assertRaisesRegex(CAPSULE.CapsuleError, "scoring_input_changed_during_read"):
                    CAPSULE.build_capsule(root, tasks, adapters)
            self.assertIsNotNone(public_descriptor)
            self.assertIn(public_descriptor, closed)

    def test_descriptor_read_errors_have_a_stable_unavailable_reason(self):
        temp, root, tasks, adapters = self.fixture_root()
        with temp:
            capsule = CAPSULE.build_capsule(root, tasks, adapters)
            with mock.patch.object(CAPSULE.os, "read", side_effect=OSError("host-specific detail")):
                self.assertEqual(
                    CAPSULE.verify_capsule(capsule, root, tasks, adapters)["reason"],
                    "scoring_input_changed_during_read",
                )

    def test_rejects_extra_stdout_success_field(self):
        temp, root, tasks, adapters = self.fixture_root()
        with temp:
            document = json.loads(adapters)
            document["adapters"][0]["success"] = {
                "kind": "stdout_equals", "value": "0", "unexpected": "field",
            }
            with self.assertRaisesRegex(CAPSULE.CapsuleError, "invalid_implemented_adapter"):
                CAPSULE.build_capsule(root, tasks, canonical(document))

    def test_rejects_malformed_and_unsafe_owner_inventory(self):
        temp, root, tasks, adapters = self.fixture_root()
        with temp:
            with self.assertRaisesRegex(CAPSULE.CapsuleError, "invalid_tasks_json"):
                CAPSULE.build_capsule(root, b"{", adapters)
            document = json.loads(tasks)
            document["tasks"][0]["languages"]["rust"]["public"] = "C:/escape"
            with self.assertRaisesRegex(CAPSULE.CapsuleError, "unsafe_task_path"):
                CAPSULE.build_capsule(root, canonical(document), adapters)

    def test_rejects_symlink_in_scoring_closure(self):
        temp, root, tasks, adapters = self.fixture_root()
        with temp:
            public = root / "benchmarks/cross-language-v1/tasks/repair-v1/public/rust"
            try:
                (public / "escape").symlink_to(root / "outside")
            except (NotImplementedError, OSError):
                self.skipTest("host does not permit symlink fixtures")
            with self.assertRaisesRegex(CAPSULE.CapsuleError, "unsafe_scoring_tree"):
                CAPSULE.build_capsule(root, tasks, adapters)


if __name__ == "__main__":
    unittest.main()
