#!/usr/bin/env python3
"""Offline regression tests for `generated-package-release.py` (issue #145).

Run directly:

    python3 scripts/test-generated-package-release.py

Exercises the two highest-value classes the release-automation testing
standard names: a determinism test (same input package directory ->
byte-identical prepared output) and refusal tests (the tool refuses rather
than proceeding when a required safety input is violated -- a live publish
credential present, a secret- or local-path-shaped byte, an inexact
inventory, or an attempted `--publish`). It also covers tamper detection
between `prepare` and `check`, and -- only when a real `npm`/`cargo` binary
is available on this machine -- the real dry-run tool invocations.
"""

import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def _load(name, relative_path):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative_path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


gpr = _load("semaprax_generated_package_release", "scripts/generated-package-release.py")


def scratch_dir():
    directory = Path(tempfile.mkdtemp(prefix="semaprax-generated-package-release-"))
    return directory


class NpmFixtureMixin:
    def npm_package_dir(self, root):
        package_dir = root / "npm-package"
        package_dir.mkdir()
        package_json = {
            "name": "frame-payload",
            "version": "0.1.0",
            "type": "module",
            "sideEffects": False,
            "exports": {
                ".": {"types": "./semaprax.bindings.d.ts", "import": "./semaprax.bindings.js"},
                "./app.wasm": "./app.wasm",
                "./manifest": "./semaprax.api.json",
            },
            "types": "./semaprax.bindings.d.ts",
            "files": ["app.wasm", "semaprax.js", "semaprax.bindings.js", "semaprax.bindings.d.ts", "semaprax.api.json"],
            "engines": {"node": ">=22"},
        }
        (package_dir / "package.json").write_text(json.dumps(package_json) + "\n", encoding="utf-8")
        (package_dir / "app.wasm").write_bytes(b"\0asm" + b"\x01\x02\x03")
        (package_dir / "semaprax.js").write_text("export const semaprax = {};\n", encoding="utf-8")
        (package_dir / "semaprax.bindings.js").write_text("export function call() {}\n", encoding="utf-8")
        (package_dir / "semaprax.bindings.d.ts").write_text("export declare function call(): void;\n", encoding="utf-8")
        (package_dir / "semaprax.api.json").write_text(
            json.dumps({"schema": "semaprax.public-owned-data-api.v1", "exports": []}) + "\n",
            encoding="utf-8",
        )
        return package_dir


class RustFixtureMixin:
    def rust_package_dir(self, root):
        package_dir = root / "rust-package"
        package_dir.mkdir()
        (package_dir / "Cargo.toml").write_text(
            '[package]\nname = "semaprax_generated_native_rust_owned_data_sdk"\n'
            'version = "0.1.0"\nedition = "2021"\nrust-version = "1.85"\n'
            'publish = false\nbuild = "build.rs"\n\n[lib]\npath = "lib.rs"\n\n[workspace]\n',
            encoding="utf-8",
        )
        (package_dir / "build.rs").write_text("fn main() {}\n", encoding="utf-8")
        (package_dir / "lib.rs").write_text("// generated\n", encoding="utf-8")
        (package_dir / "owned_data_ffi.rs").write_text("// ffi\n", encoding="utf-8")
        (package_dir / "libsemaprax_native_rust_owned_data_sdk.a").write_bytes(b"\x7fELFfakearchive")
        (package_dir / "descriptor.json").write_text(
            json.dumps({"schema": "semaprax.public-owned-data-api.v1", "exports": []}) + "\n",
            encoding="utf-8",
        )
        (package_dir / "semaprax.native-rust-owned-data-sdk.json").write_text(
            json.dumps({"schema": "semaprax.native-rust-owned-data-sdk.v1"}) + "\n",
            encoding="utf-8",
        )
        return package_dir


class PrepareDeterminismTests(NpmFixtureMixin, RustFixtureMixin, unittest.TestCase):
    """Determinism test: `prepare` on identical input produces identical output."""

    def test_npm_prepare_is_byte_identical_across_two_runs(self):
        root = scratch_dir()
        self.addCleanup(shutil.rmtree, root, ignore_errors=True)
        package_dir = self.npm_package_dir(root)
        first = root / "first"
        second = root / "second"
        gpr.prepare("npm", package_dir, "frame-payload", "0.1.0", "a" * 40, first)
        gpr.prepare("npm", package_dir, "frame-payload", "0.1.0", "a" * 40, second)
        self.assert_trees_identical(first, second)

    def test_rust_prepare_is_byte_identical_across_two_runs(self):
        root = scratch_dir()
        self.addCleanup(shutil.rmtree, root, ignore_errors=True)
        package_dir = self.rust_package_dir(root)
        first = root / "first"
        second = root / "second"
        gpr.prepare("rust", package_dir, "frame-payload", "0.1.0", "a" * 40, first)
        gpr.prepare("rust", package_dir, "frame-payload", "0.1.0", "a" * 40, second)
        self.assert_trees_identical(first, second)

    def assert_trees_identical(self, first, second):
        first_files = sorted(str(path.relative_to(first)) for path in first.rglob("*") if path.is_file())
        second_files = sorted(str(path.relative_to(second)) for path in second.rglob("*") if path.is_file())
        self.assertEqual(first_files, second_files)
        for relative in first_files:
            self.assertEqual(
                (first / relative).read_bytes(),
                (second / relative).read_bytes(),
                f"{relative} differs between two prepare runs of the same input",
            )


class PrepareRefusalTests(NpmFixtureMixin, RustFixtureMixin, unittest.TestCase):
    """Refusal tests: `prepare` fails closed on every named hazard."""

    def setUp(self):
        self.root = scratch_dir()
        self.addCleanup(shutil.rmtree, self.root, ignore_errors=True)

    def test_refuses_with_a_live_publish_credential_present(self):
        package_dir = self.npm_package_dir(self.root)
        old = os.environ.get("NPM_TOKEN")
        os.environ["NPM_TOKEN"] = "fake-token-value"
        try:
            with self.assertRaises(gpr.Rejected):
                gpr.prepare("npm", package_dir, "frame-payload", "0.1.0", None, self.root / "out")
        finally:
            if old is None:
                del os.environ["NPM_TOKEN"]
            else:
                os.environ["NPM_TOKEN"] = old

    def test_refuses_a_secret_shaped_byte_in_any_file(self):
        package_dir = self.rust_package_dir(self.root)
        (package_dir / "lib.rs").write_text(
            "// ghp_" + ("a" * 36) + "\n", encoding="utf-8"
        )
        with self.assertRaises(gpr.Rejected):
            gpr.prepare("rust", package_dir, "frame-payload", "0.1.0", None, self.root / "out")

    def test_refuses_a_local_host_path_leaked_into_a_file(self):
        package_dir = self.npm_package_dir(self.root)
        (package_dir / "semaprax.js").write_text(
            f"// built from {package_dir}\n", encoding="utf-8"
        )
        with self.assertRaises(gpr.Rejected):
            gpr.prepare("npm", package_dir, "frame-payload", "0.1.0", None, self.root / "out")

    def test_refuses_an_extra_unexpected_file(self):
        package_dir = self.npm_package_dir(self.root)
        (package_dir / "node_modules_cache.bin").write_bytes(b"cache")
        with self.assertRaises(gpr.Rejected):
            gpr.prepare("npm", package_dir, "frame-payload", "0.1.0", None, self.root / "out")

    def test_refuses_a_missing_file(self):
        package_dir = self.npm_package_dir(self.root)
        (package_dir / "app.wasm").unlink()
        with self.assertRaises(gpr.Rejected):
            gpr.prepare("npm", package_dir, "frame-payload", "0.1.0", None, self.root / "out")

    def test_refuses_a_rust_manifest_without_publish_false(self):
        package_dir = self.rust_package_dir(self.root)
        text = (package_dir / "Cargo.toml").read_text(encoding="utf-8")
        (package_dir / "Cargo.toml").write_text(text.replace("publish = false\n", ""), encoding="utf-8")
        with self.assertRaises(gpr.Rejected):
            gpr.prepare("rust", package_dir, "frame-payload", "0.1.0", None, self.root / "out")

    def test_refuses_a_rust_manifest_with_a_dependencies_table(self):
        package_dir = self.rust_package_dir(self.root)
        text = (package_dir / "Cargo.toml").read_text(encoding="utf-8")
        (package_dir / "Cargo.toml").write_text(text + "\n[dependencies]\n", encoding="utf-8")
        with self.assertRaises(gpr.Rejected):
            gpr.prepare("rust", package_dir, "frame-payload", "0.1.0", None, self.root / "out")

    def test_refuses_an_npm_package_json_with_a_forbidden_key(self):
        package_dir = self.npm_package_dir(self.root)
        parsed = json.loads((package_dir / "package.json").read_text(encoding="utf-8"))
        parsed["dependencies"] = {"left-pad": "^1.0.0"}
        (package_dir / "package.json").write_text(json.dumps(parsed), encoding="utf-8")
        with self.assertRaises(gpr.Rejected):
            gpr.prepare("npm", package_dir, "frame-payload", "0.1.0", None, self.root / "out")

    def test_refuses_a_subdirectory_in_the_package(self):
        package_dir = self.npm_package_dir(self.root)
        (package_dir / "nested").mkdir()
        with self.assertRaises(gpr.Rejected):
            gpr.prepare("npm", package_dir, "frame-payload", "0.1.0", None, self.root / "out")


class CheckTests(NpmFixtureMixin, RustFixtureMixin, unittest.TestCase):
    def setUp(self):
        self.root = scratch_dir()
        self.addCleanup(shutil.rmtree, self.root, ignore_errors=True)

    def test_publish_flag_is_always_refused(self):
        package_dir = self.npm_package_dir(self.root)
        prepared = self.root / "prepared"
        gpr.prepare("npm", package_dir, "frame-payload", "0.1.0", None, prepared)
        with self.assertRaises(gpr.Rejected):
            gpr.check("npm", prepared, publish=True)

    def test_publish_flag_is_refused_even_with_a_credential_absent_and_clean_state(self):
        # Refusal test required by the testing standard: this tool refuses to
        # proceed toward a live publish no matter how clean the input is,
        # because it implements no live-publish path at all.
        package_dir = self.rust_package_dir(self.root)
        prepared = self.root / "prepared"
        gpr.prepare("rust", package_dir, "frame-payload", "0.1.0", None, prepared)
        with self.assertRaises(gpr.Rejected):
            gpr.check("rust", prepared, publish=True)

    def test_clean_dry_run_check_succeeds_without_any_tool(self):
        package_dir = self.npm_package_dir(self.root)
        prepared = self.root / "prepared"
        gpr.prepare("npm", package_dir, "frame-payload", "0.1.0", None, prepared)
        report = gpr.check("npm", prepared, publish=False)
        self.assertTrue(any("skipped" in line for line in report))

    def test_tampered_payload_file_is_detected(self):
        package_dir = self.npm_package_dir(self.root)
        prepared = self.root / "prepared"
        gpr.prepare("npm", package_dir, "frame-payload", "0.1.0", None, prepared)
        (prepared / "payload" / "semaprax.js").write_text("export const tampered = true;\n", encoding="utf-8")
        with self.assertRaises(gpr.Rejected):
            gpr.check("npm", prepared, publish=False)

    def test_tampered_readme_is_detected(self):
        package_dir = self.rust_package_dir(self.root)
        prepared = self.root / "prepared"
        gpr.prepare("rust", package_dir, "frame-payload", "0.1.0", None, prepared)
        (prepared / "README.md").write_text("tampered\n", encoding="utf-8")
        with self.assertRaises(gpr.Rejected):
            gpr.check("rust", prepared, publish=False)

    def test_check_refuses_with_a_live_publish_credential_present(self):
        package_dir = self.npm_package_dir(self.root)
        prepared = self.root / "prepared"
        gpr.prepare("npm", package_dir, "frame-payload", "0.1.0", None, prepared)
        old = os.environ.get("CARGO_REGISTRY_TOKEN")
        os.environ["CARGO_REGISTRY_TOKEN"] = "fake-token-value"
        try:
            with self.assertRaises(gpr.Rejected):
                gpr.check("npm", prepared, publish=False)
        finally:
            if old is None:
                del os.environ["CARGO_REGISTRY_TOKEN"]
            else:
                os.environ["CARGO_REGISTRY_TOKEN"] = old

    @unittest.skipUnless(shutil.which("npm"), "npm is not installed on this machine")
    def test_real_npm_pack_dry_run_succeeds_and_writes_nothing(self):
        package_dir = self.npm_package_dir(self.root)
        prepared = self.root / "prepared"
        gpr.prepare("npm", package_dir, "frame-payload", "0.1.0", None, prepared)
        before = sorted(p.name for p in (prepared / "payload").iterdir())
        report = gpr.check("npm", prepared, publish=False, npm_bin=Path(shutil.which("npm")))
        after = sorted(p.name for p in (prepared / "payload").iterdir())
        self.assertEqual(before, after, "npm pack --dry-run must not write a tarball to disk")
        self.assertTrue(any("dry-run succeeded" in line for line in report))

    @unittest.skipUnless(shutil.which("cargo"), "cargo is not installed on this machine")
    def test_real_cargo_publish_dry_run_is_refused_by_cargo_itself(self):
        package_dir = self.rust_package_dir(self.root)
        prepared = self.root / "prepared"
        gpr.prepare("rust", package_dir, "frame-payload", "0.1.0", None, prepared)
        report = gpr.check("rust", prepared, publish=False, cargo_bin=Path(shutil.which("cargo")))
        self.assertTrue(any("independently refused" in line for line in report))


class CliEndToEndTests(NpmFixtureMixin, unittest.TestCase):
    def setUp(self):
        self.root = scratch_dir()
        self.addCleanup(shutil.rmtree, self.root, ignore_errors=True)

    def run_cli(self, *args):
        return subprocess.run(
            [sys.executable, str(ROOT / "scripts" / "generated-package-release.py"), *args],
            capture_output=True,
            text=True,
        )

    def test_cli_prepare_then_check_succeeds(self):
        package_dir = self.npm_package_dir(self.root)
        prepared = self.root / "prepared"
        result = self.run_cli(
            "prepare",
            "--kind", "npm",
            "--package-dir", str(package_dir),
            "--project-name", "frame-payload",
            "--project-version", "0.1.0",
            "--output", str(prepared),
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        result = self.run_cli("check", "--kind", "npm", "--prepared-dir", str(prepared))
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_cli_check_publish_flag_exits_nonzero(self):
        package_dir = self.npm_package_dir(self.root)
        prepared = self.root / "prepared"
        self.run_cli(
            "prepare",
            "--kind", "npm",
            "--package-dir", str(package_dir),
            "--project-name", "frame-payload",
            "--project-version", "0.1.0",
            "--output", str(prepared),
        )
        result = self.run_cli("check", "--kind", "npm", "--prepared-dir", str(prepared), "--publish")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("rejected", result.stderr)


if __name__ == "__main__":
    unittest.main()
