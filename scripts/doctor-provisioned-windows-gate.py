#!/usr/bin/env python3
"""Run the explicitly provisioned Windows confinement runtime tests.

This gate fails if its Windows host or scratch parent is absent, if Cargo or
libtest fails, or if either live test is filtered, ignored, or missing. The
test capsule is structural fixture data: the current primitive does not
verify capsule signatures, so this gate is not sealed-input evidence.
"""

from __future__ import annotations

import argparse
import os
import platform
import re
import stat
import subprocess
import sys
import tempfile
from pathlib import Path

PACKAGE = "semaprax-native-rust-interop-platform-sys"
PARENT_ENV = "SEMAPRAX_WINDOWS_CONFINEMENT_TEST_PARENT"
FILTER = "doctor::windows_confinement::primitive::tests::windows_runtime_"
EXPECTED_TESTS = (
    "doctor::windows_confinement::primitive::tests::windows_runtime_launches_restricted_child_inside_acl_scratch_and_settles_it",
    "doctor::windows_confinement::primitive::tests::windows_runtime_timeout_terminates_the_confined_job_and_settles_cancellation",
)
REPO_ROOT = Path(__file__).resolve().parents[1]


def precondition_failures(
    system,
    machine,
    pointer_bits,
    parent_present,
    parent_absolute,
    parent_directory,
    parent_reparse,
    parent_empty,
):
    failures = []
    if system != "Windows":
        failures.append("host operating system is not Windows")
    if machine not in {"AMD64", "x86_64", "ARM64", "aarch64"}:
        failures.append("host architecture is not admitted x86-64 or AArch64")
    if pointer_bits != 64:
        failures.append("host pointer width is not 64-bit")
    if not parent_present:
        failures.append(f"{PARENT_ENV} is missing")
    if not parent_absolute:
        failures.append("explicit test parent is not absolute")
    if not parent_directory:
        failures.append("explicit test parent is not an existing directory")
    if parent_reparse:
        failures.append("explicit test parent is a reparse point")
    if not parent_empty:
        failures.append("explicit test parent is not empty")
    return failures


def libtest_failures(output, return_code):
    failures = []
    output = output.replace("\r\n", "\n").replace("\r", "\n")
    if return_code != 0:
        failures.append(f"cargo test exited with status {return_code}")
    for test in EXPECTED_TESTS:
        matches = re.findall(rf"(?m)^test {re.escape(test)} \.\.\. ok$", output)
        if len(matches) != 1:
            failures.append(f"expected exactly one passing execution of {test}; saw {len(matches)}")
    summary = re.search(
        r"(?m)^test result: ok\. (\d+) passed; (\d+) failed; (\d+) ignored;",
        output,
    )
    if summary is None:
        failures.append("libtest did not report a successful test summary")
    else:
        passed, failed, ignored = map(int, summary.groups())
        if passed != len(EXPECTED_TESTS) or failed != 0 or ignored != 0:
            failures.append(
                "libtest summary must show both selected runtime tests passing "
                f"and no ignored matches; got {passed} passed, {failed} failed, {ignored} ignored"
            )
    return failures


def inspect_parent():
    value = os.environ.get(PARENT_ENV)
    if not value:
        return None, [f"{PARENT_ENV} is missing"]
    parent = Path(value)
    try:
        metadata = parent.lstat()
    except OSError as error:
        return parent, [f"explicit test parent cannot be inspected: {error}"]
    attributes = getattr(metadata, "st_file_attributes", None)
    reparse = None if attributes is None else bool(attributes & 0x400)
    try:
        empty = next(parent.iterdir(), None) is None
    except OSError as error:
        return parent, [f"explicit test parent cannot be enumerated: {error}"]
    failures = precondition_failures(
        platform.system(),
        platform.machine(),
        64 if sys.maxsize > 2**32 else 32,
        True,
        parent.is_absolute(),
        stat.S_ISDIR(metadata.st_mode),
        reparse,
        empty,
    )
    if attributes is None:
        failures.append("Windows reparse-point attributes are unavailable")
    return parent, failures


def self_test():
    valid = precondition_failures("Windows", "AMD64", 64, True, True, True, False, True)
    assert not valid, valid
    assert precondition_failures("Linux", "x86_64", 64, False, False, False, False, False)
    passing_output = "\n".join(
        [*(f"test {name} ... ok" for name in EXPECTED_TESTS),
         "test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 8 filtered out; finished in 1.00s"]
    )
    assert not libtest_failures(passing_output, 0)
    assert libtest_failures("test result: ok. 0 passed; 0 failed; 0 ignored; 10 filtered out", 0)
    assert libtest_failures(passing_output.replace(" ... ok", " ... ignored"), 0)
    previous_parent = os.environ.get(PARENT_ENV)
    with tempfile.TemporaryDirectory(prefix="semaprax-windows-gate-self-test-") as directory:
        os.environ[PARENT_ENV] = directory
        try:
            _, parent_failures = inspect_parent()
        finally:
            if previous_parent is None:
                os.environ.pop(PARENT_ENV, None)
            else:
                os.environ[PARENT_ENV] = previous_parent
    assert "explicit test parent is not empty" not in parent_failures, parent_failures
    if platform.system() != "Windows":
        assert "host operating system is not Windows" in parent_failures, parent_failures
    print("self-test passed: gate rejects missing host/provisioning and zero/ignored runtime tests; no runtime evidence produced")
    return 0


def run_gate():
    parent, failures = inspect_parent()
    if failures:
        for failure in failures:
            print(f"Windows confinement gate refusal: {failure}", file=sys.stderr)
        return 2

    command = [
        "cargo",
        "test",
        "--locked",
        "--offline",
        "-p",
        PACKAGE,
        "--lib",
        FILTER,
        "--",
        "--ignored",
        "--nocapture",
        "--test-threads=1",
    ]
    print(f"provisioned Windows test parent: {parent}")
    print("running both named restricted-token, child-launch, job, ACL, and settlement tests")
    try:
        completed = subprocess.run(
            command,
            cwd=REPO_ROOT,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=600,
            check=False,
        )
    except subprocess.TimeoutExpired as error:
        output = error.stdout or ""
        if isinstance(output, bytes):
            output = output.decode("utf-8", errors="replace")
        print(output, end="")
        print("Windows confinement gate refusal: runtime suite exceeded 600 seconds", file=sys.stderr)
        return 1
    print(completed.stdout, end="")
    failures = libtest_failures(completed.stdout, completed.returncode)
    if failures:
        for failure in failures:
            print(f"Windows confinement gate refusal: {failure}", file=sys.stderr)
        return 1
    print("both explicitly selected Windows runtime tests executed and passed")
    return 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test", action="store_true", help="exercise refusal and nonzero-result parsing only")
    parser.add_argument("--plan", action="store_true", help="print the exact runtime test selector and prerequisites")
    args = parser.parse_args()
    if args.self_test:
        return self_test()
    if args.plan:
        print(f"host: Windows x86-64 or AArch64, 64-bit process")
        print(f"required provisioned parent: {PARENT_ENV} (existing, empty, non-reparse directory)")
        print(f"Cargo selector: -p {PACKAGE} --lib {FILTER} -- --ignored --nocapture --test-threads=1")
        for test in EXPECTED_TESTS:
            print(f"required executed test: {test}")
        print("capsule bytes are structurally valid test data with an unverified signature")
        return 0
    return run_gate()


if __name__ == "__main__":
    raise SystemExit(main())
