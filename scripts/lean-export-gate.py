#!/usr/bin/env python3
"""Lean obligation-export kernel gate (issue #186).

`src/proof_export` generates deterministic Lean 4 from a small pure SEMAPRAX
subset and binds an accepted kernel result to exact source, revision,
compiler and artifact digests. When that module was written, **no Lean
toolchain had ever been run against it**: every test replayed synthesized
output through a fixture implementation of the `LeanKernel` capability, so
"Lean accepts these generated proofs" was a commitment, not a result.

This script is the missing `LeanKernel` implementation. It deliberately
lives in `scripts/` rather than in the crate: running an external kernel is
process authority, and AGENTS.md's "compiler and generated code gain no
ambient filesystem, process, network... authority" invariant is why
`proof_export` expresses the kernel as a capability the caller supplies and
ships no implementation of its own. The caller is this file.

Scope, stated up front
----------------------
**Local-host evidence only.** Hosted CI provisions no Lean toolchain (see
`docs/QUALITY-GATES.md`), so this gate is not wired into `scripts/quality.sh`
and is not in `release-gate`'s blocker set. Nothing it produces may be
described as hosted, production, or physical-device evidence. What runs
everywhere instead is the recorded half: the transcripts this script writes
are committed under `src/proof_export/testdata/` and re-checked against the
parser by ordinary `cargo test` (`src/proof_export/tests.rs`, the "Real
pinned-kernel transcripts" section).

What it checks
--------------
1. The toolchain actually on this host is the pinned one.
   -> `lean --version` must report the version in
      `proofs/kernel0-lean/lean-toolchain`. Deliberately not a second pin:
      the export module's `PINNED_TOOLCHAIN` constant, this script, and
      issue #188's Kernel-0 proof all read the same file.
2. The committed golden Lean document is accepted by that kernel.
   -> Every `#print axioms` line must name an expected theorem exactly once
      with an axiom set inside Lean's three standard axioms, and no line may
      report an error, a deterministic cutoff, or an admitted hole. This
      mirrors `proof_export::kernel_report::parse`; the Rust parser stays
      authoritative for certificates, this is the live cross-check.
3. The committed transcripts still describe what this kernel really prints.
   -> Byte-for-byte comparison against
      `src/proof_export/testdata/shifted.kernel-output*.txt`. Recorded
      evidence that no longer matches the kernel is stale evidence, and
      stale evidence that keeps passing is worse than none: the Rust tests
      would go on asserting against output Lean no longer produces.
4. Two seeded defects are still caught, and one deliberately is not.
   -> `sorry` seeded into the postcondition proof must be refused. A
      vacuously weakened conclusion (`... ∨ True`, honestly proved) must
      still be *accepted* by the kernel, because it genuinely is a theorem —
      that is the point. It is refused one layer up, by
      `verify_certificate_against_source` re-deriving the document from the
      bound source. Asserting the kernel catches it would be a false claim
      baked into a gate.

Exit behavior
-------------
No Lean toolchain, or the pinned toolchain not already installed: prints an
unambiguous `SKIP` naming exactly what was not checked and exits 0. It never
reports a run it did not perform as a pass, and it never fetches anything --
no network access is attempted, and an uninstalled pin is a skip rather than
a download, because a gate that installs a gigabyte of toolchain is not a
gate. Otherwise every check above must pass for exit 0.

`--require-kernel` inverts that default: every skip becomes a failure. A
skip-on-absence gate is the correct shape on a developer machine that may
not have Lean, and exactly the wrong shape on a runner that is supposed to
have provisioned it -- there, a silently skipped kernel is a green check
covering nothing, which is the failure mode this whole gate exists to
prevent. Hosted CI passes the flag; `scripts/quality.sh` does not.

Usage
-----
    scripts/lean-export-gate.py                    # check, skip if absent
    scripts/lean-export-gate.py --require-kernel   # absence is a failure
    scripts/lean-export-gate.py --record           # re-record transcripts
"""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

TAG = "lean-export-gate"

REPO = Path(__file__).resolve().parent.parent
TOOLCHAIN_FILE = REPO / "proofs" / "kernel0-lean" / "lean-toolchain"
TESTDATA = REPO / "src" / "proof_export" / "testdata"
GOLDEN = TESTDATA / "shifted.lean.golden"

# Lean's three standard axioms. Anything else -- `sorryAx` above all --
# invalidates a theorem. Kept in step with `kernel_report::STANDARD_AXIOMS`.
STANDARD_AXIOMS = {"propext", "Classical.choice", "Quot.sound"}

NAMESPACE = "SemapraxExport"
EXPECTED_THEOREMS = [
    f"{NAMESPACE}.spx_app_2et_2eshifted_range_0",
    f"{NAMESPACE}.spx_app_2et_2eshifted_ensures_0",
]

# The file name the generated document is checked under. It appears in every
# diagnostic line Lean prints, so it is part of the recorded transcripts and
# must not change without re-recording them.
CHECKED_AS = "Export.lean"


def seed_sorry(document: str) -> str:
    """Replace the postcondition proof's `omega` with a real `sorry`."""
    index = document.rindex("  omega")
    return document[:index] + "  sorry" + document[index + len("  omega") :]


def seed_weakened(document: str) -> str:
    """Weaken the postcondition conclusion to a tautology, honestly proved."""
    before = "    : (result ≥ v_a) := by\n  omega"
    after = "    : (result ≥ v_a) ∨ True := by\n  exact Or.inr True.intro"
    if before not in document:
        raise SystemExit(
            f"{TAG}: FAIL: the golden document no longer contains the "
            f"postcondition proof this seed rewrites; re-derive the seed"
        )
    return document.replace(before, after)


# name -> (transcript file, document transform, verdict this gate requires)
CASES = [
    ("clean", "shifted.kernel-output.txt", lambda text: text, "checked"),
    ("sorry", "shifted.kernel-output.sorry.txt", seed_sorry, "admitted_hole"),
    # Deliberately "checked": see this module's docstring, check 4.
    ("weakened", "shifted.kernel-output.weakened.txt", seed_weakened, "checked"),
]


def find_lean() -> str | None:
    """Locate `lean`, including the elan shim directory that is off PATH."""
    found = shutil.which("lean")
    if found:
        return found
    candidate = Path.home() / ".elan" / "bin" / "lean"
    return str(candidate) if candidate.exists() else None


def toolchain_env(pin: str) -> dict[str, str]:
    """Environment that names the pinned toolchain explicitly.

    elan resolves a version from the nearest `lean-toolchain` file and, with
    no default configured, fails outside a project. `ELAN_TOOLCHAIN` pins it
    regardless of the working directory.
    """
    env = dict(os.environ)
    env["ELAN_TOOLCHAIN"] = pin
    return env


def installed(pin: str) -> bool:
    """Is the pinned toolchain already on this host?

    Checked before anything runs under `ELAN_TOOLCHAIN`, because elan's
    response to an unknown toolchain is to download it, and AGENTS.md bans
    build-time network access. When elan is absent the caller is running a
    directly installed `lean`; the version probe checks that instead.
    """
    elan = shutil.which("elan") or str(Path.home() / ".elan" / "bin" / "elan")
    if not Path(elan).exists():
        return True
    listed = subprocess.run(
        [elan, "toolchain", "list"], capture_output=True, text=True, check=False
    )
    return pin in listed.stdout


def pinned_version(pin: str) -> str:
    """`leanprover/lean4:v4.34.0` -> `4.34.0`."""
    return pin.rsplit(":v", 1)[-1]


def parse_axiom_line(line: str) -> tuple[str, list[str]] | None:
    """Parse one `#print axioms` line, in either of Lean's two shapes."""
    body = line.strip()
    if body.startswith("info: "):
        body = body[len("info: ") :]
    start = body.find("'")
    if start < 0:
        return None
    rest = body[start + 1 :]
    end = rest.find("'")
    if end < 0:
        return None
    name = rest[:end]
    tail = rest[end + 1 :].lstrip()
    prefix = "depends on axioms: ["
    if tail.startswith(prefix):
        listed = tail[len(prefix) :].rstrip()
        listed = listed[:-1] if listed.endswith("]") else listed
        return name, [item.strip() for item in listed.split(",") if item.strip()]
    if tail.startswith("does not depend on any axioms"):
        return name, []
    return None


def verdict(output: str) -> str:
    """Mirror of `proof_export::kernel_report::parse`: fail-closed."""
    for line in output.splitlines():
        lower = line.lower().replace("`", "'")
        if (
            "(deterministic) timeout" in lower
            or "maximum recursion depth has been reached" in lower
            or "deep recursion was detected" in lower
        ):
            return "timeout"
        if (
            "declaration uses 'sorry'" in lower
            or "declaration uses 'admit'" in lower
            or "uses sorry" in lower
            or "sorryax" in lower
        ):
            return "admitted_hole"
        if "error:" in lower:
            return "build_error"

    reported: dict[str, int] = {}
    axioms: dict[str, list[str]] = {}
    for line in output.splitlines():
        parsed = parse_axiom_line(line)
        if parsed is None:
            continue
        name, found = parsed
        reported[name] = reported.get(name, 0) + 1
        axioms[name] = found
    if not reported:
        return "unrecognized_output"
    for theorem in EXPECTED_THEOREMS:
        if theorem not in reported:
            return "missing_theorem"
        if reported[theorem] > 1:
            return "duplicate_theorem"
        for axiom in axioms[theorem]:
            if axiom not in STANDARD_AXIOMS:
                return "forbidden_axiom"
    return "checked"


def run_kernel(lean: str, pin: str, document: str) -> str:
    """Check one Lean document with the pinned toolchain, hermetically.

    The document is written into a scratch directory beside a copy of the
    repository's `lean-toolchain` pin, which is how elan resolves a version
    for a bare `lean` invocation. Nothing is fetched: the pin is confirmed
    installed before this runs.
    """
    with tempfile.TemporaryDirectory(prefix="semaprax-lean-export-") as scratch:
        work = Path(scratch)
        (work / "lean-toolchain").write_text(pin + "\n", encoding="utf-8")
        (work / CHECKED_AS).write_text(document, encoding="utf-8")
        env = dict(os.environ)
        # Belt and braces against a surprise download on a host whose elan
        # has no default toolchain configured.
        env["ELAN_TOOLCHAIN"] = pin
        proc = subprocess.run(
            [lean, CHECKED_AS],
            cwd=work,
            env=env,
            capture_output=True,
            text=True,
            check=False,
        )
    # Lean writes diagnostics and `#print axioms` output to stdout; stderr is
    # empty on this toolchain. Both are captured so a future release that
    # splits them cannot silently drop half the evidence.
    return proc.stdout + proc.stderr


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--record",
        action="store_true",
        help="rewrite the committed transcripts from this host's kernel",
    )
    parser.add_argument(
        "--require-kernel",
        action="store_true",
        help=(
            "treat every skip as a failure: the pinned kernel must be "
            "present and must actually run"
        ),
    )
    args = parser.parse_args()

    def unavailable(reason: str) -> int:
        """Report a kernel that did not run.

        The wording is identical either way -- only the verdict and the exit
        code change -- so a hosted run can never present a check it did not
        perform as a pass, and a developer without Lean is never blocked.
        """
        if args.require_kernel:
            print(f"{TAG}: FAIL: {reason}", file=sys.stderr)
            print(
                f"{TAG}: RESULT: FAIL -- --require-kernel was passed, so a "
                f"kernel that did not run is a failure, not a skip",
                file=sys.stderr,
            )
            return 1
        print(f"{TAG}: SKIP: {reason}")
        return 0

    pin = TOOLCHAIN_FILE.read_text(encoding="utf-8").strip()
    want = pinned_version(pin)

    lean = find_lean()
    if lean is None:
        return unavailable(
            f"no `lean` on PATH or in ~/.elan/bin -- the generated Lean was "
            f"NOT checked by any kernel. Install the pinned {pin} to run this "
            f"gate; this script will not fetch it."
        )

    # `lean` here is usually elan's shim, which resolves a version from the
    # nearest `lean-toolchain` file and refuses to run outside a project when
    # no default is configured. Name the pin explicitly rather than depending
    # on the working directory -- getting this wrong turns every run into a
    # SKIP that exits 0, which is a false pass wearing a skip's clothes.
    if not installed(pin):
        return unavailable(
            f"the pinned toolchain {pin} is not installed on this host -- the "
            f"generated Lean was NOT checked by any kernel. Install it "
            f"yourself; this gate does not fetch toolchains."
        )

    try:
        probe = subprocess.run(
            [lean, "--version"],
            capture_output=True,
            text=True,
            check=False,
            env=toolchain_env(pin),
        )
        version = (probe.stdout + probe.stderr).strip()
    except OSError as error:  # pragma: no cover - environment dependent
        return unavailable(f"cannot run `{lean} --version`: {error}")

    if want not in version:
        return unavailable(
            f"this host's Lean reports `{version or '(nothing)'}`, which does "
            f"not contain the pinned {want} from "
            f"{TOOLCHAIN_FILE.relative_to(REPO)}. A kernel that is not the "
            f"pinned one proves nothing about the pinned one, so this is "
            f"never a pass and never a silent substitution."
        )

    print(f"{TAG}: pinned toolchain {pin} confirmed ({version})")

    golden = GOLDEN.read_text(encoding="utf-8")
    failures: list[str] = []

    for name, transcript_name, transform, want_verdict in CASES:
        transcript_path = TESTDATA / transcript_name
        output = run_kernel(lean, pin, transform(golden))
        got = verdict(output)

        if got != want_verdict:
            failures.append(
                f"case `{name}`: the pinned kernel's verdict is `{got}`, "
                f"expected `{want_verdict}`. Output:\n{output}"
            )
            continue

        if args.record:
            transcript_path.write_text(output, encoding="utf-8")
            print(f"{TAG}: recorded {transcript_path.relative_to(REPO)} ({got})")
            continue

        if not transcript_path.exists():
            failures.append(
                f"case `{name}`: {transcript_path.relative_to(REPO)} is missing; "
                f"re-record with --record"
            )
            continue

        recorded = transcript_path.read_text(encoding="utf-8")
        if recorded != output:
            failures.append(
                f"case `{name}`: {transcript_path.relative_to(REPO)} no longer "
                f"matches what this kernel prints. The Rust tests are asserting "
                f"against stale recorded output. Re-record deliberately with "
                f"--record and review the diff.\n--- recorded\n{recorded}"
                f"--- live\n{output}"
            )
            continue

        print(f"{TAG}: case `{name}`: verdict `{got}`, transcript byte-identical")

    if failures:
        for failure in failures:
            print(f"{TAG}: FAIL: {failure}", file=sys.stderr)
        print(f"{TAG}: RESULT: FAIL", file=sys.stderr)
        return 1

    if args.record:
        print(f"{TAG}: RESULT: RECORDED (review the diff before committing)")
        return 0

    result = (
        f"{TAG}: RESULT: PASS -- the committed Lean export is accepted by the "
        f"pinned kernel, a seeded `sorry` is refused, and every transcript is "
        f"current."
    )
    if not args.require_kernel:
        # Without the flag this run may have been a developer machine, so the
        # standing caveat stays. With it, the caller provisioned the kernel
        # and is entitled to describe the run as whatever it actually is.
        result += " LOCAL-HOST EVIDENCE unless a provisioned runner ran it."
    print(result)
    return 0


if __name__ == "__main__":
    sys.exit(main())
