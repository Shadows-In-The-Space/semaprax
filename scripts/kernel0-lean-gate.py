#!/usr/bin/env python3
"""Kernel-0 Lean proof gate (issue #188).

`proofs/kernel0-lean/Kernel0.lean` is a hole-free Lean 4 mechanization of a
Progress trichotomy (scalar-and-`if` fragment) and Preservation (the whole
language, `Let` and non-recursive `Call` included) for Kernel-0 -- see
`docs/KERNEL-PROOF-MECHANIZATION-V1.md` for the design record and
`docs/SEMANTIC-KERNEL-V1.md` for what Kernel-0 is. Before this script
existed, nothing in the repository re-checked that file: no CI job ran
`lake build`, it was not in `scripts/quality.sh`, and nothing would fail if
the proof were reverted, weakened, or silently made to stop building.

This script is that executable gate. It is invoked from `scripts/quality.sh`
(the `full` profile) and, where a Lean toolchain happens to be available,
from CI -- see docs/QUALITY-GATES.md's "Kernel-0 Lean proof gate" section for
which half runs where.

What it catches, and how
-------------------------
1. The proof stops building at all.
   -> `lake build`'s exit code, when a Lean toolchain is on PATH.
2. A `sorry`/`admit` tactic, or a new `axiom` declaration, appears in the
   source outside a comment or string literal.
   -> A nesting-aware Lean comment/string stripper (Lean 4 block comments
      nest) followed by a whole-token scan. This runs unconditionally, with
      or without a Lean toolchain, and exists specifically because grepping
      raw source for "sorry" is wrong on this exact file: six of its lines
      say the word "sorry" inside doc comments discussing this very gate,
      none of them a real tactic invocation (see
      docs/KERNEL-PROOF-MECHANIZATION-V1.md, "A concrete pitfall").
      This check is deliberately *not* the authoritative one -- (3) below,
      which inspects the elaborated proof term rather than source text, is
      -- but it is real, cheap, and needs no toolchain.
3. A headline theorem starts depending on a custom axiom, or on `sorryAx`
   (Lean's marker for an admitted hole).
   -> Every `info: ... '<name>' depends on axioms: [...]` line `lake build`
      prints (one per `#print axioms` command already at the bottom of
      Kernel0.lean) is parsed, and its axiom set must be a subset of Lean's
      three standard, accepted axioms: `propext`, `Classical.choice`,
      `Quot.sound`. Requires a Lean toolchain; skipped explicitly when one
      is unavailable.
4. A headline theorem is deleted, renamed, or its *statement* is weakened
   while the file still builds and still looks axiom-clean -- the failure
   mode a bare `lake build` gate misses entirely.
   -> (a) Presence: each headline name must resolve to
          exactly one `#print axioms` info line in the build output
          (requires a toolchain -- an unresolvable name is also a hard
          `lake build` failure, so this is belt-and-suspenders with (1)).
      (b) Signature pin (no toolchain needed, always runs): each headline
          theorem's exact statement -- from `theorem NAME` through the
          token that starts its proof -- is re-extracted from the source by
          the same algorithm used to produce the frozen copies pinned
          below, and compared byte for byte. Changing a hypothesis, a
          conclusion, or a binder fails the gate even if the edited theorem
          still typechecks against its new, weaker statement.

Exit behavior
-------------
The source-level checks (2, 4b, and a name-presence check independent of
`lake`) always run and can fail the gate with no Lean toolchain installed.
The build-dependent checks (1, 3, 4a) require `lake` on PATH; when it is
absent, this script prints an unambiguous `SKIP` line naming exactly what
was not checked and exits 0 for that half only -- it never reports a build
it did not run as a pass, and the overall run only exits 0 if every
applicable check (source-level, always; build-level, when possible) passed.
No network access is attempted; if Lean is not installed, install it
yourself (e.g. via https://leanprover-community.github.io/get_started.html)
-- this script will not fetch it.

`--require-kernel` removes the skip half: an absent `lake` becomes a hard
failure, and `PASS-PARTIAL` stops being an accepted outcome. Skip-on-absence
is right on a developer machine that may have no Lean, and wrong on a runner
that has just provisioned one -- there, a silently skipped build is a green
check over an unbuilt proof, which is precisely the hole this gate was
written to close. Hosted CI passes the flag; `scripts/quality.sh` does not.
"""

from __future__ import annotations

import argparse
import re
import shutil
import subprocess
import sys
from pathlib import Path

TAG = "KERNEL0-LEAN-GATE"

SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parent
PROOF_DIR = REPO_ROOT / "proofs" / "kernel0-lean"
SOURCE = PROOF_DIR / "Kernel0.lean"
RECURSIVE_CONTROL = PROOF_DIR / "negative" / "RecursiveCallGraph.lean"

# Fully-qualified headline theorem names this gate certifies are present,
# axiom-clean, and unchanged. Sourced from the `#print axioms` block at the
# bottom of Kernel0.lean itself -- if that list ever grows, add the new name
# both there and here (and to PINNED_SIGNATURES below).
HEADLINE_THEOREMS = [
    "progress_scalarIf",
    "progress_scalarIf_closed",
    "preservation",
    "subst_preserves_type",
    "subst_preserves_type_args",
    "hastype_weaken_right",
    "hastype_weaken_right_args",
    "bool_equality_has_type",
    "bool_equality_steps",
    "bool_inequality_steps",
    "bool_ordering_is_not_typed",
    "call_path_rank_bound",
    "ranked_call_graph_acyclic",
    "ranked_call_chain_terminates",
    "recursive_call_fixture_rejected",
    "acyclic_call_fixture_ranked",
]

# Frozen, byte-exact expected statement text for each headline theorem,
# extracted from the committed proof by `extract_signature` below (verified
# self-consistent against the file at the time this script was written).
# A change to any of these -- a hypothesis, a conclusion, a binder -- means
# the theorem now proves something different, even if the file still builds
# and still reports a clean axiom set. Do not "fix" a failure here by
# updating the pin without checking why the statement changed.
PINNED_SIGNATURES = {
    "progress_scalarIf": (
        "theorem progress_scalarIf {P Γ e T} (hs : ScalarIf e) (ht : HasType P Γ e T) :\n"
        "    IsValue e ∨ (∃ e', Step P e e') ∨ FaultRedex e"
    ),
    "progress_scalarIf_closed": (
        "theorem progress_scalarIf_closed {P e T} (hs : ScalarIf e) (ht : HasType P [] e T) :\n"
        "    IsValue e ∨ (∃ e', Step P e e') ∨ FaultRedex e"
    ),
    "preservation": (
        "theorem preservation {P Γ e e' T} (hwf : WellFormedProgram P) (ht : HasType P Γ e T)\n"
        "    (hs : Step P e e') : HasType P Γ e' T"
    ),
    "subst_preserves_type": (
        "theorem subst_preserves_type {P : Program} (Γ1 ΓMid Γ2 : List Ty) (env : List Expr) :\n"
        "    ∀ (e : Expr) {T : Ty}, (∀ v ∈ env, IsValue v) →\n"
        "      ArgsHaveTypes P (Γ1 ++ Γ2) env ΓMid →\n"
        "      HasType P (Γ1 ++ ΓMid ++ Γ2) e T →\n"
        "      HasType P (Γ1 ++ Γ2) (substEnvAt Γ1.length env e) T"
    ),
    "subst_preserves_type_args": (
        "theorem subst_preserves_type_args {P : Program} (Γ1 ΓMid Γ2 : List Ty) (env : List Expr) :\n"
        "    ∀ (args : List Expr) {Ts : List Ty}, (∀ v ∈ env, IsValue v) →\n"
        "      ArgsHaveTypes P (Γ1 ++ Γ2) env ΓMid →\n"
        "      ArgsHaveTypes P (Γ1 ++ ΓMid ++ Γ2) args Ts →\n"
        "      ArgsHaveTypes P (Γ1 ++ Γ2) (args.map (substEnvAt Γ1.length env)) Ts"
    ),
    "hastype_weaken_right": (
        "theorem hastype_weaken_right {P : Program} (Γ1 Γ2 : List Ty) :\n"
        "    ∀ (e : Expr) {T : Ty}, HasType P Γ1 e T → HasType P (Γ1 ++ Γ2) e T"
    ),
    "hastype_weaken_right_args": (
        "theorem hastype_weaken_right_args {P : Program} (Γ1 Γ2 : List Ty) :\n"
        "    ∀ (args : List Expr) {Ts : List Ty},\n"
        "      ArgsHaveTypes P Γ1 args Ts → ArgsHaveTypes P (Γ1 ++ Γ2) args Ts"
    ),
    "bool_equality_has_type": (
        "theorem bool_equality_has_type {P Γ a b} :\n"
        "    HasType P Γ (.cmp .eq (.boolLit a) (.boolLit b)) .bool"
    ),
    "bool_equality_steps": (
        "theorem bool_equality_steps {P} :\n"
        "    Step P (.cmp .eq (.boolLit true) (.boolLit false)) (.boolLit false)"
    ),
    "bool_inequality_steps": (
        "theorem bool_inequality_steps {P} :\n"
        "    Step P (.cmp .ne (.boolLit true) (.boolLit false)) (.boolLit true)"
    ),
    "bool_ordering_is_not_typed": (
        "theorem bool_ordering_is_not_typed {P Γ a b} :\n"
        "    ¬ HasType P Γ (.cmp .lt (.boolLit a) (.boolLit b)) .bool"
    ),
    "call_path_rank_bound": (
        "theorem call_path_rank_bound {P rank f g n} (hr : CallGraphRanked P rank)\n"
        "    (hp : CallPath P f g n) : n + rank g ≤ rank f"
    ),
    "ranked_call_graph_acyclic": (
        "theorem ranked_call_graph_acyclic {P rank f n} (hr : CallGraphRanked P rank)\n"
        "    (hp : CallPath P f f n) : n = 0"
    ),
    "ranked_call_chain_terminates": (
        "theorem ranked_call_chain_terminates {P rank} (hr : CallGraphRanked P rank) :\n"
        "    ¬ ∃ chain : Nat → Nat, ∀ n, CallEdge P (chain n) (chain (n + 1))"
    ),
    "recursive_call_fixture_rejected": (
        "theorem recursive_call_fixture_rejected (rank : Nat → Nat) :\n"
        "    ¬ CallGraphRanked recursiveCallFixture rank"
    ),
    "acyclic_call_fixture_ranked": (
        "theorem acyclic_call_fixture_ranked :\n"
        "    CallGraphRanked acyclicCallFixture (fun f => if f = 0 then 1 else 0)"
    ),
}

PINNED_RECURSIVE_CONTROL = """import Kernel0
open Kernel0
theorem forged_recursive_call_rank :
CallGraphRanked recursiveCallFixture (fun _ => 0) := by
intro caller callee edge
exact Nat.le_refl 0"""

ALLOWED_AXIOMS = {"propext", "Classical.choice", "Quot.sound"}

AXIOM_INFO_RE = re.compile(r"'([\w.]+)' depends on axioms: \[([^\]]*)\]")


def fail(msg: str) -> None:
    print(f"{TAG}: FAIL: {msg}", file=sys.stderr)


def extract_signature(lines: list[str], name: str) -> str | None:
    """Re-implements, against arbitrary source lines, the same extraction
    used to produce PINNED_SIGNATURES: from `theorem NAME` up to (but not
    including) whichever comes first -- a ` := by` on some line, a bare
    trailing `:=`, or an equation-compiler arm (`  | ...`) starting the
    proof. Returns None if the name is not declared as a top-level theorem
    at all (deleted or renamed)."""
    start_re = re.compile(r"^theorem " + re.escape(name) + r"\b")
    start = None
    for i, line in enumerate(lines):
        if start_re.match(line):
            start = i
            break
    if start is None:
        return None
    sig_lines: list[str] = []
    i = start
    while i < len(lines):
        line = lines[i]
        if i > start and line.startswith("  | "):
            return "\n".join(sig_lines)
        if " := by" in line:
            sig_lines.append(line.split(" := by")[0])
            return "\n".join(sig_lines)
        stripped = line.rstrip()
        if stripped.endswith(" :="):
            sig_lines.append(stripped[: -len(" :=")])
            return "\n".join(sig_lines)
        if stripped == ":=":
            return "\n".join(sig_lines)
        sig_lines.append(line)
        i += 1
    return None  # ran off the end of the file without a terminator


def strip_comments_and_strings(text: str) -> str:
    """Lean 4 line comments (`--` to end of line), block comments (`/- -/`,
    which NEST -- including `/--`/`/-!` doc comments, the same lexeme
    family), and string literals (`"..."` with `\\"` escapes), replaced with
    spaces so token positions/line count are preserved but no comment or
    string content can masquerade as a real `sorry`/`admit`/`axiom` token."""
    out = []
    i = 0
    n = len(text)
    depth = 0  # block-comment nesting depth
    while i < n:
        if depth > 0:
            if text[i : i + 2] == "/-":
                depth += 1
                out.append("  ")
                i += 2
                continue
            if text[i : i + 2] == "-/":
                depth -= 1
                out.append("  ")
                i += 2
                continue
            out.append(" " if text[i] != "\n" else "\n")
            i += 1
            continue
        if text[i : i + 2] == "/-":
            depth = 1
            out.append("  ")
            i += 2
            continue
        if text[i : i + 2] == "--":
            j = text.find("\n", i)
            j = n if j == -1 else j
            out.append(" " * (j - i))
            i = j
            continue
        if text[i] == '"':
            out.append(" ")
            i += 1
            while i < n and text[i] != '"':
                if text[i] == "\\" and i + 1 < n:
                    out.append("  ")
                    i += 2
                    continue
                out.append(" " if text[i] != "\n" else "\n")
                i += 1
            if i < n:
                out.append(" ")
                i += 1
            continue
        out.append(text[i])
        i += 1
    return "".join(out)


TOKEN_RE = re.compile(r"\b(sorry|admit)\b")
AXIOM_DECL_RE = re.compile(r"\baxiom\s+\w")


def check_source_level(source_text: str, lines: list[str]) -> list[str]:
    """Runs every check that needs only the source text, no Lean toolchain.
    Returns a list of failure messages (empty means this half passed)."""
    failures: list[str] = []

    # (4) presence + (4b) signature pin.
    missing = []
    changed = []
    for name in HEADLINE_THEOREMS:
        actual = extract_signature(lines, name)
        if actual is None:
            missing.append(name)
            continue
        expected = PINNED_SIGNATURES[name]
        if actual != expected:
            changed.append((name, expected, actual))
    if missing:
        failures.append(
            "headline theorem(s) not found in source (deleted or renamed): "
            + ", ".join(missing)
        )
    for name, expected, actual in changed:
        failures.append(
            f"headline theorem `{name}` signature changed.\n"
            f"    expected:\n      "
            + "\n      ".join(expected.splitlines())
            + "\n    actual:\n      "
            + "\n      ".join(actual.splitlines())
        )
    if not missing and not changed:
        print(
            f"{TAG}: source-presence-and-signature OK "
            f"({len(HEADLINE_THEOREMS)}/{len(HEADLINE_THEOREMS)} headline "
            "theorems present with unchanged pinned statements)"
        )

    # (2) sorry/admit/axiom token scan, comment- and string-aware.
    stripped = strip_comments_and_strings(source_text)
    bad_tokens = sorted(set(m.group(1) for m in TOKEN_RE.finditer(stripped)))
    axiom_decls = AXIOM_DECL_RE.findall(stripped)
    if bad_tokens:
        failures.append(
            "real (non-comment, non-string) tactic token(s) found: "
            + ", ".join(bad_tokens)
        )
    if axiom_decls:
        failures.append(
            f"{len(axiom_decls)} custom `axiom` declaration(s) found outside "
            "comments/strings; this proof is meant to depend on no axiom "
            "beyond Lean's own propext/Classical.choice/Quot.sound"
        )
    if not bad_tokens and not axiom_decls:
        print(
            f"{TAG}: sorry/admit/axiom token scan OK (0 found outside "
            "comments and string literals)"
        )

    if not RECURSIVE_CONTROL.is_file():
        failures.append("recursive-call negative control is missing")
    else:
        control = strip_comments_and_strings(RECURSIVE_CONTROL.read_text(encoding="utf-8"))
        normalized = "\n".join(line.strip() for line in control.splitlines() if line.strip())
        if normalized != PINNED_RECURSIVE_CONTROL:
            failures.append("recursive-call negative control changed from its pinned forged certificate")

    return failures


def check_build_level(require_kernel: bool) -> tuple[list[str], bool]:
    """Runs `lake build` and audits its output. Returns (failures, ran) --
    `ran` is False when no toolchain was available at all, in which case
    `failures` is empty unless `require_kernel` was asked for, which turns
    the absence itself into the failure."""
    lake = shutil.which("lake")
    if lake is None:
        if require_kernel:
            return (
                [
                    "`lake` not found on PATH and --require-kernel was "
                    "passed: the proof was NOT rebuilt and its axiom set "
                    "was NOT re-audited. A caller that promises a "
                    "provisioned kernel and then finds none has a "
                    "provisioning failure, not a skippable check."
                ],
                False,
            )
        print(
            f"{TAG}: SKIP: `lake` not found on PATH -- the proof was NOT "
            "rebuilt and its axiom set was NOT re-audited this run. This is "
            "a skip, not a pass: failure modes 1 (build breaks) and 3 "
            "(custom/sorryAx axiom dependency) were not checked. Install a "
            "Lean 4 toolchain (see "
            "https://leanprover-community.github.io/get_started.html) to "
            "get full coverage; this script will not fetch one itself. "
            "See docs/QUALITY-GATES.md's \"Kernel-0 Lean proof gate\" "
            "section."
        )
        return [], False

    proc = subprocess.run(
        ["lake", "build"],
        cwd=str(PROOF_DIR),
        capture_output=True,
        text=True,
    )
    combined = proc.stdout + proc.stderr
    failures: list[str] = []

    if proc.returncode != 0:
        failures.append(
            f"`lake build` exited {proc.returncode} (proof does not build):\n"
            + "\n".join("    " + l for l in combined.splitlines())
        )
        # Axiom/presence checks below need a successful build's #print
        # axioms output; a build failure is already the most serious
        # possible failure, so report it and stop here.
        return failures, True

    if "sorryAx" in combined:
        failures.append(
            "`sorryAx` appears in `lake build` output -- an admitted hole "
            "is reachable from a certified theorem:\n"
            + "\n".join(
                "    " + l for l in combined.splitlines() if "sorryAx" in l
            )
        )

    found: dict[str, list[str]] = {}
    for match in AXIOM_INFO_RE.finditer(combined):
        name, axioms_str = match.group(1), match.group(2)
        axioms = [a.strip() for a in axioms_str.split(",") if a.strip()]
        found.setdefault(name, []).append(axioms)

    missing_from_build = []
    duplicate_axiom_reports = []
    bad_axiom_sets = []
    for name in HEADLINE_THEOREMS:
        qualified = f"Kernel0.{name}"
        occurrences = found.get(qualified)
        if not occurrences:
            missing_from_build.append(qualified)
            continue
        if len(occurrences) != 1:
            duplicate_axiom_reports.append((qualified, len(occurrences)))
        for axioms in occurrences:
            extra = [a for a in axioms if a not in ALLOWED_AXIOMS]
            if extra:
                bad_axiom_sets.append((qualified, axioms, extra))

    if missing_from_build:
        failures.append(
            "headline theorem(s) produced no `#print axioms` info line in "
            "`lake build` output (their `#print axioms` command was removed, "
            "or the name no longer resolves): " + ", ".join(missing_from_build)
        )
    for qualified, count in duplicate_axiom_reports:
        failures.append(
            f"`{qualified}` produced {count} `#print axioms` info lines; expected exactly one"
        )
    for qualified, axioms, extra in bad_axiom_sets:
        failures.append(
            f"`{qualified}` depends on axiom(s) outside "
            f"{sorted(ALLOWED_AXIOMS)}: {axioms} (unexpected: {extra})"
        )

    if not failures:
        print(f"{TAG}: `lake build` OK (exit 0, cold build in {PROOF_DIR})")
        print(
            f"{TAG}: axiom-set OK for {len(HEADLINE_THEOREMS)}/"
            f"{len(HEADLINE_THEOREMS)} headline theorems (each a subset of "
            f"{sorted(ALLOWED_AXIOMS)})"
        )

    # The built module supplies the real CallGraphRanked definition. A forged
    # constant rank for its nested recursive fixture must be rejected by the
    # kernel, specifically at the <= proof offered where strict < is required.
    # Import/build failures and unrelated syntax errors are not a passing control.
    if not failures:
        control = subprocess.run(
            [lake, "env", "lean", str(RECURSIVE_CONTROL.relative_to(PROOF_DIR))],
            cwd=str(PROOF_DIR), capture_output=True, text=True,
        )
        output = control.stdout + control.stderr
        errors = [line for line in output.splitlines() if "error:" in line]
        normalized_output = re.sub(r"\s+", " ", output)
        # Lean can display the expected constant-rank application before
        # beta reduction. Accept exactly that equivalent form as well as 0.
        normalized_output = re.sub(
            r"\(fun \w+ => 0\) (?:caller|callee)\b", "0", normalized_output
        )
        if (
            control.returncode == 0
            or len(errors) != 1
            or "Type mismatch" not in errors[0]
            or "Nat.le_refl 0 has type 0 ≤ 0" not in normalized_output
            or "expected to have type 0 < 0" not in normalized_output
            or "sorryAx" in output
        ):
            failures.append(
                "recursive-call negative control did not fail at the expected strict-rank "
                "type mismatch:\n" + output
            )
        else:
            print(f"{TAG}: recursive-call negative control OK (forged rank rejected)")

    return failures, True


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--require-kernel",
        action="store_true",
        help=(
            "treat a missing Lean toolchain as a failure rather than a "
            "skip, so PASS-PARTIAL can never be reported as a pass"
        ),
    )
    arguments = parser.parse_args()

    if not SOURCE.is_file():
        fail(f"expected proof source not found at {SOURCE}")
        return 1

    source_text = SOURCE.read_text(encoding="utf-8")
    lines = source_text.split("\n")

    source_failures = check_source_level(source_text, lines)
    build_failures, build_ran = check_build_level(arguments.require_kernel)

    all_failures = source_failures + build_failures
    if all_failures:
        for msg in all_failures:
            fail(msg)
        print(f"{TAG}: RESULT: FAIL ({len(all_failures)} check(s) failed)")
        return 1

    if build_ran:
        print(f"{TAG}: RESULT: PASS (source checks + lake build + axiom audit)")
    else:
        print(
            f"{TAG}: RESULT: PASS-PARTIAL (source-level checks only -- "
            "`lake build`/axiom audit SKIPPED, no Lean toolchain on PATH)"
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
