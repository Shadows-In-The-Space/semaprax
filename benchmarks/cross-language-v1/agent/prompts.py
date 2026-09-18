"""Deterministic prompt construction.

The prompt a solver (real or replayed) receives for a (task, language) pair
is built only from files a public solver is allowed to see: the task's own
`EQUIVALENCE.md` and the *scaffold* files already present in
`public/<language>/` (the files the solver is not asked to (re)write). It
never reads the `hidden/` directory — the same isolation `run.py::stage`
already enforces for the build/run phase, enforced here one step earlier, at
prompt-construction time, so a hidden vector cannot leak into the prompt
even before a scratch tree exists.

Construction is order-independent input, order-deterministic output: files
are read in sorted relative-path order, so the exact prompt text (and its
digest, `SolverRequest.prompt_digest`) is stable across hosts and runs.
"""
from __future__ import annotations

import pathlib


def build_prompt(
    task_id: str,
    language: str,
    equivalence_text: str,
    public_dir: pathlib.Path,
    candidate_relative_paths,
) -> str:
    """`public_dir` is the task's public source tree; every file in it
    *other than* `candidate_relative_paths` is scaffold the solver sees as
    already written (test harness, helper modules). `candidate_relative_paths`
    names the relative path(s), sorted by the caller, the solver must
    produce — their current on-disk content (if any) is never shown, so a
    solver cannot anchor on a pre-existing reference answer. Neither section
    is ever read from `hidden/`.
    """
    excluded = set(candidate_relative_paths)
    sections = [
        f"# Cross-language benchmark task: {task_id} ({language})",
        "",
        "## Equivalence contract",
        equivalence_text.strip(),
        "",
        "## Scaffold already provided (do not rewrite)",
    ]
    scaffold_found = False
    if public_dir.is_dir():
        for path in sorted(public_dir.rglob("*")):
            if path.is_file():
                relative = path.relative_to(public_dir).as_posix()
                if relative in excluded:
                    continue
                scaffold_found = True
                sections.append(f"### {relative}")
                sections.append(path.read_text())
    if not scaffold_found:
        sections.append("(none)")
    sections.append("")
    sections.append("## Files you must produce")
    for relative in sorted(candidate_relative_paths):
        sections.append(f"- {relative}")
    sections.append("")
    return "\n".join(sections)
