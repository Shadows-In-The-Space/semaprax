"""Loads `run.py` (the sibling harness this package never modifies) as a
module, without mutating `sys.path` or claiming a generic module name that
could collide with something else already imported under that name.

Reusing `run.py`'s functions directly — rather than reimplementing
`digest_tree`, the leak check, or the build/test `stage` step — is
deliberate: `AGENTS.md` prohibits weakening or reinterpreting the existing
leak check and provenance computation, and the surest way not to weaken code
is to call the same code, not a second copy of it that could quietly drift.
"""
from __future__ import annotations

import importlib.util
import pathlib

_SUITE = pathlib.Path(__file__).resolve().parent.parent
_RUN_PY = _SUITE / "run.py"

_module = None


def run_module():
    global _module
    if _module is None:
        spec = importlib.util.spec_from_file_location("cross_language_v1_run", _RUN_PY)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        _module = module
    return _module


def suite_dir() -> pathlib.Path:
    return _SUITE


def repo_root() -> pathlib.Path:
    return _SUITE.parent.parent
