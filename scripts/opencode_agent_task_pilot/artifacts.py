"""Bounded, read-only candidate capture for independent pilot review.

The byte archive is authoritative evidence; its human-readable diff is only a
projection. Neither file is an acceptance verdict or reviewer-time observation.
"""
import base64
import difflib
import hashlib
import json
import os
from pathlib import Path
import stat

MAX_FILES = 64
MAX_BYTES = 8 * 1024 * 1024


def collect_source_bytes(candidate):
    root = Path(candidate)
    result = {}
    total = 0
    for path in sorted(root.rglob("*")):
        if path.is_symlink():
            raise ValueError("candidate contains a symlink")
        if not (path.suffix == ".spx" or path.name in ("semaprax.toml", "semaprax.lock")):
            continue
        relative = path.relative_to(root).as_posix()
        if len(relative.encode()) > 512 or len(result) >= MAX_FILES:
            raise ValueError("candidate source inventory exceeds bound")
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, "rb") as stream:
            info = os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                raise ValueError("candidate source must be a single-link regular file")
            if info.st_size > MAX_BYTES - total:
                raise ValueError("candidate source bytes exceed bound")
            body = stream.read(MAX_BYTES - total + 1)
        total += len(body)
        if total > MAX_BYTES:
            raise ValueError("candidate source bytes exceed bound")
        result[relative] = body
    return result


def archive_candidate(candidate, evidence_dir, baseline):
    """Archive exact baseline/final source bytes and a blinded source diff.

    Returns a compact archive identity. Call after the candidate process has
    stopped, while its sandbox still exists. Acceptance runs separately against
    that sandbox; missing review/measurements must remain explicitly missing.
    """
    after = collect_source_bytes(candidate)
    def encoded(files):
        return {name: {"base64": base64.b64encode(body).decode("ascii"),
                       "bytes": len(body), "sha256": hashlib.sha256(body).hexdigest()}
                for name, body in sorted(files.items())}
    archive = {"schema": "semaprax.pilot-candidate-source.v1",
               "before": encoded(baseline), "after": encoded(after)}
    body = (json.dumps(archive, sort_keys=True, separators=(",", ":")) + "\n").encode()
    directory = Path(evidence_dir)
    with (directory / "candidate-source.json").open("xb") as stream:
        stream.write(body)
    diff = []
    for name in sorted(set(baseline) | set(after)):
        old = baseline.get(name, b"").decode("utf-8", errors="replace")
        new = after.get(name, b"").decode("utf-8", errors="replace")
        diff.extend(difflib.unified_diff(old.splitlines(keepends=True),
                                         new.splitlines(keepends=True),
                                         fromfile="before/" + name, tofile="after/" + name))
    with (directory / "candidate.diff").open("x", encoding="utf-8") as stream:
        stream.write("".join(diff))
    return {"path": "candidate-source.json", "bytes": len(body),
            "sha256": hashlib.sha256(body).hexdigest(),
            "diff": "candidate.diff", "review": "not_observed"}
