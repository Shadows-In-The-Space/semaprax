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


def _exclusive_bytes(path, body):
    fd = None
    created = False
    try:
        if not hasattr(os, "O_NOFOLLOW"):
            raise ValueError("safe no-follow archive writes are unavailable")
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        created = True
        written = 0
        while written < len(body):
            count = os.write(fd, body[written:])
            if count <= 0:
                raise ValueError("archive write made no progress")
            written += count
    except (OSError, ValueError):
        if created:
            try:
                held = os.fstat(fd)
                current = os.stat(path, follow_symlinks=False)
                if (held.st_dev, held.st_ino) == (current.st_dev, current.st_ino):
                    os.unlink(path)
            except OSError:
                pass
        raise
    finally:
        if fd is not None:
            os.close(fd)


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
        if not hasattr(os, "O_NOFOLLOW"):
            raise ValueError("safe no-follow source reads are unavailable")
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, "rb") as stream:
            info = os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                raise ValueError("candidate source must be a single-link regular file")
            if info.st_size > MAX_BYTES - total:
                raise ValueError("candidate source bytes exceed bound")
            body = stream.read(MAX_BYTES - total + 1)
            stream.seek(0)
            confirmation = stream.read(MAX_BYTES - total + 1)
            final = os.fstat(stream.fileno())
            if body != confirmation or (info.st_dev, info.st_ino, info.st_size) != (final.st_dev, final.st_ino, final.st_size):
                raise ValueError("candidate source changed during held read")
            rebound = os.stat(path, follow_symlinks=False)
            if (rebound.st_dev, rebound.st_ino) != (info.st_dev, info.st_ino):
                raise ValueError("candidate source path changed during held read")
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
    _exclusive_bytes(directory / "candidate-source.json", body)
    diff = []
    for name in sorted(set(baseline) | set(after)):
        old = baseline.get(name, b"").decode("utf-8", errors="replace")
        new = after.get(name, b"").decode("utf-8", errors="replace")
        diff.extend(difflib.unified_diff(old.splitlines(keepends=True),
                                         new.splitlines(keepends=True),
                                         fromfile="before/" + name, tofile="after/" + name))
    _exclusive_bytes(directory / "candidate.diff", "".join(diff).encode("utf-8"))
    return {"path": "candidate-source.json", "bytes": len(body),
            "sha256": hashlib.sha256(body).hexdigest(),
            "diff": "candidate.diff", "review": "not_observed"}
