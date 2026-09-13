"""Offline acceptance replay from bounded, authenticated pilot source archives.

This reuses the frozen task oracle. It supplies neither a blinded review nor
missing tool/context measurements, and never changes the original run record.
"""
import base64
import hashlib
import importlib.util
import json
from pathlib import Path, PurePosixPath
import tempfile
import time

ROOT = Path(__file__).resolve().parents[2]
CAP = 8 * 1024 * 1024


def load_json(path, cap):
    if path.is_symlink() or not path.is_file() or path.stat().st_nlink != 1 or path.stat().st_size > cap:
        raise ValueError("replay input is not bounded regular evidence")
    body = path.read_bytes()
    return json.loads(body), hashlib.sha256(body).hexdigest()


def decode_sources(rows):
    if not isinstance(rows, dict) or len(rows) > 64:
        raise ValueError("source inventory exceeds bound")
    result = {}
    total = 0
    for name, row in rows.items():
        path = PurePosixPath(name)
        if (not name or len(name.encode()) > 512 or path.is_absolute()
                or '..' in path.parts or path.as_posix() != name
                or not (path.suffix == '.spx' or path.name in ('semaprax.toml', 'semaprax.lock'))):
            raise ValueError("invalid candidate source path")
        if not isinstance(row, dict) or set(row) != {'base64', 'bytes', 'sha256'}:
            raise ValueError("invalid candidate source row")
        body = base64.b64decode(row['base64'], validate=True)
        total += len(body)
        if (total > CAP or row['bytes'] != len(body)
                or row['sha256'] != hashlib.sha256(body).hexdigest()):
            raise ValueError("candidate source identity differs")
        result[name] = body
    return result


def replay_candidate(evidence_dir, compiler):
    evidence = Path(evidence_dir)
    output = evidence / 'independent-acceptance-replay.json'
    if output.exists():
        raise ValueError("acceptance replay already exists")
    record, record_digest = load_json(evidence / 'record.json', 1024 * 1024)
    archive, archive_digest = load_json(evidence / 'candidate-source.json', 24 * 1024 * 1024)
    if archive_digest != record.get('candidate_archive', {}).get('sha256'):
        raise ValueError("candidate archive binding differs")
    if archive.get('schema') != 'semaprax.pilot-candidate-source.v1':
        raise ValueError("candidate archive schema differs")
    before = decode_sources(archive['before'])
    after = decode_sources(archive['after'])
    for label, sources in [('before', before), ('after', after)]:
        snapshot = record.get(label)
        if not isinstance(snapshot, dict):
            raise ValueError("original source snapshot absent")
        expected_sources = {name for name in snapshot if PurePosixPath(name).suffix == '.spx' or PurePosixPath(name).name in ('semaprax.toml', 'semaprax.lock')}
        if set(sources) != expected_sources:
            raise ValueError('candidate source inventory differs from original snapshot')
        for name, body in sources.items():
            if snapshot.get(name) != {'bytes': len(body), 'sha256': 'sha256:' + hashlib.sha256(body).hexdigest()}:
                raise ValueError("archived source differs from original snapshot")
    compiler = Path(compiler).resolve(strict=True)
    if hashlib.sha256(compiler.read_bytes()).hexdigest() != record['semaprax_sha256']:
        raise ValueError("compiler differs from frozen trial")
    spec = importlib.util.spec_from_file_location('pilot_replay_oracle', ROOT / 'scripts/agent-task-comparison-runner.py')
    runner = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(runner)
    _, _, tasks = runner.atc.load_manifest('benchmarks/agent-task-comparison-v1/manifest.json')
    binding = next(task for task in tasks if task['id'] == record['task'])
    started = time.monotonic_ns()
    with tempfile.TemporaryDirectory(prefix='spx-pilot-replay-') as directory:
        candidate = Path(directory)
        for name, body in after.items():
            path = candidate / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(body)
        # Authority inventory remains the original authenticated run snapshot.
        # Non-source artifacts are not fabricated in the reconstructed tree.
        result = runner.independent_acceptance(
            record['task'], candidate, record['drift_applications'], binding,
            record['before'], record['after'], compiler,
            None, None, record['after'],
        )
    elapsed = time.monotonic_ns() - started
    rows, review = result if isinstance(result, tuple) else (result, None)
    missing = sorted(set(record['after']) - set(after))
    derived = {
        'schema': 'semaprax.private-pilot-acceptance-replay.v1',
        'record_sha256': record_digest, 'candidate_archive_sha256': archive_digest,
        'compiler_sha256': record['semaprax_sha256'],
        'oracle_sha256': hashlib.sha256((ROOT / 'scripts/agent-task-comparison-runner.py').read_bytes()).hexdigest(),
        'oracle_rows': rows,
        'acceptance': [dict(row, outcome='unavailable') if row['id'] == 'authority' else row for row in rows],
        'review_package': review,
        'validation_wall_ns': elapsed, 'validation_wall_ms': elapsed // 1_000_000,
        'non_source_files_not_reconstructed': missing,
        'limitations': ['Existing task oracle results; review criterion is not blinded reviewer time.',
                       'Authority is unavailable: this does not replay OS confinement or the original repository after-state.',
                       'Stale detection criterion uses recorded drift count, not an inferred recovery metric.'],
        'eligible_observation': False,
    }
    with output.open('x', encoding='utf-8') as destination:
        destination.write(json.dumps(derived, sort_keys=True) + '\n')
    return derived
