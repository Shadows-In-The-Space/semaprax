# Cross-language runnable adapter v1

Status: implemented local-fixture execution extension; external-language admission remains unavailable.

Audience: benchmark operators and reviewers of offline adapter provenance.

This reference defines `benchmark.cross_language.runnable_adapter.v1`. It is
an execution extension of the existing unavailable-only
[Agent Task Comparison v1](AGENT-TASK-COMPARISON-V1.md) baseline admission,
not a second corpus, identity parser, or equivalence policy. The baseline
descriptor remains authoritative for the canonical `tasks.json` bytes, exact
external subject, official source/revision, port order, port-tree digest,
oracle digest, and independently reviewed equivalence digest.

## Descriptor and admission

A descriptor is canonical UTF-8 JSON (`json.dumps(..., indent=2,
ensure_ascii=True)` plus one LF), at most 65,536 bytes, with exactly:

```json
{
  "schema": "benchmark.cross_language.runnable_adapter.v1",
  "baseline": { "...": "the unchanged baseline_admission v1 descriptor" },
  "execution": {
    "classification": "local_fixture",
    "adapter_id": "rust",
    "task_id": "sequence-digest-v1",
    "adapter_inventory_sha256": "sha256:...",
    "receipt": "bounded local receipt text",
    "receipt_sha256": "sha256:...",
    "timeout_seconds": 120
  }
}
```

The implementation passes `baseline` unchanged to
`agent.baseline_admission.admit_baseline_descriptor`; its successful result is
still `unavailable`, never execution evidence. It then verifies the canonical
owner inventory through that same module, the exact source adapter inventory
and its SHA-256 (the existing adapter inventory has no separate canonical JSON
renderer), one declared implemented adapter/task pair, a
bounded receipt (8,192 UTF-8 bytes), receipt SHA-256, and an integer timeout
from 1 through 120 seconds. No shell, environment interpolation, download,
installer, package manager, or caller-selected argv is accepted.

If the shared baseline gate refuses, this extension preserves its named
unavailable reason (for example `invalid_required_task_inventory`) rather
than replacing it with a second error taxonomy.

`classification` is currently closed to `local_fixture`. Any `external`
claim is refused as `external_execution_requires_provisioned_review`; this
prevents a locally present compiler, a mock, or the reserved Zero metadata
from becoming an external-language result by implication.

## Exact fixture execution

For an admitted local fixture, the extension runs exactly one existing
`run.py` pair using this argv shape:

```text
<current-python> benchmarks/cross-language-v1/run.py
  --root <repository-root>
  --tasks benchmarks/cross-language-v1/tasks.json
  --adapters benchmarks/cross-language-v1/adapters.json
  --only <admitted-task-id>
  --language <admitted-adapter-id>
  --output <exclusive-temporary-result.json>
```

The subprocess has the descriptor's maximum 120-second bound. The existing
scorer remains responsible for the two isolated public/hidden trees, declared
adapter build/run argv, success predicate, hidden-only leak check, observed
adapter version, source digests, and result schema. A successful fixture is
reported only as `fixture_ok`; it is not `ok` in a cross-language comparison
and cannot admit Zero, NTNT, Aver, Vera, Hale, or MoonBit.

Execution accepts only the committed repository root and the exact current
`tasks.json` and `adapters.json` bytes. A caller cannot point a valid
descriptor at a similarly shaped external tree or substitute matching-looking
inventory data after admission.

## Required future external evidence

An external-language extension requires a maintainer-reviewed versioned
successor that supplies all of the following for every canonical task in
owner order: independently reviewed port bytes and equivalence/oracle digests;
the official immutable source and revision already accepted by baseline
admission; an offline-provisioned toolchain artifact and installation receipt
whose bytes authenticate the declared digests; and a runner mapping to that
toolchain's documented bounded argv. It must retain all twelve task rows and
all six currently blocked adapter denominators unless their support decision
is independently changed.

The local Rust regression deliberately proves only that this extension really
replays the existing compiler, public/hidden, leak-check, and scoring path.
It is not an authenticated external toolchain, a Zero port, an equivalence
review, a benchmark measurement, or hosted evidence.
