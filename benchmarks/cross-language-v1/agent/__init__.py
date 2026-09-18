"""Agent-driver seam for the cross-language benchmark laboratory (issue #211).

`benchmarks/cross-language-v1/run.py` scores a *fixed, human-written* source
tree against each language's official toolchain. It has no model, provider,
sampling, or budget concept anywhere in it, and no code path invokes a model:
it is a toolchain-conformance harness, not an Agent harness.

This package adds the missing seam without touching `run.py`'s existing CLI
or behavior (other workers' tests invoke `run.py` directly and pin its exact
flags and output schema). It defines:

- `contracts`: the explicit, recorded solver request/response shapes — model
  identity, sampling, and budgets are constructor arguments, never read from
  an environment variable or other ambient source.
- `budget`: a `BudgetLedger` that charges token/retry/cost usage against a
  declared `Budget` and fails closed (raises) the instant a ceiling would be
  crossed, before any further attempt runs.
- `transport`: the abstract `SolverTransport` seam plus its exceptions.
- `replay_transport`: a deterministic, offline transport that replays a
  committed JSON fixture — no network, no credentials, fully testable in CI.
- `live_transport`: a transport for a real provider call. Declared, never
  exercised in this repository: it refuses to run without explicitly
  supplied credentials, and even then refuses to guess at an unverified wire
  protocol rather than shipping an untested "capability". See its module
  docstring.
- `orchestrator`: wires a transport's `SolverResponse` into `run.py`'s
  existing build/test/leak-check/provenance machinery (imported, not
  reimplemented) to score a solver-produced candidate exactly as strictly as
  a human-written one.

See `benchmarks/cross-language-v1/agent/README.md` for the full design and
non-claims, and `benchmarks/cross-language-v1/docs/METHODOLOGY.md`'s "Agent
driver seam" section for how this fits the rest of the laboratory.
"""
