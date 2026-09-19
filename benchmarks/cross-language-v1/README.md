# Cross-language benchmark laboratory (v1)

This suite is the **laboratory**, not a result: the harness, the task and
adapter inventories, the provenance binding, and the comparison/regression
logic that issue #211 asks for.

**What is, and is not, "Agent" here.** `run.py` (this directory's original
harness) scores a fixed, human-written source tree through each language's
official toolchain. It has no model, no provider, no sampling parameters, and
no budget anywhere in it — it is a cross-language *toolchain-conformance and
scoring* harness, not something that has ever run a model. `agent/` (added
alongside it) is the seam an Agent-driven run would go through: an explicit
solver-request/response contract, a deterministic offline replay transport
that exercises that whole path end to end with no credentials and no
network, and a declared-but-inert live-provider transport that has never
been executed against a real endpoint in this repository. **No result in
this directory or in `results/` was ever produced by a real model.** See
[`agent/README.md`](agent/README.md) for that seam's design and non-claims,
and [Non-claims](#non-claims) below for the rest (timing, single-host
evidence, and the six unimplemented languages). See
[`docs/METHODOLOGY.md`](docs/METHODOLOGY.md) for the full equivalence
contract, provenance model, and what a future quiet-host or credentialed run
must do to produce real numbers.

## Layout

| Path | Role |
| --- | --- |
| `run.py` | The toolchain-conformance harness: resolves tasks/adapters, builds and tests each task/language pair against a fixed, human-written source tree, records provenance, scores comparisons. No model involved. |
| `agent/` | The agent-driver seam: explicit model/sampling/budget contracts, a deterministic offline replay transport, a declared-but-inert live transport, and an orchestrator that scores a transport-produced candidate through `run.py`'s own build/test/leak-check/provenance machinery. See `agent/README.md`. |
| `tasks.json` | Task inventory (schema `benchmark.cross_language.tasks.v1`). Each task declares a `split` — `development` (the frozen original pilot) or `held_out` (issue #106's contamination-protected extension; see that task's `EQUIVALENCE.md`) — and both its pre-existing five-value `category` and an additive `issue_211_category` naming which of issue #211's eleven task categories it demonstrates; see `docs/METHODOLOGY.md`'s "Taxonomy mapping" section for the full table and reasoning, including why `category` itself is never rewritten |
| `adapters.json` | Per-language adapter inventory (schema `benchmark.cross_language.adapters.v1`): official toolchain invocation, version probe, success signal |
| `tasks/<task-id>/EQUIVALENCE.md` | That task's fairness contract: inputs, outputs, measured boundary, allowed optimizations |
| `tasks/<task-id>/public/<language>/` | The source tree a solver (human or Agent) would author against |
| `tasks/<task-id>/hidden/<language>/` | Files that overlay (same relative path replaces, new paths add) the public tree for scoring only; never copied into the public build step |
| `results/` | Where a real run's output JSON goes; empty in this commit (see Non-claims) |

## Quick start

```sh
# Plan only: resolve every task/language pair, run nothing.
python3 benchmarks/cross-language-v1/run.py --dry-run --output /tmp/plan.json

# Score every implemented adapter against the committed pilot task.
python3 benchmarks/cross-language-v1/run.py \
  --semaprax target/debug/semaprax \
  --output /tmp/result.json

# Restrict to one task or one language.
python3 benchmarks/cross-language-v1/run.py --semaprax target/debug/semaprax \
  --only sequence-digest-v1 --language rust --output /tmp/rust-only.json

# Compare a run against a prior recorded result (pass/fail regression only;
# there is no timing field to compare in this schema version).
python3 benchmarks/cross-language-v1/run.py --semaprax target/debug/semaprax \
  --output /tmp/local.json --compare benchmarks/cross-language-v1/results/prior.json
```

## Languages

Nine languages are on the roster in `adapters.json`, matching issue #211's
initial list: SEMAPRAX, Zero, NTNT, Aver, Vera, Hale, MoonBit, Rust, and
TypeScript. Three are wired (`"implemented": true`) with a real, working
official-toolchain adapter today: **SEMAPRAX**, **Rust**, and **TypeScript**.
The other six are declared with an honest `blocked_reason` and never scored
as a pass or a fail — the harness reports them as `blocked`, distinctly from
`ok` or `failed`. Wiring one is a scoped, mechanical follow-up once its
official toolchain is available in a pinned, network-free form (see
`adapters.json` and `docs/METHODOLOGY.md`).

## Non-claims

- **No Agent-driven result in this directory was ever produced by a real
  model.** `agent/`'s replay transport is a deterministic, hand-authored
  script standing in for a model response, the same way
  `tests/documentation/cross_language_benchmark_suite.rs`'s `MockLanguage`
  stands in for a real language toolchain to pin the harness's own logic —
  never a recorded real-model transcript. `agent/`'s live transport is
  declared and has never been executed against a real endpoint: it refuses
  to construct without explicit credentials (never an environment-variable
  fallback) and refuses to run even when credentials are supplied, because
  this repository has never verified its wire mapping against a real
  response. A live, credentialed, two-model pilot stays
  `HUMAN_BLOCKED: model budget and credentials`, exactly as before — this
  seam makes that pilot's eventual code path testable today, it does not
  perform it. See `agent/README.md`.
- **No timing was measured to produce this suite, and none is committed.**
  This host runs many concurrent build lanes at once; a wall-clock number
  measured here would record contention, not the compiler or the language
  runtime. The result schema (`benchmark.cross_language.v1`) has no field to
  receive one by accident — see `docs/METHODOLOGY.md`. Issues #85, #130, and
  #131 own adding a timing metric once an exclusive quiet host is available.
- The original pilot task (`sequence-digest-v1`, `split: development`) is
  real, small, and deliberately narrow (see its `EQUIVALENCE.md`). It is
  evidence that the harness works end to end for three real languages, not a
  claim that SEMAPRAX outperforms or underperforms Rust or TypeScript at
  anything. It stays frozen; issue #106's held-out extension
  (`bounded-counter-repair-v1`, `split: held_out`) is added alongside it, not
  in place of it — see `tasks/bounded-counter-repair-v1/EQUIVALENCE.md`'s
  "Held-out discipline" section for what that split declaration commits to.
  `concurrent-delta-merge-v1` is a further held-out addition purpose-built
  for issue #211's "concurrent change" category (`docs/METHODOLOGY.md`'s
  "Taxonomy mapping" section); it is evidence the harness's leak check and
  provenance binding hold for a newly-authored task, not a performance claim
  either.
- This is local, single-host evidence for whichever toolchain versions
  happen to be installed on the run host, recorded, not pinned by a lockfile
  or a container image. Containerized/pinned environments are in issue
  #211's scope and are not built here (see `docs/METHODOLOGY.md`'s
  "What remains for a quiet-host run" section).
