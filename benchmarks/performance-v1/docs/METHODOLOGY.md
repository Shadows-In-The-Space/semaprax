# Benchmark Methodology

## Host

The host is not declared here; it is **recorded by the runner from the machine
that actually ran**, into the result document's `host` object: platform tag
(`darwin-arm64`, `linux-x86_64`, …), system, release, machine, logical CPU
count, load average at the start, an available-memory observation, and the
`rustc`, `cargo` and `clang` versions it observed. A Linux run therefore never
identifies itself as macOS.

`host.available_memory` is an object with `bytes` and `basis`. Linux uses the
kernel's `/proc/meminfo` `MemAvailable` estimate. macOS reports `vm_stat` free
plus inactive pages; inactive pages are not guaranteed immediately available,
and this does not claim to include all purgeable memory. Unsupported platforms,
probe failures, and malformed probe output record `{"bytes": null, "basis":
"unavailable"}` rather than an inferred zero.

`results/baseline.json` holds one recorded run of the committed inventory, and
[`results/baseline.md`](../results/baseline.md) renders it. The document names
the host, the load average at the start, the toolchain, the commit, whether that
tree was dirty and the binary digest — all observed, none declared here. A host
string with no measurements behind it is provenance without evidence, so a
baseline is recorded on an idle host or not at all.

All results are **local, single-host** evidence for one binary. They are not
hosted, release, or cross-platform claims.

## Microbenchmarks (`cargo bench`)

- Harness: `criterion 0.8.2` with `sample_size=100`, `warm_up_time=3s`,
  `measurement_time=5s`.
- Throughput is reported as `bytes/s` where the input is source bytes, or as
  evaluator steps/elements where the subject is execution; latency is `ns/op`.
- Each group name says what the sample includes: `cold` groups authenticate and
  analyse per sample, `retained` and `prepared` groups do that once in setup.
- Every group verifies its expected outcome before timing, and each benchmark id
  carries its work unit (source count, byte total, declarations, or evaluator
  steps).
- HTML reports are in `target/criterion/` and are not committed.

Bench groups:

- `compiler`: `parse` (lexer+parser), `verify` (type/effect/ownership),
  `graph` (semantic graph JSON), `format` (canonical), end-to-end `check`, over
  single-file examples.
- `interpreter`:
  - `interpreter-parse`, `interpreter-verify`: front-end phases over committed
    examples.
  - `interpreter-cold-end-to-end`: `interpreter::interpret(path, …)` — read,
    parse, verify, resolve, spawn the 64 MiB-stack evaluation thread, evaluate.
    This is one cold invocation's latency, not evaluator cost. Cases: a
    generated scalar loop, `ownership` (a program declaring an owned resource,
    its drop and a postcondition, so ownership analysis and cleanup planning are
    inside the sample while its evaluation is a constant), `math_algorithms`.
    Every committed subject must be one the interpreter admits from its entry
    point; `tests/documentation/benchmark_fixtures.rs` asserts that, because a
    rejected subject cannot be measured and Criterion timing does not run in a
    pull request. The group carried `text_analytics` until the suite was first
    executed: the interpreter rejects it with SPX-F102 `unsupported_callee`.
  - `interpreter-prepared-evaluator`: the same scalar loop as an authenticated
    Project, executed through `ProjectRevision::prepare_interpreter` — closures
    resolved once, worker retained — beside the retained-but-unprepared
    revision. The original traced and retained arms remain, with an additional
    `scalar-loop-untraced` prepared arm. Traced and untraced prepared execution
    must return identical outcomes and fuel facts before timing; their difference
    measures optional trace collection/rendering. The retained arm still includes
    closure admission, worker creation and a Project execution report, so its
    delta from the untraced prepared result is not an isolated preparation cost.
    No benchmark constructs unchecked HIR. This API/arm addition supplies no
    new measured speedup. `scalar-loop-cold-untraced` and
    `scalar-loop-cold-traced` authenticate, prepare, execute and drop the worker
    inside every timed sample. Each must return exactly the same product as
    its corresponding prepared arm (including full trace bytes when traced).
    The traced prepared arm still carries evidence work; compare matching
    traced/untraced modes for lifecycle costs.

    **#85 measurement** (`cargo bench --bench interpreter -- --quick`, release
    profile, 11-core host, load average 2.3–2.9 at start, rising to ~4.9 under
    concurrent unrelated builds on this shared checkout — not the quiet window
    a committed baseline requires): `scalar-loop` (traced) 18.3 ms vs
    `scalar-loop-untraced` 3.91 ms, against `scalar-loop-retained` (unprepared,
    untraced) at 3.91 ms in the same run. Untraced prepared execution lands
    exactly on the unprepared retained arm, and traced execution is ~4.7x that
    — so trace collection/rendering, not a defect in the prepared seam,
    accounts for the previously reported inversion. The same shape reproduces
    larger in `project-retained/apex-supply-chain` below (~93x). Tracing is
    genuinely this expensive; `execute_entry_untraced` (added for #85) is the
    correct fix, and it is now the arm to use whenever a caller does not need
    a `ProjectSourceTrace`.

    **#85 quiet-host repetition** (full `cargo bench --bench interpreter --
    interpreter-prepared-evaluator`, not `--quick`; release profile, 11-core
    host; load average **1.33 at start**, rising to ~3.6 from the benchmark
    process itself; **no concurrent cargo, rustc or criterion process on the
    host**, verified by `ps` before starting — this is the quiet window the
    measurements above lacked):

    | case | time (median, 95% CI) |
    |---|---|
    | `scalar-loop` (prepared, traced) | 17.430 ms [17.403, 17.460] |
    | `scalar-loop-untraced` (prepared, untraced) | 3.7927 ms [3.7765, 3.8203] |
    | `scalar-loop-retained` (unprepared, untraced) | 3.7621 ms [3.7438, 3.7946] |
    | `scalar-loop-cold-untraced` | 5.8668 ms [5.8520, 5.8837] |
    | `scalar-loop-cold-traced` | 19.727 ms [19.686, 19.771] |

    The untraced prepared arm and the unprepared retained arm are within
    0.8% of each other and their confidence intervals overlap, so they are
    indistinguishable at this resolution. Traced prepared execution is
    **4.60x** the untraced arm. **There is no inversion in the prepared
    seam**: the reported inversion was trace collection and rendering,
    entirely and measurably. This is now a citable figure, not an indicative
    one.
- `project`:
  - `project-cold-load`: `check`, `run` and `test` through
    `project::with_authenticated_project` for the shipped `calculator-project`
    and `apex-supply-chain` manifests — the whole per-invocation CLI cost.
  - `project-retained`: one retained revision: steady-state `execute_entry`,
    prepared-interpreter execution, and interpreter preparation itself.
    **#85 measurement** (`cargo bench --bench project -- --quick`, same
    profile and host, load average 4.9–5.4 at start — heavier than the
    interpreter run above, from concurrent unrelated builds on this shared
    checkout): `apex-supply-chain`
    `prepared-run` (traced) 1.88 ms vs `prepared-run-untraced` 20.2 µs vs
    `retained-run` (unprepared, untraced) 2.09 ms. The fixture's actual
    evaluator work is only tens of microseconds; almost the entire traced cost
    is building and rendering the trace, not evaluation. This is the same
    mechanism as `interpreter-prepared-evaluator`, at a larger ratio because
    this fixture does less real work per call.
  - `project-frontend-cache`: `ProjectFrontendCache` reanalysis at 1x/2x/4x of a
    generated multi-module fixture — cold, unchanged rebuild, one leaf edited,
    and the provider every module consumes edited. **#85 measurement** (same
    run): `cold` vs `rebuild-unchanged` was 2.81/2.79 ms at 1x, 5.44/5.30 ms at
    2x, 16.25/16.23 ms at 4x — rebuild-unchanged tracks `cold` rather than
    beating it, reproducing the shape #85 reported (no speedup despite
    `modules_parsed == 0`). This is not a defect to fix here:
    `docs/PROJECT-SEMANTIC-CACHE-V1.md#what-a-hit-is-worth` documents why an
    AST-cache hit is worth much less than it sounds — `lookup` in
    `src/project/incremental.rs` returns a deep clone of the whole cached
    `Program`, a cost of the same order as the parse it replaces, and the four
    full-cost phases (source verification, HIR validation, cross-file checks,
    link/profile admission) still run in full on every rebuild regardless of
    the hit. `modules_parsed: 0` is accurate about parsing being skipped; it is
    not a proxy for wall-clock savings.

    **#85 quiet-host repetition** (full `cargo bench --bench project`, not
    `--quick`; load average 1.33 at start, no concurrent cargo/rustc/criterion
    process, verified by `ps`):

    | scale | `cold` | `rebuild-unchanged` | delta |
    |---|---|---|---|
    | 1x (5 modules, 1241 B) | 2.8559 ms | 2.8182 ms | −1.3% |
    | 2x (7 modules, 2237 B) | 5.2210 ms | 5.1916 ms | −0.6% |
    | 4x (11 modules, 4229 B) | 16.434 ms | 16.211 ms | −1.4% |

    Parity at all three scales on a quiet host, so the earlier result was not
    contention noise: an unchanged rebuild genuinely costs what a cold one
    costs. The deep-clone `lookup` and the four uncached full-cost phases are
    the whole explanation, and they bound what any AST-cache hit can be worth
    until one of them changes. `project-retained/calculator-project` in the
    same run shows the other side of it: `prepared-run-untraced` at 5.085 µs
    against `retained-run` at 179.50 µs — **35x**, once tracing is not being
    paid for.

The generated fixture is ordinary canonical `.spx` source with an ordinary
`semaprax.project.v1` manifest. `tests/documentation/benchmark_fixtures.rs`
checks, runs and tests it, and pins the invalidation shape, so fixture validity
is covered without running a Criterion campaign in every pull request.

## Macrobenchmarks (`benchmarks/performance-v1/run.py`)

### What is timed

- The runner selects the measured compiler **before** any timing: either the
  binary given with `--semaprax PATH`, or the result of one
  `cargo build --locked -p semaprax --bin semaprax` whose own duration is
  recorded separately as `subject.build_ms`. Every sample is then one direct
  execution of that binary. No Cargo process, and no Cargo freshness check, is
  inside a sample.
- The result records what was measured: `subject.binary`, its `sha256` digest,
  the build `profile` (`debug`, `release` or `provided`), the reported
  `--version`, the `commit`, and whether the working tree was `dirty`.
- Timing is `time.perf_counter()` wall time over `repetitions` (default 5, or 2
  with `--quick`), reported as `p50`/`p95` with the raw `samples` and the
  `completed_samples` count.
- Digesting inputs, the expected-outcome verification run, and build-destination
  allocation all happen outside the timed region.

### Subject identity and drift

- A scenario's subject is its whole authenticated input closure, not one path. A
  project manifest does not bind its own sources, so the manifest and every
  source it declares are digested; `subject.digest` is one digest over that
  ordered list. Changing any included source changes the recorded identity.
- A scenario may declare `expected_digest`. A mismatch is reported as `drifted`
  and nothing is timed.
- The closure is digested again after the samples. If any byte changed during
  measurement the record becomes `drifted` and publishes no `wall_ms`.

### Outcomes

Every scenario declares an expected outcome (`"expect": "success"` by default,
`"failure"` where the diagnostic path is the subject). One untimed verification
run establishes the outcome before any sample is taken. The status is then one
of:

- `ok` — the expected outcome, with `wall_ms` and a completed sample count.
- `failed` — a wrong exit status or a timeout. It publishes **no** `wall_ms`;
  any observed times are kept under `observed_ms` for diagnosis only. Failures
  and drift make the runner exit non-zero.
- `skipped` — genuinely unsupported: the path is absent, or a tool the scenario
  declares in `requires` (for example `clang`) is not installed.
- `drifted` — the inputs did not match, or did not stay, what was measured.

### Builds

`build` scenarios run only with `--with-build`. Each repetition receives its own
freshly created temporary parent directory and writes to a not-yet-existing
`out` inside it, because publication requires a fresh destination. The runner
removes only the parent it created. The committed inventory contains web
(single-file and project) and native project builds; the native one declares
`requires: ["clang"]` and is skipped where Clang is absent.

## JSON Schema (`benchmark.performance.v2`)

```json
{
  "schema": "benchmark.performance.v2",
  "timestamp": "2026-09-05T18:00:00Z",
  "host": {"platform": "linux-x86_64", "system": "Linux", "release": "6.8.0",
           "machine": "x86_64", "cpu_count": 16, "python": "3.12.3",
           "rustc": "rustc 1.88.0 (…)", "cargo": "cargo 1.88.0 (…)",
           "clang": "clang version 18.1.3", "load_average": [0.2, 0.3, 0.4],
           "available_memory": {"bytes": 123456789, "basis": "linux:/proc/meminfo:MemAvailable"}},
  "subject": {"binary": "/…/target/debug/semaprax", "digest": "sha256:…",
              "profile": "debug", "build_ms": 41234.0,
              "version": "semaprax 0.3.0", "commit": "…", "dirty": false},
  "timing": {"clock": "time.perf_counter",
             "measures": "one direct execution of the selected semaprax binary",
             "excludes": "cargo startup, compiler build, input digesting, and the untimed verification run",
             "timeout_seconds": 120},
  "summary": {"ok": 22, "failed": 0, "skipped": 3, "drifted": 0},
  "scenarios": [
    {
      "id": "check-meaning",
      "command": "check",
      "kind": "single",
      "path": "examples/meaning.spx",
      "args": [],
      "expect": "success",
      "repetitions": 5,
      "completed_samples": 5,
      "subject": {"digest": "sha256:…",
                  "inputs": [{"path": "examples/meaning.spx", "digest": "sha256:42aeae…"}]},
      "verification": {"status": "ok", "reason": ""},
      "status": "ok",
      "wall_ms": {"p50": 12, "p95": 15, "samples": [11, 12, 12, 13, 15]}
    }
  ]
}
```

The file is canonical JSON (sorted keys, 2-space indent, terminal LF).
`--markdown PATH` renders the same document as a table.

## Comparison

```sh
python3 benchmarks/performance-v1/run.py \
  --compare benchmarks/performance-v1/results/baseline.json --output /tmp/compare.json
```

Only compatible successful pairs are scored: both sides `ok`, the same command
and arguments, the same subject digest, and both carrying timing. Anything else
is reported as `incomparable` with a reason, so a fast failure can never be
scored as an improvement. For a scored pair the comparator computes
`delta = (local.p50 - baseline.p50)/baseline.p50` and reports `regression` above
`+15%` or `improvement` below `-15%`. Comparing against a baseline that holds no
recorded measurement is an error, not an empty comparison. Wall-time thresholds
stay advisory across heterogeneous hosts; the runner's exit status reflects
result accounting (failures and drift), not speed.

## Non-claims

- No benchmark is in the blocking `quality` gate. Host variance, thermal
  throttling, and background load make it flaky as a gate.
- Results are **not** normalized for CPU frequency or cross-platform
  comparison. A `debug` subject and a `release` subject are different subjects.
- `build` scenarios depend on the host Clang/wasm toolchain and are `skipped`
  where a declared tool is absent.
- Semantic benchmarks in `benchmarks/` (agent context, task comparison)
  remain separate and are not measured here.

## Reproducibility

Every scenario authenticates its whole input closure before timing and again
afterwards:

```sh
sha256sum examples/meaning.spx
python3 benchmarks/performance-v1/run.py --dry-run --output /tmp/plan.json
```

The plan reports each scenario's `subject.inputs` with their digests and the
`subject.digest` over them. Those digests must match `sha256sum`. A recorded
`expected_digest` that does not match, or any input that changes during the run,
fails the scenario closed as `drifted`.

## Adding a microbenchmark

Add a function to `benches/compiler.rs` (or `interpreter.rs`, `project.rs`):

```rust
fn bench_parse(c: &mut Criterion) {
    let source = std::fs::read_to_string("examples/meaning.spx").unwrap();
    c.bench_function("parse-meaning", |b| b.iter(|| parse(&source, Path::new("examples/meaning.spx")).unwrap()));
}
```

Register it in `criterion_group!(benches, bench_parse, …)`.

## Adding a macro scenario

Add an entry to `benchmarks/performance-v1/scenarios.json`:

```json
{"id": "check-new-example", "kind": "single", "path": "examples/new.spx", "command": "check", "repetitions": 5}
```

Optional keys: `"args"`, `"expect": "failure"` where the diagnostic path is the
subject, `"requires": ["clang"]` for an external tool, and `"expected_digest"`
to pin the subject bytes. Confirm the entry resolves and identify its subject:

```sh
python3 benchmarks/performance-v1/run.py --dry-run --output /tmp/plan.json
python3 benchmarks/performance-v1/run.py --only check-new-example \
  --semaprax target/debug/semaprax --output /tmp/one.json
```

Regenerating `results/baseline.json` is a separate act: do it on an idle host
from a clean checkout, and commit `baseline.json` with its `--markdown`
rendering. Numbers from a loaded shared machine are not a baseline.
