# Workflow Profiling v1

Status: **experimental, opt-in benchmark instrumentation**.

Audience: compiler contributors and performance operators.

Workflow profiling records bounded timing observations around selected compiler,
project, and prepared-interpreter stages. It is a diagnostic aid for local
performance investigation. It is not a language feature, a semantic profile,
or an authorization mechanism.

## Enabling the observer

The `unstable-workflow-profiling` Cargo feature is deliberately absent from the
default feature set. A normal build therefore contains no active workflow
observer and no profiling overhead at the instrumentation sites. The
`workflow_observer` benchmark also declares this feature as a required feature;
it must be enabled explicitly when building or running that target.

The feature exposes `semaprax::workflow_profile::capture`, `Observation`, and
the closed `Stage` inventory to the benchmark host. Instrumentation is compiled
at the selected sites only when the feature is enabled. The current stage
inventory is:

`parse`, `canonicalize`, `resolve`, `hir_validate`, `workspace_preflight`,
`project_link`, `graph_render`, `analysis_index`, `target_admission`,
`image_derivation`, `interpreter_preparation`, and `prepared_execution`.

Changing that inventory is a schema change for
`benchmark.workflow-observation.v1`; consumers fail closed on stage drift.

## Observation semantics

`capture` measures one synchronous operation with `std::time::Instant` and
stores its session in thread-local state. `Observation.total_ns` is elapsed wall
time for the whole closure. Each stage reports its call count, inclusive wall
time, and self wall time. Inclusive time includes nested instrumented stages;
self time subtracts nested instrumented time on the same thread. The sum of
self times is therefore useful for the closed instrumentation sites, but it is
not exhaustive CPU attribution.

The observer follows the thread on which `capture` runs. Work performed by a
worker thread is not traced as a separate interior: when the caller waits for a
worker, that wait is part of the caller's enclosing span. A capture started on a
child thread has an independent thread-local session and does not appear in the
parent's observation. Scheduling, blocking, preemption, and other host effects
remain in the wall-clock values.

Captures cannot be nested. A nested call returns `CaptureBusy` without running
its closure. The session is cleaned up on unwinding, so a panic does not leave
observation state active for later work. These refusal and unwind paths are
observability behavior; they do not turn a failed operation into a successful
measurement.

## Bounds and completeness

The enabled observer accepts at most 64 simultaneously open span frames and
1,000,000 span entries per capture. When either bound is reached, the live
operation continues, but additional spans are omitted and the observation is
marked `complete: false`. A malformed span drop also marks the observation
incomplete. The benchmark host asserts completeness and the campaign validator
rejects any incomplete sample, so truncated data cannot be summarized as a
normal observation.

The limits are an evidence bound, not a limit on compiler or interpreter
behavior. `complete: true` means that the bounded observer recorded all spans
that were opened at its instrumented sites for that capture and closed its
stack consistently. It does not mean that all work, all threads, or all CPU
activity was measured.

## Product equality and authority boundary

Timing is collected around ordinary operations and does not define their
results. The workflow observer compares the products of cold and warm frontend
arms, and compares traced and untraced execution outcomes; it also retains a
plain uncaptured timing for comparison. Those equality checks are the benchmark
fixture's guards against changing the product while observing it. They are not
proof that two arbitrary implementations are equivalent.

Observations carry no compiler, validation, execution, filesystem, workspace,
commit, or publication authority. They do not enter canonical source,
canonical formatting, semantic graph JSON, Wasm bytes, diagnostics, project
revisions, execution traces, or other generated artifacts. Recording or
serializing an observation cannot admit a target, authorize a transaction,
change an `ACTIVE` generation, or promote evidence. The observer is a benchmark
host facility and must not be used as a substitute for the ordinary locks,
checks, or commit boundaries.

## Campaign protocol and non-claims

`benchmarks/performance-v1/observe-workflows.py` launches the already-built
observer independently for each campaign, records the observer binary digest,
source inventory digest, commit, dirty-tree state, profile, host facts, and
configuration, and fails closed on source or binary drift. It requires a quiet
host before and after each campaign, bounds campaigns to 1–5 and samples to
1–20, rejects malformed or incomplete documents, and emits
`benchmark.workflow-campaign.v1`. A campaign is `quiet_observed` only after all
requested campaigns pass these checks; `nonquiet`, `failed`, and `drifted`
results are diagnostic evidence and are not successful measurements.

An observation or campaign does not claim:

- a hosted, cross-platform, physical-device, or production result;
- a speedup, regression, capacity limit, or ranking for real deployments;
- stable absolute performance across hosts, kernels, toolchains, profiles, or
  builds;
- exhaustive CPU, wall-clock, allocation, I/O, or worker-thread attribution;
- that an instrumented timing equals the performance of an uninstrumented
  release build; or
- that a quiet host removes all scheduler, thermal, cache, or background-work
  variance.

Use the values to compare like-for-like observations with the recorded subject,
fixture, profile, and host metadata. Product equality is a separate invariant
from timing equality, and neither one upgrades local benchmark evidence into a
semantic, hosted, or production claim.
