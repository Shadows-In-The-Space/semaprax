# Paired coding-agent pilot — 13 September 2026

All 18 expected tuples are accounted for exactly once. No candidate passed all
task acceptance checks (0/18). Four processes completed and 14 timed out;
process completion is not task acceptance. There were 1,180 MCP calls, including
757 failed calls.

This private pilot executed the existing three tasks in both available Semaprax
lanes with three repetitions. It supplies descriptive failed-run evidence;
it does not establish model productivity, lane superiority, statistical
significance, Zero parity, hosted support, or public benchmark eligibility.

The runner/configuration was frozen at `b8e7ccca19c715c1c835268e22c5cbdfbac3e365`,
using compiler `06bec1c29adc0cc9c28671ba64bb2e7975a3381f`, SHA-256
`0f256f0d3fbf142752558557f5da8e67500dce3e65e00c16fb5e674590214ae1`.
The model was `opencode/muse-spark-1.3-contributor-free` through OpenCode 1.18.27,
with its default decoding and no overrides. Every tuple used fresh isolated
state, the same task/fixture/model policy, and a 180-second model-run timeout.
The host was macOS 26.5.1 arm64. One serial model process ran alongside bounded
compiler implementation/build work; this is not quiet-host performance evidence.
The frozen schedule rotates tasks and alternates paired lane order (graph first
in five pairs, source first in four). Its SHA-256 is
`5befd9616d74cd711db78e9eeacc586d881917bda29cc6b811c9c0c2ff6c4b65`.

All observations remain **ineligible**: blinded active-review time, exact
model-presentation context bytes, complete typed stale/recovery metrics, and
an intervention ledger were not recorded. No missing metric is filled with
zero. The existing eligible-matrix report command cannot produce a complete
eligible report from these records. Its contract is unchanged.

Each candidate was independently replayed from its archived source inventory
bound to the original record and frozen compiler hash. Timeout and failure
records were not rewritten. Replay validates the existing task oracles; their
`review` row is a source-presence criterion, not blinded review, and their
`stale-detection` row uses the recorded drift count, not proof of model recovery.
Authority is unavailable in offline replay, because it does not reproduce the
original OS confinement/after-state. Original transport authority results remain
in the original records.

Token columns sum completed CLI-reported steps. OpenCode subtracts cache tokens
from `input` and reasoning from `output`; the separate stream-v2 derivative adds
those components back and retains each component, following the
[OpenCode normalization implementation](https://github.com/anomalyco/opencode/blob/v1.18.27/packages/opencode/src/session/session.ts). These are configured-model
CLI reports, not independent provider authentication. For timed-out runs,
unreported in-flight usage remains unknown, so these are not complete billing
or cost estimates. MCP counts and wire bytes come from the retained actual
`tools/call` frames, not inferred gateway calls.

## Per-tuple results

Every row failed full task acceptance and is ineligible. `completed` and
`failed` describe the process outcome; all failed processes hit the frozen
timeout. Token columns retain completed-step reports, including failed runs.

| Order | Task | Lane | Trial | Process | Wall ms | MCP calls | Failed calls | Reported input / output tokens |
|---|---|---|---|---|---:|---:|---:|---:|
| 1 | signature | graph | 1 | completed | 117342 | 61 | 32 | 421767 / 11758 |
| 2 | signature | source | 1 | failed | 180037 | 22 | 14 | 53317 / 2664 |
| 3 | stale-signature-recovery | source | 1 | failed | 180029 | 54 | 39 | 111912 / 13443 |
| 4 | stale-signature-recovery | graph | 1 | completed | 172010 | 87 | 51 | 862795 / 17444 |
| 5 | owned-signature | graph | 1 | failed | 180020 | 129 | 91 | 1066157 / 20488 |
| 6 | owned-signature | source | 1 | failed | 180040 | 47 | 28 | 122494 / 6808 |
| 7 | stale-signature-recovery | source | 2 | failed | 180031 | 38 | 22 | 152904 / 14706 |
| 8 | stale-signature-recovery | graph | 2 | failed | 180020 | 119 | 89 | 842918 / 18732 |
| 9 | owned-signature | graph | 2 | completed | 137149 | 56 | 22 | 528043 / 12627 |
| 10 | owned-signature | source | 2 | failed | 180033 | 48 | 32 | 158367 / 24685 |
| 11 | signature | source | 2 | failed | 180025 | 46 | 33 | 81969 / 6053 |
| 12 | signature | graph | 2 | failed | 180032 | 89 | 52 | 687657 / 14180 |
| 13 | owned-signature | graph | 3 | failed | 180039 | 120 | 84 | 931833 / 20687 |
| 14 | owned-signature | source | 3 | failed | 180021 | 54 | 40 | 85764 / 8072 |
| 15 | signature | source | 3 | failed | 180028 | 51 | 35 | 232202 / 10828 |
| 16 | signature | graph | 3 | failed | 180027 | 24 | 15 | 39583 / 2968 |
| 17 | stale-signature-recovery | graph | 3 | completed | 141317 | 89 | 48 | 719631 / 16050 |
| 18 | stale-signature-recovery | source | 3 | failed | 180031 | 46 | 30 | 119375 / 24291 |

## Prioritized observed blockers

1. **Harness/tool discoverability (#105).** Graph trials attempted permitted
   actions using unsupported command shapes or write paths. In tuple 09, repeated
   `pilot-write patch.json`, `review.json`, `proposal.json` and related requests
   were refused. The frozen tool description omitted the required `.pilot/`
   directory, and the refusal did not explain it. Top-level `--help` was denied,
   although individual compiler-command help was available. Fix these routes
   before a separately frozen follow-up cohort; do not change this cohort's
   configuration or attribute every denial solely to the model.
2. **Incorrect model edits and identity preservation (#105).** Source owned
   trial 2 (tuple 10) changed persistent `benchmark.owned.*` IDs into
   `benchmark.own.*`, leaving cross-module references stale while attempting
   the parameter reorder. The retained candidate.diff reproduces this failure;
   independent signature, identity, callers, ownership and meaning checks failed.
3. **No demonstrated stale recovery (#105).** All stale candidates examined
   retained the harness drift but failed the requested migration/recovery oracle.
   A positive drift-count criterion is not a successful stale transaction or
   preserved user work. Keep those measures distinct in the next capture.
4. **Measurement infrastructure (#105).** Long OpenCode exports truncated at
   exactly 65,536 bytes; timeouts often lacked an export/session field. Raw streams
   and candidate archives enabled separately labeled counter derivation and
   acceptance replay. Missing context, review and intervention measurements
   still prevent eligible aggregation. Add them before rerunning the pilot.
5. **Language/runtime attribution remains unproven.** Compiler diagnostics such
   as standalone library graph refusal (SPX-T105) and project-import graph
   guidance (SPX-G172) were observed while models explored unsupported command
   shapes. These traces do not establish a missing language feature or justify
   changing semantics. Reproduce a valid intended operation before assigning a
   compiler defect or widening an admitted profile.

Two earlier setup failures are retained separately: `pilot-06bec1c2-01` used the
wrong executable path as its MCP server, and `pilot-96f90af1-01` hit confined
`/dev/null` refusal. Fixes 169f7d08/b8e7ccca were validated with a local no-model
MCP probe before freezing this cohort. Neither setup failure substitutes for an
expected tuple, and no failed model trial was discarded or silently replaced.

## Retained artifacts

Original evidence is local under `benchmarks/agent-task-comparison-v1/evidence/`
with directories `pilot-b8e7ccca-01` through `-18`. Each contains raw record,
stdout/stderr, gateway and MCP wire archives, candidate source/diff, and available
session data. Separate `provider-usage-stream-v2.json` and
`independent-acceptance-replay.json` files retain derivation provenance. The
[committed companion index](../benchmarks/agent-task-comparison-v1/pilot-2026-09-13.json) identifies every record by hash; raw private artifacts
are retained locally and are not implied to be publicly hosted by these paths.

Issue #105 remains open for eligible measurement/review and the follow-up to the
reproduced harness blockers. Execution of this cohort does not make an
ineligible observation eligible or complete the full comparative-report goal.

## Post-cohort corrections

After all 18 records were closed, the gateway gained lane-specific `--help`,
and the MCP description and write-path refusal now identify the required
`.pilot/` artifact directory. A no-model two-lane regression exercises that
help without dispatching the compiler. Export counter extraction now includes
cache and reasoning components. These corrections apply to a future separately
frozen run; no original trial, counter record or candidate was rewritten, and
no rerun is claimed here.
