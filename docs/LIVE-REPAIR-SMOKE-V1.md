# Live Repair Smoke v1

Status: **LOCAL, OPT-IN, AND UNEXECUTED.** The route, its gates and its
evidence documents are implemented and covered by offline regressions. No live
provider call has been made through it, and no hosted or production support is
claimed.

Audience: operators running the repair workflow, and runtime integrators.

The repair workflow's ordinary mode is offline. It observes a real failed
check, obtains proposals from a fixture provider, previews a checked candidate
and exports reviewable evidence, and it does all of that with no credential and
no network. That path is owned by
[`crates/semaprax-toolchain/src/source_live_cli/repair.rs`](../crates/semaprax-toolchain/src/source_live_cli/repair.rs)
and reached as `semaprax-full source-live repair run|resume <config.json>
<checkpoint-dir>`.

This document covers the one thing that path deliberately cannot do: spend real
money against a real provider. That is gated behind an explicit operator act,
and this contract is that gate.

## Why a gate rather than a flag

A live smoke is the only place in the repair workflow where a decision by the
compiler, the runtime or a piece of evidence could cost someone money. The
repository's standing rule is that evidence capsules carry no authority, so the
authority to spend cannot be derived from a plan, a receipt, a journal or a
successful preflight. It has to be minted by a person and bound to one exact
thing.

Accordingly the contract is five values, in strict order, and each one refuses
rather than clamps.

## The five values

### 1. `LiveRepairSmokeTarget` — what the smoke runs against

Bound from a retained `ProjectRevision`, never from host strings. The source
path is resolved *inside* the retained source inventory: an absolute path, a
traversal, a non-`.spx` name and a path the project does not contain are all
refused. The repair target is resolved through the ordinary
`ProjectCandidate::semantic_delta` route, so a target that names nothing real is
refused before a plan exists. `observed_failure` records the identity of the
real failed check the smoke exists to repair.

`require_unchanged` rechecks the project revision, the workspace revision, the
source path and the exact source bytes. Drift fails closed: a paid call is never
made against facts that already moved.

### 2. `LiveRepairSmokePlan` — the complete, digest-identified proposal

A plan joins a target to one already bound `SourceModelBinding`. Its effective
budget is **derived**, not accepted: `bind` calls the existing
`SourceModelBinding::policy_binding`, which performs the three-way `intersect`
of the source Agent's ceilings, the deployment policy and the invocation's own
narrowing. A plan therefore cannot carry a ceiling wider than the deployment
already admitted.

`expected_turns` must be at least two. A one-turn smoke cannot exercise the
wrong-then-corrected loop the workflow exists to demonstrate, so it is refused
rather than admitted as a weaker demonstration. Sixteen is the upper bound: a
smoke stays a smoke.

A plan whose derived cost ceiling is zero is refused. The committed
`examples/offline-repair-project` fixture declares a free local provider
(`max_usd_microunits: 0`), which is exactly right for the offline demonstration
and exactly wrong for a live smoke; an operator running a live smoke supplies
their own deployment with a real monetary ceiling.

### 3. `OperatorLiveSmokeGrant` — the human act

Minted only by `grant`, which takes an operator reference, a justification and
approved ceilings, and only by `replay`, which re-derives the same value from
its own canonical bytes and digest. Nothing else in the codebase constructs one.

A grant may only narrow. Every dimension is compared against the plan's derived
ceiling and a wider value is refused *with the offending dimension named*,
rather than silently clamped — an operator who believes they approved more than
the deployment admits should be told.

A grant names one plan digest. `AuthorizedLiveRepairSmoke::authorize` refuses a
different plan, so a grant obtained for a cheap plan cannot be replayed onto an
expensive one, and a plan re-bound after anything changed carries a new digest
no existing grant names.

### 4. `LiveRepairSmokePreflight` — the route a fresh operator always runs

`plan.preflight(&project)` needs no credential, opens no socket and spends
nothing. It evaluates six prerequisites and reports every failure rather than
returning on the first, so one run shows the whole picture:

| prerequisite | meaning |
| --- | --- |
| `retained_source_bytes_unchanged` | the planned source and revision still match |
| `repair_target_resolves_in_the_retained_project` | the target still names a declaration |
| `effective_budget_admits_the_expected_turns` | the derived ceiling can carry the plan |
| `provider_adapter_selection_is_bound` | one deployment-admitted provider/model/adapter |
| `operator_grant_present` | an explicit grant was supplied |
| `operator_grant_binds_this_exact_plan` | that grant names this plan digest |

The receipt states `dispatched: false`, `provider_dispatch_count: 0`,
`credentials_read: false` and `network_observation: false` as literal document
facts, so a preflight receipt found in a log can never be misread as evidence
that a live run happened.

**Today, with no operator grant in this repository, the preflight's honest
answer is `ready: false`, blocked on `operator_grant_present`.** That is the
built-but-unexecuted state, and it is what the regressions assert.

### 5. `LiveRepairSmokeRecord` — the true outcome

Produced only from an `AuthorizedLiveRepairSmoke`. Three properties make it
honest evidence rather than a success log:

* **Failure is a first-class result.** `ProviderFailed`, `BudgetExhausted`,
  `Cancelled` and `NotRepaired` all record normally. There is no "record only on
  success" path that would push an operator toward re-running until it looks
  good.
* **Reported usage cannot exceed what was authorized.** A record claiming more
  attempts, more cost or more aggregate tokens than the intersected ceiling is
  refused, so a record can never legitimise overspend after the fact.
* **A record binds one plan.** `verify_for` refuses a different plan.

`newly_dispatched_attempts` is total attempts minus replayed attempts. An
interrupted-and-resumed smoke reports the same total with a higher replayed
count and no additional dispatch; a record replaying more attempts than it made
is refused.

## Running the opt-in live smoke

The route is implemented; running it is an operator decision with a real cost.

1. Prepare a Project whose deployment admits your provider and a real monetary
   ceiling, and authenticate it.
2. Bind the target, bind the runtime through `bind_agent_runtime_v2_live`, take
   its `source_model_binding` for your adapter identity, and bind the plan.
3. Run `plan.preflight(&project)`. Read the receipt. It will report
   `operator_grant_present: false`.
4. Decide. Mint `OperatorLiveSmokeGrant::grant` with ceilings you are willing to
   pay, and confirm `plan.authorized_preflight(&project, &grant).ready()`.
5. Run the authorized repair loop with your own provider adapter, then record
   the true outcome with `LiveRepairSmokeRecord::record`, including a failure.
6. Keep the plan, grant and record documents together. Each is canonical JSON
   with its own digest and replays exactly.

**Step 5 has not been performed in this repository.** No credential exists here
and no paid call has been attempted. A fixture pass is not hosted evidence and a
green framework is not a completed model experiment.

## Publication is a separate act again

A default repair run stops at a reviewed candidate: it leaves authoritative
source untouched and creates no Git state. Publishing goes through
`agent_runtime_v2::repair_approval`:

* `RepairCandidateReview::derive` regenerates the source diff, the semantic
  delta and the impact summary *from the candidate itself*, and records the
  host's validation results, declared blind spots and the journal digest. A
  review cannot describe a candidate other than the one it was derived from,
  and a caller cannot substitute a friendlier report.
* `RepairCandidateApproval::approve` is a distinct act over one exact review,
  and names one candidate digest. `replay` carries it across the session
  boundary as canonical bytes, so the publishing session re-derives the approval
  rather than trusting an in-process object.
* `prepare_approved_repair_publication` and
  `apply_approved_repair_publication` refuse a candidate the approval does not
  name, then delegate to the unmodified `project::prepare_candidate_publication`
  boundary, which performs its own independent replay and remains the only
  authority that pivots `ACTIVE`.

Approval for candidate A therefore cannot publish candidate B — refused here,
and refused again by the delegated boundary's own `approved_candidate_digest`
check.

## What this contract never does

It holds no credential, endpoint, prompt or response body. It opens no socket
and writes no file. A grant is not a credential and confers no transport
authority. A record is one local operator run, not hosted CI and not production
support. Nothing here grants source-write, Git or publication authority.

## Regression obligations

`tests/agent_runtime_v1.rs`'s `live_repair_smoke_v1` module owns the contract's
behavioural gate against a host-selected temporary Project: path containment,
target resolution, drift refusal, budget derivation, turn bounds, the
grant-for-A-does-not-authorize-B case, narrow-never-widen, the unready preflight
and its `dispatched: false` facts, failure-as-evidence, overspend refusal,
resume without redispatch, the untouched-source assertion and the
approval-for-A-cannot-publish-B case. `src/agent_runtime_v2/live_smoke/tests.rs`
owns the shared wire discipline those values depend on.

The offline wrong-then-corrected loop itself, including the case where the
required prior feedback observation is withheld and the repair must fail, is
owned by `crates/semaprax-toolchain/src/source_live_cli/repair_tests.rs`.
