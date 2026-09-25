# Live Invocation Contract v1

Status: **LOCAL** bounded design + reference kernel, fixture-backed. This is
the co-designed contract for issue #108 ("Define live invocation identity
and causal-journal contract") and issue #177 ("Add a provider-independent
`model.invoke` effect to the source-native Agent runtime"). Both issues share
exactly **one** runtime kernel and **one** causal journal — this document and
`src/live_invocation/` are that shared design, not two parallel ones.

Audience: implementers of the fourteen open issues in this lane (#109–#116,
#178–#181) that consume these interfaces, and reviewers of the identity,
authority and recovery contract per #108's review checkpoint.

This is the bounded #108 design checkpoint and small executable journal
reference, not permission to rewrite the frozen runtime. The reference kernel
remains separate from the compiled pipeline.
Later source-role lowering and the typed live driver now execute a declared
`propose` model role through an injected source adapter and compiler-derived
proposal decoding. That route is described by
[Language-native Agent Lowering](LANGUAGE-NATIVE-AGENT-LOWERING-V1.md) and
[Agent Runtime v2](AGENT-RUNTIME-V2.md); it does not require a literal new
`model.invoke` source expression. The checkpointed compiled-source route uses
[Source Live Journal v2](SOURCE-LIVE-JOURNAL-V2.md) and its additive profiles.
The existence of those routes does not establish exact adapter/deployment
binding, model evidence in every runtime root, or hosted support for this
reference contract; those requirements must be assessed at the executing API.

## Why a new module instead of extending typed effects v3

[Agent Typed Effects v3](AGENT-TYPED-EFFECTS-V3.md) already binds an
injected host boundary to deployed tool contracts, with its own registry,
budget and evidence. It was considered and rejected as `model.invoke`'s
transport: its admitted host scalars are `bool`/`i32`/`i64`/`u8`/`usize`,
at most eight argument and eight result fields, and "nested carriers remain
outside this profile." A `model.invoke` request's observation/context
projection and a response's raw bytes are naturally unbounded byte payloads,
not eight scalar fields — forcing them through that registry would either
violate its own admitted-vocabulary invariant or silently narrow what a
model call can carry. `model.invoke` therefore gets its own typed boundary
([`model_invoke`](#the-modelinvoke-effect)), but shares [operation checkpoint
v2](AGENT-OPERATION-CHECKPOINT-V2.md)'s vocabulary and Intent-before-dispatch
discipline for its journal, described below.

## Invocation identity

A live invocation's identity is derived once, from exactly the bytes known
before any model or effect call is made:

```
LiveInvocationSeed {
    program_root:               String,   // exact ProgramRoot
    deployment_policy:          String,   // provider/model binding digest
    task:                       Vec<u8>,
    budget:                     i64,      // total invocation budget ceiling
    interaction_schema_digest:  String,   // compiler-derived proposal grammar
    approved_providers:         Vec<String>, // deployment's approved providers, in order
}
```

`LiveInvocationId::derive(&seed)` folds a domain separator and the seed's
canonical encoding through SHA-256 into `sha256:<hex>`. Two identical seeds
produce identical identities; any differing byte — including provider list
*order*, since a reordered fallback policy is a different deployment
decision — produces a different one.

**Why this is stable across retry, resume and recovery.** No field of
`LiveInvocationSeed` can only be known after a model or effect call: there is
no response digest, no usage counter, no provider-reported identifier. A
model response is structurally incapable of contributing to the seed — the
type has no field for one. Retrying an uncertain `model.invoke` call,
resuming a suspended invocation, and recovering after a crash all re-derive
the identity from the *same* pre-dispatch bytes the original attempt used, so
a resumed causal journal is recognised as continuing the same chain rather
than starting a new one (every `TurnOpened` entry names this identity, and
[`validate`](../src/live_invocation/journal.rs) rejects any entry naming a
different one — see "Cross-invocation pairing" below).

Identity carries **no authority**. It names a causal journal chain; it does
not grant permission to extend it, dispatch a call against it, or mint an
authorization.

## The causal journal

One journal, shared by #108 and #177, records what a live invocation
actually committed before crossing each external boundary. Every
`model.invoke` call is one `RequestIntent`/`ResponseRecorded` (or
`ResponseFailed`) pair; a further tool effect within the same turn is the
matching `EffectIntent`/`EffectObserved` pair, in the same journal, the same
vocabulary, chain-linked the same way.

### Record format

`JournalEntry` (`src/live_invocation/journal.rs`) is a closed enum. Every
turn's entries appear in exactly this shape:

| Entry | When | Binds |
|---|---|---|
| `TurnOpened` | Observation prepared. No external boundary approached yet. | invocation identity, observation digest |
| `RequestIntent` | The `model.invoke` request is durable *before* dispatch. | request digest, reserved budget |
| `ResponseRecorded` **or** `ResponseFailed` | After the physical call settles. | response digest + bytes, **or** closed failure tag + attempted bytes |
| `ProposalAdmitted` **or** `ProposalRefused` | After compiler-derived decode, only following `ResponseRecorded`. | decoded proposal digest, **or** refusal reason |
| `AuthorizationConsumed` **or** `AuthorizationRefused` | The one opaque grant this turn consumed, only following `ProposalAdmitted` — **or** authorization never consumed one (gate refusal, or cancellation observed after `ProposalAdmitted`; issue #113). | grant digest, **or** closed refusal reason |
| `EffectIntent` / `EffectObserved` **or** `EffectIntent` / `EffectFailed` | Zero or more further tool-shaped effects within the turn, matched by operation identity — the effect either settles or fails/is cancelled before it is ever called (issue #113). | operation id, request/observation digest, **or** operation id + closed failure reason |
| `Transition` | The deterministic reduction's selection: `continue`/`complete`/`suspend`/`fail`. | case, carrier digest |
| `TerminalOutcome` | Only after a non-`continue` `Transition`. Nothing may follow. | case, carrier digest |

`AuthorizationRefused` and `EffectFailed` (issue #113) close a gap the
original #108/#177 vocabulary left: before they existed, an authorization
refusal or an effect failure/cancellation produced a journal that skipped
straight from `ProposalAdmitted`/`EffectIntent` to `Transition` — a shape
`journal::validate` itself rejected, so that outcome could never actually be
replayed through `kernel::run_live_invocation` a second time. Both new
entries are, like `ResponseFailed`, terminal for their own turn's remaining
phases; neither is ever a [`ModelFailure`](#closed-failure-taxonomy) — an
authorization or effect outcome is never mistaken for a model/provider
failure because it has its own entry kind and its own reason text.

This is exactly the state list #108 asked for: *observation prepared,
request intent durable, response recorded, proposal admitted/refused,
authorization consumed, effect intent/observation, transition, terminal
outcome* — plus the distinction the issue also asked for, between
*model-attempt uncertainty* (`ResponseFailed` covers `Cancelled` explicitly)
and *effect-delivery uncertainty* (the separate `EffectIntent`/`EffectObserved`
pair).

The canonical wire is a JSON array with one entry per line-equivalent object,
closed keys, sorted encoding and a `sha256:<64 hex>` digest format for every
digest field (`src/live_invocation/journal.rs::render`/`decode`). Response
and observation *bytes* — not just digests — are recorded in
`ResponseRecorded`, because a replay must consume the trusted recorded
observation, never reconstruct one by hashing caller-provided data (see
"Determinism and replay" below). Terminal carrier *bytes* are deliberately
**not** stored, only their digest — the same "digest, without exposing
payloads" discipline [Agent Iterative Lifecycle v2](AGENT-ITERATIVE-LIFECYCLE-V2.md)
already uses for its terminal-carrier evidence.

### Ordering rules

`journal::validate` is a small table-driven state machine, not a monotonic
rank check: one turn's entries must appear in exactly the table order above.
`Transition { case: "continue" }` must be followed by the next turn's
`TurnOpened` (turn number advancing by exactly one, same invocation id); any
other case must be followed by exactly one matching `TerminalOutcome`, after
which the journal must end. It rejects, by construction:

- **Omission** — a required entry (e.g. `RequestIntent`) missing from a
  turn's sequence.
- **Reorder** — any two adjacent entries transposed.
- **Cross-invocation pairing** — a `TurnOpened` naming an `invocation` other
  than the journal's own bound identity.
- **Schema drift** — enforced one layer up, by the kernel comparing a
  `ProposalDecoder`'s bound `schema_digest()` against the invocation's
  `interaction_schema_digest` *before* any dispatch (`LiveKernelError::SchemaDrift`);
  a decode that succeeds against the wrong grammar is exactly what this
  check exists to prevent from ever reaching the handler.
- **Post-terminal continuation** — any entry after `TerminalOutcome`.

A journal that ends immediately after `RequestIntent`, with no recorded
response, is **uncertain** (`ValidatedJournal::uncertain_intent`): the kernel
refuses to proceed — including refusing to redispatch the same request —
before any further stage, store write, or host call. This mirrors [operation
checkpoint v2](AGENT-OPERATION-CHECKPOINT-V2.md)'s identical rule for tool
effects.

A journal that ends cleanly right after a `continue` `Transition` (or is
empty) is **resumable** (`ValidatedJournal::resumable_turn`): the next turn
may open without redispatching anything already recorded. Every other
mid-turn ending (decode/authorize/effect pending) is neither terminal nor
resumable in this bounded kernel; the reference implementation returns
`LiveKernelError::UnresolvedPrefix` rather than guess the missing entries. A
real deployment reconciles such a state out of band (the same declared
nonclaim [Agent Checkpoint v1](../src/agent_lifecycle/durable.rs) documents
for its own uncertain window) before calling back in.

### Trust model

The journal carries **no key material and no signature** — a party who can
rewrite the caller's storage can also recompute its hash chain
(`journal::chain`). This is a declared nonclaim, matching
`src/agent_lifecycle/durable/journal.rs`'s identical position, not a gap this
contract papers over. What makes a forged, truncated or withheld journal
harmless to *authority* is that [`AuthorizationGrant`](#the-modelinvoke-effect)
is minted by re-running `AuthorizationGate::authorize` against a state and
proposal the kernel recomputes itself — never by decoding a journal entry.
A journal can misdescribe or omit a turn; it can never produce a grant for
one, and it can never resurrect a model response that was never actually
recorded: `ResponseRecorded` carries the response *bytes*, so replay
consumes what was actually observed, not a hash a caller could fabricate.

### Receipts are a projection, not a second log

`journal::receipt_projection` folds an already-`validate`d journal into a
compact summary (turn count, model call/failure counts, effect call count,
terminal case). It is a pure function of the journal's entries — there is no
receipt-only state anywhere in this module, and two callers folding the same
journal always derive the same projection. Issue #180 ("receipts") is scoped
to build its richer receipt document as a further projection of *this*
journal, not as a value tracked independently alongside it.

## Determinism and replay

`kernel::run_live_invocation` is the **one** runtime kernel both issues
share. It takes a starting journal (possibly empty) and continues from
exactly where that journal validates to:

- **Fresh start** — empty journal, begins at turn 0.
- **Resume** — a journal ending right after a `continue` transition begins
  at the next turn, without redispatching the recorded prefix.
- **Replay** — an already-terminal journal is recognised immediately
  (`ValidatedJournal::terminal`); the kernel returns its recorded terminal
  **case** with an empty payload and `LiveKernelRun::dispatched == 0` — the
  turn loop never runs, so `ModelHandler::invoke` and every other injected
  seam is never called. The journal retains the terminal carrier digest as a
  commitment to the original bytes, but deliberately does not retain those
  bytes, so replay cannot reproduce a fresh run's payload. The reference test
  `replaying_a_terminal_journal_makes_zero_dispatches_and_retains_its_terminal_case`
  wires every seam to a fixture that panics if touched, to make this an
  executable, not just an asserted, property.
- **Uncertain intent** — a journal ending right after `RequestIntent` with
  no response is refused (`LiveKernelError::UncertainIntent`) before any
  further work, including redispatch.

Recontacting a model after an uncertain or failed attempt is a **new**
`model.invoke` call under new accounting — this kernel does not attempt to
"replay" a nondeterministic model response. A retry is a fresh call through
`ModelHandler::invoke`; only the *deterministic* stages (observe, decode,
authorize, reduce) are ever replayed from recorded bytes.

## The `model.invoke` effect

`src/live_invocation/model_invoke.rs` defines the provider-independent
effect boundary; `src/live_invocation/kernel.rs` defines the seams a real
deployment binds it through.

### Typed request/response boundary

```
ModelInvocationRequest {
    turn:                      u32,
    task:                      Vec<u8>,
    observation:               Vec<u8>,     // this turn's deterministic context projection
    proposal_grammar_digest:   String,      // compiler-derived grammar identity
    deployment_binding:        String,      // exact deployment/model policy digest
    max_response_bytes:        usize,
    effective_budget:          i64,
}
```

Every field is compiler- or deployment-derived, built *before* any provider
is contacted — never model output. The request structurally cannot carry a
raw filesystem path, environment variable, credential, or unchecked dynamic
map: a real `ModelHandler` implementation is responsible for attaching
provider credentials from outside checked program data.

```
enum ModelInvocationOutcome {
    Settled(Vec<u8>),                                   // untrusted response bytes
    Failed { failure: ModelFailure, attempted_bytes: usize },
}
```

The raw response is recorded (`ResponseRecorded`) *before* decode is
attempted; decode (`ProposalDecoder::decode`) is the only path from response
bytes to a value anything downstream calls a proposal.
`AuthorizationGate::authorize` and, if bound, a further tool effect never see
raw model output — only the decoded, admitted proposal.

### Capability requirement

```
ModelInvokeCapability::grant(reason: impl Into<String>) -> Self
```

There is no `Default` implementation and no ambient constructor. Compiled
program text and generated code hold no path to a `ModelInvokeCapability`
without an explicit host-supplied value passed into
`kernel::run_live_invocation`'s `LiveInvocationHandlers`. This is the
concrete mechanism behind AGENTS.md's "capabilities are explicit... no
ambient... network... authority": declaring a `propose` role in source, or
compiling a module that uses one, creates no path to a live provider call by
itself.

### Closed failure taxonomy

```
enum ModelFailure { Timeout, Cancelled, CapacityExceeded, ProviderError, MalformedResponse, Refused }
```

Provider-specific errors never become language semantics: a real handler
normalizes whatever a transport reports into exactly one of these before
returning, and the journal records only the closed tag plus a bounded
attempted-byte count — never provider-shaped detail. `MalformedResponse`
also covers a response the kernel itself rejects as oversized
(`response.len() > max_response_bytes`), checked before decode is attempted,
so an enormous or truncated payload cannot drive unbounded downstream work.

### Cancellation point

The kernel checks `AgentCancellation::is_cancelled()` at five points per
turn (issue #113 added the fourth and fifth), mirroring [Agent Iterative
Lifecycle v2](AGENT-ITERATIVE-LIFECYCLE-V2.md)'s "checked at each
deterministic stage and before dispatch":

1. **Before opening a turn.** If cancelled here, the kernel stops cleanly
   with no entries written for that turn; the journal is left non-terminal
   (`LiveInvocationOutcome::Cancelled`).
2. **After `TurnOpened`, before committing `RequestIntent`.** Same clean
   stop; the turn's observation was recorded but nothing durable was
   committed toward a call.
3. **After `RequestIntent` is committed, immediately before calling
   `ModelHandler::invoke`.** Cancellation here is folded into the closed
   failure domain as `ModelFailure::Cancelled` — the request was already
   durable, so the turn must still resolve to a recorded outcome
   (`ResponseFailed`) rather than leaving an uncertain intent behind.
4. **After `ProposalAdmitted` is committed, immediately before calling
   `AuthorizationGate::authorize`.** Authorization is never a model call, so
   this is recorded as `AuthorizationRefused { reason: "cancelled" }`, never
   `ModelFailure::Cancelled` — the two must not collapse into one tag.
5. **After `EffectIntent` is committed, immediately before calling
   `TurnEffect::call`.** Same reasoning: recorded as
   `EffectFailed { reason: "cancelled" }`. This is also the checkpoint that
   makes "cancellation in flight blocks subsequent effects and result
   publication" (issue #113's required case) true: the effect is never
   called, and the turn resolves to `Fail`, never `Complete`/`Suspend` — a
   result a cancelled turn produced is never published.

Every checkpoint after the first two follows the same rule 3 already
established: once some entry is already durable for this turn, cancellation
cannot leave the journal stuck mid-turn — it must still resolve to a
recorded, replayable outcome. `tests::cancellation_after_proposal_admitted_stops_before_authorize_is_ever_called`
and `tests::cancellation_after_authorization_consumed_stops_before_the_effect_is_ever_called`
are checkpoints 4 and 5's dedicated tests, each proving the downstream seam
(`AuthorizationGate`/`TurnEffect`) is never actually called.

An acknowledged cancellation never proves a real provider stopped billing or
processing — that is a declared nonclaim, matching Direct Runtime v2's
existing cancellation contract.

### The budget hook

```
trait InvocationBudgetHook {
    fn reserve(&mut self, request: &ModelInvocationRequest) -> Result<ReservedBudget, BudgetRefusal>;
    fn record(&mut self, usage: &InvocationUsage);
}
```

The kernel reserves before every dispatch and records usage after every
settlement; the hook itself decides policy. The shipped `FixtureBudgetHook`
remains a trivial per-invocation counter, useful only for tests that don't
care about cumulative enforcement. `budget::CumulativeBudgetLedger` (issue
#113) is the first real policy behind this hook: one monetary ceiling and,
optionally, one absolute deadline (via an injected `InvocationClock`),
enforced identically at every attempt and nonrefundable once committed. See
[Live Invocation Budget and Deadline Accounting v1](#budget-and-deadline-accounting-issue-113)
below for the full design; issue #179 may extend this further (e.g. real
provider pricing), but does not need to invent a second hook to do it.

### Budget and deadline accounting (issue #113)

**Where the nonrefundable decrement happens, relative to dispatch.**
`CumulativeBudgetLedger::reserve` both decides whether an attempt fits the
remaining ceiling and, if it does, commits that amount against the ceiling
in the same call, before returning — strictly before the kernel's own
dispatch to `ModelHandler::invoke` (the kernel journals and persists
`RequestIntent.reserved_budget` immediately after this call and before that
dispatch; see `kernel.rs`). By the time a call could possibly have reached a
provider, its reservation is already charged; with the confirmed persistence
sink enabled, that reservation is also durable.

**Why a retry cannot double-spend.** `CumulativeBudgetLedger` is never the
durable source of truth for `committed` — `CumulativeBudgetLedger::resume`
reconstructs it by folding over an already-persisted journal prefix and
summing every `RequestIntent.reserved_budget` seen so far, the exact value
`reserve` already committed and the kernel already made durable before
dispatch. Replaying that fold after a real or simulated crash always yields
the same total, so a reservation is nonrefundable by construction — there is
no separate in-memory counter to lose. The fault-injection test proving this
directly: `budget::tests::resuming_after_a_simulated_crash_never_refunds_the_already_committed_reservation`
builds a journal ending in an uncertain `RequestIntent` (no recorded
response — the exact shape a crash between reservation and settlement
leaves behind) and shows a fresh ledger resuming from it still refuses a
retry that would exceed what actually remains.

This recovery statement applies to the kernel's confirmed persistence route.
The ledger itself is in-memory and performs no journal writes. Its use by the
private OpenCode source adapter does not supply source recovery or migration;
those routes must retain reservations through their own checked journal binding
before they can claim the same guarantee.

Source checkpoint primitives are specified separately in
[Source Live Journal v1](SOURCE-LIVE-JOURNAL-V1.md). Their budget restoration
uses the same `CumulativeBudgetLedger`, with the validated bound ceiling,
fixed reservation and committed-intent sum. `SourceInvocationClock` names the
host's restart-stable domain; restoration rejects a different domain, a clock
below the retained floor, and expiry at the original deadline. Subsequent
checks retain the highest observed time and reject regression. This clock
contract remains a host assumption; matching a domain string cannot turn a
new process-local `Instant` into a restart-stable clock. Generic v1 callers
retain their existing clock and reservation behavior. These primitives alone
do not connect the source runtime to durable storage. Recovery callers must
load the latest authoritative generation under exclusive writer control;
this byte-decoding API cannot distinguish an old valid checkpoint from the
current one without that external freshness guarantee.

**`record` never refunds.** A settlement using fewer bytes than reserved, or
a failed attempt using none at all, never credits the difference back onto
`remaining` — matching issue #113's own scope note that "monetary limits are
conservative reservations...not a promise of exact live billing." This is
also why a timeout with unknown billing never appears as zero usage: the
reservation it already consumed stays consumed regardless of what `record`
is later told.

**Budget-exhausted, deadline-exceeded and cancelled never collapse into one
tag.** `reserve`'s refusal is always one of the closed reasons
`budget::BUDGET_EXHAUSTED`, `budget::DEADLINE_EXCEEDED` or
`budget::NEGATIVE_REQUEST` — never `ModelFailure`. Previously the kernel
hardcoded `ModelFailure::CapacityExceeded` for *any* budget-hook refusal,
misrecording a self-imposed refusal as if the provider itself had reported
no capacity; the kernel now writes the hook's own reason text into
`ResponseFailed.failure` instead (`kernel.rs`,
`tests::a_cumulative_budget_ledger_stops_the_run_once_its_ceiling_is_exhausted_not_the_turn_counter`
asserts the recorded tag is never `ModelFailure::CapacityExceeded`).
Cancellation is a third, independently-checked thing (see "Cancellation
point" above) recorded through its own journal entries, never through this
hook at all.

**The deadline is an absolute instant, not a duration.**
`CumulativeBudgetLedger::with_deadline` takes an absolute `deadline_millis`
in the bound `InvocationClock`'s own units, not "N milliseconds from now." A
caller resuming a suspended or recovered invocation re-supplies the same
absolute value it used originally (typically `invocation_started_at +
max_duration`, computed once at bind time, the same way
`program_root`/`task`/`deployment_binding` are already re-supplied
identically on every call into `kernel::run_live_invocation`) — there is
no "from now" constructor. The host must preserve both the absolute value and
the clock's epoch across recovery: this API alone does not authenticate that a
caller re-supplied the original deadline, nor make a process-local clock
restart-stable.
`budget::tests::resume_preserves_an_absolute_deadline_across_the_same_simulated_crash`
exercises this directly.

`InvocationBudgetHook::check_deadline` checks the same absolute deadline without
reserving or refunding work. Its default accepts policies without a deadline;
`CumulativeBudgetLedger` uses the same injected clock and `>=` comparison as
`reserve`. Settlement and effect/publication checks must respect journal order:
a late successful model response fails before `ResponseRecorded` and decoding,
while an already observed effect remains recorded even when a later deadline
blocks publication. Existing provider, cancellation and effect failures remain
selected. Known failed response bytes remain in usage observations.

**Not a live price lookup.** `effective_budget`/`ceiling` stay opaque
caller-defined units (`ModelInvocationRequest::effective_budget`'s existing
documentation: "the deployment defines what one unit costs"). This module
does no currency conversion and no provider pricing lookup; live price
lookup, if ever added, stays outside the compiler per issue #113's own scope
note.

**Reference:** `src/live_invocation/budget.rs` (`CumulativeBudgetLedger`,
`InvocationClock`) and its `tests` submodule; `fixture::StepClock` is the
one deterministic clock implementation this crate ships.

## What downstream issues implement against

| Interface | Owns |
|---|---|
| `ModelHandler` | A real provider transport (#180/#181 own multiple providers; #112 owns the first live one) |
| `ProposalDecoder` | The real compiler-derived proposal grammar (#109 owns the rich schema) |
| `AuthorizationGate` | `agent_lifecycle::authorization`'s real mint site |
| `InvocationBudgetHook` | Cumulative budget/deadline policy: `budget::CumulativeBudgetLedger` (#113); further extension (e.g. real provider pricing) is #179's scope |
| `PricedWorkBudgetHook` | Local opt-in exact reservation quote for the generic priced envelope; it remains operator pricing plus unknown generic provider charge, not a provider billing API |
| `TurnObserver` / `TurnPolicy` | The compiled Agent's `observe`/`reduce` stages (source/HIR wiring, #109–#116) |
| `TurnEffect` | A deployed tool call via `agent_lifecycle::iterative::effects::TypedEffectHandler` |
| `journal::receipt_projection` | The richer receipt document (#180) |
| `journal::JournalEntry` (streamed) | The streaming extension (#178) — a stream is a further-refined view of the same `RequestIntent`→`ResponseRecorded` pair, not a second journal |

### Two independences this design makes structurally true

- **#112 (first live provider) does not depend on #181 (two-provider SDK).**
  `ModelHandler` is one trait with one `invoke` method; a single provider
  binds it directly. Nothing in `model_invoke.rs` or `kernel.rs` requires
  more than one registered handler to exist — a two-provider *selection*
  policy (#181) is a caller-side concern (which `ModelHandler` gets
  constructed and passed in), entirely outside this boundary.
- **#109 (rich schema) does not depend on #178 (streaming extension).**
  `ProposalDecoder::decode` takes a complete `&[u8]` response and returns
  one `ProposalOutcome`; there is no partial-decode state threaded through
  the journal. A streaming transport is free to buffer provider events into
  one complete response before calling this same boundary, so a richer
  grammar (#109) needs nothing from a streaming transport (#178) to exist.

## Issue #177 integration status

The source integration now lives in [Source Model Operation v1](SOURCE-MODEL-OPERATION-V1.md)
and [Direct Runtime v2](AGENT-RUNTIME-V2.md). The earlier audit described only
this generic kernel's original fixture boundary; its statements that source
model roles, compiled Proposal decoding, and real authorization were missing
are superseded by those implementations.

| Criterion | Current implementation and evidence |
|---|---|
| Source-native provider-neutral propose | Checked `model fn propose` roles use the compiler-derived Proposal schema through `StreamingSourceProposalAdapter` and `run_live_bound_model`; the separate durable entry reuses Source Live Journal v2. |
| Declared, capability-gated, bounded, cancellable, evidence-bearing | Exact deployment/provider/model binding, explicit adapter and model capabilities, bounded context/response and call policy, redacted model evidence roots, and cancellation/deadline checks before start, during polling, and settlement. Durable intent ACK precedes physical dispatch. |
| No provider credential in language semantics | Deployment selects the provider/model; the host injects transport and credentials. Source Agent semantic identity remains unchanged on eligible model substitution. |
| Model output cannot mint authorization | Only compiler-decoded proposals enter the checked source authorization stage and deployed typed registry. Raw provider bytes remain settlement evidence. |
| Versioned route and support evidence | Versioned source-model/runtime contracts and focused local scripted/injected-host tests are present. This update makes no hosted or public provider-support claim. |

Executable coverage is in `tests/agent_runtime_v1/execution_revision/typed/live_streaming`
(ordinary live success, policy refusal, durable success and idle terminal replay,
uncertain intent recovery, cancellation at ACK), `agent_deployment_v1` (eligible
model substitution), and `provider_adapter_sdk::source_bridge::tests`
(cancellation, deadlines, stale binding, capacity and pre-factory refusal).
Existing generic-kernel tests continue to own closed failure normalization,
raw-versus-decoded authorization, and generic journal replay.

## Boundaries and known limitations

Generic journal recovery and Source Live Journal recovery remain separate
versioned profiles. An uncertain non-idempotent intent never grants redispatch.
The durable typed source-model route currently refuses the in-memory quoted
`ModelPolicyLedger` profile; durable quote/usage recovery is remaining #113
work. Nondurable policy accounting retains its existing invocation-local
semantics. Retries, failover, network transport support and provider billing
reconciliation are owned by their respective profiles, not implied by a source
model operation or by a passing scripted test. Host evidence carries no
capability or publication authority.

## Executable reference

`src/live_invocation/` (`identity.rs`, `journal.rs`, `model_invoke.rs`,
`kernel.rs`, `persistence.rs`, `migration.rs`, `budget.rs`, `fixture.rs`,
`tests.rs`) is the complete reference implementation this document
describes, exercised end to end through the fixture provider with no
network access. Focused gate:

```sh
cargo test --locked -p semaprax --lib live_invocation
```

## Reference-contract acceptance for #108

The bounded design and reference state machine received independent code
review and local fixture validation on 2026-09-12. The `live_invocation::`
library selector executed 95 tests, including identity binding, cross-chain
and ordering rejection, uncertain-intent refusal, zero-dispatch replay,
budget/cancellation boundaries, and separation of raw and decoded bytes.

`execution_revision::frozen_execution_revision_evidence_is_byte_identical_after_a_live_fixture_run`
also passed: the real retained-source runtime executes before and after one
live fixture, and its canonical ExecutionRevision, EvidenceRoot, and lifecycle
evidence digest remain byte-identical. The production execution-revision
implementation is unchanged from issue #108's `ae25c6a4` baseline.

This records #108's design/reference deliverable at its original checkpoint.
The source/HIR/Direct Runtime integration is documented in the current #177
status above; this historical reference gate proves no real provider run,
hosted execution, or public support.

### Additive generic model-policy durable profile

The V1 causal journal remains the ordinary generic-kernel contract. The
retry/failover profile uses a distinct V2 checkpoint document because V1 has
one `RequestIntent` per turn and no ordered model-attempt reservation facts.
V2 binds a retained execution-root-derived policy binding and the exact
canonical request before persisting each adapter attempt intent. Recovery
replays a recorded response, refuses an unresolved intent as uncertain, and
continues only after a closed safe failure classification; it does not convert
V2 facts into V1 entries or broaden the V1 recovery promise.
