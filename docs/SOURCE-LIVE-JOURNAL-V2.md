# Source Live Journal v2

Status: **IMPLEMENTED SOURCE-RUNTIME ROUTE; LOCAL EXECUTABLE EVIDENCE**.
Audience: compiler contributors and live-invocation integrators.

Source Live Journal v2 is the bounded checkpointed route for one compiled
iterative source lifecycle. It is implemented by
`CompiledIterativeLifecycle::run_live_durable`,
`agent_lifecycle::iterative::source_live`, and the v2 execution profile of
`live_invocation::source_journal`. The ordinary `run_live` API stays unchanged and nondurable. This document records implementation semantics;
its focused local gates exercise checked execution and injected host boundaries.
This v2 contract alone does not claim hosted execution, live-provider execution,
or runtime durability beyond the supplied `CheckpointStore` contract. The
additive [source migration v3](SOURCE-LIVE-MIGRATION-V3.md) and
[private host CLI](SOURCE-LIVE-CLI-V1.md) specify their implemented routes and
separate local evidence.

## Route and ownership

The caller supplies a compiled lifecycle, task, iterative budget,
`SourceLivePolicy`, `SourceInvocationClock`, cancellation handle,
`CheckpointStore`, a checkpoint-capable `ProposalSource`, and an
`AgentReadOperation`. Before any stage runs, the route derives one opaque
`SourceInvocationBinding` from the compiled lifecycle and source revision,
deployment binding, task bytes and task budget, proposal-schema digest,
response limit, iteration/stage/attempt limits, stage-fuel limits, model
ceiling and fixed reservation units, clock domain and absolute deadline, and
optional ProgramRoot.

The binding grants no authority. A source task, checkpoint, terminal receipt,
model text, usage report, or evidence bytes cannot create a model invoke
capability, grant, effect handler, credential, store writer, or migration
authority. The trusted host selects the store, owns its exclusive writer, and
loads the latest authoritative generation. The hash chain checks canonical
integrity and causal order; it does not authenticate the store or prove an
older valid generation is current.

V2 uses the source execution schema
`semaprax.live-invocation.source-persisted-journal.v2`, separate from both the
generic live-invocation v1 wire and Source Live Journal v1's primitive schema.
There is no implicit migration between these documents.

The additive private v4 profile uses
`semaprax.live-invocation.source-persisted-journal.v4` and distinct binding
and chain domains. It leaves v1, v2, and v3 canonical bytes and decoders
unchanged. V4 `PricedAttemptIntent` binds the existing work reservation with
an exact integer minor-unit reservation and global money ordinal before
dispatch. Its paired `PricedAttemptUsage` closes usage and charge evidence as
`Unknown` or typed `Observed`; missing receipts and untyped provider costs remain `Unknown`. They are never
assumed to be zero or converted from floats.

The additive v5 profile binds cumulative provider request and response
reservations around the existing authenticated attempt rows. It changes no
V1--V4 bytes and may compose with V4 pricing. Its counters, recovery and
migration rules are specified in [Source Live I/O v5](SOURCE-LIVE-IO-V5.md).

## One checked loop, one journal, one ledger

`run_live_durable` invokes the same checked source-loop stages as the ordinary
live driver: initialize, observe, propose/decode, authorize, effect read, and
reduce/terminal selection. It does not introduce a second lifecycle evaluator,
proposal decoder, effect log, or budget ledger.

`SourceExecutionSession` is the one causal cursor. It acknowledges
`RunOpened`, stage reservations, observations, model intents and settlements,
compiler proposal decisions, authorization, effect intent/results, transitions,
policy stops, and one terminal snapshot. A failed store acknowledgement poisons
that cursor. It must not retry against its in-memory generation because the
store may have committed the new generation while losing the acknowledgement.
Recovery must reload the latest authoritative document before attempting any
continuation.

The one `CumulativeBudgetLedger` starts from the binding for a fresh run or is
restored from the opaque recovered checkpoint. Each acknowledged model intent
contains the fixed returned reservation. Reservations are nonrefundable:
malformed proposals, provider failures, cancellation, deadline refusal, and
unknown provider usage retain their committed amount. Provider usage is
observational only; it does not establish billing, refund a reservation, or
grant authority. Missing usage remains explicitly unknown.

V4 replays pricing from validated durable intents and usages only.
Reservations remain nonrefundable. An exact matching observed charge can
expose overage but cannot credit capacity; later admission includes it.
Recovery rejects changed pricing identity, mismatched ordinal or
turn/attempt scope, duplicate usage, malformed currency/scale, and overflow.
Its returned priced totals distinguish reserved, observed, and unknown
reservation minor units; none is settlement or payment authority.

For a migrated v4 binding, pricing replay starts from the durable priced carry.
The sink derives each new intent ordinal as the carried global ordinal plus the
local v4 intent inventory; it never renumbers predecessor attempts. Recovery
requires exact pricing identity and ordinal/scope sequence, retains unknown
exposure and observed overage, and clamps remaining admission at zero. The
returned totals remain an authority-free accounting view.

## Checkpoint-before-dispatch boundaries

The route checks cancellation and the shared absolute deadline before stages
and before external boundaries. A proposal source first prepares a canonical
attempt identity without dispatch, then must durably acknowledge its attempt
intent before it invokes the model handler. After the call it checkpoints raw
bounded settlement bytes or a closed failure before the compiler proposal
decoder sees text. A malformed decoded proposal can use only the driver's
bounded retry path and receives a fresh, charged intent.

After authorization, the route acknowledges an effect intent before calling
`AgentReadOperation`, then acknowledges a bounded observation or failure. An
unsettled model or effect intent is uncertain: recovery refuses it and performs
zero model or effect redispatches. A settled response and observation are
replayed from their exact retained bytes; they do not call the provider or
effect handler again.

The journal keeps the existing sticky checked `Fail` result. A later deadline
or cancellation cannot replace it. Conversely, a non-fail complete or suspend
candidate still passes the final policy/terminal checkpoint boundary before it
is published.

## Clock and replay fuel

The source clock is explicit. Its named domain, initial reading, and one
absolute deadline are bound before execution. The host guarantees that the
same domain has comparable epoch and units after restart. A matching domain
string alone does not prove that guarantee; a fresh process-local `Instant`
must not be used as a recoverable source clock. Recovery rejects a domain
mismatch, observed clock regression, or a clock at/after the original
deadline before further work.

Every initial stage reservation records the exact per-stage fuel allowance.
When recovery deterministically replays an already committed causal prefix,
it appends `ReplayStageReservation` entries. Those entries charge fresh replay
fuel against the one bound total-stage-fuel limit while preserving the original
stage reservation as the causal source of the lifecycle decision. They do not
create a second causal event stream or refund any previously consumed fuel.

## Recovery results and terminal evidence

Recovery validates exact keys, canonical encoding, generation, chain, binding,
phase order, capacities, byte digests, model-unit sum, and execution-stage
fuel. It returns an opaque `RecoveredSourceCheckpoint`; callers receive
validated getters rather than forgeable committed totals.

If the recovered journal ends in an unresolved model or effect intent, the
route returns a closed recovery failure without redispatch. If it contains a
validated terminal snapshot, the route returns zero model and effect dispatches
and exposes no fresh checked run. It supplies only the opaque terminal receipt
(status, evidence, and any retained carrier bytes), which does not authorize a
new effect, publication, migration, or continuation.

For nonterminal recovered prefixes, the route replays the checked lifecycle
through the same driver and compares each expected journal entry. A mismatch
fails closed before a new external dispatch. This gives one bounded replay
cursor; it is not an independent replay engine.

## Capacity and explicit nonclaims

The profile bounds source journals to 65,536 entries and 16 MiB encoded bytes.
Model request, response, effect observation, terminal evidence, and retained
terminal carrier each have their own bounded inputs. Intent preflight reserves
space for the bounded settlement and terminal material before it permits an
external dispatch. The binding also bounds attempts to four per turn,
iterations to 4,096, stages to 12,289, per-stage fuel to 1,000,000, and total
stage fuel to 1,000,000,000.

The core source journal supplies no filesystem or runtime CLI. It does not
claim durable filesystem or power-loss behavior, multi-writer coordination,
remote-provider delivery proof, provider reconciliation, price lookup, exact
billing, or hosted or live-provider evidence. Its correctness depends on a
trusted latest-store load, exclusive writer control, and the host's
restart-stable clock guarantee.
The private CLI's v2 priced configuration selects the v4 route; direct resume
of v1/v2/v3 under that configuration is refused. Its one-hop priced migration
route derives the v4 carry only after binding and recovery validate the priced
predecessor. Unsupported profile conversion remains refused. The private CLI's
v3 configuration selects V5 I/O limits and requires the same profile at both
sides of a migration; V4/V5 conversion is refused.
Local executable gates:

- `cargo test --locked -p semaprax --lib agent_lifecycle::iterative::` exercises
  the shared driver, including 18 source checkpoint/recovery cases.
- `cargo test --locked -p semaprax --lib live_invocation::source_journal::`
  exercises v1 compatibility, v2 ordering, cumulative fuel and canonical evidence.
- `cargo test --locked -p semaprax-toolchain --lib opencode_host::` exercises
  bounded fake transport, checkpoint acknowledgement loss and usage settlement.

A completed terminal snapshot is read-only recoverable after expiry. A committed
Stop can finish its terminal snapshot without continuation-budget admission.
A deadline crossed during a non-Fail terminal acknowledgement returns a failure
with the acknowledged receipt, rather than reporting fresh successful publication.
The stored terminal remains immutable; no later failure rewrites its selection.

## Compatibility

[Source Live Journal v1](SOURCE-LIVE-JOURNAL-V1.md) remains the primitive
schema and design record. The generic live-invocation persistence and migration
contracts remain separate. V2 adds no migration path and does not widen the
ordinary `run_live` contract.

## Additive V6 model-policy profile

V6 uses `semaprax.live-invocation.source-persisted-journal.v6` and a distinct
binding and chain domain. It preserves every V1--V5 document and decoder. A
V6 binding commits the source-model binding digest, policy-binding digest,
selected provider, effective model-policy limits, and the existing absolute
source deadline. The host supplies a request-digest-bound quote in a first,
non-dispatching phase. The second phase must append and acknowledge one
`PolicyAttemptIntent` before it approaches a provider. Adapter reservation of
the exact preflighted intent precedes the store acknowledgement; a failed ACK
does not refund it.

Each policy intent contains a strictly ordered `Fresh` reservation with the
selected provider, context/output token reservation, and estimated micro-cost.
The journal independently folds exact ordinals, provider, turn/attempt scope,
checked totals, and limits before a recovered adapter can restore its policy
ledger. A closed `PolicyAttemptUsage` is either `Unknown` or exact observed
usage. It never refunds a reservation. Later admission uses the checked maximum
of reserved and observed exposure, so an observed overage is retained and can
only close later capacity. Missing, malformed, or uncertain provider usage is
Unknown; none is inferred as zero or billing proof.

V6 may compose the existing V5 I/O reservation profile under its V6 schema.
A recovered terminal needs no adapter restoration. Before any nonterminal V6
continuation, the runtime supplies independently folded reservations to the
explicit adapter restore hook. Unresolved intents remain uncertain and are
never redispatched. Current V6 migration support preserves the selected
provider; changing provider is intentionally refused rather than treated as a
new durable policy chain. Model/policy identities may otherwise change only
through an already-authorized source/deployment migration handoff. V6 has
local targeted evidence only; it makes no hosted-provider, billing,
reconciliation, or provider-switch-migration claim.
