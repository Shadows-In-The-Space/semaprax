# Agent iterative lifecycle v2

Audience: runtime integrators and compiler contributors.

This lifecycle runs checked Agent stages in a bounded loop. The reducer alone
chooses whether to continue, complete, suspend, or fail; suspension is data,
not durable restart authority in this version.

Status: **HOSTED GREEN** under the [v0.4.0 release baseline](RELEASE-0.4.0-STATUS.md).
That evidence update does not change the limits below.

`agent_lifecycle::iterative::compile_agent_lifecycle_v2` binds the checked
initialize, observe, authorize and reduce operations from an unchanged
AgentDefinition v1, plus one explicitly selected persistent Step type identity.
It independently checks the whole module and uses the ordinary retained
interpreter preparation and execution path for every deterministic stage.

Step is a monomorphic authored variant with exactly Continue, Complete,
Suspend and Fail cases. Continue and Suspend carry the exact State record's
flat fields in declaration order; Complete carries the Result record's flat
fields in declaration order; Fail carries one i64 code. Field types and every
Step/case/field identity are checked. The admitted leaves are Bytes and the
retained seam's five scalar types. Nested carriers remain outside this profile.
The mapping is derived from checked declarations, never provided by a caller.

Execution initializes once and repeats observe, scripted proposal decoding,
authorize, injected read, and reduce. Only a checked reducer return selects the
next transition. Continue feeds its State to the following turn. Complete,
Suspend and Fail publish their terminal carrier and stop. Suspension is data;
this version does not accept it as durable restart authority.

Every turn runs the authorize stage anew. Its opaque, consumed grant binds the
source-revision-bearing lifecycle digest, turn ordinal, exact State, canonical
proposal, grant case and seal. Cancellation is checked at each deterministic
stage and before dispatch. A caller supplies the only host read implementation;
there is no ambient authority. A failed effect never reaches reduce.

The source-selected `compile_source_agent_lifecycle_v2` bridge derives the
Definition from the same checked module and selected Agent identity.

Caller ceilings bound iterations, deterministic stage count and interpreter
fuel per stage. Hard ceilings of 4096 iterations and 12289 stage records bound
the allocation regardless of caller input. Reducer capacity is reserved before host dispatch. Evidence
binds a length-framed invocation digest of exact task bytes, task budget, all
ordered proposal bytes and all three execution ceilings before any stage
boundary. It records actual stage order, turn and effect counts, authorization bindings and
a terminal-carrier digest, without exposing payloads. Its schema and digest
domain are additive v2; all existing Lifecycle, Definition and Runtime v1
artifacts remain unchanged. This is a retained-interpreter profile.
[Typed operation registries](AGENT-TYPED-EFFECTS-V3.md),
[per-operation durable recovery](AGENT-OPERATION-CHECKPOINT-V2.md), and
[linked Project roles](PROJECT-LINKED-AGENT-LIFECYCLE-V1.md) are implemented
additions with their own contracts and the same hosted-green release baseline;
they do not retroactively widen this v2 wire.

Focused gate: `cargo test --locked -p semaprax --all-features --lib
agent_lifecycle::iterative::tests` (the original six-case focused corpus).
The selector remains the executable reference; its earlier local run is not
the current release's evidence ceiling.

The private frozen-run parity selector
`agent_lifecycle::tests::lifecycle_parity` additionally exercises this same
driver kernel with interpreter, native C11 `-O0`/`-O2`, and Core Wasm stage
dispatch. Its test-only entry supplies the backend explicitly, including the
Wasm source text as data. Both production frozen-run entries (ordinary and
migration-seeded) continue to select the interpreter. The live and checkpoint
routes do not gain a backend selector.

This authored local gate compares proposal admission, fresh authorization
bindings and consumed requests, an injected read operation, continued State,
terminal Result, stage order, turn/effect counters, cancellation and
iteration/stage ceilings. It requires `clang` and `node`; a tool-absent skip
is not execution evidence. Native now additionally settles borrowed stage
arguments and returned `Bytes` at the real boundary, with local allocation,
free, call, cancellation, receipt, and omission/duplication controls. The
reported native cleanup count remains limited to result-copy-out settlement;
it is not full instruction/finalizer parity. Core Wasm now reports that same
event only for a record `Bytes` projection that the replay-verified generated
Node facade returned as an owned `Uint8Array`: that return follows its private
arena's consume and settlement. The stage observer checks this typed result,
and the host requires an exact tagged row at the selected projection before
counting it; missing, extra, malformed and duplicate rows fail closed. This
does not report Wasm memory frees, variant-indexed-`Bytes` cleanup, or full
stage finalizer parity. The public target-stage route instead records one
backend-neutral reservation per settled stage: the checked per-stage cap times
the recorded stage count, bounded by the run-stage cap. Pre-dispatch
cancellation settles before this accounting; otherwise the sealed dispatch
rejects an invalid retained-call stage cap before native/Node admission on
every selector. This is comparable finite admission fuel, not instruction,
full cleanup-event, timing, or byte-identical cross-engine evidence. This private
selector does not extend the released production or hosted support claim.

The canonical v2 document explicitly records initialize-once, the iteration
order, Continue targeting observe, terminal cases, and exact Step case/field
mappings. It does not embed the v1 lifecycle wire or acyclic-only nonclaims.

## Canonical retained context for explicit hosts

`agent_lifecycle::canonical_retained_value_json` exposes the lifecycle's
existing canonical retained-value encoding as read-only host context. It does
not grant a capability, decode a proposal, modify a stage binding, or change
any lifecycle wire. An explicit host may carry those bytes into a provider
request only after it has separately acquired the host capability; the source
feedback driver remains the proposal decoder and bounded retry owner.
