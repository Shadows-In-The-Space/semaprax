# Agent target host-call protocol v1

Status: **authored implementation for #182; publicly selectable through the
source-live typed-effect target adapter with an explicitly injected host.** It
is not deployed native or Wasm target support.

This document owns the target-neutral host-call boundary in
`agent_lifecycle::authorization::target_protocol`. It is additive to the
retained-interpreter lifecycle, typed-effects v3, and private C11/Core-Wasm
stage executor seam. It does not claim that an Agent stage has been moved to a
production native or Wasm route.

## Contract

One freshly minted `Authorized` value is moved into `TargetGrant::bind`. The
grant is opaque and non-cloneable. Its target-private identity is derived from
the consumed lifecycle binding and seal, exact invocation root, turn ordinal,
the source-owned operation/effect/argument/result identities, and the exact
typed argument carrier commitment. A binding
string, scalar, serialized checkpoint, target pointer, or host adapter cannot
be accepted in place of that moved value.

Before the host receives a request, the boundary checks cancellation, the
argument type identity, the grant's budget, and the cumulative call,
request-byte, aggregate-byte, and fuel ceilings. It reserves call/request/fuel
accounting atomically before dispatch. Therefore cancellation, exhausted
budget/fuel, wrong argument identity, and invalid grant material reach no host adapter. The
source-live typed-effect adapter derives its selected operation from checked
registry facts and supplies the live invocation root and turn when it binds
the grant. This remains in-process evidence only. A dispatched call remains
charged if the host
fails, panics, returns an oversized carrier, or returns malformed/wrongly typed
bytes.

The request contains only a hashed opaque grant identity, exact operation
facts, turn, fuel, and a closed length-framed typed argument carrier. It never
contains the authorization seal, filesystem/process/network capability,
source pointer, Wasm linear-memory pointer, mutable accounting handle, or a
way to dispatch another operation. A target adapter is injected by the caller;
the protocol creates no provider or ambient authority.

The injected handler writes through a protocol-owned bounded response sink; it
cannot make the boundary allocate or hash beyond the effective result,
aggregate, and carrier ceilings. Host result bytes are independently decoded as
`semaprax.agent-target-carrier.v1`: schema frame, exact result type identity,
payload frame, and no trailing bytes. The result-size ceiling is applied before
carrier parsing. Every terminal outcome normalizes into the closed `Settlement`
domain, with the first selected result retained; no cleanup or error conversion
may replace it.

## Evidence and replay

`TargetEvidence` records the opaque grant identity, authorization binding,
operation facts, turn, request/result commitments, reservation accounting,
dispatch bit, and normalized settlement. Its domain-separated digest is a
common semantic observation for retained, C11, and Core-Wasm adapters. Both
the request and observation have exact bounded length-framed v1 canonical
wires. `TargetEvidence::decode` independently rejects malformed, noncanonical
or internally inconsistent observations; `replay_wire` then rederives the
request commitment from the retained request wire and checks the observation
without invoking a handler. It does not receive or independently replay result
bytes, and cannot construct a grant, run target code, resume a checkpoint, or
publish an artifact. Decoding a request is deliberately private to replay, so
request bytes cannot be converted into a dispatch capability.

`TargetEffectRun` retains each complete `TargetEvidence` in execution order as
well as its digest in the compact aggregate document. A caller that retained
the exact host-visible request can therefore invoke the independent replay;
the aggregate is not a substitute for those request bytes.

## Current wiring and remaining work

The source-live typed-effect target adapter now, after its current
checked authorization stage and before its injected target handler:

1. move the fresh `Authorized` into `TargetGrant::bind` using the exact
   invocation root, turn, and deployed operation;
2. construct the argument `TypedCarrier` from the checked Proposal projection;
3. pass the existing cancellation and lifecycle/effect ceiling ledger to
   `target_protocol::dispatch`, with independent request, result, aggregate,
   and fuel ceilings; and
4. use `TargetEvidence` for parity comparison while retaining existing
   lifecycle/effect evidence and failure selection.

It must not deserialize grants, call the host before this boundary, treat a
target artifact as proof of execution, or describe this selectable protocol as
production target support. Per #182, durable/distributed checkpoint transport,
arbitrary nominal carrier ABI, native/Wasm backend selection, ambient
providers, physical trap recovery, and hosted target evidence remain outside
this tranche.

The crate-internal parity selector additionally drives this same live target
loop through the sealed interpreter, native C11 `-O0`/`-O2`, and Core-Wasm
stage executors. It compares the terminal carrier, target accounting, each
canonical host request and each canonical target observation, then decodes and
replays every retained observation against its request wire without handler
work. A pre-cancelled run reaches no handler on the interpreter, native and
Wasm legs. This is local execution evidence only; it does not add a public
backend selector, a deployed target adapter, durable target replay, or a
claim that target artifacts themselves provide authority.

The same local parity profile now composes an additive source-model boundary
before Proposal decoding. `iterative::model::TargetModelSource` converts only
the lifecycle-owned `ProposalRequest` into a bounded canonical v1 host request,
including exact turn/attempt, source revision, Proposal grammar, task, checked
state/observation, prior effect and retry context. Its private move-only grant
is bound to those bytes and one caller-selected deterministic model root; the
host receives only the opaque grant digest and request document. Cancellation,
call/request/aggregate/fuel exhaustion refuse before the injected model host.
Dispatched attempts remain charged after a host failure, panic, overflow or
non-UTF-8 response.

Each model attempt retains a canonical bounded observation with cumulative
accounting and a normalized settlement. Independent decoding and request-pair
replay cannot construct a grant or dispatch a host. The combined parity case
compares model request/evidence bytes, target-effect request/evidence bytes,
terminal values and both accounting ledgers across interpreter, native C11
`-O0`/`-O2`, and Core Wasm. This remains an injected local seam: it is not the
Direct Runtime provider adapter, a physical provider, durable model recovery,
public target ABI, or hosted target support.

Focused implementation gate (run by the coordinating agent):

```sh
cargo test --locked -p semaprax --lib agent_lifecycle::authorization::target_protocol
```
