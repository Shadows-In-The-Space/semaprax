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
common semantic observation for retained, C11, and Core-Wasm adapters. It is
not authority: `replay` recomputes the request commitment and checks the
retained observation digest without invoking a handler. It does not receive or
independently replay result bytes, and cannot construct a grant, run target
code, resume a checkpoint, or publish an artifact.

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

Focused implementation gate (run by the coordinating agent):

```sh
cargo test --locked -p semaprax --lib agent_lifecycle::authorization::target_protocol
```
