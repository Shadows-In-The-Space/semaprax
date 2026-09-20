# Agent target host-call protocol v1

Status: **private authored implementation for #182; not yet selected by a
production lifecycle driver.**

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
request-byte, and fuel ceilings. It reserves call/request/fuel accounting
atomically before dispatch. Therefore cancellation, exhausted budget/fuel,
wrong argument identity, and invalid grant material reach no host adapter. The
future trusted driver remains responsible for supplying the exact deployed
operation and invocation root when it binds the grant; this private tranche is
not yet independent evidence that those wiring facts are current. A dispatched
call remains charged if the host
fails, panics, returns an oversized carrier, or returns malformed/wrongly typed
bytes.

The request contains only a hashed opaque grant identity, exact operation
facts, turn, fuel, and a closed length-framed typed argument carrier. It never
contains the authorization seal, filesystem/process/network capability,
source pointer, Wasm linear-memory pointer, mutable accounting handle, or a
way to dispatch another operation. A target adapter is injected by the caller;
the protocol creates no provider or ambient authority.

Host result bytes are independently decoded as
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

## Required future wiring

The iterative target executor must, after its current checked authorization
stage and before an injected model/effect callback:

1. move the fresh `Authorized` into `TargetGrant::bind` using the exact
   invocation root, turn, and deployed operation;
2. construct the argument `TypedCarrier` from the checked Proposal projection;
3. pass the existing cancellation and lifecycle/effect ceiling ledger to
   `target_protocol::dispatch`; and
4. use `TargetEvidence` for parity comparison while retaining existing
   lifecycle/effect evidence and failure selection.

It must not deserialize grants, call the host before this boundary, treat a
target artifact as proof of execution, or describe this private protocol as
production target support. Per #182, durable/distributed checkpoint transport,
arbitrary nominal carrier ABI, ambient providers, physical trap recovery, and
hosted target evidence remain outside this tranche.

Focused implementation gate (run by the coordinating agent):

```sh
cargo test --locked -p semaprax --lib agent_lifecycle::authorization::target_protocol
```
