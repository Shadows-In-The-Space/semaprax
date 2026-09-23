# Public Generic Wasm Component v1

Status: **private local execution profile; not public support**.

This specification defines an additive callable Component Model artifact over
the existing `public-generic-wasm-provider.v1` subject. It does not change the
WIT type projection, descriptor, carrier, Project profile, legacy build routes,
or PG-9 decision.

## Admission and derivation

The input is the exact checked `ProjectRevision` and the retained
`AdmittedPublicGenericEndpointV1` replayed by that revision. The endpoint must
remain synchronous and effect-free. The existing provider admission rule is
unchanged: both input and result have exactly two ordered owned-`Bytes` leaves.
No new source forms or leaf-count allowance are admitted here.

Derivation is deterministic and takes no caller-selected descriptor, endpoint,
binding, WIT, or toolchain facts. The artifact binds the exact replayed
descriptor bytes, the component-specific provider Core Wasm bytes, the Core
bridge/module composition, and the final Component bytes. A replay API
re-derives the provider and component from the same retained revision and
rejects any component-byte, component-digest, descriptor-digest, or provider-
digest mismatch before execution. The retained revision exposes
`public_generic_wasm_component_artifact_v1` and
`replay_public_generic_wasm_component_v1`; replay does not accept replacement
source, endpoint, or binding authority.

## Private calling convention

The Component exports one versioned `adapter` interface. Its callable surface
is intentionally flattened to the descriptor's ordered leaf inventory; the
existing type-only WIT projection continues to describe the authored record
types and is not reinterpreted as a calling convention.

```wit
package semaprax:public-generic-component@0.1.0;

interface adapter {
  resource owned-bytes {
    constructor(payload: list<u8>);
    read: func() -> list<u8>;
  }

  enum failure {
    contract-violation,
    resource-or-provider-refusal,
  }

  invoke: func(left: own<owned-bytes>, right: own<owned-bytes>)
    -> result<tuple<own<owned-bytes>, own<owned-bytes>>, failure>;
}

world public-generic-component-v1 {
  export adapter;
}
```

The first and second parameters are exactly input-leaf ordinals 0 and 1; the
successful result contains exactly result-leaf ordinals 0 and 1. They are not
reordered, sorted, or inferred from source spelling. The Component-owned
`owned-bytes` resource constructor copies the input list into a bounded
component resource. `read` returns a copy and does not consume the resource.
Consuming an `own` value transfers it to `invoke`; every success and error path
settles the consumed inputs. Dropping an owning resource invokes the generated
in-component destructor, which clears its bounded storage. A stale, closed,
borrowed-as-owned, or otherwise invalid handle fails closed.

The generated Core bridge constructs and validates the existing canonical
descriptor-bound input carrier, calls the exact checked provider, validates
and decodes its result carrier, and constructs output resources. It does not
call an imported host adapter, WASI service, or ambient capability. Core
provider status maps to the closed `failure` cases above; no unknown status is
treated as success. Checked pre/postcondition failure is reported as
`contract-violation`. Provider/codec refusal maps to
`resource-or-provider-refusal`. Exhausting the fixed Component resource slots
traps in the in-component constructor; it is not represented as either enum
case. Core execution is synchronous; this profile defines no retry or
cancellation behavior.

## Bounds and compatibility

Per-resource, total-payload, carrier-wire, descriptor, semantic-graph, and
provider bounds are inherited without increase from the owning descriptor,
carrier, and provider specifications. Resource-slot exhaustion traps;
aggregate payload and carrier limit violations detected by the checked
provider remain refusals. The resource arena starts on a page boundary after
the provider's bounded scratch/private workspace. Component-owned list staging
uses a separate 64 KiB realloc range; the constructor reclaims that one-list
cursor only after copying into resource storage, and positive-size realloc
limit/growth failures trap rather than returning address zero.

The standalone `public-generic-wasm-provider.v1` emission keeps its original
bytes, memory maximum, and reserve instruction stream. The component-specific
provider variant intentionally differs only by its two private codec-helper
exports, its disjoint private layout for codec workspaces/tables, maximum-size
payloads, aggregate records, and result carrier, the already-grown reserve
guard, and the larger bounded Core memory maximum needed for that layout and
the component resource/staging arenas. The Component-specific
artifact digest is separate from the Core provider binding domain; stable IDs
and the standalone provider binding remain unchanged.

WIT projection, compatibility reports, and Wasm provider v1 remain
independently versioned. Adding this callable artifact does not change their
bytes or imply compatibility with other WIT/component producers.

## Evidence and nonclaims

The current local evidence includes deterministic retained-revision
derivation/replay, tampered component/provider-digest metadata refusal, and one
successful invocation under the repository-pinned Wasmtime 47.0.4 harness. The
runtime selector checks no ambient imports, ordered two-leaf byte identity at
the exact 64 KiB per-leaf bound, preservation of an unrelated live resource,
resource read/drop, 200 maximum-size constructor/read/drop reuse cycles, and a
second successful invocation after replay rejected tampered bytes. This is
focused private evidence, not a support claim.

Interpreter/native C11 `-O0`/`-O2`/Core-Wasm differential parity,
contract-failure execution, stale descriptor/provider runtime bindings,
use-after-close, double-close, and broader resource/payload hostile cases
remain unclaimed and outside the evidence of this focused selector. The
retained artifact replay test rejects mutated Component bytes and mismatched
provider-digest metadata; the runtime test itself does not execute a tampered
candidate. Component bytes remain immutable during the successful runtime
test and the Component requests no ambient imports.

Cancellation, hosted/provider acceptance, publication, PG-9 support, arbitrary
Component Model inputs, effects, asynchronous work, and every source shape
beyond the two-leaf owned-`Bytes` provider slice are explicitly unclaimed.
