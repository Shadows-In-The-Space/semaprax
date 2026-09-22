# Public Generic Wasm Provider Target v1

Status: **internal admission and compiler-owned Core Wasm artifact implemented**.

This document owns the additive compiler target selected by the Package
Manifest v1 profile `public-generic-wasm-provider.v1`. It creates a checked,
replayable compiler subject and a closed executable provider for issues #162
and #229. It does not publish a supported public generic ABI.

## Manifest contract

The profile is available only through the canonical `semaprax.manifest.v1`
table layout. It lowers to the internal project contract
`semaprax.project.v20`; no frozen positional v20 manifest is accepted.

The manifest must contain:

- exactly one stable ID in `[exports] web`;
- no command table;
- no capability request;
- no effect, interface, permit, or publication authority; and
- the ordinary bounded source and test-module inventories.

Existing scalar, text, byte, owned-data, and record profiles are unchanged.
In particular, this profile does not relax `SPX-W115` or reinterpret an
existing `web_export` calling convention.

## Admission product

`src/project/admission/public_generic_wasm.rs` selects the one checked export
from the aggregate-aware linked public program. It calls the existing Public
Generic Descriptor v1 producer and immediately replays the resulting bytes
through the independent verifier. The admitted endpoint retains, as one unit:

- the explicit endpoint stable ID and presentation name;
- the exact concrete generic input and result instance facts;
- the compiler-derived owned-leaf inventory and settlement plan; and
- the verified canonical descriptor bytes and descriptor digest bound to the
  exact project revision and checked program root.

Admission follows the frozen Public Generic Boundary Profile v1. The endpoint
is synchronous and effect-free, has exactly one `own` concrete authored record
instance input, and returns a concrete authored record instance. All existing
depth, field, leaf, payload, and cleanup-plan bounds continue to apply.

`ProjectRevision::public_generic_wasm_provider_endpoint_v1` does not trust the
retained Rust object as a shortcut. It replays the canonical bytes against the
retained checked program and exact project revision before returning a new
admitted value. Project Lock v1 records the replayed descriptor digest as the
profile's interface identity.

## Artifact boundary

`ProjectRevision::public_generic_wasm_provider_artifact_v1` replays the
retained endpoint and deterministically emits the dedicated artifact. The
following unrelated publication routes still fail before staging or creating
output:

- pathless and filesystem Web builds;
- npm/package builds;
- native executable builds; and
- Agent Transport build requests.

Their refusal names `public-generic-wasm-provider.v1`; this internal artifact
does not silently reopen legacy Web/npm/native/transport contracts.

## Implemented Phase B artifact

The emitter consumes only `AdmittedPublicGenericEndpointV1`; it does not
regenerate a fixture descriptor or accept caller-selected endpoint facts. It
deterministically emits one closed Core Wasm module with no ambient imports and
the versioned provider operations for:

1. provider open and exact descriptor/binding replay;
2. bounded canonical input preparation and copy-in;
3. whole-value transfer and invocation of the selected checked function;
4. private result staging followed by exact non-consuming copy-out; and
5. explicit value, result, and provider release.

The module owns scratch growth, opaque non-recycled handles, carrier SHA-256
replay, checked source invocation, result staging/export, and explicit
release/close transitions. Its binding covers normalized exact artifact bytes,
endpoint export, compiler backend, descriptor, runtime identity, and Core Wasm
target. The generated TypeScript runtime now calls these exports and no longer
contains an allocator or handle registry.

The remaining #229 integration gap is canonical carrier generation in the
TypeScript package: its older flat leaf codec is deliberately rejected by the
new module. The retired hand-assembled reference module is now a negative
compatibility fixture only. The compiler artifact's full successful lifecycle
is executed directly under Node, but #229 is not closed until the generated
TypeScript carrier codec emits the canonical descriptor-bound frames too.

## Nonclaims

The implemented Phase A product is not:

- a public or supported generic ABI;
- a replacement for the C11 reference provider or in-process Wasm model;
- proof that any physical adapter invokes the selected Semaprax function;
- permission to publish npm, native, Web, component, or transport artifacts;
  or
- completion of PG-7, PG-8, PG-9, issue #162, or issue #229.

The native settlement harness now derives and independently verifies one real
generic source subject before generating its C, C++, and Rust callers. The
physical provider still invokes the explicitly labelled reversal fixture;
that narrower improvement must not be described as compiler-derived endpoint
execution.

## Focused gates

The repository pins this phase with:

```sh
cargo test --locked -p semaprax --test project -- \
  public_generic_wasm_provider --test-threads=1
cargo test --locked -p semaprax --test public_generic_wasm_adapter_v1 -- \
  compiler_provider_artifact --test-threads=1
cargo test --locked -p semaprax --test public_generic_native_adapter_v1 -- \
  consumer_settlement:: --test-threads=1
```

The first gate covers manifest selection, checked admission, deterministic
artifact derivation, Project Lock binding, source-drift identity, shape/count
refusals, and fail-closed legacy output routes. The second validates the exact
zero-import export inventory and executes open/prepare/checked-call/export/
release/close under Node. The third proves that executed native generated
callers and their provider use the same compiler-derived descriptor, binding,
instance, leaf, and settlement identities while retaining the fixture endpoint
nonclaim.
