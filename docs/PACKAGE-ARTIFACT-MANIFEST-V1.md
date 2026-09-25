# Package Artifact Manifest v1

Status: implemented, bounded, local evidence contract for issue #195.
Audience: package, registry, and artifact-tooling contributors.

## Purpose

This manifest binds one package coordinate, its verified capsule/content/API
facts, one closed target profile, and one ordered artifact inventory. It is the
artifact evidence used by [Registry Snapshot v2](PACKAGE-REGISTRY-SNAPSHOT-V2.md);
Registry-v1 remains unchanged.

The schema is `semaprax.package-artifact-manifest.v1`. The compact canonical
object contains, in order: `schema`, `package`, `version`, `capsule_digest`,
`content_digest`, `api_abi_digest`, `target_profile`, `features`, `effects`,
`capabilities`, `artifacts`, and `nonclaims`. Its identity is SHA-256 over the
domain `semaprax.package-artifact-manifest.v1\0` followed by the exact canonical
manifest bytes. The domain-separated digest is carried by the registry entry,
not inside the manifest itself.

`create_from_linked_build` first replays Build-v2. It derives the capsule,
content, API, path, role, length, and SHA-256 facts from that replay and the
matching Subject-v3; callers do not supply trusted derived values.

## Closed initial profile

The only admitted target profile is
`linked-effect-free-core-wasm-scalar.v2`, the existing [Offline Linked Scalar
Core-Wasm Package Build v2](OFFLINE-LINKED-SCALAR-WASM-PACKAGE-BUILD-V2.md).
Its feature inventory is exactly, in this order:

1. `linked-packages`
2. `scalar-exports`

Effects and capabilities are both exactly empty. The artifact inventory is
exactly:

| Role | Path | Profile |
| --- | --- | --- |
| `core-wasm-module` | `module.wasm` | `linked-effect-free-core-wasm-scalar.v2` |
| `build-evidence` | `semaprax.package-build.evidence.json` | same |
| `build-manifest` | `semaprax.package-build.json` | same |

Every row also binds a nonzero bounded byte count and a lowercase SHA-256
digest. Roles, paths, rows, features, effects, and capabilities are ordered
inventories, not sets to be sorted or repaired by a consumer. Missing, extra,
duplicated, reordered, traversing, control-bearing, cross-profile, or spliced
inventory values fail closed.

## Bounds and replay

The manifest is at most 256 KiB. Inventories are capped at 32 items and the
artifact inventory is fixed at three. Submitted JSON is checked before DOM
use for byte count, compact canonical spelling, duplicate keys, trailing data,
maximum depth, and structural work. Decoding validates the closed profile,
regenerates the canonical bytes, and requires exact byte equality. Registry v2
then independently verifies the domain-separated digest. The three Build-v2
artifacts also have a checked cumulative limit of 16 MiB in the shared
create/decode/verify validator; the exact boundary is admitted, while boundary
plus one and a canonical three-times-16-MiB claimed inventory are refused.

Diagnostics are stable:

- `SPX-PKR614`: malformed or noncanonical manifest wire;
- `SPX-PKR615`: manifest digest association failure;
- `SPX-PKR616`: profile or inventory refusal;
- `SPX-PKR617`: manifest or inventory bound exceeded.

## Authority boundary and nonclaims

Creation, decoding, and replay are pure in-memory operations. Only the verified
producer API creates an admissible manifest; decoding a self-consistent wire is
inspection, not producer authentication. A manifest is evidence, not
permission. It grants no filesystem, registry, network, cache,
process, signing, execution, or publication authority. V1 makes no claim for
native artifacts, Component Model, WASI, dynamic linking, target execution,
cross-platform conformance, signatures, publisher identity, transparency, or
profiles with effects or capabilities.
