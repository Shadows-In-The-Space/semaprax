# Package Registry Snapshot v2

Status: implemented, bounded local replay contract for issue #195.
Audience: package-registry and resolver contributors.

## Additive relationship to v1

Registry Snapshot v2 is additive. [Registry Snapshot
v1](PACKAGE-REGISTRY-SNAPSHOT-V1.md), its document schema, canonical bytes,
decoder, digest domain, APIs, diagnostics, and behavior remain unchanged. V2
adds exactly one association: every admitted publication entry carries the
canonical bytes and domain-separated digest of one [Package Artifact Manifest
v1](PACKAGE-ARTIFACT-MANIFEST-V1.md).

The document schema is `semaprax.package-registry-document.v2`. Its exact
top-level fields are `schema` and `entries`. Entries retain the v1 publication
facts in their v1 order, followed by `artifact_manifest_digest` and
`artifact_manifest_bytes`. Entry order remains canonical `(package, version)`
order. V2 reuses the v1 snapshot builder to enforce Subject-v3 binding,
coordinate, namespace, immutability, ownership-continuity, status, and byte
bounds instead of maintaining a second interpretation of those facts.

For every admitted entry, `admit_linked_build` first runs exact Build-v2 replay
and derives the manifest. Arbitrary decoded or self-consistent caller-authored
manifests are not admissible inputs. The API consumes the publication and
populates its `api_digest` with the derived Build-v2 export-projection digest.
Replay establishes all of the following:

- the manifest digest binds its exact canonical bytes;
- manifest and publication package/version coordinates are identical;
- manifest `capsule_digest` equals the exact Build-v2 verified receipt;
- manifest `content_digest` equals the publication's Subject-v3 content
  digest;
- manifest `api_abi_digest` equals the publication's `api_digest`;
- the manifest admits the one closed linked scalar Core-Wasm build-v2 profile.

Cross-coordinate, cross-profile, cross-digest, cross-API, and cross-entry
manifest substitution therefore fail before a v2 snapshot is built.

## Snapshot envelope

The snapshot schema is `semaprax.package-registry-snapshot.v2`. Its compact
canonical envelope contains exactly `schema`, `digest`, `bytes`, and
`document`. `document` is the exact canonical document-v2 byte string;
`bytes` is its UTF-8 byte length; and `digest` is SHA-256 over the domain
`semaprax.package-registry-snapshot.v2\0` followed by those exact document
bytes. Document and snapshot are each capped at 16 MiB.

Decoding applies the repository's bounded canonical JSON scanner before DOM
construction, including duplicate-key, depth, work, trailing-data, and byte
limits. It then validates exact field order and types, replays every embedded
artifact manifest, regenerates the document and envelope, and requires exact
byte equality. `verify_snapshot` separately rebuilds from caller-owned entries
and compares the complete evidence, so a valid but stale or cross-paired
snapshot is rejected. Parsing returns the distinct
`DecodedManifestBoundEntry` inspection type; snapshot construction accepts
only `ManifestBoundEntry`, and no conversion promotes decoded evidence into
admission.

Diagnostics added by v2 are:

- `SPX-PKR618`: malformed or noncanonical document/snapshot wire;
- `SPX-PKR619`: digest, byte-count, manifest, or entry association failure;
- `SPX-PKR620`: document, snapshot, or entry-count bound exceeded.

## Authority boundary and nonclaims

Document construction, parsing, snapshot construction, decoding, and replay
are pure in-memory operations. They do not read artifacts or source files,
fetch registry data, execute target code, verify signatures, publish bytes, or
open filesystem/network/process authority. V2 does not turn the v1 opaque
signature claim into authentication and does not claim a hosted registry,
cache, key service, transparency log, general multi-target artifact format, or
artifact availability.
