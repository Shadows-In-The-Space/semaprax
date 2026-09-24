# Package Leaf Artifact Manifest v1

Status: additive local producer-admission contract; no hosted or distribution
authority claim. Audience: package and registry contributors.

This version fills the dependency-free producer gap without widening the
two-through-four reachable-package Source Capsule v1 or Linked Build v2.
`package_registry::leaf_manifest_v1::create_from_leaf_build` invokes the existing
[Build-v1 verifier](OFFLINE-PURE-WASM-PACKAGE-BUILD-V1.md) on all three artifacts
and exact original resolver evidence, catalog, options and build options. That
verifier independently regenerates the single selected dependency-free source,
HIR, scalar Core-Wasm, manifest and evidence. It gains no filesystem, execution,
network, signing or publication authority.

The publication's independently replayed Subject-v3 must have the same package
and version, no dependencies and no capabilities. Reconstructing Subject-v2
from its exact Report-v2 and empty dependency/capability inventories must equal
the uniquely selected original Subject-v2 bytes. Thus a report with the same
interface but different implementation cannot be substituted. Build-v1's exact
single selected coordinate and root must equal the publication. The ordinary
registry-v1 publication/namespace/content checks are retained. API identity is
derived from verified export facts, never supplied as trusted input. An empty
publication `api_digest` is explicitly a builder-template placeholder. A
nonempty value must equal the derived digest or admission fails with
`SPX-PKR631`; a mismatched caller claim is never silently repaired.

The producer returns `AdmittedLeafManifest`; byte-only `inspect` and
`inspect_with_digest` return the distinct `InspectedLeafManifest`. There is no
conversion from inspection to producer admission. All values are evidence,
not publisher authentication or fetch capabilities.

## Closed wire

Schema and digest domain are `semaprax.package-leaf-artifact-manifest.v1`;
digest is SHA-256 of the domain, NUL, then exact bytes. Compact JSON has the
following exact ordered fields:

`schema, package, version, content_digest, api_abi_digest, source_revision,
report_digest, subject_v2_sha256, resolution_sha256, target_profile, features,
effects, capabilities, artifacts`.

`content_digest` binds raw exact Subject-v3 bytes. Source revision and report
digest are the verified Subject-v3 facts. `subject_v2_sha256` and
`resolution_sha256` are raw exact-byte hashes, explicitly not capsule digests.
No capsule identity is invented for a standalone leaf. API digest reuses
`semaprax.package-artifact-api-abi.v1` plus NUL and compact verified export-array
bytes. The profile is exactly `effect-free-core-wasm-scalar.v1`; features are
exactly `["scalar-exports"]`, effects and capabilities empty.

Artifacts are exactly three rows, each with ordered fields
`role, path, bytes, sha256, profile`:

| Role | Path |
| --- | --- |
| `core-wasm-module` | `module.wasm` |
| `build-evidence` | `semaprax.package-build.evidence.json` |
| `build-manifest` | `semaprax.package-build.json` |

Profile on every row equals the leaf profile. Lengths are nonzero and their
checked sum is at most Build-v1's 16 MiB maximum. Exact raw file bytes determine
each SHA-256. The manifest is at most 256 KiB. A bounded duplicate-key/compact
JSON scanner precedes deserialization; unknown fields, noncanonical spelling,
wrong order, trailing data, wrong profile/inventory and bad digest associations
refuse. Re-rendered bytes must equal submitted bytes.

`SPX-PKR630` identifies new distribution shape/profile/bound refusal and
`SPX-PKR631` exact producer/source/coordinate/API association disagreement.
Existing build, report, subject and registry diagnostics propagate unchanged.

## Evidence and limits

Focused tests live with Registry-v3 in
`src/package_registry/registry_v3/tests.rs`. They build a real standalone leaf
and a real linked root using identical leaf implementation source, prove exact
manifest replay and exercise source/report, artifact, evidence, coordinate,
API, profile and inventory substitution. Artifact Manifest v1 continues to
reject leaf wire. Build-v1/v2 and Source Capsule v1 semantics are unchanged.
Native, generics, broader ABIs, target execution, cryptographic publisher
authentication, hosted service, transport, cache and publication are not part
of this additive admission path.
