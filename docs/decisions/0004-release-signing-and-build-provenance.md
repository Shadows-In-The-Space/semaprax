# ADR 0004: Release signing and build provenance via Sigstore keyless identity

Audience: maintainers deciding GitHub issue #168; release-tooling and CI
contributors.

- Status: accepted on 2026-09-19 by the repository maintainer, who delegated
  the choice of signing model to the implementing agent. This records that
  choice; it is not a claim that a release has been signed.
- Supersedes: nothing. First signing decision for this repository.
- Related: #168 (this decision), #209 (audit capsule signature verification,
  already implemented), ADR 0002 (managed workspace generations).

## Decision

Use Sigstore keyless signing from the GitHub Actions OIDC identity and require
Rekor transparency-log inclusion. Do not keep a long-lived maintainer signing
key.

Two mechanisms, chosen per artifact shape:

1. Use **`actions/attest-build-provenance`** for release archives and
   generated packages. It produces SLSA v1.0 provenance.
2. Use **`cosign` keyless** for OCI Image Layout artifacts from
   `crates/semaprax-oci-package`.

Both use the same Sigstore trust model.

## Why keyless, and not a maintainer key

SEMAPRAX does not grant ambient signing authority. A long-lived CI signing
key would give any workflow holding it broad authority until rotation. Keyless
signing instead binds a short-lived Fulcio certificate to one workflow
identity and run; there is no signing key at rest.

## Bind bytes to meaning

The attestation should bind an artifact digest to the semantic graph revision
that produced it. The deterministic `project_revision`,
`workspace_revision`, and `project_graph_digest` fields provide the inputs.
That association needs its own verified schema; a signature over bytes alone
does not prove which program meaning was compiled.

## Required operational constraints

Each requirement prevents a signature that cannot establish the intended
publisher:

- **Pin `--certificate-identity` and `--certificate-oidc-issuer`.** Without
  both, verification proves only that someone signed the artifact, not that
  the authorized workflow did.
- **Grant `permissions: id-token: write` to the signing job.** GitHub otherwise
  issues no OIDC token.
- **Sign in the artifact-producing job, immediately after the build.** A
  downstream job may miss the short OIDC token lifetime.
- **Record Rekor inclusion** so the signature is publicly auditable.

## Relationship to the audit capsule (#209)

These layers answer different questions:

- An **audit capsule** (`ed25519-raw-v1`) binds internal objects against an
  explicit trust roster. It grants no authority.
- **Sigstore** lets an outside consumer verify the artifact's build identity.

Neither substitutes for the other.

## Consequences

- No signing secret is ever stored in this repository or its CI configuration.
- Verification instructions must ship with the pinned identity and issuer, or
  they teach users a check that proves nothing.
- Offline verification requires the Rekor inclusion proof and the certificate
  chain to be bundled with the artifact, since keyless verification otherwise
  assumes network reach — relevant because this repository's own CI runs
  `--locked --offline` in many jobs.
- Nothing here grants the compiler or generated code any signing capability.
  Signing happens in the release workflow, never in the toolchain.

## What this ADR does not decide

- The exact attestation subject schema binding artifact digest to graph
  revision. That is implementation work under #168.
- Whether crates.io or npm publication carries its own provenance. Deferred to
  #145's scoped release automation.
