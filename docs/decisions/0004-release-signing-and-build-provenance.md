# ADR 0004: Release signing and build provenance via Sigstore keyless identity

Audience: maintainers deciding GitHub issue #168; release-tooling and CI
contributors.

- Status: **Accepted on 2026-09-19, by the repository maintainer (Kevin,
  `kevin.riedl@wavect.io`, `wavect/semaprax` owner).** The maintainer
  delegated this decision to the implementing agent under one stated
  constraint: choose whatever is best practice and best for the language long
  term, including competitive advantage. What follows is that delegation
  exercised, written down by the agent as scribe rather than self-approved.
- Supersedes: nothing. First signing decision for this repository.
- Related: #168 (this decision), #209 (audit capsule signature verification,
  already implemented), ADR 0002 (managed workspace generations).

## Decision

**Sign releases with Sigstore keyless identity, minted from the GitHub Actions
OIDC token, with Rekor transparency-log inclusion. Do not adopt a long-lived
maintainer-held signing key.**

Two mechanisms, chosen per artifact shape:

1. **`actions/attest-build-provenance`** for release archives and generated
   packages. This is the lower-friction path for GitHub-hosted artifacts and
   produces SLSA v1.0 provenance.
2. **`cosign` keyless** for the OCI Image Layout this repository already
   emits (`crates/semaprax-oci-package`). Container-shaped artifacts belong in
   the ecosystem that verifies container signatures.

Both are Sigstore-backed, so this is one trust model with two front ends, not
two competing systems.

## Why keyless, and not a maintainer key

This repository's central invariant is that **authority is explicit and never
ambient**: "Compiler and generated code gain no ambient filesystem, process,
network, home, secret, key, wallet, or signing authority."

A long-lived GPG or minisign key stored as a CI secret is precisely ambient
signing authority. Any workflow that can read the secret can sign anything, the
key must be rotated by a human, and its compromise is silent and unbounded in
time.

Keyless signing replaces *"prove you have this key"* with *"prove you are this
identity"*. Fulcio issues a short-lived X.509 certificate carrying the workflow
identity in its SAN extension; there is no key at rest, no secret to rotate,
and the signing capability is scoped to one workflow run. That is the same
shape as every other capability in this language.

## Why this is a competitive advantage, not just hygiene

SEMAPRAX's claim is **meaning in, verified machine code out**. Almost every
project that signs artifacts binds a signature to *bytes*. This repository can
bind provenance to **bytes and the semantic graph revision that produced
them** — `project_revision`, `workspace_revision`, and `project_graph_digest`
already exist and are already deterministic.

An attestation whose subject carries both the artifact digest and the graph
revision lets a consumer verify not merely "this binary came from this repo"
but "this binary is the compilation of this exact meaning." For an agent-native
language, where the artifact's provenance question is *"which semantics did an
agent actually ship?"*, that is the differentiating claim. It is also
achievable now, because the digests exist and the build service generates the
provenance.

## Required operational constraints

These are not optional details; each has a failure mode that silently produces
a worthless signature.

- **Pin `--certificate-identity` and `--certificate-oidc-issuer` at
  verification.** Without both pins a verifier can only conclude *someone*
  signed the artifact, not that **this workflow** signed it. An unpinned
  identity is worth nothing — the same property the #209 trust roster already
  enforces internally, where an empty roster means "not verified" and must
  never render as "verified".
- **`permissions: id-token: write`** on the signing job. Without it GitHub
  issues no OIDC token at all.
- **Sign in the job that produced the artifact, immediately after the build.**
  GitHub OIDC tokens are valid for roughly five minutes. This repository's
  matrix runs for hours, so a separate downstream signing job would routinely
  present an expired token to Fulcio. This constraint dictates workflow
  topology and must be respected when #168 is implemented.
- **Record inclusion in the public Rekor transparency log**, so a signature
  cannot be produced and later repudiated or silently replaced.

## Relationship to the audit capsule (#209)

These are complementary layers and must not be conflated in any report:

- The **audit capsule** (`ed25519-raw-v1`, verified against an explicit trust
  roster) is the *internal* substrate. It proves object associations for a
  change, an Agent run, or a release, and it carries no authority of its own.
- **Sigstore** is the *external* anchor. It proves which build identity
  produced an artifact, to a third party who has never seen this repository's
  roster.

The capsule answers "do these objects belong together?"; Sigstore answers "who
built this, and can a stranger check?". Neither substitutes for the other.

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
