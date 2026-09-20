# Release signing and provenance policy v1

Status: versioned trusted-identity policy and schema contract. The keyless
workflow path is configured; no SEMAPRAX release is signed today, and only a
completed hosted tag run with immutable assets can change that status.

Audience: maintainers, release engineers, and security reviewers.

## Scope and current state

[Issue #168](https://github.com/wavect/semaprax/issues/168) asks for
authentic signing and machine-verifiable provenance for tagged releases.
Nobody working this issue has a signing key, a local keyless-signing (Sigstore)
identity, a registry credential, or authority to publish, tag, or trigger a
release workflow; per `AGENTS.md`, generated code and this repository's own
tooling gain no ambient signing authority. The configured GitHub-hosted
`publish-release` job alone receives a short-lived OIDC token when it runs.
This document and its paired implementation therefore split the work into what
is safely buildable without any secret -- the **provenance document**, the
**identity policy**, and **binding verification** -- and the hosted evidence
and human review that remain after wiring.

**The release archives remain unsigned.** `docs/RELEASE-PROCESS.md`'s
nonclaims correctly still say so, and this document must not be read as
superseding that until the checklist below is actually completed and a real
signed release has shipped.

## Threat model

| Threat | What defends against it today | What remains open |
| --- | --- | --- |
| **Artifact substitution** (a downloaded archive differs from what CI built) | `scripts/release-manifest.py` binds each archive's exact SHA-256 digest; `src/release_provenance.rs` independently re-hashes archive bytes against the manifest ([`verify_manifest_artifacts_on_disk`]) | No signature over the manifest exists yet, so a compromised mirror could still substitute a manifest *and* its archives together |
| **Tag movement** (a tag is force-moved to a different commit after release) | `docs/RELEASE-PROCESS.md`'s "Never move or recreate a published release tag" rule; Git tag objects are content-addressed | This is a process rule, not a cryptographic one; nothing here detects a force-pushed tag after the fact |
| **Compromised workflow** (a modified `ci.yml` builds from unexpected inputs or an unapproved ref) | The identity policy below binds a claimed signature to an exact `issuer`/`subject`/`workflow_ref`, checked by [`verify_signature_claim_binds_provenance`] | No real signature exists to carry that identity yet; a compromised workflow could still forge a structurally valid but unsigned claim, which is exactly why this module never treats claim validity as proof |
| **Compromised maintainer account** (a valid GitHub credential publishes an unreviewed release) | `release-gate`'s required-check aggregation (`tests/offline_package/ci_release_gate.rs`) still must pass before `publish-release` runs | Keyless signing scoped to the *workflow* identity (not a personal account) is specifically the mitigation Sigstore/Fulcio provides for this threat, and is not wired up yet (see checklist) |
| **Stale or revoked identity** (a signature claims an identity that was valid in the past but has since been revoked) | The identity policy is a single versioned table (this document), not per-signature configuration, so revoking an identity is one document edit | No revocation list or expiry mechanism exists; Sigstore's own short-lived certificates (minutes, not the lifetime of a long-lived key) are the recommended mitigation, not built here |
| **Mirror or download corruption** (bit rot, a lossy proxy, an incomplete download) | SHA-256 digests already catch this (`docs/RELEASE-PROCESS.md`'s existing nonclaims) | Unchanged by this document |
| **Replayed provenance** (an old, validly-signed provenance/signature pair is presented alongside a newer release's artifacts) | [`verify_signature_claim_binds_provenance`]'s `subject_digest` is a byte-exact digest of the *exact* provenance document under test; a claim computed over a different version's provenance bytes cannot match | None identified beyond digest binding, which is sufficient here because there is no shared key material across versions to replay |
| **Mutable manifest signed too early** (signing an inventory before the final artifact set is known) | `scripts/release-manifest.py` is built only after every target archive exists (`collect_artifacts` fails closed on a missing target); a provenance document's `manifest_digest` binds to that exact, already-complete manifest | The checklist below states this ordering as a hard requirement for the real signing step, since nothing here can enforce workflow step ordering |

## Trusted identity policy v1

These three values are the single source of truth for "which identity is
trusted to have built a SEMAPRAX release." They are enforced, byte-for-byte,
by `src/release_provenance.rs`'s `TRUSTED_ISSUER`/`TRUSTED_REPOSITORY`/
`TRUSTED_WORKFLOW_PATH` constants and by the equivalently named constants in
`scripts/release-provenance.py`; `tests/offline_package/release_provenance.rs`
cross-checks all three (code, script, and this table) agree.

| Field | Value | Meaning |
| --- | --- | --- |
| Trusted OIDC issuer | `https://token.actions.githubusercontent.com` | The only accepted token issuer for a keyless (Sigstore/Fulcio) identity -- GitHub Actions' own OIDC provider. A claim from any other issuer is rejected regardless of its other fields. |
| Trusted repository | `wavect/semaprax` | The only accepted GitHub repository slug. |
| Trusted workflow path | `.github/workflows/ci.yml` | The only workflow file whose run may claim to have produced a release. |
| Tag pattern | `refs/tags/v<MAJOR>.<MINOR>.<PATCH>` | Bound per-release, not globally: verification always compares against the *exact* tag the provenance statement under test itself declares (its `tag` field), not a wildcard. This is what makes "replayed provenance from another version" fail: the expected identity subject is recomputed from the tag under test, so a claim minted for `v0.4.1` cannot satisfy a check against `v0.4.2`. |

The expected GitHub OIDC **`sub` claim** for a release built from tag
`vX.Y.Z` is exactly:

```
repo:wavect/semaprax:ref:refs/tags/vX.Y.Z
```

The Fulcio certificate identity used by `cosign verify-blob` is the workflow
URL SAN, exactly:

```
https://github.com/wavect/semaprax/.github/workflows/ci.yml@refs/tags/vX.Y.Z
```

The corresponding provenance **workflow reference** (the same identity
without the URL scheme and host) is exactly:

```
wavect/semaprax/.github/workflows/ci.yml@refs/tags/vX.Y.Z
```

These are GitHub Actions' standard identity representations for a
tag-triggered workflow run using `id-token: write`. The OIDC `sub` claim and
the Fulcio certificate URL SAN are deliberately distinct; the former belongs
in the structural signature claim below, while the latter is passed to
cosign's `--certificate-identity` verification option.

### Rotation and revocation

Because the policy is exactly this one table, not per-signature
configuration or a certificate transparency log this repository maintains,
rotation and revocation are document edits:

- **Repository or workflow path change** (e.g. a rename or workflow-file
  move): update `TRUSTED_REPOSITORY`/`TRUSTED_WORKFLOW_PATH` in
  `src/release_provenance.rs` and `scripts/release-provenance.py` and this
  table together, in the same commit, so the cross-check test in
  `tests/offline_package/release_provenance.rs` keeps them from drifting.
  Every release signed under the old identity remains verifiable against a
  policy version pinned to the commit that produced it (this is why the
  policy is versioned, not floating).
- **Suspected compromise of the workflow's OIDC identity**: there is no
  long-lived key to revoke in a keyless model -- each certificate is
  short-lived (Sigstore's Fulcio certificates are valid for minutes). The
  actionable response is to rotate the *workflow* (disable the compromised
  `ci.yml` run, audit and fix it, and require every subsequent release to be
  re-verified against the corrected workflow's identity) rather than to
  revoke a key.
- **A specific past release later found compromised**: record the finding in
  `docs/RELEASE-PROCESS.md`'s dated evidence section for that version (never
  silently delete or rewrite history), and do not backdate a "signed" claim
  onto it -- see "Explicitly out of scope" in issue #168.

## Schemas

### `semaprax.release-provenance.v1`

Built by `scripts/release-provenance.py` from an already-built
`semaprax.release-manifest.v1` (#167). Never restates the manifest's
version/tag/commit/prerelease/required_checks/artifacts fields independently
-- it copies them verbatim and additionally records a byte-exact
`manifest_digest`, so a verifier can catch a single-byte edit to the
manifest even if the edit reparses to the same JSON value.

| Field | Type | Meaning |
| --- | --- | --- |
| `schema` | string | Always `semaprax.release-provenance.v1`. |
| `version` / `tag` / `commit` / `prerelease` | as in the manifest | Copied verbatim from the manifest; must agree exactly. |
| `required_checks` | array of strings | Copied verbatim from the manifest's required-check inventory. |
| `artifacts` | array of `{name, platform, size, digest}` | Copied verbatim from the manifest's artifact inventory. |
| `manifest_digest` | `sha256:<64 lowercase hex>` | Digest of the exact manifest bytes this document was built from. |
| `source.repository` / `source.commit` / `source.tag` | strings | The exact source commit and tag; `repository` must equal the trusted repository. |
| `builder.workflow_identity` | string | `<repository>/<workflow path>@refs/tags/<tag>` -- what the builder claims produced this release. Checked against the trusted identity policy at build time (the script itself rejects a mismatch) and again at verification time (bound to the claim's identity). |
| `builder.run_id` / `builder.run_attempt` | strings | The workflow run that produced this document, for operator traceability. Not independently verified -- see nonclaims. |
| `toolchain.rustc_version` | string | The Rust compiler version used to build the release binaries. |
| `toolchain.cargo_locked` | boolean | Always `true`: every packaging command in `docs/RELEASE-PROCESS.md` uses `--locked`. |
| `build_host_class` | string | The admitted hosted runner that generated this aggregate provenance document, not a claim that every listed archive was built on that host. Each archive's separate GitHub attestation carries its own matrix builder identity. One of `github-hosted-ubuntu-24.04`, `github-hosted-macos-15`, `github-hosted-windows-2025` from `docs/RELEASE-PROCESS.md`. |
| `nonclaims` | array of strings | What this document does not assert (see below); never empty. |

This document is generated **before** publication (like the manifest it
extends) and therefore cannot itself record a real publication timestamp or
event. The actual GitHub Release publication event remains recorded only in
`docs/RELEASE-PROCESS.md`'s dated `## X.Y.Z hosted release evidence`
section, written by hand after a real Release is confirmed published --
never inferred from this document alone.

### `semaprax.release-signature-claim.v1`

`scripts/release-signature-claim.py` deterministically projects this document
from the exact final provenance bytes and a structurally complete `cosign
sign-blob` v0.3 message-signature bundle. It derives the subject digest and pinned per-tag
identity itself, and copies only the bundle's canonical base64 signature and
certificate encodings. It does **not** sign, verify a signature, contact a
transparency log, select/download a trust root, read a CI environment
variable, or publish. The independent Rust consumer still parses the complete
closed bundle framing before a caller-supplied offline verifier receives it.
The current workflow does not invoke this builder or publish a claim/root yet;
the script is deliberately a reviewable offline prerequisite rather than a
claim that a signed release already exists.

| Field | Type | Meaning |
| --- | --- | --- |
| `schema` | string | Always `semaprax.release-signature-claim.v1`. |
| `subject_digest` | `sha256:<64 lowercase hex>` | Digest of the exact `semaprax.release-provenance.v1` document bytes this claim signs. |
| `subject_name` | string | Human-readable label for the subject (e.g. `release-provenance.json`). |
| `identity.issuer` | string | Must equal the trusted OIDC issuer. |
| `identity.subject` | string | Must equal `repo:<trusted repository>:ref:refs/tags/<tag>` for the exact tag the provenance document declares. |
| `identity.workflow_ref` | string | Must equal `<trusted repository>/<trusted workflow path>@refs/tags/<tag>`, and must also agree with the provenance document's own `builder.workflow_identity`. |
| `algorithm` | string | One recognized value (currently only `sigstore-cosign-bundle-v0.3`); recognizing a value here is a structural admission, not a cryptographic endorsement. |
| `signature` | string (opaque) | Never decoded or cryptographically verified by this repository's code -- see "What verification does and does not prove" below. |
| `certificate` | string (opaque) | Same as `signature`. |

### Bundled offline verification material (narrow v0.3 slice)

The tag workflow publishes two intentionally different, exact Sigstore bundle
shapes. They are not interchangeable and a verifier rejects either shape where
the other is expected.

- `release-attestation-<target>.json` is the GitHub
  `actions/attest-build-provenance` output: one
  `application/vnd.dev.sigstore.bundle.v0.3+json` **DSSE** envelope, carrying
  one `application/vnd.in-toto+json` in-toto Statement v1 whose one SLSA
  provenance v1 `subject` names that target archive and its lowercase SHA-256
  digest. Its predicate is the closed GitHub workflow-v1 producer snapshot:
  `buildDefinition` has the exact workflow build type, workflow external
  parameters, GitHub internal parameters, and one through eight git-commit
  dependencies; `runDetails` has exactly builder ID and invocation ID. The
  aggregate verifier compares the subject's name and digest to the manifest
  and to the actual archive bytes; an attestation for one target cannot be
  replayed for another.
- `release-provenance.bundle` is the `cosign sign-blob` v0.3
  **`messageSignature`** bundle over the final `release-provenance.json`.
  A `semaprax.release-signature-claim.v1` consumes it exactly: the bundle's
  SHA2-256 message digest must be the digest of the exact provenance bytes,
  and the claim's opaque `signature` and `certificate` strings must be the
  exact strings in that bundle. A claim is therefore not an independently
  editable second signature representation.

The claim builder can be replayed without a signing capability:

```sh
python3 scripts/release-signature-claim.py \
  --provenance dist/release-provenance.json \
  --bundle dist/release-provenance.bundle \
  --output dist/release-signature-claim.json
python3 scripts/release-signature-claim.py \
  --provenance dist/release-provenance.json \
  --bundle dist/release-provenance.bundle \
  --check dist/release-signature-claim.json
```

The second command requires a byte-exact deterministic rendering. A changed
provenance byte, a replayed bundle message digest, non-canonical copied base64,
or a claim serialization drift fails closed. This replay is only preparation
for a later explicit cryptographic verifier; it is not a cryptographic result.
The builder reads at most 4 MiB of provenance, 2 MiB of bundle material, and
64 KiB for an existing claim under `--check`, so a hostile replay path cannot
request an unbounded allocation. It rejects duplicate JSON keys. Output uses a
same-directory temporary file followed by replacement; the caller still owns
and must trust the selected parent directory. The builder validates only the
identity/digest and closed material projection it consumes; the independent
Rust decoder remains responsible for the complete provenance and Rekor-entry
contract before any cryptographic verifier is invoked.

The parser admits one through eight fully shaped v0.3 Rekor entries for the
content kind being consumed: `hashedrekord` for the message-signature bundle and
`dsse` for an archive attestation. Every such entry has canonical decimal
indexes/times, the v0.0.1 kind/version pair, a signed-entry timestamp,
inclusion proof, and canonicalized body. `logId.keyId`, the signed-entry
timestamp, proof root/path hashes, and canonicalized body are canonical padded
standard base64. `timestampVerificationData` is either the exact empty object
(the protobuf JSON representation of zero RFC3161 timestamps) or one through
eight exact `rfc3161Timestamps` records whose `signedTimestamp` fields are the same
canonical base64. Thus an empty object never stands in for an unparsed
timestamp record, and an empty `{}` tlog entry never admits.

The certificate, `messageSignature.messageDigest.digest`,
`messageSignature.signature`, DSSE payload/`sig`, and all admitted tlog and
RFC3161 byte fields are canonical padded standard base64, not merely non-empty
strings. The narrow parser rejects URL-safe, unpadded, non-canonical, or
malformed alternatives before passing the exact bundle bytes to an external
verifier.

The admitted decimal JSON strings for every transparency-log index, integrated
time, and proof tree size are canonical nonnegative signed-64-bit values
(`0` through `9223372036854775807`); the parser rejects a sign, leading zero,
or overflow. Predicate parsing establishes that one producer snapshot is
well-formed, not that its workflow, commit, IDs, builder, or invocation is
cryptographically trustworthy or semantically bound to this release. Those
claims remain for the supplied offline capability and its explicit identity.

Offline consumers import the exact `trusted_root.jsonl` emitted by
`gh attestation trusted-root` alongside the archive/bundle, before crossing
the air gap. The package is bounded UTF-8 JSON Lines with no empty record and
is supplied by the caller as exact bytes; this repository never downloads,
updates, or silently selects a trust root. GitHub recommends refreshing that
root whenever new signed material is imported, because a stale offline root
does not learn later key revocation or rotation.

The parser deliberately admits only those v0.3, single-signature,
single-archive-subject forms. It is not a general Sigstore, DSSE, in-toto,
SLSA, X.509, certificate-chain, or Rekor client. The complete cryptographic
replay (signature, certificate identity/chain, Rekor inclusion proof, and
imported trusted-root relationship) is an explicit
`OfflineBundleVerificationCapability` supplied by a caller that has a real
offline verifier. The capability receives the exact subject, bundle, and root
bytes only after all structural and digest bindings pass.

## The verification module

`src/release_provenance.rs` (tested by its own `#[cfg(test)] mod tests` and
by `tests/offline_package/release_provenance.rs`) provides:

- `parse_manifest` / `parse_provenance` / `parse_signature_claim`: independent,
  from-bytes structural validation of each schema (exact key sets, closed
  vocabularies, `sha256:`/40-hex wire forms). Every one of these fails closed
  on a malformed, wrong-schema, or incomplete document.
- `verify_provenance_binds_manifest`: the provenance's `manifest_digest`,
  version, tag, commit, prerelease flag, required checks, and artifact
  inventory must all agree exactly with a manifest's actual on-disk bytes.
- `verify_manifest_artifacts_on_disk`: independently re-hashes every artifact
  a manifest names from a caller-supplied directory's real bytes; this is a
  from-scratch replay, not a re-use of `release-manifest.py`'s own build-time
  check.
- `verify_signature_claim_binds_provenance`: the claim's `subject_digest`
  must equal a byte-exact digest of the exact provenance bytes under test,
  and its `identity` fields must equal both the trusted policy above and the
  provenance document's own recorded builder identity.
- `verify_release_binding`: the two binding checks composed, for a single
  entry point over a manifest/provenance/claim triple.
- `SignatureVerificationCapability` / `verify_release_binding_with_capability`:
  an explicit extension point for a *cryptographic* verifier. This module
  still implements no real algorithm and still creates no key or identity
  material -- the trait exists so a caller that does hold a real verifier
  (a `cosign`/Sigstore bundle check, once one is wired up per the checklist
  below) can supply it explicitly, and so it composes with the binding
  checks (which still run first and still fail closed on their own) rather
  than duplicating them. This is the reusable surface #195 (signed package
  registry) and #209 (signed audit capsule) can implement the trait against
  without redefining what "verify a signature claim" means. Its only tests
  today use a throwaway HMAC-SHA256 key generated inside the test module
  (`src/release_provenance/tests.rs`) to prove the interface actually gates
  on cryptographic verification and is not a no-op -- HMAC is a symmetric
  stand-in for wiring only, never a claim about the real algorithm, which
  stays Sigstore/cosign per this document.
- `parse_sigstore_archive_attestation_bundle` /
  `verify_archive_attestation_binds_manifest` /
  `verify_archive_attestation_binds_release`: bounded, closed replay of the
  published archive DSSE bundle's one SLSA subject against the exact manifest
  entry and archive bytes. Aggregate verification additionally binds the
  predicate's GitHub repository URL, workflow path, tag ref, and one resolved
  source dependency commit to the exact provenance statement before handing
  any bytes to a cryptographic capability. It does not verify the predicate's
  signature or other semantics.
- `parse_sigstore_message_signature_bundle` /
  `verify_signature_claim_consumes_sigstore_bundle`: bounded, closed replay
  of the distinct `cosign sign-blob` message-signature bundle and exact claim
  consumption. A changed bundle digest, signature, certificate, or provenance
  byte rejects before any cryptographic capability runs.
- `parse_sigstore_trusted_root_jsonl` plus
  `OfflineBundleVerificationCapability`: accept caller-imported, exact,
  bounded root-package bytes and hand them with the exact subject/bundle bytes
  to a pure explicit verifier. The module has no built-in Sigstore verifier;
  absent that supplied capability, these functions establish binding only.
- `verify_offline_release_with_capability`: the only **aggregate** offline
  release API. It requires the manifest/provenance/claim/message bundle,
  one exact trusted-root package, and exactly one archive plus one DSSE
  attestation per manifest entry. Missing, duplicate, or extra archive names
  reject. It completes every structural, digest, claim, root-framing, and
  inventory check before the first capability call, then invokes that
  capability over provenance followed by archives in canonical manifest order.
  Every call receives the exact input bytes and an
  `ExpectedReleaseIdentity` derived from the bound trusted issuer,
  repository, workflow path, and exact tag.

`verify_archive_attestation_with_offline_capability` and
`verify_signature_claim_with_offline_capability` remain explicitly partial
helpers for an already-selected subject. They are not a complete release
inventory check; callers verifying a downloaded release use the aggregate API.

### The one documented command

`semaprax release verify <release-dir>` is the single command a downloader
runs over an unpacked release directory. It is a thin front over the module
above and adds no verification of its own: it reads
`release-manifest.json`, `release-provenance.json`, and -- if present --
`release-signature-claim.json` from that directory, then hands their exact
bytes to `verify_provenance_binds_manifest`,
the CLI adapter's held no-follow archive reader, and
`verify_signature_claim_binds_provenance`. Everything is re-derived from
what is on disk: the manifest digest is recomputed from the manifest's real
bytes, every archive the manifest names is re-hashed from its real bytes,
and a claim's subject digest is recomputed from the provenance statement's
real bytes. The adapter does not list the directory or reject unrelated files;
it checks only the exact regular files the admitted manifest names. Nothing a
document says about itself is trusted.

The standalone binary deliberately has no Sigstore/cosign verifier authority.
If the directory presents any v0.3 offline material --
`release-provenance.bundle`, `trusted_root.jsonl`, or a
`release-attestation-<admitted-target>.json` for one of this policy's three
closed archive targets -- it refuses with `SPX-Z706` instead of
continuing into the unsigned report. An embedding host that holds a real
offline verifier may explicitly provide its
`OfflineBundleVerificationCapability`; the CLI adapter then reads the complete
bounded inventory and passes its exact bytes to
`verify_offline_release_with_capability`. A partial inventory still fails as a
missing document (`SPX-Z705`), and structural bundle framing alone is never a
cryptographic success claim.

```sh
semaprax release verify dist
```

It fails closed on the first disagreement, exiting non-zero with the owning
module's stable code -- `SPX-Z701` (document shape), `SPX-Z702` (binding:
altered manifest, provenance for another commit or tag, replayed claim),
`SPX-Z703` (identity policy: unapproved issuer, repository, or workflow),
`SPX-Z704` (artifact: missing, resized, or substituted archive) -- plus its
own `SPX-Z705` when the directory presents no readable document at all, and
`SPX-Z706` when signed offline material is present without a caller-supplied
verification capability. It
opens only the exact paths the manifest names, lists no directory, touches
no network, spawns no process, and never executes or unpacks an artifact.

A successful run over a directory with no offline bundle material prints
`status: VERIFIED UNSIGNED RELEASE`. That is a
successful verification of an **unsigned** release, never evidence that a
release was signed: no SEMAPRAX release is signed today and no signing key
or keyless identity exists for this repository. The status is unchanged when
a `semaprax.release-signature-claim.v1` document is present and correctly
bound -- the command verifies that claim's *binding* only, and never decodes
or cryptographically verifies its `signature`/`certificate` bytes, exactly
as the next section describes. Verifying, publishing, signing, and
installing remain separate: this command performs only the first.

### What verification does and does not prove

**Does prove:** that a manifest, a provenance document, and a signature
claim name exactly the same commit, tag, version, and artifact digests; that
none of the three has been altered by even one byte since the triple was
assembled; that a claim was not lifted from a different release (a replay);
and that a claim's declared identity matches the pinned trusted-identity
policy for the exact tag under test.

**Does not prove:** that `signature`/`certificate` bytes are a real
cryptographic signature produced by the claimed identity's private key.
Verifying that honestly requires a signature-verification implementation
(Sigstore/cosign bundle verification, or raw Ed25519/ECDSA point
arithmetic), which needs a cryptography dependency this change is not
permitted to add. **A structurally valid, well-bound claim is not the same
claim as a cryptographically authentic one** -- conflating the two here
would be exactly the mistake this repository's own session precedent (no
toy password hash, no toy MAC -- see the #191 work this issue's assignment
names) warns against, applied to signing. Closing that gap requires pairing
this module's binding check with a real external verifier, such as:

```sh
cosign verify-blob \
  --certificate-identity "https://github.com/wavect/semaprax/.github/workflows/ci.yml@refs/tags/vX.Y.Z" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  --bundle release-signature.bundle \
  release-provenance.json
```

run by a real signing CI step or by a maintainer, never by this repository's
own compiler or scripts.

The added offline material framing does **not** change that boundary. Parsing
a bundle, matching its archive subject/digest, matching a claim's copied
signature/certificate strings, or accepting a `trusted_root.jsonl` package is
not cryptographic verification. No built-in implementation validates an X.509
chain, Fulcio identity, DSSE/message signature, Rekor checkpoint/inclusion
proof, or revocation state, and no test fixture is a real certificate,
signature, Rekor proof, or trusted root. Only a supplied real offline
capability may make those checks; its success remains separate from product
support, reproducibility, notarization, or publication.

Also not proved by anything in this document: reproducible builds (no
cross-host byte-identical rebuild is claimed or attempted), notarization or
OS code-signing (tracked separately, see `docs/DOCTOR-SIGNED-INSTALL-V1.md`
for the one existing, narrowly-scoped Ed25519 verification path this
repository has, which is unrelated -- it authenticates a *doctor-installed
generation directory*, not a release archive), production support, or
semantic/compiler correctness.

## Hosted-release follow-up (`HUMAN_BLOCKED`)

The workflow now applies items 1-4 below on a qualifying tag. They are listed
as an auditable configuration contract, not as a claim that a signed release
exists. A completed hosted run must still be reviewed before the status and
historical evidence are changed.

1. **Keyless workflow authority is scoped by artifact shape.** Each
   `release-artifacts` matrix producer has the `id-token: write` and
   `attestations: write` permissions needed for the pinned
   `actions/attest-build-provenance` action to attest its own smoke-tested
   archive; its returned bundle is copied into the exact target's release
   artifact and must be present at aggregate publication. `publish-release`
   separately has `id-token: write` only for the
   Sigstore/Fulcio certificate whose URL SAN is bound to
   `https://github.com/wavect/semaprax/.github/workflows/ci.yml@refs/tags/<tag>`
   over the final aggregate provenance. The underlying GitHub OIDC `sub`
   remains `repo:wavect/semaprax:ref:refs/tags/<tag>`; it is not the
   certificate identity accepted by `cosign verify-blob`. No repository
   signing secret is configured.
2. **The signing tools are pinned.** The workflow pins both
   `actions/attest-build-provenance` and `sigstore/cosign-installer` by
   immutable action revision, and requests the declared `cosign` release
   version. The workflow contract test rejects a missing or changed pin.
3. **Attestation and signing follow the admitted subjects.** Each producer
   smoke-tests then attests its archive before upload. `publish-release` freezes
   the bounded `trusted_root.jsonl` and cryptographically checks each held
   archive against its matching held bundle, pinned repository/caller workflow,
   exact tag ref, exact source commit, and hosted-runner policy before it writes
   `SHA256SUMS`. It then runs `scripts/release-manifest.py`,
   `scripts/release-provenance.py`, and signs the resulting
   `release-provenance.json`. It never signs a manifest before the last archive
   is built and independently attested, and `gh release create` fails rather
   than replacing an existing release's assets.
4. **The concrete configured shape is:**
   ```sh
   gh attestation trusted-root | head -c 4194305 > dist/trusted_root.jsonl
   gh attestation verify "dist/$ARCHIVE" \
     --bundle "dist/$ATTESTATION" \
     --custom-trusted-root dist/trusted_root.jsonl \
     --repo wavect/semaprax \
     --signer-workflow wavect/semaprax/.github/workflows/ci.yml \
     --source-digest "$COMMIT" --source-ref "refs/tags/$TAG" \
     --deny-self-hosted-runners
   python3 scripts/release-manifest.py --version "$VERSION" --tag "$TAG" \
     --commit "$COMMIT" --archives-dir dist --output dist/release-manifest.json
   python3 scripts/release-provenance.py --manifest dist/release-manifest.json \
     --workflow-identity "wavect/semaprax/.github/workflows/ci.yml@refs/tags/$TAG" \
     --run-id "$GITHUB_RUN_ID" --run-attempt "$GITHUB_RUN_ATTEMPT" \
     --rustc-version "$(rustc --version)" --host-class github-hosted-ubuntu-24.04 \
     --output dist/release-provenance.json
   cosign sign-blob --yes --bundle dist/release-provenance.bundle \
     dist/release-provenance.json
   python3 scripts/release-signature-claim.py \
     --provenance dist/release-provenance.json \
     --bundle dist/release-provenance.bundle \
     --output dist/release-signature-claim.json
   python3 scripts/release-signature-claim.py \
     --provenance dist/release-provenance.json \
     --bundle dist/release-provenance.bundle \
     --check dist/release-signature-claim.json
   ```
   followed by uploading `release-manifest.json`, `release-provenance.json`,
   `release-provenance.bundle`, `release-signature-claim.json`, and
   `trusted_root.jsonl` as release assets alongside the three archives and
   their attestations. The source-locked CI contract requires this order and
   exact asset set. The trusted root is fetched while the publisher is online;
   later offline verification receives those exact bytes explicitly and never
   updates them through an ambient network. The pipeline caps the snapshot at
   the verifier's 4 MiB input limit while streaming it, so a remote response
   cannot grow the release workspace without bound.
5. **Publish verification instructions with the one documented command.**
   The command itself now exists: `semaprax release verify <release-dir>`
   (see "The one documented command" above) performs the binding, artifact,
   and identity checks offline. What remains human-owned is pairing it with
   a real signature check once one exists: `docs/RELEASE-PROCESS.md` should
   gain a worked `cosign verify-blob` invocation alongside it, and its
   nonclaims should keep saying releases are unsigned until item 6 holds.
6. **Only after a real signed release has shipped**, update
   `docs/RELEASE-PROCESS.md`'s nonclaims to stop describing releases as
   unsigned, and add that release's own dated hosted-evidence section
   recording the real signature/provenance assets, exactly as its existing
   sections record archives today.
7. **Decide and record identity rotation ownership**: who (which maintainer
   role) is authorized to edit the trusted identity policy table above, and
   what review is required before that edit merges. This document does not
   itself grant that authority to anyone.

Items 1-4 are configuration now present in the workflow, including the
deterministic claim and offline-root release assets; items 5-7 remain
human-owned. The schemas, identity policy, binding verifier, and source-locked
workflow contract make a real hosted signature mechanically checkable rather
than a fact trusted only from prose. They do not substitute for that hosted
signature or its review.

## Nonclaims

Integrity, authenticity, provenance, reproducibility, and production support
remain five separate claims, exactly as issue #168 requires:

- **Integrity** (do these bytes match what was recorded?) is what SHA-256
  digests already gave this repository, and what this document's binding
  checks extend across three documents instead of one.
- **Authenticity** (were these bytes produced by the claimed identity?) is
  explicitly **not** established by anything in this document or
  `src/release_provenance.rs` -- see "What verification does and does not
  prove" above. No release is signed today.
- **Provenance** (what exactly was bound: commit, workflow, toolchain, host
  class, artifact digests) is what `semaprax.release-provenance.v1` records.
- **Reproducibility** (can a third party rebuild byte-identical artifacts)
  is not claimed, attempted, or implied by any field here.
- **Production support** is a separate, unrelated claim this document does
  not make or imply for any release, signed or not.
