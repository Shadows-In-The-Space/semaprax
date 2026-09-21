# Generated package publication decision (DRAFT -- not approved)

Status: **unapproved design draft** for maintainer review under GitHub issue
[#145](https://github.com/wavect/semaprax/issues/145). Nothing in this
document authorizes a registry write, a signature, or a public-support
promotion. Until a maintainer explicitly accepts a version of this draft, the
generated packages it describes remain exactly what
[docs/PUBLIC-OWNED-DATA-API-V1.md](PUBLIC-OWNED-DATA-API-V1.md) already says
they are: implemented, unpublished, and open for formal promotion.

Audience: maintainers deciding whether, and how, to publish a generated
package; implementers of the next slice of issue #145.

## What this proposes

Adopt exactly one existing generated-package profile as the first candidate
for a maintained, reproducible external-consumer route:

| Field | Value |
| --- | --- |
| Project schema / profile | `semaprax.project.v8` / `owned-data-api.v1` |
| Generated npm package identifiers | `semaprax.project-npm-build.v7` carrier, `semaprax.owned-data-api.v1` metadata |
| Generated Rust package identifier | `semaprax.native-rust-owned-data-sdk.v1` |
| Owning specification | [docs/PUBLIC-OWNED-DATA-API-V1.md](PUBLIC-OWNED-DATA-API-V1.md) |

This profile is chosen, not invented, because it is the one existing
generated-package route the repository already treats as feature-complete and
release-regressed (HOSTED GREEN under the v0.4.0 baseline) while explicitly
flagging publication as the remaining open decision. The separate public
generic ABI (issue #144/SPX-AI-045 territory) is out of scope: nothing here
changes which profile is admitted, and no generic package gains any authority
from this document.

## What is genuinely new in this slice

`scripts/generated-package-release.py` adds a release-preparation and
dry-run-check layer *around* the compiler's own generated output -- it never
edits the compiler's render pipeline or its pinned byte-exact output tests:

- `prepare` validates a built package directory's inventory is exactly the
  closed set this profile produces, scans every byte for secret-shaped and
  local-host-path-shaped substrings, and confirms the Rust crate is
  structurally unpublishable by Cargo (`publish = false`, no
  path/registry dependency) and the npm package still carries none of the
  supply-chain-risk keys the compiler already forbids
  (`dependencies`/`devDependencies`/`scripts`/`private`). It then copies the
  exact input bytes into a `payload/` directory unchanged and adds
  deterministic wrapping documents: a README naming the exact public API
  descriptor digest and declared supported toolchain, the repository's
  Apache-2.0 `LICENSE`, and a checksum manifest
  (`package-preview-manifest.json`, schema
  `semaprax.generated-package-preview.v1`) covering every file.
- `check` recomputes and diffs that checksum manifest against what is
  actually on disk (tamper detection), and only in its default (and only
  implemented) dry-run mode, optionally exercises a real `npm pack --dry-run`
  or `cargo publish --dry-run` against an explicit, caller-supplied absolute
  tool path -- never a PATH-discovered one. `--publish` is always refused:
  there is no live-publish code path in this tool.
- Both subcommands refuse outright, before touching a file, if any of a fixed
  list of publish-credential-shaped environment variables
  (`NPM_TOKEN`, `CARGO_REGISTRY_TOKEN`, and siblings) is set. This tool has no
  legitimate use for one.

See `scripts/test-generated-package-release.py` for the determinism,
tamper-detection, and refusal evidence.

## What remains open (human decisions, not implementation gaps)

1. **Whether to publish at all**, and if so to which registries (npmjs.org
   scope/org name; crates.io publisher identity) under which package name.
   Because each generated package is tied to one exact Project's exact
   public API descriptor digest, a maintainer must decide whether "publish"
   means one canonical reference package (e.g. a fixed demonstration
   Project) or a per-consumer-project workflow this repository only tools,
   never executes on a consumer's behalf.
2. **Registry credentials.** Real publication needs an `NPM_TOKEN` and a
   `CARGO_REGISTRY_TOKEN` (or equivalent OIDC trusted-publishing setup) that
   only a maintainer can provision; this tool is deliberately incapable of
   accepting or using either.
3. **Signing.** Issue [#168](https://github.com/wavect/semaprax/issues/168)
   and [docs/RELEASE-SIGNING-POLICY-V1.md](RELEASE-SIGNING-POLICY-V1.md) own
   the toolchain-archive signing decision; the same open questions
   (signing-tool selection, trusted-identity policy, `id-token: write`
   wiring) apply to a generated package and are not resolved by this draft.
4. **CI wiring for a real publish job.** This slice adds no new CI job and
   changes no job count; a future `publish-generated-package` job (mirroring
   `publish-release`'s pattern of running only after every release blocker
   succeeds, with `contents: write`/registry-publish scope granted to no
   earlier job) is a separate, explicitly maintainer-reviewed change.
5. **Consumer install-from-tarball evidence.** The release wrapper now has a
   local real-tool npm gate that packs a synthetic compiler-shaped fixture,
   verifies the tar stream, structurally binds the generated lockfile,
   installs offline with lifecycle scripts disabled, verifies the installed
   inventory byte-for-byte, and imports it. This proves the wrapper's archive
   consumer mechanics, not execution of genuinely compiler-generated Wasm.
   The existing
   `tests/release_archive_product_v1/owned_frame.rs` lane proves an external
   Node/Rust consumer builds and runs against the generated package's exact
   bytes, but does so through a path dependency into a freshly built
   directory, not through an installed npm/crates.io tarball. Closing that
   genuinely compiler-built npm gap still needs its ignored product gate to
   run with provisioned Node/npm/TypeScript; a local file tarball is not
   equivalent to a registry install. The Rust `.crate` extraction consumer is
   likewise local rather than registry evidence. Real registry evidence still
   needs credentials in a hosted, maintainer-approved job. Recording these
   distinctions avoids promoting synthetic or path-dependency evidence.

## Rollback / deprecation policy (proposed)

Nothing under this profile has ever been published, so there is no existing
artifact to roll back. Once (if) a maintainer approves real publication:

- A published version is never mutated or deleted; a broken release is
  superseded by a new version, following the existing toolchain-archive
  precedent in [docs/RELEASE-PROCESS.md](RELEASE-PROCESS.md#nonclaims).
- Deprecating the whole route means the CI publish job stops running for new
  tags; it does not retract already-published artifacts.
- A breaking change to the profile's descriptor/rename compatibility rules
  (see docs/PUBLIC-OWNED-DATA-API-V1.md) must not be disguised as a patch
  version, per this issue's required test list.

## Review checkpoint

Per issue #145's guardrails, this document is the bounded design submitted
for independent maintainer review, not a self-approved decision. A
maintainer accepting this draft should edit this file's Status line to
record the acceptance (reviewer, date, and which open items above remain
deferred vs. resolved) rather than have an implementing agent do so.
