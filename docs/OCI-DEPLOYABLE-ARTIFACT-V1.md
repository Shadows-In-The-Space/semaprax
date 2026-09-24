# OCI Deployable Artifact v1

Audience: people and coding agents packaging a SEMAPRAX project for a
container registry or an OCI-artifact-aware deployment pipeline, and compiler
contributors.

Status: implemented for exactly the Project v1 scalar and Project v3 Useful
Data v1 / Project v16 Useful Data v2 profiles; not wired to any other Project
profile, not signed, and not published anywhere. Local evidence only -- see [Evidence and
nonclaims](#evidence-and-nonclaims).

GitHub issue [#194](https://github.com/wavect/semaprax/issues/194) asks for a
deployable-artifact route out of a checked SEMAPRAX project. Before this
capsule, no OCI, container, or image-manifest generation existed anywhere in
this repository.

## What this is, and is not

`semaprax build --target oci` emits a directory that is a structurally valid
[OCI Image Layout](https://github.com/opencontainers/image-spec/blob/main/image-layout.md):
an `oci-layout` marker, an `index.json`, and content-addressed blobs under
`blobs/sha256/`. Real OCI tooling (`oras`, `skopeo`, `crane`, `podman`) can
inspect it as a layout.

It is an **OCI artifact** (per the [OCI 1.1 `artifactType` extension
guidance](https://github.com/opencontainers/image-spec/blob/main/manifest.md#guidelines-for-artifact-usage)),
not a runnable **OCI image**:

- there is **no base layer**. OCI artifacts do not require one, and the
  compiler must never fetch, resolve, or select a base image: that would be
  build-time network access and ambient registry authority, both forbidden by
  this repository's invariants. The artifact's single content layer is the
  project's own already-verified, deterministic Wasm module and nothing else.
- there is **no operating-system root filesystem**, and no entrypoint/cmd
  process metadata. The config blob is a SEMAPRAX-owned JSON document (see
  [Config blob](#config-blob)), not an
  [OCI Image Configuration](https://github.com/opencontainers/image-spec/blob/main/config.md).
  A tool that expects one and tries to `docker run` this layout will not find
  a runnable filesystem.
- it is **unsigned**. Issue [#168](https://github.com/wavect/semaprax/issues/168)
  reserves signing to a maintainer-held key; this emitter has no keys, does
  not stub or fake a signature, and never claims provenance it did not
  produce. See [Signing seam](#signing-seam) for exactly what a human needs to
  add one later.
- it is **never published**. This capsule writes one local directory and
  nothing else -- see [No publish path](#no-publish-path).

Turning this artifact into something a container runtime can execute is a
separate, later, human-owned step: combine it (via `oras`, a registry push, or
a Dockerfile `COPY --from=`) with a Wasm-capable runtime image the deployment
pipeline already trusts. This compiler does not choose that runtime image for
you.

## Command

```text
semaprax build --target oci <project-manifest-or-directory> [--output <dir>]
```

`--output` must not already exist; this route never overwrites or merges into
an existing directory. Today it admits exactly two source-carrier routes:

- the default frozen `semaprax.project.v1` schema under `ScalarV1`, replayed
  from its pathless scalar-Web carrier; and
- `semaprax.project.v3` under `UsefulDataV1` or `semaprax.project.v16` under
  `UsefulDataV2`, each replayed from the exact schema-selected Useful Data npm
  carrier.

The latter is an exact profile seam, not a generic npm-to-OCI conversion. Its
carrier replay rechecks the closed artifact inventory, every artifact byte and
digest, the canonical package metadata, and the retained Project v3 or v16
subject before its first `app.wasm` artifact can become the OCI layer. The
selected entry module comes from the authenticated snapshot; the recovered
project revision commits to the manifest that selected it. Project v16 may
retain private owned records, but only its schema-selected public byte-export
`app.wasm` crosses this bridge. Every other Project profile (including the
other npm/owned-data/command profiles) is
refused with `SPX-J142` rather than silently downgraded to a partial artifact;
extending this route to them is open follow-up scope, not implemented here.

## Layout

```text
<output>/
  oci-layout                    # {"imageLayoutVersion":"1.0.0"}\n
  index.json                    # references the one manifest below
  blobs/sha256/<config-digest>  # the config blob
  blobs/sha256/<layer-digest>   # the project's app.wasm bytes, verbatim
  blobs/sha256/<manifest-digest>
```

Every blob file is named after its own SHA-256 digest in lowercase hex, and
every digest referenced from `index.json` or the manifest is that same hash
recomputed from the bytes actually on disk -- see
`src/oci_package/tests/structural_validity.rs` for the
executable check.

### `oci-layout`

Exactly `{"imageLayoutVersion":"1.0.0"}\n`: the real OCI Image Layout version
string, not a SEMAPRAX-only one, so generic OCI tooling recognizes the
directory shape.

### `index.json`

```json
{
  "schemaVersion": 2,
  "mediaType": "application/vnd.oci.image.index.v1+json",
  "manifests": [
    {
      "mediaType": "application/vnd.oci.image.manifest.v1+json",
      "artifactType": "application/vnd.semaprax.oci-deployable.v1+json",
      "digest": "sha256:<manifest-digest>",
      "size": <n>,
      "annotations": { "org.opencontainers.image.ref.name": "<project>" }
    }
  ]
}
```

Exactly one manifest entry. No tag beyond the bare project name is ever
invented (no `:latest`, no version): this compiler does not track a semver
for the frozen v1 manifest layout, so it does not fabricate one here either.

### Manifest blob

```json
{
  "schemaVersion": 2,
  "mediaType": "application/vnd.oci.image.manifest.v1+json",
  "artifactType": "application/vnd.semaprax.oci-deployable.v1+json",
  "config": {
    "mediaType": "application/vnd.semaprax.oci-deployable.config.v1+json",
    "digest": "sha256:<config-digest>",
    "size": <n>
  },
  "layers": [
    {
      "mediaType": "application/vnd.semaprax.oci-deployable.wasm-module.v1+wasm",
      "digest": "sha256:<layer-digest>",
      "size": <n>
    }
  ],
  "annotations": {
    "io.semaprax.project": "<project>",
    "io.semaprax.project.revision": "sha256:<hex>",
    "io.semaprax.workspace.revision": "sha256:<hex>",
    "io.semaprax.project.graph-digest": "sha256:<hex>",
    "io.semaprax.entry-module": "<entry>",
    "org.opencontainers.image.title": "<project>.wasm"
  }
}
```

`artifactType` marks the whole object as a SEMAPRAX OCI deployable artifact.
`layers` always has exactly one entry: there is no base layer to list. No
`org.opencontainers.image.created` annotation is ever emitted -- a timestamp
there would break byte-for-byte determinism, so this capsule never writes one
under any name.

### Config blob

```json
{
  "schema": "semaprax.oci-deployable.config.v1",
  "project": "<project>",
  "project_revision": "sha256:<hex>",
  "workspace_revision": "sha256:<hex>",
  "project_graph_digest": "sha256:<hex>",
  "entry_module": "<entry>",
  "content": {
    "kind": "wasm-module",
    "media_type": "application/vnd.semaprax.oci-deployable.wasm-module.v1+wasm",
    "bytes": <n>,
    "sha256": "sha256:<hex>"
  },
  "nonclaims": [
    "not_a_runnable_container_image",
    "no_base_layer",
    "no_operating_system_rootfs",
    "unsigned",
    "not_published"
  ]
}
```

The five identity fields (`project`, `project_revision`, `workspace_revision`,
`project_graph_digest`, `entry_module`) come from one completely replayed
profile-selected carrier: the Project v1 scalar Web-build carrier or an exact
Project v3/v16 Useful Data npm carrier. In the latter cases the snapshot
provides the entry module, while the carrier's recovered project revision
commits to the manifest that selected that entry. This keeps the OCI artifact
identity bound to the exact checked Project subject rather than recomputing
identity from loosely parsed source.

## Determinism

Two emissions from an identical checked project produce byte-identical
`oci-layout`, `index.json`, and every blob, including every digest. No field
anywhere in the layout ever carries a wall-clock timestamp, a random nonce,
a host path, a process ID, or anything else that depends on when, where, or
how many times the emitter has run. The output directory's own path is never
embedded in any emitted byte.
`src/oci_package/tests/determinism.rs` pins this with a real
wall-clock gap between two runs.

## No ambient authority, no network

The emitter reads only the bytes handed to it (the project's own verified
Wasm module and identity) and the local filesystem path it is told to create.
It performs no DNS lookup, no TCP/TLS connection, and no registry handshake;
the private `src/oci_package` module imports no network client. It also
refuses to run at all if a container-registry-credential-shaped environment
variable (`DOCKER_PASSWORD`, `REGISTRY_TOKEN`, `GITHUB_TOKEN`, `AWS_SECRET_ACCESS_KEY`,
and similar -- see `src/oci_package/validation.rs` for the
exact list) is present in the process environment, before touching any file.
This mirrors `scripts/generated-package-release.py`'s
`assert_no_credential_env`: the emitter has no legitimate use for such a
credential, so its mere presence is refused rather than silently ignored.

## No publish path

`src/oci_package` implements no registry client, no `push`
subcommand, and no `--publish` flag of any kind: `build_and_publish` writes
one local directory and returns. This is a stronger guarantee than "declines
to publish by default" -- there is no live-publish code path to enable, the
same discipline `scripts/generated-package-release.py` established for the
npm/Rust owned-data preview route. Getting this artifact into a registry is a
separate, human-run step (`oras push`, `skopeo copy`, or equivalent) outside
this compiler entirely.

## Signing seam

This artifact is unsigned and the config blob says so explicitly
(`"unsigned"` in `nonclaims`). Issue #168 holds registry/artifact signing
authority with the maintainer; this emitter must not sign, stub-sign, or
otherwise imply a signature it cannot back. To add real signing later, a
human (not this compiler) needs to:

1. Choose a signing scheme (e.g. `cosign` OCI-referrer signatures, or an
   in-toto/SLSA provenance attestation attached as a separate OCI artifact
   referring to this manifest's digest).
2. Hold the private key outside this repository and outside any CI runner
   this repository's own workflows control.
3. Sign the manifest digest this capsule already computes and publishes
   deterministically (`OciBundle::manifest_digest()`); the digest itself never
   needs to change for a detached signature to attach to it.

Nothing in this capsule needs to change to support that: content-addressed
signing attaches to the digest, and the digest is already stable across
identical builds.

## Hostile input

A project identity component containing a path separator (`/`, `\`), a
traversal sequence (`..`), an embedded NUL byte, or an over-long value (over
64 bytes for the project name, over 128 for the entry module) is refused with
`OciErrorKind::Identity`, not sanitized. A claimed Wasm digest that disagrees
with the actual bytes is refused the same way. An output path carrying an
embedded NUL byte is refused before any directory is created.
`src/oci_package/tests/hostile_input.rs` exercises each case
and additionally asserts the output directory was never created, proving the
refusal happens before any filesystem effect.

## Evidence and nonclaims

`cargo test --locked -p semaprax --lib oci_package::tests::` selects the
relocated tests for determinism, structural OCI validity, hostile-input refusal, and
environment-credential refusal. `src/project/oci.rs`'s glue from a
`ProjectWebBuild` envelope is exercised by the `semaprax` crate's own project
build tests.

The private helper's implementation and tests are part of the compiler
archive, not a separate registry package. This packaging-boundary repair
does not authorize publication or add a support claim; the historical local
evidence does not become a fresh hosted result by relocation.

This capsule makes no claim about:

- any Project profile other than `ScalarV1` (Project v1) and `UsefulDataV1`
  (Project v3);
- native-executable packaging (only the Wasm module is ever packaged: native
  code generation is not documented as deterministic the way Wasm bytes are,
  see `AGENTS.md`'s invariant list, so this route never packages it);
- runnability under any specific container runtime, orchestrator, or registry;
- signing, provenance, or attestation of any kind;
- publication to any registry, public or private.
