# Package registry federation v1

Status: implemented, **local-only** bounded module. Unit-tested in this
worktree (`cargo test --locked -p semaprax --lib package_registry::`); not run
through `scripts/quality.sh full`, not released, not hosted, and not exposed
through a federation CLI route. The single-registry `semaprax registry` CLI
does not widen this format's scope. There is no hosted or production Semaprax
registry, and this format does not create one.

Audience: package-tool authors and compiler contributors working on issue #195.

`crate::package_registry::federation` extends [Registry Snapshot v1](PACKAGE-REGISTRY-SNAPSHOT-V1.md)
across registries. A single snapshot protects a name only within itself; two
registries can otherwise serve the same coordinate with different publishers or
content. This closes that dependency-confusion gap required by issue #195.
case. This layer refuses it.

## What this is not

It adds **no** cryptography and **no** authority. Every nonclaim in the
snapshot specification holds here verbatim: `signature` stays opaque and is
never verified anywhere in this crate (issue #168, still open, owns the signing
key), `provenance_digest` stays an unverified reference, and nothing in this
module touches the network, the clock, the environment, or the filesystem. A
federation is proof data about a caller-supplied set of snapshots, never
permission to fetch one. This layer does not even read the `signature` field;
`tests::signatures_are_never_examined_by_the_federation_layer` pins that as an
executable assertion rather than a prose claim.

## The model

A `Federation` binds two things in one canonical, content-addressed
`semaprax.package-registry-federation.v1` envelope:

1. a closed, caller-owned set of `FederatedRegistry` values, each a
   `registry_id` bound to an already-built `RegistrySnapshot` by that
   snapshot's own digest; and
2. a closed `NamespaceClaim` table assigning each package namespace — a
   dotted prefix, from one segment (`examples`) to a whole package name
   (`examples.meaning`) — to exactly one `registry_id`.

There is no ambient registry list, no default registry, no ordered search path,
and no fallback. A package the table does not explicitly authorize is refused,
never served by whichever registry happens to answer first. Search-path
precedence *is* the dependency-confusion bug, so this format has no search
path.

Claims match segment-wise, so `example` never covers `examples.meaning`. There
is also **no longest-match precedence**: if two claims both cover a package,
the federation is refused rather than resolved in favour of the more specific
one. A silent tie-break between two registries' claims over one package name is
exactly the ambiguity dependency confusion exploits, so overlapping claims are
reported as the authoring mistake they are.

`build_federation(registries, claims)` renders the envelope;
`verify_federation(evidence, registries, claims)` independently rebuilds it and
requires a byte-exact replay; `project_federated_subjects(federation, policy)`
projects the whole federation into the single `subjects: Vec<String>` catalog
[Offline deterministic package resolver v2](OFFLINE-PACKAGE-RESOLVER-V2.md)
already consumes.

## Canonical envelope

```json
{"schema":"semaprax.package-registry-federation.v1","digest":"sha256:…","bytes":N,
 "payload":{"schema":"semaprax.package-registry-federation.v1",
  "registry_count":N,"namespace_count":N,"package_count":N,
  "registries":[{"registry_id":"…","snapshot_digest":"sha256:…"}],
  "namespaces":[{"namespace":"…","registry_id":"…"}],
  "packages":[{"package":"…","version":"…","registry_id":"…",
               "content_digest":"sha256:…","status":{"state":"active"}}]}}
```

`registries` are ordered by `registry_id`, `namespaces` by `namespace`, and
`packages` globally by `(package, version)` — deliberately *not* registry by
registry, so the catalog handed to the resolver does not depend on which
registry was listed first. The envelope digest is domain-separated with
`semaprax.package-registry-federation.v1\0` and the payload length, so a
federation payload can never collide with a snapshot payload.

## Diagnostics

| Code | Meaning |
| --- | --- |
| `SPX-PKR601` | `registry_id` or `namespace` grammar violation (empty, over-long, non-lowercase, control byte, or an empty dot-separated segment). |
| `SPX-PKR604` | One `registry_id` bound to two *different* snapshot digests in one federation. Reuses the snapshot layer's immutable-conflict code rather than minting a new one: both are "an established binding cannot be silently replaced". |
| `SPX-PKR605` | One `registry_id` listed twice with the *same* snapshot digest. |
| `SPX-PKR606` | Registry count, namespace-claim count, or merged-package count bound exceeded. |
| `SPX-PKR607` | Cumulative render-budget overflow. |
| `SPX-PKR608` | `verify_federation` evidence does not byte-replay the supplied registries and claims. |
| `SPX-PKR609` / `SPX-PKR610` | Yank warning / refusal, from the shared single-registry policy step. |
| `SPX-PKR611` | **Cross-registry dependency confusion**: the same `package` name is served by more than one registry. |
| `SPX-PKR612` | **Namespace authority**: a served package is covered by no claim, by a claim naming a different registry than the one serving it, or by more than one claim; or the table repeats a namespace or names a `registry_id` absent from this federation. |

There is no separate cross-registry publisher-identity code. `SPX-PKR611`
subsumes it: one package name resolves to exactly one registry, so a second
registry cannot introduce a competing publisher claim for that name at all, and
the snapshot layer's `SPX-PKR604` ownership continuity already refuses a
divergent identity within the one registry that does serve it.

## Determinism

Registries, claims and merged packages are keyed through `BTreeMap` — never a
`HashMap`/`HashSet`. Two separate claims follow, deliberately not conflated:

- **Accepted bytes are order-independent, always.** Rendering reads only the
  canonical maps, so the same registries and claims in any argument order
  produce byte-identical evidence
  (`tests::registry_and_claim_order_do_not_affect_canonical_bytes`).
- **Refusal *selection* is content-determined for the two cross-registry rules
  only.** The `SPX-PKR611` and `SPX-PKR612` passes walk the canonical maps, so
  which conflict is reported is a pure function of content
  (`tests::dependency_confusion_is_refused_regardless_of_registry_order`
  asserts the identical refusal message from both argument orders). The
  input-table well-formedness checks — `SPX-PKR601`, `SPX-PKR604`,
  `SPX-PKR605` — must iterate the caller's list to build those maps in the
  first place, so they report the first offending element *of that list*. A
  caller needing a stable choice among several malformed entries must sort its
  own input. This limit is stated rather than papered over.

`tests::federation_source_contains_no_ambient_authority_or_unordered_iteration`
greps this module's own source for exactly the constructs this section claims
are absent.

## Revocation

Yanking is unchanged from the snapshot layer and is not reimplemented here:
`project_federated_subjects` calls the same per-entry policy step
`project_subjects` does, so a federated catalog cannot drift into a second,
subtly different revocation policy. A yanked entry stays in the digest-bound
federation bytes rather than being removed, so a later yank cannot silently
rewrite an already-resolved federation.

## Evidence and nonclaims

`src/package_registry/federation/tests.rs` pins the canonical envelope field
for field, determinism (repeat-call, both-orders, changed-snapshot,
changed-claim, tamper refusal, substituted-snapshot refusal), three
dependency-confusion refusals with per-registry controls proving each registry
alone federates cleanly, the whole-namespace and shared-text-prefix cases of
the claim rule, six namespace-authority refusals including the overlapping-claim
one, five registry-set well-formedness refusals, all three yank policies,
resolver-v2 composition, and the two nonclaims above. Every refusal test asserts
the exact diagnostic code.

This is **local evidence** from unit tests in one worktree. No hosted run,
published registry, federation CLI route, network path, or signature
verification is claimed or implied.
