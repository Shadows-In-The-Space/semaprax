# Package Registry Snapshot v1

Audience: package-tool authors and compiler contributors working on issue #195.

The additive [Registry Snapshot v2](PACKAGE-REGISTRY-SNAPSHOT-V2.md) binds a
closed [Package Artifact Manifest v1](PACKAGE-ARTIFACT-MANIFEST-V1.md) to every
publication while preserving this v1 schema, wire, decoder, digest domain, and
behavior unchanged.

Status: implemented, **local-only** bounded registry model and read-only CLI
front. Its v1 snapshot, wire, catalog, federation, and binding layers retain
their focused tests; additive v2 evidence has separate focused tests. The CLI
front has its own focused tests. None is hosted or a publication/support
decision.

`crate::package_registry` is an authority-free, content-addressed model of a
published-package registry: one deterministic immutable coordinate snapshot
that composes with the existing
[Offline Deterministic Package Resolver v2](OFFLINE-PACKAGE-RESOLVER-V2.md)
rather than reimplementing dependency solving.

## The two halves of issue #195

Issue #195 asks for both a *signed* registry and a *reproducible resolver*.

**Publication -- the signed half -- is `HUMAN_BLOCKED`.** No signing key,
keyless-signing identity, or signature-verification dependency exists in
this repository (issue #168, still open), and generated code and compiler
tooling gain no ambient signing authority (`AGENTS.md`). `RegistrySignature`
therefore carries `algorithm`/`identity`/`signature` as opaque,
structurally-checked strings only -- exactly as
[`crate::audit_capsule::SignatureEntry`](../src/audit_capsule.rs) already
does for the same reason. A forged signature naming an approved identity is
**not** rejected by this module; see
`tests::signature_is_opaque_and_never_cryptographically_checked`.
`provenance_digest` is the same kind of opaque, unverified reference.

**The reproducible-resolver half is what this module implements.**

## What a snapshot is

`build_snapshot` takes a complete, caller-owned list of `PublishedEntry`
values -- there is no ambient mutable registry server state anywhere in this
module -- and renders one canonical `semaprax.package-registry-snapshot.v1`
envelope. Each entry binds:

- a dotted lowercase `package` identity and canonical `version`;
- a `content_digest`: the plain SHA-256 of the entry's embedded Subject-v3
  `subject_bytes`, using the same digest convention as
  [`crate::audit_capsule::sha256_digest`](../src/audit_capsule.rs) and its
  `ObjectRef` binding, deliberately reused rather than reinvented;
- an opaque, caller-supplied `api_digest` and optional `provenance_digest`;
- a bounded `license` string;
- an opaque `signature`;
- a `status`: `Active`, or `Yanked { reason }`.

`subject_bytes` is authenticated with the same
[`crate::package_lock_v3::authenticate_subject_for_resolution`](../src/package_lock_v3.rs)
routine `package_resolver_v2`'s own catalog admission uses, and its embedded
coordinate is cross-checked against the entry's declared `package`/`version`.

"Publishing" a new version is a pure function from the complete prior entry
list plus one new entry -- calling `build_snapshot` again -- not a mutation
of retained state, matching how `package_lock_v3` and `package_resolver_v2`
already take a complete caller-owned catalog rather than an appended one.

## Determinism, structurally

Entries are keyed and iterated through one `BTreeMap<(String, Version),
PublishedEntry>` -- never a `HashMap`/`HashSet` -- so canonical bytes are a
pure function of entry content, never of call order or hidden iteration
order. Nothing in the module reads the clock, an environment variable, or a
file. `tests::determinism_argument_is_structural_not_just_repeated_runs`
greps the module's own source for exactly the constructs this claims are
absent (`HashMap<`, `HashSet<`, `SystemTime::now`, `Instant::now`,
`std::env::`, `std::fs::`, `read_dir(`), rather than only re-running the
build twice. `tests::entry_order_does_not_affect_canonical_bytes` builds the
same two entries in both orders and asserts byte-identical output;
`tests::one_changed_byte_changes_the_digest` asserts a changed input yields
a different digest; `verify_snapshot` recomputes the snapshot from scratch on
every call (no cache), so stale evidence that no longer matches its claimed
entries is refused (`tests::verify_snapshot_refuses_stale_evidence_after_entries_change`),
never silently accepted because a prior call happened to look similar.

## Reserved namespace

`crate::project::standard_dependencies` is the compiler's existing closed
bundled-dependency registry (`std.*`), widened from `pub(super)` to
`pub(crate)` for this issue so `package_registry` can reuse its `is_bundled`
check instead of duplicating a name list. `build_snapshot` refuses any
`std`/`std.*` package name outright (`SPX-PKR602`): the whole prefix is
reserved for the compiler-bundled closed registry, which is exactly the
dependency-confusion/squatting failure mode issue #195 names.

## Ownership continuity (anti-squatting)

`build_snapshot` refuses a snapshot in which the same `package` name appears
under two *different* `signature.identity` claims, reusing the existing
immutable-conflict `SPX-PKR604` code rather than minting a new one. This is
**not** authentication -- no identity claim is cryptographically verified
anywhere in this module -- it is a structural continuity check: having
accepted one version's claimed publisher identity for a package name, a
later version in the same snapshot cannot silently substitute a different
one. It directly targets the "package-name squatting" / dependency-confusion
failure mode issue #195 names for a single open-namespace package name.
The check is scoped per package name (two different packages may carry two
different identities in the same snapshot,
`tests::ownership_continuity_is_scoped_per_package_not_global`) and its
outcome does not depend on caller argument order
(`tests::ownership_conflict_is_detected_regardless_of_entry_order`), since it
runs over the already canonically-keyed `BTreeMap`, not the input slice.

## Revocation

`PublicationStatus::Yanked` never removes or mutates an entry; it is carried
in the same canonical, digest-bound bytes as everything else. `YankPolicy`
gives three closed choices when projecting a snapshot into a resolver
catalog: exclude yanked versions silently (`ExcludeYanked`, the default),
refuse outright if any are present (`RefuseIfYanked`, `SPX-PKR610`), or
include them with an explicit `SPX-PKR609` warning diagnostic
(`AllowYankedWithWarning`) -- never silent inclusion.

## Diagnostics

| Code | Meaning |
| --- | --- |
| `SPX-PKR601` | Shape/grammar: identity, non-canonical version text, digest shape, or bounded-text (license/signature/reason) violation. |
| `SPX-PKR602` | Package name is in the reserved `std.*` namespace. |
| `SPX-PKR603` | `content_digest` does not match the plain SHA-256 of `subject_bytes`, `subject_bytes` failed Subject-v3/Report-v2 replay, or its embedded coordinate differs from the declared `package`/`version`. |
| `SPX-PKR604` | Same `(package, version)` already published with a *different* `content_digest` (immutable conflict), **or** the same `package` name is claimed by two different `signature.identity` values within one snapshot (ownership-continuity / anti-squatting; deliberately reuses this code rather than minting a new one). |
| `SPX-PKR605` | Same `(package, version)` already published with the *same* `content_digest` (publication is one-time, not idempotent). |
| `SPX-PKR606` | Entry count or byte bound exceeded. |
| `SPX-PKR607` | Cumulative render-budget overflow. |
| `SPX-PKR608` | `verify_snapshot` evidence does not byte-replay the supplied entries. |
| `SPX-PKR609` | Warning: a yanked entry was included under `AllowYankedWithWarning`. |
| `SPX-PKR610` | A yanked entry is present and the active policy is `RefuseIfYanked`. |
| `SPX-PKR613` | `package_registry::wire`: these bytes are not a well-formed registry, entry, or resolution-template document at all -- decided before any registry rule runs, which is why it is not `SPX-PKR601`. |

## Composition with the resolver

`project_subjects` projects a snapshot's `Active` (and, per policy, `Yanked`)
entries' `subject_bytes` into the exact `subjects: Vec<String>` shape
[`crate::package_resolver_v2::ResolutionInput`](OFFLINE-PACKAGE-RESOLVER-V2.md)
already consumes, in the snapshot's canonical order.
`tests::projected_subjects_resolve_deterministically_through_package_resolver_v2`
feeds a projected catalog through `package_resolver_v2::generate`/`verify`
twice and asserts byte-identical resolver evidence, demonstrating the two
layers compose rather than duplicate one another's determinism.

## Evidence and nonclaims

`src/package_registry/tests.rs` pins 33 cases: determinism (repeat-call,
reorder, changed-input, stale-evidence-refusal), immutable no-overwrite
(duplicate and conflicting-digest refusal, each with a single-entry control
proving the coordinate alone is not the cause), reserved-namespace refusal
(both a synthetic name and the exact bundled `std.auth`), ownership
continuity / anti-squatting (conflicting-identity refusal order-independence,
the same-identity control, and the per-package scoping control), digest
binding, coordinate-mismatch, and version-only-mismatch refusal,
shape/grammar refusal (including dedicated empty-license and
control-byte-in-identity hostile cases), capacity refusal (entry-count
ceiling and an oversized single entry, each hostile before the expensive
per-entry checks run), all three yank policies, the opaque
signature/provenance nonclaim, and the resolver-v2 composition round trip.
Every refusal test asserts the
exact diagnostic code.

This module performs no cryptographic publisher authentication (only the
structural ownership-continuity check above), no cryptographic signature or
transparency-log verification, no network access, no filesystem access, and
no build execution. The CLI front described below reads caller-supplied
files and performs no publication, no network access, and no write. It does not compute `api_digest` or
`provenance_digest` itself; both are caller-owned opaque values it stores and
structurally bounds. It does not solve dependency graphs. It is not run
through the full quality-gate profile and is not a support or publication
decision for any package.

## CLI surface (`semaprax registry`)

`src/cli/registry.rs` is a thin front over this module, in the shape of
`cli::audit` and `cli::typed_workflow`: it reads bytes the caller already has
on disk, calls the owning functions, and reports. It owns no registry rule,
and a registry refusal keeps the owning module's own `SPX-PKR6xx` code.

| Verb | What it does | Authority |
| --- | --- | --- |
| `registry search <registry.json> <query>` | Lists published coordinates whose package name contains `query`, as a plain substring comparison over decoded data. | Reads one file. `query` is an opaque string, never joined into a path. |
| `registry add <registry.json> <package> <range>` | Reports the highest published version satisfying `range` (`catalog::select_version`) and the requirement to record. | Reads one file. Edits no manifest; there is no implicit "latest". |
| `registry lock <registry.json> <template.json> [--raw]` | `binding::bind_to_snapshot`; the default is a human report, while `--raw` emits exactly the canonical Registry-Bound Resolution v1 bytes. | Reads two files. Writes nothing; only `--raw` is suitable for a redirected lockfile. |
| `registry fetch <registry.json> <package> <version> [--raw]` | The default is a human report; `--raw` emits exactly one coordinate's published Subject-v3 bytes. This is the offline mirror path. | Reads one file. No cache, no network, no fallback; only `--raw` is suitable for a `[dependency-sources]` file. |
| `registry verify <registry.json> <evidence.json>` | `verify_snapshot`: independent rebuild plus byte comparison. | Read-only, fails closed with `SPX-PKR608`. |
| `registry verify <registry.json> <template.json> <lock.json>` | `binding::verify_bound_resolution`, which additionally replays the embedded resolver-v2 evidence. | Read-only, fails closed with `SPX-PKR608`. |
| `registry publish <registry.json> <entry.json>` | Rebuilds the snapshot the candidate entry would produce -- so `602`/`603`/`604`/`605`/`606` all run -- then prints the registry document that *would* hold it. | **Decide-and-record only.** Publishes nothing, writes nothing, signs nothing, contacts nothing. Making that document real is a separate human act. |

Two codes belong to the front itself and to nothing else: `SPX-Z926` for "the
requested document could not be read at all" (missing, oversized, not UTF-8),
and `SPX-Z927` for "the registry was read and checked, and does not contain
the requested coordinate". Neither is ever used for a registry rule.

### Wire formats

`package_registry::wire` owns both documents and is a decoder only -- it
performs no registry checking, which `wire::tests` pins by decoding a
reserved `std.*` entry successfully and showing `build_snapshot` is what
refuses it (`SPX-PKR602`), with an admitted-name control alongside.

- `semaprax.package-registry-document.v1`: `{"schema", "entries":[...]}`,
  each entry carrying exactly `package`, `version`, `content_digest`,
  `api_digest`, `license`, `provenance_digest` (string or `null`),
  `signature` (`algorithm`/`identity`/`signature`), `status`
  (`{"state":"active"}` or `{"state":"yanked","reason":...}`) and
  `subject_bytes`. Closed keys throughout: an unknown field is refused, never
  ignored. `render_registry_document` is the exact inverse, pinned by a
  round-trip test.
- `semaprax.registry-resolution-template.v1`: `{"schema", "requirements":
  [{"package","range"}], "target", "allowed_capabilities", "yank_policy",
  "max_bytes"}`. `yank_policy` uses the same three spellings the bound
  envelope renders, so a lock and its template cannot disagree; `max_bytes`
  is validated by `package_resolver_v2::ResolutionOptions::new` and keeps
  that module's code.

### What the CLI does *not* add

No network path, no registry URL, no default registry, and no search path --
a search path is the dependency-confusion vulnerability, so the format has
none. No cache or mirror directory: a registry document *is* the mirror. No
cryptography: `signature.identity` is reported as an unverified claim and
issue #168 still owns the signing key. No publication authority. The raw
`lock` and `fetch` forms support a clean local consumer: it independently
replays the fetched Subject-v3 and requires its digest to equal the exact
`subject_digest` selected in the already-verified lock before the subject
reaches `[dependency-sources]`. They do not create a cache, acquire packages,
or turn local evidence into a hosted/public registry claim.
