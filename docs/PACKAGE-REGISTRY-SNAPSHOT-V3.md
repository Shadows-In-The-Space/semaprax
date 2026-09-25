# Package Registry Snapshot v3

Audience: package-registry implementers and compiler contributors.

Status: additive pure local distribution evidence; not a trusted fetch or
hosted registry.

Registry-v3 combines independently admitted linked roots and dependency-free
leaves into a finite reproducible catalog. Registry-v1/v2, Artifact Manifest
v1, Source Capsule v1's 2..4 package limit, and Linked Build-v2 stay unchanged.

## Producer and inspection types

`registry_v3::admit_leaf_build` invokes [Leaf Artifact Manifest
v1](PACKAGE-LEAF-ARTIFACT-MANIFEST-V1.md)'s independent Build-v1 producer.
`admit_linked_build` invokes the existing Registry-v2 linked producer with its
complete source capsule/build/resolver replay arguments. Both return sealed
`DistributionEntry`. Publications expose only immutable references; only the
producer populates the derived API digest.

Each entry retains independently verified build facts: package/version,
exact Report-v2, actual canonical implementation source and exact direct
dependency coordinates for every package in its compiled closure. Leaf facts
are one dependency-free entry. Linked facts come from selected Subject-v2
coordinates and actual capsule sources after complete Build-v2 replay, never
from arbitrary claimed manifest facts or unselected catalog entries. The
published root's Subject-v3 dependency names and report must exactly match its
own retained build fact. There is no erased-dependency shortcut.

`build_snapshot` and `verify_snapshot` consume only sealed entries and return
`RegistrySnapshotV3`, retaining those admitted entries. `inspect_snapshot`
returns distinct `InspectedSnapshotV3`/`DecodedEntry` values. Inspection validates
canonical wire and manifest associations but never re-establishes compiler
provenance. There is no decoded-to-admitted conversion. No signing, network,
filesystem, process, cache, publication or execution effect occurs.

## Canonical carrier

The document schema is `semaprax.package-registry-document.v3`, with ordered
fields `schema, publications, manifests`. `publications` is an exact canonical
Registry-v1 document string, so all existing Subject-v3/content, namespace,
coordinate, license, opaque-signature and ownership-continuity rules are reused.
Its entries and matching manifest rows are ordered by package and semantic
version, independent of caller order.

Each manifest row has ordered fields
`package, version, kind, digest, bytes, build_facts`.
Kind is exactly `linked-v2` (unchanged Artifact Manifest-v1 bytes) or `leaf-v1`
(Leaf Artifact Manifest-v1 bytes). Each manifest's coordinate/content/API must
match its publication. Build-fact rows have ordered fields
`package, version, report, source, dependencies`, sorted by package/version;
dependencies are sorted distinct `[package,version]` pairs. One through four
facts are admitted, source at most 1 MiB, report bounded by Subject-v3's limit.
Leaf kind requires one fact with no dependencies. These serialized facts are
inspection data until the complete snapshot is compared with sealed producer
entries; a self-consistent hash does not authenticate their source.

The snapshot schema is `semaprax.package-registry-snapshot.v3`, with ordered
fields `schema, digest, bytes, document`. Digest is SHA-256 of that schema, NUL,
and exact document bytes; byte count is the document's UTF-8 length. Both
document and complete snapshot are at most 16 MiB. Entry count is 1..256.
Before rendering, the checked sum of source/report/subject/manifest input
bytes is at most 16 MiB. All JSON passes the bounded canonical scanner before
DOM deserialization; closed fields and exact typed re-render reject aliases,
duplicates, extra fields, reordering and trailing bytes. Embedded publication
order is independently canonicalized and exact-compared.

## Complete lock association

`verify_lock_selection(&RegistrySnapshotV3, lock, subjects)` consumes a sealed
producer-backed snapshot, not inspection output. It independently replays
Lock-v3 with the exact supplied Subject-v3 inventory. Each selected subject
must be byte-identical to an active admitted entry; yanked, absent, duplicate
or extra selections refuse. The verified lock coordinate set must exactly equal
the selected coordinate keys, independently of ordering. Multiple independent roots may be selected if
their complete valid closure satisfies the same rules.

For every selected entry, the actual resolved dependency coordinates must
equal the retained direct Build-v1/v2 dependency coordinates. Every package
fact in every compiled closure must appear in the lock, and must equal that
selected entry's own independently admitted package/version/report/source/
dependency fact. Thus a compatible interface or range cannot silently substitute
different source or a different compiled version. The existing resolver and
lock verifier still own range satisfaction, graph acyclicity and canonical
dependency-first ordering; this API does not implement a second solver.

The result is `Result<()>` evidence only. It neither grants fetch authority nor
widens the older registry-trust/managed-store APIs to v3. An additive trusted
v3 and physical host integration is a subsequent reviewed cut.

## Focused acceptance

`src/package_registry/registry_v3/tests.rs` constructs `app.root -> lib.leaf`:
Build-v1 emits the dependency-free leaf from exact canonical Report-v2 source;
Build-v2 emits the root with that same leaf source in its independently verified
capsule. Their independently admitted entries form a v3 registry. Repeated
Resolver-v2 calls must produce byte-identical evidence and Lock-v3 bytes;
`verify_lock_selection` proves the selected graph/source closure association.

Hostile controls include missing/yanked leaf, same-interface different-source
leaf, root dependency erasure, swapped source/report/evidence, artifact and
coordinate mutation, API/profile/inventory rebinding, envelope tamper,
noncanonical bytes and missing manifest rows. `SPX-PKR630` is shape/profile/
bound refusal; `SPX-PKR631` is exact association/replay refusal. Older compiler,
manifest, subject and resolver diagnostics remain unchanged.

This is a non-deferred R19 bounded distribution/provenance prerequisite. It
does not extend language generics/ABIs, platform breadth, effectful builds,
protected deferred scope, publisher key custody or hosted deployment.
