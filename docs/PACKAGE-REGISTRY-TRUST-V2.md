# Package registry trust v2: Registry-v3 offline proof

Status: additive pure TUF-style local policy, not TUF compliant. The separate
[Host v2](PACKAGE-REGISTRY-HOST-V2.md) owns durable commits; this verifier grants
no fetch, network, signing, publication, or durable authority itself.

## Authority and ownership

`package_registry::trust::registry_v3` verifies signed metadata-v2 against a
borrowed, sealed [Registry-v3](PACKAGE-REGISTRY-SNAPSHOT-V3.md). The caller must
independently admit every linked root and dependency-free leaf through their
build producers. Decoded snapshot/manifest inspection cannot construct that
type. A publisher signature authenticates an exact manifest claim; it does not
replace independent source/build/API/dependency replay. Existing publication
identity strings remain data, not cryptographic publisher authority.

Root installation provenance, disjoint Ed25519 roles and thresholds, namespace
delegation, exact one-version dual-threshold root rotation, revocation, canonical
JSON, signature rejection, and explicit trusted Unix-seconds time follow
[Trust v1](PACKAGE-REGISTRY-TRUST-V1.md). No production keys are supplied.
An independently installed root must not be inferred from distribution bytes.
All metadata is bound to its exact current root digest. Removal/replacement of
a publisher key takes effect through authenticated root rotation; old signatures
cannot satisfy the new root. Metadata expiry equality is expired; an offline
client cannot bypass freshness when newer metadata is unavailable.

`UpdateInputs` separates the lifetimes of signed metadata and the sealed
snapshot. `verify_update(root, checkpoint, now, inputs)` returns a borrowed
`RegistryUpdateCandidate` containing the next checkpoint and exact prior stored
checkpoint SHA-256. It cannot persist that transition, mint a reusable token,
or authorize fetch/execution. `check_lock` replays Lock-v3 against the sealed
snapshot, including exact selected coordinates, active status, source/report
facts and compiled direct-dependency edges. `check_artifact` compares coordinate,
active status, logical path, length and SHA-256 to the independently admitted
leaf or linked manifest. These checks retain the original fixed-time context;
they do not authorize later use or refresh expiry.

## Signed metadata-v2

The signature domain is UTF-8 `semaprax.registry-trust-metadata.v2` followed by
one NUL byte, then the exact canonical `signed` object. Envelope fields remain
`signed` and `signatures`. The closed signed fields are `schema`, `registry`,
`root_digest`, `role`, `version`, `expires`, `payload`; schema is
`semaprax.registry-trust-metadata.v2`. Signature rows retain v1 keyid/sig fields.
All v1 bounds apply: 1 MiB per metadata/checkpoint document, 64 signature keys,
19 roles, 256 total targets, 16 MiB registry envelope and 256 KiB per manifest.

Publisher payload is `{targets:[{package,version,manifest}]}`. Each manifest
reference has exactly `schema`, `digest`, `file`. Schema is the admitted
linked Artifact Manifest-v1 or Leaf Artifact Manifest-v1 schema; digest is its
existing domain-separated manifest digest. `file` has exact `length` and raw
`sha256` of the complete canonical manifest bytes. Every coordinate must match
the signer's namespace. Complete target inventory equals the sealed registry
inventory, including yanked entries; yank prevents subsequent selection/use.

Snapshot payload is `{registry:{schema,file},publishers:[{role,metadata}]}`.
Registry schema is `semaprax.package-registry-snapshot.v3`; file binds the entire
exact Registry-v3 envelope, not just its embedded document. Every root-delegated
publisher role appears exactly once. Each metadata reference has
`{version,file:{length,sha256}}`, pinning complete signed envelope bytes.
Timestamp payload is `{snapshot:{version,file:{length,sha256}}}` and pins the
complete independently signed snapshot metadata. Timestamp, snapshot and
publisher signing roles are disjoint. Unknown/duplicate signers or fields,
insufficient thresholds, namespace violations, missing/extra targets, profile
confusion and mixed-version metadata fail closed.

## One-way protocol checkpoint floor

`RegistryCheckpoint` is a sealed wrapper whose canonical wire is exactly
`{checkpoint:<exact canonical Checkpoint-v1 JSON string>,publishers:
[{namespace,role}],schema:
"semaprax.registry-trust-checkpoint.v2"}` (compact sorted object keys).
The embedded string is bounded by the enclosing document, rather than the
512-byte scalar-label limit. Both outer and embedded documents must reproduce
their input bytes exactly, including sorted role stamps. The required prior
digest hashes the complete outer bytes actually accepted from storage.

`initial` is only for independently authorized first installation.
`migrate_from_v1(checkpoint, root)` is an explicit one-way transition requiring
the exact installed root registry/version/digest recorded in the checkpoint,
preserving every original root, observed-time and role-version/digest stamp.
Unknown prior stamped roles refuse migration. Initial installation and migration
also pin the complete publisher role-to-namespace inventory (sorted by role),
including when no role stamps yet exist. Every update requires this inventory
to equal the current root's inventory. Root key/threshold rotation remains
possible, but adding/removing/renaming publishers or reassigning their namespaces
is refused until a future explicit delegation-migration protocol. This prevents
resetting namespace high-water marks through role-name churn or reassignment.
No unwrap or conversion to
Checkpoint-v1 exists. Trust-v1 rejects Checkpoint-v2 wire, and the v3 verifier
cannot accept a Checkpoint-v1 type. Changing metadata profile or root does not
reset stamps: lower versions or different bytes at the same version fail;
profile migration therefore requires increased metadata versions. Time cannot
move backwards. Removed role stamps remain retained, preventing key/role churn
from silently resetting their high-water marks (the 19-stamp bound remains).

The pure verifier cannot stop an external host from reconstructing older state
or discarding this floor. Before authority-bearing consumption, a separate
explicitly trusted host must durably authenticate/CAS the exact checkpoint and
root, enforce one-way migration and rotation provenance, reverify current input
bytes/time under its lock, and coordinate immutable cache effects/recovery.
The existing managed Trust-v1 host does not accept this new candidate. Existing
offline `fetch --lock` and all v1/v2 registry bytes/behavior remain unchanged.

## Focused regression contract

The owning selector is `package_registry::trust::registry_v3::tests`: a genuine
independently built app.root → lib.leaf snapshot, reproducible Lock-v3 and both
Wasm artifacts; exact checkpoint CAS bytes; target/path/hash/profile/inventory
tamper; publisher thresholds/namespace/domain; timestamp/snapshot/publisher
mix-and-match; every role expiry and clock rollback; version rollback and
same-version equivocation; dual-threshold root rotation/revocation; signed yank;
one-way protocol floor, renamed/reassigned publisher rotation, exact migration
root association and malformed checkpoint ordering. Existing Trust-v1
tests guard the schema/domain-parameterized authentication helper's old route.
These are offline proof regressions, not hosted or durable integration evidence.
